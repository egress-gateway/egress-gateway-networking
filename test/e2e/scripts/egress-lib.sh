#!/usr/bin/env bash
# Sourced after common.sh has verified this invocation's owned kind node.
node_stamp() {
  # Probes and Kubernetes timestamps use the Linux node clock; the host runner
  # can have a different clock when Docker runs inside a VM.
  docker exec "$cluster-control-plane" date -u "${1:-+%Y-%m-%dT%H:%M:%S.%NZ}"
}
epod() {
  k -n "$1" get pods -l "app=$2" -o json | jq -er '.items | map(select(.metadata.deletionTimestamp == null)) | if length == 1 then .[0].metadata.name else error("ambiguous fixture Pod") end'
}
receiver_owned() {
  local role=$1 info
  info=$(docker inspect "$cluster-$role")
  jq -e --arg owner "$state_dir/owner" --arg cluster "$cluster" '.[0] | .Config.Labels["networking.e2e.cluster"] == $cluster and any(.Mounts[]; .Source == $owner and .Destination == "/owner" and .RW == false)' <<< "$info" >/dev/null
  [[ "$(jq -r '.[0].Id' <<< "$info")" == "$(cat "$state_dir/$role-id")" ]] || { echo 'receiver identity changed' >&2; return 1; }
}
receiver_snapshot() {
  receiver_owned "$1"
  docker inspect "$cluster-$1" | jq -ce '.[0]|select(.State.Running==true)|{id:.Id,started:.State.StartedAt,restarts:.RestartCount}'
}
pod_snapshot() {
  k -n "$1" get pod "$2" -o json | jq -c '{uid:.metadata.uid,ip:.status.podIP,containers:([.status.containerStatuses[]?,.status.initContainerStatuses[]?]|map({name,containerID,restartCount}))}'
}
sandbox_pid() {
  local ns=$1 name=$2 uid sid info
  uid=$(k -n "$ns" get pod "$name" -o jsonpath='{.metadata.uid}')
  sid=$(docker exec "$cluster-control-plane" crictl pods --namespace "^$ns$" --name "^$name$" --state Ready -q)
  [[ "$sid" =~ ^[a-f0-9]+$ ]] || { echo 'ambiguous sandbox' >&2; return 1; }
  info=$(docker exec "$cluster-control-plane" crictl inspectp "$sid")
  [[ "$(jq -r '.status.metadata.uid' <<< "$info")" == "$uid" ]] || { echo 'sandbox UID mismatch' >&2; return 1; }
  jq -er '.info.pid | select(. > 0)' <<< "$info"
}
envoy_pid() {
  local ns=$1 name=$2 sid cid parent child
  sandbox_pid "$ns" "$name" >/dev/null
  sid=$(docker exec "$cluster-control-plane" crictl pods --namespace "^$ns$" --name "^$name$" --state Ready -q)
  cid=$(docker exec "$cluster-control-plane" crictl ps --pod "$sid" --name istio-proxy -q)
  [[ "$cid" =~ ^[a-f0-9]+$ ]] || return 1
  parent=$(docker exec "$cluster-control-plane" crictl inspect "$cid" | jq -er '.info.pid')
  child=$(docker exec "$cluster-control-plane" pgrep -P "$parent" envoy)
  [[ "$child" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$child"
}
remove_redirect() {
  local pid
  pid=$(sandbox_pid networking-egress "$1")
  docker exec "$cluster-control-plane" nsenter -t "$pid" -n iptables-save -t nat | rg_istio > "$artifacts/redirect-before.txt"
  docker exec "$cluster-control-plane" nsenter -t "$pid" -n iptables -t nat -F ISTIO_OUTPUT
  docker exec "$cluster-control-plane" nsenter -t "$pid" -n iptables -t nat -F ISTIO_INBOUND
  docker exec "$cluster-control-plane" nsenter -t "$pid" -n iptables-save -t nat | rg_istio > "$artifacts/redirect-after.txt"
  ! grep -E '^-A ISTIO_(OUTPUT|INBOUND) ' "$artifacts/redirect-after.txt"
}
rg_istio() { awk '/ISTIO_/ {print}'; }
repair_setting() {
  local enabled=$1
  helm --kubeconfig "$state_dir/kubeconfig" --kube-context "kind-$cluster" upgrade istio-cni "$root/.cache/istio-$ISTIO_VERSION/manifests/charts/istio-cni" -n istio-system --reuse-values --set "repair.enabled=$enabled" --wait --timeout 180s >/dev/null
  k -n istio-system rollout status daemonset/istio-cni-node --timeout=180s
}
# Clone an already-injected fixture so a gate can run before the proxy, without
# asking an unavailable webhook to inject a new Pod during the fault itself.
gated_pod() {
  local name=$1 mode=$2 source
  source=$(epod networking-egress workload)
  k -n networking-egress get pod "$source" -o json | jq --arg name "$name" --arg mode "$mode" --arg image "$(cat "$state_dir/probe-image")" --arg address "$address" --arg protocol "$protocol" --arg id "$test_id" '
    {apiVersion:"v1",kind:"Pod",metadata:{name:$name,namespace:"networking-egress",labels:(.metadata.labels|del(."pod-template-hash")|.app=$name),annotations:.metadata.annotations},spec:(.spec|del(.nodeName))}
    | .spec.restartPolicy=(if $mode == "gate" then "Always" else "Never" end)
    | if $mode == "gate" then .spec.initContainers = [{name:"test-gate",image:$image,imagePullPolicy:"Never",args:["idle"],securityContext:{runAsUser:10000,allowPrivilegeEscalation:false,capabilities:{drop:["ALL"]}}}] + (.spec.initContainers // [])
      elif $mode == "init" then .spec.initContainers += [{name:"first-probe",image:$image,imagePullPolicy:"Never",args:["request","--protocol",$protocol,"--target",$address,"--id",$id,"--duration","3s"],securityContext:{runAsUser:10000,allowPrivilegeEscalation:false,capabilities:{drop:["ALL"]}}}]
      else (.spec.containers[]|select(.name=="probe")|.args)=["request","--protocol",$protocol,"--target",$address,"--id",$id,"--duration","3s"] end
  ' > "$state_dir/fault-pod.json"
  k label namespace networking-egress istio-injection=disabled --overwrite >/dev/null
  k create -f "$state_dir/fault-pod.json"
  k label namespace networking-egress istio-injection=enabled --overwrite >/dev/null
}

capture_start() {
  capture_pid='' capture_command=()
  case "$target" in external|udp443|quic443|same|same-ip|other|other-ip|other-dns|node|wrong) ;; *) return;; esac
  capture_port=${address##*:}
  capture_stop="/capture-stop-$test_id"
  if [[ -n "$receiver_role" ]]; then
    capture_command=(docker exec "$cluster-$receiver_role" /probe)
  else
    local pid
    pid=$(sandbox_pid "$receiver_ns" "$receiver_pod")
    capture_command=(docker exec "$cluster-control-plane" nsenter -t "$pid" -n /networking-probe)
  fi
  "${capture_command[@]}" capture --port "$capture_port" --stop-file "$capture_stop" > "$artifacts/packets.jsonl" 2> "$artifacts/capture-error.txt" & capture_pid=$!
  for attempt in {1..200}; do
    if [[ -s "$artifacts/packets.jsonl" ]] && jq -se 'any(.[];.event=="capture-ready")' "$artifacts/packets.jsonl" >/dev/null; then return; fi
    kill -0 "$capture_pid" || { wait "$capture_pid"; return 1; }
    sleep 0.1
  done
  echo 'receiver capture did not become ready' >&2; return 1
}
capture_finish() {
  if [[ -n "${capture_pid:-}" ]]; then
    "${capture_command[@]}" capture --port "$capture_port" --stop-file "$capture_stop" --stop
    wait "$capture_pid" || return 1
    capture_pid=''
    jq -se 'any(.[];.event=="capture-complete")' "$artifacts/packets.jsonl" >/dev/null
  fi
}

# Mark the entire verification stage unsafe until every operation succeeds.
verify_recovery() {
  recovery_failed=true
  local recovery_pod recovery_id recovery_file count
  if [[ "$phase" == healthy || "$phase" == untrusted ]]; then recovery_failed=false; return; fi
  if [[ "$phase" == repair || "$phase" == identity-down ]]; then
    k -n networking-egress wait pod "$fault_pod" --for=condition=Ready --timeout=180s >/dev/null
    recovery_pod=$fault_pod; recovery_id="$test_id-recovered"; recovery_file=recovered.jsonl; count=1
  else
    recovery_pod=$(epod networking-egress workload); recovery_id="$test_id-recovery"; recovery_file=recovery.jsonl; count=2
  fi
  # Pod readiness can precede the workload Envoy's endpoint update. Keep
  # convergence attempts separate from the strictly authenticated proof.
  k -n networking-egress exec "$recovery_pod" -c probe -- /probe request --protocol http --target "$origin:8080" --host origin.test --id "$test_id-recovery-ready" --duration 15s --successes 1 --timeout 5s > "$artifacts/recovery-ready.jsonl"
  jq -se --arg id "$test_id-recovery-ready" 'length>0 and .[-1].id==$id and .[-1].success==true' "$artifacts/recovery-ready.jsonl" >/dev/null
  k -n networking-egress exec "$recovery_pod" -c probe -- /probe request --protocol http --target "$origin:8080" --host origin.test --id "$recovery_id" --duration 15s --successes "$count" --timeout 5s > "$artifacts/$recovery_file"
  jq -se --arg id "$recovery_id" --argjson count "$count" 'length==$count and all(.[];.id==$id and .success==true)' "$artifacts/$recovery_file" >/dev/null
  recovery_failed=false
}

release_gate() {
  local name=$1 result=0
  k -n networking-egress get pod "$name" -o json |
    jq '{uid:.metadata.uid,gate:(.status.initContainerStatuses[]|select(.name=="test-gate"))}' > "$artifacts/gate-before.json"
  jq -e '(.uid|type=="string" and length>0) and (.gate.containerID|type=="string" and length>0) and .gate.state.running!=null' "$artifacts/gate-before.json" >/dev/null
  # Stopping PID 1 can kill the exec process before its response is delivered.
  # Only the same container's successful Kubernetes completion proves release.
  k -n networking-egress exec "$name" -c test-gate -- /probe release > "$artifacts/gate-release.log" 2>&1 || result=$?
  printf '%s\n' "$result" > "$artifacts/gate-release-exit.txt"
  case "$result" in 0|137) ;; *) cat "$artifacts/gate-release.log" >&2; return "$result";; esac
  k -n networking-egress wait pod "$name" '--for=jsonpath={.status.initContainerStatuses[?(@.name=="test-gate")].state.terminated.exitCode}=0' --timeout=15s > "$artifacts/gate-wait.log"
  k -n networking-egress get pod "$name" -o json |
    jq '{uid:.metadata.uid,gate:(.status.initContainerStatuses[]|select(.name=="test-gate"))}' > "$artifacts/gate-after.json"
  jq -e --slurpfile before "$artifacts/gate-before.json" '.uid==$before[0].uid and .gate.containerID==$before[0].gate.containerID and .gate.restartCount==$before[0].gate.restartCount and .gate.state.terminated.exitCode==0 and .gate.state.terminated.reason=="Completed"' "$artifacts/gate-after.json" >/dev/null
}
