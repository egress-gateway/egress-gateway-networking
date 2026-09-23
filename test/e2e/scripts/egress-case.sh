#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$(dirname "$0")/egress-lib.sh"
source "$(dirname "$0")/calico-observation-lib.sh"
need_id
receiver_owned origin
receiver_owned quic
origin=$(jq -er '.origin' "$state_dir/egress.json")
quic=$(jq -er '.quic' "$state_dir/egress.json")
source_ns=networking-egress
source_pod=$(epod "$source_ns" "$client")
control_pod=$(epod networking-controls control)
gateway_pod=$(epod networking-gateway gateway)
receiver_role=origin receiver_ns='' receiver_pod='' receiver_container=probe
extra=()
case "$protocol" in http) port=8080;; https|tls) port=443;; tcp) port=9000;; udp) port=9001;; quic) port=8443;; dns-udp|dns-tcp) port=53;; *) echo 'unsupported protocol' >&2; exit 2;; esac
case "$target" in
  routed) address="$origin:$port"; extra+=(--host origin.test);;
  external) address="$origin:$port"; if [[ "$protocol" == http ]]; then extra+=(--host direct.origin.test); fi; if [[ "$protocol" == https ]]; then extra+=(--server-name direct.origin.test); fi;;
  udp443) address="$origin:443";;
  quic443) address="$quic:443"; receiver_role=quic;;
  dns) address="$(k -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}'):53"; extra+=(--query kubernetes.default.svc.cluster.local); receiver_role='';;
  same|same-ip|other|other-ip|other-dns|node)
    receiver_role=''
    receiver_ns=networking-controls receiver_name=other
    case "$target" in same*) receiver_ns=networking-egress receiver_name=same;; node) receiver_name=node port=18080;; esac
    receiver_pod=$(epod "$receiver_ns" "$receiver_name")
    case "$target" in *-ip|node) host=$(k -n "$receiver_ns" get pod "$receiver_pod" -o jsonpath='{.status.podIP}');; *-dns) host="$receiver_name.$receiver_ns.svc.cluster.local";; *) host=$(k -n "$receiver_ns" get svc "$receiver_name" -o jsonpath='{.spec.clusterIP}');; esac
    address="$host:$port";;
  wrong) address="$(k -n networking-gateway get svc gateway -o jsonpath='{.spec.clusterIP}'):19090"; receiver_role='' receiver_ns=networking-gateway receiver_pod="$gateway_pod" receiver_container=wrong-port-receiver;;
  gateway) address="$(k -n networking-gateway get svc gateway -o jsonpath='{.spec.clusterIP}'):15443"; extra+=(--host origin.test)
    if [[ "$protocol" == tls ]]; then extra+=(--ca /mesh/root-cert.pem --server-name gateway.networking-gateway.svc.cluster.local --peer-uri spiffe://cluster.local/ns/networking-gateway/sa/gateway); fi;;
  *) echo 'unsupported target' >&2; exit 2;;
esac
if [[ "$client" == plain ]]; then
  k -n "$source_ns" get pod "$source_pod" -o json | jq '{uid:.metadata.uid,ip:.status.podIP,containers:([.spec.containers[],.spec.initContainers[]?]|map(.name))}' > "$artifacts/unmeshed-source.json"
  jq -e '.containers|all(.[];. != "istio-proxy" and . != "istio-init")' "$artifacts/unmeshed-source.json" >/dev/null
fi
if [[ "$phase" == untrusted ]]; then extra+=(--untrusted-client); fi
started=$(node_stamp)
source_ip=$(k -n "$source_ns" get pod "$source_pod" -o jsonpath='{.status.podIP}')
fault_verified=false restored=false receiver_stable=false startup_blocked=false recovery_failed=false
fault_start='' fault_end=''
fault_pod='' stopped_pid='' background='' probe_control='' gateway_replicas='' istiod_replicas='' repair_disabled=false redirect_removed=false
printf '%s\n' "$test_id" > "$state_dir/fault-active"
restore() {
  local rc=0
  if [[ -n "$background" ]]; then stop_probe || rc=1; fi
  k label namespace networking-egress istio-injection=enabled --overwrite >/dev/null || rc=1
  if [[ -n "$stopped_pid" ]]; then docker exec "$cluster-control-plane" kill -CONT "$stopped_pid" || rc=1; stopped_pid=''; fi
  if [[ "$repair_disabled" == true ]]; then repair_setting true || rc=1; repair_disabled=false; fi
  if [[ -n "$gateway_replicas" ]]; then k -n networking-gateway scale deployment gateway --replicas="$gateway_replicas" >/dev/null || rc=1; gateway_replicas=''; fi
  if [[ -n "$istiod_replicas" ]]; then k -n istio-system scale deployment istiod --replicas="$istiod_replicas" >/dev/null || rc=1; istiod_replicas=''; fi
  if [[ "$phase" == wrong-san && -f "$state_dir/dr-before.json" ]]; then k -n networking-egress patch destinationrule gateway-mtls --type=merge --patch-file "$state_dir/dr-before.json" >/dev/null || rc=1; fi
  if [[ "$redirect_removed" == true ]]; then k -n networking-egress delete pod "$source_pod" --wait=true --timeout=60s >/dev/null || rc=1; redirect_removed=false; fi
  if [[ "$phase" == wrong-san ]]; then sleep 3; fi
  for deployment in networking-egress/workload networking-gateway/gateway istio-system/istiod; do
    k -n "${deployment%/*}" rollout status "deployment/${deployment#*/}" --timeout=180s >/dev/null || rc=1
  done
  return "$rc"
}
cleanup() {
  local rc=$? safe=true
  [[ "$recovery_failed" != true ]] || safe=false
  capture_finish || { rc=1; safe=false; }
  calico_observe_finish || { rc=1; safe=false; }
  if [[ "$restored" != true ]]; then restore || { rc=1; safe=false; }; fi
  if [[ "$rc" == 0 && "$safe" == true && "$defer_cleanup" == true ]]; then exit 0; fi
  if [[ -n "$fault_pod" ]]; then k -n networking-egress delete pod "$fault_pod" --ignore-not-found --wait=true --timeout=60s >/dev/null || { rc=1; safe=false; }; fi
  if [[ "$safe" == true ]]; then rm -f "$state_dir/fault-active" "$state_dir/fault-pod.json" "$state_dir/dr-before.json"; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
snapshot_receiver() {
  if [[ -n "$receiver_role" ]]; then docker inspect "$cluster-$receiver_role" | jq -c '.[0]|{id:.Id,started:.State.StartedAt,running:.State.Running}'
  elif [[ -n "$receiver_pod" ]]; then pod_snapshot "$receiver_ns" "$receiver_pod"
  else k -n kube-system get pod -l k8s-app=kube-dns -o json | jq -c '[.items[]|{uid:.metadata.uid,containers:.status.containerStatuses}]'; fi
}
snapshot_receiver > "$artifacts/receiver-before.json"
control() {
  local part=$1
  if [[ "$target" == gateway || "$client" == intruder || "$phase" == wrong-san || "$phase" == repair || "$phase" == identity-down ]]; then
    k -n networking-egress exec "$(epod networking-egress workload)" -c probe -- /probe request --protocol http --target "$origin:8080" --host origin.test --id "$test_id-control-$part" --timeout 5s > "$artifacts/control-$part.jsonl"
  elif [[ "$target" == node && $(jq -r '.profile' "$state_dir/environment.json") == calico-istio ]]; then
    docker exec "$cluster-origin" /probe request --protocol "$protocol" --target "$address" --id "$test_id-control-$part" --timeout 5s > "$artifacts/control-$part.jsonl"
  else
    k -n networking-controls exec "$control_pod" -c probe -- /probe request --protocol "$protocol" --target "$address" --id "$test_id-control-$part" "${extra[@]}" --timeout 5s > "$artifacts/control-$part.jsonl"
  fi
  jq -se --arg id "$test_id-control-$part" 'any(.[]; .id==$id and .success==true)' "$artifacts/control-$part.jsonl" >/dev/null
}
capture_start
calico_observe_start
control before
component_state() {
  k get pods -A -o json | jq '[.items[]|select(.metadata.namespace=="networking-egress" or .metadata.namespace=="networking-gateway" or .metadata.namespace=="istio-system")|{name:.metadata.name,namespace:.metadata.namespace,uid:.metadata.uid,ip:.status.podIP,conditions:.status.conditions,containers:([.status.containerStatuses[]?,.status.initContainerStatuses[]?]|map({name,containerID,restartCount,state,ready}))}]' > "$artifacts/components-$1.json"
}
if [[ "$phase" != healthy && "$phase" != untrusted ]]; then component_state before; fi
probe() { k -n "$source_ns" exec "$source_pod" -c probe -- /probe request --protocol "$protocol" --target "$address" --id "$test_id" "${extra[@]}" "$@" > "$artifacts/probe.jsonl"; }
start_probe() {
  local fifo="$state_dir/probe-control-$test_id"
  mkfifo "$fifo"
  exec {probe_control}<>"$fifo"
  k -n "$source_ns" exec -i "$source_pod" -c probe -- /probe request --protocol "$protocol" --target "$address" --id "$test_id" "${extra[@]}" --duration 180s --stop-on-stdin < "$fifo" > "$artifacts/probe.jsonl" & background=$!
}
stop_probe() {
  local rc=0
  printf '%s\n' "$test_id" >&"$probe_control" || rc=1
  wait "$background" || rc=1
  background=''
  exec {probe_control}>&-
  rm -f "$state_dir/probe-control-$test_id"
  jq -se --arg id "$test_id" 'any(.[];.event=="probe-stopped" and .id==$id)' "$artifacts/probe.jsonl" >/dev/null || rc=1
  return "$rc"
}
wait_probe() {
  local since=${1:-} count=${2:-1}
  for attempt in {1..300}; do
    if [[ -s "$artifacts/probe.jsonl" ]] && jq -se --arg since "$since" --arg id "$test_id" --argjson count "$count" '[.[]|select(.id==$id and .attempted==true and .started>=$since)]|length >= $count' "$artifacts/probe.jsonl" >/dev/null; then return; fi
    kill -0 "$background" || { wait "$background"; return 1; }
    sleep 0.1
  done
  echo 'background probe did not start' >&2; return 1
}
# Bound even recreation/startup phases, which may produce no application request.
if [[ "$phase" != healthy && "$phase" != untrusted ]]; then fault_start=$(node_stamp); fi
case "$phase" in
  healthy|untrusted) probe;;
  fresh)
    old_uid=$(k -n "$source_ns" get pod "$source_pod" -o jsonpath='{.metadata.uid}')
    k -n "$source_ns" delete pod "$source_pod" --wait=true >/dev/null
    k -n "$source_ns" rollout status deployment/workload --timeout=180s >/dev/null
    source_pod=$(epod "$source_ns" workload)
    [[ "$(k -n "$source_ns" get pod "$source_pod" -o jsonpath='{.metadata.uid}')" != "$old_uid" ]]
    source_ip=$(k -n "$source_ns" get pod "$source_pod" -o jsonpath='{.status.podIP}')
    probe --timeout 5s;;
  wrong-san)
    k -n networking-egress get destinationrule gateway-mtls -o json | jq '{spec:.spec}' > "$state_dir/dr-before.json"
    k -n networking-egress patch destinationrule gateway-mtls --type=merge -p '{"spec":{"trafficPolicy":{"tls":{"subjectAltNames":["spiffe://cluster.local/ns/networking-gateway/sa/unexpected"]}}}}' >/dev/null
    sleep 3
    probe --duration 3s;;
  init|first)
    fault_pod="first-$test_id"
    gated_pod "$fault_pod" "$phase"
    container=probe; [[ "$phase" != init ]] || container=first-probe
    for attempt in {1..90}; do
      state=$(k -n networking-egress get pod "$fault_pod" -o json)
      if jq -e --arg name "$container" '[.status.containerStatuses[]?,.status.initContainerStatuses[]?] | any(.[];.name==$name and .state.terminated.exitCode==0)' <<< "$state" >/dev/null; then break; fi
      sleep 1
    done
    jq -e --arg name "$container" '[.status.containerStatuses[]?,.status.initContainerStatuses[]?] | any(.[];.name==$name and .state.terminated.exitCode==0)' <<< "$state" >/dev/null
    k -n networking-egress logs "$fault_pod" -c "$container" > "$artifacts/probe.jsonl"
    source_ip=$(jq -r '.status.podIP' <<< "$state");;
  redirect)
    redirect_removed=true; remove_redirect "$source_pod"
    probe --duration 3s;;
  sidecar-stop|sidecar-unready)
    stopped_pid=$(envoy_pid "$source_ns" "$source_pod")
    docker exec "$cluster-control-plane" kill -STOP "$stopped_pid"
    docker exec "$cluster-control-plane" ps -o stat= -p "$stopped_pid" | grep T > "$artifacts/stopped-process.txt"
    if [[ "$phase" == sidecar-unready ]]; then k -n "$source_ns" wait pod "$source_pod" --for=condition=Ready=false --timeout=120s >/dev/null; k -n "$source_ns" get pod "$source_pod" -o json | jq '{uid:.metadata.uid,conditions:.status.conditions}' > "$artifacts/unready.json"; fi
    probe --duration 3s;;
  sidecar-kill)
    pod_snapshot "$source_ns" "$source_pod" > "$artifacts/source-before.json"
    start_probe
    wait_probe
    fault_start=$(node_stamp)
    docker exec "$cluster-control-plane" kill -KILL "$(envoy_pid "$source_ns" "$source_pod")"
    for attempt in {1..180}; do
      pod_snapshot "$source_ns" "$source_pod" > "$artifacts/source-after.json"
      if jq -se '([.[0].containers[]|select(.name=="istio-proxy")][0]) as $before | ([.[1].containers[]|select(.name=="istio-proxy")][0]) as $after | $after.containerID != null and $after.containerID != $before.containerID and $after.restartCount > $before.restartCount' "$artifacts/source-before.json" "$artifacts/source-after.json" >/dev/null; then break; fi
      sleep 0.2
    done
    jq -se '([.[0].containers[]|select(.name=="istio-proxy")][0]) as $before | ([.[1].containers[]|select(.name=="istio-proxy")][0]) as $after | $after.containerID != null and $after.containerID != $before.containerID and $after.restartCount > $before.restartCount' "$artifacts/source-before.json" "$artifacts/source-after.json" >/dev/null
    k -n "$source_ns" wait pod "$source_pod" --for=condition=Ready --timeout=180s >/dev/null
    wait_probe "$fault_start" 2
    fault_end=$(node_stamp)
    stop_probe;;
  gateway-down)
    gateway_replicas=$(k -n networking-gateway get deploy gateway -o jsonpath='{.spec.replicas}')
    k -n networking-gateway scale deployment gateway --replicas=0 >/dev/null
    k -n networking-gateway wait pod "$gateway_pod" --for=delete --timeout=90s >/dev/null
    fault_start=$(node_stamp)
    probe --duration 3s
    fault_end=$(node_stamp);;
  gateway-restart)
    start_probe
    wait_probe
    fault_start=$(node_stamp)
    k -n networking-gateway delete pod "$gateway_pod" --wait=true >/dev/null
    k -n networking-gateway rollout status deployment/gateway --timeout=180s >/dev/null
    [[ "$(epod networking-gateway gateway)" != "$gateway_pod" ]]
    wait_probe "$fault_start" 2
    fault_end=$(node_stamp)
    stop_probe;;
  istiod-down|existing)
    istiod_replicas=$(k -n istio-system get deployment istiod -o jsonpath='{.spec.replicas}')
    if [[ "$phase" == existing ]]; then start_probe; wait_probe; fi
    k -n istio-system scale deployment istiod --replicas=0 >/dev/null
    k -n istio-system wait pod -l app=istiod --for=delete --timeout=90s >/dev/null
    fault_start=$(node_stamp)
    if [[ "$phase" == existing ]]; then wait_probe "$fault_start" 2; else probe --duration 3s; fi
    fault_end=$(node_stamp)
    if [[ "$phase" == existing ]]; then stop_probe; fi;;
  repair|identity-down)
    fault_pod="gate-$test_id"
    gated_pod "$fault_pod" gate
    for attempt in {1..90}; do if k -n networking-egress get pod "$fault_pod" -o json | jq -e 'any(.status.initContainerStatuses[]?;.name=="test-gate" and .state.running!=null)' >/dev/null; then break; fi; sleep 1; done
    k -n networking-egress get pod "$fault_pod" -o json | jq -e 'any(.status.initContainerStatuses[]?;.name=="test-gate" and .state.running!=null)' >/dev/null
    if [[ "$phase" == repair ]]; then repair_disabled=true; repair_setting false; remove_redirect "$fault_pod"
    else istiod_replicas=$(k -n istio-system get deployment istiod -o jsonpath='{.spec.replicas}'); k -n istio-system scale deployment istiod --replicas=0 >/dev/null; k -n istio-system wait pod -l app=istiod --for=delete --timeout=90s >/dev/null; fi
    release_gate "$fault_pod"
    deadline=$((SECONDS+90))
    while ((SECONDS < deadline)); do
      k -n networking-egress get pod "$fault_pod" -o json | jq '{uid:.metadata.uid,status:.status}' > "$artifacts/startup-blocked.json"
      if [[ "$phase" == repair ]]; then
        if jq -e 'any(.status.initContainerStatuses[]?;.name=="istio-validation" and ((.state.terminated.exitCode // .lastState.terminated.exitCode // 0)!=0))' "$artifacts/startup-blocked.json" >/dev/null; then break; fi
      elif k -n networking-egress logs "$fault_pod" -c istio-proxy > "$artifacts/identity-failure.log" 2>/dev/null && grep -Ei 'ca request failed|failed to sign CSR|failed to generate workload certificate' "$artifacts/identity-failure.log" >/dev/null; then break; fi
      sleep 0.2
    done
    k -n networking-egress get pod "$fault_pod" -o json | jq '{uid:.metadata.uid,status:.status}' > "$artifacts/startup-blocked.json"
    if [[ "$phase" == repair ]]; then
      jq -e 'any(.status.initContainerStatuses[]?;.name=="istio-validation" and ((.state.terminated.exitCode // .lastState.terminated.exitCode // 0)!=0)) and ([.status.containerStatuses[]?,.status.initContainerStatuses[]?]|all(.[]; .name!="probe" or .state.running==null))' "$artifacts/startup-blocked.json" >/dev/null
      k -n networking-egress logs "$fault_pod" -c istio-validation > "$artifacts/validation.log"
    else
      jq -e '([.status.containerStatuses[]?,.status.initContainerStatuses[]?]|all(.[];.name!="probe" or .state.running==null))' "$artifacts/startup-blocked.json" >/dev/null
      k -n networking-egress logs "$fault_pod" -c istio-proxy > "$artifacts/identity-failure.log"
      grep -Ei 'ca request failed|failed to sign CSR|failed to generate workload certificate' "$artifacts/identity-failure.log" >/dev/null
      jq -e '.status.conditions | all(.[];.type!="Ready" or .status!="True")' "$artifacts/startup-blocked.json" >/dev/null
    fi
    startup_blocked=true
    : > "$artifacts/probe.jsonl";;
  *) echo 'unsupported phase' >&2; exit 2;;
esac
fault_verified=true
if [[ "$phase" != healthy && "$phase" != untrusted && -z "$fault_end" ]]; then fault_end=$(node_stamp); fi
if [[ "$phase" != healthy && "$phase" != untrusted ]]; then component_state fault; fi
restore
restored=true
recovery_failed=true
if [[ "$phase" != healthy && "$phase" != untrusted ]]; then component_state restored; fi
verify_recovery
control after
capture_finish
calico_observe_finish
snapshot_receiver > "$artifacts/receiver-after.json"
cmp "$artifacts/receiver-before.json" "$artifacts/receiver-after.json"
receiver_stable=true
gateway_pod=$(epod networking-gateway gateway)
source_pod=$(epod networking-egress "$client")
if [[ "$phase" == repair || "$phase" == identity-down ]]; then source_pod="$fault_pod"; fi
jq -n --arg id "$test_id" --arg started "$started" --arg role "$receiver_role" --arg ns "$receiver_ns" --arg pod "$receiver_pod" --arg container "$receiver_container" --arg gateway "$gateway_pod" --arg workload "$source_pod" --arg client "$client" --arg fault "$fault_pod" '{id:$id,started:$started,role:$role,namespace:$ns,pod:$pod,container:$container,gateway:$gateway,workload:$workload,client:$client,fault:$fault}' > "$artifacts/log-context.json"
"$BASH" "$root/test/e2e/scripts/egress-logs.sh" --state-dir "$state_dir" --artifacts "$artifacts" --test-id "$test_id"
jq -n --arg id "$test_id" --arg protocol "$protocol" --arg phase "$phase" --arg target "$target" --arg client "$client" --arg source_ip "$source_ip" --arg fault_start "$fault_start" --arg fault_end "$fault_end" --argjson startup_blocked "$startup_blocked" --argjson fault_verified "$fault_verified" --argjson restored "$restored" --argjson receiver_stable "$receiver_stable" '{id:$id,protocol:$protocol,phase:$phase,target:$target,client:$client,fault_start:$fault_start,fault_end:$fault_end,source_ip:$source_ip,startup_blocked:$startup_blocked,fault_verified:$fault_verified,restored:$restored,receiver_stable:$receiver_stable}' > "$artifacts/facts.json"
if [[ $(jq -r .profile "$state_dir/environment.json") == calico-istio ]]; then printf '%s\n' calico-istio > "$artifacts/profile"; fi
