#!/usr/bin/env bash
# A complete private probe operation; Go owns the security verdict.
source "$(dirname "$0")/common.sh"
source "$(dirname "$0")/egress-lib.sh"
source "$(dirname "$0")/calico-fault-lib.sh"
need_id
if [[ "$phase" == felix-new || "$phase" == felix-init || "$phase" == first-app || "$phase" == first-init ]]; then
  exec "$BASH" "$root/test/e2e/scripts/network-startup.sh" --state-dir "$state_dir" --artifacts "$artifacts" --test-id "$test_id" --protocol "$protocol" --target "$target" --phase "$phase"
fi
if [[ "$phase" == existing-revoke ]]; then
  exec "$BASH" "$root/test/e2e/scripts/network-existing.sh" --state-dir "$state_dir" --artifacts "$artifacts" --test-id "$test_id"
fi
[[ "$(jq -r .profile "$state_dir/environment.json")" == calico ]] || exit 2
case "$phase" in healthy|runtime-stopped|runtime-restarted|felix-stopped|felix-recovery|revoke) ;; *) echo "unsupported network phase: $phase" >&2; exit 2;; esac
source_ns=networking-np source_pod=client
receiver_ns=networking-np receiver_pod=httpbin receiver_container=httpbin
port=8080 httpbin=(--httpbin)
control=(k -n networking-np-other exec control -- /probe)
started=$(node_stamp)
case "$target" in
  enrollment-a-own|enrollment-a-other|enrollment-b-own|enrollment-b-other|enrollment-trusted-own|enrollment-trusted-other)
    source_ns=networking-enrollment; source_pod=a
    [[ "$target" != enrollment-b-* ]] || source_pod=b
    [[ "$target" != enrollment-trusted-* ]] || source_pod=trusted
    receiver_pod=httpbin
    if [[ "$target" == enrollment-trusted-other || "$target" == enrollment-a-other || "$target" == enrollment-b-own ]]; then receiver_pod=other; fi
    ip=$(k -n "$receiver_ns" get pod "$receiver_pod" -o jsonpath='{.status.podIP}')
    ;;
  np-service) ip=$(k -n networking-np get service httpbin -o jsonpath='{.spec.clusterIP}'); port=8000 ;;
  np-ip|np-wrong|np-udp) ip=$(k -n networking-np get pod httpbin -o jsonpath='{.status.podIP}');;
  np-other) receiver_pod=other; ip=$(k -n networking-np get pod other -o jsonpath='{.status.podIP}');;
  np-cross) receiver_ns=networking-np-other; ip=$(k -n "$receiver_ns" get pod httpbin -o jsonpath='{.status.podIP}');;
  np-external|np-dns|np-quic)
    receiver_owned origin; receiver_owned quic
    ip=$(jq -r .origin "$state_dir/egress.json"); port=9000
    [[ "$protocol" != udp ]] || port=9001
    [[ "$target" != np-dns ]] || port=53
    [[ "$target" != np-quic ]] || port=8443
    receiver_ns='' receiver_pod='' receiver_container=''; httpbin=()
    control=(docker exec "$cluster-quic" /probe)
    ;;
  np-node)
    receiver_ns=networking-np-other receiver_pod=node receiver_container=probe
    ip=$(k get node "$cluster-control-plane" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}'); port=18081
    receiver_owned origin; control=(docker exec "$cluster-origin" /probe); httpbin=()
    ;;
  *) echo "unsupported network target: $target" >&2; exit 2;;
esac
if [[ "$target" == np-wrong || "$target" == np-udp ]]; then port=19090; receiver_container=wrong-port; httpbin=(); fi
address="$ip:$port"
source_ip=$(k -n "$source_ns" get pod "$source_pod" -o jsonpath='{.status.podIP}')
interface=$(endpoint_interface "$source_ns" "$source_pod")
[[ "$interface" =~ ^cali[a-f0-9]+$ ]] || exit 2
sender=(docker exec "$cluster-control-plane" /networking-probe)
if [[ -z "$receiver_ns" ]]; then
  receiver=(docker exec "$cluster-origin" /probe)
  before=$(receiver_snapshot origin)
else
  receiver_pid=$(sandbox_pid "$receiver_ns" "$receiver_pod")
  receiver=(docker exec "$cluster-control-plane" nsenter -t "$receiver_pid" -n /networking-probe)
  before=$(pod_snapshot "$receiver_ns" "$receiver_pod")
fi
receiver_port=$port
[[ "$target" != np-service ]] || receiver_port=8080
control_address=$address; control_extra=("${httpbin[@]}")
if [[ "$protocol" == quic ]]; then control_extra+=(--ca /certs/ca.pem); fi
capture_pids=() capture_roles=()
finish_capture() {
  local i role
  for i in "${!capture_pids[@]}"; do
    role=${capture_roles[$i]}
    if [[ "$role" == receiver ]]; then
      "${receiver[@]}" capture --port "$receiver_port" --stop-file "/$test_id-receiver-stop" --stop
    else
      "${sender[@]}" capture --port "$port" --stop-file "/$test_id-sender-stop" --stop
    fi
    wait "${capture_pids[$i]}" || return 1
  done
  capture_pids=()
}
felix_pid='' policy_added=false runtime_pid=''
runtime_resume() {
  if [[ -n "$runtime_pid" ]]; then
    docker exec "$cluster-control-plane" kill -CONT "$runtime_pid" || return 1
    docker exec "$cluster-control-plane" ps -o stat= -p "$runtime_pid" | awk '$1 !~ /^T/ {ok=1} END {exit !ok}' || return 1
    runtime_pid=''
  fi
}
cleanup_network() {
  local rc=$?
  finish_capture || rc=1
  felix_resume || rc=1
  if [[ "$policy_added" == true ]]; then k -n networking-np delete networkpolicy case-allow --ignore-not-found >/dev/null || rc=1; fi
  runtime_resume || rc=1
  if [[ "$rc" == 0 && -f "$state_dir/fault-active" && $(cat "$state_dir/fault-active") == "$test_id" ]]; then rm -f "$state_dir/fault-active"; fi
  exit "$rc"
}
trap cleanup_network EXIT
trap 'exit 130' INT TERM
# Only this source endpoint's outbound chain counters are eligible evidence.
snapshot_rules() {
  docker exec "$cluster-control-plane" iptables-save -c -t filter | awk -v chain="cali-fw-$interface" '$2=="-A" && $3==chain {print}'
}
case "$phase" in
  runtime-stopped|runtime-restarted)
    [[ "$source_ns" == networking-enrollment && "$source_pod" == trusted ]] || exit 2
    printf '%s\n' "$test_id" > "$state_dir/fault-active"
    original=$(k -n "$source_ns" get pod "$source_pod" -o json)
    cid=$(jq -er '.status.initContainerStatuses[]|select(.name=="runtime")|.containerID|sub("^containerd://";"")' <<< "$original")
    runtime_pid=$(docker exec "$cluster-control-plane" crictl inspect "$cid" | jq -er --arg uid "$(jq -r .metadata.uid <<< "$original")" '. | select(.status.labels["io.kubernetes.pod.uid"]==$uid and .status.metadata.name=="runtime")|.info.pid|select(.>0)')
    if [[ "$phase" == runtime-stopped ]]; then
      docker exec "$cluster-control-plane" kill -STOP "$runtime_pid"
      docker exec "$cluster-control-plane" ps -o pid=,stat= -p "$runtime_pid" | awk '$2 ~ /^T/ {ok=1;print} END {exit !ok}' > "$artifacts/runtime-stopped.txt"
    else
      docker exec "$cluster-control-plane" kill -TERM "$runtime_pid"
      runtime_pid=''
      deadline=$((SECONDS+60))
      until k -n "$source_ns" get pod "$source_pod" -o json | jq -e --arg cid "containerd://$cid" '[.status.initContainerStatuses[]|select(.name=="runtime")]|length==1 and .[0].containerID!=$cid and .[0].restartCount>0 and .[0].state.running!=null' >/dev/null; do ((SECONDS<deadline)) || exit 1; sleep 0.2; done
      k -n "$source_ns" get pod "$source_pod" -o json | jq '.status.initContainerStatuses[]|select(.name=="runtime")' > "$artifacts/runtime-restarted.json"
    fi
    ;;
  felix-stopped) felix_pause;;
  felix-recovery) felix_pause; felix_resume;;
  revoke)
    printf '%s\n' "$test_id" > "$state_dir/fault-active"
    policy_added=true
    jq -n --arg ip "$ip" --argjson port "$port" --arg protocol "${protocol^^}" '{apiVersion:"networking.k8s.io/v1",kind:"NetworkPolicy",metadata:{name:"case-allow",namespace:"networking-np"},spec:{podSelector:{matchLabels:{"networking.egress/protected":"true"}},policyTypes:["Egress"],egress:[{to:[{ipBlock:{cidr:($ip+"/32")}}],ports:[{protocol:$protocol,port:$port}]}]}}' | k apply -f - >/dev/null
    k -n "$source_ns" exec "$source_pod" -- /probe request --protocol "$protocol" --target "$address" --id "$test_id-pre-update" --duration 15s --successes 2 --timeout 2s > "$artifacts/pre-update.jsonl"
    jq -se 'length>=2 and (.[-2:]|all(.success==true))' "$artifacts/pre-update.jsonl" >/dev/null
    k -n networking-np delete networkpolicy case-allow >/dev/null
    policy_added=false
    # Observe removal of the additive policy jump from this endpoint, not a sleep.
    deadline=$((SECONDS+30))
    until [[ "$(snapshot_rules | grep -c -- '-j cali-po-' || true)" == 1 ]]; do ((SECONDS < deadline)) || exit 1; sleep 0.1; done
    ;;
esac
for role in receiver sender; do
  output=packets capture_port=$receiver_port; cmd=("${receiver[@]}")
  capture_args=()
  if [[ "$role" == sender ]]; then output=sender capture_port=$port; cmd=("${sender[@]}"); capture_args=(--interface "$interface"); fi
  "${cmd[@]}" capture --port "$capture_port" --stop-file "/$test_id-$role-stop" "${capture_args[@]}" > "$artifacts/$output.jsonl" 2> "$artifacts/$output-error.txt" &
  capture_pids+=("$!"); capture_roles+=("$role")
  deadline=$((SECONDS+15))
  until jq -se 'any(.[];.event=="capture-ready")' "$artifacts/$output.jsonl" >/dev/null 2>&1; do
    kill -0 "$!" || exit 1
    ((SECONDS < deadline)) || exit 1
    sleep 0.1
  done
done

"${control[@]}" request --protocol "$protocol" --target "$control_address" --id "$test_id-control-before" --timeout 2s "${control_extra[@]}" > "$artifacts/control-before.jsonl"

snapshot_rules > "$artifacts/rules-before.txt"
k -n "$source_ns" exec "$source_pod" -c probe -- /probe request --protocol "$protocol" --target "$address" --id "$test_id" --timeout 2s "${httpbin[@]}" > "$artifacts/probe.jsonl"
snapshot_rules > "$artifacts/rules-after.txt"
transport=tcp; [[ "$protocol" != udp && "$protocol" != dns-udp && "$protocol" != quic ]] || transport=udp
docker exec "$cluster-control-plane" conntrack -L -p "$transport" --orig-src "$source_ip" --orig-dst "$ip" > "$artifacts/conntrack.txt" 2> "$artifacts/conntrack-status.txt" || true
receiver_ip=$ip
if [[ -n "$receiver_ns" ]]; then receiver_ip=$(k -n "$receiver_ns" get pod "$receiver_pod" -o jsonpath='{.status.podIP}'); fi
jq -n --arg source "$source_ip" --arg original "$address" --arg endpoint "$receiver_ip:$receiver_port" --arg protocol "$transport" '{source:$source,original_destination:$original,receiver_endpoint:$endpoint,protocol:$protocol}' > "$artifacts/tuple.json"
if [[ "$phase" == felix-stopped ]]; then felix_paused > "$artifacts/felix-during.txt"; fi
"${control[@]}" request --protocol "$protocol" --target "$control_address" --id "$test_id-control-after" --timeout 2s "${control_extra[@]}" > "$artifacts/control-after.jsonl"
finish_capture
if [[ "$phase" == runtime-stopped ]]; then
  docker exec "$cluster-control-plane" ps -o pid=,stat= -p "$runtime_pid" | awk '$2 ~ /^T/ {ok=1;print} END {exit !ok}' > "$artifacts/runtime-during.txt"
fi
if [[ "$phase" != healthy ]]; then runtime_resume; felix_resume; np_recovery; fi
if [[ -z "$receiver_ns" ]]; then
  after=$(receiver_snapshot origin)
  docker logs --since "$started" "$cluster-origin" > "$artifacts/receiver.log" 2>&1
else
  after=$(pod_snapshot "$receiver_ns" "$receiver_pod")
  k -n "$receiver_ns" logs "$receiver_pod" -c "$receiver_container" --since-time "$started" > "$artifacts/receiver.log"
fi
jq -n --arg id "$test_id" --arg source "$source_ip" --arg interface "$interface" --rawfile before "$artifacts/rules-before.txt" --rawfile after "$artifacts/rules-after.txt" '{id:$id,source_ip:$source,interface:$interface,before:$before,after:$after}' > "$artifacts/enforcement.json"
jq -n --arg id "$test_id" --arg protocol "$protocol" --arg target "$target" --arg phase "$phase" --arg source "$source_ip" --arg before "$before" --arg after "$after" --arg address "$address" '{id:$id,protocol:$protocol,target:$target,phase:$phase,source_ip:$source,receiver_before:$before,receiver_after:$after,address:$address,restored:true,fault_verified:true}' > "$artifacts/network.json"
