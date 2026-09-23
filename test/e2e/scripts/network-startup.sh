#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$(dirname "$0")/egress-lib.sh"
source "$(dirname "$0")/calico-fault-lib.sh"
need_id
[[ $(jq -r .profile "$state_dir/environment.json") == calico-istio && "$protocol" == udp && "$target" == np-external ]] || exit 2
[[ "$phase" == felix-new || "$phase" == felix-init ]] || exit 2
receiver_owned origin; receiver_owned quic
origin=$(jq -er .origin "$state_dir/egress.json")
address="$origin:9001"; source_pod="startup-$test_id"; felix_pid=''
receiver_id=$(receiver_snapshot origin)
jobs=() roles=()
finish_observers() {
  local i role
  for i in "${!jobs[@]}"; do
    role=${roles[$i]}
    if [[ "$role" == receiver ]]; then docker exec "$cluster-origin" /probe capture --port 9001 --stop-file "/$test_id-receiver-stop" --stop
    elif [[ "$role" == sender ]]; then docker exec "$cluster-control-plane" /networking-probe capture --port 9001 --stop-file "/$test_id-sender-stop" --stop
    else docker exec "$cluster-control-plane" /networking-probe drops --target "$address" --stop-file "/$test_id-drops-stop" --stop; fi
    wait "${jobs[$i]}" || return 1
  done
  jobs=()
}
cleanup_startup() {
  local rc=$?
  finish_observers || rc=1
  felix_resume || rc=1
  k -n networking-np delete pod "$source_pod" --ignore-not-found --wait=true --timeout=60s >/dev/null || rc=1
  if [[ "$rc" == 0 ]]; then rm -f "$state_dir/fault-active"; fi
  exit "$rc"
}
trap cleanup_startup EXIT
trap 'exit 130' INT TERM
for role in receiver sender drops; do
  output=$role; ready=capture-ready
  if [[ "$role" == receiver ]]; then output=packets; cmd=(docker exec "$cluster-origin" /probe capture --port 9001)
  elif [[ "$role" == sender ]]; then cmd=(docker exec "$cluster-control-plane" /networking-probe capture --port 9001)
  else ready=drops-ready; cmd=(docker exec "$cluster-control-plane" /networking-probe drops --target "$address"); fi
  "${cmd[@]}" --stop-file "/$test_id-$role-stop" > "$artifacts/$output.jsonl" 2> "$artifacts/$output-error.txt" &
  jobs+=("$!"); roles+=("$role")
  deadline=$((SECONDS+15))
  until jq -se --arg ready "$ready" 'any(.[];.event==$ready)' "$artifacts/$output.jsonl" >/dev/null 2>&1; do kill -0 "$!" || exit 1; ((SECONDS<deadline)) || exit 1; sleep 0.1; done
done
docker exec "$cluster-quic" /probe request --protocol udp --target "$address" --id "$test_id-control-before" --timeout 1s > "$artifacts/control-before.jsonl"
policy_wait=$(docker exec "$cluster-control-plane" cat /etc/cni/net.d/10-calico.conflist | jq -er '.plugins[]|select(.type=="calico")|.policy_setup_timeout_seconds|select(.>0)')
felix_pause
# Kubernetes creationTimestamp has second precision; compare on the same clock
# and at that precision so a Pod created later in this second is not pre-fault.
fault_start=$(node_stamp '+%Y-%m-%dT%H:%M:%SZ')
docker exec "$cluster-control-plane" iptables-save -c -t filter > "$artifacts/rules-before.txt"
jq -n --arg name "$source_pod" --arg image "$(cat "$state_dir/probe-image")" --arg id "$test_id" --arg address "$address" --arg phase "$phase" '{apiVersion:"v1",kind:"Pod",metadata:{name:$name,namespace:"networking-np",labels:{"networking.egress/protected":"true"}},spec:{restartPolicy:"Never",automountServiceAccountToken:false,containers:[{name:"keeper",image:$image,imagePullPolicy:"Never",args:["idle"],securityContext:{runAsUser:10000,allowPrivilegeEscalation:false,capabilities:{drop:["ALL"]}}}]}} | {pod:.,probe:{name:"first-probe",image:$image,imagePullPolicy:"Never",args:["request","--protocol","udp","--target",$address,"--id",$id,"--duration","15s","--timeout","300ms"],securityContext:{runAsUser:10000,allowPrivilegeEscalation:false,capabilities:{drop:["ALL"]}}}} | if $phase=="felix-init" then .pod.spec.initContainers=[.probe] else .pod.spec.containers += [.probe] end | .pod' | k create -f - >/dev/null
deadline=$((SECONDS+45))
completed=false
while ((SECONDS<deadline)); do
  if k -n networking-np get pod "$source_pod" -o json | jq -e '[.status.containerStatuses[]?,.status.initContainerStatuses[]?]|any(.name=="first-probe" and .state.terminated.exitCode==0)' >/dev/null; then completed=true; break; fi
  sleep 0.2
done
k -n networking-np get pod "$source_pod" -o json | jq '{uid:.metadata.uid,created:.metadata.creationTimestamp,ip:(.status.podIP // ""),node:.spec.nodeName,conditions:.status.conditions,containers:[.status.containerStatuses[]?,.status.initContainerStatuses[]?]|map({name,state,lastState,restartCount,containerID})}' > "$artifacts/startup.json"
source_ip=$(jq -r .ip "$artifacts/startup.json"); interface=''
if [[ "$completed" == true ]]; then
  k -n networking-np logs "$source_pod" -c first-probe > "$artifacts/probe.jsonl"
  interface=$(endpoint_interface networking-np "$source_pod")
else
  # The Go assertion distinguishes a proven CNI policy block from unrelated Pending causes.
  : > "$artifacts/probe.jsonl"
  uid=$(jq -er .uid "$artifacts/startup.json")
  k -n networking-np get events --field-selector "involvedObject.uid=$uid" -o json |
    jq '[.items[] | {uid:.involvedObject.uid,reason,message,time:(.lastTimestamp // .eventTime)}]' > "$artifacts/startup-events.json"
fi
felix_paused > "$artifacts/felix-during.txt"
fault_end=$(node_stamp '+%Y-%m-%dT%H:%M:%SZ')
docker exec "$cluster-control-plane" iptables-save -c -t filter > "$artifacts/rules-after.txt"
docker exec "$cluster-quic" /probe request --protocol udp --target "$address" --id "$test_id-control-after" --timeout 1s > "$artifacts/control-after.jsonl"
finish_observers
receiver_owned origin
[[ $(receiver_snapshot origin) == "$receiver_id" ]] || { echo 'receiver changed during startup window' >&2; exit 1; }
docker logs --since "$fault_start" "$cluster-origin" > "$artifacts/receiver.log" 2>&1
felix_resume
np_recovery
jq -n --arg id "$test_id" --arg source "$source_ip" --arg interface "$interface" --arg address "$address" '{id:$id,source_ip:$source,interface:$interface,address:$address}' > "$artifacts/enforcement.json"
jq -n --arg id "$test_id" --arg phase "$phase" --arg source "$source_ip" --arg receiver "$receiver_id" --arg start "$fault_start" --arg end "$fault_end" --argjson wait "$policy_wait" '{id:$id,protocol:"udp",target:"np-external",phase:$phase,source_ip:$source,receiver_before:$receiver,receiver_after:$receiver,restored:true,fault_verified:true,fault_start:$start,fault_end:$end,policy_wait_seconds:$wait}' > "$artifacts/network.json"
