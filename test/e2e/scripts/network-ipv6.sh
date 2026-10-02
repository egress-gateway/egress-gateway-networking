#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$(dirname "$0")/egress-lib.sh"
need_id
[[ "$protocol" == ipv6 && ( "$phase" == first-execution || "$phase" == cni-failure ) ]] || exit 2
name="ipv6-$test_id"; created=false; backup=''
restore_cni() {
  if [[ -n "$backup" ]]; then
    docker exec "$cluster-control-plane" cp "$backup" /etc/cni/net.d/10-calico.conflist || return 1
    docker exec "$cluster-control-plane" cmp "$backup" /etc/cni/net.d/10-calico.conflist || return 1
    docker exec "$cluster-control-plane" rm "$backup" || return 1
    backup=''
  fi
}
cleanup_ipv6() {
  local rc=$?
  trap - EXIT
  if [[ "$created" == true ]]; then k -n networking-np delete pod "$name" --wait=true --timeout=60s >/dev/null || rc=1; fi
  restore_cni || rc=1
  if [[ "$rc" == 0 ]]; then rm -f "$state_dir/fault-active"; fi
  exit "$rc"
}
trap cleanup_ipv6 EXIT
trap 'exit 130' INT TERM
create_source() {
  jq -n --arg name "$name" --arg id "$test_id" --arg image "$(cat "$state_dir/probe-image")" '{apiVersion:"v1",kind:"Pod",metadata:{name:$name,namespace:"networking-np"},spec:{restartPolicy:"Never",automountServiceAccountToken:false,securityContext:{runAsUser:10000,runAsGroup:10000,runAsNonRoot:true,seccompProfile:{type:"RuntimeDefault"}},initContainers:[{name:"first-init",image:$image,imagePullPolicy:"Never",args:["network-state","--id",$id,"--attempt-ipv6"],securityContext:{runAsUser:10000,allowPrivilegeEscalation:false,capabilities:{drop:["ALL"]}}}],containers:[{name:"app",image:$image,imagePullPolicy:"Never",args:["network-state","--id",$id,"--attempt-ipv6","--idle"],securityContext:{runAsUser:10000,allowPrivilegeEscalation:false,capabilities:{drop:["ALL"]}}}]}}' | protected_pod | k create -f - >/dev/null
  created=true
}
observe_source() {
  local out=$1 stage
  mkdir -p "$out"
  k -n networking-np wait "pod/$name" --for=condition=Ready --timeout=90s >/dev/null
  for stage in first-init app; do
    mkdir -p "$out/$stage"
    deadline=$((SECONDS+15))
    until k -n networking-np logs "$name" -c "$stage" > "$out/$stage/observations.jsonl" && jq -se '[.[]|select(.event=="ipv6-attempt")]|length==5' "$out/$stage/observations.jsonl" >/dev/null; do ((SECONDS<deadline)) || return 1; sleep .1; done
    jq -c 'select(.event=="network-state")' "$out/$stage/observations.jsonl" > "$out/$stage/network-state.json"
    jq -c 'select(.event=="ipv6-attempt")' "$out/$stage/observations.jsonl" > "$out/$stage/probe.jsonl"
  done
  ip=$(k -n networking-np get pod httpbin -o jsonpath='{.status.podIP}')
  k -n networking-np exec "$name" -c app -- /probe request --protocol http --target "$ip:8080" --httpbin --id "$test_id-ipv4" > "$out/ipv4.jsonl"
  k -n networking-np get pod "$name" -o json | jq '{uid:.metadata.uid,created:.metadata.creationTimestamp,ip:.status.podIP,containers:[.status.initContainerStatuses[]?,.status.containerStatuses[]?]|map({name,state,restartCount,containerID})}' > "$out/pod.json"
}
if [[ "$phase" == cni-failure ]]; then
  printf '%s\n' "$test_id" > "$state_dir/fault-active"
  backup="/etc/cni/net.d/$test_id.backup"
  docker exec "$cluster-control-plane" cp /etc/cni/net.d/10-calico.conflist "$backup"
  docker exec "$cluster-control-plane" cat "$backup" > "$artifacts/cni-before.json"
  jq --arg key "net.ipv6.conf.missing-$test_id.disable_ipv6" '.plugins[1].sysctl[$key]="1"' "$artifacts/cni-before.json" | docker exec -i "$cluster-control-plane" sh -c 'cat > /etc/cni/net.d/10-calico.conflist'
  create_source
  uid=$(k -n networking-np get pod "$name" -o jsonpath='{.metadata.uid}')
  deadline=$((SECONDS+45))
  until k -n networking-np get events --field-selector "involvedObject.uid=$uid" -o json > "$artifacts/blocked-events.json" && jq -e --arg id "$test_id" 'any(.items[];.reason=="FailedCreatePodSandBox" and (.message|contains("tuning")) and (.message|contains($id)))' "$artifacts/blocked-events.json" >/dev/null; do ((SECONDS<deadline)) || exit 1; sleep .2; done
  k -n networking-np get pod "$name" -o json | jq '{uid:.metadata.uid,created:.metadata.creationTimestamp,conditions:.status.conditions,containers:[.status.initContainerStatuses[]?,.status.containerStatuses[]?]|map({name,state,lastState,restartCount,containerID})}' > "$artifacts/blocked-pod.json"
  k -n networking-np delete pod "$name" --wait=true --timeout=60s >/dev/null; created=false
  restore_cni
  docker exec "$cluster-control-plane" cat /etc/cni/net.d/10-calico.conflist > "$artifacts/cni-restored.json"
  cmp "$artifacts/cni-before.json" "$artifacts/cni-restored.json"
  name="ipv6-recovery-$test_id"
  create_source; observe_source "$artifacts/recovery"
else
  create_source; observe_source "$artifacts"
fi
jq -n --arg id "$test_id" --arg phase "$phase" '{id:$id,phase:$phase,restored:true}' > "$artifacts/ipv6.json"
