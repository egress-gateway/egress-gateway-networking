#!/usr/bin/env bash
# Socket availability belongs to the restricted source; available paths also need
# a healthy receiver and an actual packet drop, checked by the common evaluator.
source "$(dirname "$0")/common.sh"
source "$(dirname "$0")/egress-lib.sh"
need_id
[[ "$phase" == healthy ]] || exit 2
k -n networking-np exec client -c probe -- /probe network-state --id "$test_id" > "$artifacts/network-state.json"
docker exec "$cluster-control-plane" iptables-save -c -t filter > "$artifacts/filter-rules.txt"
k -n networking-np get networkpolicy -o json > "$artifacts/network-policies.json"
[[ "$target" != np-socket-matrix ]] || exit 0
case "$protocol" in
  sctp) number=132; socket_type=1; port=9002; args=(serve --sctp "$port");;
  udplite) number=136; socket_type=2; port=9003; args=(serve --udplite "$port");;
  icmp) number=1; socket_type=2; port=9004; args=(serve);;
  *) exit 2;;
esac
errno=$(jq -er --argjson number "$number" --argjson type "$socket_type" '[.sockets[]|select(.family==2 and .type==$type and .protocol==$number)]|if length==1 then .[0].errno else error("missing socket observation") end' "$artifacts/network-state.json")
if [[ "$errno" != 0 ]]; then
  k -n networking-np exec client -c probe -- /probe request --protocol "$protocol" --target "127.0.0.1:$port" --id "$test_id" --timeout 2s > "$artifacts/probe.jsonl"
  exit 0
fi
if [[ "$protocol" == udplite ]]; then
  # An unselected Calico Pod can still reject UDP-Lite as INVALID. The external
  # receiver provides a reachable control independently of that enforcement.
  name="$cluster-udplite"
  if docker inspect "$name" >/dev/null 2>&1; then echo 'protocol receiver already exists; refusing takeover' >&2; exit 2; fi
  network=$(docker inspect "$cluster-control-plane" | jq -er '.[0].NetworkSettings.Networks|keys|if length==1 then .[0] else error("ambiguous node network") end')
  cid=''
  cleanup_external_protocol() {
    local rc=$?
    trap - EXIT
    if [[ -n "$cid" ]]; then
      if receiver_owned udplite; then docker rm -f "$cid" >/dev/null || rc=1; else rc=1; fi
    fi
    exit "$rc"
  }
  trap cleanup_external_protocol EXIT
  trap 'exit 130' INT TERM
  cid=$(docker create --name "$name" --network "$network" --label "networking.e2e.cluster=$cluster" --mount "type=bind,source=$state_dir/owner,target=/owner,readonly" "$(cat "$state_dir/probe-image")" serve --udplite "$port")
  printf '%s\n' "$cid" > "$state_dir/udplite-id"
  docker start "$cid" >/dev/null
  "$BASH" "$root/test/e2e/scripts/network-case.sh" --state-dir "$state_dir" --artifacts "$artifacts/path" --test-id "$test_id" --protocol "$protocol" --target np-udplite --phase healthy
  exit 0
fi
name="protocol-$protocol"
image=$(k -n networking-np get pod client -o jsonpath='{.spec.containers[?(@.name=="probe")].image}')
uid=''
cleanup_protocol() {
  local rc=$? actual
  trap - EXIT
  if [[ -n "$uid" ]]; then
    actual=$(k -n networking-np-other get pod "$name" -o jsonpath='{.metadata.uid}') || rc=1
    if [[ "$actual" == "$uid" ]]; then
      k -n networking-np-other delete pod "$name" --wait=true >/dev/null || rc=1
    else rc=1; fi
  fi
  exit "$rc"
}
trap cleanup_protocol EXIT
trap 'exit 130' INT TERM
args_json=$(printf '%s\n' "${args[@]}" | jq -R . | jq -s .)
uid=$(jq -n --arg name "$name" --arg image "$image" --argjson args "$args_json" '{apiVersion:"v1",kind:"Pod",metadata:{name:$name,namespace:"networking-np-other"},spec:{automountServiceAccountToken:false,restartPolicy:"Never",securityContext:{runAsNonRoot:true,runAsUser:10000,runAsGroup:10000,seccompProfile:{type:"RuntimeDefault"}},containers:[{name:"probe",image:$image,imagePullPolicy:"Never",command:["/probe"],args:$args,securityContext:{allowPrivilegeEscalation:false,capabilities:{drop:["ALL"]}}}]}}' | k create -f - -o jsonpath='{.metadata.uid}')
k -n networking-np-other wait --for=condition=Ready "pod/$name" --timeout=90s
"$BASH" "$root/test/e2e/scripts/network-case.sh" --state-dir "$state_dir" --artifacts "$artifacts/path" --test-id "$test_id" --protocol "$protocol" --target np-protocol-receiver --phase healthy
