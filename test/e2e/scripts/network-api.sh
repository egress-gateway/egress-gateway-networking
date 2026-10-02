#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$(dirname "$0")/egress-lib.sh"
source "$(dirname "$0")/calico-fault-lib.sh"
need_id
[[ "$protocol" == tcp ]] || exit 2
case "$phase" in deny|allow|wrong-port|revoke) ;; *) exit 2;; esac
k -n default get service kubernetes -o json > "$artifacts/api-service.json"
k -n default get endpointslices -l kubernetes.io/service-name=kubernetes -o json > "$artifacts/api-endpoints.json"
node_ip=$(jq -er '[.items[].endpoints[]|select(.conditions.ready!=false)|.addresses[]]|unique|if length==1 then .[0] else error("ambiguous API endpoint") end' "$artifacts/api-endpoints.json")
port=$(jq -er '[.items[].ports[]|select(.protocol=="TCP")|.port]|unique|if length==1 then .[0] else error("ambiguous API port") end' "$artifacts/api-endpoints.json")
service_ip=$(jq -er '.spec.clusterIP' "$artifacts/api-service.json")
service_port=$(jq -er '[.spec.ports[]|select(.protocol=="TCP")|.port]|if length==1 then .[0] else error("ambiguous API Service port") end' "$artifacts/api-service.json")
endpoint="$node_ip:$port"; address=$endpoint
[[ "$target" != api-service ]] || address="$service_ip:$service_port"
source_ip=$(k -n networking-np get pod client -o jsonpath='{.status.podIP}')
interface=$(endpoint_interface networking-np client)
observer='' policy_owned=false
cleanup_api() {
  local rc=$?
  trap - EXIT
  if [[ -n "$observer" ]]; then
    docker exec "$cluster-control-plane" /networking-probe drops --target "$endpoint" --stop-file "/$test_id-api-stop" --stop || rc=1
    wait "$observer" || rc=1
  fi
  if [[ "$policy_owned" == true ]]; then k -n networking-np delete networkpolicy api-case --wait=true >/dev/null || rc=1; fi
  exit "$rc"
}
trap cleanup_api EXIT
trap 'exit 130' INT TERM
policy() {
  local selected=${1:-0} operation=apply
  [[ "$policy_owned" == true ]] || operation=create
  jq -n --arg ip "$node_ip" --argjson port "$selected" '{namespace:"networking-np",binding:"np",forward:(if $port==0 then [] else [{peer:{ipv4:$ip},ports:[$port]}] end)}' | "$NETWORKING_E2E_BIN" render-fixture --api-policy | tee "$artifacts/policy-$selected.json" | k "$operation" -f - >/dev/null
  policy_owned=true
}
attempt() { k -n "$1" exec "$2" -- /probe request --protocol tcp --connect-only --target "$address" --id "$3" --timeout 1s; }
settle() {
  local expected=$1 deadline=$((SECONDS+20))
  until attempt networking-np client "$test_id-settle" > "$artifacts/settle.jsonl" && jq -e --argjson expected "$expected" '.attempted and .success==$expected' "$artifacts/settle.jsonl" >/dev/null; do ((SECONDS<deadline)) || return 1; sleep .1; done
}
policy
if [[ "$phase" != deny ]]; then
  policy "$port"; settle true
  cp "$artifacts/settle.jsonl" "$artifacts/pre-change.jsonl"
fi
expected=false
case "$phase" in allow) expected=true;; wrong-port) policy "$((port+1))";; revoke) policy;; esac
settle "$expected"
docker exec "$cluster-control-plane" /networking-probe drops --target "$endpoint" --stop-file "/$test_id-api-stop" > "$artifacts/drops.jsonl" 2> "$artifacts/drops-error.txt" &
observer=$!
deadline=$((SECONDS+15))
until jq -se 'any(.[];.event=="drops-ready")' "$artifacts/drops.jsonl" >/dev/null 2>&1; do kill -0 "$observer" || exit 1; ((SECONDS<deadline)) || exit 1; sleep .1; done
attempt networking-np-other control "$test_id-control-before" > "$artifacts/control-before.jsonl"
attempt networking-np client "$test_id" > "$artifacts/probe.jsonl"
attempt networking-np-other control "$test_id-control-after" > "$artifacts/control-after.jsonl"
docker exec "$cluster-control-plane" /networking-probe drops --target "$endpoint" --stop-file "/$test_id-api-stop" --stop
wait "$observer"; observer=''
docker exec "$cluster-control-plane" iptables-save -t nat > "$artifacts/nat-rules.txt"
docker exec "$cluster-control-plane" iptables -S cali-wl-to-host > "$artifacts/node-rules.txt"
k -n networking-np get networkpolicy api-case -o json > "$artifacts/effective-policy.json"
jq -n --arg id "$test_id" --arg phase "$phase" --arg target "$target" --arg address "$address" --arg endpoint "$endpoint" --arg source "$source_ip" --arg interface "$interface" '{id:$id,phase:$phase,target:$target,address:$address,endpoint:$endpoint,source:$source,interface:$interface}' > "$artifacts/api.json"
