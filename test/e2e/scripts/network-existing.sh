#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$(dirname "$0")/egress-lib.sh"
source "$(dirname "$0")/calico-fault-lib.sh"
need_id
[[ $(jq -r .profile "$state_dir/environment.json") == calico-istio ]] || exit 2
printf '%s\n' "$test_id" > "$state_dir/fault-active"
background='' channel='' policy_added=false
cleanup_existing() {
  local rc=$?
  if [[ -n "$background" ]]; then printf '%s\n' "$test_id" >&"$channel" || rc=1; wait "$background" || rc=1; fi
  if [[ "$policy_added" == true ]]; then k -n networking-np delete networkpolicy case-allow --ignore-not-found >/dev/null || rc=1; fi
  rm -f "$state_dir/existing-$test_id"
  if [[ "$rc" == 0 ]]; then rm -f "$state_dir/fault-active"; fi
  exit "$rc"
}
trap cleanup_existing EXIT
trap 'exit 130' INT TERM
before=$(pod_snapshot networking-np httpbin)
ip=$(k -n networking-np get pod httpbin -o jsonpath='{.status.podIP}'); address="$ip:19090"
source_ip=$(k -n networking-np get pod client -o jsonpath='{.status.podIP}')
interface=$(endpoint_interface networking-np client)
k -n networking-np-other exec control -- /probe request --protocol tcp --target "$address" --id "$test_id-control-before" > "$artifacts/control-before.jsonl"
k create -f "$root/test/e2e/config/np-additive.yaml" >/dev/null; policy_added=true
k -n networking-np exec client -- /probe request --protocol tcp --target "$address" --id "$test_id-pre-update" --duration 15s --successes 2 --timeout 2s > "$artifacts/pre-update.jsonl"
mkfifo "$state_dir/existing-$test_id"; exec {channel}<>"$state_dir/existing-$test_id"
k -n networking-np exec -i client -- /probe request --protocol tcp --target "$address" --id "$test_id" --persistent --duration 60s --stop-on-stdin < "$state_dir/existing-$test_id" > "$artifacts/probe.jsonl" & background=$!
deadline=$((SECONDS+15))
until jq -se '[.[]|select(.attempted and .success)]|length>=2' "$artifacts/probe.jsonl" >/dev/null 2>&1; do kill -0 "$background" || exit 1; ((SECONDS<deadline)) || exit 1; sleep 0.1; done
k -n networking-np delete networkpolicy case-allow >/dev/null; policy_added=false
deadline=$((SECONDS+30))
until [[ $(docker exec "$cluster-control-plane" iptables-save -t filter | awk -v chain="cali-fw-$interface" '$1=="-A" && $2==chain && /-j cali-po-/ {n++} END{print n}') == 1 ]]; do ((SECONDS<deadline)) || exit 1; sleep 0.1; done
updated=$(jq -nr 'now as $t | ($t|floor|strftime("%Y-%m-%dT%H:%M:%S")) + "." + (1000000 + (($t-($t|floor))*1000000|floor)|tostring|.[1:]) + "Z"')
deadline=$((SECONDS+15))
until jq -se --arg time "$updated" '[.[]|select(.attempted and .started>$time)]|length>=3' "$artifacts/probe.jsonl" >/dev/null; do kill -0 "$background" || exit 1; ((SECONDS<deadline)) || exit 1; sleep 0.1; done
printf '%s\n' "$test_id" >&"$channel"; wait "$background"; background=''
k -n networking-np-other exec control -- /probe request --protocol tcp --target "$address" --id "$test_id-control-after" > "$artifacts/control-after.jsonl"
after=$(pod_snapshot networking-np httpbin)
np_recovery
jq -n --arg id "$test_id" --arg source "$source_ip" --arg before "$before" --arg after "$after" --arg updated "$updated" '{id:$id,protocol:"tcp",target:"np-wrong",phase:"existing-revoke",source_ip:$source,receiver_before:$before,receiver_after:$after,restored:true,fault_verified:true,policy_updated:$updated}' > "$artifacts/network.json"
