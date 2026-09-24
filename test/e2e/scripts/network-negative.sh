#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$(dirname "$0")/egress-lib.sh"
source "$(dirname "$0")/calico-fault-lib.sh"
need_id
[[ $(jq -r .profile "$state_dir/environment.json") == calico-istio ]] || exit 2
printf 'negative-%s\n' "$test_id" > "$state_dir/fault-active"
policy_added=false
cleanup_negative() {
  local rc=$?
  if [[ "$policy_added" == true ]]; then k -n networking-np delete networkpolicy case-allow --ignore-not-found >/dev/null || rc=1; fi
  # Go removes the marker only after evaluating the complete recovery evidence.
  exit "$rc"
}
trap cleanup_negative EXIT
trap 'exit 130' INT TERM
ip=$(k -n networking-np get pod httpbin -o jsonpath='{.status.podIP}')
interface=$(endpoint_interface networking-np client)
k create -f "$root/test/e2e/config/np-additive.yaml" >/dev/null; policy_added=true
k -n networking-np exec client -- /probe request --protocol tcp --target "$ip:19090" --id "$test_id-pre-update" --duration 15s --successes 2 --timeout 2s > "$artifacts/pre-update.jsonl"
"$BASH" "$root/test/e2e/scripts/network-case.sh" --state-dir "$state_dir" --artifacts "$artifacts" --test-id "$test_id" --protocol tcp --target np-wrong --phase healthy
k -n networking-np delete networkpolicy case-allow >/dev/null; policy_added=false
deadline=$((SECONDS+30))
until [[ $(docker exec "$cluster-control-plane" iptables-save -t filter | awk -v chain="cali-fw-$interface" '$1=="-A" && $2==chain && /-j cali-po-/ {n++} END{print n}') == 1 ]]; do ((SECONDS<deadline)) || exit 1; sleep 0.1; done
"$BASH" "$root/test/e2e/scripts/network-case.sh" --state-dir "$state_dir" --artifacts "$artifacts/restored" --test-id "$test_id-restored" --protocol tcp --target np-wrong --phase healthy
