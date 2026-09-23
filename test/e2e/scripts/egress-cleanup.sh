#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
need_id
[[ "$(cat "$state_dir/fault-active")" == "$test_id" ]]
[[ "$(jq -er '.id' "$artifacts/log-context.json")" == "$test_id" ]]
fault_pod=$(jq -r '.fault' "$artifacts/log-context.json")
if [[ -n "$fault_pod" ]]; then
  [[ "$fault_pod" == "first-$test_id" || "$fault_pod" == "gate-$test_id" ]]
  k -n networking-egress delete pod "$fault_pod" --ignore-not-found --wait=true --timeout=60s >/dev/null
fi
rm -f "$state_dir/fault-active" "$state_dir/fault-pod.json" "$state_dir/dr-before.json"
