#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$(dirname "$0")/egress-lib.sh"
need_id
context="$artifacts/log-context.json"
[[ "$(jq -er '.id' "$context")" == "$test_id" ]]
started=$(jq -er '.started' "$context")
role=$(jq -r '.role' "$context")
if [[ -n "$role" ]]; then
  [[ "$role" == origin || "$role" == quic ]]
  receiver_owned "$role"
  docker logs --since "$started" "$cluster-$role" > "$artifacts/receiver.log" 2>&1
elif [[ -n "$(jq -r '.pod' "$context")" ]]; then
  k -n "$(jq -r '.namespace' "$context")" logs "$(jq -r '.pod' "$context")" -c "$(jq -r '.container' "$context")" --since-time "$started" > "$artifacts/receiver.log"
else : > "$artifacts/receiver.log"; fi
k -n networking-gateway logs "$(jq -er '.gateway' "$context")" -c istio-proxy --since-time "$started" > "$artifacts/gateway.log"
if [[ "$(jq -r '.client' "$context")" != plain ]]; then
  k -n networking-egress logs "$(jq -er '.workload' "$context")" -c istio-proxy --since-time "$started" > "$artifacts/workload.log"
else : > "$artifacts/workload.log"; fi
