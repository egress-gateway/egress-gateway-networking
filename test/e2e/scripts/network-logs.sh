#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
need_id
file="$artifacts/network-log-context.json"
[[ -f "$file" ]] || exit 0
started=$(jq -er .started "$file")
pod=$(jq -er .pod "$file")
gateway=$(jq -er .gateway "$file")
k -n networking-egress logs "$pod" -c istio-proxy --since-time "$started" > "$artifacts/workload.log"
k -n networking-gateway logs "$gateway" -c istio-proxy --since-time "$started" > "$artifacts/gateway.log"
