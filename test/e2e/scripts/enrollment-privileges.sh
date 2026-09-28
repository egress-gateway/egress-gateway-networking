#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
need_id
for container in probe runtime; do
  k -n networking-enrollment exec trusted -c "$container" -- /probe privileges --id "$test_id" > "$artifacts/$container-privileges.json"
done
