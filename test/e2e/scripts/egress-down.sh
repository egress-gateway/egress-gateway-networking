#!/usr/bin/env bash
# This also runs after partial creation, before a kubeconfig or receivers exist.
source "$(dirname "$0")/../../../environments/kind/common.sh"
owned=()
for role in origin quic dns-records dns-destinations dns-bypass dns-lifecycle; do
  name="$cluster-$role"
  if ! info=$(docker inspect "$name" 2>/dev/null); then continue; fi
  jq -e --arg owner "$state_dir/owner" --arg cluster "$cluster" '.[0] | .Config.Labels["networking.e2e.cluster"] == $cluster and any(.Mounts[]; .Source == $owner and .Destination == "/owner" and .RW == false)' <<< "$info" >/dev/null || { echo 'receiver owner mismatch; refusing deletion' >&2; exit 2; }
  [[ -f "$state_dir/$role-id" && "$(jq -r '.[0].Id' <<< "$info")" == "$(cat "$state_dir/$role-id")" ]] || { echo 'receiver ID mismatch; refusing deletion' >&2; exit 2; }
  owned+=("$name")
done
for name in "${owned[@]}"; do docker rm -f "$name" >/dev/null; done
