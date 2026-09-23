#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
docker info >/dev/null
if docker inspect "$node" >/dev/null 2>&1; then
  node_owned
  "$BASH" "$root/test/e2e/scripts/egress-down.sh" --state-dir "$state_dir"
  kind delete cluster --name "$cluster" --kubeconfig "$kubeconfig"
else
  "$BASH" "$root/test/e2e/scripts/egress-down.sh" --state-dir "$state_dir"
fi
# Go removes state only after this script succeeds.
