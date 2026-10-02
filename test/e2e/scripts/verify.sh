#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
"$BASH" "$root/install/scripts/check.sh" --kubeconfig "$state_dir/kubeconfig" --context "kind-$cluster"
docker exec "$cluster-control-plane" sh -c 'cat /etc/cni/net.d/*.conflist' > "$artifacts/cni-chain.json"
jq -e -f "$root/install/scripts/check-cni.jq" "$artifacts/cni-chain.json" >/dev/null
