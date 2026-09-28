#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
"$BASH" "$root/install/scripts/check.sh" --kubeconfig "$state_dir/kubeconfig" --context "kind-$cluster"
docker exec "$cluster-control-plane" sh -c 'cat /etc/cni/net.d/*.conflist' > "$artifacts/cni-chain.json"
jq -es 'length==1 and .[0].plugins[0].type=="calico" and .[0].plugins[0].policy_setup_timeout_seconds==10 and all(.[0].plugins[]; .type=="calico" or .type=="portmap" or .type=="bandwidth")' "$artifacts/cni-chain.json" >/dev/null
