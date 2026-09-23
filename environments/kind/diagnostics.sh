#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
[[ -n "$artifacts" ]] || exit 2
mkdir -p "$artifacts"
node_owned
docker logs --tail 1000 "$node" > "$artifacts/kind-node.log" 2>&1 || true
docker exec "$node" journalctl -u kubelet --no-pager -n 500 > "$artifacts/kubelet.log" 2>&1 || true
docker exec "$node" sh -c 'cat /etc/cni/net.d/*.conflist' > "$artifacts/cni-chain.json" 2>&1 || true
