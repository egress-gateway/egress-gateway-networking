#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
"$BASH" "$root/install/scripts/diagnostics.sh" --kubeconfig "$state_dir/kubeconfig" --context "kind-$cluster" --artifacts "$artifacts"
cp "$root/install/versions.env" "$artifacts/versions.env"
for ns in networking-np networking-np-other networking-enrollment calico-system; do
  k -n "$ns" get pods -o wide > "$artifacts/$ns-pods.txt" 2>&1 || true
  k -n "$ns" get events --sort-by=.lastTimestamp > "$artifacts/$ns-events.txt" 2>&1 || true
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    k -n "$ns" logs "$name" --all-containers --prefix --tail=300 > "$artifacts/$ns-$name.log" 2>&1 || true
  done < <(k -n "$ns" get pods -o json | jq -r '.items[].metadata.name')
  k -n "$ns" get pods -o json | jq '[.items[]|{name:.metadata.name,uid:.metadata.uid,images:[.status.containerStatuses[]?,.status.initContainerStatuses[]?]|map({name,image,imageID,restartCount,state})}]' > "$artifacts/$ns-images.json" || true
done
k get nodes -o json | jq '[.items[]|{name:.metadata.name,kernel:.status.nodeInfo.kernelVersion,architecture:.status.nodeInfo.architecture}]' > "$artifacts/kernel.json" || true
if [[ $(jq -r .profile "$state_dir/environment.json") == calico ]]; then
  cp "$root/install/calico/versions.env" "$artifacts/calico-versions.env"
fi
if [[ -f "$state_dir/egress.json" ]]; then
  source "$(dirname "$0")/egress-lib.sh"
  cp "$state_dir/egress.json" "$artifacts/egress-fixtures.json"
  for role in origin quic; do
    [[ -f "$state_dir/$role-id" ]] || continue
    if receiver_owned "$role"; then docker logs --tail 500 "$cluster-$role" > "$artifacts/$role.log" 2>&1 || true; fi
  done
fi
