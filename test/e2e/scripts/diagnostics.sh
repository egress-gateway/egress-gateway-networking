#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
"$BASH" "$root/install/scripts/diagnostics.sh" --kubeconfig "$state_dir/kubeconfig" --context "kind-$cluster" --artifacts "$artifacts"
cp "$root/install/versions.env" "$artifacts/versions.env"
k -n networking-test get pods -o json | jq '[.items[] | {name:.metadata.name, uid:.metadata.uid, serviceAccount:.spec.serviceAccountName, images:[.status.containerStatuses[]?, .status.initContainerStatuses[]?] | map({name,image,imageID,restartCount,state})}]' > "$artifacts/workload-images.json" || true
k -n istio-system get pods -o json | jq '[.items[] | {name:.metadata.name, images:[.status.containerStatuses[]?, .status.initContainerStatuses[]?] | map({name,image,imageID})}]' > "$artifacts/istio-images.json" || true
for app in curl httpbin; do
  name=$(pod "$app") || continue
  k -n networking-test logs "$name" --all-containers --prefix --tail=1000 > "$artifacts/$app.log" 2>&1 || true
  k -n networking-test logs "$name" -c istio-validation > "$artifacts/$app-validation.log" 2>&1 || true
done

for ns in networking-egress networking-gateway networking-controls networking-np networking-np-other networking-dns networking-dns-records networking-dns-destinations networking-dns-bypass networking-dns-lifecycle calico-system tigera-operator; do
  k -n "$ns" get pods -o wide > "$artifacts/$ns-pods.txt" 2>&1 || true
  k -n "$ns" get events --sort-by=.lastTimestamp > "$artifacts/$ns-events.txt" 2>&1 || true
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    k -n "$ns" logs "$name" --all-containers --prefix --tail=300 > "$artifacts/$ns-$name.log" 2>&1 || true
  done < <(k -n "$ns" get pods -o json | jq -r '.items[].metadata.name')
  k -n "$ns" get pods -o json | jq '[.items[]|{name:.metadata.name,uid:.metadata.uid,images:[.status.containerStatuses[]?,.status.initContainerStatuses[]?]|map({name,image,imageID,restartCount,state})}]' > "$artifacts/$ns-images.json" || true
done
for dns_ns in networking-dns networking-dns-records networking-dns-destinations networking-dns-bypass networking-dns-lifecycle; do
if k get namespace "$dns_ns" >/dev/null 2>&1; then
  k -n "$dns_ns" get networkpolicy,serviceentry -o json | jq '[.items[]|{kind,metadata:{name:.metadata.name,namespace:.metadata.namespace},spec,status}]' > "$artifacts/$dns_ns-configuration.json" || true
fi
done
k get nodes -o json | jq '[.items[]|{name:.metadata.name,kernel:.status.nodeInfo.kernelVersion,architecture:.status.nodeInfo.architecture}]' > "$artifacts/kernel.json" || true
if [[ $(jq -r .profile "$state_dir/environment.json") == calico-istio ]]; then
  cp "$root/install/calico/versions.env" "$artifacts/calico-versions.env"
  k get tigerastatus -o wide > "$artifacts/calico-status.txt" 2>&1 || true
fi
if [[ -f "$state_dir/egress.json" ]]; then
  source "$(dirname "$0")/egress-lib.sh"
  cp "$state_dir/egress.json" "$artifacts/egress-fixtures.json"
  for role in origin quic dns-records dns-destinations dns-bypass dns-lifecycle; do
    [[ -f "$state_dir/$role-id" ]] || continue
    if receiver_owned "$role"; then docker logs --tail 500 "$cluster-$role" > "$artifacts/$role.log" 2>&1 || true; fi
  done
fi
