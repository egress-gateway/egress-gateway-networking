#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
"$BASH" "$root/install/scripts/diagnostics.sh" --kubeconfig "$state_dir/kubeconfig" --context "kind-$cluster" --artifacts "$artifacts"
cp "$root/install/versions.env" "$artifacts/versions.env"
k -n networking-test get pods -o json | jq '[.items[] | {name:.metadata.name, uid:.metadata.uid, serviceAccount:.spec.serviceAccountName, images:[.status.containerStatuses[], .status.initContainerStatuses[]?] | map({name,image,imageID,restartCount,state})}]' > "$artifacts/workload-images.json" || true
k -n istio-system get pods -o json | jq '[.items[] | {name:.metadata.name, images:[.status.containerStatuses[]?, .status.initContainerStatuses[]?] | map({name,image,imageID})}]' > "$artifacts/istio-images.json" || true
for app in curl httpbin; do
  name=$(pod "$app") || continue
  k -n networking-test logs "$name" --all-containers --prefix --tail=1000 > "$artifacts/$app.log" 2>&1 || true
  k -n networking-test logs "$name" -c istio-validation > "$artifacts/$app-validation.log" 2>&1 || true
done
