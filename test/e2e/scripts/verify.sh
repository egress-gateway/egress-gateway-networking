#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
"$BASH" "$root/install/scripts/check.sh" --kubeconfig "$state_dir/kubeconfig" --context "kind-$cluster"
k get namespace networking-test -o json | jq -e '.metadata.labels["istio-injection"] == "enabled"' >/dev/null
k -n networking-test get peerauthentication strict -o json | jq -e '.spec.mtls.mode == "STRICT" and (.spec.selector == null)' >/dev/null
k -n networking-test get destinationrule httpbin -o json | jq -e '.spec.host == "httpbin.networking-test.svc.cluster.local" and .spec.trafficPolicy.tls.mode == "ISTIO_MUTUAL"' >/dev/null
for app in curl httpbin; do
  name=$(pod "$app")
  k -n networking-test get pod "$name" -o json | jq -e --arg sa "$app" --arg image "$ISTIO_PROXY_IMAGE" '
    .spec.serviceAccountName == $sa and
    ([.spec.containers[], .spec.initContainers[]?] | any(.name == "istio-proxy" and .image == $image)) and
    ([.spec.initContainers[]?] | all(.name != "istio-init")) and
    ([.spec.initContainers[]?] | any(.name == "istio-validation" and (.args | index("--run-validation") != null) and (.args | index("--skip-rule-apply") != null))) and
    ([.status.initContainerStatuses[]?] | any(.name == "istio-validation" and .state.terminated.exitCode == 0)) and
    ([.status.conditions[]] | any(.type == "Ready" and .status == "True"))' >/dev/null
done
docker exec "$cluster-control-plane" sh -c 'cat /etc/cni/net.d/*.conflist' > "$artifacts/cni-chain.json"
jq -es 'any(.[]; any(.plugins[]?; .type == "istio-cni"))' "$artifacts/cni-chain.json" >/dev/null
