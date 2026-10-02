#!/usr/bin/env bash
# Test-only upstream installation; the product installer remains Calico-only.
source "$(dirname "$0")/common.sh"
need_id
manifest="$root/test/e2e/config/istio-cni.yaml"
[[ -z "$(k get -f "$manifest" --ignore-not-found -o name)" && -z "$(k get namespace networking-cni --ignore-not-found -o name)" ]] || { echo 'refusing existing Istio fixture resources' >&2; exit 2; }
docker exec "$cluster-control-plane" cat /etc/cni/net.d/10-calico.conflist > "$artifacts/cni-before.json"
jq -e -f "$root/install/scripts/check-cni.jq" "$artifacts/cni-before.json" >/dev/null
installed=false
cleanup_integration() {
  local rc=$?
  trap - EXIT
  if [[ "$installed" == true ]]; then
    k delete -f "$manifest" --ignore-not-found --wait=true --timeout=90s >/dev/null || rc=1
    k delete namespace networking-cni --ignore-not-found --wait=true --timeout=60s >/dev/null || rc=1
    # Restore the verified original chain in this suite-owned cluster after the
    # test-only installer has stopped watching it, including on partial setup.
    docker exec -i "$cluster-control-plane" sh -c 'cat > /etc/cni/net.d/10-calico.conflist' < "$artifacts/cni-before.json" || rc=1
  fi
  "$BASH" "$root/install/scripts/check.sh" --kubeconfig "$state_dir/kubeconfig" --context "kind-$cluster" || rc=1
  docker exec "$cluster-control-plane" cat /etc/cni/net.d/10-calico.conflist > "$artifacts/cni-restored.json" || rc=1
  cmp "$artifacts/cni-before.json" "$artifacts/cni-restored.json" || rc=1
  if [[ "$rc" == 0 ]]; then
    rm -f "$state_dir/fault-active"
    jq -n --arg id "$test_id" '{id:$id,restored:true}' > "$artifacts/integration.json"
  else
    printf '%s\n' "$test_id" > "$state_dir/fault-active"
  fi
  exit "$rc"
}
trap cleanup_integration EXIT
trap 'exit 130' INT TERM
printf '%s\n' "$test_id" > "$state_dir/fault-active"
build="$root/.cache/probe"
digest=$(cat "$build/probe" "$root/test/e2e/config/integration.Dockerfile" | shasum -a 256 | cut -d ' ' -f1)
image="networking-integration:${digest:0:20}"
docker build --tag "$image" --file "$root/test/e2e/config/integration.Dockerfile" "$build"
kind load docker-image --name "$cluster" "$image"
printf '%s\n' "$image" > "$state_dir/integration-image"
installed=true
k create namespace networking-cni
k apply -f "$manifest"
k -n networking-cni rollout status daemonset/istio-cni-node --timeout=180s
verify_combination() {
  local label=$1 deadline=$((SECONDS+60))
  until docker exec "$cluster-control-plane" cat /etc/cni/net.d/10-calico.conflist > "$artifacts/cni-$label.json" &&
    jq -e --arg scope foundation -f "$root/install/scripts/check-cni.jq" "$artifacts/cni-$label.json" >/dev/null &&
    jq -e '(.plugins|length)==4 and .plugins[3].type=="istio-cni" and .plugins[3].ambient_enabled==false and .plugins[3].native_nftables==false' "$artifacts/cni-$label.json" >/dev/null; do
    ((SECONDS<deadline)) || return 1
    sleep .2
  done
  "$BASH" "$root/install/scripts/check.sh" --kubeconfig "$state_dir/kubeconfig" --context "kind-$cluster" --cni-scope foundation
  k -n networking-cni get pods -l k8s-app=istio-cni-node -o json | jq '[.items[]|{uid:.metadata.uid,requestedImage:.spec.containers[0].image,containers:[.status.containerStatuses[]?|{image,imageID,ready,state}]}]' > "$artifacts/cni-agent-$label.json"
}
verify_combination initial
"$BASH" "$root/test/e2e/scripts/network-startup.sh" --state-dir "$state_dir" --artifacts "$artifacts/initial" --test-id "$test_id-initial" --protocol tcp --target np-external --phase first-init --client integration
k -n networking-cni rollout restart daemonset/istio-cni-node
k -n networking-cni rollout status daemonset/istio-cni-node --timeout=180s
k -n calico-system rollout restart daemonset/calico-node
k -n calico-system rollout status daemonset/calico-node --timeout=180s
verify_combination restarted
"$BASH" "$root/test/e2e/scripts/network-startup.sh" --state-dir "$state_dir" --artifacts "$artifacts/blocked" --test-id "$test_id-blocked" --protocol tcp --target np-external --phase felix-init --client integration
"$BASH" "$root/test/e2e/scripts/network-startup.sh" --state-dir "$state_dir" --artifacts "$artifacts/recovered" --test-id "$test_id-recovered" --protocol tcp --target np-external --phase first-init --client integration
verify_combination final
