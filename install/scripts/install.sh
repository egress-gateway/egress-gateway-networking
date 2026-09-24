#!/usr/bin/env bash
# Install only shared infrastructure; the caller owns cluster and workloads.
source "$(dirname "$0")/common.sh"
require helm curl tar
[[ "$(h version --template '{{.Version}}')" == "$HELM_VERSION" ]] || { echo "Helm $HELM_VERSION required" >&2; exit 2; }
[[ "$(k version --client -o json | jq -r '.clientVersion.gitVersion')" == "$KUBECTL_VERSION" ]] || { echo "kubectl $KUBECTL_VERSION required" >&2; exit 2; }
mkdir -p "$cache_dir"
archive="$cache_dir/istio-$ISTIO_VERSION-linux-amd64.tar.gz"
if [[ ! -f "$archive" ]]; then
  curl --fail --location --retry 3 --output "$archive.part" "https://github.com/istio/istio/releases/download/$ISTIO_VERSION/istio-$ISTIO_VERSION-linux-amd64.tar.gz"
  mv "$archive.part" "$archive"
fi
[[ "$(sha256 "$archive")" == "$ISTIO_ARCHIVE_SHA256" ]] || { echo 'Istio archive checksum mismatch' >&2; exit 2; }
# Always extract from the verified archive. Only portable Helm charts are used.
tar -xzf "$archive" -C "$cache_dir" "istio-$ISTIO_VERSION/manifests/charts"
charts="$cache_dir/istio-$ISTIO_VERSION/manifests/charts"
for resource in deployment/istiod daemonset/istio-cni-node; do
  existing=$(k -n istio-system get "$resource" --ignore-not-found -o json)
  if [[ -n "$existing" ]]; then
    jq -e --arg version "$ISTIO_VERSION" '.metadata.labels["app.kubernetes.io/managed-by"] == "Helm" and .metadata.labels["app.kubernetes.io/version"] == $version' <<< "$existing" >/dev/null || { echo "refusing incompatible or unmanaged $resource" >&2; exit 2; }
  fi
done
values=()
[[ -z "$istiod_values" ]] || values=(-f "$istiod_values")
if [[ -n "$enrollment_label" ]]; then
  jq -n --arg label "$enrollment_label" '{sidecarInjectorWebhook:{neverInjectSelector:[{matchLabels:{($label):"true"}}]}}' > "$cache_dir/enrollment-injection.json"
  values+=(-f "$cache_dir/enrollment-injection.json")
fi
h upgrade --install istio-base "$charts/base" -n istio-system --create-namespace --wait --timeout 5m
h upgrade --install istiod "$charts/istio-control/istio-discovery" -n istio-system \
  -f "$root/install/values/istiod.yaml" "${values[@]}" \
  --set-string "image=$ISTIOD_IMAGE" \
  --set-string "global.proxy.image=$ISTIO_PROXY_IMAGE" \
  --set-string "global.proxy_init.image=$ISTIO_PROXY_IMAGE" --wait --timeout 5m
h upgrade --install istio-cni "$charts/istio-cni" -n istio-system \
  -f "$root/install/values/istio-cni.yaml" --set-string "image=$ISTIO_CNI_IMAGE" --wait --timeout 5m
exec "$BASH" "$root/install/scripts/check.sh" --kubeconfig "$kubeconfig" --context "$context"
