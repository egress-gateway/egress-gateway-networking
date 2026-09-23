#!/usr/bin/env bash
# Infrastructure only. The caller owns the cluster and acceptance workloads.
source "$(dirname "$0")/common.sh"
source "$root/install/calico/versions.env"
require curl
[[ -n "$artifacts" ]] || { echo '--artifacts required' >&2; exit 2; }
mkdir -p "$artifacts" "$cache_dir/calico-$CALICO_VERSION"
existing=''
if k get crd installations.operator.tigera.io >/dev/null 2>&1; then
  existing=$(k get installations.operator.tigera.io default --ignore-not-found -o json)
  [[ -z "$existing" ]] || jq -e --arg version "$CALICO_VERSION" '.metadata.labels["networking.egress/managed"] == "calico-"+$version' <<< "$existing" >/dev/null || { echo 'refusing unmanaged Calico installation' >&2; exit 2; }
fi
operator=$(k -n tigera-operator get deployment tigera-operator --ignore-not-found -o json)
if [[ -n "$operator" ]]; then
  jq -e --arg version "calico-$CALICO_VERSION" --arg image "$CALICO_OPERATOR_IMAGE" '.metadata.labels["networking.egress/managed"]==$version and any(.spec.template.spec.containers[];.image==$image)' <<< "$operator" >/dev/null || { echo 'refusing incompatible or unmanaged Tigera Operator' >&2; exit 2; }
fi
if [[ -z "$existing" ]]; then
  k get nodes -o json | jq -e 'all(.items[];.status.conditions|all(.type!="Ready" or .status!="True"))' >/dev/null || { echo 'Calico requires a new cluster without an initialized primary network' >&2; exit 2; }
fi
incompatible=$(k get daemonsets -A -o json | jq -r '.items[] | select(.metadata.name | test("kindnet|cilium|flannel|weave|canal")) | .metadata.name')
[[ -z "$incompatible" ]] || { echo "refusing other primary CNI: $incompatible" >&2; exit 2; }
for part in crds operator; do
  file="$cache_dir/calico-$CALICO_VERSION/$part.yaml"
  if [[ "$part" == crds ]]; then upstream=operator-crds.yaml; expected=$CALICO_CRDS_SHA256; else upstream=tigera-operator.yaml; expected=$CALICO_OPERATOR_SHA256; fi
  if [[ ! -f "$file" ]]; then
    curl --fail --location --retry 3 --output "$file.part" "https://raw.githubusercontent.com/projectcalico/calico/$CALICO_VERSION/manifests/$upstream"
    mv "$file.part" "$file"
  fi
  [[ "$(sha256 "$file")" == "$expected" ]] || { echo "Calico $part checksum mismatch" >&2; exit 2; }
done
k apply --server-side -f "$cache_dir/calico-$CALICO_VERSION/crds.yaml"
k wait crd/installations.operator.tigera.io --for=condition=Established --timeout=60s
k apply -f "$root/install/calico/images.yaml"
sed "s|quay.io/tigera/operator:$CALICO_OPERATOR_VERSION|$CALICO_OPERATOR_IMAGE|" "$cache_dir/calico-$CALICO_VERSION/operator.yaml" | k create --dry-run=client -f - -o json | jq --arg version "calico-$CALICO_VERSION" 'if .kind == "List" then (.items[]|.metadata.labels["networking.egress/managed"])=$version else .metadata.labels["networking.egress/managed"]=$version end' | k apply -f -
k -n tigera-operator rollout status deployment/tigera-operator --timeout=180s
k apply -f "$root/install/calico/installation.yaml"
deadline=$((SECONDS+300))
until k -n calico-system get daemonset/calico-node >/dev/null 2>&1; do
  ((SECONDS < deadline)) || { k get tigerastatus -o wide; exit 1; }
  sleep 1
done
k -n calico-system rollout status daemonset/calico-node --timeout=300s
k -n calico-system rollout status deployment/calico-kube-controllers --timeout=180s
k wait node --all --for=condition=Ready --timeout=120s
k -n kube-system rollout status daemonset/kube-proxy --timeout=120s
k -n calico-system get pods -o json | jq '[.items[] | {name:.metadata.name,uid:.metadata.uid,node:.spec.nodeName,images:[.status.containerStatuses[]?,.status.initContainerStatuses[]?|{name,image,imageID}]}]' > "$artifacts/calico-images.json"
k get installations.operator.tigera.io default -o json | jq '{spec:.spec,status:.status}' > "$artifacts/calico-installation.json"
k get nodes -o json | jq '[.items[]|{name:.metadata.name,kernel:.status.nodeInfo.kernelVersion,architecture:.status.nodeInfo.architecture}]' > "$artifacts/kernel.json"
