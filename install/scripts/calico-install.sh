#!/usr/bin/env bash
# Infrastructure only. The caller owns the cluster and acceptance workloads.
source "$(dirname "$0")/common.sh"
source "$root/install/calico/versions.env"
require curl
[[ -n "$artifacts" ]] || { echo '--artifacts required' >&2; exit 2; }
mkdir -p "$artifacts" "$cache_dir/calico-$CALICO_VERSION"
owner="calico-static-$CALICO_VERSION"
operator=$(k get crd installations.operator.tigera.io --ignore-not-found -o name)
[[ -z "$operator" ]] || { echo 'Operator installations cannot be adopted or migrated by this installer' >&2; exit 2; }
existing=$(k -n calico-system get daemonset calico-node --ignore-not-found -o json)
if [[ -z "$existing" ]]; then
  k get nodes -o json | jq -e '(.items|length)>0 and all(.items[];.status.conditions|all(.type!="Ready" or .status!="True"))' >/dev/null || { echo 'Calico requires a new cluster without an initialized primary network' >&2; exit 2; }
else
  jq -e --arg owner "$owner" '.metadata.labels["networking.egress/managed"]==$owner' <<< "$existing" >/dev/null || { echo 'refusing unmanaged Calico installation' >&2; exit 2; }
fi
incompatible=$(k get daemonsets -A -o json | jq -r '.items[] | select((.metadata.name | test("kindnet|cilium|flannel|weave|canal")) or (.metadata.name=="calico-node" and .metadata.namespace!="calico-system")) | .metadata.name')
[[ -z "$incompatible" ]] || { echo "refusing other primary CNI: $incompatible" >&2; exit 2; }
file="$cache_dir/calico-$CALICO_VERSION/calico.yaml"
if [[ ! -f "$file" ]]; then
  curl --fail --location --retry 3 --output "$file.part" "https://raw.githubusercontent.com/projectcalico/calico/$CALICO_VERSION/manifests/calico.yaml"
  mv "$file.part" "$file"
fi
[[ "$(sha256 "$file")" == "$CALICO_MANIFEST_SHA256" ]] || { echo 'Calico manifest checksum mismatch' >&2; exit 2; }
render=$(mktemp -d "$cache_dir/calico-$CALICO_VERSION/render.XXXXXX")
trap 'rm -rf "$render"' EXIT
cp "$file" "$render/upstream.yaml"
cp "$root/install/calico/"{kustomization.yaml,node-patch.json,config-patch.json,namespace.yaml} "$render/"
k kustomize "$render" > "$artifacts/calico-rendered.yaml"
# Validate every colliding object before the first apply.
existing=$(k get -f "$artifacts/calico-rendered.yaml" --ignore-not-found -o json)
[[ -z "$existing" ]] || jq -e --arg owner "$owner" 'if .kind=="List" then all(.items[];.metadata.labels["networking.egress/managed"]==$owner) else .metadata.labels["networking.egress/managed"]==$owner end' <<< "$existing" >/dev/null || { echo 'refusing existing unmanaged Calico resources' >&2; exit 2; }
if [[ -n "$(k get crd felixconfigurations.crd.projectcalico.org --ignore-not-found -o name)" ]]; then
  existing=$(k get felixconfigurations.crd.projectcalico.org default --ignore-not-found -o json)
  [[ -z "$existing" ]] || jq -e --arg owner "$owner" '.metadata.labels["networking.egress/managed"]==$owner' <<< "$existing" >/dev/null || { echo 'refusing unmanaged Felix configuration' >&2; exit 2; }
fi
k create --dry-run=client --validate=false -f "$artifacts/calico-rendered.yaml" -o json | jq -s '[.[]|if .kind=="List" then .items[] else . end]|{apiVersion:"v1",kind:"List",items:.}' > "$render/objects.json"
jq '.items|map(select(.kind=="CustomResourceDefinition"))|{apiVersion:"v1",kind:"List",items:.}' "$render/objects.json" | k apply --server-side -f -
k wait crd/felixconfigurations.crd.projectcalico.org --for=condition=Established --timeout=60s
k apply -f "$root/install/calico/installation.yaml"
jq '.items|map(select(.kind!="CustomResourceDefinition"))|{apiVersion:"v1",kind:"List",items:.}' "$render/objects.json" | k apply --server-side -f -
k -n calico-system rollout status daemonset/calico-node --timeout=300s
k -n calico-system rollout status deployment/calico-kube-controllers --timeout=180s
k wait node --all --for=condition=Ready --timeout=120s
k -n kube-system rollout status daemonset/kube-proxy --timeout=120s
k -n calico-system get pods -o json | jq '[.items[] | {name:.metadata.name,uid:.metadata.uid,node:.spec.nodeName,images:[.status.containerStatuses[]?,.status.initContainerStatuses[]?|{name,image,imageID}]}]' > "$artifacts/calico-images.json"
k get felixconfigurations.crd.projectcalico.org default -o json | jq '{spec:.spec}' > "$artifacts/calico-installation.json"
k get nodes -o json | jq '[.items[]|{name:.metadata.name,kernel:.status.nodeInfo.kernelVersion,architecture:.status.nodeInfo.architecture}]' > "$artifacts/kernel.json"
