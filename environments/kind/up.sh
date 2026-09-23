#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
[[ "$(kind version)" == "kind $KIND_VERSION "* ]] || { echo "kind $KIND_VERSION required" >&2; exit 2; }
docker info >/dev/null
if docker inspect "$node" >/dev/null 2>&1; then echo 'cluster already exists; refusing takeover' >&2; exit 2; fi
[[ ! -e "$kubeconfig" && ! -e "$state_dir/node-id" ]] || { echo 'existing receipt; refusing takeover' >&2; exit 2; }
export OWNER_FILE="$state_dir/owner"
envsubst '${OWNER_FILE}' < "$root/environments/kind/cluster.yaml" > "$state_dir/cluster.yaml"
receipt() {
  local rc=$? info
  # A mount unique to this invocation distinguishes a partial creation from a
  # concurrent creator using the same cluster name.
  info=$(docker inspect "$node" 2>/dev/null) || exit "$rc"
  if jq -e --arg file "$OWNER_FILE" '.[0] | any(.Mounts[]; .Source == $file and .Destination == "/etc/networking-e2e-owner")' <<< "$info" >/dev/null; then
    jq -r '.[0].Id' <<< "$info" > "$state_dir/node-id"
  fi
  exit "$rc"
}
trap receipt EXIT
kind create cluster --name "$cluster" --image "$KIND_IMAGE" --config "$state_dir/cluster.yaml" --kubeconfig "$kubeconfig" --wait 180s --retain
sha256 "$kubeconfig" > "$state_dir/kubeconfig.sha256"
kubectl --kubeconfig "$kubeconfig" --context "kind-$cluster" wait --for=condition=Ready node --all --timeout=180s
