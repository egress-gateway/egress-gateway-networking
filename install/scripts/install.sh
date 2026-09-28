#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
[[ "$(k version --client -o json | jq -r '.clientVersion.gitVersion')" == "$KUBECTL_VERSION" ]] || { echo "kubectl $KUBECTL_VERSION required" >&2; exit 2; }
"$BASH" "$root/install/scripts/calico-install.sh" --kubeconfig "$kubeconfig" --context "$context" --artifacts "$artifacts" --cache-dir "$cache_dir"
exec "$BASH" "$root/install/scripts/check.sh" --kubeconfig "$kubeconfig" --context "$context"
