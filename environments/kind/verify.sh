#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
node_owned
[[ -f "$state_dir/kubeconfig.sha256" && "$(sha256 "$kubeconfig")" == "$(cat "$state_dir/kubeconfig.sha256")" ]] || { echo 'kubeconfig identity mismatch; refusing access' >&2; exit 2; }
