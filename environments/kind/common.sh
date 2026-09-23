#!/usr/bin/env bash
set -euo pipefail
umask 077
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# shellcheck source=../../install/versions.env
source "$root/install/versions.env"
state_dir='' artifacts=''
while (($#)); do
  case "$1" in
    --state-dir) state_dir=$2; shift 2 ;;
    --artifacts) artifacts=$2; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -d "$state_dir" && -f "$state_dir/environment.json" ]] || { echo 'environment state required' >&2; exit 2; }
state_dir=$(cd "$state_dir" && pwd)
cluster=$(jq -er '.cluster' "$state_dir/environment.json")
[[ "$cluster" =~ ^networking-e2e-[a-z0-9-]+$ ]] || { echo 'invalid owned cluster name' >&2; exit 2; }
node="$cluster-control-plane"
kubeconfig="$state_dir/kubeconfig"
export NO_PROXY="${NO_PROXY:-},localhost,127.0.0.1,::1"
export no_proxy="$NO_PROXY"
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d ' ' -f1; else shasum -a 256 "$1" | cut -d ' ' -f1; fi; }
node_owned() {
  local info
  info=$(docker inspect "$node") || return 1
  jq -e --arg file "$state_dir/owner" --arg cluster "$cluster" '.[0] | .Config.Labels["io.x-k8s.kind.cluster"] == $cluster and any(.Mounts[]; .Source == $file and .Destination == "/etc/networking-e2e-owner" and .RW == false)' <<< "$info" >/dev/null || { echo 'node owner mount mismatch; refusing access' >&2; return 1; }
  [[ -f "$state_dir/node-id" && "$(jq -r '.[0].Id' <<< "$info")" == "$(cat "$state_dir/node-id")" ]] || { echo 'node identity mismatch; refusing access' >&2; return 1; }
}
