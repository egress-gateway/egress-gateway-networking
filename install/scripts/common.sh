#!/usr/bin/env bash
set -euo pipefail
umask 077
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# shellcheck source=../versions.env
source "$root/install/versions.env"
kubeconfig='' context='' artifacts='' cache_dir="$root/.cache" istiod_values=''
while (($#)); do
  case "$1" in
    --kubeconfig|--context|--artifacts|--cache-dir|--istiod-values)
      (($# >= 2)) || { echo "missing value: $1" >&2; exit 2; }
      key=${1#--}; key=${key//-/_}; printf -v "$key" '%s' "$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$kubeconfig" && -n "$context" && -f "$kubeconfig" ]] || { echo 'explicit --kubeconfig FILE and --context NAME required' >&2; exit 2; }
export NO_PROXY="${NO_PROXY:-},localhost,127.0.0.1,::1"
export no_proxy="$NO_PROXY"
require() { local tool; for tool; do command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; return 2; }; done; }
require kubectl jq
k() { kubectl --kubeconfig "$kubeconfig" --context "$context" --request-timeout=30s "$@"; }
h() { helm --kubeconfig "$kubeconfig" --kube-context "$context" "$@"; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d ' ' -f1; else shasum -a 256 "$1" | cut -d ' ' -f1; fi; }
