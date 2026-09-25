#!/usr/bin/env bash
set -euo pipefail
umask 077
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
# shellcheck source=../../../install/versions.env
source "$root/install/versions.env"
state_dir='' artifacts='' test_id=''
protocol='' target='' client='' phase=''
dns_lane=''
defer_cleanup=false
while (($#)); do
  case "$1" in
    --state-dir) state_dir=$2; shift 2 ;;
    --artifacts) artifacts=$2; shift 2 ;;
    --test-id) test_id=$2; shift 2 ;;
    --protocol) protocol=$2; shift 2 ;;
    --target) target=$2; shift 2 ;;
    --client) client=$2; shift 2 ;;
    --phase) phase=$2; shift 2 ;;
    --dns-lane) dns_lane=$2; shift 2 ;;
    --defer-cleanup) defer_cleanup=true; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$artifacts" ]] || { echo '--artifacts required' >&2; exit 2; }
mkdir -p "$artifacts"
"$BASH" "$root/environments/kind/verify.sh" --state-dir "$state_dir"
cluster=$(jq -er '.cluster' "$state_dir/environment.json")
export NO_PROXY="${NO_PROXY:-},localhost,127.0.0.1,::1"
export no_proxy="$NO_PROXY"
k() { kubectl --kubeconfig "$state_dir/kubeconfig" --context "kind-$cluster" --request-timeout=30s "$@"; }
pod() { k -n networking-test get pods -l "app=$1" -o json | jq -er '.items | select(length == 1) | .[0].metadata.name'; }
need_id() { [[ "$test_id" =~ ^[a-z0-9-]+$ ]] || { echo 'valid --test-id required' >&2; exit 2; }; }

# The static caller resolves infrastructure; pure enrollment never queries it.
protected_pod() {
  local ip
  ip=$(k -n istio-system get service istiod -o jsonpath='{.spec.clusterIP}')
  "$NETWORKING_E2E_BIN" render-fixture --istiod-ip "$ip" "$@"
}
enrollment_policy() {
  local ns=$1 ip=''
  if [[ "$ns" != networking-np ]]; then ip=$(k -n istio-system get service istiod -o jsonpath='{.spec.clusterIP}'); fi
  "$NETWORKING_E2E_BIN" render-fixture --policy --namespace "$ns" --istiod-ip "$ip" | k apply -f -
}
