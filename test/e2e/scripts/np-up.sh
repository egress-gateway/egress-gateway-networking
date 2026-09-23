#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
if [[ ! -f "$state_dir/egress.json" ]]; then "$BASH" "$root/test/e2e/scripts/probe-up.sh" --state-dir "$state_dir" --artifacts "$artifacts"; fi
export PROBE_IMAGE HTTPBIN_IMAGE
PROBE_IMAGE=$(cat "$state_dir/probe-image")
envsubst '${PROBE_IMAGE}' < "$root/test/e2e/config/np.yaml" | k apply -f -
for pair in networking-np/httpbin networking-np/other networking-np-other/httpbin; do
  export NP_NAME=${pair#*/} NP_NAMESPACE=${pair%/*}
  envsubst '${PROBE_IMAGE} ${HTTPBIN_IMAGE} ${NP_NAME} ${NP_NAMESPACE}' < "$root/test/e2e/config/np-httpbin.yaml" | k apply -f -
done
for ns in networking-np networking-np-other; do k -n "$ns" wait pod --all --for=condition=Ready --timeout=180s; done
