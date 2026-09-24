#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
if [[ ! -f "$state_dir/egress.json" ]]; then "$BASH" "$root/test/e2e/scripts/probe-up.sh" --state-dir "$state_dir" --artifacts "$artifacts"; fi
export PROBE_IMAGE HTTPBIN_IMAGE
PROBE_IMAGE=$(cat "$state_dir/probe-image")
for ns in networking-np networking-np-other; do k create namespace "$ns" --dry-run=client -o yaml | k apply -f -; done
enrollment_policy networking-np
objects=$(envsubst '${PROBE_IMAGE}' < "$root/test/e2e/config/np.yaml" | k create --dry-run=client -f - -o json)
while IFS= read -r object; do
  if jq -e '.kind=="Pod" and .metadata.name=="client"' <<< "$object" >/dev/null; then
    "$NETWORKING_E2E_BIN" render-fixture --policy-only <<< "$object"
  else printf '%s\n' "$object"; fi
done < <(jq -c 'if .kind=="List" then .items[] else . end' <<< "$objects") | jq -s '{apiVersion:"v1",kind:"List",items:.}' | k apply -f -
for pair in networking-np/httpbin networking-np/other networking-np-other/httpbin; do
  export NP_NAME=${pair#*/} NP_NAMESPACE=${pair%/*}
  envsubst '${PROBE_IMAGE} ${HTTPBIN_IMAGE} ${NP_NAME} ${NP_NAMESPACE}' < "$root/test/e2e/config/np-httpbin.yaml" | k apply -f -
done
for ns in networking-np networking-np-other; do k -n "$ns" wait pod --all --for=condition=Ready --timeout=180s; done
