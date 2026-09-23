#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
need_id
export PLAIN_POD="plain-$test_id" CURL_IMAGE
server=$(pod httpbin)
cleanup() {
  local rc=$?
  k -n networking-test delete pod "$PLAIN_POD" --ignore-not-found --wait=true --timeout=60s || rc=1
  exit "$rc"
}
trap cleanup EXIT
envsubst '${PLAIN_POD} ${CURL_IMAGE}' < "$root/test/e2e/config/plaintext.yaml" | k create -f -
k -n networking-test wait pod "$PLAIN_POD" --for=condition=Ready --timeout=120s
k -n networking-test get pod "$PLAIN_POD" -o json | jq -e '([.spec.containers[], .spec.initContainers[]?] | all(.name != "istio-proxy"))' >/dev/null
k -n networking-test get peerauthentication strict -o json | jq '{mode:.spec.mtls.mode}' > "$artifacts/authentication.json"
k -n networking-test get pod "$server" -o json | jq '{uid:.metadata.uid, proxy:[.status.containerStatuses[], .status.initContainerStatuses[]?] | map(select(.name == "istio-proxy") | {containerID,restartCount})}' > "$artifacts/server-before.json"
stats "$server" > "$artifacts/stats-before.json"
rc=0
k -n networking-test exec "$PLAIN_POD" -c curl -- curl --noproxy '*' --silent --show-error --max-time 10 \
  -H "X-Networking-Test-Id: $test_id" -o /dev/null -w '%{http_code}' \
  http://httpbin.networking-test.svc.cluster.local:8000/headers > "$artifacts/plaintext-code.txt" 2> "$artifacts/plaintext-error.txt" || rc=$?
printf '%s\n' "$rc" > "$artifacts/plaintext-exit.txt"
stats "$server" > "$artifacts/stats-after.json"
k -n networking-test get pod "$server" -o json | jq '{uid:.metadata.uid, proxy:[.status.containerStatuses[], .status.initContainerStatuses[]?] | map(select(.name == "istio-proxy") | {containerID,restartCount})}' > "$artifacts/server-after.json"
