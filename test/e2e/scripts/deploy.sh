#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
export CURL_IMAGE HTTPBIN_IMAGE
envsubst '${CURL_IMAGE} ${HTTPBIN_IMAGE}' < "$root/test/e2e/config/fixtures.yaml" | k apply -f -
k -n networking-test rollout status deployment/curl --timeout=180s
k -n networking-test rollout status deployment/httpbin --timeout=180s
"$BASH" "$root/test/e2e/scripts/egress-up.sh" --state-dir "$state_dir" --artifacts "$artifacts"
