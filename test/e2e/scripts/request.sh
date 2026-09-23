#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
need_id
client=$(pod curl); server=$(pod httpbin)
# Both the application and proxy evidence must identify this particular request.
k -n networking-test exec "$client" -c curl -- curl --noproxy '*' --silent --show-error --fail --max-time 15 \
  -H "X-Networking-Test-Id: $test_id" http://httpbin.networking-test.svc.cluster.local:8000/headers > "$artifacts/response.json"
for attempt in {1..30}; do
  k -n networking-test logs "$client" -c istio-proxy --tail=1000 > "$artifacts/client.log"
  k -n networking-test logs "$server" -c istio-proxy --tail=1000 > "$artifacts/server.log"
  if grep -Fq "$test_id" "$artifacts/client.log" && grep -Fq "$test_id" "$artifacts/server.log"; then exit 0; fi
  sleep 1
done
echo 'correlated proxy logs did not arrive' >&2
exit 1
