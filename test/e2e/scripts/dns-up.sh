#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$(dirname "$0")/egress-lib.sh"
[[ $(jq -r .profile "$state_dir/environment.json") == calico-istio ]]
if [[ -f "$state_dir/dns/ready" ]]; then
  k -n networking-dns get pod client receiver -o json | jq -e 'all(.items[]; .metadata.deletionTimestamp == null)' >/dev/null
  exit 0
fi
trap 'printf "dns setup failed\n" > "$state_dir/fault-active"' ERR
mkdir -p "$state_dir/dns"
export PROBE_IMAGE ISTIOD_IP DNS_RECEIVER_IP DNS_CLIENT=client
PROBE_IMAGE=$(cat "$state_dir/probe-image")
ISTIOD_IP=$(k -n istio-system get service istiod -o jsonpath='{.spec.clusterIP}')
envsubst '${PROBE_IMAGE}' < "$root/test/e2e/config/dns.yaml" | k apply -f - > "$artifacts/dns-setup.txt"
k -n networking-dns create secret generic receiver-certificates --from-file=tls.crt="$state_dir/certs/tls.crt" --from-file=tls.key="$state_dir/certs/tls.key" --dry-run=client -o json | k apply -f - >/dev/null
k -n networking-dns create configmap dns-trust --from-file=ca.pem="$state_dir/certs/ca.pem" --dry-run=client -o json | k apply -f - >/dev/null
k -n networking-dns wait pod/receiver --for=condition=Ready --timeout=90s > /dev/null
DNS_RECEIVER_IP=$(k -n networking-dns get pod receiver -o jsonpath='{.status.podIP}')
envsubst '${DNS_RECEIVER_IP}' < "$root/test/e2e/config/dns-services.yaml" | k apply -f - >> "$artifacts/dns-setup.txt"
envsubst '${DNS_CLIENT} ${PROBE_IMAGE} ${ISTIOD_IP}' < "$root/test/e2e/config/dns-client.yaml" | k create --dry-run=client -f - -o json | protected_pod | k apply -f - >> "$artifacts/dns-setup.txt"
k -n networking-dns wait pod/client --for=condition=Ready --timeout=90s >/dev/null
# The fixed registered control is a readiness condition, not a cached answer used by a case.
deadline=$((SECONDS+30))
until k -n networking-dns exec client -c probe -- /probe dns --query one.origin.test --id dns-ready --timeout 1s > "$state_dir/dns/readiness.json" 2>/dev/null && jq -e '.correlated and any(.answers[]?; startswith("240.240."))' "$state_dir/dns/readiness.json" >/dev/null; do
  ((SECONDS<deadline)) || { echo 'registered FakeIP control unavailable' >&2; exit 1; }
  sleep 0.2
done
jq -n --arg istiod "$ISTIOD_IP" --arg receiver "$DNS_RECEIVER_IP" '{istiod:$istiod,receiver:$receiver}' > "$state_dir/dns/addresses.json"
k -n networking-dns get pods -o json | jq '[.items[]|{name:.metadata.name,uid:.metadata.uid,ip:.status.podIP,images:([.status.containerStatuses[]?|{name,image,imageID}])}]' > "$state_dir/dns/images.json"
printf 'ready\n' > "$state_dir/dns/ready"
