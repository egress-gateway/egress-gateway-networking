#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$(dirname "$0")/egress-lib.sh"
case "$dns_lane" in ''|records|destinations|bypass|lifecycle) ;; *) echo 'invalid DNS lane' >&2; exit 2;; esac
export DNS_NAMESPACE="networking-dns${dns_lane:+-$dns_lane}"
dns_state="$state_dir/dns${dns_lane:+-$dns_lane}"
[[ $(jq -r .profile "$state_dir/environment.json") == calico-istio ]]
if [[ -f "$dns_state/ready" ]]; then
  if [[ -n "$dns_lane" ]]; then receiver_owned "dns-$dns_lane"; fi
  k -n "$DNS_NAMESPACE" get pod client receiver control -o json | jq -e 'all(.items[]; .metadata.deletionTimestamp == null)' >/dev/null
  exit 0
fi
trap 'printf "dns setup failed\n" > "$state_dir/fault-active"' ERR
mkdir -p "$dns_state"
export PROBE_IMAGE ISTIOD_IP DNS_RECEIVER_IP DNS_CLIENT=client
PROBE_IMAGE=$(cat "$state_dir/probe-image")
if [[ -n "$dns_lane" ]]; then
  role="dns-$dns_lane" name="$cluster-dns-$dns_lane"
  if docker inspect "$name" >/dev/null 2>&1; then echo 'DNS receiver exists; refusing takeover' >&2; exit 2; fi
  network=$(docker inspect "$cluster-control-plane" | jq -er '.[0].NetworkSettings.Networks|keys|if length==1 then .[0] else error("ambiguous node network") end')
  container=$(docker create --name "$name" --network "$network" --label "networking.e2e.cluster=$cluster" \
    --mount "type=bind,source=$state_dir/owner,target=/owner,readonly" "$PROBE_IMAGE" serve --tcp 9000 --dns 53)
  printf '%s\n' "$container" > "$state_dir/$role-id"
  docker start "$container" >/dev/null
  docker inspect "$container" | jq -er --arg network "$network" '.[0].NetworkSettings.Networks[$network].IPAddress' > "$dns_state/external-ip"
fi
ISTIOD_IP=$(k -n istio-system get service istiod -o jsonpath='{.spec.clusterIP}')
envsubst '${PROBE_IMAGE} ${DNS_NAMESPACE}' < "$root/test/e2e/config/dns.yaml" | k apply -f - > "$artifacts/dns-setup.txt"
k -n "$DNS_NAMESPACE" create secret generic receiver-certificates --from-file=tls.crt="$state_dir/certs/tls.crt" --from-file=tls.key="$state_dir/certs/tls.key" --dry-run=client -o json | k apply -f - >/dev/null
k -n "$DNS_NAMESPACE" create configmap dns-trust --from-file=ca.pem="$state_dir/certs/ca.pem" --dry-run=client -o json | k apply -f - >/dev/null
k -n "$DNS_NAMESPACE" wait pod/receiver pod/control --for=condition=Ready --timeout=90s > /dev/null
DNS_RECEIVER_IP=$(k -n "$DNS_NAMESPACE" get pod receiver -o jsonpath='{.status.podIP}')
envsubst '${DNS_RECEIVER_IP} ${DNS_NAMESPACE}' < "$root/test/e2e/config/dns-services.yaml" | k apply -f - >> "$artifacts/dns-setup.txt"
envsubst '${DNS_CLIENT} ${PROBE_IMAGE} ${ISTIOD_IP} ${DNS_NAMESPACE}' < "$root/test/e2e/config/dns-client.yaml" | k create --dry-run=client -f - -o json | protected_pod | k apply -f - >> "$artifacts/dns-setup.txt"
k -n "$DNS_NAMESPACE" wait pod/client --for=condition=Ready --timeout=90s >/dev/null
# The fixed registered control is a readiness condition, not a cached answer used by a case.
deadline=$((SECONDS+30))
until k -n "$DNS_NAMESPACE" exec client -c probe -- /probe dns --query one.origin.test --id dns-ready --timeout 1s > "$dns_state/readiness.json" 2>/dev/null && jq -e '.correlated and any(.answers[]?; startswith("240.240."))' "$dns_state/readiness.json" >/dev/null; do
  ((SECONDS<deadline)) || { echo 'registered FakeIP control unavailable' >&2; exit 1; }
  sleep 0.2
done
jq -n --arg istiod "$ISTIOD_IP" --arg receiver "$DNS_RECEIVER_IP" '{istiod:$istiod,receiver:$receiver}' > "$dns_state/addresses.json"
k -n "$DNS_NAMESPACE" get pods -o json | jq '[.items[]|{name:.metadata.name,uid:.metadata.uid,ip:.status.podIP,images:([.status.containerStatuses[]?|{name,image,imageID}])}]' > "$dns_state/images.json"
printf 'ready\n' > "$dns_state/ready"
