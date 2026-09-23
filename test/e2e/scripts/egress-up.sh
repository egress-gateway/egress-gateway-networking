#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
build="$root/.cache/probe"
mkdir -p "$build" "$state_dir/certs"
architecture=$(docker info --format '{{.Architecture}}')
case "$architecture" in aarch64|arm64) architecture=arm64;; x86_64|amd64) architecture=amd64;; *) echo 'unsupported Docker architecture' >&2; exit 2;; esac
CGO_ENABLED=0 GOOS=linux GOARCH="$architecture" go build -trimpath -o "$build/probe" "$root/test/e2e/probe"
go build -trimpath -o "$build/probe-host" "$root/test/e2e/probe"
"$build/probe-host" pki --dir "$state_dir/certs"
digest=$(cat "$build/probe" "$root/test/e2e/probe/Dockerfile" | shasum -a 256 | cut -d ' ' -f1)
export PROBE_IMAGE="networking-probe:${digest:0:20}"
docker build --tag "$PROBE_IMAGE" --file "$root/test/e2e/probe/Dockerfile" "$build"
kind load docker-image --name "$cluster" "$PROBE_IMAGE"
chmod 0755 "$build/probe"
docker cp "$build/probe" "$cluster-control-plane:/networking-probe"
printf '%s\n' "$PROBE_IMAGE" > "$state_dir/probe-image"
network=$(docker inspect "$cluster-control-plane" | jq -er '.[0].NetworkSettings.Networks | keys | if length == 1 then .[0] else error("ambiguous node network") end')
for role in origin quic; do
  name="$cluster-$role"
  if docker inspect "$name" >/dev/null 2>&1; then echo 'receiver already exists; refusing takeover' >&2; exit 2; fi
  args=(serve --quic 443)
  if [[ "$role" == origin ]]; then args=(serve --http 8080 --https 443 --tcp 9000 --udp 443,9001 --quic 8443 --dns 53); fi
  container=$(docker create --name "$name" --network "$network" --label "networking.e2e.cluster=$cluster" \
    --mount "type=bind,source=$state_dir/owner,target=/owner,readonly" \
    --mount "type=bind,source=$state_dir/certs,target=/certs,readonly" "$PROBE_IMAGE" "${args[@]}")
  printf '%s\n' "$container" > "$state_dir/$role-id"
  docker start "$container" >/dev/null
done
export ORIGIN_IP
ORIGIN_IP=$(docker inspect "$cluster-origin" | jq -er --arg network "$network" '.[0].NetworkSettings.Networks[$network].IPAddress')
quic_ip=$(docker inspect "$cluster-quic" | jq -er --arg network "$network" '.[0].NetworkSettings.Networks[$network].IPAddress')
jq -n --arg origin "$ORIGIN_IP" --arg quic "$quic_ip" --arg image "$PROBE_IMAGE" '{origin:$origin,quic:$quic,image:$image}' > "$state_dir/egress.json"
export ISTIO_PROXY_IMAGE
envsubst '${PROBE_IMAGE} ${ISTIO_PROXY_IMAGE} ${ORIGIN_IP}' < "$root/test/e2e/config/egress.yaml" | k apply -f -
for ns in networking-egress networking-controls; do
  k -n "$ns" create configmap origin-trust --from-file=ca.pem="$state_dir/certs/ca.pem" --dry-run=client -o yaml | k apply -f -
done
for CLIENT_NAME in workload intruder plain control; do
  CLIENT_NAMESPACE=networking-egress CLIENT_SA=workload INJECT=true PROTECTED=true
  case "$CLIENT_NAME" in intruder) CLIENT_SA=intruder;; plain) INJECT=false;; control) CLIENT_NAMESPACE=networking-controls CLIENT_SA=default INJECT=false PROTECTED=false;; esac
  export CLIENT_NAME CLIENT_NAMESPACE CLIENT_SA INJECT PROTECTED
  envsubst '${CLIENT_NAME} ${CLIENT_NAMESPACE} ${CLIENT_SA} ${INJECT} ${PROTECTED} ${PROBE_IMAGE}' < "$root/test/e2e/config/egress-client.yaml" | k apply -f -
done
for RECEIVER_NAME in same other node; do
  RECEIVER_NAMESPACE=networking-controls HOST_NETWORK=false RECEIVER_PORT=9000
  case "$RECEIVER_NAME" in same) RECEIVER_NAMESPACE=networking-egress;; node) HOST_NETWORK=true RECEIVER_PORT=18080;; esac
  export RECEIVER_NAME RECEIVER_NAMESPACE HOST_NETWORK RECEIVER_PORT
  envsubst '${RECEIVER_NAME} ${RECEIVER_NAMESPACE} ${HOST_NETWORK} ${RECEIVER_PORT} ${PROBE_IMAGE}' < "$root/test/e2e/config/egress-receiver.yaml" | k apply -f -
done
for ns in networking-egress networking-gateway networking-controls; do
  while IFS= read -r deployment; do k -n "$ns" rollout status "$deployment" --timeout=240s; done < <(k -n "$ns" get deployment -o name)
done
docker inspect "$cluster-origin" "$cluster-quic" | jq '[.[] | {name:.Name,id:.Id,image:.Image,state:.State.Status}]' > "$artifacts/receiver-images.json"
