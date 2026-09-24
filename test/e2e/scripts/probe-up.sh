#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
build="$root/.cache/probe"
mkdir -p "$build" "$state_dir/certs"
architecture=$(docker info --format '{{.Architecture}}')
case "$architecture" in aarch64|arm64) architecture=arm64;; x86_64|amd64) architecture=amd64;; *) echo 'unsupported Docker architecture' >&2; exit 2;; esac
CGO_ENABLED=0 GOOS=linux GOARCH="$architecture" go build -trimpath -o "$build/probe" "$root/test/e2e/probe"
go build -trimpath -o "$build/probe-host" "$root/test/e2e/probe"
"$build/probe-host" pki --dir "$state_dir/certs"
if command -v sha256sum >/dev/null 2>&1; then hash=(sha256sum); else hash=(shasum -a 256); fi
digest=$(cat "$build/probe" "$root/test/e2e/probe/Dockerfile" | "${hash[@]}" | cut -d ' ' -f1)
export PROBE_IMAGE="networking-probe:${digest:0:20}"
docker build --tag "$PROBE_IMAGE" --file "$root/test/e2e/probe/Dockerfile" "$build"
kind load docker-image --name "$cluster" "$PROBE_IMAGE"
chmod 0755 "$build/probe"
docker cp "$build/probe" "$cluster-control-plane:/networking-probe"
printf '%s\n' "$PROBE_IMAGE" > "$state_dir/probe-image"
if [[ $(jq -r '.profile' "$state_dir/environment.json") == calico-istio ]]; then
  CGO_ENABLED=0 GOOS=linux GOARCH="$architecture" go test -c -o "$build/probe-tests" "$root/test/e2e/probe"
  docker cp "$build/probe-tests" "$cluster-control-plane:/networking-probe-tests"
  docker exec -e REQUIRE_BPF_TEST=1 "$cluster-control-plane" /networking-probe-tests -test.run '^TestDropAddressComparisonInKernel$' -test.v > "$artifacts/kernel-observer-test.txt"
fi
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
