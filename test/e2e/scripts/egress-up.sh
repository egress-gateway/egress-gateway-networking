#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
if [[ ! -f "$state_dir/egress.json" ]]; then "$BASH" "$root/test/e2e/scripts/probe-up.sh" --state-dir "$state_dir" --artifacts "$artifacts"; fi
export PROBE_IMAGE ORIGIN_IP
PROBE_IMAGE=$(cat "$state_dir/probe-image")
ORIGIN_IP=$(jq -er '.origin' "$state_dir/egress.json")
export ISTIO_PROXY_IMAGE
envsubst '${PROBE_IMAGE} ${ISTIO_PROXY_IMAGE} ${ORIGIN_IP}' < "$root/test/e2e/config/egress.yaml" | k apply -f -
for ns in networking-egress networking-controls; do
  k -n "$ns" create configmap origin-trust --from-file=ca.pem="$state_dir/certs/ca.pem" --dry-run=client -o yaml | k apply -f -
done
if [[ $(jq -r '.profile' "$state_dir/environment.json") == calico-istio ]]; then k apply -f "$root/test/e2e/config/calico-egress.yaml"; fi
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
if [[ $(jq -r '.profile' "$state_dir/environment.json") == calico-istio ]]; then
  for NEIGHBOR_NAMESPACE in networking-gateway kube-system istio-system; do
    export NEIGHBOR_NAMESPACE NEIGHBOR_PORT=15443
    [[ "$NEIGHBOR_NAMESPACE" != istio-system ]] || NEIGHBOR_PORT=15012
    envsubst '${PROBE_IMAGE} ${NEIGHBOR_NAMESPACE} ${NEIGHBOR_PORT}' < "$root/test/e2e/config/calico-neighbor.yaml" | k apply -f -
    k -n "$NEIGHBOR_NAMESPACE" wait pod/network-neighbor --for=condition=Ready --timeout=90s
  done
fi
docker inspect "$cluster-origin" "$cluster-quic" | jq '[.[] | {name:.Name,id:.Id,image:.Image,state:.State.Status}]' > "$artifacts/receiver-images.json"
