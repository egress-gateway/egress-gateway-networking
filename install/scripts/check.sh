#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
k -n istio-system rollout status deployment/istiod --timeout=180s
k -n istio-system rollout status daemonset/istio-cni-node --timeout=180s
k -n istio-system get deployment/istiod -o json | jq -e --arg image "$ISTIOD_IMAGE" '.spec.template.spec.containers | any(.image == $image)' >/dev/null
k -n istio-system get daemonset/istio-cni-node -o json | jq -e --arg image "$ISTIO_CNI_IMAGE" '.spec.template.spec.containers | any(.image == $image)' >/dev/null
