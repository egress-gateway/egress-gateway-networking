#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
[[ $(jq -r .profile "$state_dir/environment.json") == calico ]]
"$NETWORKING_E2E_BIN" render-enrollment --image "$(cat "$state_dir/probe-image")" | k apply -f -
k -n networking-enrollment wait pod/a pod/b pod/trusted --for=condition=Ready --timeout=60s
