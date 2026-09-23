#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
docker info >/dev/null
if docker inspect "$node" >/dev/null 2>&1; then
  node_owned
  kind delete cluster --name "$cluster"
fi
# Go removes state only after this script succeeds.
