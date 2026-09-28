#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
[[ -n "$artifacts" ]] || { echo '--artifacts required' >&2; exit 2; }
mkdir -p "$artifacts"
# Explicit allowlist: never export Secrets, kubeconfig or full proxy config dumps.
k version -o json > "$artifacts/kubernetes-version.json" 2>&1 || true
k get nodes -o wide > "$artifacts/nodes.txt" 2>&1 || true
k get pods -A -o wide > "$artifacts/pods.txt" 2>&1 || true
k get events -A --sort-by=.metadata.creationTimestamp > "$artifacts/events.txt" 2>&1 || true
k -n calico-system logs -l k8s-app=calico-node --all-containers --prefix --tail=1000 > "$artifacts/calico-node.log" 2>&1 || true
k get tigerastatus -o wide > "$artifacts/calico-status.txt" 2>&1 || true
