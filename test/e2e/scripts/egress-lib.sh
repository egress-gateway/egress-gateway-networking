#!/usr/bin/env bash
# Sourced after common.sh has verified this invocation's owned kind node.
node_stamp() {
  # Probes and Kubernetes timestamps use the Linux node clock; the host runner
  # can have a different clock when Docker runs inside a VM.
  docker exec "$cluster-control-plane" date -u "${1:-+%Y-%m-%dT%H:%M:%S.%NZ}"
}
epod() {
  k -n "$1" get pods -l "app=$2" -o json | jq -er '.items | map(select(.metadata.deletionTimestamp == null)) | if length == 1 then .[0].metadata.name else error("ambiguous fixture Pod") end'
}
receiver_owned() {
  local role=$1 info
  info=$(docker inspect "$cluster-$role")
  jq -e --arg owner "$state_dir/owner" --arg cluster "$cluster" '.[0] | .Config.Labels["networking.e2e.cluster"] == $cluster and any(.Mounts[]; .Source == $owner and .Destination == "/owner" and .RW == false)' <<< "$info" >/dev/null
  [[ "$(jq -r '.[0].Id' <<< "$info")" == "$(cat "$state_dir/$role-id")" ]] || { echo 'receiver identity changed' >&2; return 1; }
}
receiver_snapshot() {
  receiver_owned "$1"
  docker inspect "$cluster-$1" | jq -ce '.[0]|select(.State.Running==true)|{id:.Id,started:.State.StartedAt,restarts:.RestartCount}'
}
pod_snapshot() {
  k -n "$1" get pod "$2" -o json | jq -c '{uid:.metadata.uid,ip:.status.podIP,containers:([.status.containerStatuses[]?,.status.initContainerStatuses[]?]|map({name,containerID,restartCount}))}'
}
sandbox_pid() {
  local ns=$1 name=$2 uid sid info
  uid=$(k -n "$ns" get pod "$name" -o jsonpath='{.metadata.uid}')
  sid=$(docker exec "$cluster-control-plane" crictl pods --namespace "^$ns$" --name "^$name$" --state Ready -q)
  [[ "$sid" =~ ^[a-f0-9]+$ ]] || { echo 'ambiguous sandbox' >&2; return 1; }
  info=$(docker exec "$cluster-control-plane" crictl inspectp "$sid")
  [[ "$(jq -r '.status.metadata.uid' <<< "$info")" == "$uid" ]] || { echo 'sandbox UID mismatch' >&2; return 1; }
  jq -er '.info.pid | select(. > 0)' <<< "$info"
}
