#!/usr/bin/env bash
# Private fault helpers. No filter rule is inserted, removed or flushed.
felix_pause() {
  felix_pid=$(docker exec "$cluster-control-plane" pgrep -f '^calico-node -felix$')
  [[ "$felix_pid" =~ ^[0-9]+$ ]] || { echo 'Felix process is ambiguous' >&2; return 1; }
  printf '%s\n' "$test_id" > "$state_dir/fault-active"
  docker exec "$cluster-control-plane" kill -STOP "$felix_pid"
  felix_paused > "$artifacts/felix-stopped.txt"
}
felix_paused() { docker exec "$cluster-control-plane" ps -o pid=,stat=,args= -p "$felix_pid" | awk '$2 ~ /^T/ && /calico-node -felix/ {print; found=1} END {exit !found}'; }
felix_resume() {
  if [[ -n "${felix_pid:-}" ]]; then
    docker exec "$cluster-control-plane" kill -CONT "$felix_pid" || return 1
    felix_pid=''
    k -n calico-system rollout status daemonset/calico-node --timeout=90s >/dev/null || return 1
  fi
}
endpoint_interface() {
  local pid index
  pid=$(sandbox_pid "$1" "$2")
  index=$(docker exec "$cluster-control-plane" nsenter -t "$pid" -n ip -j link show dev eth0 | jq -er '.[0].link_index')
  docker exec "$cluster-control-plane" ip -j link show | jq -er --argjson index "$index" '.[]|select(.ifindex==$index)|.ifname'
}
np_recovery() {
  local allowed
  allowed=$(k -n networking-np get pod httpbin -o jsonpath='{.status.podIP}')
  k -n networking-np exec client -- /probe request --protocol http --target "$allowed:8080" --id "$test_id-recovery" --httpbin --duration 15s --successes 2 --timeout 2s > "$artifacts/recovery-allow.jsonl" || return 1
  jq -se 'length>=2 and (.[-2:]|all(.success==true))' "$artifacts/recovery-allow.jsonl" >/dev/null || return 1
  "$BASH" "$root/test/e2e/scripts/network-case.sh" --state-dir "$state_dir" --artifacts "$artifacts/recovery-deny" --test-id "$test_id-recovery-deny" --protocol tcp --target np-wrong --phase healthy
}
