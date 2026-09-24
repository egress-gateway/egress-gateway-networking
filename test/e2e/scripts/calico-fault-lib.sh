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

# Stop every startup observer before joining any job so one failure cannot
# leave the remaining captures running throughout recovery.
finish_observers() {
  local i role pid deadline rc=0
  ((${#jobs[@]} > 0)) || return 0
  for i in "${!jobs[@]}"; do
    role=${roles[$i]}
    if [[ "$role" == receiver ]]; then
      docker exec "$cluster-origin" /probe capture --port 9001 --stop-file "/$test_id-receiver-stop" --stop || rc=1
    elif [[ "$role" == sender ]]; then
      docker exec "$cluster-control-plane" /networking-probe capture --port 9001 --stop-file "/$test_id-sender-stop" --stop || rc=1
    else
      docker exec "$cluster-control-plane" /networking-probe drops --target "$address" --stop-file "/$test_id-drops-stop" --stop || rc=1
    fi
  done
  deadline=$((SECONDS+5))
  for pid in "${jobs[@]}"; do
    while kill -0 "$pid" 2>/dev/null; do
      if ((SECONDS>=deadline)); then
        echo "startup observer did not stop: $pid" >&2
        kill "$pid" 2>/dev/null || true
        rc=1
        break
      fi
      sleep 0.1
    done
    wait "$pid" || rc=1
  done
  jobs=() roles=()
  return "$rc"
}
