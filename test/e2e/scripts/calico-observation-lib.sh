#!/usr/bin/env bash
# Read-only kernel observation for the existing PR0.5 denial cases.
calico_observe_start() {
  drop_pid=''
  [[ $(jq -r '.profile // "istio-only"' "$state_dir/environment.json") == calico-istio ]] || return 0
  case "$target" in external|udp443|quic443|same|same-ip|other|other-ip|other-dns|node|wrong) ;; *) return 0;; esac
  drop_address=$address
  if [[ -n "$receiver_pod" ]]; then drop_address="$(k -n "$receiver_ns" get pod "$receiver_pod" -o jsonpath='{.status.podIP}'):${address##*:}"; fi
  jq -n --arg source "$source_ip" --arg original "$address" --arg endpoint "$drop_address" '{source:$source,original_destination:$original,receiver_endpoint:$endpoint}' > "$artifacts/tuple.json"
  docker exec "$cluster-control-plane" /networking-probe drops --target "$drop_address" --stop-file "/$test_id-drops-stop" > "$artifacts/drops.jsonl" 2> "$artifacts/drops-error.txt" & drop_pid=$!
  local deadline=$((SECONDS+15))
  until jq -se 'any(.[];.event=="drops-ready")' "$artifacts/drops.jsonl" >/dev/null 2>&1; do kill -0 "$drop_pid" || return 1; ((SECONDS<deadline)) || return 1; sleep 0.1; done
}
calico_observe_finish() {
  if [[ -n "${drop_pid:-}" ]]; then
    docker exec "$cluster-control-plane" /networking-probe drops --target "$drop_address" --stop-file "/$test_id-drops-stop" --stop || return 1
    wait "$drop_pid" || return 1
    drop_pid=''
    docker exec "$cluster-control-plane" conntrack -L --orig-src "$source_ip" > "$artifacts/conntrack.txt" 2> "$artifacts/conntrack-status.txt" || true
    local interface
    interface=$(jq -sr --arg source "$source_ip" '[.[]|select(.event=="netfilter-drop" and (.remote|startswith($source+":")))|.interface]|unique|if length==1 then .[0] else "" end' "$artifacts/drops.jsonl")
    jq -n --arg id "$test_id" --arg source "$source_ip" --arg interface "$interface" --arg address "$drop_address" '{id:$id,source_ip:$source,interface:$interface,address:$address}' > "$artifacts/enforcement.json"
  fi
}
