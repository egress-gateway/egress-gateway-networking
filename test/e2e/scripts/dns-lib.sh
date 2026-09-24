#!/usr/bin/env bash
# Private DNS acceptance helpers, sourced after common.sh ownership validation.
dns_wait() {
  local output=$1; shift
  local deadline=$((SECONDS+15))
  until jq -se 'any(.[];.event=="capture-ready" or .event=="drops-ready")' "$output" >/dev/null 2>&1; do
    kill -0 "$1" || return 1
    ((SECONDS<deadline)) || return 1
    sleep 0.1
  done
}
dns_capture() {
  local name=$1 pid=$2 port=${3:-53}
  local stop="/dns-$test_id-$name-stop"
  docker exec "$cluster-control-plane" nsenter -t "$pid" -n /networking-probe capture --interface eth0 --port "$port" --stop-file "$stop" > "$artifacts/$name.jsonl" 2> "$artifacts/$name.err" &
  observers+=("$!|capture|$pid|$stop|$name")
  [[ "$port" != 53 ]] || captures+=("$name.jsonl")
  dns_wait "$artifacts/$name.jsonl" "$!"
}
dns_drop() {
  local address=$1 name=$2 stop="/dns-$test_id-$2-stop"
  docker exec "$cluster-control-plane" /networking-probe drops --target "$address" --stop-file "$stop" > "$artifacts/$name.jsonl" 2> "$artifacts/$name.err" &
  observers+=("$!|drops|$address|$stop|$name")
  drop_files+=("$name.jsonl")
  dns_wait "$artifacts/$name.jsonl" "$!"
}
dns_stop_observers() {
  local entry process kind address stop name rc=0
  for entry in "${observers[@]}"; do
    IFS='|' read -r process kind address stop name <<< "$entry"
    if [[ "$kind" == external ]]; then
      docker exec "$cluster-origin" /probe capture --port 53 --stop-file "$stop" --stop || rc=1
    elif [[ "$kind" == capture ]]; then
      docker exec "$cluster-control-plane" nsenter -t "$address" -n /networking-probe capture --port 53 --stop-file "$stop" --stop || rc=1
    else
      docker exec "$cluster-control-plane" /networking-probe drops --target "$address" --stop-file "$stop" --stop || rc=1
    fi
    wait "$process" || rc=1
  done
  observers=()
  return "$rc"
}
dns_control() {
  local part=$1 n=0 ip
  for ip in "${dns_ips[@]}"; do
    local file="control-$part-$n.json"
    k -n networking-controls exec "$control_pod" -c probe -- /probe dns --query kubernetes.default.svc.cluster.local --target "$ip:53" --id "$test_id-control" --transport "$transport" --timeout 3s > "$artifacts/$file"
    controls+=("$file"); ((n+=1))
  done
  local file="control-$part-external.json"
  docker exec "$cluster-quic" /probe dns --query "$test_id.control.test" --target "$external_ip:53" --id "$test_id-control" --transport "$transport" --timeout 3s > "$artifacts/$file"
  controls+=("$file")
}
dns_make_client() {
  local mode=$1
  export DNS_CLIENT="dns-$test_id" PROBE_IMAGE ISTIOD_IP
  PROBE_IMAGE=$(cat "$state_dir/probe-image"); ISTIOD_IP=$(jq -r .istiod "$state_dir/dns/addresses.json")
  envsubst '${DNS_CLIENT} ${PROBE_IMAGE} ${ISTIOD_IP}' < "$root/test/e2e/config/dns-client.yaml" | k create --dry-run=client -f - -o json | protected_pod |
    jq --arg mode "$mode" --arg external "$external_ip" '
      if $mode=="bootstrap-default" then del(.spec.hostAliases)
      elif $mode=="capture-off" then .metadata.annotations["proxy.istio.io/config"]="holdApplicationUntilProxyStarts: false\nproxyMetadata:\n  ISTIO_META_DNS_CAPTURE: \"false\"\n"
      elif $mode=="capture-excluded" then .metadata.annotations["traffic.sidecar.istio.io/excludeOutboundPorts"]="53"
      elif $mode=="proxy-uid" then .spec.containers[0].securityContext.runAsUser=1337
      elif $mode=="nameserver" then .spec.dnsPolicy="None"|.spec.dnsConfig={nameservers:[$external]}
      else . end' > "$state_dir/dns/$DNS_CLIENT.json"
  k create -f "$state_dir/dns/$DNS_CLIENT.json" >/dev/null
  source_pod=$DNS_CLIENT
  local deadline=$((SECONDS+60))
  until [[ -n $(k -n networking-dns get pod "$source_pod" -o jsonpath='{.status.podIP}') ]]; do ((SECONDS<deadline)) || return 1; sleep 0.3; done
  if [[ "$mode" != bootstrap-default ]]; then k -n networking-dns wait pod/"$source_pod" --for=condition=Ready --timeout=90s >/dev/null; fi
}
dns_proxy_logs() {
  local deadline=$((SECONDS+10)) request=${1:-application.jsonl}
  while :; do
    k -n networking-dns logs "$source_pod" -c istio-proxy --since-time="$started" > "$artifacts/proxy.log"
    local local_address
    local_address=$(jq -r '.local // empty' "$artifacts/$request" | tail -1)
    if grep -F "$test_id" "$artifacts/proxy.log" >/dev/null || { [[ -n "$local_address" ]] && grep -F "$local_address" "$artifacts/proxy.log" >/dev/null; }; then break; fi
    ((SECONDS<deadline)) || break
    sleep 0.2
  done
}
dns_external_capture() {
  local port=${1:-53} name=${2:-receiver-external}
  local stop="/dns-$test_id-$name-stop"
  docker exec "$cluster-origin" /probe capture --interface eth0 --port "$port" --stop-file "$stop" > "$artifacts/$name.jsonl" 2> "$artifacts/$name.err" &
  observers+=("$!|external|external|$stop|$name")
  [[ "$port" != 53 ]] || captures+=("$name.jsonl")
  dns_wait "$artifacts/$name.jsonl" "$!"
}

dns_app_control() {
  local part=$1 app_protocol=http port=8080
  [[ "$mode" != https-* ]] || { app_protocol=https; port=8443; }
  [[ "$mode" != raw-tcp ]] || { app_protocol=tcp; port=9000; }
  k -n networking-controls exec "$control_pod" -c probe -- /probe request --protocol "$app_protocol" --target "$(jq -r .receiver "$state_dir/dns/addresses.json"):$port" --server-name one.origin.test --id "$test_id-control-app" --timeout 3s > "$artifacts/app-control-$part.json"
}
