#!/usr/bin/env bash
# A complete private probe operation; Go owns the security verdict.
source "$(dirname "$0")/common.sh"
source "$(dirname "$0")/egress-lib.sh"
source "$(dirname "$0")/calico-fault-lib.sh"
need_id
if [[ "$phase" == felix-new || "$phase" == felix-init ]]; then
  exec "$BASH" "$root/test/e2e/scripts/network-startup.sh" --state-dir "$state_dir" --artifacts "$artifacts" --test-id "$test_id" --protocol "$protocol" --target "$target" --phase "$phase"
fi
if [[ "$phase" == primary-restart ]]; then
  exec "$BASH" "$root/test/e2e/scripts/network-primary-restart.sh" --state-dir "$state_dir" --artifacts "$artifacts" --test-id "$test_id"
fi
if [[ "$phase" == existing-revoke ]]; then
  exec "$BASH" "$root/test/e2e/scripts/network-existing.sh" --state-dir "$state_dir" --artifacts "$artifacts" --test-id "$test_id"
fi
[[ "$(jq -r .profile "$state_dir/environment.json")" == calico-istio ]] || exit 2
case "$phase" in healthy|capture|proxy-uid|exclusion|felix-stopped|felix-recovery|revoke) ;; *) echo "unsupported network phase: $phase" >&2; exit 2;; esac
source_ns=networking-np source_pod=client
receiver_ns=networking-np receiver_pod=httpbin receiver_container=httpbin
port=8080 httpbin=(--httpbin)
control=(k -n networking-np-other exec control -- /probe)
started=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
if [[ "$target" != np-* ]]; then
  source_ns=networking-egress; source_pod=$(epod "$source_ns" plain)
  httpbin=()
fi
case "$target" in
  np-service) ip=$(k -n networking-np get service httpbin -o jsonpath='{.spec.clusterIP}'); port=8000 ;;
  np-ip|np-wrong|np-udp) ip=$(k -n networking-np get pod httpbin -o jsonpath='{.status.podIP}');;
  np-other) receiver_pod=other; ip=$(k -n networking-np get pod other -o jsonpath='{.status.podIP}');;
  np-cross) receiver_ns=networking-np-other; ip=$(k -n "$receiver_ns" get pod httpbin -o jsonpath='{.status.podIP}');;
  np-external)
    receiver_owned origin; receiver_owned quic
    ip=$(jq -r .origin "$state_dir/egress.json"); port=9000
    [[ "$protocol" != udp ]] || port=9001
    receiver_ns='' receiver_pod='' receiver_container=''; httpbin=()
    control=(docker exec "$cluster-quic" /probe)
    ;;
  np-node)
    receiver_ns=networking-np-other receiver_pod=node receiver_container=probe
    ip=$(k get node "$cluster-control-plane" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}'); port=18081
    receiver_owned origin; control=(docker exec "$cluster-origin" /probe); httpbin=()
    ;;
  mesh-external)
    receiver_owned origin; receiver_owned quic
    ip=$(jq -r .origin "$state_dir/egress.json"); port=9000
    [[ "$protocol" != dns-tcp ]] || port=53
    receiver_ns='' receiver_pod='' receiver_container=''
    control=(docker exec "$cluster-quic" /probe)
    if [[ "$phase" == capture ]]; then source_pod=$(epod "$source_ns" workload); fi
    ;;
  gateway-neighbor|dns-neighbor|istiod-neighbor)
    receiver_ns=networking-gateway; port=15443
    if [[ "$target" == dns-neighbor ]]; then receiver_ns=kube-system; port=53; fi
    if [[ "$target" == istiod-neighbor ]]; then receiver_ns=istio-system; port=15012; fi
    receiver_pod=network-neighbor receiver_container=probe
    ip=$(k -n "$receiver_ns" get pod "$receiver_pod" -o jsonpath='{.status.podIP}')
    ;;
  dns-endpoint|dns-wrong)
    receiver_ns=kube-system receiver_container=coredns
    receiver_pod=$(k -n kube-system get pods -l k8s-app=kube-dns -o json | jq -er '.items|sort_by(.metadata.name)|.[0].metadata.name')
    ip=$(k -n "$receiver_ns" get pod "$receiver_pod" -o jsonpath='{.status.podIP}'); port=53
    httpbin=(--query kubernetes.default.svc.cluster.local)
    if [[ "$target" == dns-wrong ]]; then port=9153; httpbin=(--connect-only); fi
    ;;
  istiod-wrong)
    receiver_ns=istio-system receiver_container=discovery
    receiver_pod=$(epod istio-system istiod)
    ip=$(k -n "$receiver_ns" get pod "$receiver_pod" -o jsonpath='{.status.podIP}'); port=15014
    httpbin=(--connect-only)
    ;;
  gateway-endpoint|gateway-tls-endpoint)
    source_pod=$(epod "$source_ns" workload)
    export GATEWAY_ENDPOINT
    GATEWAY_ENDPOINT=$(k -n networking-gateway get pod "$(epod networking-gateway gateway)" -o jsonpath='{.status.podIP}')
    envsubst '${GATEWAY_ENDPOINT}' < "$root/test/e2e/config/gateway-endpoint.yaml" | k apply -f - >/dev/null
    deadline=$((SECONDS+30))
    until k -n "$source_ns" exec "$source_pod" -c istio-proxy -- pilot-agent request GET clusters | grep -q 'outbound|15443||gateway-endpoint.test'; do ((SECONDS < deadline)) || exit 1; sleep 0.2; done
    ip=$GATEWAY_ENDPOINT port=15443
    httpbin=(--host gateway-endpoint.test)
    if [[ "$protocol" == https ]]; then port=15444; httpbin+=(--server-name origin.test); fi
    receiver_owned origin; receiver_owned quic
    receiver_ns='' receiver_pod='' receiver_container=''
    control=(docker exec "$cluster-quic" /probe)
    ;;
  *) echo "unsupported network target: $target" >&2; exit 2;;
esac
if [[ "$target" == np-wrong || "$target" == np-udp ]]; then port=19090; receiver_container=wrong-port; httpbin=(); fi
address="$ip:$port"
source_ip=$(k -n "$source_ns" get pod "$source_pod" -o jsonpath='{.status.podIP}')
interface=$(endpoint_interface "$source_ns" "$source_pod")
[[ "$interface" =~ ^cali[a-f0-9]+$ ]] || exit 2
sender=(docker exec "$cluster-control-plane" /networking-probe)
if [[ -z "$receiver_ns" ]]; then
  receiver=(docker exec "$cluster-origin" /probe)
  before=$(receiver_snapshot origin)
else
  receiver_pid=$(sandbox_pid "$receiver_ns" "$receiver_pod")
  receiver=(docker exec "$cluster-control-plane" nsenter -t "$receiver_pid" -n /networking-probe)
  before=$(pod_snapshot "$receiver_ns" "$receiver_pod")
fi
receiver_port=$port
[[ "$target" != np-service ]] || receiver_port=8080
control_address=$address; control_extra=("${httpbin[@]}")
if [[ "$target" == gateway-endpoint || "$target" == gateway-tls-endpoint ]]; then
  receiver_port=8080; [[ "$protocol" != https ]] || receiver_port=443
  control_address="$(jq -r .origin "$state_dir/egress.json"):$receiver_port"
  control_extra=(--ca /certs/ca.pem)
fi
capture_pids=() capture_roles=()
finish_capture() {
  local i role
  for i in "${!capture_pids[@]}"; do
    role=${capture_roles[$i]}
    if [[ "$role" == receiver ]]; then
      "${receiver[@]}" capture --port "$receiver_port" --stop-file "/$test_id-receiver-stop" --stop
    else
      "${sender[@]}" capture --port "$port" --stop-file "/$test_id-sender-stop" --stop
    fi
    wait "${capture_pids[$i]}" || return 1
  done
  capture_pids=()
}
felix_pid='' policy_added=false temporary_pod=''
cleanup_network() {
  local rc=$?
  finish_capture || rc=1
  felix_resume || rc=1
  if [[ "$policy_added" == true ]]; then k -n networking-np delete networkpolicy case-allow --ignore-not-found >/dev/null || rc=1; fi
  if [[ -n "$temporary_pod" ]]; then k -n networking-egress delete pod "$temporary_pod" --ignore-not-found --wait=true --timeout=60s >/dev/null || rc=1; fi
  if [[ "$rc" == 0 && -f "$state_dir/fault-active" && $(cat "$state_dir/fault-active") == "$test_id" ]]; then rm -f "$state_dir/fault-active"; fi
  exit "$rc"
}
trap cleanup_network EXIT
trap 'exit 130' INT TERM
# Only this source endpoint's outbound chain counters are eligible evidence.
snapshot_rules() {
  docker exec "$cluster-control-plane" iptables-save -c -t filter | awk -v chain="cali-fw-$interface" '$2=="-A" && $3==chain {print}'
}
case "$phase" in
  proxy-uid|exclusion)
    temporary_pod="bypass-$test_id"
    printf '%s\n' "$test_id" > "$state_dir/fault-active"
    k -n networking-egress get deployment workload -o json | jq --arg name "$temporary_pod" --arg phase "$phase" '{apiVersion:"v1",kind:"Pod",metadata:(.spec.template.metadata+{name:$name,namespace:"networking-egress"}),spec:.spec.template.spec} | .metadata.labels.app=$name | if $phase=="proxy-uid" then (.spec.containers[]|select(.name=="probe")|.securityContext.runAsUser)=1337 else .metadata.annotations["traffic.sidecar.istio.io/excludeOutboundPorts"]="9000" end' | k create -f - >/dev/null
    k -n networking-egress wait pod "$temporary_pod" --for=condition=Ready --timeout=120s >/dev/null
    source_pod=$temporary_pod
    source_ip=$(k -n "$source_ns" get pod "$source_pod" -o jsonpath='{.status.podIP}')
    interface=$(endpoint_interface "$source_ns" "$source_pod")
    pid=$(sandbox_pid "$source_ns" "$source_pod")
    docker exec "$cluster-control-plane" nsenter -t "$pid" -n iptables-save -t nat | rg_istio > "$artifacts/exclusion-rules.txt"
    if [[ "$phase" == proxy-uid ]]; then grep -E -- '--uid-owner 1337 .* -j RETURN|--uid-owner 1337 -j RETURN' "$artifacts/exclusion-rules.txt" >/dev/null
    else grep -E -- '--dport 9000 .* -j RETURN|--dport 9000 -j RETURN' "$artifacts/exclusion-rules.txt" >/dev/null; fi
    ;;
  felix-stopped) felix_pause;;
  felix-recovery) felix_pause; felix_resume;;
  revoke)
    printf '%s\n' "$test_id" > "$state_dir/fault-active"
    policy_added=true
    jq -n --arg ip "$ip" --argjson port "$port" --arg protocol "${protocol^^}" '{apiVersion:"networking.k8s.io/v1",kind:"NetworkPolicy",metadata:{name:"case-allow",namespace:"networking-np"},spec:{podSelector:{matchLabels:{"networking.egress/protected":"true"}},policyTypes:["Egress"],egress:[{to:[{ipBlock:{cidr:($ip+"/32")}}],ports:[{protocol:$protocol,port:$port}]}]}}' | k apply -f - >/dev/null
    k -n "$source_ns" exec "$source_pod" -- /probe request --protocol "$protocol" --target "$address" --id "$test_id-pre-update" --duration 15s --successes 2 --timeout 2s > "$artifacts/pre-update.jsonl"
    jq -se 'length>=2 and (.[-2:]|all(.success==true))' "$artifacts/pre-update.jsonl" >/dev/null
    k -n networking-np delete networkpolicy case-allow >/dev/null
    policy_added=false
    # Observe removal of the additive policy jump from this endpoint, not a sleep.
    deadline=$((SECONDS+30))
    until [[ "$(snapshot_rules | grep -c -- '-j cali-po-' || true)" == 1 ]]; do ((SECONDS < deadline)) || exit 1; sleep 0.1; done
    ;;
esac
for role in receiver sender; do
  output=packets capture_port=$receiver_port; cmd=("${receiver[@]}")
  capture_args=()
  if [[ "$role" == sender ]]; then output=sender capture_port=$port; cmd=("${sender[@]}"); capture_args=(--interface "$interface"); fi
  "${cmd[@]}" capture --port "$capture_port" --stop-file "/$test_id-$role-stop" "${capture_args[@]}" > "$artifacts/$output.jsonl" 2> "$artifacts/$output-error.txt" &
  capture_pids+=("$!"); capture_roles+=("$role")
  deadline=$((SECONDS+15))
  until jq -se 'any(.[];.event=="capture-ready")' "$artifacts/$output.jsonl" >/dev/null 2>&1; do
    kill -0 "$!" || exit 1
    ((SECONDS < deadline)) || exit 1
    sleep 0.1
  done
done

"${control[@]}" request --protocol "$protocol" --target "$control_address" --id "$test_id-control-before" --timeout 2s "${control_extra[@]}" > "$artifacts/control-before.jsonl"

snapshot_rules > "$artifacts/rules-before.txt"
k -n "$source_ns" exec "$source_pod" -c probe -- /probe request --protocol "$protocol" --target "$address" --id "$test_id" --timeout 2s "${httpbin[@]}" > "$artifacts/probe.jsonl"
snapshot_rules > "$artifacts/rules-after.txt"
transport=tcp; [[ "$protocol" != udp && "$protocol" != dns-udp ]] || transport=udp
docker exec "$cluster-control-plane" conntrack -L -p "$transport" --orig-src "$source_ip" --orig-dst "$ip" > "$artifacts/conntrack.txt" 2> "$artifacts/conntrack-status.txt" || true
receiver_ip=$ip
if [[ -n "$receiver_ns" ]]; then receiver_ip=$(k -n "$receiver_ns" get pod "$receiver_pod" -o jsonpath='{.status.podIP}'); fi
jq -n --arg source "$source_ip" --arg original "$address" --arg endpoint "$receiver_ip:$receiver_port" --arg protocol "$transport" '{source:$source,original_destination:$original,receiver_endpoint:$endpoint,protocol:$protocol}' > "$artifacts/tuple.json"
if [[ "$phase" == felix-stopped ]]; then felix_paused > "$artifacts/felix-during.txt"; fi
"${control[@]}" request --protocol "$protocol" --target "$control_address" --id "$test_id-control-after" --timeout 2s "${control_extra[@]}" > "$artifacts/control-after.jsonl"
finish_capture
if [[ "$phase" != healthy && "$phase" != capture ]]; then felix_resume; np_recovery; fi
if [[ -z "$receiver_ns" ]]; then
  after=$(receiver_snapshot origin)
  docker logs --since "$started" "$cluster-origin" > "$artifacts/receiver.log" 2>&1
else
  after=$(pod_snapshot "$receiver_ns" "$receiver_pod")
  k -n "$receiver_ns" logs "$receiver_pod" -c "$receiver_container" --since-time "$started" > "$artifacts/receiver.log"
fi
if [[ "$source_ns" == networking-egress && "$source_pod" != "$(epod networking-egress plain)" ]]; then
  jq -n --arg started "$started" --arg pod "$source_pod" --arg gateway "$(epod networking-gateway gateway)" '{started:$started,pod:$pod,gateway:$gateway}' > "$artifacts/network-log-context.json"
  k -n "$source_ns" logs "$source_pod" -c istio-proxy --since-time "$started" > "$artifacts/workload.log"
  k -n networking-gateway logs "$(epod networking-gateway gateway)" -c istio-proxy --since-time "$started" > "$artifacts/gateway.log"
fi
jq -n --arg id "$test_id" --arg source "$source_ip" --arg interface "$interface" --rawfile before "$artifacts/rules-before.txt" --rawfile after "$artifacts/rules-after.txt" '{id:$id,source_ip:$source,interface:$interface,before:$before,after:$after}' > "$artifacts/enforcement.json"
jq -n --arg id "$test_id" --arg protocol "$protocol" --arg target "$target" --arg phase "$phase" --arg source "$source_ip" --arg before "$before" --arg after "$after" --arg address "$address" '{id:$id,protocol:$protocol,target:$target,phase:$phase,source_ip:$source,receiver_before:$before,receiver_after:$after,address:$address,restored:true,fault_verified:true}' > "$artifacts/network.json"
