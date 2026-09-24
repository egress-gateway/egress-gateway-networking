#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$(dirname "$0")/egress-lib.sh"
source "$(dirname "$0")/dns-lib.sh"
need_id
mode=$target transport=$protocol qtype=$client
fault_mode=${mode%-tcp}
[[ -f "$state_dir/dns/ready" ]]
observers=() captures=() drop_files=() controls=()
source_pod=client stopped='' ready=false functional=false attempted=false fault_verified=true restored=false
external_ip=$(jq -r .origin "$state_dir/egress.json")
control_pod=$(epod networking-controls control)
receiver_owned origin; receiver_owned quic
receiver_snapshot origin > "$artifacts/external-before.json"
mapfile -t dns_pods < <(k -n kube-system get pod -l k8s-app=kube-dns -o json | jq -r '.items|sort_by(.metadata.name)|.[].metadata.name')
dns_ips=()
for pod_name in "${dns_pods[@]}"; do dns_ips+=("$(k -n kube-system get pod "$pod_name" -o jsonpath='{.status.podIP}')"); done
dns_service=$(k -n kube-system get service kube-dns -o jsonpath='{.spec.clusterIP}')
cleanup() {
  local rc=$?
  if [[ -n "$stopped" ]]; then docker exec "$cluster-control-plane" kill -CONT $stopped || rc=1; fi
  dns_stop_observers || rc=1
  if [[ "$source_pod" != client ]]; then k -n networking-dns delete pod "$source_pod" --ignore-not-found --wait=true --timeout=60s >/dev/null || rc=1; fi
  if [[ $rc != 0 ]]; then printf '%s\n' "$test_id" > "$state_dir/fault-active"; fi
  exit "$rc"
}
trap cleanup EXIT
case "$mode" in
  unregistered-http|unregistered-https)
    if [[ -f "$state_dir/dns/unregistered-gap.json" ]]; then
      jq -n --arg id "$test_id" --arg dependency "Unregistered synthesis failed; see $(cat "$state_dir/dns/unregistered-gap.json")" '{id:$id,dependency:$dependency}' > "$artifacts/dns-facts.json"
      exit 0
    else
      jq -n --arg id "$test_id" '{id:$id,dependency:"Unregistered-name prerequisite has not been established in this environment"}' > "$artifacts/dns-facts.json"
      exit 0
    fi;;
esac
dns_control before
case "$mode" in http-*|https-*|raw-tcp|stale-vip|restart|recreate) dns_app_control before;; esac
case "$mode" in
 restart|recreate)
   k -n networking-dns exec client -c probe -- /probe dns --query one.origin.test --id "$test_id-cache" > "$artifacts/cached.json"
   jq -e '.correlated and all(.answers[];startswith("240.240.")) and (.answers|length)>0' "$artifacts/cached.json" >/dev/null
   ;;
 capture-off-tcp|proxy-uid-tcp|sidecar-stopped-tcp)
   docker exec "$cluster-quic" /probe request --protocol tcp --target "$external_ip:9000" --id "$test_id-control-tcp" --timeout 3s > "$artifacts/tcp-control-before.json"
   dns_external_capture 9000 receiver-tcp
   dns_drop "$external_ip:9000" drops-tcp
   ;;
esac
n=0
for pod_name in "${dns_pods[@]}"; do
  dns_capture "receiver-dns-$n" "$(sandbox_pid kube-system "$pod_name")"
  dns_drop "${dns_ips[n]}:53" "drops-dns-$n"
  ((n+=1))
done
dns_external_capture
dns_drop "$external_ip:53" drops-external
case "$fault_mode" in
 bootstrap-default|bootstrap-mapped|capture-off|capture-excluded|proxy-uid|nameserver|recreate) dns_make_client "$fault_mode";;
esac
source_ip=$(k -n networking-dns get pod "$source_pod" -o jsonpath='{.status.podIP}')
source_pid=$(sandbox_pid networking-dns "$source_pod")
question="$test_id.unregistered.test"
case "$mode" in
 declared|edns|record)
   question="$test_id.origin.test"
   k -n networking-dns get serviceentry dns-origin -o json | jq --arg name "$question" 'del(.status)|.spec.hosts=(["one.origin.test","two.origin.test",$name])' | k apply -f - >/dev/null
   deadline=$((SECONDS+20))
   until k -n networking-dns exec "$source_pod" -c istio-proxy -- pilot-agent request GET clusters | grep -F "||$question::" >/dev/null; do ((SECONDS<deadline)) || exit 1; sleep 0.2; done
   ;;
 wildcard) question="$test_id.wild.origin.test";;
 other-suffix) question="$test_id.unregistered.invalid";;
 search) question="$test_id.external.test.networking-dns.svc.cluster.local";;
 http-one|https-one|restart|recreate|bootstrap-mapped) question=one.origin.test;;
 http-two|https-two) question=two.origin.test;;
 raw-tcp) question=tcp.origin.test;;
esac
# Missing capture and unsafe UID are fixture conditions, not supported inputs.
k -n networking-dns get pod "$source_pod" -o json | jq '{uid:.metadata.uid,ip:.status.podIP,annotations:.metadata.annotations,hostAliases:.spec.hostAliases,security:[.spec.containers[]|{name,securityContext}],status:.status}' > "$artifacts/pod-before.json"
docker exec "$cluster-control-plane" nsenter -t "$source_pid" -n iptables-save -t nat > "$artifacts/redirect-nft.txt"
docker exec "$cluster-control-plane" nsenter -t "$source_pid" -n iptables-legacy-save -t nat > "$artifacts/redirect-legacy.txt"
cat "$artifacts/redirect-nft.txt" "$artifacts/redirect-legacy.txt" > "$artifacts/redirect.txt"
if [[ "$fault_mode" == capture-off ]]; then ! grep -q -- '--dport 53.*15053' "$artifacts/redirect.txt" || fault_verified=false; fi
if [[ "$fault_mode" == capture-excluded ]]; then
  [[ $(jq -r '.annotations["traffic.sidecar.istio.io/excludeOutboundPorts"]' "$artifacts/pod-before.json") == 53 ]] || fault_verified=false
  grep -q -- '--dport 53 -j RETURN' "$artifacts/redirect.txt" || fault_verified=false
fi
if [[ "$fault_mode" == proxy-uid ]]; then [[ $(jq -r '.security[]|select(.name=="probe")|.securityContext.runAsUser' "$artifacts/pod-before.json") == 1337 ]] || fault_verified=false; fi
if [[ "$fault_mode" == sidecar-stopped ]]; then
  envoy=$(envoy_pid networking-dns "$source_pod")
  parent=$(docker exec "$cluster-control-plane" ps -o ppid= -p "$envoy" | tr -d ' ')
  stopped="$parent $envoy"
  docker exec "$cluster-control-plane" kill -STOP $stopped
  docker exec "$cluster-control-plane" ps -o pid=,stat= -p "$parent,$envoy" > "$artifacts/stopped.txt"
  awk '$2 !~ /T/ {exit 1}' "$artifacts/stopped.txt" || fault_verified=false
fi
dns_capture source-dns "$source_pid"
case "$mode" in capture-off-tcp|proxy-uid-tcp|sidecar-stopped-tcp) dns_capture source-tcp "$source_pid" 9000;; esac
started=$(node_stamp)
# Record original destination and current endpoints for interpreting post-DNAT drops.
jq -n --arg source "$source_ip" --arg service "$dns_service" --arg external "$external_ip" --argjson endpoints "$(printf '%s\n' "${dns_ips[@]}" | jq -R . | jq -s .)" '{source:$source,service:$service,endpoints:$endpoints,external:$external}' > "$artifacts/dns-tuples.json"
case "$mode" in
 capture-off-tcp|proxy-uid-tcp|sidecar-stopped-tcp)
   attempted=true
   k -n networking-dns exec "$source_pod" -c probe -- /probe request --protocol tcp --target "$external_ip:9000" --id "$test_id" --timeout 4s > "$artifacts/forbidden-tcp.json" 2> "$artifacts/forbidden-tcp.err" || true
   if jq -e .success "$artifacts/forbidden-tcp.json" >/dev/null; then dns_proxy_logs forbidden-tcp.json; fi
   ;;
 http-*|https-*|raw-tcp)
   app_protocol=http port=8080
   [[ "$mode" != https-* ]] || { app_protocol=https; port=8443; }
   [[ "$mode" != raw-tcp ]] || { app_protocol=tcp; port=9000; }
   attempted=true
   k -n networking-dns exec "$source_pod" -c probe -- /probe request --protocol "$app_protocol" --target "$question:$port" --host "$question" --server-name "$question" --id "$test_id" --timeout 8s > "$artifacts/application.jsonl" 2> "$artifacts/application.err" || true
   dns_proxy_logs
   ;;
 bootstrap-default|bootstrap-mapped)
   attempted=true
   wait_time=25s; [[ "$mode" != bootstrap-mapped ]] || wait_time=90s
   k -n networking-dns wait pod/"$source_pod" --for=condition=Ready --timeout="$wait_time" > "$artifacts/ready.txt" 2>&1 && ready=true
   if [[ "$ready" == true ]]; then
     k -n networking-dns exec "$source_pod" -c istio-proxy -- pilot-agent request GET certs > "$artifacts/certificates.json"
     functional=true
   fi
   k -n networking-dns logs "$source_pod" -c istio-proxy --tail=100 > "$artifacts/bootstrap.log"
   ;;
 restart)
   attempted=true
   cid=$(k -n networking-dns get pod "$source_pod" -o json | jq -er '[.status.containerStatuses[]?,.status.initContainerStatuses[]?]|.[]|select(.name=="istio-proxy")|.containerID'); cid=${cid#containerd://}
   docker exec "$cluster-control-plane" crictl stop "$cid" >/dev/null
   deadline=$((SECONDS+90))
   until k -n networking-dns get pod "$source_pod" -o json | jq -e --arg cid "containerd://$cid" 'any(.status.containerStatuses[]?,.status.initContainerStatuses[]?; .name=="istio-proxy" and .containerID!=$cid and .ready)' >/dev/null; do ((SECONDS<deadline)) || exit 1; sleep 0.3; done
   k -n networking-dns exec "$source_pod" -c probe -- /probe dns --query "$question" --id "$test_id" > "$artifacts/query.json"
   functional=$(jq '.correlated and any(.answers[]?;startswith("240.240."))' "$artifacts/query.json")
   ;;
 recreate)
   attempted=true
   k -n networking-dns exec "$source_pod" -c probe -- /probe dns --query "$question" --id "$test_id" > "$artifacts/query.json"
   functional=$(jq '.correlated and any(.answers[]?;startswith("240.240."))' "$artifacts/query.json")
   ;;
 stale-vip)
   attempted=true
   question="$test_id.origin.test"
   k -n networking-dns get serviceentry dns-origin -o json | jq --arg name "$question" '.metadata={name:"dns-stale",namespace:"networking-dns"}|del(.status)|.spec.hosts=[$name]' | k apply -f - >/dev/null
   deadline=$((SECONDS+20))
   until k -n networking-dns exec "$source_pod" -c probe -- /probe dns --query "$question" --id "$test_id" --timeout 1s > "$artifacts/cached.json" 2>/dev/null && jq -e 'any(.answers[]?;startswith("240.240."))' "$artifacts/cached.json" >/dev/null; do ((SECONDS<deadline)) || exit 1; sleep 0.2; done
   vip=$(jq -r '.answers[0]' "$artifacts/cached.json")
   k -n networking-dns delete serviceentry dns-stale --wait=true >/dev/null
   deadline=$((SECONDS+20))
   while k -n networking-dns exec "$source_pod" -c istio-proxy -- pilot-agent request GET clusters | grep -F "||$question::" >/dev/null; do ((SECONDS<deadline)) || exit 1; sleep 0.2; done
   k -n networking-dns exec "$source_pod" -c probe -- /probe request --protocol http --target "$vip:8080" --host "$question" --id "$test_id" --timeout 4s > "$artifacts/application.jsonl" 2> "$artifacts/application.err" || true
   dns_proxy_logs
   ;;
 *)
   dns_target=()
   case "$mode" in service) dns_target=(--target "$dns_service:53");;endpoint) dns_target=(--target "${dns_ips[0]}:53");;external) dns_target=(--target "$external_ip:53");;esac
   [[ "$mode" != edns ]] || dns_target+=(--edns)
   attempted=true
   k -n networking-dns exec "$source_pod" -c probe -- /probe dns --query "$question" --qtype "$qtype" --transport "$transport" --id "$test_id" --timeout 7s "${dns_target[@]}" > "$artifacts/query.json" 2> "$artifacts/query.err" || true
   if [[ "$mode" == unregistered || "$mode" == other-suffix ]]; then
     if ! jq -e '.correlated and any(.answers[]?;startswith("240.240."))' "$artifacts/query.json" >/dev/null; then printf '%s\n' "$artifacts/query.json" > "$state_dir/dns/unregistered-gap.json"; fi
   fi
   ;;
esac
case "$mode" in
 restart|recreate)
   vip=$(jq -r '.answers[0]' "$artifacts/cached.json")
   k -n networking-dns exec "$source_pod" -c probe -- /probe request --protocol http --target "$vip:8080" --host one.origin.test --id "$test_id" --timeout 4s > "$artifacts/application.jsonl" 2> "$artifacts/application.err" || true
   dns_proxy_logs
   ;;
esac
docker exec "$cluster-control-plane" conntrack -L --orig-src "$source_ip" > "$artifacts/conntrack.txt" 2> "$artifacts/conntrack-status.txt" || true
dns_stop_observers
dns_control after
case "$mode" in http-*|https-*|raw-tcp|stale-vip|restart|recreate) dns_app_control after;; esac
case "$mode" in
 capture-off-tcp|proxy-uid-tcp|sidecar-stopped-tcp)
   docker exec "$cluster-quic" /probe request --protocol tcp --target "$external_ip:9000" --id "$test_id-control-tcp" --timeout 3s > "$artifacts/tcp-control-after.json";;
esac
if [[ -n "$stopped" ]]; then
  docker exec "$cluster-control-plane" kill -CONT $stopped
  stopped=''
  k -n networking-dns wait pod/"$source_pod" --for=condition=Ready --timeout=90s >/dev/null
  k -n networking-dns exec "$source_pod" -c probe -- /probe dns --query one.origin.test --id "$test_id-recovery" > "$artifacts/recovery.json"
  jq -e '.correlated and any(.answers[]?;startswith("240.240."))' "$artifacts/recovery.json" >/dev/null
fi
case "$fault_mode" in
 capture-off|capture-excluded|proxy-uid|nameserver|sidecar-stopped|restart|recreate|stale-vip|bootstrap-default|bootstrap-mapped)
   k -n networking-dns exec client -c probe -- /probe dns --query one.origin.test --id "$test_id-recovery" > "$artifacts/recovery.json"
   jq -e '.correlated and any(.answers[]?;startswith("240.240."))' "$artifacts/recovery.json" >/dev/null
   ;;
esac
k -n networking-dns get pod "$source_pod" -o json | jq '{uid:.metadata.uid,ip:.status.podIP,status:.status}' > "$artifacts/pod-after.json"
k -n networking-dns logs receiver --since-time="$started" > "$artifacts/receiver.log"
k -n networking-dns get pod receiver -o json | jq '{uid:.metadata.uid,ip:.status.podIP}' > "$artifacts/application-receiver.json"
receiver_snapshot origin > "$artifacts/external-after.json"
cmp "$artifacts/external-before.json" "$artifacts/external-after.json"
case "$fault_mode" in
 capture-off|capture-excluded|proxy-uid|nameserver|sidecar-stopped|restart|recreate|bootstrap-mapped)
   if [[ "$source_pod" != client ]]; then
     k -n networking-dns delete pod "$source_pod" --wait=true --timeout=60s >/dev/null
     source_pod=client
   fi
   "$BASH" "$root/test/e2e/scripts/dns-case.sh" --state-dir "$state_dir" --artifacts "$artifacts/recovery-isolation" --test-id "$test_id-recovery-isolation" --target unregistered --protocol "$transport" --client A
   ;;
esac
restored=true
case "$qtype" in A) type_number=1;;AAAA) type_number=28;;TXT) type_number=16;;SRV) type_number=33;;MX) type_number=15;;PTR) type_number=12;;NULL) type_number=10;;ANY) type_number=255;;esac
array_json() { printf '%s\n' "$@" | jq -R . | jq -s .; }
jq -n --arg id "$test_id" --arg mode "$mode" --arg name "$question." --arg source "$source_ip" --arg transport "$transport" --argjson type "$type_number" --argjson restored "$restored" --argjson fault "$fault_verified" --argjson ready "$ready" --argjson attempted "$attempted" --argjson functional "$functional" --argjson controls "$(array_json "${controls[@]}")" --argjson captures "$(array_json "${captures[@]}")" --argjson drops "$(array_json "${drop_files[@]}")" '{id:$id,mode:$mode,name:$name,source:$source,transport:$transport,type:$type,restored:$restored,fault_verified:$fault,ready:$ready,attempted:$attempted,functional:$functional,controls:$controls,captures:$captures,drop_files:$drops}' > "$artifacts/dns-facts.json"
