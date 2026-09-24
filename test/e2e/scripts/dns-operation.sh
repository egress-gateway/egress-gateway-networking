#!/usr/bin/env bash
# Concrete DNS fixture operations. Go owns ordering, waits, observers and recovery.
source "$(dirname "$0")/common.sh"
source "$(dirname "$0")/egress-lib.sh"
need_id
case "$phase" in
 discover)
  receiver_snapshot origin > "$artifacts/external-before.json"
  receiver_owned quic
  pods=$(k -n kube-system get pod -l k8s-app=kube-dns -o json)
  endpoints='[]'
  while read -r name ip; do
    pid=$(sandbox_pid kube-system "$name")
    endpoints=$(jq --arg name "$name" --arg ip "$ip" --arg pid "$pid" '.+[{name:$name,ip:$ip,pid:$pid}]' <<< "$endpoints")
  done < <(jq -r '.items|sort_by(.metadata.name)|.[]|[.metadata.name,.status.podIP]|@tsv' <<< "$pods")
  source_ns=networking-dns source_pod=client
  if [[ "$target" == egress-external ]]; then source_ns=networking-egress; source_pod=$(epod "$source_ns" workload); fi
  jq -n --arg cluster "$cluster" --arg external "$(jq -r .origin "$state_dir/egress.json")" --arg control "$(epod networking-controls control)" --arg service "$(k -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}')" --arg ns "$source_ns" --arg pod "$source_pod" --argjson endpoints "$endpoints" '{cluster:$cluster,external:$external,control:$control,service:$service,namespace:$ns,pod:$pod,endpoints:$endpoints}' > "$artifacts/discovery.json"
  ;;
 create)
  export DNS_CLIENT="dns-$test_id" PROBE_IMAGE ISTIOD_IP
  PROBE_IMAGE=$(cat "$state_dir/probe-image"); ISTIOD_IP=$(jq -r .istiod "$state_dir/dns/addresses.json")
  external_ip=$(jq -r .origin "$state_dir/egress.json")
  envsubst '${DNS_CLIENT} ${PROBE_IMAGE} ${ISTIOD_IP}' < "$root/test/e2e/config/dns-client.yaml" | k create --dry-run=client -f - -o json | protected_pod |
    jq --arg mode "$target" --arg external "$external_ip" '
      if $mode=="capture-off" then .metadata.annotations["proxy.istio.io/config"]="holdApplicationUntilProxyStarts: false\nproxyMetadata:\n  ISTIO_META_DNS_CAPTURE: \"false\"\n"
      elif $mode=="capture-excluded" then .metadata.annotations["traffic.sidecar.istio.io/excludeOutboundPorts"]="53"
      elif $mode=="proxy-uid" then .spec.containers[0].securityContext.runAsUser=1337
      elif $mode=="nameserver" then .spec.dnsPolicy="None"|.spec.dnsConfig={nameservers:[$external]}
      else . end' | k create -f -
  ;;
 source)
  source_ns=$target source_pod=$client
  source_pid=$(sandbox_pid "$source_ns" "$source_pod")
  k -n "$source_ns" get pod "$source_pod" -o json | jq '{namespace:.metadata.namespace,name:.metadata.name,uid:.metadata.uid,ip:.status.podIP,annotations:.metadata.annotations,hostAliases:.spec.hostAliases,security:[.spec.containers[]|{name,securityContext}],status:.status}' > "$artifacts/pod-before.json"
  printf '%s' "$source_pid" > "$artifacts/source-pid"
  docker exec "$cluster-control-plane" nsenter -t "$source_pid" -n iptables-save -t nat > "$artifacts/redirect-nft.txt"
  docker exec "$cluster-control-plane" nsenter -t "$source_pid" -n iptables-legacy-save -t nat > "$artifacts/redirect-legacy.txt"
  cat "$artifacts/redirect-nft.txt" "$artifacts/redirect-legacy.txt" > "$artifacts/redirect.txt"
  ;;
 suspend)
  envoy=$(envoy_pid "$target" "$client")
  parent=$(docker exec "$cluster-control-plane" ps -o ppid= -p "$envoy" | tr -d ' ')
  [[ "$parent" =~ ^[0-9]+$ ]]
  # Persist the recovery target before mutating process state.
  printf '%s\n%s\n' "$parent" "$envoy" > "$artifacts/suspended-pids"
  docker exec "$cluster-control-plane" kill -STOP "$parent" "$envoy"
  docker exec "$cluster-control-plane" ps -o pid=,stat= -p "$parent,$envoy" > "$artifacts/stopped.txt"
  awk 'NF!=2 || $2 !~ /T/ {exit 1} END {if(NR!=2) exit 1}' "$artifacts/stopped.txt"
  ;;
 snapshot)
  receiver_snapshot origin > "$artifacts/external-after.json"
  cmp "$artifacts/external-before.json" "$artifacts/external-after.json"
  ;;
 *) echo 'unknown DNS fixture operation' >&2; exit 2;;
esac
