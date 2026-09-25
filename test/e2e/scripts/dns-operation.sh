#!/usr/bin/env bash
# Concrete DNS fixture operations. Go owns ordering, waits, observers and recovery.
source "$(dirname "$0")/common.sh"
source "$(dirname "$0")/egress-lib.sh"
case "$dns_lane" in ''|records|destinations|bypass|lifecycle) ;; *) echo 'invalid DNS lane' >&2; exit 2;; esac
export DNS_NAMESPACE="networking-dns${dns_lane:+-$dns_lane}"
dns_state="$state_dir/dns${dns_lane:+-$dns_lane}"
dns_role="${dns_lane:+dns-$dns_lane}"
dns_role=${dns_role:-origin}
need_id
case "$phase" in
 resolver-allow)
  ip=$(jq -r .istiod "$dns_state/addresses.json")
  external_ip=$(cat "$dns_state/external-ip")
  "$NETWORKING_E2E_BIN" render-fixture --policy --namespace "$DNS_NAMESPACE" --istiod-ip "$ip" --resolver "$external_ip" | k apply -f -
  ;;
 resolver-revoke)
  enrollment_policy "$DNS_NAMESPACE"
  ;;
 discover)
  receiver_snapshot "$dns_role" > "$artifacts/external-before.json"
  external_ip=$(jq -r .origin "$state_dir/egress.json")
  if [[ -n "$dns_lane" ]]; then external_ip=$(cat "$dns_state/external-ip"); fi
  pods=$(k -n kube-system get pod -l k8s-app=kube-dns -o json)
  endpoints='[]'
  while read -r name ip; do
    pid=$(sandbox_pid kube-system "$name")
    endpoints=$(jq --arg name "$name" --arg ip "$ip" --arg pid "$pid" '.+[{name:$name,ip:$ip,pid:$pid}]' <<< "$endpoints")
  done < <(jq -r '.items|sort_by(.metadata.name)|.[]|[.metadata.name,.status.podIP]|@tsv' <<< "$pods")
  source_ns=$DNS_NAMESPACE source_pod=client
  if [[ "$target" == egress-external ]]; then source_ns=networking-egress; source_pod=$(epod "$source_ns" workload); fi
  jq -n --arg cluster "$cluster" --arg external "$external_ip" --arg receiver "$cluster-$dns_role" --arg control control --arg controlNS "$DNS_NAMESPACE" --arg service "$(k -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}')" --arg ns "$source_ns" --arg pod "$source_pod" --argjson endpoints "$endpoints" '{cluster:$cluster,external:$external,control:$control,controlNamespace:$controlNS,externalContainer:$receiver,service:$service,namespace:$ns,pod:$pod,endpoints:$endpoints}' > "$artifacts/discovery.json"
  ;;
 create)
  export DNS_CLIENT="dns-$test_id" PROBE_IMAGE ISTIOD_IP
  PROBE_IMAGE=$(cat "$state_dir/probe-image"); ISTIOD_IP=$(jq -r .istiod "$dns_state/addresses.json")
  external_ip=$(jq -r .origin "$state_dir/egress.json")
  if [[ -n "$dns_lane" ]]; then external_ip=$(cat "$dns_state/external-ip"); fi
  envsubst '${DNS_CLIENT} ${PROBE_IMAGE} ${ISTIOD_IP} ${DNS_NAMESPACE}' < "$root/test/e2e/config/dns-client.yaml" | k create --dry-run=client -f - -o json | protected_pod |
    jq --arg mode "$target" --arg external "$external_ip" '
      if ($mode=="capture-off" or ($mode|startswith("resolver-direct"))) then (.spec.initContainers[]|select(.name=="istio-proxy")|.env[]|select(.name=="ISTIO_META_DNS_CAPTURE")|.value)="false" | (.spec.initContainers[]|select(.name=="istio-proxy")|.env[]|select(.name=="PROXY_CONFIG")|.value) |= (fromjson | .proxyMetadata.ISTIO_META_DNS_CAPTURE="false" | tojson)
      elif $mode=="broken-dns" then (.spec.initContainers[]|select(.name=="istio-proxy")|.env[]|select(.name=="DNS_PROXY_ADDR")|.value)="localhost:16053"
      elif $mode=="capture-excluded" then .metadata.annotations["traffic.sidecar.istio.io/excludeOutboundPorts"]="53"
      elif $mode=="proxy-uid" then .spec.containers[0].securityContext.runAsUser=1337
      elif $mode=="nameserver" then .spec.dnsPolicy="None"|.spec.dnsConfig={nameservers:[$external]}
      else . end
      | if $mode=="resolver-fallback-other" then .spec.dnsPolicy="ClusterFirst" | del(.spec.dnsConfig) elif ($mode|startswith("resolver-")) then .spec.dnsPolicy="None" | .spec.dnsConfig={nameservers:[$external]} else . end' | k create -f -
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
  receiver_snapshot "$dns_role" > "$artifacts/external-after.json"
  cmp "$artifacts/external-before.json" "$artifacts/external-after.json"
  ;;
 *) echo 'unknown DNS fixture operation' >&2; exit 2;;
esac
