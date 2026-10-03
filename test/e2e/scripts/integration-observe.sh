#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$(dirname "$0")/egress-lib.sh"
need_id
[[ "$client" == "startup-$test_id" ]] || exit 2
k -n networking-np wait "pod/$client" --for=condition=Ready --timeout=60s >/dev/null
mkdir -p "$artifacts/integration/first-init" "$artifacts/integration/app" "$artifacts/integration/preparation"
k -n networking-np logs "$client" -c prepare-network > "$artifacts/integration/preparation/observations.jsonl"
jq -c 'select(.event=="network-state")' "$artifacts/integration/preparation/observations.jsonl" > "$artifacts/integration/preparation/network-state.json"
jq -c 'select(.attempted==true and .protocol=="tcp")' "$artifacts/integration/preparation/observations.jsonl" >> "$artifacts/probe.jsonl"
for stage in first-init app; do
  container=first-probe; [[ "$stage" != app ]] || container=probe
  deadline=$((SECONDS+15))
  until k -n networking-np logs "$client" -c "$container" > "$artifacts/integration/$stage/observations.jsonl" && jq -se '[.[]|select(.event=="ipv6-attempt")]|length==5' "$artifacts/integration/$stage/observations.jsonl" >/dev/null; do ((SECONDS<deadline)) || exit 1; sleep .1; done
  jq -c 'select(.event=="network-state")' "$artifacts/integration/$stage/observations.jsonl" > "$artifacts/integration/$stage/network-state.json"
  jq -c 'select(.event=="ipv6-attempt")' "$artifacts/integration/$stage/observations.jsonl" > "$artifacts/integration/$stage/probe.jsonl"
done
ip=$(k -n networking-np get pod httpbin -o jsonpath='{.status.podIP}')
k -n networking-np exec "$client" -c probe -- /probe request --protocol http --target "$ip:8080" --httpbin --id "$test_id-ipv4" > "$artifacts/integration/ipv4.jsonl"
k -n networking-np get pod "$client" -o json | jq '{uid:.metadata.uid,created:.metadata.creationTimestamp,ip:.status.podIP,containers:[.status.initContainerStatuses[]?,.status.containerStatuses[]?]|map({name,state,restartCount,containerID})}' > "$artifacts/integration/pod.json"
pid=$(sandbox_pid networking-np "$client")
docker exec "$cluster-control-plane" nsenter -t "$pid" -n iptables-save -t nat > "$artifacts/integration/capture-rules.txt"
docker exec "$cluster-control-plane" nsenter -t "$pid" -n iptables-legacy-save -t filter > "$artifacts/integration/preparation-ipv4.txt"
docker exec "$cluster-control-plane" nsenter -t "$pid" -n ip6tables-legacy-save -t filter > "$artifacts/integration/preparation-ipv6.txt"
