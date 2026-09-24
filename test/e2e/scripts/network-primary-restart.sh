#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$(dirname "$0")/egress-lib.sh"
need_id
[[ $(jq -r .profile "$state_dir/environment.json") == calico-istio ]] || exit 2
printf '%s\n' "$test_id" > "$state_dir/fault-active"
chain() { docker exec "$cluster-control-plane" cat /etc/cni/net.d/10-calico.conflist | jq '{name,plugins:[.plugins[]|{type,policy_setup_timeout_seconds}]}'; }
chain > "$artifacts/chain-before.json"
old=$(k -n calico-system get pods -l k8s-app=calico-node -o json | jq -er '.items|select(length==1)|.[0].metadata.name')
k -n calico-system get pod "$old" -o jsonpath='{.metadata.uid}' > "$artifacts/primary-before.uid"
k -n calico-system delete pod "$old" --wait=true --timeout=60s >/dev/null
k -n calico-system rollout status daemonset/calico-node --timeout=180s >/dev/null
k -n calico-system get pods -l k8s-app=calico-node -o json | jq -jer '.items|select(length==1)|.[0].metadata.uid' > "$artifacts/primary-after.uid"
if cmp -s "$artifacts/primary-before.uid" "$artifacts/primary-after.uid"; then
  echo 'Calico Pod UID did not change after restart' >&2
  exit 1
fi
deadline=$((SECONDS+30))
until chain > "$artifacts/chain-after.json" && jq -e '.plugins[0].type=="calico" and ([.plugins[]|select(.type=="istio-cni")]|length)==1' "$artifacts/chain-after.json" >/dev/null; do ((SECONDS<deadline)) || exit 1; sleep 0.2; done
"$BASH" "$root/test/e2e/scripts/egress-case.sh" --state-dir "$state_dir" --artifacts "$artifacts" --test-id "$test_id" --protocol http --target routed --client workload --phase fresh
source_pod=$(epod networking-egress workload)
k -n networking-egress get pod "$source_pod" -o json | jq -e '{uid:.metadata.uid,init:.spec.initContainers,status:.status.initContainerStatuses} | select((.init|all(.name!="istio-init")) and (.status|any(.name=="istio-validation" and .state.terminated.exitCode==0)))' > "$artifacts/new-pod-validation.json"
pid=$(sandbox_pid networking-egress "$source_pod")
docker exec "$cluster-control-plane" nsenter -t "$pid" -n iptables-save -t nat | rg_istio > "$artifacts/new-pod-redirect.txt"
grep -q -- '-A ISTIO_OUTPUT ' "$artifacts/new-pod-redirect.txt"
rm -f "$state_dir/fault-active"
