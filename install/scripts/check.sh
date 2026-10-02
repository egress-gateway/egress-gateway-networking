#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$root/install/calico/versions.env"
k -n calico-system rollout status daemonset/calico-node --timeout=180s
k -n calico-system rollout status deployment/calico-kube-controllers --timeout=180s
k -n kube-system rollout status daemonset/kube-proxy --timeout=120s
[[ -z "$(k get crd installations.operator.tigera.io --ignore-not-found -o name)" ]] || { echo 'Operator installation is unsupported' >&2; exit 2; }
k get felixconfigurations.crd.projectcalico.org default -o json | jq -e --arg owner "calico-static-$CALICO_VERSION" '.metadata.labels["networking.egress/managed"]==$owner and .spec.defaultEndpointToHostAction=="Accept" and .spec.bpfEnabled==false and .spec.ipv6Support==false and .spec.chainInsertMode=="Insert"' >/dev/null
k -n calico-system get daemonset calico-node -o json | jq -e --arg owner "calico-static-$CALICO_VERSION" -f "$root/install/scripts/check-node.jq" >/dev/null
k get ippools.crd.projectcalico.org -o json | jq -e '(.items|length)==1 and .items[0].spec.cidr=="10.244.0.0/16" and .items[0].spec.vxlanMode=="Always" and .items[0].spec.ipipMode=="Never"' >/dev/null
pods=$(k -n calico-system get pods -l k8s-app=calico-node -o json)
jq -e '(.items|length)>0 and all(.items[];.metadata.deletionTimestamp==null and .status.phase=="Running")' <<< "$pods" >/dev/null
while IFS= read -r pod; do
  # The node image already mounts CNI configuration and runs in the host network.
  # Inspect effective files and rules without another privileged workload.
  files=$(k -n calico-system exec "$pod" -c calico-node -- sh -c 'for f in /host/etc/cni/net.d/*.conf /host/etc/cni/net.d/*.conflist; do [ ! -f "$f" ] || basename "$f"; done')
  [[ "$files" == 10-calico.conflist ]] || { echo 'unexpected effective primary CNI files' >&2; exit 2; }
  k -n calico-system exec "$pod" -c calico-node -- cat /host/etc/cni/net.d/10-calico.conflist | jq -e --arg scope "$cni_scope" -f "$root/install/scripts/check-cni.jq" >/dev/null
  effective=$(k -n calico-system exec "$pod" -c calico-node -- sh -c 'printf "%s|%s|%s|%s|%s" "$FELIX_DEFAULTENDPOINTTOHOSTACTION" "$FELIX_IPV6SUPPORT" "$FELIX_BPFENABLED" "$FELIX_ENDPOINTSTATUSPATHPREFIX" "$FELIX_CHAININSERTMODE"')
  [[ "$effective" == 'ACCEPT|false|false|/var/run/calico|Insert' ]] || { echo 'effective Felix environment differs' >&2; exit 2; }
  k -n calico-system exec "$pod" -c calico-node -- iptables -S cali-wl-to-host | awk '/^-A / {n++; if(n==1 && /-j cali-from-wl-dispatch$/) policy=1; if(n==2 && /Configured DefaultEndpointToHostAction/ && /-j ACCEPT$/) accept=1} END {exit !(n==2 && policy && accept)}'
done < <(jq -r '.items[].metadata.name' <<< "$pods")
