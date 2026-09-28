#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$root/install/calico/versions.env"
k -n calico-system rollout status daemonset/calico-node --timeout=180s
k -n calico-system rollout status deployment/calico-kube-controllers --timeout=180s
k -n kube-system rollout status daemonset/kube-proxy --timeout=120s
k get installations.operator.tigera.io default -o json | jq -e --arg owner "calico-$CALICO_VERSION" '.metadata.labels["networking.egress/managed"]==$owner and (.spec.calicoNetwork|.linuxPolicySetupTimeoutSeconds==10 and .linuxDataplane=="Iptables" and .bgp=="Disabled" and .kubeProxyManagement=="Disabled" and (.ipPools|length)==1 and .ipPools[0].encapsulation=="VXLAN")' >/dev/null
k get felixconfigurations.crd.projectcalico.org default -o json | jq -e '.spec.defaultEndpointToHostAction=="Drop" and .spec.bpfEnabled==false and .spec.ipv6Support==false and .spec.chainInsertMode=="Insert"' >/dev/null
