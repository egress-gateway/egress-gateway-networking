.metadata.labels["networking.egress/managed"]==$owner and
([.spec.template.spec.containers[]|select(.name=="calico-node")|.env[]|select(.value!=null)|{key:.name,value:.value}]|from_entries|
.FELIX_DEFAULTENDPOINTTOHOSTACTION=="ACCEPT" and .FELIX_CHAININSERTMODE=="Insert" and
.FELIX_IPV6SUPPORT=="false" and .FELIX_BPFENABLED=="false" and
.FELIX_ENDPOINTSTATUSPATHPREFIX=="/var/run/calico" and
.CALICO_IPV4POOL_IPIP=="Never" and .CALICO_IPV4POOL_VXLAN=="Always")
