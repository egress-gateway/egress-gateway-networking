($ARGS.named.scope // "standalone") as $scope |
.name=="k8s-pod-network" and .cniVersion=="1.0.0" and
(if $scope=="standalone" then (.plugins|length)==3
 elif $scope=="foundation" then (.plugins|length)>=3
 else false end) and
.plugins[0].type=="calico" and .plugins[0].policy_setup_timeout_seconds==10 and
.plugins[0].ipam.type=="calico-ipam" and .plugins[0].ipam.assign_ipv4=="true" and .plugins[0].ipam.assign_ipv6=="false" and
.plugins[1].type=="tuning" and (.plugins[1].sysctl|length)==2 and
.plugins[1].sysctl["net.ipv6.conf.all.disable_ipv6"]=="1" and
.plugins[1].sysctl["net.ipv6.conf.default.disable_ipv6"]=="1" and
.plugins[2].type=="portmap" and .plugins[2].snat==true and
.plugins[2].capabilities.portMappings==true
