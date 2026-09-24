#!/usr/bin/env bash
# Render one protected Pod or Deployment JSON from stdin; never writes the cluster.
source "$(dirname "$0")/common.sh"
istiod_ip=$(k -n istio-system get service istiod -o jsonpath='{.spec.clusterIP}')
[[ "$istiod_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'IPv4 Istiod Service address required' >&2; exit 2; }
jq --arg ip "$istiod_ip" '
  def configure:
    if (.metadata.labels["networking.egress/protected"] != "true" and .metadata.labels["networking.dns/protected"] != "true") then error("protected Pod label required") else . end |
    ((.metadata.annotations["proxy.istio.io/config"] // "{}") | fromjson) as $config |
    .metadata.annotations["proxy.istio.io/config"] = ($config | .proxyMetadata.ISTIO_META_DNS_CAPTURE="true" | tojson) |
    .spec.hostAliases = ([.spec.hostAliases[]? | .hostnames -= ["istiod.istio-system.svc", "istiod.istio-system.svc.cluster.local"] | select(.hostnames|length>0)] + [{ip:$ip,hostnames:["istiod.istio-system.svc","istiod.istio-system.svc.cluster.local"]}]);
  if .kind=="Pod" then configure
  elif .kind=="Deployment" then .spec.template |= configure
  else error("expected a Pod or Deployment") end'
