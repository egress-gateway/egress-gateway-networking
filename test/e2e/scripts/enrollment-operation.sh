#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$(dirname "$0")/egress-lib.sh"
need_id
name="enrollment-$test_id"
if [[ "$phase" == listener-remove || "$phase" == listener-restore ]]; then
  if [[ "$phase" == listener-remove ]]; then
    jq -n '{apiVersion:"networking.istio.io/v1alpha3",kind:"EnvoyFilter",metadata:{name:"enrollment-listener-fault",namespace:"networking-egress"},spec:{workloadSelector:{labels:{app:"workload"}},configPatches:[{applyTo:"LISTENER",match:{context:"SIDECAR_OUTBOUND",listener:{portNumber:15001}},patch:{operation:"REMOVE"}}]}}' | k apply -f - >/dev/null
  else k -n networking-egress delete envoyfilter enrollment-listener-fault --ignore-not-found >/dev/null; fi
  source=$(epod networking-egress workload)
  deadline=$((SECONDS+30))
  while :; do
    k -n networking-egress exec "$source" -c istio-proxy -- pilot-agent request GET 'listeners?format=json' > "$artifacts/listener-transition.json"
    present=$(jq -r 'any(.listener_statuses[];.local_address.socket_address.port_value==15001)' "$artifacts/listener-transition.json")
    if [[ "$phase" == listener-remove && "$present" == false || "$phase" == listener-restore && "$present" == true ]]; then break; fi
    ((SECONDS<deadline)) || { echo 'listener transition was not observed' >&2; exit 1; }
    sleep 0.2
  done
  exit
fi
if [[ "$phase" == cleanup ]]; then
  k -n networking-egress delete pod "$name" "$name-ordinary" --ignore-not-found --wait=true --timeout=60s >/dev/null
  exit
fi
source=$(epod networking-egress workload)
if [[ "$phase" == privileges ]]; then
  k -n networking-egress exec "$source" -c probe -- /probe privileges --id "$test_id" > "$artifacts/privileges.json"
elif [[ "$phase" == injection ]]; then
  k -n networking-egress get pod "$source" -o json | jq '{uid:.metadata.uid,labels:.metadata.labels,names:[.spec.containers[].name],init:[.spec.initContainers[]|{name,restartPolicy}],status:[.status.initContainerStatuses[]?|{name,started,state}]}' > "$artifacts/enrolled.json"
  jq -n --arg name "$name-ordinary" --arg image "$(cat "$state_dir/probe-image")" '{apiVersion:"v1",kind:"Pod",metadata:{name:$name,namespace:"networking-egress"},spec:{containers:[{name:"probe",image:$image,imagePullPolicy:"Never",args:["idle"]}]}}' | k create -f - >/dev/null
  k -n networking-egress wait pod "$name-ordinary" --for=condition=Ready --timeout=90s >/dev/null
  k -n networking-egress get pod "$name-ordinary" -o json | jq '{uid:.metadata.uid,labels:.metadata.labels,names:[.spec.containers[].name],init:[.spec.initContainers[]|{name,restartPolicy}],status:[.status.initContainerStatuses[]?|{name,started,state}]}' > "$artifacts/ordinary.json"
elif [[ "$phase" == startup ]]; then
  k -n networking-egress get deployment workload -o json | jq --arg name "$name" --arg image "$(cat "$state_dir/probe-image")" --arg id "$test_id" '{apiVersion:"v1",kind:"Pod",metadata:(.spec.template.metadata+{name:$name,namespace:"networking-egress"}),spec:.spec.template.spec} | .metadata.labels.app=$name | .spec.terminationGracePeriodSeconds=1 | (.spec.initContainers[]|select(.name=="istio-proxy")|.startupProbe)={tcpSocket:{port:1},periodSeconds:1,timeoutSeconds:1,failureThreshold:1} | .spec.initContainers += [{name:"business-marker",image:$image,imagePullPolicy:"Never",args:["request","--protocol","tcp","--target","127.0.0.1:15021","--id",$id],securityContext:{runAsUser:10000,runAsGroup:10000,allowPrivilegeEscalation:false,capabilities:{drop:["ALL"]}}}]' | k create -f - >/dev/null
  deadline=$((SECONDS+60))
  until k -n networking-egress get pod "$name" -o json | jq -e 'any(.status.initContainerStatuses[]?;.name=="istio-proxy" and .restartCount>=1)' >/dev/null; do
    ((SECONDS<deadline)) || { echo 'startup failure was not exercised' >&2; exit 1; }
    sleep 0.2
  done
  k -n networking-egress get pod "$name" -o json | jq '{uid:.metadata.uid,init:[.status.initContainerStatuses[]?|{name,started,state,lastState,restartCount}],app:[.status.containerStatuses[]?|{name,started,state,lastState,restartCount}]}' > "$artifacts/startup.json"
else
  echo 'unknown enrollment operation' >&2; exit 2
fi
