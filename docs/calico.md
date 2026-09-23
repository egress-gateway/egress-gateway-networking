# Calico candidate and acceptance

This profile installs Calico 3.32.2 using Tigera Operator 1.42.6, the iptables
dataplane, IPv4 VXLAN, BGP disabled and the existing kube-proxy. Release manifests
and all operator-selected images are pinned under `install/calico/`. Istio keeps
its official chained CNI, validation and repair configuration. Installation
creates infrastructure only; test scripts own applications and NetworkPolicies.

The profile is a candidate until the exact source head passes all local and CI
acceptance. A successful subset is not a fail-closed certificate.

## Topologies and trust boundary

The four original PR0 cases retain curl/Envoy to httpbin/Envoy. PR0.5 retains its
official Istio gateway and controlled external receiver; HTTP and HTTPS still use
workload-to-gateway mTLS, and HTTPS preserves application-to-origin TLS.

An independent `networking-np` fixture has no sidecars. Its unprivileged client
can reach only `app=httpbin` in that exact namespace on TCP 8080. Service port
8000 maps to that endpoint port. Other Services selecting the same allowed
endpoint are not a separate security identity. Wrong TCP/UDP ports have healthy
listeners. The cross-namespace fixture deliberately reuses the `app=httpbin`
label to verify the namespace/Pod selector intersection.

Protected mesh Pods have the same stable protection label across ordinary,
unmeshed, reconstructed and fault instances. Their default-deny egress policy
allows only these namespace/Pod/port intersections:

| Namespace | Pod selector | Protocol and endpoint ports |
|---|---|---|
| networking-gateway | app=gateway | TCP 15443, 15444 |
| kube-system | k8s-app=kube-dns | TCP/UDP 53 |
| istio-system | app=istiod | TCP 15012 |

The gateway fixture's own outgoing traffic is separate. Httpbin, unrelated Pods,
node listeners and external targets are not protected-workload allowlist entries.
Native Calico `defaultEndpointToHostAction: Drop` remains enabled. No handwritten
host firewall rule supplies isolation. NetworkPolicy identifies endpoints,
protocols and ports; it cannot distinguish an application from its sidecar.
Gateway mTLS/identity assertions remain necessary on the permitted endpoint.

Business containers gain no proxy settings, network scripts or elevated network
capabilities. UID/capture exclusions are deliberately unsafe test fixtures, not
supported business configuration. Raw TCP capture acceptance ends at the local
workload Envoy; no new raw TCP gateway listener is installed.

## Execution

```sh
make check
make e2e E2E_ARGS='--profile=istio-only --acceptance=baseline'
make e2e E2E_ARGS='--profile=calico-istio --acceptance=enforce'

make e2e-up E2E_ARGS='--profile=calico-istio'
make e2e-test E2E_ARGS='--profile=calico-istio --acceptance=enforce'
make e2e-test E2E_ARGS='--profile=calico-istio --acceptance=enforce'
make e2e-down
```

A clean Calico run creates one CNI-free kind cluster, waits for the API, installs
Calico, and runs the eight NP Godog cases before installing Istio. NP failure
leaves subsequent cases not run. A retained `up` prepares the full environment;
`test` runs NP first and then the combined/fault cases. Profile and installation
fingerprint mismatches refuse reuse. Change configuration using a new environment.

For focused development, `--tags=@c3-03,@c3-04` selects the two startup cases.
Unselected required cases stay `not_run`; a partial run cannot pass full acceptance.
Godog's comma means OR and `&&` means AND. Test execution never rewrites baseline
expectations. Shell operations remain independently runnable with explicit owned
state and artifact directories.

## Evidence and faults

The original 43 cases remain in the inventory. Eight NP and 22 combined cases
cover address/port intersections, DNS TCP, capture bypass, initial packets beyond
the actual CNI wait, paused Felix, primary restart, recovery and policy updates.
Each case has independent receiver health controls, stable receiver identity,
correlated probes and a bounded observation. Node health controls originate from
an external trusted test receiver, not another workload subject to host denial.

Receiver AF_PACKET capture is before host INPUT filtering. Node cases therefore
use listener acceptance plus attributable netfilter denial, rather than treating
every captured ingress packet as a delivered connection. Ordinary NP cases use
the source endpoint's dedicated Calico chain counter delta, source-interface
emission and complete receiver capture. Connection/NAT tuples are retained.

Faults and original mesh denial cases also use a private read-only
`skb:kfree_skb` tracepoint observer. `github.com/cilium/ebpf v0.22.0` is a Go loader
for this test observer, **not the Cilium CNI or a replacement dataplane**. The
observer filters to the owned receiver tuple and emits only IPv4/transport header
metadata and `NETFILTER_DROP` with the interface. It does not install traffic
hooks or modify firewall rules. Kernel BTF supplies offsets; missing kernel
facilities fail execution, never pass isolation. Links/maps are process-owned
and detached at the end of the observation. This provides endpoint evidence
even before Felix has created that new endpoint's policy chain.

Felix is paused only inside the owned kind environment and its process state is
verified across the observation. Application and init probes run after the
configured 10-second CNI policy wait expires. Recovery rechecks both allowed
HTTP and forbidden TCP using the same evidence-based classifier. Failed recovery
leaves a fault marker and stops subsequent scenarios. Do not delete that marker
without diagnosing and restoring the owned environment.

Policy updates prove new TCP and UDP denial after the endpoint policy changes.
The pre-existing TCP connection's observed behavior is reported separately;
immediate revocation of established conntrack state is not claimed.

## Negative detector control and CI

The additive-allow experiment uses a separate report and environment. It
temporarily permits the previously forbidden TCP tuple, calls the same denial
classifier, removes the extra policy and proves isolation again:

```sh
make e2e-up E2E_ARGS='--profile=calico-istio'
# Must exit nonzero and report X-ALLOW as violated.
make e2e-negative E2E_ARGS='--profile=calico-istio --acceptance=enforce'
go run ./cmd/networking-e2e summary
make e2e-down
```

The Summary confirms the detector experiment only when the deliberate violation,
recovery, finalized reports and terminal expected nonzero result all agree.
These observations are excluded from the normal safety-pass count. Missing
reports, execution errors or restoration failures cannot satisfy the control.

CI runs independent Istio baseline, Calico enforce and negative-control jobs,
alongside `make check`. Every job publishes its complete case table and uploads
Markdown/JSON/JUnit plus safe evidence. Reports include profile, source identity,
configuration fingerprint, actual image IDs, kernel/architecture, case durations
and operation timings. Credentials, private keys and full proxy/Secret dumps
remain outside artifacts.

## Support limits

Acceptance is limited to the fixed version combination actually exercised on a
single IPv4 node with TCP/UDP and restricted application privileges. Multi-node,
NodeLocal DNS, IPv6, SCTP/other IP protocols, privileged/hostNetwork workloads,
instant established-connection revocation and production upgrades are excluded.
They do not count as passed cases. Public enrollment and input validation remain
PR2. MITM, OPA and gateway/controller business behavior remain downstream-owned.
