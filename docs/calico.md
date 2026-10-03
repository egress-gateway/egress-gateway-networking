# Independent foundation acceptance

The suite installs the pinned upstream Calico manifest and dataplane images on a new single-node
IPv4 kind cluster without another CNI. It retains iptables/VXLAN, kube-proxy,
effective `defaultEndpointToHostAction: Accept` after workload egress policy,
Calico CNI policy setup waiting and a chained tuning plugin that disables Pod IPv6
(all/default, including loopback) before business execution. Default installation
and standalone cases require no Istio or governance fixture. The bounded I1-01
[integration case](cni-composition.md) temporarily adds upstream Istio CNI and an
independent privileged initializer; it restores the standalone configuration afterward.

Installation verifies upstream manifest checksums and existing resource ownership;
refuses an initialized foreign primary network or any Operator installation; and
checks actual node CNI files, Felix environment and realized node policy rules.
It supports fresh installation and repeat application of owned resources, without
in-place migration or upgrades. The caller owns the cluster, workload objects and policies.

## Cases and evidence

- Plain Pod: selected namespace/Pod/TCP listener reachable; different Pod, namespace,
  port, UDP, external TCP/UDP/QUIC, default DNS TCP/UDP and node listener denied.
- Independent bindings and a Pod with trusted preparation/resident components:
  allowances remain separate; stopping or restarting the resident cannot widen them.
- Existing endpoint with Felix paused, newly created Pod/business init with Felix
  paused beyond actual CNI policy wait, healthy init/app earliest UDP and TCP attempts,
  recovery, new connection revocation and observation of existing TCP streams.
- Additive allow negative control deliberately permits a forbidden tuple. It must
  be detected as a violation, removed, and isolation reverified. Its command returns
  nonzero only as expected evidence when `negative-control.json` says verified=true.
- Explicit CNI composition and separately authorized network preparation retain
  startup denial, IPv6 closure and restricted business privileges through CNI/Calico
  restart and a policy-unavailable startup window. Actual in-Pod capture/preparation
  rules are observed; direct traffic proves confinement independently of a proxy.

Denial requires a real sender attempt and emission, a healthy stable receiver before
and after, complete lossless capture, and attributable Calico DROP evidence. A timeout,
missing sender, proxy failure, unrelated Pending or incomplete observer cannot pass.
Startup uses kernel netfilter-drop observation or a proven policy-related CNI sandbox
refusal. Node AF_PACKET precedes INPUT filtering, so node cases inspect listener
acceptance and enforcement rather than equating captured ingress with delivery.
Unattributed receiver traffic is inconclusive. Connection tuples and counters are
retained for diagnosis. No handwritten firewall rules provide isolation.

Fault cleanup verifies recovery, and an unrestored/uncertain fault prevents subsequent
cases from being counted as passed. The suite never silently translates a failed case
into a baseline success.

## Unsupported paths and API access

| Cases | Required evidence |
|---|---|
| N1-20-TCP, N1-21-TCP, C3-03-TCP, C3-04-TCP | Forbidden TCP packets, including SYN, never reach the healthy receiver from first execution or throughout the Felix fault, including beyond CNI timeout; restore and recreate the workload. |
| N1-22 | First business init and app observe disabled IPv6 on all/default/lo/eth0, no IPv6 addresses or usable routes, failed loopback/link-local TCP/UDP attempts and loopback listener creation, with working IPv4 and unchanged privileges. |
| N1-27 | Injected tuning failure prevents sandbox and business execution. Restore the exact CNI file, then prove new init/app IPv6 disablement and IPv4 functionality. |
| N1-23, N1-24, N1-25 | SCTP, ICMP and UDP-Lite: if available, actual source packets, Calico drops and healthy receiver non-delivery; if unavailable, a matching application socket error and full permission inventory. UDP-Lite uses an independently reachable external receiver because Calico can reject it as INVALID even from an unselected Pod. |
| N1-26 | AF_INET/AF_INET6 × STREAM/DGRAM/RAW/RDM/SEQPACKET/DCCP × IP protocol numbers 0–255: all 3,072 socket outcomes, actual protocol mapping and application capabilities. Remaining protocols must be unavailable; unexpected available modes fail acceptance. Known protocols and IPv6 communication have separate cases. |
| A1-01–A1-08 | Direct API endpoint and Kubernetes Service: default deny, precise endpoint allow, wrong-port deny and new-connection deny after allowance removal. Policies use the public generator. Denial correlates the source socket and time window with the kernel drop at the actual endpoint after translation, plus healthy before/after controls. |

A refused connection or unavailable probe is not isolation proof. IPv6 disablement
removes loopback communication but does not require the AF_INET6 socket API to be
absent. IPv4-mapped traffic remains subject to IPv4 policy. The node/API result is
specific to this Calico installation; host-network workloads are outside the
supported workload contract. API authentication, credentials and authorization
remain platform responsibilities. No implicit system/API allowance is generated.

## Commands and lifecycle

`make e2e` creates, tests, diagnoses and removes its own environment. Retained mode is
`make e2e-up`, `make e2e-test`, `make e2e-test`, `make e2e-down`. Installation/configuration
fingerprint changes refuse reuse, while down still verifies resource ownership before
cleanup. Legacy retained profiles cannot run the new suite. Use the same `--state-dir`
for every command. A test failure in retained mode preserves its environment.

`--tags` is for development only. Reports register every case before setup, preserve
not_run on interruption, and reject incomplete full acceptance. `.e2e/state` contains
private kubeconfig/certificates and must never be uploaded. `.e2e/artifacts` contains
safe reports and allowlisted diagnostics. Local tests and remote CI are separate
proofs and must identify their exact revision and dirty state.
