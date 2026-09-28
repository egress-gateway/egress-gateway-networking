# Independent foundation acceptance

The suite installs the pinned Calico operator/manifests/images on a new single-node
IPv4 kind cluster without another CNI. It retains iptables/VXLAN, kube-proxy,
`defaultEndpointToHostAction: Drop` and Calico CNI policy setup waiting. No Istio
installation, webhook, proxy image or governance fixture is involved.

Installation verifies upstream manifest checksums and existing resource ownership;
refuses an initialized foreign primary network; and checks effective supported
configuration. The caller owns the cluster, workload objects and policies.

## Cases and evidence

- Plain Pod: selected namespace/Pod/TCP listener reachable; different Pod, namespace,
  port, UDP, external TCP/UDP/QUIC, default DNS TCP/UDP and node listener denied.
- Independent bindings and a Pod with trusted preparation/resident components:
  allowances remain separate; stopping or restarting the resident cannot widen them.
- Existing endpoint with Felix paused, newly created Pod/business init with Felix
  paused beyond actual CNI policy wait, healthy init/app earliest UDP attempts,
  recovery, new connection revocation and observation of existing TCP streams.
- Additive allow negative control deliberately permits a forbidden tuple. It must
  be detected as a violation, removed, and isolation reverified. Its command returns
  nonzero only as expected evidence when `negative-control.json` says verified=true.

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
into a baseline success. #13 retains new protocol investigation and the four new TCP
first-packet cases; these tests do not claim coverage of arbitrary IPv4 protocols.

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
