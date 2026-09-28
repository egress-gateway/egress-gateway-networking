# Integration contract

## Ownership and call order

1. A trusted caller chooses a unique namespace/binding and composes the final Pod:
   business/init containers, trusted terminating preparation, resident components,
   volumes and startup conditions. Networking does not select a proxy or change order.
2. `ExpandPolicy(Network)` returns a `Policy` containing NetworkPolicy spec and
   binding labels. The caller assigns the resource name and preinstalls this policy.
3. `ExpandPod(finalPod, Options{Network, Trusted})` validates the complete composition
   and returns an independent Pod copy with the binding labels.
4. The platform performs final admission and creates the workload. Kubernetes/CNI
   must enforce the preinstalled policy before any init or business packet.

Both expansion functions are pure. Inputs remain unchanged; repeated calls,
including supported API-defaulted objects, are stable. Failure returns an error
identifying the field and no result. Resource naming, allocation, API writes,
reconciliation and synchronization with admission belong to the caller.

## Network permissions

`Peer` is either one exact IPv4 address or one namespace plus nonempty exact Pod
labels. `TCPDestination` adds explicit numeric ports. `Forward` describes normal
TCP peers, including control services. `DNS` separately allows TCP and UDP 53 to
its explicit peers. DNS is denied when omitted. No CIDR input, selector expressions,
unrestricted UDP, implicit control plane or default DNS allowance exists.

NetworkPolicy is additive and applies to the entire Pod. Other matching policies
can widen access; the platform must protect policy writes and binding/namespace/
endpoint labels. Services are not identities independent of their selected endpoints.
Traffic to an allowed tuple still needs Gateway identity and authorization checks.

## Trusted composition

`TrustedSpec` declares expected `InitContainers`, `Containers` and every referenced
`Volume`. It must come from platform-controlled configuration, independently of the
submitted workload. Do not construct it by copying an untrusted submitted Pod.
A name or annotation never grants trust. Missing, duplicate, wrong-role or changed
components and conflicting/replaced volume sources are rejected.

Container comparison covers the complete Kubernetes container value: image,
command/args, environment and references, mounts, devices, security, lifecycle,
probes and restart behavior. Only the enumerated Kubernetes 1.34 API defaults
already covered by #11 are normalized for comparison. Volumes are compared exactly.
Mutable ConfigMap/Secret/projected/external content is not authenticated by matching
its reference: the platform owns its content and write permissions.

Unmatched regular and init containers are business containers. Business and resident
trusted components require explicit nonzero UID/GID (or safe Pod inheritance),
`drop: [ALL]`, no added capabilities and `allowPrivilegeEscalation: false`.
Only a matched terminating init container may use root and add CHOWN, FOWNER and
DAC_OVERRIDE for file preparation. Native sidecars (`restartPolicy: Always`) remain
resident and cannot use this exception. NET_ADMIN and NET_RAW are unsupported even
for trusted components; integration needing them requires a separately accepted
contract extension.

Capabilities are configured on individual containers. Network operations can affect
the Pod's shared network namespace; NetworkPolicy also covers the entire Pod.
Root is not a Pod-wide capability grant. A preparation UID and a resident UID are
caller choices, not reserved platform identities; UID 1337 has no special meaning.
A typical preparation step assigns a private volume to the resident UID and sets
0700 so that resident can write it while other UIDs cannot traverse it.

Gateway owns reserved identities, private-resource isolation, transparent capture,
identity-provider integration and governance readiness/startup ordering. Networking
checks platform safety; it does not infer which application code is trustworthy or
ensure a business container never shares a Gateway identity or volume.

## Final object and lifecycle boundary

Host network/PID/IPC, shared process namespace, hostPath, hostPort, additional network
attachments, any explicit `runtimeClassName` (including an empty string), ephemeral
containers, unsafe root inheritance, sysctls and effective unconfined profiles are rejected. Profile omission
does not certify that a node's runtime default is restrictive. Kubernetes API validity
and final mutation/admission checks remain platform responsibilities.

Policy API creation is not dataplane readiness. The supported Calico CNI policy-setup
wait and Felix enforcement must be effective when the sandbox is created, before any
init container starts. The policy and protected labels remain in force through
preparation, app startup, resident stop/restart, Pod termination and recovery, until
the sandbox is destroyed. Do not remove a binding policy while a selected sandbox
still exists. Never recycle bindings until the old workload/sandbox is gone.

When policy programming is unavailable, admission/CNI must keep the sandbox blocked
or the existing dataplane must continue denying traffic; tests distinguish proven
Calico policy refusal from unrelated Pending/image/scheduling failures. During
recovery, allowed and denied paths must both be revalidated. Existing established
connections may persist after policy changes; immediate revocation is not promised.

## Consumer example

`examples/static` has no dependency on Gateway, Istio, controller or cluster access.
It assembles restricted business, a root file initializer, a nonroot resident and a
private volume; generates policy; validates/binds the Pod; emits policy before Pod;
and demonstrates rejected initializer substitution. The platform must precreate the
namespace/service account and install the policy before creating the workload.
The example certifies the public contract only, not image provenance, identity
systems, authorization or transparent proxy behavior.
