# Sidecar DNS capture and strict isolation

The supported `calico-istio` profile no longer allows protected Pods to reach
CoreDNS on TCP/UDP 53. This replaces the former Calico configuration; there is
no recursive compatibility mode. `istio-only` retains its historical baseline.

Official Istio answers declared names locally. Unknown names and unsupported
record types may cause fallback attempts, which Calico blocks. This is network
isolation, not arbitrary-name FakeIP synthesis. Applications requiring recursive
resolution can lose DNS functionality until their consumer supplies a governed
DNS capability. DoH/DoT content policy and SSH/SFTP target recovery are outside
this repository's acceptance.

## Static protected Pod configuration

The static consumer resolves Istiod, calls the public `enrollment.ExpandPolicy`
before workload creation, composes the native sidecar, then calls `ExpandPod`.
The public functions never query the cluster. [Enrollment](enrollment.md) specifies
variable values, fixed capture fields, original-label injection exclusion and
startup ordering. Both egress and four independent DNS groups consume it; gateway
fixtures and Istio-only retain official injection. Faults alter only test copies
of already expanded Pods.

The default Network DNS list is empty. An explicit resolver peer generates only
TCP/UDP 53 allowances. These are Pod-wide, including application bypass traffic;
consumers own query semantics and recursion. Controlled resolver tests separately
cover direct application queries and sidecar fallback, then revoke the exception
and prove that new queries are blocked with correlated observations.

## Acceptance and historical evidence

The full Calico inventory includes local positive controls, unknown names and
record types, explicit search expansion, padded EDNS, resolver changes, capture
disablement/exclusion, proxy UID and process faults, cold bootstrap and recovery.
Each case reports DNS functionality separately from security. Required positive
controls must resolve successfully; an isolation case can pass while reporting
unavailable resolution. Queries reaching a forbidden resolver are violations
even if no response returns. Missing controls, observation or recovery fail.

- `N5-01/02` retain their original resolver-allow contract in Istio-only only.
- Retired Calico `C1-04/05` remain in merged history; `C5-01/02` now prove direct
  UDP/TCP Endpoint denial from a protected unmeshed client.
- Local experiment `D1-05..08` and `D2-03..16` become new `DS-01..18` isolation
  requirements. Their previous functionality gaps remain documented in
  [the experiment report](dns-local-validation.md), not relabeled as passes.
- Default unconfigured bootstrap and undeclared-name HTTP/HTTPS feasibility
  cases remain historical observations, not applicable production requirements.
- Supported configured bootstrap, declared controls, faults and lifecycle checks
  retain their IDs. UDP EDNS FORMERR is reported as unavailable synthesis; TCP
  EDNS remains a required positive control.

Run the standard Calico enforce suite for complete acceptance. `--tags=@dns`
is a development subset: other applicable cases remain not run and the aggregate
exit is nonzero. The existing CI matrix publishes every applicable case from the
same results used for Markdown, JSON, JUnit and exit status.

Input fingerprints include shared configuration directories. Validate the
unchanged Istio-only outcomes before updating its fingerprint; never regenerate
expected outcomes automatically. A retained environment with a different
fingerprint must be recreated, even when its profile's behavior is unchanged.

## Test orchestration and timing

Godog invokes the private Go DNS runner. Go owns observer processes, readiness
barriers, deadlines, recovery and cancellation. Shell operations only discover
runtime identities, create the fixture, inspect redirection, suspend a verified
sidecar or snapshot the receiver. DNS runs in four concurrent groups: records, resolver destinations,
capture/sidecar faults, and application/lifecycle. Each has its own namespace, client, receiver,
ServiceEntries, state, recovery target and forbidden external receiver. A separate
unprotected control Pod in the same namespace verifies receiver health; namespace
membership does not impose the tested egress restriction. Cases within a group remain serial.
Node, Calico, gateway and Istiod faults run before the DNS groups, never alongside
them. `N1-15` retains its original egress workload in the serial phase.

Independent observer operations within a phase run concurrently and collect every
result. External receiver capture and its health traffic are private to each group, so
there is no cross-group observation barrier. Source and NAT attribution remain
mandatory; unaccounted receiver traffic still fails evidence validation.
Group wall times appear as `dns-group/*` operations; their intervals overlap.
Receiver/drop observers must be ready before creating a cold Pod or introducing a
fault; source observers must be ready before the probe. Recovery uses a separate
correlation and evidence directory with the same Go runner and verdict logic.

Reports include each case duration, DNS phase wall times and the slowest cases.
Concurrent operation durations overlap and must not be added to suite wall time.
Captured queries retain a seven-second upper bound to include native fallback;
direct capture/UID bypass and stopped-sidecar queries use a two-second bound.
Normal answers and ready conditions finish immediately. Short query deadlines
alone never establish isolation: receiver health, complete observations and
attributable enforcement remain required.

`N1-15` runs from the original egress workload. In Calico, DNS capture can redirect
an explicit external-resolver query to the configured fallback resolver, so the
case observes both the original destination and discovered CoreDNS endpoints.
It does not substitute the independent DNS client for the egress workload.
