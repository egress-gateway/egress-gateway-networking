# Local sidecar DNS feasibility experiment

This is a local experiment against the merged PR1 tree, not a supported installation
profile or a DNS authorization feature. Its primary question is whether official
Istio 1.31.0 can synthesize an address for **any undeclared external name**, without
forwarding the query or requiring an independent recursive resolver or gateway.

The fixture only demonstrates entry into the local Envoy. Its receiver allow rule
cannot distinguish the application from Envoy inside the same Pod. It does not
claim a complete egress authorization boundary.

## Implementation and evidence

The new `@calico @dns` feature uses the existing Godog entrypoint and report. DNS
query types, correlated answers, healthy controls, packet observation and Calico
kernel drops are recorded independently of application usability. A blocked
fallback can have `security_result=satisfied` and `functionality=not_satisfied`.
Neither a successful DNS answer nor local Envoy interception grants permission
to leave a consumer's control domain.

Private scripts deploy an isolated namespace and test receiver, with no DNS egress
allow rule. The fixture does not modify the original PR0/PR1 policies. A trusted
Istiod Service address is supplied using Pod host aliases; default discovery
bootstrap is measured separately. Both variants retain the original TLS identity
checks. `holdApplicationUntilProxyStarts: false` is confined to the experiment;
the native sidecar startup probe still prevents application startup when discovery
bootstrap fails. The bootstrap case inspects Pod status rather than assuming it
can execute a probe in that blocked application container.

Each run keeps the complete inventory. Selecting tags does not make unexecuted
cases pass; a nonzero whole-suite exit is expected for a subset but never excuses
an execution error or missing evidence. Unknown-host application scenarios stay
unexecuted when their DNS prerequisite has demonstrably failed.

## Commands

```sh
make check
make e2e E2E_ARGS='--profile=calico-istio --acceptance=enforce --keep --tags=@dns-names,@dns-bootstrap --state-dir=.e2e/state-dns --artifacts=.e2e/artifacts/dns-local'
make e2e-test E2E_ARGS='--profile=calico-istio --acceptance=enforce --tags=@dns,@pr0 --state-dir=.e2e/state-dns --artifacts=.e2e/artifacts/dns-local'
make e2e-down E2E_ARGS='--state-dir=.e2e/state-dns --artifacts=.e2e/artifacts/dns-local'
```

Retained-state fingerprint and ownership checks are unchanged. Failed setup must
be diagnosed and cleaned before recreating the environment. Changes to installation,
fixture manifests or the probe require recreation; runner-only changes do not
change the installed candidate.

## Pinned source constraints

- [ServiceEntry validation, 1.31.0](https://github.com/istio/istio/blob/1.31.0/pkg/config/validation/validation.go): a host equal to `*` is rejected. Record the server dry-run response as well as the source rule.
- [Local DNS server, 1.31.0](https://github.com/istio/istio/blob/1.31.0/pkg/dns/client/dns.go): unmatched names and locally unsupported question types use the upstream resolver. The name table supports suffix wildcards, not unrestricted new-name allocation.
- [IP allocation, 1.31.0](https://github.com/istio/istio/blob/1.31.0/pilot/pkg/controllers/ipallocate/ipallocate.go): ordinary wildcard entries are excluded from automatic allocation, with an exception for `DYNAMIC_DNS`. The wildcard control here uses an explicit synthetic VIP and a static receiver; this is not evidence of unrestricted synthesis.

## Conclusion

Official Istio 1.31.0 does **not** meet unrestricted, undeclared-name FakeIP
synthesis. Its DNS proxy answers from the Istiod name table and forwards misses;
NetworkPolicy can block that forwarding but cannot turn it into local synthesis.
The supported `ServiceEntry` API rejects a full `*` hostname. No suffix enumeration,
custom agent, additional DNS process, or custom proxy image was used to disguise
this gap.

The native capability remains useful for declared names: applications reach the
local Envoy using ordinary DNS and sockets, and HTTPS preserves the requested
hostname and validates the certificate. The DNS fixture has no gateway peer in
its NetworkPolicy. The existing suite's gateway fixture remains installed for
other scenarios but is not in this fixture's traffic path.

## Final local run, 2026-09-24

- Branch: `codex/dns-fakeip-local`; merged baseline
  `968c21ff61d7038bb7e6c93a8470727e4740f6fd` plus the uncommitted experiment.
- Run: `run-604945195`, `calico-istio / enforce`, tags `@dns,@pr0`.
- Selected: **58 cases = 37 passed + 19 functional gaps + 2 dependency skips**.
  The four PR0 regressions passed. All 56 executed cases satisfied their scoped
  safety assertions; zero security violations, execution errors, or inconclusive
  case verdicts. The 19 gaps are D1-05–08, D2-03–16, and D4-01.
- Whole inventory: 127 cases, 71 not run (69 unselected plus two dependencies).
  Whole-suite acceptance remains **FAIL / incomplete evidence**, and the command
  returned nonzero. No complete fail-closed claim is made.
- BDD time: **9m 6.293s**; report lifecycle including verification/diagnostics:
  **9m 11.173s**. Per-operation and per-case timings are in the reports.
- `make check`: PASS with Go 1.27.1 and with the repository's CI toolchain
  (`GOTOOLCHAIN=go1.26.7`). The local network runner/probe were built with Go
  1.27.1; no CI job was run or changed.
- Runtime: Linux `7.0.14-orbstack-00380-ga7e0a2dc9535`, arm64; kind v0.33.0,
  Kubernetes v1.34.11, Calico v3.32.2, official Istio v1.31.0. The existing pinned
  infrastructure image digests were retained. Runtime image IDs and configuration
  are recorded with the report.
- Input fingerprint:
  `81adec33c5a95bb509cac52710423c34228d4eece1c160f6e731f842f1d0ee89`.
- Owned cluster `networking-e2e-boxbbkf7jw`, its receiver containers, and private
  state were removed after diagnostics. Unrelated containers remained running.
  Cleanup output and source hashes are retained in the final evidence directory.
  No commit, push, PR, or CI modification was made.

Reports: [Markdown](../.e2e/artifacts/dns-local/run-604945195/summary.md),
[JSON](../.e2e/artifacts/dns-local/run-604945195/case-results.json),
[JUnit](../.e2e/artifacts/dns-local/run-604945195/junit.xml).
Each selected case directory contains its queries, observations, controls, and
fault/recovery evidence. Earlier exploratory runs remain separate; their harness
errors and incomplete verdicts are not counted as native feature failures.

## Capability matrix

"Native" describes an existing official implementation capability; "configured"
means the tested installation or declared mapping is required. Neither label is
a claim of unrestricted DNS support.

| Capability | Classification | Runtime evidence and limits |
|---|---|---|
| Registered A over UDP/TCP | Configured | D1-01/02: auto-allocated `240.240.0.0/16` answers, no upstream packet. Requires a declared ServiceEntry. |
| Names within a configured wildcard | Configured | D1-03/04: explicit wildcard VIP `240.240.20.1`; not automatic synthesis for other suffixes. |
| Arbitrary undeclared names across suffixes | Capability gap | D1-05–08: no synthetic answer; source packets and Calico drops prove fallback was attempted. Receivers observed zero delivery. |
| AAAA for a registered name in IPv4 | Native | D2-01/02: local NOERROR with no answer or upstream traffic. This is not an IPv6 networking test. |
| TXT/SRV/MX/PTR/NULL/ANY without forwarding | Capability gap | D2-03–14: forwarding attempts, blocked by Calico. The protected application obtained no external answer. |
| Unknown search-expanded name ends locally | Capability gap | D2-15: the tested Kubernetes search-expanded name still invokes fallback. This does not enumerate every OS resolver's search behavior. |
| Padded EDNS over TCP | Native | D2-17: locally synthesized A response. |
| Padded EDNS over UDP | Capability gap | D2-16: correlated local FORMERR for a query with 900 bytes of EDNS padding; no upstream traffic. |
| HTTP and TLS with visible SNI enter local Envoy | Native | D5-01–04: source connection, proxy route, receiver ID/Host/SNI; two distinct names. No application proxy, resolve override, skipped certificate verification, or MITM. Applies to declared controls. |
| Raw TCP enters local Envoy | Native | D5-05: application source socket matches Envoy access record. The cluster identifies the declared `tcp.origin.test` mapping; arbitrary TCP hostname recovery is not established. |
| DNS isolation during bypass/process faults | Configured | D3-01–14: DNS Service/Endpoint/external targets, resolver replacement, disabled capture, proxy UID, and stopped agent/Envoy over UDP/TCP. Healthy independent controls, complete receiver observation, and endpoint drop evidence where packets leave the Pod. |
| Forbidden TCP during DNS/UID/process faults | Configured | D3-15–17: external receiver zero delivery. UID bypass is dropped by Calico; stopped-sidecar traffic remains locally intercepted. See the TCP attribution qualification below. |
| Default discovery bootstrap with no DNS egress | Capability gap | D4-01: fresh Pod remains unready within the bounded observation; discovery lookup attempts are dropped. No DNS egress was temporarily allowed. |
| Bootstrap with trusted discovery mapping | Configured | D4-02: fresh Pod ready with loaded certificate metadata; installer supplies Istiod host aliases and retains its original TLS identity. No workload Kubernetes API permission. |
| Restart, rebuild, and removed mapping | Configured | D6-01–03: cached declared VIP reaches the correct target after restart/rebuild; removing a mapping permits safe failure rather than delivery to another target. |
| HTTP/HTTPS for undeclared names | Evidence gap / dependency not run | D7-01/02: stopped after the formal DNS prerequisite failed. Registered controls do not substitute for this capability. |

### Padded UDP evidence

The same EDNS payload shape succeeds over TCP. The pinned
[Istio DNS proxy](https://github.com/istio/istio/blob/1.31.0/pkg/dns/client/proxy.go#L35)
constructs a default `dns.Server` without setting `UDPSize`. Istio pins
`github.com/miekg/dns v1.1.72`; that library's
[server default](https://github.com/miekg/dns/blob/v1.1.72/server.go#L215)
is 512 bytes. This explains the observed padded UDP FORMERR, without asserting
that every use of EDNS fails. Source copies are retained with the local evidence.

### TCP attribution qualification

D3-15 sends TCP to the external fixture's IP and port 9000. The native transparent
listener routes this connection to the **allowed in-cluster TCP fixture**. The
client receives an echo while the forbidden external receiver observes zero
packets. The verdict therefore uses the actual proxy upstream, source connection,
receiver ID, and packet evidence; client success alone does not identify the
receiver. This is allowed endpoint delivery, not proof that every original
destination is authorized or that raw TCP retains an undeclared hostname.

The two TLS controls similarly distinguish endpoint receipt from log formatting:
the VIP listener records the correct domain-specific upstream cluster while its
`sni` log field is null. The receiver independently echoes the original SNI and
the client validates the certificate. No claim of Envoy TLS termination is made.

## Evidence and scope

The final report retains all 127 applicable inventory entries. Only the 54 DNS
experiments and four PR0 regressions are selected. Other PR1 cases remain not run;
this experiment does not re-certify the complete PR1 suite. DNS safety results,
functional gaps, and dependency skips remain separate in Markdown, JSON and JUnit.

Evidence covers the specified single-node IPv4 installation and the tested
time windows. It does not establish IPv6, multi-node behavior, privileged/hostNetwork
applications, every resolver/search implementation, long-term VIP allocation reuse,
or arbitrary raw TCP domain recovery. Fault fixtures are not supported workload
configuration. Packet observers only read the owned namespaces and do not add
enforcement rules. Reports contain no kubeconfig, Secret, private key, or complete
Envoy configuration dump.

## Next scope decision

If unrestricted synthesis remains mandatory, native Istio configuration alone
should be ruled out. A separate implementation scope would need an in-Pod DNS
implementation and a defined way for Envoy to consume its name/VIP mapping,
including allocation lifetime, stale addresses, non-A answers, restart behavior,
and zero upstream fallback. DNS synthesis must remain independent of out-of-domain
authorization and must not require a particular egress-gateway topology. None of
those extensions is implemented by this experiment.
