# Egress Gateway Networking

Shared Istio installation and an independent HTTP/mTLS and egress acceptance baseline for
gateway, controller and future CLI consumers. This repository depends on
Kubernetes, Helm and official Istio components; its tests use kind, Godog, curl, httpbin and a private Go protocol probe. It does not depend on gateway/controller code, images or scripts.

PR0 uses the default IPv4 kind network plus the chained Istio CNI in sidecar mode.
It **does not enforce fail-closed egress**. STRICT mTLS authenticates the test
service; it is not an egress isolation boundary.

The `calico-istio` candidate adds pinned Calico 3.32.2 (iptables, IPv4 VXLAN,
kube-proxy retained), exact Pod egress NetworkPolicies, and 30 additional cases.
It requires `--acceptance=enforce`: all 73 cases must satisfy their contracts.
See [Calico acceptance and boundaries](docs/calico.md). Neither profile imports
gateway/controller code, and neither exposes a public enrollment API.

## Layout and ownership

```text
gateway E2E ────┐
controller E2E ┼──> install/ ──> Kubernetes / Helm / official Istio
future CLI ────┘

cmd/networking-e2e/     Go command shared by Make and CI
environments/kind/     Owned test cluster lifecycle (Shell + YAML)
install/               Reusable install/check/diagnostics and pinned inputs
test/e2e/environment/  Go lifecycle, retained-state checks and cleanup tests
test/e2e/features/     English Gherkin behavioral requirements
test/e2e/suite/        Godog steps, evidence assertions and per-case reports
test/e2e/probe/        Private HTTP/TLS/TCP/UDP/DNS/HTTP3 tool and local image
test/e2e/baselines/    Reviewed Istio-only expectations (never rewritten by tests)
test/e2e/scripts/      Complete deployment/request/diagnostic operations
test/e2e/config/       Test applications, security policy and logging override
```

The installer creates only shared infrastructure. It takes an explicit kubeconfig
and context, installs official Istiod/CNI/proxyv2, and leaves upstream
validation/repair enabled. Consumers own their cluster and applications. There is
no public enrollment API in PR0.

## Local development

Required: Go >= 1.26.0 (validation/CI: 1.26.7), Bash >= 4, Docker with a running
Linux engine, kind v0.33.0, kubectl v1.33.9, Helm v4.3.0, curl, jq, envsubst, tar,
and sha256sum or shasum. macOS uses Homebrew Bash when available. Allow enough
Docker capacity for a Kubernetes control plane, Istiod/CNI and the test workloads, gateway, and two external receivers (about 4 CPUs / 6 GiB free is useful).

```sh
make check
make e2e

# Retain one environment for repeated tests; these tests never recreate it.
make e2e-up
make e2e-test
make e2e-test
# Expected nonzero on Istio-only: identical security assertions, strict acceptance.
make e2e-test E2E_ARGS='--acceptance=enforce'
make e2e-down

# Preserve even a failed setup for diagnosis.
make e2e E2E_ARGS='--keep'
```

Each full run creates a unique cluster and refuses existing state or cluster
takeover. The default private state directory is `.e2e/state`; choose a different
one with `E2E_ARGS='--state-dir .e2e/another-state'`. Use the same state path for
all retained commands. The node ID, owner mount and kubeconfig checksum are
checked before reuse. Cleanup checks the node ID and owner mount before deletion.
An identity mismatch preserves state and returns an error for manual diagnosis.
Do not edit ownership receipts to force cleanup. A `busy` directory prevents
concurrent operations on the same state; after an interrupted process, inspect
the cluster and confirm no runner is alive before removing a stale lock.

`e2e` diagnoses before cleanup on success or failure, unless `--keep` is set.
`up` and `test` always retain the environment on failure. Installation/config
input changes require `down` followed by `up`. Unit tests cover setup failure,
cleanup order, ownership refusal and retained failure behavior.

## Shared installation

Run scripts with Bash 4+ (on macOS, `/opt/homebrew/bin/bash`). The pinned Istio
archive is checksum-verified; only its portable Helm charts are used.

```sh
bash install/scripts/install.sh --kubeconfig /absolute/cluster.yaml --context my-cluster
bash install/scripts/check.sh --kubeconfig /absolute/cluster.yaml --context my-cluster
bash install/scripts/diagnostics.sh --kubeconfig /absolute/cluster.yaml --context my-cluster --artifacts ./diagnostics
```

The installer targets the default Istio revision in `istio-system`, on a
Kubernetes environment compatible with the CNI directories in
`install/values/istio-cni.yaml`. It refuses incompatible or unmanaged existing
Istiod/CNI workloads. Repeating the install reconciles the same pinned version;
it is not a general upgrade/uninstall manager. Tests pass
`--istiod-values test/e2e/config/istiod-values.yaml` to enable JSON access logs.
This logging configuration is not part of the shared defaults.

## Acceptance evidence

All expanded Godog cases run serially in one environment, including the four PR0 scenarios. Every scenario has its own
`X-Networking-Test-Id`. A temporary unmeshed client is removed after its probe.

| Behavior | Required evidence |
| --- | --- |
| CNI injection | Ready Istiod/CNI, chained plugin, successful `istio-validation` with `--skip-rule-apply`, no `istio-init` |
| Transparent HTTP | Application uses no proxy; httpbin echoes the ID; both Envoys log that ID with HTTP 200 |
| Actual mTLS | Same request has client upstream/server downstream TLS metadata and the expected opposite ServiceAccount SPIFFE identity |
| Plaintext rejection | No HTTP response and curl reports reset/empty reply; the same server logs `filter_chain_not_found` for this temporary client's Pod IP under STRICT policy |

For raw plaintext, STRICT's TLS-only inbound listener rejects the connection
before it can read an HTTP correlation header. The test therefore matches the
listener rejection log's direct remote address to the temporary client's Pod IP,
collecting logs only from the probe's start time and checking that the server
UID/container/restart count did not change. The client stays alive until evidence
is collected, so its IP cannot be reused during the probe. A timeout alone, a
changed server, another source address, or an HTTP response cannot pass.

The egress fixture uses an unprivileged application probe → workload Envoy →
official Istio gateway → controlled Docker origin outside Kubernetes. HTTPS keeps
application-to-origin TLS inside proxy-to-proxy mTLS; no MITM is implemented.
ServiceAccount identities are explicit. Separate receivers cover same namespace,
cross namespace, direct Pod IP, Service/DNS and node addresses. An independent
unmeshed control verifies receiver health before and after each observation.

The private image is built from this module and loaded into kind. `quic-go
v0.63.0` performs real HTTP/3; QUIC cases on 443 and 8443 cannot fall back to TCP.
UDP is forbidden except the designated DNS resolver; TCP DNS is also exercised.
Fault scripts affect only verified, owned fixtures and retain the primary CNI.
A failed restoration prevents subsequent cases from running.

`--acceptance=baseline` is the default. Its reviewed expectations are in
`test/e2e/baselines/istio-only.json`, bound to the installation/fixture input
fingerprint. A matching known bypass passes **baseline acceptance** while its
**security result remains violated**. Unexpected improvement also fails baseline
acceptance and requires investigation. `--acceptance=enforce` uses exactly the
same scenarios and evidence assertions, but every security violation fails.
Execution errors, inconclusive evidence, and required cases not run fail both modes.

Each run prints a unique `.e2e/artifacts/run-*` path. Start with `summary.md`:
its complete table has one row per Scenario/Examples instance, the security
requirement, actual result, reviewed baseline, acceptance and case evidence path.
`case-results.json` is the structured source; `junit.xml` uses the same acceptance
function and retains security observations in each testcase's output. Reports
are initialized before setup and saved after every case. Run failures leave the
remaining inventory marked `not_run`; an interrupted or missing report cannot
certify acceptance. `run.json` records source SHA, dirty state and terminal status.

The GitHub Actions job publishes the **entire case table** in its Summary with an
`always()` step and uploads Markdown, JSON, JUnit and the evidence directories.
The Summary lists security counts separately from acceptance counts/failing IDs.
The baseline CI being green means the reviewed **not-fail-closed** result was
reproduced; it never means all security requirements are satisfied.

Each case directory contains probe observations, bracketing controls, bounded
proxy/receiver logs, and relevant fault/restoration evidence. Raw receiver packet
observations contain only IPv4 transport headers. No application payload is saved
by the packet observer. A failed TLS handshake cannot establish network isolation:
correlated delivery/packets still violate that contract. Authentication cases
instead require no application delivery plus an attributable listener/identity
rejection. An absence conclusion additionally requires a complete packet window, zero kernel
capture drops and no unread or unattributed packets. Late observed traffic is not
discarded because the client timed out. A timeout or unhealthy receiver alone is
inconclusive or an error.

Diagnostics include pinned versions, actual image IDs, Pod/events and bounded
Istiod/CNI/proxy logs. Private kubeconfig, ownership receipts and ephemeral test
keys live outside artifacts. Full proxy config dumps and Secrets are excluded.
Do not upload the entire `.e2e` directory. IPv6, SCTP and other IP protocols are
explicitly outside this IPv4 TCP/UDP profile and do not count as passed cases.

For diagnosis use `--keep`, read the case evidence and command log, then rerun the
complete operation directly, for example:

```sh
bash test/e2e/scripts/egress-case.sh --state-dir "$PWD/.e2e/state" \
  --artifacts "$PWD/.e2e/artifacts/manual" --test-id manual-udp \
  --protocol udp --target external --client workload --phase healthy
```

After changing install/probe inputs, use `down` then `up`. To propose a baseline
change, run `enforce`, investigate all changed observations and evidence, then
edit the expectation file explicitly for review. Test execution never updates it.
Later network candidates use independent state/cluster directories and run the
same inventory with `--acceptance=enforce`.

## Versions and delivery scope

`install/versions.env` records the checked baseline from gateway
`ea2480bd755acfa2e433a36edc6d77014b283da2`: kind v0.33.0, Kubernetes v1.34.11,
Istio 1.31.0, kubectl v1.33.9, Helm v4.3.0, curl 8.10.1 and httpbin v2.15.0.
Image references pin multi-platform digests. The httpbin image follows the
[Istio 1.31.0 sample](https://github.com/istio/istio/blob/1.31.0/samples/httpbin/httpbin.yaml).
Archive/tool checksums are stored locally in version files; CI downloads only
those pinned inputs. Godog is pinned to v0.16.0 in the single Go module.

CI separates `make check` from an Ubuntu `make e2e` job and uploads only the safe
artifact directory. CI and local terminal results are separate acceptance facts.

- PR0: project foundation, shared install, HTTP/mTLS BDD acceptance.
- PR0.5: measured not-fail-closed baseline, fault/bypass coverage and per-case CI reports.
- PR1: primary CNI/NetworkPolicy choice and isolation that satisfies the same enforce suite.
- PR2: validated public Pod enrollment contract, input checks and consumer tests.

[V01-02](https://github.com/egress-gateway/egress-gateway-networking/issues/1)
remains open after PR0.5. Gateway dual roles, HTTPS MITM, OPA authorization and
controller automation remain owned and tested by their respective repositories.

## Egress case inventory

The prefix names the first failed contract condition or the permitted purpose.
Transport, destination/address form and lifecycle are orthogonal dimensions; the
inventory deliberately uses representative combinations, not a Cartesian product.

| Class | Case IDs | Coverage |
| --- | --- | --- |
| N1: disallowed destination | N1-01–15, N1-20–28 | External/Pod/Service/DNS/node paths; sidecar-only/no-sidecar; UDP, forced QUIC, wrong resolver; first packet, missing redirect, sidecar/gateway/Istiod faults |
| N2: disallowed tuple | N2-01–02 | Allowed gateway address with wrong TCP port or UDP tuple |
| N3: invalid authentication | N3-01–05 | Plaintext, missing/untrusted client certificate, wrong workload and gateway identities |
| N4: business path and startup gate | N4-01–02, N4-10–12 | HTTP/HTTPS through both proxies; existing stream during control-plane loss; validation/repair and unavailable new identity |
| N5: DNS exception | N5-01–02 | Designated resolver over UDP/TCP 53 |
| N6: mesh/control exception | N6-01 | Recreated workload obtains fresh identity/configuration and completes authenticated business traffic |
| PR0 regression | P0-01–04 | Native CNI injection, HTTP, mutual identities, STRICT rejection |

The protected Pod's declared endpoint tuples are:

| Endpoint | Transport / port | Purpose and authentication |
| --- | --- | --- |
| `gateway.networking-gateway.svc.cluster.local` | TCP 15443 / 15444 | HTTP / nested HTTPS; mutual Istio TLS with exact workload and gateway SPIFFE identities |
| `kube-dns.kube-system.svc.cluster.local` | UDP and TCP 53 | Cluster DNS resolution; Kubernetes-designated resolver, no TLS authentication |
| `istiod.istio-system.svc.cluster.local` | TCP 15012 | Certificate issuance and xDS; Istio trust root, service-account token bootstrap and issued workload identity |

The origin's TCP 8080/443 is a **gateway** destination, not an application Pod
exception. The external origin/QUIC receivers' other ports and in-cluster/node
receivers are deliberately forbidden targets. Kubernetes API/exec, node network
namespace inspection and proxy log collection are runner-side instrumentation;
they do not add destinations to the protected Pod's allow set.

The reviewed Istio-only baseline contains **17 satisfied cases and 26 violations**.
Its open cases are N1-01–15, N1-20–28 and N2-01–02: direct external/in-cluster/node
traffic, UDP/QUIC and wrong-resolver traffic, absent/broken proxy interception,
fault-window bypasses, and wrong gateway tuples. Authentication rejection and the
startup validation/identity gates do not turn those open paths into network isolation.

Restart probes stop after verified fault observations and component recovery;
the existing-connection probe stops after observing the same connection before
and during the confirmed outage. Both use a 180-second deadline instead of a
fixed 60/90-second run. Recovery requires two consecutive authenticated requests. Log evidence is
evaluated immediately; Godog retries incomplete evidence for at most 10 seconds
and retains temporary fixtures until evaluation finishes. Operation errors and
conclusive security results are never retried into a different verdict. The
native Istio readiness thresholds and bounded negative probe windows remain in
effect. Markdown, JSON and JUnit report elapsed time for each case, including its
cleanup, so runtime changes can be compared without repeating timing experiments.
