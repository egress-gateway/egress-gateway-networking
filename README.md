# Egress Gateway Networking

Shared Istio installation and an independent HTTP/mTLS acceptance baseline for
gateway, controller and future CLI consumers. This repository depends on
Kubernetes, Helm and official Istio components; its tests use kind, Godog, curl and
httpbin. It does not depend on gateway/controller code, images or scripts.

PR0 uses the default IPv4 kind network plus the chained Istio CNI in sidecar mode.
It **does not enforce fail-closed egress**. STRICT mTLS authenticates the test
service; it is not an egress isolation boundary.

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
test/e2e/suite/        Godog steps and evidence assertions
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
Docker capacity for a Kubernetes control plane, Istiod/CNI and two sidecars.

```sh
make check
make e2e

# Retain one environment for repeated tests; these tests never recreate it.
make e2e-up
make e2e-test
make e2e-test
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

Four serial Godog scenarios share one environment. Every scenario has its own
`X-Networking-Test-Id`. A temporary unmeshed client is removed after its probe.

| Behavior | Required evidence |
| --- | --- |
| CNI injection | Ready Istiod/CNI, chained plugin, successful `istio-validation` with `--skip-rule-apply`, no `istio-init` |
| Transparent HTTP | Application uses no proxy; httpbin echoes the ID; both Envoys log that ID with HTTP 200 |
| Actual mTLS | Same request has client upstream/server downstream TLS metadata and the expected opposite ServiceAccount SPIFFE identity |
| Plaintext rejection | No HTTP response and curl reports reset/empty reply; the same server's inbound TLS listener rejection counter increases under STRICT policy |

For raw plaintext, STRICT's TLS-only inbound listener rejects the connection
before an HTTP access-log entry can exist. The test therefore compares
`listener.0.0.0.0_15006.downstream_cx_no_filter_chain_match` around a single probe,
also checking that the server UID/container/restart count did not change. A
timeout alone, a changed server, or an HTTP response cannot pass this assertion.
The suite is serial in a dedicated cluster with no concurrent rejection probes.

Each run prints a unique `.e2e/artifacts/run-*` path containing JUnit, per-request
evidence, version inputs, actual runtime image IDs, Pod/events, and bounded
Istiod/CNI/sidecar logs. `run.json` records command, source SHA, dirty state,
platform, toolchain, times and terminal result. Private kubeconfig/receipts live
outside the artifact path. Diagnostics intentionally exclude Secrets, keys,
environment dumps and full proxy config dumps. Do not upload the entire `.e2e`.

For a failure, start with the step log and JUnit report, then CNI/validation logs,
Pod/events and the request-specific evidence. Use `--keep` to retain the cluster.
All scripts accept explicit state or kubeconfig arguments and can be rerun alone;
for example `bash test/e2e/scripts/verify.sh --state-dir "$PWD/.e2e/state" --artifacts "$PWD/.e2e/artifacts/manual"`.

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
- PR1: primary CNI choice, default isolation, exceptions, TCP/UDP/QUIC bypass and
  first-packet/repair/fault fail-closed validation.
- PR2: validated public Pod enrollment contract, input checks and consumer tests.

[V01-02](https://github.com/egress-gateway/egress-gateway-networking/issues/1)
remains open after PR0. Gateway dual roles, HTTPS MITM, OPA authorization and
controller automation remain owned and tested by their respective repositories.
