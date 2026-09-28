# Kubernetes / Calico networking foundation

This repository provides a restricted Kubernetes network binding and its independent
Calico acceptance suite. It contains no governance proxy or identity provider.
Gateway composes governance components; a trusted platform applies the policies,
checks the final Pod and creates the workload.

## Public contract

Import `github.com/egress-gateway/egress-gateway-networking/enrollment`:

- `Network`, `Peer`, `TCPDestination`, `Policy`, `ExpandPolicy`: exact TCP
  destinations and an optional, separately declared TCP/UDP port 53 DNS exception.
  An empty allowance means default-deny egress.
- `TrustedSpec`, `Options`, `ExpandPod`: compare independently supplied trusted
  containers and referenced volumes, check final Pod safety, and attach the binding.
  No injection, startup reordering, discovery, API writes or reconciliation.

See [the integration contract](docs/enrollment.md) and
[the external static consumer](examples/static/main.go). `go run ./examples/static`
prints policy then Pod and checks an intentionally rejected substitution. Its images
are illustrative inputs, not certified Gateway implementations.

## Supported platform

The version authority is [baseline/versions.json](baseline/versions.json):
Kubernetes 1.34.11 on kind 0.33.0, Calico 3.32.2 / Tigera Operator 1.42.6,
IPv4, iptables, VXLAN, BGP disabled, separately managed kube-proxy.
`defaultEndpointToHostAction: Drop` and CNI policy setup waiting are required.
Other runtimes, IPv6, arbitrary IP protocols and immediate established-flow
revocation are not certified. #13 owns further protocol/first-packet work.

## Validation

Docker, pinned kind/kubectl, Go, Bash 4+, jq, curl, tar and envsubst are required.
The suite creates an isolated owned cluster. It never adopts an existing cluster.

```sh
make check
make e2e
make e2e-up
make e2e-test
make e2e-test
make e2e-negative # expected nonzero; require verified=true in negative-control.json
make e2e-down
```

Use `E2E_ARGS='--state-dir=.e2e/my-state'` consistently for an independent retained
run. The only profile is `calico` and acceptance is `enforce`; both are defaults.
Old profiles, baseline acceptance and proxy-specific flags are rejected.
Old retained environments cannot be tested; owned cleanup remains available via
`down` with their original state directory and default flags.

[Acceptance and evidence](docs/calico.md) describes source/receiver correlation,
fault recovery, configuration fingerprint checks and safe cleanup. Reports under
`.e2e/artifacts/run-*` include revision, dirty state, case results, Markdown and JUnit.
Subset runs leave unexecuted cases visible and cannot pass full acceptance.

No Gateway image, identity service or controller is required by local or CI gates.
Passing these gates is not permission to merge, publish a release or deploy.
