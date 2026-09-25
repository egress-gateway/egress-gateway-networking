# Pod enrollment contract

The controller resolves the original enabled label and ServiceAccount through its
own Profile/binding model. Business workloads do not supply networking values.
The public `enrollment` package takes trusted, resolved values and returns copies;
it performs no Kubernetes, filesystem or network calls.

1. Call `ExpandPolicy(Network)` before creating the workload. The result contains
   a Pod binding label and a Kubernetes NetworkPolicy spec. The controller owns
   resource names, policy application, reconciliation and binding-token uniqueness.
2. Compose the runtime Pod, including an `istio-proxy` native sidecar in
   `initContainers` with `restartPolicy: Always`. Call `ExpandPod(Pod, Options)`
   with the identical Network. The returned copy is the final network expansion.
3. Return that Pod's admission patch only after policy resources are preprovisioned.
   Neither API creation nor readiness is proof that endpoint policy is programmed;
   the CNI first-packet gates and network acceptance remain required.

A binding can be shared intentionally by Pods with identical allowances. Different
bindings must use different tokens within a namespace. No Pod UID, IP or fixed
name is needed, so admission with `generateName` works. Kubernetes NetworkPolicies
are additive: the caller must prevent untrusted policy writes and governance-label
changes; this library cannot subtract an independently installed allow policy.

## Variable values and fixed fields

`Network` permits namespace, binding token, TCP forwarding destinations, Istiod
bootstrap information and optional resolvers. A peer is either an exact IPv4
address or the intersection of an exact namespace and nonempty Pod labels. There
is no unrestricted peer, CIDR range, protocol or wildcard-port input. DNS entries
permit TCP/UDP 53 explicitly; the default list is empty. Exceptions are Pod-wide,
including applications that bypass capture. Consumers own recursion, query policy
and tunnel prevention.

The module fixes the binding label key, default-deny egress shape, CNI capture
annotations, native proxy UID/GID 1337, DNS capture, Istiod TLS name, and the
official validation image/arguments. It rejects conflicting annotations, Env,
proxy configuration and privileges rather than silently correcting them. Missing
fixed settings are filled. Repeat expansion is idempotent and does not mutate
input. Failure returns no applicable partial output.

Applications and business init containers must have a determinate non-root,
non-proxy UID and GID, no privilege escalation, and drop all capabilities. Host
namespaces, hostPath, host ports and network sysctl overrides are unsupported.
Trusted preparation containers must be explicitly named and precede the proxy;
the designation does not permit networking capabilities or unrestricted privilege.
Validation precedes preparation; the proxy startup probe gates subsequent business
initialization. The caller owns runtime command, image, private volumes and
startup/readiness checks. Their implementation requires actual compatibility
acceptance: a syntactically valid custom image is not certified by generation.

## Installation and webhook ordering

Install with `--enrollment-label example.org/enabled`. The installer configures
Istio's `neverInjectSelector` for that original label's value `true`. It must
already exist when the workload is submitted, before controller mutation. The
controller supplies that same key in `Options.EnabledLabel`. This does not depend
on webhook ordering or a label added by the controller. Ordinary Pods continue to
use official injection. Do not set `sidecar.istio.io/inject=false`: the pinned CNI
also interprets that as a reason to skip capture.

The caller resolves the Istiod Service address and passes its certificate hostname
and exact endpoint selector. Expansion maps that name to the supplied IP without
opening DNS during bootstrap. The controller must replace affected Pod configuration
when that bootstrap address changes. Installation checks the actual environment;
the public Go accessor is not an environment validator.

## Versions and external consumption

`baseline/versions.json` is the version source for runtime components, image
digests, downloads and test tools. `baseline.Current()` returns an independent
copy of embedded version data. `go run ./internal/versionfiles` regenerates Shell
and YAML projections; `make check` verifies their consistency, CI Go version and
module Go minimum. Component upgrades require a separate validated change.

External Go modules import `enrollment` and `baseline` at a pinned module revision.
The independent-module test builds a consumer outside the repository and runs its
generator in an empty working directory. Runtime generation never reads checkout
assets. Installation and E2E deliberately use a checkout of the **same commit**;
no chart/asset publishing mechanism is introduced:

```sh
/absolute/networking/bin/networking-e2e e2e \
  --root /absolute/networking --expected-revision <full-commit-sha> \
  --profile calico-istio --acceptance enforce
```

Run the command from the pinned checkout or build `bin/networking-e2e` there and
invoke that binary from the consuming project with explicit `--root`. For a
custom proxy runtime use `--proxy-spec /absolute/runtime.json`, containing `proxy`,
optional `init`, `volumes` and `trustedInit`. This is an input to the existing
private E2E static consumer, not a second public injector or general CLI. Its
contents participate in the retained-environment fingerprint. Start from a clean
owned environment when that input changes.

The initially supported integration retains the official pilot-agent contract.
The suite covers redirection, UID exclusions, DNS handling, bootstrap and startup
failure; downstream custom-image acceptance must run it with that runtime input.
Official-image results do not certify gateway's modified proxy. Gateway private
mounts and management/signing API isolation remain V01-03 responsibilities.

## Supported boundary

Fixed versions, single-node IPv4, TCP/UDP and restricted application privileges
remain the tested scope. Calico's existing node endpoint default Drop prerequisite
remains explicit. Enrollment does not introduce Profile parsing, webhook handling,
policy reconciliation, a gateway generator, MITM, OPA, FakeIP mapping or upgrades.
Istio-only retains its historical security expectations and automatic injection;
fixture migrations update only its verified input fingerprint.
