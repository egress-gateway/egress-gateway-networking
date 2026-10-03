# Consumer-owned CNI composition

Networking installs `calico -> tuning -> portmap`. Its default effective check
requires that standalone chain. A trusted consumer may append its own CNI
components and explicitly check the foundation portion:

```sh
bash install/scripts/check.sh --kubeconfig /path/to/config --context CONTEXT \
  --cni-scope foundation
```

This checks the original first three entries and their existing invariants,
including policy waiting and both IPv6 sysctls. Missing, reordered or changed
foundation entries fail. Omitting the flag requires exactly three entries.
The foundation scope does not validate suffix plugin names, settings or behavior.
A passing configuration check alone does not certify runtime confinement.

The trusted consumer owns appended components, their configuration, compatibility,
installation, capture semantics and repair. It must validate that its composed
environment preserves external confinement and pre-business IPv6 disablement.
Recheck effective configuration after installation and component reconciliation:
the foundation installer writes its three-entry chain, and the consumer owns
reconciling its suffix. No plugin-specific version or proxy setting is part of
the networking contract, and no general plugin configuration API is provided.

For management initialization, use the independently supplied, separately authorized
terminating init contract in [enrollment.md](enrollment.md). The platform's approval
of initializer code and configuration is essential: network-administration
capabilities affect all containers sharing this network namespace. Networking
does not reserve proxy UIDs or implement management-interface isolation. Gateway
owns those semantics, its startup/readiness contract and composed-environment
acceptance.

## Test fixture and evidence

The existing `make e2e` suite includes I1-01. Istio is a concrete test fixture;
its version and plugin-specific assertions below are not public requirements.
It temporarily installs only the upstream CNI, using the pinned generated fixture in `test/e2e/config/istio-cni.yaml`.
No Gateway application image, istiod, injection webhook or controller is required.
An independent Pod deliberately uses the CNI-selected bypass UID for direct
network attempts; this is a foundation-isolation test, not a Gateway enrollment
example or a proof of two-stage authorization.

The test verifies real CNI capture rules and separately authorized terminating
network preparation, IPv6 closure and unchanged restricted business privileges,
attributable forbidden TCP during preparation/first init, and working allowed IPv4.
It repeats the execution after upstream CNI/Calico restarts and a policy-unavailable
startup window, then restores the standalone chain. These are single-node tests
for the pinned baseline, not production upgrades, arbitrary version compatibility
or complete Istio repair/governance acceptance.

The CNI manifest was generated from the official Istio 1.31.0 release archive
(SHA-256 `79fda9a16d0e718677cd8a1c01eb859dc90e18adf7fcd2a7c18cfb8819ab4903`):

```sh
helm template networking-cni istio-1.31.0/manifests/charts/istio-cni \
  --namespace networking-cni -f test/e2e/config/istio-cni-values.yaml \
  > test/e2e/config/istio-cni.yaml
```

The fixture and independent initializer base image are digest-pinned. Helm is
needed to regenerate the fixture, not to execute the suite. The test image copies
only the repository's probe into the upstream base that supplies iptables.
