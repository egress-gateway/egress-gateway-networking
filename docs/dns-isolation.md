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

`install/scripts/protected-pod.sh` reads one Pod or Deployment JSON on stdin and
writes rendered JSON on stdout. It requires explicit `--kubeconfig` and
`--context`, queries the installed Istiod Service, and never applies resources.
The caller establishes the NetworkPolicy before creating the rendered workload.

The input must carry `networking.egress/protected: 'true'` or the DNS fixture's
`networking.dns/protected: 'true'` on the Pod metadata. An existing
`proxy.istio.io/config` annotation must be JSON; unsupported input fails rather
than being silently replaced. The operation preserves other proxy metadata,
sets `ISTIO_META_DNS_CAPTURE`, and maps Istiod's two service names to its current
IPv4 Service address. It preserves TLS name validation, does not grant application
API access, and does not open DNS during bootstrap. Re-render Pods after an
Istiod Service address change. This is a static composition operation, not the
future public enrollment API or a reconciliation controller.

Both the egress and independent DNS fixtures use this operation. It does not
change mesh defaults, gateway Pods or the Istio-only profile. Fault Pods inherit
the rendered configuration before applying their deliberate test-only overrides.

The subsequent enrollment contract defaults to no DNS egress and will support
explicit caller-selected resolver endpoints and TCP/UDP 53. Such exceptions are
Pod-wide: NetworkPolicy cannot permit a sidecar while excluding the application.
The consumer owns query policy, recursion and tunnel prevention. That future
mode requires its own acceptance; it is not implemented here.

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
