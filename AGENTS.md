# Networking development

- This repository owns the Kubernetes/Calico fail-closed foundation, pure enrollment
  contract and independent acceptance suite. Gateway owns governance composition,
  proxy/identity implementations and readiness. Controller owns Kubernetes management.
  Do not import those repositories or require their images/tests as gates.
- Go 1.26.0 minimum; CI uses Go 1.26.7. Apply version-appropriate Go idioms.
- English Gherkin describes behavior. Go/Godog owns suite lifecycle and
  assertions. Shell scripts implement complete independently runnable operations.
  YAML owns deployment configuration. Make and CI call the same Go entrypoint.
- Run `make check` for code changes and `make e2e` for installation or acceptance
  changes. Lifecycle changes also require `up -> test -> test -> down` using the
  documented Make commands. Report local checks separately from CI results.
- Use explicit kubeconfig/context. Refuse existing cluster takeover and validate
  node ownership before access/deletion. Never delete unrelated Docker resources.
- Keep generated state under `.e2e/state` and safe reports under `.e2e/artifacts`.
  Never commit/upload kubeconfig, Secrets, keys or complete proxy config dumps.
- Only Calico enforce is supported. No Istio baseline success mode or compatibility
  adapter. Trusted specifications come from the platform independently of workloads.
  Keep existing security checks and independent receiver/enforcement evidence.
- #13 owns new protocol closure and four new TCP first-packet cases. Do not expand
  supported security claims from a subset of passing tests. No merge/release/deploy
  is implied by acceptance; parent V01-02 remains open.
