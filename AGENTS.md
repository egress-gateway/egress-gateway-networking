# Networking development

- This repository owns shared Istio installation and its independent network
  acceptance suite. It must not import gateway/controller code, custom images or
  scripts. Those repositories consume the installation artifacts.
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
- PR0 establishes HTTP/mTLS using Istio sidecars and chained CNI. PR0.5 measures
  its not-fail-closed baseline; expected violations remain visible in per-case reports.
  Baseline expectations change only after evidence review, never at runtime. The Istio-only profile does not
  provide fail-closed egress. Public enrollment owns fixed network templates and
  pure generation, not controller reconciliation or gateway runtime composition.
  Preserve these ownership boundaries; parent V01-02 remains open.
