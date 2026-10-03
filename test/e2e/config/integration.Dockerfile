# The pinned upstream base supplies legacy iptables; /probe stays repository-owned.
FROM docker.io/istio/proxyv2:1.31.0@sha256:e3b973cce2442c2883188d8cf839dff8a21075fab0e00e5079df6ef28c9caf17
COPY --chmod=0555 probe /probe
ENTRYPOINT ["/probe"]
