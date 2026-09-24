@pr0
Feature: Mutual TLS for shared networking consumers
  Service authentication is a baseline capability, separate from egress isolation.

  Scenario: P0-03 Both proxies authenticate the expected workload identities
    Given the shared Istio installation and test workloads are ready
    When the meshed client requests httpbin without an application proxy
    Then httpbin echoes this request's correlation ID
    And both proxies record this HTTP request
    And this request uses TLS with the expected peer SPIFFE identities on both sides

  Scenario: P0-04 STRICT authentication rejects a plaintext client
    Given the shared Istio installation and test workloads are ready
    When a temporary client without a sidecar requests httpbin in plaintext
    Then it receives no HTTP response and the server records a TLS listener rejection
