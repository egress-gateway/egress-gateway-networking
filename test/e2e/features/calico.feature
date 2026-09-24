@calico @mesh
Feature: Calico keeps the protected network closed across faults
  Policy applies to the Pod independently of sidecar capture.
  API readiness and a policy setup timeout are not isolation evidence.

  @c1-01
  Scenario: C1-01 Raw TCP reaches the local workload Envoy
    When the network probe "tcp" targets "mesh-external" during "capture"
    Then the network contract "capture" has attributable packet and enforcement evidence

  @c1-02
  Scenario: C1-02 Wrong resolver TCP DNS is isolated
    When the network probe "dns-tcp" targets "mesh-external" during "healthy"
    Then the network contract "deny" has attributable packet and enforcement evidence

  @c1-03
  Scenario: C1-03 Gateway endpoint accepts authenticated HTTP
    When the network probe "http" targets "gateway-endpoint" during "healthy"
    Then the network contract "gateway" has attributable packet and enforcement evidence

  @c5-01
  Scenario: C5-01 DNS endpoint rejects direct UDP
    When the network probe "dns-udp" targets "dns-endpoint" during "healthy"
    Then the network contract "deny" has attributable packet and enforcement evidence

  @c5-02
  Scenario: C5-02 DNS endpoint rejects direct TCP
    When the network probe "dns-tcp" targets "dns-endpoint" during "healthy"
    Then the network contract "deny" has attributable packet and enforcement evidence

  @c1-06
  Scenario: C1-06 Unselected gateway namespace Pod is blocked
    When the network probe "tcp" targets "gateway-neighbor" during "healthy"
    Then the network contract "deny" has attributable packet and enforcement evidence

  @c1-07
  Scenario: C1-07 Unselected DNS namespace Pod is blocked
    When the network probe "dns-udp" targets "dns-neighbor" during "healthy"
    Then the network contract "deny" has attributable packet and enforcement evidence

  @c1-08
  Scenario: C1-08 Unselected Istiod namespace Pod is blocked
    When the network probe "tcp" targets "istiod-neighbor" during "healthy"
    Then the network contract "deny" has attributable packet and enforcement evidence

  @c1-09
  Scenario: C1-09 Wrong DNS endpoint TCP port is blocked
    When the network probe "tcp" targets "dns-wrong" during "healthy"
    Then the network contract "deny" has attributable packet and enforcement evidence

  @c1-10
  Scenario: C1-10 Wrong Istiod endpoint TCP port is blocked
    When the network probe "tcp" targets "istiod-wrong" during "healthy"
    Then the network contract "deny" has attributable packet and enforcement evidence

  @c1-11
  Scenario: C1-11 Gateway TLS endpoint preserves authentication
    When the network probe "https" targets "gateway-tls-endpoint" during "healthy"
    Then the network contract "gateway" has attributable packet and enforcement evidence

  @c2-01
  Scenario: C2-01 Proxy UID exclusion cannot open egress
    When the network probe "tcp" targets "mesh-external" during "proxy-uid"
    Then the network contract "deny" has attributable packet and enforcement evidence

  @c2-02
  Scenario: C2-02 Capture annotation cannot open egress
    When the network probe "tcp" targets "mesh-external" during "exclusion"
    Then the network contract "deny" has attributable packet and enforcement evidence

  @c3-01
  Scenario: C3-01 Existing Pod TCP stays isolated without Felix
    When the network probe "tcp" targets "np-external" during "felix-stopped"
    Then the network contract "deny" has attributable packet and enforcement evidence

  @c3-02
  Scenario: C3-02 Existing Pod UDP stays isolated without Felix
    When the network probe "udp" targets "np-external" during "felix-stopped"
    Then the network contract "deny" has attributable packet and enforcement evidence

  @c3-03
  Scenario: C3-03 New application has no policy timeout window
    When the network probe "udp" targets "np-external" during "felix-new"
    Then the network contract "startup" has attributable packet and enforcement evidence

  @c3-04
  Scenario: C3-04 New init has no policy timeout window
    When the network probe "udp" targets "np-external" during "felix-init"
    Then the network contract "startup" has attributable packet and enforcement evidence

  @c3-05
  Scenario: C3-05 Recovered agent restores the whitelist
    When the network probe "http" targets "np-service" during "felix-recovery"
    Then the network contract "recovery" has attributable packet and enforcement evidence

  @c3-06
  Scenario: C3-06 Primary restart preserves Istio chaining
    When the network probe "http" targets "mesh-routed" during "primary-restart"
    Then the network contract "chain" has attributable packet and enforcement evidence

  @c4-01
  Scenario: C4-01 New TCP obeys realized deny policy
    When the network probe "tcp" targets "np-wrong" during "revoke"
    Then the network contract "deny" has attributable packet and enforcement evidence

  @c4-02
  Scenario: C4-02 New UDP flow obeys realized deny policy
    When the network probe "udp" targets "np-udp" during "revoke"
    Then the network contract "deny" has attributable packet and enforcement evidence

  @c4-03
  Scenario: C4-03 Existing TCP outcome is recorded separately
    When the network probe "tcp" targets "np-wrong" during "existing-revoke"
    Then the network contract "observe" has attributable packet and enforcement evidence
