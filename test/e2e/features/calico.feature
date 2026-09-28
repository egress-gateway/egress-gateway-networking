@calico
Feature: Calico keeps the network closed across faults

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

  Scenario Outline: <id> Earliest workload traffic remains isolated
    When the network probe "udp" targets "np-external" during "<phase>"
    Then the network contract "first-packet" has attributable packet and enforcement evidence

    Examples:
      | id    | phase      |
      | N1-20 | first-app  |
      | N1-21 | first-init |
