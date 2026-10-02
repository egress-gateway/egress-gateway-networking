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

  @tcp-startup
  Scenario Outline: <id> TCP remains isolated from the first possible packet
    When the network probe "tcp" targets "np-external" during "<phase>"
    Then the network contract "<contract>" has attributable packet and enforcement evidence

    Examples:
      | id        | phase      | contract     |
      | N1-20-TCP | first-init | first-packet |
      | N1-21-TCP | first-app  | first-packet |
      | C3-03-TCP | felix-new  | startup      |
      | C3-04-TCP | felix-init | startup      |

  @protocol-closure
  Scenario Outline: <id> Available non-TCP/UDP protocols cannot leave the protected Pod
    When the network probe "<protocol>" targets "np-protocol" during "healthy"
    Then the network contract "protocol-closure" has attributable packet and enforcement evidence

    Examples:
      | id    | protocol |
      | N1-23 | sctp     |
      | N1-24 | icmp     |
      | N1-25 | udplite  |

  @protocol-closure
  Scenario: N1-26 Remaining IP socket protocols are unavailable to the application
    When the network probe "inventory" targets "np-socket-matrix" during "healthy"
    Then the network contract "socket-matrix" has attributable packet and enforcement evidence

  @ipv6-closure
  Scenario Outline: <id> IPv6 closure precedes business execution
    When the network probe "ipv6" targets "np-ipv6" during "<phase>"
    Then the network contract "ipv6-closure" has attributable packet and enforcement evidence

    Examples:
      | id    | phase           |
      | N1-22 | first-execution |
      | N1-27 | cni-failure     |

  @api-endpoint
  Scenario Outline: <id> API connectivity follows the exact trusted endpoint allowance
    When the network probe "tcp" targets "<target>" during "<phase>"
    Then the network contract "api-endpoint" has attributable packet and enforcement evidence

    Examples:
      | id    | target      | phase      |
      | A1-01 | api-direct  | deny       |
      | A1-02 | api-service | deny       |
      | A1-03 | api-direct  | allow      |
      | A1-04 | api-service | allow      |
      | A1-05 | api-direct  | wrong-port |
      | A1-06 | api-service | wrong-port |
      | A1-07 | api-direct  | revoke     |
      | A1-08 | api-service | revoke     |
