@calico @np
Feature: A Pod egress whitelist works without either Istio proxy
  Only the selected httpbin endpoint and TCP listener may receive traffic.
  Receivers are healthy and unrestricted at ingress.

  Scenario Outline: <id> <description>
    When the network probe "<protocol>" targets "<target>" during "healthy"
    Then the network contract "<contract>" has attributable packet and enforcement evidence

    Examples:
      | id    | description                                      | protocol | target       | contract |
      | NP-01 | Selected httpbin Service is reachable             | http     | np-service   | allow    |
      | NP-02 | Selected httpbin Pod IP is reachable              | http     | np-ip        | allow    |
      | NP-03 | Other Pod in the allowed namespace is isolated    | http     | np-other     | deny     |
      | NP-04 | Same label in another namespace is isolated       | http     | np-cross     | deny     |
      | NP-05 | Other TCP listener on the allowed Pod is isolated | tcp      | np-wrong     | deny     |
      | NP-06 | UDP on the allowed Pod is isolated                | udp      | np-udp       | deny     |
      | NP-07 | Direct external TCP is isolated                   | tcp      | np-external  | deny     |
      | NP-08 | The local node receiver is isolated               | tcp      | np-node      | deny     |
