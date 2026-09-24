Feature: Egress contracts have observable evidence
  The Istio-only baseline records violations without calling them secure.

  Scenario Outline: <id> <description>
    When the "<protocol>" probe targets "<target>" from "<client>" during "<phase>"
    Then the egress contract "<contract>" is evaluated using complete evidence for this case

    Examples: Permitted paths
      | id    | description                          | protocol | target   | client   | phase   | contract |
      | N4-01 | HTTP uses both authenticated proxies | http     | routed   | workload | healthy | gateway  |
      | N4-02 | HTTPS uses both authenticated proxies| https    | routed   | workload | healthy | gateway  |
      | N6-01 | Fresh identity and control bootstrap | http     | routed   | workload | fresh   | gateway  |

    @istio-only
    Examples: Historical recursive DNS allowance
      | id | description | protocol | target | client | phase | contract |
      | N5-01 | UDP DNS uses the designated resolver | dns-udp  | dns      | workload | healthy | allow    |
      | N5-02 | TCP DNS uses the designated resolver | dns-tcp  | dns      | workload | healthy | allow    |

    Examples: Forbidden direct destinations and transports
      | id    | description                          | protocol | target   | client   | phase   | contract |
      | N1-01 | Sidecar HTTP bypasses gateway        | http     | external | workload | healthy | deny     |
      | N1-02 | Sidecar TLS bypasses gateway         | https    | external | workload | healthy | deny     |
      | N1-03 | Direct raw TCP reaches outside mesh  | tcp      | external | workload | healthy | deny     |
      | N1-04 | Same namespace Service is isolated   | tcp      | same     | workload | healthy | deny     |
      | N1-05 | Other namespace Service is isolated  | tcp      | other    | workload | healthy | deny     |
      | N1-06 | Node address is isolated             | tcp      | node     | workload | healthy | deny     |
      | N1-07 | Same namespace Pod IP is isolated    | tcp      | same-ip  | workload | healthy | deny     |
      | N1-08 | Other namespace Pod IP is isolated   | tcp      | other-ip | workload | healthy | deny     |
      | N1-09 | DNS-resolved Service is isolated     | tcp      | other-dns| workload | healthy | deny     |
      | N1-10 | Traffic without either proxy is denied| tcp     | external | plain    | healthy | deny     |
      | N1-11 | UDP 443 is denied                    | udp      | udp443   | workload | healthy | deny     |
      | N1-12 | Non-443 UDP is denied                | udp      | external | workload | healthy | deny     |
      | N1-13 | Real QUIC on 443 is denied           | quic     | quic443  | workload | healthy | deny     |
      | N1-14 | Real QUIC on non-443 is denied       | quic     | external | workload | healthy | deny     |
      | N1-15 | DNS to another resolver is denied    | dns-udp  | external | workload | healthy | deny     |
      | N2-01 | Wrong gateway TCP port is denied     | tcp      | wrong    | workload | healthy | deny     |
      | N2-02 | Wrong gateway UDP tuple is denied    | udp      | wrong    | workload | healthy | deny     |

    Examples: Authentication is not replaced by reachability
      | id    | description                          | protocol | target   | client   | phase     | contract |
      | N3-01 | Plaintext without sidecar is refused | http     | gateway  | plain    | healthy   | reject   |
      | N3-02 | Missing client certificate is refused| tls      | gateway  | plain    | healthy   | reject   |
      | N3-03 | Untrusted client certificate is refused| tls    | gateway  | plain    | untrusted | reject   |
      | N3-04 | Unauthorized workload identity is refused| http | routed   | intruder | healthy   | reject   |
      | N3-05 | Wrong gateway identity is refused    | http     | routed   | workload | wrong-san | reject   |

    Examples: Startup and failure windows never permit fallback
      | id    | description                          | protocol | target   | client   | phase       | contract |
      | N1-20 | Init first UDP packet is isolated    | udp      | external | workload | init        | deny     |
      | N1-21 | Application first packet is isolated | udp      | external | workload | first       | deny     |
      | N1-22 | Missing redirect never opens egress  | tcp      | external | workload | redirect    | deny     |
      | N1-23 | Stopped sidecar never opens UDP      | udp      | external | workload | sidecar-stop| deny     |
      | N1-24 | Restarting sidecar never opens egress | udp      | external | workload | sidecar-kill| deny     |
      | N1-25 | Unready sidecar never opens egress   | udp      | external | workload | sidecar-unready| deny  |
      | N1-26 | Unavailable gateway never opens egress| tcp     | external | workload | gateway-down| deny     |
      | N1-27 | Restarting gateway never opens egress| udp      | external | workload | gateway-restart| deny  |
      | N1-28 | Unavailable Istiod never opens egress| udp      | external | workload | istiod-down | deny     |
      | N4-10 | Existing authenticated stream stays governed| http| routed  | workload | existing    | gateway  |
      | N4-11 | Missing CNI redirects block startup then repair| http| routed| workload | repair     | startup  |
      | N4-12 | New identity cannot fall back when Istiod is down| http| routed| workload| identity-down| startup |
