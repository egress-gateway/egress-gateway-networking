@calico @dns
Feature: Sidecar DNS capture and strict egress isolation
  DNS synthesis is not authorization. No independent gateway or recursive resolver
  is part of this fixture. Safety and application usability are separate results.

  Scenario Outline: <id> <description>
    Given the isolated local DNS configuration is ready
    When the DNS operation "<mode>" uses "<transport>" and "<type>"
    Then local DNS functionality and isolation have independently correlated evidence

    @dns-names @dns-functional
    Examples: names
      | id | description | mode | transport | type |
      | D1-01 | declared names receive local synthetic A over udp | declared | udp | A |
      | D1-02 | declared names receive local synthetic A over tcp | declared | tcp | A |
      | D1-03 | wildcard names receive local synthetic A over udp | wildcard | udp | A |
      | D1-04 | wildcard names receive local synthetic A over tcp | wildcard | tcp | A |

    @dns-isolation
    Examples: undeclared names
      | id | description | mode | transport | type |
      | DS-01 | unregistered names cannot reach external DNS over udp | unregistered | udp | A |
      | DS-02 | unregistered names cannot reach external DNS over tcp | unregistered | tcp | A |
      | DS-03 | other-suffix names cannot reach external DNS over udp | other-suffix | udp | A |
      | DS-04 | other-suffix names cannot reach external DNS over tcp | other-suffix | tcp | A |

    @dns-records
    Examples: records
      | id | description | mode | transport | type |
      | D2-01 | AAAA over udp cannot retrieve external DNS information | record | udp | AAAA |
      | D2-02 | AAAA over tcp cannot retrieve external DNS information | record | tcp | AAAA |
      | DS-05 | TXT over udp cannot retrieve external DNS information | record | udp | TXT |
      | DS-06 | TXT over tcp cannot retrieve external DNS information | record | tcp | TXT |
      | DS-07 | SRV over udp cannot retrieve external DNS information | record | udp | SRV |
      | DS-08 | SRV over tcp cannot retrieve external DNS information | record | tcp | SRV |
      | DS-09 | MX over udp cannot retrieve external DNS information | record | udp | MX |
      | DS-10 | MX over tcp cannot retrieve external DNS information | record | tcp | MX |
      | DS-11 | PTR over udp cannot retrieve external DNS information | record | udp | PTR |
      | DS-12 | PTR over tcp cannot retrieve external DNS information | record | tcp | PTR |
      | DS-13 | NULL over udp cannot retrieve external DNS information | record | udp | NULL |
      | DS-14 | NULL over tcp cannot retrieve external DNS information | record | tcp | NULL |
      | DS-15 | ANY over udp cannot retrieve external DNS information | record | udp | ANY |
      | DS-16 | ANY over tcp cannot retrieve external DNS information | record | tcp | ANY |
      | DS-17 | Search-expanded queries cannot reach external DNS | search | udp | A |
      | DS-18 | EDNS udp queries stay local | edns | udp | A |

    @dns-functional
    Examples: EDNS TCP positive control
      | id | description | mode | transport | type |
      | D2-17 | EDNS tcp queries stay local | edns | tcp | A |

    @dns-bypass
    Examples: bypass
      | id | description | mode | transport | type |
      | D3-01 | service DNS bypass over udp remains isolated | service | udp | A |
      | D3-02 | service DNS bypass over tcp remains isolated | service | tcp | A |
      | D3-03 | endpoint DNS bypass over udp remains isolated | endpoint | udp | A |
      | D3-04 | endpoint DNS bypass over tcp remains isolated | endpoint | tcp | A |
      | D3-05 | external DNS bypass over udp remains isolated | external | udp | A |
      | D3-06 | external DNS bypass over tcp remains isolated | external | tcp | A |
      | D3-07 | nameserver DNS bypass over udp remains isolated | nameserver | udp | A |
      | D3-08 | nameserver DNS bypass over tcp remains isolated | nameserver | tcp | A |
      | D3-09 | capture-off DNS bypass over udp remains isolated | capture-off | udp | A |
      | D3-10 | capture-off DNS bypass over tcp remains isolated | capture-off | tcp | A |
      | D3-11 | proxy-uid DNS bypass over udp remains isolated | proxy-uid | udp | A |
      | D3-12 | proxy-uid DNS bypass over tcp remains isolated | proxy-uid | tcp | A |
      | D3-13 | sidecar-stopped DNS bypass over udp remains isolated | sidecar-stopped | udp | A |
      | D3-14 | sidecar-stopped DNS bypass over tcp remains isolated | sidecar-stopped | tcp | A |
      | D3-15 | Disabled DNS capture cannot open forbidden TCP egress | capture-off-tcp | tcp | A |
      | D3-16 | Proxy UID cannot open forbidden TCP egress | proxy-uid-tcp | tcp | A |
      | D3-17 | Stopped sidecar cannot open forbidden TCP egress | sidecar-stopped-tcp | tcp | A |

      | D3-18 | DNS port exclusion over udp remains isolated | capture-excluded | udp | A |
      | D3-19 | DNS port exclusion over tcp remains isolated | capture-excluded | tcp | A |

    @dns-bootstrap @dns-functional
    Examples: bootstrap
      | id | description | mode | transport | type |
      | D4-02 | Trusted discovery names bootstrap without external DNS | bootstrap-mapped | udp | A |

    @dns-application @dns-functional
    Examples: application
      | id | description | mode | transport | type |
      | D5-01 | http-one reaches the local Envoy with correlated destination evidence | http-one | udp | A |
      | D5-02 | http-two reaches the local Envoy with correlated destination evidence | http-two | udp | A |
      | D5-03 | https-one reaches the local Envoy with correlated destination evidence | https-one | udp | A |
      | D5-04 | https-two reaches the local Envoy with correlated destination evidence | https-two | udp | A |
      | D5-05 | raw-tcp reaches the local Envoy with correlated destination evidence | raw-tcp | udp | A |

    @dns-lifecycle @dns-functional
    Examples: lifecycle
      | id | description | mode | transport | type |
      | D6-01 | restart cannot misroute cached synthetic addresses | restart | udp | A |
      | D6-02 | recreate cannot misroute cached synthetic addresses | recreate | udp | A |
      | D6-03 | stale-vip cannot misroute cached synthetic addresses | stale-vip | udp | A |

