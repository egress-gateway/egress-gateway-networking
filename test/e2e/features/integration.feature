@calico @integration
Feature: Explicit upstream CNI integration preserves the foundation boundary
  The independent consumer deliberately uses the CNI bypass UID without a proxy.
  Network preparation is independently trusted and separately authorized.

  Scenario: I1-01 Istio chaining and terminating network preparation retain startup isolation
    When the fixed Istio CNI combination is exercised with trusted network preparation
    Then combination startup, IPv6, denial and recovery have attributable evidence
