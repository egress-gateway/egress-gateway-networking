@pr0
Feature: Shared Istio CNI connectivity
  Gateway and controller consumers need an independently installed network baseline.

  Scenario: P0-01 Native injection uses the chained Istio CNI
    Given the shared Istio installation and test workloads are ready
    Then native injection validates CNI redirection without istio-init

  Scenario: P0-02 Transparent HTTP traverses both proxies
    Given the shared Istio installation and test workloads are ready
    When the meshed client requests httpbin without an application proxy
    Then httpbin echoes this request's correlation ID
    And both proxies record this HTTP request
