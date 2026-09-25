@calico @enrollment
Feature: Independent network bindings preserve each Pod's whitelist
  Sharing a namespace does not grant a Pod another binding's destinations.

  Scenario Outline: <id> <description>
    Given the independent enrollment bindings are ready
    When the network probe "http" targets "<target>" during "healthy"
    Then the network contract "<contract>" has attributable packet and enforcement evidence

    Examples:
      | id    | description                         | target             | contract |
      | E1-01 | Binding A reaches its own endpoint  | enrollment-a-own   | allow    |
      | E1-02 | Binding A cannot use B's allowance  | enrollment-a-other | deny     |
      | E1-03 | Binding B reaches its own endpoint  | enrollment-b-own   | allow    |
      | E1-04 | Binding B cannot use A's allowance  | enrollment-b-other | deny     |

  Scenario: E1-05 Original enabled labels prevent duplicate injection
    Then the enrollment operation "injection" preserves the startup contract

  Scenario: E1-06 Proxy startup failure blocks business initialization
    Then the enrollment operation "startup" preserves the startup contract

  Scenario: E1-07 Applications cannot adopt proxy identity or change capture privileges
    Then the enrollment operation "privileges" preserves the startup contract

  Scenario: E3-01 Missing redirect listeners fail compatibility acceptance
    Then a missing redirect listener fails the normal capture verdict and recovers
