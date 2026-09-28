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
      | E1-05 | Trusted components retain allowance | enrollment-trusted-own   | allow |
      | E1-06 | Trusted components retain isolation | enrollment-trusted-other | deny  |

  Scenario Outline: <id> Trusted component lifecycle preserves isolation
    Given the independent enrollment bindings are ready
    When the network probe "http" targets "enrollment-trusted-other" during "<phase>"
    Then the network contract "deny" has attributable packet and enforcement evidence

    Examples:
      | id    | phase             |
      | E2-01 | runtime-stopped   |
      | E2-02 | runtime-restarted |

  Scenario: E3-01 Business and resident containers cannot change identity or network marks
    Given the independent enrollment bindings are ready
    Then restricted components cannot acquire identity or network privileges
