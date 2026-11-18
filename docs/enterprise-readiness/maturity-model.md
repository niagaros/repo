# Maturity model

Taken over unchanged from issue #294, so that the scorecard can be checked against the issue.

## Maturity (0–5)

| Score | Maturity | Definition |
|---|---|---|
| 0 | Not Started | No implementation or evidence |
| 1 | Initial | Basic implementation or informal process |
| 2 | Developing | Functionality exists but is incomplete or inconsistently applied |
| 3 | Defined | Documented, implemented and repeatable |
| 4 | Managed | Measured, tested, monitored and operationally controlled |
| 5 | Assured | Independently validated, continuously monitored and supported by evidence |

## Implementation status

Not Started → Designed → In Development → Implemented → Deployed → Operational → Tested → Validated → Independently Assessed.

## Evidence level

| Level | Example | Confidence |
|---|---|---|
| E0 | No evidence | None |
| E1 | Architecture or design documentation | Low |
| E2 | Source code, configuration or infrastructure definition | Limited |
| E3 | Automated test results or deployment evidence | Moderate |
| E4 | Production telemetry and operational records | High |
| E5 | Independent security assessment or witnessed validation | Very high |

## Rules applied in this assessment

1. A score is never calculated from documentation alone (E1 caps a domain at 1).
2. Maturity 4 needs E4 (production records) for the core claim; maturity 5 needs E5. **No domain has E5 yet**, so no
   domain scores 5.
3. A failed mandatory control cannot be offset by another domain; gates are judged separately from scores.
4. Evidence must match the scope of the claim: a local test does not prove production behaviour.
