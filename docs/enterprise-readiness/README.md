# Enterprise readiness (issue #294)

This folder is the phase 1 deliverable of #294: the **actual current state** of Niagaros, measured on
**16 November 2026**, with every score tied to evidence. It replaces the historical 0–10 baseline in the issue,
which is kept there as history. The old scores are not reused here, because they were never backed by evidence.

| File | What it answers |
|---|---|
| [maturity-model.md](maturity-model.md) | How scores, statuses and evidence levels are defined (copied from the issue, so the rules cannot drift) |
| [readiness-scorecard.md](readiness-scorecard.md) | Per domain: maturity 0–5, implementation status, evidence, owner, limits, next validation |
| [gates.md](gates.md) | The 10 readiness gates: passed or not, and what is missing |
| [capability-register.md](capability-register.md) | Every product capability with its implementation status and where the evidence is |
| [risk-register.md](risk-register.md) | Known risks and technical debt, with what limits them today |
| [p0-backlog.md](p0-backlog.md) | The prioritised P0 remediation backlog that follows from the gates |
| [evidence-register.md](evidence-register.md) | Evidence records (E-IDs) referenced by the other files |

## The infrastructure inventory is not in this repository

This repository is public. The issue itself requires that sensitive evidence stays access-controlled. The live
infrastructure inventory (Lambda functions, API routes, schedules, databases, buckets, identity configuration,
secret names, alarms) is therefore generated **locally** and is git-ignored:

```
python tests/tools/enterprise_inventory.py --profile <admin profile>   # writes docs/enterprise-readiness/inventory/ (ignored)
```

The script only reads (no AWS changes), never reads secret values, and stamps every table with the read time. The
scorecard below quotes only counts and findings from it, not the details.

## How to keep this honest

- A score changes only with new evidence in [evidence-register.md](evidence-register.md), with a date.
- "Implemented" or "Deployed" is never enough for a high score (see the evidence rule in the maturity model).
- Owners are listed as **Unassigned** where nobody has accepted ownership. Names are not filled in on someone's behalf.
- Passing a gate here is not an ISO 27001, SOC 2 or other certification.
