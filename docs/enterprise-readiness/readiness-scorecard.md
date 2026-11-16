# Readiness scorecard — 16 November 2026

Newly validated scores on the 0–5 model ([maturity-model.md](maturity-model.md)). They are **not** comparable with the
historical 0–10 baseline in issue #294. Owner is **Unassigned** wherever nobody has accepted ownership; that is itself
an open item (P0-13).

| # | Domain | Maturity | Status | Evidence | Owner | Known limitations | Open items | Next validation |
|---|---|---|---|---|---|---|---|---|
| 1 | Platform architecture & data foundation | **2** Developing | Deployed | E-001, E-013 | Unassigned | No infrastructure as code, no architecture decision records, one shared database for all environments, no per-branch backend | P0-04 | 2027-01 |
| 2 | Cloud infrastructure & platform engineering | **2** Developing | Operational | E-001, E-008, E-012 | Unassigned | Manual script deploys (verified after each deploy, but not reproducible from a definition); one function on an unsupported runtime | P0-04, P0-05 | 2027-01 |
| 3 | Identity, authentication & access | **3** Defined | Operational, tested | E-005, E-006, E-007 | Unassigned | MFA optional platform-wide; an organization's MFA policy is enforced by the web app, not by the API; no SSO/SCIM; Cognito self-service APIs accept a stolen access token for up to an hour (changes are recorded as observed) | P0-01, P0-11 | 2027-01 |
| 4 | Application security & supply chain | **2** Developing | Tested | E-002, E-003, E-004, E-016 | Unassigned | No dynamic testing, no penetration test, branch-protection workflow is commented out, backend DB tests not in CI | P0-08, P0-14 | 2027-01 |
| 5 | Data security & privacy | **3** Defined | Operational | E-008, E-011, E-017 | Unassigned | Database reachable from the internet (accepted risk); no secret rotation; customer data deletion on offboarding not validated end-to-end | P0-06, P0-07, P0-12 | 2027-01 |
| 6 | Exposure & cloud security posture (product) | **3** Defined | Operational | E-001 (weekly scan schedule), E-015, E-019 | Unassigned | Scanner failures are recorded but not alerted per account; coverage limited to S3, IAM, KMS, CloudWatch/CloudTrail, Cognito, GitHub, CIEM, AI inventory | — | 2027-01 |
| 7 | Workload, runtime & threat detection | **1** Initial | In development | E-019 (Security Agents) | Unassigned | No runtime agent, no workload or container scanning | Roadmap (P2) | — |
| 8 | AI security & governance | **2** Developing | Deployed | E-019 (AI Inventory, ISO 42001 as manual evidence) | Unassigned | Discovery of AI assets only; no model risk testing | Roadmap | — |
| 9 | Compliance, governance & audit | **3** Defined | Tested | E-014, E-015 | Unassigned | Audit trails are per module; no central administrative audit view; evidence lifecycle not formalised | P0-09 | 2027-01 |
| 10 | Integrations & open platform | **2** Developing | Deployed | E-019 | Unassigned | Jira/Monday only tested against local mocks; no public API versioning | — | — |
| 11 | Observability, reliability & operations | **2** Developing | Operational | E-009, E-010 | Unassigned | Platform alarms only since today; no SLOs, no runbooks, no incident exercise; restore tested once | P0-03, P0-10 | 2027-01 |
| 12 | Enterprise product & customer readiness | **2** Developing | Deployed | E-019, E-018 | Unassigned | Email delivery in sandbox; no published support policy or SLA | P0-10 | — |
| — | Tenant isolation (cross-cutting) | **3** Defined | Tested, live probes | E-005 | Unassigned | Isolation is enforced in application code on one shared database; no database-level row security | P0-02 (review) | Every PR |

**No domain reaches 4 or 5.** Maturity 4 needs production measurement and monitoring for the core claim; maturity 5
needs independent validation, which has not happened for any domain.
