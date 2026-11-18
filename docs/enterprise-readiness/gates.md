# Readiness gates — 16 November 2026

A gate passes only when all its mandatory requirements are implemented, tested **and** evidenced. A strong result in
one gate does not compensate for another. **No gate is passed yet.**

| Gate | Required outcome | Status | What is in place (evidence) | What blocks it |
|---|---|---|---|---|
| 1 Architecture | Approved platform architecture | Not passed | Live inventory (E-001) | No reviewed architecture diagrams or ADRs, no infrastructure as code (E-013) |
| 2 Identity | Enterprise-grade authentication and authorization | Not passed | TOTP, passkeys, recovery codes, step-up, roles, tenant guard (E-005–E-007) | MFA optional; org MFA policy not enforced server-side (P0-01); no SSO/SCIM (P0-11) |
| 3 Tenant isolation | Customer data and operations isolated | Not passed (closest) | Guard on every account-data API; IDOR matrix in CI; live 401/403 probes (E-005) | Needs an independent review of the guard and of every handler's REFS; no database-level isolation (P0-02) |
| 4 Application security | Secure development and release | Not passed | CodeQL, Dependabot, CI tests, deploy gate (E-002–E-004, E-016) | No DAST, no penetration test (P0-08); branch protection workflow disabled (P0-14) |
| 5 Data protection | Data protected through its lifecycle | Not passed | Encryption at rest and in transit, versioned buckets, backups (E-008) | Public database endpoint (P0-07); no secret rotation (P0-06); deletion on offboarding not validated (P0-12) |
| 6 Reliability | Defined and validated reliability | Not passed | Multi-AZ, restore test with measured RPO/RTO (E-009) | No SLOs, no load test, restore tested once (P0-10) |
| 7 Operations | Monitoring and incident response | Not passed | Smoke checks every 30 min; account-activity alarms; platform health alarms added today (E-010) | No runbooks, no on-call or escalation definition, no incident exercise (P0-03, P0-10) |
| 8 Auditability | Traceable security evidence | Not passed | Append-only audit trails per module (E-014) | No central administrative audit view or retention policy (P0-09) |
| 9 Compliance | Defensible control mapping | Not passed | Mapping audits and the no-fabrication test (E-015) | No external review of mappings; evidence lifecycle not formalised (P0-09) |
| 10 Enterprise operations | Repeatable onboarding and support | Not passed | Onboarding wizard and tests | Email delivery in sandbox (E-018); no support policy (P0-10) |
