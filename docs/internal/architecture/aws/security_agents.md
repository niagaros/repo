# Security Agents: Red, Blue, Green (issue #239)

Nine deterministic agents that turn data Niagaros already collects read-only into one governed security
workflow. No language model makes decisions; every agent is versioned code with a built-in evaluation.

| Category | Agents | Data | What they do |
|---|---|---|---|
| Red | Identity Attack-Path, Vulnerability Assessment, AI Security Testing | CIEM, native scanner findings (mapped-framework duplicates excluded), AI Inventory | Publish potential weaknesses and attack paths. Analysis only: every item says "not validated". |
| Blue | Identity Defense, Cloud Threat, AI Threat Defense, Incident Triage | CloudTrail `LookupEvents` (management events, account region, ≤ 90 days) | Detection rules with MITRE ids and CloudTrail event ids as evidence; triage groups detections per identity and correlates them with open Red items (raises their priority). |
| Green | Remediation Planning, Verification | Work items, latest scan results | Plans and tickets; resolves an item only when a later scan no longer reports it; re-opens it when it comes back or a recorded fix fails. |

## Governance

- **Lifecycle:** registered → configured (owner) → tested (evaluation of the current version passed) → active (approved by a person), plus paused/restricted/deprecated/retired. Only active agents run. "Set up all agents" performs the same steps for the person clicking it, each recorded.
- **Authorisation** (`sa_authorizations`): per agent, account and environment, time-bound, allowed/prohibited actions, revocable.
- **Autonomy** (`sa_policies`): L0–L4 per agent, action and environment. L5 is refused. Actions that change customer systems (containment, apply change) always need approval and are executed by the customer: Niagaros has no write access.
- **Execution-time checks:** `Workflow.check` reloads lifecycle, authorisation and policy before every action and writes the decision (allow, approval_required or block) to `sa_actions`, including blocked attempts and notifications.
- **Offensive techniques** (exploitation, scanning, credential attacks, live prompt injection, destructive tests) are always blocked and audited.
- **Approvals:** expire after 7 days. Separation of duties: a person cannot approve their own request while another administrator of the account exists. Executable actions (ticket, re-scan) are re-authorised when approved.
- **State machine:** New → Triaged → Assigned → In progress → (Awaiting approval) → Remediated → Verification → Resolved, plus Blocked, Accepted risk (reason + end date ≤ 1 year), False positive and Reopened. Only the Verification Agent sets Resolved or Reopened. Detections are closed by a person with a reason and counted separately from scan-verified resolutions.
- **Append-only** for the runtime role: `sa_work_item_events`, `sa_evidence`, `sa_audit_log`.

## Runtime

- `security-agents-scanner` (runner) is in the `scanners` table, so the orchestrator starts it with every account scan; it hands off to an async invocation. One invocation is one workflow with one run per active agent.
- Each Blue agent keeps its own CloudTrail cursor and moves it only after a complete, published read. Unreadable or truncated event types are coverage gaps shown on the page, never "no threat".
- `security-agents-handler` serves `GET/POST /security-agents` behind `tenant_auth.guard` (REFS for every id); unauthenticated calls are rejected before a database connection.

## Added 2026-10-22

- **Attack Surface Agent (Red):** reads security groups, instances (IPv4 and IPv6, with their instance role), RDS and
  Lambda function URLs in every enabled region and builds paths internet → port/protocol → resource → role →
  what the role can do (CIEM). Configuration only; nothing is scanned. Verification: the item resolves when a later
  complete read no longer finds the exposure.
- **AWS Detection Integration Agent (Blue):** active GuardDuty and Security Hub findings in every region (a Security
  Hub copy of a GuardDuty finding is skipped only when that finding was imported directly). Regions where the services
  are off are reported as coverage gaps.
- CloudTrail detections in every enabled region; a failed region list makes the run partial (the cursor does not move).
- SLA due dates per severity (7/30/90/180 days) and a daily overdue notification; verification re-scans for every
  source (the account-scoped orchestrator scan for CIS/FSBP findings), at most once per source per 6 hours.

## Not covered

Active penetration testing, network scanning, runtime/EDR telemetry, containers/Kubernetes, SBOM and
threat-intelligence feeds, and executing changes in customer accounts. The page states this.
