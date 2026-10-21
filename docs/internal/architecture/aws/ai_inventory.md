# AI Inventory (issue #236)

Finds the AI a customer uses and keeps it governed: applications, agents, models, providers, MCP servers,
tools, prompts, knowledge bases, vector stores, AI endpoints and the IAM roles AI workloads run as.

## Pieces

| Piece | What it does |
|---|---|
| `ai_inventory_collector.py` | Reads AWS with the customer's `CSPMScannerRole` (Bedrock guardrails/models/logging/knowledge bases/agents, CloudWatch `AWS/Bedrock` invocations, SageMaker, OpenSearch Serverless vector collections, Lambda AI env var *names*) and the connected GitHub organisation (default branch, tarball or tree API). Secret values are never kept. |
| `ai_inventory_engine.py` | Pure: turns that into assets with stable keys, relationships, findings with evidence and compliance references. Every item has a verification level: declared (code/config), discovered (AWS lists it), observed (usage metrics), verified (a person reviewed it). |
| `ai_inventory_scanner_handler.py` | Lambda `ai-inventory-scanner`, run by the orchestrator in wave 1 (self-invokes async). Upserts assets, observations, relationships, change history and findings. |
| `ai_inventory_handler.py` | Lambda `ai-inventory-handler` behind `GET/POST /ai-inventory`, `tenant_auth.guard` on every call; rejects unauthenticated calls before opening a DB connection. |
| `frontend/public/ai_inventory.html` | Overview with coverage and denominators, assets, shadow AI, relationship graph with impact analysis, findings (status, risk acceptance, tickets), changes, manual registration and CSV import, settings, exports and audit trail. |
| `backend/migrations/033_ai_inventory.sql` | Eight tables. `ai_asset_changes` and `ai_inventory_audit_log` are append-only for `cspm_lambda`; change history outlives a deleted asset. |

## Rules that keep it honest

- An asset only becomes stale/inactive, a relationship is only removed, and a finding is only resolved when the
  source that reported it was read completely in this run (per AWS service, per repository). A failed or
  truncated source never turns into "gone".
- Scans never overwrite governance fields (owner, purpose, environment, criticality, approval). A high-impact
  configuration change withdraws "verified" and sets the review date to today.
- Providers come from endpoints in code or from AWS, not from model names. The OpenAI SDK only counts for OpenAI
  when no other provider endpoint was found.
- Credentials in MCP configs (env, headers, URL userinfo/query, `--token`, header arguments) are redacted before
  storage and reported as a finding by name only.

## Deploy

Done 2026-10-22 with a journaled script (read-only preflight, strict migration with privilege checks, own
least-privilege roles with scoped logs, canary run on the internal test account before routes were created,
CORS/401 checks, then the `scanners` row). A journal-driven rollback script exists next to it.
Reserved concurrency is not set: the account's Lambda concurrency limit is 10.

## Open

- GitHub must be connected per account (Settings → GitHub) for code to be inventoried.
- Single region (the account's region). SaaS AI tools, other clouds and runtime traffic are not covered yet;
  the page says so and offers manual registration.
