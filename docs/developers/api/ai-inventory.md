# AI Inventory

`/ai-inventory` lists the AI agents, models, guardrails, tools and MCP servers found in your AWS account and GitHub
organisation.

Every request needs `cloud_account_id`.

## Read (`GET /ai-inventory?cloud_account_id=…&view=…`)

| `view` | Extra parameters | Returns |
|---|---|---|
| `overview` (default) | | Counts, risk summary, last collection per source |
| `assets` | Filters as query parameters | AI assets |
| `asset` | `asset_id` | One asset with its relationships, findings and risk factors |
| `findings`, `changes` | Filters as query parameters | Findings, and the change history |
| `graph` | | Relationships between assets |
| `shadow` | | AI use found in code but not registered |
| `settings`, `audit`, `scans` | | Settings, audit log, collection history |
| `export` | `what` (`assets`, `findings`, `relationships`, `changes`, `audit`, `evidence`), `format` | A download (`evidence` is JSON only) |

## Change (`POST /ai-inventory`)

`action` is one of `register_asset`, `update_asset`, `import_assets`, `delete_asset`, `link_assets`, `unlink_assets`,
`set_finding_status`, `create_ticket`, `refresh_ticket`, `save_settings`, `run_scan`.
