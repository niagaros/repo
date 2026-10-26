# CIEM

`/ciem` shows which identities in your AWS account can do what.

Every request needs `cloud_account_id`.

## Read (`GET /ciem?cloud_account_id=…&view=…`)

| `view` | Extra parameters | Returns |
|---|---|---|
| `overview` (default) | | Latest scan, finding counts, top identities by risk |
| `identities` | | All users, groups and roles, with risk score |
| `identity` | `arn` | One identity: effective access, findings, risk history |
| `findings` | | Open and resolved findings |
| `finding` | `finding_id` | One finding with its evidence |
| `paths` | | Privilege escalation and role-assumption paths |
| `external` | | Trust relationships with other AWS accounts, and external access |
| `reviews` / `review` | `review_id` for a single review | Access reviews |
| `business_units` | | Summary per business unit you can see |
| `settings`, `audit`, `scans` | | Rule settings, audit log, scan history |
| `export` | `what`, `format` (`csv` or `json`) | A download |

## Change (`POST /ciem`)

`action` is one of `set_finding_status`, `save_settings`, `save_custom_policies`, `create_review`,
`decide_review_item`, `create_ticket`, `refresh_ticket`.
