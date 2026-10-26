# AI Security Agents

`/security-agents` covers the Red (analysis), Blue (detection) and Green (verified resolution) agents.

Every request needs `cloud_account_id`. Red agents only observe and assess: they never attack or change anything.
Each agent action is authorised again at the moment it runs, against the autonomy level you granted.

## Read (`GET /security-agents?cloud_account_id=…&view=…`)

| `view` | Extra parameters | Returns |
|---|---|---|
| `overview` (default) | | Agent status, open work, recent detections |
| `agents` / `agent` | `agent_id` for a single agent | Agents and their authorisations |
| `runs` / `run` | `run_id` for a single run | Agent runs |
| `queue` / `item` | `work_item_id` for a single item | Work items with their SLA |
| `detections`, `incidents` / `incident` | | Blue findings and incidents |
| `attack_paths`, `approvals`, `policies`, `settings`, `audit` | | |
| `export` | `what`, `format` | A download |

## Change (`POST /security-agents`)

`action` is one of `configure_agent`, `authorize_agent`, `revoke_authorization`, `set_policy`, `run_evaluation`,
`approve_agent`, `set_agent_status`, `activate_recommended`, `run_agents`, `transition_item`, `assign_item`,
`record_remediation`, `create_ticket`, `refresh_ticket`, `request_containment`, `decide_approval`, `update_incident`,
`update_detection`, `save_settings`, `request_technique`.
