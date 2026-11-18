# Trust Center

`/trust-center`

## Public view (no token)

| Request | Returns |
|---|---|
| `GET /trust-center?slug=<public_slug>` | The public Trust Center of the company with that slug |
| `GET /trust-center?domain=<hostname>` | The public Trust Center connected to a verified custom domain, such as `trust.domits.com` |
| `POST /trust-center` with `{"action": "request_access", "document_id", "requester_name", "requester_email", "reason", "nda_accepted_name"}` | Requests access to a restricted document |

Both views return `404` if the Trust Center does not exist or is not public. The compliance scores in the view are
live. They come from the latest scan, using the same query as the dashboard.

## Settings (token with write rights)

Send `POST /trust-center` with `cloud_account_id` and one of these actions:

| `action` | Fields |
|---|---|
| `update_settings` | `is_public`, `company_name`, `intro_text`, `contact_email` |
| `set_custom_domain` | `custom_domain`: a hostname such as `trust.yourcompany.com`. An empty value removes it |
| `verify_custom_domain` | No extra fields. Checks the TXT record `_niagaros-trust.<domain>` |

### Custom domain

1. `set_custom_domain` returns `txt_name` and `txt_value`. Add that TXT record at your DNS provider.
2. `verify_custom_domain` looks up the record. Until the record is found, the domain stays unverified and serves
   nothing. If another Trust Center has already verified the domain, you get `409`.
3. Niagaros then enables HTTPS for the domain and gives you the CNAME record that makes it live.
