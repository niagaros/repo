# Digital domains (GitHub issue #272)

Added 2026-10-26. This covers the part of #272 assigned to this branch: `app.niagaros.com`, `trust.niagaros.com`,
`trust.domits.com` and `developers.niagaros.com`.

## What is built

| Domain | Served by | Status |
|---|---|---|
| `app.niagaros.com` | Amplify app `d3joqokkaynfaq`, branch `main` | DNS records added at SiteGround on 2026-10-30 |
| `trust.niagaros.com` | Same app, branch `sofyan-dev` for now; the host picks the Trust Center | DNS records added at SiteGround and TXT verified on 2026-10-30. The first association (26 Oct) timed out and was recreated, which changed the CloudFront target |
| `trust.domits.com` | Same app, branch `sofyan-dev` for now | Live (HTTPS); DNS records added in the Domits Route 53 on 2026-10-26. Waits for the Domits TXT verification |
| `developers.niagaros.com` | GitBook, from `docs/developers/` (Git Sync) | Content ready; needs a GitBook space with this domain |

### Trust Center on a company's own domain

- Settings page (`trust_center.html`, card "Custom domain"): the admin enters a hostname. The API stores it
  unverified, with a random token, and shows a TXT record `_niagaros-trust.<domain>` = `niagaros-verify=<token>`.
- "Verify" looks the record up over DNS-over-HTTPS (`DOH_URL`, default Cloudflare). A failed lookup returns 503 and
  never counts as "record absent". A missing record ends an earlier verification.
- Only verified domains are unique (partial unique index, migration `036`), so an unverified claim can never block
  the real owner. `app.niagaros.com` and the other Niagaros hosts can never be claimed.
- `GET /trust-center?domain=<host>` (public) returns the Trust Center for a verified domain only.
- On a host other than the app hosts, `index.html` sends visitors to `trust_center_public.html`. That page then
  ignores `?slug=` and only asks for its own hostname, so `trust.domits.com/?slug=other` cannot show another
  company's page under the Domits address.
- Approval emails keep using the Niagaros host for download links, because a verified domain may not have HTTPS yet.

### Security headers

`customHttp.yml` (repo root, Amplify monorepo format) sets HSTS, X-Frame-Options DENY, nosniff, Referrer-Policy,
Permissions-Policy and a CSP with `frame-ancestors 'none'; object-src 'none'; base-uri 'self'`. The CSP does not
restrict scripts yet, because the standalone pages still use inline scripts and CDN libraries. HTTP to HTTPS is
handled by Amplify/CloudFront.

### Other changes

- The auditor invite link only uses the request origin when it is one of our own app hosts. Before, any
  `*.amplifyapp.com` origin was accepted, so an attacker's Amplify app could receive invite links.
- The Trust Center handler refuses ids that are not canonical UUIDs before `tenant_auth.guard` runs (see open item 1).

## Steps that need someone with access

### 1. SiteGround (niagaros.com DNS)

| Type | Name | Value |
|---|---|---|
| CNAME | `_300e373fc99208e65085f6b43f546c95` | `_266383a255706bf364ad333424a406c6.wzccmgtwzk.acm-validations.aws.` |
| CNAME | `app` | `dk5ppe8zpz66a.cloudfront.net` |
| CNAME | `trust` | `dk5ppe8zpz66a.cloudfront.net` |
| TXT | `_niagaros-trust.trust` | `niagaros-verify=acda09580364326900a1aea50d7c7f5c` (set for the Niagaros account on 2026-10-26) |
| CNAME | `developers` | the target GitBook shows when you add the custom domain (step 3) |

### 2. Domits (domits.com DNS, Route 53 in the Domits AWS account)

| Type | Name | Value |
|---|---|---|
| CNAME | `_f8d026c1d039122f98ea860f353aa4a9.domits.com` | `_9c1b34f0e06f78d4370b869115b2973e.wzccmgtwzk.acm-validations.aws.` |
| CNAME | `trust.domits.com` | `dlvm613unyqmq.cloudfront.net` |
| TXT | `_niagaros-trust.trust.domits.com` | shown on the Domits Trust Center settings page after a Domits admin enters `trust.domits.com` |

The Domits Trust Center must also be switched to public, or the domain shows "not public".

### 3. GitBook (developers.niagaros.com)

1. Create a GitBook space "Niagaros Developers" and enable Git Sync with `niagaros/repo`, branch `main`, project
   directory `docs/developers` (`.gitbook.yaml` is there).
2. In the space, add the custom domain `developers.niagaros.com` and put the CNAME it shows at SiteGround.

### 4. After DNS

- Amplify issues the certificate once the validation CNAMEs resolve (`aws amplify get-domain-association`).
  Amplify gives up after about 72 hours without DNS; then delete and recreate the association.
- The host routing only works once this branch is merged into `main`, because the domains serve `main`.
- Add `https://app.niagaros.com` to the callback URLs of the GitHub OAuth app (its owner must do this) and set
  `FRONTEND_BASE_URL` / `APP_BASE_URL` on the Lambdas to `https://app.niagaros.com` once the domain is live.

## Open items

1. `tenant_auth.guard` skips a `cloud_account_id` or REFS id that is not a canonical UUID, while PostgreSQL also
   accepts other spellings (32 hex digits, braces). The Trust Center handler now checks this itself; CIEM, AI
   Inventory and Security Agents already validate the id before the guard. The other handlers still need a check.
   Fixing it inside the guard needs care, because some REFS keys (`audit_detail`, `gap_data`, `list_scenarios`, …)
   are aliases whose values may not be ids.
2. The rest of #272 (www, auth, api, docs, marketplace, partners, status, security, academy, community, support,
   staging/dev environments) is not part of this branch.
