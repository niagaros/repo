# Authentication

Niagaros users sign in with Amazon Cognito. The API accepts the user's **Cognito access token** as a bearer token:

```http
Authorization: Bearer <access token>
```

On every request, the API validates the token with Cognito. It then checks that every account and record the request
touches belongs to that user, either as owner or through organisation or business-unit membership. `GET` requests
only need read access. Changes need a role with write rights.

**Getting a token during the preview.** Sign in to [app.niagaros.com](https://app.niagaros.com). The app keeps your
session's access token in the browser, under `localStorage["niagaros_token"]`. A token is valid for one hour. Treat
it like a password: anyone who has it can act as you until it expires.

**Not available yet:** API keys, OAuth 2.0 client credentials for machine-to-machine use, and scoped tokens. Until
they exist, don't build unattended integrations on a copied user token.

**Public endpoints** need no token. Each API page lists its public endpoints, for example the public Trust Center
view.
