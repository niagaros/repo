# Niagaros for developers

Niagaros scans your AWS accounts and GitHub organisation, maps findings onto compliance frameworks and shows the
results in [app.niagaros.com](https://app.niagaros.com). Everything the app shows comes from the HTTP API described
here.

**Status: preview.** This is the API the Niagaros app itself uses. You can read data from it today, but there are no
API keys, OAuth applications, SDKs or webhooks yet. They are planned. Until then, you call the API with the access
token of a signed-in Niagaros user (see [Authentication](authentication.md)).

| | |
|---|---|
| Base URL | `https://hzf92ft6j7.execute-api.eu-west-1.amazonaws.com/default` |
| Format | JSON in, JSON out (exports can be CSV) |
| Region | All data is stored and processed in AWS `eu-west-1` (Ireland) |
| Tenant isolation | Every request is checked against the accounts, organisation and business units of the user behind the token |
