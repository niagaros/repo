# Errors

An error returns a JSON body with one readable message:

```json
{"error": "cloud_account_id is required"}
```

| Status | Meaning |
|---|---|
| `400` | A parameter is missing or has an invalid value |
| `401` | There is no token, or the token is invalid or expired |
| `403` | The token is valid, but the user may not see or change this account or record |
| `404` | The record does not exist (for public endpoints: or it is not public) |
| `405` | This endpoint does not support the HTTP method |
| `409` | The change conflicts with the current state, for example a domain that is already in use |
| `503` | A dependency, such as a DNS check, could not be reached. Try again later |
| `500` | Unexpected error. The message never contains internal details. Contact support if it keeps happening |
