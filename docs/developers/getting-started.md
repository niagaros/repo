# Getting started

1. **Create an account** at [app.niagaros.com](https://app.niagaros.com). Follow the onboarding to connect an AWS
   account. Niagaros reads that account through a read-only IAM role (`CSPMScannerRole`), which you create in your
   own account with an external ID.
2. **Find your cloud account ID.** After the first scan, the dashboard URL contains it:
   `app.niagaros.com/niagaros-dashboard.html?account_id=<cloud_account_id>`. Most endpoints need this ID.
3. **Get an access token** for your user (see [Authentication](authentication.md)).
4. **Make a request:**

```bash
curl -s "https://hzf92ft6j7.execute-api.eu-west-1.amazonaws.com/default/ciem?cloud_account_id=$ACCOUNT&view=overview" \
  -H "Authorization: Bearer $TOKEN"
```

If you request an account your user cannot see, you get `403`. You never get another tenant's data.
