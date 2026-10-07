# Offboarding — Removing a Team Member

Follow this checklist when a team member leaves. Complete all steps — do not skip any even if the person is leaving on good terms. Access that is not removed is a security risk.

---

## GitHub

- [ ] Go to `github.com/niagaros/repo` → Settings → Collaborators
- [ ] Find the person and click **Remove**
- [ ] If they had any open pull requests, reassign or close them
- [ ] Check if they had any personal access tokens or GitHub Apps authorized — revoke if found

---

## AWS — CSPM platform account (225989360315)

Log in as admin:

```powershell
aws sso login --profile niagaros-cspm
$env:AWS_PROFILE = "niagaros-cspm"
```

**Deactivate access keys:**

```bash
# List their access keys
aws iam list-access-keys --user-name THEIR_USERNAME

# Deactivate each key
aws iam update-access-key \
    --user-name THEIR_USERNAME \
    --access-key-id AKIAXXXXXXXXXXXXXXXX \
    --status Inactive
```

**Remove from IAM groups:**

```bash
# List which groups they are in
aws iam list-groups-for-user --user-name THEIR_USERNAME

# Remove from each group
aws iam remove-user-from-group \
    --group-name GROUP_NAME \
    --user-name THEIR_USERNAME
```

**Delete console access:**

```bash
aws iam delete-login-profile --user-name THEIR_USERNAME
```

**Delete access keys:**

```bash
aws iam delete-access-key \
    --user-name THEIR_USERNAME \
    --access-key-id AKIAXXXXXXXXXXXXXXXX
```

**Delete the IAM user:**

```bash
aws iam delete-user --user-name THEIR_USERNAME
```

---

## AWS — Domits account (115462458880)

If the person had direct access to the Domits account, repeat the same IAM steps above but switch to the Domits account first.

---

## SSO

If the person was set up with AWS SSO:

1. Go to AWS IAM Identity Center in the CSPM account
2. Find the user under **Users**
3. Click **Delete user**
4. This also revokes all active SSO sessions immediately

---

## Database

The database is accessed via Secrets Manager credentials shared by the team. If the departing person knew the database password, rotate the secret:

```bash
# Generate a new password and update the secret
aws secretsmanager rotate-secret \
    --secret-id cspm/database/credentials
```

Also update the Lambda environment variables if the secret ARN changes.

---

## Checklist summary

| Step | Done |
|---|---|
| Removed from GitHub repository | [ ] |
| Access keys deactivated and deleted | [ ] |
| Removed from all IAM groups | [ ] |
| Console login deleted | [ ] |
| IAM user deleted | [ ] |
| SSO user deleted (if applicable) | [ ] |
| Database secret rotated (if they had DB access) | [ ] |
| Open PRs reassigned or closed | [ ] |

---

## After offboarding

Verify no active sessions remain:

```bash
aws iam list-access-keys --user-name THEIR_USERNAME
# Should return empty or NoSuchEntity error
```

Document the offboarding by adding a line to the team access log with the date and what was removed.