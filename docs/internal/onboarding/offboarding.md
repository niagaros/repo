# CSPM Offboarding Guide  
**Scope:** GitHub and AWS  
**Audience:** Platform admins, DevOps, Security team

---

## Overview

This document describes how to safely offboard a team member or service account from the CSPM platform. Offboarding ensures that access to source code, CI/CD, cloud infrastructure, and production data is fully revoked and auditable.

The process is split into two parts:
1. GitHub access removal
2. AWS access removal

All steps should be logged in the internal security or IT ticketing system.

---

## When to Offboard

Offboarding should be performed when:
- A team member leaves the organization
- A contractor’s engagement ends
- A service account is no longer needed
- Access must be revoked due to a security incident

---

## Part 1 – GitHub Offboarding

### 1. Identify User Access

Check the user’s access level:
- Organization membership
- Repository permissions
- Team memberships
- GitHub Actions access (if applicable)

### 2. Remove Organization Membership

1. Go to **GitHub Organization Settings**
2. Select **People**
3. Find the user
4. Click **Remove from organization**

This immediately revokes access to all private repositories.

### 3. Remove from Teams (If Needed)

If the user should stay in the org but lose project access:
1. Go to **Teams**
2. Remove the user from relevant teams
3. Verify they no longer have repo access

### 4. Revoke GitHub Actions and Tokens

1. Go to **Settings → Developer settings → Personal access tokens**
2. Revoke any tokens tied to the user or automation they owned
3. Rotate secrets in:
   - `.github/workflows/`
   - Repository Secrets
   - Organization Secrets

### 5. Transfer Ownership (If Required)

If the user owned:
- Repositories
- GitHub Apps
- CI secrets

Transfer ownership to a platform or admin account.

### 6. Audit Log Review

Check:
- **Organization → Audit Log**
- Confirm user removal and token revocation events are recorded

---

## Part 2 – AWS Offboarding

### 1. Identify IAM Identity Type

Determine if the user uses:
- IAM User
- Federated login (SSO / Cognito / IAM Identity Center)
- Service role
- Access keys for automation

---

### 2. IAM User Offboarding

#### Disable Console Access
1. Open **IAM → Users**
2. Select the user
3. Under **Security Credentials**
4. Disable password access

#### Deactivate Access Keys
1. Go to **Access Keys**
2. Set all keys to **Inactive**
3. Delete keys after verification

#### Remove from Groups
1. Go to **Groups**
2. Remove the user from all groups

#### Delete User (Optional)
After verification and audit:
1. Delete the IAM user
2. Confirm no resources depend on this identity

---

### 3. Federated User / SSO Offboarding

If using AWS IAM Identity Center or Cognito:
- Remove user from:
  - Identity groups
  - Assigned AWS accounts
  - Permission sets
- Disable or delete the user in the identity provider (Azure AD, Google Workspace, etc.)

---

### 4. Service Account / Automation User

If the offboarded identity is used by CI/CD or automation:
1. Identify:
   - GitHub Actions
   - Lambda environment variables
   - Secrets Manager entries
2. Rotate credentials:
   - Generate new access keys
   - Update secrets
3. Validate pipelines and services still work

---

### 5. Revoke Role Trust Relationships

If the user could assume roles:
1. Go to **IAM → Roles**
2. Review **Trust Relationships**
3. Remove the user or identity provider from allowed principals

---

## Part 3 – CSPM-Specific Cleanup

### 1. Remove Cloud Account Ownership

In the CSPM system:
- Transfer ownership of cloud accounts to another admin
- Or remove the user’s access to scan results and dashboards

### 2. Invalidate Active Sessions

If using Cognito:
- Force sign-out
- Revoke refresh tokens

---

## Part 4 – Validation Checklist

Confirm:
- User cannot log into GitHub
- User cannot access repositories
- No active AWS access keys remain
- No roles can be assumed
- CI/CD pipelines still function
- CSPM frontend access is revoked

---

## Logging and Evidence

Store the following:
- Date and time of offboarding
- Admin who performed the action
- GitHub audit log entries
- AWS CloudTrail logs
- List of revoked credentials

---

## Security Best Practices

- Always rotate shared secrets after offboarding
- Prefer federated access over IAM users
- Use least-privilege roles instead of long-lived access keys
- Review IAM users quarterly for inactivity

---

## Emergency Offboarding

If a security incident is suspected:
1. Immediately deactivate all AWS access keys
2. Remove GitHub organization access
3. Invalidate all sessions (Cognito / SSO)
4. Rotate all secrets
5. Notify security leadership
6. Preserve logs for investigation

---

## Ownership

**Document Owner:** Platform Security Team  
**Review Cycle:** Every 6 months or after major platform changes
