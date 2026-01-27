## AWS Identity Center (SSO) – Internal Access

---

## 1. Purpose & Scope

**Purpose:** Centralized, secure access for internal users (admins, engineers, security, auditors) to AWS accounts using AWS Identity Center (formerly AWS SSO).

- **Single Sign-On:** Users log in once to an SSO portal and then assume roles in AWS accounts.
- **No long-lived IAM keys:** Access is via temporary credentials only.
- **Integrated with CSPM:** Backend services use these temporary credentials to collect configuration data and run scans.
- **Separation of concerns:** SSO is only for internal cloud users, fully separate from Cognito/web login for customers.

---

## 2. Access Model – IAM Permission Sets

Identity Center uses **Permission Sets** that map to IAM roles in each AWS account. These roles are aligned to the `niagaros-*` access profiles:

### 2.1 `niagaros-admins` – Break‑Glass / Org Admins

**Goal:** Full administrative control for exceptional use only (account setup, incident response, IAM recovery).

**Key characteristics:**
- Full access `Action: "*"`, `Resource: "*"`.
- **MFA required** and tightly monitored.
- Used only for:
  - Initial AWS account setup.
  - Incident response and forensics.
  - Recovery from IAM misconfiguration.

**Example policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AdminFullAccess",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```

---

### 2.2 `niagaros-platform` – Infra, IAM, CI/CD, Observability

**Goal:** Manage infrastructure, IAM roles, CI/CD, and observability without direct access to business data.

- Focus on **platform and infra**:
  - CloudFormation, IAM role lifecycle, Amplify, logging, and monitoring.
- **Explicitly not allowed:**
  - DynamoDB data writes.
  - Cognito user management.

**Example policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InfrastructureManagement",
      "Effect": "Allow",
      "Action": [
        "cloudformation:*",
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PassRole",
        "iam:Get*",
        "iam:List*",
        "amplify:*",
        "logs:*",
        "cloudwatch:*",
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:ListAllMyBuckets"
      ],
      "Resource": "*"
    }
  ]
}
```

---

### 2.3 `niagaros-backend` – APIs, Business Logic, Data Access

**Goal:** Backend engineers and services that manage APIs, business logic, and data access.

- **Allowed:**
  - DynamoDB CRUD on CSPM tables.
  - S3 object read/write/delete for backend buckets.
  - Writing logs to CloudWatch.
- **Not allowed:**
  - IAM management.
  - Amplify management.
  - Cognito administrative actions.

**Example policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DynamoDBAccess",
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem",
        "dynamodb:Query"
      ],
      "Resource": "arn:aws:dynamodb:<REGION>:<ACCOUNT_ID>:table/niagaros-<ENV>-*"
    },
    {
      "Sid": "S3BackendAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::niagaros-<ENV>-*/*"
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

---

### 2.4 `niagaros-frontend` – Frontend Devs

**Goal:** Frontend developers deploying via Amplify and reading backend data for debugging and dashboards.

- **Allowed:**
  - Amplify app listing, details, and deployment jobs.
  - Read‑only DynamoDB and S3 for backend data.
- **Not allowed:**
  - Any write to production data.
  - Infra changes.
  - IAM actions.

**Example policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AmplifyFrontend",
      "Effect": "Allow",
      "Action": [
        "amplify:ListApps",
        "amplify:GetApp",
        "amplify:StartJob",
        "amplify:GetJob"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ReadOnlyBackend",
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:Query",
        "s3:GetObject"
      ],
      "Resource": "*"
    }
  ]
}
```

---

### 2.5 `niagaros-security` – Audit, Compliance, Monitoring

**Goal:** Security and compliance (SOC, auditors) with **zero mutation**.

- **Read‑only visibility** into:
  - CloudTrail events.
  - Logs and metrics.
  - IAM configuration.
  - Encryption state for S3 and DynamoDB metadata.
- **No writes or deployments** allowed.

**Example policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SecurityAudit",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:LookupEvents",
        "logs:Describe*",
        "logs:Get*",
        "iam:Get*",
        "iam:List*",
        "dynamodb:DescribeTable",
        "s3:GetBucketPolicy",
        "s3:GetEncryptionConfiguration"
      ],
      "Resource": "*"
    }
  ]
}
```

---

### 2.6 `niagaros-readonly` – Stakeholders, Support, External Parties

**Goal:** Broad, read‑only visibility for non‑engineering stakeholders and external partners.

- **Allowed:** Read/describe on DynamoDB, S3, CloudWatch Logs, and CloudWatch metrics.
- **No writes** and **no deployments**.

**Example policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadOnlyEverything",
      "Effect": "Allow",
      "Action": [
        "dynamodb:Get*",
        "dynamodb:Describe*",
        "s3:Get*",
        "s3:List*",
        "logs:Get*",
        "logs:Describe*",
        "cloudwatch:Get*",
        "cloudwatch:Describe*"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## 3. Summary – Who May Do What

High‑level capabilities per group:

| Group              | Write / Admin        | Infra / IAM          | Data Access         | Security / Audit     |
|--------------------|----------------------|----------------------|---------------------|----------------------|
| `niagaros-admins`  | ✅ Full              | ✅ Full              | ✅ Full             | ✅ Full              |
| `niagaros-platform`| ⚠️ Infra‑focused    | ✅ Infra + IAM roles | ❌ No business data | ⚠️ Limited (logs)   |
| `niagaros-backend` | ✅ Data writes       | ❌ No infra          | ✅ Data             | ❌ Limited           |
| `niagaros-frontend`| ⚠️ Deploy only      | ❌ No infra          | 🔍 Read‑only        | ❌ None              |
| `niagaros-security`| ❌ No writes         | ❌ No infra changes  | 🔍 Read‑only meta   | ✅ Audit / monitoring|
| `niagaros-readonly`| ❌ No writes         | ❌ No infra          | 🔍 Read‑only        | 🔍 Read‑only         |

---

## 4. Setup Guide – AWS Identity Center

### 4.1 Enable Identity Center

- Open AWS Console → `AWS Identity Center`.
- Click **Enable AWS SSO**.
- Choose identity source:
  - AWS managed Microsoft AD.
  - External IdP (SAML/OIDC).
  - Default AWS Identity Center directory (simple for startups).

### 4.2 Create Permission Sets

- Go to `Identity Center → Permission sets → Create permission set`.
- Choose **Custom permissions** and attach IAM policies based on the `niagaros-*` profiles above.
- Configure:
  - Session duration.
  - MFA requirements.
  - Tags (e.g., `env`, `owner`, `purpose`) for auditability.

### 4.3 Assign Users and Groups to Accounts

- Navigate to `Identity Center → AWS accounts → Assign users/groups`.
- Select:
  - Target AWS account(s).
  - Users or groups from the identity source.
  - Appropriate **permission set** (e.g., `niagaros-backend`).
- Result: Users log in via SSO and assume the associated IAM role(s).

---

## 5. Using SSO – Console and CLI

### 5.1 Console Login Flow

1. User navigates to the **SSO portal URL** (from AWS Identity Center).
2. Authenticates with corporate credentials and MFA.
3. Chooses:
   - AWS account.
   - Role / permission set (e.g., `niagaros-security`).
4. Console session is created using **temporary credentials**.

### 5.2 CLI Login Flow

Configure SSO for the AWS CLI:

```bash
aws configure sso
# Provide:
# - SSO start URL
# - SSO region
# - AWS account
# - Permission set (role)
```

- CLI stores temporary credentials locally.
- CSPM backend jobs can use these profiles to:
  - Collect configuration data.
  - Run `ScanRun → CollectedData → Findings`.
  - Map findings to resources and compliance standards.

---

## 6. Best Practices

- **MFA everywhere:** Enforce MFA for all SSO logins, with stricter policies for `niagaros-admins`.
- **Group‑based access:** Manage access via identity provider groups mapped to permission sets.
- **Session tagging:** Tag sessions (e.g., `user`, `team`, `ticket`) for traceability and billing.
- **No permanent keys:** Prohibit long‑lived IAM users for internal access where SSO is available.
- **Regular reviews:** Periodically review:
  - Membership of SSO groups.
  - Permissions in each permission set.
  - CloudTrail logs for role assumptions and anomalies.


