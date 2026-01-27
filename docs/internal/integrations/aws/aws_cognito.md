## AWS Cognito – Web User Accounts for CSPM

---

## 1. Purpose & Separation of Concerns

**Purpose:** Manage **web frontend users** of the CSPM platform (customers, stakeholders, auditors) via Amazon Cognito.

- Handles **signup/login** and web session management.
- Supports **Cognito groups** for web permission tiers.
- Fully **separate from AWS IAM / Identity Center**:
  - Cognito users do **not** receive IAM roles or cloud privileges.
  - IAM/SSO is only for internal cloud access.
- Integrates with the CSPM data model through a `User.cognitoId` field.

---

## 2. Cognito User Pool – Core Setup

### 2.1 Create User Pool

Steps:

1. Open AWS Console → `Cognito → User Pools → Create user pool`.
2. Name the pool: `niagaros-customer-users`.
3. Set **primary identifier**: `Email`.
4. Keep default attributes:
   - `name`
   - `email`
5. Configure security:
   - Strong password policy.
   - (Recommended) Multi‑Factor Authentication (MFA).

### 2.2 Data Model Integration

Each Cognito user is linked to an internal `User` entity in the CSPM backend:

- `User.userId` (PK)
- `User.name`
- `User.email`
- `User.cognitoId` ← **Cognito user ID**

This allows the backend to:

- Attach ownership of cloud accounts, ScanRuns, and Findings to a web user.
- Enforce web‑level permissions without exposing AWS IAM roles.

---

## 3. Cognito Groups – Web Permission Tiers

Use Cognito **Groups** to model frontend authorization. Example groups:

| Group Name         | Purpose                             | Data Model Mapping                                                   |
|--------------------|-------------------------------------|-----------------------------------------------------------------------|
| `frontend-readonly`| Stakeholders, support, auditors     | `User → CloudAccount → ScanRun → Findings` (view‑only)               |
| `frontend-dev`     | Developers using dashboards/tools   | Limited datasets, non‑sensitive operations, no destructive actions   |
| `frontend-audit`   | Security / compliance auditors      | Full read‑only view of Findings, ScanRuns, ComplianceStandards       |

### 3.1 Creating Groups

1. Go to `User Pool → Groups → Create group`.
2. Name the group, e.g. `frontend-readonly`.
3. Optionally set **precedence** if users can be in multiple groups.
4. Save; repeat for `frontend-dev` and `frontend-audit`.

> These groups **only** affect web application permissions; they do not change IAM or SSO roles.

---

## 4. User Lifecycle – Create, Onboard, and Manage

### 4.1 Create Users

1. Navigate to `User Pool → Users and groups → Create user`.
2. Enter:
   - `email`
   - `name`
   - Temporary password.
3. Assign user to appropriate group(s):
   - `frontend-readonly`
   - `frontend-dev`
   - `frontend-audit`

User flow:

- User receives email with temporary password.
- On first login, sets a permanent password and (optionally) configures MFA.
- Backend creates/updates a `User` record and stores `cognitoId`.

### 4.2 Optional Automation

Automate onboarding via Lambda triggers:

- **Post Confirmation trigger:**
  - Assign default group (e.g. `frontend-readonly`).
  - Create the `User` entity in the backend database.
  - Send welcome email with MFA and security guidance.

This ensures consistent, auditable onboarding for all web users.

---

## 5. Frontend Integration

Connect the CSPM web app to Cognito via:

- **AWS Amplify** Auth module, or
- Native **Cognito SDK** (e.g. `amazon-cognito-identity-js`).

### 5.1 Configuration

Typical configuration parameters:

- `User Pool ID` (e.g. `eu-west-1_XXXXXXXXX`).
- `App Client ID`.
- (Optional) `Identity Pool ID` if using Cognito Federated Identities.

### 5.2 Example (JavaScript + Amplify)

```javascript
import { Auth } from 'aws-amplify';

// Sign up a new user
Auth.signUp({
  username: 'alice@example.com',
  password: 'SuperSecurePassword123!',
  attributes: { email: 'alice@example.com' },
});

// Sign in
Auth.signIn('alice@example.com', 'SuperSecurePassword123!');
```

- The frontend inspects Cognito **groups** in the ID token to drive UI access:
  - Example: Only `frontend-audit` may see compliance dashboards.
  - Example: `frontend-dev` may see additional debugging or dev views.

> Important: These operations authenticate to the web app only; **no IAM access is granted**.

---

## 6. Authorization in the CSPM Backend

The backend should treat Cognito as the **authentication** source and enforce **authorization** via:

- `User.cognitoId` + group claims from the ID token.
- Role checks based on group membership:
  - `frontend-readonly`: Read‑only endpoints for Findings, ScanRuns, CloudAccounts.
  - `frontend-dev`: Additional non‑sensitive operations/tools.
  - `frontend-audit`: Broad read‑only access to compliance and security data.

Recommended checks:

- Validate and verify JWT tokens (signature, audience, issuer).
- Extract `sub` (Cognito user ID) and groups from token claims.
- Map `sub` to internal `User` record and apply business rules.

---

## 7. Audit, Monitoring, and Security

### 7.1 Logging and Monitoring

- Enable **CloudTrail** for Cognito control plane events:
  - User creation, deletion, password reset, MFA changes, group changes.
- Aggregate logs into a central logging account or SIEM.
- Create CSPM views that correlate:
  - User logins.
  - Access to Findings and ScanRuns.
  - Permission changes (group membership).

### 7.2 Security Best Practices

- Enforce MFA for all privileged web users (e.g. `frontend-audit`).
- Use strong password policies and account lockout thresholds.
- Regularly review:
  - Cognito groups and memberships.
  - Stale or inactive accounts.
  - Failed login patterns and anomalies.
- Never expose Cognito app client secrets to the browser or store them in source control.

---

## 8. Relationship to AWS SSO / IAM

- **Cognito:** Web users of the CSPM product (customers, stakeholders, auditors).
  - Scoped to app‑level permissions only.
  - No ability to modify AWS infrastructure or cloud accounts directly.
- **AWS SSO / IAM:** Internal engineers, admins, and security teams.
  - Assume `niagaros-*` roles to access AWS accounts.
  - Used by backend collectors and automated scans.

Keeping these planes separate minimizes blast radius:

- A compromised Cognito user cannot escalate to AWS infrastructure control.
- IAM and SSO credentials are governed by corporate identity and security policies.


