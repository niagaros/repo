# IAM Documentation for CSPM Discovery Phase

---

## 1. IAM Overview 

**Purpose:** Provide a high-level summary of the IAM setup, security goals, and AWS services in use.

**Summary:**
- The environment uses AWS services: **Amplify**, **Cognito**, **S3**, **CloudWatch**, **AWS Config**.  
- IAM roles and users follow the **least privilege principle**.  
- MFA is enforced for all console users.  
- IAM is integrated with CSPM prototype to monitor misconfigurations and risk levels.  

**Structure of IAM Documentation:**
1. IAM Inventory 
2. Policy Mapping & Analysis 
3. IAM Risk Register 
4. IAM Architecture & Access Flow  
5. IAM Best Practices  

---

## 2. IAM Inventory 

| Name                | Type  | Access Type           | Attached Policies                         | Status | Notes                                           |
|--------------------|-------|---------------------|------------------------------------------|--------|------------------------------------------------|
| AdminUser          | User  | Console + API       | AdministratorAccess                       | Active | MFA enforced; limited to corporate network    |
| AmplifyServiceRole | Role  | API only            | AmplifyFullAccess, S3ReadWritePolicy     | Active | Used for Amplify deployments                  |
| CognitoAuthRole    | Role  | API only            | CognitoPowerUser, S3ReadPolicy           | Active | Provides temporary access to authenticated users |
| DevGroup           | Group | Console + API       | ReadOnlyAccess, CloudWatchReadOnlyAccess | Active | Developer access; MFA enforced               |
| CI/CDServiceRole   | Role  | API only            | CodePipelineFullAccess, S3WriteAccess    | Active | Used for deployment pipelines; bucket-limited |

**Notes:**
- All users and roles follow **least privilege** principles.  
- MFA is mandatory for all console-access users.  
- Service roles (Amplify, CI/CD, Cognito) are scoped to necessary resources only.  

---

## 3. IAM Policy Mapping & Analysis 

| Policy Name            | Description                             | Critical Permissions      | Risk Notes                                         | Mitigation                    |
|------------------------|-----------------------------------------|--------------------------|--------------------------------------------------|-------------------------------|
| AdministratorAccess     | Full admin rights                        | *                        | High risk: full access; limited to very few users | Enforce MFA, review regularly |
| S3ReadWritePolicy       | Read/write on S3 buckets                 | s3:*                     | Medium risk: broad S3 access                      | Scope to specific buckets     |
| AmplifyFullAccess       | Full Amplify deployment rights           | amplify:*                | High risk if role is compromised                  | Restrict to deployment role   |
| CognitoPowerUser        | Manage Cognito users and groups          | cognito:*                | Medium risk if credentials are leaked            | Scope to environment          |
| CloudWatchReadOnlyAccess| Read logs and metrics                     | logs:Describe*, cloudwatch:Describe* | Low risk: read-only                       | No immediate mitigation needed |

---

## 4. IAM Risk Register 

| IAM Entity          | Risk Description                               | Severity | Mitigation Suggestion                                     |
|--------------------|-----------------------------------------------|---------|-----------------------------------------------------------|
| AdminUser          | Full console + API access; high misuse potential | Critical | MFA enforced, CloudWatch monitoring, monthly review       |
| AmplifyServiceRole | Broad Amplify + S3 access                        | High     | Limit S3 buckets and Amplify app scope                   |
| DevGroup           | Excess developer permissions                    | Medium   | Apply least privilege, enforce MFA, monitor via AWS Config |
| CognitoAuthRole    | Authenticated users with excessive S3 access    | Medium   | Fine-grained bucket policies, CloudWatch alerts           |

**Notes:**  
- Each risk entry is mapped to CSPM checks.  
- CloudWatch monitors IAM events, S3 access attempts, and policy changes.  

---

## 5. IAM Architecture & Access Flow 

**Purpose:** Visual overview of IAM configuration and access flows for CSPM reference.

**Architecture Summary:**
- **Amplify**: Deploys apps using **AmplifyServiceRole**, scoped to specific S3 buckets.  
- **Cognito**: Manages authentication; temporary credentials for authenticated users via **CognitoAuthRole**.  
- **CloudWatch**: Monitors IAM events, logs S3 access, tracks policy changes.  
- **AWS Config**: Continuously evaluates IAM policies and triggers alerts for drift.  
- **Developers (DevGroup)**: Console access with read-only permissions; MFA enforced.  
- **CI/CD Pipelines**: Run under **CI/CDServiceRole**, limited to deployment buckets.  

---

## 6. IAM Best Practices

- **Least Privilege Principle:** Limit permissions to the minimum necessary.  
- **MFA Enforcement:** All console users must use MFA.  
- **Scoped Service Roles:** Amplify, Cognito, CI/CD roles limited to specific buckets/resources.  
- **AWS Config Rules:** Automatically check for:
  - Public S3 buckets  
  - Inactive IAM users > 90 days  
  - Over-permissive roles  
- **CloudWatch Logging:** Monitor policy changes, access attempts, S3 object events.  
- **Cognito Integration:** Temporary credentials with expiration, minimal permissions.  
- **Secrets Management:** No hardcoded credentials; use AWS Secrets Manager or temporary roles.  

---
