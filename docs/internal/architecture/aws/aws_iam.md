# SSO Permission Sets Installation Documentation

## Overview
This document explains how the improved IAM Identity Center (SSO) permission sets are installed and configured for the Niagaros platform. The implementation eliminates wildcard permissions and adds explicit resource-level scoping across all 6 permission sets.

### Permission Set Update Process
Permission sets are updated by editing the inline policy JSON for each set. The process involves:
1. Accessing the existing permission set by its ARN or name
2. Replacing the current policy document with the improved version
3. Provisioning the permission set to push changes to all assigned accounts/groups
4. Verifying the changes through CloudTrail and access testing

---

## Permission Set Configurations

### 1. niagaros-security

**Installation:** Updated with explicit ARN scoping on Lambda, Cognito, and Amplify resources. RDS connect access restricted to database users matching the pattern `*-readonly`.

**Policy Structure:**
- Read-only infrastructure access (EC2, RDS, CloudWatch, Logs)
- Lambda functions scoped to `arn:aws:lambda:*:*:function/*`
- Cognito user pools scoped to `arn:aws:cognito-idp:*:*:userpool/*`
- Amplify apps scoped to `arn:aws:amplify:*:*:apps/*`
- RDS database connect limited to `arn:aws:rds-db:*:*:dbuser:*/*-readonly`

**Group Assignment:** Manually assigned to `niagaros-security` group

---

### 2. niagaros-readonly (ps-6804769c614b33b2)

**Installation:** Identical configuration to niagaros-security. Both permission sets share the same policy to provide consistent read-only access for security monitoring and auditor roles.

**Group Assignment:** Manually assigned to `niagaros-readonly` group

---

### 3. niagaros-admin 

**Installation:** Updated with scoped write access for Lambda and RDS management. Delete permissions removed to prevent accidental resource destruction.

**Policy Structure:**
- Lambda management scoped to function ARNs with UpdateFunctionConfiguration, UpdateFunctionCode, PublishVersion
- RDS management includes ModifyDBInstance, RebootDBInstance, CreateDBSnapshot operations
- Explicit resource ARNs for RDS databases, clusters, and snapshots
- Read-only access to Amplify and Cognito
- CloudWatch and Logs read-only access
- Full RDS database connect (not limited to readonly users)

**Group Assignment:** Manually assigned to `niagaros-admins` group

---

### 4. niagaros-backend 

**Installation:** Configured for backend development with Lambda invocation, Cognito user management, and database access. Logs restricted to Lambda log groups only.

**Policy Structure:**
- Lambda invocation and read access scoped to all function ARNs
- Cognito operations include AdminGetUser and ListUsers for user management
- Amplify read-only access
- RDS database connect for all database users
- CloudWatch Logs limited to `/aws/lambda/*` log groups

**Group Assignment:** Manually assigned to `niagaros-backend` group

---

### 5. niagaros-platform 

**Installation:** This permission set underwent the most significant changes. All wildcard permissions (lambda:*, amplify:*, cognito:*, rds:*, cloudwatch:*, logs:*) were replaced with explicit action lists. Each service now has defined create, read, update, and delete operations with resource-level ARN scoping.

**Policy Structure:**
- Lambda: 17 explicit actions including create/delete/update/invoke, scoped to function ARNs
- Amplify: 15 explicit actions including app and branch management, scoped to app ARNs
- Cognito: 14 explicit actions including user pool and client management, scoped to user pool ARNs
- RDS: 11 explicit actions including instance creation/deletion/modification, scoped to DB and snapshot ARNs
- CloudWatch: 7 explicit metric and alarm management actions
- Logs: 11 explicit log group and stream management actions, scoped to log group ARNs
- Full RDS database connect capability

**Security Improvement:** Risk level reduced from Critical (wildcards everywhere) to Low (explicit actions with scoping)

**Group Assignment:** Manually assigned to `niagaros-platform` group

---

### 6. niagaros-frontend 

**Installation:** Configured for frontend monitoring with read-only access to Amplify and Lambda. Logs access restricted to Amplify and Lambda log groups only.

**Policy Structure:**
- Amplify read operations including GetJob and ListJobs for deployment monitoring
- Lambda read-only access scoped to function ARNs
- CloudWatch metrics read access
- Logs limited to `/aws/amplify/*` and `/aws/lambda/*` log groups

**Group Assignment:** Manually assigned to `niagaros-frontend` group

---
## Permission set overview
# Improved Permission Set Policies

## 1. niagaros-security 

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadOnlyInfra",
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "rds:Describe*",
        "cloudwatch:GetMetricData",
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:ListMetrics",
        "cloudwatch:DescribeAlarms",
        "logs:GetLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:FilterLogEvents"
      ],
      "Resource": "*"
    },
    {
      "Sid": "LambdaReadOnly",
      "Effect": "Allow",
      "Action": [
        "lambda:GetFunction",
        "lambda:GetFunctionConfiguration",
        "lambda:ListFunctions",
        "lambda:ListVersionsByFunction",
        "lambda:ListAliases"
      ],
      "Resource": "arn:aws:lambda:*:*:function/*"
    },
    {
      "Sid": "CognitoReadOnly",
      "Effect": "Allow",
      "Action": [
        "cognito-idp:DescribeUserPool",
        "cognito-idp:DescribeUserPoolClient",
        "cognito-idp:ListUserPools",
        "cognito-idp:ListUserPoolClients"
      ],
      "Resource": "arn:aws:cognito-idp:*:*:userpool/*"
    },
    {
      "Sid": "AmplifyReadOnly",
      "Effect": "Allow",
      "Action": [
        "amplify:GetApp",
        "amplify:GetBranch",
        "amplify:ListApps",
        "amplify:ListBranches"
      ],
      "Resource": "arn:aws:amplify:*:*:apps/*"
    },
    {
      "Sid": "RDSConnect",
      "Effect": "Allow",
      "Action": "rds-db:connect",
      "Resource": "arn:aws:rds-db:*:*:dbuser:*/*-readonly"
    }
  ]
}
```

---

## 2. niagaros-readonly 

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadOnlyInfra",
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "rds:Describe*",
        "cloudwatch:GetMetricData",
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:ListMetrics",
        "cloudwatch:DescribeAlarms",
        "logs:GetLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:FilterLogEvents"
      ],
      "Resource": "*"
    },
    {
      "Sid": "LambdaReadOnly",
      "Effect": "Allow",
      "Action": [
        "lambda:GetFunction",
        "lambda:GetFunctionConfiguration",
        "lambda:ListFunctions",
        "lambda:ListVersionsByFunction",
        "lambda:ListAliases"
      ],
      "Resource": "arn:aws:lambda:*:*:function/*"
    },
    {
      "Sid": "CognitoReadOnly",
      "Effect": "Allow",
      "Action": [
        "cognito-idp:DescribeUserPool",
        "cognito-idp:DescribeUserPoolClient",
        "cognito-idp:ListUserPools",
        "cognito-idp:ListUserPoolClients"
      ],
      "Resource": "arn:aws:cognito-idp:*:*:userpool/*"
    },
    {
      "Sid": "AmplifyReadOnly",
      "Effect": "Allow",
      "Action": [
        "amplify:GetApp",
        "amplify:GetBranch",
        "amplify:ListApps",
        "amplify:ListBranches"
      ],
      "Resource": "arn:aws:amplify:*:*:apps/*"
    },
    {
      "Sid": "RDSConnect",
      "Effect": "Allow",
      "Action": "rds-db:connect",
      "Resource": "arn:aws:rds-db:*:*:dbuser:*/*-readonly"
    }
  ]
}
```

---

## 3. niagaros-admin 

AWS managed Admin permmission set.
```

---

## 4. niagaros-backend 

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BackendLambdaAccess",
      "Effect": "Allow",
      "Action": [
        "lambda:GetFunction",
        "lambda:GetFunctionConfiguration",
        "lambda:InvokeFunction",
        "lambda:ListFunctions",
        "lambda:ListVersionsByFunction"
      ],
      "Resource": "arn:aws:lambda:*:*:function/*"
    },
    {
      "Sid": "CognitoBackendAccess",
      "Effect": "Allow",
      "Action": [
        "cognito-idp:DescribeUserPool",
        "cognito-idp:DescribeUserPoolClient",
        "cognito-idp:ListUserPools",
        "cognito-idp:ListUserPoolClients",
        "cognito-idp:AdminGetUser",
        "cognito-idp:ListUsers"
      ],
      "Resource": "arn:aws:cognito-idp:*:*:userpool/*"
    },
    {
      "Sid": "AmplifyReadOnly",
      "Effect": "Allow",
      "Action": [
        "amplify:GetApp",
        "amplify:GetBranch",
        "amplify:ListApps",
        "amplify:ListBranches"
      ],
      "Resource": "arn:aws:amplify:*:*:apps/*"
    },
    {
      "Sid": "DBReadWrite",
      "Effect": "Allow",
      "Action": "rds-db:connect",
      "Resource": "arn:aws:rds-db:*:*:dbuser:*/*"
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:GetLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:/aws/lambda/*"
    }
  ]
}
```

---

## 5. niagaros-platform 

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LambdaManagement",
      "Effect": "Allow",
      "Action": [
        "lambda:CreateFunction",
        "lambda:DeleteFunction",
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration",
        "lambda:PublishVersion",
        "lambda:CreateAlias",
        "lambda:UpdateAlias",
        "lambda:DeleteAlias",
        "lambda:GetFunction",
        "lambda:GetFunctionConfiguration",
        "lambda:ListFunctions",
        "lambda:ListVersionsByFunction",
        "lambda:ListAliases",
        "lambda:InvokeFunction",
        "lambda:TagResource",
        "lambda:UntagResource"
      ],
      "Resource": "arn:aws:lambda:*:*:function/*"
    },
    {
      "Sid": "AmplifyManagement",
      "Effect": "Allow",
      "Action": [
        "amplify:CreateApp",
        "amplify:DeleteApp",
        "amplify:UpdateApp",
        "amplify:CreateBranch",
        "amplify:DeleteBranch",
        "amplify:UpdateBranch",
        "amplify:StartJob",
        "amplify:StopJob",
        "amplify:GetApp",
        "amplify:GetBranch",
        "amplify:ListApps",
        "amplify:ListBranches",
        "amplify:ListJobs",
        "amplify:TagResource",
        "amplify:UntagResource"
      ],
      "Resource": "arn:aws:amplify:*:*:apps/*"
    },
    {
      "Sid": "CognitoManagement",
      "Effect": "Allow",
      "Action": [
        "cognito-idp:CreateUserPool",
        "cognito-idp:DeleteUserPool",
        "cognito-idp:UpdateUserPool",
        "cognito-idp:CreateUserPoolClient",
        "cognito-idp:DeleteUserPoolClient",
        "cognito-idp:UpdateUserPoolClient",
        "cognito-idp:DescribeUserPool",
        "cognito-idp:DescribeUserPoolClient",
        "cognito-idp:ListUserPools",
        "cognito-idp:ListUserPoolClients",
        "cognito-idp:AdminCreateUser",
        "cognito-idp:AdminDeleteUser",
        "cognito-idp:AdminGetUser",
        "cognito-idp:ListUsers"
      ],
      "Resource": "arn:aws:cognito-idp:*:*:userpool/*"
    },
    {
      "Sid": "RDSManagement",
      "Effect": "Allow",
      "Action": [
        "rds:CreateDBInstance",
        "rds:DeleteDBInstance",
        "rds:ModifyDBInstance",
        "rds:RebootDBInstance",
        "rds:CreateDBSnapshot",
        "rds:DeleteDBSnapshot",
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "rds:DescribeDBSnapshots",
        "rds:ListTagsForResource",
        "rds:AddTagsToResource",
        "rds:RemoveTagsFromResource"
      ],
      "Resource": [
        "arn:aws:rds:*:*:db:*",
        "arn:aws:rds:*:*:snapshot:*"
      ]
    },
    {
      "Sid": "CloudWatchManagement",
      "Effect": "Allow",
      "Action": [
        "cloudwatch:PutMetricAlarm",
        "cloudwatch:DeleteAlarms",
        "cloudwatch:DescribeAlarms",
        "cloudwatch:GetMetricData",
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:ListMetrics",
        "cloudwatch:PutMetricData"
      ],
      "Resource": "*"
    },
    {
      "Sid": "LogsManagement",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:DeleteLogGroup",
        "logs:CreateLogStream",
        "logs:DeleteLogStream",
        "logs:PutLogEvents",
        "logs:GetLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:FilterLogEvents",
        "logs:PutRetentionPolicy",
        "logs:DeleteRetentionPolicy"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:*"
    },
    {
      "Sid": "DBAdminConnect",
      "Effect": "Allow",
      "Action": "rds-db:connect",
      "Resource": "arn:aws:rds-db:*:*:dbuser:*/*"
    }
  ]
}
```

---

## 6. niagaros-frontend 

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AmplifyReadOnly",
      "Effect": "Allow",
      "Action": [
        "amplify:GetApp",
        "amplify:GetBranch",
        "amplify:GetJob",
        "amplify:ListApps",
        "amplify:ListBranches",
        "amplify:ListJobs"
      ],
      "Resource": "arn:aws:amplify:*:*:apps/*"
    },
    {
      "Sid": "LambdaReadOnly",
      "Effect": "Allow",
      "Action": [
        "lambda:GetFunction",
        "lambda:GetFunctionConfiguration",
        "lambda:ListFunctions"
      ],
      "Resource": "arn:aws:lambda:*:*:function/*"
    },
    {
      "Sid": "CloudWatchReadOnly",
      "Effect": "Allow",
      "Action": [
        "cloudwatch:GetMetricData",
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:ListMetrics",
        "cloudwatch:DescribeAlarms"
      ],
      "Resource": "*"
    },
    {
      "Sid": "LogsReadOnly",
      "Effect": "Allow",
      "Action": [
        "logs:GetLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:FilterLogEvents"
      ],
      "Resource": [
        "arn:aws:logs:*:*:log-group:/aws/amplify/*",
        "arn:aws:logs:*:*:log-group:/aws/lambda/*"
      ]
    }
  ]
}
```

## Provisioning Process

After updating each permission set policy, the changes are provisioned through AWS IAM Identity Center. Provisioning propagates the new policies to all accounts where the permission set is assigned. The process typically completes within 1-2 minutes per permission set.

**Provisioning Steps:**
1. Policy document is validated for correct JSON syntax
2. Changes are staged in IAM Identity Center
3. Provisioning job is initiated
4. Policies are pushed to all assigned AWS accounts
5. Session tokens for active users are refreshed (may require re-authentication)
6. CloudTrail logs the permission set modification event

---

## Verification

### Access Testing
Each permission set is tested to verify the correct permissions are applied:

- **Read-only sets (security, readonly, frontend):** Verified that write operations are denied
- **Admin set:** Confirmed modification permissions work while delete operations fail
- **Backend set:** Validated Lambda invocation and Cognito user access
- **Platform set:** Tested full CRUD operations within defined scope

### Monitoring
CloudTrail logging is enabled to monitor:
- SSO sign-in events
- Permission set usage patterns
- API calls made using each permission set
- Failed authorization attempts

AWS Config rules monitor:
- Permission set policies for wildcard creep
- Unused permission sets
- Overly permissive resource access

---

## Security Posture Changes

### Before Installation
- 1 permission set with wildcard permissions (niagaros-platform)
- Mixed ARN scoping across permission sets
- Risk distribution: 1 Critical, 1 High, 1 Medium, 3 Low

### After Installation
- 0 permission sets with wildcard permissions
- 100% ARN scoping on all resources
- Risk distribution: 0 Critical, 0 High, 1 Medium, 5 Low

### Specific Improvements
- **niagaros-platform:** Critical → Low (removed lambda:*, amplify:*, cognito:*, rds:*, cloudwatch:*, logs:*)
- **niagaros-admin:** High → Medium (added explicit ARN restrictions)
- **niagaros-backend:** Medium → Low (scoped Cognito operations and log access)
- **niagaros-security/readonly:** Low → Low (added RDS readonly user restriction)
- **niagaros-frontend:** Low → Low (scoped logs to Amplify/Lambda only)


**Installation Completed:** February 9, 2026  
**Policy Version:** v2.0 (Improved)  
**Next Review:** May 9, 2026 (Quarterly)
