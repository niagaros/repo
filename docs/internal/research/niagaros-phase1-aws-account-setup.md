# Niagaros — Phase 1: AWS Account Setup & IAM Governance

## Purpose

Set up AWS organizations, accounts, baseline security, and identity boundaries that all other components depend on.

## Prerequisites

- AWS root access  
- AWS CLI installed  
- Decided account structure (security, platform, dev, staging, prod)

## 1.1 Create AWS Organization & OUs

```bash
# Create organization
aws organizations create-organization --feature-set ALL

# Create OUs (replace <root-id>)
aws organizations create-organizational-unit --parent-id <root-id> --name "security"
aws organizations create-organizational-unit --parent-id <root-id> --name "platform"
aws organizations create-organizational-unit --parent-id <root-id> --name "dev"
aws organizations create-organizational-unit --parent-id <root-id> --name "staging"
aws organizations create-organizational-unit --parent-id <root-id> --name "prod"
```

## 1.2 Create Accounts

```bash
aws organizations create-account \
  --email ops+dev@example.com \
  --account-name "niagaros-dev" \
  --role-name "OrganizationAccountAccessRole"

# Repeat for staging, prod, security, platform with unique emails.
```

## 1.3 IAM Governance

### Delegated Admin / Deploy Role Trust Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::111122223333:root" },
    "Action": "sts:AssumeRole"
  }]
}
```

### Deploy Role Permissions (example)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudformation:*", "s3:*", "lambda:*", "apigateway:*",
        "iam:PassRole", "iam:GetRole", "dynamodb:*",
        "cognito-idp:*", "amplify:*"
      ],
      "Resource": "*"
    }
  ]
}
```

## 1.4 CloudTrail Setup

```bash
aws cloudtrail create-trail \
  --name NiagarosOrgTrail \
  --s3-bucket-name niagaros-logs-1234 \
  --is-multi-region-trail

aws cloudtrail start-logging --name NiagarosOrgTrail
```

## 1.5 GuardDuty Setup

```bash
# In security account
aws guardduty create-detector --enable

# Add member account
aws guardduty create-members \
  --account-details AccountId=222233334444,Email=ops+prod@example.com
```

## 1.6 S3 Logging Bucket Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCloudTrailWrite",
      "Effect": "Allow",
      "Principal": { "Service": "cloudtrail.amazonaws.com" },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::niagaros-logs-1234/AWSLogs/*",
      "Condition": {
        "StringEquals": { "s3:x-amz-acl": "bucket-owner-full-control" }
      }
    }
  ]
}
```

## Verification

- IAM least privilage
- Cloudwatch logs active
- S3 logging bucket blocks public access

