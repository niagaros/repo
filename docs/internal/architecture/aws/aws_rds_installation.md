# AWS RDS PostgreSQL Setup Guide for CSPM
**Complete Installation and Configuration Documentation**

---

## Table of Contents
1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Database Installation](#database-installation)
4. [Schema Setup](#schema-setup)
5. [Lambda Configuration](#lambda-configuration)
6. [Testing and Verification](#testing-and-verification)
7. [Troubleshooting](#troubleshooting)
8. [Next Steps](#next-steps)

---

## Overview

This guide documents the complete setup of an AWS RDS PostgreSQL database for the CSPM (Cloud Security Posture Management) platform, including:

- RDS Aurora PostgreSQL instance creation
- Database schema deployment
- Lambda function configuration for database access
- Secrets Manager integration
- IAM permissions setup

**Architecture:**
- **Database**: Aurora PostgreSQL (RDS)
- **Region**: Configurable (example uses eu-west-1)
- **Lambda Runtime**: Python 3.11
- **Database Driver**: pg8000 (pure Python, no compilation required)

---

## Prerequisites

### Required Access
- AWS Console access with permissions for:
  - RDS (database creation and management)
  - Lambda (function creation and deployment)
  - Secrets Manager (secret creation and access)
  - IAM (role and policy management)
  - CloudShell (for CLI operations)

### Existing Resources
Before starting, ensure you have:
- AWS account
- VPC with appropriate subnet configuration
- Security group configured for PostgreSQL access (port 5432)

---

## Database Installation

### 1. RDS Instance Details

**Connection Information:**
```
Endpoint: <YOUR_RDS_ENDPOINT>
Port: 5432
Database Name: cspm_production
Master Username: <YOUR_MASTER_USERNAME>
Master Password: <STORED_IN_SECRETS_MANAGER>
```

**Instance Specifications:**
- **Instance Class**: db.t3.micro (or higher based on requirements)
- **Storage**: 20 GB gp2 (expandable)
- **Engine**: Aurora PostgreSQL (compatible with PostgreSQL 13+)
- **Public Access**: Configure based on your VPC setup

### 2. Initial Connection

Connect to the database using CloudShell:

```bash
psql -h <YOUR_RDS_ENDPOINT> \
     -U <YOUR_MASTER_USERNAME> \
     -d cspm_production
```

When prompted, enter your master password.

### 3. Enable Required Extensions

```sql
-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
```

---

## Schema Setup

### 1. Core Tables

The CSPM database uses four core tables that represent the security scanning workflow:

**Relationship Hierarchy:**
```
users (Cognito authenticated users)
  └── cloud_accounts (AWS accounts to scan)
        └── resources (Discovered AWS resources)
              └── findings (Security issues detected)
```

### 2. Create Users Table

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cognito_sub VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_users_cognito_sub ON users(cognito_sub);
CREATE INDEX idx_users_email ON users(email);
```

**Purpose:**
- Stores authenticated users from Amazon Cognito
- Links JWT tokens (via `cognito_sub`) to internal user data
- Populated automatically by Cognito post-confirmation trigger

### 3. Create Cloud Accounts Table

```sql
CREATE TABLE cloud_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_id VARCHAR(50) NOT NULL,
    account_name VARCHAR(255),
    role_arn VARCHAR(512) NOT NULL,
    external_id VARCHAR(255),
    status VARCHAR(20) DEFAULT 'active',
    last_scan_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, account_id)
);

CREATE INDEX idx_cloud_accounts_user ON cloud_accounts(user_id);
```

**Purpose:**
- Tracks AWS accounts connected by users for scanning
- Stores IAM role information for cross-account access
- Maintains scan status and history

### 4. Create Resources Table

```sql
CREATE TABLE resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id UUID NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(512) NOT NULL,
    resource_name VARCHAR(255),
    region VARCHAR(50),
    config JSONB NOT NULL,
    last_scanned_at TIMESTAMP,
    UNIQUE(cloud_account_id, resource_id)
);

CREATE INDEX idx_resources_account ON resources(cloud_account_id);
CREATE INDEX idx_resources_type ON resources(resource_type);
CREATE INDEX idx_resources_config ON resources USING GIN(config);
```

**Purpose:**
- Stores all discovered AWS resources (S3, EC2, RDS, etc.)
- Uses JSONB for flexible configuration storage
- GIN index on `config` enables fast JSON queries

### 5. Create Findings Table

```sql
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id UUID NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    check_id VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) DEFAULT 'open',
    detected_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(resource_id, check_id)
);

CREATE INDEX idx_findings_resource ON findings(resource_id);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_severity ON findings(severity);
```

**Purpose:**
- Records security issues discovered during scans
- One finding per resource per check (enforced by unique constraint)
- Tracks remediation status over time

### 6. Create Lambda Database User

```sql
-- Create dedicated user for Lambda functions
CREATE USER cspm_lambda WITH PASSWORD '<GENERATE_SECURE_PASSWORD>';

-- Grant connection and schema access
GRANT CONNECT ON DATABASE cspm_production TO cspm_lambda;
GRANT USAGE ON SCHEMA public TO cspm_lambda;

-- Grant table permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO cspm_lambda;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO cspm_lambda;

-- Ensure future tables also grant permissions
ALTER DEFAULT PRIVILEGES IN SCHEMA public 
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO cspm_lambda;

-- Exit psql
\q
```

**Security Notes:**
- `cspm_lambda` user has limited permissions (no DDL operations)
- Store the password securely in AWS Secrets Manager
- Permissions are scoped to public schema only

---

## Lambda Configuration

### 1. Store Database Credentials in Secrets Manager

Run in CloudShell:

```bash
aws secretsmanager create-secret \
    --name cspm/database/credentials \
    --description "CSPM database credentials" \
    --secret-string '{
        "username": "cspm_lambda",
        "password": "<YOUR_LAMBDA_USER_PASSWORD>",
        "host": "<YOUR_RDS_ENDPOINT>",
        "port": 5432,
        "database": "cspm_production"
    }'
```

**Expected Output:**
```json
{
    "ARN": "arn:aws:secretsmanager:<region>:<account-id>:secret:cspm/database/credentials-XXXXXX",
    "Name": "cspm/database/credentials",
    "VersionId": "..."
}
```

### 2. Create pg8000 Lambda Layer

pg8000 is a pure Python PostgreSQL driver that requires no compilation, making it ideal for Lambda.

```bash
# Create layer directory
mkdir -p python
pip3 install pg8000 -t python/
zip -r pg8000-layer.zip python
rm -rf python

# Upload to Lambda
aws lambda publish-layer-version \
    --layer-name pg8000-python311 \
    --description "pg8000 for Python 3.11" \
    --zip-file fileb://pg8000-layer.zip \
    --compatible-runtimes python3.11
```

**Expected Output:**
```json
{
    "LayerVersionArn": "arn:aws:lambda:<region>:<account-id>:layer:pg8000-python311:1",
    ...
}
```

**Save this ARN** - you'll need it in the next step.

### 3. Create Lambda Test Function

**Via AWS Console:**

1. Navigate to **Lambda** → **Create function**
2. Configure:
   - **Function name**: `test-db-connection`
   - **Runtime**: Python 3.11
   - **Architecture**: x86_64
3. Click **Create function**

### 4. Add Lambda Code

Replace the default Lambda code with:

```python
import boto3
import json
import pg8000.native

def lambda_handler(event, context):
    """
    Test Lambda function to verify database connectivity.
    Retrieves credentials from Secrets Manager and queries the users table.
    """
    # Get credentials from Secrets Manager
    secrets = boto3.client('secretsmanager')
    secret = secrets.get_secret_value(SecretId='cspm/database/credentials')
    creds = json.loads(secret['SecretString'])
    
    # Connect using pg8000
    conn = pg8000.native.Connection(
        user=creds['username'],
        password=creds['password'],
        host=creds['host'],
        port=creds['port'],
        database=creds['database']
    )
    
    # Query user count
    result = conn.run('SELECT COUNT(*) FROM users')
    count = result[0][0]
    
    conn.close()
    
    return {
        'statusCode': 200,
        'body': f'Users count: {count}'
    }
```

Click **Deploy**

### 5. Attach pg8000 Layer

1. Scroll to **Layers** section
2. Click **Add a layer**
3. Choose **Specify an ARN**
4. Paste your layer ARN from step 2 (e.g., `arn:aws:lambda:<region>:<account-id>:layer:pg8000-python311:1`)
5. Click **Add**

### 6. Grant Secrets Manager Permissions

1. Go to **Configuration** tab
2. Click **Permissions**
3. Click the execution role name (opens IAM)
4. Click **Add permissions** → **Attach policies**
5. Search for **SecretsManagerReadWrite**
6. Check the box and click **Add permissions**

---

## Testing and Verification

### 1. Test Lambda Function

1. Go to **Test** tab in Lambda console
2. Click **Create new event**
3. Configure:
   - **Event name**: `test`
   - **Event JSON**: Leave default `{}`
4. Click **Save**
5. Click **Test**

**Expected Result:**
```json
{
  "statusCode": 200,
  "body": "Users count: 0"
}
```

### 2. Verify Database Tables

Connect to database:
```bash
psql -h <YOUR_RDS_ENDPOINT> \
     -U <YOUR_MASTER_USERNAME> \
     -d cspm_production
```

List tables:
```sql
\dt

-- Expected output:
--  Schema |      Name       | Type  |   Owner    
-- --------+-----------------+-------+------------
--  public | cloud_accounts  | table | <master_user>
--  public | findings        | table | <master_user>
--  public | resources       | table | <master_user>
--  public | users           | table | <master_user>
```

Verify table structure:
```sql
\d users
\d cloud_accounts
\d resources
\d findings
```

### 3. Test Lambda User Permissions

```sql
-- Switch to Lambda user
SET ROLE cspm_lambda;

-- Test insert (should work)
INSERT INTO users (cognito_sub, email, full_name) 
VALUES ('test-sub-123', 'test@example.com', 'Test User');

-- Test select (should work)
SELECT * FROM users;

-- Test delete (should work)
DELETE FROM users WHERE cognito_sub = 'test-sub-123';

-- Switch back to admin
RESET ROLE;

\q
```

---

## Troubleshooting

### Common Issues

#### Issue: "No module named 'psycopg2._psycopg'"
**Cause**: Using psycopg2 layer compiled for wrong Python version  
**Solution**: Use pg8000 layer instead (pure Python, no compilation needed)

#### Issue: "Unable to import module 'lambda_function'"
**Cause**: Layer not attached or wrong architecture  
**Solution**: 
1. Verify layer ARN is correct
2. Ensure Lambda uses x86_64 architecture
3. Confirm layer is compatible with Python 3.11

#### Issue: Lambda timeout when connecting
**Cause**: Security group not allowing Lambda to reach RDS  
**Solution**:
1. Check RDS security group allows inbound on port 5432
2. Ensure Lambda is in same VPC as RDS (or has appropriate routing)
3. Increase Lambda timeout to 30 seconds

#### Issue: "Access denied" from Secrets Manager
**Cause**: Lambda execution role missing permissions  
**Solution**: Attach `SecretsManagerReadWrite` policy to Lambda execution role

#### Issue: Database connection refused
**Cause**: RDS not publicly accessible or wrong endpoint  
**Solution**:
1. Verify RDS endpoint in Secrets Manager matches actual endpoint
2. Check RDS is publicly accessible (or Lambda in same VPC)
3. Verify security group allows your IP for testing

---

## Next Steps

### 1. Create Cognito Post-Confirmation Trigger
Set up Lambda to automatically create user records when users sign up via Cognito.

**Function Purpose:**
- Triggered after successful Cognito user confirmation
- Extracts user details from Cognito event
- Inserts new record into `users` table

**Sample Code Structure:**
```python
def lambda_handler(event, context):
    cognito_sub = event['request']['userAttributes']['sub']
    email = event['request']['userAttributes']['email']
    full_name = event['request']['userAttributes'].get('name', '')
    
    # Insert into users table
    # ...
    
    return event  # Must return event for Cognito
```

### 2. Build CSPM Scanner Lambda
Create Lambda functions to:
- Enumerate AWS resources in connected accounts
- Run security checks against discovered resources
- Store results in `resources` and `findings` tables

### 3. Implement API Layer
Build API Gateway + Lambda to:
- Allow users to connect AWS accounts
- Trigger scans on demand
- Query findings and generate reports

### 4. Add Monitoring and Alerting
- CloudWatch dashboards for database performance
- Alerts for failed scans or critical findings
- Cost monitoring for RDS usage

### 5. Production Best Practices
- Implement database connection pooling
- Set up automated backups and point-in-time recovery
- Configure VPC endpoints for private connectivity
- Enable RDS Performance Insights for monitoring
- Implement proper error handling and retry logic in Lambda functions

---

## Architecture Diagram

```
┌─────────────────┐
│   Cognito       │
│   User Pool     │
└────────┬────────┘
         │ (trigger on signup)
         ▼
┌─────────────────┐      ┌──────────────────┐
│  Post-Confirm   │─────▶│  Secrets Manager │
│  Lambda         │      │  (DB Credentials)│
└────────┬────────┘      └──────────────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│     RDS Aurora PostgreSQL               │
│  ┌────────────────────────────────────┐ │
│  │  users                             │ │
│  │  ├── cloud_accounts                │ │
│  │  │   ├── resources                 │ │
│  │  │   │   └── findings              │ │
│  └────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

---

## Database Schema Summary

| Table | Purpose | Key Fields | Relationships |
|-------|---------|------------|---------------|
| **users** | Cognito authenticated users | `cognito_sub`, `email` | Parent to cloud_accounts |
| **cloud_accounts** | AWS accounts to scan | `account_id`, `role_arn` | Child of users, parent to resources |
| **resources** | Discovered AWS resources | `resource_type`, `config` (JSONB) | Child of cloud_accounts, parent to findings |
| **findings** | Security issues | `check_id`, `severity`, `status` | Child of resources |

---

## Support and Resources

- **AWS RDS Documentation**: https://docs.aws.amazon.com/rds/
- **pg8000 Documentation**: https://github.com/tlocke/pg8000
- **Lambda Best Practices**: https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html
- **PostgreSQL Documentation**: https://www.postgresql.org/docs/

---

## Change Log

| Date | Version | Changes |
|------|---------|---------|
| 2026-02-16 | 1.0 | Initial documentation - Complete setup guide with pg8000 layer |

---

**Document maintained by**: CSPM Development Team  
**Last updated**: February 16, 2026
