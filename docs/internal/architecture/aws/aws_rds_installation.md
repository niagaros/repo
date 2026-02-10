CSPM Database Installation Guide - MVP Version
Goal: Get a working CSPM database up and running with the absolute minimum needed.
What you'll have:

✅ Users (linked to Cognito)
✅ Cloud accounts (customers' AWS accounts to scan)
✅ Resources (S3, EC2, etc.)
✅ Findings (security issues)


Step 1: Choose Your Database
Recommended: Aurora PostgreSQL Serverless v2
Why:

Auto-scales (0.5 to 16 ACU)
Pay only for what you use
No capacity planning
Perfect for MVP through production

Alternative (cheaper but manual):

PostgreSQL RDS db.t3.micro = $15/month
Fixed capacity, no auto-scaling


Step 2: Create Aurora Cluster
Option A: AWS Console (Easiest)

Go to RDS Console
Click "Create database"
Choose:

Engine: Aurora (PostgreSQL Compatible)
Edition: Aurora PostgreSQL (Serverless v2)
Version: 15.4 (or the latest Aurora PostgreSQL 15.x version recommended by AWS)
Template: Production
DB cluster identifier: cspm-db
Public access: No
Encryption: Yes
Backup retention: 7 days



Option B: AWS CLI (Automated)

Bash (AWS CLI) - create cluster:
```bash
aws rds create-db-cluster \
    --db-cluster-identifier cspm-db \
    --engine aurora-postgresql \
    --engine-version 15.4 \
    --master-username cspm_admin \
    --master-user-password 'YOUR_SECURE_PASSWORD_HERE' \
    --database-name cspm_production \
    --vpc-security-group-ids sg-YOUR_SECURITY_GROUP \
    --db-subnet-group-name your-private-subnet-group \
    --serverless-v2-scaling-configuration MinCapacity=0.5,MaxCapacity=16 \
    --backup-retention-period 7 \
    --storage-encrypted \
    --deletion-protection
```

# Create instance
```bash
aws rds create-db-instance \
    --db-instance-identifier cspm-db-instance \
    --db-instance-class db.serverless \
    --engine aurora-postgresql \
    --db-cluster-identifier cspm-db
```
Wait 5-10 minutes for cluster to be available.

Step 3: Configure Security Group

Bash (AWS CLI) - allow PostgreSQL (5432) from Lambda security group:
```bash
aws ec2 authorize-security-group-ingress \
    --group-id sg-YOUR_RDS_SECURITY_GROUP \
    --protocol tcp \
    --port 5432 \
    --source-group sg-YOUR_LAMBDA_SECURITY_GROUP
```
Important: RDS should be in private subnet, only accessible from Lambda/VPC.

Step 4: Get Connection Endpoint

Bash (AWS CLI) - get writer endpoint:
```bash
aws rds describe-db-clusters \
    --db-cluster-identifier cspm-db \
    --query 'DBClusters[0].Endpoint' \
    --output text
```
Save this endpoint - you'll need it for connection strings.
Example: cspm-db.cluster-xxxxx.us-east-1.rds.amazonaws.com

Step 5: Connect to Database
From EC2/Cloud9 (in same VPC)

Bash (Linux) - install PostgreSQL client:
```bash
sudo apt-get update
sudo apt-get install postgresql-client
```

# Connect
```bash
psql -h cspm-db.cluster-xxxxx.us-east-1.rds.amazonaws.com \
     -U cspm_admin \
     -d cspm_production \
     -p 5432
```
Enter password when prompted.

Step 6: Run Schema SQL
Download Schema

Bash (Linux/macOS) - download the schema file:
```bash
curl -o cspm_schema.sql https://YOUR_URL/cspm_mvp_schema.sql
```
Execute Schema
In psql prompt:

```sql
-- Create extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Run the full schema
\i cspm_schema.sql

-- Verify tables created
\dt

-- Should see:
--  users
--  cloud_accounts
--  resources
--  findings
```
Or paste directly:
```sql
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- TABLE 1: USERS
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cognito_sub VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_users_cognito_sub ON users(cognito_sub);

-- TABLE 2: CLOUD_ACCOUNTS
CREATE TABLE cloud_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
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

-- TABLE 3: RESOURCES
CREATE TABLE resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id UUID REFERENCES cloud_accounts(id) ON DELETE CASCADE,
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

-- TABLE 4: FINDINGS
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id UUID REFERENCES resources(id) ON DELETE CASCADE,
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

-- VIEWS
CREATE VIEW user_stats AS
SELECT 
    u.id as user_id,
    u.email,
    COUNT(DISTINCT ca.id) as accounts,
    COUNT(DISTINCT r.id) as resources,
    COUNT(f.id) FILTER (WHERE f.status = 'open') as open_findings,
    COUNT(f.id) FILTER (WHERE f.status = 'open' AND f.severity = 'critical') as critical
FROM users u
LEFT JOIN cloud_accounts ca ON u.id = ca.user_id
LEFT JOIN resources r ON ca.id = r.cloud_account_id
LEFT JOIN findings f ON r.id = f.resource_id
GROUP BY u.id, u.email;

CREATE VIEW active_findings AS
SELECT 
    f.id,
    f.severity,
    f.title,
    f.check_id,
    r.resource_type,
    r.resource_name,
    r.region,
    ca.account_name,
    u.cognito_sub
FROM findings f
JOIN resources r ON f.resource_id = r.id
JOIN cloud_accounts ca ON r.cloud_account_id = ca.id
JOIN users u ON ca.user_id = u.id
WHERE f.status = 'open';
```

Step 7: Verify Installation
-- Check tables
```sql
\dt

-- Should show:
--  public | cloud_accounts | table | cspm_admin
--  public | findings       | table | cspm_admin
--  public | resources      | table | cspm_admin
--  public | users          | table | cspm_admin

-- Check views
\dv

-- Should show:
--  public | active_findings | view | cspm_admin
--  public | user_stats      | view | cspm_admin

-- Check indexes
\di

-- Should show indexes on:
--  users(cognito_sub)
--  cloud_accounts(user_id)
--  resources(cloud_account_id, resource_type, config)
--  findings(resource_id, status, severity)
```

Step 8: Create Database User for Lambda
Don't use admin account for Lambda!
-- Create Lambda user
```sql
CREATE USER cspm_lambda WITH PASSWORD 'lambda_secure_password_here';

-- Grant permissions
GRANT CONNECT ON DATABASE cspm_production TO cspm_lambda;
GRANT USAGE ON SCHEMA public TO cspm_lambda;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO cspm_lambda;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO cspm_lambda;

-- For future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public 
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO cspm_lambda;
```

Step 9: Store Credentials in Secrets Manager
Bash (AWS CLI) - create secret:
```bash
aws secretsmanager create-secret \
    --name cspm/database/credentials \
    --description "CSPM database credentials" \
    --secret-string '{
        "username": "cspm_lambda",
        "password": "lambda_secure_password_here",
        "host": "cspm-db.cluster-xxxxx.us-east-1.rds.amazonaws.com",
        "port": 5432,
        "database": "cspm_production"
    }'
```
Lambda will read from Secrets Manager (never hardcode passwords).

Step 10: Test Connection from Lambda

Lambda Connection Code (Node.js)
```javascript
const AWS = require('aws-sdk');
const { Client } = require('pg');

exports.handler = async (event) => {
    // Get credentials from Secrets Manager
    const secretsManager = new AWS.SecretsManager();
    const secret = await secretsManager.getSecretValue({ 
        SecretId: 'cspm/database/credentials' 
    }).promise();
    
    const creds = JSON.parse(secret.SecretString);
    
    // Connect to database
    const client = new Client({
        host: creds.host,
        user: creds.username,
        password: creds.password,
        database: creds.database,
        port: creds.port,
        ssl: { rejectUnauthorized: true }
    });
    
    await client.connect();
    
    // Test query
    const result = await client.query('SELECT COUNT(*) FROM users');
    console.log('Users count:', result.rows[0].count);
    
    await client.end();
    
    return { statusCode: 200, body: 'Connected!' };
};
```

Lambda Connection Code (Python)
```python
import boto3
import psycopg2
import json

def lambda_handler(event, context):
    # Get credentials
    secrets = boto3.client('secretsmanager')
    secret = secrets.get_secret_value(SecretId='cspm/database/credentials')
    creds = json.loads(secret['SecretString'])
    
    # Connect
    conn = psycopg2.connect(
        host=creds['host'],
        user=creds['username'],
        password=creds['password'],
        database=creds['database'],
        port=creds['port'],
        sslmode='require'
    )
    
    cur = conn.cursor()
    cur.execute('SELECT COUNT(*) FROM users')
    print(f"Users count: {cur.fetchone()[0]}")
    
    cur.close()
    conn.close()
    
    return {'statusCode': 200, 'body': 'Connected!'}
```

Step 11: Setup Cognito Post-Confirmation Trigger
When user signs up in Cognito, automatically create database record.

Lambda Function
```javascript
const { Client } = require('pg');
const AWS = require('aws-sdk');

exports.handler = async (event) => {
    // Get DB credentials
    const secretsManager = new AWS.SecretsManager();
    const secret = await secretsManager.getSecretValue({ 
        SecretId: 'cspm/database/credentials' 
    }).promise();
    const creds = JSON.parse(secret.SecretString);
    
    // Connect
    const client = new Client({
        host: creds.host,
        user: creds.username,
        password: creds.password,
        database: creds.database,
        ssl: { rejectUnauthorized: true }
    });
    await client.connect();
    
    // Extract user info from Cognito
    const cognitoSub = event.request.userAttributes.sub;
    const email = event.request.userAttributes.email;
    const name = event.request.userAttributes.name || '';
    
    // Create user in database
    await client.query(`
        INSERT INTO users (cognito_sub, email, full_name)
        VALUES ($1, $2, $3)
        ON CONFLICT (cognito_sub) DO NOTHING
    `, [cognitoSub, email, name]);
    
    await client.end();
    
    return event;  // Must return event for Cognito
};
```
Attach to Cognito
```bash
aws cognito-idp update-user-pool \
    --user-pool-id us-east-1_XXXXXXXXX \
    --lambda-config '{
        "PostConfirmation": "arn:aws:lambda:us-east-1:ACCOUNT:function:cognito-post-confirmation"
    }'
```

Database Schema Explained
Table Flow
User signs up in Cognito
    ↓
users table (cognito_sub links to Cognito)
    ↓
cloud_accounts (user connects their AWS account)
    ↓
resources (scanner discovers S3, EC2, RDS, etc.)
    ↓
findings (security checks create findings)
Why Each Table
USERS

Links Cognito users to your CSPM data
cognito_sub = Cognito user ID from JWT token
NO passwords stored (Cognito handles authentication)

CLOUD_ACCOUNTS

Customer's AWS accounts they want scanned
role_arn = IAM role for cross-account access
external_id = Security token to prevent confused deputy attacks
One user can connect multiple AWS accounts

RESOURCES

Generic table for ANY AWS resource type
resource_type: 's3-bucket', 'ec2-instance', 'rds-database', etc.
config (JSONB): Stores complete resource configuration
Different resource types = different config structures (S3 vs EC2 vs RDS)

FINDINGS

Security issues detected on resources
check_id: Identifies which security check (e.g., 'AWS-S3-001')
severity: critical, high, medium, low
status: open, resolved


Common Queries
Get user dashboard stats
```sql
SELECT * FROM user_stats
WHERE email = 'user@company.com';
```
Returns:
user_id | email              | accounts | resources | open_findings | critical
--------+--------------------+----------+-----------+---------------+---------
uuid... | user@company.com   | 2        | 150       | 12            | 3
Get all findings for a user
```sql
SELECT * FROM active_findings
WHERE cognito_sub = 'abc-123-xyz'
ORDER BY severity DESC
LIMIT 20;
```
Find public S3 buckets
```sql
SELECT 
    resource_name,
    region,
    config->>'is_public' as is_public
FROM resources
WHERE resource_type = 's3-bucket'
  AND config->>'is_public' = 'true';
```
Count resources by type
```sql
SELECT 
    resource_type,
    COUNT(*) as count
FROM resources
WHERE cloud_account_id = 'account-uuid'
GROUP BY resource_type
ORDER BY count DESC;
```

Troubleshooting
Can't connect from Lambda
Check:

Lambda in same VPC as RDS
Security group allows Lambda SG → RDS on port 5432
Correct credentials in Secrets Manager
Database endpoint is writer endpoint (not reader)

bash# Test from Lambda
aws lambda invoke \
    --function-name test-db-connection \
    --payload '{}' \
    response.json
"relation does not exist"
Schema not created properly
-- Check if tables exist
```sql
\dt

-- If missing, re-run schema
\i cspm_schema.sql
```
"permission denied"
Lambda user doesn't have permissions
-- Grant permissions again
```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO cspm_lambda;
```
Slow queries
Check if indexes exist
-- List indexes
```sql
\di
```

-- Should see indexes on:
--   cognito_sub
--   user_id (cloud_accounts)
--   cloud_account_id (resources)
--   resource_type (resources)
--   resource_id (findings)

Maintenance
Backups
Aurora automatically backs up to S3:

Continuous backups
7-day retention (configurable)
Point-in-time recovery

Manual snapshot:
```bash
aws rds create-db-cluster-snapshot \
    --db-cluster-identifier cspm-db \
    --db-cluster-snapshot-identifier cspm-manual-backup-$(date +%Y%m%d)
```
Monitoring
Key metrics in CloudWatch:

DatabaseConnections - Should stay under 100
CPUUtilization - Should stay under 80%
ACUUtilization - Shows Aurora capacity usage
ReadLatency / WriteLatency - Should be < 10ms

