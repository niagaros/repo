# AWS Environment Inventory (Niagaros)

This document provides a high-level overview of the AWS resources currently used by Niagaros.  
Each service listed here will have its own detailed documentation file inside the `/Environments/AWS/services/` directory.

---

## 1. Overview of Active AWS Services

### **Amplify**
- Used for hosting the frontend application.
- Automatically manages deployments and build pipelines.

### **S3**
- Used for application assets and storage.
- Multiple buckets for hosting, logs, and internal storage.
- Bucket-specific documentation will follow separately.

### **IAM**
- Centralized identity and access management for all AWS resources.
- Roles and policies for Amplify, Config, Cognito, and internal automations.

### **Cognito**
- Authentication provider for the platform.
- User pools and identity pools used for login flows.

### **AWS Config**
- Used for continuous configuration monitoring.
- Tracks resource changes and compliance.

### **CloudWatch**
- Logging and monitoring layer for application and AWS service events.
- Used for alarms, metrics, and log retention.

---

## 2. Networking (High-Level)

> Networking is minimal and not actively used by the platform architecture.  
> No custom network components have been created at this stage.

- **Default VPC** (auto-created by AWS)
- **Default Subnets**
- **Default Security Groups**
- No EC2, RDS, Load Balancers, or Lambda functions requiring custom networking.

---

## 3. Regions

Niagaros primarily operates in European AWS regions. The recommended setup is:

- **Primary Region:**  
  **eu-west-1 (Ireland)** — stable, cost-efficient, and broad service coverage.

- **Alternative Region:**  
  **eu-central-1 (Frankfurt)** — lowest latency to the Netherlands; used if performance is prioritized.

- **Optional Backup / DR Region:**  
  **eu-west-2 (London)** — used for multi-region redundancy such as S3 replication or configuration backups.

A detailed region selection and DR approach is documented separately.
---

## 4. Resource Structure

Each AWS service will include its own `.md` file with detailed configuration: