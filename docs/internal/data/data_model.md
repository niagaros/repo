# CSPM Data Model Documentation

## Overview

This document describes the logical data model used by the CSPM MVP. The data model defines how users, cloud accounts, scans, findings, rules, and compliance mappings relate to each other. It ensures that scan results can be traced back to the correct cloud environment, security rule, and compliance standard.

The full Entity Relationship Diagram (ERD) is available here:

> **ERD Diagram:**  
> `/docs/images/cspm.png`

This model is designed to support:
- Multi-user access
- Multiple connected cloud accounts
- Repeated security scans over time
- Rule-based findings
- Compliance mapping (e.g. CIS, PCI-DSS)
- Future extensibility toward a CNAPP architecture

---

## Core Entities

### 1. User

Represents a platform user who can access the CSPM frontend and manage connected cloud accounts.

**Purpose:**  
Controls ownership, access, and visibility of cloud accounts and scan results.

**Fields:**
- `userId` (PK) – Unique user identifier
- `name` – Display name
- `email` – Login and notification address
- `cognitoId` – Reference to AWS Cognito identity

**Relationships:**
- One user can own multiple cloud accounts
- One user can have access to multiple scan results through owned accounts

---

### 2. CloudAccount

Represents a connected AWS account that will be scanned by the CSPM system.

**Purpose:**  
Defines the security boundary for scans, rules, and findings.

**Fields:**
- `accountId` (PK) – Internal account identifier
- `awsAccountId` – AWS account number
- `accountName` – Friendly name for display
- `ownerUserId` (FK) – Reference to User

**Relationships:**
- Belongs to one user
- Has many scan runs
- Stores collected configuration data

---

### 3. ScanRun

Represents a single execution of a CSPM scan against a cloud account.

**Purpose:**  
Tracks scan history and allows trend analysis over time.

**Fields:**
- `scanId` (PK) – Unique scan identifier
- `accountId` (FK) – Target cloud account
- `startTime` – When scan started
- `endTime` – When scan finished
- `status` – Running, Completed, Failed

**Relationships:**
- Belongs to one cloud account
- Produces many findings
- Uses many rules during evaluation

---

### 4. Resource

Represents a cloud resource discovered during a scan.

**Purpose:**  
Provides context for findings (what is misconfigured and where).

**Fields:**
- `resourceId` (PK) – Internal identifier
- `resourceType` – e.g. S3, IAM Role, Lambda, Cognito Pool
- `resourceArn` – AWS ARN
- `region` – AWS region
- `accountId` (FK) – Owner cloud account

**Relationships:**
- Belongs to one cloud account
- Can have many findings

---

### 5. Rule

Represents a security rule used to evaluate cloud configurations.

**Purpose:**  
Defines what is considered secure or insecure.

**Fields:**
- `ruleId` (PK) – Unique rule identifier
- `name` – Rule name
- `service` – AWS service (S3, IAM, Lambda, etc.)
- `description` – What the rule checks
- `severity` – Low, Medium, High, Critical
- `enabled` – Whether rule is active

**Relationships:**
- Can produce many findings
- Can map to multiple compliance standards

---

### 6. Finding

Represents a security issue discovered by a rule during a scan.

**Purpose:**  
This is the main output of the CSPM system.

**Fields:**
- `findingId` (PK) – Unique identifier
- `scanId` (FK) – Scan that produced the finding
- `ruleId` (FK) – Rule that triggered the finding
- `resourceId` (FK) – Affected resource
- `status` – Open, Acknowledged, Resolved
- `riskScore` – Numeric or severity-based score
- `createdAt` – Detection time

**Relationships:**
- Belongs to one scan
- Refers to one rule
- Refers to one resource

---

### 7. ComplianceStandard

Represents a security or regulatory framework.

**Purpose:**  
Allows findings and rules to be mapped to compliance requirements.

**Examples:**
- CIS AWS Benchmark
- PCI-DSS
- ISO 27001

**Fields:**
- `standardId` (PK)
- `name`
- `version`
- `description`

**Relationships:**
- Has many compliance controls

---

### 8. ComplianceControl

Represents a specific requirement within a standard.

**Purpose:**  
Links technical findings to formal compliance language.

**Fields:**
- `controlId` (PK)
- `standardId` (FK)
- `controlCode` – e.g. CIS 2.1.1
- `description`

**Relationships:**
- Belongs to one compliance standard
- Can map to many rules

---

### 9. RuleComplianceMap

Join table that maps rules to compliance controls.

**Purpose:**  
Allows one rule to satisfy multiple compliance requirements.

**Fields:**
- `ruleId` (FK)
- `controlId` (FK)

**Relationships:**
- Many-to-many between rules and compliance controls

---

### 10. CollectedData

Stores raw configuration data collected from AWS APIs.

**Purpose:**  
Separates data collection from rule evaluation and supports reprocessing.

**Fields:**
- `dataId` (PK)
- `scanId` (FK)
- `service` – AWS service name
- `region`
- `rawPayload` – JSON data from AWS API

**Relationships:**
- Belongs to one scan

---

## Relationship Summary

- **User → CloudAccount**: One-to-many  
- **CloudAccount → ScanRun**: One-to-many  
- **ScanRun → Finding**: One-to-many  
- **ScanRun → CollectedData**: One-to-many  
- **Resource → Finding**: One-to-many  
- **Rule → Finding**: One-to-many  
- **ComplianceStandard → ComplianceControl**: One-to-many  
- **Rule ↔ ComplianceControl**: Many-to-many (via RuleComplianceMap)

---

## Design Rationale

This model was designed to:
- Keep **scans immutable** so historical security posture can be reviewed
- Allow **rules and compliance standards to evolve independently**
- Support **multi-account and multi-user environments**
- Enable **future expansion toward CNAPP features** such as runtime risk, workload identity, and vulnerability correlation

---

## Architecture Alignment

This data model directly supports the backend folder structure:

- `collectors/` → Populates **CollectedData** and **Resource**
- `rules/` → Defines **Rule**
- `engine/` → Creates **ScanRun** and evaluates **Findings**
- `standards/` → Defines **ComplianceStandard** and **ComplianceControl**
- `postprocess/` → Enriches **Findings** with risk and compliance context
- `frontend/` → Displays **Findings**, **Scans**, and **Compliance Status**

---

## ERD Reference

The full visual ERD can be found at:
/docs/images/Niagaros_ERD.png
