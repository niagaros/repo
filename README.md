# Niagaros CSPM (Cloud Security Posture Management) – MVP

Niagaros is developing a Cloud Security Posture Management (CSPM) solution to help organizations identify security misconfigurations in their cloud environments.  
This repository contains the initial MVP version of the Niagaros CSPM platform, built specifically for **Domits** as the first pilot customer.

The first iteration focuses exclusively on **AWS** and starts with a single resource type: **Amazon S3**.

---

## Project Overview

Modern cloud environments introduce a wide range of security risks, especially when configurations are inconsistent or not continuously monitored. Domits currently lacks clear visibility into whether their AWS resources — particularly S3 buckets — are securely configured.

Niagaros is creating a targeted CSPM solution that:
- Analyzes AWS S3 configurations
- Detects misconfigurations and security risks
- Rates these risks by severity
- Generates clear and actionable insights

This MVP lays the foundation for future expansion (multiple AWS services, multi-cloud support, dashboards, automated remediation, etc.).

---

## MVP Scope

### **Included**
- AWS as the only cloud provider
- S3 as the only supported service
- Detection of S3 misconfigurations such as:
  - Public exposure
  - Missing or weak encryption
  - Misconfigured bucket policies or ACLs
  - Missing logging or versioning
  - Excessive IAM permissions
- Risk rating (Low, Medium, High, Critical)
- Basic output/reporting of findings (CLI or simple API)

### **Excluded (for now)**
- Additional AWS services (EC2, RDS, IAM, Lambda, etc.)
- Multi-cloud support (Azure, GCP)
- Automated remediation
- Dashboard UI
- Organization-wide posture scoring

---

## Architecture (High-Level)

The MVP architecture consists of:

1. **AWS Data Collector**  
   Retrieves S3 configuration details using AWS SDK.

2. **Rule Engine**  
   Applies CIS Benchmarks/Controls, AWS best practices, and Niagaros-defined rules.

3. **Risk Classifier**  
   Evaluates findings and assigns a severity rating.

4. **Results Output**  
   Outputs findings as JSON, logs, or a basic report format.

---

## Why S3 First?

S3 buckets are one of the most commonly misconfigured AWS resources and often lead to:
- Data exposure  
- Public access issues  
- Sensitive information leaks  
- Compliance violations  

Starting with S3 allows Niagaros to build a strong foundation while addressing Domits' security visibility needs.

---

## Development Status

This project is currently in **active development** as part of the Niagaros CSPM pilot for Domits.

Planned MVP deliverables:
- [ ] S3 configuration scanner  
- [ ] Core rule engine  
- [ ] Risk scoring model  
- [ ] Basic output formatting  
- [ ] Documentation for setup and usage  
- [ ] Initial validation against the Domits AWS environment  

---

## Technologies

- **AWS SDK (boto3 or AWS SDK for Node/Go/Python)**  
- **Python or TypeScript (tech stack depends on final choice)**  
- **CIS Benchmark for AWS**  
- **AWS IAM, S3 APIs, CloudFormation metadata (optional)**  
- **Niagaros internal risk model**  

---

## Documentation

- `docs/internal` – Internal Niagaros documentation, including product vision, long-term strategy, and architectural decisions.
- `docs/public` – Public-facing documentation such as security rules, detected misconfigurations, and general CSPM methodology.
- `docs/partner` – Documentation intended for partner organizations like Domits, including onboarding instructions, usage guidelines, and integration requirements.


---

