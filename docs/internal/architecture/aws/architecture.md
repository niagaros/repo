# ☁️ Cloud Security Platform – Architecture Overview

This document describes the technical architecture of our cloud security platform, inspired by solutions like Wiz and Orca Security.  
The platform analyzes customer environments in AWS for risks, misconfigurations, and security issues using an agentless scanner.

## 🗺️ Architecture Diagram

<p align="center">
  <img src="./docs/images/ArchitectureNiagaros.png" width="80%" alt="Niagaros Architecture Diagram">
</p>

<p align="center"><em>Figure 1: Overview of the Niagaros Cloud Security Architecture</em></p>

## Lambda Scanner
The **Lambda Scanner** is the core of the scan engine.  
This function performs periodic or on-demand scans in customer environments using **AWS STS AssumeRole** to obtain temporary access.  
The Lambda retrieves metadata from cloud resources (S3, EC2, IAM, etc.) and converts it into structured data.  
The results are forwarded to DynamoDB for analysis and reporting.

---

## Amazon API Gateway
The **API Gateway** serves as the secure entry point of the backend.  
It receives requests from the frontend (such as “start scan” or “fetch results”) and routes them to the correct Lambda functions.  
Additionally, it handles authentication, throttling, logging, and request validation.  
This ensures scalable and secure communication between the frontend and backend.

---

## External AWS (Customer Environment)
The **customer environment** contains the AWS resources being analyzed.  
Our Lambda Scanner uses temporary STS credentials to log in through a trust policy.  
Only **read-only** API calls are performed (no changes).  
This keeps the customer environment fully secure and controllable.

---

## AWS IAM (Assume Role + Permissions)
The customer creates an **IAM Role** with restricted read privileges.  
This Role only trusts our AWS account through a trust policy.  
Our Lambda uses **AssumeRole** to obtain temporary access and then performs the scans.  
No permanent keys or agents are required.

---

## AWS Resources (S3, EC2, VPC, RDS, etc.)
These are the actual components being checked.  
The Scanner reviews configurations, permissions, and security settings of these resources.  
Risks such as publicly accessible S3 buckets or weak IAM policies are detected.  
The raw scan results are then processed by a second Lambda.

---

## DynamoDB
**DynamoDB** stores all processed scan results and risks.  
The database is fast, serverless, and ideal for real-time dashboards.  
Each record contains information such as resource ID, tenant ID, severity, and detection timestamp.  
The frontend can directly fetch insights without heavy querying.

---

## Lambda (Data Processing)
This **processing Lambda** filters, classifies, and prioritizes scan results.  
It enriches data with context (e.g., “critical” or “compliant”).  
The function writes the refined data into DynamoDB.  
This keeps the dataset clean and useful for reporting and visualization.

---

## GitHub + CI/CD Pipeline
The codebase resides in **GitHub** and is automatically deployed via a **CI/CD pipeline** (AWS CodePipeline or GitHub Actions).  
Each update triggers automated tests and builds.  
Successful builds are deployed directly into the AWS environment.  
This ensures fast iterations and secure releases.

---

## Amplify (Domain Hosting)
**AWS Amplify** hosts the frontend web application and connects it to a domain.  
It provides automated builds, HTTPS security, and versioning through GitHub integration.  
Amplify ensures that the web-app is always up-to-date with the latest backend capabilities.  
It is the central interface for customers to review risks and reports.

---

## AWS Cognito (User Database)
**Cognito** handles user authentication and authorization.  
Users log in via email or Single Sign-On (e.g., Google or Microsoft).  
Cognito generates secure JWT tokens for API verification.  
It ensures only authorized users can access their data.

---

## Front-end Web (Dashboard)
The **frontend web application** is built in React or Next.js and displays risk analysis and compliance statuses.  
It retrieves data via API Gateway and visualizes it through interactive charts.  
Customers can start scans, filter results, and export reports.  
The frontend communicates exclusively over secure HTTPS connections.

---

## Amazon CloudWatch (Monitoring & Debugging)
**CloudWatch** collects logs, metrics, and alerts from all AWS components.  
It helps monitor performance, debug issues, and maintain uptime.  
Automatic alerts notify of problems or failed scans immediately.  
It is essential for stability, troubleshooting, and incident response.
