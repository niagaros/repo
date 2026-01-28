# 📅 Niagaros CSPM Prototype — 20-Week Project Plan

This document outlines the high-level planning for developing the Niagaros Cloud Security Posture Management (CSPM) MVP.  
The project is structured into broad phases to allow flexibility while maintaining clear deliverables.

---

## Phase 1 — Onboarding & Environment Understanding (Weeks 1–2)

**Goal:** Establish project foundation and understand the Niagaros environment.

### Activities
- Kickoff with Niagaros stakeholders  
- Review existing AWS accounts and structure  
- Set up private GitHub repository  
- Document initial scope and constraints  
- Create base documentation layout  

### Deliverables
- Confirmed scope  
- Project structure in GitHub  
- Initial environment overview  

---

## Phase 2 — AWS Environment Research & Security Analysis (Weeks 3–7)

**Goal:** Build a thorough understanding of Niagaros’ AWS configuration and required CSPM functionality.

### Activities

### 2.1 Environment Inventory
- Map all relevant AWS services (S3, IAM, CloudWatch, AWS Config, etc.)  
- Document S3 usage and potential misconfiguration risks  
- Analyze IAM roles and permissions needed for scanning  

### 2.2 Security Standards Research
- Study CSPM industry leaders (Wiz, Lacework, Orca)  
- Review AWS Well-Architected & CIS Benchmark controls  
- Identify which S3 misconfiguration types the MVP must detect  

### 2.3 Requirement Definition
- Draft functional requirements specific to Niagaros  
- Define technical requirements (SDK usage, region approach, permissions)  
- Create draft risk scoring model for S3 findings  

### Deliverables
- Full AWS environment inventory  
- Niagaros CSPM requirements  
- Initial list of S3 misconfiguration checks  

---

## Phase 3 — CSPM Prototype Design (Weeks 8–10)

**Goal:** Create the high-level design of the scanning MVP.

### Activities

### 3.1 Architecture Design
- Define the scanning workflow (trigger → analyze → classify → output)  
- Determine region approach (Ireland recommended; Frankfurt optional; London for DR)  
- Document integration points with Niagaros systems  

### 3.2 Rule & Detection Logic Design
- Define detection logic for each S3 misconfiguration  
- Map misconfigurations to severity levels  
- Specify IAM permission validation rules  

### 3.3 Output & Data Model Design
- Define JSON output format  
- Describe data model for findings  
- Determine how results will be consumed or exported  

### Deliverables
- Architecture document  
- Detection rule definitions  
- Output/data model specification  

---

## Phase 4 — CSPM MVP Implementation (Weeks 11–15)

**Goal:** Build the first working version of the Niagaros scanning engine.

### Activities

### 4.1 Core Scanning Engine
- Implement AWS authentication flow  
- Build scanning structure and rule dispatcher  
- Implement core S3 checks  
  - Public access  
  - Bucket policy analysis  
  - Encryption (SSE-S3 / SSE-KMS)  
  - Versioning  
  - Logging  

### 4.2 Risk Scoring Engine
- Implement severity calculations based on defined model  
- Link metadata (ACLs, block public access settings, policies)  
- Normalize findings  

### 4.3 Output Layer
- Produce JSON results  
- Add structured logging  
- Implement error handling and edge-case handling  

### Deliverables
- Functioning CSPM MVP  
- Initial S3 rule set  
- Consistent output structure  

---

## Phase 5 — Testing & Validation (Weeks 16–18)

**Goal:** Validate the scanner using the real Niagaros AWS environment.

### Activities
- Test against actual production and development buckets  
- Create intentional misconfigurations for validation  
- Tune rule logic to reduce false positives  
- Validate scoring accuracy with Niagaros stakeholders  
- Perform security and performance checks  

### Deliverables
- Verified rule set  
- Test results document  
- Updated scoring model  

---

## Phase 6 — Finalization & Handover (Weeks 19–20)

**Goal:** Deliver polished CSPM MVP, documentation, and handoff materials.

### Activities
- Finalize full documentation package (architecture, usage, rules, outputs)  
- Document installation and setup instructions  
- Clean and refactor the codebase  
- Internal demo/presentation to Niagaros  
- Prepare future improvement recommendations  

### Deliverables
- Final CSPM MVP  
- Documentation bundle  
- Handover presentation/demo  

---

## Summary

| Phase | Weeks | Focus |
|-------|-------|--------|
| 1 | 1–2 | Onboarding & Scope |
| 2 | 3–7 | Research & Requirements |
| 3 | 8–10 | Design |
| 4 | 11–15 | Implementation |
| 5 | 16–18 | Testing & Validation |
| 6 | 19–20 | Finalization & Handover |

---