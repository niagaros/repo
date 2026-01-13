# GitHub Security Features: Dependabot & Secret Scanning

This documentation provides an overview of the github security implementations

---

# 📦 Dependabot

GitHub **Dependabot** helps keep your dependencies secure and up to date. It automatically scans your repository for outdated or vulnerable dependencies and creates pull requests to update them.

---

## 1. Dependabot Alerts

Dependabot Alerts notify you when vulnerabilities are detected in your project's dependencies.

### **How It Works**
- GitHub continuously scans dependency manifests such as:
  - `package.json`
  - `requirements.txt`
  - `pom.xml`
  - `go.mod`
- If a vulnerability is identified, an alert is created in:
  - **Security → Dependabot Alerts**

Each alert includes:
- Vulnerability severity
- Affected package and version
- CVE link or advisory
- Recommended fix version

### **Best Practices**
- Prioritize high and critical severity alerts.
- Enable automatic updates for minor changes.
- Review alerts weekly.

---

## 2. Dependabot Security Updates

Dependabot can automatically open pull requests to fix vulnerable dependencies.

### **Enabling Security Updates**
Public repos: Enabled by default  
Private repos:
1. Go to **Settings → Code security and analysis**
2. Enable:
   - ✔ Dependabot alerts  
   - ✔ Dependabot security updates  

Dependabot will submit PRs with:
- The updated version
- Links to the CVE/advisory
- Impact description

---

## 3. Dependabot Version Updates

Dependabot can also keep your dependencies fresh, reducing technical debt.


# GitHub Secret Scanning

GitHub **Secret Scanning** helps you detect and prevent the accidental exposure of sensitive credentials in your repositories. This documentation covers how it works, how to enable it, and best practices for managing secrets securely.

---

## What is Secret Scanning?

Secret scanning automatically scans your repository for patterns that match sensitive information, such as:

- API keys  
- OAuth tokens  
- Cloud credentials (AWS, GCP, Azure)  
- Database connection strings  
- Private keys  

When a secret is detected, GitHub generates a **security alert** to notify repository administrators or security teams.

---

## How Secret Scanning Works

1. GitHub scans commits and pull requests for sensitive data patterns.  
2. Alerts are triggered when a match is found.  
3. Alerts include:
   - The type of secret detected
   - The file and commit location
   - Remediation guidance  

Optional: **Push Protection** can prevent secrets from being pushed to protected branches.

---

## Enabling Secret Scanning

### For Public Repositories
- Secret scanning is enabled by default.

### For Private Repositories
1. Navigate to **Settings → Code security and analysis**.  
2. Enable:
   - ✔ Secret scanning  
   - ✔ Secret scanning push protection (optional, recommended)

> Push protection blocks commits containing secrets before they reach the repository.

---

## Responding to Secret Scanning Alerts

When an alert is triggered:

1. **Revoke** the compromised secret immediately.  
2. **Remove** the secret from your code and commit history:
   ```bash
   git filter-repo --path filename --invert-paths