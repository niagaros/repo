```text
===================================================================
CODEOWNERS
Niagaros
===================================================================
Docs: https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners
Rules:
- Order matters: last matching rule wins
- Owners must be GitHub users or teams (@niagaros/team)
- Security-first ownership model
===================================================================
-------------------------------------------------------------------
Global default (everything not explicitly owned below)
-------------------------------------------------------------------
@niagaros/platform-core @niagaros/security-core
-------------------------------------------------------------------
GitHub & CI/CD
-------------------------------------------------------------------
.github/ @niagaros/platform-core @niagaros/security-core
.github/workflows/ @niagaros/platform-core @niagaros/security-core
.github/actions/ @niagaros/platform-core

CODEOWNERS @niagaros/platform-core @niagaros/security-core

-------------------------------------------------------------------
Infrastructure as Code (High risk)
-------------------------------------------------------------------
infra/ @niagaros/cloud-platform @niagaros/security-core
terraform/ @niagaros/cloud-platform @niagaros/security-core
pulumi/ @niagaros/cloud-platform @niagaros/security-core
k8s/ @niagaros/cloud-platform @niagaros/security-core
helm/ @niagaros/cloud-platform

docker/ @niagaros/cloud-platform
Dockerfile @niagaros/cloud-platform

-------------------------------------------------------------------
Advanced Networking (explicit control plane)
-------------------------------------------------------------------
network/ @niagaros/network-platform @niagaros/security-core

-------------------------------------------------------------------
Backend services
-------------------------------------------------------------------
services/ @niagaros/backend-core
services/api/ @niagaros/backend-api
services/auth/ @niagaros/identity @niagaros/security-core
services/policy-engine/ @niagaros/security-research @niagaros/security-core
services/graph/ @niagaros/security-graph
services/ingestion/ @niagaros/data-platform
services/notifications/ @niagaros/backend-core

-------------------------------------------------------------------
Identity, auth & security-critical code paths (always reviewed by security)
-------------------------------------------------------------------
/auth/ @niagaros/identity @niagaros/security-core
/crypto/ @niagaros/security-core
/encryption/ @niagaros/security-core
/iam/ @niagaros/identity @niagaros/security-core
/rbac/ @niagaros/identity @niagaros/security-core

-------------------------------------------------------------------
Cloud provider integrations
-------------------------------------------------------------------
integrations/aws/ @niagaros/cloud-aws @niagaros/security-core
integrations/azure/ @niagaros/cloud-azure @niagaros/security-core
integrations/gcp/ @niagaros/cloud-gcp @niagaros/security-core
integrations/kubernetes/ @niagaros/cloud-platform

-------------------------------------------------------------------
Frontend & UX
-------------------------------------------------------------------
frontend/ @niagaros/frontend-core
frontend/dashboard/ @niagaros/frontend-dashboard
frontend/auth/ @niagaros/frontend-core @niagaros/identity
ui/ @niagaros/design-system

*.css @niagaros/frontend-core
*.scss @niagaros/frontend-core
*.tsx @niagaros/frontend-core

-------------------------------------------------------------------
Data, analytics & ML
-------------------------------------------------------------------
data/ @niagaros/data-platform
analytics/ @niagaros/data-platform
ml/ @niagaros/ml-platform
pipelines/ @niagaros/data-platform

-------------------------------------------------------------------
Compliance, policies, audit & risk
-------------------------------------------------------------------
compliance/ @niagaros/security-core @niagaros/compliance
audit/ @niagaros/security-core @niagaros/compliance
risk/ @niagaros/security-core @niagaros/compliance
policies/ @niagaros/security-core @niagaros/security-research
benchmarks/ @niagaros/security-core @niagaros/security-research

soc/ @niagaros/security-core @niagaros/security-research
cis/ @niagaros/security-core @niagaros/security-research
nist/ @niagaros/security-core @niagaros/security-research
iso27001/ @niagaros/security-core @niagaros/compliance

-------------------------------------------------------------------
Documentation & public content
-------------------------------------------------------------------
docs/ @niagaros/platform-core @niagaros/docs
README.md @niagaros/platform-core @niagaros/docs
CHANGELOG.md @niagaros/platform-core

website/ @niagaros/marketing
blog/ @niagaros/marketing

-------------------------------------------------------------------
SDKs & APIs
-------------------------------------------------------------------
sdk/ @niagaros/sdk
sdk/python/ @niagaros/sdk
sdk/go/ @niagaros/sdk
sdk/typescript/ @niagaros/sdk

openapi.yaml @niagaros/backend-api

-------------------------------------------------------------------
Tests & quality
-------------------------------------------------------------------
tests/ @niagaros/quality
e2e/ @niagaros/quality
security-tests/ @niagaros/security-core

-------------------------------------------------------------------
Experimental Labs / research
-------------------------------------------------------------------
labs/ @niagaros/security-core @niagaros/security-research
prototypes/ @niagaros/platform-core

-------------------------------------------------------------------
Secrets & sensitive files (locked down)
-------------------------------------------------------------------
/credentials/ @niagaros/security-core
/keys/ @niagaros/security-core
/secrets/ @niagaros/security-core
/certs/ @niagaros/security-core

**/.pem @niagaros/security-core
**/.key @niagaros/security-core
**/.crt @niagaros/security-core
**/.p12 @niagaros/security-core
**/.pfx @niagaros/security-core
**/.secrets.* @niagaros/security-core
