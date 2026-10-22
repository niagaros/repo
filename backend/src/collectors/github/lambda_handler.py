"""
CIS GitHub Benchmark v1.0.0 Scanner Lambda

Scans a customer's GitHub organization against the CIS GitHub Benchmark v1.0.0
(automated checks only). Stores results in the same resources/findings tables
used by all other CSPM scanners.

Event payload (passed by orchestrator):
    cloud_account_id: str   UUID of cloud_accounts row
    role_arn / external_id / region are accepted but ignored.

Prerequisites:
    - A row in github_integrations (cloud_account_id, org_name, github_token_secret)
    - github_token_secret: Secrets Manager secret name whose SecretString is either
      plain-text PAT or {"github_token": "<pat>"}
    - PAT minimum scopes: repo, read:org. Some checks need an organisation owner (2FA lists, member privilege
      settings) or repository admin (branch protection, Dependabot, secret scanning). When the token cannot read
      what a check needs, that check is recorded as NOT CHECKED with the reason; it is never turned into a PASS
      or FAIL from missing data.

Environment variables:
    DB_SECRET_NAME   (default: cspm/database/credentials)
"""

import json
import logging
import os
import datetime
from typing import Any, Dict, List, Optional, Tuple

import boto3
import psycopg2
import requests

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

FRAMEWORK = "CIS GitHub Benchmark v1.0.0"
GITHUB_API = "https://api.github.com"


# ── DB helpers ────────────────────────────────────────────────────────────────

def _get_db_creds() -> dict:
    secret_name = os.environ.get("DB_SECRET_NAME", "cspm/database/credentials")
    sm = boto3.client("secretsmanager", region_name="eu-west-1")
    return json.loads(sm.get_secret_value(SecretId=secret_name)["SecretString"])


def _get_db_conn():
    c = _get_db_creds()
    return psycopg2.connect(
        host=c["host"], port=c.get("port", 5432),
        dbname=c["database"], user=c["username"], password=c["password"],
        sslmode="require", connect_timeout=10,
    )


def _get_github_integration(conn, cloud_account_id: str) -> Optional[Dict]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT org_name, github_token_secret "
            "FROM github_integrations WHERE cloud_account_id = %s",
            (cloud_account_id,),
        )
        row = cur.fetchone()
    return {"org_name": row[0], "github_token_secret": row[1]} if row else None


def _get_github_token(secret_name: str) -> str:
    sm = boto3.client("secretsmanager", region_name="eu-west-1")
    raw = sm.get_secret_value(SecretId=secret_name)["SecretString"]
    try:
        return json.loads(raw)["github_token"]
    except (json.JSONDecodeError, KeyError):
        return raw.strip()


# ── GitHub API client ─────────────────────────────────────────────────────────

class GitHubClient:
    def __init__(self, token: str, org: str):
        self.org = org
        self.s = requests.Session()
        self.s.headers.update({
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })

    def _fetch(self, path: str, accept: str = None, **kw) -> Tuple[int, Optional[Any]]:
        """(HTTP status, JSON body or None). Status 0 = the request itself failed."""
        h = {"Accept": accept} if accept else {}
        try:
            r = self.s.get(f"{GITHUB_API}{path}", headers=h, timeout=30, **kw)
            body = None
            if r.status_code == 200 and r.content:
                try:
                    body = r.json()
                except ValueError:
                    body = None
            return r.status_code, body
        except Exception as e:
            logger.warning("GitHub GET %s: %s", path, e)
            return 0, None

    def _pages_checked(self, path: str, extra_params: dict = None) -> Tuple[List[Any], bool]:
        """All pages, and whether every page was actually readable (a refused or failed page is not 'empty')."""
        items, page = [], 1
        while True:
            params = {"per_page": 100, "page": page, **(extra_params or {})}
            status, chunk = self._fetch(path, params=params)
            if status != 200 or not isinstance(chunk, list):
                return items, False
            items.extend(chunk)
            if len(chunk) < 100:
                return items, True
            page += 1

    def _get(self, path: str, accept: str = None, **kw) -> Optional[Any]:
        h = {"Accept": accept} if accept else {}
        try:
            r = self.s.get(f"{GITHUB_API}{path}", headers=h, timeout=30, **kw)
            if r.status_code in (401, 403, 404):
                return None
            r.raise_for_status()
            return r.json() if r.content else {}
        except Exception as e:
            logger.warning("GitHub GET %s: %s", path, e)
            return None

    def _status(self, path: str, accept: str = None) -> int:
        h = {"Accept": accept} if accept else {}
        try:
            return self.s.get(f"{GITHUB_API}{path}", headers=h, timeout=30).status_code
        except Exception:
            return 0

    def _pages(self, path: str, extra_params: dict = None) -> List[Any]:
        items, page = [], 1
        while True:
            params = {"per_page": 100, "page": page, **(extra_params or {})}
            chunk = self._get(path, params=params)
            if not chunk:
                break
            items.extend(chunk)
            if len(chunk) < 100:
                break
            page += 1
        return items

    def collect_snapshot(self) -> Dict[str, Any]:
        logger.info("Collecting GitHub snapshot for org: %s", self.org)

        status, org_data = self._fetch(f"/orgs/{self.org}")
        if status != 200 or not isinstance(org_data, dict):
            raise RuntimeError(f"the organisation could not be read (HTTP {status})")
        unknown = []   # data this token could not read; checks that need it are NOT CHECKED
        for field in ORG_OWNER_FIELDS:
            if field not in org_data:          # GitHub only returns these to organisation owners
                unknown.append(field)
        repos, repos_ok = self._pages_checked(f"/orgs/{self.org}/repos")
        if not repos_ok:
            unknown.append("repositories")
        members_no_mfa, ok = self._pages_checked(f"/orgs/{self.org}/members", {"filter": "2fa_disabled"})
        if not ok:
            unknown.append("members_without_mfa")
        collabs_no_mfa, ok = self._pages_checked(f"/orgs/{self.org}/outside_collaborators", {"filter": "2fa_disabled"})
        if not ok:
            unknown.append("collaborators_without_mfa")

        repo_details = []
        for repo in repos:
            rname = repo["name"]
            default_branch = repo.get("default_branch", "main")
            is_admin = bool((repo.get("permissions") or {}).get("admin"))
            repo_unknown = []

            # Branch protection: 200 = rules, 404 = none — but only an admin gets a meaningful 404.
            st, bp = self._fetch(f"/repos/{self.org}/{rname}/branches/{default_branch}/protection")
            if st == 200 and isinstance(bp, dict):
                pass
            elif st == 404 and is_admin:
                bp = None
            else:
                bp = None
                repo_unknown.append("branch_protection")

            co = [self._status(f"/repos/{self.org}/{rname}/contents/{p}") for p in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS")]
            has_codeowners = True if 200 in co else (False if all(c == 404 for c in co) else None)
            if has_codeowners is None:
                repo_unknown.append("codeowners")

            has_security_md = None
            if not repo.get("private"):
                st = self._status(f"/repos/{self.org}/{rname}/contents/SECURITY.md")
                has_security_md = True if st == 200 else (False if st == 404 else None)
                if has_security_md is None:
                    repo_unknown.append("security_md")

            # Dependabot alerts: 204 = on, 404 = off, for admins; anything else is unknown.
            st = self._status(f"/repos/{self.org}/{rname}/vulnerability-alerts", accept="application/vnd.github+json")
            vuln_alerts = True if st == 204 else (False if st == 404 and is_admin else None)
            if vuln_alerts is None:
                repo_unknown.append("vulnerability_alerts")

            st, full_repo = self._fetch(f"/repos/{self.org}/{rname}")
            ss = ((full_repo or {}).get("security_and_analysis") or {}).get("secret_scanning")
            secret_scanning = (ss.get("status") == "enabled") if isinstance(ss, dict) and ss.get("status") else None
            if secret_scanning is None:
                repo_unknown.append("secret_scanning")   # only shown to repository admins

            repo_details.append({
                "name": rname,
                "full_name": repo.get("full_name"),
                "private": repo.get("private", False),
                "archived": repo.get("archived", False),
                "default_branch": default_branch,
                "branch_protection": bp,
                "has_codeowners": has_codeowners,
                "has_security_md": has_security_md,
                "vulnerability_alerts": vuln_alerts,
                "secret_scanning": secret_scanning,
                "is_admin": is_admin,
                "unknown": repo_unknown,
            })
            logger.info("Collected repo: %s (branch_protection=%s)", rname, bool(bp))

        return {
            "org_name": self.org,
            "collected_at": datetime.datetime.utcnow().isoformat() + "Z",
            "org": org_data,
            "repos": repo_details,
            "members_without_mfa": members_no_mfa,
            "collaborators_without_mfa": collabs_no_mfa,
            "unknown": unknown,
        }


ORG_OWNER_FIELDS = ("two_factor_requirement_enabled", "members_can_create_repositories",
                    "members_can_delete_repositories", "default_repository_permission")

# What each check needs; when any of it could not be read, the check is NOT CHECKED.
ORG_NEEDS = {"github_1.2.2": ["members_can_create_repositories"], "github_1.2.3": ["members_can_delete_repositories"],
             "github_1.3.4": ["collaborators_without_mfa"], "github_1.3.5": ["two_factor_requirement_enabled", "members_without_mfa"],
             "github_1.3.8": ["default_repository_permission"], "github_1.3.9": []}
BP_CHECKS = ("github_1.1.3", "github_1.1.4", "github_1.1.7", "github_1.1.9", "github_1.1.11", "github_1.1.12",
             "github_1.1.13", "github_1.1.14", "github_1.1.16", "github_1.1.17", "github_1.1.20")
REPO_NEEDS = {**{c: ["branch_protection"] for c in BP_CHECKS}, "github_1.1.6": ["codeowners"], "github_1.2.1": ["security_md"],
              "github_1.5.1": ["secret_scanning"], "github_1.5.5": ["vulnerability_alerts"]}
WHY = {"two_factor_requirement_enabled": "only organisation owners can see the 2FA requirement",
       "members_without_mfa": "only organisation owners can list members without 2FA",
       "collaborators_without_mfa": "only organisation owners can list outside collaborators",
       "members_can_create_repositories": "only organisation owners can see member privileges",
       "members_can_delete_repositories": "only organisation owners can see member privileges",
       "default_repository_permission": "only organisation owners can see the base permission",
       "branch_protection": "branch protection is only visible to repository admins",
       "codeowners": "the repository contents could not be read",
       "security_md": "the repository contents could not be read",
       "vulnerability_alerts": "the Dependabot setting is only visible to repository admins",
       "secret_scanning": "the secret-scanning setting is only visible to repository admins",
       "repositories": "the organisation's repositories could not be listed"}


def _not_checked(control_id: str, resource_id: str, missing: List[str]) -> Dict:
    return {"control_id": control_id, "resource_id": resource_id, "status": "NOT_CHECKED",
            "reason": "; ".join(sorted({WHY.get(m, m) for m in missing})), "missing": missing}


# ── CIS check helpers ─────────────────────────────────────────────────────────

def _find(control_id: str, title: str, status: str, severity: str,
          resource_id: str, resource_type: str, remediation: str,
          details: dict = None) -> Dict:
    return {
        "control_id": control_id,
        "title": title,
        "status": status,
        "severity": severity,
        "resource_id": resource_id,
        "resource_type": resource_type,
        "remediation": remediation,
        "details": details or {},
    }


def _bp(repo: Dict) -> Optional[Dict]:
    return repo.get("branch_protection")


def _rpr(repo: Dict) -> Optional[Dict]:
    bp = _bp(repo)
    return (bp or {}).get("required_pull_request_reviews")


# ── Section 1.1 – Branch Protection ──────────────────────────────────────────

def check_1_1_3(repo: Dict, org: str) -> Dict:
    rpr = _rpr(repo)
    count = (rpr or {}).get("required_approving_review_count", 0)
    return _find(
        "github_1.1.3",
        "Ensure at least 2 reviewers are required to review and approve pull requests",
        "PASS" if count >= 2 else "FAIL",
        "HIGH", f"{org}/{repo['name']}", "github_repository",
        "Set 'Required approving reviews' to 2 or more in branch protection rules.",
        {"required_approving_review_count": count},
    )


def check_1_1_4(repo: Dict, org: str) -> Dict:
    rpr = _rpr(repo)
    passed = bool((rpr or {}).get("dismiss_stale_reviews"))
    return _find(
        "github_1.1.4",
        "Ensure stale reviews are dismissed when new commits are pushed",
        "PASS" if passed else "FAIL",
        "MEDIUM", f"{org}/{repo['name']}", "github_repository",
        "Enable 'Dismiss stale pull request approvals when new commits are pushed'.",
        {"dismiss_stale_reviews": passed},
    )


def check_1_1_6(repo: Dict, org: str) -> Dict:
    passed = repo.get("has_codeowners", False)
    return _find(
        "github_1.1.6",
        "Ensure code owners are set for critical code repositories",
        "PASS" if passed else "FAIL",
        "MEDIUM", f"{org}/{repo['name']}", "github_repository",
        "Create a CODEOWNERS file in the root, .github/, or docs/ directory.",
        {"has_codeowners": passed},
    )


def check_1_1_7(repo: Dict, org: str) -> Dict:
    rpr = _rpr(repo)
    passed = bool((rpr or {}).get("require_code_owner_reviews"))
    return _find(
        "github_1.1.7",
        "Ensure code owner review is required when a CODEOWNERS file exists",
        "PASS" if passed else "FAIL",
        "HIGH", f"{org}/{repo['name']}", "github_repository",
        "Enable 'Require review from Code Owners' in branch protection settings.",
        {"require_code_owner_reviews": passed},
    )


def check_1_1_9(repo: Dict, org: str) -> Dict:
    bp = _bp(repo)
    rsc = (bp or {}).get("required_status_checks")
    checks_count = len((rsc or {}).get("contexts", []) + (rsc or {}).get("checks", []))
    passed = rsc is not None and checks_count > 0
    return _find(
        "github_1.1.9",
        "Ensure status checks are required to pass before merging pull requests",
        "PASS" if passed else "FAIL",
        "MEDIUM", f"{org}/{repo['name']}", "github_repository",
        "Configure required status checks under branch protection rules.",
        {"required_status_checks": bool(rsc), "checks_count": checks_count},
    )


def check_1_1_11(repo: Dict, org: str) -> Dict:
    bp = _bp(repo)
    passed = bool((bp or {}).get("required_conversation_resolution", {}).get("enabled"))
    return _find(
        "github_1.1.11",
        "Ensure all conversations on code changes are resolved before merging",
        "PASS" if passed else "FAIL",
        "LOW", f"{org}/{repo['name']}", "github_repository",
        "Enable 'Require conversation resolution before merging' in branch protection.",
        {"required_conversation_resolution": passed},
    )


def check_1_1_12(repo: Dict, org: str) -> Dict:
    bp = _bp(repo)
    passed = bool((bp or {}).get("required_signatures", {}).get("enabled"))
    return _find(
        "github_1.1.12",
        "Ensure commits are cryptographically signed on the default branch",
        "PASS" if passed else "FAIL",
        "LOW", f"{org}/{repo['name']}", "github_repository",
        "Enable 'Require signed commits' in branch protection settings.",
        {"required_signatures": passed},
    )


def check_1_1_13(repo: Dict, org: str) -> Dict:
    bp = _bp(repo)
    passed = bool((bp or {}).get("required_linear_history", {}).get("enabled"))
    return _find(
        "github_1.1.13",
        "Ensure linear history is required on the default branch",
        "PASS" if passed else "FAIL",
        "LOW", f"{org}/{repo['name']}", "github_repository",
        "Enable 'Require linear history' in branch protection settings.",
        {"required_linear_history": passed},
    )


def check_1_1_14(repo: Dict, org: str) -> Dict:
    bp = _bp(repo)
    passed = bool((bp or {}).get("enforce_admins", {}).get("enabled"))
    return _find(
        "github_1.1.14",
        "Ensure branch protection rules apply to administrators",
        "PASS" if passed else "FAIL",
        "HIGH", f"{org}/{repo['name']}", "github_repository",
        "Enable 'Include administrators' in branch protection settings.",
        {"enforce_admins": passed},
    )


def check_1_1_16(repo: Dict, org: str) -> Dict:
    bp = _bp(repo)
    force_push = (bp or {}).get("allow_force_pushes", {}).get("enabled", True)
    return _find(
        "github_1.1.16",
        "Ensure force pushes to the default branch are disallowed",
        "PASS" if not force_push else "FAIL",
        "HIGH", f"{org}/{repo['name']}", "github_repository",
        "Disable 'Allow force pushes' in branch protection settings.",
        {"allow_force_pushes": force_push},
    )


def check_1_1_17(repo: Dict, org: str) -> Dict:
    bp = _bp(repo)
    allow_del = (bp or {}).get("allow_deletions", {}).get("enabled", True)
    return _find(
        "github_1.1.17",
        "Ensure branch deletions on the default branch are denied",
        "PASS" if not allow_del else "FAIL",
        "HIGH", f"{org}/{repo['name']}", "github_repository",
        "Disable 'Allow deletions' in branch protection settings.",
        {"allow_deletions": allow_del},
    )


def check_1_1_20(repo: Dict, org: str) -> Dict:
    passed = _bp(repo) is not None
    return _find(
        "github_1.1.20",
        "Ensure default branch protection is enabled",
        "PASS" if passed else "FAIL",
        "CRITICAL", f"{org}/{repo['name']}", "github_repository",
        "Enable branch protection rules for the default branch in repository settings.",
        {"protection_enabled": passed},
    )


# ── Section 1.2 – Repository Management ──────────────────────────────────────

def check_1_2_1(repo: Dict, org: str) -> Dict:
    if repo.get("private"):
        return _find(
            "github_1.2.1",
            "Ensure security.md file is present in public repositories",
            "PASS", "MEDIUM", f"{org}/{repo['name']}", "github_repository",
            "Create a SECURITY.md file with a vulnerability disclosure policy.",
            {"skipped": "private repository"},
        )
    passed = bool(repo.get("has_security_md"))
    return _find(
        "github_1.2.1",
        "Ensure security.md file is present in public repositories",
        "PASS" if passed else "FAIL",
        "MEDIUM", f"{org}/{repo['name']}", "github_repository",
        "Create a SECURITY.md with a vulnerability disclosure policy in the repository root.",
        {"has_security_md": passed},
    )


def check_1_2_2(org_data: Dict, org: str) -> Dict:
    can_create = org_data.get("members_can_create_repositories", True)
    return _find(
        "github_1.2.2",
        "Ensure repository creation is limited to specific members",
        "PASS" if not can_create else "FAIL",
        "MEDIUM", org, "github_organization",
        "Restrict repository creation in organization Settings > Member privileges.",
        {"members_can_create_repositories": can_create},
    )


def check_1_2_3(org_data: Dict, org: str) -> Dict:
    can_delete = org_data.get("members_can_delete_repositories", True)
    return _find(
        "github_1.2.3",
        "Ensure repository deletion is limited to specific members",
        "PASS" if not can_delete else "FAIL",
        "MEDIUM", org, "github_organization",
        "Disable repository deletion for members in organization Settings > Member privileges.",
        {"members_can_delete_repositories": can_delete},
    )


# ── Section 1.3 – Identity and Access ────────────────────────────────────────

def check_1_3_4(snapshot: Dict, org: str) -> Dict:
    collabs = snapshot.get("collaborators_without_mfa", [])
    count = len(collabs)
    return _find(
        "github_1.3.4",
        "Ensure two-factor authentication is required for outside collaborators",
        "PASS" if count == 0 else "FAIL",
        "CRITICAL", org, "github_organization",
        "Require 2FA for all outside collaborators in organization Security settings.",
        {"collaborators_without_mfa": count, "logins": [c["login"] for c in collabs[:10]]},
    )


def check_1_3_5(snapshot: Dict, org: str) -> Dict:
    org_data = snapshot.get("org", {})
    two_fa = org_data.get("two_factor_requirement_enabled", False)
    members = snapshot.get("members_without_mfa", [])
    count = len(members)
    passed = two_fa and count == 0
    return _find(
        "github_1.3.5",
        "Ensure two-factor authentication is required for all organization members",
        "PASS" if passed else "FAIL",
        "CRITICAL", org, "github_organization",
        "Enable 'Require two-factor authentication' in organization Security settings.",
        {
            "two_factor_requirement_enabled": two_fa,
            "members_without_mfa_count": count,
            "members_without_mfa": [m["login"] for m in members[:10]],
        },
    )


def check_1_3_8(org_data: Dict, org: str) -> Dict:
    perm = org_data.get("default_repository_permission", "read")
    passed = perm in ("none", "read")
    return _find(
        "github_1.3.8",
        "Ensure minimum default repository permissions are set for organization members",
        "PASS" if passed else "FAIL",
        "MEDIUM", org, "github_organization",
        "Set base permissions to 'No permission' or 'Read' in organization Settings > Member privileges.",
        {"default_repository_permission": perm},
    )


def check_1_3_9(org_data: Dict, org: str) -> Dict:
    verified = org_data.get("is_verified", False)
    return _find(
        "github_1.3.9",
        "Ensure the organization has a verified domain or email",
        "PASS" if verified else "FAIL",
        "LOW", org, "github_organization",
        "Verify a domain or email address for the organization in Settings > Profile.",
        {"is_verified": verified},
    )


# ── Section 1.5 – Code Security ───────────────────────────────────────────────

def check_1_5_1(repo: Dict, org: str) -> Dict:
    passed = repo.get("secret_scanning", False)
    return _find(
        "github_1.5.1",
        "Ensure secret scanning is enabled for all repositories",
        "PASS" if passed else "FAIL",
        "CRITICAL", f"{org}/{repo['name']}", "github_repository",
        "Enable secret scanning in repository Settings > Security & analysis.",
        {"secret_scanning_enabled": passed},
    )


def check_1_5_5(repo: Dict, org: str) -> Dict:
    passed = repo.get("vulnerability_alerts", False)
    return _find(
        "github_1.5.5",
        "Ensure vulnerability alerts are enabled for all repositories",
        "PASS" if passed else "FAIL",
        "HIGH", f"{org}/{repo['name']}", "github_repository",
        "Enable Dependabot alerts in repository Settings > Security & analysis.",
        {"vulnerability_alerts_enabled": passed},
    )


# ── Run all checks ────────────────────────────────────────────────────────────

ORG_CHECKS = (("github_1.2.2", lambda s, o: check_1_2_2(s["org"], o)), ("github_1.2.3", lambda s, o: check_1_2_3(s["org"], o)),
              ("github_1.3.4", check_1_3_4), ("github_1.3.5", check_1_3_5),
              ("github_1.3.8", lambda s, o: check_1_3_8(s["org"], o)), ("github_1.3.9", lambda s, o: check_1_3_9(s["org"], o)))
REPO_CHECKS = (("github_1.1.3", check_1_1_3), ("github_1.1.4", check_1_1_4), ("github_1.1.6", check_1_1_6),
               ("github_1.1.7", check_1_1_7), ("github_1.1.9", check_1_1_9), ("github_1.1.11", check_1_1_11),
               ("github_1.1.12", check_1_1_12), ("github_1.1.13", check_1_1_13), ("github_1.1.14", check_1_1_14),
               ("github_1.1.16", check_1_1_16), ("github_1.1.17", check_1_1_17), ("github_1.1.20", check_1_1_20),
               ("github_1.2.1", check_1_2_1), ("github_1.5.1", check_1_5_1), ("github_1.5.5", check_1_5_5))


def run_checks(snapshot: Dict) -> Tuple[List[Dict], List[Dict]]:
    """(findings, not_checked). A check whose input could not be read is never scored."""
    org = snapshot["org_name"]
    unknown = set(snapshot.get("unknown") or [])
    findings, not_checked = [], []
    for cid, fn in ORG_CHECKS:
        missing = [k for k in ORG_NEEDS[cid] if k in unknown]
        if cid == "github_1.3.9" and "is_verified" not in (snapshot.get("org") or {}):
            missing = ["is_verified"]
        if missing:
            not_checked.append(_not_checked(cid, org, missing))
        else:
            findings.append(fn(snapshot, org))
    for repo in snapshot.get("repos", []):
        r_unknown = set(repo.get("unknown") or [])
        for cid, fn in REPO_CHECKS:
            if cid == "github_1.2.1" and repo.get("private"):
                continue                       # SECURITY.md applies to public repositories only
            missing = [k for k in REPO_NEEDS[cid] if k in r_unknown]
            if missing:
                not_checked.append(_not_checked(cid, f"{org}/{repo['name']}", missing))
            else:
                findings.append(fn(repo, org))
    if "repositories" in unknown:
        not_checked.append(_not_checked("github_1.1.*", org, ["repositories"]))
    return findings, not_checked


# ── DB writer ─────────────────────────────────────────────────────────────────

def save_results(conn, findings: List[Dict], snapshot: Dict,
                 cloud_account_id: str, not_checked: Optional[List[Dict]] = None) -> Dict[str, int]:
    org = snapshot["org_name"]

    # Collect unique resources referenced by findings
    unique_resources: Dict[str, str] = {org: "github_organization"}
    for f in findings:
        unique_resources[f["resource_id"]] = f["resource_type"]
    for repo in snapshot.get("repos", []):
        unique_resources.setdefault(f"{org}/{repo['name']}", "github_repository")
    for n in not_checked or []:
        unique_resources.setdefault(n["resource_id"], "github_repository" if "/" in n["resource_id"] else "github_organization")
    org_config = json.dumps({"not_checked": not_checked or [], "collected_at": snapshot.get("collected_at"),
                             "note": "Checks listed here were not scored because the connected token could not read their data."})

    resource_id_map: Dict[str, str] = {}
    resources_upserted = 0
    findings_upserted = 0

    with conn.cursor() as cur:
        for rid, rtype in unique_resources.items():
            name = rid.split("/")[-1] if "/" in rid else rid
            cur.execute(
                """
                INSERT INTO resources
                    (cloud_account_id, resource_type, resource_id,
                     resource_name, region, config, last_scanned_at)
                VALUES (%s, %s, %s, %s, 'global', %s, NOW())
                ON CONFLICT (cloud_account_id, resource_id)
                DO UPDATE SET
                    resource_name   = EXCLUDED.resource_name,
                    config          = CASE WHEN %s THEN EXCLUDED.config ELSE resources.config END,
                    last_scanned_at = NOW()
                RETURNING id
                """,
                (cloud_account_id, rtype, rid, name, org_config if rid == org else "{}", rid == org),
            )
            resource_id_map[rid] = str(cur.fetchone()[0])
            resources_upserted += 1

        for f in findings:
            resource_uuid = resource_id_map.get(f["resource_id"])
            if not resource_uuid:
                continue

            cur.execute(
                """
                INSERT INTO findings
                    (resource_id, check_id, title, description,
                     severity, status, result, framework, remediation, details, detected_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                ON CONFLICT (resource_id, check_id)
                DO UPDATE SET
                    title       = EXCLUDED.title,
                    description = EXCLUDED.description,
                    severity    = EXCLUDED.severity,
                    status      = EXCLUDED.status,
                    result      = EXCLUDED.result,
                    framework   = EXCLUDED.framework,
                    remediation = EXCLUDED.remediation,
                    details     = EXCLUDED.details,
                    detected_at = NOW()
                """,
                (
                    resource_uuid,
                    f["control_id"],
                    f["title"],
                    f["title"],
                    f["severity"].upper(),
                    "pass" if f["status"] == "PASS" else "open",
                    f["status"],
                    FRAMEWORK,
                    f.get("remediation", ""),
                    json.dumps(f.get("details", {}), default=str),
                ),
            )
            findings_upserted += 1

        # A check that could not be read this time keeps its last known result, marked as not re-checked; its
        # detected_at is not refreshed, so the dashboard shows it as stale. Deleting it would make reports call it
        # resolved. SECURITY.md does not apply to private repositories at all: an old result for one is removed.
        removed = 0
        for n in not_checked or []:
            rid = resource_id_map.get(n["resource_id"])
            if rid and not n["control_id"].endswith("*"):
                cur.execute("""UPDATE findings SET details = COALESCE(details, '{}'::jsonb) || %s::jsonb
                               WHERE resource_id = %s AND check_id = %s AND framework = %s""",
                            (json.dumps({"not_rechecked": n["reason"], "not_rechecked_at": snapshot.get("collected_at")}),
                             rid, n["control_id"], FRAMEWORK))
                removed += cur.rowcount
        for repo in snapshot.get("repos", []):
            if repo.get("private") and f"{org}/{repo['name']}" in resource_id_map:
                cur.execute("DELETE FROM findings WHERE resource_id = %s AND check_id = 'github_1.2.1' AND framework = %s",
                            (resource_id_map[f"{org}/{repo['name']}"], FRAMEWORK))

        total = len(findings)
        passed = sum(1 for f in findings if f["status"] == "PASS")
        score = round((passed / total) * 100) if total else 0

        cur.execute(
            "UPDATE cloud_accounts SET last_scan_at = NOW() WHERE id = %s",
            (cloud_account_id,),
        )

    conn.commit()
    logger.info(
        "DB write complete: resources=%d findings=%d score=%d%%",
        resources_upserted, findings_upserted, score,
    )
    return {"resources_upserted": resources_upserted,
            "findings_upserted": findings_upserted, "score": score, "results_marked_not_rechecked": removed}


# ── Lambda entry point ────────────────────────────────────────────────────────

def lambda_handler(event, context):
    cloud_account_id = event.get("cloud_account_id") or os.environ.get("CLOUD_ACCOUNT_ID", "")
    if not cloud_account_id:
        return {"statusCode": 400, "body": json.dumps({"error": "cloud_account_id required"})}

    conn = None
    try:
        conn = _get_db_conn()
        integration = _get_github_integration(conn, cloud_account_id)
        if not integration:
            logger.info(
                "No GitHub integration for cloud_account_id=%s — skipping",
                cloud_account_id,
            )
            return {"statusCode": 200,
                    "body": json.dumps({"skipped": True, "reason": "no_github_integration"})}

        org_name = integration["org_name"]
        token = _get_github_token(integration["github_token_secret"])

        logger.info("Starting CIS GitHub scan for org=%s", org_name)
        snapshot = GitHubClient(token, org_name).collect_snapshot()
        findings, not_checked = run_checks(snapshot)

        total = len(findings)
        passed = sum(1 for f in findings if f["status"] == "PASS")
        failed = total - passed
        logger.info("Scan complete: total=%d passed=%d failed=%d not_checked=%d", total, passed, failed, len(not_checked))

        db_stats = save_results(conn, findings, snapshot, cloud_account_id, not_checked)

        return {
            "statusCode": 200,
            "body": {
                "org": org_name,
                "collected_at": snapshot["collected_at"],
                "summary": {"total": total, "passed": passed, "failed": failed, "not_checked": len(not_checked)},
                "not_checked": not_checked,
                "db": db_stats,
            },
        }

    except Exception as e:
        logger.error("GitHub scanner fatal error: %s", e, exc_info=True)
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
    finally:
        if conn:
            conn.close()
