def check(resources):
    account = next((r for r in resources if r.get("resource_type") == "iam-account"), None)

    if not account:
        return {
            "check": "IAM.4",
            "status": "FAIL",
            "severity": "CRITICAL",
            "title": "IAM account not found",
            "reason": "No iam-account resource found.",
            "remediation": "Ensure the IAM collector is running correctly."
        }

    if account.get("config", {}).get("root_access_keys_present"):
        return {
            "check": "IAM.4",
            "status": "FAIL",
            "severity": "CRITICAL",
            "title": "Root account has active access keys",
            "reason": "Root account has active access keys.",
            "remediation": "Remove root access keys via My Security Credentials → Access keys → Delete. Use IAM users for programmatic access."
        }

    return {
        "check": "IAM.4",
        "status": "PASS",
        "severity": "CRITICAL",
        "title": "Root account has no access keys",
        "reason": "No active root access keys were found.",
        "remediation": None
    }