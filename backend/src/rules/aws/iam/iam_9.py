def check(resources):
    account = next((r for r in resources if r.get("resource_type") == "iam-account"), None)

    if not account:
        return {
            "check": "IAM.9",
            "status": "FAIL",
            "severity": "CRITICAL",
            "title": "IAM account not found",
            "reason": "No iam-account resource found.",
            "remediation": "Ensure the IAM collector is running correctly."
        }

    if account.get("config", {}).get("root_mfa_enabled"):
        return {
            "check": "IAM.9",
            "status": "PASS",
            "severity": "CRITICAL",
            "title": "Root account has MFA enabled",
            "reason": "MFA is enabled on the root account.",
            "remediation": None
        }

    return {
        "check": "IAM.9",
        "status": "FAIL",
        "severity": "CRITICAL",
        "title": "Root account has no MFA",
        "reason": "MFA is not enabled on the root account.",
        "remediation": "Enable MFA via root login → My Security Credentials → MFA → Activate MFA."
    }