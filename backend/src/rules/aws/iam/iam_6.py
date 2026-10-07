def check(resources):
    account = next((r for r in resources if r.get("resource_type") == "iam-account"), None)

    if not account:
        return {
            "check": "IAM.6",
            "status": "FAIL",
            "severity": "CRITICAL",
            "title": "IAM account not found",
            "reason": "No iam-account resource found.",
            "remediation": "Ensure the IAM collector is running correctly."
        }

    if account.get("config", {}).get("root_hardware_mfa_enabled"):
        return {
            "check": "IAM.6",
            "status": "PASS",
            "severity": "CRITICAL",
            "title": "Root account has hardware MFA enabled",
            "reason": "Hardware MFA is enabled on the root account.",
            "remediation": None
        }

    return {
        "check": "IAM.6",
        "status": "FAIL",
        "severity": "CRITICAL",
        "title": "Root account is missing hardware MFA",
        "reason": "Root account does not have hardware MFA enabled.",
        "remediation": "Enable hardware MFA via root login → My Security Credentials → MFA → Activate MFA → Hardware MFA device."
    }