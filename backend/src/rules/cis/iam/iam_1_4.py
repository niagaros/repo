def check(resources):
    account_resources = [r for r in resources if r.get("resource_type") == "iam-account"]

    if not account_resources:
        return {
            "check": "IAM 1.4",
            "status": "FAIL",
            "reason": "No iam-account resource found"
        }

    account = account_resources[0]
    root_mfa_enabled = account.get("config", {}).get("root_mfa_enabled")

    if root_mfa_enabled is True:
        return {
            "check": "IAM 1.4",
            "status": "PASS",
            "reason": "Root MFA is enabled"
        }

    return {
        "check": "IAM 1.4",
        "status": "FAIL",
        "reason": "Root MFA is not enabled"
    }