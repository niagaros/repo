def check(resources):
    account = next((r for r in resources if r.get("resource_type") == "iam-account"), None)

    if not account:
        return {
            "check": "IAM.15",
            "status": "FAIL",
            "severity": "MEDIUM",
            "title": "IAM account not found",
            "reason": "No iam-account resource found.",
            "remediation": "Ensure the IAM collector is running correctly."
        }

    policy = account.get("config", {}).get("password_policy")
    if not policy:
        return {
            "check": "IAM.15",
            "status": "FAIL",
            "severity": "MEDIUM",
            "title": "No password policy configured",
            "reason": "No password policy found.",
            "remediation": "Set a password policy via IAM → Account settings → Set password policy."
        }

    min_length = policy.get("MinimumPasswordLength", 0)
    if min_length >= 14:
        return {
            "check": "IAM.15",
            "status": "PASS",
            "severity": "MEDIUM",
            "title": "Password length meets requirement",
            "reason": f"Minimum password length is {min_length}.",
            "remediation": None
        }

    return {
        "check": "IAM.15",
        "status": "FAIL",
        "severity": "MEDIUM",
        "title": "Password length is too short",
        "reason": f"Minimum password length is {min_length}, minimum 14 required.",
        "remediation": "Set a password policy via IAM → Account settings → Set password policy."
    }