def check(resources):
    account = next((r for r in resources if r.get("resource_type") == "iam-account"), None)

    if not account:
        return {
            "check": "IAM.16",
            "status": "FAIL",
            "severity": "LOW",
            "title": "IAM account not found",
            "reason": "No iam-account resource found.",
            "remediation": "Ensure the IAM collector is running correctly."
        }

    policy = account.get("config", {}).get("password_policy")
    if not policy:
        return {
            "check": "IAM.16",
            "status": "FAIL",
            "severity": "LOW",
            "title": "No password policy configured",
            "reason": "No password policy found.",
            "remediation": "Set a password policy via IAM → Account settings → Set password policy."
        }

    reuse = policy.get("PasswordReusePrevention", 0)
    if reuse >= 24:
        return {
            "check": "IAM.16",
            "status": "PASS",
            "severity": "LOW",
            "title": "Password reuse is restricted",
            "reason": f"Password reuse prevention is set to {reuse}.",
            "remediation": None
        }

    return {
        "check": "IAM.16",
        "status": "FAIL",
        "severity": "LOW",
        "title": "Password reuse is not restricted enough",
        "reason": f"Password reuse prevention is {reuse}, minimum 24 required.",
        "remediation": "Set a password policy via IAM → Account settings → Set password policy."
    }