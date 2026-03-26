def check(resources):

    account = None

    for resource in resources:
        if resource.get("resource_type") == "iam-account":
            account = resource
            break

    if not account:
        return {
            "check": "IAM 1.8",
            "status": "FAIL",
            "reason": "No IAM account resource found"
        }

    password_policy = account.get("config", {}).get("password_policy")

    if not password_policy:
        return {
            "check": "IAM 1.8",
            "status": "FAIL",
            "reason": "No password policy configured"
        }

    reuse_prevention = password_policy.get("PasswordReusePrevention")

    if reuse_prevention is None:
        return {
            "check": "IAM 1.8",
            "status": "FAIL",
            "reason": "Password reuse prevention is not configured"
        }

    if reuse_prevention >= 24:
        return {
            "check": "IAM 1.8",
            "status": "PASS",
            "reason": f"Password reuse prevention is set to {reuse_prevention}"
        }

    return {
        "check": "IAM 1.8",
        "status": "FAIL",
        "reason": f"Password reuse prevention too low ({reuse_prevention}), expected at least 24"
    }