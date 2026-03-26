def check(resources):

    account = None

    for resource in resources:
        if resource.get("resource_type") == "iam-account":
            account = resource
            break

    if not account:
        return {
            "check": "IAM 1.9",
            "status": "FAIL",
            "reason": "No IAM account resource found"
        }

    password_policy = account.get("config", {}).get("password_policy")

    if not password_policy:
        return {
            "check": "IAM 1.9",
            "status": "FAIL",
            "reason": "No password policy configured"
        }

    max_age = password_policy.get("MaxPasswordAge")

    if max_age is None:
        return {
            "check": "IAM 1.9",
            "status": "FAIL",
            "reason": "Password expiration is not configured"
        }

    if max_age <= 90:
        return {
            "check": "IAM 1.9",
            "status": "PASS",
            "reason": f"Password expiration is set to {max_age} days"
        }

    return {
        "check": "IAM 1.9",
        "status": "FAIL",
        "reason": f"Password expiration too high ({max_age} days), expected 90 or less"
    }