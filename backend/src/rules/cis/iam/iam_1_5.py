def check(resources):

    account = None

    for r in resources:
        if r.get("resource_type") == "iam-account":
            account = r
            break

    if not account:
        return {
            "check": "IAM 1.5",
            "status": "FAIL",
            "reason": "No IAM account resource found"
        }

    password_policy = account["config"].get("password_policy")

    if not password_policy:
        return {
            "check": "IAM 1.5",
            "status": "FAIL",
            "reason": "No password policy configured"
        }

    min_length = password_policy.get("MinimumPasswordLength", 0)

    if min_length >= 14:
        return {
            "check": "IAM 1.5",
            "status": "PASS",
            "reason": f"Minimum password length is {min_length}"
        }

    return {
        "check": "IAM 1.5",
        "status": "FAIL",
        "reason": f"Password length too short ({min_length})"
    }