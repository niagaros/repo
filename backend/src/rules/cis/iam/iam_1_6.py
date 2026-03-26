def check(resources):

    account = None

    for resource in resources:
        if resource.get("resource_type") == "iam-account":
            account = resource
            break

    if not account:
        return {
            "check": "IAM 1.6",
            "status": "FAIL",
            "reason": "No IAM account resource found"
        }

    password_policy = account.get("config", {}).get("password_policy")

    if not password_policy:
        return {
            "check": "IAM 1.6",
            "status": "FAIL",
            "reason": "No password policy configured"
        }

    require_uppercase = password_policy.get("RequireUppercaseCharacters", False)
    require_lowercase = password_policy.get("RequireLowercaseCharacters", False)
    require_numbers = password_policy.get("RequireNumbers", False)
    require_symbols = password_policy.get("RequireSymbols", False)

    missing = []

    if not require_uppercase:
        missing.append("uppercase")
    if not require_lowercase:
        missing.append("lowercase")
    if not require_numbers:
        missing.append("numbers")
    if not require_symbols:
        missing.append("symbols")

    if not missing:
        return {
            "check": "IAM 1.6",
            "status": "PASS",
            "reason": "Password policy enforces uppercase, lowercase, numbers and symbols"
        }

    return {
        "check": "IAM 1.6",
        "status": "FAIL",
        "reason": f"Password policy missing complexity requirements: {', '.join(missing)}"
    }