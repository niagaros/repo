def check(resources):
    users = [r for r in resources if r.get("resource_type") == "iam-user"]
    failing = [r["resource_name"] for r in users if r.get("config", {}).get("attached_policies")]

    if failing:
        return {
            "check": "IAM.2",
            "status": "FAIL",
            "severity": "MEDIUM",
            "title": "IAM users have directly attached policies",
            "reason": f"Users with directly attached policies: {', '.join(failing)}",
            "remediation": "Remove directly attached policies from users. Use IAM groups for permission management."
        }

    return {
        "check": "IAM.2",
        "status": "PASS",
        "severity": "MEDIUM",
        "title": "IAM users do not have directly attached policies",
        "reason": "No users with directly attached policies were found.",
        "remediation": None
    }