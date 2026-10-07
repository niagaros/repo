def check(resources):
    users = [r for r in resources if r.get("resource_type") == "iam-user"]
    failing = [
        r["resource_name"] for r in users
        if "arn:aws:iam::aws:policy/AWSCloudShellFullAccess" in r.get("config", {}).get("attached_policies", [])
    ]

    if failing:
        return {
            "check": "IAM.27",
            "status": "FAIL",
            "severity": "MEDIUM",
            "title": "Users have unrestricted CloudShell access",
            "reason": f"Users with AWSCloudShellFullAccess: {', '.join(failing)}",
            "remediation": "Remove AWSCloudShellFullAccess via IAM → Users → Permissions. Use a restrictive custom policy if access is needed."
        }

    return {
        "check": "IAM.27",
        "status": "PASS",
        "severity": "MEDIUM",
        "title": "No unrestricted CloudShell access",
        "reason": "No users with AWSCloudShellFullAccess were found.",
        "remediation": None
    }