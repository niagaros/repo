def check(resources):
    users = [r for r in resources if r.get("resource_type") == "iam-user"]
    failing = [
        r["resource_name"] for r in users
        if r.get("config", {}).get("password_enabled") and not r.get("config", {}).get("mfa_enabled")
    ]

    if failing:
        return {
            "check": "IAM.5",
            "status": "FAIL",
            "severity": "HIGH",
            "title": "IAM users without MFA have console access",
            "reason": f"Users without MFA: {', '.join(failing)}",
            "remediation": "Enable MFA via IAM → Users → Security credentials → Assign MFA device."
        }

    return {
        "check": "IAM.5",
        "status": "PASS",
        "severity": "HIGH",
        "title": "All console users have MFA enabled",
        "reason": "All users with console access have MFA enabled.",
        "remediation": None
    }