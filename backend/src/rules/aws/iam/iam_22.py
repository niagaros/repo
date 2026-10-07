from datetime import datetime, timezone


def check(resources):
    users = [r for r in resources if r.get("resource_type") == "iam-user"]
    failing = []

    for user in users:
        last_used = user.get("config", {}).get("password_last_used")
        if last_used and last_used not in ("no_information", "N/A", "not_supported", "None"):
            try:
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(last_used)).days
                if age > 45:
                    failing.append(f"{user['resource_name']} ({age} days unused)")
            except Exception:
                pass

    if failing:
        return {
            "check": "IAM.22",
            "status": "FAIL",
            "severity": "MEDIUM",
            "title": "Inactive IAM users found",
            "reason": f"Users inactive for more than 45 days: {', '.join(failing)}",
            "remediation": "Deactivate or remove inactive users via IAM → Users → Security credentials."
        }

    return {
        "check": "IAM.22",
        "status": "PASS",
        "severity": "MEDIUM",
        "title": "No inactive IAM users",
        "reason": "All users are active within 45 days.",
        "remediation": None
    }