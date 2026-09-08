from datetime import datetime, timezone


def check(resources):
    users = [r for r in resources if r.get("resource_type") == "iam-user"]
    failing = []

    for user in users:
        for key in user.get("config", {}).get("access_keys", []):
            if not key.get("active"):
                continue

            rotated = key.get("last_rotated")
            if rotated:
                try:
                    age = (datetime.now(timezone.utc) - datetime.fromisoformat(rotated)).days
                    if age > 90:
                        failing.append(f"{user['resource_name']} ({age} days old)")
                except Exception:
                    pass

    if failing:
        return {
            "check": "IAM.3",
            "status": "FAIL",
            "severity": "MEDIUM",
            "title": "Access keys are older than 90 days",
            "reason": f"Access keys older than 90 days: {', '.join(failing)}",
            "remediation": "Rotate access keys via IAM → Users → Security credentials. Create a new key, update the application and remove the old key."
        }

    return {
        "check": "IAM.3",
        "status": "PASS",
        "severity": "MEDIUM",
        "title": "Access keys have been rotated recently",
        "reason": "All active access keys have been rotated within 90 days.",
        "remediation": None
    }