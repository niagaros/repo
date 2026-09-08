def check(resources):
    account = next((r for r in resources if r.get("resource_type") == "iam-account"), None)

    if not account:
        return {
            "check": "IAM.18",
            "status": "FAIL",
            "severity": "LOW",
            "title": "IAM account not found",
            "reason": "No iam-account resource found.",
            "remediation": "Ensure the IAM collector is running correctly."
        }

    if not account.get("config", {}).get("has_support_role"):
        return {
            "check": "IAM.18",
            "status": "FAIL",
            "severity": "LOW",
            "title": "No support role present",
            "reason": "No IAM support role found.",
            "remediation": "Create a support role via IAM → Roles → Create role → attach AWSSupportAccess policy."
        }

    return {
        "check": "IAM.18",
        "status": "PASS",
        "severity": "LOW",
        "title": "Support role is present",
        "reason": "An IAM support role is configured.",
        "remediation": None
    }