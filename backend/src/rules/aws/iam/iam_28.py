def check(resources):
    account = next((r for r in resources if r.get("resource_type") == "iam-account"), None)

    if not account:
        return {
            "check": "IAM.28",
            "status": "FAIL",
            "severity": "HIGH",
            "title": "IAM account not found",
            "reason": "No iam-account resource found.",
            "remediation": "Ensure the IAM collector is running correctly."
        }

    if account.get("config", {}).get("access_analyzer_enabled"):
        return {
            "check": "IAM.28",
            "status": "PASS",
            "severity": "HIGH",
            "title": "IAM Access Analyzer is enabled",
            "reason": "Access Analyzer is enabled.",
            "remediation": None
        }

    return {
        "check": "IAM.28",
        "status": "FAIL",
        "severity": "HIGH",
        "title": "IAM Access Analyzer is not enabled",
        "reason": "Access Analyzer is not enabled.",
        "remediation": "Enable Access Analyzer via IAM → Access Analyzer → Create analyzer → External access analyzer."
    }