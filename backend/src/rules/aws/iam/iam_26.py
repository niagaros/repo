from datetime import datetime, timezone


def check(resources):
    certs = [r for r in resources if r.get("resource_type") == "iam-ssl-certificate"]
    failing = []

    for cert in certs:
        expiry = cert.get("config", {}).get("expiration")
        if expiry:
            try:
                expiry_date = datetime.fromisoformat(expiry)
                if expiry_date < datetime.now(timezone.utc):
                    failing.append(cert.get("resource_name", "unknown"))
            except Exception:
                pass

    if failing:
        return {
            "check": "IAM.26",
            "status": "FAIL",
            "severity": "MEDIUM",
            "title": "Expired SSL certificates are present",
            "reason": f"Expired certificates: {', '.join(failing)}",
            "remediation": "Remove expired certificates via AWS CLI: aws iam delete-server-certificate --server-certificate-name <name>."
        }

    return {
        "check": "IAM.26",
        "status": "PASS",
        "severity": "MEDIUM",
        "title": "No expired SSL certificates",
        "reason": "No expired SSL certificates were found.",
        "remediation": None
    }