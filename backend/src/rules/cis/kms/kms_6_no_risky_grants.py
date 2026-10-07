class KMS6NoRiskyGrants:

    CONTROL_ID = "KMS.6"
    TITLE = "Ensure KMS grants do not allow overly permissive access"
    SEVERITY = "HIGH"
    REMEDIATION = (
        "Review and remove overly permissive KMS grants. "
        "Ensure grants are restricted to specific principals and operations."
    )

    def evaluate(self, kms_keys):

        findings = []

        for key in kms_keys:

            risky = False

            for grant in key.get("grants", []):
                if grant.get("GranteePrincipal") == "*":
                    risky = True
                if "All" in grant.get("Operations", []):
                    risky = True

            findings.append({
                "control_id": self.CONTROL_ID,
                "title": self.TITLE,
                "severity": self.SEVERITY,
                "status": "FAIL" if risky else "PASS",
                "message": (
                    "Risky grant detected"
                    if risky
                    else "No risky grants"
                ),
                "remediation": self.REMEDIATION,
                "resource_id": key.get("arn")
            })

        return findings