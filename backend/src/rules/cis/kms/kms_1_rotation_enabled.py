class KMS1RotationEnabled:

    CONTROL_ID = "KMS.1"
    TITLE = "Ensure rotation is enabled for customer managed KMS keys"
    SEVERITY = "MEDIUM"
    REMEDIATION = (
        "Enable automatic key rotation for customer-managed KMS keys. "
        "Use the AWS Console, CLI, or SDK to enable key rotation."
    )

    def evaluate(self, kms_keys):

        findings = []

        for key in kms_keys:

            if key.get("key_manager") != "CUSTOMER":
                continue

            rotation_enabled = key.get("rotation_enabled")

            findings.append({
                "control_id": self.CONTROL_ID,
                "title": self.TITLE,
                "severity": self.SEVERITY,
                "status": "PASS" if rotation_enabled else "FAIL",
                "message": (
                    "Rotation is enabled"
                    if rotation_enabled
                    else "Rotation is NOT enabled"
                ),
                "remediation": self.REMEDIATION,
                "resource_id": key.get("arn")
            })

        return findings