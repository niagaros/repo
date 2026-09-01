class KMS4KeyNotDisabled:

    CONTROL_ID = "KMS.4"
    TITLE = "Ensure KMS keys are not disabled"
    SEVERITY = "MEDIUM"
    REMEDIATION = (
        "Ensure KMS keys are enabled. "
        "Disabled keys cannot be used for encryption or decryption."
    )

    def evaluate(self, kms_keys):

        findings = []

        for key in kms_keys:

            disabled = key.get("key_state") == "Disabled"

            findings.append({
                "control_id": self.CONTROL_ID,
                "title": self.TITLE,
                "severity": self.SEVERITY,
                "status": "FAIL" if disabled else "PASS",
                "message": "Key is disabled" if disabled else "Key is enabled",
                "remediation": self.REMEDIATION,
                "resource_id": key.get("arn")
            })

        return findings