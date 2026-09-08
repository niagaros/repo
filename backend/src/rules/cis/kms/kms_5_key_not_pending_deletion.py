class KMS5KeyNotPendingDeletion:

    CONTROL_ID = "KMS.5"
    TITLE = "Ensure KMS keys are not pending deletion"
    SEVERITY = "HIGH"
    REMEDIATION = (
        "Cancel key deletion if the key is still required. "
        "Ensure keys scheduled for deletion are intentional."
    )

    def evaluate(self, kms_keys):

        findings = []

        for key in kms_keys:

            pending = key.get("key_state") == "PendingDeletion"

            findings.append({
                "control_id": self.CONTROL_ID,
                "title": self.TITLE,
                "severity": self.SEVERITY,
                "status": "FAIL" if pending else "PASS",
                "message": (
                    "Key is pending deletion"
                    if pending
                    else "Key is active"
                ),
                "remediation": self.REMEDIATION,
                "resource_id": key.get("arn")
            })

        return findings