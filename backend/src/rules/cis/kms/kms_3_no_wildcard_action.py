import json

class KMS3NoWildcardAction:

    CONTROL_ID = "KMS.3"
    TITLE = "Ensure KMS key policy does not allow wildcard actions"
    SEVERITY = "HIGH"
    REMEDIATION = (
        "Remove '*' or 'kms:*' from the Action field in the KMS key policy. "
        "Restrict permissions to only the required KMS actions."
    )

    def evaluate(self, kms_keys):

        findings = []

        for key in kms_keys:

            policy_str = key.get("policy")
            if not policy_str:
                continue

            policy = json.loads(policy_str)
            wildcard_action = False

            for stmt in policy.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue

                actions = stmt.get("Action")

                if actions == "*" or actions == "kms:*":
                    wildcard_action = True

                if isinstance(actions, list):
                    if "*" in actions or "kms:*" in actions:
                        wildcard_action = True

            findings.append({
                "control_id": self.CONTROL_ID,
                "title": self.TITLE,
                "severity": self.SEVERITY,
                "status": "FAIL" if wildcard_action else "PASS",
                "message": (
                    "Wildcard action found"
                    if wildcard_action
                    else "No wildcard action"
                ),
                "remediation": self.REMEDIATION,
                "resource_id": key.get("arn")
            })

        return findings