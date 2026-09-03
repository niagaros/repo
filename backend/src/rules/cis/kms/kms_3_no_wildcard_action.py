import json

# AWS auto-generates an "Enable IAM User Permissions" statement on every
# customer-managed KMS key granting the account root "kms:*" so that IAM
# policies (not the key policy) govern day-to-day access — this is the
# documented, recommended default, not an open permission. A wildcard Action
# is only a real risk when paired with a wildcard Principal on the same
# statement (i.e. anyone, not just this account, can do anything).
def _is_wildcard_principal(principal) -> bool:
    return principal == "*" or principal == {"AWS": "*"}

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

                if not _is_wildcard_principal(stmt.get("Principal")):
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