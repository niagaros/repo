import json

# Condition keys AWS itself generates on the default key policy for service-linked
# KMS access (e.g. "Allow access through Backup/Lambda/SNS/... for all principals
# in the account that are authorized to use <service>"). These restrict a
# wildcard "AWS": "*" principal to callers within the same account acting through
# a specific service — they are not public/external access, so a wildcard
# Principal scoped by one of these should not be flagged as a real KMS.2 finding.
ACCOUNT_SCOPING_CONDITION_KEYS = (
    "kms:calleraccount",
    "aws:sourceaccount",
    "aws:principalaccount",
    "aws:principalorgid",
)

def _is_account_scoped(condition: dict) -> bool:
    if not condition:
        return False
    for operator_block in condition.values():
        if not isinstance(operator_block, dict):
            continue
        for key in operator_block:
            if key.lower() in ACCOUNT_SCOPING_CONDITION_KEYS:
                return True
    return False

class KMS2NoWildcardPrincipal:

    CONTROL_ID = "KMS.2"
    TITLE = "Ensure KMS key policy does not allow wildcard principals"
    SEVERITY = "CRITICAL"
    REMEDIATION = "Remove wildcard (*) principals from the KMS key policy."

    def evaluate(self, kms_keys):

        findings = []

        for key in kms_keys:

            policy_str = key.get("policy")
            if not policy_str:
                continue

            policy = json.loads(policy_str)
            wildcard_found = False

            for stmt in policy.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue

                principal = stmt.get("Principal")

                if principal == "*" or principal == {"AWS": "*"}:
                    if not _is_account_scoped(stmt.get("Condition")):
                        wildcard_found = True

            findings.append({
                "control_id": self.CONTROL_ID,
                "title": self.TITLE,
                "severity": self.SEVERITY,
                "status": "FAIL" if wildcard_found else "PASS",
                "message": "Wildcard principal found"
                           if wildcard_found
                           else "No wildcard principal",
                "remediation": self.REMEDIATION,
                "resource_id": key.get("arn")
            })

        return findings