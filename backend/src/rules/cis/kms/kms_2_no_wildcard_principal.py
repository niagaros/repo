import json

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