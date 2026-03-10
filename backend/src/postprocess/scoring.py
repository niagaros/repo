import logging

logger = logging.getLogger(__name__)

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def calculate_score(findings: list) -> dict:
    if not findings:
        return {
            "overall":     0,
            "passed":      0,
            "failed":      0,
            "total":       0,
            "by_severity": {},
        }

    passed = sum(1 for f in findings if f["result"] == "PASS")
    total  = len(findings)
    failed = total - passed

    by_severity = {}
    for sev in SEVERITIES:
        group   = [f for f in findings if str(f["severity"]) == sev]
        s_total = len(group)
        if s_total:
            s_passed = sum(1 for f in group if f["result"] == "PASS")
            by_severity[sev] = {
                "passed": s_passed,
                "failed": s_total - s_passed,
                "total":  s_total,
            }

    score = {
        "overall":     round(passed / total * 100, 1) if total else 0,
        "passed":      passed,
        "failed":      failed,
        "total":       total,
        "by_severity": by_severity,
    }

    logger.info(f"Scoring: {score}")
    return score