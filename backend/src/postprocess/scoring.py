import logging

logger = logging.getLogger(__name__)

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def calculate_score(findings: list) -> dict:
    """
    Calculates overall compliance score and breaks it down per severity.

    Returns:
    {
        "overall":     87.5,
        "passed":      14,
        "failed":      2,
        "total":       16,
        "by_severity": {
            "CRITICAL": {"passed": 1, "failed": 1, "total": 2},
            "HIGH":     {"passed": 5, "failed": 1, "total": 6},
            ...
        }
    }
    """
    if not findings:
        return {
            "overall":     0,
            "passed":      0,
            "failed":      0,
            "total":       0,
            "by_severity": {},
        }

    passed = sum(1 for f in findings if f["status"] == "PASS")
    total  = len(findings)
    failed = total - passed

    by_severity = {}
    for sev in SEVERITIES:
        group   = [f for f in findings if str(f["severity"]) == sev]
        s_total = len(group)
        if s_total:
            s_passed = sum(1 for f in group if f["status"] == "PASS")
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