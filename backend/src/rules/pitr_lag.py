"""Shared RPO measurement for the point-in-time-recovery rules (RDS.DR.4, DynamoDB.DR.3).

Lag = moment the AWS API answered (config["observed_at"], set by the collector)
minus the latest restorable point. Measuring against the API answer instead of
the moment the rule runs keeps scanner runtime out of the RPO figure. Older
resource configs without observed_at fall back to "now", which can only
overstate the lag, never hide it.
"""
import datetime

from rules.base_check import CheckResult


def _parse_utc(value):
    if not value:
        return None
    ts = datetime.datetime.fromisoformat(value)
    if ts.tzinfo is None:
        raise ValueError(f"timestamp without timezone: {value}")
    return ts.astimezone(datetime.timezone.utc)


def evaluate_pitr_lag(config, target_seconds, missing_reason):
    try:
        latest_restorable = _parse_utc(config.get("latest_restorable_time"))
        if latest_restorable is None:
            return CheckResult("FAIL", {"reason": missing_reason})
        observed_at = _parse_utc(config.get("observed_at"))
    except ValueError as e:
        return CheckResult("FAIL", {"reason": f"unreadable restore-point timestamp ({e})"})

    measured_from = "api_response"
    if observed_at is None:
        observed_at = datetime.datetime.now(datetime.timezone.utc)
        measured_from = "rule_execution"

    lag_seconds = (observed_at - latest_restorable).total_seconds()
    # Small negative values are clock skew between AWS and the scanner; a restore
    # point clearly in the future is not trustworthy evidence.
    if lag_seconds < -60:
        return CheckResult("FAIL", {
            "reason": "latest restorable point lies in the future — clock or data problem",
            "measured_rpo_seconds": round(lag_seconds),
        })
    lag_seconds = max(lag_seconds, 0)
    return CheckResult("PASS" if lag_seconds <= target_seconds else "FAIL", {
        "measured_rpo_seconds": round(lag_seconds),
        "target_seconds": target_seconds,
        "measured_from": measured_from,
    })
