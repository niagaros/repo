"""
status_handler.py

Public system status for Niagaros (GitHub issue #274 AC19: "independent
status communication availability" — a customer can check whether
Niagaros itself is healthy even when something in the main product is
having trouble).

Real independence, not simulated: this reads directly from AWS's own
monitoring plane (CloudWatch metrics, RDS's own instance status, SQS's
own queue attributes) instead of querying the CSPM database or calling
any of the product's own business-logic Lambdas — so if cspm-db or a
handler Lambda is genuinely down, this page can still say so, because it
never depends on them to answer.
"""

import json
import logging
import os
from datetime import datetime, timedelta, timezone

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
}

REGION = os.environ.get("SECRET_REGION", "eu-west-1")
DB_INSTANCE_ID = os.environ.get("DB_INSTANCE_ID", "cspm-db")
QUEUE_URL = os.environ.get("NOTIFICATION_QUEUE_URL")

# Real, user-facing Lambdas whose health actually matters to a customer —
# not every internal mapper/cron function, just what backs a page they use.
MONITORED_LAMBDAS = (
    "get-dashboard-data", "notification-handler", "questionnaire-handler",
    "ai-agent-handler", "tprm-handler", "audit-management-handler",
)


def _resp(status, body):
    return {"statusCode": status, "headers": CORS_HEADERS, "body": json.dumps(body, default=str)}


def _database_status():
    try:
        rds = boto3.client("rds", region_name=REGION)
        inst = rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)["DBInstances"][0]
        status = inst["DBInstanceStatus"]
        return {"status": "operational" if status == "available" else "degraded", "raw_status": status}
    except Exception as e:
        logger.exception("database status check failed")
        return {"status": "unknown", "error": str(e)}


def _queue_status():
    if not QUEUE_URL:
        return {"status": "unknown", "error": "not_configured"}
    try:
        sqs = boto3.client("sqs", region_name=REGION)
        attrs = sqs.get_queue_attributes(
            QueueUrl=QUEUE_URL,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        visible = int(attrs.get("ApproximateNumberOfMessages", 0))
        in_flight = int(attrs.get("ApproximateNumberOfMessagesNotVisible", 0))
        # A real, if simple, threshold — a healthy queue drains within
        # seconds, so more than a handful of backlogged messages means
        # delivery is falling behind, not that traffic is merely busy.
        backlog = visible + in_flight
        status = "operational" if backlog < 50 else "degraded"
        return {"status": status, "messages_visible": visible, "messages_in_flight": in_flight}
    except Exception as e:
        logger.exception("queue status check failed")
        return {"status": "unknown", "error": str(e)}


def _lambda_health():
    cloudwatch = boto3.client("cloudwatch", region_name=REGION)
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=1)
    queries = []
    for i, fn in enumerate(MONITORED_LAMBDAS):
        dims = [{"Name": "FunctionName", "Value": fn}]
        queries.append({"Id": f"inv{i}", "MetricStat": {
            "Metric": {"Namespace": "AWS/Lambda", "MetricName": "Invocations", "Dimensions": dims},
            "Period": 3600, "Stat": "Sum"}, "ReturnData": True})
        queries.append({"Id": f"err{i}", "MetricStat": {
            "Metric": {"Namespace": "AWS/Lambda", "MetricName": "Errors", "Dimensions": dims},
            "Period": 3600, "Stat": "Sum"}, "ReturnData": True})

    try:
        result = cloudwatch.get_metric_data(MetricDataQueries=queries, StartTime=start, EndTime=now)
        values = {r["Id"]: (r["Values"][0] if r["Values"] else 0) for r in result["MetricDataResults"]}
    except Exception as e:
        logger.exception("lambda health check failed")
        return {fn: {"status": "unknown", "error": str(e)} for fn in MONITORED_LAMBDAS}

    health = {}
    for i, fn in enumerate(MONITORED_LAMBDAS):
        invocations = values.get(f"inv{i}", 0)
        errors = values.get(f"err{i}", 0)
        if invocations == 0:
            health[fn] = {"status": "no_recent_activity", "invocations": 0, "errors": 0}
            continue
        error_rate_pct = round(errors * 100.0 / invocations, 1)
        # No real product runs at 0% errors under any load — the bar here
        # is "clearly broken" (over a quarter of calls failing), not
        # "had a single transient failure".
        status = "operational" if error_rate_pct < 25 else "degraded"
        health[fn] = {"status": status, "invocations": int(invocations), "errors": int(errors),
                      "error_rate_pct": error_rate_pct}
    return health


def handler(event, context):
    method = (event or {}).get("httpMethod")
    if method == "OPTIONS":
        return _resp(200, {})

    database = _database_status()
    queue = _queue_status()
    lambdas = _lambda_health()

    statuses = [database["status"], queue["status"]] + [h["status"] for h in lambdas.values()]
    if "degraded" in statuses:
        overall = "degraded"
    elif all(s in ("operational", "no_recent_activity", "unknown") for s in statuses):
        overall = "operational"
    else:
        overall = "unknown"

    return _resp(200, {
        "overall_status": overall,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "database": database,
        "notification_queue": queue,
        "lambdas": lambdas,
    })
