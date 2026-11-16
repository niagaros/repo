"""
cost_engine.py — pure logic for Niagaros Cloud Cost (issue #295). No AWS or database calls here, so every rule can be
unit-tested against recorded AWS responses.

Principles (from the issue):
  * every number keeps its source (AWS Cost Explorer, AWS Pricing API, EC2/ELB describe calls) and whether it is an
    AWS estimate (`Estimated: true` for recent days) or final;
  * credits, refunds, tax and discounts stay separate record types, never folded silently into "usage";
  * savings are only stated when they can be computed from a public AWS price for that exact resource; otherwise the
    opportunity says "savings unknown" instead of guessing;
  * nothing is executed: an opportunity goes observed -> approved (by a second person) -> executed (by the customer) ->
    verified (a later ingestion no longer finds the resource).
"""
import statistics
from datetime import date, datetime, timedelta, timezone

ENGINE_VERSION = "cost-engine/1.0"
SOURCE_CE = "aws-cost-explorer"

# Cost Explorer RECORD_TYPE values that are not usage. Kept separate so totals can be explained.
NON_USAGE_RECORD_TYPES = ("Credit", "Refund", "Tax", "Discount", "BundledDiscount", "SavingsPlanNegation",
                          "EdpDiscount", "PrivateRateDiscount", "DistributorDiscount")

# AWS service names (as Cost Explorer reports them) that are AI / ML spend. Only services that exist in Cost Explorer;
# model / agent / token level needs provider usage data Niagaros does not ingest yet.
AI_SERVICES = ("Amazon Bedrock", "Amazon SageMaker", "Amazon Comprehend", "Amazon Rekognition", "Amazon Textract",
               "Amazon Transcribe", "Amazon Translate", "Amazon Polly", "Amazon Lex", "Amazon Kendra", "Amazon Q",
               "Amazon Personalize", "Amazon Forecast", "Amazon Q Business", "Amazon Q Developer")
KUBERNETES_SERVICES = ("Amazon Elastic Container Service for Kubernetes", "Amazon Elastic Kubernetes Service")

# Which Niagaros scanner resource types belong to a billed service, to put cost next to security findings.
SERVICE_TO_RESOURCE_TYPES = {
    "Amazon Simple Storage Service": ("s3-bucket",),
    "AWS Key Management Service": ("kms-key",),
    "AWS CloudTrail": ("cloudwatch_trail",),
    "AmazonCloudWatch": ("cloudwatch_trail",),
    "Amazon Cognito": ("cognito-userpool",),
}


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


# ── Cost Explorer normalisation ─────────────────────────────────────────────

def normalize_daily(results_by_time, metric="UnblendedCost"):
    """GetCostAndUsage DAILY grouped by [SERVICE, RECORD_TYPE] -> one record per (day, service, record_type).
    Zero rows are dropped; the provider's own keys are kept unchanged."""
    out = []
    for period in results_by_time or []:
        day = period["TimePeriod"]["Start"]
        estimated = bool(period.get("Estimated"))
        for g in period.get("Groups") or []:
            keys = g.get("Keys") or []
            m = (g.get("Metrics") or {}).get(metric) or {}
            amount = _num(m.get("Amount"))
            if abs(amount) < 0.0000005:
                continue
            out.append({"day": day, "service": keys[0] if keys else "Unknown",
                        "record_type": keys[1] if len(keys) > 1 else "Usage",
                        "amount": round(amount, 6), "currency": m.get("Unit") or "USD", "estimated": estimated})
    return out


def normalize_tag_daily(results_by_time, tag_key, metric="UnblendedCost"):
    """GetCostAndUsage DAILY grouped by TAG:<key>. Cost Explorer returns '<key>$' for untagged spend: that is kept
    as tag_value '' and shown as unallocated, never spread over the tagged values."""
    out = []
    for period in results_by_time or []:
        day = period["TimePeriod"]["Start"]
        for g in period.get("Groups") or []:
            raw = (g.get("Keys") or [""])[0]
            value = raw.split("$", 1)[1] if "$" in raw else raw
            m = (g.get("Metrics") or {}).get(metric) or {}
            amount = _num(m.get("Amount"))
            if abs(amount) < 0.0000005:
                continue
            out.append({"day": day, "tag_key": tag_key, "tag_value": value, "amount": round(amount, 6),
                        "currency": m.get("Unit") or "USD", "estimated": bool(period.get("Estimated"))})
    return out


def diff_records(existing, new_records):
    """Which stored amounts changed (late billing adjustments). existing: {(day, service, record_type): amount}.
    Returns revisions so history is never silently overwritten."""
    revs = []
    for r in new_records:
        k = (r["day"], r["service"], r["record_type"])
        old = existing.get(k)
        if old is not None and abs(float(old) - r["amount"]) >= 0.000001:
            revs.append({"key": k, "old": float(old), "new": r["amount"]})
    return revs


# ── aggregation ─────────────────────────────────────────────────────────────

def summarize(records, today=None):
    """Totals for the explorer. records: dicts with day (str or date), service, record_type, amount, estimated."""
    today = today or date.today()
    month_start = today.replace(day=1)
    prev_end = month_start - timedelta(days=1)
    prev_start = prev_end.replace(day=1)
    by_service, by_type, by_day = {}, {}, {}
    mtd = prev = mtd_usage = 0.0
    estimated_days = set()
    currency = None
    for r in records:
        d = r["day"] if isinstance(r["day"], date) else date.fromisoformat(str(r["day"])[:10])
        a = float(r["amount"])
        currency = currency or r.get("currency")
        by_day[d] = by_day.get(d, 0.0) + a
        if r.get("estimated"):
            estimated_days.add(d)
        if d >= month_start:
            mtd += a
            by_service[r["service"]] = by_service.get(r["service"], 0.0) + a
            by_type[r["record_type"]] = by_type.get(r["record_type"], 0.0) + a
            if r["record_type"] == "Usage":
                mtd_usage += a
        elif prev_start <= d <= prev_end:
            prev += a
    days_with_data = sorted(by_day)
    return {
        "currency": currency or "USD",
        "month_to_date": round(mtd, 2), "month_to_date_usage": round(mtd_usage, 2),
        "previous_month": round(prev, 2),
        "by_service": sorted(({"service": k, "amount": round(v, 2)} for k, v in by_service.items()), key=lambda x: -x["amount"]),
        "by_record_type": sorted(({"record_type": k, "amount": round(v, 2)} for k, v in by_type.items()), key=lambda x: -abs(x["amount"])),
        "daily": [{"day": d.isoformat(), "amount": round(by_day[d], 4), "estimated": d in estimated_days} for d in days_with_data],
        "latest_day_with_data": days_with_data[-1].isoformat() if days_with_data else None,
        "estimated_days": len(estimated_days),
    }


def subset(records, services):
    s = set(services)
    return [r for r in records if r["service"] in s]


# ── anomalies ───────────────────────────────────────────────────────────────

def detect_anomalies(records, min_amount=5.0, lookback=14, recent_days=7, today=None):
    """Per service, a recent day is anomalous when it exceeds the mean of the previous `lookback` days by both
    3 standard deviations and 50% of the mean, and by at least `min_amount`. Needs 7+ days of history.
    Only usage records count (a tax line at month end is not an anomaly)."""
    today = today or date.today()
    series = {}
    for r in records:
        if r["record_type"] != "Usage":
            continue
        d = r["day"] if isinstance(r["day"], date) else date.fromisoformat(str(r["day"])[:10])
        series.setdefault(r["service"], {})
        series[r["service"]][d] = series[r["service"]].get(d, 0.0) + float(r["amount"])
    out = []
    for svc, days in series.items():
        for i in range(recent_days, 0, -1):
            d = today - timedelta(days=i)
            if d not in days:
                continue
            hist = [days.get(d - timedelta(days=k), 0.0) for k in range(1, lookback + 1)]
            if sum(1 for k in range(1, lookback + 1) if (d - timedelta(days=k)) in days) < 7:
                continue
            mean = statistics.fmean(hist)
            sd = statistics.pstdev(hist)
            actual = days[d]
            threshold = mean + max(3 * sd, 0.5 * mean)
            if actual > threshold and actual - mean >= min_amount:
                out.append({"service": svc, "day": d.isoformat(), "actual": round(actual, 2), "expected": round(mean, 2),
                            "threshold": round(threshold, 2), "impact": round(actual - mean, 2),
                            "method": f"actual > mean of previous {lookback} days + max(3σ, 50%) and ≥ {min_amount} more"})
    return out


def normalize_aws_anomalies(resp):
    out = []
    for a in (resp or {}).get("Anomalies") or []:
        impact = a.get("Impact") or {}
        out.append({"anomaly_id": a.get("AnomalyId"), "start": a.get("AnomalyStartDate"), "end": a.get("AnomalyEndDate"),
                    "dimension": a.get("DimensionValue"), "impact": round(_num(impact.get("TotalImpact")), 2),
                    "max_impact": round(_num(impact.get("MaxImpact")), 2),
                    "root_causes": [{k: rc.get(k) for k in ("Service", "Region", "UsageType", "LinkedAccount")}
                                    for rc in (a.get("RootCauses") or [])][:5],
                    "feedback": a.get("Feedback")})
    return out


# ── budgets ─────────────────────────────────────────────────────────────────

def evaluate_budget(budget, month_to_date, forecast_total=None):
    """Which thresholds a monthly budget has crossed, and whether the AWS forecast exceeds it.
    budget: {id, monthly_amount, thresholds:[50,80,100], forecast_alert:bool}"""
    amount = float(budget["monthly_amount"])
    used_pct = (month_to_date / amount * 100) if amount > 0 else 0
    crossed = [t for t in sorted(budget.get("thresholds") or [80, 100]) if used_pct >= t]
    over_forecast = bool(budget.get("forecast_alert") and forecast_total is not None and forecast_total > amount)
    return {"used_pct": round(used_pct, 1), "crossed": crossed, "forecast_over": over_forecast,
            "forecast_total": round(forecast_total, 2) if forecast_total is not None else None,
            "remaining": round(amount - month_to_date, 2)}


# ── idle resources ─────────────────────────────────────────────────────────

def _age_days(ts, now):
    if not ts:
        return None
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (now - ts).days


def _stopped_since(reason):
    """EC2 StateTransitionReason 'User initiated (2026-10-01 10:00:00 GMT)' -> datetime, else None."""
    if not reason or "(" not in reason:
        return None
    try:
        raw = reason[reason.rindex("(") + 1:reason.rindex(")")].replace(" GMT", "")
        return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (ValueError, IndexError):
        return None


def find_idle(region, volumes, addresses, instances, load_balancers, target_health, prices, now=None):
    """Idle resources from describe calls in one region. `prices` holds monthly USD list prices from the AWS
    Pricing API: {"ebs": {"gp3": 0.088, ...}, "ipv4_month": 3.6, "alb_month": 18.4, "nlb_month": 18.4}; a missing
    price leaves savings unknown. Returns opportunity dicts with a stable fingerprint."""
    now = now or datetime.now(timezone.utc)
    ebs = prices.get("ebs") or {}
    out = []

    def vol_cost(v):
        p = ebs.get(v.get("VolumeType"))
        return round(p * v.get("Size", 0), 2) if p is not None else None

    for v in volumes or []:
        if v.get("State") != "available":
            continue
        age = _age_days(v.get("CreateTime"), now)
        cost = vol_cost(v)
        out.append({
            "fingerprint": f"idle_ebs:{region}:{v['VolumeId']}", "kind": "idle_ebs", "region": region,
            "resource_id": v["VolumeId"], "title": f"Unattached EBS volume {v['VolumeId']} ({v.get('Size')} GiB {v.get('VolumeType')})",
            "monthly_savings": cost,
            "savings_basis": (f"AWS list price for {v.get('VolumeType')} in {region} × {v.get('Size')} GiB" if cost is not None
                              else "No public price found for this volume type; savings unknown"),
            "confidence": "high", "risk": "medium",
            "detail": {"state": "available (not attached to any instance)", "size_gib": v.get("Size"), "type": v.get("VolumeType"),
                       "created_days_ago": age, "encrypted": v.get("Encrypted"), "tags": v.get("Tags") or []},
            "recommendation": "Snapshot the volume if the data may be needed, then delete it.",
            "rollback": "Restore a new volume from the snapshot.",
        })
    ipv4 = prices.get("ipv4_month")
    for a in addresses or []:
        if a.get("AssociationId") or a.get("InstanceId") or a.get("NetworkInterfaceId"):
            continue
        out.append({
            "fingerprint": f"idle_eip:{region}:{a.get('AllocationId') or a.get('PublicIp')}", "kind": "idle_eip", "region": region,
            "resource_id": a.get("AllocationId") or a.get("PublicIp"), "title": f"Elastic IP {a.get('PublicIp')} is not associated",
            "monthly_savings": round(ipv4, 2) if ipv4 is not None else None,
            "savings_basis": "AWS list price for an idle public IPv4 address × 730 hours" if ipv4 is not None else "Price not found; savings unknown",
            "confidence": "high", "risk": "low",
            "detail": {"public_ip": a.get("PublicIp"), "domain": a.get("Domain"), "tags": a.get("Tags") or []},
            "recommendation": "Release the address if nothing depends on it (DNS records, allow-lists).",
            "rollback": "A released address cannot be guaranteed back; check DNS and partner allow-lists first.",
        })
    vols_by_id = {v["VolumeId"]: v for v in volumes or []}
    for i in instances or []:
        if (i.get("State") or {}).get("Name") != "stopped":
            continue
        since = _stopped_since(i.get("StateTransitionReason"))
        stopped_days = (now - since).days if since else None
        if stopped_days is not None and stopped_days < 14:
            continue
        attached = [m.get("Ebs", {}).get("VolumeId") for m in i.get("BlockDeviceMappings") or []]
        costs = [vol_cost(vols_by_id[x]) for x in attached if x in vols_by_id]
        cost = round(sum(costs), 2) if costs and all(c is not None for c in costs) else None
        out.append({
            "fingerprint": f"stopped_instance:{region}:{i['InstanceId']}", "kind": "stopped_instance", "region": region,
            "resource_id": i["InstanceId"],
            "title": f"Instance {i['InstanceId']} ({i.get('InstanceType')}) stopped" + (f" for {stopped_days} days" if stopped_days else ""),
            "monthly_savings": cost,
            "savings_basis": ("Attached EBS storage at AWS list price (a stopped instance is not billed for compute)" if cost is not None
                              else "Attached volume prices unknown; savings unknown"),
            "confidence": "medium" if stopped_days else "low", "risk": "medium",
            "detail": {"instance_type": i.get("InstanceType"), "stopped_days": stopped_days, "volumes": attached,
                       "tags": i.get("Tags") or []},
            "recommendation": "If it is no longer needed, create an AMI or snapshots and terminate it.",
            "rollback": "Launch a new instance from the AMI.",
        })
    for lb in load_balancers or []:
        arn = lb.get("LoadBalancerArn")
        healthy = target_health.get(arn)
        if healthy is None or healthy > 0:
            continue  # unknown target health is never called idle
        kind = lb.get("Type") or "application"
        price = prices.get("alb_month" if kind == "application" else "nlb_month")
        out.append({
            "fingerprint": f"idle_lb:{region}:{arn}", "kind": "idle_lb", "region": region, "resource_id": arn,
            "title": f"Load balancer {lb.get('LoadBalancerName')} has no registered targets",
            "monthly_savings": round(price, 2) if price is not None else None,
            "savings_basis": (f"AWS list price for one {kind} load balancer-hour × 730 (capacity units not included)"
                              if price is not None else "Price not found; savings unknown"),
            "confidence": "medium", "risk": "medium",
            "detail": {"type": kind, "scheme": lb.get("Scheme"), "dns_name": lb.get("DNSName"),
                       "created_days_ago": _age_days(lb.get("CreatedTime"), now), "registered_targets": 0},
            "recommendation": "Delete the load balancer if no service uses it any more.",
            "rollback": "Recreate it from your infrastructure code; DNS names change.",
        })
    return out


def opportunity_transition(status, still_idle, still_exists):
    """Lifecycle after an ingestion that read the resource's region completely. Returns (new_status, event).
    A saving is only verified when the resource no longer exists: a volume that got attached, an address that got
    associated or an instance that was started again is no longer idle, but it is still billed."""
    if status == "executed":
        if still_exists:
            return "approved", "verification_failed"
        return "verified", "verified_by_ingestion"
    if status in ("observed", "approval_requested", "approved") and not still_idle:
        return "gone", ("no_longer_idle" if still_exists else "resource_no_longer_found")
    if status == "gone" and still_idle:
        return "observed", "found_again"
    return status, None


def inventory_ids(volumes, addresses, instances, load_balancers):
    """Every resource id that exists in a region (idle or not), to tell 'deleted' from 'no longer idle'."""
    ids = {v["VolumeId"] for v in volumes or []}
    ids |= {a.get("AllocationId") or a.get("PublicIp") for a in addresses or []}
    ids |= {i["InstanceId"] for i in instances or [] if (i.get("State") or {}).get("Name") != "terminated"}
    ids |= {lb["LoadBalancerArn"] for lb in load_balancers or []}
    return ids
