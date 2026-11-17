"""
cost_scanner_handler.py — Cloud Cost ingestion (issue #295). Lambda `cloud-cost-scanner`.

Events
  {"mode": "daily"}                              EventBridge schedule: queue one async run per opted-in account
  {"cloud_account_id": "...", "trigger": ...}    ingest one account (async from the API's "Refresh now")

Per run (all read-only, through the customer's existing CSPMScannerRole with its external id):
  Cost Explorer   GetCostAndUsage DAILY by SERVICE+RECORD_TYPE (last 90 days), by REGION (30 days, to pick the
                  regions to inspect), by the configured allocation tag (90 days), GetCostForecast (rest of month),
                  GetAnomalies (30 days), reservation and Savings Plans utilisation (30 days)
  EC2 / ELBv2     unattached volumes, unassociated Elastic IPs, long-stopped instances, load balancers without targets
                  in the regions that actually have spend (plus the account's home region)
  Pricing API     list prices for the savings estimates, read with Niagaros' own account (free)

Every paid Cost Explorer request is counted (ce_requests) and shown to the customer. Features AWS keeps opt-in
(resource-level cost, rightsizing, Compute Optimizer) are recorded in coverage as "not enabled", never guessed.
"""
import json
import logging
import os
from datetime import date, datetime, timedelta, timezone

import boto3
import psycopg2
from psycopg2.extras import Json

from collectors.aws.scanner import cost_engine as E

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REGION = os.environ.get("SECRET_REGION", "eu-west-1")
HISTORY_DAYS = 90
_J = lambda o: Json(o, dumps=lambda x: json.dumps(x, default=str))  # noqa: E731


def _get_connection():
    s = json.loads(boto3.client("secretsmanager", region_name=REGION).get_secret_value(
        SecretId=os.environ.get("DB_SECRET_NAME", "cspm/database/credentials"))["SecretString"])
    return psycopg2.connect(host=s["host"], port=s.get("port", 5432), dbname=s["database"], user=s["username"],
                            password=s["password"], sslmode="require", connect_timeout=10)


def _assume(role_arn, external_id):
    c = boto3.client("sts", region_name=REGION).assume_role(
        RoleArn=role_arn, ExternalId=external_id, RoleSessionName="niagaros-cost", DurationSeconds=3600)["Credentials"]
    return boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
                         aws_session_token=c["SessionToken"], region_name=REGION)


def _err(e):
    code = getattr(e, "response", {}).get("Error", {}).get("Code") if hasattr(e, "response") else None
    msg = str(e)
    if "opt-in" in msg.lower():
        return {"state": "not_enabled", "reason": "AWS keeps this feature opt-in; enable it in the Cost Explorer preferences of the payer account"}
    if code in ("AccessDeniedException", "AccessDenied", "UnauthorizedOperation"):
        return {"state": "no_access", "reason": "The scanner role is not allowed to read this"}
    if code == "DataUnavailableException":
        return {"state": "no_data", "reason": "AWS has no data for this (for example: no Savings Plans)"}
    return {"state": "error", "reason": f"{type(e).__name__}"}


class CE:
    """Cost Explorer wrapper that counts paid requests and follows pagination."""

    def __init__(self, session):
        self.c = session.client("ce", region_name="us-east-1")
        self.requests = 0

    def call(self, name, **kw):
        self.requests += 1
        return getattr(self.c, name)(**kw)

    def cost_and_usage(self, **kw):
        out, token = [], None
        while True:
            r = self.call("get_cost_and_usage", **kw, **({"NextPageToken": token} if token else {}))
            out += r.get("ResultsByTime") or []
            token = r.get("NextPageToken")
            if not token:
                return out


def _merge_periods(results):
    """Pagination splits groups of the same period over pages; merge them per period."""
    merged = {}
    for p in results:
        k = p["TimePeriod"]["Start"]
        if k not in merged:
            merged[k] = {"TimePeriod": p["TimePeriod"], "Estimated": p.get("Estimated"), "Groups": []}
        merged[k]["Groups"] += p.get("Groups") or []
    return [merged[k] for k in sorted(merged)]


# ── pricing (Niagaros' own account; the Pricing API is free) ─────────────────

_PRICE_CACHE = {}


def _price(service, filters, unit, usage_suffix=None):
    key = (service, tuple(sorted(filters.items())), usage_suffix)
    if key in _PRICE_CACHE:
        return _PRICE_CACHE[key]
    val = None
    try:
        p = boto3.client("pricing", region_name="us-east-1")
        r = p.get_products(ServiceCode=service, MaxResults=50,
                           Filters=[{"Type": "TERM_MATCH", "Field": k, "Value": v} for k, v in filters.items()])
        for raw in r.get("PriceList") or []:
            d = json.loads(raw)
            ut = d["product"]["attributes"].get("usagetype", "")
            if usage_suffix and not ut.endswith(usage_suffix):
                continue
            if "Outposts" in ut:
                continue
            for term in (d.get("terms", {}).get("OnDemand") or {}).values():
                for pd in term["priceDimensions"].values():
                    if pd.get("unit") == unit and pd["pricePerUnit"].get("USD") is not None:
                        val = float(pd["pricePerUnit"]["USD"])
            if val is not None:
                break
    except Exception:
        logger.exception("pricing lookup failed for %s %s", service, filters)
    _PRICE_CACHE[key] = val
    return val


def region_prices(region):
    ebs = {}
    for t in ("gp2", "gp3", "io1", "io2", "st1", "sc1", "standard"):
        v = _price("AmazonEC2", {"productFamily": "Storage", "volumeApiName": t, "regionCode": region}, "GB-Mo")
        if v is not None:
            ebs[t] = v
    ipv4 = _price("AmazonVPC", {"regionCode": region, "group": "VPCPublicIPv4Address"}, "Hrs", "PublicIPv4:IdleAddress")
    alb = _price("AWSELB", {"productFamily": "Load Balancer-Application", "regionCode": region}, "Hrs", "LoadBalancerUsage")
    nlb = _price("AWSELB", {"productFamily": "Load Balancer-Network", "regionCode": region}, "Hrs", "LoadBalancerUsage")
    return {"ebs": ebs, "ipv4_month": ipv4 * 730 if ipv4 is not None else None,
            "alb_month": alb * 730 if alb is not None else None, "nlb_month": nlb * 730 if nlb is not None else None}


# ── AWS region names from Cost Explorer -> region codes ─────────────────────

def _spend_regions(ce, start, end, coverage):
    try:
        res = ce.cost_and_usage(TimePeriod={"Start": str(start), "End": str(end)}, Granularity="MONTHLY",
                                Metrics=["UnblendedCost"], GroupBy=[{"Type": "DIMENSION", "Key": "REGION"}])
    except Exception as e:  # noqa: BLE001
        coverage["regions"] = _err(e)
        return set()
    regions = set()
    for p in res:
        for g in p.get("Groups") or []:
            k = (g.get("Keys") or [""])[0]
            if k and k not in ("global", "NoRegion") and float(g["Metrics"]["UnblendedCost"]["Amount"] or 0) > 0:
                regions.add(k)
    coverage["regions"] = {"state": "ok", "with_spend": sorted(regions)}
    return regions


def _paginate(client, op, key, **kw):
    out = []
    for page in client.get_paginator(op).paginate(**kw):
        out += page.get(key) or []
    return out


def collect_idle(session, regions, coverage, inventory):
    opps, per_region = [], {}
    for region in sorted(regions):
        try:
            ec2 = session.client("ec2", region_name=region)
            vols = _paginate(ec2, "describe_volumes", "Volumes")
            addrs = ec2.describe_addresses().get("Addresses") or []
            insts = [i for r in _paginate(ec2, "describe_instances", "Reservations") for i in r.get("Instances") or []]
            elb = session.client("elbv2", region_name=region)
            lbs = _paginate(elb, "describe_load_balancers", "LoadBalancers")
            health = {}
            for lb in lbs:
                try:
                    tgs = elb.describe_target_groups(LoadBalancerArn=lb["LoadBalancerArn"]).get("TargetGroups") or []
                    n = 0
                    for tg in tgs:
                        n += len(elb.describe_target_health(TargetGroupArn=tg["TargetGroupArn"]).get("TargetHealthDescriptions") or [])
                    health[lb["LoadBalancerArn"]] = n
                except Exception:  # noqa: BLE001 - unknown stays unknown, never "idle"
                    health[lb["LoadBalancerArn"]] = None
            found = E.find_idle(region, vols, addrs, insts, lbs, health, region_prices(region))
            opps += found
            unread = sum(1 for v in health.values() if v is None)
            inventory[region] = E.inventory_ids(vols, addrs, insts, lbs)
            # A region only supports lifecycle decisions (gone / verified) when everything in it was read.
            per_region[region] = {"state": "ok" if not unread else "partial", "volumes": len(vols), "addresses": len(addrs),
                                  "instances": len(insts), "load_balancers": len(lbs), "opportunities": len(found),
                                  **({"reason": f"Target health of {unread} load balancer(s) could not be read"} if unread else {})}
        except Exception as e:  # noqa: BLE001
            per_region[region] = _err(e)
    coverage["idle_resources"] = per_region
    return opps


# ── commitments, AI usage types, EKS (#295 second pass) ─────────────────────

EKS_TAG = "aws:eks:cluster-name"


def collect_commitments(session, ce, regions, coverage, used_services):
    """Inventory (free describe calls) and, when there is compute usage to base them on, AWS's own purchase
    recommendations (two paid Cost Explorer requests)."""
    sps, ris, dbs = [], [], []
    errs = {}
    try:
        sp = session.client("savingsplans", region_name="us-east-1")
        token = None
        while True:
            r = sp.describe_savings_plans(**({"nextToken": token} if token else {}))
            sps += r.get("savingsPlans") or []
            token = r.get("nextToken")
            if not token:
                break
    except Exception as e:  # noqa: BLE001
        errs["savings_plans"] = _err(e)
    for region in sorted(regions):
        try:
            ris += [{**r, "_region": region} for r in session.client("ec2", region_name=region).describe_reserved_instances().get("ReservedInstances") or []]
        except Exception as e:  # noqa: BLE001
            errs[f"ec2_reservations:{region}"] = _err(e)
        try:
            rds = session.client("rds", region_name=region)
            marker = None
            while True:
                r = rds.describe_reserved_db_instances(**({"Marker": marker} if marker else {}))
                dbs += [{**x, "_region": region} for x in r.get("ReservedDBInstances") or []]
                marker = r.get("Marker")
                if not marker:
                    break
        except Exception as e:  # noqa: BLE001
            errs[f"rds_reservations:{region}"] = _err(e)
    items = E.commitment_inventory(sps, ris, dbs)
    recs = {}
    compute = {"Amazon Elastic Compute Cloud - Compute", "AWS Lambda", "Amazon Elastic Container Service", "AWS Fargate"}
    if used_services & compute:
        try:
            recs["savings_plans"] = E.normalize_sp_recommendation(ce.call(
                "get_savings_plans_purchase_recommendation", SavingsPlansType="COMPUTE_SP", TermInYears="ONE_YEAR",
                PaymentOption="NO_UPFRONT", LookbackPeriodInDays="THIRTY_DAYS"))
        except Exception as e:  # noqa: BLE001
            recs["savings_plans"] = {"available": False, **_err(e)}
        if "Amazon Elastic Compute Cloud - Compute" in used_services:
            try:
                recs["reservations"] = E.normalize_ri_recommendation(ce.call(
                    "get_reservation_purchase_recommendation", Service="Amazon Elastic Compute Cloud - Compute",
                    TermInYears="ONE_YEAR", PaymentOption="NO_UPFRONT", LookbackPeriodInDays="THIRTY_DAYS"))
            except Exception as e:  # noqa: BLE001
                recs["reservations"] = {"available": False, **_err(e)}
    else:
        recs["note"] = "No compute usage (EC2, Lambda, ECS/Fargate) in the last 90 days, so no purchase recommendation was requested"
    coverage["commitment_inventory"] = {"state": "ok" if not errs else "partial", "items": len(items), "errors": errs}
    return items, recs


def collect_ai_usage(ce, start, end, ai_services, coverage):
    if not ai_services:
        coverage["ai_usage_types"] = {"state": "no_data", "reason": "No spend on AI services in the last 90 days"}
        return []  # reconciles: anything stored earlier for this period becomes zero
    try:
        res = _merge_periods(ce.cost_and_usage(
            TimePeriod={"Start": str(start.replace(day=1)), "End": str(end)}, Granularity="MONTHLY",
            Metrics=["UnblendedCost", "UsageQuantity"], Filter={"Dimensions": {"Key": "SERVICE", "Values": sorted(ai_services)}},
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}, {"Type": "DIMENSION", "Key": "USAGE_TYPE"}]))
        rows = E.normalize_usage_types(res)
        coverage["ai_usage_types"] = {"state": "ok", "rows": len(rows)}
        return rows
    except Exception as e:  # noqa: BLE001
        coverage["ai_usage_types"] = _err(e)
        return None


def collect_eks(session, ce, regions, start, end, eks_spend, coverage, reuse=None):
    clusters = []
    for region in sorted(regions):
        try:
            eks = session.client("eks", region_name=region)
            names, token = [], None
            while True:
                r = eks.list_clusters(**({"nextToken": token} if token else {}))
                names += r.get("clusters") or []
                token = r.get("nextToken")
                if not token:
                    break
            for name in names:
                c = eks.describe_cluster(name=name).get("cluster") or {}
                clusters.append({"name": name, "region": region, "status": c.get("status"), "version": c.get("version"),
                                 "created": c.get("createdAt")})
        except Exception as e:  # noqa: BLE001
            coverage.setdefault("eks_errors", {})[region] = _err(e)
    alloc, fetched = [], False
    if eks_spend and reuse is not None:
        alloc, fetched = reuse, True  # the account's allocation tag is already the cluster tag: no second paid request
    elif eks_spend:
        try:
            alloc = E.normalize_tag_daily(_merge_periods(ce.cost_and_usage(
                TimePeriod={"Start": str(start), "End": str(end)}, Granularity="DAILY", Metrics=["UnblendedCost"],
                GroupBy=[{"Type": "TAG", "Key": EKS_TAG}])), EKS_TAG)
            fetched = True
        except Exception as e:  # noqa: BLE001
            coverage["eks_cost"] = _err(e)
    tagged = any(r["tag_value"] for r in alloc)
    coverage["eks_cost"] = coverage.get("eks_cost") or (
        {"state": "ok", "clusters": len(clusters)} if tagged else
        {"state": "not_configured" if eks_spend else "no_data",
         "reason": ("Activate the AWS-generated cost allocation tag aws:eks:cluster-name in Billing to see cost per cluster"
                    if eks_spend else "No EKS spend in the last 90 days")})
    return clusters, alloc, fetched


def store_usage_types(cur, account, ingestion_id, rows, period_start=None):
    seen = {(str(r["month"]), r["service"], r["usage_type"]) for r in rows}
    if period_start is not None:
        # A charge AWS no longer reports for a refreshed month (corrected away) becomes zero, not stale.
        cur.execute("""SELECT month, service, usage_type FROM cost_usage_type_monthly WHERE cloud_account_id = %s
                       AND month >= %s AND amount <> 0""", (account, period_start))
        for m, s, u in cur.fetchall():
            if (str(m), s, u) not in seen:
                cur.execute("""UPDATE cost_usage_type_monthly SET amount = 0, usage_quantity = 0, ingestion_id = %s, updated_at = NOW()
                               WHERE cloud_account_id = %s AND month = %s AND service = %s AND usage_type = %s""",
                            (ingestion_id, account, m, s, u))
    for r in rows:
        cur.execute("""INSERT INTO cost_usage_type_monthly (cloud_account_id, month, service, usage_type, amount, usage_quantity, unit,
                                                            currency, estimated, ingestion_id)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                       ON CONFLICT (cloud_account_id, month, service, usage_type) DO UPDATE SET amount = EXCLUDED.amount,
                         usage_quantity = EXCLUDED.usage_quantity, unit = EXCLUDED.unit, estimated = EXCLUDED.estimated,
                         ingestion_id = EXCLUDED.ingestion_id, updated_at = NOW()""",
                    (account, r["month"], r["service"], r["usage_type"], r["amount"], r["usage_quantity"], r["unit"],
                     r["currency"], r["estimated"], ingestion_id))


# ── storage ────────────────────────────────────────────────────────────────

def store_daily(cur, account, ingestion_id, records, start, end, estimated_by_day=None):
    cur.execute("""SELECT day, service, record_type, amount, estimated FROM cost_daily
                   WHERE cloud_account_id = %s AND day >= %s AND day < %s""", (account, start, end))
    existing = {(str(d), s, t): (float(a), e) for d, s, t, a, e in cur.fetchall()}
    seen = set()
    revisions = 0
    for r in records:
        k = (r["day"], r["service"], r["record_type"])
        seen.add(k)
        old = existing.get(k)
        if old is not None and abs(old[0] - r["amount"]) >= 0.000001:
            cur.execute("""INSERT INTO cost_daily_revisions (cloud_account_id, day, service, record_type, old_amount, new_amount,
                                                             old_estimated, ingestion_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                        (account, r["day"], r["service"], r["record_type"], old[0], r["amount"], old[1], ingestion_id))
            revisions += 1
        cur.execute("""INSERT INTO cost_daily (cloud_account_id, day, service, record_type, amount, currency, estimated, ingestion_id)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                       ON CONFLICT (cloud_account_id, day, service, record_type) DO UPDATE SET amount = EXCLUDED.amount,
                         currency = EXCLUDED.currency, estimated = EXCLUDED.estimated, ingestion_id = EXCLUDED.ingestion_id,
                         updated_at = NOW()""",
                    (account, r["day"], r["service"], r["record_type"], r["amount"], r["currency"], r["estimated"], ingestion_id))
    # A stored amount AWS no longer reports for that day became zero (e.g. an estimate that was corrected away).
    for k, (amt, est) in existing.items():
        now_est = bool((estimated_by_day or {}).get(k[0], False))
        if k not in seen and abs(amt) < 0.000001 and est != now_est:
            cur.execute("""UPDATE cost_daily SET estimated = %s, ingestion_id = %s, updated_at = NOW()
                           WHERE cloud_account_id = %s AND day = %s AND service = %s AND record_type = %s""",
                        (now_est, ingestion_id, account, k[0], k[1], k[2]))
            continue
        if k not in seen and abs(amt) >= 0.000001:
            cur.execute("""INSERT INTO cost_daily_revisions (cloud_account_id, day, service, record_type, old_amount, new_amount,
                                                             old_estimated, ingestion_id) VALUES (%s, %s, %s, %s, %s, 0, %s, %s)""",
                        (account, k[0], k[1], k[2], amt, est, ingestion_id))
            # The zero comes from this response, so it carries this response's estimate flag for that day.
            cur.execute("""UPDATE cost_daily SET amount = 0, estimated = %s, ingestion_id = %s, updated_at = NOW()
                           WHERE cloud_account_id = %s AND day = %s AND service = %s AND record_type = %s""",
                        (bool((estimated_by_day or {}).get(k[0], False)), ingestion_id, account, k[0], k[1], k[2]))
            revisions += 1
    return revisions


def store_allocation(cur, account, ingestion_id, rows, tag_key, start, end, estimated_by_day=None):
    seen = set()
    for r in rows:
        seen.add((r["day"], r["tag_value"]))
        cur.execute("""INSERT INTO cost_allocation_daily (cloud_account_id, day, tag_key, tag_value, amount, currency, estimated, ingestion_id)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                       ON CONFLICT (cloud_account_id, day, tag_key, tag_value) DO UPDATE SET amount = EXCLUDED.amount,
                         estimated = EXCLUDED.estimated, ingestion_id = EXCLUDED.ingestion_id, updated_at = NOW()""",
                    (account, r["day"], tag_key, r["tag_value"], r["amount"], r["currency"], r["estimated"], ingestion_id))
    cur.execute("""SELECT day, tag_value, amount, estimated FROM cost_allocation_daily WHERE cloud_account_id = %s AND tag_key = %s
                   AND day >= %s AND day < %s""", (account, tag_key, start, end))
    for d, v, amt, est in cur.fetchall():
        now_est = bool((estimated_by_day or {}).get(str(d), False))
        if (str(d), v) not in seen and (float(amt) != 0 or est != now_est):
            cur.execute("""UPDATE cost_allocation_daily SET amount = 0, estimated = %s, ingestion_id = %s, updated_at = NOW()
                           WHERE cloud_account_id = %s AND day = %s AND tag_key = %s AND tag_value = %s""",
                        (now_est, ingestion_id, account, d, tag_key, v))


def _alert(cur, account, fingerprint, kind, title, amount, detail, notify):
    cur.execute("""INSERT INTO cost_alerts (cloud_account_id, fingerprint, kind, title, amount, detail)
                   VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (cloud_account_id, fingerprint) DO NOTHING RETURNING id""",
                (account, fingerprint, kind, title[:500], amount, _J(detail)))
    row = cur.fetchone()
    if row:
        notify.append((kind, title, str(row[0])))
    return bool(row)


def sync_opportunities(cur, account, ingestion_id, found, regions_ok, inventory=None, evidence_at=None):
    """Upsert what was found; move tracked opportunities through their lifecycle. Lifecycle decisions need a region
    that was read completely in this run, and evidence collected after the change was marked as done."""
    inventory = inventory or {}
    events = []
    by_fp = {o["fingerprint"]: o for o in found}
    cur.execute("""SELECT id, fingerprint, status, region, resource_id, executed_at, kind, detail FROM cost_opportunities
                   WHERE cloud_account_id = %s FOR UPDATE""", (account,))
    existing, billed_ids = {}, {}
    for i, fp, st, rg, rid, ex, kind, detail in cur.fetchall():
        existing[fp] = (i, st, rg, rid, ex)
        # The saving of a stopped instance is its storage: it is only gone when the volumes are gone too.
        billed_ids[fp] = {rid} | (set((detail or {}).get("volumes") or []) if kind == "stopped_instance" else set())
    for fp, o in by_fp.items():
        if fp in existing:
            oid, st, _rg, _rid, ex = existing[fp]
            if st == "executed" and evidence_at and ex and ex >= evidence_at:
                new, ev = st, None  # evidence predates the change; wait for the next ingestion
            else:
                new, ev = E.opportunity_transition(st, True, True)
            cur.execute("""UPDATE cost_opportunities SET title = %s, monthly_savings = %s, savings_basis = %s, detail = %s,
                                  last_seen = NOW(), status = %s WHERE id = %s""",
                        (o["title"][:500], o["monthly_savings"], o["savings_basis"], _J(o["detail"]), new, oid))
            if ev:
                events.append((oid, ev, st, new))
        else:
            cur.execute("""INSERT INTO cost_opportunities (cloud_account_id, fingerprint, kind, region, resource_id, title, monthly_savings,
                                   savings_basis, confidence, risk, detail, recommendation, rollback)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                        (account, fp, o["kind"], o["region"], o["resource_id"], o["title"][:500], o["monthly_savings"],
                         o["savings_basis"], o["confidence"], o["risk"], _J(o["detail"]), o["recommendation"], o["rollback"]))
            events.append((cur.fetchone()[0], "detected", None, "observed"))
    for fp, (oid, st, rg, rid, ex) in existing.items():
        if fp in by_fp or rg not in regions_ok:
            continue
        if st == "executed" and evidence_at and ex and ex >= evidence_at:
            continue
        new, ev = E.opportunity_transition(st, False, bool(billed_ids[fp] & inventory.get(rg, set())))
        if ev:
            extra = ", verified_at = NOW()" if new == "verified" else ""
            cur.execute(f"UPDATE cost_opportunities SET status = %s {extra} WHERE id = %s", (new, oid))
            events.append((oid, ev, st, new))
    for oid, ev, frm, to in events:
        cur.execute("""INSERT INTO cost_audit_log (cloud_account_id, actor_email, action, target, details)
                       VALUES (%s, 'cost-scanner', %s, %s, %s)""",
                    (account, f"opportunity_{ev}", str(oid), _J({"from": frm, "to": to, "ingestion_id": str(ingestion_id)})))
    return len(events)


def run(conn, account, session, trigger="schedule", requested_by=None, today=None, ingestion_id=None):
    today = today or date.today()
    start, end = today - timedelta(days=HISTORY_DAYS), today
    with conn.cursor() as cur:
        if ingestion_id:
            # Reserved by the API (rate limit); claim it once.
            cur.execute("""UPDATE cost_ingestions SET period_start = %s, period_end = %s, engine_version = %s, started_at = NOW(),
                                  claimed_at = NOW()
                           WHERE id = %s AND cloud_account_id = %s AND status = 'running' AND claimed_at IS NULL
                           RETURNING id""", (start, end, E.ENGINE_VERSION, ingestion_id, account))
            if not cur.fetchone():
                conn.rollback()
                return {"ingestion_id": str(ingestion_id), "status": "skipped"}
        else:
            # Same lock as the API's reservation: never two paid runs for one account at the same time.
            cur.execute("SELECT pg_advisory_xact_lock(hashtext('cost_ingest:' || %s))", (str(account),))
            cur.execute("""SELECT 1 FROM cost_ingestions WHERE cloud_account_id = %s AND status = 'running'
                           AND started_at > NOW() - interval '15 minutes'""", (account,))
            if cur.fetchone():
                conn.rollback()
                return {"status": "skipped", "reason": "another refresh is running"}
            cur.execute("""INSERT INTO cost_ingestions (cloud_account_id, trigger, requested_by, period_start, period_end, engine_version,
                                                        claimed_at)
                           VALUES (%s, %s, %s, %s, %s, %s, NOW()) RETURNING id""",
                        (account, trigger, requested_by, start, end, E.ENGINE_VERSION))
            ingestion_id = cur.fetchone()[0]
        cur.execute("SELECT started_at FROM cost_ingestions WHERE id = %s", (ingestion_id,))
        evidence_at = cur.fetchone()[0]
        cur.execute("SELECT allocation_tag_key, anomaly_min_amount FROM cost_settings WHERE cloud_account_id = %s", (account,))
        st = cur.fetchone() or (None, 5)
        cur.execute("SELECT account_id, region FROM cloud_accounts WHERE id = %s", (account,))
        aws_account, home_region = cur.fetchone() or (None, None)
    conn.commit()
    ce = CE(session)
    coverage = {}
    notify = []
    try:
        # 1. daily cost by service and record type — the one required source.
        daily = _merge_periods(ce.cost_and_usage(
            TimePeriod={"Start": str(start), "End": str(end)}, Granularity="DAILY", Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}, {"Type": "DIMENSION", "Key": "RECORD_TYPE"}]))
        records = E.normalize_daily(daily)
        estimated_by_day = {p["TimePeriod"]["Start"]: bool(p.get("Estimated")) for p in daily}
        coverage["daily_cost"] = {"state": "ok", "records": len(records), "metric": "UnblendedCost"}
        # 2. allocation tag
        alloc = []
        if st[0]:
            try:
                alloc = E.normalize_tag_daily(_merge_periods(ce.cost_and_usage(
                    TimePeriod={"Start": str(start), "End": str(end)}, Granularity="DAILY", Metrics=["UnblendedCost"],
                    GroupBy=[{"Type": "TAG", "Key": st[0]}])), st[0])
                coverage["allocation"] = {"state": "ok", "tag_key": st[0], "rows": len(alloc)}
            except Exception as e:  # noqa: BLE001
                coverage["allocation"] = _err(e)
        else:
            coverage["allocation"] = {"state": "not_configured", "reason": "No cost-allocation tag chosen"}
        # 3. forecast for the rest of this month
        forecast = None
        month_end = (today.replace(day=28) + timedelta(days=4)).replace(day=1)
        try:
            if today < month_end - timedelta(days=0):
                f = ce.call("get_cost_forecast", TimePeriod={"Start": str(today), "End": str(month_end)},
                            Metric="UNBLENDED_COST", Granularity="MONTHLY")
                forecast = {"start": today, "end": month_end, "amount": float(f["Total"]["Amount"]), "currency": f["Total"]["Unit"]}
                coverage["forecast"] = {"state": "ok"}
        except Exception as e:  # noqa: BLE001
            coverage["forecast"] = _err(e)
        # 4. AWS's own anomaly detection
        aws_anoms = []
        try:
            aws_anoms = E.normalize_aws_anomalies(ce.call("get_anomalies", DateInterval={"StartDate": str(today - timedelta(days=30))}))
            coverage["aws_anomalies"] = {"state": "ok", "count": len(aws_anoms)}
        except Exception as e:  # noqa: BLE001
            coverage["aws_anomalies"] = _err(e)
        # 5. commitments
        commitments = {}
        for kind, op in (("reservations", "get_reservation_utilization"), ("savings_plans", "get_savings_plans_utilization")):
            try:
                r = ce.call(op, TimePeriod={"Start": str(today - timedelta(days=30)), "End": str(today)})
                r.pop("ResponseMetadata", None)
                commitments[kind] = {"available": True, "data": r.get("Total") or {}}
            except Exception as e:  # noqa: BLE001
                commitments[kind] = {"available": False, "data": _err(e)}
        coverage["commitments"] = {k: ("ok" if v["available"] else v["data"]["state"]) for k, v in commitments.items()}
        # 6. opt-in features: recorded, not probed with paid calls every run
        coverage["resource_level_cost"] = {"state": "not_enabled", "reason": "Resource-level cost data is opt-in in Cost Explorer (payer account)"}
        coverage["rightsizing"] = {"state": "not_enabled", "reason": "EC2 rightsizing recommendations are opt-in in Cost Explorer (payer account)"}
        # 7. idle resources in regions with spend
        regions = _spend_regions(ce, today - timedelta(days=30), today, coverage) | {home_region or REGION}
        inventory = {}
        found = collect_idle(session, regions, coverage, inventory)
        regions_ok = {r for r, v in coverage["idle_resources"].items() if v.get("state") == "ok"}
        used = {r["service"] for r in records if r["record_type"] == "Usage" and r["amount"] > 0}
        lookback = str(today - timedelta(days=30))
        used_30d = {r["service"] for r in records if r["record_type"] == "Usage" and r["amount"] > 0 and r["day"] >= lookback}
        commit_items, commit_recs = collect_commitments(session, ce, regions, coverage, used_30d)
        ai_rows = collect_ai_usage(ce, start, end, used & set(E.AI_SERVICES), coverage)
        reuse = alloc if (st[0] == EKS_TAG and coverage.get("allocation", {}).get("state") == "ok") else None
        eks_clusters, eks_alloc, eks_fetched = collect_eks(session, ce, regions, start, end, bool(used & set(E.KUBERNETES_SERVICES)),
                                                           coverage, reuse)

        with conn.cursor() as cur:
            revisions = store_daily(cur, account, ingestion_id, records, start, end, estimated_by_day)
            if st[0] and coverage["allocation"].get("state") == "ok":
                store_allocation(cur, account, ingestion_id, alloc, st[0], start, end, estimated_by_day)
            if forecast:
                cur.execute("""INSERT INTO cost_forecasts (cloud_account_id, ingestion_id, period_start, period_end, mean_amount, currency)
                               VALUES (%s, %s, %s, %s, %s, %s)""",
                            (account, ingestion_id, forecast["start"], forecast["end"], forecast["amount"], forecast["currency"]))
            for kind, v in commitments.items():
                cur.execute("""INSERT INTO cost_commitment_snapshots (cloud_account_id, ingestion_id, kind, available, data)
                               VALUES (%s, %s, %s, %s, %s)""", (account, ingestion_id, kind, v["available"], _J(v["data"])))
            opp_events = sync_opportunities(cur, account, ingestion_id, found, regions_ok, inventory, evidence_at)
            # A read that failed is stored as unavailable (with the errors), never as an empty list.
            inv_ok = not (coverage.get("commitment_inventory") or {}).get("errors")
            eks_ok = not coverage.get("eks_errors")
            for kind, ok, data in (("inventory", inv_ok, {"items": commit_items, "errors": (coverage.get("commitment_inventory") or {}).get("errors")}),
                                   ("recommendations", True, commit_recs),
                                   ("eks_clusters", eks_ok, {"clusters": eks_clusters, "errors": coverage.get("eks_errors")})):
                cur.execute("""INSERT INTO cost_commitment_snapshots (cloud_account_id, ingestion_id, kind, available, data)
                               VALUES (%s, %s, %s, %s, %s)""", (account, ingestion_id, kind, ok, _J(data)))
            if ai_rows is not None:
                store_usage_types(cur, account, ingestion_id, ai_rows, start.replace(day=1))
            if eks_fetched and st[0] != EKS_TAG:
                store_allocation(cur, account, ingestion_id, eks_alloc, EKS_TAG, start, end, estimated_by_day)
            # A proposed commitment purchase counts as verified once AWS lists an active commitment that started after
            # it was marked as done.
            cur.execute("""SELECT detail->>'verified_commitment' FROM cost_opportunities WHERE cloud_account_id = %s
                           AND kind = 'commitment_purchase' AND status = 'verified'""", (account,))
            used_ids = {r[0] for r in cur.fetchall() if r[0]}
            cur.execute("""SELECT id, approved_at, fingerprint FROM cost_opportunities WHERE cloud_account_id = %s
                           AND kind = 'commitment_purchase' AND status = 'executed' ORDER BY approved_at FOR UPDATE""", (account,))
            for oid, approved, fp in cur.fetchall():
                which = fp.split(":")[1] if fp.count(":") >= 2 else None
                bought = E.match_purchase(which, approved, commit_items, used_ids)
                if bought:
                    used_ids.add(bought["id"])
                    cur.execute("""UPDATE cost_opportunities SET status = 'verified', verified_at = NOW(),
                                   detail = detail || jsonb_build_object('verified_commitment', %s::text) WHERE id = %s""",
                                (bought["id"], oid))
                    cur.execute("""INSERT INTO cost_audit_log (cloud_account_id, actor_email, action, target, details)
                                   VALUES (%s, 'cost-scanner', 'opportunity_verified_by_ingestion', %s, %s)""",
                                (account, str(oid), _J({"commitment": bought["id"]})))
            for c in E.expiry_alerts(commit_items):
                _alert(cur, account, c["fingerprint"], "commitment_expiry",
                       f"{c['kind'].replace('_', ' ').capitalize()} {c['id']} ends in {c['days_left']} days ({c['end']})",
                       None, {k: v for k, v in c.items() if k != "fingerprint"}, notify)
            # budgets and anomalies on the stored (current) numbers
            cur.execute("""SELECT day, service, record_type, amount, estimated, currency FROM cost_daily
                           WHERE cloud_account_id = %s AND day >= %s""", (account, start))
            stored = [{"day": d, "service": s, "record_type": t, "amount": float(a), "estimated": e, "currency": c}
                      for d, s, t, a, e, c in cur.fetchall()]
            summary = E.summarize(stored, today)
            fc_total = (summary["month_to_date"] + forecast["amount"]) if forecast else None
            cur.execute("""SELECT id, name, monthly_amount, thresholds, forecast_alert FROM cost_budgets
                           WHERE cloud_account_id = %s AND active""", (account,))
            month = today.strftime("%Y-%m")
            for bid, name, amount, thresholds, fa in cur.fetchall():
                ev = E.evaluate_budget({"monthly_amount": amount, "thresholds": thresholds, "forecast_alert": fa},
                                       summary["month_to_date"], fc_total)
                for t in ev["crossed"]:
                    _alert(cur, account, f"budget:{bid}:{month}:{t}", "budget_threshold",
                           f"Budget '{name}' reached {t}% ({summary['month_to_date']:.2f} of {float(amount):.2f} {summary['currency']})",
                           summary["month_to_date"], {"budget_id": str(bid), "threshold": t, **ev}, notify)
                if ev["forecast_over"]:
                    _alert(cur, account, f"budget_forecast:{bid}:{month}", "budget_forecast",
                           f"Budget '{name}' is forecast to be exceeded ({fc_total:.2f} forecast vs {float(amount):.2f})",
                           fc_total, {"budget_id": str(bid), **ev, "forecast_basis": "AWS Cost Explorer forecast + month to date"}, notify)
            for a in E.detect_anomalies(stored, float(st[1] or 5), today=today):
                _alert(cur, account, f"anomaly:{a['service']}:{a['day']}", "anomaly",
                       f"Unusual spend on {a['service']} on {a['day']}: {a['actual']:.2f} vs usual {a['expected']:.2f}",
                       a["impact"], a, notify)
            for a in aws_anoms:
                # Same minimum as Niagaros' own detection: AWS also flags cent-level blips.
                if a["anomaly_id"] and a["impact"] >= float(st[1] or 0):
                    _alert(cur, account, f"aws_anomaly:{a['anomaly_id']}", "aws_anomaly",
                           f"AWS detected unusual spend on {a['dimension']} (impact {a['impact']:.2f})", a["impact"], a, notify)
            failed = [k for k, v in coverage.items() if isinstance(v, dict) and v.get("state") in ("error", "no_access")]
            failed += [r for r, v in coverage.get("idle_resources", {}).items() if v.get("state") != "ok"]
            status = "partial" if failed else "succeeded"
            coverage["revisions"] = revisions
            coverage["opportunity_events"] = opp_events
            cur.execute("""UPDATE cost_ingestions SET status = %s, finished_at = NOW(), ce_requests = %s, coverage = %s
                           WHERE id = %s""", (status, ce.requests, _J(coverage), ingestion_id))
        conn.commit()
        _send(conn, account, notify)
        return {"ingestion_id": str(ingestion_id), "status": status, "ce_requests": ce.requests, "records": len(records)}
    except Exception as e:
        conn.rollback()
        logger.exception("cost ingestion failed")
        with conn.cursor() as cur:
            cur.execute("""UPDATE cost_ingestions SET status = 'failed', finished_at = NOW(), ce_requests = %s, coverage = %s,
                           error = %s WHERE id = %s""",
                        (ce.requests, _J(coverage), f"{type(e).__name__}: {_err(e)['reason']}", ingestion_id))
        conn.commit()
        return {"ingestion_id": str(ingestion_id), "status": "failed"}


def _send(conn, account, notify):
    for kind, title, alert_id in notify:
        try:
            from collectors.aws.scanner.notification_lib import create_notification
            create_notification(conn, account, "billing", f"cost_{kind}", "P2" if kind.startswith("budget") else "P3", title,
                                "See Cloud Cost for the numbers and how they were calculated.",
                                resource_link=f"cloud_cost.html?account_id={account}#alerts", actor="cost-scanner")
        except Exception:  # noqa: BLE001 - the alert row exists; a failed notification must not undo it
            logger.exception("cost notification failed")
            try:
                conn.rollback()
            except Exception:  # noqa: BLE001
                pass


def handler(event, context):
    event = event or {}
    lam = boto3.client("lambda", region_name=REGION)
    if event.get("mode") == "daily":
        conn = _get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""SELECT s.cloud_account_id FROM cost_settings s JOIN cloud_accounts c ON c.id = s.cloud_account_id
                               WHERE s.enabled AND c.status = 'active'""")
                ids = [str(r[0]) for r in cur.fetchall()]
        finally:
            conn.close()
        for i in ids:
            lam.invoke(FunctionName=context.invoked_function_arn, InvocationType="Event",
                       Payload=json.dumps({"cloud_account_id": i, "trigger": "schedule"}).encode())
        return {"queued": len(ids)}
    account = event.get("cloud_account_id")
    if not account:
        return {"statusCode": 400, "body": json.dumps({"error": "cloud_account_id is required"})}
    conn = _get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""SELECT c.role_arn, c.external_id, COALESCE(s.enabled, false) FROM cloud_accounts c
                           LEFT JOIN cost_settings s ON s.cloud_account_id = c.id WHERE c.id = %s""", (account,))
            row = cur.fetchone()
        if not row:
            return {"statusCode": 404, "body": json.dumps({"error": "unknown cloud account"})}
        if not row[2]:
            # Opt-in is checked here too, so nothing can make paid calls for an account that did not agree to them.
            if event.get("ingestion_id"):
                with conn.cursor() as cur:
                    cur.execute("""UPDATE cost_ingestions SET status = 'failed', finished_at = NOW(), error = 'Cost data was turned off'
                                   WHERE id = %s AND status = 'running'""", (event["ingestion_id"],))
                conn.commit()
            return {"statusCode": 409, "body": json.dumps({"error": "cost ingestion is not enabled for this account"})}
        try:
            session = _assume(row[0], row[1])
        except Exception as e:  # noqa: BLE001
            msg = f"Could not assume the scanner role ({type(e).__name__})"
            with conn.cursor() as cur:
                if event.get("ingestion_id"):
                    cur.execute("""UPDATE cost_ingestions SET status = 'failed', finished_at = NOW(), error = %s
                                   WHERE id = %s AND status = 'running'""", (msg, event["ingestion_id"]))
                else:
                    cur.execute("""INSERT INTO cost_ingestions (cloud_account_id, status, finished_at, trigger, requested_by, error)
                                   VALUES (%s, 'failed', NOW(), %s, %s, %s)""",
                                (account, event.get("trigger", "schedule"), event.get("requested_by"), msg))
            conn.commit()
            return {"statusCode": 200, "body": json.dumps({"status": "failed", "error": "assume_role"})}
        result = run(conn, account, session, event.get("trigger", "schedule"), event.get("requested_by"),
                     ingestion_id=event.get("ingestion_id"))
        return {"statusCode": 200, "body": json.dumps(result, default=str)}
    finally:
        conn.close()


lambda_handler = handler
