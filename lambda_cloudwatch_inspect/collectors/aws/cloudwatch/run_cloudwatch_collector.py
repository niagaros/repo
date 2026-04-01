import argparse
import json
import os
from pathlib import Path

from cloudwatch_collector import CloudWatchCollector


def _get_region(snapshot: dict) -> str:
    # New format: snapshot["region"]
    if snapshot.get("region"):
        return snapshot["region"]
    # Old format: snapshot["metadata"]["region"]
    return snapshot.get("metadata", {}).get("region", "unknown")


def _get_logs_block(snapshot: dict) -> dict:
    # New format: snapshot["logs"] = {"log_groups": [...]}
    if isinstance(snapshot.get("logs"), dict) and "log_groups" in snapshot["logs"]:
        return snapshot["logs"]
    # Old format: snapshot["logs"] = {"logGroups": [...], "metricFiltersByLogGroup": {...}}
    return snapshot.get("logs", {})


def _get_log_groups(logs_block: dict):
    return logs_block.get("log_groups") or logs_block.get("logGroups") or []


def _get_metric_filters_map(logs_block: dict):
    # New format: metric filters are inside each log group (metric_filters)
    if "log_groups" in logs_block:
        return None
    # Old format: separate map
    return logs_block.get("metricFiltersByLogGroup") or {}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "eu-north-1"))
    parser.add_argument("--out", default="out")
    args = parser.parse_args()

    collector = CloudWatchCollector(region=args.region)
    snapshot = collector.collect()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    account_id = snapshot.get("account_id") or snapshot.get("metadata", {}).get("accountId", "unknown")
    region = _get_region(snapshot)
    out_path = out_dir / f"cloudwatch-snapshot-{account_id}-{region}.json"

    out_path.write_text(json.dumps(snapshot, indent=2, default=str), encoding="utf-8")

    # Console summary (acceptance criteria friendly)
    trails = snapshot.get("cloudtrail", {}).get("trails", [])

    logs_block = _get_logs_block(snapshot)
    log_groups = _get_log_groups(logs_block)

    alarms = snapshot.get("cloudwatch", {}).get("alarms", [])
    topics = snapshot.get("sns", {}).get("topics", [])

    # metric filters total:
    mf_map = _get_metric_filters_map(logs_block)
    if mf_map is not None:
        metric_filters_total = sum(len(v) for v in mf_map.values())
    else:
        # New format: sum metric_filters arrays inside log_groups
        metric_filters_total = 0
        for lg in log_groups:
            metric_filters_total += len(lg.get("metric_filters", []) or [])

    print("✅ CloudWatchCollector snapshot written")
    print(f"   file: {out_path}")
    print(f"   trails: {len(trails)}")
    print(f"   logGroups: {len(log_groups)}")
    print(f"   metricFiltersTotal: {metric_filters_total}")
    print(f"   alarms: {len(alarms)}")
    print(f"   snsTopics: {len(topics)}")


if __name__ == "__main__":
    main()