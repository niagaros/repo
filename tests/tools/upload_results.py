"""Store the last real test run in the database (test-results-handler), so the coverage dashboard shows real history.

Token: E2E_INGEST_TOKEN, or (locally, with AWS credentials) the secret cspm/tests/ingest-token. Without either the
upload is skipped and says so — it never fakes success. Exit code is 0 when skipped, 1 when the upload fails."""
import json
import os
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[2]
API = os.environ.get("E2E_API_BASE", "https://hzf92ft6j7.execute-api.eu-west-1.amazonaws.com/default")


def token():
    t = os.environ.get("E2E_INGEST_TOKEN", "").strip()
    if t:
        return t
    try:
        import boto3
        return boto3.client("secretsmanager", region_name="eu-west-1").get_secret_value(SecretId="cspm/tests/ingest-token")["SecretString"].strip()
    except Exception:
        return ""


def main():
    t = token()
    if not t:
        print("Upload skipped: no E2E_INGEST_TOKEN and no AWS credentials to read cspm/tests/ingest-token.")
        return 0
    reports = ROOT / "tests" / "reports"
    summary = json.loads((reports / "summary.json").read_text(encoding="utf-8"))
    results = json.loads((reports / "latest.json").read_text(encoding="utf-8"))["results"]
    r = requests.post(f"{API}/test-results", headers={"X-Ingest-Token": t, "Content-Type": "application/json"},
                      data=json.dumps({"summary": summary, "results": results}), timeout=60)
    if r.status_code != 200:
        print(f"Upload FAILED: {r.status_code} {r.text[:200]}")
        return 1
    body = r.json()
    print("Run already stored (duplicate)." if body.get("duplicate") else f"Run stored in the database: {body['run_id']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
