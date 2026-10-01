"""Resources that AWS no longer lists are pruned on each scan (with their findings), but only
when the listing was complete and non-empty, so a failed region, page or describe call can
never delete a resource that still exists. No AWS or database needed."""
import sys
import types

import pytest

# engine.scanner imports config.database, which needs the real psycopg2; the scanner gets a
# FakeDb below, so a stub module is enough here.
try:
    import config.database  # noqa: F401
except ImportError:
    sys.modules["config.database"] = types.SimpleNamespace(Database=object)

from collectors.aws.dynamoDB.collector import DynamoDBCollector
from collectors.aws.s3.collector import S3Collector
from collectors.base_collector import BaseCollector
from engine import scanner as scanner_mod

pytestmark = [pytest.mark.flow("E2E-INFRA-001"), pytest.mark.severity("P1")]


class FakeDb:
    def __init__(self):
        self.pruned_calls, self.conn = [], type("C", (), {"rollback": lambda self: None})()

    def upsert_resources(self, account, resources):
        return {}

    def current_timestamp(self):
        return "scan-start"

    def prune_resources(self, account, rtype, ids, regions=None, scan_started_at=None):
        assert scan_started_at == "scan-start"  # every prune is bounded by the scan start
        self.pruned_calls.append((account, rtype, set(ids), regions))
        return [{"resource_id": "gone", "resource_name": "gone"}]

    def upsert_findings(self, findings):
        pass

    def update_compliance_score(self, account, score):
        pass

    def close(self):
        pass


def _collector(rtype, ids, complete=True, raises=False, opt_in=True, regions=None):
    class C(BaseCollector):
        def get_resource_type(self):
            return rtype

        def collect(self):
            if raises:
                raise RuntimeError("AccessDenied")
            if opt_in:
                self.existing_ids = set(ids)
                self.listing_complete = complete
                self.listed_regions = regions
            return []
    return C


def _run(monkeypatch, *collector_classes):
    db = FakeDb()
    monkeypatch.setattr(scanner_mod, "_discover",
                        lambda pkg, base: list(collector_classes) if base is BaseCollector else [])
    monkeypatch.setattr(scanner_mod, "calculate_score", lambda findings: {"failed": 0})
    s = object.__new__(scanner_mod.Scanner)
    s.cloud_account_id, s.aws, s.db = "acct-1", None, db
    result = s.run()
    return db.pruned_calls, result


def test_complete_listing_is_pruned_for_its_own_type_and_account(monkeypatch):
    calls, result = _run(monkeypatch, _collector("s3-bucket", {"arn:aws:s3:::a", "arn:aws:s3:::b"}))
    assert calls == [("acct-1", "s3-bucket", {"arn:aws:s3:::a", "arn:aws:s3:::b"}, None)]
    assert result["resources_pruned"] == 1


@pytest.mark.parametrize("collector", [
    _collector("dynamodb-table", {"arn:t1"}, complete=False),  # a region or describe failed
    _collector("rds-instance", set()),                          # empty listing
    _collector("s3-bucket", {"x"}, raises=True),                # listing call itself failed
    _collector("kms-key", {"k1"}, opt_in=False),                # collector did not opt in
], ids=["incomplete", "empty", "collector-error", "no-opt-in"])
def test_nothing_is_pruned_without_a_complete_listing(monkeypatch, collector):
    calls, result = _run(monkeypatch, collector)
    assert calls == [] and result["resources_pruned"] == 0


def test_s3_bucket_with_unreadable_config_is_still_kept(monkeypatch):
    class FakeS3:
        def list_buckets(self):
            return {"Buckets": [{"Name": "ok-bucket"}, {"Name": "locked-bucket"}]}

    c = S3Collector(type("A", (), {"get_client": lambda self, *a, **k: FakeS3()})())
    monkeypatch.setattr(c, "_get_region", lambda s3, name: "eu-west-1")

    def config(s3, name):
        if name == "locked-bucket":
            raise RuntimeError("AccessDenied")
        return {}
    monkeypatch.setattr(c, "_get_config", config)

    resources = c.collect()
    assert [r["resource_name"] for r in resources] == ["ok-bucket"]
    assert c.existing_ids == {"arn:aws:s3:::ok-bucket", "arn:aws:s3:::locked-bucket"}
    assert c.listing_complete is True


class _Paginator:
    def __init__(self, names, fail):
        self.names, self.fail = names, fail

    def paginate(self):
        if self.fail:
            raise RuntimeError("region unreachable")
        return [{"TableNames": self.names}]


def _ddb_collector(per_region):
    class Client:
        def __init__(self, region):
            self.region, self.cfg = region, per_region.get(region, {"names": [], "fail": False, "describe_fail": set()})

        def get_paginator(self, op):
            return _Paginator(self.cfg["names"], self.cfg["fail"])

        def describe_table(self, TableName):
            if TableName in self.cfg.get("describe_fail", set()):
                raise RuntimeError("throttled")
            return {"Table": {"TableArn": f"arn:{self.region}:{TableName}"}}

        def describe_continuous_backups(self, TableName):
            return {"ContinuousBackupsDescription": {"PointInTimeRecoveryDescription": {}}}

    return DynamoDBCollector(type("A", (), {"get_client": lambda self, svc, region=None: Client(region)})())


def test_dynamodb_complete_listing_reports_every_table_arn():
    c = _ddb_collector({"eu-west-1": {"names": ["t1", "t2"], "fail": False}})
    c.collect()
    assert c.existing_ids == {"arn:eu-west-1:t1", "arn:eu-west-1:t2"} and c.listing_complete is True


def test_dynamodb_unreachable_region_marks_listing_incomplete():
    c = _ddb_collector({"eu-west-1": {"names": ["t1"], "fail": False}, "eu-north-1": {"names": [], "fail": True}})
    c.collect()
    assert c.listing_complete is False


def test_dynamodb_failed_describe_marks_listing_incomplete():
    c = _ddb_collector({"eu-west-1": {"names": ["t1", "t2"], "fail": False, "describe_fail": {"t2"}}})
    c.collect()
    assert c.listing_complete is False and c.existing_ids == {"arn:eu-west-1:t1"}


def test_regional_listing_passes_its_regions_to_pruning(monkeypatch):
    calls, _ = _run(monkeypatch, _collector("rds-instance", {"arn:aws:rds:eu-west-1:1:db:a"}, regions={"eu-west-1"}))
    assert calls[0][3] == {"eu-west-1"}


def _rds_collector(instances):
    from collectors.aws.rds.collector import RDSCollector

    class Client:
        def get_paginator(self, op):
            return type("P", (), {"paginate": lambda self: [{"DBInstances": instances}]})()
    return RDSCollector(type("A", (), {"get_client": lambda self, *a, **k: Client()})())


def test_rds_listing_covers_only_its_region_and_uses_arns():
    c = _rds_collector([{"DBInstanceIdentifier": "db1", "DBInstanceArn": "arn:aws:rds:eu-west-1:1:db:db1"}])
    c.collect()
    assert c.existing_ids == {"arn:aws:rds:eu-west-1:1:db:db1"}
    assert c.listed_regions == {"eu-west-1"} and c.listing_complete is True


def test_rds_instance_without_arn_blocks_pruning():
    c = _rds_collector([{"DBInstanceIdentifier": "db1"}])
    c.collect()
    assert c.listing_complete is False


def test_dynamodb_table_without_arn_blocks_pruning():
    class Client:
        def get_paginator(self, op):
            return _Paginator(["t1"], False)

        def describe_table(self, TableName):
            return {"Table": {}}

        def describe_continuous_backups(self, TableName):
            return {"ContinuousBackupsDescription": {}}
    c = DynamoDBCollector(type("A", (), {"get_client": lambda self, svc, region=None: Client()})())
    c.collect()
    assert c.listing_complete is False and c.existing_ids == set()


def test_dynamodb_records_only_regions_it_could_list():
    c = _ddb_collector({"eu-west-1": {"names": ["t1"], "fail": False}, "eu-north-1": {"names": [], "fail": True}})
    c.collect()
    assert c.listed_regions == {"eu-west-1"}


class _SqlCursor:
    def __init__(self, log):
        self.log = log

    def execute(self, q, params=None):
        self.log.append((q, params))

    def fetchall(self):
        return []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_prune_sql_is_scoped_to_account_type_regions_and_scan_start():
    import importlib
    try:
        database = importlib.import_module("config.database")
        Database = database.Database
        if Database is object:
            raise ImportError
    except ImportError:
        pytest.skip("real psycopg2 not available in this environment")
    log = []
    db = object.__new__(Database)
    db.conn = type("Conn", (), {"cursor": lambda self: _SqlCursor(log), "commit": lambda self: None})()
    db.prune_resources("acct-1", "rds-instance", {"arn:a"}, {"eu-west-1"}, scan_started_at="T0")
    q, params = log[0]
    assert "cloud_account_id = %s AND resource_type = %s" in q
    assert "last_scanned_at IS NOT NULL AND last_scanned_at < %s" in q
    assert params == ("acct-1", "rds-instance", ["arn:a"], ["eu-west-1"], ["eu-west-1"], ["eu-west-1"], "T0")
    with pytest.raises(ValueError):
        db.prune_resources("acct-1", "rds-instance", {"arn:a"}, None)
