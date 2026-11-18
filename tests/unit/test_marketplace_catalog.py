"""Marketplace catalog (#90): every entry is well-formed, and nothing is offered as connectable unless Niagaros really
has the connector and the setup page it links to."""
import re
from pathlib import Path

import pytest

from collectors.aws.scanner import marketplace_lib as M

pytestmark = [pytest.mark.flow("E2E-MKT-001"), pytest.mark.severity("P2")]

ROOT = Path(__file__).resolve().parents[2]
ISSUE_CATEGORIES_COVERED = ("Cloud Infrastructure", "Identity & Access Management", "CI/CD & DevOps", "Ticketing & ITSM",
                            "Compliance & GRC", "SIEM & Log Management", "SOAR & Automation", "SSPM", "Version Control",
                            "Vulnerability Management", "Threat Detection & Intelligence", "Data Security", "Network Security")
OBJECTS = {"Assets", "Users", "Identities", "Vulnerabilities", "Risks", "Security findings", "Compliance controls",
           "Evidence", "Audit findings", "Vendors", "Incidents", "Tickets"}


def test_catalog_has_300_plus_unique_entries_across_the_categories_of_the_issue():
    cat = M.catalog()
    assert len(cat) >= 340
    assert len({e["slug"] for e in cat}) == len(cat)
    cats = {e["category"] for e in cat}
    assert set(ISSUE_CATEGORIES_COVERED) <= cats and len(cats) >= 30
    for e in cat:
        assert e["name"] and e["vendor"] and e["delivers"] and e["objects"], e
        assert set(e["objects"]) <= OBJECTS, (e["name"], e["objects"])
        assert e["status"] in M.STATUSES


def test_only_real_connectors_are_available_and_have_real_detail():
    available = [e for e in M.catalog() if e["status"] == "Available"]
    assert {e["slug"] for e in available} == set(M.FIRST_PARTY)
    main = (ROOT / "frontend/src/main.tsx").read_text(encoding="utf-8")
    for e in available:
        d = e["detail"]
        for key in ("auth_method", "permissions", "security", "revoke", "setup", "data_types", "last_updated", "code"):
            assert d.get(key), (e["name"], key)
        assert re.match(r"^\d{4}-\d{2}-\d{2}$", d["last_updated"])
        page = d["setup"]["page"]
        if page.startswith("/"):
            assert f'path="{page}"' in main, page
        else:
            assert (ROOT / "frontend/public" / page).exists(), page
        for path in d["code"].split(", "):
            assert (ROOT / path).exists(), path
    for e in M.catalog():
        if e["status"] != "Available":
            # Not built: no guessed permissions, auth or frameworks.
            assert e["detail"] is None and e["certification"] is None


def test_aws_lists_every_mapped_framework_and_github_its_benchmark():
    s = M.by_slug()
    import ast
    src = (ROOT / "backend/src/config/database.py").read_text(encoding="utf-8")
    node = next(n for n in ast.parse(src).body if isinstance(n, ast.Assign) and n.targets[0].id == "MAPPED_FRAMEWORK_NAMES")
    assert ast.literal_eval(node.value) == M.MAPPED_FRAMEWORK_NAMES
    assert set(M.MAPPED_FRAMEWORK_NAMES) <= set(s["amazon-web-services"]["detail"]["frameworks"])
    assert s["github"]["detail"]["frameworks"] == ["CIS GitHub Benchmark v1.0.0"]


def test_an_available_entry_without_a_connector_is_refused(tmp_path):
    p = tmp_path / "c.csv"
    p.write_text("name,vendor,category,delivers,niagaros_objects,status\n"
                 "Okta,Okta,Identity & Access Management,Users,Users,Available\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no connector"):
        M.load_catalog(p)


def test_recommended_slugs_exist():
    s = M.by_slug()
    for slug in ("jira", "monday-com", "slack", "microsoft-teams", "discord", "custom-webhook", "github", "okta",
                 "microsoft-entra-id", "google-workspace"):
        assert slug in s
