"""Every compliance-framework mapper must be internally consistent — the real invariants behind the
'no fabricated compliance data' rule: each control maps to real technical checks, or is honestly
listed as manual evidence with a reason — never both, never silently empty."""
import importlib
import pkgutil

import pytest

import collectors.aws.scanner as scanner_pkg

pytestmark = [pytest.mark.flow("E2E-CMP-002"), pytest.mark.severity("P1")]
SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def _mappers():
    out = []
    for m in sorted(pkgutil.iter_modules(scanner_pkg.__path__), key=lambda x: x.name):
        if m.name.endswith("_mapper_handler"):
            mod = importlib.import_module(f"collectors.aws.scanner.{m.name}")
            names = [n for n in dir(mod) if n.endswith("_MAPPING")]
            if names:
                out.append((m.name, mod, getattr(mod, names[0])))
    return out


MAPPERS = _mappers()
IDS = [n for n, _, _ in MAPPERS]


def test_all_framework_mappers_were_discovered():
    assert len(MAPPERS) >= 25, f"expected the full framework set, found {len(MAPPERS)}: {IDS}"


@pytest.mark.parametrize("name,mod,mapping", MAPPERS, ids=IDS)
def test_every_control_has_title_valid_severity_and_real_checks(name, mod, mapping):
    assert mapping, f"{name} has an empty mapping"
    for control_id, c in mapping.items():
        assert c.get("title"), f"{name}:{control_id} has no title"
        assert c.get("severity") in SEVERITIES, f"{name}:{control_id} severity {c.get('severity')!r}"
        checks = c.get("checks")
        assert isinstance(checks, (list, tuple)) and checks, f"{name}:{control_id} maps to no technical checks"
        assert all(isinstance(x, str) and x.strip() for x in checks), f"{name}:{control_id} has blank check ids"
        assert len(set(checks)) == len(checks), f"{name}:{control_id} lists a check twice"


@pytest.mark.parametrize("name,mod,mapping", MAPPERS, ids=IDS)
def test_manual_evidence_controls_are_honest_and_disjoint_from_automated(name, mod, mapping):
    manual = getattr(mod, "MANUAL_EVIDENCE_CONTROLS", None)
    if manual is None:
        pytest.skip("mapper declares no manual-evidence controls")
    manual_ids = set()
    for entry in manual:
        control_id, reason = entry[0], entry[2]
        assert reason and len(reason) > 10, f"{name}:{control_id} manual control has no honest reason"
        manual_ids.add(control_id)
    overlap = manual_ids & set(mapping)
    assert not overlap, f"{name}: {sorted(overlap)} are both auto-mapped and manual"


@pytest.mark.parametrize("name,mod,mapping", MAPPERS, ids=IDS)
def test_mapper_exposes_a_lambda_entrypoint(name, mod, mapping):
    assert callable(getattr(mod, "handler", None)) or callable(getattr(mod, "lambda_handler", None))
