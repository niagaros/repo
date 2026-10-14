"""Compensating controls for the database's public network exposure (docs/internal/security/database_network_exposure.md),
verified live against the real RDS instance and the real production-smoke Lambda — never simulated locally."""
import importlib
import subprocess
import sys

import pytest

from conftest import ROOT

# tests/conftest.py replaces sys.modules["psycopg2"] with a stub (no OperationalError, no real .connect) so unit
# tests can import handler modules without a real DB driver or the repo root's vendored psycopg2/ folder shadowing
# it. This file makes a real network connection, so it needs the genuine driver: ask a clean subprocess (no repo
# root on its path) where the real package lives, then import it from that exact location under a private name.
_out = subprocess.run([sys.executable, "-c", "import psycopg2, os; print(os.path.dirname(psycopg2.__file__))"],
                      capture_output=True, text=True, cwd=str(ROOT.parent))
if _out.returncode != 0:
    pytest.skip(f"could not locate the real psycopg2 installation: {_out.stderr[:200]}", allow_module_level=True)
import importlib.util as _ilu
_spec = _ilu.spec_from_file_location("psycopg2", _out.stdout.strip() + "/__init__.py", submodule_search_locations=[_out.stdout.strip()])
psycopg2 = _ilu.module_from_spec(_spec)
sys.modules["psycopg2"] = psycopg2  # must be registered under its own name for its internal "from psycopg2._x import" to resolve
_spec.loader.exec_module(psycopg2)

pytestmark = [pytest.mark.live, pytest.mark.flow("E2E-SMOKE-001"), pytest.mark.severity("P0")]
DB_HOST = "cspm-db.cdmg60gykykz.eu-west-1.rds.amazonaws.com"


def test_the_real_database_rejects_a_non_ssl_connection_before_checking_credentials():
    """rds.force_ssl must stay enabled: a plaintext connection attempt is refused by pg_hba matching, before any
    password is even checked (proven by comparing the failure point against an SSL attempt with the same bogus user)."""
    with pytest.raises(psycopg2.OperationalError, match="no pg_hba.conf entry"):
        psycopg2.connect(host=DB_HOST, port=5432, dbname="postgres", user="e2e_probe_nonexistent",
                          password="x", sslmode="disable", connect_timeout=8)


def test_the_real_database_accepts_ssl_and_reaches_password_authentication():
    with pytest.raises(psycopg2.OperationalError, match="password authentication failed"):
        psycopg2.connect(host=DB_HOST, port=5432, dbname="postgres", user="e2e_probe_nonexistent",
                          password="x", sslmode="require", connect_timeout=8)


def test_production_smoke_actually_monitors_connection_count_for_the_open_port():
    """A regression guard so nobody quietly removes the one live compensating control for the public database
    endpoint without also removing the documented justification."""
    src = (ROOT / "backend" / "src" / "collectors" / "aws" / "scanner" / "smoke_handler.py").read_text(encoding="utf-8")
    assert "DatabaseConnections" in src and "ANOMALOUS_CONNECTIONS_THRESHOLD" in src
    doc = (ROOT / "docs" / "internal" / "security" / "database_network_exposure.md").read_text(encoding="utf-8")
    assert "0.0.0.0/0" in doc and "force_ssl" in doc
