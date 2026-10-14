"""Which critical flows does a change touch?  (issue #279: "a pull request modifies a critical workflow -> the relevant tests run")

    python tests/tools/select_tests.py [--base origin/main] [--files a.py b.py]

Prints a comma-separated list of flow ids for `pytest --flows ...`, or ALL when the change touches shared plumbing
(the test framework, workflows, dependencies) or a path no flow claims — so nothing is ever silently skipped.
P0 tests run regardless (see tests/conftest.py)."""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ALWAYS_ALL = ("tests/conftest.py", "tests/tools/", "tests/registry/", ".github/", "amplify.yml", "pytest.ini", "requirements")
IGNORED = ("docs/", "README", ".md", "stage-portfolio/", "frontend/package", "package-lock.json")


def changed_files(base):
    out = subprocess.run(["git", "diff", "--name-only", f"{base}...HEAD"], cwd=ROOT, capture_output=True, text=True).stdout
    return [l.strip().replace("\\", "/") for l in out.splitlines() if l.strip()]


def _claims(pattern, path):
    """A flow path is a file, a folder prefix, or (for the many framework mappers) a shared file-name suffix."""
    if pattern.endswith("_mapper_handler.py"):
        return path.endswith("_mapper_handler.py")
    return path == pattern or path.startswith(pattern)


def select(files, flows):
    """(flow ids, reason). `flows` is the registry list."""
    if not files:
        return "ALL", "no changed files could be determined"
    picked, unclaimed = set(), []
    for f in files:
        if any(f.startswith(p) or f == p or (p in f and p in ('requirements',)) for p in ALWAYS_ALL):
            return "ALL", f"{f} is shared test/CI plumbing"
        if any(i in f for i in IGNORED):
            continue
        hit = [fl["id"] for fl in flows if any(_claims(p, f) for p in fl.get("paths", []) if p)]
        if hit:
            picked.update(hit)
        else:
            unclaimed.append(f)
    if unclaimed:
        return "ALL", f"no flow claims {unclaimed[0]}"
    return (",".join(sorted(picked)) or "NONE"), ("matched by flow paths" if picked else "only documentation changed; P0 tests still run")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="origin/main")
    ap.add_argument("--files", nargs="*")
    a = ap.parse_args()
    flows = json.loads((ROOT / "tests" / "registry" / "critical_flows.json").read_text(encoding="utf-8"))["flows"]
    sel, why = select(a.files if a.files is not None else changed_files(a.base), flows)
    print(sel)
    print(f"# {why}", file=sys.stderr)


if __name__ == "__main__":
    main()
