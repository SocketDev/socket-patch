#!/usr/bin/env python3
"""Print the capstones one vlt-compatibility install-proof row still runs.

A suite is left out when ci.yml's `e2e` job (which runs on every pull
request, main push and the nightly schedule) has a row for the identical
cell: same suite, OS and vlt release, the default Node, the same store
linker, no cache root and, for mode_migration_vlt (the one suite that reads
it), the same upgrade vlt. Everything else runs here.
"""

import argparse
import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github" / "workflows" / "ci.yml"
UPGRADE_SUITE = "mode_migration_vlt"


def load_reader():
    path = ROOT / "scripts" / "tests" / "test_ci_vlt_rows.py"
    spec = importlib.util.spec_from_file_location("ci_rows", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def proof_upgrade(vlt, node):
    """The upgrade vlt install-proof gives a row (its `Install vlt` step)."""
    if node:
        return ""
    m = re.fullmatch(r"0\.0\.0-(\d+)|1\.0\.0-rc\.(\d+)", vlt)
    if m and (int(m.group(1)) >= 19 if m.group(1) else int(m.group(2)) <= 14):
        return "1.2.0"
    return ""


def ci_cells(text=None):
    reader = load_reader()
    rows = reader.job_rows(reader.jobs(text if text is not None else CI.read_text(encoding="utf-8")), "e2e")
    return {(r["suite"], r["os"], r["vlt"], r.get("vlt_store_linker", ""), r.get("vlt_upgrade", ""))
            for r in rows if r.get("vlt") and r.get("test_filter") == "--include-ignored vlt_pinned_matrix"}


def remaining(suites, os_name, vlt, node="", linker="", cache_root="", text=None):
    if node or cache_root:
        return list(suites)
    cells = ci_cells(text)
    upgrade = proof_upgrade(vlt, node)
    keep = []
    for suite in suites:
        want_upgrade = upgrade if suite == UPGRADE_SUITE else None
        covered = any(s == suite and o == os_name and v == vlt and lk == linker
                      and (want_upgrade is None or up == want_upgrade)
                      for s, o, v, lk, up in cells)
        if not covered:
            keep.append(suite)
    return keep


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--os", required=True)
    ap.add_argument("--vlt", required=True)
    ap.add_argument("--node", default="")
    ap.add_argument("--linker", default="")
    ap.add_argument("--cache-root", default="")
    ap.add_argument("suites", nargs="+")
    args = ap.parse_args(argv)
    keep = remaining(args.suites, args.os, args.vlt, args.node, args.linker, args.cache_root)
    for suite in args.suites:
        if suite not in keep:
            print(f"{suite}: run by ci.yml's e2e row for this cell", file=sys.stderr)
    print(" ".join(keep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
