#!/usr/bin/env python3
"""Audit the real-Bazel cell reports: what ran, and what may be claimed.

Every test of e2e_bazel_build writes one JSON report per cell
(tests/bazel_build_common/probe_report.rs). A test that printed SKIP still
passes for libtest, so a green job proves nothing by itself: only a report
of status `ran` does. This script reads a directory of reports and fails
when

  * a report is not a report (unreadable, no test, a status other than
    `ran` / `skipped`);
  * a `ran` report lacks the hosts it contacted or its wall time, or its
    hosts did not come from the fixture server's request log
    (`hosts_source`; `none` only with an empty list);
  * a `ran` report resolved a ruleset to another version than the
    MATRIX.json of its fixture pins (a baseline must resolve every pin);
  * `--require a,b`: a `ran` report lacks one of those fields;
  * `--tiers pr|full`: a test the matrices plan for that run has no `ran`
    report on its Bazel release and runner (`--cell ID`: that cell alone).
    Over a whole run a record-only cell is only listed, never an error;
  * `--claims FILE`: a claim of `lanes::claims_json()` has no evidence.

A claim is `{lane, mode, ruleset, tier, lo, hi, system, os}`: the lane runs
on Bazel `lo` to `hi` under one dependency system. It is held to the pinned
releases CI can run (scripts/bazel-pins.txt): `hi` must be one, every major
the range spans must have one inside it, and the newest of each needs a
`ran` report that names the lane (`lanes` in the report) under that system,
on each OS the claim lists (on any OS while it lists none). A claim above
its evidence, or over a line with no cell, fails.

  bazel-matrix-audit.py --reports DIR [--require hosts,wall_ms,resolved]
                        [--tiers pr|full [--cell ID]] [--claims FILE]
"""

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
STATUSES = ("ran", "skipped")
# The fields of a report (probe_report.rs `Report::to_json`).
FIELDS = ("test", "status", "reason", "bazel", "os", "arch", "group", "system", "lanes", "hosts",
          "hosts_source", "direct_network", "wall_ms", "resolved", "details")
HOSTS_SOURCES = ("fixture_server_log", "none")
CLAIM_KEYS = ("lane", "mode", "ruleset", "tier", "lo", "hi", "system", "os")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


matrix = load("bazel_matrix", SCRIPTS / "bazel-matrix.py")
OSES = tuple(os_name for os_name, _ in matrix.RUNNERS.values())


def version_key(text):
    """An order over Bazel versions in which a pre-release is below its
    release (`10.0.0rc3` < `10.0.0`); None for anything else."""
    found = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:(rc|-pre\.)([0-9.]+))?", text or "")
    if not found:
        return None
    numbers = tuple(int(n) for n in found.group(1, 2, 3))
    if found.group(4) is None:
        return numbers + (1, ())
    return numbers + (0, tuple(int(n) for n in found.group(5).split(".") if n))


def read_reports(directory):
    """([report], [error]) of every `*.json` under `directory`."""
    reports, errors = [], []
    for path in sorted(Path(directory).rglob("*.json")):
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            errors.append(f"{path.name}: unreadable: {e}")
            continue
        if not isinstance(report, dict) or not isinstance(report.get("test"), str):
            errors.append(f"{path.name}: not a cell report (no `test`)")
        elif report.get("status") not in STATUSES:
            errors.append(f"{path.name}: status {report.get('status')!r} is neither `ran` nor `skipped`")
        else:
            reports.append(dict(report, _file=path.name))
    return reports, errors


def pins_by_test(fixtures=None):
    """{test: (pins, baseline?)} from the light and heavy matrices."""
    found = {}
    for _, doc in matrix.matrices(fixtures or matrix.FIXTURES):
        for fixture in doc.get("fixtures", []) if isinstance(doc, dict) else []:
            pins = fixture.get("pins", {})
            found[fixture.get("test")] = (pins, True)
            for lane in fixture.get("lanes", []):
                found.setdefault(lane.get("test"), (pins, False))
    return found


def report_errors(report, required, pins):
    """What is wrong with one `ran` report."""
    errors, name = [], report["_file"]
    hosts = report.get("hosts")
    if not isinstance(hosts, list) or not all(isinstance(h, str) for h in hosts):
        errors.append(f"{name}: no `hosts` list: the report does not say what the cell contacted")
    source = report.get("hosts_source")
    if source not in HOSTS_SOURCES:
        errors.append(f"{name}: `hosts_source` is {source!r}: the hosts must come from the "
                      "fixture server's request log (Report::hosts_from_log)")
    elif source == "none" and hosts:
        errors.append(f"{name}: lists hosts {hosts} that no fixture server logged")
    wall = report.get("wall_ms")
    if not isinstance(wall, int) or isinstance(wall, bool) or wall < 0:
        errors.append(f"{name}: no `wall_ms`")
    if version_key(report.get("bazel")) is None:
        errors.append(f"{name}: `bazel` is {report.get('bazel')!r}, not a Bazel version")
    if report.get("os") not in OSES:
        errors.append(f"{name}: `os` is {report.get('os')!r}, not one of {', '.join(OSES)}")
    for field in required:
        if report.get(field) is None:
            errors.append(f"{name}: no `{field}` field")
    resolved = report.get("resolved")
    wanted, baseline = pins.get(report["test"], ({}, False))
    if wanted and not isinstance(resolved, dict):
        errors.append(f"{name}: no `resolved` versions for a fixture that pins {wanted}")
    for ruleset, pin in (wanted.items() if isinstance(resolved, dict) else ()):
        got = resolved.get(ruleset)
        if got != pin and (baseline or got is not None):
            errors.append(f"{name}: resolved {ruleset} to {got}, MATRIX.json pins {pin}")
    return errors


def planned_errors(reports, tiers, cell=None):
    """([error], [note]): the planned tests of the run (or of one cell)
    that have no `ran` report on their Bazel release and runner."""
    broken = matrix.check()
    if broken:
        return [f"the matrices cannot be planned: {error}" for error in broken], []
    cells = matrix.plan(matrix.entries(), tiers, matrix.suite_tests())
    if cell is not None:
        cells = [c for c in cells if c["id"] == cell]
        if not cells:
            return [f"no cell `{cell}` in the {'/'.join(tiers)} plan"], []
    errors, notes = [], []
    for planned in cells:
        os_name = matrix.RUNNERS[planned["os"]][0]
        for test in planned["tests"]:
            here = [r for r in reports if r["test"] == test and r.get("os") == os_name
                    and r.get("bazel") in (planned["bazel"], None)]
            if any(r["status"] == "ran" and r.get("bazel") == planned["bazel"] for r in here):
                continue
            why = "; ".join(sorted({f"skipped: {r.get('reason')}" for r in here})) or "no report"
            line = f"{planned['id']}: {test} did not run ({why})"
            # A record-only cell is evidence when it runs and no gate when
            # it does not; asked about by itself it is held like any other.
            (notes if planned["record_only"] and cell is None else errors).append(line)
    return errors, notes


def claim_errors(doc, reports, pins):
    """What the claims document states without evidence."""
    if not isinstance(doc, dict) or doc.get("version") != 1 or not isinstance(doc.get("claims"), list):
        return ['the claims file is not `{"version": 1, "claims": [...]}`']
    releases = sorted({version for version, _ in pins}, key=version_key)
    errors = []
    for claim in doc["claims"]:
        if not isinstance(claim, dict) or any(key not in claim for key in CLAIM_KEYS):
            errors.append(f"claim {claim!r}: needs {', '.join(CLAIM_KEYS)}")
            continue
        what = f"{claim['lane']} ({claim['system']}, {claim['lo']} to {claim['hi']})"
        lo, hi = version_key(claim["lo"]), version_key(claim["hi"])
        if lo is None or hi is None or lo > hi or claim["system"] not in matrix.SYSTEMS:
            errors.append(f"{what}: not a line range under a dependency system")
            continue
        if not isinstance(claim["os"], list) or any(name not in OSES for name in claim["os"]):
            errors.append(f"{what}: `os` {claim['os']!r} is not a list of {', '.join(OSES)}")
            continue
        if claim["hi"] not in releases:
            errors.append(f"{what}: {claim['hi']} is not a pinned release, so no cell ran at "
                          "the top of the claim")
            continue
        inside = [v for v in releases if lo <= version_key(v) <= hi]
        for major in range(lo[0], hi[0] + 1):
            line = [v for v in inside if version_key(v)[0] == major]
            if not line:
                errors.append(f"{what}: spans Bazel {major}.x, where no pinned release lies "
                              "inside the range")
                continue
            for os_name in claim["os"] or [None]:
                proof = [r for r in reports if r["status"] == "ran"
                         and claim["lane"] in (r.get("lanes") or [])
                         and r.get("bazel") == line[-1] and r.get("system") == claim["system"]
                         and os_name in (None, r.get("os"))]
                if not proof:
                    errors.append(f"{what}: no `ran` report names the lane on Bazel {line[-1]}"
                                  f" under {claim['system']} on {os_name or 'any OS'}")
    return errors


def audit(directory, required=(), tiers=None, cell=None, claims=None, fixtures=None):
    """(errors, notes, summary) for the reports under `directory`."""
    reports, errors = read_reports(directory)
    pins = pins_by_test(fixtures)
    ran = [r for r in reports if r["status"] == "ran"]
    for report in ran:
        errors += report_errors(report, required, pins)
    notes = []
    if tiers is not None:
        missing, notes = planned_errors(reports, tiers, cell)
        errors += missing
    if claims is not None:
        errors += claim_errors(claims, reports, matrix.pinned())
    direct = sum(1 for r in ran if r.get("direct_network"))
    summary = (f"{len(reports)} reports: {len(ran)} ran ({direct} with direct network), "
               f"{len(reports) - len(ran)} skipped")
    return errors, notes, summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--reports", type=Path, required=True, help="the directory of cell reports")
    ap.add_argument("--require", default="", help="comma-separated fields every `ran` report must carry")
    ap.add_argument("--tiers", choices=("pr", "full"), help="hold the reports to the plan of that run")
    ap.add_argument("--cell", help="with --tiers: only this cell of the plan")
    ap.add_argument("--claims", type=Path, help="the JSON `lanes::claims_json()` wrote")
    args = ap.parse_args(argv)
    required = [field for field in args.require.split(",") if field]
    unknown = [field for field in required if field not in FIELDS]
    if unknown:
        ap.error(f"--require names no report field: {', '.join(unknown)}")
    if args.cell and not args.tiers:
        ap.error("--cell needs --tiers")
    if not args.reports.is_dir():
        print(f"bazel-matrix-audit: {args.reports} is not a directory", file=sys.stderr)
        return 1
    claims = None
    if args.claims is not None:
        try:
            claims = json.loads(args.claims.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            print(f"bazel-matrix-audit: {args.claims}: {e}", file=sys.stderr)
            return 1
    tiers = None if args.tiers is None else (("pr",) if args.tiers == "pr" else matrix.TIERS)
    errors, notes, summary = audit(args.reports, required, tiers, args.cell, claims)
    for note in notes:
        print(f"bazel-matrix-audit: record-only: {note}")
    for error in errors:
        print(f"bazel-matrix-audit: {error}", file=sys.stderr)
    print(f"bazel-matrix-audit: {'FAILED' if errors else 'ok'} ({summary})")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
