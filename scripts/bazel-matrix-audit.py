#!/usr/bin/env python3
"""Audit the real-Bazel cell reports: what ran, and what may be claimed.

Every test of e2e_bazel_build writes one JSON report per cell
(tests/bazel_build_common/probe_report.rs). A test that printed SKIP still
passes for libtest, so a green job proves nothing by itself: only a report
of status `ran` does. This script reads a directory of reports and fails
when

  * a report is not a report (unreadable, no test, a status other than
    `ran` / `skipped`);
  * a `ran` report lacks the hosts it contacted, its wall time or its list
    of lanes, or its hosts did not come from the fixture server's request
    log (`hosts_source`; `none` only with an empty list, and never in a
    report that names a lane);
  * a `ran` report resolved a ruleset to another version than its fixture
    pins in MATRIX.json (a baseline must resolve every pin). The pins are
    those of the fixture that lists the test on the report's Bazel release:
    one test may be listed under two fixtures on different releases;
  * `--require a,b`: a `ran` report lacks one of those fields;
  * `--tiers pr|full`: a test the matrices plan for that run has no `ran`
    report on its Bazel release and runner (`--cell ID`: that cell alone).
    Over a whole run a record-only cell is only listed, never an error;
  * `--claims FILE`: a claim of `lanes::claims_json()` has no evidence.

A claim is `{lane, mode, ruleset, tier, lo, hi, system, os, classes, anchor,
stale, tool, bump}` (version 2 of the document): the lane runs on Bazel `lo`
to `hi` under one dependency system. `classes`, `anchor`, `stale` and `tool`
say what the lane may write and are printed for the reviewer of a claim;
this audit requires them. `bump` is the test that ran the lane's bump cell
(the user bumps the package and does not run socket-patch), or null. A lane
whose `classes` hold `hook` or `tag_edit` leaves wiring in the user's files,
so its claim needs that test, by a name that holds `_bump`, and a `ran`
report of it that names the lane under the claim's system, on a release
inside the claim, with its hosts taken from the fixture server's log. The
claim itself is held to the pinned
releases CI can run (scripts/bazel-pins.txt) and to the Bazel lines of
DESIGN 8, which are the majors, except that under Bzlmod (and hybrid) 7.0
and 7.1 are each a line of their own beside 7.2 - 7.x: their lock is of
another family, and DESIGN 8 gives them their own cells (7.0.2 and 7.1.2).
`hi` must be a pinned release, every line the range reaches must have a
pinned release inside the range, and the newest such release of each line
needs a `ran` report that names the lane (`lanes` in the report) under that
system, with its hosts taken from the fixture server's log, on each OS the
claim lists (on any OS while it lists none). A claim above its evidence, or
over a line with no cell, fails. A release that is not the newest of its
line inside the range needs no report: 8.4.2 is pinned for one ruleset.

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
LOGGED = "fixture_server_log"
HOSTS_SOURCES = (LOGGED, "none")
# The (major, minor) at which a line of DESIGN 8 starts inside a major, per
# dependency system: 7.0 - 7.1 Bzlmod is Beta on the family-A lock, with the
# cells 7.0.2 and 7.1.2, and 7.2 - 7.7 is Supported. Section 8 splits no
# WORKSPACE line below the major.
LINE_STARTS = {"bzlmod": ((7, 1), (7, 2)), "hybrid": ((7, 1), (7, 2))}
CLAIM_KEYS = ("lane", "mode", "ruleset", "tier", "lo", "hi", "system", "os",
              "classes", "anchor", "stale", "tool", "bump")
# The version `lanes::claims_json()` writes. Version 1 had no write classes,
# anchor, staleness behaviour or tool; no lane was ever claimed in it.
CLAIMS_VERSION = 2
# The write classes that leave wiring in a file of the user's: what it does
# after a bump of the package is proven by the lane's bump cell (rev4/ARCH.md
# 2.7 and 2.8), and a claim of such a lane stands only with its report.
BUMP_CLASSES = ("hook", "tag_edit")


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


def pins_by_cell(fixtures=None):
    """{(test, Bazel): (pins, baseline?)} from the light and heavy matrices,
    keyed the way the planner keys an entry (bazel-matrix.py refuses a test
    listed twice on one Bazel and runner, not one listed under two
    fixtures): a lane test under an e9 and an e7 fixture is held to the
    pins of the fixture whose cells name the report's Bazel release."""
    found = {}
    for _, doc in matrix.matrices(fixtures or matrix.FIXTURES):
        for fixture in doc.get("fixtures", []) if isinstance(doc, dict) else []:
            pins = fixture.get("pins", {})
            for cell in fixture.get("cells", []):
                found[(fixture.get("test"), cell.get("bazel"))] = (pins, True)
            for lane in fixture.get("lanes", []):
                for cell in lane.get("cells", []):
                    found.setdefault((lane.get("test"), cell.get("bazel")), (pins, False))
    return found


def pins_of(report, pins):
    """((pins, baseline?), error) for a `ran` report: the pins of the
    fixture that lists its test on its Bazel release. A test no fixture
    lists (the toy, the harness) has none. A release no fixture lists the
    test on (a local run off the matrix) is held to the pins all its
    fixtures agree on; where they pin different versions nothing says
    which fixture it built, and that is an error, not a pass."""
    test, bazel = report["test"], report.get("bazel")
    if (test, bazel) in pins:
        return pins[(test, bazel)], None
    others = [value for (name, _), value in pins.items() if name == test]
    if not others:
        return ({}, False), None
    if all(pinned == others[0][0] for pinned, _ in others):
        return (others[0][0], any(baseline for _, baseline in others)), None
    listed = ", ".join(sorted(str(release) for name, release in pins if name == test))
    return ({}, False), (f"ran {test} on Bazel {bazel}, where no MATRIX.json lists it (listed on "
                         f"{listed}, under fixtures with different pins): its resolved versions "
                         "can be held to no pin")


def names_lane(report, lane):
    """Whether the report's `lanes` holds exactly this lane id. A string
    would also answer `in`, for any substring of it."""
    lanes = report.get("lanes")
    return isinstance(lanes, list) and lane in lanes


def report_errors(report, required, pins):
    """What is wrong with one `ran` report."""
    errors, name = [], report["_file"]
    hosts = report.get("hosts")
    if not isinstance(hosts, list) or not all(isinstance(h, str) for h in hosts):
        errors.append(f"{name}: no `hosts` list: the report does not say what the cell contacted")
    lanes = report.get("lanes")
    if not isinstance(lanes, list) or not all(isinstance(lane, str) for lane in lanes):
        errors.append(f"{name}: `lanes` is {lanes!r}, not a list of lane ids")
        lanes = []
    source = report.get("hosts_source")
    if source not in HOSTS_SOURCES:
        errors.append(f"{name}: `hosts_source` is {source!r}: the hosts must come from the "
                      "fixture server's request log (Report::hosts_from_log)")
    elif source != LOGGED:
        if hosts:
            errors.append(f"{name}: lists hosts {hosts} that no fixture server logged")
        # A test that started no fixture server names no host and no lane.
        # A lane test serves its packages, so its report reads the log.
        if lanes:
            errors.append(f"{name}: names the lanes {lanes} with `hosts_source` {source!r}: a "
                          "report is evidence for a lane only with its hosts taken from the "
                          "fixture server's request log (Report::hosts_from_log)")
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
    (wanted, baseline), unpinned = pins_of(report, pins)
    if unpinned:
        errors.append(f"{name}: {unpinned}")
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


def line_name(start, end):
    (major, minor), (next_major, next_minor) = start, end
    if (next_major, next_minor) == (major + 1, 0):
        return f"{major}.x" if minor == 0 else f"{major}.{minor} - {major}.x"
    if (next_major, next_minor) == (major, minor + 1):
        return f"{major}.{minor}.x"
    return f"{major}.{minor} - {next_major}.{next_minor - 1}.x"


def lines_of(lo, hi, system):
    """[(name, first, end)] of the Bazel lines of DESIGN 8 that a claim from
    `lo` to `hi` (version keys) reaches under `system`, oldest first. A line
    holds the versions from `first` up to, not including, `end`: a major,
    or a part of one where `LINE_STARTS` splits it for the system."""
    majors = range(lo[0], hi[0] + 2)
    starts = sorted({(major, 0) for major in majors}
                    | {start for start in LINE_STARTS.get(system, ()) if start[0] in majors})
    found = []
    for start, end in zip(starts, starts[1:]):
        # Below every release and pre-release of that minor.
        first, after = start + (0, 0, ()), end + (0, 0, ())
        if lo < after and first <= hi:
            found.append((line_name(start, end), first, after))
    return found


def bump_errors(claim, what, lo, hi, reports):
    """What a claim of a lane that writes a hook or a tag edit lacks: the
    `ran` report of its bump cell. `lo` and `hi` are the claim's version
    keys."""
    classes = claim["classes"]
    if not isinstance(classes, list) or not all(isinstance(name, str) for name in classes):
        return [f"{what}: `classes` {classes!r} is not a list of write classes"]
    marked = [name for name in classes if name in BUMP_CLASSES]
    if not marked:
        return []
    wrote = " and ".join(f"`{name}`" for name in marked)
    test = claim["bump"]
    if not isinstance(test, str) or "_bump" not in test:
        return [f"{what}: lists the write class {wrote} and names no bump cell (`bump` is "
                f"{test!r}): what its wiring does after a bump of the package is not proven"]
    inside = [r for r in reports if r["test"] == test and r["status"] == "ran"
              and names_lane(r, claim["lane"]) and r.get("system") == claim["system"]
              and version_key(r.get("bazel")) is not None
              and lo <= version_key(r.get("bazel")) <= hi]
    if not inside:
        return [f"{what}: no `ran` report of its bump cell `{test}` names the lane under "
                f"{claim['system']} on a release inside the claim"]
    if not any(r.get("hosts_source") == LOGGED for r in inside):
        files = ", ".join(sorted(r["_file"] for r in inside))
        return [f"{what}: no `ran` report of its bump cell `{test}` took its hosts from the "
                f"fixture server's log: {files} did not read the log (`hosts_source`), so it "
                "proves nothing"]
    return []


def claim_errors(doc, reports, pins):
    """What the claims document states without evidence."""
    if (not isinstance(doc, dict) or doc.get("version") != CLAIMS_VERSION
            or not isinstance(doc.get("claims"), list)):
        return [f'the claims file is not `{{"version": {CLAIMS_VERSION}, "claims": [...]}}`']
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
        errors += bump_errors(claim, what, lo, hi, reports)
        inside = [v for v in releases if lo <= version_key(v) <= hi]
        for name, first, after in lines_of(lo, hi, claim["system"]):
            line = [v for v in inside if first <= version_key(v) < after]
            if not line:
                errors.append(f"{what}: spans Bazel {name}, where no pinned release lies "
                              "inside the range")
                continue
            for os_name in claim["os"] or [None]:
                where = (f"on Bazel {line[-1]} under {claim['system']} on {os_name or 'any OS'}"
                         f" (the newest pinned release of Bazel {name} inside the claim)")
                named = [r for r in reports if r["status"] == "ran"
                         and names_lane(r, claim["lane"])
                         and r.get("bazel") == line[-1] and r.get("system") == claim["system"]
                         and os_name in (None, r.get("os"))]
                if not named:
                    errors.append(f"{what}: no `ran` report names the lane {where}")
                elif not any(r.get("hosts_source") == LOGGED for r in named):
                    files = ", ".join(sorted(r["_file"] for r in named))
                    errors.append(f"{what}: no `ran` report with hosts from the fixture "
                                  f"server's log names the lane {where}: {files} did not read "
                                  "the log (`hosts_source`), so it proves nothing")
    return errors


def audit(directory, required=(), tiers=None, cell=None, claims=None, fixtures=None):
    """(errors, notes, summary) for the reports under `directory`."""
    reports, errors = read_reports(directory)
    pins = pins_by_cell(fixtures)
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
