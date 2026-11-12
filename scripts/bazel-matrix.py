#!/usr/bin/env python3
"""Plan the real-Bazel CI cells from the fixture matrices.

bazel-compatibility.yml's matrix is generated, not hand-written: its `plan`
job runs this script, which reads every
crates/socket-patch-cli/tests/fixtures/bazel/**/MATRIX.json and prints the
cells of the event. A package adds a cell by editing the MATRIX.json of its
own fixtures, and nobody edits the workflow.

Each fixture package wrote its own MATRIX.json shape, and the Rust suite
parses each one strictly, so this script reads them as they are:

  core    {"filter", "cells": [{"bazel", "os": [..], "tier": {os: tier},
          "network"}], "tests": {name: {"system", "bazel": [..], "os"?}}}
  light   {"group", "ruleset", "fixtures": [{"path", "test", "system",
          "pins", "fetch"?, "cells": [{"bazel", "proof", "tier"}],
          "lanes"?: [{"test", "cells"}]}]}
  heavy   as light, with "fixture" (relative to fixtures/bazel) for "path"

A file of another shape is refused: a matrix this script cannot read would
otherwise plan nothing and look covered.

An entry is one test on one Bazel release on one runner. Its tier is `pr`
(the path-filtered pull-request run and every wider run) or `nightly`
(schedule, dispatch, and a pull request labelled `bazel-matrix`). The light
and heavy matrices give one tier per (fixture, Bazel) and name no runner;
`runner_tiers` holds the table of DESIGN 9.5 that says where each runs.

A cell is one CI job: every entry of one (group, Bazel, runner, mode), where
the mode is the test-name prefix (`bazel_core_`, `bazel_guard_`,
`bazel_agent_`, `bazel_hosted_`, `bazel_vendor_`, `bazel_canary_`). Its
libtest filter is `--exact` with the full path of each test, so a cell runs
the tests its matrices list and no other: a prefix would also run the
nightly tests of the same mode in the pull-request tier.

  bazel-matrix.py --check
      Hold the matrices to the rules below and to the suite's sources.
  bazel-matrix.py --event E [--labels JSON] [--github-output FILE]
      Print the plan of the event as JSON; with --github-output write
      `cells`, `extras`, `build` and `tiers` for the workflow instead, and
      print one line per cell.

Rules of --check (scripts/tests/test_bazel_matrix.py runs them too): every
entry's test is an `#[ignore]` test of e2e_bazel_build and every such test
has an entry; every (Bazel, runner) is pinned in scripts/bazel-pins.txt;
every (fixture, Bazel) pair is in the era table; no rules_jvm_external
entry is `pr` above proof tier 0; no Go or Rust entry is `pr` without a
restored repository cache; a fixture whose packages a tool fetches says
`"fetch": "tool"`.
"""

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "crates" / "socket-patch-cli" / "tests"
FIXTURES = TESTS / "fixtures" / "bazel"
PINS = ROOT / "scripts" / "bazel-pins.txt"
SUITE = "e2e_bazel_build"
# The label that selects the whole matrix on a pull request.
LABEL = "bazel-matrix"
TIERS = ("pr", "nightly")
SYSTEMS = ("bzlmod", "workspace", "hybrid")
# Runner label: the `os` a cell report carries (`std::env::consts::OS`),
# and the platform its Bazel must be pinned for.
RUNNERS = {
    "ubuntu-latest": ("linux", "linux-x86_64"),
    "macos-latest": ("macos", "darwin-arm64"),
    "windows-latest": ("windows", "windows-x86_64"),
}
# It alone writes absolute file:/// registry keys into MODULE.bazel.lock.
NEVER_PINNED = "7.7.0"
# The releases whose light and heavy cells run on all three runners every
# night (DESIGN 9.5); every other pinned line runs on ubuntu.
NIGHTLY_ON_EVERY_RUNNER = ("7.7.2", "8.8.2", "9.3.2")
# (group, mode, Bazel): the runners beside ubuntu whose cell is in the
# pull-request tier when the entry is.
PR_ALSO = {("light", "hosted", "9.3.2"): ("windows-latest",)}
# Modes whose result is recorded and never gates: a canary tells when an
# assumption stops holding.
RECORD_ONLY_MODES = ("canary",)
# The matrices whose fetch needs a language toolchain even at proof tier 0
# (the 65 MB Go SDK; 121.5 MB from static.rust-lang.org and cargo-bazel).
GO_RUST = ("gazelle", "gazelle_directory", "gazelle_workspace", "rules_rust", "rules_rs")

# Real-Bazel tests of the harness itself. They open no fixture, so no
# MATRIX.json can list them; each runs on ubuntu every night, record-only.
# The tree-artifact canary covers the pinned lines on which the toy test of
# the same rule (bazel_core_probe_rule_takes_a_tree_artifact) is not claimed.
HARNESS_TESTS = {
    "bazel_canary_probe_rule_tree_artifact": {
        "group": "core",
        "bazel": ("5.4.1", "6.6.0", "7.0.2", "7.1.2", "8.4.2", "10.0.0rc3"),
    },
}

B, W, BW = ("bzlmod",), ("workspace",), ("bzlmod", "workspace")
# The era table of DESIGN 9.2: ruleset release -> Bazel release -> the
# dependency systems the pairing is planned on. A pairing is one a probe
# ran, or one the table marks unverified (its baseline canary is then the
# first evidence). Two rows are not in 9.2 as written and are probe cells:
# rules_rust 0.75.0 on 7.7.2 (rules-rust R1, R2: m75-b7) and rules_js 1.39.1
# on 7.0.2 / 7.1.2 (rules-js J1, B2; RECONCILE wp-fixtures-light item 3).
ERAS = {
    "aspect_rules_js": {
        "3.6.0": {"9.3.2": B, "8.8.2": B},
        "2.9.3": {"8.8.2": W, "7.7.2": BW},
        "1.42.3": {"7.1.2": B, "7.0.2": B, "6.6.0": BW},
        "1.39.1": {"7.1.2": B, "7.0.2": B, "6.6.0": B},
    },
    "rules_python": {
        "2.5.0-rc4": {"9.3.2": B, "8.8.2": B, "7.7.2": B},
        "1.4.2": {"7.7.2": BW},
        "1.3.0": {"7.7.2": B},
        "0.31.0": {"7.1.2": B, "7.0.2": B, "6.6.0": BW},
        "0.27.0": {"5.4.1": W},
    },
    "aspect_rules_py": {
        "2.0.0-alpha.10": {"9.3.2": B, "8.8.2": B},
        "1.13.0": {"9.3.2": B, "8.8.2": B},
        "1.8.4": {"8.8.2": B},
    },
    "rules_pycross": {"2.0.1": {"9.3.2": B, "8.8.2": B}, "0.8.3": {"9.3.2": B, "8.8.2": B}},
    "rules_jvm_external": {
        "7.2": {"9.3.2": B, "8.8.2": B, "7.7.2": B},
        "6.10": {"8.8.2": B},
        "6.5": {"7.7.2": B},
        "5.3": {"6.6.0": W},
        "4.5": {"5.4.1": W},
    },
    "gazelle": {
        "2.0.0-beta.2": {"9.3.2": B},
        "0.54.0": {"9.3.2": B, "8.8.2": B},
        "0.45.0": {"7.7.2": B},
        "0.37.0": {"7.1.2": B, "7.0.2": B},
        "0.36.0": {"7.7.2": B},
        "0.35.0": {"8.8.2": BW, "7.7.2": BW, "6.6.0": BW},
        "0.34.0": {"5.4.1": W},
    },
    "rules_go": {
        "0.65.0": {"9.3.2": B, "8.8.2": B},
        "0.53.0": {"7.7.2": B},
        "0.46.0": {"7.7.2": B},
        "0.44.0": {"8.8.2": BW, "7.7.2": BW, "6.6.0": BW},
        "0.42.0": {"5.4.1": W},
    },
    "rules_rust": {
        "0.75.0": {"9.3.2": B, "8.8.2": B, "7.7.2": B},
        "0.57.1": {"7.7.2": B},
        "0.56.0": {"7.7.2": B},
        "0.49.3": {"6.6.0": W},
    },
    "rules_rs": {"0.2.2": {"9.3.2": B, "8.8.2": B}, "0.0.112": {"8.4.2": B}},
    "rules_ruby": {
        "1.0.0-rc2": {"9.3.2": B, "8.8.2": B, "7.1.2": B},
        "0.21.1": {"7.7.2": W},
        "0.16.0": {"7.0.2": B, "6.6.0": W},
    },
    "rules_dotnet": {"0.22.2": {"9.3.2": B, "8.8.2": B}, "0.14.0": {"7.7.2": B}},
    "rules_csharp": {"0.5.0": {"9.3.2": B, "8.8.2": B}},
}
# Matrix `ruleset` -> the pins the era table is asked about. A fixture also
# pins what its ruleset builds on (rules_python under aspect_rules_py),
# which has no era of its own.
SUBJECTS = {
    "rules_js": ("aspect_rules_js",),
    "rules_jvm_external": ("rules_jvm_external",),
    "rules_ruby": ("rules_ruby",),
    "rules_dotnet": ("rules_dotnet",),
    "rules_csharp": ("rules_csharp",),
    "rules_python": ("rules_python",),
    "rules_python_uv": ("rules_python",),
    "aspect_rules_py": ("aspect_rules_py",),
    "rules_pycross": ("rules_pycross",),
    "gazelle": ("gazelle", "rules_go"),
    "gazelle_directory": ("gazelle", "rules_go"),
    "gazelle_workspace": ("gazelle", "rules_go"),
    "rules_rust": ("rules_rust",),
    "rules_rs": ("rules_rs",),
}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bundle = load("ci_e2e_bundle", ROOT / "scripts" / "ci-e2e-bundle.py")
PREFIXES = bundle.BAZEL_SUITE_PREFIXES[SUITE]


class MatrixError(Exception):
    """A MATRIX.json this script cannot read as one of its three shapes."""


def mode_of(test):
    """`bazel_hosted_x` -> `hosted`; None for a name outside the six prefixes."""
    for prefix in PREFIXES:
        if test.startswith(prefix):
            return prefix[len("bazel_"):-1]
    return None


def pinned(path=PINS):
    """{(Bazel version, platform)} of scripts/bazel-pins.txt."""
    rows = (line.split() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#"))
    return {(row[1], row[2]) for row in rows if row[0] == "bazel"}


def runner_tiers(group, mode, bazel, tier):
    """{runner: tier} of a light or heavy entry, which names one tier and no
    runner. Every night it runs on ubuntu, and on macOS and Windows too when
    it is a lane test on one of the three Supported releases; `pr` moves the
    ubuntu cell (and the PR_ALSO ones) into the pull-request tier. Nothing
    is left out for want of a pin: an entry no runner can install is an
    error of `--check`, never a cell that silently plans nothing."""
    everywhere = bazel in NIGHTLY_ON_EVERY_RUNNER and mode not in RECORD_ONLY_MODES
    runners = {runner: "nightly" for runner in (RUNNERS if everywhere else ("ubuntu-latest",))}
    if tier == "pr":
        for runner in ("ubuntu-latest",) + PR_ALSO.get((group, mode, bazel), ()):
            runners[runner] = "pr"
    return runners


def need(holder, key, kind, where):
    value = holder.get(key) if isinstance(holder, dict) else None
    if not isinstance(value, kind) or isinstance(value, bool):
        raise MatrixError(f"{where}: `{key}` is missing or not a {kind.__name__}")
    return value


def entry(matrix, group, ruleset, test, system, bazel, runner, tier, **more):
    base = {"matrix": matrix, "group": group, "ruleset": ruleset, "test": test, "system": system,
            "bazel": bazel, "os": runner, "tier": tier, "proof": None, "cache": "", "network": ""}
    return {**base, **more}


def read_core(doc, matrix):
    """The entries of the core shape: a test runs on every runner of each
    cell of a release it names, or on those of its own `os` list."""
    group, prefix = need(doc, "group", str, matrix), need(doc, "filter", str, matrix)
    cells = need(doc, "cells", list, matrix)
    out = []
    for name, claim in need(doc, "tests", dict, matrix).items():
        where = f"{matrix}: {name}"
        if not name.startswith(prefix):
            raise MatrixError(f"{where}: not a `{prefix}` test")
        scope = claim.get("os")
        for bazel in need(claim, "bazel", list, where):
            rows = [cell for cell in cells if cell.get("bazel") == bazel]
            if not rows:
                raise MatrixError(f"{where}: no cell on Bazel {bazel}")
            for cell in rows:
                tiers = need(cell, "tier", dict, f"{matrix}: cell {bazel}")
                for runner in need(cell, "os", list, f"{matrix}: cell {bazel}"):
                    if scope is not None and runner not in scope:
                        continue
                    if runner not in tiers:
                        raise MatrixError(f"{matrix}: cell {bazel} names no tier for {runner}")
                    out.append(entry(matrix, group, "", name, need(claim, "system", str, where),
                                     bazel, runner, tiers[runner],
                                     network=need(cell, "network", str, f"{matrix}: cell {bazel}")))
    return out


def read_fixtures(doc, matrix):
    """The entries of the light and heavy shapes: the baseline of each
    fixture and the lane tests listed under it, on the runners
    `runner_tiers` gives each (fixture, Bazel) cell."""
    group, ruleset = need(doc, "group", str, matrix), need(doc, "ruleset", str, matrix)
    out = []
    for fixture in need(doc, "fixtures", list, matrix):
        path = fixture.get("fixture") or f"{group}/{ruleset}/{fixture.get('path', '')}"
        where = f"{matrix}: {path}"
        system = need(fixture, "system", str, where)
        claims = [fixture] + fixture.get("lanes", [])
        for claim in claims:
            test = need(claim, "test", str, where)
            for cell in need(claim, "cells", list, f"{where}: {test}"):
                at = f"{where}: {test}"
                bazel, tier = need(cell, "bazel", str, at), need(cell, "tier", str, at)
                proof, mode = need(cell, "proof", int, at), mode_of(test)
                if tier not in TIERS:
                    raise MatrixError(f"{at}: `{tier}` is no tier ({', '.join(TIERS)})")
                for runner, runs in runner_tiers(group, mode, bazel, tier).items():
                    out.append(entry(matrix, group, ruleset, test, system, bazel, runner, runs,
                                     proof=proof, cache=cell.get("cache", ""), fixture=path,
                                     # A baseline fetches its ruleset from the real origins.
                                     network="direct" if mode in RECORD_ONLY_MODES else "cache"))
    return out


def matrices(fixtures=FIXTURES):
    """[(relative path, document)] of every MATRIX.json under `fixtures`."""
    found = []
    for path in sorted(fixtures.rglob("MATRIX.json")):
        rel = path.relative_to(fixtures).as_posix()
        try:
            found.append((rel, json.loads(path.read_text(encoding="utf-8"))))
        except ValueError as e:
            raise MatrixError(f"{rel}: not JSON: {e}") from e
    return found


def harness_entries():
    return [entry("(harness)", spec["group"], "", test, "any", bazel, "ubuntu-latest", "nightly",
                  network="direct")
            for test, spec in HARNESS_TESTS.items() for bazel in spec["bazel"]]


def entries(fixtures=FIXTURES):
    """Every entry of every matrix, and the harness's own."""
    out = []
    for rel, doc in matrices(fixtures):
        if not isinstance(doc, dict):
            raise MatrixError(f"{rel}: not an object")
        if "tests" in doc and "cells" in doc:
            out += read_core(doc, rel)
        elif "fixtures" in doc:
            out += read_fixtures(doc, rel)
        else:
            raise MatrixError(f"{rel}: neither the core shape (`cells` and `tests`) nor the "
                              "fixture shape (`fixtures`)")
    return out + harness_entries()


def macro_tests(text):
    """The tests a `macro_rules!` of the suite declares: for each macro whose
    body holds `#[ignore` and `fn $name`, the names that start a line of its
    invocations (`name! {` up to the `}` at the same indentation)."""
    lines, names = text.splitlines(), []
    macros = set()
    for i, line in enumerate(lines):
        opened = re.match(r"^(\s*)macro_rules!\s*([A-Za-z_][A-Za-z0-9_]*)\s*\{", line)
        if not opened:
            continue
        body = []
        for inner in lines[i + 1:]:
            if inner.startswith(opened.group(1) + "}"):
                break
            body.append(inner)
        if any("#[ignore" in b for b in body) and any(re.search(r"\bfn \$", b) for b in body):
            macros.add(opened.group(2))
    for i, line in enumerate(lines):
        called = re.match(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)!\s*\{\s*$", line)
        if not called or called.group(2) not in macros:
            continue
        for inner in lines[i + 1:]:
            if inner.startswith(called.group(1) + "}"):
                break
            name = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\b", inner)
            if name:
                names.append(name.group(1))
    return names


def suite_tests(tests=TESTS):
    """{test name: its libtest path} for every `#[ignore]` test of the
    suite, a macro's included. The path is `<module>::<name>`, which is what
    `--exact` compares."""
    found = {}
    for path in bundle.suite_files(SUITE, tests):
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(tests / SUITE).with_suffix("")
        parts = [p for p in rel.parts if p not in ("main", "mod")]
        for name in bundle.ignored_tests(text) + macro_tests(text):
            if name in found:
                raise MatrixError(f"{SUITE}: two tests are named {name}")
            found[name] = "::".join(parts + [name])
    return found


def fetches_by_tool(ruleset, fixture):
    """Whether Bazel's downloader never sees the fixture's packages: pip
    mode (rules_python below 2.x, and every WORKSPACE `pip_parse`),
    crate_universe (cargo-bazel's cargo), an unpinned Coursier hub and the
    legacy package-manager rules. The fake Socket API then hands out a
    loopback origin, which the matrix must say."""
    if ruleset in ("rules_rust", "rules_nodejs") or "loopback_repository" in fixture:
        return True
    if ruleset != "rules_python":
        return False
    major = re.match(r"\d+", str(fixture.get("pins", {}).get("rules_python", "")))
    return fixture.get("system") == "workspace" or major is None or int(major.group()) < 2


def fixture_errors(fixtures=FIXTURES):
    """What the light and heavy matrices state against the rules of DESIGN
    9.2 and 9.5: eras, the pull-request tier, the fetch path."""
    errors = []
    for rel, doc in matrices(fixtures):
        if "fixtures" not in doc:
            continue
        ruleset = doc.get("ruleset", "")
        subjects = SUBJECTS.get(ruleset)
        if subjects is None:
            errors.append(f"{rel}: ruleset `{ruleset}` has no row in the era table")
            continue
        for fixture in doc["fixtures"]:
            path = fixture.get("fixture") or fixture.get("path", "")
            where, pins = f"{rel}: {path}", fixture.get("pins", {})
            system = fixture.get("system")
            if fetches_by_tool(ruleset, fixture) and fixture.get("fetch") != "tool":
                errors.append(f"{where}: a tool fetches its packages, not Bazel's downloader: "
                              'say `"fetch": "tool"`')
            for claim in [fixture] + fixture.get("lanes", []):
                for cell in claim.get("cells", []):
                    bazel, at = cell.get("bazel"), f"{where}: {claim.get('test')} on {cell.get('bazel')}"
                    for name in subjects:
                        eras = ERAS[name].get(pins.get(name), {})
                        if system not in eras.get(bazel, ()):
                            errors.append(f"{at}: {name} {pins.get(name)} under {system} is not "
                                          "a pairing of the era table (DESIGN 9.2)")
                    if cell.get("tier") != "pr":
                        continue
                    if ruleset == "rules_jvm_external" and cell.get("proof", 0) > 0:
                        errors.append(f"{at}: a rules_jvm_external cell of the pull-request "
                                      "tier stops at proof tier 0 (a build through @maven// "
                                      "pulls a JDK)")
                    if ruleset in GO_RUST and cell.get("cache") != "restored":
                        errors.append(f"{at}: a Go or Rust cell is in the pull-request tier "
                                      'only with a restored repository cache (`"cache": '
                                      '"restored"`)')
    return errors


def entry_errors(found, pins, tests):
    """What the entries state against the pins file and the suite."""
    errors, seen = [], set()
    for e in found:
        where = f"{e['matrix']}: {e['test']} on {e['bazel']} / {e['os']}"
        if e["os"] not in RUNNERS:
            errors.append(f"{where}: `{e['os']}` is no runner ({', '.join(RUNNERS)})")
            continue
        if e["tier"] not in TIERS:
            errors.append(f"{where}: `{e['tier']}` is no tier ({', '.join(TIERS)})")
        if e["system"] not in SYSTEMS + ("any",):
            errors.append(f"{where}: `{e['system']}` is no dependency system")
        if e["bazel"] == NEVER_PINNED:
            errors.append(f"{where}: Bazel {NEVER_PINNED} is never pinned")
        elif (e["bazel"], RUNNERS[e["os"]][1]) not in pins:
            errors.append(f"{where}: no pin for Bazel {e['bazel']} on {RUNNERS[e['os']][1]} "
                          "in scripts/bazel-pins.txt")
        if mode_of(e["test"]) is None:
            errors.append(f"{where}: the name starts with none of {', '.join(PREFIXES)}")
        if e["test"] not in tests:
            errors.append(f"{where}: {SUITE} has no `#[ignore]` test of that name")
        key = (e["test"], e["bazel"], e["os"])
        if key in seen:
            errors.append(f"{where}: listed twice")
        seen.add(key)
    listed = {e["test"] for e in found}
    for name in sorted(set(tests) - listed):
        errors.append(f"{SUITE}: `{name}` is in no MATRIX.json, so no cell runs it")
    return errors


def check(fixtures=FIXTURES, pins=None, tests=None):
    """Every reason the matrices cannot be planned as they stand."""
    pins = pinned() if pins is None else pins
    try:
        found = entries(fixtures)
        tests = suite_tests() if tests is None else tests
    except MatrixError as e:
        return [str(e)]
    return entry_errors(found, pins, tests) + fixture_errors(fixtures)


def tiers_of(event, labels=()):
    """The tiers an event runs: the pull-request tier for a pull request,
    everything for the nightly, a dispatch and a pull request that carries
    the label (which stands in for a dispatch while the workflow is not on
    the default branch)."""
    if event == "pull_request" and LABEL not in labels:
        return ("pr",)
    return TIERS


def cell_id(e):
    return "-".join((e["group"], e["bazel"], e["os"].split("-")[0], mode_of(e["test"])))


def plan(found, tiers, tests):
    """The cells of a run: [{id, name, job, group, bazel, os, mode, filter,
    tests, record_only, cache, timeout}], sorted by id."""
    cells = {}
    for e in found:
        if e["tier"] in tiers:
            cells.setdefault(cell_id(e), []).append(e)
    out = []
    for key in sorted(cells):
        members = sorted(cells[key], key=lambda e: e["test"])
        first, mode = members[0], mode_of(members[0]["test"])
        prerelease = re.fullmatch(r"\d+\.\d+\.\d+", first["bazel"]) is None
        record_only = mode in RECORD_ONLY_MODES or prerelease
        # DESIGN 9.5: 30 minutes, Windows 60. A baseline cell builds every
        # fixture of its group on the line, each from a cold cache.
        slow = first["os"] == "windows-latest" or (record_only and first["group"] != "core")
        # A cell on a restored repository cache: a core line whose module
        # archives are not committed, and every lane cell of a ruleset. A
        # canary stays cold, or it could not tell when a pinned URL rots.
        restore = any(e["network"] in ("archives", "cache") for e in members)
        out.append({
            "id": key,
            "name": f"{first['group']} / {first['bazel']} / {first['os'].split('-')[0]} / {mode}",
            "job": "extras" if record_only else "cells",
            "group": first["group"],
            "bazel": first["bazel"],
            "os": first["os"],
            "mode": mode,
            "filter": " ".join(["--exact"] + [tests[e["test"]] for e in members]),
            "tests": [e["test"] for e in members],
            "record_only": "true" if record_only else "",
            "cache": "restore" if restore else "",
            "timeout": 60 if slow else 30,
        })
    return out


def compact(value):
    """One line of JSON: a workflow output is a single line."""
    return json.dumps(value, separators=(",", ":"))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="only validate the matrices")
    ap.add_argument("--event", help="pull_request, schedule or workflow_dispatch")
    ap.add_argument("--labels", default="[]", help="the pull request's label names, as a JSON list")
    ap.add_argument("--github-output", type=Path, help="append the workflow outputs to this file")
    args = ap.parse_args(argv)
    errors = check()
    for error in errors:
        print(f"bazel-matrix: {error}", file=sys.stderr)
    if errors:
        return 1
    found, tests = entries(), suite_tests()
    if args.check:
        full = plan(found, TIERS, tests)
        print(f"bazel-matrix: ok ({len(matrices())} matrices, {len(found)} entries, "
              f"{len(full)} cells, {len(plan(found, ('pr',), tests))} in the pull-request tier)")
        return 0
    if not args.event:
        ap.error("--event is required unless --check")
    try:
        # `null` off pull_request: `toJSON` of a context that is not there.
        labels = json.loads(args.labels) or []
    except ValueError:
        ap.error(f"--labels is not JSON: {args.labels!r}")
    if not isinstance(labels, list):
        ap.error(f"--labels is not a JSON list: {args.labels!r}")
    tiers = tiers_of(args.event, labels)
    cells = plan(found, tiers, tests)
    doc = {"tiers": "full" if "nightly" in tiers else "pr", "cells": cells}
    if not args.github_output:
        print(json.dumps(doc, indent=2))
    else:
        for cell in cells:
            print(f"bazel-matrix: {cell['job']}: {cell['id']} ({len(cell['tests'])} tests)")
        # The matrix rows carry scalars only: the tests of a cell are
        # recomputed from its id where they are needed.
        rows = [{k: v for k, v in cell.items() if k != "tests"} for cell in cells]
        with args.github_output.open("a", encoding="utf-8") as out:
            out.write(f"tiers={doc['tiers']}\n")
            for job in ("cells", "extras"):
                out.write(f"{job}={compact([row for row in rows if row['job'] == job])}\n")
            out.write(f"build={compact(sorted({row['os'] for row in rows}))}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
