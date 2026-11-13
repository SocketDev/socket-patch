"""scripts/bazel-matrix-audit.py: a claim, and a planned cell, stand only on
a report of status `ran`. Every case writes its own reports into a temp
directory; the plans and pins are the checkout's. No test here runs Bazel."""

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


audit = load("bazel_matrix_audit", ROOT / "scripts" / "bazel-matrix-audit.py")
matrix = audit.matrix
FULL = matrix.plan(matrix.entries(), matrix.TIERS, matrix.suite_tests())
PR = matrix.plan(matrix.entries(), ("pr",), matrix.suite_tests())
PINS = audit.pins_by_cell()
BASELINE = "bazel_canary_baseline_rules_js_bzlmod_e9"   # light/rules_js: aspect_rules_js 3.6.0


def report(test="bazel_core_zero_network", bazel="9.3.2", os_name="linux", system="bzlmod", **more):
    """A report as probe_report.rs writes one for a test that ran."""
    base = {"test": test, "status": "ran", "reason": None, "bazel": bazel, "os": os_name,
            "arch": "x86_64", "group": "core", "system": system, "lanes": [],
            "hosts": ["patch.socket.dev", "registry.toy.invalid"], "hosts_source": "fixture_server_log",
            "direct_network": False, "wall_ms": 4200, "resolved": {}, "details": {}}
    return {**base, **more}


def skipped(test, why="not a bzlmod test", **more):
    return report(test, status="skipped", reason=why, hosts=[], hosts_source="none", **more)


def cell_reports(cell, **more):
    """A sound report for each test of a planned cell, whatever the cell:
    a test under a fixture resolved what the fixture pins."""
    return [report(test, cell["bazel"], matrix.RUNNERS[cell["os"]][0],
                   **{"resolved": dict(PINS.get((test, cell["bazel"]), ({}, False))[0]), **more})
            for test in cell["tests"]]


class Audit(unittest.TestCase):
    def run_audit(self, reports, **options):
        """(errors, notes) of an audit over `reports` (dicts, or raw text)."""
        with tempfile.TemporaryDirectory() as tmp:
            for i, item in enumerate(reports):
                text = item if isinstance(item, str) else json.dumps(item)
                (Path(tmp) / f"r{i:03}.json").write_text(text, encoding="utf-8")
            errors, notes, _ = audit.audit(tmp, **options)
            return errors, notes

    def assert_one(self, errors, text):
        self.assertEqual(len(errors), 1, errors)
        self.assertIn(text, errors[0])


class Reports(Audit):
    def test_sound_reports_pass(self):
        self.assertEqual(self.run_audit([report(), skipped("bazel_core_x")]), ([], []))
        # A test that started no fixture server reports no host.
        self.assertEqual(self.run_audit([report(hosts=[], hosts_source="none")])[0], [])

    def test_negative_a_file_that_is_no_report(self):
        self.assert_one(self.run_audit(["{"])[0], "unreadable")
        self.assert_one(self.run_audit(['["ran"]'])[0], "not a cell report")
        self.assert_one(self.run_audit([report(status="passed")])[0], "neither `ran` nor `skipped`")

    def test_negative_a_ran_report_without_hosts_or_wall_time(self):
        for field in ("hosts", "wall_ms"):
            with self.subTest(field=field):
                lacking = report()
                del lacking[field]
                self.assert_one(self.run_audit([lacking])[0], f"no `{field}`")
        self.assert_one(self.run_audit([report(wall_ms=None)])[0], "no `wall_ms`")
        self.assert_one(self.run_audit([report(bazel="latest")])[0], "not a Bazel version")
        self.assert_one(self.run_audit([report(os_name="freebsd")])[0], "`os` is 'freebsd'")
        # A skipped report is held to none of this: it claims nothing.
        self.assertEqual(self.run_audit([skipped("bazel_core_x", bazel=None, wall_ms=None)])[0], [])

    def test_negative_hosts_that_did_not_come_from_the_fixture_server_log(self):
        self.assert_one(self.run_audit([report(hosts_source="none")])[0], "no fixture server logged")
        unsourced = report()
        del unsourced["hosts_source"]
        self.assert_one(self.run_audit([unsourced])[0], "`hosts_source` is None")
        self.assert_one(self.run_audit([report(hosts_source="by hand")])[0], "`hosts_source` is 'by hand'")

    def test_negative_a_report_that_names_a_lane_without_the_fixture_server_log(self):
        """The harness cannot write a host list without reading a server's
        log, so the one way to a `ran` report with no log is to never call
        `hosts_from_log`: an empty list beside `none`. That is what a test
        with no fixture server reports, and it is no evidence for a lane."""
        unlogged = dict(hosts=[], hosts_source="none")
        self.assertEqual(self.run_audit([report(**unlogged)])[0], [])
        self.assert_one(self.run_audit([report(lanes=["H-JS1"], **unlogged)])[0],
                        "names the lanes ['H-JS1'] with `hosts_source` 'none'")
        self.assertEqual(self.run_audit([report(lanes=["H-JS1"])])[0], [])
        # A skipped report proves nothing and is not asked.
        self.assertEqual(self.run_audit([skipped("bazel_hosted_x", lanes=["H-JS1"])])[0], [])

    def test_negative_lanes_that_are_no_list_of_lane_ids(self):
        for lanes in ("H-JS1", None, {"H-JS1": True}, ["H-JS1", 7]):
            with self.subTest(lanes=lanes):
                self.assert_one(self.run_audit([report(lanes=lanes)])[0], "not a list of lane ids")
        absent = report()
        del absent["lanes"]
        self.assert_one(self.run_audit([absent])[0], "`lanes` is None")

    def test_negative_a_required_field_is_missing(self):
        lacking = report()
        del lacking["resolved"]
        self.assertEqual(self.run_audit([lacking])[0], [])
        self.assert_one(self.run_audit([lacking], required=["resolved"])[0], "no `resolved` field")
        self.assertEqual(self.run_audit([report()], required=["hosts", "wall_ms", "resolved"])[0], [])

    def test_negative_a_resolved_version_differs_from_the_pin(self):
        pinned = {"aspect_rules_js": "3.6.0"}
        self.assertEqual(PINS[(BASELINE, "9.3.2")], (pinned, True))
        self.assertEqual(self.run_audit([report(BASELINE, resolved=pinned)])[0], [])
        self.assert_one(self.run_audit([report(BASELINE, resolved={"aspect_rules_js": "3.5.1"})])[0],
                        "resolved aspect_rules_js to 3.5.1, MATRIX.json pins 3.6.0")
        # A baseline must resolve every pin; saying nothing is not agreement.
        self.assert_one(self.run_audit([report(BASELINE, resolved={})])[0], "resolved aspect_rules_js to None")
        self.assert_one(self.run_audit([report(BASELINE, resolved=None)])[0], "no `resolved` versions")
        # A skipped baseline resolved nothing and is not asked.
        self.assertEqual(self.run_audit([skipped(BASELINE)])[0], [])

    LANE = "bazel_hosted_rules_js_bzlmod"

    def lane_pins(self, *fixtures):
        """`pins_by_cell` of a light/rules_js matrix with these fixtures:
        (path, canary, aspect_rules_js pin, [Bazel of the lane test])."""
        cells = lambda releases: [{"bazel": bazel, "proof": 1, "tier": "nightly"} for bazel in releases]
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "light" / "rules_js"
            target.mkdir(parents=True)
            doc = {"group": "light", "ruleset": "rules_js", "fixtures": [{
                "path": path, "test": canary, "system": "bzlmod", "pins": {"aspect_rules_js": pin},
                "cells": cells(releases), "lanes": [{"test": self.LANE, "cells": cells(releases)}]}
                for path, canary, pin, releases in fixtures]}
            (target / "MATRIX.json").write_text(json.dumps(doc), encoding="utf-8")
            # The planner takes the matrix as it is: one test under two
            # fixtures is two entries on different Bazel releases.
            known = {name: f"m::{name}" for name in [self.LANE, *matrix.HARNESS_TESTS] + [f[1] for f in fixtures]}
            self.assertEqual(matrix.check(Path(tmp), matrix.pinned(), known), [])
            return audit.pins_by_cell(Path(tmp))

    def errors_of(self, pins, **fields):
        return audit.report_errors(dict(report(self.LANE, **fields), _file="r"), [], pins)

    def test_a_lane_test_is_held_to_the_pins_only_where_it_resolved_them(self):
        """A lane test listed under a fixture need not ask `bazel mod graph`,
        but what it did resolve must be the pin."""
        pins = self.lane_pins(("bzlmod/e9", BASELINE, "3.6.0", ["9.3.2"]))
        self.assertEqual(pins[(self.LANE, "9.3.2")], ({"aspect_rules_js": "3.6.0"}, False))
        self.assertEqual(pins[(BASELINE, "9.3.2")], ({"aspect_rules_js": "3.6.0"}, True))
        self.assertEqual(self.errors_of(pins), [])
        self.assert_one(self.errors_of(pins, resolved={"aspect_rules_js": "2.9.3"}), "MATRIX.json pins 3.6.0")
        # A run on a release the matrix does not list is held to the one fixture.
        self.assert_one(self.errors_of(pins, bazel="8.8.2", resolved={"aspect_rules_js": "2.9.3"}),
                        "MATRIX.json pins 3.6.0")

    def test_a_lane_test_under_two_fixtures_is_held_to_the_pins_of_its_bazel(self):
        """One lane test on the e9 fixture (aspect_rules_js 3.6.0, Bazel
        9.3.2 and 8.8.2) and on the e7 fixture (2.9.3, Bazel 7.7.2). Keyed
        by test alone, the first fixture's pins were asked of every report:
        a correct 7.7.2 report failed and one that resolved the e9 version
        on 7.7.2 passed."""
        pins = self.lane_pins(("bzlmod/e9", BASELINE, "3.6.0", ["9.3.2", "8.8.2"]),
                              ("bzlmod/e7", "bazel_canary_baseline_rules_js_bzlmod_e7", "2.9.3", ["7.7.2"]))
        new, old = {"aspect_rules_js": "3.6.0"}, {"aspect_rules_js": "2.9.3"}
        self.assertEqual({key: value for key, value in pins.items() if key[0] == self.LANE},
                         {(self.LANE, "9.3.2"): (new, False), (self.LANE, "8.8.2"): (new, False),
                          (self.LANE, "7.7.2"): (old, False)})
        self.assertEqual(self.errors_of(pins, bazel="7.7.2", resolved=old), [])
        self.assertEqual(self.errors_of(pins, bazel="9.3.2", resolved=new), [])
        self.assertEqual(self.errors_of(pins, bazel="8.8.2", resolved=new), [])
        self.assert_one(self.errors_of(pins, bazel="7.7.2", resolved=new),
                        "resolved aspect_rules_js to 3.6.0, MATRIX.json pins 2.9.3")
        self.assert_one(self.errors_of(pins, bazel="9.3.2", resolved=old),
                        "resolved aspect_rules_js to 2.9.3, MATRIX.json pins 3.6.0")
        # On a release neither fixture lists, nothing says which one was
        # built: an error, not a report no pin is asked of.
        self.assert_one(self.errors_of(pins, bazel="7.1.2", resolved=old),
                        "on Bazel 7.1.2, where no MATRIX.json lists it (listed on 7.7.2, 8.8.2, 9.3.2")
        # Each baseline keeps its own fixture's pins.
        self.assertEqual(pins[("bazel_canary_baseline_rules_js_bzlmod_e7", "7.7.2")], (old, True))
        # A test no fixture lists (the toy, the harness) is asked for none.
        self.assertEqual(audit.report_errors(dict(report(bazel="7.1.2"), _file="r"), [], pins), [])


class Planned(Audit):
    PR_CELL = next(cell for cell in FULL if cell["id"] == "core-9.3.2-ubuntu-core")

    def test_a_cell_whose_planned_tests_all_ran_passes(self):
        reports = cell_reports(self.PR_CELL)
        self.assertEqual(self.run_audit(reports, tiers=("pr",), cell=self.PR_CELL["id"]), ([], []))
        # The whole pull-request tier: the reports of each of its cells.
        # Only a gating cell is asked for; a record-only one is listed.
        self.assertIn(self.PR_CELL["id"], [cell["id"] for cell in PR])
        gating = [r for cell in PR if not cell["record_only"] for r in cell_reports(cell)]
        errors, notes = self.run_audit(gating, tiers=("pr",))
        self.assertEqual(errors, [])
        self.assertEqual(len(notes), sum(len(cell["tests"]) for cell in PR if cell["record_only"]))
        every = [r for cell in PR for r in cell_reports(cell)]
        self.assertEqual(self.run_audit(every, tiers=("pr",)), ([], []))

    def test_negative_a_planned_test_that_skipped_or_left_no_report(self):
        reports = cell_reports(self.PR_CELL)
        gone = reports.pop(0)["test"]
        self.assert_one(self.run_audit(reports, tiers=("pr",), cell=self.PR_CELL["id"])[0],
                        f"core-9.3.2-ubuntu-core: {gone} did not run (no report)")
        # A test that printed SKIP passed for libtest; its report says why.
        reports.append(skipped(gone, "SOCKET_PATCH_BAZEL_E2E_GROUP selects light"))
        self.assert_one(self.run_audit(reports, tiers=("pr",), cell=self.PR_CELL["id"])[0],
                        "did not run (skipped: SOCKET_PATCH_BAZEL_E2E_GROUP selects light)")
        # A skip before a Bazel was found names no version; it is still this cell's.
        reports[-1] = skipped(gone, "no Bazel", bazel=None)
        self.assert_one(self.run_audit(reports, tiers=("pr",), cell=self.PR_CELL["id"])[0], "skipped: no Bazel")

    def test_negative_a_report_from_another_release_or_runner_is_no_evidence(self):
        for change in ({"bazel": "8.8.2"}, {"os_name": "macos"}):
            with self.subTest(change=change):
                reports = cell_reports(self.PR_CELL)
                first = reports[0]["test"]
                reports[0] = report(first, **{"bazel": "9.3.2", "os_name": "linux", **change})
                self.assert_one(self.run_audit(reports, tiers=("pr",), cell=self.PR_CELL["id"])[0],
                                f"{first} did not run (no report)")

    def test_negative_an_unknown_cell(self):
        self.assert_one(self.run_audit([], tiers=("pr",), cell="core-9.3.2-ubuntu-hosted")[0],
                        "no cell `core-9.3.2-ubuntu-hosted` in the pr plan")
        # The cell exists only in the full plan.
        self.assert_one(self.run_audit([], tiers=("pr",), cell="core-8.8.2-ubuntu-core")[0], "no cell")

    def test_over_a_whole_run_a_record_only_cell_is_listed_not_failed(self):
        gating = [r for cell in FULL if not cell["record_only"] for r in cell_reports(cell)]
        errors, notes = self.run_audit(gating, tiers=matrix.TIERS)
        self.assertEqual(errors, [])
        record_only = sum(len(cell["tests"]) for cell in FULL if cell["record_only"])
        self.assertGreater(record_only, 50)
        self.assertEqual(len(notes), record_only)
        # Asked about by itself, the same cell is held like any other.
        canary = next(cell for cell in FULL if cell["record_only"])
        errors, notes = self.run_audit(gating, tiers=matrix.TIERS, cell=canary["id"])
        self.assertEqual((len(errors), notes), (len(canary["tests"]), []))
        # And an empty directory passes nothing.
        errors, _ = self.run_audit([], tiers=matrix.TIERS)
        self.assertEqual(len(errors), sum(len(c["tests"]) for c in FULL if not c["record_only"]))


def claim(lane="H-TOY1", lo="7.2.0", hi="9.3.2", system="bzlmod", os_names=(), **more):
    base = {"lane": lane, "mode": "hosted", "ruleset": "rules_js", "tier": "supported",
            "lo": lo, "hi": hi, "system": system, "os": list(os_names),
            "classes": ["native_lock", "owned"], "anchor": "digest", "stale": "inert", "tool": None}
    return {**base, **more}


def claims(*rows):
    return {"version": 2, "claims": list(rows)}


def proof(bazel, os_name="macos", system="bzlmod", lanes=("H-TOY1",), **more):
    return report("bazel_hosted_toy_bzlmod", bazel, os_name, system, lanes=list(lanes), **more)


class Claims(Audit):
    def test_no_claim_needs_no_report(self):
        """The skeleton state: every lane is a disabled stub."""
        self.assertEqual(self.run_audit([], claims=claims())[0], [])
        self.assertEqual(self.run_audit([], claims=json.loads('{\n  "version": 2,\n  "claims": []\n}\n'))[0], [])

    def test_a_range_is_held_to_the_newest_pinned_release_of_each_line(self):
        reports = [proof("7.7.2"), proof("8.8.2"), proof("9.3.2")]
        self.assertEqual(self.run_audit(reports, claims=claims(claim()))[0], [])
        for missing in ("7.7.2", "8.8.2", "9.3.2"):
            with self.subTest(missing=missing):
                kept = [r for r in reports if r["bazel"] != missing]
                self.assert_one(self.run_audit(kept, claims=claims(claim()))[0],
                                f"no `ran` report names the lane on Bazel {missing} under bzlmod on any OS")
        # An older release of the line is not the line's evidence, and it
        # is not asked for either: 8.4.2 is pinned for one ruleset.
        swapped = [proof("7.7.2"), proof("8.4.2"), proof("9.3.2")]
        errors = self.run_audit(swapped, claims=claims(claim()))[0]
        self.assert_one(errors, "on Bazel 8.8.2")
        self.assertIn("(the newest pinned release of Bazel 8.x inside the claim)", errors[0])

    def test_negative_a_bzlmod_range_below_7_2_needs_the_cells_of_the_7_0_and_7_1_lines(self):
        """DESIGN 8: 7.0 - 7.1 Bzlmod is a Beta line of its own (the
        family-A lock), with the cells 7.0.2 and 7.1.2. A claim is the
        range a lane runs in, so a low `lo` enables the lane there: held to
        the majors alone, 7.0.0 to 9.3.2 stood on a 7.7.2 report."""
        supported = [proof("7.7.2"), proof("8.8.2"), proof("9.3.2")]
        wide = claims(claim(lo="7.0.0"))
        errors = self.run_audit(supported, claims=wide)[0]
        self.assertEqual(len(errors), 2, errors)
        self.assertIn("no `ran` report names the lane on Bazel 7.0.2 under bzlmod on any OS (the newest pinned "
                      "release of Bazel 7.0.x inside the claim)", errors[0])
        self.assertIn("on Bazel 7.1.2 under bzlmod on any OS (the newest pinned release of Bazel 7.1.x", errors[1])
        self.assert_one(self.run_audit(supported + [proof("7.1.2")], claims=wide)[0], "on Bazel 7.0.2")
        self.assertEqual(self.run_audit(supported + [proof("7.0.2"), proof("7.1.2")], claims=wide)[0], [])
        # The Beta line by itself: the 7.1.2 report does not carry 7.0.x.
        beta = claims(claim(lo="7.0.0", hi="7.1.2"))
        self.assert_one(self.run_audit([proof("7.1.2")], claims=beta)[0], "on Bazel 7.0.2")
        self.assertEqual(self.run_audit([proof("7.0.2"), proof("7.1.2")], claims=beta)[0], [])
        # From 7.1.0 the 7.0.x line is not claimed, and 7.1.x still is.
        from_7_1 = claims(claim(lo="7.1.0"))
        self.assert_one(self.run_audit(supported, claims=from_7_1)[0], "on Bazel 7.1.2")
        # A range that ends inside the 7.2 - 7.x line needs no 7.1.x cell.
        self.assertEqual(self.run_audit([proof("7.7.2")], claims=claims(claim(lo="7.2.0", hi="7.7.2")))[0], [])
        # Hybrid is split the same way (7.0.x is hybrid by default).
        hybrid = [proof(bazel, system="hybrid") for bazel in ("7.7.2", "8.8.2")]
        errors = self.run_audit(hybrid, claims=claims(claim(lo="7.0.0", hi="8.8.2", system="hybrid")))[0]
        self.assertEqual([e.split(" on Bazel ")[1][:5] for e in errors], ["7.0.2", "7.1.2"])
        # Section 8 names one WORKSPACE line for 7.x.
        workspace = [proof(bazel, system="workspace") for bazel in ("7.7.2", "8.8.2")]
        self.assertEqual(self.run_audit(workspace, claims=claims(claim(lo="7.0.0", hi="8.8.2", system="workspace")))[0],
                         [])

    def test_the_lines_a_range_reaches(self):
        key = audit.version_key
        names = lambda lo, hi, system: [name for name, _, _ in audit.lines_of(key(lo), key(hi), system)]
        self.assertEqual(names("7.0.0", "9.3.2", "bzlmod"), ["7.0.x", "7.1.x", "7.2 - 7.x", "8.x", "9.x"])
        self.assertEqual(names("7.0.0", "9.3.2", "hybrid"), ["7.0.x", "7.1.x", "7.2 - 7.x", "8.x", "9.x"])
        self.assertEqual(names("7.0.0", "9.3.2", "workspace"), ["7.x", "8.x", "9.x"])
        self.assertEqual(names("7.2.0", "9.3.2", "bzlmod"), ["7.2 - 7.x", "8.x", "9.x"])
        self.assertEqual(names("7.1.2", "7.1.2", "bzlmod"), ["7.1.x"])
        self.assertEqual(names("7.0.2", "7.1.0", "bzlmod"), ["7.0.x", "7.1.x"])
        self.assertEqual(names("6.6.0", "7.0.2", "bzlmod"), ["6.x", "7.0.x"])
        self.assertEqual(names("5.4.1", "6.6.0", "workspace"), ["5.x", "6.x"])
        # A pre-release belongs to the line of its release.
        self.assertEqual(names("7.2.0rc1", "7.2.0rc1", "bzlmod"), ["7.2 - 7.x"])
        self.assertEqual(names("10.0.0rc3", "10.0.0rc3", "bzlmod"), ["10.x"])

    def test_negative_evidence_that_does_not_count(self):
        good = [proof("7.7.2"), proof("8.8.2")]
        cases = {
            "skipped": skipped("bazel_hosted_toy_bzlmod", bazel="9.3.2", lanes=["H-TOY1"]),
            "another lane": proof("9.3.2", lanes=["H-TOY2"]),
            "a longer lane id": proof("9.3.2", lanes=["H-TOY10"]),
            "no lane named": proof("9.3.2", lanes=[]),
            "another system": proof("9.3.2", system="workspace"),
            "no system": proof("9.3.2", system=None),
        }
        for name, last in cases.items():
            with self.subTest(case=name):
                self.assert_one(self.run_audit(good + [last], claims=claims(claim()))[0], "on Bazel 9.3.2")

    def test_negative_a_report_that_did_not_read_the_fixture_server_log_proves_no_lane(self):
        """A lane test built on `Cell` that forgets `hosts_from_log` writes
        `hosts: []` beside `hosts_source: none`. The report itself is
        refused, and so is the claim that has nothing else to stand on."""
        good = [proof("7.7.2"), proof("8.8.2")]
        unlogged = proof("9.3.2", hosts=[], hosts_source="none", direct_network=True)
        errors = self.run_audit(good + [unlogged], claims=claims(claim()), required=["hosts", "wall_ms", "resolved"])[0]
        self.assertEqual(len(errors), 2, errors)
        self.assertIn("names the lanes ['H-TOY1'] with `hosts_source` 'none'", errors[0])
        self.assertIn("H-TOY1 (bzlmod, 7.2.0 to 9.3.2): no `ran` report with hosts from the fixture server's log "
                      "names the lane on Bazel 9.3.2 under bzlmod on any OS", errors[1])
        self.assertIn("r002.json did not read the log", errors[1])
        # Three such reports, one per line: no line of the claim is proven.
        every = [proof(bazel, hosts=[], hosts_source="none") for bazel in ("7.7.2", "8.8.2", "9.3.2")]
        errors = self.run_audit(every, claims=claims(claim()))[0]
        self.assertEqual(len([e for e in errors if "no `ran` report with hosts from the fixture" in e]), 3, errors)
        # A logged report of the same cell beside it is the proof.
        self.assert_one(self.run_audit(good + [unlogged, proof("9.3.2", os_name="linux")], claims=claims(claim()))[0],
                        "names the lanes ['H-TOY1'] with `hosts_source` 'none'")

    def test_negative_lanes_as_a_string_prove_no_lane(self):
        """`"H-TOY1" in "XH-TOY1X"` is true of a string: `lanes` counts
        only as a list, where a lane id is matched whole."""
        good = [proof("7.7.2"), proof("8.8.2")]
        for lanes, lane in (("XH-TOY1X", "H-TOY1"), ("H-JS10", "H-JS1"), ("H-TOY1", "H-TOY1")):
            with self.subTest(lanes=lanes):
                forged = dict(proof("9.3.2"), lanes=lanes)
                rows = claims(claim(lane=lane, lo="9.0.0"))
                errors = self.run_audit(good + [forged], claims=rows)[0]
                self.assertEqual(len(errors), 2, errors)
                self.assertIn(f"`lanes` is {lanes!r}, not a list of lane ids", errors[0])
                self.assertIn(f"{lane} (bzlmod, 9.0.0 to 9.3.2): no `ran` report names the lane on Bazel 9.3.2",
                              errors[1])
        self.assertTrue(audit.names_lane({"lanes": ["H-JS1"]}, "H-JS1"))
        self.assertFalse(audit.names_lane({"lanes": ["H-JS10"]}, "H-JS1"))
        self.assertFalse(audit.names_lane({"lanes": "H-JS1"}, "H-JS1"))
        self.assertFalse(audit.names_lane({}, "H-JS1"))

    def test_an_os_claim_needs_a_report_on_each_os(self):
        reports = [proof("9.3.2", "macos")]
        one_line = dict(lo="9.0.0", hi="9.3.2")
        self.assertEqual(self.run_audit(reports, claims=claims(claim(**one_line)))[0], [])
        self.assertEqual(self.run_audit(reports, claims=claims(claim(os_names=["macos"], **one_line)))[0], [])
        self.assert_one(self.run_audit(reports, claims=claims(claim(os_names=["macos", "linux"], **one_line)))[0],
                        "under bzlmod on linux")
        self.assert_one(self.run_audit(reports, claims=claims(claim(os_names=["darwin"], **one_line)))[0],
                        "`os` ['darwin'] is not a list of")

    def test_negative_a_claim_above_its_evidence_or_over_a_line_with_no_cell(self):
        reports = [proof("7.7.2"), proof("8.8.2"), proof("9.3.2")]
        self.assert_one(self.run_audit(reports, claims=claims(claim(hi="9.9.9")))[0],
                        "9.9.9 is not a pinned release")
        # 7.8.0 to 9.3.2 claims 7.x, and no pinned 7.x release is that new.
        self.assert_one(self.run_audit(reports, claims=claims(claim(lo="7.8.0")))[0],
                        "spans Bazel 7.2 - 7.x, where no pinned release lies inside the range")
        workspace = [proof(bazel, system="workspace") for bazel in ("7.7.2", "8.8.2", "9.3.2")]
        self.assert_one(self.run_audit(workspace, claims=claims(claim(lo="7.8.0", system="workspace")))[0],
                        "spans Bazel 7.x, where no pinned release")
        # 7.1.3 to 9.3.2 reaches the 7.1.x line above its one pinned release.
        self.assert_one(self.run_audit(reports, claims=claims(claim(lo="7.1.3")))[0], "spans Bazel 7.1.x")
        self.assert_one(self.run_audit(reports, claims=claims(claim(lo="9.3.2", hi="7.7.2")))[0],
                        "not a line range")
        self.assert_one(self.run_audit(reports, claims=claims(claim(system="both")))[0], "not a line range")

    def test_each_row_stands_alone_and_a_prerelease_is_below_its_release(self):
        rows = claims(claim(lo="7.0.0", hi="7.0.2"), claim(lo="7.1.0", hi="7.1.2"),
                      claim(lane="H-TOY2", lo="10.0.0rc3", hi="10.0.0rc3"))
        reports = [proof("7.0.2"), proof("7.1.2"), proof("10.0.0rc3", lanes=["H-TOY2"])]
        self.assertEqual(self.run_audit(reports, claims=rows)[0], [])
        self.assert_one(self.run_audit(reports[1:], claims=rows)[0], "on Bazel 7.0.2")
        key = audit.version_key
        self.assertLess(key("10.0.0rc3"), key("10.0.0"))
        self.assertLess(key("9.3.2"), key("10.0.0rc3"))
        self.assertLess(key("9.0.0-pre.20250101.1"), key("9.0.0"))
        self.assertLess(key("7.7.2"), key("7.10.0"))
        for text in ("7.7", "latest", "", None, "v7.7.2", "7.x"):
            self.assertIsNone(key(text), text)

    def test_negative_a_claims_file_of_another_shape(self):
        # Version 1 is the document from before the write classes: a dump
        # in it comes from a build that does not print what a lane may write.
        for doc in ([], {"version": 1, "claims": []}, {"version": 3, "claims": []}, {"version": 2},
                    {"version": 2, "claims": {}}):
            self.assert_one(self.run_audit([], claims=doc)[0], "the claims file is not")
        for key in ("system", "classes", "anchor", "stale", "tool"):
            row = claim()
            del row[key]
            self.assert_one(self.run_audit([], claims=claims(row))[0], "needs lane, mode, ruleset")


class CommandLine(unittest.TestCase):
    def main(self, *argv):
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            try:
                code = audit.main(list(argv))
            except SystemExit as stop:
                code = stop.code
        return code, out.getvalue(), err.getvalue()

    def test_exit_codes_and_messages(self):
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp) / "reports"
            reports.mkdir()
            cell = Planned.PR_CELL
            for i, item in enumerate(cell_reports(cell)):
                (reports / f"{i}.json").write_text(json.dumps(item), encoding="utf-8")
            empty = Path(tmp) / "claims.json"
            empty.write_text(json.dumps(claims()), encoding="utf-8")
            code, out, _ = self.main("--reports", str(reports), "--tiers", "pr", "--cell", cell["id"],
                                     "--require", "hosts,wall_ms,resolved", "--claims", str(empty))
            self.assertEqual(code, 0)
            self.assertIn(f"ok ({len(cell['tests'])} reports: {len(cell['tests'])} ran", out)

            claimed = Path(tmp) / "claimed.json"
            claimed.write_text(json.dumps(claims(claim())), encoding="utf-8")
            code, out, err = self.main("--reports", str(reports), "--claims", str(claimed))
            self.assertEqual(code, 1)
            self.assertIn("FAILED", out)
            self.assertEqual(err.count("no `ran` report names the lane"), 3)

            self.assertEqual(self.main("--reports", str(reports), "--tiers", "full")[0], 1)
            self.assertEqual(self.main("--reports", str(Path(tmp) / "absent"))[0], 1)
            self.assertEqual(self.main("--reports", str(reports), "--claims", str(Path(tmp) / "absent.json"))[0], 1)
            # Usage errors, not passes.
            self.assertEqual(self.main("--reports", str(reports), "--require", "hostz")[0], 2)
            self.assertEqual(self.main("--reports", str(reports), "--cell", cell["id"])[0], 2)


if __name__ == "__main__":
    unittest.main()
