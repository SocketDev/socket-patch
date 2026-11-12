"""scripts/bazel-matrix.py and the fixture matrices it plans
bazel-compatibility.yml from: every cell's filter selects exactly the
`#[ignore]` tests its matrices list and every such test of e2e_bazel_build
is in a cell; every cell's Bazel is pinned for its runner; the matrices keep
the era table and the pull-request-tier rules of DESIGN 9.2 and 9.5; and the
workflow's path filter matches the files a Bazel change touches. No test
here runs Bazel."""

import contextlib
import importlib.util
import io
import json
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "bazel-compatibility.yml"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tool = load("bazel_matrix", ROOT / "scripts" / "bazel-matrix.py")
PINS = tool.pinned()
TESTS = tool.suite_tests()
ENTRIES = tool.entries()
FULL = tool.plan(ENTRIES, tool.TIERS, TESTS)
PR = tool.plan(ENTRIES, ("pr",), TESTS)


def libtest_selects(words, path):
    """libtest's selection for the arguments a cell passes: with `--exact` a
    test runs when its full path equals a filter, else when it contains one."""
    filters = [w for w in words if not w.startswith("--")]
    if "--exact" in words:
        return path in filters
    return not filters or any(f in path for f in filters)


def gh_glob(pattern):
    """A GitHub Actions path filter as a regex: `*` and `?` stop at `/`,
    `**` does not, and `**/` also matches no directory at all."""
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out, i = out + "(?:.*/)?", i + 3
        elif pattern.startswith("**", i):
            out, i = out + ".*", i + 2
        elif pattern[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif pattern[i] == "?":
            out, i = out + "[^/]", i + 1
        else:
            out, i = out + re.escape(pattern[i]), i + 1
    return re.compile(out + r"\Z")


def path_filters():
    """The `on.pull_request.paths` list of the workflow."""
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    at = lines.index("    paths:")
    found = []
    for line in lines[at + 1:]:
        item = re.match(r"^      - '([^']+)'$", line)
        if item:
            found.append(item.group(1))
        elif line.strip() and not line.strip().startswith("#"):
            break
    return found


def triggers(path):
    return any(gh_glob(pattern).match(path) for pattern in path_filters())


def fixture(test="bazel_canary_baseline_x_bzlmod_e9", cells=None, **more):
    base = {"path": "bzlmod/e9", "test": test, "system": "bzlmod", "pins": {},
            "cells": cells if cells is not None else [{"bazel": "9.3.2", "proof": 1, "tier": "nightly"}]}
    return {**base, **more}


class Synthetic(unittest.TestCase):
    """A fixture tree of the test's own, checked against the real pins."""

    def check(self, group, ruleset, fixtures, tests=None, pins=None):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / group / ruleset
            target.mkdir(parents=True)
            doc = {"group": group, "ruleset": ruleset, "fixtures": fixtures}
            (target / "MATRIX.json").write_text(json.dumps(doc), encoding="utf-8")
            names = {f["test"] for f in fixtures} | {l["test"] for f in fixtures for l in f.get("lanes", [])}
            known = {name: f"m::{name}" for name in names | set(tool.HARNESS_TESTS)}
            return tool.check(Path(tmp), PINS if pins is None else pins, known if tests is None else tests)

    def assert_one(self, errors, text):
        self.assertEqual(len(errors), 1, errors)
        self.assertIn(text, errors[0])


class CommittedMatrices(unittest.TestCase):
    def test_the_checkout_passes_every_rule(self):
        self.assertEqual(tool.check(), [])
        with contextlib.redirect_stdout(io.StringIO()) as printed:
            self.assertEqual(tool.main(["--check"]), 0)
        self.assertIn("bazel-matrix: ok", printed.getvalue())
        # A pull request with no label and an unlabelled event read as JSON `null`.
        with contextlib.redirect_stdout(io.StringIO()) as printed:
            self.assertEqual(tool.main(["--event", "pull_request", "--labels", "null"]), 0)
        self.assertEqual(json.loads(printed.getvalue())["tiers"], "pr")
        # A label list that cannot be read is a usage error, not "no label".
        for labels in ("bazel-matrix", '"bazel-matrix"'):
            with self.assertRaises(SystemExit) as stop, contextlib.redirect_stderr(io.StringIO()):
                tool.main(["--event", "pull_request", "--labels", labels])
            self.assertEqual(stop.exception.code, 2)

    def test_every_matrix_is_read(self):
        """Fifteen matrices in three shapes today; a file that planned
        nothing would look covered."""
        files = [rel for rel, _ in tool.matrices()]
        self.assertIn("core/MATRIX.json", files)
        self.assertGreaterEqual(len(files), 15)
        for rel in files:
            with self.subTest(matrix=rel):
                self.assertTrue([e for e in ENTRIES if e["matrix"] == rel], "plans no entry")

    def test_every_cell_filter_selects_exactly_its_tests(self):
        self.assertGreaterEqual(len(FULL), 30)
        for cell in FULL:
            with self.subTest(cell=cell["id"]):
                words = cell["filter"].split()
                selected = sorted(name for name, path in TESTS.items() if libtest_selects(words, path))
                self.assertTrue(selected, "the filter selects no #[ignore] test")
                self.assertEqual(selected, sorted(cell["tests"]))

    def test_every_ignored_test_maps_to_a_cell(self):
        self.assertGreater(len(TESTS), 70)
        planned = {name for cell in FULL for name in cell["tests"]}
        self.assertEqual(planned, set(TESTS))

    def test_every_cell_version_is_pinned_for_its_runner(self):
        versions = {version for version, _ in PINS}
        for cell in FULL:
            with self.subTest(cell=cell["id"]):
                self.assertIn(cell["bazel"], versions)
                self.assertIn((cell["bazel"], tool.RUNNERS[cell["os"]][1]), PINS)
                self.assertNotEqual(cell["bazel"], "7.7.0")

    def test_the_pull_request_tier_is_a_subset_and_holds_the_zero_network_cell(self):
        full = {cell["id"]: set(cell["tests"]) for cell in FULL}
        for cell in PR:
            self.assertLessEqual(set(cell["tests"]), full[cell["id"]])
        # Today: the toy fixture on 9.3.2 on ubuntu, and nothing that needs
        # a ruleset or a language toolchain.
        self.assertEqual([cell["id"] for cell in PR], ["core-9.3.2-ubuntu-core"])
        self.assertEqual(PR[0]["cache"], "")

    def test_cells_carry_what_the_workflow_reads(self):
        ids = [cell["id"] for cell in FULL]
        self.assertEqual(len(ids), len(set(ids)))
        for cell in FULL:
            with self.subTest(cell=cell["id"]):
                # The id is an artifact name.
                self.assertRegex(cell["id"], r"^[a-z0-9.]+(-[a-z0-9.]+){3}$")
                record_only = cell["mode"] == "canary" or "rc" in cell["bazel"]
                self.assertEqual(cell["record_only"], "true" if record_only else "")
                self.assertEqual(cell["job"], "extras" if record_only else "cells")
                slow = cell["os"] == "windows-latest" or (record_only and cell["group"] != "core")
                self.assertEqual(cell["timeout"], 60 if slow else 30)
                self.assertTrue(cell["filter"].startswith("--exact "))
        by_id = {cell["id"]: cell for cell in FULL}
        # 8.8.2 commits no module archives: its cells want the restored cache.
        self.assertEqual(by_id["core-8.8.2-ubuntu-core"]["cache"], "restore")
        self.assertEqual(by_id["core-9.3.2-ubuntu-core"]["cache"], "")
        # A canary stays cold, or it could not see a pinned URL rot.
        self.assertEqual({c["cache"] for c in FULL if c["mode"] == "canary"}, {""})
        # A test that is not applicable on Windows is not planned there.
        self.assertNotIn("bazel_core_shutdown_after_the_server_was_killed",
                         by_id["core-9.3.2-windows-core"]["tests"])

    def test_the_harness_canary_runs_where_the_toy_test_of_the_rule_does_not(self):
        core = json.loads((tool.FIXTURES / "core/MATRIX.json").read_text(encoding="utf-8"))
        toy = set(core["tests"]["bazel_core_probe_rule_takes_a_tree_artifact"]["bazel"])
        canary = set(tool.HARNESS_TESTS["bazel_canary_probe_rule_tree_artifact"]["bazel"])
        self.assertFalse(toy & canary)
        self.assertEqual(toy | canary, {version for version, _ in PINS})

    def test_workflow_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            with contextlib.redirect_stdout(io.StringIO()) as printed:
                self.assertEqual(tool.main(["--event", "pull_request", "--labels", '["x","bazel-matrix"]',
                                            "--github-output", str(out)]), 0)
            self.assertEqual(len(printed.getvalue().splitlines()), len(FULL))
            lines = dict(line.split("=", 1) for line in out.read_text(encoding="utf-8").splitlines())
        self.assertEqual(set(lines), {"tiers", "cells", "extras", "build"})
        self.assertEqual(lines["tiers"], "full")
        cells, extras = json.loads(lines["cells"]), json.loads(lines["extras"])
        self.assertEqual(sorted(c["id"] for c in cells + extras), sorted(c["id"] for c in FULL))
        self.assertEqual(json.loads(lines["build"]), ["macos-latest", "ubuntu-latest", "windows-latest"])
        for row in cells + extras:
            # A matrix row holds scalars only.
            self.assertTrue(all(isinstance(v, (str, int)) for v in row.values()), row)
            self.assertEqual(row["job"], "cells" if row in cells else "extras")

    def test_the_era_table_names_pinned_bazel_releases_only(self):
        versions = {version for version, _ in PINS}
        for module, releases in tool.ERAS.items():
            for release, pairs in releases.items():
                self.assertLessEqual(set(pairs), versions, (module, release))
                for systems in pairs.values():
                    self.assertLessEqual(set(systems), set(tool.SYSTEMS))
        for ruleset, subjects in tool.SUBJECTS.items():
            self.assertLessEqual(set(subjects), set(tool.ERAS), ruleset)


class Tiers(unittest.TestCase):
    def test_an_event_selects_its_tiers(self):
        self.assertEqual(tool.tiers_of("pull_request"), ("pr",))
        self.assertEqual(tool.tiers_of("pull_request", ["needs-review"]), ("pr",))
        for event, labels in (("pull_request", ["bazel-matrix"]), ("schedule", []), ("workflow_dispatch", [])):
            self.assertEqual(set(tool.tiers_of(event, labels)), {"pr", "nightly"}, event)

    def test_a_ruleset_entry_runs_where_design_9_5_puts_it(self):
        tiers = tool.runner_tiers
        every = {"ubuntu-latest", "macos-latest", "windows-latest"}
        self.assertEqual(tiers("light", "hosted", "9.3.2", "nightly"), dict.fromkeys(every, "nightly"))
        self.assertEqual(tiers("light", "hosted", "9.3.2", "pr"),
                         {"ubuntu-latest": "pr", "windows-latest": "pr", "macos-latest": "nightly"})
        self.assertEqual(tiers("heavy", "hosted", "9.3.2", "pr"),
                         {"ubuntu-latest": "pr", "windows-latest": "nightly", "macos-latest": "nightly"})
        # A canary, a Legacy or Beta line and a pre-release run on ubuntu.
        for mode, bazel in (("canary", "9.3.2"), ("hosted", "6.6.0"), ("guard", "7.1.2"), ("hosted", "10.0.0rc3")):
            self.assertEqual(tiers("light", mode, bazel, "nightly"), {"ubuntu-latest": "nightly"}, (mode, bazel))
        # Every release that runs on all three runners is pinned for all three.
        for bazel in tool.NIGHTLY_ON_EVERY_RUNNER:
            for _, platform in tool.RUNNERS.values():
                self.assertIn((bazel, platform), PINS)


class MacroReader(unittest.TestCase):
    SOURCE = """
macro_rules! canaries {
    ($($test:ident => ($ruleset:literal, $path:literal);)*) => {
        $(
            #[test]
            #[ignore = "real Bazel; run with --ignored"]
            fn $test() { baseline(stringify!($test), $ruleset, $path); }
        )*
    };
}

canaries! {
    bazel_canary_baseline_a_bzlmod_e9 => ("a", "bzlmod/e9");
    bazel_canary_baseline_a_bzlmod_e9_sub => ("a", "bzlmod/e9-sub");
}

macro_rules! helpers {
    ($($name:ident),*) => { $( fn $name() {} )* };
}

helpers! {
    bazel_canary_not_a_test
}

mod inner {
    macro_rules! baselines {
        ($($name:ident),* $(,)?) => {
            $( #[test] #[ignore] fn $name() {} )*
        };
    }
    baselines! {
        bazel_hosted_one,
        bazel_hosted_two,
    }
}
"""

    def test_reads_the_tests_a_macro_declares_and_no_other_invocation(self):
        self.assertEqual(tool.macro_tests(self.SOURCE), [
            "bazel_canary_baseline_a_bzlmod_e9", "bazel_canary_baseline_a_bzlmod_e9_sub",
            "bazel_hosted_one", "bazel_hosted_two"])

    def test_the_suite_tests_are_named_by_module(self):
        self.assertEqual(TESTS["bazel_core_zero_network"], "core::bazel_core_zero_network")
        self.assertEqual(TESTS["bazel_canary_baseline_rules_js_bzlmod_e9"],
                         "baseline_light::bazel_canary_baseline_rules_js_bzlmod_e9")
        self.assertEqual(TESTS["bazel_canary_baseline_rules_rust_bzlmod_e7"],
                         "baseline_heavy::bazel_canary_baseline_rules_rust_bzlmod_e7")
        # Each macro-declared baseline is the test of exactly one fixture.
        declared = [n for n, path in TESTS.items() if path.startswith("baseline_")]
        listed = [f["test"] for _, doc in tool.matrices() for f in doc.get("fixtures", [])]
        self.assertEqual(sorted(declared), sorted(listed))

    def test_exact_filters_do_not_select_a_longer_name(self):
        """Why a cell passes `--exact`: as a substring filter one fixture's
        test would also select every variant of it."""
        name = "baseline_light::bazel_canary_baseline_rules_js_bzlmod_e9"
        variant = name + "_sub"
        self.assertTrue(libtest_selects([name], variant))
        self.assertFalse(libtest_selects(["--exact", name], variant))
        self.assertTrue(libtest_selects(["--ignored", "--exact", name], name))


class Rules(Synthetic):
    def test_a_sound_matrix_passes(self):
        self.assertEqual(self.check("light", "rules_js", [fixture(pins={"aspect_rules_js": "3.6.0"})]), [])

    def test_negative_an_unknown_shape_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "extras").mkdir()
            (Path(tmp) / "extras" / "MATRIX.json").write_text('{"group": "extras", "rows": []}', encoding="utf-8")
            self.assertIn("neither the core shape", tool.check(Path(tmp), PINS, {})[0])
            (Path(tmp) / "extras" / "MATRIX.json").write_text("{", encoding="utf-8")
            self.assertIn("not JSON", tool.check(Path(tmp), PINS, {})[0])

    def test_negative_a_pair_outside_the_era_table(self):
        # rules_pycross 2.0.1 does not load on 7.7.2: no blanket "9.3.2 and 7.7.2".
        cells = [{"bazel": "9.3.2", "proof": 1, "tier": "nightly"}, {"bazel": "7.7.2", "proof": 1, "tier": "nightly"}]
        errors = self.check("heavy", "rules_pycross", [fixture(pins={"rules_pycross": "2.0.1"}, cells=cells)])
        self.assert_one(errors, "on 7.7.2: rules_pycross 2.0.1 under bzlmod is not a pairing of the era table")
        # The era names a dependency system too: rules_js 2.9.3 on 8.8.2 is WORKSPACE.
        cells = [{"bazel": "8.8.2", "proof": 1, "tier": "nightly"}]
        errors = self.check("light", "rules_js", [fixture(pins={"aspect_rules_js": "2.9.3"}, cells=cells)])
        self.assert_one(errors, "aspect_rules_js 2.9.3 under bzlmod")
        self.assertEqual(self.check("light", "rules_js", [
            fixture(pins={"aspect_rules_js": "2.9.3"}, cells=cells, system="workspace")]), [])
        # A release the table does not know, a pin that is missing, a ruleset with no row.
        self.assert_one(self.check("light", "rules_js", [fixture(pins={"aspect_rules_js": "3.7.0"})]), "3.7.0")
        self.assert_one(self.check("light", "rules_js", [fixture()]), "aspect_rules_js None")
        self.assert_one(self.check("light", "rules_new", [fixture()]), "no row in the era table")
        # Both pins of a gazelle fixture are held to it.
        go = {"gazelle": "0.54.0", "rules_go": "0.53.0"}
        self.assert_one(self.check("heavy", "gazelle", [fixture(pins=go, fetch="tool")]), "rules_go 0.53.0")

    def test_negative_a_rules_jvm_external_pr_cell_above_proof_tier_0(self):
        pins = {"rules_jvm_external": "7.2"}
        cell = {"bazel": "9.3.2", "proof": 1, "tier": "pr"}
        self.assert_one(self.check("light", "rules_jvm_external", [fixture(pins=pins, cells=[cell])]),
                        "stops at proof tier 0")
        self.assertEqual(self.check("light", "rules_jvm_external", [
            fixture(pins=pins, cells=[dict(cell, proof=0)])]), [])
        self.assertEqual(self.check("light", "rules_jvm_external", [
            fixture(pins=pins, cells=[dict(cell, tier="nightly")])]), [])
        # A lane test listed under the fixture is held to the same rule.
        lane = {"test": "bazel_hosted_rules_jvm_external_bzlmod", "cells": [cell]}
        self.assert_one(self.check("light", "rules_jvm_external", [fixture(pins=pins, lanes=[lane])]),
                        "bazel_hosted_rules_jvm_external_bzlmod on 9.3.2")

    def test_negative_a_go_or_rust_pr_cell_without_a_restored_cache(self):
        cases = (("gazelle", {"gazelle": "0.54.0", "rules_go": "0.65.0"}),
                 ("rules_rust", {"rules_rust": "0.75.0"}), ("rules_rs", {"rules_rs": "0.2.2"}))
        for ruleset, pins in cases:
            with self.subTest(ruleset=ruleset):
                cell = {"bazel": "9.3.2", "proof": 0, "tier": "pr"}
                fetch = {"fetch": "tool"} if ruleset != "rules_rs" else {}
                errors = self.check("heavy", ruleset, [fixture(pins=pins, cells=[cell], **fetch)])
                self.assert_one(errors, "only with a restored repository cache")
                restored = dict(cell, cache="restored")
                self.assertEqual(self.check("heavy", ruleset, [fixture(pins=pins, cells=[restored], **fetch)]), [])
        # A ruleset that needs no toolchain to fetch may be in the tier as it is.
        cell = {"bazel": "9.3.2", "proof": 1, "tier": "pr"}
        self.assertEqual(self.check("light", "rules_js", [
            fixture(pins={"aspect_rules_js": "3.6.0"}, cells=[cell])]), [])

    def test_negative_a_tool_fetched_fixture_that_does_not_say_so(self):
        seven = [{"bazel": "7.7.2", "proof": 1, "tier": "nightly"}]
        cases = (
            ("rules_python", fixture(pins={"rules_python": "1.4.2"}, cells=seven)),                       # pip mode
            ("rules_python", fixture(pins={"rules_python": "1.4.2"}, cells=seven, system="workspace")),   # pip_parse
            ("rules_rust", fixture(pins={"rules_rust": "0.75.0"})),                                       # crate_universe
            ("rules_jvm_external", fixture(pins={"rules_jvm_external": "7.2"},
                                           loopback_repository="http://127.0.0.1:18731/maven2")),         # Coursier
        )
        for ruleset, fx in cases:
            with self.subTest(ruleset=ruleset, system=fx["system"]):
                self.assert_one(self.check("heavy", ruleset, [fx]), '"fetch": "tool"')
                self.assertEqual(self.check("heavy", ruleset, [dict(fx, fetch="tool")]), [])
        # From 2.x rules_python fetches through Bazel's downloader.
        self.assertEqual(self.check("heavy", "rules_python", [fixture(pins={"rules_python": "2.5.0-rc4"})]), [])

    def test_negative_versions_no_runner_can_install(self):
        pins = {"aspect_rules_js": "3.6.0"}
        errors = self.check("light", "rules_js", [fixture(pins=pins, cells=[
            {"bazel": "7.7.0", "proof": 1, "tier": "nightly"}])], pins=PINS | {("7.7.0", "linux-x86_64")})
        self.assertTrue(any("7.7.0 is never pinned" in e for e in errors), errors)
        # An unpinned release is an error beside a pinned one too: it must
        # not drop out of the plan and leave the fixture looking covered.
        errors = self.check("light", "rules_js", [fixture(pins=pins, cells=[
            {"bazel": "9.3.2", "proof": 1, "tier": "nightly"}, {"bazel": "9.9.9", "proof": 1, "tier": "nightly"}])])
        self.assertTrue(any("no pin for Bazel 9.9.9 on linux-x86_64" in e for e in errors), errors)
        # The Windows cell a `pr` hosted entry on 9.3.2 adds needs its pin too.
        errors = self.check("light", "rules_js", [fixture(test="bazel_hosted_x", pins=pins, cells=[
            {"bazel": "9.3.2", "proof": 1, "tier": "pr"}])], pins=PINS - {("9.3.2", "windows-x86_64")})
        self.assert_one(errors, "no pin for Bazel 9.3.2 on windows-x86_64")
        self.assert_one(self.check("light", "rules_js", [fixture(pins=pins, cells=[
            {"bazel": "9.3.2", "proof": 1, "tier": "weekly"}])]), "`weekly` is no tier")

    def test_negative_the_matrices_and_the_suite_disagree(self):
        fx = fixture(pins={"aspect_rules_js": "3.6.0"})
        harness = {name: name for name in tool.HARNESS_TESTS}
        self.assert_one(self.check("light", "rules_js", [fx], tests=harness),
                        "has no `#[ignore]` test of that name")
        known = dict(harness, **{fx["test"]: "m::t", "bazel_hosted_orphan": "m::o"})
        self.assert_one(self.check("light", "rules_js", [fx], tests=known),
                        "`bazel_hosted_orphan` is in no MATRIX.json")
        stray = fixture(test="hosted_without_prefix", pins={"aspect_rules_js": "3.6.0"})
        errors = self.check("light", "rules_js", [stray])
        self.assertTrue(errors and all("starts with none of bazel_core_" in e for e in errors), errors)
        self.assert_one(self.check("light", "rules_js", [fx, fx]), "listed twice")

    def test_negative_a_core_matrix_with_a_test_no_cell_carries(self):
        doc = {"group": "core", "filter": "bazel_core_",
               "cells": [{"bazel": "9.3.2", "os": ["ubuntu-latest"], "tier": {"ubuntu-latest": "pr"},
                          "network": "none", "fixtures": {}}],
               "tests": {"bazel_core_x": {"system": "bzlmod", "bazel": ["9.3.2"]}}}
        known = {"bazel_core_x": "core::bazel_core_x", **{n: n for n in tool.HARNESS_TESTS}}

        def check(mutate):
            changed = json.loads(json.dumps(doc))
            mutate(changed)
            with tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / "core").mkdir()
                (Path(tmp) / "core" / "MATRIX.json").write_text(json.dumps(changed), encoding="utf-8")
                return tool.check(Path(tmp), PINS, known)

        self.assertEqual(check(lambda d: None), [])
        self.assert_one(check(lambda d: d["tests"]["bazel_core_x"]["bazel"].append("8.8.2")), "no cell on Bazel 8.8.2")
        self.assert_one(check(lambda d: d["cells"][0]["os"].append("macos-latest")), "names no tier for macos-latest")
        self.assert_one(check(lambda d: d["tests"].update(bazel_canary_y=d["tests"]["bazel_core_x"])),
                        "not a `bazel_core_` test")
        self.assert_one(check(lambda d: d["cells"][0].update(bazel="10.0.0rc3")
                              or d["tests"]["bazel_core_x"].update(bazel=["10.0.0rc3"])
                              or d["cells"][0].update(os=["macos-latest"], tier={"macos-latest": "nightly"})),
                        "no pin for Bazel 10.0.0rc3 on darwin-arm64")


class PathFilter(unittest.TestCase):
    def test_glob_semantics(self):
        self.assertTrue(gh_glob("**/*bazel*").match("scripts/bazel-pins.txt"))
        self.assertTrue(gh_glob("**/*bazel*").match("bazel.md"))
        self.assertFalse(gh_glob("*.md").match("docs/a.md"))
        self.assertTrue(gh_glob("**/*bazel*/**").match("a/bazel/b/c.rs"))
        self.assertFalse(gh_glob("scripts/bazel-*.py").match("scripts/tests/bazel-x.py"))

    def test_a_lane_source_a_lane_test_and_a_fixture_matrix_each_trigger(self):
        for path in ("crates/socket-patch-core/src/bazel/lanes/rules_js.rs",
                     "crates/socket-patch-cli/tests/e2e_bazel_build/rules_js.rs",
                     "crates/socket-patch-cli/tests/fixtures/bazel/light/rules_js/MATRIX.json"):
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).is_file(), "the example must be a real file")
                self.assertTrue(triggers(path))
        # `*` does not cross `/`: the first pattern alone misses a lane file.
        self.assertFalse(gh_glob("**/*bazel*").match("crates/socket-patch-core/src/bazel/lanes/rules_js.rs"))

    def test_everything_the_cells_run_from_triggers(self):
        paths = [f"crates/socket-patch-cli/tests/fixtures/bazel/{rel}" for rel, _ in tool.matrices()]
        paths += [p.relative_to(ROOT).as_posix() for p in tool.bundle.suite_files(tool.SUITE)]
        paths += ["scripts/install-bazelisk.sh", "scripts/bazel-pins.txt", "scripts/bazel-matrix.py",
                  "scripts/bazel-matrix-audit.py", "scripts/bazel-fixture-registry.py",
                  ".github/workflows/bazel-compatibility.yml",
                  "crates/socket-patch-cli/tests/bazel_build_common/server.rs",
                  "crates/socket-patch-cli/tests/bazel_common/write_policy.rs",
                  "crates/socket-patch-cli/src/bazel_gate/mod.rs",
                  "crates/socket-patch-core/src/crawlers/bazel_root.rs",
                  "crates/socket-patch-core/src/patch/redirect/bazel.rs",
                  "crates/socket-patch-core/src/hosted/bazel_reads.rs"]
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue(triggers(path))

    def test_negative_an_unrelated_change_does_not_trigger(self):
        for path in ("crates/socket-patch-core/src/gradle/dsl.rs", "README.md", "scripts/install-gradle.sh",
                     "crates/socket-patch-cli/tests/e2e_redirect_gradle_build/main.rs", ".github/workflows/ci.yml"):
            with self.subTest(path=path):
                self.assertFalse(triggers(path))


if __name__ == "__main__":
    unittest.main()
