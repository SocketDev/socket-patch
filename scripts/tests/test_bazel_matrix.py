"""scripts/bazel-matrix.py and the fixture matrices it plans
bazel-compatibility.yml from: every cell's filter selects exactly the
`#[ignore]` tests its matrices list and every such test of e2e_bazel_build
is in a cell; every cell's Bazel is pinned for its runner; the matrices keep
the era table and the pull-request-tier rules of DESIGN 9.2 and 9.5; and the
workflow's path filter matches the files a Bazel change touches. No test
here runs Bazel.

The tests of the committed matrices assert rules, not today's list of cells
and tests: a package that adds a test and its MATRIX.json row must not turn
this file red."""

import ast
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
AUDIT = ROOT / "scripts" / "bazel-matrix-audit.py"
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
        self.assertIn("core/guard/MATRIX.json", files)
        self.assertGreaterEqual(len(files), 16)
        for rel in files:
            with self.subTest(matrix=rel):
                self.assertTrue([e for e in ENTRIES if e["matrix"] == rel], "plans no entry")

    def test_every_cell_filter_is_one_exact_path_per_test_under_a_declared_module(self):
        """A filter is `--exact` and one libtest path per test of the cell.
        The paths are the planner's model of what rustc names a test, so
        that they select the cell's tests among the model's own paths says
        little. What can be held here without the binary: each path ends in
        its test's name and starts at a module main.rs declares (a file
        outside the module tree is not compiled, and its path would run
        nothing). `Libtest` below holds the model to a listing, and the
        workflow's build job to the binary's own."""
        main = (tool.TESTS / tool.SUITE / "main.rs").read_text(encoding="utf-8")
        modules = set(re.findall(r"^mod ([a-z0-9_]+);$", main, re.M))
        self.assertGreaterEqual(len(FULL), 30)
        for cell in FULL:
            with self.subTest(cell=cell["id"]):
                words = cell["filter"].split()
                self.assertEqual(words[0], "--exact")
                self.assertTrue(cell["tests"], "the cell runs no test")
                self.assertEqual(len(words) - 1, len(cell["tests"]))
                self.assertEqual(len(set(words)), len(words))
                for path, name in zip(words[1:], cell["tests"]):
                    self.assertEqual(path.split("::")[-1], name)
                    self.assertIn(path.split("::")[0], modules)
                selected = sorted(name for name, path in TESTS.items() if libtest_selects(words, path))
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
            with self.subTest(cell=cell["id"]):
                self.assertLessEqual(set(cell["tests"]), full[cell["id"]])
                # DESIGN 9.5: the tier runs on ubuntu, and on the runners
                # PR_ALSO adds for one (group, mode, Bazel).
                also = tool.PR_ALSO.get((cell["group"], cell["mode"], cell["bazel"]), ())
                self.assertIn(cell["os"], ("ubuntu-latest",) + also)
        # The toy fixture on 9.3.2 on ubuntu is in the tier, on no cache:
        # its archives are committed and it contacts no host.
        core = {cell["id"]: cell for cell in PR}.get("core-9.3.2-ubuntu-core")
        self.assertIsNotNone(core, [cell["id"] for cell in PR])
        self.assertEqual(core["cache"], "")
        self.assertIn("bazel_core_zero_network", core["tests"])

    def test_a_toy_cell_is_all_in_one(self):
        """DESIGN 9.5: a core cell runs every gating test of the toy fixture
        on its Bazel and runner, whatever the prefix; its canaries keep a
        record-only cell of their own."""
        guards = {"bazel_guard_ignore_agent_go_tree_at_the_root", "bazel_guard_ignore_agent_go_tree_below_the_root"}
        self.assertLessEqual(guards, set(TESTS))
        by_id = {cell["id"]: cell for cell in FULL}
        for cell_id in ("core-9.3.2-ubuntu-core", "core-9.3.2-macos-core", "core-7.7.2-ubuntu-core"):
            tests = set(by_id[cell_id]["tests"])
            self.assertLessEqual(guards, tests, cell_id)
            self.assertIn("bazel_core_zero_network", tests)
        # Every gating test of the group is in the `core` cell of each
        # (Bazel, runner) its matrix lists it on, and in no other cell.
        gating = [e for e in ENTRIES if e["group"] == "core" and tool.mode_of(e["test"]) != "canary"]
        self.assertTrue([e for e in gating if tool.mode_of(e["test"]) != "core"], "no toy test outside bazel_core_")
        for name in {e["test"] for e in gating}:
            listed = {f"core-{e['bazel']}-{e['os'].split('-')[0]}-core" for e in gating if e["test"] == name}
            self.assertEqual({cell["id"] for cell in FULL if name in cell["tests"]}, listed, name)
        self.assertFalse([cell for cell in FULL if cell["group"] == "core" and cell["mode"] == "guard"])
        self.assertLessEqual(guards, set({cell["id"]: cell for cell in PR}["core-9.3.2-ubuntu-core"]["tests"]))
        self.assertLessEqual({cell["mode"] for cell in FULL if cell["group"] == "core"}, {"core", "canary"})
        # A ruleset group keeps one cell per prefix.
        entry = {"group": "light", "bazel": "9.3.2", "os": "ubuntu-latest", "test": "bazel_guard_x"}
        self.assertEqual(tool.cell_id(entry), "light-9.3.2-ubuntu-guard")
        self.assertEqual(tool.cell_id(dict(entry, group="core")), "core-9.3.2-ubuntu-core")
        self.assertEqual(tool.cell_id(dict(entry, group="core", test="bazel_canary_x")), "core-9.3.2-ubuntu-canary")

    def test_an_agent_test_rides_the_vendor_cell_of_its_ruleset_group(self):
        """DESIGN 9.5, the nightly table: "heavy | guard, hosted, vendor
        (agent Go rides the vendor cell)". An agent job of its own would be
        up to nine more jobs a night, each with its own setup."""
        agent = {"group": "heavy", "bazel": "9.3.2", "os": "ubuntu-latest", "test": "bazel_agent_gazelle_bzlmod"}
        self.assertEqual(tool.cell_id(agent), "heavy-9.3.2-ubuntu-vendor")
        self.assertEqual(tool.cell_id(dict(agent, group="light")), "light-9.3.2-ubuntu-vendor")
        self.assertEqual(tool.cell_id(dict(agent, os="windows-latest")), "heavy-9.3.2-windows-vendor")
        self.assertEqual(tool.cell_id(dict(agent, test="bazel_hosted_gazelle_bzlmod")), "heavy-9.3.2-ubuntu-hosted")
        # The toy group stays all in one.
        self.assertEqual(tool.cell_id(dict(agent, group="core")), "core-9.3.2-ubuntu-core")
        # One job runs both, each by its own exact path, and no cell is `agent`.
        names = ("bazel_agent_gazelle_bzlmod", "bazel_vendor_gazelle_bzlmod", "bazel_hosted_gazelle_bzlmod")
        found = [tool.entry("heavy/gazelle/MATRIX.json", "heavy", "gazelle", name, "bzlmod", "9.3.2", runner, tier,
                            network="cache")
                 for name in names
                 for runner, tier in tool.runner_tiers("heavy", tool.mode_of(name), "9.3.2", "nightly").items()]
        cells = tool.plan(found, tool.TIERS, {name: f"gazelle::{name}" for name in names})
        self.assertEqual({cell["mode"] for cell in cells}, {"vendor", "hosted"})
        self.assertEqual(len(cells), 6)
        vendor = next(cell for cell in cells if cell["id"] == "heavy-9.3.2-ubuntu-vendor")
        self.assertEqual(vendor["tests"], ["bazel_agent_gazelle_bzlmod", "bazel_vendor_gazelle_bzlmod"])
        self.assertEqual(vendor["filter"],
                         "--exact gazelle::bazel_agent_gazelle_bzlmod gazelle::bazel_vendor_gazelle_bzlmod")
        self.assertEqual((vendor["job"], vendor["cache"]), ("cells", "restore"))

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
        # Every baseline canary is the test of a fixture, whichever module
        # declares it: a lane package declares the canary of a fixture it
        # adds in its own module (baseline_light.rs).
        declared = {name for name in TESTS if name.startswith("bazel_canary_baseline_")}
        listed = {f["test"] for _, doc in tool.matrices() for f in doc.get("fixtures", [])}
        self.assertGreater(len(declared), 50)
        self.assertLessEqual(declared, listed)

    NESTED = """
macro_rules! baselines {
    ($($name:ident),* $(,)?) => {
        $( #[test] #[ignore] fn $name() {} )*
    };
}

#[test]
#[ignore]
fn bazel_hosted_top() {}

mod inner {
    mod empty {}

    #[test]
    #[ignore = "real Bazel; run with --ignored"]
    fn bazel_hosted_nested() {
        if true {
        }
    }

    pub(crate) mod deeper {
        #[test]
        #[ignore]
        fn bazel_hosted_deep() {}
    }

    baselines! {
        bazel_hosted_by_macro,
    }
}

#[test]
#[ignore]
fn bazel_hosted_after() {}
"""

    def test_a_test_in_an_inline_module_is_named_by_it(self):
        """libtest names a test by every module around it. Filed one level
        up, its `--exact` filter would run nothing and exit 0."""
        with tempfile.TemporaryDirectory() as tmp:
            suite = Path(tmp) / tool.SUITE
            (suite / "lanes").mkdir(parents=True)
            (suite / "main.rs").write_text("mod lane;\nmod lanes;\n", encoding="utf-8")
            (suite / "lane.rs").write_text(self.NESTED, encoding="utf-8")
            (suite / "lanes" / "mod.rs").write_text("pub mod go;\n", encoding="utf-8")
            (suite / "lanes" / "go.rs").write_text(
                "mod tamper {\n    #[test]\n    #[ignore]\n    fn bazel_vendor_go_twin() {}\n}\n", encoding="utf-8")
            self.assertEqual(tool.suite_tests(Path(tmp)), {
                "bazel_hosted_top": "lane::bazel_hosted_top",
                "bazel_hosted_nested": "lane::inner::bazel_hosted_nested",
                "bazel_hosted_deep": "lane::inner::deeper::bazel_hosted_deep",
                "bazel_hosted_by_macro": "lane::inner::bazel_hosted_by_macro",
                "bazel_hosted_after": "lane::bazel_hosted_after",
                "bazel_vendor_go_twin": "lanes::go::tamper::bazel_vendor_go_twin"})
        # The same reader, line by line: a block ends at the `}` of its own
        # indentation, and a one-line `mod x {}` opens nothing.
        inside = tool.inline_modules(self.NESTED)
        lines = self.NESTED.split("\n")
        self.assertEqual(inside[lines.index("fn bazel_hosted_top() {}")], [])
        self.assertEqual(inside[lines.index("        }")], ["inner"])
        self.assertEqual(inside[lines.index("        fn bazel_hosted_deep() {}")], ["inner", "deeper"])
        self.assertEqual(inside[lines.index("    fn bazel_hosted_nested() {")], ["inner"])
        self.assertEqual(inside[lines.index("fn bazel_hosted_after() {}")], [])

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

    def test_negative_a_core_matrix_whose_os_list_drops_a_test_from_a_cell(self):
        """A test's `os` list narrows the runners it is planned on. A name
        that is no runner, or a runner no cell of the test has, used to
        narrow it to nothing without a word: the cell then no longer asked
        for the test's report. The rule is core.rs's for core/MATRIX.json,
        applied to every file of the shape (core/guard/MATRIX.json too)."""
        both = ["ubuntu-latest", "macos-latest"]
        doc = {"group": "core", "filter": "bazel_guard_",
               "cells": [{"bazel": "9.3.2", "os": both, "tier": dict.fromkeys(both, "nightly"), "network": "none"},
                         {"bazel": "7.7.2", "os": ["ubuntu-latest"], "tier": {"ubuntu-latest": "nightly"},
                          "network": "none"}],
               "tests": {"bazel_guard_x": {"system": "bzlmod", "bazel": ["9.3.2", "7.7.2"]}}}
        known = {"bazel_guard_x": "ignore::bazel_guard_x", **{n: n for n in tool.HARNESS_TESTS}}

        def check(scope):
            """(errors, the (Bazel, runner) pairs the test is planned on)."""
            changed = json.loads(json.dumps(doc))
            changed["tests"]["bazel_guard_x"]["os"] = scope
            with tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / "core" / "guard").mkdir(parents=True)
                (Path(tmp) / "core" / "guard" / "MATRIX.json").write_text(json.dumps(changed), encoding="utf-8")
                errors = tool.check(Path(tmp), PINS, known)
                found = [] if errors else tool.entries(Path(tmp))
                return errors, {(e["bazel"], e["os"]) for e in found if e["test"] == "bazel_guard_x"}

        self.assertEqual(check(both), ([], {("9.3.2", "ubuntu-latest"), ("9.3.2", "macos-latest"),
                                            ("7.7.2", "ubuntu-latest")}))
        self.assertEqual(check(["ubuntu-latest"]), ([], {("9.3.2", "ubuntu-latest"), ("7.7.2", "ubuntu-latest")}))
        # A misspelt runner beside a real one: the ubuntu cells lost the test.
        self.assert_one(check(["ubuntu-lastest", "macos-latest"])[0],
                        "bazel_guard_x: `os` is ['ubuntu-lastest', 'macos-latest'], not a list of runners")
        # A string is matched by substring: `ubuntu-latest` is "in" it.
        self.assert_one(check("ubuntu-latest-and-more")[0], "bazel_guard_x: `os` is missing or not a list")
        self.assert_one(check([])[0], "`os` is [], not a list of runners")
        self.assert_one(check([["ubuntu-latest"]])[0], "not a list of runners")
        # A real runner that leaves one of the test's releases with none.
        self.assert_one(check(["macos-latest"])[0], "no cell on Bazel 7.7.2 runs on any of macos-latest")
        # A real runner none of the test's cells runs on.
        self.assert_one(check(["ubuntu-latest", "windows-latest"])[0],
                        "`os` names windows-latest, where no cell of its Bazel releases runs")


class Libtest(unittest.TestCase):
    """`--check --libtest-list FILE`: the planner's test paths against what
    the built binary lists. bazel-compatibility.yml's build job runs it."""

    @staticmethod
    def listing(paths):
        """What `e2e_bazel_build --list --ignored` prints for `paths`."""
        return "".join(f"{path}: test\n" for path in sorted(paths)) + f"\n{len(paths)} tests, 0 benchmarks\n"

    def test_the_paths_of_the_checkout_are_a_listing_of_their_own(self):
        self.assertEqual(tool.libtest_errors(self.listing(TESTS.values()), TESTS), [])
        # A benchmark line is no test, and a Windows line ending hides none.
        text = self.listing(TESTS.values()).replace("\n", "\r\n") + "x::bench_it: benchmark\r\n"
        self.assertEqual(tool.libtest_errors(text, TESTS), [])

    def test_negative_a_path_the_binary_names_otherwise(self):
        """The drift this check exists for: the binary has the test in an
        inline module, and the cell's `--exact` path names nothing."""
        paths = set(TESTS.values())
        flat = TESTS["bazel_core_zero_network"]
        nested = flat.replace("::", "::inner::")
        errors = tool.libtest_errors(self.listing(paths - {flat} | {nested}), TESTS)
        self.assertEqual(len(errors), 2, errors)
        self.assertIn(f"a cell filters on `{flat}`, which the binary does not list", errors[0])
        self.assertIn(f"the binary lists the `#[ignore]` test `{nested}`, which no cell can select", errors[1])
        # A test of the binary that no source file of the suite spells out.
        unseen = "bazel_build_common::selftests::bazel_canary_unseen"
        errors = tool.libtest_errors(self.listing(paths | {unseen}), TESTS)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn(unseen, errors[0])
        # A test the sources declare and the binary does not have.
        errors = tool.libtest_errors(self.listing(paths - {flat}), TESTS)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("under `--exact` it would run nothing", errors[0])
        # Something that is no listing at all is not "no difference".
        for text in ("", "error: unrecognized option\n", "0 tests, 0 benchmarks\n"):
            self.assertIn("the listing names no test", tool.libtest_errors(text, TESTS)[0])

    def test_the_command_line(self):
        def run(*argv):
            with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
                try:
                    code = tool.main(list(argv))
                except SystemExit as stop:
                    code = stop.code
            return code, out.getvalue(), err.getvalue()

        with tempfile.TemporaryDirectory() as tmp:
            good, bad = Path(tmp) / "good.txt", Path(tmp) / "bad.txt"
            good.write_text(self.listing(TESTS.values()), encoding="utf-8")
            code, out, _ = run("--check", "--libtest-list", str(good))
            self.assertEqual(code, 0)
            self.assertIn("bazel-matrix: ok", out)
            paths = sorted(TESTS.values())
            bad.write_text(self.listing(paths[1:]), encoding="utf-8")
            code, out, err = run("--check", "--libtest-list", str(bad))
            self.assertEqual(code, 1)
            self.assertNotIn("bazel-matrix: ok", out)
            self.assertIn(f"bazel-matrix: {tool.SUITE}: a cell filters on `{paths[0]}`", err)
            self.assertEqual(run("--check", "--libtest-list", str(Path(tmp) / "absent.txt"))[0], 1)
            # The listing is checked with the matrices, not while planning.
            self.assertEqual(run("--event", "schedule", "--libtest-list", str(good))[0], 2)


def rust_struct(text, name):
    """(fields, strict) of `struct <name> { .. }` in a Rust source, or None
    when it declares no such struct. `strict`: the struct refuses unknown
    keys, so a matrix cannot carry a key that is not a field."""
    found = re.search(r"((?:^#\[[^\n]*\]\n)*)^(?:pub(?:\([^)]*\))?\s+)?struct " + name + r" \{\n(.*?)^\}",
                      text, re.M | re.S)
    if not found:
        return None
    attributes, body = found.group(1), found.group(2)
    if "rename" in attributes or re.search(r"#\[serde\([^)]*rename", body):
        raise AssertionError(f"struct {name} renames a field: teach rust_struct the JSON names")
    fields = set(re.findall(r"^    (?:pub(?:\([^)]*\))?\s+)?([a-z_][a-z0-9_]*):", body, re.M))
    return fields, "deny_unknown_fields" in attributes


def keys_read(path, functions):
    """{(variable, key)} for every string key the named functions of a
    script read from a variable: `v.get("k")`, `need(v, "k", ..)`,
    `v["k"]` and `"k" in v`."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    bodies = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name in functions]
    assert {node.name for node in bodies} == set(functions), (path.name, functions)
    text = lambda node: node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None
    found = set()
    for body in bodies:
        for node in ast.walk(body):
            if isinstance(node, ast.Call) and node.args:
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr == "get" and isinstance(func.value, ast.Name):
                    found.add((func.value.id, text(node.args[0])))
                elif (isinstance(func, ast.Name) and func.id == "need" and len(node.args) > 1
                      and isinstance(node.args[0], ast.Name)):
                    found.add((node.args[0].id, text(node.args[1])))
            elif isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
                found.add((node.value.id, text(node.slice)))
            elif (isinstance(node, ast.Compare) and len(node.comparators) == 1
                  and isinstance(node.ops[0], (ast.In, ast.NotIn)) and isinstance(node.comparators[0], ast.Name)):
                found.add((node.comparators[0].id, text(node.left)))
    return {(variable, key) for variable, key in found if key is not None}


class Schemas(unittest.TestCase):
    """Two parsers read every light and heavy MATRIX.json: the planner and
    the audit by key, and the suite through serde structs that refuse
    unknown keys (baseline_light.rs, baseline_heavy.rs). A key the scripts
    read and a struct does not have is one no committed matrix can carry:
    a rule built on it can never be met, and a guide that tells an author
    to write it sends them into a red hermetic suite. This holds the two
    sides to each other, key by key."""

    SOURCES = {"light": tool.TESTS / tool.SUITE / "baseline_light.rs",
               "heavy": tool.TESTS / tool.SUITE / "baseline_heavy.rs"}
    # The functions that read a fixture-shape matrix, per script.
    READERS = ((ROOT / "scripts" / "bazel-matrix.py", ("read_fixtures", "fixture_errors", "fetches_by_tool")),
               (AUDIT, ("pins_by_cell",)))
    # What each variable of those functions holds: the structs whose
    # fields its keys must be. `claim` is a fixture or one of its lanes.
    HOLDS = {"doc": ("Matrix",), "fixture": ("Fixture",), "lane": ("Lane",), "claim": ("Fixture", "Lane"),
             "cell": ("CellSpec",)}
    # (shape, struct, key) the scripts read and the struct lacks, with why
    # that is no drift. The first three are one thing spelled per shape.
    # The last two are open: the planner is ahead of the heavy schema, and
    # the fields are for the owner of baseline_heavy.rs to add (`lanes:
    # Vec<Lane>` on the heavy `Fixture`, `cache: Option<String>` on the heavy
    # `CellSpec`; the light one has it). An entry whose field has landed
    # is dead and may go; it fails nothing while it stays.
    ACCEPTED = {
        ("light", "Fixture", "fixture"): "the heavy spelling of `path`; the planner tries both",
        ("heavy", "Fixture", "path"): "the light spelling of `fixture`",
        ("heavy", "Fixture", "loopback_repository"): "only a light fixture has an unpinned Coursier hub",
        ("heavy", "Fixture", "lanes"): "OPEN: a heavy lane test cannot be listed under its fixture",
        ("heavy", "CellSpec", "cache"): "OPEN: no Go or Rust cell can be `pr` with a restored cache",
    }

    def reads(self):
        found = set()
        for path, functions in self.READERS:
            found |= keys_read(path, functions)
        return found

    def test_the_struct_reader(self):
        text = ('#[derive(Deserialize)]\n#[serde(deny_unknown_fields)]\npub(crate) struct Fixture {\n'
                '    /// `a: b` in a comment is no field.\n    pub(crate) path: String,\n'
                '    #[serde(default = "downloader")]\n    fetch: String,\n    cells: Vec<CellSpec>,\n}\n\n'
                '#[derive(Deserialize)]\nstruct Loose {\n    bazel: String,\n}\n')
        self.assertEqual(rust_struct(text, "Fixture"), ({"path", "fetch", "cells"}, True))
        self.assertEqual(rust_struct(text, "Loose"), ({"bazel"}, False))
        self.assertIsNone(rust_struct(text, "Lane"))
        with self.assertRaises(AssertionError):
            rust_struct(text.replace("    fetch", '    #[serde(rename = "fetchedBy")]\n    fetch'), "Fixture")

    def test_the_key_reader_sees_every_way_a_script_reads_a_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "reader.py"
            script.write_text('def read(doc, fixture, cell):\n'
                              '    a = need(doc, "group", str, "x")\n'
                              '    b = fixture.get("pins", {}).get("rules_python")\n'
                              '    c = cell["bazel"]\n'
                              '    d = "lanes" in fixture and "cache" not in cell\n'
                              '    e = cell.get(name)\n'
                              'def other(doc):\n    return doc["unread"]\n', encoding="utf-8")
            self.assertEqual(keys_read(script, ("read",)), {
                ("doc", "group"), ("fixture", "pins"), ("cell", "bazel"), ("fixture", "lanes"), ("cell", "cache")})

    def test_every_key_the_scripts_read_is_a_field_of_the_suites_schema(self):
        reads = self.reads()
        # The reader is static: it knows a key by the variable it is read
        # from. A new variable must be given its struct here, or its keys
        # would go unchecked.
        self.assertLessEqual({variable for variable, _ in reads}, set(self.HOLDS))
        for variable, keys in (("fixture", {"pins", "lanes", "fetch"}), ("cell", {"bazel", "proof", "tier", "cache"}),
                               ("claim", {"test", "cells"})):
            self.assertLessEqual(keys, {key for name, key in reads if name == variable}, variable)
        lacking = set()
        for shape, source in self.SOURCES.items():
            text = source.read_text(encoding="utf-8")
            structs = {name: rust_struct(text, name) for names in self.HOLDS.values() for name in names}
            for name in ("Matrix", "Fixture", "CellSpec"):
                self.assertIsNotNone(structs[name], f"{source.name} has no struct {name}")
            for variable, key in reads:
                for name in self.HOLDS[variable]:
                    # No struct (heavy has no `Lane`): the key that would
                    # hold it (`lanes`) is the one reported.
                    if structs[name] and structs[name][1] and key not in structs[name][0]:
                        lacking.add((shape, name, key))
        self.assertLessEqual(lacking, set(self.ACCEPTED),
                             "a script reads a matrix key the suite's schema refuses: no committed "
                             "MATRIX.json can carry it")

    def test_the_open_keys_are_the_ones_the_planner_says_are_open(self):
        """The module docstring names them, so an author can tell which key
        the hermetic suite still refuses, and in which matrix."""
        still_open = {entry for entry, why in self.ACCEPTED.items() if why.startswith("OPEN")}
        self.assertEqual({key for _, _, key in still_open}, {"lanes", "cache"})
        self.assertIn("Two keys are read here that the suite's schemas do not take yet", tool.__doc__)
        for phrase in ("`lanes`\nunder a heavy fixture", "`cache` in\na cell"):
            self.assertIn(phrase, tool.__doc__)


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
