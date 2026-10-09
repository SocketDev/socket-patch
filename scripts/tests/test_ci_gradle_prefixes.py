"""The Gradle CI test-name contract: every `#[ignore]` test of a real-Gradle
suite starts with a prefix the CI rows running that suite filter on
(ci-e2e-bundle.py's per-suite prefix guard), every prefix a suite admits is
selected for it by a ci.yml row and a gradle-compatibility.yml mode, the
guard really rejects a stray name (or a right prefix in the wrong suite), and
an `allow_empty` row only keeps its allowance while one of its suites has not
landed."""

import importlib.util
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[2]
CI = ROOT / ".github" / "workflows" / "ci.yml"
COMPAT = ROOT / ".github" / "workflows" / "gradle-compatibility.yml"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rows_mod = load("ci_rows", Path(__file__).parent / "test_ci_vlt_rows.py")
bundle = load("ci_e2e_bundle", ROOT / "scripts" / "ci-e2e-bundle.py")

SUITE = """
#[test]
#[ignore = "real Gradle; run with --ignored"]
fn gradle_agent_349_applies_every_copy() {}

#[test]
#[ignore]
// a comment between the attributes and the fn
#[serial_test::serial]
fn gradle_hosted_settings_plugins_block_no_throw() {}

#[ignore = "a \\"quoted\\" reason"]
#[test]
pub async fn gradle_vendor_395_composed_transaction() {}

#[test]
#[ignore]
fn gradle_multi_project_fake_central_mirror_smoke_both_dsls() {}

#[test]
fn unguarded_but_not_ignored() {}
"""


def suite_text(prefix):
    return (f"#[test]\n#[ignore = \"real Gradle\"]\nfn {prefix}one() {{}}\n\n"
            f"#[test]\n#[ignore]\n#[serial_test::serial]\nfn {prefix}two() {{}}\n\n"
            "#[test]\nfn unguarded_but_not_ignored() {}\n")


def compat_modes():
    """`{mode: (suites, filter prefixes)}` from gradle-compatibility.yml's
    run step `case` table."""
    text = COMPAT.read_text(encoding="utf-8")
    return {m.group(1): (m.group(2).split(), m.group(3).split())
            for m in re.finditer(r"^\s+(\w+)\) suites='([^']*)'; filter='([^']*)' ;;$", text, re.M)}


class PrefixGuard(unittest.TestCase):
    def test_reads_ignored_tests_through_attributes_and_comments(self):
        self.assertEqual(bundle.ignored_tests(SUITE), [
            "gradle_agent_349_applies_every_copy",
            "gradle_hosted_settings_plugins_block_no_throw",
            "gradle_vendor_395_composed_transaction",
            "gradle_multi_project_fake_central_mirror_smoke_both_dsls",
        ])

    def test_every_gradle_suite_is_guarded_by_its_own_prefixes(self):
        self.assertEqual(set(bundle.PREFIX_GUARDS), set(bundle.GRADLE_SUITES))
        admits = {suite: [n for n in ("gradle_agent_x", "gradle_hosted_x", "gradle_vendor_x", "gradle_multi_project_x")
                          if guard.match(n)] for suite, guard in bundle.PREFIX_GUARDS.items()}
        self.assertEqual(admits, {
            "e2e_gradle_discovery_build": ["gradle_agent_x"],
            "e2e_gradle_agent_build": ["gradle_agent_x"],
            "e2e_redirect_gradle_build": ["gradle_hosted_x"],
            "e2e_vendor_gradle_build": ["gradle_vendor_x", "gradle_multi_project_x"],
        })
        for name in ("gradle_agentx", "agent_gradle_x", "gradle_sbt_x", "gradle_vex_x", "x_gradle_agent_"):
            for suite, guard in bundle.PREFIX_GUARDS.items():
                self.assertFalse(guard.match(name), (suite, name))

    def test_conforming_suites_pass_in_both_layouts(self):
        with tempfile.TemporaryDirectory() as tmp:
            tests = Path(tmp)
            (tests / "e2e_gradle_agent_build.rs").write_text(suite_text("gradle_agent_"), encoding="utf-8")
            (tests / "e2e_vendor_gradle_build").mkdir()
            (tests / "e2e_vendor_gradle_build" / "main.rs").write_text(suite_text("gradle_vendor_"), encoding="utf-8")
            (tests / "e2e_vendor_gradle_build" / "cells.rs").write_text(
                suite_text("gradle_multi_project_"), encoding="utf-8")
            self.assertEqual(bundle.prefix_violations(tests), [])
            self.assertTrue(bundle.landed("e2e_vendor_gradle_build", tests))
            self.assertFalse(bundle.landed("e2e_redirect_gradle_build", tests))

    def test_negative_a_stray_ignored_test_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            tests = Path(tmp)
            (tests / "e2e_redirect_gradle_build").mkdir()
            (tests / "e2e_redirect_gradle_build" / "main.rs").write_text(
                suite_text("gradle_hosted_"), encoding="utf-8")
            (tests / "e2e_redirect_gradle_build" / "extra.rs").write_text(
                "#[test]\n#[ignore = \"real Gradle\"]\nfn hosted_wiring_without_prefix() {}\n", encoding="utf-8")
            (tests / "e2e_gradle_agent_build.rs").write_text(
                "#[test]\n#[ignore]\nfn gradle_vex_attests() {}\n", encoding="utf-8")
            self.assertEqual(bundle.prefix_violations(tests), [
                ("e2e_gradle_agent_build", "e2e_gradle_agent_build.rs", "gradle_vex_attests"),
                ("e2e_redirect_gradle_build", "e2e_redirect_gradle_build/extra.rs", "hosted_wiring_without_prefix"),
            ])

    def test_negative_a_right_prefix_in_the_wrong_suite_is_reported(self):
        """A Gradle-campaign prefix only counts in a suite whose rows select it:
        no row runs the discovery suite with `gradle_vendor_`, the agent suite
        with `gradle_hosted_` (the 36-cell grid filters agent cells on
        `gradle_agent_` only) or the vendor suite with `gradle_agent_`."""
        with tempfile.TemporaryDirectory() as tmp:
            tests = Path(tmp)
            (tests / "e2e_gradle_discovery_build.rs").write_text(suite_text("gradle_vendor_395_"), encoding="utf-8")
            (tests / "e2e_gradle_agent_build.rs").write_text(suite_text("gradle_hosted_"), encoding="utf-8")
            (tests / "e2e_vendor_gradle_build.rs").write_text(suite_text("gradle_agent_"), encoding="utf-8")
            self.assertEqual(sorted((s, n) for s, _, n in bundle.prefix_violations(tests)), [
                ("e2e_gradle_agent_build", "gradle_hosted_one"),
                ("e2e_gradle_agent_build", "gradle_hosted_two"),
                ("e2e_gradle_discovery_build", "gradle_vendor_395_one"),
                ("e2e_gradle_discovery_build", "gradle_vendor_395_two"),
                ("e2e_vendor_gradle_build", "gradle_agent_one"),
                ("e2e_vendor_gradle_build", "gradle_agent_two"),
            ])

    def test_the_checkout_passes_the_guard(self):
        self.assertEqual(bundle.prefix_violations(), [])
        self.assertEqual(bundle.main(["--check"]), 0)

    def test_every_admitted_prefix_runs_in_both_tiers(self):
        """Every (suite, prefix) the guard admits is selected by an ubuntu PR
        row that runs that suite and by the gradle-compatibility.yml mode that
        runs it, so a conforming test runs on every PR and in every grid
        cell of its mode."""
        rows = [r for r in rows_mod.job_rows(rows_mod.jobs(CI.read_text(encoding="utf-8")), "e2e")
                if r.get("jvm_tool") == "gradle" and r["os"] == "ubuntu-latest"]
        modes = compat_modes()
        self.assertEqual(set(modes), {"agent", "hosted", "vendor"})
        for suite, prefixes in bundle.GRADLE_SUITE_PREFIXES.items():
            for prefix in prefixes:
                with self.subTest(suite=suite, prefix=prefix):
                    self.assertTrue(any(suite in r["suite"].split() and prefix in r["test_filter"].split()
                                        for r in rows), "no ci.yml row")
                    self.assertTrue(any(suite in s and prefix in f for s, f in modes.values()),
                                    "no gradle-compatibility.yml mode")

    def test_compat_overrides_select_admitted_tests(self):
        """An extras row's `suites` / `test_filter` override stays inside its
        mode's suites, and every filter word is a test name its guarded suites
        admit (so the row cannot target tests that live in another suite)."""
        modes = compat_modes()
        for row in rows_mod.matrix_include(rows_mod.jobs(COMPAT.read_text(encoding="utf-8"))["extras"]):
            suites, words = modes[row["mode"]]
            suites = row.get("suites", "").split() or suites
            words = row.get("test_filter", "").split() or words
            with self.subTest(row=row):
                self.assertTrue(set(suites) <= set(modes[row["mode"]][0]))
                for suite in suites:
                    guard = bundle.PREFIX_GUARDS.get(suite)
                    if guard is not None:
                        for word in words:
                            self.assertTrue(guard.match(word), f"{word} cannot live in {suite}")
                if row.get("test_filter"):
                    self.assertTrue(row.get("suites"), "a narrowed filter names the suite that owns it")


def libtest_selects(words, name):
    """libtest's filter semantics for the argument words a row passes: a
    name runs when it contains any positional filter (all names when there
    is none) and no `--skip` word."""
    filters, skips, it = [], [], iter(words)
    for word in it:
        if word == "--skip":
            skips.append(next(it))
        elif not word.startswith("--"):
            filters.append(word)
    return (not filters or any(f in name for f in filters)) and not any(s in name for s in skips)


class HostedShards(unittest.TestCase):
    """The hosted suite runs as several legs per Gradle line (it is the
    merge-queue critical path in one leg). Every hosted test must run in
    exactly one leg of each line, and the catch-all leg's `--skip` words
    must be exactly the other legs' hosted words."""
    SUITE = "e2e_redirect_gradle_build"

    def rows_by_line(self):
        rows = [r for r in rows_mod.job_rows(rows_mod.jobs(CI.read_text(encoding="utf-8")), "e2e")
                if r.get("jvm_tool") == "gradle" and self.SUITE in r["suite"].split()]
        lines = {}
        for row in rows:
            lines.setdefault(row["gradle"], []).append(row["test_filter"].split())
        return lines

    def test_every_hosted_test_runs_in_exactly_one_leg_per_line(self):
        names = [n for path in bundle.suite_files(self.SUITE)
                 for n in bundle.ignored_tests(path.read_text(encoding="utf-8"))]
        self.assertGreater(len(names), 20)
        lines = self.rows_by_line()
        self.assertTrue(lines)
        for line, filters in lines.items():
            for name in names:
                with self.subTest(gradle=line, test=name):
                    self.assertEqual(sum(libtest_selects(f, name) for f in filters), 1)

    def test_catch_all_skips_exactly_the_other_legs_words(self):
        for line, filters in self.rows_by_line().items():
            with self.subTest(gradle=line):
                catch_all = [f for f in filters if "gradle_hosted_" in f]
                self.assertEqual(len(catch_all), 1)
                skips = {w for a, w in zip(catch_all[0], catch_all[0][1:]) if a == "--skip"}
                named = {w for f in filters if f is not catch_all[0]
                         for w in f if w.startswith("gradle_hosted_")}
                self.assertEqual(skips, named)

    def test_libtest_selects_negative(self):
        self.assertFalse(libtest_selects(["--ignored", "gradle_hosted_b"], "gradle_hosted_catalog"))
        self.assertFalse(libtest_selects(["--ignored", "gradle_hosted_", "--skip", "gradle_hosted_c"],
                                         "gradle_hosted_catalog"))
        self.assertTrue(libtest_selects(["--ignored", "gradle_hosted_", "--skip", "gradle_hosted_c"],
                                        "gradle_hosted_tamper_fails"))


class AllowEmpty(unittest.TestCase):
    rows = rows_mod.job_rows(rows_mod.jobs(CI.read_text(encoding="utf-8")), "e2e")

    def test_allow_empty_only_while_a_suite_is_unlanded(self):
        """The allowance is for rows whose owning package has not landed. Once
        every suite of a row exists (the campaign's last package), the row
        must drop `allow_empty` so an empty selection fails again."""
        for row in self.rows:
            if row.get("allow_empty") is None:
                continue
            with self.subTest(row=row):
                self.assertEqual(row["allow_empty"], "true")
                self.assertEqual(row.get("jvm_tool"), "gradle", "allow_empty is a Gradle-campaign scaffold")
                self.assertTrue(any(not bundle.landed(s) for s in row["suite"].split()),
                                f"every suite of {row['suite']!r} has landed: drop allow_empty")

    def test_rows_without_allowance_name_landed_suites(self):
        for row in self.rows:
            if row.get("allow_empty") == "true":
                continue
            for suite in row["suite"].split():
                with self.subTest(row=row, suite=suite):
                    self.assertTrue(bundle.landed(suite), f"{suite} has no test target")

    def test_row_suites_skip_unlanded_only_with_allowance(self):
        with tempfile.TemporaryDirectory() as tmp:
            tests = Path(tmp)
            (tests / "e2e_vendor_jvm_build.rs").write_text("", encoding="utf-8")
            row = {"suite": "e2e_vendor_gradle_build e2e_vendor_jvm_build"}
            self.assertEqual(bundle.row_suites(row, tests), ["e2e_vendor_gradle_build", "e2e_vendor_jvm_build"])
            row["allow_empty"] = "true"
            self.assertEqual(bundle.row_suites(row, tests), ["e2e_vendor_jvm_build"])


if __name__ == "__main__":
    unittest.main()
