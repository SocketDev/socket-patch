"""The Gradle CI test-name contract: every `#[ignore]` test of a real-Gradle
suite starts with a prefix some CI row filters on (ci-e2e-bundle.py's prefix
guard), the guard really rejects a stray name, and an `allow_empty` row only
keeps its allowance while one of its suites has not landed."""

import importlib.util
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


class PrefixGuard(unittest.TestCase):
    def test_reads_ignored_tests_through_attributes_and_comments(self):
        self.assertEqual(bundle.ignored_tests(SUITE), [
            "gradle_agent_349_applies_every_copy",
            "gradle_hosted_settings_plugins_block_no_throw",
            "gradle_vendor_395_composed_transaction",
            "gradle_multi_project_fake_central_mirror_smoke_both_dsls",
        ])

    def test_every_gradle_suite_is_guarded(self):
        self.assertEqual(set(bundle.PREFIX_GUARDS), set(bundle.GRADLE_SUITES))
        for name in ("gradle_agent_x", "gradle_hosted_x", "gradle_vendor_x", "gradle_multi_project_x",
                     "gradle_agent_cache_semantics_canaries"):
            self.assertTrue(bundle.GRADLE_PREFIX.match(name), name)
        for name in ("gradle_agentx", "agent_gradle_x", "gradle_sbt_x", "gradle_vex_x", "x_gradle_agent_"):
            self.assertFalse(bundle.GRADLE_PREFIX.match(name), name)

    def test_conforming_suites_pass_in_both_layouts(self):
        with tempfile.TemporaryDirectory() as tmp:
            tests = Path(tmp)
            (tests / "e2e_gradle_agent_build.rs").write_text(SUITE, encoding="utf-8")
            (tests / "e2e_vendor_gradle_build").mkdir()
            (tests / "e2e_vendor_gradle_build" / "main.rs").write_text(SUITE, encoding="utf-8")
            (tests / "e2e_vendor_gradle_build" / "cells.rs").write_text(SUITE, encoding="utf-8")
            self.assertEqual(bundle.prefix_violations(tests), [])
            self.assertTrue(bundle.landed("e2e_vendor_gradle_build", tests))
            self.assertFalse(bundle.landed("e2e_redirect_gradle_build", tests))

    def test_negative_a_stray_ignored_test_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            tests = Path(tmp)
            (tests / "e2e_redirect_gradle_build").mkdir()
            (tests / "e2e_redirect_gradle_build" / "main.rs").write_text(SUITE, encoding="utf-8")
            (tests / "e2e_redirect_gradle_build" / "extra.rs").write_text(
                "#[test]\n#[ignore = \"real Gradle\"]\nfn hosted_wiring_without_prefix() {}\n", encoding="utf-8")
            (tests / "e2e_gradle_agent_build.rs").write_text(
                "#[test]\n#[ignore]\nfn gradle_vex_attests() {}\n", encoding="utf-8")
            self.assertEqual(bundle.prefix_violations(tests), [
                ("e2e_gradle_agent_build", "e2e_gradle_agent_build.rs", "gradle_vex_attests"),
                ("e2e_redirect_gradle_build", "e2e_redirect_gradle_build/extra.rs", "hosted_wiring_without_prefix"),
            ])

    def test_the_checkout_passes_the_guard(self):
        self.assertEqual(bundle.prefix_violations(), [])
        self.assertEqual(bundle.main(["--check"]), 0)

    def test_suites_filter_the_rows_select_exist(self):
        """Every prefix the guard admits is selected by an ubuntu PR row, so a
        conforming test runs on every PR."""
        filters = " ".join(r.get("test_filter", "") for r in rows_mod.matrix_include(
            rows_mod.jobs(CI.read_text(encoding="utf-8"))["e2e"]) if r.get("jvm_tool") == "gradle")
        for prefix in ("gradle_agent_", "gradle_hosted_", "gradle_vendor_", "gradle_multi_project"):
            self.assertIn(prefix, filters.split())


class AllowEmpty(unittest.TestCase):
    rows = rows_mod.matrix_include(rows_mod.jobs(CI.read_text(encoding="utf-8"))["e2e"])

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
