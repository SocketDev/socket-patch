"""Grouped jobs must keep each member's tool pins, filters and failure verdict."""

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


groups = load("ci-e2e-groups")
runner = load("ci-e2e-run")


class Groups(unittest.TestCase):
    def test_regrouping_preserves_all_selections_and_is_idempotent(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text()
        reader = groups.reader()
        jobs = reader.jobs(text)
        updated = groups.regroup(text)
        updated_jobs = reader.jobs(updated)
        for job in groups.FAMILIES:
            key = lambda row: json.dumps(row, sort_keys=True)
            self.assertCountEqual(list(map(key, reader.matrix_include(jobs[job]))),
                                  list(map(key, reader.matrix_include(updated_jobs[job]))))
        self.assertEqual(groups.regroup(updated), updated)
        for job, limit in (("e2e", 60), ("e2e-macos", 6), ("e2e-windows", 6), ("e2e-full", 20)):
            self.assertLessEqual(len(reader.matrix_include(jobs[job], expand=False)), limit)

    def test_conflicting_versions_and_long_gradle_legs_do_not_share_jobs(self):
        rows = [
            {"os": "ubuntu-latest", "suite": "e2e_redirect_uv_build", "uv": version}
            for version in ("0.1.45", "0.12.17")
        ] + [{"os": "ubuntu-latest", "suite": "e2e_redirect_gradle_build", "gradle": "9.8.0"}] * 2
        self.assertEqual(len(groups.pack(rows)), 4)

    def test_all_bins_respect_their_member_setup_and_runtime_budget(self):
        reader = groups.reader()
        jobs = reader.jobs((ROOT / ".github/workflows/ci.yml").read_text())
        for job in groups.FAMILIES:
            for row in reader.matrix_include(jobs[job], expand=False):
                cases = runner.members(row)
                if len(cases) == 1:
                    continue
                self.assertLessEqual(sum(groups.estimate(c) for c in cases), groups.BUDGET_SECONDS)
                for case in cases:
                    for key, value in groups.settings(case).items():
                        self.assertEqual(row[key], value)


class Runner(unittest.TestCase):
    def test_empty_groups_cannot_pass_without_running_anything(self):
        for row in ({"cases": "[]"}, {"suite": ""}, {"cases": '[{"suite":"  "}]'}):
            with self.subTest(row=row), self.assertRaises(ValueError):
                runner.members(row)

    def test_numeric_yaml_versions_become_process_environment_strings(self):
        env = runner.environment({"dotnet": 8, "npm_required": 1}, "suite", {}, ROOT)
        self.assertEqual(env["SOCKET_PATCH_DOTNET_E2E_VERSION"], "8")
        self.assertEqual(env["SOCKET_PATCH_NPM_E2E_REQUIRED"], "1")

    def test_each_case_has_its_own_guards_versions_and_linker(self):
        base = {"SOCKET_PATCH_BUN_E2E_REQUIRED": "1", "SOCKET_PATCH_VLT_E2E_STORE_LINKER": "hardlink",
                "SOCKET_PATCH_VLT_E2E_JS": "/pinned/vlt.js", "SOCKET_PATCH_VLT_E2E_UPGRADE_JS": "/upgrade/vlt.js"}
        plain = runner.environment({"suite": "e2e_redirect_npm_build", "npm_required": "1"},
                                   "e2e_redirect_npm_build", base, ROOT)
        self.assertEqual(plain["SOCKET_PATCH_NPM_E2E_REQUIRED"], "1")
        self.assertEqual(plain["SOCKET_PATCH_BUN_E2E_REQUIRED"], "")
        self.assertNotIn("SOCKET_PATCH_VLT_E2E_STORE_LINKER", plain)
        self.assertNotIn("SOCKET_PATCH_VLT_E2E_UPGRADE_JS", plain)
        self.assertEqual(base["SOCKET_PATCH_VLT_E2E_STORE_LINKER"], "hardlink")
        pinned = runner.environment({"vlt": "1.2.0", "vlt_store_linker": "hardlink"}, "e2e_safety_vlt", base, ROOT)
        self.assertEqual(pinned["SOCKET_PATCH_VLT_E2E_REQUIRED"], "1")
        self.assertEqual(pinned["SOCKET_PATCH_VLT_E2E_VERSION"], "1.2.0")
        self.assertEqual(pinned["SOCKET_PATCH_VLT_E2E_STORE_LINKER"], "hardlink")
        self.assertEqual(pinned["SOCKET_PATCH_VLT_E2E_JS"], "/pinned/vlt.js")

    def test_maven_guard_follows_the_case_and_bun_lockb_only_its_suite(self):
        cases = [({"jvm_tool": "maven", "maven": "3.6.3"}, "1", "3.6.3"),
                 ({"jvm_tool": "gradle", "test_filter": "--ignored gradle_vendor_"}, "1", "3.9.16"),
                 ({"jvm_tool": "gradle", "test_filter": "--ignored gradle_multi_project"}, "", ""),
                 ({"dotnet": "8"}, "", "")]
        for case, required, version in cases:
            env = runner.environment(case, "test_suite", {}, ROOT)
            self.assertEqual(env["SOCKET_PATCH_MAVEN_E2E_REQUIRED"], required)
            self.assertEqual(env["SOCKET_PATCH_MAVEN_E2E_VERSION"], version)
        for suite in ("e2e_bun_lockb", "e2e_redirect_bun_build"):
            env = runner.environment({"bun": "1.1.45"}, suite, {}, ROOT)
            self.assertEqual(env["SOCKET_PATCH_BUN_LOCKB_VERSION"], "1.1.45" if suite == "e2e_bun_lockb" else "")

    def test_failure_empty_selection_and_vlt_proof_do_not_hide_later_cases(self):
        cases = [{"suite": "broken", "test_filter": "--ignored first"},
                 {"suite": "empty", "test_filter": "--exact missing"},
                 {"suite": "e2e_safety_vlt", "vlt": "1.2.0", "vlt_store_linker": "hardlink",
                  "test_filter": "--include-ignored vlt_pinned_matrix"},
                 {"suite": "last", "test_filter": "--ignored final"}]
        calls = []

        def execute(args, env, cwd, log):
            calls.append(args)
            name = Path(args[0]).stem
            count = 0 if name == "empty" else 1
            log.write_text(f"test result: ok. {count} passed; 0 failed; 0 ignored; finished in 0.00s\n")
            return 1 if name == "broken" else 0

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target").mkdir()
            with patch.object(runner, "run_binary", side_effect=execute), patch.object(
                    runner.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)) as checker:
                self.assertEqual(runner.run_cases({"cases": json.dumps(cases)}, root, {}), 1)
                self.assertEqual(len(calls), 4)
                self.assertEqual(calls[-1][1:], ["--ignored", "final"])
                self.assertEqual(checker.call_count, 1)
                self.assertIn("--binary", checker.call_args.args[0])
                self.assertIn("e2e_safety_vlt", checker.call_args.args[0])
                self.assertEqual(checker.call_args.kwargs["env"]["SOCKET_PATCH_VLT_E2E_STORE_LINKER"],
                                 "hardlink")

    def test_a_missing_binary_fails_but_other_members_still_run(self):
        cases = {"cases": json.dumps([{"suite": "missing"}, {"suite": "present"}])}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target").mkdir()
            (root / "target/e2e-1-present.log").write_text("test result: ok. 1 passed; 0 failed;\n")
            with patch.object(runner, "run_binary", side_effect=[FileNotFoundError(), 0]) as execute:
                self.assertEqual(runner.run_cases(cases, root, {}), 1)
                self.assertEqual(execute.call_count, 2)


if __name__ == "__main__":
    unittest.main()
