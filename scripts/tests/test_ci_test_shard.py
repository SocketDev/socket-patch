"""ci-test-shard.py: the debug/release shards preserve the workspace tests."""

import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parents[2]
spec = importlib.util.spec_from_file_location("ci_test_shard", ROOT / "scripts" / "ci-test-shard.py")
shard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shard)


def selected(runs):
    names = []
    for args in runs:
        names += [args[i + 1] for i, a in enumerate(args) if a == "--test"]
    return names


class Partition(unittest.TestCase):
    NAMES = [f"t{i:03}" for i in range(236)]

    def test_every_target_runs_in_exactly_one_shard(self):
        for count in (1, 2, 3):
            with self.subTest(count=count):
                got = []
                for k in range(1, count + 1):
                    got += selected(shard.invocations(k, count, self.NAMES))
                self.assertEqual(sorted(got), self.NAMES)

    def test_unit_tests_and_doctests_run_once_on_shard_one(self):
        for count in (1, 2, 3):
            runs = [args for k in range(1, count + 1) for args in shard.invocations(k, count, self.NAMES)]
            self.assertEqual(sum("--lib" in a and "--bins" in a for a in runs), 1)
            self.assertEqual(sum("--doc" in a for a in runs), 1)
            self.assertTrue(all("--doc" not in a or "--test" not in a for a in runs),
                            "cargo rejects --doc with other target selectors")

    def test_shard_one_takes_the_smaller_share(self):
        first, second = shard.partition(self.NAMES, 2)
        self.assertLess(len(first), len(second))
        self.assertAlmostEqual(len(first) / len(second), shard.FIRST_SHARD_WEIGHT, delta=0.02)

    def test_every_run_is_workspace_wide_and_keeps_going(self):
        for args in shard.invocations(2, 2, self.NAMES, ["--locked"]):
            self.assertEqual(args[:4], ["cargo", "test", "--workspace", "--no-fail-fast"])
            self.assertIn("--locked", args)

    def test_release_profile_is_kept_for_integration_unit_and_doc_tests(self):
        for k in range(1, 4):
            for args in shard.invocations(k, 3, self.NAMES, ["--locked", "--profile", "ci-release"]):
                self.assertIn("--locked", args)
                self.assertEqual(args[args.index("--profile") + 1], "ci-release")

    def test_failed_unit_or_integration_run_still_runs_docs_and_fails_the_shard(self):
        metadata = {"workspace_members": ["a"], "packages": [
            {"id": "a", "targets": [{"name": "integration", "kind": ["test"]}]}]}
        with patch.object(shard.subprocess, "run", side_effect=[
            subprocess.CompletedProcess([], 0, stdout=json.dumps(metadata)),
            subprocess.CompletedProcess([], 1),
            subprocess.CompletedProcess([], 0),
        ]) as run:
            self.assertEqual(shard.main(["1", "3", "--locked", "--profile", "ci-release"]), 1)
        self.assertEqual(run.call_count, 3)
        self.assertIn("--doc", run.call_args_list[-1].args[0])

    def test_negative_bad_shard(self):
        with self.assertRaises(ValueError):
            shard.invocations(3, 2, self.NAMES)
        with self.assertRaises(ValueError):
            shard.invocations(0, 2, self.NAMES)

    def test_integration_targets_reads_workspace_test_kinds(self):
        metadata = {
            "workspace_members": ["a", "b"],
            "packages": [
                {"id": "a", "targets": [{"name": "lib_a", "kind": ["lib"]}, {"name": "e2e_x", "kind": ["test"]}]},
                {"id": "b", "targets": [{"name": "e2e_x", "kind": ["test"]}, {"name": "zz", "kind": ["test"]}]},
                {"id": "dep", "targets": [{"name": "not_ours", "kind": ["test"]}]},
            ],
        }
        self.assertEqual(shard.integration_targets(metadata), ["e2e_x", "zz"])

    def test_timed_shards_cover_new_targets_and_balance_the_recorded_work(self):
        timings = json.loads((ROOT / "scripts/ci-test-durations.json").read_text())
        names = sorted(timings["targets"]) + ["a_new_test_target"]
        partitions = shard.partition(names, 2, timings)
        self.assertCountEqual([name for part in partitions for name in part], names)
        loads = [timings["unit_seconds"], 0.0]
        for i, part in enumerate(partitions):
            loads[i] += sum(timings["compile_seconds"] + timings["targets"].get(n, timings["default_seconds"])
                            for n in part)
        self.assertLess(abs(loads[0] - loads[1]), 5)
        actual = [args for k in (1, 2) for args in shard.invocations(k, 2, names, timings=timings)]
        self.assertCountEqual(selected(actual), names)
        self.assertEqual(sum("--doc" in args for args in actual), 1)

    def test_the_checkout_has_integration_targets(self):
        try:
            out = subprocess.run(["cargo", "metadata", "--no-deps", "--format-version", "1"],
                                 cwd=ROOT, check=True, capture_output=True, text=True).stdout
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("cargo not available")
        names = shard.integration_targets(json.loads(out))
        self.assertGreater(len(names), 100)


class ReleaseWorkflow(unittest.TestCase):
    def test_all_release_shards_are_required_and_use_the_matrix_size(self):
        # Read the configured matrix, rather than assuming the workflow kept
        # the same shard count as this test. A missing shard silently loses
        # tests; an unguarded aggregate can turn a failed matrix green.
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        release = workflow.split("\n  test-release:\n")[1].split("\n  coverage:\n")[0]
        count = json.loads(re.search(r"^        shard: (\[.*\])$", release, re.M)[1])
        self.assertEqual(count, list(range(1, len(count) + 1)))
        self.assertGreater(len(count), 1)
        self.assertIn("TEST_SHARD: ${{ matrix.shard }}", release)
        self.assertIn("TEST_SHARD_COUNT: ${{ strategy.job-total }}", release)
        self.assertIn('python3 scripts/ci-test-shard.py "$TEST_SHARD" "$TEST_SHARD_COUNT" '
                      '--locked --profile ci-release', release)
        self.assertIn("fail-fast: false", release)
        self.assertIn("github.event_name != 'merge_group'", release)
        verdict = workflow.split("\n  ci-ok:\n")[1]
        needs = re.search(r"^    needs: \[(.*)\]$", verdict, re.M)[1].split(", ")
        self.assertIn("test-release", needs)
        self.assertIn("if: always()", verdict)
        self.assertIn('if v["result"] not in ("success", "skipped")', verdict)


@unittest.skipUnless(shutil.which("cargo"), "cargo not available")
class CargoSelection(unittest.TestCase):
    def test_three_release_shards_run_the_same_tests_as_cargo_workspace(self):
        # Exercise Cargo, including duplicate target names across packages,
        # binary/library units, ignored tests and doctests. This catches
        # selector interactions that argument-list assertions cannot prove.
        with tempfile.TemporaryDirectory(prefix="ci-release-shards-") as directory:
            root = Path(directory)
            files = {
                "Cargo.toml": '[workspace]\nmembers=["one","two"]\nresolver="2"\n'
                              '[profile.ci-release]\ninherits="release"\nlto=false\n',
                "one/Cargo.toml": '[package]\nname="one"\nversion="0.1.0"\nedition="2021"\n',
                "one/src/lib.rs": '/// ```\n/// assert_eq!(one::answer(), 42);\n/// ```\n'
                                  'pub fn answer() -> u8 { 42 }\n'
                                  '#[test] fn release_semantics() {\n'
                                  '    assert!(!cfg!(debug_assertions));\n'
                                  '    let n = std::hint::black_box(u8::MAX);\n'
                                  '    assert_eq!(n + 1, 0);\n}\n',
                "one/src/main.rs": 'fn main() {}\n#[test] fn binary_unit() {}\n',
                "one/tests/shared.rs": '#[test] fn first_shared() { assert!(std::path::Path::new(env!("CARGO_BIN_EXE_one")).is_file()); }\n'
                                       '#[test] #[ignore] fn ignored_case() {}\n',
                "one/tests/tail.rs": '#[test] fn tail_case() {}\n',
                "two/Cargo.toml": '[package]\nname="two"\nversion="0.1.0"\nedition="2021"\n'
                                  '[lib]\ntest=false\ndoctest=false\n',
                "two/src/lib.rs": 'pub fn value() -> u8 { 1 }\n',
                "two/tests/shared.rs": '#[test] fn second_shared() {}\n',
            }
            for name, content in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            env = dict(os.environ, CARGO_TARGET_DIR=str(root / "target"), CARGO_PROFILE_DEV_DEBUG="line-tables-only")

            def run(args):
                result = subprocess.run(args, cwd=root, env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return result.stdout

            metadata = json.loads(run(["cargo", "metadata", "--offline", "--no-deps", "--format-version", "1"]))
            run(["cargo", "generate-lockfile", "--offline"])
            extra = ["--offline", "--locked", "--profile", "ci-release"]
            baseline = run(["cargo", "test", "--workspace", *extra])
            actual = "\n".join(run(args) for k in range(1, 4)
                               for args in shard.invocations(k, 3, shard.integration_targets(metadata), extra))
            pattern = re.compile(r"^test (.+) \.\.\. (ok|ignored)$", re.M)
            expected = pattern.findall(baseline)
            self.assertGreaterEqual(len(expected), 7)
            self.assertCountEqual(pattern.findall(actual), expected)


if __name__ == "__main__":
    unittest.main()
