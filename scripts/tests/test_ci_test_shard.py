"""ci-test-shard.py: the debug/release shards preserve the workspace tests."""

import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parents[2]
spec = importlib.util.spec_from_file_location("ci_test_shard", ROOT / "scripts" / "ci-test-shard.py")
shard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shard)


def quiet():
    """Capture the script's stdout (text and raw bytes) instead of printing it."""
    return patch.object(shard.sys, "stdout", io.TextIOWrapper(io.BytesIO(), encoding="utf-8", write_through=True))


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
        with patch.object(shard.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 0, stdout=json.dumps(metadata))), \
                patch.object(shard, "run", side_effect=[(1, None), (0, None)]) as run, quiet():
            self.assertEqual(shard.main(["1", "3", "--locked", "--profile", "ci-release"]), 1)
        self.assertEqual(run.call_count, 2)
        self.assertIn("--doc", run.call_args_list[-1].args[0])

    def test_coverage_shards_run_llvm_cov_without_doctests(self):
        # The unsharded `cargo llvm-cov --workspace` ran no doctests; the
        # shards must neither add them nor drop a unit or integration target.
        for count in (1, 2):
            runs = [args for k in range(1, count + 1)
                    for args in shard.invocations(k, count, self.NAMES, coverage=True)]
            self.assertTrue(all(a[:5] == ["cargo", "llvm-cov", "--no-report", "--workspace", "--no-fail-fast"]
                                for a in runs))
            self.assertFalse(any("--doc" in a for a in runs))
            self.assertEqual(sum("--lib" in a and "--bins" in a for a in runs), 1)
            self.assertEqual(sorted(selected(runs)), self.NAMES)

    def test_coverage_mode_comes_from_the_environment(self):
        metadata = {"workspace_members": ["a"], "packages": [
            {"id": "a", "targets": [{"name": "integration", "kind": ["test"]}]}]}
        env = {k: v for k, v in shard.os.environ.items() if k != "CI_TEST_TIMINGS"}
        with patch.dict(shard.os.environ, {**env, "CI_TEST_COVERAGE": "1"}, clear=True), \
                patch.object(shard.subprocess, "run", return_value=subprocess.CompletedProcess(
                    [], 0, stdout=json.dumps(metadata))), \
                patch.object(shard, "run", return_value=(0, None)) as run, quiet():
            self.assertEqual(shard.main(["1", "2"]), 0)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args_list[-1].args[0][:3], ["cargo", "llvm-cov", "--no-report"])

    def test_run_echoes_output_and_records_each_binary_time(self):
        script = (
            "import sys\n"
            "print('\\x1b[1m\\x1b[92m     Running\\x1b[0m unittests src/lib.rs (target/debug/deps/socket_patch_core-0123456789abcdef)',"
            " file=sys.stderr, flush=True)\n"
            "print('test result: ok. 3 passed; 0 failed; finished in 30.12s', flush=True)\n"
            "print(r'     Running tests\\apply\\main.rs (target\\debug\\deps\\apply-fedcba9876543210.exe)',"
            " file=sys.stderr, flush=True)\n"
            "print('test result: FAILED. 1 passed; 1 failed; finished in 1.50s', flush=True)\n"
            "print('   Doc-tests socket_patch_core', file=sys.stderr, flush=True)\n"
            "print('test result: ok. 9 passed; 0 failed; finished in 4.00s', flush=True)\n"
            "sys.stdout.buffer.write('\\u2550\\u274c\\n'.encode('utf-8'))\n"
            "sys.exit(3)\n")
        timings = {}
        with quiet() as out:
            status, first = shard.run([sys.executable, "-c", script], timings)
        self.assertEqual(status, 3)
        self.assertIsNotNone(first)
        self.assertEqual(timings, {"unit:socket_patch_core": 30.12, "apply": 1.5})
        text = out.buffer.getvalue().decode("utf-8")
        self.assertIn("Doc-tests socket_patch_core", text)
        self.assertIn("finished in 4.00s", text)
        self.assertIn("\u2550\u274c", text)

    def test_run_does_not_wait_for_a_leftover_process_holding_the_pipe(self):
        # A test can leave a daemon behind with cargo's stdout inherited; the
        # old subprocess.run(args) returned when cargo exited, and so must this.
        script = ("import subprocess, sys\n"
                  "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n")
        start = time.monotonic()
        with quiet(), patch.object(shard, "DRAIN_SECONDS", 0.5):
            self.assertEqual(shard.run([sys.executable, "-c", script], {})[0], 0)
        self.assertLess(time.monotonic() - start, 15)

    def test_main_prints_the_timing_sample_last(self):
        metadata = {"workspace_members": ["a"], "packages": [
            {"id": "a", "targets": [{"name": "integration", "kind": ["test"]}]}]}

        def fake_run(args, timings):
            timings["integration"] = 2.0
            return 0, shard.time.monotonic()
        with patch.object(shard.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 0, stdout=json.dumps(metadata))), \
                patch.object(shard, "run", side_effect=fake_run), quiet() as out:
            self.assertEqual(shard.main(["2", "2"]), 0)
        last = out.buffer.getvalue().decode("utf-8").splitlines()[-1]
        self.assertTrue(last.startswith("ci-test-shard: timings "), last)
        sample = json.loads(last.removeprefix("ci-test-shard: timings "))
        self.assertEqual(list(sample), ["_build_seconds", "integration"])
        self.assertEqual(sample["integration"], 2.0)

    def test_coverage_shards_default_to_the_linux_sample(self):
        # With the sample, the longest target gets shard 1 to itself; the
        # count split gives shard 1 only `b`, by its smaller weight.
        metadata = {"workspace_members": ["x"], "packages": [
            {"id": "x", "targets": [{"name": n, "kind": ["test"]} for n in ("a", "b", "c")]}]}
        sample = {"unit_seconds": 0.0, "compile_seconds": 0.0, "default_seconds": 1.0,
                  "targets": {"a": 1.0, "b": 2.0, "c": 100.0}}
        env = {k: v for k, v in shard.os.environ.items() if k not in ("CI_TEST_TIMINGS", "CI_TEST_COVERAGE")}
        cases = [({"CI_TEST_COVERAGE": "1"}, ["c"]),
                 ({"CI_TEST_COVERAGE": "1", "CI_TEST_TIMINGS": ""}, ["b"]),
                 ({}, ["b"])]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.json"
            path.write_text(json.dumps(sample), encoding="utf-8")
            for extra, expected in cases:
                with self.subTest(env=extra), \
                        patch.dict(shard.os.environ, {**env, **extra}, clear=True), \
                        patch.object(shard, "COVERAGE_TIMINGS", path), \
                        patch.object(shard.subprocess, "run", return_value=subprocess.CompletedProcess(
                            [], 0, stdout=json.dumps(metadata))), \
                        patch.object(shard, "run", return_value=(0, None)) as run, quiet():
                    shard.main(["1", "2"])
                    self.assertEqual(selected([run.call_args_list[0].args[0]]), expected)

    def test_the_linux_coverage_sample_covers_the_checkout(self):
        sample = json.loads(shard.COVERAGE_TIMINGS.read_text(encoding="utf-8"))
        for key in ("unit_seconds", "compile_seconds", "default_seconds", "targets"):
            self.assertIn(key, sample)
        try:
            out = subprocess.run(["cargo", "metadata", "--no-deps", "--format-version", "1"],
                                 cwd=ROOT, check=True, capture_output=True, text=True).stdout
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("cargo not available")
        names = shard.integration_targets(json.loads(out))
        # New targets fall back to default_seconds; a mostly-stale sample
        # would quietly degrade into an unbalanced split.
        missing = [n for n in names if n not in sample["targets"]]
        self.assertLess(len(missing), len(names) // 10, missing)

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

    def test_all_coverage_shards_are_required_and_upload_distinct_lcov(self):
        # coverage is the gating Linux test run: every shard must run under
        # cargo-llvm-cov, gate ci-ok, and upload an LCOV coverage-merge picks
        # up (its `coverage-{host*,docker-*}` pattern) without name clashes.
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        cov = workflow.split("\n  coverage:\n")[1].split("\n  docker-base:\n")[0]
        count = json.loads(re.search(r"^        shard: (\[.*\])$", cov, re.M)[1])
        self.assertEqual(count, list(range(1, len(count) + 1)))
        self.assertIn("fail-fast: false", cov)
        self.assertIn("CI_TEST_COVERAGE: '1'", cov)
        self.assertIn('python3 scripts/ci-test-shard.py "$TEST_SHARD" "$TEST_SHARD_COUNT"', cov)
        self.assertIn("TEST_SHARD_COUNT: ${{ strategy.job-total }}", cov)
        self.assertIn('--output-path "coverage-host-$TEST_SHARD.lcov"', cov)
        self.assertIn("name: coverage-host-${{ matrix.shard }}", cov)
        self.assertIn("pattern: coverage-{host*,docker-*}", workflow)
        verdict = workflow.split("\n  ci-ok:\n")[1]
        self.assertIn("coverage", re.search(r"^    needs: \[(.*)\]$", verdict, re.M)[1].split(", "))


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
                "one/tests/shared.rs": '#[test] fn first_shared() {}\n'
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
            env = dict(os.environ, CARGO_TARGET_DIR=str(root / "target"))

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
