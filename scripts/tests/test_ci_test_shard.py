"""ci-test-shard.py: the `test` job's shards together run exactly the old
single `cargo test --workspace` selection."""

import importlib.util
import json
import subprocess
import unittest
from pathlib import Path

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

    def test_the_checkout_has_integration_targets(self):
        try:
            out = subprocess.run(["cargo", "metadata", "--no-deps", "--format-version", "1"],
                                 cwd=ROOT, check=True, capture_output=True, text=True).stdout
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("cargo not available")
        names = shard.integration_targets(json.loads(out))
        self.assertGreater(len(names), 100)


if __name__ == "__main__":
    unittest.main()
