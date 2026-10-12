"""Failing `cargo test` cases become annotations naming the binary and test."""

import contextlib
import importlib.util
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[2]
spec = importlib.util.spec_from_file_location("test_failures", ROOT / "scripts/ci-test-failures.py")
tf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tf)

LOG = """\
2026-10-12T16:01:00.0000000Z      Running unittests src/lib.rs (target/llvm-cov-target/debug/deps/socket_patch_core-0123abcd)
2026-10-12T16:01:00.1000000Z test formats::ok ... ok
2026-10-12T16:01:00.2000000Z test formats::pure ... FAILED
2026-10-12T16:01:00.3000000Z
2026-10-12T16:01:00.4000000Z failures:
2026-10-12T16:01:00.5000000Z
2026-10-12T16:01:00.6000000Z ---- formats::pure stdout ----
2026-10-12T16:01:00.7000000Z thread 'formats::pure' panicked at src/formats/mod.rs:95:13:
2026-10-12T16:01:00.8000000Z 100% impure, a: b
2026-10-12T16:01:00.9000000Z
2026-10-12T16:01:01.0000000Z
2026-10-12T16:01:01.1000000Z failures:
2026-10-12T16:01:01.2000000Z     formats::pure
2026-10-12T16:01:01.3000000Z
2026-10-12T16:01:01.4000000Z test result: FAILED. 1 passed; 1 failed
2026-10-12T16:01:02.0000000Z      Running tests/in_process_edge_cases.rs (target/llvm-cov-target/debug/deps/in_process_edge_cases-feedbeef)
2026-10-12T16:01:02.1000000Z ---- apply_one stdout ----
2026-10-12T16:01:02.2000000Z assertion `left == right` failed
2026-10-12T16:01:02.3000000Z ---- apply_two stdout ----
2026-10-12T16:01:02.4000000Z thread 'apply_two' panicked
"""


class Failures(unittest.TestCase):
    def parse(self, text):
        return [(t, n, tf.trim(b)) for t, n, b in tf.failures(io.StringIO(text))]

    def test_each_section_is_attributed_to_its_binary(self):
        self.assertEqual(
            self.parse(LOG),
            [
                (
                    "socket_patch_core",
                    "formats::pure",
                    [
                        "thread 'formats::pure' panicked at src/formats/mod.rs:95:13:",
                        "100% impure, a: b",
                    ],
                ),
                ("in_process_edge_cases", "apply_one", ["assertion `left == right` failed"]),
                ("in_process_edge_cases", "apply_two", ["thread 'apply_two' panicked"]),
            ],
        )

    def test_a_passing_log_has_no_failures(self):
        self.assertEqual(self.parse("     Running tests/a.rs (target/debug/deps/a-1)\ntest x ... ok\n"), [])

    def test_long_bodies_are_capped(self):
        body = tf.trim([str(i) for i in range(tf.MAX_LINES + 5)] + ["", ""])
        self.assertEqual(len(body), tf.MAX_LINES + 1)
        self.assertIn("5 more lines", body[-1])

    def test_annotations_and_summary_are_escaped(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp, "log")
            log.write_text(LOG)
            summary = Path(tmp, "summary.md")
            out = io.StringIO()
            with mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary)}):
                with contextlib.redirect_stdout(out):
                    self.assertEqual(tf.main(["ci-test-failures.py", str(log)]), 0)
            lines = out.getvalue().splitlines()
            self.assertEqual(len(lines), 3)
            self.assertEqual(
                lines[0],
                "::error title=socket_patch_core formats%3A%3Apure::"
                "thread 'formats::pure' panicked at src/formats/mod.rs:95:13:%0A100%25 impure, a: b",
            )
            self.assertIn("## Failing tests (3)", summary.read_text())
            self.assertIn("### `apply_two`", summary.read_text())


if __name__ == "__main__":
    unittest.main()
