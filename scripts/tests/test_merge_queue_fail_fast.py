"""Tests for scripts/merge-queue-fail-fast.py."""

import importlib.util
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[2]
CI = ROOT / ".github" / "workflows" / "ci.yml"


def load_script():
    spec = importlib.util.spec_from_file_location("fail_fast", ROOT / "scripts" / "merge-queue-fail-fast.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ff = load_script()


def job(name, status="completed", conclusion="success"):
    return {"name": name, "status": status, "conclusion": conclusion}


class FatalJobs(unittest.TestCase):
    def test_all_green_or_running_is_not_fatal(self):
        jobs = [job("clippy"), job("e2e (ubuntu)", "in_progress", None), job("e2e-full", conclusion="skipped")]
        self.assertEqual(ff.fatal_jobs(jobs), [])

    def test_failed_and_timed_out_jobs_are_fatal(self):
        jobs = [job("coverage", conclusion="failure"), job("test (windows-latest)", conclusion="timed_out"), job("clippy")]
        self.assertEqual(ff.fatal_jobs(jobs), ["coverage", "test (windows-latest)"])

    def test_cancelled_jobs_and_the_gate_itself_are_ignored(self):
        jobs = [job("e2e (ubuntu)", conclusion="cancelled"), job("ci-ok", conclusion="failure")]
        self.assertEqual(ff.fatal_jobs(jobs), [])


class CiWorkflowContract(unittest.TestCase):
    """Cancelling on a failed job is safe only while ci.yml keeps these."""

    text = CI.read_text(encoding="utf-8")

    def test_no_job_tolerates_failure(self):
        # A job-level continue-on-error would let ci-ok pass despite a failed
        # job, and this script would then cancel a run that could still land.
        self.assertIsNone(re.search(r"^\s*continue-on-error:", self.text, re.M))

    def test_gate_runs_on_a_cancelled_merge_group_run(self):
        gate = self.text[self.text.index("\n  ci-ok:"):]
        # Only PR cancellations can skip the verdict. The merge-queue
        # watcher must still turn failed/cancelled dependencies into failure.
        self.assertIn("\n    if: ${{ always() && (github.event_name != 'pull_request' || !cancelled()) }}\n", gate)


if __name__ == "__main__":
    unittest.main()
