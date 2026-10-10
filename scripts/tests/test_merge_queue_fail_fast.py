"""Tests for scripts/merge-queue-fail-fast.py."""

import importlib.util
import io
import re
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

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


def note(message, level="failure"):
    return {"annotation_level": level, "message": message}


class RunnerLost(unittest.TestCase):
    """Annotations GitHub attached to jobs whose Depot runner died (2026-10-09)."""

    def test_depot_runner_deaths_are_recognised(self):
        for message in (
            "Step canceled by GitHub (see: https://depot.dev/docs/github-actions/troubleshooting#error-step-canceled-by-github)",
            "The runner has received a shutdown signal. This can happen when the runner service is stopped, "
            "or a manually started runner is canceled.",
            "The self-hosted runner lost communication with the server. Verify the machine is running and has "
            "a healthy network connection.",
        ):
            with self.subTest(message=message[:30]):
                self.assertTrue(ff.runner_lost([note("Node.js 20 is deprecated.", "warning"), note(message)]))

    def test_a_real_failure_is_not_a_runner_loss(self):
        self.assertFalse(ff.runner_lost([]))
        self.assertFalse(ff.runner_lost([note("Process completed with exit code 101.")]))

    def test_only_failure_level_annotations_count(self):
        self.assertFalse(ff.runner_lost([note("Step canceled by GitHub", "warning")]))


class Watch(unittest.TestCase):
    """main() against a fake API: which failed jobs make it cancel the run."""

    def watch(self, notes_by_job):
        jobs = [
            {"id": i, "name": f"job{i}", "status": "completed", "conclusion": "failure", "html_url": f"u{i}"}
            for i in notes_by_job
        ]
        calls = []

        def request(method, path, token):
            calls.append((method, path))
            if "/annotations" in path:
                return notes_by_job[int(path.split("/")[-2])]
            if path.endswith("/jobs?filter=latest&per_page=100&page=1"):
                return {"jobs": jobs}
            if "/workflows/ci.yml/runs" in path:
                return {"workflow_runs": [{"id": 7, "html_url": "run"}]}
            if path.endswith("/runs/7"):
                # Report completion on the second poll so the watch ends.
                done = sum(1 for _, p in calls if p.endswith("/runs/7")) > 1
                return {"status": "completed" if done else "in_progress"}
            return None

        env = {"GITHUB_REPOSITORY": "o/r", "HEAD_SHA": "abc", "GH_TOKEN": "t", "POLL_SECONDS": "0"}
        with mock.patch.dict(ff.os.environ, env, clear=True), mock.patch.object(ff, "request", request), \
                mock.patch.object(ff.time, "sleep"), redirect_stdout(io.StringIO()):
            ff.main()
        return calls

    def test_a_runner_loss_does_not_cancel_the_run(self):
        calls = self.watch({1: [note("Step canceled by GitHub (see: https://depot.dev/...)")]})
        self.assertNotIn(("POST", "repos/o/r/actions/runs/7/cancel"), calls)
        # The verdict is cached: annotations are fetched once across polls.
        self.assertEqual(sum("/annotations" in p for _, p in calls), 1)

    def test_a_real_failure_still_cancels_the_run(self):
        calls = self.watch({1: [note("The runner has received a shutdown signal.")], 2: [note("exit code 1")]})
        self.assertIn(("POST", "repos/o/r/actions/runs/7/cancel"), calls)


class CiWorkflowContract(unittest.TestCase):
    """Cancelling on a failed job is safe only while ci.yml keeps these."""

    text = CI.read_text(encoding="utf-8")

    def test_no_job_tolerates_failure(self):
        # A job-level continue-on-error would let ci-ok pass despite a failed
        # job, and this script would then cancel a run that could still land.
        self.assertIsNone(re.search(r"^\s*continue-on-error:", self.text, re.M))

    def test_gate_runs_on_a_cancelled_run(self):
        gate = self.text[self.text.index("\n  ci-ok:"):]
        self.assertRegex(gate, r"\n    if: always\(\)\n")


if __name__ == "__main__":
    unittest.main()
