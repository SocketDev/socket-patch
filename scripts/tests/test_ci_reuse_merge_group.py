"""A reused CI verdict must belong to this workflow, repository and exact SHA."""

import importlib.util
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parents[2]
spec = importlib.util.spec_from_file_location("reuse", ROOT / "scripts/ci-reuse-merge-group.py")
reuse = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reuse)


class Reuse(unittest.TestCase):
    env = {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main",
           "GITHUB_REPOSITORY": "SocketDev/socket-patch", "GITHUB_SHA": "a" * 40}
    queue_run = {"id": 123, "event": "merge_group", "head_sha": "a" * 40,
           "status": "completed", "conclusion": "success", "path": ".github/workflows/ci.yml",
           "head_repository": {"full_name": "SocketDev/socket-patch"},
           "head_branch": "gh-readonly-queue/main/pr-1-abc"}

    def result(self, runs):
        return subprocess.CompletedProcess([], 0, stdout=json.dumps({"workflow_runs": runs}))

    def test_only_the_same_successful_merge_queue_workflow_is_reused(self):
        with patch.object(reuse.subprocess, "run", return_value=self.result([self.queue_run])) as call:
            self.assertEqual(reuse.reusable_run(self.env), 123)
        endpoint = call.call_args.args[0][-1]
        self.assertIn("/actions/workflows/ci.yml/runs?", endpoint)
        self.assertIn("event=merge_group", endpoint)
        self.assertIn("head_sha=" + self.env["GITHUB_SHA"], endpoint)
        self.assertLessEqual(call.call_args.kwargs["timeout"], 15)

    def test_unrelated_or_incomplete_results_cannot_skip_tests(self):
        mismatches = [
            {"head_sha": "b" * 40}, {"event": "pull_request"},
            {"path": ".github/workflows/other.yml"}, {"status": "in_progress"},
            {"conclusion": "failure"}, {"conclusion": "cancelled"},
            {"conclusion": "skipped"}, {"conclusion": None},
            {"head_repository": {"full_name": "fork/socket-patch"}},
            {"head_branch": "gh-readonly-queue/release/pr-1-abc"},
        ]
        for change in mismatches:
            with self.subTest(change=change), patch.object(
                    reuse.subprocess, "run", return_value=self.result([dict(self.queue_run, **change)])):
                self.assertIsNone(reuse.reusable_run(self.env))

    def test_direct_push_with_no_queue_run_keeps_all_checks(self):
        with patch.object(reuse.subprocess, "run", return_value=self.result([])):
            self.assertIsNone(reuse.reusable_run(self.env))

    def test_non_main_pushes_and_other_events_never_query_or_skip(self):
        changes = [{"GITHUB_EVENT_NAME": e} for e in
                   ("pull_request", "merge_group", "schedule", "workflow_dispatch")]
        changes.append({"GITHUB_REF": "refs/heads/feature"})
        for change in changes:
            with self.subTest(change=change), patch.object(reuse.subprocess, "run") as call:
                self.assertIsNone(reuse.reusable_run(dict(self.env, **change)))
                call.assert_not_called()

    def test_api_failure_timeout_and_bad_payload_keep_all_checks(self):
        for error in (FileNotFoundError(), subprocess.CalledProcessError(1, "gh"),
                      subprocess.TimeoutExpired("gh", 15)):
            with self.subTest(error=error), patch.object(reuse.subprocess, "run", side_effect=error):
                self.assertIsNone(reuse.reusable_run(self.env))
        for text in ("not json", "{}", '{"workflow_runs": null}', '{"workflow_runs": [null]}'):
            with self.subTest(text=text), patch.object(reuse.subprocess, "run", return_value=
                    subprocess.CompletedProcess([], 0, stdout=text)):
                self.assertIsNone(reuse.reusable_run(self.env))


if __name__ == "__main__":
    unittest.main()
