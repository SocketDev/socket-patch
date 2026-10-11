"""Only a clean base-branch merge onto a head that passed CI may skip tests."""

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parents[2]
spec = importlib.util.spec_from_file_location("reuse_pr", ROOT / "scripts/ci-reuse-pr-head.py")
reuse = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reuse)

REPO = "SocketDev/socket-patch"
HEAD, PREVIOUS, MAIN_TIP = "a" * 40, "b" * 40, "c" * 40


def file(name="src/lib.rs", patch_text="@@ -10,2 +10,3 @@ fn main() {\n a\n+b\n c", **extra):
    return dict({"filename": name, "status": "modified", "patch": patch_text}, **extra)


class PrHeadReuse(unittest.TestCase):
    env = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_REPOSITORY": REPO,
           "PR_HEAD_SHA": HEAD, "PR_BASE_REF": "main", "PR_HEAD_REPOSITORY": REPO}
    pr_run = {"id": 77, "event": "pull_request", "head_sha": PREVIOUS, "status": "completed",
              "conclusion": "success", "path": ".github/workflows/ci.yml",
              "head_repository": {"full_name": REPO}}
    jobs = [{"name": "clippy", "conclusion": "success"}, {"name": "ci-ok", "conclusion": "success"},
            {"name": "e2e-build (ubuntu-latest)", "conclusion": "success"}]

    def responses(self, parents=(PREVIOUS, MAIN_TIP), now=None, before=None, runs=None, jobs=None):
        """Fake `gh api` keyed on the endpoint, recording every call."""
        now = [file()] if now is None else now
        before = [file(patch_text="@@ -4,2 +4,3 @@ fn main() {\n a\n+b\n c")] if before is None else before
        table = {
            f"repos/{REPO}/commits/{HEAD}": {"parents": [{"sha": p} for p in parents]},
            f"repos/{REPO}/compare/main...{HEAD}?per_page=1": {"files": now},
            f"repos/{REPO}/compare/main...{PREVIOUS}?per_page=1": {"files": before},
            f"repos/{REPO}/actions/workflows/ci.yml/runs?event=pull_request&head_sha={PREVIOUS}&per_page=20":
                {"workflow_runs": [self.pr_run] if runs is None else runs},
            f"repos/{REPO}/actions/runs/77/jobs?filter=latest&per_page=100":
                {"jobs": self.jobs if jobs is None else jobs},
        }
        calls = []

        def run(argv, **kwargs):
            self.assertEqual(argv[:2], ["gh", "api"])
            self.assertLessEqual(kwargs["timeout"], 15)
            calls.append(argv[2])
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(table[argv[2]]))
        return run, calls

    def reuse_with(self, env=None, **kwargs):
        run, calls = self.responses(**kwargs)
        with patch.object(reuse.subprocess, "run", side_effect=run):
            return reuse.reusable_run(self.env if env is None else env), calls

    def test_clean_merge_of_main_onto_a_passing_head_is_reused(self):
        # main moved the PR's hunk down six lines; the change itself is equal.
        run, calls = self.reuse_with()
        self.assertEqual(run, 77)
        self.assertEqual(len(calls), 5)

    def test_ordinary_pushes_cost_one_request_and_run_everything(self):
        for parents in ((PREVIOUS,), (PREVIOUS, MAIN_TIP, "d" * 40)):
            with self.subTest(parents=len(parents)):
                run, calls = self.reuse_with(parents=parents)
                self.assertIsNone(run)
                self.assertEqual(len(calls), 1)

    def test_a_changed_pr_diff_runs_everything(self):
        cases = {
            "conflict resolution edits a hunk": [file(patch_text="@@ -10,2 +10,3 @@\n a\n+B\n c")],
            "merge brings in another file": [file(), file("src/other.rs")],
            "file renamed": [file(previous_filename="src/old.rs", status="renamed")],
            "binary or oversized patch": [{"filename": "src/lib.rs", "status": "modified"}],
            "empty PR diff": [],
            "too many files": [file(f"f{i}") for i in range(reuse.MAX_FILES)],
        }
        for name, now in cases.items():
            with self.subTest(name):
                run, _ = self.reuse_with(now=now)
                self.assertIsNone(run)

    def test_previous_head_without_a_full_passing_run_runs_everything(self):
        mismatches = [
            {"head_sha": "e" * 40}, {"event": "push"}, {"event": "merge_group"},
            {"path": ".github/workflows/other.yml"}, {"status": "in_progress"},
            {"conclusion": "failure"}, {"conclusion": "cancelled"}, {"conclusion": None},
            {"head_repository": {"full_name": "fork/socket-patch"}},
        ]
        for change in mismatches:
            with self.subTest(change=change):
                run, _ = self.reuse_with(runs=[dict(self.pr_run, **change)])
                self.assertIsNone(run)
        with self.subTest("no run"):
            self.assertIsNone(self.reuse_with(runs=[])[0])
        # A draft run passes with every job skipped; it tested nothing.
        for jobs in ([{"name": "clippy", "conclusion": "skipped"},
                      {"name": "ci-ok", "conclusion": "success"}],
                     [{"name": "clippy", "conclusion": "failure"}],
                     []):
            with self.subTest(jobs=jobs):
                self.assertIsNone(self.reuse_with(jobs=jobs)[0])

    def test_other_events_never_query_or_skip(self):
        for event in ("push", "merge_group", "schedule", "workflow_dispatch"):
            with self.subTest(event=event), patch.object(reuse.subprocess, "run") as call:
                self.assertIsNone(reuse.reusable_run(dict(self.env, GITHUB_EVENT_NAME=event)))
                call.assert_not_called()

    def test_api_failure_timeout_and_bad_payload_run_everything(self):
        for error in (FileNotFoundError(), subprocess.CalledProcessError(1, "gh"),
                      subprocess.TimeoutExpired("gh", 15)):
            with self.subTest(error=error), patch.object(reuse.subprocess, "run", side_effect=error):
                self.assertIsNone(reuse.reusable_run(self.env))
        for text in ("not json", "{}", '{"parents": null}', '{"parents": [null, null]}'):
            with self.subTest(text=text), patch.object(reuse.subprocess, "run", return_value=
                    subprocess.CompletedProcess([], 0, stdout=text)):
                self.assertIsNone(reuse.reusable_run(self.env))
        with self.subTest("missing env"), patch.object(reuse.subprocess, "run") as call:
            self.assertIsNone(reuse.reusable_run({"GITHUB_EVENT_NAME": "pull_request"}))
            call.assert_not_called()

    def test_main_writes_the_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            run, _ = self.responses()
            with patch.object(reuse.subprocess, "run", side_effect=run), \
                    patch.dict(reuse.os.environ, dict(self.env, GITHUB_OUTPUT=str(output)), clear=True):
                reuse.main()
            self.assertEqual(output.read_text(encoding="utf-8"), "unchanged=true\n")


if __name__ == "__main__":
    unittest.main()
