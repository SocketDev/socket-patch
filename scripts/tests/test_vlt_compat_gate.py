"""scripts/vlt-compat-gate.py: vlt-compatibility skips its matrix only when
ci.yml is the one matching change and its vlt cells are untouched."""

import contextlib
import importlib.util
import io
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[2]
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
COMPAT = (ROOT / ".github" / "workflows" / "vlt-compatibility.yml").read_text(encoding="utf-8")

spec = importlib.util.spec_from_file_location("gate", ROOT / "scripts" / "vlt-compat-gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

PR = gate.event_paths(COMPAT, "pull_request")
PUSH = gate.event_paths(COMPAT, "push")
CI_PATH = ".github/workflows/ci.yml"


def drop_a_vlt_row(text):
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if "vlt:" in line and "--include-ignored vlt_pinned_matrix" in line:
            return "".join(lines[:i] + lines[i + 1:])
    raise AssertionError("no vlt row in ci.yml")


class Filters(unittest.TestCase):
    def test_both_events_list_ci_yml_and_the_gate(self):
        for paths in (PR, PUSH):
            self.assertIn(CI_PATH, paths)
            self.assertIn("scripts/vlt-compat-gate.py", paths)
        self.assertIn("crates/socket-patch-core/src/vendor/**", PUSH)
        self.assertNotIn("crates/socket-patch-core/src/vendor/**", PR)

    def test_globs(self):
        star = gate.glob_re("crates/*/src/**/*vlt*")
        self.assertTrue(star.match("crates/socket-patch-core/src/vendor/vlt.rs"))
        self.assertTrue(star.match("crates/socket-patch-cli/src/vlt_preflight.rs"))
        self.assertFalse(star.match("crates/a/b/src/vlt.rs"))
        self.assertTrue(gate.glob_re("crates/x/**").match("crates/x/a/b.rs"))
        self.assertFalse(gate.glob_re("crates/x/*.rs").match("crates/x/a/b.rs"))


class Decision(unittest.TestCase):
    def test_ci_yml_alone_with_the_same_cells_skips(self):
        edited = CI + "\n# an unrelated edit\n"
        for event, paths in (("pull_request", PR), ("push", PUSH)):
            self.assertFalse(gate.needs_matrix(event, [CI_PATH, "README.md"], paths, CI, edited))

    def test_a_changed_vlt_row_runs(self):
        self.assertTrue(gate.needs_matrix("pull_request", [CI_PATH], PR, CI, drop_a_vlt_row(CI)))

    def test_another_matching_file_runs(self):
        changed = [CI_PATH, "scripts/check-vlt-legs.py"]
        self.assertTrue(gate.needs_matrix("pull_request", changed, PR, CI, CI))
        changed = [CI_PATH, "crates/socket-patch-core/src/vendor/npm.rs"]
        self.assertTrue(gate.needs_matrix("push", changed, PUSH, CI, CI))

    def test_other_events_and_missing_inputs_run(self):
        for event in ("schedule", "workflow_dispatch"):
            self.assertTrue(gate.needs_matrix(event, [CI_PATH], PR, CI, CI))
        self.assertTrue(gate.needs_matrix("pull_request", [CI_PATH], [], CI, CI))
        self.assertTrue(gate.needs_matrix("pull_request", [CI_PATH], PR, None, CI))

    def test_no_base_runs(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            gate.main(["--event", "pull_request", "--base", "0" * 40])
        self.assertEqual(out.getvalue().split(), ["matrix=true"])


class ChangedPaths(unittest.TestCase):
    """main() on real commits: odd file names and renames still match."""

    def commit_pair(self, before, after):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = Path(tmp.name)

        def run(*args):
            return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True,
                                  text=True).stdout.strip()

        def write(files):
            for name, body in files.items():
                path = repo / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body, encoding="utf-8")

        run("init", "-q")
        run("config", "user.email", "t@example.com")
        run("config", "user.name", "t")
        write(before)
        run("add", "-A")
        run("commit", "-qm", "base")
        base = run("rev-parse", "HEAD")
        for name in [n for n in before if n not in after]:
            run("rm", "-q", name)
        write(after)
        run("add", "-A")
        run("commit", "-qm", "head")
        return repo, base

    def decide(self, before, after):
        repo, base = self.commit_pair(before, after)
        out = io.StringIO()
        old_repo = gate.REPO
        gate.REPO = repo
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                gate.main(["--event", "pull_request", "--base", base])
        finally:
            gate.REPO = old_repo
        return out.getvalue().split()

    def base_tree(self):
        return {CI_PATH: CI, "scripts/check-vlt-legs.py": "x\n"}

    def test_inert_ci_yml_edit_skips(self):
        after = dict(self.base_tree(), **{CI_PATH: CI + "\n# unrelated\n"})
        self.assertEqual(self.decide(self.base_tree(), after), ["matrix=false"])

    def test_odd_names_and_renames_still_run(self):
        for name in ("crates/socket-patch-cli/tests/a vlt b.rs",
                     "crates/socket-patch-cli/tests/\u00e9vlt.rs"):
            after = dict(self.base_tree(), **{CI_PATH: CI + "\n# unrelated\n", name: "x\n"})
            self.assertEqual(self.decide(self.base_tree(), after), ["matrix=true"], name)
        moved = {CI_PATH: CI + "\n# unrelated\n", "scripts/elsewhere.py": "x\n"}
        self.assertEqual(self.decide(self.base_tree(), moved), ["matrix=true"])


class Workflow(unittest.TestCase):
    def test_heavy_jobs_wait_on_the_gate(self):
        for job in ("build", "plan"):
            block = COMPAT.split(f"\n  {job}:\n", 1)[1].split("\n  ", 1)[0]
            self.assertIn("needs: changes", block, job)
        self.assertIn("needs.changes.outputs.matrix == 'true'", COMPAT.split("\n  lock-diff:\n", 1)[1][:200])
        self.assertIn("scripts/vlt-compat-gate.py", COMPAT.split("\n  changes:\n", 1)[1])


if __name__ == "__main__":
    unittest.main()
