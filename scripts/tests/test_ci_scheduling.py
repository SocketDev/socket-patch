"""Keep CI's required verdict complete while scheduling each OS independently."""

import importlib.util
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[2]
spec = importlib.util.spec_from_file_location("ci_rows", Path(__file__).with_name("test_ci_vlt_rows.py"))
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)
TEXT = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
JOBS = reader.jobs(TEXT)


def dependencies(job):
    for line in JOBS[job]:
        match = re.match(r"^    needs: (.*)$", line)
        if match:
            return {s.strip() for s in match[1].strip("[]").split(",")}
    return set()


def ancestors(job, visiting=()):
    if job in visiting:
        raise AssertionError(f"dependency cycle: {visiting + (job,)}")
    parents = dependencies(job)
    return parents | {parent for dep in parents for parent in ancestors(dep, visiting + (job,))}


class Scheduling(unittest.TestCase):
    def test_required_verdict_includes_every_job(self):
        # A successful aggregate must never hide a failed OS builder/consumer
        # introduced when a matrix is split into independently scheduled jobs.
        self.assertEqual(dependencies("ci-ok"), set(JOBS) - {"ci-ok"})
        self.assertIn("    if: always()", JOBS["ci-ok"])
        self.assertIn('if v["result"] not in ("success", "skipped")', "\n".join(JOBS["ci-ok"]))
        for job in JOBS:
            ancestors(job)  # All dependencies exist and the graph is acyclic.

    def test_expensive_jobs_cannot_start_after_a_failed_preflight(self):
        cheap = {"clippy", "lint-ecosystems", "release-readiness", "dispatch-tests", "ci-ok"}
        for job in set(JOBS) - cheap:
            with self.subTest(job=job):
                self.assertIn("clippy", ancestors(job))
                # Job-level always() would defeat failure/skip propagation.
                self.assertFalse(any(line.startswith("    if:") and "always()" in line
                                     for line in JOBS[job]))
        self.assertIn("    if: github.event.pull_request.draft != true", JOBS["clippy"])
        preflight = "\n".join(JOBS["clippy"])
        self.assertIn("cargo check --locked --workspace --all-targets --all-features", preflight)

    def test_consumers_wait_only_for_their_own_os_build(self):
        for family in ("e2e", "cargo-vex-matrix"):
            for suffix, os_name in (("", "ubuntu-latest"), ("-windows", "windows-latest"),
                                    ("-macos", "macos-latest"), ("-full", "ubuntu-latest")):
                job = family + suffix
                builder = "e2e-build" + (suffix if suffix in ("-windows", "-macos") else "")
                with self.subTest(job=job):
                    self.assertEqual(dependencies(job), {builder})
                    self.assertEqual({row["os"] for row in reader.matrix_include(JOBS[job])}, {os_name})
                    self.assertIn(f"        os: [{os_name}]", JOBS[builder])
                    self.assertEqual(ancestors(job), {builder, "clippy"})

    def test_os_builds_use_the_same_artifact_contract(self):
        producer = "\n".join(JOBS["e2e-build"])
        self.assertIn("    steps: &e2e-build-steps", producer)
        self.assertIn("--all-features --tests --no-run", producer)
        self.assertIn("name: e2e-bin-${{ matrix.os }}", producer)
        self.assertIn("--os \"$BUNDLE_OS\"", producer)
        for suffix in ("windows", "macos"):
            self.assertIn("    steps: *e2e-build-steps", JOBS[f"e2e-build-{suffix}"])
            self.assertIn("    env: *e2e-build-env", JOBS[f"e2e-build-{suffix}"])
        for family in ("e2e", "cargo-vex-matrix"):
            self.assertIn("pattern: e2e-bin-${{ matrix.os }}*", "\n".join(JOBS[family]))
        for job in ("e2e-build-macos", "e2e-macos", "cargo-vex-matrix-macos", "yarn-berry-e2e-macos"):
            # Never on pull_request; lean scope also skips them (CI_SCOPE).
            condition = next(line for line in JOBS[job] if line.startswith("    if:"))
            self.assertTrue(condition.startswith("    if: (github.event_name != 'pull_request'"), condition)
            self.assertTrue(condition.endswith(" && (vars.CI_SCOPE == 'full' || github.event_name == 'schedule'"
                                               " || github.event_name == 'workflow_dispatch')"), condition)

    def test_reused_push_keeps_cache_writers_and_unqueued_jobs(self):
        # A push whose SHA passed the merge queue still compiles (main is the
        # only cache writer) and still runs what the queue never ran.
        for job in ("clippy", "node-addon", "test", "test-release", "coverage", "e2e-build",
                    "e2e-build-windows", "e2e-build-macos", "cargo-old-toolchains",
                    "e2e-full", "cargo-vex-matrix-full", "yarn-berry-full", "hosted-e2e"):
            with self.subTest(job=job):
                condition = next((line for line in JOBS[job] if line.startswith("    if:")), "")
                self.assertNotIn("outputs.reuse", condition)
        for job in ("docker-base", "yarn-classic-matrix", "yarn-berry-e2e", "yarn-berry-e2e-macos"):
            with self.subTest(job=job):
                condition = next(line for line in JOBS[job] if line.startswith("    if:"))
                self.assertIn("needs.clippy.outputs.reuse != 'true'", condition)
        for family in ("e2e", "cargo-vex-matrix"):
            for suffix in ("", "-windows", "-macos"):
                build = "e2e-build" + suffix
                with self.subTest(job=family + suffix):
                    condition = next(line for line in JOBS[family + suffix] if line.startswith("    if:"))
                    self.assertIn(f"needs.{build}.outputs.reuse != 'true'", condition)
                    self.assertIn("      reuse: ${{ needs.clippy.outputs.reuse }}", JOBS[build])
        self.assertIn("needs.e2e-build.outputs.reuse != 'true'",
                      next(line for line in JOBS["e2e-extended"] if line.startswith("    if:")))
        for job in ("test", "coverage", "cargo-old-toolchains"):
            with self.subTest(job=job):
                warm = [body for name, body in reader.steps(JOBS[job]) if name.startswith("Warm ")]
                self.assertEqual(len(warm), 1)
                self.assertIn("if: needs.clippy.outputs.reuse == 'true'", warm[0])
                self.assertIn("--no-run", warm[0])
        clippy = "\n".join(JOBS["clippy"])
        self.assertIn("actions: read", clippy)
        self.assertIn("reuse: ${{ steps.merge-queue.outputs.reuse }}", clippy)
        self.assertIn("python3 scripts/ci-reuse-merge-group.py", clippy)

    def test_row_reader_preserves_both_os_siblings(self):
        jobs = reader.jobs("""jobs:
  example:
    strategy:
      matrix:
        include:
          - {os: ubuntu-latest, suite: linux_only}
  example-windows:
    strategy:
      matrix:
        include:
          - {os: windows-latest, suite: windows_only}
  example-macos:
    strategy:
      matrix:
        include:
          - {os: macos-latest, suite: macos_only}
""")
        rows = reader.job_rows(jobs, "example")
        self.assertEqual(len(rows), 3)
        self.assertEqual({r["suite"] for r in rows}, {"linux_only", "windows_only", "macos_only"})


if __name__ == "__main__":
    unittest.main()
