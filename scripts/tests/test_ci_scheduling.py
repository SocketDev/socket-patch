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


# `workflow_dispatch -f os=<os>` (#1818) appends one OS term to a job's
# `if:`. Off dispatch inputs.os is empty, so the term is always true there
# and the rest of the condition is what PRs, the queue and the nightly see.
OS_TERM = re.compile(r"^    if: \((.*)\) && \((inputs\.os [^()]*)\)$")
OS_TERMS = {
    "linux": "inputs.os != 'windows' && inputs.os != 'macos'",
    "windows": "inputs.os != 'linux' && inputs.os != 'macos'",
    "macos": "inputs.os != 'linux' && inputs.os != 'windows'",
    "test": "inputs.os != 'linux'",
    "yarn-berry-e2e": "inputs.os != 'macos'",
}


def raw_if(job):
    return next((line for line in JOBS[job] if line.startswith("    if:")), "")


def os_term(job):
    match = OS_TERM.match(raw_if(job))
    return match[2] if match else None


def job_if(job):
    """The job's `if:` line without its dispatch-only OS term."""
    match = OS_TERM.match(raw_if(job))
    return f"    if: {match[1]}" if match else raw_if(job)


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

    def test_ci_ok_defaults_to_a_hosted_runner(self):
        # A 2 s check that runs last must not pay a Depot host boot on the
        # merge's critical path (#1745); the repo variable is the escape hatch.
        runs_on = [line for line in JOBS["ci-ok"] if line.startswith("    runs-on:")]
        self.assertEqual(runs_on, ["    runs-on: ${{ vars.CI_OK_RUNNER || 'ubuntu-latest' }}"])

    def test_release_readiness_defaults_to_a_hosted_runner(self):
        # A ~10 s gate in front of coverage and e2e-build must not pay a Depot
        # host boot on the critical path (#1795); the variable is the escape hatch.
        runs_on = [line for line in JOBS["release-readiness"] if line.startswith("    runs-on:")]
        self.assertEqual(runs_on,
                         ["    runs-on: ${{ vars.RELEASE_READINESS_RUNNER || 'ubuntu-latest' }}"])

    def test_expensive_jobs_cannot_start_after_a_failed_preflight(self):
        cheap = {"clippy", "lint-ecosystems", "release-readiness", "dispatch-tests", "ci-ok"}
        # windows-compile-check is the lean queue's only Windows job and sits
        # on its critical path, so it starts in parallel with clippy;
        # merge-queue fail-fast cancels it when clippy fails.
        parallel = {"windows-compile-check"}
        # coverage and e2e-build head the two critical-path chains and wait
        # only for the ~10 s release-readiness job, not clippy (#1681).
        # Everything downstream of them still waits for clippy.
        early = {"coverage", "e2e-build"}
        for job in early:
            self.assertEqual(dependencies(job), {"release-readiness"})
        for job in set(JOBS) - cheap:
            with self.subTest(job=job):
                if job not in parallel | early:
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
                    # The ubuntu build skips clippy (#1681), so its consumers
                    # wait for clippy themselves.
                    extra = {"clippy"} if builder == "e2e-build" else set()
                    self.assertEqual(dependencies(job), {builder} | extra)
                    self.assertEqual({row["os"] for row in reader.matrix_include(JOBS[job])}, {os_name})
                    self.assertIn(f"        os: [{os_name}]", JOBS[builder])
                    self.assertEqual(ancestors(job), {builder, "release-readiness", "clippy"})

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
            condition = job_if(job)
            self.assertTrue(condition.startswith("    if: (github.event_name != 'pull_request'"), condition)
            self.assertTrue(condition.endswith(" && (vars.CI_SCOPE == 'full' || github.event_name == 'schedule'"
                                               " || github.event_name == 'workflow_dispatch')"), condition)

    def test_lean_queue_type_checks_windows_and_full_scope_builds_it(self):
        # The lean merge queue type-checks the CLI and every CLI test target
        # on Windows (#1324) without linking (#1385); full scope, nightly and
        # dispatch build the binaries their consumers download. Lean PR and
        # push runs do neither. The nightly also runs the check, only so main
        # saves the check-mode cache the queue restores.
        check = JOBS["windows-compile-check"]
        self.assertIn("    if: (github.event_name == 'merge_group' && vars.CI_SCOPE != 'full')"
                      " || github.event_name == 'schedule'", check)
        self.assertIn("    runs-on: windows-latest", check)
        self.assertEqual(dependencies("windows-compile-check"), set())
        body = "\n".join(check)
        self.assertIn("cargo check --locked -p socket-patch-cli --all-features --lib --bins --tests", body)
        self.assertIn("    env: *e2e-build-env", check)
        self.assertIn("shared-key: check-windows-latest", body)
        self.assertIn("save-if: ${{ github.ref == 'refs/heads/main' }}", body)
        self.assertNotIn("upload-artifact", body)
        self.assertNotIn("--no-run", body)
        build = job_if("e2e-build-windows")
        self.assertEqual(build, "    if: ((github.event.pull_request.draft != true) && (vars.CI_SCOPE == 'full'"
                                " || github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'))"
                                " && needs.release-readiness.outputs.pr_unchanged != 'true'")

    def test_reused_push_keeps_cache_writers_and_unqueued_jobs(self):
        # A push whose SHA passed the merge queue still compiles (main is the
        # only cache writer) and still runs what the queue never ran. The
        # full tier runs on a push only when CI_SCOPE is full, so only then
        # does e2e-build still ship the ubuntu binaries it downloads.
        for job in ("clippy", "node-addon", "test", "test-release", "coverage", "e2e-build",
                    "e2e-build-windows", "e2e-build-macos", "cargo-old-toolchains",
                    "e2e-full", "cargo-vex-matrix-full", "yarn-berry-full", "hosted-e2e"):
            with self.subTest(job=job):
                condition = job_if(job)
                self.assertNotIn("outputs.reuse", condition)
        ship = [body for name, body in reader.steps(JOBS["e2e-build"])
                if name.startswith(("Bundle ", "Compress ")) or "upload-artifact" in body]
        self.assertEqual(len(ship), 3)
        for body in ship:
            self.assertIn("if: needs.release-readiness.outputs.reuse != 'true'"
                          " || (matrix.os == 'ubuntu-latest' && vars.CI_SCOPE == 'full')", body)
        for job in ("docker-base", "yarn-classic-matrix", "yarn-berry-e2e", "yarn-berry-e2e-macos"):
            with self.subTest(job=job):
                condition = job_if(job)
                self.assertIn("needs.release-readiness.outputs.reuse != 'true'", condition)
        for family in ("e2e", "cargo-vex-matrix"):
            for suffix in ("", "-windows", "-macos"):
                build = "e2e-build" + suffix
                with self.subTest(job=family + suffix):
                    condition = job_if(family + suffix)
                    self.assertIn(f"needs.{build}.outputs.reuse != 'true'", condition)
                    self.assertIn("      reuse: ${{ needs.release-readiness.outputs.reuse }}", JOBS[build])
        self.assertIn("needs.e2e-build.outputs.reuse != 'true'",
                      job_if("e2e-extended"))
        for job in ("test", "coverage", "cargo-old-toolchains"):
            with self.subTest(job=job):
                warm = [body for name, body in reader.steps(JOBS[job]) if name.startswith("Warm ")]
                self.assertEqual(len(warm), 1)
                self.assertIn("if: needs.release-readiness.outputs.reuse == 'true'", warm[0])
                self.assertIn("--no-run", warm[0])
        owner = "\n".join(JOBS["release-readiness"])
        self.assertIn("actions: read", owner)
        self.assertIn("reuse: ${{ steps.merge-queue.outputs.reuse }}", owner)
        self.assertIn("python3 scripts/ci-reuse-merge-group.py", owner)
        self.assertNotIn("ci-reuse-", "\n".join(JOBS["clippy"]))

    def test_every_needs_output_reader_needs_that_job(self):
        # `needs.<job>.outputs` is empty unless <job> is a direct `needs:`
        # entry, which would silently turn every reuse gate off.
        for job in JOBS:
            for parent in set(re.findall(r"needs\.([a-z0-9-]+)\.outputs", "\n".join(JOBS[job]))):
                with self.subTest(job=job, parent=parent):
                    self.assertIn(parent, dependencies(job))

    def test_unchanged_pr_merge_skips_only_what_the_queue_re_tests(self):
        # A PR push that only merged main keeps clippy and the cheap preflight
        # jobs; everything that builds or tests skips, directly or through
        # e2e-build, because the merge queue runs it again on the latest
        # main. test-release is not in the queue and hosted-e2e is never
        # scoped, so both still run.
        gated = {"node-addon", "test", "coverage", "docker-base", "e2e-build",
                 "e2e-build-windows", "yarn-classic-matrix", "yarn-berry-e2e",
                 "cargo-old-toolchains"}
        never_on_pr = "    if: (github.event_name != 'pull_request'"
        # The full tier runs on a PR only as the v5 integration PR.
        full_tier = ("    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"
                     " || (github.event_name == 'push' && vars.CI_SCOPE == 'full')"
                     " || github.head_ref == 'release/v5-prerelease'")
        for job in JOBS:
            condition = job_if(job)
            with self.subTest(job=job):
                self.assertEqual("needs.release-readiness.outputs.pr_unchanged != 'true'" in condition,
                                 job in gated)
                if job in gated:
                    self.assertTrue(condition.endswith(") && needs.release-readiness.outputs.pr_unchanged != 'true'"))
        pr_tier = {job for job in JOBS if ancestors(job) & {"clippy", "release-readiness"}}
        for job in sorted(pr_tier - gated - {"hosted-e2e", "test-release"}):
            condition = job_if(job)
            with self.subTest(job=job):
                # Ungated jobs wait on a gated build, never run on a PR, or run
                # only on the v5 integration PR, which never reuses (below).
                self.assertTrue(ancestors(job) & gated or condition == full_tier
                                or condition.startswith(never_on_pr) and "head_ref" not in condition, job)
        owner = "\n".join(JOBS["release-readiness"])
        self.assertIn("pr_unchanged: ${{ steps.pr-head.outputs.unchanged }}", owner)
        self.assertIn("python3 scripts/ci-reuse-pr-head.py", owner)
        self.assertIn("if: github.event_name == 'pull_request' && github.base_ref == 'main'"
                      " && github.head_ref != 'release/v5-prerelease'", owner)

    def test_dispatch_os_runs_only_that_os(self):
        # A Windows-only fix dispatches `-f os=windows` (#1818): its PR run
        # and the queue already cover Linux, so the ~95 Linux and macOS
        # nightly-tier jobs must not run again. clippy and release-readiness
        # always run because every OS leg waits on them.
        self.assertRegex(TEXT, r"(?m)^      os:\n(?:        #.*\n)*        description: .*\n"
                               r"        type: choice\n        default: all\n"
                               r"        options: \[all, linux, windows, macos\]$")
        oses = ("linux", "windows", "macos")
        excluded = {job: set(re.findall(r"inputs\.os != '([a-z]+)'", os_term(job) or ""))
                    for job in JOBS}

        def runs(job, os_name):
            return all(os_name not in excluded[j] for j in {job} | ancestors(job))

        def platforms(job):
            # Matrix rows and a fixed runner name the OS; every runs-on
            # mapping mentions ubuntu, and comments mention anything.
            body = "\n".join(reader.strip_comment(line) for line in JOBS[job]
                              if not line.startswith("    runs-on: ${{"))
            found = {os_name for os_name in oses
                     if re.search(rf"\b{'ubuntu' if os_name == 'linux' else os_name}-(latest|22\.04)", body)}
            return found or {"linux"}

        always = {"clippy", "release-readiness", "ci-ok", "windows-compile-check"}
        for job in JOBS:
            with self.subTest(job=job):
                if job in always:
                    self.assertIsNone(os_term(job))
                    continue
                if os_term(job) is not None:
                    self.assertIn(os_term(job), OS_TERMS.values())
                ran = {os_name for os_name in oses if runs(job, os_name)}
                self.assertEqual(ran, platforms(job))
        # Mixed-OS matrices narrow their rows to the requested OS.
        self.assertIn("          - os: ${{ inputs.os == 'windows' && 'macos-latest'"
                      " || inputs.os == 'macos' && 'windows-latest' || '' }}", JOBS["test"])
        include = next(line for line in JOBS["yarn-berry-e2e"] if "include:" in line)
        self.assertIn("""(inputs.os == 'windows' && '[{"os":"windows-latest","yarn":"4.12.0"}]'""", include)
        self.assertIn("""inputs.os == 'linux' && '[{"os":"ubuntu-latest","yarn":"4.0.2"},""", include)
        # Each OS still runs at least its build and one consumer.
        for os_name, jobs in (("linux", {"e2e-build", "e2e", "coverage"}),
                              ("windows", {"e2e-build-windows", "e2e-windows", "test"}),
                              ("macos", {"e2e-build-macos", "e2e-macos", "test"})):
            for job in jobs:
                with self.subTest(os=os_name, job=job):
                    self.assertTrue(runs(job, os_name))

    def test_late_draft_run_cannot_cancel_the_ready_run(self):
        # A push's draft-payload `synchronize` can land after `ready_for_review`
        # on the same head; sharing a group, it cancelled the real run and left
        # ci-ok green with every job skipped.
        group = re.search(r"^concurrency:\n  group: (.*)$", TEXT, re.M)[1]
        self.assertIn("github.event.pull_request.draft && '-draft'", group)
        # One dispatch per OS must not cancel the pending one before it.
        self.assertIn("${{ inputs.os && inputs.os != 'all' && format('-{0}', inputs.os) || '' }}", group)

    def test_one_os_dispatch_cannot_post_a_green_ci_ok(self):
        # A dispatch on a PR head that skipped the other OSes must not report
        # under the required check's name (#1818); every other event does.
        names = [line for line in JOBS["ci-ok"] if line.startswith("    name:")]
        self.assertEqual(names, ["    name: ${{ inputs.os && inputs.os != 'all'"
                                 " && format('ci-ok ({0} only)', inputs.os) || 'ci-ok' }}"])

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
