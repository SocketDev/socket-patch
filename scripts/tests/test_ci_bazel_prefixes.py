"""The real-Bazel CI contract: every `#[ignore]` test of e2e_bazel_build
starts with one of the six prefixes the rows and cells select by
(ci-e2e-bundle.py's guard, and scripts/bazel-matrix.py for the tests a
macro declares); ci.yml has exactly one Bazel row, the required zero-network
`bazel_core_` row on the release the toy fixture claims it for; and
bazel-compatibility.yml keeps the shape DESIGN 9.5 gives it."""

import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[2]
CI = ROOT / ".github" / "workflows" / "ci.yml"
COMPAT = ROOT / ".github" / "workflows" / "bazel-compatibility.yml"
CLAIMS_SOURCE = "crates/socket-patch-core/tests/bazel_golden/claims.rs"
SUITE = "e2e_bazel_build"
PREFIXES = ("bazel_core_", "bazel_guard_", "bazel_agent_", "bazel_hosted_", "bazel_vendor_", "bazel_canary_")
# The one required Bazel row of ci.yml (DESIGN 9.5).
ROW = {"os": "ubuntu-latest", "suite": SUITE, "bazel": "9.3.2", "test_filter": "--ignored bazel_core_"}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rows_mod = load("ci_rows", Path(__file__).parent / "test_ci_vlt_rows.py")
bundle = load("ci_e2e_bundle", ROOT / "scripts" / "ci-e2e-bundle.py")
matrix = load("bazel_matrix", ROOT / "scripts" / "bazel-matrix.py")
CI_JOBS = rows_mod.jobs(CI.read_text(encoding="utf-8"))
COMPAT_TEXT = COMPAT.read_text(encoding="utf-8")
COMPAT_JOBS = rows_mod.jobs(COMPAT_TEXT)


class PrefixGuard(unittest.TestCase):
    def test_the_suite_is_guarded_by_its_six_prefixes(self):
        self.assertEqual(bundle.BAZEL_SUITE_PREFIXES, {SUITE: PREFIXES})
        guard = bundle.PREFIX_GUARDS[SUITE]
        for prefix in PREFIXES:
            self.assertTrue(guard.match(prefix + "x"), prefix)
        for name in ("bazel_corex", "core_bazel_x", "bazel_beta_x", "bazel_extras_x", "bazel_x",
                     "gradle_hosted_x", "x_bazel_core_"):
            self.assertFalse(guard.match(name), name)
        # And no Bazel name passes a Gradle suite's guard.
        for suite in bundle.GRADLE_SUITES:
            self.assertFalse(bundle.PREFIX_GUARDS[suite].match("bazel_hosted_x"), suite)

    def test_every_real_bazel_test_carries_a_prefix_a_macros_included(self):
        """ci-e2e-bundle.py reads `fn name` under `#[ignore]`; the baselines
        are declared by macros, which only bazel-matrix.py expands."""
        tests = matrix.suite_tests()
        plain = {n for path in bundle.suite_files(SUITE) for n in bundle.ignored_tests(path.read_text(encoding="utf-8"))}
        self.assertTrue(plain and plain < set(tests))
        self.assertGreater(len(set(tests) - plain), 50, "the macro-declared baselines")
        for name in tests:
            with self.subTest(test=name):
                self.assertTrue(bundle.PREFIX_GUARDS[SUITE].match(name))
        self.assertEqual(bundle.prefix_violations(guards={SUITE: bundle.PREFIX_GUARDS[SUITE]}), [])

    def test_negative_a_stray_name_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            suite = Path(tmp) / SUITE
            suite.mkdir()
            (suite / "main.rs").write_text("mod lane;\n", encoding="utf-8")
            (suite / "lane.rs").write_text(
                '#[test]\n#[ignore = "real Bazel"]\nfn bazel_hosted_rules_js_bzlmod() {}\n\n'
                "#[test]\n#[ignore]\nfn bazel_beta_rules_js_bzlmod() {}\n\n"
                "#[test]\nfn hermetic_and_not_ignored() {}\n", encoding="utf-8")
            self.assertEqual(bundle.prefix_violations(Path(tmp), {SUITE: bundle.PREFIX_GUARDS[SUITE]}),
                             [(SUITE, f"{SUITE}/lane.rs", "bazel_beta_rules_js_bzlmod")])
            self.assertEqual(matrix.suite_tests(Path(tmp)), {
                "bazel_hosted_rules_js_bzlmod": "lane::bazel_hosted_rules_js_bzlmod",
                "bazel_beta_rules_js_bzlmod": "lane::bazel_beta_rules_js_bzlmod"})
            self.assertIsNone(matrix.mode_of("bazel_beta_rules_js_bzlmod"))
            self.assertEqual(matrix.mode_of("bazel_hosted_rules_js_bzlmod"), "hosted")


class CiRow(unittest.TestCase):
    """The primary acceptance: T3 and T4 reported the zero-network row
    reachable on 9.3.2, so ci.yml carries it. Should a Linux x86_64 cell
    refute that, the row goes and this class asserts its absence instead."""

    def bazel_rows(self, job):
        return [r for r in rows_mod.matrix_include(CI_JOBS[job]) if "bazel" in r or "bazel" in r.get("suite", "")]

    def test_ci_has_exactly_the_one_required_core_row(self):
        self.assertEqual(self.bazel_rows("e2e"), [ROW])
        self.assertNotIn("jvm_tool", self.bazel_rows("e2e")[0])
        for job in CI_JOBS:
            if job != "e2e" and any(l.strip() == "include:" for l in CI_JOBS[job]):
                with self.subTest(job=job):
                    self.assertEqual(self.bazel_rows(job), [])

    def test_the_row_runs_the_cell_the_toy_matrix_claims_without_network(self):
        core = json.loads((matrix.FIXTURES / "core/MATRIX.json").read_text(encoding="utf-8"))
        cell = next(c for c in core["cells"] if c["bazel"] == ROW["bazel"])
        self.assertEqual(cell["tier"][ROW["os"]], "pr")
        # Zero network: the row is claimed where the archives are committed.
        self.assertEqual(cell["network"], "none")
        self.assertIn(ROW["bazel"], core["tests"]["bazel_core_zero_network"]["bazel"])
        self.assertIn((ROW["bazel"], matrix.RUNNERS[ROW["os"]][1]), matrix.pinned())
        # The prefix selects toy tests only, and every one the cell plans.
        prefix = ROW["test_filter"].split()[-1]
        self.assertEqual(prefix, core["filter"])
        selected = {name for name in matrix.suite_tests() if prefix in name}
        self.assertEqual(selected, set(core["tests"]))
        planned = next(c for c in matrix.plan(matrix.entries(), ("pr",), matrix.suite_tests())
                       if c["id"] == "core-9.3.2-ubuntu-core")
        # The row runs every `bazel_core_` test the cell plans. What else
        # the cell holds (the toy fixture's tests of another prefix) is
        # left to bazel-compatibility.yml.
        in_cell = {name for name in planned["tests"] if name.startswith(core["filter"])}
        self.assertGreaterEqual(len(in_cell), 9)
        self.assertLessEqual(in_cell, selected)

    def test_the_install_steps_key_on_the_row(self):
        steps = dict(rows_mod.steps(CI_JOBS["e2e"]))
        for name in ("Restore the Bazel ${{ matrix.bazel }} binaries", "Install Bazel ${{ matrix.bazel }}",
                     "Save the Bazel ${{ matrix.bazel }} binaries"):
            with self.subTest(step=name):
                self.assertIn("matrix.bazel != ''", steps[name])
        install = steps["Install Bazel ${{ matrix.bazel }}"]
        self.assertIn('scripts/install-bazelisk.sh "$BAZEL_VERSION" "$RUNNER_TEMP/bazel-dist" >> "$GITHUB_ENV"', install)
        # The leg fails instead of skipping when Bazel is missing.
        self.assertIn('echo "SOCKET_PATCH_BAZEL_E2E_REQUIRED=1"', install)
        self.assertIn('echo "SOCKET_PATCH_BAZEL_E2E_GROUP=core"', install)
        self.assertIn("github.ref == 'refs/heads/main'", steps["Save the Bazel ${{ matrix.bazel }} binaries"])
        # setup-bazel rewrites ~/.bazelrc and verifies no digest.
        self.assertNotIn("setup-bazel", CI.read_text(encoding="utf-8").replace("no setup-bazel", ""))

    def test_the_installer_is_shellchecked(self):
        lint = "\n".join(CI_JOBS["lint-ecosystems"])
        self.assertRegex(lint, r"run: shellcheck [^\n]*scripts/install-bazelisk\.sh")

    def test_the_bundle_carries_the_suite_for_the_row(self):
        self.assertIn(SUITE, bundle.suites_for("ubuntu-latest"))
        self.assertTrue(bundle.landed(SUITE))


class CompatWorkflow(unittest.TestCase):
    def test_triggers(self):
        head = COMPAT_TEXT.split("\njobs:\n")[0]
        on = head[head.index("\non:\n"):head.index("\npermissions:\n")]
        self.assertIn("types: [opened, synchronize, reopened, ready_for_review, labeled]", on)
        self.assertRegex(on, r"\n  schedule:\n(    #[^\n]*\n)*    - cron: '\d+ \d+ \* \* \*'")
        self.assertIn("\n  workflow_dispatch:\n", on)
        # Never in the merge queue, and no other trigger.
        self.assertEqual(re.findall(r"^  ([a-z_]+):", on, re.M), ["pull_request", "schedule", "workflow_dispatch"])
        self.assertIn(f"github.event.label.name != '{matrix.LABEL}'", head)

    def test_it_is_not_part_of_the_required_verdict(self):
        self.assertNotIn("bazel-compatibility", CI.read_text(encoding="utf-8").split("\n  ci-ok:\n")[1])

    def test_jobs_run_plan_build_cells_extras_audit(self):
        self.assertEqual(list(COMPAT_JOBS), ["plan", "build", "cells", "extras", "audit"])
        needs = {job: re.search(r"^    needs: \[([^\]]*)\]", "\n".join(lines), re.M) for job, lines in COMPAT_JOBS.items()}
        self.assertIsNone(needs["plan"])
        self.assertEqual({job: [n.strip() for n in found.group(1).split(",")] for job, found in needs.items() if found},
                         {"build": ["plan"], "cells": ["plan", "build"], "extras": ["plan", "build"],
                          "audit": ["plan", "cells", "extras"]})
        plan = "\n".join(COMPAT_JOBS["plan"])
        self.assertIn("python3 scripts/ci-e2e-bundle.py --check", plan)
        self.assertIn("python3 scripts/bazel-matrix.py --check", plan)
        self.assertIn('python3 scripts/bazel-matrix.py --event "$EVENT_NAME" --labels "$LABELS" '
                      '--github-output "$GITHUB_OUTPUT"', plan)
        for output in ("tiers", "cells", "extras", "build"):
            self.assertIn(f"      {output}: ${{{{ steps.plan.outputs.{output} }}}}", plan)
        build = "\n".join(COMPAT_JOBS["build"])
        self.assertIn(f"--test {SUITE} > target-build.json", build)
        self.assertIn(f"--dest target/bazel-bin --suites {SUITE}", build)
        # The paths the cells filter on are held to the binary's own list,
        # after the bundle and before it is uploaded for the cells.
        steps = [name for name, _ in rows_mod.steps(COMPAT_JOBS["build"])]
        listed = "Hold the cell filters to the tests the binary lists"
        self.assertLess(steps.index("Bundle the binaries the cells run"), steps.index(listed))
        self.assertEqual(steps[-1], "", "the upload is the last step")
        check = dict(rows_mod.steps(COMPAT_JOBS["build"]))[listed]
        self.assertIn(f'"target/bazel-bin/{SUITE}$exe" --list --ignored > target/bazel-tests.txt', check)
        self.assertIn("scripts/bazel-matrix.py --check --libtest-list target/bazel-tests.txt", check)
        self.assertIn("set -euo pipefail", check)
        # The matrices are generated: nothing is listed by hand.
        for job, output in (("cells", "cells"), ("extras", "extras")):
            text = "\n".join(COMPAT_JOBS[job])
            self.assertIn(f"include: ${{{{ fromJSON(needs.plan.outputs.{output}) }}}}", text)
            self.assertIn(f"if: needs.plan.outputs.{output} != '[]'", text)
            self.assertIn("continue-on-error: ${{ matrix.record_only == 'true' }}", text)
        self.assertIn("steps: *cell-steps", "\n".join(COMPAT_JOBS["extras"]))

    def test_a_cell_runs_its_exact_tests_and_then_audits_its_reports(self):
        run = dict(rows_mod.steps(COMPAT_JOBS["cells"]))["Run the cell"]
        self.assertIn(f'"../../target/bazel-bin/{SUITE}$exe" --ignored --nocapture --test-threads=2 $CELL_FILTER', run)
        self.assertIn("SOCKET_PATCH_BAZEL_E2E_REQUIRED: '1'", run)
        self.assertIn("SOCKET_PATCH_BAZEL_E2E_GROUP: ${{ matrix.group }}", run)
        self.assertIn("SOCKET_PATCH_BAZEL_E2E_PROBE_DIR: ${{ github.workspace }}/target/bazel-probe", run)
        self.assertIn('scripts/bazel-matrix-audit.py --reports target/bazel-probe --tiers "$TIERS" --cell "$CELL_ID" '
                      "--require hosts,wall_ms,resolved || status=1", run)
        audit = dict(rows_mod.steps(COMPAT_JOBS["audit"]))["Audit the reports"]
        self.assertIn('args=(--reports target/bazel-reports --tiers "$TIERS" --require "hosts,wall_ms,resolved")', audit)
        self.assertIn('if [ -n "$CLAIMS" ]; then args+=(--claims "$CLAIMS"); fi', audit)
        # After failed cells too, and not on a cancelled run: `always()`
        # would start the audit of a superseded commit.
        conditions = re.findall(r"^    if: (.*)$", "\n".join(COMPAT_JOBS["audit"]), re.M)
        self.assertEqual(conditions, ["${{ !cancelled() && needs.plan.result == 'success' }}"])
        self.assertNotIn("always()", conditions[0])
        self.assertIn("cancel-in-progress: ${{ github.event_name == 'pull_request' }}", COMPAT_TEXT)
        # Every key a step reads from the matrix is one the planner emits.
        emitted = set(matrix.plan(matrix.entries(), matrix.TIERS, matrix.suite_tests())[0]) - {"tests"}
        for job in ("cells", "extras"):
            read = set(re.findall(r"matrix\.([a-z_]+)", "\n".join(COMPAT_JOBS[job])))
            self.assertLessEqual(read, emitted, job)

    def test_the_repository_cache_is_one_rolling_cache_per_group_bazel_and_runner(self):
        """The cells of one (group, Bazel, runner) differ by mode and share
        a repository cache. A key is written once: under one key for all of
        them the first cell to finish saved its own fetches and the others
        never could. So each cell saves under a key of its own, and every
        cell restores the newest one of the shared prefix."""
        steps = dict(rows_mod.steps(COMPAT_JOBS["cells"]))
        restore = steps["Restore the repository cache"]
        key = re.search(r"^          key: (.*)$", restore, re.M).group(1)
        shared = "bazel-repos-${{ matrix.group }}-${{ matrix.bazel }}-${{ runner.os }}-"
        self.assertTrue(key.startswith(shared + "${{ hashFiles("), key)
        # Unique per cell and run: never an exact hit, never a key already taken.
        self.assertTrue(key.endswith("-${{ matrix.mode }}-${{ github.run_id }}-${{ github.run_attempt }}"), key)
        fallbacks = re.search(r"^          restore-keys: \|\n((?:            .*\n?)+)", restore, re.M).group(1)
        fallbacks = [line.strip() for line in fallbacks.splitlines()]
        self.assertEqual(len(fallbacks), 2, fallbacks)
        # Each is a prefix of the key that stops before the mode, so it
        # matches what any cell of the line saved: the same fixtures
        # first, then any.
        for prefix in fallbacks:
            self.assertTrue(key.startswith(prefix) and prefix.endswith("-"), prefix)
            self.assertNotIn("matrix.mode", prefix)
            self.assertNotIn("github.run_id", prefix)
        self.assertGreater(len(fallbacks[0]), len(fallbacks[1]))
        self.assertEqual(fallbacks[1], shared)
        self.assertIn("if: matrix.cache == 'restore'", restore)
        # A cell saves when it fetched what the restored cache lacked,
        # which the run step reports, and only from main.
        run = steps["Run the cell"]
        self.assertIn("        id: run\n", run)
        for line in ('cached > "$RUNNER_TEMP/bazel-repos.before"', 'cached > "$RUNNER_TEMP/bazel-repos.after"',
                     'comm -13 "$RUNNER_TEMP/bazel-repos.before" "$RUNNER_TEMP/bazel-repos.after"',
                     'echo "repos_grew=true" >> "$GITHUB_OUTPUT"'):
            self.assertIn(line, run)
        self.assertLess(run.index("bazel-repos.before"), run.index(f"bazel-bin/{SUITE}$exe"))
        self.assertLess(run.index("bazel-matrix-audit.py"), run.index("bazel-repos.after"))
        save = steps["Save the repository cache"]
        for condition in ("matrix.cache == 'restore'", "github.ref == 'refs/heads/main'",
                          "steps.run.outputs.repos_grew == 'true'", "steps.repo-cache.outcome == 'success'"):
            self.assertIn(condition, save)
        self.assertNotIn("cache-hit", save)
        self.assertIn("key: ${{ steps.repo-cache.outputs.cache-primary-key }}", save)
        # The planner gives the cells that share a prefix different modes.
        restoring = [c for c in matrix.plan(matrix.entries(), matrix.TIERS, matrix.suite_tests()) if c["cache"]]
        self.assertTrue(restoring)
        keys = [(c["group"], c["bazel"], c["os"], c["mode"]) for c in restoring]
        self.assertEqual(len(keys), len(set(keys)))

    def claims_step(self):
        return dict(rows_mod.steps(COMPAT_JOBS["audit"]))["Dump the lane claims"]

    def is_stub(self, text):
        """The workflow's own test for "claims.rs holds no code", applied
        to `text`: `grep -Evq PATTERN` finds a line that is neither blank
        nor a comment."""
        pattern = re.search(r"if ! grep -Evq '([^']+)' \"\$CLAIMS_SOURCE\"; then", self.claims_step()).group(1)
        blank_or_comment = re.compile(pattern.replace("[[:space:]]", r"\s"))
        return all(blank_or_comment.match(line) for line in text.splitlines())

    def test_the_claims_dump_is_found_by_its_source_not_by_how_many_tests_ran(self):
        """"0 passed" is what a stub prints, and also a `claims::dump` that
        was renamed, moved or ignored. The step tells them apart by the
        source: comments only is the stub; code means exactly one test
        named `claims::dump` must run and leave the file."""
        step = self.claims_step()
        self.assertIn(f"CLAIMS_SOURCE: {CLAIMS_SOURCE}", step)
        self.assertIn("if: needs.plan.outputs.tiers == 'full'", step)
        self.assertIn("--test bazel_golden -- --exact claims::dump 2>&1 | tee claims.log", step)
        stub_branch = step[step.index("if ! grep -Evq"):step.index("cargo test")]
        self.assertIn("::notice::", stub_branch)
        self.assertIn("exit 0", stub_branch)
        after = step[step.index("cargo test"):]
        self.assertNotIn("::notice::", after)
        self.assertRegex(after, r'if \[ "\$\{ran:-0\}" != 1 \]; then\n\s+echo "::error::[^\n]*\n\s+exit 1\n')
        self.assertRegex(after, r'if \[ ! -f target/bazel-claims\.json \]; then\n\s+echo "::error::[^\n]*\n\s+exit 1\n')
        self.assertRegex(step, r'if \[ ! -f "\$CLAIMS_SOURCE" \]; then\n\s+echo "::error::[^\n]*\n\s+exit 1\n')
        self.assertTrue(after.rstrip().endswith('echo "file=target/bazel-claims.json" >> "$GITHUB_OUTPUT"'))
        # The stub test itself, on sources of both kinds.
        self.assertTrue(self.is_stub("//! Goldens: writes the claims.\n//! Stub until the gate.\n\n  // fn dump\n"))
        for code in ("//! Doc.\n\n#[test]\nfn dump() {}\n", "//! Doc.\nmod dump;\n", "use x::y;\n",
                     "//! Doc.\n    #[test]\n    #[ignore]\n    fn dump_later() {}\n", "claims! { dump }\n"):
            self.assertFalse(self.is_stub(code), code)

    def test_the_claims_source_is_the_stub_or_declares_the_test_the_workflow_runs(self):
        """Holds claims.rs to the name the audit job runs. Once the file
        holds code it declares `#[test] fn dump()` at its top level (libtest:
        `claims::dump`), not ignored; a rename fails here, in a required
        unit test, instead of leaving the claims unaudited."""
        path = ROOT / CLAIMS_SOURCE
        self.assertTrue(path.is_file(), f"{CLAIMS_SOURCE} moved: the audit job reads the claims dump from it")
        golden = (path.parent / "main.rs").read_text(encoding="utf-8")
        self.assertIn("\nmod claims;\n", golden)

        def problem(text):
            if self.is_stub(text):
                return None
            other = r"((?:#\[[^\n]*\]\n|//[^\n]*\n)*)"
            found = re.search("^" + other + r"#\[test\]\n" + other + r"fn dump\(\)", text, re.M)
            if not found:
                return "no top-level `#[test] fn dump()`"
            return "`dump` is ignored" if "#[ignore" in found.group(1) + found.group(2) else None

        self.assertIsNone(problem(path.read_text(encoding="utf-8")))
        # The rule, on what the file may become.
        self.assertIsNone(problem("//! Doc.\n\nuse x::y;\n\n/// Writes it.\n#[test]\nfn dump() {\n    y();\n}\n"))
        self.assertEqual(problem("//! Doc.\n\n#[test]\nfn dump_claims() {}\n"), "no top-level `#[test] fn dump()`")
        self.assertEqual(problem("//! Doc.\n\nmod inner {\n    #[test]\n    fn dump() {}\n}\n"),
                         "no top-level `#[test] fn dump()`")
        self.assertEqual(problem("//! Doc.\n\nfn dump() {}\n"), "no top-level `#[test] fn dump()`")
        self.assertEqual(problem('#[test]\n#[ignore = "later"]\nfn dump() {}\n'), "`dump` is ignored")
        self.assertEqual(problem("//! Doc.\n\n/// Writes it.\n#[ignore]\n#[test]\nfn dump() {}\n"), "`dump` is ignored")

    def test_every_action_is_pinned_to_a_commit_and_bazel_comes_from_the_installer(self):
        uses = re.findall(r"^\s*(?:- )?uses: (\S+)", COMPAT_TEXT, re.M)
        self.assertGreater(len(uses), 10)
        for ref in uses:
            with self.subTest(uses=ref):
                self.assertTrue(ref.startswith("./") or re.fullmatch(r"[^@]+@[0-9a-f]{40}", ref), ref)
        self.assertNotIn("setup-bazel", COMPAT_TEXT.replace("no setup-bazel", ""))
        install = dict(rows_mod.steps(COMPAT_JOBS["cells"]))["Install Bazel ${{ matrix.bazel }}"]
        self.assertIn('scripts/install-bazelisk.sh "$BAZEL_VERSION" "$RUNNER_TEMP/bazel-dist" >> "$GITHUB_ENV"', install)
        # Both workflows restore the installer's directory under one key.
        key = "key: bazel-dist-${{ matrix.bazel }}-${{ runner.os }}-${{ hashFiles('scripts/bazel-pins.txt', 'scripts/install-bazelisk.sh') }}"
        self.assertIn(key, COMPAT_TEXT)
        self.assertIn(key, CI.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
