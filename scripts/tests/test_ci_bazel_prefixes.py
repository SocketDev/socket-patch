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
        self.assertTrue(set(planned["tests"]) <= selected)
        self.assertGreaterEqual(len(planned["tests"]), 9)

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
        self.assertIn("if: always() && needs.plan.result == 'success'", "\n".join(COMPAT_JOBS["audit"]))
        # Every key a step reads from the matrix is one the planner emits.
        emitted = set(matrix.plan(matrix.entries(), matrix.TIERS, matrix.suite_tests())[0]) - {"tests"}
        for job in ("cells", "extras"):
            read = set(re.findall(r"matrix\.([a-z_]+)", "\n".join(COMPAT_JOBS[job])))
            self.assertLessEqual(read, emitted, job)

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
