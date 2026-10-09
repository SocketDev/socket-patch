"""ci.yml's build-once e2e fan-out and its PR / full tiers: every row names a
real test target that e2e-build bundles, the off-PR tiers only add releases
to suites the PR tier already runs on that OS, and the cargo toolchain x
lock cross is exactly split between the two cargo-vex jobs."""

import importlib.util
import itertools
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[2]
CI = ROOT / ".github" / "workflows" / "ci.yml"
PDM = ROOT / ".github" / "workflows" / "pdm-compatibility.yml"
TESTS = ROOT / "crates" / "socket-patch-cli" / "tests"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rows_mod = load("ci_rows", Path(__file__).parent / "test_ci_vlt_rows.py")
bundle = load("ci_e2e_bundle", ROOT / "scripts" / "ci-e2e-bundle.py")
proof = load("ci_vlt_proof_suites", ROOT / "scripts" / "ci-vlt-proof-suites.py")
COMPAT = ROOT / ".github" / "workflows" / "vlt-compatibility.yml"
TEXT = CI.read_text(encoding="utf-8")
JOBS = rows_mod.jobs(TEXT)


def rows(job):
    return rows_mod.job_rows(JOBS, job)


def job_text(job):
    return "\n".join(JOBS[job])


class Tiers(unittest.TestCase):
    def test_every_row_is_a_test_target(self):
        # `suite` may list several binaries; an `allow_empty` row may name
        # suites that have not landed yet (test_ci_gradle_prefixes.py).
        for job in ("e2e", "e2e-full"):
            for row in rows(job):
                for suite in bundle.row_suites(row):
                    with self.subTest(job=job, row=row, suite=suite):
                        self.assertTrue((TESTS / f"{suite}.rs").is_file() or (TESTS / suite / "main.rs").is_file(),
                                        f"no test target {suite}")

    def test_full_rows_only_add_releases_to_pr_suites(self):
        pr = {(r["suite"], r["os"], r.get("test_filter", "")) for r in rows("e2e")}
        for row in rows("e2e-full"):
            with self.subTest(row=row):
                self.assertIn((row["suite"], row["os"], row.get("test_filter", "")), pr)
        pr_rows = [tuple(sorted(r.items())) for r in rows("e2e")]
        full_rows = [tuple(sorted(r.items())) for r in rows("e2e-full")]
        self.assertFalse(set(pr_rows) & set(full_rows), "a row in both tiers runs twice")
        self.assertEqual(len(pr_rows + full_rows), len(set(pr_rows + full_rows)), "duplicate rows")

    def test_full_jobs_skip_pull_requests_and_share_steps(self):
        for job, anchor in (("e2e-full", "e2e-steps"), ("yarn-berry-full", "yarn-berry-steps"),
                            ("cargo-vex-matrix-full", "cargo-vex-steps")):
            with self.subTest(job=job):
                text = job_text(job)
                # The merge queue runs the pull_request tier, so the full tier
                # skips merge_group too.
                self.assertIn("if: (github.event_name != 'pull_request' && github.event_name != 'merge_group')",
                              text)
                self.assertIn(f"steps: *{anchor}", text)
                self.assertIn(f"steps: &{anchor}", TEXT)

    def test_nightly_schedule_runs_the_full_tier(self):
        self.assertRegex(TEXT, r"(?m)^  schedule:\n(?:    #.*\n)*    - cron: '[^']+'$")
        self.assertIn("if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' ||",
                      job_text("e2e-docker"))

    def test_cargo_cross_is_split_exactly(self):
        pr = [(r["os"], r["toolchain"], r.get("lock", "")) for r in rows("cargo-vex-matrix")]
        full = [(r["os"], r["toolchain"], r.get("lock", "")) for r in rows("cargo-vex-matrix-full")]
        want = {("ubuntu-latest", t, l) for t, l in itertools.product(("1.82.0", "1.93.1", "stable"),
                                                                    ("", "1", "2", "3", "4"))}
        want |= {("macos-latest", "stable", "1"), ("windows-latest", "stable", "1"),
                 ("macos-latest", "1.93.1", ""), ("windows-latest", "1.93.1", "")}
        self.assertEqual(len(pr + full), len(want))
        self.assertEqual(set(pr) | set(full), want)
        for os_name in ("ubuntu-latest", "macos-latest", "windows-latest"):
            self.assertIn((os_name, "1.93.1", ""), pr, "the pinned toolchain's own lock on every OS")
        ubuntu = [c for c in pr if c[0] == "ubuntu-latest"]
        self.assertEqual({c[1] for c in ubuntu}, {"1.82.0", "1.93.1", "stable"}, "every toolchain on PRs")
        self.assertEqual({c[2] for c in ubuntu}, {"", "1", "2", "3", "4"}, "every lock on PRs")

    def test_cargo_vex_runs_the_bundled_suites(self):
        text = job_text("cargo-vex-matrix")
        ran = set(re.findall(r"\b(e2e_[a-z_]+|mode_migration_[a-z_]+)\b", text.split("Real-cargo hosted")[1]))
        self.assertEqual(ran, set(bundle.CARGO_VEX_SUITES))

    def test_bundle_covers_every_os(self):
        for os_name in ("ubuntu-latest", "macos-latest", "windows-latest"):
            with self.subTest(os=os_name):
                suites = bundle.suites_for(os_name, TEXT)
                for job in ("e2e", "e2e-full"):
                    for row in rows(job):
                        if row["os"] == os_name:
                            for suite in bundle.row_suites(row):
                                self.assertIn(suite, suites)

    def test_bundle_reads_cargo_json(self):
        json_lines = "\n".join([
            '{"reason":"compiler-artifact","target":{"name":"e2e_vlt","kind":["test"]},'
            '"profile":{"test":true},"executable":"/t/deps/e2e_vlt-abc"}',
            '{"reason":"compiler-artifact","target":{"name":"socket_patch_cli","kind":["lib"]},'
            '"profile":{"test":true},"executable":"/t/deps/socket_patch_cli-abc"}',
            '{"reason":"compiler-artifact","target":{"name":"socket-patch","kind":["bin"]},'
            '"profile":{"test":false},"executable":"/t/debug/socket-patch"}',
            "not json",
        ])
        self.assertEqual({k: str(v) for k, v in bundle.executables(json_lines).items()},
                         {"e2e_vlt": "/t/deps/e2e_vlt-abc"})


GRADLE_COMPAT = ROOT / ".github" / "workflows" / "gradle-compatibility.yml"
GRADLE_LINES = {"6.9.4": "11", "7.6.6": "17", "8.14.3": "21", "9.8.0": "21"}
# The hosted suite is sharded over three legs per line (test_ci_gradle_prefixes
# HostedShards checks every hosted test runs in exactly one of them).
HOSTED_SHARD_1 = ["gradle_hosted_3", "gradle_hosted_4", "gradle_hosted_5"]
HOSTED_SHARD_2 = ["gradle_hosted_" + c for c in "bcdeflmnop"]
VENDOR_HOSTED = ["gradle_hosted_config_cache_second_row", "gradle_hosted_fallback_snippet_compiles_kotlin",
                 "gradle_hosted_vendored_takeover_and_eject"]
AGENT_HOSTED = (
    ("e2e_gradle_discovery_build e2e_gradle_agent_build e2e_redirect_gradle_build",
     " ".join(["--ignored", "gradle_agent_", *HOSTED_SHARD_1])),
    ("e2e_redirect_gradle_build", " ".join(["--ignored", *HOSTED_SHARD_2] + [w for p in VENDOR_HOSTED[:2] for w in ("--skip", p)])),
    ("e2e_redirect_gradle_build",
     " ".join(["--ignored", "gradle_hosted_"] + [w for p in HOSTED_SHARD_1 + HOSTED_SHARD_2 + VENDOR_HOSTED for w in ("--skip", p)])),
)
VENDOR = ("e2e_vendor_gradle_build e2e_vendor_jvm_build e2e_redirect_gradle_build",
          " ".join(["--ignored", "gradle_vendor_", "gradle_multi_project", *VENDOR_HOSTED]))


def matrix_axes(job_lines):
    """`{axis: [values]}` of a job's flow-list matrix axes (`os: [a, b]`)."""
    axes = {}
    for line in job_lines:
        match = re.match(r"^        ([a-z_]+): \[(.*)\]\s*$", rows_mod.strip_comment(line))
        if match:
            axes[match.group(1)] = [rows_mod.scalar(v) for v in rows_mod.split_top(match.group(2))]
    return axes


def expand(job_lines):
    """GitHub's matrix expansion for axes + an `include` that only extends."""
    axes = matrix_axes(job_lines)
    names = list(axes)
    cells = [dict(zip(names, combo)) for combo in itertools.product(*(axes[n] for n in names))]
    for extra in rows_mod.matrix_include(job_lines):
        matched = [c for c in cells if all(c.get(k, v) == v for k, v in extra.items() if k in names)]
        assert matched, f"include {extra} would add a cell"
        for cell in matched:
            for key, value in extra.items():
                cell.setdefault(key, value)
    return cells


class GradleRows(unittest.TestCase):
    """The PR-tier Gradle rows are the lean table the campaign decided on, the
    JVM-tool steps key on `jvm_tool`, and gradle-compatibility.yml expands to
    the full grid."""

    def test_pr_rows_are_the_lean_table(self):
        gradle = [r for r in rows("e2e") if r.get("jvm_tool") == "gradle"]
        want = []
        for line, java in GRADLE_LINES.items():
            for suite, test_filter in (*AGENT_HOSTED, VENDOR):
                row = {"os": "ubuntu-latest", "suite": suite, "jvm_tool": "gradle", "gradle": line,
                       "java": java, "test_filter": test_filter}
                if "e2e_gradle_agent_build" in suite.split():
                    row["parallel_suites"] = "true"
                # The allowance lasts only while a suite of the row is unlanded.
                if not all(bundle.landed(s) for s in suite.split()):
                    row["allow_empty"] = "true"
                want.append(row)
        want.append({"os": "windows-latest", "suite": "e2e_vendor_jvm_build", "jvm_tool": "gradle",
                     "gradle": "8.14.3", "java": "17", "test_filter": "--ignored gradle_multi_project"})
        self.assertEqual(len(gradle), 17)
        self.assertCountEqual(gradle, want)
        self.assertFalse([r for r in rows("e2e-full") if "gradle" in r or "jvm_tool" in r])

    def test_jvm_tool_marks_every_jvm_row(self):
        for job in ("e2e", "e2e-full"):
            for row in rows(job):
                with self.subTest(row=row):
                    if "gradle" in row:
                        self.assertEqual(row.get("jvm_tool"), "gradle")
                    elif "maven" in row:
                        self.assertEqual(row.get("jvm_tool"), "maven")
                    elif "sbt" in row:
                        self.assertEqual(row.get("jvm_tool"), "sbt")
                    else:
                        self.assertNotIn("jvm_tool", row)
                    self.assertIn(row.get("jvm_tool", "gradle"), ("gradle", "maven", "sbt"))

    def test_steps_key_on_jvm_tool_and_maven_only_where_seeded(self):
        steps = dict(rows_mod.steps(JOBS["e2e"]))
        select = steps["Select the JVM toolchain (JVM legs)"]
        self.assertIn("if: matrix.jvm_tool != ''", select)
        self.assertIn('var="JAVA_HOME_${JAVA_FEATURE}_${arch}"', select)
        self.assertIn("maven) maven=true ;;", select)
        # Only gradle_vendor_395 needs Maven; the multi-project capstone
        # reads the Gradle cache, so its windows row runs Maven-free.
        self.assertIn("gradle) case \" $TEST_FILTER \" in *gradle_vendor_*) maven=true ;; esac ;;", select)
        self.assertNotIn("*gradle_multi_project*", select)
        self.assertIn("if: matrix.jvm_tool != '' && steps.jvm.outputs.runner-jdk != 'true'",
                      steps["Setup Java (JDK not on the runner image)"])
        self.assertIn("if: steps.jvm.outputs.maven == 'true'", steps["Install Maven ${{ matrix.maven || '3.9.16' }}"])
        run = steps["Run e2e tests"]
        self.assertIn("scripts/ci-e2e-run.py", run)
        self.assertIn("E2E_ROW_JSON: ${{ toJSON(matrix) }}", run)

    def test_maven_seeding_follows_the_filter(self):
        def needs_maven(row):
            if row.get("jvm_tool") == "maven":
                return True
            words = row.get("test_filter", "").split()
            return row.get("jvm_tool") == "gradle" and any(
                w.startswith("gradle_vendor_") or w.startswith("gradle_multi_project") for w in words)
        gradle = [r for r in rows("e2e") if r.get("jvm_tool") == "gradle"]
        self.assertEqual(sum(needs_maven(r) for r in gradle), 5, "the vendor legs + the windows multi-project leg")
        for row in gradle:
            self.assertEqual(needs_maven(row), "gradle_vendor_" in row["test_filter"] or "gradle_multi_project" in row["test_filter"], row)

    def test_compat_grid_expands_to_36_cells_plus_extras(self):
        compat = rows_mod.jobs(GRADLE_COMPAT.read_text(encoding="utf-8"))
        cells = expand(compat["cells"])
        self.assertEqual(len(cells), 36)
        self.assertEqual({(c["os"], c["gradle"], c["java"], c["mode"]) for c in cells},
                         {(o, g, j, m) for o in ("ubuntu-latest", "macos-latest", "windows-latest")
                          for g, j in GRADLE_LINES.items() for m in ("agent", "hosted", "vendor")})
        extras = rows_mod.matrix_include(compat["extras"])
        self.assertEqual(len(extras), 13)
        labels = {}
        for row in extras:
            labels.setdefault(row["label"], []).append(row)
            self.assertEqual(row["os"], "ubuntu-latest")
        ceilings = {(r["gradle"], r["java"]) for r in labels["jdk-ceiling"]}
        self.assertEqual(ceilings, {("6.9.4", "15"), ("7.6.6", "19"), ("8.14.3", "24")})
        self.assertEqual(len(labels["jdk-ceiling"]), 9)
        self.assertEqual({(r["gradle"], r["mode"]) for r in labels["configuration-cache"]},
                         {("9.8.0", "hosted"), ("9.8.0", "vendor")})
        self.assertEqual([(r["gradle"], r["mode"], r.get("record_only")) for r in labels["isolated-projects"]],
                         [("9.8.0", "hosted", "true")])
        self.assertEqual([(r["gradle"], r["real_central"]) for r in labels["real-central"]], [("8.14.3", "1")])
        self.assertEqual(set(GRADLE_LINES), {r["gradle"] for r in rows("e2e") if r.get("jvm_tool") == "gradle"},
                         "both tiers run the same Gradle lines")

    def test_compat_pr_keeps_windows_boundaries_and_all_agent_vendor_cells(self):
        compat = rows_mod.jobs(GRADLE_COMPAT.read_text(encoding="utf-8"))
        cells = expand(compat["cells"])
        exclude_block = "\n".join(compat["cells"]).split("        exclude:", 1)[1]
        excludes = rows_mod.matrix_include(("        include:" + exclude_block).splitlines())
        for event in ("pull_request", "schedule", "workflow_dispatch"):
            resolved = []
            for row in excludes:
                row = dict(row)
                match = re.fullmatch(r"\$\{\{ github.event_name == 'pull_request' && '([^']+)' \|\| '' \}\}", row["os"])
                self.assertIsNotNone(match, row)
                row["os"] = match[1] if event == "pull_request" else ""
                resolved.append(row)
            remaining = [c for c in cells if not any(all(c[k] == v for k, v in r.items()) for r in resolved)]
            with self.subTest(event=event):
                if event == "pull_request":
                    want = {("windows-latest", g, m) for g in GRADLE_LINES for m in ("agent", "vendor")}
                    want |= {("windows-latest", g, "hosted") for g in ("6.9.4", "9.8.0")}
                    self.assertEqual({(c["os"], c["gradle"], c["mode"]) for c in remaining}, want)
                else:
                    self.assertEqual(remaining, cells, "nightly and dispatch keep the full grid")

    def test_compat_workflow_builds_its_own_binaries(self):
        text = GRADLE_COMPAT.read_text(encoding="utf-8")
        compat = rows_mod.jobs(text)
        self.assertIn("fail-fast: false", "\n".join(compat["cells"]))
        self.assertIn("timeout-minutes: 60", "\n".join(compat["cells"]))
        self.assertIn("--suites $BUNDLE_SUITES", "\n".join(compat["build"]))
        self.assertIn("python3 scripts/ci-e2e-bundle.py --check", "\n".join(compat["build"]))
        self.assertNotIn("e2e-bin", text, "the grid never reuses ci.yml's bundle")
        for trigger in ("pull_request:", "schedule:", "workflow_dispatch:"):
            self.assertIn(trigger, text)
        for path in ("crates/socket-patch-core/src/gradle/**", "crates/socket-patch-core/src/crawlers/gradle_cache.rs",
                     "crates/socket-patch-core/src/vendor/jvm/**", "crates/socket-patch-core/src/patch/jvm_jar.rs",
                     "crates/socket-patch-cli/tests/jvm_fixture_repo/**", "crates/socket-patch-cli/tests/e2e_*gradle*"):
            self.assertIn(f"'{path}'", text)
        self.assertIn("6.9 <= 15", text)
        self.assertIn("7.6 <= 19", text)
        self.assertIn("8.14 <= 24", text)
        self.assertIn("gradle-probe", text)


class PdmCapstone(unittest.TestCase):
    job = rows_mod.jobs(PDM.read_text(encoding="utf-8"))["capstone"]

    def test_excludes_exactly_the_cells_ci_runs_on_every_pr(self):
        excluded = [r for r in rows_mod.matrix_include([l.replace("exclude:", "include:") for l in self.job])
                    if not r["os"].startswith("${{")]  # the PR-only macOS exclude
        ci = {(r["os"], r["pdm"]) for r in rows("e2e") if "pdm" in r}
        self.assertEqual({(r["os"], r["pdm"]) for r in excluded}, ci)
        self.assertEqual(len(excluded), len(ci))
        for row in rows("e2e"):
            if "pdm" in row:
                self.assertEqual(row.get("test_filter"), "pdm:: --ignored")
        self.assertFalse(any("pdm" in r for r in rows("e2e-full")),
                         "a pdm row off the PR tier would leave its cell unrun on PRs")
        versions = re.search(r"pdm: \[([^\]]*)\]", "\n".join(self.job)).group(1)
        for _, version in ci:
            self.assertIn(f"'{version}'", versions)


class VltProofDedupe(unittest.TestCase):
    suites = ["e2e_redirect_vlt_build", "e2e_vendor_vlt_build", "mode_migration_vlt", "e2e_safety_vlt",
              "e2e_vlt"]

    def test_only_identical_ci_cells_are_left_out(self):
        cells = proof.ci_cells(TEXT)
        compat = rows_mod.jobs(COMPAT.read_text(encoding="utf-8"))
        for row in rows_mod.job_rows(compat, "install-proof"):
            suites = row.get("suites", " ".join(self.suites)).split()
            keep = proof.remaining(suites, row["os"], row["vlt"], row.get("node", ""), row.get("linker", ""),
                                   row.get("cache_root", ""), TEXT)
            for suite in set(suites) - set(keep):
                with self.subTest(row=row, suite=suite):
                    self.assertFalse(row.get("node") or row.get("cache_root"))
                    upgrade = proof.proof_upgrade(row["vlt"], "") if suite == proof.UPGRADE_SUITE else None
                    self.assertTrue(any(c[:4] == (suite, row["os"], row["vlt"], row.get("linker", ""))
                                        and (upgrade is None or c[4] == upgrade) for c in cells))

    def test_ci_vlt_rows_match_the_proof_invocation(self):
        for row in rows("e2e"):
            if row.get("vlt"):
                self.assertEqual(row["test_filter"], "--include-ignored vlt_pinned_matrix", row)
        ci_node = rows_mod.step(JOBS["e2e"], "Setup Node.js 24 (vlt legs)")
        proof_text = "\n".join(rows_mod.jobs(COMPAT.read_text(encoding="utf-8"))["install-proof"])
        node = re.search(r"node-version: '([^']+)'", ci_node).group(1)
        self.assertIn(f"node-version: ${{{{ matrix.node || '{node}' }}}}", proof_text)

    def test_upgrade_rule_matches_the_install_step(self):
        text = "\n".join(rows_mod.jobs(COMPAT.read_text(encoding="utf-8"))["install-proof"])
        self.assertIn("Number(m[1]) >= 19 : Number(m[2]) <= 14", text)
        self.assertIn("scripts/install-vlt.sh 1.2.0", text)
        self.assertEqual(proof.proof_upgrade("0.0.0-19", ""), "1.2.0")
        self.assertEqual(proof.proof_upgrade("0.0.0-18", ""), "")
        self.assertEqual(proof.proof_upgrade("1.0.0-rc.14", ""), "1.2.0")
        self.assertEqual(proof.proof_upgrade("1.0.0-rc.15", ""), "")
        self.assertEqual(proof.proof_upgrade("1.0.0-rc.14", "22.13.0"), "")

    def test_lv0_mode_migration_without_ci_upgrade_stays(self):
        self.assertIn("mode_migration_vlt", proof.remaining(self.suites, "windows-latest", "1.0.0-rc.14", text=TEXT))
        self.assertNotIn("mode_migration_vlt", proof.remaining(self.suites, "ubuntu-latest", "1.0.0-rc.14", text=TEXT))


if __name__ == "__main__":
    unittest.main()
