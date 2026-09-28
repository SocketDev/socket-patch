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
    return rows_mod.matrix_include(JOBS[job])


def job_text(job):
    return "\n".join(JOBS[job])


class Tiers(unittest.TestCase):
    def test_every_row_is_a_test_target(self):
        for job in ("e2e", "e2e-full"):
            for row in rows(job):
                with self.subTest(job=job, row=row):
                    suite = row["suite"]
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
                self.assertIn("if: github.event_name != 'pull_request'", text)
                self.assertIn(f"steps: *{anchor}", text)
                self.assertIn(f"steps: &{anchor}", TEXT)

    def test_nightly_schedule_runs_the_full_tier(self):
        self.assertRegex(TEXT, r"(?m)^  schedule:\n(?:    #.*\n)*    - cron: '[^']+'$")
        self.assertIn("if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'",
                      job_text("e2e-docker"))

    def test_cargo_cross_is_split_exactly(self):
        pr = [(r["os"], r["toolchain"], r.get("lock", "")) for r in rows("cargo-vex-matrix")]
        full = [(r["os"], r["toolchain"], r.get("lock", "")) for r in rows("cargo-vex-matrix-full")]
        want = {("ubuntu-latest", t, l) for t, l in itertools.product(("1.82.0", "1.93.1", "stable"),
                                                                    ("", "1", "2", "3", "4"))}
        want |= {("macos-latest", "stable", "1"), ("windows-latest", "stable", "1")}
        self.assertEqual(len(pr + full), len(want))
        self.assertEqual(set(pr) | set(full), want)
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
                            self.assertIn(row["suite"], suites)

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


class PdmCapstone(unittest.TestCase):
    job = rows_mod.jobs(PDM.read_text(encoding="utf-8"))["capstone"]

    def test_excludes_exactly_the_cells_ci_runs_on_every_pr(self):
        excluded = rows_mod.matrix_include([l.replace("exclude:", "include:") for l in self.job])
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
        for row in rows_mod.matrix_include(compat["install-proof"]):
            suites = row.get("suites", " ".join(self.suites)).split()
            keep = proof.remaining(suites, row["os"], row["vlt"], row.get("node", ""), row.get("linker", ""),
                                   row.get("cache_root", ""), TEXT)
            for suite in set(suites) - set(keep):
                with self.subTest(row=row, suite=suite):
                    self.assertFalse(row.get("node") or row.get("cache_root"))
                    upgrade = proof.proof_upgrade(row["vlt"], "") if suite == proof.UPGRADE_SUITE else None
                    self.assertTrue(any(c[:4] == (suite, row["os"], row["vlt"], row.get("linker", ""))
                                        and (upgrade is None or c[4] == upgrade) for c in cells))

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
