"""Tests for scripts/check-vlt-legs.py and the vlt leg manifest it checks."""

import importlib.util
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[2]
DOC = ROOT / "docs" / "testing" / "vlt-compatibility.md"
MANIFEST = ROOT / "crates" / "socket-patch-cli" / "tests" / "vlt-leg-manifest.json"
TESTS = ROOT / "crates" / "socket-patch-cli" / "tests"


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


legs = load_script("check-vlt-legs")


def log(version, os_name, lines, binaries=("e2e_redirect_vlt_build",), passed=None):
    out = []
    for b in binaries:
        out.append(f"     Running tests/{b}.rs (target/debug/deps/{b}-0123)")
    for suite, leg, status in lines:
        out.append(f"VLT-LEG {version} {os_name} {suite} {leg} {status}")
    n = len(lines) if passed is None else passed
    out.append(f"test result: ok. {n} passed; 0 failed; 0 ignored; 0 measured; 3 filtered out")
    return "\n".join(out)


def full_run(manifest, binary, version, os_name, knobs, mutate=None):
    v = legs.Version.parse(version)
    k = legs.Knobs(
        os=os_name,
        linker=knobs.get("linker") or "unset",
        cache_root=bool(knobs.get("cache_root")),
        upgrade=knobs.get("upgrade") or None,
    )
    lines = []
    for suite, names in manifest["binaries"][binary].items():
        for leg in names:
            lines.append((suite, leg, legs.expected_status(manifest, suite, leg, v, k)))
    if mutate:
        lines = mutate(lines)
    return log(version, os_name, lines, binaries=(binary,))


class ManifestIsDerivedFromTheDoc(unittest.TestCase):
    def test_the_committed_manifest_is_the_doc_derivation(self):
        derived = legs.derive(DOC.read_text(encoding="utf-8"))
        committed = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(
            committed,
            derived,
            "vlt-leg-manifest.json is stale: regenerate it with "
            "`python3 scripts/check-vlt-legs.py --derive docs/testing/vlt-compatibility.md`",
        )

    def test_every_manifest_leg_is_a_test_and_every_test_is_listed(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        declared = set()
        for binary, suites in manifest["binaries"].items():
            source = (TESTS / f"{binary}.rs").read_text(encoding="utf-8")
            found = set(re.findall(r"fn vlt_pinned_matrix_([a-z]+)_([a-z0-9_]+)\(", source))
            wanted = set()
            for suite, names in suites.items():
                for name in names:
                    wanted.add((suite, name))
            if binary.endswith("_production"):
                found = {(s, n) for s, n in found if s == "production"}
            self.assertEqual(found, wanted, f"{binary}: test fns vs manifest")
            declared |= wanted
        for suite, names in manifest["legs"].items():
            for name in names:
                self.assertIn((suite, name), declared)

    def test_every_leg_is_ignored_and_prints_through_the_leg_guard(self):
        for binary in ["e2e_redirect_vlt_build", "e2e_vendor_vlt_build", "mode_migration_vlt",
                       "e2e_safety_vlt", "e2e_vlt", "e2e_hosted_production",
                       "e2e_vendored_production"]:
            source = (TESTS / f"{binary}.rs").read_text(encoding="utf-8")
            fns = re.findall(r"((?:#\[[^\n]*\]\n)*)async fn (vlt_pinned_matrix_\w+)\(", source)
            self.assertTrue(fns, binary)
            for attrs, name in fns:
                self.assertIn("#[ignore", attrs, f"{binary}::{name} must be #[ignore]-gated")
            if not binary.endswith("_production"):
                self.assertNotIn('println!("SKIP', source, f"{binary}: skips must be VLT-LEG lines")

    def test_the_supported_releases_are_ordered_and_distinct(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        versions = [legs.Version.parse(v) for v in manifest["supported"]]
        self.assertEqual(versions, sorted(versions))
        self.assertEqual(len(versions), len(set(versions)))
        for gate in ["0.0.0-16", "0.0.0-32", "1.0.0-rc.12", "1.0.0-rc.14", "1.0.0-rc.32",
                     "1.0.4", "1.0.7", "1.1.1", "1.2.0"]:
            self.assertIn(gate, manifest["supported"])
        for gone in ["0.0.0-0", "0.0.0-5", "1.0.0-rc.20", "0.0.1", "0.0.0-22"]:
            self.assertIn(gone, manifest["excluded"])

    def test_every_rule_can_fire_on_some_supported_release(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        versions = [legs.Version.parse(v) for v in manifest["supported"]]
        for rule in manifest["rules"]:
            self.assertTrue(
                any(legs.version_matches(rule["versions"], v) for v in versions),
                f"rule never fires: {rule['boundary']}",
            )


class Versions(unittest.TestCase):
    def test_order(self):
        v = legs.Version.parse
        self.assertLess(v("0.0.0-1"), v("0.0.0-11"))
        self.assertLess(v("0.0.0-32"), v("1.0.0-rc.1"))
        self.assertLess(v("1.0.0-rc.34"), v("1.0.1"))
        self.assertLess(v("1.0.8"), v("1.0.10"))
        self.assertEqual(v("rc.14"), v("1.0.0-rc.14"))

    def test_version_cells(self):
        self.assertEqual(legs.parse_versions("`< 0.0.0-19`"), {"op": "<", "a": "0.0.0-19"})
        self.assertEqual(
            legs.parse_versions("`1.0.0-rc.7 … 1.0.0-rc.29`"),
            {"op": "range", "a": "1.0.0-rc.7", "b": "1.0.0-rc.29"},
        )
        self.assertEqual(legs.parse_versions("`all`"), {"op": "all"})
        with self.assertRaises(ValueError):
            legs.parse_versions("`sometimes`")

    def test_conditions(self):
        c = legs.parse_conditions("`linker in unset+auto, os=linux`")
        self.assertEqual(c[0], {"key": "linker", "op": "in", "value": ["unset", "auto"]})
        self.assertEqual(c[1], {"key": "os", "op": "=", "value": "linux"})
        with self.assertRaises(ValueError):
            legs.parse_conditions("`phase=moon`")


class Checking(unittest.TestCase):
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def run_check(self, text, knobs=None, binaries=()):
        return legs.check(self.manifest, text, knobs or {}, list(binaries))

    def test_a_complete_run_passes_on_every_supported_release(self):
        for binary in self.manifest["binaries"]:
            for version in self.manifest["supported"]:
                for os_name in ["linux", "macos", "windows"]:
                    text = full_run(self.manifest, binary, version, os_name, {})
                    self.assertEqual(self.run_check(text), [], f"{binary} {version} {os_name}")

    def test_era_skips_follow_the_boundaries(self):
        m = self.manifest
        k = legs.Knobs(os="macos", linker="unset", cache_root=False, upgrade=None)
        es = lambda s, l, v: legs.expected_status(m, s, l, legs.Version.parse(v), k)
        self.assertEqual(es("hosted", "frozen_dead_registry", "0.0.0-16"), "skip:no-vlt-ci")
        self.assertEqual(es("hosted", "frozen_dead_registry", "1.0.0-rc.14"), "skip:non-hermetic-registry")
        self.assertEqual(es("hosted", "frozen_dead_registry", "1.2.0"), "ran")
        self.assertEqual(es("hosted", "tamper_cold_eintegrity", "0.0.0-1"), "skip:integrity-unenforced")
        self.assertEqual(es("hosted", "tamper_cold_eintegrity", "0.0.0-11"), "ran")
        self.assertEqual(es("vendored", "scan_fresh_ci", "0.0.0-18"), "skip:a0-vendored-unsupported")
        self.assertEqual(es("vendored", "absent_version_refused", "0.0.0-16"), "ran")
        self.assertEqual(es("vendored", "absent_version_refused", "1.2.0"), "skip:lockfile-version-present")
        self.assertEqual(es("safety", "agent_rollback", "1.1.1"), "skip:no-global-store")
        self.assertEqual(es("setup", "hook_fires_per_reify", "1.0.0-rc.12"), "skip:root-postinstall-not-run")
        self.assertEqual(es("setup", "hook_fires_per_reify", "1.0.0-rc.13"), "ran")

    def test_knobs_select_the_safety_legs(self):
        m = self.manifest
        v = legs.Version.parse("1.2.0")
        es = lambda leg, **kw: legs.expected_status(
            m, "safety", leg, v,
            legs.Knobs(os=kw.get("os", "linux"), linker=kw.get("linker", "unset"),
                       cache_root=kw.get("cache_root", False), upgrade=None),
        )
        self.assertEqual(es("linux_auto"), "ran")
        self.assertEqual(es("linux_auto", os="macos"), "skip:not-linux-auto")
        self.assertEqual(es("linux_auto", linker="hardlink"), "skip:not-linux-auto")
        self.assertEqual(es("explicit_hardlink", os="macos", linker="hardlink"), "ran")
        self.assertEqual(es("private_copies", os="macos"), "ran")
        self.assertEqual(es("private_copies"), "skip:store-linker-hardlinks")
        self.assertEqual(es("private_copies", linker="copy"), "ran")
        self.assertEqual(es("cross_device_cache"), "skip:no-cache-root")
        self.assertEqual(es("cross_device_cache", linker="hardlink", cache_root=True), "ran")

    def test_the_upgrade_knob_selects_the_upgrade_legs(self):
        m = self.manifest
        es = lambda v, up: legs.expected_status(
            m, "migration", "upgrade_hosted", legs.Version.parse(v),
            legs.Knobs(os="linux", linker="unset", cache_root=False, upgrade=up),
        )
        self.assertEqual(es("1.0.0-rc.14", None), "skip:no-upgrade-vlt")
        self.assertEqual(es("1.0.0-rc.14", "1.2.0"), "ran")
        self.assertEqual(es("1.2.0", "1.2.0"), "skip:no-grammar-upgrade")
        self.assertEqual(es("1.0.0-rc.14", "1.0.0-rc.14"), "skip:no-grammar-upgrade")

    def test_failures_are_reported(self):
        good = full_run(self.manifest, "e2e_redirect_vlt_build", "1.2.0", "macos", {})
        self.assertEqual(self.run_check(good), [])
        missing = full_run(self.manifest, "e2e_redirect_vlt_build", "1.2.0", "macos", {},
                           mutate=lambda ls: ls[1:])
        self.assertTrue(any("no VLT-LEG line" in e for e in self.run_check(missing)))
        wrong = full_run(self.manifest, "e2e_redirect_vlt_build", "1.2.0", "macos", {},
                         mutate=lambda ls: [(s, l, "skip:whatever") if i == 0 else (s, l, st)
                                            for i, (s, l, st) in enumerate(ls)])
        self.assertTrue(any("expected ran" in e for e in self.run_check(wrong)))
        twice = full_run(self.manifest, "e2e_redirect_vlt_build", "1.2.0", "macos", {},
                         mutate=lambda ls: ls + ls[:1])
        self.assertTrue(any("more than one" in e for e in self.run_check(twice)))
        unknown = full_run(self.manifest, "e2e_redirect_vlt_build", "1.2.0", "macos", {},
                           mutate=lambda ls: ls + [("hosted", "not_a_leg", "ran")])
        self.assertTrue(any("not a leg" in e for e in self.run_check(unknown)))

    def test_vacuous_and_failed_runs_fail(self):
        zero = log("1.2.0", "macos", [("hosted", "scan_fresh_ci", "ran")], passed=0)
        self.assertTrue(any("0 passed" in e for e in self.run_check(zero)))
        failed = log("1.2.0", "macos", []).replace("0 failed", "2 failed").replace("ok.", "FAILED.")
        self.assertTrue(any("failed" in e for e in self.run_check(failed)))
        self.assertTrue(any("no VLT-LEG" in e for e in self.run_check(log("1.2.0", "macos", []))))

    def test_mixed_versions_fail(self):
        text = log("1.2.0", "macos", [("hosted", "scan_fresh_ci", "ran")]) + "\n" + log(
            "1.1.1", "macos", [("hosted", "scoped", "ran")])
        self.assertTrue(any("one vlt" in e for e in self.run_check(text)))

    def test_leg_lines_are_found_behind_libtest_progress_dots(self):
        text = full_run(self.manifest, "e2e_redirect_vlt_build", "1.2.0", "macos", {})
        dotted = "\n".join("." + l if l.startswith("VLT-LEG") else l for l in text.splitlines())
        self.assertEqual(self.run_check(dotted), [])

    def test_excluded_releases_are_rejected(self):
        text = log("0.0.0-22", "macos", [("hosted", "scan_fresh_ci", "ran")])
        self.assertTrue(any("excluded" in e for e in self.run_check(text)))


if __name__ == "__main__":
    unittest.main()
