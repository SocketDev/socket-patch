"""docs/testing/vlt-coverage.json (DESIGN §8.4): every vlt code (§2.3) is
asserted by a test, and every test, golden and CI row the map names exists."""

import importlib.util
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[2]
MAP = ROOT / "docs" / "testing" / "vlt-coverage.json"
CONTRACT = ROOT / "crates" / "socket-patch-cli" / "CLI_CONTRACT.md"
GOLDENS = ROOT / "crates" / "socket-patch-core" / "tests" / "fixtures" / "redirect"

# DESIGN §2.3, the complete list of codes vlt support adds (plus
# vendor_vlt_reinstall_required, added after the design).
CODES = [
    "redirect_vlt_lock_unsupported", "redirect_vlt_missing_sha512", "redirect_vlt_entry_not_found",
    "redirect_vlt_entry_vendored", "redirect_vlt_unsupported_lock_key",
    "redirect_vlt_custom_registry_skipped", "redirect_vlt_old_lockfile_ignored",
    "redirect_vlt_scalar_registry_ignored", "redirect_vlt_lockfile_version_missing",
    "redirect_vlt_sibling_lockfiles", "redirect_vlt_no_lockfile", "redirect_vlt_artifact_unverifiable",
    "redirect_vlt_reinstall_required", "vendor_vlt_transitive_unsupported",
    "vendor_vlt_lock_out_of_sync", "vendor_vlt_legacy_lockfile", "vendor_vlt_reinstall_required",
    "vendor_flavor_changed", "vendor_artifact_gitignored", "vlt_root_scripts_not_run",
]
MODE_COMMANDS = [
    "hosted/scan", "hosted/get", "hosted/rollback", "hosted/remove", "hosted/vex",
    "hosted/takeover (vendored to hosted)", "vendored/vendor", "vendored/scan", "vendored/get",
    "vendored/revert", "vendored/repair", "vendored/remove", "vendored/list", "vendored/vex",
    "vendored/takeover (hosted to vendored)", "vendored/scan --prune", "agent/scan", "agent/get",
    "agent/apply", "agent/rollback", "agent/remove", "agent/list", "agent/vex", "agent/crawl",
    "setup",
]
FN = re.compile(r"^(?P<indent>\s*)(?:pub(?:\([a-z]+\))?\s+)?(?:async\s+)?fn\s+(?P<name>[A-Za-z0-9_]+)")
ASSERTS = re.compile(r"assert|expect|\.contains\(|matches!")


def load_rows_module():
    spec = importlib.util.spec_from_file_location(
        "test_ci_vlt_rows", Path(__file__).with_name("test_ci_vlt_rows.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rust_sources():
    return sorted(p for p in (ROOT / "crates").rglob("*.rs") if "target" not in p.parts)


def test_regions():
    """(path, lines) of test code: files under a crate's `tests/`, and the
    part of a source file from its first `#[cfg(test)]` on."""
    out = []
    for path in rust_sources():
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        rel = path.relative_to(ROOT).parts
        if "tests" in rel:
            out.append((path, lines))
            continue
        start = next((i for i, line in enumerate(lines) if line.strip().startswith("#[cfg(test)]")),
                     None)
        if start is not None:
            out.append((path, lines[start:]))
    return out


def asserted_in_rust(code, regions):
    """The code is a literal within six lines of an assertion in test code."""
    for _, lines in regions:
        for i, line in enumerate(lines):
            if f'"{code}"' in line and any(ASSERTS.search(l) for l in lines[max(0, i - 6):i + 7]):
                return True
    return False


def asserted_in_goldens(code):
    return any(code in json.loads(p.read_text(encoding="utf-8"))
               for p in GOLDENS.rglob("expected-warnings.json"))


def fn_bodies():
    """{fn name: [body text, …]} of every Rust fn."""
    bodies = {}
    for path in rust_sources():
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        starts = [(i, m) for i, line in enumerate(lines) for m in [FN.match(line)] if m]
        for n, (i, m) in enumerate(starts):
            end = len(lines)
            for j, other in starts[n + 1:]:
                if len(other.group("indent")) <= len(m.group("indent")):
                    end = j
                    break
            bodies.setdefault(m.group("name"), []).append("\n".join(lines[i:end]))
    return bodies


class VltCoverageMap(unittest.TestCase):
    data = json.loads(MAP.read_text(encoding="utf-8"))
    bodies = fn_bodies()
    rows = load_rows_module()

    def check_names(self, names, code=None):
        for name in names:
            with self.subTest(name=name):
                if name.startswith("golden:"):
                    case = GOLDENS / name[len("golden:"):]
                    self.assertTrue((case / "expected-warnings.json").is_file(), name)
                    if code:
                        self.assertIn(code, json.loads(
                            (case / "expected-warnings.json").read_text(encoding="utf-8")), name)
                elif name.startswith(("ci:", "compat:")):
                    self.assertIn(name, self.ci_ids(), name)
                else:
                    self.assertIn(name, self.bodies, f"no `fn {name}` under crates/")

    def ci_ids(self):
        ci = self.rows.jobs((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
        compat = self.rows.jobs(
            (ROOT / ".github/workflows/vlt-compatibility.yml").read_text(encoding="utf-8"))
        ids = {f"ci:{r['suite']}:{r['os']}:{r['vlt']}"
               for r in self.rows.matrix_include(ci["e2e"]) if "vlt" in r}
        ids |= {f"compat:{r['os']}:{r['vlt']}"
                for r in self.rows.matrix_include(compat["install-proof"])}
        return ids

    def test_every_code_is_mapped_and_documented(self):
        self.assertEqual(sorted(self.data["codes"]), sorted(CODES))
        contract = CONTRACT.read_text(encoding="utf-8")
        for code in CODES:
            self.assertTrue(re.search(rf"^\| [^\n]*`{code}`", contract, re.M),
                            f"{code} is not in a CLI_CONTRACT.md table row")

    def test_every_code_is_asserted_by_a_test(self):
        regions = test_regions()
        for code in CODES:
            with self.subTest(code=code):
                self.assertTrue(asserted_in_rust(code, regions) or asserted_in_goldens(code),
                                f"{code} appears in no assertion or golden")

    def test_every_mapped_test_exists_and_one_names_the_code(self):
        for code, names in self.data["codes"].items():
            self.assertTrue(names, code)
            self.check_names(names, code)
            named = any(code in json.loads((GOLDENS / n[len("golden:"):] /
                                            "expected-warnings.json").read_text(encoding="utf-8"))
                        if n.startswith("golden:") else
                        any(code in body for body in self.bodies.get(n, []))
                        for n in names)
            self.assertTrue(named, f"no test listed for {code} mentions it")

    def test_every_advisory_variant_maps_to_existing_tests(self):
        variants = self.data["advisoryVariants"]
        for key, names in variants.items():
            self.assertIn(key.split(":", 1)[0], CODES, key)
            self.assertTrue(names, key)
            self.check_names(names)
        for code in ("redirect_vlt_reinstall_required", "redirect_vlt_artifact_unverifiable",
                     "vlt_root_scripts_not_run"):
            self.assertTrue(any(k.startswith(code + ":") for k in variants), code)

    def test_every_mode_command_cell_maps_to_existing_tests(self):
        self.assertEqual(sorted(self.data["modeCommand"]), sorted(MODE_COMMANDS))
        for key, names in self.data["modeCommand"].items():
            self.assertTrue(names, key)
            self.check_names(names)

    def test_every_era_os_cell_maps_to_ci_rows(self):
        cells = self.data["eraOs"]
        want = [f"{era}/{os_name}" for era in self.rows.ERAS
                for os_name in ("linux", "macos", "windows")]
        self.assertEqual(sorted(cells), sorted(want))
        ids = self.ci_ids()
        backtest = self.rows.backtest
        for cell, names in cells.items():
            era, os_name = cell.split("/")
            with self.subTest(cell=cell):
                self.assertTrue(names, cell)
                for name in names:
                    self.assertIn(name, ids)
                    runner = name.split(":")[-2]
                    self.assertTrue(runner.startswith({"linux": "ubuntu", "macos": "macos",
                                                       "windows": "windows"}[os_name]), name)
                    self.assertEqual(backtest.era_of(name.split(":")[-1]), era, name)


class AssertionReaderSelfTests(unittest.TestCase):
    def test_a_literal_near_an_assert_counts(self):
        regions = [(None, ['let x = 1;', 'assert_eq!(code, "vendor_x");'])]
        self.assertTrue(asserted_in_rust("vendor_x", regions))
        far = [(None, ['"vendor_y"'] + ['let a = 1;'] * 10 + ['assert!(true);'])]
        self.assertFalse(asserted_in_rust("vendor_y", far))


if __name__ == "__main__":
    unittest.main()
