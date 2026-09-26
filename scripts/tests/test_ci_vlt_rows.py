"""The vlt CI rows (DESIGN §8.4): ci.yml's required `e2e` rows and
`hosted-e2e` wiring, and the era × suite × OS coverage of
vlt-compatibility.yml. Parses the workflows with a small reader of the YAML
subset they use (no PyYAML on the runners)."""

import importlib.util
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[2]
CI = ROOT / ".github" / "workflows" / "ci.yml"
COMPAT = ROOT / ".github" / "workflows" / "vlt-compatibility.yml"
WATCHDOG = ROOT / ".github" / "workflows" / "vlt-serve-watchdog.yml"
SUITES = ["e2e_redirect_vlt_build", "e2e_vendor_vlt_build", "mode_migration_vlt", "e2e_safety_vlt",
          "e2e_vlt"]
ERAS = ["A0", "A", "B", "C", "D", "E", "F"]
OSES = ["ubuntu-latest", "macos-latest", "windows-latest"]


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


backtest = load_script("backtest-vlt")


def strip_comment(line):
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
    return line.rstrip()


def indent(line):
    return len(line) - len(line.lstrip(" "))


def scalar(text):
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    return text


def split_top(text):
    """Split a flow mapping's body at top-level commas."""
    parts, depth, quote, start = [], 0, None, 0
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    return [p for p in (p.strip() for p in parts) if p]


def flow_mapping(text):
    body = text.strip()
    assert body.startswith("{") and body.endswith("}"), body
    out = {}
    for item in split_top(body[1:-1]):
        key, _, value = item.partition(":")
        out[key.strip()] = scalar(value)
    return out


def jobs(text):
    """{job id: its lines} of a workflow."""
    lines = text.splitlines()
    start = lines.index("jobs:")
    found, current = {}, None
    for line in lines[start + 1:]:
        match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if match:
            current = match.group(1)
            found[current] = []
        elif current and (not line.strip() or line.startswith("   ") or line.startswith("#")):
            found[current].append(line)
        elif current and line.strip() and not line.startswith(" "):
            current = None
    return found


def matrix_include(job_lines):
    """The `strategy.matrix.include` rows of a job (flow or block style)."""
    lines = [strip_comment(l) for l in job_lines]
    at = next(i for i, l in enumerate(lines) if l.strip() == "include:")
    base = indent(lines[at])
    rows, current, item_indent = [], None, None
    for line in lines[at + 1:]:
        if not line.strip():
            continue
        if indent(line) <= base:
            break
        stripped = line.strip()
        if stripped.startswith("- "):
            item_indent = indent(line)
            body = stripped[2:]
            if body.startswith("{"):
                current = flow_mapping(body)
            else:
                key, _, value = body.partition(":")
                current = {key.strip(): scalar(value)}
            rows.append(current)
        elif current is not None and indent(line) > item_indent:
            key, _, value = stripped.partition(":")
            current[key.strip()] = scalar(value)
    return rows


def steps(job_lines):
    """[(name, text)] of a job's steps."""
    out, current = [], None
    for line in job_lines:
        match = re.match(r"^      - (?:name: (.*)|uses: .*|id: .*)$", line)
        if match:
            current = [match.group(1) or "", [line]]
            out.append(current)
        elif current is not None:
            current[1].append(line)
    return [(name, "\n".join(body)) for name, body in out]


def step(job_lines, name):
    for step_name, text in steps(job_lines):
        if step_name == name:
            return text
    raise AssertionError(f"no step named {name!r}")


class CiE2eVltRows(unittest.TestCase):
    ci = jobs(CI.read_text(encoding="utf-8"))
    rows = matrix_include(ci["e2e"])
    vlt_rows = [r for r in rows if "vlt" in r or "vlt" in r.get("suite", "")]

    def test_every_vlt_row_pins_a_release_and_includes_the_ignored_legs(self):
        self.assertTrue(self.vlt_rows)
        for row in self.vlt_rows:
            with self.subTest(row=row):
                self.assertTrue(row.get("vlt"), "a vlt row must pin a vlt release")
                self.assertIn("--include-ignored", row.get("test_filter", ""),
                              "the job default `--ignored` alone selects nothing vacuously")
                self.assertIn("vlt_pinned_matrix", row.get("test_filter", ""))
                self.assertIn(row["suite"], SUITES)

    def test_the_pr_rows_are_the_design_table(self):
        got = sorted((r["suite"], r["os"], r["vlt"], r.get("vlt_store_linker", ""),
                      r.get("vlt_upgrade", "")) for r in self.vlt_rows)
        want = []
        for suite in ("e2e_redirect_vlt_build", "e2e_vendor_vlt_build", "mode_migration_vlt",
                      "e2e_vlt"):
            want += [(suite, os_name, "1.2.0", "", "") for os_name in OSES]
        want += [("e2e_redirect_vlt_build", "ubuntu-latest", v, "", "")
                 for v in ("0.0.0-16", "0.0.0-32", "1.0.0-rc.14", "1.0.0-rc.32", "1.0.4",
                           "1.1.1")]
        want += [("e2e_vendor_vlt_build", "ubuntu-latest", v, "", "")
                 for v in ("0.0.0-32", "1.0.0-rc.14", "1.0.0-rc.32", "1.0.4")]
        want += [("e2e_vendor_vlt_build", "windows-latest", "1.0.0-rc.14", "", ""),
                 ("mode_migration_vlt", "ubuntu-latest", "0.0.0-32", "", ""),
                 ("mode_migration_vlt", "ubuntu-latest", "1.0.0-rc.14", "", "1.2.0"),
                 ("mode_migration_vlt", "windows-latest", "1.0.0-rc.14", "", ""),
                 ("e2e_safety_vlt", "ubuntu-latest", "1.2.0", "", ""),
                 ("e2e_safety_vlt", "ubuntu-latest", "1.2.0", "hardlink", ""),
                 ("e2e_safety_vlt", "macos-latest", "1.2.0", "hardlink", ""),
                 ("e2e_safety_vlt", "windows-latest", "1.2.0", "hardlink", ""),
                 ("e2e_vlt", "windows-latest", "1.0.0-rc.14", "", "")]
        want += [("e2e_vlt", "ubuntu-latest", v, "", "")
                 for v in ("0.0.0-32", "1.0.0-rc.12", "1.0.0-rc.32", "1.0.7")]
        self.assertEqual(len(want), 35)
        self.assertEqual(got, sorted(want))

    def test_every_era_has_a_row(self):
        eras = {backtest.era_of(r["vlt"]) for r in self.vlt_rows}
        self.assertEqual(sorted(eras, key=ERAS.index), ERAS)

    def test_rows_pin_supported_releases(self):
        supported, excluded = backtest.release_lists()
        for row in self.vlt_rows:
            for version in filter(None, (row["vlt"], row.get("vlt_upgrade"))):
                self.assertEqual(backtest.release_status(version, supported, excluded),
                                 "supported", version)

    def test_the_steps_install_vlt_and_check_the_legs(self):
        e2e = "\n".join(self.ci["e2e"])
        self.assertIn("key: ${{ matrix.suite }}-${{ matrix.vlt || ", e2e,
                      "vlt releases share a suite, so the release is part of the cache key")
        setup = step(self.ci["e2e"], "Setup vlt")
        self.assertIn("if: matrix.vlt != ''", setup)
        self.assertIn("scripts/install-vlt.sh", setup)
        for exported in ("SOCKET_PATCH_VLT_E2E_JS=", "SOCKET_PATCH_VLT_E2E_VERSION=",
                         "SOCKET_PATCH_VLT_E2E_REQUIRED=1", "SOCKET_PATCH_VLT_E2E_STORE_LINKER=",
                         "SOCKET_PATCH_VLT_E2E_UPGRADE_JS=", "LANG=C", "LC_ALL=C"):
            self.assertIn(exported, setup)
        node = step(self.ci["e2e"], "Setup Node.js 24 (vlt legs)")
        self.assertIn("node-version: '24.21.0'", node)
        run = step(self.ci["e2e"], "Run vlt e2e tests")
        self.assertIn("if: matrix.vlt != ''", run)
        self.assertIn("SOCKET_PATCH_VLT_E2E_REQUIRED: ${{ matrix.vlt != '' && '1' || '' }}", run)
        self.assertIn("scripts/check-vlt-legs.py", run)
        self.assertIn("vlt-leg-manifest.json", run)
        other = step(self.ci["e2e"], "Run e2e tests")
        self.assertIn("if: matrix.vlt == ''", other)

    def test_hosted_e2e_proves_vlt_against_production(self):
        hosted = self.ci["hosted-e2e"]
        setup = step(hosted, "Setup npm-family package managers")
        self.assertIn("scripts/install-vlt.sh 1.2.0", setup)
        for exported in ("SOCKET_PATCH_VLT_E2E_JS=", "SOCKET_PATCH_VLT_E2E_VERSION=1.2.0",
                         "SOCKET_PATCH_VLT_E2E_REQUIRED=1", "SOCKET_PATCH_HOSTED_E2E_STRICT=1"):
            self.assertIn(exported, setup)
        text = "\n".join(hosted)
        self.assertNotIn("SOCKET_PATCH_VLT_HOSTED_PRODUCTION_REQUIRED", text,
                         "stays unset until the serve fix is verified")
        self.assertIn("check-vlt-legs.py", step(hosted, "Run hosted-mode production e2e"))
        vendored = step(hosted, "Run vendored-mode production e2e (vlt)")
        self.assertIn("--test e2e_vendored_production", vendored)
        self.assertIn("--include-ignored vlt_pinned_matrix", vendored)
        self.assertIn("check-vlt-legs.py", vendored)
        self.assertIn("if: steps.gate.outputs.run == 'true'", vendored)


class CompatibilityWorkflow(unittest.TestCase):
    compat = jobs(COMPAT.read_text(encoding="utf-8"))
    rows = matrix_include(compat["install-proof"])

    def covered(self):
        cells = set()
        for row in self.rows:
            suites = row.get("suites", " ".join(SUITES)).split()
            for suite in suites:
                cells.add((backtest.era_of(row["vlt"]), suite, row["os"]))
        return cells

    def test_every_era_suite_and_os_is_covered(self):
        cells = self.covered()
        missing = [(e, s, o) for e in ERAS for s in SUITES for o in OSES if (e, s, o) not in cells]
        self.assertEqual(missing, [])

    def test_the_design_release_lists_are_in_the_matrix(self):
        plain = {}
        for row in self.rows:
            if not ({"node", "linker", "cache_root", "suites"} & set(row)):
                plain.setdefault(row["os"], []).append(row["vlt"])
        self.assertEqual(len(plain["ubuntu-latest"]), 31)
        self.assertLessEqual(
            {"0.0.0-30", "1.0.0-rc.8", "1.0.0-rc.13", "1.0.0-rc.14", "1.0.0-rc.15", "1.0.0-rc.22",
             "1.0.0-rc.33", "1.0.8", "1.1.1", "1.2.0"}, set(plain["macos-latest"]))
        self.assertEqual(len(plain["windows-latest"]), 15)
        supported, excluded = backtest.release_lists()
        for row in self.rows:
            self.assertEqual(backtest.release_status(row["vlt"], supported, excluded), "supported",
                             row)

    def test_node_floors_and_store_linkers(self):
        floors = sorted((r["vlt"], r["node"]) for r in self.rows if "node" in r)
        self.assertEqual(floors, [("0.0.0-1", "22.0.0"), ("0.0.0-30", "22.7.0"),
                                  ("1.0.0-rc.18", "22.13.0"), ("1.2.0", "22.22.0")])
        linkers = sorted((r["os"], r["linker"], r.get("cache_root", "")) for r in self.rows
                         if "linker" in r)
        self.assertEqual(linkers, sorted([
            ("ubuntu-latest", "auto", ""), ("ubuntu-latest", "hardlink", ""),
            ("ubuntu-latest", "copy", ""), ("ubuntu-latest", "unpack", ""),
            ("ubuntu-latest", "hardlink", "/dev/shm/vlt-e2e-cache"),
            ("macos-latest", "auto", ""), ("macos-latest", "hardlink", ""),
            ("windows-latest", "auto", ""), ("windows-latest", "hardlink", "")]))
        self.assertIn("gen-vlt-collation-golden.mjs",
                      step(self.compat["install-proof"], "Collation golden under this Node"))

    def test_jobs_and_triggers(self):
        for job in ("build", "install-proof", "native", "lock-diff", "canary", "downgrade"):
            self.assertIn(job, self.compat)
        text = COMPAT.read_text(encoding="utf-8")
        self.assertIn("schedule:", text)
        self.assertIn("workflow_dispatch:", text)
        for path in ("'scripts/backtest-vlt.py'", "'scripts/check-vlt-legs.py'",
                     "'crates/socket-patch-core/src/vendor/**'", "'Cargo.lock'",
                     "'rust-toolchain.toml'", "'.github/workflows/vlt-compatibility.yml'"):
            self.assertEqual(text.count(path), 2, f"{path} in both pull_request and push filters")
        self.assertIn("continue-on-error: true", "\n".join(self.compat["downgrade"]))
        self.assertIn("--canary-checks", "\n".join(self.compat["canary"]))
        self.assertIn("--diff-locks", "\n".join(self.compat["lock-diff"]))
        native = "\n".join(self.compat["native"])
        self.assertIn("vlt-results-${{ matrix.os }}-${{ matrix.vlt }}", native)
        self.assertIn("native-vlt/captures/**/result.json", native)
        self.assertIn("native-vlt/captures/**/tree/**", native)

    def test_watchdog(self):
        text = WATCHDOG.read_text(encoding="utf-8")
        self.assertIn("cron: '23 */6 * * *'", text)
        self.assertIn("continue-on-error: true", text)
        self.assertIn("scripts/backtest-vlt.py --serve-probe", text)


class ReaderSelfTests(unittest.TestCase):
    def test_flow_and_block_rows(self):
        job = """    strategy:
      matrix:
        include:
          # a comment
          - {os: ubuntu-latest, suite: a, test_filter: 'x:: --ignored', vlt: '1.2.0'}
          - os: macos-latest
            suite: b  # trailing
            bun: '1.4.2'
    runs-on: x""".splitlines()
        self.assertEqual(matrix_include(job), [
            {"os": "ubuntu-latest", "suite": "a", "test_filter": "x:: --ignored", "vlt": "1.2.0"},
            {"os": "macos-latest", "suite": "b", "bun": "1.4.2"}])

    def test_comment_inside_quotes_is_kept(self):
        self.assertEqual(strip_comment("a: '#b' # c"), "a: '#b'")


if __name__ == "__main__":
    unittest.main()
