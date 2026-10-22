"""Tests for scripts/check-tool-pins.py, the floating-toolchain lint (#1645).

`Repository` is the gate: lint-ecosystems runs this module on every PR, so a
floating node/python/go/uv version in ci.yml fails the lean CI run.
"""

import importlib.util
from pathlib import Path
import textwrap
import unittest

ROOT = Path(__file__).parents[2]
SHA = "0" * 40


def load_script():
    spec = importlib.util.spec_from_file_location(
        "check_tool_pins", ROOT / "scripts" / "check-tool-pins.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pins = load_script()


def workflow(steps, matrix=""):
    """A one-job workflow; `steps` and `matrix` are dedented YAML blocks."""
    out = "on: push\njobs:\n  e2e:\n    runs-on: ubuntu-latest\n"
    if matrix:
        out += "    strategy:\n" + textwrap.indent(textwrap.dedent(matrix).strip("\n"), "      ") + "\n"
    out += "    steps:\n" + textwrap.indent(textwrap.dedent(steps).strip("\n"), "      ") + "\n"
    return out


def violations(steps, matrix=""):
    return pins.check_text("ci.yml", workflow(steps, matrix))


def setup(action, key, value):
    return f"""
        - name: Setup
          uses: {action}@{SHA} # vX
          with:
            {key}: {value}
        """


class FloatingVersions(unittest.TestCase):
    def test_floating_runtime_versions_are_rejected(self):
        for key, value in [
            ("node-version", "'24.x'"),
            ("python-version", "'3.12.x'"),
            ("python-version", "'3.12'"),
            ("python-version", "3.12"),
            ("go-version", "'1.24'"),
            ("node-version", "24"),
            ("node-version", "latest"),
            ("go-version", "'>=1.24.0'"),
            ("node-version", "'24.x' # exact? no"),
        ]:
            with self.subTest(key=key, value=value):
                found = violations(setup("actions/setup-x", key, value))
                self.assertEqual(len(found), 1, found)
                self.assertIn(key, found[0])
                self.assertIn("ci.yml:9:", found[0])

    def test_exact_versions_pass(self):
        self.assertEqual(violations(
            setup("actions/setup-node", "node-version", "'24.21.0' # bump deliberately")
            + setup("actions/setup-python", "python-version", "3.12.10")
            + setup("actions/setup-go", "go-version", '"1.24.13"')
        ), [])

    def test_step_starting_with_uses_is_checked(self):
        found = violations(f"""
            - uses: actions/setup-node@{SHA}
              with:
                node-version: '24.x'
            """)
        self.assertEqual(len(found), 1, found)

    def test_other_inputs_and_run_scripts_are_not_checked(self):
        self.assertEqual(violations(f"""
            - uses: ruby/setup-ruby@{SHA}
              with:
                bundler: '2.6'
            - name: Script
              run: |
                echo node-version: 24.x
                - with:
                    version: latest
            - name: Env
              env:
                go-version: '1.24'
              run: true
            """), [])


class SetupUv(unittest.TestCase):
    def test_setup_uv_without_version_is_rejected(self):
        # The 10-20 incident: no `version:`, so every run took the latest uv.
        found = violations(f"""
            - name: Setup uv
              uses: astral-sh/setup-uv@{SHA} # v6.8.0
              with:
                enable-cache: false
            - name: Next
              with:
                version: '0.13.1'
            """)
        self.assertEqual(len(found), 1, found)
        self.assertIn("without `version:`", found[0])

    def test_setup_uv_with_no_inputs_is_rejected(self):
        found = violations(f"- uses: astral-sh/setup-uv@{SHA}\n")
        self.assertEqual(len(found), 1, found)

    def test_owner_and_repo_match_case_insensitively(self):
        found = violations(f"- uses: Astral-sh/Setup-UV@{SHA}\n")
        self.assertEqual(len(found), 1, found)

    def test_setup_uv_floating_version_is_rejected(self):
        found = violations(setup("astral-sh/setup-uv", "version", "'0.13.x'"))
        self.assertEqual(len(found), 1, found)

    def test_setup_uv_exact_version_with_comments_passes(self):
        self.assertEqual(violations(f"""
            - name: Setup uv
              uses: astral-sh/setup-uv@{SHA}
              with:
                # Pin uv: bump deliberately.
                version: "0.13.1"
            """), [])


class Expressions(unittest.TestCase):
    STEP = setup("actions/setup-node", "node-version", "${{ matrix.node || '24.21.0' }}")

    def test_exact_include_values_and_fallback_pass(self):
        matrix = """
            matrix:
              include:
                - {os: ubuntu-latest, node: '22.22.1'}
                - {os: x}
            """
        self.assertEqual(violations(self.STEP, matrix), [])

    def test_floating_include_value_is_rejected(self):
        matrix = """
            matrix:
              include:
                - {os: ubuntu-latest, node: '22.x', bun: '1'}
            """
        found = violations(self.STEP, matrix)
        self.assertEqual(len(found), 1, found)
        self.assertIn("matrix.node value '22.x'", found[0])

    def test_floating_inline_axis_value_is_rejected(self):
        found = violations(self.STEP, "matrix:\n  node: ['24.21.0', '22']\n")
        self.assertEqual(len(found), 1, found)
        self.assertIn("'22'", found[0])

    def test_floating_block_axis_value_is_rejected(self):
        found = violations(self.STEP, "matrix:\n  node:\n    - 24.21.0\n    - 22.x\n")
        self.assertEqual(len(found), 1, found)
        self.assertIn("'22.x'", found[0])

    def test_floating_fallback_literal_is_rejected(self):
        found = violations(setup("actions/setup-node", "node-version", "${{ matrix.node || '24.x' }}"))
        self.assertEqual(len(found), 1, found)
        self.assertIn("'24.x'", found[0])

    def test_comparison_operands_are_not_versions(self):
        step = setup(
            "actions/setup-node",
            "node-version",
            "${{ matrix.node != '' && matrix.node || runner_os == 'Windows' && '22.22.1' || '24.21.0' }}",
        )
        found = violations(step)
        # `runner_os` isn't a context reference (no dot); only the yielded
        # literals are checked, and both are exact.
        self.assertEqual(found, [])

    def test_non_matrix_context_is_rejected(self):
        for expr in ("${{ vars.NODE_VERSION }}", "${{ env.NODE }}", "${{ inputs.node || '24.21.0' }}"):
            with self.subTest(expr=expr):
                found = violations(setup("actions/setup-node", "node-version", expr))
                self.assertEqual(len(found), 1, found)
                self.assertIn("can't be checked", found[0])

    def test_from_json_matrix_is_left_to_review(self):
        found = violations(self.STEP, "matrix: ${{ fromJSON(vars.M) }}\n")
        self.assertEqual(found, [])

    def test_matrix_of_another_job_is_not_used(self):
        text = workflow(self.STEP) + "  other:\n    strategy:\n      matrix:\n        node: ['22.x']\n"
        self.assertEqual(pins.check_text("ci.yml", text), [])


class Repository(unittest.TestCase):
    CI = ROOT / ".github" / "workflows" / "ci.yml"

    def test_ci_yml_has_no_floating_toolchains(self):
        self.assertEqual(pins.check_workflow(str(self.CI)), [])

    def test_ci_yml_setup_steps_are_seen(self):
        # Guard against the text scan silently finding nothing: count the
        # inputs it checks in ci.yml.
        lines = self.CI.read_text().splitlines()
        seen = [
            key
            for _, _, inputs in pins.steps(lines)
            for key in inputs
            if key in pins.VERSION_KEYS
        ]
        self.assertGreaterEqual(seen.count("node-version"), 6, seen)
        self.assertGreaterEqual(seen.count("python-version"), 2, seen)
        self.assertGreaterEqual(seen.count("go-version"), 3, seen)

    def test_main_exit_codes(self):
        self.assertEqual(pins.main([]), 2)
        self.assertEqual(pins.main([str(self.CI)]), 0)


if __name__ == "__main__":
    unittest.main()
