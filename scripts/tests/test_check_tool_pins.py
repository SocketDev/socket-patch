"""Tests for scripts/check-tool-pins.py, the floating-toolchain lint (#1645)."""

import importlib.util
from pathlib import Path
import tempfile
import unittest

import yaml

ROOT = Path(__file__).parents[2]


def load_script():
    spec = importlib.util.spec_from_file_location(
        "check_tool_pins", ROOT / "scripts" / "check-tool-pins.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pins = load_script()


SHA = "0" * 40


def violations(steps, matrix=None):
    job = {"runs-on": "ubuntu-latest", "steps": steps}
    if matrix is not None:
        job["strategy"] = {"matrix": matrix}
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "ci.yml"
        path.write_text(yaml.safe_dump({"jobs": {"e2e": job}}))
        return pins.check_workflow(str(path))


def setup(action, **inputs):
    step = {"uses": f"{action}@{SHA}"}
    if inputs:
        step["with"] = {k.replace("_", "-"): v for k, v in inputs.items()}
    return step


class FloatingVersions(unittest.TestCase):
    def test_floating_runtime_versions_are_rejected(self):
        for key, value in [
            ("node-version", "24.x"),
            ("python-version", "3.12.x"),
            ("python-version", "3.12"),
            ("python-version", 3.12),
            ("go-version", "1.24"),
            ("node-version", "24"),
            ("node-version", 24),
            ("node-version", "latest"),
            ("go-version", ">=1.24.0"),
        ]:
            with self.subTest(key=key, value=value):
                found = violations([{"uses": f"actions/setup-x@{SHA}", "with": {key: value}}])
                self.assertEqual(len(found), 1, found)
                self.assertIn(key, found[0])

    def test_exact_versions_pass(self):
        self.assertEqual(violations([
            setup("actions/setup-node", node_version="24.21.0"),
            setup("actions/setup-python", python_version="3.12.10"),
            setup("actions/setup-go", go_version="1.24.13"),
        ]), [])

    def test_other_inputs_are_not_checked(self):
        self.assertEqual(violations([
            setup("ruby/setup-ruby", bundler="2.6"),
            {"run": "echo node-version 24.x"},
        ]), [])


class SetupUv(unittest.TestCase):
    def test_setup_uv_without_version_is_rejected(self):
        # The 10-20 incident: no `version:`, so every run took the latest uv.
        found = violations([setup("astral-sh/setup-uv", enable_cache=False)])
        self.assertEqual(len(found), 1, found)
        self.assertIn("without `version:`", found[0])

    def test_setup_uv_with_no_inputs_is_rejected(self):
        found = violations([setup("astral-sh/setup-uv")])
        self.assertEqual(len(found), 1, found)

    def test_setup_uv_floating_version_is_rejected(self):
        found = violations([setup("astral-sh/setup-uv", version="0.13.x")])
        self.assertEqual(len(found), 1, found)

    def test_setup_uv_exact_version_passes(self):
        self.assertEqual(violations([setup("astral-sh/setup-uv", version="0.13.1")]), [])


class Expressions(unittest.TestCase):
    STEP = setup("actions/setup-node", node_version="${{ matrix.node || '24.21.0' }}")

    def test_exact_matrix_values_and_fallback_pass(self):
        matrix = {"include": [{"node": "22.22.1"}, {"os": "x"}]}
        self.assertEqual(violations([self.STEP], matrix), [])

    def test_floating_matrix_include_value_is_rejected(self):
        found = violations([self.STEP], {"include": [{"node": "22.x"}]})
        self.assertEqual(len(found), 1, found)
        self.assertIn("matrix.node", found[0])

    def test_floating_matrix_axis_value_is_rejected(self):
        found = violations([self.STEP], {"node": ["24.21.0", "22"]})
        self.assertEqual(len(found), 1, found)
        self.assertIn("'22'", found[0])

    def test_floating_fallback_literal_is_rejected(self):
        found = violations([setup("actions/setup-node", node_version="${{ matrix.node || '24.x' }}")])
        self.assertEqual(len(found), 1, found)
        self.assertIn("fallback", found[0])

    def test_from_json_matrix_is_left_to_review(self):
        self.assertEqual(violations([self.STEP], "${{ fromJSON(vars.M) }}"), [])


class Repository(unittest.TestCase):
    def test_ci_yml_has_no_floating_toolchains(self):
        workflow = ROOT / ".github" / "workflows" / "ci.yml"
        self.assertEqual(pins.check_workflow(str(workflow)), [])

    def test_main_exit_codes(self):
        self.assertEqual(pins.main([]), 2)
        self.assertEqual(
            pins.main([str(ROOT / ".github" / "workflows" / "ci.yml")]), 0
        )


if __name__ == "__main__":
    unittest.main()
