"""Tests for scripts/loc-budget.py's Rust line counter."""

import importlib.util
import json
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "loc-budget.py"
spec = importlib.util.spec_from_file_location("loc_budget", SCRIPT)
loc_budget = importlib.util.module_from_spec(spec)
# dataclasses resolve annotations through sys.modules.
sys.modules["loc_budget"] = loc_budget
spec.loader.exec_module(loc_budget)


def count(src: str):
    return loc_budget.count_source(src)


class CountSourceTest(unittest.TestCase):
    def test_blank_and_comment_lines_do_not_count(self):
        src = "//! module doc\n\n/// item doc\nfn a() {}\n/* block\n   comment */\n"
        self.assertEqual(count(src).code, 1)

    def test_nested_block_comment(self):
        src = "/* outer /* inner */ still comment */\nfn a() {}\n"
        self.assertEqual(count(src).code, 1)

    def test_cfg_test_module_is_excluded(self):
        src = (
            "fn a() {}\n"
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    #[test]\n"
            "    fn t() { assert!(true); }\n"
            "}\n"
            "fn b() {}\n"
        )
        fc = count(src)
        self.assertEqual(fc.code, 2)
        self.assertEqual(fc.test, 5)

    def test_cfg_all_test_is_excluded_but_cfg_any_is_not(self):
        src = (
            "#[cfg(all(test, unix))]\nfn only_test() {}\n"
            "#[cfg(any(test, feature = \"x\"))]\nfn maybe_shipped() {}\n"
        )
        self.assertEqual(count(src).code, 2)

    def test_braces_inside_strings_and_chars_do_not_end_the_item(self):
        src = (
            "#[cfg(test)]\n"
            "mod tests {\n"
            '    const S: &str = "}";\n'
            "    const C: char = '}';\n"
            '    const R: &str = r#"}"#;\n'
            "    // }\n"
            "}\n"
            "fn shipped() {}\n"
        )
        self.assertEqual(count(src).code, 1)

    def test_lifetimes_are_not_char_literals(self):
        src = (
            "#[cfg(test)]\n"
            "fn helper<'a>(s: &'a str) -> &'a str { s }\n"
            "fn shipped<'b>(s: &'b str) -> &'b str { s }\n"
        )
        self.assertEqual(count(src).code, 1)

    def test_cfg_test_inside_a_string_is_ignored(self):
        src = 'const DOC: &str = "#[cfg(test)]";\nfn a() {}\n'
        self.assertEqual(count(src).code, 2)

    def test_test_module_declarations_are_reported(self):
        src = (
            "#[cfg(test)]\nmod tests;\n"
            '#[cfg(test)]\n#[path = "x_tests.rs"]\nmod x_tests;\n'
            "mod shipped;\n"
        )
        fc = count(src)
        self.assertEqual(fc.test_mods, [("tests", None), ("x_tests", "x_tests.rs")])
        self.assertEqual(fc.code, 1)


class ModeTest(unittest.TestCase):
    """--check fails over budget, --warn only annotates."""

    def setUp(self):
        self.saved = (loc_budget.load_budget, loc_budget.count_repo)
        loc_budget.load_budget = lambda: {
            "groups": {
                "g": {"paths": ["a/"], "exclude": ["a/skip/"], "max": 10},
            }
        }
        loc_budget.count_repo = lambda: {"a/x.rs": 8, "a/y.rs": 5, "a/skip/z.rs": 100, "b/w.rs": 1}

    def tearDown(self):
        loc_budget.load_budget, loc_budget.count_repo = self.saved

    def run_main(self, *argv):
        import contextlib
        import io

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = loc_budget.main(list(argv))
        return code, out.getvalue()

    def test_exclude_and_over_budget(self):
        code, out = self.run_main("--check")
        self.assertEqual(code, 1)
        self.assertIn("g                              13 /       10  over", out)
        self.assertIn("::warning title=loc budget::g has 13", out)

    def test_warn_annotates_but_passes(self):
        code, out = self.run_main("--warn")
        self.assertEqual(code, 0)
        self.assertIn("::warning title=loc budget::g has 13", out)

    def test_report_mode_never_fails(self):
        code, out = self.run_main()
        self.assertEqual(code, 0)
        self.assertNotIn("::warning", out)


class BudgetFileTest(unittest.TestCase):
    def test_budget_file_is_well_formed(self):
        budget = json.loads(loc_budget.BUDGET_FILE.read_text())
        self.assertTrue(budget["groups"])
        for name, group in budget["groups"].items():
            self.assertIsInstance(group["max"], int, name)
            self.assertTrue(group["paths"], name)
            for p in group["paths"]:
                self.assertTrue((loc_budget.REPO / p).exists(), f"{name}: {p} does not exist")


if __name__ == "__main__":
    unittest.main()
