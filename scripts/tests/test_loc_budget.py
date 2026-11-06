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
        self.assertEqual(fc.test_mods, [("tests", None, ()), ("x_tests", "x_tests.rs", ())])
        self.assertEqual(fc.code, 1)

    # Review findings on #2001.

    def test_cfg_test_struct_field_does_not_swallow_following_code(self):
        src = (
            "struct S {\n"
            "    #[cfg(test)]\n"
            "    probe: HashMap<String, u32>,\n"
            "    real: u32,\n"
            "}\n"
            "fn shipped() {}\n"
        )
        fc = count(src)
        self.assertEqual(fc.code, 4)
        self.assertEqual(fc.test, 2)

    def test_cfg_test_pub_field_last_without_comma(self):
        src = "struct S {\n    real: u32,\n    #[cfg(test)]\n    pub probe: u32\n}\nfn shipped() {}\n"
        self.assertEqual(count(src).code, 4)

    def test_cfg_test_enum_variant_and_match_arm(self):
        src = (
            "enum E {\n"
            "    A,\n"
            "    #[cfg(test)]\n"
            "    B { x: u8 },\n"
            "    C,\n"
            "}\n"
            "fn f(e: E) -> u8 {\n"
            "    match e {\n"
            "        #[cfg(test)]\n"
            "        E::B { .. } => 1,\n"
            "        _ => 0,\n"
            "    }\n"
            "}\n"
        )
        fc = count(src)
        self.assertEqual(fc.code, 9)
        self.assertEqual(fc.test, 4)

    def test_cfg_test_fn_param(self):
        src = "fn f(\n    a: u8,\n    #[cfg(test)] b: u8,\n) -> u8 {\n    a\n}\nfn g() {}\n"
        self.assertEqual(count(src).code, 6)

    def test_cfg_test_braced_use_consumes_its_semicolon(self):
        src = "#[cfg(test)]\nuse a::{\n    b,\n    c,\n};\nfn shipped() {}\n"
        fc = count(src)
        self.assertEqual(fc.code, 1)
        self.assertEqual(fc.test, 5)

    def test_cfg_all_with_test_not_first_and_not_test(self):
        src = (
            "#[cfg(all(unix, test))]\nfn a() {}\n"
            "#[cfg(all(unix, all(windows, test)))]\nfn b() {}\n"
            "#[cfg(all(unix, not(test)))]\nfn shipped() {}\n"
            "#[cfg(any(test, test))]\nfn c() {}\n"
        )
        self.assertEqual(count(src).code, 2)

    def test_file_level_cfg_test(self):
        src = "//! helpers\n#![cfg(test)]\n\nfn a() {}\nmod nested;\n"
        fc = count(src)
        self.assertTrue(fc.test_file)
        self.assertEqual(fc.code, 0)
        src = "#![cfg(not(test))]\nfn a() {}\n"
        self.assertFalse(count(src).test_file)
        self.assertEqual(count(src).code, 2)

    def test_path_attr_after_other_attrs(self):
        src = (
            "#[cfg(test)]\n"
            '#[path = "x_tests.rs"]\n'
            "#[allow(dead_code)]\n"
            "mod x_tests;\n"
        )
        self.assertEqual(count(src).test_mods, [("x_tests", "x_tests.rs", ())])

    def test_inline_test_mod_records_nested_file_modules(self):
        src = (
            "#[cfg(test)]\n"
            "mod support {\n"
            "    mod fixtures;\n"
            "    pub mod inner {\n"
            '        #[path = "h.rs"]\n'
            "        mod helpers;\n"
            "    }\n"
            "}\n"
        )
        self.assertEqual(
            count(src).test_mods,
            [("fixtures", None, ("support",)), ("helpers", "h.rs", ("support", "inner"))],
        )


class ResolveModuleTest(unittest.TestCase):
    def setUp(self):
        self.saved = loc_budget.is_file
        self.files = set()
        loc_budget.is_file = lambda p: p in self.files

    def tearDown(self):
        loc_budget.is_file = self.saved

    def test_path_attr_is_relative_to_the_declaring_files_dir(self):
        # Rust resolves an out-of-line #[path] against the declaring file's
        # directory, even for a non-mod.rs file.
        self.files = {"src/a/x_tests.rs", "src/a/x/x_tests.rs"}
        self.assertEqual(
            loc_budget.resolve_module("src/a/x.rs", "t", "x_tests.rs", ()), "src/a/x_tests.rs"
        )

    def test_inline_module_path(self):
        self.files = {"src/a/x/support/fixtures.rs", "src/a/support/fixtures.rs"}
        self.assertEqual(
            loc_budget.resolve_module("src/a/x.rs", "fixtures", None, ("support",)),
            "src/a/x/support/fixtures.rs",
        )
        self.assertEqual(
            loc_budget.resolve_module("src/a/mod.rs", "fixtures", None, ("support",)),
            "src/a/support/fixtures.rs",
        )


class RustFilesTest(unittest.TestCase):
    def test_paths_with_spaces_survive(self):
        saved = loc_budget.subprocess.check_output
        loc_budget.subprocess.check_output = lambda *a, **k: "a b/c.rs\0x/tests/t.rs\0d.rs\0"
        try:
            self.assertEqual(loc_budget.rust_files(), ["a b/c.rs", "d.rs"])
        finally:
            loc_budget.subprocess.check_output = saved


class ModeTest(unittest.TestCase):
    """--check fails over budget, --warn only annotates."""

    def setUp(self):
        self.saved = (loc_budget.load_budget, loc_budget.count_repo)
        loc_budget.load_budget = lambda: {
            "groups": {
                "g": {"paths": ["a/"], "exclude": ["a/skip/"], "max": 10},
            }
        }
        loc_budget.count_repo = lambda groups=None: {"a/x.rs": 8, "a/y.rs": 5, "a/skip/z.rs": 100, "b/w.rs": 1}

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
        self.assertIn("all groups                     13", out)

    def test_files_lists_one_group(self):
        code, out = self.run_main("--files", "g")
        self.assertEqual(code, 0)
        self.assertIn("      8  a/x.rs", out)
        self.assertIn("     13  total", out)

    def test_files_with_an_unknown_group_is_a_usage_error(self):
        import contextlib
        import io

        with contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit) as cm:
            loc_budget.main(["--files", "nope"])
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("unknown group 'nope'", err.getvalue())


class InScopeTest(unittest.TestCase):
    def test_reads_group_files_siblings_and_declarers_only(self):
        files = [
            "c/src/lib.rs",
            "c/src/a/mod.rs",
            "c/src/a/g/mod.rs",
            "c/src/a/g/x.rs",
            "c/src/a/g/deep/y.rs",
            "c/src/a/sib.rs",
            "c/src/other/z.rs",
            "d/src/lib.rs",
        ]
        groups = {"g": {"paths": ["c/src/a/g/"], "max": 1}}
        self.assertEqual(
            loc_budget.in_scope(files, groups),
            ["c/src/lib.rs", "c/src/a/mod.rs", "c/src/a/g/mod.rs", "c/src/a/g/x.rs", "c/src/a/g/deep/y.rs"],
        )


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
