"""The cheap coverage summary counts the exported data, including empty metrics."""

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[2]
spec = importlib.util.spec_from_file_location("lcov_summary", ROOT / "scripts/ci-lcov-summary.py")
lcov = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lcov)


class Summary(unittest.TestCase):
    sample = """TN:
SF:/work/src/one.rs
FN:2,one
FNDA:1,one
FNF:2
FNH:1
DA:2,1
DA:3,0
LF:2
LH:1
BRF:2
BRH:1
end_of_record
SF:/work/src/two.rs
LF:10
LH:9
FNF:1
FNH:1
end_of_record
"""

    def test_totals_are_weighted_by_counts_not_file_percentages(self):
        text = lcov.summary(lcov.read_lcov(self.sample), Path("/work"))
        self.assertIn("src/one.rs", text)
        total = text.splitlines()[-1]
        self.assertIn("10/12 (83.33%)", total)
        self.assertIn("2/3 (66.67%)", total)
        self.assertIn("1/2 (50.00%)", total)
        self.assertIn("0/0 (-)", text)

    def test_truncated_duplicate_empty_and_invalid_exports_fail(self):
        for text in ("", "SF:file.rs\nLF:1\nLH:1\n", self.sample + self.sample,
                     "SF:file.rs\nend_of_record\n", self.sample.replace("LH:1\n", "LH:3\n")):
            with self.subTest(text=text), self.assertRaises(ValueError):
                lcov.read_lcov(text)


if __name__ == "__main__":
    unittest.main()
