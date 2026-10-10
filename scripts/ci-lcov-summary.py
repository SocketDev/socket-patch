#!/usr/bin/env python3
"""Render the existing LCOV export without another llvm-profdata/llvm-cov pass.

LCOV carries line, function and branch totals, not LLVM region totals.
The raw LCOV artifact remains the source of truth for the merged report.
"""

import argparse
from pathlib import Path

METRICS = (("Lines", "LH", "LF"), ("Functions", "FNH", "FNF"), ("Branches", "BRH", "BRF"))


def read_lcov(text):
    files = {}
    name, counts = None, {}
    for line in text.splitlines():
        key, _, value = line.partition(":")
        if key == "SF":
            if name is not None:
                raise ValueError("LCOV record missing end_of_record")
            name, counts = value, {}
        elif key in {key for _, hit, found in METRICS for key in (hit, found)}:
            counts[key] = int(value)
        elif line == "end_of_record":
            if not name or name in files:
                raise ValueError("LCOV source missing or duplicated")
            if "LF" not in counts or "LH" not in counts:
                raise ValueError(f"LCOV line totals missing: {name}")
            for _, hit, found in METRICS:
                if not 0 <= counts.get(hit, 0) <= counts.get(found, 0):
                    raise ValueError(f"Invalid LCOV totals: {name}")
            files[name] = counts
            name = None
    if name is not None or not files:
        raise ValueError("LCOV export empty or truncated")
    return files


def summary(files, root):
    def metric(counts, hit, found):
        total, covered = counts.get(found, 0), counts.get(hit, 0)
        return f"{covered}/{total} ({100 * covered / total:.2f}%)" if total else "0/0 (-)"

    def label(name):
        try:
            return str(Path(name).relative_to(root))
        except ValueError:
            return name

    rows = [["File", *(name for name, _, _ in METRICS)]]
    for name, counts in sorted(files.items()):
        rows.append([label(name), *(metric(counts, hit, found) for _, hit, found in METRICS)])
    totals = {key: sum(counts.get(key, 0) for counts in files.values())
              for _, hit, found in METRICS for key in (hit, found)}
    rows.append(["TOTAL", *(metric(totals, hit, found) for _, hit, found in METRICS)])
    widths = [max(len(row[i]) for row in rows) for i in range(4)]
    return "\n".join("  ".join(value.ljust(widths[i]) if i == 0 else value.rjust(widths[i])
                               for i, value in enumerate(row)).rstrip() for row in rows) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lcov", type=Path)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    print(summary(read_lcov(args.lcov.read_text(encoding="utf-8")), args.root), end="")


if __name__ == "__main__":
    main()
