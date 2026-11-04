#!/usr/bin/env python3
"""Count implementation lines of Rust code and compare them to a budget.

A line counts when it holds code outside a comment. These never count:

* blank and comment-only lines (doc comments included);
* items gated by ``#[cfg(test)]`` or ``#[cfg(all(test, ...))]`` (inline
  ``mod tests { ... }`` blocks, test-only helpers and ``use`` lines);
* files declared as ``#[cfg(test)] mod name;`` and every module below them;
* files under a ``tests/`` or ``benches/`` directory.

Budgets live in ``scripts/loc-budget.json``. Each group names path prefixes
(relative to the repo root), optional prefixes to leave out, and the most
implementation lines the group may hold:

    {"groups": {"readers": {"paths": ["crates/x/src/formats/"],
                            "exclude": ["crates/x/src/formats/old/"],
                            "max": 123}}}

Usage:

    scripts/loc-budget.py              # print every group's count
    scripts/loc-budget.py --check      # exit 1 when a group is over budget
    scripts/loc-budget.py --warn       # annotate groups over budget, exit 0
    scripts/loc-budget.py --lower      # rewrite each max down to its count
    scripts/loc-budget.py --files GROUP  # per-file counts for one group

``--check`` and ``--warn`` print a GitHub ``::warning::`` annotation per
group over budget; CI uses ``--warn`` so a bug fix that adds lines to these
files never fails on it. ``--lower`` never raises a max: a PR that grows a group raises the
number by hand, where a reviewer sees it.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BUDGET_FILE = REPO / "scripts" / "loc-budget.json"

CFG_TEST = re.compile(r"#\[cfg\(\s*(?:test|all\(\s*test\b[^\]]*)\)\]")
RAW_STRING = re.compile(r'b?r(#*)"')
CHAR_LITERAL = re.compile(r"'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|.)|[^\\'])'", re.S)
MOD_DECL = re.compile(
    r'(?:#\[path\s*=\s*"([^"]+)"\]\s*)?(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;\s*$'
)

CODE, COMMENT, STRING = 0, 1, 2


def classify(src: str) -> bytearray:
    """Mark every character of Rust source as code, comment or literal."""
    n = len(src)
    kind = bytearray(n)
    i = 0

    def ident_before(at: int) -> bool:
        return at > 0 and (src[at - 1].isalnum() or src[at - 1] == "_")

    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            kind[i:j] = bytes([COMMENT]) * (j - i)
            i = j
            continue
        if src.startswith("/*", i):
            depth, j = 0, i
            while j < n:
                if src.startswith("/*", j):
                    depth += 1
                    j += 2
                elif src.startswith("*/", j):
                    depth -= 1
                    j += 2
                    if depth == 0:
                        break
                else:
                    j += 1
            kind[i:j] = bytes([COMMENT]) * (j - i)
            i = j
            continue
        if c in "rb" and not ident_before(i):
            m = RAW_STRING.match(src, i)
            if m:
                close = '"' + m.group(1)
                j = src.find(close, m.end())
                j = n if j < 0 else j + len(close)
                kind[i:j] = bytes([STRING]) * (j - i)
                i = j
                continue
        if c == '"' or (src.startswith('b"', i) and not ident_before(i)):
            j = i + (2 if c == "b" else 1)
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            j = min(j + 1, n)
            kind[i:j] = bytes([STRING]) * (j - i)
            i = j
            continue
        if c == "'":
            m = CHAR_LITERAL.match(src, i)
            if m:
                kind[i : m.end()] = bytes([STRING]) * (m.end() - i)
                i = m.end()
                continue
        i += 1
    return kind


@dataclass
class FileCount:
    code: int
    test: int
    test_mods: list[tuple[str, str | None]] = field(default_factory=list)


def count_source(src: str) -> FileCount:
    """Count code lines in one Rust file, splitting off ``cfg(test)`` items."""
    kind = classify(src)
    n = len(src)
    excluded = bytearray(n)
    test_mods: list[tuple[str, str | None]] = []
    for m in CFG_TEST.finditer(src):
        start = m.start()
        if kind[start] != CODE or excluded[start]:
            continue
        # The gated item ends at its first top-level `;` or at the brace
        # closing its first `{`.
        j, depth, end = m.end(), 0, n
        while j < n:
            if kind[j] == CODE:
                ch = src[j]
                if ch in "{([":
                    depth += 1
                elif ch in "})]":
                    depth -= 1
                    if depth == 0 and ch == "}":
                        end = j + 1
                        break
                elif ch == ";" and depth == 0:
                    end = j + 1
                    break
            j += 1
        item = src[m.end() : end]
        decl = MOD_DECL.search(item)
        if decl and "{" not in item:
            test_mods.append((decl.group(2), decl.group(1)))
        excluded[start:end] = b"\x01" * (end - start)

    code_lines: set[int] = set()
    test_lines: set[int] = set()
    line = 1
    for k, ch in enumerate(src):
        if ch == "\n":
            line += 1
        elif not ch.isspace() and kind[k] != COMMENT:
            (test_lines if excluded[k] else code_lines).add(line)
    return FileCount(len(code_lines), len(test_lines - code_lines), test_mods)


def resolve_module(declaring: str, name: str, path_attr: str | None) -> str | None:
    """The file a ``mod name;`` in ``declaring`` loads, if it exists."""
    d, base = os.path.split(declaring)
    owns_dir = base in ("mod.rs", "lib.rs", "main.rs")
    sub = d if owns_dir else os.path.join(d, base[:-3])
    if path_attr:
        candidates = [os.path.join(sub, path_attr), os.path.join(d, path_attr)]
    else:
        candidates = [os.path.join(sub, name + ".rs"), os.path.join(sub, name, "mod.rs")]
    for c in candidates:
        if (REPO / c).is_file():
            return os.path.normpath(c)
    return None


def rust_files() -> list[str]:
    out = subprocess.check_output(["git", "ls-files", "*.rs"], cwd=REPO, text=True)
    return [
        f
        for f in out.split()
        if not re.search(r"(^|/)(tests|benches)/", f)
    ]


def count_repo() -> dict[str, int]:
    """Implementation lines per tracked Rust file (test-only files count 0)."""
    files = rust_files()
    counts = {f: count_source((REPO / f).read_text(encoding="utf-8", errors="replace")) for f in files}
    test_files: set[str] = set()
    for f, fc in counts.items():
        for name, path_attr in fc.test_mods:
            target = resolve_module(f, name, path_attr)
            if target:
                test_files.add(target)
    # A module below a test-only module is test-only too.
    roots = {t[:-3] if not t.endswith("/mod.rs") else os.path.dirname(t) for t in test_files}
    for f in files:
        if any(f.startswith(r + "/") for r in roots):
            test_files.add(f)
    return {f: (0 if f in test_files else fc.code) for f, fc in counts.items()}


def in_group(path: str, group: dict) -> bool:
    return any(path.startswith(p) for p in group["paths"]) and not any(
        path.startswith(p) for p in group.get("exclude", [])
    )


def group_total(per_file: dict[str, int], group: dict) -> int:
    return sum(c for f, c in per_file.items() if in_group(f, group))


def load_budget() -> dict:
    return json.loads(BUDGET_FILE.read_text())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="exit 1 when a group is over budget")
    mode.add_argument("--warn", action="store_true", help="annotate groups over budget, exit 0")
    mode.add_argument("--lower", action="store_true", help="lower each max to its current count")
    mode.add_argument("--files", metavar="GROUP", help="per-file counts for one group")
    args = ap.parse_args(argv)

    budget = load_budget()
    groups = budget["groups"]
    per_file = count_repo()

    if args.files:
        group = groups[args.files]
        rows = sorted(((c, f) for f, c in per_file.items() if c and in_group(f, group)), reverse=True)
        for c, f in rows:
            print(f"{c:7d}  {f}")
        print(f"{sum(c for c, _ in rows):7d}  total")
        return 0

    over = []
    for name, g in groups.items():
        total = group_total(per_file, g)
        cap = g["max"]
        status = "over" if total > cap else "ok"
        print(f"{name:24s} {total:8d} / {cap:8d}  {status}")
        if total > cap:
            over.append((name, total, cap))
        if args.lower and total < cap:
            g["max"] = total
    print(f"{'all implementation':24s} {sum(per_file.values()):8d}")

    if args.lower:
        BUDGET_FILE.write_text(json.dumps(budget, indent=2) + "\n")
    if (args.check or args.warn) and over:
        for name, total, cap in over:
            print(
                f"::warning title=loc budget::{name} has {total} implementation lines, "
                f"over its budget of {cap} (scripts/loc-budget.json)"
            )
        return 1 if args.check else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
