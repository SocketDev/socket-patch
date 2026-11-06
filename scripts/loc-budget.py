#!/usr/bin/env python3
"""Count implementation lines of Rust code and compare them to a budget.

A line counts when it holds code outside a comment. These never count:

* blank and comment-only lines (doc comments included);
* items gated by a ``cfg`` that implies ``test`` -- ``#[cfg(test)]``,
  ``#[cfg(all(unix, test))]`` -- with their other attributes: inline
  ``mod tests { ... }`` blocks, test-only helpers, ``use`` lines, struct
  fields, enum variants, parameters and match arms;
* files declared as ``#[cfg(test)] mod name;`` (also with ``#[path]``, or
  inside a test-only inline module), files that open with
  ``#![cfg(test)]``, and every module below them;
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

# `#[cfg(` or `#![cfg(`; implies_test parses the predicate.
CFG_ATTR = re.compile(r"#\s*(!)?\s*\[\s*cfg\s*\(")
CFG_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\w+|\S')
RAW_STRING = re.compile(r'b?r(#*)"')
CHAR_LITERAL = re.compile(r"'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|.)|[^\\'])'", re.S)
IDENT = re.compile(r"(?:r#)?[A-Za-z_]\w*")
ITEM_KEYWORDS = frozenset(
    "async const crate enum extern fn impl let macro_rules mod static struct trait type union unsafe use".split()
)
MOD_ITEM = re.compile(r"(?<![\w#])mod\s+(\w+)\s*([;{])")
PATH_ATTR = re.compile(r'#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]')

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
    # (name, #[path] value, enclosing inline modules) for each file module a
    # test-only item declares.
    test_mods: list[tuple[str, str | None, tuple[str, ...]]] = field(default_factory=list)
    # The file opens with an inner `#![cfg(test)]`.
    test_file: bool = False


def implies_test(pred: str) -> bool:
    """Whether a ``cfg`` predicate can only hold when ``test`` is set:
    ``test`` itself, an ``all(...)`` with such an argument, or an ``any(...)``
    whose every argument is one. ``not(...)`` never is."""
    toks = CFG_TOKEN.findall(pred)
    pos = 0

    def parse() -> bool:
        nonlocal pos
        if pos >= len(toks):
            return False
        name = toks[pos]
        pos += 1
        if pos < len(toks) and toks[pos] == "=":
            pos += 2  # key = "value"
            return False
        if pos < len(toks) and toks[pos] == "(":
            pos += 1
            args = []
            while pos < len(toks) and toks[pos] != ")":
                if toks[pos] == ",":
                    pos += 1
                    continue
                args.append(parse())
            pos += 1
            if name == "all":
                return any(args)
            if name == "any":
                return bool(args) and all(args)
            return False
        return name == "test"

    return parse() and pos == len(toks)


def _next_code(src: str, kind: bytearray, j: int) -> int:
    n = len(src)
    while j < n and (kind[j] == COMMENT or src[j].isspace()):
        j += 1
    return j


def _match_close(src: str, kind: bytearray, j: int) -> int | None:
    """Index of the bracket closing the one at ``j``."""
    depth = 0
    for k in range(j, len(src)):
        if kind[k] != CODE:
            continue
        if src[k] in "{([":
            depth += 1
        elif src[k] in "})]":
            depth -= 1
            if depth == 0:
                return k
    return None


def _attrs_before(src: str, kind: bytearray, pos: int) -> tuple[int, list[str]]:
    """The outer attributes written directly before ``pos``: (start, texts)."""
    attrs: list[str] = []
    while True:
        q = pos - 1
        while q >= 0 and (kind[q] == COMMENT or src[q].isspace()):
            q -= 1
        if q < 0 or src[q] != "]" or kind[q] != CODE:
            break
        depth, r = 0, q
        while r >= 0:
            if kind[r] == CODE and src[r] == "]":
                depth += 1
            elif kind[r] == CODE and src[r] == "[":
                depth -= 1
                if depth == 0:
                    break
            r -= 1
        h = r - 1
        while h >= 0 and src[h].isspace():
            h -= 1
        if r < 0 or h < 0 or src[h] != "#":
            break
        attrs.append(src[h : q + 1])
        pos = h
    return pos, attrs


def _starts_item(src: str, kind: bytearray, j: int) -> bool:
    """Whether the code at ``j`` is an item or statement, rather than a
    struct field, enum variant, parameter or match arm."""
    n = len(src)
    while True:
        j = _next_code(src, kind, j)
        if j < n and src[j] == "#":  # another attribute
            k = _next_code(src, kind, j + 1)
            close = _match_close(src, kind, k) if k < n and src[k] == "[" else None
            if close is None:
                return True
            j = close + 1
            continue
        break
    if j >= n or src[j] == "{":
        return True
    m = IDENT.match(src, j)
    if not m:
        return False
    word, after = m.group(0), _next_code(src, kind, m.end())
    if word == "pub":
        if after < n and src[after] == "(":
            after = _next_code(src, kind, (_match_close(src, kind, after) or after) + 1)
        m = IDENT.match(src, after)
        if not m:
            return True
        word, after = m.group(0), _next_code(src, kind, m.end())
        # `pub name: Type` is a field.
        return word in ITEM_KEYWORDS or not (src.startswith(":", after) and not src.startswith("::", after))
    return word in ITEM_KEYWORDS or (after < n and src[after] == "!")  # or a macro call


def _item_end(src: str, kind: bytearray, pos: int) -> int:
    """End of the item that starts at ``pos``.

    An item ends at its first top-level ``;``, at the brace closing its first
    ``{`` (and a ``;`` right after it), or just before a bracket that closes
    the enclosing container. A field, variant, parameter or match arm also
    ends at its first top-level ``,``.
    """
    n = len(src)
    is_field = not _starts_item(src, kind, pos)
    depth, angle, in_expr = 0, 0, False
    for j in range(pos, n):
        if kind[j] != CODE:
            continue
        ch = src[j]
        if ch in "{([":
            depth += 1
        elif ch in "})]":
            if depth == 0:
                return j
            depth -= 1
            if depth == 0 and ch == "}":
                nxt = _next_code(src, kind, j + 1)
                if nxt < n and (src[nxt] == ";" or (is_field and src[nxt] == ",")):
                    return nxt + 1
                # `Variant { .. } => arm` and `S { .. }.method()` go on.
                if not is_field or nxt >= n or src[nxt] not in "=.?":
                    return j + 1
        elif depth == 0:
            if ch == ";":
                return j + 1
            if is_field:
                prev = src[j - 1]
                if ch == ">" and prev == "=":
                    in_expr, angle = True, 0  # past a match arm's `=>`
                elif in_expr:
                    pass
                elif ch == "<":
                    angle += 1
                elif ch == ">" and prev != "-":
                    angle = max(0, angle - 1)
                if ch == "," and angle == 0:
                    return j + 1
    return n


def _file_mods(src: str, kind: bytearray, lo: int, hi: int) -> list[tuple[str, str | None, tuple[str, ...]]]:
    """The ``mod name;`` declarations in ``src[lo:hi]``, each with its
    ``#[path]`` and the inline modules around it."""
    out = []
    stack: list[tuple[str, int]] = []
    for m in MOD_ITEM.finditer(src, lo, hi):
        at = m.start()
        if kind[at] != CODE:
            continue
        while stack and stack[-1][1] < at:
            stack.pop()
        name = m.group(1)
        if m.group(2) == "{":
            close = _match_close(src, kind, m.end() - 1)
            stack.append((name, hi if close is None else close))
            continue
        _, attrs = _attrs_before(src, kind, at)
        paths = [pm.group(1) for pm in map(PATH_ATTR.search, attrs) if pm]
        out.append((name, paths[0] if paths else None, tuple(s for s, _ in stack)))
    return out


def count_source(src: str) -> FileCount:
    """Count code lines in one Rust file, splitting off ``cfg(test)`` items."""
    kind = classify(src)
    n = len(src)
    excluded = bytearray(n)
    test_mods: list[tuple[str, str | None, tuple[str, ...]]] = []
    test_file = False
    for m in CFG_ATTR.finditer(src):
        start = m.start()
        if kind[start] != CODE or excluded[start]:
            continue
        close = _match_close(src, kind, m.end() - 1)
        if close is None:
            continue
        attr_end = _next_code(src, kind, close + 1)
        if attr_end >= n or src[attr_end] != "]" or not implies_test(src[m.end() : close]):
            continue
        if m.group(1):
            # `#![cfg(test)]` outside any block gates the whole file.
            opened = sum(1 if c == "{" else -1 for c, k in zip(src[:start], kind) if k == CODE and c in "{}")
            if opened == 0:
                test_file = True
                excluded = bytearray(b"\x01" * n)
                break
            continue
        end = _item_end(src, kind, attr_end + 1)
        start, _ = _attrs_before(src, kind, start)
        test_mods.extend(_file_mods(src, kind, start, end))
        excluded[start:end] = b"\x01" * (end - start)

    code_lines: set[int] = set()
    test_lines: set[int] = set()
    line = 1
    for k, ch in enumerate(src):
        if ch == "\n":
            line += 1
        elif not ch.isspace() and kind[k] != COMMENT:
            (test_lines if excluded[k] else code_lines).add(line)
    return FileCount(len(code_lines), len(test_lines - code_lines), test_mods, test_file)


def is_file(rel: str) -> bool:
    return (REPO / rel).is_file()


def resolve_module(declaring: str, name: str, path_attr: str | None, inline: tuple[str, ...] = ()) -> str | None:
    """The file a ``mod name;`` in ``declaring`` loads, if it exists.

    ``inline`` names the inline ``mod x { ... }`` blocks around the
    declaration. Like rustc, an out-of-line ``#[path]`` resolves against the
    declaring file's own directory, and one inside inline modules against
    their directory.
    """
    d, base = os.path.split(declaring)
    owns_dir = base in ("mod.rs", "lib.rs", "main.rs")
    sub = os.path.join(d if owns_dir else os.path.join(d, base[:-3]), *inline)
    if path_attr:
        candidates = [os.path.join(sub if inline else d, path_attr)]
    else:
        candidates = [os.path.join(sub, name + ".rs"), os.path.join(sub, name, "mod.rs")]
    for c in candidates:
        if is_file(c):
            return os.path.normpath(c)
    return None


def rust_files() -> list[str]:
    out = subprocess.check_output(["git", "ls-files", "-z", "*.rs"], cwd=REPO, text=True)
    return [f for f in out.split("\0") if f and not re.search(r"(^|/)(tests|benches)/", f)]


def in_scope(files: list[str], groups: dict) -> list[str]:
    """The group files and every file that can declare one of them as a
    module: the files beside them and each ancestor directory's module file."""
    member = {f for f in files if any(in_group(f, g) for g in groups.values())}
    dirs = {os.path.dirname(f) for f in member}
    declarers: set[str] = set()
    for d in dirs:
        while d:
            declarers.update(d + ext for ext in (".rs", "/mod.rs", "/lib.rs", "/main.rs"))
            d = os.path.dirname(d)
    return [f for f in files if f in member or f in declarers or os.path.dirname(f) in dirs]


def count_repo(groups: dict | None = None) -> dict[str, int]:
    """Implementation lines per tracked Rust file (test-only files count 0).

    With ``groups``, reads only the files those groups and their module
    declarations need.
    """
    files = rust_files()
    if groups is not None:
        files = in_scope(files, groups)
    counts = {f: count_source((REPO / f).read_text(encoding="utf-8", errors="replace")) for f in files}
    test_files = {f for f, fc in counts.items() if fc.test_file}
    for f, fc in counts.items():
        for name, path_attr, inline in fc.test_mods:
            target = resolve_module(f, name, path_attr, inline)
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
    if args.files and args.files not in groups:
        ap.error(f"unknown group {args.files!r}; groups: {', '.join(groups)}")
    per_file = count_repo(groups)

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
    union = sum(c for f, c in per_file.items() if any(in_group(f, g) for g in groups.values()))
    print(f"{'all groups':24s} {union:8d}")

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
