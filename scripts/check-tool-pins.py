#!/usr/bin/env python3
"""Fail when a workflow installs an oracle toolchain at a floating version.

`pin-check.yml` makes every `uses:` reference an immutable SHA, but the
*tool* a setup action installs can still float: `node-version: '24.x'`,
`python-version: '3.12.x'`, `go-version: '1.24'`, or `astral-sh/setup-uv`
with no `version:` at all. Any upstream release then changes what CI runs
while main stays the same. On 2026-10-20 uv 0.13.2 did exactly that, failed
a Pipenv leg on every merge-queue entry and stalled the queue for 2.7 h
(#1645).

Rules, per step:
  * `astral-sh/setup-uv` must set `with.version`.
  * `with.version` of setup-uv, and `with.node-version`, `python-version`
    and `go-version` of any step, must be an exact `X.Y.Z` release.
  * A `${{ ... }}` expression may read only `matrix.*`. Every quoted value
    it can yield (comparison operands aside) must be exact, and so must
    every value the job's matrix gives a key it reads. A matrix built with
    `fromJSON` can't be resolved statically and is left to review.

The workflow is scanned as text with the standard library only, the same
way scripts/tests reads ci.yml, so the lint runs on any python3. It relies
on the block style ci.yml uses: steps as `- ` items, `with:` inputs one
per line, matrix rows as `{key: value, ...}` or `key: [a, b]`. A step
shared through a YAML anchor is checked once, against the matrix of the
job that defines it.

Repo gate: scripts/tests/test_check_tool_pins.py runs this on ci.yml in
the lean `lint-ecosystems` job.

Usage: check-tool-pins.py WORKFLOW.yml [...]   (exit 1 on any violation)
"""

import re
import sys

EXACT = re.compile(r"^\d+\.\d+\.\d+$")
VERSION_KEYS = ("node-version", "python-version", "go-version")
UV_ACTION = "astral-sh/setup-uv"
LITERAL = re.compile(r"'([^']*)'")
CONTEXT_REF = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z0-9_-]+)")
COMPARED = re.compile(r"(==|!=)\s*$")
COMPARES = re.compile(r"^\s*(==|!=)")
JOB = re.compile(r"^  ([A-Za-z0-9_-]+):\s*(#.*)?$")
KEY_VALUE = re.compile(r"^(\s*)(-\s+)?([A-Za-z0-9_-]+):\s*(.*)$")


def indent(line):
    return len(line) - len(line.lstrip(" "))


def strip_comment(value):
    """Drop a trailing ` # ...` comment that sits outside quotes."""
    quote = None
    for i, ch in enumerate(value):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or value[i - 1].isspace()):
            return value[:i].rstrip()
    return value.strip()


def unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def is_content(line):
    stripped = line.strip()
    return stripped != "" and not stripped.startswith("#")


def job_spans(lines):
    """(name, start, end) for every job under the top-level `jobs:` key."""
    try:
        top = next(i for i, l in enumerate(lines) if re.match(r"^jobs:\s*(#.*)?$", l))
    except StopIteration:
        return []
    starts = []
    for i in range(top + 1, len(lines)):
        line = lines[i]
        if is_content(line) and indent(line) == 0:
            break
        m = JOB.match(line)
        if m:
            starts.append((m.group(1), i))
    end_of_jobs = next(
        (i for i in range(top + 1, len(lines)) if is_content(lines[i]) and indent(lines[i]) == 0),
        len(lines),
    )
    return [
        (name, start, starts[n + 1][1] if n + 1 < len(starts) else end_of_jobs)
        for n, (name, start) in enumerate(starts)
    ]


def matrix_values(lines, start, end, key):
    """Every value the job's matrix gives `key`, or None if unresolvable."""
    matrix_at = None
    for i in range(start, end):
        m = KEY_VALUE.match(lines[i])
        if m and m.group(3) == "matrix" and not m.group(2):
            matrix_at = i
            break
    if matrix_at is None:
        return []
    m = KEY_VALUE.match(lines[matrix_at])
    if "${{" in m.group(4):
        return None
    base = indent(lines[matrix_at])
    block_end = matrix_at + 1
    while block_end < end and (not is_content(lines[block_end]) or indent(lines[block_end]) > base):
        block_end += 1
    values = []
    flow = re.compile(r"[{,]\s*" + re.escape(key) + r"""\s*:\s*('[^']*'|"[^"]*"|[^,}]+)""")
    for i in range(matrix_at + 1, block_end):
        line = strip_comment(lines[i])
        for v in flow.findall(line):
            values.append(unquote(v))
        kv = KEY_VALUE.match(line)
        if kv and kv.group(3) == key and not kv.group(2):
            rest = kv.group(4).strip()
            if rest.startswith("${{"):
                return None
            if rest.startswith("["):
                values.extend(unquote(v) for v in rest.strip("[]").split(",") if v.strip())
            elif rest:
                values.append(unquote(rest))
            else:
                j = i + 1
                while j < block_end and (not is_content(lines[j]) or indent(lines[j]) > indent(lines[i])):
                    item = re.match(r"^\s*-\s+(.*)$", strip_comment(lines[j]))
                    if item:
                        values.append(unquote(item.group(1)))
                    j += 1
    return values


def yielded_literals(expr):
    """Quoted literals an expression can evaluate to (not compared against)."""
    out = []
    for m in LITERAL.finditer(expr):
        before, after = expr[: m.start()], expr[m.end() :]
        if COMPARED.search(before) or COMPARES.match(after):
            continue
        out.append(m.group(1))
    return out


def check_value(lines, span, value):
    """Return reasons `value` is not an exact pin (empty if it is)."""
    text = unquote(strip_comment(value))
    if "${{" not in text:
        return [] if EXACT.match(text) else [f"{text!r} is not an exact X.Y.Z"]
    reasons = []
    body = LITERAL.sub("''", text)
    for ctx, key in CONTEXT_REF.findall(body):
        if ctx != "matrix":
            reasons.append(f"reads `{ctx}.{key}`, which can't be checked; use a literal or matrix value")
            continue
        values = matrix_values(lines, span[1], span[2], key) if span else None
        for v in values or []:
            if not EXACT.match(v):
                reasons.append(f"matrix.{key} value {v!r} is not an exact X.Y.Z")
    for literal in yielded_literals(text):
        if not EXACT.match(literal):
            reasons.append(f"value {literal!r} in the expression is not an exact X.Y.Z")
    return reasons


def steps(lines):
    """Yield (line_no, uses, {input: (line_no, value)}) for every `- ` item."""
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)-\s+(.*)$", line)
        if not m or m.group(2).startswith("{") or m.group(2).startswith("#"):
            continue
        dash = len(m.group(1))
        item = dash + 2
        uses, inputs, with_at = None, {}, None
        j = i
        while j < len(lines):
            cur = lines[j]
            if j > i and is_content(cur) and indent(cur) <= dash:
                break
            text = cur if j > i else " " * item + m.group(2)
            kv = KEY_VALUE.match(text)
            if kv and not kv.group(2):
                level = len(kv.group(1))
                if level == item:
                    with_at = j if kv.group(3) == "with" else None
                    if kv.group(3) == "uses":
                        uses = unquote(strip_comment(kv.group(4)))
                elif with_at is not None and level == item + 2:
                    inputs[kv.group(3)] = (j, kv.group(4))
            j += 1
        if uses is not None or inputs:
            yield i, uses, inputs


def check_text(path, text):
    lines = text.splitlines()
    spans = job_spans(lines)
    violations = []
    for line_no, uses, inputs in steps(lines):
        span = next((s for s in spans if s[1] <= line_no < s[2]), None)
        where = f"{path}:{line_no + 1}" + (f": job {span[0]!r}" if span else "")
        if uses and uses.split("@")[0].lower() == UV_ACTION:
            if "version" not in inputs:
                violations.append(f"{where}: {UV_ACTION} without `version:`")
            else:
                at, value = inputs["version"]
                for r in check_value(lines, span, value):
                    violations.append(f"{path}:{at + 1}: setup-uv version {r}")
        for key in VERSION_KEYS:
            if key in inputs:
                at, value = inputs[key]
                for r in check_value(lines, span, value):
                    violations.append(f"{path}:{at + 1}: {key} {r}")
    return violations


def check_workflow(path):
    with open(path, encoding="utf-8") as f:
        return check_text(path, f.read())


def main(argv):
    if not argv:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    violations = [v for path in argv for v in check_workflow(path)]
    for v in violations:
        print(f"::error::{v}")
    if violations:
        print(
            f"{len(violations)} floating toolchain version(s). Pin each to an "
            "exact release and bump it deliberately in its own PR."
        )
        return 1
    print("All toolchain versions are pinned to exact releases.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
