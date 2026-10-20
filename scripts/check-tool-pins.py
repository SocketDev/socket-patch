#!/usr/bin/env python3
"""Fail when a workflow installs an oracle toolchain at a floating version.

`pin-check.yml` already makes every `uses:` reference an immutable SHA, but
the *tool* a setup action installs can still float: `node-version: '24.x'`,
`python-version: '3.12.x'`, `go-version: '1.24'`, or `astral-sh/setup-uv`
with no `version:` at all. Any upstream release then changes what CI runs
while main stays the same. On 2026-10-20 uv 0.13.2 did exactly that, failed
a Pipenv leg on every merge-queue entry and stalled the queue for 2.7 h
(#1645).

Rules, per step:
  * `astral-sh/setup-uv` must set `with.version`.
  * `with.version` of setup-uv, and `with.node-version`, `python-version`
    and `go-version` of any step, must be an exact `X.Y.Z` release.
  * A `${{ ... }}` expression is allowed when every quoted literal inside it
    is exact, and every `matrix.<key>` it reads is exact in each matrix
    entry of that job that sets the key. A matrix built with `fromJSON`
    can't be resolved statically and is left to review.

Usage: check-tool-pins.py WORKFLOW.yml [...]   (exit 1 on any violation)
"""

import re
import sys

import yaml

EXACT = re.compile(r"^\d+\.\d+\.\d+$")
VERSION_KEYS = ("node-version", "python-version", "go-version")
UV_ACTION = "astral-sh/setup-uv"
LITERAL = re.compile(r"'([^']*)'")
MATRIX_REF = re.compile(r"\bmatrix\.([A-Za-z0-9_-]+)")


def matrix_values(job, key):
    """Every value `matrix.<key>` takes in `job`, or None if unresolvable."""
    matrix = (job.get("strategy") or {}).get("matrix")
    if matrix is None:
        return []
    if isinstance(matrix, str):
        return None
    values = []
    axis = matrix.get(key)
    if isinstance(axis, str):
        return None
    if isinstance(axis, list):
        values.extend(axis)
    include = matrix.get("include")
    if isinstance(include, str):
        return None
    for entry in include or []:
        if isinstance(entry, dict) and key in entry:
            values.append(entry[key])
    return values


def check_value(job, value):
    """Return a list of reasons `value` is not an exact pin (empty if ok)."""
    text = str(value).strip()
    if "${{" not in text:
        return [] if EXACT.match(text) else [f"{text!r} is not an exact X.Y.Z"]
    reasons = []
    for literal in LITERAL.findall(text):
        if not EXACT.match(literal):
            reasons.append(f"fallback {literal!r} is not an exact X.Y.Z")
    for key in MATRIX_REF.findall(text):
        values = matrix_values(job, key)
        if values is None:
            continue
        for v in values:
            if not EXACT.match(str(v)):
                reasons.append(f"matrix.{key} value {v!r} is not an exact X.Y.Z")
    return reasons


def check_workflow(path):
    with open(path, encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    violations = []
    for job_name, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        for i, step in enumerate(job.get("steps") or []):
            if not isinstance(step, dict):
                continue
            where = f"{path}: job {job_name!r}, step {step.get('name') or i!r}"
            with_ = step.get("with") or {}
            uses = str(step.get("uses") or "")
            if uses.split("@")[0] == UV_ACTION:
                if "version" not in with_:
                    violations.append(f"{where}: {UV_ACTION} without `version:`")
                else:
                    for r in check_value(job, with_["version"]):
                        violations.append(f"{where}: version {r}")
            for key in VERSION_KEYS:
                if key in with_:
                    for r in check_value(job, with_[key]):
                        violations.append(f"{where}: {key} {r}")
    return violations


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
