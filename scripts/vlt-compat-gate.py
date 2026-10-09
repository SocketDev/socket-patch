#!/usr/bin/env python3
"""Print whether a vlt-compatibility run needs its matrix (`matrix=true`).

The workflow's pull_request and push filters list ci.yml because
install-proof leaves out the cells ci.yml's `e2e` rows already run
(scripts/ci-vlt-proof-suites.py). Most ci.yml edits don't touch those rows,
and then the matrix would run exactly as it did on the base. So the answer
is `matrix=false` only when ci.yml is the one changed file the event's
filter matches and its vlt cells are the same on both sides. Anything
unexpected (a base that isn't there, a filter that doesn't parse) answers
`matrix=true`.
"""

import argparse
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "vlt-compatibility.yml"
REPO = ROOT  # where git runs; the tests point it at a scratch repository
CI_PATH = ".github/workflows/ci.yml"


def event_paths(text, event):
    """The `paths:` list of `on.<event>` in the workflow text."""
    paths, in_on, in_event, in_paths = [], False, False, False
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        depth = len(line) - len(line.lstrip(" "))
        if depth == 0:
            in_on = line.rstrip() == "on:"
            in_event = in_paths = False
        elif in_on and depth == 2:
            in_event = line.strip() == f"{event}:"
            in_paths = False
        elif in_event and depth == 4:
            in_paths = line.strip() == "paths:"
        elif in_paths and line.strip().startswith("- "):
            paths.append(line.strip()[2:].strip().strip("'\""))
    return paths


def glob_re(pattern):
    """GitHub's filter globs: `**` crosses `/`, `*` and `?` don't."""
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out, i = out + "(?:.*/)?", i + 3
        elif pattern.startswith("**", i):
            out, i = out + ".*", i + 2
        elif pattern[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif pattern[i] == "?":
            out, i = out + "[^/]", i + 1
        else:
            out, i = out + re.escape(pattern[i]), i + 1
    return re.compile(out + r"\Z")


def ci_cells(text):
    path = ROOT / "scripts" / "ci-vlt-proof-suites.py"
    spec = importlib.util.spec_from_file_location("ci_vlt_proof_suites", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.ci_cells(text)


def git(*args):
    return subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True, check=True).stdout


def needs_matrix(event, changed, filters, base_ci, head_ci):
    """The decision on already-fetched inputs (see the module docstring)."""
    if event not in ("pull_request", "push") or not filters:
        return True
    rules = [glob_re(p) for p in filters]
    relevant = [f for f in changed if any(r.match(f) for r in rules)]
    if relevant != [CI_PATH]:
        return True
    return base_ci is None or ci_cells(base_ci) != ci_cells(head_ci)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--event", required=True)
    ap.add_argument("--base", default="")
    ap.add_argument("--head", default="HEAD")
    args = ap.parse_args(argv)
    matrix = True
    if args.event in ("pull_request", "push") and args.base:
        try:
            # NUL-separated paths are never quoted or split on spaces; with
            # --no-renames a moved file lists both its old and new path.
            out = git("diff", "-z", "--name-only", "--no-renames", args.base, args.head)
            changed = [p for p in out.split("\0") if p]
            filters = event_paths(WORKFLOW.read_text(encoding="utf-8"), args.event)
            base_ci = git("show", f"{args.base}:{CI_PATH}")
            head_ci = git("show", f"{args.head}:{CI_PATH}")
            matrix = needs_matrix(args.event, changed, filters, base_ci, head_ci)
        except Exception as e:  # any doubt runs the matrix
            detail = getattr(e, "stderr", "") or e
            print(f"::warning::vlt-compat-gate: {str(detail).strip()}; running the matrix", file=sys.stderr)
            matrix = True
    if not matrix:
        print("::notice::only ci.yml changed and its vlt cells did not; skipping the vlt matrix",
              file=sys.stderr)
    print(f"matrix={'true' if matrix else 'false'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
