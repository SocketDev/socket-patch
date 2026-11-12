#!/usr/bin/env python3
"""Rebuild the probe-derived files of this directory from the Bazel-support campaign's probes.

    python3 reduce.py <campaign probes directory> <output directory>

Run with this directory as the output it rewrites, byte for byte, the S5 vectors
(`s5/module`, `s5/workspace`, `s5/bare`), `s5/accepts.tsv`, the S1c rows (`s1c/rows`) and
`s1c/accepts.tsv`, and then `SHA256SUMS` over every input here. The probe directory is not
part of this repository; README.md says what it holds. `corpus/` is not made here: its
files are copies from public repositories.
"""
import hashlib
import json
import os
import re
import shutil
import sys

PROBES, OUT = sys.argv[1], sys.argv[2]
GROUP = os.path.join(PROBES, "starlark-include")


def write(rel, data):
    path = os.path.join(OUT, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def table(header, rows):
    """`rows` is [(columns, {outcome: [versions]})], outcomes in the order first seen."""
    lines = ["# " + line for line in header]
    for columns, outcomes in rows:
        cells = ["%s => %s" % (",".join(versions), outcome) for outcome, versions in outcomes.items()]
        lines.append("\t".join([*columns, *cells]))
    return ("\n".join(lines) + "\n").encode()


# ---- S5: what Bazel accepts -------------------------------------------------------------
S5_VERSIONS = ["5.4.1", "6.6.0", "7.7.2", "8.8.2", "9.3.2", "10.0.0rc3"]
S5_KINDS = ["module", "segment", "bzl", "build", "workspace"]

# The segment, `.bzl` and `BUILD` vectors are the same bytes: one copy, `bare/`.
for kind, out in [("module", "module"), ("workspace", "workspace"), ("bzl", "bare")]:
    src = os.path.join(GROUP, "s5", "vectors", kind)
    for name in sorted(os.listdir(src)):
        with open(os.path.join(src, name), "rb") as f:
            write(os.path.join("s5", out, name), f.read())
for kind in ["segment", "build"]:
    src = os.path.join(GROUP, "s5", "vectors", kind)
    for name in os.listdir(src):
        with open(os.path.join(src, name), "rb") as a, open(os.path.join(OUT, "s5", "bare", name), "rb") as b:
            assert a.read() == b.read(), (kind, name)

rows = []
for kind in S5_KINDS:
    seen = {}
    for version in S5_VERSIONS:
        path = os.path.join(GROUP, "s5", "accepts-%s-%s.json" % (kind, version))
        if not os.path.exists(path):
            continue  # no segments before 7.2.0, no WORKSPACE from 9.0.0
        for cell in json.load(open(path)):
            prefix, variant = cell["id"].split("/")
            assert prefix == kind
            printed = set()
            for run in cell["runs"]:
                for line in (run["stderr"] + "\n" + run["stdout"]).splitlines():
                    found = re.search(r"S5VAL (.*)$", line)
                    if found:
                        printed.add(found.group(1))
            # A cell is a value when Bazel exited 0 and printed it, and an error otherwise.
            assert len(printed) == (1 if cell["ok"] else 0), cell["id"]
            outcome = printed.pop() if cell["ok"] else "error"
            seen.setdefault(variant, {}).setdefault(outcome, []).append(version)
    rows += [((kind, variant), seen[variant]) for variant in sorted(seen)]
write(
    "s5/accepts.tsv",
    table(
        [
            "Probe S5: what Bazel did with each vector. One row per file kind and variant:",
            "kind, variant, then per distinct outcome `<versions> => <repr(V)> <len(V)>` or `<versions> => error`.",
            "Derived from the campaign's starlark-include/s5/accepts-<kind>-<version>.json; see README.md.",
        ],
        rows,
    ),
)

# ---- S1c: include() syntax and placement ------------------------------------------------
S1C_VERSIONS = ["6.6.0", "7.1.2", "7.2.0", "7.7.2", "8.0.0", "8.1.0", "8.8.2", "9.3.2", "10.0.0rc3"]
# The rows whose root MODULE.bazel is the thing varied. The other eight vary the segment,
# nest includes or use a non-root module: their root file is the baseline's.
S1C_ROWS = 27
# Row ids that are not file names.
S1C_NAMES = {"label-@//": "label-at-main", "label-@@//": "label-atat-main", "label-@s1//": "label-at-s1"}

sys.path.insert(0, GROUP)
sys.dont_write_bytecode = True
import s1_syntax  # noqa: E402  (the probe driver: its CELLS table holds each row's files)

cells = s1_syntax.CELLS[:S1C_ROWS]
assert cells[0]["id"] == "ok-baseline" and cells[-1]["id"] == "indented-include"
results = {}
for version in S1C_VERSIONS:
    for row in json.load(open(os.path.join(GROUP, "s1", "syntax-%s.json" % version))):
        results[(row["id"], version)] = row
shutil.rmtree(os.path.join(OUT, "s1c", "rows"), ignore_errors=True)
rows = []
for cell in cells:
    name = S1C_NAMES.get(cell["id"], cell["id"])
    write(os.path.join("s1c", "rows", name), cell["files"]["MODULE.bazel"].encode())
    outcomes = {}
    for version in S1C_VERSIONS:
        row = results.get((cell["id"], version))
        if row is None:
            continue  # a cell with a minimum version
        if row["ok"]:
            outcome = "ok"
        elif all(rc == 0 for rc in row["rc"]):
            outcome = "skipped"  # exit 0 and the segment was not evaluated
        else:
            outcome = "error"
        outcomes.setdefault(outcome, []).append(version)
    rows.append(((name,), outcomes))
write(
    "s1c/accepts.tsv",
    table(
        [
            "Probe S1c: what `bazel mod graph` did with each root MODULE.bazel of `rows/`. One row per file:",
            "row, then per distinct outcome `<versions> => ok` (exit 0, the segment's module is in the graph),",
            "`<versions> => skipped` (exit 0, the segment was not evaluated) or `<versions> => error`.",
            "Derived from the campaign's starlark-include/s1/syntax-<version>.json; see README.md.",
        ],
        rows,
    ),
)

# ---- checksums --------------------------------------------------------------------------
# Every input: not the goldens, which are what the reader produces, and not this list.
listed = []
for base, dirs, files in os.walk(OUT):
    dirs[:] = sorted(d for d in dirs if d != "__pycache__")
    for name in files:
        rel = os.path.relpath(os.path.join(base, name), OUT).replace(os.sep, "/")
        if rel != "SHA256SUMS" and not rel.endswith(".golden"):
            listed.append(rel)
with open(os.path.join(OUT, "SHA256SUMS"), "w", newline="\n") as sums:
    for rel in sorted(listed):
        with open(os.path.join(OUT, rel), "rb") as f:
            sums.write("%s  %s\n" % (hashlib.sha256(f.read()).hexdigest(), rel))
