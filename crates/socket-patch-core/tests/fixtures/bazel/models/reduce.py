#!/usr/bin/env python3
"""Rebuild the probe-derived files of this directory from the Bazel-support campaign's probes.

    python3 reduce.py <campaign probes directory> <output directory>

Run with this directory as the output it rewrites `s1c.json`, `s2.json`, `ws-order.json` and
`ws-units.json` byte for byte. The probe directory is not part of this repository; README.md
says what it holds. The `*.golden` files are not made here: they are what the readers produce.
"""
import json
import os
import re
import sys

PROBES, OUT = sys.argv[1], sys.argv[2]
INCLUDE = os.path.join(PROBES, "starlark-include")
# The probe drivers hold each cell's files as Python literals. Importing one only defines
# them: nothing runs Bazel.
sys.path.insert(0, INCLUDE)
sys.dont_write_bytecode = True
import s1_syntax  # noqa: E402
import s2_segments  # noqa: E402


def write(name, cells):
    with open(os.path.join(OUT, name), "w", newline="\n") as f:
        json.dump(cells, f, indent=1, sort_keys=True)
        f.write("\n")


def starlark(files):
    """The files of a cell a module reader could be asked for; a directory where a file
    is expected is listed apart."""
    keep, directories = {}, []
    for path, text in files.items():
        if text is None or os.path.basename(path) in ("BUILD.bazel", "keep"):
            if os.path.basename(path) == "keep":
                directories.append(os.path.dirname(path))
            continue
        if path.startswith(("segdep/", "rules_x/", "tools/")):
            continue  # another module, or the probe's own extension
        keep[path] = text
    return keep, sorted(directories)


def versions(prefix):
    names = [n for n in os.listdir(os.path.dirname(prefix)) if n.startswith(os.path.basename(prefix))]
    found = [n[len(os.path.basename(prefix)):-len(".json")] for n in names if n.endswith(".json")]
    key = lambda v: [int(p) if p.isdigit() else 0 for p in re.split(r"[.rc]+", v)]
    return sorted((v for v in found if v[0].isdigit()), key=key)


# ---- S1c: include syntax and placement ----------------------------------------------------
cells = {}
for cell in s1_syntax.CELLS:
    files, directories = starlark(cell["files"])
    cells[cell["id"]] = {"files": files, "directories": directories, "bazel": {}}
prefix = os.path.join(INCLUDE, "s1", "syntax-")
for version in versions(prefix):
    for row in json.load(open(prefix + version + ".json")):
        if row["ok"]:
            outcome = "ok"
        elif -999 in row["rc"]:
            outcome = "timeout"
        elif all(rc == 0 for rc in row["rc"]):
            outcome = "skipped"  # exit 0 and the segment's dependency is not in the graph
        else:
            outcome = "error"
        cells[row["id"]]["bazel"][version] = outcome
write("s1c.json", cells)

# ---- S2: segment semantics -----------------------------------------------------------------
cells = {}
for cell in s2_segments.CELLS:
    files, _ = starlark(cell["files"])
    flags = sorted({arg for cmd in cell["cmds"] if isinstance(cmd, list) for arg in cmd if arg.startswith("--")})
    cells[cell["id"]] = {"files": files, "flags": flags, "bazel": {}}
prefix = os.path.join(INCLUDE, "s2", "segments-")
for version in versions(prefix):
    for row in json.load(open(prefix + version + ".json")):
        seen = []
        for run in row["runs"]:
            for line in (run["stderr"] + "\n" + run["stdout"]).splitlines():
                found = re.search(r"SEEN module=s2 is_root=True tags=(\[.*\]) nmodules=", line)
                if found and json.loads(found.group(1)) not in seen:
                    seen.append(json.loads(found.group(1)))
        # What the extension saw of the root module: one list of tags per evaluation.
        cells[row["id"]]["bazel"][version] = {"ok": row["ok"], "seen": seen}
write("s2.json", cells)

# ---- S6: WORKSPACE definition order --------------------------------------------------------
cells = {}
group = os.path.join(PROBES, "versions-hybrid", "vectors", "ws-order")
for case in sorted(os.listdir(group)):
    files = {}
    for base, _, names in os.walk(os.path.join(group, case)):
        for name in names:
            if name == "WORKSPACE" and base.endswith(case) or name.endswith(".bzl"):
                path = os.path.relpath(os.path.join(base, name), os.path.join(group, case))
                files[path.replace(os.sep, "/")] = open(os.path.join(base, name)).read()
    expected = json.load(open(os.path.join(group, case, "expected.json")))
    built = set(expected["marker_by_bazel"].values())
    shown = set(expected["query_external_build_shows"].values())
    assert len(built) == 1 and len(shown) == 1 and len(expected["marker_by_bazel"]) == 7, case
    cells[case] = {
        "description": expected["description"],
        "repo": expected["repo"],
        "files": files,
        "runs": sorted(expected["marker_by_bazel"]),
        "built": built.pop(),
        "query_shows": shown.pop(),
    }
write("ws-order.json", cells)

# ---- A unit that declares a repository again: after, in and before the chunk of the first ---
# The `-fresh` copy of a pypi row is the workspace as the row's build read it: the unit is in
# the `WORKSPACE` and its macro file under `.socket/`. The Go workspace is the one the two
# steps of the attack report started from; the probe kept no copy with the unit in it.
cells = {}
group = os.path.join(PROBES, "rev4-vendored-pypi")
HOOK = ".socket/bazel/socket_patch_pypi.bzl"
for row, description in [
    ("row7-ws-redeclare-b7.7.2", "the unit appended after the chunk of install_deps()"),
    ("row7-ws-inline-b7.7.2", "the unit's load among the loads of the chunk of install_deps(), its call after it"),
    ("row7-ws-inline-b8.8.2", "the same on Bazel 8.8.2"),
]:
    root = os.path.join(group, "ws", row + "-fresh")
    summary = open(os.path.join(group, "logs", row, "SUMMARY.txt")).read()
    ran = re.search(r"^a03-patched-run \| exit=0 \| SPVICTIM=(\S+)", summary, re.M).group(1)
    assert ran == "vulnerable" or ran == "patched-" + row, (row, ran)
    cells["pypi-" + row] = {
        "description": description,
        "repo": "pypi_spvictim",
        "files": {name: open(os.path.join(root, name)).read() for name in ("WORKSPACE", HOOK)},
        "bazel": row.rsplit("-b", 1)[1],
        "built": "the hub's" if ran == "vulnerable" else "the unit's",
    }
root = os.path.join(PROBES, "rev4-go-unconditional-attack", "ws", "aw35", "ws")
cells["go-aw35"] = {
    "description": "a gazelle WORKSPACE whose go_repository rules are in a macro file; no unit",
    "repo": "com_example_upstream",
    "files": {name: open(os.path.join(root, name)).read() for name in ("WORKSPACE", "deps.bzl")},
    "bazel": "7.7.2",
    "built": "the macro's",
}
write("ws-units.json", cells)
