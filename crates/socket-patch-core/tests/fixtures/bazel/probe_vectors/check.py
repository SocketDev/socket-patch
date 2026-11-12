#!/usr/bin/env python3
"""Consistency check of the probe vectors. Run `python3 check.py` in this directory.

`shasum -a 256 -c SHA256SUMS` proves only that the listed files have not changed. This
script checks what a test that reads the vectors relies on:

- `SHA256SUMS` lists every file, and no file has the literal name of a Bazel boundary file
  or carries a machine path;
- every file a `vectors.json` names exists and has the digest recorded for it;
- every workspace file that a committed lock records has its bytes committed: the label
  of each file the X4 module file reads has its package's BUILD file, and each root or
  `othermod` `go.mod` / `go.sum` row of the X3 locks has a fixture file with that SHA-256
  (files of other repositories, such as rules_go's, live in the output base);
- the static reading of each lock agrees with what Bazel did (`expected.json`, the X4 rows);
- each verdict that a design rule rests on is still what the files show: a byte-real lock
  for each lock version run, a lock written under a non-default digest function, the
  crate extension absent from the X2 lock, and the `hosted` / `skew` pair of X3 with equal
  root digests and different selected versions.

Standard library only. Reads bytes, writes nothing, runs no Bazel. Prints one line per
check and exits 1 if any failed.
"""
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BOUNDARY_NAMES = {"MODULE.bazel", "MODULE.bazel.lock", "BUILD", "BUILD.bazel", "WORKSPACE",
                  "WORKSPACE.bazel", "WORKSPACE.bzlmod", "REPO.bazel"}
LOCK_VERSIONS = [3, 6, 11, 13, 16, 18, 24, 26, 28]
CONTAINERS = ("accumulatedFileDigests", "recordedFileInputs", "recordedInputs")

failures = []


def read(rel):
    with open(os.path.join(HERE, rel), "rb") as f:
        return f.read()


def load(rel):
    return json.loads(read(rel))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def exists(rel):
    return os.path.isfile(os.path.join(HERE, rel))


def check(name, problems):
    problems = list(problems)
    print(("ok    " if not problems else "FAIL  ") + name)
    for p in problems[:20]:
        print("        " + str(p))
    if problems:
        failures.append(name)


def all_files():
    out = []
    for dirpath, dirnames, names in os.walk(HERE):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
        out += [os.path.relpath(os.path.join(dirpath, n), HERE) for n in sorted(names)]
    return [p.replace(os.sep, "/") for p in out]


def unescape(text):
    """Undo the `recordedInputs` escape: backslash-s is a space, backslash-n a newline."""
    out, i = [], 0
    while i < len(text):
        if text[i] == "\\" and i + 1 < len(text):
            out.append({"s": " ", "n": "\n"}.get(text[i + 1], text[i + 1]))
            i += 2
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def recorded(lock):
    """Every recorded file input of every extension entry: (container, key, repo, path, value).

    `key` is the spelling in the lock. `repo` is "" for the main repository. The three
    shapes: `accumulatedFileDigests` {"@@repo//pkg:name": hex}, `recordedFileInputs`
    {"@@repo//pkg/name": hex}, `recordedInputs` ["FILE:@@repo//pkg/name hex"].
    """
    rows = []

    def split(label, colon):
        repo, _, rest = label[2:].partition("//")
        if colon:
            pkg, _, name = rest.partition(":")
            rest = name if not pkg else pkg + "/" + name
        return repo, rest

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in CONTAINERS[:2] and isinstance(value, dict):
                    for k, v in value.items():
                        rows.append((key, k) + split(k, key == CONTAINERS[0]) + (v,))
                elif key == CONTAINERS[2] and isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and item.startswith("FILE:@@"):
                            body, _, digest = item.rpartition(" ")
                            rows.append((key, body) + split(unescape(body[len("FILE:"):]), False) + (digest,))
                else:
                    walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(lock.get("moduleExtensions", {}))
    return rows


def family(lock):
    return "A" if "moduleDepGraph" in lock else "B"


# ------------------------------------------------------------------ the tree
def check_tree():
    files = all_files()
    listed = {}
    for line in read("SHA256SUMS").decode("utf-8").splitlines():
        digest, _, rel = line.partition("  ")
        listed[rel] = digest
    on_disk = [f for f in files if f != "SHA256SUMS"]
    check("SHA256SUMS lists every file and nothing else",
          [f"not listed: {f}" for f in on_disk if f not in listed]
          + [f"listed but missing: {f}" for f in listed if f not in on_disk])
    check("every listed digest is the file's SHA-256",
          [f for f in on_disk if f in listed and sha256(read(f)) != listed[f]])
    check("no file has the literal name of a Bazel boundary file",
          [f for f in files if os.path.basename(f) in BOUNDARY_NAMES])
    # Spelled in two parts so that this file does not match its own needle.
    needle = b"/" + b"Users/"
    check("no file carries a machine path", [f for f in files if needle in read(f)])


# ------------------------------------------------------------------ X4
def check_x4():
    v = load("x4/vectors.json")
    inputs = {i["path"][len("inputs/"):]: i for i in v["inputs"]}
    check("x4: every input file has the size and SHA-256 that vectors.json records",
          [p for p, i in inputs.items()
           if not exists("x4/inputs/" + p) or sha256(read("x4/inputs/" + p)) != i["sha256"]
           or len(read("x4/inputs/" + p)) != i["size"]])

    problems, versions_with_lock, referenced = [], set(), set()
    for cell in v["cells"]:
        where = f"bazel {cell['bazel']}"
        if len(cell["recorded"]) != len(inputs) or not cell["all_match"]:
            problems.append(f"{where}: not every input is recorded and matching")
        for row in cell["recorded"]:
            if not (row["value"] == row["sha256_on_disk"] == inputs[row["path"]]["sha256"]):
                problems.append(f"{where}: {row['path']} row does not hold the file's SHA-256")
        if not cell["lock_file"]:
            continue
        referenced.add(cell["lock_file"])
        if not exists("x4/" + cell["lock_file"]):
            problems.append(f"{where}: {cell['lock_file']} is missing")
            continue
        data = read("x4/" + cell["lock_file"])
        lock = json.loads(data)
        versions_with_lock.add(lock["lockFileVersion"])
        if sha256(data) != cell["lock_sha256"] or lock["lockFileVersion"] != cell["lockFileVersion"]:
            problems.append(f"{where}: lock digest or version differs from vectors.json")
        if family(lock) != cell["family"]:
            problems.append(f"{where}: family")
        in_lock = {(c, k): val for c, k, repo, path, val in recorded(lock) if repo == ""}
        for row in cell["recorded"]:
            if in_lock.get((cell["container"], row["key"])) != row["value"]:
                problems.append(f"{where}: the lock does not record {row['key']!r} as vectors.json says")
        if len(in_lock) != len(inputs):
            problems.append(f"{where}: the lock records {len(in_lock)} main-repository files")
    check("x4: every cell's rows are the on-disk SHA-256, and every committed lock holds them", problems)

    problems = []
    lf = sha256(read("x4/inputs/lf.lock"))
    not_64, same_length = False, False
    for row in v["digest_function"]:
        value = row["recorded_value_for_lf_lock"]
        if value == lf or row["equals_sha256_of_bytes"]:
            problems.append(f"{row['bazel']} {row['startup_option']}: the row does not refute")
        if not row["lock_file"]:
            continue
        referenced.add(row["lock_file"])
        if not exists("x4/" + row["lock_file"]):
            problems.append(f"{row['lock_file']} is missing")
            continue
        data = read("x4/" + row["lock_file"])
        values = {path: val for c, k, repo, path, val in recorded(json.loads(data)) if repo == ""}
        if sha256(data) != row["lock_sha256"] or values.get("lf.lock") != value:
            problems.append(f"{row['lock_file']}: digest or recorded value differs from vectors.json")
        if any(val == inputs[path]["sha256"] for path, val in values.items()):
            problems.append(f"{row['lock_file']}: a recorded value is a SHA-256 of the bytes")
        not_64 |= not re.fullmatch(r"[0-9a-f]{64}", value)
        same_length |= bool(re.fullmatch(r"[0-9a-f]{64}", value))
    if not (not_64 and same_length):
        problems.append("need one committed lock whose values are not 64 hex digits and one whose are")
    check("x4: the non-default digest function refutation has byte-real locks", problems)

    on_disk = {f[len("x4/"):] for f in all_files() if f.startswith("x4/locks/")}
    check("x4: every lock under locks/ is named by vectors.json", sorted(on_disk ^ referenced))

    problems = []
    ws = v["workspace"]["files"]
    build_of = {os.path.dirname(path): rel for rel, path in ws.items() if os.path.basename(path) == "BUILD.bazel"}
    problems += [f"missing x4/{rel}" for rel in ws if not exists("x4/" + rel)]
    module = [rel for rel, path in ws.items() if path == "MODULE.bazel"]
    labels = re.findall(r'"//([^":]*):([^"]+)"', read("x4/" + module[0]).decode("utf-8")) if module else []
    if len([lb for lb in labels if lb[1].endswith(".lock")]) != len(inputs):
        problems.append("the module file does not name every input")
    for pkg, name in labels:
        if name.endswith(".bzl"):
            continue
        if pkg not in build_of:
            problems.append(f"//{pkg}:{name}: no BUILD file committed for package '{pkg}'")
        if not exists("x4/inputs/" + (pkg + "/" if pkg else "") + name):
            problems.append(f"//{pkg}:{name}: input file not committed")
    check("x4: the committed workspace has a BUILD file for every package the module file reads", problems)
    return versions_with_lock


# ------------------------------------------------------------------ X2
def check_x2():
    v = load("x2/vectors.json")
    problems, with_lock = [], 0
    for cell in v["cells"]:
        where = f"bazel {cell['bazel']}"
        ml = cell["module_lock"]
        if cell["crate_extension_in_module_lock"] is not False:
            problems.append(f"{where}: crate_extension_in_module_lock")
        if not ml["lock_file"]:
            continue
        with_lock += 1
        data = read("x2/" + ml["lock_file"])
        keys = list(json.loads(data).get("moduleExtensions", {}))
        if sha256(data) != ml["sha256"]:
            problems.append(f"{where}: {ml['lock_file']} digest")
        if ml["absent_extension_key"] in keys or any(k.endswith("%crate") for k in keys):
            problems.append(f"{where}: the lock has an entry for the crate extension")
        if not set(ml["rules_rust_extension_keys"]) <= set(keys):
            problems.append(f"{where}: rules_rust_extension_keys are not in the lock")
    if with_lock == 0:
        problems.append("no baseline MODULE.bazel.lock is committed")
    check("x2: the crate extension has no entry in the baseline MODULE.bazel.lock", problems)

    problems = []
    differs = v["environment"]["exit_codes_that_differ_without_them"]
    want = {"Q4a-bump-build-no-repin": {"exit_without": 37, "exit_with": 1},
            "Q4c-bump-build": {"exit_without": 37, "exit_with": 1}}
    if differs != {"7.7.2": want, "8.8.2": {}, "9.3.2": {}}:
        problems.append(f"exit_codes_that_differ_without_them is {differs}")
    for cell in v["cells"]:
        stale = cell["stale_override_after_bump"]
        if (stale["build_without_repin"]["exit"], stale["build"]["exit"]) != (1, 1):
            problems.append(f"bazel {cell['bazel']}: the two failing build steps do not record exit 1")
    check("x2: the environment note matches the recorded exit codes", problems)


# ------------------------------------------------------------------ X3
def check_x3():
    v = load("x3/vectors.json")
    fixture = {}
    for f in all_files():
        if f.startswith("x3/fixture/"):
            fixture.setdefault(sha256(read(f)), []).append(f[len("x3/fixture/"):])

    problems, locks = [], []
    for cell in v["cells"]:
        for state, row in cell["states"].items():
            copy = row["hidden_lock"].get("reduced_copy")
            if copy:
                if exists("x3/" + copy):
                    locks.append("x3/" + copy)
                else:
                    problems.append(f"{copy} is missing")
    check("x3: every reduced hidden lockfile that vectors.json names exists", problems)

    locks += [f for f in all_files() if f.startswith("x3/locks/")]
    problems = []
    for rel in locks:
        for c, key, repo, path, value in recorded(load(rel)):
            if repo not in ("", "othermod+") or os.path.basename(path) not in ("go.mod", "go.sum"):
                continue  # rules_go's and gazelle's own files are in the output base
            names = fixture.get(value, [])
            prefix = "othermod." if repo else ""
            if not any(n.startswith(prefix) and n.endswith("." + path) and (repo or not n.startswith("othermod."))
                       for n in names):
                problems.append(f"{rel}: {key} {value[:12]}... has no file under x3/fixture/")
    check("x3: every root and othermod go.mod / go.sum row has its bytes under fixture/", problems)

    problems = []
    rows = v["freshness_by_root_go_mod_digest"]
    hidden_cells = sum(1 for c in v["cells"] if c["states"]["hosted"]["hidden_lock"].get("exists"))
    if len(rows) != hidden_cells or not rows:
        problems.append(f"{len(rows)} rows for {hidden_cells} cells with a hidden lockfile")
    root_pair = {"go.mod": sha256(read("x3/fixture/hosted.go.mod")), "go.sum": sha256(read("x3/fixture/hosted.go.sum"))}
    for row in rows:
        where = f"gazelle {row['gazelle']} on {row['bazel']}"
        entries = {}
        for state, copy in row["reduced_copies"].items():
            ext = load("x3/" + copy)["moduleExtensions"]
            entries[state] = next(val["general"] for key, val in ext.items() if key.endswith("%go_deps"))
        root = {st: {path: val for c, k, repo, path, val in recorded({"moduleExtensions": {"x": {"general": e}}})
                     if repo == ""} for st, e in entries.items()}
        pgx = {st: e["generatedRepoSpecs"]["com_github_jackc_pgx_v5"]["attributes"] for st, e in entries.items()}
        only_skew = set(entries["skew"]["recordedInputs"]) - set(entries["hosted"]["recordedInputs"])
        if root["hosted"] != root["skew"] or root["hosted"] != root_pair:
            problems.append(f"{where}: the two entries do not record the same root go.mod / go.sum")
        if (pgx["hosted"]["version"], pgx["skew"]["version"]) != ("v5.7.0-socketpatch.1", "v5.7.1"):
            problems.append(f"{where}: selected versions")
        if not pgx["hosted"].get("replace") or pgx["skew"].get("replace"):
            problems.append(f"{where}: replace")
        if entries["hosted"]["usagesDigest"] == entries["skew"]["usagesDigest"]:
            problems.append(f"{where}: usagesDigest does not differ")
        if set(entries["hosted"]["recordedInputs"]) - set(entries["skew"]["recordedInputs"]):
            problems.append(f"{where}: the hosted entry has a row the skew entry lacks")
        if not only_skew or not all(i.startswith("FILE:@@othermod+//") for i in only_skew):
            problems.append(f"{where}: rows only in skew are {sorted(only_skew)}")
        if row["patched_marker_file_present"] != {"hosted": True, "skew": False}:
            problems.append(f"{where}: fetched bytes")
    if "REFUTED as sufficient" not in v["verdict"].get("freshness_by_root_go_mod_digest", ""):
        problems.append("the verdict is missing")
    check("x3: hosted and skew record the same root go.mod / go.sum and select different versions", problems)

    problems = []
    modules = sorted(n for names in fixture.values() for n in names if n.endswith(".MODULE.bazel"))
    hosted = [n for n in modules if n.startswith("hosted.")]
    skew = [n for n in modules if n.startswith("skew.")]
    if len(hosted) != 1 or len(skew) != 1:
        problems.append(f"module files under fixture/: {modules}")
    else:
        h, s = read("x3/fixture/" + hosted[0]), read("x3/fixture/" + skew[0])
        added = s[len(h):].decode("utf-8")
        if not s.startswith(h) or "othermod" not in added or 'path = "../othermod"' not in added:
            problems.append("skew is not hosted plus the othermod lines")
        real = [f for f in all_files() if f.startswith("x3/locks/")]
        deps = re.findall(r'bazel_dep\(name = "([^"]+)", version = "([^"]+)"\)', s.decode("utf-8"))
        for rel in real:
            registry = load(rel)["registryFileHashes"]
            for name, version in deps:
                has = any(u.endswith(f"/modules/{name}/{version}/MODULE.bazel") for u in registry)
                if has == (name == "othermod"):
                    problems.append(f"{rel}: registry key for bazel_dep {name}@{version}: {has}")
        if not real:
            problems.append("no byte-real workspace lock under x3/locks/")
    check("x3: the byte-real skew lock has its MODULE.bazel, and hosted differs from it by the othermod lines",
          problems)


# ------------------------------------------------------------------ lockfile (L1, L6)
def check_lockfile():
    v = load("lockfile/vectors.json")
    names = v["file_names"]
    check("lockfile: every workspace file that vectors.json names exists",
          [rel for rel in names if rel.startswith("workspace/") and not exists("lockfile/" + rel)])

    problems, versions = [], set()
    vectors = v["recorded_inputs"]["vectors"]
    for row in vectors:
        for side in ("fresh", "stale"):
            base = f"lockfile/{row['dir']}/{side}/"
            where = f"bazel {row['bazel']} {side}"
            try:
                expected = load(base + "expected.json")
                data = read(base + "root.MODULE.bazel.lock")
            except OSError as e:
                problems.append(f"{where}: {e}")
                continue
            lock = json.loads(data)
            versions.add(lock["lockFileVersion"])
            mine = sorted((path, val, sha256(read(base + path))) for c, k, repo, path, val in recorded(lock)
                          if repo == "")
            theirs = sorted((r["path"], r["recorded"], r["actual"]) for r in expected["prototype"]["inputs"])
            stale = [path for path, val, actual in mine if val != actual]
            if mine != theirs or len(mine) != 2:
                problems.append(f"{where}: the lock and the files do not give expected.json's rows")
            if bool(stale) != (expected["bazel_error_mode_build_exit"] != 0):
                problems.append(f"{where}: stale rows {stale} against Bazel's exit "
                                f"{expected['bazel_error_mode_build_exit']}")
            if stale != row[side]["stale_inputs"] or sha256(data) != row[side]["lock_sha256"]:
                problems.append(f"{where}: vectors.json row")
            if (lock["lockFileVersion"], family(lock)) != (row["lockFileVersion"], row["family"]):
                problems.append(f"{where}: lock version or family")
            if "moduleFileHash" in lock and lock["moduleFileHash"] != sha256(read(base + "root.MODULE.bazel")):
                problems.append(f"{where}: moduleFileHash is not the module file's SHA-256")
            if ("moduleFileHash" in lock) != row["records_moduleFileHash"]:
                problems.append(f"{where}: records_moduleFileHash")
    if len(vectors) != 17:
        problems.append(f"{len(vectors)} releases, expected 17")
    check("lockfile: 34 vectors, each stale exactly when Bazel's error-mode build failed", problems)

    pair = v["l6_crlf_pair"]
    base = f"lockfile/{pair['dir']}/"
    problems = []
    lf_in, crlf_in = read(base + pair["lf"]["input"]), read(base + pair["crlf"]["input"])
    lf_lock, crlf_lock = read(base + pair["lf"]["lock"]), read(base + pair["crlf"]["lock"])
    module = sha256(read(base + "root.MODULE.bazel"))

    def value(data):
        return {k: val for c, k, repo, path, val in recorded(json.loads(data))}.get(pair["key"])

    if b"\r" in lf_in or crlf_in != lf_in.replace(b"\n", b"\r\n"):
        problems.append("the inputs are not one text with LF and with CRLF")
    if value(lf_lock) != sha256(lf_in) or value(crlf_lock) != sha256(crlf_in):
        problems.append("each lock must record the SHA-256 of its own input")
    if b"\r" in lf_lock or crlf_lock.count(b"\r\n") != crlf_lock.count(b"\n") or b"\r\n" not in crlf_lock:
        problems.append("line endings of the locks")
    as_lf = crlf_lock.replace(b"\r\n", b"\n").split(b"\n")
    if len(as_lf) != len(lf_lock.split(b"\n")) or sum(a != b for a, b in zip(as_lf, lf_lock.split(b"\n"))) != 1:
        problems.append("the locks differ in more than the one digest line")
    if json.loads(lf_lock)["moduleFileHash"] != module or json.loads(crlf_lock)["moduleFileHash"] != module:
        problems.append("moduleFileHash is not the module file's SHA-256")
    if (sha256(lf_lock), sha256(crlf_lock)) != (pair["lf"]["lock_sha256"], pair["crlf"]["lock_sha256"]):
        problems.append("lock digests differ from vectors.json")
    check("lockfile: the L6 pair is one input with LF and CRLF and the lock for each", problems)
    return versions


def main():
    check_tree()
    x4_versions = check_x4()
    check_x2()
    check_x3()
    lockfile_versions = check_lockfile()
    check("a byte-real lock for each of the nine lock versions run (3 to 28)",
          [f"lockFileVersion {n}" for n in LOCK_VERSIONS if n not in (x4_versions | lockfile_versions)]
          + [f"lockfile/ alone lacks lockFileVersion {n}" for n in LOCK_VERSIONS if n not in lockfile_versions])
    print(f"{len(failures)} failed" if failures else "all checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
