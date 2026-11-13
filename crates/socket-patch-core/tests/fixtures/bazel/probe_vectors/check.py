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
- each output-tree layout still gives what was recorded for it: the tree of a detect vector
  alone yields every classification in its `expect`, each convenience link cut at
  `execroot` names its output base, and each repository-cache entry and `id-` file follows
  from the checksum and the canonical id, in the entries collected from their `id-` files
  and in the sample of every download of five runs, which has entries with no `id-` file
  and one under `sha384`;
- each verdict that a design rule rests on is still what the files show: a byte-real lock
  for each lock version run, a lock written under a non-default digest function, the
  crate extension absent from the X2 lock, and the `hosted` / `skew` pair of X3 with equal
  root digests and different selected versions.

Standard library only. Reads bytes, writes nothing, runs no Bazel. Prints one line per
check and exits 1 if any failed.
"""
import base64
import hashlib
import json
import os
import posixpath
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


# ------------------------------------------------------------------ output-tree layouts
def classify(nodes, query):
    """What the recorded tree alone says about `query`, by the rules of the detect prototype.

    `nodes` maps a tokenized path to its tree entry. Returns the fields of an `expect` row:
    the path with every recorded link followed, the kinds, and the directory each marker
    names. A path is judged as spelled and as resolved, nearest ancestor first.
    """
    def is_file(path):
        return nodes.get(path, {}).get("type") == "file"

    todo, crossed = query.split("/"), False
    real = todo.pop(0)
    for _ in range(200):  # more components than any vector has; a link cycle ends here
        if not todo:
            break
        real += "/" + todo.pop(0)
        node = nodes.get(real, {})
        if node.get("type") == "symlink":
            target, crossed = node["target"], True
            if not target.startswith("<"):
                target = posixpath.dirname(real) + "/" + target
            todo = target.split("/") + todo
            real = todo.pop(0)

    def ancestors(path):
        child = None
        while True:
            yield path, child
            if "/" not in path:
                return
            path, child = path.rsplit("/", 1)

    base = cache = vendor = None
    for spelling in (query, real):
        for d, child in ancestors(spelling):
            if base is None and child in ("external", "execroot") and is_file(d + "/DO_NOT_BUILD_HERE"):
                base = d
    for d, child in ancestors(real):
        key = posixpath.basename(posixpath.dirname(d))
        first = nodes.get(d + ".recorded_inputs", {}).get("content", "").split("\n")[0]
        if cache is None and re.fullmatch(r"[0-9a-f]{64}", key) and is_file(d + ".recorded_inputs") and first == key:
            cache = d
        if vendor is None and child is not None and is_file(d + "/VENDOR.bazel"):
            vendor = d
    kinds = [name for name, hit in (("via_link", crossed), ("bazel_output_base", base),
                                    ("bazel_repo_contents_cache", cache), ("bazel_vendor_dir", vendor)) if hit]
    return {"canonical": real, "kinds": kinds, "output_base": base, "cache_entry": cache, "vendor_dir": vendor}


def check_layouts():
    detect = "core-external-edits/vectors/detect/"
    problems, queries, seen = [], 0, set()
    vectors = [f for f in all_files() if f.startswith(detect)]
    for rel in vectors:
        v = load(rel)
        nodes = {}
        for entry in v["tree"]:
            if nodes.setdefault(entry["path"], entry) != entry:
                problems.append(f"{rel}: two different entries for {entry['path']}")
        if rel != f"{detect}{v['bazel']}-{v['cfg']}.json":
            problems.append(f"{rel}: the name is not <bazel>-<cfg>")
        if nodes.get("<OB>/DO_NOT_BUILD_HERE", {}).get("content") != "<WS>":
            problems.append(f"{rel}: the output-base marker does not hold the workspace path")
        if nodes.get("<OB>/execroot", {}).get("type") != "dir":
            problems.append(f"{rel}: no execroot directory in the output base")
        for row in v["expect"]:
            queries += 1
            got = classify(nodes, row["query"])
            seen.update(got["kinds"])
            want = {k: (sorted(row[k]) if k == "kinds" else row[k]) for k in got}
            got["kinds"].sort()
            if got != want:
                problems.append(f"{rel}: {row['query']}: the tree gives {got}")
    if (len(vectors), queries, len(seen)) != (10, 42, 4):
        problems.append(f"{len(vectors)} layouts, {queries} queries, kinds {sorted(seen)}; want 10, 42, all four")
    check("layouts: each of the 42 recorded classifications follows from its recorded tree (10 detect vectors)",
          problems)

    problems, prefixes, in_tree = [], {}, 0
    links = load("core-output-base/proto/vectors/link_route.json")
    for row in links:
        where = f"{row['workspace_basename']} {row['link']}"
        parts = row["target"].split("/")
        base = "/".join(parts[:parts.index("execroot")]) if "execroot" in parts else None
        if not (base == row["expected_output_base"] == row["find_output_base(canonical link target)"]):
            problems.append(f"{where}: the target cut at `execroot` is {base}")
        if not (row["classified"] and row["marker_names_this_workspace"] and row["marker"] == row["workspace"]):
            problems.append(f"{where}: the marker does not name the workspace")
        if not (row["link"].startswith(row["prefix"])
                and posixpath.basename(row["workspace"]) == row["workspace_basename"]):
            problems.append(f"{where}: link name, prefix or workspace basename")
        prefixes[row["prefix"]] = prefixes.get(row["prefix"], 0) + 1
        in_tree += (base or "").startswith(row["workspace"] + "/")
    if (len(links), prefixes, in_tree) != (24, {"bazel-": 20, "dist/": 4}, 4):
        problems.append(f"{len(links)} links, prefixes {prefixes}, {in_tree} with the base inside the workspace")
    check("layouts: each of the 24 convenience links leads to its output base when cut at `execroot`", problems)

    problems, lengths, bazels = [], {}, {}
    rows = load("platform-server/vectors/repo_cache_vectors.json")
    for row in rows:
        kind, entry, marker, whole = cache_entry(row["checksum"], row["canonical_id"])
        if row["entry_dir"] != entry or row["observed_id_marker"] != marker:
            problems.append(f"{row['name']}: entry directory or id marker")
        if not whole or row["canonical_id"] != " ".join(row["urls"]):
            problems.append(f"{row['name']}: digest length or canonical id")
        lengths[kind] = lengths.get(kind, 0) + 1
        bazels[row["bazel"]] = bazels.get(row["bazel"], 0) + 1
    if (lengths, bazels) != ({"sha256": 27, "sha512": 8}, {"7.7.2": 14, "9.3.2": 19, "6.6.0": 2}):
        problems.append(f"entries by algorithm {lengths}, by release {bazels}")
    check("layouts: each of the 35 repository-cache entries and id markers follows from its checksum and canonical id",
          problems)
    check_repo_cache_sample()


def cache_entry(checksum, canonical_id):
    """Where the repository cache keeps a download with this checksum, by the rule of the
    two probes: the digest kind, the entry directory under the cache root, the name of the
    `id-` file a caller that passes `canonical_id` leaves in it, and whether the digest is
    as long as its kind says. The checksum is an SRI string or 64 hex digits (SHA-256)."""
    kind, _, b64 = checksum.rpartition("-")
    digest = base64.b64decode(b64).hex() if kind else checksum.lower()
    kind = kind or "sha256"
    marker = "id-" + hashlib.new(kind, canonical_id.encode("utf-8")).hexdigest()
    return (kind, f"content_addressable/{kind}/{digest}", marker,
            len(digest) == 2 * hashlib.new(kind).digest_size)


def check_repo_cache_sample():
    """The sample of `test-infra-offline`: every download of five runs, by shape.

    Unlike the 35 entries above, these were not collected from `id-` files, so most have
    none. A run is `<fixture>-<bazel>`; a row with no `key_type` is a download that is in
    no cache directory.
    """
    per_shape = 3
    doc = load("test-infra-offline/vectors/repo_cache/observed.sample.json")
    rows, shapes, totals = doc["rows"], doc["source_shapes"], doc["source_totals"]

    problems, seen, cached = [], {}, []
    for row in rows:
        where = f"{row['run']} {row['url']}"
        host = re.fullmatch(r"https://([^/]+)/.*", row["url"]).group(1)
        key = (row["run"], host, row["key_type"], bool(row.get("id_markers_present")))
        seen[key] = seen.get(key, 0) + 1
        if row["key_type"] is None:
            if sorted(row) != ["bytes", "key_type", "run", "url"]:
                problems.append(f"{where}: a download in no cache directory names an entry")
            continue
        cached.append(row)
        kind, entry, marker, whole = cache_entry(row["integrity"], row["url"])
        if not whole or kind != row["key_type"] or row["cache_file"] != entry + "/file":
            problems.append(f"{where}: the entry is not where the checksum puts it")
        if row["id_marker_if_canonical_id_is_url"] != f"{entry}/{marker}":
            problems.append(f"{where}: the id file a canonical id of the URL would leave")
        if row["id_markers_present"] not in ([], [marker]):
            problems.append(f"{where}: an id file that is not the hash of the URL")
        if row["canonical_id_is_url"] != bool(row["id_markers_present"]):
            problems.append(f"{where}: canonical_id_is_url")
    check(f"layouts: each of the {len(cached)} sampled repository-cache entries follows from its checksum, "
          "and its id file, where it has one, from the URL", problems)

    problems = []
    listed = {(s["run"], s["host"], s["key_type"], s["id_file"]): s for s in shapes}
    if len(listed) != len(shapes) or list(seen) != list(listed):
        problems.append("the shapes of the rows, in order of first row, are not source_shapes")
    for key, s in listed.items():
        if s["sampled"] != min(s["rows"], per_shape) or seen.get(key) != s["sampled"]:
            problems.append(f"{key}: {seen.get(key)} rows for a shape of {s['rows']}")
    in_cache = [s for s in shapes if s["key_type"] is not None]
    by_kind = {}
    for s in in_cache:
        by_kind[s["key_type"]] = by_kind.get(s["key_type"], 0) + s["rows"]
    counted = {
        "in_a_cache_directory": sum(s["rows"] for s in in_cache),
        "with_an_id_file": sum(s["rows"] for s in in_cache if s["id_file"]),
        "without_an_id_file": sum(s["rows"] for s in in_cache if not s["id_file"]),
        "in_no_cache_directory": sum(s["rows"] for s in shapes if s["key_type"] is None),
        "by_key_type": by_kind,
    }
    want = {"in_a_cache_directory": 842, "with_an_id_file": 45, "without_an_id_file": 797,
            "in_no_cache_directory": 38, "by_key_type": {"sha256": 839, "sha384": 1, "sha512": 2}}
    if not (totals == counted == want) or (len(shapes), len(rows)) != (14, 39):
        problems.append(f"source_totals {totals}; the {len(shapes)} shapes add up to {counted}; {len(rows)} rows")
    if doc["source"]["rows"] != sum(s["rows"] for s in shapes) or doc["source"]["rows"] != 880:
        problems.append("the shapes do not add up to the rows of the source")
    check("layouts: the sample has up to three downloads of each of the 14 shapes, which add up to the 880 recorded",
          problems)

    problems = []
    no_id = [r for r in cached if not r["id_markers_present"]]
    sha384 = [r for r in cached if r["cache_file"].startswith("content_addressable/sha384/")]
    if not no_id or len(sha384) != 1 or sha384[0]["id_markers_present"]:
        problems.append(f"{len(no_id)} entries with no id file, {len(sha384)} under sha384")
    kinds = sorted({(r["key_type"], bool(r["id_markers_present"])) for r in cached})
    if kinds != [("sha256", False), ("sha256", True), ("sha384", False), ("sha512", True)]:
        problems.append(f"digest kinds with and without an id file: {kinds}")
    # No id file is not a shape of old releases alone: registry files and release
    # downloads of the runs on 7.7.2 and later have none either.
    later = [r for r in no_id if not r["run"].endswith("-6.6.0")]
    if {"bcr.bazel.build", "github.com"} - {r["url"].split("/")[2] for r in later}:
        problems.append("no entry without an id file from a registry and from a release host on Bazel 7+")
    # Bazel 6.6.0 leaves none at all, and the same download has one on 7.7.2.
    with_id = {r["cache_file"] for r in cached if r["id_markers_present"] and r["run"] == "skylib-7.7.2"}
    old = [r for r in cached if r["run"].endswith("-6.6.0")]
    if len(old) != 3 or any(r["id_markers_present"] for r in old):
        problems.append(f"{len(old)} cached downloads of the 6.6.0 run, or one has an id file")
    for r in old:
        if r["cache_file"] not in with_id:
            problems.append(f"{r['url']}: the 7.7.2 run does not have this entry with an id file")
    if (len(no_id), len(cached)) != (19, 36):
        problems.append(f"{len(no_id)} of {len(cached)} cached rows have no id file")
    check("layouts: the sample has entries with no id file, one of them under sha384, and three that "
          "Bazel 6.6.0 left without the id file Bazel 7.7.2 wrote", problems)


def main():
    check_tree()
    x4_versions = check_x4()
    check_x2()
    check_x3()
    lockfile_versions = check_lockfile()
    check_layouts()
    check("a byte-real lock for each of the nine lock versions run (3 to 28)",
          [f"lockFileVersion {n}" for n in LOCK_VERSIONS if n not in (x4_versions | lockfile_versions)]
          + [f"lockfile/ alone lacks lockFileVersion {n}" for n in LOCK_VERSIONS if n not in lockfile_versions])
    print(f"{len(failures)} failed" if failures else "all checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
