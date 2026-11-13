#!/usr/bin/env python3
"""Real-Bazel driver for `ws-shapes.json`: WORKSPACE shapes beyond the 20 of probe S6.

    ws_shapes.py run <s6-fixture> <bazel> <out-dir> <bazel-version> [flag...]
    ws_shapes.py merge <cases.json>... > ws-shapes.json

`run` copies <s6-fixture> (the directory `versions-hybrid/fixtures/ws-order` of the
Bazel-support campaign's probes: three archives of one file `marker.txt`, and a BUILD file
whose `//:show` copies `@dep//:marker.txt`) to <out-dir>/runs/<version and flags>, and for
each case writes the WORKSPACE, builds `//:show` with <bazel> (a bazelisk-style launcher
that reads USE_BAZEL_VERSION) and records the marker the build copied, or that it failed.
With WS_SHAPES_TOUCH_MODULE set it creates an empty MODULE.bazel first, for a run with
Bzlmod on. It writes <out-dir>/cases-<version and flags>.json.

`merge` joins the files of several runs: the cases must have the same files in each.
Nothing here is imported by a test; the tests read `ws-shapes.json`.
"""
import hashlib, json, os, re, shutil, subprocess, sys

HTTP = 'load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")\n'
UTILS = 'load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")\n'
NOOP = 'load("//:noop.bzl", "noop")\n'
RULE = 'load("//:repo.bzl", "marker_repo")\n'
OWN = 'load("@ws_shapes//:deps_plain.bzl", own_deps = "dep_deps")\n'
HDR = 'workspace(name = "ws_shapes")\n\n'
ELSEWHERE = 'local_repository(\n    name = "ws_shapes",\n    path = "elsewhere",\n)\n\n'

REPO_BZL = '''def _impl(ctx):
    ctx.file("marker.txt", ctx.attr.tag + "\\n")
    ctx.file("BUILD.bazel", 'exports_files(["marker.txt"])\\n')

marker_repo = repository_rule(
    implementation = _impl,
    attrs = {"tag": attr.string()},
)
'''


def build(fixture, run_dir):
    """The macro files and the cases of a workspace at `run_dir`."""
    def sha(t):
        return hashlib.sha256(open(f"{fixture}/archives/dep-{t}.tar.gz", "rb").read()).hexdigest()

    def attrs(t, name="dep", indent="    "):
        return (f'{indent}name = "{name}",\n'
                f'{indent}urls = ["file://{run_dir}/archives/dep-{t}.tar.gz"],\n'
                f'{indent}sha256 = "{sha(t)}",\n'
                f'{indent}strip_prefix = "dep-{t}",\n')

    def lit(t, name="dep"):
        return f"http_archive(\n{attrs(t, name)})\n"

    def plain(t):
        return HTTP + "\ndef dep_deps():\n    http_archive(\n" + attrs(t, indent="        ") + "    )\n"

    rule = 'marker_repo(name = "dep", tag = "rule")\n'
    macros = {
        "noop.bzl": "def noop():\n    pass\n",
        "deps_plain.bzl": plain("v1"),
        "repo.bzl": REPO_BZL,
        "outer.bzl": 'load("//:deps_plain.bzl", "dep_deps")\n\ndef outer():\n    dep_deps()\n',
        "inner_rule.bzl": REPO_BZL.replace("marker_repo", "_marker_repo")
        + '\ndef own_deps():\n    _marker_repo(name = "dep", tag = "inner")\n',
        # Another repository, whose macro defines `dep` as v2: what `@ws_shapes//`
        # reaches where the name is not the main repository's.
        "elsewhere/WORKSPACE": "",
        "elsewhere/BUILD.bazel": "",
        "elsewhere/deps_plain.bzl": plain("v2"),
    }
    # (id, description, the whole WORKSPACE)
    cases = [
        # 1: one symbol, loaded twice from one label
        ("s1a", "http_archive loaded twice: literal(v1) after the first load, another repository after the second",
         HDR + HTTP + "\n" + lit("v1") + "\n" + NOOP + "\nnoop()\n\n" + HTTP + "\n" + lit("v2", "other")),
        ("s1b", "http_archive loaded twice: the only literal(v2) after the second load",
         HDR + HTTP + NOOP + "\nnoop()\n\n" + HTTP + "\n" + lit("v2")),
        ("s1c", "http_archive loaded twice: literal(v1); the second load; literal(v2)",
         HDR + HTTP + "\n" + lit("v1") + "\n" + HTTP + "\n" + lit("v2")),
        ("s1d", "http_archive loaded twice by two loads of one chunk: literal(v1); literal(v2)",
         HDR + HTTP + HTTP + "\n" + lit("v1") + "\n" + lit("v2")),
        # 2: a repository rule of the main repository
        ("s2a", "own rule(dep) only", HDR + RULE + "\n" + rule),
        ("s2b", "literal(v1); own rule(dep) in one chunk", HDR + HTTP + RULE + "\n" + lit("v1") + "\n" + rule),
        ("s2c", "own rule(dep); literal(v2) in one chunk", HDR + HTTP + RULE + "\n" + rule + "\n" + lit("v2")),
        ("s2d", "literal(v1); own rule(other) in one chunk",
         HDR + HTTP + RULE + "\n" + lit("v1") + '\nmarker_repo(name = "other", tag = "rule")\n'),
        ("s2e", "own rule(dep); load; literal(v2) (two chunks)",
         HDR + HTTP + RULE + "\n" + rule + "\n" + NOOP + "\n" + lit("v2")),
        ("s2f", "literal(v1); maybe(own rule, dep) in one chunk",
         HDR + HTTP + UTILS + RULE + "\n" + lit("v1") + '\nmaybe(marker_repo, name = "dep", tag = "rule")\n'),
        ("s2g", "maybe(own rule, dep) only", HDR + UTILS + RULE + '\nmaybe(marker_repo, name = "dep", tag = "rule")\n'),
        ("s2h", "a macro that calls a repository rule of its own file",
         HDR + 'load("//:inner_rule.bzl", "own_deps")\n\nown_deps()\n'),
        # 3: a load through the workspace's own name; a macro called by a macro
        ("s3a", "workspace(name); load @<name>//:deps_plain.bzl; macro(v1)", HDR + OWN + "\nown_deps()\n"),
        ("s3b", "load @<name>//:deps_plain.bzl in the chunk of workspace(name)", OWN + "\n" + HDR + "own_deps()\n"),
        ("s3c", "workspace(name); local_repository(name) in its chunk; load @<name>//:deps_plain.bzl; macro",
         HDR + ELSEWHERE + OWN + "\nown_deps()\n"),
        ("s3d", "local_repository(name) and no workspace(name); load @<name>//:deps_plain.bzl; macro(v2)",
         ELSEWHERE + OWN + "\nown_deps()\n"),
        ("s3e", "a macro that calls a macro(v1)", HDR + 'load("//:outer.bzl", "outer")\n\nouter()\n'),
        ("s3f", "literal(v2); a macro that calls a macro(v1) in one chunk",
         HDR + HTTP + 'load("//:outer.bzl", "outer")\n\n' + lit("v2") + "\nouter()\n"),
    ]
    return macros, cases


NOISE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def run(fixture, bazel, out_dir, version, flags):
    label = " ".join([version, *flags])
    slug = re.sub(r"[^A-Za-z0-9.]+", "_", label)
    run_dir = os.path.join(os.path.abspath(out_dir), "runs", slug)
    shutil.rmtree(run_dir, ignore_errors=True)
    shutil.copytree(fixture, run_dir)
    os.chdir(run_dir)
    macros, cases = build(os.path.abspath(fixture), run_dir)
    for rel, text in macros.items():
        os.makedirs(os.path.dirname(rel) or ".", exist_ok=True)
        open(rel, "w").write(text)
    if os.environ.get("WS_SHAPES_TOUCH_MODULE"):
        open("MODULE.bazel", "a").close()
    env = dict(os.environ, USE_BAZEL_VERSION=version)

    def call(*args):
        done = subprocess.run([bazel, "--nohome_rc", "--nosystem_rc", *args, *flags],
                              capture_output=True, text=True, env=env)
        return done.returncode, NOISE.sub("", done.stdout + done.stderr).splitlines()

    report = {}
    for cid, description, text in cases:
        open("WORKSPACE", "w").write(text)
        if os.path.exists("bazel-bin/out.txt"):
            os.remove("bazel-bin/out.txt")
        code, lines = call("build", "//:show")
        built = open("bazel-bin/out.txt").read().strip() if os.path.exists("bazel-bin/out.txt") else None
        errors = [line.replace(run_dir, "/WS") for line in lines if line.startswith("ERROR")][:3]
        print(f"{cid} | {description} | {built or f'build failed, exit {code}'}")
        files = {"WORKSPACE": text, **macros}
        report[cid] = {
            "description": description,
            "files": {rel: body.replace(run_dir, "/WS") for rel, body in files.items()},
            "built": built,
            "errors": [] if built else errors,
        }
    call("shutdown")
    path = os.path.join(os.path.abspath(out_dir), f"cases-{slug}.json")
    json.dump({"run": label, "cases": report}, open(path, "w"), indent=1, sort_keys=True)
    print("wrote", path)


def merge(paths):
    cells = {}
    for path in paths:
        one = json.load(open(path))
        for cid, case in one["cases"].items():
            cell = cells.setdefault(cid, {"description": case["description"], "files": case["files"], "built": {}})
            assert cell["files"] == case["files"], (path, cid)
            cell["built"][one["run"]] = case["built"]
    json.dump(cells, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    if sys.argv[1] == "run":
        run(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6:])
    elif sys.argv[1] == "merge":
        merge(sys.argv[2:])
    else:
        sys.exit(__doc__)
