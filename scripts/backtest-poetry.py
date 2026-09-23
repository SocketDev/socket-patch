#!/usr/bin/env python3
"""Drive the real socket-patch CLI and real Poetry releases through hosted,
vendored and agent mode on native poetry.lock generations.

For every Poetry version the harness bootstraps that exact release with uv,
generates a native lock for a one-dependency project (urllib3 1.26.18, which
has a public free-tier Socket patch), then for each mode:

  hosted    scan --mode hosted   -> poetry install -> installed bytes == patch
  vendored  scan --mode vendored -> poetry install -> installed bytes == patch
  agent     poetry install -> scan --mode agent -> installed bytes == patch

and checks idempotent re-scans, unchanged pyproject, lock-driven installs in a
FRESH clone of the committed state, tampered-hash rejection, what Poetry's own
relock does to the patch source, `poetry check --lock`, `vex`, and `rollback`
restoring every byte.  Extra modes: `agent-oot` (Poetry's default out-of-tree
venv) and `setup`.  Shapes: `direct` (native lock), `populated` (legacy locks
with real hashes filled in, as 2020-era locks have), `crlf`, `pep621` (2.x).

Needs network (PyPI + patch.socket.dev), uv, and no Socket token.
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import traceback
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

VERSIONS = [
    "0.12.17",
    "1.0.10",
    "1.1.15",
    "1.2.2",
    "1.3.2",
    "1.4.2",
    "1.5.1",
    "1.6.1",
    "1.7.1",
    "1.8.5",
    "2.0.1",
    "2.1.4",
    "2.2.1",
    "2.3.4",
    "2.4.3",
]
MODES = ["hosted", "vendored", "agent", "agent-oot", "setup"]
SHAPES = ["direct", "populated", "crlf", "pep621"]

PROJECT = """[tool.poetry]
name = "poetry-patch-fixture"
version = "0.1.0"
description = ""
authors = ["Socket <engineering@socket.dev>"]

[tool.poetry.dependencies]
python = ">=3.8"
urllib3 = "1.26.18"
"""
PROJECT_PEP621 = """[project]
name = "poetry-patch-fixture"
version = "0.1.0"
requires-python = ">=3.8"
dependencies = ["urllib3==1.26.18"]

[tool.poetry]
package-mode = false
"""
ORACLE = """import hashlib,json,pathlib,sys,sysconfig
root=pathlib.Path(sysconfig.get_paths()['purelib'])
out={}
for name in json.loads(sys.argv[1]):
    p=root/name
    if p.is_file():
        d=p.read_bytes(); out[name]=hashlib.sha256(('blob %d\\0'%len(d)).encode()+d).hexdigest()
    else:
        out[name]=None
print(json.dumps(out))
"""
PATCH_UUID = "e828efa5-5c6d-43f3-9909-03f5ac232b98"
PURL_BASE = "pkg:pypi/urllib3@1.26.18"


def vtuple(v):
    return tuple(int(x) for x in v.split("."))


def save(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


DEFAULT_TIMEOUT = int(os.environ.get("BACKTEST_TIMEOUT", "900"))


class Run:
    def __init__(self, cmd, cwd, env, log, timeout=None):
        timeout = timeout or DEFAULT_TIMEOUT
        self.cmd = [str(c) for c in cmd]
        try:
            r = subprocess.run(
                self.cmd,
                cwd=cwd,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
            )
            self.rc, self.out, self.err = r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired as e:
            def text(b):
                return b.decode("utf-8", "replace") if isinstance(b, bytes) else (b or "")
            self.rc, self.out, self.err = 124, text(e.stdout), text(e.stderr) + "\nTIMEOUT after %ss" % timeout
        Path(log).write_text(
            "$ " + " ".join(self.cmd) + f"\n# exit {self.rc}\n--- stdout\n{self.out}\n--- stderr\n{self.err}"
        )

    def ok(self):
        return self.rc == 0

    def json(self):
        i = self.out.find("{")
        if i < 0:
            raise RuntimeError("no JSON in output: " + (self.out + self.err)[-2000:])
        return json.loads(self.out[i:])

    def json_or_empty(self):
        try:
            return self.json()
        except Exception:
            return {}


def require(r, what):
    if not r.ok():
        raise RuntimeError(f"{what} failed (exit {r.rc}):\n{(r.out + r.err)[-4000:]}")
    return r


def base_env():
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("PYTHON", "PIP_", "POETRY_", "SOCKET_", "UV_")) and k != "VIRTUAL_ENV"
    }
    env.update(
        SOCKET_NO_CONFIG="1",
        SOCKET_TELEMETRY_DISABLED="1",
        PIP_CONFIG_FILE=os.devnull,
        PIP_DISABLE_PIP_VERSION_CHECK="1",
        PYTHONDONTWRITEBYTECODE="1",
    )
    return env


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cli", required=True, type=Path)
    ap.add_argument("--cli-revision", required=True)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--versions", nargs="+", default=VERSIONS)
    ap.add_argument("--modes", nargs="+", default=MODES, choices=MODES)
    ap.add_argument("--shapes", nargs="+", default=["direct", "populated", "crlf"], choices=SHAPES)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--render-doc-table", type=Path, metavar="SUMMARY_JSON")
    args = ap.parse_args()
    if args.render_doc_table:
        summary = json.loads(args.render_doc_table.read_text())
        print(render_doc_table(summary))
        print()
        print(render_table(summary))
        return
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=True)
    cli = args.cli.resolve()
    env = base_env()
    provenance = {
        "capturedAt": datetime.now(timezone.utc).isoformat(),
        "cliRevision": args.cli_revision,
        "cliSha256": hashlib.sha256(cli.read_bytes()).hexdigest(),
        "poetryVersions": args.versions,
        "modes": args.modes,
        "shapes": args.shapes,
        "host": os.uname().sysname + " " + os.uname().machine,
    }
    save(root / "provenance.json", provenance)

    # Real hashes of the upstream artifacts, for the `populated` legacy shape.
    with urllib.request.urlopen("https://pypi.org/pypi/urllib3/1.26.18/json", timeout=60) as r:
        pypi = json.load(r)
    upstream_files = [
        {"file": u["filename"], "hash": "sha256:" + u["digests"]["sha256"]}
        for u in pypi["urls"]
        if u["filename"].endswith((".whl", ".tar.gz"))
    ]

    def python_for(version):
        return "3.8.20" if version.startswith(("0.", "1.0.", "1.1.")) else "3.12.13"

    def prepare_tool(version):
        tool = root / "tools" / version
        if not (tool / "bin/poetry").exists():
            require(Run(["uv", "venv", "-q", "--python", python_for(version), tool], root, env, root / f"tool-{version}-venv.log"), "uv venv")
            pkgs = ["poetry==" + version, "pip==24.0", "setuptools==69.5.1"]
            if version == "1.2.2":
                pkgs.append("cleo==1.0.0a5")
            require(Run(["uv", "pip", "install", "-q", "--python", tool / "bin/python", *pkgs], root, env, root / f"tool-{version}-bootstrap.log"), "poetry bootstrap")
        return tool

    log_lock = __import__("threading").Lock()

    def say(*a):
        with log_lock:
            print(*a, flush=True)

    def poetry_env(project, venv=None, cache=None, home=None):
        e = dict(env)
        e["POETRY_VIRTUALENVS_IN_PROJECT"] = "true"
        e["POETRY_CACHE_DIR"] = str(cache or (project / ".poetry-cache"))
        # Poetry <= 1.1 keeps its HTTP cache under ~/Library/Caches/pypoetry
        # regardless of POETRY_CACHE_DIR, behind a single lockfile that wedges
        # every parallel run (and stays wedged after a SIGKILL). Give each case
        # its own HOME so legacy releases never share that lock.
        h = home or (project.parent / "home")
        h.mkdir(parents=True, exist_ok=True)
        e["HOME"] = str(h)
        if venv is not None:
            e["VIRTUAL_ENV"] = str(venv)
        return e

    def native_lock(version, tool, shape):
        """Generate (once) the native lock for `version`/`shape`; return dir."""
        key = "pep621" if shape == "pep621" else "direct"
        original = root / "original" / version / key
        if not (original / "poetry.lock").exists():
            original.mkdir(parents=True, exist_ok=True)
            (original / "pyproject.toml").write_text(PROJECT_PEP621 if key == "pep621" else PROJECT)
            (original / "poetry_patch_fixture").mkdir(exist_ok=True)
            (original / "poetry_patch_fixture/__init__.py").touch()
            require(Run([tool / "bin/poetry", "lock", "-n"], original, poetry_env(original), original / "generation.log"), f"poetry {version} lock")
        return original

    def derive_shape(version, original, shape, dest):
        dest.mkdir(parents=True, exist_ok=True)
        for f in ["pyproject.toml", "poetry.lock"]:
            shutil.copyfile(original / f, dest / f)
        (dest / "poetry_patch_fixture").mkdir(exist_ok=True)
        (dest / "poetry_patch_fixture/__init__.py").touch()
        lock = (dest / "poetry.lock").read_text()
        if shape == "populated":
            if version.startswith("0."):
                hashes = ", ".join(json.dumps(f["hash"].split(":", 1)[1]) for f in upstream_files)
                lock = re.sub(r"(?m)^urllib3 = \[\]$", f"urllib3 = [{hashes}]", lock)
            else:
                entries = ",\n".join(
                    "    {file = %s, hash = %s}" % (json.dumps(f["file"]), json.dumps(f["hash"])) for f in upstream_files
                )
                lock = re.sub(r"(?m)^urllib3 = \[\]$", f"urllib3 = [\n{entries},\n]", lock)
            if "urllib3 = []" in lock:
                raise RuntimeError("populated shape: could not fill hashes")
            (dest / "poetry.lock").write_text(lock)
        if shape == "crlf":
            for f in ["pyproject.toml", "poetry.lock"]:
                p = dest / f
                p.write_bytes(p.read_text().replace("\r\n", "\n").replace("\n", "\r\n").encode())

    def make_venv(tool, venv, cwd, log, packages=()):
        require(Run(["uv", "venv", "-q", "--python", tool / "bin/python", venv], cwd, env, log), "uv venv")
        pkgs = ["pip==24.0", "setuptools==69.5.1", *packages]
        require(Run(["uv", "pip", "install", "-q", "--python", venv / "bin/python", *pkgs], cwd, env, str(log) + ".pip"), "venv bootstrap")

    def oracle(python, names, cwd, log):
        r = Run([python, "-c", ORACLE, json.dumps(names)], cwd, env, log)
        return json.loads(r.out) if r.ok() and r.out.strip() else {}

    def record_hashes(project, mode):
        if mode == "hosted":
            ledger = json.loads((project / ".socket/vendor/redirect-state.json").read_text())
            recs = ledger["records"]
        elif mode == "vendored":
            # Vendored mode never writes `.socket/manifest.json`: the ledger
            # entry embeds the patch record.
            entries = json.loads((project / ".socket/vendor/state.json").read_text())["entries"]
            recs = {k: e["record"] for k, e in entries.items() if e.get("record")}
        else:
            recs = json.loads((project / ".socket/manifest.json").read_text())["patches"]
        rec = next(iter(recs.values()))
        return (
            {n: i["afterHash"] for n, i in rec["files"].items()},
            {n: i["beforeHash"] for n, i in rec["files"].items() if i.get("beforeHash")},
            rec.get("uuid"),
        )

    def poetry_install_cmd(version, poetry):
        cmd = [poetry, "install", "-n"]
        if not version.startswith("0."):
            cmd.append("--no-root")
        return cmd

    def cli_cmd(project, *rest):
        return [cli, *rest, "--cwd", project, "--json", "--yes", "--no-telemetry"]

    def applied_count(mode, envelope):
        if mode == "hosted":
            return envelope.get("redirect", {}).get("redirected", 0)
        if mode == "vendored":
            return envelope.get("vendor", {}).get("summary", {}).get("applied", 0)
        return envelope.get("apply", {}).get("applied", 0)

    def lock_check(version, poetry, project, penv, log):
        """Poetry's own lock consistency check, whichever spelling exists."""
        v = vtuple(version)
        if v >= (1, 6):
            r = Run([poetry, "check", "--lock", "-n"], project, penv, log)
            return {"cmd": "check --lock", "exit": r.rc, "tail": (r.out + r.err)[-400:]}
        if v >= (1, 2):
            r = Run([poetry, "lock", "--check", "-n"], project, penv, log)
            return {"cmd": "lock --check", "exit": r.rc, "tail": (r.out + r.err)[-400:]}
        return {"cmd": None}

    def relock(version, poetry, project, penv, log):
        v = vtuple(version)
        if (1, 1) <= v < (2, 0):
            cmd = [poetry, "lock", "--no-update", "-n"]
        else:
            cmd = [poetry, "lock", "-n"]
        r = Run(cmd, project, penv, log, timeout=600)
        return {"cmd": " ".join(cmd[1:]), "exit": r.rc, "tail": (r.out + r.err)[-400:]}

    def sync_cmd(version, poetry):
        v = vtuple(version)
        if v >= (2, 0):
            return [poetry, "sync", "-n", "--no-root"]
        if v >= (1, 2):
            return [poetry, "install", "-n", "--no-root", "--sync"]
        return None

    def backtest(job):
        version, shape, mode = job
        tool = root / "tools" / version
        poetry = tool / "bin/poetry"
        case = root / "captures" / f"{version}-{shape}-{mode}"
        if case.exists():
            shutil.rmtree(case)
        case.mkdir(parents=True)
        original = native_lock(version, tool, shape)
        pristine_dir = case / "pristine"
        derive_shape(version, original, shape, pristine_dir)
        project = case / "project"
        shutil.copytree(pristine_dir, project)
        pristine_lock = (pristine_dir / "poetry.lock").read_bytes()
        pristine_pyproject = (pristine_dir / "pyproject.toml").read_bytes()
        row = {"poetry": version, "shape": shape, "mode": mode, "checks": {}, "info": {}, "passed": None}
        checks, info = row["checks"], row["info"]
        v = vtuple(version)

        def check(name, value, note=None):
            checks[name] = bool(value)
            if note is not None:
                info[name] = note
            return bool(value)

        venv = project / ".venv"
        python = venv / "bin/python"

        # ------------------------------------------------------------ setup
        if mode == "setup":
            senv = dict(env)
            senv["PATH"] = str(tool / "bin") + os.pathsep + senv.get("PATH", "")
            # `setup` shells out to that Poetry; give it the case's isolated
            # HOME too (Poetry <= 1.1's shared HTTP-cache lock, see poetry_env).
            senv["HOME"] = poetry_env(project)["HOME"]
            r = Run(cli_cmd(project, "setup"), project, senv, case / "setup.log")
            info["setupExit"] = r.rc
            try:
                info["setupEnvelope"] = r.json()
            except Exception:
                info["setupOutput"] = (r.out + r.err)[-1500:]
            info["pyprojectChanged"] = (project / "pyproject.toml").read_bytes() != pristine_pyproject
            info["pyprojectDiff"] = (project / "pyproject.toml").read_text()
            info["lockChanged"] = (project / "poetry.lock").read_bytes() != pristine_lock
            # Can Poetry itself resolve the committed hook dependency?
            rl = Run([poetry, "lock", "-n"] + (["--no-update"] if (1, 1) <= v < (2, 0) else []), project, poetry_env(project), case / "setup-relock.log")
            info["poetryLockAfterSetup"] = {"exit": rl.rc, "tail": (rl.out + rl.err)[-600:]}
            chk = Run(cli_cmd(project, "setup", "--check"), project, senv, case / "setup-check.log")
            info["setupCheckExit"] = chk.rc
            row["passed"] = r.rc == 0 and info["pyprojectChanged"] and rl.rc == 0
            row["expected"] = "informational: setup edits pyproject; poetry must resolve socket-patch[hook]"
            return row

        # -------------------------------------------------------- agent-oot
        if mode == "agent-oot":
            penv = dict(env)
            penv["POETRY_VIRTUALENVS_IN_PROJECT"] = "false"
            penv["POETRY_VIRTUALENVS_PATH"] = str(case / "venvs")
            penv["POETRY_CACHE_DIR"] = str(case / "poetry-cache")
            require(Run(poetry_install_cmd(version, poetry), project, penv, case / "install-upstream.log"), "poetry install (out-of-tree)")
            ep = Run([poetry, "env", "info", "-p"], project, penv, case / "env-info.log")
            oot_venv = Path(ep.out.strip().splitlines()[-1]) if ep.ok() and ep.out.strip() else None
            info["ootVenv"] = str(oot_venv)
            if not oot_venv or not (oot_venv / "bin/python").exists():
                raise RuntimeError("could not locate Poetry's out-of-tree venv: " + ep.out + ep.err)
            # 1. bare scan from the project dir, no VIRTUAL_ENV: does the CLI see the venv?
            # The CLI inherits the user's Poetry configuration (the custom
            # virtualenvs path below is configuration, not an activation) but
            # not VIRTUAL_ENV — that is exactly what `poetry run` would add.
            bare_env = dict(env)
            for key in ("POETRY_VIRTUALENVS_PATH", "POETRY_CACHE_DIR", "POETRY_VIRTUALENVS_IN_PROJECT"):
                bare_env[key] = penv[key]
            r1 = Run(cli_cmd(project, "scan", "--mode", "agent", "--dry-run"), project, bare_env, case / "scan-bare-dryrun.log")
            e1 = r1.json_or_empty()
            paths = [p for p in (e1.get("paths") or [])]
            pkgs = e1.get("packages") or []
            info["bareScan"] = {
                "exit": r1.rc,
                "scannedPackages": e1.get("scannedPackages"),
                "packagesWithPatches": e1.get("packagesWithPatches"),
                "paths": paths[:10],
                "urllib3Found": any("urllib3" in (p.get("purl") or "") for p in pkgs),
                "packageDirs": [pth for p in pkgs for pth in (p.get("paths") or [])][:10],
            }
            # Did the bare dry-run see the package inside Poetry's venv (not
            # merely list it lockfile-only)? A crawler that finds the venv reports
            # urllib3 as installed with a patch to add; one that does not falls
            # through to the global interpreter and reports it not installed.
            sees = any(
                "urllib3" in (p.get("purl") or "") and not p.get("notInstalled")
                for p in pkgs
            ) and e1.get("apply", {}).get("found", 0) >= 1 and not any(
                ev.get("errorCode") == "package_not_installed" for ev in e1.get("apply", {}).get("patches", [])
            )
            check("bareScanSeesPoetryVenv", sees, {"scannedPackages": e1.get("scannedPackages"), "found": e1.get("apply", {}).get("found")})
            # 2. apply for real: BARE when the crawler found the venv (the fixed
            # CLI), else via `poetry run` (Poetry exports VIRTUAL_ENV).
            bare = bool(sees)
            info["applyPath"] = "bare" if bare else "poetry run"
            cmd = cli_cmd(project, "scan", "--mode", "agent") if bare else [poetry, "run", *cli_cmd(project, "scan", "--mode", "agent")]
            r2 = Run(cmd, project, bare_env if bare else penv, case / "scan-apply.log")
            e2 = r2.json_or_empty()
            check("poetryRunScanApplied", applied_count("agent", e2) == 1, {"exit": r2.rc, "applied": applied_count("agent", e2), "path": info["applyPath"]})
            after, before, _ = record_hashes(project, "agent") if (project / ".socket/manifest.json").exists() else ({}, {}, None)
            res = oracle(oot_venv / "bin/python", list(after), project, case / "oracle-1.log")
            check("patchedViaPoetryRun", bool(after) and all(res.get(n) == h for n, h in after.items()), res)
            # 3. a repeat `poetry install` must not revert the in-place patch
            require(Run(poetry_install_cmd(version, poetry), project, penv, case / "install-again.log"), "poetry install again")
            res = oracle(oot_venv / "bin/python", list(after), project, case / "oracle-2.log")
            check("survivesRepeatInstall", bool(after) and all(res.get(n) == h for n, h in after.items()), res)
            sc = sync_cmd(version, poetry)
            if sc:
                rs = Run(sc, project, penv, case / "sync.log")
                res = oracle(oot_venv / "bin/python", list(after), project, case / "oracle-3.log")
                check("survivesSync", rs.ok() and bool(after) and all(res.get(n) == h for n, h in after.items()), {"exit": rs.rc, "oracle": res})
            # 4. rollback the same way the patch was applied (bare when the
            # crawler sees the venv; a bare rollback that cannot see it would
            # prune the manifest while the venv stays patched)
            rb = Run(cli_cmd(project, "rollback") if bare else [poetry, "run", *cli_cmd(project, "rollback")], project, bare_env if bare else penv, case / "rollback.log")
            res = oracle(oot_venv / "bin/python", list(after), project, case / "oracle-4.log")
            check("rollbackRestoresUpstream", rb.ok() and bool(before) and all(res.get(n) == h for n, h in before.items()), {"exit": rb.rc, "oracle": res})
            check("rollbackClearsManifest", not (project / ".socket/manifest.json").exists() or json.loads((project / ".socket/manifest.json").read_text()).get("patches") == {})
            row["passed"] = all(checks[k] for k in checks if k != "bareScanSeesPoetryVenv")
            row["expected"] = "bareScanSeesPoetryVenv is informational (known crawler gap); the rest must pass"
            return row

        # ------------------------------------------------- hosted / vendored / agent
        if mode == "vendored":
            # Fresh-clone scenario first: nothing installed, lock only.
            r0 = Run(cli_cmd(project, "scan", "--mode", "vendored"), project, env, case / "scan-lockonly.log")
            e0 = r0.json_or_empty()
            events = e0.get("vendor", {}).get("events", [])
            info["lockOnlyVendor"] = {
                "exit": r0.rc,
                "applied": applied_count("vendored", e0),
                "codes": sorted({ev.get("errorCode") for ev in events if ev.get("errorCode")}),
            }
            check("lockOnlyVendorApplies", applied_count("vendored", e0) == 1, info["lockOnlyVendor"])
            # reset any partial state
            shutil.rmtree(project / ".socket", ignore_errors=True)
            (project / "poetry.lock").write_bytes(pristine_lock)

        make_venv(tool, venv, project, case / "venv.log", packages=["urllib3==1.26.18"] if mode != "agent" else ())
        penv = poetry_env(project, venv=venv)
        if mode == "agent":
            require(Run(poetry_install_cmd(version, poetry), project, penv, case / "install-upstream.log"), "poetry install (upstream)")

        r = Run(cli_cmd(project, "scan", "--mode", mode), project, env, case / "scan.log")
        info["scanExit"] = r.rc
        try:
            envelope = r.json()
        except Exception as e:
            raise RuntimeError(f"scan produced no JSON: {e}")
        save(case / "cli-output.json", envelope)
        applied = applied_count(mode, envelope)
        info["applied"] = applied
        warnings = envelope.get("redirect", {}).get("warnings", []) if mode == "hosted" else envelope.get("vendor", {}).get("events", [])
        info["warnings"] = warnings[:8]
        lock_after = (project / "poetry.lock").read_bytes()
        check("pyprojectUnchanged", (project / "pyproject.toml").read_bytes() == pristine_pyproject)

        if mode == "hosted" and version.startswith("0."):
            row["expected"] = "refused: Poetry 0.x ignores URL sources"
            check("refusedWithWarning", applied == 0 and any("ignores URL sources" in json.dumps(w) for w in warnings), warnings[:3])
            check("lockUnchanged", lock_after == pristine_lock)
            check("noLedger", not (project / ".socket/vendor/redirect-state.json").exists())
            row["passed"] = all(checks.values())
            return row

        check("appliedExactlyOne", applied == 1, {"applied": applied, "status": envelope.get("status"), "warnings": warnings[:4]})
        if not checks["appliedExactlyOne"]:
            row["passed"] = False
            return row
        if mode == "agent":
            check("lockUnchanged", lock_after == pristine_lock)
        else:
            check("lockRewritten", lock_after != pristine_lock)
            if shape == "crlf":
                check("crlfPreserved", b"\n" not in lock_after.replace(b"\r\n", b""))
        after, before, uuid = record_hashes(project, mode)
        info["uuid"] = uuid
        check("recordHasFiles", bool(after))
        if mode == "vendored":
            wheel_dir = project / ".socket/vendor/pypi" / (uuid or "")
            check("vendoredWheelPresent", wheel_dir.is_dir() and any(wheel_dir.glob("*.whl")))
            check("lockHasFileSource", b'type = "file"' in lock_after)
        if mode == "hosted":
            check("lockHasUrlSource", b'type = "url"' in lock_after and b"patch.socket.dev" in lock_after)

        # idempotent re-scan
        r2 = Run(cli_cmd(project, "scan", "--mode", mode), project, env, case / "rescan.log")
        e2 = r2.json_or_empty()
        check("rescanIdempotent", r2.ok() and (project / "poetry.lock").read_bytes() == lock_after and (project / "pyproject.toml").read_bytes() == pristine_pyproject, {"exit": r2.rc, "applied": applied_count(mode, e2), "status": e2.get("status")})

        if mode == "agent":
            res = oracle(python, list(after), project, case / "oracle-1.log")
            check("installedBytesPatched", all(res.get(n) == h for n, h in after.items()), res)
            # repeat install must not revert; sync too
            ri = Run(poetry_install_cmd(version, poetry), project, penv, case / "install-again.log")
            res = oracle(python, list(after), project, case / "oracle-2.log")
            check("survivesRepeatInstall", ri.ok() and all(res.get(n) == h for n, h in after.items()), {"exit": ri.rc, "oracle": res})
            sc = sync_cmd(version, poetry)
            if sc:
                rs = Run(sc, project, penv, case / "sync.log")
                res = oracle(python, list(after), project, case / "oracle-3.log")
                check("survivesSync", rs.ok() and all(res.get(n) == h for n, h in after.items()), {"exit": rs.rc, "oracle": res})
        else:
            # Warm venv: upstream urllib3 is already installed. Does the
            # redirected lock make Poetry replace it? (Poetry <= 1.1 compares
            # name+version only and leaves the vulnerable copy in place.)
            warm = Run(poetry_install_cmd(version, poetry), project, penv, case / "install-warm.log")
            wres = oracle(python, list(after), project, case / "oracle-warm.log")
            info["warmInstall"] = {"exit": warm.rc, "patched": bool(after) and all(wres.get(n) == h for n, h in after.items()), "tail": (warm.out + warm.err)[-300:]}
            check("warmInstallReplacesUpstream", warm.ok() and info["warmInstall"]["patched"], info["warmInstall"])
            # Lock-driven install into the (now emptied) venv.
            require(Run(["uv", "pip", "uninstall", "-q", "--python", python, "urllib3"], project, env, case / "uninstall.log"), "uninstall")
            inst = Run(poetry_install_cmd(version, poetry), project, penv, case / "install.log")
            res = oracle(python, list(after), project, case / "oracle-1.log")
            check("poetryInstallExit0", inst.ok(), (inst.out + inst.err)[-600:])
            check("installedBytesPatched", all(res.get(n) == h for n, h in after.items()), res)
            check("lockUnchangedByInstall", (project / "poetry.lock").read_bytes() == lock_after)
            info["lockCheck"] = lock_check(version, poetry, project, penv, case / "lock-check.log")
            # Fresh clone of the committed state (no venv, no caches)
            fresh = case / "fresh"
            shutil.copytree(project, fresh, ignore=shutil.ignore_patterns(".venv", ".poetry-cache", "__pycache__"))
            make_venv(tool, fresh / ".venv", fresh, case / "fresh-venv.log")
            fenv = poetry_env(fresh, venv=fresh / ".venv", cache=fresh / ".poetry-cache")
            finst = Run(poetry_install_cmd(version, poetry), fresh, fenv, case / "fresh-install.log")
            fres = oracle(fresh / ".venv/bin/python", list(after), fresh, case / "fresh-oracle.log")
            check("freshCloneInstallsPatch", finst.ok() and all(fres.get(n) == h for n, h in after.items()), {"exit": finst.rc, "oracle": fres, "tail": (finst.out + finst.err)[-500:]})
            # vex over the installed, redirected/vendored tree
            vx = Run([cli, "vex", "--cwd", project, "--no-telemetry"], project, env, case / "vex.log")
            try:
                vdoc = json.loads(vx.out[vx.out.find("{"):]) if vx.ok() else {}
                info["vex"] = {"exit": vx.rc, "statements": len(vdoc.get("statements", []))}
            except Exception:
                info["vex"] = {"exit": vx.rc, "tail": (vx.out + vx.err)[-400:]}
            # Tamper: corrupt the recorded hash, install must fail where the installer verifies.
            if shape != "crlf":
                require(Run(["uv", "pip", "uninstall", "-q", "--python", python, "urllib3"], project, env, case / "tamper-uninstall.log"), "uninstall")
                corrupt = re.sub(rb"sha256[:=][a-f0-9]{64}", lambda m: m[0][:7] + b"0" * 64, lock_after)
                if version.startswith("0."):
                    corrupt = re.sub(rb'"[a-f0-9]{64}"', b'"' + b"0" * 64 + b'"', corrupt)
                (project / "poetry.lock").write_bytes(corrupt)
                tam = Run(poetry_install_cmd(version, poetry), project, poetry_env(project, venv=venv, cache=case / "tamper-cache"), case / "tamper-install.log")
                tres = oracle(python, list(after), project, case / "tamper-oracle.log")
                (project / "poetry.lock").write_bytes(lock_after)
                expects_reject = mode == "hosted" or v >= (1, 4)
                info["tamper"] = {"installExit": tam.rc, "installedPatchedAnyway": all(tres.get(n) == h for n, h in after.items()), "expectsReject": expects_reject}
                check("tamperBehaviorAsDocumented", (tam.rc != 0) == expects_reject, info["tamper"])
                # reinstall the good state for the remaining steps
                Run(["uv", "pip", "uninstall", "-q", "--python", python, "urllib3"], project, env, case / "tamper-uninstall2.log")
                require(Run(poetry_install_cmd(version, poetry), project, penv, case / "reinstall.log"), "reinstall")
            # Relock: does Poetry's own relock keep the patch source? (informational)
            rl = relock(version, poetry, project, penv, case / "relock.log")
            relocked = (project / "poetry.lock").read_bytes()
            marker = b"patch.socket.dev" if mode == "hosted" else b".socket/vendor/pypi"
            rl.update(lockBytesUnchanged=relocked == lock_after, patchSourceKept=marker in relocked, pyprojectUnchanged=(project / "pyproject.toml").read_bytes() == pristine_pyproject)
            info["relock"] = rl
            if rl["patchSourceKept"] and not rl["lockBytesUnchanged"]:
                # Poetry re-laid the unit around the kept source (1.1/1.2 drop
                # the inserted `files` line). The documented recovery is a
                # re-scan; it must restore the entry and leave a ledger that
                # the final rollback below can still invert to pristine bytes.
                rs = Run(cli_cmd(project, "scan", "--mode", mode), project, env, case / "rescan-after-relock.log")
                ers = rs.json_or_empty()
                check("rescanAfterRelockApplies", rs.ok() and applied_count(mode, ers) >= 0 and marker in (project / "poetry.lock").read_bytes(), {"exit": rs.rc, "applied": applied_count(mode, ers)})
                info["rescanAfterRelock"] = {"exit": rs.rc, "applied": applied_count(mode, ers), "lockChanged": (project / "poetry.lock").read_bytes() != relocked}
            else:
                (project / "poetry.lock").write_bytes(lock_after)

        # Rollback restores every byte and clears the ledgers.
        rb = Run(cli_cmd(project, "rollback"), project, env, case / "rollback.log")
        erb = rb.json_or_empty()
        check("rollbackExit0", rb.ok(), (rb.out + rb.err)[-600:] if not rb.ok() else None)
        check("rollbackRestoresLockBytes", (project / "poetry.lock").read_bytes() == pristine_lock)
        check("rollbackKeepsPyproject", (project / "pyproject.toml").read_bytes() == pristine_pyproject)
        if mode == "hosted":
            check("rollbackClearsRedirectLedger", not (project / ".socket/vendor/redirect-state.json").exists() or not json.loads((project / ".socket/vendor/redirect-state.json").read_text()).get("records"))
        if mode == "vendored":
            check("rollbackRemovesVendoredWheel", not (project / ".socket/vendor/pypi" / (uuid or "x")).exists())
        if mode == "agent":
            res = oracle(python, list(after), project, case / "oracle-rollback.log")
            check("rollbackRestoresUpstreamBytes", bool(before) and all(res.get(n) == h for n, h in before.items()), res)
        mf = project / ".socket/manifest.json"
        if mode == "agent":
            check("rollbackClearsManifest", not mf.exists() or json.loads(mf.read_text()).get("patches") in ({}, None))
        else:
            # Hosted and vendored runs are manifest-free (v5.0): nothing may
            # have been written to `.socket/manifest.json` at any point.
            check("noManifestWritten", not mf.exists())
        info["rollbackEnvelope"] = {k: erb.get(k) for k in ("status", "rolledBack", "failed", "hosted", "vendoredReverted", "manifest") if k in erb}
        informational = {"lockOnlyVendorApplies", "warmInstallReplacesUpstream"}
        row["passed"] = all(val for k, val in checks.items() if k not in informational)
        return row

    prepared = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futs = {pool.submit(prepare_tool, v): v for v in args.versions}
        for f in concurrent.futures.as_completed(futs):
            v = futs[f]
            try:
                prepared[v] = f.result()
                say("bootstrapped poetry", v)
            except Exception as e:
                say("BOOTSTRAP FAILED", v, str(e)[-800:])

    def wanted(version, shape, mode):
        v = vtuple(version)
        if version not in prepared:
            return False
        if shape == "populated" and not version.startswith(("0.", "1.0.", "1.1.")):
            return False
        if shape == "pep621" and v < (2, 0):
            return False
        if shape in ("crlf", "pep621") and mode in ("agent", "agent-oot", "setup"):
            return False
        if shape == "populated" and mode in ("agent", "agent-oot", "setup"):
            return False
        if mode == "agent-oot" and version.startswith("0."):
            return False
        if mode == "setup" and version not in ("1.1.15", "1.8.5", "2.4.3"):
            return False
        return True

    jobs = [(v, s, m) for v in args.versions for s in args.shapes for m in args.modes if wanted(v, s, m)]
    say(f"{len(jobs)} cases")
    results, errors = [], []
    # Generate native locks serially per version first (the pool would race on the shared dir).
    for v in args.versions:
        if v in prepared:
            for shape in {("pep621" if s == "pep621" else "direct") for s in args.shapes if any(wanted(v, s, m) for m in args.modes)}:
                try:
                    native_lock(v, prepared[v], shape)
                except Exception as e:
                    say("LOCK GENERATION FAILED", v, shape, str(e)[-800:])
                    errors.append({"poetry": v, "shape": shape, "error": "lock generation: " + str(e)[-1500:]})
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        pending = {pool.submit(backtest, job): job for job in jobs}
        for fut in concurrent.futures.as_completed(pending):
            job = pending[fut]
            try:
                row = fut.result()
                results.append(row)
                failed = [k for k, ok in row["checks"].items() if not ok]
                say(*job, "PASS" if row["passed"] else "FAIL", ",".join(failed))
            except Exception as e:
                errors.append({"poetry": job[0], "shape": job[1], "mode": job[2], "error": str(e)[-3000:], "trace": traceback.format_exc()[-1500:]})
                say(*job, "ERROR", str(e)[-300:].replace("\n", " "))
            save(root / "summary.json", {"provenance": provenance, "results": sorted(results, key=lambda r: (vtuple(r["poetry"]), r["shape"], r["mode"])), "errors": errors})
    summary = json.loads((root / "summary.json").read_text()) if (root / "summary.json").exists() else {"provenance": provenance, "results": results, "errors": errors}
    (root / "summary.md").write_text(render_table(summary))
    say(render_table(summary))
    if errors or any(not r["passed"] for r in results):
        sys.exit(1)


def render_doc_table(summary):
    """Per-version compatibility table for docs/testing/poetry-compatibility.md."""
    rows = summary["results"]
    by = {}
    for r in rows:
        by.setdefault(r["poetry"], []).append(r)
    lines = [
        "| Poetry | hosted | vendored | agent (in-project venv) | agent (`poetry run`, out-of-tree venv) | tamper rejected (hosted / vendored) | warm venv re-installed (hosted / vendored) | relock keeps patch (hosted / vendored) | lock-only vendored |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]

    def cell(cases):
        if not cases:
            return "n/a"
        ok = sum(1 for c in cases if c["passed"])
        shapes = ",".join(sorted({c["shape"] for c in cases}))
        return ("pass" if ok == len(cases) else f"{ok}/{len(cases)}") + f" ({shapes})"

    def flag(cases, key, sub=None):
        vals = set()
        for c in cases:
            i = c.get("info", {}).get(key)
            if isinstance(i, dict):
                vals.add(i.get(sub))
        vals.discard(None)
        return "/".join(sorted(str(v).lower() for v in vals)) or "n/a"

    for version in sorted(by, key=vtuple):
        cs = by[version]
        m = lambda mode: [c for c in cs if c["mode"] == mode]
        hosted, vendored = m("hosted"), m("vendored")
        refused = any(c.get("expected", "").startswith("refused") for c in hosted)
        hosted_cell = "refused (0.x ignores URL sources)" if refused else cell(hosted)
        direct_h = [c for c in hosted if c["shape"] == "direct" and "tamper" in c["info"]]
        direct_v = [c for c in vendored if c["shape"] == "direct" and "tamper" in c["info"]]
        tamper = f"{'yes' if any(c['info']['tamper']['installExit'] != 0 for c in direct_h) else ('n/a' if not direct_h else 'no')} / {'yes' if any(c['info']['tamper']['installExit'] != 0 for c in direct_v) else ('n/a' if not direct_v else 'no')}"
        relock = f"{flag([c for c in hosted if c['shape']=='direct'], 'relock', 'patchSourceKept')} / {flag([c for c in vendored if c['shape']=='direct'], 'relock', 'patchSourceKept')}"
        warm = f"{flag([c for c in hosted if c['shape']=='direct'], 'warmInstall', 'patched')} / {flag([c for c in vendored if c['shape']=='direct'], 'warmInstall', 'patched')}"
        # Per shape: the unpopulated legacy fixtures (`urllib3 = []`) name no
        # wheel hash, so they stay refused while the populated ones vendor.
        per_shape = {}
        for c in vendored:
            lo = c.get("info", {}).get("lockOnlyVendor")
            if lo is not None:
                per_shape[c["shape"]] = "yes" if lo.get("applied") == 1 else "refused"
        if not per_shape:
            lockonly = "n/a"
        elif len(set(per_shape.values())) == 1:
            lockonly = next(iter(per_shape.values()))
        else:
            lockonly = ", ".join(f"{v} ({k})" for k, v in sorted(per_shape.items()))
        lines.append(
            f"| {version} | {hosted_cell} | {cell(vendored)} | {cell(m('agent'))} | {cell(m('agent-oot'))} | {tamper} | {warm} | {relock} | {lockonly} |"
        )
    return "\n".join(lines)


def render_table(summary):
    rows = summary["results"]
    lines = ["| Poetry | shape | mode | passed | failed checks | notes |", "| --- | --- | --- | --- | --- | --- |"]
    for r in sorted(rows, key=lambda r: (vtuple(r["poetry"]), r["shape"], r["mode"])):
        failed = ", ".join(k for k, ok in r["checks"].items() if not ok)
        notes = []
        info = r.get("info", {})
        if "relock" in info:
            notes.append(f"relock({info['relock'].get('cmd')}) exit {info['relock'].get('exit')} keeps patch={info['relock'].get('patchSourceKept')}")
        if "lockCheck" in info and info["lockCheck"].get("cmd"):
            notes.append(f"{info['lockCheck']['cmd']} exit {info['lockCheck']['exit']}")
        if "tamper" in info:
            notes.append(f"tamper install exit {info['tamper']['installExit']} (expects reject={info['tamper']['expectsReject']})")
        if "lockOnlyVendor" in info:
            notes.append(f"lock-only vendor applied={info['lockOnlyVendor']['applied']} {info['lockOnlyVendor']['codes']}")
        if "bareScan" in info:
            notes.append(f"bare scan sees venv={r['checks'].get('bareScanSeesPoetryVenv')}")
        if "vex" in info:
            notes.append(f"vex exit {info['vex'].get('exit')} stmts={info['vex'].get('statements')}")
        if "poetryLockAfterSetup" in info:
            notes.append(f"poetry lock after setup exit {info['poetryLockAfterSetup']['exit']}")
        lines.append(f"| {r['poetry']} | {r['shape']} | {r['mode']} | {'PASS' if r['passed'] else 'FAIL'} | {failed} | {'; '.join(notes)} |")
    for e in summary.get("errors", []):
        lines.append(f"| {e.get('poetry')} | {e.get('shape')} | {e.get('mode')} | ERROR | {e['error'][-160:].replace(chr(10), ' ')} | |")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
