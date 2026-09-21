#!/usr/bin/env python3
"""Drive the real socket-patch CLI and real Pipenv releases through hosted,
vendored and agent mode on native Pipfile.lock generations.

For the last stable release of every published Pipenv major the harness
bootstraps that exact release (uv venv for 2018+, a `python:3.6.15-slim`
Docker venv for the pre-2018 majors that no longer run on modern Pythons),
generates a native lock for a one-dependency project (urllib3 1.26.18, which
has a public free-tier Socket patch), then for each mode:

  hosted     scan --mode hosted   -> pipenv install -> installed bytes == patch
  vendored   scan --mode vendored -> pipenv install -> installed bytes == patch
  agent      pipenv install -> scan --mode agent -> installed bytes == patch
  agent-oot  same as agent, but with Pipenv's DEFAULT out-of-tree virtualenv
             (WORKON_HOME) instead of an in-project .venv

and checks --dry-run parity, idempotent re-scans, an untouched Pipfile, the
lock-driven install of a FRESH clone of the committed state, whether a WARM
venv (upstream urllib3 already installed) gets the patched wheel, tampered
hashes, `pipenv verify`, what `pipenv lock` does to the patched entry, `vex`,
and `rollback` restoring every byte.  Pre-2018 releases are expected to be
REFUSED (old lock spec for 0–6, vendored for 7–11) without touching the lock.

Shapes mirror the depscan capture harness: direct, dev, category (2022+),
marker, marker-excluded, extras, transitive, crlf.  Invocations vary how the
CLI is pointed at the project: in-dir (cwd = project, no --cwd), cwd-flag
(run from the output root with --cwd), subdir (project nested two levels down,
--cwd relative), symlink (cwd = a symlink to the project).

Needs network (PyPI + patch.socket.dev), uv, Docker (pre-2018 majors only) and
no Socket token.

  scripts/backtest-pipenv.py --socket-patch target/debug/socket-patch \
      --socket-patch-revision $(git rev-parse --short HEAD) --output /tmp/pipenv-compat
  scripts/backtest-pipenv.py --render-doc-table /tmp/pipenv-compat/summary.json
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import traceback
import uuid as uuid_mod
from datetime import datetime, timezone
from pathlib import Path

VERSIONS = [
    "0.2.8",
    "3.6.2",
    "4.1.4",
    "5.4.2",
    "6.2.9",
    "7.9.10",
    "8.3.2",
    "9.1.0",
    "10.1.2",
    "11.10.4",
    "2018.11.26",
    "2020.11.15",
    "2021.11.23",
    "2022.12.19",
    "2023.12.1",
    "2024.4.1",
    "2025.1.3",
    "2026.8.0",
]
MODES = ["hosted", "vendored", "agent", "agent-oot"]
SHAPES = ["direct", "dev", "category", "marker", "marker-excluded", "extras", "transitive", "crlf"]
INVOCATIONS = ["in-dir", "cwd-flag", "subdir", "symlink"]
LEGACY_IMAGE = "python:3.6.15-slim"

PROJECT = """[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
urllib3 = "==1.26.18"

[dev-packages]
"""
# Pins for the transitive shape (urllib3 reached through requests).
TRANSITIVE_MODERN = {
    "requests": "2.31.0",
    "charset-normalizer": "3.3.2",
    "idna": "3.6",
    "certifi": "2024.2.2",
    "urllib3": "1.26.18",
}
TRANSITIVE_LEGACY = {
    "requests": "2.27.1",
    "charset-normalizer": "2.0.12",
    "idna": "3.6",
    "certifi": "2024.2.2",
    "urllib3": "1.26.18",
}
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
ABSENT = "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('urllib3') is None else 1)"
PATCH_UUID = "e828efa5-5c6d-43f3-9909-03f5ac232b98"
PURL_BASE = "pkg:pypi/urllib3@1.26.18"

LEGACY_TOOL_PACKAGES = [
    "pip==9.0.3",
    "pip-tools==1.11.0",
    "setuptools==44.1.1",
    "wheel==0.37.1",
    "virtualenv==16.7.12",
    "click==6.7",
    "requests==2.27.1",
    "pexpect==4.2.1",
    "delegator.py==0.0.14",
]
LEGACY_VENV_PACKAGES = ["pip==9.0.3", "setuptools==44.1.1", "wheel==0.37.1"]


def major_of(version):
    return int(version.split(".")[0])


def vtuple(v):
    return tuple(int(x) for x in v.split("."))


def is_legacy(version):
    return major_of(version) < 2018


def save(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


DEFAULT_TIMEOUT = int(os.environ.get("BACKTEST_TIMEOUT", "900"))


class Run:
    """Run a command in its own process group, capture output, write a log.

    A timeout kills the whole group (Docker clients, pip subprocesses, …).
    """

    def __init__(self, cmd, cwd, env, log, timeout=None, container=None):
        timeout = timeout or DEFAULT_TIMEOUT
        self.cmd = [str(c) for c in cmd]
        try:
            with subprocess.Popen(
                self.cmd,
                cwd=str(cwd),
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            ) as p:
                try:
                    self.out, self.err = p.communicate(timeout=timeout)
                    self.rc = p.returncode
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(p.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    out, err = p.communicate()
                    self.rc, self.out, self.err = 124, out or "", (err or "") + f"\nTIMEOUT after {timeout}s"
        except OSError as e:
            self.rc, self.out, self.err = 127, "", str(e)
        finally:
            if container:
                subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
        Path(log).write_text(
            "$ " + " ".join(shlex.quote(c) for c in self.cmd) + f"\n# cwd {cwd}\n# exit {self.rc}\n--- stdout\n{self.out}\n--- stderr\n{self.err}"
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

    def tail(self, n=400):
        return (self.out + self.err)[-n:]


def urllib3_entries(lock_bytes):
    """Every category's urllib3 entry of a Pipfile.lock, parsed, for a
    semantic (key-order- and whitespace-insensitive) comparison."""
    data = json.loads(lock_bytes.decode("utf-8-sig"))
    return {cat: entries["urllib3"] for cat, entries in data.items() if cat != "_meta" and isinstance(entries, dict) and "urllib3" in entries}


def require(r, what):
    if not r.ok():
        raise RuntimeError(f"{what} failed (exit {r.rc}):\n{(r.out + r.err)[-4000:]}")
    return r


def base_env():
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("PYTHON", "PIP_", "PIPENV_", "SOCKET_", "UV_", "WORKON_HOME")) and k != "VIRTUAL_ENV"
    }
    env.update(
        SOCKET_NO_CONFIG="1",
        SOCKET_NO_UPDATE_CHECK="1",
        SOCKET_TELEMETRY_DISABLED="1",
        PIP_CONFIG_FILE=os.devnull,
        PIP_DISABLE_PIP_VERSION_CHECK="1",
        PIPENV_YES="1",
        PIPENV_NOSPIN="1",
        PIPENV_IGNORE_VIRTUALENVS="1",
        PYTHONDONTWRITEBYTECODE="1",
    )
    return env


def pipenv_shim_dir(root, version, tool):
    """Expose only pipenv on PATH, without the tool venv's Python.

    Different shape workers share this directory. Create the link atomically
    and accept EEXIST only when another worker created the same shim.
    """
    if is_legacy(version):
        return root / "legacy-bin" / version
    directory = root / "pipenv-bin" / version
    directory.mkdir(parents=True, exist_ok=True)
    link = directory / "pipenv"
    target = tool / "bin/pipenv"
    try:
        link.symlink_to(target)
    except FileExistsError:
        if not link.is_symlink() or os.readlink(link) != str(target):
            raise
    return directory


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--socket-patch", type=Path, help="socket-patch CLI binary")
    ap.add_argument("--socket-patch-revision", help="git revision the binary was built from (recorded)")
    ap.add_argument("--output", type=Path)
    ap.add_argument("--tools-root", type=Path, help="where Pipenv releases are (or get) bootstrapped; default <output>/tools-root")
    ap.add_argument("--versions", nargs="+", default=VERSIONS)
    ap.add_argument("--modes", nargs="+", default=MODES, choices=MODES)
    ap.add_argument("--shapes", nargs="+", default=["direct"], choices=SHAPES)
    ap.add_argument("--invocations", default="in-dir", help="comma-separated subset of " + ",".join(INVOCATIONS) + " (direct shape only)")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--render-doc-table", type=Path, metavar="SUMMARY_JSON")
    args = ap.parse_args()
    if args.render_doc_table:
        summary = json.loads(args.render_doc_table.read_text())
        print(render_doc_table(summary))
        print()
        print(render_table(summary))
        return
    if not (args.socket_patch and args.socket_patch_revision and args.output):
        ap.error("--socket-patch, --socket-patch-revision and --output are required")
    invocations = [i.strip() for i in args.invocations.split(",") if i.strip()]
    for inv in invocations:
        if inv not in INVOCATIONS:
            ap.error(f"unknown invocation {inv!r}")

    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=True)
    tools_root = (args.tools_root or (root / "tools-root")).resolve()
    tools_root.mkdir(parents=True, exist_ok=True)
    cli_path = args.socket_patch.resolve()
    env = base_env()
    provenance = {
        "capturedAt": datetime.now(timezone.utc).isoformat(),
        "cliRevision": args.socket_patch_revision,
        "cliSha256": hashlib.sha256(cli_path.read_bytes()).hexdigest(),
        "pipenvVersions": args.versions,
        "modes": args.modes,
        "shapes": args.shapes,
        "invocations": invocations,
        "host": os.uname().sysname + " " + os.uname().machine,
        "legacyImage": LEGACY_IMAGE,
    }
    save(root / "provenance.json", provenance)

    log_lock = threading.Lock()

    def say(*a):
        with log_lock:
            print(*a, flush=True)

    # ------------------------------------------------------------------ docker
    def docker_cmd(cwd, extra_env, workdir=None, name=None):
        """`docker run` prefix that mirrors ROOTs + cwd at identical paths."""
        mounts = []
        seen = set()
        for path in [tools_root, root, Path(cwd)]:
            p = str(path)
            if not any(p == s or p.startswith(s.rstrip("/") + "/") for s in seen):
                mounts += ["-v", f"{p}:{p}"]
                seen.add(p)
        cmd = ["docker", "run", "--rm", "--name", name or ("pipenv-bt-" + uuid_mod.uuid4().hex[:12]), *mounts, "-w", str(workdir or cwd)]
        for k, v in extra_env.items():
            cmd += ["-e", f"{k}={v}"]
        cmd.append(LEGACY_IMAGE)
        return cmd

    def legacy_run(cmd, cwd, extra_env, log, timeout=None, workdir=None):
        name = "pipenv-bt-" + uuid_mod.uuid4().hex[:12]
        full = docker_cmd(cwd, extra_env, workdir=workdir, name=name) + [str(c) for c in cmd]
        return Run(full, cwd, env, log, timeout=timeout, container=name)

    # ------------------------------------------------------------------ tools
    def tool_dir(version):
        return tools_root / ("legacy-tools" if is_legacy(version) else "tools") / version

    def wrapper_dir(version):
        return root / "legacy-bin" / version

    def prepare_tool(version):
        tool = tool_dir(version)
        legacy = is_legacy(version)
        logs = root / "bootstrap-logs"
        logs.mkdir(exist_ok=True)
        if legacy:
            # Host-side `pipenv` that runs the legacy release inside Docker with
            # the tool root, the output root and the caller's cwd bind-mounted at
            # identical paths — the CLI's `pipenv --version` probe and the
            # harness's own pipenv invocations both go through it.
            wd = wrapper_dir(version)
            wd.mkdir(parents=True, exist_ok=True)
            mounts = " ".join(f"-v {shlex.quote(str(p))}:{shlex.quote(str(p))}" for p in [tools_root, root])
            (wd / "pipenv").write_text(
                "#!/bin/sh\n"
                f"# Pipenv {version} inside {LEGACY_IMAGE}; tool root, output root and $PWD bind-mounted\n"
                f'exec docker run --rm -i {mounts} -v "$PWD":"$PWD" -w "$PWD" \\\n'
                f"  -e PATH={shlex.quote(str(tool / 'bin'))}:/usr/local/bin:/usr/bin:/bin \\\n"
                "  -e PIPENV_VENV_IN_PROJECT -e PIPENV_YES=1 -e PIPENV_NOSPIN=1 -e PIP_DISABLE_PIP_VERSION_CHECK=1 -e WORKON_HOME -e PIPENV_PYTHON \\\n"
                f"  {LEGACY_IMAGE} {shlex.quote(str(tool / 'bin/pipenv'))} \"$@\"\n"
            )
            (wd / "pipenv").chmod(0o755)
            if not (tool / "bin/pipenv").exists():
                tool.parent.mkdir(parents=True, exist_ok=True)
                require(legacy_run(["python", "-m", "venv", tool], tools_root, {"PIP_DISABLE_PIP_VERSION_CHECK": "1"}, logs / f"{version}-venv.log"), f"legacy venv {version}")
                require(
                    legacy_run([tool / "bin/python", "-m", "pip", "install", f"pipenv=={version}", *LEGACY_TOOL_PACKAGES], tools_root, {"PIP_DISABLE_PIP_VERSION_CHECK": "1"}, logs / f"{version}-install.log"),
                    f"legacy pipenv {version} install",
                )
        elif not (tool / "bin/pipenv").exists():
            major = major_of(version)
            py = os.environ.get("BACKTEST_PY38", "3.8.20") if major <= 2022 else os.environ.get("BACKTEST_PY312", "3.12.13")
            require(Run(["uv", "venv", "-q", "--python", py, tool], root, env, logs / f"{version}-venv.log"), "uv venv")
            pkgs = [f"pipenv=={version}", "pip==24.0", "setuptools==69.5.1" if major >= 2023 else "setuptools==57.5.0"]
            require(Run(["uv", "pip", "install", "-q", "--python", tool / "bin/python", *pkgs], root, env, logs / f"{version}-install.log"), "pipenv bootstrap")
        return tool

    # ------------------------------------------------------------- pipenv env
    def pipenv_env(version, tool, in_project=True, workon_home=None):
        e = dict(env)
        e["PATH"] = str(pipenv_shim_dir(root, version, tool)) + os.pathsep + e.get("PATH", "")
        e["PIPENV_PYTHON"] = str(tool / "bin/python")
        if in_project:
            e["PIPENV_VENV_IN_PROJECT"] = "1"
        if workon_home is not None:
            e["WORKON_HOME"] = str(workon_home)
        return e

    def pipenv_bin(version, tool):
        return (wrapper_dir(version) / "pipenv") if is_legacy(version) else (tool / "bin/pipenv")

    def run_pipenv(version, tool, args_, cwd, penv, log, timeout=None):
        """Run `pipenv <args>` for `version` in `cwd` (Docker for legacy)."""
        if is_legacy(version):
            extra = {k: v for k, v in penv.items() if k.startswith(("PIP", "WORKON_HOME"))}
            extra["PATH"] = f"{tool / 'bin'}:/usr/local/bin:/usr/bin:/bin"
            return legacy_run([tool / "bin/pipenv", *args_], cwd, extra, log, timeout=timeout)
        return Run([tool / "bin/pipenv", *args_], cwd, penv, log, timeout=timeout)

    def run_python(version, python, args_, cwd, penv, log, timeout=None):
        """Run the PROJECT interpreter (Docker for legacy: linux venv)."""
        if is_legacy(version):
            extra = {k: v for k, v in penv.items() if k.startswith(("PIP", "WORKON_HOME"))}
            return legacy_run([python, *args_], cwd, extra, log, timeout=timeout)
        return Run([python, *args_], cwd, penv, log, timeout=timeout)

    def make_venv(version, tool, venv, cwd, log, packages=(), native=False):
        """Create the project venv.

        Modern: uv venv on the tool's interpreter + pip 24 (+ packages).
        Legacy: `native=True` builds the Docker (linux, python 3.6) venv that
        Pipenv itself installs into; otherwise a host uv venv (python 3.8) so
        the CLI can crawl an installed urllib3 the way the depscan captures did.
        """
        if venv.exists():
            shutil.rmtree(venv)
        if is_legacy(version) and native:
            venv.mkdir(parents=True)
            require(legacy_run(["/usr/local/bin/python", "-m", "venv", venv], cwd, {"PIP_DISABLE_PIP_VERSION_CHECK": "1"}, log), "docker venv")
            require(legacy_run([venv / "bin/python", "-m", "pip", "install", *LEGACY_VENV_PACKAGES, *packages], cwd, {"PIP_DISABLE_PIP_VERSION_CHECK": "1"}, str(log) + ".pip"), "docker venv bootstrap")
            return
        py = os.environ.get("BACKTEST_PY38", "3.8.20") if is_legacy(version) else tool / "bin/python"
        require(Run(["uv", "venv", "-q", "--python", py, venv], cwd, env, log), "uv venv")
        pkgs = ["pip==24.0", "setuptools==69.5.1", *packages]
        require(Run(["uv", "pip", "install", "-q", "--python", venv / "bin/python", *pkgs], cwd, env, str(log) + ".pip"), "venv bootstrap")

    def uninstall_urllib3(version, python, cwd, penv, log):
        if is_legacy(version):
            r = run_python(version, python, ["-m", "pip", "uninstall", "-y", "urllib3"], cwd, penv, log)
        else:
            r = Run(["uv", "pip", "uninstall", "-q", "--python", python, "urllib3"], cwd, env, log)
        if not r.ok():
            # Tolerate "not installed" as long as the package is truly absent.
            require(run_python(version, python, ["-c", ABSENT], cwd, penv, str(log) + ".absent"), "urllib3 uninstall")

    def oracle(version, python, names, cwd, penv, log):
        # For the pre-2018 releases the oracle runs in a fresh container over a
        # bind mount the host CLI just wrote through (stage + rename): Docker
        # Desktop's shared file cache occasionally shows the directory without
        # the renamed entry for a moment, so a missing file is re-read a few
        # times before it counts (a real absence stays absent).
        attempts = 4 if is_legacy(version) else 1
        result = {}
        for attempt in range(attempts):
            r = run_python(version, python, ["-c", ORACLE, json.dumps(list(names))], cwd, penv, log)
            result = json.loads(r.out.strip().splitlines()[-1]) if r.ok() and r.out.strip() else {}
            if result and all(v is not None for v in result.values()):
                return result
            if attempt + 1 < attempts:
                time.sleep(1.5)
        return result

    def urllib3_absent(version, python, cwd, penv, log):
        return run_python(version, python, ["-c", ABSENT], cwd, penv, log).ok()

    def install_args(version, shape, deploy=True):
        # `--ignore-pipfile` arrives with Pipenv 3; `--deploy` with Pipenv 9.
        a = ["install"] + (["--ignore-pipfile"] if major_of(version) >= 3 else [])
        if deploy and major_of(version) >= 9:
            a.append("--deploy")
        if shape == "dev":
            a.append("--dev")
        if shape == "category":
            a += ["--categories", "tests"]
        return a

    def sync_args(version, shape):
        if major_of(version) < 2018:
            return None
        a = ["sync"]
        if shape == "dev":
            a.append("--dev")
        if shape == "category":
            a += ["--categories", "tests"]
        return a

    # ------------------------------------------------------------ fixtures
    def pipfile_text(version, shape):
        text = PROJECT
        if shape == "dev":
            text = PROJECT.replace('urllib3 = "==1.26.18"\n', "").replace("[dev-packages]", '[dev-packages]\nurllib3 = "==1.26.18"')
        elif shape == "category":
            text = PROJECT.replace("[packages]", "[tests]")
        elif shape in ("marker", "marker-excluded", "extras"):
            field = 'extras = ["socks"]' if shape == "extras" else 'markers = "python_version ' + (">" if shape == "marker-excluded" else "<") + " '4'\""
            text = PROJECT.replace('"==1.26.18"', '{version="==1.26.18", ' + field + "}")
        elif shape == "transitive":
            pins = TRANSITIVE_LEGACY if is_legacy(version) else TRANSITIVE_MODERN
            text = PROJECT.split("[packages]")[0] + "[packages]\n" + "".join(f'{n} = "=={v}"\n' for n, v in pins.items()) + "\n[dev-packages]\n"
        return text

    def content_hash(version, tool, project, penv, log):
        code = (
            "import pipenv,pipfile; print(pipfile.load('Pipfile').hash)"
            if is_legacy(version)
            else "from pipenv.project import Project; p=Project(); print(p.calculate_pipfile_hash() if hasattr(p,'calculate_pipfile_hash') else p.pipfile.calculate_hash())"
        )
        r = require(run_python(version, tool / "bin/python", ["-c", code], project, penv, log), "content hash")
        return r.out.strip().splitlines()[-1]

    def native_lock(version, tool, shape):
        """Generate (once) the native Pipfile.lock for version/shape."""
        original = root / "original" / version / shape
        if (original / "Pipfile.lock").exists():
            return original
        original.mkdir(parents=True, exist_ok=True)
        (original / "Pipfile").write_text(pipfile_text(version, shape))
        penv = pipenv_env(version, tool)
        # Legacy Pipenv resolves through the project venv's pip-tools; give it one.
        make_venv(version, tool, original / ".venv", original, original / "venv.log", native=True)
        require(run_pipenv(version, tool, ["lock"], original, penv, original / "generation.log"), f"pipenv {version} lock ({shape})")
        if shape == "transitive":
            # Lock with every pin (so urllib3 is pinned to 1.26.18), then shrink
            # the Pipfile to `requests` only and stamp its content hash so
            # `--deploy` still accepts the lock.
            pins = TRANSITIVE_LEGACY if is_legacy(version) else TRANSITIVE_MODERN
            (original / "Pipfile").write_text(PROJECT.replace('urllib3 = "==1.26.18"', 'requests = "==' + pins["requests"] + '"'))
            hashed = content_hash(version, tool, original, penv, original / "content-hash.log")
            lock = json.loads((original / "Pipfile.lock").read_text())
            lock["_meta"]["hash"]["sha256"] = hashed
            (original / "Pipfile.lock").write_text(json.dumps(lock, indent=4, sort_keys=True) + "\n")
        if shape == "crlf":
            for name in ["Pipfile", "Pipfile.lock"]:
                p = original / name
                p.write_bytes(p.read_text().replace("\r\n", "\n").replace("\n", "\r\n").encode())
        shutil.rmtree(original / ".venv", ignore_errors=True)
        return original

    # --------------------------------------------------------------- the CLI
    def cli_invocation(case, project, invocation):
        """(cwd, extra args) for pointing the CLI at `project`."""
        if invocation == "in-dir":
            return project, []
        if invocation == "cwd-flag":
            return root, ["--cwd", str(project)]
        if invocation == "subdir":
            # project lives at <case>/nested/app; run from <case>/nested
            return project.parent, ["--cwd", project.name]
        if invocation == "symlink":
            link = case / "link"
            if not link.is_symlink():
                link.symlink_to(project, target_is_directory=True)
            return link, ["--cwd", str(link)]
        raise ValueError(invocation)

    def applied_count(mode, envelope):
        if mode == "hosted":
            return envelope.get("redirect", {}).get("redirected", 0)
        if mode == "vendored":
            return envelope.get("vendor", {}).get("summary", {}).get("applied", 0)
        return envelope.get("apply", {}).get("applied", 0)

    def planned_count(mode, envelope):
        """What a --dry-run envelope says WOULD happen (no summary is written)."""
        if mode == "hosted":
            return envelope.get("redirect", {}).get("redirected", 0)
        if mode == "vendored":
            v = envelope.get("vendor", {})
            if v.get("dryRun"):
                return sum(1 for p in v.get("patches", []) if p.get("action") == "would_vendor")
            return v.get("summary", {}).get("applied", 0)
        a = envelope.get("apply", {})
        return a.get("added", 0) + a.get("updated", 0) if a.get("dryRun") else a.get("applied", 0)

    def envelope_warnings(mode, envelope):
        if mode == "hosted":
            return envelope.get("redirect", {}).get("warnings", [])
        if mode == "vendored":
            return envelope.get("vendor", {}).get("events", [])
        return envelope.get("apply", {}).get("patches", [])

    def record_hashes(project, mode):
        if mode == "hosted":
            recs = json.loads((project / ".socket/vendor/redirect-state.json").read_text())["records"]
        else:
            recs = json.loads((project / ".socket/manifest.json").read_text())["patches"]
        rec = next(iter(recs.values()))
        return (
            {n: i["afterHash"] for n, i in rec["files"].items()},
            {n: i["beforeHash"] for n, i in rec["files"].items() if i.get("beforeHash")},
            rec.get("uuid"),
        )

    def lock_entries(text):
        """Every (section, key, entry) for urllib3 in a Pipfile.lock text."""
        try:
            lock = json.loads(text)
        except Exception:
            return []
        out = []
        for section, entries in lock.items():
            if section == "_meta" or not isinstance(entries, dict):
                continue
            for key, entry in entries.items():
                if key.lower().replace("_", "-") == "urllib3":
                    out.append((section, key, entry))
        return out

    def source_keys(text):
        return sorted({k for _, _, e in lock_entries(text) if isinstance(e, dict) for k in ("file", "path") if k in e})

    # -------------------------------------------------------------- one case
    def backtest(job):
        """Run one case; persist its row (or error) as <case>/result.json."""
        version, shape, mode, invocation = job
        suffix = "" if invocation == "in-dir" else "-" + invocation
        case = root / "captures" / f"{version}-{shape}-{mode}{suffix}"
        try:
            row = backtest_case(job)
        except Exception as e:
            case.mkdir(parents=True, exist_ok=True)
            save(case / "result.json", {"pipenv": version, "shape": shape, "mode": mode, "invocation": invocation, "passed": False, "error": str(e)[-3000:], "trace": traceback.format_exc()[-2000:]})
            raise
        save(case / "result.json", row)
        return row

    def backtest_case(job):
        version, shape, mode, invocation = job
        legacy = is_legacy(version)
        major = major_of(version)
        tool = tool_dir(version)
        suffix = "" if invocation == "in-dir" else "-" + invocation
        case = root / "captures" / f"{version}-{shape}-{mode}{suffix}"
        if case.exists():
            shutil.rmtree(case)
        case.mkdir(parents=True)
        if major < 3 and shape == "transitive":
            # Pipenv 0.x has no `pipfile` module to stamp the Pipfile content
            # hash with, so the transitive Pipfile cannot be paired with the
            # generated lock (`pipenv install` would re-lock on the mismatch).
            return {"pipenv": version, "shape": shape, "mode": mode, "invocation": invocation, "pipfileSpec": None, "supported": False,
                    "expected": "skipped: Pipenv 0.x cannot stamp the transitive Pipfile's content hash", "checks": {}, "info": {}, "passed": True}
        original = native_lock(version, tool, shape)
        project = (case / "nested" / "app") if invocation == "subdir" else (case / "project")
        project.mkdir(parents=True)
        for name in ["Pipfile", "Pipfile.lock"]:
            shutil.copyfile(original / name, project / name)
        pristine_lock = (project / "Pipfile.lock").read_bytes()
        pristine_pipfile = (project / "Pipfile").read_bytes()
        spec = json.loads(pristine_lock.decode()).get("_meta", {}).get("pipfile-spec")
        row = {"pipenv": version, "shape": shape, "mode": mode, "invocation": invocation, "pipfileSpec": spec, "supported": None, "expected": None, "checks": {}, "info": {}, "passed": None}
        checks, info = row["checks"], row["info"]

        def check(name, value, note=None):
            checks[name] = bool(value)
            if note is not None:
                info[name] = note
            return bool(value)

        cwd, cli_args = cli_invocation(case, project, invocation)

        def cli_run(penv_, *rest, log):
            return Run([cli_bin, *rest, *cli_args, "--json", "--yes", "--no-telemetry"], cwd, penv_, case / log)

        cli_bin = cli_path
        venv = project / ".venv"
        python = venv / "bin/python"
        penv = pipenv_env(version, tool)

        # Pipenv 0.x installs plain string pins only: inline-table entries with
        # markers / extras are not understood, so nothing gets installed for
        # agent mode to patch — nothing to measure there.
        if mode in ("agent", "agent-oot") and major < 7 and shape in ("marker", "marker-excluded", "extras"):
            # Pipenv 0.x–6.x install plain string pins only: inline-table
            # entries are mis-handled (markers ignored, extras fail to
            # install), so there is nothing meaningful for agent mode to
            # measure; hosted/vendored rows for these releases are refusals
            # judged before any install.
            row["supported"] = False
            row["expected"] = "skipped: Pipenv 0.x–6.x mishandle inline-table (markers/extras) Pipfile entries"
            row["passed"] = True
            return row

        # --------------------------------------------------------- agent-oot
        if mode == "agent-oot":
            if major == 7:
                # Pipenv 7 creates its out-of-tree venv through pew + virtualenv
                # 16, whose seeding fails inside the python:3.6.15-slim harness
                # image ("Can not use any platform or abi specific options");
                # its in-project agent leg and the 8–11 out-of-tree legs cover
                # the crawler on the legacy layout.
                row["supported"] = False
                row["expected"] = "skipped: Pipenv 7 cannot create its out-of-tree virtualenv in the harness image"
                row["passed"] = True
                return row
            if major < 3:
                row["supported"] = False
                row["expected"] = "skipped: Pipenv 0.x has no `--venv` and no WORKON_HOME placement to discover"
                row["passed"] = True
                return row
            workon = case / "venvs"
            workon.mkdir()
            oenv = pipenv_env(version, tool, in_project=False, workon_home=workon)
            # Pipenv creates the venv itself here; pin its interpreter explicitly
            # (2022.12.19 ignored PIPENV_PYTHON and picked the newest python3 on
            # PATH, whose pkgutil no longer suits its vendored pip).
            first = install_args(version, shape) + ([] if legacy else ["--python", str(tool / "bin/python")])
            require(run_pipenv(version, tool, first, project, oenv, case / "install-upstream.log"), "pipenv install (out-of-tree)")
            vp = run_pipenv(version, tool, ["--venv"], project, oenv, case / "venv-path.log")
            candidates = [Path(line.strip()) for line in vp.out.splitlines() if line.strip().startswith("/")]
            oot_venv = next((c for c in candidates if (c / "bin/python").exists()), None)
            if oot_venv is None:
                found = [d for d in workon.iterdir() if (d / "bin/python").exists()]
                oot_venv = found[0] if found else None
            info["ootVenv"] = str(oot_venv)
            info["ootVenvNameMatchesWorkon"] = bool(oot_venv) and oot_venv.parent == workon
            if not oot_venv:
                raise RuntimeError("could not locate Pipenv's out-of-tree venv: " + vp.out + vp.err)
            opython = oot_venv / "bin/python"
            # 1. BARE scan: the CLI inherits Pipenv's configuration (WORKON_HOME)
            # but not an activation (VIRTUAL_ENV) — exactly what `pipenv run` adds.
            bare_env = dict(env)
            bare_env["WORKON_HOME"] = str(workon)
            bare_env["PATH"] = oenv["PATH"]
            r1 = cli_run(bare_env, "scan", "--mode", "agent", "--dry-run", log="scan-bare-dryrun.log")
            e1 = r1.json_or_empty()
            pkgs = e1.get("packages") or []
            u3 = [p for p in pkgs if "urllib3" in (p.get("purl") or "")]
            found = e1.get("apply", {}).get("found", 0)
            # The envelope names packages but not where they live. A crawler that
            # found the out-of-tree venv scans exactly its distributions; the
            # project-marker fallback scans `python3`-on-PATH instead (here the
            # Pipenv tool venv, which may itself carry an urllib3 1.26.18).
            cnt = run_python(version, opython, ["-c", "import os,sysconfig; print(sum(1 for d in os.listdir(sysconfig.get_paths()['purelib']) if d.endswith(('.dist-info', '.egg-info'))))"], project, oenv, case / "venv-dist-count.log")
            venv_dists = int(cnt.out.strip().splitlines()[-1]) if cnt.ok() and cnt.out.strip() else None
            scanned = e1.get("scannedPackages")
            sees = bool(u3) and found >= 1 and venv_dists is not None and scanned is not None and abs(scanned - venv_dists) <= 2
            info["bareScan"] = {"exit": r1.rc, "scannedPackages": scanned, "venvDistributions": venv_dists, "found": found, "paths": (e1.get("paths") or [])[:10], "urllib3Listed": bool(u3), "foreignInterpreterHit": bool(u3) and found >= 1 and not sees}
            check("bareScanSeesPipenvVenv", sees, info["bareScan"])
            # 2. apply: bare when the crawler saw the venv, else the way a user
            # would — `pipenv run` (modern; exports VIRTUAL_ENV) or an explicit
            # VIRTUAL_ENV (legacy: the CLI is a host binary, pipenv lives in Docker).
            bare = bool(sees)
            if bare:
                info["applyPath"] = "bare"
                r2 = cli_run(bare_env, "scan", "--mode", "agent", log="scan-apply.log")
            elif legacy:
                info["applyPath"] = "VIRTUAL_ENV"
                venv_env = dict(bare_env, VIRTUAL_ENV=str(oot_venv))
                r2 = cli_run(venv_env, "scan", "--mode", "agent", log="scan-apply.log")
            else:
                info["applyPath"] = "pipenv run"
                r2 = Run([tool / "bin/pipenv", "run", cli_bin, "scan", "--mode", "agent", *cli_args, "--json", "--yes", "--no-telemetry"], cwd, oenv, case / "scan-apply.log")
            e2 = r2.json_or_empty()
            check("scanApplied", applied_count("agent", e2) == 1, {"exit": r2.rc, "applied": applied_count("agent", e2), "path": info["applyPath"], "tail": r2.tail(300) if not r2.ok() else None})
            if not checks["scanApplied"]:
                row["passed"] = False
                return row
            after, before, _ = record_hashes(project, "agent")
            res = oracle(version, opython, after, project, oenv, case / "oracle-1.log")
            check("installedBytesPatched", bool(after) and all(res.get(n) == h for n, h in after.items()), res)
            # 3. a repeat install / sync must not revert the in-place patch
            ri = run_pipenv(version, tool, install_args(version, shape), project, oenv, case / "install-again.log")
            res = oracle(version, opython, after, project, oenv, case / "oracle-2.log")
            check("survivesRepeatInstall", ri.ok() and all(res.get(n) == h for n, h in after.items()), {"exit": ri.rc, "oracle": res})
            sa = sync_args(version, shape)
            if sa:
                rs = run_pipenv(version, tool, sa, project, oenv, case / "sync.log")
                res = oracle(version, opython, after, project, oenv, case / "oracle-3.log")
                check("survivesSync", rs.ok() and all(res.get(n) == h for n, h in after.items()), {"exit": rs.rc, "oracle": res})
            # 4. rollback the same way the patch was applied
            if bare:
                rb = cli_run(bare_env, "rollback", log="rollback.log")
            elif legacy:
                rb = cli_run(dict(bare_env, VIRTUAL_ENV=str(oot_venv)), "rollback", log="rollback.log")
            else:
                rb = Run([tool / "bin/pipenv", "run", cli_bin, "rollback", *cli_args, "--json", "--yes", "--no-telemetry"], cwd, oenv, case / "rollback.log")
            res = oracle(version, opython, after, project, oenv, case / "oracle-rollback.log")
            check("rollbackRestoresUpstream", rb.ok() and bool(before) and all(res.get(n) == h for n, h in before.items()), {"exit": rb.rc, "oracle": res})
            mf = project / ".socket/manifest.json"
            check("rollbackClearsManifest", not mf.exists() or json.loads(mf.read_text()).get("patches") in ({}, None))
            check("lockUntouched", (project / "Pipfile.lock").read_bytes() == pristine_lock and (project / "Pipfile").read_bytes() == pristine_pipfile)
            row["supported"] = True
            row["passed"] = all(checks.values())
            return row

        # ------------------------------------------------------------- agent
        if mode == "agent":
            make_venv(version, tool, venv, project, case / "venv.log", native=True)
            require(run_pipenv(version, tool, install_args(version, shape), project, penv, case / "install-upstream.log"), "pipenv install (upstream)")
            if shape == "marker-excluded":
                check("excludedStaysAbsent", urllib3_absent(version, python, project, penv, case / "absence.log"))
                r = cli_run(penv, "scan", "--mode", "agent", log="scan.log")
                e = r.json_or_empty()
                save(case / "cli-output.json", e)
                check("nothingApplied", applied_count("agent", e) == 0, {"exit": r.rc, "applied": applied_count("agent", e)})
                check("lockUntouched", (project / "Pipfile.lock").read_bytes() == pristine_lock)
                row["supported"] = True
                row["expected"] = "marker excludes urllib3: nothing installed, nothing to patch"
                row["passed"] = all(checks.values())
                return row
            r = cli_run(penv, "scan", "--mode", "agent", log="scan.log")
            info["scanExit"] = r.rc
            envelope = r.json()
            save(case / "cli-output.json", envelope)
            applied = applied_count("agent", envelope)
            check("appliedExactlyOne", applied == 1, {"applied": applied, "status": envelope.get("status"), "patches": envelope_warnings("agent", envelope)[:4]})
            if not checks["appliedExactlyOne"]:
                row["passed"] = False
                return row
            check("lockUntouched", (project / "Pipfile.lock").read_bytes() == pristine_lock and (project / "Pipfile").read_bytes() == pristine_pipfile)
            after, before, uuid = record_hashes(project, "agent")
            info["uuid"] = uuid
            res = oracle(version, python, after, project, penv, case / "oracle-1.log")
            check("installedBytesPatched", bool(after) and all(res.get(n) == h for n, h in after.items()), res)
            r2 = cli_run(penv, "scan", "--mode", "agent", log="rescan.log")
            e2 = r2.json_or_empty()
            res = oracle(version, python, after, project, penv, case / "oracle-rescan.log")
            check("rescanIdempotent", r2.ok() and all(res.get(n) == h for n, h in after.items()) and (project / "Pipfile.lock").read_bytes() == pristine_lock, {"exit": r2.rc, "applied": applied_count("agent", e2), "status": e2.get("status")})
            ri = run_pipenv(version, tool, install_args(version, shape), project, penv, case / "install-again.log")
            res = oracle(version, python, after, project, penv, case / "oracle-2.log")
            check("survivesRepeatInstall", ri.ok() and all(res.get(n) == h for n, h in after.items()), {"exit": ri.rc, "oracle": res, "tail": ri.tail(300) if not ri.ok() else None})
            sa = sync_args(version, shape)
            if sa:
                rs = run_pipenv(version, tool, sa, project, penv, case / "sync.log")
                res = oracle(version, python, after, project, penv, case / "oracle-3.log")
                check("survivesSync", rs.ok() and all(res.get(n) == h for n, h in after.items()), {"exit": rs.rc, "oracle": res, "tail": rs.tail(300) if not rs.ok() else None})
            vx = Run([cli_bin, "vex", "--product", "pkg:pypi/pipenv-backtest-fixture@0.1.0", *cli_args, "--no-telemetry"], cwd, penv, case / "vex.log")
            info["vex"] = vex_info(vx)
            rb = cli_run(penv, "rollback", log="rollback.log")
            erb = rb.json_or_empty()
            res = oracle(version, python, after, project, penv, case / "oracle-rollback.log")
            check("rollbackExit0", rb.ok(), rb.tail(600) if not rb.ok() else None)
            check("rollbackRestoresUpstreamBytes", bool(before) and all(res.get(n) == h for n, h in before.items()), res)
            mf = project / ".socket/manifest.json"
            check("rollbackClearsManifest", not mf.exists() or json.loads(mf.read_text()).get("patches") in ({}, None))
            check("rollbackKeepsLock", (project / "Pipfile.lock").read_bytes() == pristine_lock and (project / "Pipfile").read_bytes() == pristine_pipfile)
            info["rollbackEnvelope"] = {k: erb.get(k) for k in ("status", "rolledBack", "failed", "hosted", "vendoredReverted", "manifest") if k in erb}
            row["supported"] = True
            row["passed"] = all(checks.values())
            return row

        # ------------------------------------------------- hosted / vendored
        # Fresh-clone scenario first: nothing installed, lock only. An EMPTY
        # in-project venv keeps the crawl hermetic (the project-marker fallback
        # would otherwise walk this machine's global interpreters).
        make_venv(version, tool, venv, project, case / "venv-empty.log")
        r0 = cli_run(penv, "scan", "--mode", mode, log="scan-lockonly.log")
        e0 = r0.json_or_empty()
        codes0 = sorted({(w.get("code") or w.get("errorCode")) for w in envelope_warnings(mode, e0) if (w.get("code") or w.get("errorCode"))})
        info["lockOnly"] = {"exit": r0.rc, "applied": applied_count(mode, e0), "lockfileOnlyPackages": e0.get("lockfileOnlyPackages"), "codes": codes0}
        check("lockOnlyApplies", applied_count(mode, e0) == 1, info["lockOnly"])
        if applied_count(mode, e0) == 1:
            # The CI re-run shape: the checkout already carries the committed
            # reference and nothing is installed — the re-scan must stay green
            # (hosted re-confirms; vendored reports already_vendored), not
            # `package_not_installed`, and the lock must not change.
            lock1 = (project / "Pipfile.lock").read_bytes()
            r1 = cli_run(penv, "scan", "--mode", mode, log="scan-lockonly-rescan.log")
            e1 = r1.json_or_empty()
            codes1 = sorted({(w.get("code") or w.get("errorCode")) for w in envelope_warnings(mode, e1) if (w.get("code") or w.get("errorCode"))})
            ok1 = r1.ok() and e1.get("status") == "success" and (project / "Pipfile.lock").read_bytes() == lock1 and "package_not_installed" not in codes1
            check("lockOnlyRescanGreen", ok1, {"exit": r1.rc, "status": e1.get("status"), "codes": codes1})
        shutil.rmtree(project / ".socket", ignore_errors=True)
        shutil.rmtree(venv, ignore_errors=True)
        (project / "Pipfile.lock").write_bytes(pristine_lock)
        (project / "Pipfile").write_bytes(pristine_pipfile)

        # The CLI phase runs against a venv with upstream urllib3 installed
        # (vendored needs an installed package; hosted does not care).
        make_venv(version, tool, venv, project, case / "venv.log", packages=["urllib3==1.26.18"])

        # --dry-run first: must report the same count and leave everything untouched.
        rd = cli_run(penv, "scan", "--mode", mode, "--dry-run", log="scan-dryrun.log")
        ed = rd.json_or_empty()
        dry_applied = planned_count(mode, ed)
        dry_clean = (project / "Pipfile.lock").read_bytes() == pristine_lock and (project / "Pipfile").read_bytes() == pristine_pipfile and not (project / ".socket").exists()
        info["dryRun"] = {"exit": rd.rc, "applied": dry_applied, "untouched": dry_clean}

        r = cli_run(penv, "scan", "--mode", mode, log="scan.log")
        info["scanExit"] = r.rc
        try:
            envelope = r.json()
        except Exception as e:
            raise RuntimeError(f"scan produced no JSON: {e}\n{r.tail(2000)}")
        save(case / "cli-output.json", envelope)
        applied = applied_count(mode, envelope)
        info["applied"] = applied
        warnings = envelope_warnings(mode, envelope)
        info["warnings"] = warnings[:8]
        lock_after = (project / "Pipfile.lock").read_bytes()
        check("pipfileUnchanged", (project / "Pipfile").read_bytes() == pristine_pipfile)
        # Hosted --dry-run computes the rewrite; vendored --dry-run is a
        # ledger-only preview (`would_vendor`) that runs no backend guard, so
        # its parity is recorded, not required.
        check("dryRunParity", dry_applied == applied and dry_clean, info["dryRun"])

        # ---- expected refusals (pre-2018 majors)
        refusal = None
        if spec != 6:
            # Hosted: an old lock says nothing about the project's other install
            # files, so it is a SKIP (not a veto) — `redirect_pipenv_skipped`.
            refusal = ("unsupported-lock-spec", "redirect_pipenv_skipped" if mode == "hosted" else "pypi_pipenv_spec_unsupported")
        elif legacy and mode == "vendored":
            refusal = ("unsupported-vendored-installer", "pypi_pipenv_installer_unsupported")
        if refusal:
            reason, code = refusal
            row["supported"] = False
            row["expected"] = f"refused: {reason} ({code})"
            codes = sorted({(w.get("code") or w.get("errorCode")) for w in warnings if (w.get("code") or w.get("errorCode"))})
            check("refusedWithCode", applied == 0 and code in codes, {"applied": applied, "codes": codes, "exit": r.rc})
            check("lockUnchanged", lock_after == pristine_lock)
            check("noLedger", not (project / ".socket/vendor/redirect-state.json").exists() and not (project / ".socket/vendor/state.json").exists())
            rb = cli_run(penv, "rollback", log="rollback.log")
            check("rollbackHarmless", (project / "Pipfile.lock").read_bytes() == pristine_lock and (project / "Pipfile").read_bytes() == pristine_pipfile, {"exit": rb.rc})
            row["passed"] = all(val for k, val in checks.items() if k not in ("lockOnlyApplies", "dryRunParity"))
            return row

        row["supported"] = True
        check("appliedExactlyOne", applied == 1, {"applied": applied, "status": envelope.get("status"), "warnings": warnings[:4], "exit": r.rc})
        if not checks["appliedExactlyOne"]:
            row["passed"] = False
            return row
        # The scan ran against a venv holding the UPSTREAM release: Pipenv will
        # not reinstall it, so the CLI must say so (positive-evidence probe).
        stale_code = "redirect_pypi_stale_install" if mode == "hosted" else "pypi_pipenv_stale_install"
        stale = [w for w in warnings if (w.get("code") or w.get("errorCode")) == stale_code]
        stale_text = (stale[0].get("detail") or stale[0].get("reason") or "") if stale else ""
        check("staleInstallWarned", bool(stale) and "pipenv run pip uninstall" in stale_text, {"codes": sorted({(w.get("code") or w.get("errorCode")) for w in warnings if (w.get("code") or w.get("errorCode"))}), "detail": stale_text[:300] or None})
        check("lockRewritten", lock_after != pristine_lock)
        if shape == "crlf":
            check("crlfPreserved", b"\n" not in lock_after.replace(b"\r\n", b""))
        else:
            check("noCrlfIntroduced", b"\r\n" not in lock_after)
        check("lockStillJson", json.loads(lock_after.decode()) is not None)
        check("metaUnchanged", json.loads(lock_after.decode()).get("_meta") == json.loads(pristine_lock.decode()).get("_meta"))
        keys = source_keys(lock_after.decode())
        info["sourceKeys"] = keys
        entries = lock_entries(lock_after.decode())
        info["rewrittenEntries"] = [{"section": s, "key": k, "entry": e} for s, k, e in entries][:4]
        if mode == "hosted":
            expected_key = "path" if 7 <= major < 2018 else "file"
            check("lockHasPatchUrl", b"patch.socket.dev" in lock_after and b"#sha256=" in lock_after)
        else:
            has_extras = any(isinstance(e, dict) and e.get("extras") for _, _, e in lock_entries(pristine_lock.decode()))
            expected_key = "path" if has_extras else "file"
            check("lockHasVendoredRef", b".socket/vendor/pypi" in lock_after)
        check("expectedSourceKey", keys == [expected_key], {"expected": expected_key, "got": keys})
        pristine_entries = {(s, k): e for s, k, e in lock_entries(pristine_lock.decode())}
        check("allCategoriesRewritten", entries and all(("file" in e or "path" in e) and "version" not in e and "index" not in e for _, _, e in entries) and {(s, k) for s, k, _ in entries} == set(pristine_entries), {"pristine": sorted(pristine_entries), "rewritten": sorted((s, k) for s, k, _ in entries)})
        check("markersExtrasPreserved", all(e.get("markers") == pristine_entries.get((s, k), {}).get("markers") and e.get("extras") == pristine_entries.get((s, k), {}).get("extras") for s, k, e in entries))
        after, before, uuid = record_hashes(project, mode)
        info["uuid"] = uuid
        check("recordHasFiles", bool(after))
        if mode == "vendored":
            wheel_dir = project / ".socket/vendor/pypi" / (uuid or "")
            check("vendoredWheelPresent", wheel_dir.is_dir() and any(wheel_dir.glob("*.whl")))

        # idempotent re-scan
        r2 = cli_run(penv, "scan", "--mode", mode, log="rescan.log")
        e2 = r2.json_or_empty()
        check("rescanIdempotent", r2.ok() and (project / "Pipfile.lock").read_bytes() == lock_after and (project / "Pipfile").read_bytes() == pristine_pipfile, {"exit": r2.rc, "applied": applied_count(mode, e2), "status": e2.get("status")})

        # For legacy majors Pipenv installs into a Docker (linux) venv: replace
        # the host venv the CLI crawled with a native one carrying upstream urllib3.
        if legacy:
            make_venv(version, tool, venv, project, case / "native-venv.log", native=True, packages=["urllib3==1.26.18"])

        # WARM venv: upstream urllib3 already installed — does the redirected
        # lock make Pipenv install the patched wheel? (informational)
        warm_cmds = [("install", install_args(version, shape))]
        if sync_args(version, shape):
            warm_cmds.append(("sync", sync_args(version, shape)))
        info["warmReinstalled"] = {}
        for label, a in warm_cmds:
            w = run_pipenv(version, tool, a, project, penv, case / f"warm-{label}.log")
            wres = oracle(version, python, after, project, penv, case / f"oracle-warm-{label}.log")
            info["warmReinstalled"][label] = {"exit": w.rc, "patched": bool(after) and all(wres.get(n) == h for n, h in after.items()), "tail": w.tail(300)}
            # put the pristine copy back for the next warm command
            uninstall_urllib3(version, python, project, penv, case / f"warm-{label}-uninstall.log")
            require(run_python(version, python, ["-m", "pip", "install", "urllib3==1.26.18"], project, penv, case / f"warm-{label}-reinstall.log"), "pristine reinstall")
        check("warmInstallReplacesUpstream", all(v["exit"] == 0 and v["patched"] for v in info["warmReinstalled"].values()), info["warmReinstalled"])

        # Lock-driven install into the emptied venv.
        uninstall_urllib3(version, python, project, penv, case / "uninstall.log")
        inst = run_pipenv(version, tool, install_args(version, shape), project, penv, case / "install.log")
        res = oracle(version, python, after, project, penv, case / "oracle-1.log")
        check("pipenvInstallExit0", inst.ok(), inst.tail(600) if not inst.ok() else None)
        if shape == "marker-excluded":
            check("excludedStaysAbsent", urllib3_absent(version, python, project, penv, case / "absence.log") and not any(res.values()), res)
        else:
            check("installedBytesPatched", all(res.get(n) == h for n, h in after.items()), res)
        check("lockUnchangedByInstall", (project / "Pipfile.lock").read_bytes() == lock_after)
        check("pipfileUnchangedByInstall", (project / "Pipfile").read_bytes() == pristine_pipfile)
        vf = run_pipenv(version, tool, ["verify"], project, penv, case / "verify.log")
        info["verify"] = {"exit": vf.rc, "tail": vf.tail(200)}
        if major >= 2022:
            rq = run_pipenv(version, tool, ["requirements"] + (["--dev"] if shape == "dev" else []) + (["--categories", "tests"] if shape == "category" else []), project, penv, case / "requirements.log")
            marker = "patch.socket.dev" if mode == "hosted" else ".socket/vendor/pypi"
            info["requirementsExport"] = {"exit": rq.rc, "exportsPatchRef": marker in rq.out, "urllib3Line": next((l for l in rq.out.splitlines() if "urllib3" in l.lower()), None)}

        # Fresh clone of the committed state (Pipfile, Pipfile.lock, .socket/), new venv.
        fresh = case / "fresh"
        shutil.copytree(project, fresh, ignore=shutil.ignore_patterns(".venv", "__pycache__"))
        make_venv(version, tool, fresh / ".venv", fresh, case / "fresh-venv.log", native=True)
        finst = run_pipenv(version, tool, install_args(version, shape), fresh, penv, case / "fresh-install.log")
        fres = oracle(version, fresh / ".venv/bin/python", after, fresh, penv, case / "fresh-oracle.log")
        if shape == "marker-excluded":
            check("freshCloneKeepsExcluded", finst.ok() and urllib3_absent(version, fresh / ".venv/bin/python", fresh, penv, case / "fresh-absence.log"), {"exit": finst.rc})
        else:
            check("freshCloneInstallsPatch", finst.ok() and all(fres.get(n) == h for n, h in after.items()), {"exit": finst.rc, "oracle": fres, "tail": finst.tail(500) if not finst.ok() else None})
        check("freshCloneLockUnchanged", (fresh / "Pipfile.lock").read_bytes() == lock_after)

        # vex over the installed, redirected/vendored tree
        vx = Run([cli_bin, "vex", "--product", "pkg:pypi/pipenv-backtest-fixture@0.1.0", *cli_args, "--no-telemetry"], cwd, penv, case / "vex.log")
        info["vex"] = vex_info(vx)

        # Tamper: corrupt every recorded sha; the install must fail where the installer verifies.
        if shape in ("direct", "crlf") and shape != "marker-excluded":
            uninstall_urllib3(version, python, project, penv, case / "tamper-uninstall.log")
            corrupt = re.sub(rb"sha256[:=][a-f0-9]{64}", lambda m: m[0][:7] + b"0" * 64, lock_after)
            (project / "Pipfile.lock").write_bytes(corrupt)
            tam = run_pipenv(version, tool, install_args(version, shape), project, penv, case / "tamper-install.log")
            tres = oracle(version, python, after, project, penv, case / "tamper-oracle.log")
            (project / "Pipfile.lock").write_bytes(lock_after)
            info["tamper"] = {"installExit": tam.rc, "installedPatchedAnyway": bool(after) and all(tres.get(n) == h for n, h in after.items()), "expectsReject": mode == "hosted", "tail": tam.tail(300)}
            if mode == "hosted":
                check("tamperRejected", tam.rc != 0, info["tamper"])
            uninstall_urllib3(version, python, project, penv, case / "tamper-uninstall2.log")
            require(run_pipenv(version, tool, install_args(version, shape), project, penv, case / "reinstall.log"), "reinstall after tamper")
            check("lockRestoredAfterTamper", (project / "Pipfile.lock").read_bytes() == lock_after)

        # Relock: does Pipenv's own `lock` keep the patch reference? (informational)
        rl = run_pipenv(version, tool, ["lock"], project, penv, case / "relock.log", timeout=900)
        relocked = (project / "Pipfile.lock").read_bytes()
        marker = b"patch.socket.dev" if mode == "hosted" else b".socket/vendor/pypi"
        info["relock"] = {"exit": rl.rc, "lockBytesUnchanged": relocked == lock_after, "patchSourceKept": marker in relocked, "pipfileUnchanged": (project / "Pipfile").read_bytes() == pristine_pipfile, "tail": rl.tail(300) if not rl.ok() else None}
        # A relock regenerated the entry: `rollback` must retire the redirect
        # cleanly (exit 0, ledger cleared) instead of refusing forever — judged
        # in a copy so the main flow keeps its state. Two relock outcomes exist:
        # registry shape (the reference is gone; the relocked lock is the desired
        # end state and must be kept) and the Pipenv 2023+ hybrid of a
        # marker-excluded entry (our reference kept, upstream hashes + version
        # restored around it); that entry is still ours and must roll back to
        # the original registry entry, leaving no Socket reference behind.
        if rl.ok() and relocked != lock_after:
            relocked_dir = case / "relocked"
            shutil.copytree(project, relocked_dir, ignore=shutil.ignore_patterns(".venv", "__pycache__"))
            rcwd, rargs = cli_invocation(case, relocked_dir, "in-dir")
            rrb = Run([cli_bin, "rollback", *rargs, "--json", "--yes", "--no-telemetry"], rcwd, penv, case / "relocked-rollback.log")
            erb2 = rrb.json_or_empty()
            ledger2 = relocked_dir / ".socket/vendor/redirect-state.json"
            state2 = relocked_dir / ".socket/vendor/state.json"
            cleared = (not ledger2.exists() or not json.loads(ledger2.read_text()).get("records")) and (not state2.exists() or not json.loads(state2.read_text()).get("entries"))
            post = (relocked_dir / "Pipfile.lock").read_bytes()
            hybrid = marker in relocked
            if hybrid:
                lock_ok = marker not in post and urllib3_entries(post) == urllib3_entries(pristine_lock)
            else:
                lock_ok = post == relocked
            check("rollbackAfterRelockRetires", rrb.ok() and cleared and lock_ok, {"exit": rrb.rc, "cleared": cleared, "hybridRelock": hybrid, "lockKeptRelocked": post == relocked, "lockRestoredOriginal": post == pristine_lock, "referenceLeft": marker in post, "envelope": {k: erb2.get(k) for k in ("status", "hosted", "vendoredReverted", "failed") if k in erb2}, "tail": rrb.tail(400) if not rrb.ok() else None})
        (project / "Pipfile.lock").write_bytes(lock_after)
        (project / "Pipfile").write_bytes(pristine_pipfile)

        # Rollback restores every byte and clears the ledgers.
        rb = cli_run(penv, "rollback", log="rollback.log")
        erb = rb.json_or_empty()
        check("rollbackExit0", rb.ok(), rb.tail(600) if not rb.ok() else None)
        check("rollbackRestoresLockBytes", (project / "Pipfile.lock").read_bytes() == pristine_lock)
        check("rollbackKeepsPipfile", (project / "Pipfile").read_bytes() == pristine_pipfile)
        if mode == "hosted":
            ledger = project / ".socket/vendor/redirect-state.json"
            check("rollbackClearsRedirectLedger", not ledger.exists() or not json.loads(ledger.read_text()).get("records"))
        if mode == "vendored":
            check("rollbackRemovesVendoredWheel", not (project / ".socket/vendor/pypi" / (uuid or "x")).exists())
            state = project / ".socket/vendor/state.json"
            check("rollbackClearsVendorState", not state.exists() or not json.loads(state.read_text()).get("entries"))
        mf = project / ".socket/manifest.json"
        check("rollbackClearsManifest", not mf.exists() or json.loads(mf.read_text()).get("patches") in ({}, None))
        info["rollbackEnvelope"] = {k: erb.get(k) for k in ("status", "rolledBack", "failed", "hosted", "vendoredReverted", "manifest") if k in erb}
        # Measured boundaries, recorded rather than required: Pipenv never
        # reinstalls a present release (warmInstallReplacesUpstream — the CLI
        # warns instead, see staleInstallWarned) and the vendored --dry-run
        # preview runs no backend guard.
        informational = {"warmInstallReplacesUpstream"}
        if mode == "vendored":
            # The vendored --dry-run preview is ledger-only by design; recorded.
            informational.add("dryRunParity")
        row["passed"] = all(val for k, val in checks.items() if k not in informational)
        return row

    def vex_info(vx):
        try:
            vdoc = json.loads(vx.out[vx.out.find("{"):]) if vx.ok() else {}
            return {"exit": vx.rc, "statements": len(vdoc.get("statements", []))}
        except Exception:
            return {"exit": vx.rc, "tail": vx.tail(400)}

    # ------------------------------------------------------------ schedule
    prepared = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futs = {pool.submit(prepare_tool, v): v for v in args.versions}
        for f in concurrent.futures.as_completed(futs):
            v = futs[f]
            try:
                prepared[v] = f.result()
                say("bootstrapped pipenv", v)
            except Exception as e:
                say("BOOTSTRAP FAILED", v, str(e)[-800:])

    def wanted(version, shape, mode, invocation):
        if version not in prepared:
            return False
        if shape == "category" and major_of(version) < 2022:
            return False
        if invocation != "in-dir" and shape != "direct":
            return False
        if mode in ("agent", "agent-oot") and shape in ("crlf",):
            return False
        if mode == "agent-oot" and shape == "marker-excluded":
            return False
        return True

    # One job per (version, shape[, invocation]); modes run sequentially inside so
    # the shared original/<version>/<shape> lock is generated exactly once.
    groups = {}
    for v in args.versions:
        for s in args.shapes:
            for inv in invocations:
                for m in args.modes:
                    if wanted(v, s, m, inv):
                        groups.setdefault((v, s), []).append((m, inv))
    say(f"{sum(len(ms) for ms in groups.values())} cases in {len(groups)} jobs")
    results, errors = [], []

    def run_group(key):
        v, s = key
        out = []
        for m, inv in groups[key]:
            job = (v, s, m, inv)
            try:
                row = backtest(job)
                out.append(("row", job, row))
            except Exception as e:
                out.append(("error", job, {"pipenv": v, "shape": s, "mode": m, "invocation": inv, "error": str(e)[-3000:], "trace": traceback.format_exc()[-1500:]}))
            yield out[-1]

    def flush():
        save(root / "summary.json", {"provenance": provenance, "results": sorted(results, key=lambda r: (vtuple(r["pipenv"]), r["shape"], r["mode"], r["invocation"])), "errors": errors})

    def consume(key):
        for kind, job, payload in run_group(key):
            with log_lock:
                if kind == "row":
                    results.append(payload)
                    failed = [k for k, ok in payload["checks"].items() if not ok]
                    print(*job, "PASS" if payload["passed"] else "FAIL", ",".join(failed), flush=True)
                else:
                    errors.append(payload)
                    print(*job, "ERROR", payload["error"][-300:].replace("\n", " "), flush=True)
                flush()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        list(pool.map(consume, list(groups)))
    flush()
    summary = json.loads((root / "summary.json").read_text())
    (root / "summary.md").write_text(render_table(summary))
    say(render_table(summary))
    if errors or any(not r["passed"] for r in results):
        sys.exit(1)


def _flag(cases, key, sub=None, sub2=None):
    vals = set()
    for c in cases:
        i = c.get("info", {}).get(key)
        if isinstance(i, dict) and sub is not None:
            i = i.get(sub)
        if isinstance(i, dict) and sub2 is not None:
            i = i.get(sub2)
        if isinstance(i, (bool, int, str)):
            vals.add(i)
    return "/".join(sorted(str(v).lower() for v in vals)) or "n/a"


def render_doc_table(summary):
    """Per-version compatibility table for docs/testing/pipenv-compatibility.md."""
    rows = summary["results"]
    by = {}
    for r in rows:
        by.setdefault(r["pipenv"], []).append(r)
    lines = [
        "| Pipenv | hosted | vendored | agent (in-project venv) | agent (out-of-tree venv) | bare CLI sees out-of-tree venv | tamper rejected (hosted / vendored) | warm venv re-installed (hosted / vendored) | relock keeps patch (hosted / vendored) | `pipenv verify` (hosted / vendored) |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]

    def cell(cases):
        if not cases:
            return "n/a"
        refused = [c for c in cases if c.get("supported") is False]
        if refused and len(refused) == len(cases):
            ok = sum(1 for c in cases if c["passed"])
            return ("refused" if ok == len(cases) else f"refused {ok}/{len(cases)}") + " (" + refused[0]["expected"].split("(")[-1].rstrip(")") + ")"
        ok = sum(1 for c in cases if c["passed"])
        shapes = ",".join(sorted({c["shape"] for c in cases}))
        return ("pass" if ok == len(cases) else f"{ok}/{len(cases)}") + f" ({shapes})"

    def yes_no(cases, key, sub):
        vals = {c["info"][key][sub] for c in cases if isinstance(c.get("info", {}).get(key), dict)}
        if not vals:
            return "n/a"
        return "/".join("yes" if v else "no" for v in sorted(vals, key=lambda x: not x))

    for version in sorted(by, key=vtuple):
        cs = by[version]
        m = lambda mode: [c for c in cs if c["mode"] == mode and c["invocation"] == "in-dir"]
        hosted, vendored = m("hosted"), m("vendored")
        dh = [c for c in hosted if c["shape"] == "direct" and c.get("supported")]
        dv = [c for c in vendored if c["shape"] == "direct" and c.get("supported")]
        tamper = f"{'yes' if any(c['info'].get('tamper', {}).get('installExit') not in (None, 0) for c in dh) else ('n/a' if not dh else 'no')} / {'yes' if any(c['info'].get('tamper', {}).get('installExit') not in (None, 0) for c in dv) else ('n/a' if not dv else 'no')}"
        warm = f"{_flag(dh, 'warmReinstalled', 'install', 'patched')} / {_flag(dv, 'warmReinstalled', 'install', 'patched')}"
        relock = f"{_flag(dh, 'relock', 'patchSourceKept')} / {_flag(dv, 'relock', 'patchSourceKept')}"
        verify = f"{_flag(dh, 'verify', 'exit')} / {_flag(dv, 'verify', 'exit')}"
        oot = m("agent-oot")
        sees = "/".join(sorted({str(c["checks"].get("bareScanSeesPipenvVenv")).lower() for c in oot})) if oot else "n/a"
        lines.append(f"| {version} | {cell(hosted)} | {cell(vendored)} | {cell(m('agent'))} | {cell(oot)} | {sees} | {tamper} | {warm} | {relock} | {verify} |")
    return "\n".join(lines)


def render_table(summary):
    rows = summary["results"]
    lines = ["| Pipenv | shape | mode | invocation | passed | failed checks | notes |", "| --- | --- | --- | --- | --- | --- | --- |"]
    for r in sorted(rows, key=lambda r: (vtuple(r["pipenv"]), r["shape"], r["mode"], r["invocation"])):
        failed = ", ".join(k for k, ok in r["checks"].items() if not ok)
        notes = []
        info = r.get("info", {})
        if r.get("expected"):
            notes.append(r["expected"])
        if "sourceKeys" in info:
            notes.append("source key " + ",".join(info["sourceKeys"]))
        if "warmReinstalled" in info:
            notes.append("warm reinstalled " + ",".join(f"{k}={v['patched']}" for k, v in info["warmReinstalled"].items()))
        if "relock" in info:
            notes.append(f"relock exit {info['relock'].get('exit')} keeps patch={info['relock'].get('patchSourceKept')}")
        if "tamper" in info:
            notes.append(f"tamper install exit {info['tamper']['installExit']}")
        if "verify" in info:
            notes.append(f"verify exit {info['verify']['exit']}")
        if "requirementsExport" in info:
            notes.append(f"requirements exports patch ref={info['requirementsExport'].get('exportsPatchRef')}")
        if "lockOnly" in info:
            notes.append(f"lock-only applied={info['lockOnly']['applied']} {info['lockOnly']['codes']}")
        if "bareScan" in info:
            notes.append(f"bare scan sees venv={r['checks'].get('bareScanSeesPipenvVenv')} apply via {info.get('applyPath')}")
        if "vex" in info:
            notes.append(f"vex exit {info['vex'].get('exit')} stmts={info['vex'].get('statements')}")
        lines.append(f"| {r['pipenv']} | {r['shape']} | {r['mode']} | {r['invocation']} | {'PASS' if r['passed'] else 'FAIL'} | {failed} | {'; '.join(notes)} |")
    for e in summary.get("errors", []):
        lines.append(f"| {e.get('pipenv')} | {e.get('shape')} | {e.get('mode')} | {e.get('invocation')} | ERROR | {e['error'][-160:].replace(chr(10), ' ')} | |")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
