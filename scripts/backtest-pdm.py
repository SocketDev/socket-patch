#!/usr/bin/env python3
"""Drive the real socket-patch CLI and real PDM releases through hosted,
vendored and agent mode on native pdm.lock generations.

For every PDM version the harness bootstraps that exact release with uv
(per-era dependency pins, see `pins_for`), generates a native lock for a
one-dependency project (urllib3 1.26.18, which has a public free-tier Socket
patch) in a number of project shapes, then for each mode:

  hosted    scan --mode hosted   -> pdm sync -> installed bytes == patch
  vendored  scan --mode vendored -> pdm sync -> installed bytes == patch
  agent     pdm sync -> scan --mode agent    -> installed bytes == patch

and checks idempotent re-scans, unchanged pyproject, lock byte-stability
across `pdm sync` / `pdm install`, `pdm lock --check`, tampered-hash
rejection, what PDM's own relock does to the patch source (and whether a
re-scan + rollback still restores the relocked bytes), `pdm export`, and
`rollback` restoring every byte.  Lock formats the CLI does not support
(lock_version 3.1 / 4.0 / 4.1 / 4.2, PDM 0.8's version-less lock) must be
REFUSED with the lock untouched while the native install keeps working; the
`two-versions` and `custom-lockfile` shapes are likewise expected no-ops.

Shapes: direct, transitive (overrides / pinned resolution), dev, optional,
extras, marker, marker-excluded, platform-linux, platform-windows, crlf,
static-urls (>= 2.11), space-unicode, dependency-groups (PEP 735, >= 2.20),
multi-target (>= 2.17), two-versions (>= 2.17), custom-lockfile (`-L`),
pep582 (`__pypackages__` layout).

Every case is fully isolated: its own project dir, HOME, PDM config + cache,
and venv.  Needs network (PyPI + patch.socket.dev), uv, and no Socket token.

Usage:
  scripts/backtest-pdm.py --socket-patch target/debug/socket-patch \\
      --socket-patch-revision <sha> --output /tmp/pdm-backtest \\
      [--versions 2.29.2 ...] [--modes hosted vendored agent] \\
      [--shapes direct ...] [--jobs 4] [--tools-dir <dir-with-<version>-venvs>]
  scripts/backtest-pdm.py --render-doc-table /tmp/pdm-backtest/summary.json
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

VERSIONS = [
    "0.8.7", "0.12.3",
    "1.0.0", "1.4.5", "1.8.5", "1.12.8", "1.15.5",
    "2.0.3", "2.1.5", "2.2.1", "2.3.4", "2.4.9", "2.5.6", "2.6.1", "2.7.4",
    "2.8.0", "2.8.2", "2.9.0", "2.9.3", "2.10.0", "2.10.4", "2.11.0", "2.11.2",
    "2.12.4", "2.13.3", "2.14.0", "2.15.4", "2.16.1", "2.17.0", "2.17.3",
    "2.18.2", "2.19.3", "2.20.0", "2.20.1", "2.21.0", "2.22.0", "2.22.4",
    "2.23.1", "2.24.2", "2.25.0", "2.25.9", "2.26.0", "2.26.9", "2.27.0",
    "2.28.2", "2.29.0", "2.29.2",
]
MODES = ["hosted", "vendored", "agent"]
SHAPES = [
    "direct", "transitive", "dev", "optional", "extras", "marker",
    "marker-excluded", "platform-linux", "platform-windows", "crlf",
    "static-urls", "space-unicode", "dependency-groups", "multi-target",
    "two-versions", "custom-lockfile", "pep582",
]
# What the PR's shared rewriter accepts; anything else must be refused.
SUPPORTED_LOCK_VERSIONS = {"2", "4.3", "4.4", "4.4.1", "4.5.0", "4.5.1"}
# Shapes where the CLI is EXPECTED to leave the lock alone.
EXPECTED_NOOP_SHAPES = {"two-versions", "custom-lockfile"}
# Shapes whose requirement marker excludes this host (package never installed).
def excluded_shape(shape):
    return (
        shape == "marker-excluded"
        or (shape == "platform-windows" and os.name != "nt")
        or (shape == "platform-linux" and platform.system() != "Linux")
    )

PROJECT_NAME = "pdm-patch-backtest"
PATCH_UUID = "e828efa5-5c6d-43f3-9909-03f5ac232b98"
PURL_BASE = "pkg:pypi/urllib3@1.26.18"
HOSTED_MARKER = b"patch.socket.dev"
VENDORED_MARKER = b".socket/vendor/pypi"
TRANSITIVE_PINS = [
    ("urllib3", "1.26.18"),
    ("charset-normalizer", "3.3.2"),
    ("idna", "3.6"),
    ("certifi", "2024.2.2"),
]
FIXTURES = Path(__file__).resolve().parents[1] / "crates/socket-patch-core/tests/fixtures/pdm-native"

ORACLE = """import hashlib,importlib.util,json,pathlib,sys
spec=importlib.util.find_spec('urllib3')
root=pathlib.Path(spec.origin).parent.parent if spec and spec.origin else pathlib.Path('/missing')
checks={}
for name,expected in json.loads(sys.argv[1]).items():
    p=root/name
    data=p.read_bytes() if p.is_file() else b''
    checks[name]=p.is_file() and hashlib.sha256(('blob %d\\0'%len(data)).encode()+data).hexdigest()==expected
print(json.dumps(dict(installed=spec is not None, origin=(spec.origin if spec else None), files=checks)))
"""
# Content hash + freshness through PDM's own API (constructor changed in
# 1.12 and the hash method moved in 2.x, hence the fallbacks).
HASH_SNIPPET = """import json,sys
algo=sys.argv[1]
def project():
    from pdm.project.core import Project
    try:
        return Project()
    except TypeError:
        from pdm.core import Core
        core=Core()
        try:
            return core.create_project('.')
        except Exception:
            return Project(core, '.')
p=project()
out={}
try:
    out['hash']=p.get_content_hash(algo)
except Exception:
    try:
        out['hash']=p.pyproject.content_hash(algo)
    except Exception as e:
        out['hashError']=repr(e)
try:
    out['fresh']=bool(p.is_lockfile_hash_match())
except Exception as e:
    out['freshError']=repr(e)
print(json.dumps(out))
"""
NETWORK_RE = re.compile(
    r"ConnectionError|ConnectTimeout|ReadTimeout|Temporary failure|timed out|"
    r"Connection reset|RemoteDisconnected|Max retries exceeded|"
    r"HTTP Error 5\d\d|503|502|Failed to (fetch|download)|error sending request|"
    r"network is unreachable|NewConnectionError|SSLError",
    re.I,
)
DEFAULT_TIMEOUT = int(os.environ.get("BACKTEST_TIMEOUT", "600"))


def vtuple(v):
    return tuple(int(x) for x in v.split("."))


def python_for(version):
    v = vtuple(version)
    if v < (2, 0):
        return "3.8"
    if v < (2, 21):
        return "3.11"
    if v < (2, 27):
        return "3.12"
    return "3.13"


def pins_for(version):
    """Per-era bootstrap pins.  0.x and 1.x carry unpinned upper bounds that
    modern PyPI resolves to incompatible releases (pythonfinder >= 2 lost
    `pythonfinder.models.python`, packaging >= 22 lost LegacyVersion, pip
    moved the shims PDM 1.x imports, resolvelib >= 0.6 renamed the identify
    argument PDM 1.0 uses).  Verified on macOS arm64 against real binaries."""
    v = vtuple(version)
    pins = ["pdm==" + version, "setuptools==57.5.0", "wheel==0.37.1"]
    if v < (1, 0):
        pins += [
            "pip==20.2.4" if v < (0, 9) else "pip==20.3.4",
            "six==1.17.0", "toml==0.10.2", "tomlkit==0.7.2", "click==7.1.2",
            "pythonfinder==1.2.10", "resolvelib==0.5.5", "packaging==20.9",
            "requests==2.27.1",
        ]
    elif v < (1, 15):
        if v < (1, 5):
            pins += ["pip==20.3.4", "requests==2.27.1"]
        elif v < (1, 12):
            pins += ["pip==21.3.1", "requests==2.31.0"]
        else:
            pins += ["pip==22.0.4", "requests==2.31.0"]
        pins += ["six==1.17.0", "toml==0.10.2", "pythonfinder==1.2.10", "packaging==20.9"]
        if v < (1, 1):
            pins.append("resolvelib==0.5.5")
    elif v < (2, 0):
        pins += ["pip==22.0.4", "requests==2.31.0"]
    else:
        pins += ["pip==24.0"]
    return pins


def required_pins(version):
    """Subset of pins whose absence means a reused venv is broken."""
    v = vtuple(version)
    if v >= (1, 15):
        return []
    return [p for p in pins_for(version) if p.split("==")[0] in ("pip", "pythonfinder", "packaging", "toml", "six", "resolvelib")]


def legacy_manifest(version, shape=None):
    """PDM < 1.5: `[tool.pdm]` metadata, flat `<group>-dependencies` tables,
    `-s SECTION` selection.  1.5 introduced dependency groups and `-G`.

    Exception: the transitive shape on 1.0-1.4 uses PEP 621 `[project]`
    metadata (which those releases accept) because PDM 1.0-1.4 rewrite
    legacy metadata into `[project]` on every lock/install, and the
    pinned-resolution trick restores the manifest after locking."""
    v = vtuple(version)
    if shape == "transitive" and (1, 0) <= v < (1, 5):
        return False
    return v < (1, 5)


def honours_config_file(version):
    """PDM_CONFIG_FILE is honoured from 1.15; earlier releases read only
    ~/.pdm/config.toml (so each case gets its own HOME)."""
    return vtuple(version) >= (1, 15)


def shape_applies(version, shape):
    v = vtuple(version)
    if shape == "static-urls":
        return v >= (2, 11)
    if shape == "dependency-groups":
        return v >= (2, 20)
    if shape in ("multi-target", "two-versions"):
        return v >= (2, 17)
    if shape == "custom-lockfile":
        return v >= (1, 5)  # `pdm lock -L` (checked again against --help)
    return True


def wanted(version, shape, mode):
    if not shape_applies(version, shape):
        return False
    if mode == "agent" and (excluded_shape(shape) or shape in EXPECTED_NOOP_SHAPES):
        return False
    return True


def save(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def lock_version_of(text):
    m = re.search(r'lock_version = "([^"]+)"', text)
    return m.group(1) if m else None


class Run:
    """Run a command with a per-case env, log everything, kill the whole
    process group on timeout, optionally retry once on network flakes."""

    def __init__(self, cmd, cwd, env, log, timeout=None, retry=False):
        self.cmd = [str(c) for c in cmd]
        timeout = timeout or DEFAULT_TIMEOUT
        attempts = 0
        while True:
            attempts += 1
            self.rc, self.out = self._exec(cwd, env, timeout)
            if self.rc == 0 or not retry or attempts >= 2 or not NETWORK_RE.search(self.out):
                break
            time.sleep(5)
        self.attempts = attempts
        Path(log).write_text(
            "$ " + " ".join(self.cmd) + f"\n# cwd {cwd}\n# exit {self.rc} (attempts {attempts})\n--- output\n{self.out}",
            encoding="utf-8",
        )

    def _exec(self, cwd, env, timeout):
        with subprocess.Popen(
            self.cmd, cwd=str(cwd), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=os.name != "nt",
        ) as proc:
            try:
                out, _ = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], check=False, capture_output=True)
                else:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                out, _ = proc.communicate()
                return 124, out.decode("utf-8", "replace") + f"\nTIMEOUT after {timeout}s"
            return proc.returncode, out.decode("utf-8", "replace")

    def ok(self):
        return self.rc == 0

    def tail(self, n=500):
        return self.out[-n:]

    def json(self):
        i = self.out.find("{")
        if i < 0:
            raise RuntimeError("no JSON in output: " + self.out[-2000:])
        return json.loads(self.out[i:])

    def json_or_empty(self):
        try:
            return self.json()
        except Exception:
            return {}


def require(r, what):
    if not r.ok():
        raise RuntimeError(f"{what} failed (exit {r.rc}):\n{r.tail(4000)}")
    return r


def base_env():
    env = {
        k: v for k, v in os.environ.items()
        if not k.startswith(("PDM_", "PIP_", "PYTHON", "SOCKET_", "UV_", "VIRTUAL_ENV", "CONDA_"))
    }
    env.update(
        PDM_CHECK_UPDATE="false",
        PDM_PYPI_URL="https://pypi.org/simple",
        PIP_CONFIG_FILE=os.devnull,
        PIP_DISABLE_PIP_VERSION_CHECK="1",
        PYTHONIOENCODING="utf-8",
        PYTHONDONTWRITEBYTECODE="1",
        NO_COLOR="1",
        SOCKET_NO_CONFIG="1",
        SOCKET_NO_UPDATE_CHECK="1",
        SOCKET_TELEMETRY_DISABLED="1",
    )
    if platform.system() == "Linux":
        # Python 3.8 still calls pthread_exit when a worker finishes. glibc
        # lazily loads libgcc_s there and can abort during concurrent installs:
        # "libgcc_s.so.1 must be installed for pthread_exit to work". Load it
        # before threads start, including in PDM's build subprocesses. Keep
        # Python 3.8 coverage and the install assertions instead of retrying
        # (or skipping) interpreter crashes. CPython's documented workaround:
        # https://github.com/python/cpython/issues/88600#issuecomment-1093919486
        env["LD_PRELOAD"] = " ".join(filter(None, ("libgcc_s.so.1", env.get("LD_PRELOAD"))))
    return env


# --------------------------------------------------------------- manifests

def requirement(shape):
    target = "requests==2.31.0" if shape == "transitive" else "urllib3==1.26.18"
    if shape == "extras":
        target = "urllib3[socks]==1.26.18"
    if shape in ("marker", "marker-excluded"):
        target += "; python_version " + (">" if shape == "marker-excluded" else "<") + " '4'"
    if shape.startswith("platform-"):
        target += "; sys_platform == '" + ("win32" if shape == "platform-windows" else "linux") + "'"
    return target


def project_text(version, shape, overrides=True):
    """pyproject.toml for `shape` as `version` understands it."""
    if legacy_manifest(version, shape):
        text = f'[tool.pdm]\nname = "{PROJECT_NAME}"\nversion = "0.0.0"\npython_requires = ">=3.8"\n'
        group = {"dev": "dev-dependencies", "optional": "feature-dependencies"}.get(shape, "dependencies")
        if group != "dependencies":
            text += "\n[tool.pdm.dependencies]\n"
        text += f"\n[tool.pdm.{group}]\n"
        if shape == "extras":
            text += 'urllib3 = {version = "==1.26.18", extras = ["socks"]}\n'
        elif shape in ("marker", "marker-excluded") or shape.startswith("platform-"):
            marker = requirement(shape).split("; ", 1)[1]
            text += "urllib3 = {version = \"==1.26.18\", marker = " + json.dumps(marker) + "}\n"
        else:
            name, pin = requirement(shape).split("==")
            text += f'{name} = "=={pin}"\n'
        return text
    text = f'[project]\nname = "{PROJECT_NAME}"\nversion = "0.0.0"\nrequires-python = ">=3.8"\n'
    if shape == "two-versions":
        text += 'dependencies = [\n    "urllib3==1.26.18; python_version < \'3.10\'",\n    "urllib3==2.2.3; python_version >= \'3.10\'",\n]\n'
    elif shape in ("dev", "optional", "dependency-groups"):
        text += "dependencies = []\n"
        if shape == "dev":
            text += "\n[tool.pdm.dev-dependencies]\nqa = " + json.dumps([requirement(shape)]) + "\n"
        elif shape == "optional":
            text += "\n[project.optional-dependencies]\nfeature = " + json.dumps([requirement(shape)]) + "\n"
        else:
            text += "\n[dependency-groups]\ndev = " + json.dumps([requirement(shape)]) + "\n"
    else:
        text += "dependencies = " + json.dumps([requirement(shape)]) + "\n"
    text += "\n[tool.pdm]\ndistribution = false\n"
    if shape == "transitive" and overrides and vtuple(version) >= (2, 0):
        table = "[tool.pdm.resolution.overrides]" if vtuple(version) >= (2, 11) else "[tool.pdm.overrides]"
        text += "\n" + table + "\n" + "".join(f'{n} = "=={p}"\n' for n, p in TRANSITIVE_PINS)
    return text


def transitive_pinned_text(version):
    """PDM < 2.0 has no resolution overrides: lock with the pins as direct
    requirements, then restore the real manifest and recompute the content
    hash (same trick as the depscan reference harness)."""
    if legacy_manifest(version, "transitive"):
        return project_text(version, "transitive") + "".join(f'{n} = "=={p}"\n' for n, p in TRANSITIVE_PINS)
    deps = ["requests==2.31.0"] + [f"{n}=={p}" for n, p in TRANSITIVE_PINS]
    return project_text(version, "transitive").replace(
        "dependencies = " + json.dumps(["requests==2.31.0"]), "dependencies = " + json.dumps(deps)
    )


def host_platform():
    return {"Darwin": "macos", "Linux": "linux", "Windows": "windows"}.get(platform.system(), "linux")


# ------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--socket-patch", type=Path, help="socket-patch CLI binary")
    ap.add_argument("--socket-patch-revision", help="git revision of the CLI, recorded in the summary")
    ap.add_argument("--output", type=Path, help="output directory (tools, originals, cases, summary)")
    ap.add_argument("--versions", nargs="+", default=VERSIONS)
    ap.add_argument("--modes", nargs="+", default=MODES, choices=MODES)
    ap.add_argument("--shapes", nargs="+", default=SHAPES, choices=SHAPES)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--tools-dir", type=Path, help="reuse <dir>/<version> PDM venvs (re-bootstrapped in place when broken)")
    ap.add_argument("--keep-environments", action="store_true", help="keep each case's venv, HOME and PDM cache (default: pruned after the case, logs and result.json stay)")
    ap.add_argument("--render-doc-table", type=Path, metavar="SUMMARY_JSON", help="print the docs table from an existing summary.json and exit")
    args = ap.parse_args()
    if args.render_doc_table:
        summary = json.loads(args.render_doc_table.read_text(encoding="utf-8"))
        print(render_doc_table(summary))
        return
    missing = [f for f, v in [("--socket-patch", args.socket_patch), ("--socket-patch-revision", args.socket_patch_revision), ("--output", args.output)] if v is None]
    if missing:
        ap.error("the following arguments are required: " + ", ".join(missing))

    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=True)
    cli = args.socket_patch.resolve()
    tools_root = args.tools_dir.resolve() if args.tools_dir else root / "tools"
    tools_root.mkdir(parents=True, exist_ok=True)
    (root / "tool-logs").mkdir(exist_ok=True)
    env = base_env()
    env["UV_CACHE_DIR"] = str(root / "uv-cache")
    say_lock = threading.Lock()

    def say(*a):
        with say_lock:
            print(*a, flush=True)

    provenance = {
        "capturedAt": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "hostPython": sys.version.split()[0],
        "cliPath": str(cli),
        "cliRevision": args.socket_patch_revision,
        "cliSha256": sha256_file(cli),
        "cliVersion": subprocess.run([str(cli), "--version"], capture_output=True, text=True, env=env).stdout.strip(),
        "uvVersion": subprocess.run(["uv", "--version"], capture_output=True, text=True, env=env).stdout.strip(),
        "pdmVersions": args.versions,
        "modes": args.modes,
        "shapes": args.shapes,
        "patchUuid": PATCH_UUID,
        "toolsDir": str(tools_root),
    }

    # ------------------------------------------------------------ tools
    def tool_paths(version):
        venv = tools_root / version
        return venv, venv / "bin/pdm", venv / "bin/python"

    def tool_healthy(version, log_prefix):
        venv, pdm, python = tool_paths(version)
        if not pdm.exists():
            return False, "missing"
        r = Run([pdm, "--version"], root, env, log_prefix + "-version.log", timeout=120)
        if not r.ok() or "version" not in r.out.lower():
            return False, "pdm --version failed: " + r.tail(300).strip().splitlines()[-1] if r.out.strip() else "pdm --version failed"
        frozen = Run(["uv", "pip", "freeze", "--python", python], root, env, log_prefix + "-freeze.log", timeout=120).out
        missing = [p for p in required_pins(version) if p not in frozen]
        if missing:
            return False, "pins missing: " + " ".join(missing)
        return True, frozen

    def bootstrap(version):
        venv, pdm, python = tool_paths(version)
        log_prefix = str(root / "tool-logs" / version)
        record = {"version": version, "python": python_for(version), "pins": pins_for(version), "reused": venv.exists(), "path": str(venv)}
        healthy, detail = tool_healthy(version, log_prefix)
        if not healthy:
            record["rebootstrapReason"] = detail if venv.exists() else "not installed"
            if venv.exists():
                shutil.rmtree(venv)
            r = Run(["uv", "venv", "--quiet", "--python", python_for(version), venv], root, env, log_prefix + "-venv.log", timeout=600, retry=True)
            if not r.ok():
                record["error"] = "uv venv: " + r.tail(600)
                return record
            r = Run(["uv", "pip", "install", "--quiet", "--python", python, *pins_for(version)], root, env, log_prefix + "-install.log", timeout=900, retry=True)
            if not r.ok():
                record["error"] = "uv pip install: " + r.tail(1200)
                return record
            healthy, detail = tool_healthy(version, log_prefix)
            if not healthy:
                record["error"] = "unhealthy after bootstrap: " + detail
                return record
        record["frozen"] = [l for l in detail.splitlines() if "==" in l]
        record["ok"] = True
        return record

    # per-(version, subcommand) --help text cache
    help_cache, help_lock = {}, threading.Lock()

    def pdm_help(version, subcommand):
        key = (version, subcommand)
        with help_lock:
            if key in help_cache:
                return help_cache[key]
        _, pdm, _ = tool_paths(version)
        r = Run([pdm, subcommand, "--help"], root, env, root / "tool-logs" / f"{version}-help-{subcommand}.log", timeout=120)
        with help_lock:
            help_cache[key] = r.out
        return r.out

    def install_cmd(version, verb, groups, lockfile=None):
        _, pdm, _ = tool_paths(version)
        cmd = [pdm, verb]
        if "--no-self" in pdm_help(version, verb):
            cmd.append("--no-self")
        cmd += groups
        if lockfile:
            cmd += ["-L", lockfile]
        return cmd

    def group_flags(version, shape):
        legacy = legacy_manifest(version, shape)
        if shape == "dev":
            return ["-d"] if legacy else ["-d", "-G", "qa"]
        if shape == "optional":
            return ["-s", "feature"] if legacy else ["-G", "feature"]
        if shape == "dependency-groups":
            return ["-d", "-G", "dev"]
        return []

    # ------------------------------------------------------ environments
    def write_configs(version, project, home, cache, pep582):
        """Per-case PDM config: PDM_CONFIG_FILE for >= 1.15, ~/.pdm/config.toml
        (via the case HOME) for older releases.  `use_venv` makes 0.x/1.x
        install into the project venv instead of __pypackages__."""
        (home / ".pdm").mkdir(parents=True, exist_ok=True)
        cache.mkdir(parents=True, exist_ok=True)
        v = vtuple(version)
        lines = ["cache_dir = " + json.dumps(str(cache))]
        if honours_config_file(version):
            lines.append("check_update = false")
            lines.append("python.use_venv = " + ("false" if pep582 else "true"))
        else:
            if v >= (1, 5):
                lines.append("check_update = false")
            lines.append("use_venv = " + ("false" if pep582 else "true"))
        text = "\n".join(lines) + "\n"
        (project / "native-config.toml").write_text(text, encoding="utf-8")
        (home / ".pdm" / "config.toml").write_text(text, encoding="utf-8")

    def pdm_env(version, project, home, cache, venv=None):
        _, pdm, _ = tool_paths(version)
        e = dict(env)
        e["HOME"] = str(home)
        e["PATH"] = str(pdm.parent) + os.pathsep + e.get("PATH", "")
        e["PDM_CONFIG_FILE"] = str(project / "native-config.toml")
        e["PDM_CACHE_DIR"] = str(cache)
        if venv is not None:
            # Select the project venv through VIRTUAL_ENV: `pdm use -f
            # <venv>/bin/python` dereferences the uv venv symlink to the base
            # interpreter on 0.x, 1.x and early 2.x (2.0.3 then silently
            # installs into __pypackages__), while VIRTUAL_ENV + use_venv is
            # honoured by every release tested (0.12 .. 2.29).
            e["VIRTUAL_ENV"] = str(venv)
        return e

    def cli_env(version, home):
        _, pdm, _ = tool_paths(version)
        e = dict(env)
        e["HOME"] = str(home)
        e["PATH"] = str(pdm.parent) + os.pathsep + e.get("PATH", "")
        return e

    def select_python(version, project, penv, log, venv=None):
        """Point PDM at the case interpreter.  With a venv, VIRTUAL_ENV in
        `penv` does the selecting (see `pdm_env`); for the PEP 582 layout
        `pdm use -f <base interpreter>` so no release mistakes the PDM tool
        venv on PATH for the target."""
        _, pdm, tool_python = tool_paths(version)
        if venv is not None:
            return None
        base_python = Path(os.path.realpath(tool_python))
        return Run([pdm, "use", "-f", base_python], project, penv, log, timeout=300)

    def make_venv(version, venv, cwd, log, packages=()):
        _, _, tool_python = tool_paths(version)
        require(Run(["uv", "venv", "--quiet", "--python", tool_python, venv], cwd, env, log, timeout=300, retry=True), "uv venv")
        if packages:
            require(Run(["uv", "pip", "install", "--quiet", "--python", venv / "bin/python", *packages], cwd, env, str(log) + ".pip", timeout=600, retry=True), "venv bootstrap")

    def content_hash(version, project, penv, log, algo="sha256"):
        _, _, tool_python = tool_paths(version)
        r = Run([tool_python, "-c", HASH_SNIPPET, algo], project, penv, log, timeout=300)
        try:
            return json.loads(r.out.strip().splitlines()[-1])
        except Exception:
            return {"error": r.tail(800)}

    # ------------------------------------------------------- originals
    original_locks = {}
    original_guard = threading.Lock()

    def original_lock_for(version, shape):
        key = (version, shape)
        with original_guard:
            if key not in original_locks:
                original_locks[key] = threading.Lock()
            lock = original_locks[key]
        with lock:
            return generate_original(version, shape)

    def lock_filename(shape):
        return "custom.lock" if shape == "custom-lockfile" else "pdm.lock"

    def generate_original(version, shape):
        """Generate (once) the pristine pyproject + lock for version/shape.
        Returns the directory plus generation metadata."""
        original = root / "original" / version / shape
        meta_path = original / "generation.json"
        if meta_path.exists():
            return original, json.loads(meta_path.read_text(encoding="utf-8"))
        if original.exists():
            shutil.rmtree(original)
        original.mkdir(parents=True)
        home, cache = original / "home", original / "native-cache"
        write_configs(version, original, home, cache, pep582=True)
        penv = pdm_env(version, original, home, cache)
        _, pdm, _ = tool_paths(version)
        meta = {"version": version, "shape": shape, "lockfile": lock_filename(shape), "seededFromFixture": False}
        lock_help = pdm_help(version, "lock")
        if shape == "custom-lockfile" and "-L" not in lock_help:
            meta["skip"] = "pdm lock has no -L/--lockfile on this release"
            save(meta_path, meta)
            return original, meta
        pinned = shape == "transitive" and vtuple(version) < (2, 0)
        (original / "pyproject.toml").write_text(transitive_pinned_text(version) if pinned else project_text(version, shape), encoding="utf-8")
        use = select_python(version, original, penv, original / "use.log")
        if use is not None and not use.ok():
            meta["skip"] = "pdm use failed: " + use.tail(400)
            save(meta_path, meta)
            return original, meta
        # Seed from the checked-in native fixture when one exists and PDM
        # itself agrees it is fresh for this pyproject.
        fixture = FIXTURES / (version + ("-extras" if shape == "extras" else "") + ".lock")
        if shape in ("direct", "extras") and fixture.exists():
            (original / "pdm.lock").write_bytes(fixture.read_bytes())
            fresh = content_hash(version, original, penv, original / "fixture-freshness.log")
            if fresh.get("fresh") is True:
                meta["seededFromFixture"] = str(fixture)
            else:
                meta["fixtureRejected"] = fresh
                (original / "pdm.lock").unlink()
        if not (original / meta["lockfile"]).exists():
            commands = []
            if shape == "multi-target":
                alt = "windows" if host_platform() != "windows" else "linux"
                commands = [[pdm, "lock", "--platform", host_platform()], [pdm, "lock", "--platform", alt, "--append"]]
            elif shape == "two-versions":
                commands = [[pdm, "lock", "--python", ">=3.8,<3.10"], [pdm, "lock", "--python", ">=3.10", "--append"]]
            else:
                cmd = [pdm, "lock"]
                if shape == "optional" and "--group" in lock_help:
                    cmd += ["-G", "feature"]
                if shape == "dependency-groups" and "--group" in lock_help:
                    cmd += ["-G", "dev"]
                if shape == "static-urls":
                    cmd += ["--strategy", "static_urls"]
                if shape == "custom-lockfile":
                    cmd += ["-L", "custom.lock"]
                commands = [cmd]
            for i, cmd in enumerate(commands):
                r = Run(cmd, original, penv, original / f"generation-{i}.log", timeout=900, retry=True)
                if not r.ok():
                    meta["skip"] = f"pdm lock failed (exit {r.rc}): " + r.tail(600)
                    save(meta_path, meta)
                    return original, meta
            meta["lockCommands"] = [[str(c) for c in cmd[1:]] for cmd in commands]
        lock_path = original / meta["lockfile"]
        written = transitive_pinned_text(version) if pinned else project_text(version, shape)
        # PDM 1.0-1.4 rewrite legacy `[tool.pdm]` metadata into `[project]`
        # while locking; the migrated file is what the cases start from.
        meta["pyprojectMigratedByPdm"] = (original / "pyproject.toml").read_text(encoding="utf-8") != written
        if pinned:
            (original / "pyproject.toml").write_text(project_text(version, shape), encoding="utf-8")
            algo = "md5" if b'content_hash = "md5:' in lock_path.read_bytes() else "sha256"
            digest = content_hash(version, original, penv, original / "content-hash.log", algo)
            if digest.get("hash"):
                lock_path.write_text(
                    re.sub(r'content_hash = "(sha256|md5):[a-f0-9]+"', f'content_hash = "{algo}:{digest["hash"]}"', lock_path.read_text(encoding="utf-8")),
                    encoding="utf-8",
                )
                meta["contentHashRecomputed"] = True
            else:
                meta["contentHashRecomputeFailed"] = digest
        if shape == "crlf":
            for name in ("pyproject.toml", "pdm.lock"):
                p = original / name
                p.write_bytes(p.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
        text = lock_path.read_text(encoding="utf-8", errors="replace")
        meta["lockVersion"] = lock_version_of(text)
        meta["lockHasTarget"] = re.search(r'name = "urllib3"\s*\n(?:[^\n]*\n)*?version = "1\.26\.18"', text) is not None or re.search(r'"urllib3(\[[^\]]*\])? 1\.26\.18"', text) is not None
        if not meta["lockHasTarget"]:
            meta["skip"] = "native lock does not pin urllib3 1.26.18 for this shape"
        freshness = content_hash(version, original, penv, original / "freshness.log", "md5" if b'content_hash = "md5:' in lock_path.read_bytes() else "sha256")
        meta["baselineFresh"] = freshness.get("fresh")
        meta["freshness"] = freshness
        for junk in ("__pypackages__", ".venv"):
            shutil.rmtree(original / junk, ignore_errors=True)
        save(meta_path, meta)
        return original, meta

    # -------------------------------------------------------- one case
    def cli_cmd(project, *rest):
        return [cli, *rest, "--cwd", project, "--json", "--yes", "--no-telemetry"]

    def applied_count(mode, envelope):
        if mode == "hosted":
            return envelope.get("redirect", {}).get("redirected", 0)
        if mode == "vendored":
            return envelope.get("vendor", {}).get("summary", {}).get("applied", 0)
        return envelope.get("apply", {}).get("applied", 0)

    def refusal_codes(mode, envelope):
        if mode == "hosted":
            return sorted({w.get("code") for w in envelope.get("redirect", {}).get("warnings", []) if w.get("code")})
        if mode == "vendored":
            return sorted({e.get("errorCode") for e in envelope.get("vendor", {}).get("events", []) if e.get("errorCode")})
        return sorted({p.get("errorCode") for p in envelope.get("apply", {}).get("patches", []) if p.get("errorCode")})

    def record_hashes(project, mode):
        """The first patch record the mode's store holds: the redirect ledger's
        `records` (hosted), the vendor ledger entry's embedded `record`
        (vendored — vendored mode never writes `.socket/manifest.json`), or the
        manifest's `patches` (agent)."""
        ledger = project / {"hosted": ".socket/vendor/redirect-state.json", "vendored": ".socket/vendor/state.json"}.get(mode, ".socket/manifest.json")
        if not ledger.exists():
            return {}, {}, None
        data = json.loads(ledger.read_text(encoding="utf-8"))
        if mode == "hosted":
            recs = data.get("records") or {}
        elif mode == "vendored":
            recs = {k: e.get("record") for k, e in (data.get("entries") or {}).items() if e.get("record")}
        else:
            recs = data.get("patches") or {}
        if not recs:
            return {}, {}, None
        rec = next(iter(recs.values()))
        files = rec.get("files", {})
        return (
            {n: i["afterHash"] for n, i in files.items()},
            {n: i["beforeHash"] for n, i in files.items() if i.get("beforeHash")},
            rec.get("uuid"),
        )

    def ledger_cleared(project, mode):
        if mode == "hosted":
            p = project / ".socket/vendor/redirect-state.json"
            return not p.exists() or not json.loads(p.read_text(encoding="utf-8")).get("records")
        if mode == "vendored":
            # Vendored mode is manifest-free: the ledger is the only store.
            st = project / ".socket/vendor/state.json"
            return not st.exists() or not json.loads(st.read_text(encoding="utf-8")).get("entries")
        mf = project / ".socket/manifest.json"
        return not mf.exists() or json.loads(mf.read_text(encoding="utf-8")).get("patches") in ({}, None)

    def oracle(version, project, penv, hashes, log):
        _, pdm, _ = tool_paths(version)
        r = Run([pdm, "run", "python", "-c", ORACLE, json.dumps(hashes)], project, penv, log, timeout=300)
        try:
            return json.loads(r.out.strip().splitlines()[-1])
        except Exception:
            return {"error": r.tail(600)}

    def patched(res, hashes):
        return bool(hashes) and res.get("installed") is True and all(res.get("files", {}).get(n) for n in hashes)

    def self_install_only(text):
        """PDM < 1.5 has no --no-self and cannot build the fixture project
        (0.8: `Installation failed: <name>`, 1.0-1.4: `Install <name> 0.0.0
        failed` after egg_info / PEP 621 validation); the dependency install
        itself completes before that error.  Only counts when no dependency
        install line failed."""
        name = re.escape(PROJECT_NAME)
        return (
            re.search(rf"Installation failed: {name}|Install {name} 0\.0\.0 failed", text) is not None
            and re.search(r"Install (?!" + name + r")\S+ [^\n]*failed", text) is None
        )

    def prune(case, project):
        if args.keep_environments:
            return
        for path in (project / ".venv", project / "__pypackages__", case / "home", case / "native-cache", case / "saved-socket", project / ".socket"):
            shutil.rmtree(path, ignore_errors=True)

    def backtest(job):
        version, shape, mode = job
        started = time.time()
        row = {"pdm": version, "python": python_for(version), "shape": shape, "mode": mode, "checks": {}, "info": {}, "passed": None, "outcome": None}
        checks, info = row["checks"], row["info"]

        def check(name, value, note=None):
            checks[name] = bool(value)
            if note is not None:
                info[name] = note
            return bool(value)

        def finish(outcome):
            row["outcome"] = outcome
            row["passed"] = outcome in ("PASS", "REFUSED-EXPECTED")
            row["durationSeconds"] = round(time.time() - started, 1)
            origin = info.get("installedOrigin") or info.get("upstreamOrigin") or ""
            if "__pypackages__" in origin:
                row["layout"] = "__pypackages__"
            elif "/.venv/" in origin or "\\.venv\\" in origin:
                row["layout"] = ".venv"
            if row.get("caseDir"):
                save(Path(row["caseDir"]) / "result.json", row)
                prune(Path(row["caseDir"]), Path(row["caseDir"]) / ("project space café" if shape == "space-unicode" else "project"))
            return row

        def native_broken(reason, tail):
            """A native PDM install that fails on the PRISTINE lock is a PDM
            defect for this version/shape, not a patch outcome: SKIP it."""
            info["skip"] = f"native `pdm sync` fails on this release/shape ({reason}): " + tail[-400:].replace("\n", " ")
            return finish("SKIP")

        original, meta = original_lock_for(version, shape)
        row["lockVersion"] = meta.get("lockVersion")
        row["baselineFresh"] = meta.get("baselineFresh")
        row["seededFromFixture"] = bool(meta.get("seededFromFixture"))
        if meta.get("skip"):
            info["skip"] = meta["skip"]
            return finish("SKIP")
        lockname = meta["lockfile"]
        case = root / "cases" / version / shape / mode
        if case.exists():
            shutil.rmtree(case)
        case.mkdir(parents=True)
        row["caseDir"] = str(case)
        project = case / ("project space café" if shape == "space-unicode" else "project")
        project.mkdir()
        for name in ("pyproject.toml", lockname):
            shutil.copyfile(original / name, project / name)
        pristine_lock = (project / lockname).read_bytes()
        pristine_pyproject = (project / "pyproject.toml").read_bytes()
        home, cache = case / "home", case / "native-cache"
        pep582 = shape == "pep582"
        row["layout"] = "__pypackages__" if pep582 else ".venv"
        write_configs(version, project, home, cache, pep582)
        venv = None if pep582 else project / ".venv"
        penv = pdm_env(version, project, home, cache, venv)
        cenv = cli_env(version, home)
        _, pdm, tool_python = tool_paths(version)
        groups = group_flags(version, shape)
        lockflag = "custom.lock" if shape == "custom-lockfile" else None
        sync = install_cmd(version, "sync", groups, lockflag)
        install = install_cmd(version, "install", groups, lockflag)
        excluded = excluded_shape(shape)
        v = vtuple(version)

        def native_sync(log):
            r = Run(sync, project, penv, case / log, timeout=900, retry=True)
            ok = r.ok() or self_install_only(r.out)
            return r, ok

        def uninstall(log):
            if pep582:
                shutil.rmtree(project / "__pypackages__", ignore_errors=True)
                return
            Run(["uv", "pip", "uninstall", "--quiet", "--python", venv / "bin/python", "urllib3"], project, env, case / log, timeout=300)

        # ----------------------------------------------------- hosted probe
        if mode == "hosted" and not pep582:
            r0 = Run(cli_cmd(project, "scan", "--mode", "hosted"), project, cenv, case / "scan-lockonly.log", timeout=600, retry=True)
            e0 = r0.json_or_empty()
            info["lockOnlyHosted"] = {"exit": r0.rc, "redirected": applied_count("hosted", e0), "codes": refusal_codes("hosted", e0), "lockfileOnlyPackages": e0.get("lockfileOnlyPackages"), "scannedPackages": e0.get("scannedPackages"), "crawledUrllib3": sorted(p["purl"] for p in e0.get("packages", []) if "urllib3" in p.get("purl", ""))}
            shutil.rmtree(project / ".socket", ignore_errors=True)
            (project / lockname).write_bytes(pristine_lock)

        # ----------------------------------------------------- environment
        if pep582:
            use = select_python(version, project, penv, case / "use.log")
            if use is not None and not use.ok():
                raise RuntimeError("pdm use failed: " + use.tail(600))
            r, ok = native_sync("install-upstream.log")
            info["upstreamInstall"] = {"exit": r.rc, "tail": r.tail(300)}
            if not ok:
                return native_broken("upstream install", r.out)
        else:
            make_venv(version, venv, project, case / "venv.log", packages=() if mode == "agent" else ("urllib3==1.26.18",))
            use = select_python(version, project, penv, case / "use.log", venv)
            if use is not None and not use.ok():
                raise RuntimeError("pdm use failed: " + use.tail(600))
            if mode == "agent":
                r, ok = native_sync("install-upstream.log")
                info["upstreamInstall"] = {"exit": r.rc, "tail": r.tail(300)}
                if not ok:
                    return native_broken("upstream install", r.out)
        if mode == "agent" or pep582:
            pre = oracle(version, project, penv, {}, case / "oracle-upstream.log")
            info["upstreamOrigin"] = pre.get("origin")

        # ----------------------------------------------------------- scan
        scan_mode = ["--mode", mode]
        r = Run(cli_cmd(project, "scan", *scan_mode), project, cenv, case / "scan.log", timeout=900, retry=True)
        info["scanExit"] = r.rc
        envelope = r.json()
        save(case / "cli-output.json", envelope)
        applied = applied_count(mode, envelope)
        info["applied"] = applied
        info["scannedPackages"] = envelope.get("scannedPackages")
        codes = refusal_codes(mode, envelope)
        info["codes"] = codes
        crawled = sorted(p.get("purl", "") for p in envelope.get("packages", []))
        info["crawledWithPatches"] = crawled
        lock_after = (project / lockname).read_bytes()
        check("pyprojectUnchanged", (project / "pyproject.toml").read_bytes() == pristine_pyproject)

        if pep582 and (
            mode in ("agent", "vendored")
            or not any(p.startswith(PURL_BASE) for p in crawled)
        ):
            # PDM installs into a `__pypackages__` tree the crawler never
            # probes. Hosted redirect rewrites the lock without an install, so
            # a discovered coordinate is enough (handled below); agent (patches
            # installed files) and vendored (rebuilds from, and re-verifies,
            # the install) cannot serve this layout — with no venv the crawler
            # falls through to the `python` on PATH, which is NOT this
            # project's install. Documented `__pypackages__` limitation.
            row["expected"] = "PDM `__pypackages__` layout: agent/vendored cannot verify the install (use hosted, or set `python.use_venv`)"
            if not applied:
                # Refused / no-op (the common case): nothing was written.
                check("lockUnchanged", lock_after == pristine_lock)
                return finish("UNSUPPORTED" if checks["lockUnchanged"] else "FAIL")
            # The CLI still wired/patched something despite the invisible
            # `__pypackages__` layout — vendored via a prebuilt-wheel download,
            # or agent patching the PATH interpreter. The install itself is
            # unverifiable here, but whatever changed MUST be cleanly reversible
            # and must not strand the project.
            info["patchedOutsideProject"] = {"applied": applied, "crawled": crawled}
            rb = Run(cli_cmd(project, "rollback"), project, cenv, case / "rollback.log", timeout=900)
            restored = (
                rb.ok()
                and (project / lockname).read_bytes() == pristine_lock
                and (project / "pyproject.toml").read_bytes() == pristine_pyproject
            )
            info["rollbackOutsideProject"] = {"exit": rb.rc, "restored": restored}
            check("rollbackRestoresUnverifiableWrite", restored)
            return finish("UNSUPPORTED" if restored else "FAIL")

        expected_refusal = mode != "agent" and (row["lockVersion"] not in SUPPORTED_LOCK_VERSIONS or shape in EXPECTED_NOOP_SHAPES)
        if expected_refusal:
            if shape in EXPECTED_NOOP_SHAPES:
                row["expected"] = {"two-versions": "refused: two locked urllib3 versions (forked package)", "custom-lockfile": "no-op: the CLI only reads pdm.lock"}[shape]
            else:
                row["expected"] = f"refused: lock_version {row['lockVersion']!r} is not supported by the rewriter"
            check("appliedZero", applied == 0, {"applied": applied, "codes": codes})
            if shape != "custom-lockfile":
                check("refusalCodeReported", bool(codes), codes)
            check("lockUnchanged", lock_after == pristine_lock)
            if mode == "hosted":
                check("noPatchWiring", ledger_cleared(project, "hosted"))
            else:
                st = project / ".socket/vendor/state.json"
                entries = json.loads(st.read_text(encoding="utf-8")).get("entries") if st.exists() else None
                check("noPatchWiring", not entries and not any((project / ".socket/vendor/pypi").glob("*/*.whl")), {"vendorEntries": sorted(entries or {})})
            # Vendored mode is manifest-free (v5.0): a refused vendored scan
            # must not leave a `.socket/manifest.json` record behind either.
            if mode == "vendored":
                check("noManifestWritten", not (project / ".socket/manifest.json").exists())
            uninstall("uninstall.log")
            r, ok = native_sync("native-install.log")
            if not ok and applied == 0:
                return native_broken("pristine lock", r.out)
            check("nativeInstallOk", ok, {"exit": r.rc, "tail": r.tail(300)})
            res = oracle(version, project, penv, {}, case / "oracle-native.log")
            check("nativeInstallsPackage", res.get("installed") is (not excluded), res)
            info["installedOrigin"] = res.get("origin")
            if applied != 0:
                # Not refused after all: run the full flow and say so.
                row["unexpected"] = "the CLI rewrote a lock the harness expected it to refuse"
            else:
                return finish("REFUSED-EXPECTED" if all(checks.values()) else "FAIL")

        if mode == "agent":
            found = envelope.get("apply", {}).get("found", 0)
            info["found"] = found
            if not check("appliedExactlyOne", applied == 1, {"applied": applied, "found": found, "codes": codes, "status": envelope.get("status")}):
                return finish("FAIL")
            check("lockUnchanged", lock_after == pristine_lock)
            after, before, uuid = record_hashes(project, "agent")
            info["uuid"] = uuid
            check("recordHasFiles", bool(after))
            res = oracle(version, project, penv, after, case / "oracle-1.log")
            info["installedOrigin"] = res.get("origin")
            check("installedBytesPatched", patched(res, after), res)
            r2 = Run(cli_cmd(project, "scan", *scan_mode), project, cenv, case / "rescan.log", timeout=900, retry=True)
            e2 = r2.json_or_empty()
            res2 = oracle(version, project, penv, after, case / "oracle-2.log")
            check("rescanIdempotent", r2.ok() and patched(res2, after) and (project / lockname).read_bytes() == pristine_lock, {"exit": r2.rc, "applied": applied_count("agent", e2)})
            rs, ok = native_sync("sync-again.log")
            res3 = oracle(version, project, penv, after, case / "oracle-3.log")
            check("survivesSync", ok and patched(res3, after), {"exit": rs.rc, "oracle": res3})
            ri = Run(install, project, penv, case / "install-again.log", timeout=900, retry=True)
            res4 = oracle(version, project, penv, after, case / "oracle-4.log")
            check("survivesInstall", (ri.ok() or self_install_only(ri.out)) and patched(res4, after), {"exit": ri.rc, "oracle": res4})
            lock_now = (project / lockname).read_bytes()
            info["ordinaryInstall"] = {"exit": ri.rc, "lockStable": lock_now == pristine_lock, "baselineFresh": row["baselineFresh"]}
            # The agent never touches the lock; a regenerated lock here is
            # PDM's own doing (0.x calls its fresh lock stale) and is judged
            # like the hosted/vendored ordinary-install check.
            check("lockUnchangedAfterInstalls", lock_now == pristine_lock or row["baselineFresh"] is not True, info["ordinaryInstall"])
            rb = Run(cli_cmd(project, "rollback"), project, cenv, case / "rollback.log", timeout=900)
            erb = rb.json_or_empty()
            check("rollbackExit0", rb.ok(), rb.tail(600) if not rb.ok() else None)
            res5 = oracle(version, project, penv, before, case / "oracle-rollback.log")
            check("rollbackRestoresUpstreamBytes", patched(res5, before), res5)
            check("rollbackClearsManifest", ledger_cleared(project, "agent"))
            check("rollbackKeepsPyproject", (project / "pyproject.toml").read_bytes() == pristine_pyproject)
            check("rollbackKeepsLock", (project / lockname).read_bytes() == lock_now)
            info["rollbackEnvelope"] = {k: erb.get(k) for k in ("status", "rolledBack", "failed") if k in erb}
            return finish("PASS" if all(checks.values()) else "FAIL")

        # ------------------------------------------------ hosted / vendored
        if not check("appliedExactlyOne", applied == 1, {"applied": applied, "codes": codes, "status": envelope.get("status")}):
            return finish("FAIL")
        check("lockRewritten", lock_after != pristine_lock)
        if shape == "crlf":
            check("crlfPreserved", b"\n" not in lock_after.replace(b"\r\n", b""))
        marker = HOSTED_MARKER if mode == "hosted" else VENDORED_MARKER
        check("lockHasPatchSource", marker in lock_after)
        after, before, uuid = record_hashes(project, mode)
        info["uuid"] = uuid
        check("recordHasFiles", bool(after))
        if mode == "vendored":
            wheel_dir = project / ".socket/vendor/pypi" / (uuid or "")
            check("vendoredWheelPresent", wheel_dir.is_dir() and any(wheel_dir.glob("*.whl")))
        # idempotent re-scan
        r2 = Run(cli_cmd(project, "scan", *scan_mode), project, cenv, case / "rescan.log", timeout=900, retry=True)
        e2 = r2.json_or_empty()
        check("rescanIdempotent", r2.ok() and (project / lockname).read_bytes() == lock_after and (project / "pyproject.toml").read_bytes() == pristine_pyproject, {"exit": r2.rc, "applied": applied_count(mode, e2), "status": e2.get("status")})
        # lock-driven install of the patched artifact
        uninstall("uninstall.log")
        r, ok = native_sync("install.log")
        info["install"] = {"exit": r.rc, "selfInstallOnly": self_install_only(r.out), "tail": r.tail(300)}
        if not ok:
            # Is it the patched lock, or does this PDM release fail the
            # pristine lock just the same?  Re-run against the pristine lock.
            (project / lockname).write_bytes(pristine_lock)
            uninstall("baseline-uninstall.log")
            rb0, ok0 = native_sync("baseline-install.log")
            (project / lockname).write_bytes(lock_after)
            info["nativeBaseline"] = {"exit": rb0.rc, "ok": ok0, "tail": rb0.tail(300)}
            if not ok0:
                return native_broken("pristine lock fails too", rb0.out)
        check("nativeInstallOk", ok, info["install"])
        res = oracle(version, project, penv, after, case / "oracle-1.log")
        info["installedOrigin"] = res.get("origin")
        if excluded:
            check("installedBytesPatched", res.get("installed") is False, {"expected": "not installed (marker excludes this host)", "oracle": res})
        else:
            check("installedBytesPatched", patched(res, after), res)
        check("lockUnchangedByInstall", (project / lockname).read_bytes() == lock_after)
        # ordinary `pdm install`
        ri = Run(install, project, penv, case / "ordinary-install.log", timeout=900, retry=True)
        ordinary_stable = (project / lockname).read_bytes() == lock_after
        info["ordinaryInstall"] = {"exit": ri.rc, "lockStable": ordinary_stable, "baselineFresh": row["baselineFresh"], "tail": ri.tail(300)}
        check("ordinaryInstallOk", ri.ok() or self_install_only(ri.out), info["ordinaryInstall"])
        check("ordinaryInstallKeepsLock", ordinary_stable or row["baselineFresh"] is not True, info["ordinaryInstall"])
        if not ordinary_stable:
            shutil.copyfile(project / lockname, case / "ordinary-result.lock")
            (project / lockname).write_bytes(lock_after)
        res_o = oracle(version, project, penv, after, case / "oracle-ordinary.log")
        info["ordinaryInstallPatched"] = patched(res_o, after)
        # `pdm lock --check` where it exists (2.11+)
        if "--check" in pdm_help(version, "lock"):
            lc = Run([pdm, "lock", "--check"] + (["-L", lockflag] if lockflag else []), project, penv, case / "lock-check.log", timeout=300)
            info["lockCheck"] = {"exit": lc.rc, "tail": lc.tail(200)}
        # `pdm export`
        ex_help = pdm_help(version, "export")
        if "usage" in ex_help.lower() and "invalid choice" not in ex_help:
            ex = Run([pdm, "export", "-f", "requirements", *groups] + (["-L", lockflag] if lockflag else []), project, penv, case / "export.log", timeout=300)
            info["export"] = {"exit": ex.rc, "mentionsPatchSource": marker.decode() in ex.out, "mentionsUrllib3": "urllib3" in ex.out}
        # tampered hash must be rejected by the installer
        if not excluded:
            uninstall("tamper-uninstall.log")
            shutil.rmtree(cache, ignore_errors=True)
            cache.mkdir(parents=True, exist_ok=True)
            bad = re.sub(rb"sha256:[a-f0-9]{64}", b"sha256:" + b"0" * 64, lock_after)
            (project / lockname).write_bytes(bad)
            tam, _ = native_sync("tamper-install.log")
            tres = oracle(version, project, penv, after, case / "tamper-oracle.log")
            (project / lockname).write_bytes(lock_after)
            info["tamper"] = {"installExit": tam.rc, "mentionsHash": bool(re.search(r"hash|digest|checksum|integrity", tam.out, re.I)), "installedPatchedAnyway": patched(tres, after)}
            check("integrityRejected", tam.rc != 0 and not info["tamper"]["installedPatchedAnyway"], info["tamper"])
            uninstall("tamper-uninstall2.log")
            r, ok = native_sync("reinstall.log")
            check("reinstallOk", ok, r.tail(300))
        # relock -> re-scan -> rollback (must restore the relocked bytes)
        saved = case / "saved-socket"
        shutil.copytree(project / ".socket", saved)
        if excluded:
            # The marker kept PDM from installing urllib3, so put the upstream
            # copy back for discovery (the starting condition of this case).
            Run(["uv", "pip", "install", "--quiet", "--python", venv / "bin/python", "urllib3==1.26.18"], project, env, case / "relock-reinstall.log", timeout=600, retry=True)
        rl = Run([pdm, "lock"] + (["-L", lockflag] if lockflag else []), project, penv, case / "relock.log", timeout=900, retry=True)
        relocked = (project / lockname).read_bytes()
        shutil.copyfile(project / lockname, case / "relocked.lock")
        info["relock"] = {"exit": rl.rc, "keepsPatch": marker in relocked, "lockBytesUnchanged": relocked == lock_after, "equalsOriginal": relocked == pristine_lock, "crlfKept": b"\r\n" in relocked if shape == "crlf" else None, "pyprojectUnchanged": (project / "pyproject.toml").read_bytes() == pristine_pyproject, "tail": rl.tail(200)}
        if rl.ok():
            relocked_text = relocked.decode("utf-8", "replace")
            target_kept = re.search(r'name = "urllib3"\s*\r?\n(?:[^\n]*\n)*?version = "1\.26\.18"', relocked_text) is not None or re.search(r'"urllib3(\[[^\]]*\])? 1\.26\.18"', relocked_text) is not None
            info["relock"]["targetKept"] = target_kept
            rs = Run(cli_cmd(project, "scan", *scan_mode), project, cenv, case / "rescan-after-relock.log", timeout=900, retry=True)
            ers = rs.json_or_empty()
            rescanned = (project / lockname).read_bytes()
            info["rescanAfterRelock"] = {"exit": rs.rc, "applied": applied_count(mode, ers), "codes": refusal_codes(mode, ers), "patchInLock": marker in rescanned}
            rb1 = Run(cli_cmd(project, "rollback"), project, cenv, case / "rollback-after-relock.log", timeout=900)
            erb1 = rb1.json_or_empty()
            shutil.copyfile(project / lockname, case / "rollback-after-relock.lock")
            failures = (erb1.get("hosted") or {}).get("failed") or erb1.get("vendoredFailed") or []
            rollback_note = {"exit": rb1.rc, "status": erb1.get("status"), "failed": failures[:3], "lockEqualsRelocked": (project / lockname).read_bytes() == relocked}
            if target_kept:
                check("rescanAfterRelockApplies", rs.ok() and marker in rescanned, info["rescanAfterRelock"])
                if mode == "vendored":
                    # The re-scan re-wires the COMMITTED wheel (no service
                    # call, no rebuild): the patched sha the first scan
                    # wired is the one wired again.
                    sha_re = rb"sha256:([a-f0-9]{64})"
                    patched_shas = set(re.findall(sha_re, lock_after)) - set(re.findall(sha_re, pristine_lock))
                    reused = bool(patched_shas) and patched_shas <= set(re.findall(sha_re, rescanned))
                    info["rescanAfterRelock"]["reusesWheel"] = reused
                    check("rescanReusesWheel", reused, info["rescanAfterRelock"])
                check("rollbackAfterRelockPristine", rb1.ok() and rollback_note["lockEqualsRelocked"], rollback_note)
            else:
                # The relock resolved urllib3 away from 1.26.18 (PDM < 2.0
                # has no overrides, so the pinned transitive resolution does
                # not survive `pdm lock`): nothing left to redirect, so the
                # re-scan and the rollback of the stale ledger are recorded
                # for the doc, not judged.
                info["relock"]["note"] = "relock dropped urllib3 1.26.18 from the lock; re-scan/rollback recorded only"
                info["rollbackAfterRelock"] = rollback_note
        shutil.rmtree(project / ".socket", ignore_errors=True)
        shutil.copytree(saved, project / ".socket")
        (project / lockname).write_bytes(lock_after)
        # final rollback restores every byte
        rb = Run(cli_cmd(project, "rollback"), project, cenv, case / "rollback.log", timeout=900)
        erb = rb.json_or_empty()
        check("rollbackExit0", rb.ok(), rb.tail(600) if not rb.ok() else None)
        check("rollbackRestoresLockBytes", (project / lockname).read_bytes() == pristine_lock)
        check("rollbackKeepsPyproject", (project / "pyproject.toml").read_bytes() == pristine_pyproject)
        check("rollbackClearsLedger", ledger_cleared(project, mode))
        if mode == "vendored":
            check("rollbackRemovesVendoredWheel", not (project / ".socket/vendor/pypi" / (uuid or "x")).exists())
        info["rollbackEnvelope"] = {k: erb.get(k) for k in ("status", "rolledBack", "failed", "vendoredReverted") if k in erb}
        if erb.get("hosted"):
            info["rollbackEnvelope"]["hosted"] = {k: erb["hosted"].get(k) for k in ("reverted", "failed", "unsupported", "editedFiles")}
        return finish("PASS" if all(checks.values()) else "FAIL")

    # --------------------------------------------------------- execution
    tool_environments = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futs = {pool.submit(bootstrap, v): v for v in args.versions}
        for f in concurrent.futures.as_completed(futs):
            v = futs[f]
            try:
                rec = f.result()
            except Exception as e:
                rec = {"version": v, "error": "bootstrap raised: " + str(e)[-800:]}
            tool_environments[v] = rec
            say("tool", v, "ok" if rec.get("ok") else "FAILED: " + rec.get("error", "?")[-300:].replace("\n", " "))
    jobs = [(v, s, m) for v in args.versions for s in args.shapes for m in args.modes if wanted(v, s, m)]
    say(f"{len(jobs)} cases across {len(args.versions)} PDM releases")
    results, errors = [], []
    for v in args.versions:
        if not tool_environments.get(v, {}).get("ok"):
            for s in args.shapes:
                for m in args.modes:
                    if wanted(v, s, m):
                        results.append({"pdm": v, "python": python_for(v), "shape": s, "mode": m, "outcome": "SKIP", "passed": None, "checks": {}, "info": {"skip": "tool bootstrap failed: " + tool_environments.get(v, {}).get("error", "?")[-300:]}})
    jobs = [j for j in jobs if tool_environments.get(j[0], {}).get("ok")]

    def persist():
        save(root / "summary.json", {
            "provenance": provenance,
            "toolEnvironments": tool_environments,
            "results": sorted(results, key=lambda r: (vtuple(r["pdm"]), r["shape"], r["mode"])),
            "errors": errors,
        })

    persist()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        pending = {pool.submit(backtest, job): job for job in jobs}
        for fut in concurrent.futures.as_completed(pending):
            job = pending[fut]
            try:
                row = fut.result()
                results.append(row)
                failed = [k for k, ok in row["checks"].items() if not ok]
                say(*job, row["outcome"], ",".join(failed), f"{row.get('durationSeconds', '?')}s")
            except Exception as e:
                err = {"pdm": job[0], "shape": job[1], "mode": job[2], "outcome": "ERROR", "error": str(e)[-3000:], "trace": traceback.format_exc()[-2000:]}
                errors.append(err)
                results.append({"pdm": job[0], "python": python_for(job[0]), "shape": job[1], "mode": job[2], "outcome": "ERROR", "passed": False, "checks": {}, "info": {"error": str(e)[-600:]}})
                say(*job, "ERROR", str(e)[-300:].replace("\n", " "))
            persist()
    summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
    (root / "summary.md").write_text(render_matrix(summary) + "\n\n" + render_details(summary) + "\n", encoding="utf-8")
    say(render_matrix(summary))
    bad = [r for r in summary["results"] if r["outcome"] in ("FAIL", "ERROR")]
    say(f"{len(summary['results'])} rows: " + ", ".join(f"{o} {sum(1 for r in summary['results'] if r['outcome'] == o)}" for o in ("PASS", "REFUSED-EXPECTED", "UNSUPPORTED", "SKIP", "FAIL", "ERROR")))
    if bad or errors:
        sys.exit(1)


# -------------------------------------------------------------- rendering
CODES = {"PASS": "PASS", "FAIL": "FAIL", "REFUSED-EXPECTED": "REF", "UNSUPPORTED": "UNS", "SKIP": "SKIP", "ERROR": "ERR"}


def render_matrix(summary):
    rows = summary["results"]
    versions = sorted({r["pdm"] for r in rows}, key=vtuple)
    shapes = [s for s in SHAPES if any(r["shape"] == s for r in rows)]
    modes = [m for m in MODES if any(r["mode"] == m for r in rows)]
    cols = [(s, m) for s in shapes for m in modes if any(r["shape"] == s and r["mode"] == m for r in rows)]
    by = {(r["pdm"], r["shape"], r["mode"]): r for r in rows}
    head = "| PDM | lock | " + " | ".join(f"{s}<br>{m}" for s, m in cols) + " |"
    sep = "| --- | --- | " + " | ".join("---" for _ in cols) + " |"
    lines = ["Cell legend: PASS, FAIL, REF = refused as expected (unsupported lock_version / expected no-op shape), UNS = layout the CLI cannot see (agent on `__pypackages__`), SKIP = shape not lockable on this release, ERR = harness error. Empty = not run.", "", head, sep]
    for v in versions:
        lock = next((r.get("lockVersion") for r in rows if r["pdm"] == v and r.get("lockVersion")), None)
        cells = []
        for s, m in cols:
            r = by.get((v, s, m))
            cells.append(CODES.get(r["outcome"], r["outcome"]) if r else "")
        lines.append(f"| {v} | {lock or '—'} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def render_details(summary):
    rows = summary["results"]
    lines = ["| PDM | shape | mode | outcome | failed checks | notes |", "| --- | --- | --- | --- | --- | --- |"]
    for r in sorted(rows, key=lambda r: (vtuple(r["pdm"]), r["shape"], r["mode"])):
        failed = ", ".join(k for k, ok in r.get("checks", {}).items() if not ok)
        info = r.get("info", {})
        notes = []
        if r.get("expected"):
            notes.append(r["expected"])
        if r.get("unexpected"):
            notes.append("UNEXPECTED: " + r["unexpected"])
        if info.get("skip"):
            notes.append(info["skip"][:160].replace("\n", " "))
        if info.get("error"):
            notes.append("error: " + info["error"][-160:].replace("\n", " "))
        if "codes" in info and info["codes"]:
            notes.append("codes=" + ",".join(str(c) for c in info["codes"]))
        if "lockOnlyHosted" in info:
            notes.append(f"lock-only hosted redirected={info['lockOnlyHosted'].get('redirected')}")
        if "ordinaryInstall" in info:
            o = info["ordinaryInstall"]
            notes.append(f"pdm install exit {o.get('exit')} lockStable={o.get('lockStable')} baselineFresh={o.get('baselineFresh')} patched={info.get('ordinaryInstallPatched')}")
        if r.get("checks", {}).get("noManifestWritten") is False:
            notes.append("refused vendored scan wrote a `.socket/manifest.json` record (vendored mode must be manifest-free)")
        if "lockCheck" in info:
            notes.append(f"lock --check exit {info['lockCheck'].get('exit')}")
        if "tamper" in info:
            notes.append(f"tamper install exit {info['tamper'].get('installExit')}")
        if "relock" in info:
            notes.append(f"relock exit {info['relock'].get('exit')} keepsPatch={info['relock'].get('keepsPatch')} rescanApplied={info.get('rescanAfterRelock', {}).get('applied')}")
            rb1 = info.get("rollbackAfterRelockPristine")
            if isinstance(rb1, dict) and rb1.get("failed"):
                notes.append("rollback after relock: " + str(rb1["failed"][0].get("error", ""))[:140])
        if info.get("patchedOutsideProject"):
            notes.append(f"agent patched the PATH interpreter instead ({','.join(info['patchedOutsideProject']['crawled'])}); rolled back exit {info.get('rollbackOutsideProject', {}).get('exit')}")
        if "export" in info:
            notes.append(f"export exit {info['export'].get('exit')} mentionsPatch={info['export'].get('mentionsPatchSource')}")
        if "installedOrigin" in info and info["installedOrigin"]:
            notes.append("installed in " + ("__pypackages__" if "__pypackages__" in info["installedOrigin"] else ".venv" if "/.venv/" in info["installedOrigin"] else info["installedOrigin"]))
        lines.append(f"| {r['pdm']} | {r['shape']} | {r['mode']} | {r['outcome']} | {failed} | {'; '.join(notes)} |")
    return "\n".join(lines)


def render_doc_table(summary):
    """Per-PDM-version compatibility table for docs/testing/pdm-compatibility.md."""
    rows = summary["results"]
    prov = summary.get("provenance", {})
    by = {}
    for r in rows:
        by.setdefault(r["pdm"], []).append(r)
    lines = []
    if prov:
        lines += [
            f"Run captured {prov.get('capturedAt', '?')[:10]} on {prov.get('platform', '?')} with socket-patch "
            f"`{prov.get('cliVersion', '?')}` (source `{prov.get('cliRevision', '?')}`, binary sha256 `{prov.get('cliSha256', '?')}`), "
            f"{len(by)} PDM releases, shapes: {', '.join(prov.get('shapes', []))}.",
            "",
        ]
    lines += [
        "| PDM | Python | lock_version | hosted | vendored | agent | tamper rejected (H/V) | `pdm install` keeps lock (H/V) | relock keeps patch (H/V) | notes |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]

    def cell(cases):
        ran = [c for c in cases if c["outcome"] not in ("SKIP",)]
        if not ran:
            return "n/a"
        refused = [c for c in ran if c["outcome"] == "REFUSED-EXPECTED" and c["shape"] not in EXPECTED_NOOP_SHAPES]
        if refused and len(refused) == len([c for c in ran if c["shape"] not in EXPECTED_NOOP_SHAPES]):
            return f"refused ({len(refused)} shapes)"
        unsupported = [c for c in ran if c["outcome"] == "UNSUPPORTED"]
        if unsupported and len(unsupported) == len(ran):
            return f"unsupported layout ({len(ran)} shapes)"
        ok = sum(1 for c in ran if c["outcome"] in ("PASS", "REFUSED-EXPECTED"))
        return ("pass" if ok == len(ran) else f"{ok}/{len(ran)}") + f" ({len(ran)} shapes)"

    def flag(cases, key, sub):
        vals = set()
        for c in cases:
            i = c.get("info", {}).get(key)
            if isinstance(i, dict) and i.get(sub) is not None:
                vals.add(i.get(sub))
        return "/".join(sorted(str(v).lower() for v in vals)) or "n/a"

    def tamper(cases):
        vals = {("yes" if c["info"]["tamper"]["installExit"] != 0 else "no") for c in cases if "tamper" in c.get("info", {})}
        return "/".join(sorted(vals)) or "n/a"

    def keeps_lock(cases):
        vals = set()
        for c in cases:
            o = c.get("info", {}).get("ordinaryInstall")
            if o:
                vals.add("yes" if o.get("lockStable") else ("regenerated (stale by PDM's own check)" if o.get("baselineFresh") is False else "NO"))
        return "/".join(sorted(vals)) or "n/a"

    for version in sorted(by, key=vtuple):
        cs = by[version]
        m = lambda mode: [c for c in cs if c["mode"] == mode]
        hosted, vendored, agent = m("hosted"), m("vendored"), m("agent")
        lock = next((c.get("lockVersion") for c in cs if c.get("lockVersion")), None)
        py = next((c.get("python") for c in cs if c.get("python")), "")
        notes = []
        if lock not in SUPPORTED_LOCK_VERSIONS:
            notes.append(f"lock_version {lock or 'absent'} unsupported: refused before any write, native install intact" if any(c["outcome"] == "REFUSED-EXPECTED" for c in hosted + vendored) else f"lock_version {lock or 'absent'}")
        if any(c["outcome"] == "UNSUPPORTED" for c in hosted + vendored + agent):
            notes.append("`__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter)")
        if any(c.get("info", {}).get("patchedOutsideProject") for c in agent):
            notes.append("agent mode on a `__pypackages__` project patched the PATH interpreter's site-packages")
        drift = [c for c in hosted + vendored if isinstance(c.get("info", {}).get("rollbackAfterRelockPristine"), dict) and c["info"]["rollbackAfterRelockPristine"].get("failed") and c["info"].get("rescanAfterRelock", {}).get("patchInLock")]
        if drift:
            notes.append("rollback after relock+re-scan fails (`" + ",".join(sorted({c["shape"] for c in drift})) + "`): the re-scan rewrote the lock but left the old ledger fragments, rollback reports drift")
        dropped = [c for c in hosted + vendored if c.get("info", {}).get("relock", {}).get("targetKept") is False]
        if dropped:
            notes.append("relock dropped urllib3 1.26.18 (`" + ",".join(sorted({c["shape"] for c in dropped})) + "`: pinned resolution, no overrides on this release); re-scan then has nothing to redirect and rollback of the stale ledger exits " + "/".join(sorted({str(c["info"].get("rollbackAfterRelock", {}).get("exit")) for c in dropped})))
        if any(c.get("checks", {}).get("noManifestWritten") is False for c in vendored):
            notes.append("refused vendored scan wrote a `.socket/manifest.json` record (vendored mode must be manifest-free)")
        relocked = [c for c in hosted + vendored if c.get("info", {}).get("ordinaryInstall", {}).get("lockStable") is False]
        if relocked:
            shapes_ = ",".join(sorted({c["shape"] for c in relocked}))
            kept = sorted({str(c["info"].get("ordinaryInstallPatched")).lower() for c in relocked})
            stale = any(c.get("baselineFresh") is False for c in relocked)
            notes.append(
                f"`pdm install` re-locked ({shapes_}): "
                + ("PDM's own freshness check flags its freshly generated lock as stale; " if stale else "")
                + f"patched install afterwards={'/'.join(kept)}; use `pdm sync`"
            )
        for c in hosted + vendored:
            lo = c.get("info", {}).get("lockOnlyHosted")
            if lo and lo.get("redirected") == 0 and c["shape"] == "direct" and c["mode"] == "hosted":
                notes.append("lock-only checkout (nothing installed) is not redirected")
                break
        for c in hosted + vendored + agent:
            if c["outcome"] in ("FAIL", "ERROR"):
                failed = ", ".join(k for k, ok in c.get("checks", {}).items() if not ok) or c.get("info", {}).get("error", "")[-80:]
                notes.append(f"{c['mode']}/{c['shape']} {c['outcome']}: {failed}")
        if any(c.get("unexpected") for c in cs):
            notes.append("UNEXPECTED: " + "; ".join(sorted({c["unexpected"] for c in cs if c.get("unexpected")})))
        def representative(cases):
            direct = [c for c in cases if c["shape"] == "direct"]
            return direct or [c for c in cases if "tamper" in c.get("info", {})]

        direct_h, direct_v = representative(hosted), representative(vendored)
        lines.append(
            f"| {version} | {py} | {lock or '—'} | {cell(hosted)} | {cell(vendored)} | {cell(agent)} | "
            f"{tamper(direct_h)} / {tamper(direct_v)} | {keeps_lock(direct_h)} / {keeps_lock(direct_v)} | "
            f"{flag(direct_h, 'relock', 'keepsPatch')} / {flag(direct_v, 'relock', 'keepsPatch')} | {'; '.join(dict.fromkeys(notes))} |"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    main()
