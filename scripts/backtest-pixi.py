#!/usr/bin/env python3
"""Drive the real socket-patch CLI and real pixi releases through a pixi
project's patch flows.

For every pixi version the harness downloads that exact release (the GitHub
release asset for this host, SHA-256 pinned below), installs a one-dependency
project (urllib3 1.26.18, which has a public free-tier Socket patch) in a
number of project shapes, and then runs socket-patch from the project root
with NO `pixi run` / `pixi shell` around it, the way a CI step after `pixi
install` does:

  agent     pixi install -> scan --mode agent -> installed bytes == patch,
            in every environment; pixi's package cache keeps the upstream
            bytes (an environment's files are hard links into it); `apply`
            is idempotent; `pixi install` and `pixi run` keep the patch and
            the environment's Python imports the patched module; `vex`
            attests it; a reinstall brings the upstream bytes back and
            `apply` restores the patch; `rollback` restores every byte.
  hosted    scan (the default mode) -> nothing is written, and the run
            warns `redirect_pypi_pixi_project`, which names agent mode.
  vendored  scan --mode vendored -> the patch is refused, nothing written.
  fresh     a checkout with no environment installed, and a decoy
            interpreter holding one package first on PATH: nothing is read
            from it, until a requirements.txt (which pip, not pixi,
            installs from) says another installer may fill it.

Shapes: conda (the package from conda-forge, the usual pixi project),
pypi (the same release from PyPI through `[pypi-dependencies]`, installed
by pixi's uv), pyproject (the pixi manifest in `pyproject.toml`), multi-env
(two environments, both hold the package), detached (pixi's
`detached-environments`, the environments outside the project; pixi 0.30
and later).

Every case has its own project directory and PIXI_HOME; the cases of one
pixi version share its package cache. Needs network (conda-forge, PyPI,
GitHub releases, patch.socket.dev) and no Socket token. POSIX only.

Usage:
  scripts/backtest-pixi.py --socket-patch target/debug/socket-patch \\
      --socket-patch-revision <sha> --output /tmp/pixi-backtest \\
      [--versions 0.84.2 ...] [--shapes conda ...] [--modes agent ...] \\
      [--pixi-dir <dir-with-<version>/pixi>]
"""

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import traceback
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# The oldest release whose manifest and `pixi install -e <environment>` this
# harness can drive, a lock-format-6 release, and two recent ones.
VERSIONS = ["0.20.1", "0.39.5", "0.63.2", "0.84.2"]
MODES = ["agent", "hosted", "vendored", "fresh"]
SHAPES = ["conda", "pypi", "pyproject", "multi-env", "detached"]

PACKAGE = "urllib3"
PACKAGE_VERSION = "1.26.18"
PURL_BASE = f"pkg:pypi/{PACKAGE}@{PACKAGE_VERSION}"
PYTHON = "3.12.*"

# SHA-256 of `pixi-<triple>.tar.gz` per release: a release asset can be
# replaced upstream, and this harness runs what it downloads.
PIXI_SHA256 = {
    ("0.20.1", "x86_64-unknown-linux-musl"): "bca8d0be25e5d8c45e29985d28fc28adf8297c6190f5ff064ba217cd054de831",
    ("0.20.1", "aarch64-unknown-linux-musl"): "46b7e01170aa250d210f979e1cda0f966a74f8fc234be0098eeeabadbf74ec5f",
    ("0.20.1", "aarch64-apple-darwin"): "21f0b7e74c68c3c6c78f85cf6e9efbf6200962a85a437fb44df7882c54241d01",
    ("0.20.1", "x86_64-apple-darwin"): "24041eaed68b356deeba782ba1f41de66ac6c844cbabf038a6e8488b9e5730c9",
    ("0.39.5", "x86_64-unknown-linux-musl"): "b2cce3fdb6037db67fec0712eed8ea58fab93bd922c3bfbc396fe7b9495e360a",
    ("0.39.5", "aarch64-unknown-linux-musl"): "27372f80b23c82d0bd577399e49399ce71c7431b618a6e6c00a35d68321ef4af",
    ("0.39.5", "aarch64-apple-darwin"): "7aebfee390acbc5643561900ec88b7fc3f7f89d28186dd9675647081b33d8b41",
    ("0.39.5", "x86_64-apple-darwin"): "11f41364d118b64e6937e9e0b3bbcfed5fe16e9277969d0485f0935c4d92efa9",
    ("0.63.2", "x86_64-unknown-linux-musl"): "b2a9e26bb6c80fe00618a02e7198dec222e1fbcec61e04c11b6e6538089ab100",
    ("0.63.2", "aarch64-unknown-linux-musl"): "dbde6dbc2806602171e17305ce005e1aed519f2f2461a7cafd0093e92b7e7681",
    ("0.63.2", "aarch64-apple-darwin"): "28fca5e7335b5f6b5b05acb9f83b61fa65e27e5dd69fe7a1750aa884ea4163cb",
    ("0.63.2", "x86_64-apple-darwin"): "85ea41d0310acd8e13edf4923b65c101fc3fc5f8d2ee48d85d64f2bcd9781830",
    ("0.84.2", "x86_64-unknown-linux-musl"): "6d2a576bde0a7b26533a068fec0aea6e4ee21c36668efc1dc73fce90110906ae",
    ("0.84.2", "aarch64-unknown-linux-musl"): "0957b6352d077bb3ffcce913f90b1e6cfbc6b98888a45d59ee2910e8c4811110",
    ("0.84.2", "aarch64-apple-darwin"): "039d4b48c7e17bc62a36faa2af1b13d0d187f5dd6e8fea17e0587302438df6e6",
    ("0.84.2", "x86_64-apple-darwin"): "a633a4f8276955b73248397c17ce77380eb7133dc96c54bc271239b7dc9b8837",
}

# pixi 0.20 has no `detached-environments` setting and keeps the
# environments in the project whatever its configuration says; 0.30 is the
# oldest release this harness has seen honor it.
DETACHED_SINCE = (0, 30, 0)

DEFAULT_TIMEOUT = int(os.environ.get("BACKTEST_TIMEOUT", "900"))


def vtuple(version):
    return tuple(int(part) for part in version.split("."))


def host_triple():
    machine = platform.machine().lower()
    arch = {"arm64": "aarch64", "amd64": "x86_64"}.get(machine, machine)
    system = platform.system()
    if system == "Linux":
        return f"{arch}-unknown-linux-musl"
    if system == "Darwin":
        return f"{arch}-apple-darwin"
    raise SystemExit(f"backtest-pixi.py is POSIX only (host: {system})")


def conda_platform():
    machine = platform.machine().lower()
    if platform.system() == "Darwin":
        return "osx-arm64" if machine in ("arm64", "aarch64") else "osx-64"
    return "linux-aarch64" if machine in ("arm64", "aarch64") else "linux-64"


def save(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def git_blob_sha256(path):
    data = path.read_bytes()
    return hashlib.sha256(b"blob %d\0" % len(data) + data).hexdigest()


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
            self.rc, self.out, self.err = 124, text(e.stdout), text(e.stderr) + f"\nTIMEOUT after {timeout}s"
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


class CaseFailure(RuntimeError):
    pass


def require(run, what):
    if not run.ok():
        raise CaseFailure(f"{what} failed (exit {run.rc}): {(run.err or run.out)[-1500:]}")
    return run


def base_env():
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("PYTHON", "PIP_", "PIXI_", "CONDA_", "SOCKET_", "UV_")) and k != "VIRTUAL_ENV"
    }
    env.update(SOCKET_NO_CONFIG="1", SOCKET_NO_UPDATE_CHECK="1", SOCKET_TELEMETRY_DISABLED="1")
    return env


def fetch_pixi(version, tools, pixi_dir):
    """The pixi binary of `version`: a prefetched one, else the release asset."""
    if pixi_dir:
        binary = pixi_dir / version / "pixi"
        if not binary.is_file():
            raise SystemExit(f"--pixi-dir has no {binary}")
        return binary
    binary = tools / version / "pixi"
    if binary.is_file():
        return binary
    triple = host_triple()
    pinned = PIXI_SHA256.get((version, triple))
    if pinned is None:
        raise SystemExit(
            f"no SHA-256 pinned for pixi {version} on {triple}: add it to PIXI_SHA256, or pass --pixi-dir"
        )
    url = f"https://github.com/prefix-dev/pixi/releases/download/v{version}/pixi-{triple}.tar.gz"
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()
    actual = hashlib.sha256(data).hexdigest()
    if actual != pinned:
        raise SystemExit(f"{url}: sha256 {actual} is not the pinned {pinned}")
    binary.parent.mkdir(parents=True, exist_ok=True)
    archive = binary.parent / "pixi.tar.gz"
    archive.write_bytes(data)
    with tarfile.open(archive) as tar:
        # `pixi` in recent archives, `./pixi` in older ones.
        member = next(m for m in tar.getmembers() if m.isfile() and Path(m.name).name == "pixi")
        with tar.extractfile(member) as src, open(binary, "wb") as dst:
            shutil.copyfileobj(src, dst)
    binary.chmod(0o755)
    archive.unlink()
    return binary


def manifest_text(shape, version):
    """The pixi manifest of `shape`, as (file name, text)."""
    # `[workspace]` replaced `[project]` as the manifest's own table in 0.41.
    table = "workspace" if vtuple(version) >= (0, 41, 0) else "project"
    head = f'name = "backtest"\nchannels = ["conda-forge"]\nplatforms = ["{conda_platform()}"]\n'
    conda_dep = f'python = "{PYTHON}"\n{PACKAGE} = "=={PACKAGE_VERSION}"\n'
    if shape == "pypi":
        body = (
            f"[{table}]\n{head}\n[dependencies]\npython = \"{PYTHON}\"\n\n"
            f'[pypi-dependencies]\n{PACKAGE} = "=={PACKAGE_VERSION}"\n'
        )
        return "pixi.toml", body
    if shape == "pyproject":
        body = (
            '[project]\nname = "backtest"\nversion = "0.1.0"\nrequires-python = ">=3.12"\n\n'
            f"[tool.pixi.{table}]\n{head}\n[tool.pixi.dependencies]\n{conda_dep}"
        )
        return "pyproject.toml", body
    body = f"[{table}]\n{head}\n[dependencies]\n{conda_dep}"
    if shape == "multi-env":
        body += '\n[feature.extra.dependencies]\nsix = "*"\n\n[environments]\nextra = ["extra"]\n'
    return "pixi.toml", body


def environments(shape):
    return ["default", "extra"] if shape == "multi-env" else ["default"]


def site_packages(project):
    """Every environment's site-packages, by environment name."""
    found = {}
    envs = project / ".pixi" / "envs"
    for prefix in sorted(envs.iterdir()) if envs.exists() else []:
        for site in sorted(prefix.glob("lib/python3.*/site-packages")):
            found[prefix.name] = site
    return found


def installed_hashes(project, files):
    return {
        name: {rel: git_blob_sha256(site / rel) if (site / rel).is_file() else None for rel in files}
        for name, site in site_packages(project).items()
    }


def project_files(project):
    """The bytes of every tracked-looking project file (not `.pixi`, `.socket`)."""
    out = {}
    for path in sorted(project.rglob("*")):
        rel = path.relative_to(project)
        if rel.parts[0] in (".pixi", ".socket") or not path.is_file():
            continue
        out[str(rel)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def warning_codes(envelope):
    codes = set()
    for warning in envelope.get("warnings") or []:
        if isinstance(warning, dict) and warning.get("code"):
            codes.add(warning["code"])
    for event in envelope.get("events") or []:
        if event.get("errorCode"):
            codes.add(event["errorCode"])
    return codes


def run_case(job, ctx):
    version, shape, mode = job
    case = ctx["root"] / "cases" / f"{version}-{shape}-{mode}"
    if case.exists():
        shutil.rmtree(case)
    project = case / "project"
    project.mkdir(parents=True)
    logs = case / "logs"
    logs.mkdir()
    env = dict(ctx["env"])
    env["PIXI_HOME"] = str(case / "pixi-home")
    env["PIXI_CACHE_DIR"] = str(ctx["root"] / "cache" / version)
    pixi, cli = ctx["pixi"][version], ctx["cli"]
    row = dict(version=version, shape=shape, mode=mode, checks={}, passed=False)
    step = [0]

    def log(name):
        step[0] += 1
        return logs / f"{step[0]:02d}-{name}.log"

    def check(name, value, note=None):
        row["checks"][name] = bool(value)
        if note and not value:
            row.setdefault("notes", {})[name] = note

    def sp(*args, name):
        return Run([cli, *args], project, env, log(name))

    try:
        name, text = manifest_text(shape, version)
        (project / name).write_text(text)
        if shape == "detached":
            (project / ".pixi").mkdir()
            (project / ".pixi" / "config.toml").write_text("detached-environments = true\n")

        def pixi_install(tag):
            for environment in environments(shape):
                require(
                    Run([pixi, "install", "-e", environment], project, env, log(f"pixi-install-{tag}-{environment}")),
                    f"pixi install -e {environment}",
                )

        if mode == "fresh":
            # A lock but no environment, as a fresh checkout has, and a decoy
            # interpreter with one package first on PATH (not activated: the
            # fallback under test asks whichever `python3` PATH finds).
            # Dry runs only: a regression must not patch the decoy's
            # neighbours on the host.
            (project / "pixi.lock").write_text("version: 6\n")
            decoy = case / "decoy"
            require(
                Run([sys.executable, "-m", "venv", "--without-pip", decoy], case, env, log("decoy-venv")),
                "decoy venv",
            )
            decoy_site = next(decoy.glob("lib/python3.*/site-packages"))
            dist = decoy_site / "decoy_pkg-6.6.6.dist-info"
            dist.mkdir()
            (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: decoy-pkg\nVersion: 6.6.6\n")
            env["PATH"] = f"{decoy / 'bin'}{os.pathsep}{env['PATH']}"

            scan = sp("scan", "--mode", "agent", "--dry-run", "--json", name="scan-fresh")
            envelope = scan.json()
            check("scanExitsZero", scan.ok(), scan.err[-500:])
            check("nothingReadFromPath", envelope.get("scannedPackages", 0) == 0, envelope.get("scannedPackages"))
            check("noEnvironmentCreated", not (project / ".pixi" / "envs").exists())

            # The other half of the rule: pip installs from a
            # requirements.txt, so with one the interpreter on PATH may hold
            # the project's packages and is still asked.
            (project / "requirements.txt").write_text(f"{PACKAGE}=={PACKAGE_VERSION}\n")
            scan = sp("scan", "--mode", "agent", "--dry-run", "--json", name="scan-fresh-with-requirements")
            envelope = scan.json()
            check(
                "pathInterpreterKeptForAPipProject",
                scan.ok() and envelope.get("scannedPackages", 0) >= 1,
                envelope.get("scannedPackages"),
            )
            row["passed"] = all(row["checks"].values())
            return row

        pixi_install("first")
        sites = site_packages(project)
        check("everyEnvironmentInstalled", sorted(sites) == environments(shape), sorted(sites))
        if shape == "detached":
            check("environmentsAreDetached", (project / ".pixi" / "envs").is_symlink())
        before_tree = project_files(project)

        if mode in ("hosted", "vendored"):
            args = ["scan", "--json"] + (["--mode", "vendored"] if mode == "vendored" else [])
            scan = sp(*args, name=f"scan-{mode}")
            envelope = scan.json()
            codes = warning_codes(envelope)
            check("packageFound", any(p.get("purl") == PURL_BASE for p in envelope.get("packages") or []))
            check("projectFilesUntouched", project_files(project) == before_tree)
            check("nothingVendored", not (project / ".socket" / "vendor").exists())
            if mode == "hosted":
                # Nothing to redirect is not a failure; the warning says
                # where the patch can go.
                check("scanExitsZero", scan.ok(), scan.err[-500:])
                check("pointsAtAgentMode", "redirect_pypi_pixi_project" in codes, sorted(codes))
            else:
                # A vendored run that vendors nothing it was asked to fails.
                check("scanRefuses", scan.rc == 1 and envelope.get("status") == "partialFailure", scan.rc)
                check(
                    "refusedWithAgentRemedy",
                    bool(codes & {"pypi_no_requirements", "pypi_pyproject_only"}),
                    sorted(codes),
                )
            row["passed"] = all(row["checks"].values())
            return row

        # ── agent ──
        scan = sp("scan", "--mode", "agent", "--json", name="scan-agent")
        envelope = scan.json()
        check("scanExitsZero", scan.ok(), (scan.err or scan.out)[-800:])
        manifest = json.loads((project / ".socket" / "manifest.json").read_text())
        records = [r for purl, r in manifest["patches"].items() if purl.split("?")[0] == PURL_BASE]
        check("patchRecorded", len(records) == 1, list(manifest["patches"]))
        files = records[0]["files"]
        after = {rel: f["afterHash"] for rel, f in files.items()}
        before = {rel: f["beforeHash"] for rel, f in files.items()}
        every_env = lambda want: all(got == want for got in installed_hashes(project, files).values())  # noqa: E731
        check("installedBytesArePatched", every_env(after), installed_hashes(project, files))
        check("projectFilesUntouched", project_files(project) == before_tree)

        # pixi links an environment's files from its package cache: the
        # patch must not reach through the link.
        cached = [
            path
            for rel in files
            for path in (Path(env["PIXI_CACHE_DIR"]) / "pkgs").glob(f"{PACKAGE}-{PACKAGE_VERSION}-*/site-packages/{rel}")
        ]
        if shape != "pypi":
            check("cacheCopyFound", bool(cached))
        check(
            "packageCacheKeepsUpstreamBytes",
            all(git_blob_sha256(p) == before[str(p).split("site-packages/")[1]] for p in cached),
        )

        again = sp("apply", "--json", name="apply-again")
        check("applyIsIdempotent", again.ok() and every_env(after), (again.err or again.out)[-500:])

        pixi_install("again")
        probe = Run(
            [pixi, "run", "python", "-c", f"import {PACKAGE}; print({PACKAGE}.__file__)"],
            project,
            env,
            log("pixi-run-import"),
        )
        check("pixiInstallAndRunKeepThePatch", probe.ok() and every_env(after), (probe.err or probe.out)[-500:])

        vex = sp("vex", "--product", "pkg:generic/backtest", "-O", case / "vex.json", name="vex")
        attested = (case / "vex.json").read_text() if (case / "vex.json").exists() else ""
        check("vexAttestsThePatch", vex.ok() and PURL_BASE in attested, (vex.err or vex.out)[-500:])

        # A reinstall brings the upstream bytes back; `apply` restores the
        # patch. `pixi reinstall` is recent, so rebuild the environments.
        envs = (project / ".pixi" / "envs").resolve()
        shutil.rmtree(envs)
        envs.mkdir()
        pixi_install("rebuild")
        check("reinstallRevertsThePatch", every_env(before), installed_hashes(project, files))
        reapply = sp("apply", "--json", name="apply-after-reinstall")
        check("applyRestoresThePatch", reapply.ok() and every_env(after), (reapply.err or reapply.out)[-500:])

        rollback = sp("rollback", "--json", name="rollback")
        check("rollbackRestoresEveryByte", rollback.ok() and every_env(before), (rollback.err or rollback.out)[-500:])
        row["passed"] = all(row["checks"].values())
    except Exception as error:  # noqa: BLE001 - every failure is a failed row
        row["error"] = f"{type(error).__name__}: {error}"
        row["traceback"] = traceback.format_exc()
    finally:
        save(case / "result.json", row)
    return row


def render_table(rows):
    lines = ["| pixi | shape | mode | result | failed checks |", "|---|---|---|---|---|"]
    for row in rows:
        failed = [name for name, ok in row["checks"].items() if not ok]
        detail = ", ".join(failed) or row.get("error", "")
        lines.append(
            f"| {row['version']} | {row['shape']} | {row['mode']} | {'pass' if row['passed'] else 'FAIL'} | {detail} |"
        )
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--socket-patch", required=True, type=Path)
    ap.add_argument("--socket-patch-revision", required=True)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--versions", nargs="+", default=VERSIONS)
    ap.add_argument("--modes", nargs="+", default=MODES, choices=MODES)
    ap.add_argument("--shapes", nargs="+", default=SHAPES, choices=SHAPES)
    ap.add_argument("--pixi-dir", type=Path, help="prefetched binaries, as <dir>/<version>/pixi")
    args = ap.parse_args()

    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=True)
    cli = args.socket_patch.resolve()
    ctx = dict(root=root, cli=cli, env=base_env(), pixi={})
    save(
        root / "provenance.json",
        {
            "capturedAt": datetime.now(timezone.utc).isoformat(),
            "cliRevision": args.socket_patch_revision,
            "cliSha256": hashlib.sha256(cli.read_bytes()).hexdigest(),
            "pixiVersions": args.versions,
            "modes": args.modes,
            "shapes": args.shapes,
            "host": os.uname().sysname + " " + os.uname().machine,
        },
    )
    rows = []
    for version in args.versions:
        ctx["pixi"][version] = fetch_pixi(version, root / "tools", args.pixi_dir)
        for shape in args.shapes:
            if shape == "detached" and vtuple(version) < DETACHED_SINCE:
                continue
            for mode in args.modes:
                # The refusal does not depend on where the package comes
                # from. The fresh-checkout probe needs a Python marker beside
                # pixi's files (a `pyproject.toml`): without one no release
                # ever asked the interpreter on PATH.
                if mode == "vendored" and shape not in ("conda", "pyproject"):
                    continue
                if mode == "fresh" and shape != "pyproject":
                    continue
                row = run_case((version, shape, mode), ctx)
                rows.append(row)
                print(
                    f"{'PASS' if row['passed'] else 'FAIL'} pixi {version} {shape} {mode}"
                    + ("" if row["passed"] else f": {row.get('error') or [n for n, ok in row['checks'].items() if not ok]}"),
                    flush=True,
                )
    save(root / "summary.json", {"rows": rows})
    (root / "summary.md").write_text(render_table(rows) + "\n")
    print(render_table(rows))
    failed = [row for row in rows if not row["passed"]]
    if failed:
        print(f"{len(failed)} of {len(rows)} cells failed", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
