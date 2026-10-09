#!/usr/bin/env python3
"""Run a grouped CI row without losing any member's filters or environment.

Each original row keeps its own required-tool guards, versions and vlt leg
checker. A failed or empty suite is reported, and later members still run.
"""

import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = {
    "bun": "BUN", "uv": "UV", "poetry": "POETRY", "pdm": "PDM", "hatch": "HATCH",
    "bundler": "BUNDLER", "composer": "COMPOSER", "gradle": "GRADLE", "dotnet": "DOTNET",
    "deno": "DENO", "sbt": "SBT", "vlt": "VLT",
}


def members(row):
    cases = json.loads(row["cases"]) if row.get("cases") else [row]
    if not cases or any(not case.get("suite", "").strip() for case in cases):
        raise ValueError("An e2e group must contain nonempty suite selections")
    return cases


def environment(row, suite, base, root):
    env = dict(base)
    for key, tool in TOOLS.items():
        version = str(row.get(key) or "")
        env[f"SOCKET_PATCH_{tool}_E2E_REQUIRED"] = "1" if version else ""
        env[f"SOCKET_PATCH_{tool}_E2E_VERSION"] = version
    for key in ("pipenv", "pip"):
        versions = str(row.get(key) or "")
        env[f"SOCKET_PATCH_{key.upper()}_E2E_REQUIRED"] = "1" if versions else ""
        env[f"SOCKET_PATCH_{key.upper()}_E2E_VERSIONS"] = versions
    env["SOCKET_PATCH_NPM_E2E_REQUIRED"] = str(row.get("npm_required") or "")
    env["SOCKET_PATCH_CARGO_E2E_REQUIRED"] = "1" if suite == "e2e_safety_cargo_build" else ""
    for key in ("REQUIRED", "EXTENDED", "PRODUCTION"):
        env[f"SOCKET_PATCH_BUN_LOCKB_{key}"] = "1" if suite == "e2e_bun_lockb" else ""
    env["SOCKET_PATCH_BUN_LOCKB_VERSION"] = str(row.get("bun") or "") if suite == "e2e_bun_lockb" else ""
    maven = row.get("jvm_tool") == "maven" or (
        row.get("jvm_tool") == "gradle" and "gradle_vendor_" in row.get("test_filter", ""))
    env["SOCKET_PATCH_MAVEN_E2E_REQUIRED"] = "1" if maven else ""
    env["SOCKET_PATCH_MAVEN_E2E_VERSION"] = str(row.get("maven") or "3.9.16") if maven else ""
    env["SOCKET_PATCH_GRADLE_E2E_PROBE_DIR"] = str(root / "target/gradle-probe") if row.get("gradle") else ""
    # An unset linker is distinct from an explicitly pinned hardlink cell.
    env.pop("SOCKET_PATCH_VLT_E2E_STORE_LINKER", None)
    if row.get("vlt_store_linker"):
        env["SOCKET_PATCH_VLT_E2E_STORE_LINKER"] = str(row["vlt_store_linker"])
    if not row.get("vlt_upgrade"):
        env.pop("SOCKET_PATCH_VLT_E2E_UPGRADE_JS", None)
        env.pop("SOCKET_PATCH_VLT_E2E_UPGRADE_VERSION", None)
    env["CARGO_MANIFEST_DIR"] = str(root / "crates/socket-patch-cli")
    return env


def run_binary(args, env, cwd, log):
    with log.open("w", encoding="utf-8") as output:
        with subprocess.Popen(args, env=env, cwd=cwd, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace") as process:
            for line in process.stdout:
                print(line, end="", flush=True)
                output.write(line)
            return process.wait()


def run_cases(row, root=ROOT, base=None):
    base = os.environ if base is None else base
    cli = root / "crates/socket-patch-cli"
    suffix = ".exe" if sys.platform == "win32" else ""
    status = 0
    for index, case in enumerate(members(row)):
        for suite in case["suite"].split():
            if not re.fullmatch(r"[A-Za-z0-9_]+", suite):
                raise ValueError(f"Invalid test suite: {suite}")
            if case.get("allow_empty") == "true" and not any(
                    path.is_file() for path in (cli / f"tests/{suite}.rs", cli / f"tests/{suite}/main.rs")):
                print(f"::notice::{suite} has not landed yet; skipped (allow_empty)")
                continue
            filters = shlex.split(case.get("test_filter") or "--ignored")
            log = root / f"target/e2e-{index}-{suite}.log"
            env = environment(case, suite, base, root)
            print(f"::group::{suite} {case.get('test_filter', '--ignored')}", flush=True)
            try:
                failed = run_binary([str(root / f"target/e2e-bin/{suite}{suffix}"), *filters],
                                    env, cli, log) != 0
                passed = re.search(r"^test result: .*? (\d+) passed;", log.read_text(encoding="utf-8"), re.M)
                if not passed or int(passed[1]) == 0:
                    print(f"::error::{suite} ran no tests; check its filters.")
                    failed = True
                if case.get("vlt"):
                    checker = subprocess.run([sys.executable, str(root / "scripts/check-vlt-legs.py"),
                                              "--binary", suite, "--manifest",
                                              str(cli / "tests/vlt-leg-manifest.json"), str(log)],
                                             cwd=root, env=env)
                    failed |= checker.returncode != 0
                if failed:
                    print(f"::error::{suite} failed (row {index}, filters: {' '.join(filters)}).")
                    status = 1
            except OSError as error:
                print(f"::error::{suite} could not run: {error}")
                status = 1
            finally:
                print("::endgroup::", flush=True)
    return status


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(run_cases(json.loads(os.environ["E2E_ROW_JSON"])))
