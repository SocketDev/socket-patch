#!/usr/bin/env python3
"""Pack compatible short e2e rows while preserving their original selections.

Run with --write after editing ci.yml's rows. The cases stored in each bin
are the complete original rows, so regrouping is lossless and idempotent.
Long Gradle/sbt legs stay separate. Estimates are deliberately conservative
against #1172's measured short-leg times; bins target at most six minutes
of tests, below the merge queue's long-running jobs.
"""

import argparse
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/ci.yml"
FAMILIES = ("e2e", "e2e-windows", "e2e-macos", "e2e-full", "e2e-gradle-mid")
CASE_KEYS = {"suite", "test_filter", "npm_required", "vlt_store_linker", "allow_empty", "parallel_suites"}
BUDGET_SECONDS = 360
ESTIMATES = {
    "e2e_safety_pnpm": 30, "e2e_redirect_npm_build": 90, "e2e_redirect_rush_sim": 30,
    "e2e_redirect_pnpm_build": 90, "e2e_redirect_bun_build": 30, "e2e_vendor_bun_build": 30,
    "mode_migration_bun": 30, "e2e_bun_lockb": 180, "e2e_redirect_vlt_build": 45,
    "e2e_vendor_vlt_build": 45, "mode_migration_vlt": 45, "e2e_safety_vlt": 45, "e2e_vlt": 45,
    "e2e_redirect_uv_build": 30, "e2e_vendor_pypi_build": 30, "e2e_vex_build": 60,
    "e2e_redirect_maven_build": 45, "e2e_vendor_maven_build": 60, "e2e_vendor_jvm_build": 60,
    "e2e_nuget_dotnet_build": 45,
}


def reader():
    spec = importlib.util.spec_from_file_location("ci_rows", ROOT / "scripts/tests/test_ci_vlt_rows.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def family(row):
    if row.get("gradle") or row.get("sbt"):
        return None
    if row.get("vlt") or "e2e_redirect_pnpm_build" in row["suite"].split():
        return "node24"
    if row.get("bun") or row["suite"] in ("e2e_safety_pnpm", "e2e_redirect_npm_build", "e2e_redirect_rush_sim"):
        return "node20"
    if row.get("uv"):
        return "uv"
    # Pip/pipenv use setup-uv's current release; the other Python tools
    # bootstrap through pinned uv 0.11.19. Do not overwrite either PATH.
    if row.get("pipenv") or row.get("pip"):
        return "python-installers"
    if any(row.get(key) for key in ("poetry", "pdm", "hatch")):
        return "python"
    if row.get("maven") or row.get("dotnet"):
        return "jvm-dotnet"
    return None


def estimate(row):
    return sum(ESTIMATES.get(suite, BUDGET_SECONDS) for suite in row["suite"].split())


def settings(row):
    return {key: value for key, value in row.items() if key not in CASE_KEYS}


def pack(rows):
    bins = []
    for row in rows:
        kind, config = family(row), settings(row)
        for bucket in bins:
            if (kind is not None and bucket["family"] == kind
                    and bucket["seconds"] + estimate(row) <= BUDGET_SECONDS
                    and all(bucket["settings"].get(k, v) == v for k, v in config.items())):
                break
        else:
            bucket = {"family": kind, "settings": {}, "rows": [], "seconds": 0}
            bins.append(bucket)
        bucket["rows"].append(row)
        bucket["settings"].update(config)
        bucket["seconds"] += estimate(row)
    result = []
    for index, bucket in enumerate(bins):
        cases = bucket["rows"]
        if len(cases) == 1:
            group = dict(cases[0])
        else:
            group = dict(bucket["settings"])
            group["suite"] = " ".join(dict.fromkeys(s for row in cases for s in row["suite"].split()))
            group["cases"] = json.dumps(cases, separators=(",", ":"))
        versions = [v for k, v in bucket["settings"].items() if k not in ("os", "jvm_tool", "java")]
        group["ci_group"] = "-".join([bucket["family"] or cases[0].get("gradle") or cases[0]["suite"],
                                   *versions, str(index + 1)])
        result.append(group)
    return result


def render(group):
    def scalar(value):
        return "'" + value.replace("'", "''") + "'"
    return "          - {" + ", ".join(f"{k}: {scalar(v)}" for k, v in group.items()) + "}"


def regroup(text):
    rows_reader = reader()
    jobs = rows_reader.jobs(text)
    for name in FAMILIES:
        rows = rows_reader.matrix_include(jobs[name])
        # Generated labels describe bins, never affect a member's setup.
        rows = [{k: v for k, v in row.items() if k != "ci_group"} for row in rows]
        groups = pack(rows)
        pattern = rf"(\n  {re.escape(name)}:\n.*?        include:\n).*?(?=    runs-on:)"
        text, count = re.subn(pattern, lambda m: m[1] + "\n".join(map(render, groups)) + "\n",
                             text, count=1, flags=re.S)
        if count != 1:
            raise ValueError(f"Missing matrix for {name}")
        print(f"{name}: {len(rows)} selections -> {len(groups)} jobs")
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    text = regroup(WORKFLOW.read_text(encoding="utf-8"))
    if args.write:
        WORKFLOW.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
