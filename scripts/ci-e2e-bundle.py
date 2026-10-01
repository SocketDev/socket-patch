#!/usr/bin/env python3
"""Copy the CLI and the test binaries one OS's CI legs run into one directory.

ci.yml's e2e-build job compiles every CLI test target once per OS
(`cargo test --no-run --message-format=json`); this picks out the binaries
the `e2e` and `e2e-full` rows name for that OS, plus the suites every
cargo-vex-matrix leg runs, so the legs download them instead of compiling.
"""

import argparse
import importlib.util
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github" / "workflows" / "ci.yml"
MATRIX_JOBS = ("e2e", "e2e-full")
# The binaries cargo-vex-matrix and cargo-vex-matrix-full run on every OS.
CARGO_VEX_SUITES = (
    "e2e_redirect_cargo_build",
    "e2e_redirect_cargo_shapes",
    "e2e_vendor_cargo_build",
    "mode_migration_cargo",
    "e2e_safety_cargo_build",
)


def load_reader():
    path = ROOT / "scripts" / "tests" / "test_ci_vlt_rows.py"
    spec = importlib.util.spec_from_file_location("ci_rows", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def suites_for(os_name, text=None):
    reader = load_reader()
    jobs = reader.jobs(text if text is not None else CI.read_text(encoding="utf-8"))
    suites = set(CARGO_VEX_SUITES)
    for job in MATRIX_JOBS:
        for row in reader.matrix_include(jobs[job]):
            if row["os"] == os_name:
                suites.add(row["suite"])
    return sorted(suites)


def executables(cargo_json):
    found = {}
    for line in cargo_json.splitlines():
        if not line.startswith("{"):
            continue
        item = json.loads(line)
        target = item.get("target", {})
        if item.get("executable") and item.get("profile", {}).get("test") and "test" in target.get("kind", []):
            found[target["name"]] = Path(item["executable"])
    return found


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--os", required=True, help="the runner label the rows use, e.g. ubuntu-latest")
    ap.add_argument("--cargo-json", required=True, type=Path)
    ap.add_argument("--dest", required=True, type=Path)
    args = ap.parse_args(argv)
    exe = ".exe" if sys.platform == "win32" else ""
    built = executables(args.cargo_json.read_text(encoding="utf-8"))
    wanted = suites_for(args.os)
    missing = [s for s in wanted if s not in built]
    if missing:
        print(f"ci-e2e-bundle: no test binary for {missing}", file=sys.stderr)
        return 1
    args.dest.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "target" / "debug" / f"socket-patch{exe}", args.dest / f"socket-patch{exe}")
    for suite in wanted:
        shutil.copy2(built[suite], args.dest / f"{suite}{exe}")
    print(f"ci-e2e-bundle: {len(wanted)} test binaries for {args.os}: {' '.join(wanted)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
