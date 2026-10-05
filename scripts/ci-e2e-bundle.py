#!/usr/bin/env python3
"""Copy the CLI and the test binaries one OS's CI legs run into one directory.

ci.yml's e2e-build job compiles every CLI test target once per OS
(`cargo test --no-run --message-format=json`); this picks out the binaries
the `e2e` and `e2e-full` rows name for that OS, plus the suites every
cargo-vex-matrix leg runs, so the legs download them instead of compiling.
A row's `suite` may list several binaries (space-separated); a row marked
`allow_empty: 'true'` names suites that have not landed yet, which are
skipped until their test file exists. `--suites` bundles an explicit list
instead (gradle-compatibility.yml's own build).

Every run also enforces the per-suite test-name prefix contract
(`PREFIX_GUARDS`): each `#[ignore]` test of a guarded suite must start with
one of the prefixes the rows running that suite select, because the CI rows
select those tests by name prefix and any other test would silently run
nowhere. `--check` runs only
the guard.
"""

import argparse
import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github" / "workflows" / "ci.yml"
TESTS = ROOT / "crates" / "socket-patch-cli" / "tests"
MATRIX_JOBS = ("e2e", "e2e-full")
# The binaries cargo-vex-matrix and cargo-vex-matrix-full run on every OS.
CARGO_VEX_SUITES = (
    "e2e_redirect_cargo_build",
    "e2e_redirect_cargo_shapes",
    "e2e_vendor_cargo_build",
    "mode_migration_cargo",
    "e2e_safety_cargo_build",
)


# The real-Gradle suites (one per package of the Gradle campaign) and the
# libtest prefixes the CI rows that run each suite filter on (ci.yml's PR
# tier and gradle-compatibility.yml's modes). A suite admits only the
# prefixes its own rows select: a `gradle_vendor_` test in the agent suite
# would match the global vocabulary yet run in no row. sbt registers its own
# suites here.
GRADLE_SUITE_PREFIXES = {
    "e2e_gradle_discovery_build": ("gradle_agent_",),
    "e2e_gradle_agent_build": ("gradle_agent_",),
    "e2e_redirect_gradle_build": ("gradle_hosted_",),
    "e2e_vendor_gradle_build": ("gradle_vendor_", "gradle_multi_project"),
}
GRADLE_SUITES = tuple(GRADLE_SUITE_PREFIXES)


def prefix_pattern(prefixes):
    return re.compile("^(?:" + "|".join(re.escape(p) for p in prefixes) + ")")


PREFIX_GUARDS = {suite: prefix_pattern(prefixes) for suite, prefixes in GRADLE_SUITE_PREFIXES.items()}

IGNORED_FN = re.compile(
    r"#\[\s*ignore\b(?:\s*=\s*\"(?:[^\"\\]|\\.)*\")?\s*\]"
    r"(?:\s*(?://[^\n]*|#\[[^\]]*\]))*"
    r"\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)",
)


def ignored_tests(text):
    """The names of the `#[ignore]` functions in a Rust source text."""
    return IGNORED_FN.findall(text)


def suite_files(suite, tests=TESTS):
    """A test target's source files: `<suite>.rs` or `<suite>/**/*.rs`."""
    single = tests / f"{suite}.rs"
    files = [single] if single.is_file() else []
    folder = tests / suite
    if folder.is_dir():
        files += sorted(folder.rglob("*.rs"))
    return files


def landed(suite, tests=TESTS):
    return (tests / f"{suite}.rs").is_file() or (tests / suite / "main.rs").is_file()


def prefix_violations(tests=TESTS, guards=None):
    """[(suite, file, test)] for every guarded `#[ignore]` test outside its prefixes."""
    found = []
    for suite, pattern in (PREFIX_GUARDS if guards is None else guards).items():
        for path in suite_files(suite, tests):
            for name in ignored_tests(path.read_text(encoding="utf-8")):
                if not pattern.match(name):
                    found.append((suite, path.relative_to(tests).as_posix(), name))
    return found


def row_suites(row, tests=TESTS):
    """The binaries a row runs; an `allow_empty` row skips unlanded suites."""
    suites = row["suite"].split()
    if row.get("allow_empty") == "true":
        suites = [s for s in suites if landed(s, tests)]
    return suites


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
                suites.update(row_suites(row))
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


def check_prefixes():
    violations = prefix_violations()
    for suite, path, name in violations:
        print(f"ci-e2e-bundle: {path}: #[ignore] test `{name}` matches none of {suite}'s CI prefixes "
              f"({PREFIX_GUARDS[suite].pattern})", file=sys.stderr)
    return not violations


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--os", help="the runner label the rows use, e.g. ubuntu-latest")
    ap.add_argument("--cargo-json", type=Path)
    ap.add_argument("--dest", type=Path)
    ap.add_argument("--suites", nargs="*", help="bundle exactly these (landed) suites instead of the rows'")
    ap.add_argument("--check", action="store_true", help="only run the test-name prefix guard")
    args = ap.parse_args(argv)
    if not check_prefixes():
        return 1
    if args.check:
        print(f"ci-e2e-bundle: prefix guard ok ({', '.join(PREFIX_GUARDS)})")
        return 0
    if not (args.os and args.cargo_json and args.dest):
        ap.error("--os, --cargo-json and --dest are required unless --check")
    exe = ".exe" if sys.platform == "win32" else ""
    built = executables(args.cargo_json.read_text(encoding="utf-8"))
    if args.suites is not None:
        wanted = sorted(s for s in args.suites if landed(s))
    else:
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
