#!/usr/bin/env python3
"""Run one shard of ci.yml's `test`, `test-release` or `coverage` job:
`cargo test --workspace` split over `COUNT` runners. Each runner compiles
and executes only its assigned integration targets, shortening both the
debug and release-mode jobs without changing their compilation profiles.

Shard 1 runs the unit tests (`--lib --bins`, ~4 min of the run on Windows)
and the doctests; the integration-test targets (`cargo metadata`, kind
`test`) are dealt out over the shards by name, with shard 1 taking a smaller
share to balance its unit tests. Every target lands in exactly one shard, so
the union of the shards is the old single `cargo test --workspace` run.

Windows debug CI sets CI_TEST_TIMINGS to the checked-in runtime sample.
Those shards balance measured test time plus linking work, with shard 1's
unit tests reserved up front. Coverage shards do the same on their own
Linux sample (scripts/ci-coverage-durations.json) unless CI_TEST_TIMINGS
is set; setting it empty on the coverage step keeps the count split.

CI_TEST_COVERAGE=1 runs the shard under cargo-llvm-cov for ci.yml's
`coverage` job: `cargo llvm-cov --no-report` in place of `cargo test`, and
no doctests, which cargo-llvm-cov leaves out without `--doctests`. A later
`cargo llvm-cov report` exports the shard's profiles.

Each test binary's `finished in` time is collected from cargo's output and
printed at the end as one `ci-test-shard: timings {...}` JSON line, along
with how long cargo took to reach its first test binary. The log tail is
what log viewers and the log API return, so a fresh runtime sample can be
read from any shard's log.

Extra arguments after `SHARD COUNT` go to every `cargo` invocation.
Each invocation runs with `--no-fail-fast`; the exit status is non-zero if
any of them failed.

    python3 scripts/ci-test-shard.py 1 2
    python3 scripts/ci-test-shard.py 1 3 --locked --profile ci-release
"""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time

# The Linux runtime sample coverage shards balance on (the Windows one,
# scripts/ci-test-durations.json, doesn't model them: #1768).
COVERAGE_TIMINGS = Path(__file__).with_name("ci-coverage-durations.json")

# Shard 1's share of the integration targets, relative to every other
# shard's 1.0 (it also carries the unit tests and doctests).
FIRST_SHARD_WEIGHT = 0.5

# cargo's `Running tests/x.rs (target/debug/deps/x-0123456789abcdef)` and
# `test result: ... finished in 1.23s` lines. The binary name, not the source
# path, is the target name (tests/apply/main.rs is `apply`); unit-test
# binaries are recorded as `unit:<crate>`. ANSI colour is stripped first.
ANSI = re.compile(r"\x1b\[[0-9;]*m")
RUNNING = re.compile(r"^\s*Running (unittests )?\S+ \(.*?([^/\\]+)-[0-9a-f]{16}(?:\.exe)?\)\s*$")
RESULT = re.compile(r"^test result: .*finished in ([0-9.]+)s\s*$")

# How long run() keeps reading cargo's pipe after cargo exits.
DRAIN_SECONDS = 10


def integration_targets(metadata):
    """Sorted, de-duplicated names of the workspace's integration tests."""
    members = set(metadata["workspace_members"])
    return sorted({t["name"] for p in metadata["packages"] if p["id"] in members
                   for t in p["targets"] if "test" in t["kind"]})


def partition(names, count, timings=None):
    """`count` lists covering `names` exactly once, in order, with the first
    list weighted by FIRST_SHARD_WEIGHT."""
    if count < 1:
        raise ValueError("count must be >= 1")
    if timings is not None:
        # Longest processing time first, reserving shard 1's unit-test cost.
        # Link overhead keeps a pile of fast tests from becoming a slow build.
        def cost(name):
            return timings["compile_seconds"] + timings["targets"].get(name, timings["default_seconds"])
        shards = [[] for _ in range(count)]
        load = [timings["unit_seconds"]] + [0.0] * (count - 1)
        for name in sorted(names, key=lambda n: (-cost(n), n)):
            i = min(range(count), key=lambda k: (load[k], k))
            shards[i].append(name)
            load[i] += cost(name)
        return [sorted(shard) for shard in shards]
    weights = [FIRST_SHARD_WEIGHT if count > 1 else 1.0] + [1.0] * (count - 1)
    shards = [[] for _ in range(count)]
    load = [0.0] * count
    for name in names:
        # The least-loaded shard relative to its weight; ties go to the lower index.
        i = min(range(count), key=lambda k: ((load[k] + 1) / weights[k], k))
        shards[i].append(name)
        load[i] += 1
    return shards


def invocations(shard, count, names, extra=(), timings=None, coverage=False):
    """The `cargo test` argument lists shard `shard` (1-based) runs."""
    if not 1 <= shard <= count:
        raise ValueError(f"shard {shard} not in 1..{count}")
    runner = ["llvm-cov", "--no-report"] if coverage else ["test"]
    base = ["cargo", *runner, "--workspace", "--no-fail-fast", *extra]
    mine = partition(names, count, timings)[shard - 1]
    runs = []
    if shard == 1:
        runs.append(base + ["--lib", "--bins"] + [a for n in mine for a in ("--test", n)])
        if not coverage:
            runs.append(base + ["--doc"])
    elif mine:
        runs.append(base + [a for n in mine for a in ("--test", n)])
    return runs


def run(args, timings):
    """Run `args`, echoing its merged output byte for byte, and add each test
    binary's `finished in` seconds to `timings`. Returns the exit status and
    when the first test binary started (None if none did)."""
    first = None

    def forward(pipe):
        nonlocal first
        current = None
        echo = True
        for raw in pipe:
            # Keep draining after a failed write (say `tee` died): a reader
            # that stops would leave cargo blocked on a full pipe.
            if echo:
                try:
                    sys.stdout.buffer.write(raw)
                    sys.stdout.buffer.flush()
                except (OSError, ValueError):
                    echo = False
            line = ANSI.sub("", raw.decode("utf-8", "replace"))
            if m := RUNNING.match(line):
                current = ("unit:" if m[1] else "") + m[2]
                first = first or time.monotonic()
            elif current and (m := RESULT.match(line)):
                timings[current] = timings.get(current, 0.0) + float(m[1])
                current = None

    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    reader = threading.Thread(target=forward, args=(proc.stdout,), daemon=True)
    reader.start()
    status = proc.wait()
    # A process a test left behind (a build daemon, say) can hold the pipe
    # open after cargo exits; don't wait for it past a short drain.
    reader.join(timeout=DRAIN_SECONDS)
    if not reader.is_alive():
        proc.stdout.close()
    return status, first


def main(argv):
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    shard, count = int(argv[0]), int(argv[1])
    metadata = json.loads(subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        check=True, capture_output=True, text=True).stdout)
    names = integration_targets(metadata)
    coverage = os.environ.get("CI_TEST_COVERAGE") == "1"
    timing_path = os.environ.get("CI_TEST_TIMINGS", COVERAGE_TIMINGS if coverage else None)
    timings = json.loads(Path(timing_path).read_text(encoding="utf-8")) if timing_path else None
    print(f"ci-test-shard: shard {shard}/{count}: "
          f"{len(partition(names, count, timings)[shard - 1])} of {len(names)} integration targets", flush=True)
    status = 0
    measured = {}
    build = 0.0
    for args in invocations(shard, count, names, argv[2:], timings, coverage):
        print("+ " + " ".join(args), flush=True)
        start = time.monotonic()
        code, first = run(args, measured)
        if code != 0:
            status = 1
        # Build time of this invocation: start to its first test binary.
        # (The doctest run prints no `Running` line and isn't counted.)
        if first is not None:
            build += first - start
    measured = {"_build_seconds": build, **dict(sorted(measured.items(), key=lambda kv: (-kv[1], kv[0])))}
    print("ci-test-shard: timings " + json.dumps({k: round(v, 2) for k, v in measured.items()}), flush=True)
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
