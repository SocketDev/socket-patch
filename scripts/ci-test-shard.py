#!/usr/bin/env python3
"""Run one shard of ci.yml's `test` or `test-release` job:
`cargo test --workspace` split over `COUNT` runners. Each runner compiles
and executes only its assigned integration targets, shortening both the
debug and release-mode jobs without changing their compilation profiles.

Shard 1 runs the unit tests (`--lib --bins`, ~4 min of the run on Windows)
and the doctests; the integration-test targets (`cargo metadata`, kind
`test`) are dealt out over the shards by name, with shard 1 taking a smaller
share to balance its unit tests. Every target lands in exactly one shard, so
the union of the shards is the old single `cargo test --workspace` run.

Extra arguments after `SHARD COUNT` go to every `cargo test` invocation.
Each invocation runs with `--no-fail-fast`; the exit status is non-zero if
any of them failed.

    python3 scripts/ci-test-shard.py 1 2
    python3 scripts/ci-test-shard.py 1 3 --locked --profile ci-release
"""

import json
import subprocess
import sys

# Shard 1's share of the integration targets, relative to every other
# shard's 1.0 (it also carries the unit tests and doctests).
FIRST_SHARD_WEIGHT = 0.5


def integration_targets(metadata):
    """Sorted, de-duplicated names of the workspace's integration tests."""
    members = set(metadata["workspace_members"])
    return sorted({t["name"] for p in metadata["packages"] if p["id"] in members
                   for t in p["targets"] if "test" in t["kind"]})


def partition(names, count):
    """`count` lists covering `names` exactly once, in order, with the first
    list weighted by FIRST_SHARD_WEIGHT."""
    if count < 1:
        raise ValueError("count must be >= 1")
    weights = [FIRST_SHARD_WEIGHT if count > 1 else 1.0] + [1.0] * (count - 1)
    shards = [[] for _ in range(count)]
    load = [0.0] * count
    for name in names:
        # The least-loaded shard relative to its weight; ties go to the lower index.
        i = min(range(count), key=lambda k: ((load[k] + 1) / weights[k], k))
        shards[i].append(name)
        load[i] += 1
    return shards


def invocations(shard, count, names, extra=()):
    """The `cargo test` argument lists shard `shard` (1-based) runs."""
    if not 1 <= shard <= count:
        raise ValueError(f"shard {shard} not in 1..{count}")
    base = ["cargo", "test", "--workspace", "--no-fail-fast", *extra]
    mine = partition(names, count)[shard - 1]
    runs = []
    if shard == 1:
        runs.append(base + ["--lib", "--bins"] + [a for n in mine for a in ("--test", n)])
        runs.append(base + ["--doc"])
    elif mine:
        runs.append(base + [a for n in mine for a in ("--test", n)])
    return runs


def main(argv):
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    shard, count = int(argv[0]), int(argv[1])
    metadata = json.loads(subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        check=True, capture_output=True, text=True).stdout)
    names = integration_targets(metadata)
    print(f"ci-test-shard: shard {shard}/{count}: "
          f"{len(partition(names, count)[shard - 1])} of {len(names)} integration targets", flush=True)
    status = 0
    for args in invocations(shard, count, names, argv[2:]):
        print("+ " + " ".join(args), flush=True)
        if subprocess.run(args).returncode != 0:
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
