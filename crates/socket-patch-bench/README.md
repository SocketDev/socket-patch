# socket-patch-bench

Benchmarks for `socket-patch scan`, and the CI gate that keeps it from
getting slower. The harness generates a synthetic project per package
manager, serves the patch API from a local mock, runs the real
`socket-patch` binary on it, and checks every run did the work the project
calls for before keeping its timing.

```sh
# Build the binary the way CI does (release semantics, thin LTO).
cargo build --locked --profile perf -p socket-patch-cli -p socket-patch-bench

target/perf/socket-patch-bench list
target/perf/socket-patch-bench run --bin target/perf/socket-patch
target/perf/socket-patch-bench run --bin target/perf/socket-patch -f '^npm/' -f '^uv/' -v

# A/B: interleaved base/head runs on this machine, same verdict as CI.
target/perf/socket-patch-bench compare --base /tmp/base/socket-patch --head target/perf/socket-patch
```

`run` and `compare` print a markdown table; `--out DIR` also writes
`results.json` (every sample, request counts and verdicts) and `summary.md`.

## What is measured

Each scenario is one project and one `scan` invocation:

| scenario | what runs |
|---|---|
| `<pm>/hosted` | `socket-patch scan --json` (the default hosted mode) on a freshly installed project: crawl, lockfile inventory, hosted-pin discovery, batch query, per-package details, reference resolution, artifact checks where the ecosystem needs them, the rewrite, patch views and the writes |
| `<pm>/rescan` | the same scan on a project a previous scan already redirected — the steady state of a CI job that scans every build: pin discovery and update detection over rewritten lockfiles, and a no-op redirect |
| `npm/dry-run` | `scan --dry-run`: everything up to the rewrite, no views, no writes |
| `npm/public-proxy` | no API token: the public proxy's routes, batch size and concurrency cap |
| `npm/latency` | 40 ms per API request: request concurrency, not local work, decides the time |

Package managers (`<pm>`), each in its native lockfile format and install
layout: `npm`, `pnpm` (isolated `.pnpm` store with symlinks), `yarn-classic`,
`yarn-berry` (node-modules linker), `bun` (text `bun.lock`, hoisted),
`bun-isolated` (the same lockfile, Bun 1.3's isolated `.bun` store),
`vlt` (`.vlt` store), `pip` (hash-pinned `requirements.txt`), `uv`, `pylock`
(PEP 751), `poetry`, `pipenv`, `pdm`, `hatch` (lockless: `hatch.toml`
environment pins, rewritten in place), `bundler`, `composer`, `cargo`,
`golang`, `nuget` (a restored project: `packages.lock.json` plus
`obj/project.assets.json`, so the crawl looks the restore's packages up
in `~/.nuget/packages` instead of walking it), `maven` and `gradle`
(`gradle.lockfile`, Gradle's `modules-2/files-2.1` cache; hosted mode
wires the build through
`.socket/gradle/`). Deno has no hosted rewrite and is not benchmarked
separately.

Sizes are a large-but-ordinary project for the ecosystem (3000 npm-family
packages, 1500 for vlt, 400-1200 for the others, so every scan takes about
70 ms or more; `--scale` multiplies them), with 2-3% of packages patched. The graphs are generated from a fixed seed:
every run, on every machine, scans byte-identical projects.

Per run the harness records wall time (spawn to exit), user+system CPU time
and peak RSS (from `wait4`, for exactly that child), and the mock's request
count per endpoint.

### Making sure a timing means something

A fast run that skipped work is a bug, not a speedup, so every run is
validated and an invalid run fails the scenario instead of contributing a
sample:

- exit code 0 and one JSON document on stdout, `status: success`;
- `scannedPackages`, `lockfileOnlyPackages`, `packagesWithPatches` and
  `totalPatches` equal what the generated project contains;
- hosted runs: `redirect.redirected` is every patch, `rewrittenFiles` is
  exactly the expected set, nothing is skipped, every warning code is one
  the scenario expects, and each reported file really changed on disk;
- dry runs: nothing on disk changed;
- rescans: nothing is rewritten and every patch is classified `already`;
- the CLI made no request the mock does not serve, and the same requests
  on every run.

Each run starts from the pristine project: wet runs rewrite lockfiles, so
the harness diffs the tree against a snapshot after every run and restores
whatever changed (cheap, and it also catches a run that writes somewhere
unexpected). A rescan's first, preparing scan is untimed.

The environment is rebuilt from nothing for every run (`env -i`): `HOME`,
`XDG_*` and `TMPDIR` point into the fixture, so per-user caches
(`~/.cargo`, `~/go/pkg/mod`, `~/.nuget/packages`, `~/.m2`, and
`GRADLE_USER_HOME`, which the Gradle fixture sets) are the fixture's own
and the runner's are never read; telemetry, the update check
and the persisted Socket login are off; and every proxy variable points at a
closed port, so a request to anything but the mock fails the run instead of
timing the internet. Python fixtures carry a project `.venv` and Ruby ones
`vendor/bundle`, as installed projects do — without them the crawlers would
spawn `python3` / `gem env` and read the machine's global packages. The
`pipenv` scenario sets `SOCKET_PIPENV_MAJOR` so the CLI does not spawn
`pipenv --version`. `strace -f -e trace=execve` on any scenario shows the
CLI spawns nothing.

## The CI gate

`.github/workflows/bench.yml` runs `compare` on every pull request that
touches Rust code. It builds the PR's base commit and the PR head with the
same profile, on the same runner, and interleaves their runs (base, head,
head, base, ...): runner-to-runner variance is larger than most regressions,
so only same-machine pairs are compared.

A scenario fails the gate when any of these hold:

- **wall or CPU time**: the median of the per-pair `head / base` ratios is
  above `1 + --threshold` (default 10%) *and* its 95% sign-test confidence
  interval lies entirely above 1 *and* the medians differ by at least 3 ms.
  A scenario that first looks regressed is re-run with `--confirm-runs`
  more pairs and judged on all of them, so one noisy burst cannot fail a PR;
- **peak RSS**: the same test at `--rss-threshold` (default 15%);
- **API requests**: head makes more requests than base (deterministic, so
  any increase counts);
- **validation**: the head binary fails a scenario's checks. (A base that
  fails one only loses that scenario's comparison — e.g. a PR that changes
  the JSON output and updates the expectations here in the same PR.)

The job summary has the full table; `results.json` is uploaded as an
artifact. A PR whose slowdown is intentional can carry the
`performance-regression-accepted` label: the comparison still runs and is
reported, but does not fail.

On pushes to `main` the same comparison runs against the previous commit
and is recorded as an artifact without gating.

## Profiling one scenario

`serve` builds a scenario's project, starts its mock API and prints the exact
command line a run uses, then waits:

```sh
target/perf/socket-patch-bench serve poetry/hosted --bin target/perf/socket-patch
# paste the printed `env -i ...` command under perf / samply / strace
```

A wet scan edits the project in place; rerun `serve` for a fresh copy.

## Adding a scenario

Fixtures live in `src/fixtures/` (`npm.rs` for the npm family, `pypi.rs`,
`other.rs`) and are registered in `fixtures::ALL`. A generator writes the
project under `project/` (and any per-user cache under `home/`), and returns
the patches the mock serves and an `Expect` describing what a correct scan
reports. Run it with `-v` until it validates; the error names the first
mismatch. The record/replay harness in `scripts/perf/` complements this for
measuring against real API traffic.
