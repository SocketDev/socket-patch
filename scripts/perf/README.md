# Network benchmark harness

Most `scan` time is spent waiting on API round trips. Live timings are noisy
and can't be repeated, so this harness records the API traffic of one real run
and then replays it locally. That makes timing deterministic and gives a
byte-level oracle for "same output" when comparing two builds.

- `replay.py` is a plain-HTTP stand-in for `api.socket.dev`,
  `patch.socket.dev` and the public proxy `patches-api.socket.dev`. It has
  two modes:
  - `record` forwards each request and stores the response.
  - `replay` serves responses from the store only. It can add a fixed
    per-request latency (`--latency-ms`) or replay the latency measured while
    recording (`--latency recorded`). It can also add a per-connection
    latency (`--conn-latency-ms`).

  Batch POSTs are replayed per purl, so a build that changes chunking, batch
  size or purl order still gets the same answers. Each run's stats report
  request counts per endpoint, `max_inflight`, connections, `network_span_s`,
  average parallelism, `misses` and `batch_unknown_purls`.
- `bench.sh` starts `replay.py`, points the CLI at it through
  `SOCKET_API_URL`, `SOCKET_PROXY_URL` and `SOCKET_PATCH_SERVER_URL`, and
  prints one stats line per run. Run `bench.sh` with no arguments to see all
  of its settings.

A store holds real API responses, which can include paid-patch data. Keep
stores outside the repository: `bench.sh` refuses to use a store path inside
the repository. For the same reason, never commit recorded responses or
third-party lockfiles.

## Usage

```sh
S=/some/dir/outside/the/repo
P=~/Projects/some-project

# 1. Record one real run. This uses your normal token/org config; replay must
#    use the same auth state, because it decides which routes the CLI calls.
CWD=$P BIN=./target/release/socket-patch \
  scripts/perf/bench.sh record $S/store -- scan --json --mode hosted --dry-run --no-telemetry

# 2. Replay three times with 100 ms of simulated latency per request (no network).
CWD=$P scripts/perf/bench.sh replay $S/store 100 3 -- scan --json --mode hosted --dry-run --no-telemetry

# 3. A/B test: runs BASE, NEW, BASE, NEW, ... (3 pairs here) against the same store.
CWD=$P BASE=$S/socket-patch-base NEW=./target/release/socket-patch PORT=18200 \
  scripts/perf/bench.sh ab $S/store 100 3 -- scan --json --mode hosted --dry-run --no-telemetry
```

Use a different `PORT` for each concurrent bench (it takes `PORT` through
`PORT+2`). Latency `0` isolates local work such as the crawl and rewrites.
`recorded` gives realistic totals. `FILL=1` forwards and records requests the
store doesn't have yet, for when a change adds endpoints.

## Reading the results

`ab` passes only if every run's stdout sha256 and exit code match the first
BASE run. Otherwise it exits 1 and lists the runs that differ as
`vs_base=DIFFERS`. It also prints the median wall time for each binary and
whether stderr was byte-identical across runs. Per-run stdout, stderr and
stats JSON, plus `ab-summary.tsv`, go to `$OUT` (default: `STORE/runs`).
Check every run for all of the following:

- `misses=0` and `unknown_purls=0`. Anything else means the run asked for
  something that was never recorded. Record again, or use `FILL=1`.
- `by_kind` totals match between BASE and NEW, unless the change is meant to
  alter request counts.
- A concurrency change shows up as a higher `max_inflight` and a lower
  `net_span`.

On a loaded machine, compare only interleaved runs, which is what `ab` does,
and look at medians. A wet (non-`--dry-run`) run changes the project, so set
`PRE_RUN` to a command that restores a scratch copy of the project before each
invocation. Never point a wet run at a checkout you care about.
