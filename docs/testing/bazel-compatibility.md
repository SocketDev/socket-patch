# Bazel compatibility

This guide covers the real-Bazel suite, `e2e_bazel_build`: the installer and
pins that provide Bazel, the harness that runs it, and the rules a test
follows. socket-patch itself never runs Bazel. The suite does, to prove with
Bazel's own output that a build consumes what socket-patch wrote, or still
passes where socket-patch refused to write.

The hermetic Bazel suites (`e2e_bazel`, and the unit tests under
`crates/socket-patch-core/src/bazel/`) need no Bazel and run in the normal
`cargo test` job. Everything below needs a Bazel binary.

State of this document: it describes the harness, the CI matrix and the
report audit. The lane tests land in later changes. Everything has run on
macOS arm64 only; where a statement about Windows or Linux x86_64 has not been
confirmed by a CI cell it says so.

## Getting a pinned Bazel

```sh
scripts/install-bazelisk.sh <bazel-version> <dir>
```

The script installs two single-file binaries into `<dir>`: bazelisk v1.30.0
and the Bazel release itself, from the GitHub release (for Bazel,
`releases.bazel.build` is tried second). Each must match the sha256 pinned for
the platform in [`scripts/bazel-pins.txt`](../../scripts/bazel-pins.txt). It
fails closed: a version or platform with no pin exits non-zero before anything
is downloaded, and a download that does not match is deleted. A file already
in `<dir>` that matches its pin is reused, so CI can restore `<dir>` from a
cache. It prints four lines for `$GITHUB_ENV`:

```
SOCKET_PATCH_BAZEL_E2E_BAZEL=<dir>/bazel-<version>-<platform>
SOCKET_PATCH_BAZEL_E2E_BINARY=<dir>/bazel-<version>-<platform>
SOCKET_PATCH_BAZEL_E2E_BAZELISK=<dir>/bazelisk-v1.30.0-<platform>
SOCKET_PATCH_BAZEL_E2E_VERSION=<version>
```

Tests drive the verified Bazel binary directly, so no `.bazelversion`,
`tools/bazel` wrapper or network version lookup is involved. Bazelisk is used
by the launcher cell alone, which runs it with `USE_BAZEL_VERSION` set to the
binary's absolute path. `setup-bazel` is not used: it rewrites `~/.bazelrc`
with one output base for every workspace and verifies no digest.

### Pins

`scripts/bazel-pins.txt` holds one pin per line, `<tool> <version> <platform>
<sha256>`. Pinned today: Bazel 5.4.1, 6.6.0, 7.0.2, 7.1.2, 7.7.2, 8.4.2, 8.8.2
and 9.3.2 for `linux-x86_64`, `darwin-arm64` and `windows-x86_64`; 10.0.0rc3
for `linux-x86_64` (record-only cells); bazelisk v1.30.0 for the three
platforms. To add a version, copy one digest per platform from the release's
published `.sha256` file (the URLs are in the file's header), never from a
download of your own. `scripts/tests/test_install_bazelisk.py` fails when a
version lacks a platform, so a cell on an unpinned version fails a unit test
before it fails in CI. Bazel 7.7.0 must not be pinned: it alone writes absolute
`file:///` registry keys into `MODULE.bazel.lock`.

## Running the suite

```sh
eval "$(scripts/install-bazelisk.sh 9.3.2 "$HOME/.cache/socket-patch-bazel" | sed 's/^/export /')"
export SOCKET_PATCH_BAZEL_E2E_REQUIRED=1
cargo test -p socket-patch-cli --test e2e_bazel_build -- --ignored bazel_core_ --test-threads=2
```

Every test that runs Bazel is `#[ignore]`. Without `--ignored` the binary runs
only the harness's own self-tests, which need no Bazel. With `--ignored` and no
`SOCKET_PATCH_BAZEL_E2E_*` variable, a test looks for `bazel` on `PATH`; when
there is none it prints `SKIP`, writes a report of status `skipped` and passes.

A test name starts with one of six prefixes, which the CI cells group by:
`bazel_core_` (the toy fixture; no network where the line's module archives
are committed, which is every pinned line but 8.8.2), `bazel_guard_`,
`bazel_agent_`, `bazel_hosted_`, `bazel_vendor_` and `bazel_canary_`
(record-only). `scripts/ci-e2e-bundle.py --check` refuses any other name, and
`scripts/bazel-matrix.py --check` does the same for a test a macro declares.

| Variable | Meaning |
|---|---|
| `SOCKET_PATCH_BAZEL_E2E_BAZEL` | The Bazel binary to drive, or a launcher. Unset: `bazel` on `PATH`. A relative path is resolved against the directory the tests run from (`crates/socket-patch-cli`), not against the workspace copy Bazel runs in. |
| `SOCKET_PATCH_BAZEL_E2E_VERSION` | `bazel --version` must print exactly this. Exported to the child as `USE_BAZEL_VERSION`, so a launcher selects it. |
| `SOCKET_PATCH_BAZEL_E2E_REQUIRED` | Non-empty: a missing Bazel or an unreachable origin fails instead of printing `SKIP`. CI sets it. |
| `SOCKET_PATCH_BAZEL_E2E_GROUP` | `core`, `light` or `heavy`. A test of another group prints `SKIP (n/a)`. |
| `SOCKET_PATCH_BAZEL_E2E_SYSTEM` | `bzlmod`, `workspace` or `hybrid`. A test of another system, or of a system the Bazel line does not have, prints `SKIP (n/a)`. |
| `SOCKET_PATCH_BAZEL_E2E_BAZELISK`, `_BINARY` | The launcher cell: the pinned bazelisk runs the release binary. |
| `SOCKET_PATCH_BAZEL_E2E_PROBE_DIR` | Where the per-cell JSON reports go. Default: `target/tmp/bazel-probe`, which persists between runs. A run whose reports are audited sets this to an empty directory (see [Reports](#reports)). |
| `SOCKET_PATCH_BAZEL_E2E_CACHE_ROOT` | A persistent repository cache (`<root>/repos`) shared by every test. Default: an empty cache per test. |
| `SOCKET_PATCH_BAZEL_E2E_OUTPUT_ROOT` | A short directory for output user roots (Windows path limits). |
| `SOCKET_PATCH_BAZEL_E2E_ARGS` | Extra whitespace-separated options for every Bazel command. |
| `SOCKET_PATCH_BAZEL_E2E_OFFLINE` | The offline phase (below). |
| `SOCKET_PATCH_BAZEL_E2E_REAL_REGISTRIES` | The real-registry cell: tests with such a variant skip the fixture server. |

A name that `_GROUP` or `_SYSTEM` does not know is a failure, not "run
everything": a typo in a CI cell must not turn into a run that skips what it
was meant to cover.

A test of the toy group runs only where its matrix claims it. `Cell::open`
reads the group's matrices (`core/MATRIX.json`, `core/guard/MATRIX.json`):
on a Bazel release one of them has a cell for, a test they list runs only
when its own row names that release, and prints `SKIP (n/a)` otherwise. A
prefix run such as `--ignored bazel_core_` therefore leaves a `ran` report
for the claimed (test, Bazel) pairs and for no other. To run a test on one
more release, add the release to its row first; the report of that run is
then the evidence for the claim. On a release no toy matrix has a cell for
(8.4.2, 10.0.0rc3) nothing is declined this way: a toy test there runs if the
fixture and the registry files exist, and fails a required cell if they do
not. The rule looks at the Bazel release only, not at the `os` list of a row.

## Isolation

Each test owns one temp root (`<T>`), with one workspace copy and one output
base. Nothing may be written outside it. Every invocation is

```
bazel --nohome_rc --nosystem_rc --output_user_root=<T>/root --max_idle_secs=15 \
      --host_jvm_args=-Djava.io.tmpdir=<T>/tmp --host_jvm_args=-XX:-UsePerfData \
      <command> --color=no --curses=no --repository_cache=<T>/cache --repo_env=HOME=<T>/home ...
```

plus, per Bazel line: the dependency-system flags, `--lockfile_mode` with a
stated value (6.2 and later), `--repo_contents_cache=` (8.3 and later, so
fetched repositories are not shared between workspaces), and the downloader
config when the test has a fixture server (`--downloader_config` from 8.2.0,
`--experimental_downloader_config` before: 8.0.x and 8.1.x do not know the
new name). The workspace `.bazelrc` stays active, because socket-patch's
model reads it.

- `--output_user_root` alone keeps the output base and install base inside
  `<T>`. `--output_base` does not: Bazel still creates the default user root.
- Without the two JVM options the server writes `hsperfdata_<user>`,
  `bazel-jni.<N>` and a netty library into the shared temp directory, and
  Bazel 10.0.0rc3 exits 37 when that directory is not writable. On macOS the
  JVM does not follow `TMPDIR`.
- The startup options never vary within a test: a different
  `--host_jvm_args` restarts the server.
- Environment: `HOME`, `USERPROFILE`, `TMPDIR`, `TMP`, `TEMP` and
  `COURSIER_CACHE` point into `<T>`; `DO_NOT_TRACK=1`; `TEST_TMPDIR`, `NETRC`,
  `XDG_CACHE_HOME`, the proxy variables, `CI`, `GITHUB_ACTIONS`, `CARGO_HOME`,
  `GOFLAGS`, `GOENV`, `GOMODCACHE`, `NUGET_PACKAGES`, `GEM_HOME` and every
  `BAZELISK_*` are removed. `TEST_TMPDIR` must not reach a Bazel server: it
  puts the server in test mode, where a failing module extension on 7.x is a
  crash (exit 37) instead of an error. Because a launcher may export it
  itself, the harness also sets `ENABLE_BUG_REPORT_LOGGING_IN_TEST=1` and
  `NO_CRASH_ON_LOGGING_IN_TEST=1`.
- Bazelisk creates its home directory on every run, `--version` included, and
  a scratch `HOME` does not move it. When the program is known to be bazelisk
  (the launcher cell, or a file named `bazelisk`) the harness sets
  `BAZELISK_HOME=<T>/bazelisk`. A wrapper script that contains bazelisk itself
  keeps its own home; `bazel_core_launch_isolated` fails if any launcher
  writes the default one.
- The harness fails fast when the workspace path holds a space (Bazel 7.2.0
  and earlier refuse to run) or a non-ASCII byte (7.7.2 and earlier).
- A `Drop` guard runs `bazel shutdown`, makes the output base writable and
  removes `<T>`, also when the test panics. At most two servers run at once,
  and a test holds one cell at a time: it closes its cell before it opens a
  twin (opening a second one panics).
- A server that was killed or that crashed (exit 37, the OOM killer) leaves
  its `server/server.pid.txt` behind: only a JVM shutdown hook removes it,
  and `bazel shutdown` returns at once when no server answers. After a
  successful `bazel shutdown` the harness therefore checks whether the
  process a remaining pid file names still exists (`kill(pid, 0)`; on
  Windows `tasklist`, untested) and removes the file of a dead one. Only a
  server that is still running is an error.
  `bazel_core_shutdown_after_the_server_was_killed` kills a server with
  `SIGKILL` and checks that the cell shuts down, starts a new server and
  closes (Unix only; `SKIP (n/a)` on Windows).

`bazel_core_launch_isolated` is the test of these rules: the version matches,
the output base and install base are under `<T>/root`, the server JVM has the
scratch temp directory and wrote no perf-data file, and none of
`~/.cache/bazel`, `~/Library/Caches/bazel`, `/private/var/tmp/_bazel_$USER` or
the default bazelisk home was created or changed. It runs only `info` and
`shutdown`, so it needs no network. It has run on macOS arm64 for Bazel 7.0.2,
7.7.2 and 9.3.2; Linux and Windows are unconfirmed until a CI cell runs it.

The check must not depend on the test process having `USER` set (a Docker
container often sets `HOME` alone). The perf-data check looks into every
`hsperfdata_*` directory for the server's pid. The user's name in the default
output root (`/private/var/tmp/_bazel_<user>` on macOS,
`%USERPROFILE%\_bazel_<user>` on Windows) comes from `USER` or `USERNAME`, else
from `LOGNAME` and `id -un`. When no name can be found on those two systems
the test fails instead of watching nothing; on Linux the root is under
`~/.cache/bazel`, which is watched through `HOME`. A test process with
neither `HOME` nor `USERPROFILE` fails the same way.

On Windows the harness sets `BAZEL_SH` to Git's or MSYS2's `bash.exe` when it
is unset (Bazel otherwise takes the first `bash.exe` on `PATH`, which on a
hosted runner is WSL's). This is untested.

## Fixture server and downloads

Locks keep production host names. A test that serves packages starts the
harness's loopback server and passes the downloader config rendered from
[`fixtures/bazel/common/downloader.cfg.tmpl`](../../crates/socket-patch-cli/tests/fixtures/bazel/common/downloader.cfg.tmpl):

```
rewrite ((?!127\.0\.0\.1[:/]).*) http://127.0.0.1:<port>/$1
block *
allow 127.0.0.1
```

Every URL Bazel's downloader fetches then reaches the server as
`/<host>/<path>`. A URL with nothing registered gets a 404 at once (a rewrite
to a closed port costs Bazel 12 to 79 seconds per miss). The server's request
log is the `hosts` field of the cell report.

- **Offline phase** (`SOCKET_PATCH_BAZEL_E2E_OFFLINE`): the same config
  against a server whose store is empty, with `HTTP_PROXY`, `HTTPS_PROXY` and
  `ALL_PROXY` at `127.0.0.1:9` and `NO_PROXY=127.0.0.1,localhost`. The
  assertion is "the server log holds no request for the package's own URL"
  (`FixtureServer::assert_not_requested`), not "no request", and it has no
  minimum either: the phase runs on the warm cache, where a fully checksummed
  fixture sends nothing at all. A warm repository cache plus `block *` is not
  an offline recipe before Bazel 9.3.0: it fails at the first archive without
  a `type`.
- **Twins.** A tamper or withdrawal twin runs on a new output base with an
  empty repository cache (`Cell::open_cold`): with a warm cache the same URL
  and checksum pass with zero requests. Every assertion about what a cold run
  sent first asserts that the artifact itself was requested
  (`FixtureServer::assert_requested(url, ..)`, which returns its requests so
  a withdrawal twin can read the status). "Some request arrived" is not
  enough: under the rewrite a cold cell always asks the server for registry
  files (`bcr.bazel.build/...`), also when the artifact was never fetched.
  `assert_no_header(name, artifact_url, ..)` makes that check and then scans
  every request, because a credential on any of them is a leak.
- `FixtureServer::serve` answers with `Content-Type: application/octet-stream`,
  which Bazel's downloader ignores. A client that reads the type gets it from
  `serve_as(url, content_type, bytes)`: pip accepts an index page only as
  `text/html` or `application/vnd.pypi.simple.v1+html` / `+json`.
- Fetches that do not go through Bazel's downloader (pip, cargo under
  crate_universe, Go modules, unpinned Coursier) need their own lever. One
  module per upstream registry lives under
  `tests/bazel_build_common/registry/`. A fixture whose packages such a tool
  fetches says `"fetch": "tool"` in its `MATRIX.json`, and a test that plays
  the Socket API takes the origin it advertises from
  `FixtureServer::hosted_origin(fetcher)`: `https://patch.socket.dev` for
  Bazel's downloader, so everything socket-patch writes is production-shaped
  and arrives through the rewrite, and the loopback origin for a tool the
  rewrite cannot reach.

## `MODULE.bazel.lock`

Bazel owns this file, and a live server keeps its own view of it.

1. A test writes it only through `Cell::write_module_lock`, which runs `bazel
   shutdown` first. On 7.2.0 to 8.7.0 and 9.0.2 a live server that just
   rewrote the lock reverts an outside edit at its next `info` or `shutdown`.
2. A lock snapshot is never restored onto an output base that already
   evaluated newer inputs. Close the cell, open a new one and build its tree
   again.
3. One tree yields three different locks (`query`; `build`, `cquery` and
   `fetch`; the `mod` commands). An oracle `mod` command runs with
   `--lockfile_mode=off` (`Cell::mod_oracle`). The stale-lock oracle is an
   `error`-mode build of a target that consumes the hub
   (`Cell::error_mode_build`), never `bazel mod deps --lockfile_mode=error`.
   A cell refuses both mistakes on every `mod` command it builds: `deps` in
   `error` mode, and any subcommand that only asks (`graph`, `show_repo`,
   `show_extension`, `all_paths`, `path`, `explain`, `dump_repo_mapping`) in
   a mode other than `off`.
4. The repository cache lies outside the workspace copy (9.3.2 exits 2
   otherwise).
5. A cell that expects a fetch to fail runs one command with
   `--experimental_repository_downloader_retries=0` (`Cell::failing_fetch`).

Rule 2 is the one rule no helper enforces: to the harness a restored snapshot
and a hand edit are the same bytes. There is no restore helper; a saved tree
goes into a new cell.

`Cell::write` refuses `MODULE.bazel.lock` (and a path that leaves the
workspace copy), so rule 1 cannot be skipped by accident.
`bazel_core_lock_writes_stop_the_server` checks against a live server that
`write_module_lock` and a tree copy that carries a lock stop it first; it runs
only `info` and `shutdown`.

`Cell::baseline` runs every command class a scenario later runs, before the
test takes its snapshot. Tree comparisons after Bazel ran leave out what Bazel
owns (`bazel_common::assert_same_tree_but_bazel_owned`), and lock equality
after a rollback is asserted only after `bazel shutdown` and a second
baseline: `Cell::lock_after_rebaseline` does both and returns the lock to
compare with the one step 1 left.

## Proof ladder

The oracle is always something Bazel reports or builds, never a file
socket-patch wrote, and the harness never names `external/<repo>` itself: it
asks Bazel. Every fixture defines `//:socket_probe` with the shared rule in
[`fixtures/bazel/common/probe.bzl`](../../crates/socket-patch-cli/tests/fixtures/bazel/common/probe.bzl),
which the harness copies to the workspace root (`load("//:probe.bzl",
"socket_probe")`); a fixture that ships its own `probe.bzl` is refused. The
rule symlinks each source to an output and uses no shell, so it builds
without Bash. A file input builds on every line from 5.4.1 on. A
tree-artifact input gets a directory output, which needs Bazel 6: it builds
on 6.2.1 and 6.6.0 (6.0 and 6.1 were not run) and fails on 5.4.1 with
`Creating symlink ... failed: ... (File exists)`. No fixture gives the probe
a directory input on a 5.x line.

| Tier | Command | Proves |
|---|---|---|
| 0 | `bazel query --noimplicit_deps --notool_deps --output=location 'kind("source file", deps(//:socket_probe))'`, then the digest of the one listed file the ruleset's anchor names | The repository Bazel materialised holds the patched bytes. rules_js: the sha512 of `package.tgz` against the lock's `integrity`. rules_jvm_external: the jar under the artifact repository's `file/` directory, never `processed_<jar>`. |
| 1 | `bazel build //:socket_probe` and `cquery --output=files`, on a warm server and after `bazel shutdown` | An action input is the patched file. |
| 2 | `bazel run //:consumer` printing a marker from patched code | The language rule consumes it. |

Two tests build the rule over a file and a tree artifact (the shape rules_js
hands it), on a warm and on a restarted server:

- `bazel_core_probe_rule_takes_a_tree_artifact` runs on the toy cell of
  every release that has the Bzlmod fixture (6.6.0, 7.0.2, 7.1.2, 7.7.2,
  8.8.2 and 9.3.2), so nothing leaves the machine where the line's module
  archives are committed (every one of them but 8.8.2). It also checks that
  a restarted server writes the same `MODULE.bazel.lock` for the baseline
  commands (`Cell::lock_after_rebaseline`), also on 6.6.0, 7.0.2 and 7.1.2,
  whose lock is of the older family that names the registry it was made
  against. The tree is made with `/bin/cp`: `SKIP (n/a)` on Windows.
- `bazel_canary_probe_rule_tree_artifact` runs on any selected Bazel, with no
  fixture; the nightly plan runs it on the pinned releases the toy test does
  not claim (5.4.1, 8.4.2 and 10.0.0rc3). Before Bazel 6 it builds the file
  input alone and records `"tree_artifact": "unsupported before Bazel 6"` in
  the report's details. It is record-only and uses the network on a Bzlmod
  line (Bazel resolves its builtin modules from the registry), so it prints
  `SKIP (n/a)` in the offline phase.

## Reports

Each test writes `<probe dir>/<test>.<bazel>.<system>.<os>-<arch>.json`:

```json
{
  "test": "bazel_core_launch_isolated",
  "status": "ran",
  "reason": null,
  "bazel": "9.3.2",
  "os": "macos",
  "arch": "aarch64",
  "group": "core",
  "system": null,
  "lanes": [],
  "hosts": [],
  "hosts_source": "none",
  "direct_network": false,
  "wall_ms": 11022,
  "resolved": {},
  "details": {}
}
```

`status` is `ran` only when the test reached its last line; a test that
printed `SKIP` or `SKIP (n/a)` writes `skipped` with the reason. A lane may
claim a Bazel line, dependency system or OS only with a `ran` report for it.
`hosts` is the fixture server's log, `resolved` the ruleset versions `bazel
mod graph` reported, and `direct_network` marks a test that reached hosts
without the downloader rewrite.

- `hosts_source` says where `hosts` came from: `fixture_server_log` when the
  test set it with `Report::hosts_from_log` (or `hosts_from_renamed_log`, for
  a request a tool sent straight to the loopback origin, which the log cannot
  name), else `none` beside an empty list. The field is private, so a test
  cannot write a list by hand, and the audit refuses any report whose list
  names a host without that source. `hosts_from_renamed_log` takes the
  server's own list with some entries renamed to `127.0.0.1` and panics on
  anything else: a name the server did not log, or a logged name left out.
- `lanes` names the lanes the test proves on its cell (`Report::proves("H-JS1")`).
  The claims audit matches a lane's claim against it, so a lane test that does
  not call `proves` is evidence for nothing. Neither is one that never read
  its fixture server's log: the audit refuses a `ran` report that names a
  lane with `hosts_source` `none`, and does not count it for a claim.

A test that fails leaves no report. It writes none, and because the file name
is fixed per cell and the default directory persists, `Cell::open` removes the
report an earlier run of the same cell left as soon as it knows the Bazel
version: a passing run followed by a failing one does not keep a `ran` report
on disk. Two cases are out of that reach, because the later run never learns
the earlier file's name: a test the later run does not run at all, and a later
run that skips before it finds a Bazel (no Bazel, or another `_GROUP` or
`_SYSTEM`; that report is `<test>.none...json`). **A run whose reports are
audited therefore sets `SOCKET_PATCH_BAZEL_E2E_PROBE_DIR` to a new, empty
directory.**

## CI matrix and audit

| Where | Runs | Blocking |
|---|---|---|
| `ci.yml`, job `e2e`, one row | `--ignored bazel_core_` on Bazel 9.3.2 on ubuntu: the toy fixture, no network | yes |
| [`bazel-compatibility.yml`](../../.github/workflows/bazel-compatibility.yml) on a pull request that touches a Bazel path | the cells of tier `pr` | no |
| the same workflow nightly, on dispatch, and on a pull request labelled `bazel-matrix` | every cell | no (a red audit blocks promoting a lane) |

The workflow's matrix is generated. Each fixture group or ruleset has a
`MATRIX.json` under `crates/socket-patch-cli/tests/fixtures/bazel/` that lists
its tests, the Bazel releases each runs on and a tier (`pr` or `nightly`).
`scripts/bazel-matrix.py` reads all of them and prints the cells of an event:
one cell per (fixture group, Bazel, runner, test-name prefix), run with
`--exact` and the full path of each test, so a cell runs the tests its
matrices list and no other. The toy group is all in one: its `core` cell
also runs the guard tests that use the toy fixture
(`core/guard/MATRIX.json`), which the `bazel_core_` row of `ci.yml` does not
select. In a ruleset group the `bazel_agent_` tests ride the `vendor` cell;
there is no agent job. To add a cell, edit the `MATRIX.json` of your
fixtures; nobody edits the workflow. A new `#[ignore]` test that no matrix
lists fails `--check`: a `bazel_core_` test goes into `core/MATRIX.json`, any
other test on the toy fixture into `core/guard/MATRIX.json` (or a file of the
same shape with its own `filter`), and a ruleset's test under its fixture in
the ruleset's file (`lanes`). A heavy lane cell also names its `evidence`, as
a heavy baseline cell does (`heavy/README.md` in that directory).

```sh
python3 scripts/bazel-matrix.py --check                  # the rules below
python3 scripts/bazel-matrix.py --event pull_request     # the plan, as JSON
```

Under `--exact` a path libtest does not know runs nothing and exits 0. The
planner computes each path from the sources (the file's module, the inline
`mod` blocks around the test, its name), and the workflow's `build` job holds
the result to the binary:

```sh
target/bazel-bin/e2e_bazel_build --list --ignored > target/bazel-tests.txt
python3 scripts/bazel-matrix.py --check --libtest-list target/bazel-tests.txt
```

`--check` (also run by `scripts/tests/test_bazel_matrix.py`) fails when a
listed test is not an `#[ignore]` test of the suite or such a test is in no
matrix, when a (Bazel, runner) has no pin, when a (fixture, Bazel) pair is not
in the era table the script carries, when a rules_jvm_external entry of tier
`pr` climbs above proof tier 0, when a Go or Rust entry is `pr` without a
restored repository cache (`"cache": "restored"`, which the cell of a lane
test may say; without the key such a cell is `nightly`, and a canary fetches
cold, so a Go or Rust baseline stays `nightly`), when a fixture whose
packages a tool fetches (pip mode, crate_universe, an unpinned Coursier hub)
does not say `"fetch": "tool"`, or when the `os` list of a toy test is not a
list of runners its cells run on, with at least one for each of its Bazel
releases. The light and heavy matrices name no runner: a nightly
entry runs on ubuntu, and a lane test on 7.7.2, 8.8.2 or 9.3.2 also on macOS
and Windows; `pr` moves the ubuntu cell into the pull-request tier.

A test that printed `SKIP` still passes for libtest, so a green cell proves
nothing by itself. Each cell therefore ends with the audit, and the `audit`
job repeats it over the whole run:

```sh
python3 scripts/bazel-matrix-audit.py --reports <dir> --require hosts,wall_ms,resolved \
    [--tiers pr|full [--cell <id>]] [--claims target/bazel-claims.json]
```

It fails when a `ran` report lacks its hosts, their source, its wall time or
its list of lanes, when a resolved ruleset version differs from the pin of
the fixture that lists the test on the report's Bazel release, when a test
planned for the run (or the cell) has no `ran` report on its Bazel release
and runner, and when a claim of `lanes::claims_json()` has no evidence. A
claim is a lane on Bazel `lo` to `hi` under one dependency system. It is held
to the pinned releases and to the Bazel lines of the support table: the
majors, except that under Bzlmod (and hybrid) 7.0 and 7.1 are each a line of
their own beside 7.2 and later 7.x. `hi` must be a pinned release, every line
the range reaches must have a pinned release inside the range, and the newest
such release of each line needs a `ran` report that names the lane, under
that system, with its hosts from the fixture server's log, on each OS the
claim lists (on any OS while it lists none). So a Bzlmod claim from 7.0.0
needs reports on 7.0.2 and 7.1.2 as well as on 7.7.2. A lane whose claim
lists the write class `hook` or `tag_edit` leaves wiring in a file of the
user's, so its claim also names the test of its bump cell (`bump`, a name
that holds `_bump`) and needs a `ran` report of that test, which names the
lane under the claim's system on a release inside the claim. Over a whole
run a record-only cell that did not run is listed and is not an error.

To check a local run against the plan of its cell (the cell ids are in the
plan; a macOS cell is `nightly`, so `--tiers full`):

```sh
python3 scripts/bazel-matrix-audit.py --reports "$SOCKET_PATCH_BAZEL_E2E_PROBE_DIR" \
    --tiers full --cell core-9.3.2-macos-core
```

## Local runs on a shared machine

Each test starts a Bazel server (200 to 500 MB) and extracts an install base
(about 180 MB) into its temp root. Keep `--test-threads=2`. If a run is
interrupted hard, look for leftovers with `pgrep -fl 'bazel('` and remove
`sp-bazel-*` directories from the system temp directory; a server whose
output root is gone exits by itself within seconds on Unix, and after 15 idle
seconds otherwise.
