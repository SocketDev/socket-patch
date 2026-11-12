# Bazel compatibility

This guide covers the real-Bazel suite, `e2e_bazel_build`: the installer and
pins that provide Bazel, the harness that runs it, and the rules a test
follows. socket-patch itself never runs Bazel. The suite does, to prove with
Bazel's own output that a build consumes what socket-patch wrote, or still
passes where socket-patch refused to write.

The hermetic Bazel suites (`e2e_bazel`, and the unit tests under
`crates/socket-patch-core/src/bazel/`) need no Bazel and run in the normal
`cargo test` job. Everything below needs a Bazel binary.

State of this document: it describes the harness. The fixture workspaces, the
lane tests and the CI workflow land in later changes; where a statement about
Windows or Linux x86_64 has not been confirmed by a CI cell it says so.

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

A test name starts with one of six prefixes, which the CI cells filter on:
`bazel_core_` (the toy fixture; no network), `bazel_guard_`, `bazel_agent_`,
`bazel_hosted_`, `bazel_vendor_` and `bazel_canary_` (record-only).

| Variable | Meaning |
|---|---|
| `SOCKET_PATCH_BAZEL_E2E_BAZEL` | The Bazel binary to drive, or a launcher. Unset: `bazel` on `PATH`. |
| `SOCKET_PATCH_BAZEL_E2E_VERSION` | `bazel --version` must print exactly this. Exported to the child as `USE_BAZEL_VERSION`, so a launcher selects it. |
| `SOCKET_PATCH_BAZEL_E2E_REQUIRED` | Non-empty: a missing Bazel or an unreachable origin fails instead of printing `SKIP`. CI sets it. |
| `SOCKET_PATCH_BAZEL_E2E_GROUP` | `core`, `light` or `heavy`. A test of another group prints `SKIP (n/a)`. |
| `SOCKET_PATCH_BAZEL_E2E_SYSTEM` | `bzlmod`, `workspace` or `hybrid`. A test of another system, or of a system the Bazel line does not have, prints `SKIP (n/a)`. |
| `SOCKET_PATCH_BAZEL_E2E_BAZELISK`, `_BINARY` | The launcher cell: the pinned bazelisk runs the release binary. |
| `SOCKET_PATCH_BAZEL_E2E_PROBE_DIR` | Where the per-cell JSON reports go. Default: `target/tmp/bazel-probe`. |
| `SOCKET_PATCH_BAZEL_E2E_CACHE_ROOT` | A persistent repository cache (`<root>/repos`) shared by every test. Default: an empty cache per test. |
| `SOCKET_PATCH_BAZEL_E2E_OUTPUT_ROOT` | A short directory for output user roots (Windows path limits). |
| `SOCKET_PATCH_BAZEL_E2E_ARGS` | Extra whitespace-separated options for every Bazel command. |
| `SOCKET_PATCH_BAZEL_E2E_OFFLINE` | The offline phase (below). |
| `SOCKET_PATCH_BAZEL_E2E_REAL_REGISTRIES` | The real-registry cell: tests with such a variant skip the fixture server. |

A name that `_GROUP` or `_SYSTEM` does not know is a failure, not "run
everything": a typo in a CI cell must not turn into a run that skips what it
was meant to cover.

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
config when the test has a fixture server. The workspace `.bazelrc` stays
active, because socket-patch's model reads it.

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

`bazel_core_launch_isolated` is the test of these rules: the version matches,
the output base and install base are under `<T>/root`, the server JVM has the
scratch temp directory and wrote no perf-data file, and none of
`~/.cache/bazel`, `~/Library/Caches/bazel`, `/private/var/tmp/_bazel_$USER` or
the default bazelisk home was created or changed. It runs only `info` and
`shutdown`, so it needs no network. It has run on macOS arm64 for Bazel 7.0.2,
7.7.2 and 9.3.2; Linux and Windows are unconfirmed until a CI cell runs it.

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
  assertion is "the server log holds no request for the package's own URL",
  not "no request". A warm repository cache plus `block *` is not an offline
  recipe before Bazel 9.3.0: it fails at the first archive without a `type`.
- **Twins.** A tamper or withdrawal twin runs on a new output base with an
  empty repository cache (`Cell::open_cold`): with a warm cache the same URL
  and checksum pass with zero requests. Every assertion about what the server
  received first asserts that at least one request arrived.
- Fetches that do not go through Bazel's downloader (pip, cargo under
  crate_universe, Go modules, unpinned Coursier) need their own lever. One
  module per upstream registry lives under
  `tests/bazel_build_common/registry/`; each is a stub that refuses until the
  package that needs it lands the emulation.

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
4. The repository cache lies outside the workspace copy (9.3.2 exits 2
   otherwise).
5. A cell that expects a fetch to fail runs one command with
   `--experimental_repository_downloader_retries=0` (`Cell::failing_fetch`).

`Cell::baseline` runs every command class a scenario later runs, before the
test takes its snapshot. Tree comparisons after Bazel ran leave out what Bazel
owns (`bazel_common::assert_same_tree_but_bazel_owned`), and lock equality
after a rollback is asserted only after `bazel shutdown` and a second
baseline.

## Proof ladder

The oracle is always something Bazel reports or builds, never a file
socket-patch wrote, and the harness never names `external/<repo>` itself: it
asks Bazel. Every fixture defines `//:socket_probe` with the shared rule in
[`fixtures/bazel/common/probe.bzl`](../../crates/socket-patch-cli/tests/fixtures/bazel/common/probe.bzl),
which the harness copies to the workspace root (`load("//:probe.bzl",
"socket_probe")`). The rule symlinks each source to an output and uses no
shell, so it builds without Bash; a tree-artifact input gets a directory
output.

| Tier | Command | Proves |
|---|---|---|
| 0 | `bazel query --noimplicit_deps --notool_deps --output=location 'kind("source file", deps(//:socket_probe))'`, then the digest of the one listed file the ruleset's anchor names | The repository Bazel materialised holds the patched bytes. rules_js: the sha512 of `package.tgz` against the lock's `integrity`. rules_jvm_external: the jar under the artifact repository's `file/` directory, never `processed_<jar>`. |
| 1 | `bazel build //:socket_probe` and `cquery --output=files`, on a warm server and after `bazel shutdown` | An action input is the patched file. |
| 2 | `bazel run //:consumer` printing a marker from patched code | The language rule consumes it. |

`bazel_canary_probe_rule_tree_artifact` builds the rule over a file and a
tree artifact on the selected Bazel. It is record-only and uses the network on
a Bzlmod line (Bazel resolves its builtin modules from the registry).

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
  "hosts": [],
  "direct_network": false,
  "wall_ms": 11022,
  "resolved": {},
  "details": {}
}
```

`status` is `ran` only when the test reached its last line; a test that
printed `SKIP` or `SKIP (n/a)` writes `skipped` with the reason, and a test
that failed writes nothing. A lane may claim a Bazel line, dependency system or
OS only with a `ran` report for it. `hosts` is the fixture server's log,
`resolved` the ruleset versions `bazel mod graph` reported, and
`direct_network` marks a canary that reached hosts without the downloader
rewrite.

## Local runs on a shared machine

Each test starts a Bazel server (200 to 500 MB) and extracts an install base
(about 180 MB) into its temp root. Keep `--test-threads=2`. If a run is
interrupted hard, look for leftovers with `pgrep -fl 'bazel('` and remove
`sp-bazel-*` directories from the system temp directory; a server whose
output root is gone exits by itself within seconds on Unix, and after 15 idle
seconds otherwise.
