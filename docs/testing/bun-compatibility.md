# Bun patch compatibility

`socket-patch` supports hosted, vendored and agent-mode npm patches in Bun
projects using text `bun.lock` or native binary `bun.lockb`. Real-Bun evidence backs both formats:

- **The native matrix** — `scripts/backtest-bun.py` runs real Bun releases
  against the public free Socket patch for `minimist@1.2.2`
  (`80630680-4da6-45f9-bba8-b888e0ffd58c`) with the production CLI and patch
  service, without a token or substitute service, and checks the INSTALLED
  bytes, lock stability, digest rejection and rollback on Linux, macOS and
  Windows ([workflow](../../.github/workflows/bun-compatibility.yml)).
- **The hermetic real-Bun suites** —
  `crates/socket-patch-cli/tests/e2e_redirect_bun_build.rs` (hosted),
  `e2e_vendor_bun_build.rs` (vendored), `e2e_bun_lockb.rs` (native binary) and `mode_migration_bun.rs`
  (hosted ⇄ vendored takeover, scoped unwind) drive a real `bun install`
  against a wiremock patch service. The text suites run in `ci.yml`'s `e2e`
  matrix; the binary writer/reader suite runs in `bun-compatibility.yml`.

Underneath, the hosted and vendored bun rewriters are pinned by shared golden
fixtures (`crates/socket-patch-core/tests/fixtures/redirect/npm/bun/*`, shared
with the depscan TypeScript backend, whose golden harness asserts every case it
does not list as lagging — the cases authored Rust-first here lag until
`bun.ts` is ported, see [depscan TS parity](#depscan-ts-parity); refusal
fixtures pin their warning code through `expected-warnings.json`) and by
hermetic CLI suites that
need no Bun binary (`tests/in_process_vendor_bun.rs`,
`tests/in_process_vendor_bun_takeover.rs`, the bun cases of
`tests/in_process_redirect.rs`, `tests/covgap_commands_scan_hosted.rs`,
`tests/covgap_commands_scan_mod.rs`, `tests/covgap_commands_rollback.rs`,
`tests/scan_vendor_e2e.rs`, `tests/get_modes_e2e.rs`,
`tests/repair_vendor_flavors_e2e.rs`). The
[machine contract](../../crates/socket-patch-cli/CLI_CONTRACT.md) is the
authority on envelopes and codes; this page is the measured matrix behind it.
See the [ecosystem matrix](../ecosystems.md#mode--ecosystem-matrix) for the
other npm lockfile flavors.

## Formats and rewrite behavior

| Input | Hosted (`scan` / `get --mode hosted`) | Vendored (`scan` / `get --mode vendored`, `vendor`) | Agent / discovery |
|-------|------|------|------|
| Text `bun.lock`, lockfileVersion 0, 1 or 2, no `workspace:` packages | Registry 4-tuple `["name@ver", "<registry>", {deps}, "sha512-…"]` → URL 3-tuple `["name@https://patch.socket.dev/…/name-ver.tgz", {deps}, "sha512-<patched>"]`; the `{deps}` meta object (dependencies, bin, …), the lock's version line and its line endings are kept verbatim. | Same entry → local 3-tuple `["name@.socket/vendor/npm/<uuid>/name-ver.tgz", {deps}, "sha512-<ours>"]`, tarball committed under `.socket/vendor/npm/<uuid>/`; `--detached` keeps the record in `.socket/vendor/state.json` only. | The installed tree is patched in place; the lock's registry tuples are inventoried, so lockfile-only packages join discovery. |
| Version-0 lock (Bun 1.1.39–1.1.45 `--save-text-lockfile`) with `workspace:` packages — 2-tuple entries `"consumer": ["consumer@workspace:packages/consumer", { "dependencies": { … } }]` | Refused `redirect_bun_workspace_unsupported`, lock untouched, exit 0. Remedy: delete `bun.lock` and re-lock with Bun ≥ 1.2 (writes lockfileVersion 1, which hosted mode accepts; 2 on Bun ≥ 1.4). A plain in-place `bun install` bumps the version only when a workspace depends on another workspace (root → member — the matrix's `workspace` shape, the only shape it was measured on); otherwise Bun 1.2.0 keeps version 0 and 1.2.23+ fail to resolve (see [In-place re-versioning](#installer-boundaries-measured)). | Refused `vendor_bun_workspace_unsupported` (pre-version-2 policy, next row); its remedy tail for a version-0 lock says to re-lock with Bun ≥ 1.2 before trying `--mode hosted`, which refuses version 0 too. | Works. |
| Version-1 lock (Bun 1.2–1.3 default) with `workspace:` packages — 1-tuple entries `["consumer@workspace:packages/consumer"]` | Rewritten (golden `lock-v1-workspace`; matrix 1.2.0–1.3.14 `workspace` / `workspace-nested`). | Refused `vendor_bun_workspace_unsupported` before any write. Policy, not a grammar limit: Bun 1.2.x–1.3.x resolve a workspace member's local-tarball path relative to the MEMBER (our root-relative tuple ENOENTs on `bun install`), 1.4.x relative to the lockfile, and a committed lockfileVersion-2 lock is the only proof that every consumer runs Bun ≥ 1.4 (1.3.x cannot parse v2). A deliberate over-approximation: a package declared only by the workspace ROOT vendors and installs on v1 too, but the lock cannot cheaply prove which workspace declares a hoisted entry. Remedy in the detail: delete `bun.lock`, re-run `bun install` with Bun ≥ 1.4 (an in-place `bun install` keeps the existing version), or — version 1 — use `--mode hosted`, which accepts version-1 workspace locks (a version-0 lock is told to re-lock with Bun ≥ 1.2 first). NOT refused: purls the vendor ledger wires at the selected uuid, purls whose every matching lock tuple already points into `.socket/vendor/npm/` (any uuid — a superseding patch re-pins in place; the lock-derived rule the engine uses), in-sync re-runs and `repair` rebuilds. `vendor` and the vendor step run the same preflight BEFORE a hosted → vendored takeover's revert, so a hosted-redirected purl on such a lock stays hosted-patched (`failed vendor_bun_workspace_unsupported`, lock and ledgers untouched; `vendor --dry-run` previews the same code). A `.socket/vendor/state.json` the preflight cannot read is `vendor_state_unreadable`, fail-closed. | Works. |
| Version-2 lock (Bun 1.4+) with `workspace:` packages, nested versions included | Rewritten (golden `lock-v2-workspace-nested` — provenance: its nested same-version `consumer/left-pad` entry is a synthetic, grammar-valid extension of the 1.4.2 capture; bun hoists identical resolutions and never writes that entry itself, but bun 1.4.2 installs the fixture unchanged, and it is the only case pinning the rewrite of every matching tuple in one lock). | Vendored (matrix 1.4.0 / 1.4.2 `workspace`, `workspace-nested`, `already-vendored-workspace`). | Works. |
| Binary `bun.lockb` (binary format revisions 1, 2 and 3) | Package resolution and integrity records are rewritten in place. The CLI does not spawn Bun or produce a text lock. | Native local-tarball wiring, committed artifact, detached mode, repair and hosted ⇄ vendored takeover. | Registry package records are inventoried directly, including lockfile-only projects without `node_modules`. |
| Truncated, corrupt or unrecognized binary `bun.lockb` | Refused with `redirect_bun_lockb_invalid`, preserving the lock. | Refused with `vendor_bun_lockb_invalid` before downloads or artifact creation. | The inventory reports the malformed lock. |
| `bun.lock` with a `lockfileVersion` ≥ 3, no integer version, or a `packages` section outside bun's single-line grammar | Refused `redirect_bun_lock_unsupported`. | Refused `vendor_lockfile_version_unsupported` (preflight and engine). | The inventory skips the lock. |

One detail text serves both modes for the version gate: a newer version says
"update socket-patch, or re-lock with a Bun release that writes
lockfileVersion 0–2" (re-locking with a newer Bun would reproduce it); a
missing integer says "re-lock with Bun ≥ 1.2".

**Pre-download preflight (vendored).** `scan --mode vendored`,
`get --mode vendored` (search and uuid paths) and `--detached` runs check
`bun.lock` / `bun.lockb` ONCE before any patch download when the selection
holds an npm purl. A refused project marks every npm result `failed` with the
vendor code + detail, fetches nothing and records no patch: the `scan` /
`get <purl>` path still writes an unchanged `.socket/manifest.json` (an empty
`{"patches": {}}` on a fresh project; a record seeded for another purl
survives) and exits `partial_failure` / 1; `get <uuid> --mode vendored` exits
1 with `status: "error"` and `error: {code, message}` before creating
`.socket/` at all; detached runs never write a manifest. `--silent` keeps the
code-tagged refusal on stderr; `--dry-run` previews it as the additive
`would_refuse` action. Agent-mode `get --save-only` is not preflighted.

**Mode conversion.** Hosted → vendored (`scan` / `get --mode vendored`,
`vendor` over a hosted-redirected `bun.lock`) reverts the hosted line to its
pristine registry tuple, drops the redirect-ledger record and vendors
(`vendor_takeover_reverted_redirect`; `vendor --dry-run` PROBES the revert and
reports `vendor_would_revert_redirect`) — but only after the Bun vendored
preflight accepted the lock: on a lock the vendored backend refuses (a
pre-version-2 `workspace:` lock) `vendor`, the vendor step and the dry run
report `failed vendor_bun_workspace_unsupported` BEFORE the revert, leaving the
hosted wiring, the redirect ledger and `bun.lock` byte-untouched (the purl
stays hosted-patched). Vendored → hosted reverts the vendored
wiring, ledger entry and committed artifact first
(`redirect_takeover_reverted_vendored`). `rollback <purl>` / `remove <purl>`
unwind one of several hosted bun records; an unscoped `rollback` unwinds
everything through the whole-ledger replay. Pinned hermetically by
`tests/in_process_vendor_bun_takeover.rs`, against real Bun by
`tests/mode_migration_bun.rs` (CI: Bun 1.4.2 on three OSes, 1.3.14 on Linux)
and by the matrix's `hosted-then-vendored` / `vendored-then-hosted` shapes.

### Native `bun.lockb` support

Binary locks are parsed and patched directly. The codec understands the original
version-1 representation, the version-2 URL representation, the later scripts
package field, and version 3's wider semantic-version representation. It keeps
package IDs, dependency edges, hoisting data, package metadata and optional
extensions intact. Historical workspace dependency flags and literals are
normalized to the equivalent representation accepted by old and new readers;
the original encoding is retained for rollback. Unknown versions and invalid
offsets fail closed.

Hosted redirects and vendoring use per-package binary snapshots in their ledgers.
This allows a scoped rollback or mode switch to restore one package while keeping
other packages wired. Whole-ledger reverse replay restores the original binary
bytes when no external re-save occurred. Scoped rollback restores package
resolutions and may retain equivalent binary normalization; if Bun itself has
subsequently upgraded the binary schema, rollback preserves that schema and
restores the original package resolutions.
Dry runs validate the same input and drift conditions without changing it. No Bun
executable is required to inspect, rewrite or restore a binary lock.

Binary locks stay binary through patching, mode changes and rollback. A format-1
input is promoted directly to binary format 2 when needed for tarball resolutions,
with an exact original snapshot for rollback. When `bun.lock` also exists, it
takes precedence, matching modern Bun's installer.

Binary workspace vendoring records byte-identical tarball copies under each
workspace's `.socket/vendor/npm/<uuid>/` directory as well as the canonical root
artifact. This supports Bun releases that interpret local-tarball paths relative
to the workspace and those that interpret them relative to the lockfile. Commit
these copies along with the root artifact. Repair rebuilds missing or corrupt
copies, including recovery when the local ledger is missing; rollback and mode
switches remove the tracked copies with drift checks.

Bun 1.2 and newer can still write native binary locks. Use the following project
configuration in `bunfig.toml` when creating a new binary lock:

```toml
[install]
saveTextLockfile = false
```

The committed real-Bun captures live in
`crates/socket-patch-core/tests/fixtures/bun-lockb/<version>/`, with their manifest,
lock and SHA-256 provenance. They cover 0.1.1, 0.1.6, 0.1.7, 0.5.9, 0.6.7, 0.6.8,
0.8.1, 1.0.0, 1.0.36, 1.1.0, 1.1.38, 1.1.45, 1.2.0, 1.2.23, 1.3.0,
1.3.14 and 1.4.2. The fixture boundaries follow Bun's
[binary lock implementation](https://github.com/oven-sh/bun/blob/bun-v1.4.2/src/install/lockfile.rs).

Run the dedicated binary acceptance matrix:

```sh
python3 scripts/backtest-bun-lockb.py \
  --tools /tmp/bun-tools \
  --output /tmp/bun-lockb-compatibility
```

Bun 0.1.x predates upstream checksum manifests; its official release assets use
the reviewed SHA-256 pins in `scripts/bun-historical-shas.json`. Later releases
are verified against their published `SHASUMS256.txt`.

Native writers from Bun 0.5.9 onward are paired with their own reader. Bun
0.1.1, 0.1.6 and 0.1.7 have no tarball installer: they silently omit tarball
packages even when installation exits zero. Their original binary locks are
therefore tested with Bun 0.5.9, the first tarball-capable reader; this upstream
limitation is recorded explicitly in each matrix row. Newer readers also consume an
unchanged 1.1.45 binary lock. The Rust tests assert cold frozen installs from an
empty cache, exact patched and bystander bytes, preservation of the binary file,
hosted and vendored reruns, both takeover directions, dry-run immutability,
artifact repair, detached mode and byte-exact rollback. Extended cells cover npm
aliases, overridden transitives, workspace members, multiple versions, root and
workspace scripts, and GitHub resolutions. Workspace cells also exercise missing
and corrupt copies, with and without the local ledger.
Production cells from writer 0.8.1 onward patch two packages, retain a transitive
dependency and its bin plus root lifecycle-script metadata, and exclude a dev
alias and another dev package. They verify cold frozen production installs after
each scoped rollback, in both package orders.
The public-service matrix additionally verifies ordinary installs, warmed-cache
frozen and ordinary installs, and digest tampering.
`SOCKET_PATCH_BUN_LOCKB_REQUIRED=1` makes missing tools a failure. A regular
`cargo test -p socket-patch-cli --test e2e_bun_lockb` uses Bun on `PATH`; a modern
Bun reads the committed binary fixture, so no separate old writer is needed.

### Measured validation

Measured on 2026-09-21, macOS arm64, using the native binary implementation in
the worktree based on `4b61c9620b800d26056211060ebb4a4c60288da5`:

| Suite | Result | Coverage |
|-------|--------|----------|
| Public patch service | 370 / 370 cases passed | 11 releases: 0.8.1, 1.0.0, 1.0.36, 1.1.0, 1.1.38, 1.1.45, 1.2.0, 1.2.23, 1.3.0, 1.3.14, 1.4.2. 340 accepted flows and 30 expected text-workspace refusals. Direct, alias, transitive, two-version, workspace, nested workspace, root workspace, lockfile-only, UUID/search get, legacy binary and both takeover shapes. |
| Explicit warm-cache installs | 90 / 90 cases passed | Six eras: 0.8.1, 1.0.36, 1.1.45, 1.2.23, 1.3.14, 1.4.2. Direct, workspace, nested workspace, legacy binary and both takeovers, with cold and warmed-cache frozen and ordinary installs. Includes eight expected text-workspace refusals. |
| Native binary writer/reader matrix | 25 / 25 pairs passed | All 17 fixture writers listed above; own-version readers from 0.5.9 onward, 0.5.9 readers for the three 0.1.x writers, five 1.2–1.4 readers of 1.1.45, and 1.4.2 readers of 0.1.1, 0.1.6 and 0.6.7. All three Rust acceptance tests ran in each pair. |
| Historical concurrency regression | 30 / 30 pairs passed | Six repetitions of 0.5.9 reading 0.1.1, 0.1.6 and 0.5.9, plus 1.4.2 reading 0.1.1 and 0.1.6, with isolated temporary directories. |

The public-service captures record CLI SHA-256
`a3e7683d66e6e6654644c3cd51ada1260a58a8d8f9b96c0a2ea4f585a9219910`.
The binary matrix records both Bun executable hashes and its test executable
hash in every result. The final local reports are under
`/tmp/socket-patch-bun-public-final`, `/tmp/socket-patch-bun-public-warm-final`
and `/tmp/socket-patch-bun-native-final-isolated`.

Early parallel historical probes exposed Bun 0.5.9's `FileNotFound extracting
tarball` and Bun 0.1.1's lockfile `AccessDenied` errors in a shared temporary
directory. The harness now gives every fixture its own temporary directory and
an empty cache directory. Historical writers use timestamp-derived temporary
names. The failing logs remain under `/tmp/socket-patch-bun-native-verified` and
`/tmp/socket-patch-bun-native-emptycache-*`; the six repeated runs above verify
the corrected isolation without retrying failed assertions or changing readers.

On 2026-09-22, the full workspace test run passed 7,326 tests with no failures,
and production Clippy passed with warnings denied. The production-filter
regression passed all 33 public-service cases across the same 11 release eras,
including cold and warmed-cache frozen and ordinary installs. A separate complex
graph passed both scoped rollback orders on 0.8.1 and 1.0.0; that graph is now
part of the permanent binary matrix. These local measurements use macOS arm64.

The [PR validation run for `9644add`](https://github.com/SocketDev/socket-patch/actions/runs/35729497310)
also passed all 25 native binary writer/reader pairs on macOS and all 13 pairs
available on Windows, including the permanent production/scoped-rollback cases.
Windows has no official Bun binaries before 1.1.0. Each pair ran all three Rust
acceptance tests.

The Linux runner exposed a separate historical-runtime boundary: official Bun
0.5.9, 0.6.7 and 0.6.8 crashed with `SIGSEGV` during pristine installs on
`ubuntu-latest` (Ubuntu 24.04), before `socket-patch` ran. The workflow retains
all 25 required historical pairs on Ubuntu 22.04, and additionally runs the 16
pairs using Bun 0.8.1 and later on `ubuntu-latest`; every historical format and
reader remains in the required matrix. Linux failures upload bounded pristine
runtime probes and, when available, syscall traces under the binary result artifact's
`linux-diagnostics/` directory.

## Installer boundaries (measured)

Local probes ran on macOS arm64 with the releases named below; the workflow
downloads the matching linux / darwin / windows build (x64, or aarch64 on ARM
runners) from the GitHub releases and verifies it against `SHASUMS256.txt`. Every measurement sets
`BUN_INSTALL_CACHE_DIR` and `BUN_INSTALL` per project and passes
`--ignore-scripts`.

- **Lock history.** Binary `bun.lockb` only through 1.1.38. The text lock
  arrives in 1.1.39 as the `--save-text-lockfile` opt-in (lockfileVersion 0:
  trailing commas, no `configVersion`, 2-tuple workspace entries);
  `--lockfile-only` exists from 1.1.43; text is the default from 1.2.0
  (lockfileVersion 1) through 1.3.x; 1.4.0 writes 2 for a FRESH lock behind
  an unchanged grammar. Registry 4-tuples are byte-identical across 0/1/2,
  so the rewrite is version-independent; the workspace grammar, the
  binary layout and digest enforcement are not.
- **In-place re-versioning.** Bun never bumps an existing version-1 lock in
  place — 1.4.x `install`, `add`, `update`, `--force` and
  `--save-text-lockfile` all keep 1; only deleting `bun.lock` and re-locking
  writes 2 (hence the vendored workspace remedy). A version-0 lock WITHOUT
  workspaces stays 0 under 1.2.0, 1.2.23 and 1.3.0 and is rewritten as 1 by
  1.3.9, 1.3.10, 1.3.13, 1.3.14, 1.4.0 and 1.4.2 (the first bumping release
  lies in (1.3.0, 1.3.9]). A version-0 lock WITH workspaces whose root
  depends on the member (the matrix's `workspace` shape) is rewritten as 1 by
  a plain `bun install` on 1.2.0, 1.2.23, 1.3.0, 1.3.14 and 1.4.2 — the root
  dependency's spelling changes from a bare path to `workspace:*`, which
  forces the save — while 1.1.45 keeps it at 0. That bump is CONDITIONAL on
  an inter-workspace dependency: on a version-0 workspace lock whose root
  does not depend on its members, a plain `bun install` keeps version 0 on
  1.2.0 (exit 0, lock byte-identical) and fails with `<pkg>@<ver> failed to
  resolve` on 1.2.23–1.4.2 (exit 1, lock unchanged; `--force` and
  `--save-text-lockfile` too), so hosted mode keeps refusing. The hosted
  refusal's remedy is therefore `rm bun.lock && bun install` with Bun ≥ 1.2,
  which converges on every release (version 1 on 1.2–1.3, 2 on 1.4); the
  in-place bump is a measured convenience for the matrix's shape only, and
  the root-independent shape is not in the matrix.
- **Workspace-member local tarballs.** Bun 1.2.x–1.3.x resolve a
  local-tarball dependency declared by a workspace member relative to the
  member (`.socket/vendor/…` → ENOENT on `bun install`); 1.4.x resolve it
  relative to the lockfile. A package declared only by the root installs on
  version-1 locks as well; the vendored gate still refuses (policy above).
- **Digest enforcement.** Bun verifies the sha512 of URL and local-tarball
  tuples only from **1.3.10**: 1.3.9 installs a tarball whose bytes do not
  match the lock with exit 0, 1.3.10 fails with `Integrity check failed`.
  Registry 4-tuples are verified from 1.2.0. So on 1.1.39–1.3.9 a hosted or
  vendored rewrite REMOVES digest enforcement for the patched package (the
  registry tuple it replaced was checked; the URL / local tuple is not) — the
  committed lock and artifact are the protection there. The PR's first
  matrix placed the boundary at 1.3.14 because it sampled only 1.3.0 and
  1.3.14; the hermetic suites pin it from both sides
  (`TARBALL_INTEGRITY_ENFORCED_FROM = (1, 3, 10)` with the 1.1.45 / 1.2.23 /
  1.4.2 legs) and the matrix carries 1.3.9 and 1.3.10.
- **Digest-less re-saves.** The same releases (every text-lock Bun below
  1.3.10 — measured on 1.1.45 at lockfileVersion 0, 1.2.23 and 1.3.9)
  re-save a URL or local-tarball tuple WITHOUT its `sha512` whenever the lock
  is re-saved for another reason: `bun add <pkg>`, or `bun install` after a
  package.json / workspace change (a root rename alone does not re-save; a
  frozen install never writes). The 3-tuple comes back as the 2-tuple
  `["name@<url|path>", {meta}]`, spec and meta intact; 1.3.10, 1.3.14 and
  1.4.2 keep the digest. The CLI recognises that spelling as its own wiring:
  the repeat hosted run heals it (`redirected: 1`, no
  `redirect_bun_entry_not_found`, a second ledger edit whose `original` is
  the 2-tuple), the vendored re-run stays `already_vendored` and re-pins the
  digest on disk, `repair` rebuilds through it, and `rollback` / scoped
  `rollback` / `remove` / `vendor --revert` / both takeovers accept the
  digest-less spelling of a recorded line and restore the registry original
  over it. Before the fix every one of those refused after any lock re-save
  on those releases (`redirect_bun_entry_not_found` beside `redirected: 1`,
  `rollback` → `partial_failure`, `vendor_lock_entry_not_found` /
  `vendor_lock_entry_drifted`); the `already-vendored-workspace` matrix
  shape on 1.2.0–1.3.9 is the regression guard.
- **Both lockfiles present.** Modern Bun prefers text `bun.lock` over
  `bun.lockb`. The CLI follows the selected lock format; native binary writes
  never create a sibling text lock.
- **Bun 0.8.1 / 1.0.0 with peer or overridden-transitive shapes** do not
  install the selected patched version. Those projects remain unchanged; the
  matrix records this upstream limitation and checks lock presence explicitly.
- **Modern frozen installs preserve the lock**. Bun 0.5.9 upgrades an untouched
  format-1 registry lock to format 2 even with `--frozen-lockfile`; that historical
  exception is checked explicitly. Modern ordinary installs upgrade format 2 to
  3, which the matrix validates using Bun's complete semantic lockfile dump.
  Outside these schema transitions, only a plain `bun install` can
  observe re-serialization drift — the matrix's `ordinaryStableLock` check and
  the plain-install legs of the hermetic suites both run it.

## Running the matrix

```sh
cargo build --locked -p socket-patch-cli
python3 scripts/backtest-bun.py \
  --cli target/debug/socket-patch \
  --cli-revision "$(git rev-parse HEAD)" \
  --output /tmp/bun-compatibility \
  --modes hosted vendored vendored-detached
```

Use `--versions 1.4.2 --shapes workspace-nested` for a focused reproduction,
`--tools <dir>` to reuse pre-downloaded binaries
(`<dir>/<version>/bun-<os>-<arch>/bun[.exe]`, the layout the workflow
pre-populates), `--cli-build-sha <sha>` (or `CLI_BUILD_SHA` in the
environment) when the built commit differs from `--cli-revision`, and
`--jobs N` for parallel cells. A narrowing that leaves no applicable
`(version, shape, mode)` cell — e.g. `--shapes isolated` on Bun < 1.3.0 —
prints a notice, writes a single `{"noCells": true, "passed": false, …}`
summary row and exits 0 (the default shape list always holds `direct`, which
applies everywhere, so an un-narrowed run can never go vacuous). Windows uses
`target/debug/socket-patch.exe`. Bun binaries are downloaded from the GitHub
release with retries and verified against `SHASUMS256.txt` (`bunSha256` in the
provenance); releases before 1.1.0 have no Windows binary. The `legacy-lockb`
shape also needs Bun 1.1.38 (its baseline writer), fetched or reused the same
way whenever a `legacy-lockb` cell applies to a requested release.

Public-service cells retry at most three times when a captured CLI response
contains an explicit request transport error. Every retry recreates the project
and its caches, and preserves the failed attempt's logs, result and captured
tree under `attempts/`; the final row records `networkRetryAttempts`. Functional
failures without a transport error are never retried. CI limits the public
matrix to six concurrent jobs, with three cells per job. Each cell has its own
temporary directory so historical Bun processes cannot collide while extracting
identically named packages.

**Pinned versions:** 0.8.1, 1.0.0, 1.0.36, 1.1.0, 1.1.38 (binary lock),
1.1.39 (first text lock, version 0), 1.1.43 (first `--lockfile-only`), 1.1.45
(last version-0 writer), 1.2.0, 1.2.23, 1.3.0 (version 1), 1.3.9 / 1.3.10
(digest boundary), 1.3.14 (last pre-v2 default), 1.4.0, 1.4.2 (version 2).

**Shapes.** `direct`, `dev`, `optional`, `peer`, `alias` (`npm:` alias
install), `transitive` (overridden transitive), `two-versions`, `workspace`
(the member declares the dep), `workspace-nested` (root and member at
different versions), `workspace-root` (the root declares the dep, the member
something else), `text-workspace` (Bun 1.1.39–1.1.45 `--save-text-lockfile`
on the workspace project — a REAL version-0 workspace lock), `workspace-get-uuid` / `workspace-get-search`
(`get` by uuid and by PURL on the workspace project), `already-vendored-
workspace` (vendor a plain project, add a workspace member, `bun install`,
re-run — must be `already_vendored`; then `repair` rebuilds a deleted
tarball), `crlf` (CRLF manifest), `crlf-lock` (CRLF `bun.lock`),
`space-unicode` (a path with spaces and Unicode), `custom-registry` (a
non-empty registry slot the rewrite must drop), `text` (`--save-text-lockfile`
opt-in, Bun ≥ 1.1.39 only — asserts `bun.lock` exists after the baseline),
`isolated` / `hoisted` linkers, `lockfile-only` (no `node_modules`),
`production`, `get-uuid`, `get-search`, `legacy-lockb` (the baseline is
installed with Bun 1.1.38 so the project starts with `bun.lockb`; the matrix
Bun then runs the CLI), `hosted-then-vendored` / `vendored-then-hosted` (mode
conversion on ONE project) and `preexisting-manifest` (a record seeded for
another purl must survive a refused vendored run).

**Expectation oracle.** `expected_outcome(version, shape, mode)` encodes the
boundaries above — not the CLI's own output — and every cell asserts
`supported` against it and the refusal codes EXACTLY, after removing an
explicit informational allowlist (`vendor_prebuilt_downloaded`,
`vendor_fetched_missing`, `reinstall_required`,
…); substring matching is never used. A configuration expected to be
supported FAILS on unexpected warnings, `redirect_bun_entry_not_found`
or `redirect_revert_failed`. Exit codes are recorded for every invocation and
asserted: supported → 0; hosted refusals → 0 with `redirect.redirected == 0`
(the documented hosted-refusal posture); vendored, detached and `get` refusals
→ non-zero, with `download.downloaded == 0` and no stray manifest record.

**Every supported case verifies:**

- the ledger (or manifest) record names the expected published patch uuid;
- a fresh `bun install --frozen-lockfile` and a fresh ordinary `bun install`
  (empty caches, no `node_modules`) install the record's exact `afterHash`
  bytes and leave the lockfile byte-identical;
- the repeat run is a no-op with the documented envelope — hosted:
  `status: success`, `redirect.redirected == 1`, no non-informational warning;
  vendored / detached: `summary.applied == 0`, `summary.skipped == 1`,
  `summary.failed == 0`, one `already_vendored` event, no `failed` action —
  and preserves the lock bytes;
- `registryDigestEnforced`: before the CLI runs, a copy of the project with a
  tampered REGISTRY-tuple sha512 fails `bun install --frozen-lockfile` on
  every release whose baseline wrote a text lock (documents what the rewrite
  is compared against);
- `rejectCorruptDigest`: a tampered sha512 on the PATCHED tuple is rejected on
  Bun ≥ 1.3.10; below that the observation is RECORDED
  (`legacyDigestBehavior`) rather than asserted;
- rollback restores the original manifest / lock bytes, removes the
  `.socket/vendor` state, and a clean install reproduces the record's
  `beforeHash` bytes; text projects retain `bun.lock`, and binary projects
  retain `bun.lockb` without creating a text lock. The original lock presence
  and SHA-256 are both checked.

The runner captures the exact project manifests, lockfiles, optional
`.socket/manifest.json`, CLI JSON, exit codes, file hashes and assertion
results (`captures/<version>-<shape>-<mode>/`), plus provenance
(`cliRevision` — the branch-resolvable commit the row is about; `cliBuildSha`
— the commit actions/checkout actually built, `refs/pull/N/merge` on a pull
request, `null` when not supplied; `cliSha256`; `bunSha256`;
`bunArchiveSha256`). The depscan SBOM tests import
these captures through their fixture validation framework
(`bun-compatibility/generate-fixtures.py --captures`, depscan #26453).
Vendored artifact contents are verified by the native runner; they are not
needed for SBOM lockfile annotation.

## depscan TS parity

The bun golden fixtures are shared with the depscan TypeScript backend
(`bun.ts`), whose `golden.test.ts` asserts a byte match for every case it does
not list in `TS_LAGGING`. Several bun cases were authored Rust-first on this
branch, so the depscan submodule bump that adopts them must either port
`bun.ts` or extend `TS_LAGGING` — otherwise its golden suite fails:

- **`TS_LAGGING` entries the bump needs**, all under `npm/bun/`: `lock-v0`
  (pre-existing: TS refuses lockfileVersion 0), `alias`, `lock-v2-crlf`,
  `lock-v2-workspace-nested`, `re-redirect-stale-url`,
  `digestless-hosted-already-wired`, `digestless-hosted-stale-url-repin`,
  and `lock-v0-workspace-refusal` for as long as `bun.ts` lacks the version-0
  workspace gate (TS refuses that lock with `redirect_bun_lock_unsupported`
  while `expected-warnings.json` pins `redirect_bun_workspace_unsupported`,
  so the case matches on files/edits by coincidence today and fails the
  moment the TS harness reads the warnings file). `lock-v2-crlf` is not a
  gate lag but a `bun.ts` bug twin: it drops the `\r` on the rewritten line
  (the defect 532c40b fixed here).
- **Harness requirement**: `golden.test.ts` must read the optional
  `expected-warnings.json` and assert the warning-code set, as
  `redirect_golden.rs` does; until the dispatcher-level
  `redirect_npm_no_lockfile` suppression for bun-only projects is ported, that
  assertion fails every bun case that ships the file.
- **`bun.ts` porting items** (what lifts each case out of `TS_LAGGING`):
  `SUPPORTED_LOCK_VERSIONS = [0, 1, 2]` with the shared gate text; the
  version-0 workspace gate; CR re-emit on the rewritten line; the prior-URL
  re-pin arm (a hosted URL left by an earlier grant of the same
  `name@version` is re-pinned in place); the digest-less 2-tuple heal
  (Bun 1.1.39–1.3.9 re-saves); blank-line and `configVersion` tolerance in
  the `packages` walk.

The fixtures carry the grammar bun writes (captured from 1.1.45 / 1.3.14 /
1.4.2) with one deliberate exception, `lock-v2-workspace-nested`'s
same-version nested `consumer/left-pad` entry — see its row in the format
table above.

## What is verified where

| Claim | Real-Bun matrix (`backtest-bun.py`) | Real-Bun hermetic suites (`ci.yml` `e2e`) | Bun-less unit / CLI tests |
|---|---|---|---|
| Text lock 0 / 1 / 2 rewritten and installed, both modes | 1.1.39–1.4.2 | `e2e_redirect_bun_build` + `e2e_vendor_bun_build` on 1.4.2 (3 OS), 1.1.45 and 1.2.23 (Linux); the fixture asserts the lock version matches the era table, the v1-on-1.4 leg proves a committed v1 lock keeps installing | goldens `lock-v0`, `basic` (v1), `lock-v2`; `bun_lock.rs`, `lock_inventory.rs` |
| Native binary formats 1 / 2 / 3: inventory, hosted, vendored, detached, repair, takeovers, rollback | `direct`, `legacy-lockb`, conversion shapes; dedicated `backtest-bun-lockb.py` | `e2e_bun_lockb` across writer / reader revisions | `bun_lockb.rs` and committed real binary fixtures; native CLI tests |
| Version-0 workspace hosted refusal + remedy | `text-workspace` (1.1.39–1.1.45) | — | golden `lock-v0-workspace-refusal` (+ `expected-warnings.json`), `redirect/mod.rs` unit tests |
| Pre-v2 workspace vendored refusal (policy) + remedy; version 2 supported incl. nested | v1: 1.2.0–1.3.14 `workspace*`; v0: `text-workspace`; v2: 1.4.x | `e2e_vendor_bun_build` scoped leg (deps + bin meta survive) | `bun_lock.rs` (`legacy_workspace_tarballs_refuse_before_writes`, in-sync / rebuild exemptions), `in_process_vendor_bun`, `repair_vendor_flavors_e2e` over {0, 1, 2} × workspace shapes |
| Digest boundary 1.3.10 (registry tuples 1.2.0) | 1.3.9 vs 1.3.10 cells, `registryDigestEnforced` | tampered twins in both suites, pinned from both sides | — |
| Digest-less re-saves below 1.3.10 recognised, healed and unwound (both modes, takeovers, scoped unwinds, `repair`) | `already-vendored-workspace` on 1.2.0–1.3.9 (`digestDroppedOnResave`; `resaveKeepsDigest` from 1.3.10) | `bun_redirect_survives_a_digest_dropping_lock_resave`, `bun_vendor_survives_a_digest_dropping_lock_resave` (real `file:`-dep re-save; the era's spelling asserted from both sides) | goldens `digestless-hosted-already-wired`, `digestless-hosted-stale-url-repin`; `bun_lock_text.rs` (`same_wiring_modulo_integrity`), `redirect/mod.rs`, `replay.rs`, `takeover.rs`, `bun_lock.rs` unit tests; `in_process_redirect`, `in_process_vendor_bun`, `in_process_vendor_bun_takeover` |
| Mode conversion both directions; scoped `rollback` / `remove` | `hosted-then-vendored`, `vendored-then-hosted` | `mode_migration_bun` (1.4.2 × 3 OS, 1.3.14) | `in_process_vendor_bun_takeover`, `takeover.rs`, `covgap_commands_rollback` |
| CRLF lockfiles preserved (hosted line, vendored, rollback) | `crlf-lock` | — | golden `lock-v2-crlf`, `bun_lock.rs` |
| Bun 0.8.1 / 1.0.0 peer / transitive upstream limitation | recorded per cell; no selected target is installed, exit 0 and lock unchanged | — | — |
| Pre-download preflight envelopes, `--silent`, `--dry-run` `would_refuse`, detached parity | `get-uuid` / `get-search` / `workspace-get-uuid` / `workspace-get-search` refusals (exit codes, `downloaded == 0`) | — | `in_process_vendor_bun` (exact uuid-path envelope), `scan_vendor_e2e`, `get_modes_e2e`, `vendor_flow.rs` |

Not measured: a `--cwd <workspace member>` run (the member holds no
`bun.lock`, so the preflight passes and the engine refuses
`vendor_lockfile_missing` — pinned as today's behaviour, not a promise), and
package shapes the real registry never installs for the free patch
(non-empty peer meta on the oldest releases).

## CI wiring

- **`ci.yml` `e2e` matrix** — `oven-sh/setup-bun` installs the pinned release
  and the job exports `SOCKET_PATCH_BUN_E2E_REQUIRED=1` +
  `SOCKET_PATCH_BUN_E2E_VERSION`, under which the suites hard-fail instead of
  soft-skipping when `bun` is missing, is the wrong version, or the fixture
  install yields no text lock. Legs: `e2e_redirect_bun_build` and
  `e2e_vendor_bun_build` on ubuntu / macos / windows with Bun 1.4.2 plus
  ubuntu lock-era legs on 1.1.45 (version 0) and 1.2.23 (version 1);
  `mode_migration_bun` on the three OSes with 1.4.2 and on ubuntu with
  1.3.14. Without the `bun:` key the suites print `SKIP` and pass — the plain
  `test` job never exercises them.
- **`bun-compatibility.yml`** — the native matrix (16 releases × 3 OS, minus
  the three pre-1.1 Windows cells) on pull requests that touch the bun code
  paths, on pushes to `main` (the only rust-cache writer; the push filter
  covers `Cargo.lock`, `core/src/vendor/**`, the hosted rewriter + unwinds,
  and the CLI's `scan/**`, `get`, `vendor`, `repair_vendor`, `remove` and
  `rollback` commands) and on `workflow_dispatch` with `versions` / `shapes`
  / `modes` inputs. Each cell pre-downloads the release it runs — plus Bun
  1.1.38, the `legacy-lockb` baseline, de-duplicated — with retries, checks
  the `SHASUMS256.txt` listing before fetching the archive and verifies the
  archive against it, passes `--cli-revision` and `--cli-build-sha`, and
  uploads `summary.json` plus the captures as `bun-results-<os>-<bun>`. On
  dispatch, a `versions` override runs in every cell (the matrix is static),
  releases before 1.1.0 are skipped on Windows with a notice (an empty
  remainder writes a `noCells` summary and passes), and a `shapes` / `modes`
  narrowing that applies to none of a cell's release yields the script's
  `noCells` row rather than a red cell.
- **Native binary matrix** — `bun-compatibility.yml` also runs
  `scripts/backtest-bun-lockb.py` on Linux, macOS and Windows. Unix exercises all
  17 pinned binary writers and their compatible readers, plus modern readers
  of 1.1.45 and the earliest format-1 / pre-scripts locks. Windows starts at
  1.1.0, its first available release. Each job builds the Rust test executable,
  rejects missing tools and skipped required cases, and uploads every pair's
  log and SHA-256 provenance in `bun-binary-results-<os>`.
- **Production suites (on demand).**
  `e2e_hosted_production::bun_hosted_install_proof` runs in `ci.yml`'s
  `hosted-e2e` job (`npm install -g bun@1`,
  `SOCKET_PATCH_HOSTED_E2E_STRICT=1`);
  `e2e_vendored_production::bun_vendored_install_proof` is `#[ignore]`-gated
  and runs only by hand (`cargo test -p socket-patch-cli --test
  e2e_vendored_production -- --ignored`) — the production vendored proof for
  bun on three OSes is the native matrix above.
