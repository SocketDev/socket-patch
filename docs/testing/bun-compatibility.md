# Bun patch compatibility

`socket-patch` supports hosted, vendored and agent-mode npm patches in Bun
projects (text `bun.lock`). Two layers of real-Bun evidence back this page:

- **The native matrix** — `scripts/backtest-bun.py` runs real Bun releases
  against the public free Socket patch for `minimist@1.2.2`
  (`80630680-4da6-45f9-bba8-b888e0ffd58c`) with the production CLI and patch
  service, without a token or substitute service, and checks the INSTALLED
  bytes, lock stability, digest rejection and rollback on Linux, macOS and
  Windows ([workflow](../../.github/workflows/bun-compatibility.yml)).
- **The hermetic real-Bun suites** —
  `crates/socket-patch-cli/tests/e2e_redirect_bun_build.rs` (hosted),
  `e2e_vendor_bun_build.rs` (vendored) and `mode_migration_bun.rs`
  (hosted ⇄ vendored takeover, scoped unwind) drive a real `bun install`
  against a wiremock patch service on every pull request, in `ci.yml`'s
  `e2e` matrix.

Underneath, the hosted and vendored bun rewriters are pinned by shared golden
fixtures (`crates/socket-patch-core/tests/fixtures/redirect/npm/bun/*`,
byte-identical to the depscan TypeScript twins; refusal fixtures pin their
warning code through `expected-warnings.json`) and by hermetic CLI suites that
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
| Version-0 lock (Bun 1.1.39–1.1.45 `--save-text-lockfile`) with `workspace:` packages — 2-tuple entries `"consumer": ["consumer@workspace:packages/consumer", { "dependencies": { … } }]` | Refused `redirect_bun_workspace_unsupported`, lock untouched, exit 0. Remedy (measured): a plain `bun install` with any Bun ≥ 1.2 rewrites the lock in place as lockfileVersion 1, which hosted mode accepts; or delete `bun.lock` and re-lock. | Refused `vendor_bun_workspace_unsupported` (pre-version-2 policy, next row). | Works. |
| Version-1 lock (Bun 1.2–1.3 default) with `workspace:` packages — 1-tuple entries `["consumer@workspace:packages/consumer"]` | Rewritten (golden `lock-v1-workspace`; matrix 1.2.0–1.3.14 `workspace` / `workspace-nested`). | Refused `vendor_bun_workspace_unsupported` before any write. Policy, not a grammar limit: Bun 1.2.x–1.3.x resolve a workspace member's local-tarball path relative to the MEMBER (our root-relative tuple ENOENTs on `bun install`), 1.4.x relative to the lockfile, and a committed lockfileVersion-2 lock is the only proof that every consumer runs Bun ≥ 1.4 (1.3.x cannot parse v2). A deliberate over-approximation: a package declared only by the workspace ROOT vendors and installs on v1 too, but the lock cannot cheaply prove which workspace declares a hoisted entry. Remedy in the detail: delete `bun.lock`, re-run `bun install` with Bun ≥ 1.4 (an in-place `bun install` keeps the existing version), or use `--mode hosted`. Already-vendored purls, in-sync re-runs and `repair` rebuilds on such a lock are NOT refused. | Works. |
| Version-2 lock (Bun 1.4+) with `workspace:` packages, nested versions included | Rewritten (golden `lock-v2-workspace-nested`). | Vendored (matrix 1.4.0 / 1.4.2 `workspace`, `workspace-nested`, `already-vendored-workspace`). | Works. |
| Binary `bun.lockb` only (Bun ≤ 1.1.38 always; 1.1.39–1.1.45 without `--save-text-lockfile`) | Auto-migrated to text before the read when an npm patch is granted — see [the `bun.lockb` migration](#the-bunlockb-migration). | Refused `vendor_bun_lockb_unsupported`: "run `bun install --save-text-lockfile` (Bun >= 1.1.39), commit the resulting bun.lock, and re-run" — one detail text on the `vendor` router and on the `get` / `scan` pre-download preflight. | The installed tree is patched; the inventory cannot read the lock, so `scan` warns `bun_lockb_unsupported` (run-level `warnings[]` + stderr) instead of reporting a clean empty inventory on a fresh clone. |
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
reports `vendor_would_revert_redirect`). Vendored → hosted reverts the vendored
wiring, ledger entry and committed artifact first
(`redirect_takeover_reverted_vendored`). `rollback <purl>` / `remove <purl>`
unwind one of several hosted bun records; an unscoped `rollback` unwinds
everything through the whole-ledger replay. Pinned hermetically by
`tests/in_process_vendor_bun_takeover.rs`, against real Bun by
`tests/mode_migration_bun.rs` (CI: Bun 1.4.2 on three OSes, 1.3.14 on Linux)
and by the matrix's `hosted-then-vendored` / `vendored-then-hosted` shapes.

### The `bun.lockb` migration

Hosted mode needs a text lock to edit. On a project whose only lock is
`bun.lockb`, and only when an npm patch is granted, the CLI runs the `bun`
resolved on absolute `PATH` entries (Windows `bun.cmd` / `.bat` shims through
`PATHEXT` and `cmd.exe /C`; a relative `PATH` entry never runs a
repository-planted `bun`) as

```sh
bun install --save-text-lockfile --frozen-lockfile --lockfile-only
```

which needs no network and fails closed on drift. Measured against real
releases (macOS arm64, 2026-09-21; the matrix's `legacy-lockb` shape
re-measures it per OS):

| Bun on `PATH` | What the recipe does | CLI outcome |
|---|---|---|
| ≤ 1.1.38 | exit 0, "no changes" — no text lockfile exists | `redirect_bun_lockb_manual_migration`; the detail says Bun ≤ 1.1.38 must be upgraded |
| 1.1.39–1.1.42 | exit 0, "no changes", **no `bun.lock` written** (`--frozen-lockfile` suppresses the save; a bare `bun install --save-text-lockfile` does write one) | `redirect_bun_lockb_manual_migration` — run `bun install --save-text-lockfile` yourself, then re-run |
| 1.1.43–1.1.45 | writes `bun.lock` (lockfileVersion 0) and **keeps `bun.lockb`** | migrated; the CLI deletes the surviving `bun.lockb` itself |
| ≥ 1.2.0 | writes `bun.lock` (lockfileVersion 1) and deletes `bun.lockb` | migrated |
| `bun` missing, unspawnable, or exit ≠ 0 | — | `redirect_bun_lockb_unsupported` with bun's output tail in the detail; `bun.lockb` untouched (never parsed) |
| `--dry-run` | not spawned | `redirect_bun_lockb_would_migrate` |

A successful migration is recorded as a `redirect_bun_lockb_migrated` /
`removed` ledger edit whose `original` carries the pre-migration bytes
(standard base64, locks up to 8 MiB). `rollback` writes `bun.lockb` back and
warns `redirect_bun_lockb_restored` (the generated `bun.lock` is kept —
Bun ≥ 1.1.39 reads `bun.lock` when both exist; delete whichever you do not
want); `redirect_bun_lockb_unrestorable` is reserved for a marker without
bytes while the file is absent, or a different `bun.lockb` that appeared
since (never clobbered). A migration whose rewrite then lands nothing (the
granted version is not in the lock) is undone — bytes restored, text lock
removed, no ledger record — and reported
`redirect_bun_lockb_migration_reverted`. Bun ≥ 1.2 has no flag that emits the
binary form, so the hermetic suites cannot generate a `bun.lockb`; the branch
is pinned by shim-driven CLI tests (`tests/in_process_redirect.rs` incl. the
Windows `bun.cmd` twins, `tests/covgap_commands_scan_hosted.rs`) and by the
matrix's `legacy-lockb` shape against real Bun 1.1.39–1.4.2.

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
  migration recipe and digest enforcement are not.
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
  forces the save — while 1.1.45 keeps it at 0; that is the hosted refusal's
  remedy.
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
- **Both lockfiles present.** Bun ≥ 1.1.39 reads `bun.lock` when `bun.lockb`
  sits beside it; Bun ≤ 1.1.38 reads only `bun.lockb` — which is why the CLI
  removes a surviving `bun.lockb` after the migration (a stale binary lock
  beside the redirected text lock is what an old Bun would silently install
  the UNPATCHED bytes from).
- **Bun 0.8.1 / 1.0.0 with peer or overridden-transitive shapes** do not
  install the selected patched version at all; the CLI leaves those projects
  unchanged (an upstream limitation, recorded by the matrix as such).
- **Frozen installs never write the lock**, so only a plain `bun install` can
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
pre-populates) and `--jobs N` for parallel cells. Windows uses
`target/debug/socket-patch.exe`. Bun binaries are downloaded from the GitHub
release with retries and verified against `SHASUMS256.txt` (`bunSha256` in the
provenance); releases before 1.1.0 have no Windows binary.

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
`vendor_fetched_missing`, `reinstall_required`, `redirect_bun_lockb_restored`,
…); substring matching is never used. A configuration expected to be
supported FAILS on `redirect_bun_lockb_migration_reverted`,
`redirect_bun_lockb_migrated_without_redirect`, `redirect_bun_entry_not_found`
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
  `beforeHash` bytes; text-lock projects end with `bun.lock` restored and no
  `bun.lockb`, and `legacy-lockb` cells end with `bun.lockb` restored
  byte-identical (sha256 == baseline) beside the generated `bun.lock`, with
  `redirect_bun_lockb_restored` and never `redirect_bun_lockb_unrestorable`.

The runner captures the exact project manifests, lockfiles, optional
`.socket/manifest.json`, CLI JSON, exit codes, file hashes and assertion
results (`captures/<version>-<shape>-<mode>/`), plus provenance
(`cliRevision`, the build SHA, `bunSha256`). The depscan SBOM tests import
these captures through their fixture validation framework
(`bun-compatibility/generate-fixtures.py --captures`, depscan #26453).
Vendored artifact contents are verified by the native runner; they are not
needed for SBOM lockfile annotation.

## What is verified where

| Claim | Real-Bun matrix (`backtest-bun.py`) | Real-Bun hermetic suites (`ci.yml` `e2e`) | Bun-less unit / CLI tests |
|---|---|---|---|
| Text lock 0 / 1 / 2 rewritten and installed, both modes | 1.1.39–1.4.2 | `e2e_redirect_bun_build` + `e2e_vendor_bun_build` on 1.4.2 (3 OS), 1.1.45 and 1.2.23 (Linux); the fixture asserts the lock version matches the era table, the v1-on-1.4 leg proves a committed v1 lock keeps installing | goldens `lock-v0`, `basic` (v1), `lock-v2`; `bun_lock.rs`, `lock_inventory.rs` |
| Binary lock → vendored refuses; `scan` warns `bun_lockb_unsupported` | 0.8.1–1.1.45, `legacy-lockb` | — | `in_process_vendor_bun`, `covgap_commands_scan_mod` |
| lockb migration bands (manual 1.1.39–1.1.42; migrates ≥ 1.1.43; the CLI removes `bun.lockb`; rollback restores it) | `legacy-lockb`, 1.1.39–1.4.2 | — (Bun ≥ 1.2 cannot write a `bun.lockb`) | shim-driven `in_process_redirect` (incl. Windows `bun.cmd`), `covgap_commands_scan_hosted`, `replay.rs` |
| Version-0 workspace hosted refusal + remedy | `text-workspace` (1.1.39–1.1.45); 1.1.45 `workspace*` after migration | — | golden `lock-v0-workspace-refusal` (+ `expected-warnings.json`), `redirect/mod.rs` unit tests |
| Pre-v2 workspace vendored refusal (policy) + remedy; version 2 supported incl. nested | v1: 1.2.0–1.3.14 `workspace*`; v0: `text-workspace`; v2: 1.4.x | `e2e_vendor_bun_build` scoped leg (deps + bin meta survive) | `bun_lock.rs` (`legacy_workspace_tarballs_refuse_before_writes`, in-sync / rebuild exemptions), `in_process_vendor_bun`, `repair_vendor_flavors_e2e` over {0, 1, 2} × workspace shapes |
| Digest boundary 1.3.10 (registry tuples 1.2.0) | 1.3.9 vs 1.3.10 cells, `registryDigestEnforced` | tampered twins in both suites, pinned from both sides | — |
| Mode conversion both directions; scoped `rollback` / `remove` | `hosted-then-vendored`, `vendored-then-hosted` | `mode_migration_bun` (1.4.2 × 3 OS, 1.3.14) | `in_process_vendor_bun_takeover`, `takeover.rs`, `covgap_commands_rollback` |
| CRLF lockfiles preserved (hosted line, vendored, rollback) | `crlf-lock` | — | golden `lock-v2-crlf`, `bun_lock.rs` |
| Bun 0.8.1 / 1.0.0 peer / transitive upstream limitation | recorded per cell | — | — |
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
  paths, on pushes to `main` (the only rust-cache writer) and on
  `workflow_dispatch` with `versions` / `shapes` / `modes` inputs. Each cell
  pre-downloads the release with retries, verifies `SHASUMS256.txt`, and
  uploads `summary.json` plus the captures as `bun-results-<os>-<bun>`.
- **Production suites (on demand).**
  `e2e_hosted_production::bun_hosted_install_proof` runs in `ci.yml`'s
  `hosted-e2e` job (`npm install -g bun@1`,
  `SOCKET_PATCH_HOSTED_E2E_STRICT=1`);
  `e2e_vendored_production::bun_vendored_install_proof` is `#[ignore]`-gated
  and runs only by hand (`cargo test -p socket-patch-cli --test
  e2e_vendored_production -- --ignored`) — the production vendored proof for
  bun on three OSes is the native matrix above.
