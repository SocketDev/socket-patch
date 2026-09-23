# Changelog

All notable changes to socket-patch are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-v3.0 entries are concise summaries derived from each tag's commit
history. For full per-release detail, see the
[GitHub releases page](https://github.com/SocketDev/socket-patch/releases).

The `Release` workflow refuses to publish a version that does not appear
in this file — see `scripts/release-lint.sh` (run by the `version` job in
`.github/workflows/release.yml` and by CI on version-bump PRs). Bump PRs
are opened by `scripts/bump-version.sh`, which rolls `[Unreleased]` over
into the new version's section — see docs/releasing.md.

## [Unreleased]

> **Semver note:** this entry changes `rollback`'s default behavior, narrows
> the meaning of its existing `vendored: []` JSON key, makes vendored mode
> manifest-free, and turns a plain non-TTY `scan` report-only — all MAJOR
> per CLI_CONTRACT.md's semver policy — so it ships as the next major
> release (v5.0).

### Changed (BREAKING)

- **Binary Bun lockfiles are patched natively in place.** Hosted and vendored
  modes read and rewrite `bun.lockb` formats 1–3 directly, including mode
  changes, repair, and scoped rollback. Binary-to-text conversion, migration
  ledger replay, and their warning codes and tests have been removed.
- **`rollback` is now the full-state dual of `scan`.** `scan` and `rollback`
  are the batch primaries (`get`↔`remove` stay the single-patch duals): a
  bare `rollback` restores the SYSTEM to unpatched across all three modes —
  in-place file restore (agent), vendored unwire + artifact deletion +
  ledger-entry drop, hosted lockfile-redirect unwind + redirect-record drop
  — then removes the rolled-back entries from `.socket/manifest.json` and
  GCs the now-unused blobs plus diff/package archives. No `--mode` needed:
  state is inferred from the manifest, the vendor ledger, and the redirect
  ledger, and rollback now runs manifest-less when a ledger holds work
  (hosted-only and vendored projects; the truly-empty project
  keeps the "Manifest not found" exit 1, and a wired-but-ledgerless project
  errors naming `socket-patch repair`). Wet non-preserve runs confirm once
  ("Roll back N patches, remove them from the local manifest, and delete
  M vendored artifacts and their ledger records?" — auto-accepted under `--yes`/`--json`/non-TTY;
  declining prints "Rollback cancelled." and exits 0). Drift-keeps, hosted
  refusals/unsupported targets, corrupt ledgers, and a failed manifest
  write exit 1 `partial_failure`; not-installed entries still exit 0.
- **`rollback --json`'s `vendored: []` array narrows** to vendor-owned purls
  the run did NOT act on (today: the corrupt-vendor-ledger skip). Acted-on
  entries move to the new always-present `vendoredReverted` /
  `vendoredPreserved` / `vendoredKept` arrays; the envelope also gains
  always-present `warnings[]` (`{code, detail}`, now populated), `hosted`
  (`{reverted, failed, unsupported, editedFiles}`), `manifest`
  (`{removedEntries, preserved}`), `gc`, and `paths` keys.
- **Vendored mode is manifest-free.** `scan --mode vendored` and
  `get --mode vendored` never write (or read) `.socket/manifest.json`: the
  selected patch records are fetched into memory and every vendor-ledger entry
  carries `detached: true` plus the embedded `record` as its verification
  source, so a vendored project's footprint is `.socket/vendor/**` only. The
  former `--detached` opt-in is now the only vendored posture — the flag is
  hidden, accepted as a no-op for compatibility, and still a usage error
  without vendored mode. JSON uses the detached download vocabulary for both
  commands (`downloaded: N`, `detached: true`, `patches[].action` =
  `downloaded` | `skipped` | `failed`). The vendor step vendors exactly what
  discovery selected — the "whole manifest is vendored" re-vendor from a
  committed manifest on an empty discovery is retired (`repair` verifies and
  rebuilds committed vendored state) — and a legacy manifest record for a purl
  a vendored run vendors is migrated into the ledger (dropped from the
  manifest; an emptied manifest is left as `{"patches": {}}`). `list` now
  reads the vendor ledger too, so a vendored-only project lists its patches
  with a `Mode: vendored` label and exits 0 instead of `manifest_not_found`;
  `scan --prune`'s lockfile-unused reconcile applies to every ledger entry
  (the check is about the lockfile, not the manifest); and standalone `vendor`
  with no manifest is a clean exit-0 no-op whose message names the missing
  manifest (and the ledger entries `repair` verifies) instead of claiming
  "No .socket folder found".
- **A plain `scan` without a TTY is report-only.** When stdin is not a TTY,
  `--yes` is absent, and no intent flag (`--mode`, `--apply`, `--sync`,
  `--vendor`, `--redirect`, `--prune`) is given, human-mode `scan` prints the
  discovery report and the "To apply a single patch, run: …" hint, downloads
  nothing, creates no `.socket/`, and exits 0 — it no longer auto-accepts the
  apply prompt. Any intent flag, `--yes`, or a TTY keeps the previous
  behavior; `rollback`/`remove`/`get`'s non-TTY auto-accept is unchanged.
  Human `scan --mode hosted` now prints the results table and update
  detection like the other modes and confirms once ("Redirect N packages
  to the hosted patch server?" — the same prompt as `get --mode hosted` —
  default yes, skipped by `--yes`/`--json`/`--dry-run`; on a non-TTY stdin
  without `--yes` it prints `Non-interactive mode detected, proceeding
  automatically.` and proceeds), fetches patch details with the agent arm's
  progress counter and per-package warnings, and an empty hosted discovery
  prints `No patches available for installed packages.` and exits 0 without
  entering the redirect engine (was `Redirected 0 package(s)`); a discovery
  whose every offer is paid-tier for an org without paid access stops the
  same way with `No downloadable patches (paid subscription required).`. A
  malformed redirect ledger on a human hosted run that stops before the
  engine is reported as the read-only `Warning: the redirect ledger … is
  malformed` advisory instead of nowhere.
- **`apply.lock` never outlives a command, and hosted mode takes it.** Lock
  acquisition creates `.socket/` when missing; the lock file is unlinked
  (while still held) and an otherwise-empty `.socket/` removed when the
  command exits, dry runs included, so there is nothing to `.gitignore` and
  `repair` no longer has a lock-cleanup step (a leftover from a crashed run is
  reclaimed and removed by the next lock-taking command; a live holder is
  still `lock_held`, exit 1). `scan`/`get --mode hosted` now acquire the lock
  around their first wet write — never on `--dry-run` or when nothing would
  be written, so previews create no `.socket/` — and report `lock_held` /
  `lock_io` like the other lock holders (top-level `errorCode` on the hosted
  JSON shape; a read-only project root or a file squatting on `.socket/` is
  refused at the lock, before the redirect ledger is touched, and a
  vendored→hosted takeover over a symlinked wiring file is refused with
  `redirect_symlinked_file_unsupported` before any revert). A zero-grant wet
  run — which holds no lock — no longer moves a malformed
  `redirect-state.json` aside: like a dry run it reports the hard error and
  leaves the file in place; only the lock holder quarantines. The lock guard
  unlinks only the file it holds (a replacement planted by a non-cooperating
  `rm` + `touch` is left for the next acquire), and a long `--lock-timeout`
  wait behind a hot loop of short commands can no longer accumulate its
  vanished-file retries into a spurious `lock_io`. Agent-mode `get`
  and `scan --apply`/`--sync` hold one lock window across download →
  manifest write → nested apply (the nested apply no longer re-acquires and
  now inherits `--lock-timeout`/`--verbose`); `setup` takes the lock while
  persisting `--exclude`; `scan --prune` acquires once for its vendored
  reconcile and manifest prune, and the GC legs of `scan --prune` and
  `vendor` honor `--lock-timeout` and report a lock I/O error instead of
  silently skipping on it.
- **Retired:** the legacy `.socket/cargo-patches` redirect takeover in the
  cargo vendor backend (never shipped in a tagged release — such
  `[patch.crates-io]` entries now refuse as `user_authored_patch_entry`) and
  the `pypi_pipenv_invalid_wheel` refusal code (the Pipenv backend takes the
  resolved version instead of parsing the wheel filename).

### Added

- **Pipenv projects can use hosted patches, and vendored patches keep every
  category.** `scan --mode hosted` rewrites every `Pipfile.lock` category
  (`default`, `develop`, Pipenv 2022+ named categories) that pins the patched
  release to the hosted wheel — `file` references for Pipenv 2018 and later,
  `path` for 7–11 (probed once with `pipenv --version`; `SOCKET_PIPENV_MAJOR`
  pins it), pipfile-spec < 6 refused — preserving markers, extras, unrelated
  entries, the Pipfile and its content hash, with per-entry rollback
  (`redirect_pipenv_entry`). Vendored mode keeps custom categories and extras,
  uses `path` for wheels with extras (Pipenv 2022's file-URL bug) and refuses
  installers older than 2018 (`pypi_pipenv_installer_unsupported`). A stale
  Pipfile.lock only vetoes the sibling Python rewriters on a real pin/source
  conflict (`redirect_pipenv_refused`); anything else is
  `redirect_pipenv_skipped`. Measured across the last stable release of all
  18 published Pipenv majors — see `docs/testing/pipenv-compatibility.md` and
  `scripts/backtest-pipenv.py`.
- **`Pipfile.lock` is inventoried.** Lock-only Pipenv checkouts (a fresh
  clone with nothing installed) now discover their pins in every mode —
  hosted redirects them, vendored fetches the pristine wheel by one of the
  lock's recorded digests (`LockIntegrity::Sha256AnyOf`, resolved through
  PyPI's JSON API and verified against the same digest) and agent/scan list
  them as lockfile-only packages. Previously they discovered nothing and
  exited 0. Socket's own references stay discoverable, so a re-scan of an
  already-redirected or already-vendored lock-only checkout re-confirms it;
  a lock that resolves only from private indexes is never looked up on
  pypi.org.
- **Pipenv's out-of-tree virtualenv is discovered.** Agent mode (bare `scan`,
  `rollback`, `vex`) now finds `$WORKON_HOME/<dir>-<hash>[-<python>]` (the
  `.venv` file pointer, `PIPENV_CUSTOM_VENV_NAME` and `PIPENV_PIPFILE`
  included) exactly as Pipenv 7 through 2026 place it, instead of falling
  through to the global interpreter's site-packages.
- **Pipenv stale-install guard.** Pipenv never reinstalls a release that is
  already present, so a hosted or vendored rewrite over a warm venv leaves the
  upstream bytes installed; `redirect_pypi_stale_install` /
  `pypi_pipenv_stale_install` now say so, naming the site-packages dir and
  the verified remedy (`pipenv run pip uninstall -y <pkg> && pipenv sync`, or
  a clean `pipenv --rm && pipenv sync`), and the stale purl is excluded from
  the same-run `--vex`.
- **PDM projects take hosted patches, and hosted and vendored patches share
  one validated `pdm.lock` rewriter.** `scan --mode hosted` rewrites `pdm.lock`
  to point the target `[[package]]` at the hosted wheel URL with the patched
  SHA-256 (`redirect_pdm_lock_package`), and `scan --mode vendored` wires the
  same unit to a committed wheel through the shared rewriter
  (`utils/pdm_lock.rs`). Both preserve line endings and non-canonical spacing,
  support the legacy `[metadata.files]` table and separate `extras` entries,
  are idempotent, and leave `pyproject.toml` and `content_hash` untouched.
  Supported lock formats are `2` (PDM 0.12–1.4) and `4.3`–`4.5.1` (PDM 2.8.1+;
  PDM 2.8.0 writes the same `4.3` lock but still loses candidate identity, so
  upgrade to ≥ 2.8.1);
  the identity-losing `3.1` / `4.0`–`4.2` formats (PDM 1.8–2.7) and unknown
  future formats are refused before any write (`redirect_pdm_refused` /
  `pypi_pdm_lock_version_unsupported`), leaving the registry lock installable.
  A `pdm.lock` written by PDM 0.x/1.x (lock format `2`) warns
  `redirect_pdm_legacy_sync_required`: those releases have an upstream
  freshness bug, so `pdm install` can regenerate the lock — use `pdm sync`.
  Verified end-to-end against real PDM 0.12–2.29 across hosted, vendored and
  agent mode on Linux, Windows and macOS; see
  `docs/testing/pdm-compatibility.md` and `scripts/backtest-pdm.py`. When
  several Python lockfiles coexist, `uv.lock` and `poetry.lock` drive hosted
  PyPI redirects ahead of `pdm.lock`, so a leftover `pdm.lock` beside them
  neither blocks a live redirect nor is falsely attested. A hosted lock-only
  `pdm.lock` checkout is discovered and redirected (the lock inventory now
  reads `pdm.lock`), and a re-scan after an external `pdm lock` rebases the
  ledger's recorded edits onto the relocked text so `rollback` stays
  byte-invertible even when PDM reflows the lock's line endings.
- **Poetry projects take hosted patches, and vendored patches now cover every
  `poetry.lock` generation.** `scan --mode hosted` rewrites `poetry.lock` to a
  `[package.source] type = "url"` pointing at the Socket-hosted, SHA-256-pinned
  wheel (Poetry 1.0 through 2.x; Poetry 0.12 ignores URL sources and is refused
  with `redirect_poetry_lock_unsupported`), and `scan --mode vendored` accepts
  the legacy `[metadata.hashes]` (0.12) and `[metadata.files]` (lock 1.0/1.1)
  layouts next to the 2.x `files` arrays, CRLF locks included. The rewrite keeps
  every other byte of the lock — dependency metadata, groups, markers, extras
  and the pyproject `content-hash` — and records independent rollback fragments
  per patch, so `rollback` restores the recorded originals in any order.
  Verified end-to-end against real Poetry 0.12.17, 1.0.10, 1.1.15, 1.2.2,
  1.3.2, 1.4.2, 1.5.1, 1.6.1, 1.7.1, 1.8.5, 2.0.1, 2.1.4, 2.2.1, 2.3.4 and
  2.4.3 in hosted, vendored and agent mode — see
  `docs/testing/poetry-compatibility.md` and `scripts/backtest-poetry.py`.
  Poetry releases before 1.4 neither verify local wheel hashes nor replace an
  already-installed package at the same version; both modes surface that as an
  advisory (`pypi_poetry_integrity_unverified`, `redirect_poetry_stale_install_risk`)
  keyed on the lock's writer, and the hosted rewriter warns
  `redirect_poetry_entry_not_found` when a lock has no entry for a granted
  patch (uv parity). A rotated grant token or republished patch supersedes the
  earlier hosted URL in place instead of being refused as a foreign source,
  a future `lock-version = "2.<n>"` is rewritten like 2.1 on every path
  (the vendored loader already accepted it), and a malformed
  `[metadata.files]` / `[metadata.hashes]` value is refused instead of
  panicking the scan. Rollback stays invertible across Poetry's own relocks:
  the recorded package fragment carries its boundary header, so a unit that
  Poetry 1.1/1.2 re-laid (source kept, inserted `files` line dropped) is
  refused rather than mistaken for an already-reverted lock, a lock-1.0
  redirect restored by hand converges instead of refusing, and a re-scan
  after such a relock REBASES the ledger's edits (pristine → current)
  instead of appending a chain whose older links match nothing — which made
  `rollback` and `remove` refuse forever. (#241)
- **Python patches survive uv lockfiles in both hosted and vendored modes.**
  `scan --mode hosted|vendored` now rewrites native `uv.lock` together with
  the paired `pyproject.toml` source and metadata, PEP 723 script locks
  (`*.py.lock` plus the script's inline metadata), PEP 751 `pylock*.toml`,
  and uv-compiled hashed `requirements.txt`, so `uv sync --frozen|--locked`,
  `uv run --script`, and `uv pip sync --require-hashes` install the patched
  wheel instead of the registry artifact. Verified against real uv binaries
  from every 0.x release family (0.0 through 0.12) — first and latest release
  of each plus every observed behaviour boundary — see
  `docs/testing/uv-compatibility.md`: hosted mode covers requirements from
  uv 0.0.5 and native `uv.lock` from 0.1.45 — the first release whose
  `uv lock` writes one — through all three `[[distribution]]` lock shapes
  and `[[package]]`; vendored native covers every `[[package]]` release
  (uv ≥ 0.2.35), vendored requirements cover uv ≥ 0.1.24 (hash-enforced by
  `uv pip sync --require-hashes` from 0.1.32 and by default from 0.5.x).
  Follow-up hardening:
  `vendor --revert` refuses to delete a vendored Python wheel a lock still
  references when the ledger entry has no wiring to replay (the shape
  `repair` rebuilds), a script or PEP 751 lock supplements rather than hides
  `poetry.lock`/`requirements.txt` pins, symlinked locks are discovered, and
  refused before any write (never rewritten in place — uv writes through the
  link, an atomic rename would replace it; hosted
  `redirect_symlinked_file_unsupported`, vendored
  `pypi_uv_symlink_unsupported` / `pypi_lock_symlink_unsupported`), CRLF
  locks keep their line endings in both the hosted rewriter and the vendored
  uv backend (`pyproject.toml`, the rewritten `[[package]]` unit and the
  appended `[manifest]` / `[package.metadata]` fragments, plus their revert),
  and the hosted `[tool.uv.sources]` edit renders as a header after
  `[project]` the way uv writes it. (#238, #239)
- **uv `--locked` survives the project shapes the plain fixture never
  reached.** A package listed only in `[tool.uv] dev-dependencies` is now
  classified as a direct dependency (it was wired as a transitive override
  and its `requires-dev` entry left stale), and every duplicate
  `requires-dist` / `requires-dev` entry for the package — extras, markers —
  is repointed rather than only the first, so `uv sync --locked` and
  `uv lock --check` accept the patched lock instead of exiting 2 and a plain
  `uv sync` no longer rewrites it. `[tool.uv] constraint-dependencies` /
  `build-constraint-dependencies` naming the package have their `[manifest]`
  `constraints` / `build-constraints` entries repointed too (uv ≥ 0.5.6
  serializes them with the package's source; 0.2.37–0.5.3 reject the
  repointed entry under `--locked`, so the repoint emits the advisory
  `pypi_uv_constraints_require_uv_0_5_6`). The transitive
  (override-dependencies) branch emits the advisory
  `pypi_uv_override_requires_uv_0_5_6`: uv applies `[tool.uv.sources]` to
  overrides only from 0.5.6, so on 0.2.35–0.5.3 `--frozen` installs the
  patch but a plain `uv sync` reinstalls the registry wheel. The
  `[[distribution]]`-grammar vendoring refusal now names the real reasons
  (relative path sources unparseable through 0.2.6, rejected by `--locked`
  and absolutized by `uv lock` / `uv sync` on 0.2.17–0.2.34) instead of
  "records absolute paths". `scripts/backtest-uv.py` gains a project-variant
  lane covering these shapes on every `[[package]]` binary and a
  `--render-doc-table` mode that prints the doc's results tables from
  `results.json`; its export lane reads `uv export` from stdout because
  `--output-file` only exists from 0.4.7. (#239)
- **Unwired Python vendor entries revert safely.** `vendor --revert` /
  `rollback` on a ledger entry without wiring to replay (the shape `repair`
  reconstructs) skips the lock-reference guard under `--preserve-state`
  (nothing is deleted, so nothing needs protecting), refuses fail-closed when
  the project root cannot be listed or a lock's symlink target cannot be
  read (instead of treating "could not enumerate locks" as "no lock
  references it" and deleting the wheel), probes `-r` / `--requirement`
  includes of `requirements.txt` alongside the root file — the orphan sweep
  and `repair` see include-hosted pins too — and reclaims a genuinely
  orphaned artifact directory whose lock is gone or whose ledger flavor is
  unknown instead of failing forever. Hosted `scan` / `get`, `repair`, and
  ledger-less `rollback` read candidate lockfiles through the FIFO-safe
  reader, so a named pipe at a lockfile name no longer wedges the command in
  `open(2)`. (#239)

- **Path targeting on `scan` and `rollback`.** `scan [PATHS]...` scopes
  discovery to packages with an installed copy under a matching glob
  (ancestor rule: `scan packages/foo` covers the subtree; `*` never crosses
  `/`; absolute patterns are the only way to reach `--global` stores); the
  prune universe is never narrowed (`scan PATHS --prune` prunes exactly
  what an unscoped run would), lockfile-only/vendor-ledger supplements are
  excluded with a `path_scope_excluded_supplements` warning, an empty match
  is a normal empty scan (exit 0, no GC), and PATHS is rejected with
  `--mode hosted|vendored` (exit 2). `rollback [TARGET]...` accepts
  PURLs, UUIDs, and path globs (variadic, unioned); only path-SHAPED tokens
  (separator, glob metachar, `./` prefix, absolute) become globs, so a
  mistyped identifier stays a safe exit-1 error. A path target selecting
  nothing is an error on rollback (exit 1) and an empty scan on scan
  (exit 0); path targets select installed copies, and rollback restores
  EVERY installed copy of a selected patch (`out_of_scope_copies_restored`
  warning when copies live outside the patterns).
- **`--preserve-state` on `rollback` and `remove`** (env
  `SOCKET_PRESERVE_STATE`): fully unpatch the system but keep the local
  state for a later re-apply — manifest entries, vendored artifacts +
  ledger entries (kept byte-identical; re-vendor re-wires from the live
  lock) — and skip all GC. Hosted redirects have no preservable state:
  they are unwound and their records dropped either way
  (`hosted_state_not_preservable` warning). On `remove`, combining it with
  `--skip-rollback` is a usage error (exit 2, flag- or env-sourced): the
  combination would be a no-op — one flag keeps the tree and drops the
  state, the other restores the tree and keeps the state.
- **Hosted redirect unwind.** Per-purl reverts for cargo + the npm family,
  plus a whole-ledger reverse replay (core `patch/redirect/replay.rs`) that
  runs whenever the scope covers every redirect record: a per-kind inverse
  table, staged all-or-nothing per ecosystem group, covering gem, golang,
  pypi, composer, bun, and the non-package rideshare edits (pnpm
  `trustLockfile` auto-config — pristine scaffold deleted, modified
  scaffold keeps the file and loses only the owned line). Native `bun.lockb`
  package snapshots restore binary resolutions directly;
  maven and nuget fail closed with `hosted_revert_unsupported` guidance
  (their structured-metadata edits keep their ledger records; re-run
  `scan --mode hosted` or restore from VCS). Refused groups keep their
  edits AND records — the coherent ledger a retry needs.
- **`remove` gains the hosted leg and full archive GC**: an identifier
  matching hosted redirect-ledger records unwinds those redirects (per-purl
  or via the replay when it covers the full record set; works manifest-less
  on hosted-only projects; unsupported ecosystems fail closed with
  `hosted_revert_unsupported` before the manifest mutation), and remove's
  default GC extends from blobs-only to blobs + diff + package archives
  (parity with rollback/repair/`scan --prune`).

### Fixed

- **Terminal output is clean on every command.** Progress lines no longer
  leave stale text behind (`scan` printed e.g. `Found 7 patches for 1
  packagesatch 7/7)`) or run into warnings printed while they are active.
  Progress, prompts, color and truncation now share one implementation.
  - **Progress lines:** a status line clears itself on finish. It is never
    drawn off a TTY, under `TERM=dumb`, in debug mode, or under
    `--json`/`--silent`. `fetch`, `vendor`, `setup`, lock waits and
    `--update` checks now show progress instead of going quiet.
  - **Prompts:** Ctrl-D at a `[Y/n]` prompt now declines instead of
    accepting. Keys pressed while a scan is running no longer answer the
    prompt that follows. The cursor is restored when a selection menu is
    interrupted.
  - **Color:** `NO_COLOR`, `CLICOLOR`, `CLICOLOR_FORCE` and `TERM=dumb` are
    honored. Colored table rows now align.
  - **Wording:** counted nouns read `1 package` / `2 packages` instead of
    `package(s)`. `Error:` / `Warning:` prefixes are consistent, and
    warnings go to stderr. `--silent` is errors-only, but a failing run
    still prints why. Output that came out in random order is now sorted.
    `--help` pages no longer show developer notes.
  - **Behavior fixes:** `get --dry-run` and `vex --dry-run` no longer write
    anything, and `vex -O -` writes to stdout. `scan --json` never stops at
    an interactive menu. API errors show the server's message instead of a
    raw JSON body.
- **Reversal leaves no `.socket/` residue.** `rollback`, `remove`,
  `vendor --revert`, the hosted unwind and the GC sweeps now prune what they
  empty: an emptied redirect or vendor ledger is deleted together with the
  empty `.socket/vendor/<eco>/` and `.socket/vendor/` directories (per-entry
  vendored reverts prune their ecosystem husk; a `redirect-state.json.corrupt`
  quarantine keeps its directory), emptied `blobs/`, `diffs/` and `packages/`
  stores are removed, and `.socket/` itself goes with the lock when nothing is
  left — so a fully unwound hosted or vendored project has no `.socket/` at
  all. Deliberately kept: the zero-patch `.socket/manifest.json`
  (`{"patches": {}}` + its `setup` block — `list`/`apply`/`vex` exit codes
  depend on it) and the `setup`-owned `.socket/.gitignore`,
  `gem-plugin-stamp` and `bundler-plugin/` (rollback never undoes setup).
  `setup --remove` now also removes an emptied `.socket/`.
- **`scan --prune` says what it skipped and what it could not finish.** The
  `gc` JSON sub-object gains `failedVendoredEntries` plus the additive
  `skipped: {code, message}` (`lock_held` | `lock_io`) and
  `warnings: [{code, detail}]` (`vendor_state_write_failed`,
  `manifest_write_failed`, `cleanup_failed`) keys, with matching `GC: …`
  human lines, so a pass that could not take the lock or could not rewrite a
  ledger no longer reads as a clean all-zero sweep — and a lock I/O fault or
  a failed rewrite is never mislabelled as lock contention. A legacy manifest
  record migrated into the vendor ledger is reported as the
  `vendor_manifest_record_migrated` / `vendor_manifest_migration_failed` run
  warnings; a corrupt manifest no longer fails a vendored run (standalone
  `vendor` still fails closed on it).
- **Vendored `get`/`scan` name the patch they replace.** A `downloaded`
  record for a purl the vendor ledger holds at another uuid carries `oldUuid`
  and the human `[fetch]` line reads `(replacing <uuid>)`;
  `get --mode vendored --dry-run` prints `[dry-run] Would download and vendor
  N patches. No changes made.` on both identifier paths; the `[note]` and
  `Patch record saved to` lines are gone with the manifest.
- **Agent-mode `get` leaves nothing behind when it records nothing.**
  `.socket/` and `.socket/blobs/` are created only when a record is
  persisted (all-skipped and all-failed runs leave no `.socket/`), a
  same-uuid `get <uuid>` re-run rewrites neither the manifest nor the blobs,
  and a blob/diff fetch that lands nothing creates no `.socket/blobs/` or
  `diffs/` — the `Cannot create blobs/archives directory` all-failed envelope
  is gone; an uncreatable cache dir is a per-entry
  `Failed to write blob/archive to disk`.
- **`ownership_not_restored` is a warning, not silence.** A file `apply`
  patched (or `rollback` restored) whose ownership could not be put back to
  the original uid/gid now surfaces as an `ownership_not_restored` run
  warning (`warnings[]` plus `Warning (ownership_not_restored): …` on
  stderr) instead of riding a successful result unseen; the mode is still
  restored.
- **`remove` on ledger-only state.** A missing manifest beside a vendor or
  redirect ledger that holds nothing for the identifier answers `not_found`
  (exit 1) instead of `manifest_not_found`; a second `--skip-rollback` on
  the ledger-only leftover of an earlier `--skip-rollback` is refused with
  `vendor_state_retained` (was `not_found`); every matching vendor-ledger
  entry — detached or not — is removable through the ledger with
  `--preserve-state` and drift-keeps honored exactly as on the manifest
  path; manifest entries are removed in sorted order, and the
  `(not installed)` line prints only when something was not installed.
  `rollback` prints `No patches found in manifest` only for an unscoped run
  with no work in any leg.
- **`setup --exclude` persists after the prompt, under the lock.** The
  exclusion list is written after discovery and confirmation (also on the
  already-configured path when the flag is explicit) as a read-modify-write
  under `apply.lock`; a held or unopenable lock, or a manifest that cannot
  be read or written, is reported as `not persisting --exclude: …` instead
  of being swallowed. `setup --check` reads the vendor ledger even without
  a manifest and, on a corrupt one, warns `unreadable vendor state` and
  reports a `vendor_ledger` error entry (verdict `error`, exit 1) — never
  `configured`; `vex` discloses the same unreadable ledger before its
  `manifest_not_found` / `no_patches` exit on a manifest-free project; `list`
  degrades a corrupt vendor ledger to a `Warning: unreadable vendor ledger …`
  line (muted by `--silent`) rather than an error; `patch_setup` telemetry
  fires only for a successful, non-dry-run setup.
- **`repair`/`vendor` state hygiene.** `repair` resolves installed copies
  through qualified ledger keys (gem `?platform=`, pypi `?artifact_id=`,
  maven `?classifier=` no longer read as "not installed"), puts a crashed
  rebuild's `<uuid>.pre-rebuild` set-aside back when it is the only copy,
  and reports an absent or empty blobs dir as `No blobs to clean up.`; every
  artifact sweep (`repair`, `rollback`, `remove`, `scan --prune`) keeps going
  past one unremovable file and reports the failures afterwards; `vendor`'s
  dropped-record reconcile saves per purl and counts a failed save as
  `vendor_state_write_failed`; `vendor_marker_write_failed` is the one
  marker-failure warning for every backend (cargo/golang/pypi's
  `marker_write_failed` retired), and a pypi vendor whose informational
  marker cannot be written now succeeds with that warning instead of
  sweeping the wheel; npm, yarn (classic and berry) and pnpm reverts honor
  the drift-keep on an unwired entry like bun and legacy pnpm already did;
  the hosted replay no longer credits a byte-identical hatch rewrite as an
  edited file; a corrupt redirect ledger met by a hosted scan is reported
  once, not twice.
- **Manifest inputs are validated before they become paths.** `apply`
  refuses an `afterHash` that is not a 64-hex blob hash or a uuid that is not
  a plain path segment and reads blobs through a symlink-refusing opener (a
  poisoned manifest or a planted `blobs/` symlink can no longer read out of
  tree); `rollback` deletes patch-added files in every pnpm store copy and
  heals a patched twin of an already-original primary.
- **Human chrome.** The global-mode `Using <X> at: <path>` banner moves to
  stderr so piped stdout stays clean; the empty-crawl hint of `scan` and
  `get` reads `Run your package manager's install first.` instead of a fixed
  npm/yarn/pnpm/pip/cargo/go/mvn/composer list; `vendor --revert` and the no-manifest
  no-ops of `vendor` and `apply` (and `apply --check`) build no API client,
  so the `SOCKET_API_TOKEN` advisories no longer print on hooked
  manifest-less runs, and `repair` prints its token notice once.
- **Telemetry and self-update robustness.** The telemetry client uses a 2 s
  connect timeout (a blackholed endpoint no longer stalls every command for
  the full request budget), and `--update` maps only a contention errno to
  `update_in_progress` — other lock failures surface their real cause.
- **A normal `scan` never creates `.socket/`.** Report-only, `--dry-run`,
  zero-discovery and no-op runs (hosted or otherwise) no longer scaffold the
  directory or a lock file; a GC pass checks for a manifest before it locks.
- **`apply --silent` on an all-unmatched manifest prints its error line** —
  errors are never muted by `--silent`; and the no-manifest early exits of
  `apply` and `vendor` name the missing `.socket/manifest.json` instead of
  "No .socket folder found" (the folder may legitimately hold setup files or
  vendored state).
- **Hosted redirect hygiene.** Missing project files no longer skip silently:
  `redirect_composer_no_lockfile`, `redirect_gem_no_gemfile` (neither manifest
  nor lock present) and `redirect_maven_no_pom` (no `pom.xml`, no Gradle
  build) warn once per run; a present-but-corrupt `packages.lock.json` warns
  `redirect_nuget_lock_unparseable` before any config mutation; a `Cargo.lock`
  with several same-name+version `[[package]]` blocks and no `source`
  disambiguation warns `redirect_cargo_lock_pkg_ambiguous` and skips
  transactionally; a registry override of the wrong kind now warns the arm's
  missing-override code for nuget/gem/golang (previously a silent skip); the
  ledger's `redirect_nuget_source` edit records `action: "added"` when
  `nuget.config` was authored from scratch; hosted-revert lockfile restores are
  atomic and mode-preserving (including `bun.lockb`), and a FIFO or symlink
  squatting on a lockfile is refused instead of wedging the revert.
- **Vendor backend parity.** Gem reverts follow every other backend's
  drift-keep rule (genuine drift keeps artifact + ledger entry; converged files
  are silent; a missing `Gemfile`/`Gemfile.lock` warns `vendor_lockfile_missing`
  and still removes the artifact); composer, maven and nuget reverts keep the
  artifact + ledger entry (`kept_artifact`, the `vendor_revert_kept` skip)
  while the live `composer.lock` / `pom.xml` / `nuget.config` still names the
  drift-skipped entry's uuid dir — previously the dir was deleted under a
  `<repository>` / `<add>` that still routed at it — and remove it once
  nothing references it; the golang service leg stages its download
  and, when a re-download of a wired present copy fails, keeps the copy and
  directive instead of tearing them down; poetry/pipenv/requirements refuse
  symlinked targets (`pypi_{poetry,pipenv,requirements}_symlink_unsupported`)
  and every pypi flavor refuses a project file that changed between plan and
  write (`pypi_{poetry,pdm,pipenv,uv}_changed`) instead of clobbering it;
  `pyproject.toml` edits made by `setup` preserve CRLF line endings; an
  unreadable (EACCES / squatting directory or FIFO) redirect ledger is
  reported as unreadable and left in place instead of being quarantined as
  "malformed"; a blob-cleanup pass keeps sweeping after one unremovable file
  and reports the first error afterwards; the ledgers skip byte-identical
  rewrites.
- **Bun refusal safety:** hosted compatibility is checked before removing
  an existing vendored patch, including during dry-run. Vendored preflight
  exemptions require live local lock tuples; a ledger retained by
  `rollback --preserve-state` cannot bypass a refusal or hide it in a preview.
  Symlinked `bun.lockb` files are refused before patching so their links
  survive, and `vendor --silent` keeps refusal diagnostics on stderr.

- **Bun projects: every text-lock generation is accepted, vendored refusals
  fire before any write, and every mode change unwinds.** `bun.lock`
  `lockfileVersion` 0 — the opt-in text lock Bun 1.1.39–1.1.45 write with
  `--save-text-lockfile` — joins 1 and 2 in the shared version gate, so hosted
  mode redirects it (golden fixture `npm/bun/lock-v0`), vendored mode wires it
  and the lockfile inventory discovers it; a newer version is now refused with
  "update socket-patch" instead of a re-lock that would reproduce it. Workspace
  locks are refused only where Bun cannot consume the rewrite: hosted mode
  refuses a version-0 lock holding `workspace:` packages
  (`redirect_bun_workspace_unsupported`; delete `bun.lock` and re-lock with
  Bun ≥ 1.2, which writes version 1 — accepted; a plain in-place
  `bun install` bumps the version only when a workspace depends on another
  workspace, otherwise Bun 1.2.0 keeps version 0 and 1.2.23+ fail to
  resolve) and vendored mode refuses any pre-version-2 workspace lock before
  writing (`vendor_bun_workspace_unsupported` — Bun 1.2–1.3 resolve a
  workspace member's local tarball path relative to the member; delete
  `bun.lock` and re-lock with Bun ≥ 1.4, since an in-place `bun install`
  keeps the existing version, or — for a version-1 lock — use hosted mode; a
  version-0 lock is told to re-lock with Bun ≥ 1.2 first, since hosted
  refuses it too), while purls already vendored (by the ledger at the
  selected uuid, or with every matching lock tuple already pointing into
  `.socket/vendor/`, so a superseding patch uuid re-pins in place), re-runs
  and `repair` on such a lock keep working; a corrupt
  `.socket/vendor/state.json` met by that preflight is reported as
  `vendor_state_unreadable` rather than a Bun lock code. `scan --mode vendored`,
  `get --mode vendored` (search and uuid paths) now
  preflight the Bun lock BEFORE any download: a malformed binary, unreadable,
  unsupported-version or pre-version-2 workspace lock marks the npm patches
  `failed` with the vendor refusal code and detail, fetches nothing and
  records no patch — the `scan` / `get <purl>` path writes nothing under
  `.socket/` and exits `partial_failure`, `get <uuid> --mode
  vendored` exits 1 with `status: "error"` and writes nothing — where
  previously the record landed in the manifest and the vendor step failed
  afterwards (and a detached run over an alias install misreported
  `package_not_installed`). The refusals stay visible under `--silent`
  (code-tagged stderr line), `--dry-run` previews them as the additive
  `would_refuse` action (the human `scan` and `get` previews both print the
  `[would-refuse]` lines). Valid binary locks are inventoried and patched
  directly without a Bun runtime; malformed binary locks report
  `bun_lockb_invalid`, `redirect_bun_lockb_invalid`, or
  `vendor_bun_lockb_invalid` at the corresponding entry point. Hosted → vendored
  takeover now works for bun —
  `scan`/`get --mode vendored` and `vendor` over a hosted-redirected `bun.lock`
  claim and replay that purl's hosted edit instead of refusing
  `redirect_revert_failed`, and `vendor --dry-run` probes the takeover instead
  of promising it — as do `rollback <purl>` / `remove <purl>` of one of
  several hosted bun records; on a lock the vendored backend refuses (a
  pre-version-2 workspace lock) `vendor` and its dry run report the refusal
  BEFORE the hosted revert, leaving the purl hosted-patched instead of
  un-hosting it and then refusing. Native `bun.lockb` edits preserve the
  dependency graph and unrelated package metadata while updating binary
  pointers, tarball integrity, and the package metadata hash. The hosted text
  rewrite keeps CRLF on the rewritten `bun.lock` line. Real-Bun
  coverage now runs in CI: the hermetic hosted and vendored suites on Linux,
  macOS and Windows (Bun 1.4.2, plus 1.1.45 and 1.2.23 lock-era legs), and
  the production native matrix — 16 releases from 0.8.1 to 1.4.2 in hosted
  and vendored mode — on pull requests and `main` (rows
  carry `cliRevision` and `cliBuildSha` provenance), with
  the corrected digest boundary (Bun verifies URL/local tarball sha512 from
  1.3.10, not 1.3.14). Bun 1.1.39–1.3.9 also re-save a hosted URL or
  vendored local-tarball tuple WITHOUT its `sha512` on any later lock
  re-save (`bun add`, `bun install` after a manifest change); that
  digest-less 2-tuple is now recognised as the CLI's own wiring — repeat runs
  heal the digest, `repair` rebuilds through it, and `rollback`, scoped
  `rollback` / `remove`, `vendor --revert` and both mode takeovers unwind it
  to the registry line — where previously every re-save on those releases
  left `redirect_bun_entry_not_found` beside `redirected: 1`, a
  `partial_failure` rollback and `vendor_lock_entry_not_found` /
  `vendor_lock_entry_drifted` refusals. See
  `docs/testing/bun-compatibility.md` and `scripts/backtest-bun.py`. (#245)
- **Rollback after a Pipenv relock no longer refuses forever.** `pipenv lock`
  (and `update`, and `install <other>` before 2024) regenerates a redirected
  or vendored entry to registry shape on every Pipenv major; that is now the
  desired end state — the hosted edit retires and the vendored record is
  dropped (`vendor_lock_entry_relocked`) — instead of a permanent drift
  refusal that held every pypi revert and kept the orphaned wheel dir. A
  foreign `file`/`path` reference is still drift.
- **Same-run `--vex` attests lock-only pypi redirects.** The confirmed purl is
  unqualified while the ledger records the API's artifact-qualified purl;
  both sides now match on the qualifier-stripped purl, so a lock-only Pipenv
  (or uv) checkout no longer exits 1 `no_applicable_patches` after
  redirecting its lock.
- **The Pipenv installer probe runs only when a patch targets the lock**, warns
  only when the lock was actually rewritten, resolves `pipenv` on absolute
  `PATH` entries only (a relative entry would have executed a `pipenv` planted
  in the scanned repository), finds `.bat`/`.cmd` shims on Windows, and takes
  only the token after `version` (never a stray `Python 3.12` banner).
- Hosted Python redirects now warn when installed files still contain upstream
  or modified bytes and omit those packages from same-run VEX. The read-only
  probe covers Poetry virtualenvs, repeats on re-scans, and uses persisted patch
  records if fetching fresh records fails.

- **Agent mode finds Poetry's out-of-tree virtualenv.** Poetry keeps a
  project's virtualenv under `{cache-dir}/virtualenvs/<name>-<hash>-py<X.Y>`
  by default, so after a plain `poetry install` the crawler saw no
  `VIRTUAL_ENV` / `.venv` / `venv` and fell through to the global interpreter:
  `scan --mode agent` patched nothing for the project's dependencies (or the
  wrong interpreter) while reporting success, and a bare `rollback` pruned the
  manifest while the venv stayed patched. The crawler now reproduces Poetry's
  own placement — `virtualenvs.create` / `in-project` / `path` and `cache-dir`
  from `POETRY_*`, the project's `poetry.toml` and the user `config.toml`, the
  platform default cache dir, and Poetry's env-name hash — without running
  Poetry, and scans every `-py<X.Y>` sibling. `poetry run socket-patch …` and
  `VIRTUAL_ENV` keep working as before.
- **`scan --mode vendored` works from a lock-only Poetry checkout.** The
  `poetry.lock` inventory was discovery-only, so a fresh clone with nothing
  installed was skipped with `vendor_fetch_unverifiable` even though the lock
  records the wheel's sha256 (uv's lock vendored fine in the same scenario).
  The inventory now carries the pure-Python wheel's sha256 from `files` (lock
  2.x) or `[metadata.files]` (lock 1.0/1.1), and the pypi fetcher resolves a
  hash-only entry through PyPI's JSON API by that digest (verified again after
  download; `SOCKET_PYPI_JSON_API` overrides the endpoint). Poetry 0.12's bare
  `[metadata.hashes]` names no wheel and still needs an installed copy.
- **`remove` no longer drops the manifest entry of a drift-kept vendored
  purl.** When the vendored revert keeps the artifact (`kept_artifact` —
  the lockfile drifted), the manifest entry is now kept too
  (`skipped`/`vendor_revert_kept`), matching the core RevertOutcome
  contract; previously the entry was deleted, stranding a live ledger
  entry with no backing record. An all-kept run exits 1 `partialFailure`
  with `summary.removed: 0` (never `not_found` — the identifier matched).
- **Rebuilding a missing gem, maven or nuget vendored artifact now updates
  the ledger.** When `vendor` / `scan --vendor` found a wired project whose
  committed artifact was missing or broken, it rebuilt the artifact but kept
  the old fingerprint in `.socket/vendor/state.json` (the gem file
  inventory, the maven/nuget `sha256`, and the nuget `packages.lock.json`
  pin). If the rebuild came from the other source (the patch service instead
  of a local build, or the reverse), the new bytes no longer matched the
  ledger. VEX and verification then reported the artifact as tampered,
  `repair` could fail, and `vendor --revert` left `packages.lock.json`
  pinned to the patched `contentHash`. A rebuild from the patch service was
  also reported as `already_vendored` instead of `applied`. The rebuild now
  records the new fingerprint and keeps the entry's original wiring records,
  so revert still restores the pre-vendor files. If `state.json` has no
  entry for the package, the rebuild still runs but no entry is added,
  because the run has no pre-vendor originals to record.
- **A prebuilt maven `.jar` or nuget `.nupkg` from the patch service must now
  contain the patched files.** Checking its integrity hash only showed that
  the download was intact, not that the archive carried the patch. The
  archive was still written as-is and every file was reported as already
  patched, so an unpatched archive could be committed and then rebuilt on
  every run. Each patched file inside the archive is now checked against the
  patch's expected hash before the archive is used. On a mismatch, `auto`
  builds the archive locally and warns `vendor_prebuilt_layout_mismatch`,
  and `--vendor-source=service` refuses with `vendor_prebuilt_required`.
- **A prebuilt artifact that fails its integrity check is always refused.**
  Under the default `--vendor-source=auto`, npm, pypi, golang, composer and
  gem (both the `.gem` and its stub gemspec) printed a warning and built the
  package locally when the downloaded bytes did not match the integrity the
  patch service reported. Bytes that fail verification may have been
  tampered with, so these ecosystems now refuse the package in every mode,
  as cargo, maven and nuget already did. The refusal code is
  `vendor_prebuilt_integrity_mismatch` (npm fails the package with the
  integrity detail). Under `--vendor-source=service`, golang, composer, gem
  and pypi now report `vendor_prebuilt_integrity_mismatch` instead of
  `vendor_prebuilt_required`.
- **`service` vendor source without an API client is refused.** This affects
  `socket-patch-core` callers that pass a `VendorServiceConfig` with
  `source: Service` and no `client` (the CLI always configures a client).
  Every backend used to build the artifact locally in that case, even though
  `service` promises that only the patch service's artifact is used. They now
  refuse with `vendor_prebuilt_required` before doing any work, the same way
  `--offline` is already refused.
- **Rebuilding a missing cargo vendored copy now honours
  `--vendor-source`.** When a wired project's committed crate copy was
  missing or stale, `vendor` always rebuilt it locally from the installed
  source. Under `--vendor-source=service` it did so even with `--offline`
  or without an API client, and reported success. The rebuild now uses the
  patch service's prebuilt crate like a fresh vendor does, so `service`
  mode refuses (`vendor_service_offline_conflict` / `vendor_prebuilt_required`)
  when the service cannot be used, and `auto` still builds locally when it
  has no prebuilt crate.

### Changed

- **Release publishing decomposed into per-registry workflows.** The
  crates.io, npm, PyPI, and RubyGems legs of the `Release` workflow now live
  in their own workflows
  (`.github/workflows/publish-{cargo,npm,pypi,rubygems}.yml`). A release is
  still one dispatch — `release.yml` dispatches each leg at the release tag
  (`scripts/dispatch-publish.sh`) and watches it to completion — but after a
  mid-release failure any single registry can now also be retried
  standalone (Actions → the registry's publish workflow → Run workflow with
  the release version) without rebuilding: each leg checks out the
  `v<version>` tag and, where binaries are needed, takes them from the
  GitHub release's assets verified against `SHA256SUMS` (release-run
  dispatches additionally pin the sums file by digest, and same-version leg
  runs serialize through a concurrency group). Registry-side
  trusted publishers must be re-registered against the new workflow
  filenames (the legs always run as top-level `workflow_dispatch` runs, so
  every registry's filename matching sees the leg's own file) — see
  docs/releasing.md § One-time registry setup.

## [4.0.0] — 2026-08-20

v4.0 is the three-modes release. What began as an agent-style tool that
patches installed packages in place now offers three deployment modes,
selected with `scan --mode <agent|vendored|hosted>` (each mode's detailed
entries follow below; per-ecosystem mechanics live in `docs/ecosystems.md`):

- **Agent mode** (the default, and the original behavior): `apply` patches
  installed packages in place on the current machine — `node_modules/`,
  site-packages, the cargo registry cache, and so on — tracked in the local
  `.socket/` manifest and re-applied after installs by the hooks `setup`
  configures. Requires socket-patch (and Socket API access, or pre-fetched
  blobs) on every machine that installs dependencies.

- **Vendored mode** (`vendor`, or `scan --mode vendored`): ejects each
  patched package into a committed
  `.socket/vendor/<ecosystem>/<patch-uuid>/<artifact>` and rewires the
  ecosystem's lockfile so the project consumes the vendored copy. After
  committing, a fresh checkout builds with the patched dependency on
  machines with no socket-patch installed and no Socket API access — fully
  offline/airgap-friendly, and the strictest install flags (`npm ci`,
  `--frozen-lockfile`, `--locked`, `--deploy`, …) verify the vendored
  artifact like any other. A committed ledger records the verbatim original
  lockfile fragments, so `vendor --revert` restores them byte-exactly.
  Covered in v4.0: the whole npm family (npm, yarn classic, yarn berry
  node-modules, pnpm, bun), pypi (uv, requirements, poetry, pdm, pipenv),
  cargo, go, composer, gem, maven, and nuget.

- **Hosted mode** (`scan --mode hosted`, new in v4.0): rewrites lockfiles /
  registry configs so ONLY the patched dependencies resolve to
  Socket-hosted, integrity-pinned artifacts on patch.socket.dev — no
  artifact bytes land in the repo and no CI changes are needed. The package
  manager's own integrity checking pins the patched bytes (tamper fails the
  native install), and re-runs are idempotent. Covered in v4.0: the npm
  family (package-lock/shrinkwrap, pnpm — including Rush monorepos — yarn
  classic, yarn berry, bun), pypi (requirements, uv), cargo, composer, gem,
  nuget, maven (fail-closed version suffixing + Trusted Checksums), and
  golang for references carrying a `goproxy` registry override (free tier;
  otherwise Go stays vendored — see the documented NO-GO analysis).

All three modes feed VEX attestation, with a provenance marker per mode:
plain (agent), `(vendored)`, and `(redirected)` (hosted).

### Removed (BREAKING)

- **The `unlock` subcommand.** Folded into `repair`, which now deletes the
  leftover `<.socket>/apply.lock` file as its final housekeeping step (skipped
  under `--dry-run`, refused with `lock_held` while another live socket-patch
  process holds the lock). Rationale: a leftover lock file from a crashed run
  never blocked acquisition in the first place — the OS releases a dead
  holder's advisory lock along with its file handle — so `unlock`'s inspect
  path had no recovery scenario, and its `--release` file deletion is now
  automatic. Migration: `unlock --release` → `repair`; the probe-style
  "is anything holding the lock?" check → run the mutating command (optionally
  with `--lock-timeout`) and branch on `errorCode: lock_held`.
  `SOCKET_UNLOCK_RELEASE` is gone with the subcommand, and the
  `patch_unlocked` / `patch_unlock_failed` telemetry events are retired.
- **The global `--break-lock` flag and `SOCKET_BREAK_LOCK` env var.** It never
  stole a live holder's lock (deliberately, since that defeats mutual
  exclusion) and a stale file never contends, so all it did was emit a
  `lock_broken` audit event for a reclaim that plain acquisition performs
  anyway. The `lock_broken` warning event and rollback's `warnings[]`
  `lock_broken` entry are no longer emitted (`warnings` stays present, now
  always empty). The `lock_held` stderr hint now advises waiting /
  `--lock-timeout` instead of pointing at the removed commands.

### Changed (BREAKING)

- **`--help` command order** is now workflow-first: `scan`, `apply`, `vex`,
  `vendor`, `setup`, then `rollback`, `get`, `list`, `remove`, `repair`.

### Added

- **`get --mode <hosted|vendored|agent>` — per-advisory hosted/vendored
  patching.** `get` (fetch/apply a single patch by CVE/GHSA id, patch UUID,
  or package name) now honors the same mode selector as `scan`: hosted
  rewrites lockfiles for just the selected patches through scan's redirect
  engine verbatim; vendored routes through scan's vendor step with scan's
  save-only download posture. CVE/GHSA fan-outs are narrowed to versions
  actually installed (disk ∪ manifest, plus the lockfile inventory and
  vendor ledger in hosted/vendored modes); when narrowing leaves nothing,
  the new additive `not_installed` status reports it at exit 0. Exempt from
  narrowing: UUID ids, exact-versioned purls, `--save-only`,
  `--all-releases`, and the package-name path.
- **Hosted mode for Go (free tier).** `scan --mode hosted` now redirects
  golang dependencies when the reference carries a `goproxy` registry
  override: a fork-style
  `replace <mod> <ver> => patch.socket.dev/gopatch/<uuid> <ver>-socketpatch.<n>`
  in `go.mod` plus the socket module's two `h1:` lines in `go.sum` (and the
  replaced original's lines pruned — the tidy-stable state). Day-2 machines
  need no configuration: go consults the checksum database only for modules
  absent from `go.sum`, so the committed pair is the whole redirect —
  validated end-to-end in `e2e_golang_hosted_build.rs` (fresh caches, bogus
  `GOSUMDB` tripwire, `go mod tidy` byte-level no-op, tampered-hash
  `SECURITY ERROR`). Fails closed (per-dep `redirect_golang_*` warnings, no
  partial writes) on missing hashes, an out-of-namespace module path, a
  require-version mismatch, or a user-authored replace conflict; references
  without the override keep the historical `redirect_golang_unsupported`
  warning (paid tier stays vendored — see `docs/design/golang-hosted.md`).
  Wire schema gains `integrity.goModH1` and
  `registryOverride.identifiers.goModuleVersion` (additive). Requires
  server-side publication of the grant-free `gopatch` artifact flavor —
  production publishes no golang hosted modules yet, so behavior is unchanged
  until it does.
- **Version-bump automation + release-readiness gate.**
  `scripts/bump-version.sh <X.Y.Z> --pr` performs the whole bump chore —
  stamps every packaging site via `version-sync.sh`, rolls `[Unreleased]`
  into a dated `## [X.Y.Z]` CHANGELOG section, and opens the `release/vX.Y.Z`
  PR (also dispatchable from the Actions tab as the **Version Bump**
  workflow). A new `release-readiness` CI job runs `scripts/release-lint.sh`
  on every PR: version-coherence always (version-sync must be a no-op, so a
  hand-edited version in any one packaging site fails CI), plus the full
  gate — non-empty CHANGELOG section, no pre-existing tag — on PRs that bump
  the workspace version. The `Release` workflow's `version` job now runs the
  same script, so the publish gate and the PR gate cannot drift. Playbook:
  docs/releasing.md.
- **`socket-patch --update` — self-update.** Downloads the release for the
  compiled target from GitHub Releases, verifies it against the published
  `SHA256SUMS` before extraction, sanity-execs the staged binary, and
  atomically swaps it in place (Windows uses the rename-dance via
  `self-replace`; a setuid/setgid install is refused). `--update 3.4.0`
  (or `SOCKET_PATCH_VERSION`) pins a version, up or down; bare `--update`
  never downgrades; `--force` reinstalls. `--dry-run` is a check-only
  probe (zero downloads, `updateAvailable` in the `--json` details).
  Package-manager-managed installs (npm, pip, cargo, the gem launcher
  cache, Homebrew) are detected from the canonicalized executable
  path and refused with that manager's own upgrade command; `--force`
  overrides. `--offline` refuses up front and `--force` cannot bypass it.
  Concurrent updates are single-flighted via an advisory lock; every
  failure path leaves the installed binary untouched.
- **Passive update notice.** Interactive runs mention a newer release at
  most once a day, on stderr only, after the command's own output:
  suppressed under `--json`/`--silent`/`--offline`, in CI, when stderr is
  not a terminal, or with `SOCKET_NO_UPDATE_CHECK=1` (suppressed means
  zero network I/O). The background check can never alter a command's
  exit code, stdout, or add more than ~500 ms; state corruption degrades
  to "never checked". An explicit `--update` refreshes the notice's cache.
- **`shellcheck scripts/install.sh` in CI** (and a fix for the SC2144
  glob-with-`-e` musl-loader probe it found).
- **`socket login` now configures socket-patch.** The JS Socket CLI's
  persisted config (`<data dir>/socket/settings/config.json`) is read —
  never written — as a fallback layer below env vars for `apiToken`,
  `defaultOrg`, and `apiBaseUrl`: precedence per key is CLI flag > env var
  > socket-cli config > built-in default. Four `SOCKET_CLI_*` env names
  are accepted as silent peer aliases (`SOCKET_CLI_API_TOKEN`,
  `SOCKET_CLI_ORG_SLUG`, `SOCKET_CLI_API_BASE_URL`,
  `SOCKET_CLI_NO_API_TOKEN`); the canonical `SOCKET_*` names win. Two new
  env-only toggles: `SOCKET_NO_API_TOKEN` ignores ambient tokens (env +
  config; an explicit `--api-token` still authenticates) and
  `SOCKET_NO_CONFIG` disables the config layer. A corrupt config file
  warns once on stderr and is ignored; `--json` stdout is unaffected. The
  telemetry endpoint now resolves the API base through the same chain as
  client construction, so a config-supplied `apiBaseUrl` applies to both.
  Design notes: `docs/design/configuration.md`.


- **Hosted patch mode: `scan --mode hosted` (a.k.a. the hidden `--redirect`).**
  The third patch-application mode: instead of applying in place (agent) or
  committing artifacts (vendored), `scan` rewrites lockfiles / registry
  configs so ONLY the patched dependencies resolve to Socket-hosted,
  integrity-pinned packages on patch.socket.dev — no artifact bytes land in
  the repo and no CI changes are needed. Per ecosystem: npm rewrites
  `package-lock.json`/`npm-shrinkwrap.json` `resolved`+`integrity` (v2 legacy
  `dependencies` mirror included), `pnpm-lock.yaml` inline resolutions, and
  yarn classic `resolved`/`integrity` blocks; pypi rewrites `requirements.txt`
  pins to `name @ <url> --hash=sha256:…` (pip-compile continuation lines are
  refused rather than corrupted) and `uv.lock` wheel entries; cargo defines a
  per-patch sparse registry in `.cargo/config.toml` plus `Cargo.toml`
  `registry =` keys and Cargo.lock `source`/`checksum` surgery; composer
  rewrites the lock entry's `dist` url/shasum; nuget adds a `nuget.config`
  source + `packageSourceMapping` and repins `packages.lock.json`
  `contentHash`; gem adds a per-dep `source` block + a `CHECKSUMS` pin
  (bundler ≥ 2.6). A dep counts as redirected only when its hosted URL (or
  per-dep registry index) actually landed in a project file; re-runs are
  idempotent (zero new edits over already-rewritten output). The Rust
  rewriters are held byte-identical to the depscan backend's TS twins (the
  GitHub-app hosted PR flow) by shared golden fixtures under
  `tests/fixtures/redirect/`. JSON output gains a `redirect` sub-object with
  `mode: "hosted"`, `redirected`, `rewrittenFiles`, `skipped`, `warnings`.
- **`scan --mode <hosted|vendored|agent>`: the documented mode selector.** One
  value-enum flag replaces the boolean spellings (`--redirect` == hosted,
  `--vendor` == vendored, `--apply`/`--sync` == agent), which remain supported
  as aliases. Combining `--mode` with a boolean of a DIFFERENT mode is a
  usage error (exit 2); the same mode spelled both ways is accepted, and
  `--detached` now requires vendored mode in either spelling.
- **VEX support for hosted mode: the `(redirected)` provenance marker + the
  redirect ledger.** `scan --mode hosted` persists its recorded file edits and
  the full patch records (file hashes + vulnerabilities) into
  `.socket/vendor/redirect-state.json` (merge-on-rewrite, append-only edits —
  the pre-redirect originals a future revert needs are never clobbered).
  Redirected patches carry the impact-statement marker "Patched via Socket
  patch `<uuid>` (redirected)", completing the provenance trio (plain =
  agent, `(vendored)`, `(redirected)`). In-run `scan --mode hosted --vex`
  attests confirmed redirects from the ledger WITHOUT hash verification (the
  bytes are fetched at install time; the JSON `vex` summary carries
  `verified: false`), while a post-install `socket-patch vex` reads the ledger
  back and hash-verifies the redirected patches against the installed tree.
  A confirmed redirect whose record fetch failed surfaces a
  `record_fetch_failed` warning (the patch is missing from VEX until a
  re-run).
- **NuGet + Maven vendor backends (`vendor` / `scan --mode vendored`).**
  NuGet: the uuid dir is a committed *folder feed* holding a deterministically
  rebuilt `.nupkg` (embedded signature dropped; unsigned is accepted under
  NuGet's default validation), wired via a `nuget.config` source +
  `packageSourceMapping` and a `packages.lock.json` `contentHash` repin —
  `dotnet restore --locked-mode` then fails NU1403 on tamper. Maven: the uuid
  dir is a committed *maven2 `file://` repository* (rebuilt `.jar` + the
  verbatim upstream pom so transitives survive + `.sha1` sidecars), wired via
  a `pom.xml` `<repository>` with `checksumPolicy=fail`; multi-module
  aggregator poms (`vendor_maven_multimodule_unsupported`) and gradle-only
  projects (`vendor_gradle_unsupported`) are refused fail-closed, and the
  always-on `vendor_maven_local_cache_shadow` advisory carries the
  `mvn dependency:purge-local-repository` one-liner (a warm `~/.m2` copy
  silently shadows any repository). Both are proven by docker capstones
  against the real .NET SDK / Apache Maven (cold-cache, `--network none`,
  RED + TAMPER probes). `nuget` and `maven` are now DEFAULT compile features;
  the `SOCKET_EXPERIMENTAL_NUGET` / `SOCKET_EXPERIMENTAL_MAVEN` runtime
  opt-ins that briefly gated in-place agent apply were retired later in this
  cycle (see the "promoted to fully available" entry under Changed). The vendored
  path convention + uuid recovery rule now covers `nuget` and `maven` dirs,
  and `--vendor-source` prebuilt downloads cover nuget.
- **Maven hosted rewriter (pom projects) — fail-closed version suffixing +
  Trusted Checksums.** Hosted mode's maven leg pins the patched jar the only
  way a lockfile-less ecosystem can: the serve route exposes the patch under a
  Socket-only `<version>-socket.<hex8>` suffix (existing ONLY on the injected
  `socket-patch-<uuid>` repository), and the rewriter pins that version
  explicitly — it rewrites the literal `<version>`, or (for a transitive /
  managed dependency with no literal version) adds a `<dependencyManagement>`
  entry — alongside the `<repository>` insert (releases enabled,
  `checksumPolicy=fail`, snapshots disabled). An outage or tamper on the Socket
  repo then HARD-FAILS the build: the suffixed version resolves nowhere else,
  so there is no silent fall-through to Central (the base version 404s). A
  `${property}` version is refused (`redirect_maven_dep_unpinned` — a literal
  edit would break the reference and a depMgmt pin could strand sibling
  artifacts); a literal version matching neither the base nor the suffixed
  value is skipped (`redirect_maven_dep_version_mismatch`); a non-jar `<type>`
  is skipped (`redirect_maven_unsupported_packaging`). When the serve route
  supplies both the jar and pom sha256, the rewriter also emits Maven 3.9+
  Trusted Checksums files — `.mvn/maven.config` resolver args (`originAware=false`,
  `failIfMissing=false`) + `.mvn/checksums/checksums.sha256` entries pinning
  both artifacts under the suffixed version's local-repo path, merging into any
  pre-existing user config / checksum set (a conflicting value is never
  overridden — `redirect_maven_trusted_checksums_conflict`). The `.mvn/*` files
  are silently inert below Maven 3.9 (the version suffixing is still fail-closed
  on its own); on 3.9.0–3.9.8 a mismatch is enforced but reported unclearly
  (readability fixed in 3.9.9, MNG-8182). When the upstream pom is unavailable /
  unsuffixable the rewriter falls back to the legacy same-GAV repository
  injection with a `redirect_maven_same_gav_fallback` warning (NOT fail-closed:
  a Socket-repo failure falls back to the unpatched artifact). Gradle build
  scripts are never edited: a present `build.gradle*` / `settings.gradle*`
  emits a paste-able `exclusiveContent` snippet carrying the suffixed version
  (`redirect_gradle_manual_snippet`) plus a reminder to bump the dependency
  declaration — fail-closed by repository exclusivity.
- **Hosted mode now rewrites yarn-berry and bun lockfiles.** The hosted npm
  family gains two flavors beyond package-lock / pnpm / yarn-classic. **yarn
  berry** (`__metadata:` v2+ lock): the rewriter edits ONLY the lock entry —
  `resolution:` gains yarn's own `::__archiveUrl=<encodeURIComponent(url)>`
  binding and `checksum:` becomes the precomputed `yarnBerry10c0` cache-zip
  sha512 — leaving the descriptor key and `package.json` untouched, so `yarn
  install --immutable --check-cache` passes and tamper fails YN0018. Whole-file
  gates refuse a `cacheKey ≠ 10c0` or a `.yarnrc.yml compressionLevel ≠ 0`
  (`redirect_yarn_berry_cache_unsupported`) — no offline-reproducible checksum.
  Validated e2e against real `corepack yarn@4.12.0` on the node-modules linker;
  PnP is not exercised for hosted (the lock rewrite fires, but PnP's
  `.yarn/cache` resolution is untested). **bun** (text `bun.lock` v1): the
  packages-entry registry 4-tuple `["name@ver","<reg>",{deps},"sha512-…"]` is
  rewritten to a URL 3-tuple `["name@<url>",{deps},"sha512-…"]`, fail-closed on
  any grammar deviation; `bun install --frozen-lockfile` then installs the
  hosted bytes and tamper fails the integrity check. A binary `bun.lockb` with
  no text lock is auto-migrated first via the user's own `bun install
  --save-text-lockfile --frozen-lockfile --lockfile-only` (deletes `bun.lockb`,
  recorded as a `removed` ledger edit, offline, fails closed;
  `redirect_bun_lockb_would_migrate` on `--dry-run`,
  `redirect_bun_lockb_unsupported` if the migration is unavailable). The Rust
  rewriters are byte-identical to the depscan backend's TS twins via shared
  golden fixtures.
- **Hosted mode supports Rush monorepos.** A Rush repo has no root
  `package.json`/lockfile pair — its pnpm source-of-truth lock lives at
  `common/config/rush/pnpm-lock.yaml` (plus one per subspace under
  `common/config/subspaces/<name>/`). `scan --mode hosted` discovers those
  locks when `rush.json` is present and repoints them in place (the pnpm
  rewriter is now basename-generalized, so nested locks rewrite path-generically).
  Editing a Rush lock outside `rush update` desyncs the `pnpmShrinkwrapHash` in
  `common/config/rush/repo-state.json`, so a `redirect_rush_repo_state_stale`
  warning fires when a lock was touched and that file exists — `rush install`
  fails under `preventManualShrinkwrapChanges` until `rush update` refreshes it,
  but the redirect survives the refresh (pnpm keeps locked resolutions for
  unchanged specifiers). Agent mode already works through Rush's generated
  project symlink farm; vendored mode is refused (`vendor_rush_unsupported`)
  because `rush install` copies the lock into `common/temp`, so vendor's
  relative `file:` specs can't survive — the refusal routes to hosted mode.
- **pnpm hosted rewriter generalized to nested lockfiles.** The
  `pnpm-lock.yaml` rewriter now matches any `pnpm-lock.yaml` at the project
  root OR at any nested path (`*/pnpm-lock.yaml`), so Rush subspace locks and
  other nested-lock layouts are rewritten in place under their repo-relative
  keys. Write-back and confirmed-redirect gating are path-generic.
- **Golang hosted mode is a documented NO-GO.** Hosted redirect for Go is
  deliberately unsupported — sumdb hard-fails the patched pseudo-version on
  every day-2 machine and the only escapes are uncommittable machine-local
  config; Go's module-path identity would force per-grant artifacts against
  the build-once converter; and the default `GOPROXY` chain would leak
  licensed bytes / tokened URLs to the public mirror. The full analysis lives
  in `docs/design/golang-hosted-no-go.md`; both the CLI rewriter and the
  depscan backend twin emit `redirect_golang_unsupported` naming the remedy
  (use vendored mode, which gives Go everything hosted promises elsewhere).
  The one sanctioned exception — an ephemeral-CI GOPROXY recipe — is
  documentation-only and never written into a repository.

- **`vendor` now supports every major npm and pypi package manager.** The npm
  ecosystem gained four lockfile flavors beyond `package-lock.json` — yarn
  classic (`yarn.lock` v1), yarn berry with the node-modules linker
  (`resolutions` + a cache-zip `10c0` checksum reproduced offline from the
  vendored tarball), pnpm (`pnpm.overrides` + `pnpm-lock.yaml` surgery, pnpm 9
  & 10), and bun (`bun.lock`) — all sharing the one vendored tarball and
  selected by a content-sniffing probe (yarn-berry PnP and bun's binary
  `bun.lockb` are refused with pointers to the native flow). The pypi
  ecosystem gained poetry, pdm, and pipenv (lock-only `[[package]]` / entry
  splices, like the existing uv/requirements flavors). Every lockfile
  checksum/reference field for a vendored package is now recomputed
  coherently (the v2 "update checksums and references" directive); the gem
  backend handles bundler ≥ 2.6's optional `CHECKSUMS` section; composer's
  `dist.reference` carries the patch UUID into `installed.json`. Each flavor
  has a real-package-manager build-proof capstone (fresh-checkout, cold-cache,
  strictest-install — `--frozen`/`--immutable`/`--deploy`/`--locked` — with
  byte-identical revert). `vendor --force`/`--revert` accept empty env vars
  (`SOCKET_FORCE=`) as false, matching the global-flag contract.

- **New `vendor` subcommand: committable vendoring of patched dependencies.**
  Where `apply` patches installed packages in place (machine-local state),
  `socket-patch vendor` ejects each patched package into a committed
  `.socket/vendor/<ecosystem>/<patch-uuid>/<artifact>` and rewires the
  ecosystem's lockfile so the project consumes the vendored copy — after
  committing, a fresh checkout builds with the patched dependency on machines
  with no socket-patch installed and no Socket API access. Per ecosystem
  (each mechanism validated against the real package manager): npm rewrites
  `package-lock.json` only (deterministic patched tarball, recomputed
  integrity, `npm ci`-verified); cargo writes a `[patch.crates-io]` entry in
  `.cargo/config.toml` plus surgical Cargo.lock edits so `cargo build
  --locked --offline` works; golang reuses the `replace`-directive engine
  pointed at the vendor tree; composer rewrites the lock entry to a
  `dist: path` copy; gem edits the Gemfile + Gemfile.lock pair in bundler's
  canonical form; pypi rebuilds a valid wheel (regenerated RECORD) wired
  through uv's `pyproject.toml`/`uv.lock` pair (uv-first) or
  requirements.txt (`pip` / `uv pip`). The patch UUID is recoverable from the
  lockfile path string alone (a documented convention for external tools), a
  committed `.socket/vendor/state.json` ledger records the verbatim original
  lockfile fragments, and `vendor --revert` restores them byte-exactly.
  `vendor --vex` mirrors `apply --vex`; VEX generation attests vendored
  patches by hashing the committed artifacts, and `apply` yields ownership of
  vendored packages (`vendored` skip reason).


- **Cargo support (`cargo` is now a default feature).** `apply` patches a Rust
  dependency **in place** wherever the crawler finds it — the project `vendor/`
  directory or the shared `$CARGO_HOME` registry cache — rewriting the crate's
  `.cargo-checksum.json` sidecar so `cargo build` accepts the modified files.
  `rollback` restores the original bytes from the `beforeHash` blobs, like
  npm/PyPI/gem. `cargo` ships on by default (alongside the always-on npm + PyPI
  + Ruby gems support), so released binaries and a plain `cargo install
  socket-patch-cli` patch Rust dependencies out of the box;
  `maven`/`composer`/`nuget`/`deno` remain opt-in.
- **Project-local Go `replace`-redirect backend (`golang`, default feature).**
  The Go module cache is shared, read-only and checksum-verified, so in-place
  patching would fail `go.sum` at build time. Instead `apply` writes a
  project-local patched **copy** under `.socket/go-patches/<module>@<version>/`
  and a managed `replace` directive in the project `go.mod`, so the patch is
  project-scoped and the cache stays pristine for sibling projects. `rollback`
  cleanly drops the `replace` directive + copy. `apply --check` is a read-only,
  lock-free, offline auditor that verifies the committed redirects match the
  manifest, exiting non-zero on drift (for CI / GitHub-App use).
- **Inline OpenVEX generation on `apply` and `scan` via `--vex <path>`.** A
  single successful `apply`/`scan` can now both patch and emit the OpenVEX
  0.2.0 attestation, instead of requiring a separate `socket-patch vex` step.
  The `--vex-product` / `--vex-no-verify` / `--vex-doc-id` / `--vex-compact`
  flags mirror the standalone `vex` knobs (and reuse the `SOCKET_VEX_*` env
  vars). The document is always written to the given path (never stdout, so it
  never races `--json`), built from the post-run manifest and verified against
  on-disk state. JSON output gains a top-level `vex` summary
  (`{ path, statements, format }`). A requested-but-failed VEX makes the
  command exit non-zero even when the apply/scan itself succeeded, surfacing a
  stable error code in the envelope.

### Changed

- **`install.sh` can install without reaching github.com.** New
  `SOCKET_PATCH_BASE_URL` points the archive downloads at any releases base that
  answers GitHub's two asset paths — notably
  `https://install.socket.dev/patch/SocketDev/socket-patch/releases`, which relays them
  from the GitHub release, so one URL template covers either origin. A new
  release needs no publish for this: the origin resolves "latest" per request.
  `socket-patch --update` can use the same host today through the
  `SOCKET_UPDATE_BASE_URL` override it already has. Also new:
  `SOCKET_PATCH_INSTALL_DIR` to choose the install directory explicitly instead
  of taking `/usr/local/bin` or `~/.local/bin`. The default download origin is
  still GitHub — see `docs/installer-hosting.md`.

- **The documented one-liner installs from `https://install.socket.dev/patch`.**
  The previous URL was `raw.githubusercontent.com`, which asks users to trust a
  third-party CDN for a script they pipe into a shell and is the first URL a
  locked-down egress policy blocks. The hosted copy is byte-for-byte
  `scripts/install.sh`, with its SHA-256 published at
  `install.socket.dev/patch.sha256`; the GitHub raw URL keeps working and serves
  the same bytes. Binaries are still downloaded from the GitHub release and
  verified against its `SHA256SUMS` — the trust model is unchanged, only the
  script's origin moved. New: `docs/installer-hosting.md` (how the copy is
  published), a CI step that runs the installer end to end instead of only
  linting it, and an `installer-drift` workflow that checks the hosted copy
  against this repository weekly.

- **Maven and NuGet promoted to fully available — the
  `SOCKET_EXPERIMENTAL_MAVEN` / `SOCKET_EXPERIMENTAL_NUGET` runtime gates
  are retired.** Every flow (`scan` in all modes, `apply`, `get`,
  `rollback`, `vendor`, `repair`, `vex`, `setup`) now discovers and
  patches installed Maven and NuGet packages unconditionally; the
  "N patch(es) skipped — support is experimental" warnings are gone, and
  the previously `#[ignore]`d maven/nuget dispatch e2e tests now gate CI.
  Setting the old env vars is harmless but does nothing. Behavior notes:
  a default `scan` now walks the local Maven repository (`~/.m2` /
  `MAVEN_REPO_LOCAL`) and the NuGet caches, and `scan --prune`/`--sync`
  now judges maven/nuget manifest entries like any other ecosystem's
  (previously they were exempt from pruning while the gate was closed).
  The in-place sidecar caveat is unchanged and now documented per mode in
  `docs/ecosystems.md`: agent-mode patching leaves Maven's
  `.jar.sha1`/`.jar.md5` stale and NuGet's fixup deletes
  `.nupkg.metadata` + advises on `.nupkg.sha512`; the vendored/hosted
  modes never touch the caches.

- **Release workflow consolidated into a single `release.yml`.** One
  dispatch now publishes every package — crates.io, npm, PyPI, and
  RubyGems (both gems), all via OIDC trusted publishing — with the
  launcher-gem job gated on the GitHub release existing. The separate
  `release-ecosystems.yml` workflow is removed (its `release: published`
  trigger never fired: the release is created with `GITHUB_TOKEN`, which
  suppresses downstream workflow events). The CLI is distributed via
  GitHub releases, npm, PyPI, crates.io, and RubyGems only — the
  Composer/Packagist, Maven Central, and NuGet launcher channels drafted
  earlier in this cycle were dropped before ever shipping in a release.
- `--api-url` / `--proxy-url` no longer carry clap-level defaults: with
  neither flag nor env var set they parse as unset and the documented
  default URLs are applied at API-client construction (after the
  socket-cli config layer). Observable behavior is unchanged unless a
  socket-cli login exists.
- **All ecosystem feature flags removed — every ecosystem is always compiled
  in.** The `cargo`, `golang`, `maven`, `composer`, `nuget`, and `deno` Cargo
  features are gone from both crates; npm, PyPI, Ruby gems, Go, Cargo, NuGet,
  Maven, Composer, and Deno support is now unconditional. Builds that passed
  `--features <eco>` will get an "unknown feature" error and should simply
  drop the flag; `--no-default-features` no longer produces a minimal binary
  (there is nothing left to strip). The `SOCKET_EXPERIMENTAL_MAVEN` /
  `SOCKET_EXPERIMENTAL_NUGET` runtime gates outlived this entry only briefly —
  they are retired in the same release (see the "promoted to fully available"
  entry under Changed). The only remaining features are the
  test-suite gates `docker-e2e` and `setup-e2e` on `socket-patch-cli`. (MAJOR
  for anyone scripting `--features`; no behavior change for default builds
  beyond composer/deno support now being present.)

- **Token-less `scan` now batch-queries the public proxy.** Proxy-mode scans
  POST `{proxy}/patch/batch` (one request per `--batch-size` chunk, mirroring
  the authenticated `/v0/orgs/{slug}/patches/batch` endpoint) instead of
  issuing one `GET /patch/by-package/:purl` per package. The client
  transparently degrades to the legacy per-package GET path against proxies
  that predate the batch endpoint, and when the all-or-nothing batch
  validation rejects a chunk (e.g. a crawled PURL type the server doesn't
  recognize, such as `pkg:jsr/…` — per-package queries tolerate those
  individually, so one exotic package can't fail a whole scan). Rate limits
  and over-capacity 503s still surface instead of silently degrading. (MINOR)

### Fixed

- **bun 1.4 lockfiles are accepted again.** bun 1.4.0 bumped `bun.lock`
  `lockfileVersion` to 2 while leaving the emitted grammar unchanged; the
  shared version gate refused everything but 1, so hosted and vendored
  modes refused every lock written by bun ≥ 1.4
  (`redirect_bun_lock_unsupported` / `vendor_lockfile_version_unsupported`).
  The gate now accepts versions 1 and 2 and keeps failing closed on
  anything else; new shared golden fixture `npm/bun/lock-v2` (the depscan
  TS twin needs the matching acceptance + fixture sync).
- **gem: every coexisting installed copy is patched.** Bundler's scoped
  `<engine>/<abi>/gems` and flat `gems/` stores can coexist under one
  `BUNDLE_PATH` root, each holding a real copy of the same gem@version;
  first-wins resolution patched one store and reported success while the
  other bundler loaded pristine (vulnerable) bytes. `apply` now fans out
  per copy (per-copy `Applied` events, each counted in `summary.applied`),
  bundle-path roots are crawled in bundler precedence order, and
  config-sourced roots are contained. The `gem_bundle_config_path_ignored`
  warning also prints the skipped path verbatim instead of
  backslash-escaped.
- **npm `@socketsecurity/socket-patch`: the `./schema` export is now built
  at publish.** The subpath pointed at a gitignored `dist/` directory that
  nothing built during release, so it shipped broken; a `prepack` script
  now compiles it as part of `npm publish`.
- **Release workflow tag-guard and idempotency fixes.** The
  tag-already-exists guard never fired (it ran `git rev-parse` in a
  shallow, tagless checkout) — it is now a stateless `git ls-remote` check
  that still permits same-commit retries; the GitHub-release step re-runs
  cleanly instead of hard-failing when the release already exists; and the
  cargo/PyPI/gem publish jobs skip already-published versions, so
  "Re-run failed jobs" can resume a partial release safely.
- **NuGet hosted rewriter: creating a `packageSourceMapping` from scratch now
  emits a catch-all for pre-existing sources.** `packageSourceMapping` is
  exclusive — once ANY mapping exists, every package must match some source's
  pattern or restore hard-fails NU1100. A redirect into a `nuget.config` with
  no prior mapping previously routed only the patched id, breaking every
  OTHER package's restore; the rewriter now fans a `<package pattern="*" />`
  mapping out to each pre-existing package source (longest-prefix match still
  routes the patched id to the Socket source). Golden fixtures updated on
  both the Rust and TS sides.

- **VEX now attests Go `replace`-redirect patches.** `socket-patch vex`
  previously verified golang patches against the pristine module cache
  instead of the patched `.socket/go-patches/` copy, so redirect-applied
  patches were silently omitted from the document (reported `not_applied`,
  or `package_not_found` on cache-less CI). Verification now follows the
  managed `replace` directive to the committed copy.

- **`repair` on a hosted-only project is an informational no-op.** Hosted
  (`--mode hosted`) mode leaves no local artifacts to repair — the lockfiles
  point at `patch.socket.dev` URLs, and there is no manifest or vendor ledger.
  A project whose only `.socket/` trace is `redirect-state.json` (no manifest,
  no vendor ledger, no vendored lockfile references) previously errored with
  `manifest_not_found` (exit 1); it now exits 0 with a `redirect_only_project`
  skip pointing at `scan --mode hosted`. Repair still errors on a bare
  directory with no traces at all.

## [3.2.0] — 2026-05-29

A repo-wide correctness, security, and filesystem-safety hardening pass: every
source file in both crates was reviewed line by line, the bugs found were fixed,
and regression tests were added throughout (the lib + integration suites grow by
~10k lines of mostly tests). The audit harness used to drive the review lives in
`scripts/study-crates.ts`.

### Security

- **Path-traversal in archive extraction.** `read_archive_to_map`
  (`patch/package.rs`) validated the raw tar entry path but returned the
  `package/`-stripped path, so an entry like `package//etc/passwd` passed every
  check and then resolved to an absolute `/etc/passwd` that `Path::join`
  writes outside the package tree. Validation now runs on the normalized path
  actually written to disk.
- **Unbounded preallocation from an untrusted delta header.** `apply_diff`
  (`patch/diff.rs`) reserved a `Vec` sized from the bsdiff target-size header,
  which qbsdiff never validates — a tiny hostile delta could claim up to
  `i64::MAX` and abort the process. The hint is now clamped to 64 MiB.
- **Evidence-free VEX attestation.** `verify_patch_record` (`vex/verify.rs`)
  returned `applied` for a patch touching zero files, producing a
  `not_affected` statement with no on-disk evidence; zero-file records are now
  omitted (`no_files`).

### Fixed — filesystem safety, atomicity & rollback

- **`apply` could not write into read-only directories** (Go module cache marks
  dirs `0o555`); added a `DirWriteGuard` that temporarily grants write on the
  parent dir around the CoW-break + atomic rename and restores its exact mode.
- **`apply` stripped setuid/setgid bits** on every patched file because `chown`
  ran after `chmod`; reordered to chown-before-chmod, plus a parent-dir `fsync`
  so the rename survives a crash.
- **Non-atomic symlink break** (`patch/cow.rs`) removed the file before staging
  its replacement, destroying it with no rollback on a failed write; now
  rename-over the link, matching the hardlink path. Stage files are cleaned up
  on every error arm.
- **`rollback` used an unsafe in-place write**; it now delegates to the hardened
  `apply_file_patch` (atomic, CoW-safe, validate-before-write, permission
  restore). Also: a GC'd before-blob no longer shadows the already-original
  short-circuit, and new-file deletion works inside read-only directories.
- **Hash integrity:** `compute_file_git_sha256` (`patch/file_hash.rs`) opened
  and stat'd the path separately (TOCTOU) and never checked the target was a
  regular file (a directory hashed as the empty blob); now opens once, fstats
  the descriptor, and rejects non-regular files. `compute_git_sha256_from_reader`
  now errors when the streamed byte count disagrees with the declared size.
- **Sidecar writes in read-only caches:** the cargo `.cargo-checksum.json`
  rewrite and the NuGet `.nupkg.metadata` delete used bare, non-atomic I/O that
  failed `EACCES` in the locked-down registry trees they exist to serve; both
  now go through the hardened write/`DirWriteGuard` paths.
- **Blob cleanup** (`utils/cleanup_blobs.rs`) aborted the whole sweep on one
  dangling symlink and inflated the "checked" count with subdirs/dotfiles; now
  uses `symlink_metadata`, skips stat errors, and counts only real blobs.
- **Lock acquisition** (`patch/apply_lock.rs`) mapped every `flock` error to
  `Held` (masking `ENOLCK`/`EACCES`/unsupported-FS and busy-waiting through the
  whole timeout) and overshot sub-100 ms waits; genuine faults now surface
  immediately and the sleep is clamped to the remaining budget.

### Fixed — crawlers (on-disk layout & metadata)

- **Composer:** normalize the `v`-prefixed `installed.json` version against bare
  PURLs, tolerate a single malformed entry instead of dropping the file, and
  skip packages absent on disk.
- **Go:** only skip `cache/` at the module-cache root (not at any depth),
  decode/encode case-escaped versions (`v1.0.0-RC1` ↔ `…-!r!c1`), treat `GOPATH`
  as a path list, and reject malformed/empty `module` directives.
- **npm:** follow symlinked directories during the global-fallback walk
  (`DirEntry::metadata()` doesn't follow links) and guard nested recursion so it
  doesn't descend through symlinked packages.
- **NuGet:** lowercase the version directory (not just the id) when resolving the
  global packages folder, so prerelease-cased versions resolve.
- **Python:** the macOS framework `Versions/` layout uses bare `3.11` dirs, and a
  package with missing/malformed `METADATA` now falls back to its
  `<name>-<version>.dist-info` directory name instead of vanishing.
- **Deno:** correct the macOS cache path (`~/Library/Caches/deno`), honor
  `XDG_CACHE_HOME` on Linux, and treat an empty `DENO_DIR` as unset.
- **Maven:** strip XML comments before tag matching and handle self-closing /
  inline skip-sections so a commented or oddly-formatted POM can't leak a
  plugin's coordinates as the project's.
- **Cargo:** tolerate `[package]` headers with comments/whitespace and split
  `<name>-<version>` dirs at the dotted version (handles numeric pre-releases).
- **Shared:** `utils/fs::entry_is_dir` now follows symlinks, fixing symlinked
  package-dir discovery across every dir-walking crawler at once.

### Fixed — API client, commands & misc

- **API client:** honor a `--proxy-url` override on binary downloads (was
  re-derived from env), and make org selection, patch titles, and the
  individual-query batch capability flag deterministic / order-independent;
  hash comparison is now case-insensitive.
- **Version reporting:** `USER_AGENT` and telemetry `context.version` were
  hardcoded to `1.0`/`1.0.0`; both now derive from `CARGO_PKG_VERSION`.
- **`apply`** no longer emits a spurious `Failed` envelope event for a
  release-variant whose first file is `NotFound`.
- **UTF-8 safety:** `get`/`scan`/`remove` truncated display strings with raw
  byte slices that panic on multi-byte API text; all use char-safe truncation.
- **Exit codes:** `setup` now exits non-zero (not `already_configured`) when a
  `package.json` fails to parse, and `repair` exits non-zero and fires failure
  telemetry on a partial download failure (also gates the offline dry-run
  "would download" event and threads through `bytes_freed`).
- **`rollback`** no longer miscounts zero-file records as already-original or
  double-counts no-ops in dry-run; **`unlock`** reports `released` from a
  pre-`acquire` snapshot so a probe-created lock file isn't reported as removed.
- **`vex`** resolves qualified PyPI/Gem/Maven PURLs via the rollback-aware
  resolver so those patches are no longer dropped as `package_not_found`.
- **`package.json` handling:** no longer panics on a non-object root or
  non-object `scripts`, de-dups overlapping workspace patterns, handles bare
  `*`/`**`/deep globs, strips inline YAML comments, and preserves top-level key
  order (enabled `serde_json`'s `preserve_order`).
- Smaller fixes: deterministic `list` output ordering, case-insensitive
  `fuzzy_match` tie-break, `json_envelope` status-invariant enforcement +
  `oldUuid` field, `lock_cli` sub-second timeout message, blob-fetcher
  all-skipped formatting, VEX `Statement.timestamp` made optional per OpenVEX
  0.2.0, and VEX git-remote `url` parsing.

### Tests & tooling

- Hundreds of regression tests added across the patch engine, crawlers, API
  client, manifest, `package.json`, VEX, and CLI command layers; the stale
  `repair`/`python_crawler` e2e expectations were updated to the corrected
  contracts. Full suite green (`--features cargo`).
- Added the `scripts/study-crates.ts` per-file audit harness (with an example
  prompt config) used to drive this review.

## [3.1.0] — 2026-05-26

### Added

- **Telemetry coverage for read-side + housekeeping + attestation commands.**
  `scan`, `get`, `list`, `setup`, `repair`, `unlock`, and the new `vex`
  command each emit a `patch_<action>` (and matching `*_failed`) event
  through the existing send path, joining the apply/remove/rollback
  trio that already shipped. The `scan` event carries per-tier counts
  (`free_patches`/`paid_patches`/`can_access_paid`), the ecosystems
  filter, and a `fallback_to_proxy` flag; `get` carries
  `uuid`/`tier`/`ecosystem`/`download_mode`/`fallback_to_proxy`.

- **`scan` + `get` automatically fall back to the public proxy on
  401/403** from the authenticated endpoint. A stale or revoked
  token no longer blocks access to free patches — the CLI logs a
  warning to stderr, swaps to the proxy, retries once, and tags the
  resulting telemetry event with `fallback_to_proxy: true`. The
  classifier is deliberately narrow: 404, 5xx, network, and rate-limit
  errors do NOT trigger fallback so backend issues stay visible.
  `apply`/`remove`/`rollback`/`vex` keep their fail-loud semantics.

- **`SOCKET_OFFLINE` (airgap mode) now disables telemetry universally.**
  `is_telemetry_disabled()` honors the same `SOCKET_OFFLINE=1|true`
  signal `--offline` uses for network suppression, so apply (and
  every future command) no longer attempts a 5-second telemetry POST
  against `https://api.socket.dev` when the operator explicitly
  requested airgap.

### Tests

- New `tests/telemetry_e2e.rs` end-to-end behavioral coverage:
  apply/scan/get/list emit telemetry against a wiremock recorder;
  `SOCKET_OFFLINE=1` produces zero telemetry POSTs across all four;
  scan falls back on 401 + tags the resulting event; scan does NOT
  fall back on 500 (conservative classifier).
- New `scan_invariants` cases for the patch-management lifecycle:
  withdrawn patches keep their entry when the package is still
  installed but API is silent; entries for uninstalled packages get
  pruned; `scan` without `--apply` is read-only against the manifest
  and blobs even when an update is detected.

## [3.0.0] — 2026-05-22

### Breaking

- **`--offline` semantics unified** to strict airgap on every subcommand.
  Previously meant three different things across `apply` (strict airgap),
  `repair` (skip downloads / cleanup-only), and `rollback` (fail when blobs
  missing). All three now mean the same thing: never contact the network,
  fail loudly when a required local source is missing.
- **`repair --download-mode` default** changed from `file` to `diff` to
  match every other subcommand. Users who need the legacy per-file blob
  behavior must now opt in with `--download-mode file`.
- **`repair --offline` is mutually exclusive with `--download-only`** —
  passing both exits with code 2.
- **Env vars renamed.** The three remaining `SOCKET_PATCH_*` env vars now
  use the `SOCKET_*` prefix:
  - `SOCKET_PATCH_PROXY_URL` → `SOCKET_PROXY_URL`
  - `SOCKET_PATCH_DEBUG` → `SOCKET_DEBUG`
  - `SOCKET_PATCH_TELEMETRY_DISABLED` → `SOCKET_TELEMETRY_DISABLED`

  The legacy names are still honored at runtime but emit a one-shot
  deprecation warning to stderr (the warning fires even under `--silent`
  and `--json` because the transition signal must reach scripts and CI
  logs). Legacy names will be removed in v4.

### Added

- Shared `GlobalArgs` clap struct `#[command(flatten)]`-ed into every
  subcommand. Every flag is now accepted on every subcommand (silently
  no-op'd where the subcommand doesn't consume it). Every flag has a
  matching `SOCKET_*` env-var binding with precedence
  `CLI arg > env var > default`. See `CLI_CONTRACT.md` for the full
  global-arguments table.
- `apply` and `repair` accept `--api-url`, `--api-token`, `--org` via the
  global flatten (previously env-var only — telemetry would silently fall
  back to the public proxy when the CLI was the only way to set these).
- New global flags `--debug` and `--no-telemetry`, promoted from env-only
  toggles.
- `--proxy-url` (env: `SOCKET_PROXY_URL`) as an explicit CLI knob for the
  public patch proxy.
- New CI guard in the `Release` workflow: the workflow fails before tag
  creation if `CHANGELOG.md` lacks an entry for the version in
  `Cargo.toml`. Blocks every downstream publish (cargo, npm, pypi).

### Changed

- Garbage collection moved out of `apply`. Use `scan --prune`,
  `scan --sync`, or `repair` / `gc` instead. `apply` is now strictly
  non-mutating against `.socket/`: when blobs need to be fetched they go
  to a temp overlay; the persistent cache is never written to.
- Unified JSON envelope (`command` / `status` / `events` / `summary`) for
  `apply`, `list`, `remove`, `repair`. Other subcommands keep their
  pre-v3 ad-hoc shapes for now; see `CLI_CONTRACT.md` for migration status.

## [2.1.4] — 2026-04-09

- Release workflow tolerates already-published npm packages so a partial
  publish can be retried without re-tagging.

## [2.1.3] — 2026-04-08

- Pin Node `22.22.1` in the release workflow to dodge a broken
  upstream npm.

## [2.1.2] — 2026-04-08

- Harden core error handling, blob verification, and `--force` reporting.
- Surface `find_by_purls` errors instead of silently swallowing them.
- Add diagnostics to `apply` for silent no-op failures in CI.
- Add explicit Node typings for TypeScript 6 compatibility in the npm
  wrapper.

## [2.1.1] — 2026-04-02

- Simplify release to `workflow_dispatch` only (no bot commits).
- Split release into PR-based version prep + auto-publish on dispatch.
- Prioritize `pnpm-workspace.yaml` detection and restrict `setup` to root
  `package.json` for pnpm monorepos.
- Harden GitHub Actions workflows per `zizmor` audit.
- Unflag Ruby gem (`gem`) support and add e2e bundler tests.
- Use `npx @socketsecurity/socket-patch` for the generated postinstall
  command.

## [2.1.0] — 2026-03-10

- Full glibc/musl support across all Linux architectures (16 platform
  combinations now published per release).

## [2.0.0] — 2026-03-06

- Interactive prompts and smart patch selection when multiple patches
  match a query.

## [1.7.1] — 2026-03-06

- Ensure the binary has execute permission in the PyPI wrapper.
- Restore `bin` and `optionalDependencies` to the npm wrapper
  `package.json`.

## [1.7.0] — 2026-03-06

- Expand ecosystem support: rough-in for composer, go, maven, nuget, ruby.
- Add a TypeScript schema library to the npm wrapper.
- Treat empty `SOCKET_API_TOKEN` as unset.

## [1.6.3] — 2026-03-05

- Maintenance release.

## [1.6.2] — 2026-03-05

- Maintenance release (version sync).

## [1.6.1] — 2026-03-05

- Switch to per-platform `optionalDependencies` for the npm package.
- Add macOS global-package crawling fallbacks and pyenv support.

## [1.6.0] — 2026-03-04

- Add support for more platforms; fix pypi and npm publish flows.

## [1.5.0] — 2026-03-04

- Fix trusted publishing setup for npm and PyPI.

## [1.4.0] — 2026-03-04

- Update PyPI publish action and add npm provenance permissions.

## [1.3.1] — 2026-03-04

- Fix action image references in the publish workflow.

## [1.3.0] — 2026-03-04

- Add `apply --force`; rename `--no-apply` to `--save-only` (the old name
  remains as a hidden alias).
- Cargo/Rust crate patching support behind a feature flag.
- Auto-resolve org slug from API token when `SOCKET_ORG_SLUG` is unset.

## [1.2.0] — 2026-01-10

- Fix publish workflow to checkout the bumped version.

## [1.1.0] — 2026-01-10

- Pin GitHub Actions to full commit SHAs and wire up version-bump
  support in the publish workflow.
