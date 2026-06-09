# Changelog

All notable changes to socket-patch are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-v3.0 entries are concise summaries derived from each tag's commit
history. For full per-release detail, see the
[GitHub releases page](https://github.com/SocketDev/socket-patch/releases).

The `Release` workflow refuses to publish a version that does not appear
in this file — see `.github/workflows/release.yml` (`version` job).

## [Unreleased]

### Added

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

- **Token-less `scan` now batch-queries the public proxy.** Proxy-mode scans
  POST `{proxy}/patch/batch` (one request per `--batch-size` chunk, mirroring
  the authenticated `/v0/orgs/{slug}/patches/batch` endpoint) instead of
  issuing one `GET /patch/by-package/:purl` per package. Against proxies that
  predate the batch endpoint, the client transparently degrades to the legacy
  per-package GET path; rate limits and over-capacity 503s still surface
  instead of silently degrading. (MINOR)

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
