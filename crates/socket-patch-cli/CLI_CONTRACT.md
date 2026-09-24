# socket-patch CLI contract

This document defines the **public surface** of the `socket-patch` binary. Anything listed here is part of the user-visible contract: third-party scripts, CI pipelines, and the npm/pypi/cargo wrappers depend on it. Changes are governed by the semver policy at the bottom of this file.

> **Why this exists.** Until late 2026 the CLI crate had zero unit tests under `src/` — only network-dependent `tests/e2e_*.rs` suites that run with `--ignored`. A flag rename, a default-value change, or a JSON key rename could land green and break every shipped wrapper silently. The contract below is now backed by the unit tests under `crates/socket-patch-cli/src/**` (`#[cfg(test)] mod tests`) and the parser tests under `crates/socket-patch-cli/tests/cli_parse_*.rs`. Changes that violate the contract must update those tests in lock-step with a major version bump.

## Subcommands

| Name | Visible alias(es) | Notes |
|---|---|---|
| `scan` | — | Crawl installed packages for available patches |
| `apply` | — | Apply patches from the local manifest |
| `vex` | — | Emit an OpenVEX 0.2.0 attestation derived from the local manifest, the `.socket/vendor` ledgers, and the hosted / vendored patch references the project's lockfiles wire (no manifest required) |
| `vendor` | — | Eject patched dependencies into committable `.socket/vendor/` and rewire lockfiles |
| `setup` | — | Wire automatic-patching install hooks (npm/pypi/gem) |
| `rollback` | — | **Full-state rollback (v5.0, MAJOR)**: restore original files AND unwind vendored/hosted lockfile wiring, remove the rolled-back entries from the manifest, and GC their blobs/archives; takes optional variadic positional `targets` (PURL \| UUID \| path glob). See [Rollback command contract](#rollback-command-contract-v50) |
| `get` | `download` | Fetch + apply patch; requires positional `identifier` |
| `list` | — | Print patches in the local manifest, plus the vendor ledger's (v5.0) and the hosted redirect ledger's records (labeled; see the `manifest_not_found` row and the action matrix) |
| `remove` | — | Remove patch from manifest (rolls back first); requires positional `identifier` |
| `repair` | `gc` | Download missing blobs, rebuild missing/corrupt vendored artifacts, and clean up unused ones (refuses with `lock_held` when a live process holds the lock; see "Lock lifecycle" below) |

**Removed in v4.0:** the `unlock` subcommand (a leftover lock from a crashed run never blocks acquisition — the OS releases a dead holder's advisory lock — so there is no stale-lock state to inspect or clear before a mutating command; `repair` briefly owned lock-file cleanup in v4.x, and since v5.0 every lock-taking command removes its own lock file on exit).

**Lock lifecycle (v5.0).** `<.socket>/apply.lock` never outlives the command that took it: acquisition creates `.socket/` when it is missing, the guard's drop unlinks the file WHILE the lock is still held (so a waiter can never lock an orphaned inode), releases it, and then removes `.socket/` itself if that left the directory empty — a run that had nothing to persist leaves no `.socket/` behind, and there is nothing to `.gitignore`. A leftover file from a crashed (SIGKILLed) run is reclaimed in place and removed by the next lock-taking command. The lock is taken by `apply`, `rollback`, `remove`, `repair`, `vendor`, `setup` while it persists `--exclude` (v5.0), agent-mode `get` and `scan --apply`/`--sync` (download → manifest write → nested apply is ONE lock window — the nested apply never re-acquires), and `scan`/`get` in vendored **and hosted** mode — hosted acquires it around its first wet write (the takeover pre-reverts), never on `--dry-run` and never when the run would write nothing, so hosted previews and no-op runs create no `.socket/`. Dry runs of the other commands may still take the lock; it is residue-free either way. A live holder is `lock_held` (exit 1); a directory or special file squatting on `.socket/` or on the lock path is a lock I/O error — `lock_io` (exit 1, `failed to open lock file at <path>: …`; a read-only project root surfaces the same code at the acquire, before any ledger or manifest write) — never `lock_held`.

**Bare-UUID fallback.** `socket-patch <UUID>` is rewritten to `socket-patch get <UUID>`. The UUID shape checked is the standard 8-4-4-4-12 hex pattern (case-insensitive). See [`src/lib.rs::looks_like_uuid`](src/lib.rs).

**Root `--update` flag.** `socket-patch --update [VERSION]` updates the binary itself from GitHub Releases. It is a root flag, not a subcommand: argv is rewritten (the same mechanism as the bare-UUID fallback) onto an internal hidden subcommand whose name carries no stability guarantee — script the flag, never the internal name. Combining the flag with a subcommand (`socket-patch --update scan`) is a usage error (exit 2). Full contract: [Self-update contract](#self-update-contract-socket-patch---update).

## Global arguments

In v3.0 every subcommand accepts the same set of "global" flags via a single shared `GlobalArgs` struct that's `#[command(flatten)]`-ed into each per-command struct (`crates/socket-patch-cli/src/args.rs`). Subcommands that don't actually consume a given flag accept it silently — e.g. `list --global` parses fine and is a no-op. Every flag also has an environment-variable binding; precedence is **CLI arg > env var > default** — and for exactly three keys (`--api-token`, `--org`, `--api-url`) the JS socket-cli's persisted login sits between env var and default: **CLI arg > env var (canonical, then `SOCKET_CLI_*` alias) > socket-cli `config.json` > default**. See "Persisted configuration" under Environment variables.

| Long | Short | Env var | Default | Type | Semantic |
|---|---|---|---|---|---|
| `--cwd` | — | `SOCKET_CWD` | `.` | path | Working directory |
| `--manifest-path` | — | `SOCKET_MANIFEST_PATH` | `.socket/manifest.json` | path | Manifest location (resolved relative to `--cwd`) |
| `--api-url` | — | `SOCKET_API_URL` | `https://api.socket.dev` | string | Authenticated API endpoint |
| `--api-token` | — | `SOCKET_API_TOKEN` | (none) | string | Auth token (absence selects the public proxy) |
| `--org` | `-o` | `SOCKET_ORG_SLUG` | (auto-resolve) | string | Org slug |
| `--proxy-url` | — | `SOCKET_PROXY_URL` | `https://patches-api.socket.dev` | string | Public proxy when no token |
| `--ecosystems` | `-e` | `SOCKET_ECOSYSTEMS` | (all) | CSV → `Vec<String>` | Restrict to these ecosystems |
| `--download-mode` | — | `SOCKET_DOWNLOAD_MODE` | **`diff`** | enum: `diff` \| `package` \| `file` | Patch artifact format |
| `--vendor-source` | — | `SOCKET_VENDOR_SOURCE` | **`auto`** | enum: `auto` \| `service` \| `build` | How `vendor` acquires the installable artifact (see "Prebuilt vendor artifacts") |
| `--vendor-url` | — | `SOCKET_VENDOR_URL` | (active API/proxy base) | string | Base host for the vendoring-service package-reference request |
| `--patch-server-url` | — | `SOCKET_PATCH_SERVER_URL` | (server-returned) | string | Override the host of the prebuilt-archive download URL (local-dev / testing) |
| `--offline` | — | `SOCKET_OFFLINE` | `false` | bool | **Strict airgap on every command** — never contact the network |
| `--strict` | — | `SOCKET_STRICT` | `false` | bool | Treat a beforeHash mismatch as a hard error in the in-place apply paths (see the mismatch-policy note below) |
| `--global` | `-g` | `SOCKET_GLOBAL` | `false` | bool | Operate on globally-installed packages |
| `--global-prefix` | — | `SOCKET_GLOBAL_PREFIX` | (auto) | path | Override global packages root |
| `--json` | `-j` | `SOCKET_JSON` | `false` | bool | Machine-readable output |
| `--verbose` | `-v` | `SOCKET_VERBOSE` | `false` | bool | Extra detail |
| `--silent` | `-s` | `SOCKET_SILENT` | `false` | bool | Errors only |
| `--dry-run` | — | `SOCKET_DRY_RUN` | `false` | bool | Preview, no mutations (a dry run may still take the transient `apply.lock`, removed again on exit — see "Lock lifecycle"; hosted and vendored previews never leave a `.socket/`) |
| `--yes` | `-y` | `SOCKET_YES` | `false` | bool | Skip prompts |
| `--lock-timeout` | — | `SOCKET_LOCK_TIMEOUT` | (none) | seconds (u64) | How long to wait for `<.socket>/apply.lock`. Unset and `0` both mean a single non-blocking try; a positive value retries with a 100 ms backoff. Only meaningful on the lock-taking subcommands — `apply`, `rollback`, `repair`, `remove`, `vendor`, `setup` (while persisting `--exclude`), and `scan`/`get` whenever they write (agent-mode download + apply, vendored, hosted) |
| `--debug` | — | `SOCKET_DEBUG` | `false` | bool | Verbose debug logs to stderr |
| `--no-telemetry` | — | `SOCKET_TELEMETRY_DISABLED` | `false` | bool | Disable anonymous usage telemetry |
| `--no-trust-lockfile-config` | — | `SOCKET_NO_TRUST_LOCKFILE_CONFIG` | `false` | bool | Opt out of hosted mode's automatic `trustLockfile: true` write to `pnpm-workspace.yaml` (see the pnpm trust-config note under the scan arguments) |
| `--no-npm-allow-remote-config` | — | `SOCKET_NO_NPM_ALLOW_REMOTE_CONFIG` | `false` | bool | Opt out of hosted mode's automatic `allow-remote=all` write to the project `.npmrc` (see the npm allow-remote note under the scan arguments). Read by `scan --mode hosted` and `get --mode hosted`; other subcommands accept it silently |

The `--offline` semantics unified in v3.0. Previously `apply` enforced strict airgap, `repair` skipped network ops, and `rollback` failed when blobs were missing. All three now mean the same thing: never contact the network, fail loudly when a required local source is missing. On `repair`, `--offline` and `--download-only` are mutually exclusive (exit 2). `scan` and `get` need remote data for their core function (patch discovery / patch fetch), so `--offline` refuses them up front — exit 1 with an error naming the offline gate (JSON: `status: "error"`), before any crawl, client build, or network contact. This covers `scan --vendor` too: offline vendored staging is `vendor --offline`'s job.

The `--strict` mismatch policy applies to the in-place apply paths (apply/get/scan --apply/hook/go redirect). DEFAULT (v3.4): a file whose on-disk content matches neither the patch's beforeHash nor its afterHash is overwritten with the FULL verified patched content (the diff strategy self-disables on a wrong base; archive/blob writes are hash-gated to exactly afterHash; the missing blob is downloaded on demand) and surfaced as a `content_mismatch_overwritten` stderr warning + Skipped event. `--strict` turns that case into a hard error. `--force` overrides `--strict` and additionally skips missing files. Vendor staging is unaffected (it always auto-overwrites into its private stage).

## Per-subcommand arguments

Beyond the globals above, each subcommand defines a small set of local arguments.

| Subcommand | Local arg | Env var | Purpose |
|---|---|---|---|
| `apply` | `--force` / `-f` | `SOCKET_FORCE` | Bypass beforeHash check |
| `apply` | `--check` | — | Read-only audit that the committed **Go** `replace`-redirects match the manifest (CI / GitHub-App auditing) — Go ONLY (cargo patches in place, so there is no redirect to audit). Lock-free, crawl-free, offline-safe; exits 0 in sync, 1 on drift. Vendored modules are excluded from the audit |
| `vendor` | `--force` / `-f` | `SOCKET_FORCE` | Tolerate missing patch-target files in the stage + bypass the variant probe. A beforeHash mismatch no longer needs it: vendor staging auto-overwrites with the verified patched content (`vendor_content_mismatch_overwritten` warning) |
| `vendor` | `--revert` | `SOCKET_VENDOR_REVERT` | Undo vendoring: restore recorded original lockfile fragments + remove `.socket/vendor/` artifacts. Works without a manifest |
| `apply`, `scan`, `vendor` | `--vex` | `SOCKET_VEX` | Generate an OpenVEX 0.2.0 document at this path on a successful run; see "embedded VEX" below |
| `apply`, `scan`, `vendor` | `--vex-product`, `--vex-no-verify`, `--vex-doc-id`, `--vex-compact` | `SOCKET_VEX_PRODUCT`, `SOCKET_VEX_NO_VERIFY`, `SOCKET_VEX_DOC_ID`, `SOCKET_VEX_COMPACT` | Passthrough to the embedded VEX builder; mirror the standalone `vex` knobs. Inert unless `--vex` is set |
| `scan` | positional `[PATHS]...` | — | (v5.0) Optional path globs scoping DISCOVERY to packages installed under matching paths (`packages/foo`, `apps/**`). Purl-level: a package is in scope when ANY of its installed copies sits under a matching path. Rejected with `--mode hosted`/`--mode vendored` (exit 2, `resolve_mode_flags` — their lockfile rewiring is whole-project by construction); combines with `--apply`/`--sync`/`--prune`. See "Path-scoped scans" below |
| `scan` | `--mode <hosted\|vendored\|agent>` | — | The documented selector for the three patch-application modes. Each value is equivalent to one legacy boolean spelling: `hosted` == `--redirect`, `vendored` == `--vendor`, `agent` == `--apply` (`--sync` counts as an agent spelling). Combining `--mode` with a boolean of a DIFFERENT mode is a usage error (exit 2, enforced in `resolve_mode_flags` — clap's `conflicts_with` is value-independent); the same mode spelled both ways is accepted. `--prune` is an orthogonal GC knob and never conflicts — but hosted mode runs no GC, so `--mode hosted --prune` emits an explicit `redirect_prune_ignored` warning (JSON `redirect.warnings[]` + stderr) instead of silently dropping the flag |
| `scan` | `--redirect` | — | Hosted mode's legacy boolean spelling (**hidden from `--help`** and **deprecated** — `--mode hosted` is the documented spelling; this alias is scheduled for removal in v4): rewrite lockfiles / registry configs so ONLY the patched dependencies resolve to Socket's hosted patch server; no artifact bytes land in the repo. Conflicts with `--apply`/`--sync`/`--vendor` |
| `scan` | `--apply` / `--prune` / `--sync` | — | Mode selectors (sync = apply + prune); `--apply` == `--mode agent` |
| `scan` | `--vendor` / `--detached` | — | Vendor every patched dependency instead of applying in place (`--vendor` == `--mode vendored`; conflicts with `--apply`/`--sync`, combines with `--prune`). Vendored mode is manifest-free (v5.0): the vendor ledger embeds the patch records and `.socket/manifest.json` is never written. `--detached` — the former opt-in for exactly that — is **hidden** and retained for compatibility as a no-op; it is still a usage error (exit 2) without vendored mode in either spelling |
| `scan` | `--batch-size` | `SOCKET_BATCH_SIZE` | API batch chunk size (default `100`) |
| `get`, `scan` | `--all-releases` | `SOCKET_ALL_RELEASES` | Download patches for every release/distribution variant of a matched package — PyPI wheel/sdist (`artifact_id`), RubyGems (`platform`), Maven (`classifier`) — not just the one(s) matching the locally-installed distribution. On `scan` this makes the stored manifest portable across environments (e.g. cross-platform CI caches). On `get` (v3.6) it ALSO disables the coarse installed-**version** narrowing of CVE/GHSA fan-outs (see "get --mode and installed narrowing"): every found version's patch is fetched, installed or not |
| `get` | positional `identifier`; `--id` / `--cve` / `--ghsa` / `--package` (`-p`); `--save-only` (alias `--no-apply`); `--one-off` (hidden from `--help`: always fails "not yet implemented"); `--mode <hosted\|vendored\|agent>` | `SOCKET_SAVE_ONLY`, `SOCKET_ONE_OFF` | Patch lookup + consumption mode (v3.6). `--mode` reuses scan's value enum (same hidden value aliases `host`/`redirect`/`vendor`; deliberately no env binding, matching scan). Default `agent` = today's save+apply flow, unchanged. `--save-only` conflicts with `--mode hosted\|vendored` — rejected with **exit 1** via get's established self-enforced-conflict style (unlike scan's exit-2 mode conflicts; see the exit-code table) |
| `remove` | positional `identifier`; `--skip-rollback`; `--preserve-state` (v5.0) | `SOCKET_SKIP_ROLLBACK`, `SOCKET_PRESERVE_STATE` | Manifest entry removal. `--preserve-state` is the single-patch twin of `rollback --preserve-state`: restore the tree and unwind the identifier's vendored/hosted wiring, but keep the manifest entry, the vendored artifact + ledger entry, and skip all GC. Combining it with `--skip-rollback` is a self-enforced usage error (exit 2): one flag keeps the tree and drops the state, the other restores the tree and keeps the state — together they select the do-nothing quadrant ("the combination would be a no-op: nothing would change"). The conflict fires whether either flag is spelled on the command line or sourced from its env var |
| `rollback` | optional variadic positional `targets` (PURL \| UUID \| path glob); `--one-off`; `--preserve-state` (v5.0) | `SOCKET_ONE_OFF`, `SOCKET_PRESERVE_STATE` | Rollback scope. Multiple targets union. A token becomes a path glob ONLY when it is path-SHAPED — contains a separator (`/` or `\`) or a glob metacharacter (`*?[`), or starts with `./`, or is absolute; a `pkg:` prefix is a PURL and every other bare word keeps identifier (PURL/UUID) semantics, so a mistyped identifier or truncated UUID stays a safe exit-1 "No patch found matching identifier: X" (with a hint suggesting `./X` or `X/**` for directory targeting) instead of silently becoming a path scope. An unparseable glob is a usage error (exit 2) |
| `vex` | `--output` / `-O`, `--product`, `--no-verify`, `--doc-id`, `--compact` | `SOCKET_VEX_OUTPUT`, `SOCKET_VEX_PRODUCT`, `SOCKET_VEX_NO_VERIFY`, `SOCKET_VEX_DOC_ID`, `SOCKET_VEX_COMPACT` | OpenVEX 0.2.0 document generation; see "vex output channels" below |
| `repair` | `--download-only` | `SOCKET_DOWNLOAD_ONLY` | Repair-specific cleanup mode (mutually exclusive with `--offline`; combining them is a usage error, exit 2) |
| `setup` | `--check`, `--remove` (mutually exclusive); `--exclude` (CSV member paths); honors global `--ecosystems` | `SOCKET_SETUP_EXCLUDE`, `SOCKET_ECOSYSTEMS` | Wire / verify / revert the automatic-patching install hooks. `--exclude` skips + persists workspace members (property 9). See [Setup command contract](#setup-command-contract) |

**pnpm hosted-mode contract**: `scan --mode hosted` handles block and flow resolutions in legacy `shrinkwrap.yaml` and lockfileVersion 5.x, 6.0, and 9.0. The [pinned compatibility matrix](../../docs/testing/pnpm-compatibility.md) samples pnpm majors 1–12. Early shrinkwrapVersion 3 without a positive minor version is refused with `redirect_pnpm_legacy_lockfile_unsupported`: pnpm 1.0.0 discards hosted URLs even on frozen installs. Upgrade to a tested release (1.43.1 or newer) and regenerate the lock, or use agent mode.

Each matching package instance is spliced, including scoped, quoted and nested-peer keys, with one `redirect_pnpm_resolution` revert-ledger edit per changed instance. LF/CRLF and unrelated lock bytes are preserved. Unsupported matching instances refuse that dependency across the lockfile set; an already-hosted URL elsewhere cannot confirm a partial rewrite.

For a **9.0 root lock**, the CLI ensures `pnpm-workspace.yaml` carries `trustLockfile: true` (created with a root-only `packages:` scaffold, or appended while preserving user bytes). pnpm >=11 requires this to accept hosted URLs; it disables registry re-verification for the whole lock, while sha512 tarball integrity remains enforced. The write is ledger-recorded as `redirect_pnpm_workspace_trust`, respects `--dry-run`, skips legacy locks and Rush repos, preserves explicit user settings, and is disabled by `--no-trust-lockfile-config`. The `redirect_pnpm_trust_lockfile` warning explains manual configuration when required and clean reinstall guidance for all pnpm versions. Existing installs and warm stores can retain upstream files; use a clean install tree and empty store, then verify installed files with `socket-patch vex`. Neither a successful install nor a local VEX export guarantees hosted SBOM recognition or changes dashboard alert actions/counts.

**npm hosted-mode `allow-remote` contract**: npm >=12 defaults `allow-remote=none` and refuses (EALLOWREMOTE) every lockfile entry whose `resolved` tarball is not served by the configured registry — exactly what a hosted redirect writes into `package-lock.json` / `npm-shrinkwrap.json`. Whenever a run leaves a ROOT npm lock carrying a granted hosted artifact URL (spliced this run, or already redirected by an earlier one — a missed config heals on re-run), the CLI ensures `allow-remote=all` in the project-root `.npmrc`: the file is created holding exactly `allow-remote=all\n` when absent, otherwise one `allow-remote=all` line is spliced in after the last non-empty top-level line (before any ini `[section]` header), in the file's own line ending, with the BOM, CRLF and trailing-newline shape preserved. The write lands in `redirect.rewrittenFiles` and is ledger-recorded as `redirect_npmrc_allow_remote` (`path: ".npmrc"`, `key: "allow-remote"`, `new: "all"`; `action: "created"` for a new file, `"added"` for a spliced line), respects `--dry-run` (nothing written; the warning says what would be — including for a vendored → hosted takeover the dry run only previews), and is disabled by `--no-npm-allow-remote-config` / `SOCKET_NO_NPM_ALLOW_REMOTE_CONFIG`. The `.npmrc` grammar is npm's own `ini` parser's (cross-checked against it): lines split on any run of `\r` / `\n` (a bare `\r` ends a line), only the exact key `allow-remote` counts after ini unquoting (npm ignores `allow_remote` / `ALLOW-REMOTE` in a `.npmrc`; such a line is left alone and the real key appended), comment lines are ignored, a `[section]` header is recognized only as npm does — on the UNTRIMMED line (an indented or BOM-prefixed `[sec]` is a plain top-level key) — and ends the top-level scope, quotes and inline comments are stripped, the LAST top-level assignment wins, and the value is case-sensitive. An explicit other value (`allow-remote=none` / `root` / anything but `all`) is RESPECTED and never rewritten — the pnpm `trustLockfile: false` precedent — in the project `.npmrc` AND in every other npm config layer npm would consult: an `npm_config_allow_remote` environment variable (any spelling npm normalizes; it beats every `.npmrc`, so a project write could not take effect), and — when the project file sets nothing — the user (`npm_config_userconfig` / `~/.npmrc`), global (`npm_config_globalconfig` / `<prefix>/etc/npmrc`, prefix from `npm_config_prefix`, the user/builtin config, `PREFIX` or the `node` binary's install root) and builtin (npm's own `npmrc` beside the `node` binary: `<dir>/lib/node_modules/npm/npmrc`, `<dir>\node_modules\npm\npmrc` on Windows) config files — path values `${VAR}`-expanded and `~`-expanded like npm, env names case-insensitive on Windows, where a committed project line would silently override a machine / org policy. A symlinked, non-regular or unreadable `.npmrc`, or one with bare-`\r` line endings (npm splits on them, the line splice does not), is left untouched. Every variant emits the `redirect_npm_allow_remote` warning (written / would write / already set / explicit value respected — naming the project file, the env var, or the user/global/builtin config path — / opted out / unreadable or unsupported), always with the tradeoff: `allow-remote=all` lets npm install ANY url-resolved dependency, not just Socket's patched ones, while the per-entry sha512 integrity pins stay enforced; the remedy for the non-writing variants is `allow-remote=all` in `.npmrc` or `npm ci --allow-remote=all`. npm <=11 is unaffected (11 defaults to `all`, <=10 has no such setting). **Unwind**: the edit is removed exactly once no `redirect_npm_lock_entry` / `redirect_npm_lock_dep` edit remains in the ledger — by the per-purl npm revert of the LAST package-lock entry (scoped `rollback <purl>` / `remove <purl>`, the hosted → vendored takeover), by the whole-ledger replay (`rollback` / `remove`, `npm` group — a refused package-lock edit keeps the setting it needs), and by the vendored-supersedes-hosted reconcile. A `created` file still holding exactly `allow-remote=all\n` is deleted; otherwise only the one top-level `allow-remote=all` line is removed, user edits kept (a modified created file warns `redirect_npmrc_allow_remote_modified`, surfaced in the `warnings[]` of `rollback`, `remove`, `vendor` and the vendored reconcile, and as a `Warning (<code>): …` stderr line in human mode); copies under an ini `[section]` are inert to npm and never counted, and a duplicated TOP-LEVEL line refuses fail-closed (ambiguous). A symlinked or non-regular `.npmrc` refuses the unwind while it is still being PLANNED, so the revert writes nothing (never a reverted lock behind a ledger that still records the redirect). The rewrite's stage file is created with the `.npmrc`'s own permission bits (a 0600 token-bearing file is never staged world-readable). **Vendored mode is unaffected**: its `file:.socket/vendor/…` resolutions are npm `file` specs, which npm gates by `allow-file` (default `all`), never `allow-remote` — verified by the real npm 12 vendored matrix.

`redirect_pnpm_no_lockfile` names pnpm when installer markers exist without a lock; `redirect_pnpm_entry_vendored` identifies a vendored entry instead of reporting it missing. Supported `shrinkwrap.yaml` files are writable lockfiles, not read-only markers.

**Takeover reconciliation (npm family, bun included)**: vendoring over a hosted-redirected purl (`vendor`, `scan --mode vendored`, `get --mode vendored`) first REVERTS that purl's hosted lockfile edits to their pre-redirect registry values through the per-purl redirect revert, drops the purl's record + package edits from `redirect-state.json`, and then vendors — so the vendor ledger records the PRISTINE registry fragment as its wiring `original` and `vendor --revert` lands back on registry state, never on an expiring hosted URL. The run that takes over records a `vendor_takeover_reverted_redirect` advisory event (`skipped` action beside the purl's genuine outcome; the human path prints `Warning (vendor_takeover_reverted_redirect): …`). `--dry-run` PROBES the same revert against an in-memory ledger clone instead of promising it: a clean probe reports `vendor_would_revert_redirect`, and a drifted lock or an undecidable ledger edit surfaces in the preview with the wet run's `redirect_revert_failed` code and detail (for bun, whose hosted rewrite replaces the entry's `name@version` spec, the preview first runs the Bun vendored preflight described below and then stops at the advisory instead of reading the still-hosted lock — a lock the vendored backend would refuse is previewed as the wet run's `failed <code>`, never as `vendor_would_revert_redirect`). A purl whose hosted edits cannot be cleanly reverted fails `redirect_revert_failed` (exit 1 / `partial_failure`, nothing vendored for it, the hosted wiring left in place, the remedy in the detail). **bun** participates like every other npm-family flavor: binary `redirect_bun_lockb_package` snapshots are claimed by their recorded package identity and restore individual binary resolutions; its text `redirect_bun_lock_package` edits are claimed by the recorded line's spec — the registry spec `<name>@<version>`, or a hosted URL whose tarball leaf is `<name>-<version>.tgz` — so a sibling version's or an aliased sibling's edit is neither claimed nor a refusal, and only an edit that mentions the package without being a bun packages-entry line refuses (remedy: an unscoped `socket-patch rollback`, whose whole-ledger replay unwinds bun.lock hosted edits; never hand-edit the ledger). The same claim rule serves scoped `rollback <purl>` / `remove <purl>` of one of several hosted bun records (see "Hosted unwind coverage"). Hosted → vendored and vendored → hosted (`redirect_takeover_reverted_vendored` in `redirect.warnings[]`) both work in place on bun locks the target mode accepts. **Bun vendored preflight before the takeover**: `vendor` — like `scan` / `get --mode vendored`, whose pre-download preflight runs earlier — checks `bun.lock` / `bun.lockb` with the shared Bun vendored preflight BEFORE the per-purl hosted revert, so a hosted-redirected purl on a lock the vendored backend refuses (a pre-version-2 `workspace:` lock → `vendor_bun_workspace_unsupported`; a malformed or unsupported binary lock → `vendor_bun_lockb_invalid`; an unsupported text-lock version → its code) is reported `failed <code>` with the hosted wiring, the redirect ledger and active Bun lock byte-untouched (exit 1 / `partial_failure`): the package stays hosted-patched instead of being un-hosted and then refused. `vendor --dry-run` previews that same `failed` code (exit-code parity with the wet run, nothing written) instead of promising `vendor_would_revert_redirect`. Pinned by `tests/in_process_vendor_bun_takeover.rs` and, against real Bun, `tests/mode_migration_bun.rs`. **golang** takes over the same way: the per-purl revert drops the module's hosted `replace`, removes the socket module's go.sum lines, puts the pruned upstream go.sum lines back in go's sort order, and drops the ledger record, so the vendored `replace` is recorded over pristine go.mod/go.sum (a go.mod whose replace for the module is no longer the recorded one refuses `redirect_revert_failed`). The separate run-level `vendor_supersedes_redirect` warning covers the reconcile-only case — a live lock that already proves vendored won over a stale hosted ledger record (the vendor wiring then holds the hosted-spliced fragment as `original`) — and fires exactly once, on the run that drops the stale records. Which way the live lock points is decided by the same lockfile discovery and ledger-liveness rules `vex` gates attestations on (see "Manifest-less VEX (lockfile discovery)"), for this warning, its `redirect_supersedes_vendored` twin and `hosted_wiring_retained` alike.

`scan --apply` opts JSON callers into the full discover → select → apply pipeline. Without it, `scan --json` stays read-only (discovery + the `updates` array + the `redirectState` state block below). No effect outside `--json` mode. The non-JSON path prompts the user interactively in a TTY; when stdin is NOT a TTY (CI, a pipe), `--yes` is absent, and no intent flag (`--mode`, `--apply`, `--sync`, `--vendor`, `--redirect`, `--prune`) is given, a human-mode `scan` is **report-only** (v5.0): it prints the discovery report and the existing "To apply a single patch, run: …" hint, downloads nothing, writes nothing (no `.socket/`), and exits 0. Any intent flag, `--yes`, or a TTY keeps the previous behavior (prompt in a TTY, auto-proceed otherwise). Only `scan` gained this pre-check — `rollback`/`remove`/`get`'s non-TTY auto-accept is unchanged.

**Hosted-state visibility (`redirectState`, additive/MINOR).** Every non-hosted-mode, non-vendored-mode `scan --json` SUCCESS envelope (report-only, `--mode agent`/`--apply`/`--sync`, and the zero-discovery envelope) carries an additive top-level `redirectState` object whenever the hosted redirect ledger (`.socket/vendor/redirect-state.json`) holds ≥ 1 `records` entry: `{ mode, ledger, records: [{purl, ledgerKey, uuid}], wiringLive: [purl] }`. It is a descriptive STATE block, not a warning — a hosted-wired project's report-only scan used to be byte-identical to a never-touched project's. `mode` is the constant `"hosted"` (the mode's documented name, whatever opaque `mode` string the ledger itself carries — pre-rename ledgers say `"redirect"`) and `ledger` the ledger's repo-relative path. `records` lists every ledger record (sorted by ledger key): each entry's `purl` is CANONICALIZED (qualifiers stripped, percent-decoded — e.g. `pkg:npm/@scope/pkg@1.0.0`, `pkg:gem/nokogiri@1.13.3`) to the same spelling `wiringLive` carries, so the records↔proof join is a plain string compare, and `ledgerKey` preserves the ledger's verbatim key (percent-encoded scoped names, `?platform=` qualifiers) for consumers addressing the ledger itself. `wiringLive` is the subset of this run's *counted* purls (post-`--ecosystems`-filter) whose hosted lockfile wiring the LIVE lock still proves — the same proof, computed once per run, that feeds `hosted_wiring_retained`, and the same liveness rule `vex` applies to a redirect-ledger record (see "Manifest-less VEX (lockfile discovery)"). Consumers must treat the split as exactly that: records are the ledger's word, `wiringLive` the live lock's proof — a record with no proof means the wiring was unwound, the lock is unreadable, or the purl was not crawled/queried this run (an `--ecosystems` filter, a zero discovery), never "still live". The key is omitted when the ledger is absent or its `records` are empty (an edits-only ledger asserts no patches), and error envelopes (the `--offline` refusal, all-batches-failed) are deliberately minimal and never carry it. A malformed ledger degrades to "nothing to consult" (no block) with a stderr warning, muted by `--silent`. Hosted-mode runs carry the `redirect` sub-object instead (the run's own result; the ledger is re-persisted mid-run), and vendored-mode runs carry the takeover warnings (their reconciliation may retire records mid-run) — neither duplicates a pre-run snapshot that could go stale.

**Agent-flow run-level warnings (additive).** An agent-mode apply (`--mode agent` / `--apply` / `--sync`, `--json`) may add a top-level `warnings[]` array of `{code, detail}` entries to the scan envelope (absent when none fired; each is also mirrored to stderr unless `--silent`). They surface cross-mode state the apply cannot change — never a status or exit-code change (hosted refusals set the precedent: exit 0 + warning). Codes (stable; new codes are additive/MINOR): `vendored_ownership_retained` — vendor-owned package(s) were skipped before download (the per-patch `skipped`/`vendored` records in `apply.patches[]` are unchanged); the detail names the purls and the migration path (`remove <purl>`, or `vendor --revert` which unwinds every vendored package, then re-run). `hosted_wiring_retained` — the hosted redirect ledger records scanned package(s) whose hosted lockfile wiring the live lock still proves (the agent run does not unwind hosted wiring — as of v5.0 that is `socket-patch rollback`'s job, or `remove <purl>` per package); the detail names the purls and the options (stay `--mode hosted`, or migrate via `scan --mode vendored`) and never advises hand-deleting the ledger. The warning keys on ledger *records* still live at scan time — a flow that pre-reverted the redirect (retiring the records) retires the warning with them, even while the append-only `edits` (revert originals) remain. The interactive path prints the same `hosted_wiring_retained` text to stderr after an apply; the vendored counterpart is already covered by its per-package `[skip] … (vendored …)` lines. `ownership_not_restored` (v5.0; `apply` and `rollback` `warnings[]` alike) — a file WAS patched (or restored) but its ownership could not be put back to the original uid/gid (the mode is still restored last); the detail is `<purl>: <path>: patched, but ownership could not be restored to uid N gid M: <error>` and the human line `Warning (ownership_not_restored): <detail>` (stderr, muted by `--silent`); never a status or exit change.

`scan --prune` opts into garbage collection. When set, `scan` removes manifest entries for packages no longer present in the crawl, then deletes orphan blob, diff, and package-archive files from `.socket/`. Off by default (v3.0) so a temporary uninstall doesn't silently destroy manifest state. Only entries whose ecosystem this run actually crawled are eligible: a `pkg:<type>/` with no crawler in this build (a newer CLI's ecosystem in the committed manifest) and the runtime-gated maven/nuget crawlers with their gate off are exempt — the crawl never looked for them, so their absence is not evidence of removal (same fail-safe as the `--ecosystems` filter, which narrows the query but never the prune's installed set). The pass also reconciles vendored state (runs FIRST, under ONE apply-lock acquisition shared with the manifest prune — lock contention skips the whole pass without failing the scan; `--lock-timeout` is honored and a lock I/O error is reported rather than swallowed; the existence gate — a manifest file OR a vendor ledger file, both cheap stats; an emptied ledger is deleted on save, so its presence is its content proxy — runs BEFORE the lock, so a bare project never gets a `.socket/`; in the vendored scan arms the pass runs AFTER the vendor step): (a) ledger entries still tracked by a manifest record (manifest-mode entries written by standalone `vendor`) whose patch is gone from the manifest are reverted — `detached` entries (every `scan`/`get --mode vendored` entry, v5.0) have no manifest record to lose and are exempt from this leg; (b) EVERY ledger entry whose dependency is no longer in the lockfile graph is reverted and any manifest entry it still had dropped (v5.0: the check is about the lockfile, not the manifest, so embedded-record entries are no longer exempt; a missing or undeterminable lockfile keeps the entry, fail-safe); and (c) orphan `.socket/vendor/<eco>/<uuid>` dirs with no ledger entry are swept. The prune never deletes a zero-patch `.socket/manifest.json` (its `{"patches": {}}` + `setup` block stay). The JSON `gc` sub-object gains `revertedVendoredEntries` + `keptVendoredEntries` + `failedVendoredEntries` + `removedVendorOrphanDirs` (wet) / `revertableVendoredEntries` + `vendorOrphanDirs` (preview), plus two ADDITIVE wet-only keys: `skipped: {code, message}` — present exactly when the pass was skipped at the lock (`lock_held` | `lock_io`; every count is then zero) — and `warnings: [{code, detail}]` — `vendor_state_write_failed` / `manifest_write_failed` (entries were reverted but the ledger or manifest rewrite failed) and `cleanup_failed` (an orphan sweep failed mid-way). Human mode prints `GC: skipped (<code>): <message>.`, one `GC: <detail>.` line per warning, and `GC: failed to revert N vendored entries: …` (singular for one) for `failedVendoredEntries`. `keptVendoredEntries` lists drift-kept entries the revert deliberately preserved (`vendor_artifact_kept` — undo the drift and re-run `vendor --revert` to finish); the preview cannot see drift (backends return before the wiring replay on dry runs), so `revertableVendoredEntries` may over-promise what a wet run will actually reclaim.

`scan` queries the patch API in `--batch-size` chunks. Authenticated runs POST `/v0/orgs/{slug}/patches/batch`; token-less runs POST `{proxy}/patch/batch` on the public proxy and degrade to per-package `GET /patch/by-package/:purl` requests in two cases: the deployed proxy predates the batch endpoint (legacy proxies answer the POST with their `400 "Unsupported endpoint"` catch-all), or the all-or-nothing batch validation rejects the chunk (e.g. a crawled PURL type the server doesn't recognize, such as `pkg:jsr/…` — the per-package path tolerates those individually, preserving the pre-batch scan semantics). Rate limits and over-capacity 503s surface instead of silently degrading.

**Lockfile supplement (v3.4)**: `scan` discovery is no longer limited to installed trees. The project's lockfiles (`package-lock.json`/`npm-shrinkwrap.json`, `pnpm-lock.yaml` v9, `yarn.lock` classic + berry, `bun.lock`, `Cargo.lock`, `go.sum`, `composer.lock`, `Gemfile.lock`, `uv.lock`/`poetry.lock`/pinned `requirements.txt`) are inventoried and dependencies with NO installed copy join discovery — counts, the API lookup, the table (flagged ` [NOT INSTALLED]`, plus a stderr note), and the prune "scanned" set (a wiped node_modules no longer prunes lockfile-listed entries). JSON gains a top-level `lockfileOnlyPackages` count and an additive `notInstalled: true` on matching `packages[]` entries. `--apply` partitions lockfile-only patches out BEFORE download (calm `skipped`/`package_not_installed` records — never an error exit, never a manifest write); `--vendor` passes them through to the vendor engine's auto-fetch. Vendored-ledger entries likewise stay discoverable on a fresh clone (the committed artifact is the dependency). Global scans (`--global`) get no supplement. **Rush monorepos** (no root lockfile, `rush.json` present): the npm-lock inventory falls back to the Rush source-of-truth locks — `common/config/rush/pnpm-lock.yaml` plus every `common/config/subspaces/*/pnpm-lock.yaml` (`read_dir`-sorted, repo-relative paths preserved) — so a Rush repo's dependencies still join discovery. **Plug'n'Play layouts are an explicit refusal, not an empty inventory**: a `.pnp.*` loader means the npm packages are structurally unreachable in EVERY mode (under yarn PnP the installed-tree crawl is empty too — no `node_modules/`), so `scan` surfaces an additive top-level `warnings[]` array (`{code, detail}` objects, omitted when empty) carrying `yarn_pnp_unsupported` (same code as apply's refusal; remedy `yarn patch <pkg>`) or `pnpm_pnp_unsupported` (pnpm's `node-linker=pnp` twin; pnpm remedies), plus a stderr `Warning (<code>): …` line on the human path. Exit code and `status` are deliberately unchanged (exit 0 / `success` — the same posture as hosted refusals, which exit 0 with `redirected: 0`); the warning is the machine-readable signal that nothing was checked. Pinned by `tests/e2e_safety_yarn_pnp.rs`.

**Vendor auto-fetch (v3.4)**: `vendor`/`scan --vendor` no longer fail on lockfile-resolved packages with no installed copy. Already-vendored purls stage from their committed artifact (sha256-verified against the vendor ledger; offline-safe). Otherwise the pristine artifact is fetched per the lockfile resolution and verified against the lock's recorded integrity FAIL-CLOSED before any write: npm SRI (or yarn classic's sha1 fragment), yarn berry's cache-zip checksum (rebuilt from the fetched tarball; cacheKey 10c0 only), Cargo.lock sha256 over the .crate, go.sum `h1:` dirhash over the module zip, composer `dist.shasum` (sha1), Gemfile.lock `CHECKSUMS` sha256, uv.lock wheel sha256 (pure `py3-none-any` wheels only). Entries the lock cannot verify are NEVER fetched (`vendor_fetch_unverifiable` warning + the calm `package_not_installed` skip). Registry bases honor `SOCKET_NPM_REGISTRY`, `SOCKET_CRATES_REGISTRY`, `SOCKET_GOPROXY` (else `GOPROXY`, `GONOPROXY` and `GOPRIVATE` the way go reads them — see the env table); npm/yarn/composer/gem/uv lock-recorded URLs are used verbatim. `--offline` refuses the fetch with the calm skip (the detail names the lockfile resolution). The fetch stages into a private tempdir — the project tree is never touched.

`scan --sync` is sugar for `--apply --prune` — the canonical single-flag bot invocation. `scan --json --sync --yes` discovers, applies, and reconciles state in one pass.

**Path-scoped scans (`scan [PATHS]...`, v5.0)**: optional variadic positional path globs scope DISCOVERY at the **purl level** — a package is in scope iff ANY of its crawled installed copies sits under a matching path, and a selected package is then handled with ALL its copies (scoping selects which packages are considered, never which copies). Glob semantics (shared with `rollback`'s path targets, `src/path_scope.rs`): Unix-shell globs with `require_literal_separator` — `*`/`?` never cross a `/`, `**` spans directories; a pattern matching any **ancestor** directory of the copy path also matches, so a bare `scan packages/foo` scopes the whole subtree without `/**`; relative patterns match against the copy path relativized to `--cwd`, absolute patterns against the absolute path (the ONLY way to reach paths outside the project tree, e.g. `--global` stores — a relative pattern never matches outside `--cwd`); leading `./` and trailing `/` are normalized away, matching is purely textual (no filesystem access or symlink resolution), case-sensitive except on Windows (whose filesystems are not); an unparseable or empty pattern is a usage error (exit 2). **The prune universe is never narrowed**: the path filter is applied strictly AFTER the `scanned_purls` capture (and after `--ecosystems`), so `scan PATHS --prune` prunes exactly what an unscoped `scan --prune` would — a scoped scan can never treat an out-of-scope package as uninstalled (the same fail-safe as the `--ecosystems` filter). Lockfile-only and vendor-ledger supplement records have no installed path and are EXCLUDED from a path-scoped scan, surfaced as one run-level `path_scope_excluded_supplements` warning carrying the count. A scope matching nothing is a normal empty scan — exit 0, zero packages, **no GC** (the zero-package early return fires before any GC). `PATHS` with `--mode hosted` or `--mode vendored` is a usage error (exit 2, `resolve_mode_flags`: "path targeting … applies to agent-mode and read-only scans" — their lockfile rewiring is whole-project by construction); `PATHS` with `--apply`/`--sync`/`--prune`/`--global` is fine. Every scan JSON shape (success, zero-package, and error alike) gains an additive always-present `paths` key echoing the patterns verbatim (empty array when unscoped). One-sentence duality rule: **a target that selects nothing is an error on `rollback` (exit 1) and an empty scan on `scan` (exit 0)**.

`scan --vendor` swaps the in-place apply for the vendor pipeline: discover → download the selected patch records **into memory** (no manifest write) → vendor every selected dependency via the same engine as the `vendor` command (under the same lock). Vendored mode is **manifest-free (v5.0)**: `.socket/manifest.json` is never written or read by a vendored run; each ledger entry carries `detached: true` plus an embedded copy of the patch record (`record`) as its verification source, and the run's footprint is `.socket/vendor/**` only. The vendor step's scope is what discovery selected — the former "whole manifest is vendored" re-vendor on an empty discovery is retired (`repair` verifies and rebuilds committed vendored state; `scan --prune` reconciles ledger entries whose dependency left the lockfile). A package the ledger holds at an older patch uuid is still **re-vendored automatically** when discovery selects the newer patch (its old uuid dir is removed — `vendor_stale_artifact_removed`); same-uuid re-runs reuse the embedded record, skip the patch-view fetch, and are `already_vendored` skips. **Legacy manifest-mode entries**: when a vendored run vendors a purl that also has a `.socket/manifest.json` record (a project vendored by a pre-5.0 binary, or by standalone `vendor` from an agent-mode manifest), that manifest record is dropped in the same run — the ledger becomes the owner (migration write); an emptied manifest is left as `{"patches": {}}`, never deleted. The migration is reported through the run-level `warnings[]` (stderr in human mode), never as a run error: `vendor_manifest_record_migrated` (`N manifest records moved to the vendor ledger (vendored mode is manifest-free): <purls>`) or `vendor_manifest_migration_failed` (the manifest or the ledger could not be read or rewritten; the legacy records were left in place) — so a corrupt `.socket/manifest.json` no longer fails a vendored run (standalone `vendor`, the one manifest-driven writer, still fails closed on it). With `--prune`, GC runs **after** the vendor step (the step never reads the manifest, and running the sweep last lets it reclaim what the run itself orphaned — a migrated legacy record's blobs, a superseded uuid dir). JSON output gains a `download` sub-object — the detached download envelope `{found, downloaded, skipped, failed, detached: true, patches: [{purl, uuid, action: "downloaded" | "skipped" | "failed", …}], warnings?}` (no `applied` field — nothing is applied in place; `detached: true` is pinned and always present; a `downloaded` record whose purl the ledger already holds at another uuid carries the additive `oldUuid` — the re-vendor the vendor step then performs — and its human `[fetch]` line reads `<purl> (replacing <short uuid>)`) — and a `vendor` sub-object (a full vendor Envelope). Patch blobs are held in memory (see "Patch sources stay in memory" under the vendor contract). `--dry-run` previews per-patch `would_vendor` | `would_revendor` (+`oldUuid`) | `already_vendored` — plus, additive, `would_refuse` (+`errorCode`, `error`) for npm purls the wet run's Bun preflight (see the `get --mode vendored` bullet below) would refuse — without network downloads or disk writes; the preview never flips status or exit (the human path — `scan` and `get` alike, through one shared printer — prints `[would-refuse] <purl> (<code>): <detail>` lines behind the `--silent` gate). Interactive mode prompts "Download and vendor N patches?" (singular for one).

**Vendored entries and the rest of the CLI.** Because nothing is in the manifest, vendored patches are invisible to `apply` (nothing to apply in place) but fully visible to `list` (listed from the ledger, labeled `Mode: vendored (recorded in .socket/vendor/state.json)` in human mode, exit 0 on a vendored-only project), `vex` (attested from the embedded records while a lockfile still wires the artifact — see "Manifest-less VEX"), `repair` (health-checked and rebuilt from the ledger), `scan --prune` (lockfile-driven reconcile) and `setup --check`'s patch-consistency property (consulted from the embedded records). They are exempt from standalone `vendor`'s manifest reconcile (`reconcile_dropped` never touches `detached` entries) and exit via `remove <purl>` (which reverts them), `vendor --revert`, or `rollback`, whose vendored leg reverts every in-scope ledger entry (unscoped and identifier-scoped runs; path-scoped runs reach them only when an installed copy matches). The hidden `--detached` flag (`scan --vendor --detached`) names exactly this — the only — vendored posture and is accepted as a no-op for compatibility.

`scan --mode hosted` (== `--redirect`) swaps the in-place apply for the registry-redirect pipeline: discover → resolve hosted-patch references (grant token + integrity + per-dep registry override) → rewrite ONLY the patched dependencies' lockfile / registry-config entries to point at the hosted packages. A dep counts as **redirected** only when its hosted-artifact URL (or per-dep registry index URL) actually landed in a project file — a granted reference whose rewriter found nothing to edit is neither recorded nor attested. Cargo and golang are confirmed only by their rewriter's own report (`confirmed_cargo_uuids` / `confirmed_golang_uuids`): a golang dep counts only when its go.mod `replace M V => patch.socket.dev/gopatch/<uuid> <sver>` and both go.sum lines are in place, never because the patch-server origin or leftover go.sum lines appear somewhere. A golang module that go.mod does not require and go.sum does not list at the patched version is outside the build graph and is refused with `redirect_golang_not_in_module_graph` (nothing written). Only the exact module `patch.socket.dev/gopatch/<canonical uuid>` is socket-owned; any other module path is refused with `redirect_golang_untrusted_module_path`. A vendored golang module is taken over like cargo and the npm family: its vendor wiring, committed copy and ledger entry are reverted first (`redirect_takeover_reverted_vendored`). Re-runs over already-rewritten output record zero new edits. **Lock (v5.0)**: the hosted engine acquires `<.socket>/apply.lock` around its first wet write (the takeover pre-reverts) — not on `--dry-run`, and not when the run would write nothing (zero redirects, all skipped) — so previews and no-op runs never create `.socket/` (and never quarantine: a `--dry-run` or a zero-grant wet run that finds a malformed `redirect-state.json` reports it as the hard error it is — exit 1, the repair-or-move-aside remedy — but moves nothing; only a run holding the lock moves it aside to `redirect-state.json.corrupt`); contention is `lock_held` and a lock-file I/O fault (a read-only project root, a file squatting on `.socket/`) is `lock_io` — both exit 1, refused BEFORE the redirect ledger is read or written, and rendered like every other lock holder: human `Error (<code>): <message>` on stderr (+ the `--lock-timeout` hint for a live holder); JSON keeps the hosted shape — top-level `status: "error"`, `errorCode: "lock_held" | "lock_io"`, a string `error`, and `redirect: {mode: "hosted"}` retained (NOT the vendored `error: {code, message}` object). **Takeover symlink pre-check (v5.0)**: a vendored→hosted takeover whose recorded wiring file is a symlink is refused up front with `redirect_symlinked_file_unsupported` — wet and `--dry-run` alike, before any revert — so "nothing was written" holds. **Human mode (v5.0)**: `scan --mode hosted` prints the results table and update detection like the other modes and confirms once — `Redirect N packages to the hosted patch server?` (singular for one), default yes, skipped by `--yes`/`--json`, on `--dry-run` (the engine honors the preview itself; nothing mutates), and when the detail fetch leaves nothing to redirect (that run enters the engine as a no-op — `Redirected 0 packages; rewrote 0 files.`, no lock, no `.socket/` — without prompting); without `--yes` on a non-TTY stdin the shared prompt prints `Non-interactive mode detected, proceeding automatically.` to stderr (unless `--silent`) and proceeds — before rewriting anything (parity with the agent/vendored arms and with `get --mode hosted`). The detail fetch prints the same progress counter and per-package `Warning: could not fetch details for …` lines as the agent arm. An EMPTY hosted discovery prints `No patches available for installed packages.` and exits 0 without entering the engine (previously `Redirected 0 packages; rewrote 0 files.`); a discovery whose every offer is paid-tier for an org without paid access prints the table's paid nudge, then `No downloadable patches (paid subscription required).`, and exits 0 without entering the engine (parity with the agent/vendored arms). A malformed redirect ledger on a human hosted run that returns before the engine (empty discovery, nothing downloadable, a detail-fetch failure, a declined confirm) is surfaced there as the read-only `Warning: the redirect ledger … is malformed …` advisory (muted by `--silent`), never moved; the `--json` arm always enters the engine and hard-errors instead. JSON output gains a `redirect` sub-object: `{ mode: "hosted", redirected, rewrittenFiles, skipped, warnings, dryRun }` (`mode` is additive so consumers can dispatch without inferring it). Rewriter warnings carry stable `redirect_*` codes (e.g. `redirect_npm_no_lockfile`, `redirect_gradle_manual_snippet`, `redirect_golang_unsupported`); new codes are additive (MINOR). v5.0 additive codes: `redirect_composer_no_lockfile` / `redirect_gem_no_gemfile` (composer / gem: neither manifest nor lock present — once per run, after the intake gates), `redirect_maven_no_pom` (no `pom.xml` and no Gradle build), `redirect_nuget_lock_unparseable` (a present-but-corrupt `packages.lock.json` — warned once, nothing mutated; an absent lock still proceeds), `redirect_cargo_lock_pkg_ambiguous` (several same-name+version `[[package]]` blocks and none carries the index `source` — transactional skip). Also v5.0: a registry override of the wrong kind (or none at all) warns the arm's missing-override code for nuget/gem/golang where it used to skip silently, and the ledger's `redirect_nuget_source` edit records `action: "added"` when `nuget.config` was authored from scratch (`rewritten` otherwise). Refusals stay fail-closed with a diagnosis that names the actual cause: a yarn-berry lock entry resolving through a non-`npm:` protocol keeps `redirect_yarn_berry_unsupported_protocol` with the entry's ACTUAL protocol in the detail — except socket-patch's OWN vendored wiring (a `file:` range into `.socket/vendor/`), which gets the distinct `redirect_yarn_berry_vendored_entry` code whose detail names the retirement path (`remove <purl>` per package, or `vendor --revert` which unwinds every vendored package, then re-run `scan --mode hosted`). Both leave the entry byte-identical; neither changes exit code or status. **yarn berry line endings (v5.0)**: yarn writes a NEW `yarn.lock` with the OS line ending (`os.EOL` — CRLF on Windows) and keeps an existing lock's majority ending on every later write, and a `core.autocrlf` checkout turns an LF lock CRLF on any OS — so a uniformly CRLF lock is rewritten in its own ending: every untouched byte (a leading BOM included) round-trips, and the `redirect_yarn_berry_entry` ledger edits record the lock's ON-DISK (CRLF) fragments, which the reverts match byte-exactly. A lock that MIXES CRLF and LF (or holds a bare CR) has no single ending to keep — yarn's own `--immutable` check rejects it too (YN0028) — so it is refused untouched with `redirect_yarn_berry_mixed_line_endings` (the detail names `yarn install`, which normalizes it). This replaces v4's `redirect_yarn_berry_crlf_unsupported`, which refused every CRLF lock and is no longer emitted. A vendored→hosted takeover runs these berry gates (mixed line endings, unsupported `cacheKey`, a non-zero `.yarnrc.yml` `compressionLevel`) BEFORE reverting a vendored berry purl — wet and `--dry-run` alike — so a refused purl keeps its vendored wiring, ledger entry and artifact byte-identical and is skipped with the gate's code (never announced as `redirect_takeover_reverted_vendored` and then left unpatched in both modes).

The rewriter reads a fixed set of candidate files from the project root: the npm-family locks (`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `shrinkwrap.yaml`, `yarn.lock`, plus `.yarnrc.yml` for the berry cache-config gate and `bun.lock` / `bun.lockb`), `requirements.txt` / `uv.lock` / `Pipfile.lock` (pipfile-spec 6; see the Pipenv section below) / `poetry.lock` (every Poetry lock generation from 1.0 on — the 0.12 `[metadata.hashes]` layout is refused because that installer ignores URL sources; a Poetry < 1.4 writer additionally gets `redirect_poetry_stale_install_risk`, see `docs/testing/poetry-compatibility.md`) / `pdm.lock` (PDM lock formats `2` and `4.3`–`4.5.1`; the identity-losing `3.1` / `4.0`–`4.2` formats and unknown future formats are refused with `redirect_pdm_refused`, and a lock-format-`2` writer additionally gets `redirect_pdm_legacy_sync_required`, see `docs/testing/pdm-compatibility.md`; when `uv.lock` or `poetry.lock` sits beside it they drive and `pdm.lock` is left alone), `Cargo.toml` / `Cargo.lock` / `.cargo/config.toml` (plus the legacy extensionless `.cargo/config` — cargo reads that spelling in preference when both exist, so the managed `[registries.…]` block is written into whichever one is present; **cargo also reads every workspace-member manifest** — the `[workspace] members` globs minus `exclude` — and every in-root path-dependency manifest, recursively, reached without crossing a symbolic link and never under `.socket/`, and pins the crate in each one that declares it, so those `<dir>/Cargo.toml` files can appear in `rewrittenFiles`. A crate is redirected only when every declaration pins and every other `Cargo.lock` package depending on it is a planned member: one a registry or git crate — or a path package outside the root or behind a link — also depends on is refused `redirect_cargo_transitive_dependents` (a pin reaches only the declarations it sits on; without a `Cargo.lock` this check cannot run), a crate no manifest declares keeps `redirect_cargo_toml_dep_not_found` with a transitive-only detail naming `--mode vendored`, and a requirement that also matches another locked version of the crate is refused `redirect_cargo_toml_dep_unrewritable` — each a transactional skip, never recorded or attested. All-CRLF manifests, locks and configs are rewritten with CRLF kept (mixed endings keep refusing where the grammar does not match), and `remove` / rollback match the recorded fragments across a later CRLF↔LF checkout conversion), `composer.lock`, `nuget.config` / `packages.lock.json`, `Gemfile` / `Gemfile.lock`, `pom.xml` (+ `.mvn/maven.config` / `.mvn/checksums/checksums.sha256` for maven Trusted Checksums merge, and the Gradle build scripts read only to trigger the manual-snippet warning). **npm-family flavor coverage**: package-lock / npm-shrinkwrap, pnpm (root OR any nested `*/pnpm-lock.yaml`), yarn classic, **yarn berry** (`yarn.lock` entry only — `resolution: ::__archiveUrl=` + `yarnBerry10c0` checksum; cacheKey `10c0` and `.yarnrc.yml compressionLevel 0` gated by `redirect_yarn_berry_cache_unsupported`), and **bun** (text `bun.lock` lockfileVersion 0, 1 or 2 — 0 is the `--save-text-lockfile` opt-in lock of Bun 1.1.39–1.1.45, 1 the 1.2–1.3 default, 2 the 1.4+ default; all three emit one `packages` grammar, so the registry 4-tuple → URL 3-tuple rewrite is version-independent and the lock's own version line is kept. Any other or missing version, or a `packages` section outside bun's single-line grammar, is refused `redirect_bun_lock_unsupported` — the detail is the shared version gate's text (a newer version: update socket-patch, re-locking would reproduce it; no integer: re-lock with Bun ≥ 1.2), identical to the vendored refusal. A version-0 lock holding `workspace:` packages is refused `redirect_bun_workspace_unsupported` (its 2-tuple workspace grammar cannot keep the hosted tuple through a frozen install); the remedy is to delete `bun.lock` and re-run `bun install` with Bun ≥ 1.2, which writes lockfileVersion 1 (accepted). A plain in-place `bun install` bumps the version only when a workspace depends on another workspace (e.g. root → member — the shape the matrix measured); otherwise Bun 1.2.0 keeps version 0 and Bun 1.2.23+ fail to resolve, so the in-place bump is not the documented remedy. Bun lock version, grammar and workspace compatibility are checked before a vendored takeover, including during dry-run: these refusals preserve the existing lock, artifact and vendor ledger. Version-1 and version-2 workspace locks are rewritten, nested versions included. A granted dep with no rewritable entry warns `redirect_bun_entry_not_found`, a grant without a sha512 `redirect_bun_missing_sha512`; a CRLF lock keeps `\r\n` on the rewritten line, and a hosted URL left by an earlier grant of the same `name@version` is re-pinned in place. **Digest-less re-saves (Bun 1.1.39–1.3.9)**: every text-lock Bun below 1.3.10 re-saves a URL tuple WITHOUT its `sha512` whenever the lock is re-saved for another reason (`bun add`, `bun install` after a package.json or workspace change), leaving the 2-tuple `["name@<url>", {meta}]` — the spec Bun installs from is intact. The CLI treats that spelling as its own wiring: a repeat hosted run counts the dep as redirected (no `redirect_bun_entry_not_found`) and HEALS the line back to the 3-tuple with the current `sha512`, recording the heal as a further `redirect_bun_lock_package` edit whose `original` is the 2-tuple (a stale URL is re-pinned from either spelling); `rollback`, scoped `rollback <purl>` / `remove <purl>` and the vendored takeover accept the digest-less spelling of a recorded `new` line (same key, spec and meta, only the trailing `"sha512-…"` missing) and restore the recorded original over it, so the chain always unwinds to the pristine registry line. Anything else — another uuid/token, another version, a re-laid meta object — is still drift. **Native `bun.lockb`**: when no text `bun.lock` exists, binary format versions 1, 2 and 3 are read and rewritten directly. Socket Patch does not invoke Bun or convert the project to a text lockfile. Exact matching package records are rewritten to hosted tarballs with the granted integrity, preserving dependency resolution IDs, workspace/dependency topology and unrelated package metadata; binary pointers and the package metadata hash are updated. Per-package `redirect_bun_lockb_package` snapshots support scoped rollback, repeat runs, superseding grants and hosted ↔ vendored takeover. A regular binary lock is discoverable even with no Bun runtime or `node_modules`; a dry run previews the same binary edits without writing them. A malformed, unreadable, unsupported or unverified binary structure is `redirect_bun_lockb_invalid` (exit 0, `redirected: 0`), and it refuses the npm rewrite before any takeover or sibling npm-family lock mutation. A symlinked binary write target is `redirect_symlinked_file_unsupported` (exit 1, including dry-run). `bun.lock` wins when both spellings exist. Binary-only projects do not receive `redirect_npm_no_lockfile`. Measured boundaries and the real-Bun matrix: `docs/testing/bun-compatibility.md`). **Rush monorepos**: when `rush.json` is present the rewriter also reads `common/config/rush/pnpm-lock.yaml` and each `common/config/subspaces/<name>/pnpm-lock.yaml` (sorted for determinism) under their repo-relative keys and repoints them in place; editing them emits `redirect_rush_repo_state_stale` when `common/config/rush/repo-state.json` exists (the `pnpmShrinkwrapHash` desync is refreshed by `rush update`, which the redirect survives). **maven** is fail-closed via version suffixing: a `mavenSuffixedVersion` + `mavenPomSha256` override pins the Socket-only `<version>-socket.<hex8>` by rewriting the literal `<version>` (`redirect_maven_dep_version`) or adding a `<dependencyManagement>` entry (`redirect_maven_dep_management_added`), plus optional Trusted Checksums (`redirect_maven_trusted_checksums`, conflicts as `redirect_maven_trusted_checksums_conflict`); a `${property}` version is refused (`redirect_maven_dep_unpinned`), a non-matching literal skipped (`redirect_maven_dep_version_mismatch`), and an override without a suffixed version falls back to same-GAV repository injection (`redirect_maven_same_gav_fallback`, NOT fail-closed).

**Gem stale-install guard (additive warning — the canonical narrative; other mentions point here)**: the gem hosted rewrite is pure Gemfile/lock text, so a gem ALREADY materialized under the project's bundle paths keeps its upstream bytes — the next `bundle install` prints `Using <gem>` and never refetches, on **every** bundler major (live-verified 2026-08-19 on 1.17.3 / 2.7.2 / 4.0.18: bundler 4's CHECKSUMS verify at download time only, and nothing is downloaded; `bundle install --force`/`--redownload` re-install from the stale cached `.gem` instead of re-fetching — bundler 1 silently, bundler 4 with an exit-37 checksum refusal that still leaves the upstream bytes installed; the **verified** remedy is removing the installed dir + cache `.gem` + `specifications` entry, then `bundle install`). After the rewrite, a hosted run therefore probes the installed-gem discovery paths (the same ruby-crawler discovery `apply` uses, honoring `--global`/`--global-prefix` like scan's own discovery) for each confirmed gem redirect and judges the materialization against the patch record's `afterHash` file map. Judgment rules: records are found **by uuid** — this run's fetched records first, then the redirect ledger's persisted ones, so a transiently failed `/patches/view` fetch cannot retire the warning (it re-fires on every re-scan until the stale materialization is gone); a materialization with every file at `afterHash` is already patched and never warns (an agent→hosted migration stays quiet by construction), and when several confirmed variant purls resolve to one installed dir, ANY of them judging it patched keeps it quiet; staleness needs **positive evidence** — at least one record file whose bytes were actually read and hash to neither state's expectation — so missing or unreadable files never produce a warning. Warnings emit `redirect_gem_stale_install` (JSON `redirect.warnings[]` + a code-tagged stderr line) in three flavors: a PROJECT-LOCAL dir gets the verified delete-list remedy (installed dir, cache `.gem`, `specifications` entry — plus the project's committed `vendor/cache/<leaf>.gem` when present and not proven to be the patched artifact, since bundler installs from `vendor/cache` in preference to fetching); a SHARED gem-env home gets a caveat that the home is shared machine-wide and prefers migrating the project to a local bundle path over deleting shared files; and a committed `vendor/cache` archive whose sha256 differs from the patched artifact's warns standalone even with no installed dir at all (a fresh checkout with a committed stale cache re-materializes the upstream bytes forever). A stale-flagged purl is additionally **excluded from the same run's `--vex` `assume_applied` set** — the envelope must never attest a CVE its own warning says is live; the purl falls back to normal installed-tree verification (a patched install still attests, a stale one is omitted). The probe is read-only (nothing is deleted) and skipped on `--dry-run` — deliberately explicit, since nothing was rewritten but the ledger fallback could otherwise judge an already-redirected project. Exit code and `status` are unchanged (warning-only, the hosted-refusal posture); a same-run `--vex` may still fail on "nothing to attest" per the embedded-VEX contract.

**Pipenv hosted redirect (`Pipfile.lock`, pipfile-spec 6)**: every category other than `_meta` (`default`, `develop`, and Pipenv 2022+ named categories) that pins the package at the patched version is rewritten to the hosted reference — `{"file" | "path": "<artifact url>#sha256=<hex>", "hashes": ["sha256:<hex>"]}` with `markers`/`extras` preserved and `version`/`index` dropped; `_meta` (the Pipfile content hash) and the Pipfile itself are never touched, so `pipenv install --deploy`/`sync`/`verify` keep passing. The reference KEY depends on the installing Pipenv: releases 7–11 only install `path` references, 2018 and later `file` ones (0–6 write pipfile-spec < 6 and are refused). The release is probed once per command with `pipenv --version`, resolved on ABSOLUTE `PATH` entries only (a relative entry would run a `pipenv` planted in the scanned repository; `.bat`/`.cmd` shims are found through `PATHEXT` on Windows), only when a pypi patch actually targets an entry of the lock, and `SOCKET_PIPENV_MAJOR=<major>` pins the answer without spawning anything. An unknown installer selects `file` and warns `redirect_pipenv_installer_unknown` only when the lock was rewritten. **Refusal scope**: a pin/source CONFLICT (another version pinned, a foreign `file`/`path` source, a VCS/editable dependency) refuses the whole dependency atomically across categories as `redirect_pipenv_refused` AND vetoes the sibling Python rewriters (requirements.txt / uv.lock / pyproject) for that patch — the project's Pipenv install could not pick the patch up, so a half-redirected checkout is refused; anything else (no entry for the package, an old pipfile-spec, an unparseable lock, a digest-less patch) is `redirect_pipenv_skipped` and leaves the siblings alone (a stale Pipfile.lock in a uv/Poetry/requirements project must not block them). The veto applies to a LIVE lock only: a `Pipfile.lock` with no `Pipfile` beside it is abandoned, so its conflict refuses that file but never the siblings. Hash enforcement at install time is split by era — the `#sha256=` URL fragment is what Pipenv 2023+ verifies, the `hashes` list what 2018–2022 verify, Pipenv 11 either — so both are load-bearing. **Pipenv stale-install guard**: Pipenv never reinstalls a release that is already present (`pipenv install`, `install --deploy` and `sync` all exit 0 and keep the installed bytes — measured on 11.10.4, 2018.11.26 and 2026.8.0, hosted and vendored), so after the rewrite the run probes the Python crawler's site-packages (VIRTUAL_ENV, `./.venv`, `./venv`, Pipenv's out-of-tree `WORKON_HOME` venv; `--global`/`--global-prefix` honoured) for each confirmed Pipfile.lock redirect with the same rules as the gem guard (records by uuid with the ledger fallback, PATCHED = `verify_patch_record` Ok, STALE needs positive evidence, read-only, skipped on `--dry-run`, stale purls excluded from the same-run `--vex` `assume_applied` set) and the Python stale-install guard (`redirect_pypi_stale_install`, see above) names the site-packages dir and the Pipenv-specific verified remedy: `pipenv run pip uninstall -y <pkg> && pipenv sync` (or `pipenv --rm && pipenv sync`) — NOT `pipenv uninstall`, which rewrites the Pipfile and re-locks the patch away. The vendored backend emits the twin `pypi_pipenv_stale_install` (`skipped` warning event). **Rollback**: `redirect_pipenv_entry` edits replay per entry, compared as parsed JSON (a whole-file CRLF/LF conversion or a Pipenv re-serialization that kept our reference and hashes is not drift; the original is spliced back in the live file's line ending); an entry a relock removed retires the edit; a relock (`pipenv lock`, `update`, `install <other>` before 2024) regenerates the entry to registry shape on every Pipenv major and is NOT drift — the edit retires and the user's fresh resolution stands (vendored twin: `vendor_lock_entry_relocked`); a foreign `file`/`path` reference still refuses the pypi group. A Pipfile names no project, so a same-run `--vex` on a Pipenv project needs `--vex-product` (or a git remote) to detect a product purl. **Discovery**: `Pipfile.lock` is part of the lockfile inventory (every category's `==` pins, with the lock's digest set as `Sha256AnyOf` integrity so a lock-only checkout can be vendored by fetching the pure wheel through PyPI's JSON API — only when `_meta.sources` name the public index; a private-index lock stays discovery-only and never reaches pypi.org), and Socket's own hosted / vendored references stay discoverable as the package they replace, so a re-scan of an already-redirected or already-vendored lock-only checkout re-confirms it (`--vex` attests, vendored reports `already_vendored`) instead of finding nothing.

**Mode ledgers (contract surfaces).** Each committable mode persists its state at a stable repo-relative path; external tools (and the depscan backend's GitHub-app PR flows) read and write these files, so path + schema are part of the contract:

* `.socket/vendor/state.json` — the **vendored**-mode ledger (see "Ownership, state, and reversal" below): wiring edits with verbatim pre-vendor originals, artifact fingerprints, and the embedded patch `record` — for every entry written by `scan`/`get --mode vendored` beside `detached: true` (the record is that entry's only source), and for standalone `vendor` fed by an agent-mode manifest as a fallback copy without `detached` (the manifest record stays authoritative while the manifest covers the entry, by ledger key or base purl; `vex`, `list` and `setup --check` fall back to the embedded copy when it does not, `repair` only with no manifest at all). Entries written before 5.0 by standalone `vendor` carry no `record`; readers tolerate its absence.
* `.socket/vendor/redirect-state.json` — the **hosted**-mode ledger (`RedirectState` in `socket-patch-core/src/patch/redirect/state.rs`): `{ version, mode: "hosted", edits[], records{} }`. `edits` are recorded `FileEdit`s (append-only across re-runs — merge, never clobber: the pre-redirect originals a future revert needs live here; v5.0: a byte-identical re-save is skipped, which still satisfies the rule); `records` maps PURL → the full manifest `PatchRecord`, one of `vex`'s record sources for redirected patches with no manifest entry (a record attests only while a lockfile still wires its hosted patch — see "Manifest-less VEX" below). The `mode` string is opaque to the loader (pre-rename ledgers carrying `"redirect"` still load; a hosted re-run normalizes them to `"hosted"`). Written identically by this CLI and by the depscan backend's hosted PR flow (`github-patch-pr-hosted.ts`).

**get --mode and installed narrowing (v3.6).** `get <identifier> --mode hosted|vendored` consumes the resolved patch(es) through the SAME engines as `scan --mode hosted|vendored`, so for the same selected (purl, uuid) set the on-disk result is identical by construction — this is the per-advisory selector hosted/vendored previously lacked (the old workaround, `get <id> --save-only` then `vendor`, still works but is superseded). **Agent mode (v5.0 lock + residue rules)**: the download phase runs under `<.socket>/apply.lock` and hands the guard to the nested apply, so download → manifest write → apply is one lock window (the nested apply never re-acquires and inherits every caller flag — `--lock-timeout` and `--verbose` included); a failed acquire is `{status: "error", errorCode: "lock_held" | "lock_io", error}` on get's legacy envelope, exit 1, before any fetch (a read-only `.socket/` fails here, naming the lock path). `.socket/` and `.socket/blobs/` are created only when a record is actually persisted — an all-skipped or all-failed run leaves no `.socket/` on a fresh project — and a same-uuid `get <uuid>` re-run rewrites neither the manifest nor the blobs. Semantics:

* **Hosted** (`get GHSA-… --mode hosted`): resolves the advisory, then hands the selected (purl, uuid) pairs to scan's hosted engine — reference grants, cross-mode takeover pre-revert, lockfile rewrite, `redirect-state.json` ledger (merge-never-clobber), gem stale-install probe, warnings, confirmation rules (cargo via `confirmed_cargo_uuids`, golang via `confirmed_golang_uuids` only) all identical to `scan --mode hosted`, and (v5.0) under the same `apply.lock` acquisition — taken around the first wet write, never on `--dry-run` or when nothing would be written; a failed acquire folds as top-level `errorCode: "lock_held" | "lock_io"` + string `error` (exit 1), and `--dry-run` under a held lock still exits 0. **No manifest write, no blobs** — the ledger is the persistence. JSON: get's legacy envelope gains the same nested `redirect` sub-object as scan's (`{mode:"hosted", redirected, rewrittenFiles, skipped, warnings, dryRun}`); the top-level shape is `{status, found, patches:[<narrowing skips>], warnings?}` — `downloaded`/`applied` are absent (nothing is downloaded into `.socket/`). Exit codes follow scan's hosted semantics: skipped grants and rewriter warnings never flip the exit; infra errors (reference fetch, corrupt/unwritable ledger, file writes) exit 1. Human prompt: `Redirect N packages to the hosted patch server?` (singular for one; get keeps its confirm gate, `--yes`/`--json`/non-TTY auto-accept as usual; as of v5.0 human `scan --mode hosted` prompts too — see the hosted section above).
* **Vendored** (`get GHSA-… --mode vendored`): the download phase is scan's vendored posture — **manifest-free (v5.0)**: the selected records are fetched into memory (`download_patch_records`; blobs held in memory; nothing under `.socket/` is written; the nested apply never runs), then scan's vendor step runs under the apply lock over exactly the selected records, like `scan --mode vendored` (no whole-manifest scope and no `[note]` about other records — that blast radius is retired with the manifest; a legacy manifest record for a vendored purl is migrated out of `.socket/manifest.json` the same way scan does it). JSON: get's envelope takes the detached download envelope's shape — `{status, found, downloaded, skipped, failed, detached: true, patches: [{purl, uuid, action: "downloaded" | "skipped" | "failed", …}], warnings?}` (`applied` is absent; `detached: true` is pinned; a `downloaded` record for a purl the vendor ledger holds at another uuid carries the additive `oldUuid`, derived from the ledger — the human `[fetch]` line reads `<purl> (replacing <short uuid>)`) — and gains the nested `vendor` Envelope exactly like scan's `result["vendor"]`; a vendor-step error folds the partial envelope + `{status:"error", error:{code,message}}` in (a pre-failure takeover reconcile may have already mutated the ledger — its events must reach the consumer). Exit: download failures or vendor `has_errors` → `partial_failure`/1. Human prompt: `Download and vendor N patches?`; `--dry-run` prints `[dry-run] Would download and vendor N patches. No changes made.` on both identifier paths (uuid and search). Telemetry mirrors scan's vendored arms (`track_outcomes_for_vendor` / `track_patch_vendor_failed`). **Bun vendored preflight (additive)** — shared by `get --mode vendored` on both its paths and `scan --mode vendored`: before ANY patch download, and only when the selection holds a `pkg:npm/` purl, the download phase reads `bun.lock`/`bun.lockb` once (`preflight_vendor`) and, when the vendor backend would refuse the project — a malformed, unreadable or unsupported `bun.lockb` → `vendor_bun_lockb_invalid`; an unreadable `bun.lock` → `vendor_lockfile_missing`; a `lockfileVersion` other than 0/1/2 or a non-canonical `packages` grammar → `vendor_lockfile_version_unsupported`; `workspace:` packages in a lock below version 2 → `vendor_bun_workspace_unsupported` — every `pkg:npm/` result becomes `{action:"failed", errorCode:<code>, error:<detail>}` with NO fetch (the patch view is never requested) and no patch record; other ecosystems' results are untouched. **Search path** (`get <purl|advisory> --mode vendored`) and `scan --mode vendored`: the records ride `patches[]` / `download.patches[]` with `downloaded: 0`, the download phase writes nothing under `.socket/` (v5.0 — a pre-existing `.socket/manifest.json`, including a record seeded for another purl, is left byte-untouched; previously the run re-serialized the manifest), the vendor step still runs over the remaining records (no event for the refused purl), exit `partial_failure`/1. **uuid path** (`get <uuid> --mode vendored`): the uuid lookup is the only fetch; the run exits 1 BEFORE the vendor step with exactly `{status:"error", found:1, downloaded:0, skipped:0, failed:1, error:{code, message}, patches:[{purl, uuid, action:"failed", errorCode, error}]}` (the `error` OBJECT is the vendored-mode error shape of the vendor-step fold-in above) and writes nothing — no `.socket/` on a fresh project; human mode prints `Error (<code>): <detail>` on stderr. **Already-vendored exemption**: a purl is exempt from the workspace refusal only when every instance of its `name@version` in `bun.lock` is already a `.socket/vendor/npm/…` local tuple (any uuid; the digest-less 2-tuple counts) — the engine's own criterion — so in-sync re-runs, `repair`, and a superseding patch uuid on a project vendored before it grew a workspace member all flow to the engine (re-pinning an already-local tuple adds no workspace-relative exposure); a wiped ledger alone is not a refusal (the engine path decides). UUID equality in the ledger alone never exempts a purl: `rollback --preserve-state` retains its record after unwiring. Dry-run refusal takes priority over `already_vendored`. **Unreadable vendor ledger**: a `.socket/vendor/state.json` the preflight cannot read or parse is itself the refusal — `vendor_state_unreadable` with the io/parse detail, fail-closed (nothing is exempt) — on the uuid path, the search / `scan` path and the `--dry-run` preview alike; never a Bun lock code. **`--silent`** is "errors only" and never mutes the refusal: the code-tagged `[error] <purl> (<code>): <detail>` (per-patch paths) / `Error (<code>): …` (uuid path) line stays on stderr with an empty stdout. **`--dry-run`** previews the refusal as the additive `would_refuse` action (see `--dry-run` below). Agent-mode `get --save-only` is NOT preflighted (record-only intent has no consumption precondition). Pinned by `tests/in_process_vendor_bun.rs` (exact uuid-path envelope, seeded-manifest survival, `--silent`, `--dry-run`) and `tests/scan_vendor_e2e.rs`.
* **Installed-version narrowing** (all modes, `get`'s search path): a CVE/GHSA fan-out returns one patch record per patched VERSION; get keeps only versions present here and emits calm `skipped` records (`errorCode: "package_not_installed"`) for the rest — never an error exit. Presence = installed on disk (qualified-aware resolver) ∪ already tracked in the manifest (record maintenance keeps working on hosts without an installed copy); hosted/vendored modes additionally count lockfile-resolved deps and vendor-ledger purls (mirroring scan's discovery supplements, including their `--global` gate). **Exempt** (no narrowing): UUID identifiers, exact-versioned PURL identifiers (explicit intent), `--save-only` runs (record-only has no installation precondition — the fresh-clone record→vendor flow keeps working), `--all-releases`, and the package-name path (already installed-derived). When EVERY found patch is filtered out, get exits 0 with the additive status **`not_installed`** (`{status:"not_installed", found:N, downloaded:0, applied:0, patches:[<skip records>], warnings?}`) — never `no_match`, which remains pinned to the fuzzy package-name path. PnP layouts are surfaced, not misreported: yarn-PnP npm results skip with `errorCode: "yarn_pnp_unsupported"` in every mode; pnpm-PnP skips carry `pnpm_pnp_unsupported` in agent/vendored modes; hosted mode — the refusal's own remedy — keeps ONLY the versions the raw `pnpm-lock.yaml` text actually resolves (boundary-anchored probe over the v5/v6/v9 key spellings, so a large fan-out never requests grants for every version ever patched), labels a JUDGED miss `package_not_installed` exactly like a non-PnP project (the layout blocked nothing — the lock was read and the version isn't resolved), and reserves the layout code for an unreadable lock (no judgment possible). When EVERY narrowed-out result is a PnP refusal, the human terminal names the layout instead of claiming "not installed" and never advises `--all-releases` (which cannot make PnP patchable); the JSON status stays `not_installed` — consumers dispatch on the per-record `errorCode`. Hosted mode also runs the per-release VARIANT filter (`filter_to_installed_releases`) on its search path before requesting grants — agent/vendored runs get it inside the download engines — with the same keep-all-plus-warning fallbacks (surfaced as `(release_narrowing)`-prefixed strings in `warnings[]`). An ecosystem this binary has no crawler for is likewise never judged: its results are KEPT (absence from a crawl that never looked carries no information — the same fail-safe as scan's prune GC). The human `Found N patches:` listing shows only the patches whose package version survived the narrowing (the narrowing is judged over every result, so an installed package's paid fix a free user cannot download still lists as `[PAID] (no access)`, while skip records and counts cover only accessible patches), sorted by PURL in natural version order (`4.17.2` before `4.17.10`); the narrowed-out ones are summarized on stderr in one line per reason (`Skipped N patches for M package versions not installed here (use --all-releases to include them).`), and `--verbose` adds one `[skip] <purl> (<reason>)` line per skipped version after that summary, in natural version order. When the candidates hold more patches than were selected and the pick was made without a menu (a paid user's auto-pick, `--yes`, a non-TTY run), a `Selected:` block names the patch (purl, tier, short uuid, advisories) that will be installed before the prompt. Machine output (the prompt count, the JSON envelope) uses the kept set, unchanged. The finer per-release variant narrowing (`filter_to_installed_releases`) is unchanged and still runs inside the download engines (and before an agent-mode `--dry-run` preview, so the preview names only the variants a wet run would fetch).
* **Deliberate divergences from scan** (documented, not drift): get keeps its `selection_required` JSON posture for free multi-patch PURLs (scan auto-picks); get has no `--vex` (an ambient `SOCKET_VEX` is ignored by get's modes), no `--detached` (moot — `get --mode vendored` is manifest-free by construction), no `--prune`; get does not run scan's pre-confirm vendor baseline annotation; and an all-narrowed-out run exits `not_installed` without entering the vendor step (heal-after-wipe re-vendoring stays `scan --mode vendored`'s job). Agent-mode `get` honors `--dry-run` too (v5.x; it used to download, save and apply anyway): the search and uuid paths classify each selected patch against the manifest (read-only; an unreadable manifest fails closed like the wet run) and stop before the prompt, the download, any `.socket/` write and the apply — human `[would-add]` / `[would-update] … (replacing <short uuid>)` / `[skip] … (already in manifest)` lines then `[dry-run] Would download and apply N patches. No changes made.`; JSON `{status:"success", dryRun:true, found, downloaded:0, skipped, applied:0, patches:[{purl, uuid, action:"would_add"|"would_update"(+oldUuid)|"skipped"}, <narrowing skip records>], warnings?}`, exit 0.

`--dry-run` previews what `apply` / `rollback` / `scan --apply` / `repair` / `remove` — and `get` in every mode (hosted/vendored since v3.6, agent since v5.x) — would do without mutating disk. `get --mode hosted --dry-run` flows through the hosted engine's dry-run contract (no lock, no `.socket/`, no ledger write, no lockfile writes, `redirect.dryRun: true`); `get --mode vendored --dry-run` emits the same ledger-classification preview as scan's (`would_vendor` / `already_vendored` / `would_revendor`+`oldUuid` under the nested `vendor` key — plus, additive, `would_refuse` + `errorCode` + `error` for npm purls the wet run's Bun preflight would refuse: an in-sync `already_vendored` entry is exempt, as is a `would_revendor` entry whose `bun.lock` instances are all already local tuples; a purl the lock still resolves from the registry is refused like a fresh one, and the preview stays exit 0 / `status: "success"` with nothing written) before any download, and both skip the confirm prompt (nothing to confirm). In JSON mode, the envelope is populated with would-be actions and counts (`remove --dry-run` skips the confirmation prompt — there is nothing to confirm — and flips its would-be `Removed` events to `Verified` previews, so `summary.removed` stays "entries actually deleted"). `rollback --dry-run` (v5.0) previews every leg — the in-place restore verification, the vendored unwire (`Would revert/unwire vendoring for …`), the hosted unwind (the redirect engines resolve every inverse and drift check exactly like a wet run, flush nothing to disk, and claim the IN-MEMORY ledger clone exactly like a wet run — so the composed preview, per-purl reverts then whole-ledger replay, sees the same intermediate state a wet run would; the ON-DISK ledger is untouched), the manifest removals (simulated in memory), and the blob/archive GC — with no writes and no prompt.

The hidden alias `--no-apply` on `get --save-only` is **part of the contract** — it does not appear in `--help` but is widely used in existing scripts.

`repair` keeps its `gc` visible alias.

**Python stale-install guard**: after a hosted redirect, `scan` / `get` use the Python crawler to inspect every matching installed package, including Poetry's out-of-tree virtualenvs and `--global-prefix`. A readable file that differs from the patch's `afterHash` emits `redirect_pypi_stale_install` in JSON `redirect.warnings[]` and human stderr. The probe changes no installed files, re-runs on idempotent scans, and falls back to persisted patch records when fresh record fetching fails. Missing/unreadable files alone do not prove staleness; lock-only checkouts stay quiet. Dry runs skip the probe. Same-run VEX excludes positively stale Python packages (qualifier-insensitive), even with `--vex-no-verify` or a healthy copy in another interpreter; if nothing remains to attest, the command exits 1 with `no_applicable_patches`. Reinstall from the rewritten lock in the affected interpreter and verify with `socket-patch vex`.

### Embedded VEX (`apply --vex` / `scan --vex` / `vendor --vex`)

`--vex <path>` folds OpenVEX 0.2.0 generation into `apply`, `scan`, and `vendor`: on a successful run the command writes the document to `<path>` using the same engine as the standalone `vex` command. The `--vex-*` flags mirror `vex`'s `--product` / `--no-verify` / `--doc-id` / `--compact` knobs (namespaced to avoid colliding with the host command), and reuse the standalone env vars (`SOCKET_VEX_PRODUCT`, etc.). They are inert unless `--vex` is set.

Contract details:

* **Always written to the file** — never stdout — so the document never races the command's own `--json` output.
* **Fail-the-command**: if `--vex` was requested but generation fails (product PURL undetectable, nothing to attest in the manifest / ledgers / lockfiles, all patches omitted, a corrupt ledger, unwritable path), the command exits non-zero **even when the apply/scan itself succeeded**. In `--json` mode the failure surfaces in the envelope's `error` (`apply`) / top-level `error` (`scan`), with a stable code (`product_undetected`, `no_applicable_patches`, `write_failed`, …).
* **Built from the post-run state** — the manifest, both `.socket/vendor` ledgers and the project's lockfile references (see "Manifest-less VEX" below) — and verified against on-disk state (unless `--vex-no-verify`; the wiring gates apply either way). Generated for real applies and read-only `scan` alike; `--dry-run` skips generation on every host command (nothing was changed, and a preview must not write an attestation — `scan --json` marks it `vex: {skipped: true, reason: "dry_run"}`).
* **JSON success surface**: `apply` adds a top-level `vex` object to its envelope; `scan` adds a top-level `vex` key to its result. Both carry `{ path, statements, format: "openvex-0.2.0" }`.
* `apply`'s no-manifest early exit (the `noManifest` success no-op; v5.0: its human line is `No patch manifest found; nothing to apply.` — it names the missing `.socket/manifest.json`, not the folder, since `.socket/` may legitimately hold setup files or vendored state) and `vendor`'s (`No manifest found, nothing to vendor.`) still generate the document from the lockfiles and `.socket/vendor` ledgers (manifest-less VEX: hosted / vendored checkouts carry no manifest). Nothing referenced anywhere keeps the calm exit 0 (a stale document at the path is removed; `--json` carries any discovery diagnostics in `warnings[]`); any other VEX failure fails the command with exit 1 — including a run whose only candidates are omitted `record_unavailable` (an `--offline` run over a lockfile-wired checkout with no local records), so an ambient `SOCKET_VEX` there fails the install. `--dry-run` skips generation on both, and so does `apply --check` — it stays read-only and offline-safe, leaving the output path untouched. `scan` has no such early exit: with no manifest and nothing wired anywhere its `--vex` fails with `manifest_not_found`.
* **Stale-doc removal (v3.5)**: a run that ends in a VEX error removes a recognizably-OpenVEX file (JSON whose `@context` names openvex.dev) already sitting at the output path — a pipeline reusing one path can never ship yesterday's attestation for a now-unpatched tree. Unrelated files at the path are never touched; a mid-write partial that no longer parses as JSON is left for downstream parsers to reject loudly.
* **Additive warnings (v3.5)**: `product_not_iri` (the `--product`/`--vex-product` override is neither a `pkg:` purl nor an absolute IRI; honored verbatim, warned) and `vendored_tree_out_of_sync` (a healthy vendored attestation stands on the committed artifact + lock wiring while the PRESENT installed tree hash-mismatches the patched bytes — run the package manager's install; the attestation itself is unchanged). Both ride stderr in human mode and `warnings[]` in the standalone `vex --json` envelope. Same channel for `product_multiple_manifests` (auto-detect found several project manifests and names the one it used), `vex_stale_doc_removed` (the stale-doc removal above happened), the manifest-less plan's advisories — `vex_wiring_conflict` (the lockfiles wire a package to different patches: which files, which uuids, how to fix it), `vex_record_superseded` (a recorded patch replaced by the lockfile-wired one), `vex_claim_unwired` (a ledger claim whose patch the lockfiles still mention, but not as wiring), `vex_record_offline` / `vex_record_not_found` / `vex_record_fetch_failed` (why a lockfile-wired patch has no record — the detail behind a `record_unavailable` skip) and `api_auth_fallback` (the authenticated API refused the credentials and the public proxy served free patches only; `get` / `scan`'s warning text) — and, standalone only, `org_looks_like_path` (`-o`/`--org` given a file-shaped value — `-O` is `--output`). The standalone error envelope carries `warnings[]` too. An embedded `--vex` that fails also folds each omitted patch into the host command's `warnings[]` as `vex_omitted` (`<purl>: <why> (<errorCode>)` — standalone `vex` lists them as `skipped` events), and `--silent` lists them as `omitted: <purl> (<errorCode>)` lines under the error. A corrupt `.socket/vendor/state.json` or `redirect-state.json` is no longer degraded with a warning: every form of vex fails with `vendor_ledger_corrupt` / `redirect_ledger_corrupt` (see the error-code table).

### VEX provenance markers (contract)

Every VEX statement's impact string records which patch-application mode persists the patch. The three marker strings are **stable contract surfaces** — scanners and policy engines match on them, so renaming or reformatting any of them is a MAJOR change:

| Impact statement | Mode | Verification evidence |
|---|---|---|
| `Patched via Socket patch <uuid>` | agent | installed-tree file hashes vs the manifest's `afterHash` |
| `Patched via Socket patch <uuid> (vendored)` | vendored | the committed `.socket/vendor/` artifact (no install hook needed) |
| `Patched via Socket patch <uuid> (redirected)` | hosted | the lockfile's hosted integrity pin; in-run `scan --mode hosted --vex` attests from the redirect ledger WITHOUT hash verification (the JSON `vex` summary carries `verified: false`), while a post-install `socket-patch vex` re-proves the lockfile wiring and hash-verifies the installed copy the build consumes — or, with nothing installed, attests a discovered lockfile reference from its integrity pin (see "Manifest-less VEX") |

`vendored` and `redirected` are disjoint in practice (the modes conflict); if a PURL somehow appears in both sets, `vendored` wins.

**Patch hosts (manifest-less VEX).** A hosted lockfile reference counts only when it points at Socket's patch server or the operator's `--patch-server-url` / `SOCKET_PATCH_SERVER_URL` origin. A redirect-ledger record whose recorded wiring names its patch on any OTHER host — a staging patch server used without `--patch-server-url`, or a look-alike host — is judged by the ledger's own recorded wiring: with verification on it attests only an installed tree that hashes to the record (nothing installed is `package_not_found`, pristine bytes `not_applied`), but `--no-verify` / `--vex-no-verify` trusts the records by definition and attests it `(redirected)`, because the wiring gate cannot tell a staging host from a hostile one. Pass `--patch-server-url` for a non-production patch server, and do not combine `--no-verify` with lockfiles you do not trust.

### Manifest-less VEX (lockfile discovery)

`vex` and every embedded `--vex` attest hosted and vendored patches without `.socket/manifest.json`, and without the `.socket/vendor` ledgers too, by reading the wiring out of the project's lockfiles and package-manager configs. This covers a depscan-opened PR, a clone of a repo that never committed its ledgers, and a `scan --mode hosted` checkout. The merge lives in `commands/vex_sources.rs`; discovery lives in `socket-patch-core/src/vex/discover/`.

**Inputs.** Four sources feed one record view:

1. `.socket/manifest.json`. A missing file counts as empty.
2. The redirect ledger's `records`.
3. The vendor ledger entries' embedded `record`s.
4. Lockfile discovery.

Discovery is read-only, never touches the network, and never fails the run: a malformed file becomes a diagnostic. It reads files at `--cwd`, the root where the ledgers are read, and it does so under `--global` / `--global-prefix` as well, because discovery is what gates the ledgers (below). It reads only root files (no nested workspace-member locks) except where noted, and it reads **every** supported file that is present. There is no precedence chain: the hosted rewriter edits every candidate it finds, so a lock that another lock "shadows" can still carry wiring. Every value is committed, tamperable data, so each one is validated fail-closed: canonical uuid grammar, path-safe coordinates, root-anchored `.socket/vendor/` paths, and the patch-host allowlist.

| Ecosystem | Files read | Hosted reference | Vendored reference | Hosted pin (`integrity_required`) |
|---|---|---|---|---|
| npm | `package-lock.json` and `npm-shrinkwrap.json` (both when both exist) | `resolved` on the patch host (`packages` in v2/v3; `dependencies` only in v1; `link` / `inBundle` / `bundled` entries skipped) | `resolved: file:.socket/vendor/npm/<uuid>/<name>-<ver>.tgz` | `integrity`, required |
| pnpm | `pnpm-lock.yaml` (every `lockfileVersion`); `shrinkwrap.yaml` only when there is no `pnpm-lock.yaml`; with `rush.json`, `common/config/rush/pnpm-lock.yaml` + `common/config/subspaces/*/pnpm-lock.yaml` | `packages:` `resolution.tarball` on the patch host | `file:.socket/vendor/npm/…` tarball + key | `integrity`, required |
| yarn | `yarn.lock` (classic and berry) | classic `resolved`; berry `resolution: …::__archiveUrl=<url>` | classic `resolved "file:./.socket/vendor/npm/…#<sha1>"`; berry `file:` entry **plus** a root `package.json` `resolutions` mapping onto the same artifact (without it the entry is orphaned: diagnosed, no ref) | classic `integrity` / `#sha1`, berry `checksum`, required |
| bun | `bun.lock`; `bun.lockb` only when there is no `bun.lock` (bun reads exactly one) | URL tuple / binary remote-tarball resolution; version from the URL leaf | `.socket/vendor/npm/<uuid>/<name>-<ver>.tgz` tuple / local-tarball resolution | `sha512-…`, required. A 2-tuple that Bun < 1.3.10 re-saved without its digest is still a reference, but it attests only from an installed tree. |
| cargo | `Cargo.lock`, `Cargo.toml`, `.cargo/config` (else `.cargo/config.toml`) | `Cargo.lock` `source = "sparse+…/<uuid>/index/"`, confirmed by `Cargo.toml`: a crate the root manifest declares must pin `registry = "socket-patch-<uuid>"`. A reverted pin is diagnosed, no ref. | `[patch.<source>] <key> = { path = ".socket/vendor/cargo/<uuid>/<name>-<ver>" }` — primarily the root `Cargo.toml` (v5 `vendor`; key-agnostic: `<name>` is `package` when renamed, else the key, so `<name>-socket-<uuid8>` keys count), also the project config (pre-v5 wiring), live only while the lock holds a sourceless entry for it that is not in `[[patch.unused]]`; a manifest entry cargo ignores — the project config redefines its key with another path, or a `[patch."https://github.com/rust-lang/crates.io-index"]` table replaces `[patch.crates-io]` — is diagnosed (`patched_ref_invalid`), no ref | `checksum` (v1: `[metadata]`), required |
| golang | `go.mod`, `go.work`, `go.sum`, `go.work.sum` | `replace M v => patch.socket.dev/gopatch/<uuid> <sver>` | `replace M v => ./.socket/vendor/golang/<uuid>/M@v` | both go.sum lines, required. A replace that `require` no longer selects (`require M v'`) is inert: diagnosed, no ref. |
| pypi | `uv.lock` (confirmed by `pyproject.toml` `[tool.uv.sources]` when present), PEP 723 `<script>.py.lock`, `pylock.toml` / `pylock.<name>.toml`, `poetry.lock`, `pdm.lock`, `Pipfile.lock`, `requirements.txt` + its in-root `-r` includes, PEP 508 direct references in `pyproject.toml` / `hatch.toml` | Socket-host artifact url | `.socket/vendor/pypi/<uuid>/<wheel>` naming the entry's own dist | sha256, required |
| gem | `Gemfile.lock` and `gems.locked` (the `Gemfile` / `gems.rb` only to cross-check a merged multi-remote `GEM` section) | a `GEM` section whose remote ends `patch-registry/gem/<token>/<uuid>` | `PATH` remote `.socket/vendor/gem/<uuid>/<name>-<ver>` | `CHECKSUMS` sha256, required only when the lock has a `CHECKSUMS` section (bundler ≥ 2.6) |
| composer | `composer.lock` (`packages` + `packages-dev`) | `dist.url` on the patch host | `dist: {type: "path", url: ".socket/vendor/composer/<uuid>/…", reference: "<uuid>"}` | `dist.shasum`, required |
| maven | `pom.xml` (+ `.mvn/maven.config`, `.mvn/checksums/checksums.sha256`) | a dependency version `<base>-socket.<hex8>` matching exactly ONE `socket-patch-<uuid>` repository on the patch host | `socket-patch-vendor-<uuid>` repository + exactly one jar under `.socket/vendor/maven/<uuid>/` with a matching `.sha1` | Trusted Checksums line when enabled; not required (the suffixed version is the pin) |
| nuget | the first of `nuget.config` / `NuGet.config` / `NuGet.Config`, + `packages.lock.json` | source `socket-patch-<uuid>` + its exclusive exact-id `<packageSourceMapping>`; version from `packages.lock.json` | the same mapping onto `.socket/vendor/nuget/<uuid>`; version from the lock, else the feed's single nupkg | `contentHash`, required |
| deno | none | — (no hosted mode) | — (no vendored backend) | — |

Recognition rules that hold for every ecosystem:

* **Patch hosts.** A hosted reference counts only on `https://patch.socket.dev` or the `--patch-server-url` / `SOCKET_PATCH_SERVER_URL` origin, with no userinfo. The uuid is the URL's LAST canonical-uuid path segment, because grant tokens may themselves be uuid-shaped. The Go module prefix is fixed. `socket-patch-<uuid>` registry / repository / source names count only through a pin. For a redirect-ledger record on any other host, see **Patch hosts** above.
* **Pins, not definitions.** A registry, index or source *definition* alone (cargo `[registries]`, nuget `<add>`, pom `<repository>`, uv index tables, `.npmrc`) never makes a reference, because it survives a reverted pin. Sections the package manager ignores are not read: npm's v2 `dependencies` mirror, a `.cargo/config.toml` shadowed by `.cargo/config`. A Socket pin inside a maven `<profile>` is diagnosed, never a reference.
* **Contested locks.** When one lock wires a package to a patch and another lock resolves the same `name@version` from a non-Socket source, the build's bytes depend on which package manager runs. The reference is then dropped with a `patched_ref_unattributable` diagnostic naming both files. This applies across npm / pnpm / yarn / bun and across uv / pylock / poetry / pdm / Pipfile.lock / requirements. PEP 723 script locks neither contest nor are contested.
* **Lockless pins.** With no lock to name a version, a `Cargo.toml` pin (every declaration on `socket-patch-<uuid>`, that registry defined on the patch host for the same uuid) or an exclusive nuget exact-id mapping is never a reference on its own. It still keeps a redirect-ledger record live for a version the pin admits.

**Record resolution.** A candidate's record must carry the patch uuid the lockfile actually **wires**. It is taken from the first source that has one: the manifest (matched qualifier-insensitively), the redirect ledger's `records`, then the vendor ledger's embedded records. If none has it and the run is online, `vex` fetches the patch view by uuid from the patch API. The fetch uses `get`'s API client: the public proxy when no token is configured, and a one-shot 401/403 fallback to the proxy (free patches only). At most 10 fetches run concurrently. Fetched records stay in memory: `vex` never writes the manifest. A candidate still has no record under `--offline`, after a transport error or a 404, or when the patch is refused (paid without an entitled token); it is then omitted as `record_unavailable`, and the run is not aborted. A record whose uuid or package disagrees with the wiring is omitted as `record_mismatch`. The informational `socket-patch.vendor.json` marker is never a record source. When the lockfile wires a package to patch U, a manifest or ledger record for that package under another uuid is superseded, and a human-mode `Note:` says so.

**Verification basis.** `(vendored)` and `(redirected)` patches bypass the Property 7 ecosystem filter, because their wiring is the persistence. With no manifest there is no `setup.manual`, and none is needed.

| Wiring | Evidence (verify mode) | Marker |
|---|---|---|
| Vendored: a lockfile/config wires a `.socket/vendor` artifact, or a live vendor ledger entry | The **committed artifact** is hashed against the record's `afterHash`. The ledger entry is used when it names the wired artifact (it carries the dir-artifact inventory); otherwise an entry is synthesized from the reference. A present installed tree with different bytes only warns `vendored_tree_out_of_sync`. | `(vendored)` |
| Hosted: a discovered patch-host reference, or a live redirect-ledger record | The installed copies the build **consumes** through the hosted wiring are hash-verified when any exist: the Go replacement module, never the pristine `M@v` in the module cache; the Socket-registry cargo source dir; maven's suffixed version. Installed evidence wins: `hash_mismatch` / `not_applied` are omitted. With **nothing installed**, a discovered reference whose lock pins the artifact (or whose format's rewriter never writes a pin) attests from that pin, which is the same evidence as in-run `scan --mode hosted --vex`. A ledger-only record, or a reference whose required pin is missing, stays `package_not_found`. So do purls that `--ecosystems` kept out of the crawl, because "not installed" has to mean the crawler looked. | `(redirected)` |
| Agent: a manifest record with no live hosted/vendored wiring | The installed tree, unchanged | none |

**Liveness gates.** These gates run before hashing, and `--no-verify` / `--vex-no-verify` skips only the hashing, never the gates:

* A **vendor ledger entry** attests only while some lockfile or config still wires its artifact. Otherwise it is omitted as `vendor_unwired`. The exception is a hosted takeover: the same package with a live redirect record falls through to that hosted claim.
* A **redirect ledger record** attests only while a lockfile still wires its hosted patch. Otherwise it is omitted as `redirect_unwired`. The exception is a manifest-owned purl, which falls back to agent-mode verification. The purls that an in-run `scan --mode hosted --vex` itself confirmed count as live.
* **Discovery is authoritative** for every patch uuid that a file it read *mentions*: the accepted references alone decide. A mention an extractor rejected keeps nothing alive, whatever raw text survives. That covers an orphaned berry entry, an inert Go replace, a reverted cargo pin, a uv lock its `pyproject.toml` does not confirm, a shadowed maven pin, a contested lock, a commented-out line and an unparseable lock. Only for a uuid that no read file mentions (formats no extractor reads, patch hosts outside the allowlist) does the ledger's own recorded wiring decide. Even then, only files that PIN the resolution count, never a leftover registry definition.
* **Wiring conflict.** When the lockfiles wire one package to two or more different patches, every candidate for that package is omitted as `wiring_conflict`, with a note naming the patches.

A reverted lockfile plus a leftover ledger or artifact therefore stops attesting, even under `--no-verify`.

**Run warnings.** Discovery diagnostics surface as run warnings. In human mode they print on stderr as `Warning: <detail>`, and the detail names the file. Under `--json` they go to the standalone envelope's `warnings[]` or the embedded `vex.warnings`; on a failed run they go to the command's top-level `warnings[]`. The codes (additive; new codes are MINOR):

| Code | Meaning |
|---|---|
| `lockfile_unreadable` | A supported file exists but could not be read (permissions, a FIFO squatting the name, non-UTF-8). |
| `lockfile_unparseable` | A supported file is not valid for its format. Nothing is discovered from it, and its Socket mentions are dead. |
| `patched_ref_invalid` | A Socket-shaped reference failed validation or is not live wiring: unsafe coordinates, a non-canonical uuid, a leaf naming another package, a path escaping the root, an inert or orphaned entry. |
| `patched_ref_unattributable` | A Socket patch uuid cannot be tied to exactly one artifact / version. Examples: a maven repository no pin names, a nuget source without a mapping, a lock contested by another lock. |

Human mode also prints `Note:` lines: superseded records, fetch failures, `--offline` withholding fetches, conflict details, and why a claim is dead. While patch records are fetched, a terminal shows a transient `Fetching patch records... (n/N)` status line on stderr (never under `--json` / `--silent`).

**Output.** A manifest-less run honors every `vex` output convention: `--output -` (or `-O -`) prints the document to stdout; `--dry-run` still discovers, fetches records and verifies, but writes nothing and leaves a previous document at the path alone (`[dry-run] Would write …`, `dryRun: true`); an embedded `--vex` under `--dry-run` skips generation with the shared `Skipping VEX generation (--dry-run: nothing was …).` line.

## Setup command contract

`setup` wires a repository for **automatic patching**: after the ecosystem's own install/build step
runs, locally-installed dependencies are re-patched to match the Socket manifest (`.socket/manifest.json`)
with no further human action. It does this by installing an ecosystem-native hook (see the support
matrix below). `setup --check` verifies that state; `setup --remove` reverts it.

The properties below are the public contract. Each is backed by a test under
`crates/socket-patch-cli/tests/setup_*.rs`; properties not yet fully implemented are called out
explicitly and guarded by a deliberately-failing (RED) test that encodes the intended behavior — these
are the executable spec for follow-up work, **not** regressions. Changing any property below is governed
by the [semver policy](#semver-policy) (scoping `setup` by `--ecosystems` and strengthening `--check`,
in particular, are behavior changes that gate a version bump when implemented).

1. **Idempotent.** Re-running `setup` on an already-configured repo changes nothing: status
   `already_configured`, `updated: 0`, every manifest byte-identical. *(Implemented.)*

2. **Ecosystem-scoped.** `setup`, `setup --check`, and `setup --remove` honor the global
   `--ecosystems` filter and act on only the named ecosystems; with no filter they act on every
   detected ecosystem. *(Intended; **not yet implemented** — `setup` currently ignores `--ecosystems`
   and always processes every detected ecosystem (npm + python + gem). RED-guarded.)*

3. **Consistency after install.** Once an ecosystem is set up, its locally-installed dependencies are
   re-patched to match the manifest after **any** of: a dependency added, updated, or removed; **or** a
   new patch added to the manifest. The re-patch is carried by the ecosystem's install hook (npm
   `postinstall`/`dependencies`, the Python `.pth` startup hook, the gem Bundler plugin) which runs
   `socket-patch apply` after the ecosystem's installer finishes, so patch state always reconverges with
   the manifest. *(Implemented for npm/pypi/gem via the support matrix. Cargo and Go have no `setup`
   hook — see "Cargo and Go: apply-only, no setup" below.)*

4. **`check` proves a correctly-patched state.** `setup --check` reports `configured` only when the
   in-scope ecosystems are *actually in a correctly patched state* — install hooks present **and**
   on-disk patch consistency verified (the `apply --check` invariant: every manifest file's hash matches
   `afterHash`). *(Implemented — `run_check` appends a `patch` entry per installed-but-drifted PURL via
   `append_patch_consistency_entries`; uninstalled packages and zero-file records are not drift.
   v5.0: vendored patches are consulted from the vendor ledger's embedded `record`s and verified
   against the committed artifact — a manifest-less vendored project is checked the same way.)*

5. **In-repo and committable.** `setup` writes only inside the working tree: `package.json`,
   `pyproject.toml`/`requirements.txt`, `composer.json` (the `post-install-cmd`/`post-update-cmd`
   hooks), the `Gemfile` + the generated `.socket/bundler-plugin/{plugins.rb,socket-patch.gemspec}`
   and `.socket/.gitignore` (one line ignoring the machine-local stamp), and `.socket/manifest.json`
   only when `--exclude` persists an exclusion (property 9). Every artifact is git-committable.
   `setup --check` writes nothing, and an already-configured `setup` writes nothing unless
   `--exclude` is passed explicitly. The `--exclude` persistence (v5.0) runs AFTER discovery and
   the confirm prompt, as a read-modify-write under `<.socket>/apply.lock` (`setup` joins the
   `--lock-timeout` contenders): a held or unopenable lock, or a manifest that cannot be read or
   written, is reported as a `not persisting --exclude: <reason> — <hint>` warning — never exit 1 —
   and a byte-identical exclude list neither locks nor rewrites. `--check` (property 4) reads the
   vendor ledger even without a manifest; a ledger it cannot read or parse is surfaced as a
   `Warning: Unreadable vendor state (…)` line (muted by `--silent`) plus a `vendor_ledger` `files[]`
   entry with `status: error` — verdict `error`, exit 1 — never as a `configured` verdict. It never writes outside
   `--cwd` — no `$HOME`, no global `site-packages` (the Python `.pth` wheel is installed later by the
   user's package manager, not by `setup`; the gem patch stamp is written by the plugin at
   `bundle install` time, not by `setup`, at `.socket/gem-plugin-stamp` — machine-local, hence the
   `.gitignore` line; the legacy stamp under `Bundler.bundle_path` is deleted by the plugin). These
   files are **setup-owned residue**: `rollback`/`remove` never undo `setup`, so `.socket/.gitignore`,
   `.socket/bundler-plugin/` and `gem-plugin-stamp` survive a full reversal (see the residue rule
   under the rollback contract). *(Implemented — `crates/socket-patch-core/src/setup/gem/mod.rs`.)*

6. **Clone-portable.** Because all setup state is committed files, a fresh checkout on another host —
   CI, a deploy, a teammate's machine — inherits the setup state unchanged; `setup --check` passes on
   the clone with no re-run required. *(Implemented; a consequence of properties 5 + 1.)*

7. **Reflected in VEX.** A patch contributes a `not_affected` statement to the repo's OpenVEX document
   only for ecosystems that are **actually set up** — or explicitly declared **manual** (below) — or
   **vendored** (a `socket-patch vendor`ed package needs no install hook by construction: the package
   manager itself installs the patched artifact, so its purls bypass this filter) — or **hosted** (a
   live lockfile redirect is likewise its own persistence; manifest-less lockfile references are always
   vendored or hosted, so they never need `setup.manual`). Patches for an
   ecosystem that is neither set up, declared manual, vendored, nor hosted produce no VEX statement. *(Implemented —
   `generate_vex` filters `applied` to ecosystems returned by `commands/setup::configured_ecosystems`
   (on-disk hook presence) ∪ the manifest's `setup.manual`, in addition to the existing `--ecosystems`
   filter and on-disk verification. Applies in both verify and `--no-verify` modes.)*
   - **Manual declaration.** Users who run `socket-patch apply` by hand (e.g. in a CI step) declare an
     ecosystem as `manual` so VEX still attests its patches even though the auto-install hook is
     intentionally not wired. This is the normal path for **cargo** and **golang** (apply-only, no
     `setup` hook). Home: the `setup.manual` array (a list of ecosystem `cli_name`s — `pypi`, `cargo`,
     `golang`, …) in `.socket/manifest.json`. *(Implemented for the read/attest path; a `setup` flag to
     populate it is a future nicety — today it's hand-authored in the manifest.)*

8. **Graceful, exact remove.** `setup --remove` (optionally per-ecosystem via `--ecosystems`) restores
   the repo to its exact pre-setup state: manifests byte-for-byte, sibling scripts/dependencies
   preserved, keys that became empty dropped. Afterward `setup --check` reports needs-configuration
   again. For gem projects it also removes the plugin dir, the stamp and its `.gitignore` line, and
   (v5.0) prunes an emptied `.socket/` (non-recursive `remove_dir` — a `.socket/` still holding a
   manifest, blobs, vendored state or a user-authored `.gitignore` is kept), so a project that never
   ran `apply` is back to its pre-setup tree. *(Implemented for the manifest edits — npm
   `package.json` and Python deps round-trip byte-for-byte. `package.json` is re-serialized in its
   own layout — BOM, indent, line ending and trailing-newline shape (v5.0) — so a Windows manifest
   (yarn berry pretty-prints it with CRLF) keeps CRLF through `setup` and `setup --remove`.)*

9. **Nested workspaces, with exclude.** Setup applies to every subproject below the repo root: npm /
   yarn / pnpm / bun workspace members are all discovered and configured (pnpm is root-package-only by
   design, because workspace-member `postinstall` scripts fail under pnpm's strict module isolation).
   Selected paths may be **excluded**, and the exclusion is **persisted in `.socket/manifest.json`** so
   `check`, `apply`, and any clone all honor it. *(Implemented — nested-workspace discovery plus the
   `--exclude` flag, persisted as the `setup.exclude` array in `.socket/manifest.json` and honored by
   discovery + `check` (a fresh clone inherits it without re-passing the flag). Excludes apply to npm
   workspace members; the repo root is never excludable.)*
   - **Nested workspaces (implemented).** A workspace member that is itself a workspace root is recursed
     into and has its own members configured. `find_workspace_packages` re-reads each discovered
     member's own `workspaces` field (bounded depth). Guarded by the nested-workspace pins in
     `tests/setup_invariants.rs`.

### Per-ecosystem setup support

`setup` installs an automatic-repatch hook for the four ecosystems with a usable post-install /
startup hook (npm, pypi, gem, composer — every ecosystem is built in unconditionally; there are no
ecosystem feature gates). The remaining ecosystems are **apply-only**: `socket-patch apply` patches them on demand, but
there is no hook for `setup` to install, so `setup` is a `no_files` no-op for them. These are exactly
the ecosystems for which property 7's **manual** declaration is intended (so their hand-applied patches
still show up in VEX).

| Ecosystem | Hook `setup` installs | Repatch trigger | Notes |
|---|---|---|---|
| npm / yarn / pnpm / bun | `scripts.postinstall` + `scripts.dependencies` | `npm/pnpm install` (+ `install <pkg>`) | pnpm: root package only |
| pypi | `socket-patch[hook]` dependency → `.pth` startup hook | Python interpreter startup after installed-set change | manifest = `pyproject.toml` (uv/poetry/pdm/hatch) or `requirements.txt` (pip) |
| gem | managed `plugin "socket-patch"` block in the `Gemfile` → committed in-tree Bundler plugin under `.socket/bundler-plugin/` | every `bundle install` (cached + fresh: load-time digest gate + `after-install-all` hook) | the plugin is `path:`-sourced (a `git:` dir source is uncloneable — the generated dir is not a git repo — and fails `bundle install`); the dir must be committed so clones/CI have it; CLI must be on `PATH`. Phase 2 (follow-up) switches to a published `socket-patch-bundler` gem |
| composer | `socket-patch apply` appended to `composer.json`'s `post-install-cmd` + `post-update-cmd` script events | every `composer install` / `composer update` | CLI must be on `PATH` |
| cargo · golang | **none** (apply-only) | — | see "Cargo and Go: apply-only, no setup" below; candidates for the **manual** declaration |
| nuget · maven · deno | **none** (apply-only) | — | `setup` reports `no_files`; candidates for the **manual** declaration |

#### Cargo and Go: apply-only, no setup

Cargo and Go have **no `setup` hook** — a one-click, auto-repatch-on-build setup isn't possible for
them, so `setup` skips both (it makes no manifest edits for either as a *setup* action; the `go.mod`
`replace` that local-mode `apply` writes is an *apply*-time redirect, not setup state). Patch them
with `socket-patch apply` directly (manually or from a per-project install script), and declare them
in `setup.manual` for VEX attestation.

- **cargo** — `apply` patches the crate **in place** wherever the crawler finds it: the project
  `vendor/` directory or the shared registry cache (`$CARGO_HOME/registry/src/...`). The
  `.cargo-checksum.json` sidecar is rewritten so `cargo build` accepts the modified files. Rollback
  restores the original bytes from the `beforeHash` blobs. *(Note: a non-vendored crate patches the
  **shared** registry cache, which affects other projects on the machine and is reset by `cargo clean`
  / a cache prune. Vendor the dependency for a project-local, committable patch.)*
- **golang** — `apply` writes a project-local **patched copy** under `.socket/go-patches/<module>@<ver>/`
  and a `go.mod` `replace` directive pointing at it; `go build` links the copy (the module cache is
  `go.sum`-verified, so in-place patching can't build). Commit `go.mod` + `.socket/go-patches/` + your
  `.socket/` patches so a clone builds the patched bytes with no further setup. `socket-patch apply
  --check` is a read-only audit of the committed redirect.

### Monorepo / multi-project discovery model

How `setup` (and the underlying `scan`/`apply` crawlers) find subprojects differs by ecosystem, and
the model is **not uniform** today:

- **Workspace-aware (walk members):** npm / yarn / pnpm / bun (`workspaces` / `pnpm-workspace.yaml`).
  One repo-root invocation discovers and configures every member. *Single level only* — see property
  9's nested-workspace gap.
- **cwd-only (single project):** gem, pypi, composer. The crawler inspects only the project
  rooted at `--cwd` (pypi looks at `$VIRTUAL_ENV`, `<cwd>/.venv` / `venv`, then a Poetry project's out-of-tree virtualenv(s) under Poetry's `virtualenvs.path`; composer at the vendor tree); it does **not**
  descend into sibling subprojects. A monorepo with several independent lockfiles in subdirectories
  (`backend/Gemfile.lock` + `frontend/Gemfile.lock`, multiple `.venv`, multiple `go.mod` /
  `composer.json`) is handled by invoking the tool **once per subproject** (`--cwd` each), as a
  per-directory install hook would.

  *Gem install roots (a refinement of "cwd-only", not an exception to the one-project model):* the
  crawler probes the project's Bundler install roots in **bundler's own precedence order** — the app
  config file's `BUNDLE_PATH:` (`$BUNDLE_APP_CONFIG/config`, else `<cwd>/.bundle/config` — what
  `bundle config set --local path` records), then the **`BUNDLE_PATH` environment variable**, then the
  default `<cwd>/vendor/bundle` — each in both store layouts bundler produces (scoped
  `<root>/<engine>/<abi>/gems/` and flat `<root>/gems/`). The env variable is the user's own machine
  state, so it is honored verbatim (it may point outside `--cwd`; a leading `~` expands against home);
  the **config file is typically committed — untrusted input — so a config-sourced root that resolves
  outside the project root is skipped** (`BUNDLE_PATH__SYSTEM: "true"` likewise drops the recorded
  path, as bundler itself ignores it). The skip is surfaced per the run-warning conventions: a
  `gem_bundle_config_path_ignored` entry in the run-level `warnings[]` of `scan`/`apply` `--json`
  envelopes (detail names the config value and the env-`BUNDLE_PATH` remedy), and one stderr
  `Warning (gem_bundle_config_path_ignored): …` line on the human path, gated on `!--silent`
  (`--silent` = errors only). Explicit env/config roots only count when `--cwd` holds a Bundler
  manifest/lockfile. When the default `vendor/bundle` root holds no store, the gem homes `gem env`
  reports are appended (default gems like rexml/json only ever live there). When several roots hold
  **coexisting physical copies of one `gem@version`** (bundler-2's scoped store beside bundler-1's
  flat store), `apply`/`rollback` patch/restore **every copy** — one summary event per copy,
  mirroring npm's multi-copy fan-out — while single-representative consumers (`get`, `vendor`,
  `setup`, `vex`) use the highest-precedence copy.

  *Copy classes (additive to the multi-copy vocabulary):* a copy under a **bundle-path store**
  (config/env/default root) is PRIMARY — a variant mismatch or write failure there fails the run,
  as always. A copy in a **`gem env` fallback home** (rvm `@global`, `--user-install`, system gem
  dirs — shared, often root-owned) is patched too when it matches and is writable, but becomes
  BEST-EFFORT once at least one bundle-store copy applied: its mismatch/write failure surfaces as a
  non-fatal `skipped` event (`errorCode: gem_fallback_home_skipped`, detail names the copy's path
  and reason; gated stderr twin on the human path) instead of failing a run whose loaded copy is
  patched. With **no** bundle-store copy (the historic fallback-only layout, and every `--global`
  run) the fallback-home copy IS the primary install and keeps loud-fail parity with pre-bundle-path
  `apply`.

**Intended (gap):** the cwd-only ecosystems *should* also auto-discover per-subproject lockfiles when
run from the repo root, matching the npm workspace model. The npm-vs-others asymmetry is a known
defect, guarded by the `#[ignore]`d gap pin
`gem_crawl_from_repo_root_discovers_all_subproject_lockfiles` in
`crates/socket-patch-core/tests/crawler_monorepo_gaps.rs` (gem is the representative; python/go/composer
share the limitation).

**Deeply nested transitive dependencies are fully supported.** The npm crawler recurses `node_modules`
at unbounded depth, and `apply` is path-agnostic — it patches a package by PURL against the manifest
regardless of how deep in the dependency tree it was installed, so a deeply-nested transitive dependency
is patched identically to a direct one. Both halves are pinned in
`crates/socket-patch-core/tests/crawler_npm_e2e.rs`: discovery by
`crawl_all_discovers_deeply_nested_transitive_deps`, and apply-side resolution by
`find_by_purls_resolves_nested_only_install` (`find_by_purls` probes the tree root first, then falls
back breadth-first into nested `node_modules` for still-unresolved PURLs; a root-level install always
wins, pinned by `find_by_purls_prefers_root_copy_over_nested_duplicate`).

### JSON output shapes (`setup`, `setup --check`, `setup --remove`)

`setup` predates the v3.0 unified envelope and emits its own three shapes. They are stable as of v3.0;
consumers may rely on these keys. All three share a `files[*]` entry shape; `kind` is one of
`package_json`, `pth`, `gemfile`, `gem_plugin`, `composer`, `patch` (`--check` property 4: a manifest
or ledger patch not applied on disk, `needs_configuration`), `vendor_ledger` (`--check`: a
`.socket/vendor/state.json` that cannot be read or parsed, `error`), `gem_plugin_registration` (the last is
`setup --remove`-only: clearing bundler's machine-local `.bundle/plugin` registration of the wired
plugin — emitted only when a registration existed; `status: error` carries the
`bundler plugin uninstall socket-patch` remedy when it could not be cleared safely).

**`setup`:**

```jsonc
{
  "status": "success" | "already_configured" | "dry_run" | "partial_failure" | "error" | "no_files",
  "updated":            0,
  "alreadyConfigured":  0,
  "errors":             0,
  "packageManager":      "npm" | "pnpm",                 // always emitted; defaults to "npm", only meaningful when npm files were found
  "pythonPackageManager":"pip" | "uv" | "poetry" | "pdm" | "hatch",  // present only when Python detected
  "dryRun":   true,                                      // only on status=dry_run
  "wouldUpdate": 0,                                      // only on status=dry_run
  "warnings": [ "..." ],                                 // only when non-empty (e.g. lockfile refresh)
  "files": [
    { "kind": "package_json", "path": "...", "status": "updated" | "already_configured" | "error",
      "error": null | "..." }
  ]
}
```

**`setup --check`** (read-only; never writes — exit `0` only when all in-scope manifests are configured
and none errored):

```jsonc
{
  "status": "configured" | "needs_configuration" | "error" | "no_files",
  "configured":          0,
  "needsConfiguration":  0,
  "errors":              0,
  "files": [
    { "kind": "...", "path": "...", "status": "configured" | "needs_configuration" | "error",
      "error": null | "..." }
  ]
}
```

**`setup --remove`:**

```jsonc
{
  "status": "success" | "not_configured" | "dry_run" | "partial_failure" | "error" | "no_files",
  "removed":        0,
  "notConfigured":  0,
  "errors":         0,
  "dryRun":   true,            // only on status=dry_run
  "wouldRemove": 0,            // only on status=dry_run
  "warnings": [ "..." ],       // only when non-empty
  "files": [
    { "kind": "...", "path": "...", "status": "removed" | "not_configured" | "error",
      "error": null | "..." }
  ]
}
```

**Exit codes** (all three): `0` when nothing errored and the operation was satisfiable (including
`no_files` and `not_configured`); `1` on any per-file error, partial failure, or — for `--check` — any
manifest that needs configuration. `setup --check --remove` is a clap usage error (exit `2`).

## Vendor command contract

`vendor` is `apply`'s committable sibling: instead of patching installed packages in place
(machine-local state), it ejects each patched package into `.socket/vendor/` and rewires the
ecosystem's lockfile/config so the project consumes the vendored copy. After committing
`.socket/vendor/` + the lockfile edits, a fresh checkout builds with the patched dependency on
machines with **no socket-patch installed and no Socket API access** (registry access for other,
unvendored dependencies may still be needed). Every mechanism below was validated against the real
package managers (`spikes/PHASE0-FINDINGS.txt`).

**Prebuilt vendor artifacts (`--vendor-source`)**: by default (`auto`) `vendor` first tries to
DOWNLOAD the already-built patched artifact + integrity from the patch.socket.dev vendoring service,
and silently falls back to building it locally on any non-fatal miss. `service` requires the service
(fail-closed); `build` always builds locally (the pre-service behavior). The download is a two-step
flow on the configured API/proxy host (`--vendor-url` overrides it): a package-reference POST
(`/v0/orgs/{slug}/patches/package` authenticated, else the public proxy's `/patch/package`) yields a
grant-tokenized serve URL + integrity, then a GET fetches the archive (`--patch-server-url` rewrites
that URL's host for local-dev / testing). The downloaded bytes are ALWAYS integrity-verified before
use (sha512 SRI for every ecosystem; golang additionally the `h1:` module dirhash) — a mismatch is a
hard error, never a silent fallback. A service-vended package reports each patched file as
`AlreadyPatched` (trust is the verified service integrity, not a local re-apply). The fallback ladder
per service outcome:

| Service outcome | `auto` | `service` |
|---|---|---|
| granted/reused, integrity ok | **use service** | **use service** |
| integrity mismatch (including the gem stub gemspec) | **refuse** (`vendor_prebuilt_integrity_mismatch`; npm: the package fails with the integrity detail). Tampered bytes never fall back to a local build | refuse (same) |
| integrity ok, but the archive does not carry the patched files (a member at a recorded path fails its `afterHash`; checked for cargo/golang/composer/gem after extraction, and for maven/nuget/pypi/npm before the archive is written; npm under `service` fails the package with the detail) | local build + `vendor_prebuilt_layout_mismatch` | refuse (`vendor_prebuilt_required`) |
| still building (`pending_build` / serve 408) | local build + `vendor_prebuilt_pending` | refuse |
| not built / withdrawn / not found / no usable artifact | local build (quiet) | refuse |
| gem stub gemspec missing / invalid | local build + `vendor_prebuilt_stub_missing` / `vendor_prebuilt_stub_invalid` (invalid + gem not installed: refuse `vendor_prebuilt_stub_invalid` — no stub source exists) | refuse (`vendor_prebuilt_required` / `vendor_prebuilt_stub_invalid`) |
| 401 / 403 grant / 5xx / network error | local build + `vendor_prebuilt_unavailable` | refuse |
| `--offline` | local build | refuse (`vendor_service_offline_conflict`) |
| no API client configured (library callers of the vendor engine; the CLI always configures one) | local build | refuse (`vendor_prebuilt_required`) |

`--vendor-source` governs ACQUISITION, not reuse: a re-run whose committed artifact the ledger
vouches for (npm tarball / pypi wheel: path under this patch uuid, no symlink, whole-file sha256 and
size equal to the ledger, every afterHash verified from the same bytes; the dir-shaped ecosystems:
the wired copy's afterHashes) keeps it in every mode — no service request, no local build, no
rewrite — whichever source built it. So a service outage (or its recovery) never re-vendors an
already-vendored package: the re-run is `already_vendored`, including under `service` +
`--offline`, and `build` does not rebuild a service-built artifact (delete the uuid dir to force
a rebuild). The ledger records no provenance, so `service` cannot tell a locally built committed
artifact from a prebuilt one; it keeps what verifies. A lock that drifted off a verified committed
artifact (a relock, a hand revert) is re-wired to those exact bytes (pypi re-scans report the
Verbose `vendor_artifact_reused`). Service round trips are retried on transport errors and
429/500/502/503/504 (3 attempts, exponential backoff with jitter, `Retry-After` honored, 4s cap);
after 2 consecutive exhausted fetches the rest of the run skips the service (`auto` builds
locally, `service` refuses).

**golang service leg staging (v5.0)**: the module zip is downloaded, extracted and `h1:`-verified in a `<copy>.socket-stage` sibling and swapped into place only afterwards; a failed re-download of a WIRED, present copy keeps the copy and its `replace` directive (previously both were torn down), while a missing copy still drops the dangling directive.

Coverage today: **npm** (all lock flavors), **pypi** (wheel — sdist falls back / refuses), **cargo**
(download + extract the `.crate`), **golang** (download + extract the module zip, verify the `h1:`
dirhash, wire the `replace`), **composer** (download + extract the dist zip), **gem** (download +
extract the `.gem`, plus a `gem-stub-gemspec` SECOND artifact), **nuget** (download the prebuilt
`.nupkg`), and **maven** (download the prebuilt `.jar` + the registry pom; in the fail-closed
`service` coverage list since the `service_mode_gate_admits_maven` fix — PR #117 shipped the backend
but left maven off `SERVICE_ECOSYSTEMS`). The Tier-B ecosystems
(cargo/golang/composer/gem) download the patched archive and extract it into the vendor directory —
the same source tree the local build commits — then run the existing path-dep wiring; their
build-equivalence is exercised by the toolchain-backed e2e suites (which skip when the package
manager is absent). **gem** needs the extra `gem-stub-gemspec` artifact because a path-sourced gem
needs an eval-able stub gemspec that the `.gem` archive doesn't carry in bundler's required form (a
`.gem` keeps the gemspec as YAML in `metadata.gz`); the converter generates that stub and serves it
alongside the `.gem`, and the gem backend downloads + integrity-verifies both. A served gem whose
stub is missing (a native-extension gem, for which the converter emits no stub, or a patch built
before the stub rollout) is treated as a service miss — `auto` falls back to the local build,
`service` refuses (`vendor_prebuilt_required`). A served stub that is present but INVALID — it
fails the rubygems `summary`/`authors` bar, so every bundler major would reject the vendored
path source at install time (a defect the 2026-08-19 live matrix found in every then-published
gem stub) — follows the same miss policy under its own code (additive/MINOR): `auto` falls back
to the local build with a loud `vendor_prebuilt_stub_invalid` warning naming the missing
attributes, `service` refuses with `vendor_prebuilt_stub_invalid`. (Semver note: before the
hardening, `service` mode exited 0 here while writing a stub bundler rejects — an UNINSTALLABLE
project. The refusal is the bug fix; the exit-0 was the defect, so this rides a MINOR.) When the
invalid-stub fallback finds the gem is ALSO not installed locally (no `specifications/` stub to
derive), the vendor refuses with the same `vendor_prebuilt_stub_invalid` code, naming the served
defect and the install-the-gem remedy. The locally-derived stub is validated at the same write
choke point: a corrupted local `specifications/` stub failing the bar refuses with
`gem_spec_invalid` naming the file. The bar is a conservative textual heuristic matched to what
rubygems 3.3–3.6 actually hard-fails (no assignment of `summary`; no `authors`/`author`
assignment, or one that collapses to no String elements — `[]`/`nil`/`[nil]`/`%w[]`; nil/empty
strings are rubygems-tolerated and pass); a valid stub is still written byte-verbatim, and the
idempotent re-vendor path re-checks the ON-DISK stub, routing a pre-hardening invalid one into
the artifact rebuild. For any ecosystem with no service path at all
`auto`/`build` build locally as before, and `service` refuses with
`vendor_service_unsupported_ecosystem`. A successful service vend emits `vendor_prebuilt_downloaded`.
Unrelated to `--download-mode` (which selects the patch-CONTENT format for the local build).

**Patch sources stay in memory (v3.4)**: vendoring never writes `.socket/blobs/`, `.socket/diffs/`,
or temporary patch files. Pre-existing `.socket/` artifacts (from a prior `apply`/`get`/`repair`)
are read in place; already-vendored purls re-stage patch content from the committed artifact itself
(uuid-matched against the ledger, every harvested blob self-verified by its afterHash — so in-sync
re-runs and fresh clones of vendored projects need no network); anything still missing is fetched
into memory via the patch-view endpoint. A vendored project's `.socket/` holds only `vendor/`
(v5.0 — vendored runs never write `manifest.json`; one exists only when standalone `vendor` was fed
by an agent-mode manifest, or as the `{"patches": {}}` husk left after a legacy record migrated
into the ledger).

**Vendored artifact repair (v3.5)**: `repair` health-checks every ledger entry — per-file
afterHashes inside the artifact plus, for file-shaped artifacts (`.tgz`/`.whl`), the whole file
against the ledger's recorded sha256 (the rewired lock integrity references those exact bytes) —
and REBUILDS missing/corrupt artifacts through the normal vendor backends. The wired hot paths
rebuild the artifact only: lockfiles stay byte-identical and the ledger entry is not re-recorded
(the first run's entry holds the only pre-vendor originals). Pristine sources follow the same
ladder as vendor: the installed copy first (works under `--offline`), then a lockfile-verified
registry fetch, then the pre-vendor registry fragment recovered from the ledger's wiring
`original`s (`recover_lock_entry`) — always integrity-verified fail-closed, and the rebuilt
artifact is re-verified against the recorded fingerprint before the run counts it (`rebuilt`
event; a mismatch removes the artifact and fails with `vendor_artifact_rebuild_failed`).
Lockfile references to `.socket/vendor/<eco>/<uuid>/...` with NO ledger coverage (the ledger was
deleted wholesale) are RECONSTRUCTED: the uuid comes from the path (the recovery rule above), the
record from the manifest — or the patch API, yielding an entry with the record embedded (the same
`detached: true` + `record` shape every `scan`/`get --mode vendored` entry has)
— and a fresh ledger entry is persisted with the rebuilt artifact's fingerprint. When nothing is
installed and the ledger is gone, npm-family reconstruction has one more rung: the REWIRED
lockfile still records the integrity of the packed vendored tarball, so the pristine copy is
fetched (unverified, conventional registry URL, `SOCKET_NPM_REGISTRY` honored) and the
deterministically REBUILT artifact must reproduce that wired integrity — a tampered pristine
source changes the rebuilt bytes and fails closed (`vendor_artifact_rebuild_failed`, nothing
kept). Reconstructed entries carry no pre-vendor wiring originals, so a later `--revert` degrades
to the documented `vendor_lock_entry_drifted` guidance (re-resolve with the package manager). Because of this
phase, `repair` no longer errors with `manifest_not_found` when the project has a vendor ledger
or vendor-path lockfile references — it runs the vendored phase alone. A **hosted-only** project
(no manifest, no vendor ledger, no vendored references — only `.socket/vendor/redirect-state.json`)
is a no-op: `repair` exits 0 with a `redirect_only_project` skip pointing at `scan --mode hosted`
(hosted redirects have no local artifacts to repair), rather than the `manifest_not_found` error a
bare directory still gets. Step 1's source download
likewise skips vendored-in-sync manifest entries (their content lives in the committed artifact),
so repairing a vendored project never re-litters `.socket/blobs`. `--dry-run` previews
(`details.wouldRebuild`); `--offline` rebuilds only from fully local sources and fails per-entry
otherwise; `vendor`/`scan --vendor` re-runs get the same rebuild for wired-but-broken artifacts
(`vendor_artifact_rebuilt` warning) and recover registry resolutions for missing committed
artifacts instead of failing.

### Path convention + patch-UUID recovery (stable)

```text
.socket/vendor/<eco>/<patch-uuid>/<natural-leaf>
```

The full 36-char lowercase hyphenated patch UUID is a dedicated path level, so it appears verbatim
in every lockfile-visible path string. External tools recover "this dependency is Socket-vendored,
by patch `<uuid>`" from the lockfile alone with this rule (no access to `.socket/` needed):

```text
(?:file:)?(?:\./)?\.socket[/\\]vendor[/\\](npm|cargo|golang|composer|gem|pypi|nuget|maven)[/\\]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[/\\](.+)
```

Updating a patch changes the UUID → changes the path → changes the lockfile, so staleness is
diffable by construction. Each vendored unit also carries an informational
`socket-patch.vendor.json` marker (`{schemaVersion, purl, patchUuid, ecosystem, vulnerabilities,
vendoredAt}`) next to the artifact — belt-and-braces for tools that have the tree but not the
lockfile; never a trust input. `socket-patch vex` itself recovers vendored (and hosted) patch
references from the lockfiles this way — see "Manifest-less VEX (lockfile discovery)".

### Per-ecosystem wiring matrix

The npm ecosystem has **five lockfile flavors** — all sharing one vendored
tarball at `.socket/vendor/npm/<uuid>/[@scope/]<name>-<version>.tgz`; a
content-sniffing probe (`npm_flavor`) picks the flavor and the ledger records
it so `--revert` routes back. The pypi ecosystem similarly routes by lockfile
to **six flavors**.

| eco / flavor | vendored artifact | committed wiring | consumption proof |
|---|---|---|---|
| npm (package-lock) | deterministic patched tarball `[@scope/]<name>-<version>.tgz` | `package-lock.json` only (`npm-shrinkwrap.json` wins when present): every entry matching name+version gets `resolved: "file:…"` + recomputed `integrity`. `package.json` untouched | `npm ci` (integrity-verified). Plain `npm install` preserves the entry; `npm update <pkg>` re-resolves and drops it |
| npm / yarn classic | (same tarball) | `yarn.lock` only: matching blocks get `resolved "file:./…#<sha1>"` + `integrity` (both checksums recomputed; merged-key & `npm:`-alias blocks covered) | `yarn install --frozen-lockfile --offline` (sha1 fragment + sha512 SRI both enforced; byte-stable lock) |
| npm / yarn berry (node-modules linker) | (same tarball) | root `package.json` `resolutions` + `yarn.lock` entry with `checksum: 10c0/<sha512>` of the berry cache-zip (reproduced from the tarball offline). **PnP is refused** (`.pnp.*` → different artifact pipeline) | `yarn install --immutable --check-cache`, cold cache. Refused if `__metadata.cacheKey ≠ 10c0` or a non-default `compressionLevel`. Both files keep their own layout — a CRLF lock (yarn's output on Windows) is spliced in CRLF, `package.json` is re-serialized with its BOM, indent, line ending and trailing-newline shape — so vendor + `--revert` round-trip byte-exactly; a lock or `package.json` MIXING CRLF and LF is refused before any write (`vendor_yarn_berry_mixed_line_endings`) |
| npm / pnpm (lockfileVersion 9) | (same tarball) | root `package.json` `pnpm.overrides` (versioned selector) **+** `pnpm-lock.yaml` surgery (overrides / importer version / packages `resolution.integrity` / snapshots) | `pnpm install --frozen-lockfile --offline`, cold store (integrity-verified; byte-stable on pnpm 9 & 10). Other lockfileVersions: 5.4/6.0 route to the legacy backend below; anything else refused |
| npm / pnpm LEGACY (lockfileVersion 5.4 = pnpm 7, 6.0 = pnpm 8; flavor `pnpm-legacy`) | (same tarball) | root `package.json` `pnpm.overrides` **+** legacy lock surgery (overrides / root dep + specifiers / packages rekey to a bare `file:` key with recomputed integrity / in-package dep refs). **No `pnpm-workspace.yaml` is written** (pnpm ≤ 8 reads overrides only from package.json). The lock's SPECIFIER is machine-ABSOLUTE — pnpm ≤ 8 absolutizes `file:` overrides itself — surfaced as `vendor_pnpm_legacy_absolute_specifier`. Legacy WORKSPACE locks (`importers:`) refused | same-path `pnpm install --frozen-lockfile --offline`, cold store (byte-stable on pnpm 7.33.5 / 8.15.9). A checkout at a DIFFERENT path fails the frozen check (path-bound specifier) and must run `pnpm install --offline --no-frozen-lockfile` once (the flag matters on CI, where pnpm defaults frozen on), which installs the vendored tarball and re-resolves only the specifier line |
| npm / bun (`bun.lock`, lockfileVersion 0, 1 or 2 — `vendor_lockfile_version_unsupported` otherwise) | (same tarball) | `bun.lock` only: the packages entry's registry 4-tuple → local 3-tuple with recomputed `sha512`; the entry's `{deps}` meta, the lock's version line and its line endings are preserved. A lock holding `workspace:` packages is refused `vendor_bun_workspace_unsupported` unless lockfileVersion is 2 — Bun 1.2–1.3 resolve a workspace member's local-tarball path relative to the MEMBER (ENOENT on our root-relative path), 1.4 relative to the lockfile, and a committed version-2 lock is the only proof every consumer runs Bun ≥ 1.4 (a deliberate over-approximation: a package declared only by the workspace root would install on version 1 too). The gate fires only on a run that would WRITE a new local tuple, so in-sync re-runs, `already_vendored` skips and `repair` rebuilds on such a lock pass. The detail names the version and the remedy: delete `bun.lock` and re-lock with Bun ≥ 1.4 (an in-place `bun install` keeps the existing lockfileVersion), or `--mode hosted`. Native binary support is described in the next row. `scan`/`get --mode vendored` apply all four refusals BEFORE downloading (see the `get --mode vendored` bullet). Bun 1.1.39–1.3.9 re-save the local tuple WITHOUT its `sha512` on any later lock re-save (`bun add`, `bun install` after a manifest change); the digest-less 2-tuple is recognised as the same wiring — an in-sync re-run stays `already_vendored` and re-pins the digest on disk (no new wiring record) when the committed artifact still holds the bytes the lock was written from — otherwise, as for any stale tuple of ours, the line is re-pinned and the fresh entry carries the new fingerprint — `repair` rebuilds through it, and `vendor --revert` / `rollback` restore the registry line over it (a 2-tuple at ANOTHER uuid is still `vendor_lock_entry_drifted`) | `bun install --frozen-lockfile`, cold cache (the local tarball's sha512 is enforced by Bun ≥ 1.3.10; 1.1.39–1.3.9 install it unverified — the committed artifact is the protection there) |
| npm / bun binary (`bun.lockb`, native binary format 1, 2 or 3) | (same tarball) | Rewrite matching binary package resolutions and integrity in place; preserve topology and unrelated metadata, update binary offsets and the package metadata hash. Text `bun.lock` takes precedence. `bun_lockb_package` wiring snapshots recover pristine registry metadata for repair and support per-package revert and hosted ↔ vendored migration. Binary discovery and rewrites require no installed Bun runtime. Malformed or unsupported content refuses `vendor_bun_lockb_invalid` before download or takeover. | Frozen installs with the original compatible Bun reader; see `docs/testing/bun-compatibility.md` for the release matrix and historical runtime integrity limits. |
| cargo | crate dir `<name>-<version>/` (no `.cargo-checksum.json`) | (v5.0) `[patch.crates-io]` path entry in the **workspace-root `Cargo.toml`** (the manifest beside the `Cargo.lock` it detaches — never `.cargo/config*`) **+** Cargo.lock surgery (the `[[package]]` entry's `source`/`checksum` removed and its `version` set to the copy's TAGGED version `<version>+socket.<uuid>` — `<core>+<meta>.socket.<uuid>` when the version already has build metadata — with every lock reference that spells the old version rewritten, formats v1–v4; the copy's own `Cargo.toml` version carries the same tag, so the patched crate sees it in `CARGO_PKG_VERSION`; revert restores the lock byte for byte). Key: always the Socket-owned `<name>-socket-<first 8 hex of the uuid>` with `package = "<name>"` (the full uuid hex when that key is taken), never the bare crate name — cargo lets a config-file `[patch]` item (project, ancestor directory or `$CARGO_HOME`) replace the manifest item with the same key whatever its version, so keys any of those configs use are avoided and a re-run moves an entry off a now-shadowed key; two versions of one crate are wired side by side. Pre-v5 wiring in `.cargo/config.toml` / `.cargo/config` is moved into `Cargo.toml` by a re-run (`vendor`, `scan`/`get --mode vendored`) or `repair` (`cargo_wiring_migrated` note; the ledger's `cargo_patch_entry` record then names `Cargo.toml`); a detached lock entry left unwired by the pre-v5 multi-version overwrite is re-wired the same way (`cargo_wiring_restored`); every revert removes both spellings | `cargo build --locked --offline` on a fresh checkout — single-version manifest `[patch]` also builds with no network on cargo older than 1.56 (the old config-file wiring's floor); two vendored versions of ONE crate need `--offline` on cargo 1.56 and a populated registry index (or network access) on older cargo such as 1.41, which loads the index to tell them apart. Note: path deps build **without** `--cap-lints allow` |
| golang | module dir `<module>@<version>/` | `go.mod` `replace <module> <ver> => ./.socket/vendor/golang/<uuid>/<module>@<ver>` | `go build` with `GOPROXY=off` + empty `GOMODCACHE` (directory replaces bypass go.sum entirely; survives `go mod tidy`) |
| composer | package dir `<vendor>/<name>@<version>/` | `composer.lock` only: entry's `dist` → `{type: "path", url, reference: null}`, `source` removed, `transport-options: {symlink: false}` added. `content-hash` unaffected; `composer.json` untouched | `composer install` (from the lock alone, real copy not symlink, works under `--network none`). `composer update <pkg>` reverts it |
| gem | gem dir `<name>-<version>/` + gemspec materialized from `specifications/` | **Gemfile + Gemfile.lock pair**: the `gem` line gains `path:` (or a managed block for transitive deps); the lock's spec block moves GEM→PATH and the DEPENDENCIES entry becomes `<name> (= <ver>)!`, in bundler's exact canonical form | `bundle install` (normal **and** `BUNDLE_FROZEN=true`), byte-stable lock. Lock-only edits are a silent unpatch — hence the mandatory pair |
| pypi / uv (uv.lock) | rebuilt wheel (canonical PEP 427 filename; RECORD regenerated) | `[tool.uv.sources] <name> = {path}` in pyproject + surgical uv.lock rewrite; transitive deps via `[tool.uv] override-dependencies` | `uv sync --locked` / `--frozen --offline` (hash-verified, byte-stable lock) |
| pypi / poetry (poetry.lock: legacy `[metadata.hashes]`, lock 1.0/1.1 `[metadata.files]`, 2.x `files`) | (rebuilt wheel) | lock-only: the target `[[package]]` gets `[package.source] type="file"` (+ `reference = ""` on the 0.12/1.0 layouts, which read it unconditionally) and the single `{file, hash: sha256-of-our-wheel}` entry in whichever table the generation keeps it. pyproject + `metadata.content-hash` untouched; CRLF locks keep their line endings. A lock written by Poetry < 1.4 emits `pypi_poetry_integrity_unverified` (that installer verifies no local hashes and skips an already-installed version) | `poetry check --lock && poetry sync`, cold cache (hash fail-closed from Poetry 1.4; byte-stable lock) — see `docs/testing/poetry-compatibility.md` |
| pypi / pdm (pdm.lock) | (rebuilt wheel) | lock-only: the `[[package]]` gains the local-file `path` + `files[]` hash. pyproject + `content_hash` untouched. Non-fixture `[metadata] strategy` / hash-less locks refused | `pdm sync` (+ `pdm install --check`), cold cache |
| pypi / pipenv (Pipfile.lock) | (rebuilt wheel) | lock-only: the `default`/`develop` entry → `{file, hashes:[sha256-of-our-wheel]}`. Pipfile + `_meta.hash` untouched. Emits `vendor_integrity_unverified` — pipenv does not hash-check file entries; the committed wheel bytes are the protection | `pipenv install --deploy` (+ `pipenv verify`), cold cache |
| pypi / requirements.txt (pip / `uv pip`) | (rebuilt wheel) | pin line → `./<wheel> --hash=sha256:<hex>` (markers carried over; transitive deps appended) | `pip install -r` / `uv pip install -r` **run from the project root** (both resolve bare paths against the CWD) |
| nuget | deterministically rebuilt `.nupkg` at `<idLower>.<versionNorm>.nupkg` (the uuid dir IS a NuGet folder feed; the stale embedded signature is dropped — unsigned is accepted under NuGet's default validation) | `nuget.config` source + `packageSourceMapping` for the id (creating the mapping from scratch ALSO fans a `<package pattern="*" />` out to every pre-existing source — mapping is exclusive, NU1100 otherwise) **+** `packages.lock.json` `contentHash` → `base64(sha512(nupkg))` when the lock exists (`vendor_nuget_no_lockfile` warning otherwise) | `dotnet restore --locked-mode`, cold cache, `--network none` (tampered nupkg fails NU1403) |
| maven | deterministically rebuilt `.jar` + the **verbatim upstream pom** (transitives survive; refused via `vendor_maven_pom_unavailable` rather than fabricated) + `.sha1` sidecars, laid out as a maven2 repository under the uuid dir | `pom.xml` `<repository>` (`id=socket-patch-vendor-<uuid>`, `url=file://${project.basedir}/.socket/vendor/maven/<uuid>`, `checksumPolicy=fail`, snapshots disabled). Multi-module aggregator poms refused (`vendor_maven_multimodule_unsupported`); gradle-only projects refused (`vendor_gradle_unsupported`); always-on `vendor_maven_local_cache_shadow` advisory (warm `~/.m2` wins over any repository) | `mvn` build on a fresh checkout with the GAV purged from the local repo, `--network none` (docker capstone; note `mvn -o` refuses `file://` repositories outright) |

Ecosystems with no vendor backend (jsr) refuse per-purl with
`vendor_unsupported_ecosystem`. yarn-berry **PnP**
(`.pnp.*`) is refused with a stable code pointing at the native patch workflow.
Bun's binary `bun.lockb` is supported natively, including lockfile-only discovery,
vendoring, hosting, repair and migration between those modes. A lock-less tool marker (a `[tool.uv]`/`[tool.poetry]`/
`[tool.pdm]` table or a `Pipfile` without its lock) refuses `<tool>_no_lockfile` unless a
`requirements.txt` fallback exists. PURLs of **compiled-out** ecosystems are invisible to `vendor`
exactly as they are to `apply` (the binary cannot parse them).

### Checksum coverage

Every checksum-like field a lockfile carries for a vendored package is updated coherently —
never inherited from the registry entry (a stale checksum either hard-fails the install or,
worse, lets a warm cache silently serve unpatched bytes):

| eco / flavor | checksum/reference fields | vendor behavior |
|---|---|---|
| npm (lock v2/v3) | `packages[].integrity` + `resolved`; v2 legacy `dependencies` mirror; `dependencies`/`peerDependencies`/`optionalDependencies`/`bin` mirrors | integrity recomputed (sha512 of the packed tarball); `resolved` → relative `file:`; legacy mirror rewritten; dep mirrors recomputed when the patch touches the package's package.json |
| cargo | `[[package]].source` + `checksum`; `.cargo-checksum.json` in the copy | both lock keys removed (the canonical path-dep form); checksum sidecar excluded from the copy; originals kept verbatim in the ledger for `--revert` |
| golang | `go.sum` | untouched **by design** — directory `replace` targets are never sum-verified. Caveat: a user `go mod tidy` may prune the replaced module's go.sum lines; revert does not restore them (the next online build re-adds them) |
| composer | `dist.{url,reference,shasum}`, `source.reference`, `content-hash` | `dist` → `{type: path, url, reference: "<patch-uuid>"}` (the uuid is preserved verbatim into `installed.json` — in-tree traceability); `source` removed; `content-hash` untouched (covers composer.json only) |
| npm / yarn classic | `resolved "…#<sha1>"` fragment + `integrity` SRI | both recomputed from the packed tarball (sha1 fragment + sha512 SRI); integrity line added when the registry block lacked one — yarn then enforces both |
| npm / yarn berry | `checksum: 10c0/<sha512>` (over berry's cache zip) | recomputed by rebuilding berry's deterministic cache-zip from the tarball and hashing it (byte-identical to yarn's own); refused if the lock's `cacheKey`/`compressionLevel` would change the zip |
| npm / pnpm | `packages[].resolution.integrity` (sha512) | recomputed from the tarball; the versioned `pnpm.overrides` selector pins exactly the patched version |
| npm / bun | the packages-entry trailing `sha512-…` | recomputed from the tarball; tamper fails the frozen install on Bun ≥ 1.3.10 (URL/local tarball tuples are verified from 1.3.10, registry 4-tuples from 1.2.0 — so on 1.1.39–1.3.9 a hosted or vendored rewrite removes digest enforcement for the patched package; see `docs/testing/bun-compatibility.md`) |
| gem | `CHECKSUMS` section (bundler ≥ 2.6 opt-in) | the vendored gem's entry rewritten to bundler's own path-gem form (bare `name (ver)`, sha256 token stripped) so re-locks stay byte-stable; original line in the ledger |
| pypi / uv | `wheels[].hash`, `sdist.hash`, requires-dist specifiers | single `{filename, hash: sha256-of-our-wheel}`; sdist dropped; dropped specifiers ledgered for revert |
| pypi / poetry | `files = [{file, hash}]` (2.x) / `[metadata.files]` entry (1.0/1.1) / `[metadata.hashes]` entry (0.12) | replaced with a single `{file, hash: sha256-of-our-wheel}` (or the bare hash for 0.12) in the generation's own table (Poetry ≥ 1.4 verifies the artifact against one listed hash; older writers are flagged `pypi_poetry_integrity_unverified`; stale registry hashes removed) |
| pypi / pdm | `[[package]].files[]` hashes | replaced with our wheel's sha256; hash-less locks refused (`pypi_pdm_lock_no_hashes`) |
| pypi / pipenv | per-entry `hashes[]` | replaced with `["sha256:<ours>"]` — but pipenv does **not** enforce hashes on file entries (`vendor_integrity_unverified` warning); the committed wheel bytes are the actual protection |
| pypi / requirements | `--hash=sha256:` | fresh hash of the rebuilt wheel always emitted (turns on pip's hash-checking for the line) |

### Ownership, state, and reversal

* `.socket/vendor/state.json` (committed) is the revert ledger: every wiring edit records the
  **verbatim original** lockfile fragment it replaced (registry URLs, integrity strings, Cargo.lock
  `source`/`checksum`, requirement lines, uv specifiers). Those are not recoverable offline, so
  `--revert` never guesses at unrecorded fragments: a missing ledger is an empty ledger (clean
  no-op plus the orphan-dir sweep), and entries whose recorded fragments no longer match are left
  alone with warnings. Every entry written by `scan`/`get --mode vendored` (v5.0: the only
  vendored posture) carries `detached: true` and `record` (an embedded copy of the patch record —
  same committed-file trust class as the manifest; artifact verification still re-hashes against
  its afterHashes and the uuid-in-path cross-checks); standalone `vendor` fed by an agent-mode
  manifest embeds `record` too, as a fallback copy, but never `detached` — the manifest record stays
  authoritative while the manifest covers the entry (ledger key or base purl); `vex`, `list` and
  `setup --check` read the fallback copy only when it does not, `repair` only with no manifest at all.
* **Re-vendor carries originals forward**: re-vendoring under a newer patch uuid rewrites the
  previous run's own wiring (`original: None` from the backend — it must never record a dangling
  `.socket/vendor/` pointer as pre-vendor state); the engine merges the TRUE pre-vendor originals
  from the replaced ledger entry by wiring identity, so `--revert` after any number of re-vendors
  still restores the registry fragments byte-for-byte. The old uuid's now-orphaned artifact dir is
  removed (`vendor_stale_artifact_removed`) unless another entry still references it.
* `vendor --revert` restores the originals (fragments that no longer match — a user re-resolved —
  are left alone with a `vendor_lock_entry_drifted` warning; the drift-kept artifact and entry stay,
  every backend alike — gem included as of v5.0, where a MISSING `Gemfile`/`Gemfile.lock` instead
  warns `vendor_lockfile_missing` and still removes the artifact; composer / maven / nuget, whose
  whole-file wiring cannot tell a converged fragment from a drifted one, keep the artifact exactly
  while the live `composer.lock` / `pom.xml` / `nuget.config` still names its
  `.socket/vendor/<eco>/<uuid>` dir — a file that no longer references it is warned about and the
  artifact removed), removes the artifacts, prunes the
  ledger, sweeps orphan uuid dirs, and (v5.0) prunes the now-empty `.socket/vendor/<eco>/` and
  `.socket/vendor/` levels — `.socket/` itself is removed by the lock guard when nothing else is
  left. It works without a manifest: with no manifest and no ledger it is a clean exit-0 no-op.
* Re-running `vendor` is idempotent (byte-stable lockfiles, deterministic artifacts →
  `already_vendored` skips). Manifest-tracked entries whose patches were dropped from the manifest
  are auto-reverted at the start of the next `vendor` run (`vendor_reconciled` events); `detached`
  entries have no manifest record and are exempt. Standalone `vendor` (no flags) is fed
  by `.socket/manifest.json` only: with no manifest it is a clean exit-0 no-op whose human line names
  the missing manifest — `No manifest found, nothing to vendor.`, or, when the vendor ledger holds
  entries, `No manifest to vendor from; N vendored entr(y is|ies are) tracked in the ledger —
  `socket-patch repair` verifies (it|them).` — and it never re-vendors from the ledger. This no-op
  and `--revert` build no API client (v5.0), so no token advisory prints there.
* **remove reverts vendoring**: `remove <purl|uuid>` on a vendored patch restores the recorded
  lockfile fragments, deletes the artifact, and drops the ledger entry (envelope events
  `removed`/`vendor_reverted`, which do NOT bump `summary.removed` — that count stays "manifest
  entries deleted") before deleting the manifest entry; a revert failure (`vendor_revert_failed`)
  aborts with the manifest intact. `--skip-rollback` ("don't touch my tree") skips the revert too
  (`skipped`/`vendor_state_retained`) — the wiring then stays until the next `vendor` run
  reconciles the dropped entry. `--preserve-state` (v5.0) unwires the lockfile but keeps the
  artifact, the ledger entry (byte-identical — its already-reverted wiring records replay as
  silent no-ops on a later revert, per the liveness contract, and a re-vendor re-wires from the
  live lock probe), AND the manifest entry (`skipped`/`vendor_state_preserved`; `summary.removed`
  stays 0), and skips all GC — equivalent to `rollback <id> --preserve-state`. Ledger entries with
  no manifest record (every `scan`/`get --mode vendored` entry) are removable by purl/uuid through
  the same command (`--skip-rollback` is refused there: reverting IS the removal). **Drift-keep fix (v5.0,
  bugfix)**: when the revert drift-keeps (`kept_artifact` — the lock changed under us and the
  backend left wiring + artifact alone), the manifest entry for that purl is now ALSO kept
  (`skipped`/`vendor_revert_kept`) — previously `remove` dropped it, stranding a live ledger
  entry with no backing record. A run where EVERY matching entry drift-kept exits 1 with
  `status: partialFailure` and top-level error `vendor_revert_kept` (`summary.removed` honest at
  0) — NOT `not_found`, which stays reserved for identifier-matches-nothing. `remove`'s default
  GC also extends (v5.0, additive) from blobs-only to blobs + diff archives + package archives
  (parity with rollback/repair/`scan --prune`; GC errors warn and continue, repair's posture).
* **remove unwinds hosted redirects (v5.0)**: an identifier matching hosted records in the
  redirect ledger unwinds those redirects too — per-purl for the supported ecosystems (cargo +
  npm-family), via the whole-ledger reverse replay when the identifier covers EVERY record (the
  same eligibility rule as `rollback`). A hosted-only match works with no manifest at all
  (mirroring the manifest-less vendored escape). Unsupported-ecosystem hosted targets fail closed
  BEFORE the manifest mutation with top-level `hosted_revert_unsupported` (exit 1; remedy:
  unscoped `socket-patch rollback`, or re-run `scan --mode hosted`); a failed unwind or ledger
  persist is `hosted_revert_failed` (exit 1, manifest not modified). Successful unwinds ride the
  envelope as `removed`/`hosted_reverted` events (bypassing `summary.removed`, like
  `vendor_reverted`). `--skip-rollback` leaves hosted wiring untouched; `--preserve-state` still
  unwinds — hosted has no preservable local state (a stderr note says the records were dropped).
* **rollback reverts vendored and hosted state by default (v5.0, MAJOR — was: excluded)**: the
  agent leg still excludes vendor-owned purls from IN-PLACE restore (their patch lives in the
  committed artifact, not the installed tree, so before-blob restoration is meaningless), but a
  v5.0 `rollback` then unwires those purls through its vendored leg and unwinds hosted redirects
  through its hosted leg — `remove <purl>` and `vendor --revert` are no longer the only exits
  from vendored/hosted state. The JSON `vendored: []` array's meaning NARROWS accordingly (MAJOR):
  it now lists only vendor-owned purls the run did NOT act on (today: the corrupt-vendor-ledger
  skip — reserved-empty in v5.0, since naming skipped purls needs the very ledger that failed
  to load); acted-on entries land in the new `vendoredReverted`/`vendoredPreserved`/`vendoredKept`
  arrays. An identifier matching only vendored purls is still a success, not `not_found`. See
  [Rollback command contract](#rollback-command-contract-v50).
* **apply yields to vendor — every ecosystem**: a purl recorded in the ledger is skipped by
  `apply` with reason `vendored`, even when the installed tree is absent entirely (never
  `package_not_installed`; a vendored variant also accounts for its qualified release-variant
  siblings). Golang especially — apply never repoints a vendor-owned `replace` back at
  `.socket/go-patches/` — and `apply --check` excludes vendored modules from its drift audit.
* **scan skips vendored purls before download** (plain `--apply`/`--sync`): the manifest is never
  moved past the vendored uuid (that would break VEX verification with `vendor_uuid_mismatch`
  until a vendor run). The skip rides `apply.patches[]` as `skipped`/`vendored`; a newer available
  patch still surfaces in `updates[]` — the signal to run `scan --vendor`. In `--json` mode the
  run additionally carries one top-level `vendored_ownership_retained` warning naming the skipped
  purls and the migration path (see "Agent-flow run-level warnings"), so consumers need not dig
  into `apply.patches[]` to learn the mode did not change; exit code and status are unaffected. `scan --prune` exempts
  vendored purls from the crawl-based manifest prune (an absent installed copy is their NORMAL
  state) but reconciles vendored state via the lockfile instead — see the `--prune` section. An
  explicit `get` is allowed to move the manifest past the vendored uuid and warns
  (`warnings[]` + stderr) that a `vendor` run must refresh the artifact — while
  `get … --mode vendored` (v3.6) re-vendors at the new uuid in the same run instead
  of warning (the vendor step immediately resolves the drift the warning describes).
* **Old-binary skew caveat**: EVERY `scan`/`get --mode vendored` entry is now detached-shaped, so a
  `socket-patch` binary that predates the `detached` flag (pre-4.0) running `vendor` against such a
  checkout cannot see the flag and will reconcile-revert every vendored entry; a 4.x binary honors
  the flag but drives its own re-vendor from the manifest and finds nothing to do. Pin the CLI
  version in CI when mixing generations. The ledger schema itself stays parseable both ways
  (additive optional fields).

### Caveats (documented behavior, not bugs)

* npm: a **warm local npm cache** can satisfy `npm ci` by integrity even when the vendored tarball
  is deleted or corrupted on disk — the lockfile integrity, not the file, is the source of truth.
  Fresh checkouts (the committable guarantee) fail closed. Never reuse a stale registry integrity:
  recomputation is mandatory and enforced by the implementation.
* npm redacts uuid-like path segments as `***` in its own error output (its secret heuristic);
  the path on disk and in the lockfile is unaffected.
* cargo: the vendored `[patch]` lives in the workspace-root `Cargo.toml`, so it applies however
  cargo is invoked (the pre-v5 `.cargo/config.toml` wiring was skipped when cargo ran from
  outside the project root). CI should still build with `--locked`.
* cargo (v5.0): the vendored wiring edits the root manifest format-preservingly (comments,
  ordering, CRLF / mixed line endings, a UTF-8 BOM and the trailing-newline state survive; a
  revert with nothing else changed restores `Cargo.toml` byte for byte, keeping a user's
  explicit `[patch]` header and a `[patch.crates-io]` header that another table follows or
  that carries a comment). Vendor refuses up front — nothing written — with
  `cargo_manifest_unreadable` (no root `Cargo.toml`, or not a readable regular file),
  `cargo_manifest_unparseable` (not valid TOML, or `[patch.crates-io]` is not a table),
  `cargo_manifest_symlink_unsupported` (a symlinked `Cargo.toml`; a revert that must edit a
  symlinked manifest fails with the same code, nothing reverted),
  `cargo_manifest_not_workspace_root` (the project directory is a workspace member — its
  manifest sets `package.workspace`, or an ancestor `[workspace]` claims it without
  `exclude` — whose `[patch]` cargo ignores; run from the workspace root),
  `cargo_manifest_patch_source_alias` (the manifest also has a
  `[patch."https://github.com/rust-lang/crates.io-index"]` table — cargo keys manifest
  `[patch]` tables by URL and lets that one replace `[patch.crates-io]` wholesale), and
  `user_authored_patch_entry` (a user-authored crates.io `[patch]` entry in `Cargo.toml` or in
  any cargo config file cargo merges — the project's, every ancestor directory's,
  `$CARGO_HOME`'s — whose crate — `package` or key — is the vendored crate and which is not
  provably a DIFFERENT version: a git/registry patch, or a path whose `Cargo.toml` version is
  unreadable or equal). Each is a `failed` event, exit 1 (`partialFailure`).
* pip/`uv pip`: bare relative requirement paths resolve against the invoking process's CWD; run
  installs from the project root.
* `vendor` exits like `apply`: 0 on success (benign skips included), 1 on any refusal/failure
  (`partialFailure`), 2 on usage errors. `--dry-run` verifies and writes nothing.

## Rollback command contract (v5.0)

> **Semver note.** v5.0 changes `rollback`'s DEFAULT behavior (a default-value/behavior change → **MAJOR** per the [semver policy](#semver-policy)) and narrows the meaning of the existing `vendored: []` JSON key (**MAJOR**). Every new envelope key, flag, and warning code below is additive on top of that.

`rollback` and `scan` are now the batch-level duals — `scan` moves the project toward "fully patched", `rollback` toward "fully unpatched" — the way `get` and `remove` are the single-patch duals. `rollback` needs no `--mode`: it infers what to undo from the three state stores (`.socket/manifest.json` = agent/in-place, `.socket/vendor/state.json` = vendored, `.socket/vendor/redirect-state.json` = hosted).

### Targets

`rollback [TARGET]...` — zero or more targets, unioned. `pkg:` tokens are PURLs (base purl matches every release variant; qualified purl exact), other identifier-shaped tokens are UUIDs, and only **path-shaped** tokens (separator, glob metachar `*?[`, `./` prefix, or absolute) are path globs — see the per-subcommand args table for the safety rationale. Identifier matching runs across ALL THREE stores; an identifier matching nothing anywhere is the familiar exit-1 error. Path globs use the same matcher as `scan [PATHS]` (ancestor rule, `require_literal_separator`, absolute-only outside `--cwd`, Windows case-insensitive): installed copies of every candidate purl are discovered and purls with ≥ 1 matching copy are selected. Scoping sentences (shared with scan):

* **A target that selects nothing is an error on `rollback` (exit 1) and an empty scan on `scan` (exit 0).** Each rollback path pattern must select at least one patched package; the error names the pattern and the reachability rule.
* **Path targets select installed copies; entries with no installed copy are reachable only by identifier or unscoped runs.**
* **Rollback restores every installed copy of a selected patch** — patches are tracked per-package, not per-path; copies restored outside the given patterns are surfaced as an `out_of_scope_copies_restored` warning, never skipped.

`--ecosystems` narrows every leg. `--one-off` still requires ≥ 1 identifier-shaped target and still fails "not yet implemented" before any network or disk activity.

### Default behavior: full-state rollback (MAJOR)

A bare `rollback` (or a scoped one, for its scope) restores the SYSTEM to unpatched and cleans up the local state, in phases under one `apply.lock` acquisition:

1. **State discovery.** A missing manifest is no longer fatal when the vendor or redirect ledger holds work (`rollback` runs manifest-less on hosted-only / vendored projects — every `scan`/`get --mode vendored` project is manifest-less). The **truly-empty** project — all three stores absent — keeps the legacy "Manifest not found" exit 1 (JSON: the legacy `{status: "error", error: "Manifest not found", path}` shape). A project whose lockfiles still reference `.socket/vendor/` artifacts but whose vendor ledger is missing errors naming `socket-patch repair` (reconstruct the ledger, then roll back). **Corrupt-ledger containment**: an unreadable vendor ledger fails ONLY the legs that need it — the vendored leg, manifest cleanup, and GC are skipped fail-closed (`vendor_state_unreadable` warning) while the agent leg still restores files; an unreadable redirect ledger skips only the hosted leg (`redirect_state_unreadable` warning; v5.0 distinguishes a ledger that cannot be READ — EACCES, a directory or FIFO squatting on the path — which is reported as such and left in place with a fix-the-permissions remedy, from MALFORMED JSON, which is quarantined to `redirect-state.json.corrupt` with the restore remedy). Either drives `partial_failure` exit 1; an emergency restore is never blocked by an unrelated corrupt ledger. When the ONLY state on disk is an unreadable ledger, the run fails closed naming the store.
2. **Agent leg** — the existing in-place restore machinery, unchanged (v5.0 presentation: the human `No patches found in manifest` line prints only for an unscoped run with no work in ANY leg — a run whose work is all vendored/hosted stays quiet about the manifest): multi-copy restore, release-variant narrowing, the before-blob gate (+ on-demand download; a gate abort still exits 1 with per-package `missing_blob` failure results **and** skips manifest cleanup + GC entirely — nothing was restored, and the retry's revert data must survive), local-go redirect drop, and the `not_installed` exit-0 asymmetry verbatim. Vendor-owned purls are still excluded here (see the vendored-mode section) — they are handled by the next leg instead of being punted to other commands.
3. **Vendored leg** — each in-scope ledger entry (embedded-record entries included) is reverted through the vendor backends: lockfile wiring restored, artifact dir deleted (and its emptied `.socket/vendor/<eco>/` husk pruned, v5.0), ledger entry dropped + persisted per purl (crash-consistent, like `vendor --revert`). A **drift-keep** (the backend refused a drifted lock) keeps the entry, the artifact, AND the manifest record (`vendoredKept`, exit 1 — the system is still patched); a failure is recorded and other entries proceed.
4. **Hosted leg** — see "Hosted unwind coverage" below.
5. **Manifest cleanup** — entries are removed ONLY for in-scope purls whose legs fully succeeded, were not-installed, or were release-variant siblings narrowed away by an attempted variant that succeeded (half a variant group never lingers — `remove` parity); drift-kept and failed purls keep their records, and a failed variant holds its whole group. No-op removals never rewrite the file. A failed write surfaces as `manifest_write_failed` (warning + `partial_failure` exit 1; GC still runs against the unchanged manifest).
6. **GC** — `cleanup_unused_blobs` + diff/package-archive sweeps against the post-removal manifest, with beforeHash blobs pinned (synthetic afterHash-slot records) for (a) removed-but-not-installed entries (a crawler miss must not destroy the only local revert data — `remove` parity) and (b) EVERY entry remaining in the post-removal manifest — still-active patches (failed, drift-kept, eco-/path-excluded) keep their revert data, so a scoped or failed run never destroys the blobs a later rollback needs; only blobs referenced solely by genuinely-removed entries are swept. GC errors warn (`cleanup_failed`) and continue — they never affect the exit (repair's posture).

**Confirmation prompt.** A wet, non-preserve run with work prompts once, remove-style, composing only the clauses that apply into one English list (`a and b`, `a, b, and c`) with counted nouns: `Roll back N patches`, `remove them from the local manifest`, `delete M vendored artifacts and their ledger records`, `unwind H hosted redirects` (a hosted ledger with leftover edits but no records gets `replay K leftover hosted redirect edits` instead of the unwind clause; e.g. `Roll back 1 patch, remove it from the local manifest, and unwind 1 hosted redirect?`) — default yes, auto-accepted under `--yes`/`--json`/non-TTY (the shared `confirm` semantics; CI unaffected). Decline prints `Rollback cancelled.` and exits 0. `--dry-run` and `--preserve-state` runs are prompt-free (they delete no local state).

### `--preserve-state` (opt-out, both `rollback` and `remove`)

Restore the system but keep the local patch state for a later re-apply: manifest entries kept, vendored artifacts + ledger entries kept byte-identical (only the lockfile wiring is reverted; the already-reverted wiring records replay as silent no-ops on a later revert, and a re-vendor re-wires from the live lock), and all blob/archive GC skipped. **Hosted redirects have no preservable local state**: their ledger records describe live wiring only, so a preserve run still unwinds them and drops the records either way — surfaced as the `hosted_state_not_preservable` warning (re-run `scan --mode hosted` to re-wire). Caveat (documented): preserved vendored entries may be reclaimed by an explicit later `scan --prune` (user-invoked GC); `vendor` re-runs re-wire them.

**Replay fail-closed carve-outs (v5.0)**: the gem SECTION-MOVE record (`redirect_gemfile_lock_gem_source`) refuses in the replay — the writer records only the bare remote URLs, not the moved spec block, so a URL swap cannot invert the move (remedy: `scan --mode hosted` normalize). A socket-owned go.mod `replace` folded into a `replace ( … )` BLOCK and later refreshed also refuses (the ledger records the single-line spelling). Both keep their records + edits for a retry. **Ledger persistence rule**: rollback and remove persist the mutated redirect ledger whenever it changed — INCLUDING on partial-failure exits — so lockfile writes that already flushed are never stranded against a stale on-disk ledger. **Lock discipline**: all three state stores are LOADED under the apply lock (only cheap existence probes run before it), so a concurrent run's writes are never clobbered by a stale pre-lock snapshot. **Residue rule (v5.0)**: a reversal that empties a ledger deletes the file — `redirect-state.json` and/or `vendor/state.json` — and prunes the emptied `.socket/vendor/<eco>/` and `.socket/vendor/` directories (non-recursive, so a `redirect-state.json.corrupt` quarantine or any other stray file keeps its directory alive — the one sanctioned `.socket/vendor/` residue); emptied `blobs/`, `diffs/` and `packages/` stores are removed by the GC sweep; `.socket/` itself is removed by the lock guard when the run leaves it empty, so a fully unwound hosted or vendored project has no `.socket/` at all. What legitimately survives a full reversal: `.socket/manifest.json` at `{"patches": {}}` (+ its `setup` block — never deleted, see the exit-code section), the setup-owned `.socket/.gitignore`, `gem-plugin-stamp` and `bundler-plugin/`, and `.corrupt` quarantine files.

### Hosted unwind coverage

* **Per-purl reverts** exist for **cargo, golang and the npm family** (`redirect_revert_supported`): staged, fail-closed on drift, and honoring `dry_run` (every inverse and drift check resolves like a wet run; nothing flushes and the ledger is untouched). npm purls on projects with bun-lock edits DEFER to the whole-ledger replay (below) whenever it will run — the scope covers every record, and the replay stages the bun group all-or-nothing. A SCOPED unwind (`rollback <purl>`, or `remove <purl>` while other hosted records remain) takes the per-purl revert instead: it claims that purl's `redirect_bun_lock_package` edits by the recorded line's spec (`<name>@<version>` registry spec, or a hosted URL whose tarball leaf is `<name>-<version>.tgz`) and replays them like the yarn/pnpm text kinds (whole-line fragments, CRLF-exact); a sibling version's edit is neither claimed nor a refusal; an edit that mentions the package but is not a bun packages-entry line refuses with the unscoped-`rollback` remedy. Pinned by `tests/in_process_vendor_bun_takeover.rs` (`bun_scoped_rollback_of_one_of_two_hosted_records_unwinds_only_that_purl` and the `remove` twin). Native binary `redirect_bun_lockb_package` snapshots follow the same scoped ownership rule and restore only the claimed package records; unrelated binary resolutions stay intact. yarn lock blocks (`redirect_yarn_berry_entry` / `redirect_yarn_classic_entry`) are recorded in the lock's on-disk line endings and replayed byte-exactly; when a `core.autocrlf` checkout has since flipped the lock's UNIFORM ending (LF ↔ CRLF — the committed ledger keeps its fragments verbatim), this per-purl revert and the whole-ledger replay below match the recorded blocks respelled in the live ending and restore in that ending (v5.0). A lock with mixed endings proves nothing and still refuses as drift.
* **Whole-ledger reverse replay** (`revert_remaining_redirect_edits`, core `patch/redirect/replay.rs`) runs whenever the in-scope hosted record set equals the FULL ledger record set — however the scope was spelled (bare `rollback`, `rollback '**'`, an identifier set covering every record; `remove` reuses the same eligibility rule). It walks every remaining ledger edit in reverse write order through a **per-kind inverse table**, staged and committed **per ecosystem group, all-or-nothing**: one drifted, ambiguous (a fragment appearing more than once), or unhandled edit refuses the whole group byte-untouched while other groups proceed. This covers **gem, golang, pypi, composer, bun**, the yarn/pnpm text kinds (normally claimed by the per-purl npm revert first), and the **non-package rideshare edits** — the pnpm `trustLockfile` auto-config (a pristine created scaffold is deleted; a user-modified one keeps the file and loses only the `trustLockfile: true` line, warned as `redirect_pnpm_trust_scaffold_modified`) — plus a "last one out turns off the lights" pass: when the record map empties but non-package edits remain, they are replayed in the same persist, so the trust edit never strands. The npm `.npmrc` `allow-remote=all` auto-config (`redirect_npmrc_allow_remote`) replays in the `npm` group (a pristine created file is deleted; otherwise only the line is removed, warned as `redirect_npmrc_allow_remote_modified` for a modified created file) and is ALSO claimed by the per-purl npm revert of the last package-lock entry, so a scoped unwind never strands it.
* **maven and nuget fail closed**: their structured-metadata kinds (`redirect_maven_repository` / `redirect_maven_dep_management` / `redirect_maven_config` / `redirect_maven_trusted_checksums`, `redirect_nuget_source` / `redirect_nuget_lock`) have no revert implementation, so any such edit refuses its whole group (the maven `<version>` suffix rewrite alone IS invertible, but it rides the same all-or-nothing group). The refusal keeps their records + edits in the ledger and names the remedy: re-run `scan --mode hosted` to normalize, or restore the lockfiles from version control. Unknown future kinds refuse the same way (forward-compat).
* **Scoped runs** (paths / identifiers / `--ecosystems`) that do NOT cover the full record set get per-purl reverts only; in-scope hosted purls of ecosystems without one fail closed — `rollback` reports them in `hosted.unsupported` (exit 1), `remove` as the top-level `hosted_revert_unsupported` error — with the remedy "run an unscoped `socket-patch rollback` to unwind ALL hosted redirects, or re-run `scan --mode hosted`".
* **Ledger accounting**: exactly the replayed (or already-at-original) edits are dropped; a record is dropped only when every group its ecosystem writes ended clean, so refused groups keep both edits and records — the intermediate-but-coherent ledger a retry needs. The mutated ledger is persisted (delete-when-empty); a failed persist rides `hosted.failed` / `hosted_revert_failed`.

### JSON envelope (legacy shape + additive always-present keys)

`rollback --json` keeps its legacy top-level shape (`status` — `"success"` \| `"partial_failure"` — `rolledBack`, `alreadyOriginal`, `failed`, `dryRun`, `results[]`) and adds these keys, ALL always present so consumers never null-check:

| Key | Shape | Meaning |
|---|---|---|
| `warnings` | `[{code, detail}]` | Run-level warnings, now populated (previously always empty): `reinstall_required`, `hosted_state_not_preservable`, `out_of_scope_copies_restored`, `vendor_state_unreadable`, `redirect_state_unreadable`, `cleanup_failed`, `manifest_write_failed`, `redirect_pnpm_trust_scaffold_modified`, `redirect_npmrc_allow_remote_modified`, `ownership_not_restored` (a restored file whose ownership could not be put back — see the apply warnings), plus vendored/hosted leg advisories. New codes are additive (MINOR) |
| `vendored` | `[purl]` | **Meaning narrowed (MAJOR)**: vendor-owned purls the run did NOT act on — today exactly the corrupt-vendor-ledger skip. Previously this listed every vendor-owned skip |
| `vendoredReverted` | `[purl]` | Ledger entries cleanly reverted this run (unwired + artifact deleted + entry dropped; previewed on dry-run) |
| `vendoredPreserved` | `[purl]` | `--preserve-state`: unwired with artifact + ledger entry kept |
| `vendoredKept` | `[{purl, reason}]` | Drift-keeps — wiring drifted, vendored state (and the manifest entry) left untouched; drives exit 1 |
| `vendoredFailed` | `[{purl, error}]` | Vendored reverts that errored — entry, artifact, and manifest record all survive for a retry; drives exit 1 |
| `hosted` | `{reverted: [purl], failed: [{purl, error}], unsupported: [purl], editedFiles: N}` | The hosted leg. `failed` entries may carry a `group:<name>` pseudo-purl for whole-group replay refusals; `unsupported` lists scoped purls with no per-purl revert; `editedFiles` counts distinct files rewritten |
| `manifest` | `{removedEntries: [purl], preserved: bool}` | Entries removed from the manifest (would-be removals on dry-run); `preserved` mirrors `--preserve-state` |
| `gc` | `{skipped: true}` \| `{removedBlobs, removedDiffArchives, removedPackageArchives, bytesFreed}` | Skipped under `--preserve-state`, after a blob-gate abort, and under a corrupt vendor ledger |
| `paths` | `[string]` | The path-glob targets verbatim (empty when none) |

**Exit rules**: not-installed entries never flip the exit (the documented apply/rollback asymmetry — even an all-not-installed run exits 0 `success`). Everything that leaves the system still patched DOES flip it to `partial_failure` exit 1: agent-leg failures, vendored drift-keeps and revert failures, hosted refusals and scoped-unsupported targets, corrupt ledgers, and a failed manifest write. GC failures never affect the exit.

## Self-update contract (`socket-patch --update`)

`socket-patch --update [VERSION]` replaces the running binary with a release from `https://github.com/SocketDev/socket-patch/releases` — the same artifacts, `SHA256SUMS` verification, and asset naming `install.sh` uses. It is for **standalone installs** (install.sh, manual tarball copy); every other channel is refused with that channel's own upgrade command.

Synopsis and behavior:

| Invocation | Behavior |
|---|---|
| `--update` | Resolve the latest release; install it if newer than the running version. Already-newest (including a dev build newer than any release): informational no-op, exit 0. `latest` never downgrades. |
| `--update 3.4.0` | Install exactly that version, **up or down** — an explicit pin is explicit intent, no `--force` needed. Pin == current: no-op, exit 0. The inline `--update=3.4.0` spelling is equivalent. Also settable via `SOCKET_PATCH_VERSION` (the same pin env `install.sh` and the gem launcher honor); a malformed version is a usage error (exit 2). |
| `--update --force` | Reinstall/downgrade even when already at the target version, and proceed past a managed-install refusal (with a warning that the owning manager's next upgrade will overwrite the binary). Env: `SOCKET_FORCE`. |
| `--update --dry-run` | **Check-only**: one metadata request, zero downloads, zero mutation, exit 0 — and always the `verified`/`update_check` event shape, whether or not an update exists. `--json` details carry `{current, latest, updateAvailable, target, asset, path}` — the cheap scriptable "is an update available" probe. |
| `--update --offline` | Refused up front (strict airgap, before any client exists), exit 1. `--force` does **not** bypass it. |

Honored global flags: `--json`, `--silent` (errors only), `--yes` (skip the confirm prompt; `--json` also auto-confirms), `--dry-run`, `--offline`, `--verbose`, `--debug`, `--no-telemetry`. Other global flags parse and are ignored (the `list --global` precedent).

**Managed-install refusal.** The canonicalized executable path (symlinked invocations resolve to the real file) is classified before any network I/O; non-standalone channels exit 1 with `errorCode: managed_install` and the owning manager's command:

| Detected channel | Hint |
|---|---|
| npm (`node_modules` path component) | project-local (the directory holding the outermost `node_modules` has a `package.json`, and it is not directly under `lib`/`npm` or below a yarn/pnpm `global` store): `npm install @socketsecurity/socket-patch@latest`; otherwise global (including version-manager prefixes such as nvm-windows and fnm): `npm update -g @socketsecurity/socket-patch` |
| PyPI wheel (`site-packages`/`dist-packages`) | `pip install --upgrade socket-patch` |
| `cargo install` (`$CARGO_HOME/bin`, `~/.cargo/bin`) | `cargo install socket-patch-cli` |
| gem launcher cache (`<cache>/socket-patch/bin/…`) | `gem update socket-patch` |
| Homebrew (`Cellar`, `/opt/homebrew`) | `brew upgrade socket-patch` |

**Pipeline order** (each step gates the next; a failure at any point leaves the installed binary untouched): fetch `SHA256SUMS` → fetch the archive (`socket-patch-<target-triple>.tar.gz`/`.zip`, explicit timeouts, size caps) → verify the SHA-256 **before** extraction → extract the single expected member → stage as an executable sibling **in the install directory** (`EACCES` here is the permissions preflight → exit 1 with a sudo hint; system temp is never used, so `noexec` mounts don't matter) → run the staged binary's `--version` self-check (against real GitHub the reported version must equal the release tag; under a `SOCKET_UPDATE_BASE_URL` override a mismatch only warns) → one atomic rename over the install path (mode-preserving; a **setuid/setgid** target — or, on Linux, one carrying **file capabilities** (`setcap`) — is refused, since an unprivileged swap cannot restore those grants; Windows uses the rename-dance via `self-replace`). Concurrent updates are single-flighted per environment by an advisory lock at `<state dir>/update.lock` (`errorCode: update_in_progress`; the OS releases a dead holder's lock, so there is no stale-lock state). Two updaters whose state dirs diverge (e.g. different `$HOME`s targeting one shared `/usr/local/bin`) are not serialized, but every path to the destination is a whole-file rename and stage cleanup is age-gated — the worst case is duplicated work, never a torn binary.

**Envelope.** `command: "update"`. Success events: `downloaded` (`details: {asset, bytes, sha256}`) then `updated` (`details: {from, to, path, target}`). No-op: `skipped` with reason `already_latest`. Dry-run: `verified` with reason `update_check`. Non-fatal advisories ride the run-level `warnings[]` (`{code, detail}`, omitted when empty) — human runs print the same text to stderr as `Warning: <detail>` (first letter capitalized), and `--json` (which silences stderr) carries them here instead so an override is never silent: `managed_install_override` (a `--force` run replaced a package-manager-owned binary that manager's next upgrade will overwrite) and `update_warning` (a non-fatal note from the update engine, today the relaxed version self-check under a `SOCKET_UPDATE_BASE_URL` override). Top-level `errorCode` values (stable): `offline`, `managed_install`, `check_failed`, `asset_not_found`, `download_failed`, `checksum_mismatch`, `verify_failed`, `swap_failed`, `permission_denied`, `update_in_progress`. Exit codes: 0 success / no-op / dry-run; 1 operational failure; 2 usage.

**Trust model.** Checksum-only, rooted in HTTPS + GitHub (identical to install.sh and the launcher wrappers): `SHA256SUMS` is served from the same origin as the archives, there are no signatures yet. Downloads are credential-free — the Socket API bearer is never sent to the release host — and non-HTTPS redirect hops are refused when talking to the default endpoints.

### Passive update notice

Commands other than `--update` itself may print, on **stderr only**, after all command output:

```
[socket-patch] Update available: 3.3.0 → 3.4.0
[socket-patch] Run `socket-patch --update` to upgrade (set SOCKET_NO_UPDATE_CHECK=1 to hide)
```

The notice is preceded by one blank line (it follows the command's own output, often an error). The second line is channel-aware (an npm-managed install is pointed at its npm upgrade command from the table above, not at `--update`). Contract promises:

- At most one release-metadata fetch per 24 h (cached in the state file below; a failed fetch also counts), and at most one notice per 24 h while an update is pending.
- Never under `--json`, `--silent`, `--offline`/`SOCKET_OFFLINE`, in CI (`CI`/`GITHUB_ACTIONS` env), when stderr is not a terminal, or when `SOCKET_NO_UPDATE_CHECK` is truthy. Silenced means **zero network I/O**, not just no output.
- Never changes a command's exit code or stdout; adds at most ~500 ms to a run (the background check is abandoned past that grace budget and retried on a later run).
- State-file corruption, clock skew, or an unwritable cache dir degrade to "never checked" — they can never break a command.
- Independent of telemetry: `--no-telemetry` does not affect the update check (it fetches public release metadata with no identifying payload beyond the CLI User-Agent); `SOCKET_OFFLINE` kills both.

State lives at `$XDG_CACHE_HOME`|`~/.cache` (Unix/macOS) or `%LOCALAPPDATA%` (Windows) + `/socket-patch/update-check.json` (camelCase JSON: `schemaVersion`, `lastCheckAt`, `latestSeen`, `lastNotifiedAt`; unix seconds). A completed `--update` refreshes `latestSeen`, so the notifier never nags about a version the user just installed.

## Environment variables

All v3.0 env vars use the `SOCKET_*` prefix. Three legacy `SOCKET_PATCH_*` names are still honored at runtime for compatibility: on first read of any of the three the binary emits a one-shot deprecation warning to stderr (the warning fires unconditionally — even under `--silent` / `--json` — because it's a transition signal users need to see). The legacy names will be removed in the next major release.

Four `SOCKET_CLI_*` names from the sibling JS Socket CLI are additionally accepted as **peer aliases** (supported, not deprecated — no warning): `SOCKET_CLI_API_TOKEN` → `SOCKET_API_TOKEN`, `SOCKET_CLI_ORG_SLUG` → `SOCKET_ORG_SLUG`, `SOCKET_CLI_API_BASE_URL` → `SOCKET_API_URL`, `SOCKET_CLI_NO_API_TOKEN` → `SOCKET_NO_API_TOKEN`. The canonical `SOCKET_*` name always wins when both are set; promotion is silent and happens in-process before clap parses. Other socket-cli names (`SOCKET_CLI_CONFIG`, `SOCKET_CLI_API_PROXY`, `SOCKET_CLI_DEBUG`) are deliberately **not** honored.

Empty string means unset at every layer: exported-but-empty flag-bound vars are scrubbed before clap parses, and the API-client resolution filters empty values at each fallback step.

| Env var | CLI equivalent | Default | Notes |
|---|---|---|---|
| `SOCKET_CWD` | `--cwd` | `.` | — |
| `SOCKET_MANIFEST_PATH` | `--manifest-path` | `.socket/manifest.json` | — |
| `SOCKET_API_URL` | `--api-url` | `https://api.socket.dev` | — |
| `SOCKET_API_TOKEN` | `--api-token` | (none) | Absence selects the public proxy. |
| `SOCKET_ORG_SLUG` | `--org` / `-o` | (auto-resolve) | — |
| `SOCKET_PROXY_URL` | `--proxy-url` | `https://patches-api.socket.dev` | **Renamed in v3.0** (was `SOCKET_PATCH_PROXY_URL`). |
| `SOCKET_ECOSYSTEMS` | `--ecosystems` / `-e` | (all) | Comma-separated list. |
| `SOCKET_DOWNLOAD_MODE` | `--download-mode` | `diff` | One of `diff` / `package` / `file`. |
| `SOCKET_VENDOR_SOURCE` | `--vendor-source` | `auto` | One of `auto` / `service` / `build`. |
| `SOCKET_VENDOR_URL` | `--vendor-url` | (active API/proxy base) | Vendoring-service package-reference host. |
| `SOCKET_PATCH_SERVER_URL` | `--patch-server-url` | (server-returned) | Rewrites the prebuilt-archive download host. |
| `SOCKET_OFFLINE` | `--offline` | `false` | — |
| `SOCKET_STRICT` | `--strict` | `false` | Mismatch policy for the in-place apply paths; see "Global arguments". |
| `SOCKET_GLOBAL` | `--global` / `-g` | `false` | — |
| `SOCKET_GLOBAL_PREFIX` | `--global-prefix` | (auto) | — |
| `SOCKET_JSON` | `--json` / `-j` | `false` | — |
| `SOCKET_VERBOSE` | `--verbose` / `-v` | `false` | — |
| `SOCKET_SILENT` | `--silent` / `-s` | `false` | — |
| `SOCKET_DRY_RUN` | `--dry-run` | `false` | — |
| `SOCKET_YES` | `--yes` / `-y` | `false` | — |
| `SOCKET_LOCK_TIMEOUT` | `--lock-timeout` | (none) | Seconds to wait for `apply.lock` on the lock-taking subcommands (incl. hosted/vendored `scan`/`get`); unset/`0` = single non-blocking try. |
| `SOCKET_DEBUG` | `--debug` | `false` | **Renamed in v3.0** (was `SOCKET_PATCH_DEBUG`). |
| `SOCKET_TELEMETRY_DISABLED` | `--no-telemetry` | `false` | **Renamed in v3.0** (was `SOCKET_PATCH_TELEMETRY_DISABLED`). |
| `SOCKET_FORCE` | `apply --force` / `-f`, `--update --force` | `false` | Local to `apply` and `--update`. |
| `SOCKET_PATCH_VERSION` | `--update <VERSION>` | (latest) | Local to `--update`; the same pin `install.sh` and the gem launcher honor. Not one of the deprecated legacy `SOCKET_PATCH_*` trio. |
| `SOCKET_BATCH_SIZE` | `scan --batch-size` | `100` | Local to `scan`. |
| `SOCKET_SAVE_ONLY` | `get --save-only` | `false` | Local to `get`. |
| `SOCKET_ONE_OFF` | `get --one-off` / `rollback --one-off` | `false` | Local to `get`/`rollback`. Both are **not yet implemented**: the flag parses (boolishly, empty-tolerant) and the command fails up front with a "not yet implemented" error, before any network or disk activity (on `rollback`, with no identifier-shaped target it instead fails "requires an identifier", equally up front). |
| `SOCKET_ALL_RELEASES` | `get --all-releases` / `scan --all-releases` | `false` | Local to `get`/`scan`. Download patches for every release/distribution variant, not just the installed one. |
| `SOCKET_SKIP_ROLLBACK` | `remove --skip-rollback` | `false` | Local to `remove`. Conflicts with `--preserve-state`/`SOCKET_PRESERVE_STATE` (exit 2 — see below). |
| `SOCKET_PRESERVE_STATE` | `rollback --preserve-state` / `remove --preserve-state` | `false` | (v5.0) Shared by `rollback`/`remove` (boolish, empty-tolerant parse like the other bool flags): restore the system but keep the local patch state — manifest entries, vendored artifacts + ledger entries — and skip all GC. On `remove`, combining it with `--skip-rollback` is a usage error (exit 2) **whether either side is flag- or env-sourced** (`SOCKET_PRESERVE_STATE=true remove --skip-rollback` exits 2 too). |
| `SOCKET_DOWNLOAD_ONLY` | `repair --download-only` | `false` | Local to `repair`. |
| `SOCKET_SETUP_EXCLUDE` | `setup --exclude` | (none) | Local to `setup`; comma-separated workspace-member paths, persisted to `setup.exclude`. |
| `SOCKET_VEX` | `apply --vex` / `scan --vex` / `vendor --vex` | (none) | Embedded OpenVEX output path. The `SOCKET_VEX_*` knobs (`_PRODUCT`, `_NO_VERIFY`, `_DOC_ID`, `_COMPACT`) are shared with the standalone `vex` command; on the host commands they bind to `--vex-product` etc. |
| `SOCKET_VEX_OUTPUT` | `vex --output` / `-O` | (none) | Local to the standalone `vex`: document output path (required with `--json`). |

### Config-layer toggles (env-only)

| Env var | Default | Notes |
|---|---|---|
| `SOCKET_NO_CONFIG` | `false` | Truthy (`1`/`true`/`yes`/`on`): disable the socket-cli persisted-config fallback layer entirely — pure flag+env behavior. Also the test-hermeticity switch (the workspace `.cargo/config.toml` exports it as `1` for every cargo-run process). |
| `SOCKET_NO_API_TOKEN` | `false` | Truthy: ignore **ambient** API tokens (the `SOCKET_API_TOKEN` env var and the socket-cli config token); only an explicit `--api-token` flag authenticates. Peer alias: `SOCKET_CLI_NO_API_TOKEN`. |
| `SOCKET_NO_UPDATE_CHECK` | `false` | Truthy: disable the passive update notice entirely (see "Passive update notice"). Explicit `--update` still works. Also a test-hermeticity switch (the workspace `.cargo/config.toml` exports it as `1` for every cargo-run process). No `SOCKET_CLI_*` alias (socket-cli has no equivalent today). |

### Persisted configuration (socket-cli `config.json`)

The binary reads — **never writes** — the JS Socket CLI's persisted config, so a single `socket login` (or `socket config set apiToken/defaultOrg`) configures socket-patch too. The file is `<data dir>/socket/settings/config.json`, a base64-encoded JSON object:

| Platform | Location |
|---|---|
| Linux | `$XDG_DATA_HOME` or `~/.local/share`, + `/socket/settings/config.json` |
| macOS | `$XDG_DATA_HOME` or `~/Library/Application Support`, + `/socket/settings/config.json`; when `$XDG_DATA_HOME` is unset the legacy `~/.local/share` location is probed second (older socket-cli releases wrote the Linux-style path on every platform) |
| Windows | `%LOCALAPPDATA%` or `%USERPROFILE%\AppData\Local`, + `\socket\settings\config.json` |

Exactly three keys are honored, each slotting **below** the env var and **above** the built-in default for its setting, resolved per key independently:

| Config key | Feeds | Env var above it |
|---|---|---|
| `apiToken` | `--api-token` | `SOCKET_API_TOKEN` |
| `defaultOrg` (alias `org`; `defaultOrg` wins) | `--org` | `SOCKET_ORG_SLUG` |
| `apiBaseUrl` | `--api-url` | `SOCKET_API_URL` |

Contract properties:

- **Read-only pledge**: socket-patch never creates, modifies, or deletes this file; socket-cli owns it. There is no `socket-patch login`/`config` subcommand — use `socket login`.
- Other socket-cli keys (`apiProxy`, `enforcedOrgs`, `skipAskToPersistDefaultOrg`) and unknown keys are ignored. Non-string or empty values for the three honored keys count as unset. For an HTTP forward proxy use the standard `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` vars, which the HTTP client honors; socket-cli's `apiProxy` is deliberately not mapped (and is unrelated to `--proxy-url`, which is the public patch *endpoint*).
- Missing file / unresolvable data dir: silent (the normal case). Present but unreadable or undecodable (not base64(JSON), with a plain-JSON leniency fallback): a one-shot stderr warning naming the path, then treated as absent — never fatal, and `--json` stdout stays clean (all diagnostics are stderr-only).
- The file is read lazily at most once per process, only when a key is still unresolved after flag + env.
- The telemetry endpoint resolver shares the same `apiBaseUrl` chain as API-client construction (`resolve_api_base_url`), so telemetry can never target a different host than the client.
- `--offline` semantics are unchanged: reading the local file is not network contact; a config-sourced token is inert offline.
- **Repo-level files never carry endpoints, credentials, or interlock-disablers**: configuration for those comes only from flags, env vars, this user-level file, and built-in defaults — never from files inside the repository being patched (manifest, socket.yml, `.env`, …).
- `--debug` names the source on stderr whenever a setting resolves from the socket-cli config (the token value itself is never echoed).

### Registry override env vars

Env-only knobs (no CLI flag) read by the vendor auto-fetch / artifact-rebuild paths in `socket-patch-core` (`src/vendor/registry_fetch.rs`, `src/vendor/maven_repo.rs`). Each is the enterprise-mirror / test escape hatch for one registry base; trailing slashes are trimmed and an exported-but-empty value falls back to the default. Lock-recorded URLs (npm/yarn/composer/gem/uv `resolved`/dist URLs) are used verbatim and bypass these.

| Env var | Default | Notes |
|---|---|---|
| `SOCKET_NPM_REGISTRY` | `https://registry.npmjs.org` | Base for conventional npm tarball URLs (vendor auto-fetch + the npm-family lockfile-integrity reconstruction rung in `repair`). |
| `SOCKET_CRATES_REGISTRY` | `https://static.crates.io/crates` | crates.io static `.crate` download host. |
| `SOCKET_GOPROXY` | `https://proxy.golang.org` | Go module proxy. Wins over the standard `GOPROXY` env var, whose first element is used otherwise. When that element is `off` or `direct`, or the module matches `GONOPROXY` (default `GOPRIVATE`), go would not ask a proxy, so the pristine fetch is refused (`vendor_fetch_unverifiable` + the calm `package_not_installed` skip) instead of falling back to `proxy.golang.org`. |
| `SOCKET_MAVEN_REGISTRY` | `https://repo1.maven.org/maven2` | maven2 base for the fallback upstream-pom download. |

### Internal env vars (no stability guarantee)

These exist for staged rollouts and the launcher wrappers. They are **internal**: names, semantics, and existence may change in any release without a semver bump.

| Env var | Purpose |
|---|---|
| `SOCKET_PATCH_BIN` | Points the RubyGems CLI launcher and the gem Bundler plugin at an existing `socket-patch` binary (skips the download-on-first-run); also the escape hatch `apply` names when a golang-featureless binary is asked to audit Go redirects. |
| `SOCKET_UPDATE_BASE_URL` | Points BOTH the release-metadata and asset-download routes of `--update`/the update notice at one base (mirror or test fixture) instead of `github.com` + `api.github.com`. Overriding it relaxes the downloaded binary's version self-check from hard-fail to warning. |
| `SOCKET_UPDATE_STATE_DIR` | Overrides the per-user dir holding `update-check.json` + `update.lock` (tests point it into a tempdir). |
| `SOCKET_UPDATE_TIMEOUT_MS` | Caps the update fetches' connect/metadata/download budgets (defaults 10 s / 30 s / 300 s; the notice's fetch defaults to 2 s). Doubles as the slow-network escape hatch. |
| `SOCKET_UPDATE_NOTIFIER_FORCE` | Test hook: bypasses the update notice's stderr-TTY guard — and nothing else (opt-out, offline, `--silent`, `--json`, CI all still win). |
| `SOCKET_UPDATE_GRACE_MS` | Test hook: overrides the notice's post-command join grace (default 500 ms — how long the run waits for the background check before abandoning it and exiting). Lets the e2e suite await the loopback fetch to completion so its observable effect is deterministic; production keeps the tight 500 ms ceiling. |

### Deprecated env vars

| Legacy | Renamed to | Status |
|---|---|---|
| `SOCKET_PATCH_PROXY_URL` | `SOCKET_PROXY_URL` | Honored with warning; remove in next major. |
| `SOCKET_PATCH_DEBUG` | `SOCKET_DEBUG` | Honored with warning; remove in next major. |
| `SOCKET_PATCH_TELEMETRY_DISABLED` | `SOCKET_TELEMETRY_DISABLED` | Honored with warning; remove in next major. |

## CSV value parsing

`--ecosystems` on `apply`, `rollback`, and `scan` uses clap's `value_delimiter = ','`. Input `--ecosystems npm,pypi,cargo` becomes `vec!["npm", "pypi", "cargo"]`. Switching to space-separated or dropping the delimiter is a **breaking** change.

## JSON output shapes

Every `--json` invocation emits a single JSON object that follows the **unified envelope** below. The envelope was introduced in v3.0; older per-command shapes are deprecated. See `src/json_envelope.rs` for the source of truth and `tests/cli_parse_*.rs` for snapshot tests that lock the shape.

### Envelope shape

```jsonc
{
  "command":  "scan" | "apply" | "vex" | "vendor" | "setup" | "rollback" | "get" | "list" | "remove" | "repair",
  "status":   "success" | "partialFailure" | "error" | "noManifest" | "paidRequired" | "notFound",
  "dryRun":   false,
  "events":   [ <PatchEvent>, ... ],
  "summary":  {
    "discovered":      0,
    "downloaded":      0,
    "applied":         0,
    "updated":         0,
    "skipped":         0,
    "failed":          0,
    "removed":         0,
    "verified":        0,
    "bytesDownloaded": 0,
    "bytesFreed":      0
  },
  "error":    { "code": "...", "message": "..." }   // only on status=error
}
```

`events` is the load-bearing payload. `summary` is pre-computed from `events` so consumers don't have to walk the array. `error` is set only on top-level failures (e.g. `manifest_not_found`); per-patch failures appear as `events[*]` with `action: "failed"`.

### `PatchEvent` shape

```jsonc
{
  "action":    "discovered" | "downloaded" | "applied" | "updated" | "skipped" | "failed" | "removed" | "verified",
  "purl":      "pkg:npm/foo@1.2.3",        // omitted on artifact-level events
  "uuid":      "<patch uuid>",              // optional
  "oldUuid":   "<previous uuid>",           // only when action=updated
  "files": [
    {
      "path":        "package/index.js",
      "verified":    true,
      "appliedVia":  "package" | "diff" | "blob"   // only on action=applied
    }
  ],
  "bytes":      1234,                       // optional (downloaded/removed)
  "reason":     "Files match afterHash",    // human-readable explanation (skipped)
  "errorCode":  "already_patched",          // stable snake_case routing tag
  "error":      "<message>",                // only when action=failed
  "details":    { ... }                     // command-specific extras (see below)
}
```

`details` is intentionally schemaless — different subcommands attach different keys. Consumers MUST treat unknown keys as best-effort metadata and must not break on absence.

### `PatchAction` vocabulary

| Action       | Emitted by                            | Meaning |
|--------------|---------------------------------------|---------|
| `discovered` | `scan`, `list`                        | Patch exists upstream / in the manifest — no work taken. |
| `downloaded` | `get`, `repair`, `scan --apply`       | Patch bytes were fetched from the registry. `bytes` set. |
| `applied`    | `apply`, `scan --sync`                | Patch was written to disk. `files` enumerates what changed. |
| `updated`    | `apply`, `scan --sync`, `get`         | A different UUID replaced an older one for this PURL. `oldUuid` set. |
| `skipped`    | every command                         | No-op — already patched, not in scope, filtered, etc. `errorCode` carries the reason. |
| `failed`     | every command                         | A specific patch attempt failed. `errorCode` + `error` set. |
| `removed`    | `gc`/`repair`, `remove`, `rollback`   | Data was removed from `.socket/` (or files rolled back). `bytes` optional. |
| `verified`   | `apply --dry-run`, `scan --dry-run`   | The patch *would* apply cleanly. `files` lists previewed changes. |
| `rebuilt`    | `repair`                              | A missing/corrupt vendored artifact was rebuilt in place (or its lost ledger entry restored — `details.ledgerRestored`). `summary.rebuilt` counts these (the field is omitted while zero). |

### Stable `errorCode` tags

| Tag                       | Action(s)        | Context |
|---------------------------|------------------|---------|
| `already_patched`         | `skipped`        | apply: every file's hash already matches `afterHash`. |
| `package_not_installed`   | `skipped`        | apply: manifest entry has no matching installed package. |
| `apply_failed`            | `failed`         | apply: hash mismatch, write error, archive read error. |
| `no_local_source`         | `skipped`/`failed` | `--offline` and the patch is missing from `.socket/`. |
| `offline_missing_sources` / `sources_download_failed` | apply run-level `warnings[]` | apply (additive): the patch sources were unavailable — `--offline` with no local source, or the download left a patch with no source — so nothing was attempted. The envelope keeps its pinned shape (`partialFailure`, empty `events[]`, zero summary, no top-level `error`); the warning is its machine-readable reason (the human path prints the staging `Error:` line on stderr instead, even under `--silent`). |
| `paid_required`           | `failed` / status=`paidRequired` | get/scan: patch needs a paid plan and the caller's token isn't entitled. `get <uuid>` on the public proxy reports it (exit 0) both for a `tier: "paid"` view and for the proxy's 403 refusal, whose record then carries only `uuid` + `tier` (the proxy never named the purl). |
| `download_failed`         | `failed`         | repair/get: network or 404 on patch fetch. |
| `cleanup_failed`          | `skipped` (warning) | repair: an orphan-sweep pass (blobs, diff or package archives) failed mid-way (e.g. permission error). The run continues and exits 0; human mode carries the warning on stderr (not muted by `--silent`). v5.0: `rollback`'s default GC surfaces the same condition in its run-level `warnings[]` (and `remove`'s extended archive GC on stderr) — same posture, never affects the exit. |
| `rollback_failed`         | `failed`         | remove/rollback: file restore could not complete. |
| `vendored`                | `skipped`        | apply (every ecosystem) + scan `--apply`: the package is managed by `socket-patch vendor`; the command yields ownership (scan also skips the download). v5.0: rollback no longer yields — its vendored leg reverts these entries by default, and its `vendored: []` array is reserved-empty (a corrupt vendor ledger surfaces via the `vendor_state_unreadable` warning + exit 1 — the skip cannot name purls, since naming them needs the ledger). Scan `--apply --json` additionally surfaces one run-level `vendored_ownership_retained` warning naming the skipped purls (additive; exit/status unchanged). |
| `vendor_reverted`         | `removed`        | remove: vendoring reverted (lock fragments restored, artifact + ledger entry gone) as part of removing the patch. |
| `vendor_revert_failed`    | top-level error  | remove: the vendor revert failed; the manifest was NOT modified. |
| `vendor_state_retained`   | `skipped`        | remove `--skip-rollback`: vendor wiring + artifact deliberately left in place (the next `vendor` run reconciles the dropped entry). Also the top-level error code when `--skip-rollback` targets a vendored patch with no manifest record (every `scan`/`get --mode vendored` entry — and, v5.0, the ledger-only leftover of an earlier `remove --skip-rollback` of a manifest-tracked vendored patch, which used to answer `not_found`). |
| `hosted_state_retained`   | (top-level error) | remove `--skip-rollback` targeting a hosted-only patch (no manifest entry): unwinding the redirect is the only possible removal, so the combination is refused (exit 1), mirroring the manifest-less vendored refusal above. |
| `vendor_state_preserved`  | `skipped`        | remove `--preserve-state` (v5.0): lockfile unwired; artifact, ledger entry, and manifest entry all kept for a later re-apply. Rollback's counterpart is the `vendoredPreserved: []` envelope array. |
| `vendor_revert_kept`      | `skipped` + top-level error | remove (v5.0): the vendored revert drift-kept (`kept_artifact`), so the ledger entry AND the manifest entry were both kept. ANY drift-keep makes the run a `partialFailure` (exit 1) — part of the requested removal did not happen; when EVERY matching entry drift-kept, the top-level error carries this code (`summary.removed` stays 0; the identifier DID match, so never `not_found`). Remedy: re-run `scan --mode vendored` to normalize, then remove. Rollback's counterpart is the `vendoredKept: []` envelope array (also exit 1). |
| `hosted_reverted`         | `removed`        | remove (v5.0): a hosted lockfile redirect was unwound as part of removing the patch (`verified` on dry-run). Bypasses `summary.removed` like `vendor_reverted`. |
| `hosted_revert_unsupported` | top-level error | remove (v5.0): the identifier matches hosted records of an ecosystem with no per-purl revert (and the identifier does not cover the full record set, so the whole-ledger replay cannot serve it — maven/nuget always land here scoped, as do npm purls a refused replay left behind). The manifest was not modified; exit 1. Remedy: unscoped `socket-patch rollback`, or re-run `scan --mode hosted`. Rollback reports the same condition in its `hosted.unsupported` array (exit 1). |
| `hosted_revert_failed`    | top-level error  | remove (v5.0): a per-purl hosted unwind, group replay, or redirect-ledger persist failed; the manifest was not modified, exit 1. Rollback's counterpart is a `hosted.failed[]` entry (also `partial_failure` exit 1). |
| `reinstall_required`      | rollback `warnings[]` | rollback (v5.0): vendored/hosted wiring was unwound, but installed trees keep their patched bytes until the next package-manager install — the stale-install advisory. |
| `hosted_state_not_preservable` | rollback `warnings[]` | rollback `--preserve-state` (v5.0): hosted redirects were unwound and their ledger records dropped anyway — hosted has no preservable local state; re-run `scan --mode hosted` to re-wire. (`remove --preserve-state` prints the same note on stderr.) |
| `out_of_scope_copies_restored` | rollback `warnings[]` | path-scoped rollback (v5.0): a selected patch had installed copies outside the given patterns; ALL copies were restored (patches are per-package). Informational — never flips the exit. |
| `path_scope_excluded_supplements` | scan `warnings[]` | path-scoped scan (v5.0): lockfile-only / vendor-ledger supplement packages have no installed path and were excluded from the scoped scan; the detail carries the count. |
| `vendor_state_unreadable` / `redirect_state_unreadable` | rollback `warnings[]`; remove top-level error | corrupt-ledger containment (v5.0). Rollback: an unreadable vendor ledger skips the vendored leg + manifest cleanup + GC; an unreadable redirect ledger skips the hosted leg (quarantine/restore remedy in the detail); either drives `partial_failure` exit 1 while the agent leg still restores files. Remove: `vendor_state_unreadable` is a hard top-level error before any mutation (an unreadable redirect ledger only warns — the identifier may match other stores). Also the Bun vendored preflight's refusal code: `get` / `scan --mode vendored`, `vendor`'s pre-takeover check and the `--dry-run` `would_refuse` preview report an unreadable `.socket/vendor/state.json` as itself (`errorCode` in `patches[]` / `download.patches[]`, or `get <uuid>`'s top-level `error.code`), fail-closed — nothing is exempt — instead of a Bun lock code. |
| `manifest_write_failed`   | rollback `warnings[]` | rollback (v5.0): the post-rollback manifest update could not be written; no entries were removed (`manifest.removedEntries: []`) and the run exits `partial_failure` 1. |
| `redirect_pnpm_trust_scaffold_modified` | rollback/remove `warnings[]` | hosted replay (v5.0): the redirect-created `pnpm-workspace.yaml` scaffold was modified since; the file was kept and only the `trustLockfile: true` line removed. |
| `redirect_npmrc_allow_remote_modified` | rollback/remove `warnings[]` (+ human stderr); vendored-supersedes-hosted reconcile `warnings[]` (`vendor`, `scan --mode vendored`); vendor advisory event | hosted unwind (v5.0): the redirect-created project `.npmrc` was modified since; the file was kept and only the `allow-remote=all` line removed. |
| `vendor_stale_artifact_removed` | `removed`  | vendor / scan `--vendor`: re-vendor under a newer patch uuid removed the previous uuid's orphaned artifact dir. |
| `vendor_unsupported_ecosystem` | `skipped`   | vendor: no vendor backend for this purl's ecosystem (jsr). |
| `already_vendored`        | `skipped`        | vendor: artifact + wiring already in sync for this patch uuid. |
| `unsafe_coordinates`      | `failed`         | vendor: purl/uuid would escape `.socket/vendor/` (tampered manifest/state); refused before any write. |
| `revert_failed`           | `failed`         | vendor --revert: a recorded entry could not be reverted. |
| `vendor_wiring_unknown_revert_blocked` | `skipped` (beside the `failed`/`revert_failed` event) | vendor --revert: the ledger entry was reconstructed by `repair` without wiring records and the live lockfile still resolves through the artifact — the revert refuses (fail-closed) instead of deleting a tarball the lock points at. Recovery: `socket-patch repair`, then restore the pre-vendor lock (or re-lock without the override) and re-run the revert. |
| `ecosystem_not_setup`     | `skipped`        | vex: the patch is applied and byte-verified but its ecosystem has no install hook configured and is not declared in the manifest's `setup.manual`, so it is omitted from the document (Property 7). Previously invisible in `--json`. |
| `stale_install`           | `skipped`        | vex (in-run `scan --mode hosted --vex`): a hosted stale-install probe found positively unpatched installed bytes, so the purl is omitted even under `--vex-no-verify` (see the gem / Python stale-install guards). |
| `record_unavailable`      | `skipped`        | vex (manifest-less): a lockfile-wired patch has no local record (manifest, redirect ledger, vendor ledger) and none could be fetched — `--offline`, transport error, 404, or a refused (paid) patch. Omitted, never attested from the `socket-patch.vendor.json` marker. |
| `record_mismatch`         | `skipped`        | vex (manifest-less): the record found for a wired patch names another package or another patch uuid than the wiring. |
| `vendor_unwired`          | `skipped`        | vex: a vendor-ledger entry whose committed artifact no lockfile/config wires any more (reverted lock, leftover ledger or artifact). Applies under `--no-verify` too. |
| `redirect_unwired`        | `skipped`        | vex: a redirect-ledger record whose hosted patch no lockfile wires any more (and no manifest entry owns the purl). Applies under `--no-verify` too. |
| `wiring_conflict`         | `skipped`        | vex (manifest-less): the lockfiles wire one package to two or more different patches (e.g. a stale sibling lock); which one the build installs is undecidable, so none is attested. |
| `hash_mismatch` / `not_applied` / `file_not_found` / `package_not_found` / `no_files` / `vendor_*` | `skipped` | vex: verification omissions — the installed copy (agent / hosted) or the committed artifact (`vendor_hash_mismatch`, `vendor_artifact_missing`, `vendor_artifact_unreadable`, `vendor_inventory_mismatch`, `vendor_uuid_mismatch`, `vendor_path_unsafe`) does not carry the patched bytes, or nothing is installed. A lockfile-pinned hosted reference with nothing installed attests instead of `package_not_found` (see "Manifest-less VEX"). |
| `lockfile_unreadable` / `lockfile_unparseable` / `patched_ref_invalid` / `patched_ref_unattributable` | run-level `warnings[]` | vex (every form): lockfile-discovery diagnostics — see "Manifest-less VEX (lockfile discovery)". Never flip the exit on their own. |
| `vendor_multiple_lockfiles` / `pypi_multiple_lockfiles` | `skipped` (warning) | vendor: a sibling lockfile of another package manager will still install UNPATCHED bytes; names the wired winner + the ignored locks. |
| `vendor_yarn_berry_unsupported` | `failed` | vendor (npm): yarn-berry Plug'n'Play layout; use its native `yarn patch` workflow. |
| `vendor_bun_lockb_invalid` | `failed` | vendor / scan / get `--mode vendored`: the binary lock is malformed, unreadable, unsupported or cannot be rewritten safely. The detail names the parser, hash or filesystem error. Refused before patch downloads and before hosted takeover; `patches[]` / `download.patches[]` carry `errorCode` and `error`, while `get <uuid>` also carries top-level `error.code`. Dry-run predicts the same refusal. |
| `vendor_bun_workspace_unsupported` | `failed` | vendor / scan / get `--mode vendored` (bun): the text lock holds `workspace:` packages and its `lockfileVersion` is below 2 — Bun 1.2–1.3 resolve a workspace member's local-tarball path relative to the member; a committed version-2 lock is the proof every consumer runs Bun ≥ 1.4 (deliberate over-approximation: root-only declared packages would install on version 1 too). Detail names the version integer and a version-specific remedy: delete `bun.lock` and re-lock with Bun ≥ 1.4 (an in-place `bun install` keeps the existing version) — then, for a version-1 lock, "or use `--mode hosted`, which accepts version-1 workspace locks"; for a version-0 lock, "or delete `bun.lock`, re-lock with Bun ≥ 1.2 (which writes lockfileVersion 1) and use `--mode hosted`" (hosted refuses version-0 workspace locks, so a bare hosted pointer would send the user into a second refusal). Refused before any write — in the pre-download preflight on `get`/`scan` (see `vendor_bun_lockb_invalid` for the placements); in the shared preflight that `vendor` and the vendor step run BEFORE a hosted → vendored takeover's revert (a hosted-redirected purl stays hosted-wired, ledger and lock untouched; `vendor --dry-run` previews the same `failed` code); and in the engine when the run would write a NEW local tuple. Exempt: purls the vendor ledger wires at the selected uuid, purls whose every `bun.lock` instance is already a `.socket/vendor/npm/` tuple (any uuid), in-sync re-runs and `repair` rebuilds. |
| `vendor_lockfile_missing` / `vendor_lockfile_version_unsupported` (bun preflight placement) | `failed` | scan / get `--mode vendored` (bun): the pre-download preflight found `bun.lock` unreadable / at a `lockfileVersion` other than 0, 1 or 2 (a newer version: update socket-patch; no integer: re-lock with Bun ≥ 1.2 — the same text as hosted's `redirect_bun_lock_unsupported`) or outside bun's single-line `packages` grammar. Same placements as `vendor_bun_lockb_invalid`; nothing fetched, no patch record. An unreadable `.socket/vendor/state.json` met by the same preflight is `vendor_state_unreadable` (see that row), never one of these. |
| `bun_lockb_invalid` | scan `warnings[]` (run-level) | scan (every mode): the native binary inventory could not parse or read `bun.lockb`; detail names the format or filesystem error. Also printed as `Warning (bun_lockb_invalid): …` on stderr. Exit and status remain unchanged. The warning is retained on empty and non-empty scans; valid binary locks are inventoried normally without a runtime or install. |
| `would_refuse` | dry-run preview action (`vendor.patches[]`) | scan `--mode vendored --dry-run` / get `--mode vendored --dry-run`: the wet run's Bun preflight would refuse this npm purl; the record carries `errorCode` (one of the four Bun lock codes above, or `vendor_state_unreadable` for an unreadable vendor ledger) + `error`. Exit 0 / `status: "success"`, nothing written. |
| `cargo_wiring_migrated` | `skipped` (advisory note) | vendor / scan / get `--mode vendored` / repair (v5.0): a pre-v5 `.cargo/config.toml` / `.cargo/config` vendored `[patch.crates-io]` entry was moved into the workspace-root `Cargo.toml` (dry run: "would move"); the ledger entry is rewritten to name `Cargo.toml` (lock originals kept). A vendor re-run that migrates reports the package `applied`, not `already_vendored`. |
| `cargo_legacy_wiring_kept` | vendor: `failed`; repair: `skipped` (warning) | vendor / scan / get `--mode vendored` (v5.0): the pre-v5 config entry could not be removed after the manifest took the wiring — the run is unwound (manifest, lock and copy as before) and the package fails, since a kept entry would double-wire the crate and, on a uuid bump, point at a copy the stale sweep deletes; the code prefixes the error detail. repair: the move was refused (e.g. an unparseable `Cargo.toml`, a user entry for the crate, or an unremovable legacy entry — the manifest edit is unwound); left in place. |
| `cargo_version_tagged` | `skipped` (advisory note) | vendor / scan / get `--mode vendored` / repair (v5.0): a vendored copy and its detached Cargo.lock entry were (re)tagged `<version>+socket.<uuid>` — a copy vendored before tagged versions, or a lock entry tagged for another uuid while the wiring points at this copy (dry run: "would tag"). A vendor re-run that tags reports the package `applied`. |
| `cargo_version_untagged` | `skipped` (warning) | repair (v5.0): the tag could not be written (an unreadable copy manifest, or a lock the retag cannot keep consistent); nothing else was undone — re-run `socket-patch vendor`. |
| `cargo_lock_untaggable` | `failed` | vendor / scan / get `--mode vendored` (cargo, v5.0): the Cargo.lock entry cannot carry the copy's tagged version consistently (a dependency reference in a spelling the edit does not own, a v1 `replace` naming the crate, or an entry already at the tagged version). Refused before any write; a dry run previews the same refusal. |
| `cargo_copy_untaggable` | `failed` (error prefix) | vendor / scan / get `--mode vendored` (cargo, v5.0): the copy's `Cargo.toml` has no literal `[package] version` string that can be rewritten byte-exactly (or it names another version); nothing is swapped in. A dry run over an already-vendored copy reports the same failure; a patch-service crate that cannot be tagged is a miss (`vendor_prebuilt_layout_mismatch`: `auto` builds locally, `service` fails `vendor_prebuilt_required`). |
| `cargo_wiring_restored` | `skipped` (advisory note) | repair (v5.0): a vendored crate's Cargo.lock entry was detached with no Socket-owned `[patch]` pointing at its committed copy (a pre-v5 release overwrote its crate-named config key when a second version was vendored); the manifest entry is written back and the ledger updated (dry run: "would restore"). A `vendor` re-run heals the same state as a plain re-vendor. |
| `cargo_manifest_unreadable` / `cargo_manifest_unparseable` / `cargo_manifest_symlink_unsupported` / `cargo_manifest_not_workspace_root` / `cargo_manifest_patch_source_alias` | `failed` | vendor / scan / get `--mode vendored` (cargo, v5.0): the workspace-root `Cargo.toml` cannot carry the vendored `[patch.crates-io]` entry (or cargo would ignore it there) — see the cargo caveat under "Vendored mode". Refused before any write. |
| `vendor_would_revert_redirect` / `vendor_takeover_reverted_redirect` | `skipped` (advisory event) | vendor / scan / get `--mode vendored` over a hosted-redirected purl (cargo and the npm family, bun included): dry run — the per-purl hosted revert was PROBED and would succeed (for bun, only after the Bun vendored preflight accepted the lock; a refused lock is previewed as the wet run's `failed <code>` instead) / wet run — the hosted lockfile edits were reverted to their pre-redirect registry values and the redirect-ledger record dropped before vendoring (mode takeover). Fires on the run that takes over, not on re-runs. |
| `redirect_revert_failed` | `failed` | vendor / scan / get `--mode vendored` (dry and wet): the per-purl hosted revert refused (drifted lock, missing original fragment, an undecidable ledger edit) — nothing vendored for the purl, hosted wiring left in place, exit 1 `partial_failure`; the detail names the remedy (for bun: an unscoped `socket-patch rollback`). |
| `vendor_yarn_berry_cache_unsupported` | `failed` | vendor (yarn berry): lock `cacheKey ≠ 10c0` or non-default `.yarnrc.yml` `compressionLevel` — the cache-zip checksum is not reproducible. |
| `vendor_yarn_berry_mixed_line_endings` | `failed` | vendor (yarn berry): `yarn.lock` or the root `package.json` mixes CRLF and LF line endings (or holds a bare CR) — no single ending can be kept, and yarn rewrites such a file wholesale on its next install (a mixed lock also fails `--immutable`, YN0028). Refused before any write; `yarn install` normalizes the files. A uniformly CRLF pair is vendored in CRLF. A hosted→vendored takeover (`vendor`, `scan`/`get --mode vendored`) raises this — and the berry `vendor_yarn_berry_cache_unsupported` gates — BEFORE reverting the hosted redirect (dry run too), so a refused purl stays hosted. |
| `vendor_override_conflict` | `failed`        | vendor (pnpm/yarn-berry): a user-authored override/resolution for the package already exists. |
| `vendor_integrity_unverified` | `skipped` (warning) | vendor (pipenv): the lockfile format does not hash-check file entries; the committed wheel bytes are the protection. |
| `vendor_content_mismatch_overwritten` | `skipped` (warning) | vendor: a staged file matched NEITHER beforeHash nor afterHash (patch built against different bytes, or local edits); the stage was overwritten with the verified patched content and the vendor succeeded. |
| `vendor_fetched_missing` | `skipped` (warning) | vendor: the package was not installed; its pristine artifact was fetched per the lockfile resolution (or staged from the committed vendor artifact), integrity-verified, and vendored — the project tree was not touched. For `poetry.lock` (which records hashes but no URLs) the pure-Python wheel's sha256 selects the file through PyPI's JSON API (`SOCKET_PYPI_JSON_API` overrides the endpoint); Poetry 0.12's bare `[metadata.hashes]` names no wheel, so those locks still need an installed copy (`vendor_fetch_unverifiable`). |
| `vendor_fetch_failed` | `failed` | vendor: the lockfile-resolved fetch was attempted and failed (HTTP error, size cap, integrity mismatch, or a PRESENT-but-corrupt committed artifact — pointed at `socket-patch repair`). A MISSING committed artifact no longer lands here: it falls through to the ledger-recovered registry fetch. Suppresses the duplicate `package_not_installed` skip. |
| `vendor_fetch_unverifiable` | `skipped` (warning) | vendor: the lockfile records no usable integrity for the missing package; nothing was fetched (fail-closed) and the `package_not_installed` skip follows. |
| `vendor_artifact_missing` | `skipped` (warning) / `failed` | vendor: the committed artifact is gone — the registry resolution is recovered from the ledger and the artifact rebuilt (warning); repair `--offline` with no local source surfaces it as the per-entry failure instead. |
| `vendor_artifact_corrupt` | `failed` | repair `--offline`: the committed artifact fails verification (member afterHashes or the ledger's whole-file sha256) and no local source can rebuild it. Online repairs rebuild instead. |
| `vendor_artifact_reused` | `skipped` (verbose note) | vendor / scan `--vendor` (pypi): the wiring was dropped by a relock but the committed wheel the ledger vouches for verified, so it was re-wired as-is — no service download, no rebuild; the lock pins the first run's sha again. |
| `vendor_artifact_rebuilt` | `skipped` (warning) | vendor / scan `--vendor`: a wired-but-missing/stale artifact was rebuilt in place. The lockfiles are untouched, except that nuget re-pins `packages.lock.json` to the rebuilt bytes. gem/maven/nuget: the package's event is `applied` (also for a rebuild from the patch service), and the ledger entry's artifact fingerprint (gem `fileInventory`, maven/nuget `sha256` + `size`, and the nuget lock pin) is refreshed to the rebuilt bytes, and its wiring records are kept unchanged, so `--revert` still restores the pre-vendor files. A rebuild whose ledger has no entry for the package, or only one from another patch uuid, records none. cargo/composer/gem rebuilds honour `--vendor-source` like a fresh vendor (`service` downloads the prebuilt artifact and refuses when it cannot). Other ecosystems leave the ledger entry untouched. (Under `repair` the `rebuilt` event carries this signal.) |
| `vendor_artifact_rebuild_failed` | `failed` | repair: the rebuild ran but the result failed verification against the recorded fingerprint (e.g. an edited state.json sha); the unverifiable artifact was removed. |
| `vendor_artifact_unrepairable` | `failed` | repair: no verifiable pristine source exists (not installed + lockfile rewired + no recoverable ledger fragment), the wheel is platform-locked with no installed copy, or the ledger entry itself cannot be trusted. |
| `vendor_uuid_mismatch` | `skipped` | repair: the manifest's patch uuid moved past the vendored artifact — a re-vendor (`vendor` / `scan --vendor`) is pending; repair does not cross patch generations. |
| `content_mismatch_overwritten` | `skipped` (warning) | apply (default policy): a file matched NEITHER beforeHash nor afterHash and was overwritten with the full verified patched content. `--strict` turns this case into a `failed` event instead. |
| `vendor_lock_checksums_unsupported` / `vendor_stale_lock_checksum` | `failed` | vendor (gem): an ambiguous/platform CHECKSUMS entry, or a v1-wired lock whose stale token blocks the hot path (run `vendor --revert` + re-vendor). |
| `redirect_pypi_stale_install` | `redirect.warnings[]` (warning) | Hosted Python redirect: readable installed files differ from patched hashes. Read-only, repeated on re-scan, and excludes the package from same-run VEX. See the "Python stale-install guard" section. |
| `redirect_gem_stale_install` | `redirect.warnings[]` (warning) | scan `--mode hosted` (gem): a stale UNPATCHED materialization (installed gem, or committed `vendor/cache` archive) that `bundle install` will reuse instead of fetching the redirected patch; the detail carries the verified remedy. Full rules and flavors: the "Gem stale-install guard" section. |
| `redirect_pipenv_refused` | `redirect.warnings[]` (warning) | scan `--mode hosted` (pipenv): the Pipfile.lock pins another version or a non-registry / foreign source for the package — refused atomically across categories, and the patch is vetoed from the sibling Python rewriters (see the "Pipenv hosted redirect" section). |
| `redirect_pipenv_skipped` | `redirect.warnings[]` (warning) | scan `--mode hosted` (pipenv): no entry for the package, pipfile-spec < 6, an unparseable lock or a digest-less patch — nothing rewritten here; the sibling rewriters proceed. |
| `redirect_pipenv_installer_unknown` | `redirect.warnings[]` (warning) | scan `--mode hosted` (pipenv): the lock was rewritten with the modern `file` reference because no `pipenv` answered on PATH; Pipenv 7–11 projects need `path` — put that pipenv on PATH or set `SOCKET_PIPENV_MAJOR`. |
| `pypi_pipenv_installer_unsupported` | `failed` | vendor (pipenv): the installed Pipenv is older than 2018 and cannot consume vendored wheel references — upgrade Pipenv or use hosted mode. |
| `pypi_pipenv_version_mismatch` | `failed` | vendor (pipenv): a category pins a different version than the patch — refused before any write. (`pypi_pipenv_invalid_wheel` retired in v5.0: the backend takes the orchestrator's resolved version instead of parsing the wheel filename.) |
| `pypi_poetry_symlink_unsupported` / `pypi_pipenv_symlink_unsupported` / `pypi_requirements_symlink_unsupported` | `failed` | vendor (pypi, v5.0): a target file (`pyproject.toml` / `poetry.lock`, `Pipfile` / `Pipfile.lock`, or any planned `requirements*.txt`) is a symlink — refused before any write on wire AND on revert (the revert keeps the artifact, `kept_artifact`); the twins of the existing pdm/uv symlink refusals. |
| `pypi_poetry_changed` / `pypi_pdm_changed` / `pypi_pipenv_changed` / `pypi_uv_changed` | `failed` | vendor (pypi, v5.0): the lock / project file changed between the read that planned the edit and the first write — refused before any write (worded like `pypi_lock_changed`: "<file> changed during vendoring; re-run"). |
| `pypi_pipenv_stale_install` | `skipped` (warning) | vendor (pipenv): the vendored twin of `redirect_pypi_stale_install` — the project's venv still holds the upstream release Pipenv will not reinstall over; the detail names the `pipenv run pip uninstall -y <pkg> && pipenv sync` remedy. |
| `pypi_pipenv_installer_unknown` | `skipped` (warning) | vendor (pipenv): no `pipenv` answered on PATH; the vendored references assume Pipenv 2018 or later (7–11 cannot consume them — use hosted mode there); `SOCKET_PIPENV_MAJOR` pins the release. |
| `vendor_lock_entry_relocked` | revert `warnings[]` | vendor `--revert` / rollback (pipenv): a relock regenerated the wired entry to a registry reference, or removed it; the record is retired (artifact removed, ledger entry dropped) instead of drift-kept. |
| `pypi_{poetry,pdm,pipenv}_no_lockfile` | `failed` | vendor (pypi): a lock-less tool marker with no `requirements.txt` fallback — run `<tool> lock`. |
| `pypi_poetry_integrity_unverified` | `skipped` (warning) | vendor (pypi / poetry): the lock was written by Poetry < 1.4 (0.12 `[metadata.hashes]`, lock 1.0/1.1, or a 2.0 lock without a `@generated by Poetry X.Y.Z` header — 1.3 wrote those). That installer does not verify local wheel hashes (the committed wheel bytes are the protection) and does not replace an already-installed package at the same version; recreate the virtualenv or `pip uninstall` the package before `poetry install`, or upgrade Poetry. |
| `redirect_poetry_stale_install_risk` | `redirect.warnings[]` (warning) | scan `--mode hosted` (poetry): same writer test as above — a warm virtualenv keeps the upstream package after the redirect on Poetry < 1.4 (1.4+ re-installs from the new source); fresh installs pick up the patched wheel. Emitted once per rewritten lock, only on the run that rewrites it. |
| `redirect_poetry_entry_not_found` / `redirect_poetry_missing_sha256` / `redirect_poetry_lock_unsupported` | `redirect.warnings[]` (warning) | scan `--mode hosted` (poetry): the lock has no `[[package]]` at the granted version (uv-parity twin of `redirect_uv_entry_not_found`); the grant carries no SHA-256 (gated once per dep, not per lock); the lock is refused — Poetry 0.12 layout (URL sources ignored), an unsupported `lock-version`, a forked package listed at several versions, a user-authored `[package.source]` on another origin (an earlier Socket URL for the same wheel is superseded in place), a malformed `[metadata.files]`/`[metadata.hashes]`, or a wheel whose filename does not match the locked package. Exit code and `status` unchanged (hosted-refusal posture). |
| `redirect_pdm_refused` / `redirect_pdm_legacy_sync_required` | `redirect.warnings[]` (warning) | scan `--mode hosted` (pdm): the `pdm.lock` rewrite was refused — an unsupported `[metadata] lock_version` (the identity-losing `3.1` / `4.0`–`4.2` formats or an untested future format), an unsupported `strategy`, a package listed at several versions (fork) or absent, a user-authored `url`/`path`/VCS/`editable` source, hash-less or malformed `files`, or a wheel whose filename does not match the locked package (`redirect_pdm_refused`); or the lock was written in format `2` (PDM 0.12–1.4), whose upstream freshness bug lets `pdm install` regenerate the lock — use `pdm sync` (`redirect_pdm_legacy_sync_required`). A refused uuid is withheld from every other PyPI rewriter when `pdm.lock` is the install driver, and its patch is not confirmed. Exit code and `status` unchanged (hosted-refusal posture). |
| `redirect_bun_lock_unsupported` | `redirect.warnings[]` (warning) | scan/get `--mode hosted` (bun): the text lock's `lockfileVersion` is not 0, 1 or 2 (a newer version: update socket-patch, re-locking would reproduce it; no integer: re-lock with Bun ≥ 1.2 — the shared gate's text, identical to vendored's `vendor_lockfile_version_unsupported`), or its `packages` section is not bun's single-line grammar. Nothing rewritten; exit 0 (hosted-refusal posture). |
| `redirect_bun_workspace_unsupported` | `redirect.warnings[]` (warning) | scan/get `--mode hosted` (bun): a lockfileVersion-0 lock (Bun 1.1.39–1.1.45 `--save-text-lockfile`) holds `workspace:` packages; frozen installs of that grammar cannot keep the hosted tuple. Detail: "Bun version-0 workspace locks cannot preserve hosted tarballs on frozen installs; delete bun.lock and re-run `bun install` with Bun >= 1.2 (which writes lockfileVersion 1, accepted by hosted mode) — a plain in-place `bun install` bumps the version only when a workspace depends on another workspace (e.g. root -> member); otherwise it keeps version 0 or fails to resolve" (measured: Bun 1.2.0 keeps 0, 1.2.23–1.4.2 exit 1 "failed to resolve" on a root that does not depend on its members). Version-1/2 workspace locks are rewritten. Exit 0. |
| `redirect_bun_lockb_invalid` | `redirect.warnings[]` (warning) | scan/get `--mode hosted`: the native binary lock is malformed, unreadable, unsupported or cannot be rewritten safely. No installer is spawned and no binary or sibling npm lock edit or takeover occurs; dry-run reports the same format error. Exit 0, `redirected: 0`. |
| `redirect_bun_entry_not_found` / `redirect_bun_missing_sha512` | `redirect.warnings[]` (warning) | scan/get `--mode hosted` (bun): the lock has no rewritable entry at the granted version (re-resolved, or occupied by an unowned URL/file spec) / the grant carries no sha512 integrity. Per-dep; nothing rewritten for it; exit 0. NOT emitted for the digest-less 2-tuple Bun 1.1.39–1.3.9 re-save our URL tuple as — that entry counts as redirected and is healed. |
| `vendor_prebuilt_stub_invalid` | `failed` / `skipped` (warning) | vendor (gem, `--vendor-source`): the served stub gemspec fails the rubygems `summary`/`authors` bar, so bundler would refuse the vendored path source at install time. `service`: refusal naming the missing attributes; `auto`: loud warning + local-build fallback — or, when the gem is also not installed locally (no stub to derive), a refusal naming the served defect and the install-the-gem remedy. |
| `gem_spec_invalid` | `failed` | vendor (gem): the LOCAL `specifications/` stub gemspec fails the same rubygems `summary`/`authors` bar (a corrupted or hand-edited gem home); the refusal names the file — reinstall the gem (`gem pristine <name>` / fresh `bundle install`). |
| `vendor_*` / `pypi_*` / `gemfile_*` / `lock_*` / `locked_version_mismatch` / `user_authored_*` / `native_extensions_unsupported` / `platform_gem_unsupported` | `failed`/`skipped` | vendor: per-ecosystem refusal + drift vocabulary; see the Vendor command contract section. New tags are additive (MINOR). |

### Top-level `EnvelopeError` codes

| Code                  | Subcommands                      | Meaning |
|-----------------------|----------------------------------|---------|
| `manifest_not_found`  | list, remove, repair, rollback, vex | `.socket/manifest.json` doesn't exist. For `vex` (and `scan --vex`) it fires only when, in addition, NOTHING else names a patch — no redirect-ledger record, no vendor-ledger entry, no lockfile reference — and the message says so (exit 2 standalone; `apply`/`vendor --vex` treat it as their calm no-op). v3.5: `repair` proceeds anyway (vendored phase only) when a vendor ledger or vendor-path lockfile references exist, and exits 0 with a `redirect_only_project` skip (not this error) when the only `.socket/` trace is a hosted-mode `redirect-state.json`. `list` likewise no longer fires this on a hosted-only project: when the hosted redirect ledger holds ≥ 1 `records` entry, the records are listed (exit 0, labeled `details.mode: "hosted"` + `details.ledger`; when the manifest exists too, both stores are shown, purl-sorted with the manifest entry first on a tie). v5.0: `list` reads the vendor ledger the same way — a vendored-only project (every `scan`/`get --mode vendored` project) lists its ledger entries' embedded records labeled `Mode: vendored (recorded in .socket/vendor/state.json)` in human mode — the twin of the hosted `Mode: hosted (recorded in .socket/vendor/redirect-state.json)` line — (`details.mode: "vendored"` + `details.ledger: ".socket/vendor/state.json"` in JSON), exit 0. A standalone-`vendor` entry's fallback `record` lists the same way once no manifest entry covers it (by ledger key or base purl) — the copy manifest-less `vex` attests from, so `list` never reports `manifest_not_found` for a tree whose VEX document attests a patch; while the manifest covers it, only the manifest entry is listed. All stores always come from the SAME project: the ledger is resolved against the root the RESOLVED manifest path implies (its `.socket` parent's parent in the standard layout, else the manifest file's directory — exactly `--cwd` for the default path), so `--manifest-path` into another project reads that project's ledger, never the local one. The error still fires when NONE of the three stores has a record — an edits-only ledger asserts no patches — and a present-but-broken manifest still reports `manifest_invalid`/`manifest_unreadable` regardless of ledger records (corruption is never masked). A malformed ledger degrades to "nothing to consult" with a stderr warning, muted by `--silent` (read-only consumer posture; the hosted write path hard-errors instead); `list --json` carries it in the run-level `warnings[]` as `redirect_ledger_corrupt` instead of on stderr. v5.0: `rollback` likewise proceeds manifest-less when the vendor ledger or the redirect ledger holds work (its error is the legacy `{status: "error", error: "Manifest not found", path}` shape, not this envelope code); only the truly-empty project — all three stores absent — keeps the exit-1 error, and a project whose lockfiles still reference `.socket/vendor/` artifacts with NO vendor ledger gets a distinct error naming `socket-patch repair`. `remove` (v5.0) proceeds manifest-less whenever a vendor OR redirect ledger file exists (two existence probes before the lock; the stores themselves load under it): ANY vendor-ledger entry matching the identifier — detached or not — is removed through the ledger path (`--preserve-state` and drift-keeps behave exactly as on the manifest path), a hosted-only match unwinds its redirect, and when the ledgers exist but hold nothing for the identifier the error is `not_found` (exit 1), not this code — `manifest_not_found` fires from `remove` only when all three stores are absent. Manifest entries are removed in sorted purl order. |
| `manifest_invalid`    | list, remove                     | Manifest exists but is unparseable. |
| `manifest_unreadable` | list, remove, vex                | I/O error reading manifest (vex: also an unparseable manifest; exit 2). |
| `no_patches`          | vex                              | The manifest file exists but is empty AND no ledger record or lockfile reference names a patch (exit 1). |
| `redirect_ledger_corrupt` / `vendor_ledger_corrupt` | vex (every form) | `.socket/vendor/redirect-state.json` / `.socket/vendor/state.json` exists but is malformed or unreadable. Both ledgers are attestation inputs (records and liveness), so attesting from a partial view is refused (exit 2 standalone; the host command fails). A missing ledger is simply empty. |
| `serialize_failed`    | vex                              | The built document could not be serialized (exit 2). |
| `apply_failed`        | apply                            | apply pipeline error before any patch ran. |
| `repair_failed`       | repair                           | repair pipeline error. |
| `remove_failed`       | remove                           | Could not write the modified manifest. |

### Per-subcommand action matrix

| Subcommand   | Emits |
|--------------|---|
| `apply`      | `Applied` · `Updated` · `Skipped` (already_patched / package_not_installed / vendored) · `Failed` · `Verified` (dry-run) |
| `vendor`     | `Applied` (= vendored; `command` routes) · `Skipped` (refusals, warnings, unsupported ecosystems) · `Failed` · `Removed` (reconcile + `--revert`) · `Verified` (dry-run) |
| `list`       | `Discovered` (with `details.vulnerabilities`, `details.tier`, `details.license`, `details.description`, `details.exportedAt`; hosted redirect-ledger records additionally carry `details.mode: "hosted"` — the constant mode name, whatever opaque mode string the ledger itself carries — and `details.ledger: ".socket/vendor/redirect-state.json"`, both additive and absent on manifest entries; v5.0: vendor-ledger records carry `details.mode: "vendored"` + `details.ledger: ".socket/vendor/state.json"` the same way, and the human listing labels them `Mode: vendored (recorded in .socket/vendor/state.json)`; a `state.json` that cannot be read or parsed degrades to nothing-to-consult with the stderr line `Warning: unreadable vendor ledger (<error>); its vendored patches are not listed` — muted by `--silent`, exit unchanged) |
| `repair`/`gc`| `Downloaded` (or `Verified` on dry-run) · `Rebuilt` (vendored artifacts; `Verified` previews on dry-run) · `Skipped` (vendor_uuid_mismatch) · `Removed` (or `Verified`) · `Failed` events |
| `remove`     | `Removed` (per purl; `Verified` on dry-run) · artifact-level `Removed`/`Verified` event (with `details.blobsRemoved`, `details.rolledBack`) |
| `--update`   | `Downloaded` → `Updated` (success) · `Skipped` (already_latest) · `Verified` (dry-run check, reason update_check) — see the Self-update contract section for details fields and top-level error codes |

### Migration status (v3.0)

The unified envelope is the v3.0 contract. As of this release, these commands emit the envelope and have snapshot-test coverage:

- ✅ `apply`
- ✅ `list`
- ✅ `repair` / `gc`
- ✅ `remove`
- ✅ `vendor`

The remaining commands still emit their pre-v3.0 ad-hoc JSON shapes and will migrate in a follow-up PR. Until then, downstream consumers should branch on the `command` field (envelope) vs the legacy shape (no `command` field, `status` in snake_case):

- ⏳ `scan` — still emits the discovery + `apply.patches[*]` + `gc.*` shape documented in earlier drafts of this file.
- ⏳ `get` — still emits per-patch action arrays.
- ⏳ `rollback` — still emits per-package result records. Additive (v3.5): a manifest entry with no matching installed package appears in `results[]` as a marker record `{ "purl", "path": null, "skipped": "package_not_installed" }` — no `success`/`error` keys, never counted in `rolledBack`/`failed`, never flips the status or exit code (rollback's job is "make the tree unpatched"; a not-installed package already satisfies that end state, deliberately asymmetric with apply's exit-1-on-unmatched). v5.0 keeps that legacy shape and adds the ALWAYS-PRESENT keys `warnings[]` (`{code, detail}` objects, now populated), `vendored` (meaning narrowed — MAJOR), `vendoredReverted`, `vendoredPreserved`, `vendoredKept` (`{purl, reason}`), `hosted` (`{reverted, failed: [{purl, error}], unsupported, editedFiles}`), `manifest` (`{removedEntries, preserved}`), `gc` (`{skipped: true}` \| `{removedBlobs, removedDiffArchives, removedPackageArchives, bytesFreed}`), and `paths` — full key semantics and exit rules in the [Rollback command contract](#rollback-command-contract-v50).
- ⏳ `setup` — still emits its own `{ status, updated, alreadyConfigured, errors, files }` shape (and the `--check` / `--remove` variants), now documented in full under [Setup command contract](#setup-command-contract).

One command is **intentionally not** plain-envelope and will stay that way (not migration debt):

- `vex` — **hybrid**: the OpenVEX document is itself JSON and is the primary output; the envelope appears only under `--json --output <path>`. See the [vex output channels](#vex-output-channels) table.

### `patches[]` entry shape for `get` and `scan --apply`

Per-patch records emitted in `patches[]` (and in `scan --apply`'s
`apply.patches[*]`) carry the same metadata regardless of which command
produced them — both flow through `download_and_apply_patches_with` in
`src/commands/get.rs`. The shape is stable as of v3.0; consumers can
rely on these keys.

```jsonc
{
  "purl":        "pkg:npm/minimist@1.2.2",
  "uuid":        "11111111-1111-4111-8111-111111111111",
  "action":      "added" | "updated" | "skipped" | "failed",
  "oldUuid":     "<previous uuid>",          // only on action=updated

  // ----- patch metadata (only on action=added | updated) -----
  "description": "Fixes prototype pollution in minimist",
  "license":     "MIT",
  "tier":        "free" | "paid",
  "exportedAt":  "2024-01-01T00:00:00Z",     // publishedAt from API — when the PATCH was published
  "severity":    "critical" | "high" | "medium" | "low",  // max across all vulnerabilities; omitted when no vulns
  "vulnerabilities": [
    {
      "id":          "GHSA-xvch-5gv4-984h",  // GHSA/CVE/etc — the canonical advisory ID
      "cves":        ["CVE-2024-12345"],
      "severity":    "high",
      "summary":     "Prototype Pollution",
      "description": "merge() does not check Object.prototype"
    }
    // … one entry per advisory the patch addresses, sorted by `id`
  ],

  // ----- failure path (only on action=failed) -----
  "errorCode":   "vendor_bun_workspace_unsupported", // additive; today only the vendored-mode Bun preflight refusals (+ vendor_state_unreadable)
  "error":       "could not fetch details"
}
```

The metadata block (`description`, `license`, `tier`, `exportedAt`,
`severity`, `vulnerabilities[]`) is intentionally **omitted on
`skipped`** — those records mean "already in manifest, no work taken",
and the consumer already saw the metadata when the patch was first
added. It's also omitted on `failed`.

Additive (v3.6): a `skipped` record may carry an `errorCode` naming WHY it
was skipped before download — `package_not_installed` (the coarse
installed-version narrowing; see "get --mode and installed narrowing"),
`yarn_pnp_unsupported`, or `pnpm_pnp_unsupported` (PnP layout refusals) —
the same calm-skip vocabulary as scan's pre-download partitions. Absent on
the classic "already in manifest" skip.

Vendored mode (v5.0) uses the detached download vocabulary instead:
`get --mode vendored`'s `patches[]` and `scan --mode vendored`'s
`download.patches[]` carry `action: "downloaded" | "skipped" | "failed"`
(no `added`/`updated` — the vendor ledger, not the manifest, tracks patch
generations; a `downloaded` record whose purl the ledger already holds at
another uuid carries the additive `oldUuid`, and its human `[fetch]` line
reads `<purl> (replacing <short uuid>)`) beside the same metadata keys, and
the enclosing object carries `downloaded: N` and `detached: true`.

Additive: a `failed` record may ALSO carry `errorCode` beside `error` —
today exactly the vendored-mode Bun preflight refusals
(`vendor_bun_lockb_invalid`, `vendor_lockfile_missing`,
`vendor_lockfile_version_unsupported`, `vendor_bun_workspace_unsupported`,
and `vendor_state_unreadable` when the preflight cannot read
`.socket/vendor/state.json`)
that `get --mode vendored` and `scan --mode vendored` (`download.patches[]`)
emit before any download; see "get --mode and installed narrowing" →
Vendored → Bun vendored preflight. Every other `failed` record carries only
`error`. The dry-run preview's `would_refuse` records carry the same pair.

`vulnerabilities[]` is always sorted by `id` so consumer diffs and
test snapshots are stable. `severity` at the top level is the max
across the array using the ordering `critical > high > medium = moderate > low > (unknown)`.

`exportedAt` is the API's `publishedAt` **verbatim**: the date **the
patch** was published, *not* the date the upstream package version was
released. The two are unrelated — a package from 2020 routinely carries
a patch published last week, and two patches for one package version
carry two different dates. Note the wire format is RFC 2822 / HTTP-date
(`Fri, 27 Mar 2026 19:12:42 GMT`), not ISO 8601 — do not compare these
as raw strings, they sort by weekday name.

### Which patch gets selected

A package can have several available patches; the manifest holds one
record per PURL, so exactly one is chosen. Both `get` and every `scan`
mode rank candidates identically (`socket_patch_core::api::ranking`),
best first:

1. **Severity** — `critical > high > medium = moderate > low > (unknown)`,
   taken as the worst severity across everything the patch fixes.
2. **Merge state** — a patch that remediates *more* advisories in one blob
   leads. Inferred, not flagged: see below.
3. **Patch publish date**, most recent first — when the *patch* was
   published, never the upstream package's release date. Unparseable or
   absent dates sort last.
4. `tier` (paid first), then `uuid` — tiebreaks only, present so the
   order is total and therefore reproducible across runs.

`tier` is an **access filter, not a ranking signal**: a free `critical`
patch outranks a paid `low` one. Paid patches are excluded outright for
callers whose `canAccessPaidPatches` is false.

#### Merge state is inferred, not reported

There is no `merged` field on the wire and none is required. A merged
patch is by definition one that folds several fixes into a single blob,
so it **names several advisories** — which every endpoint already tells
us. Merge state is therefore the count of distinct advisories a patch
remediates: `vulnerabilities` map keys on `by-package` / `view`,
`ghsaIds` on `batch` (falling back to `cveIds` only when no GHSA is
named). `1` is an ordinary patch, `>= 2` is merged.

Advisories are counted, **not** CVE ids: one advisory routinely carries
several CVE aliases, and counting those would inflate a single-fix patch
into a phantom merged one.

As of 2026-08-05 production publishes no merged patches — all 28 patches
sampled across npm/PyPI/gem/cargo covered exactly one advisory each — so
this rung is currently inert and ranking falls through to recency. The
moment a consolidated patch is published it is preferred automatically,
with no client *or* server change.

#### Why severity sits above merge state

The merged patch is the general preference: it fixes the most in one
shot, and only one patch per PURL can be applied, so breadth is what an
operator wants. But it must never shadow a *worse* vulnerability. If a
patch addresses a higher-severity advisory than anything the merged patch
covers, that one wins — you do not leave a critical unfixed to pick up
two extra mediums. Severity on the top rung expresses exactly that,
because a patch's severity is the worst advisory it fixes:

| merged patch | rival patch | winner | why |
|---|---|---|---|
| high     | critical | rival  | higher severity available |
| critical | high     | merged | merged already covers the worst |
| high     | high     | merged | severities tie → breadth decides |

This ordering is also the presentation order everywhere patches are
listed — `scan --json`'s `packages[].patches[]`, `get`'s "Found
patches:" listing, and the `selection_required` `options[]` array — so
`patches[0]` for a package is the patch that would be applied, and
`updates[].newUuid` names that same patch.

Free/unauthorized callers with more than one candidate for a PURL still
get the interactive picker (or `selection_required` in `--json`); the
ranking decides the presented order and hence the highlighted default,
not the outcome. `--yes` answers the picker with that default without
showing it (the same pick a non-terminal run makes); `--json` keeps
`selection_required` even with `--yes`.

One additive key may appear on `scan --json`'s `packages[].patches[]`
entries, omitted when absent: `publishedAt`, present whenever the server
supplies it (the public-proxy fallback path fills it in from the
per-package results).

> **Known gap — batch responses without `publishedAt`.** `scan`'s
> discovery (`packages[]`, the table, `updates[]`) is built from the
> **batch** endpoint, whose response shape currently omits `publishedAt`;
> the selection that `--apply` performs is built from the **by-package**
> endpoint, which carries it. Ranks 1, 2 and 4 agree across both, so the
> two only diverge for a package whose top candidates tie on severity
> *and* merge state — there the batch side falls through to the UUID
> tiebreak while apply correctly uses the date.
>
> Live example: `pkg:npm/axios@1.6.0` has two free `HIGH` patches;
> `packages[0].patches[0]` reports `0bc312a6…` (2026-03-27) while
> `--apply` installs the newer `83f5a654…` (2026-08-03), which is the
> correct choice. Only the reported ordering is affected — never which
> patch lands on disk.
>
> The client already deserializes `publishedAt` on the batch shape
> (`#[serde(default)]`), so this closes with no client change the moment
> the batch endpoint emits it.

### `jq` recipes for PR-comment bots

Applied + updated patches (envelope shape):

```bash
socket-patch apply --json | jq '
  .events[]
  | select(.action == "applied" or .action == "updated")
  | { purl, uuid, oldUuid, files: [.files[].path] }
'
```

GC summary (after `repair --json`):

```bash
socket-patch repair --json | jq '{
  removed:     .summary.removed,
  bytesFreed:  .summary.bytesFreed,
  failed:      .summary.failed
}'
```

Combined apply summary for a PR description:

```bash
socket-patch apply --json | jq '
  .summary
  | "Applied \(.applied) patches, updated \(.updated), skipped \(.skipped), failed \(.failed)."
'
```

### Exit code semantics

Exit `0` when `status` is `success`, `noManifest`, or `notFound`-with-zero-failed.
Exit `1` when `status` is `partialFailure` (any `events[*].action == "failed"`) or `error`.

`apply` with no manifest at all is a clean exit-0 no-op (`status: "noManifest"`), and an **empty** manifest (zero patches) is a plain `success` exit 0 — this is load-bearing for the install hooks, which run `apply` on every install. A fully rolled-back agent project therefore keeps `.socket/manifest.json` at `{"patches": {}}` (+ its `setup` block): the v5.0 residue rule never deletes a zero-patch manifest, precisely so these hook exits (and `list`'s 0-vs-1 below) never flip. Pinned by `tests/in_process_edge_cases.rs` and `tests/cli_dry_run_paths_e2e.rs`. **One carve-out**: a yarn-berry Plug'n'Play layout (`.pnp.*` loader at `--cwd`) refuses with the loud `yarn_pnp_unsupported` error (exit 1) even when no manifest exists — `scan` cannot discover PnP packages (they live inside `.yarn/cache/*.zip`, no `node_modules/`) and therefore never writes a manifest, so without the carve-out the documented refusal was unreachable and a PnP project's only signal was the calm noManifest exit. Pinned by `tests/e2e_safety_yarn_pnp.rs`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Error (missing/invalid manifest, fetch failed, apply failed, selection cancelled in non-JSON mode, etc.) |
| `2` | Usage error: clap parse failures (unknown flag/value, missing required arg — including the clap-enforced `setup --check --remove` conflict) and the conflicts the commands enforce themselves — `scan`'s cross-mode conflicts (`--mode` combined with a DIFFERENT mode's boolean spelling, rejected in `resolve_mode_flags`), `scan PATHS` combined with `--mode hosted`/`--mode vendored` (same enforcement point), `remove --preserve-state --skip-rollback` (the no-op quadrant; flag- or env-sourced alike), an unparseable path glob on `scan`/`rollback`, `repair --offline --download-only`. `vex` also exits `2` on hard errors before document generation (see its tri-state table below). **Carve-out**: `get`'s self-enforced conflicts have always exited `1` via its error envelope (`--id`/`--cve`/`--ghsa`/`--package` multi-select, `--one-off --save-only`) and the v3.6 `--mode hosted\|vendored --save-only` conflict deliberately follows that get-internal precedent — changing the existing ones to `2` would be a MAJOR exit-code change |

`list` returns **`0`** for an empty manifest and **`1`** for a missing manifest — these are distinct and load-bearing (a manifest-less project whose vendor or redirect ledger holds records is NOT "missing": `list` reads all three stores and exits 0 — see the `manifest_not_found` row). Every lock-taking subcommand — including `scan`/`get --mode hosted` as of v5.0 — returns **`1`** with `errorCode: lock_held` when another live socket-patch process holds `<.socket>/apply.lock`.

`vex` exit codes are tri-state:

| Code | Meaning |
|---|---|
| `0` | A non-empty OpenVEX document was produced |
| `1` | Nothing attested: `no_applicable_patches` (every candidate was omitted — by verification, a wiring gate, a missing record, or Property 7; the omissions ride `skipped` events) or `no_patches` (an empty manifest file and nothing wired anywhere) |
| `2` | Hard error: `manifest_not_found` (no manifest AND no ledger record / lockfile reference anywhere), `manifest_unreadable`, `redirect_ledger_corrupt`, `vendor_ledger_corrupt`, `json_requires_output`, `product_undetected`, `serialize_failed`, `write_failed` |

A missing manifest alone is not an error: a hosted or vendored checkout attests from its lockfiles (see "Manifest-less VEX"). Embedded `--vex` maps every failure to the host command's exit `1`.

### vex output channels

The VEX document is JSON-LD, which collides with the standard `--json` envelope on stdout. The shape is:

| `--output` | `--json` | VEX → | Envelope → |
|---|---|---|---|
| unset | unset | stdout | stderr (one-line summary) |
| set to `<path>` | unset | `<path>` | stdout (one-line summary) |
| set to `<path>` | set | `<path>` | stdout (full envelope, with one `verified` event per emitted subcomponent) |
| unset | set | (error: `json_requires_output`, exit `2`) | stdout (envelope-only) |

`--output -` means stdout (the first row). With `--dry-run`, a document bound for `--output` is built and verified but not written, a previous document at that path is left alone, the one-line summary reads `[dry-run] Would write OpenVEX document with N statements to <path>`, and the envelope's `dryRun` is `true`. A written file ends with a newline, like the stdout form.

When verification is enabled (the default) and a patch is omitted, the failed PURLs are surfaced on stderr in plain mode (one `Warning: omitting <purl> from VEX: <reason> (<tag>)` line each, sorted by PURL) or as `skipped` events on the envelope in JSON mode (same order; `errorCode` is the tag). Status becomes `partialFailure` when at least one patch was omitted but at least one was emitted.

## Semver policy

Versioning lives in **`Cargo.toml`** at the workspace root (`version = "..."`) and is propagated to every ecosystem wrapper and launcher package by **`scripts/version-sync.sh <new-version>`** (the full list of stamped files is below).

| Change | Bump |
|---|---|
| Rename or remove a subcommand | **MAJOR** |
| Rename or remove a visible alias (`download`, `gc`) | **MAJOR** |
| Rename or remove a hidden alias (`--no-apply`) | **MAJOR** |
| Rename, remove, or change short form of a flag (`-d`, `-m`, etc.) | **MAJOR** |
| Change a default value (`--download-mode`, `--batch-size`, `--manifest-path`, …) | **MAJOR** |
| Change an exit code's meaning or add a new non-zero code with different semantics | **MAJOR** |
| Rename a JSON output key or change a `status` string | **MAJOR** |
| Remove a JSON output key | **MAJOR** |
| Rename or remove a per-patch `action` value (`added`/`updated`/`skipped`/`failed`) | **MAJOR** |
| Change `scan`'s default behavior (e.g. flipping `--prune` to opt-out, or making `--apply` default) | **MAJOR** |
| Demote `repair`'s `gc` from `visible_alias` to hidden, or remove the `repair` subcommand | **MAJOR** |
| Drop the bare-UUID fallback | **MAJOR** |
| Add a *required* new flag | **MAJOR** |
| Add a new subcommand | **MINOR** |
| Add a new optional flag | **MINOR** |
| Add a new optional JSON output key (additive) | **MINOR** |
| Add a new value to a per-patch `action` enum (additive) | **MINOR** |
| Add a new visible alias to an existing subcommand | **MINOR** |
| Fix a bug without changing any of the above | **PATCH** |

After bumping `Cargo.toml`, run:

```bash
scripts/version-sync.sh <new-version>
```

This syncs the workspace package version into:

- `npm/socket-patch/package.json` (and its `optionalDependencies`)
- every per-platform `npm/socket-patch-*/package.json`
- `pypi/socket-patch/pyproject.toml` and `pypi/socket-patch-hook/pyproject.toml`
- `gem/socket-patch-bundler/socket-patch-bundler.gemspec` (the Bundler plugin gem)
- `gem/socket-patch/socket-patch.gemspec` + its launcher `VERSION` (the RubyGems CLI launcher)

All ecosystem publishing fans out from the single
**`.github/workflows/release.yml`** dispatch: one run publishes crates.io,
npm, and PyPI plus the CLI launcher gem (`socket-patch` on RubyGems). Each
registry leg lives in its own workflow
(`.github/workflows/publish-{cargo,npm,pypi,rubygems}.yml`), dispatched at
the release tag by the release run and also independently dispatchable to
retry one registry against an existing release. The npm, PyPI, and
launcher-gem legs are gated on the GitHub release — with its binaries and
`SHA256SUMS` — existing.

## How the contract is enforced

Every item in this document is locked in by at least one of:

- **clap parser snapshots** in `crates/socket-patch-cli/tests/cli_parse_*.rs` — assert flag names, short forms, defaults, aliases, and CSV delimiters by calling `socket_patch_cli::Cli::try_parse_from(...)`.
- **Helper unit tests** in `crates/socket-patch-cli/src/**` (`#[cfg(test)] mod tests` blocks) — cover `looks_like_uuid`, `parse_argv_with_shortcuts`, `detect_identifier_type`, `select_patches`, `find_patches_to_rollback`, `partition_purls`, `verify_status_str`, the JSON serializers, and the terminal UI in `src/ui/` (`StatusLine` redraw/clear/`println` byte streams, `confirm_with` answers and non-interactive notes, `select_one`'s JSON/empty guards, `plural`, `truncate`, the `color_enabled` truth table, `paint`/`severity`, and `pad`/`strip_ansi` alignment).
- **Async `run()` integration tests** in `tests/cli_parse_list.rs`, `tests/cli_parse_remove.rs`, `tests/cli_parse_setup.rs` — exercise the no-network error paths and assert JSON shape via `serde_json::from_str::<Value>` + per-key assertions.

If you add a new flag/subcommand/JSON key, add a test here that locks the new surface in the same PR.
