# socket-patch CLI contract

This document defines the **public surface** of the `socket-patch` binary. Third-party scripts, CI pipelines, and the npm distribution depend on this contract. Changes are governed by the semver policy at the bottom of this file.

> **Why this exists.** A flag rename, a default-value change, or a JSON key rename can land green and break every shipped wrapper silently. The contract below is backed by the unit tests under `crates/socket-patch-cli/src/**` (`#[cfg(test)] mod tests`) and the parser tests under `crates/socket-patch-cli/tests/cli_parse_*.rs`. Changes that violate the contract must update those tests in lock-step with a major version bump.

For task-oriented guidance, start with [usage](../../docs/usage.md),
[configuration](../../docs/configuration.md), or [v5 migration](../../docs/migrating-to-v5.md).

**Reference:** [Commands](#subcommands) · [Arguments](#global-arguments) ·
[Policy](#socketyml-patch-policy-v50) · [VEX](#manifest-less-vex-lockfile-discovery) ·
[Vendoring](#vendor-command-contract) · [Rollback](#rollback-command-contract-v50) ·
[Environment](#environment-variables) · [JSON](#json-output-shapes) · [Exit codes](#exit-codes)

## Subcommands

| Name | Visible alias(es) | Notes |
|---|---|---|
| `scan` | — | Find patches for installed packages and apply them. **v5.0 (MAJOR)**: a bare `scan` runs hosted mode (rewrites lockfiles so only the patched dependencies resolve to Socket-hosted, integrity-pinned packages); `--mode vendored` / `--mode agent` pick the other modes. Never prompts. See [scan modes](#scan-modes-v50) |
| `vex` | — | Emit an OpenVEX 0.2.0 attestation derived from the local manifest, the vendor ledger, and the hosted / vendored patch references the project's lockfiles wire (no manifest required; hosted records come from the API) |
| `vendor` | — | Eject patched dependencies into committable `.socket/vendor/` and rewire lockfiles |
| `list` | — | Print patches in the local manifest, plus the vendor ledger's records (v5.0) and the hosted pins the lockfiles wire (labeled; see the action matrix; an empty project exits 0) |
| `get` | `download` | Fetch a selected patch in hosted mode by default; `--mode agent` selects in-place application, also the default with `--save-only` or global targeting. Requires positional `identifier`. |
| `apply` | — | Agent mode: apply patches from the local manifest |
| `rollback` | — | **Full-state rollback (v5.0, MAJOR)**: restore original files AND unwind vendored lockfile wiring / restore hosted pins to their upstream registry entries, remove the rolled-back entries from the manifest, and GC their blobs/archives; takes optional variadic positional `targets` (PURL \| UUID \| path glob). See [Rollback command contract](#rollback-command-contract-v50) |
| `remove` | — | Restore and remove one patch across hosted, vendored, and agent state; requires positional `identifier`. |
| `repair` | `gc` | Download missing agent blobs, redownload missing/corrupt vendored artifacts (never re-synthesizing a lost ledger), and clean up unused ones (refuses with `lock_held` when a live process holds the lock; see "Lock lifecycle" below) |

Rows are in `--help` order (v5.0): the hosted/vendored workflow (`scan` → `vex` → `vendor`, with `list` to inspect), then the agent-mode (in-place patching) commands.

**Removed in v5.0:** the `setup` subcommand (see [Agent mode in CI](#agent-mode-in-ci-v50-setup-removed)).

**Removed in v4.0:** the `unlock` subcommand (a leftover lock from a crashed run never blocks acquisition — the OS releases a dead holder's advisory lock — so there is no stale-lock state to inspect or clear before a mutating command; `repair` briefly owned lock-file cleanup in v4.x, and since v5.0 every lock-taking command removes its own lock file on exit).

**Lock lifecycle (v5.0).** `<.socket>/apply.lock` never outlives the command that took it: acquisition creates `.socket/` when it is missing, the guard's drop unlinks the file WHILE the lock is still held (so a waiter can never lock an orphaned inode), releases it, and then removes `.socket/` itself if that left the directory empty — a run that had nothing to persist leaves no `.socket/` behind, and there is nothing to `.gitignore`. A leftover file from a crashed (SIGKILLed) run is reclaimed in place and removed by the next lock-taking command. The lock is taken by `apply`, `rollback`, `remove`, `repair`, `vendor`, agent-mode `get` and `scan --apply`/`--sync` (download → manifest write → nested apply is ONE lock window — the nested apply never re-acquires), and `scan`/`get` in vendored **and hosted** mode — hosted acquires it around its first wet write (the takeover pre-reverts), never on `--dry-run` and never when the run would write nothing, so hosted previews and no-op runs create no `.socket/`. Dry runs of the other commands may still take the lock; it is residue-free either way. A live holder is `lock_held` (exit 1); a directory or special file squatting on `.socket/` or on the lock path is a lock I/O error — `lock_io` (exit 1, `failed to open lock file at <path>: …`; a read-only project root surfaces the same code at the acquire, before any ledger or manifest write) — never `lock_held`.

**Bare-UUID fallback.** `socket-patch <UUID>` is rewritten to `socket-patch get <UUID>`. The UUID shape checked is the standard 8-4-4-4-12 hex pattern (case-insensitive). See [`src/lib.rs::looks_like_uuid`](src/lib.rs).

**Root `--update` flag.** `socket-patch --update [VERSION]` updates the binary itself from GitHub Releases. It is a root flag, not a subcommand: argv is rewritten (the same mechanism as the bare-UUID fallback) onto an internal hidden subcommand whose name carries no stability guarantee — script the flag, never the internal name. Combining the flag with a subcommand (`socket-patch --update scan`) is a usage error (exit 2). Full contract: [Self-update contract](#self-update-contract-socket-patch---update).

**Internal `hosted-bundle` subcommand.** `socket-patch hosted-bundle` is a hidden, INTERNAL parity/debug harness for the in-memory hosted engine (`socket-patch-core` `src/hosted/memory/`, the engine the Node addon embeds): it reads a JSON bundle `{"files": {path: text}, "binaryFiles"?: {path: base64}, "presentOnly"?: [path], "symlinks"?: [path], "projectRoots"?: [dir], "pipenvMajor"?: n, "batchSize"?: n, "noSocketYml"?: bool, "minSeverity"?: s, "policyPaths"?: [path], "policySha256"?: s}` on stdin, queries the authenticated org API built from `--api-url` / `--api-token` / `--org` only (both of the latter are required; no public-proxy fallback), and prints the engine result — or `{"status":"error","error":{"code","message"}}` with exit 1 (exit 2 for unusable input or missing credentials). It never touches the filesystem. Its name, input and output carry NO stability guarantee; do not script it.

## Global arguments

Every subcommand accepts the same set of "global" flags via a single shared `GlobalArgs` struct that's `#[command(flatten)]`-ed into each per-command struct (`crates/socket-patch-cli/src/args.rs`). Subcommands that don't actually consume a given flag accept it silently — e.g. `list --global` parses fine and is a no-op. For flags with an environment-variable binding, precedence is **CLI arg > env var > default** — and for exactly three keys (`--api-token`, `--org`, `--api-url`) the JS socket-cli's persisted login sits between env var and default: **CLI arg > env var (canonical, then `SOCKET_CLI_*` alias) > socket-cli `config.json` > default**. See "Persisted configuration" under Environment variables.

| Long | Short | Env var | Default | Type | Semantic |
|---|---|---|---|---|---|
| `--cwd` | — | `SOCKET_CWD` | `.` | path | Working directory |
| `--manifest-path` | — | `SOCKET_MANIFEST_PATH` | `.socket/manifest.json` | path | Manifest location (resolved relative to `--cwd`) |
| `--api-url` | — | `SOCKET_API_URL` | `https://api.socket.dev` | string | Authenticated API endpoint |
| `--api-token` | — | `SOCKET_API_TOKEN` | (none) | string | Auth token (absence selects the public proxy) |
| `--org` | `-o` | `SOCKET_ORG_SLUG` | (auto-resolve) | string | Org slug |
| `--proxy-url` | — | `SOCKET_PROXY_URL` | `https://patches-api.socket.dev` | string | Public proxy when no token |
| `--ecosystems` | `-e` | `SOCKET_ECOSYSTEMS` | (all) | CSV → `Vec<String>` | Restrict to these ecosystems |
| `--vendor-source` | — | `SOCKET_VENDOR_SOURCE` | **`service`** | enum: `service` \| `auto` (alias) | How `vendor` acquires the installable artifact (see "Prebuilt vendor artifacts") |
| `--maven-config` | — | — | (recorded choice, else `auto`) | enum: `auto` \| `none` | Maven reactor vendoring: write the repository tail (`auto`) or use only the fallback file repository (`none`). The choice persists in the vendor ledger. |
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
| `--yes` | `-y` | `SOCKET_YES` | `false` | bool | Skip prompts (`scan` never prompts) |
| `--lock-timeout` | — | `SOCKET_LOCK_TIMEOUT` | (none) | seconds (u64) | How long to wait for `<.socket>/apply.lock`. Unset and `0` both mean a single non-blocking try; a positive value retries with a 100 ms backoff. Only meaningful on the lock-taking subcommands — `apply`, `rollback`, `repair`, `remove`, `vendor`, and `scan`/`get` whenever they write (agent-mode download + apply, vendored, hosted) |
| `--debug` | — | `SOCKET_DEBUG` | `false` | bool | Verbose debug logs to stderr |
| `--no-telemetry` | — | `SOCKET_TELEMETRY_DISABLED` | `false` | bool | Disable anonymous usage telemetry |
| `--no-trust-lockfile-config` | — | `SOCKET_NO_TRUST_LOCKFILE_CONFIG` | `false` | bool | Opt out of hosted mode's automatic `trustLockfile: true` write to `pnpm-workspace.yaml` (see the pnpm trust-config note under the scan arguments) |
| `--no-npm-allow-remote-config` | — | `SOCKET_NO_NPM_ALLOW_REMOTE_CONFIG` | `false` | bool | Opt out of hosted mode's automatic `allow-remote=all` write to the project `.npmrc` (see the npm allow-remote note under the scan arguments). Read by `scan --mode hosted` and `get --mode hosted`; other subcommands accept it silently |
| `--no-vlt-install-cleanup` | — | `SOCKET_NO_VLT_INSTALL_CLEANUP` | `false` | bool | Opt out of hosted mode's warm-tree heal for vlt: stale installed copies (`node_modules/.vlt-lock.json` and the stale `node_modules/.vlt/<DepID>` entries) are left in place after `vlt-lock.json` is repointed (`scan`/`get --mode hosted`) or restored (`rollback`/`remove`), and the `redirect_vlt_reinstall_required` advisory tells you to run `vlt ci` instead. Stale copies of optional dependencies are always left in place (see `redirect_vlt_reinstall_required`). Other subcommands accept it silently |

**`--download-mode` removed (v5.0, MAJOR).** The global `--download-mode` flag and its `SOCKET_DOWNLOAD_MODE` binding are gone, with no alias: passing the flag is a usage error (exit 2) and the env var is ignored. Patch content is always fetched as per-file blobs (`.socket/blobs/`); `.socket/diffs/` archives are obsolete, never read, and removed by the cleanup sweeps.

`--offline` means the same thing on every command (v3.0): never contact the network, fail loudly when a required local source is missing. On `repair`, `--offline` and `--download-only` are mutually exclusive (exit 2). `scan` and `get` need remote data for their core function (patch discovery / patch fetch), so `--offline` refuses them up front — exit 1 with an error naming the offline gate (JSON: `status: "error"`), before any crawl, client build, or network contact. This covers `scan --vendor` too: offline vendored staging is `vendor --offline`'s job.

The `--strict` mismatch policy applies to the in-place apply paths (apply/get/scan --apply/hook/go redirect). DEFAULT (v3.4): a file whose on-disk content matches neither the patch's beforeHash nor its afterHash is overwritten with the FULL verified patched content (blob writes are hash-gated to exactly afterHash) and surfaced as a `content_mismatch_overwritten` stderr warning + Skipped event. A file the patch adds (empty beforeHash) that already exists with other content is the same case. `--strict` turns that case into a hard error. Rollback of an added file deletes it; the content it replaced is not kept. `--force` overrides `--strict` and additionally skips missing files. Vendor staging is unaffected (it always auto-overwrites into its private stage).

## Per-subcommand arguments

Beyond the globals above, each subcommand defines a small set of local arguments.

| Subcommand | Local arg | Env var | Purpose |
|---|---|---|---|
| `apply` | `--force` / `-f` | `SOCKET_FORCE` | Bypass beforeHash check |
| `apply` | `--check` | — | Read-only audit that every in-scope (`--ecosystems`) manifest patch is in place, for CI / GitHub-App auditing (v5.0: previously Go-only, which passed on any unpatched non-Go tree). Local Go patches: the committed `.socket/go-patches/` copies and `go.mod` `replace` directives match the manifest (`go_redirect_drift`). Every other patch: each installed copy hashes to the record's `afterHash` — the `vex` verifier over the `vex` copy lookup; the copies are narrowed by `apply`'s own rules: a release variant (a qualified purl such as `?artifact_id=` / `?platform=`) is judged only on the copies holding its distribution, matched against every variant of its base as `apply` matches them, and an installed copy that holds none of them is drift of the base purl (`no_matching_variant`, the copy `apply` fails with "no matching variant found"; a Gradle / Ivy cache dir is exempt, as in `apply`); for gem, once a bundle-store copy exists the `gem env` fallback-home copies are not judged (`apply` treats them as best-effort). Drift is a `failed` event per patch with `errorCode` `not_applied` (still unpatched), `hash_mismatch` (neither the original nor the patched bytes), `file_not_found` or `no_matching_variant`, status `partialFailure`, exit 1, and the human `Error: Patches are OUT OF SYNC:` report (printed even under `--silent`). In sync is exit 0: `Patches are in sync (N checked).` and, under `--json`, a `skipped` event per verified patch (`errorCode: already_patched`). A patch with no installed copy is skipped as `apply` skips it (`package_not_installed`; the human line adds `M not installed, skipped`). Vendor-owned patches are excluded (`vendor --check` audits them). Lock-free, fetch-free, offline-safe; it never writes. An unreadable manifest is drift (`manifest_unreadable`, exit 1) |
| `vendor` | `--force` / `-f` | `SOCKET_FORCE` | Tolerate missing patch-target files in the stage + bypass the variant probe. A beforeHash mismatch no longer needs it: vendor staging auto-overwrites with the verified patched content (`vendor_content_mismatch_overwritten` warning) |
| `vendor` | `--revert` | `SOCKET_VENDOR_REVERT` | Undo vendoring: restore recorded original lockfile fragments + remove `.socket/vendor/` artifacts. Works without a manifest. A package vendored over a hosted pin returns to its upstream registry entry, never to hosted (see "Takeover reconciliation") |
| `vendor` | `--check` | — | Offline, read-only artifact and wiring audit; exits 1 on drift. Conflicts with `--revert`. |
| `vendor` | `--local-repo <path>` | — | With `--check`, also inspect suffixed Maven jar/POM copies in this cache for conflicts. |
| `apply`, `scan`, `vendor` | `--vex` | `SOCKET_VEX` | Generate an OpenVEX 0.2.0 document at this path on a successful run; see "embedded VEX" below |
| `apply`, `scan`, `vendor` | `--vex-product`, `--vex-no-verify`, `--vex-doc-id`, `--vex-compact` | `SOCKET_VEX_PRODUCT`, `SOCKET_VEX_NO_VERIFY`, `SOCKET_VEX_DOC_ID`, `SOCKET_VEX_COMPACT` | Passthrough to the embedded VEX builder; mirror the standalone `vex` knobs. Inert unless `--vex` is set |
| `scan` | positional `[PATHS]...` | — | (v5.0) Meaning depends on the mode. **Hosted / vendored** (bare `scan` included): each PATH, or directory glob (`apps/*`), is a project directory scanned on its own as if it were `--cwd`. **Agent** (and a mode-less `--prune`/`--global` report): path globs scoping DISCOVERY to packages installed under matching paths (`packages/foo`, `apps/**`). See "Path-scoped scans" below |
| `scan` | `--mode <hosted\|vendored\|agent>` | — | The documented selector for the three patch-application modes (v5.0 default: `hosted`, except that a `--prune` or `--global`/`--global-prefix` scan with no mode is report-only). v5.0 removes the hidden value aliases `host`/`redirect`/`vendor` (now an invalid-value usage error). `vendored` and `agent` each keep one hidden, deprecated boolean spelling: `vendored` == `--vendor`, `agent` == `--apply` (`--sync` counts as an agent spelling); hosted has none (v5.0 removes `--redirect`). Combining `--mode` with a boolean of a DIFFERENT mode is a usage error (exit 2, enforced in `resolve_mode_flags` — clap's `conflicts_with` is value-independent); the same mode spelled both ways is accepted. `--prune` is an orthogonal GC knob and never conflicts — but hosted mode runs no GC, so `--mode hosted --prune` emits an explicit `redirect_prune_ignored` warning (JSON `redirect.warnings[]` + stderr) instead of silently dropping the flag |
| `scan` | `--apply` / `--prune` / `--sync` | — | `--apply` == `--mode agent` (deprecated spelling); `--prune` = GC after the scan (ignored with a `redirect_prune_ignored` warning in hosted mode); `--sync` = `--mode agent --prune` |
| `scan` | `--package <name\|purl>` (repeatable or comma-separated) | `SOCKET_SCAN_PACKAGES` | (v5.0) Only scan these packages: a name (`lodash`, `@scope/pkg`, `requests`, `group:artifact`; matched against the full name or its last segment, case-insensitively; PyPI names compare by their PEP 503 canonical form, so `typing_extensions` matches `pkg:pypi/typing-extensions`) or a purl with or without a version (`pkg:npm/lodash` matches every version, `pkg:pypi/requests@2.31.0` only that one). Qualifiers are ignored. Filters the crawl like `--ecosystems`, after the prune universe is captured, so `--prune` still judges the full crawl |
| `scan` | `--vendor` | — | Vendor every patched dependency instead of applying in place (`--vendor` == `--mode vendored`; conflicts with `--apply`/`--sync`, combines with `--prune`). Vendored mode is manifest-free (v5.0): the vendor ledger embeds the patch records and `.socket/manifest.json` is never written. The former opt-in for exactly that, `--detached`, is removed in v5.0 (unknown-flag usage error) |
| `scan` | `--batch-size` | `SOCKET_BATCH_SIZE` | API batch chunk size. Unset (v5.0): `500` on the authenticated API (the server's per-request maximum), `100` on the public proxy; a given value applies on either endpoint (`0` is floored to `1`). A chunk whose request body would exceed 256 KiB (the public proxy's body cap) is split into consecutive smaller chunks, deterministically (greedy, in crawl order). A mid-run downgrade to the proxy keeps the chunks already formed |
| `scan` | `--max-new-patches <N\|none>` | `SOCKET_MAX_NEW_PATCHES` | (v5.0) Per-run cap on NEW patches (packages with no recorded patch in the project), most severe first; the rest are deferred to the next scan. `0` admits upgrades only, `none` (case-insensitive) is unlimited, absent is unlimited unless socket.yml sets `patches.maxNewPatches`. Precedence: flag > env > socket.yml > unlimited (`--no-socket-yml` drops the socket.yml layer). The env value is read at run time (the `rollout` block reports `flag` vs `env`): empty is unset, malformed is a usage error (exit 2, before any network access). Upgrades and already-applied patches are never capped. See "Per-run limit on new patches" below |
| `scan` | `--no-socket-yml` | `SOCKET_NO_SOCKET_YML` | (v5.0) Ignore the repository's socket.yml patch policy (its `patches` block and `projectIgnorePaths`) for this run; the built-in test/fixture ignores still apply. The `policy` block reports `source: "bypassed"`. See "socket.yml patch policy". |
| `scan` | `--min-severity <critical\|high\|medium\|moderate\|low\|none>` | `SOCKET_MIN_SEVERITY` | (v5.0) Severity floor for the patch a package may receive (worst advisory severity; unknown severity is skipped whenever a floor is set). Beats `patches.minSeverity`; the flag beats the env; `none` lifts the floor. A malformed value is exit 2. |
| `get`, `scan` | `--all-releases` | `SOCKET_ALL_RELEASES` | Download patches for every release/distribution variant of a matched package — PyPI wheel/sdist (`artifact_id`), RubyGems (`platform`), Maven (`classifier`) — not just the one(s) matching the locally-installed distribution. On `scan` this makes the stored manifest portable across environments (e.g. cross-platform CI caches). On `get` (v3.6) it ALSO disables the coarse installed-**version** narrowing of CVE/GHSA fan-outs (see "get --mode and installed narrowing"): every found version's patch is fetched, installed or not |
| `get` | positional `identifier`; `--id` / `--cve` / `--ghsa` / `--package` (`-p`); `--save-only` (alias `--no-apply`); `--mode <hosted\|vendored\|agent>` | `SOCKET_SAVE_ONLY` | Patch lookup + consumption mode (v3.6). `--mode` reuses scan's value enum (same hidden value aliases `host`/`redirect`/`vendor`; deliberately no env binding, matching scan). Default (v5.0): `hosted`, like scan; `agent` (save + apply in place) when `--save-only` or `--global`/`--global-prefix` is given. An explicit `--mode hosted\|vendored` with `--global`/`--global-prefix` is a usage error (exit 2, scan's wording: global installs have no project lockfile). An explicit `--save-only` conflicts with `--mode hosted\|vendored` — rejected with **exit 1** via get's established self-enforced-conflict style (unlike scan's exit-2 mode conflicts; see the exit-code table) |
| `remove` | positional `identifier`; `--skip-rollback`; `--preserve-state` (v5.0) | `SOCKET_SKIP_ROLLBACK`, `SOCKET_PRESERVE_STATE` | Manifest entry removal. The identifier matches like a `rollback` target (a PyPI name compares by its PEP 503 canonical form). `--preserve-state` is the single-patch twin of `rollback --preserve-state`: restore the tree and unwind the identifier's vendored/hosted wiring, but keep the manifest entry, the vendored artifact + ledger entry, and skip all GC. Combining it with `--skip-rollback` is a self-enforced usage error (exit 2): one flag keeps the tree and drops the state, the other restores the tree and keeps the state — together they select the do-nothing quadrant ("the combination would be a no-op: nothing would change"). The conflict fires whether either flag is spelled on the command line or sourced from its env var |
| `rollback` | optional variadic positional `targets` (PURL \| UUID \| path glob); `--preserve-state` (v5.0) | `SOCKET_PRESERVE_STATE` | Rollback scope. Multiple targets union. A token becomes a path glob ONLY when it is path-SHAPED — contains a separator (`/` or `\`) or a glob metacharacter (`*?[`), or starts with `./`, or is absolute; a `pkg:` prefix is a PURL and every other bare word keeps identifier (PURL/UUID) semantics, so a mistyped identifier or truncated UUID stays a safe exit-1 "No patch found matching identifier: X" (with a hint suggesting `./X` or `X/**` for directory targeting) instead of silently becoming a path scope. An unparseable glob is a usage error (exit 2) |
| `vex` | `--output` / `-O`, `--product`, `--no-verify`, `--doc-id`, `--compact` | `SOCKET_VEX_OUTPUT`, `SOCKET_VEX_PRODUCT`, `SOCKET_VEX_NO_VERIFY`, `SOCKET_VEX_DOC_ID`, `SOCKET_VEX_COMPACT` | OpenVEX 0.2.0 document generation; see "vex output channels" below |
| `repair` | `--download-only` | `SOCKET_DOWNLOAD_ONLY` | Repair-specific cleanup mode (mutually exclusive with `--offline`; combining them is a usage error, exit 2) |

**pnpm hosted-mode contract**: `scan --mode hosted` handles block and flow resolutions in legacy `shrinkwrap.yaml` and lockfileVersion 5.x, 6.0, and 9.0. The [pinned compatibility matrix](../../docs/testing/pnpm-compatibility.md) samples pnpm majors 1–12. Early shrinkwrapVersion 3 without a positive minor version is refused with `redirect_pnpm_legacy_lockfile_unsupported`: pnpm 1.0.0 discards hosted URLs even on frozen installs. Upgrade to a tested release (1.43.1 or newer) and regenerate the lock, or use agent mode.

Each matching package instance is spliced, including scoped, quoted and nested-peer keys, one `redirect_pnpm_resolution` edit per changed instance (`rollback` / `remove` restore each from the npm registry — see "Hosted unwind coverage"). LF/CRLF and unrelated lock bytes are preserved. Unsupported matching instances refuse that dependency across the lockfile set; an already-hosted URL elsewhere cannot confirm a partial rewrite.

For a **9.0 root lock**, the CLI ensures `pnpm-workspace.yaml` carries `trustLockfile: true` (created with a root-only `packages:` scaffold, or appended while preserving user bytes). pnpm >=11 requires this to accept hosted URLs; it disables registry re-verification for the whole lock, while sha512 tarball integrity remains enforced. The write (edit kind `redirect_pnpm_workspace_trust`) respects `--dry-run`, skips legacy locks and Rush repos, preserves explicit user settings (an existing top-level key in any YAML spelling: quoted, `trustLockfile :`, with a trailing comment), and is disabled by `--no-trust-lockfile-config`. The key goes inside the document (before a `...` end marker); a file a line append would corrupt (a flow-style root, an indented root, several documents) is left untouched and the warning gives the manual recoveries. The vendored `overrides:` mirror in `pnpm-workspace.yaml` reads keys the same way and refuses those shapes before writing. The `redirect_pnpm_trust_lockfile` warning explains manual configuration when required and clean reinstall guidance for all pnpm versions. Existing installs and warm stores can retain upstream files; use a clean install tree and empty store, then verify installed files with `socket-patch vex`. Neither a successful install nor a local VEX export guarantees hosted SBOM recognition or changes dashboard alert actions/counts.

**npm hosted-mode `allow-remote` contract**: npm >=12 defaults `allow-remote=none` and refuses (EALLOWREMOTE) every lockfile entry whose `resolved` tarball is not served by the configured registry — exactly what a hosted redirect writes into `package-lock.json` / `npm-shrinkwrap.json`. Whenever a run leaves a ROOT npm lock carrying a granted hosted artifact URL (spliced this run, or already redirected by an earlier one — a missed config heals on re-run), the CLI ensures `allow-remote=all` in the project-root `.npmrc`: the file is created holding exactly `allow-remote=all\n` when absent, otherwise one `allow-remote=all` line is spliced in after the last non-empty top-level line (before any ini `[section]` header), in the file's own line ending, with the BOM, CRLF and trailing-newline shape preserved. The write lands in `redirect.rewrittenFiles` (edit kind `redirect_npmrc_allow_remote`), respects `--dry-run` (nothing written; the warning says what would be — including for a vendored → hosted takeover the dry run only previews), and is disabled by `--no-npm-allow-remote-config` / `SOCKET_NO_NPM_ALLOW_REMOTE_CONFIG`. The `.npmrc` grammar is npm's own `ini` parser's (cross-checked against it): lines split on any run of `\r` / `\n` (a bare `\r` ends a line), only the exact key `allow-remote` counts after ini unquoting (npm ignores `allow_remote` / `ALLOW-REMOTE` in a `.npmrc`; such a line is left alone and the real key appended), comment lines are ignored, a `[section]` header is recognized only as npm does — on the UNTRIMMED line (an indented or BOM-prefixed `[sec]` is a plain top-level key) — and ends the top-level scope, quotes and inline comments are stripped, the LAST top-level assignment wins, and the value is case-sensitive. An explicit other value (`allow-remote=none` / `root` / anything but `all`) is RESPECTED and never rewritten — the pnpm `trustLockfile: false` precedent — in the project `.npmrc` AND in every other npm config layer npm would consult: an `npm_config_allow_remote` environment variable (any spelling npm normalizes; it beats every `.npmrc`, so a project write could not take effect), and — when the project file sets nothing — the user (`npm_config_userconfig` / `~/.npmrc`), global (`npm_config_globalconfig` / `<prefix>/etc/npmrc`, prefix from `npm_config_prefix`, the user/builtin config, `PREFIX` or the `node` binary's install root) and builtin (npm's own `npmrc` beside the `node` binary: `<dir>/lib/node_modules/npm/npmrc`, `<dir>\node_modules\npm\npmrc` on Windows) config files — path values `${VAR}`-expanded and `~`-expanded like npm, env names case-insensitive on Windows, where a committed project line would silently override a machine / org policy. A symlinked, non-regular or unreadable `.npmrc`, or one with bare-`\r` line endings (npm splits on them, the line splice does not), is left untouched. Every variant emits the `redirect_npm_allow_remote` warning (written / would write / already set / explicit value respected — naming the project file, the env var, or the user/global/builtin config path — / opted out / unreadable or unsupported), always with the tradeoff: `allow-remote=all` lets npm install ANY url-resolved dependency, not just Socket's patched ones, while the per-entry sha512 integrity pins stay enforced; the remedy for the non-writing variants is `allow-remote=all` in `.npmrc` or `npm ci --allow-remote=all`. npm <=11 is unaffected (11 defaults to `all`, <=10 has no such setting). **Unwind (v5.0: no ledger)**: once `rollback`, `remove` or a hosted → vendored takeover has restored the last hosted entry of the root `package-lock.json` / `npm-shrinkwrap.json` to its upstream registry entry (see "Hosted unwind coverage"), a project `.npmrc` holding exactly `allow-remote=all\n` (the file hosted mode creates) is deleted; any other `.npmrc` that still has a top-level `allow-remote=all` line is left untouched and the `npm_allow_remote_left` warning says the line may be removed if nothing else needs it (v5 keeps no record of whether hosted mode added it, so it is never removed behind the user's back). The rewrite's stage file is created with the `.npmrc`'s own permission bits (a 0600 token-bearing file is never staged world-readable). **Vendored mode is unaffected**: its `file:.socket/vendor/…` resolutions are npm `file` specs, which npm gates by `allow-file` (default `all`), never `allow-remote` — verified by the real npm 12 vendored matrix.

`redirect_pnpm_no_lockfile` names pnpm when installer markers exist without a lock; `redirect_pnpm_entry_vendored` identifies a vendored entry instead of reporting it missing. Supported `shrinkwrap.yaml` files are writable lockfiles, not read-only markers.

**vlt hosted-mode contract**: `scan` / `get --mode hosted` rewrite, in `vlt-lock.json`, every default-registry node of a granted `name@version` (the `''` / `npm` segment or a URL segment equal to the lock's scalar `registry`, both DepID grammars, every peer and modifier variant): slot [2] becomes the granted sha512 and slot [3] the hosted URL (appended to a 3-tuple); the DepID, flags and trailing slots, the line ending and every other byte stay. `options` is never edited and `vlt.json` is only read. A lock with another `lockfileVersion` (decided on the raw JSON token), a BOM, a non-object body or a `nodes` section outside vlt's one-node-per-line layout refuses the whole lock (`redirect_vlt_lock_unsupported`). **Confirmation**: vlt drives when its install state (`node_modules/.vlt-lock.json` or `node_modules/.vlt/`) is present or no other npm-family lock is; then only `vlt-lock.json` confirms a uuid. Otherwise every lock is rewritten, `redirect_vlt_sibling_lockfiles` warns, and the other locks' rules confirm, including a dep `vlt-lock.json` merely does not wire (`redirect_vlt_entry_not_found`, `redirect_vlt_entry_vendored`). Whichever lock drives, a dep the vlt rewriter refuses (`redirect_vlt_missing_sha512`, `redirect_vlt_unsupported_lock_key`) is never confirmed by any lock, although a sibling lock may already carry its rewritten URL. **Artifact preflight**: before any takeover or write (dry runs included), each granted artifact with a default-registry instance is fetched once as vlt fetches it and must verify, else the dep is withheld (`redirect_vlt_artifact_unverifiable`, see the tag table). **Heal**: stale installed copies of Socket-owned nodes are removed so the next `vlt install` extracts the patched bytes, and `rollback` / `remove` do the same for the registry bytes (`--no-vlt-install-cleanup` keeps them; optional dependencies' copies are always kept); `redirect_vlt_reinstall_required` says what happened and what to run. The same-run `--vex` never attests a vlt package whose installed copy is stale or unchecked, whose lock a vlt release may ignore (`redirect_vlt_lockfile_version_missing`, `redirect_vlt_old_lockfile_ignored`, `redirect_vlt_scalar_registry_ignored`), or which also resolves from a non-default registry (`redirect_vlt_custom_registry_skipped`). `vlt.json` or vlt install state without `vlt-lock.json` warns `redirect_vlt_no_lockfile` instead of `redirect_npm_no_lockfile`. `rollback` / `remove` restore each hosted node's slots [2] and [3] from the version document of the registry the node resolves against (slot [3] is its `dist.tarball`, as vlt writes it; `upstream_registry_fallback` when that registry can't be read), following the lock's own slot-[3] convention (see "Hosted unwind coverage"). Tested releases: `docs/testing/vlt-compatibility.md`.

**Takeover reconciliation (every hosted ecosystem, v5.0)**: vendoring over a hosted pin (`vendor`, `scan --mode vendored`, `get --mode vendored`) first RESTORES that purl's lock entries to their default upstream registry entry — the same restore `rollback` runs (core `patch::redirect::upstream::restore_upstream`; see "Hosted unwind coverage"), over the hosted pins lockfile discovery finds (v5 keeps no hosted ledger) — and then vendors, so the vendor ledger records the PRISTINE registry entry as its wiring `original` and `vendor --revert` lands back on upstream registry state, never on hosted. The run that takes over records a `vendor_takeover_reverted_redirect` advisory event (`skipped` action beside the purl's genuine outcome; detail `<purl> was hosted; restored its upstream registry entry (<files>) before vendoring (mode takeover)`; the human path prints `Warning: …`), plus any advisory the restore raised (`npm_allow_remote_left`, …). **A takeover the vendored backend does not carry through keeps the hosted pin (#853, #944)**: the wet run holds the restore in its group commit, and when the backend then refuses the purl — whatever the code: a pnpm `catalog:` dependency (`vendor_lock_entry_unsupported`), a CRLF `pnpm-lock.yaml` (`vendor_lockfile_crlf_unsupported`), a workspace exact-pin override (`vendor_override_conflict`), a uv inline `[tool.uv] sources` table, a prebuilt download that fails, … — or its apply fails with nothing recorded, the restore is rolled back before anything reaches disk: the purl is reported `failed <code>` with the backend's own code and detail, neither `vendor_takeover_reverted_redirect` nor the restore's advisories are recorded for it, and the hosted wiring stays byte-for-byte (exit 1 / `partial_failure`), so the package stays hosted-patched instead of being un-hosted and then refused. `vendor --dry-run` previews that same `failed <code>` by running the backend's dry run over the restored project staged in memory (nothing written). A restore that writes a file outside the group commit's captured set (`.socket/gradle/hosted-index.tsv`) is not rolled back. The `scan` / `get --mode vendored --dry-run` preview does not model the takeover yet (it still lists such a purl `would_vendor`), except for the gem preflight below. **Gem preflight before the takeover**: `scan` / `get --mode vendored` ask the gem vendored backend's own refusals BEFORE the upstream restore — the manifest gate (`gemfile_not_loaded`: a `gems.rb` twin or a `BUNDLE_GEMFILE`-configured manifest) and the Gemfile declaration gate evaluated on the Gemfile and Gemfile.lock text the restore would leave (`gemfile_declaration_not_editable`: a declaration inside a `group` / `platforms` / conditional block, a parenthesized or duplicate declaration, …) — so a hosted gem vendored mode cannot wire is reported `failed <code>` with the hosted `Gemfile` / `Gemfile.lock` byte-untouched (exit 1 / `partial_failure`), and their `--dry-run` preview reports that gem as `would_refuse` with the same `errorCode` (exit 0, like the Bun / vlt `would_refuse` rows), never `would_vendor`. Pinned against real Bundler by `tests/e2e_redirect_gem_build.rs`. `--dry-run` resolves the same restore without writing (registry lookups included): a pin that would restore reports `vendor_would_revert_redirect`, and one that would be refused surfaces in the preview with the wet run's `redirect_revert_failed` code and detail (for bun, whose hosted rewrite replaces the entry's `name@version` spec, the preview first runs the Bun vendored preflight described below and then stops at the advisory instead of reading the still-hosted lock — a lock the vendored backend would refuse is previewed as the wet run's `failed <code>`, never as `vendor_would_revert_redirect`). A purl whose upstream entry cannot be restored — `--offline`, a registry that does not answer, a lock the restore refuses (see "Hosted unwind coverage"; a hosted binary `bun.lockb` pin IS restored for the takeover — its npm registry record is rebuilt natively — while `rollback` / `remove` refuse it) — fails `redirect_revert_failed` with the detail `cannot vendor over the live hosted pin: cannot restore <purl> to its upstream registry entry: <why>; restore it from version control instead (`git checkout -- <files>`)` (exit 1 / `partial_failure`, nothing vendored for it, the hosted wiring left in place). The cargo backend's `hosted_redirect_live` refusal backstops a crate whose hosted residue is still in place when it is reached; its detail names `socket-patch rollback` and `git checkout -- Cargo.toml Cargo.lock`. **Bun vendored preflight before the takeover**: `vendor` — like `scan` / `get --mode vendored`, whose pre-download preflight runs earlier — checks `bun.lock` / `bun.lockb` with the shared Bun vendored preflight BEFORE the upstream restore, so a hosted purl on a lock the vendored backend refuses (a pre-version-2 `workspace:` lock → `vendor_bun_workspace_unsupported`; a malformed or unsupported binary lock → `vendor_bun_lockb_invalid`; an unsupported text-lock version → its code) is reported `failed <code>` with the hosted wiring and active Bun lock byte-untouched (exit 1 / `partial_failure`): the package stays hosted-patched instead of being un-hosted and then refused. `vendor --dry-run` previews that same `failed` code (exit-code parity with the wet run, nothing written) instead of promising `vendor_would_revert_redirect`. Pinned by `tests/in_process_vendor_bun_takeover.rs` and, against real Bun, `tests/mode_migration_bun.rs`. The npm package-lock backend's lock gate gets the same placement: a hosted pin in a project whose `npm-shrinkwrap.json` / `package-lock.json` is not a v2/v3 lock (npm 6's lockfileVersion 1) is refused `failed vendor_lockfile_version_unsupported` BEFORE the restore, in `vendor`, `scan --mode vendored` and `get --mode vendored` alike, so the package stays hosted-patched; the vendored dry-run preview lists every npm purl of such a project as `would_refuse` with that code. Pinned by `tests/in_process_vendor_npm_v1_takeover.rs`. Hosted → vendored and vendored → hosted (`redirect_takeover_reverted_vendored` in `redirect.warnings[]`) both work in place on the locks the target mode accepts. **Removed in v5.0**: the run-level `vendor_supersedes_redirect` warning and its reconcile of the redirect ledger (a live lock that already proved vendored won over a stale hosted ledger record) — once the lock routes a package to `.socket/vendor/`, no hosted state is left to go stale. Which way the live lock points is decided by the same lockfile discovery rules `vex` gates attestations on (see "Manifest-less VEX (lockfile discovery)"), for `redirect_supersedes_vendored` and `hosted_wiring_retained` alike.

### Scan modes (v5.0)

**Mode resolution (`resolve_mode_flags`, MAJOR in v5.0).** `--mode`, or one of its legacy boolean spellings (`--vendor`, `--apply`/`--sync`), picks the mode. With none of them, `scan` runs **hosted** mode — JSON and human alike; the result nests under the JSON `redirect` sub-object (see the hosted paragraph below). The one exception: a `--prune` or `--global`/`--global-prefix` scan with no mode has no project lockfile to rewire, so it is **report-only** — discovery, the table, the `updates` array and the `redirectState` block below, plus the `--prune` GC — and, in human mode, ends with the hint `To apply these patches in place, run:` / `  socket-patch scan --mode agent [PATHS]` / `  socket-patch get <package-name-or-purl-or-CVE-ID>`. A global scan's hint carries the run's scope, so it can be run verbatim: `-g` (`scan --mode agent -g` / `get -g <…>`), or `--global-prefix <dir>` when a prefix was given (the directory shell-quoted when it needs it). An explicit `--mode hosted` or `--mode vendored` (or the hidden `--vendor`) with `--global`/`--global-prefix` is a usage error (exit 2: global installs have no project lockfile to redirect, or to wire vendored artifacts into); `get` enforces the same rule with the same wording.

**Global scope never touches the project's state (v5.0).** A `--global`/`--global-prefix` run that starts inside a project acts on the global installs only. The `--cwd` project's hosted pins and vendor ledger are not its target: `rollback` and `remove` run no hosted or vendored leg (they restore the global copies and drop their manifest records; `rollback` keeps the manifest records of purls the project vendors), a pre-v5 hosted ledger is never retired, and the project's vendor ledger does not own the global copies, so `apply` and `scan --mode agent` patch the global copy of a purl the project vendors (no `vendored` skip, no `vendored_ownership_retained` warning). The standalone `vendor` command acts only on the project, so every form of it (plain, `--revert`, `--check`) is a usage error under global scope: exit 2, human `Error: <flag> cannot be used with vendor[ --revert| --check]: global installs have no project lockfile to …`, JSON `{status: "error", error: {code: "global_scope_unsupported", message}}`, checked before the project is read or locked (#498).

**scan never prompts, in any mode** (v5.0): no confirm, no free-tier patch menu (it always takes the top-ranked downloadable patch; see "Which patch gets selected"), and no `Non-interactive mode detected` note. `--yes` does not change a scan. `get` (agent mode only — hosted/vendored `get` never prompts either, v5.0), `rollback`, `remove` and `--update` keep their prompts.

**Hosted-state visibility (`redirectState`, additive/MINOR).** Every non-hosted-mode, non-vendored-mode `scan --json` SUCCESS envelope (report-only, `--mode agent`/`--apply`/`--sync`, and the zero-discovery envelope) carries an additive top-level `redirectState` object whenever the project's lockfiles pin ≥ 1 hosted patch: `{ mode, records: [{purl, uuid}], wiringLive: [purl] }`. It is a descriptive STATE block, not a warning. `mode` is the constant `"hosted"`. **v5.0 (MAJOR shape change)**: hosted mode keeps no ledger, so `records` lists the hosted pins lockfile discovery finds (one per `(purl, uuid)`, the same discovery `vex` uses: a hosted URL counts only on `https://patch.socket.dev` or the `--patch-server-url` origin), and the v4 `ledger` and `records[].ledgerKey` keys are gone. Each record's `purl` is CANONICALIZED (qualifiers stripped, percent-decoded — e.g. `pkg:npm/@scope/pkg@1.0.0`, `pkg:gem/nokogiri@1.13.3`) to the same spelling `wiringLive` carries, so the join is a plain string compare. `wiringLive` is the subset of those pins among this run's *counted* purls (post-`--ecosystems`-filter) — computed once per run, the same set that feeds `hosted_wiring_retained`. A record missing from `wiringLive` is still wired; it just was not crawled/queried this run (an `--ecosystems` filter, a zero discovery). The key is omitted when no lockfile pins a hosted patch (and under `--global`), and error envelopes (the `--offline` refusal, all-batches-failed) are deliberately minimal and never carry it. A pre-v5 `.socket/vendor/redirect-state.json` is not read. Hosted-mode runs carry the `redirect` sub-object instead (the run's own result), and vendored-mode runs carry the takeover warnings (their takeovers may restore pins mid-run) — neither duplicates a pre-run snapshot that could go stale.

**Agent-flow run-level warnings (additive).** An agent-mode apply (`--mode agent` / `--apply` / `--sync`, `--json`) may add a top-level `warnings[]` array of `{code, detail}` entries to the scan envelope (absent when none fired; each is also mirrored to stderr unless `--silent`). They surface cross-mode state the apply cannot change — never a status or exit-code change (hosted refusals set the precedent: exit 0 + warning). Codes (stable; new codes are additive/MINOR): `vendored_ownership_retained` — vendor-owned package(s) were skipped before download (the per-patch `skipped`/`vendored` records in `apply.patches[]` are unchanged); the detail names the purls and the migration path (`remove <purl>`, or `vendor --revert` which unwinds every vendored package, then re-run). `hosted_wiring_retained` — the lockfiles still pin scanned package(s) to a hosted patch (the agent run does not unwind hosted wiring — as of v5.0 that is `socket-patch rollback`'s job, which restores the upstream registry entries, or `remove <purl>` per package); the detail names the purls and the options (stay `--mode hosted`, migrate via `scan --mode vendored`, or `socket-patch rollback`). The warning keys on the hosted pins lockfile discovery finds at scan time, so a flow that restored the upstream entries retires it. The human path prints the same `hosted_wiring_retained` text to stderr after an apply; the vendored counterpart is already covered by its per-package `[skip] … (vendored …)` lines. `ownership_not_restored` (v5.0; `apply` and `rollback` `warnings[]` alike) — a file WAS patched (or restored) but its ownership could not be put back to the original uid/gid (the mode is still restored last); the detail is `<purl>: <path>: patched, but ownership could not be restored to uid N gid M: <error>` and the human line `Warning: <detail>` (stderr, muted by `--silent`); never a status or exit change.

`scan --prune` opts into garbage collection. When set, `scan` removes manifest entries for packages no longer present in the crawl, then deletes orphan blob files, and every obsolete diff and package archive, from `.socket/`. Off by default (v3.0) so a temporary uninstall doesn't silently destroy manifest state. Only entries whose ecosystem this run actually crawled are eligible: a `pkg:<type>/` with no crawler in this build (a newer CLI's ecosystem in the committed manifest) is exempt — the crawl never looked for them, so their absence is not evidence of removal (same fail-safe as the `--ecosystems` filter, which narrows the query but never the prune's installed set). The pass also reconciles vendored state (runs FIRST, under ONE apply-lock acquisition shared with the manifest prune — lock contention skips the whole pass without failing the scan; `--lock-timeout` is honored and a lock I/O error is reported rather than swallowed; the existence gate — a manifest file OR a vendor ledger file, both cheap stats; an emptied ledger is deleted on save, so its presence is its content proxy — runs BEFORE the lock, so a bare project never gets a `.socket/`; in the vendored scan arms the pass runs AFTER the vendor step): (a) ledger entries still tracked by a manifest record (manifest-mode entries written by standalone `vendor`) whose patch is gone from the manifest are reverted — `detached` entries (every `scan`/`get --mode vendored` entry, v5.0) have no manifest record to lose and are exempt from this leg; (b) EVERY ledger entry whose dependency is no longer in the lockfile graph is reverted and any manifest entry it still had dropped (v5.0: the check is about the lockfile, not the manifest, so embedded-record entries are no longer exempt; a missing or undeterminable lockfile keeps the entry, fail-safe); and (c) orphan `.socket/vendor/<eco>/<uuid>` dirs with no ledger entry are swept. The prune never deletes a zero-patch `.socket/manifest.json` (its `{"patches": {}}` + `setup` block stay). The JSON `gc` sub-object gains `revertedVendoredEntries` + `keptVendoredEntries` + `failedVendoredEntries` + `removedVendorOrphanDirs` (wet) / `revertableVendoredEntries` + `vendorOrphanDirs` (preview), plus two ADDITIVE wet-only keys: `skipped: {code, message}` — present exactly when the pass was skipped at the lock (`lock_held` | `lock_io`; every count is then zero) — and `warnings: [{code, detail}]` — `vendor_state_write_failed` / `manifest_write_failed` (entries were reverted but the ledger or manifest rewrite failed) and `cleanup_failed` (an orphan sweep failed mid-way). Human mode prints `GC: skipped (<code>): <message>.`, one `GC: <detail>.` line per warning, and `GC: failed to revert N vendored entries: …` (singular for one) for `failedVendoredEntries`. `keptVendoredEntries` lists drift-kept entries the revert deliberately preserved (`vendor_artifact_kept` — undo the drift and re-run `vendor --revert` to finish); the preview cannot see drift (backends return before the wiring replay on dry runs), so `revertableVendoredEntries` may over-promise what a wet run will actually reclaim.

`scan` queries the patch API in `--batch-size` chunks. Authenticated runs POST `/v0/orgs/{slug}/patches/batch`; token-less runs POST `{proxy}/patch/batch` on the public proxy and degrade to per-package `GET /patch/by-package/:purl` requests in two cases: the deployed proxy predates the batch endpoint (legacy proxies answer the POST with their `400 "Unsupported endpoint"` catch-all), or the all-or-nothing batch validation rejects the chunk (e.g. a crawled PURL type the server doesn't recognize, such as `pkg:jsr/…` — the per-package path tolerates those individually, preserving the pre-batch scan semantics). Rate limits and over-capacity 503s surface instead of silently degrading.

**Throttling: bounded retry, then a reported failure.** Every patch-API JSON call (the batch query, the per-package patch lists, patch views and VEX record fetches, hosted package references) retries an HTTP `429` or `503` answer up to 3 times (`SOCKET_API_MAX_RETRIES=<n>`, `0`-`10`; `0` = no retry). The wait honors `Retry-After` (delta-seconds or HTTP-date); a `Retry-After` over 30 s is not waited out — the answer is final at once — and one under the jittered first backoff step (`0`, a past date) waits that step instead. Without one it backs off 0.5 s / 1 s / 2 s (each step up to 8 s, with jitter in its upper half). All retries in one run share a 60 s wall-clock window that opens with the run's first retry: a retry whose wait would end after it closes is refused and the answer is final. Parallel requests wait in parallel, so each still gets its retries while the run adds at most about 60 s. Nothing else is retried (401/403 still drive the proxy fallback on the first answer; the public proxy's permanent `503 "Patch API is not configured"` is never retried on any path — the batch query still degrades to the per-package path at once, and a per-package lookup or patch view answering it is the same non-throttle failure it always was, so the legacy per-package path still skips that package), and a retried answer folds exactly where the first attempt's would have, so output is identical to an unthrottled run's. A request still throttled after that is a failure in the channel its siblings use: a failed batch is the human `Warning: API batch <n> of <total> failed: <error>` line and, under `--json`, a run-level `warnings[]` entry `{code: "api_batch_failed", detail: "API batch <n> of <total> failed: <error>"}` (additive; `status` stays `success`, exit 0 — the other batches' packages are reported); a failed per-package patch-list query in the agent / hosted / vendored flows is the human `Warning: could not fetch details for <purl>: <error>` line and, under `--json`, `{code: "patch_details_failed", detail: "could not fetch details for <purl>: <error>"}`. When every batch (or every patch-list query) fails, the existing all-failed error envelope and exit 1 apply. The error names the exhausted retry: `Rate limit exceeded (HTTP 429, gave up after 3 retries). Please try again later.` / `API request failed with status 503: <body> (gave up after 3 retries)` (or `(Retry-After <n> s exceeds the 30 s retry cap)` / `(the run's 60 s retry window has closed)`); with retries off it is the pre-retry text. On the token-less legacy per-package proxy path (a proxy without `POST /patch/batch`), a package still throttled (429 / over-capacity 503) after its retries fails its whole batch query, so every package in that batch goes unchecked and is reported through the batch-failure channel above (an unresolvable PURL, or a "not configured" 503, is still skipped individually). Pinned by `tests/scan_api_retry_e2e.rs` and the core crate's `tests/api_retry_e2e.rs`.

**Lockfile supplement (v3.4)**: `scan` discovery is no longer limited to installed trees. The project's lockfiles (`package-lock.json`/`npm-shrinkwrap.json`, `pnpm-lock.yaml` v9, `yarn.lock` classic + berry, `bun.lock`, `vlt-lock.json` (registry nodes, Socket-hosted pins included; vendored `file` nodes are left to the vendor ledger), `Cargo.lock`, `go.sum`, `composer.lock`, `Gemfile.lock`, `uv.lock`/`poetry.lock`/pinned `requirements.txt`) are inventoried and dependencies with NO installed copy join discovery — counts, the API lookup, the table (flagged ` [NOT INSTALLED]`, plus a stderr note), and the prune "scanned" set (a wiped node_modules no longer prunes lockfile-listed entries). JSON gains a top-level `lockfileOnlyPackages` count and an additive `notInstalled: true` on matching `packages[]` entries. `--apply` partitions lockfile-only patches out BEFORE download (calm `skipped`/`package_not_installed` records — never an error exit, never a manifest write); `--vendor` passes them through to the vendor engine's server download. Vendored-ledger entries likewise stay discoverable on a fresh clone (the committed artifact is the dependency). Global scans (`--global`) get no supplement. **Rush monorepos** (no root lockfile, `rush.json` present): the npm-lock inventory falls back to the Rush source-of-truth locks — `common/config/rush/pnpm-lock.yaml` plus every `common/config/subspaces/*/pnpm-lock.yaml` (`read_dir`-sorted, repo-relative paths preserved) — so a Rush repo's dependencies still join discovery. **Plug'n'Play layouts are an explicit refusal, not an empty inventory**: a `.pnp.*` loader means the npm packages are structurally unreachable in EVERY mode (under yarn PnP the installed-tree crawl is empty too — no `node_modules/`), so `scan` surfaces an additive top-level `warnings[]` array (`{code, detail}` objects, omitted when empty) carrying `yarn_pnp_unsupported` (same code as apply's refusal; remedy `yarn patch <pkg>`) or `pnpm_pnp_unsupported` (pnpm's `node-linker=pnp` twin; pnpm remedies), plus a stderr `Warning: …` line on the human path. Exit code and `status` are deliberately unchanged (exit 0 / `success` — the same posture as hosted refusals, which exit 0 with `redirected: 0`); the warning is the machine-readable signal that nothing was checked. Pinned by `tests/e2e_safety_yarn_pnp.rs`.

**Server artifact acquisition (v5.0)**: vendoring downloads the patched artifact for the selected UUID, including on a fresh checkout with no installed package. The CLI no longer downloads pristine packages, stages patch blobs, applies patches to vendor copies, or constructs archives. Backend lock and package-identity checks still run before acquisition; git and custom-registry Cargo sources are refused with `vendor_source_unsupported`. Healthy committed artifacts are reused offline. A changed UUID downloads a fresh server artifact; an unhealthy artifact at the recorded UUID uses the exact redownload procedure below, except that a directory copy whose ledger entry has no file inventory (vendored before v5.0) is rebuilt by its backend from a fresh verified download, and a missing or stale Bun workspace mirror over a healthy canonical tarball is rewritten from that tarball by the backend; those cases report the backend's own failure codes.

**Vendored write durability (v5.0)**: every write is atomic (stage + rename), but only the durable commit points — lockfiles, `go.mod`/`go.sum`, `pom.xml`, `nuget.config`, `package.json`, `pnpm-workspace.yaml`, `.cargo/config.toml`, the Python/Ruby manifests, `.socket/vendor/state.json` and `redirect-state.json` — are fsynced on write. The content-verified artifacts under `.socket/vendor/<eco>/<uuid>/` (patched copies, packed/rebuilt archives and sidecars, markers) are written without an fsync and made durable by one barrier (file + directory fsync, one `F_FULLFSYNC` per device on macOS) ahead of the next commit point — and, for an artifact rebuilt in place that no commit point follows, at the end of the vendored run's commit and when the command releases the apply lock — so a crash can only lose an artifact that no durable commit point names yet, which the next run redownloads.

**Vendored group commit (v5.0)**: `vendor`, `scan --mode vendored` and `get --mode vendored` capture every lockfile / manifest / config edit and every ledger save of the run in memory (reads inside the run see them) and commit them ONCE after the per-package loop — including the packages that succeeded in a run where others failed, so a completed run leaves the same files per-package commits would. Captured: every file under the project root outside `.socket/`, plus `.socket/vendor/state.json` and `.socket/vendor/redirect-state.json`; artifacts are written directly (see the durability note). A multi-file commit goes through a roll-forward journal, `.socket/vendor/.commit-journal.json` (the new bytes of every changed file, plus the bytes each replaces and their sha256; deleted once the commit completes). **Crash semantics**: before the journal is durable, nothing is committed — the lockfiles and ledgers are the pre-run ones and the run's artifacts are unreferenced orphans; after it, the next command that takes the apply lock replays the journal before reading anything (files already at their new bytes are left alone), so a locked command never observes a half-committed run. A journal that matches neither side of some file (edited by hand since the crash) is renamed to `.socket/vendor/.commit-journal.set-aside-<uuid>.json` (keeping every file's pre-commit bytes) and stderr says what was done (`Warning: an interrupted vendored run's commit could not be finished as written: …`): the edited files are never written over; when they all still carry the commit's own lines the rest of the commit is finished around them, when none of them does the files the crash had already replaced are put back to their pre-commit bytes, and otherwise nothing is applied. A journal that is unreadable, names a path outside the lockfiles and ledgers, or would write through a symbolic link is set aside with nothing applied. A replay that fails on I/O keeps the journal and fails the lock acquire (`lock_io`, naming the journal). Read-only commands that take no lock (`vex`, `list`) may observe the interrupted state until then. A re-vendor under a newer uuid removes the replaced uuid's dir only after the commit (its `vendor_stale_artifact_removed` event follows the run's per-package events), and a golang takeover removes the `.socket/go-patches/` copy only after the commit that repoints `go.mod`. A commit never renames over a symbolic link: when a changed file is a symlink, the whole commit is refused before anything is written, with the top-level error `redirect_symlinked_file_unsupported` (exit 1; a `--dry-run` predicts it with a `vendor_would_refuse_symlinked_file` advisory). A commit write failure is the top-level error `vendor_commit_failed` (exit 1; the pre-run lockfiles and ledger stay — unless putting back the files already replaced failed too, in which case the journal is kept and the next locked command finishes the commit). `repair`, `vendor --revert` and `rollback` still save per entry.

`scan --sync` is sugar for `--mode agent --prune` — the canonical single-flag agent-mode bot invocation. `scan --json --sync` discovers, applies, and reconciles state in one pass.

**`scan --ecosystems` scopes the crawl (v5.0)**: without `--prune`/`--sync`, a `scan` given `--ecosystems`/`-e` runs only the named ecosystems' crawlers — everything the run counts, queries and shows (`scannedPackages`, the batch query, `packages[]`, the table, `updates[]`, `wiringLive`, the `gem_bundle_config_path_ignored` warning) was already narrowed to them, so the skipped crawls could only be filtered away. The one visible difference: `lockfileOnlyPackages` (and the human "not yet installed" note) counts only the selected ecosystems' lockfile-only entries (a skipped crawl cannot vouch for another ecosystem's uninstalled lockfile entries). A GC run (`--prune`, or `--sync`, which implies it — in every mode, hosted included) still crawls every ecosystem, because the prune judges each manifest entry against the FULL installed set (see `scan --prune` above); its output, `lockfileOnlyPackages` included, is unchanged. Without `--ecosystems` nothing changes. Pinned by `tests/scan/scan_ecosystems_scope_e2e.rs`.

**Path-scoped scans (`scan [PATHS]...`, v5.0)**: what a PATH means depends on the mode.

* **Hosted and vendored mode (bare `scan` included) — project directories** (`run_project_dirs`). Each PATH is a directory, or a glob (`*?[`) matching directories, relative to `--cwd`; the set is sorted and deduplicated, and each directory is scanned on its own exactly as if it were `--cwd` (its own lockfiles, ledgers and `.socket/`). With more than one directory, each run is headed `== <dir> ==` on stdout (unless `--silent`), and the exit code is the worst of the runs. Usage errors (exit 2, stderr only, before any scan): a PATH that is not a directory (`` `X` is not a directory``), a glob matching no directory (`` `X` matches no directory``), an invalid glob, and `--json` with more than one directory (`--json takes one project directory (N given); run one scan per directory`), so stdout stays one document. Likewise `--vex` with more than one directory (`--vex takes one project directory (N given); run one scan per directory`): the one output path would be overwritten by each run.
* **Agent mode (and a mode-less `--prune`/`--global` report) — installed-path globs** scoping DISCOVERY at the **purl level**: a package is in scope iff ANY of its crawled installed copies sits under a matching path, and a selected package is then handled with ALL its copies (scoping selects which packages are considered, never which copies). Glob semantics (shared with `rollback`'s path targets, `src/path_scope.rs`): Unix-shell globs with `require_literal_separator` — `*`/`?` never cross a `/`, `**` spans directories; a pattern matching any **ancestor** directory of the copy path also matches, so a bare `scan packages/foo` scopes the whole subtree without `/**`; relative patterns match against the copy path relativized to `--cwd`, absolute patterns against the absolute path (the ONLY way to reach paths outside the project tree, e.g. `--global` stores — a relative pattern never matches outside `--cwd`); leading `./` and trailing `/` are normalized away, matching is purely textual (no filesystem access or symlink resolution), case-sensitive except on Windows (whose filesystems are not); an unparseable or empty pattern is a usage error (exit 2). **The prune universe is never narrowed**: the path filter is applied strictly AFTER the `scanned_purls` capture (and after `--ecosystems`), so `scan PATHS --prune` prunes exactly what an unscoped `scan --prune` would — a scoped scan can never treat an out-of-scope package as uninstalled (the same fail-safe as the `--ecosystems` filter). Lockfile-only and vendor-ledger supplement records have no installed path and are EXCLUDED from a path-scoped scan, surfaced as one run-level `path_scope_excluded_supplements` warning carrying the count. A scope matching nothing is a normal empty scan — exit 0, zero packages, **no GC** (the zero-package early return fires before any GC). `PATHS` combine with `--apply`/`--sync`/`--prune`/`--global`. Every scan JSON shape (success, zero-package, and error alike) carries an always-present `paths` key echoing the patterns verbatim (empty array when unscoped; a hosted/vendored per-directory run is unscoped, so it is `[]`). One-sentence duality rule: **a target that selects nothing is an error on `rollback` (exit 1) and an empty scan on an agent-mode `scan` (exit 0)**.

`scan --vendor` swaps the in-place apply for the vendor pipeline: discover → download the selected patch records **into memory** (no manifest write) → vendor every selected dependency via the same engine as the `vendor` command (under the same lock). Vendored mode is **manifest-free (v5.0)**: `.socket/manifest.json` is never written or read by a vendored run; each ledger entry carries `detached: true` plus an embedded copy of the patch record (`record`) as its verification source, and the run's footprint is `.socket/vendor/**` only. The vendor step's scope is what discovery selected — the former "whole manifest is vendored" re-vendor on an empty discovery is retired (`repair` verifies and redownloads committed vendored state; `scan --prune` reconciles ledger entries whose dependency left the lockfile). The vendor-ledger discovery supplement (the fresh-clone rule: a ledger entry with no installed copy stays discoverable because its committed artifact IS the dependency) holds only while the lockfile still resolves through that artifact: an entry the lockfile in-use probe (the one `--prune` reverts by) proves unwired, because the dependency was upgraded or removed, is NOT discovered and so is never re-vendored. A run without a non-hosted `--prune` reports it through the run-level `vendor_ledger_entry_unwired` warning; a `--prune` run reverts it in its GC and exits 0. That GC runs even when the crawl found no packages, as its vendored half alone (the manifest prune stays skipped there). A package the ledger holds at an older patch uuid is still **re-vendored automatically** when discovery selects the newer patch (its old uuid dir is removed — `vendor_stale_artifact_removed`); same-uuid re-runs reuse the embedded record, skip the patch-view fetch, and are `already_vendored` skips. **Legacy manifest-mode entries**: when a vendored run vendors a purl that also has a `.socket/manifest.json` record (a project vendored by a pre-5.0 binary, or by standalone `vendor` from an agent-mode manifest), that manifest record is dropped in the same run — the ledger becomes the owner (migration write); an emptied manifest is left as `{"patches": {}}`, never deleted. The migration is reported through the run-level `warnings[]` (stderr in human mode), never as a run error: `vendor_manifest_record_migrated` (`N manifest records moved to the vendor ledger (vendored mode is manifest-free): <purls>`) or `vendor_manifest_migration_failed` (the manifest or the ledger could not be read or rewritten; the legacy records were left in place) — so a corrupt `.socket/manifest.json` no longer fails a vendored run (standalone `vendor`, the one manifest-driven writer, still fails closed on it). With `--prune`, GC runs **after** the vendor step (the step never reads the manifest, and running the sweep last lets it reclaim what the run itself orphaned — a migrated legacy record's blobs, a superseded uuid dir). JSON output gains a `download` sub-object — the detached download envelope `{found, downloaded, skipped, failed, detached: true, patches: [{purl, uuid, action: "downloaded" | "skipped" | "failed", …}], warnings?}` (no `applied` field — nothing is applied in place; `detached: true` is pinned and always present; a `downloaded` record whose purl the ledger already holds at another uuid carries the additive `oldUuid` — the re-vendor the vendor step then performs — and its human `[fetch]` line reads `<purl> (replacing <short uuid>)`) — and a `vendor` sub-object (a full vendor Envelope). Patch blobs are held in memory (see "Patch sources stay in memory" under the vendor contract). `--dry-run` previews per-patch `would_vendor` | `would_revendor` (+`oldUuid`) | `already_vendored` — plus, additive, `would_refuse` (+`errorCode`, `error`) for npm purls the wet run's Bun preflight (see the `get --mode vendored` bullet below) would refuse — without network downloads or disk writes; the preview never flips status or exit (the human path — `scan` and `get` alike, through one shared printer — prints `[would-refuse] <purl> (<code>): <detail>` lines behind the `--silent` gate). Interactive mode prompts "Download and vendor N patches?" (singular for one).

**Vendored entries and the rest of the CLI.** Because nothing is in the manifest, vendored patches are invisible to `apply` (nothing to apply in place) but fully visible to `list` (listed from the ledger, labeled `Mode: vendored (recorded in .socket/vendor/state.json)` in human mode, exit 0 on a vendored-only project), `vex` (attested from the embedded records while a lockfile still wires the artifact — see "Manifest-less VEX"), `repair` (health-checked and rebuilt from the ledger), and `scan --prune` (lockfile-driven reconcile). They are exempt from standalone `vendor`'s manifest reconcile (`reconcile_dropped` never touches `detached` entries) and exit via `remove <purl>` (which reverts them), `vendor --revert`, or `rollback`, whose vendored leg reverts every in-scope ledger entry (unscoped and identifier-scoped runs; path-scoped runs reach them only when an installed copy matches).

`scan --mode hosted` swaps the in-place apply for the registry-redirect pipeline: discover → resolve hosted-patch references (grant token + integrity + per-dep registry override) → rewrite ONLY the patched dependencies' lockfile / registry-config entries to point at the hosted packages. A dep counts as **redirected** only when its hosted-artifact URL (or per-dep registry index URL) actually landed in a project file — a granted reference whose rewriter found nothing to edit is neither counted nor attested. **No ledger (v5.0)**: hosted mode writes ONLY the lockfile / registry-config edits — `.socket/vendor/redirect-state.json` is never written (on success or failure), and a pre-v5 one on disk is ignored (never read for planning, never quarantined, left byte-identical). The lockfiles are the only record of a hosted patch: `list`, `vex`, `rollback`, `remove`, `vendor` and `repair` all discover the hosted pins from them (a hosted URL counts only on `https://patch.socket.dev` or the `--patch-server-url` / `SOCKET_PATCH_SERVER_URL` origin), and commit-ready output is just the lockfile / config changes. Cargo and golang are confirmed only by their rewriter's own report (`confirmed_cargo_uuids` / `confirmed_golang_uuids`): a golang dep counts only when its go.mod `replace M V => patch.socket.dev/gopatch/<uuid> <sver>` and both go.sum lines are in place, never because the patch-server origin or leftover go.sum lines appear somewhere. Gradle is confirmed the same way (`confirmed_gradle_uuids`): only when the final files hold the owned script, the index row, the live apply line in every build's settings file and the suffixed version in every lock entry of the GA (see [Gradle builds](#gradle-builds-v50)). A golang module that go.mod does not require and go.sum does not list at the patched version is outside the build graph and is refused with `redirect_golang_not_in_module_graph` (nothing written). Only the exact module `patch.socket.dev/gopatch/<canonical uuid>` is socket-owned; any other module path is refused with `redirect_golang_untrusted_module_path`. A vendored golang module is taken over like cargo and the npm family: its vendor wiring, committed copy and ledger entry are reverted first (`redirect_takeover_reverted_vendored`). A vendored PyPI package (requirements.txt, Poetry, Pipenv, uv, Hatch, PDM, pylock) is taken over the same way: its vendored wiring is restored to the recorded registry entry, its ledger entry and wheel are removed, and only then is it redirected. The Python rewriters treat any non-registry source as user-authored, so without the revert they refused socket-patch's own vendored source and left the project vendored. A takeover revert that leaves vendored wiring in place is refused with `redirect_vendored_revert_failed`. That covers a drift-skipped record (`vendor_lock_entry_drifted`) and a reverted file that still references the artifact (`vendor_revert_residual_reference`). The ledger entry and artifact are kept, and the package stays vendored and skipped. `--dry-run` predicts the same refusal from the same signals instead of previewing `redirect_would_revert_vendored`. The hosted requirements.txt rewriter only rewrites an existing pin in the root `requirements.txt`, so a vendored requirements.txt package whose wiring is a pin in a `-r` include or a `(transitive)` line vendored mode appended is refused BEFORE its revert, wet and `--dry-run` alike, with `redirect_requirements_takeover_unreachable` (`redirect.warnings[]`, and `redirect.skipped[].reason`). Its wiring, ledger entry and wheel are kept, so it stays vendored and patched (exit 0). The uv and Poetry rewriters are gated the same way, from the ledger entry and the lock on disk: a vendored uv package whose recorded pre-vendor `uv.lock` entry is at another version than the patch (vendored uv pins the entry down to the patch's version; the revert brings the lock's own version back, and hosted mode only pins the version the lock resolves) is refused with `redirect_uv_takeover_version_unreachable`, and a vendored Poetry package on a Poetry 0.x lock (which hosted mode refuses outright) is refused with `redirect_poetry_lock_unsupported`. A taken-over package whose wiring was reverted but that was then not pinned to hosted now installs the unpatched registry release in both modes. Causes include a refused lock, unavailable hosted wheel metadata, or a vendored ledger update that failed after the revert (refused with `redirect_vendored_revert_failed`). It is reported as `redirect_takeover_unpatched` with `status: "partial_failure"` and exit 1, never as success. That warning also prints under `--silent`. Human output prints no `Migrated …` progress line for the package and no "keep the hosted patches" next steps. Re-runs over already-rewritten output plan from the current lock text and are idempotent (exit 0, lock unchanged). **Lock (v5.0)**: the hosted engine acquires `<.socket>/apply.lock` around its first wet write (the takeover pre-reverts) — not on `--dry-run`, and not when the run would write nothing (zero redirects, all skipped) — so previews and no-op runs never create `.socket/`; contention is `lock_held` and a lock-file I/O fault (a read-only project root, a file squatting on `.socket/`) is `lock_io` — both exit 1, refused BEFORE any project file is written, and rendered like every other lock holder: human `Error (<code>): <message>` on stderr (+ the `--lock-timeout` hint for a live holder); JSON keeps the hosted shape — top-level `status: "error"`, `errorCode: "lock_held" | "lock_io"`, a string `error`, and `redirect: {mode: "hosted"}` retained (NOT the vendored `error: {code, message}` object). **Takeover symlink pre-check (v5.0)**: a vendored→hosted takeover whose recorded wiring file is a symlink is refused up front with `redirect_symlinked_file_unsupported` — wet and `--dry-run` alike, before any revert — so "nothing was written" holds. **Human mode (v5.0)**: hosted `scan` prints the results table and update detection like the other modes, then rewrites without a prompt (scan never prompts); `--dry-run` previews through the engine, and a detail fetch that leaves nothing to redirect enters the engine as a no-op (`Redirected 0 packages; rewrote 0 files.`, no lock, no `.socket/`). The detail fetch prints the same progress counter and per-package `Warning: could not fetch details for …` lines as the agent arm. An EMPTY hosted discovery prints `No patches available for installed packages.` and exits 0 without entering the engine; a discovery whose every offer is paid-tier for an org without paid access prints the table's paid nudge, then `No downloadable patches (paid subscription required).`, and exits 0 without entering the engine (parity with the agent/vendored arms). JSON output gains a `redirect` sub-object: `{ mode: "hosted", redirected, rewrittenFiles, skipped, patches, warnings, dryRun }` (`mode` is additive so consumers can dispatch without inferring it). `patches` (additive, v5.0) is the per-purl outcome of every selected patch, sorted by purl: `{purl, uuid, action}` with `action` `pinned` (`would_pin` under `--dry-run`; `redirected` counts these), `skipped` (`errorCode` = the `skipped[]` reason, `error` = its detail when it has one), or `unpinned` (`errorCode: redirect_unconfirmed` — the patch was granted but no lockfile entry pinning it could be rewritten; the human output's `Not hosted <purl>: …` line). An `unpinned` or `skipped` row does not change `status` or the exit code (the hosted exit policy is an open decision, #704). Rewriter warnings carry stable `redirect_*` codes (e.g. `redirect_npm_no_lockfile`, `redirect_gradle_manual_snippet`, `redirect_golang_unsupported`); new codes are additive (MINOR). v5.0 additive codes: `redirect_composer_no_lockfile` / `redirect_gem_no_gemfile` (composer / gem: neither manifest nor lock present — once per run, after the intake gates), `redirect_gem_bundle_gemfile_unsupported` (gem: `BUNDLE_GEMFILE` — `BUNDLE_GEMFILE:` in the bundler app config, which outranks the environment variable as in `Bundler::Settings`, else the environment variable — names a manifest other than the project's `Gemfile` / `gems.rb`, so no gem is redirected or attested; a value naming one of those two selects that pair even when the other spelling is present), `redirect_gem_mirror_overrides_source` (gem: Bundler's all-source, exact patch-source or patch-hostname mirror can route the per-dep `source` block to an unpatched upstream gem. Intake reads the app config (`BUNDLE_APP_CONFIG`, where a set-but-empty value selects `<root>/config`, honoring `BUNDLE_IGNORE_CONFIG`) and all `BUNDLE_MIRROR__...` variables visible to the scan; app config overrides the environment per encoded key, then `mirror.all` takes precedence over exact source, which takes precedence over hostname. URI matching follows Bundler's whole-URI case folding, default-port/trailing-slash normalization and single slash key alias, not URL prefixes. An exact-source fallback-timeout key without a mirror URL shadows the hostname mirror and fetches that source directly; a configured URL is conservatively refused even if a timeout could bypass an unreachable mirror at install time. Like `redirect_gem_bundle_gemfile_unsupported`, the gate leaves the Gemfile pair byte-identical and confirms no gem redirect. On an embedded `scan --vex`, rediscovered older hosted gem pins may attest only from verified installed bytes: a missing tree is not excused by the lockfile, and `--vex-no-verify` omits those hosted gems with `mirror_overrides_source` rather than trusting their intercepted source. Agent/vendored evidence, unrelated ecosystems and standalone VEX behavior are unchanged. Details identify the setting form and its app/environment origin without printing mirror values or source URLs, which may contain credentials. Remove the applicable all/source/hostname setting (including any slash alias) from that origin and reuse its existing mirror URL under `mirror.https://rubygems.org` to clear the refusal; an environment setting must be unset in the scan/install environment. User-global Bundler config and mirrors set only in a later install environment are not inspected; keep those mirrors scoped to the upstream source too), `redirect_maven_no_pom` (no `pom.xml` and no Gradle build), `redirect_nuget_lock_unparseable` (a present-but-corrupt `packages.lock.json` — warned once, nothing mutated; an absent lock still proceeds), `redirect_cargo_lock_pkg_ambiguous` (several same-name+version `[[package]]` blocks and none carries the index `source` — transactional skip). Also additive: `redirect_gem_version_not_locked` (gem: no `GEM` section of the lock lists the crawled `name (version)`, for example a version another project installed into the shared gem home; the gem is skipped with nothing written, so the user's declared constraint and the locked version are never overwritten). Also v5.0: a registry override of the wrong kind (or none at all) warns the arm's missing-override code for nuget/gem/golang. Refusals stay fail-closed with a diagnosis that names the actual cause: a yarn-berry lock entry resolving through a non-`npm:` protocol keeps `redirect_yarn_berry_unsupported_protocol` with the entry's ACTUAL protocol in the detail — except socket-patch's OWN vendored wiring (a `file:` range into `.socket/vendor/`), which gets the distinct `redirect_yarn_berry_vendored_entry` code whose detail names the retirement path (`remove <purl>` per package, or `vendor --revert` which unwinds every vendored package, then re-run `scan --mode hosted`). Both leave the entry byte-identical; neither changes exit code or status. **yarn berry line endings (v5.0)**: yarn writes a NEW `yarn.lock` with the OS line ending (`os.EOL` — CRLF on Windows) and keeps an existing lock's majority ending on every later write, and a `core.autocrlf` checkout turns an LF lock CRLF on any OS — so a uniformly CRLF lock is rewritten in its own ending: every untouched byte (a leading BOM included) round-trips (and `rollback`'s upstream restore keeps the lock's own ending). A lock that MIXES CRLF and LF (or holds a bare CR) has no single ending to keep — yarn's own `--immutable` check rejects it too (YN0028) — so it is refused untouched with `redirect_yarn_berry_mixed_line_endings` (the detail names `yarn install`, which normalizes it). The root `package.json`, which the rewrite re-renders to add `resolutions`, gets the same gate: a mixed one is refused untouched with the same code — the decision vendored mode takes with `vendor_yarn_berry_mixed_line_endings`, from the same shared berry gate set. This replaces v4's `redirect_yarn_berry_crlf_unsupported`, which refused every CRLF lock and is no longer emitted. A vendored→hosted takeover runs these berry gates (mixed line endings, unsupported `cacheKey`, a non-zero `.yarnrc.yml` `compressionLevel`) BEFORE reverting a vendored berry purl — wet and `--dry-run` alike — so a refused purl keeps its vendored wiring, ledger entry and artifact byte-identical and is skipped with the gate's code (never announced as `redirect_takeover_reverted_vendored` and then left unpatched in both modes).

The rewriter reads a fixed set of candidate files from the project root: the npm-family locks (`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `shrinkwrap.yaml`, `yarn.lock`, plus `.yarnrc.yml` for the berry cache-config gate, `bun.lock` / `bun.lockb`, and `vlt-lock.json` with `vlt.json` and `node_modules/.vlt-lock.json` read only), `requirements.txt` / `uv.lock` / `Pipfile.lock` (pipfile-spec 6; see the Pipenv section below) / `poetry.lock` (every Poetry lock generation from 1.0 on — the 0.12 `[metadata.hashes]` layout is refused because that installer ignores URL sources; a Poetry < 1.4 writer additionally gets `redirect_poetry_stale_install_risk`, see `docs/testing/poetry-compatibility.md`) / `pdm.lock` (PDM lock formats `2` and `4.3`–`4.5.1`; the identity-losing `3.1` / `4.0`–`4.2` formats and unknown future formats are refused with `redirect_pdm_refused`, and a lock-format-`2` writer additionally gets `redirect_pdm_legacy_sync_required`, see `docs/testing/pdm-compatibility.md`; when `uv.lock` or `poetry.lock` sits beside it they drive and `pdm.lock` is left alone), `Cargo.toml` / `Cargo.lock` / `.cargo/config.toml` (plus the legacy extensionless `.cargo/config` — cargo reads that spelling in preference when both exist, so the managed `[registries.…]` block is written into whichever one is present; **cargo also reads every workspace-member manifest** — the `[workspace] members` globs minus `exclude` — and every in-root path-dependency manifest, recursively, reached without crossing a symbolic link and never under `.socket/`, and pins the crate in each one that declares it, so those `<dir>/Cargo.toml` files can appear in `rewrittenFiles`. A crate is redirected only when every declaration pins and every other `Cargo.lock` package depending on it is a planned member: one a registry or git crate — or a path package outside the root or behind a link — also depends on is refused `redirect_cargo_transitive_dependents` (a pin reaches only the declarations it sits on), a crate no manifest declares keeps `redirect_cargo_toml_dep_not_found` with a transitive-only detail naming `--mode vendored`, a crate every declaration of which requires another version (no requirement accepts the patched version) is refused `redirect_cargo_toml_dep_unrewritable`, and so is a requirement that also matches another locked version of the crate — each a transactional skip, never recorded or attested. With NO `Cargo.lock` there is no resolved graph to ask, so the dependents question is answered from the manifests instead: a crate declared beside any other dependency — anything but a path dependency on a manifest this run also pins, or a `workspace = true` inheritor of a table it scans — or beside a workspace member this run did not read (a `members` glob, or a member outside the project or behind a symbolic link, which member discovery drops) is refused `redirect_cargo_lockless_dependents`, whose detail names the remedies (commit a lockfile, or `--mode vendored`); a project whose only dependency is the patched crate has nothing that could pull it in and still redirects. All-CRLF manifests, locks and configs are rewritten with CRLF kept (mixed endings keep refusing where the grammar does not match), and `remove` / rollback match the recorded fragments across a later CRLF↔LF checkout conversion), `composer.lock`, `nuget.config` / `packages.lock.json`, `Gemfile` / `Gemfile.lock`, `pom.xml` (+ `.mvn/maven.config` / `.mvn/checksums/checksums.sha256` for maven Trusted Checksums merge, and, for a Gradle build, every settings, build, `buildSrc`, included-build, applied and plugin-source script, version catalog and lock file the script graph reaches, plus `gradle/verification-metadata.xml`, `gradle/wrapper/gradle-wrapper.properties` and the owned `.socket/gradle/` files), and the sbt build files (`socket-patch.sbt`, `socket-patch-vendor.sbt`, `build.sbt`, `project/build.properties`, `.sbtopts`, `.jvmopts`; `build.sbt.lock` and the Mill / scala-cli build files `build.mill`, `build.mill.yaml`, `build.sc`, `.mill-version`, `project.scala` for their presence only) — read, never edited; `socket-patch.sbt` is the only sbt file hosted mode writes (see **Hosted sbt** below). **npm-family flavor coverage**: package-lock / npm-shrinkwrap, pnpm (root OR any nested `*/pnpm-lock.yaml`), yarn classic (a yarn 2+ install migrates a v1 `yarn.lock` and drops its pins, so a run whose v1 lock carries a hosted pin warns `redirect_yarn_classic_berry_migration_risk` — the hosted twin of the vendored `yarn_classic_berry_migration_risk` — unless the root `package.json`, read as advisory input, declares `"packageManager": "yarn@1…"`), **yarn berry** (the pin yarn writes for a root `resolutions` entry: the root `package.json` — edited only beside a berry `yarn.lock` — gains one `"<name>@npm:<range>": "<hosted tgz url>"` selector per locked range (`redirect_yarn_berry_resolution` edits), and only that `yarn.lock` entry is re-keyed `"<name>@<hosted tgz url>"` with the same `resolution:` + `yarnBerry10c0` checksum (`redirect_yarn_berry_entry`), moved to yarn's key order; never an `npm:` locator, whose fetcher sends npm registry auth to the patch host, nor a tarball locator under an `npm:` key, which hardened mode rejects (YN0078). An older release's `npm:<v>::__archiveUrl=` pin is still recognized and is re-pinned on the next run; rollback rebuilds the key from the selectors and drops them. Refused, nothing written: a user-authored `resolutions` entry for the package `redirect_yarn_berry_resolutions_conflict`, no root manifest `redirect_yarn_berry_manifest_missing`, a builtin `patch:` entry wrapping the same descriptor `redirect_yarn_berry_shared_descriptor`, an artifact URL yarn cannot fetch as a tarball `redirect_yarn_berry_artifact_url_unsupported`; cacheKey `10c0` and `.yarnrc.yml compressionLevel 0` gated by `redirect_yarn_berry_cache_unsupported`), and **bun** (text `bun.lock` lockfileVersion 0, 1 or 2 — 0 is the `--save-text-lockfile` opt-in lock of Bun 1.1.39–1.1.45, 1 the 1.2–1.3 default, 2 the 1.4+ default; all three emit one `packages` grammar, so the registry 4-tuple → URL 3-tuple rewrite is version-independent and the lock's own version line is kept. Any other or missing version, or a `packages` section outside bun's single-line grammar, is refused `redirect_bun_lock_unsupported` — the detail is the shared version gate's text (a newer version: update socket-patch, re-locking would reproduce it; no integer: re-lock with Bun ≥ 1.2), identical to the vendored refusal. A version-0 lock holding `workspace:` packages is refused `redirect_bun_workspace_unsupported` (its 2-tuple workspace grammar cannot keep the hosted tuple through a frozen install); the remedy is to delete `bun.lock` and re-run `bun install` with Bun ≥ 1.2, which writes lockfileVersion 1 (accepted). A plain in-place `bun install` bumps the version only when a workspace depends on another workspace (e.g. root → member — the shape the matrix measured); otherwise Bun 1.2.0 keeps version 0 and Bun 1.2.23+ fail to resolve, so the in-place bump is not the documented remedy. Bun lock version, grammar and workspace compatibility are checked before a vendored takeover, including during dry-run: these refusals preserve the existing lock, artifact and vendor ledger. Version-1 and version-2 workspace locks are rewritten, nested versions included. A granted dep with no rewritable entry warns `redirect_bun_entry_not_found`, a grant without a sha512 `redirect_bun_missing_sha512`; a CRLF lock keeps `\r\n` on the rewritten line, and a hosted URL left by an earlier grant of the same `name@version` is re-pinned in place. **Digest-less re-saves (Bun 1.1.39–1.3.9)**: every text-lock Bun below 1.3.10 re-saves a URL tuple WITHOUT its `sha512` whenever the lock is re-saved for another reason (`bun add`, `bun install` after a package.json or workspace change), leaving the 2-tuple `["name@<url>", {meta}]` — the spec Bun installs from is intact. The CLI treats that spelling as its own wiring: a repeat hosted run counts the dep as redirected (no `redirect_bun_entry_not_found`) and HEALS the line back to the 3-tuple with the current `sha512`, recording the heal as a further `redirect_bun_lock_package` edit whose `original` is the 2-tuple (a stale URL is re-pinned from either spelling); `rollback`, scoped `rollback <purl>` / `remove <purl>` and the vendored takeover accept the digest-less spelling of a recorded `new` line (same key, spec and meta, only the trailing `"sha512-…"` missing) and restore the recorded original over it, so the chain always unwinds to the pristine registry line. Anything else — another uuid/token, another version, a re-laid meta object — is still drift. **Native `bun.lockb`**: when no text `bun.lock` exists, binary format versions 1, 2 and 3 are read and rewritten directly. Socket Patch does not invoke Bun or convert the project to a text lockfile. Exact matching package records are rewritten to hosted tarballs with the granted integrity, preserving dependency resolution IDs, workspace/dependency topology and unrelated package metadata; binary pointers and the package metadata hash are updated. Per-package `redirect_bun_lockb_package` snapshots support scoped rollback, repeat runs, superseding grants and hosted ↔ vendored takeover. A regular binary lock is discoverable even with no Bun runtime or `node_modules`; a dry run previews the same binary edits without writing them. A malformed, unreadable, unsupported or unverified binary structure is `redirect_bun_lockb_invalid` (exit 0, `redirected: 0`), and it refuses the npm rewrite before any takeover or sibling npm-family lock mutation. A symlinked binary write target is `redirect_symlinked_file_unsupported` (exit 1, including dry-run). `bun.lock` wins when both spellings exist. Binary-only projects do not receive `redirect_npm_no_lockfile`. Measured boundaries and the real-Bun matrix: `docs/testing/bun-compatibility.md`), and **vlt** (`vlt-lock.json` without `lockfileVersion`, `0` or `1`; see the vlt hosted-mode contract below). **Rush monorepos**: when `rush.json` is present the rewriter also reads `common/config/rush/pnpm-lock.yaml` and each `common/config/subspaces/<name>/pnpm-lock.yaml` (sorted for determinism) under their repo-relative keys and repoints them in place; editing them emits `redirect_rush_repo_state_stale` when `common/config/rush/repo-state.json` exists (the `pnpmShrinkwrapHash` desync is refreshed by `rush update`, which the redirect survives). **maven** is fail-closed via version suffixing: a `mavenSuffixedVersion` + `mavenPomSha256` override pins the Socket-only `<version>-socket.<hex8>` by rewriting the literal `<version>` (`redirect_maven_dep_version`) or adding a `<dependencyManagement>` entry (`redirect_maven_dep_management_added`), plus optional Trusted Checksums (`redirect_maven_trusted_checksums`, conflicts as `redirect_maven_trusted_checksums_conflict`; when `.mvn/wrapper/maven-wrapper.properties` pins a Maven older than 3.9.4, which ignores those files, the additive warning `redirect_maven_trusted_checksums_unenforced`); a `${property}` version is refused (`redirect_maven_dep_unpinned`), a non-matching literal skipped (`redirect_maven_dep_version_mismatch`), and an override without a suffixed version falls back to same-GAV repository injection (`redirect_maven_same_gav_fallback`, NOT fail-closed). **gradle** (v5.0) is automated wiring, no longer a pasted snippet: the owned settings script `.socket/gradle/socket-patch.hosted.settings.gradle` with its index `.socket/gradle/hosted-index.tsv`, one apply line per build's settings file, every lock entry of the GA moved to the suffixed version, and the suffixed component in an existing `gradle/verification-metadata.xml`. A refused dep writes nothing and keeps `redirect_gradle_manual_snippet` as its fallback; same-GAV grants are refused (`redirect_gradle_same_gav_unsupported`). Rules, refusals and codes: [Gradle builds](#gradle-builds-v50).

**Hosted sbt (v5.0, additive)**: an sbt build root (`project/build.properties` naming an `sbt.version`, 0.13.18 or later) is wired through ONE generated root file, `socket-patch.sbt` — no user file is edited. It pins every granted Maven patch build-wide (a `ThisBuild` `dependencyOverrides +=` of the Socket-only `<base>-socket.<hex8>` version plus a `file:` resolver over `.socket/sbt-hosted/maven2/`, moved ahead of the default repositories on sbt 0.13 / 1.x so an unreachable one never blocks it offline), downloads the pinned pom and jar there on the first sbt load (sha256-checked, gitignored by the file itself), and installs a load-time verifier that fails `update` when any project resolves another version or a pinned artifact whose bytes are not pinned. Edits: `redirect_sbt_pin` (added), `redirect_sbt_pin_updated` (an existing row replaced: same GA and base under a new uuid, or the same uuid with new served values; `original` names the previous uuid and version), `redirect_sbt_pin_rechecked` (an existing row re-verified after the build's dependencies changed: its dependency digest is recorded anew, `original`/`new` are `{deps}`). The load-time verifier also fails `update` when a project declares a pinned GA at a version newer than the pin's base (the build-wide override would otherwise force it back down). A new pin is gated on sbt's own resolution records under `target/` (never the machine-wide cache): run-level stops wire nothing, warn once and exit 0 — `redirect_sbt_no_resolution_evidence` (none; run `sbt update` first; always the in-memory engine's answer), `redirect_sbt_resolution_incomplete` (a declared project left no evidence, or the project definitions cannot be read statically), `redirect_sbt_resolution_stale` (a build source is newer than some project's evidence: each project is dated by its own newest record, so a partial `sbt <proj>/update` does not vouch for the others). Per-patch refusals (never confirmed): `redirect_sbt_missing_override` (no `maven2` override or no suffixed version), `redirect_sbt_integrity_missing` (jar or pom sha256 missing), `redirect_sbt_unsafe_value` (a value unsafe in a Scala literal, or an index URL not naming the uuid), `redirect_sbt_version_conflict` (some project resolves another version, or a build source declares the GA newer than the patch's base), `redirect_sbt_override_conflict` (two patches for one GA in a run, or another base already pinned), `redirect_sbt_vendored_conflict` (the GA is pinned by `socket-patch-vendor.sbt`, or that file cannot be parsed — then every Maven patch), `redirect_sbt_owned_file_modified` / `redirect_sbt_owned_file_foreign` (`socket-patch.sbt` edited, or not socket-patch's — every Maven patch), `redirect_sbt_owned_file_unreadable` (a whole-run refusal: `socket-patch.sbt` is on disk but cannot be read as UTF-8 text, so writing it would replace it; nothing is written), `redirect_sbt_unsupported_version`, `redirect_sbt_build_root_unknown` (sbt files but no versioned build root — every Maven patch), `redirect_sbt_overrides_assignment` / `redirect_sbt_resolvers_assignment` (a build source reassigns `dependencyOverrides` / `resolvers` with `:=`, `~=` or `--=`), `redirect_sbt_dependency_lock_present` (a `build.sbt.lock`), `redirect_sbt_scala_runtime_unsupported` (`org.scala-lang`), `redirect_sbt_classifier_unsupported`; a GA no library configuration resolves is skipped silently (`redirect_sbt_meta_build_only` when only the meta-build resolves it). Advisories: `redirect_sbt_version_untested` (sbt 2.1+, still wired), `redirect_sbt_override_build_repos` (`sbt.override.build.repos=true`), `redirect_maven_pom_ignored_sbt_build` (a `pom.xml` beside the sbt build, which sbt never reads; the Maven rewriter still edits it for the Maven build). A re-run keeps an existing row and re-checks it. When the build's dependency digest changed since the pin, evidence resolved after the change (fresh, newer than the generated file) re-verifies it and the row's digest is refreshed (`redirect_sbt_pin_rechecked`); the uuid is NOT confirmed on `redirect_sbt_pin_declared_newer` (a build source now declares the GA newer than the pin's base; the row stays, sbt's load-time verifier fails the build, and the remedy is `socket-patch rollback` or declaring the base again), `redirect_sbt_pin_unverifiable` (the digest changed and the evidence predates the change, or the digest cannot be computed: run `sbt update`, then re-run socket-patch), `redirect_sbt_override_shadowed` (the evidence still resolves the base version) or `redirect_sbt_resolved_elsewhere` (the pinned version resolves from outside the pin repository from a file whose sha256 is not the pinned jar's; a copy holding the pinned bytes, such as the Ivy cache a second checkout reads, is fine — at most 64 pinned artifact files of up to 256 MiB are hashed, anything else counts as elsewhere), and also when a build source now reassigns `dependencyOverrides` / `resolvers` or a `build.sbt.lock` appeared (the same `redirect_sbt_overrides_assignment` / `redirect_sbt_resolvers_assignment` / `redirect_sbt_dependency_lock_present` codes; the row stays and sbt's load-time verifier fails the build). For a pure sbt root (no `pom.xml` / Gradle script beside it), maven confirmation is decided only by the sbt rewriter's report; on a mixed root a uuid the sbt rewriter refused is still confirmed by the Maven rewriter's own `pom.xml` pin (the generated sbt files never prove a pin by substring). **Mill and scala-cli** are guidance only: per Maven patch `redirect_mill_manual_snippet` / `redirect_scala_cli_manual_snippet` carry a paste-able snippet (repository + forced suffixed version), nothing is written or confirmed, and a pure Mill / scala-cli root gets no `redirect_maven_no_pom`; there, a Maven patch the server sent without a `maven2` registry override gets `redirect_maven_missing_override` instead of a snippet (with a `pom.xml` beside the Mill / scala-cli files the pom rewriter reports it). `rollback` / `remove` restore `socket-patch.sbt` offline (the rows removed, the file deleted with its last pin; the gitignored downloads are left). Manifest-less VEX reads every strictly parsed pin as a hosted reference but grants it the lockfile basis only when the local evidence shows every recorded version of the GA is the pinned one and every recorded artifact hashes to a pinned sha256 (else `sbt_resolution_unverified`).

**Non-UTF-8 candidate files (#721)**: the rewriters edit UTF-8 text only. A candidate file that exists but is not UTF-8 (for example a UTF-16 `requirements.txt`, which is what Windows PowerShell 5.1's `pip freeze >` writes and which pip installs from) is never read as absent. When a candidate of its ecosystem could rewrite it, the run is refused with `candidate_file_unreadable` (exit 1, `--dry-run` included), the message names the file, and nothing is written; the remedy is to re-save the file as UTF-8. Two exceptions keep their own refusals. A Gradle build file the Gradle planner reaches gets that planner's per-build refusal (`redirect_gradle_build_file_unreadable`, exit 0) and the rest of the run goes ahead, and with no readable Gradle build a stray Gradle file (a lock, a nested script) is never rewritten, so it does not refuse the run, while a non-UTF-8 root `settings.gradle(.kts)` or `build.gradle(.kts)` still refuses it (it may be the build itself). An unreadable `socket-patch.sbt` is refused with `redirect_sbt_owned_file_unreadable`. A vendored→hosted takeover checks this before it reverts anything, so a refused run leaves the vendored wiring, ledger entry and artifact byte-identical. Vendored mode likewise refuses a non-UTF-8 `requirements.txt` or `-r` include by name (`pypi_no_requirements`) instead of wiring around it. Lock-only discovery reads `requirements.txt` and its in-root `-r` includes the way pip decodes them (a UTF-16 or UTF-32 byte-order mark selects that encoding), so such a project's pins are still found instead of reporting "No packages found".

**Gem stale-install guard (additive warning — the canonical narrative; other mentions point here)**: the gem hosted rewrite is pure Gemfile/lock text, so a gem ALREADY materialized under the project's bundle paths keeps its upstream bytes — the next `bundle install` prints `Using <gem>` and never refetches, on **every** bundler major (live-verified 2026-08-19 on 1.17.3 / 2.7.2 / 4.0.18: bundler 4's CHECKSUMS verify at download time only, and nothing is downloaded; `bundle install --force`/`--redownload` re-install from the stale cached `.gem` instead of re-fetching — bundler 1 silently, bundler 4 with an exit-37 checksum refusal that still leaves the upstream bytes installed; the **verified** remedy is removing the installed dir + cache `.gem` + `specifications` entry, then `bundle install`). After the rewrite, a hosted run therefore probes the installed-gem discovery paths (the same ruby-crawler discovery `apply` uses, honoring `--global`/`--global-prefix` like scan's own discovery, plus — read-only — a `.bundle/config` bundle path refused as a write root because it resolves outside the project, which takes the project-local remedy; the `gem env` homes count only when Bundler uses system gems, i.e. no deployment store under `vendor/bundle`, and the first settings tier (app config, environment, global config) that sets `path`, `path.system` or `disable_shared_gems` doesn't set a non-empty `path` without `path.system: true` or `disable_shared_gems: false`, since with such a `path` `bundle install` fetches non-default gems into it and never reuses a system copy) for each confirmed gem redirect and judges the materialization against the patch record's `afterHash` file map. Judgment rules: records are found **by uuid** among this run's fetched records (v5.0: hosted mode persists no records, so a purl whose `/patches/view` fetch failed this run is not judged; the warning re-fires on every re-scan whose fetch succeeds, until the stale materialization is gone); a materialization with every file at `afterHash` is already patched and never warns (an agent→hosted migration stays quiet by construction), and when several confirmed variant purls resolve to one installed dir, ANY of them judging it patched keeps it quiet; staleness needs **positive evidence** — at least one record file whose bytes were actually read and hash to neither state's expectation — so missing or unreadable files never produce a warning. Warnings emit `redirect_gem_stale_install` (JSON `redirect.warnings[]` + a code-tagged stderr line) in three flavors: a PROJECT-LOCAL dir (under the project root, compared on absolute paths so the default `--cwd .` counts, or under the project's own refused `.bundle/config` path) gets the verified delete-list remedy (installed dir, cache `.gem`, `specifications` entry — plus the project's committed `<cache dir>/<leaf>.gem` when present and not proven to be the patched artifact, since bundler installs from its cache dir in preference to fetching); a SHARED gem-env home gets a caveat that the home is shared machine-wide and prefers migrating the project to a local bundle path over deleting shared files; and a committed cache-dir archive whose sha256 differs from the patched artifact's warns standalone even with no installed dir at all (a fresh checkout with a committed stale cache re-materializes the upstream bytes forever). A stale-flagged purl is additionally **excluded from the same run's `--vex` `assume_applied` set** — the envelope must never attest a CVE its own warning says is live; the purl falls back to normal installed-tree verification (a patched install still attests, a stale one is omitted). The cache dir is bundler's `cache_path` setting (`Bundler.app_cache`), resolved in `Bundler::Settings` priority: `BUNDLE_CACHE_PATH:` in the bundler app config (`$BUNDLE_APP_CONFIG/config`, else `.bundle/config`) first, then the `BUNDLE_CACHE_PATH` environment variable, then `BUNDLE_CACHE_PATH:` in the global config (`bundle config set --global`: `$BUNDLE_CONFIG`, else `$BUNDLE_USER_CONFIG`, else `$BUNDLE_USER_HOME/config`, else `~/.bundle/config`), else `vendor/cache`; a relative value is read against the project root. The same global tier, below the app config and the environment, applies to `BUNDLE_GEMFILE:` and, for agent-mode install-root discovery, to `BUNDLE_PATH:`. A present local or environment `path`, `path.system`, or `disable_shared_gems` setting (including an empty string or false flag) shadows the global path tier, matching the tested Bundler 2.6/4 behavior; Bundler 1.x's legacy global-path shortcut is not modeled. An empty higher-tier `gemfile` setting also shadows the global value but leaves an existing nonempty `BUNDLE_GEMFILE` environment value in effect, or uses default manifest discovery when there is none. With `BUNDLE_IGNORE_CONFIG` set (any value) bundler reads no config file, so the app and global configs are skipped here too and only the environment and the default count — the same holds for the `BUNDLE_GEMFILE:` app-config setting. The probe is read-only (nothing is deleted) and skipped on `--dry-run` — deliberately explicit, since nothing was rewritten. Exit code and `status` are unchanged (warning-only, the hosted-refusal posture); a same-run `--vex` may still fail on "nothing to attest" per the embedded-VEX contract.

**Pipenv hosted redirect (`Pipfile.lock`, pipfile-spec 6)**: every category other than `_meta` (`default`, `develop`, and Pipenv 2022+ named categories) that pins the package at the patched version is rewritten to the hosted reference — `{"file" | "path": "<artifact url>#sha256=<hex>", "hashes": ["sha256:<hex>"]}` with `markers`/`extras`/`index` kept exactly as Pipenv wrote them (present or absent: whether Pipenv records `index` depends on its release, the Pipfile spelling and the locking environment, so only the entry itself knows) and `version` dropped; `_meta` (the Pipfile content hash) and the Pipfile itself are never touched, so `pipenv install --deploy`/`sync`/`verify` keep passing. The reference KEY depends on the installing Pipenv: releases 7–11 only install `path` references, 2018 and later `file` ones (0–6 write pipfile-spec < 6 and are refused). The release is probed once per command with `pipenv --version`, resolved on ABSOLUTE `PATH` entries only (a relative entry would run a `pipenv` planted in the scanned repository; `.bat`/`.cmd` shims are found through `PATHEXT` on Windows), only when a pypi patch actually targets an entry of the lock, and `SOCKET_PIPENV_MAJOR=<major>` pins the answer without spawning anything. An unknown installer selects `file` and warns `redirect_pipenv_installer_unknown` only when the lock was rewritten. **Refusal scope**: a pin/source CONFLICT (another version pinned, a foreign `file`/`path` source, a VCS/editable dependency) refuses the whole dependency atomically across categories as `redirect_pipenv_refused` AND vetoes the sibling Python rewriters (requirements.txt / uv.lock / pyproject) for that patch — the project's Pipenv install could not pick the patch up, so a half-redirected checkout is refused; anything else (no entry for the package, an old pipfile-spec, an unparseable lock, a digest-less patch) is `redirect_pipenv_skipped` and leaves the siblings alone (a stale Pipfile.lock in a uv/Poetry/requirements project must not block them). The veto applies to a LIVE lock only: a `Pipfile.lock` with no `Pipfile` beside it is abandoned, so its conflict refuses that file but never the siblings. Hash enforcement at install time is split by era — the `#sha256=` URL fragment is what Pipenv 2023+ verifies, the `hashes` list what 2018–2022 verify, Pipenv 11 either — so both are load-bearing. **Pipenv stale-install guard**: Pipenv never reinstalls a release that is already present (`pipenv install`, `install --deploy` and `sync` all exit 0 and keep the installed bytes — measured on 11.10.4, 2018.11.26 and 2026.8.0, hosted and vendored), so after the rewrite the run probes the Python crawler's site-packages (VIRTUAL_ENV, `./.venv`, `./venv`, Pipenv's out-of-tree `WORKON_HOME` venv; `--global`/`--global-prefix` honoured) for each confirmed Pipfile.lock redirect with the same rules as the gem guard (records by uuid from this run's fetch, PATCHED = `verify_patch_record` Ok, STALE needs positive evidence, read-only, skipped on `--dry-run`, stale purls excluded from the same-run `--vex` `assume_applied` set) and the Python stale-install guard (`redirect_pypi_stale_install`, see above) names the site-packages dir and the Pipenv-specific verified remedy: `pipenv run pip uninstall -y <pkg> && pipenv sync` (or `pipenv --rm && pipenv sync`), with the `sync` arguments following the lock, since plain `pipenv sync` installs only `default`: the targeted form re-syncs the categories that pin the package (`--dev` for `develop`, `--categories "<Pipfile names>"` for a named category) and the `--rm` form re-syncs every non-empty category — NOT `pipenv uninstall`, which rewrites the Pipfile and re-locks the patch away. The vendored backend emits the twin `pypi_pipenv_stale_install` (`skipped` warning event). **Rollback** (v5.0, upstream restore): each hosted entry gets its registry shape back — `"version": "==<v>"`, the entry's own `index` carried back unchanged (refused unless it — and the Pipfile's explicit `index`, if any — names a PyPI source in `_meta.sources`), and every release file's sha256 from PyPI's JSON API (`SOCKET_PYPI_JSON_API`), sorted by filename as Pipenv records them; an entry that pins another version beside the hosted reference is refused with the `git checkout` remedy (see "Hosted unwind coverage"). A Pipfile names no project, so a same-run `--vex` on a Pipenv project needs `--vex-product` (or a git remote) to detect a product purl. **Discovery**: `Pipfile.lock` is part of the lockfile inventory (every category's `==` pins, with the lock's digest set as `Sha256AnyOf` integrity so a lock-only checkout can be vendored by fetching the pure wheel through PyPI's JSON API — only when `_meta.sources` name the public index; a private-index lock stays discovery-only and never reaches pypi.org), and Socket's own hosted / vendored references stay discoverable as the package they replace, so a re-scan of an already-redirected or already-vendored lock-only checkout re-confirms it (`--vex` attests, vendored reports `already_vendored`) instead of finding nothing.

**Mode ledgers (contract surfaces).** Vendored mode persists its state at a stable repo-relative path; external tools (and the depscan backend's GitHub-app PR flows) read and write it, so path + schema are part of the contract. Hosted mode (v5.0) persists nothing but its lockfile / config edits:

* `.socket/vendor/state.json` — the **vendored**-mode ledger (see "Ownership, state, and reversal" below): wiring edits with verbatim pre-vendor originals, artifact fingerprints, and the embedded patch `record` — for every entry written by `scan`/`get --mode vendored` beside `detached: true` (the record is that entry's only source), and for standalone `vendor` fed by an agent-mode manifest as a fallback copy without `detached` (the manifest record stays authoritative while the manifest covers the entry, by ledger key or base purl; `vex`, `list` and `setup --check` fall back to the embedded copy when it does not, `repair` only with no manifest at all). Entries written before 5.0 by standalone `vendor` carry no `record`; readers tolerate its absence. **Schema version 2 (v5.0)**: the `new` of a whole-file wiring record (kinds `maven_pom_repository`, `nuget_config_source`, `python_lock_document`, `python_script_metadata`, `hatch_document`) of 1 KiB or more, when its `original` is a string, is stored as an edit of that same record's `original`: `{"snapshot": "<sha256 of the text>", "ops": [[start, len] | "inserted text", …]}` (the text is the ops concatenated in order: a `[start, len]` byte range copied from the `original`, a string inserted as is), and the ledger's `version` is `2`; the `original` stays a plain string, no other record kind is touched, and a ledger without such a record keeps the version-1 bytes. Both versions are read; a version-2 edit is rebuilt and checked against its hash (a mismatch, a missing `original`, an out-of-range copy, or any other `{"snapshot": …}` value is `vendor_state_unreadable`), so every consumer sees the same full texts as with an inline version-1 ledger. Records are self-contained, so an older socket-patch re-saving a version-2 ledger (it keeps `original` / `new` verbatim and drops unknown fields) loses nothing.
* `.socket/vendor/redirect-state.json` — the **pre-v5 hosted**-mode ledger (`RedirectState` in `socket-patch-core/src/patch/redirect/state.rs`: `{ version, mode, edits[], records{} }`). **Retired in v5.0**: no command writes it, and `scan` / `get --mode hosted` ignore it. It is read for migration only — `list` and `vex` take a record from it for a hosted pin with the same purl and uuid (the lockfiles still decide what is hosted; its `edits` are never replayed), and a malformed one is only the `redirect_ledger_corrupt` warning there — and `rollback` / `remove` delete it once no lockfile pins a hosted patch any more (a `rollback` in a project whose ONLY state is this file removes it and exits 0, JSON `legacyRedirectLedgerRemoved: true`). A project scanned in hosted mode by v5 commits only its lockfile / config edits.

**get --mode and installed narrowing (v3.6).** `get <identifier> --mode hosted|vendored` consumes the resolved patch(es) through the SAME engines as `scan --mode hosted|vendored`, so for the same selected (purl, uuid) set the on-disk result is identical by construction — the per-advisory selector for hosted/vendored (`get <id> --save-only` then `vendor` still works). **Agent mode (v5.0 lock + residue rules)**: the download phase runs under `<.socket>/apply.lock` and hands the guard to the nested apply, so download → manifest write → apply is one lock window (the nested apply never re-acquires and inherits every caller flag — `--lock-timeout` and `--verbose` included); a failed acquire is `{status: "error", errorCode: "lock_held" | "lock_io", error}` on get's legacy envelope, exit 1, before any fetch (a read-only `.socket/` fails here, naming the lock path). `.socket/` and `.socket/blobs/` are created only when a record is actually persisted — an all-skipped or all-failed run leaves no `.socket/` on a fresh project — and a same-uuid `get <uuid>` re-run rewrites neither the manifest nor the blobs. Semantics:

* **Hosted** (`get GHSA-… --mode hosted`): resolves the advisory, then hands the selected (purl, uuid) pairs to scan's hosted engine — reference grants, cross-mode takeover pre-revert, lockfile rewrite (no ledger, v5.0), gem stale-install probe, warnings, confirmation rules (cargo via `confirmed_cargo_uuids`, golang via `confirmed_golang_uuids` only) all identical to `scan --mode hosted`, and (v5.0) under the same `apply.lock` acquisition — taken around the first wet write, never on `--dry-run` or when nothing would be written; a failed acquire folds as top-level `errorCode: "lock_held" | "lock_io"` + string `error` (exit 1), and `--dry-run` under a held lock still exits 0. **No manifest write, no blobs, no ledger** — the lockfile edits are the persistence. JSON: get's legacy envelope gains the same nested `redirect` sub-object as scan's (`{mode:"hosted", redirected, rewrittenFiles, skipped, warnings, dryRun}`); the top-level shape is `{status, found, patches:[<narrowing skips>], warnings?}` — `downloaded`/`applied` are absent (nothing is downloaded into `.socket/`). Exit codes follow scan's hosted semantics: skipped grants and rewriter warnings never flip the exit; infra errors (reference fetch, file writes) exit 1. Human prompt: `Redirect N packages to the hosted patch server?` (singular for one; `--yes`/`--json`/non-TTY auto-accept as usual). This confirm is get's alone: `scan` never prompts.
* **Vendored** (`get GHSA-… --mode vendored`): the download phase is scan's vendored posture — **manifest-free (v5.0)**: the selected records are fetched into memory (`download_patch_records`; no blob staging; nothing under `.socket/` is written; the nested apply never runs), then scan's vendor step runs under the apply lock over exactly the selected records, like `scan --mode vendored` (no whole-manifest scope and no `[note]` about other records — that blast radius is retired with the manifest; a legacy manifest record for a vendored purl is migrated out of `.socket/manifest.json` the same way scan does it). JSON: get's envelope takes the detached download envelope's shape — `{status, found, downloaded, skipped, failed, detached: true, patches: [{purl, uuid, action: "downloaded" | "skipped" | "failed", …}], warnings?}` (`applied` is absent; `detached: true` is pinned; a `downloaded` record for a purl the vendor ledger holds at another uuid carries the additive `oldUuid`, derived from the ledger — the human `[fetch]` line reads `<purl> (replacing <short uuid>)`) — and gains the nested `vendor` Envelope exactly like scan's `result["vendor"]`; a vendor-step error folds the partial envelope + `{status:"error", error:{code,message}}` in (a pre-failure takeover reconcile may have already mutated the ledger — its events must reach the consumer). Exit: download failures or vendor `has_errors` → `partial_failure`/1. Human prompt: `Download and vendor N patches?`; `--dry-run` prints `[dry-run] Would download and vendor N patches. No changes made.` on both identifier paths (uuid and search). Telemetry mirrors scan's vendored arms (`track_outcomes_for_vendor` / `track_patch_vendor_failed`). **Bun vendored preflight (additive)** — shared by `get --mode vendored` on both its paths and `scan --mode vendored`: before ANY patch download, and only when the selection holds a `pkg:npm/` purl, the download phase reads `bun.lock`/`bun.lockb` once (`preflight_vendor`) and, when the vendor backend would refuse the project — a malformed, unreadable or unsupported `bun.lockb` → `vendor_bun_lockb_invalid`; an unreadable `bun.lock` → `vendor_lockfile_missing`; a `lockfileVersion` other than 0/1/2 or a non-canonical `packages` grammar → `vendor_lockfile_version_unsupported`; `workspace:` packages in a lock below version 2 → `vendor_bun_workspace_unsupported` — every `pkg:npm/` result becomes `{action:"failed", errorCode:<code>, error:<detail>}` with NO fetch (the patch view is never requested) and no patch record; other ecosystems' results are untouched. **Search path** (`get <purl|advisory> --mode vendored`) and `scan --mode vendored`: the records ride `patches[]` / `download.patches[]` with `downloaded: 0`, the download phase writes nothing under `.socket/` (v5.0 — a pre-existing `.socket/manifest.json`, including a record seeded for another purl, is left byte-untouched), the vendor step still runs over the remaining records (no event for the refused purl), exit `partial_failure`/1. **uuid path** (`get <uuid> --mode vendored`): the uuid lookup is the only fetch; the run exits 1 BEFORE the vendor step with exactly `{status:"error", found:1, downloaded:0, skipped:0, failed:1, error:{code, message}, patches:[{purl, uuid, action:"failed", errorCode, error}]}` (the `error` OBJECT is the vendored-mode error shape of the vendor-step fold-in above) and writes nothing — no `.socket/` on a fresh project; human mode prints `Error (<code>): <detail>` on stderr. **Already-vendored exemption**: a purl is exempt from the workspace refusal only when every instance of its `name@version` in `bun.lock` is already a `.socket/vendor/npm/…` local tuple (any uuid; the digest-less 2-tuple counts) — the engine's own criterion — so in-sync re-runs, `repair`, and a superseding patch uuid on a project vendored before it grew a workspace member all flow to the engine (re-pinning an already-local tuple adds no workspace-relative exposure); a wiped ledger alone is not a refusal (the engine path decides). UUID equality in the ledger alone never exempts a purl: `rollback --preserve-state` retains its record after unwiring. Dry-run refusal takes priority over `already_vendored`. **Unreadable vendor ledger**: a `.socket/vendor/state.json` the preflight cannot read or parse is itself the refusal — `vendor_state_unreadable` with the io/parse detail, fail-closed (nothing is exempt) — on the uuid path, the search / `scan` path and the `--dry-run` preview alike; never a Bun lock code. **`--silent`** is "errors only" and never mutes the refusal: the code-tagged `[error] <purl> (<code>): <detail>` (per-patch paths) / `Error (<code>): …` (uuid path) line stays on stderr with an empty stdout. **`--dry-run`** previews the refusal as the additive `would_refuse` action (see `--dry-run` below). Agent-mode `get --save-only` is NOT preflighted (record-only intent has no consumption precondition). Pinned by `tests/vendor/in_process_vendor_bun.rs` (exact uuid-path envelope, seeded-manifest survival, `--silent`, `--dry-run`) and `tests/scan_vendor_e2e.rs`.

**Lock-text refusals before the download (v5.0)** — shared by `get --mode vendored` on both its paths and `scan --mode vendored`, after the Bun preflight above and the ledger's `already vendored` skip: a `pkg:npm/` result in a **pnpm, yarn classic or yarn berry** project, or a `pkg:cargo/` result, that its vendor backend refuses on the project's lock and manifest text alone is refused BEFORE its patch view is fetched — the pnpm / classic / berry gates the backend runs before it reads the package (coordinates, the lock and manifest reads and their line-ending / version / `cacheKey` / `.yarnrc.yml` gates, override and `resolutions` conflicts, the lock entry present and rewritable) and cargo's `locked_version_mismatch` (only when it is the crate's FIRST refusal; an in-tree `cargo vendor` copy still refuses in the loop as `already_vendored_in_tree`). **Scope:** only a package the vendor loop would hand to its backend is refused early — one installed on disk (the loop's own qualified-aware resolver plus the npm identity lookup), or one the lockfile inventory resolves to a verifiable registry source (a lock entry with an integrity, or the ledger-recovered pre-vendor resolution — exactly the entry the pristine fetch would use). A package absent from the lock and not installed never reached its backend and is untouched: its view is fetched, it downloads, and the vendor loop skips it `skipped` / `package_not_installed` as in v4.x (so cargo's `locked_version_mismatch` is refused early only for a crate installed at the unlocked version). The result becomes `{action:"failed", errorCode:<code>, error:<detail>}` in `download.patches[]` / `patches[]` with the backend's exact code and detail, no view and no pristine fetch, no patch record, and therefore no vendor event: compared with v4.x, `download.downloaded` drops and `download.failed` rises by the number of such packages, `vendor.summary.failed` and `vendor.events` lose their `failed` events, and a lockfile-only package among them loses its `vendor_fetched_missing` event (it is never fetched). Exit code and top-level `status` are unchanged (`partial_failure`/1); the nested `vendor.status` becomes `success` when those refusals were the vendor step's only failures (observed on the depscan fixture: 3 refusals, `partialFailure` → `success`), and when every selected package is refused this way the human `scan --vendor` arm prints `Nothing was vendored: N patches failed (see above).`. **Precedence:** the lock-text refusal is decided before the view, so it wins over every view-derived outcome — a package that would also have been a paid-access 403 (`[PAID]`/no access), a failed view fetch, or a no-applicable-files skip reports the lock refusal instead (the Bun refusal and the ledger's `already vendored` skip still come first). The human `[error] <purl> (<code>): <detail>` line is printed during the download instead of the vendor step's failure line (the human (non-`--silent`) `scan --vendor` arm's baseline pre-check still fetches the views it verifies; only the download, the pristine fetch and the vendor step skip the package there). A purl the lockfiles pin hosted keeps the loop's refusal (its takeover restore rewrites the lock the gates read); other flavors (package-lock, pnpm-legacy, bun) and ecosystems are untouched, and `--dry-run` is unchanged. `vendor` (manifest-driven, no view fetch) keeps its per-package `failed` events but no longer fetches the pristine source of a lockfile-only package it refuses this way — the source is deferred to the backend, which refuses before reading it (no `vendor_fetched_missing` event and no registry request; a refused package whose registry is unreachable reports the gate's code instead of `vendor_fetch_failed`); only a package the lock resolves to a verifiable source is deferred, and one it does not resolve keeps its `package_not_installed` skip. Pinned by `tests/scan_vendor_e2e.rs` (`exact_download_plan`: scan and exact-purl get, pnpm and cargo scope), `tests/e2e_yarn_legacy_cachekey_refusal_build.rs` and `tests/vendor/vendor_rerun_no_network_e2e.rs`.
* **Installed-version narrowing** (all modes, `get`'s search path): a CVE/GHSA fan-out returns one patch record per patched VERSION; get keeps only versions present here and emits calm `skipped` records (`errorCode: "package_not_installed"`) for the rest — never an error exit. Presence = installed on disk (qualified-aware resolver) ∪ already tracked in the manifest (record maintenance keeps working on hosts without an installed copy); hosted/vendored modes additionally count lockfile-resolved deps and vendor-ledger purls (mirroring scan's discovery supplements, including their `--global` gate). **Exempt** (no narrowing): UUID identifiers, exact-versioned PURL identifiers (explicit intent), `--save-only` runs (record-only has no installation precondition — the fresh-clone record→vendor flow keeps working), `--all-releases`, and the package-name path (already installed-derived). When EVERY found patch is filtered out, get exits 0 with the additive status **`not_installed`** (`{status:"not_installed", found:N, downloaded:0, applied:0, patches:[<skip records>], warnings?}`) — never `no_match`, which remains pinned to the fuzzy package-name path. PnP layouts are surfaced, not misreported: yarn-PnP npm results skip with `errorCode: "yarn_pnp_unsupported"` in every mode; pnpm-PnP skips carry `pnpm_pnp_unsupported` in agent/vendored modes; hosted mode — the refusal's own remedy — keeps ONLY the versions the raw `pnpm-lock.yaml` text actually resolves (boundary-anchored probe over the v5/v6/v9 key spellings, so a large fan-out never requests grants for every version ever patched), labels a JUDGED miss `package_not_installed` exactly like a non-PnP project (the layout blocked nothing — the lock was read and the version isn't resolved), and reserves the layout code for an unreadable lock (no judgment possible). When EVERY narrowed-out result is a PnP refusal, the human terminal names the layout instead of claiming "not installed" and never advises `--all-releases` (which cannot make PnP patchable); the JSON status stays `not_installed` — consumers dispatch on the per-record `errorCode`. Hosted mode also runs the per-release VARIANT filter (`filter_to_installed_releases`) on its search path before requesting grants — agent/vendored runs get it inside the download engines — with the same keep-all-plus-warning fallbacks (surfaced as `(release_narrowing)`-prefixed strings in `warnings[]`). An ecosystem this binary has no crawler for is likewise never judged: its results are KEPT (absence from a crawl that never looked carries no information — the same fail-safe as scan's prune GC). The human `Found N patches:` listing shows only the patches whose package version survived the narrowing (the narrowing is judged over every result, so an installed package's paid fix a free user cannot download still lists as `[PAID] (no access)`, while skip records and counts cover only accessible patches), sorted by PURL in natural version order (`4.17.2` before `4.17.10`); the narrowed-out ones are summarized on stderr in one line per reason (`Skipped N patches for M package versions not installed here (use --all-releases to include them).`), and `--verbose` adds one `[skip] <purl> (<reason>)` line per skipped version after that summary, in natural version order. When the candidates hold more patches than were selected and the pick was made without a menu (a paid user's auto-pick, `--yes`, a non-TTY run), a `Selected:` block names the patch (purl, tier, short uuid, advisories) that will be installed before the prompt. Machine output (the prompt count, the JSON envelope) uses the kept set, unchanged. The finer per-release variant narrowing (`filter_to_installed_releases`) is unchanged and still runs inside the download engines (and before an agent-mode `--dry-run` preview, so the preview names only the variants a wet run would fetch).
* **Deliberate divergences from scan** (documented, not drift): agent-mode get keeps its `selection_required` JSON posture for free multi-patch PURLs (scan and, v5.0, hosted/vendored get auto-pick); get has no `--vex` (an ambient `SOCKET_VEX` is ignored by get's modes), no `--prune`; get does not run scan's pre-vendor baseline annotation; and an all-narrowed-out run exits `not_installed` without entering the vendor step (heal-after-wipe re-vendoring stays `scan --mode vendored`'s job). Agent-mode `get` honors `--dry-run` too (v5.0): the search and uuid paths classify each selected patch against the manifest (read-only; an unreadable manifest fails closed like the wet run) and stop before the prompt, the download, any `.socket/` write and the apply — human `[would-add]` / `[would-update] … (replacing <short uuid>)` / `[skip] … (already in manifest)` lines then `[dry-run] Would download and apply N patches. No changes made.`; JSON `{status:"success", dryRun:true, found, downloaded:0, skipped, applied:0, patches:[{purl, uuid, action:"would_add"|"would_update"(+oldUuid)|"skipped"}, <narrowing skip records>], warnings?}`, exit 0.

`--dry-run` previews what `apply` / `rollback` / `scan --apply` / `repair` / `remove` — and `get` in every mode (hosted/vendored since v3.6, agent since v5.0) — would do without mutating disk. `get --mode hosted --dry-run` flows through the hosted engine's dry-run contract (no lock, no `.socket/`, no lockfile writes, `redirect.dryRun: true`); `get --mode vendored --dry-run` emits the same ledger-classification preview as scan's (`would_vendor` / `already_vendored` / `would_revendor`+`oldUuid` under the nested `vendor` key — plus, additive, `would_refuse` + `errorCode` + `error` for npm purls the wet run's Bun preflight would refuse: an in-sync `already_vendored` entry is exempt, as is a `would_revendor` entry whose `bun.lock` instances are all already local tuples; a purl the lock still resolves from the registry is refused like a fresh one, and the preview stays exit 0 / `status: "success"` with nothing written) before any download, and both skip the confirm prompt (nothing to confirm). In JSON mode, the envelope is populated with would-be actions and counts (`remove --dry-run` skips the confirmation prompt — there is nothing to confirm — and flips its would-be `Removed` events to `Verified` previews, so `summary.removed` stays "entries actually deleted"). `rollback --dry-run` (v5.0) previews every leg — the in-place restore verification, the vendored unwire (`Would revert/unwire vendoring for …`), the hosted upstream restore (every pin is resolved exactly like a wet run — registry lookups included, so a pin the wet run would refuse is previewed as that refusal — and nothing is flushed to disk), the manifest removals (simulated in memory), and the blob/archive GC — with no writes and no prompt.

The hidden alias `--no-apply` on `get --save-only` is **part of the contract** — it does not appear in `--help` but is widely used in existing scripts.

`repair` keeps its `gc` visible alias.

**Python stale-install guard**: after a hosted redirect, `scan` / `get` use the Python crawler to inspect every matching installed package, including Poetry's out-of-tree virtualenvs, the project's Hatch environments (Hatch's data dir / `HATCH_DATA_DIR`, `[dirs.env] virtual`, explicit env `path`s) and `--global-prefix`. A readable file that differs from the patch's `afterHash` emits `redirect_pypi_stale_install` in JSON `redirect.warnings[]` and human stderr. The probe changes no installed files, re-runs on idempotent scans, and falls back to persisted patch records when fresh record fetching fails. Missing/unreadable files alone do not prove staleness; lock-only checkouts stay quiet. Dry runs skip the probe. Same-run VEX excludes positively stale Python packages (qualifier-insensitive), even with `--vex-no-verify` or a healthy copy in another interpreter; if nothing remains to attest, the command exits 1 with `no_applicable_patches`. Reinstall from the rewritten lock in the affected interpreter and verify with `socket-patch vex`. A stale Hatch environment instead names `hatch env remove <env>` / `hatch env prune`: Hatch's pip installer (and uv before Hatch 1.16) keeps a same-version release, so only a recreated env picks up the patch. The same Hatch envs are what agent mode patches and `vex` judges for a Hatch project.

### socket.yml patch policy (v5.0)

A repository can **narrow** what `scan` patches with a `patches` block in its root `socket.yml` (the Socket scanner's config file; `version: 2` keeps every other consumer working — they strip or ignore the block). Usage guide: [repository patch policy](../../docs/configuration.md#repository-patch-policy).

**Grammar.** Every key is optional; camelCase, like the rest of socket.yml.

```yaml
version: 2                          # required once a patches block exists (integer 2 or string "2")
projectIgnorePaths: ["examples/**"] # the scanner's key; socket-patch honors it too
patches:
  enabled: true                     # bool, default true; false = report only, nothing is written
  includePaths: ["/services/payments/"]   # gitignore list; absent = every project
  ignorePaths: ["/legacy/"]         # gitignore list, evaluated after the built-in defaults
  ecosystems: [npm, pypi]           # any --ecosystems name (npm pypi cargo gem golang maven composer nuget deno)
  packages: ["pkg:npm/lodash"]      # allowlist in the --package grammar
  ignorePackages: ["pkg:npm/left-pad"]    # denylist in the --package grammar
  minSeverity: high                 # critical|high|medium|moderate|low (moderate = medium)
  maxNewPatches: 5                  # integer 0..=4294967295; the per-run cap of `--max-new-patches`
```

- Deny wins: `ignorePackages` beats `packages`, ignore paths beat `includePaths`. An empty allowlist (`includePaths: []`, `ecosystems: []`, `packages: []`) is an error ("use `enabled: false`"), never "all".
- Package specs are exactly `--package`'s: a name (full or last segment, case-insensitive) or a purl with or without a version; qualifiers ignored. A bare name matches across ecosystems (`core` matches `@babel/core`), so prefer purls. Invalid: empty, or `pkg:` without a type and a name.
- `minSeverity` judges the patch by the worst severity across the advisories it fixes (the per-package records scan fetches, never the batch summary). With a floor set, a patch of unknown severity is skipped (`minSeverity: low` therefore still skips those). The floor restricts which patch may **win** a package: a lower-ranked patch above the floor can still win.

**Precedence (flags narrow, never widen).** List filters intersect: `--ecosystems`, `--package` and PATH arguments narrow the file's lists further. Scalars go flag > env > file > default: `--min-severity <critical|high|medium|moderate|low|none>` > `SOCKET_MIN_SEVERITY` > `patches.minSeverity` > no floor. `--no-socket-yml` / `SOCKET_NO_SOCKET_YML` skips the file entirely (the built-in default ignores still apply). An empty env value is unset; a malformed flag or env value is a usage error (exit 2).

**Paths.** Path lists are gitignore patterns with the npm `ignore` package's semantics (the backend's `projectIgnorePaths` matcher): case-insensitive, anchored at the repo root, a leading or middle `/` anchors, a bare name matches at any depth, a trailing `/` matches directories only, `!` negates, the last match wins, and a negation cannot re-include anything under an ignored directory (evaluation walks top-down). Backslash is gitignore's escape character, not a separator. Patterns with a `..` segment, a drive letter, a NUL byte, or over 1024 bytes are rejected.

- They are matched against a project root's **marker files**, repo-relative: the lockfiles in the root's directory (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock(b)`, `vlt-lock.json`, `rush.json`, `uv.lock`, `poetry.lock`, `pdm.lock`, `Pipfile.lock`, `requirements.txt`, `*.py.lock`/`pylock*.toml`, `Cargo.lock`, `go.mod`, `go.sum`, `composer.lock`, `Gemfile.lock`, `gems.locked`, plus the Maven/NuGet markers). A root is ignored iff **every** marker is ignored; with `includePaths`, it is included iff **any** marker matches; a disk root with no lockfile uses its manifests (`package.json`, `pyproject.toml`, `setup.py`, `Cargo.toml`, `composer.json`, `Gemfile`, and the JVM build files: `pom.xml`, `build.gradle(.kts)`, `settings.gradle(.kts)`, `build.sbt`, `build.mill`, `build.mill.yaml`, `build.sc`, `project.scala`) instead, and one with neither is matched as its directory. So `/package-lock.json`, `**/yarn.lock` and `examples/**` mean what they mean to the scanner; `includePaths: ["/*", "!/*/"]` targets only the repo-root project.
- Evaluation order (one combined list): the **built-in defaults** `test/ tests/ fixtures/ __fixtures__/ testdata/`, then `projectIgnorePaths`, then `patches.ignorePaths`. Re-include a default with a negation (`ignorePaths: ["!/e2e/tests/"]`). The defaults apply only to **discovered** roots: hosted/vendored PATH-glob matches and roots the in-memory engine detects. A root you name — `--cwd`, a literal PATH, an in-memory `projectRoots` entry — skips them (the other lists still apply). `node_modules .git .socket .yarn vendor` stay structural excludes of in-memory root detection; no policy negates them.
- A workspace member that shares its root's lockfile is part of that root's project: exclude it with `ignorePackages`, not paths.
- A hosted/vendored PATH that resolves outside the repository root is a usage error (exit 2): one policy per invocation.

**Lookup.** The repo root is the nearest ancestor of `--cwd` (inclusive) holding `.git` (a directory, a file for worktrees and submodules, or a symlink to either), not walking past a `GIT_CEILING_DIRECTORIES` entry or into the home directory (unless `--cwd` is it), and, on Unix, only when `.git` belongs to the current user, to root, or to the user `sudo` ran for (`SUDO_UID`); a root process trusts every owner, since CI containers commonly run as root over a checkout owned by another uid (otherwise warning `socket_yml_repo_untrusted` and `--cwd` is the root). No `.git`: the root is `--cwd`. Only `<root>/socket.yml` and `<root>/socket.yaml` are read, matched by exact directory-entry name (`Socket.yml` is not read: warning `socket_yml_name_case`); nested files never are. A symlinked file is followed only to a regular file inside the repo root. `--global` / `--global-prefix` scans read no file.

**In memory (two-phase).** The host fetches the tree's root `socket.yml` / `socket.yaml` first and passes each to `selectHostedScanPaths` as `policyFiles: [{path, text} | {path, missing: true}]` (and `noSocketYml` when the session will bypass it). `text` must be a lossless UTF-8 decode (Node `buffer.toString('utf8')`; `TextDecoder` drops a BOM). Selection applies the full path policy (defaults, `projectIgnorePaths`, `patches` lists, negations), so a negated default-ignored root is fetched and patched as on disk; an excluded root is not streamed and is reported in `ignoredSample` with its `policy_*` reason (the session's `policy.filtered[]` lists only roots it received). Unless `noSocketYml`, a listed policy file not passed, passed `missing`, symlinked or invalid makes selection return `policyError` with nothing selected. Selection returns `policyPaths` and `policySha256` (`null` with no file, an empty file, or `noSocketYml`); the host streams the same text and passes both to the session, with the same `noSocketYml`. The session fails `socket_yml_invalid` when the policy it reads differs from `policySha256`, including a bypassed session given a digest.

**Validation (fail closed).** Because the file only narrows, a file that cannot be honored never means "no policy". Checked in order: file access (a regular file after resolving, at most 64 KiB, read from the opened handle), encoding (UTF-8; a BOM is stripped and CRLF is fine; UTF-16 and NUL bytes are errors), YAML 1.2 syntax (duplicate keys, a non-mapping top level, nesting deeper than 32 and a second document are errors), a top-level key that looks like a misspelled `patches` (equal to `patch`/`patches` ignoring case, or within two edits of it and starting `pat`/`pac`, e.g. `patchs`), a top-level merge key (`<<`) or aliased key (either could carry a `patches` block other YAML readers apply), the version gate (`patches` requires `version: 2`), then the keys. Inside `patches` and `projectIgnorePaths`, anchors, aliases, merge keys (`<<`) and custom tags are errors (aliases elsewhere are never expanded). An unknown key under `patches` is an error with a did-you-mean hint and "a newer socket-patch may support it". Wrong types are errors — no coercion (`"false"` is not a bool; YAML 1.2, so `no` is a string) — as are an unknown severity, an out-of-range `maxNewPatches`, an invalid pattern or spec, a list over 1000 entries and an entry over 1024 bytes. Every error names the file and the key path (`patches.minSeverity`). `projectIgnorePaths` is validated strictly when a `patches` block exists (a single string is coerced to a one-element list); without one, a malformed value only warns `socket_yml_ignored_value` and is ignored, and it is honored whatever the `version`. An empty or comment-only file counts as no file. When both `socket.yml` and `socket.yaml` exist, both are validated; if their `projectIgnorePaths` and `patches` are equal as parsed values `socket.yml` is used, otherwise the run fails with `socket_yml_ambiguous`.

**Error output.** Before any request or write, `scan` exits **1** with scan's error object plus an additive `errorCode` (`socket_yml_invalid` or `socket_yml_ambiguous`): `{"status": "error", "error": "socket.yml: patches.minSeverty: unknown key … (fix the file, or pass --no-socket-yml to ignore it)", "errorCode": "socket_yml_invalid", …}` with every count at zero; no `policy` block. Human output: `Error (socket_yml_invalid): …` on stderr. The in-memory engine reports `policyError: {code, detail}` (the detail without the CLI remedy) with no root processed and no file changed.

**The trust boundary holds.** No key names an endpoint, a credential, an org, a mode, a download format or a safety switch — such keys are unknown keys and fail validation. Every key only removes candidates or (`maxNewPatches`) delays them; none can add a package or bypass the tier filter, the agent partition, reference grants, containment checks or any refusal.

**Narrowing never removes.** The policy runs after the `--prune` universe is captured, so `--prune` still judges the full crawl. A package that already carries a recorded patch (the merged recorded view: manifest > hosted lockfile pins > vendor ledger) and is now excluded by paths, ecosystems, packages or `enabled: false` is **retained**: never handed to the hosted rewriters, the vendor engine or agent apply, never upgraded, left byte-identical, and listed under `policy.retained[]` with `upgradeAvailable`. A recorded package whose patches all fall below a new floor keeps its recorded patch, and the floor never replaces a recorded patch that outranks every admitted one. Removing a patch is only ever `rollback` / `remove`, or the dependency leaving the lockfile.

**`enabled: false`.** Discovery and the table still run; nothing is written (the `--prune` GC is skipped too); every candidate is reported `policy_disabled` (recorded ones as retained); warning `patches_disabled`; exit 0.

**Commands.** `scan` (hosted, vendored, agent; wet and `--dry-run`), the in-memory engine and `hosted-bundle` honor the policy. `get` is explicit intent: it ignores the policy and warns `policy_bypassed` (in `warnings[]`, and on stderr) when socket.yml would have skipped the package; an invalid file never fails `get`, it only drops the warning. `apply`, `list`, `vex`, `rollback`, `remove`, `repair` and `vendor` ignore it.

**`policy` JSON block** (additive, MINOR; on every successful `scan --json` result, and session-level on the in-memory result):

```json
"policy": {
  "source": "file",
  "path": "socket.yml",
  "sha256": "…",
  "enabled": true,
  "minSeverity": {"value": "high", "source": "file"},
  "counts": {"filtered": 3, "retained": 1},
  "filtered": [
    {"purl": "pkg:npm/qs@6.5.2", "uuid": null, "project": "services/legacy",
     "reason": "policy_path_excluded", "detail": "/legacy/ (patches.ignorePaths)"}
  ],
  "retained": [
    {"purl": "pkg:npm/lodash@4.17.20", "project": "", "recordedUuid": "…",
     "reason": "policy_package_ignored", "detail": "lodash (patches.ignorePackages)", "upgradeAvailable": true}
  ]
}
```

- `source`: `none` (no file, an empty file, `--global`, or only a case variant; `path`/`sha256` null), `file` (the file used and the SHA-256 of its bytes), `bypassed` (`--no-socket-yml`).
- `minSeverity.source`: `flag` | `env` | `file` | `default`; `value` null = no floor (`moderate` reads as `medium`).
- `project`: the repo-relative root directory (`""` for the repo root).
- `filtered[]`: `uuid` is null for a package filtered before any patch lookup (path, ecosystem and package reasons — those packages are never queried); a root filtered as a whole is one entry with `purl: null`. A severity entry names the top-ranked patch the floor withheld. `retained[]`: recorded packages the filters hold in place.
- Reason codes (stable): `policy_disabled`, `policy_path_excluded`, `policy_path_not_included`, `policy_ecosystem`, `policy_package_not_listed`, `policy_package_ignored`, `policy_severity` (detail `low < high`, `unknown < high`). In-memory `ProjectResult.skipped[]` carries the post-lookup ones (severity, disabled) with the same codes.
- Every string copied from the file (patterns, specs, key names) is truncated to 200 characters with control characters stripped.
- Warnings ride scan's top-level `warnings[]` (`{code, detail}`): `socket_yml_ignored_value`, `socket_yml_name_case`, `socket_yml_repo_untrusted`, `patches_disabled`.
- Human output: one line after the table when anything was filtered or held, e.g. `Policy (socket.yml): 3 skipped by filters, 1 patched package held.`, then every skipped project and every critical/high patch the severity floor or `enabled: false` held back, by name (a policy must not hide those silently; path, ecosystem and package filters run before any patch lookup, so their severity is unknown); `--verbose` lists every entry. A report-only `--json` run (`--prune` or `--global` with no mode) fetches patch details only when a floor or `enabled: false` could withhold something, so its `filtered[]` matches the human output.
- `filtered[]` and `retained[]` are sorted by project, then purl; purls use the canonical spelling (qualifiers stripped, percent-decoded).
- Exit code is unchanged by filtering.

### Per-run limit on new patches (`scan --max-new-patches`, v5.0)

`scan --max-new-patches <N|none>` (env `SOCKET_MAX_NEW_PATCHES`; socket.yml `patches.maxNewPatches`) paces a rollout: each run adds at most N patches to packages that had none, the most critical first, and defers the rest to the next run. It applies to `scan` in hosted, vendored and agent mode, wet and `--dry-run`, and to the in-memory engine (napi `maxNewPatches`, `hosted-bundle`); `get` is explicit intent and ignores it. Usage guide: [gradual rollout](../../docs/configuration.md#gradual-rollout).

**Classification.** After per-package selection, each selected `(project, purl)` row is compared with the project's **recorded view** — the merged manifest > hosted lockfile pins > vendor ledger that `updates[]` reads:

| Class | Rule | Capped | The writer gets |
|---|---|---|---|
| ALREADY | the recorded uuid is the selected one, or the selection does not supersede it | no | the **recorded** uuid (re-confirmed idempotently, never swapped) |
| UPGRADE | the selection supersedes the recorded uuid (`ranking::search_result_supersedes`), or the recorded uuid is no longer offered | no | the selected uuid |
| NEW | nothing recorded for the base purl in this project | **yes** | the selected uuid, if admitted |

Supersession is judged on the by-package records the selection itself uses, so a scan with or without a cap never replaces an applied patch with an equal sibling (the tier and uuid tiebreaks and a missing date never count). When the lockfiles of a project pin a purl to several uuids, the recorded uuid is the selected one if it is among them, else the smallest. A hosted pin on a patch server that discovery does not recognize (an origin missing from `--patch-server-url`) still counts as ALREADY when a lockfile names the selected uuid, so the cap can never stall on it.

**Eligibility.** A NEW row is eligible only if every check the mode can decide without writing passes: the tier filter; the agent partition (vendor-owned and not-installed packages); the vendored Bun / vlt preflight; a `granted` hosted reference with a usable purl and url; the vlt artifact preflight; the vendored-to-hosted takeover refusals; wheel metadata; and a hosted rewrite whose confirmation probe shows a lockfile edit that pins it. Ineligible rows keep their own skip reasons and never hold a slot. References are fetched for every row before the budget is spent, and `--dry-run` fetches them too, so a dry run makes exactly the wet run's decisions.

**Unit and order.** The budget counts distinct **base purls** (ecosystem + name + version, qualifiers stripped, percent-decoded; qualifier twins are one package): admitting one admits all of its eligible rows and costs one slot. Eligible NEW base purls are ranked by, ascending: in-flight first (in-memory `inFlightPatches` only); severity of the selected patch (critical, high, medium, low, unknown — the worst advisory it fixes); advisory count, descending; ecosystem name; base purl (bytewise); uuid. The order is total and has no time-dependent key (publish dates still pick the patch within a package, never the package order).

**Budget scope.** Disk: one budget per invocation. The project directories a hosted or vendored scan's PATHs name are visited in sorted order; each spends what is left in rank order, and a base purl admitted in an earlier directory is admitted free in a later one. `scan --json` takes one directory, so a CI job per directory gets N per directory. In memory: one budget across every project root (roots are collected, planned once, then applied). The two therefore rank a multi-root repo differently, by design.

**Incomplete data.** With a finite cap, a failed batch query, or a failed detail query for a package with no recorded patch, admits no NEW row that run (they are all deferred) and adds warning `rollout_incomplete_lookup`: a missing package must not let lower-ranked ones take its slot. ALREADY and UPGRADE rows proceed as usual. A failed hosted reference lookup that could only affect NEW rows of a capped run is warning `rollout_reference_failed` (the rows are deferred) instead of a run failure.

**Convergence.** The limit is stateless: run k lands the top N, run k+1 finds them recorded and lands the next N, so M waiting patches take at most ceil(M/N) *committed* runs. A newly published or re-scored more severe patch moves ahead of the queue (intended: most critical first), and low-severity patches can wait while more severe ones keep arriving. A CI job that does not commit the scan's changes never advances: there a cap means "only the top N, every run" — commit the changes (or use a PR bot), or set no cap in such jobs. A write failure after admission still spends its slot (no backfill within a run). Known limits: a dependency that moves to a new version is NEW again (its hosted pin stays with the old lock entry); a qualifier twin that lands on a later run joins its package as ALREADY / UPGRADE, uncapped.

**Output.** Every successful `scan --json` result carries an additive top-level `rollout` block (MINOR), zero counts when the run planned nothing (report-only and empty scans):

```json
"rollout": {
  "maxNewPatches": {"value": 5, "source": "flag"},
  "counts": {"new": 5, "deferred": 9, "upgrade": 1, "already": 12},
  "deferred": [
    {"purl": "pkg:npm/minimist@1.2.5", "uuids": ["…"], "severity": "critical",
     "advisoryCount": 1, "projects": [""], "rank": 6}
  ]
}
```

`maxNewPatches.value` is `null` for unlimited; `source` is `flag`, `env`, `file`, `default` or `cap` (the in-memory `maxNewPatchesCap` tightened it; the in-memory `maxNewPatches` option reports `flag`). `counts.new` / `counts.deferred` count base purls, `counts.upgrade` / `counts.already` count `(project, purl)` rows. `deferred[]` is in rank order: `purl` is the base purl, `uuids` the distinct selected uuids across its rows, `projects` the repo-relative project directories (`""` is the scanned directory), `rank` 1-based among eligible NEW base purls. Deferred rows are never written, downloaded or vendored: hosted mode mirrors each into `redirect.skipped[]` as `{purl, uuid, reason: "rollout_deferred", detail}`, the in-memory engine lists them in `ProjectResult.deferred[]` (`{purl, uuid, severity, rank}`) and `skipped[]`, and agent / vendored mode leave them out of `apply.patches[]` / `vendor`. Warnings (`rollout_incomplete_lookup`, `rollout_reference_failed`) go to the top-level `warnings[]`. Exit codes are unchanged: deferring is not a failure.

Human output adds, when a cap is set, `Rollout: 3 of 9 new patches applied (maxNewPatches=3 from --max-new-patches); 0 upgrades, 0 already applied.` (with several project directories: `…, shared by this run's directories, 1 left)`) and next steps naming the deferred patches (`6 new patches deferred; commit these changes and run scan again to apply the next 3.`, `Next up: minimist@1.2.5 (critical), …`; a dry run says `would be deferred`, and an incomplete lookup says so instead). Hosted mode prints them on stdout after its own next steps, unindented; agent and vendored mode under a `Next steps:` heading. The `rollout` block is left out of error envelopes (`status: "error"`).

CI recipe: `socket-patch scan --json --max-new-patches 5 | jq '.rollout.counts.deferred'`.

### Embedded VEX (`apply --vex` / `scan --vex` / `vendor --vex`)

`--vex <path>` folds OpenVEX 0.2.0 generation into `apply`, `scan`, and `vendor`: on a successful run the command writes the document to `<path>` using the same engine as the standalone `vex` command. The `--vex-*` flags mirror `vex`'s `--product` / `--no-verify` / `--doc-id` / `--compact` knobs (namespaced to avoid colliding with the host command), and reuse the standalone env vars (`SOCKET_VEX_PRODUCT`, etc.). They are inert unless `--vex` is set.

Contract details:

* **Always written to the file** — never stdout — so the document never races the command's own `--json` output.
* **Fail-the-command**: if `--vex` was requested but generation fails (product PURL undetectable, nothing to attest in the manifest / vendor ledger / lockfiles, all patches omitted, a corrupt vendor ledger, unwritable path), the command exits non-zero **even when the apply/scan itself succeeded**. In `--json` mode the failure surfaces in the envelope's `error` (`apply`) / top-level `error` (`scan`), with a stable code (`product_undetected`, `no_applicable_patches`, `write_failed`, …).
* **Built from the post-run state** — the manifest, the `.socket/vendor/state.json` ledger and the project's lockfile references, with hosted records fetched from the API (see "Manifest-less VEX" below) — and verified against on-disk state (unless `--vex-no-verify`; the wiring gates apply either way). Generated for real applies and read-only `scan` alike; `--dry-run` skips generation on every host command (nothing was changed, and a preview must not write an attestation — `scan --json` marks it `vex: {skipped: true, reason: "dry_run"}`).
* **JSON success surface**: `apply` adds a top-level `vex` object to its envelope; `scan` adds a top-level `vex` key to its result. Both carry `{ path, statements, format: "openvex-0.2.0" }`.
* `apply`'s no-manifest early exit (the `noManifest` success no-op; v5.0: its human line is `No patch manifest found; nothing to apply.` — it names the missing `.socket/manifest.json`, not the folder, since `.socket/` may legitimately hold vendored state) and `vendor`'s (`No manifest found, nothing to vendor.` — a project with hosted pins ejects instead, v5.0) still generate the document from the lockfiles and the vendor ledger (manifest-less VEX: hosted / vendored checkouts carry no manifest). Nothing referenced anywhere keeps the calm exit 0 (a stale document at the path is removed; `--json` carries any discovery diagnostics in `warnings[]`); any other VEX failure fails the command with exit 1 — including a run whose only candidates are omitted `record_unavailable` (an `--offline` run over a lockfile-wired checkout with no local records), so an ambient `SOCKET_VEX` there fails the install. `--dry-run` skips generation on both, and so does `apply --check` — it stays read-only and offline-safe, leaving the output path untouched. `scan` has no such early exit: with no manifest and nothing wired anywhere its `--vex` fails with `manifest_not_found`.
* **Stale-doc removal (v3.5)**: a run that ends in a VEX error removes a recognizably-OpenVEX file (JSON whose `@context` names openvex.dev) already sitting at the output path — a pipeline reusing one path can never ship yesterday's attestation for a now-unpatched tree. Unrelated files at the path are never touched; a mid-write partial that no longer parses as JSON is left for downstream parsers to reject loudly.
* **Additive warnings (v3.5)**: `product_not_iri` (the `--product`/`--vex-product` override is neither a `pkg:` purl nor an absolute IRI; honored verbatim, warned) and `vendored_tree_out_of_sync` (a healthy vendored attestation stands on the committed artifact + lock wiring while the PRESENT installed tree hash-mismatches the patched bytes — run the package manager's install (for a project with Hatch environments the detail also names `hatch env remove <env>`, since Hatch keeps an installed release); the attestation itself is unchanged). Both ride stderr in human mode and `warnings[]` in the standalone `vex --json` envelope. Same channel for `product_multiple_manifests` (auto-detect found several project manifests and names the one it used), `vex_stale_doc_removed` (the stale-doc removal above happened), the manifest-less plan's advisories — `vex_wiring_conflict` (the lockfiles wire a package to different patches: which files, which uuids, how to fix it), `vex_record_superseded` (a recorded patch replaced by the lockfile-wired one), `vex_claim_unwired` (a ledger claim whose patch the lockfiles still mention, but not as wiring), `vex_record_offline` / `vex_record_not_found` / `vex_record_fetch_failed` (why a lockfile-wired patch has no record — the detail behind a `record_unavailable` skip) and `api_auth_fallback` (the authenticated API refused the credentials and the public proxy served free patches only; `get` / `scan`'s warning text) — and, standalone only, `org_looks_like_path` (`-o`/`--org` given a file-shaped value — `-O` is `--output`). The standalone error envelope carries `warnings[]` too. An embedded `--vex` that fails also folds each omitted patch into the host command's `warnings[]` as `vex_omitted` (`<purl>: <why> (<errorCode>)` — standalone `vex` lists them as `skipped` events), and `--silent` lists them as `omitted: <purl> (<errorCode>)` lines under the error. A corrupt `.socket/vendor/state.json` is no longer degraded with a warning: every form of vex fails with `vendor_ledger_corrupt` (see the error-code table). A malformed pre-v5 `redirect-state.json` is, as of v5.0, only the `redirect_ledger_corrupt` warning (hosted mode keeps no ledger; the file is an optional migration record source).

### VEX provenance markers (contract)

Every VEX statement's impact string records which patch-application mode persists the patch. The three marker strings are **stable contract surfaces** — scanners and policy engines match on them, so renaming or reformatting any of them is a MAJOR change:

| Impact statement | Mode | Verification evidence |
|---|---|---|
| `Patched via Socket patch <uuid>` | agent | installed-tree file hashes vs the manifest's `afterHash` |
| `Patched via Socket patch <uuid> (vendored)` | vendored | the committed `.socket/vendor/` artifact (no install hook needed) |
| `Patched via Socket patch <uuid> (redirected)` | hosted | the lockfile's hosted integrity pin; in-run `scan --mode hosted --vex` attests from the patch records THIS RUN fetched (v5.0: held in memory; hosted mode persists none) WITHOUT hash verification (the JSON `vex` summary carries `verified: false`), while a post-install `socket-patch vex` re-proves the lockfile wiring and hash-verifies the installed copy the build consumes — or, with nothing installed, attests a discovered lockfile reference from its integrity pin (see "Manifest-less VEX") |

`vendored` and `redirected` are disjoint in practice (the modes conflict); if a PURL somehow appears in both sets, `vendored` wins.

**Patch hosts (manifest-less VEX).** A hosted lockfile reference counts only when it points at Socket's patch server or the operator's `--patch-server-url` / `SOCKET_PATCH_SERVER_URL` origin. A hosted URL on any OTHER host — a staging patch server used without `--patch-server-url`, or a look-alike host — is not a hosted pin at all (v5.0: there is no redirect ledger to vouch for it), so `vex` does not attest it, and `list`, `rollback`, `remove`, `vendor` and `repair` do not see it either. Pass `--patch-server-url` for a non-production patch server. (A pre-v5 redirect ledger still on disk can keep such a record in play under the pre-v5 rule: judged by the ledger's own recorded wiring, attesting only an installed tree that hashes to the record unless `--no-verify` / `--vex-no-verify` trusts it; do not combine `--no-verify` with lockfiles you do not trust.)

### Manifest-less VEX (lockfile discovery)

`vex` and every embedded `--vex` attest hosted and vendored patches without `.socket/manifest.json`, and without the vendor ledger too, by reading the wiring out of the project's lockfiles and package-manager configs. This covers a depscan-opened PR, a clone of a repo that never committed its vendor ledger, and every `scan --mode hosted` checkout (v5.0 hosted mode keeps no ledger at all: its records come from the API). The merge lives in `commands/vex_sources.rs`; discovery lives in `socket-patch-core/src/vex/discover/`.

**Inputs.** Four sources feed one record view:

1. `.socket/manifest.json`. A missing file counts as empty.
2. The vendor ledger entries' embedded `record`s.
3. Lockfile discovery — the only source of hosted references (v5.0).
4. Hosted records: the ones an in-run `scan --mode hosted --vex` fetched this run, and — for migration only — a pre-v5 `.socket/vendor/redirect-state.json`'s `records` (a malformed one is the `redirect_ledger_corrupt` WARNING, v5.0, and is simply not consulted). Anything else is fetched from the API (see **Record resolution**).

Discovery is read-only, never touches the network, and never fails the run: a malformed file becomes a diagnostic. It reads files at `--cwd`, the root where the vendor ledger is read, and it does so under `--global` / `--global-prefix` as well, because discovery is what gates the ledger entries (below). It reads only root files (no nested workspace-member locks) except where noted, and it reads **every** supported file that is present. There is no precedence chain: the hosted rewriter edits every candidate it finds, so a lock that another lock "shadows" can still carry wiring. Every value is committed, tamperable data, so each one is validated fail-closed: canonical uuid grammar, path-safe coordinates, root-anchored `.socket/vendor/` paths, and the patch-host allowlist.

| Ecosystem | Files read | Hosted reference | Vendored reference | Hosted pin (`integrity_required`) |
|---|---|---|---|---|
| npm | `package-lock.json` and `npm-shrinkwrap.json` (both when both exist) | `resolved` on the patch host (`packages` in v2/v3; `dependencies` only in v1; `link` / `inBundle` / `bundled` entries skipped, and so is any entry npm installs from a git, URL or `file:` spec, together with every ref for the same `name@version`) | `resolved: file:.socket/vendor/npm/<uuid>/<name>-<ver>.tgz` | `integrity`, required |
| pnpm | `pnpm-lock.yaml` (every `lockfileVersion`); `shrinkwrap.yaml` only when there is no `pnpm-lock.yaml`; with `rush.json`, `common/config/rush/pnpm-lock.yaml` + `common/config/subspaces/*/pnpm-lock.yaml` | `packages:` `resolution.tarball` on the patch host | `file:.socket/vendor/npm/…` tarball + key | `integrity`, required |
| yarn | `yarn.lock` (classic and berry) | classic `resolved`; berry entry keyed and resolved `<name>@<url>` + root `package.json` `resolutions` `"<name>@npm:<range>": "<url>"` (older releases: `resolution: …::__archiveUrl=<url>`) | classic `resolved "file:./.socket/vendor/npm/…#<sha1>"`; berry `file:` entry **plus** a root `package.json` `resolutions` mapping onto the same artifact (without it the entry is orphaned: diagnosed, no ref) | classic `integrity` / `#sha1`, berry `checksum`, required |
| bun | `bun.lock`; `bun.lockb` only when there is no `bun.lock` (bun reads exactly one) | URL tuple / binary remote-tarball resolution; version from the URL leaf | `.socket/vendor/npm/<uuid>/<name>-<ver>.tgz` tuple / local-tarball resolution | `sha512-…`, required. A 2-tuple that Bun < 1.3.10 re-saved without its digest is still a reference, but it attests only from an installed tree. |
| vlt | `vlt-lock.json` (lockfileVersion absent, `0` or `1`; a BOM-prefixed, unparseable, non-object or other-version lock is not read: diagnosed, no ref). `vlt.json` (read only for its `modifiers`) and `node_modules/.vlt-lock.json` are never wiring. | a registry node (any segment) whose slot [3] is a `/patch/npm/…` URL on the patch host with the leaf `<bare>-<ver>.tgz` of its DepID's `name@version`, whose embedded `<name>/<ver>` path (when present) is that `name@version`, and slot [1] == name; version from the DepID | a `file` node `.socket/vendor/npm/<uuid>/<name>-<ver>/node_modules/<name>` (or a user-installed `<name>-<ver>.tgz`) with slot [1] == name; version from the path. A same-`name@version` registry node, or a diagnosed Socket-shaped one, beside it is diagnosed, no ref. | slot [2] `sha512-…`, required (a hosted node without one is no reference). A same-`name@version` node on another registry, or a diagnosed Socket-shaped one, keeps the reference but withholds the lockfile basis: only an installed tree whose every store copy verifies attests. So does a lock some vlt release discards, the conditions of `redirect_vlt_lockfile_version_missing`, `redirect_vlt_old_lockfile_ignored` and `redirect_vlt_scalar_registry_ignored` (which in-run `--vex` withholds too): every hosted reference in it keeps no pin, and one `patched_ref_unattributable` names them. |
| cargo | `Cargo.lock`, `Cargo.toml`, `.cargo/config` (else `.cargo/config.toml`) | `Cargo.lock` `source = "sparse+…/<uuid>/index/"`, confirmed by `Cargo.toml`: a crate the root manifest declares must pin `registry = "socket-patch-<uuid>"`. A reverted pin is diagnosed, no ref. | `[patch.<source>] <key> = { path = ".socket/vendor/cargo/<uuid>/<name>-<ver>" }` — primarily the root `Cargo.toml` (v5 `vendor`; key-agnostic: `<name>` is `package` when renamed, else the key, so `<name>-socket-<uuid8>` keys count), also the project config (pre-v5 wiring), live only while the lock holds a sourceless entry for it that is not in `[[patch.unused]]`; a manifest entry cargo ignores — the project config redefines its key with another path, or a `[patch."https://github.com/rust-lang/crates.io-index"]` table replaces `[patch.crates-io]` — is diagnosed (`patched_ref_invalid`), no ref | `checksum` (v1: `[metadata]`), required |
| golang | `go.mod`, `go.work`, `go.sum`, `go.work.sum` | `replace M v => patch.socket.dev/gopatch/<uuid> <sver>` | `replace M v => ./.socket/vendor/golang/<uuid>/M@v` | both go.sum lines, required. A replace that `require` no longer selects (`require M v'`) is inert: diagnosed, no ref. |
| pypi | `uv.lock` (confirmed by `pyproject.toml` `[tool.uv.sources]` when present), PEP 723 `<script>.py.lock`, `pylock.toml` / `pylock.<name>.toml`, `poetry.lock`, `pdm.lock`, `Pipfile.lock`, `requirements.txt` + its in-root `-r` includes, PEP 508 direct references in `pyproject.toml` / `hatch.toml` | Socket-host artifact url | `.socket/vendor/pypi/<uuid>/<wheel>` naming the entry's own dist | sha256, required |
| gem | `Gemfile.lock` and `gems.locked` (the `Gemfile` / `gems.rb` only to cross-check a merged multi-remote `GEM` section) | a `GEM` section whose remote ends `patch-registry/gem/<token>/<uuid>` | `PATH` remote `.socket/vendor/gem/<uuid>/<name>-<ver>` | `CHECKSUMS` sha256, required only when the lock has a `CHECKSUMS` section (bundler ≥ 2.6) |
| composer | `composer.lock` (`packages` + `packages-dev`) | `dist.url` on the patch host | `dist: {type: "path", url: ".socket/vendor/composer/<uuid>/…", reference: "<uuid>"}` | `dist.shasum`, required |
| maven | `pom.xml` (+ `.mvn/maven.config`, `.mvn/checksums/checksums.sha256`) | a dependency version `<base>-socket.<hex8>` matching exactly ONE `socket-patch-<uuid>` repository on the patch host | `socket-patch-vendor-<uuid>` repository + exactly one jar under `.socket/vendor/maven/<uuid>/` with a matching `.sha1` | Trusted Checksums line when enabled; not required (the suffixed version is the pin) |
| gradle (v5.0) | `.socket/gradle/hosted-index.tsv`, the owned hosted script, and every settings script and lock file the script graph reaches | an index row whose repository URL is on the patch host and names the row's uuid, live only while the owned script is intact, every build's settings file applies it with the current index digest, every lock entry of the GA is the suffixed version, no `settings-gradle.lockfile` names the GA and no build script sets a custom `lockFile` (otherwise `patched_ref_invalid`) | none here: a vendored Gradle entry is gated by its ledger entry's wiring check | the suffixed copies installed in the Gradle cache; required (never the lock basis), because the script lets a higher upstream version resolve |
| nuget | the first of `nuget.config` / `NuGet.config` / `NuGet.Config`, + `packages.lock.json` | source `socket-patch-<uuid>` + its exclusive exact-id `<packageSourceMapping>`; version from `packages.lock.json` | the same mapping onto `.socket/vendor/nuget/<uuid>`; version from the lock, else the feed's single nupkg | `contentHash`, required |
| deno | `deno.lock`'s npm section, only as evidence against an npm-family pin of a `name@version` it also locks, which `vex` then omits (see **Unattested references**, #406) | — (no hosted mode) | — (no vendored backend) | — |

Recognition rules that hold for every ecosystem:

* **Patch hosts.** A hosted reference counts only on `https://patch.socket.dev` or the `--patch-server-url` / `SOCKET_PATCH_SERVER_URL` origin, with no userinfo. The uuid is the URL's LAST canonical-uuid path segment, because grant tokens may themselves be uuid-shaped. The Go module prefix is fixed. `socket-patch-<uuid>` registry / repository / source names count only through a pin. For a URL on any other host, see **Patch hosts** above.
* **Pins, not definitions.** A registry, index or source *definition* alone (cargo `[registries]`, nuget `<add>`, pom `<repository>`, uv index tables, `.npmrc`) never makes a reference, because it survives a reverted pin. Sections the package manager ignores are not read: npm's v2 `dependencies` mirror, a `.cargo/config.toml` shadowed by `.cargo/config`. A Socket pin inside a maven `<profile>` is diagnosed, never a reference.
* **Contested locks.** When one lock wires a package to a patch and another lock resolves the same `name@version` from a non-Socket source, the build's bytes depend on which package manager runs. The reference is then dropped with a `patched_ref_unattributable` diagnostic naming both files. This applies across npm / pnpm / yarn / bun and across uv / pylock / poetry / pdm / Pipfile.lock / requirements. PEP 723 script locks neither contest nor are contested. A **bundled** npm copy (`inBundle: true`, or v1 `bundled: true`) of the same `name@version` contests the reference too, in the same lock, in the other npm lock of a shrinkwrap/package-lock pair, or in any other lock. npm unpacks it from the parent package's tarball, so no rewire reaches it and it stays unpatched. Bun and vlt unpack bundled copies the same way (#469, #471). pnpm unpacks bundled copies too, but its lock cannot tie one to a reference (see **Unattested references** below). For Bun, that is a `bun.lock` entry whose meta is `{ "bundled": true }`, or a `bun.lockb` record that a dependency edge with the `bundled` behavior bit reaches, including one Bun shares with a regular install. Such an entry is never a reference, and it contests the reference the same way. For vlt, the lock records no node for a bundled copy, so the copy is found in the installed store: a real package directory inside a store package's own `node_modules`. Hosted and vendored scans skip these copies with `redirect_bun_bundled_instance_skipped` / `redirect_vlt_bundled_instance_skipped` / `vendor_bundled_instance_skipped`. When a bundled copy is the only instance, vendoring refuses with `vendor_lock_entry_not_rewritable`. Another entry of the **same** npm, Bun or yarn lock that resolves the wired `name@version` from a non-Socket source (for example a workspace member added after the rewire, then `npm install` / `bun install` / `yarn install`; for yarn berry, a registry locator such as `left-pad@npm:1.3.0` beside the hosted `…::__archiveUrl=` one) contests the reference too (#588). The package manager installs both entries, and that copy stays unpatched. Re-running `scan` / `vendor` rewires every copy.
* **Unattested references.** Some evidence shows a build may run a copy no wiring reaches, but cannot be tied to the reference's exact `name@version` or cannot say the build runs it. The reference then stays a reference: `list`, `rollback` and `remove` find it, and the ledgers' liveness gates (`vendor --check`, `scan`) keep treating the wiring as live, because re-running `scan` / `vendor` could never clear the evidence. Only `vex` omits it, as a run warning and as the `failed[].reason`. Two cases besides Gradle's (`vex_gradle_lock_above_base`): **pnpm bundled copies** (`vex_pnpm_bundled_copy`): a `packages:` entry's `bundledDependencies:` names the copies pnpm unpacks from that package's own tarball, but pnpm never locks them, so the bundled version is not in the lock. A pnpm reference whose package name a `bundledDependencies` list in the same lock names is omitted whatever its version (a missed attestation when the bundled copy is another version, never a false one), and `bundledDependencies: true` (or a value that cannot be read) omits every reference of that lock. It reaches no other lock. **deno.lock** (`vex_deno_lock_copy`): `deno install` installs a `package.json` project's npm dependencies from `deno.lock` and never reads `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock`, so an npm-family reference whose `name@version` the `deno.lock` npm section also locks is omitted (#406). Whether Deno or another package manager populates `node_modules` (`nodeModulesDir: "manual"` allows either) is not in the files, so this holds whatever `nodeModulesDir` says.
* **Lockless pins.** With no lock to name a version, a `Cargo.toml` pin (every declaration on `socket-patch-<uuid>`, that registry defined on the patch host for the same uuid) or an exclusive nuget exact-id mapping is never a reference on its own, so v5.0 does not attest it (nor does `list` show it, or `rollback` / `remove` restore it — restore those files from version control). Only a pre-v5 redirect-ledger record naming a version the pin admits keeps it live. The same holds for a gem wired only in the `Gemfile` (the pre-bundler-2.6 mixed state, lock not converged).

**Record resolution.** A candidate's record must carry the patch uuid the lockfile actually **wires**. It is taken from the first source that has one: the manifest (matched qualifier-insensitively), the hosted records above (this run's, then a pre-v5 ledger's), then the vendor ledger's embedded records. If none has it and the run is online, `vex` fetches the patch view by uuid from the patch API — for a v5 hosted checkout this is the normal path. The fetch uses `get`'s API client: the public proxy when no token is configured, and a one-shot 401/403 fallback to the proxy (free patches only). At most 10 fetches run concurrently. Fetched records stay in memory: `vex` never writes the manifest. A candidate still has no record under `--offline`, after a transport error or a 404, or when the patch is refused (paid without an entitled token); it is then omitted as `record_unavailable`, and the run is not aborted. A record whose uuid or package disagrees with the wiring is omitted as `record_mismatch`. The informational `socket-patch.vendor.json` marker is never a record source. When the lockfile wires a package to patch U, a manifest or ledger record for that package under another uuid is superseded, and a human-mode `Note:` says so.

**Verification basis.**

| Wiring | Evidence (verify mode) | Marker |
|---|---|---|
| Vendored: a lockfile/config wires a `.socket/vendor` artifact, or a live vendor ledger entry | The **committed artifact** is hashed against the record's `afterHash`. The ledger entry is used when it names the wired artifact (it carries the dir-artifact inventory); otherwise an entry is synthesized from the reference. A present installed tree with different bytes only warns `vendored_tree_out_of_sync`. | `(vendored)` |
| Hosted: a discovered patch-host reference (or a live pre-v5 redirect-ledger record) | The installed copies the build **consumes** through the hosted wiring are hash-verified when any exist: the Go replacement module, never the pristine `M@v` in the module cache; the Socket-registry cargo source dir; maven's suffixed version. Installed evidence wins: `hash_mismatch` / `not_applied` are omitted. With **nothing installed**, a discovered reference whose lock pins the artifact (or whose format's rewriter never writes a pin) attests from that pin, which is the same evidence as in-run `scan --mode hosted --vex`. A pre-v5 ledger-only record, or a reference whose required pin is missing, stays `package_not_found`. So do purls that `--ecosystems` kept out of the crawl, because "not installed" has to mean the crawler looked. The same goes for npm purls when an installed pnpm tree records its virtual store outside the project (`enableGlobalVirtualStore`, or a `virtualStoreDir` that climbs out): transitive deps there are invisible to the crawler. A pnpm `modulesDir` inside the project is crawled. A yarn Plug'n'Play project (`.pnp.cjs` / `.pnp.js`) has no tree to crawl: an npm purl there attests from the lock's pin only when the PnP loader itself resolves it through the patch (berry names the hosted url, yarn 1 the resolved url's `#<sha1>` in its cache folder). A loader written before the lock was rewired runs the registry copy, so the purl stays omitted until `yarn install` rewrites it (#519). | `(redirected)` |
| Agent: a manifest record with no live hosted/vendored wiring | The installed tree, unchanged. **Every** installed copy the crawler finds for the purl (npm nests duplicates of one `name@version`; pnpm, vlt, Bun and Deno stores add peer-variant copies and copies bundled inside other packages) must hash to the patched bytes, as `apply` patches every copy (Maven: every copy a build consumes, Gradle hash dirs included — see [Gradle builds](#gradle-builds-v50)). One unpatched copy omits the purl with that copy's tag (`not_applied` / `hash_mismatch`). | none |

**Liveness gates.** These gates run before hashing, and `--no-verify` / `--vex-no-verify` skips only the hashing, never the gates:

* A **vendor ledger entry** attests only while some lockfile or config still wires its artifact. Otherwise it is omitted as `vendor_unwired`. The exception is a hosted takeover: the same package with a live redirect record falls through to that hosted claim.
* A **hosted record** (this run's, or a pre-v5 ledger's) attests only while a lockfile still wires its hosted patch. Otherwise it is omitted as `redirect_unwired`. The exception is a manifest-owned purl, which falls back to agent-mode verification. The purls that an in-run `scan --mode hosted --vex` itself confirmed count as live.
* **Discovery is authoritative** for every patch uuid that a file it read *mentions*: the accepted references alone decide. A mention an extractor rejected keeps nothing alive, whatever raw text survives. That covers an orphaned berry entry, an inert Go replace, a reverted cargo pin, a uv lock its `pyproject.toml` does not confirm, a shadowed maven pin, a contested lock, a commented-out line and an unparseable lock. Only for a uuid that no read file mentions (formats no extractor reads, patch hosts outside the allowlist) does a ledger's own recorded wiring decide. Even then, only files that PIN the resolution count, never a leftover registry definition.
* **Wiring conflict.** When the lockfiles wire one package to two or more different patches, every candidate for that package is omitted as `wiring_conflict`, with a note naming the patches.

A reverted lockfile plus a leftover ledger or artifact therefore stops attesting, even under `--no-verify`.

**Run warnings.** Discovery diagnostics surface as run warnings. In human mode they print on stderr as `Warning: <detail>`, and the detail names the file. Under `--json` they go to the standalone envelope's `warnings[]` or the embedded `vex.warnings`; on a failed run they go to the command's top-level `warnings[]`. The codes (additive; new codes are MINOR):

| Code | Meaning |
|---|---|
| `lockfile_unreadable` | A supported file exists but could not be read (permissions, a FIFO squatting the name, non-UTF-8). |
| `lockfile_unparseable` | A supported file is not valid for its format. Nothing is discovered from it, and its Socket mentions are dead. |
| `patched_ref_invalid` | A Socket-shaped reference failed validation or is not live wiring: unsafe coordinates, a non-canonical uuid, a leaf naming another package, a path escaping the root, an inert or orphaned entry. |
| `patched_ref_unattributable` | A Socket patch uuid cannot be tied to exactly one artifact / version. Examples: a maven repository no pin names, a nuget source without a mapping, a lock contested by another lock. |
| `sbt_owned_file_modified` | `socket-patch.sbt` / `socket-patch-vendor.sbt` is not byte-for-byte what socket-patch generates; none of its pins is discovered. |
| `sbt_resolution_unverified` | An sbt pin the build's local resolution evidence (`target/`, after `sbt update`) does not verify: the reference stays, without the lockfile basis. |
| `vendored_tree_missing` | A `socket-patch-vendor.sbt` pin whose `.socket/vendor/maven2/` file is missing or modified. |

Human mode also prints `Note:` lines: superseded records, fetch failures, `--offline` withholding fetches, conflict details, and why a claim is dead. While patch records are fetched, a terminal shows a transient `Fetching patch records... (n/N)` status line on stderr (never under `--json` / `--silent`).

**Output.** A manifest-less run honors every `vex` output convention: `--output -` (or `-O -`) prints the document to stdout; `--dry-run` still discovers, fetches records and verifies, but writes nothing and leaves a previous document at the path alone (`[dry-run] Would write …`, `dryRun: true`); an embedded `--vex` under `--dry-run` skips generation with the shared `Skipping VEX generation (--dry-run: nothing was …).` line.

## Human output conventions (v5.0)

Human (non-`--json`) output is not a stable interface, but these rules hold:

* Warning lines carry no machine code: `Warning: <detail>` (and `GC: skipped: <message>.`); error lines keep theirs (`Error (<code>): …`) so a `--silent` run stays grep-able. The stable codes stay in the JSON envelope (`warnings[].code`, `error.code`, `errorCode`).
* Hosted mode is called "hosted" in human text (`Switched N packages to hosted patches; rewrote M files.`); JSON keys and codes keep their `redirect*` names.
* npm's `allow-remote` notice prints as one line (`Note: set \`allow-remote=all\` in .npmrc …` or `Warning: npm >=12 refuses the hosted patches until …`); the full `redirect_npm_allow_remote` detail is in `--json` and under `--verbose`.
* Hosted and vendored runs that change the project end with one shared `Next steps:` block (commit, reinstall + `socket-patch vex`, then any extra step).
* A declined prompt prints `Cancelled; no changes made.`; the paid-plan upsell is `Upgrade to a paid Socket plan to access all patches: https://socket.dev/pricing`.
* `-h` lists about eight common options per command; `--help` lists all of them. `scan --apply` / `--vendor` are hidden (still accepted).

## Agent mode in CI (v5.0: `setup` removed)

**Removed in v5.0 (MAJOR):** the `setup` subcommand and every install hook it wired (npm
`postinstall`/`dependencies` scripts, the `socket-patch[hook]` Python `.pth` wheel, the Bundler
plugin under `.socket/bundler-plugin/`, the Composer script hook). `socket-patch setup` is now an
unknown subcommand (clap usage error, exit `2`). Hooks a previous release committed keep calling
`socket-patch apply`, which still exists, so they keep working until you delete them; remove them by
hand (the `postinstall`/`dependencies` entries, the `socket-patch[hook]` dependency, the managed
`plugin "socket-patch"` Gemfile block + `.socket/bundler-plugin/`, the composer
`post-install-cmd`/`post-update-cmd` entries). The `socket-patch-hook` wheel and the
`socket-patch-bundler` gem are no longer published.

Prefer hosted or vendored mode: their lockfile (and `.socket/vendor/`) edits are the persistence, so
no Socket Patch install hook is needed. Agent mode (`scan --mode agent`, `get --mode agent`, `apply`) patches the installed tree
in place, which the next package-manager install reverts; wire it into CI yourself:

```sh
socket-patch scan --mode agent     # once, locally: record patches in .socket/manifest.json (commit it)
# in CI, after every dependency install:
socket-patch apply                 # re-apply the committed manifest
```

`vex` attests an agent-mode patch whenever verification finds it applied (v5.0: the old "Property 7"
filter, which dropped patches for ecosystems with no configured install hook unless declared in
`setup.manual`, is gone together with `setup`; the `ecosystem_not_setup` omission code is retired). A
manifest's legacy `setup` object (`manual`, `exclude`) still parses and round-trips but is ignored.

### Cargo and Go in agent mode

Hosted and vendored mode need no per-install step for any ecosystem. In agent mode, cargo and Go
are patched by `socket-patch apply` like every other ecosystem:

- **cargo** — `apply` patches the crate **in place** wherever the crawler finds it: the project
  `vendor/` directory or the shared registry cache (`$CARGO_HOME/registry/src/...`). The
  `.cargo-checksum.json` sidecar is rewritten so `cargo build` accepts the modified files. Rollback
  restores the original bytes from the `beforeHash` blobs. *(Note: a non-vendored crate patches the
  **shared** registry cache, which affects other projects on the machine and is reset by `cargo clean`
  / a cache prune. Vendor the dependency for a project-local, committable patch.)*
- **golang** — `apply` writes a project-local **patched copy** under `.socket/go-patches/<module>@<ver>/`
  and a `go.mod` `replace` directive pointing at it; `go build` links the copy (the module cache is
  `go.sum`-verified, so in-place patching can't build). Commit `go.mod` + `.socket/go-patches/` + your
  `.socket/` patches so a clone builds the patched bytes with no further step. `socket-patch apply
  --check` is a read-only audit of the committed redirect.

### sbt / Mill / scala-cli caches in agent mode

A JVM project root (any `JVM_PROJECT_MARKERS` file, `build.sbt` / `build.mill` / `build.sc` /
`project.scala` included) makes agent-mode Maven discovery crawl the Maven local repository. Locally, only
an sbt / Mill / scala-cli project (`build.sbt`, `project/build.properties`, `build.mill`, `build.mill.yaml`,
`build.sc`, `project.scala` or `.scala-build/`; a Maven or Gradle build never reads these caches) also crawls,
after it in order and first copy winning the crawl dedup (`--global` always): every **Coursier** cache (`$COURSIER_CACHE`; `-Dcoursier.cache=`
in `$JAVA_OPTS`, `$SBT_OPTS`, `<cwd>/.jvmopts`, `<cwd>/.sbtopts`, `-J` prefix allowed; `-Dsbt.coursier.home=<h>`
→ `<h>/cache`; the OS default `$XDG_CACHE_HOME/coursier/v1` or `~/.cache/coursier/v1`,
`~/Library/Caches/Coursier/v1`, `%LOCALAPPDATA%\Coursier\{Cache,cache}\v1`; legacy `~/.coursier/cache/v1`),
each expanded to its per-repository Maven2 roots (`<cache>/https/<host>/<repo path>/`, found from poms whose
own coordinates spell their path); then every **Ivy** cache (`-Dsbt.ivy.home=<h>` / `-Divy.home=<h>` →
`<h>/cache`, then `~/.ivy2/cache`, whose package directory is the module's `jars/` / `bundles/` / `orbits/`).
Every existing location is kept (an empty value counts as unset; a relative one resolves against the
project); an Ivy home whose path does not end in `<…ivy…>/cache` is skipped. The crawl is **not scoped** to
the build: as for `~/.m2`, every cached GAV is queried and patched. `--global-prefix` names exactly one
root, its layout read from its path. Patch keys are whole files in the package directory (`<a>-<v>.jar`),
the same parity as `~/.m2`. A GAV cached in several roots (say `~/.m2`, a Coursier cache and an Ivy cache)
is patched and restored in **every** root, one summary event per copy, since the build loads whichever its
resolver picks: the Coursier and Ivy copies join the Maven every-copy fan-out of
[Gradle builds](#gradle-builds-v50) as consumed copies (never `~/.m2` copies a Gradle-only build ignores), and
`vex` re-hashes each of them. Each per-repository root of a Coursier cache holding the GAV is its own copy; a
root reached twice through a symlink counts once. An Ivy copy is the module's `jars/` (`bundles/`, `orbits/`)
directory, and each patch file is looked up in every artifact type directory of the module, so a
`?classifier=sources` record patches `srcs/<a>-<v>-sources.jar`. A Coursier version directory holding only its `.pom` (a
version Coursier considered and evicted; it downloads jars only for the versions it picks) is no copy and
is never a target.

Coursier keeps hidden checksum sidecars beside each cached file and silently re-downloads a file whose
`.<file>__sha1` disagrees with it, so after apply **and** rollback the CLI resyncs them: every
`.<file>__{sha1,sha256,sha512,md5}` and its `.computed` digest is deleted, then the sha1 / sha256 / sha512 ones
that existed are rewritten to the new bytes (digest first, then checksum; each step atomic, so no
interruption leaves a stale checksum). md5 stays deleted (not restored by rollback); `.checked` is left
alone. The envelope's `sidecars[]` carries one `maven` record listing those files (`rewritten` / `deleted`,
paths relative to the package directory); a resync that fails is the usual `sidecar_fixup_failed` record
with the patch still applied, and the next `apply` / `rollback` (every file already at its target) retries
it when the sidecars show the resync unfinished (a sha checksum or digest disagreeing with the bytes, or md5
left without a matching sha1); a copy Coursier left consistent, such as a pristine one a rollback finds
already original, is not touched and gets no record. `~/.m2` and Ivy copies produce no record. No new codes. A running sbt server, Bloop or Metals may hold
the old classpath: restart it after an agent apply.

### Monorepo / multi-project discovery model

How the `scan`/`apply` crawlers find subprojects differs by ecosystem, and
the model is **not uniform** today:

- **Workspace-aware (walk members):** npm / yarn / pnpm / bun / vlt (`workspaces` / `pnpm-workspace.yaml` /
  vlt.json `workspaces` — a glob, a list, or named groups of either — or vlt <= 0.0.0-12's
  `vlt-workspaces.json`; vlt's declaration wins over the others and vlt never reads package.json
  `workspaces`). One repo-root invocation discovers every member. A member that is itself a
  workspace root is recursed into (bounded depth).
- **cwd-only (single project):** gem, pypi, composer. The crawler inspects only the project
  rooted at `--cwd` (pypi first takes the env the project's manager records: PDM's `.pdm-python` interpreter, meaning its venv or, for a base interpreter, PEP 582 `__pypackages__/<X.Y>/lib`, and uv's `UV_PROJECT_ENVIRONMENT`. Otherwise it looks at `$VIRTUAL_ENV`, `<cwd>/.venv` / `venv`, then a Poetry project's out-of-tree virtualenv(s) under Poetry's `virtualenvs.path`; composer at the vendor tree); it does **not**
  descend into sibling subprojects. A monorepo with several independent lockfiles in subdirectories
  (`backend/Gemfile.lock` + `frontend/Gemfile.lock`, multiple `.venv`, multiple `go.mod` /
  `composer.json`) is handled by invoking the tool **once per subproject** (`--cwd` each), as a
  per-directory CI step would.

  *Gem install roots (a refinement of "cwd-only", not an exception to the one-project model):* the
  crawler probes the project's Bundler install roots in **bundler's own precedence order** — the app
  config file's `BUNDLE_PATH:` (`$BUNDLE_APP_CONFIG/config`, else `<cwd>/.bundle/config` — what
  `bundle config set --local path` records), then the **`BUNDLE_PATH` environment variable**, then the
  **standalone `<cwd>/bundle`** tree when it holds `bundle/bundler/setup.rb` (what `bundle install
  --standalone` writes and the app loads; bundler 4 records no config for it), then **`<cwd>/.bundle`**
  when no Bundler tier sets a path or a truthy `path.system` (Bundler's base path under
  `default_install_uses_path` on 2.x and `simulate_version 5` on 4.x, and the default from Bundler 5
  on; it keeps the `gem env` fallback on, like the explicit roots, #967), then the
  default `<cwd>/vendor/bundle` — each in both store layouts bundler produces (scoped
  `<root>/<engine>/<abi>/gems/` and flat `<root>/gems/`). The env variable is the user's own machine
  state, so it is honored verbatim (it may point outside `--cwd`; a leading `~` expands against home);
  the **config file is typically committed — untrusted input — so a config-sourced root that resolves
  outside the project root is skipped** (`BUNDLE_PATH__SYSTEM: "true"` likewise drops the recorded
  path, as bundler itself ignores it). The skip is surfaced per the run-warning conventions: a
  `gem_bundle_config_path_ignored` entry in the run-level `warnings[]` of `scan`/`apply` `--json`
  envelopes (detail names the config value and the env-`BUNDLE_PATH` remedy), and one stderr
  `Warning: …` line on the human path, gated on `!--silent`
  (`--silent` = errors only). The skip is about WRITES only: bundler still installs into and loads
  from that root, so the read-only verifiers — the hosted gem stale-install probe and `vex`'s
  installed-copy lookup — still read it (a copy there must verify; an unpatched one is never the
  "nothing installed" absence the hosted lockfile basis excuses), while `apply`/`rollback` never
  touch it (#709). Explicit env/config/standalone roots only count when `--cwd` holds a Bundler
  manifest/lockfile. When the default `vendor/bundle` root holds no store, the gem homes `gem env`
  reports are appended (default gems like rexml/json only ever live there). When the Bundler tier that
  decides the install path (the first of the app config, the environment and the global config that
  sets `path`, `path.system` or `disable_shared_gems`) sets a truthy `path.system` (Bundler's own
  coercion: anything but `false`/`f`/`no`/`n`/`0`/empty), bundler installs into and loads from the
  system gem home, so the default `vendor/bundle` root is not probed at all: a leftover store there
  is neither crawled nor allowed to hide the `gem env` homes (#915). When several roots hold
  **coexisting physical copies of one `gem@version`** (bundler-2's scoped store beside bundler-1's
  flat store), `apply`/`rollback` patch/restore **every copy** — one summary event per copy,
  mirroring npm's multi-copy fan-out — while single-representative consumers (`get`, `vendor`,
  `vex`) use the highest-precedence copy. PyPI follows the same rule: when the crawler resolves
  one release in several site-packages dirs (a Pipenv WORKON_HOME venv beside an auto-detected
  `./.venv`, or the user site beside a system dir in global scope), agent `apply` patches **every**
  copy, one summary event per copy, because any of them may be the one the interpreter imports.
  Paths that resolve to the same directory (a symlinked site-packages) count as one copy.

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
wins, pinned by `find_by_purls_prefers_root_copy_over_nested_duplicate`). An **npm alias install**
(`"lp": "npm:left-pad@1.3.0"`, written by npm, yarn, Bun and pnpm's hoisted linker) is a copy of
the purl its own `package.json` names, so `apply`, `rollback` and `vex` cover `node_modules/lp`
beside any plain `node_modules/left-pad` copy. Only real package dirs count: a link is a dependency
edge, never an alias copy of its own.

### Links under `.socket/` and write containment (v5.0)

socket-patch creates `.socket/` and everything under it itself and never writes a symlink or junction there, so a linked level below the project root is never its own. The rules below share one check (core `utils::containment`); each refusal names the linked path and carries the substring `is a symlink`. Levels at or above the project path (a symlinked home directory, `/tmp -> /private/tmp`) are never checked.

- **Blob and diff cache writes** (agent-mode `get`, `scan --apply`, `apply` and `repair` downloads, and `rollback`'s before-blob fetch): a linked `.socket/blobs` or `.socket/diffs`, or a linked `.socket/blobs/<hash>` entry, is refused before anything is written. That blob is reported failed (a `get` patch fails as a whole, and its own new blobs are unwound); nothing is written at the link's target. A project that pointed `.socket/blobs` at a shared cache must replace the link with a real directory.
- **Inline blobs in `get`**: a patch view's `blobContent` / `beforeBlobContent` must hash (git-sha256) to the `afterHash` / `beforeHash` it is stored under, or the patch fails with `content hash mismatch: content hashes to <actual>` before anything is written, the same rule a downloaded blob is held to. An existing blob that already verifies is never rewritten; every blob is staged and renamed into place, never truncated in place.
- **Ledgers**: the vendored ledger (`.socket/vendor/state.json`) and the pre-v5 hosted redirect ledger are refused when `.socket` itself, a directory below it or the ledger file is a link (`vendor_dir_symlink_unsupported` for the vendored flows), so a hosted run that still has to update a pre-v5 redirect ledger fails under a linked `.socket`.
- **Agent-mode apply and rollback outside the install tree**: `apply` and `rollback` (dry run included) refuse a package whose written directories resolve outside the install tree they were found in: a Composer path repository (`vendor/<ns>/<name>` linked to first-party source), a `flit install --symlink` / editable-by-link package, or a package directory a package manager links into `site-packages` from its own prefix (Homebrew's Cellar, a Nix store path). The per-package error carries `outside the install tree`. For `apply` the remedy is to patch that source directly or install the package as a copy; for `rollback` it is to restore that source from version control, since socket-patch does not write into a tree it does not own.

Not covered: the agent-mode blob cache and manifest are checked from `.socket` down, so a `.socket` that is itself a link still redirects those writes (deciding that at lock time is deferred).

## Vendor command contract

`vendor` is `apply`'s committable sibling: instead of patching installed packages in place
(machine-local state), it ejects each patched package into `.socket/vendor/` and rewires the
ecosystem's lockfile/config so the project consumes the vendored copy. After committing
`.socket/vendor/` + the lockfile edits, a fresh checkout builds with the patched dependency on
machines with **no socket-patch installed and no Socket API access** (registry access for other,
unvendored dependencies may still be needed). Every mechanism below was validated against the real
package managers (`spikes/PHASE0-FINDINGS.txt`).

**Eject a hosted project (v5.0)**: standalone `vendor` with NO manifest in a project whose lockfiles
pin hosted patches (not under `--global`; `--ecosystems` narrows the pins) takes its patch set from
those pins — each pin's purl plus the patch uuid in its hosted URL — fetches each record from the
patch API (`GET …/patches/view/<uuid>`, the same client and public-proxy fallback as `get`), vendors
into `.socket/vendor/` exactly like `scan --mode vendored`, and rewires each package from hosted to
vendored (the upstream registry entry is restored first, so a later `vendor --revert` returns the
project to upstream, never to hosted). The human output opens with
`Ejecting N hosted package(s) into .socket/vendor/...` (`Would eject …` under `--dry-run`); the
JSON is the vendor envelope. It needs no installed `node_modules` / site-packages: the sources are
fetched from the upstream registry, so a fresh hosted checkout ejects.

The eject is ONE planned transition, all-or-nothing: (1) every record is fetched first — a failed
(or 404) view fetch is a `failed` event with `errorCode: "patch_fetch_failed"` and the run stops
with `status: "error"`, `errorCode: "eject_refused"`, exit 1, nothing touched; (2) the upstream
restore of every pin is resolved against staged copies — a refused pin (offline registry, a
non-derivable field; a binary `bun.lockb` record is rebuilt like the takeover's) is `eject_refused` with the `git checkout -- <lockfile>`
remedy, nothing touched; (3) `--dry-run` stops here and reports each pin as an `applied` event with
reason `eject_planned` — no file is written and no `.socket/` is created; (4) the wet run snapshots
every file the eject may touch under one `apply.lock`, restores upstream, then vendors. If any
package then fails, exactly the files the eject wrote are put back (the pins' files, the upstream
restore's files, and every file the vendored apply committed, each only when its bytes changed) —
the project stays hosted exactly as before, and every other file (a `--json > report.json` redirect
target, a log another process appends to) is left alone, with the
`eject_rolled_back` warning and `partial_failure`, exit 1; if putting the snapshot back itself fails,
the error is `eject_rollback_failed` naming the files to `git checkout`. The eject does not emit the
per-purl `vendor_takeover_reverted_redirect` warning (the restore is its own planned step).
`--offline` (or `SOCKET_OFFLINE`) refuses the eject up front with `offline_eject_unavailable` —
records and registry entries cannot be fetched offline — making zero network requests (dry run
included). A hosted wiring that discovery cannot attribute (a lock mentioning a recognized hosted
uuid it rejected, or a pin with no lockfile) is refused with `hosted_wiring_contested` (exit 1,
nothing touched) rather than ejecting a partial set; `rollback`, `remove` and `list` refuse the same
way (`list` degrades to a warning when it can still list). The grant token of an attributed pin's
own URL is never contested wiring where the same file also names that pin's patch uuid (a uv
pin's paired `pyproject.toml` `[tool.uv.sources]` entry, a vlt pin in a `vlt-lock.json` whose pins
are withheld from the lock basis); any other unattributed uuid still is. `--vex` works as on the manifest-driven
path. Without hosted pins the no-manifest no-op below is unchanged.

**Prebuilt vendor artifacts (`--vendor-source`)**: `service` is the default and `auto` is a compatibility alias. `build` is rejected at argument parsing. There is no local construction or fallback. Package-reference POSTs on the configured API/proxy (`--vendor-url` overrides it) return the download URL and integrity; `--patch-server-url` can override the download origin. The CLI verifies transfer integrity and patched-member afterHashes before writing. Pending builds, missing artifacts, service failures, wrong layouts and integrity mismatches fail closed. Fresh acquisition requires the network; healthy committed artifacts remain reusable offline.

Coverage includes npm (all lock flavors), Python wheels and source distributions, Cargo crates, Go module zips, Composer dist zips, RubyGems, NuGet packages and JVM jars. Directory artifacts are extracted and receive only the existing package-manager layout transformations. RubyGems requires the server's separately verified `gem-stub-gemspec`; a missing or invalid stub is a failure. Yarn Berry checksums come from server metadata. Hosted Berry rollback retrieves upstream checksum metadata from `/upstream/npm/<uuid>.json` and checks its package identity and upstream integrity against the registry; the CLI does not recreate the Berry zip.

Agent runs fetch patch content as per-file blobs (v5.0 removed `--download-mode` and the diff archive path). Vendored runs retain patch records in memory and embed them in the vendor ledger, without staging blobs. N-API and the hosted in-memory engine remain supported for callers such as the future GitHub App.

**Vendored artifact repair (v5.0)**: `repair` checks the committed artifact and downloads a replacement for the same UUID into a temporary location. Before replacement it checks transfer integrity, patched-member hashes, and the original ledger's SHA-256 and size (file artifacts) or complete file inventory (directory artifacts). JVM repair also reproduces and checks the recorded repository metadata. Different downloaded bytes or inventories are refused; the old files, ledger and lockfiles remain intact. No installed package or patch blobs are required, and none are used to construct a replacement. Missing directory inventories cannot establish an exact replacement and require explicit re-vendoring.

Successful redownloads retain the JSON `rebuilt` action and `summary.rebuilt` for compatibility, with `details.redownloaded`. Dry runs report `details.wouldRedownload` without writing. Human output says “Redownloaded”. Failed repair downloads report `vendor_artifact_redownload_failed`; the same failure during `vendor` reports `vendor_redownload_failed`. Offline repair refuses missing or corrupt artifacts even if installed copies and patch blobs exist. Revert and explicitly vendor again to adopt different bytes; repair never refreshes fingerprints or rewrites lockfiles to accept them.

**The ledger is not rebuilt from lockfiles (v5.0).** A lockfile reference to
`.socket/vendor/<eco>/<uuid>/...` with NO ledger entry (state.json deleted or never committed)
fails with `vendor_ledger_missing` (an artifact-level `failed` event carrying `uuid` and
`details.{ecosystem,path}`; exit 1) — the pre-vendor originals a revert needs cannot be recovered
from the rewired lockfile. Recovery: restore `.socket/vendor/state.json` from version control and
re-run `repair`, or restore the lockfile (`git checkout -- <lockfile>`) and re-vendor. Earlier
releases re-synthesized such entries (`details.ledgerRestored`); ledgers they wrote keep working.

Because of this phase, `repair` does not error with `manifest_not_found` when the project has a
vendor ledger or vendor-path lockfile references — it runs the vendored phase alone. A
**hosted-only** project (no manifest, no vendor ledger, no vendored references — only hosted pins
in its lockfiles, v5.0, or a pre-v5 `.socket/vendor/redirect-state.json`) is a no-op: `repair`
exits 0 with a `redirect_only_project` skip pointing at `scan --mode hosted` (hosted pins have no
local artifacts to repair), rather than the `manifest_not_found` error a bare directory still
gets. Agent blob acquisition skips vendored records and lockfile-referenced UUIDs, so repairing a vendored project does not populate `.socket/blobs`.

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

The npm ecosystem has **seven lockfile flavors** — all but vlt sharing one vendored
tarball at `.socket/vendor/npm/<uuid>/[@scope/]<name>-<version>.tgz` (vlt gets a
patched package directory); a content-sniffing probe (`npm_flavor`, `vlt-lock.json`
first) picks the flavor and the ledger records it so `--revert` routes back. The pypi ecosystem similarly routes by lockfile
to **six flavors**.

| eco / flavor | vendored artifact | committed wiring | consumption proof |
|---|---|---|---|
| npm (package-lock) | deterministic patched tarball `[@scope/]<name>-<version>.tgz`, plus `<uuid>/.gitignore` (re-includes the tarball against the project's ignores, such as Node.gitignore's `*.tgz`) and `<uuid>/.gitattributes` (`-text`); every tarball flavor below writes the same pair and refuses `vendor_artifact_gitignored` when git would still drop the tarball | `package-lock.json` only (`npm-shrinkwrap.json` wins when present): every entry matching name+version gets `resolved: "file:…"` + recomputed `integrity`. `package.json` untouched | `npm ci` (integrity-verified). Plain `npm install` preserves the entry; `npm update <pkg>` re-resolves and drops it |
| npm / yarn classic | (same tarball) | `yarn.lock` only: matching blocks get `resolved "file:./…#<sha1>"` + `integrity` (both checksums recomputed; merged-key & `npm:`-alias blocks covered) | `yarn install --frozen-lockfile --offline` (sha1 fragment + sha512 SRI both enforced; byte-stable lock) |
| npm / yarn berry (node-modules linker) | (same tarball) | root `package.json` `resolutions` + `yarn.lock` entry with `checksum: 10c0/<sha512>` of the berry cache-zip (reproduced from the tarball offline). **PnP is refused** (`.pnp.*` → different artifact pipeline) | `yarn install --immutable --check-cache`, cold cache. Refused if `__metadata.cacheKey ≠ 10c0` or a non-default `compressionLevel`. Both files keep their own layout — a CRLF lock (yarn's output on Windows) is spliced in CRLF, `package.json` is re-serialized with its BOM, indent, line ending and trailing-newline shape — so vendor + `--revert` round-trip byte-exactly; a lock or `package.json` MIXING CRLF and LF is refused before any write (`vendor_yarn_berry_mixed_line_endings`) |
| npm / pnpm (lockfileVersion 9) | (same tarball) | root `package.json` `pnpm.overrides` (versioned selector) **+** `pnpm-lock.yaml` surgery (overrides / importer version / packages `resolution.integrity` / snapshots) | `pnpm install --frozen-lockfile --offline`, cold store (integrity-verified; byte-stable on pnpm 9 & 10). Other lockfileVersions: 5.4/6.0 route to the legacy backend below; anything else refused |
| npm / pnpm LEGACY (lockfileVersion 5.4 = pnpm 7, 6.0 = pnpm 8; flavor `pnpm-legacy`) | (same tarball) | root `package.json` `pnpm.overrides` **+** legacy lock surgery (overrides / root dep + specifiers / packages rekey to a bare `file:` key with recomputed integrity / in-package dep refs). **No `pnpm-workspace.yaml` is written** (pnpm ≤ 8 reads overrides only from package.json). The lock's SPECIFIER is machine-ABSOLUTE — pnpm ≤ 8 absolutizes `file:` overrides itself — surfaced as `vendor_pnpm_legacy_absolute_specifier`. Legacy WORKSPACE locks (`importers:`) refused | same-path `pnpm install --frozen-lockfile --offline`, cold store (byte-stable on pnpm 7.33.5 / 8.15.9). A checkout at a DIFFERENT path fails the frozen check (path-bound specifier) and must run `pnpm install --offline --no-frozen-lockfile` once (the flag matters on CI, where pnpm defaults frozen on), which installs the vendored tarball and re-resolves only the specifier line |
| npm / bun (`bun.lock`, lockfileVersion 0, 1 or 2 — `vendor_lockfile_version_unsupported` otherwise) | (same tarball) | `bun.lock` only: the packages entry's registry 4-tuple → local 3-tuple with recomputed `sha512`; the entry's `{deps}` meta, the lock's version line and its line endings are preserved. A lock holding `workspace:` packages is refused `vendor_bun_workspace_unsupported` unless lockfileVersion is 2 — Bun 1.2–1.3 resolve a workspace member's local-tarball path relative to the MEMBER (ENOENT on our root-relative path), 1.4 relative to the lockfile, and a committed version-2 lock is the only proof every consumer runs Bun ≥ 1.4 (a deliberate over-approximation: a package declared only by the workspace root would install on version 1 too). The gate fires only on a run that would WRITE a new local tuple, so in-sync re-runs, `already_vendored` skips and `repair` redownloads on such a lock pass. The detail names the version and the remedy: delete `bun.lock` and re-lock with Bun ≥ 1.4 (an in-place `bun install` keeps the existing lockfileVersion), or `--mode hosted`. Native binary support is described in the next row. `scan`/`get --mode vendored` apply all four refusals BEFORE downloading (see the `get --mode vendored` bullet). Bun 1.1.39–1.3.9 re-save the local tuple WITHOUT its `sha512` on any later lock re-save (`bun add`, `bun install` after a manifest change); the digest-less 2-tuple is recognised as the same wiring — an in-sync re-run stays `already_vendored` and re-pins the digest on disk (no new wiring record) when the committed artifact still holds the bytes the lock was written from — otherwise, as for any stale tuple of ours, the line is re-pinned and the fresh entry carries the new fingerprint — `repair` redownloads through it, and `vendor --revert` / `rollback` restore the registry line over it (a 2-tuple at ANOTHER uuid is still `vendor_lock_entry_drifted`) | `bun install --frozen-lockfile`, cold cache (the local tarball's sha512 is enforced by Bun ≥ 1.3.10; 1.1.39–1.3.9 install it unverified — the committed artifact is the protection there) |
| npm / bun binary (`bun.lockb`, native binary format 1, 2 or 3) | (same tarball) | Rewrite matching binary package resolutions and integrity in place; preserve topology and unrelated metadata, update binary offsets and the package metadata hash. Text `bun.lock` takes precedence. `bun_lockb_package` wiring snapshots recover pristine registry metadata for repair and support per-package revert and hosted ↔ vendored migration. Binary discovery and rewrites require no installed Bun runtime. Malformed or unsupported content refuses `vendor_bun_lockb_invalid` before download or takeover. | Frozen installs with the original compatible Bun reader; see `docs/testing/bun-compatibility.md` for the release matrix and historical runtime integrity limits. |
| npm / vlt (`vlt-lock.json`, lockfileVersion 0 or 1 — A0 locks without a version and every other version refuse `vendor_lockfile_version_unsupported`; flavor `vlt`) | patched package **directory** `.socket/vendor/npm/<uuid>/[@scope/]<name>-<version>/node_modules/<name>/` (the extra `node_modules/<name>` level lets a package `require()` its own name), its `package.json` without `devDependencies`, plus `<uuid>/.gitignore` (re-includes the payload against the project's ignores, ignores vlt's links inside it) and `<uuid>/.gitattributes` (`-text`) | direct dependencies of the root or a workspace member only: the lock node becomes a `file` node for the directory, its importer edges and outgoing edges are re-keyed, and each importer's `package.json` spec becomes `file:<path>`; every moved entry lands where vlt's serializer puts it. A node whose only extra is one peer context (`ṗ:N`, `peer.N`, `peer.<16 hex>`: from vlt 1.0.8 a root dependency with resolved peers, from rc.15 a workspace member's) becomes a `file` node without the extra, as vlt writes `file:` dependencies, keeping its peer edges; revert restores the extra-bearing DepID. Refused before any write: transitive targets (`vendor_vlt_transitive_unsupported`), two or more instances of one `name@version` or a modifier extra, importer `peer` edges, foreign registries, a git, remote-tarball or local-directory node of the same package name (vlt records no version for it), a package `vlt build` would build in place (`vendor_vlt_build_scripts_unsupported`), a name declared in several dependency fields (`vendor_lock_entry_unsupported`), a spec that disagrees with the lock (`vendor_vlt_lock_out_of_sync`), a payload git would ignore (`vendor_artifact_gitignored`), a purl vendored under another flavor (`vendor_flavor_changed`); era-A locks warn `vendor_vlt_legacy_lockfile`; an optional dependency (or any dependency node_modules still links to its installed upstream copy) gets `vendor_vlt_reinstall_required` | fresh checkout, `vlt ci` with cold caches: the patched bytes load and `vlt-lock.json` stays byte-identical, also through a warm and a cold `vlt install --frozen-lockfile` (checked on 1.2.0, 1.0.10, 1.0.4, 1.0.0-rc.32 and 1.0.0-rc.14, and on every release by `docs/testing/vlt-compatibility.md`); no-op installs, `vlt install <new>`, `uninstall` and `vlt update` keep the direct dependency vendored. `vendor --revert` restores the registry node, edges and specs, keeping what vlt re-laid since, and refuses on drift |
| cargo | crate dir `<name>-<version>/` (no `.cargo-checksum.json`) | (v5.0) `[patch.crates-io]` path entry in the **workspace-root `Cargo.toml`** (the manifest beside the `Cargo.lock` it detaches — never `.cargo/config*`) **+** Cargo.lock surgery (the `[[package]]` entry's `source`/`checksum` removed and its `version` set to the copy's TAGGED version `<version>+socket.<uuid>` — `<core>+<meta>.socket.<uuid>` when the version already has build metadata — with every lock reference that spells the old version rewritten, formats v1–v4; the copy's own `Cargo.toml` version carries the same tag, so the patched crate sees it in `CARGO_PKG_VERSION`; revert restores the lock byte for byte). Key: always the Socket-owned `<name>-socket-<first 8 hex of the uuid>` with `package = "<name>"` (the full uuid hex when that key is taken), never the bare crate name — cargo lets a config-file `[patch]` item (project, ancestor directory or `$CARGO_HOME`) replace the manifest item with the same key whatever its version, so keys any of those configs use are avoided and a re-run moves an entry off a now-shadowed key; two versions of one crate are wired side by side. Pre-v5 wiring in `.cargo/config.toml` / `.cargo/config` is moved into `Cargo.toml` by a re-run (`vendor`, `scan`/`get --mode vendored`) or `repair` (`cargo_wiring_migrated` note; the ledger's `cargo_patch_entry` record then names `Cargo.toml`); a detached lock entry left unwired by the pre-v5 multi-version overwrite is re-wired the same way (`cargo_wiring_restored`); every revert removes both spellings | `cargo build --locked --offline` on a fresh checkout — single-version manifest `[patch]` also builds with no network on cargo older than 1.56 (the old config-file wiring's floor); two vendored versions of ONE crate need cargo 1.45 or newer (`--offline` from an empty CARGO_HOME is enough there); older cargo fails closed whatever the index state, and a project that does not pin cargo ≥ 1.45 (`rust-version` or toolchain file) gets the `cargo_multi_version_old_cargo` warning. Note: path deps build **without** `--cap-lints allow` |
| golang | module dir `<module>@<version>/` | `go.mod` `replace <module> <ver> => ./.socket/vendor/golang/<uuid>/<module>@<ver>` | `go build` with `GOPROXY=off` + empty `GOMODCACHE` (directory replaces bypass go.sum entirely; survives `go mod tidy`) |
| composer | package dir `<vendor>/<name>@<version>/`; the copy's `.gitignore` / `.hgignore` are emptied and its `.gitattributes` `export-ignore` rules dropped, because Composer's path mirror skips the files they match (`vendor_composer_mirror_filters_neutralized`; a patch that rewrites one of them is refused `vendor_composer_mirror_filter_conflict`). Re-runs heal copies vendored before this | `composer.lock` only: entry's `dist` → `{type: "path", url, reference: "<patch-uuid>"}`, `source` removed, `transport-options: {symlink: false}` added. `content-hash` unaffected; `composer.json` untouched | `composer install` (from the lock alone, real copy not symlink, works under `--network none`). Composer 1 does not reinstall an already-installed package whose dist changed: remove `vendor/<vendor>/<name>` first. `composer update <pkg>` reverts it. See `docs/testing/composer-compatibility.md` |
| gem | gem dir `<name>-<version>/` + gemspec materialized from `specifications/` | **Gemfile + Gemfile.lock pair**: the `gem` line gains `path:` (or a managed block for transitive deps); the lock's spec block moves GEM→PATH and the DEPENDENCIES entry becomes `<name> (= <ver>)!`, in bundler's exact canonical form | `bundle install` (normal **and** `BUNDLE_FROZEN=true`), byte-stable lock. Lock-only edits are a silent unpatch — hence the mandatory pair |
| pypi / uv (uv.lock) | rebuilt wheel (canonical PEP 427 filename; RECORD regenerated) | `[tool.uv.sources] <name> = {path}` in pyproject + surgical uv.lock rewrite; transitive deps via `[tool.uv] override-dependencies` | `uv sync --locked` / `--frozen --offline` (hash-verified, byte-stable lock) |
| pypi / poetry (poetry.lock: legacy `[metadata.hashes]`, lock 1.0/1.1 `[metadata.files]`, 2.x `files`) | (rebuilt wheel) | lock-only: the target `[[package]]` gets `[package.source] type="file"` (+ `reference = ""` on the 0.12/1.0 layouts, which read it unconditionally) and the single `{file, hash: sha256-of-our-wheel}` entry in whichever table the generation keeps it. pyproject + `metadata.content-hash` untouched; CRLF locks keep their line endings. A lock written by Poetry < 1.4 emits `pypi_poetry_integrity_unverified` (that installer verifies no local hashes and skips an already-installed version) | `poetry check --lock && poetry sync`, cold cache (hash fail-closed from Poetry 1.4; byte-stable lock) — see `docs/testing/poetry-compatibility.md` |
| pypi / pdm (pdm.lock) | (rebuilt wheel) | lock-only: the `[[package]]` gains the local-file `path` + `files[]` hash. pyproject + `content_hash` untouched. Non-fixture `[metadata] strategy` / hash-less locks refused | `pdm sync` (+ `pdm install --check`), cold cache |
| pypi / pipenv (Pipfile.lock) | (rebuilt wheel) | lock-only: the `default`/`develop` entry → `{file, hashes:[sha256-of-our-wheel]}`. Pipfile + `_meta.hash` untouched. Emits `vendor_integrity_unverified` — pipenv does not hash-check file entries; the committed wheel bytes are the protection | `pipenv install --deploy` (+ `pipenv verify`), cold cache |
| pypi / requirements.txt (pip / `uv pip`) | (rebuilt wheel) | pin line → `./<wheel>` (markers carried over; transitive deps appended), plus `--hash=sha256:<hex>` only when the requirements tree is already in pip's hash-checking mode (any `--hash` or `--require-hashes`) | `pip install -r` / `uv pip install -r` **run from the project root** (both resolve bare paths against the CWD) |
| nuget | deterministically rebuilt `.nupkg` at `<idLower>.<versionNorm>.nupkg` (the uuid dir IS a NuGet folder feed; the stale embedded signature is dropped — unsigned is accepted under NuGet's default validation) | `nuget.config` source + `packageSourceMapping` for the id (creating the mapping from scratch ALSO fans a `<package pattern="*" />` out to every pre-existing source — mapping is exclusive, NU1100 otherwise) **+** `packages.lock.json` `contentHash` → `base64(sha512(nupkg))` when the lock exists (`vendor_nuget_no_lockfile` warning otherwise) | `dotnet restore --locked-mode`, cold cache, `--network none` (tampered nupkg fails NU1403) |
| maven | deterministically rebuilt `.jar` + the **verbatim upstream pom** (transitives survive; refused via `vendor_maven_pom_unavailable` rather than fabricated) + `.sha1` sidecars, laid out as a maven2 repository under the uuid dir | `pom.xml` `<repository>` (`id=socket-patch-vendor-<uuid>`, `url=file://${project.basedir}/.socket/vendor/maven/<uuid>`, `checksumPolicy=fail`, snapshots disabled). Multi-module aggregator poms refused (`vendor_maven_multimodule_unsupported`); gradle-only projects refused (`vendor_gradle_unsupported`); always-on `vendor_maven_local_cache_shadow` advisory (warm `~/.m2` wins over any repository) | `mvn` build on a fresh checkout with the GAV purged from the local repo, `--network none` (docker capstone; note `mvn -o` refuses `file://` repositories outright) |

Ecosystems with no vendor backend (jsr) refuse per-purl with
`vendor_unsupported_ecosystem`. yarn-berry **PnP**
(`.pnp.*`) is refused with a stable code pointing at the native patch workflow.
Bun's binary `bun.lockb` is supported natively, including lockfile-only discovery,
vendoring, hosting, repair and migration between those modes. A lock-less tool marker (a `[tool.uv]`/`[tool.poetry]`/
`[tool.pdm]` table or a `Pipfile` without its lock) refuses `<tool>_no_lockfile` unless a
`requirements.txt` fallback exists. PURLs of ecosystems this binary has no backend for (e.g. a newer
CLI's ecosystem in the committed manifest) are invisible to `vendor` exactly as they are to `apply`.

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
| npm / yarn berry | `checksum: 10c0/<sha512>` (over Berry's cache zip) | supplied by the patch service; the CLI never builds the cache zip. Hosted rollback obtains the upstream checksum from `/upstream/npm/<uuid>.json`, anchored to the registry tarball integrity. Unsupported cache keys or compression levels are refused. |
| npm / pnpm | `packages[].resolution.integrity` (sha512) | recomputed from the tarball; the versioned `pnpm.overrides` selector pins exactly the patched version |
| npm / bun | the packages-entry trailing `sha512-…` | recomputed from the tarball; tamper fails the frozen install on Bun ≥ 1.3.10 (URL/local tarball tuples are verified from 1.3.10, registry 4-tuples from 1.2.0 — so on 1.1.39–1.3.9 a hosted or vendored rewrite removes digest enforcement for the patched package; see `docs/testing/bun-compatibility.md`) |
| npm / vlt | node slot [2] (sha512), slot [3] (resolved) | a `file` node carries none: the committed directory is the artifact, verified against the ledger's file inventory (`vendor_inventory_mismatch` on a planted, removed or changed file); integrity-less by vlt's design, like every `file:` directory dependency |
| gem | `CHECKSUMS` section (bundler ≥ 2.6 opt-in) | the vendored gem's entry rewritten to bundler's own path-gem form (bare `name (ver)`, sha256 token stripped) so re-locks stay byte-stable; original line in the ledger |
| pypi / uv | `wheels[].hash`, `sdist.hash`, requires-dist specifiers | single `{filename, hash: sha256-of-our-wheel}`; sdist dropped; dropped specifiers ledgered for revert |
| pypi / poetry | `files = [{file, hash}]` (2.x) / `[metadata.files]` entry (1.0/1.1) / `[metadata.hashes]` entry (0.12) | replaced with a single `{file, hash: sha256-of-our-wheel}` (or the bare hash for 0.12) in the generation's own table (Poetry ≥ 1.4 verifies the artifact against one listed hash; older writers are flagged `pypi_poetry_integrity_unverified`; stale registry hashes removed) |
| pypi / pdm | `[[package]].files[]` hashes | replaced with our wheel's sha256; hash-less locks refused (`pypi_pdm_lock_no_hashes`) |
| pypi / pipenv | per-entry `hashes[]` | replaced with `["sha256:<ours>"]` — but pipenv does **not** enforce hashes on file entries (`vendor_integrity_unverified` warning); the committed wheel bytes are the actual protection |
| pypi / requirements | `--hash=sha256:` | fresh hash of the rebuilt wheel emitted only when the requirements tree is already in pip's hash-checking mode; an unhashed tree stays unhashed, since one `--hash` turns the mode on for every requirement (#376) |

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
  authoritative while the manifest covers the entry (ledger key or base purl); `vex` and `list`
  read the fallback copy only when it does not, `repair` only with no manifest at all.
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
  artifact removed; in the npm family (npm, yarn classic and berry, pnpm, bun) a recorded lock entry
  that no longer exists at all — the user removed the dependency — is not drift: it warns
  `vendor_lock_entry_removed` and the artifact and entry are kept unless every wired file that exists
  was read and none mentions the uuid in any spelling (an unreadable lock keeps them), so `rollback` / `remove` / `scan --prune` clean up
  after `npm uninstall` / `yarn remove` / `pnpm remove` / `bun remove`), removes the artifacts, prunes the
  ledger, sweeps orphan uuid dirs, and (v5.0) prunes the now-empty `.socket/vendor/<eco>/` and
  `.socket/vendor/` levels — `.socket/` itself is removed by the lock guard when nothing else is
  left. It works without a manifest: with no manifest and no ledger it is a clean exit-0 no-op.
* Re-running `vendor` is idempotent (byte-stable lockfiles, deterministic artifacts →
  `already_vendored` skips). Manifest-tracked entries whose patches were dropped from the manifest
  are auto-reverted at the start of the next `vendor` run (`vendor_reconciled` events); `detached`
  entries have no manifest record and are exempt. Standalone `vendor` (no flags) is fed
  by `.socket/manifest.json` — or, with no manifest, by the lockfiles' hosted pins (the eject
  above); with neither it is a clean exit-0 no-op whose human line names
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
  Diff archives (`.socket/diffs/`) and package archives (`.socket/packages/`) are obsolete in
  v5.0: nothing writes or reads them, so every GC sweep removes both directories whole.
  Like `rollback`, `remove` retains the original blobs for every patch left in the manifest
  and for removed-but-not-installed patches, so removing one patch preserves offline rollback
  of other active patches. Only blobs no longer referenced by that keep set are collected.
* **remove restores hosted pins (v5.0)**: an identifier matching hosted pins in the lockfiles
  (purl or patch uuid; v5 keeps no hosted ledger) restores each matched pin to its default
  upstream registry entry — the same restore as `rollback` (see "Hosted unwind coverage"), for every
  ecosystem. A hosted-only match works with no manifest at all (mirroring the manifest-less
  vendored escape). **One owned pin per release**: an identifier that matches a manifest entry
  also selects the vendored ledger entry that entry claims and every hosted pin wiring the same
  package release, whatever patch uuid (generation) each recorded — so `remove <uuid A>` of a
  record a later scan superseded with patch B (vendored or hosted) unwinds B's wiring too. That
  hosted restore needs the registry lookups below, so such a remove can refuse offline where the
  manifest entry alone would not. A pin the restore refuses (`--offline`, a registry that does not answer,
  `bun.lockb`, …) or a failed write is the top-level `hosted_revert_failed` error BEFORE the
  manifest mutation (exit 1, manifest not modified; message `could not restore <purl> to its
  upstream registry entry: … (`git checkout -- <files>`)`). v4's `hosted_revert_unsupported` is no
  longer emitted. Successful restores ride the envelope as `removed`/`hosted_reverted` events
  (beside a manifest entry they bypass `summary.removed`, like `vendor_reverted`; for a hosted-only
  match the restore IS the removal and they count); once no hosted pin is left, a pre-v5
  `redirect-state.json` is deleted. `--skip-rollback` leaves hosted wiring untouched (and is refused
  for a hosted-only match); `--preserve-state` still restores — hosted has no preservable local
  state (a stderr note says the lockfile pins now resolve upstream).

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

> **Semver note.** v5.0 changes `rollback`'s DEFAULT behavior (a default-value/behavior change → **MAJOR** per the [semver policy](#semver-policy)) and narrows the meaning of the existing `vendored: []` JSON key (**MAJOR**). Every new envelope key, flag, and warning code below is additive on top of that. **Hosted leg (v5.0)**: hosted mode keeps no ledger, so the hosted leg restores each hosted pin to its default upstream registry entry (re-resolved from the registry) instead of replaying recorded fragments; a pin that cannot be restored is refused with the `git checkout -- <files>` remedy.

`rollback` and `scan` are now the batch-level duals — `scan` moves the project toward "fully patched", `rollback` toward "fully unpatched" — the way `get` and `remove` are the single-patch duals. `rollback` needs no `--mode`: it infers what to undo from three sources (`.socket/manifest.json` = agent/in-place, `.socket/vendor/state.json` = vendored, and the hosted pins lockfile discovery finds in the project's lockfiles = hosted — v5.0 hosted mode keeps no ledger).

### Targets

`rollback [TARGET]...` — zero or more targets, unioned. `pkg:` tokens are PURLs (base purl matches every release variant; qualified purl exact; PyPI names compare by their PEP 503 canonical form, so `pkg:pypi/typing_extensions@4.7.1` selects `pkg:pypi/typing-extensions@4.7.1`), other identifier-shaped tokens are UUIDs, and only **path-shaped** tokens (separator, glob metachar `*?[`, `./` prefix, or absolute) are path globs — see the per-subcommand args table for the safety rationale. Identifier matching runs across ALL THREE sources (a hosted pin matches by purl or by the patch uuid in its hosted URL); an identifier that matches a manifest entry also selects the vendored ledger entry that entry claims and every hosted pin of the same package release under any patch uuid (one owned pin per release — `remove` parity); an identifier matching nothing anywhere is the familiar exit-1 error. Path globs use the same matcher as `scan [PATHS]` (ancestor rule, `require_literal_separator`, absolute-only outside `--cwd`, Windows case-insensitive): installed copies of every candidate purl are discovered and purls with ≥ 1 matching copy are selected. Scoping sentences (shared with scan):

* **A target that selects nothing is an error on `rollback` (exit 1) and an empty scan on `scan` (exit 0).** Each rollback path pattern must select at least one patched package; the error names the pattern and the reachability rule.
* **Path targets select installed copies; entries with no installed copy are reachable only by identifier or unscoped runs.**
* **Rollback restores every installed copy of a selected patch** — patches are tracked per-package, not per-path; copies restored outside the given patterns are surfaced as an `out_of_scope_copies_restored` warning, never skipped.

`--ecosystems` narrows every leg.

### Default behavior: full-state rollback (MAJOR)

A bare `rollback` (or a scoped one, for its scope) restores the SYSTEM to unpatched and cleans up the local state, in phases under one `apply.lock` acquisition:

1. **State discovery.** A missing manifest is no longer fatal when the vendor ledger or the lockfiles' hosted pins hold work (`rollback` runs manifest-less on hosted-only / vendored projects — every `scan`/`get --mode vendored` and v5 `scan --mode hosted` project is manifest-less). The **truly-empty** project — no manifest, no vendor ledger, no hosted pin — keeps the legacy "Manifest not found" exit 1 (JSON: the legacy `{status: "error", error: "Manifest not found", path}` shape), with one v5.0 exception: when a pre-v5 `.socket/vendor/redirect-state.json` is the only thing left, nothing pins it any more, so a wet run deletes it and exits 0 (human `Removed the pre-v5 hosted ledger .socket/vendor/redirect-state.json: no lockfile pins a hosted patch.`, `Would remove …` on `--dry-run`, which deletes nothing; JSON `{status: "success", rolledBack: 0, alreadyOriginal: 0, failed: 0, dryRun, warnings, legacyRedirectLedgerRemoved}` — a minimal envelope without the keys below; a failed delete is the `legacy_redirect_ledger_kept` warning, still exit 0). A project whose lockfiles still reference `.socket/vendor/` artifacts but whose vendor ledger is missing errors asking for `.socket/vendor/state.json` to be restored from version control first (v5.0: `repair` no longer reconstructs the ledger). **Corrupt-ledger containment**: an unreadable vendor ledger fails ONLY the legs that need it — the vendored leg, manifest cleanup, and GC are skipped fail-closed (`vendor_state_unreadable` warning) while the agent and hosted legs still run; it drives `partial_failure` exit 1, and an emergency restore is never blocked by it. When the ONLY state on disk is an unreadable vendor ledger, the run fails closed naming the store. A pre-v5 redirect ledger is never read by rollback (v4's `redirect_state_unreadable` is no longer emitted). Under `--global`/`--global-prefix` the project's hosted pins and vendor ledger are not discovered at all, so the vendored and hosted legs below do not run (see "Global scope never touches the project's state").
2. **Agent leg** — the existing in-place restore machinery, unchanged (v5.0 presentation: the human `No patches found in manifest` line prints only for an unscoped run with no work in ANY leg — a run whose work is all vendored/hosted stays quiet about the manifest): multi-copy restore, release-variant narrowing, the before-blob gate (+ on-demand download; a gate abort still exits 1 with per-package `missing_blob` failure results **and** skips manifest cleanup + GC entirely — nothing was restored, and the retry's revert data must survive), local-go redirect drop, and the `not_installed` exit-0 asymmetry verbatim. Vendor-owned purls are still excluded here (see the vendored-mode section) — they are handled by the next leg instead of being punted to other commands.
3. **Vendored leg** — each in-scope ledger entry (embedded-record entries included) is reverted through the vendor backends: lockfile wiring restored, artifact dir deleted (and its emptied `.socket/vendor/<eco>/` husk pruned, v5.0), ledger entry dropped + persisted per purl (crash-consistent, like `vendor --revert`). A **drift-keep** (the backend refused a drifted lock) keeps the entry, the artifact, AND the manifest record (`vendoredKept`, exit 1 — the system is still patched); a failure is recorded and other entries proceed.
4. **Hosted leg** — each in-scope hosted pin is restored to its default upstream registry entry; see "Hosted unwind coverage" below. After a hosted leg with no failure, a wet run deletes a pre-v5 `redirect-state.json` once no lockfile pins a hosted patch any more (a failed delete is the `legacy_redirect_ledger_kept` warning).
5. **Manifest cleanup** — entries are removed ONLY for in-scope purls whose legs fully succeeded, were not-installed, or were release-variant siblings narrowed away by an attempted variant that succeeded (half a variant group never lingers — `remove` parity); drift-kept and failed purls keep their records, and a failed variant holds its whole group. A manifest record that a live hosted pin has superseded (the lockfile wires the same package release to a different patch uuid, e.g. an agent → hosted migration after the patch was replaced) and whose installed copy holds neither side of the record is not restored in place and does not fail the run: the hosted leg's lock restore and the next install unwind it, and the record leaves the manifest with the `rollback_record_superseded` warning (`remove` does the same instead of aborting before its hosted leg). A copy still holding the record's patched bytes is restored as usual. No-op removals never rewrite the file. A failed write surfaces as `manifest_write_failed` (warning + `partial_failure` exit 1; GC still runs against the unchanged manifest).
6. **GC** — blob, diff and legacy package-archive sweeps against the post-removal manifest, using the same artifact-reference policy as `remove`, retaining beforeHash blobs for (a) removed-but-not-installed entries (a crawler miss must not destroy the only local revert data — `remove` parity) and (b) EVERY entry remaining in the post-removal manifest — still-active patches (failed, drift-kept, eco-/path-excluded) keep their revert data, so a scoped or failed run never destroys the blobs a later rollback needs; only blobs referenced solely by genuinely-removed entries are swept. GC errors warn (`cleanup_failed`) and continue — they never affect the exit (repair's posture).

**Confirmation prompt.** A wet, non-preserve run with work prompts once, remove-style, composing only the clauses that apply into one English list (`a and b`, `a, b, and c`) with counted nouns: `Roll back N patches`, `remove them from the local manifest`, `delete M vendored artifacts and their ledger records`, `restore H hosted packages to the upstream registry` (e.g. `Roll back 1 patch, remove it from the local manifest, and restore 1 hosted package to the upstream registry?`) — default yes, auto-accepted under `--yes`/`--json`/non-TTY (the shared `confirm` semantics; CI unaffected). Decline prints `Cancelled; no changes made.` (stdout) and exits 0. `--dry-run` and `--preserve-state` runs are prompt-free (they delete no local state).

### `--preserve-state` (opt-out, both `rollback` and `remove`)

Restore the system but keep the local patch state for a later re-apply: manifest entries kept, vendored artifacts + ledger entries kept byte-identical (only the lockfile wiring is reverted; the already-reverted wiring records replay as silent no-ops on a later revert, and a re-vendor re-wires from the live lock), and all blob/archive GC skipped. **Hosted pins have no preservable local state**: the lockfile pins are the only record, so a preserve run still restores them to upstream — surfaced as the `hosted_state_not_preservable` warning (re-run `scan --mode hosted` to re-wire). Caveat (documented): preserved vendored entries may be reclaimed by an explicit later `scan --prune` (user-invoked GC); `vendor` re-runs re-wire them.

**Lock discipline**: the manifest and vendor ledger are LOADED under the apply lock (only cheap existence probes and the read-only hosted-pin discovery run before it; the upstream restore re-reads every file it rewrites under the lock), so a concurrent run's writes are never clobbered by a stale pre-lock snapshot. **Residue rule (v5.0)**: a reversal that empties the vendor ledger deletes `vendor/state.json` (and a pre-v5 `redirect-state.json` is retired as above) and prunes the emptied `.socket/vendor/<eco>/` and `.socket/vendor/` directories (non-recursive, so a pre-v5 `redirect-state.json.corrupt` quarantine or any other stray file keeps its directory alive — the one sanctioned `.socket/vendor/` residue); emptied `blobs/`, `diffs/` and `packages/` stores are removed by the GC sweep; `.socket/` itself is removed by the lock guard when the run leaves it empty, so a fully unwound hosted or vendored project has no `.socket/` at all. What legitimately survives a full reversal: `.socket/manifest.json` at `{"patches": {}}` (+ its `setup` block — never deleted, see the exit-code section), the setup-owned `.socket/.gitignore`, `gem-plugin-stamp` and `bundler-plugin/`, and `.corrupt` quarantine files.

### Hosted unwind coverage

v5.0 replaces v4's per-purl reverts and whole-ledger reverse replay (`revert_remaining_redirect_edits`) with ONE mechanism, the **upstream restore** (core `patch/redirect/upstream/`), shared by `rollback`, `remove` and the hosted → vendored takeover:

* **Scope.** The hosted pins are what lockfile discovery finds — `(purl, patch uuid, files wiring it)`, recognized only on `https://patch.socket.dev` or the `--patch-server-url` / `SOCKET_PATCH_SERVER_URL` origin. A scoped rollback (paths / identifiers / `--ecosystems`) restores exactly the pins in scope; each pin restores or refuses on its own (there is no whole-ledger replay, and a pre-v5 ledger's edits are never replayed). A pin discovery cannot see is out of reach: a lockless cargo `registry = "socket-patch-<uuid>"` pin, a nuget exact-id mapping with no `packages.lock.json`, a gem wired only in the `Gemfile` (pre-bundler-2.6 mixed state) — restore those files from version control.
* **What a restore does.** Every file wiring the pin is rewritten back to the DEFAULT UPSTREAM registry entry for `name@version`, re-resolving whatever the entry pins (tarball URL, integrity, checksum, hashes) from the public registry; only the hosted entries change and every other byte stays the file's own. A pin is **all-or-nothing**: refused in one of its files, it is restored in none of them, so no pin is left half hosted. Nothing reaches disk until every pin has resolved, and `--dry-run` resolves exactly like a wet run — registry lookups included — and skips only the write. Per format:
  * **npm family** — `package-lock.json` / `npm-shrinkwrap.json`, `yarn.lock` (classic and berry), `pnpm-lock.yaml` / `shrinkwrap.yaml`, `bun.lock`: resolution + integrity (+ shasum where recorded) from the npm registry's version document (`SOCKET_NPM_REGISTRY`); a yarn berry lock whose `.yarnrc.yml` names another `npmRegistryServer` reads that registry's document instead, so a mirror's off-path `dist.tarball` keeps its `::__archiveUrl=` binding (falling back to the default registry, with `upstream_registry_fallback`, when the mirror can't be read). Side settings: a project `.npmrc` that is exactly `allow-remote=all\n` is deleted once no root npm lock entry is hosted, otherwise a remaining top-level `allow-remote=all` warns `npm_allow_remote_left`; a `pnpm-workspace.yaml` that is exactly the scaffold hosted mode creates is deleted once `pnpm-lock.yaml` is no longer hosted, otherwise a remaining `trustLockfile: true` warns `pnpm_trust_lockfile_left`. **`bun.lockb` (binary)**: `rollback` and `remove` refuse it (the checkout remedy). The hosted → vendored takeover and the eject DO restore it, since the vendor ledger then records the rebuilt record as its pre-vendor original: the native codec turns each hosted remote-tarball record back into Bun's npm registry record for `name@version` (the registry's `dist.tarball` + `dist.integrity`, the package metadata hash re-derived, the hosted URL string dropped from the string pool). The hosted rewrite keeps the registry record's inactive bytes (padding, semver) in the tarball record, so a lock it wrote comes back byte for byte — early writers' uninitialized padding included; a record without them (an older socket-patch or a Bun re-save) is rebuilt the way Bun writes one, and refused for a prerelease/build version. A lock the hosted rewrite had to normalize is marked in the root package's resolution value bytes (which no Bun reader reads): a binary format 1 lock it promoted to format 2 is demoted back to its exact format-1 bytes (verified by promoting it again, otherwise refused), and a lock whose workspace dependency behaviors it normalized is refused with the `git checkout -- bun.lockb` remedy.
  * **vlt** — `vlt-lock.json`: slot [2] from the registry's `dist.integrity`, slot [3] per the lock's own convention (see the vlt hosted-mode contract); every hosted instance of the pin together.
  * **cargo** — `Cargo.lock` back on crates.io (source + the sparse index's checksum, `SOCKET_CRATES_INDEX`); every `Cargo.toml` declaration loses its `registry = "socket-patch-<uuid>"` pin (the shorthand the rewriter produced collapses back); every `[registries.socket-patch-<uuid>]` block no manifest or lock still references leaves the project cargo config — including a superseded patch generation's block an earlier re-pin left behind (#864). A declaration it cannot unpin refuses.
  * **golang** — the hosted `replace` and the socket module's go.sum lines go; the upstream module's two go.sum lines come back, hashed from the module proxy (`SOCKET_GOPROXY`, else `GOPROXY` / `GONOPROXY` / `GOPRIVATE` as go reads them) and cross-checked against the checksum database (`SOCKET_GOSUMDB_URL`, else `sum.golang.org` unless `GOSUMDB=off` / `GONOSUMDB` / `GOPRIVATE` say go would not ask it). A `replace` the user had before the hosted run is not recorded anywhere, so the restore lands on the plain upstream module.
  * **pypi** — `Pipfile.lock`, `requirements.txt` (+ in-root `-r` includes), Hatch PEP 508 direct references (`pyproject.toml` / `hatch.toml`), `poetry.lock`, `pdm.lock`, `uv.lock`, PEP 723 script locks and PEP 751 `pylock*.toml` (+ the paired `pyproject.toml` / script metadata): hashes re-derived from PyPI's JSON API (`SOCKET_PYPI_JSON_API`). A restored `requirements.txt` line gets `--hash` options only when the file is in pip's hash-checking mode. The mode is read off the file's other requirement lines (an `-e` / `--editable` line means unhashed). When every requirement is a hosted pin, it is read off the hosted line itself (`--hash` vs a `#sha256=` url fragment) (#410). Refused: a `pdm.lock` without `cross_platform`, or a uv / script / pylock lock, whose release has a wheel that is not pure Python 3 (which files the lock keeps is not re-derivable); a uv lock whose options filter files (`exclude-newer`, `no-binary`, `no-build`), or whose other registry packages name no registry, several, or one other than PyPI's simple index; a pylock whose other registry packages show neither an `index` nor (as `uv pip compile` writes them) only PyPI files with none, which restores the entry without an `index` too; uv 0.2 `[[distribution]]` locks. Restored artifact fields keep the spelling the lock's other entries show, including the `upload_time` that uv 0.6.15–0.6.17 write. A restored pylock entry's `upload-time`s are whole seconds, as uv writes them, unless the lock's other entries show fractions. Its artifacts come back in the TOML spelling the other entries use: uv's inline `wheels = [{ … }]`, or the standard tables `pip lock` writes (`[[packages.wheels]]` with a `[packages.wheels.hashes]` sub-table, `[packages.sdist]`). A `pip lock` file (`created-by = "pip"`) records only the artifact pip selected, so the entry is restored with only the release's wheel (its sdist when it has none), and a release with several wheels is refused. A transitive `override-dependencies` entry hosted mode added is removed (`upstream_uv_override_removed`).
  * **gem** — `Gemfile.lock` / `gems.locked` + `Gemfile` / `gems.rb`: the spec moves back into the upstream `GEM` section (or the Socket remote leaves a merged section), the `source "<patch registry>" do … end` block is undone, the `CHECKSUMS` entry is re-pinned from the rubygems.org compact index (`SOCKET_RUBYGEMS_URL`) and the `DEPENDENCIES` pin loses its `!`. The declaration's original constraint is not recorded, so it comes back as the exact pin `gem "<name>", "<version>"`. A transitive gem (one the manifest never declared) gets an appended block with a blank line before it; the restore removes that block, its blank line and the `DEPENDENCIES` entry, so the pair comes back byte for byte. An appended block with no blank line before it (written by a release before this one) can't be told apart from an in-place rewrite, so it still comes back as the exact pin. Refused: an ambiguous upstream section, an upstream remote other than rubygems.org.
  * **composer** — `composer.lock`: `dist` and the deleted `source` block from packagist's composer v2 metadata (`SOCKET_PACKAGIST_URL`). Refused unless the entry is packagist-sourced and packagist still serves the lock's `dist.reference` for the version.
  * **maven** — `pom.xml` (the `-socket.<hex8>` version suffix, the added `<repository>` / `<dependencyManagement>` entry) and the `.mvn/maven.config` / `.mvn/checksums/checksums.sha256` lines hosted mode writes: **no network**, so it restores under `--offline` too. `.mvn` files holding anything else keep the resolver lines (`maven_trusted_checksums_left`).
  * **nuget** — `nuget.config` loses the `socket-patch-<uuid>` source and its exact-id mapping; every `packages.lock.json` entry of the id gets nuget.org's `contentHash` back (`SOCKET_NUGET_URL`). Refused when the restored config would not resolve the id from nuget.org alone. A config hosted mode created from scratch is kept (`nuget_default_config_left`).
  * Any other file wiring a pin refuses it (`socket-patch cannot re-derive the upstream entry in <files>`).
* **Refusals.** `--offline` refuses every pin whose restore needs a registry lookup (all but maven), as does a registry that does not answer or no longer describes the entry. A refused pin writes nothing; its message is `cannot restore <purl> to its upstream registry entry: <why>; restore it from version control instead (`git checkout -- <files>`)` — human `Error: Cannot restore …` on stderr (even under `--silent`), JSON `hosted.failed[{purl, error}]`, and `partial_failure` exit 1 (`remove`: the `hosted_revert_failed` error). A write failure after every pin resolved is one `hosted.failed` entry with the pseudo-purl `files`.
* **Output.** Human `Restored <purl> to its upstream registry entry` / `Would restore <purl> to its upstream registry entry` (`--dry-run`). vlt: the stale installed copies of restored nodes are removed afterwards, as before (`--no-vlt-install-cleanup` keeps them).

### JSON envelope (legacy shape + additive always-present keys)

`rollback --json` keeps its legacy top-level shape (`status` — `"success"` \| `"partial_failure"` — `rolledBack`, `alreadyOriginal`, `failed`, `dryRun`, `results[]`) and adds these keys, ALL always present so consumers never null-check:

| Key | Shape | Meaning |
|---|---|---|
| `warnings` | `[{code, detail}]` | Run-level warnings, now populated (previously always empty): `reinstall_required`, `hosted_state_not_preservable`, `out_of_scope_copies_restored`, `vendor_state_unreadable`, `cleanup_failed`, `manifest_write_failed`, `legacy_redirect_ledger_kept`, the upstream-restore advisories (`npm_allow_remote_left`, `pnpm_trust_lockfile_left`, `maven_trusted_checksums_left`, `nuget_default_config_left`, `upstream_uv_override_removed`, `upstream_registry_fallback`), `ownership_not_restored` (a restored file whose ownership could not be put back — see the apply warnings), `rollback_record_superseded` (a manifest record superseded by a live hosted pin, left to the hosted leg — see Manifest cleanup), plus vendored/hosted leg advisories. New codes are additive (MINOR) |
| `vendored` | `[purl]` | **Meaning narrowed (MAJOR)**: vendor-owned purls the run did NOT act on — today exactly the corrupt-vendor-ledger skip. |
| `vendoredReverted` | `[purl]` | Ledger entries cleanly reverted this run (unwired + artifact deleted + entry dropped; previewed on dry-run) |
| `vendoredPreserved` | `[purl]` | `--preserve-state`: unwired with artifact + ledger entry kept |
| `vendoredKept` | `[{purl, reason}]` | Drift-keeps — wiring drifted, vendored state (and the manifest entry) left untouched; drives exit 1 |
| `vendoredFailed` | `[{purl, error}]` | Vendored reverts that errored — entry, artifact, and manifest record all survive for a retry; drives exit 1 |
| `hosted` | `{reverted: [purl], failed: [{purl, error}], unsupported: [purl], editedFiles: N}` | The hosted leg (v5.0: the upstream restore). `reverted` lists the pins restored (would-be on dry-run); `failed` the refused pins with the version-control remedy in `error` (the pseudo-purl `files` for a write failure); `unsupported` is kept for shape and is always empty (every ecosystem has a restore); `editedFiles` counts distinct files rewritten |
| `manifest` | `{removedEntries: [purl], preserved: bool}` | Entries removed from the manifest (would-be removals on dry-run); `preserved` mirrors `--preserve-state` |
| `gc` | `{skipped: true}` \| `{removedBlobs, removedDiffArchives, removedPackageArchives, bytesFreed}` | Skipped under `--preserve-state`, after a blob-gate abort, and under a corrupt vendor ledger |
| `paths` | `[string]` | The path-glob targets verbatim (empty when none) |

**Exit rules**: not-installed entries never flip the exit (the documented apply/rollback asymmetry — even an all-not-installed run exits 0 `success`). Everything that leaves the system still patched DOES flip it to `partial_failure` exit 1: agent-leg failures, vendored drift-keeps and revert failures, hosted refusals, a corrupt vendor ledger, and a failed manifest write. GC failures never affect the exit.

## Self-update contract (`socket-patch --update`)

`socket-patch --update [VERSION]` replaces the running binary with a release from `https://github.com/SocketDev/socket-patch/releases` — the same artifacts, `SHA256SUMS` verification, and asset naming `install.sh` uses. It is for **standalone installs** (install.sh, manual tarball copy); every other channel is refused with that channel's own upgrade command.

Synopsis and behavior:

| Invocation | Behavior |
|---|---|
| `--update` | Resolve the latest release; install it if newer than the running version. Already-newest (including a dev build newer than any release): informational no-op, exit 0. `latest` never downgrades. |
| `--update 3.4.0` | Install exactly that version, **up or down** — an explicit pin is explicit intent, no `--force` needed. Pin == current: no-op, exit 0. The inline `--update=3.4.0` spelling is equivalent. Also settable via `SOCKET_PATCH_VERSION` (the same pin env `install.sh` honors); a malformed version is a usage error (exit 2). |
| `--update --force` | Reinstall/downgrade even when already at the target version, and proceed past a managed-install refusal (with a warning that the owning manager's next upgrade will overwrite the binary). Env: `SOCKET_FORCE`. |
| `--update --dry-run` | **Check-only**: one metadata request, zero downloads, zero mutation, exit 0 — and always the `verified`/`update_check` event shape, whether or not an update exists. `--json` details carry `{current, latest, updateAvailable, target, asset, path}` — the cheap scriptable "is an update available" probe. |
| `--update --offline` | Refused up front (strict airgap, before any client exists), exit 1. `--force` does **not** bypass it. |

Honored global flags: `--json`, `--silent` (errors only), `--yes` (skip the confirm prompt; `--json` also auto-confirms), `--dry-run`, `--offline`, `--verbose`, `--debug`, `--no-telemetry`. Other global flags parse and are ignored (the `list --global` precedent).

**Managed-install refusal.** The canonicalized executable path (symlinked invocations resolve to the real file) is classified before any network I/O; non-standalone channels exit 1 with `errorCode: managed_install` and an upgrade or migration command:

| Detected channel | Hint |
|---|---|
| npm (`node_modules` path component) | project-local (the directory holding the outermost `node_modules` has a `package.json`, and it is not directly under `lib`/`npm` or below a yarn/pnpm `global` store): `npm install @socketsecurity/socket-patch@latest`, or `vlt install @socketsecurity/socket-patch@latest` when that directory holds `vlt-lock.json`, or `vlx -y -- @socketsecurity/socket-patch@latest …` when its `package.json` is vlx's (`"name": "vlx"`, the vlx cache); otherwise global (including version-manager prefixes such as nvm-windows and fnm): `npm update -g @socketsecurity/socket-patch` |
| Legacy PyPI wheel (`site-packages`/`dist-packages`) | `pip uninstall socket-patch` followed by the standalone installer (macOS/Linux) or `npm install -g @socketsecurity/socket-patch` (Windows) |
| `cargo install` (`$CARGO_HOME/bin`, `~/.cargo/bin`) | `cargo install socket-patch-cli` |
| Legacy gem launcher cache (`<cache>/socket-patch/bin/…`) | `gem uninstall socket-patch` followed by the standalone installer (macOS/Linux) or `npm install -g @socketsecurity/socket-patch` (Windows) |
| Homebrew (`Cellar`, `/opt/homebrew`) | `brew upgrade socket-patch` |

v5 publishes only standalone binaries, Cargo crates, and npm packages. Legacy
PyPI and RubyGems locations remain detectable so self-update does not silently
replace a binary owned by an old package. The standalone migration command is
`curl -fsSL https://install.socket.dev/patch | sh`.

**Pipeline order** (each step gates the next; a failure at any point leaves the installed binary untouched): fetch `SHA256SUMS` → fetch the archive (`socket-patch-<target-triple>.tar.gz`/`.zip`, explicit timeouts, size caps) → verify the SHA-256 **before** extraction → extract the single expected member → stage as an executable sibling **in the install directory** (`EACCES` here is the permissions preflight → exit 1 with a sudo hint; system temp is never used, so `noexec` mounts don't matter) → run the staged binary's `--version` self-check (against real GitHub the reported version must equal the release tag; under a `SOCKET_UPDATE_BASE_URL` override a mismatch only warns) → one atomic rename over the install path (mode-preserving; a **setuid/setgid** target — or, on Linux, one carrying **file capabilities** (`setcap`) — is refused, since an unprivileged swap cannot restore those grants; Windows uses the rename-dance via `self-replace`). Concurrent updates are single-flighted per environment by an advisory lock at `<state dir>/update.lock` (`errorCode: update_in_progress`; the OS releases a dead holder's lock, so there is no stale-lock state). Two updaters whose state dirs diverge (e.g. different `$HOME`s targeting one shared `/usr/local/bin`) are not serialized, but every path to the destination is a whole-file rename and stage cleanup is age-gated — the worst case is duplicated work, never a torn binary.

**Envelope.** `command: "update"`. Success events: `downloaded` (`details: {asset, bytes, sha256}`) then `updated` (`details: {from, to, path, target}`). No-op: `skipped` with reason `already_latest`. Dry-run: `verified` with reason `update_check`. Non-fatal advisories ride the run-level `warnings[]` (`{code, detail}`, omitted when empty) — human runs print the same text to stderr as `Warning: <detail>` (first letter capitalized), and `--json` (which silences stderr) carries them here instead so an override is never silent: `managed_install_override` (a `--force` run replaced a package-manager-owned binary that manager's next upgrade will overwrite) and `update_warning` (a non-fatal note from the update engine, today the relaxed version self-check under a `SOCKET_UPDATE_BASE_URL` override). Top-level `errorCode` values (stable): `offline`, `managed_install`, `check_failed`, `asset_not_found`, `download_failed`, `checksum_mismatch`, `verify_failed`, `swap_failed`, `permission_denied`, `update_in_progress`. Exit codes: 0 success / no-op / dry-run; 1 operational failure; 2 usage.

**Trust model.** Checksum-only, rooted in HTTPS + GitHub (identical to install.sh): `SHA256SUMS` is served from the same origin as the archives, there are no signatures yet. Downloads are credential-free — the Socket API bearer is never sent to the release host — and non-HTTPS redirect hops are refused when talking to the default endpoints.

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

Public configuration uses the `SOCKET_*` names below. The three deprecated v3/v4 environment aliases were removed in v5; see [Removed env vars](#removed-env-vars).

Four `SOCKET_CLI_*` names from the sibling JS Socket CLI are additionally accepted as **peer aliases** (supported, not deprecated — no warning): `SOCKET_CLI_API_TOKEN` → `SOCKET_API_TOKEN`, `SOCKET_CLI_ORG_SLUG` → `SOCKET_ORG_SLUG`, `SOCKET_CLI_API_BASE_URL` → `SOCKET_API_URL`, `SOCKET_CLI_NO_API_TOKEN` → `SOCKET_NO_API_TOKEN`. The canonical `SOCKET_*` name always wins when both are set; promotion is silent and happens in-process before clap parses. Other socket-cli names (`SOCKET_CLI_CONFIG`, `SOCKET_CLI_API_PROXY`, `SOCKET_CLI_DEBUG`) are deliberately **not** honored.

Empty string means unset at every layer: exported-but-empty flag-bound vars are scrubbed before clap parses, and the API-client resolution filters empty values at each fallback step.

| Env var | CLI equivalent | Default | Notes |
|---|---|---|---|
| `SOCKET_CWD` | `--cwd` | `.` | — |
| `SOCKET_MANIFEST_PATH` | `--manifest-path` | `.socket/manifest.json` | — |
| `SOCKET_API_URL` | `--api-url` | `https://api.socket.dev` | — |
| `SOCKET_API_TOKEN` | `--api-token` | (none) | Absence selects the public proxy. |
| `SOCKET_ORG_SLUG` | `--org` / `-o` | (auto-resolve) | — |
| `SOCKET_PROXY_URL` | `--proxy-url` | `https://patches-api.socket.dev` | — |
| `SOCKET_ECOSYSTEMS` | `--ecosystems` / `-e` | (all) | Comma-separated list. |
| `SOCKET_VENDOR_SOURCE` | `--vendor-source` | `service` | `auto` is a compatibility alias for `service`; `build` is rejected. |
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
| `SOCKET_YES` | `--yes` / `-y` | `false` | Skips the prompts of `get`, `rollback`, `remove` and `--update`; `scan` never prompts, so it has no effect there. |
| `SOCKET_LOCK_TIMEOUT` | `--lock-timeout` | (none) | Seconds to wait for `apply.lock` on the lock-taking subcommands (incl. hosted/vendored `scan`/`get`); unset/`0` = single non-blocking try. |
| `SOCKET_DEBUG` | `--debug` | `false` | — |
| `SOCKET_TELEMETRY_DISABLED` | `--no-telemetry` | `false` | — |
| `SOCKET_NO_TRUST_LOCKFILE_CONFIG` | `--no-trust-lockfile-config` | `false` | Hosted mode: skip the `trustLockfile: true` write to `pnpm-workspace.yaml`. |
| `SOCKET_NO_NPM_ALLOW_REMOTE_CONFIG` | `--no-npm-allow-remote-config` | `false` | Hosted mode: skip the `allow-remote=all` write to the project `.npmrc`. |
| `SOCKET_NO_VLT_INSTALL_CLEANUP` | `--no-vlt-install-cleanup` | `false` | Hosted mode, `rollback`, `remove`: keep stale vlt installed copies. |
| `SOCKET_FORCE` | `apply --force` / `-f`, `vendor --force` / `-f`, `--update --force` | `false` | Local to `apply`, `vendor` and `--update`. |
| `SOCKET_PATCH_VERSION` | `--update <VERSION>` | (latest) | Local to `--update`; the same pin `install.sh` honors. |
| `SOCKET_BATCH_SIZE` | `scan --batch-size` | `500` authenticated / `100` proxy | Local to `scan`. |
| `SOCKET_MAX_NEW_PATCHES` | `scan --max-new-patches` | (unlimited) | Local to `scan` (v5.0): a count or `none`; empty is unset, malformed exits 2. |
| `SOCKET_SCAN_PACKAGES` | `scan --package` | (none) | Local to `scan` (v5.0); comma-separated names or purls. |
| `SOCKET_NO_SOCKET_YML` | `scan --no-socket-yml` | `false` | Local to `scan` (v5.0); bool vocabulary, empty = unset. |
| `SOCKET_MIN_SEVERITY` | `scan --min-severity` | (none) | Local to `scan` (v5.0); read by scan (not clap) so the `policy` block can say `source: "env"`; empty = unset, malformed = exit 2. |
| `SOCKET_SAVE_ONLY` | `get --save-only` | `false` | Local to `get`. |
| `SOCKET_ALL_RELEASES` | `get --all-releases` / `scan --all-releases` | `false` | Local to `get`/`scan`. Download patches for every release/distribution variant, not just the installed one. |
| `SOCKET_SKIP_ROLLBACK` | `remove --skip-rollback` | `false` | Local to `remove`. Conflicts with `--preserve-state`/`SOCKET_PRESERVE_STATE` (exit 2 — see below). |
| `SOCKET_PRESERVE_STATE` | `rollback --preserve-state` / `remove --preserve-state` | `false` | (v5.0) Shared by `rollback`/`remove` (boolish, empty-tolerant parse like the other bool flags): restore the system but keep the local patch state — manifest entries, vendored artifacts + ledger entries — and skip all GC. On `remove`, combining it with `--skip-rollback` is a usage error (exit 2) **whether either side is flag- or env-sourced** (`SOCKET_PRESERVE_STATE=true remove --skip-rollback` exits 2 too). |
| `SOCKET_DOWNLOAD_ONLY` | `repair --download-only` | `false` | Local to `repair`. |
| `SOCKET_VENDOR_REVERT` | `vendor --revert` | `false` | Local to `vendor`. |
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
- **Repo-level files never carry endpoints, credentials, or interlock-disablers**: configuration for those comes only from flags, env vars, this user-level file, and built-in defaults — never from files inside the repository being patched (manifest, socket.yml, `.env`, …). A repository file may **narrow or pace** what `scan` patches (socket.yml's `patches` block and `projectIgnorePaths`, see "socket.yml patch policy"). It may never name an endpoint or credential, pick a mode or download format, turn off a safety check, or make `scan` patch anything it would not patch with no file present; the one exception is negating the built-in test/fixture path ignores, which are repo policy by nature.
- `--debug` names the source on stderr whenever a setting resolves from the socket-cli config (the token value itself is never echoed).

### Registry override env vars

Env-only knobs used for hosted upstream restoration and JVM metadata verification. They do not enable local artifact construction. Trailing slashes are trimmed and empty values use the default.

| Env var | Default | Notes |
|---|---|---|
| `SOCKET_NPM_REGISTRY` | `https://registry.npmjs.org` | Base for npm version documents (`<base>/<name>/<version>`, a scoped name's `/` as `%2f`; `dist.tarball` / `integrity` / `shasum`) the npm-family and vlt upstream restore reads, unless the project names another registry (yarn berry `npmRegistryServer`, vlt's node registry), whose document is read first. |
| `SOCKET_GOPROXY` | `https://proxy.golang.org` | Go module proxy used for upstream restoration, honoring `GOPROXY`, `GONOPROXY` and `GOPRIVATE`. |
| `SOCKET_MAVEN_REGISTRY` | `https://repo1.maven.org/maven2` | maven2 base for the fallback upstream-pom download. |
| `SOCKET_CRATES_INDEX` | `https://index.crates.io` | v5.0 upstream restore: the crates.io sparse index whose `checksum` a restored `Cargo.lock` entry gets back. |
| `SOCKET_GOSUMDB_URL` | `https://sum.golang.org` | v5.0 upstream restore: the checksum database the restored go.sum lines are checked against. Without it, `GOSUMDB=off` or a module matching `GONOSUMDB` (default `GOPRIVATE`) skips the database and the hashes come from the module proxy's bytes alone (`SOCKET_GOPROXY` above). |
| `SOCKET_PYPI_JSON_API` | `https://pypi.org/pypi` | PyPI's JSON API (`<base>/<name>/<version>/json`): the release files whose sha256 the upstream restore writes back into every Python lock format. |
| `SOCKET_RUBYGEMS_URL` | `https://rubygems.org` | v5.0 upstream restore: the compact index (`/info/<name>`) a restored `CHECKSUMS` entry is re-pinned from. |
| `SOCKET_PACKAGIST_URL` | `https://repo.packagist.org` | v5.0 upstream restore: packagist's composer v2 metadata (`/p2/<vendor>/<package>.json`) a restored `composer.lock` `dist` / `source` comes from. |
| `SOCKET_NUGET_URL` | `https://api.nuget.org` | v5.0 upstream restore: the nuget.org API host whose catalog `packageHash` a restored `packages.lock.json` `contentHash` comes from. |

### Internal env vars (no stability guarantee)

These exist for mirrors and testing. They are **internal**: names, semantics, and existence may change in any release without a semver bump.

| Env var | Purpose |
|---|---|
| `SOCKET_UPDATE_BASE_URL` | Points BOTH the release-metadata and asset-download routes of `--update`/the update notice at one base (mirror or test fixture) instead of `github.com` + `api.github.com`. Overriding it relaxes the downloaded binary's version self-check from hard-fail to warning. |
| `SOCKET_UPDATE_STATE_DIR` | Overrides the per-user dir holding `update-check.json` + `update.lock` (tests point it into a tempdir). |
| `SOCKET_UPDATE_TIMEOUT_MS` | Caps the update fetches' connect/metadata/download budgets (defaults 10 s / 30 s / 300 s; the notice's fetch defaults to 2 s). Doubles as the slow-network escape hatch. |
| `SOCKET_UPDATE_NOTIFIER_FORCE` | Test hook: bypasses the update notice's stderr-TTY guard — and nothing else (opt-out, offline, `--silent`, `--json`, CI all still win). |
| `SOCKET_UPDATE_GRACE_MS` | Test hook: overrides the notice's post-command join grace (default 500 ms — how long the run waits for the background check before abandoning it and exiting). Lets the e2e suite await the loopback fetch to completion so its observable effect is deterministic; production keeps the tight 500 ms ceiling. |

### Removed env vars

The v3.0 legacy names `SOCKET_PATCH_PROXY_URL`, `SOCKET_PATCH_DEBUG` and `SOCKET_PATCH_TELEMETRY_DISABLED` were removed in v5.0 and are ignored; use `SOCKET_PROXY_URL`, `SOCKET_DEBUG` and `SOCKET_TELEMETRY_DISABLED`.

## CSV value parsing

`--ecosystems` on `apply`, `rollback`, and `scan` uses clap's `value_delimiter = ','`. Input `--ecosystems npm,pypi,cargo` becomes `vec!["npm", "pypi", "cargo"]`. Switching to space-separated or dropping the delimiter is a **breaking** change.

## JSON output shapes

Every `--json` invocation emits a single JSON object that follows the **unified envelope** below. The envelope was introduced in v3.0; older per-command shapes are deprecated. See `src/json_envelope.rs` for the source of truth; its unit tests pin the serialized names, and each command's e2e tests assert the envelope it emits. The `tests/cli_parse_*.rs` files pin the parsed clap arguments, not this shape (a few, such as `cli_parse_list.rs`, also spot-check `list`'s envelope).

### Envelope shape

```jsonc
{
  "command":  "scan" | "apply" | "vex" | "vendor" | "rollback" | "get" | "list" | "remove" | "repair",
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
      "appliedVia":  "blob"   // only on action=applied; v5.0 drops "package" and "diff"
    }
  ],
  "bytes":      1234,                       // optional (downloaded/removed)
  "reason":     "Files match afterHash",    // human-readable explanation (skipped)
  "errorCode":  "already_patched",          // stable snake_case routing tag
  "error":      "<message>",                // only when action=failed
  "details":    { ... }                     // command-specific extras (see below)
}
```

`files[].path` is the manifest file key (`package/index.js`). A pnpm or vlt package installed as more than one peer-variant store copy is patched (and rolled back) in every copy; a file of a copy other than the one the package resolved to is listed under that copy's on-disk path (`…/.pnpm/foo@1.0.0_react@18.3.1/node_modules/foo/index.js`). So a run that wrote only such a copy reports `applied` with that file, not `already_patched`, and rollback's `filesRolledBack` / `filesVerified` carry the same paths (it counts the package in `rolledBack`, not `alreadyOriginal`).

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
| `rebuilt`    | `repair`                              | A missing/corrupt vendored artifact was restored from its exact server download (v5.0: never a lost ledger entry — see `vendor_ledger_missing`). `summary.rebuilt` counts these (the field is omitted while zero). |

### Stable `errorCode` tags

| Tag                       | Action(s)        | Context |
|---------------------------|------------------|---------|
| `already_patched`         | `skipped`        | apply: every file's hash already matches `afterHash`. |
| `package_not_installed`   | `skipped`        | apply: manifest entry has no matching installed package. When the project's lockfiles resolve the purl (a platform-gated optional dependency, a devDependency under `--omit=dev`), the detail says it is lockfile-only and the entry never fails the run, even when no other patch matched; only an all-miss run with an unmatched purl that no lock resolves exits 1 (`partialFailure`). |
| `apply_failed`            | `failed`         | apply: hash mismatch, write error, archive read error. |
| `no_local_source` | `skipped`/`failed` | Agent patch application cannot obtain the required local or downloaded patch source. Vendored mode consumes complete server artifacts and no longer stages patch blobs. |
| `offline_missing_sources` / `sources_download_failed` | apply run-level `warnings[]` | apply (additive): the patch sources were unavailable — `--offline` with no local source, or the download left a patch with no source — so nothing was attempted. The envelope keeps its pinned shape (`partialFailure`, empty `events[]`, zero summary, no top-level `error`); the warning is its machine-readable reason (the human path prints the staging `Error:` line on stderr instead, even under `--silent`). |
| `paid_required`           | `failed` / status=`paidRequired` | get/scan: patch needs a paid plan and the caller's token isn't entitled. `get <uuid>` on the public proxy reports it (exit 0) both for a `tier: "paid"` view and for the proxy's 403 refusal, whose record then carries only `uuid` + `tier` (the proxy never named the purl). |
| `download_failed`         | `failed`         | repair/get: network or 404 on patch fetch. |
| `cleanup_failed`          | `skipped` (warning) | repair: an orphan-sweep pass (blobs, diff or package archives) failed mid-way (e.g. permission error). The run continues and exits 0; human mode carries the warning on stderr (not muted by `--silent`). v5.0: `rollback`'s default GC surfaces the same condition in its run-level `warnings[]` (and `remove`'s extended archive GC on stderr) — same posture, never affects the exit. |
| `rollback_failed`         | `failed`         | remove/rollback: file restore could not complete. |
| `vendored`                | `skipped`        | apply (every ecosystem) + scan `--apply`: the package is managed by `socket-patch vendor`; the command yields ownership (scan also skips the download). v5.0: rollback no longer yields — its vendored leg reverts these entries by default, and its `vendored: []` array is reserved-empty (a corrupt vendor ledger surfaces via the `vendor_state_unreadable` warning + exit 1 — the skip cannot name purls, since naming them needs the ledger). Scan `--apply --json` additionally surfaces one run-level `vendored_ownership_retained` warning naming the skipped purls (additive; exit/status unchanged). |
| `vendor_reverted`         | `removed`        | remove: vendoring reverted (lock fragments restored, artifact + ledger entry gone) as part of removing the patch. |
| `vendor_revert_failed`    | top-level error  | remove: the vendor revert failed; the manifest was NOT modified. |
| `vendor_state_retained`   | `skipped`        | remove `--skip-rollback`: vendor wiring + artifact deliberately left in place (the next `vendor` run reconciles the dropped entry). Also the top-level error code when `--skip-rollback` targets a vendored patch with no manifest record (every `scan`/`get --mode vendored` entry — and, v5.0, the ledger-only leftover of an earlier `remove --skip-rollback` of a manifest-tracked vendored patch). |
| `hosted_state_retained`   | (top-level error) | remove `--skip-rollback` targeting a hosted-only patch (no manifest entry): restoring the pin's upstream registry entry is the only possible removal, so the combination is refused (exit 1), mirroring the manifest-less vendored refusal above. |
| `vendor_state_preserved`  | `skipped`        | remove `--preserve-state` (v5.0): lockfile unwired; artifact, ledger entry, and manifest entry all kept for a later re-apply. Rollback's counterpart is the `vendoredPreserved: []` envelope array. |
| `vendor_revert_kept`      | `skipped` + top-level error | remove (v5.0): the vendored revert drift-kept (`kept_artifact`), so the ledger entry AND the manifest entry were both kept. ANY drift-keep makes the run a `partialFailure` (exit 1) — part of the requested removal did not happen; when EVERY matching entry drift-kept, the top-level error carries this code (`summary.removed` stays 0; the identifier DID match, so never `not_found`). Remedy: re-run `scan --mode vendored` to normalize, then remove. Rollback's counterpart is the `vendoredKept: []` envelope array (also exit 1). |
| `hosted_reverted`         | `removed`        | remove (v5.0): a hosted lockfile pin was restored to its upstream registry entry as part of removing the patch (`verified` on dry-run). Beside a manifest entry it bypasses `summary.removed` like `vendor_reverted`. |
| `hosted_revert_failed`    | top-level error  | remove (v5.0): a matched hosted pin could not be restored to its upstream registry entry (`--offline`, a registry that does not answer, `bun.lockb`, a lock shape the restore refuses — see "Hosted unwind coverage"), or writing the restored files failed; the message names the `git checkout -- <files>` remedy. The manifest was not modified, exit 1. Rollback's counterpart is a `hosted.failed[]` entry (also `partial_failure` exit 1). v4's `hosted_revert_unsupported` is no longer emitted (every ecosystem has a restore). |
| `reinstall_required`      | rollback `warnings[]` | rollback (v5.0): vendored/hosted wiring was unwound, but installed trees keep their patched bytes until the next package-manager install — the stale-install advisory. |
| `hosted_state_not_preservable` | rollback `warnings[]` | rollback `--preserve-state` (v5.0): hosted pins were restored to upstream anyway — the lockfile pins are hosted mode's only record, so there is no local state to preserve; re-run `scan --mode hosted` to re-wire. (`remove --preserve-state` prints the same note on stderr.) |
| `out_of_scope_copies_restored` | rollback `warnings[]` | path-scoped rollback (v5.0): a selected patch had installed copies outside the given patterns; ALL copies were restored (patches are per-package). Informational — never flips the exit. |
| `vendor_ledger_entry_unwired` | scan `warnings[]` | a vendored entry's dependency left the lockfile (upgraded or removed), so the ledger supplement skipped it; the detail names the purls and points at `scan --prune`, which reverts them (no warning on a pruning non-hosted run). An entry that prune drift-keeps (its lock entries were re-resolved since vendoring, e.g. an npm uninstall re-locked it away) is reported on the prune's `GC: kept` line and keeps being warned about. |
| `path_scope_excluded_supplements` | scan `warnings[]` | path-scoped scan (v5.0): lockfile-only / vendor-ledger supplement packages have no installed path and were excluded from the scoped scan; the detail carries the count. |
| `vendor_commit_failed` | top-level error (`vendor`, and the nested vendor envelope of `scan` / `get --mode vendored`) | v5.0 group commit: the run's lockfile / manifest / ledger edits could not be written (the detail names the I/O error). Exit 1; the project's lockfiles and `.socket/vendor/state.json` are left as they were before the run (a partially-applied commit is put back), and the per-package events describe the uncommitted outcome. When putting a partially-applied commit back fails too, the journal is kept instead and the detail says the next socket-patch command in the project finishes the commit. |
| `redirect_symlinked_file_unsupported` (vendored) | top-level error (`vendor`, and the nested vendor envelope of `scan` / `get --mode vendored`) | v5.0 group commit (#627): a file the run would rewrite — a lockfile, `package.json`, `pnpm-workspace.yaml`, `nuget.config`, … — is a symbolic link. The commit stages each file and renames it over the path, which would replace the link with a detached copy and leave its target (the lock other checkouts read) unpatched, so it refuses before writing anything — the same code and message as the hosted guard. Exit 1; the link, its target and `.socket/vendor/state.json` are left as they were, and the per-package events describe the uncommitted outcome (the artifacts written are unreferenced orphans, as for `vendor_commit_failed`). Backends that check their own targets first (bun.lockb, Hatch, uv, Poetry, Pipenv, requirements, Cargo) keep their own codes. |
| `vendor_would_refuse_symlinked_file` | `skipped` (advisory event) under `vendor --dry-run`; a `warnings: [{code, detail}]` entry on the `would_vendor` / `would_revendor` row of the `vendor` preview under `scan` / `get --mode vendored --dry-run` (human: an `[warning] <purl> (<code>): <detail>` line) | dry run (#627): a dry run captures no writes, so for each package it would vendor (not one previewed as in sync, whose re-run writes nothing) it names every symlinked file of that package's ecosystem a vendored run may rewrite (the registry's vendored rewrite targets plus `pnpm-workspace.yaml`, `nuget.config`, `packages.lock.json`, the root `pom.xml`, `.mvn/maven.config` and `hatch.toml`; files a vendored run only reads, such as `.yarnrc.yml` or `vlt.json`, are never named); the wet run refuses with `redirect_symlinked_file_unsupported` if it must rewrite one. Does not change the exit code. |
| `vendor_state_unreadable` | rollback `warnings[]`; remove top-level error | corrupt-ledger containment (v5.0). Rollback: an unreadable vendor ledger skips the vendored leg + manifest cleanup + GC and drives `partial_failure` exit 1 while the agent and hosted legs still run. Remove: a hard top-level error before any mutation. Also the Bun vendored preflight's refusal code: `get` / `scan --mode vendored`, `vendor`'s pre-takeover check and the `--dry-run` `would_refuse` preview report an unreadable `.socket/vendor/state.json` as itself (`errorCode` in `patches[]` / `download.patches[]`, or `get <uuid>`'s top-level `error.code`), fail-closed — nothing is exempt — instead of a Bun lock code. (v4's `redirect_state_unreadable` is no longer emitted: v5 never reads the redirect ledger on these paths.) |
| `manifest_write_failed`   | rollback `warnings[]` | rollback (v5.0): the post-rollback manifest update could not be written; no entries were removed (`manifest.removedEntries: []`) and the run exits `partial_failure` 1. |
| `npm_allow_remote_left` / `pnpm_trust_lockfile_left` | rollback/remove `warnings[]`; vendor advisory event (takeover) | upstream restore (v5.0): no npm-family lock entry is hosted any more, but the project `.npmrc` keeps a top-level `allow-remote=all` (resp. `pnpm-workspace.yaml` keeps `trustLockfile: true`) in a file that is not exactly what hosted mode creates; the file is left untouched (v5 records no provenance), remove the line if nothing else needs it. A file that is exactly hosted mode's own is deleted silently. |
| `maven_trusted_checksums_left` / `nuget_default_config_left` / `upstream_uv_override_removed` | rollback/remove `warnings[]`; vendor advisory event (takeover) | upstream restore (v5.0): `.mvn` config keeps the trusted-checksums resolver lines because it holds more than hosted mode writes; `nuget.config` now holds only the nuget.org source (delete it if hosted mode created it); a transitive `override-dependencies` entry hosted mode added to `pyproject.toml` was removed. |
| `upstream_registry_fallback` | rollback/remove `warnings[]`; vendor advisory event (takeover) | upstream restore: a yarn berry or vlt entry is restored from the version document of the registry the project resolves it against (`.yarnrc.yml` `npmRegistryServer`, vlt's node registry); that registry could not be read (e.g. it needs credentials), so the default registry's document was used and the restored tarball URL may not be the mirror's. |
| `legacy_redirect_ledger_kept` | rollback `warnings[]` (+ remove stderr) | v5.0: a pre-v5 `.socket/vendor/redirect-state.json` could not be deleted once no hosted pin was left; the file is inert (never read for planning). Never flips the exit. |
| `vendor_stale_artifact_removed` | `removed`  | vendor / scan `--vendor`: re-vendor under a newer patch uuid removed the previous uuid's orphaned artifact dir. |
| `vendor_unsupported_ecosystem` | `skipped`   | vendor: no vendor backend for this purl's ecosystem (jsr). |
| `already_vendored`        | `skipped`        | vendor: artifact + wiring already in sync for this patch uuid. |
| `unsafe_coordinates`      | `failed`         | vendor: purl/uuid would escape `.socket/vendor/` (tampered manifest/state); refused before any write. |
| `revert_failed`           | `failed`         | vendor --revert: a recorded entry could not be reverted. |
| `vendor_ledger_missing` | `failed` (artifact-level: `uuid` + `details.{ecosystem,path}`, no purl) | repair (v5.0) and `vendor --check`: a lockfile references `.socket/vendor/<eco>/<uuid>/` but the vendor ledger has no entry for it; repair no longer rebuilds ledger entries from lockfiles. Recovery: restore `.socket/vendor/state.json` from version control and re-run `repair`, or `git checkout -- <lockfile>` and re-vendor. |
| `vendor_wiring_unknown_revert_blocked` | `skipped` (beside the `failed`/`revert_failed` event) | vendor --revert: the ledger entry was reconstructed by a pre-v5 `repair` without wiring records and the live lockfile still resolves through the artifact — the revert refuses (fail-closed) instead of deleting a tarball the lock points at. Recovery: `socket-patch repair`, then restore the pre-vendor lock (or re-lock without the override) and re-run the revert. repair: an npm ledger entry whose `flavor` this release does not know (written by a newer socket-patch) is skipped, never health-checked or rebuilt, and the artifact, wiring and ledger stay as found (a lone `skipped` event; the run's exit is unaffected). Recovery: upgrade socket-patch. |
| `stale_install`           | `skipped`        | vex (in-run `scan --mode hosted --vex`): a hosted stale-install probe found positively unpatched installed bytes, so the purl is omitted even under `--vex-no-verify` (see the gem / Python stale-install guards). |
| `record_unavailable`      | `skipped`        | vex (manifest-less): a lockfile-wired patch has no local record (manifest, this run's hosted records or a pre-v5 redirect ledger, vendor ledger) and none could be fetched — `--offline`, transport error, 404, or a refused (paid) patch. Omitted, never attested from the `socket-patch.vendor.json` marker. |
| `record_mismatch`         | `skipped`        | vex (manifest-less): the record found for a wired patch names another package or another patch uuid than the wiring. |
| `vendor_unwired`          | `skipped`        | vex: a vendor-ledger entry whose committed artifact no lockfile/config wires any more (reverted lock, leftover ledger or artifact). Applies under `--no-verify` too. |
| `redirect_unwired`        | `skipped`        | vex: a hosted record (this run's, or a pre-v5 redirect ledger's) whose hosted patch no lockfile wires any more (and no manifest entry owns the purl). Applies under `--no-verify` too. |
| `wiring_conflict`         | `skipped`        | vex (manifest-less): the lockfiles wire one package to two or more different patches (e.g. a stale sibling lock); which one the build installs is undecidable, so none is attested. |
| `hash_mismatch` / `not_applied` / `file_not_found` / `package_not_found` / `no_files` / `vendor_*` | `skipped` | vex: verification omissions — the installed copy (agent / hosted) or the committed artifact (`vendor_hash_mismatch`, `vendor_artifact_missing`, `vendor_artifact_unreadable`, `vendor_inventory_mismatch`, `vendor_uuid_mismatch`, `vendor_path_unsafe`) does not carry the patched bytes, or nothing is installed. `vendor_manifest_unverifiable`: a vendored vlt directory verified without its vendor ledger (from `vlt-lock.json` alone) holds a `package.json` with its devDependencies stripped, and the patched `package.json` blob is not in `.socket/blobs`, so it cannot be checked. A lockfile-pinned hosted reference with nothing installed attests instead of `package_not_found` (see "Manifest-less VEX"). |
| `not_applied` / `hash_mismatch` / `file_not_found` / `no_matching_variant` | `failed` | `apply --check` (v5.0): an installed copy of the patch does not verify (still unpatched; neither the original nor the patched bytes; a patched file missing; a copy of a release-variant base that holds none of the manifest's variants, keyed by the base purl). Exit 1, status `partialFailure`. |
| `redirect_unconfirmed`    | `redirect.patches[]` `unpinned` row | hosted `scan` / `get` (v5.0, additive): the patch was granted but no lockfile entry pinning it could be rewritten. The status and exit code are unchanged for now, pending the open hosted exit-policy decision (#704); `--silent` hides the human line. |
| `lockfile_unreadable` / `lockfile_unparseable` / `patched_ref_invalid` / `patched_ref_unattributable` | run-level `warnings[]` | vex (every form): lockfile-discovery diagnostics — see "Manifest-less VEX (lockfile discovery)". Never flip the exit on their own. |
| `vendor_multiple_lockfiles` / `pypi_multiple_lockfiles` | `skipped` (warning) | vendor: a sibling lockfile of another package manager (for PyPI, also a root `requirements.txt` that pins the package beside the wired tool lock) will still install UNPATCHED bytes; names the wired winner + the ignored locks. |
| `vendor_yarn_berry_unsupported` | `failed` | vendor (npm): yarn-berry Plug'n'Play layout; use its native `yarn patch` workflow. |
| `vendor_bun_lockb_invalid` | `failed` | vendor / scan / get `--mode vendored`: the binary lock is malformed, unreadable, unsupported or cannot be rewritten safely. The detail names the parser, hash or filesystem error. Refused before patch downloads and before hosted takeover; `patches[]` / `download.patches[]` carry `errorCode` and `error`, while `get <uuid>` also carries top-level `error.code`. Dry-run predicts the same refusal. |
| `vendor_bun_workspace_unsupported` | `failed` | vendor / scan / get `--mode vendored` (bun): the text lock holds `workspace:` packages and its `lockfileVersion` is below 2 — Bun 1.2–1.3 resolve a workspace member's local-tarball path relative to the member; a committed version-2 lock is the proof every consumer runs Bun ≥ 1.4 (deliberate over-approximation: root-only declared packages would install on version 1 too). Detail names the version integer and a version-specific remedy: delete `bun.lock` and re-lock with Bun ≥ 1.4 (an in-place `bun install` keeps the existing version) — then, for a version-1 lock, "or use `--mode hosted`, which accepts version-1 workspace locks"; for a version-0 lock, "or delete `bun.lock`, re-lock with Bun ≥ 1.2 (which writes lockfileVersion 1) and use `--mode hosted`" (hosted refuses version-0 workspace locks, so a bare hosted pointer would send the user into a second refusal). Refused before any write — in the pre-download preflight on `get`/`scan` (see `vendor_bun_lockb_invalid` for the placements); in the shared preflight that `vendor` and the vendor step run BEFORE a hosted → vendored takeover's revert (a hosted-redirected purl stays hosted-wired, ledger and lock untouched; `vendor --dry-run` previews the same `failed` code); and in the engine when the run would write a NEW local tuple. Exempt: purls the vendor ledger wires at the selected uuid, purls whose every `bun.lock` instance is already a `.socket/vendor/npm/` tuple (any uuid), in-sync re-runs and `repair` redownloads. |
| `vendor_lockfile_missing` / `vendor_lockfile_version_unsupported` (bun preflight placement) | `failed` | scan / get `--mode vendored` (bun): the pre-download preflight found `bun.lock` unreadable / at a `lockfileVersion` other than 0, 1 or 2 (a newer version: update socket-patch; no integer: re-lock with Bun ≥ 1.2 — the same text as hosted's `redirect_bun_lock_unsupported`) or outside bun's single-line `packages` grammar. Same placements as `vendor_bun_lockb_invalid`; nothing fetched, no patch record. An unreadable `.socket/vendor/state.json` met by the same preflight is `vendor_state_unreadable` (see that row), never one of these. |
| `bun_lockb_invalid` | scan `warnings[]` (run-level) | scan (every mode): the native binary inventory could not parse or read `bun.lockb`; detail names the format or filesystem error. Also printed as `Warning: …` on stderr. Exit and status remain unchanged. The warning is retained on empty and non-empty scans; valid binary locks are inventoried normally without a runtime or install. |
| `would_refuse` | dry-run preview action (`vendor.patches[]`) | scan `--mode vendored --dry-run` / get `--mode vendored --dry-run`: the wet run's Bun preflight would refuse this npm purl; the record carries `errorCode` (one of the four Bun lock codes above, or `vendor_state_unreadable` for an unreadable vendor ledger) + `error`. Exit 0 / `status: "success"`, nothing written. |
| `cargo_wiring_migrated` | `skipped` (advisory note) | vendor / scan / get `--mode vendored` / repair (v5.0): a pre-v5 `.cargo/config.toml` / `.cargo/config` vendored `[patch.crates-io]` entry was moved into the workspace-root `Cargo.toml` (dry run: "would move"); the ledger entry is rewritten to name `Cargo.toml` (lock originals kept). A vendor re-run that migrates reports the package `applied`, not `already_vendored`. |
| `cargo_legacy_wiring_kept` | vendor: `failed`; repair: `skipped` (warning) | vendor / scan / get `--mode vendored` (v5.0): the pre-v5 config entry could not be removed after the manifest took the wiring — the run is unwound (manifest, lock and copy as before) and the package fails, since a kept entry would double-wire the crate and, on a uuid bump, point at a copy the stale sweep deletes; the code prefixes the error detail. repair: the move was refused (e.g. an unparseable `Cargo.toml`, a user entry for the crate, or an unremovable legacy entry — the manifest edit is unwound); left in place. |
| `cargo_version_tagged` | `skipped` (advisory note) | vendor / scan / get `--mode vendored` / repair (v5.0): a vendored copy and its detached Cargo.lock entry were (re)tagged `<version>+socket.<uuid>` — a copy vendored before tagged versions, or a lock entry tagged for another uuid while the wiring points at this copy (dry run: "would tag"). A vendor re-run that tags reports the package `applied`. |
| `cargo_version_untagged` | `skipped` (warning) | repair (v5.0): the tag could not be written (an unreadable copy manifest, or a lock the retag cannot keep consistent); nothing else was undone — re-run `socket-patch vendor`. |
| `cargo_lock_untaggable` | `failed` | vendor / scan / get `--mode vendored` (cargo, v5.0): the Cargo.lock entry cannot carry the copy's tagged version consistently (a dependency reference in a spelling the edit does not own, a v1 `replace` naming the crate, or an entry already at the tagged version). Refused before any write; a dry run previews the same refusal. |
| `cargo_copy_untaggable` | `failed` (error prefix) | vendor / scan / get `--mode vendored` (cargo, v5.0): the copy's `Cargo.toml` has no literal `[package] version` string that can be rewritten byte-exactly (or it names another version); nothing is swapped in. A dry run over an already-vendored copy reports the same failure; a patch-service crate that cannot be tagged fails with `vendor_prebuilt_required`. |
| `cargo_wiring_restored` | `skipped` (advisory note) | repair (v5.0): a vendored crate's Cargo.lock entry was detached with no Socket-owned `[patch]` pointing at its committed copy (a pre-v5 release overwrote its crate-named config key when a second version was vendored); the manifest entry is written back and the ledger updated (dry run: "would restore"). A `vendor` re-run heals the same state as a plain re-vendor. |
| `cargo_manifest_unreadable` / `cargo_manifest_unparseable` / `cargo_manifest_symlink_unsupported` / `cargo_manifest_not_workspace_root` / `cargo_manifest_patch_source_alias` | `failed` | vendor / scan / get `--mode vendored` (cargo, v5.0): the workspace-root `Cargo.toml` cannot carry the vendored `[patch.crates-io]` entry (or cargo would ignore it there) — see the cargo caveat under "Vendored mode". Refused before any write. |
| `vendor_would_revert_redirect` / `vendor_takeover_reverted_redirect` | `skipped` (advisory event) | vendor / scan / get `--mode vendored` over a hosted pin (every ecosystem, v5.0): dry run — the upstream restore was resolved (registry lookups included) and would succeed (for bun, only after the Bun vendored preflight accepted the lock; a refused lock is previewed as the wet run's `failed <code>` instead) / wet run — the pin's lock entries were restored to their upstream registry entry before vendoring (mode takeover; detail `<purl> was hosted; restored its upstream registry entry (<files>) before vendoring (mode takeover)`), so `vendor --revert` later returns to upstream. Fires on the run that takes over, not on re-runs, and not for a purl whose takeover was rolled back because the backend refused it (see "Takeover reconciliation"). |
| `redirect_revert_failed` | `failed` | vendor / scan / get `--mode vendored` (dry and wet): the upstream restore of a hosted pin was refused (`--offline`, a registry that does not answer, a lock shape the restore refuses — for `bun.lockb`, a record the codec cannot rebuild) — detail `cannot vendor over the live hosted pin: cannot restore <purl> to its upstream registry entry: <why>; restore it from version control instead (`git checkout -- <files>`)`; nothing vendored for the purl, hosted wiring left in place, exit 1 `partial_failure`. |
| `patch_fetch_failed` (eject) | `failed` | vendor eject (v5.0): a hosted pin's patch record could not be fetched from `…/patches/view/<uuid>`; the whole eject is refused (`eject_refused`), nothing touched, exit 1. |
| `redirect_pnpm_lockfile_elsewhere` / `redirect_workspace_lockfile_elsewhere` / `cargo_manifest_not_workspace_root` (hosted) | top-level `errorCode` (`status: "error"`) | scan / get `--mode hosted` (v5.0): the project directory is a workspace member whose lock lives in another directory, so the rewriters, which read only the project directory, would pin nothing (pnpm: no npm-family lock here, and the nearest ancestor `pnpm-workspace.yaml` or the project's `lockfile-dir` (`.npmrc`) / `lockfileDir` (`pnpm-workspace.yaml`) puts `pnpm-lock.yaml` elsewhere; npm / yarn / Bun, `redirect_workspace_lockfile_elsewhere`: no npm-family lock here, and the nearest ancestor `package.json` whose `workspaces` (array, or the object form's `packages`) matches the directory holds `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `bun.lock` or `bun.lockb`; a matching root with none of them that is itself listed by an outer root's `workspaces` hands the check to that root; vlt, same code: the nearest ancestor `vlt.json` whose `workspaces` (a string, an array, or an object of groups) matches the directory holds `vlt-lock.json`, or, as vlt falls back to it when `vlt.json` has no `workspaces` field, the `package.json` `workspaces` root above holds `vlt-lock.json`, and the nearer of a `vlt.json` and a `package.json` root is named; `workspaces` patterns use the glob grammar the package managers share: `*`, `?`, `**`, brace sets and sequences (`{a,b}`, `{1..3}`) and character classes (`[a-c]`, `[!a]`); when a pnpm workspace also governs the directory, the nearer root is named and a tie goes to `redirect_pnpm_lockfile_elsewhere`) or rewrite the member as a lockless project (cargo: the vendored workspace-root check). Refused before any takeover or write, `--dry-run` included; the message names the directory to run from; exit 1. Disk runs only (an in-memory project has no ancestors). |
| `redirect_pnpm_settings_elsewhere` | top-level `errorCode` (`status: "error"`) | scan / get `--mode hosted`: the project directory is a pnpm workspace member with its own v9 `pnpm-lock.yaml` (`sharedWorkspaceLockfile: false`) and no `pnpm-workspace.yaml` of its own, so its pnpm settings come from the nearest ancestor `pnpm-workspace.yaml`, which pnpm reads alone (a member's own file is ignored). When that file neither carries `trustLockfile: true` nor explicitly sets another value, the trust auto-config has nowhere to go: refused before any takeover or write, `--dry-run` included; the message names the root file to add `trustLockfile: true` to (or `--no-trust-lockfile-config` pins without it); exit 1. Once the root file trusts the lock (or opts out), the member is pinned and no nested `pnpm-workspace.yaml` is created; the `redirect_pnpm_trust_lockfile` warning names the root file. Disk runs only. |
| `eject_refused` | top-level `errorCode` (`status: "error"`) | vendor eject (v5.0): a record fetch failed or a pin's upstream restore was refused while planning; nothing was changed, exit 1. |
| `eject_planned` | `applied` (reason) | vendor eject `--dry-run` (v5.0): the pin would be restored upstream and vendored; nothing written. |
| `eject_rolled_back` | warning | vendor eject (v5.0): a package failed after the restore began; every touched file was put back from the pre-eject snapshot, so the project is still hosted; `partial_failure`, exit 1. |
| `eject_rollback_failed` | top-level `errorCode` | vendor eject (v5.0): putting the pre-eject snapshot back failed; the detail names the files to `git checkout --`; exit 1. |
| `offline_eject_unavailable` | top-level `errorCode` | vendor eject under `--offline` / `SOCKET_OFFLINE` (v5.0): records and registry entries cannot be fetched offline; zero network requests, nothing touched, exit 1. |
| `hosted_wiring_contested` | top-level `errorCode` (list: warning when it can still list) | rollback / remove / vendor eject / list (v5.0): a lockfile mentions a recognized hosted patch uuid that discovery rejected (or a pin with no lockfile), so the hosted set is not known exactly; refused with nothing touched, exit 1. Remedy: fix or `git checkout` the named lockfile. |
| `vendor_pnpm_settings_elsewhere` | `failed` | vendor / scan / get `--mode vendored` (pnpm, v9 lock): the project directory is a pnpm workspace member with its own `pnpm-lock.yaml` and no `pnpm-workspace.yaml` of its own; pnpm reads `overrides:` only from the nearest ancestor `pnpm-workspace.yaml`, so an override wired into the member (its `package.json` or a nested workspace file) would be ignored, failing frozen installs on pnpm >= 11 and silently reinstalling the unpatched package on a plain install. Refused before any write (the pre-download preflight and `--dry-run` included); the detail names the governing file; remedy: `--mode hosted`. |
| `vendor_dir_symlink_unsupported` | `failed` | vendor / scan / get `--mode vendored` (every ecosystem): `.socket` itself (#887), `.socket/vendor`, `.socket/vendor/<eco>` or the patch's `<uuid>` dir is a symlink or junction. socket-patch creates those directories itself and never writes links, so a linked one is not ours; its target may be another project's vendor store. Refused before any write. The vendored revert (`vendor --revert`, `rollback`, `remove`, the vendored → hosted takeover) fails on the same check with the same detail before it edits a lock or deletes anything, so it never deletes another project's artifacts through the link. The detail names the linked path. Remedy: replace the link with a real directory and re-run. |
| `vendor_yarn_berry_cache_unsupported` | `failed` | vendor (yarn berry): lock `cacheKey ≠ 10c0` or non-default `.yarnrc.yml` `compressionLevel` — the cache-zip checksum is not reproducible. |
| `vendor_yarn_berry_mixed_line_endings` | `failed` | vendor (yarn berry): `yarn.lock` or the root `package.json` mixes CRLF and LF line endings (or holds a bare CR) — no single ending can be kept, and yarn rewrites such a file wholesale on its next install (a mixed lock also fails `--immutable`, YN0028). Refused before any write; `yarn install` normalizes the files. A uniformly CRLF pair is vendored in CRLF. A hosted→vendored takeover (`vendor`, `scan`/`get --mode vendored`) raises this — and the berry `vendor_yarn_berry_cache_unsupported` gates — BEFORE restoring the hosted pin's upstream entry (dry run too), so a refused purl stays hosted. |
| `vendor_override_conflict` | `failed`        | vendor (pnpm/yarn-berry): a user-authored override/resolution for the package already exists. |
| `vendor_integrity_unverified` | `skipped` (warning) | vendor (pipenv): the lockfile format does not hash-check file entries; the committed wheel bytes are the protection. |
| `vendor_content_mismatch_overwritten` | `skipped` (warning) | vendor: a staged file matched NEITHER beforeHash nor afterHash (patch built against different bytes, or local edits); the stage was overwritten with the verified patched content and the vendor succeeded. |
| `vendor_vlt_transitive_unsupported` | `failed` | vendor (vlt): the target has an inbound edge from another package in `vlt-lock.json` (the detail names it); vendored mode rewires only direct dependencies of the root or a workspace member, because vlt silently reverts transitive lock surgery. Remedy: `--mode hosted`. Refused before any download or write, dry runs included (`would_refuse`). |
| `vendor_vlt_lock_out_of_sync` | `failed` | vendor (vlt): an importer's `package.json` is missing, unparseable, or declares a spec for the dependency that differs from the lock's importer edge. Remedy: `vlt install` first. Refused before any write. |
| `vendor_vlt_build_scripts_unsupported` | `failed` | vendor (vlt): the package declares a `preinstall`, `install`, `postinstall` or `prepare` script, or ships a `binding.gyp`. vlt builds a registry copy in the untracked store, but a vendored `file:` dependency in place, so `vlt build` would rewrite the committed artifact (a platform binary over a JS shim, say) and every later vendor, repair and `vex` would treat it as tampered. Remedy: `--mode hosted`. Refused before any write. |
| `vendor_vlt_legacy_lockfile` | `skipped` (warning) | vendor (vlt): an era-A lock (vlt 0.0.0-19 … 1.0.0-rc.8): a `··` default-registry id, or default-registry ids that are URL segments equal to a scalar `options.registry` with no `·npm·` id (era B writes `·npm·` whatever the scalar). vlt 0.0.0-31 … 1.0.0-rc.5 install the vendored lock but fail to reinstall the vendored `file:` dependency if `vlt-lock.json` is deleted and re-created (the other era-A releases reinstall it; the lock does not say which release reads it). The package is still vendored; remedy: upgrade vlt. |
| `vendor_vlt_reinstall_required` | `skipped` (advisory; human: `Warning: …`) | vendor / scan / get `--mode vendored` (vlt), wet and dry runs, and in-sync reruns: (a) the run rewires an optional dependency, or an importer's `node_modules/<name>` of an optional dependency still resolves into `node_modules/.vlt/`: from vlt 0.0.0-30 a plain `vlt install` (1.2.0: also `--force`) keeps that installed upstream copy linked; the detail says to run `vlt ci` (or delete `node_modules` and run `vlt install`) to link the vendored copy, and that vlt 0.0.0-30 … 1.0.4 install no optional dependency from the lock of a project that declares only optional dependencies (upgrade to 1.0.5 or later first); (b) otherwise, an importer's link of the dependency still resolves into `node_modules/.vlt/`: the detail names the links (`node_modules/<name>`, `<member dir>/node_modules/<name>`) and says `vlt install` (or `vlt ci`) links the vendored copy — on a warm tree after a plain `vlt install` that is true of every vendored direct dependency; (c) an importer's link resolves into the vendored dir of the patch this run replaces (a new patch uuid), which the run removes: the detail names the links and says `vlt install` (or `vlt ci`) links the new vendored copy; (d) a redownload of the payload (vendor, or `repair` after a corrupt or missing payload) could not keep vlt's links to the package's own dependencies (its old `node_modules/` held more than links): the detail says to run `vlt ci` (or delete `node_modules` and run `vlt install`), since a plain `vlt install` does not re-link them. `repair` moves those links back into the downloaded payload when they are only links. The package is vendored either way; a run whose patch fails to apply emits neither. A wet `vendor --revert` (and the revert a vendored → hosted takeover runs, whose advisory joins `redirect.warnings[]`): (a) the revert moves an `optionalDependencies` spec back from the `file:` dir, or an optional importer's `node_modules/<name>` still resolves into the vendored uuid dir: from vlt 0.0.0-30 a plain `vlt install` keeps that link (dangling once the dir is removed), so the detail says to run `vlt ci` (or delete `node_modules` and run `vlt install`) to link the restored copy, with the same vlt 1.0.5 note; (b) otherwise, an importer's link still resolves into the vendored uuid dir: the detail names the links and says `vlt install` (or `vlt ci`) links the restored copy. A dry-run revert emits neither. |
| `vendor_flavor_changed` | `failed` | vendor (npm): the purl's vendor ledger entry was written for another lockfile `flavor` than the one the router now detects (for example `npm` → `vlt` after switching package managers). Remedy: `socket-patch vendor --revert` it first, then re-vendor. Refused before any write. |
| `vendor_artifact_gitignored` | `failed` | vendor (vlt and the npm-family tarball flavors: npm, pnpm, bun, yarn classic, yarn berry): inside a git work tree, `git check-ignore --no-index` reports the new artifact's uuid directory as ignored by a rule its own `.gitignore` cannot override (such as a root `.socket/` or `vendor/` rule; the detail names the rule). Remedy: drop that rule for `.socket/vendor/`. Refused before any write. A file rule such as `*.tgz` is overridden by the `<uuid>/.gitignore` vendoring writes; if the written artifact still reads as ignored, the run refuses and removes the uuid dir it created. |
| `vendor_artifact_gitignore_unchecked` | warning | vendor (vlt and the npm-family tarball flavors): git is installed but could not answer the ignore check for the written vendored directory (it failed to start, ran past 30 s, or `rev-parse` / `check-ignore` exited with an error); the package is vendored and the detail names what failed. Remedy: make sure no ignore rule covers `.socket/` before committing. Git absent, or a project outside any work tree, raises nothing. |
| `vendor_ledger_entry_missing` | `failed` | vendor (vlt): the only installed copy is vlt's link to a committed vendored directory, but the vendor ledger has no entry for the package; restore `.socket/vendor/state.json` from version control (v5.0: `repair` no longer re-synthesizes it). Replaces the `package_not_installed` skip. |
| `vendor_variant_ambiguous` | `failed` | vendor / scan / get `--mode vendored` (pypi, gem): the package is not installed and the manifest holds several release variants of it (`?artifact_id=` / `?platform=`), none of which the vendor ledger records, so nothing says which distribution to vendor; install the package or keep one release variant. A variant the ledger records (at any patch uuid) is taken as the wired one and its siblings are left out without an event. |
| `vendor_artifact_missing` | reason | The recorded artifact is missing; repair requires an online exact redownload. |
| `vendor_artifact_corrupt` | reason | The artifact does not match the recorded hash or inventory; repair requires an online exact redownload. |
| `vendor_artifact_reused` | `skipped` (verbose note) | vendor / scan `--vendor` (pypi): the wiring was dropped by a relock but the committed wheel the ledger vouches for verified, so it was re-wired as-is — no service download, no rebuild; the lock pins the first run's sha again. |
| `vendor_redownload_failed` | `failed` | vendor: the same-UUID artifact could not be downloaded and verified against its original ledger. Existing files and fingerprints are preserved. |
| `vendor_artifact_redownload_failed` | `failed` | repair: download unavailable, integrity mismatch, or downloaded bytes/inventory differ from the ledger. Existing files are preserved. |
| `vendor_artifact_unrepairable` | `failed` | repair: the ledger identity or patch record cannot be trusted or recovered. |
| `vendor_uuid_mismatch` | `skipped` | repair: the manifest's patch uuid moved past the vendored artifact — a re-vendor (`vendor` / `scan --vendor`) is pending; repair does not cross patch generations. |
| `content_mismatch_overwritten` | `skipped` (warning) | apply (default policy): a file matched NEITHER beforeHash nor afterHash and was overwritten with the full verified patched content. This includes a file the patch adds (empty beforeHash) that already exists with other content. `--strict` turns this case into a `failed` event instead. |
| `vendor_lock_checksums_unsupported` / `vendor_stale_lock_checksum` | `failed` | vendor (gem): an ambiguous/platform CHECKSUMS entry, or a v1-wired lock whose stale token blocks the hot path (run `vendor --revert` + re-vendor). |
| `redirect_pypi_stale_install` | `redirect.warnings[]` (warning) | Hosted Python redirect: readable installed files differ from patched hashes. Read-only, repeated on re-scan, and excludes the package from same-run VEX. See the "Python stale-install guard" section. |
| `redirect_gem_stale_install` | `redirect.warnings[]` (warning) | scan `--mode hosted` (gem): a stale UNPATCHED materialization (installed gem, or committed archive in bundler's cache dir — `vendor/cache` unless `cache_path` moves it) that `bundle install` will reuse instead of fetching the redirected patch; the detail carries the verified remedy. Full rules and flavors: the "Gem stale-install guard" section. |
| `redirect_gem_version_not_locked` | `redirect.warnings[]` (warning) | scan `--mode hosted` (gem): the crawled gem version is installed on the machine but no `GEM` section of the project's lock resolves it (another project's copy in the shared gem home). The gem is skipped and the Gemfile and lock stay byte-identical. |
| `redirect_pipenv_refused` | `redirect.warnings[]` (warning) | scan `--mode hosted` (pipenv): the Pipfile.lock pins another version or a non-registry / foreign source for the package — refused atomically across categories, and the patch is vetoed from the sibling Python rewriters (see the "Pipenv hosted redirect" section). |
| `redirect_pipenv_skipped` | `redirect.warnings[]` (warning) | scan `--mode hosted` (pipenv): no entry for the package, pipfile-spec < 6, an unparseable lock or a digest-less patch — nothing rewritten here; the sibling rewriters proceed. |
| `redirect_pipenv_installer_unknown` | `redirect.warnings[]` (warning) | scan `--mode hosted` (pipenv): the lock was rewritten with the modern `file` reference because no `pipenv` answered on PATH; Pipenv 7–11 projects need `path` — put that pipenv on PATH or set `SOCKET_PIPENV_MAJOR`. |
| `redirect_pypi_platform_wheel` | `redirect.warnings[]` (warning) | scan / get `--mode hosted` (pypi, every lane: uv.lock, PEP 723 script locks, pylock.toml, Pipfile.lock, poetry.lock, pdm.lock, requirements.txt, Hatch): the patch service granted the patch as a platform-, ABI- or interpreter-tagged wheel (any tag triple other than `<py>-none-any` whose python tag set holds a generic Python 3 tag, `py3` or `py3<minor>`; e.g. `cp311-cp311-manylinux…`, or `cp311-none-any`, which pip installs on CPython 3.11 only). A hosted pin would narrow the cross-platform lock entry to that one wheel, so installs on any other interpreter, OS or architecture would fail and hosted rollback could not derive the upstream wheels to restore. The patch is withheld from every PyPI rewriter (nothing is written or confirmed for it, and a same-run `--vex` does not attest it); exit 0, like every hosted refusal. The tags are read as vendored mode reads them for `vendor_platform_locked`. |
| `pypi_pipenv_installer_unsupported` | `failed` | vendor (pipenv): the installed Pipenv is older than 2018 and cannot consume vendored wheel references — upgrade Pipenv or use hosted mode. |
| `pypi_pipenv_version_mismatch` | `failed` | vendor (pipenv): a category pins a different version than the patch — refused before any write. (`pypi_pipenv_invalid_wheel` retired in v5.0: the backend takes the orchestrator's resolved version instead of parsing the wheel filename.) |
| `pypi_poetry_symlink_unsupported` / `pypi_pipenv_symlink_unsupported` / `pypi_requirements_symlink_unsupported` | `failed` | vendor (pypi, v5.0): a target file (`pyproject.toml` / `poetry.lock`, `Pipfile` / `Pipfile.lock`, or any planned `requirements*.txt`) is a symlink — refused before any write on wire AND on revert (the revert keeps the artifact, `kept_artifact`); the twins of the existing pdm/uv symlink refusals. |
| `pypi_poetry_changed` / `pypi_pdm_changed` / `pypi_pipenv_changed` / `pypi_uv_changed` | `failed` | vendor (pypi, v5.0): the lock / project file changed between the read that planned the edit and the first write — refused before any write (worded like `pypi_lock_changed`: "<file> changed during vendoring; re-run"). |
| `pypi_pipenv_stale_install` | `skipped` (warning) | vendor (pipenv): the vendored twin of `redirect_pypi_stale_install` — the project's venv still holds the upstream release Pipenv will not reinstall over; the detail names the `pipenv run pip uninstall -y <pkg> && pipenv sync` remedy, with the same lock-category `sync` arguments as the hosted warning. |
| `pypi_hatch_stale_install` | `skipped` (warning) | vendor (hatch): an existing Hatch environment of the project (found under Hatch's data dir, `dirs.env.virtual` or an explicit env `path`) still holds the upstream release; Hatch keeps it on the next `hatch run`, so the detail names the env and the `hatch env remove <env>` / `hatch env prune` remedy. |
| `pypi_pipenv_installer_unknown` | `skipped` (warning) | vendor (pipenv): no `pipenv` answered on PATH; the vendored references assume Pipenv 2018 or later (7–11 cannot consume them — use hosted mode there); `SOCKET_PIPENV_MAJOR` pins the release. |
| `vendor_lock_entry_relocked` | revert `warnings[]` | vendor `--revert` / rollback (pipenv): a relock regenerated the wired entry to a registry reference, or removed it; the record is retired (artifact removed, ledger entry dropped) instead of drift-kept. |
| `pypi_{poetry,pdm,pipenv}_no_lockfile` | `failed` | vendor (pypi): a lock-less tool marker with no `requirements.txt` fallback — run `<tool> lock`. |
| `pypi_poetry_integrity_unverified` | `skipped` (warning) | vendor (pypi / poetry): the lock was written by Poetry < 1.4 (0.12 `[metadata.hashes]`, lock 1.0/1.1, or a 2.0 lock without a `@generated by Poetry X.Y.Z` header — 1.3 wrote those). That installer does not verify local wheel hashes (the committed wheel bytes are the protection) and does not replace an already-installed package at the same version; recreate the virtualenv or `pip uninstall` the package before `poetry install`, or upgrade Poetry. |
| `redirect_poetry_stale_install_risk` | `redirect.warnings[]` (warning) | scan `--mode hosted` (poetry): same writer test as above — a warm virtualenv keeps the upstream package after the redirect on Poetry < 1.4 (1.4+ re-installs from the new source); fresh installs pick up the patched wheel. Emitted once per rewritten lock, only on the run that rewrites it. |
| `redirect_poetry_entry_not_found` / `redirect_poetry_missing_sha256` / `redirect_poetry_lock_unsupported` | `redirect.warnings[]` (warning) | scan `--mode hosted` (poetry): the lock has no `[[package]]` at the granted version (uv-parity twin of `redirect_uv_entry_not_found`); the grant carries no SHA-256 (gated once per dep, not per lock); the lock is refused — Poetry 0.12 layout (URL sources ignored), an unsupported `lock-version`, a forked package listed at several versions, a user-authored `[package.source]` on another origin (an earlier Socket URL for the same wheel is superseded in place), a malformed `[metadata.files]`/`[metadata.hashes]`, or a wheel whose filename does not match the locked package. Exit code and `status` unchanged (hosted-refusal posture). A vendored → hosted takeover over a Poetry 0.x lock is refused with this code BEFORE the revert (wet and `--dry-run`): the purl stays vendored and patched and is skipped with this code as `redirect.skipped[].reason`. The detail names the remedy and its reach: run `socket-patch vendor --revert` (it reverts EVERY vendored package in the project, not just this one), upgrade to Poetry >= 1.0 and re-lock, then re-run `scan --mode hosted`. |
| `redirect_pdm_refused` / `redirect_pdm_legacy_sync_required` | `redirect.warnings[]` (warning) | scan `--mode hosted` (pdm): the `pdm.lock` rewrite was refused — an unsupported `[metadata] lock_version` (the identity-losing `3.1` / `4.0`–`4.2` formats or an untested future format), an unsupported `strategy`, a package listed at several versions (fork) or absent, a user-authored `url`/`path`/VCS/`editable` source, hash-less or malformed `files`, or a wheel whose filename does not match the locked package (`redirect_pdm_refused`); or the lock was written in format `2` (PDM 0.12–1.4), whose upstream freshness bug lets `pdm install` regenerate the lock — use `pdm sync` (`redirect_pdm_legacy_sync_required`). A refused uuid is withheld from every other PyPI rewriter when `pdm.lock` is the install driver, and its patch is not confirmed. Exit code and `status` unchanged (hosted-refusal posture). |
| `redirect_bun_lock_unsupported` | `redirect.warnings[]` (warning) | scan/get `--mode hosted` (bun): the text lock's `lockfileVersion` is not 0, 1 or 2 (a newer version: update socket-patch, re-locking would reproduce it; no integer: re-lock with Bun ≥ 1.2 — the shared gate's text, identical to vendored's `vendor_lockfile_version_unsupported`), or its `packages` section is not bun's single-line grammar. Nothing rewritten; exit 0 (hosted-refusal posture). |
| `redirect_bun_workspace_unsupported` | `redirect.warnings[]` (warning) | scan/get `--mode hosted` (bun): a lockfileVersion-0 lock (Bun 1.1.39–1.1.45 `--save-text-lockfile`) holds `workspace:` packages; frozen installs of that grammar cannot keep the hosted tuple. Detail: "Bun version-0 workspace locks cannot preserve hosted tarballs on frozen installs; delete bun.lock and re-run `bun install` with Bun >= 1.2 (which writes lockfileVersion 1, accepted by hosted mode) — a plain in-place `bun install` bumps the version only when a workspace depends on another workspace (e.g. root -> member); otherwise it keeps version 0 or fails to resolve" (measured: Bun 1.2.0 keeps 0, 1.2.23–1.4.2 exit 1 "failed to resolve" on a root that does not depend on its members). Version-1/2 workspace locks are rewritten. Exit 0. |
| `redirect_bun_lockb_invalid` | `redirect.warnings[]` (warning) | scan/get `--mode hosted`: the native binary lock is malformed, unreadable, unsupported or cannot be rewritten safely. No installer is spawned and no binary or sibling npm lock edit or takeover occurs; dry-run reports the same format error. Exit 0, `redirected: 0`. |
| `redirect_bun_entry_not_found` / `redirect_bun_missing_sha512` | `redirect.warnings[]` (warning) | scan/get `--mode hosted` (bun): the lock has no rewritable entry at the granted version (re-resolved, or occupied by an unowned URL/file spec) / the grant carries no sha512 integrity. Per-dep; nothing rewritten for it; exit 0. NOT emitted for the digest-less 2-tuple Bun 1.1.39–1.3.9 re-save our URL tuple as — that entry counts as redirected and is healed. |
| `redirect_bun_patched_dependency_skipped` | `redirect.warnings[]` (warning) | scan/get `--mode hosted` (bun, `bun.lock` and `bun.lockb`): the project patches the granted `name@version` itself with `bun patch` (a `patchedDependencies` key for `name@version`, or the bare name, in the root `package.json` or mirrored in `bun.lock`). Bun applies that patch only to the registry resolution, so the entry is left on its registry tuple instead of silently losing the user's patch (#367). Per-dep; the detail names the key and the remedy (fold the Socket fix into the user's patch, or drop the `patchedDependencies` entry and re-run); the in-run VEX never assumes the uuid applied. Vendored mode refuses the same package `vendor_lock_entry_unsupported` before any write or download. Exit 0. |
| `redirect_vlt_lock_unsupported` | `redirect.warnings[]` (warning) | scan/get `--mode hosted` (vlt): `vlt-lock.json` has a `lockfileVersion` other than absent, `0` or `1` (decided on the raw JSON token), is not a JSON object, starts with a UTF-8 BOM, or its `nodes` section is not vlt's one-node-per-line layout. Nothing rewritten; also refuses a vendored → hosted takeover of a `flavor: "vlt"` entry before its revert (`redirect.skipped[].reason`). Exit 0. |
| `redirect_requirements_takeover_unreachable` | `redirect.warnings[]` (warning) | scan/get `--mode hosted` (pypi / requirements.txt): a vendored → hosted takeover of a package that vendored mode wired through a pin in a `-r` include, or through a `(transitive)` line it appended to the root `requirements.txt`. Hosted mode only rewrites an existing pin in the root `requirements.txt`, so the takeover is refused before the revert (wet and `--dry-run`): the vendored wiring, ledger entry and wheel stay byte-identical, the purl is skipped with this code as `redirect.skipped[].reason`, and nothing is redirected for it. Exit 0. The detail names the remedy and its reach: run `socket-patch vendor --revert` (it reverts EVERY vendored package in the project, not just this one), move the pin from the include into the root `requirements.txt` and delete it from the include (or, for a `(transitive)` line, add an exact `==` pin to the root file), then re-run `scan --mode hosted`. |
| `redirect_uv_takeover_version_unreachable` | `redirect.warnings[]` (warning) | scan/get `--mode hosted` (pypi / uv): a vendored → hosted takeover of a package whose recorded pre-vendor `uv.lock` entry is at another version than the patch (vendored uv pins the lock entry down to the patch's version, for example when the lock resolved a newer release). Reverting would bring the lock's own version back, and hosted mode only pins the version the lock resolves, so the takeover is refused before the revert (wet and `--dry-run`): the vendored wiring, ledger entry and wheel stay byte-identical, the purl is skipped with this code as `redirect.skipped[].reason`, and nothing is redirected for it. Exit 0. The detail names the remedy and its reach: run `socket-patch vendor --revert` (it reverts EVERY vendored package in the project, not just this one), make the project resolve the patch's version (for example an exact `==` requirement) and re-lock, then re-run `scan --mode hosted`. |
| `redirect_vlt_missing_sha512` / `redirect_vlt_entry_not_found` / `redirect_vlt_entry_vendored` / `redirect_vlt_unsupported_lock_key` | `redirect.warnings[]` (warning) | scan/get `--mode hosted` (vlt): the grant has no sha512 / the lock has no default-registry node for `name@version` / the only match is a vendored `file` node under `.socket/vendor/npm/<uuid>/` / a default-registry instance is outside vlt's node-line grammar or still unpatched after the splice. Per dep; none of the dep's instances is written. `redirect_vlt_missing_sha512` and `redirect_vlt_unsupported_lock_key` refuse the dep: it is never confirmed, whichever lock drives (a sibling lock may still carry its rewritten URL). `redirect_vlt_entry_not_found` and `redirect_vlt_entry_vendored` only say `vlt-lock.json` does not wire it: while vlt drives it is not confirmed; otherwise a sibling lock's rules may confirm it. Exit 0. |
| `redirect_vlt_custom_registry_skipped` | `redirect.warnings[]` (warning) | scan/get `--mode hosted` (vlt): same-`name@version` nodes under a named alias, a scoped registry or jsr, or git, remote-tarball or local-directory nodes of the same package name (vlt records no version for those; a remote tarball whose `<name>-<version>.tgz` leaf names another version does not count), were left untouched (hosted mode only redirects vlt's default registry). The dep is still redirected, but the run's `--vex` does not attest it, and neither does a later `vex` from the lock alone. |
| `redirect_vlt_lockfile_version_missing` / `redirect_vlt_old_lockfile_ignored` / `redirect_vlt_scalar_registry_ignored` | `redirect.warnings[]` (warning) | scan/get `--mode hosted` (vlt): the lock has no `lockfileVersion` (vlt ≥ 1.0.0-rc.15 re-resolves it) / a legacy default-registry id without `"modifiers"` in `vlt.json` (vlt 0.0.0-16 … 0.0.0-24 ignore the lock) / a scalar `registry` option that vlt 1.0.0-rc.7 … rc.29 honor over the lock. The deps stay redirected, but the run's `--vex` does not attest them. |
| `redirect_vlt_sibling_lockfiles` | `redirect.warnings[]` (warning) | scan/get `--mode hosted` (vlt): `vlt-lock.json` and another npm-family lock are both present and vlt's install state (`node_modules/.vlt-lock.json` or `node_modules/.vlt/`) is not, so both locks were rewritten and the other lock's rules confirm. |
| `redirect_vlt_no_lockfile` | `redirect.warnings[]` (warning) | scan/get `--mode hosted` (vlt): `vlt.json` or vlt's install state is present without `vlt-lock.json`; replaces `redirect_npm_no_lockfile` for vlt projects. |
| `redirect_vlt_artifact_unverifiable` | `redirect.warnings[]` (warning), `redirect.skipped[].reason` | scan/get `--mode hosted` (vlt): before any takeover or rewrite (dry runs included), each granted artifact with a default-registry instance in `vlt-lock.json` (or, for a purl a `flavor: "vlt"` vendored entry claims, its vendored node, probed before the takeover reverts it) is fetched once as vlt fetches it (`accept-encoding: gzip;q=1.0, identity;q=0.5`, no `Authorization`, up to 10 redirects) and must return 200 with no content encoding (or `identity`) and the granted sha512. On failure (`content-encoding <v>`, `sha512 mismatch`, `http <status>`, `fetch error <e>`, `offline`) the dep is withheld from every rewriter when vlt drives or it is vlt-vendored (which also keeps it vendored), and from the vlt rewrite only otherwise (detail "…; vlt-lock.json was not changed for {purl}"; only the sibling lock this run rewrote can confirm it). A lock already pinned by an earlier run is left pinned, and neither confirmed nor attested. Projects without `vlt-lock.json` make no such request. The detail quotes the artifact URL (and any fetch error that echoes it) with its grant-token path level, the one just before the patch uuid, spelled `<redacted>`; host, uuid and leaf stay. The in-memory hosted engine (`hosted-bundle`, the Node addon) has no network for this fetch, so it judges every in-scope artifact as `--offline` does (withheld, never pinned; the vendored takeover it refuses anyway). Exit 0. |
| `redirect_vlt_reinstall_required` | `redirect.warnings[]` (advisory); rollback/remove `warnings[]` (+ human stderr) | vlt: `vlt-lock.json` pins (or, after rollback/remove, no longer pins) Socket-patched packages, and vlt never refreshes an installed copy. The heal removes `node_modules/.vlt-lock.json` and each stale `node_modules/.vlt/<DepID>` of a Socket-owned node (never a link's target, never outside the project, never a copy it cannot judge) unless `--no-vlt-install-cleanup` or `--dry-run`. It never removes an optional node's copy (lock flags 1 or 3, or flags it cannot read): `vlt install` does not put a removed optional dependency back (its link dangles) unless the same install also reinstalls a non-optional node, so such a copy is left stale and the detail says to run `vlt ci` (or delete `node_modules` and run `vlt install`); vlt 0.0.0-30 … 1.0.4 install no optional dependency from the lock of a project that declares only optional dependencies, so there both commands remove the installed copy and the detail says to upgrade vlt to 1.0.5 or later first. The detail says whether copies were removed, left stale by a skipped cleanup, could not be checked, or none were stale, and adds how many optional copies were kept whenever there are any. The kept optional copies are named by what they are: `unpatched copies of optional dependencies` after `scan`/`get`, `patched copies of optional dependencies` after `rollback`/`remove`, and `installed copies of the vendored optional dependencies` after a hosted → vendored takeover (the copy the hosted pin left installed, which may still be the registry bytes). Stale or unchecked copies are not attested by the run's `--vex`, nor is a confirmed vlt pin the heal did not check (a URL on a host other than patch.socket.dev and the configured `--patch-server-url`/`--api-url`). A hidden lock that cannot be removed keeps every store entry. Invalidation failures only warn. |
| `vendor_prebuilt_stub_invalid` | `failed` | RubyGems: the server stub lacks required attributes or is otherwise invalid; no local stub fallback is permitted. |
| `vendor_*` / `pypi_*` / `gemfile_*` / `lock_*` / `locked_version_mismatch` / `user_authored_*` / `native_extensions_unsupported` / `platform_gem_unsupported` | `failed`/`skipped` | vendor: per-ecosystem refusal + drift vocabulary; see the Vendor command contract section. New tags are additive (MINOR). |

### Top-level `EnvelopeError` codes

| Code                  | Subcommands                      | Meaning |
|-----------------------|----------------------------------|---------|
| `manifest_not_found`  | remove, repair, rollback, vex (not `list` since v5.0: a missing manifest is an empty list) | `.socket/manifest.json` doesn't exist. For `vex` (and `scan --vex`) it fires only when, in addition, NOTHING else names a patch — no vendor-ledger entry, no lockfile reference (hosted or vendored) — and the message says so (exit 2 standalone; `apply`/`vendor --vex` treat it as their calm no-op). v3.5: `repair` proceeds anyway (vendored phase only) when a vendor ledger or vendor-path lockfile references exist, and exits 0 with a `redirect_only_project` skip (not this error) when the project's only patch state is hosted pins in its lockfiles (v5.0; or a pre-v5 `redirect-state.json`). `list` likewise no longer fires this on a hosted-only project: v5.0 lists every hosted pin the lockfiles wire (exit 0, labeled `details.mode: "hosted"` + `details.lockfiles: [<files wiring it>]` — no `details.ledger`, since hosted mode keeps none; when the manifest exists too, both are shown, purl-sorted with the manifest entry first on a tie). A pin carries its uuid and empty details unless a pre-v5 redirect ledger records the same purl and uuid (read for migration only: its record supplies the vulnerabilities / tier / description); a pre-v5 ledger record whose pin is in no lockfile is not listed. v5.0: `list` reads the vendor ledger the same way — a vendored-only project (every `scan`/`get --mode vendored` project) lists its ledger entries' embedded records labeled `Mode: vendored (recorded in .socket/vendor/state.json)` in human mode — the twin of the hosted `Mode: hosted (wired in <lockfiles>)` line — (`details.mode: "vendored"` + `details.ledger: ".socket/vendor/state.json"` in JSON), exit 0. A standalone-`vendor` entry's fallback `record` lists the same way once no manifest entry covers it (by ledger key or base purl) — the copy manifest-less `vex` attests from, so `list` never reports `manifest_not_found` for a tree whose VEX document attests a patch; while the manifest covers it, only the manifest entry is listed. All sources always come from the SAME project: the vendor ledger and the lockfiles are resolved against the root the RESOLVED manifest path implies (its `.socket` parent's parent in the standard layout, else the manifest file's directory — exactly `--cwd` for the default path), so `--manifest-path` into another project reads that project's state, never the local one. The error still fires when NONE of the three sources has a patch, and a present-but-broken manifest still reports `manifest_invalid`/`manifest_unreadable` regardless (corruption is never masked). A malformed pre-v5 redirect ledger degrades to "nothing to consult" with a stderr warning, muted by `--silent` (the pins still list); `list --json` carries it in the run-level `warnings[]` as `redirect_ledger_corrupt` instead of on stderr. v5.0: `rollback` likewise proceeds manifest-less when the vendor ledger or the lockfiles' hosted pins hold work (its error is the legacy `{status: "error", error: "Manifest not found", path}` shape, not this envelope code); only the truly-empty project — no manifest, no vendor ledger, no hosted pin (a lone pre-v5 redirect ledger is deleted, exit 0) — keeps the exit-1 error, and a project whose lockfiles still reference `.socket/vendor/` artifacts with NO vendor ledger gets a distinct error naming `socket-patch repair`. `remove` (v5.0) proceeds manifest-less whenever a vendor ledger file exists or the lockfiles pin a hosted patch (an existence probe and the read-only hosted-pin discovery before the lock; the vendor ledger loads under it): ANY vendor-ledger entry matching the identifier — detached or not — is removed through the ledger path (`--preserve-state` and drift-keeps behave exactly as on the manifest path), a hosted-only match restores its upstream registry entry, and when that state exists but holds nothing for the identifier the error is `not_found` (exit 1), not this code — `manifest_not_found` fires from `remove` only when all three sources are empty. Manifest entries are removed in sorted purl order. |
| `manifest_invalid`    | list, remove                     | Manifest exists but is unparseable. |
| `manifest_unreadable` | list, remove, vex                | I/O error reading manifest (vex: also an unparseable manifest; exit 2). |
| `no_patches`          | vex                              | The manifest file exists but is empty AND no vendor-ledger record or lockfile reference names a patch (exit 1). |
| `vendor_ledger_corrupt` | vex (every form) | `.socket/vendor/state.json` exists but is malformed or unreadable. The vendor ledger is an attestation input (records and liveness), so attesting from a partial view is refused (exit 2 standalone; the host command fails). A missing ledger is simply empty. |
| `redirect_ledger_corrupt` | vex, list (`warnings[]`) | v5.0: a WARNING, no longer an error — a pre-v5 `.socket/vendor/redirect-state.json` exists but is malformed or unreadable. v5 hosted mode keeps no ledger (hosted references come from the lockfiles, their records from the API), so the file is only an optional migration record source: its records are not consulted and the run continues. Delete the file or restore it from version control. |
| `serialize_failed`    | vex                              | The built document could not be serialized (exit 2). |
| `apply_failed`        | apply                            | apply pipeline error before any patch ran. |
| `repair_failed`       | repair                           | repair pipeline error. |
| `remove_failed`       | remove                           | Could not write the modified manifest. |

### Per-subcommand action matrix

| Subcommand   | Emits |
|--------------|---|
| `apply`      | `Applied` · `Updated` · `Skipped` (already_patched / package_not_installed / vendored) · `Failed` · `Verified` (dry-run) |
| `vendor`     | `Applied` (= vendored; `command` routes) · `Skipped` (refusals, warnings, unsupported ecosystems) · `Failed` · `Removed` (reconcile + `--revert`) · `Verified` (dry-run) |
| `list`       | `Discovered` (with `details.vulnerabilities`, `details.tier`, `details.license`, `details.description`, `details.exportedAt`; hosted pins (v5.0: one per `(purl, uuid)` the lockfiles wire) additionally carry `details.mode: "hosted"` and `details.lockfiles: [<root-relative files wiring it>]` (no `details.ledger` — hosted mode keeps no ledger; the human listing labels them `Mode: hosted (wired in <files>)`), both additive and absent on manifest entries; v5.0: vendor-ledger records carry `details.mode: "vendored"` + `details.ledger: ".socket/vendor/state.json"` the same way, and the human listing labels them `Mode: vendored (recorded in .socket/vendor/state.json)`; a `state.json` that cannot be read or parsed degrades to nothing-to-consult with the stderr line `Warning: unreadable vendor ledger (<error>); its vendored patches are not listed` — muted by `--silent`, exit unchanged) |
| `repair`/`gc`| `Downloaded` (or `Verified` on dry-run; `details: {count, mode: "file"}` — `mode` is always `"file"` since v5.0 removed the diff download path) · `Rebuilt` (vendored artifacts; `Verified` previews on dry-run) · `Skipped` (vendor_uuid_mismatch) · `Removed` (or `Verified`) · `Failed` events |
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
- ⏳ `rollback` — still emits per-package result records. Additive (v3.5): a manifest entry with no matching installed package appears in `results[]` as a marker record `{ "purl", "path": null, "skipped": "package_not_installed" }` — no `success`/`error` keys, never counted in `rolledBack`/`failed`, never flips the status or exit code (rollback's job is "make the tree unpatched"; a not-installed package already satisfies that end state, deliberately asymmetric with apply's exit-1 on an all-miss run whose unmatched purls are not lockfile-resolved). v5.0 keeps that legacy shape and adds the ALWAYS-PRESENT keys `warnings[]` (`{code, detail}` objects, now populated), `vendored` (meaning narrowed — MAJOR), `vendoredReverted`, `vendoredPreserved`, `vendoredKept` (`{purl, reason}`), `hosted` (`{reverted, failed: [{purl, error}], unsupported, editedFiles}`), `manifest` (`{removedEntries, preserved}`), `gc` (`{skipped: true}` \| `{removedBlobs, removedDiffArchives, removedPackageArchives, bytesFreed}`), and `paths` — full key semantics and exit rules in the [Rollback command contract](#rollback-command-contract-v50).

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
  "errorCode":   "vendor_bun_workspace_unsupported", // additive; the vendored-mode Bun preflight refusals (+ vendor_state_unreadable) and agent-mode apply failures (apply_failed, package_not_installed)
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
Vendored → Bun vendored preflight. Every other download-phase `failed`
record carries only `error`. The dry-run preview's `would_refuse` records
carry the same pair.

Agent-mode apply failures (#424): when the nested apply that follows the
download (`get` / `scan --mode agent`, not `--save-only`) fails a patch,
that patch's record becomes `action: "failed"` with the same `errorCode` /
`error` pair the standalone `apply --json` reports — `apply_failed` (the
apply error text, e.g. `Permission denied (os error 13)`) or
`package_not_installed` (no installed copy, and the project's lockfiles
do not resolve it either). The record keeps `purl` and `uuid`, drops the
metadata like every `failed` record, and stays saved in the manifest (only
the apply failed). A failing manifest patch the run did not select (the
nested apply covers the whole `--ecosystems`-scoped manifest) is appended
as its own `failed` record. `failed` counts these records beside the
download failures, and `applied` counts only the patches that did apply.
A failure no single patch explains (an unreadable manifest, the yarn PnP
refusal, unavailable patch sources) sets top-level `errorCode` / `error`
on the same object (`apply` in `scan`'s envelope).

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
best first (v5.0, MAJOR):

1. **Severity** (`critical > high > medium = moderate > low > (unknown)`),
   using the worst severity across everything the patch fixes.
2. **Advisory count**, most distinct advisories fixed first. This breaks
   severity ties, including between merged patches: a three-advisory
   `high` patch beats a two-advisory `high` patch, but neither beats a
   single-advisory `critical` patch.
3. **Patch publish date**, most recent first.
4. `tier` (paid first), then `uuid` — tiebreaks only, present so the
   order is total and therefore reproducible across runs.

"Publish date" is when the *patch* was published, never the upstream
package's release date; unparseable or absent dates sort last.

`tier` is an **access filter, not a ranking signal**: paid patches are
excluded before ranking for callers whose `canAccessPaidPatches` is
false, so the winner is the best patch the account can download.

`scan`'s `[UPDATE]` marker and `updates[]` use the same order
(`ranking::search_result_supersedes`, v5.0): a candidate supersedes the
applied patch only on a meaningful rung — higher severity, more advisories
at equal severity, or a real, strictly later publish date at equal severity
and advisory count. The tier and uuid tiebreaks and a missing date never
count. Every mode that fetches the by-package records (hosted, vendored, agent, and
every human run with a downloadable patch) judges this on those records,
so `updates[]` lists exactly the UPGRADE rows the run acts on; a package
the by-package lookup returns no offer for, and a JSON report-only run
(which fetches no by-package records), fall back to the batch records
(`ranking::batch_supersedes`). When the selection does not supersede the
recorded patch, scan keeps the recorded one (v5.0): a re-scan never swaps
an applied patch for an equal sibling.

This order picks one patch **per package**. Which packages a capped scan
patches first is a separate, cross-package order (`rollout::rollout_cmp`,
see "Per-run limit on new patches"): severity of the selected patch, then
advisory count, then ecosystem, base purl and uuid — never the publish
date.

#### Advisory count

There is no `merged` field on the wire and none is required. The count is
the number of distinct advisories a patch names: `vulnerabilities` map
keys on `by-package` / `view`, distinct `ghsaIds` on `batch` (falling back
to distinct `cveIds` only when no GHSA is named). A patch naming several
advisories is a merged patch, but its count does not prove that it includes
every fix from another patch.

When GHSA ids are present, CVE aliases do not increase the count: one
advisory routinely carries several CVE aliases. Repeated ids in a batch
response are counted once.

Production published its first merged patch on 2026-09-04.

This ordering is also the presentation order everywhere patches are
listed — `scan --json`'s `packages[].patches[]`, `get`'s "Found
patches:" listing, and the `selection_required` `options[]` array — so
`patches[0]` for a package is the patch that would be applied, and
`updates[].newUuid` names that same patch.

`scan` never shows a picker: it always takes the top-ranked downloadable
patch. Neither does hosted or vendored `get` (v5.0): no picker, no
confirmation, no `selection_required` — the top-ranked accessible patch per
package, in `--json` too. On agent-mode `get`, free/unauthorized callers with more than one candidate
for a PURL still get the interactive picker (or `selection_required` in
`--json`); the ranking decides the presented order and hence the
highlighted default, not the outcome. `--yes` answers the picker with
that default without showing it (the same pick a non-terminal run makes);
`--json` keeps `selection_required` even with `--yes`.

One additive key may appear on `scan --json`'s `packages[].patches[]`
entries, omitted when absent: `publishedAt`, present whenever the server
supplies it (the public-proxy fallback path fills it in from the
per-package results).

> **Known gap — batch responses without `publishedAt`.** `scan`'s
> discovery (`packages[]`, and `updates[]` on a JSON report-only run) is
> built from the **batch** endpoint, whose response shape currently omits `publishedAt`;
> the selection that `--apply` performs is built from the **by-package**
> endpoint, which carries it. The two diverge wherever the date decides —
> between patches of equal severity and advisory count —
> where the batch side falls through to the tier/UUID tiebreak while apply
> correctly uses the date.
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

Deferred by the per-run cap (`scan --max-new-patches`), most urgent first:

```bash
socket-patch scan --json --max-new-patches 5 | jq -r '
  .rollout.deferred[] | "\(.rank). \(.purl) (\(.severity))"
'
```

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

`apply` with no manifest at all is a clean exit-0 no-op (`status: "noManifest"`), and an **empty** manifest (zero patches) is a plain `success` exit 0 — this is load-bearing for CI steps that run `apply` after every install. A fully rolled-back agent project therefore keeps `.socket/manifest.json` at `{"patches": {}}`: the v5.0 residue rule never deletes a zero-patch manifest, precisely so these CI exits (and `list`'s 0-vs-1 below) never flip. Pinned by `tests/in_process_edge_cases.rs` and `tests/cli/cli_dry_run_paths_e2e.rs`. **One carve-out**: a yarn-berry Plug'n'Play layout (`.pnp.*` loader at `--cwd`) refuses with the loud `yarn_pnp_unsupported` error (exit 1) even when no manifest exists — `scan` cannot discover PnP packages (they live inside `.yarn/cache/*.zip`, no `node_modules/`) and therefore never writes a manifest, so without the carve-out the documented refusal was unreachable and a PnP project's only signal was the calm noManifest exit. Pinned by `tests/e2e_safety_yarn_pnp.rs`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Error (missing/invalid manifest, fetch failed, apply failed, selection cancelled in non-JSON mode, an invalid or ambiguous socket.yml on `scan` (v5.0), etc.) |
| `2` | Usage error: clap parse failures (unknown flag/value, missing required arg, an unknown subcommand such as the removed `setup`) and the conflicts the commands enforce themselves — `scan`'s cross-mode conflicts (`--mode` combined with a DIFFERENT mode's boolean spelling, rejected in `resolve_mode_flags`) and `--mode hosted\|vendored` with `--global`/`--global-prefix` (same enforcement point; `get` refuses the same combination); in hosted/vendored `scan` (bare `scan` included), a PATH that is not a directory, a PATH glob matching no directory, and `--json` with more than one project directory (`run_project_dirs`); on every project command (all but `--update`), a `--cwd` / `SOCKET_CWD` or `--global-prefix` / `SOCKET_GLOBAL_PREFIX` that is not an existing directory, and a non-default `--manifest-path` / `SOCKET_MANIFEST_PATH` that names a directory or sits in a project directory that does not exist (v5.0; checked once before the command runs, whether or not the command uses the flag — previously these read as an empty project and exited 0, and `remove` / `rollback` exited 1; a missing manifest FILE in an existing project stays legal, and `get` / `scan`, which create the manifest, still create a missing manifest directory); `remove --preserve-state --skip-rollback` (the no-op quadrant; flag- or env-sourced alike), an unparseable path glob on `scan`/`rollback`, a `scan` PATH outside the repository root and a malformed `SOCKET_MIN_SEVERITY` or `SOCKET_MAX_NEW_PATCHES` (v5.0), `repair --offline --download-only`. `vex` also exits `2` on hard errors before document generation (see its tri-state table below). v5.0: `get`'s self-enforced conflicts exit `2` too (`--id`/`--cve`/`--ghsa`/`--package` multi-select, `--mode hosted\|vendored --save-only`, a malformed identifier for a forced `--id`/`--cve`/`--ghsa`) — previously `1` (MAJOR). The never-implemented `get --one-off` / `rollback --one-off` (and `SOCKET_ONE_OFF`) are removed in v5.0; `--one-off` is now an ordinary unknown-flag clap error. |

`list` returns **`0`** for every project it can read, empty or not (**v5.0, BREAKING**: a project with no manifest and no ledger record — normal for hosted mode, which writes no manifest — used to exit `1` with `manifest_not_found`; it is now an empty list: `No patches in this project. Run \`socket-patch scan\`.` on stdout, and under `--json` the success envelope with `events: []`). Only an unreadable or invalid manifest (`manifest_unreadable` / `manifest_invalid`) exits `1`. Every lock-taking subcommand — including `scan`/`get --mode hosted` as of v5.0 — returns **`1`** with `errorCode: lock_held` when another live socket-patch process holds `<.socket>/apply.lock`.

`vex` exit codes are tri-state:

| Code | Meaning |
|---|---|
| `0` | A non-empty OpenVEX document was produced |
| `1` | Nothing attested: `no_applicable_patches` (every candidate was omitted — by verification, a wiring gate, or a missing record; the omissions ride `skipped` events) or `no_patches` (an empty manifest file and nothing wired anywhere) |
| `2` | Hard error: `manifest_not_found` (no manifest AND no vendor-ledger record / lockfile reference anywhere), `manifest_unreadable`, `vendor_ledger_corrupt` (v5.0: `redirect_ledger_corrupt` is a warning), `json_requires_output`, `product_undetected`, `serialize_failed`, `write_failed` |

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

Versioning lives in **`Cargo.toml`** at the workspace root (`version = "..."`) and is propagated to the Cargo and npm packages by **`scripts/version-sync.sh <new-version>`** (the full list of stamped files is below).

| Change | Bump |
|---|---|
| Rename or remove a subcommand | **MAJOR** |
| Rename or remove a visible alias (`download`, `gc`) | **MAJOR** |
| Rename or remove a hidden alias (`--no-apply`) | **MAJOR** |
| Rename, remove, or change short form of a flag (`-d`, `-m`, etc.) | **MAJOR** |
| Change a default value (`--vendor-source`, `--batch-size`, `--manifest-path`, …) | **MAJOR** |
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

- `Cargo.toml` (workspace version and the exact `socket-patch-core` dependency pin)
- `Cargo.lock` (the workspace members' own entries)
- `npm/socket-patch/package.json` (and its `optionalDependencies`) and `package-lock.json`
- every per-platform `npm/socket-patch-*/package.json`

Publishing fans out from the single **`.github/workflows/release.yml`**
dispatch: one run creates a GitHub release with standalone binaries and
`SHA256SUMS`, and publishes the crates.io and npm packages. The binary is
the preferred install via `https://install.socket.dev/patch`; npm also
supplies the official Socket CLI. Each registry leg lives in its own
workflow (`.github/workflows/publish-{cargo,npm}.yml`), dispatched at the
release tag and independently dispatchable to retry one registry against
an existing release. The npm leg waits for the GitHub release so it can
package those same binaries. See [the release runbook](../../docs/releasing.md).

## How the contract is enforced

Every item in this document is locked in by at least one of:

- **clap parser snapshots** in `crates/socket-patch-cli/tests/cli_parse_*.rs` — assert flag names, short forms, defaults, aliases, and CSV delimiters by calling `socket_patch_cli::Cli::try_parse_from(...)`.
- **Helper unit tests** in `crates/socket-patch-cli/src/**` (`#[cfg(test)] mod tests` blocks) — cover `looks_like_uuid`, `parse_argv_with_shortcuts`, `detect_identifier_type`, `select_patches`, `find_patches_to_rollback`, `partition_purls`, the JSON serializers, and the terminal UI in `src/ui/` (`StatusLine` redraw/clear/`println` byte streams, `confirm_with` answers and non-interactive notes, `select_one`'s JSON/empty guards, `plural`, `truncate`, the `color_enabled` truth table, `paint`/`severity`, and `pad`/`strip_ansi` alignment).
- **Async `run()` integration tests** in `tests/cli_parse_list.rs`, `tests/cli_parse_remove.rs` — exercise the no-network error paths and assert JSON shape via `serde_json::from_str::<Value>` + per-key assertions.

If you add a new flag/subcommand/JSON key, add a test here that locks the new surface in the same PR.


### Vendored JVM support (v5)

Maven reactors and Gradle 6.8+ route to the JVM backend automatically. Ledger
entries use ecosystem `jvm` with Maven PURLs. Revert, remove, rollback and repair
share the v5 vendored backend; existing prototype wiring remains readable.
See [the JVM design](../../docs/design/maven-vendoring.md) for supported shapes.

`vendor --check` is an offline, read-only audit. Healthy entries emit `verified`
with `vendor_check_ok`; drift emits `failed` with `vendor_check_failed`, a
`partialFailure` envelope and exit 1. Drift covers the committed artifact and its
wiring: an entry whose lockfile or config no longer references its
`.socket/vendor/` artifact (for example after `pipenv lock`, `uv lock` or
`npm install` re-resolved it) fails by the same liveness rule as `vex`'s
`vendor_unwired`. The reason names the cause: another lock resolving the same
version from elsewhere (`wiring contested`, naming both locks; delete the one
the project does not install from), or, for npm and PyPI, a dependency no lock
resolves any more (`dependency removed`; `scan --mode vendored --prune` reverts
the entry). For a package-lock entry, drift also includes a
`package-lock.json` / `npm-shrinkwrap.json` entry for the vendored `name@version`
that `vendor` would rewire but that does not resolve to the vendored artifact
(#588); the reason names that entry. Missing ledger entries fail with
`vendor_ledger_missing`: a manifest patch with no ledger entry, and a lockfile
reference to `.socket/vendor/<eco>/<uuid>/` that no ledger entry owns (the
artifact-level event repair emits: `uuid` plus `details.{ecosystem,path}`, no
purl), so a checkout whose ledger was ignored or dropped from the commit no
longer passes with nothing to check. Offline upstream metadata is reported as the run warning
`vendor_jvm_upstream_unverified`. The check never starts an API client or writes
lock/recovery files. `--check` conflicts with `--revert`.

`vendor --check --local-repo <path>` additionally checks existing suffixed Maven
jar/POM copies for conflicting bytes. `--maven-config auto|none` is a global
vendoring option so scan/get/repair receive it too; omission preserves the
ledger's recorded choice. Switching existing auto-config wiring to `none`
requires reverting it first. `none` cannot be combined with a repository ban.

### sbt resolution evidence (hosted and vendored sbt)

Hosted and vendored sbt pins are gated on sbt's own resolution records under
`target/` (the update-cache JSON on sbt 1.0–2.x, the Ivy reports on 0.13–1.2
and `useCoursier := false`; scala-cli's `.scala-build/.bloop/*.json`), never on
the machine-wide cache, and sbt is never run. The walk looks for `target/` to
depth 6, skips `.git`, `node_modules`, `.socket`, `.bsp`, `.idea`, `.metals`,
`.bloop`, `.scala-build` and a top-level `out/`, never follows a symbolic link,
reads FIFO-safely, and stops at 512 files / 64 MiB / 8 MiB per file. Over a cap,
or with an unreadable or malformed record, there is no evidence at all. The
in-memory hosted engine never has evidence. Evidence is stale when a build
source (`*.sbt`, `project/*.scala`, `project/build.properties`) is newer than
the newest library record (the meta-build's records, which every sbt load
rewrites, never count); the remedy is `sbt update` (`sbt clean update` if the
warning persists). An sbt 2 project whose id is the meta-build's
(`<root dir>-build`) shares its record directory with the meta-build and is
never trusted (its evidence counts as missing).

Vendored codes (emitted before planning):

| Code | Kind | Meaning |
|---|---|---|
| `vendor_sbt_no_resolution_evidence` | `skipped`, exit 0 | No readable evidence (the detail names a cap or read error) |
| `vendor_sbt_resolution_incomplete` | `skipped`, exit 0 | A declared project has no evidence, or the project definitions cannot be read statically |
| `vendor_sbt_resolution_stale` | `skipped`, exit 0 | A build source is newer than some project's evidence |
| `vendor_sbt_meta_build_only` | `skipped`, exit 0 | Only the meta-build (sbt plugins) resolves the GA |
| `vendor_jvm_not_resolved` | `skipped`, exit 0 | No project of the build resolves the GA; nothing to vendor |
| `vendor_sbt_pin_declared_newer` | refusal | A build source now declares an existing pin's GA newer than its base (the override would force it back down; sbt's load-time verifier fails the build). Revert the patch, or declare the base again |
| `vendor_sbt_version_conflict` | refusal | Some project resolves another version than the patch's base |
| `vendor_sbt_scala_runtime_unsupported` | refusal | `org.scala-lang` / `org.scala-lang.*` |
| `vendor_sbt_classifier_unsupported` | refusal | A classified artifact other than `sources` / `javadoc` is resolved |
| `vendor_sbt_pin_unverifiable` | advisory | An existing pin's dependency digest no longer matches the build and the evidence predates the change (fresh evidence re-verifies the pin and records the new digest) |
| `vendor_sbt_override_shadowed` | advisory | An existing pin's base version is still resolved somewhere |
| `vendor_sbt_resolved_elsewhere` | advisory | An existing pin's suffixed version resolves from outside `.socket/vendor/maven2` from a file whose sha256 is not the pinned jar's (a copy with the pinned bytes, e.g. the Ivy cache, is fine) |

A run-level skip is a `skipped` event carrying the code (never counted
applied). A GA no project resolves is `vendor_jvm_not_resolved` (`SOCKET_DEBUG`
also logs `vendor_sbt_not_resolved`). Vendoring over a hosted sbt pin (a
takeover, or an eject) runs this gate BEFORE the hosted pin is restored: a pin
the gate would stop is refused (`failed` with the gate's code; an eject is
refused whole, `eject_refused`) and stays hosted. An eject whose vendored run
leaves any ejected package without a ledger entry is `eject_incomplete` and
restores the pre-eject files. The pin's dependency digest is the one over every
build source the evidence walk reads (the hosted definition).

**Vendored sbt.** An sbt build root (`project/build.properties` naming an
`sbt.version` of 0.13.18 or later) routes to the JVM backend as well. It writes
no user file: the generated root `socket-patch-vendor.sbt` pins the sha256 of
each tree file, resolves from the reactor-style suffixed tree
`.socket/vendor/maven2/<g>/<a>/<v>-socket.<hex8>/` (its resolver moved ahead of the
default repositories on 0.13 / 1.x, so the tree resolves with the network down) (re-included by its own
`.gitignore`, `!*`, and kept byte-exact by `.gitattributes`) and forces the
suffixed version with `dependencyOverrides +=`. Its load-time check and
post-resolution verifier fail the sbt build closed on a tampered tree or a
replaced pin. Ledger records: `sbt_build_fragment` (`file`, `pin:<uuid>`), the
tree root's `jvm_owned_file`s, and the usual tree/upstream records. Revert drops
the patch's rows in any order and deletes the generated file, after a strict
parse proves it socket-patch's, once no pins remain; an edited file is
`vendor_lock_entry_drifted` and keeps the tree while it still names the patch.
A project already vendored through the Maven reactor, the single-pom path or the
Gradle backend stays on it when sbt files appear. A generated file left without
a ledger is `vendor_ledger_missing` for `vendor --check`. Refusals (nothing written):
`vendor_sbt_build_root_unknown` (no `sbt.version`; a subproject directory
inside an sbt build is `vendor_jvm_shape_unsupported` with
`reason: not_build_root`), `vendor_sbt_unsupported_version`,
`vendor_jvm_build_ambiguous` (a `<modules>` `pom.xml`, Gradle or Mill files
beside the sbt build), `vendor_sbt_owned_file_modified`,
`vendor_sbt_owned_file_foreign` (rename your own file),
`vendor_sbt_hosted_conflict` (the hosted `socket-patch.sbt` pins the GA, or
cannot be read), `vendor_sbt_override_conflict` (another base version of the
GA is pinned), `vendor_sbt_unsafe_value`, and, for a new pin only,
`vendor_sbt_overrides_assignment` / `vendor_sbt_resolvers_assignment`
(`dependencyOverrides` / `resolvers` assigned with `:=` or `~=` in `build.sbt`,
`project/plugins.sbt`, `project/Dependencies.scala`, `project/Build.scala` or a
declared subproject's `build.sbt`) and `vendor_sbt_dependency_lock_present`.
Warnings (still wired): `vendor_sbt_pom_ignored` (a single-module `pom.xml`
beside the build), `vendor_sbt_version_untested` (sbt 2.1 and later),
`vendor_sbt_override_build_repos` (`sbt.override.build.repos=true` in
`.sbtopts`, `.jvmopts` or `project/build.properties`: the build fails closed
at load), and `vendor_sbt_pin_unverifiable` (the build's dependency literals
changed since the pin was written and no evidence resolved since; the pin is
kept). The next steps name the generated root file to commit
(`socket-patch-vendor.sbt`, or `socket-patch.scala` for scala-cli) and
`sbt update` / `scala-cli compile --test .`.

### Vendored scala-cli builds

A root holding `project.scala` (or the owned `socket-patch.scala`) and no
`pom.xml`, Gradle or Mill build file is a scala-cli directory build. Vendoring
writes only owned files: the root `socket-patch.scala`, the guard
`.socket/vendor/coursier/socket-patch.scala`, the same-GAV tree
`.socket/vendor/coursier/<g>/<a>/<v>/` (jar, upstream pom, `.sha1` files,
marker) with its `.gitignore` (`!*`) and `.gitattributes`, and
`.socket/vendor/coursier-index.tsv`. Ledger entries use ecosystem `jvm`:
`coursier_index_fragment` (the index), `jvm_owned_file` (the two `.scala`
files and the tree's git files) and the usual tree/upstream records.
The gate reads scala-cli's Bloop project files under `.scala-build/.bloop/`;
it never runs scala-cli. See [the sbt / Mill / scala-cli design](../../docs/design/sbt-support.md).

| Code | Action | Meaning |
|---|---|---|
| `vendor_scala_cli_resolution_missing` | `skipped` (warning, exit 0) | No Bloop project of this workspace under `.scala-build/.bloop/` (fresh clone, or only `--server=false` builds). Nothing is written; remedy: `scala-cli compile --test .` with the default Bloop server, then re-run. A GAV the committed tree already serves (`coursier-index.tsv` lists it) is never skipped for missing or stale evidence: it is re-planned in sync. |
| `vendor_scala_cli_resolution_stale` | `skipped` (warning, exit 0) | An input the evidence lists, or a source anywhere in the directory input it does not list, is newer than the last Bloop compile, or the evidence is a single-file run's (it does not list `project.scala`). Remedy: `scala-cli compile --test .`, then re-run. |
| `vendor_scala_cli_not_resolved` | `skipped` (warning, exit 0) | The build does not resolve the patched GA; nothing to vendor. |
| `vendor_scala_cli_version_conflict` | `failed` | The build resolves the GA at another version than the patch's base. |
| `vendor_scala_cli_classifier_unsupported` | `failed` | The build also resolves a classified artifact of the GA (other than `sources` / `javadoc`), which the tree's plain jar cannot serve. |
| `vendor_scala_cli_scala_runtime_unsupported` | `failed` | The GA is the Scala runtime (`org.scala-lang`), selected by `//> using scala`. |
| `vendor_scala_cli_repository_shadowed` | `failed` | An input (any source the evidence lists, inside the project or not, or any `.scala`/`.sc`/`.java` file of the directory) declares a repository (`//> using repository`/`repositories`/`repo`, or a `-r` / `--repository` option), which scala-cli consults before the tree, or pins a dependency of the patched group to a direct `,url=`, which bypasses every repository, or a build after wiring resolved the GA outside the tree (a command-line `-r`). Remedy: move the repository to `COURSIER_REPOSITORIES` (consulted after the tree) or use hosted mode. |
| `vendor_scala_cli_path_unsupported` | `failed` | The project path holds `%` or a non-ASCII character, which scala-cli's `file://${.}` URL cannot carry (it percent-decodes, and fails the build on non-ASCII). |
| `vendor_scala_cli_windows_unsupported` | `failed` | Windows: `file://${.}` is unverified there. |
| `vendor_scala_cli_owned_file_modified` | `failed` | `socket-patch.scala` or the guard exists with other bytes (a CRLF checkout of the owned text counts as unmodified). |
| `vendor_coursier_tree_conflict` | `failed` | The patch's version directory holds another patch's marker that the index does not list. |
| `vendor_scala_cli_directives_split` | warning | `project.scala` exists, so scala-cli warns "Using directives detected in multiple files"; `project.scala` is never edited. |

Revert removes the patch's index rows and tree; the last one out also deletes
the index, both `.scala` files and the tree's git files. A modified owned file
is left alone (`vendor_lock_entry_drifted`), and while a left-behind
`socket-patch.scala` still includes the guard, the guard and the tree stay
(`kept_artifact`). Single-file runs (`scala-cli run main.scala`) ignore the
directory wiring: pass `-r file://$PWD/.socket/vendor/coursier`.

## Gradle builds (v5.0)

Gradle is part of the `maven` ecosystem: Gradle-resolved artifacts are Maven PURLs
(`pkg:maven/<group>/<artifact>@<version>`), and every mode below works on Gradle 6.8
or newer, Groovy and Kotlin DSL alike. The per-mode guide is
[docs/ecosystems.md](../../docs/ecosystems.md#gradle). Every code in this section is
additive (MINOR); `test_gradle_contract_codes` (`tests/contract_gradle_codes.rs`)
fails when the source emits a Gradle or JVM code this section does not name.

### Discovery (`scan`, every mode)

The crawler reads the Gradle user home's `caches/modules-2/files-2.1` and, when set,
the read-only cache `$GRADLE_RO_DEP_CACHE/modules-2/files-2.1` (scanned, never
written), before the Maven local repository. The user home is resolved the way the
JVM does it: `-Dgradle.user.home` in `GRADLE_OPTS`, else `GRADLE_USER_HOME`, else
`<home>/.gradle`, where `<home>` is the passwd entry's directory on Unix (not
`$HOME`) and `USERPROFILE` / `HOME` on Windows. One Gradle version directory holds a
hash directory per download (named by the file's sha1, leading zeros possibly
dropped); every hash directory holding a record's files is a separate installed copy.

For a Gradle-only build, `~/.m2` is a scan root only when the build can read it:
`mavenLocal()` (or `mavenLocal { … }`) in any settings, build, `buildSrc`,
included-build, applied or init script makes it one; a script or init script that
cannot be read literally makes the gate undetermined, and the repository is scanned.
Run-level `warnings[]` entries for these carry an additive `level` field (`info` or
`warn`; every other code has none); human mode prints `info` as `Note:` lines, which
`--silent` suppresses:

| Code | Level | Meaning |
|---|---|---|
| `gradle_build_ignores_m2` | `warn` | The build declares no `mavenLocal()`, and modules its locks (or the manifest) name exist only in `~/.m2`; they are not scanned. |
| `gradle_maven_local_undetermined` | `info` | `mavenLocal()` could not be ruled out (an unreadable script or init script), so `~/.m2` stays a scan root. |
| `gradle_user_home_differs` | `info` | The passwd home differs from `$HOME`, so Gradle's cache is not under `$HOME/.gradle`. Never emitted with `--global-prefix`. |

A package crawled from a Gradle cache gets an additive `inLock` boolean when the
`--cwd` is a Gradle build whose lock files were read (local and global runs): `true`
when a `gradle.lockfile` / `buildscript-gradle.lockfile` / `settings-gradle.lockfile`
or a legacy `gradle/dependency-locks/*.lockfile` names that GAV. It annotates and
never filters.

### Agent mode (`apply`, `scan --mode agent`)

`apply` writes every copy a build consumes: each `~/.m2` version directory the build
reads and each Gradle hash directory that holds the record's files. A Gradle version
directory holding none of the record's files is not an install of it
(`package_not_installed`). One holding only some of them is: the held files are
patched and the missing ones fail that copy as not found, as on `~/.m2` (the build
still loads the held jar). A record keyed by jar members (`<a>-<v>.jar/<member>`,
#264) swaps the whole jar for the patch service's build of it, in one transaction
across every consumed copy: one download, one backup per distinct original under
`.socket/jvm-originals/`, and a failed write puts every copy already swapped back.
`rollback` (and `remove`) restores every writable copy that still holds the record's
patched bytes: never the read-only cache, but also a `~/.m2` copy a Gradle-only build
no longer reads (an earlier apply wrote it while the build declared `mavenLocal()`,
or before v5.0 gated `~/.m2`; leaving it would strand the shared jar patched once
`remove` drops the record). It restores from the backup, else, online and for a
Gradle copy only, from an upstream download that hashes to the copy's hash
directory. Such an unread `~/.m2` copy never fails the run: one that holds bytes
that are neither side of the record (another build applied a different patch there,
or `mvn install` rebuilt it), lacks a file, or is a swapped jar whose original this
project never backed up is left as it is with `gradle_m2_copy_not_restored`, and
`remove` still drops the record.

Run-level `warnings[]` codes (a refusal is also a `failed` event whose `error`
starts with the code):

| Code | Run result | Meaning |
|---|---|---|
| `gradle_verification_metadata_present` | refused, exit 1 | `gradle/verification-metadata.xml` exists; rewritten cache bytes would fail (or, with key-only trust, slip past) Gradle's dependency verification. Nothing is written; use `--mode vendored` or `--mode hosted`. |
| `gradle_build_ignores_m2` | refused, exit 1 | The only installed copy is in `~/.m2`, which this Gradle-only build never reads. Nothing is patched; build once so Gradle caches it, then apply again. |
| `gradle_m2_may_be_unconsumed` | warning | A Gradle-only build that declares `mavenLocal()` (or may) has no Gradle cache copy, so only the `~/.m2` copy was patched. Gradle takes a module from the first declared repository that has it: with another repository before `mavenLocal()`, the next build downloads the unpatched jar. Run the build once and apply again. |
| `gradle_ro_cache_shadows` | exit 1 | The read-only cache holds a copy that is never written and that Gradle may read first. Writable copies are still patched. |
| `gradle_copy_unexpected_bytes` | refused, exit 1 | A hash directory's file is the pristine download (its sha1 names the directory) but neither side of the record, or a hash directory holds a variant's files whose bytes no variant was made for. That copy is left unpatched and the run fails (changed in v5.0: it used to only warn), since the build still loads it. |
| `gradle_transform_copy_stale` | that copy fails | After the write, Gradle still holds a copy derived from the pristine jar (`caches/transforms-*`, `caches/jars-*`, instrumented jars). Run `gradle --stop`, delete those directories, apply again. |
| `gradle_transform_copy_unverified` | warning | A same-named derived copy is neither the pristine nor the patched jar and is older than the patch, or the derived-cache walk was cut short. |
| `gradle_jar_locked_by_daemon` | that copy fails | Windows only: the jar is held open (errors 32, 33, 303, or 5 on an existing writable file), normally by a Gradle daemon. Also reported by rollback. Run `gradle --stop` and retry. |
| `jvm_agent_service_required` | refused, exit 1 | A member-keyed record needs the patch service's jar, and the run is offline, the service is disabled or pending, or it did not provide one. Nothing is written. |
| `jvm_agent_service_integrity` | refused, exit 1 | The service jar failed transfer-integrity verification. Nothing is written. |
| `jvm_agent_service_jar_mismatch` | refused, exit 1 | The service jar does not carry the record's `afterHash` members, is unreadable, or differs from the installed jar outside the patched members. Nothing is written. |
| `jvm_jar_backup_failed` | refused, exit 1 | The original jar could not be backed up before the swap. Nothing is written. |
| `gradle_rollback_hash_mismatch` | rollback: that copy fails | A file restored into a Gradle hash directory does not hash to the directory's name (the sha1 Gradle verified on download): the before-blob is not that download. The file is left as it is and the result fails; delete that hash directory so Gradle downloads it again. |
| `jvm_jar_backup_missing` | rollback: that copy fails | No backup of the original jar exists (and, for a Gradle copy, no upstream download matched its hash directory, or the run is offline). The copy is left as it is. |
| `gradle_m2_copy_not_restored` | rollback / remove: warning | A `~/.m2` copy this Gradle-only build does not read could not be restored (its bytes are neither side of the record, a file is missing, or it is a swapped jar with no backup in this project). It is left as it is and does not fail the run. A file that is there but cannot be read (permissions, not a regular file) may still hold the patched bytes, so it fails the run and `remove` keeps the record. |

Each patched Gradle copy's sidecar record (`PatchEvent.sidecar`) carries an advisory
instead of a checksum-file rewrite (a `files-2.1` copy has none):
`gradle_refresh_reverts` (info: `--refresh-dependencies` downloads a fresh copy),
`gradle_daemon_stale` (info: a registered daemon of this user home may still hold the
old jar; `gradle --stop`), `gradle_global_cache_shared` (info: every build of the user
home sees the patch) and `gradle_jar_locked_by_daemon` (error, above). A `~/.m2` copy's
`.sha1` / `.md5` files that described the pre-patch bytes are rewritten to the patched
ones, and back on rollback; a checksum file that already disagreed is left alone.

### Hosted mode (`scan --mode hosted`)

A Gradle build (a root `settings.gradle[.kts]` or `build.gradle[.kts]`) gets automated
wiring; the pasted `exclusiveContent` snippet of v4 is now only the refusal fallback.
The planner writes, all committed with the build:

- `.socket/gradle/socket-patch.hosted.settings.gradle` (static, changes only with a
  CLI release), `.socket/gradle/hosted-index.tsv` (one row per pinned GA:
  `g:a:base`, suffixed version, repository URL, jar and pom sha256, uuid) and
  `.socket/gradle/.gitattributes` (`* -text`);
- one apply line in every settings file of the checkout's builds (root, `buildSrc`,
  each literal `includeBuild`), `apply from: '.socket/gradle/socket-patch.hosted.settings.gradle' // socket-patch-hosted <digest>`
  (Kotlin: `apply(from = …)`), carrying the index digest so a changed index
  invalidates the configuration cache; a settings file the planner had to create
  carries ` created` after the digest, and only such files are deleted on restore;
- every lock entry of the GA in every build's lock files moved from the base to the
  suffixed version (each line keeps its line ending);
- the suffixed component in an existing `gradle/verification-metadata.xml` (never
  created).

The script routes the suffixed version to its Socket repository with
`exclusiveContent`, substitutes every request whose selector admits the base (direct,
transitive, ranges, dynamic and rich versions), rejects every other candidate at or
below the base, and fails the build (`socket-patch: … resolved …`) if anything still
resolves there; it also checks the jar's sha256 against the index. A request whose
selector does not admit the base (an explicit newer version, a lock or `strictly` above
the base, a transitive bump) is left alone and resolves above the base (a newer
upstream fix is never downgraded); `vex` withholds the attestation when a lock entry
records such a version (`vex_gradle_lock_above_base`), and otherwise judges the
installed suffixed copies. A dynamic or range selector that admits the base is pinned
like a lock: it resolves the patched version even after a newer upstream release
appears (the Socket repository lists no versions), reported as
`redirect_gradle_dynamic_selector_pinned`. A `latest.release` / `latest.integration`
request is refused (`redirect_gradle_latest_selector`): whether it admits the base
depends on what the repositories list, so the script cannot rewrite it, and with every
upstream candidate at or below the base rejected it fails to resolve until upstream
ships a newer release. Detached
configurations (`configurations.detachedConfiguration`) are not reached.

A dep is **confirmed** (`redirected`, attested) only when the final files hold the
socket-patch script, the live apply line with the current digest in every target
settings file, the index row, and in every lock entry of the GA the suffixed version
or a release above the base (`confirmed_gradle_uuids`); anything else is not counted. `list`, `vex`, `rollback`,
`remove`, `vendor` and `repair` discover hosted Gradle pins from the index under the
same rules (a settings-classpath lock naming the GA, a stale digest, a custom
`lockFile`, a non-Socket URL, a lock at another version, or any build- or GA-level
refusal of the planner holding now — a settings-classpath declaration, an
`includeBuild` it cannot follow, an Android / KMP plugin, a classifier request, a user
`exclusiveContent` rule — is `patched_ref_invalid`, no reference). A lock entry above
the base is still a reference, so `list`, `rollback` and `remove` find the pin, but
`vex` omits it (`vex_gradle_lock_above_base`, as a run warning and as the
`failed[].reason`): that build resolves the newer upstream release, not the patch.
`rollback` /
`remove` restore without the network: lock entries back to
the base, the row out of the index, the verification component out when it is still
exactly what the planner wrote (else `gradle_verification_component_left`), and the
owned files and apply lines once no row is left.

`scan --mode hosted` over a vendored Gradle entry runs this planner's checks first
(`takeover_refusal`, wet and `--dry-run` alike): a refused purl keeps its vendored
patch byte-identical and is skipped with the refusal code, whose detail says so. An
eject (`vendor` over hosted pins) snapshots every Gradle wiring file before it
restores, so a failed vendor step rolls the whole build back byte-exact.

Refusals write nothing for the dep and are followed by `redirect_gradle_manual_snippet`
(a per-DSL snippet applying the owned script's rules for this dep: `exclusiveContent`
for the suffixed version, every request whose selector admits the base rewritten to it
— by dependency substitution on the strictly / require / prefer constraint, so a
`prefer`-only rich version is covered, and by `eachDependency` — and every other
candidate at or below the base rejected; it declares no dependency):

| Code | Cause |
|---|---|
| `redirect_gradle_version_unsupported` | The wrapper pins Gradle below 6.8. |
| `redirect_gradle_android_or_kmp` | An Android or Kotlin Multiplatform plugin, in any script or catalog `[plugins]`. |
| `redirect_gradle_include_build_unresolved` | An `includeBuild` the script graph cannot follow. |
| `redirect_gradle_lock_location_unknown` | A build script sets a custom `lockFile`. |
| `redirect_gradle_build_file_unreadable` | A settings, build, catalog, lock or owned file the script graph reaches exists but cannot be read as UTF-8 text (permissions, encoding, not a regular file). The planner refuses rather than take it for absent, which would create a settings file over the user's. The hosted writer also refuses, as a whole-run refusal, to write a settings file it did not read over one on disk. |
| `redirect_gradle_index_malformed` | `.socket/gradle/hosted-index.tsv` does not parse. |
| `redirect_gradle_same_gav_unsupported` | The grant serves the original GAV (no `mavenSuffixedVersion` / `mavenPomSha256`), which cannot be pinned fail-closed. |
| `redirect_gradle_override_invalid` | The grant has unsafe coordinates, a non-canonical uuid, a wrong suffix, a non-https repository, a missing digest, or no maven2 repository. |
| `redirect_gradle_vendored_conflict` | The GA is vendored (`.socket/vendor/gradle-index.tsv`); `vendor --revert` first. |
| `redirect_gradle_settings_classpath` | The GA is on a settings-script classpath (declared, or named in any `settings-gradle.lockfile`), which resolves before the script runs. |
| `redirect_gradle_classifier_declared` | A declaration requests a classifier the Socket repository does not serve. |
| `redirect_gradle_range_declared` | A `strictly` constraint excludes the patched base version and admits nothing above it. |
| `redirect_gradle_latest_selector` | A declaration requests `latest.release` / `latest.integration`, which the pin cannot rewrite; the build would fail until upstream ships a release above the base. Declare the base version explicitly and scan again. |
| `redirect_gradle_exclusive_content_conflict` | A user `exclusiveContent` rule routes the group to another repository. |
| `redirect_gradle_version_conflict` | The index already pins the GA at another base, or two patches pin it in one run. |
| `redirect_gradle_lock_conflict` | A lock entry names the GA below the base (and not at the suffixed version); re-lock (`--write-locks`) first. A lock above the base is a newer upstream release the pin lets resolve, not a conflict. |
| `redirect_gradle_verification_unparseable` | `gradle/verification-metadata.xml` cannot be edited. |

Warnings on a confirmed run: `redirect_gradle_detached_configs_unguarded` (always:
detached configurations are not reached), `redirect_gradle_dynamic_selector_pinned` (a
declaration's dynamic or range selector admits the base, so it stays on the patched
version while the patch is in place), `redirect_gradle_verification_component_left`
(a replaced patch's verification component was edited by hand, so it is kept; an
unedited one is removed with its row), `redirect_gradle_unscanned_build_logic`
(build logic the graph could not follow, so a declaration, lock or repository there
is unchecked) and `redirect_gradle_module_metadata_unavailable` (the grant carries no
`mavenModuleSha256`: the Socket repository serves no suffixed `.module`, so Gradle
falls back to the pom and the upstream module's variants and capabilities are not
applied). When it does, the suffixed `.module` and its digest go into the
verification component, also on a rescan of a component written before the service
served it. File edits in `rewrittenFiles` / the edit list carry the kinds
`redirect_gradle_hosted_index`, `redirect_gradle_hosted_script`,
`redirect_gradle_gitattributes`, `redirect_gradle_settings_apply`,
`redirect_gradle_lock_entry` and `redirect_gradle_verification_component`. The
`RewriteResult` keeps `gradle_uuids`, `confirmed_gradle_uuids` and
`refused_gradle_uuids` (every maven uuid of a Gradle build lands in exactly one of the
last two).

### Vendored mode (`vendor`, `scan --mode vendored`, `get --mode vendored`)

See [Vendored JVM support](#vendored-jvm-support-v5) and the
[JVM design](../../docs/design/maven-vendoring.md#gradle). Gradle keeps the original
coordinates: the GAV is committed under `.socket/vendor/gradle/`, indexed by
`.socket/vendor/gradle-index.tsv` and served by `.socket/gradle/socket-patch.settings.gradle`
through one apply line per settings file. Results use these codes; the detail starts
with `reason: <reason>: `:

| Code | Effect | Gradle reasons |
|---|---|---|
| `vendor_jvm_shape_unsupported` | refusal, nothing written | `gradle_below_6_8`, `android_or_kmp` (also `available-at` module redirects), `gradle_exclusive_content_conflict` (a user rule claiming the module, in any script), `gradle_range_excludes_vendored` (no declared selector admits the vendored version), `gradle_verification_unparseable`, `gradle_index_unreadable`, `build_file_unreadable` (including a non-UTF-8 settings file), `build_file_outside_root`, `not_build_root` (run from a directory an ancestor settings file includes or may include, from a project with no settings file of its own below one, or below an ancestor settings file that is not UTF-8; `repair` refuses there too), `no_build_file` |
| `vendor_jvm_upstream_unavailable` | refusal | `classifier_unavailable` (a declared classifier jar no cache or registry has), `module_unavailable` (the pom declares Gradle module metadata that cannot be sourced), `pom_unavailable`, `verification_metadata_unavailable` |
| `vendor_jvm_degraded` | applied, VEX withheld | `gradle_unscanned_build_logic`, `unwired_build_logic` (a nonliteral included build), `settings_plugins_unwired`, `classifier_unpatched_copy` (a classifier jar carries an unpatched copy of a patched member), `verification_parent_chain_unhandled`, `legacy_maven_root` (a single-POM root next to a Gradle build whose ledger already holds a single-POM entry; the Gradle build stays unpatched until `vendor --revert` and vendor again) |
| `vendor_jvm_note` | applied, informational | `range_declared` (a range, prefix or rich selector lists versions from the derived `maven-metadata.xml`), `ide_sources_unavailable` |
| `vendor_jvm_upstream_unverified` | warning | Upstream metadata was taken offline and not authenticated against registry checksums. |
| `vendor_gradle_unsupported` | refusal | Legacy single-POM path only: a Gradle project with no `pom.xml` that the JVM backend did not route. |

A root holding both `pom.xml` and a Gradle build vendors both in one ledger entry
(#395); either half refusing writes nothing. A derived
`.socket/vendor/gradle/<group-path>/<artifact>/maven-metadata.xml` keeps range,
prefix and rich selectors on the vendored version (#511). Existing pgp-only
verification entries get a `sha256` beside them (#487), and so do the classifier jars
the tree serves (a declared classifier, the IDE sources): the vendored repository
serves no signatures, so each gets its upstream `sha256` unless its entry already
holds a checksum. The owned script, index,
derived metadata and `.gitattributes` are compared line-ending blind (#429). Ledger
fragments use the kinds `gradle_settings_fragment`, `gradle_verification_fragment`,
`gradle_derived_metadata`, `jvm_owned_file`, `jvm_vendor_tree`, `jvm_created_dir`
and `jvm_upstream_status`; they are internal to the ledger and read back only by this
CLI.

### VEX

`vex` re-hashes every copy a build consumes (`~/.m2` copies the build reads, every
Gradle hash directory holding the record's files, and the suffixed copies of a
hosted pin) and attests only when all of them carry the patch. A Gradle version
directory that holds none of the record's files is ignored; one that holds only some
of them is judged, and its missing files withhold the statement. A derived copy
(`caches/transforms-*`, `caches/jars-*`, instrumented jars) proven to come from the
pristine jar, or a same-named one that is older than the patched jar and does not
match it, withholds the statement:

| Code | Kind | Meaning |
|---|---|---|
| `vex_gradle_unpatched_copy` | run warning | A copy a build may load does not carry the patch; no statement until every copy does. |
| `gradle_unpatched_copy` | `failed[].reason` | The purl the warning above withheld. |
| `vex_gradle_lock_above_base` | run warning and `failed[].reason` | A hosted pin is wired, but a lock file records a release above its base, which that build resolves instead of the patch; no statement until it is re-locked or the patch is rolled back. |
| `vex_pnpm_bundled_copy` | run warning and `failed[].reason` | An npm pin is wired, but its pnpm lock names a package whose `bundledDependencies` may ship an unpatched copy of it (the lock does not record that copy's version); no statement while that package bundles it. `vendor --check` and `scan` still treat the wiring as live. |
| `vex_deno_lock_copy` | run warning and `failed[].reason` | An npm pin is wired, but `deno.lock` locks the same `name@version`, which `deno install` installs without the wiring; no statement while it does. `vendor --check` and `scan` still treat the wiring as live. |
| `vex_gradle_derived_cache_unchecked` | run warning | The derived-cache walk was cut short (a very large transforms cache); the statement is still emitted, the copies the walk did reach were checked. |

A vendored Gradle entry attests only while its wiring is live (apply line, index rows,
intact script, a re-plan over the committed tree refused and degraded nowhere,
classifier jars free of unpatched patched members per the tree marker's `patched`
list); otherwise `vendor_unwired`.
