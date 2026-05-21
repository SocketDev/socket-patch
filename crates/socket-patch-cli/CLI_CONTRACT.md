# socket-patch CLI contract

This document defines the **public surface** of the `socket-patch` binary. Anything listed here is part of the user-visible contract: third-party scripts, CI pipelines, and the npm/pypi/cargo wrappers depend on it. Changes are governed by the semver policy at the bottom of this file.

> **Why this exists.** Until late 2026 the CLI crate had zero unit tests under `src/` — only network-dependent `tests/e2e_*.rs` suites that run with `--ignored`. A flag rename, a default-value change, or a JSON key rename could land green and break every shipped wrapper silently. The contract below is now backed by the unit tests under `crates/socket-patch-cli/src/**` (`#[cfg(test)] mod tests`) and the parser tests under `crates/socket-patch-cli/tests/cli_parse_*.rs`. Changes that violate the contract must update those tests in lock-step with a major version bump.

## Subcommands

| Name | Visible alias(es) | Notes |
|---|---|---|
| `apply` | — | Apply patches from the local manifest |
| `rollback` | — | Restore original files; takes optional positional `identifier` |
| `get` | `download` | Fetch + apply patch; requires positional `identifier` |
| `scan` | — | Crawl installed packages for available patches |
| `list` | — | Print patches in the local manifest |
| `remove` | — | Remove patch from manifest (rolls back first); requires positional `identifier` |
| `setup` | — | Configure package.json postinstall scripts |
| `repair` | `gc` | Download missing blobs + clean up unused ones |

**Bare-UUID fallback.** `socket-patch <UUID>` is rewritten to `socket-patch get <UUID>`. The UUID shape checked is the standard 8-4-4-4-12 hex pattern (case-insensitive). See [`src/lib.rs::looks_like_uuid`](src/lib.rs).

## Flags — long and short forms

Every flag below is part of the contract. The default values are pinned by parser tests.

### `apply`

| Long | Short | Default | Type |
|---|---|---|---|
| `--cwd` | — | `.` | path |
| `--dry-run` | `-d` | `false` | bool |
| `--silent` | `-s` | `false` | bool |
| `--manifest-path` | `-m` | `.socket/manifest.json` | string |
| `--offline` | — | `false` | bool |
| `--global` | `-g` | `false` | bool |
| `--global-prefix` | — | (none) | path |
| `--ecosystems` | — | (none) | CSV → `Vec<String>` |
| `--force` | `-f` | `false` | bool |
| `--json` | — | `false` | bool |
| `--verbose` | `-v` | `false` | bool |
| `--download-mode` | — | **`diff`** | string |

### `rollback`

Same as `apply` plus: `--one-off` (bool), `--org` (string), `--api-url` (string), `--api-token` (string). Positional `identifier` is **optional** (omit to rollback everything).

### `get`

Required positional `identifier`. Flags:

| Long | Short | Alias | Default | Type |
|---|---|---|---|---|
| `--org` | — | — | (none) | string |
| `--cwd` | — | — | `.` | path |
| `--id` | — | — | `false` | bool |
| `--cve` | — | — | `false` | bool |
| `--ghsa` | — | — | `false` | bool |
| `--package` | `-p` | — | `false` | bool |
| `--yes` | `-y` | — | `false` | bool |
| `--api-url` | — | — | (none) | string |
| `--api-token` | — | — | (none) | string |
| `--save-only` | — | **`--no-apply`** | `false` | bool |
| `--global` | `-g` | — | `false` | bool |
| `--global-prefix` | — | — | (none) | path |
| `--one-off` | — | — | `false` | bool |
| `--json` | — | — | `false` | bool |
| `--download-mode` | — | — | **`diff`** | string |

The hidden alias `--no-apply` on `--save-only` is **part of the contract** — it does not appear in `--help` but is widely used in existing scripts.

### `scan`

| Long | Short | Default | Type |
|---|---|---|---|
| `--cwd` | — | `.` | path |
| `--org` | — | (none) | string |
| `--json` | — | `false` | bool |
| `--yes` | `-y` | `false` | bool |
| `--global` | `-g` | `false` | bool |
| `--global-prefix` | — | (none) | path |
| `--batch-size` | — | **`100`** | usize |
| `--api-url` | — | (none) | string |
| `--api-token` | — | (none) | string |
| `--ecosystems` | — | (none) | CSV → `Vec<String>` |
| `--download-mode` | — | **`diff`** | string |
| `--apply` | — | `false` | bool |
| `--prune` | — | `false` | bool |
| `--sync` | — | `false` | bool |
| `--dry-run` | `-d` | `false` | bool |

`--apply` opts JSON callers into the full discover → select → apply pipeline. Without it, `scan --json` stays read-only (discovery + `updates` array only). No effect outside `--json` mode — the non-JSON path always prompts the user interactively. Designed for unattended workflows (cron jobs, bots that open PRs).

`--prune` opts into garbage collection. When set, `scan` removes manifest entries for packages no longer present in the crawl, then deletes orphan blob, diff, and package-archive files from `.socket/`. Off by default (v3.0) so a temporary uninstall doesn't silently destroy manifest state. Pair with `--apply` (or use `--sync`) for the auto-update workflow.

`--sync` is sugar for `--apply --prune` — the canonical single-flag bot invocation. `scan --json --sync --yes` discovers, applies, and reconciles state in one pass.

`--dry-run` (`-d`) previews what `--apply` / `--prune` / `--sync` would do without mutating disk. In JSON mode, `apply.patches[*]` is populated with would-be actions (computed via `decide_patch_action` against the current manifest) and `gc.prunable*` / `gc.orphan*` fields report counts via the cleanup helpers' built-in dry-run mode. No effect without at least one of `--apply`, `--prune`, or `--sync`.

### `list`

| Long | Short | Default | Type |
|---|---|---|---|
| `--cwd` | — | `.` | path |
| `--manifest-path` | `-m` | `.socket/manifest.json` | string |
| `--json` | — | `false` | bool |

### `remove`

Required positional `identifier`. Flags:

| Long | Short | Default | Type |
|---|---|---|---|
| `--cwd` | — | `.` | path |
| `--manifest-path` | `-m` | `.socket/manifest.json` | string |
| `--skip-rollback` | — | `false` | bool |
| `--yes` | `-y` | `false` | bool |
| `--global` | `-g` | `false` | bool |
| `--global-prefix` | — | (none) | path |
| `--json` | — | `false` | bool |

### `setup`

| Long | Short | Default | Type |
|---|---|---|---|
| `--cwd` | — | `.` | path |
| `--dry-run` | `-d` | `false` | bool |
| `--yes` | `-y` | `false` | bool |
| `--json` | — | `false` | bool |

### `repair`

`repair` (alias `gc`) is a first-class command for cleaning up the `.socket/` directory without running a scan. For the combined discover-and-apply workflow with GC, use `scan --sync --json --yes`; for cleanup alone, use `repair` (or `gc`) directly. The `gc` visible alias is part of the contract — removing or demoting it is a MAJOR bump.

| Long | Short | Default | Type |
|---|---|---|---|
| `--cwd` | — | `.` | path |
| `--manifest-path` | `-m` | `.socket/manifest.json` | string |
| `--dry-run` | `-d` | `false` | bool |
| `--offline` | — | `false` | bool |
| `--download-only` | — | `false` | bool |
| `--json` | — | `false` | bool |
| `--download-mode` | — | **`file`** | string |

**Note:** `repair`'s `--download-mode` default differs from every other command (`file` vs `diff`). This is intentional — repair restores legacy per-file blobs needed to apply any patch.

## CSV value parsing

`--ecosystems` on `apply`, `rollback`, and `scan` uses clap's `value_delimiter = ','`. Input `--ecosystems npm,pypi,cargo` becomes `vec!["npm", "pypi", "cargo"]`. Switching to space-separated or dropping the delimiter is a **breaking** change.

## JSON output shapes

Every `--json` invocation emits a single JSON object that follows the **unified envelope** below. The envelope was introduced in v3.0; older per-command shapes are deprecated. See `src/json_envelope.rs` for the source of truth and `tests/cli_parse_*.rs` for snapshot tests that lock the shape.

### Envelope shape

```jsonc
{
  "command":  "apply" | "rollback" | "get" | "scan" | "list" | "remove" | "repair" | "setup",
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

### Stable `errorCode` tags

| Tag                       | Action(s)        | Context |
|---------------------------|------------------|---------|
| `already_patched`         | `skipped`        | apply: every file's hash already matches `afterHash`. |
| `package_not_installed`   | `skipped`        | apply: manifest entry has no matching installed package. |
| `apply_failed`            | `failed`         | apply: hash mismatch, write error, archive read error. |
| `no_local_source`         | `skipped`/`failed` | `--offline` and the patch is missing from `.socket/`. |
| `paid_required`           | `failed` / status=`paidRequired` | get/scan: patch needs a paid plan and the caller's token isn't entitled. |
| `download_failed`         | `failed`         | repair/get: network or 404 on patch fetch. |
| `rollback_failed`         | `failed`         | remove/rollback: file restore could not complete. |

### Top-level `EnvelopeError` codes

| Code                  | Subcommands                      | Meaning |
|-----------------------|----------------------------------|---------|
| `manifest_not_found`  | list, remove, repair, rollback   | `.socket/manifest.json` doesn't exist. |
| `manifest_invalid`    | list, remove                     | Manifest exists but is unparseable. |
| `manifest_unreadable` | list, remove                     | I/O error reading manifest. |
| `apply_failed`        | apply                            | apply pipeline error before any patch ran. |
| `repair_failed`       | repair                           | repair pipeline error. |
| `remove_failed`       | remove                           | Could not write the modified manifest. |

### Per-subcommand action matrix

| Subcommand   | Emits |
|--------------|---|
| `apply`      | `Applied` · `Updated` · `Skipped` (already_patched / package_not_installed) · `Failed` · `Verified` (dry-run) |
| `list`       | `Discovered` (with `details.vulnerabilities`, `details.tier`, `details.license`, `details.description`, `details.exportedAt`) |
| `repair`/`gc`| `Downloaded` (or `Verified` on dry-run) · `Removed` (or `Verified`) · `Failed` artifact events |
| `remove`     | `Removed` (per purl) · artifact-level `Removed` event (with `details.blobsRemoved`, `details.rolledBack`) |

### Migration status (v3.0)

The unified envelope is the v3.0 contract. As of this release, these commands emit the envelope and have snapshot-test coverage:

- ✅ `apply`
- ✅ `list`
- ✅ `repair` / `gc`
- ✅ `remove`

The remaining commands still emit their pre-v3.0 ad-hoc JSON shapes and will migrate in a follow-up PR. Until then, downstream consumers should branch on the `command` field (envelope) vs the legacy shape (no `command` field, `status` in snake_case):

- ⏳ `scan` — still emits the discovery + `apply.patches[*]` + `gc.*` shape documented in earlier drafts of this file.
- ⏳ `get` — still emits per-patch action arrays.
- ⏳ `rollback` — still emits per-package result records.
- ⏳ `setup` — still emits `{ status, updated, alreadyConfigured, errors, files }`.

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

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Error (missing/invalid manifest, fetch failed, apply failed, selection cancelled in non-JSON mode, etc.) |

`list` returns **`0`** for an empty manifest and **`1`** for a missing manifest — these are distinct and load-bearing.

## Semver policy

Versioning lives in **`Cargo.toml`** at the workspace root (`version = "..."`) and is propagated to npm, pypi, and cargo wrappers by **`scripts/version-sync.sh <new-version>`**.

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
- `pypi/socket-patch/pyproject.toml`

## How the contract is enforced

Every item in this document is locked in by at least one of:

- **clap parser snapshots** in `crates/socket-patch-cli/tests/cli_parse_*.rs` — assert flag names, short forms, defaults, aliases, and CSV delimiters by calling `socket_patch_cli::Cli::try_parse_from(...)`.
- **Helper unit tests** in `crates/socket-patch-cli/src/**` (`#[cfg(test)] mod tests` blocks) — cover `looks_like_uuid`, `parse_with_uuid_fallback`, `detect_identifier_type`, `select_patches`, `find_patches_to_rollback`, `partition_purls`, `verify_status_str`, `format_severity`, `color`, and the JSON serializers.
- **Async `run()` integration tests** in `tests/cli_parse_list.rs`, `tests/cli_parse_remove.rs`, `tests/cli_parse_setup.rs` — exercise the no-network error paths and assert JSON shape via `serde_json::from_str::<Value>` + per-key assertions.

If you add a new flag/subcommand/JSON key, add a test here that locks the new surface in the same PR.
