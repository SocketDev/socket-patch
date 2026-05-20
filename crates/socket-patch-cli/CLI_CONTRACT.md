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
| `--no-prune` | — | `false` | bool |

`--apply` opts JSON callers into the full discover → select → apply pipeline. Without it, `scan --json` stays read-only (discovery + `updates` array + `gc` preview only). No effect outside `--json` mode — the non-JSON path always prompts the user interactively. Designed for unattended workflows (cron jobs, bots that open PRs).

`--no-prune` disables garbage collection. By default (since v3.0) `scan` removes manifest entries for packages no longer present in the crawl and deletes orphan blob, diff, and package-archive files from `.socket/`. Pass `--no-prune` to leave the manifest and `.socket/` directory untouched.

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

### `repair` *(deprecated since v3.0)*

`scan` now performs garbage collection by default (manifest pruning + orphan file cleanup); prefer `scan` or `scan --no-prune`. `repair` and its `gc` alias remain available for direct invocation but no longer appear in `socket-patch --help`. The subcommand itself is hidden via `clap`'s `hide = true`, and `gc` is demoted from `visible_alias` to `alias`. **Removing `repair` entirely or unhiding it requires a MAJOR bump.**

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

When `--json` is set, commands print a single JSON object to stdout. The schemas below are stable.

### Missing-manifest error (`apply`/`list`/`remove`/`repair`/`rollback`)

```json
{
  "status": "error",
  "error": "Manifest not found",
  "path": "<absolute path that was looked up>"
}
```

### Invalid-manifest error

```json
{ "status": "error", "error": "Invalid manifest" }
```

### Generic error

```json
{ "status": "error", "error": "<message>" }
```

### `list` success — empty manifest

```json
{ "status": "success", "patches": [] }
```

### `list` success — populated

```json
{
  "status": "success",
  "patches": [
    {
      "purl": "pkg:npm/foo@1.2.3",
      "uuid": "…",
      "exportedAt": "…",
      "tier": "free|paid",
      "license": "…",
      "description": "…",
      "files": ["…"],
      "vulnerabilities": [
        { "id": "…", "cves": ["…"], "summary": "…", "severity": "…", "description": "…" }
      ]
    }
  ]
}
```

### `setup` — no package.json files found

```json
{
  "status": "no_files",
  "updated": 0,
  "alreadyConfigured": 0,
  "errors": 0,
  "files": []
}
```

### `get` — multiple-patch selection required (JSON mode)

```json
{
  "status": "selection_required",
  "error": "Multiple patches available for <purl>. Specify --id <UUID> to select one.",
  "purl": "<purl>",
  "options": [
    { "uuid": "…", "tier": "…", "published_at": "…", "description": "…", "vulnerabilities": [ … ] }
  ]
}
```

### `scan` — discovery (read-only, default `--json` mode)

```json
{
  "status": "success",
  "scannedPackages": 42,
  "packagesWithPatches": 3,
  "totalPatches": 5,
  "freePatches": 4,
  "paidPatches": 1,
  "canAccessPaidPatches": false,
  "packages": [
    {
      "purl": "pkg:npm/minimist@1.2.2",
      "patches": [
        { "uuid": "…", "purl": "pkg:npm/minimist@1.2.2", "tier": "free", "cveIds": ["CVE-…"], "ghsaIds": [], "severity": "high", "title": "…" }
      ]
    }
  ],
  "updates": [
    { "purl": "pkg:npm/foo@1.0", "oldUuid": "<previous>", "newUuid": "<newest>" }
  ],
  "gc": {
    "prunableManifestEntries": ["pkg:npm/uninstalled@1.0"],
    "orphanBlobs": 3,
    "orphanDiffArchives": 1,
    "orphanPackageArchives": 0,
    "bytesReclaimable": 8421
  }
}
```

The `updates` array lists PURLs where the newest available patch UUID differs from the one currently recorded in `.socket/manifest.json`. Bots use this to drive "what would change" summaries without mutating anything.

The `gc` sub-object in read-only mode is a *preview*: it reports what `scan --apply` *would* prune and clean up, without touching disk. When `scan` runs with no crawl results (e.g., empty project, `node_modules` missing), GC is intentionally skipped and `gc` is emitted as `{ "skipped": true }` to prevent destroying a manifest the user may still want.

### `scan` — `--apply` mode

When invoked as `scan --json --apply`, the discovery object above is augmented with a top-level `apply` sub-object reporting per-patch outcomes from the download + manifest write, and the `gc` sub-object switches from preview to actual results:

```json
{
  "status": "success",                  // or "partial_failure"
  "scannedPackages": 42,
  // … all discovery fields above …
  "updates": [ … ],
  "apply": {
    "found": 3,
    "downloaded": 2,
    "skipped": 1,
    "failed": 0,
    "applied": 2,
    "updated": 1,
    "patches": [
      { "purl": "pkg:npm/foo@1.0", "uuid": "<new>", "action": "added" },
      { "purl": "pkg:npm/bar@2.0", "uuid": "<new>", "action": "updated", "oldUuid": "<previous>" },
      { "purl": "pkg:npm/baz@3.0", "uuid": "<existing>", "action": "skipped" },
      { "purl": "pkg:npm/qux@4.0", "uuid": "<attempted>", "action": "failed", "error": "…" }
    ]
  },
  "gc": {
    "prunedManifestEntries": ["pkg:npm/uninstalled@1.0"],
    "removedBlobs": 3,
    "removedDiffArchives": 1,
    "removedPackageArchives": 0,
    "bytesFreed": 8421
  }
}
```

With `--no-prune`, the `gc` sub-object is emitted as `{ "skipped": true }` in both read-only and `--apply` modes. GC field names differ between preview (`prunable*`/`orphan*`/`bytesReclaimable`) and apply (`pruned*`/`removed*`/`bytesFreed`) modes — bots should check `gc.prunedManifestEntries` vs `gc.prunableManifestEntries` accordingly.

Per-patch `action` vocabulary is stable:

| `action` | Meaning |
|---|---|
| `"added"` | PURL was not in the manifest before. |
| `"updated"` | PURL was in the manifest with a different UUID. `oldUuid` is included. |
| `"skipped"` | PURL was in the manifest with the same UUID. No work was done. |
| `"failed"` | The patch could not be downloaded or saved. `error` is included. |

Exit code follows the apply outcome: `0` if every selected patch was added, updated, or skipped; `1` if any `failed` record is present (and `status` becomes `"partial_failure"`).

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
| Change `scan`'s default behavior (e.g. pruning, GC, apply) | **MAJOR** — done once in v3.0; future flips also MAJOR. |
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
