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
| `setup` | — | Wire automatic-patching install hooks (npm/pypi/cargo/gem/golang) |
| `repair` | `gc` | Download missing blobs + clean up unused ones |
| `vex` | — | Emit an OpenVEX 0.2.0 attestation derived from the local manifest |

**Bare-UUID fallback.** `socket-patch <UUID>` is rewritten to `socket-patch get <UUID>`. The UUID shape checked is the standard 8-4-4-4-12 hex pattern (case-insensitive). See [`src/lib.rs::looks_like_uuid`](src/lib.rs).

## Global arguments

In v3.0 every subcommand accepts the same set of "global" flags via a single shared `GlobalArgs` struct that's `#[command(flatten)]`-ed into each per-command struct (`crates/socket-patch-cli/src/args.rs`). Subcommands that don't actually consume a given flag accept it silently — e.g. `list --global` parses fine and is a no-op. Every flag also has an environment-variable binding; precedence is **CLI arg > env var > default**.

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
| `--offline` | — | `SOCKET_OFFLINE` | `false` | bool | **Strict airgap on every command** — never contact the network |
| `--global` | `-g` | `SOCKET_GLOBAL` | `false` | bool | Operate on globally-installed packages |
| `--global-prefix` | — | `SOCKET_GLOBAL_PREFIX` | (auto) | path | Override global packages root |
| `--json` | `-j` | `SOCKET_JSON` | `false` | bool | Machine-readable output |
| `--verbose` | `-v` | `SOCKET_VERBOSE` | `false` | bool | Extra detail |
| `--silent` | `-s` | `SOCKET_SILENT` | `false` | bool | Errors only |
| `--dry-run` | — | `SOCKET_DRY_RUN` | `false` | bool | Preview, no mutations |
| `--yes` | `-y` | `SOCKET_YES` | `false` | bool | Skip prompts |
| `--debug` | — | `SOCKET_DEBUG` | `false` | bool | Verbose debug logs to stderr |
| `--no-telemetry` | — | `SOCKET_TELEMETRY_DISABLED` | `false` | bool | Disable anonymous usage telemetry |

The `--offline` semantics unified in v3.0. Previously `apply` enforced strict airgap, `repair` skipped network ops, and `rollback` failed when blobs were missing. All three now mean the same thing: never contact the network, fail loudly when a required local source is missing. On `repair`, `--offline` and `--download-only` are mutually exclusive.

## Per-subcommand arguments

Beyond the globals above, each subcommand defines a small set of local arguments.

| Subcommand | Local arg | Env var | Purpose |
|---|---|---|---|
| `apply` | `--force` / `-f` | `SOCKET_FORCE` | Bypass beforeHash check |
| `apply`, `scan` | `--vex` | `SOCKET_VEX` | Generate an OpenVEX 0.2.0 document at this path on a successful run; see "embedded VEX" below |
| `apply`, `scan` | `--vex-product`, `--vex-no-verify`, `--vex-doc-id`, `--vex-compact` | `SOCKET_VEX_PRODUCT`, `SOCKET_VEX_NO_VERIFY`, `SOCKET_VEX_DOC_ID`, `SOCKET_VEX_COMPACT` | Passthrough to the embedded VEX builder; mirror the standalone `vex` knobs. Inert unless `--vex` is set |
| `scan` | `--apply` / `--prune` / `--sync` | — | Mode selectors (sync = apply + prune) |
| `scan` | `--batch-size` | `SOCKET_BATCH_SIZE` | API batch chunk size (default `100`) |
| `get` | positional `identifier`; `--id` / `--cve` / `--ghsa` / `--package` (`-p`); `--save-only` (alias `--no-apply`); `--one-off` | `SOCKET_SAVE_ONLY`, `SOCKET_ONE_OFF` | Patch lookup + save-vs-apply mode |
| `remove` | positional `identifier`; `--skip-rollback` | `SOCKET_SKIP_ROLLBACK` | Manifest entry removal |
| `rollback` | optional positional `identifier`; `--one-off` | `SOCKET_ONE_OFF` | Rollback target |
| `vex` | `--output` / `-O`, `--product`, `--no-verify`, `--doc-id`, `--compact` | `SOCKET_VEX_OUTPUT`, `SOCKET_VEX_PRODUCT`, `SOCKET_VEX_NO_VERIFY`, `SOCKET_VEX_DOC_ID`, `SOCKET_VEX_COMPACT` | OpenVEX 0.2.0 document generation; see "vex output channels" below |
| `repair` | `--download-only` | `SOCKET_DOWNLOAD_ONLY` | Repair-specific cleanup mode (mutually exclusive with `--offline`) |
| `setup` | `--check`, `--remove` (mutually exclusive); `--exclude` (CSV member paths); honors global `--ecosystems` | `SOCKET_SETUP_EXCLUDE`, `SOCKET_ECOSYSTEMS` | Wire / verify / revert the automatic-patching install hooks. `--exclude` skips + persists workspace members (property 9). See [Setup command contract](#setup-command-contract) |

`scan --apply` opts JSON callers into the full discover → select → apply pipeline. Without it, `scan --json` stays read-only (discovery + `updates` array only). No effect outside `--json` mode — the non-JSON path always prompts the user interactively.

`scan --prune` opts into garbage collection. When set, `scan` removes manifest entries for packages no longer present in the crawl, then deletes orphan blob, diff, and package-archive files from `.socket/`. Off by default (v3.0) so a temporary uninstall doesn't silently destroy manifest state.

`scan --sync` is sugar for `--apply --prune` — the canonical single-flag bot invocation. `scan --json --sync --yes` discovers, applies, and reconciles state in one pass.

`--dry-run` previews what `apply` / `rollback` / `scan --apply` / `repair` would do without mutating disk. In JSON mode, the envelope is populated with would-be actions and counts.

The hidden alias `--no-apply` on `get --save-only` is **part of the contract** — it does not appear in `--help` but is widely used in existing scripts.

### Embedded VEX (`apply --vex` / `scan --vex`)

`--vex <path>` folds OpenVEX 0.2.0 generation into `apply` and `scan`: on a successful run the command writes the document to `<path>` using the same engine as the standalone `vex` command. The `--vex-*` flags mirror `vex`'s `--product` / `--no-verify` / `--doc-id` / `--compact` knobs (namespaced to avoid colliding with the host command), and reuse the standalone env vars (`SOCKET_VEX_PRODUCT`, etc.). They are inert unless `--vex` is set.

Contract details:

* **Always written to the file** — never stdout — so the document never races the command's own `--json` output.
* **Fail-the-command**: if `--vex` was requested but generation fails (product PURL undetectable, empty/missing manifest, all patches unverified, unwritable path), the command exits non-zero **even when the apply/scan itself succeeded**. In `--json` mode the failure surfaces in the envelope's `error` (`apply`) / top-level `error` (`scan`), with a stable code (`product_undetected`, `no_applicable_patches`, `write_failed`, …).
* **Built from the post-run manifest**, verified against on-disk state (unless `--vex-no-verify`). Generated for real applies, `--dry-run`, and read-only `scan` alike.
* **JSON success surface**: `apply` adds a top-level `vex` object to its envelope; `scan` adds a top-level `vex` key to its result. Both carry `{ path, statements, format: "openvex-0.2.0" }`.
* `apply`'s no-manifest early exit (the "No .socket folder found" success no-op) does **not** trigger VEX generation — there is nothing to attest.

`repair` keeps its `gc` visible alias.

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
   and always processes every detected ecosystem (npm + python + cargo + golang + gem). RED-guarded.)*

3. **Consistency after install.** Once an ecosystem is set up, its locally-installed dependencies are
   re-patched to match the manifest after **any** of: a dependency added, updated, or removed; **or** a
   new patch added to the manifest. The re-patch is carried by the ecosystem's install/build hook (npm
   `postinstall`/`dependencies`, the Python `.pth` startup hook, the cargo guard build script, the gem
   Bundler plugin, the golang guard package) which runs `socket-patch apply` after the ecosystem's
   installer finishes, so patch state always reconverges with the manifest. *(Implemented for
   npm/pypi/cargo/gem/golang via the support matrix.)*

4. **`check` proves a correctly-patched state.** `setup --check` reports `configured` only when the
   in-scope ecosystems are *actually in a correctly patched state* — install hooks present **and**
   on-disk patch consistency verified (the `apply --check` invariant: every manifest file's hash matches
   `afterHash`). *(Partially implemented; **hook-presence only today** — `check` does not yet verify
   on-disk patch consistency. RED-guarded.)*

5. **In-repo and committable.** `setup` writes only inside the working tree: `package.json`,
   `pyproject.toml`/`requirements.txt`, member `Cargo.toml`s, `.cargo/config.toml`, the `Gemfile` +
   generated `.socket/bundler-plugin/`. Every artifact is git-committable. It never writes outside
   `--cwd` — no `$HOME`, no global `site-packages` (the Python `.pth` wheel is installed later by the
   user's package manager, not by `setup`; the gem patch stamp is written under `Bundler.bundle_path`
   by the plugin at `bundle install` time, not by `setup`). *(Implemented.)*

6. **Clone-portable.** Because all setup state is committed files, a fresh checkout on another host —
   CI, a deploy, a teammate's machine — inherits the setup state unchanged; `setup --check` passes on
   the clone with no re-run required. *(Implemented; a consequence of properties 5 + 1.)*

7. **Reflected in VEX.** A patch contributes a `not_affected` statement to the repo's OpenVEX document
   only for ecosystems that are **actually set up** — or explicitly declared **manual** (below). Patches
   for an ecosystem that is neither set up nor declared manual produce no VEX statement. *(Implemented —
   `generate_vex` filters `applied` to ecosystems returned by `commands/setup::configured_ecosystems`
   (on-disk hook presence) ∪ the manifest's `setup.manual`, in addition to the existing `--ecosystems`
   filter and on-disk verification. Applies in both verify and `--no-verify` modes.)*
   - **Manual declaration.** Users who run `socket-patch apply` by hand (e.g. in a CI step) declare an
     ecosystem as `manual` so VEX still attests its patches even though the auto-install hook is
     intentionally not wired. Home: the `setup.manual` array (a list of ecosystem `cli_name`s — `pypi`,
     `cargo`, …) in `.socket/manifest.json`. *(Implemented for the read/attest path; a `setup` flag to
     populate it is a future nicety — today it's hand-authored in the manifest.)*

8. **Graceful, exact remove.** `setup --remove` (optionally per-ecosystem via `--ecosystems`) restores
   the repo to its exact pre-setup state: manifests byte-for-byte, sibling scripts/dependencies
   preserved, keys that became empty dropped. Afterward `setup --check` reports needs-configuration
   again. *(Implemented for the manifest edits — npm `package.json`, Python deps, and member
   `Cargo.toml`s all round-trip byte-for-byte. **Known residue:** a `.cargo/config.toml` (and its
   `.cargo/` dir) that `setup` created is left behind empty rather than deleted on `--remove`;
   RED-guarded.)*

9. **Nested workspaces, with exclude.** Setup applies to every subproject below the repo root: npm /
   yarn / pnpm / bun workspace members and cargo workspace members are all discovered and configured
   (pnpm is root-package-only by design, because workspace-member `postinstall` scripts fail under
   pnpm's strict module isolation). Selected paths may be **excluded**, and the exclusion is **persisted
   in `.socket/manifest.json`** so `check`, `apply`, and any clone all honor it. *(Implemented —
   nested-workspace discovery plus the `--exclude` flag, persisted as the `setup.exclude` array in
   `.socket/manifest.json` and honored by discovery + `check` (a fresh clone inherits it without
   re-passing the flag). Excludes apply to npm + cargo workspace members; the repo root is never
   excludable.)*
   - **Nested workspaces (implemented).** A workspace member that is itself a workspace root — or, for
     cargo, members matched by a recursive `members = ["crates/**"]` glob — is recursed into and has its
     own members configured. `find_workspace_packages` re-reads each discovered member's own
     `workspaces` field (bounded depth), and `discover_cargo_project`'s `expand_member` expands the
     recursive `crates/**` glob (`glob_dir_recursive`, skipping `target/` + hidden dirs). Guarded by
     `setup_recurses_into_nested_npm_workspace` / `setup_expands_recursive_cargo_member_glob` in
     `tests/setup_monorepo_invariants.rs`.

### Per-ecosystem setup support

`setup` installs an automatic-repatch hook for the five ecosystems with a usable post-install / build /
startup hook (npm, pypi, cargo, gem, golang) — plus **composer** when the binary is built with the
opt-in `composer` feature. The remaining ecosystems are **apply-only**: `socket-patch apply` patches
them on demand, but there is no hook for `setup` to install, so `setup` is a `no_files` no-op for them.
These are exactly the ecosystems for which property 7's **manual** declaration is intended (so their
hand-applied patches still show up in VEX).

| Ecosystem | Hook `setup` installs | Repatch trigger | Notes |
|---|---|---|---|
| npm / yarn / pnpm / bun | `scripts.postinstall` + `scripts.dependencies` | `npm/pnpm install` (+ `install <pkg>`) | pnpm: root package only |
| pypi | `socket-patch[hook]` dependency → `.pth` startup hook | Python interpreter startup after installed-set change | manifest = `pyproject.toml` (uv/poetry/pdm/hatch) or `requirements.txt` (pip) |
| cargo | `socket-patch-guard` dependency + `[env] SOCKET_PATCH_ROOT` in `.cargo/config.toml` | every `cargo build` (fail-closed guard) | per-member dep + one workspace-root `[env]`; the guard crate is published to crates.io each release |
| gem | managed `plugin "socket-patch"` block in the `Gemfile` → committed in-tree Bundler plugin under `.socket/bundler-plugin/` | every `bundle install` (cached + fresh: load-time digest gate + `after-install-all` hook) | Bundler loads only committed git plugins, so the generated dir must be committed; CLI must be on `PATH`. Phase 1 references the in-tree plugin via `git:`; Phase 2 (follow-up) switches to a published `socket-patch-bundler` gem |
| golang | generated `internal/socketpatchguard/` guard package (`guard.go` + `guard_test.go`) + a blank import in each `main` package | every `go test ./...` (CI gate) **and** every `go run` / binary launch (`init()` guard) — fail-closed | self-contained: committed Go source, no published artifact; CLI must be on `PATH` |
| composer *(opt-in `composer` feature)* | `socket-patch apply` appended to `composer.json`'s `post-install-cmd` + `post-update-cmd` script events | every `composer install` / `composer update` | CLI must be on `PATH`; only compiled in with `--features composer` (apply support is likewise feature-gated). Without the feature, composer is a `no_files` no-op |
| nuget · maven · deno | **none** (apply-only) | — | `setup` reports `no_files`; candidates for the **manual** declaration |

### Monorepo / multi-project discovery model

How `setup` (and the underlying `scan`/`apply` crawlers) find subprojects differs by ecosystem, and
the model is **not uniform** today:

- **Workspace-aware (walk members):** npm / yarn / pnpm / bun (`workspaces` / `pnpm-workspace.yaml`)
  and cargo (`[workspace] members`). One repo-root invocation discovers and configures every member.
  *Single level only* — see property 9's nested-workspace gap.
- **cwd-only (single project):** gem, pypi, golang, composer. The crawler inspects only the project
  rooted at `--cwd` (e.g. gem looks at `<cwd>/vendor/bundle/...`; pypi at `<cwd>/.venv`); it does **not**
  descend into sibling subprojects. A monorepo with several independent lockfiles in subdirectories
  (`backend/Gemfile.lock` + `frontend/Gemfile.lock`, multiple `.venv`, multiple `go.mod` /
  `composer.json`) is handled by invoking the tool **once per subproject** (`--cwd` each), as a
  per-directory install hook would.

**Intended (gap):** the cwd-only ecosystems *should* also auto-discover per-subproject lockfiles when
run from the repo root, matching the npm/cargo workspace model. The npm-vs-others asymmetry is a known
defect, guarded by the `#[ignore]`d gap pin
`gem_crawl_from_repo_root_discovers_all_subproject_lockfiles` in
`crates/socket-patch-core/tests/crawler_monorepo_gaps.rs` (gem is the representative; python/go/composer
share the limitation).

**Deeply nested transitive dependencies are fully supported.** The npm crawler recurses `node_modules`
at unbounded depth, and `apply` is path-agnostic — it patches a package by PURL against the manifest
regardless of how deep in the dependency tree it was installed, so a deeply-nested transitive dependency
is patched identically to a direct one. Pinned by
`crawl_all_discovers_deeply_nested_transitive_deps` in
`crates/socket-patch-core/tests/crawler_npm_e2e.rs`.

### JSON output shapes (`setup`, `setup --check`, `setup --remove`)

`setup` predates the v3.0 unified envelope and emits its own three shapes. They are stable as of v3.0;
consumers may rely on these keys. All three share a `files[*]` entry shape; `kind` is one of
`package_json`, `pth`, `cargo`, `cargo_env`, `go_guard`, `go_import`, `gemfile`, `gem_plugin`,
`composer`.

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

## Environment variables

All v3.0 env vars use the `SOCKET_*` prefix. Three legacy `SOCKET_PATCH_*` names are still honored at runtime for compatibility: on first read of any of the three the binary emits a one-shot deprecation warning to stderr (the warning fires unconditionally — even under `--silent` / `--json` — because it's a transition signal users need to see). The legacy names will be removed in the next major release.

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
| `SOCKET_OFFLINE` | `--offline` | `false` | — |
| `SOCKET_GLOBAL` | `--global` / `-g` | `false` | — |
| `SOCKET_GLOBAL_PREFIX` | `--global-prefix` | (auto) | — |
| `SOCKET_JSON` | `--json` / `-j` | `false` | — |
| `SOCKET_VERBOSE` | `--verbose` / `-v` | `false` | — |
| `SOCKET_SILENT` | `--silent` / `-s` | `false` | — |
| `SOCKET_DRY_RUN` | `--dry-run` | `false` | — |
| `SOCKET_YES` | `--yes` / `-y` | `false` | — |
| `SOCKET_DEBUG` | `--debug` | `false` | **Renamed in v3.0** (was `SOCKET_PATCH_DEBUG`). |
| `SOCKET_TELEMETRY_DISABLED` | `--no-telemetry` | `false` | **Renamed in v3.0** (was `SOCKET_PATCH_TELEMETRY_DISABLED`). |
| `SOCKET_FORCE` | `apply --force` / `-f` | `false` | Local to `apply`. |
| `SOCKET_BATCH_SIZE` | `scan --batch-size` | `100` | Local to `scan`. |
| `SOCKET_SAVE_ONLY` | `get --save-only` | `false` | Local to `get`. |
| `SOCKET_ONE_OFF` | `get --one-off` / `rollback --one-off` | `false` | Local to `get`/`rollback`. |
| `SOCKET_SKIP_ROLLBACK` | `remove --skip-rollback` | `false` | Local to `remove`. |
| `SOCKET_DOWNLOAD_ONLY` | `repair --download-only` | `false` | Local to `repair`. |
| `SOCKET_SETUP_EXCLUDE` | `setup --exclude` | (none) | Local to `setup`; comma-separated workspace-member paths, persisted to `setup.exclude`. |
| `SOCKET_VEX` | `apply --vex` / `scan --vex` | (none) | Embedded OpenVEX output path. The `SOCKET_VEX_*` knobs (`_PRODUCT`, `_NO_VERIFY`, `_DOC_ID`, `_COMPACT`) are shared with the standalone `vex` command; on `apply`/`scan` they bind to `--vex-product` etc. |

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
- ⏳ `setup` — still emits its own `{ status, updated, alreadyConfigured, errors, files }` shape (and the `--check` / `--remove` variants), now documented in full under [Setup command contract](#setup-command-contract).

### `patches[]` entry shape for `get` and `scan --apply`

Per-patch records emitted in `patches[]` (and in `scan --apply`'s
`apply.patches[*]`) carry the same metadata regardless of which command
produced them — both flow through `download_and_apply_patches` in
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
  "exportedAt":  "2024-01-01T00:00:00Z",     // publishedAt from API
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
  "error":       "could not fetch details"
}
```

The metadata block (`description`, `license`, `tier`, `exportedAt`,
`severity`, `vulnerabilities[]`) is intentionally **omitted on
`skipped`** — those records mean "already in manifest, no work taken",
and the consumer already saw the metadata when the patch was first
added. It's also omitted on `failed`.

`vulnerabilities[]` is always sorted by `id` so consumer diffs and
test snapshots are stable. `severity` at the top level is the max
across the array using the ordering `critical > high > medium = moderate > low > (unknown)`.

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

`vex` exit codes are tri-state:

| Code | Meaning |
|---|---|
| `0` | A non-empty OpenVEX document was produced |
| `1` | No applicable patches (empty manifest, or every patch failed verification with `--verify`) |
| `2` | Hard error before document generation (manifest unreadable, `--json` without `--output`, product auto-detect failed, write error) |

### vex output channels

The VEX document is JSON-LD, which collides with the standard `--json` envelope on stdout. The shape is:

| `--output` | `--json` | VEX → | Envelope → |
|---|---|---|---|
| unset | unset | stdout | stderr (one-line summary) |
| set to `<path>` | unset | `<path>` | stdout (one-line summary) |
| set to `<path>` | set | `<path>` | stdout (full envelope, with one `verified` event per emitted subcomponent) |
| unset | set | (error: `json_requires_output`, exit `2`) | stdout (envelope-only) |

When verification is enabled (the default) and a patch is omitted, the failed PURLs are surfaced on stderr in plain mode or as `skipped` events on the envelope in JSON mode. Status becomes `partialFailure` when at least one patch was omitted but at least one was emitted.

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
- `pypi/socket-patch/pyproject.toml` and `pypi/socket-patch-hook/pyproject.toml`
- `gem/socket-patch-bundler/socket-patch-bundler.gemspec` (the Bundler plugin gem)
- `gem/socket-patch/socket-patch.gemspec` + its launcher `VERSION` (the RubyGems CLI launcher)
- the Composer CLI launcher's `SP_VERSION` (`composer/socket-patch/bin/socket-patch`)

The RubyGems + Composer CLI launchers (`socket-patch` gem, `socketsecurity/socket-patch`
on Packagist) are published by the separate **`.github/workflows/release-ecosystems.yml`**,
which runs after the main release publishes and only needs the GitHub release binaries to exist.

## How the contract is enforced

Every item in this document is locked in by at least one of:

- **clap parser snapshots** in `crates/socket-patch-cli/tests/cli_parse_*.rs` — assert flag names, short forms, defaults, aliases, and CSV delimiters by calling `socket_patch_cli::Cli::try_parse_from(...)`.
- **Helper unit tests** in `crates/socket-patch-cli/src/**` (`#[cfg(test)] mod tests` blocks) — cover `looks_like_uuid`, `parse_with_uuid_fallback`, `detect_identifier_type`, `select_patches`, `find_patches_to_rollback`, `partition_purls`, `verify_status_str`, `format_severity`, `color`, and the JSON serializers.
- **Async `run()` integration tests** in `tests/cli_parse_list.rs`, `tests/cli_parse_remove.rs`, `tests/cli_parse_setup.rs` — exercise the no-network error paths and assert JSON shape via `serde_json::from_str::<Value>` + per-key assertions.

If you add a new flag/subcommand/JSON key, add a test here that locks the new surface in the same PR.
