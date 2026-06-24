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
| `setup` | — | Wire automatic-patching install hooks (npm/pypi/gem) |
| `repair` | `gc` | Download missing blobs, rebuild missing/corrupt vendored artifacts, clean up unused ones |
| `vendor` | — | Eject patched dependencies into committable `.socket/vendor/` and rewire lockfiles |
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
| `--vendor-source` | — | `SOCKET_VENDOR_SOURCE` | **`auto`** | enum: `auto` \| `service` \| `build` | How `vendor` acquires the installable artifact (see "Prebuilt vendor artifacts") |
| `--vendor-url` | — | `SOCKET_VENDOR_URL` | (active API/proxy base) | string | Base host for the vendoring-service package-reference request |
| `--patch-server-url` | — | `SOCKET_PATCH_SERVER_URL` | (server-returned) | string | Override the host of the prebuilt-archive download URL (local-dev / testing) |
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
| `vendor` | `--force` / `-f` | `SOCKET_FORCE` | Tolerate missing patch-target files in the stage + bypass the variant probe. A beforeHash mismatch no longer needs it: vendor staging auto-overwrites with the verified patched content (`vendor_content_mismatch_overwritten` warning) |
| (global) | `--strict` | `SOCKET_STRICT` | Treat a beforeHash mismatch as a hard error in the in-place apply paths (apply/get/scan --apply/hook/go redirect). DEFAULT (v3.4): a mismatched file is overwritten with the FULL verified patched content (the diff strategy self-disables on a wrong base; archive/blob writes are hash-gated to exactly afterHash; the missing blob is downloaded on demand) and surfaced as a `content_mismatch_overwritten` stderr warning + Skipped event. `--force` overrides `--strict` and additionally skips missing files. Vendor staging is unaffected (it always auto-overwrites into its private stage). |
| `vendor` | `--revert` | `SOCKET_VENDOR_REVERT` | Undo vendoring: restore recorded original lockfile fragments + remove `.socket/vendor/` artifacts. Works without a manifest |
| `apply`, `scan`, `vendor` | `--vex` | `SOCKET_VEX` | Generate an OpenVEX 0.2.0 document at this path on a successful run; see "embedded VEX" below |
| `apply`, `scan`, `vendor` | `--vex-product`, `--vex-no-verify`, `--vex-doc-id`, `--vex-compact` | `SOCKET_VEX_PRODUCT`, `SOCKET_VEX_NO_VERIFY`, `SOCKET_VEX_DOC_ID`, `SOCKET_VEX_COMPACT` | Passthrough to the embedded VEX builder; mirror the standalone `vex` knobs. Inert unless `--vex` is set |
| `scan` | `--apply` / `--prune` / `--sync` | — | Mode selectors (sync = apply + prune) |
| `scan` | `--vendor` / `--detached` | — | Vendor every patched dependency instead of applying in place (`--vendor`; conflicts with `--apply`/`--sync`, combines with `--prune`); `--detached` additionally skips all manifest writes — the vendor ledger embeds the patch records (requires `--vendor`) |
| `scan` | `--batch-size` | `SOCKET_BATCH_SIZE` | API batch chunk size (default `100`) |
| `get` | positional `identifier`; `--id` / `--cve` / `--ghsa` / `--package` (`-p`); `--save-only` (alias `--no-apply`); `--one-off` | `SOCKET_SAVE_ONLY`, `SOCKET_ONE_OFF` | Patch lookup + save-vs-apply mode |
| `remove` | positional `identifier`; `--skip-rollback` | `SOCKET_SKIP_ROLLBACK` | Manifest entry removal |
| `rollback` | optional positional `identifier`; `--one-off` | `SOCKET_ONE_OFF` | Rollback target |
| `vex` | `--output` / `-O`, `--product`, `--no-verify`, `--doc-id`, `--compact` | `SOCKET_VEX_OUTPUT`, `SOCKET_VEX_PRODUCT`, `SOCKET_VEX_NO_VERIFY`, `SOCKET_VEX_DOC_ID`, `SOCKET_VEX_COMPACT` | OpenVEX 0.2.0 document generation; see "vex output channels" below |
| `repair` | `--download-only` | `SOCKET_DOWNLOAD_ONLY` | Repair-specific cleanup mode (mutually exclusive with `--offline`) |
| `setup` | `--check`, `--remove` (mutually exclusive); `--exclude` (CSV member paths); honors global `--ecosystems` | `SOCKET_SETUP_EXCLUDE`, `SOCKET_ECOSYSTEMS` | Wire / verify / revert the automatic-patching install hooks. `--exclude` skips + persists workspace members (property 9). See [Setup command contract](#setup-command-contract) |

`scan --apply` opts JSON callers into the full discover → select → apply pipeline. Without it, `scan --json` stays read-only (discovery + `updates` array only). No effect outside `--json` mode — the non-JSON path always prompts the user interactively.

`scan --prune` opts into garbage collection. When set, `scan` removes manifest entries for packages no longer present in the crawl, then deletes orphan blob, diff, and package-archive files from `.socket/`. Off by default (v3.0) so a temporary uninstall doesn't silently destroy manifest state. The pass also reconciles vendored state (runs FIRST, under the apply lock — lock contention skips it without failing the scan): vendored entries whose patch is gone from the manifest are reverted, vendored entries whose dependency is no longer in the lockfile graph are reverted AND their manifest entries dropped (detached entries are exempt from both — they are manifest- and lockfile-invisible by design; a missing or undeterminable lockfile keeps the entry, fail-safe), and orphan `.socket/vendor/<eco>/<uuid>` dirs with no ledger entry are swept. The JSON `gc` sub-object gains `revertedVendoredEntries` + `removedVendorOrphanDirs` (wet) / `revertableVendoredEntries` + `vendorOrphanDirs` (preview).

`scan` queries the patch API in `--batch-size` chunks. Authenticated runs POST `/v0/orgs/{slug}/patches/batch`; token-less runs POST `{proxy}/patch/batch` on the public proxy and degrade to per-package `GET /patch/by-package/:purl` requests in two cases: the deployed proxy predates the batch endpoint (legacy proxies answer the POST with their `400 "Unsupported endpoint"` catch-all), or the all-or-nothing batch validation rejects the chunk (e.g. a crawled PURL type the server doesn't recognize, such as `pkg:jsr/…` — the per-package path tolerates those individually, preserving the pre-batch scan semantics). Rate limits and over-capacity 503s surface instead of silently degrading.

**Lockfile supplement (v3.4)**: `scan` discovery is no longer limited to installed trees. The project's lockfiles (`package-lock.json`/`npm-shrinkwrap.json`, `pnpm-lock.yaml` v9, `yarn.lock` classic + berry, `bun.lock`, `Cargo.lock`, `go.sum`, `composer.lock`, `Gemfile.lock`, `uv.lock`/`poetry.lock`/pinned `requirements.txt`) are inventoried and dependencies with NO installed copy join discovery — counts, the API lookup, the table (flagged ` [NOT INSTALLED]`, plus a stderr note), and the prune "scanned" set (a wiped node_modules no longer prunes lockfile-listed entries). JSON gains a top-level `lockfileOnlyPackages` count and an additive `notInstalled: true` on matching `packages[]` entries. `--apply` partitions lockfile-only patches out BEFORE download (calm `skipped`/`package_not_installed` records — never an error exit, never a manifest write); `--vendor` passes them through to the vendor engine's auto-fetch. Vendored-ledger entries likewise stay discoverable on a fresh clone (the committed artifact is the dependency). Global scans (`--global`) get no supplement.

**Vendor auto-fetch (v3.4)**: `vendor`/`scan --vendor` no longer fail on lockfile-resolved packages with no installed copy. Already-vendored purls stage from their committed artifact (sha256-verified against the vendor ledger; offline-safe). Otherwise the pristine artifact is fetched per the lockfile resolution and verified against the lock's recorded integrity FAIL-CLOSED before any write: npm SRI (or yarn classic's sha1 fragment), yarn berry's cache-zip checksum (rebuilt from the fetched tarball; cacheKey 10c0 only), Cargo.lock sha256 over the .crate, go.sum `h1:` dirhash over the module zip, composer `dist.shasum` (sha1), Gemfile.lock `CHECKSUMS` sha256, uv.lock wheel sha256 (pure `py3-none-any` wheels only). Entries the lock cannot verify are NEVER fetched (`vendor_fetch_unverifiable` warning + the calm `package_not_installed` skip). Registry bases honor `SOCKET_NPM_REGISTRY`, `SOCKET_CRATES_REGISTRY`, `SOCKET_GOPROXY` (else `GOPROXY`); npm/yarn/composer/gem/uv lock-recorded URLs are used verbatim. `--offline` refuses the fetch with the calm skip (the detail names the lockfile resolution). The fetch stages into a private tempdir — the project tree is never touched.

`scan --sync` is sugar for `--apply --prune` — the canonical single-flag bot invocation. `scan --json --sync --yes` discovers, applies, and reconciles state in one pass.

`scan --vendor` swaps the in-place apply for the vendor pipeline: discover → download (manifest written, as `--apply`) → vendor every patched dependency via the same engine as the `vendor` command (under the same lock). The whole manifest is vendored, so a package vendored at an older patch uuid is **re-vendored automatically** (its old uuid dir is removed — `vendor_stale_artifact_removed`); same-uuid re-runs are `already_vendored` skips. With `--prune`, GC runs **before** the vendor step so stale manifest entries don't fail vendoring with `package_not_installed`. JSON output gains a `download` sub-object (the download phase; no `applied` field — nothing is applied in place) and a `vendor` sub-object (a full vendor Envelope). The download phase writes only `.socket/manifest.json`; patch blobs are held in memory (see "Patch sources stay in memory" under the vendor contract). `--dry-run` previews per-patch `would_vendor` | `would_revendor` (+`oldUuid`) | `already_vendored` without network downloads or disk writes. Interactive mode prompts "Download and vendor N patch(es)?".

`scan --vendor --detached` performs the same vendoring **without ever writing `.socket/manifest.json`**: records are fetched into memory (`download.detached: true`), the artifacts are built + wired, and the ledger entry carries `detached: true` plus an embedded copy of the patch record (`record`) as the verification source. Detached patches are invisible to apply/rollback/repair (nothing is in the manifest), exempt from `vendor`'s manifest reconcile, and exit via `remove <purl>` (which reverts them) or `vendor --revert`. Idempotent re-runs reuse the embedded record and skip the patch-view fetch entirely.

`--dry-run` previews what `apply` / `rollback` / `scan --apply` / `repair` would do without mutating disk. In JSON mode, the envelope is populated with would-be actions and counts.

The hidden alias `--no-apply` on `get --save-only` is **part of the contract** — it does not appear in `--help` but is widely used in existing scripts.

### Embedded VEX (`apply --vex` / `scan --vex` / `vendor --vex`)

`--vex <path>` folds OpenVEX 0.2.0 generation into `apply`, `scan`, and `vendor`: on a successful run the command writes the document to `<path>` using the same engine as the standalone `vex` command. The `--vex-*` flags mirror `vex`'s `--product` / `--no-verify` / `--doc-id` / `--compact` knobs (namespaced to avoid colliding with the host command), and reuse the standalone env vars (`SOCKET_VEX_PRODUCT`, etc.). They are inert unless `--vex` is set.

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
   `afterHash`). *(Partially implemented; **hook-presence only today** — `check` does not yet verify
   on-disk patch consistency. RED-guarded.)*

5. **In-repo and committable.** `setup` writes only inside the working tree: `package.json`,
   `pyproject.toml`/`requirements.txt`, the `Gemfile` + generated `.socket/bundler-plugin/`. Every
   artifact is git-committable. It never writes outside
   `--cwd` — no `$HOME`, no global `site-packages` (the Python `.pth` wheel is installed later by the
   user's package manager, not by `setup`; the gem patch stamp is written under `Bundler.bundle_path`
   by the plugin at `bundle install` time, not by `setup`). *(Implemented.)*

6. **Clone-portable.** Because all setup state is committed files, a fresh checkout on another host —
   CI, a deploy, a teammate's machine — inherits the setup state unchanged; `setup --check` passes on
   the clone with no re-run required. *(Implemented; a consequence of properties 5 + 1.)*

7. **Reflected in VEX.** A patch contributes a `not_affected` statement to the repo's OpenVEX document
   only for ecosystems that are **actually set up** — or explicitly declared **manual** (below) — or
   **vendored** (a `socket-patch vendor`ed package needs no install hook by construction: the package
   manager itself installs the patched artifact, so its purls bypass this filter). Patches for an
   ecosystem that is neither set up, declared manual, nor vendored produce no VEX statement. *(Implemented —
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
   again. *(Implemented for the manifest edits — npm `package.json` and Python deps round-trip
   byte-for-byte.)*

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

`setup` installs an automatic-repatch hook for the three ecosystems with a usable post-install /
startup hook (npm, pypi, gem) — plus **composer** when the binary is built with the opt-in `composer`
feature. The remaining ecosystems are **apply-only**: `socket-patch apply` patches them on demand, but
there is no hook for `setup` to install, so `setup` is a `no_files` no-op for them. These are exactly
the ecosystems for which property 7's **manual** declaration is intended (so their hand-applied patches
still show up in VEX).

| Ecosystem | Hook `setup` installs | Repatch trigger | Notes |
|---|---|---|---|
| npm / yarn / pnpm / bun | `scripts.postinstall` + `scripts.dependencies` | `npm/pnpm install` (+ `install <pkg>`) | pnpm: root package only |
| pypi | `socket-patch[hook]` dependency → `.pth` startup hook | Python interpreter startup after installed-set change | manifest = `pyproject.toml` (uv/poetry/pdm/hatch) or `requirements.txt` (pip) |
| gem | managed `plugin "socket-patch"` block in the `Gemfile` → committed in-tree Bundler plugin under `.socket/bundler-plugin/` | every `bundle install` (cached + fresh: load-time digest gate + `after-install-all` hook) | Bundler loads only committed git plugins, so the generated dir must be committed; CLI must be on `PATH`. Phase 1 references the in-tree plugin via `git:`; Phase 2 (follow-up) switches to a published `socket-patch-bundler` gem |
| composer *(opt-in `composer` feature)* | `socket-patch apply` appended to `composer.json`'s `post-install-cmd` + `post-update-cmd` script events | every `composer install` / `composer update` | CLI must be on `PATH`; only compiled in with `--features composer` (apply support is likewise feature-gated). Without the feature, composer is a `no_files` no-op |
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
  rooted at `--cwd` (e.g. gem looks at `<cwd>/vendor/bundle/...`; pypi at `<cwd>/.venv`); it does **not**
  descend into sibling subprojects. A monorepo with several independent lockfiles in subdirectories
  (`backend/Gemfile.lock` + `frontend/Gemfile.lock`, multiple `.venv`, multiple `go.mod` /
  `composer.json`) is handled by invoking the tool **once per subproject** (`--cwd` each), as a
  per-directory install hook would.

**Intended (gap):** the cwd-only ecosystems *should* also auto-discover per-subproject lockfiles when
run from the repo root, matching the npm workspace model. The npm-vs-others asymmetry is a known
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
`package_json`, `pth`, `gemfile`, `gem_plugin`, `composer`.

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
| integrity mismatch | local build + `vendor_prebuilt_integrity_mismatch` | refuse (`vendor_prebuilt_required`) |
| still building (`pending_build` / serve 408) | local build + `vendor_prebuilt_pending` | refuse |
| not built / withdrawn / not found / no usable artifact | local build (quiet) | refuse |
| 401 / 403 grant / 5xx / network error | local build + `vendor_prebuilt_unavailable` | refuse |
| `--offline` | local build | refuse (`vendor_service_offline_conflict`) |

Coverage today: **npm** (all lock flavors), **pypi** (wheel — sdist falls back / refuses), **cargo**
(download + extract the `.crate`), **golang** (download + extract the module zip, verify the `h1:`
dirhash, wire the `replace`), and **composer** (download + extract the dist zip). The Tier-B
ecosystems (cargo/golang/composer) download the patched archive and extract it into the vendor
directory — the same source tree the local build commits — then run the existing path-dep wiring;
their build-equivalence is exercised by the toolchain-backed e2e suites (which skip when the package
manager is absent). **gem** is NOT covered (it builds locally): a path-sourced gem needs a stub
gemspec that the `.gem` archive doesn't carry in bundler's required form. For not-covered ecosystems
`auto`/`build` build locally as before, and `service` refuses with `vendor_service_unsupported_ecosystem`.
A successful service vend emits `vendor_prebuilt_downloaded`. Unrelated to `--download-mode` (which
selects the patch-CONTENT format for the local build).

**Patch sources stay in memory (v3.4)**: vendoring never writes `.socket/blobs/`, `.socket/diffs/`,
or temporary patch files. Pre-existing `.socket/` artifacts (from a prior `apply`/`get`/`repair`)
are read in place; already-vendored purls re-stage patch content from the committed artifact itself
(uuid-matched against the ledger, every harvested blob self-verified by its afterHash — so in-sync
re-runs and fresh clones of vendored projects need no network); anything still missing is fetched
into memory via the patch-view endpoint. A vendored project's `.socket/` holds only
`manifest.json` (omitted in detached mode) and `vendor/`.

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
record from the manifest — or the patch API, yielding a *detached* entry with the record embedded
— and a fresh ledger entry is persisted with the rebuilt artifact's fingerprint. When nothing is
installed and the ledger is gone, npm-family reconstruction has one more rung: the REWIRED
lockfile still records the integrity of the packed vendored tarball, so the pristine copy is
fetched (unverified, conventional registry URL, `SOCKET_NPM_REGISTRY` honored) and the
deterministically REBUILT artifact must reproduce that wired integrity — a tampered pristine
source changes the rebuilt bytes and fails closed (`vendor_artifact_rebuild_failed`, nothing
kept). Reconstructed entries carry no pre-vendor wiring originals, so a later `--revert` degrades
to the documented `vendor_lock_entry_drifted` guidance (re-resolve with the package manager). Because of this
phase, `repair` no longer errors with `manifest_not_found` when the project has a vendor ledger
or vendor-path lockfile references — it runs the vendored phase alone. Step 1's source download
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
(?:file:)?(?:\./)?\.socket[/\\]vendor[/\\](npm|cargo|golang|composer|gem|pypi)[/\\]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[/\\](.+)
```

Updating a patch changes the UUID → changes the path → changes the lockfile, so staleness is
diffable by construction. Each vendored unit also carries an informational
`socket-patch.vendor.json` marker (`{schemaVersion, purl, patchUuid, ecosystem, vulnerabilities,
vendoredAt}`) next to the artifact — belt-and-braces for tools that have the tree but not the
lockfile; never a trust input.

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
| npm / yarn berry (node-modules linker) | (same tarball) | root `package.json` `resolutions` + `yarn.lock` entry with `checksum: 10c0/<sha512>` of the berry cache-zip (reproduced from the tarball offline). **PnP is refused** (`.pnp.*` → different artifact pipeline) | `yarn install --immutable --check-cache`, cold cache. Refused if `__metadata.cacheKey ≠ 10c0` or a non-default `compressionLevel` |
| npm / pnpm (lockfileVersion 9) | (same tarball) | root `package.json` `pnpm.overrides` (versioned selector) **+** `pnpm-lock.yaml` surgery (overrides / importer version / packages `resolution.integrity` / snapshots) | `pnpm install --frozen-lockfile --offline`, cold store (integrity-verified; byte-stable on pnpm 9 & 10). lockfileVersion ≠ 9 refused |
| npm / bun (`bun.lock`) | (same tarball) | `bun.lock` only: the packages entry's registry 4-tuple → local 3-tuple with recomputed `sha512`. `bun.lockb` (binary) refused with a `--save-text-lockfile` pointer | `bun install --frozen-lockfile`, cold cache (integrity-enforced) |
| cargo | crate dir `<name>-<version>/` (no `.cargo-checksum.json`) | `.cargo/config.toml` `[patch.crates-io]` path entry **+** Cargo.lock surgery (the `[[package]]` entry's `source`/`checksum` removed) | `cargo build --locked --offline` on a fresh checkout. Requires cargo ≥ 1.56 (`[patch]` in config files). Note: path deps build **without** `--cap-lints allow` |
| golang | module dir `<module>@<version>/` | `go.mod` `replace <module> <ver> => ./.socket/vendor/golang/<uuid>/<module>@<ver>` | `go build` with `GOPROXY=off` + empty `GOMODCACHE` (directory replaces bypass go.sum entirely; survives `go mod tidy`) |
| composer | package dir `<vendor>/<name>@<version>/` | `composer.lock` only: entry's `dist` → `{type: "path", url, reference: null}`, `source` removed, `transport-options: {symlink: false}` added. `content-hash` unaffected; `composer.json` untouched | `composer install` (from the lock alone, real copy not symlink, works under `--network none`). `composer update <pkg>` reverts it |
| gem | gem dir `<name>-<version>/` + gemspec materialized from `specifications/` | **Gemfile + Gemfile.lock pair**: the `gem` line gains `path:` (or a managed block for transitive deps); the lock's spec block moves GEM→PATH and the DEPENDENCIES entry becomes `<name> (= <ver>)!`, in bundler's exact canonical form | `bundle install` (normal **and** `BUNDLE_FROZEN=true`), byte-stable lock. Lock-only edits are a silent unpatch — hence the mandatory pair |
| pypi / uv (uv.lock) | rebuilt wheel (canonical PEP 427 filename; RECORD regenerated) | `[tool.uv.sources] <name> = {path}` in pyproject + surgical uv.lock rewrite; transitive deps via `[tool.uv] override-dependencies` | `uv sync --locked` / `--frozen --offline` (hash-verified, byte-stable lock) |
| pypi / poetry (poetry.lock 2.0/2.1) | (rebuilt wheel) | lock-only: the target `[[package]]` gets `[package.source] type="file"` + `files = [{file, hash: sha256-of-our-wheel}]`. pyproject + `metadata.content-hash` untouched | `poetry check --lock && poetry sync`, cold cache (hash fail-closed; byte-stable lock) |
| pypi / pdm (pdm.lock) | (rebuilt wheel) | lock-only: the `[[package]]` gains the local-file `path` + `files[]` hash. pyproject + `content_hash` untouched. Non-fixture `[metadata] strategy` / hash-less locks refused | `pdm sync` (+ `pdm install --check`), cold cache |
| pypi / pipenv (Pipfile.lock) | (rebuilt wheel) | lock-only: the `default`/`develop` entry → `{file, hashes:[sha256-of-our-wheel]}`. Pipfile + `_meta.hash` untouched. Emits `vendor_integrity_unverified` — pipenv does not hash-check file entries; the committed wheel bytes are the protection | `pipenv install --deploy` (+ `pipenv verify`), cold cache |
| pypi / requirements.txt (pip / `uv pip`) | (rebuilt wheel) | pin line → `./<wheel> --hash=sha256:<hex>` (markers carried over; transitive deps appended) | `pip install -r` / `uv pip install -r` **run from the project root** (both resolve bare paths against the CWD) |

Ecosystems with no vendor backend that this build still *recognizes* (maven/nuget/jsr when their
features are compiled in) refuse per-purl with `vendor_unsupported_ecosystem`. yarn-berry **PnP**
(`.pnp.*`) and bun's binary `bun.lockb` are refused with stable codes pointing at the native
alternative / a text-lockfile migration; a lock-less tool marker (a `[tool.uv]`/`[tool.poetry]`/
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
| npm / bun | the packages-entry trailing `sha512-…` | recomputed from the tarball; tamper fails the frozen install |
| gem | `CHECKSUMS` section (bundler ≥ 2.6 opt-in) | the vendored gem's entry rewritten to bundler's own path-gem form (bare `name (ver)`, sha256 token stripped) so re-locks stay byte-stable; original line in the ledger |
| pypi / uv | `wheels[].hash`, `sdist.hash`, requires-dist specifiers | single `{filename, hash: sha256-of-our-wheel}`; sdist dropped; dropped specifiers ledgered for revert |
| pypi / poetry | `files = [{file, hash}]` | replaced with a single `{file, hash: sha256-of-our-wheel}` (poetry verifies the artifact against one listed hash; stale registry hashes removed) |
| pypi / pdm | `[[package]].files[]` hashes | replaced with our wheel's sha256; hash-less locks refused (`pypi_pdm_lock_no_hashes`) |
| pypi / pipenv | per-entry `hashes[]` | replaced with `["sha256:<ours>"]` — but pipenv does **not** enforce hashes on file entries (`vendor_integrity_unverified` warning); the committed wheel bytes are the actual protection |
| pypi / requirements | `--hash=sha256:` | fresh hash of the rebuilt wheel always emitted (turns on pip's hash-checking for the line) |

### Ownership, state, and reversal

* `.socket/vendor/state.json` (committed) is the revert ledger: every wiring edit records the
  **verbatim original** lockfile fragment it replaced (registry URLs, integrity strings, Cargo.lock
  `source`/`checksum`, requirement lines, uv specifiers). Those are not recoverable offline, so
  `--revert` never guesses at unrecorded fragments: a missing ledger is an empty ledger (clean
  no-op plus the orphan-dir sweep), and entries whose recorded fragments no longer match are left
  alone with warnings. Entries written by `scan --vendor --detached` additionally carry
  `detached: true` and `record` (an embedded copy of the patch record — same committed-file trust
  class as the manifest; artifact verification still re-hashes against its afterHashes and the
  uuid-in-path cross-checks).
* **Re-vendor carries originals forward**: re-vendoring under a newer patch uuid rewrites the
  previous run's own wiring (`original: None` from the backend — it must never record a dangling
  `.socket/vendor/` pointer as pre-vendor state); the engine merges the TRUE pre-vendor originals
  from the replaced ledger entry by wiring identity, so `--revert` after any number of re-vendors
  still restores the registry fragments byte-for-byte. The old uuid's now-orphaned artifact dir is
  removed (`vendor_stale_artifact_removed`) unless another entry still references it.
* `vendor --revert` restores the originals (fragments that no longer match — a user re-resolved —
  are left alone with a `vendor_lock_entry_drifted` warning), removes the artifacts, prunes the
  ledger, and sweeps orphan uuid dirs. It works without a manifest.
* Re-running `vendor` is idempotent (byte-stable lockfiles, deterministic artifacts →
  `already_vendored` skips). Patches dropped from the manifest are auto-reverted at the start of
  the next `vendor` run (`vendor_reconciled` events).
* **remove reverts vendoring**: `remove <purl|uuid>` on a vendored patch restores the recorded
  lockfile fragments, deletes the artifact, and drops the ledger entry (envelope events
  `removed`/`vendor_reverted`, which do NOT bump `summary.removed` — that count stays "manifest
  entries deleted") before deleting the manifest entry; a revert failure (`vendor_revert_failed`)
  aborts with the manifest intact. `--skip-rollback` ("don't touch my tree") skips the revert too
  (`skipped`/`vendor_state_retained`) — the wiring then stays until the next `vendor` run
  reconciles the dropped entry. Detached entries are removable by purl/uuid through the same
  command even though they have no manifest record (`--skip-rollback` is refused there: reverting
  IS the removal).
* **rollback excludes vendored purls**: their patch lives in the committed artifact, not the
  installed tree, so in-place restore is meaningless. The benign skip is surfaced in rollback's
  JSON as the additive `vendored: [purls]` array (exit 0; an identifier matching only vendored
  purls is a success, not `not_found`).
* **apply yields to vendor — every ecosystem**: a purl recorded in the ledger is skipped by
  `apply` with reason `vendored`, even when the installed tree is absent entirely (never
  `package_not_installed`; a vendored variant also accounts for its qualified release-variant
  siblings). Golang especially — apply never repoints a vendor-owned `replace` back at
  `.socket/go-patches/` — and `apply --check` excludes vendored modules from its drift audit.
* **scan skips vendored purls before download** (plain `--apply`/`--sync`): the manifest is never
  moved past the vendored uuid (that would break VEX verification with `vendor_uuid_mismatch`
  until a vendor run). The skip rides `apply.patches[]` as `skipped`/`vendored`; a newer available
  patch still surfaces in `updates[]` — the signal to run `scan --vendor`. `scan --prune` exempts
  vendored purls from the crawl-based manifest prune (an absent installed copy is their NORMAL
  state) but reconciles vendored state via the lockfile instead — see the `--prune` section. An
  explicit `get` is allowed to move the manifest past the vendored uuid and warns
  (`warnings[]` + stderr) that a `vendor` run must refresh the artifact.
* **Old-binary skew caveat**: a pre-detached `socket-patch` binary running `vendor` against a
  checkout with detached entries cannot see the `detached` flag and will reconcile-revert them.
  The ledger schema itself stays parseable both ways (additive optional fields).

### Caveats (documented behavior, not bugs)

* npm: a **warm local npm cache** can satisfy `npm ci` by integrity even when the vendored tarball
  is deleted or corrupted on disk — the lockfile integrity, not the file, is the source of truth.
  Fresh checkouts (the committable guarantee) fail closed. Never reuse a stale registry integrity:
  recomputation is mandatory and enforced by the implementation.
* npm redacts uuid-like path segments as `***` in its own error output (its secret heuristic);
  the path on disk and in the lockfile is unaffected.
* cargo: invoking cargo from **outside** the project root skips `.cargo/config.toml` discovery and
  an unlocked build will silently re-lock to the registry crate. CI should build with `--locked`.
* pip/`uv pip`: bare relative requirement paths resolve against the invoking process's CWD; run
  installs from the project root.
* `vendor` exits like `apply`: 0 on success (benign skips included), 1 on any refusal/failure
  (`partialFailure`), 2 on usage errors. `--dry-run` verifies and writes nothing.

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
| `SOCKET_VENDOR_SOURCE` | `--vendor-source` | `auto` | One of `auto` / `service` / `build`. |
| `SOCKET_VENDOR_URL` | `--vendor-url` | (active API/proxy base) | Vendoring-service package-reference host. |
| `SOCKET_PATCH_SERVER_URL` | `--patch-server-url` | (server-returned) | Rewrites the prebuilt-archive download host. |
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
| `rebuilt`    | `repair`                              | A missing/corrupt vendored artifact was rebuilt in place (or its lost ledger entry restored — `details.ledgerRestored`). `summary.rebuilt` counts these (the field is omitted while zero). |

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
| `vendored`                | `skipped`        | apply (every ecosystem) + scan `--apply`: the package is managed by `socket-patch vendor`; the command yields ownership (scan also skips the download). Rollback surfaces the same skip via its `vendored: []` array. |
| `vendor_reverted`         | `removed`        | remove: vendoring reverted (lock fragments restored, artifact + ledger entry gone) as part of removing the patch. |
| `vendor_revert_failed`    | top-level error  | remove: the vendor revert failed; the manifest was NOT modified. |
| `vendor_state_retained`   | `skipped`        | remove `--skip-rollback`: vendor wiring + artifact deliberately left in place (the next `vendor` run reconciles the dropped entry). Also the top-level error code when `--skip-rollback` targets a detached-only patch. |
| `vendor_stale_artifact_removed` | `removed`  | vendor / scan `--vendor`: re-vendor under a newer patch uuid removed the previous uuid's orphaned artifact dir. |
| `vendor_unsupported_ecosystem` | `skipped`   | vendor: no vendor backend for this purl's ecosystem (maven/nuget/jsr, or compiled out). |
| `already_vendored`        | `skipped`        | vendor: artifact + wiring already in sync for this patch uuid. |
| `unsafe_coordinates`      | `failed`         | vendor: purl/uuid would escape `.socket/vendor/` (tampered manifest/state); refused before any write. |
| `revert_failed`           | `failed`         | vendor --revert: a recorded entry could not be reverted. |
| `vendor_multiple_lockfiles` / `pypi_multiple_lockfiles` | `skipped` (warning) | vendor: a sibling lockfile of another package manager will still install UNPATCHED bytes; names the wired winner + the ignored locks. |
| `vendor_yarn_berry_unsupported` / `vendor_bun_lockb_unsupported` | `failed` | vendor (npm): yarn-berry PnP / bun binary lockfile — pointer to `yarn patch` / `bun install --save-text-lockfile`. |
| `vendor_yarn_berry_cache_unsupported` | `failed` | vendor (yarn berry): lock `cacheKey ≠ 10c0` or non-default `.yarnrc.yml` `compressionLevel` — the cache-zip checksum is not reproducible. |
| `vendor_override_conflict` | `failed`        | vendor (pnpm/yarn-berry): a user-authored override/resolution for the package already exists. |
| `vendor_integrity_unverified` | `skipped` (warning) | vendor (pipenv): the lockfile format does not hash-check file entries; the committed wheel bytes are the protection. |
| `vendor_content_mismatch_overwritten` | `skipped` (warning) | vendor: a staged file matched NEITHER beforeHash nor afterHash (patch built against different bytes, or local edits); the stage was overwritten with the verified patched content and the vendor succeeded. |
| `vendor_fetched_missing` | `skipped` (warning) | vendor: the package was not installed; its pristine artifact was fetched per the lockfile resolution (or staged from the committed vendor artifact), integrity-verified, and vendored — the project tree was not touched. |
| `vendor_fetch_failed` | `failed` | vendor: the lockfile-resolved fetch was attempted and failed (HTTP error, size cap, integrity mismatch, or a PRESENT-but-corrupt committed artifact — pointed at `socket-patch repair`). A MISSING committed artifact no longer lands here: it falls through to the ledger-recovered registry fetch. Suppresses the duplicate `package_not_installed` skip. |
| `vendor_fetch_unverifiable` | `skipped` (warning) | vendor: the lockfile records no usable integrity for the missing package; nothing was fetched (fail-closed) and the `package_not_installed` skip follows. |
| `vendor_artifact_missing` | `skipped` (warning) / `failed` | vendor: the committed artifact is gone — the registry resolution is recovered from the ledger and the artifact rebuilt (warning); repair `--offline` with no local source surfaces it as the per-entry failure instead. |
| `vendor_artifact_corrupt` | `failed` | repair `--offline`: the committed artifact fails verification (member afterHashes or the ledger's whole-file sha256) and no local source can rebuild it. Online repairs rebuild instead. |
| `vendor_artifact_rebuilt` | `skipped` (warning) | vendor / scan `--vendor`: a wired-but-missing/stale artifact was rebuilt in place; lockfiles and the ledger entry untouched. (Under `repair` the `rebuilt` event carries this signal.) |
| `vendor_artifact_rebuild_failed` | `failed` | repair: the rebuild ran but the result failed verification against the recorded fingerprint (e.g. an edited state.json sha); the unverifiable artifact was removed. |
| `vendor_artifact_unrepairable` | `failed` | repair: no verifiable pristine source exists (not installed + lockfile rewired + no recoverable ledger fragment), the wheel is platform-locked with no installed copy, or the ledger entry itself cannot be trusted. |
| `vendor_uuid_mismatch` | `skipped` | repair: the manifest's patch uuid moved past the vendored artifact — a re-vendor (`vendor` / `scan --vendor`) is pending; repair does not cross patch generations. |
| `content_mismatch_overwritten` | `skipped` (warning) | apply (default policy): a file matched NEITHER beforeHash nor afterHash and was overwritten with the full verified patched content. `--strict` turns this case into a `failed` event instead. |
| `vendor_lock_checksums_unsupported` / `vendor_stale_lock_checksum` | `failed` | vendor (gem): an ambiguous/platform CHECKSUMS entry, or a v1-wired lock whose stale token blocks the hot path (run `vendor --revert` + re-vendor). |
| `pypi_{poetry,pdm,pipenv}_no_lockfile` | `failed` | vendor (pypi): a lock-less tool marker with no `requirements.txt` fallback — run `<tool> lock`. |
| `vendor_*` / `pypi_*` / `gemfile_*` / `lock_*` / `locked_version_mismatch` / `user_authored_*` / `native_extensions_unsupported` / `platform_gem_unsupported` | `failed`/`skipped` | vendor: per-ecosystem refusal + drift vocabulary; see the Vendor command contract section. New tags are additive (MINOR). |

### Top-level `EnvelopeError` codes

| Code                  | Subcommands                      | Meaning |
|-----------------------|----------------------------------|---------|
| `manifest_not_found`  | list, remove, repair, rollback   | `.socket/manifest.json` doesn't exist. v3.5: `repair` proceeds anyway (vendored phase only) when a vendor ledger or vendor-path lockfile references exist. |
| `manifest_invalid`    | list, remove                     | Manifest exists but is unparseable. |
| `manifest_unreadable` | list, remove                     | I/O error reading manifest. |
| `apply_failed`        | apply                            | apply pipeline error before any patch ran. |
| `repair_failed`       | repair                           | repair pipeline error. |
| `remove_failed`       | remove                           | Could not write the modified manifest. |

### Per-subcommand action matrix

| Subcommand   | Emits |
|--------------|---|
| `apply`      | `Applied` · `Updated` · `Skipped` (already_patched / package_not_installed / vendored) · `Failed` · `Verified` (dry-run) |
| `vendor`     | `Applied` (= vendored; `command` routes) · `Skipped` (refusals, warnings, unsupported ecosystems) · `Failed` · `Removed` (reconcile + `--revert`) · `Verified` (dry-run) |
| `list`       | `Discovered` (with `details.vulnerabilities`, `details.tier`, `details.license`, `details.description`, `details.exportedAt`) |
| `repair`/`gc`| `Downloaded` (or `Verified` on dry-run) · `Rebuilt` (vendored artifacts; `Verified` previews on dry-run) · `Skipped` (vendor_uuid_mismatch) · `Removed` (or `Verified`) · `Failed` events |
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
