# socket-patch NuGet implementation map (branch v5/nuget-vendoring, read-only)

All paths are relative to `/home/user/socket-patch/crates/`. Where a line number carries a `~` it points to the right block but is not exact.

## 1. Backend interface a new vendored layout must implement

**There is no trait.** Backends are free functions with one shared signature. The CLI calls them through `match` arms.

**Vendor entry** (the same 9 arguments for every backend), `socket-patch-core/src/vendor/nuget_feed.rs:399`:
```rust
pub async fn vendor_nuget(purl: &str, installed_dir: &Path, project_root: &Path,
    record: &PatchRecord, sources: &PatchSources<'_>, vendored_at: &str,
    dry_run: bool, force: bool, service: Option<&VendorServiceConfig>) -> VendorOutcome
```

**Revert entry**, `nuget_feed.rs:762` and `:772`:
```rust
pub async fn revert_nuget(entry: &VendorEntry, project_root: &Path, dry_run: bool) -> RevertOutcome
pub async fn revert_nuget_opts(entry: &VendorEntry, project_root: &Path, opts: RevertOpts) -> RevertOutcome
```

**Service preflight**, `nuget_feed.rs:372`:
```rust
pub(crate) async fn service_preflight(purl, project_root, record) -> Option<PlannedDownload>
```
- It must run the same refusal checks as `vendor_nuget`, so the download plan never asks the service for a package the loop will refuse. Today it shares `nuget_prelude` (`:243`) for this.
- It is routed from `vendor/mod.rs:918` (the nuget arm is at `:932`).

**Dispatch points** in `socket-patch-cli/src/commands/vendor.rs`:
- `dispatch_vendor_one` (`:112`) uses the `vend_installed!` macro (`:168-190`). That macro asserts `PackageSource::Installed`, because NuGet and Maven have no registry-fetch rung. The nuget arm is at `:215`.
- `SERVICE_ECOSYSTEMS` includes nuget (`:135`).
- `dispatch_revert_one_opts` (`:237`), nuget arm at `:245`.
- `dispatch_in_use_one` (`:256`) returns `None` for nuget, so there is no in-use probe.

**Types**
- `vendor/mod.rs`:
  - `VendorWarning` `:142`
  - `VendorServiceConfig` `:268`
  - `VendorOutcome::{Refused{code,detail}, Done{result: ApplyResult, entry: Option<VendorEntry>, warnings}}` `:785`
  - `RevertOpts{dry_run, keep_artifact}` `:801`
  - `RevertOutcome{success, warnings, error, kept_artifact}` `:824`
  - `force_apply_staged` `:732`, which applies the patch into a private stage and is hash-gated.
- `vendor/state.rs`:
  - `VendorArtifact{path, sha256, size, platform_locked, file_inventory}` `:52`
  - `WiringAction{Rewritten, Added}` `:83`
  - `WiringRecord{file, kind, action, key, original, new}` `:97`
  - `VendorEntry` `:212`
  - `VendorState` `:324`
  - `VENDOR_STATE_REL = ".socket/vendor/state.json"` `:43`
  - `VENDOR_MARKER_FILE = "socket-patch.vendor.json"` `:764`
  - `VendorEntry::committed_artifact_intact` (a sha256 check of file artifacts), right after `:212`.

**Shared helpers to hook into**
- `vendor/common.rs`: `refused`, `done`, `already_patched_result`, `prepare_memory_repack`/`MemoryRepack`, `rebuild_zip`, `write_zip_entries`, `zip_bytes_match_after_hashes`, `any_live_file_references` (`:993`), `prune_empty_vendor_levels`.
- `vendor/path.rs`:
  - `vendor_uuid_dir_rel("nuget", uuid)`
  - leaf parser for `nuget` at `:280-286`, with `split_nuget_leaf` at `:207`
  - ecosystem list at `:44`
- `vendor/ledger_snapshots.rs:56-62`: `WHOLE_FILE_KINDS` includes `"nuget_config_source"`. Whole-file values of 1024 bytes or more (`SNAPSHOT_MIN_BYTES`) are stored as diff ops, and those ledgers are written as version 2.
- `vendor/verify.rs:93-102, 488-498, 711`: `.nupkg` is treated as a single committed zip file, and its members are checked against the afterHashes.
- `vendor/reuse.rs:1-12`: the reuse path is for npm/pypi only. NuGet decides "in sync" from the committed artifact itself.
- `vendor/service_fetch.rs:155-240`: `service_archive_copy` returns `ServiceCopy::{Used, HardFail, FallBack}` (the Tier-A path).
- `socket-patch-cli/src/commands/repair_vendor.rs:105-129`: `WIRING_FILES` **does not include `nuget.config`** (see §7).

## 2. Current on-disk layout, edits, state record and revert

**Artifact**
- Path: `.socket/vendor/nuget/<uuid>/<idLower>.<versionNorm>.nupkg` (`nupkg_leaf` `:172`, `normalize_nuget_version` `:125`). The normalizer mirrors the TS `normalizeNuGetVersion` and the two must stay in sync.
- Marker `socket-patch.vendor.json` is written beside it (`:664`).
- The uuid dir is the local folder feed itself (module doc `:8-18`).

**Source key:** `socket-patch-<uuid>` (prelude, around `:280`).

**nuget.config** (`build_config_edit` `:1161`)
- Config lookup is root-only. `existing_config_path` (`:1145`) probes `nuget.config`, then `NuGet.Config`. It does not probe `NuGet.config`, although `nuget_config.rs:228` `CONFIG_NAMES` lists all three.
- **No config:** writes a fresh file (`:1171-1195`) containing the nuget.org source plus ours, and a mapping of `nuget.org → *` plus `socket → <exact id>`. It is written to `project_root/nuget.config` (`:599`).
- **Existing config** (`:1196-1285`):
  - Anchors are found on a comment-blanked view (`blank_comments` `:1292`).
  - Our `<add>` is inserted before `</packageSources>`. A self-closing `<packageSources/>` is expanded (`:1390`), and if the section is missing it is created before `</configuration>`.
  - If `</packageSourceMapping>` exists, only our `<packageSource>` block is appended.
  - Otherwise a new mapping is created that fans `*` out to every pre-existing source key (`parse_config_source_keys` `:1330`). nuget.org is seeded if there are none.
  - It errors if there is no `</configuration>`.

**packages.lock.json** (`edit_lock` `:1545`)
- Only the root `project_root/packages.lock.json` is considered (`:93`).
- Every `dependencies.<tfm>.<id>` entry (case-insensitive) whose `resolved` normalizes to the version (`locked_at` `:208`) gets `contentHash` replaced with `base64(sha512(nupkg))` (`content_hash` `:1116`).
- This is a string replace of the quoted old hash, so formatting is preserved.
- Entries that disagree on the hash cause a failure. An entry with no match gives the `vendor_nuget_lock_entry_absent` warning (`~:633`). A missing lock gives `vendor_nuget_no_lockfile` (`:653`).

**Edit order:** artifact → config → lock. A failure in the lock step unwinds the config and deletes the uuid dir (`unwind_config` `:1641`, called around `:619` and `:646`).

**state.json entry** (`nuget_entry` `:713`)
- Fields: `ecosystem:"nuget"`, `basePurl`, `uuid`, `artifact{path, sha256 (plain hex of the nupkg), size}`. All the extras (`lock`, `flavor`, `uv`, …) are `None`.
- The CLI adds `detached`/`record`.
- Wiring records, in application order (`:678-705`):
  1. `nuget_config_source`: `file` = the config basename; `Added` if we created the file, otherwise `Rewritten`; `key` = the source key; `original` = the whole pre-vendor file text (or none); `new` = the whole post-edit file text. This is the authoritative revert record.
  2. `nuget_config_mapping`: `Added`, `key` = the id, `new` = the mapping fragment. Audit only.
  3. `nuget_lock_entry`: `Rewritten`, `key` = the id, `original` = the old contentHash, `new` = the new one.
- Example: `socket-patch-cli/tests/fixtures/legacy-ledgers/nuget/wired/.socket/vendor/state.json`.

**Hot path** (prelude, around `:318-345`; `vendor_nuget` `:437-535`)
- `config_wired` is a plain substring test: does the config text contain the source key?
- `in_sync` also requires the committed nupkg's members to match the afterHashes, and the lock to be pinned (or to have no matching entry).
- Wired and in sync: returns `AlreadyPatched` with no entry.
- Wired but stale: rebuilds only the artifact and re-pins the lock (with `original: None`; the CLI's `carry_forward_wiring` fills it in), and warns `vendor_artifact_rebuilt`. The config is never touched on this path.

**Revert** (`revert_nuget_opts` `:772`)
- The uuid is validated first.
- Records are walked in reverse:
  - Lock (`revert_lock_record` `:1606`): replaces our hash with the original. If ours is gone but the original is present, it counts as done. Otherwise it is drift.
  - Mapping record: no-op.
  - Config (`revert_config_record` `:1419`):
    - The file name must be a safe single segment.
    - If the live file is byte-identical to `new`: restore `original`, or delete the file if we created it.
    - Otherwise: excise only our verbatim `<add …/>` line and our `<packageSource key=…>` block (`excise_source_mapping` `:1507`).
    - If neither is present: drift (`Ok(false)`).
    - The catch-all mapping is left in place.
- **Drift-keep** (`:844-860`): if any record drifted and a live wiring file still contains the uuid dir path, the artifact is kept (`kept_artifact`) so the exclusive mapping is not left pointing at a missing dir.
- Otherwise `remove_tree_and_prune` runs (`:871`). `keep_artifact` supports `--preserve-state`.

## 3. Supported and refused project shapes

**Explicit refusals** (prelude `:250-310`)
- Not a NuGet purl, non-canonical uuid, or id/version outside `[A-Za-z0-9._+-]` → `unsafe_coordinates`.
- Unreadable config → `vendor_nuget_config_unreadable`.
- Unreadable lock → `vendor_nuget_lock_unreadable`.
- No cached `.nupkg` → `vendor_nupkg_not_found` (`:962`).
- A config without `</configuration>` → a failed result (not a refusal).

**Everything else is accepted without detection:**

| Shape | Handling today |
|---|---|
| **No lockfile** | Accepted with a warning. There is no content pin (`:653`; `docs/ecosystems.md:382-386`). |
| **Existing mapping** | Accepted. Our block is appended (`:1255-1260`). Nothing checks whether another source already maps the same exact id. NuGet then treats both sources as eligible, so the patched copy is not guaranteed. The vex doc lists this as a non-goal (`vex/discover/nuget.rs:59-65`). |
| **Multi-project / per-project locks** | Only the root `packages.lock.json` and root `nuget.config` are used (`:93`, `:1145`). Locks in sub-projects are never pinned. Parent-dir or user-level configs, `<clear/>`, and custom `NuGetLockFilePath` are not handled (`vex/discover/nuget.rs:59-65`). The crawler reads `obj/project.assets.json` one level deep (`crawlers/nuget_crawler.rs:483-498`), but only to find package folders. |
| **CPM (`Directory.Packages.props`)** | Not referenced anywhere. No refusal and no special handling. A typical CPM solution keeps its locks per project, so it falls into the "no lockfile" warning path. |
| **packages.config** | Recognized as a .NET marker (`nuget_crawler.rs:419-436`), and the legacy `packages/<Name>.<Version>/` dir is crawled. `vendor_nuget` accepts that dir as `installed_dir` (doc `:392-397`). No special handling and no test for restore under packages.config. |
| **Warm global cache** | Every real-restore test uses a cold `NUGET_PACKAGES` (`docker_e2e_vendor_nuget.rs:185-224`; `e2e_nuget_dotnet_build.rs` also uses a "cold `NUGET_PACKAGES`"). A same-id/version pristine copy already in `~/.nuget/packages` is untested. |

## 4. How the patched .nupkg is built (`materialise_patched_nupkg` `:892`)

1. **Service first.** `service_archive_copy(service, record, name, ".nupkg")` (`service_fetch.rs:169`).
   - It POSTs `/v0/orgs/{slug}/patches/package` (or the public proxy's `/patch/package`) and GETs the grant URL (`api/client.rs:1106-1113`).
   - The SRI is checked, and every member must hash to its afterHash, before the bytes are written verbatim.
   - An integrity mismatch is always a hard failure.
   - A miss under `auto` falls back to the local build. Under `--vendor-source=service` it is refused (`vendor_prebuilt_required`).
2. **Local rebuild** (`local_rebuild` `:949`).
   - `locate_cached_nupkg(installed_dir)` (`:1123`) takes the first `*.nupkg` in the crawler's package dir. That is `~/.nuget/packages/<idLower>/<ver>/` or `$NUGET_PACKAGES`, or the legacy `packages/<Name>.<Ver>/`. **The pristine bytes therefore come from the global packages folder** (or the legacy folder), never from a registry: NuGet has no fetch rung (`vendor.rs:168-170`).
   - The in-memory repack (`prepare_memory_repack`, which also stages `.nupkg.metadata` and `*.nupkg.sha512`), then `force_apply_staged`, which also runs the sidecar fixup.
   - Deterministic lexicographic re-zip that drops `.signature.p7s` (`rebuild_nupkg_bytes` `:1079`, `SIGNATURE_PART` `:108`).
   - The upstream id and version are kept, with the same filename leaf.

## 5. Hosted NuGet (`patch/redirect/mod.rs`)

**Entry point:** `rewrite_nuget` (`:5317`), registered at `:449`.
- It reads only a root `nuget.config` (lowercase) and `packages.lock.json` (`scan/hosted.rs:75-76`, `mod.rs:5330`, `:5346`). If there is no config it starts from `default_nuget_config()` (`:5127`).
- An unparseable lock skips the whole NuGet rewrite (`redirect_nuget_lock_unparseable`).
- Per dep it requires a `nuget-v3` override and a sha512 (`:5362-5376`).

**Config**
- `add_nuget_source` (`:5142`) adds `<add key="socket-patch-<uuid>" value="<indexUrl>"/>`. It seeds nuget.org when the new mapping would otherwise have no catch-all target.
- If there is no mapping, it creates socket-exact-id plus a `*` catch-all for each pre-existing source. If a mapping exists, it prepends only ours after `<packageSourceMapping>`.

**Lock**
- For every framework entry whose id matches (**id only, not version**; `:5431`), it sets `resolved` = `nugetVersionNorm` and `contentHash` = the SRI with `sha512-` stripped.

**URL form** (fixtures `socket-patch-core/tests/fixtures/redirect/nuget/packages-lock/{basic,empty-sources,empty-sources-selfclosing,no-preexisting-mapping}`):
- index: `https://patch.socket.dev/patch-registry/nuget/<grantToken>/<uuid>/index.json`
- artifact: `…/<uuid>/flat/<idLower>/<ver>/<idLower>.<ver>.nupkg`
- The data comes from `api_client.fetch_registry_references` (`scan/hosted.rs:1244`, `client.rs:748-776`, same POST `…/patches/package`). Integrity is taken from the reference's `tarball`-kind artifact (`hosted.rs:1281-1287`).

**Why hosted revert is unsupported**
- The config `FileEdit` records only `new: {source, pattern}` with `original: None` (`:5413-5421`). No pre-edit snapshot exists, so it cannot be inverted.
- `replay.rs:181` classifies `redirect_nuget_source` and `redirect_nuget_lock` as `Inverse::Unsupported`; the module doc `:20-23` says these groups refuse with `hosted_revert_unsupported`.
- `takeover.rs:79-83` `redirect_revert_supported` covers only cargo, npm and golang. So vendored takeover of a hosted NuGet purl is also blocked (`vendor.rs:1585`, `:2416`), and `remove.rs:1359` reports `hosted_revert_unsupported`.
- The v5 plan (`docs/design/v5-plan.md` WS1) replaces this with a re-resolve from nuget v3.
- Hosted in-memory mode can't take inventory from NuGet either (`hosted_memory/roots.rs:51` `UNSUPPORTED_MARKERS`).

## 6. Tests and how to run them

Run everything from `/home/user/socket-patch`.

| Test | Needs | Gate / command |
|---|---|---|
| Inline unit tests in `nuget_feed.rs` (from `:1662`, roughly 3.7k lines: config surgery, lock, revert, drift, hot path, service, tamper guards) | nothing | `cargo test -p socket-patch-core --lib nuget_feed` |
| `socket-patch-core/tests/covgap_vendor_nuget_feed.rs` (TMPDIR failure; `cfg(unix)`) | nothing | `cargo test -p socket-patch-core --test covgap_vendor_nuget_feed` |
| `crawler_nuget_e2e.rs`, `redirect_golden.rs` (shared TS goldens), redirect `mod.rs` tests `:7915+`, `replay.rs:3406` | nothing | `cargo test -p socket-patch-core` |
| `socket-patch-cli/tests/e2e_vex_lockfile/nuget.rs` (module in the `e2e_vex_lockfile` binary; hermetic, wiremock, no dotnet) | nothing | `cargo test -p socket-patch-cli --test e2e_vex_lockfile nuget` |
| `e2e_nuget.rs` (crawl only, wiremock proxy) | nothing | `#[ignore]` at `:182`, `:250`; run with `cargo test -p socket-patch-cli --test e2e_nuget -- --ignored` |
| `e2e_nuget_dotnet_build.rs` (hosted `:725` + vendored `:834`, real SDK, needs nuget.org) | host `dotnet` + network | `#[ignore]`; soft-skips without dotnet unless `SOCKET_PATCH_DOTNET_E2E_REQUIRED=1`; `SOCKET_PATCH_DOTNET_E2E_VERSION=8` picks the SDK; `cargo test -p socket-patch-cli --all-features --test e2e_nuget_dotnet_build -- --ignored` |
| `docker_e2e_nuget.rs` (apply chain, `:570`, `:607`) | Docker image `socket-patch-test-nuget:latest` | `#![cfg(feature="docker-e2e")]`; soft-skips if the image is missing (`:482`); `cargo test -p socket-patch-cli --features docker-e2e --test docker_e2e_nuget` |
| `docker_e2e_vendor_nuget.rs` (`:472`: 3-stage vendor → cold offline `--locked-mode` restore → RED/TAMPER(NU1403) → idempotence and revert) | Docker (SDK 8.0) | `--features docker-e2e --test docker_e2e_vendor_nuget` |
| `setup_matrix_nuget.rs` | host guard runs; `dotnet()` is `#[ignore]` (baseline gap) | `--features setup-e2e --test setup_matrix_nuget` |
| Other hermetic CLI tests (`in_process_get_hosted_ecosystems.rs:532`, `in_process_scan.rs:1374`, `in_process_rollback_all_ecosystems.rs:552`, `apply/e2e_safety_advisories.rs`, `ecosystem_dispatch_e2e.rs:310,986`, `vendor_ecosystem_fixtures/mod.rs:748`, `e2e_vex_vendor.rs`, `e2e_vendored_production.rs`) | nothing (production suites are canaries) | normal `cargo test -p socket-patch-cli --test <name>` |

**Docker images:** build `tests/docker/Dockerfile.base` tagged `socket-patch-test-base:latest`, then `tests/docker/Dockerfile.nuget` (FROM `mcr.microsoft.com/dotnet/sdk:8.0`, copies the binary from base) tagged `socket-patch-test-nuget:latest`.

**CI (`.github/workflows/ci.yml`)**
- `coverage-docker` (`:455`, matrix `:479`) and `e2e-docker` (`:1390`, matrix `:1398`) run `docker_e2e_nuget`, adding `docker_e2e_vendor_nuget` at `:561` and `:1447`.
- `e2e` (`:675`) runs `suite: e2e_nuget` (`:696`) and `e2e_nuget_dotnet_build` for dotnet 6/7/8/9/10 on ubuntu and 8 on macOS (`:1057-1064`, setup-dotnet at `:1248`, env at `:1351`). The default filter is `--ignored` (`:1353`).
- `setup-matrix` (`:1634`) is non-blocking.

## 7. Known TODOs and limitations

- `v5-plan.md:30-31`: "a better vendored story for … NuGet (… NuGet feed is fragile). Keep the current behavior; do not invest further now."
- There are no literal `TODO`/`FIXME` comments in the NuGet files. Documented non-goals are in `vex/discover/nuget.rs:59-65`: parent/user configs, per-project locks, `<clear/>`, a non-Socket source that also maps the id, and `NuGetLockFilePath`.
- **Orphan-sweep gap.** `nuget.config` is missing from `repair_vendor.rs` `WIRING_FILES` (`:105-129`). That list feeds both `repair`'s ledger reconstruction and `sweep_orphan_vendor_dirs` (`vendor.rs:283-326`). Separately, the config names the uuid dir rather than a leaf file. Together this likely means repair cannot recover a NuGet entry, and the sweep could delete a NuGet uuid dir that is still wired. This comes from reading the code only; no test was run to confirm it.
- Config-name mismatch: vendor probes 2 spellings, vex/crawler probe 3, hosted probes only `nuget.config`.
- The hosted lock rewrite matches on id regardless of version (`redirect/mod.rs:5431`).
- The same id+version as upstream means the global-cache collision is untested (every test uses a cold `NUGET_PACKAGES`).
- The signature is dropped, so the package reads as unsigned. This relies on NuGet's default signature validation mode being `accept` (`:15-18`).
- Sidecar (agent mode): `patch/sidecars/nuget.rs:1-18` deletes `.nupkg.metadata` and only advises when `.nupkg.sha512` is present.
- `dispatch_in_use_one` has no NuGet probe (`vendor.rs:256-265`).

## 8. The NuGet crawler (`socket-patch-core/src/crawlers/nuget_crawler.rs`)

- **Global mode** (`:37-49`): uses `--global-prefix` if given, else `NUGET_PACKAGES`, else `~/.nuget/packages` (`nuget_home` `:392`).
- **Local mode** is gated by `is_dotnet_project(cwd)` (`:406`): a root entry that is `*.csproj`, `*.fsproj`, `*.vbproj`, `*.sln` or `*.slnx`, or `nuget.config` / `packages.config` in any casing. When the gate passes, paths are returned in this order:
  1. `<cwd>/packages/` (legacy)
  2. the global cache
  3. the `packageFolders` keys of `obj/project.assets.json` in cwd and one level of subdirectories (`:472-512`)
- **Layouts** (`classify_package_entry` `:228`):
  - Global: `<name>/<version>/`, where the version must start with a digit (`:286-328`).
  - Legacy: `<Name>.<Version>/`, split at the first `.`+digit (`:453`).
  - A package is verified by `lib/` or a `*.nuspec` (`:331`).
- It crawls **every package in those folders**. It does not filter by the project's dependency graph (it does not read assets targets or the lock).
- The purl comes from the directory name, which is lowercased in the global cache.