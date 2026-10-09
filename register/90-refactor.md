### Refactor routine (`refactor`, hourly, highest leverage first)
_Last updated 2026-10-09T20:20Z · main @ 85105c9_

**In flight:**
- [#1370](https://github.com/SocketDev/socket-patch/pull/1370): #782 slice (#801 scope): dead `lock_inventory/wired.rs` (`wired_vendor_integrity`) and its tests deleted. E41. +3/−224 prod, +4/−256 tests. `state: ready`.
- [#1366](https://github.com/SocketDev/socket-patch/pull/1366): #824 children 2–3 slice 3: 5 more test files use `tests/common` `binary()`/`git_sha256` (`vendor_ecosystem_fixtures` includers take `mod common`). C30. +0/−0 prod, +24/−50 tests. `state: ready`.
- [#1358](https://github.com/SocketDev/socket-patch/pull/1358): scala-cli Bloop evidence fails closed on an oversized, unreadable or non-Bloop project file, the sbt reader's policy; skip branches deleted. Fixes #1270 (E95). +23/−6 prod, +87/−1 tests. `state: ready`.
- [#1347](https://github.com/SocketDev/socket-patch/pull/1347): one `crawlers::pnpm_layout` answers where pnpm installs (crawler roots, `detect_npm_pkg_manager`, PnP carve-out over disk/snapshot/memory); `node_modules`-only probes deleted. Fixes #1129 (E92). +191/−92 prod, +213 tests. `state: ready`.
- [#1294](https://github.com/SocketDev/socket-patch/pull/1294): `utils::target` keys packages by `package_identity` (`PurlKey` base); versionless purls and the ambiguity guard stop lowercasing npm/Go/Maven/cargo/gem. Fixes #1292 (C80). +78/−34 prod, +168 tests. `state: ready`.
- [#1188](https://github.com/SocketDev/socket-patch/pull/1188): one `Pipfile.lock` writer (`formats::pipenv::splice_entry`). #1128 (E14). +303/−235 prod. `state: ready`.
- [#1126](https://github.com/SocketDev/socket-patch/pull/1126): 7 inline purl-type checks through `Ecosystem::from_purl` + guard. Issue #747 (C20, slice 1). `state: ready`.
- Maintainer draft: #1049 (#792).

**Merged:** #1288 (E10, #685; +128/−150 prod), #1277 (E64), #1272 (C32), #1262 (C77), #1258 (C30), #1245 (E24), #1264 (E16), #1239, #1253, #1227, #1221, #1230, #1217/#1209/#1205/#1183; 32 earlier PRs (#572 … #1191, see `entries/refactor/`). Leftovers: `blob_hash_matches` (#1163), dead `eco == "maven2"` arm in `commands/vendor.rs` (#1015), `vendor/common.rs` jar caller of #1253.

**Queue** (score = 3B + 2U + 2D + S − risk). Standalone refactor issues closed `not_planned` live on as tracker checklist items; rank the tracker's next item.

| # | Candidate | B | U | D | R | Score | Note |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| 1 | #782 E41 (#801 scope): delete dead `lock_inventory/wired.rs` | 0 | 0 | ≈2.3 | L | ≈4.6 | **taken: #1370** |
| 2 | #931 + #998 + #1063 + #1123: one manifest load + error mapper | 4 | 1 | ≈6 | M | ≈24 | skipped: `apply.rs`, `vendor.rs`, `repair.rs` (#1049, #1273, #1345, #1357, #1369 …) |
| 3 | #1365 (E96): one requirements.txt exact-pin grammar | 1 | 1 | ≈2.5 | M | ≈6 | skipped: `redirect/requirements.rs` (#1333, #1279), `vendor/pypi_requirements.rs` (#1309, #1279) |
| 4 | #824 child 4: `oracle_support` and `npm_crawler/oracle` xorshift onto `test_rng::Rng` | 0 | 0 | 2 | L | 4 | free |
| 5 | #782 rest: `PnpmLock::wired_integrity`, `python_lock.rs` doc, `vex/discover/mod.rs` needle | 0 | 0 | ≈0.3 | L | ≈0.6 | skipped: #1320, #1332, #1321/#1349; C17 `group_commit.rs` digest slice (score 2) free |
Re-ranked 2026-10-09T20:00Z at `85105c9` against 78 open PRs. #1274 merging freed `lock_inventory/tests.rs`. Also skipped by file overlap: #1114, #1235, #614/#675, #705, #833 moves, E12, E15, E19, E64 rest, #914 rest, #1202 rest, #823; `nuget_feed.rs` (8 PRs) and `redirect/mod.rs` (13 PRs) stay busy.

**Notes:**
- Test binaries that add `#[path = "common/mod.rs"] mod common;` must drop their own `#[path]` mods of `common/{cache_env,hermetic,envelope}.rs` and take them through `common` (re-export at the crate root when a helper module says `crate::cache_env`). The `jvm_env` duplicate-module warning from `common` + `prebuilt_common` already exists on main; CI clippy skips test targets.
- JVM evidence (#1358): both readers (sbt, scala-cli) fail closed on a record they cannot read; only non-regular entries and other workspaces' projects are ignored.
- The clone is shallow (depth 50): `git fetch --deepen=400 origin main` before computing merge-bases for the file-overlap map, or old PR heads show "no merge base" / hundreds of files.
- pnpm layout (#1347): ask `crawlers::pnpm_layout` (`configured_modules_dirs`, `installed_store_in`) for where pnpm installs; never probe a literal `node_modules/.pnpm` again. A snapshot read through it goes through `root()` (recording not reused), only when `node_modules` holds no store.
- Target identity (#1294): `utils::target::package_identity` is the `PurlKey` base without version; a lowercase name over case-distinct packages is ambiguous, an uppercase-bearing name settles on its exact case. `package_spec_matches` stays lenient for `scan --package`/socket.yml only.
- NuGet config (#1288): vendored writes anchor on `parse_config`'s `ConfigSection`; malformed XML or `repeated_sections` is refused. Hosted inserts at section start, vendored before the close line (revert excises its exact bytes): don't merge the writers without moving the revert. `formats::nuget::xml_attribute` duplicates hosted `nuget_xml_attribute` until `redirect/mod.rs` frees.
- #1279 (maintainer draft, `refactor/crate-bloat-cleanup`) changes `vendor/common.rs`, `vendor/{cargo,gem,registry_fetch}.rs` and most of `redirect/upstream/`: treat as busy.
- BOM (#905, #1277): `top_level_key` and the TOML lexer (toml_parser) already skip one leading BOM; never strip before them (that accepts two).
- CLI tests read `--json` through `common::envelope` since #1272 (`parse_json_envelope`, strict `events`, `find_event`, `event_triples`, lenient `event_codes`/`codes_in`, recursive `all_codes`); `cli/envelope_helper_copies.rs` fails on new private copies, stale entries allowed.
- Gradle line endings (#1264): `gradle::eol` is gone; Gradle writers insert with `line_endings::terminator` and find what they wrote with `line_endings::respell(text, terminator(current))`, compare owned files with `line_endings::eol_eq`. Keep forward and revert on the same rule.
- User-named output paths (`--output`, `--vex <path>`) go through `utils::fs::write_user_output` since #1262, never stage-and-rename. Root-proof write failure: `RLIMIT_FSIZE` + ignored `SIGXFSZ` in `pre_exec`, with `LLVM_PROFILE_FILE=/dev/null` on that child.
- Revert finish (#1245): new backends end with `revert::finish(…, KeepPolicy::…)`; npm family keeps bare `cannot remove <rel>`, the rest `failed to remove <abs>` with warnings. Extend the policy, do not re-copy the sequence.
- `bench.yml` gates +10% per scenario: time a per-dep reader (hosted converge) in release against `main` before pushing.
- Gem lock edits locate through `formats::gem::parse` since #1221 (`Section::lines()`/`end`, `remote_line_nos`, `GemfileLock::dependencies`); the vendored slice reads the same fields.
- Crawl scopes (#1205 cargo, #1209 Go, #1217 Deno): only a parseable `<cwd>` lock (`Cargo.lock`; `go.sum` with no workspace; `deno.lock` with `version`) scopes. "Only the crawl vouches" fixtures must lock the cached package (cargo: put it in `vendor/`) or drop the lock; narrowing a crawl changes `scan --prune`.
- `Pipfile.lock` edits go through `formats::pipenv::splice_entry` since #1188: sort the value (`sort_all_objects`) before splicing; never re-serialize the whole lock.
- NuGet crawl scope (#1183): only a `cwd` with a project file is scoped; a solution root keeps the walk (restores at any depth). Extend through `PackageRoots::scope`, not a second assets reader.
- A hash read from a manifest is lowercase after #1163; `api::blob_fetcher::blob_hash_matches` and vendored `eq_ignore_ascii_case` sites become plain `==` once their files are free (#707 remainder).
- `formats::xml` (#1145) is the shared XML element scanner (comment + CDATA blanking, `elements`, `children`, `attr`); route new XML readers (NuGet, pom writers) through it instead of a private masker.
- Test-helper migrations (#824): directory binaries import via `crate::common`. `spawn_env_hygiene` scans test text, literals included: never spell a bare binary spawn in a new test file; run it before pushing.
- Equivalence goldens (`tests/equivalence/*.golden`, bless with `SOCKET_PATCH_BLESS_GOLDEN=1`) include mixed-ending inputs: prove only mixed cases move before re-blessing a line-ending change.
- Root sandbox: 4 core lib tests fail on main too (permission-dependent): `copy_tree::relax_loop_must_not_traverse_symlinked_root`, `vlt_heal::an_unremovable_hidden_lock_keeps_every_store_entry`, `pypi_poetry::wire_write_failure_maps_error_and_leaves_lock_untouched`, `pypi_requirements::wire_failure_rolls_back_already_written_files`.
- `redirect/pipenv.rs`, `vendor/pypi.rs` and `vendor/lock_inventory/vlt.rs` aren't rustfmt-clean on main: format only your own hunks there. Check `rustfmt --check` on the `main` copy before formatting a whole file.
- `lock_inventory/mod.rs` `architecture_tests` forbid `hosted_patch_uuid*` in a format file's model section. Origin-policy helpers go after the `// ── registry view ──` marker.
- NuGet identity (#1230): `PurlKey` folds versions through `vendor::nuget_feed::normalize_nuget_version` (a utils→vendor import until `nuget_feed.rs` frees for the `formats::nuget` move). `test_support::service_fixture` builds its NuGet grant from `<id>.<purl version>.nupkg`, so a test vendoring a non-normalized version needs that file too.
- Steering (2026-10-02, #569/#571): no size caps on trusted upstream data; stream, don't buffer.
- `tests/spawn_env_hygiene.rs` allowlists (`PENDING_RAW_SPAWNS` / `PENDING_SCRUB_COPIES`) fail on new **and** stale entries: drop a file when you migrate it.
- Probe spawns go through `utils::process::output_within` since #886 (blocking; async callers wrap it in `utils::fs::run_blocking`). It nulls stderr; don't add a new `tokio::time::timeout` + `kill_on_drop` site.
