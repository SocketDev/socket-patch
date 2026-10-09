### Refactor routine (`refactor`, hourly, highest leverage first)
_Last updated 2026-10-09T04:25Z · main @ f3c6313_

**In flight:**
- [#1221](https://github.com/SocketDev/socket-patch/pull/1221): hosted `converge_gem_lock_source` reads `formats::gem` section spans, remote lines and DEPENDENCIES entries; `GemLockSection` + `gem_lock_dependency_name` deleted. #780 hosted slice (E19). +143/−104 prod, +325 tests. `state: ready`.
- [#1217](https://github.com/SocketDev/socket-patch/pull/1217): Deno crawl scoped to `deno.lock` `jsr` keys; one `locate`, one `lock_section` (shared with VEX). #1216 (E05). +108/−43 prod, +142 tests; 48.1 → 7.5 ms (debug). `state: ready`.
- [#1209](https://github.com/SocketDev/socket-patch/pull/1209): Go crawl scoped to `go.sum` modules; one `locate_module`. #1207 (E05). +132/−44 prod, +269 tests; 7.7 → 1.0 ms. `state: ready`.
- [#1188](https://github.com/SocketDev/socket-patch/pull/1188): one `Pipfile.lock` writer (`formats::pipenv::splice_entry`, `formats::json`). Issue #1128 (E14). +303/−235 production. `redirect/mod.rs` wrapper `pipenv_reserialized_around_reference` left for when that file is free. `state: ready`.
- [#1126](https://github.com/SocketDev/socket-patch/pull/1126): 7 inline purl-type checks through `Ecosystem::from_purl` + guard. Issue #747 (C20, slice 1). `state: ready`.
- Maintainer drafts (decided issues): #1036 (#973), #1041 (#648), #1049 (#792). #1027 (#704), #1030 (#808), #1031 (#966) and #1051 (#580) merged.

**Merged:**
- [#1205](https://github.com/SocketDev/socket-patch/pull/1205): cargo crawl scoped to `Cargo.lock` registry packages. #1204 (E05 partly fixed). +144/−49 prod, +226/−11 tests.
- [#1183](https://github.com/SocketDev/socket-patch/pull/1183): NuGet crawl scoped to the restore's `libraries`. #427 (E05 partly fixed). +130 prod, +220 tests.
- [#1191](https://github.com/SocketDev/socket-patch/pull/1191): 4 more files onto `formats::text`; `PENDING_INLINE_BOMS` 11. Issue #905 (E64 slice 3). +11/−13 production, +74 tests.
- [#1103](https://github.com/SocketDev/socket-patch/pull/1103): `go.sum` edits through `GoSumEditor` only; oracle-only free helpers deleted. Issue #631 (E52 partly fixed; the move to `formats/golang/sum.rs` remains).
- [#1185](https://github.com/SocketDev/socket-patch/pull/1185): one Poetry forward splicer (`utils::poetry_lock`); 2.x `files` multi-line in both modes. Issue #936 (E66 fixed). +37/−166 production.
- Earlier: #1108 (E16 slice 1), #1163 (C41; `blob_hash_matches` remains), #1160 (E64 slice 2), #1153, #1151, #1145, #1141 (see entries), #1106 (C48), #1110 (E15 slice 1), #1117 (E64), #1121 (E89 slice 1), #1124 (C30), #1021 (C05), #1015 (E61; left: dead `eco == "maven2"` arm in `commands/vendor.rs`), #889, #876, #886, #870, #865, #858, #850, #607, #602, #597, #587, #583, #581, #574, #572 (see `entries/refactor/`).

**Queue** (B bugs closed, U unblocks, D duplication removed, R risk; score = 3B + 2U + 2D + S − risk). Since the 2026-10-08 backlog review, standalone refactor issues are closed as `not_planned` and kept as checklist items of their tracker; rank the tracker's next unchecked item.

| # | Candidate | B | U | D | R | Score | Note |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| 1 | #989 item: one `vendor::revert::finish` for the 12 copied finish blocks | 0 | 1 | ≈12 | L | ≈26 | skipped: every backend file is in an open PR (#1007, #1009, #1026, #1036, #1041, #1161, #1187, #1193, #1211) |
| 2 | #931 + #998 + #1063 + #1123: one manifest load + error mapper for every command | 4 | 1 | ≈6 | M | ≈24 | skipped: `apply.rs`, `vendor.rs`, `repair.rs`, `remove.rs`, `rollback.rs`, `scan/`, `ledgers.rs`, `args.rs` all in open PRs |
| 3 | #717 (E10): hosted pom edits + restore through `formats::maven` | 3 | 1 | ≈4 | M | ≈17 | skipped: `redirect/mod.rs` (#1009, #1026, #1180, #1193, #1211) |
| 4 | #780 (E19) hosted slice: `formats::gem` spans for hosted convergence | 0 | 1 | ≈2 | L | ≈6 | **taken: #1221**; vendored slice waits for `vendor/gem.rs` (#1026, #1041) |
| 5 | #1220 (C78): bound upstream-restore fan-out through `utils::concurrent::registry_concurrency` | 1 | 0 | ≈4 | L | ≈11 | skipped: `upstream/{npm,pypi,cargo,composer,mod}.rs` and `concurrent.rs` in open PRs |

Re-ranked 2026-10-09T04:00Z at `f3c6313` (#1008 merged) against 17 `arch-refactor/*` / `agent/fix-*` / `arch-fix/*` PRs changing 354 files. Free but lower: E16 remainder (`detect_eol` caller in `yarn_classic_lock.rs`, #1211), #1202 (`nuget_feed.rs` in #1041), #1014 (`.mill-version` needs a decision), #265 Maven crawl (no lockfile to scope by: risk H), E37 (`composer_crawler::normalize_version` ≡ `strip_leading_v`, D 1).

**Notes:**
- Gem lock edits locate through `formats::gem::parse` since #1221: `Section::lines()` / `end`, `remote_line_nos`, `GemfileLock::dependencies` (entries with one name rule). Whitespace-only lines are blank separators. The vendored slice should read the same fields, not add a fourth walker.
- Real bundler (4.0.18) is installed in the sandbox: `e2e_redirect_gem_build -- --ignored` (25) and `e2e_vendor_gem_build -- --include-ignored` (41) run in ~30 s each.
- Deno crawl scope (#1217): only a local project whose `<cwd>/deno.lock` parses and has a `version` is scoped; a lock with no `jsr` section crawls no JSR package. A CLI fixture that needs the crawl to find a cached JSR package must lock it (or omit `deno.lock`). `lock_section` lives in `deno_crawler.rs` until `formats/mod.rs` is free for a `formats::deno` model.
- Go crawl scope (#1209): only a local project with a readable `<cwd>/go.sum` and no workspace (`go.work` in cwd or an ancestor, or `GOWORK` set to a file; `GOWORK=off` scopes) is scoped. A CLI fixture that needs the crawl to vouch for a cached module must list it in `go.sum` or drop `go.sum`.
- Cargo crawl scope (#1205): only a local project's registry cache with a parseable `<cwd>/Cargo.lock` is scoped; `vendor/`, global and lockless crawls walk. A CLI test that needs "only the crawl vouches" must put the crate in `vendor/`, not an unlocked `CARGO_HOME`. Narrowing a crawl changes `scan --prune` (an unlocked cached crate's entry becomes prunable): say so in the PR.
- `Pipfile.lock` edits go through `formats::pipenv::splice_entry` since #1188: sort the value (`sort_all_objects`) before splicing; never re-serialize the whole lock.
- NuGet crawl scope (#1183): only a `cwd` with a project file is scoped; a solution root keeps the walk (restores at any depth). Extend through `PackageRoots::scope`, not a second assets reader.
- Poetry 2.x `files` is written one file per line by the shared engine since #1185; a test or golden that greps `files = [{ file` only sees 1.0/1.1 package-level `files` now.
- A hash read from a manifest is lowercase after #1163; `api::blob_fetcher::blob_hash_matches` and vendored `eq_ignore_ascii_case` sites become plain `==` once their files are free (#707 remainder).
- A closed issue whose register row is only `partly fixed` needs a new follow-up issue for the remainder (#1150 after #1079); don't reopen the closed one.
- `formats::xml` (#1145) is the shared XML element scanner (comment + CDATA blanking, `elements`, `children`, `attr`); route new XML readers (NuGet, pom writers) through it instead of a private masker.
- The skip rule names only `arch-refactor/*` and `agent/fix-*` PRs; `arch-fix/*`, `ci*` and `ci-janitor/*` files are not blockers by the letter, but check their hunks before touching the same lines.
- E35's crawler oracles can't become `golden.rs` digests: their randomized trees (symlinks, modes, case collisions) differ by OS and uid. Keep them until a crawler can be checked without one.
- Test-helper migrations (#824): directory binaries import via `crate::common`; prune the unused imports `--no-run --message-format=short` lists. `spawn_env_hygiene` scans test text, string literals included: never spell a bare binary spawn in a new test file, and run that suite before pushing.
- Source-scan guards: one-sided (fail on new files only) and normalize `\r\n` (Windows CI checks out CRLF).
- `toml_edit` parse: ~81 µs per `Cargo.toml` vs 0.5 µs for a line scanner; disclose it on hot crawl paths. It skips one leading BOM itself.
- Equivalence goldens (`tests/equivalence/*.golden`, bless with `SOCKET_PATCH_BLESS_GOLDEN=1`) include mixed-ending inputs: prove only mixed cases move before re-blessing a line-ending change.
- Upstream gem `restore_manifest` pins CRLF output for a CRLF Gemfile with an LF block; migrate it only together with the forward Gemfile writer in `redirect/mod.rs`.
- Deleting a refactor oracle: refactor the kept code under the oracle, pin its outputs on odd inputs, then delete it (#1103).
- The sandbox runs as root, so 4 core lib tests fail on main and on branches alike: `copy_tree::relax_loop_must_not_traverse_symlinked_root`, `vlt_heal::an_unremovable_hidden_lock_keeps_every_store_entry`, `pypi_poetry::wire_write_failure_maps_error_and_leaves_lock_untouched`, `pypi_requirements::wire_failure_rolls_back_already_written_files`.
- `redirect/pipenv.rs`, `vendor/pypi.rs` and `vendor/lock_inventory/vlt.rs` aren't rustfmt-clean on main: format only your own hunks there. Check `rustfmt --check` on the `main` copy before formatting a whole file.
- `lock_inventory/mod.rs` `architecture_tests` forbid `hosted_patch_uuid*` in a format file's model section. Origin-policy helpers go after the `// ── registry view ──` marker.
- 2026-10-08: ~40 refactor issues were closed `not_planned` into trackers ("Consolidated work"); that is scheduling, not rejection. Claim/`Fixes` the item's issue only if still open, else reference the tracker.
- Pushes need verified signatures: commit with the session's default git identity, never an overridden `user.email`.
- Maintainer steering (2026-10-02, on #569 and #571): don't add size caps on trusted upstream data; stream instead of buffering.
- `cargo clippy --all-targets` already fails on `main` (old test lints); CI gates `cargo clippy --workspace --all-features -- -D warnings`.
- `tests/spawn_env_hygiene.rs` allowlists (`PENDING_RAW_SPAWNS` / `PENDING_SCRUB_COPIES`) fail on new **and** stale entries: drop a file when you migrate it.
- Probe spawns go through `utils::process::output_within` since #886 (blocking; async callers wrap it in `utils::fs::run_blocking`). It nulls stderr; don't add a new `tokio::time::timeout` + `kill_on_drop` site.
