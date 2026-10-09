### Refactor routine (`refactor`, hourly, highest leverage first)
_Last updated 2026-10-09T02:26Z · main @ eb3fcc4_

**In flight:**
- [#1209](https://github.com/SocketDev/socket-patch/pull/1209): project-mode Go crawl looks up `go.sum`'s module-zip lines in `GOMODCACHE` instead of walking (workspaces, no `go.sum` and global still walk); one `locate_module` shared with `find_by_purls`. Issue #1207 (E05, #595 Go child). +132/−44 production, +269 tests. 3,000-module cache, 300-module `go.sum`: 7.7 ms → 1.0 ms. `state: ready`.
- [#1205](https://github.com/SocketDev/socket-patch/pull/1205): project-mode cargo crawl looks up `Cargo.lock`'s registry packages in `registry/src/*` instead of walking; one `formats::cargo::is_registry_source`. Issue #1204 (E05, #595 cargo child). +144/−49 production, +226/−11 tests. Only change: cached-but-unlocked crates no longer crawled (so `scan --prune` treats their manifest entries as uninstalled). 3,000-crate cache, 300-crate lock: 26.0 ms → 4.7 ms. `state: ready`.
- [#1188](https://github.com/SocketDev/socket-patch/pull/1188): one `Pipfile.lock` writer (`formats::pipenv::splice_entry`, `formats::json`). Issue #1128 (E14). +303/−235 production. `redirect/mod.rs` wrapper `pipenv_reserialized_around_reference` left for when that file is free. `state: ready`.
- [#1183](https://github.com/SocketDev/socket-patch/pull/1183): project-mode NuGet crawl of a restored project looks up the shared roots for the restore's `libraries` instead of walking them; one `project.assets.json` reader. Issue #427 (E05, #595 NuGet child). +130 production, +220 tests. Only change: unresolved shared-cache packages are no longer crawled. 3,000-package cache: 58 ms → 0.8 ms. `state: ready`.
- [#1126](https://github.com/SocketDev/socket-patch/pull/1126): 7 inline purl-type checks through `Ecosystem::from_purl` + guard. Issue #747 (C20, slice 1). `state: ready`.
- Maintainer drafts (decided issues): #1036 (#973), #1041 (#648), #1049 (#792). #1027 (#704), #1030 (#808), #1031 (#966) and #1051 (#580) merged.

**Merged:**
- [#1191](https://github.com/SocketDev/socket-patch/pull/1191): 4 more files onto `formats::text`; `PENDING_INLINE_BOMS` 11. Issue #905 (E64 slice 3). +11/−13 production, +74 tests.
- [#1103](https://github.com/SocketDev/socket-patch/pull/1103): `go.sum` edits through `GoSumEditor` only; oracle-only free helpers deleted. Issue #631 (E52 partly fixed; the move to `formats/golang/sum.rs` remains).
- [#1185](https://github.com/SocketDev/socket-patch/pull/1185): one Poetry forward splicer (`utils::poetry_lock`); 2.x `files` multi-line in both modes. Issue #936 (E66 fixed). +37/−166 production.
- Earlier: #1108 (E16 slice 1), #1163 (C41; `blob_hash_matches` remains), #1160 (E64 slice 2), #1153, #1151, #1145, #1141 (see entries), #1106 (C48), #1110 (E15 slice 1), #1117 (E64), #1121 (E89 slice 1), #1124 (C30), #1021 (C05), #1015 (E61; left: dead `eco == "maven2"` arm in `commands/vendor.rs`), #889, #876, #886, #870, #865, #858, #850, #607, #602, #597, #587, #583, #581, #574, #572 (see `entries/refactor/`).

**Queue** (B bugs closed, U unblocks, D duplication removed, R risk; score = 3B + 2U + 2D + S − risk). Since the 2026-10-08 backlog review, standalone refactor issues are closed as `not_planned` and kept as checklist items of their tracker; rank the tracker's next unchecked item.

| # | Candidate | B | U | D | R | Score | Note |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| 1 | #989 item: one `vendor::revert::finish` for the 12 copied finish blocks | 0 | 1 | ≈12 | L | ≈26 | skipped: backend files changed by open PRs (#1008, #1041, #1036, …) |
| 2 | #717 (E10): hosted pom edits + restore through `formats::maven` | 3 | 1 | ≈4 | M | ≈17 | skipped: `redirect/mod.rs` (#1008, #1009, #1026, #1180, #1190, #1193) |
| 3 | #705 (C18): one `utils::uuid` grammar | 0 | 0 | ≈4 | L | ≈8 | skipped: `cli/lib.rs` + `api/client.rs` in #1034, `apply.rs` in #1049 |
| 4 | #595 Go child (E05): scope project-mode crawl to `go.sum` modules | 0 | 1 | ≈1 | M | ≈5 (S 3) | **taken: #1207 / #1209** |
| 5 | #595 Deno child (E05): scope to the `deno.lock` `jsr` entries | 0 | 0 | ≈1 | M | ≈3 (S 3) | free (`deno_crawler.rs`); next run |

Re-ranked 2026-10-09T02:00Z at `793edd4` against 16 `arch-refactor/*` / `agent/fix-*` / `arch-fix/*` PRs; only `context.rs`, `lock_cli.rs`, `update.rs`, `composer_hints.rs`, `lib.rs`, `main.rs` and a few `scan/` helpers are free in the CLI. Also blocked: #1098 (`ecosystem_dispatch.rs`), #1129 (`npm_crawler.rs`), #914 (`jvm_jar.rs`, #1041), #893 (`cleanup_blobs.rs`, #1049), #1144 (`commands/vex.rs`, #1041), #757 (`redirect/mod.rs`), #913/#675/#676 (`api/client.rs`), #1064 (`vex/product.rs`, #1007). Next free #595 child: Deno (`deno_crawler.rs`), same scope + locate shape.

**Notes:**
- Go crawl scope (#1209): only a local project with a readable `<cwd>/go.sum` and no workspace (`go.work` in cwd or an ancestor, or `GOWORK` set to a file; `GOWORK=off` scopes) is scoped. A CLI fixture that needs the crawl to vouch for a cached module must list it in `go.sum` or drop `go.sum`.
- Cargo crawl scope (#1205): only a local project's registry cache with a parseable `<cwd>/Cargo.lock` is scoped; `vendor/`, global and lockless crawls walk. A CLI test that needs "only the crawl vouches" must put the crate in `vendor/`, not an unlocked `CARGO_HOME`. Narrowing a crawl changes `scan --prune` (an unlocked cached crate's entry becomes prunable): say so in the PR.
- `Pipfile.lock` edits go through `formats::pipenv::splice_entry` since #1188: sort the value (`sort_all_objects`) before splicing; never re-serialize the whole lock.
- NuGet crawl scope (#1183): only a `cwd` with a project file is scoped; a solution root keeps the walk (restores at any depth). Extend through `PackageRoots::scope`, not a second assets reader.
- Overlapping runs: re-fetch the ledger and open PRs right before claiming.
- Poetry 2.x `files` is written one file per line by the shared engine since #1185; a test or golden that greps `files = [{ file` only sees 1.0/1.1 package-level `files` now.
- A hash read from a manifest is lowercase after #1163; `api::blob_fetcher::blob_hash_matches` and vendored `eq_ignore_ascii_case` sites become plain `==` once their files are free (#707 remainder).
- A closed issue whose register row is only `partly fixed` needs a new follow-up issue for the remainder (#1150 after #1079); don't reopen the closed one.
- `formats::xml` (#1145) is the shared XML element scanner (comment + CDATA blanking, `elements`, `children`, `attr`); route new XML readers (NuGet, pom writers) through it instead of a private masker.
- The skip rule names only `arch-refactor/*` and `agent/fix-*` PRs; `arch-fix/*`, `ci*` and `ci-janitor/*` files are not blockers by the letter, but check their hunks before touching the same lines.
- Maintainer "Defer" closes (e.g. #706) are steering: don't rank until reopened.
- E35's crawler oracles can't become `golden.rs` digests: their randomized trees (symlinks, modes, case collisions) differ by OS and uid. Keep them until a crawler can be checked without one.
- Test-helper migrations (#824): directory binaries import via `crate::common`; prune the unused imports `--no-run --message-format=short` lists. `spawn_env_hygiene` scans test text, string literals included: never spell a bare binary spawn in a new test file, and run that suite before pushing.
- Source-scan guards: one-sided (fail on new files only) and normalize `\r\n` (Windows CI checks out CRLF).
- `toml_edit` parse: ~81 µs per `Cargo.toml` vs 0.5 µs for a line scanner; disclose it on hot crawl paths. It skips one leading BOM itself.
- Equivalence goldens (`tests/equivalence/*.golden`, bless with `SOCKET_PATCH_BLESS_GOLDEN=1`) include mixed-ending inputs: prove only mixed cases move before re-blessing a line-ending change.
- Upstream gem `restore_manifest` pins CRLF output for a CRLF Gemfile with an LF block; migrate it only together with the forward Gemfile writer in `redirect/mod.rs`.
- Overlap check: fetch `/pulls/<n>/files` for every open PR, match exact paths; `comm -23` of `git ls-files` against that set lists the free files.
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
