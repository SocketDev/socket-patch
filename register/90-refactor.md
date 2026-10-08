### Refactor routine (`refactor`, hourly, highest leverage first)
_Last updated 2026-10-08T22:20Z · main @ 830749f_

**In flight:**
- [#1185](https://github.com/SocketDev/socket-patch/pull/1185): every vendored Poetry lock wires through `utils::poetry_lock`; the engine writes 2.x `files` one file per line; deletes the LF line scanner, `toml_surgery::{package_unit_lines, replace_files_array}` and `common::unit_has_canon_name`. Issue #936 (E66). +37/−166 production. Only change: hosted and CRLF-vendored 2.x `files` layout (Poetry's own); `name="…"` / files-less units wire instead of refusing. `state: ready`.
- [#1163](https://github.com/SocketDev/socket-patch/pull/1163): `PatchFileInfo` hashes load as lowercase hex (`deserialize_with`), so agent apply/rollback `==` checks, blob names and vendored pins share one case rule. Issue #707 (C41). +18 production, +112 tests. Only change: an uppercase-hash manifest now applies and rolls back, and is written back lowercase. `state: ready`.
- [#1160](https://github.com/SocketDev/socket-patch/pull/1160): inline BOM handling in 8 more files onto `formats::text`; `PENDING_INLINE_BOMS` 26 → 15. Issue #905 (E64, slice 2). Only change: two leading BOMs. `state: ready`.
- [#1126](https://github.com/SocketDev/socket-patch/pull/1126): 7 inline purl-type checks through `Ecosystem::from_purl` + guard. Issue #747 (C20, slice 1). `state: ready`.
- [#1108](https://github.com/SocketDev/socket-patch/pull/1108): one `utils::line_endings::terminator` for 7 inserted-line sites. Issue #815 (E16, slice 1; the rest is in open-PR files). Re-blesses mixed-ending go/uv goldens only. `state: ready`.
- [#1103](https://github.com/SocketDev/socket-patch/pull/1103): `go.sum` edits through `GoSumEditor` only; deletes the oracle-only free functions and names the key rule once. Issue #631 (E52, slice: steps 2–3; the move to `formats/golang/sum.rs` remains). `state: ready`, handed to the burn-down.
- Maintainer drafts (decided issues): #1027 (#704), #1031 (#966), #1036 (#973), #1041 (#648), #1049 (#792). #1030 (#808) and #1051 (#580) merged.

**Merged:**
- [#1153](https://github.com/SocketDev/socket-patch/pull/1153): one `path_safety::is_safe_name_version` for the cargo/gem/nuget crawlers. Tracker #748 (E37).
- [#1151](https://github.com/SocketDev/socket-patch/pull/1151): one `portable_wheel_artifact` for uv/poetry inventory and recovery. Issue #1150 (E89 fixed).
- [#1145](https://github.com/SocketDev/socket-patch/pull/1145): Gradle XML through `formats::xml`. Issue #715 (E10, Gradle half).
- [#1141](https://github.com/SocketDev/socket-patch/pull/1141): dead hosted-vlt ledger helpers deleted, −181 production. Issue #782 (E58 slice 1).
- [#1106](https://github.com/SocketDev/socket-patch/pull/1106): PDM site probe through `utils::process::output_within` + `kill_on_drop` guard test. Issue #1067 (C48). `c4235a2`.
- [#1110](https://github.com/SocketDev/socket-patch/pull/1110): one `formats::cargo::manifest` `[package]` reader for crawler, VEX and `cargo_tag`. Issue #693 (E15 slice 1). `d52a67b`.
- [#1117](https://github.com/SocketDev/socket-patch/pull/1117): 8 inline BOM strips onto `formats::text` + one-sided guard. Issue #905 (E64). `d13657b`.
- Earlier: #1121 (E89 slice 1), #1124 (C30), #1021 (C05), #1015 (E61; left: dead `eco == "maven2"` arm in `commands/vendor.rs`), #889, #876, #886, #870, #865, #858, #850, #607, #602, #597, #587, #583, #581, #574, #572 (see `entries/refactor/`).

**Queue** (B bugs closed, U unblocks, D duplication removed, R risk; score = 3B + 2U + 2D + S − risk). Since the 2026-10-08 backlog review, standalone refactor issues are closed as `not_planned` and kept as checklist items of their tracker; rank the tracker's next unchecked item.

| # | Candidate | B | U | D | R | Score | Note |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| 1 | #989 item (was #990): one `vendor::revert::finish` for the 12 copied finish blocks | 0 | 1 | ≈12 | L | ≈26 | skipped: backend files changed by open PRs (#1008, #1041, #1026, …) |
| 2 | #717 (E10): hosted pom edits + restore through `formats::xml` / `formats::maven` | 3 | 1 | ≈4 | M | ≈17 | skipped: `redirect/mod.rs` (#1008, #1009, #1026); `upstream/maven.rs` and `formats/maven` are free |
| 3 | #594 (E10): nuget.config edits through `formats::nuget` | 1 | 1 | ≈3 | M | ≈9 | skipped: `redirect/mod.rs`, `vendor/nuget_feed.rs` (#1041) |
| 4 | #936 (E66): one Poetry forward splicer | 0 | 1 | ≈1.6 | M | ≈3 | **taken: #1185** |
| 5 | #705 (C18): one `utils::uuid` grammar | 0 | 0 | 3 | L | ≈6 | skipped: `api/client.rs`, CLI `lib.rs` (#1034, #1041, #1049) |

Re-ranked 2026-10-08T22:00Z at `830749f` against 29 open PRs (387 files in `arch-refactor/*` or `agent/fix-*`). Still blocked by open-PR files: #1144 (CLI `commands/vex.rs`, #1027/#1041), #914 (`jvm_jar.rs`, #1041), #893 (`cleanup_blobs.rs`, #1049), #780 (`vendor/gem.rs`), #1128 (`pypi_pipenv.rs`, #1147), #1064 (`vex/product.rs`, #1007), #913/#675/#676 (`api/client.rs`), #823/#824, #833, #1014 (`jvm/sbt.rs`, #1036), every CLI `commands/*` site. Free but low-leverage: #715's crawler-reader item (`maven_crawler.rs` is free, `vex/product.rs` is not; the crawler path is hot, so it needs timings).

**Notes:**
- Poetry 2.x `files` is written one file per line by the shared engine since #1185; a test or golden that greps `files = [{ file` only sees 1.0/1.1 package-level `files` now.
- A hash read from a manifest is lowercase after #1163; `api::blob_fetcher::blob_hash_matches` and vendored `eq_ignore_ascii_case` sites become plain `==` once their files are free (#707 remainder).
- `mode_migration_pypi::pipenv_hosted_to_vendored_*` needs pypi.org; fails in the sandbox on `main` too.
- A closed issue whose register row is only `partly fixed` needs a new follow-up issue for the remainder (#1150 after #1079); don't reopen the closed one.
- `formats::xml` (#1145) is the shared XML element scanner (comment + CDATA blanking, `elements`, `children`, `attr`); route new XML readers (NuGet, pom writers) through it instead of a private masker.
- The skip rule names only `arch-refactor/*` and `agent/fix-*` PRs; `arch-fix/*`, `ci*` and `ci-janitor/*` files are not blockers by the letter, but check their hunks before touching the same lines.
- A maintainer-closed issue whose backlog note says "Defer" (e.g. #706) is steering: don't rank it until reopened.
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
- `--test repair` has 2 root-only failures (they chmod a directory read-only).
- `tests/spawn_env_hygiene.rs` allowlists (`PENDING_RAW_SPAWNS` / `PENDING_SCRUB_COPIES`) fail on new **and** stale entries: drop a file when you migrate it.
- Probe spawns go through `utils::process::output_within` since #886 (blocking; async callers wrap it in `utils::fs::run_blocking`). It nulls stderr; don't add a new `tokio::time::timeout` + `kill_on_drop` site.
