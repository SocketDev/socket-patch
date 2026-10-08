### Refactor routine (`refactor`, hourly, highest leverage first)
_Last updated 2026-10-08T18:40Z · main @ c4235a2_

**In flight:**
- [#1153](https://github.com/SocketDev/socket-patch/pull/1153): one `path_safety::is_safe_name_version` for the cargo, gem and NuGet crawlers (and NuGet's oracle) and the cargo/gem/nuget and PyPI purl builders; deletes `is_safe_{cargo,gem,nuget}_coordinate` and their three test copies. Tracker #748 (E37, the #630 item; composer `normalize_version` half waits on #1108). +97 / −141 (production ≈ +12 / −45). `state: ready`.
- [#1151](https://github.com/SocketDev/socket-patch/pull/1151): uv/PEP 751 and poetry lock inventory pick pure wheels through the shared `is_portable_wheel_url` (#1048) rule, and inventory and ledger recovery share one `portable_wheel_artifact` pick; deletes both `-none-any.whl` suffix checks and recovery's copy. Issue #1150 (E89, the rest of #1079). +30 / −32 production, +101 tests. Only change: `cp*`/`pp*`/`py2-none-any` wheels are no longer pinned by inventory. `state: ready`.
- [#1145](https://github.com/SocketDev/socket-patch/pull/1145): Gradle's `verification-metadata.xml` and parent-pom reads go through a new `formats::xml` (the pom scanner moved out of `formats::maven`); deletes `gradle.rs`'s `mask_xml_comments`/`xml_elements`/`xml_attr`. Issue #715 (E10, item 6, Gradle half). +282 / −308 production (~120 moved), +123 tests. Only change: CDATA markup is text, malformed verification files refuse. `state: ready`.
- [#1141](https://github.com/SocketDev/socket-patch/pull/1141): deletes the dead hosted-vlt redirect-ledger helpers (`vlt::{edit_dep_id, lock_node_ids, claims_key, carried_pin_*}`, `vlt_heal::ledger_targets`), gates `jvm::apply::read_project_file` to tests, and pins `lock_targets` with a unit test. Issue #782 (E58, slice 1). +13 / −194 production, +36 / −150 tests. `state: ready`.
- [#1126](https://github.com/SocketDev/socket-patch/pull/1126): 7 inline `starts_with("pkg:<type>/")` checks (Bun/vlt preflights, PyPI fuzzy match, Coursier sidecar, VEX verify) through `Ecosystem::from_purl`, plus an equivalence table test and a one-sided guard listing 16 pending files. Issue #747 (C20, slice 1). +18 / −9 production, +155 tests. `state: ready`.
- [#1108](https://github.com/SocketDev/socket-patch/pull/1108): one `utils::line_endings::terminator` for 7 inserted-line sites. Issue #815 (E16, slice 1; the rest is in open-PR files). Re-blesses mixed-ending go/uv goldens only. `state: ready`.
- [#1103](https://github.com/SocketDev/socket-patch/pull/1103): `go.sum` edits through `GoSumEditor` only; deletes the oracle-only free functions and names the key rule once. Issue #631 (E52, slice: steps 2–3; the move to `formats/golang/sum.rs` remains). `state: ready`, handed to the burn-down.
- Maintainer drafts (decided issues): #1027 (#704), #1030 (#808), #1031 (#966), #1036 (#973), #1041 (#648), #1049 (#792), #1051 (#580).

**Merged:**
- [#1106](https://github.com/SocketDev/socket-patch/pull/1106): PDM site probe through `utils::process::output_within` + `kill_on_drop` guard test. Issue #1067 (C48). `c4235a2`.
- [#1110](https://github.com/SocketDev/socket-patch/pull/1110): one `formats::cargo::manifest` `[package]` reader for crawler, VEX and `cargo_tag`. Issue #693 (E15 slice 1). `d52a67b`.
- [#1117](https://github.com/SocketDev/socket-patch/pull/1117): 8 inline BOM strips onto `formats::text` + one-sided guard. Issue #905 (E64). `d13657b`.
- Earlier: #1121 (E89 slice 1), #1124 (C30), #1021 (C05), #1015 (E61; left: dead `eco == "maven2"` arm in `commands/vendor.rs`), #889, #876, #886, #870, #865, #858, #850, #607, #602, #597, #587, #583, #581, #574, #572 (see `entries/refactor/`).

**Queue** (B bugs closed, U unblocks, D duplication removed, R risk; score = 3B + 2U + 2D + S − risk). Since the 2026-10-08 backlog review, standalone refactor issues are closed as `not_planned` and kept as checklist items of their tracker; rank the tracker's next unchecked item.

| # | Candidate | B | U | D | R | Score | Note |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| 1 | #989 item (was #990): one `vendor::revert::finish` for the 12 copied finish blocks | 0 | 1 | ≈12 | L | ≈26 | skipped: all 12 backend files changed by open PRs (#1008, #1041, …) |
| 2 | #594 / #717 (E10): nuget.config and pom.xml edits through the `formats::nuget` / `formats::maven` tokenizers | 3 | 1 | ≈6 | M | ≈21 | skipped: `redirect/mod.rs`, `vendor/nuget_feed.rs` (#1041) |
| 3 | #1014 (E69): one Scala-tool build classifier for six marker lists | 1 | 0 | ≈5 | M | ≈11 | skipped: `vendor/jvm/sbt.rs` (#1036), `hosted/engine.rs` (#1007–#1009); E69 also in PR #1032 |
| 4 | #748 item #630 (E37): crawler coordinate guards → `path_safety::is_safe_name_version` | 0 | 0 | 3 | L | ≈6 | **taken: #1153** |
| 5 | #748 item #630 rest: composer `normalize_version` → `composer_version::strip_leading_v` | 0 | 0 | 1 | L | ≈2 | skipped: `upstream/composer.rs` (#1108) |

Re-ranked 2026-10-08T18:05Z at `c4235a2` against 32 open PRs (394 files in `arch-refactor/*` or `agent/fix-*`). C69/#836 (`redirect/mod.rs`), #1129 (`npm_crawler.rs`), C50/#893 (`cleanup_blobs.rs`, #1049), C77/#1144 (`commands/vex.rs`), C51/#914 (`jvm_jar.rs`), E41/E28/#782 rest (`lock_inventory`, #1141 open on #782), #705, #913, #675, #780, #936, #1128 and every `commands/*` manifest reader remain blocked by open-PR files. #706's digest slice stays deferred.

**Notes:**
- `mode_migration_pypi::pipenv_hosted_to_vendored_names_the_unpatched_requirements` needs a GET to pypi.org and fails in the sandbox on `main` too.
- A closed issue whose register row is only `partly fixed` needs a new follow-up issue for the remainder (#1150 after #1079); don't reopen the closed one.
- `formats::xml` (#1145) is the shared XML element scanner (comment + CDATA blanking, `elements`, `children`, `attr`); route new XML readers (NuGet, pom writers) through it instead of a private masker.
- The skip rule names only `arch-refactor/*` and `agent/fix-*` PRs; `arch-fix/*`, `ci*` and `ci-janitor/*` files are not blockers by the letter, but check their hunks before touching the same lines.
- A maintainer-closed issue whose backlog note says "Defer" (e.g. #706) is steering: don't rank it until reopened.
- E35's crawler oracles can't become `golden.rs` digests: their randomized trees (symlinks, modes, case collisions) differ by OS and uid. Keep them until a crawler can be checked without one.
- Test-helper migrations (#824): directory binaries import via `crate::common`; prune the unused imports `--no-run --message-format=short` lists. `spawn_env_hygiene` scans test text, string literals included: never spell a bare binary spawn in a new test file, and run that suite before pushing.
- Source-scan guards: one-sided (fail on new files only) and normalize `\r\n` (Windows CI checks out CRLF).
- `toml_edit` parse: ~81 µs per crates.io `Cargo.toml` vs 0.5 µs for a line scanner; disclose it when a hot crawl path moves to it.
- Equivalence goldens (`tests/equivalence/*.golden`, bless with `SOCKET_PATCH_BLESS_GOLDEN=1`) include mixed-ending inputs: prove only mixed cases move before re-blessing a line-ending change.
- Upstream gem `restore_manifest` pins CRLF output for a CRLF Gemfile with an LF block; migrate it only together with the forward Gemfile writer in `redirect/mod.rs`.
- Overlap check: fetch `/pulls/<n>/files` for every open PR, match exact paths; `comm -23` of `git ls-files` against that set lists the free files.
- Deleting a refactor oracle: refactor the kept code under the oracle, pin its outputs on odd inputs, then delete it (#1103).
- The sandbox runs as root, so 4 core lib tests fail on main and on branches alike: `copy_tree::relax_loop_must_not_traverse_symlinked_root`, `vlt_heal::an_unremovable_hidden_lock_keeps_every_store_entry`, `pypi_poetry::wire_write_failure_maps_error_and_leaves_lock_untouched`, `pypi_requirements::wire_failure_rolls_back_already_written_files`.
- `redirect/pipenv.rs`, `vendor/pypi.rs` and `vendor/lock_inventory/vlt.rs` aren't rustfmt-clean on main: format only your own hunks there. Check `rustfmt --check` on the `main` copy before formatting a whole file.
- `lock_inventory/mod.rs` `architecture_tests` forbid `hosted_patch_uuid*` in a format file's model section. Origin-policy helpers go after the `// ── registry view ──` marker.
- 2026-10-08: ~40 refactor issues were closed `not_planned` into trackers ("Consolidated work"); that is scheduling, not rejection. Claim/`Fixes` the item's issue only if still open, else reference the tracker.
- Ledger and branch pushes need verified signatures (org ruleset). Commit with the session's default git identity; overriding `user.email` (e.g. to a bot address) makes GitHub reject the signature.
- Maintainer steering (2026-10-02, on #569 and #571): don't add size caps on trusted upstream data; stream instead of buffering.
- `cargo clippy --all-targets` already fails on `main` (old test lints); CI gates `cargo clippy --workspace --all-features -- -D warnings`.
- `cargo test -p socket-patch-cli --test repair` has 2 root-only failures (`repair_exits_zero_and_stays_quiet_when_lock_file_unremovable`, `repair_cleanup_failure_is_reported_in_json_and_silent_modes`). They chmod a directory read-only.
- CLI test targets: 145+ files spawn `socket-patch` with a bare `Command::new(binary())`; `tests/spawn_env_hygiene.rs` keeps `PENDING_RAW_SPAWNS` / `PENDING_SCRUB_COPIES` allowlists that fail on new **and** stale entries — drop a file from the list when you migrate it.
- Probe spawns go through `utils::process::output_within` since #886 (blocking; async callers wrap it in `utils::fs::run_blocking`). It nulls stderr; don't add a new `tokio::time::timeout` + `kill_on_drop` site.
