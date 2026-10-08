### Refactor routine (`refactor`, hourly, highest leverage first)
_Last updated 2026-10-08T15:16Z · main @ 823810a_

**In flight:**
- [#1141](https://github.com/SocketDev/socket-patch/pull/1141): deletes the dead hosted-vlt redirect-ledger helpers (`vlt::{edit_dep_id, lock_node_ids, claims_key, carried_pin_*}`, `vlt_heal::ledger_targets`), gates `jvm::apply::read_project_file` to tests, and pins `lock_targets` with a unit test. Issue #782 (E58, slice 1). +13 / −194 production, +36 / −150 tests. `state: ready`.
- [#1126](https://github.com/SocketDev/socket-patch/pull/1126): 7 inline `starts_with("pkg:<type>/")` checks (Bun/vlt preflights, PyPI fuzzy match, Coursier sidecar, VEX verify) through `Ecosystem::from_purl`, plus an equivalence table test and a one-sided guard listing 16 pending files. Issue #747 (C20, slice 1). +18 / −9 production, +155 tests. `state: ready`.
- [#1124](https://github.com/SocketDev/socket-patch/pull/1124): 72 CLI test files use `tests/common`'s `binary()` and `git_sha256` instead of private copies (52 + 45 deleted), plus a one-sided `cli/shared_helper_copies.rs` ratchet. Issue #824 (C30, children 2–3; 68 files in open PRs and the three `vlt_*_common` modules remain). Test-only, +450 / −583. `state: ready`.
- [#1121](https://github.com/SocketDev/socket-patch/pull/1121): ledger recovery reads the recorded uv/pdm `[[package]]` unit through `utils::python_lock::package_artifacts` and picks wheels through the shared `pypi_distribution::is_portable_wheel_url`; deletes recovery's string scanner and suffix rule. Issue #1079 (E89, slice 1; the `lock_inventory/pypi.rs` suffix checks and the rename remain, in files #1058/#1009/#1045/#768 change). `state: ready`.
- [#1117](https://github.com/SocketDev/socket-patch/pull/1117): 8 inline BOM strips (requirements lexers, manifest, hosted npm manifest, Gradle DSL, socket.yml, CLI Pipenv remedy) onto `formats::text`, plus `strip_bom_bytes` and a one-sided guard with a 26-file pending list. Issue #905 (E64, step 3 slice 1). Only change: a double-BOM Pipfile.lock is unparseable in the stale-install remedy. `state: ready`.
- [#1110](https://github.com/SocketDev/socket-patch/pull/1110): one `formats::cargo::manifest` reader (`toml_edit`, `[package]` else `[project]`) for the crawler, VEX product and `cargo_tag`; deletes the crawler's line scanner. Issue #693 (E15, slice 1; `vendor/cargo.rs` `path_crate_version`/`declared_cargo_minor` and #651 remain, blocked by #1026/#1039/#1041/#1043/#1050). Parse cost 0.5 µs → 81 µs per manifest, disclosed. `state: ready`.
- [#1108](https://github.com/SocketDev/socket-patch/pull/1108): one `utils::line_endings::terminator` (CRLF → CRLF, mixed → majority, else LF) for 7 inserted-line sites: gem lock converge, composer/requirements restore, Pipfile.lock entry formatter, PEP 723 writer, go.mod append/re-join. Issue #815 (E16, slice 1; `detect_eol`, `pypi_uv::newline_of`, Maven ×2, `redirect/mod.rs`, the `crlf` flags and upstream gem's Gemfile restore remain, all in open-PR files). Re-blesses the go/uv equivalence goldens (mixed inputs only). `state: ready`.
- [#1106](https://github.com/SocketDev/socket-patch/pull/1106): the macOS PDM site probe runs through `utils::process::output_within`; a guard test rejects new production `kill_on_drop` spawns (pending: `vendor/npm_dir.rs`). Issue #1067 (C48, slice: `pdm_site`; the `npm_dir` git exchange remains, blocked on #1026). `state: ready`, handed to the burn-down.
- [#1103](https://github.com/SocketDev/socket-patch/pull/1103): `go.sum` edits through `GoSumEditor` only; deletes the oracle-only free functions and names the key rule once. Issue #631 (E52, slice: steps 2–3; the move to `formats/golang/sum.rs` remains). `state: ready`, handed to the burn-down.
- Maintainer drafts (decided issues): #1021 (#615), #1027 (#704), #1030 (#808), #1031 (#966), #1036 (#973), #1041 (#648), #1049 (#792), #1051 (#580).
- October 7 campaign: open #1026, #1034, #1043, #1058; the rest merged (#1039 last; rows in the auditors' registers).

**Merged:**
- [#1015](https://github.com/SocketDev/socket-patch/pull/1015): vendored-reference scan reads every `VENDORED` row. Issues #832, #958 (E61). `8e521f9` (+308 / −41). Left: dead `eco == "maven2"` arm in `commands/vendor.rs`.
- Earlier: #889, #876, #886, #870, #865, #858, #850, #607, #602, #597, #587, #583, #581, #574, #572 (see `entries/refactor/`).

**Queue** (B bugs closed, U unblocks, D duplication removed, R risk; score = 3B + 2U + 2D + S − risk). Since the 2026-10-08 backlog review, standalone refactor issues are closed as `not_planned` and kept as checklist items of their tracker; rank the tracker's next unchecked item.

| # | Candidate | B | U | D | R | Score | Note |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| 1 | #989 item (was #990): one `vendor::revert::finish` for the 12 copied finish blocks | 0 | 1 | ≈12 | L | ≈26 | skipped: all 12 backend files changed by open PRs |
| 2 | #594 / #717 (E10): nuget.config and pom.xml edits through the `formats::nuget` / `formats::maven` tokenizers | 3 | 1 | ≈6 | M | ≈21 | skipped: hosted halves in `redirect/mod.rs`; a restore-only slice would make restore disagree with the writer |
| 3 | #914 (C51): stream agent-mode jar members through one zip-member hasher | 0 | 0 | 1 | L | ≈5 (S 3) | skipped: `patch/jvm_jar.rs` is in #1041 (one test hunk) |
| 4 | #782 slice 1 (E58): dead hosted-vlt ledger helpers | 0 | 0 | ≈1 | L | ≈2 | **taken: #1141** |
| 5 | #824 item 4: core's xorshift copies onto `test_rng` | 0 | 0 | 2 | L | ≈4 | test-only; `crawlers/npm_crawler/oracle.rs` (third copy) is in an open PR |

Re-ranked 2026-10-08T15:05Z at `823810a` against 31 open PRs (551 files; 20 `arch-refactor/*` or `agent/fix-*`). #706's remaining digest slice is deferred by the maintainer's backlog review ("Defer the remaining consolidation"), so it is not ranked. Also blocked by open-PR files: #727/#630 items, #705, #913, #675, #780, #936, #1128, #931/#998/#1063/#1123 (every `commands/*` manifest reader).

**Notes:**
- The skip rule names only `arch-refactor/*` and `agent/fix-*` PRs; `arch-fix/*`, `ci*` and `ci-janitor/*` files are not blockers by the letter, but check their hunks before touching the same lines.
- A maintainer-closed issue whose backlog note says "Defer" (e.g. #706) is steering: don't rank it until reopened.
- E35's crawler oracles can't become `golden.rs` digests: their randomized trees (symlinks, modes, case collisions) differ by OS and uid. Keep them until a crawler can be checked without one.
- Test-helper migrations (#824): directory binaries import via `crate::common`; prune the unused imports `--no-run --message-format=short` lists. `spawn_env_hygiene` scans test text, string literals included: never spell a bare binary spawn in a new test file, and run that suite before pushing.
- Source-scan guards: make new ones one-sided (fail on new files only), so a PR migrating a pending file can't turn `main` red.
- `toml_edit` parse: ~81 µs per crates.io `Cargo.toml` vs 0.5 µs for a line scanner; disclose it when a hot crawl path moves to it.
- Equivalence goldens (`tests/equivalence/*.golden`, bless with `SOCKET_PATCH_BLESS_GOLDEN=1`) include mixed-ending inputs: prove only mixed cases move before re-blessing a line-ending change.
- Upstream gem `restore_manifest` pins CRLF output for a CRLF Gemfile with an LF block; migrate it only together with the forward Gemfile writer in `redirect/mod.rs`.
- Overlap check: fetch `/pulls/<n>/files` for every open PR, match exact paths; `comm -23` of `git ls-files` against that set lists the free files.
- Deleting a refactor oracle: refactor the kept code under the oracle, pin its outputs on odd inputs, then delete it (#1103).
- The sandbox runs as root, so 4 core lib tests fail on main and on branches alike: `copy_tree::relax_loop_must_not_traverse_symlinked_root`, `vlt_heal::an_unremovable_hidden_lock_keeps_every_store_entry`, `pypi_poetry::wire_write_failure_maps_error_and_leaves_lock_untouched`, `pypi_requirements::wire_failure_rolls_back_already_written_files`.
- `redirect/pipenv.rs`, `vendor/pypi.rs` and `vendor/lock_inventory/vlt.rs` aren't rustfmt-clean on main: format only your own hunks there. Check `rustfmt --check` on the `main` copy before formatting a whole file.
- `lock_inventory/mod.rs` `architecture_tests` forbid `hosted_patch_uuid*` in a format file's model section. Origin-policy helpers go after the `// ── registry view ──` marker.
- 2026-10-08: ~40 refactor issues were closed `not_planned` into trackers ("Consolidated work"); that is scheduling, not rejection. Claim/`Fixes` the item's issue only if still open, else reference the tracker.
- `redirect/mod.rs` is a hot file (4 open PRs); prefer other files.
- Ledger and branch pushes need verified signatures (org ruleset). Commit with the session's default git identity; overriding `user.email` (e.g. to a bot address) makes GitHub reject the signature.
- Maintainer steering (2026-10-02, on #569 and #571): don't add size caps on trusted upstream data; stream instead of buffering.
- `cargo clippy --all-targets` already fails on `main` (old test lints); CI gates `cargo clippy --workspace --all-features -- -D warnings`.
- Windows CI checks out CRLF: source-scan tests must normalize `\r\n` first (#602 failed this way).
- `cargo test -p socket-patch-cli --test repair` has 2 root-only failures (`repair_exits_zero_and_stays_quiet_when_lock_file_unremovable`, `repair_cleanup_failure_is_reported_in_json_and_silent_modes`). They chmod a directory read-only.
- CLI test targets: 145+ files spawn `socket-patch` with a bare `Command::new(binary())`; `tests/spawn_env_hygiene.rs` keeps `PENDING_RAW_SPAWNS` / `PENDING_SCRUB_COPIES` allowlists that fail on new **and** stale entries — drop a file from the list when you migrate it.
- Probe spawns go through `utils::process::output_within` since #886 (blocking; async callers wrap it in `utils::fs::run_blocking`). It nulls stderr; don't add a new `tokio::time::timeout` + `kill_on_drop` site.
