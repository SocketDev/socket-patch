### Refactor routine (`refactor`, hourly, highest leverage first)
_Last updated 2026-10-08T10:20Z · main @ b96a785_

**In flight:**
- [#1124](https://github.com/SocketDev/socket-patch/pull/1124): 72 CLI test files use `tests/common`'s `binary()` and `git_sha256` instead of private copies (52 + 45 deleted), plus a one-sided `cli/shared_helper_copies.rs` ratchet. Issue #824 (C30, children 2–3; 68 files in open PRs and the three `vlt_*_common` modules remain). Test-only, +450 / −583. `state: ready`.
- [#1121](https://github.com/SocketDev/socket-patch/pull/1121): ledger recovery reads the recorded uv/pdm `[[package]]` unit through `utils::python_lock::package_artifacts` and picks wheels through the shared `pypi_distribution::is_portable_wheel_url`; deletes recovery's string scanner and suffix rule. Issue #1079 (E89, slice 1; the `lock_inventory/pypi.rs` suffix checks and the rename remain, in files #1058/#1009/#1045/#768 change). `state: ready`.
- [#1117](https://github.com/SocketDev/socket-patch/pull/1117): 8 inline BOM strips (requirements lexers, manifest, hosted npm manifest, Gradle DSL, socket.yml, CLI Pipenv remedy) onto `formats::text`, plus `strip_bom_bytes` and a one-sided guard with a 26-file pending list. Issue #905 (E64, step 3 slice 1). Only change: a double-BOM Pipfile.lock is unparseable in the stale-install remedy. `state: ready`.
- [#1110](https://github.com/SocketDev/socket-patch/pull/1110): one `formats::cargo::manifest` reader (`toml_edit`, `[package]` else `[project]`) for the crawler, VEX product and `cargo_tag`; deletes the crawler's line scanner. Issue #693 (E15, slice 1; `vendor/cargo.rs` `path_crate_version`/`declared_cargo_minor` and #651 remain, blocked by #1026/#1039/#1041/#1043/#1050). Parse cost 0.5 µs → 81 µs per manifest, disclosed. `state: ready`.
- [#1108](https://github.com/SocketDev/socket-patch/pull/1108): one `utils::line_endings::terminator` (CRLF → CRLF, mixed → majority, else LF) for 7 inserted-line sites: gem lock converge, composer/requirements restore, Pipfile.lock entry formatter, PEP 723 writer, go.mod append/re-join. Issue #815 (E16, slice 1; `detect_eol`, `pypi_uv::newline_of`, Maven ×2, `redirect/mod.rs`, the `crlf` flags and upstream gem's Gemfile restore remain, all in open-PR files). Re-blesses the go/uv equivalence goldens (mixed inputs only). `state: ready`.
- [#1106](https://github.com/SocketDev/socket-patch/pull/1106): the macOS PDM site probe runs through `utils::process::output_within`; a guard test rejects new production `kill_on_drop` spawns (pending: `vendor/npm_dir.rs`). Issue #1067 (C48, slice: `pdm_site`; the `npm_dir` git exchange remains, blocked on #1026). `state: ready`, handed to the burn-down.
- [#1103](https://github.com/SocketDev/socket-patch/pull/1103): `go.sum` edits through `GoSumEditor` only; deletes the oracle-only free functions and names the key rule once. Issue #631 (E52, slice: steps 2–3; the move to `formats/golang/sum.rs` remains). `state: ready`, handed to the burn-down.
- Maintainer drafts (decided issues): #1021 (#615), #1027 (#704), #1030 (#808), #1031 (#966), #1036 (#973), #1041 (#648), #1049 (#792), #1051 (#580).
- October 7 campaign (one PR per duplicated-logic seam): open #1026, #1032, #1034, #1039, #1043, #1045, #1050, #1058; merged #1042, #1033, #1038, #1046, #1035, #1044, #1029, #1057 (rows in `register/20-audit-core.md` and `10-audit-ecosystems.md`).

**Merged:**
- [#1015](https://github.com/SocketDev/socket-patch/pull/1015): vendored-reference scan reads every `VENDORED` row. Issues #832, #958 (E61). `8e521f9` (+308 / −41). Left: dead `eco == "maven2"` arm in `commands/vendor.rs`.
- Earlier: #889, #876, #886, #870, #865, #858, #850, #607, #602, #597, #587, #583, #581, #574, #572 (see `entries/refactor/`).

**Queue** (B bugs closed, U unblocks, D duplication removed, R risk; score = 3B + 2U + 2D + S − risk):

| # | Candidate | B | U | D | R | Score | Note |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| 1 | #824 (C30) children 2–3: private `binary()`/`git_sha256` copies onto `tests/common` (free files) | 0 | 1 | ≈97 | L | high | **taken: #1124** (test-only) |
| 2 | #990 (E24, child 1 of #989): one `vendor::revert::finish` for the 12 copied finish blocks | 0 | 1 | ≈12 | L | ≈26 | skipped: all 12 backend files changed by open PRs |
| 3 | #823 (C47) slice 2: the 7 `PENDING_SCRUB_COPIES` files | 0 | 1 | 7 | L | ≈16 | skipped: the 7 files are free, but its two-sided guard `spawn_env_hygiene.rs` is changed by #1049 |
| 4 | #922 (E22): one `VendorEntry::npm` constructor for 7 npm-family ledger tails | 0 | 1 | ≈7 | L | ≈16 | skipped: claimed; drivers changed by #1008 |
| 5 | #706 (C17) slice 2: the 6 `PENDING_INLINE_DIGESTS` files | 0 | 1 | ≈6 | L | ≈14 | skipped: files changed by open PRs |

Re-ranked 2026-10-08T10:00Z at `b96a785` against the 33 open PRs' 515 files. E35's crawler-oracle slice is dropped (see Notes).

**Notes:**
- E35's crawler oracles (composer/go/nuget/python/maven) can't become `golden.rs` digests: their randomized trees use symlinks (no-ops on Windows), permission modes (ignored as root and on Windows) and case-colliding names (folded on macOS). The outputs therefore differ by OS and by uid, and a golden blessed in the root sandbox would fail on non-root Linux CI. Keep the oracles until a crawler can be checked without one.
- Test-helper migrations (#824): `common/mod.rs` is `#![allow(dead_code)]`, so declaring it costs nothing. Directory binaries (`apply/`, `cli/`, …) import through `crate::common`. After deleting copies, build with `--no-run --message-format=short` and prune the unused `sha2`/`PathBuf` imports it lists.
- zizmor (`Audit GitHub Actions`) fails new PR heads on main's `ci.yml:1400` setup-php `# v2` label until #1118 merges; port its one-line fix.
- Lead for `audit-ecosystems` (not filed): hosted `redirect/requirements.rs` keeps its own pip lexer beside `utils::requirements` (quote-aware comment finder vs pip's `COMMENT_RE`).
- Source-scan guards: make new ones one-sided (fail on new files only), so a PR migrating a pending file can't turn `main` red.
- `toml_edit::Document::parse` costs about 81 µs per real crates.io `Cargo.toml` (release), against 0.5 µs for an early-exit line scanner. Disclose it whenever a hot crawl path moves to `toml_edit`.
- Equivalence goldens (`tests/equivalence/*.golden`, bless with `SOCKET_PATCH_BLESS_GOLDEN=1`) run one input in five through a mixed-ending generator: any line-ending rule change moves them; prove only mixed cases move before re-blessing.
- Upstream gem `restore_manifest` pins CRLF output for a CRLF Gemfile with an LF block; migrate it only together with the forward Gemfile writer in `redirect/mod.rs`.
- `crawlers/python_crawler/pdm_site.rs` is macOS-only; to test it here, temporarily make its `mod` line `#[cfg(unix)] #[allow(dead_code)]` and revert.
- Overlap check: fetch `/pulls/<n>/files` for every open PR and match exact paths (suffix matches on `mod.rs`/`client.rs` are false positives); `comm -23` of `git ls-files` against that set lists the free files.
- Deleting a refactor oracle: refactor the kept code under the oracle, pin its outputs on odd inputs, then delete it (#1103).
- The sandbox runs as root, so 4 core lib tests fail on main and on branches alike: `copy_tree::relax_loop_must_not_traverse_symlinked_root`, `vlt_heal::an_unremovable_hidden_lock_keeps_every_store_entry`, `pypi_poetry::wire_write_failure_maps_error_and_leaves_lock_untouched`, `pypi_requirements::wire_failure_rolls_back_already_written_files`.
- `redirect/pipenv.rs`, `vendor/pypi.rs` and `vendor/lock_inventory/vlt.rs` aren't rustfmt-clean on main: format only your own hunks there. Check `rustfmt --check` on the `main` copy before formatting a whole file.
- `lock_inventory/mod.rs` `architecture_tests` forbid `hosted_patch_uuid*` in a format file's model section. Origin-policy helpers go after the `// ── registry view ──` marker.
- `redirect/mod.rs` is a hot file (4 open PRs). Prefer candidates outside it until those land.
- Ledger and branch pushes need verified signatures (org ruleset). Commit with the session's default git identity; overriding `user.email` (e.g. to a bot address) makes GitHub reject the signature.
- Maintainer steering (2026-10-02, on #569 and #571): don't add size caps on trusted upstream data; stream instead of buffering.
- `rustfmt <file>` also formats that file's out-of-line child modules (formatting `crawlers/mod.rs` rewrote `python_crawler.rs`). Check `git diff --stat` after formatting and restore any file you didn't mean to touch.
- `cargo clippy --all-targets` already fails on `main` (old test lints); CI gates `cargo clippy --workspace --all-features -- -D warnings`.
- Windows CI checks out CRLF: source-scan tests must normalize `\r\n` first (#602 failed this way).
- `cargo test -p socket-patch-cli --test repair` has 2 root-only failures (`repair_exits_zero_and_stays_quiet_when_lock_file_unremovable`, `repair_cleanup_failure_is_reported_in_json_and_silent_modes`). They chmod a directory read-only.
- CLI test targets: 145+ files spawn `socket-patch` with a bare `Command::new(binary())`; `tests/spawn_env_hygiene.rs` keeps `PENDING_RAW_SPAWNS` / `PENDING_SCRUB_COPIES` allowlists that fail on new **and** stale entries — drop a file from the list when you migrate it.
- Test modules lean on the parent's imports via `use super::*`: removing a production import can break only `cargo test --lib --no-run`.
- go.mod's lexer treats `//` as a comment anywhere (`module a//b` declares `a`).
- Never share a process-global `reqwest::Client` in core tests (pooled connections bind to one tokio runtime); build per call from a shared builder.
- The sandbox (root) also fails 3 `covgap_commands_vendor` state-write-failure tests (chmod-based) on main and branches alike.
- Probe spawns go through `utils::process::output_within` since #886 (blocking; async callers wrap it in `utils::fs::run_blocking`). It nulls stderr; don't add a new `tokio::time::timeout` + `kill_on_drop` site.
