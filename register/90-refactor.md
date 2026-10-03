### Refactor routine (`refactor`, hourly, highest leverage first)
_Last updated 2026-10-03T23:58Z · main @ 045d7ec_

**In flight:**
- [#574](https://github.com/SocketDev/socket-patch/pull/574): one vlt `registry_base` following vlt's DepID hydration. Issues #562 (E02, E03). State: ready (Ready for review). It awaits human approval.
- [#602](https://github.com/SocketDev/socket-patch/pull/602): crawler project-tree reads go through `utils::fs::read_regular_*`, plus a `crawlers::architecture_tests` guard against bare reads. Issue #592 (E06). State: ready, handed to the PR burn-down.
- [#607](https://github.com/SocketDev/socket-patch/pull/607): blob and diff downloads stream to disk through `BinaryBody`; one `download_entries` loop replaces the blob and diff copies. Issue #571 (C37). State: ready, handed to the PR burn-down (CI green, 338 checks; Bugbot clean on ae928ae).

**Merged:**
- [#572](https://github.com/SocketDev/socket-patch/pull/572): one hosted-PyPI-URL recognizer for hosted and vendored Pipenv. Issues #563 (E04, E49). Production +31 / −48, tests +174 / −37 (approx.).
- [#581](https://github.com/SocketDev/socket-patch/pull/581): one `ApiTimeouts` policy (10 s connect, 60 s idle read) on both `ApiClient` reqwest clients. Issue #570 (C02).

**Queue** (B bugs closed, U unblocks, D duplication removed, R risk; score = 3B + 2U + D − risk):

| # | Candidate | B | U | D | R | Score | Note |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| 1 | #717 (E10 slice of #715): hosted Maven rewrite and upstream restore locate edits through `formats::maven` element queries; delete `MAVEN_DEPENDENCY_BLOCK_RE`, `maven_tag_inner_range` and restore's regexes | 3 | 1 | 4 | M | 13 | skipped: `redirect/mod.rs` changed by open PRs #597, #637, #646, #657, #669, #690, #708 and #710; fixes #259, #342 (hosted rows), #683 (exclusions half) |
| 2 | #706 (C17): one `utils::digest` compute API (`sha256_hex`, `sha1_hex`, `sha512_sri`); delete the jvm, ledger_snapshots, group_commit, maven_repo, npm_pack and bun_lock copies | 0 | 1 | 5 | L | 7 | skipped: `jvm/mod.rs`, `maven_repo.rs`, `group_commit.rs` changed by open PRs #690 and #646, `bun_lock.rs` by #689; unblocks #707 being fixed in one place |
| 3 | #693 (E15): one `toml_edit` `Cargo.toml` package reader for crawler, VEX, `cargo_tag` and `path_crate_version`; delete the crawler's line scanner | 1 | 0 | 3 | L | 6 | skipped: `cargo_crawler.rs` changed by open PR #602, `vendor/cargo.rs` by #598 |
| 4 | #728 (C21): one `utils::fs` stage-and-rename core with policy flags; delete the six-writer spread and the blocking `atomic_write_sync` copy | 0 | 1 | 3.5 | L | 5.5 | eligible once capacity frees (`utils/fs.rs` touched by no open PR); leave `write_cache_entry_atomic` for after #607; makes #726's writer fix one call |
| 5 | #707 (C41): one case-insensitive hash comparison for agent-mode apply/rollback and vendored verify | 1 | 0 | 2 | L | 5 | skipped: `patch/apply.rs`/`patch/rollback.rs` changed by open PRs #634, #646 and #690; simpler after #706 |

At capacity (3 open, all ready, all reviewed "ready to merge") on 2026-10-03T01:05Z; re-ranked with the new issues #628–#631, no new work started (blockers #597, #598, #602, #607, #610 still open). Next: #631 (E52, go.sum oracle delete + move to `formats/golang`), score 3.5 (D3.5 R L), skipped while #597 changes `redirect/mod.rs`. Dropped C07 from the queue: needs an owner decision on the fallback route. Taken: #571 (C37) in #607, score 2 (B1 D1 R M). Re-ranked 2026-10-03T04:00Z with #647 (C09/C39) and #649 (C08, hygiene, score ≈1); still at capacity, no new work. #614 (C38, score 4) drops to sixth. #648 is a decision. Re-ranked hourly 2026-10-03T05:58Z–17:56Z: still at capacity (#574, #602, #607 ready, awaiting human merge), nothing merged, no steering. Entered: #662 (E53), #663 (E07), #693 (E15), #706 (C17, first), #707 (C41, third). Left: #628/#629 (fixer PR #657), #694/#695 (fixer PR #703). Outside the top five: #593 and #614 (score 4), #630, #662, #705 (C18, score 2), #675–#678 (≤2.5). Decisions: #648, #704. Bughunt #685 may share #593's XML-walker root cause. Every queue blocker (#589, #597, #598, #602, #634, #646, #657, #660, #689, #690) still open. 2026-10-03T19:05Z: still at capacity; entered #717 (E10 Maven slice, first); #568 (C03) drops to sixth. #716 (E55, score 4) skipped: `maven_repo.rs`/`jvm/` changed by #646, #690. 19:58Z–20:57Z: still at capacity, nothing merged, no steering; no new `arch-audit`/`refactor` issues (#713, #714, #718, #720, #721, #723 are fixer/bughunt bugs); queue unchanged, every blocker still open. 21:56Z: still at capacity, nothing merged, no steering. Entered: #728 (C21, fourth). Left: #663 (E07, 4.5, sixth). Outside the top five: #727 (C19, env helpers, D≈4 R M, score ≈2–4, eligible), #726 (C42 bug, B1 D1 R L, score 4; skipped: `get.rs` changed by #646). 22:56Z: still at capacity, nothing merged, no steering, no new `arch-audit`/`refactor` issues; queue unchanged, every blocker still open (new fixer PRs #724, #730). 23:56Z: same; new fixer PR #731, no new `arch-audit`/`refactor` issues.

**Notes:**
- The sandbox runs as root, so 4 core lib tests fail on main and on branches alike: `copy_tree::relax_loop_must_not_traverse_symlinked_root`, `vlt_heal::an_unremovable_hidden_lock_keeps_every_store_entry`, `pypi_poetry::wire_write_failure_maps_error_and_leaves_lock_untouched`, `pypi_requirements::wire_failure_rolls_back_already_written_files`.
- `redirect/pipenv.rs`, `vendor/pypi.rs` and `vendor/lock_inventory/vlt.rs` aren't rustfmt-clean on main: format only your own hunks there. Check `rustfmt --check` on the `main` copy before formatting a whole file.
- `lock_inventory/mod.rs` `architecture_tests` forbid `hosted_patch_uuid*` in a format file's model section. Origin-policy helpers go after the `// ── registry view ──` marker.
- `redirect/mod.rs` is a hot file (4 open PRs). Prefer candidates outside it until those land.
- `CLI_CONTRACT.md` lives at `crates/socket-patch-cli/CLI_CONTRACT.md`.
- vlt registry semantics: `hydrate` and `Spec` memoize by id/spec and ignore options, so run each vlt case in a fresh `node` process. `scoped-registries[scope]` wins for every segment; `~~` splits to `npm`. Cite `@vltpkg/dep-id` `hydrateTuple` and `@vltpkg/spec` (`registry ?? registries[default-registry-alias]`); the packages download from npm.
- Runs overlap: two runs started within minutes of each other on 2026-10-02. Claims and the status block kept them apart; `git pull --rebase` the ledger before writing.
- Maintainer steering (2026-10-02, on #569 and #571): don't add size caps on trusted upstream data; stream instead of buffering.
- reqwest 0.12 `ClientBuilder::read_timeout` is an idle bound (resets per chunk) and also bounds the wait for response headers; `RequestBuilder::timeout` is total.
- `rustfmt <file>` also formats that file's out-of-line child modules (formatting `crawlers/mod.rs` rewrote `python_crawler.rs`). Check `git diff --stat` after formatting and restore any file you didn't mean to touch.
- `cargo clippy --all-targets` (and `-p socket-patch-core --tests`) already fails on `main` from older lints in test code. CI's gate is `cargo clippy --workspace --all-features -- -D warnings`.
- Windows CI checks out with CRLF. A test that scans source text for `\n`-joined markers must normalize `\r\n` first: #602 failed `test (windows-latest)` this way.
- reqwest 0.12 `Response::chunk()` streams without the `stream` feature. `BinaryBody::chunk` returns `impl AsRef<[u8]>`, so core needs no direct `bytes` dependency.
- `cargo test -p socket-patch-cli --test repair` has 2 root-only failures (`repair_exits_zero_and_stays_quiet_when_lock_file_unremovable`, `repair_cleanup_failure_is_reported_in_json_and_silent_modes`). They chmod a directory read-only.
- Windows: `DirEntry::metadata().len()` reports a stale (cached) size for a file another handle is still writing. Size live files with `std::fs::metadata(path)` in tests.
