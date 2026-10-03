### Refactor routine (`refactor`, hourly, highest leverage first)
_Last updated 2026-10-03T11:00Z · main @ 045d7ec_

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
| 1 | #663 (E07): one addressed package-lock entry walk for inventory, vendored, hosted and restore; delete `entry_name` and both JSON-pointer escapes | 0 | 1 | 4.5 | M | 4.5 | skipped: `npm_lock.rs`/`lock_inventory/npm.rs` changed by open PRs #660 and #589, `redirect/mod.rs`/`upstream/npm.rs` by #657 and #597 |
| 2 | #568 (C03): takeover honors `kept_artifact` via `vendored_backend`'s revert step | 1 | 0 | 1 | L | 4 | skipped: `scan/hosted.rs` changed by open PR #598 |
| 3 | #593 (E50): one version-aware `packages.lock.json` walker | 1 | 0 | 3 | M | 4 | skipped: `redirect/mod.rs` changed by open PR #597; bughunt #623 (BOM) and #624 may share this root cause, re-score B once #597 lands |
| 4 | #630 (E37): one `path_safety::is_safe_name_version` + Maven guard in utils; delete `is_safe_{cargo,gem,nuget}_coordinate` and `composer_crawler::normalize_version` | 0 | 0 | 4 | L | 4 | skipped: `cargo_crawler.rs`/`nuget_crawler.rs` changed by open PR #602 |
| 5 | #662 (E53): vendored pnpm writes the root `package.json` through `JsonLayout` + `parse_json_manifest` | 1 | 0 | 1 | L | 4 | at capacity; not yet claimed |

At capacity (3 open, all ready, all reviewed "ready to merge") on 2026-10-03T01:05Z; re-ranked with the new issues #628–#631, no new work started (blockers #597, #598, #602, #607, #610 still open). Next: #631 (E52, go.sum oracle delete + move to `formats/golang`), score 3.5 (D3.5 R L), skipped while #597 changes `redirect/mod.rs`. Dropped C07 from the queue: needs an owner decision on the fallback route. Taken: #571 (C37) in #607, score 2 (B1 D1 R M). Re-ranked 2026-10-03T04:00Z with #647 (C09/C39) and #649 (C08, hygiene, score ≈1); still at capacity, no new work. #614 (C38, score 4) drops to sixth. #648 is a decision. Re-ranked 2026-10-03T05:58Z: no new `arch-audit`/`refactor` issues, nothing merged, blockers still open; queue unchanged. Re-ranked 2026-10-03T07:05Z with #662 (E53) and #663 (E07): still at capacity, nothing merged. #628/#629 left the queue because fixer PR #657 now references them. #647 (C09/C39, score 4) drops to sixth. Re-ranked 2026-10-03T08:58Z: no new issues, nothing merged, no steering, all blockers still open; queue unchanged. Re-ranked 2026-10-03T10:05Z with #675 (C16, one `api::batch` chunker; D ≈2.5 R L, score ≈2.5; skipped: `api/client.rs` changed by #607 and #610), #676 (C15 tracking; next child #677: vendor `Retry-After`/jitter onto `api::retry`, D 2 R L, score 2, same `client.rs` skip) and #678 (C40, docs + env-var guard test, score ≈0): none enters the top five; still at capacity, nothing merged, no steering. Re-ranked 2026-10-03T11:00Z: no new `arch-audit`/`refactor` issues (#679 and #681 are bughunt bugs outside the queue), nothing merged, no steering; queue unchanged. Checked and set aside: E13 (`poetry_lock`/`pdm_lock`): the fragment walkers differ in real format handling, not just one shape check.

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
