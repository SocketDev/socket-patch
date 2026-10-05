### Refactor routine (`refactor`, hourly, highest leverage first)
_Last updated 2026-10-05T13:30Z · main @ 4646693_

**In flight:**
- [#850](https://github.com/SocketDev/socket-patch/pull/850): one hermetic `common/hermetic.rs` builder for CLI test children; 8 `scrub_socket_env` copies deleted, 7 unscrubbed spawners made hermetic, `spawn_env_hygiene` ratchet. Issue #823 slice 1 (C30, C47). State: ready, handed to the PR burn-down 2026-10-05T13:16Z (CI green on `efa5cde`, 414 passed / 0 failed, macOS legs queued; Bugbot clean). Carries a port of #851 (the `vex_consumed` alias tests that `main` @ `4646693` broke).
- [#858](https://github.com/SocketDev/socket-patch/pull/858): one blocking `stage_and_rename_blocking` core with a private `WriteOpts` policy behind the six `utils::fs` writers; `atomic_write_sync`'s copy and `create_stage`/`commit_stage` deleted; one `stage_path` builds `.socket-stage-` and `.socket-dl-` names. Issue #728 (C21). Production +171 / −168, tests ≈ +85 / −12. State: ready for review (2026-10-05T13:30Z), CI and Bugbot pending.

**Merged:**
- [#607](https://github.com/SocketDev/socket-patch/pull/607): blob and diff downloads stream to disk through `BinaryBody`; one `download_entries` loop replaces the blob and diff copies. Issue #571 (C37). Merged 2026-10-05 as `366b155`. Production ≈ +190 / −80 (`blob_fetcher.rs`, `client.rs`), tests ≈ +230.
- [#602](https://github.com/SocketDev/socket-patch/pull/602): crawler project-tree reads go through `utils::fs::read_regular_*`, plus a `crawlers::architecture_tests` guard against bare reads. Issue #592 (E06). Merged 2026-10-05 as `2eae9a0`. Production +4 / −4, tests +241.
- [#574](https://github.com/SocketDev/socket-patch/pull/574): one vlt `registry_base(era, segment, name, options)` for lock inventory and hosted restore, following vlt 1.3.5 DepID hydration (scoped registries, `~~` as `npm`, restore admission matching the rewrite). Issue #562 (E02, E03). Merged 2026-10-05 as `6ca92f5`.
- [#572](https://github.com/SocketDev/socket-patch/pull/572): one hosted-PyPI-URL recognizer for hosted and vendored Pipenv. Issues #563 (E04, E49). Production +31 / −48, tests +174 / −37 (approx.).
- [#581](https://github.com/SocketDev/socket-patch/pull/581): one `ApiTimeouts` policy (10 s connect, 60 s idle read) on both `ApiClient` reqwest clients. Issue #570 (C02).

**Queue** (B bugs closed, U unblocks, D duplication removed, R risk; score = 3B + 2U + D − risk):

| # | Candidate | B | U | D | R | Score | Note |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| 1 | #728 (C21): one `utils::fs` stage-and-rename core | 0 | 1 | ≈3 | L | ≈5 | taken: PR #858 |
| 2 | #823 slice 2: the 7 remaining copies + `scan_invariants`, `in_process_npm_multicopy` | 0 | 1 | ≈7 | L | ≈9 | skipped until #850 and #763, #774, #802, #820, #837, #839, #849 land |
| 3 | #815 (E16 child 1 of #814): one `line_endings::terminator` | 0 | 1 | ≈12 | L | ≈14 raw | skipped: 9 of 12 copies in files changed by open PRs (#820, #827, #841, #690, #646, `redirect/mod.rs`) |
| 4 | #717 (E10 slice of #715): `formats::maven` element queries for hosted rewrite + restore | 3 | 1 | 4 | M | 13 raw | skipped: `redirect/mod.rs` changed by open PRs #646, #657, #690 |
| 5 | #726 (C42): `get` writes blobs through the verified cache writer | 1 | 0 | 1 | L | 4 | next after #858 merges (shares `utils/fs.rs`, `blob_fetcher.rs`) |

Re-ranked 2026-10-05T12:56Z: nothing merged since 11:56Z; 1 open (#850), so #728 was the top candidate free of open-PR file overlap. Outside the top five unchanged from the previous run (see the entry for 20261005T115639Z): #706, #693, #707, #747, #773, #794, #746, #663, #757, #631, #809, #816, #832, #835, #834, #845, #844 and smaller. Decisions (not candidates): #648, #704, #792, #808; C07 needs an owner decision.

**Notes:**
- The sandbox runs as root, so 4 core lib tests fail on main and on branches alike: `copy_tree::relax_loop_must_not_traverse_symlinked_root`, `vlt_heal::an_unremovable_hidden_lock_keeps_every_store_entry`, `pypi_poetry::wire_write_failure_maps_error_and_leaves_lock_untouched`, `pypi_requirements::wire_failure_rolls_back_already_written_files`.
- `redirect/pipenv.rs`, `vendor/pypi.rs` and `vendor/lock_inventory/vlt.rs` aren't rustfmt-clean on main: format only your own hunks there. Check `rustfmt --check` on the `main` copy before formatting a whole file.
- `lock_inventory/mod.rs` `architecture_tests` forbid `hosted_patch_uuid*` in a format file's model section. Origin-policy helpers go after the `// ── registry view ──` marker.
- `redirect/mod.rs` is a hot file (4 open PRs). Prefer candidates outside it until those land.
- `CLI_CONTRACT.md` lives at `crates/socket-patch-cli/CLI_CONTRACT.md`.
- vlt registry semantics: `hydrate` and `Spec` memoize by id/spec and ignore options, so run each vlt case in a fresh `node` process. `scoped-registries[scope]` wins for every segment; `~~` splits to `npm`. Cite `@vltpkg/dep-id` `hydrateTuple` and `@vltpkg/spec` (`registry ?? registries[default-registry-alias]`); the packages download from npm.
- Runs overlap: two runs started within minutes of each other on 2026-10-02. Claims and the status block kept them apart; `git pull --rebase` the ledger before writing.
- Ledger and branch pushes need verified signatures (org ruleset). Commit with the session's default git identity; overriding `user.email` (e.g. to a bot address) makes GitHub reject the signature.
- Maintainer steering (2026-10-02, on #569 and #571): don't add size caps on trusted upstream data; stream instead of buffering.
- reqwest 0.12 `ClientBuilder::read_timeout` is an idle bound (resets per chunk) and also bounds the wait for response headers; `RequestBuilder::timeout` is total.
- `rustfmt <file>` also formats that file's out-of-line child modules (formatting `crawlers/mod.rs` rewrote `python_crawler.rs`). Check `git diff --stat` after formatting and restore any file you didn't mean to touch.
- `cargo clippy --all-targets` (and `-p socket-patch-core --tests`) already fails on `main` from older lints in test code. CI's gate is `cargo clippy --workspace --all-features -- -D warnings`.
- Windows CI checks out with CRLF. A test that scans source text for `\n`-joined markers must normalize `\r\n` first: #602 failed `test (windows-latest)` this way.
- reqwest 0.12 `Response::chunk()` streams without the `stream` feature. `BinaryBody::chunk` returns `impl AsRef<[u8]>`, so core needs no direct `bytes` dependency.
- `cargo test -p socket-patch-cli --test repair` has 2 root-only failures (`repair_exits_zero_and_stays_quiet_when_lock_file_unremovable`, `repair_cleanup_failure_is_reported_in_json_and_silent_modes`). They chmod a directory read-only.
- Windows: `DirEntry::metadata().len()` reports a stale (cached) size for a file another handle is still writing. Size live files with `std::fs::metadata(path)` in tests.
- CLI test targets: 145+ files spawn `socket-patch` with a bare `Command::new(binary())`; `tests/spawn_env_hygiene.rs` keeps `PENDING_RAW_SPAWNS` / `PENDING_SCRUB_COPIES` allowlists that fail on new **and** stale entries — drop a file from the list when you migrate it.
- `utils::fs` writers run on the blocking pool via `run_blocking` since #858: a test calling them needs a tokio runtime but either flavor works.
- `cargo test --test repair` under `SOCKET_DRY_RUN=true` is a quick hermeticity probe: on `main` 20 fail, after #850 only the 2 root-only tests.
- `main` @ `4646693` (#605) broke 2 `socket-patch-cli --lib` `vex_consumed` alias tests, so `coverage` fails on every PR until #851 lands; #850 carries the port.
