### Refactor routine (`refactor`, hourly, highest leverage first)
_Last updated 2026-10-05T15:16Z · main @ 0d302dc_

**In flight:**
- [#858](https://github.com/SocketDev/socket-patch/pull/858): one blocking `stage_and_rename_blocking` core with a private `WriteOpts` policy behind the six `utils::fs` writers; `atomic_write_sync`'s copy and `create_stage`/`commit_stage` deleted; one `stage_path` builds `.socket-stage-` and `.socket-dl-` names. Issue #728 (C21). Production +171 / −168, tests ≈ +85 / −12. State: ready, with the PR burn-down.
- [#865](https://github.com/SocketDev/socket-patch/pull/865): `utils::digest` gains `sha256_hex_of`, `sha1_hex_of`, `sha512_base64_of`, `sha512_sri_of`; production digest sites in the 14 files no open PR changes move onto them; `ledger_snapshots::sha256_hex`, `vlt_preflight::sha512_sri`, `nuget_feed::content_hash`, `client::is_valid_sha256_hex` and the npm_pack/bun_lock SRI blocks deleted; a ratchet lists the 6 files left for slice 2. Issue #706 slice 1 (C17).

- [#870](https://github.com/SocketDev/socket-patch/pull/870): `go_mod_edit::module_path` on the shared directive walker reads the go.mod `module` directive for VEX `--product` (fixes the block-form `module ( … )` misread); `go_crawler::parse_go_mod_module` (dead) and `product.rs`'s line scanner deleted. Issue #781 (E19 Go half). Production ≈ +22 / −64, tests ≈ +65 / −117. State: ready, with the PR burn-down.

**Merged:**
- [#850](https://github.com/SocketDev/socket-patch/pull/850): one hermetic `common/hermetic.rs` builder for CLI test children; 8 `scrub_socket_env` copies deleted, 7 unscrubbed spawners made hermetic, `spawn_env_hygiene` ratchet. Issue #823 slice 1 (C30, C47). Merged 2026-10-05 as `99f61d2`. Test-only: +745 / −322.
- [#607](https://github.com/SocketDev/socket-patch/pull/607): blob and diff downloads stream to disk through `BinaryBody`; one `download_entries` loop replaces the blob and diff copies. Issue #571 (C37). Merged 2026-10-05 as `366b155`. Production ≈ +190 / −80 (`blob_fetcher.rs`, `client.rs`), tests ≈ +230.
- [#602](https://github.com/SocketDev/socket-patch/pull/602): crawler project-tree reads go through `utils::fs::read_regular_*`, plus a `crawlers::architecture_tests` guard against bare reads. Issue #592 (E06). Merged 2026-10-05 as `2eae9a0`. Production +4 / −4, tests +241.
- [#574](https://github.com/SocketDev/socket-patch/pull/574): one vlt `registry_base(era, segment, name, options)` for lock inventory and hosted restore, following vlt 1.3.5 DepID hydration (scoped registries, `~~` as `npm`, restore admission matching the rewrite). Issue #562 (E02, E03). Merged 2026-10-05 as `6ca92f5`.
- [#572](https://github.com/SocketDev/socket-patch/pull/572): one hosted-PyPI-URL recognizer for hosted and vendored Pipenv. Issues #563 (E04, E49). Production +31 / −48, tests +174 / −37 (approx.).
- [#581](https://github.com/SocketDev/socket-patch/pull/581): one `ApiTimeouts` policy (10 s connect, 60 s idle read) on both `ApiClient` reqwest clients. Issue #570 (C02).

**Queue** (B bugs closed, U unblocks, D duplication removed, R risk; score = 3B + 2U + D − risk):

| # | Candidate | B | U | D | R | Score | Note |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| 1 | #781 (E19 Go half): go.mod `module` through `go_mod_edit`, delete `parse_go_mod_module` | 0 | 0 | ≈2.2 | L | ≈2 | taken: PR #870 (only top candidate free of open-PR overlap) |
| 2 | #856 (E62, child 1 of #855): VEX npm aliases through the core resolver | 1 | 1 | ≈1.8 | M | ≈5 | skipped: `vex_consumed.rs` changed by 15 open fix PRs, `npm_crawler.rs` by #829 |
| 3 | #773 (C44): one `Ecosystem::from_cli_name` for flag, env, socket.yml, vendor | 1 | 0 | ≈2 | L | ≈5 | skipped: `commands/vendor.rs` changed by #730, #776, #802, #825 |
| 4 | #816 (E38): CLI `PRODUCT_MANIFESTS` copy → `ProductDetection.present` | 1 | 0 | ≈1 | L | ≈4 | skipped: `commands/vex.rs` changed by #684, #700 |
| 5 | #631 slice 1 (E52): delete `go_sum_edit`'s oracle-only free functions (no move) | 0 | 0 | ≈1.5 | L | ≈1.5 | free of overlap if limited to `go_sum_edit.rs`; the move touches `redirect/mod.rs` (7 open PRs) |

Re-ranked 2026-10-05T15:00Z: 3 open (#858, #865, #870). With 30 open fix PRs, most candidates overlap: #823 slice 2, #815, #717, #856 (`vex_consumed.rs`), #773 (`vendor.rs`), #816 (`commands/vex.rs`), #705 and #677 (`api/client.rs`, #865), #693 (`vendor/cargo.rs`, #598), #801 and #782 (`lock_inventory`, `vendor/state.rs`, `redirect/vlt*.rs`), #845 (`npm_crawler.rs`, #829). #726 waits on #858. Decisions (not candidates): #648, #704, #792, #808, #615; C07 needs an owner decision.

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
- `#[cfg(test)] mod tests` blocks often lean on the parent's `use sha2::…` through `use super::*`: removing a production import breaks the test build (`cargo test --lib --no-run`), not `cargo build`. Add the import to the test module.
- go.mod's lexer treats `//` as a comment anywhere, so `module a//b` declares `a`: don't expect `//` inside a token to be rejected.
- `vendor/berry_zip.rs`'s `berry_cache_checksum_10c0` has only test callers, so a helper used only there is dead code in the lib build.
