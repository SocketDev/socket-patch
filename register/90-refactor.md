### Refactor routine (`refactor`, hourly, highest leverage first)
_Last updated 2026-10-06T19:58Z · main @ 9c43dfc_

**In flight:**
- [#876](https://github.com/SocketDev/socket-patch/pull/876): registry clients (`build_registry_client`, Maven `fetch_registry_bytes`) built through one `registry_client_builder` under `ApiTimeouts`; `registry_fetch::download` onto `read_capped`. Also ports the base-red digest-ratchet fix for #646's JVM files. Issue #872 (C49). `ready`.
- [#886](https://github.com/SocketDev/socket-patch/pull/886): one `utils::process::output_within` bounded spawn; `run_resolved` (every crawler probe) runs under `PROBE_TIMEOUT` (10 s), and the pipenv, hatch and self-update `sanity_exec` timeout blocks are deleted. Issue #845 slice 1 (C48). `ready`. Remaining: `vendor/npm_dir.rs` git exchange (wait for #837), async `CommandRunner`, `architecture_tests` guard.
- [#889](https://github.com/SocketDev/socket-patch/pull/889): vendor-service retries read `Retry-After` through `api::retry::parse_retry_after` (HTTP-date now honored, still capped at `max_delay`) and draw jitter from the seeded `api::retry::jitter_sample` on the client's `RetryHooks`; `client.rs`'s `retry_after_secs` and `jitter_sample()` deleted. Issue #677 (C15 child 1). `ready`.

**Merged:**
- [#870](https://github.com/SocketDev/socket-patch/pull/870): `go_mod_edit::module_path` on the shared directive walker reads the go.mod `module` directive for VEX `--product` (block form fixed); `go_crawler::parse_go_mod_module` and `product.rs`'s scanner deleted. Issue #781 (E19 Go half). Merged 2026-10-05 as `c644ab0`. Production ≈ +22 / −64, tests ≈ +65 / −117.
- [#865](https://github.com/SocketDev/socket-patch/pull/865): `utils::digest` compute helpers; 4 private copies and the inline digest sites in 14 files deleted; ratchet for the 6 slice-2 files. Issue #706 slice 1 (C17). Merged 2026-10-05 as `1714299`. Production ≈ +45 / −105, tests ≈ +145 / −11.
- [#858](https://github.com/SocketDev/socket-patch/pull/858): one blocking `stage_and_rename_blocking` core with a private `WriteOpts` policy behind the six `utils::fs` writers; `atomic_write_sync`'s copy and `create_stage`/`commit_stage` deleted; one `stage_path` builds `.socket-stage-` and `.socket-dl-` names. Issue #728 (C21). Production +171 / −168, tests ≈ +85 / −12. Merged 2026-10-05 as `ee8ebf4`.
- [#850](https://github.com/SocketDev/socket-patch/pull/850): one hermetic `common/hermetic.rs` builder for CLI test children; 8 `scrub_socket_env` copies deleted, 7 unscrubbed spawners made hermetic, `spawn_env_hygiene` ratchet. Issue #823 slice 1 (C30, C47). Merged 2026-10-05 as `99f61d2`. Test-only: +745 / −322.
- Earlier: [#607](https://github.com/SocketDev/socket-patch/pull/607) (#571, C37, streamed blob/diff downloads), [#602](https://github.com/SocketDev/socket-patch/pull/602) (#592, E06), [#574](https://github.com/SocketDev/socket-patch/pull/574) (#562, E02/E03), [#572](https://github.com/SocketDev/socket-patch/pull/572) (#563, E04/E49), [#581](https://github.com/SocketDev/socket-patch/pull/581) (#570, C02).

**Queue** (B bugs closed, U unblocks, D duplication removed, R risk; score = 3B + 2U + D − risk):

| # | Candidate | B | U | D | R | Score | Note |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| 1 | #922 (E22, child 1 of #920): one `VendorEntry::npm` constructor for the 7 npm-family ledger tails | 0 | 1 | ≈7 | L | ≈9 | skipped: drivers changed by #657, #873, #888, #909 |
| 2 | #931 (C52, child 1 of #930): one manifest-read error mapper (`manifest_invalid`/`manifest_unreadable`) for every command | 1 | 1 | ≈2.5 | M | ≈5.5 | skipped: `commands/vendor.rs` changed by #690, #776, #825, #837, #877 |
| 3 | #773 (C44): one `Ecosystem::from_cli_name` for flag, env, socket.yml, vendor | 1 | 0 | ≈2 | L | ≈5 | skipped: `commands/vendor.rs` changed by #690, #776, #825, #837, #877 |
| 4 | #856 (E62, child 1 of #855): VEX npm aliases through the core resolver | 1 | 1 | ≈1.8 | M | ≈5 | skipped: `vex_consumed.rs` changed by #690 |
| 5 | #883 (E39): `canonicalize_pypi_name` + `pep508_name` into one PyPI name module | 0 | 1 | ≈3 | L | ≈5 | skipped: 13 files changed by open PRs |

Re-ranked 2026-10-06T19:58Z: main, discussion steering and queue unchanged since 19:05Z. #960 (E21, child 1 of tracking #959): one core `VendorBackend` enum for CLI revert/in-use dispatch, B0 U1 D≈2 R L ≈4, skipped: `commands/vendor.rs` changed by #690, #776, #825, #837, #877. New bug #958 (hatch.toml unread by the vendored-reference scan) shares #832's root cause; left to the fixer. #893 (≈4, `cleanup_blobs.rs`) is still the best eligible; then #871 after #889, then #705. 3 of 3 slots used (#876, #886, #889 `ready` and approved, no review questions). Decisions: #648, #704, #792, #808, #615; C07.

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
- `#[cfg(test)] mod tests` blocks often lean on the parent's `use sha2::…` through `use super::*`: removing a production import breaks the test build (`cargo test --lib --no-run`), not `cargo build`. Add the import to the test module.
- Bun backtest `native (macos-latest, 1.3.10)` cell `preexisting-manifest vendored` is flaky (failed once on #870, passed on re-run).
- Bugbot may review the PR's start commit when a draft opens; check the review's commit SHA and re-trigger on the real head.
- go.mod's lexer treats `//` as a comment anywhere, so `module a//b` declares `a`: don't expect `//` inside a token to be rejected.
- #646 merged inline digests after the `utils::digest` ratchet, so `production_digests_go_through_the_helpers` failed on `main` @ `a1d4260`; #876 carries the fix (`gradle_cache.rs` added to `PENDING_INLINE_DIGESTS` because #690 edits it). Drop it from the list when #706 slice 2 migrates it.
- A process-global `reqwest::Client` (`LazyLock`) is unsafe in core tests: pooled connections stay bound to the tokio runtime that opened them, and each `#[tokio::test]` has its own runtime. Build per call through a shared builder instead.
- Probe spawns go through `utils::process::output_within` since #886 (blocking; async callers wrap it in `utils::fs::run_blocking`). It nulls stderr; don't add a new `tokio::time::timeout` + `kill_on_drop` site.
- Vendor-service retries share `ApiClient`'s `RetryHooks` (clock, jitter seed, sleep) since #889: tests inject a recording sleep through `with_api_retry(ApiRetryPolicy::default(), hooks)` instead of timing real sleeps.
