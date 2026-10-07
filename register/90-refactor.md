### Refactor routine (`refactor`, hourly, highest leverage first)
_Last updated 2026-10-07T15:57Z · main @ c5be5d1_

**In flight:**
- [#1015](https://github.com/SocketDev/socket-patch/pull/1015): the vendored-reference scan (repair, orphan sweeps, `vendor` stranded gate, rollback) reads every `VENDORED` row; the eight `VENDORED_WRITES_UNMARKED` files get the role and the list is deleted; `vendor::path::parse_vendor_reference` accepts the bare uuid dir (NuGet feed, Maven repo). Issues #832, #958 (E61, E67). `ready`. Left: dead `eco == "maven2"` arm in `commands/vendor.rs` (busy file).
- Maintainer drafts on `arch-refactor/*` branches (count toward `MAX_OPEN`): [#1021](https://github.com/SocketDev/socket-patch/pull/1021) (#615, remove `SOCKET_FORCE`), [#1027](https://github.com/SocketDev/socket-patch/pull/1027) (#704, `{code, message}` `--json` errors; C53), [#1030](https://github.com/SocketDev/socket-patch/pull/1030) (#808, `apply.lock` interrupt cleanup), [#1031](https://github.com/SocketDev/socket-patch/pull/1031) (#966, legacy spellings), [#1036](https://github.com/SocketDev/socket-patch/pull/1036) (#973, single-pom Maven planner), [#1041](https://github.com/SocketDev/socket-patch/pull/1041) (#648, resolve org once).

**Merged:**
- [#876](https://github.com/SocketDev/socket-patch/pull/876): registry clients built through one `registry_client_builder` under `ApiTimeouts` (10 s connect, 60 s idle) instead of a 60 s total deadline; `registry_fetch::download` onto `read_capped`. Issue #872 (C49). Merged 2026-10-07 as `e2300cc` (+154 / −33 total).
- [#889](https://github.com/SocketDev/socket-patch/pull/889): vendor-service retries read `Retry-After` through `api::retry::parse_retry_after` (HTTP-date honored) and jitter from `api::retry::jitter_sample` on `RetryHooks`; `client.rs` copies deleted. Issue #677 (C15 child 1). Merged 2026-10-07 as `835601b` (+209 / −38 total). Left: blob/diff fetches still have no retry (#676).
- Earlier: [#886](https://github.com/SocketDev/socket-patch/pull/886) (#845, C48), [#870](https://github.com/SocketDev/socket-patch/pull/870) (#781, E19 Go half), [#865](https://github.com/SocketDev/socket-patch/pull/865) (#706 slice 1, C17), [#858](https://github.com/SocketDev/socket-patch/pull/858) (#728, C21), [#850](https://github.com/SocketDev/socket-patch/pull/850) (#823 slice 1, C30/C47), [#607](https://github.com/SocketDev/socket-patch/pull/607) (#571, C37, streamed blob/diff downloads), [#602](https://github.com/SocketDev/socket-patch/pull/602) (#592, E06), [#574](https://github.com/SocketDev/socket-patch/pull/574) (#562, E02/E03), [#572](https://github.com/SocketDev/socket-patch/pull/572) (#563, E04/E49), [#581](https://github.com/SocketDev/socket-patch/pull/581) (#570, C02).

**Queue** (B bugs closed, U unblocks, D duplication removed, R risk; score = 3B + 2U + D − risk):

| # | Candidate | B | U | D | R | Score | Note |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| 1 | #990 (E24, child 1 of #989): one `vendor::revert::finish` with an explicit `KeepPolicy` for the 12 copied finish blocks | 0 | 1 | ≈12 | L | ≈14 | skipped: most backend files changed by open PRs (#657, #776, #909, #943, #978, #980, #997) |
| 2 | #922 (E22, child 1 of #920): one `VendorEntry::npm` constructor for the 7 npm-family ledger tails | 0 | 1 | ≈7 | L | ≈9 | skipped: claimed (`agent:claimed`); drivers changed by #657, #909 |
| 3 | #998 (C56): one NotFound-only manifest probe for `apply`, `vendor`, `repair`, `remove`, `rollback` (5 `metadata().is_err()` copies) | 1 | 1 | ≈5 | M | ≈8 | skipped: `commands/vendor.rs` changed by #776, #978; pairs with #931 |
| 4 | #931 (C52, child 1 of #930): one manifest-read error mapper (`manifest_invalid`/`manifest_unreadable`) for every command | 1 | 1 | ≈2.5 | M | ≈5.5 | skipped: `commands/vendor.rs` changed by #776, #978 |
| 5 | #773 (C44): one `Ecosystem::from_cli_name` for flag, env, socket.yml, vendor | 1 | 0 | ≈2 | L | ≈5 | skipped: `commands/vendor.rs` changed by #776, #978 |

Re-ranked 2026-10-07T15:57Z: #876 and #889 merged (main @ c5be5d1); audit-core already rewrote the C49 and 7.2 passages. 7 `arch-refactor/*` PRs open (#1015 `ready` with the burn-down; maintainer drafts #1021, #1027, #1030, #1031, #1036, #1041), so no new PR this run. #776, #909, #980 merged, but the top five stay skipped: `commands/vendor.rs` is changed by #978, #1021, #1027, #1032, #1041, #1043, #1045; backend files by #657, #943, #997, #1026, #1036, #1038–#1040, #1043, #1044; #922 is claimed. Next eligible when a slot frees: #893 (C50, ≈4), #705 (one `utils::uuid` grammar; #1042 touches uuid), #871 (now unblocked by #889). C07 still open.

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
- `#[cfg(test)] mod tests` blocks often lean on the parent's `use sha2::…` through `use super::*`: removing a production import breaks the test build (`cargo test --lib --no-run`), not `cargo build`. Add the import to the test module.
- Bugbot may review the PR's start commit when a draft opens; check the review's commit SHA and re-trigger on the real head.
- go.mod's lexer treats `//` as a comment anywhere, so `module a//b` declares `a`: don't expect `//` inside a token to be rejected.
- #646 merged inline digests after the `utils::digest` ratchet, so `production_digests_go_through_the_helpers` failed on `main` @ `a1d4260`; #876 landed the fix (`gradle_cache.rs` added to `PENDING_INLINE_DIGESTS` because #690 edits it). Drop it from the list when #706 slice 2 migrates it.
- A process-global `reqwest::Client` (`LazyLock`) is unsafe in core tests: pooled connections stay bound to the tokio runtime that opened them, and each `#[tokio::test]` has its own runtime. Build per call through a shared builder instead.
- The sandbox (root) also fails 3 `covgap_commands_vendor` state-write-failure tests (chmod-based) on main and branches alike.
- Probe spawns go through `utils::process::output_within` since #886 (blocking; async callers wrap it in `utils::fs::run_blocking`). It nulls stderr; don't add a new `tokio::time::timeout` + `kill_on_drop` site.
- Vendor-service retries share `ApiClient`'s `RetryHooks` (clock, jitter seed, sleep) since #889: tests inject a recording sleep through `with_api_retry(ApiRetryPolicy::default(), hooks)` instead of timing real sleeps.
