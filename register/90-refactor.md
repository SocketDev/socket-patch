### Refactor routine (`refactor`, hourly, highest leverage first)
_Last updated 2026-10-07T17:49Z · main @ 431b818 (October 7 reconciliation)_

**In flight:**
- No routine-opened PR is open. 24 `arch-refactor` PRs are open, so `MAX_OPEN` is full; the routine re-ranks only.
- Maintainer drafts (decided issues): [#1021](https://github.com/SocketDev/socket-patch/pull/1021) (#615), [#1027](https://github.com/SocketDev/socket-patch/pull/1027) (#704), [#1030](https://github.com/SocketDev/socket-patch/pull/1030) (#808), [#1031](https://github.com/SocketDev/socket-patch/pull/1031) (#966), [#1036](https://github.com/SocketDev/socket-patch/pull/1036) (#973), [#1041](https://github.com/SocketDev/socket-patch/pull/1041) (#648), [#1049](https://github.com/SocketDev/socket-patch/pull/1049) (#792), [#1051](https://github.com/SocketDev/socket-patch/pull/1051) (#580).
- October 7 campaign (duplicate business logic, one PR per seam; register rows in brackets): #1026 credentials [C59], #1029 trust signals [C61], #1032 JVM layout [E77, E69], #1033 VEX attestation [E72], #1034 target grammar [C62], #1035 supersede lifecycle [E71], #1038 paths and roots [C64], #1039 atomic takeover [E70], #1042 `.socket` containment [C60, C42], #1043 command cycles and UI text [C65, C12], #1044 governing locks [E75], #1045 `PurlKey` [C63], #1046 test hygiene [C66], #1050 vendored liveness [E74], #1057 yarn grammar [E08, E76], #1058 pinned check [E73]. CI merge queue: #1018 [C67].

**Merged:**
- [#1015](https://github.com/SocketDev/socket-patch/pull/1015): the vendored-reference scan reads every `VENDORED` row and accepts the bare uuid dir. Issues #832, #958 (E61). `8e521f9` (+308 / −41). Left: dead `eco == "maven2"` arm in `commands/vendor.rs`.
- [#876](https://github.com/SocketDev/socket-patch/pull/876): registry clients under `ApiTimeouts` through one `registry_client_builder`. Issue #872 (C49). `e2300cc` (+154 / −33).
- [#889](https://github.com/SocketDev/socket-patch/pull/889): vendor-service retries share `api::retry` (`Retry-After` HTTP-date, jitter). Issue #677 (C15 child 1). `835601b` (+209 / −38). Left: blob/diff fetches have no retry (#676).
- Earlier: [#886](https://github.com/SocketDev/socket-patch/pull/886) (#845, C48 slice 1), [#870](https://github.com/SocketDev/socket-patch/pull/870) (#781), [#865](https://github.com/SocketDev/socket-patch/pull/865) (#706 slice 1), [#858](https://github.com/SocketDev/socket-patch/pull/858) (#728), [#850](https://github.com/SocketDev/socket-patch/pull/850) (#823 slice 1), [#607](https://github.com/SocketDev/socket-patch/pull/607) (#571), [#602](https://github.com/SocketDev/socket-patch/pull/602) (#592), [#597](https://github.com/SocketDev/socket-patch/pull/597) (#561, E01), [#587](https://github.com/SocketDev/socket-patch/pull/587) (#569, C01), [#583](https://github.com/SocketDev/socket-patch/pull/583) (E12), [#581](https://github.com/SocketDev/socket-patch/pull/581) (#570), [#574](https://github.com/SocketDev/socket-patch/pull/574) (#562), [#572](https://github.com/SocketDev/socket-patch/pull/572) (#563).

**Queue** (B bugs closed, U unblocks, D duplication removed, R risk; score = 3B + 2U + D − risk):

| # | Candidate | B | U | D | R | Score | Note |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| 1 | #990 (E24, child 1 of #989): one `vendor::revert::finish` with an explicit `KeepPolicy` for the 12 copied finish blocks | 0 | 1 | ≈12 | L | ≈14 | skipped: backend files changed by #1032, #1039, #1043, #1044, #1050, #1057 |
| 2 | #922 (E22, child 1 of #920): one `VendorEntry::npm` constructor for the 7 npm-family ledger tails | 0 | 1 | ≈7 | L | ≈9 | skipped: claimed; drivers changed by #1008 |
| 3 | #998 (C56): one NotFound-only manifest probe (5 `metadata().is_err()` copies) | 1 | 1 | ≈5 | M | ≈8 | skipped: `commands/vendor.rs` changed by open PRs; pairs with #931 and #1063 |
| 4 | #931 (C13 child 1): one manifest-read error mapper for every command | 1 | 1 | ≈2.5 | M | ≈5.5 | skipped: as #998 |
| 5 | #893 (C50): one artifact GC retention policy | 1 | 0 | ≈2 | L | ≈4 | next eligible when a slot frees |

Re-ranked 2026-10-07T17:49Z by the October 7 reconciliation: stale skip lists replaced (#657, #909, #940, #1015, #876, #889 merged). The campaign PRs above cover E08, E69–E77, C42 and C59–C67; don't start work on those rows.

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
- A process-global `reqwest::Client` (`LazyLock`) is unsafe in core tests: pooled connections stay bound to the tokio runtime that opened them, and each `#[tokio::test]` has its own runtime. Build per call through a shared builder instead.
- The sandbox (root) also fails 3 `covgap_commands_vendor` state-write-failure tests (chmod-based) on main and branches alike.
- Probe spawns go through `utils::process::output_within` since #886 (blocking; async callers wrap it in `utils::fs::run_blocking`). It nulls stderr; don't add a new `tokio::time::timeout` + `kill_on_drop` site.
