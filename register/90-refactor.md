### Refactor routine (`refactor`, hourly, highest leverage first)
_Last updated 2026-10-08T05:10Z · main @ 05fd82b_

**In flight:**
- [#1108](https://github.com/SocketDev/socket-patch/pull/1108): one `utils::line_endings::terminator` (CRLF → CRLF, mixed → majority, else LF) for 7 inserted-line sites: gem lock converge, composer/requirements restore, Pipfile.lock entry formatter, PEP 723 writer, go.mod append/re-join. Issue #815 (E16, slice 1; `detect_eol`, `pypi_uv::newline_of`, Maven ×2, `redirect/mod.rs`, the `crlf` flags and upstream gem's Gemfile restore remain, all in open-PR files). Re-blesses the go/uv equivalence goldens (mixed inputs only). `state: ready`.
- [#1106](https://github.com/SocketDev/socket-patch/pull/1106): the macOS PDM site probe runs through `utils::process::output_within`; a guard test rejects new production `kill_on_drop` spawns (pending: `vendor/npm_dir.rs`). Issue #1067 (C48, slice: `pdm_site`; the `npm_dir` git exchange remains, blocked on #1026). `state: ready`, handed to the burn-down.
- [#1103](https://github.com/SocketDev/socket-patch/pull/1103): `go.sum` edits through `GoSumEditor` only; deletes the oracle-only free functions and names the key rule once. Issue #631 (E52, slice: steps 2–3; the move to `formats/golang/sum.rs` remains). `state: ready`, handed to the burn-down.
- Maintainer drafts (decided issues): [#1021](https://github.com/SocketDev/socket-patch/pull/1021) (#615), [#1027](https://github.com/SocketDev/socket-patch/pull/1027) (#704), [#1030](https://github.com/SocketDev/socket-patch/pull/1030) (#808), [#1031](https://github.com/SocketDev/socket-patch/pull/1031) (#966), [#1036](https://github.com/SocketDev/socket-patch/pull/1036) (#973), [#1041](https://github.com/SocketDev/socket-patch/pull/1041) (#648), [#1049](https://github.com/SocketDev/socket-patch/pull/1049) (#792), [#1051](https://github.com/SocketDev/socket-patch/pull/1051) (#580).
- October 7 campaign (duplicate business logic, one PR per seam; register rows in brackets): #1026 credentials [C59], #1029 trust signals [C61], #1032 JVM layout [E77, E69], #1033 VEX attestation [E72], #1034 target grammar [C62], #1035 supersede lifecycle [E71], #1038 paths and roots [C64], #1039 atomic takeover [E70], #1043 command cycles and UI text [C65, C12], #1044 governing locks [E75], #1045 `PurlKey` [C63], #1046 test hygiene [C66], #1050 vendored liveness [E74], #1057 yarn grammar [E08, E76], #1058 pinned check [E73]. #1042 `.socket` containment [C60, C42] merged as `ddc3bfb`.

**Merged:**
- [#1015](https://github.com/SocketDev/socket-patch/pull/1015): the vendored-reference scan reads every `VENDORED` row and accepts the bare uuid dir. Issues #832, #958 (E61). `8e521f9` (+308 / −41). Left: dead `eco == "maven2"` arm in `commands/vendor.rs`.
- [#876](https://github.com/SocketDev/socket-patch/pull/876): registry clients under `ApiTimeouts` through one `registry_client_builder`. Issue #872 (C49). `e2300cc` (+154 / −33).
- [#889](https://github.com/SocketDev/socket-patch/pull/889): vendor-service retries share `api::retry` (`Retry-After` HTTP-date, jitter). Issue #677 (C15 child 1). `835601b` (+209 / −38). Left: blob/diff fetches have no retry (#676).
- Earlier: #886, #870, #865, #858, #850, #607, #602, #597, #587, #583, #581, #574, #572 (see `entries/refactor/`).

**Queue** (B bugs closed, U unblocks, D duplication removed, R risk; score = 3B + 2U + 2D + S − risk):

| # | Candidate | B | U | D | R | Score | Note |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| 1 | #990 (E24, child 1 of #989): one `vendor::revert::finish` for the 12 copied finish blocks | 0 | 1 | ≈12 | L | ≈26 | skipped: all 12 backend files changed by open PRs |
| 2 | #922 (E22): one `VendorEntry::npm` constructor for 7 npm-family ledger tails | 0 | 1 | ≈7 | L | ≈16 | skipped: claimed; drivers changed by #1008 |
| 3 | #815 (E16) slice 1: `line_endings::terminator` for the 7 copies in free files | 0 | 1 | 7 | L | ≈16 | **taken: #1108** |
| 4 | #906 (E25): one `stage_prebuilt` for the 4 `<eco>_service_copy` pipelines | 0 | 1 | 4–5 | L | ≈11 | skipped: `vendor/{cargo,composer_lock,gem,golang,service_fetch}.rs` changed by #1026, #1041 and others |
| 5 | #998 (C56): one NotFound-only manifest probe | 1 | 1 | ≈5 | M | ≈13 | skipped: `commands/vendor.rs` changed by 11 open PRs |

Re-ranked 2026-10-08T03:58Z at `b762f41` against the files of the 39 open PRs (547 paths). 156 of 383 production `.rs` files are free. Only #815's slice and #649 (comments only, score 0) fit inside them. #906 looked free on body paths alone, but its link targets are backticked, so a path-only match misses them. Check symbol definitions, not body paths. 05:10Z at `05fd82b`: nothing merged or closed, so the overlap set is unchanged. New since: #1107 (C75, one `utils::http` client builder) overlaps `client.rs`/`telemetry.rs`/`registry_fetch.rs` (#1026, #1041, #1049) and waits on a trust-default decision; #1090 (C32 child 1) and every #1089 child's covgap file are changed by open PRs; E88's severity ladder already delegates to `api::ranking`. No PR opened.

**Notes:**
- Equivalence goldens (`tests/equivalence/*.golden`, re-bless with `SOCKET_PATCH_BLESS_GOLDEN=1`) feed one input in five through a mixed-ending generator, so any line-ending rule change moves them. Show that only mixed cases can move (a rule argument plus a chunk count) before you re-bless.
- Upstream gem's `restore_manifest` pins CRLF output for a CRLF Gemfile holding an LF block (an older rewriter wrote one). Migrate it together with the forward Gemfile writer in `redirect/mod.rs`, never alone.
- `crawlers/python_crawler/pdm_site.rs` is compiled only on macOS, and the sandbox can't cross-check `aarch64-apple-darwin` (`ring` needs an Apple cc). To test it, temporarily change its `mod` line in `python_crawler.rs` to `#[cfg(unix)] #[allow(dead_code)]` and revert before committing.
- Overlap check: fetch `/pulls/<n>/files` for every open PR and match exact paths (suffix matches on `mod.rs`/`client.rs` are false positives); `comm -23` of `git ls-files` against that set lists the free files.
- To delete a refactor oracle safely: first refactor the kept code while the oracle test still runs, then capture the oracle's outputs on odd inputs as fixed expectations, then delete it (done in #1103).
- The sandbox runs as root, so 4 core lib tests fail on main and on branches alike: `copy_tree::relax_loop_must_not_traverse_symlinked_root`, `vlt_heal::an_unremovable_hidden_lock_keeps_every_store_entry`, `pypi_poetry::wire_write_failure_maps_error_and_leaves_lock_untouched`, `pypi_requirements::wire_failure_rolls_back_already_written_files`.
- `redirect/pipenv.rs`, `vendor/pypi.rs` and `vendor/lock_inventory/vlt.rs` aren't rustfmt-clean on main: format only your own hunks there. Check `rustfmt --check` on the `main` copy before formatting a whole file.
- `lock_inventory/mod.rs` `architecture_tests` forbid `hosted_patch_uuid*` in a format file's model section. Origin-policy helpers go after the `// ── registry view ──` marker.
- `redirect/mod.rs` is a hot file (4 open PRs). Prefer candidates outside it until those land.
- `CLI_CONTRACT.md` lives at `crates/socket-patch-cli/CLI_CONTRACT.md`.
- vlt registry semantics: `hydrate` and `Spec` memoize by id/spec and ignore options, so run each vlt case in a fresh `node` process. `scoped-registries[scope]` wins for every segment; `~~` splits to `npm`. Cite `@vltpkg/dep-id` `hydrateTuple` and `@vltpkg/spec` (`registry ?? registries[default-registry-alias]`); the packages download from npm.
- Runs overlap; `git pull --rebase` the ledger before writing.
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
- Test modules lean on the parent's imports via `use super::*`: removing a production import can break only `cargo test --lib --no-run`.
- Bugbot may review a draft's start commit: check the review SHA, re-trigger on the head.
- go.mod's lexer treats `//` as a comment anywhere (`module a//b` declares `a`).
- A process-global `reqwest::Client` (`LazyLock`) is unsafe in core tests: pooled connections stay bound to the tokio runtime that opened them, and each `#[tokio::test]` has its own runtime. Build per call through a shared builder instead.
- The sandbox (root) also fails 3 `covgap_commands_vendor` state-write-failure tests (chmod-based) on main and branches alike.
- Probe spawns go through `utils::process::output_within` since #886 (blocking; async callers wrap it in `utils::fs::run_blocking`). It nulls stderr; don't add a new `tokio::time::timeout` + `kill_on_drop` site.
