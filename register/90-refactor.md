### Refactor routine (`refactor`, hourly, highest leverage first)
_Last updated 2026-10-02T18:00Z · main @ 203e092_

**In flight:**
- [#572](https://github.com/SocketDev/socket-patch/pull/572): one hosted-PyPI-URL recognizer for hosted and vendored Pipenv. Issues #563 (E04, E49). State: ready, handed to the PR burn-down.
- [#574](https://github.com/SocketDev/socket-patch/pull/574): one vlt `registry_base` following vlt's DepID hydration. Issues #562 (E02, E03). State: blocked; review found `scoped-registries` precedence missing and `~~` resolving as plain-spec instead of the `npm` alias. A correction is in progress.
- [#581](https://github.com/SocketDev/socket-patch/pull/581): one `ApiTimeouts` policy (10 s connect, 60 s idle read) on both `ApiClient` reqwest clients. Issue #570 (C02). State: ready, handed to the PR burn-down.

**Merged:** none yet.

**Queue** (B bugs closed, U unblocks, D duplication removed, R risk; score = 3B + 2U + D − risk):

| # | Candidate | B | U | D | R | Score | Note |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| 1 | #561 (E01): hosted NuGet sources via `formats::nuget` | 1 | 1 | 1 | L | 6 | skipped: `redirect/mod.rs` is changed by open PR #552 (#470, #465 merged) |
| 2 | #568 (C03): takeover honors `kept_artifact` via `vendored_backend`'s revert step | 1 | 0 | 1 | L | 4 | skipped: `scan/hosted.rs` is changed by open PR #503 |
| 3 | E37: byte-identical `is_safe_{cargo,gem,nuget}_coordinate` + `normalize_version` copy | 0 | 0 | 4 | L | 4 | next when capacity frees; to verify, no issue yet; `vendor/gem.rs` also changed by open PR #552 |
| 4 | #571 (C37): stream blob/diff bodies | 1 | 0 | 0 | M | 1 | maintainer: no size cap, stream instead; changes `fetch_binary`'s return shape |
| 5 | #569 (C01): stream zip entry comparison | 1 | 0 | 0 | M | 1 | maintainer: data is trusted, stream for performance instead of capping |

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
