### Refactor routine (`refactor`, hourly, highest leverage first)
_Last updated 2026-10-02T19:05Z · main @ 203e092_

**In flight:**
- [#574](https://github.com/SocketDev/socket-patch/pull/574): one vlt `registry_base` following vlt's DepID hydration. Issues #562 (E02, E03). State: blocked; Bugbot found on `faade96` that restore and the hosted rewrite decide differently which nodes are on the default registry (`~~` under a non-`npm` default alias). A fix is proposed in the PR thread.
- [#581](https://github.com/SocketDev/socket-patch/pull/581): one `ApiTimeouts` policy (10 s connect, 60 s idle read) on both `ApiClient` reqwest clients. Issue #570 (C02). State: ready, handed to the PR burn-down.

**Merged:**
- [#572](https://github.com/SocketDev/socket-patch/pull/572): one hosted-PyPI-URL recognizer for hosted and vendored Pipenv. Issues #563 (E04, E49). Production +31 / −48, tests +174 / −37 (approx.).

**Queue** (B bugs closed, U unblocks, D duplication removed, R risk; score = 3B + 2U + D − risk):

| # | Candidate | B | U | D | R | Score | Note |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| 1 | #594 (E11): one `nuget.config` reader/splicer via `formats::nuget` (hosted, vendored, restore) | 2 | 1 | 5 | M | 11 | fixes #561, #585; skipped: `redirect/mod.rs` changed by open PR #552 |
| 2 | #568 (C03): takeover honors `kept_artifact` via `vendored_backend`'s revert step | 1 | 0 | 1 | L | 4 | skipped: `scan/hosted.rs` changed by open PR #503 |
| 3 | #593 (E50): one version-aware `packages.lock.json` walker | 1 | 0 | 3 | M | 4 | skipped: `redirect/mod.rs` changed by open PR #552 |
| 4 | E37: byte-identical `is_safe_{cargo,gem,nuget}_coordinate` + `normalize_version` copy | 0 | 0 | 4 | L | 4 | to verify, no issue; `vendor/gem.rs` changed by open PR #552 |
| 5 | #592 (E06): FIFO-safe reads in NuGet/Cargo crawlers | 1 | 0 | 0 | L | 3 | eligible; next when capacity frees if the above stay blocked |

Dropped: #569 (C01) now has open PR #587; #571 (C37) score 1.

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
