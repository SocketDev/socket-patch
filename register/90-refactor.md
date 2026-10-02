### Refactor routine (`refactor`, hourly, highest leverage first)
_Last updated 2026-10-02T16:28Z · main @ 1169ae6_

**In flight:**
- [#572](https://github.com/SocketDev/socket-patch/pull/572): one hosted-PyPI-URL recognizer for hosted and vendored Pipenv. Issues #563 (E04, E49). State: ready, handed to the PR burn-down.
- [#574](https://github.com/SocketDev/socket-patch/pull/574): one vlt `registry_base` following vlt's DepID hydration. Issues #562 (E02, E03). State: ready, handed to the PR burn-down.

**Merged:** none yet.

**Queue** (B bugs closed, U unblocks, D duplication removed, R risk; score = 3B + 2U + D − risk):

| # | Candidate | B | U | D | R | Score | Note |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| 1 | #561 (E01): hosted NuGet sources via `formats::nuget` | 1 | 1 | 1 | L | 6 | skipped: `redirect/mod.rs` is changed by open PRs #552, #491, #470, #465 |
| 2 | #571 (C37): `fetch_binary` through the shared `read_capped` | 1 | 0 | 1 | L | 4 | next |
| 3 | #569 (C01): capped zip inflate, one archive-cap set | 1 | 0 | 1 | L | 4 | |
| 4 | E37: byte-identical `is_safe_{cargo,gem,nuget}_coordinate` + `normalize_version` copy | 0 | 0 | 4 | L | 4 | to verify, no issue yet |
| 5 | #570 (C02): API client request timeout | 1 | 0 | 0 | L | 3 | overlaps C15's retry primitive |

**Notes:**
- The sandbox runs as root, so 4 core lib tests fail on main and on branches alike: `copy_tree::relax_loop_must_not_traverse_symlinked_root`, `vlt_heal::an_unremovable_hidden_lock_keeps_every_store_entry`, `pypi_poetry::wire_write_failure_maps_error_and_leaves_lock_untouched`, `pypi_requirements::wire_failure_rolls_back_already_written_files`.
- `redirect/pipenv.rs`, `vendor/pypi.rs` and `vendor/lock_inventory/vlt.rs` aren't rustfmt-clean on main: format only your own hunks there. Check `rustfmt --check` on the `main` copy before formatting a whole file.
- `lock_inventory/mod.rs` `architecture_tests` forbid `hosted_patch_uuid*` in a format file's model section. Origin-policy helpers go after the `// ── registry view ──` marker.
- `redirect/mod.rs` is a hot file (4 open PRs). Prefer candidates outside it until those land.
- `CLI_CONTRACT.md` lives at `crates/socket-patch-cli/CLI_CONTRACT.md`.
- vlt registry semantics: cite `@vltpkg/dep-id` `hydrateTuple` and `@vltpkg/spec` (`registry ?? registries[default-registry-alias]`); the packages download from npm.
- Runs overlap: two runs started within minutes of each other on 2026-10-02. Claims and the status block kept them apart; `git pull --rebase` the ledger before writing.
