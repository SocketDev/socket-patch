[agent] Progress ledger for the scheduled Cargo bug-hunt routine (label pm:cargo).

Last updated: 2026-09-30 (run 1), main `f6b7fb9` (CLI 4.0.0), latest release 4.0.0 (previous 3.3.0).

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Every cell uses a real cargo build (`--locked`/`--frozen`/`--offline`) plus a compile oracle: the patch appends `pub fn socket_patched()` to `cfg-if`, and `main.rs` calls it. Patch data is a hand-staged `.socket/manifest.json` plus blobs for agent and vendored mode (the same shape `tests/e2e_vendor_cargo_build.rs` uses). Hosted mode uses the wiremock sparse-registry harness from `tests/e2e_redirect_cargo_shapes.rs`, with extra shapes added locally and not committed. The existing test suites and the `cargo_e2e_matrix` already cover the plain shapes, lock v1–v4 and the old toolchains. This ledger tracks what they don't.

| OS | cargo | Agent `vendor/` (source replacement) | Agent custom vendor dir / member cwd / unwired `vendor/` | Agent two registry index dirs (1.84 + ≥1.85 on one CARGO_HOME) | Agent→vendored takeover + rollback | Vendored (CRLF, BOM, no-EOL, rename, virtual ws, existing `[patch]`, dotted `patch.crates-io`, idempotent re-run, repair, `cargo update`) | Hosted extra shapes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.56.1 | pass (probe) | fail #338 (probe) | n/a | untested | untested | untested |
| Linux | 1.84.1 | untested | untested | fail #339 | untested | untested | untested |
| Linux | 1.93.1 | pass | fail #338 | fail #339 (order-dependent: sandbox fails the 1.84 project, the GH runner fails the 1.93 project) | fail #336 | pass (all listed) | pass (target-specific, `[dependencies.x]` table, trailing comment, `cfg_if` rename, build-deps, `[workspace.dependencies.x]` table + `x.workspace = true`, member→member path chain, excluded non-member path dep, direct + transitive other version) |
| macOS | 1.56.1 / 1.84.1 / 1.93.1 / stable | pass (probe) | fail #338 (probe, 1.56.1 + stable) | fail #339 (1.93 project unpatched) | untested | untested | untested |
| Windows | 1.56.1 / 1.84.1 / 1.93.1 / stable | pass (probe, stable; 1.56.1 not captured) | fail #338 (probe, 1.56.1 + stable) | fail #339 (1.84 project unpatched) | untested | untested | untested |

## Backlog

0. Delete stale probe branches `bughunt/cargo/20260930-vendor-dir` and `bughunt/cargo/20260930-index-dirs`: the git proxy refused `git push --delete` with HTTP 403 in run 1. A maintainer needs to delete them.
1. `.cargo-checksum.json` formatting: agent `rollback` restores a `cargo vendor` checksum file semantically but not byte-for-byte (compact JSON is re-emitted pretty-printed; `sidecars/cargo.rs:134` uses `to_vec_pretty`), which leaves a whole-file diff in a committed `vendor/`. Check whether the contract promises byte-exact rollback for sidecars before filing. It's low severity.
2. Agent mode with the git index (`github.com-1ecc6299db9ec823`, cargo < 1.70 or `CARGO_REGISTRIES_CRATES_IO_PROTOCOL=git`) alongside the sparse dirs is the same family as #339. Add it to #339 if it's confirmed.
3. Vendored mode on Windows and macOS (CRLF checkouts, long paths under `.socket/vendor/cargo/<uuid>/`), and vendored mode with `cargo +1.56` / `+1.45` / `+1.41` builds from the probe.
4. Hosted mode `--locked`/`--frozen` on a fresh checkout for Windows; hosted multi-member workspace where one member uses a renamed dep and another uses the plain name; `cargo vendor` after a hosted redirect (does `cargo vendor` pull the socket registry?).
5. Agent `vex` against a `cargo vendor` tree whose `.cargo-checksum.json` was hand-edited, and `repair` in agent mode for a deleted vendored file.
6. Agent `--global` / `--global-prefix` against a CARGO_HOME with several index dirs (relates to #339).

## Known non-bugs

- `patches-api.socket.dev` is blocked by the sandbox proxy (403). Stage `.socket/manifest.json` plus blobs locally, or use the repo's wiremock harnesses.
- A hosted dependency declared with dotted keys (`cfg-if.version = "1.0.4"`) is skipped with `redirect_cargo_toml_dep_unrewritable` ("declared with dotted keys this rewriter does not edit"), with nothing rewritten. It's a loud, documented-by-warning limitation, not a silent failure.
- `vendor` / `--mode vendored` refuses `already_vendored_in_tree` when `vendor/<crate>` exists: intended ("patch it in place with `apply` instead"). What's wrong is only that the detection is hard-coded to `vendor/` (see #338).
- `cargo vendor -q DIR` prints no source-replacement snippet, so write `.cargo/config.toml` by hand in fixtures (a fixture pitfall).
- Release 3.3.0's `apply` doesn't accept the hand-staged manifest used here (`partialFailure`, no events), so 3.3.0 can't be compared for these cells.
