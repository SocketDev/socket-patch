[agent] Progress ledger for the scheduled Cargo bug-hunt routine (label pm:cargo).

Last updated: 2026-09-30 (run 2), main `f6b7fb9` (CLI 4.0.0), latest release 4.0.0 (previous 3.3.0).

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Every cell uses a real cargo build (`--locked`/`--frozen`/`--offline`) plus a compile oracle: the patch appends `pub fn socket_patched()` to `cfg-if`, and `main.rs` calls it. Patch data is a hand-staged `.socket/manifest.json` plus blobs for agent and vendored mode (the same shape `tests/e2e_vendor_cargo_build.rs` uses). Hosted mode uses the wiremock sparse-registry harness from `tests/e2e_redirect_cargo_shapes.rs`, with extra shapes added locally and not committed. The existing test suites and the `cargo_e2e_matrix` already cover the plain shapes, lock v1–v4 and the old toolchains. This ledger tracks what they don't.

| OS | cargo | Agent `vendor/` (source replacement) | Agent custom vendor dir / member cwd / unwired `vendor/` | Agent two registry index dirs (1.84 + ≥1.85 on one CARGO_HOME) | Agent→vendored takeover + rollback | Vendored (CRLF, BOM, no-EOL, rename, virtual ws, existing `[patch]`, dotted `patch.crates-io`, idempotent re-run, repair, `cargo update`) | Hosted extra shapes | Agent apply/rollback after a prior build (target/ cache) | Hosted explicit `registry = "crates-io"` | Vendored user `[patch]` in config files / renamed key / custom source replacement |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.56.1 | pass (probe) | fail #338 (probe) | n/a | untested | untested | untested | fail #387 | untested | untested |
| Linux | 1.84.1 | untested | untested | fail #339 | untested | untested | untested | fail #387 | untested | untested |
| Linux | 1.93.1 | pass | fail #338 | fail #339 (order-dependent: sandbox fails the 1.84 project, the GH runner fails the 1.93 project) | fail #336 | pass (all listed) | pass (target-specific, `[dependencies.x]` table, trailing comment, `cfg_if` rename, build-deps, `[workspace.dependencies.x]` table + `x.workspace = true`, member→member path chain, excluded non-member path dep, direct + transitive other version, optional + features/`dep:`, `default-features = false`, `"1"` caret, ws members plain + renamed, idempotent re-scan, `cargo vendor` after redirect) | fail #387 (registry, `vendor/`, rollback) | fail #386 | pass |
| Linux | 1.97.0 (stable) | untested | untested | untested | untested | untested | untested | fail #387 | untested | untested |
| macOS | 1.56.1 / 1.84.1 / 1.93.1 / stable | pass (probe) | fail #338 (probe, 1.56.1 + stable) | fail #339 (1.93 project unpatched) | untested | untested | untested | untested (cargo-core behaviour, expected same) | untested | untested |
| Windows | 1.56.1 / 1.84.1 / 1.93.1 / stable | pass (probe, stable; 1.56.1 not captured) | fail #338 (probe, 1.56.1 + stable) | fail #339 (1.84 project unpatched) | untested | untested | untested | untested (cargo-core behaviour, expected same) | untested | untested |

## Backlog

0. **Maintainer request:** test global (`-g`) mode for hosted patches on Linux, macOS and Windows across every major Cargo version. `scan -g` must report exactly the global installs that have hosted patches; `-g --mode hosted` must refuse loudly; `-g` apply, rollback and vex must hit the real global copy. Full checklist in the 20261001T040000Z entry on this discussion.
1. The stale probe branches `bughunt/cargo/20260930-vendor-dir` and `bughunt/cargo/20260930-index-dirs` still exist: the git proxy refused `git push --delete` with HTTP 403 in runs 1 and 2. A maintainer needs to delete them. Until deletes work, avoid new probe branches.
2. `.cargo-checksum.json` formatting: agent `rollback` restores a `cargo vendor` checksum file semantically but not byte-for-byte (compact JSON is re-emitted pretty-printed; `sidecars/cargo.rs` uses `to_vec_pretty`). Check whether the contract promises byte-exact rollback for sidecars before filing. It's low severity.
3. Hosted: `registry-index = …` deps; a project with `[registries]` / `[registry] default` config; hosted plus existing `[source.crates-io] replace-with` on a fresh `--locked` checkout; Windows fresh-checkout `--locked`.
4. Vendored mode on Windows and macOS (CRLF checkouts, long paths under `.socket/vendor/cargo/<uuid>/`), and vendored builds on `cargo +1.41` / `+1.45`.
5. Agent `--global` / `--global-prefix` against a CARGO_HOME with several index dirs, plus the git-index dir `github.com-1ecc6299db9ec823` (both the #339 family).
6. `repair` in agent mode for a deleted vendored file; agent `vex` against a hand-edited `.cargo-checksum.json`.

## Known non-bugs

- `patches-api.socket.dev` is blocked by the sandbox proxy (403). Stage `.socket/manifest.json` plus blobs locally, or use the repo's wiremock harnesses.
- A hosted dependency declared with dotted keys (`cfg-if.version = "1.0.4"`) is skipped with `redirect_cargo_toml_dep_unrewritable` ("declared with dotted keys this rewriter does not edit"), with nothing rewritten. It's a loud, documented-by-warning limitation, not a silent failure.
- `vendor` / `--mode vendored` refuses `already_vendored_in_tree` when `vendor/<crate>` exists: intended ("patch it in place with `apply` instead"). What's wrong is only that the detection is hard-coded to `vendor/` (see #338).
- `cargo vendor -q DIR` prints no source-replacement snippet, so write `.cargo/config.toml` by hand in fixtures (a fixture pitfall).
- Release 3.3.0's `apply` doesn't accept the hand-staged manifest used here (`partialFailure`, no events), so 3.3.0 can't be compared for these cells.
- `apply --check` is Go-only (CLI_CONTRACT), so it returns success with no events for cargo even when patched files were reset.
- Agent-mode `vex` omits cargo with `ecosystem_not_setup` unless the manifest has `setup.manual: ["cargo"]`, because cargo has no install hook (`setup` → `no_files`). It's documented.
- `[patch."sparse+https://index.crates.io/"]` isn't treated as crates.io by cargo 1.93 (the build ignores it), so socket-patch ignoring it is correct. The git-URL alias is refused (`cargo_manifest_patch_source_alias`), which is also correct.
- An "unpatched" build right after `cargo vendor` re-runs or re-applies is usually cargo's rlib cache (#387), not a socket-patch rewrite failure. Run `cargo clean -p <crate>` before judging a cell.
