[agent] Progress ledger for the scheduled Cargo bug-hunt routine (label pm:cargo).

Last updated: 2026-10-01 (run 3), main `2463257` (v5 consolidation #277; CLI reports 4.0.0), latest release 4.0.0.

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Every cell uses a real cargo build (`--locked`/`--frozen`/`--offline`) plus a compile oracle: the patch appends `pub fn socket_patched()` to `cfg-if`, and `main.rs` calls it. Patch data comes from a local public-proxy stand-in (`--proxy-url`, serving `/patch/batch`, `/patch/view/<uuid>` and `/patch/blob/<hash>`) for agent and global mode. Hosted mode uses the wiremock sparse-registry harness in `tests/e2e_redirect_cargo_shapes.rs`, with extra shapes added locally and not committed. The repo suites and `cargo_e2e_matrix` already cover the plain shapes, lock v1–v4 and the old toolchains. All of them passed on `2463257` in run 3.

Cells marked (pre-v5) were last verified on `f6b7fb9` and need a re-check on v5.

| OS | cargo | Agent `vendor/` (source replacement) | Agent custom vendor dir / member cwd | Agent two index dirs (#339 family) | Agent→vendored takeover + rollback | Vendored (CRLF, BOM, ws, existing `[patch]`, re-run, repair) | Hosted extra shapes | Agent after prior build (target/ cache) | Hosted `registry = "crates-io"` | Agent rollback of `cargo vendor` `.cargo-checksum.json` | Hosted `--cwd` = workspace member | Global `-g`: scan report / hosted refusal / apply / rollback / vex |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.56.1 | pass (probe, pre-v5) | fail #338 (probe) | n/a | untested | untested | untested | fail #387 | untested | untested | untested | untested |
| Linux | 1.84.1 | untested | untested | fail #339 | untested | untested | untested | fail #387 | untested | untested | untested | untested |
| Linux | 1.93.1 | pass | fail #338 (pre-v5) | fail #339 (re-confirmed on v5, also under `-g`) | fail #336 (pre-v5) | pass (pre-v5; repo suites pass on v5) | pass (pre-v5 list, plus v5: `[registries.other]` config, CRLF config, dead-index remove fails loudly) | fail #387 (pre-v5) | fail #386 (re-confirmed on v5) | fail #416 | fail #417 | pass / pass / pass / pass / pass (plus unicode path, unwritable dir, `SOCKET_GLOBAL`, `--global-prefix`); multi-index fail #339 |
| Linux | 1.97.0 (stable) | pass (v5) | untested | untested | untested | pass (repo suites, lock v1–v3) | pass (repo shapes, lock v1–v3) | fail #387 | untested | fail #416 | fail #417 | untested (the CLI path is the same as on 1.93.1) |
| macOS | 1.56.1 / 1.84.1 / 1.93.1 / stable | pass (probe, pre-v5) | fail #338 (probe) | fail #339 | untested | untested | untested | untested | untested | untested (expected same) | untested | untested (needs a probe) |
| Windows | 1.56.1 / 1.84.1 / 1.93.1 / stable | pass (probe, stable, pre-v5) | fail #338 (probe) | fail #339 | untested | untested | untested | untested | untested | untested (expected same) | untested | untested (needs a probe) |

## Backlog

0. **Maintainer request (Linux done in run 3):** global `-g` mode on macOS and Windows across the Cargo majors: scan report, hosted refusal, apply, rollback and vex. The full checklist is in the 20261001T040000Z entry.
1. The stale probe branches `bughunt/cargo/20260930-vendor-dir` and `bughunt/cargo/20260930-index-dirs` still exist. `git push --delete` fails through the git proxy (HTTP 403 in runs 1 and 2, "unexpected disconnect" in run 3). A maintainer needs to delete them. Until deletes work, avoid new probe branches.
2. Hosted with an existing `[source.crates-io] replace-with` (vendored or mirror source) on a fresh `--locked` checkout. Also `[registry] default = …`.
3. Re-triage #336, #338 and #387 on v5.
4. Vendored from a workspace member, and with a CRLF or BOM root `Cargo.toml`, on v5. Check that `cargo_manifest_not_workspace_root` fires. Also vendored builds on `cargo +1.41` / `+1.45`, and vendored on Windows and macOS (CRLF, long `.socket/vendor/cargo/<uuid>/` paths).
5. Agent `repair` for a deleted blob; agent `vex` against a hand-edited `.cargo-checksum.json`; the git-index dir `github.com-1ecc6299db9ec823` under `-g`.
6. Maintainer call needed: a local agent scan patches registry-cache crates that the project's `Cargo.lock` doesn't contain, and `vex --product <project>` lists them (see Known non-bugs).

## Known non-bugs

- `patches-api.socket.dev` is blocked by the sandbox proxy (403). Use a local `--proxy-url` stand-in or the repo's wiremock harnesses.
- A hosted dependency declared with dotted keys (`cfg-if.version = "1.0.4"`) is skipped with `redirect_cargo_toml_dep_unrewritable`, with nothing rewritten. It's a loud, documented-by-warning limitation.
- `vendor` / `--mode vendored` refuses `already_vendored_in_tree` when `vendor/<crate>` exists: intended. What's wrong is only the hard-coded `vendor/` detection (#338).
- `cargo vendor -q DIR` prints no source-replacement snippet, so write `.cargo/config.toml` by hand in fixtures.
- Release 3.3.0's `apply` doesn't accept the hand-staged manifest (`partialFailure`), so it can't be compared.
- `apply --check` is Go-only (CLI_CONTRACT).
- (v5) `setup` was removed, and agent-mode `vex` attests cargo patches without any `setup.manual` declaration. The old `ecosystem_not_setup` note no longer applies.
- `[patch."sparse+https://index.crates.io/"]` isn't honoured by cargo 1.93, so ignoring it is correct. The git-URL alias is refused (`cargo_manifest_patch_source_alias`), which is also correct.
- An "unpatched" build right after `cargo vendor` re-runs or re-applies is usually cargo's rlib cache (#387). Run `cargo clean -p <crate>` before judging.
- `vex -g` without `--product` exits 2 ("Could not auto-detect a top-level product PURL"): expected, since a global scope has no project PURL.
- `scan -g --mode hosted` / `--global-prefix … --mode hosted` / `SOCKET_GLOBAL=1 scan --mode hosted` exit 2 by design.
- Hosted `remove` / `rollback` with the crates.io index unreachable fails with `hosted_revert_failed` and leaves the files intact: correct, loud behaviour.
- `-g` patches `$CARGO_HOME/registry/src`, not binaries already built by `cargo install`. That's inherent to cargo.
- A local agent scan crawls the whole shared registry cache (the crawler's documented fallback), so it can patch and attest crates outside the project's `Cargo.lock`. It isn't filed: it's documented as "wherever the crawler finds it" and is pending a maintainer call (backlog 6).
