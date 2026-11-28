[agent] Progress ledger for the scheduled pnpm bug-hunt routine (label pm:pnpm).

Last run: 2026-11-28 (run 52), main `cfc870f`, release v5.1.0, newest pnpm 12.23.0 (11.29.0, 10.34.9, 9.15.9, 8.15.9, 7.33.7 latest per major; 12.24.0 on `next-12`).

Method (since run 51): agent = real npmjs packages + hand-staged `.socket/` + `apply --offline` (stage only the after blob, so offline rollback of an applied patch needs the before blob too); vendored = local uncommitted test that starts `prebuilt_common::Server::project` and exports `SOCKET_VENDOR_URL` (running the issue-embedded mock is blocked by the sandbox); hosted = `e2e_redirect_pnpm_build pnpm_pinned_matrix` with `SOCKET_PATCH_PNPM_E2E_BIN`. Earlier method: real pnpm installs on Linux against a local Python stand-in for the patch server and npm registry, modeled on the registry-route legs of `crates/socket-patch-cli/tests/e2e_redirect_pnpm_build.rs` (packages `leaf`, `mid`→`leaf`, `host`, `peer-user` (peer `host`, dep `leaf`); patches A=`leaf` uuid `aaaaaaaa-…`, B=`peer-user` uuid `bbbbbbbb-…`, grants with `npmRegistryUrl`). The script is embedded in #2263. Set `SOCKET_PATCH_SERVER_URL` and `SOCKET_NPM_REGISTRY` to the mock, strip proxy env for pnpm 12, use `--store-dir` per step. Oracle: marker at the top of `index.js` after a fresh-clone `--frozen-lockfile` install from an empty store. Release focus: cells last tested before 2026-11-11 count as untested.

## Coverage matrix

One row per workflow; "≤10-18" = last passed by 2026-10-18 on 5.0.x/main of that time, so untested for the release.

| Workflow | Agent | Vendored | Hosted |
| --- | --- | --- | --- |
| Common path: scan → fresh frozen install → vex → rollback byte-exact | pass 9.15.9 / 10.34.9 / 11.29.0 / 12.23.0 (11-27) | pass 9.15.9 / 10.34.9 / 11.29.0 / 12.23.0 (11-27 pinned matrix + fixture) | pass, registry route, 11.20.0 / 11.29.0 / 12.23.0 (11-26); trustLockfile path ≤10-18 |
| Registry route: re-lock byte-identical, `update`, `dedupe` keep patch | n/a | n/a | pass 11.20.0 / 11.29.0 / 12.23.0 (11-26) |
| Registry route: `remove` one patch, `repair --offline` after `pnpm remove` | n/a | n/a | pass 11.29.0 / 12.23.0 (11-26) |
| Registry route: `packageManager` with `+sha512.` suffix | n/a | n/a | pass 12.23.0 (11-26) |
| Workspace + `catalog:` (CRLF / LF workspace file) | untested | untested | fallback to trustLockfile, misleading reason: #2264; install + rollback pass 11.29 / 12.23 |
| Mixed modes per patch (hosted B + vendored A); git-hosted parent of vendored pkg | untested | fail #2263 on 12.23.0 (pass 11.20–12.22); git parent also fails (11-27); registry tarball-URL parent pass | fail #2263 on 12.23.0 |
| Takeover hosted → vendored | n/a | partial: peer-suffixed refusal (known), then #2263 on 12.23 | — |
| Workspaces / `sharedWorkspaceLockfile: false` / member locks | untested (≤10-18) | shared lock pass 12.23.0 (11-27); per-member from root: #2298 (9.15.9 / 10.34.9 `.npmrc` + ws file / 12.23.0, 11-28); member dir refusal pass | untested (≤10-18) |
| Global virtual store / custom virtualStoreDir / hoisted | GVS refusal + remedy, hoisted pass 11.29.0 / 12.23.0 (11-27) | hoisted pass 12.23.0 (11-27) | untested (≤10-18) |
| Legacy locks (shrinkwrap.yaml, 5.x, 6.0) on pnpm 2–8 | n/a (agent ignores the lock) | pass pinned matrix 7.33.7 / 8.15.9 (11-28); pnpm 1–6 untested | pass pinned matrix incl. workspace peer instances 7.33.7 / 8.15.9 (11-28); pnpm 1–6 untested |
| Rush / subspaces | untested (≤10-18) | n/a | untested (≤10-18) |
| `patchedDependencies`, aliases, peer-suffixed, injected | patchedDependencies: `user_patch_conflict` refusal, `--allow-patch-conflicts` apply + vex, store clean pass 10.34.9 / 12.23.0 (11-28); aliases / injected untested | untested (≤10-18) | untested (≤10-18) |
| Build approvals (`allowBuilds`, `onlyBuiltDependencies`) | n/a | pass 10.30.0 / 10.34.9 / 11.5.2 / 11.5.3 / 11.29.0 / 12.23.0: block, quoted, `name@ver` keys, CRLF file, `package.json#pnpm`; flow style gives `vendor_pnpm_build_approval_lost` and its remedy works (11-28) | untested (≤10-18) |
| `-g` global install | untested (≤10-18, Linux only) | n/a | n/a |
| macOS / Windows | probes switched off (INSTRUCTIONS.md) | — | — |

## Backlog

1. Hosted custom shapes need a patch-server stand-in that isn't copied from an issue: write a small local wiremock test in the style of `e2e_redirect_pnpm_build.rs` (uncommitted; the `run_build_approval_capstone` mock registry in `e2e_vendor_pnpm_build.rs` is a good template), then do route edge shapes on 12.23.0 / 11.29.0: `sharedWorkspaceLockfile: false` members, scoped package, user's own `namedRegistries` / `overrides`, supersede A→A', a pin that drops below 11.20.
2. Re-verify #2263 (incl. the git-parent shape), #2264 and #2298 once a fix lands (main unchanged since `cfc870f`).
3. Hosted build approvals (`allowBuilds` vs the routed `socket-<id>` name) on 11.29.0 / 12.23.0.
4. npm handover (#1756, CRLF shebang rewritten by bin-links) on pnpm 9/10/12, agent / vendored.
5. Re-verify closed pnpm bughunt issues on main for the release: #1619, #1638, #935 vendored half (#1597 done 11-28).
6. Pinned matrix for pnpm 1–6 (refusal / shrinkwrap.yaml / 5.0–5.3) on main; pnpm 7/8 vendored moved checkout (`vendor_pnpm_legacy_absolute_specifier`).
7. Run reporting (#2178): `--json` counts for hosted pnpm runs, `scan --prune` vendored revert reporting (#2246).
8. Rush / subspace locks on 12.23, `--frozen-lockfile` / `--offline`.
9. Aliases (`npm:` specifiers) and `injected` workspace deps, agent / vendored.

## Known non-bugs

Full list: `known-non-bugs/pnpm.md` (search it with `git grep`). Most likely to be re-filed:
- Hosted rollback leaves a `trustLockfile: true` it may have added to a user's own `pnpm-workspace.yaml`, with `pnpm_trust_lockfile_left`.
- pnpm 9.15.9 frozen install in the same checkout after a hosted pin says "Already up to date" and keeps upstream bytes (documented "Reinstall after redirecting").
- `pnpm install --fix-lockfile` / `dedupe` / `--resolution-only` drop trustLockfile-path hosted pins on 11/12 (upstream re-resolution); the registry route keeps them.
- pnpm 12.0.0–12.12.1 record `tarball:` for every scoped-registry package; 12.13+ don't.
- Vendored refuses a user override that references the patched package (`vendor_override_conflict`).
- Hosted pins next to a `bundledDependencies` copy: only `vex` omits the bundled copy.
- Mock setup: rollback / vex need `SOCKET_PATCH_SERVER_URL`; pnpm 12 needs proxy env stripped for a localhost registry.
- Peer-suffixed hosted snapshot refused by the hosted → vendored takeover ("not supported yet").
- Agent `apply` skips a package pnpm `patchedDependencies` already patches (`user_patch_conflict`, remedy `--allow-patch-conflicts`).
