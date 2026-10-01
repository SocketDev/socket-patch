[agent] Progress ledger for the scheduled npm bug-hunt routine (label pm:npm).

Last updated: 2026-10-01 (run 2 with a ledger), main `f6b7fb9` (CLI 4.0.0), latest release 4.0.0 (previous 3.3.0, both from npm `@socketsecurity/socket-patch`).

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Every cell uses a real npm install. Agent and vendored cells hand-stage `.socket/manifest.json` plus blobs (a marker prepended to `index.js`, the shape `tests/e2e_vendor_npm_build.rs` uses). Hosted cells use a local mock of the patch API or the repo's wiremock suites (`e2e_redirect_npm_build`). "Suites" means `e2e_redirect_npm_build` + `e2e_vendor_npm_build` with `SOCKET_PATCH_NPM_E2E_REQUIRED=1`.

| OS | npm | Agent (apply / scan --apply) | Vendored | Hosted | setup hook |
| --- | --- | --- | --- | --- | --- |
| Linux | 6.14.18 | fail #356 (alias). pass: global `-g` | pass: nested copy in a v2 lock (`npm ci` from the legacy mirror) | untested (fails closed, documented) | untested |
| Linux | 8.19.4 | fail #356 (alias), fail #403 (platform-skipped optional) | pass: nested v2 lock. fail #326 (`file:` tarball) | untested | fail #403 |
| Linux | 9.9.4 | pass: global `-g` | pass (suites) | pass (suites) | untested |
| Linux | 10.9.7 | pass: workspace nested copies, bundled copies. fail #356, #359, #403 | pass: workspace nested entry, overrides→alias. fail #324, #325, #326 (git, URL, `file:` tarball) | pass: `npm install`, `npm install <pkg>`; `npm update` unwires it and `vex` catches it | pass. fail #403 |
| Linux | 11.20.0 | pass: global, symlinked `node_modules`, concurrent-lock, CRLF manifest. fail #403 | pass: suites, dual-lock drift, overrides→alias, scoped alias, autocrlf clone. fail #326 (`file:` tarball) | pass (suites) | pass (workspace, `npm ci`). fail #403 |
| Linux | 12.1.0 | pass: workspace, bundled, `.store` direct dep, global. fail #356, #359, #403 | pass: workspace nested entry, dual-lock drift, overrides→alias, nested v2. fail #359, #326 (`file:` tarball) | pass: member nested entry, `.npmrc` auto-config variants, rollback | pass. fail #403 |
| macOS | 6.14.18 | untested | pass (suites, earlier probe) | pass (suites, earlier probe) | untested |
| macOS | 10.9.x | fail #356, #359, #403. pass: CRLF manifest, unicode path | pass: suites (10.9.9), autocrlf clone + `npm ci` + `vex`, deep path | pass (suites, 10.9.9) | fail #403 |
| macOS | 12.1.0 | fail #356, #359, #403. pass: CRLF manifest, unicode path | pass: suites, autocrlf clone, deep path | pass (suites) | fail #403 |
| Windows | 8.19.4 | untested | pass (suites, earlier probe) | pass (suites, earlier probe) | untested |
| Windows | 10.9.x | fail #403. pass: CRLF manifest, unicode path | pass: suites (10.9.9), autocrlf clone + `npm ci` + `vex` (revert drops CRLF, #324) | pass (suites, 10.9.9) | fail #403 |
| Windows | 12.1.0 | fail #356, #359, #403. pass: CRLF manifest, unicode path | pass: suites, autocrlf clone (revert drops CRLF, #324) | pass (suites) | fail #403 |

## Backlog

1. **Maintainer request:** test global (`-g`) mode for hosted patches on Linux, macOS and Windows across every major npm version. `scan -g` must report exactly the global installs that have hosted patches; `-g --mode hosted` must refuse loudly; `-g` apply, rollback and vex must hit the real global copy. Full checklist in the 20261001T040000Z entry on this discussion.
2. Hosted mode on macOS and Windows with the `.npmrc` allow-remote auto-config (user-config `none`, env overrides, CRLF `.npmrc`).
3. `npm ci --omit=optional` / `--omit=dev` against a manifest that patches an omitted package, in agent, vendored and hosted modes (likely related to #403).
4. Node 18 with npm 9/10, and npm 12 on Node 26.
5. `install-links=true` file: directory deps (packed copies) in agent and vendored modes.
6. An interrupted hosted run (`.npmrc` written, lock unchanged), via the wiremock harness.
7. Stale probe branches the proxy can't delete (`git push --delete` prints "Everything up-to-date" and deletes nothing): `bughunt/npm/20260930-alias-linked`, `20260930-win-mac-e2e`, `20260930-win-old-npm`, `20261001-crlf-paths`, `20261001-optional-dep`. A maintainer needs to delete them.

## Known non-bugs

- `patches-api.socket.dev` is unreachable from the sandbox. Use hand-staged manifests, a local mock API, or the wiremock suites.
- Running `scan --mode hosted` from a workspace member directory finds no packages, because discovery is cwd-scoped. It's loud and writes nothing.
- An explicit `allow-remote` other than `all` is respected with a loud `redirect_npm_allow_remote` warning, and a fresh npm 12 install then fails EALLOWREMOTE (fails closed). This is documented.
- `npm update` re-resolves a hosted or vendored entry back to the registry. That's npm's behaviour; `vex` then refuses (`redirect_unwired` / `vendor_unwired`).
- After that, `apply` skips the package as "managed by `socket-patch vendor`" with exit 0 and doesn't take ownership back. That's by design (`apply.rs` `VENDOR_OWNED_MARKER`), and `vex` refuses.
- npm 12 doesn't install the dependencies of a `file:` directory dependency into the linked directory.
- The walk skips `build`, `dist`, `vendor`, `tmp`, `temp`, `coverage` and hidden directories, even when one is an npm workspace member (documented in docs/ecosystems.md).
- `apply` from a workspace member directory reports `noManifest` when `.socket/` lives at the root (`--cwd` scoping).
- Concurrent lock-taking commands fail fast with `lock_held` unless `--lock-timeout` is set (documented).
- `rollback` drops the rolled-back manifest entries and GCs their blobs unless `--preserve-state` is set (documented).
- Agent-mode `vex` omits patches (`ecosystem_not_setup`) when there's no `setup` hook and no `setup.manual` (documented).
- The VEX product `@id` is the raw origin URL for a non-GitHub/GitLab/Bitbucket remote (documented in `vex --help`).
- npm ≥ 11 redacts UUID-shaped path segments in `npm root -g` stdout, so `apply -g` misses a global prefix whose path contains a UUID. That's npm's behaviour, it's loud (exit 1), and `--global-prefix` works around it. Not filed.
- The Windows + npm 6 suite cell needs `SOCKET_PATCH_NPM_E2E_LOCK_WRITER_BIN` (an npm ≥ 7 to write the v2 lock). That's a harness requirement.
- On Windows, npm/node can't run in a cwd longer than the Win32 limit, so deep-path cells there can't run.
