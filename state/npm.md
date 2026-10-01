[agent] Progress ledger for the scheduled npm bug-hunt routine (label pm:npm).

Last updated: 2026-10-01 (run 3 with a ledger), main `2463257` (the **v5 consolidation**, #277; the binary still reports 4.0.0), latest release v4.0.0 (previous v3.3.0, both from npm `@socketsecurity/socket-patch`). v5 makes hosted the default, removes `setup`, and makes hosted `rollback` re-resolve upstream registry entries. Cells marked (v4) were last verified on `f6b7fb9`.

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Every cell uses a real npm install. Hosted cells use a local mock of the patch API with `--patch-server-url` pointed at it. Agent and vendored cells use the same mock or a hand-staged `.socket/`. "Cycle" means scan → fresh `npm ci` → `vex` → `rollback` byte-exact. "Suites" means `e2e_redirect_npm_build` + `e2e_vendor_npm_build` with `SOCKET_PATCH_NPM_E2E_REQUIRED=1`.

| OS | npm | Agent (apply / scan --mode agent) | Vendored | Hosted (v5 default) | Global `-g` (scan report / get+apply / vex / rollback) |
| --- | --- | --- | --- | --- | --- |
| Linux | 6.14.18 | fail #356 (v4). pass: `-g` (v4) | pass: nested v2 lock (v4). fail #432 (alias mirror) | pass: v1-lock cycle (npm 6 installs the patched bytes). v1 alias: not wired (#432) | pass (v4) |
| Linux | 8.19.4 | fail #356 (v4), #403 (v4) | fail #326 (v4), #432 | pass: nested v2 cycle. fail #432 (alias mirror, npm 6 consumer) | untested |
| Linux | 9.9.4 | pass `-g` (v4) | pass (suites, v4) | pass (suites, v4) | pass (v4) |
| Linux | 10.9.7 | fail #356 (re-checked on v5), #403 (re-checked on v5), #359 (v4) | pass (v4). fail #324, #325, #326 (v4) | pass: cycles (plain, alias, nested), stale tree, lockfile-only, dry-run, rescan no-op, nested project (loud) | pass: all four, `--global-prefix`, `SOCKET_GLOBAL`, `--mode hosted` refused |
| Linux | 11.20.0 | pass (v4). fail #403 (v4) | pass (v4). fail #326 (v4) | pass: scoped, duplicate nested workspace copies, dual-lock drift, `omit-lockfile-registry-resolved` | untested |
| Linux | 12.1.0 | fail #356, #359, #403 (v4) | pass: hosted→vendored takeover + rollback, `repair` | pass: workspace + alias cycle, dual-lock, drift, `npm install <pkg>` keeps the pin, path-scoped rollback, remove. fail #433 | pass: all four |
| macOS | 10.9.7 | fail #356, #359, #403 (v4) | pass (v4) | pass: cycle (probe) | pass: all four (custom prefix) |
| macOS | 12.1.0 | fail #356, #359, #403 (v4) | pass (v4) | pass: cycle (probe) | pass: all four (custom prefix) |
| Windows | 10.9.7 | fail #403 (v4) | pass (v4). #324 (v4) | pass: cycle (probe) | **fail #434** (default and custom prefix; `--global-prefix` works) |
| Windows | 12.1.0 | fail #356, #359, #403 (v4) | pass (v4). #324 (v4) | pass: cycle (probe) | **fail #434** |
| Windows 2022 | 10.9.7 / 12.1.0 | untested | untested | untested | **fail #434** |

## Backlog

1. **Maintainer request (global `-g`), still open:** Linux, macOS and Windows are covered for npm 10/12 (Windows is #434). Remaining: npm 6/8/11 on macOS and Windows; an unwritable prefix (root-owned / `Program Files`; the sandbox runs as root); nvm, volta, fnm and Homebrew prefixes on macOS; and `%APPDATA%\npm` once #434 is fixed. Full checklist in the 20261001T040000Z entry.
2. Hosted mode with an `.npmrc` `registry=` mirror or a scoped registry: what rollback restores to, and whether `npm ci` works afterwards.
3. `npm ci --omit=optional` / `--omit=dev` against hosted and vendored entries plus `vex`.
4. v5 `socket.yml` policy (`minSeverity`, `maxNewPatches`) and the `--package` filter on npm workspaces and aliases.
5. Node 18 with npm 9/10, and npm 12 on Node 26.
6. Re-verify the (v4) agent and vendored cells on v5 (#324, #325, #326 and #359 on the new main).
7. Stale probe branches the proxy can't delete (`git push --delete` prints "Everything up-to-date"): `bughunt/npm/20260930-alias-linked`, `20260930-win-mac-e2e`, `20260930-win-old-npm`, `20261001-crlf-paths`, `20261001-optional-dep`, `20261001-v5-hosted-global`, `20261001-win-global`. A maintainer needs to delete them.

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
- Hosted pins on any host other than `patch.socket.dev` or the `--patch-server-url` origin are invisible to `rollback`, `vex`, `list` and `remove` (documented). Mock runs must pass `--patch-server-url`.
- In the sandbox, hosted `rollback` can't reach registry.npmjs.org (the Rust client doesn't trust the proxy CA). Use `SOCKET_NPM_REGISTRY` pointed at a local passthrough.
- npm 6 installs the patched bytes from a hosted lockfileVersion 1 lock (measured on Linux, Node 22). npm-compatibility.md says it fails closed with EINTEGRITY; that's better than documented, not a bug.
- `rollback` re-adds `resolved` under `omit-lockfile-registry-resolved=true`: hosted keeps no ledger, and npm drops the field on its next install.
- A failed hosted lock write (an immutable lock) leaves `allow-remote=all` in `.npmrc`: exit 1, the documented mid-flush I/O residual.
- A bare hosted `scan` wires only the cwd project's lock. A nested non-workspace project warns `redirect_npm_entry_not_found`. `scan . sub` wires both, but `rollback` / `vex` from the root don't see `sub`'s pins (use `--cwd sub`).
- `rollback <path>` path targets select installed copies, so a workspace member whose dependency is hoisted to the root matches nothing (documented).
- Vendored `vex` attests from the committed artifact and only warns `vendored_tree_out_of_sync` when the live tree is stale (documented).
- `scan -g` without `-e` also scans the cargo, pypi and gem global stores (by design). `vex -g` outside a project needs `--product`.
- v5 removes `setup`, so the setup-hook cells are retired.
