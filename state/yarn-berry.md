[agent] Progress ledger for the scheduled Yarn Berry (2+) bug-hunt routine (label pm:yarn-berry).

Last updated: 2026-09-30 (run 1), main `f6b7fb9` (CLI 4.0.0 workspace version), latest release 4.0.0 (previous 3.3.0, both from npm `@socketsecurity/socket-patch`).

Harness: yarn bundles come from npm `@yarnpkg/cli-dist@<v>` (`node package/bin/yarn.js`), because corepack's fetch can't use the sandbox proxy. Yarn 4 needs `YARN_HTTPS_CA_FILE_PATH`; yarn 2/3 need `YARN_CA_FILE_PATH`. The npm registry has 2.4.2 as the last 2.x in cli-dist. Agent and vendored cells hand-stage `.socket/manifest.json` plus blobs (a marker prepended to `index.js`). Hosted cells use a local Python mock of the patch API (batch, by-package, `patches/package` with a `yarn-berry-zip` `yarnBerry10c0` artifact, `view`, and the tarball route). The 10c0 checksum is bootstrapped with a real yarn `resolutions: file:` install. Every hosted and vendored cell ends in a fresh-checkout `yarn install --immutable`. On GH runners, fixture installs need `YARN_ENABLE_IMMUTABLE_INSTALLS=false` (CI turns immutable on).

## Coverage matrix

Cells are "pass", "fail #N", "refused (by design)" or "untested". Linker is node-modules unless noted.

| OS | yarn | Agent apply / rollback | Vendored | Hosted | setup hook |
| --- | --- | --- | --- | --- | --- |
| Linux | 2.4.2 (cacheKey 7) | untested | untested | refused (by design) `redirect_yarn_berry_cache_unsupported` | untested |
| Linux | 3.8.7 (cacheKey 8) | untested | refused (by design) `vendor_yarn_berry_cache_unsupported` | refused (by design) | untested |
| Linux | 4.0.2 (bare-hex checksums) | untested | untested | pass (left-pad); fail #368 (resolve) | untested |
| Linux | 4.12.0 | pass (node-modules and pnpm linkers, rollback byte-exact) | pass: root, scoped root name, scoped target, `**/` glob resolution, workspaces, pnpm linker, re-run idempotent, `--revert`, in-place immutable install. Refused (by design): resolve/typescript (`patch:` builtin), yarn 3. fail #370 (commented compressionLevel) | pass: left-pad, pnpm linker + vex, rollback byte-exact. fail #368 (resolve, typescript). fail #369 (hosted→vendored takeover). fail #370. Refused (by design): PnP (`yarn_pnp_unsupported`), direct + alias merged entry (`redirect_yarn_berry_ambiguous_entry`) | pass (postinstall re-patches; `setup --remove` byte-exact) |
| Linux | 4.18.1 (latest) | untested | pass (CRLF-respelled lock + package.json) | pass (left-pad); fail #368; fail #370 | untested |
| macOS | 4.12.0, 4.18.1 | untested | untested | pass (left-pad); fail #368; fail #369 (probe run 36764922521) | untested |
| Windows | 4.12.0, 4.18.1 (yarn writes CRLF) | untested | untested | pass (left-pad, CRLF lock); fail #368; fail #369 (probe run 36764922521) | untested |

## Backlog

1. Yarn 2/3 cells for agent mode and vendored (2.4.2), plus `get --mode vendored|hosted` front doors.
2. Zero-install `.yarn/cache` committed: after hosted or vendored, `yarn install --immutable --immutable-cache` has to fail (a new cache zip is needed). This is undocumented; decide whether it's a doc gap, and check that the stale unpatched zip is pruned.
3. PnP lock-only checkouts (no `.pnp.cjs` committed, default `nodeLinker`): refusal detection keys on the loader file, so vendor/hosted proceed. Check what the resulting install does under PnP (`vendor` tried a registry fetch; the release binary can't reach the registry in the sandbox).
4. Takeover vendored→hosted with a refused hosted target (the mirror of #369), and the same hosted→vendored per-target gap on yarn classic and npm (the takeover preflight is berry-only).
5. `compressionLevel` supplied outside the project `.yarnrc.yml` (`YARN_COMPRESSION_LEVEL`, `~/.yarnrc.yml`, a parent-dir rc) while the lock still says 10c0, plus a quoted key (`"compressionLevel": mixed`).
7. Stale probe branch `bughunt/yarn-berry/20260930-builtin-patch-takeover`: `git push --delete` failed three times (remote end hung up), and the REST ref delete returned 403. Retry it; otherwise a maintainer needs to delete it.
6. `enableImmutableInstalls: true` in `.yarnrc.yml` combined with `rollback` / `remove` on workspaces; macOS/Windows cells for vendored and agent mode.

## Known non-bugs

- Yarn 2/3 (cacheKey 7/8) are refused by hosted and vendored mode (documented).
- PnP projects with a `.pnp.cjs` are refused in every mode with `yarn_pnp_unsupported` (documented).
- Vendoring a package yarn builtin-patches (`resolve`, `typescript`, `fsevents`) is refused fail-closed with `vendor_override_conflict`. It's loud and closed, so it isn't filed (the hosted counterpart is #368).
- Hosted refuses an entry that merges a direct descriptor with an `npm:` alias (`"left-pad@npm:1.3.0, lp@npm:left-pad@1.3.0"`) with `redirect_yarn_berry_ambiguous_entry` and exit 1. It's fail-closed and loud; arguably over-broad, but not filed.
- Agent mode: a later `yarn install --immutable` in the same tree doesn't restore unpatched bytes (yarn's install-state), and the setup hook re-patches after a clean install. Standalone `vex` in agent mode needs `setup` or `setup.manual` (documented).
- `patches-api.socket.dev` is unreachable from the sandbox; use the mock.
