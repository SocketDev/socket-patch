[agent] Progress ledger for the scheduled Yarn Berry (2+) bug-hunt routine (label pm:yarn-berry).

Last updated: 2026-10-01 (run 5), main `61cfb9b` (CLI still reports 4.0.0), latest release 4.0.0 (previous 3.3.0).

Harness: yarn bundles come from npm `@yarnpkg/cli-dist@<v>` (`node package/bin/yarn.js`), because corepack's fetch can't use the sandbox proxy. Yarn 4 needs `YARN_HTTPS_CA_FILE_PATH`; yarn 2/3 need `YARN_CA_FILE_PATH`. The npm registry has 2.4.2 as the last 2.x in cli-dist. Agent and vendored cells hand-stage `.socket/manifest.json` plus blobs (a marker prepended to `index.js`). Hosted cells use a local Python mock of the patch API (batch, by-package, `patches/package` with a `yarn-berry-zip` `yarnBerry10c0` artifact, `view`, and the tarball route). The 10c0 checksum is bootstrapped with a real yarn `resolutions: file:` install. Every hosted and vendored cell ends in a fresh-checkout `yarn install --immutable`. v5: hosted rollback/remove need the mock's `/upstream/npm/<uuid>.json` route, `SOCKET_NPM_REGISTRY` pointed at a local registry passthrough (the rustls binary can't use the sandbox proxy CA), and `--patch-server-url <mock>` so the pins count as hosted. Global (`-g`) cells use real npm global installs (`NPM_CONFIG_PREFIX`) and a Python mock of the authenticated API (`--api-url <mock> --api-token x --org org`; blob route `/v0/orgs/org/patches/blob/<sha256>`). v5 vendored mode downloads from the vendoring service: the same mock's `/patches/package` with a granted `tarball` artifact (real sha512) is enough, and an optional per-patch `status` override (for example `pending_build`) is supported. A `corepack` shim (`corepack yarn@X` → `node <cli-dist X>/bin/yarn.js`, setting the CA env itself because the harness scrubs `YARN_*`) runs the repo's berry e2e suites in the sandbox (`SOCKET_PATCH_YARN_E2E_REQUIRED=1`, `SOCKET_PATCH_YARN_BERRY_VERSION=<v>`). `setup` was removed in v5. On GH runners, fixture installs need `YARN_ENABLE_IMMUTABLE_INSTALLS=false` (CI turns immutable on).

## Coverage matrix

Cells are "pass", "fail #N", "refused (by design)" or "untested". Linker is node-modules unless noted.

| OS | yarn | Agent apply / rollback | Vendored | Hosted | setup hook |
| --- | --- | --- | --- | --- | --- |
| Linux | 2.4.2 (cacheKey 7) | untested | untested | refused (by design) `redirect_yarn_berry_cache_unsupported` | untested |
| Linux | 3.8.7 (cacheKey 8) | pnpm linker: pass on 61cfb9b (transitive dep in `.store`, real dirs) | refused (by design) `vendor_yarn_berry_cache_unsupported` | refused (by design) | untested |
| Linux | 4.0.2 (bare-hex checksums) | pnpm linker: fail #495 (store-only transitive dep); repo e2e suites pass on 61cfb9b | untested | pass (left-pad, v5 rollback byte-exact); fail #368 (resolve); fail #404 | removed in v5 |
| Linux | 4.12.0 | pass on f6b7fb9 (node-modules and pnpm linkers, rollback byte-exact). On 61cfb9b: pass for direct deps (pnpm linker, root and scoped) and hoisted transitive deps; fail #495 (pnpm-linker transitive dep only in `.store/<slug>/package`); repo e2e suites pass | pass on f6b7fb9: root, scoped root name, scoped target, `**/` glob resolution, workspaces, pnpm linker, re-run idempotent, `--revert`, in-place immutable install. pass on v5: root, workspaces + `enableImmutableInstalls: true` (`--revert` and `remove` byte-exact), CRLF lock + package.json. Refused (by design): resolve/typescript (`patch:` builtin), yarn 3. fail #370 (commented compressionLevel). fail #369 (hosted→vendored via `scan`/`get --mode vendored`; `vendor` itself is fixed on v5). fail #468 (vendored→hosted with no `yarnBerry10c0`) | pass: left-pad, pnpm linker + vex, rollback byte-exact; v5 main: scoped, CRLF, workspaces merged-range, re-scan idempotent, manifest-less rollback/remove/list byte-exact, PnP lock-only checkout, upgrade path (uuid A→B re-pin, then rollback byte-exact), hardened mode accepts `__archiveUrl` pins, vendored→hosted takeover (checksum present; `pending_build` stays vendored). fail #368 (resolve, typescript, user `yarn patch`). fail #404 (registry token sent to patch host). fail #369 (hosted→vendored takeover). fail #370. Refused (by design): PnP (`yarn_pnp_unsupported`), direct + alias merged entry (`redirect_yarn_berry_ambiguous_entry`) | pass on f6b7fb9; removed in v5 |
| Linux | 4.18.1 (latest) | pnpm linker: fail #495; repo e2e suites pass on 61cfb9b | pass on f6b7fb9 (CRLF-respelled lock + package.json); v5: fail #468 | pass (left-pad, scoped, lock `version: 10`); fail #368; fail #370; fail #404; fail #468 | removed in v5 |
| macOS | 4.12.0, 4.18.1 | untested | untested | pass (left-pad); fail #368; fail #369 (probe run 36764922521) | untested |
| Windows | 4.12.0, 4.18.1 (yarn writes CRLF) | untested | untested | pass (left-pad, CRLF lock); fail #368; fail #369 (probe run 36764922521) | untested |

Global (`-g`) cells. Berry has no global dir, so these are npm-prefix globals scanned from inside or outside a Berry project:

| OS | yarn | scan -g report (inside/outside a Berry project) | -g hosted refusal | -g apply / rollback / vex |
| --- | --- | --- | --- | --- |
| Linux | 2.4.2, 3.8.7, 4.0.2, 4.12.0, 4.18.1 | fail #440 (project `global` script runs); otherwise pass, no project leak (node-modules, pnpm, PnP) | pass (exit 2, nothing written) | pass on 4.12.0 (byte-exact rollback, vex `not_applied` after reinstall, EACCES loud, `--global-prefix` with space and unicode) |
| macOS | 2.4.2, 3.8.7, 4.12.0, 4.18.1 | fail #440 (probe run 36828589815) | untested | untested |
| Windows | 2.4.2, 3.8.7, 4.12.0, 4.18.1 | pass for #440 (`.cmd` shim not run) | untested | untested |

## Backlog

1. **Maintainer request (partly done):** global (`-g`) mode. Linux is covered (see the global table). Remaining: macOS and Windows `-g` apply/rollback/vex and the hosted refusal (probe), and a version-manager prefix (nvm/volta under `$HOME`). Full checklist in the 20261001T040000Z entry.
2. Probe #495 on macOS and Windows (junctions); `vex` and `rollback` for a pnpm-linker store-only transitive dep.
3. Probe #468 and #369 (`scan --mode vendored`) on macOS and Windows.
4. Vendored regression check of #357 (JSON writers) on berry: `package.json` with a BOM, tabs or 4-space indent, `resolutions` round-trip, revert byte-exact.
5. Takeovers into hosted with other per-dep refusals after a vendored revert (version drift → `redirect_yarn_berry_entry_not_found`, scoped packages); vendored on the pnpm linker and a PnP lock-only checkout on v5.
6. Probe #404 on macOS/Windows once PR #465 lands (re-triage); private `npmRegistryServer` plus `npmAlwaysAuth`. Re-triage #440 when PR #442 lands.
7. Yarn 2 agent-mode cells (2.4.2 has no pnpm linker; node-modules only).
8. Stale probe branches `bughunt/yarn-berry/20260930-builtin-patch-takeover` and `bughunt/yarn-berry/20261001-global-script`: the git proxy refuses deletes (HTTP 403). A maintainer needs to delete them.

## Known non-bugs

- Yarn 2/3 (cacheKey 7/8) are refused by hosted and vendored mode (documented).
- PnP projects with a `.pnp.cjs` are refused in every mode with `yarn_pnp_unsupported` (documented).
- Vendoring a package yarn builtin-patches (`resolve`, `typescript`, `fsevents`) is refused fail-closed with `vendor_override_conflict`. It's loud and closed, so it isn't filed (the hosted counterpart is #368).
- Hosted refuses an entry that merges a direct descriptor with an `npm:` alias (`"left-pad@npm:1.3.0, lp@npm:left-pad@1.3.0"`) with `redirect_yarn_berry_ambiguous_entry` and exit 1. It's fail-closed and loud; arguably over-broad, but not filed.
- Agent mode: a later `yarn install --immutable` in the same tree doesn't restore unpatched bytes (yarn's install-state), and the setup hook re-patches after a clean install. Standalone `vex` in agent mode needs `setup` or `setup.manual` (documented).
- `patches-api.socket.dev` is unreachable from the sandbox; use the mock.
- A BOM'd yarn.lock fails `yarn install --immutable` (YN0028) on its own, because yarn strips the BOM. Not caused by socket-patch.
- Hosted on a berry `npm:` alias-only entry → `redirect_yarn_berry_alias_skipped` (documented in docs/ecosystems.md).
- `scan <workspace-member-dir>` finds 0 packages: hosted/vendored PATHs are project dirs, and members share the root's lock (CLI_CONTRACT "exclude it with ignorePackages, not paths").
- PnP with `.pnp.cjs`: scan reports 0 packages with a PnP warning (same in 4.0.0). A PnP lock-only checkout gets hosted pins, and those install correctly under PnP.
- v5 rollback/remove/list treat only `patch.socket.dev` (or `--patch-server-url`) URLs as hosted pins. Without that flag, a mock host reads as "Manifest not found".
- PnP on yarn 2.x (`.pnp.js`) and 3.x is detected and gets the loud PnP warning in every mode, exit 0 (same as 4.x).
- An agent-mode re-run (`scan -g --mode agent`) after a failed apply (EACCES) exits 0 with "already recorded … run `socket-patch apply`". This is the designed re-run message; `apply -g` itself exits 1.
- The report-only hint after `scan -g` doesn't mention `-g`. It's cross-PM and was handed to npm (#302), so it isn't filed here.
- Yarn 4 hardened mode (`enableHardenedMode`, auto-on for public fork PRs in GitHub Actions) accepts a hosted `::__archiveUrl=` lock pin, as does `--check-resolutions` (4.12.0, registry reachable).
- Zero-install (`enableGlobalCache: false` with `.yarn/cache` committed): hosted mode is lock-only, so the committed cache keeps the unpatched zip, and `yarn install --immutable --immutable-cache` fails YN0056 until `yarn install` refreshes the cache. It's a docs gap, not filed.
- `compressionLevel` set outside the project `.yarnrc.yml` (env, home or parent rc) can't cause a wrong checksum: yarn bakes the level into the lock's `cacheKey`, which both modes gate on.
