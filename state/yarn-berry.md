[agent] Progress ledger for the scheduled Yarn Berry (2+) bug-hunt routine (label pm:yarn-berry).

Last updated: 2026-10-02 (run 7), main `61cfb9b` (CLI still reports 4.0.0), latest release 4.0.0 (previous 3.3.0).

Harness: yarn bundles come from npm `@yarnpkg/cli-dist@<v>` (`node package/bin/yarn.js`), because corepack's fetch can't use the sandbox proxy. Yarn 4 needs `YARN_HTTPS_CA_FILE_PATH`; yarn 2/3 need `YARN_CA_FILE_PATH`. The npm registry has 2.4.2 as the last 2.x in cli-dist. Agent and vendored cells hand-stage `.socket/manifest.json` plus blobs (a marker prepended to `index.js`). Hosted cells use a local Python mock (fresh-checkout copies must keep `.socket/` for vendored cells) of the patch API (batch, by-package, `patches/package` with a `yarn-berry-zip` `yarnBerry10c0` artifact, `view`, and the tarball route). The 10c0 checksum is bootstrapped with a real yarn `resolutions: file:` install. Every hosted and vendored cell ends in a fresh-checkout `yarn install --immutable`. v5: hosted rollback/remove need the mock's `/upstream/npm/<uuid>.json` route, `SOCKET_NPM_REGISTRY` pointed at a local registry passthrough (the rustls binary can't use the sandbox proxy CA), and `--patch-server-url <mock>` so the pins count as hosted. Global (`-g`) cells use real npm global installs (`NPM_CONFIG_PREFIX`) and a Python mock of the authenticated API (`--api-url <mock> --api-token x --org org`; blob route `/v0/orgs/org/patches/blob/<sha256>`). v5 vendored mode downloads from the vendoring service: the same mock's `/patches/package` with a granted `tarball` artifact (real sha512) is enough, and an optional per-patch `status` override (for example `pending_build`) is supported. A `corepack` shim (`corepack yarn@X` → `node <cli-dist X>/bin/yarn.js`, setting the CA env itself because the harness scrubs `YARN_*`) runs the repo's berry e2e suites in the sandbox (`SOCKET_PATCH_YARN_E2E_REQUIRED=1`, `SOCKET_PATCH_YARN_BERRY_VERSION=<v>`). `setup` was removed in v5. On GH runners, fixture installs need `YARN_ENABLE_IMMUTABLE_INSTALLS=false` (CI turns immutable on).

## Coverage matrix

Cells are "pass", "fail #N", "refused (by design)" or "untested". Linker is node-modules unless noted.

| OS | yarn | Agent apply / rollback | Vendored | Hosted | setup hook |
| --- | --- | --- | --- | --- | --- |
| Linux | 2.4.2 (cacheKey 7) | pass on 61cfb9b (node-modules: apply, vex, rollback byte-exact and idempotent) | untested | refused (by design) `redirect_yarn_berry_cache_unsupported` | untested |
| Linux | 3.8.7 (cacheKey 8) | pass on 61cfb9b: node-modules and pnpm linker (transitive dep in `.store`, real dirs), apply/vex/rollback byte-exact | refused (by design) `vendor_yarn_berry_cache_unsupported` | refused (by design) | untested |
| Linux | 4.0.2 (bare-hex checksums) | pnpm linker: fail #495 (store-only transitive dep); repo e2e suites pass on 61cfb9b | PnP lock-only: fail #539 (re-run) | pass (left-pad, v5 rollback byte-exact); fail #368 (resolve); fail #404 | removed in v5 |
| Linux | 4.12.0 | pass on f6b7fb9 (node-modules and pnpm linkers, rollback byte-exact). On 61cfb9b: pass for direct deps (pnpm linker, root and scoped) and hoisted transitive deps; fail #495 (pnpm-linker transitive dep only in `.store/<slug>/package`); repo e2e suites pass | pass on 61cfb9b: pnpm linker (in-place + fresh `--check-cache`, `--revert` byte-exact); PnP lock-only checkout vendors and loads patched bytes, but re-run after install fails #539 (also 4.0.2, 4.18.1); zero-install committed cache → YN0056 (docs gap). package.json tab / 4-space / BOM / CRLF+tab / no trailing newline / existing or empty `resolutions` (fresh immutable + `--revert` byte-exact); mixed-EOL yarn.lock refused loudly (`vendor_yarn_berry_mixed_line_endings`). pass on f6b7fb9: root, scoped root name, scoped target, `**/` glob resolution, workspaces, pnpm linker, re-run idempotent, `--revert`, in-place immutable install. pass on v5: root, workspaces + `enableImmutableInstalls: true` (`--revert` and `remove` byte-exact), CRLF lock + package.json. Refused (by design): resolve/typescript (`patch:` builtin), yarn 3. fail #370 (commented compressionLevel). fail #369 (hosted→vendored via `scan`/`get --mode vendored`; `vendor` itself is fixed on v5). fail #468 (vendored→hosted with no `yarnBerry10c0`) | pass: left-pad, pnpm linker + vex, rollback byte-exact; 61cfb9b: rollback and remove byte-exact for `npm:^1.3.0`, dev-only and optional-only descriptors; v5 main: `npm:1.3.0` / `npm:^1.3.0` descriptors, dev-only and optional-only deps, mixed-case name `JSONStream` (case-kept purl, also on 4.18.1), mixed-EOL lock refused loudly, scoped, CRLF, workspaces merged-range, re-scan idempotent, manifest-less rollback/remove/list byte-exact, PnP lock-only checkout, upgrade path (uuid A→B re-pin, then rollback byte-exact), hardened mode accepts `__archiveUrl` pins, vendored→hosted takeover (checksum present; `pending_build` stays vendored). fail #368 (resolve, typescript, user `yarn patch`). fail #404 (registry token sent to patch host). fail #369 (hosted→vendored takeover). fail #370. Refused (by design): PnP (`yarn_pnp_unsupported`), direct + alias merged entry (`redirect_yarn_berry_ambiguous_entry`). PnP stale `.pnp.cjs` + hosted pin → standalone `vex` attests unpatched copy: fail #519 (yarn-classic issue; berry evidence commented, also 4.0.2 and 4.18.1) | pass on f6b7fb9; removed in v5 |
| Linux | 4.18.1 (latest) | pnpm linker: fail #495; repo e2e suites pass on 61cfb9b | pass on f6b7fb9 (CRLF-respelled lock + package.json); v5: fail #468; PnP lock-only: fail #539 (re-run) | pass (left-pad, scoped, lock `version: 10`); fail #368; fail #370; fail #404; fail #468 | removed in v5 |
| macOS | 4.12.0, 4.18.1 | untested | untested | pass (left-pad); fail #368; fail #369 (probe run 36764922521) | untested |
| Windows | 4.12.0, 4.18.1 (yarn writes CRLF) | untested | untested | pass (left-pad, CRLF lock); fail #368; fail #369 (probe run 36764922521) | untested |

Global (`-g`) cells. Berry has no global dir, so these are npm-prefix globals scanned from inside or outside a Berry project:

| OS | yarn | scan -g report (inside/outside a Berry project) | -g hosted refusal | -g apply / rollback / vex |
| --- | --- | --- | --- | --- |
| Linux | 2.4.2, 3.8.7, 4.0.2, 4.12.0, 4.18.1 | fail #440 (project `global` script runs); otherwise pass, no project leak (node-modules, pnpm, PnP) | pass (exit 2, nothing written) | pass on 4.12.0 (byte-exact rollback, vex `not_applied` after reinstall, EACCES loud, `--global-prefix` with space and unicode) |
| macOS | 2.4.2, 3.8.7, 4.12.0, 4.18.1 | fail #440 (probe run 36828589815) | untested | untested |
| Windows | 2.4.2, 3.8.7, 4.12.0, 4.18.1 | pass for #440 (`.cmd` shim not run) | untested | untested |

## Backlog

1. **Blocked on a maintainer:** the git proxy drops probe-branch deletes, so no new probes. Stale branches `bughunt/yarn-berry/20260930-builtin-patch-takeover` and `bughunt/yarn-berry/20261001-global-script` need deleting by hand. After that, probe #495 (Windows junctions), #468, #369 and #539 on macOS/Windows.
2. Re-triage when the fix PRs land: #470 (#468, #369), #508 (#370), #465 (#404), #442 (#440), #496 (#495). #368 and #539 have no PR yet.
3. **Maintainer request (partly done):** global (`-g`) mode. Linux is covered (see the global table). Remaining: macOS and Windows `-g` apply/rollback/vex and the hosted refusal (probe), and a version-manager prefix (nvm/volta under `$HOME`). Full checklist in the 20261001T040000Z entry.
4. Vendored PnP workspaces and a vendored upgrade (uuid A→B) from a lock-only PnP checkout; takeovers into hosted after a vendored revert with version drift.
5. Unconfirmed lead: a lower-cased npm purl from the API (`pkg:npm/jsonstream@1.3.5`) for a mixed-case package is missed by every mode (agent skips with exit 1; hosted/vendored `*_entry_not_found`). File it (cross-PM, npm crawler) only if the real API is shown to lower-case.
6. Private `npmRegistryServer` plus `npmAlwaysAuth` for hosted (#404 follow-up).

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
- Zero-install (`enableGlobalCache: false` with `.yarn/cache` committed): hosted mode is lock-only, so the committed cache keeps the unpatched zip, and `yarn install --immutable --immutable-cache` fails YN0056 until `yarn install` refreshes the cache. Vendored mode behaves the same way (the `file:` entry has no cache zip; no warning). It's a docs gap, not filed.
- `compressionLevel` set outside the project `.yarnrc.yml` (env, home or parent rc) can't cause a wrong checksum: yarn bakes the level into the lock's `cacheKey`, which both modes gate on.
- Vendored refuses a user `yarn patch` (`patch:` descriptor) with `vendor_override_conflict`, plus an alias-only dependency (root or workspace member) with `vendor_lock_entry_not_found`, a merged direct + alias entry, and a user-authored `resolutions` key for the target. All are loud and closed with nothing written, so none are filed.
- Mixed CRLF/LF `yarn.lock` is refused by vendored (`vendor_yarn_berry_mixed_line_endings`) and hosted (`redirect_yarn_berry_mixed_line_endings`). That's correct: yarn itself fails YN0028 on such a lock.
- v5 `rollback` drops the patch's manifest entry, so a later `apply` is a no-op (designed).
- A berry install rewrites a BOM'd, compact, or no-trailing-newline `package.json`. Vendored snapshots the post-install bytes and reverts to them byte-exactly.
