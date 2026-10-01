[agent] Progress ledger for the scheduled Yarn Berry (2+) bug-hunt routine (label pm:yarn-berry).

Last updated: 2026-10-01 (run 3), main `2463257` (v5 consolidation #277; CLI still reports 4.0.0), latest release 4.0.0 (previous 3.3.0).

Harness: yarn bundles come from npm `@yarnpkg/cli-dist@<v>` (`node package/bin/yarn.js`), because corepack's fetch can't use the sandbox proxy. Yarn 4 needs `YARN_HTTPS_CA_FILE_PATH`; yarn 2/3 need `YARN_CA_FILE_PATH`. The npm registry has 2.4.2 as the last 2.x in cli-dist. Agent and vendored cells hand-stage `.socket/manifest.json` plus blobs (a marker prepended to `index.js`). Hosted cells use a local Python mock of the patch API (batch, by-package, `patches/package` with a `yarn-berry-zip` `yarnBerry10c0` artifact, `view`, and the tarball route). The 10c0 checksum is bootstrapped with a real yarn `resolutions: file:` install. Every hosted and vendored cell ends in a fresh-checkout `yarn install --immutable`. v5: hosted rollback/remove need the mock's `/upstream/npm/<uuid>.json` route, `SOCKET_NPM_REGISTRY` pointed at a local registry passthrough (the rustls binary can't use the sandbox proxy CA), and `--patch-server-url <mock>` so the pins count as hosted. Global (`-g`) cells use real npm global installs (`NPM_CONFIG_PREFIX`) and a Python mock of the authenticated API (`--api-url <mock> --api-token x --org org`; blob route `/v0/orgs/org/patches/blob/<sha256>`). v5 vendored mode downloads from a vendoring service (`--vendor-url`); that mock isn't built yet. `setup` was removed in v5. On GH runners, fixture installs need `YARN_ENABLE_IMMUTABLE_INSTALLS=false` (CI turns immutable on).

## Coverage matrix

Cells are "pass", "fail #N", "refused (by design)" or "untested". Linker is node-modules unless noted.

| OS | yarn | Agent apply / rollback | Vendored | Hosted | setup hook |
| --- | --- | --- | --- | --- | --- |
| Linux | 2.4.2 (cacheKey 7) | untested | untested | refused (by design) `redirect_yarn_berry_cache_unsupported` | untested |
| Linux | 3.8.7 (cacheKey 8) | untested | refused (by design) `vendor_yarn_berry_cache_unsupported` | refused (by design) | untested |
| Linux | 4.0.2 (bare-hex checksums) | untested | untested | pass (left-pad, v5 rollback byte-exact); fail #368 (resolve); fail #404 | removed in v5 |
| Linux | 4.12.0 | pass on f6b7fb9 (node-modules and pnpm linkers, rollback byte-exact); untested on v5 | pass: root, scoped root name, scoped target, `**/` glob resolution, workspaces, pnpm linker, re-run idempotent, `--revert`, in-place immutable install. Refused (by design): resolve/typescript (`patch:` builtin), yarn 3. fail #370 (commented compressionLevel) | pass: left-pad, pnpm linker + vex, rollback byte-exact; v5 main: scoped, CRLF, workspaces merged-range, re-scan idempotent, manifest-less rollback/remove/list byte-exact, PnP lock-only checkout. fail #368 (resolve, typescript, user `yarn patch`). fail #404 (registry token sent to patch host). fail #369 (hosted→vendored takeover). fail #370. Refused (by design): PnP (`yarn_pnp_unsupported`), direct + alias merged entry (`redirect_yarn_berry_ambiguous_entry`) | pass on f6b7fb9; removed in v5 |
| Linux | 4.18.1 (latest) | untested | pass on f6b7fb9 (CRLF-respelled lock + package.json); untested on v5 | pass (left-pad, scoped, lock `version: 10`); fail #368; fail #370; fail #404 | removed in v5 |
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
2. Build a vendoring-service mock (`--vendor-url`) and re-run the v5 vendored cells, #369 and the takeovers (#369 hasn't been re-checked on v5).
3. Probe branch: #404 on macOS/Windows; yarn with `npmRegistryServer` set to a private registry plus `npmAlwaysAuth`.
4. Hosted upgrade path (a superseding uuid), and rollback through the new uuid's `/upstream` metadata.
5. Zero-install committed `.yarn/cache` after hosted/rollback (stale zips, `--immutable-cache`).
6. `compressionLevel` from `YARN_COMPRESSION_LEVEL` / `~/.yarnrc.yml` / a parent rc; a quoted key.
7. Yarn 2/3 agent-mode cells; `enableImmutableInstalls: true` with rollback/remove on workspaces.
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
