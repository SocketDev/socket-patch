[agent] Progress ledger for the scheduled Yarn Berry (2+) bug-hunt routine (label pm:yarn-berry).

Last run: 2026-11-27 (run 49), main `cfc870f`, release v5.1.0, newest yarn 4.19.0 (also tested 4.0.2, 3.8.7, 2.4.2).

Compacted in run 49: the per-run matrix rows and the known-non-bug list (runs 1-48) moved out; the old version is in this branch's history (commit before run 49). Open `pm:yarn-berry` issues: none (all earlier filings closed by 2026-10-27).

Harness (rebuild each run, ~10 min): yarn via `corepack yarn@X` with `NODE_USE_ENV_PROXY=1 COREPACK_NPM_REGISTRY=https://registry.npmjs.org` (repo.yarnpkg.com is unreachable). A Python mock serves the patch API (`/v0/orgs/<org>/patches/{batch,by-package,package,view,blob}`), the tarball, `/upstream/npm/<uuid>.json` (needed by hosted rollback) and any `<base>/patch/...` path as a mirror. Pass `--patch-server-url <mock>` to every command, or rollback/remove/list don't see the pin. Put the mirror on a different port from the patch server: the patch-server origin owns its whole host. The checksum comes from a bootstrap `resolutions: file:./patched.tgz` install. `patches-api.socket.dev` is blocked (403).

## Coverage matrix

Linux only (macOS/Windows probes are off). Versions are yarn releases; date is the last pass. Linker node-modules unless noted.

| Workflow | Agent | Vendored | Hosted |
| --- | --- | --- | --- |
| Common path: scan, fresh `--immutable --check-cache`, vex, rollback byte-exact | pass 4.19.0 (pnpm-linker workspace, 3 copies + `.store`), 2.4.2, 3.8.7 (2026-11-27) | pass 4.19.0 pnpm-linker workspace (2026-11-27) | pass 4.19.0, 4.0.2 (2026-11-27) |
| Patch mirror (`SOCKET_PATCH_MIRROR_URL`, new since v5.1.0) | n/a | mirrored hosted pin → `vendor` takeover + `--revert` byte-exact: pass 4.19.0 (2026-11-27) | pass 4.19.0, 4.0.2: pin, fresh install, re-scan no-op, rollback byte-exact, `catalog:` + named catalog workspace, trailing-slash and host-case base, 404/down mirror → `redirect_mirror_unavailable` nothing written, earlier patch-server pin → `redirect_mirror_pin_not_moved` and its remedy works, pin on another base → `redirect_pin_on_unconfigured_host` (2026-11-27) |
| Yarn 2/3 (cacheKey 7/8) | pass apply + rollback 2.4.2, 3.8.7 (2026-11-27) | refused by design (2026-11-27) | refused by design (2026-11-27) |
| PnP refusal (`.pnp.cjs`, `${}` linker, `.env.yarn`) | pass 4.0.2/4.18.1 (run 46-48, before 2026-11-11: untested) | same | same |
| Workspaces, `catalog:`, member adds, aliases | pass 4.0.2/4.18.1 (runs 38-48, untested since 2026-11-11 except catalog hosted) | untested since 2026-11-11 | catalog: pass 4.19.0 (2026-11-27) |
| Renamed copies (`portal:`/`link:`/`file:`/`exec:`/`github:`) | n/a | pass 4.18.1 (run 48; untested since 2026-11-11) | same |
| Custom registry / `npmScopes` / env registry rollback | n/a | pass (runs 39-41; untested since 2026-11-11) | same |
| compressionLevel, CRLF / mixed EOL, BOM, zero-install cache | pass (runs ≤45; untested since 2026-11-11) | same | same |
| Takeovers (hosted↔vendored), interrupts (SIGKILL), journals | pass (runs 33-37; untested since 2026-11-11) | same | same |
| Unreadable vendor ledger (#2250) | n/a | rollback/remove/`--revert`/`--check` report `vendor_state_unreadable`, nothing written: pass 4.19.0 (2026-11-27) | n/a |
| Stray `MODULE.bazel` (empty, or rules_js dep without a translate) | n/a | unaffected: pass 4.19.0 (2026-11-27) | same |
| Repo berry e2e suites (redirect, vendor, pnpm linker, workspaces, PnP safety) | 74/74 pass 4.19.0 (2026-11-27) | same | same |
| Zero-install `.yarn/cache` + `yarn install --immutable --immutable-cache` | n/a | YN0056 after the pin, no warning: known docs gap (re-confirmed 4.19.0, 2026-11-27) | same |
| Global `-g` | pass 4.12.0 (pre-v5) | n/a | refused |

## Backlog

1. Re-run the repo berry e2e suites (`SOCKET_PATCH_YARN_BERRY_VERSION=<new> SOCKET_PATCH_YARN_E2E_REQUIRED=1`, five suites, 74 tests) on the next yarn release; 4.19.0 passed 74/74 in run 49.
2. Re-run on 4.19.0 the untested-since-2026-11-11 rows: renamed copies, PnP refusal shapes, compressionLevel/CRLF, custom-registry rollback, takeovers.
3. Mirror: workspace member `get <uuid>` and `scan --prune`/`repair` under a mirror; a mirror pin with `SOCKET_PATCH_MIRROR_URL` unset on another machine (rollback says only "Manifest not found"; decide if that is friction worth filing); a mirror on the pnpm linker.
4. Mirror friction candidate: `redirect_mirror_pin_not_moved` comes with two misleading extra warnings (`redirect_yarn_berry_unsupported_protocol` calling Socket's own pin an `http:` protocol entry, and `redirect_yarn_berry_entry_not_found`). Check whether the Bun/vlt siblings do the same before filing.
5. `report` command (#2193) and `vex --grype-config` (#2252) on a berry project.
6. Zero-install `--immutable-cache` YN0056 is listed as a docs gap in known-non-bugs (never filed). It breaks Yarn's recommended zero-install CI check silently; a maintainer may want to reconsider. Don't file it unless that line is removed.
7. A berry project that Bazel does build (rules_js `npm_translate_lock` reading a lock), only if rules_js can read a berry lock at all.

## Known non-bugs

Full list: `known-non-bugs/yarn-berry.md` (search it with `git grep`). The ones most likely to be re-filed:

- Yarn 2/3 (cacheKey 7/8) are refused by hosted and vendored mode; agent mode works.
- PnP projects with a `.pnp.cjs` are refused in every mode with `yarn_pnp_unsupported`.
- v5 rollback/remove/list treat only `patch.socket.dev`, `--patch-server-url` or the mirror base as hosted pins; a mock host without the flag reads as "Manifest not found".
- v5 `rollback` drops the agent manifest entry, so a later `apply` is a no-op.
- The default `scan` mode is hosted; pass `--mode agent` for the manifest flow.
- Hosted vex on a tree that wasn't reinstalled reports `not_applied` (correct).
- An uppercase scheme in `SOCKET_PATCH_MIRROR_URL` (`HTTP://`) is a usage error (exit 2); an uppercase host works.
- Mixed CRLF/LF `yarn.lock` is refused by both modes (`*_mixed_line_endings`).
- `compressionLevel: mixed` / non-zero is refused (`*_cache_unsupported`).
- Zero-install committed `.yarn/cache`: hosted is lock-only and the cache entry is replaced on install (documented).
