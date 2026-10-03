[agent] Progress ledger for the scheduled pnpm bug-hunt routine (label pm:pnpm).

Last updated: 2026-10-03 (run 11), main `045d7ec` (#583 pnpm vendoring refactor merged), latest release 4.0.0.

Method: real pnpm installs. Hosted, vendored and global agent mode run against a local Python mock of the patch API (batch, by-package, view with inline blobs, package grant, hosted tarball, `/registry/<name>/<ver>` mirror). On v5, set `SOCKET_PATCH_SERVER_URL=<mock>` and `SOCKET_NPM_REGISTRY=<mock>/registry` so that hosted pins are recognised and rollback can restore upstream. The oracle is a marker prepended to `index.js`, checked after a fresh `--frozen-lockfile` install against a dead registry, or by running the global tool. The repo's pinned matrix (`.github/workflows/pnpm-compatibility.yml`) already covers plain hosted and vendored installs on pnpm 1–12. This ledger tracks what it doesn't.

## Coverage matrix

Project modes (cells before run 3 were tested on main `f6b7fb9`; "v5" marks cells re-run on `2463257`):

| OS | pnpm | Agent: default `.pnpm` | Agent: global virtual store | Agent: custom virtualStoreDir | Agent: hoisted | Vendored: plain / hoisted | Vendored: workspace-file edge shapes | Hosted: plain / catalog | Hosted: trustLockfile edge shapes | Takeover vendored ⇄ hosted |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 7.33.7 | untested | n/a | untested | untested | untested | n/a | pass (lock 5.4) | n/a (no trust) | untested |
| Linux | 8.15.9 | pass | n/a | pass (#365) | untested | untested | n/a | pass (lock 6.0) | n/a (no trust) | untested |
| Linux | 9.15.9 | pass | n/a | pass (#365) | untested | untested | untested | pass / pass; v5 rollback pass | untested | untested |
| Linux | 10.0.0 | untested | n/a | untested | untested | untested | pass (10.0 ignores user overrides) | untested | untested | untested |
| Linux | 10.5.2 / 10.12.1 | untested | fail #362 (10.12.1; #361 fixed) | untested | untested | untested | fail #360 | untested | untested | untested |
| Linux | 10.34.5 | pass | #361 fixed (refusal); fail #362 | pass (#365) | untested | pass | fail #360 (v5 too) | pass / pass; v5 rollback pass | fail #400 #402 | untested |
| Linux | 11.27.0 / 11.28.3 | pass | #361 fixed (refusal); fail #362 | pass (#365) | pass | pass | fail #400 #402 | pass / pass; v5 rollback pass | fail #400 #402; pass CRLF, no-EOL, comment | v5 pass (#401 closed: `pnpm_trust_lockfile_left` warning) |
| Linux | 12.8.1 | pass | #361 fixed (refusal); fail #362 | pass (#365) | untested | pass; fail #466 with `packageManager` (two-doc lock) | fail #400 #402 | pass / pass; v5 rollback pass; two-doc lock pass | fail #400 #402 | v5 pass (#401 closed); vendored→hosted on two-doc lock fail #466 |
| macOS | 10.34.5 | pass | n/a on CI (pnpm 10 disables it) | fail #362 | untested | untested | untested | untested | untested | untested |
| macOS | 11.27.0 / 12.8.1 | pass | #361 fixed (refusal); fail #362 | fail #362 | untested | untested | untested | untested | untested | untested |
| Windows | 10.34.5 | pass | n/a on CI | fail #362 | untested | untested | untested | untested | untested | untested |
| Windows | 11.27.0 / 12.8.1 | pass | #361 fixed (refusal); fail #362 | fail #362 | untested | untested | untested | untested | untested | untested |

Run 6 additions (main `61cfb9b`, Linux):

| pnpm | Hosted: `sharedWorkspaceLockfile: false` | Hosted: `configDependencies` (two-doc on 11+) | Vendored: `configDependencies` | Hosted: catalogs / peer-suffixed instances | Hosted: node-linker=hoisted | Agent: hard-linked CAS store |
| --- | --- | --- | --- | --- | --- | --- |
| 8.15.9 | fail #492 | untested | untested | untested | untested | untested |
| 9.15.9 | fail #492 | n/a | n/a | pass / pass | pass | pass (hardlink broken, store pristine) |
| 10.34.5 | fail #492 | pass (single doc) | pass | pass / untested | untested | untested |
| 11.28.3 | fail #492 | pass (both docs pinned) | fail #466 (wrong doc, success) | pass / pass | untested | untested |
| 12.8.1 | fail #492 | pass (both docs pinned) | fail #466 (wrong doc, success) | pass / pass | pass | pass |

Run 7 additions (main `61cfb9b`, Linux):

| pnpm (lock) | Agent: transitive apply / rollback | Hosted: pin → fresh frozen → rollback | Agent: peer-suffixed | Alias `npm:` agent / hosted | Hosted: injected | Rush (hosted / vex / agent transitive) |
| --- | --- | --- | --- | --- | --- | --- |
| 2.25.7 (shrinkwrap.yaml, Node 10) | pass | pass, byte-exact | untested | untested | n/a | n/a |
| 3.8.1 (5.1, Node 16) | pass | pass, byte-exact | untested | untested | n/a | n/a |
| 4.14.4 (5.1) | pass | pass, byte-exact | untested | untested | n/a | n/a |
| 5.18.10 (5.2) | pass | pass, byte-exact | untested | untested | n/a | n/a |
| 6.35.1 (5.3) | pass | pass | untested | untested | n/a | n/a |
| 7.33.7 (5.4) | untested | pass | untested | untested / pass | untested | untested |
| 8.15.9 (6.0) | untested | pass | untested | untested / pass | pass | pass / fail #518 / untested |
| 9.15.9 (9.0) | pass | pass | pass | pass / pass | blocked (upstream pnpm bug) | pass / fail #518 / fail #518 |
| 11.28.3 | untested | pass | untested | untested / pass | untested | untested |
| 12.8.1 | pass | pass | pass | pass / pass | pass | untested |

Run 8 additions (main `61cfb9b`, Linux):

| pnpm (lock) | Agent: hoisted + npm alias (two copies) | Agent: patchedDependencies instance | Hosted: patchedDependencies (other file / same file) | Hosted: scoped pkg | Agent: import-method copy / hardlink, hoisted, alias | Vendored: legacy lock | Hosted: legacy workspace (member dep) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 5.18.10 (5.2) / 6.35.1 (5.3) | untested | untested | untested | untested | untested | pass (loud `vendor_lockfile_version_unsupported`) | untested |
| 7.33.7 (5.4) | untested | pass | untested | pass | pass | pass; moved checkout: documented recovery + byte-exact rollback; workspace refused as documented | pass |
| 8.15.9 (6.0) | untested | pass | pass / pass | pass | untested | pass, same as 7 | pass |
| 9.15.9 | fail #356 | pass | pass / pass (vex declines same-file) | pass | untested | n/a | n/a |
| 10.34.5 | fail #356 | pass | pass / pass | untested | pass | n/a | n/a |
| 11.28.3 | untested | n/a (package.json field ignored) | pass / pass | untested | pass | n/a | n/a |
| 12.8.1 | fail #356 | n/a (package.json field ignored) | pass / pass | pass | untested | n/a | n/a |

Run 9 additions (main `61cfb9b`, Linux):

| pnpm | Hosted: `gitBranchLockfile` (both locks / branch lock only) | Hosted: `lockfileIncludeTarballUrl` pin + fresh frozen | Rollback byte-exact with tarball URLs | Hosted: catalog + patchedDependencies + overrides | Hosted from workspace member cwd |
| --- | --- | --- | --- | --- | --- |
| 9.15.9 | n/a (no branch lock written) | pass | fail #557 | untested | untested |
| 10.34.5 | fail #556 / untested | pass | untested | untested | untested |
| 11.28.3 | fail #556 / untested | untested | untested | untested | untested |
| 12.8.1 | fail #556 / fail #556 | pass | fail #557 | pass (vex, rollback) | no-op + `redirect_npm_no_lockfile` (not filed; see #417) |

Run 10 additions (main `203e092`, Linux):

| pnpm | Agent: isolated / hoisted transitive (post-#486/#555) | Agent: GVS direct | Agent: GVS transitive | Hosted: member cwd / `lockfile-dir=..` | Vendored: member cwd | Vendored: `gitBranchLockfile` | Rush hosted / vex / agent transitive |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 8.15.9 | pass / pass | n/a | n/a | untested | untested | n/a | untested |
| 9.15.9 | pass / pass | n/a | n/a | fail #590 / fail #590 | pass (fails closed) | n/a | pass / pass (#518 fixed) / pass |
| 10.34.5 | pass / pass | untested | untested | fail #590 / fail #590 | untested | fail #556 (frozen install breaks) | untested |
| 11.28.3 | pass / pass | untested | untested | fail #590 / n/a | untested | fail #556 | untested |
| 12.8.1 | pass / pass | pass (#361 fixed: loud refusal) | fail #362 (now exit 0 since #555) | fail #590 / fail #590 | pass (fails closed) | fail #556 | untested |

Run 11 additions (main `045d7ec`, Linux):

| pnpm (lock) | Vendored after #583: plain / transitive / user override (frozen, vex, revert) | Vendored: 2+ packages, revert / rollback byte-exact | Agent: workspace member links (event counts) | Agent: bundled copy in another store entry (isolated / hoisted) |
| --- | --- | --- | --- | --- |
| 7.33.7 (5.4) | pass / pass / pass | fail #636 (package.json) | untested | untested |
| 8.15.9 (6.0) | pass / pass / pass | fail #636 (package.json) | untested | fail #601 / pass |
| 9.15.9 | untested | fail #636 (package.json + workspace) | fail #633 (hoisted pass) | fail #601 / pass |
| 10.34.5 | untested | fail #636 | untested (Bun saw it on 10.28.0) | fail #601 / pass |
| 11.28.3 | untested | fail #636 | untested | fail #601 / pass |
| 12.8.1 | untested | fail #636 (also 3 packages, also `rollback`) | fail #633 (hoisted pass) | fail #601 / pass |

#636 first bad commit: `09956d90` (#247). Release 4.0.0 is byte-exact.

Default isolated linker + alias: pass on 7.33.7 / 9.15.9 / 10.34.5 / 11.28.3 / 12.8.1 (one shared `.pnpm` copy).

#492 also reproduces on pnpm 7.33.7 (there's no root lock at all, only `redirect_pnpm_no_lockfile`).

Hosted `--frozen-lockfile [--offline]` over an upstream `node_modules` or warm store (run 5): VEX stays honest on 9.15.9 / 10.34.5 / 11.28.3 / 12.8.1 (pass).

"Edge shapes" means a whole-document flow mapping, a `...` document end, and quoted or `key :` top-level keys.

Global mode (`-g`, v5 main `2463257`):

| OS | pnpm | `pnpm root -g` layout | scan -g report (direct) | scan -g transitive | get/apply -g direct | rollback -g | vex -g | duplicate copies across install groups | `--mode hosted` refusal |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 7.33.7 / 8.15.9 / 9.15.9 / 10.34.5 | `global/5/node_modules`, `virtualStoreDir: ../.pnpm` | pass | fail #362 (fixed by PR #365) | pass | pass, byte-exact | pass | n/a (one shared `.pnpm`) | pass (9, 11) |
| Linux | 11.0.0 / 11.27.0 / 11.28.3 (default) | `global/v11/<hash>/` → global virtual store `store/v11/links` | pass | fail #362 (GVS half; also #361) | pass (writes the shared links dir) | pass | untested | pass (one shared copy) | pass |
| Linux | 11.28.3, `enableGlobalVirtualStore: false` | `global/v11/<hash>/node_modules/.pnpm` | untested | untested | pass | untested | untested | fail #435 | untested |
| Linux | 12.4.2 / 12.8.1 / 12.8.2 | `global/v11/<hash>/node_modules/.pnpm` | pass | pass | pass | pass, byte-exact | pass | fail #435 (regression since b32711f) | pass |
| Linux | any | unwritable global prefix | blocked (sandbox runs as root) | | | | | | |
| macOS / Windows | all | | untested | untested | untested | untested | untested | untested | untested |

## Backlog

0. **Maintainer request (global `-g` mode):** the Linux cells are done. Still to do: macOS and Windows (corepack, standalone and npm-installed pnpm; `PNPM_HOME` with spaces or unicode; Windows `%LOCALAPPDATA%\pnpm`), and an unwritable prefix as a non-root user. Full checklist in the 20261001T040000Z entry. Needs a probe branch.
1. Delete the stale probe branch `bughunt/pnpm/20260930-virtual-store`. `git push --delete` failed through the git proxy in runs 1, 3 and 10, and was denied by the permission policy in runs 2, 5–9 and 11, so a maintainer needs to do it. macOS and Windows probes stay on hold until branch cleanup works.
2. #636 follow-ups: a hosted → vendored takeover with several packages, then revert, and a user-created `pnpm` table with several vendored packages.
3. #362 GVS transitive and #435 global `-g`: re-check exit codes under #555's skip semantics on 11.28.3 / 12.8.1.
4. Rush subspaces (`common/config/subspaces/*`), and Rush + pnpm 8 / 10.
5. `pnpm patch-commit` after a hosted pin, then rollback. `package-import-method=clone` on reflink (needs CI).
6. #556 follow-ups: merging branch lockfiles after a hosted pin, and agent `vex` on the branch.
7. Re-verify #360, #362, #435, #466, #492, #556, #557, #590, #601 (PR #605), #633 and #636 when fixes land.
8. Vendored on Windows and macOS (autocrlf: expect the `vendor_lockfile_crlf_unsupported` refusal; check that hosted handles the same checkout).

## Known non-bugs

- `patches-api.socket.dev` and (for the Rust client) `registry.npmjs.org` are unreachable from the sandbox. Mock the API and point `SOCKET_NPM_REGISTRY` at a mirror.
- v5 recognises hosted pins only on the configured patch server. Against a mock without `SOCKET_PATCH_SERVER_URL`, `rollback` says "Manifest not found". That's a fixture artifact.
- v5 hosted rollback and takeover keep a user-edited `trustLockfile: true` and warn `pnpm_trust_lockfile_left`. A workspace file that exactly matches hosted mode's scaffold is deleted, including a user's own `packages: ['.']` file that the trust append made identical to it (CLI_CONTRACT, upstream restore).
- pnpm 10 ignores `enableGlobalVirtualStore` when `CI` is set, so the global-virtual-store cells don't engage on GH runners with pnpm 10.
- pnpm 12 (and 11) ignore `.npmrc` for `virtual-store-dir` / `enable-global-virtual-store`. Put them in `pnpm-workspace.yaml`, or in the global `config.yaml`.
- pnpm 11+ `pnpm root -g` / `pnpm add -g` fail unless `$PNPM_HOME/bin` is on `PATH`. Put it there in fixtures.
- Vendored refusals that are intended, loud and fail-closed: a CRLF `pnpm-lock.yaml` or `pnpm-workspace.yaml` (`vendor_lockfile_crlf_unsupported`), a BOM package.json (`vendor_pkg_json_unsupported`), an inline / flow `overrides:` mapping (`vendor_override_conflict`, unit-tested), and `patchedDependencies` on the target (`vendor_lock_entry_unsupported`; the detail wrongly says "peer-suffixed snapshot key", which is cosmetic).
- Vendored `vex` attests from the committed artifact plus lock wiring even when the tree isn't installed. That's by design (CLI_CONTRACT "Manifest-less VEX").
- `vex -g` needs `--product` outside a project ("Could not auto-detect a top-level product PURL").
- Agent-mode `get <purl>` for an uninstalled package reports `success, applied: 1` when another manifest entry applies. The nested apply fails only when nothing matches. It's not pnpm-specific (noted on #362).
- A compact single-line `package.json` comes back 2-space-indented after vendor + rollback. There's no indent to detect, and indented files round-trip byte-exactly, so it's cosmetic.
- Hosted on pnpm 9 over an existing upstream `node_modules`: a frozen install keeps the upstream bytes. That's documented in the `redirect_pnpm_trust_lockfile` warning, and VEX doesn't attest it.
- pnpm 12 warns that `package.json` `pnpm.overrides` is ignored on vendored projects. The workspace-file override is what takes effect, so this is noise only.
- A `vex --output /dev/stdout` hang when stdout is a pipe is not pnpm-specific.
- Vendored refuses pnpm catalogs (`catalogs:` entry) and peer-suffixed snapshot keys with `vendor_lock_entry_unsupported` ("this lock shape is not supported yet"). It's loud and writes nothing. Hosted handles both.
- pnpm 10's `configDependencies` copy (`node_modules/.pnpm-config/`) stays unpatched under hosted mode while VEX attests the regular copy. Config deps run only at install time, and pnpm 10 keeps their integrity in `pnpm-workspace.yaml`.
- On v5, vendoring always downloads its artifact from the patch service (`--vendor-source build` was removed), so offline vendoring with only a staged manifest fails with `vendor_service_offline_conflict`. Fixtures need the mock grant to match the manifest UUID.
- `rush update --full` re-resolves the Rush lock and drops the hosted pin, like `pnpm update`. VEX then honestly reports nothing to attest.
- pnpm 9.15.9's frozen install fails on its own unmodified lock when a workspace uses `dependenciesMeta.injected` ("importer dependencies meta (undefined) doesn't match"). That's upstream pnpm, not socket-patch.
- Old pnpm needs an old Node (≤ 6 needs Node 16, ≤ 2 needs Node 10), and pnpm 3 takes `--store` rather than `--store-dir`. Fixture notes.
- Agent apply over a pnpm `patchedDependencies` edit to the same file overwrites it with the verified patched content and warns `content_mismatch_overwritten` (documented default mismatch policy; `--strict` refuses). Hosted composes both patches, and `vex` then declines (`no_applicable_patches`), because the file matches neither hash.
- Hosted on pnpm 11/12 respects an explicit `trustLockfile: false` (any YAML spelling) and warns `redirect_pnpm_trust_lockfile` with the remedy. The following frozen install fails, which is documented.
- Vendored refuses pnpm ≤ 6 locks (5.x up to 5.3) with `vendor_lockfile_version_unsupported`, and pnpm 7/8 workspace locks with `vendor_lock_entry_unsupported`. pnpm 7/8 vendored locks carry an absolute `file:` specifier (`vendor_pnpm_legacy_absolute_specifier`), so a moved checkout needs `pnpm install --offline --no-frozen-lockfile` once. Both are documented.
- pnpm 11+ ignores `package.json` `pnpm.patchedDependencies`. Put it in `pnpm-workspace.yaml`.
- A dead-registry fresh install fails when the fixture has any unpatched dependency (it still needs the registry). Use the live registry for those fixtures, or patch every dependency.
- Vendored from a workspace member cwd fails closed with `vendor_lockfile_missing` (`partial_failure`). Hosted's silent success in the same layout is #590.
- A `package.json` without a trailing newline gains one after vendor + revert. That's a fixture artifact; files that end in a newline round-trip byte-exactly.
- Bundled-copy fixtures need a registry-served host package. A `file:` tarball host (`.pnpm/bundler@file+…`) is patched correctly, so it doesn't reproduce #601.
