[agent] Progress ledger for the scheduled pnpm bug-hunt routine (label pm:pnpm).

Last updated: 2026-10-01 (run 6), main `61cfb9b` (#365, #414 merged), latest release 4.0.0.

Method: real pnpm installs. Hosted, vendored and global agent mode run against a local Python mock of the patch API (batch, by-package, view with inline blobs, package grant, hosted tarball, `/registry/<name>/<ver>` mirror). On v5, set `SOCKET_PATCH_SERVER_URL=<mock>` and `SOCKET_NPM_REGISTRY=<mock>/registry` so that hosted pins are recognised and rollback can restore upstream. The oracle is a marker prepended to `index.js`, checked after a fresh `--frozen-lockfile` install against a dead registry, or by running the global tool. The repo's pinned matrix (`.github/workflows/pnpm-compatibility.yml`) already covers plain hosted and vendored installs on pnpm 1–12. This ledger tracks what it doesn't.

## Coverage matrix

Project modes (cells before run 3 were tested on main `f6b7fb9`; "v5" marks cells re-run on `2463257`):

| OS | pnpm | Agent: default `.pnpm` | Agent: global virtual store | Agent: custom virtualStoreDir | Agent: hoisted | Vendored: plain / hoisted | Vendored: workspace-file edge shapes | Hosted: plain / catalog | Hosted: trustLockfile edge shapes | Takeover vendored ⇄ hosted |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 7.33.7 | untested | n/a | untested | untested | untested | n/a | pass (lock 5.4) | n/a (no trust) | untested |
| Linux | 8.15.9 | pass | n/a | pass (#365) | untested | untested | n/a | pass (lock 6.0) | n/a (no trust) | untested |
| Linux | 9.15.9 | pass | n/a | pass (#365) | untested | untested | untested | pass / pass; v5 rollback pass | untested | untested |
| Linux | 10.0.0 | untested | n/a | untested | untested | untested | pass (10.0 ignores user overrides) | untested | untested | untested |
| Linux | 10.5.2 / 10.12.1 | untested | fail #361 #362 (10.12.1) | untested | untested | untested | fail #360 | untested | untested | untested |
| Linux | 10.34.5 | pass | fail #361 #362 | pass (#365) | untested | pass | fail #360 (v5 too) | pass / pass; v5 rollback pass | fail #400 #402 | untested |
| Linux | 11.27.0 / 11.28.3 | pass | fail #361 #362 | pass (#365) | pass | pass | fail #400 #402 | pass / pass; v5 rollback pass | fail #400 #402; pass CRLF, no-EOL, comment | v5 pass (#401 closed: `pnpm_trust_lockfile_left` warning) |
| Linux | 12.8.1 | pass | fail #361 #362 | pass (#365) | untested | pass; fail #466 with `packageManager` (two-doc lock) | fail #400 #402 | pass / pass; v5 rollback pass; two-doc lock pass | fail #400 #402 | v5 pass (#401 closed); vendored→hosted on two-doc lock fail #466 |
| macOS | 10.34.5 | pass | n/a on CI (pnpm 10 disables it) | fail #362 | untested | untested | untested | untested | untested | untested |
| macOS | 11.27.0 / 12.8.1 | pass | fail #361 #362 | fail #362 | untested | untested | untested | untested | untested | untested |
| Windows | 10.34.5 | pass | n/a on CI | fail #362 | untested | untested | untested | untested | untested | untested |
| Windows | 11.27.0 / 12.8.1 | pass | fail #361 #362 | fail #362 | untested | untested | untested | untested | untested | untested |

Run 6 additions (main `61cfb9b`, Linux):

| pnpm | Hosted: `sharedWorkspaceLockfile: false` | Hosted: `configDependencies` (two-doc on 11+) | Vendored: `configDependencies` | Hosted: catalogs / peer-suffixed instances | Hosted: node-linker=hoisted | Agent: hard-linked CAS store |
| --- | --- | --- | --- | --- | --- | --- |
| 8.15.9 | fail #492 | untested | untested | untested | untested | untested |
| 9.15.9 | fail #492 | n/a | n/a | pass / pass | pass | pass (hardlink broken, store pristine) |
| 10.34.5 | fail #492 | pass (single doc) | pass | pass / untested | untested | untested |
| 11.28.3 | fail #492 | pass (both docs pinned) | fail #466 (wrong doc, success) | pass / pass | untested | untested |
| 12.8.1 | fail #492 | pass (both docs pinned) | fail #466 (wrong doc, success) | pass / pass | pass | pass |

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
1. Delete the stale probe branch `bughunt/pnpm/20260930-virtual-store`. `git push --delete` failed through the git proxy in runs 1 and 3, and was denied by the permission policy in runs 2, 5 and 6, so a maintainer needs to do it. macOS and Windows probes stay on hold until branch cleanup works.
2. Re-verify #492 (also on pnpm 7 / lock 5.4, plus rollback and vex once member locks are pinned) and #466 (both the `packageManager` and the `configDependencies` triggers) when fixes land.
3. Hosted Rush / subspace locks with a real `rush install`, including `preventManualShrinkwrapChanges`.
4. Agent: `dependenciesMeta.injected`, `package-import-method=clone|copy`, and pnpm 1–6 legacy layouts (Node 16).
5. Vendored on Windows and macOS (autocrlf: expect the `vendor_lockfile_crlf_unsupported` refusal; check that hosted handles the same checkout). Needs a probe branch.
6. Re-verify #360, #361, the global-virtual-store half of #362, and #435 when fixes land.

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
