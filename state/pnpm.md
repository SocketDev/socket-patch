[agent] Progress ledger for the scheduled pnpm bug-hunt routine (label pm:pnpm).

Last updated: 2026-09-30 (run 1), main `f6b7fb9`, latest release 4.0.0 (previous 3.3.0).

Method: real pnpm installs with a hand-staged `.socket/manifest.json` plus blobs (agent and vendored), and a local Python mock of the patch API and hosted tarball route (hosted). The oracle is a marker prepended to `index.js`, checked through Node resolution. The repo's pinned matrix (`.github/workflows/pnpm-compatibility.yml`) already covers plain hosted and vendored installs on pnpm 1–12. This ledger tracks what it doesn't.

## Coverage matrix

| OS | pnpm | Agent: default `.pnpm` | Agent: global virtual store | Agent: custom virtualStoreDir | Agent: hoisted | Vendored: plain / hoisted | Vendored: user overrides in pnpm-workspace.yaml | Hosted: trustLockfile variants |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 7.33.7 | untested | n/a | untested | untested | untested | n/a | untested |
| Linux | 8.15.9 / 9.15.9 | pass | n/a | fail #362 | untested | untested | n/a | untested |
| Linux | 10.0.0 | untested | n/a | untested | untested | untested | pass (10.0 ignores them) | untested |
| Linux | 10.5.2 / 10.12.1 | untested | fail #361 #362 (10.12.1) | untested | untested | untested | fail #360 | untested |
| Linux | 10.34.5 | pass | fail #361 #362 | fail #362 | untested | pass | fail #360 | untested |
| Linux | 11.27.0 | pass | fail #361 #362 | fail #362 | pass | pass | pass | pass (CRLF, no-EOL, comment); fail on whole-flow / `...` files (unfiled, backlog 1) |
| Linux | 12.8.1 | pass | fail #361 #362 | fail #362 | untested | untested | pass | untested |
| macOS | 10.34.5 | pass | n/a on CI (pnpm 10 disables it) | fail #362 | untested | untested | untested | untested |
| macOS | 11.27.0 / 12.8.1 | pass | fail #361 #362 | fail #362 | untested | untested | untested | untested |
| Windows | 10.34.5 | pass | n/a on CI | fail #362 | untested | untested | untested | untested |
| Windows | 11.27.0 / 12.8.1 | pass | fail #361 #362 | fail #362 | untested | untested | untested | untested |

## Backlog

0. Delete the stale probe branch `bughunt/pnpm/20260930-virtual-store`. The git proxy refused `git push --delete` in run 1, so a maintainer needs to do it.
1. Whole-document flow `pnpm-workspace.yaml` (`{packages: [.]}`), or one ending in `...`: the hosted `trustLockfile: true` append (`plan_workspace_trust`, crates/socket-patch-cli/src/commands/scan/hosted.rs:386) and the vendored `overrides:` append both produce YAML pnpm can't parse, while reporting success. Reproduced on pnpm 11.27.0. Confirm on 10 and 12, then file.
2. Hosted: pnpm 7/8 workspaces with catalogs, peer-suffixed instances, Rush/subspace locks, `--frozen-lockfile --offline` with a warm store (mock harness: `mock.py` in the run-1 entry's method).
3. Vendored ⇄ hosted takeover on pnpm 11/12, and byte-exact rollback of `pnpm-workspace.yaml` after both edits.
4. Agent: `dependenciesMeta.injected`, `package-import-method=clone|copy`, pnpm 1–6 legacy layouts (Node 16).
5. Vendored on Windows and macOS (autocrlf checkouts: expect the documented `vendor_lockfile_crlf_unsupported` refusal; check that it fires and that hosted handles the same checkout).

## Known non-bugs

- `patches-api.socket.dev` is blocked by the sandbox proxy. Stage `.socket/` locally or mock the API.
- pnpm 10 ignores `enableGlobalVirtualStore` when `CI` is set, so the global-virtual-store cells don't engage on GH runners with pnpm 10.
- pnpm 12 (and 11) ignore `.npmrc` for `virtual-store-dir` / `enable-global-virtual-store`. Put them in `pnpm-workspace.yaml`.
- Vendored refusals that are intended, loud and fail-closed: a CRLF `pnpm-lock.yaml` or `pnpm-workspace.yaml` (`vendor_lockfile_crlf_unsupported`), a BOM package.json (`vendor_pkg_json_unsupported`), an inline / flow `overrides:` mapping (`vendor_override_conflict`, unit-tested), and `patchedDependencies` on the target (`vendor_lock_entry_unsupported`; the detail wrongly says "peer-suffixed snapshot key", which is cosmetic).
- Vendored `vex` attests from the committed artifact plus lock wiring even when the tree isn't installed. That's by design (CLI_CONTRACT "Manifest-less VEX").
- Agent rollback needs the *before* blob in `.socket/blobs`, so fixtures must stage both blobs (`missing_blob` otherwise). VEX needs `setup.manual: ["npm"]` or a setup hook (`ecosystem_not_setup`).
- A `vex --output /dev/stdout` hang when stdout is a pipe is not pnpm-specific.
