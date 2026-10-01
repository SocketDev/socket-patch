[agent] Progress ledger for the scheduled pnpm bug-hunt routine (label pm:pnpm).

Last updated: 2026-10-01 (run 2), main `f6b7fb9`, latest release 4.0.0 (previous 3.3.0).

Method: real pnpm installs. Agent and vendored modes use a hand-staged `.socket/manifest.json` plus both blobs. Hosted mode uses a local Python mock of the patch API (batch, by-package, package grant, view) and the hosted tarball route. The oracle is a marker prepended to `left-pad/index.js` after a fresh `--frozen-lockfile` install against a dead registry. The repo's pinned matrix (`.github/workflows/pnpm-compatibility.yml`) already covers plain hosted and vendored installs on pnpm 1–12. This ledger tracks what it doesn't.

## Coverage matrix

| OS | pnpm | Agent: default `.pnpm` | Agent: global virtual store | Agent: custom virtualStoreDir | Agent: hoisted | Vendored: plain / hoisted | Vendored: workspace-file edge shapes | Hosted: plain / catalog | Hosted: trustLockfile edge shapes | Takeover vendored ⇄ hosted |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 7.33.7 | untested | n/a | untested | untested | untested | n/a | pass (lock 5.4) | n/a (no trust) | untested |
| Linux | 8.15.9 | pass | n/a | fail #362 | untested | untested | n/a | pass (lock 6.0) | n/a (no trust) | untested |
| Linux | 9.15.9 | pass | n/a | fail #362 | untested | untested | untested | pass / pass | untested | untested |
| Linux | 10.0.0 | untested | n/a | untested | untested | untested | pass (10.0 ignores user overrides) | untested | untested | untested |
| Linux | 10.5.2 / 10.12.1 | untested | fail #361 #362 (10.12.1) | untested | untested | untested | fail #360 | untested | untested | untested |
| Linux | 10.34.5 | pass | fail #361 #362 | fail #362 | untested | pass | fail #360 | pass / pass | fail #400 #402 | untested |
| Linux | 11.27.0 | pass | fail #361 #362 | fail #362 | pass | pass | fail #400 #402 | pass / pass | fail #400 #402; pass CRLF, no-EOL, comment | fail #401 (trust left); otherwise pass, byte-exact rollback |
| Linux | 12.8.1 | pass | fail #361 #362 | fail #362 | untested | pass | fail #400 #402 | pass / pass | fail #400 #402 | fail #401 |
| macOS | 10.34.5 | pass | n/a on CI (pnpm 10 disables it) | fail #362 | untested | untested | untested | untested | untested | untested |
| macOS | 11.27.0 / 12.8.1 | pass | fail #361 #362 | fail #362 | untested | untested | untested | untested | untested | untested |
| Windows | 10.34.5 | pass | n/a on CI | fail #362 | untested | untested | untested | untested | untested | untested |
| Windows | 11.27.0 / 12.8.1 | pass | fail #361 #362 | fail #362 | untested | untested | untested | untested | untested | untested |

"Edge shapes" means a whole-document flow mapping, a `...` document end, and quoted or `key :` top-level keys.

## Backlog

0. Delete the stale probe branch `bughunt/pnpm/20260930-virtual-store`. Run 1 failed through the git proxy, and run 2 was denied by the session permission policy, so a maintainer needs to do it. Until deletion works, new probe branches can't be cleaned up, so macOS and Windows cells are on hold.
1. Hosted: Rush / subspace locks and peer-suffixed workspace instances, using the mock harness.
2. Hosted `--frozen-lockfile --offline` with a warm store holding the upstream tarball, on pnpm 9–12. Check that `vex` doesn't attest unpatched installed bytes.
3. Agent: `dependenciesMeta.injected`, `package-import-method=clone|copy`, and pnpm 1–6 legacy layouts (Node 16).
4. Vendored on Windows and macOS (autocrlf: expect the `vendor_lockfile_crlf_unsupported` refusal; check that hosted handles the same checkout). Needs a probe branch.
5. Re-verify #360–#362 (PR #365) and #400–#402 when fixes land.

## Known non-bugs

- `patches-api.socket.dev` is blocked by the sandbox proxy. Stage `.socket/` locally or mock the API.
- pnpm 10 ignores `enableGlobalVirtualStore` when `CI` is set, so the global-virtual-store cells don't engage on GH runners with pnpm 10.
- pnpm 12 (and 11) ignore `.npmrc` for `virtual-store-dir` / `enable-global-virtual-store`. Put them in `pnpm-workspace.yaml`.
- Vendored refusals that are intended, loud and fail-closed: a CRLF `pnpm-lock.yaml` or `pnpm-workspace.yaml` (`vendor_lockfile_crlf_unsupported`), a BOM package.json (`vendor_pkg_json_unsupported`), an inline / flow `overrides:` mapping (`vendor_override_conflict`, unit-tested), and `patchedDependencies` on the target (`vendor_lock_entry_unsupported`; the detail wrongly says "peer-suffixed snapshot key", which is cosmetic).
- Vendored `vex` attests from the committed artifact plus lock wiring even when the tree isn't installed. That's by design (CLI_CONTRACT "Manifest-less VEX").
- Agent rollback needs the *before* blob in `.socket/blobs`, so fixtures must stage both blobs (`missing_blob` otherwise). VEX needs `setup.manual: ["npm"]` or a setup hook (`ecosystem_not_setup`).
- A bare `rollback` garbage-collects `.socket/blobs`. A later vendored run in a mock harness that serves no blob content then fails, and that's a fixture artifact.
- A compact single-line `package.json` comes back 2-space-indented after vendor + rollback. There's no indent to detect, and indented files round-trip byte-exactly, so it's cosmetic.
- Scoped `rollback <purl>` of the only hosted purl removes `trustLockfile` correctly (whole-ledger replay). The leftover in #401 is specific to the vendored takeover.
- A `vex --output /dev/stdout` hang when stdout is a pipe is not pnpm-specific.
