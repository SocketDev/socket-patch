[agent] Progress ledger for the scheduled Bun bug-hunt routine (label pm:bun).

Last updated: 2026-10-01 (run 3), main `2463257` (v5 consolidation, #277), latest release 4.0.0.

Method: real Bun installs (npm `@oven/bun-*` or GitHub release binaries) and a local Python mock of the patch API: batch, by-package, the `patches/package` grant, `patches/view` with blob contents, `blob/<hash>`, the hosted tarball route, and a `/registry/` passthrough for `SOCKET_NPM_REGISTRY`. Set `SOCKET_PATCH_SERVER_URL` to the mock. The oracle is the marker bytes after a fresh-checkout `bun install --frozen-lockfile` with an empty cache, plus byte comparison of the lockfiles and `node require` where runtime matters. The repo's own matrix (`scripts/backtest-bun.py`, `bun-compatibility.yml`) already covers plain hosted and vendored shapes across Bun 0.8.1–1.4.2. It always runs with `--ignore-scripts` and never in agent mode, and it never runs `vex` on an isolated-linker tree. This ledger tracks what it doesn't.

## Coverage matrix

| OS | Bun | Agent: hoisted | Agent: isolated linker | Hosted/vendored: `bun patch` | Hosted/vendored: default-trusted scripts | Hosted → `vex`: isolated linker | Hosted rollback/remove byte-exact (text lock) | `bun.lockb` takeover ⇄ revert |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.1.45 | untested | n/a | untested | pass | n/a | pass (v0) | untested |
| Linux | 1.2.23 | pass | fail #366 (opt-in) | fail #367 | pass | fail #405 (opt-in) | untested | untested |
| Linux | 1.3.0–1.3.4 | untested | untested | untested | pass | untested | untested | untested |
| Linux | 1.3.5–1.3.9 | untested | untested | fail #367 (1.3.9) | fail #371 | untested | untested | untested |
| Linux | 1.3.14 | pass | fail #366 (default for workspaces) | fail #367 | fail #371 | fail #405 | pass (v1, workspace, catalog) | untested |
| Linux | 1.4.2 | pass | fail #366 (default for workspaces) | fail #367 (text + lockb) | fail #371 | fail #405 | pass (v2, alias, overrides) | pass (semantic; not byte-exact, see Known non-bugs) |
| macOS | 1.2.23 | pass | fail #366 | fail #367 | untested | fail #405 | untested | untested |
| macOS | 1.3.4 / 1.3.5 | untested | untested | untested | pass / fail #371 | untested | untested | untested |
| macOS | 1.3.14 / 1.4.2 | pass | fail #366 | fail #367 | fail #371 (1.4.2) | fail #405 | untested | untested |
| Windows | 1.2.23 | pass | fail #366 | fail #367 | untested | fail #405 | untested | untested |
| Windows | 1.3.4 / 1.3.5 | untested | untested | untested | pass / fail #371 | untested | untested | untested |
| Windows | 1.3.14 / 1.4.2 | pass | fail #366 (bunfig) | fail #367 | fail #371 (1.4.2) | fail #405 (bunfig + default workspace) | untested | untested |

### Global mode (`-g`, agent; run 3)

| OS | Bun | default layout: scan report / apply / vex / rollback / get | `BUN_INSTALL_BIN` set | `BUN_INSTALL_GLOBAL_DIR` set | npm-installed bun (shim only) | `-g --mode hosted` refusal |
| --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.1.45 / 1.2.23 / 1.3.14 / 1.4.2 | pass | fail #443 | fail #443 | pass (1.4.2) | pass |
| macOS | 1.1.45 / 1.2.23 / 1.3.14 / 1.4.2 | pass | fail #443 | fail #443 | pass | pass |
| Windows | 1.3.14 / 1.4.2 | pass | fail #443 | fail #443 | fail #434 (`bun.cmd`) | pass |
| Windows | 1.1.45 / 1.2.23 | blocked (`bun add -g` failed in the probe's space+unicode temp path) | blocked | blocked | blocked | untested |

Untested: a non-writable global dir, a symlinked `BUN_INSTALL`, and Bun 1.0.x.

Other passes (Linux, 1.4.2 unless noted):
- Run 1: agent `scan --global`, and the (pre-v5) `setup` hook.
- Run 3: `SOCKET_GLOBAL=1` ≡ `-g`; `SOCKET_GLOBAL_PREFIX` / `--global-prefix` scan only that dir; `scan -g` inside a project with a bunfig setting `globalDir` doesn't leak project dirs; `vex` without `-g` ignores global copies.
- Run 2:
  - Agent scan → vex → rollback, with no cache write-through.
  - `remove`, `repair` and `list` on hosted pins.
  - Hosted `bun.lockb` idempotency, `--dry-run`, and the rollback refusal.
  - Vendored `catalog:` and `overrides`.
  - Lockfile-only vendored scan on 1.1.45 v0 with a CRLF + BOM `package.json`.
  - A corrupt served tarball rejected on 1.3.9, 1.3.10 and 1.4.2, text + lockb.

## Backlog

0. **Maintainer request (partly covered in run 3):** global (`-g`) mode for hosted patches. Still to do: a non-writable global dir must fail loudly; a symlinked `BUN_INSTALL`; Windows 1.1.45/1.2.23 with an ASCII temp path; Bun 1.0.x. Re-test #443 and #434 (`bun.cmd`) once PR #442 lands. Checklist: the 20261001T040000Z entry.
1. A maintainer needs to delete the probe branches `bughunt/bun/20260930-default-trust`, `bughunt/bun/20260930-isolated-bunpatch`, `bughunt/bun/20261001-vex-isolated` and `bughunt/bun/20261001-global-dirs`. The sandbox can't delete branches.
2. A hosted → vendored takeover on a v1 workspace lock (1.3.14). It must refuse before writes and leave the hosted pin untouched. Check `--dry-run` parity.
3. `vex` on a vendored project with the isolated linker: does `vendored_tree_out_of_sync` fire for a stale `.bun/` copy?
4. Windows agent mode with the isolated linker (junctions) once #366 lands. VEX after a real frozen hosted install on Windows.
5. v5 `socket.yml` policy and per-run limits in a Bun workspace.
6. Hosted rollback on macOS and Windows (CRLF lock on Windows checkouts with `core.autocrlf`).
7. Digest boundary with a valid substitute tarball, 1.3.9 text lock vs 1.3.10. Low priority: Bun < 1.3.10 is a documented limitation.

## Known non-bugs

- `patches-api.socket.dev` is blocked by the sandbox proxy. Mock the API. Also, the CLI's reqwest can't reach `registry.npmjs.org` from the sandbox (curl can), so hosted rollback/remove need `SOCKET_NPM_REGISTRY` pointed at a local passthrough. Without it you get `cannot restore … error sending request`, which is a sandbox artifact.
- Agent `rollback` → `missing_blob` when the mock serves no before-blob (fixture limit).
- v5 `rollback` removes the rolled-back entries from `.socket/manifest.json`, so a later `apply` is a success no-op (CLI_CONTRACT `rollback` row).
- Hosted `bun.lockb` pins: `rollback` / `remove` refuse with the `git checkout -- bun.lockb` remedy (documented). After a hosted → vendored → `vendor --revert` round trip, `bun.lockb` is semantically identical (same `bun pm hash` and yarn dump) but not byte-identical: its string buffer keeps the dead URLs. The doc promises a byte-exact *registry record*, not the whole file.
- Bun 1.2.23 workspaces default to the hoisted layout (isolated only via `linker = "isolated"`). From Bun 1.3.x a fresh workspace lock defaults to isolated.
- `setup` was removed in v5 (#277). The run-1 `setup` pass is obsolete.
- esbuild after rewiring is listed by `bun pm untrusted` but has no observable effect. Use better-sqlite3 to observe #371.
- Documented refusals (docs/testing/bun-compatibility.md): a version-0 workspace lock in hosted mode (`redirect_bun_workspace_unsupported`), a pre-v2 workspace lock in vendored mode (`vendor_bun_workspace_unsupported`), and missing digest enforcement for text-lock URL/local tuples on Bun < 1.3.10.
- Agent-mode npm aliases under Bun are #356 (npm-owned).
- `--global-prefix` must name the `node_modules` dir itself (`~/.bun/install/global/node_modules`). Its parent scans 0 packages; the flag is documented as the packages root.
- `-g` combined with `--mode hosted` is a clap-level conflict: plain-text error, exit 2, no JSON envelope even with `--json`. Consistent with other usage errors.
- `bun pm bin -g` ignores a project-local `bunfig.toml`, so `scan -g` inside a project can't be redirected by the project.
