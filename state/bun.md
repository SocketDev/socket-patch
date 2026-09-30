[agent] Progress ledger for the scheduled Bun bug-hunt routine (label pm:bun).

Last updated: 2026-09-30 (run 1), main `f6b7fb9`, latest release 4.0.0 (previous 3.3.0).

Method: real Bun installs (GitHub release binaries) and a local Python mock of the patch API and hosted tarball route (batch, by-package, `patches/package` grant, `patches/view` with `blobContent`). The oracle is a marker in the installed file after a fresh-checkout `bun install --frozen-lockfile` with an empty cache, plus `node require` where runtime matters. The repo's own matrix (`scripts/backtest-bun.py`, `bun-compatibility.yml`) already covers plain hosted and vendored shapes across Bun 0.8.1–1.4.2, but always with `--ignore-scripts` and never in agent mode. This ledger tracks what it doesn't.

## Coverage matrix

| OS | Bun | Agent: hoisted | Agent: isolated linker | Hosted / vendored: `bun patch` (patchedDependencies) | Hosted / vendored: default-trusted lifecycle scripts | Hosted: `bun update` → vex |
| --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.1.45 | untested | n/a | untested | pass | untested |
| Linux | 1.2.23 | pass | fail #366 (opt-in) | fail #367 | pass | untested |
| Linux | 1.3.0–1.3.4 | untested | untested | untested | pass | untested |
| Linux | 1.3.5–1.3.9 | untested | untested | fail #367 (1.3.9) | fail #371 | untested |
| Linux | 1.3.14 | pass | fail #366 (default for workspaces) | fail #367 | fail #371 | untested |
| Linux | 1.4.2 | pass | fail #366 (default for workspaces) | fail #367 (text + lockb) | fail #371 | pass |
| macOS | 1.2.23 | pass | fail #366 | fail #367 | untested | untested |
| macOS | 1.3.4 | untested | untested | untested | pass | untested |
| macOS | 1.3.5 | untested | untested | untested | fail #371 | untested |
| macOS | 1.3.14 / 1.4.2 | pass | fail #366 | fail #367 | fail #371 (1.4.2) | untested |
| Windows | 1.2.23 | pass | fail #366 | fail #367 | untested | untested |
| Windows | 1.3.4 | untested | untested | untested | pass | untested |
| Windows | 1.3.5 | untested | untested | untested | fail #371 | untested |
| Windows | 1.3.14 / 1.4.2 | pass | fail #366 (bunfig); default-workspace cell inconclusive | fail #367 | fail #371 (1.4.2) | untested |

Other passes (Linux, 1.4.2): agent `scan --global` on Bun globals; the `setup` hook in a Bun-only PATH; a hosted scoped rollback restoring a user `bun patch`.

## Backlog

0. Delete the stale probe branches `bughunt/bun/20260930-isolated-bunpatch` and `bughunt/bun/20260930-default-trust`. The git proxy refused `git push --delete` in run 1.
1. Agent + isolated linker on Windows (junctions), and the Windows default-workspace `bun install` exit 1.
2. `bun.lockb` hosted ⇄ vendored takeover and scoped rollback / remove with two patched packages, one of them workspace-only (1.2.23 vs 1.4.2).
3. The digest boundary (1.3.9 vs 1.3.10) with a tampered hosted tarball on a `bun.lockb` project.
4. `overrides` / `resolutions` targeting the patched package, and `catalog:` specs in workspaces (Bun 1.3+).
5. Lockfile-only vendored `scan` on Bun 1.1.45 (lockfileVersion 0), CRLF + BOM `package.json`.
6. Agent `rollback` with a mock that serves before-blobs (run 1's mock lacked them).

## Known non-bugs

- `patches-api.socket.dev` is blocked by the sandbox proxy. Mock the API; `mkpatch` + `mock.py` are described in the run-1 entry.
- Agent `rollback` → `missing_blob` when the fixture has no before-blob in `.socket/blobs` and the mock serves none.
- Bun 1.2.23 workspaces default to the hoisted layout (isolated only via `linker = "isolated"`). From Bun 1.3.x a fresh workspace lock (`configVersion: 1`) defaults to isolated.
- The `setup` hook's `npx @socketsecurity/socket-patch …` works in Bun-only environments: Bun's script runner maps `npx`.
- esbuild after rewiring: `bun pm untrusted` lists it, but nothing observable breaks (its binary comes via optionalDependencies). Use a native-build package (better-sqlite3) to observe #371.
- Documented refusals (see docs/testing/bun-compatibility.md): a version-0 workspace lock in hosted mode (`redirect_bun_workspace_unsupported`), a pre-v2 workspace lock in vendored mode (`vendor_bun_workspace_unsupported`), and missing digest enforcement on Bun < 1.3.10.
- Agent-mode npm aliases under Bun are #356 (npm-owned, same `find_by_purls` path), not a separate Bun bug.
