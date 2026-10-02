[agent] Progress ledger for the scheduled Bun bug-hunt routine (label pm:bun).

Last updated: 2026-10-02 (run 6), main `61cfb9b`, latest release 4.0.0, latest Bun 1.4.2.

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

### Bundled dependencies (`bundled: true` lock entries; run 4)

| OS | Bun | lock | hosted scan warns/skips | vendored scan warns/skips | bundled copy patched after frozen install | vendored `vex` | hosted `vex` | hosted `vex --no-verify` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.1.45 | text v0 / lockb | fail #469 | fail #469 | fail #469 | fail #469 (attests) | pass (`not_applied`) | fail #469 |
| Linux | 1.2.23 / 1.3.14 | text v1 | fail #469 | fail #469 | fail #469 | fail #469 | pass | fail #469 |
| Linux | 1.4.2 | text v2 / lockb | fail #469 | fail #469 | fail #469 | fail #469 | pass | fail #469 |
| macOS, Windows | all | all | untested | untested | untested | untested | untested | untested |

### Non-registry copies of a patched `name@version` (run 5, Linux)

| Bun | lock | URL tgz + nested registry copy: scan warns | root copy patched after frozen install | vendored `vex` | hosted `vex` | hosted `vex --no-verify` | URL-only refusal |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1.1.45 | text v0 | fail #497 | fail #497 | fail #497 (attests) | pass (`not_applied`) | fail #497 | untested |
| 1.2.23 | text v1 | fail #497 | fail #497 | fail #497 | pass | fail #497 | untested |
| 1.3.14 | text v1 | fail #497 | fail #497 | fail #497 | pass | untested | untested |
| 1.4.2 | text v2 (URL and `file:` tgz) | fail #497 | fail #497 | fail #497 | pass | fail #497 | pass |
| 1.1.45 (read by 1.1.45 / 1.2.23 / 1.4.2) | `bun.lockb` (URL tgz; run 6) | fail #497 | fail #497 | fail #497 | pass | fail #497 | untested |
| any | `github:` tuples | untested | untested | untested | untested | untested | untested |
| macOS, Windows | all | untested | untested | untested | untested | untested | untested |

### `socket.yml` policy and staged rollout (run 6, Linux)

| Bun | lock | hosted `maxNewPatches: 1` advance | vendored `maxNewPatches: 1` advance | vendored → hosted takeover under cap | `ignorePackages` keeps pin | `enabled: false` writes nothing | hosted upgrade (new uuid) | rollback after upgrade |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1.1.45 | lockb (workspace) | pass | untested | untested | pass | pass | pass | n/a (refuses, documented) |
| 1.3.14 | text v1 (workspace) | pass | untested | untested | untested | untested | pass | pass (byte-exact) |
| 1.4.2 | text v2 (workspace) | pass | pass | pass | pass | pass | untested | untested |
| macOS, Windows | all | untested | untested | untested | untested | untested | untested | untested |

Also passing in run 6: a dual-lock checkout (`bun.lock` + a stale `bun.lockb`, where Bun ≥ 1.2 reads `bun.lock` and hosted rewrites only it), and global mode with a symlinked `BUN_INSTALL` (1.4.2: agent scan, `vex -g`, `rollback -g`).

### Lock-shape edge cases (run 5, Linux)
- CRLF `bun.lock` + CRLF `package.json` (1.1.45 v0, 1.3.14, 1.4.2): hosted scan → frozen install → `rollback`, and vendored → `vendor --revert`. Both byte-exact: pass.
- `bun install --yarn` (sibling `yarn.lock`), on 1.1.45 lockb, 1.2.23 and 1.4.2: hosted rewires both locks; lockb `rollback` refuses and touches neither file: pass.
- `[install.scopes]` custom-registry scope (1.3.14, 1.4.2): hosted rewrite and byte-exact rollback: pass.
- 1.1.45 binary workspace lock, hosted, read by 1.1.45 / 1.2.23 / 1.3.14 / 1.4.2. Frozen installs are patched, the takeover refuses as documented, and `vex` is correct: pass.
- `bun add` after hosted (all four versions; the pins survive) and after vendored (digest-less re-save on < 1.3.10, healed by the re-run): pass.

### Takeovers and vendored VEX (run 4, Linux)
- Hosted → vendored on a v1 workspace lock (1.3.14): pass. Refuses before any write; dry-run parity is as documented.
- Vendored + isolated linker, stale tree → `vendored_tree_out_of_sync` is missing (1.4.2): fail, under #405 (comment). Hoisted control: pass.

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

0. **Maintainer request (partly covered in runs 3 and 6):** global (`-g`) mode for hosted patches. A symlinked `BUN_INSTALL` passes (run 6). Still to do: a non-writable global dir must fail loudly (the sandbox runs as root, so it needs a probe); Windows 1.1.45/1.2.23 with an ASCII temp path; Bun 1.0.x. Re-test #443 and #434 (`bun.cmd`) once PR #442 lands. Checklist: the 20261001T040000Z entry.
1. A maintainer needs to delete the probe branches `bughunt/bun/20260930-default-trust`, `bughunt/bun/20260930-isolated-bunpatch`, `bughunt/bun/20261001-vex-isolated` and `bughunt/bun/20261001-global-dirs`. Deletion is still blocked from the sandbox (run 6), so no new probes until then.
2. #497 `github:` tuples (unresolvable in the sandbox, needs a probe). The lockb variant was confirmed in run 6. Re-test when fixed.
3. #469 follow-ups: macOS/Windows cells; `bundled` inside a workspace member; `rollback` / `remove` of a rewired bundled entry; re-test when PR #472 lands.
4. Re-test #366 once `.bun` joins the crawler walks (#365 landed without it). Then re-check the #405 vendored warning and Windows agent mode with the isolated linker (junctions).
5. `socket.yml` `includePaths` / `ignorePaths` across several independent Bun projects in one repo (shared budget, sorted visit order); `minSeverity` via `SOCKET_MIN_SEVERITY`.
6. Hosted rollback on real macOS and Windows checkouts (the Linux CRLF analog passes, run 5).
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
- Vendored `scan --dry-run` exits 0 with `status: success` and `would_refuse` while the real run exits 1 with `partial_failure`, for the same Bun preflight refusal. Documented (CLI_CONTRACT `would_refuse`).
- Vendored `vex` attests from the committed artifact even when the installed tree is stale. By design: only a `vendored_tree_out_of_sync` warning is owed.
- Hosted default `vex` on a bundled-copy project correctly refuses (`not_applied`). #469 is about vendored mode and `--no-verify`.
- `bun pm bin -g` ignores a project-local `bunfig.toml`, so `scan -g` inside a project can't be redirected by the project.
- Vendored, then `bun add`, on Bun < 1.3.10 re-saves the local tuples without `sha512`. That's documented ("Digest-less re-saves"): the vendored re-run reports `already_vendored` and re-pins the digest.
- Bun records `""` as the registry field of a tuple even when it came from an `[install.scopes]` or custom default registry, so rollback restoring `""` is correct.
- On a `bun install --yarn` project, hosted `rollback` restores `bun.lock` byte-exact but adds a `#<sha1>` fragment to Bun's `yarn.lock` `resolved` lines. It's semantically equivalent and yarn-classic's rewriter, so it isn't filed as a Bun bug.
- Mock fixture: build the patched tarball with a fixed gzip mtime. Otherwise a mock restart changes its sha512 and later installs fail `IntegrityCheckFailed`.
- `link:` deps need `bun link` registration, and `github:` deps don't resolve in the sandbox. Both are environment limits.
- `scan <workspace-member>` (e.g. `scan packages/a`): hosted reports `success` with 0 redirected and `redirect_npm_no_lockfile`; vendored refuses with `vendor_lockfile_missing`. Pinned as today's behaviour in bun-compatibility.md ("Not measured"); scan the root instead.
- Mode-less `scan -g` is report-only. Use `--mode agent` to patch global copies. `-g` agent runs record the global copies in the cwd's `.socket/manifest.json` (by design).
- A v1/v2 text `bun.lock` can't be read by Bun 1.1.45 (`lockfile had changes, but lockfile is frozen`) even without socket-patch. When `bun.lock` and `bun.lockb` are both present, Bun ≥ 1.2 reads `bun.lock`.
- Mock fixture: `SOCKET_PATCH_SERVER_URL` must name the same origin across runs. A mock on another port makes the earlier pins non-hosted.
