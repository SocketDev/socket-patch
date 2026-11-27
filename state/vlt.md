[agent] Progress ledger for the scheduled vlt bug-hunt routine (label pm:vlt).

Last run: 2026-11-27, main `cfc870f`, release v5.1.0, newest vlt **1.9.0** (2026-11-27; 1.5.x … 1.8.2 also published since run 27). Compacted this run: older per-run cells and the mock notes are in this file's branch history (2026-10-17 version); known non-bugs moved to `known-non-bugs/vlt.md`.

Method: real vlt (`scripts/install-vlt.sh <ver> <prefix>`) against a local Node mock of the npm registry plus the patch API: the `mock.mjs` in #1494 (left-pad + right-pad 1.3.0, patchable), started on :18555 (registry) and :18556 (`SOCKET_PATCH_SERVER_URL`, `SOCKET_API_URL`), `SOCKET_NPM_REGISTRY` = :18555, `vlt.json` `config.registries.npm` = :18555. Add a non-patchable `wrapper@1.0.0` → `left-pad@1.3.0` for transitive shapes. Isolate vlt's XDG dirs per project, outside the project. Run `vlt install` / `vlt ci` with `--allow-scripts :scripts` (the sandbox blocks vlt's security-data fetch). Oracle: `require('left-pad')` prints `patched` / `pristine`. Kill mocks with `pkill -f '^node .*mock[.]mjs'`. Release binaries download from the GitHub release assets (`socket-patch-x86_64-unknown-linux-gnu.tar.gz`). Linux only (probe branches off by instruction).

## Coverage matrix

Cells tested before 2026-11-11 count as untested for the release (see INSTRUCTIONS).

| Workflow (Linux) | Hosted | Vendored | Agent |
| --- | --- | --- | --- |
| Common path, 2 root deps: scan → `vlt ci` → patched → vex → re-run → rollback byte-exact → `vlt ci` pristine | pass 1.9.0 (2026-11-27); rollback note false: #2323 | pass 1.9.0 incl. frozen install, `vendor --check` (2026-11-27); rollback note false: #2323 | pass 1.9.0 (2026-11-27) |
| Workspace (root + 2 members, member alias `npm:left-pad`, `workspace:*` edge) | pass 1.9.0 (2026-11-27) | pass 1.9.0 (2026-11-27) | pass 1.9.0 (2026-11-27) |
| Transitive target (`wrapper` → left-pad), alone and beside a direct dep | pass 1.9.0: pinned, `vlt ci` patched, vex (2026-11-27) | refused `vendor_vlt_transitive_unsupported`, untouched (documented; 2026-11-27) | pass 1.9.0 (2026-11-27) |
| Rollback note accuracy (`reinstall_required`) | fail #2323 (1.2.0 / 1.4.0 / 1.8.2 / 1.9.0, main and v5.1.0) | fail #2323 | n/a |
| Common path on vlt 1.2.0 / 1.4.0 / 1.8.2 | scan / ci / rollback pass (2026-11-27, via #2323 repro); vex untested | same | untested |
| Older eras (0.0.0-x, rc.5, rc.14, 1.0.10) | untested since 2026-10 (last pass run 16 / 18) | untested since 2026-10 | untested |
| `pnpm-workspace.yaml` workspaces, stray member locks, glob shapes (#1542 / #1564 / #1584 fixed) | untested since fix (Oct) | untested since fix | untested |
| Named / scoped / jsr registries (hint fixed by #1601) | untested since fix | untested since fix | untested since 2026-10 |
| Lifecycle scripts (`preprepare` / `postprepare`, #1633 fixed) | untested since fix | untested since fix | n/a |
| Brotli `tar.br` alternates (`NO_ALT=`) | untested since 2026-10 (#941 closed not_planned) | untested since 2026-10 | untested |
| Peer variants (`~peer.<hex>`), graph modifiers | untested since 2026-10 | refused, documented | untested since 2026-10 |
| Agent added file under a shipped empty dir | n/a | n/a | fail #862 (needs-human) |
| Global mode `-g` (npm prefix, vlt project in cwd) | untested since 2026-10 | untested since 2026-10 | untested since 2026-10 |
| macOS / Windows | untested (probes off) | untested | untested |

## Backlog

1. vlt 1.5 … 1.9 changelog: find what changed (store linker defaults, lock save rules, new DepID shapes) and test each against hosted / vendored. The docs Releases table still stops at 1.3.8; check whether the nightly canary flags 1.4.0 … 1.9.0.
2. Re-verify the fixed bughunt issues on 1.9.0: #1584 (nested dirs, `..` globs, no root `vlt.json`), #1601 hints, #1633 (plus `hasInstallScript` / whitespace scripts), #1564 yaml workspaces.
3. #2323 once fixed: also `remove`, `vendor --revert`, and a mixed hosted + vendored project.
4. #2254 (not bughunt, open): check after its fix that rollback / remove no longer report an unchecked lock as pinned.
5. Brotli registries and `~peer.<hex>` instances on 1.9.0.
6. Older eras on main: 1.0.10 scalar `config.registry` 3-tuple, rc.14, 0.0.0-20 advisory.
7. #862 once `patch/rollback.rs` changes (rebuild the `ADD=1` / `EMPTYDIR=1` mock).
8. `repair` from a member with an alias dep (needs a mock that serves diff archives); `--update` from a vlx cache (blocked locally).

## Known non-bugs

Full list: `known-non-bugs/vlt.md` (search it with `git grep`). Most likely to be re-filed:
- Hosted pins are recognized only on `patch.socket.dev` or `SOCKET_PATCH_SERVER_URL`; a mock without it gives "Manifest not found".
- vlt cold-cache "Failed to fetch security data" in the sandbox: use `--allow-scripts :scripts`.
- A hosted scan or rollback deletes the stale store copies, so `require` fails until `vlt ci` (documented, warned).
- Agent-mode patches disappear after `rm -rf node_modules && vlt ci` (expected).
- `vendor_vlt_transitive_unsupported` and `vendor_lock_entry_unsupported` (peer / modifier variants, named registries) are documented fail-closed refusals.
- vlt re-saves CRLF locks as LF; a BOM lock is unreadable by vlt itself.
- `vlt update` re-resolves exact specs and drops a hosted pin (documented).
- A mock `/patches/batch` that answers every request gives false `partial_failure`; filter by the request body.
- #941 (brotli rollback restores gzip) was closed not_planned; don't re-file.
- `vex --json` needs `-O <file>` (`json_requires_output`).
