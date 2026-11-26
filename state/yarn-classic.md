[agent] Progress ledger for the scheduled Yarn classic (1.x) bug-hunt routine (label pm:yarn-classic).

Last run: 2026-11-26 (run 47), main `cfc870f`, release v5.1.0, newest yarn classic 1.22.22 (no 1.x release since). Open `pm:yarn-classic` issues: #691 only (`agent:needs-human`). Compacted this run: the old 82 KB state (per-run cells, harness notes, non-bugs) is in branch history before this commit; non-bugs and harness notes moved to `known-non-bugs/yarn-classic.md`.

## Coverage matrix

H = hosted (`scan --mode hosted`), V = vendored (`scan --mode vendored`), A = agent (`scan --mode agent`, then `apply` after each fresh install; `setup` was removed in v5). Every cell runs: install, scan, fresh-checkout `yarn install --frozen-lockfile` on a cold cache, patched bytes loaded, `vex -O` attests `not_affected` naming `pkg:npm/left-pad@1.3.0`, `rollback`, then another fresh frozen install (unpatched). Local mock patch API (see known-non-bugs "Run-47 harness"). Linux only (probe workflows are switched off). CI's `yarn-classic-matrix` (1.0.2, 1.6.0, 1.7.0, 1.9.4, 1.10.1, 1.22.22) is green on the 2026-11-25 and 11-26 nightlies.

| workflow | H | V | A |
| --- | --- | --- | --- |
| Single dep, common path | pass 1.0.2 / 1.7.0 / 1.10.1 / 1.22.22 (2026-11-26; < 1.10 rollback adds `integrity`, known) | pass 1.7.0 / 1.10.1 / 1.22.22 (2026-11-26); 1.0.2: yarn ≤ 1.6 installs nothing (known limitation) | pass 1.0.2 / 1.7.0 / 1.10.1 / 1.22.22 (2026-11-26) |
| Workspaces (`^1.3.0` + `1.3.0` merged block) | pass 1.7.0 / 1.10.1 / 1.22.22 (2026-11-26) | pass 1.7.0 / 1.10.1 / 1.22.22 (2026-11-26); member-dir install: #691 | pass 1.22.22 (2026-11-26) |
| CRLF yarn.lock | pass 1.7.0 / 1.10.1 / 1.22.22 (2026-11-26) | pass 1.7.0 / 1.10.1 / 1.22.22 (2026-11-26) | pass 1.22.22 (2026-11-26) |
| BOM yarn.lock | pass 1.22.22 (2026-11-26) | pass 1.22.22 (2026-11-26) | pass 1.22.22 (2026-11-26) |
| `resolutions` forcing the patched version | pass 1.7.0 / 1.10.1 / 1.22.22 (2026-11-26) | pass 1.7.0 / 1.10.1 / 1.22.22 (2026-11-26) | pass 1.22.22 (2026-11-26) |
| `npm:` alias (alias only / alias + direct) | refused `redirect_yarn_classic_alias_skipped`, vex omits (documented) 1.22.22 (2026-11-26) | pass 1.22.22 (2026-11-26) | pass 1.22.22 (2026-11-26) |
| Offline mirror (`.yarnrc`, pruning) + `yarn add` + rollback | refused `redirect_yarn_classic_offline_mirror` 1.10.1 / 1.22.22 (2026-11-26) | pass 1.10.1 / 1.22.22 (2026-11-26) | untested |
| Re-run idempotency + mode switch H→V→A→H→rollback | pass 1.22.22 (2026-11-26; re-run reports `applied`, see backlog 1) | pass 1.22.22 (2026-11-26) | pass (keeps vendored ownership) 1.22.22 (2026-11-26) |
| `get <name>` / `list` / `remove <name>` | pass 1.22.22 (2026-11-26) | pass 1.22.22 (2026-11-26) | pass 1.22.22 (2026-11-26) |
| git dep (`git+…`) | untested since 11-11 (last pass run 20; needs github.com) | untested since 11-11 | untested since 11-11 |
| Merge flows (two branches vendor / pin) | untested since 11-11 (runs 44–45 pass) | untested since 11-11 (#1610 fixed) | n/a |
| Global (`-g`) | untested since 11-11 | refused (documented) | untested since 11-11 |
| `file:` copies (dir, renamed, tarball, backslash) | untested since 11-11 (run 45 pass) | untested since 11-11 | n/a |
| Interrupted runs (SIGKILL) | untested since 11-11 (run 42 pass) | untested since 11-11 | untested since 11-11 |
| macOS / Windows | probes off; last results in history (run 31 / 18) | same | same |

## Backlog

1. Hosted re-run that changes nothing reports `applied: 1` (event `applied`, mode hosted, lock byte-identical), while vendored says `skipped already_vendored`. Same on v5.1.0. Since #2178 telemetry is derived from these events, so hosted pin counts may inflate. Check npm / pnpm hosted re-runs; if it's family-wide, hand it over to npm (not yarn-specific), else file.
2. Re-run the untested-since-11-11 rows above: git dep (H/V), merge flows, global `-g`, `file:` copies, SIGKILL.
3. Offline mirror in agent mode; user-level / env mirror refusal on main (#1013 / #1078 shapes); workspace member `.yarnrc` mirror (#1115 fixed).
4. `yarn upgrade left-pad` / `yarn add left-pad@^1.3.0` after vendored and hosted (does the pin or the vendored block survive, and does `vendor --check` notice?).
5. `integrity sha1-` locks and 1.9.4 (no `integrity` line) on main, H/V.
6. Friction: `vex` in a project whose only pin is skipped (alias + direct) says "No patches in this project … Run `socket-patch scan` first" (exit 2) right after a scan that pinned one copy. Decide whether that remedy misleads enough to file.
7. Yarn ≤ 1.6 vendored installs nothing (exit 0) and `vex` still attests from the lock. Known yarn limitation, not in user docs. Ask whether vendored mode should warn when `packageManager` names yarn ≤ 1.6.
8. #691 (`agent:needs-human`): leave alone unless a maintainer comments.
9. New on main: `vex --grype-config` with a yarn project (needs grype; generic, low priority).

## Known non-bugs

Full list: `known-non-bugs/yarn-classic.md` (search it with `git grep`). The ones most likely to be re-filed:
- yarn 1.0.2–1.6.x install nothing (exit 0) for `file:` tarball lock entries, with or without socket-patch; CI reports vendored ≤ 1.6 as KNOWN LIMITATION.
- Hosted rollback of a lock without `integrity` lines (yarn < 1.10) adds `integrity` lines; yarn 1.7 still installs it frozen.
- With a mock patch host, hosted pins count as hosted wiring only when `--patch-server-url` names it; rollback otherwise says "Manifest not found".
- Hosted mode refuses a yarn offline mirror (`redirect_yarn_classic_offline_mirror`) and skips `npm:` alias entries (`redirect_yarn_classic_alias_skipped`); both documented.
- Agent mode patches yarn-cache copies when `--cache-folder` is a non-hidden dir inside the project; keep harness caches outside the project.
- npm 7+ `npm install` in a yarn 1 project rewrites yarn.lock, so the frozen install still passes (#1629 context).
- yarn 1 `workspaces` ignore `!` patterns.
- Lock / ledger mixed merges fail closed (`vendor --check` / `rollback` exit 1); the remedy loop is the #1072 / #991 class.
- `vex --json` needs `--output`; `setup` and `scan --apply` were removed in v5 (use `--mode agent` + `apply`).
