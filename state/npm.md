[agent] Progress ledger for the scheduled npm bug-hunt routine (label pm:npm).

Last run: 2026-11-28, main `cfc870f`, release v5.1.0, newest npm 12.2.3 (next-11 11.21.3, next-10 10.9.11).

Compacted 2026-11-26 from a 110 KB file (runs 1-65 kept in branch history; per-run notes are in `entries/npm/`). Open npm bughunt issues: #2275, #2304, #2331. Every `#N` below is closed unless marked open.

## Coverage matrix

Linux unless noted. Every cell is a real npm install. Hosted and agent/vendored cells use a local mock of the patch API (`--api-url` / `--patch-server-url`). "Cycle" = scan → fresh `npm ci` (patched) → `vex` → re-scan no-op → `rollback` byte-exact → `npm ci` unpatched. Cells last run before 2026-11-11 count as untested for the release (INSTRUCTIONS "Release focus").

| Workflow | Agent | Vendored | Hosted |
| --- | --- | --- | --- |
| Common-path cycle, npm 12.2.3 / Node 22 | pass 12.2.3 (2026-11-26; `npm ci` → `apply` re-patches) | pass 12.2.3 (2026-11-26; `vendor --check`) | pass 12.2.3 (2026-11-26) |
| Common-path cycle, npm 10.9.9 | pass 10.9.9 (2026-11-26) | pass 10.9.9 (2026-11-26) | pass 10.9.9 (2026-11-26) |
| `omit-lockfile-registry-resolved=true` + `npm install` (8.19.4 / 10.9.9 / 11.21.3 / 12.2.3) | n/a | **fail #2331** (open; `file:` resolved stripped, cold `npm ci` EINTEGRITY, no warning; v5.1.0 too) | warned (#1871, documented); remedy it names is #2331 |
| Common-path cycle, npm 11.21.3 | pass 11.21.3 (2026-11-27) | pass 11.21.3 (2026-11-27) | pass 11.21.3 (2026-11-27) |
| Common-path cycle, npm 7.24.2 (v2 lock) | pass 7.24.2 (2026-11-27) | pass 7.24.2 (2026-11-27) | pass 7.24.2 (2026-11-27; alias warns `redirect_npm_legacy_alias_client`) |
| Common-path cycle, npm 8.19.4 (v2 lock) | pass 8.19.4 (2026-11-26) | pass 8.19.4 (2026-11-26) | pass 8.19.4 (2026-11-26) |
| Common-path cycle, npm 6.14.18 (v1 lock) | pass (2026-11-27) | refused (documented) | pass (2026-11-27): cold-cache EINTEGRITY + `redirect_npm_legacy_client` (documented) |
| Scoped + VEX products (#2243) | n/a | n/a | pass 12.2.3 (2026-11-26): scoped `@tootallnate/once` + alias `lp@npm:left-pad` products named by Socket purl (`@`, not `%40`); scanner match unverified |
| Patch mirror (`SOCKET_PATCH_pass 12.2.3 (2026-11-26): pins under the base, `npm ci` via mirror, `vex`, re-run no-op, re-pin from patch server, `rollback`; 403 → `redirect_mirror_unverified`, 404 → `redirect_mirror_unavailable`_URL`, #2180) | n/a | n/a | pass 12.2.3 (2026-11-26): pins under the base, `npm ci` via mirror, `vex`, re-run no-op, re-pin from patch server, `rollback`; 403 → `redirect_mirror_unverified`, 404 → `redirect_mirror_unavailable` |
| Workspaces, root scan, 2 members (npm 12.2.3) | pass (2026-11-26) | pass (2026-11-26) | pass (2026-11-26) |
| Workspaces: member dir (unhoisted copy), root cycle on a nested member copy | agent pass (2026-11-27) | member refused, root pass (2026-11-27) | member `redirect_workspace_lockfile_elsewhere`, root pass (2026-11-27) |
| Workspaces: hidden `.github/actions/x` + `build/y` members, 12.2.3 | pass (2026-11-28) | pass (2026-11-28) | pass (2026-11-28) |
| Dual lock (shrinkwrap + package-lock), 10.9.9 / 12.2.3 | n/a | pass (2026-11-26, both locks byte-exact) | pass (2026-11-26) |
| Dual lock one-sided drift (npm 10 updates only the shrinkwrap) | n/a | fail-closed pass (2026-11-27) | fail-closed pass (2026-11-27; unattributable pin, `--json` explains) |
| npm 12 `allow-remote=root` (transitive pin) / `allowScripts` (#1595) / `allow-file` (#969) | n/a | `allowScripts`, `allow-file` pass before 11-11 | `allow-remote=root` respected + warned, `npm ci` EALLOWREMOTE (documented; 2026-11-27) |
| `overrides` (flat, `$ref`; alias / URL target #1965 before 11-11), fresh `npm ci` and `npm install` | n/a | pass 12.2.3 (2026-11-27) | pass 12.2.3 (2026-11-27) |
| Aliases + scoped (`lp@npm:left-pad`, `@tootallnate/once`), 12.2.3 | pass (2026-11-26) | pass (2026-11-26) | pass (2026-11-26) |
| Bundled deps (#1618) dependency-bundled copy, 12.2.3; `hasShrinkwrap` nested (#753) | patched (2026-11-28) | refused loudly, exit 1 (2026-11-28) | refused loudly, exit 0 (2026-11-28); `hasShrinkwrap` before 11-11 |
| `install-strategy=linked` 12.2.3 (nested/shallow before 11-11) | pass (2026-11-28) | pass (2026-11-28) | pass (2026-11-28) |
| Lock layout CRLF / BOM+CRLF / tab; CRLF-shebang bins (#1756) | n/a | layouts pass 12.2.3 (2026-11-27); bins before 11-11 | layouts pass 12.2.3 (2026-11-27); bins before 11-11 |
| Unreadable vendor ledger (merge conflict in `state.json`) | n/a | **fail #2275** (open; remedy loop vex → vendor → repair; v5.1.0 too) | n/a |
| `vex --grype-config` (#2252) | n/a | n/a | pass 12.2.3 (2026-11-26: created, then removed after rollback) |
| Global `--global-prefix` agent scan + rollback | pass 12.2.3 (2026-11-27) | n/a | n/a |
| `npm install <new dep>` after scan keeps pins (8.19.4 / 10.9.9 / 12.2.3) | n/a | pass (2026-11-27) | pass (2026-11-27) |
| Mode switching hosted → vendored → agent → hosted → vendored → rollback (12.2.3); vendored → agent → vendored (10.9.9); workspaces hosted → vendored → agent → hosted (8.19.4 / 12.2.3) | **fail #2304** (open; vendored → agent totals say "left to patch"; same on 10 / 8 / workspaces) | pass (2026-11-28) | pass (2026-11-28) |
| `report` (#2193) name / scoped / `%40` purl | pass (2026-11-27; alias name `lp` unmatched, same as `rollback`) | n/a | pass (2026-11-27) |
| macOS / Windows | probes switched off (INSTRUCTIONS step 5); last pass 2026-10 | same | same |

## Backlog

1. Re-check #2331, #2304 and #2275 when fixed.
2. VEX products (#2243): prove or rule out a Grype / Trivy miss for `pkg:npm/@scope/name` vs `%40scope`. The sandbox policy denied running the Grype binary (2026-11-27). Try Trivy / Syft from npm or pip, or hand over.
3. Other npm settings that rewrite the lock on save, with vendored and hosted pins: `install-links`, `save-exact`, `lockfile-version=3` under npm 8, `package-lock-only` installs, `npm dedupe` / `npm prune`.
4. Remaining pre-11-11 cells: npm 12 `allowScripts` (needs a patched package with an install script), `hasShrinkwrap` nested, CRLF-shebang bins, `install-strategy=nested/shallow`.
5. Patch mirror on npm: vendored eject over mirrored pins, `allow-remote=root` with a mirror host, `SOCKET_PATCH_MIRROR_AUTHORIZATION` with `.npmrc` `_auth`.
6. `scan --prune` vendored revert reporting (#2246) on npm.

Mock tip: the hosted mock must be passed as `--patch-server-url` as well as `--api-url`, or lockfile discovery (`vex`, `rollback`) doesn't recognize the pins ("No patches in this project").

## Known non-bugs

Full list: `known-non-bugs/npm.md` (search it with `git grep`). Most likely to be re-filed:
- A hosted re-run with every pin in place reports `applied` events with `rewrittenFiles: []` (deliberate).
- npm itself drops a hosted pin on `npm update` / `npm install <pkg>@<same ver>`; `vex` then refuses and a re-scan re-pins.
- Hosted / vendored `rollback` restores the lock but leaves installed patched bytes until the next `npm ci` (documented "reinstall" step).
- Vendored mode refuses a lockfileVersion 1 lock (documented).
- npm 6 with a v1 hosted pin and a cold cache fails EINTEGRITY (documented `redirect_npm_legacy_client`).
- A dir carrying a signed CACHEDIR.TAG is pruned from the crawl (documented).
- npm doesn't install deps of a `file:` target or workspace outside the project root.
- Hosted `rollback` reads the version document only from the default registry, not a project `.npmrc` `registry=`.
- Agent mode: `npm ci` reinstalls upstream bytes; `apply` re-patches. Not a bug.
- `report` / `rollback` match registry names, not an npm alias name (`lp`); the error says to use the UUID.
