[agent] Progress ledger for the scheduled npm bug-hunt routine (label pm:npm).

Last run: 2026-11-26, main `cfc870f`, release v5.1.0, newest npm 12.2.3 (next-11 11.21.3, next-10 10.9.11).

Compacted 2026-11-26 from a 110 KB file (runs 1-65 kept in branch history; per-run notes are in `entries/npm/`). Open npm bughunt issues: #2275. Every `#N` below is closed unless marked open.

## Coverage matrix

Linux unless noted. Every cell is a real npm install. Hosted and agent/vendored cells use a local mock of the patch API (`--api-url` / `--patch-server-url`). "Cycle" = scan → fresh `npm ci` (patched) → `vex` → re-scan no-op → `rollback` byte-exact → `npm ci` unpatched. Cells last run before 2026-11-11 count as untested for the release (INSTRUCTIONS "Release focus").

| Workflow | Agent | Vendored | Hosted |
| --- | --- | --- | --- |
| Common-path cycle, npm 12.2.3 / Node 22 | pass 12.2.3 (2026-11-26; `npm ci` → `apply` re-patches) | pass 12.2.3 (2026-11-26; `vendor --check`) | pass 12.2.3 (2026-11-26) |
| Common-path cycle, npm 10.9.9 | pass 10.9.9 (2026-11-26) | pass 10.9.9 (2026-11-26) | pass 10.9.9 (2026-11-26) |
| Common-path cycle, npm 8.19.4 (v2 lock) | pass 8.19.4 (2026-11-26) | pass 8.19.4 (2026-11-26) | pass 8.19.4 (2026-11-26) |
| Common-path cycle, npm 6.14.18 (v1 lock) | pass (2026-11-26) | refused (documented) | pass (2026-11-26): cold-cache EINTEGRITY + `redirect_npm_legacy_client` (documented) |
| Scoped + VEX products (#2243) | n/a | n/a | pass 12.2.3 (2026-11-26): scoped `@tootallnate/once` + alias `lp@npm:left-pad` products named by Socket purl (`@`, not `%40`); scanner match unverified |
| Patch mirror (`SOCKET_PATCH_pass 12.2.3 (2026-11-26): pins under the base, `npm ci` via mirror, `vex`, re-run no-op, re-pin from patch server, `rollback`; 403 → `redirect_mirror_unverified`, 404 → `redirect_mirror_unavailable`_URL`, #2180) | n/a | n/a | pass 12.2.3 (2026-11-26): pins under the base, `npm ci` via mirror, `vex`, re-run no-op, re-pin from patch server, `rollback`; 403 → `redirect_mirror_unverified`, 404 → `redirect_mirror_unavailable` |
| Workspaces, root scan, 2 members (npm 12.2.3) | pass (2026-11-26) | pass (2026-11-26) | pass (2026-11-26) |
| Workspaces: member dir, hidden member #1827, `build`-named member #1627 | pass before 11-11 | pass before 11-11 (#1904, #1921 fixed) | pass before 11-11 |
| Dual lock (shrinkwrap + package-lock), 10.9.9 / 12.2.3 | n/a | pass (2026-11-26, both locks byte-exact) | pass (2026-11-26) |
| Dual lock one-sided drift | n/a | pass before 11-11 | pass before 11-11 |
| npm 12 `allow-remote` / `allowScripts` (#1595) / `allow-file` (#969) | n/a | pass before 11-11 | pass before 11-11 |
| `overrides` (flat, alias, `$ref`, URL target #1965) | n/a | pass before 11-11 | pass before 11-11 |
| Aliases + scoped (`lp@npm:left-pad`, `@tootallnate/once`), 12.2.3 | pass (2026-11-26) | pass (2026-11-26) | pass (2026-11-26) |
| Bundled deps (#1618), `hasShrinkwrap` nested (#753) | pass before 11-11 | pass before 11-11 | pass before 11-11 |
| `install-strategy=linked/nested/shallow` | pass before 11-11 | pass before 11-11 | pass before 11-11 |
| CRLF-shebang bins (#1756, #1791, #1804) | pass before 11-11 | pass before 11-11 | pass before 11-11 |
| Unreadable vendor ledger (merge conflict in `state.json`) | n/a | **fail #2275** (open; remedy loop vex → vendor → repair; v5.1.0 too) | n/a |
| `vex --grype-config` (#2252) | n/a | n/a | pass 12.2.3 (2026-11-26: created, then removed after rollback) |
| Global `-g` (Linux) | pass before 11-11 | n/a | n/a |
| macOS / Windows | probes switched off (INSTRUCTIONS step 5); last pass 2026-10 | same | same |

## Backlog

1. Common path on npm 6.14.18 (v1 lock) and 7.24.2 on main, hosted + agent.
2. Re-run pre-11-11 cells on main, most valuable first: workspaces (member dir, hidden member), dual lock + drift, npm 12 `allowScripts` / `allow-remote=root`, `overrides`, aliases.
3. VEX products (#2243): scoped npm products are written `pkg:npm/@scope/name@v`; Syft/Grype/Trivy report `pkg:npm/%40scope/name@v`. Prove (or rule out) a missed suppression with a real Grype / Trivy (GitHub release downloads were 404 / 403 through the proxy on 2026-11-26). Also nested duplicate versions and a patched + unpatched copy of one name@version.
4. Re-check #2275 when fixed. `report` (#2193) human / JSON text on npm.
5. Patch mirror on npm: vendored eject over mirrored pins, npm 12 `allow-remote=root` with a mirror host, `SOCKET_PATCH_MIRROR_AUTHORIZATION` with `.npmrc` `_auth`.
6. `scan --prune` vendored revert reporting (#2246) and an unreadable vendor ledger (#2250) on npm.

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
- Agent mode: `npm ci` reinstalls upstream bytes; `apply` (or the `setup` hook) re-patches. Not a bug.
