[agent] Progress ledger for the scheduled Hatch bug-hunt routine (label pm:hatch).

Last run: 2026-11-26 on main `cfc870f`, release v5.1.0, newest Hatch 1.18.2 (bundled uv 0.13.10). Linux only (the probe workflows are off). Harness: real Hatch against a local mock patch API (`six` 1.16.0 with a `SOCKET_PATCHED = 1` marker). The mock serves batch / by-package / package grant (`kind: tarball`, sha256 + `sha512-` SRI) / view (`blobContent` base64) / `patches/blob/<git-sha256>`, plus GET **and HEAD** on the wheel route. Set `SOCKET_PATCH_SERVER_URL` to the mock and use `--vendor-source service` for vendored. Put only the `hatch` binary on PATH (not its venv `bin/`), and create the env before scanning.

All `bughunt` issues filed through 2026-10-03 (#335 #385 #415 #454 #479 #505 #547 #650 #673 #674) are closed as fixed. Open: #2295.

## Coverage matrix
Cells dated before 2026-11-11 count as untested for the release (INSTRUCTIONS "Release focus").

| Workflow | hosted | vendored | agent |
| --- | --- | --- | --- |
| Common path, project dep, pip installer (scan, existing env, fresh env, vex, build, rollback, reinstall) | pass 1.7.0 / 1.16.5 / 1.18.2 (2026-11-26) | pass 1.7.0 / 1.16.5 / 1.18.2 (2026-11-26) | pass 1.18.2: scan, `apply --check`, vex, apply after env recreate, rollback, remove (2026-11-26) |
| Common path, uv installer | pass 1.16.5 / 1.18.2, existing env resynced (2026-11-26) | refused (documented) | untested |
| Locked env / `lock-envs`, committed pylock | scan + fresh env pass 1.18.2; **rollback / remove fail #2295** on 1.18.1 / 1.18.2 (`--no-header` lock); pass 1.17.0 (2026-11-26) | refused (uv installer, documented) | untested |
| Superseding patch uuid (#650) | pass 1.18.2, rollback byte-exact (2026-11-26) | pass 1.18.2, old artifact removed (2026-11-26) | untested |
| Mode takeover H→V / V→H, 1 patch | pass 1.18.2 (2026-11-26) | pass 1.18.2 (2026-11-26) | n/a |
| Takeover with 2 patches (#674) | untested since fix | untested since fix | n/a |
| `installer = "uv"` + `[tool.uv.sources]` (#673) | url / path refused, nothing written; index source pass (1.18.2, 2026-11-26) | refused | untested |
| Shapes: markers, extras, features, env deps, hatch.toml envs, matrix, templates, CRLF, TOML spellings | pass 1.7.0 / 1.16.5 / 1.18.1 (pre-release, 2026-10) | pass (pre-release, 2026-10) | untested |
| Workspaces (member deps, #505) | pass (pre-release) | untested since fix | untested |
| Checkout path with `%XX` / `#` / `;` (#547) | n/a | untested since fix | n/a |
| Rollback after an unrelated edit (#385) | pass (pre-release) | pass (pre-release) | n/a |
| Global `-g`: pipx / uv-tool Hatch (#415, #449) | n/a | n/a | pass Linux (pre-release) |
| Agent re-scan after env recreate (#454) | n/a | n/a | untested since fix |

## Backlog
1. #2295 follow-ups: H→V takeover from a hosted Hatch 1.18 locked env; `lock-filename` custom names; Hatch 1.18.0.
2. Re-run the 2-patch takeover (#674) and workspace vendored (#505) cells on main for the release.
3. Vendored from a checkout path with `%20` / `#` (#547 fix: it should be refused before writing).
4. Agent mode with the uv installer and with locked envs; `scan --sync` after `hatch env prune` (#454).
5. Shapes re-run on 1.18.2: hatch.toml-only envs, `hatch-test` matrix, features, PEP 735 groups, CRLF.
6. `vex --grype-config` (new on main, #2252) on a hosted / vendored Hatch project.
7. Hatch 1.0 / 1.2 boundary (vendored preflight `pypi_hatch_unsupported`) on main.
8. Re-triage #2295 when the uv restore code moves.

## Known non-bugs
Full list: `known-non-bugs/hatch.md` (search it with `git grep`). Most likely to be re-filed:
- Ranges, transitive-only, dynamic deps, sources, overrides, custom env types and vendored PEP 735 groups are refused: documented.
- Vendored with `installer = "uv"` / `uv-path` is refused, and so are locked envs (uv installer): documented.
- Hosted `vex` with no Hatch env yet attests from the wiring (like a lockfile-only checkout): by design.
- A no-env scan reads the venv `python3` on PATH as the project's env (#2170): put only the `hatch` binary on PATH in the harness.
- The mock needs HEAD on the wheel route (uv) and `/patches/blob/` (agent rollback): harness requirements.
- Hosted rollback rebuilds the requirement from the URL, so spelling isn't byte-exact (`SIX == 1.16.0` → `SIX==1.16.0`): semantically equal.
- Hosted rollback drops a user-preset `allow-direct-references` when no direct reference remains: low severity, logged.
- Hosted project rewrites embed a direct URL in the built wheel's `Requires-Dist`: inherent.
- A pyproject.toml with a UTF-8 BOM isn't loadable by Hatch: invalid input.
- In the sandbox, the system `/usr/lib/python3/dist-packages/six.py` makes vex / vendored see an extra six: a sandbox artifact.
