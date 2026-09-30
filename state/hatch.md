[agent] Progress ledger for the scheduled Hatch bug-hunt routine (label pm:hatch).

Last run: 2026-09-30 on main `f6b7fb9` (v4.0.0 predates Hatch support, #244). Linux runs use real Hatch against a local mock patch API, because the sandbox blocks the Socket patch hosts. macOS and Windows runs use probe branches.

## Coverage matrix
| Hatch | hosted, existing env, pip (Linux / macOS / Windows) | hosted, existing env, uv | hosted shapes + rollback (Linux) | vendored shapes + rollback (Linux) | agent |
| --- | --- | --- | --- | --- | --- |
| 1.0 – 1.6 | untested | n/a | untested | untested | untested |
| 1.7.0 | fail #335 (all 3 OS) | n/a | untested | pass (unicode/space path) | untested |
| 1.9.7 | fail #335 (all 3 OS) | untested | untested | untested | untested |
| 1.14.1 | blocked (virtualenv incompatibility) | blocked | untested | untested | untested |
| 1.16.5 | fail #335 (all 3 OS) | pass | untested | untested | fail (see #335) |
| 1.18.1 | fail #335 (all 3 OS) | pass | pass (13 shapes) | pass (12 shapes; group refused) | untested |

Fresh-environment installs of hosted and vendored rewrites pass on 1.18.1 (and on 1.7.0 for vendored).

## Backlog
1. Hatch 1.0 / 1.1 / 1.2 vendored-env boundary; 1.14.x with a pinned virtualenv.
2. Hatch workspaces (1.16+) and local path deps.
3. Refusal correctness: `overrides`, `template`, `[env]` collectors, custom env types (hatch-pip-compile lock plugin), hatch.toml `envs` non-table.
4. Mode takeovers on Hatch; `rollback --preserve-state` and permission ownership across multiple patches.
5. Windows long paths / drive letters for vendored `{root:uri}` (probe).
6. Re-triage #335.

## Known non-bugs
- Vendored PEP 735 dependency groups are refused (Hatch does not expand `{root:uri}` there): documented.
- Vendored with `installer = "uv"` / `uv-path` is refused: documented. Note that uv 0.12 does enforce local wheel hashes, so the documented rationale looks outdated. Hatch's internal uv envs (`hatch-test` etc.) aren't covered by the refusal, but the hash is still enforced (verified with a tampered wheel).
- Ranges, transitive-only, dynamic deps, sources, overrides and custom env types are refused: documented.
- `rollback` with nothing ever written exits 2 `Manifest not found`.
- Vendored scan fails `package_not_installed` against the mock (no vendoring-service endpoints): a harness artifact, not a bug.
