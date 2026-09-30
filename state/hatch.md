[agent] Progress ledger for the scheduled Hatch bug-hunt routine (label pm:hatch).

Last run: 2026-09-30 (second run) on main `f6b7fb9` (v4.0.0 predates Hatch support, #244). Linux runs use real Hatch against a local mock patch API, because the sandbox blocks the Socket patch hosts. macOS and Windows runs use probe branches.

## Coverage matrix
| Hatch | hosted, existing env, pip (Linux / macOS / Windows) | hosted, existing env, uv | hosted shapes + rollback (Linux) | vendored shapes + rollback (Linux) | rollback after an unrelated edit | mode takeover | agent |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1.0 – 1.6 | untested | n/a | untested | untested | untested | untested | untested |
| 1.7.0 | fail #335 (all 3 OS) | n/a | untested | pass (unicode/space path) | fail #385 | untested | untested |
| 1.9.7 | fail #335 (all 3 OS) | untested | untested | untested | untested | untested | untested |
| 1.14.1 | blocked (virtualenv incompatibility) | blocked | untested | untested | untested | untested | untested |
| 1.16.5 | fail #335 (all 3 OS) | pass | untested | untested | untested | untested | fail (see #335) |
| 1.18.1 | fail #335 (all 3 OS) | pass | pass (13 shapes) | pass (12 shapes; group refused) | fail #385 | fail #328 (both directions) | untested |

Fresh-environment installs of hosted and vendored rewrites pass on 1.18.1 (and on 1.7.0 for vendored). Workspaces (1.18.1): a member-only dependency is refused from the root with a warning, and passes when scanned from the member.

## Backlog
1. Hatch 1.0 / 1.1 / 1.2 vendored-env boundary; 1.14.x with a pinned virtualenv.
2. Refusal correctness: `overrides`, `template`, `[env]` collectors, custom env types (hatch-pip-compile lock plugin), hatch.toml `envs` non-table.
3. Multi-patch `rollback <purl>` / `--preserve-state` and `allow-direct-references` ownership (the mock needs a second package).
4. Windows long paths / drive letters for vendored `{root:uri}` (probe).
5. Re-triage #335, #385, and the Hatch rows of #328 when main moves.

## Known non-bugs
- Vendored PEP 735 dependency groups are refused (Hatch does not expand `{root:uri}` there): documented.
- Vendored with `installer = "uv"` / `uv-path` is refused: documented. Note that uv 0.12 does enforce local wheel hashes, so the documented rationale looks outdated. Hatch's internal uv envs (`hatch-test` etc.) aren't covered by the refusal, but the hash is still enforced (verified with a tampered wheel).
- Vendored needs `hatch` >= 1.2 on PATH (preflight `pypi_hatch_unsupported`): documented, including for `pipx run` / `uvx` users.
- Ranges, transitive-only (including workspace-member-only deps when scanned from the root), dynamic deps, sources, overrides and custom env types are refused: documented.
- Hosted project rewrites embed a direct URL in the built wheel's `Requires-Dist` (so the result can't be uploaded to PyPI): inherent to the design.
- `rollback` with nothing ever written exits 2 `Manifest not found`.
- Vendored scan fails `package_not_installed` against the mock (no vendoring-service endpoints) unless `VIRTUAL_ENV` points at the Hatch env: a harness artifact, not a bug.
