[agent] Progress ledger for the scheduled Hatch bug-hunt routine (label pm:hatch).

Last run: 2026-10-01 on main `2463257` (v5 workflow, #277). The latest tag v4.0.0 predates Hatch support (#244). Linux runs use real Hatch against a local mock patch API (six 1.16.0; v5 vendored needs `integrity.sha512` in the mock). macOS and Windows use probe branches.

## Coverage matrix
| Hatch | hosted, existing env, pip (Linux / macOS / Windows) | hosted, existing env, uv | vendored, existing env | hosted shapes + rollback (Linux) | vendored shapes + rollback (Linux) | rollback after an unrelated edit (hosted / vendored) | mode takeover | agent | global `-g`, pipx-installed (L / M / W) | global-prefix apply / vex / rollback (L / M / W) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1.0 – 1.6 | untested | n/a | untested | untested | untested | untested | untested | untested | untested | untested |
| 1.7.0 | fail #335 (all 3 OS) | n/a | untested | untested | pass (unicode/space path) | hosted untested on v5 / fail #385 | untested | untested | fail #415 (all 3) | pass (all 3) |
| 1.9.7 | fail #335 (all 3 OS) | untested | untested | untested | untested | untested | untested | untested | untested | untested |
| 1.14.1 | blocked (virtualenv incompatibility) | blocked | blocked | untested | untested | untested | untested | untested | untested | untested |
| 1.16.5 | fail #335 (all 3 OS) | pass | untested | untested | untested | untested | untested | fail (see #335) | fail #415 (all 3); uv-tool pass (Linux) | pass (all 3) |
| 1.18.1 | fail #335 (Linux re-checked on v5) | pass | fail (#335 comment) | pass (13 shapes, pre-v5) | pass (12 shapes; group refused, pre-v5) | pass on v5 / fail #385 | fail #328 (both directions, pre-v5) | fail (see #335) | fail #415 (all 3) | pass (all 3) |

Also on v5: `scan -g` is report-only and never touches pyproject or the Hatch env dirs; `-g` / `--global-prefix` / `SOCKET_GLOBAL=1` with `--mode hosted` exit 2 and write nothing. Fresh-environment installs of hosted and vendored rewrites pass on 1.18.1 (and on 1.7.0 for vendored). Workspaces (1.18.1, pre-v5): a member-only dependency is refused from the root with a warning, and passes when scanned from the member.

## Backlog
1. **Maintainer request (global mode), remaining cells:** a uv-tool Hatch under `-g` on macOS / Windows; a read-only global prefix on a non-root runner (must fail loudly); a non-root user's prefix. See the 20261001T040000Z entry.
2. Vendored #385 / #335 cells on Hatch 1.7.0, and with `installer = "uv"` envs.
3. Refusal correctness: `overrides`, `template`, `[env]` collectors, custom env types (hatch-pip-compile lock plugin), hatch.toml `envs` non-table.
4. Multi-patch `rollback <purl>` / `--preserve-state` and `allow-direct-references` ownership (the mock needs a second package).
5. Hatch 1.0 / 1.1 / 1.2 vendored-env boundary; 1.14.x with a pinned virtualenv.
6. Re-check mode takeover (#328) and the 13 hosted / 12 vendored shapes on v5.
7. Re-triage #335, #385 and #415 when main moves.

## Known non-bugs
- Vendored PEP 735 dependency groups are refused (Hatch does not expand `{root:uri}` there): documented.
- Vendored with `installer = "uv"` / `uv-path` is refused: documented. Note that uv 0.12 does enforce local wheel hashes, so the documented rationale looks outdated. Hatch's internal uv envs (`hatch-test` etc.) aren't covered by the refusal, but the hash is still enforced (verified with a tampered wheel).
- Vendored needs `hatch` >= 1.2 on PATH (preflight `pypi_hatch_unsupported`): documented, including for `pipx run` / `uvx` users.
- Ranges, transitive-only (including workspace-member-only deps when scanned from the root), dynamic deps, sources, overrides and custom env types are refused: documented.
- Hosted project rewrites embed a direct URL in the built wheel's `Requires-Dist` (so the result can't be uploaded to PyPI): inherent to the design.
- `rollback` with nothing ever written exits 2 `Manifest not found`. `remove` after a full rollback gives `manifest_not_found`.
- Vendored scan against the mock fails `vendor_prebuilt_required` unless the grant's artifact carries `integrity.sha512` (v5): a harness requirement, not a bug.
- In mock runs every purl "has" a six patch (the batch endpoint answers six for any input). Use `scannedPackages` and the apply results, not `packages[]`, to judge discovery.
- `scan -g`, and the bare `-g` hosted refusal, print the usage error to stderr only, even with `--json` (exit 2): this matches the exit-code table.
