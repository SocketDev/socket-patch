[agent] Progress ledger for the scheduled Hatch bug-hunt routine (label pm:hatch).

Last run: 2026-10-01 21:53Z on main `61cfb9b`. The latest tag v4.0.0 predates Hatch support (#244). Linux runs use real Hatch against a local mock patch API (six 1.16.0; v5 vendored uses `--vendor-source service` (local `build` was removed) and needs `integrity.sha512` in the mock, the grant artifact `kind` must be `tarball`, and `SOCKET_PATCH_SERVER_URL` must point at the mock so hosted wiring is recognised). macOS and Windows use probe branches.

## Coverage matrix
| Hatch | hosted, existing env, pip (Linux / macOS / Windows) | hosted, existing env, uv | vendored, existing env | hosted shapes + rollback (Linux) | vendored shapes + rollback (Linux) | rollback after an unrelated edit (hosted / vendored) | mode takeover (H→V / V→H) | agent | agent re-scan after env recreate | global `-g`, pipx-installed (L / M / W) | global `-g`, uv-tool-installed (L / M / W) | global-prefix apply / vex / rollback (L / M / W) | locked env + pylock, hosted / vendored (L / M / W) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1.0 – 1.6 | untested | n/a | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested | n/a (no `hatch lock`) |
| 1.7.0 | fail #335 (all 3 OS) | n/a | untested | untested | pass (unicode/space path) | hosted untested on v5 / fail #385 | untested | untested | fail #454 | fail #415 (all 3) | untested | pass (all 3) | n/a (no `hatch lock`) |
| 1.9.7 | fail #335 (all 3 OS) | untested | untested | untested | untested | untested | untested | untested | untested | untested | pass / pass / fail #449 | untested | n/a (no `hatch lock`) |
| 1.14.1 | blocked (virtualenv incompatibility) | blocked | blocked | untested | untested | untested | untested | untested | untested | untested | untested | untested | n/a (no `hatch lock`) |
| 1.16.5 | fail #335 (all 3 OS) | pass | untested | untested | untested | untested | untested | fail (see #335) | untested | fail #415 (all 3); uv-tool pass (Linux) | pass / pass / fail #449 | pass (all 3) | n/a (no `hatch lock`) |
| 1.17.0 | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested | untested | fail #479 (all 3, both modes) |
| 1.18.1 | fail #335 (Linux re-checked on v5) | pass | fail (#335 comment) | pass (13 shapes pre-v5; v5: template, dotted keys, matrix, features, detached, hatch.toml envs pass) | pass (12 shapes; group refused, pre-v5) | pass on v5 (bump + added dep, `61cfb9b`) / fail #385 | v5: pass / fail #328 | fail (see #335) | fail #454 | fail #415 (all 3) | pass / pass / fail #449; `UV_TOOL_DIR` fail #449 (Linux) | pass (all 3); read-only root-owned prefix: exits 1 (#424 JSON), re-run exits 0 (#454) | fail #479 (all 3, both modes) |

Also on v5: `scan -g` is report-only and never touches pyproject or the Hatch env dirs; `-g` / `--global-prefix` / `SOCKET_GLOBAL=1` with `--mode hosted` exit 2 and write nothing. Fresh-environment installs of hosted and vendored rewrites pass on 1.18.1 (and on 1.7.0 for vendored). Locked env with no committed pylock (pyproject lane) passes on 1.18.1. On main `6e7ef74`: #335 and the vendored #385 cell still reproduce, and the hosted version-bump rollback passes. Workspaces (1.16.5 / 1.18.1, v5): a member-only dependency is refused from the root with a warning. Scanned from the member, hosted passes (fresh root env patched) but **vendored fails #505**: the root env doesn't expand `{root:uri}` in member deps. CRLF pyproject on v5: hosted and vendored pass, with fresh env patched and rollback byte-exact (1.18.1). On main `61cfb9b`: #335 and the vendored #385 cell still reproduce; the hosted #385 cells (version bump, added dependency) pass. #454 and #415 are fixed and closed.

## Backlog
0. #505 follow-ups: workspace members with `features`, dynamic-dep members, `workspace` declared in hatch.toml; probe #505 on macOS / Windows.
1. #479 follow-ups: `lock-filename` context formatting, global `lock-envs`, matrix envs sharing a lock, `hatch dep sync`, rollback / remove on a pylock-wired Hatch project (see #407).
2. **Maintainer request (global mode), remaining cells:** `UV_TOOL_DIR` on macOS / Windows; a read-only, root-owned prefix on macOS (needs sudo on the runner); Windows Program Files prefix.
3. Vendored → hosted takeover (#328) once it moves; multi-patch `rollback <purl>` / `--preserve-state` and `allow-direct-references` ownership (the mock needs a second package).
4. Vendored #385 / #335 cells on Hatch 1.7.0, and with `installer = "uv"` envs.
5. Hatch 1.0 / 1.1 / 1.2 vendored-env boundary; 1.14.x with a pinned virtualenv.
6. Re-triage #335, #385 (vendored only), #479, #505 when main moves.

## Known non-bugs
- Locked Hatch envs with `installer = "pip"`: Hatch's pip locker can't apply lockfiles (`LockerUnsupportedError`), so it's a Hatch limitation.
- Probing Hatch through `uv tool run` with uv 0.12 leaks `UV` / `UV_INTERNAL__PARENT_INTERPRETER` and breaks Hatch's locked sync: a harness artifact. Use installed Hatch binaries.
- Vendored PEP 735 dependency groups are refused (Hatch does not expand `{root:uri}` there): documented.
- Vendored with `installer = "uv"` / `uv-path` is refused: documented. Note that uv 0.12 does enforce local wheel hashes, so the documented rationale looks outdated. Hatch's internal uv envs (`hatch-test` etc.) aren't covered by the refusal, but the hash is still enforced (verified with a tampered wheel).
- Vendored needs `hatch` >= 1.2 on PATH (preflight `pypi_hatch_unsupported`): documented, including for `pipx run` / `uvx` users.
- Ranges, transitive-only (including workspace-member-only deps when scanned from the root), dynamic deps, sources, overrides and custom env types are refused: documented.
- Hosted project rewrites embed a direct URL in the built wheel's `Requires-Dist` (so the result can't be uploaded to PyPI): inherent to the design.
- `rollback` with nothing ever written exits 2 `Manifest not found`. `remove` after a full rollback gives `manifest_not_found`.
- Vendored scan against the mock fails `vendor_prebuilt_required` unless the grant's artifact carries `integrity.sha512` (v5): a harness requirement, not a bug.
- In mock runs every purl "has" a six patch (the batch endpoint answers six for any input). Use `scannedPackages` and the apply results, not `packages[]`, to judge discovery.
- `scan -g`, and the bare `-g` hosted refusal, print the usage error to stderr only, even with `--json` (exit 2): this matches the exit-code table.
- Hosted `rollback` only recognises wiring on `patch.socket.dev` or the `--patch-server-url` origin. A mock URL on another origin gives `Manifest not found`, which is a harness artifact.
- A "read-only" prefix the current user owns (chmod 0444 / 0555) still gets patched, because the owner can write. Only a prefix the user can't write to is a real refusal case.
- Env `overrides`, `[tool.hatch.env]` (requires / collectors), custom env `type`, and a non-table `envs` in hatch.toml are refused with nothing written: documented.
- `six==1.16` (PEP 440-equal to the installed 1.16.0) is refused as not exact. It's a minor over-refusal that fails closed, logged rather than filed.
- A pyproject.toml with a UTF-8 BOM isn't loadable by Hatch (`TOMLDecodeError` at 1:1). Hosted strips the BOM and rollback doesn't restore it; vendored preserves it. Not filed, because the input is invalid for Hatch.
- vex from the project root in the sandbox can omit six as `not_applied` because of the system `/usr/lib/python3/dist-packages/six.py`: a sandbox artifact.
