[agent] Progress ledger for the scheduled PDM bug-hunt routine (label pm:pdm).

Last run: 2026-11-26, main `cfc870f`, latest release v5.1.0, newest PDM 2.29.7. Linux only, real PDM against a local mock patch API (`scan`/`view`/`package`/`blob` routes plus a PyPI JSON pass-through), because the sandbox blocks the Socket patch hosts. Release focus: cells last tested before 2026-11-11 count as untested.

## Coverage matrix
One row per workflow. The old per-version matrix is in this file's history (before 2026-11-26).

| Workflow | agent | hosted | vendored |
| --- | --- | --- | --- |
| Common path, PDM 2.29.7 (lock 4.5.1): scan → sync → vex → re-scan idempotent → rollback byte-exact → reinstall | pass 2026-11-26 (incl. remove, rollback via blob) | pass 2026-11-26 (`lock --check`, `install` stable, reinstall warning) | pass 2026-11-26 |
| Common path, PDM 1.4.5 (lock 2, PEP 582 `__pypackages__`) | **fail #2293** (venv in `.pdm.toml`) | pass 2026-11-26 (sync patched, vex, rollback byte-exact) | pass 2026-11-26 |
| Common path, PDM 2.12.4 / 2.26.9 / 2.29.2 | pass before 2026-11-11 (untested since) | pass before 2026-11-11 (untested since) | scan pass 2026-11-26; unwind **fail #2292** |
| Superseding patch uuid (re-scan offers patch B) | — | pass 2026-11-26 (2.29.7) | pass 2026-11-26 (2.29.7; Poetry #1136 handover: PDM OK) |
| Unwind after a later PDM lock write (`pdm add` / `update <other>` / `lock --refresh`) | — | pass 2026-11-26 (`pdm add`, 2.29.7) | **fail #2292** (2.12.4 – 2.29.7, also v5.1.0; Poetry #1615 handover) |
| Unwind after plain `pdm lock` (wiring dropped) | — | pass (pre-11-11) | pass 2026-11-26 |
| Env discovery: saved venv + `use_venv` off (PEP 582) | **fail #2293** (1.4.5, 2.12.4, 2.29.2, 2.29.7; also v5.1.0) | vex fails closed (#2293) | untested |
| Env discovery: base interpreter + `use_venv` off, `PDM_PYTHON`, out-of-tree venv (#502/#528/#609) | pass before 2026-11-11 | pass before 2026-11-11 | pass before 2026-11-11 |
| Refusals: lock_version 3 / 3.1 / 4.0–4.2, multi-target fork, private-index static_urls (#413) | — | pass before 2026-11-11 | pass before 2026-11-11 |
| Stale install on PDM < 2.11 (#641), post-rollback reinstall advice (#477) | — | pass before 2026-11-11 | pass before 2026-11-11 |
| Groups (dev / optional / PEP 735), extras, `pdm export`, CRLF / mixed locks, space/unicode paths | pass before 2026-11-11 | pass before 2026-11-11 | pass before 2026-11-11 |
| Global `-g` (system, `global-project/.venv`, managed CPython, site config #566) | pass before 2026-11-11 | refused (documented) | — |
| PDM 0.12.3 / 1.0.0 / 1.5.3 legacy | pass before 2026-11-11 | pass before 2026-11-11 | pass before 2026-11-11 |
| macOS / Windows | probe branches disabled (Linux only) | same | same |

## Backlog
1. Re-run the pre-11-11 common-path cells on main: PDM 2.12.4 / 2.20.1 / 2.29.2 hosted + agent, 1.5.3 / 0.12.3 hosted + vendored, CRLF lock on 2.29.7.
2. Vendored on a PEP 582 project with a saved venv (#2293 shape): does `pypi_pdm_stale_install` / vendored `vex` check the wrong env too?
3. #2292 variants: CRLF lock re-render, `pdm remove <other>`, vendored → hosted takeover after the re-render; re-run once a fix merges.
4. `pdm add` / `pdm update` after a hosted scan on 2.29.7 with `static_urls` and `inherit_metadata` cross-platform locks.
5. `pdm sync` vs `pdm install --frozen-lockfile` on 2.29.7 after vendored, with groups (`-G`, `--prod`).
6. PDM 2.8.0 caveat re-check (accepted-but-crashes) and the 2.8.1 boundary on main.
7. `--json` envelopes for `vendor --revert` drift-keep (exit 0 with `vendor_revert_kept`): is the status `success` correct per CLI_CONTRACT?

## Known non-bugs
Full list: `known-non-bugs/pdm.md` (search with `git grep`). The ones most likely to be re-filed:
- lock_version absent / 3 / 3.1 / 4.0–4.2 refused; PDM 2.8.0 accepted-but-crashes (documented).
- A plain relock (`pdm lock`, `pdm update <pkg>`) drops the hosted/vendored patch (documented; re-scan).
- PDM < 2.11 keeps an installed same-version package after a hosted rewrite (`redirect_pdm_stale_install_risk`, documented).
- Vendored refuses lock-only checkouts (`vendor_fetch_unverifiable`); hosted → vendored fails closed with `pypi_pdm_source_already_exists` (run `rollback` first).
- Hosted VEX on a lock-only checkout attests the redirect (the lock is the hosted state).
- A multi-target (`pdm lock --append`) lock with the package at two versions is refused (documented).
- Hosted rollback of a mixed CRLF/LF lock normalizes it to LF (cosmetic).
- `rollback` deletes the manifest entry, so a later `apply` is a no-op (documented).
- PDM 1.x rollback warning names `pdm sync --reinstall` (absent on 1.4/1.5) next to a working alternative (cosmetic).
- Harness: `pdm use` in a fresh dir can pick another project's venv, so write `.pdm-python` explicitly; unset proxies for PDM's 127.0.0.1 downloads.
