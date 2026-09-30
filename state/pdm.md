[agent] Progress ledger for the scheduled PDM bug-hunt routine (label pm:pdm).

Last run: 2026-09-30 on main `f6b7fb9` (v4.0.0). Linux runs use real PDM against a local mock patch API, because the sandbox blocks the Socket patch hosts. macOS and Windows runs use probe branches.

## Coverage matrix
| PDM | lock_version | agent (Linux / macOS / Windows) | hosted (Linux) | vendored (Linux) |
| --- | --- | --- | --- | --- |
| 2.0.3 | 4.0 | fail #332 w/ install.cache symlink / untested / untested | refused (documented) | refused (documented) |
| 2.8.2 | 4.3 | fail #332 w/ install.cache symlink (all 3 OS) | pass (stale-install warning) | untested |
| 2.10.4 | 4.4 | fail #332 w/ install.cache symlink; pth fails closed | pass (stale-install warning) | untested |
| 2.11.2 | 4.4.1 | fail #332 w/ install.cache symlink | untested | untested |
| 2.12.4 | 4.4.1 | fail #332 w/ install.cache symlink (all 3 OS); hardlink pass | pass; fail #331 (`pdm add` + rollback) | untested |
| 2.15.4 | 4.4.1 | pass (all 3 OS, symlink + hardlink) | untested | untested |
| 2.20.1 | 4.5.0 | pass | pass; fail #331 | untested |
| 2.26.9 | 4.5.0 | pass (symlink/hardlink/pth) | pass; fail #331 | untested |
| 2.29.2 | 4.5.1 | pass (all 3 OS) | pass (all strategies, groups, VEX); fail #331 | pass (sync/frozen/idempotent/rollback) |
| 0.12 – 1.15 | 2 / 3.1 | untested | untested | untested |

Modes × macOS/Windows for hosted and vendored: untested by this routine (the repo's pdm-compatibility.yml covers them).

## Backlog
1. PDM 1.x `feature.install_cache` (symlink/pth) with agent mode.
2. Hosted after `pdm update urllib3` / `pdm remove` / `pdm lock --refresh`, plus the rollback invariants.
3. CRLF + `pdm add` rebase; custom `-L` lockfile renamed to `pdm.lock`.
4. Windows long-path / unicode dirs, hosted and vendored (probe).
5. Multi-target `--append` locks: fork refusal and VEX.
6. Vendored on 2.12 / 2.20 and legacy lock_version 2 (0.12, 1.4).
7. Re-triage #331 and #332.

## Known non-bugs
- lock_version absent / 3.1 / 4.0–4.2 refused; 2.8.0 accepted-but-crashes (documented).
- `__pypackages__` (PEP 582) not crawled; agent mode falls through to the PATH interpreter (documented).
- A plain relock (`pdm lock`, `--refresh`, `pdm update <pkg>`) drops the hosted redirect (documented; re-scan).
- PDM < 2.11 keeps an already-installed same-version package after a hosted rewrite (`redirect_pdm_stale_install_risk`, documented).
- Vendored refuses lock-only checkouts (`vendor_fetch_unverifiable`), by design.
- Hosted never takes over a vendored `path` (`redirect_pdm_refused`), by design (hosted-direction takeover is warn-only). Hosted→vendored for PyPI fails closed with `pypi_pdm_source_already_exists` (the same for uv/poetry): run `rollback` first.
- PDM 2.10 `install.cache_method=pth`: agent apply fails closed with `File not found`.
- `pdm lock` without `-G` does not lock optional groups (PDM behaviour, not a socket-patch bug).
