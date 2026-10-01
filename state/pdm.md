[agent] Progress ledger for the scheduled PDM bug-hunt routine (label pm:pdm).

Last run: 2026-10-01 09:18Z on main `2463257` (v5 consolidation #277; latest tag v4.0.0). Linux runs use real PDM against a local mock patch API, because the sandbox blocks the Socket patch hosts. macOS and Windows runs use probe branches.

## Coverage matrix
| PDM | lock_version | agent (Linux / macOS / Windows) | hosted (Linux) | vendored (Linux) |
| --- | --- | --- | --- | --- |
| 1.4.5 | 2 | untested | pass on v4 (`__pypackages__` sync, legacy `[metadata.files]`); untested on v5 | untested |
| 2.0.3 | 4.0 | fail #332 w/ install.cache symlink / untested / untested | refused (documented) | refused (documented) |
| 2.8.2 | 4.3 | fail #332 w/ install.cache symlink (all 3 OS) | pass (stale-install warning) | untested |
| 2.10.4 | 4.4 | fail #332 w/ install.cache symlink; pth fails closed | pass (stale-install warning) | untested |
| 2.11.2 | 4.4.1 | fail #332 w/ install.cache symlink | untested | untested |
| 2.12.4 | 4.4.1 | fail #332 w/ install.cache symlink (all 3 OS; re-confirmed on v5 Linux); hardlink pass | pass (v5: #331/#382 fixed); fail #413 (private index static_urls) | pass (v4) |
| 2.15.4 | 4.4.1 | pass (all 3 OS, symlink + hardlink) | untested | untested |
| 2.20.1 | 4.5.0 | pass | pass (v5: #331/#382 fixed); fail #413 | pass (v4) |
| 2.26.9 | 4.5.0 | pass (symlink/hardlink/pth) | pass on v4; untested on v5 | untested |
| 2.29.2 | 4.5.1 | pass (all 3 OS) | pass on v5 (lock-only scan, sync, manifest-less rollback byte-exact, VEX); multi-target fork refused (documented); fail #413 | pass on v4 (sync/frozen/idempotent/rollback); untested on v5 |
| 0.12, 1.0, 1.8 – 1.15 | 2 / 3.1 | untested | untested | untested |

Modes × macOS/Windows for hosted and vendored: untested by this routine (the repo's pdm-compatibility.yml covers them).

### Global mode (`-g`, maintainer request)
| PDM | global location | scan -g report (Linux) | apply / rollback / vex -g | macOS / Windows |
| --- | --- | --- | --- | --- |
| 2.29.2 | system interpreter (default) | pass | untested | untested |
| 2.29.2 | `pdm use -g` → `global-project/.venv` | fail #451 | untested (same discovery) | untested |
| 2.29.2 | PDM-managed `cpython@3.12` | fail #451 | untested | untested |
| 2.12.4 | system interpreter (default) | pass | untested | untested |
| 2.12.4 | `pdm use -g <pdm python>` (no venv) | fail #451 | untested | untested |
| 0.12 – 2.0.3 | — | untested | untested | untested |

`-g --mode hosted` and `--global-prefix --mode hosted` refuse with exit 2 (pass). `SOCKET_GLOBAL=1` matches `-g` (pass). `--global-prefix <site-packages>` finds both #451 locations (pass).

## Backlog
1. **Maintainer request (global `-g`), still open:** agent `scan -g --mode agent` / `apply -g` / `rollback -g` / `vex -g` against a real global install, byte-exact rollback; `-g` must not write PDM's install cache; PDM 1.4.5 / 2.0.3 global; `venv.in_project=false` global venv; unwritable prefix (needs a non-root user); macOS / Windows. Full checklist in the 20261001T040000Z entry.
2. Vendored on v5 (`vendored_backend`): 2.29.2 / 2.12.4 / 1.4.5, incl. private index + static_urls.
3. Hosted lock_version 2 (0.12, 1.4.5) through the v5 upstream restore.
4. Hosted → vendored takeover on v5; `pdm update --unconstrained` / `lock --update-all` on hosted.
5. Non-static private index with different bytes (the hash variant of #413); PDM 1.x `feature.install_cache` with agent mode.
6. macOS / Windows probes, once probe-branch deletion works (`git push --delete` fails through the git proxy; the stale `bughunt/pdm/20260930-cache-symlink` still needs a maintainer to delete it).

## Known non-bugs
- lock_version absent / 3.1 / 4.0–4.2 refused; 2.8.0 accepted-but-crashes (documented).
- `__pypackages__` (PEP 582) not crawled; agent mode falls through to the PATH interpreter (documented). Hosted mode installs into `__pypackages__` fine.
- A plain relock (`pdm lock`, `--refresh`, `pdm update <pkg>`) drops the hosted redirect (documented; re-scan). Rollback still works when the package stays at the same version.
- PDM < 2.11 keeps an already-installed same-version package after a hosted rewrite (`redirect_pdm_stale_install_risk`, documented).
- Vendored refuses lock-only checkouts (`vendor_fetch_unverifiable`), by design.
- Hosted never takes over a vendored `path` (`redirect_pdm_refused`), by design (hosted-direction takeover is warn-only). Hosted→vendored for PyPI fails closed with `pypi_pdm_source_already_exists` (the same for uv/poetry): run `rollback` first.
- A multi-target (`pdm lock --append`) lock holding the package at two versions is refused (`redirect_pdm_refused`), documented.
- PDM 2.10 `install.cache_method=pth`: agent apply fails closed with `File not found`.
- `pdm lock` without `-G` does not lock optional groups (PDM behaviour, not a socket-patch bug).
- The mock-based published 4.0.0 wheel yields `redirected: 0` on lock-only projects, so it can't be used to bisect hosted findings.
- v5 hosted rollback/remove after the package left the lock (`pdm remove`, upgrade): exit 1 `Manifest not found` is the documented truly-empty result (formerly #382).
- v5 hosted rollback refuses a non-universal release (binary wheels) on a lock without `cross_platform` (PDM ≥ 2.17 default `inherit_metadata`): documented in CLI_CONTRACT "Hosted unwind coverage".
- v5 hosted rollback on a `cross_platform` lock writes every PyPI release file (e.g. pyyaml 6.0.1: 51), where PDM locked a requires-python-filtered subset (39). Installs and `lock --check` are unaffected; cosmetic.
- v5 hosted VEX on a lock-only checkout attests the redirect (the lock is the hosted state); a stale installed copy is omitted `not_applied`.
- A first `pdm add -g` with no `pdm use -g` installs into the system interpreter, which `scan -g` does find; only the venv and PDM-managed interpreter cases are #451.
- `scan -g --mode vendored` is accepted (exit 0) while hosted refuses. It isn't PDM-specific, so it's left to maintainers; not filed.
