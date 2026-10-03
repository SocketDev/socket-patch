[agent] Progress ledger for the scheduled PDM bug-hunt routine (label pm:pdm).

Last run: 2026-10-03 03:15Z on main `045d7ec` (latest tag v4.0.0; #522 and #540 merged; #332/#451/#502/#528 closed by maintainers). Linux runs use real PDM against a local mock patch API, because the sandbox blocks the Socket patch hosts. macOS and Windows runs use probe branches.

## Coverage matrix
| PDM | lock_version | agent (Linux / macOS / Windows) | hosted (Linux) | vendored (Linux) |
| --- | --- | --- | --- | --- |
| 1.4.5 | 2 | untested | pass on v5 (`__pypackages__` sync, legacy `[metadata.files]`, rollback byte-exact; CRLF lock pass `d63ae5f`); post-rollback install fail #477 | pass `d63ae5f` (CRLF lock, sync patched, rollback byte-exact) |
| 2.0.3 | 4.0 | fail #332 w/ install.cache symlink; fail #502 (`.pdm.toml` `python.path`) / untested / untested | refused (documented) | refused (documented) |
| 2.8.2 | 4.3 | fail #332 w/ install.cache symlink (all 3 OS) | pass (stale-install warning) | untested |
| 2.10.4 | 4.4 | fail #332 w/ install.cache symlink; pth fails closed | pass (stale-install warning) | untested |
| 2.11.2 | 4.4.1 | fail #332 w/ install.cache symlink | untested | untested |
| 2.12.4 | 4.4.1 | fail #332 w/ install.cache symlink (all 3 OS; re-confirmed on v5 Linux); hardlink pass; fail #502 (`venv.in_project=false`; pass on PR #540) | pass (v5: #331/#382 fixed; dev/optional groups, relocks, `pdm add` repair); fail #528 (PEP 582 stale warning + VEX; pass on PR #540); fail #413 (private index static_urls); post-rollback install fail #477; CRLF lock pass; extras `[socks]` pass | pass on v5 (warm sync patched, vex; CRLF / mixed-ending lock, extras `[socks]`); post-rollback install fail #477 |
| 2.15.4 | 4.4.1 | pass (all 3 OS, symlink + hardlink) | untested | untested |
| 2.20.1 | 4.5.0 | pass | pass (v5: #331/#382 fixed); fail #413 | pass (v4) |
| 2.26.9 | 4.5.0 | pass (symlink/hardlink/pth) | pass on v4; untested on v5 | untested |
| 2.29.2 | 4.5.1 | pass (all 3 OS, in-project `.venv`); fail #502 Linux (`venv.in_project=false` / `pdm use <venv>`: real env skipped, stray `.venv` or PATH python patched; pass on PR #540); space/unicode path pass | fail #528 (PEP 582 `__pypackages__`: no stale warning, VEX attests; pass on PR #540); CRLF lock pass, mixed-ending rollback LF-normalizes (cosmetic); extras `[socks]` pass; concurrent scans `lock_held` pass; space/unicode path pass; pass on v5 (dev/optional groups, `update --update-all/--update-reuse/--unconstrained`, `lock --refresh` keeps patch, lock-only scan, sync, manifest-less rollback byte-exact, VEX); multi-target fork refused (documented); fail #413 (re-confirmed `61cfb9b`); stale warning + VEX with out-of-tree env fail #502; post-rollback install fail #477 | pass on v5 (warm/fresh/frozen, lock --check, idempotent, vex, rollback byte-exact; private index + `static_urls` rollback byte-exact; nested `services/*` project; agent→vendored takeover; CRLF / mixed-ending lock; extras `[socks]`; `rollback --preserve-state` → re-scan; concurrent scans; space/unicode path); post-rollback / `remove` install fail #477 |
| 1.15.5 | 3.1 | fail #502 (`.pdm.toml` `python.path` external venv) | refused (documented) | refused (documented) |
| 2.15.4, 2.20.1 | 4.4.1 / 4.5.0 | — | `pdm add` → uninstallable lock (PDM reuse, #331); re-scan repairs (pass) | `pdm add` → rollback fails closed; `pdm lock` → re-scan → rollback (pass) |
| 1.4.5 / 1.15.5 / 2.0.3 | 2 / 3.1 / 4.0 | agent PEP 582 (`.pdm.toml` `python.path`; plain, activated venv, stray `.venv`) pass on `045d7ec` | — | — |
| 2.27.0 – 2.29.2 | 4.5.x | agent PEP 582 with `pdm.toml` `use_venv = "false"` (PDM-written string) + activated / stray venv: **fail #609**; bool form and `PDM_USE_VENV` pass | — | — |
| all (2.26.9, 2.29.2 run) | — | agent PEP 582 with `use_venv` false in the **user** config + stray venv: **fail #609** | — | — |
| 0.12.3 | 2 (legacy `[tool.pdm]`) | untested | pass (fresh sync patched, rollback byte-exact); `vex` / `scan --vex` **fail #642** | pass (same); `vex` **fail #642** |
| 1.0.0 | 2 | untested | pass (fresh, vex, rollback byte-exact) | pass (fresh, vex, rollback byte-exact) |
| 1.5.3 | 2 | untested | pass (fresh) | pass (fresh, rollback byte-exact); warm env **fail #641** |
| 1.6.4 | 3 | untested | refused (pass) | refused (pass) |
| 1.4.5 / 2.8.2 / 2.10.4 | 2 / 4.3 / 4.4 | — | warm env warns (pass) | warm env: no stale warning, `pdm sync`/`install` keep upstream, vex attests: **fail #641** |
| 2.11.2 / 2.29.2 | 4.4.1 / 4.5.1 | — | — | warm env re-installs patched (pass) |
| 1.8 – 1.14 | 3.1 | untested | untested | untested |

Modes × macOS/Windows for hosted and vendored: untested by this routine (the repo's pdm-compatibility.yml covers them).

### Global mode (`-g`, maintainer request)
| PDM | global location | scan -g report (Linux) | apply / rollback / vex -g (Linux) | macOS / Windows |
| --- | --- | --- | --- | --- |
| 2.29.2 | system interpreter (default) | pass | pass (apply, idempotent, vex, rollback byte-exact) | untested |
| 2.29.2 | `pdm use -g` → `global-project/.venv` | pass on main `d63ae5f` (#451 fixed) | pass via `--global-prefix` (incl. space/unicode path, install.cache symlink per-file) | untested |
| 2.29.2 | PDM-managed `cpython@3.12` | fail #451 (pass on PR #522, apply + rollback) | untested |
| 2.29.2 / 2.12.4 | `venv.in_project=false` → `<data>/pdm/venvs/global-project-*` | pass on main (user-config `venv.location`, apply + rollback) | untested |
| 2.29.2 / 2.12.4 | `global_project.path` set in the **site** config `/etc/xdg/pdm/config.toml` | **fail #566** (user-config control passes) | get -g patches another copy, global-project copy unpatched | untested |
| any | same release also in an earlier global env (system / pipx) | — | only the first copy patched (#501, generic) | untested |
| 2.12.4 | system interpreter (default) | pass | pass without install.cache; **fail #332** with install.cache symlink (writes PDM cache) | untested |
| 2.12.4 | `pdm use -g <pdm python>` (no venv) | fail #451 | untested |
| 2.12.4 | `global-project/.venv` | fail #451 (pass on PR #522) | — | untested |
| any | unwritable prefix (non-root) | — | exit 1, file untouched (pass); `scan --json` drops the reason (#424) | untested |
| 0.12 – 2.0.3 | — | untested | untested | untested |

`-g --mode hosted` and `--global-prefix --mode hosted` refuse with exit 2 (pass). `SOCKET_GLOBAL=1` matches `-g` (pass). `--global-prefix <site-packages>` finds both #451 locations (pass).

## Backlog
1. #641 follow-ups: vendored on a warm PEP 582 `__pypackages__` (PDM 1.x); per-version `pdm sync --reinstall` remedy.
2. #609 on macOS / Windows user-config paths, site config, `PDM_CONFIG_FILE`. (PDM ≥ 2.27 string `venv.in_project` doesn't matter: socket-patch never reads it and follows `.pdm-python` instead.)
3. #566 on macOS / Windows site-config paths and site-config `venv.location` / `python.install_root` (use a non-3.11 interpreter). PDM 1.x global project (`~/.pdm/global-project`) under `-g`.
4. Re-run #477 / #413 on main once `patch/redirect/pdm.rs` or `upstream/pypi_locks.rs` change (hosted mock: references + view).
5. Hash variant of #413 (private index serving different bytes); PDM 1.x `feature.install_cache` with agent mode; PDM 1.8 – 1.14 agent cells.
6. macOS / Windows probes (branch deletion through the proxy / permission policy has failed before; the stale `bughunt/pdm/20260930-cache-symlink` needs a maintainer to delete it).
7. Done: PDM 0.12.3 / 1.0.0 / 1.5.3 hosted + vendored fresh; #502/#528 on main for 1.4.5 / 1.15.5 / 2.0.3 agent PEP 582; CRLF lock_version 2, SIGKILL-interrupted scans, groups, relocks, `pdm add` after hosted/vendored, CRLF / mixed / BOM locks, extras, `rollback --preserve-state`, concurrent scans, space/unicode paths.

## Known non-bugs
- lock_version absent / 3.1 / 4.0–4.2 refused; 2.8.0 accepted-but-crashes (documented).
- `__pypackages__` (PEP 582) not crawled; agent mode falls through to the PATH interpreter (documented). Hosted mode installs into `__pypackages__` fine.
- A plain relock (`pdm lock`, `pdm update <pkg>`) drops the hosted / vendored patch (documented; re-scan). Measured: `pdm lock --refresh` actually **keeps** it on 2.12.4 and 2.29.2 (the doc's claim is conservative drift, not a bug). Rollback still works when the package stays at the same version.
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
- `rollback` deletes the manifest entry (documented: it removes local state), so a later `apply` is a no-op.
- A mode-less `scan` without `-g` / `--prune` defaults to hosted and rewrites `pdm.lock` (documented default).
- From a monorepo root, `scan 'services/*'` writes per-project `.socket/`, but `rollback` from the root reports `Manifest not found` (use `--cwd services/api`). That's generic, not PDM-specific; left to maintainers.
- After an agent → vendored takeover, `.socket/manifest.json` stays as `{"patches": {}}` (cosmetic).
- Test-harness note: PDM's http:// downloads from a 127.0.0.1 mock get a 405 from the agent proxy unless `HTTPS_PROXY` is unset (sandbox artifact, not a bug).
- PDM 2.12 – 2.20 `pdm add <other>` after hosted/vendored keeps the patched hash but drops the `url`/`path` (an uninstallable lock, PDM reuse behaviour, known from #331). Hosted re-scan repairs it. Vendored re-scan refuses (`pypi_pdm_source_already_exists`, "run `pdm lock`") and rollback fails closed (drift); the `pdm lock` → re-scan → rollback path works. 2.29.2 keeps the source.
- `pdm sync --prod --clean` leaves dev/optional-only packages installed: identical without socket-patch (PDM behaviour).
- The hosted stale-install warning mentions "Poetry before 1.4" on PDM projects (generic text, cosmetic).
- Test-harness note: VEX resolves the hosted patch uuid from the URL's second uuid segment, so a mock `view` must answer for it. Don't `pkill -f mock`, which kills the calling shell.
- A UTF-8 BOM `pdm.lock` is rejected by PDM itself (`lock --check` / `sync` fail with no socket-patch involved).
- Hosted rollback of a lock that **mixes** CRLF and LF rewrites the whole file to LF (scan only touches the edited unit; vendored rollback and pure-CRLF hosted rollback are byte-exact). PDM never writes mixed endings and the result is semantically identical, so it's cosmetic and not filed, though it drifts from pdm-compatibility.md's "preserves line endings".
- Test-harness note: hosted refs on a mock origin need `SOCKET_PATCH_SERVER_URL`; vendored grants need `integrity.sha512` as SRI. `pdm use` in a fresh dir can pick another project's interpreter, so write `.pdm-python` explicitly. Out-of-tree PDM venvs are shared between copies of a project dir, so reset them (`pdm sync --reinstall`) between builds.
- A SIGKILLed hosted/vendored scan leaves `.socket-stage-pdm.lock-<uuid>` files in the project root that re-scan / rollback never sweep. The lock itself is always original or fully rewritten (85 kills, 2.29.2). Generic staging behaviour and crash-only, so it's left to maintainers.
- Test-harness note: the sandbox's `/usr/local/lib/python3.11/dist-packages` now carries urllib3 1.26.18 (from a `pdm add -g` with no global venv), which masks `-g` scan counts on python3.11; check the file bytes of the target copy instead.
- PDM 2.0–2.4 treat a `.pdm.toml` with a base `python.path` (from `pdm use -f <base>`) as PEP 582, and discovery agrees (verified on 2.0.3).
- Agent `vex` after a #609 mis-patch fails closed (`not_applied`), so there's no false attestation there.
- `lock_version` by release: 1.5.x writes `2` (supported, installs fine), 1.6.x writes `3` and 1.7.x writes `3.1` (both refused, lock untouched). pdm-compatibility.md's "0.12 – 1.4" / "1.8 – 1.15" ranges are slightly off (doc drift only).
- The vendored `vex` attestation over an out-of-sync installed tree is by design (the `vendored_tree_out_of_sync` disclosure). #641 covers only the missing scan warning and the remedy on PDM < 2.11.
- Test-harness note: PDM 1.5.x needs `resolvelib==0.7.0`; PDM 1.x `pdm sync` exits 1 on a throwaway `[project]` without `[tool.pdm] distribution = false` (self-install), unrelated to socket-patch.
