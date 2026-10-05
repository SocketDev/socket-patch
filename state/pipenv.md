[agent] Progress ledger for the scheduled Pipenv bug-hunt routine (label pm:pipenv).

The routine runs every 6 hours. Each run adds one comment here with the socket-patch commit it tested, the OS × Pipenv-version × mode cells it covered, the issues it filed, updated or closed, and what it plans to probe next. The routine treats this thread as its only memory.

Last run: 2026-10-05 ~09:30Z, main `045d7ec` (CLI 4.0.0, unchanged). A Pipfile `[pipenv] venv_in_project = true` with no `./.venv` makes agent mode miss the WORKON_HOME venv on Pipenv 2018–2026.1 (only 2026.2+ read the key). It patches the system Python instead and vex attests `not_affected`: filed #842 (PR #654 doesn't fix it). PR #654 (#645 + #546), #730 (#725), #795 (#790) and #825 (#769) are still open.

## Coverage matrix

Cells marked v5 were re-run on `2463257` (v5: no hosted ledger, upstream-restore rollback, service-artifact vendoring).

| OS | Pipenv | agent (OOT venv) | agent (stray venv/ or .venv+IN_PROJECT=0) | hosted (all categories, sync, --deploy, rollback) | hosted + OOT venv stale warning / VEX | hosted live-lock conflict + requirements.txt | vendored (lock-only, repair, revert) | hosted → vendored | vendored → hosted | VIRTUAL_ENV w/ IGNORE_VIRTUALENVS / PIPENV_ACTIVE |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 2018.11.26 | pass `61cfb9b` (unicode/space/paren names, nested PIPENV_PYTHON chain) | .venv + WORKON venv: pass `d63ae5f` (#529 fixed); `.venv` + `PIPENV_VENV_IN_PROJECT=0` / `NO_VENV_IN_PROJECT=1`: fail #645 `045d7ec` | pass v5 (+CRLF); `Six` casing pass `045d7ec` | stale warning + remedy pass `045d7ec` | fail #333 | pass v5; + sibling requirements.txt fail #612 | pass `045d7ec` (default + develop) | pass `045d7ec` (default + develop) | fail #384 |
| Linux | 2022.12.19 | multi-copy (.venv + WORKON) + rollback w/ modified copy pass `045d7ec` | .venv + WORKON venv, nothing explicit: pass (#529 fixed); `.venv` + `PIPENV_VENV_IN_PROJECT=0` / `NO_VENV_IN_PROJECT=1`: fail #645 `045d7ec` | pass v5 (+relock); `[docs]`-only + rollback pass `61cfb9b`; `--hash` requirements.txt pass `045d7ec` | stale warning + remedy pass `045d7ec` | fail #333 | pass `045d7ec` (lock-only, sync / --deploy, tamper rejected, repair, revert byte-exact) | pass `045d7ec` (default + develop) | untested | untested |
| Linux | 2023.12.1 | pass; `PIPENV_VENV_IN_PROJECT=0` + .venv + WORKON pass `045d7ec` (2023.11.14 too; 2023.10.24 fails #645) | .venv + WORKON venv: pass `d63ae5f` (#529 fixed); `.venv` reset to pristine → vex `not_applied` pass `045d7ec` (#516 fixed) | pass v5 (+relock); verify / requirements / deploy pass `61cfb9b` | pass; fail #334/#384 shapes (false VEX) | fail #333 | + sibling requirements.txt fail #612 | pass `045d7ec` (prefix) | pass `045d7ec` (+ requirements.txt) | fail #384 (agent + hosted VEX) |
| Linux | 2026.8.0 | pass `61cfb9b`; `NO_VENV_IN_PROJECT=1` / `VENV_IN_PROJECT=0` + .venv pass `045d7ec`; PIPENV_PYTHON-suffixed twin venv pass `d63ae5f`; `.env` WORKON_HOME still fails #546 `045d7ec` | pass `61cfb9b` (#334 fixed); .venv + WORKON pass `d63ae5f`; #504 still fails `d63ae5f`; no-Pipenv-venv shapes patch the system Python, fail #504 | pass v5 (+CRLF); verify / requirements / deploy pass `61cfb9b` | pass; #334/#384 shapes untested since the fix | pass `61cfb9b` (#333 fixed) | pass v5; + sibling requirements.txt fail #612 | pass v5; prefixed server pass `045d7ec`; requirements.txt unpatched fail #612 | pass `045d7ec` (#328 fixed; default + develop + `[docs]`, requirements.txt) | pass `61cfb9b` (#384 fixed) |
| Linux | 2020.11.15 (py3.8) | warm venv agent + rollback pass `045d7ec`; `.venv` + `PIPENV_VENV_IN_PROJECT=0` → global fallback fail #645 | untested | pass `045d7ec` (lock-only deploy / sync / vex / byte-exact rollback) | stale warning + both remedies + vex pass `045d7ec` | untested | pass `045d7ec` (lock-only, tamper rejected, `vendor --check` exit 1) | untested | untested | untested |
| Linux | 2021.5.29 (py3.8) | same as 2020.11.15 (pass; #645 shape fails) | untested | pass `045d7ec` (+ `get CVE`, idempotent re-run, `remove` byte-exact) | stale warning + both remedies + vex pass `045d7ec` | untested | pass `045d7ec` (+ `get --mode vendored`, `remove` byte-exact) | untested | untested | untested |
| Linux | 2024.4.1 | pass `61cfb9b`; multi-copy + rollback w/ modified copy pass `045d7ec` | untested | pass `61cfb9b` (default + `[docs]`, verify / requirements / sync / --deploy / vex / byte-exact rollback) | untested | untested | pass `61cfb9b` (both categories, sync / --deploy / vex / repair / rollback) | untested | untested | untested |
| Linux | 2025.1.3 | multi-copy + rollback w/ modified copy pass `045d7ec`; Pipfile `venv_in_project = true` fail #842 `045d7ec` (also 2018 / 2023 / 2026.1) | untested | pass `61cfb9b` (same as 2024.4.1) | untested | untested | pass `61cfb9b` (same as 2024.4.1) | untested | untested | untested |
| macOS | 2023.12.1 | pass | fail #334 | untested | untested | fail #333 | untested | untested | untested | fail #384 |
| macOS | 2026.8.0 | pass | fail #334 | untested | untested | fail #333 | untested | untested | untested | fail #384 |
| Windows | 2023.12.1 | pass | fail #334 | untested | untested | fail #333 | untested | untested | untested | fail #384 |
| Windows | 2026.8.0 | pass | fail #334 | untested | untested | fail #333 | untested | untested | untested | fail #384 |
| Linux | 2022.12.19 `-g` (`install --system --deploy`, py3.10) | `-g --global-prefix <site-packages> --apply` / `rollback -g` pass, lock untouched; hosted refused exit 2 pass (`61cfb9b`) | | | | | | | | |
| Linux | 2018.11.26 `-g` (`install --system`) | scan -g report pass; `-g --mode hosted` refused exit 2 pass; `-g --apply` / vex / rollback pass | | | | | | | | |
| Linux | 2023.12.1 `-g` (`install --system`) | scan -g report (in/out of project), hosted refused exit 2, `-g --apply` / vex / rollback, SOCKET_GLOBAL, `--global-prefix` pass; `rollback -g` / `remove -g` / `get -g --mode hosted\|vendored` unwind or rewire the cwd project's Pipfile.lock (#445 / #436) | | | | | | | | |
| Linux | 2026.8.0 `-g` (`install --system`) | scan -g report (in/out of project), SOCKET_GLOBAL, `--global-prefix` pass; hosted refused exit 2 pass; `-g --apply` / `get -g` / vex / rollback pass | no-`-g` agent scan in a venv-less project patches the global interpreter (needs a maintainer decision, see Known non-bugs) | | | | | | | |
| Linux | 9.1.0 / 11.10.4 (py3.8) | pass on 11 `61cfb9b` (unicode/space/paren names, PIPENV_PYTHON suffix) | untested | pass v5 (`path` ref, `--deploy`, rollback; 11 byte-exact) | pass on 11 (stale warning, VEX `not_applied`) | untested | refused (documented) | n/a | n/a | untested |
| macOS / Windows | 7–11 | untested | untested | untested | untested | untested | refused (documented) | n/a | n/a | untested |
| any | 0–6 | untested | n/a | refused (documented) | n/a | n/a | refused (documented) | n/a | n/a | untested |

Dotted / underscored distribution names (`jaraco.context`, `typing_extensions`), `09:37Z` run, `045d7ec`: hosted lock-only (2023), vendored (2018 / 2023 / 2026), agent + stale-warning remedy (2018 / 2026) all pass. Lock entries with `extras`: hosted (`file`) and vendored (`path`) on 2022 / 2023 / 2026 pass; a tampered `path` + extras wheel is rejected on 2018 / 2022 (pass). Pipenv 2026 `install <other>` keeps the hosted or vendored reference (pass). Hosted stale warning with `.venv` + WORKON + `PIPENV_VENV_IN_PROJECT=0` on 2018 / 2022 names only WORKON: fail, #645 (vex stays conservative, `not_applied`).

Non-default `index` (`six = {version, index = "private"}`, second http `[[source]]`), `15:32Z` run, `045d7ec`: hosted lock-only on 2018.11.26 / 2022.12.19 / 2023.12.1 / 2026.8.0 keeps `index`, and `sync` / `--deploy` give PATCHED (pass). 2026 vex / `verify` / `requirements` → pip pass. Vendored on 2018 / 2026: sync / --deploy / check / byte-exact rollback pass. Hosted → vendored is refused fail-closed (`redirect_revert_failed`), and vendored → hosted restores `index` (pass). Hosted rollback refusal: documented.

Hosted with a path-prefixed `--patch-server-url`, a rotated grant token, or an sdist hosted artifact (2026.8.0, `045d7ec`, #572): rotate, sync / --deploy, verify, vex and byte-exact rollback all pass.

Hosted + `requirements.txt` with `-r req/base.txt` pinning the package (Pipenv 2018 / 2023 / 2026 locks, `d63ae5f` and `8eec03a`): fail #567. Hosted lock-only `default` + `develop` + root requirements.txt (2023 / 2026, `d63ae5f`): pass, except rollback refuses the all-hosted requirements.txt (#410).

`.env`-borne Pipenv settings (agent + hosted stale warning): `PIPENV_CUSTOM_VENV_NAME` in `.env` fails #546 on 2022.12.19 / 2023.12.1 / 2024.4.1 / 2025.1.3 / 2026.8.0 (the exported control passes); `WORKON_HOME` in `.env` fails #546 on 2023 / 2026. `--global-prefix` with spaces and unicode (site-packages path, 2026.8.0): pass.

Agent rerun after a reinstall (2026.8.0, `61cfb9b`): `--json` pass; human-mode `scan --apply` / `--mode agent` / `--sync` fail, #454 incomplete (commented). `PIPENV_PIPFILE` spellings with `--cwd`: pass.

Policy (socket.yml) cells, Linux 2026.8.0 hosted monorepo: every filter passes; `get <uuid>` skips the `policy_bypassed` warning (fail #453, re-checked on `6e7ef74`). socket.yml × `--package` / `--min-severity` / `--max-new-patches` intersections: pass (`6e7ef74`). Concurrent hosted scans: pass. SIGKILL mid hosted / vendored run: pass. Mirror / env-var source rollback refusal: pass (documented).

Named category on 2026.8.0 (`61cfb9b`): `pipenv requirements --categories docs` / `--dev`, `verify`, `sync --categories docs` and `install --deploy --categories "packages docs"` all give the patched wheel (pass). Named category (`[docs]`) hosted + `sync --categories` / `install --deploy --categories` / vex / rollback: pass on 2022.12.19, 2023.12.1 and 2026.8.0; vendored: pass on 2022.12.19 and 2023.12.1 (`6e7ef74`). Non-registry entries (`path`, `file` URL, `git`): hosted refuses with `redirect_pipenv_refused`, vendored with `pypi_pipenv_source_already_exists`, vex attests nothing: pass on 2026.8.0.

`-g` / agent on an unwritable prefix or a root-owned `.venv`, as a non-root user (2026.8.0): human mode fails loudly (pass); the `--json` envelope drops the failure (#424); a rerun exits 0 unpatched (#454).

Hosted `pipenv requirements --hash` sibling (2022 / 2026, `045d7ec`): hash mode kept, `pip install --require-hashes` PATCHED (pass); rollback refusal there is #410. Vendored + hashed sibling requirements.txt: `vendor --revert` / rollback byte-exact on both files (2026, pass).

`pypi`-named `[[source]]` on a mirror (no pypi.org in `_meta.sources`), `21:36Z` run, `045d7ec`: hosted lock-only on 2018.11.26 / 2026.8.0 (sync / --deploy PATCHED, vex `not_affected`) pass; hosted rollback refused (documented); vendored on 2018 / 2026 (sync / --deploy / check / vex / byte-exact rollback) pass. Hosted path-prefixed server (`/cdn/v2`), lock-only: Pipenv 11.10.4 (`path`), 2018.11.26 and 2022.12.19 (--deploy, vex, idempotent re-scan, byte-exact rollback) pass. A transitive entry with `markers` and no `index` (hosted, 2026): pass. Vendored, then `pipenv lock` (ref dropped) on 2018 / 2022 / 2023 / 2026: vex `vendor_unwired` (correct), but `vendor --check` stays green: fail #725.

In-run VEX (`scan --vex`), `04:00Z` run, `045d7ec`: hosted with a stale OOT venv on 2018 / 2022 / 2026 omits the patch and exits 1 with `no_applicable_patches` (also with `--vex-no-verify`), and attests after the remedy (pass). Vendored in-run VEX over a warm unpatched venv attests with `vendored_tree_out_of_sync` (documented). Hosted `.venv` + WORKON + `PIPENV_VENV_IN_PROJECT=0` with WORKON patched (2018 / 2022): in-run and standalone vex give a false `not_affected` (fail #645; PR #654 fixes it). `--dry-run` hosted / vendored / agent scan and hosted / vendored get write nothing (pass); hosted JSON drops the vex dry_run marker (fail #744). Vendored `remove` gives a byte-exact lock (pass). `vendor --check` with the file ref pointing at another or missing uuid stays green (fail #725).

Superseding patch (uuid A → B), `~10Z` run, `045d7ec`: hosted re-pin + stale warning + remedy + vex on 2026.8.0 pass. Vendored re-vendor fails on 2018.11.26 / 2022.12.19 / 2023.12.1 / 2026.8.0, both lock-only and venv-present (#769); `--dry-run` previews `would_revendor`. The `vendor --revert` + re-scan workaround passes.

CRLF Pipfile + Pipfile.lock, `21:42Z` run, `045d7ec`: vendored on 2018 / 2026 (CRLF kept, `--deploy` patched, vex, byte-exact rollback) pass; hosted on 2018 / 2026 (CRLF kept, `--deploy`, vex) pass. `vendor` / `apply --dry-run --vex` write no VEX (pass). `pipenv install <other>` on 2022 / 2023 relocks the reference away and vex refuses (documented, pass). PR #795 cells: see #790.

Stale-install remedy followed verbatim, `15:30Z` run, `045d7ec`: `default` patched on 2018 / 2022 / 2023 / 2026 (pass). `develop` (2018–2026) and `[docs]` (2022–2026), hosted and vendored, both printed remedies leave the package uninstalled (fail #790). Hosted supersede A → B on 2018 (default / develop), 2022 (develop / docs), 2023 (default / docs) and 2026 (docs / develop): re-pin, stale warning and conservative vex all pass; rollback / remove after the supersede are byte-exact (pass); with a sibling requirements.txt both files re-pin (pass), and the rollback refusal is #410.

`03:38Z` run (2026-10-05), `045d7ec`: mixed sources (a mirror named `pypi` first, pypi.org as `upstream`) hosted rollback on 2026: an index-less entry is restored byte-exact (pass); `index = "pypi"` (the mirror) is refused (documented). Symlinked `Pipfile` / `Pipfile.lock`: hosted `redirect_symlinked_file_unsupported` and vendored `pypi_pipenv_symlink_unsupported`, nothing written (pass). `.venv` symlinked to an out-of-tree directory (IN_PROJECT=1 / unset): pass. Venv drift (venv 1.15.0, lock 1.16.0), hosted + vendored: pass. Pipenv project with a pdm-backend `pyproject.toml`: pass. `list` on hosted: pass. `pipenv --site-packages` / `PIPENV_SITE_PACKAGES=1` with six in the base interpreter: hosted (2018 / 2022 / 2023 / 2026) and vendored (2018 / 2026) keep the base's unpatched six even in a fresh venv, give no warning, and vex attests `not_affected`: fail, #409 (commented).

`09:32Z` run (2026-10-05), `045d7ec`: Pipfile `[pipenv] venv_in_project = true` with no `./.venv`, agent mode: fail #842 on 2018.11.26 / 2023.12.1 / 2025.1.3 / 2026.1.0 (WORKON venv unpatched, system Python patched, vex `not_affected`); pass on 2026.8.0 (`./.venv`) and on the key-less control; the PR #654 head `d8356ae` still fails. Relative `WORKON_HOME` with `--cwd` from another directory: misses the venv (see Known non-bugs).

macOS/Windows rows are from the 2026-09-30 probes on `f6b7fb9`. No probe ran on v5 because branch deletion through the git proxy still fails (re-checked 2026-10-03 03:30Z); `bughunt/pipenv/20260930-venv-discovery` and `bughunt/pipenv/20260930-virtualenv` still need a maintainer to delete them.

## Backlog

000. Re-verify #790 on main once PR #795 merges (#795 `fbdfa6f` passes every Linux cell, see the #790 comment of 2026-10-04 21:42Z). Windows cmd / PowerShell quoting of `--categories "…"` is untested.
00. Re-verify #769 once fixed (vendored re-vendor A → B: rewire in place, old uuid dir removed, revert byte-exact, no false `package_not_installed` with a venv). (Hosted supersede on 2018 / 2022 / 2023, develop / named categories and with a sibling requirements.txt: done 2026-10-04 15:30Z, pass.)
0. Re-verify #645 once it's fixed (now including hosted in-run / standalone VEX, which gives a false `not_affected` on main and passes on `d8356ae`) (PR #654 `d8356ae` already passes the agent + hosted-warning repros on 2018 / 2022) (2018 / 2022 / 2023.10.24 with `PIPENV_VENV_IN_PROJECT=0`, `=false`, `PIPENV_NO_VENV_IN_PROJECT=1`; 2023.11.14+ must keep using WORKON). Also check its hosted shape: the stale warning and vex look at WORKON while Pipenv ≤ 2023.10 installs into `.venv`.
1. #612 variants still open: `-r` includes in vendored mode. Re-verify once fixed. (Revert / rollback on the half-wired project pass.)
2. Re-verify #546 once it's fixed: `.env` with `PIPENV_CUSTOM_VENV_NAME`, `WORKON_HOME`, `PIPENV_VENV_IN_PROJECT=0` + `.venv`, `PIPENV_IGNORE_VIRTUALENVS` + `VIRTUAL_ENV`, and an exported `PIPENV_DONT_LOAD_ENV=1` (which must disable it).
3. Re-verify #504 and the #454 human-mode gap once they're fixed.
4. #567 variants: vendored mode with an `-r` include, `remove`, `-c` constraints; re-verify once fixed.
5. **Maintainer request (global `-g` mode):** still to do: macOS / Windows, `-g` on 2018 / 11, and `--global-prefix` as a venv root (scans 0; undocumented). Checklist in the 20261001T040000Z entry.
6. Re-verify #725 once fixed (incl. the uuid-drift shapes), and #744. (`install <other>` on 2022 / 2023 and the vendor / apply dry-run VEX: done 2026-10-04 21:42Z, pass.) (Mirror-named `pypi` source and hosted path-prefix on 11 / 2018 / 2022 done 2026-10-03 21:36Z, pass.)
6b. Re-verify #409 for Pipenv once fixed: `--site-packages` fresh + warm venv, hosted + vendored, 2018–2026 (stale warning or vex refusal expected). (Mixed-sources hosted rollback: done 2026-10-05, pass.)
6c. Pipenv 2020 / 2021: the #790 `[dev-packages]` remedy, and include them in the #645 re-verification. (Relative `WORKON_HOME` with `--cwd`: done 2026-10-05 09:32Z, see Known non-bugs.)
6d. #842: verify the hosted shape (stale-install warning with a warm WORKON venv + `venv_in_project = true` on ≤ 2026.1), and re-verify once fixed (2018 / 2023 / 2025 / 2026.1 fail, 2026.2+ use `./.venv`). Also Pipfile key × `PIPENV_VENV_IN_PROJECT` precedence on 2026.2+.
7. A macOS/Windows probe re-verifying #333 / #334 / #384 / #529 / #546 / #645, and hosted / vendored on 2018 / 2022 there (CRLF on Windows). Blocked until branch deletion through the git proxy works (still denied 2026-10-05 03:30Z).

## Known non-bugs

- Hosted vex with `.venv` + WORKON venv under `PIPENV_VENV_IN_PROJECT=0` checks both copies, so it gives `not_applied` when either is stale. That's correct; only the stale warning is #645.

- Vendored over a hosted pin from a path-prefixed patch server, with no `--patch-server-url` / `SOCKET_PATCH_SERVER_URL` naming that origin: `pypi_pipenv_source_already_exists`. Since #572 a foreign origin isn't ours, so this fails closed by design.

- Pipfile.lock with `pipfile-spec` < 6 (Pipenv 0–6): hosted is refused (`redirect_pipenv_skipped`) and vendored is refused (`pypi_pipenv_spec_unsupported`). Documented.
- Vendored on Pipenv 7–11 is refused (`pypi_pipenv_installer_unsupported`). Documented.
- A warm venv is never reinstalled by `pipenv install` / `sync` / `--deploy`; the stale-install warning is the designed remedy. Documented.
- `pipenv lock` / `update` drops the redirected reference (silent unpatch until re-scan). Documented.
- Pipenv 2023+ don't hash-check local wheels, so vendored carries `vendor_integrity_unverified`. Documented.
- The CLI doesn't walk up to a parent Pipfile or follow `PIPENV_PIPFILE`. Documented.
- `rollback` drops manifest entries, so a later `apply` is a no-op. Documented.
- Pipenv 2026.8.0 crashes on `$VAR` inside `WORKON_HOME`. That's Pipenv's bug.
- `vendor_fetch_failed` against pypi.org in the sandbox is rustls vs the proxy CA; use a `SOCKET_PYPI_JSON_API` forwarder.
- `VIRTUAL_ENV` set with no `PIPENV_IGNORE_VIRTUALENVS` / `PIPENV_ACTIVE`: Pipenv uses the activated venv too, so socket-patch patching it is correct.
- `.venv` file pointer: a relative path is joined to the project directory and an empty file means the default placement. Matches Pipenv 2026.8.0.
- v5 `rollback` on a project with no manifest, ledger or hosted pin exits 1 "Manifest not found". Documented (CLI_CONTRACT, truly-empty project).
- v5 hosted rollback refuses when the entry's index isn't PyPI, or when offline. Documented (the upstream-restore refusals).
- Vendored drops the Pipfile.lock entry's `index` key. Harmless for a local wheel, and rollback restores it.
- `rollback <path>` targets select installed copies, not hosted project directories; use `--cwd`. Documented, and cross-PM anyway.
- Mock-API note: a hosted artifact URL must have the `/patch/pypi/<name>/<ver>/<token>/<uuid>/<wheel>` shape, and `SOCKET_PATCH_SERVER_URL` must name the mock origin, or vex / rollback see no hosted reference.
- `scan -g --mode hosted --json` prints a plain-text usage error with exit 2 (a clap-level refusal, documented).
- Mock-API notes: vendoring needs `integrity.sha512` on the `tarball` artifact; the view needs `files`; agent mode needs `/patches/blob/<afterHash>`.
- **Filed as #504 (2026-10-01), formerly an open question:** with no venv found and a Python project marker present, the crawler deliberately falls back to the global interpreter (`python_crawler.rs` `get_site_packages_paths`). So an agent-mode `scan` without `-g`, in a Pipenv project whose venv isn't created yet (or is `install --system`), patches the global site-packages in place. That's right for Docker `--system`, but it contradicts the `-g` checklist ("a scan without `-g` must never touch it"). Filing waits on a maintainer decision.
- A Pipenv 9.1.0 lock written with `"hashes": []` (seen in the sandbox) comes back from hosted rollback with PyPI's full hash list: not byte-exact, but a valid and stricter registry entry. The upstream restore re-derives hashes by design.
- Hosted rollback refuses a `_meta.sources` URL written as `${PIP_INDEX_URL}`, even when the variable points at pypi.org; env vars aren't expanded. Documented and fail-closed, with the `git checkout` remedy.
- `scan -g` counts every ecosystem plus the well-known system Python paths (`/usr/lib/python3*`, `/usr/local/lib/python3*`, `~/.local`). That's by design; Pipenv's WORKON_HOME venvs aren't included.
- `--prune` warns that it has no effect with `--mode hosted`. Documented.
- Non-registry Pipfile.lock entries (`path`, `file` URL, `git`) are refused in hosted (warning, exit 0) and vendored (`pypi_pipenv_source_already_exists`, exit 1). By design; the "no Pipfile beside the lock" wording in the hosted detail is #333.
- Mock-API note: the batch mock must filter by the requested purls, and `by-package` must carry `vulnerabilities[*].severity`, or `--package` / `--min-severity` cells give false failures.
- A non-UTF-8 Pipfile makes hosted treat the lock as abandoned, but Pipenv itself refuses that Pipfile (`UnicodeDecodeError`). Not a real-world shape.
- `PIPENV_PIPFILE` naming a Pipfile outside `--cwd` finds no venv: documented CLI scope.
- Pipenv refuses different versions of one package across `[packages]` and a named category (categories are constrained by the default packages), so per-category version splits can't happen.
- `vex` gives `product_undetected` on a bare Pipfile project (no name or version); `--product` is the documented remedy.
- Pipenv 11.x / 2018.x with `virtualenv<20` can't create venvs from uv's standalone CPython (missing `libpython`): a sandbox tooling artifact, so use virtualenv 20.x. Pipenv 11.x also breaks on `(` in a project name (an unsanitized shebang): Pipenv's bug.
- A hosted requirements.txt rewrite touches only the root file; an included pin gets `redirect_requirements_entry_not_found` (documented). The Pipenv-project consequence is #567.
- Pipenv 2026.8.0 recreates a `PIPENV_PYTHON`-suffixed venv on `pipenv run` when `PIPENV_PYTHON` names a PATH symlink ("Python version differs"). That's Pipenv's quirk.
- Pipenv 2018.11.26 reads `PIPENV_VENV_IN_PROJECT` with `bool(os.environ.get(...))`, so `"0"` means in project, and Pipenv ≤ 2023.10.24 always uses an existing `.venv` directory. That's Pipenv's behaviour, and the reason #645 is a socket-patch bug.
- v5 `scan` defaults to hosted mode; agent cells need `--mode agent`.
- A hand-reformatted Pipfile.lock (2-space indent or minified) gets the hosted entry in Pipenv's 4-space style, so rollback is semantically exact but not byte-exact. Cosmetic: Pipenv re-serializes on any `pipenv lock`.
- Pipenv 11.x crashes on `PIP_NO_CACHE_DIR=1` (its vendored pip9 `_build_session` TypeError): a sandbox env artifact, so unset it.
- `repair` after a relock leaves an unwired vendored entry unwired (success, 0 events): documented as artifact-only. `get --mode vendored` re-wires it. (Only `vendor --check` staying green is a bug, #725.)
- A vendored in-run or standalone VEX attests from the committed artifact even when a warm venv still holds the upstream bytes; it only warns `vendored_tree_out_of_sync` (CLI_CONTRACT, vendored evidence row). The `pypi_pipenv_stale_install` event beside it gives the Pipenv remedy.
- Correction: in the #645 shape (`.venv` + WORKON + `PIPENV_VENV_IN_PROJECT=0`, Pipenv ≤ 2023.10), hosted vex is NOT conservative. With the WORKON venv patched it attests a false `not_affected` (the 10-03 note was wrong). That's #645.
- After a stale-install remedy has removed a package (#790 shape), `vex` attests `not_affected` from the lock wiring. The package is absent, so this isn't a false attestation of unpatched bytes.
- `pipenv install --system --deploy` over a warm interpreter that already holds the upstream release: the hosted / vendored scan gives no stale-install warning (hosted deliberately skips global interpreters, see the `stale_install_warnings` comment in `scan/hosted/python.rs`), and the next `--system --deploy` keeps the upstream bytes. Hosted vex refuses (`not_applied`); vendored vex attests with `vendored_tree_out_of_sync` (documented). A fresh Docker build is unaffected. This is a maintainer question, not filed.
- `pipenv install <other>` on Pipenv before 2024 is a full relock and drops the reference (pipenv-compatibility.md:51). vex refuses afterwards (correct).
- A symlinked `Pipfile.lock` is refused in hosted (`redirect_symlinked_file_unsupported`) and vendored (`pypi_pipenv_symlink_unsupported`) mode, and nothing is written. Fail-closed by design.
- `pipenv --site-packages` false VEX: not Pipenv-specific; tracked in #409 (pm:pip), with Pipenv evidence in a comment there. Don't re-file it.
- Mock-API notes: the blob route must return the content for the requested hash (before or after), or agent rollback fails with a hash mismatch; `get CVE-…` needs a `/patches/by-cve/` route.
- A relative `WORKON_HOME` (e.g. `.venvs`) is resolved against socket-patch's process cwd, as Python does, not against `--cwd`. So `scan --cwd app` run from the parent misses `app/.venvs/…`, while running inside `app/` passes. Not filed: the env var means whatever the reading process's cwd makes it, and Pipenv run from a subdirectory would differ too. The system-Python write that follows is #504.
