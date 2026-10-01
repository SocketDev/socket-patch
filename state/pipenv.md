[agent] Progress ledger for the scheduled Pipenv bug-hunt routine (label pm:pipenv).

The routine runs every 6 hours. Each run adds one comment here with the socket-patch commit it tested, the OS × Pipenv-version × mode cells it covered, the issues it filed, updated or closed, and what it plans to probe next. The routine treats this thread as its only memory.

Last run: 2026-10-01, main `2463257` (v5 consolidation #277; CLI 4.0.0).

## Coverage matrix

Cells marked v5 were re-run on `2463257` (v5: no hosted ledger, upstream-restore rollback, service-artifact vendoring).

| OS | Pipenv | agent (OOT venv) | agent (stray venv/ or .venv+IN_PROJECT=0) | hosted (all categories, sync, --deploy, rollback) | hosted + OOT venv stale warning / VEX | hosted live-lock conflict + requirements.txt | vendored (lock-only, repair, revert) | hosted → vendored | vendored → hosted | VIRTUAL_ENV w/ IGNORE_VIRTUALENVS / PIPENV_ACTIVE |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 2018.11.26 | untested | fail #334 (venv/) | pass v5 (+CRLF) | untested | fail #333 | pass v5 | untested | untested | fail #384 |
| Linux | 2022.12.19 | untested | untested | pass v5 (+relock) | untested | fail #333 | untested | untested | untested | untested |
| Linux | 2023.12.1 | pass | fail #334 | pass v5 (+relock) | pass; fail #334/#384 shapes (false VEX) | fail #333 | untested | untested | untested | fail #384 (agent + hosted VEX) |
| Linux | 2026.8.0 | pass v5 | fail #334 v5 | pass v5 (+CRLF) | pass; fail #334/#384 shapes (false VEX) | fail #333 v5 | pass v5 | pass v5 | fail #328 v5 | fail #384 (agent + hosted VEX) |
| macOS | 2023.12.1 | pass | fail #334 | untested | untested | fail #333 | untested | untested | untested | fail #384 |
| macOS | 2026.8.0 | pass | fail #334 | untested | untested | fail #333 | untested | untested | untested | fail #384 |
| Windows | 2023.12.1 | pass | fail #334 | untested | untested | fail #333 | untested | untested | untested | fail #384 |
| Windows | 2026.8.0 | pass | fail #334 | untested | untested | fail #333 | untested | untested | untested | fail #384 |
| Linux | 2018.11.26 `-g` (`install --system`) | scan -g report pass; `-g --mode hosted` refused exit 2 pass; `-g --apply` / vex / rollback pass | | | | | | | | |
| Linux | 2026.8.0 `-g` (`install --system`) | scan -g report (in/out of project), SOCKET_GLOBAL, `--global-prefix` pass; hosted refused exit 2 pass; `-g --apply` / `get -g` / vex / rollback pass | no-`-g` agent scan in a venv-less project patches the global interpreter (needs a maintainer decision, see Known non-bugs) | | | | | | | |
| any | 7–11 | untested | untested | untested | untested | untested | refused (documented) | n/a | n/a | untested |
| any | 0–6 | untested | n/a | refused (documented) | n/a | n/a | refused (documented) | n/a | n/a | untested |

macOS/Windows rows are from the 2026-09-30 probes on `f6b7fb9`. No probe ran on v5 because branch deletion through the git proxy fails; `bughunt/pipenv/20260930-venv-discovery` and `bughunt/pipenv/20260930-virtualenv` still need a maintainer to delete them.

## Backlog

1. **Maintainer request (global `-g` mode):** Linux is covered on 2018.11.26 and 2026.8.0 (all pass, except the no-`-g` fallback noted below). Still to do: macOS and Windows (blocked: no probe this run), 2022 / 2023, and an unwritable prefix as a non-root user (the sandbox runs as root). Full checklist in the 20261001T040000Z entry.
2. Pipenv 7–11 hosted `path` refs on v5 (py3.6 / 3.7) and their rollback, plus the `SOCKET_PIPENV_MAJOR` override.
3. A macOS/Windows probe for hosted + VEX under the #334 / #384 shapes, and hosted / vendored on 2018 / 2022 there (CRLF on Windows).
4. v5 `socket.yml` policy, `--package`, `--min-severity` and `--max-new-patches` on Pipenv projects.
5. Hosted rollback refusal messages when `_meta.sources` is a mirror or an env-var URL.
6. Concurrent or interrupted scans on a Pipfile.lock.
7. `PIPENV_PIPFILE` / subdirectory runs (a documented limitation; check the refusal message).

## Known non-bugs

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
- Mock-API notes: vendoring needs `integrity.sha512` on the `tarball` artifact; the view needs `files`; agent mode needs `/patches/blob/<afterHash>`.
- **Open question for maintainers (not filed):** with no venv found and a Python project marker present, the crawler deliberately falls back to the global interpreter (`python_crawler.rs` `get_site_packages_paths`). So an agent-mode `scan` without `-g`, in a Pipenv project whose venv isn't created yet (or is `install --system`), patches the global site-packages in place. That's right for Docker `--system`, but it contradicts the `-g` checklist ("a scan without `-g` must never touch it"). Filing waits on a maintainer decision.
