[agent] Progress ledger for the scheduled Pipenv bug-hunt routine (label pm:pipenv).

The routine runs every 6 hours. Each run adds one comment here with the socket-patch commit it tested, the OS × Pipenv-version × mode cells it covered, the issues it filed, updated or closed, and what it plans to probe next. The routine treats this thread as its only memory.

Last run: 2026-09-30 (second run), main `f6b7fb9` (4.0.0).

## Coverage matrix

| OS | Pipenv | agent (OOT venv) | agent (stray venv/ or .venv+IN_PROJECT=0) | hosted | hosted live-lock conflict + requirements.txt | vendored | hosted ⇄ vendored | agent + VIRTUAL_ENV w/ IGNORE_VIRTUALENVS / PIPENV_ACTIVE |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 2018.11.26 | untested (bare) | fail #334 (venv/) | untested | fail #333 | untested | untested | fail #384 |
| Linux | 2022.12.19 | untested | untested | untested | fail #333 | untested | untested | untested |
| Linux | 2023.12.1 | pass | fail #334 | untested | fail #333 | untested | untested | fail #384 |
| Linux | 2026.8.0 | pass | fail #334 (also auto-`.venv` + existing WORKON_HOME venv, and Pipfile `venv_in_project=false`, on 2026.2+) | pass (all categories, sync, --deploy, rollback) | fail #333 | pass (lock-only vendor, repair) | fail #328 | fail #384 |
| macOS | 2023.12.1 | pass | fail #334 | untested | fail #333 | untested | untested | fail #384 |
| macOS | 2026.8.0 | pass | fail #334 | untested | fail #333 | untested | untested | fail #384 |
| Windows | 2023.12.1 | pass | fail #334 | untested | fail #333 | untested | untested | fail #384 |
| Windows | 2026.8.0 | pass | fail #334 | untested | fail #333 | untested | untested | fail #384 |
| any | 7–11 | untested | untested | untested | untested | refused (documented) | n/a | untested |
| any | 0–6 | untested | n/a | refused (documented) | n/a | refused (documented) | n/a | untested |

## Backlog

1. Pipenv 7–11 hosted `path` refs (py3.6 / Docker, or py3.7 via uv), and the `SOCKET_PIPENV_MAJOR` override.
2. Windows and macOS hosted and vendored on 2018 / 2022, and CRLF locks on Windows.
3. Relock on 2022 (`install <other>`) after hosted or vendored, then rollback, re-scan and VEX.
4. Hosted stale-install warning under the #384 / #334 conditions and a 2026.2+ auto-`.venv`.
5. Concurrent or interrupted scans on a Pipfile.lock.
6. `PIPENV_PIPFILE` / subdirectory runs (a documented limitation; check the refusal message).

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
