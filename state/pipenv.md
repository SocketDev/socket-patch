[agent] Progress ledger for the scheduled Pipenv bug-hunt routine (label pm:pipenv).

The routine runs every 6 hours. Each run adds one comment here with the socket-patch commit it tested, the OS × Pipenv-version × mode cells it covered, the issues it filed, updated or closed, and what it plans to probe next. The routine treats this thread as its only memory.

Last run: 2026-09-30, main `f6b7fb9` (4.0.0).

## Coverage matrix

| OS | Pipenv | agent (OOT venv) | agent (stray venv/ or .venv+IN_PROJECT=0) | hosted | hosted live-lock conflict + requirements.txt | vendored | hosted ⇄ vendored |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 2018.11.26 | untested (bare) | fail #334 (venv/) | untested | fail #333 | untested | untested |
| Linux | 2022.12.19 | untested | untested | untested | fail #333 | untested | untested |
| Linux | 2023.12.1 | pass | fail #334 | untested | fail #333 | untested | untested |
| Linux | 2026.8.0 | pass | fail #334 | pass (all categories, sync, --deploy, rollback) | fail #333 | pass (lock-only vendor, repair) | fail #328 |
| macOS | 2023.12.1 | pass | fail #334 | untested | fail #333 | untested | untested |
| macOS | 2026.8.0 | pass | fail #334 | untested | fail #333 | untested | untested |
| Windows | 2023.12.1 | pass | fail #334 | untested | fail #333 | untested | untested |
| Windows | 2026.8.0 | pass | fail #334 | untested | fail #333 | untested | untested |
| any | 7–11 | untested | untested | untested | untested | refused (documented) | n/a |
| any | 0–6 | untested | n/a | refused (documented) | n/a | refused (documented) | n/a |

## Backlog

1. Pipenv 7–11 hosted `path` refs (py3.6 / Docker), and the `SOCKET_PIPENV_MAJOR` override.
2. Windows and macOS hosted and vendored on 2018 / 2022, and CRLF locks on Windows.
3. Agent mode with an unrelated `VIRTUAL_ENV` activated.
4. The `.venv` file pointer with a relative path, and `PIPENV_PIPFILE` / subdirectory runs.
5. Relock on 2022 (`install <other>`) after hosted or vendored, then rollback, re-scan and VEX.
6. Concurrent or interrupted scans on a Pipfile.lock; a BOM-prefixed Pipfile.lock.

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
