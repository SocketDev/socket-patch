[agent] Progress ledger for the scheduled pip / requirements.txt bug-hunt routine (label pm:pip).

Last run: 2026-09-30, main `f6b7fb9`, release v4.0.0.

## Coverage matrix

| OS | pip / Python | agent | hosted | vendored | setup (.pth) |
| --- | --- | --- | --- | --- | --- |
| Linux | 20.3.4 / py3.8, py3.10 | untested | fail #376 | fail #376 | fail #377, #378 |
| Linux | 23.3.2 / py3.8, py3.13 | untested | fail #376 | fail #376 | fail #377, #378 |
| Linux | 24.0 / py3.11 | pass (.venv, venv, VIRTUAL_ENV) | fail #376 (single-line and fully hashed files pass) | fail #376 | fail #377, #378 |
| Linux | 26.2.1 / py3.11, py3.13 | untested | fail #376 | fail #376 | fail #377, #378 |
| macOS | 20.3.4 / 23.3.2 / bundled, py3.8 + py3.13 | untested | fail #376 | fail #376 | fail #377, #378 |
| Windows | 20.3.4 / 23.3.2 / bundled, py3.8 + py3.13 | untested | fail #376 | fail #376 | fail #377, #378 |

Commands covered on Linux: scan (all modes), rollback (hosted byte-exact; agent), apply, remove, setup, setup --remove, vex. Not yet covered: repair, get, `--json` contract details, concurrent runs.

## Backlog

1. `-c` constraints and nested `-r` includes in subdirectories (vendored wheel path resolved against the CWD).
2. `-e .`, VCS/URL lines, index-option lines and sdist-only (`--no-binary`) installs after a hosted rewrite.
3. Agent mode on Windows (`Scripts/` + `Lib/`), `--system-site-packages`, `--user`, and virtualenv layouts; the .pth hook once #377 is fixed.
4. Dotted and underscored names (`zope.interface`, `ruamel.yaml`) in discovery and the rewriter.
5. VEX after `--force-reinstall` and in the #376 state; `repair` for vendored requirements.
6. Lock-only discovery ignoring `name == ver` (spaces) and `===` while the rewriter accepts them (deliberate per the `exact_pin` tests; decide whether a silent miss deserves a warning).

## Known non-bugs

- Hosted mode reads only the root `requirements.txt`; a pin reached only through `-r` gets `redirect_requirements_entry_not_found` rather than a rewrite (vendored follows includes).
- A warm venv keeps the upstream same-version install after a hosted rewrite; this is warned (`redirect_pypi_stale_install`) and `vex` omits it (`not_applied`).
- `rollback` in agent mode drops the manifest entry, so a later `apply` is a no-op (documented).
- A venv directory not named `.venv` / `venv` is only found through `VIRTUAL_ENV`.
- `SOCKET_API_TOKEN` format warnings and the `uv pip` HEAD 501 are artifacts of the local mock.
