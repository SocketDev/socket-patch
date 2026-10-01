[agent] Progress ledger for the scheduled pip / requirements.txt bug-hunt routine (label pm:pip).

Last run: 2026-10-01 (fourth run), main `6e7ef74`, latest release v4.0.0 (`96df6ae`).

## Coverage matrix

| OS | pip / Python | agent | hosted | vendored | rollback / remove / takeover | system-site venv | `-r` include, lock-only | legacy egg-info install | PEP 440-equivalent pin (`==1.16`) | global `-g` (`--user`) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 20.3.4 / py3.8, py3.10 | untested | fail #376 | fail #376 | fail #410 | fail #409 | fail #412 | fail #447 | fail #475 | untested |
| Linux | 23.x / py3.8, py3.11 | untested | fail #376 | fail #376 | fail #410 | fail #409 | fail #412 | n/a (dist-info) | fail #475 | untested |
| Linux | 24.0, 24.3.1 / py3.11, py3.12 | pass (.venv, venv, VIRTUAL_ENV); fail #409 (system-site) | fail #376 (single-line, fully hashed, `-c`, `--no-binary`, marker continuations and duplicate-marker pins pass) | fail #376 (include, duplicate markers, `repair`, `list` pass) | fail #410 (multi-line, hashed, duplicate-marker files restore byte-exact) | fail #409 | fail #412 | n/a (dist-info) | fail #475 | pass (report, hosted refusal, get / rollback / vex, `--global-prefix`, unwritable); egg-info globals fail #447 |
| Linux | 25.0.1 / py3.8; 26.2.1 / py3.13 | untested | fail #376 | fail #376 | fail #410 | fail #409 | fail #412 | n/a (dist-info) | fail #475 | untested |
| macOS | 20.3.4 – 26.2.1, py3.8 + py3.13 | untested | fail #376 | fail #376 | fail #410 | fail #409 | fail #412 | fail #447 (≤ 23.0.1) | fail #475 | pass (`--user`, py3.8 / pip 20.3.4 and py3.13); `--global-prefix` egg-info fail #447 |
| Windows | 20.3.4 – 26.2.1, py3.8 + py3.13 | untested | fail #376 | fail #376 | fail #410 | fail #409 | fail #412 | fail #447 (≤ 23.0.1) | fail #475 | pass (`--user`, `%APPDATA%\Python`, py3.8 / pip 20.3.4 and py3.13 / 26.2.1); `--global-prefix` egg-info fail #447 |

pip 20.3.4 on py3.13 is blocked (no `distutils`). `setup` was removed in v5, so the old setup column (#377, #378) is retired; both issues are closed.

Commands covered on Linux: scan (all modes), get (hosted, agent `-g`), rollback, remove, vendored takeover, vex (hosted with the mock origin, vendored, `-g`), repair, list, concurrent runs. Not yet covered: `--json` envelopes of rollback / remove failures, interrupted runs.

## Backlog

1. **Maintainer request (mostly done):** global (`-g`) mode. Done: Linux (all items), plus macOS and Windows `--user` (report, hosted refusal, get, byte-exact rollback). Left: Homebrew / PEP 668 interpreters, py launcher with several interpreters, pipx venvs, non-root unwritable prefixes on CI. Open question for the maintainer: the non-`-g` no-venv fallback to global site-packages (see the 20261001T083942Z entry).
2. Lock-only discovery of `==X.Y` short pins (purl `six@1.16`) once #475 is fixed; needs a mock that mirrors the real API's version matching.
3. Agent mode on Windows (`Scripts/` + `Lib/`) and virtualenv (not venv) layouts under v5.
4. Legacy `pip install -e .` (`.egg-link`) next to a patched pin.
5. VCS / URL lines after a hosted rewrite; `uv pip install -r` on a pip-hosted file.
6. `--json` envelopes for rollback / remove failures; interrupted runs.
7. Re-verify #376 / #409 / #410 / #412 / #447 / #475 as fixes land (#383 needs a rebase onto v5).

## Known non-bugs

- Hosted mode rewrites only the root `requirements.txt`; an installed pin reached only through `-r` gets `redirect_requirements_entry_not_found` (vendored follows includes). The lock-only discovery gap is #412.
- A warm plain venv keeps the upstream same-version install after a hosted rewrite; this is warned (`redirect_pypi_stale_install`) and `vex` omits it. The system-site-venv variant is #409.
- Vendored `vex` attests from the committed artifact even when a plain venv still holds upstream bytes; it warns `vendored_tree_out_of_sync` (documented).
- The v5 upstream restore of a hosted line lowercases the name (`Six` → `six`) and normalises spacing before a trailing comment; pip reads both forms the same way.
- Hosted rollback refuses a file that mixes hashed and unhashed requirements ("not derivable"); pip can't install such a file anyway.
- Vendored refuses `===` pins, `==X.*` wildcards and a tab before `--hash` (`pypi_requirement_not_pinned`). This is fail-closed and isn't filed (the `==1.16` zero-padding case is part of #475).
- `--vendor-source build` was removed in v5; vendoring always needs a patch-service artifact.
- `rollback` in agent mode drops the manifest entry, so a later `apply` is a no-op (documented).
- A venv directory not named `.venv` / `venv` is only found through `VIRTUAL_ENV`.
- `SOCKET_API_TOKEN` format warnings and the `uv pip` HEAD 501 are mock artifacts. `vex -o` is `--org`, not `--output`. `vex --json` requires `--output`.
- `scan --mode agent` after a failed `get` (unwritable target) skips the recorded entry ("already recorded … run `socket-patch apply`") and exits 0. This is documented, and the failed `get` itself exits 1.
- Hosted `vex` ignores hosted URLs that aren't on `patch.socket.dev`. Pass `--patch-server-url <mock origin>` to attest mock-hosted projects locally.
- A concurrent second run in the same project exits 1 with "Another socket-patch process is operating in this directory" (by design).
