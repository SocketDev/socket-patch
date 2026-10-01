[agent] Progress ledger for the scheduled pip / requirements.txt bug-hunt routine (label pm:pip).

Last run: 2026-10-01 (third run), main `2463257` (v5 consolidation, #277), latest release v4.0.0.

## Coverage matrix

| OS | pip / Python | agent | hosted | vendored | rollback / remove / takeover | system-site venv | `-r` include, lock-only | legacy egg-info install | global `-g` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 20.3.4 / py3.8, py3.10 | untested | fail #376 | fail #376 | fail #410 | fail #409 | fail #412 | fail #447 | untested |
| Linux | 23.3.2 / py3.11 | untested | fail #376 | fail #376 | fail #410 | fail #409 | fail #412 | n/a (dist-info) | untested |
| Linux | 24.0, 24.3.1 / py3.11, py3.12 | pass (.venv, venv, VIRTUAL_ENV); fail #409 (system-site) | fail #376 (single-line and fully hashed files pass; `-c` constraints pass) | fail #376 (include with venv passes) | fail #410 (multi-line and hashed files restore byte-exact) | fail #409 | fail #412 | n/a (dist-info) | report pass, hosted refusal pass, `--global-prefix` get / rollback / vex pass, unwritable pass; egg-info globals fail #447 |
| Linux | 25.0.1 / py3.8; 26.2.1 / py3.13 | untested | fail #376 | fail #376 | fail #410 | fail #409 | fail #412 | n/a (dist-info) | untested |
| macOS | 20.3.4 / 25.0.1 / 26.2.1, py3.8 + py3.13 | untested | fail #376 | fail #376 | fail #410 | fail #409 | fail #412 | fail #447 (20.3.4 / 22.3.1 / 23.0.1; 23.1 passes) | `--global-prefix` report fail #447 for egg-info; rest untested |
| Windows | 20.3.4 / 25.0.1 / 26.2.1, py3.8 + py3.13 | untested | fail #376 | fail #376 | fail #410 | fail #409 | fail #412 | fail #447 (20.3.4 / 22.3.1 / 23.0.1; 23.1 passes) | `--global-prefix` report fail #447 for egg-info; rest untested |

pip 20.3.4 on py3.13 is blocked (no `distutils`). `setup` was removed in v5, so the old setup column (#377, #378) is retired; both issues are closed.

pip 22.3.1 / 23.0.1 / 23.1 were also covered on all three OS (py3.8 / 3.11) for the egg-info cells.

Commands covered on Linux: scan (all modes), rollback, remove, vendored takeover, vex, setup (v4 only). Not yet covered: repair, list, get, `--json` failure envelopes, concurrent runs.

## Backlog

1. **Maintainer request (partly done):** global (`-g`) mode on Linux, macOS and Windows. Done on Linux: report, hosted refusal, `--global-prefix` + `SOCKET_GLOBAL_PREFIX` round trip with a space / unicode path, vex, unwritable dir. Left: `--user` on macOS / Windows, python.org / Homebrew / py-launcher interpreters, non-root unwritable prefixes on CI. Full checklist in the 20261001T040000Z entry. Open question for the maintainer: the non-`-g` no-venv fallback to global site-packages (see the latest entry).
2. Agent mode on Windows (`Scripts/` + `Lib/`), `--user`, and virtualenv (not venv) layouts under v5.
3. Legacy `pip install -e .` (`.egg-link`) next to a patched pin; re-verify #447 when fixed.
4. VCS / URL / `--no-binary` sdist-only installs after a hosted rewrite; `uv pip install -r` on a pip-hosted file.
5. `repair` and `list` for vendored requirements; `--json` envelopes for rollback / remove failures.
6. The same name pinned twice under different markers: hosted rewrite + upstream restore.
7. Re-verify #376 / #409 / #410 / #412 / #447 as fixes land (#383 needs a rebase onto v5).

## Known non-bugs

- Hosted mode rewrites only the root `requirements.txt`; an installed pin reached only through `-r` gets `redirect_requirements_entry_not_found` (vendored follows includes). The lock-only discovery gap is #412.
- A warm plain venv keeps the upstream same-version install after a hosted rewrite; this is warned (`redirect_pypi_stale_install`) and `vex` omits it. The system-site-venv variant is #409.
- Vendored `vex` attests from the committed artifact even when a plain venv still holds upstream bytes; it warns `vendored_tree_out_of_sync` (documented).
- The v5 upstream restore of a hosted line lowercases the name (`Six` → `six`) and normalises spacing before a trailing comment; pip reads both forms the same way.
- `rollback` in agent mode drops the manifest entry, so a later `apply` is a no-op (documented).
- A venv directory not named `.venv` / `venv` is only found through `VIRTUAL_ENV`.
- `SOCKET_API_TOKEN` format warnings and the `uv pip` HEAD 501 are artifacts of the local mock. `vex -o` is `--org`, not `--output`.
- `scan --mode agent` after a failed `get` (unwritable target) skips the recorded entry ("already recorded … run `socket-patch apply`") and exits 0. This is documented, and the failed `get` itself exits 1.
- Hosted `vex` ignores non-`patch.socket.dev` URLs, so mock-hosted projects can't be attested locally (mock artifact).
