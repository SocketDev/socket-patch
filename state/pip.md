[agent] Progress ledger for the scheduled pip / requirements.txt bug-hunt routine (label pm:pip).

Last run: 2026-11-28, main `cfc870f`, release v5.1.0, newest pip 26.3 (CPython 3.8–3.14 covered). Open bughunt issues: #2329 (new), #2302, #2272, #977 (needs-human). Harness: mock2.py from entry 20261029T021000Z plus a `/patches/blob/<gitsha>` route (BLOB map of before/after file contents) and an auth-checking mirror proxy (entry 20261127).

## Coverage matrix

Cells dated before 2026-11-11 count as untested for the release (see INSTRUCTIONS "Release focus"). Linux only.

| Workflow | agent | hosted | vendored |
| --- | --- | --- | --- |
| Common path: scan → install → vex → rollback/revert → reinstall | pass (26.3/py3.13, 2026-11-26) | pass (26.3/py3.12, 20.3.4/py3.8, 2026-11-26) | pass (26.3/py3.12, 20.3.4/py3.8, 2026-11-26) |
| Plain `pip install -r` after rollback / revert (#1953) | n/a | pass: reinstall advisory (2026-11-26) | pass: advisory (2026-11-26) |
| CRLF + marker + mixed-case name | pass (26.3/py3.12, 20.3.4/py3.8, 2026-11-27) | pass (20.3.4, 2026-11-26; restore normalises name) | pass (20.3.4, 2026-11-26) |
| pip-compile hashed pins, `--require-hashes` | pass (old) | pass (26.3 + mirror, 2026-11-26) | pass (24.0/25.0.1, 2026-10-29) |
| `-r` / `-c` includes | n/a | root file only (documented) | pass (2026-10-29) |
| `${VAR}` in requirement lines + pylock (#1873) | n/a | pass (refuses) | pass: fixed, six refused, not attested (2026-11-26) |
| Out-of-root `-r` include (#1851) | n/a | root-only (documented), eject refused (2026-11-27) | pass: refused, fixed (26.3, 2026-11-27) |
| `pip lock` pylock.toml / `pip install -r pylock.toml` | n/a | pass (26.3, 2026-11-26); sole-package restore refusal is known | pass (26.2.2, 2026-10-29) |
| Patch mirror (`--patch-mirror-url`, new since v5.1.0) | n/a | pass: re-pin, install, vex, rollback, dead/404 mirror skip, takeover (2026-11-26); without the setting → fail #2272 | pass: eject + `--check` with mirror (2026-11-26) |
| Editable `-e ./app`, option lines, marker-split duplicates | n/a | pass (26.2.2, 2026-11-01) | pass (2026-11-01) |
| Extras (`six[foo]`) eject / vendored (#1794) | n/a | pass | pass: refused (2026-11-01) |
| Vendored comment edited then revert | n/a | n/a | fail #977 (needs-human) |
| system-site venv / global `-g` (`--user`) | pass (26.3 system-site, 24.0 `-g`, 2026-11-27) | pass (old) | system-site: known non-bug (base copy kept, vex warns out-of-sync), CRLF + marker revert byte-identical (26.3, 2026-11-28) |
| No venv (lock-only) hosted | n/a | `redirect_unconfirmed` / #638 class (closed) | pass |
| UTF-16 / BOM / PEP 263 coding line | n/a | pass BOM / fail-closed UTF-16, latin-1 (2026-11-27) | pass BOM / fail-closed latin-1 (2026-11-27) |
| `pip freeze`-regenerated file, `--max-new-patches` | pass (2026-11-27) | pass (2026-11-27) | pass `--max-new-patches` (2026-11-27) |
| pip 26.3 `--group` from pylock with group markers | n/a | pass (2026-11-27) | pass (2026-11-27) |
| Warm venv: follow the printed reinstall advice | n/a | fail #2302 | fail #2302 |
| `pip lock -r requirements.txt` over a hosted requirements.txt (archive entries, no `version`): re-scan / rollback / list / vex | n/a | fail #2329 (26.3, 25.1; also v5.1.0) | untested |
| Mirror: fork in another repository of the mirror host (`/other/…` patch-path shape) | n/a | pass: left alone, `redirect_pin_on_unconfigured_host`; list / vex ignore it (2026-11-28) | untested |
| pip 26.3 `--uploaded-prior-to` with hosted URL pins | n/a | pass (2026-11-28) | n/a |
| macOS / Windows | blocked (probe workflows off by maintainer decision) | blocked | blocked |

## Backlog

1. #2272, #2302, #2329: re-verify once fixed (#2329: also check the vendored eject over a `pip lock -r` pylock with no `version`).
2. Mirror follow-ups: a `-r` include pinned on the patch server, then a mirror run (vendored → hosted takeover); mirror fork cell in vendored mode.
3. `pip lock -r` over a vendored requirements.txt (`file://` archive, no version) + `vex` — the 2026-10-14 revert drift-keep is known; check list / vex attribution.
4. Hosted `-g` on main; vendored `--user`.
5. #2201 / #2194 (enhancements, agent-mode RECORD / variant selection): don't re-file; check `pip check` / `pip uninstall` after an agent apply once they land.
6. Maintainer questions still open (details in history): hosted rollback restoring an unpinned root as `==X`; `vendor --revert` vs `rollback` on a one-sided `state.json` merge; residual probe reading only `*.txt` / `*.lock`.
7. Friction (not filed): with the mirror set, a pin elsewhere on the mirror host gets "which this run was not given as a patch mirror … set --patch-mirror-url" though it was; consider if users hit it.

## Known non-bugs

Full list: `known-non-bugs/pip.md` (search with `git grep`). Most likely to be re-filed:
- Hosted restore writes a pip-equivalent line: name case / `_` `.` normalised, hash continuations joined, one hash per PyPI file.
- Hosted over a warm venv stays upstream after a plain `pip install -r` until `--force-reinstall`; `redirect_pypi_stale_install` warns.
- Rollback / eject over a pylock where every package is hosted refuses ("no sibling registry package shows the registry and artifact fields").
- Hosted edits only the root requirements.txt; pins only in a `-r` include → `No requirements.txt entry`.
- Name-less source directories (`./src/six`, `-e ./src/six`) don't contest a pylock wiring.
- `-c` constraints-only pins, ranges and direct URLs are refused by vendored mode (`pypi_requirement_not_pinned`).
- After an eject, a re-run of `vendor` reports `noManifest` (exit 0).
- The agent mock needs a `/patches/blob/<sha>` route; "Before blob could not be downloaded" from a mock without it is a harness gap.
- v5 has no `setup` command / `.pth` hook; that focus area is obsolete.
- `vex` attests a pylock dependency-group package that the venv didn't install: documented verification basis (lock pin / committed artifact).
