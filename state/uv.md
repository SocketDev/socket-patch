[agent] Progress ledger for the scheduled uv bug-hunt routine (label pm:uv).

Last run: 2026-11-27 (run 48) on main `cfc870f`, release **v5.1.0**, newest uv **0.13.10**. Open `bughunt` + `pm:uv` issues: #2316. Every earlier bughunt issue is closed. The state file was compacted this run (91 KB → this). The old matrix and narrative are in the branch history (`0175cd6`), and the old Known non-bugs are in `known-non-bugs/uv.md`.

## Coverage matrix
H = hosted, V = vendored, A = agent. Linux only (macOS / Windows probes are switched off). Cells dated before 2026-11-11 count as untested for the release focus.

| Workflow | H | V | A |
| --- | --- | --- | --- |
| uv.lock project, scan → fresh `--locked` / `--frozen` sync → vex → unwind | pass 0.5.31 / 0.8.17 / 0.13.10, 2026-11-27 (rollback exit 0, `lock --check` ok, pyproject identical) | pass 0.5.31 / 0.8.17 / 0.13.10, 2026-11-27 (`vendor --check`, revert byte-identical) | pass 0.5.31 / 0.8.17 / 0.13.10, 2026-11-27 |
| PEP 723 script lock (`s.py.lock`), with a sibling | pass 0.13.10, 2026-11-27 (rollback byte-identical) | pass 0.13.10, 2026-11-27 | untested |
| `uv pip compile` `pylock.toml` + `uv pip sync`, with a sibling | pass 0.13.10, 2026-11-27 | pass 0.13.10, 2026-11-27 | untested |
| requirements.txt beside a uv.lock that doesn't hold the package (`uv pip install -r`) | **fail #2316** (rewrites, reports skipped) 0.5.31 / 0.8.17 / 0.13.10; v5.1.0 same | refused `pypi_uv_lock_package_missing` (correct; no-op remedy, known non-bug) | untested |
| `no-sources` (pyproject / uv.toml) | warn-only `redirect_uv_project_unsupported`, nothing written, 2026-11-27 | refused `pypi_uv_no_sources`, nothing written, 2026-11-27 | – |
| requirements lane (uv 0.0.5 – 0.1.44) | pass (v5.0.x, Oct) – untested on v5.1+ | pass 0.1.44 (Oct) – untested on v5.1+ | untested |
| `[[distribution]]` locks (0.1.45 – 0.2.34) | pass (Oct) – untested on v5.1+ | refused (documented) | pass 0.2.34 (Oct) |
| Workspaces / members | pass after #1138 fix (Oct) – untested on v5.1+ | same | untested |
| exclude-newer / no-binary / no-build / ancestor config refusals (#1545, #1603, #1604, #1613) | fixed and closed in Oct – untested on v5.1+ | same | – |
| `uv export` requirements / pylock beside a vendored lock (#996, #1252) | – | fixed (Oct) – untested on v5.1+ | – |
| Global `-g` (tool dirs, `UV_TOOL_DIR`, `UV_PYTHON_INSTALL_DIR`) | refused (exit 2) | – | pass Linux / macOS / Windows (v5.0, Oct) – untested on v5.1+ |
| Interrupted runs (SIGKILL), file modes, symlinks, `--cwd`, odd paths | pass (Oct) – untested on v5.1+ | same | – |

## Backlog
1. Re-triage #2316 once a fix lands. Neighbours: the same shape with `requirements-dev.txt`, a pylock beside a uv.lock that lacks the package, and the `--json` `redirect` block's `unpinned` rows.
2. Release focus: re-run on v5.1+ the cells above that are dated Oct: workspaces, the requirements lane on 0.1.44, `[[distribution]]` on 0.2.34, the #1545 / #1603 / #1604 / #1613 refusals on 0.13.10, and the export lanes #996 / #1252.
3. New since v5.1.0 and touching PyPI: the Bazel hub declines (#2208, #2212). Check that a uv project with an unrelated `MODULE.bazel` (no pip hub) isn't over-refused `vendor_pypi_bazel_hub`.
4. #2178 changed the per-run patch counts: check `rollback` / `remove` / `vendor --revert` `--json` summaries on the uv lanes (`rolledBack`, `removed`).
5. The `--patch-mirror-url` hosted mirror (#2180, experimental): does a uv.lock / pylock pin move to the mirror and restore on rollback?
6. Agent mode on the script-lock and pylock lanes (untested), and uv 0.13.10 with Python 3.15.
7. The friction note in `known-non-bugs/uv.md`: vendored `pypi_uv_lock_package_missing` says "run `uv lock` first" when pyproject doesn't declare the package at all. File it if a user-facing remedy check turns up more cases.

## Known non-bugs
Full list: `known-non-bugs/uv.md` (search with `git grep`, don't read it whole). The ones most likely to be re-filed:
- `pypi_uv_lock_revision_untested` on uv ≥ 0.12.22 locks (revision 5 > fixture-tested 3): informational.
- Hosted rollback refuses a lock whose only registry package is the patched one ("no sibling registry package…"): documented.
- Hosted rollback refuses `exclude-newer` / `no-binary` / `no-build` locks and `[[distribution]]` locks: documented.
- Hosted on a `no-sources` project is warn-only `redirect_uv_project_unsupported`, nothing written.
- Hosted never follows requirements `-r` includes (`redirect_requirements_entry_not_found`).
- Vendored `vex` attests from the committed artifact even while `.venv` is stale: documented.
- uv marker forks (one package at several versions) are refused in hosted and vendored.
- UTF-16 requirements.txt beside uv.lock → `candidate_file_unreadable`: documented.
- `vex --json` without `--output` exits 2 `json_requires_output`.
- Hosted `-g` is refused (exit 2) by design.
