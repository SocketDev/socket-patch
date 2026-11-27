[agent] Progress ledger for the scheduled Poetry bug-hunt routine (label pm:poetry).

Last run: 2026-11-27 (run 29), main `cfc870f`, latest release v5.1.0 (2026-11-11), newest Poetry 2.5.2 (2026-11-21).

Compacted in run 29 from a 54 KB file. The per-run cell tables for runs 1–28 and the old known-non-bug list are in this file's git history on `bughunt/ledger` (commit `9326906`) and in `entries/poetry/`. Open bughunt issues: #2320. Closed since run 28: #450, #1105, #1184, #1589, #1615, #1635 (all fixed). #1114 (arch-audit, not bughunt) is still open, though #2229 says it fixes it.

## Coverage matrix

Linux only (macOS / Windows probes are switched off; see INSTRUCTIONS.md). The mock is a local patch API that serves a deterministic patched copy of the real six 1.16.0 wheel (grant with sha256 + sha512, view, blob). Real Poetry, real PyPI (now reachable directly). A cell dated before 2026-11-11 counts as untested for the release.

| Workflow | Agent | Hosted | Vendored |
| --- | --- | --- | --- |
| Common path: scan, re-scan, fresh install, import check, `vex`, rollback, reinstall | pass 2.5.2 in-project + default out-of-tree env (2026-11-27) | pass 1.1.15, 1.3.2, 1.8.5, 2.5.2 (2026-11-27), CRLF 2.5.2; rollback advice wrong on 1.1–1.3: fail #2320 | pass 1.1.15, 1.8.5, 2.5.2 incl. `vendor --check` (2026-11-27); revert advice wrong on 1.1–1.3: fail #2320 |
| Mode switch hosted → vendored → hosted, fresh install after each, rollback | n/a | pass 2.5.2 (2026-11-27) | pass 2.5.2 (2026-11-27) |
| Lock formats 1.0 / 1.1 / 2.0 / 2.1, CRLF / mixed EOL, hand-edited units | untested since v5.1.0 | 1.1 / 2.0 / 2.1 pass (2026-11-27); 1.0 and mixed EOL pass pre-release (r13–r26) | 1.1 / 2.1 pass (2026-11-27); 1.0 pass pre-release |
| Groups, extras, markers, `install --sync` / `sync`, `--without` | pass pre-release (r19, 2.5.1) | pass pre-release (2.5.1) | pass pre-release (2.5.1) |
| Sources with priority (primary / secondary / supplemental / explicit / default), `source = "pypi"` pins | n/a | pass pre-release (r18, r28) | pass pre-release (r18, r28) |
| Path / URL / git deps of the patched package | n/a | refused before writing (documented, r12) | refused before writing (documented) |
| Venv discovery: in-project, default path, `virtualenvs.path` templates, `envs.toml`, `env use`, `VIRTUAL_ENV` / conda | pass pre-release (r9–r13, r27) | VEX stale check pass pre-release (r27) | n/a |
| `virtualenvs.create = false` / system-site-packages | pass pre-release (#671, #1023, #409 fixed); dpkg-copy lead open | pass pre-release | pass pre-release |
| Relock after patch (`poetry lock`, `add --lock`, cross-major relock) | n/a | pass pre-release (r27) | pass pre-release (#1615 fixed, not re-run) |
| Supersede A → B, `remove` of one of two packages | pass pre-release | pass pre-release (r16) | pass pre-release (#1136 fixed) |
| Global mode `-g` / cross-scope rollback | pass pre-release; #450 fixed, not re-run | n/a | n/a |
| Ownership / mode of rewritten `poetry.lock` (root run on uid-1000 tree) | pass pre-release | #1635 fixed, not re-run | #1635 fixed, not re-run |
| Poetry 0.12 (must be refused for hosted) | untested | refused pre-release (`redirect_poetry_lock_unsupported`) | pass pre-release; #945 fixed |

## Backlog

1. Re-check #2320 once fixed (1.1.15 and 1.3.2, hosted `rollback`, vendored `rollback` and `vendor --revert`, then plain `poetry install`).
2. Re-run the pre-release cells on main after v5.1.0: groups / extras / `sync --without`, sources with priority, `source = "pypi"`, cross-major relock (#1615), root-run ownership (#1635), cross-scope rollback (#450). Start with Poetry 2.5.2 and 1.8.5.
3. Lock 1.0 (Poetry 1.0.10) hosted and vendored on main, plus Poetry 0.12 refusal.
4. #2170 (no-venv Python projects scan only declared packages) for Poetry: a PEP 621-only Poetry 2 project with no `poetry.lock` and `create = false`. The sandbox's system Python already has an apt `six` in `/usr/lib/python3/dist-packages`, so use a controlled interpreter on PATH.
5. Lead (r29), not filed: since #2243, a PyPI patch's VEX product keeps `?artifact_id=…` (by design, from the review). If Grype / Trivy compare qualifiers, the document suppresses nothing for PyPI findings. Needs a real scanner run, and downloading Grype / Trivy was denied in this sandbox.
6. #1635 follow-up: a root vendored run leaves a root-owned `.socket/vendor` tree; check the owner's later `vendor --revert` / `rollback`.
7. Lead (r24): Poetry 2 `[tool.poetry.requires-plugins]` installs plugins into `<project>/.poetry/plugins`, which no mode crawls. Needs a maintainer call on scope.
8. Lead (r14): with `virtualenvs.create = false`, the project fallback patches the system interpreter's dpkg-owned copy. Needs a maintainer call.
9. Docs: `installer.modern-installation = false` (1.4–1.8) keeps a warm same-version install, though the "Installer boundaries" table says 1.4–1.8 replace it.

## Known non-bugs

The full list is in `known-non-bugs/poetry.md`; search it with `git grep`. These are the ones most likely to be re-filed:

- patches-api / api.socket.dev are blocked from the sandbox. Use a local mock with `--api-url` and set `SOCKET_PATCH_SERVER_URL` to the mock so `list`, `vex` and rollback see the hosted origin.
- On Poetry 1.1–1.3, a warm venv keeps upstream bytes after a hosted rewrite, even when Poetry prints "Updating six". Documented, and flagged `redirect_poetry_stale_install_risk`.
- On Poetry < 1.4, vendored warns `pypi_poetry_integrity_unverified` and hosted warns `redirect_poetry_stale_install_risk`. Both are deliberate.
- A user-authored `[package.source]` (mirror default source, git, path, URL) is refused before writing by hosted and vendored. Documented.
- Forked locks (one package at two versions by marker) are refused. Documented.
- pypi is cwd-only: running from a subdirectory doesn't find the project. Use `--cwd`.
- Hosted rollback re-renders a hand-edited unit in Poetry's canonical layout. There's no byte-layout guarantee.
- A mock that rebuilds its wheel on each request breaks `poetry install` hash checks. Build it deterministically.
- `poetry check --lock` fails on Poetry 1.1 / 1.2 on its own.
- Poetry 1.0 + pip 22.3 / 23.0 refuse the hosted wheel's `#sha256=…&` fragment. Documented.
