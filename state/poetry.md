[agent] Progress ledger for the scheduled Poetry bug-hunt routine (label pm:poetry).

Last updated: 2026-09-30 (run 1), main `f6b7fb9`, latest release 4.0.0 (previous 3.3.0).

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Hosted and vendored cells use a local mock of the patch API (patches-api.socket.dev is blocked from the sandbox) serving a real patched `six-1.16.0` wheel, then a real `poetry install` / `poetry sync` and a byte check of the installed file. The existing `poetry-compatibility.yml` matrix (Linux + macOS, 1.0–2.4 against production) covers the plain hosted/vendored/agent cells. This ledger tracks what that matrix does not.

| OS | Poetry | Agent (in-project `.venv`) | Agent (default out-of-tree venv) | Agent: nameless `package-mode=false` / `[project].name` override / `in-project=false` + stray `.venv` | Hosted | Vendored | Mode switch hosted ⇄ vendored | Vendored `repair` (lock-only, wheel deleted) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 1.1.15 | untested | untested | n/a | pass (dotted name, lock 1.1) | untested | untested | untested |
| Linux | 1.2.2 | untested | untested | n/a | pass (dotted name, lock 1.1) | untested | untested | untested |
| Linux | 1.8.5 | untested | pass | fail #327 | pass (LF + CRLF, CI) | pass (LF + CRLF, CI) | untested | untested |
| Linux | 2.0.1 | untested | pass | fail #327 | untested | untested | untested | untested |
| Linux | 2.3.3 | pass | pass | fail #327 | pass (groups, markers, path/url deps, supersede, dry-run, get) | pass (path/url deps) | fail #328 | fail (backlog 1) |
| Linux | 2.4.3 | untested | pass | fail #327 | pass (LF + CRLF) | pass (LF + CRLF, CI) | untested | untested |
| macOS | 1.8.5 | untested | pass | fail #327 | pass (LF + CRLF) | pass (LF + CRLF) | untested | untested |
| macOS | 2.0.1 | untested | pass | fail #327 | untested | untested | untested | untested |
| macOS | 2.4.3 | untested | pass | fail #327 | pass (LF + CRLF) | pass (LF + CRLF) | untested | untested |
| Windows | 1.8.5 | untested | fail #329 | fail #327 | pass (LF + CRLF) | pass (LF + CRLF) | untested | untested |
| Windows | 2.0.1 | untested | fail #329 | fail #327 | untested | untested | untested | untested |
| Windows | 2.4.3 | untested | fail #329 | fail #327 | pass (LF + CRLF) | pass (LF + CRLF) | untested | untested |

## Backlog

1. **Ready to file:** vendored `repair` on a lock-only Poetry checkout whose committed wheel was deleted fails `vendor_artifact_unrepairable` ("no PyPI release file for six@1.16.0 matches the lockfile's sha256 <patched hash>"). The vendor ledger's `wiring[].original` fragment still carries the pristine `sha256:8abb2f…`, and CLI_CONTRACT.md reserves that code for "no recoverable ledger fragment". Reproduced twice on Poetry 2.3.3 Linux. With an installed copy, repair rebuilds fine. Check whether uv, PDM and Pipenv share it before filing; suspect `commands/repair_vendor.rs` pristine-source ladder reading the rewired lock instead of the ledger fragment.
2. Windows: hosted / vendored on Poetry 2.x (1.8.5 passes LF + CRLF), `poetry sync`, very long project paths (> 260 chars) under `.socket/vendor/pypi/`, and agent mode with in-project `.venv` (`Lib\\site-packages`).
7. Delete stale probe branches `bughunt/poetry/20260930-venv-discovery` and `bughunt/poetry/20260930-windows-modes`: the git proxy refused `git push --delete` (HTTP 403) in run 1.
3. Agent mode on Poetry ≤ 1.7 out-of-tree venvs, and `virtualenvs.path` with `{cache-dir}` / relative paths / `~`; `POETRY_VIRTUALENVS_PREFER_ACTIVE_PYTHON`; `poetry env use` with several minors.
4. Running `socket-patch scan` from a subdirectory of a Poetry project (Poetry walks up to `pyproject.toml`; the crawler reads `cwd/pyproject.toml` only).
5. Legacy locks 1.0 / 1.1 with extras, groups (`category = "dev"`), and a marker fork refusal message; `poetry install --sync` on 1.2–1.3 warm venv after hosted.
6. VEX for hosted/vendored Poetry after `poetry update <pkg>` drops the source (documented as not attested); verify on Windows.

## Known non-bugs

- `patches-api.socket.dev` / `patch.socket.dev` / `api.socket.dev` are blocked by the sandbox proxy (403). Use a local mock API (`SOCKET_API_URL`).
- Vendored runs in the sandbox fail with `vendor_fetch_failed` for `https://pypi.org/pypi/...`: the CLI's rustls client doesn't trust the sandbox's re-terminating proxy CA. Point `SOCKET_PYPI_JSON_API` at a local HTTP forwarder that rewrites `files.pythonhosted.org`. Not a product bug.
- A `poetry.lock` with a UTF-8 BOM is rejected by Poetry itself ("Invalid statement (at line 1, column 1)"), so socket-patch's handling of it doesn't matter.
- A lock whose packages come from a custom `[[tool.poetry.source]]` (even a PyPI mirror, `priority = "primary"`) is refused by hosted (`redirect_poetry_lock_unsupported`, exit 0) and vendored (`pypi_poetry_source_already_exists`, exit 1) before any write. Documented ("a user-authored `[package.source]` on another origin").
- Agent-mode `vex` on a project with no install hook reports `ecosystem_not_setup` / `no_applicable_patches`. Documented; run `setup` or declare `setup.manual`.
- `vex` on a `package-mode = false` project with no version needs `--product` (`product_undetected`). Expected.
- Poetry 1.8 ignores PEP 621 `[project]` dependencies, so "`[project].name` + `[tool.poetry].name`" is n/a before 2.0.
- CLI_CONTRACT.md lives at `crates/socket-patch-cli/CLI_CONTRACT.md`, not the repo root.
