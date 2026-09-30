[agent] Progress ledger for the scheduled uv bug-hunt routine (label pm:uv).

Last run: 2026-09-30 on main `f6b7fb9` (CLI 4.0.0; the released 4.0.0 predates the current uv backend). Linux runs use real uv against a local mock patch API. macOS and Windows runs use probe branches.

## Coverage matrix
H = hosted, V = vendored, A = agent. "pass/fail" is Linux unless an OS is named.

| uv | H native | H rollback after edit / `uv add` | V native | V repair (patched venv) | V repair (lock-only) | A | Other |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0.2.37 | untested | untested | untested | pass Linux/macOS, **fail Windows #381** | pass Linux/macOS, fail Windows (see #381) | untested | |
| 0.4.30 | pass | **fail #379** | untested | untested | untested | untested | |
| 0.5.31 | pass | **fail #379** (Linux/macOS/Windows) | untested | untested | untested | untested | |
| 0.8.17 | pass | **fail #379** | untested | untested | untested | untested | workspace refused (by design) |
| 0.12.21 | pass (--locked/--frozen/plain, inline sources, BOM, odd-case name, idempotent, VEX, pylock.dev.toml, script lock) | **fail #379** (Linux/macOS/Windows; script lock too) | pass (install, rollback after `uv add`) | **fail #381** (Linux/macOS/Windows) | pass (Linux/macOS/Windows) | pass (hardlink / symlink link-mode) | H→V fail #328; V→H warn-only |
| 0.0.5 – 0.1.44 (requirements lane) | untested | – | untested | – | – | untested | |
| 0.1.45 – 0.2.34 (`[[distribution]]`) | untested | untested | refused (documented) | – | – | untested | |

## Backlog
1. Windows + uv 0.2.37 lock-only repair mismatch: is the vendor-time wheel built from the installed dist?
2. `[[distribution]]` hosted locks (0.1.45 / 0.2.5 / 0.2.18 / 0.2.34): relock, rollback, `--locked`.
3. Non-default / explicit `[[tool.uv.index]]` and `{ index = … }` pins, including transitive overrides.
4. Hosted hashed requirements (`uv pip compile --generate-hashes`) + `--require-hashes`, upgrade, rollback; requirements floor 0.0.5.
5. CRLF uv.lock + `uv add` on Windows; `resolution-markers` forks (refusal vs VEX).
6. `uv sync --frozen` with `default-groups` / `--no-dev`, and `package = false` projects.
7. Re-triage #379 and #381.

## Known non-bugs
- uv workspaces (`[tool.uv.workspace]` or `[manifest] members` beyond the root) are refused in both modes: `redirect_uv_project_unsupported` ("hosted sources for uv workspaces require a package-scoped source mapping") and `pypi_uv_workspace_unsupported`. This is by design, though it's missing from docs/testing/uv-compatibility.md.
- Scanning from inside a workspace member directory falls through to the PATH interpreter and finds nothing (documented fall-through).
- vendored → hosted on a uv project is warn-only (`redirect_uv_project_unsupported`, exit 0).
- A failed `repair` removes the package's `socket-patch.vendor.json` sidecar ("nothing kept" contract). `vendor --revert` still works from state.json.
- Hosted rollback needs `.socket/vendor/redirect-state.json`; without it the result is `Manifest not found`.
- `vendor_fetch_failed` against files.pythonhosted.org in the sandbox is a rustls vs proxy-CA artifact.
- The `redirect_pypi_stale_install` text mentions Poetry on uv projects (cosmetic).
