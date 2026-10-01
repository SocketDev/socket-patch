[agent] Progress ledger for the scheduled uv bug-hunt routine (label pm:uv).

Last run: 2026-10-01 (run 3, global mode) on main `2463257` (v5, #277; CLI reports 4.0.0, and the released 4.0.0 predates both the v4 uv rewriter and the v5 upstream restore). Linux runs use real uv against a local mock patch API (with `integrity.sha512`, `--patch-server-url`, and `SOCKET_PYPI_JSON_API` → a local pypi.org forwarder). macOS and Windows runs use probe branches.

## Coverage matrix
H = hosted, V = vendored, A = agent. "pass/fail" is Linux unless an OS is named. Results are from v5 main `2463257` unless marked (v4).

| uv | H native | H rollback / remove (upstream restore) | V native | V repair | A | Other |
| --- | --- | --- | --- | --- | --- | --- |
| 0.0.5 – 0.1.44 (requirements lane) | blocked in sandbox (TLS) | – | – | – | untested | |
| 0.1.45 / 0.2.5 / 0.2.18 / 0.2.34 (`[[distribution]]`) | pass (plain sync; 0.2.34 `--frozen`/`--locked`) | refused (documented) | refused (documented) | – | untested | |
| 0.2.37 | pass | pass after edit / `uv add` (Linux, macOS, Windows); **fail #411** user override (Linux, Windows) | pass | pass (Linux, macOS, Windows) | untested | |
| 0.4.30 | pass (v4) | untested on v5 | untested | untested | untested | |
| 0.5.31 | pass | pass after edit / `uv add` (3 OS); **fail #411** (3 OS) | pass | pass (Windows, macOS) | untested | |
| 0.8.17 | pass | **fail #407** pip-compile pylock; **fail #408** export pylock precision | untested | untested | untested | workspace refused (by design) |
| 0.12.21 | pass (`--locked`/`--frozen`/plain, inline sources, BOM, odd-case name, idempotent, VEX, pylock, script lock, CRLF, hashed requirements, markers, ranges, groups, extras, transitive override) | pass after edit / `uv add` (3 OS), script lock, hashed requirements, CRLF, multi-file; **fail #411** (3 OS); **fail #407**; **fail #408** | pass | pass (3 OS, venv + lock-only) | pass (v4: hardlink / symlink link-mode) | H→V pass (v5); V→H warn-only |


### Global (`-g`) mode
| OS | uv | scan -g default tool dir | `UV_TOOL_DIR` / `XDG_DATA_HOME` | `UV_PYTHON_INSTALL_DIR` | hosted refusal | get / rollback / vex -g |
| --- | --- | --- | --- | --- | --- | --- |
| Linux | 0.4.30 / 0.5.31 / 0.8.17 / 0.9.5 | pass | **fail #449** | **fail #449** | pass (exit 2) | blocked (e2e patch UUID `not_found`) |
| macOS | 0.4.30 / 0.5.31 / 0.8.17 / 0.9.5 | pass | **fail #449** | untested | untested | blocked |
| Windows | 0.4.30 / 0.5.31 / 0.8.17 / 0.9.5 | **fail #449** (`%APPDATA%\uv\tools`) | **fail #449** | untested | untested | blocked |

`SOCKET_GLOBAL=1`, `--global-prefix` / `SOCKET_GLOBAL_PREFIX` with space and unicode paths, and project isolation (`-g` skips `.venv`) all pass on Linux.

## Backlog
1. **Maintainer request (still open):** global `-g` apply / rollback / vex against a live free pypi patch (the e2e UUID `725a5343-…` now returns `not_found`), plus the unwritable-prefix cell. Checklist in the 20261001T040000Z entry.
2. Windows uv-managed Python root under `-g`.
3. uv 0.0.5 – 0.1.44 hosted requirements lane via a probe (the sandbox can't reach PyPI with those binaries).
4. `[[tool.uv.index]]` / `{ index = … }` pins and a non-PyPI default index: hosted scan plus the documented restore refusals.
5. Agent mode on v5 (`scan --mode agent`, `apply` after `uv sync`, `--sync` prune).
6. `pylock.<name>.toml` variants and mixed index / no-index pylock siblings (#407 rule).
7. Vendored script-lock and pylock round-trips on v5; Windows CRLF checkout + `repair`.
8. `uv sync --frozen` with `default-groups` / `--no-dev`, and `package = false` projects.
9. Re-triage #407, #408, #411 and #449 once main moves.

## Known non-bugs
- uv workspaces (`[tool.uv.workspace]` or `[manifest] members` beyond the root) are refused in both modes (`redirect_uv_project_unsupported` / `pypi_uv_workspace_unsupported`). This is by design, though it's missing from docs/testing/uv-compatibility.md.
- Scanning from inside a workspace member directory falls through to the PATH interpreter and finds nothing.
- vendored → hosted on a uv project is warn-only (`redirect_uv_project_unsupported`, exit 0). In v5, `vendored_takeover` only covers cargo/npm/golang. CLI_CONTRACT.md line ~123 says both directions "work in place on the locks the target mode accepts", so a maintainer may want to clarify that this is PyPI-wide (Poetry/PDM too).
- v5 hosted rollback refuses a uv project whose only registry package is the patched one ("no sibling registry package…"). Documented in CLI_CONTRACT "Hosted unwind coverage".
- v5 hosted rollback refuses a multi-clause direct specifier (`six>=1.10,<1.17`) unless another lock entry shows uv's clause spelling. This is in the `upstream/uv.rs` module doc, not the user docs. It's justified: uv 0.2.37 keeps clause order and ≥0.5 sorts them.
- v5 hosted rollback refuses `[[distribution]]` locks, `exclude-newer` / `no-binary` / `no-build`, and non-PyPI registries (documented).
- Hosted rollback without `--patch-server-url` for a non-Socket origin reports "Manifest not found" (the origin isn't recognised as hosted). This is a harness artifact.
- `vendor_fetch_failed` / "error sending request" for pypi.org / files.pythonhosted.org in the sandbox is a rustls vs proxy-CA artifact. Use a local forwarder via `SOCKET_PYPI_JSON_API`.
- The `redirect_pypi_stale_install` text mentions Poetry on uv projects (cosmetic, v4 observation).
- `scan -g --mode hosted` (and `--global-prefix` / `SOCKET_GLOBAL=1` with hosted) exits 2 by design. A global scan with no mode is report-only.
