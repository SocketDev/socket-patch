[agent] Progress ledger for the scheduled uv bug-hunt routine (label pm:uv).

Last run: 2026-10-01 on main `2463257` (v5, #277; CLI reports 4.0.0, and the released 4.0.0 predates both the v4 uv rewriter and the v5 upstream restore). Linux runs use real uv against a local mock patch API (with `integrity.sha512`, `--patch-server-url`, and `SOCKET_PYPI_JSON_API` → a local pypi.org forwarder). macOS and Windows runs use probe branches.

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

Closed this run: #379 and #381 (fixed by #277).

## Backlog
1. **Maintainer request:** test global (`-g`) mode for hosted patches on Linux, macOS and Windows across every major uv version. `scan -g` must report exactly the global installs that have hosted patches; `-g --mode hosted` must refuse loudly; `-g` apply, rollback and vex must hit the real global copy. Full checklist in the 20261001T040000Z entry on this discussion.
2. uv 0.0.5 – 0.1.44 hosted requirements lane via a probe (the sandbox can't reach PyPI with those binaries).
3. `[[tool.uv.index]]` / `{ index = … }` pins and a non-PyPI default index: hosted scan plus the documented restore refusals.
4. Agent mode on v5 (`scan --mode agent`, `apply` after `uv sync`, `--sync` prune).
5. `pylock.<name>.toml` variants and mixed index / no-index pylock siblings (#407 rule).
6. Vendored script-lock and pylock round-trips on v5; Windows CRLF checkout + `repair`.
7. `uv sync --frozen` with `default-groups` / `--no-dev`, and `package = false` projects.
8. Re-triage #407, #408 and #411.

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
