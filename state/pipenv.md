[agent] Progress ledger for the scheduled Pipenv bug-hunt routine (label pm:pipenv).

Last run: 2026-11-26 ~19:30Z, main `cfc870f` (release v5.1.0; release focus is on), newest Pipenv 2026.12.1 (2026.10.0–2026.12.1 are new since the previous run on 2026-10-17). Linux only. Compacted from 60 KB this run: the old matrix and per-run narrative are in the branch history (state/pipenv.md before 2026-11-26), and the non-bugs moved to `known-non-bugs/pipenv.md`.

## Coverage matrix

One row per workflow, one column per mode. "pass `cfc870f`" means re-run this release cycle (on or after 2026-11-11); a pass with an older SHA only counts as untested for the release (see INSTRUCTIONS.md "Release focus").

| Workflow | agent | hosted | vendored |
| --- | --- | --- | --- |
| Common path: scan, lock-only `sync` + fresh `install --deploy`, stale warning + remedy, vex, rollback byte-exact | pass 2026.12.1 `cfc870f` (2018–2026.9 pass `045d7ec`–`657fce2`) | pass 2022.12.19 / 2023.12.1 / 2026.12.1 `cfc870f` | pass 2022.12.19 / 2023.12.1 / 2026.12.1 `cfc870f` |
| Pipenv 2018.11.26 / 2020 / 2021 / 2024 / 2025 / 11.x common path | pass `045d7ec`–`61cfb9b`; untested this release | pass (11 `path` form, 2018 py3.8) `2e0d17f`; untested this release | pass `2e0d17f` (7–11 refused, documented); untested this release |
| Patch mirror (`--patch-mirror-url`, experimental) | n/a | pass 2026.12.1 `cfc870f`: fresh pin, lock-only `--deploy` PATCHED, idempotent rescan, `redirect_pin_on_unconfigured_host` without the mirror, patch.socket.dev pin moved onto the mirror, rollback byte-exact; no-mirror list/remove/rollback silence is #2272 (commented) | takeover of a mirrored pin with the mirror: pass 2026.12.1 `cfc870f` (revert byte-exact); without it: "user-declared file reference" (#2272 comment) |
| Relock (`pipenv install <other>` keeps the pin, `pipenv lock` drops it, documented) | n/a | pass 2026.12.1 `cfc870f` | pass 2026.12.1 `cfc870f` |
| `use_pylock` (Pipfile.lock + pylock.toml) | n/a | pass 2026.12.1 `cfc870f` (both rewritten, sync PATCHED, rollback TOML-equivalent) | pass 2026.12.1 `cfc870f` |
| Stray `MODULE.bazel` at the repo root (Bazel lookup, new since v5.1.0) | untested | pass 2026.12.1 `cfc870f` | pass 2026.12.1 `cfc870f` (not declined) |
| Named categories (`develop`, `[docs]`, `[tests]`), split versions (#1616) | n/a | pass 2022–2026.9 `657fce2`; untested this release | pass 2022–2026.9 `657fce2`; untested this release |
| Out-of-tree venv discovery (WORKON_HOME, IN_PROJECT, `.env`, `.venv` pointer, VIRTUAL_ENV) | pass 2018–2026.8 `9c43dfc`–`b96a785`; untested this release; #842 (closed) | stale warning pass `9c43dfc`; untested this release | n/a |
| requirements.txt sibling / `pipenv requirements` export | n/a | pass `657fce2`; `--hash` hosted pass | #981 (`--hash` on 2023.7.9+) closed; pass `657fce2` |
| `--prune` GC, interrupted runs (SIGKILL), concurrent scans | n/a | pass `e76cb9b` | pass `7d3086f` |
| `-g` / `install --system` | pass 2018 / 2022 / 2023 / 2026.8 `61cfb9b` | refused exit 2 (documented) | n/a |
| macOS / Windows | probes disabled by maintainers (Linux only) | | |

## Backlog

1. Pipenv 2026.10–2026.12 on the remaining common-path shapes: named categories (`develop` / `[docs]` / `[tests]`, #1616 split versions), `pylock_name`, `resolver_backend = "pure-python"`, out-of-tree venv discovery (WORKON_HOME, `PIPENV_VENV_IN_PROJECT`, `.env`). Check Pipenv's 2026.10–2026.12 changelog for lock-format or venv-location changes first.
2. Release re-run of the oldest supported Pipenvs: 2018.11.26 (py3.8) and 11.10.4 (`path` form) hosted + vendored common path on `cfc870f` or later.
3. Patch mirror edge cases: a user's own source on the mirror's host outside the base in the patch-server path shape (must be a conflict, not rotated), a mirror base with a trailing slash or a path prefix, a `pipenv requirements` export beside a mirrored lock, netrc credentials with Pipenv 2023 / 2026.
4. `vendor_pypi_bazel_hub`: a Bazel `pip.parse` hub that reads `requirements_lock` exported from Pipfile.lock (must decline vendored), and `SOCKET_NO_BAZEL` with the same shape.
5. #2272: re-verify for Pipfile.lock once fixed (list / remove / rollback / vex / vendored without the mirror setting should name the mirror host).
6. #1572, #1608 and #1616 are closed (no open `pm:pipenv` bughunt issues on 2026-11-26): re-verify their fixes on Pipenv 2026.12.1 (ignore rules / LFS, drift warnings, split-version categories).
7. #1050 GC on the #1122 pylock-wired shape; the #1142 named-category-with-packages-left variant.
8. Agent mode with a stray `MODULE.bazel`; `report` command (new since v5.1.0) on a Pipenv project.

## Known non-bugs

Full list: `known-non-bugs/pipenv.md` (search it with `git grep`). The ones most likely to be re-filed:
- A warm venv is never reinstalled by `pipenv install` / `sync` / `--deploy`; the stale-install warning and its remedy are the design.
- `pipenv lock` / `update` (and `install <other>` before Pipenv 2024) drop the reference; a re-scan restores it.
- Pipenv 2023+ don't hash-check local wheels: vendored carries `vendor_integrity_unverified`.
- Vendored vex attests from the committed artifact even when a warm venv holds upstream bytes (`vendored_tree_out_of_sync` warning).
- Hosted vex with a stale venv exits 1 "No applied patches…" until the remedy runs.
- Hosted rollback is an upstream restore: pylock.toml comes back TOML-equivalent, not byte-exact (`{ name = … }` spacing, real URLs, sdist line).
- Pipfile.lock `pipfile-spec` < 6 and vendored on Pipenv 7–11 are refused (documented).
- Under a patch mirror, a pin on a custom `--patch-server-url` origin isn't moved (`redirect_mirror_pin_not_moved`); a patch.socket.dev pin is.
- `uv pip install -r pylock.toml` of a Pipenv pylock installs nothing even before socket-patch runs (Pipenv/uv interplay).
- Mock-API notes: vendoring needs `integrity.sha512`; batch must filter by purl; the mock is rebuilt each run (python http.server with batch / by-package / view with base64 `blobContent` / package grant / serve, plus a second instance with `MOCK_PREFIX` as the mirror).
