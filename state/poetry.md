[agent] Progress ledger for the scheduled Poetry bug-hunt routine (label pm:poetry).

Last updated: 2026-10-02 (run 8), main `61cfb9b` (includes #330, #446, #452, #456), latest release 4.0.0 (previous 3.3.0).

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Hosted and vendored cells use a local mock of the patch API (patches-api.socket.dev is blocked from the sandbox) serving a patched `six-1.16.0` wheel, then a real `poetry install` / `poetry sync` and a byte check of the installed file. The existing `poetry-compatibility.yml` matrix (Linux + macOS) covers the plain cells against production. Rows before run 3 were measured on main `f6b7fb9` (pre-v5). Run 3 re-measured the cells marked "v5". Run 5 re-measured the cells marked "r5" on `6e7ef74` (after #330); #327 cells on macOS / Windows still show the pre-fix result because probe branches are blocked.

| OS | Poetry | Agent (in-project `.venv`) | Agent (default out-of-tree venv) | Agent: nameless `package-mode=false` / `[project].name` override / `in-project=false` + stray `.venv` | Agent + hosted VEX: `in-project=true`, no `.venv`, existing out-of-tree env | Hosted (scan, install, rollback) | Hosted VEX with undiscovered venv | Vendored | Mode switch hosted ⇄ vendored | Vendored `repair` (lock-only, wheel deleted) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 0.12.17 | untested | untested | n/a | untested | pass v5 (refused, `redirect_poetry_lock_unsupported`) | n/a | pass v5 (`[metadata.hashes]`) | n/a | untested |
| Linux | 1.0.10 | untested | pass r8 (scan, re-run, vex, rollback) | n/a | untested | pass v5 (lock 1.0 native-empty + populated; pip ≥ 23.1) | untested | pass v5 (populated lock 1.0) | untested | untested |
| Linux | 1.1.15 | pass v5 | pass r8 (scan, re-run, vex, rollback) | n/a | fail #476 | pass v5 (lock 1.1, extras + dev); r5 dotted name `jaraco.context` rewrite/install/vex/rollback | untested | pass v5 (LF + CRLF, unicode/space path) | untested | untested |
| Linux | 1.2.2 | untested | untested | n/a | untested | pass v5 (lock 1.1, extras + dev, warm-venv stale check) | untested | pass (lock 1.1) | untested | untested |
| Linux | 1.8.5 | untested | pass | pass r5 (fixed by #330; nameless, in-project=false, unicode path) | fail #476 | pass v5 (LF + CRLF) | pass r5 (#330) | pass v5 (LF + CRLF, unicode/space path) | untested | pass v5 (#380 fixed) |
| Linux | 2.0.1 | untested | pass | pass r5 (fixed by #330; nameless, in-project=false, unicode path, both names) | fail #476 | pass v5 (LF + CRLF) | pass r5 (#330) | untested | untested | untested |
| Linux | 2.1.1 | untested | untested | untested | untested | pass v5 (repo e2e, up to rollback) | untested | pass v5 (repo e2e) | untested | untested |
| Linux | 2.3.3 | pass | pass | fail #327 (pre-#330, not re-run) | untested | pass (groups, markers, path/url deps, supersede, dry-run, get) | untested | pass (path/url deps) | fail #328 | fixed (#380) |
| Linux | 2.4.3 | untested | pass | fail #327 (pre-#330, not re-run) | untested | pass (LF + CRLF) | untested | pass (LF + CRLF, CI) | untested | fixed (#380) |
| Linux | 2.5.1 | pass v5 | pass r5 (full agent cycle incl. rollback + vex) | pass r5 (all 3 cases, plus long names, symlinked dir, relative / `{cache-dir}` / `~` virtualenvs.path, XDG_CACHE_HOME, `.venv` symlink) | fail #476 (poetry.toml + user config) | pass v5 (LF + CRLF, PEP 621 extras/groups/markers, `sync`, `remove`, dry-run, `get`, relock/`add`, directory targets) | pass r5 (#330: stale check fires) | pass v5 (LF + CRLF, unicode/space path) | hosted→vendored pass r5; vendored→hosted fail #328 | pass v5 (#380 fixed) |
| macOS | 1.8.5 | untested | pass | fail #327 | untested | pass (LF + CRLF) | untested | pass (LF + CRLF) | untested | untested |
| macOS | 2.0.1 | untested | pass | fail #327 | untested | untested | untested | untested | untested | untested |
| macOS | 2.4.3 | untested | pass | fail #327 | untested | pass (LF + CRLF) | untested | pass (LF + CRLF) | untested | untested |
| macOS | 2.5.1 | untested | untested | untested | untested | untested | untested | untested | untested | untested |
| Windows | 1.8.5 | untested | fail #329 | fail #327 | untested | pass (LF + CRLF) | untested (likely #327/#329) | pass (LF + CRLF) | untested | untested |
| Windows | 2.0.1 | untested | fail #329 | fail #327 | untested | untested | untested | untested | untested | untested |
| Windows | 2.4.3 | untested | fail #329 | fail #327 | untested | pass (LF + CRLF) | untested (likely #327/#329) | pass (LF + CRLF) | untested | untested |
| Windows | 2.5.1 | untested | untested | untested | untested | untested | untested | untested | untested | untested |

### Venv selection and policy (run 7, Linux, main `61cfb9b`)

| Poetry | Cell | Result |
| --- | --- | --- |
| 1.8.5, 2.5.1 | Several per-minor envs (`poetry env use`), active env sorts after an older one (3.11→3.12, 3.10→3.13), custom and default `virtualenvs.path` | fail #526 (patches the first-sorted env, VEX attests) |
| 1.8.5, 2.5.1 | Several per-minor envs, active env sorts first | pass (by luck) |
| 2.5.1 | `VIRTUAL_ENV` set to another venv + `envs.toml` entry for the project | fail #526 (comment) |
| 2.5.1 | #456: reinstall wipes the patch, `scan --mode agent` re-applies | pass |
| 2.5.1 | Agent `socket.yml`: `minSeverity`, `ignorePackages` (purl, name, case), `maxNewPatches: 0`, `ecosystems`, `ignorePaths`, `enabled: false`, retain-on-narrow | pass |
| 2.5.1 | Hosted `socket.yml` | untested (mock has no grant route) |

### Global mode (`-g` / `--global-prefix` / `SOCKET_GLOBAL=1`), agent patches (run 4)

Global installs aren't Poetry-specific (Poetry never installs globally unless `virtualenvs.create = false`), so these cells were run from inside a Poetry 2.1.1 project (in-project `.venv`) against a real `pip install --user` copy and a `pip install --target` prefix.

| OS | Cell | Result |
| --- | --- | --- |
| Linux | `scan -g` report-only (`--json`): global user-site `six` found, project `.venv` and lock-only packages don't leak in | pass |
| Linux | `scan -g` sees Debian/apt `.egg-info` installs | fixed by #452 (but see #501) |
| Linux | `scan -g` sees Poetry's official-installer venv (`~/.local/share/pypoetry/venv`) | fail (commented on #415) |
| Linux | `scan -g --mode hosted`, `--global-prefix --mode hosted`, `SOCKET_GLOBAL=1 --mode hosted`: exit 2, poetry.lock untouched | pass |
| Linux | `scan -g --mode agent`, re-run idempotent, `get <uuid> -g`, `SOCKET_GLOBAL=1 get`: global copy patched, `.venv` and lock untouched | pass |
| Linux | `vex -g` attests applied global patch; plain `vex` refuses (`not_applied`) | pass |
| Linux | `rollback -g` restores the global copy byte for byte | pass |
| Linux | Cross-scope rollback (project apply + `rollback -g`, or `-g` apply + `rollback`) | fail #450 (still on `61cfb9b`, r6) |
| Linux | `scan -g` / `create = false` project scan with the same release in user site **and** a system dir (apt egg-info or `/usr/local` dist-info) | fail #501 (patches the shadowed system copy; apt case regressed in #452) |
| Linux | #436/#445 on a hosted Poetry project: `get -g --mode hosted\|vendored`, `scan -g --mode hosted\|vendored` refuse; `rollback -g` / `remove -g` leave `poetry.lock` alone | pass (r6) |
| Linux | Poetry `virtualenvs.create = false`, single system copy | pass (r6: 1.8.5, 2.0.1, 2.2.1, 2.5.1) |
| Linux | `vex -g` from a hosted, synced Poetry project with an unpatched global copy: refuses (`not_applied`) | pass (r5) |
| Linux | `list -g` from a hosted Poetry project lists the project's hosted pin | not filed (PR #446 notes it) |
| Linux | Read-only `--global-prefix` (non-root user, path with space + `é`): human mode shows the error, exit 1 | pass; JSON drops the error (#424) |
| Linux | Project scan without `-g`, Poetry venv undiscovered / not created yet: falls back to and **patches** the global interpreter | #327 layouts fixed by #330 (r5); still happens for `in-project = true` + no `.venv` (#476, re-confirmed r6 on `61cfb9b`; now lands in apt's dist-packages) |
| macOS / Windows | all of the above | untested (probe branches blocked) |

### Run 8 cells (Linux, main `61cfb9b`)

| Poetry | Cell | Result |
| --- | --- | --- |
| 2.5.1 | Hosted, then `poetry export` (plugin), then `pip install -r` | pass |
| 2.5.1 | Hosted with a `supplemental` / `explicit` mirror source, six from PyPI | pass (install, `check --lock`, vex) |
| 2.5.1 | Forked lock (six at two versions by marker) | hosted and vendored refuse before writing (documented) |
| 2.5.1 | Agent, `virtualenvs.options.system-site-packages = true`, six in system site | fail #409 (comment): Poetry 2 skips installing into `.venv`, agent says `package_not_installed`, exit 0 |
| 1.8.5 | Same, agent | pass (Poetry 1.8 installs into `.venv`) |
| 1.8.5, 2.5.1 | Same, hosted, then install, then vex | pass |
| 1.8.5, 2.5.1 | Hosted, then install with `installer.no-binary` = `six` / `:all:` | pass |
| 1.8.5, 2.5.1 | Hosted `rollback` (PyPI forwarder), `check --lock`, reinstall | pass |
| macOS 1.2–2.x | `XDG_CACHE_HOME` / `XDG_CONFIG_HOME` set (platformdirs ≥ 4.6 honours them on macOS; socket-patch doesn't) | untested, suspected fail (needs probe) |
| Windows 1.0/1.1 | Out-of-tree env-name hash (Poetry < 1.2 doesn't `normcase`; socket-patch lowercases) | untested, suspected fail (needs probe) |

## Backlog

1. **macOS XDG** (run 8 lead): with `XDG_CACHE_HOME` / `XDG_CONFIG_HOME` set and platformdirs ≥ 4.6.0 (2026-02-12; Poetry 1.2–2.x pull 4.12.x), Poetry uses `$XDG_CACHE_HOME/pypoetry/virtualenvs` and `$XDG_CONFIG_HOME/pypoetry/config.toml`. `python_crawler.rs` `poetry_default_cache_dir` / `poetry_user_config_path` only look in `~/Library/...` on macOS. This needs a macOS probe.
2. **Windows Poetry 1.0/1.1 env hash** (run 8 lead): Poetry < 1.2 hashes the raw cwd, while socket-patch lowercases it (`windows_normcase`). This needs a Windows probe.
3. Global mode on macOS / Windows (maintainer request), including #501's ordering on macOS, plus #330 verification (#329 Windows hash; macOS case-preserving `realpath`) and long paths. This needs probe branches.
4. Probe branches are blocked: `git push --delete` and `git push origin :refs/heads/...` still fail (runs 1–8). A maintainer needs to delete `bughunt/poetry/20260930-venv-discovery` and `bughunt/poetry/20260930-windows-modes`.
5. Conda `CONDA_PREFIX` (with `CONDA_DEFAULT_ENV != base`) as Poetry's env. Needs micromamba.
6. `virtualenvs.use-poetry-python` / `prefer-active-python` with no `envs.toml` entry (a #526 follow-on).
7. Hosted `socket.yml` policy on Poetry (the mock now has a grant route).

## Known non-bugs

- `patches-api.socket.dev` / `patch.socket.dev` / `api.socket.dev` are blocked by the sandbox proxy (403). Use a local mock API (`SOCKET_API_URL`).
- The CLI's rustls client doesn't trust the sandbox's re-terminating proxy CA. So vendored PyPI fetches (`vendor_fetch_failed`) and **v5 hosted rollback/remove** (re-resolves `https://pypi.org/pypi/<name>/<ver>/json`) fail in the sandbox. Point `SOCKET_PYPI_JSON_API` at a local HTTP forwarder that also rewrites `files.pythonhosted.org`. The repo's `e2e_vex_build -- poetry::` hosted test scrubs `SOCKET_*`, so its rollback step fails in the sandbox for the same reason. Not a product bug.
- A `poetry.lock` with a UTF-8 BOM is rejected by Poetry itself ("Invalid statement (at line 1, column 1)").
- A lock whose packages come from a custom `[[tool.poetry.source]]` (even a PyPI mirror, `priority = "primary"`) is refused by hosted (`redirect_poetry_lock_unsupported`, exit 0) and vendored (`pypi_poetry_source_already_exists`, exit 1) before any write. Documented ("a user-authored `[package.source]` on another origin").
- Agent-mode `vex` on a project with no install hook reports `ecosystem_not_setup` / `no_applicable_patches`. Documented.
- `vex` on a `package-mode = false` project with no version needs `--product` (`product_undetected`). Expected.
- Poetry 1.8 ignores PEP 621 `[project]` dependencies, so "`[project].name` + `[tool.poetry].name`" is n/a before 2.0.
- CLI_CONTRACT.md lives at `crates/socket-patch-cli/CLI_CONTRACT.md`, not the repo root.
- Running from a subdirectory of a Poetry project doesn't find it: pypi is cwd-only (CLI_CONTRACT.md "Monorepo / multi-project discovery model"; use `--cwd` or a directory target).
- On Poetry < 1.4, vendored emits `pypi_poetry_integrity_unverified` and hosted emits `redirect_poetry_stale_install_risk`. Both are deliberate advisories.
- On Poetry 1.1–1.3, a warm venv keeps the upstream bytes after a hosted rewrite, even when Poetry prints "Updating six (1.16.0 -> 1.16.0 <url>)". Documented. v5 flags it as `redirect_pypi_stale_install` and refuses VEX.
- `poetry check --lock` fails on Poetry 1.1 / 1.2 (1.2 has no `--lock` option, and 1.1's `check` crashes). This isn't caused by socket-patch.
- Poetry 1.0 + pip 22.3 / 23.0 (e.g. venvs seeded with pip 23.0.1) refuses the hosted wheel's `#sha256=…&#egg=` fragment. Documented, and named in the `redirect_poetry_stale_install_risk` detail. Use pip ≤ 22.2 or ≥ 23.1.
- Poetry 1.0 writes empty `[metadata.files]` against today's PyPI. Documented (backtest "populated" shape).
- Vendored `--vex` on a warm, unpatched venv still attests, with the warning `vendored_tree_out_of_sync`. Documented in CLI_CONTRACT.md.
- `list` / standalone `vex` only recognise hosted pins on Socket's origin. A mock origin needs `--patch-server-url`.
- `scan --json` with several directory targets is refused ("--json takes one project directory").
- v5 removed `--vendor-source build` (local artifact construction). Repair re-downloads from the service.
- Agent rollback needs the "before" blob from `/v0/orgs/<org>/patches/blob/<hash>`. A mock without that route gives `missing_blob`.
- `scan --mode agent` re-run after a failed apply says `[skip] … (already recorded)` and exits 0 with the file unpatched. That's by design (it prints "run `socket-patch apply` to re-apply them"), and `apply` / `vex` then report the failure correctly.
- My mock answers every per-ecosystem batch with the same patch, so a mode-less multi-ecosystem scan lists `six` twice. That's a mock artifact; pass `--ecosystems pypi`.
- In the sandbox, `/usr/lib/python3/dist-packages/six` is an apt `.egg-info` install, invisible to the crawler (#447). Use `pip install --user --ignore-installed` for a real global copy.
- `POETRY_VIRTUALENVS_IN_PROJECT=yes` / `on` is true to socket-patch and false to Poetry (`boolean_normalizer` accepts only "true" / "1"). Theoretical, not filed.
- The CLI's PyPI requests (hosted rollback, hosted → vendored takeover) need `SOCKET_PYPI_JSON_API` pointed at a local forwarder in the sandbox. Without it the takeover fails closed with `redirect_revert_failed`. A forwarder script that rewrites `files.pythonhosted.org` works.
- Concurrent `scan` runs in one project: the extra runs exit 1 with "Another socket-patch process is operating in this directory" (use `--lock-timeout`). This is by design.
- Dotted names (`jaraco.context`): Poetry 1.1 keeps the dotted name in the lock (quoted `[metadata.files]` key), Poetry ≥ 1.8 canonicalizes it. Hosted rewrite, install, vex and rollback all work with both purl spellings (r5).
- `rollback -g --json` with no manifest returns `error` as a plain string ("Manifest not found"), not a `{code, message}` object. This is a shape nit, not Poetry-specific, and not filed.
- Poetry 1.8 – 2.2 with `virtualenvs.create = false` running as root in this image reinstall a user-site package into `/usr/local/lib/python3.11/dist-packages`. That's Poetry's behaviour, not socket-patch.
- The uv-tool-installed Poetry in this image builds `poetry env use python3.12` envs on its own 3.11 interpreter (`pyvenv.cfg` says 3.11.15). That's a sandbox quirk; use pip-installed Poetry for multi-interpreter cells.
- In agent `scan --json`, `ecosystems: [npm]` reports `policy.counts.filtered: 2` for a single `six` (likely the lock and the installed copy). Cosmetic, not filed.
- Forked Poetry locks (one package at several versions by marker) are refused by hosted (`redirect_poetry_lock_unsupported`, "forked Poetry package requires an unambiguous source") and vendored ("forked resolution"). Documented in CLI_CONTRACT.md.
- Hosted `vex` attests a lock pin for a package that isn't installed (for example an optional group left uninstalled). Documented ("with nothing installed, attests a discovered lockfile reference from its integrity pin").
- `rollback` on a project with no manifest, ledger or hosted pin gives "Manifest not found", exit 1. Documented (truly-empty project).
- Hosted-only `rollback --json` reports `rolledBack: 0` while it restores the lock. Cosmetic, not filed.
- uv can't install from `poetry export` output against the sandbox mock (it sends `HEAD`, which the mock doesn't answer). Mock artifact.
