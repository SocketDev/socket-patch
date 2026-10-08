[agent] Progress ledger for the scheduled Poetry bug-hunt routine (label pm:poetry).

Last updated: 2026-10-08 (run 16), main `3b4ac84` (includes #330, #446, #452, #456, #503, #527, #538, #540, #644, #703, #708, #946, #950, #963, #1025, #1035, #1044), latest release 4.0.0 (previous 3.3.0). Run 9 re-measured the cells marked "r9". Runs 10–16 have their own tables below. #327, #329, #945 and #1024 are closed: macOS / Windows cells that still show #327 / #329 haven't been re-run, because probe branches are blocked.

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Hosted and vendored cells use a local mock of the patch API (patches-api.socket.dev is blocked from the sandbox) serving a patched `six-1.16.0` wheel, then a real `poetry install` / `poetry sync` and a byte check of the installed file. The existing `poetry-compatibility.yml` matrix (Linux + macOS) covers the plain cells against production. Rows before run 3 were measured on main `f6b7fb9` (pre-v5). Run 3 re-measured the cells marked "v5". Run 5 re-measured the cells marked "r5" on `6e7ef74` (after #330); #327 cells on macOS / Windows still show the pre-fix result because probe branches are blocked.

| OS | Poetry | Agent (in-project `.venv`) | Agent (default out-of-tree venv) | Agent: nameless `package-mode=false` / `[project].name` override / `in-project=false` + stray `.venv` | Agent + hosted VEX: `in-project=true`, no `.venv`, existing out-of-tree env | Hosted (scan, install, rollback) | Hosted VEX with undiscovered venv | Vendored | Mode switch hosted ⇄ vendored | Vendored `repair` (lock-only, wheel deleted) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 0.12.17 | untested | untested | n/a | untested | pass v5 (refused, `redirect_poetry_lock_unsupported`) | n/a | pass v5 (`[metadata.hashes]`); r14 pass | vendored→hosted fail #945 | untested |
| Linux | 1.0.10 | untested | pass r8 (scan, re-run, vex, rollback) | n/a | untested | pass v5 (lock 1.0 native-empty + populated; pip ≥ 23.1) | untested | pass v5 (populated lock 1.0) | untested | untested |
| Linux | 1.1.15 | pass v5 | pass r8 (scan, re-run, vex, rollback); r9 `envs.toml` (3.10/3.11) pass | n/a | fixed by #527 (not re-run) | pass v5 (lock 1.1, extras + dev); r5 dotted name `jaraco.context` rewrite/install/vex/rollback | untested | pass v5 (LF + CRLF, unicode/space path) | pass r14 (both ways, LF + CRLF) | untested |
| Linux | 1.2.2 | untested | untested | n/a | untested | pass v5 (lock 1.1, extras + dev, warm-venv stale check) | untested | pass (lock 1.1) | untested | untested |
| Linux | 1.8.5 | untested | pass; r9 `envs.toml` + custom path pass | pass r5 (fixed by #330; nameless, in-project=false, unicode path) | pass r9 (#527) | pass v5 (LF + CRLF) | pass r5 (#330) | pass v5 (LF + CRLF, unicode/space path) | pass r14 (both ways, LF + CRLF) | pass v5 (#380 fixed) |
| Linux | 2.0.1 | untested | pass | pass r5 (fixed by #330; nameless, in-project=false, unicode path, both names) | fixed by #527 (not re-run) | pass v5 (LF + CRLF) | pass r5 (#330) | untested | untested | untested |
| Linux | 2.1.1 | untested | untested | untested | untested | pass v5 (repo e2e, up to rollback) | untested | pass v5 (repo e2e) | untested | untested |
| Linux | 2.3.3 | pass | pass | pass r11 (all 3 layouts) | untested | pass (groups, markers, path/url deps, supersede, dry-run, get) | untested | pass (path/url deps) | fixed by #503 (not re-run) | fixed (#380) |
| Linux | 2.4.3 | untested | pass | pass r11 (all 3 layouts) | untested | pass (LF + CRLF) | untested | pass (LF + CRLF, CI) | untested | fixed (#380) |
| Linux | 2.5.1 | pass v5 | pass r5 (full agent cycle incl. rollback + vex) | pass r5 (all 3 cases, plus long names, symlinked dir, relative / `{cache-dir}` / `~` virtualenvs.path, XDG_CACHE_HOME, `.venv` symlink) | pass r9 (#527) | pass v5 (LF + CRLF, PEP 621 extras/groups/markers, `sync`, `remove`, dry-run, `get`, relock/`add`, directory targets) | pass r5 (#330: stale check fires) | pass v5 (LF + CRLF, unicode/space path) | hosted→vendored pass r5; vendored→hosted pass r10 (#328 fixed by #503); r14 both ways LF + CRLF pass, mixed EOL → whole-file LF (#814) | pass v5 (#380 fixed) |
| macOS | 1.8.5 | untested | pass | fail #327 (closed; not re-run) | untested | pass (LF + CRLF) | untested | pass (LF + CRLF) | untested | untested |
| macOS | 2.0.1 | untested | pass | fail #327 (closed; not re-run) | untested | untested | untested | untested | untested | untested |
| macOS | 2.4.3 | untested | pass | fail #327 (closed; not re-run) | untested | pass (LF + CRLF) | untested | pass (LF + CRLF) | untested | untested |
| macOS | 2.5.1 | untested | untested | untested | untested | untested | untested | untested | untested | untested |
| Windows | 1.8.5 | untested | fail #329 (closed; not re-run) | fail #327 (closed; not re-run) | untested | pass (LF + CRLF) | untested (likely #327/#329) | pass (LF + CRLF) | untested | untested |
| Windows | 2.0.1 | untested | fail #329 (closed; not re-run) | fail #327 (closed; not re-run) | untested | untested | untested | untested | untested | untested |
| Windows | 2.4.3 | untested | fail #329 (closed; not re-run) | fail #327 (closed; not re-run) | untested | pass (LF + CRLF) | untested (likely #327/#329) | pass (LF + CRLF) | untested | untested |
| Windows | 2.5.1 | untested | untested | untested | untested | untested | untested | untested | untested | untested |

### Venv selection and policy (run 7, Linux, main `61cfb9b`)

| Poetry | Cell | Result |
| --- | --- | --- |
| 1.8.5, 2.5.1 | Several per-minor envs (`poetry env use`), active env sorts after an older one (3.11→3.12, 3.10→3.13), custom and default `virtualenvs.path` | fixed by #527; pass r9 (2.5.1, 1.8.5, 1.1.15) |
| 1.8.5, 2.5.1 | Several per-minor envs, active env sorts first | pass (by luck) |
| 2.5.1 | `VIRTUAL_ENV` set to another venv + `envs.toml` entry for the project | fixed by #527 (unit-tested; r9 conda variants pass) |
| 2.5.1 | #456: reinstall wipes the patch, `scan --mode agent` re-applies | pass |
| 2.5.1 | Agent `socket.yml`: `minSeverity`, `ignorePackages` (purl, name, case), `maxNewPatches: 0`, `ecosystems`, `ignorePaths`, `enabled: false`, retain-on-narrow | pass |
| 2.5.1 | Hosted `socket.yml` | untested (mock has no grant route) |

### Global mode (`-g` / `--global-prefix` / `SOCKET_GLOBAL=1`), agent patches (run 4)

Global installs aren't Poetry-specific (Poetry never installs globally unless `virtualenvs.create = false`), so these cells were run from inside a Poetry 2.1.1 project (in-project `.venv`) against a real `pip install --user` copy and a `pip install --target` prefix.

| OS | Cell | Result |
| --- | --- | --- |
| Linux | `scan -g` report-only (`--json`): global user-site `six` found, project `.venv` and lock-only packages don't leak in | pass |
| Linux | `scan -g` sees Debian/apt `.egg-info` installs | fixed by #452 (but see #501) |
| Linux | `scan -g` sees Poetry's official-installer venv (`~/.local/share/pypoetry/venv`, custom `POETRY_HOME`) | pass r13 (#640 fixed by #644) |
| Linux | `scan -g --mode hosted`, `--global-prefix --mode hosted`, `SOCKET_GLOBAL=1 --mode hosted`: exit 2, poetry.lock untouched | pass |
| Linux | `scan -g --mode agent`, re-run idempotent, `get <uuid> -g`, `SOCKET_GLOBAL=1 get`: global copy patched, `.venv` and lock untouched | pass |
| Linux | `vex -g` attests applied global patch; plain `vex` refuses (`not_applied`) | pass |
| Linux | `rollback -g` restores the global copy byte for byte | pass |
| Linux | Cross-scope rollback (project apply + `rollback -g`, or `-g` apply + `rollback`) | fail #450 (still on `d63ae5f`, r9) |
| Linux | `scan -g` / `create = false` project scan with the same release in user site **and** a system dir (apt egg-info or `/usr/local` dist-info) | fixed by #538 (not re-run) |
| Linux | #436/#445 on a hosted Poetry project: `get -g --mode hosted\|vendored`, `scan -g --mode hosted\|vendored` refuse; `rollback -g` / `remove -g` leave `poetry.lock` alone | pass (r6) |
| Linux | Poetry `virtualenvs.create = false`, single system copy | pass (r6: 1.8.5, 2.0.1, 2.2.1, 2.5.1) |
| Linux | `vex -g` from a hosted, synced Poetry project with an unpatched global copy: refuses (`not_applied`) | pass (r5) |
| Linux | `list -g` from a hosted Poetry project lists the project's hosted pin | not filed (PR #446 notes it) |
| Linux | Read-only `--global-prefix` (non-root user, path with space + `é`): human mode shows the error, exit 1 | pass; JSON drops the error (#424) |
| Linux | Project scan without `-g`, Poetry venv undiscovered / not created yet: falls back to and **patches** the global interpreter | #327 layouts fixed by #330 (r5); `in-project = true` + no `.venv` fixed by #527 (r9 pass) |
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

### Run 9 cells (Linux, main `d63ae5f`)

| Poetry | Cell | Result |
| --- | --- | --- |
| 2.5.1, 1.8.5, 1.1.15 | `poetry env use` on two minors (`envs.toml`): only the active env is patched, `poetry run` imports the patched copy | pass (#526 fixed) |
| 2.5.1, 1.8.5 | `envs.toml` under a custom `virtualenvs.path`, `Demo_App.Core` name, path with a space and `é` | pass |
| 2.5.1, 1.8.5 | `CONDA_PREFIX` + `CONDA_DEFAULT_ENV` = work / base; `VIRTUAL_ENV` under conda base; empty `CONDA_PREFIX` / `VIRTUAL_ENV` | pass |
| 2.5.1 | #538: two envs, no `envs.toml`; drift in one copy: `vex` refuses, `apply` re-run fixes it, `rollback` restores both | pass |
| 2.5.1 | Project apply with the same release in user site | pass (user site untouched) |
| 2.5.1, 1.8.5 | Hosted + `envs.toml` envs: `vex` follows the active env (refuses for the stale env) | pass |
| 2.5.1 | Hosted `socket.yml`: minSeverity, ignorePackages, ecosystems + `--prune`, `enabled: false`, maxNewPatches, ignorePaths, includePaths | pass (needs `SOCKET_PATCH_SERVER_URL` for `retained`) |

### Run 10 cells (Linux, main `045d7ec`)

| Poetry | Cell | Result |
| --- | --- | --- |
| 2.5.1, 1.8.5, 1.1.15 | Vendored → hosted takeover, then fresh install | pass (#328 fixed) |
| 2.5.1, 1.8.5 | Vendored + `poetry add` sibling edit, re-run, rollback; relock drops the wiring, then `vendor_artifact_reused` | pass |
| 2.5.1 | Agent `scan` (API path) after the env set changes (`env use` + `env remove`) | pass |
| 2.5.1, 1.8.5 | Agent apply with an uninstalled optional group (#555) | pass |
| 2.5.1 | Hosted with path-prefixed `--patch-server-url` (scan, re-scan, list, vex, rollback) | pass |
| 2.5.1, 1.8.5 | Vendored install via `poetry -C` / `--directory` / from a subdir | pass |
| 2.5.1, 1.8.5 | Hosted `virtualenvs.create = false` into an activated env | pass |
| 1.1.15, 2.5.1 | `Jinja2` / `typing_extensions` name normalization × hosted / vendored / agent | pass |
| 1.1.15 → 1.8.5 / 2.5.1 | Lock 1.1 rewrite consumed by newer Poetry, tampered hash refused | pass |
| 1.8.5 | `installer.modern-installation = false`, warm venv | Poetry keeps the upstream bytes; CLI fail-closed (stale warning, vex refuses); docs table is inaccurate |
| 1.1.15, 1.8.5, 2.5.1 | `virtualenvs.path = "{project-dir}/.envs"` | fail #608 |

### Run 11 cells (Linux, main `045d7ec`)

| Poetry | Cell | Result |
| --- | --- | --- |
| 2.3.3, 2.4.3 | #327 layouts (nameless `package-mode=false`, `[project].name` override, `in-project=false` + stray `.venv`), agent scan finds the out-of-tree env | pass |
| 2.2.1 (official installer), 1.8.5 (`POETRY_HOME`) | `scan -g` crawls `$POETRY_HOME/venv` / `~/.local/share/pypoetry/venv` | fail #640 (pipx-layout control passes) |
| 2.5.1 | `virtualenvs.path = "{data-dir}/venvs"`; `cache-dir = "{data-dir}/cache"` | fail (commented on #608; `data-dir` key exists from Poetry 2.1) |
| 1.8.5 | same (`{data-dir}` stays literal in Poetry < 2.1) | pass |
| 1.8.5, 2.5.1 | `path = "{cache-dir}/venvs"` control | pass |

### Run 12 cells (Linux, main `045d7ec`)

| Poetry | Cell | Result |
| --- | --- | --- |
| 1.3.2 → 1.8.5 (every minor) | Hosted, warm venv: the 1.3 / 1.4 boundary (version stamp, advisory, byte replacement), then `vex` | pass (matches the docs) |
| 1.3.2, 1.4.0, 1.5.1, 1.7.1, 2.0.1, 2.1.1 | Vendored scan, install, vex (1.3.2 warns `vendored_tree_out_of_sync`) | pass |
| 1.2.2 – 1.7.1, 2.1.1 | Agent, out-of-tree env, `Demo_App.Core` / `My Proj é` names | pass |
| 2.1.1 | Agent list / rollback / apply / repair / remove | pass |
| 2.5.1 | Agent, dev-group-only patch, `sync --without dev`, then `vex` omits it | pass |
| 2.5.1 | Hosted / vendored with six as a path-wheel or URL dependency | refused before any write (documented) |
| 1.0.10, 1.1.15 | Hosted on a CRLF lock + fresh install + idempotent re-scan | pass |
| 1.0.10, 1.1.15, 1.3.2 | Hosted rollback (via the forwarder): byte-identical lock | pass |
| 1.8.5, 2.5.1 | `virtualenvs.create = false` + stray `./venv`, or `./.venv` with `in-project = false` | fail #671 (also release 4.0.0 and the PR #644 head) |
| 2.5.1 | `create = false` controls (no stray tree; `.venv` with in-project unset) | pass |

### Run 13 cells (Linux, main `99f61d2`)

| Poetry | Cell | Result |
| --- | --- | --- |
| 2.5.1, 1.8.5 | #608 re-check: `{data-dir}/venvs` (2.5.1), `{project-dir}/.envs` literal (1.8.5) + vex | pass (fixed by #644) |
| any | #640 re-check: `scan -g` / `rollback -g` on `$POETRY_HOME/venv` and `~/.local/share/pypoetry/venv` | pass (fixed by #644) |
| 2.5.1, 1.8.5 | `{data-dir}/venvs` + `env use` + unrelated `VIRTUAL_ENV` / conda env | fail #866 (agent over-patches; hosted vex refuses) |
| 2.5.1 | default path + `env use` + unrelated `VIRTUAL_ENV` | pass (control) |
| 2.5.1, 1.8.5 | Hosted forward splice on a mixed CRLF/LF lock (#703) | pass |
| 1.2.2 | Hosted on a mixed lock 1.1 (`[metadata.files]` LF), then install | pass |
| 2.5.1, 1.8.5 | Hosted `rollback` / `remove` on a mixed lock | whole file goes LF (see #814, comment) |
| 2.5.1 | #671, #450 | still fail |

### Run 14 cells (Linux, main `9c43dfc`)

| Poetry | Cell | Result |
| --- | --- | --- |
| 2.5.1, 1.8.5, 1.1.15 | hosted → vendored → hosted takeovers + fresh installs + rollback, LF and CRLF locks | pass (EOL kept, rollback byte-identical) |
| 2.5.1 | same on a mixed CRLF/LF lock | takeover revert writes the lock all-LF (#814 child 2) |
| 2.5.1 | symlinked `poetry.lock`: hosted / vendored takeover | pass (both refuse before writing) |
| 0.12.17 | vendored → hosted takeover | fail #945 (dry run promises `redirected: 1`; wet run un-vendors, then refuses) |
| 2.5.1 | #866, #671 | still fail |
| 2.5.1, `create = false` (uv CPython) | hosted `vex` / agent with an apt `python3-six` in `/usr/lib/python3/dist-packages` | vex refuses (`not_applied`); agent also patches the dpkg-owned copy. Lead (backlog 1) |

### Run 15 cells (Linux, main `db83f01`)

| Poetry | Cell | Result |
| --- | --- | --- |
| 2.5.1, 2.2.1, 1.8.5 | Fresh lock-only checkout (default `create = true`, no env yet), apt `six` in system Python: vendored | fail #1023 (exit 1, `pypi_poetry_lock_package_missing`) |
| 2.5.1 | same, agent | fail #1023 (patches dpkg-owned `six.py`) |
| 2.2.1 | `in-project = true`, no `.venv`, no out-of-tree env | fail #1023 |
| 2.2.1 | `create = false` | fallback intended |
| 2.5.1, 1.8.5 | Two patched packages, `remove` one: hosted + vendored, LF + CRLF; vendored `remove <uuid>` | pass |
| 2.5.1 | `remove` / `rollback` with a non-canonical PyPI purl (`typing_extensions`, `Typing-Extensions`), agent / hosted / vendored | fail #1024 |
| 0.12.17 | #945 re-check | still fails (commented) |

### Run 16 cells (Linux, main `3b4ac84`)

| Poetry | Cell | Result |
| --- | --- | --- |
| 1.1.15, 1.8.5, 2.0.1, 2.4.3 (LF + CRLF) | Vendored A → vendored B (superseding uuid), dry run, `get --mode vendored` | fail #1136 (wet exit 1 `pypi_poetry_source_already_exists`; dry run `would_revendor`) |
| 1.1.15, 1.8.5, 2.4.3 (LF + CRLF) | Hosted A → hosted B (#1035), then `remove` / `rollback`, fresh installs | pass |
| 1.1.15, 1.8.5, 2.4.3 | Hosted A → vendored B takeover, venv holds A | fail (#1105 comment): exit 1 `package_not_installed`, dry run `would_vendor` |
| 1.8.5 | same, no venv; or B = A | pass |
| 2.4.3 | `poetry.lock` + exported `requirements.txt`: hosted (scan, `pip install -r`, rollback) / vendored | pass / `pypi_multiple_lockfiles` (documented) |
| 2.4.3 | #1023 / #671 re-check | still fail |

## Backlog

1. Re-check #1136 (vendored re-vendor to a superseding uuid) and #1105 (hosted → vendored onto a newer uuid with a warm venv) once fixed, including dry-run / wet parity.
2. Re-check #1023 when a Poetry guard lands (PR #965 covers uv only). Confirm that `create = false` still falls back.
3. **Lead (run 14):** with `virtualenvs.create = false`, the project global fallback (`get_global_python_site_packages`) crawls every well-known dir, including other interpreters' `/usr/lib/python3/dist-packages` and `/usr/local/lib/python3.X`. Hosted `vex` then refuses a correct install because of an unrelated apt copy, and agent mode patches dpkg-owned files. That follows from #538's "patch every copy" design, so it needs a maintainer call before anyone files it.
4. Vendored `repair` / `scan --prune` after a superseding uuid; two-patch cells on a lock 1.1 (Poetry 1.1.15) and on a mixed-EOL lock; vendored `repair` with one of two wheels deleted.
5. **macOS / Windows re-checks for closed #327 / #329**, the #640 default paths, #866 on macOS, macOS XDG (`XDG_CACHE_HOME` / `XDG_CONFIG_HOME` with platformdirs ≥ 4.6), and the Windows Poetry 1.0/1.1 env hash (raw vs lowercased cwd). All need probe branches.
6. Probe branches are still blocked: `bughunt/poetry/20260930-venv-discovery` and `bughunt/poetry/20260930-windows-modes` still exist (run 16), and deletion was denied in runs 9–16. A maintainer needs to delete them and allow deleting `bughunt/poetry/*`.
7. Docs: `installer.modern-installation = false` (Poetry 1.4–1.8) keeps a warm same-version install, but the poetry-compatibility "Installer boundaries" table says 1.4–1.8 replace it.

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
- In the sandbox, `/usr/lib/python3/dist-packages/six` is an apt `.egg-info` install. Since #452 the crawler sees it, so global-fallback cells pick it up (see backlog 1). Use `pip install --user --ignore-installed` for a controlled global copy, and `rollback` afterwards if agent mode patched it.
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
- Poetry 1.0's `EnvManager.get()` uses an existing `./.venv` even with an explicit `virtualenvs.in-project = false`; 1.1+ honour the `false` and socket-patch follows them. It only diverges when Poetry 1.0 also has an out-of-tree env. Theoretical, not filed.
- Hosted `socket.yml` narrowing lists recorded pins under `policy.filtered` rather than `retained` when the mock origin isn't the patch server. Set `SOCKET_PATCH_SERVER_URL`; this is the documented hosted-origin rule.
- #543's vendored "unwired ledger entry" check doesn't cover pypi (`dispatch_in_use_one` returns `None`), so Poetry vendored re-runs are unchanged by it.
- A test mock that answers every `/patches/batch` with the same patch makes agent scans report `partial_failure` for packages the project doesn't have. Filter the mock to the requested purls.
- Poetry < 2.1 has no `data-dir` config key, so `{data-dir}` in `virtualenvs.path` stays a literal relative directory, and socket-patch matches it.
- `vex` saying "No applied patches with vulnerability metadata" after a hand-staged manifest with empty `vulnerabilities` is a fixture artifact.
- Poetry 1.x's env-var `boolean_normalizer` is case-sensitive (`POETRY_VIRTUALENVS_IN_PROJECT=True` is false), while 2.x lowercases. Same theoretical class as `yes` / `on`; it only diverges with a stray `.venv`. Not filed.
- Standalone `vex --json` needs `-O <file>` (`-o` is `--org`), and against a mock it needs `--api-url` / `--org` for vulnerability metadata. Without them you get harness errors, not product bugs.
- Hosted `rollback` prints "1 unwired package keeps its patched bytes in installed trees" even when no venv exists. Cosmetic, not filed.
- Hosted `rollback` / `remove` on a lock mixing CRLF and LF rewrites the whole file as LF (content equal modulo EOL; Poetry still installs). Tracked under #814 child 2 (comment from run 13), not filed separately.
- Release 4.0.0 doesn't redirect against a v5-shaped mock (`Redirected 0`). It's no baseline for hosted cells.
- A vendored grant needs `integrity.sha512` on the tarball artifact. A mock grant with only `sha256` gives `vendor_prebuilt_required` ("tarball artifact has no sha512 integrity"), and a takeover then un-hosts first. Mock artifact.
- uv's standalone CPython ships an `EXTERNALLY-MANAGED` marker, so Poetry with `create = false` fails at `pip uninstall`. Delete the marker in the sandbox.
- Copying a project together with its `.venv` (virtualenv-created) keeps pip entry scripts pointing at the source venv, so Poetry 1.1 installs land in the wrong tree. Always create fresh venvs.
- `redirect_takeover_unpatched` after a refused lock is documented in CLI_CONTRACT.md. #945 covers only the Poetry 0.x dry-run mismatch and the missing pre-revert gate.
- Symlinked `poetry.lock`: hosted (`redirect_symlinked_file_unsupported`) and vendored (`pypi_poetry_symlink_unsupported`) both refuse before writing. Documented.
- With Poetry ≤ 2.2, `poetry lock` creates the project env. A "fresh checkout" cell has to delete the env after locking, or the scan correctly finds it.
- Two patched packages: `remove` of one keeps the other's hosted / vendored wiring (r15, LF + CRLF, Poetry 1.8.5 / 2.5.1). Not a bug.
- A mock that rebuilds its wheel on every request (zip timestamps) makes `poetry install` fail "Hash … not found in known hashes", and Poetry then keeps the bad bytes in `~/.cache/pypoetry/artifacts` (keyed by URL). Build the mock wheel deterministically and clear that cache.
- Hosted rollback of an exported `requirements.txt` beside `poetry.lock` folds its `\` continuation lines into one line (semantically equal). It's pip's file and cosmetic, so not filed.
- Vendored with `poetry.lock` + `requirements.txt` warns `pypi_multiple_lockfiles` and wires only `poetry.lock`. Documented.
