# Pipenv compatibility and production backtests

`socket-patch` supports hosted, vendored and agent-mode Python patches in
Pipenv projects. The tests use real Pipenv releases, real PyPI artifacts and
the public Socket patch service. Rewriting alone is not an installation
result: the backtest reinstalls from the rewritten `Pipfile.lock` (fresh
clone, warm venv, lock-only checkout) and compares the installed bytes with
the published patch.

This supplements the [hosted](hosted-production-e2e.md) and
[vendored](vendored-production-e2e.md) production suites; see the
[ecosystem matrix](../ecosystems.md#mode--ecosystem-matrix) for the other
package managers and [uv compatibility](uv-compatibility.md) for the uv /
requirements.txt lanes of the same ecosystem.

## Formats and rewrite behavior

| Input | Hosted | Vendored | Agent |
|-------|--------|----------|-------|
| `Pipfile.lock`, `pipfile-spec: 6` (Pipenv 7 and later) | Every category (`default`, `develop`, Pipenv 2022+ named categories) that pins the patched release becomes `{"file" \| "path": "<url>#sha256=<hex>", "hashes": ["sha256:<hex>"]}` with `markers`/`extras` preserved and `version`/`index` dropped. `path` for Pipenv 7–11, `file` from 2018. `_meta` (the Pipfile content hash) and the Pipfile are untouched. | Every matching category refers to the committed wheel under `.socket/vendor/pypi/<uuid>/`; wheels with extras use `path` (Pipenv 2022's file-URL bug). Requires Pipenv 2018 or later (`pypi_pipenv_installer_unsupported`). | Independent of the lock: patches the installed distribution in the project's venv — in-project `.venv`, `VIRTUAL_ENV`, or Pipenv's default `$WORKON_HOME/<dir>-<hash>[-<python>]` (discovered without running Pipenv). |
| `Pipfile.lock`, `pipfile-spec` < 6 (Pipenv 0–6) | Refused (`redirect_pipenv_skipped`), lock untouched. | Refused (`pypi_pipenv_spec_unsupported`). | Works. |
| Lock-only checkout (nothing installed) | Discovered from the lock and redirected. | Discovered from the lock; the pristine wheel is fetched by one of the lock's recorded digests (Pipenv records every release file's sha256 without filenames) through PyPI's JSON API, verified against the same digest, and the patched wheel comes from the service. | Nothing to patch (no installed distribution); the lock's pins are listed as lockfile-only packages. |

Both hash fields are load-bearing: Pipenv 2023+ verifies the `#sha256=` URL
fragment, 2018–2022 verify the `hashes` list, Pipenv 11 accepts either. A
tampered hosted reference fails to install on every supported release.
Pipenv 2023+ does not verify the hash of a *local* wheel (vendored mode), so
the committed wheel bytes are the protection there; `socket-patch vex
--product <purl>` re-verifies the installed files (a Pipfile names no
project, so the product purl must be passed explicitly).

## Installer boundaries (measured)

Measured with the last stable release of every published Pipenv major
(`releases.json` of the depscan harness, PyPI as of 2026-09-17): 0.2.8,
3.6.2, 4.1.4, 5.4.2, 6.2.9, 7.9.10, 8.3.2, 9.1.0, 10.1.2, 11.10.4,
2018.11.26, 2020.11.15, 2021.11.23, 2022.12.19, 2023.12.1, 2024.4.1,
2025.1.3, 2026.8.0. Pre-2018 releases run on Python 3.6 (they no longer
import on modern Pythons); 2018–2022 on Python 3.8; 2023+ on Python 3.12.

- **Warm virtualenvs are never reinstalled.** With the same release already
  installed, `pipenv install`, `pipenv install --deploy` and `pipenv sync`
  exit 0 and keep the upstream bytes — on every major, hosted and vendored.
  The rewritten lock protects fresh installs; the CLI warns
  (`redirect_pypi_stale_install` / `pypi_pipenv_stale_install`) while a
  venv still holds the upstream release. Verified remedies (Pipfile
  byte-untouched): `pipenv run pip uninstall -y <pkg> && pipenv sync`, or
  `pipenv --rm && pipenv sync`. `pipenv uninstall <pkg>` is **not** a remedy:
  it rewrites the Pipfile and re-locks the patch away. `PIP_FORCE_REINSTALL=1
  pipenv sync` works on 2018 but is ignored by 2026.
- **Relocking drops the reference.** `pipenv lock` (and `update`, and
  `install <other>` on releases before 2024, where it is a full relock)
  regenerates the redirected entry to its registry reference on every major,
  hosted and vendored — a silent unpatch. Re-run Socket Patch afterwards;
  `rollback` retires the stale record cleanly (2026 reproduces the original
  entry byte for byte, 2022 writes a different hash list, `pipenv uninstall`
  removes the entry — all are the desired end state, not drift). Pipenv 2023+
  keep a hosted reference on an entry excluded by its marker and re-serialize
  it; that is still ours and rolls back.
- **Reference key by release.** Pipenv 7–11 install only `path` references
  (`file` fails); 2018 and later install `file`. The CLI probes
  `pipenv --version` on absolute `PATH` entries (every release prints
  `pipenv, version X`) only when a patch targets the lock;
  `SOCKET_PIPENV_MAJOR=<major>` pins the answer for CI images without pipenv.
- **Line endings.** Pipenv preserves a CRLF lock (git autocrlf); so do both
  rewriters and both rollbacks, and a checkout that converted the file
  between the redirect and the rollback still restores.
- **Vendored refusal for 7–11.** Those releases cannot reliably consume
  vendored wheel references; hosted mode covers them.
- **Command availability.** `--ignore-pipfile` and `--venv` arrive with
  Pipenv 3, `--deploy` with 9, `pipenv sync` with 2018, `pipenv verify` with
  2020, `pipenv requirements` with 2022 (it exports the hosted URL / vendored
  path). Pipenv 0.x has no `WORKON_HOME` placement to discover.
- **Out-of-tree venv naming** is unchanged from Pipenv 7 through 2026:
  `sanitize(<project dir name>)[:42]-<8 chars of urlsafe-base64(sha256(<abs
  Pipfile path>))>`, plus `-<PIPENV_PYTHON>` when that variable is set (the
  interpreter's basename on 2026, the full string on 2018 and 11). The
  crawler reproduces it (and honours the `.venv` file pointer,
  `PIPENV_CUSTOM_VENV_NAME`, `PIPENV_PIPFILE`, `WORKON_HOME` and Pipenv's
  case-insensitive-filesystem fallback) so a bare `scan`/`rollback` sees the
  project's venv; before, it fell through to the global interpreter and
  reported success while the venv stayed unpatched.
- **CLI scope.** The CLI reads `<cwd>/Pipfile.lock` and discovers the
  project's venv from that directory; it does not walk up to a parent
  Pipfile the way Pipenv does (`PIPENV_MAX_DEPTH`) and does not follow
  `PIPENV_PIPFILE` to another project's lock. Run it in the project
  directory (or pass `--cwd`).

## Running the matrix

```sh
cargo build -p socket-patch-cli
cp target/debug/socket-patch /tmp/socket-patch-under-test
scripts/backtest-pipenv.py \
  --socket-patch /tmp/socket-patch-under-test \
  --socket-patch-revision "$(git rev-parse --short HEAD)" \
  --output /tmp/pipenv-compat \
  --modes hosted vendored agent agent-oot \
  --shapes direct dev category marker marker-excluded extras transitive crlf \
  --jobs 4
scripts/backtest-pipenv.py --render-doc-table /tmp/pipenv-compat/summary.json
```

Needs network (PyPI + patch.socket.dev), `uv`, Docker for the pre-2018
releases (they run inside `python:3.6.15-slim` through a host-side `pipenv`
wrapper, so the CLI's installer probe sees them) and no Socket token (the
fixture dependency is `urllib3 1.26.18`, which has a public free-tier
patch). Copy the binary out of `target/` first — a rebuild would swap it
under the run. Concurrent invocations must use disjoint version/shape sets.

Per (release, shape, mode) the harness checks: the lock-only fresh checkout,
`--dry-run` parity (hosted; the vendored preview is ledger-only by design and
is recorded), an idempotent re-scan, the untouched Pipfile and `_meta`, the
expected reference key, every category rewritten with markers/extras kept,
the stale-install warning over a warm venv, whether Pipenv reinstalls a warm
venv (recorded), the lock-driven install into an emptied venv with the
installed bytes checked against the patch record's Git blob SHA-256 hashes, a
fresh clone of the committed state, `pipenv verify` / `requirements`, tamper
rejection, what `pipenv lock` does to the entry, rollback after that relock
(a registry-shaped entry is kept and only the ledger retires; the Pipenv 2023+
hybrid that still carries our reference rolls back to the original entry),
`vex`, and a byte-exact `rollback`. Agent mode additionally checks that
repeat installs and `sync` keep the in-place patch, and the out-of-tree leg
requires the bare scan to see Pipenv's venv.

## Results

<!-- GENERATED:BEGIN pipenv-matrix -->
### macOS — full matrix (18 majors × 8 shapes × 4 modes)

CLI revision `e521093`: **470 cases, 470 pass** (103 expected refusals, 36 skipped installer limitations, 0 failing, 0 harness errors).

| Pipenv | hosted | vendored | agent (in-project venv) | agent (out-of-tree venv) | bare CLI sees out-of-tree venv | tamper rejected (hosted / vendored) | warm venv re-installed (hosted / vendored) | relock keeps patch (hosted / vendored) | `pipenv verify` (hosted / vendored) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0.2.8 | refused (redirect_pipenv_skipped) | refused (pypi_pipenv_spec_unsupported) | pass (dev,direct,extras,marker,marker-excluded,transitive) | refused (skipped: Pipenv 0.x has no `--venv` and no WORKON_HOME placement to discover) | none | n/a / n/a | n/a / n/a | n/a / n/a | n/a / n/a |
| 3.6.2 | refused (redirect_pipenv_skipped) | refused (pypi_pipenv_spec_unsupported) | pass (dev,direct,extras,marker,marker-excluded,transitive) | pass (dev,direct,extras,marker,transitive) | none/true | n/a / n/a | n/a / n/a | n/a / n/a | n/a / n/a |
| 4.1.4 | refused (redirect_pipenv_skipped) | refused (pypi_pipenv_spec_unsupported) | pass (dev,direct,extras,marker,marker-excluded,transitive) | pass (dev,direct,extras,marker,transitive) | none/true | n/a / n/a | n/a / n/a | n/a / n/a | n/a / n/a |
| 5.4.2 | refused (redirect_pipenv_skipped) | refused (pypi_pipenv_spec_unsupported) | pass (dev,direct,extras,marker,marker-excluded,transitive) | pass (dev,direct,extras,marker,transitive) | none/true | n/a / n/a | n/a / n/a | n/a / n/a | n/a / n/a |
| 6.2.9 | refused (redirect_pipenv_skipped) | refused (pypi_pipenv_spec_unsupported) | pass (dev,direct,extras,marker,marker-excluded,transitive) | pass (dev,direct,extras,marker,transitive) | none/true | n/a / n/a | n/a / n/a | n/a / n/a | n/a / n/a |
| 7.9.10 | pass (crlf,dev,direct,extras,marker,marker-excluded,transitive) | refused (pypi_pipenv_installer_unsupported) | pass (dev,direct,extras,marker,marker-excluded,transitive) | refused (skipped: Pipenv 7 cannot create its out-of-tree virtualenv in the harness image) | none | yes / n/a | false / n/a | false / n/a | 2 / n/a |
| 8.3.2 | pass (crlf,dev,direct,extras,marker,marker-excluded,transitive) | refused (pypi_pipenv_installer_unsupported) | pass (dev,direct,extras,marker,marker-excluded,transitive) | pass (dev,direct,extras,marker,transitive) | true | yes / n/a | false / n/a | false / n/a | 2 / n/a |
| 9.1.0 | pass (crlf,dev,direct,extras,marker,marker-excluded,transitive) | refused (pypi_pipenv_installer_unsupported) | pass (dev,direct,extras,marker,marker-excluded,transitive) | pass (dev,direct,extras,marker,transitive) | true | yes / n/a | false / n/a | false / n/a | 2 / n/a |
| 10.1.2 | pass (crlf,dev,direct,extras,marker,marker-excluded,transitive) | refused (pypi_pipenv_installer_unsupported) | pass (dev,direct,extras,marker,marker-excluded,transitive) | pass (dev,direct,extras,marker,transitive) | true | yes / n/a | false / n/a | false / n/a | 2 / n/a |
| 11.10.4 | pass (crlf,dev,direct,extras,marker,marker-excluded,transitive) | refused (pypi_pipenv_installer_unsupported) | pass (dev,direct,extras,marker,marker-excluded,transitive) | pass (dev,direct,extras,marker,transitive) | true | yes / n/a | false / n/a | false / n/a | 2 / n/a |
| 2018.11.26 | pass (crlf,dev,direct,extras,marker,marker-excluded,transitive) | pass (crlf,dev,direct,extras,marker,marker-excluded,transitive) | pass (dev,direct,extras,marker,marker-excluded,transitive) | pass (dev,direct,extras,marker,transitive) | true | yes / yes | false / false | false / false | 2 / 2 |
| 2020.11.15 | pass (crlf,dev,direct,extras,marker,marker-excluded,transitive) | pass (crlf,dev,direct,extras,marker,marker-excluded,transitive) | pass (dev,direct,extras,marker,marker-excluded,transitive) | pass (dev,direct,extras,marker,transitive) | true | yes / yes | false / false | false / false | 2 / 2 |
| 2021.11.23 | pass (crlf,dev,direct,extras,marker,marker-excluded,transitive) | pass (crlf,dev,direct,extras,marker,marker-excluded,transitive) | pass (dev,direct,extras,marker,marker-excluded,transitive) | pass (dev,direct,extras,marker,transitive) | true | yes / yes | false / false | false / false | 2 / 2 |
| 2022.12.19 | pass (category,crlf,dev,direct,extras,marker,marker-excluded,transitive) | pass (category,crlf,dev,direct,extras,marker,marker-excluded,transitive) | pass (category,dev,direct,extras,marker,marker-excluded,transitive) | pass (category,dev,direct,extras,marker,transitive) | true | yes / yes | false / false | false / false | 0 / 0 |
| 2023.12.1 | pass (category,crlf,dev,direct,extras,marker,marker-excluded,transitive) | pass (category,crlf,dev,direct,extras,marker,marker-excluded,transitive) | pass (category,dev,direct,extras,marker,marker-excluded,transitive) | pass (category,dev,direct,extras,marker,transitive) | true | yes / no | false / false | false / false | 0 / 0 |
| 2024.4.1 | pass (category,crlf,dev,direct,extras,marker,marker-excluded,transitive) | pass (category,crlf,dev,direct,extras,marker,marker-excluded,transitive) | pass (category,dev,direct,extras,marker,marker-excluded,transitive) | pass (category,dev,direct,extras,marker,transitive) | true | yes / no | false / false | false / false | 0 / 0 |
| 2025.1.3 | pass (category,crlf,dev,direct,extras,marker,marker-excluded,transitive) | pass (category,crlf,dev,direct,extras,marker,marker-excluded,transitive) | pass (category,dev,direct,extras,marker,marker-excluded,transitive) | pass (category,dev,direct,extras,marker,transitive) | true | yes / no | false / false | false / false | 0 / 0 |
| 2026.8.0 | pass (category,crlf,dev,direct,extras,marker,marker-excluded,transitive) | pass (category,crlf,dev,direct,extras,marker,marker-excluded,transitive) | pass (category,dev,direct,extras,marker,marker-excluded,transitive) | pass (category,dev,direct,extras,marker,transitive) | true | yes / no | false / false | false / false | 0 / 0 |

### Linux — release binary in a container (2018+ majors, direct shape, 4 modes)

CLI revision `e521093`: **32 cases, 32 pass** (0 expected refusals, 0 skipped installer limitations, 0 failing, 0 harness errors).

| Pipenv | hosted | vendored | agent (in-project venv) | agent (out-of-tree venv) | bare CLI sees out-of-tree venv | tamper rejected (hosted / vendored) | warm venv re-installed (hosted / vendored) | relock keeps patch (hosted / vendored) | `pipenv verify` (hosted / vendored) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2018.11.26 | pass (direct) | pass (direct) | pass (direct) | pass (direct) | true | yes / yes | false / false | false / false | 2 / 2 |
| 2020.11.15 | pass (direct) | pass (direct) | pass (direct) | pass (direct) | true | yes / yes | false / false | false / false | 2 / 2 |
| 2021.11.23 | pass (direct) | pass (direct) | pass (direct) | pass (direct) | true | yes / yes | false / false | false / false | 2 / 2 |
| 2022.12.19 | pass (direct) | pass (direct) | pass (direct) | pass (direct) | true | yes / yes | false / false | false / false | 0 / 0 |
| 2023.12.1 | pass (direct) | pass (direct) | pass (direct) | pass (direct) | true | yes / no | false / false | false / false | 0 / 0 |
| 2024.4.1 | pass (direct) | pass (direct) | pass (direct) | pass (direct) | true | yes / no | false / false | false / false | 0 / 0 |
| 2025.1.3 | pass (direct) | pass (direct) | pass (direct) | pass (direct) | true | yes / no | false / false | false / false | 0 / 0 |
| 2026.8.0 | pass (direct) | pass (direct) | pass (direct) | pass (direct) | true | yes / no | false / false | false / false | 0 / 0 |

### Invocation variants (`--cwd`, nested `--cwd`, symlinked project directory; direct shape, 4 modes)

CLI revision `e521093`: **48 cases, 48 pass** (3 expected refusals, 0 skipped installer limitations, 0 failing, 0 harness errors).

| Pipenv | invocation | hosted | vendored | agent | agent-oot |
| --- | --- | --- | --- | --- | --- |
| 11.10.4 | `--cwd <project>` | pass | refused (pypi_pipenv_installer_unsupported) | pass | pass |
| 11.10.4 | `--cwd` from a nested directory | pass | refused (pypi_pipenv_installer_unsupported) | pass | pass |
| 11.10.4 | symlinked project directory | pass | refused (pypi_pipenv_installer_unsupported) | pass | pass |
| 2018.11.26 | `--cwd <project>` | pass | pass | pass | pass |
| 2018.11.26 | `--cwd` from a nested directory | pass | pass | pass | pass |
| 2018.11.26 | symlinked project directory | pass | pass | pass | pass |
| 2022.12.19 | `--cwd <project>` | pass | pass | pass | pass |
| 2022.12.19 | `--cwd` from a nested directory | pass | pass | pass | pass |
| 2022.12.19 | symlinked project directory | pass | pass | pass | pass |
| 2026.8.0 | `--cwd <project>` | pass | pass | pass | pass |
| 2026.8.0 | `--cwd` from a nested directory | pass | pass | pass | pass |
| 2026.8.0 | symlinked project directory | pass | pass | pass | pass |

Every `pass` cell verified the installed `urllib3/response.py` against the patch record's Git blob SHA-256 after a real Pipenv install. Columns: `warm venv re-installed` and `relock keeps patch` are measured Pipenv boundaries (see above), not requirements; `pipenv verify` exit 2 means the subcommand does not exist on that release. Per-case checks, notes and harness provenance: [`results.json`](pipenv-compatibility/results.json).
<!-- GENERATED:END pipenv-matrix -->
