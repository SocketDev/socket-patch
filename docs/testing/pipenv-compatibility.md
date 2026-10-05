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
| `Pipfile.lock`, `pipfile-spec: 6` (Pipenv 7 and later) | Every category (`default`, `develop`, Pipenv 2022+ named categories) that pins the patched release becomes `{"file" \| "path": "<url>#sha256=<hex>", "hashes": ["sha256:<hex>"]}` with `markers`/`extras`/`index` kept as Pipenv wrote them and `version` dropped. `path` for Pipenv 7–11, `file` from 2018. `_meta` (the Pipfile content hash) and the Pipfile are untouched. | Every matching category refers to the committed wheel under `.socket/vendor/pypi/<uuid>/`; wheels with extras use `path` (Pipenv 2022's file-URL bug). Requires Pipenv 2018 or later (`pypi_pipenv_installer_unsupported`). | Independent of the lock: patches the installed distribution in the venv Pipenv resolves for the project — `VIRTUAL_ENV` unless `PIPENV_ACTIVE` / `PIPENV_IGNORE_VIRTUALENVS` is set, in-project `.venv` subject to `PIPENV_VENV_IN_PROJECT` and the Pipfile's `[pipenv] venv_in_project`, or Pipenv's default `$WORKON_HOME/<dir>-<hash>[-<python>]`; never `venv/` (discovered without running Pipenv). Settings come from the project's `.env` (or `PIPENV_DOTENV_LOCATION`, unless `PIPENV_DONT_LOAD_ENV`) and the process environment using the concrete current, process-cached, 2018 shell, and 2020 shell profiles described below. With a `.venv` directory and an existing WORKON_HOME venv, each profile retains its native in-project choice: Pipenv 2026.2+ prefers the WORKON_HOME venv when nothing is set, 2023.11.14+ uses it when the project is explicitly not in-project, and older releases use `.venv` either way. |
| `Pipfile.lock`, `pipfile-spec` < 6 (Pipenv 0–6) | Refused (`redirect_pipenv_skipped`), lock untouched. | Refused (`pypi_pipenv_spec_unsupported`). | Works. |
| Lock-only checkout (nothing installed) | Discovered from the lock and redirected. | Discovered from the lock; the patched wheel or source distribution is downloaded and verified from the service without a local install. | Nothing to patch (no installed distribution); the lock's pins are listed as lockfile-only packages. |

Pipenv command timing and dotenv behavior changed across supported releases. Current commands resolve complete python-dotenv records with preceding bindings ahead of process variables, then apply their active-environment settings. Older commands can cache placement before loading dotenv, so discovery also retains the process-only result. The 2018 shell instead resolves dotenv references from the complete final mapping with process variables first; its Project settings were cached before loading, and it marks itself active before final placement. The 2020 shell uses modern parsing but still caches Project settings such as `IGNORE_VIRTUALENVS` and `VENV_IN_PROJECT`; it reads the active prefix before setting `PIPENV_ACTIVE`. These two cached profiles do not support custom venv names. Discovery combines only project-owned environments from these observed profiles, without executing Pipenv or searching unrelated venvs.

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
  `pipenv --rm && pipenv sync`, for a `default` package. Plain `pipenv sync`
  installs only `default`, so the printed `sync` arguments follow the lock:
  `--dev` when the package is pinned in `develop`, and
  `--categories "<names>"` (Pipfile names: `packages`, `dev-packages`,
  `<category>`) when it is pinned in a named category. The `--rm` form
  re-syncs every non-empty category (#790). `pipenv uninstall <pkg>` is **not** a remedy:
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
  case-insensitive-filesystem fallback) so an agent-mode `scan`/`rollback`
  run outside `pipenv run` sees the project's venv.
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

A case that fails with a transport error in its error text or logs (pip
giving up on PyPI, e.g. `too many 503 error responses`, a connection error,
or a CLI request error / patch API 5xx) is re-run from a fresh case
directory, at most three attempts in total. The failed attempts' logs stay
under `attempts/<case>/<n>/` and the final row lists them in
`transportRetries`. Functional failures are never retried.

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
requires an agent-mode scan run outside `pipenv run` to see Pipenv's venv.

Full run results belong with the source revision and toolchain versions in CI
artifacts or a local output directory. See the [testing guide](README.md#ci-and-results).
