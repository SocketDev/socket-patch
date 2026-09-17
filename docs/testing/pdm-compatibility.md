# PDM compatibility and production backtests

`socket-patch` supports hosted and vendored Python patches in the `pdm.lock`
generations PDM has written since the lock gained per-file hashes, plus agent
mode (in-place patching of the project's environment) on every release that
records a supported lock. The tests use real PDM releases bootstrapped with uv,
real PyPI artifacts, and the public Socket patch service. Successful rewriting
alone is not an installation result: the backtest reinstalls from the rewritten
lock and compares the installed bytes with the published patch.

This supplements the [hosted](hosted-production-e2e.md) and
[vendored](vendored-production-e2e.md) production suites and mirrors the
[uv](uv-compatibility.md) and [Poetry](poetry-compatibility.md) matrices. See
the [ecosystem matrix](../ecosystems.md#mode--ecosystem-matrix) for other
package managers.

## Formats and rewrite behavior

A shared rewriter (`utils/pdm_lock.rs`) drives both modes: it validates the
`[metadata] lock_version` and `strategy`, rewrites the target `[[package]]`
unit's source (`url` for hosted, local `path` for vendored) and its `files`
hashes — including the PDM 0.x/1.x legacy `[metadata.files]` table and separate
`extras` entries — preserves line endings and non-canonical spacing through
span-based edits, and produces byte-exact fragments for replay. The
`pyproject.toml` and `[metadata] content_hash` are never touched.

| Lock generation (writer) | `lock_version` | Hosted (`scan --mode hosted`) | Vendored (`scan --mode vendored`) |
| --- | --- | --- | --- |
| PDM ≤ 0.11 | none | **Refused** (`…lock_version` missing): the lock records no per-file hashes to rewrite coherently. | Refused for the same reason. |
| PDM 0.12 – 1.4 | `2` | `url` + `files = [{file, hash}]` (or the legacy `[metadata.files]` entry). PDM 0.x/1.x has an upstream freshness bug — a freshly generated lock can fail its own hash check, so ordinary `pdm install` may regenerate it and discard the redirect. The CLI warns `redirect_pdm_legacy_sync_required`; use `pdm sync`. | Local-file `path` + `files` hash; same freshness advisory (`pypi_pdm_legacy_sync_required`). |
| PDM 1.8 – 1.15 | `3.1` | **Refused** (`unsupported PDM lock_version`): native dependency lookup loses URL/path candidate identity before install, so a rewrite would not resolve. The original registry lock still installs. | Refused for the same reason. |
| PDM 2.0 – 2.7 | `4.0` / `4.1` / `4.2` | **Refused** (same identity loss). | Refused. |
| PDM 2.8 – current | `4.3` / `4.4` / `4.4.1` / `4.5.0` / `4.5.1` | `url` + single `{file, hash}`; `static_urls` locks keep their `{url, hash}` file shape. | Local-file `path` + `{file, hash}`. |
| Any future `lock_version` | unknown | **Refused** until the format is tested (fail-closed). | Refused. |

Both modes retain the package version, extras, groups, markers and the
`content_hash`; no `pyproject.toml` edit is required. A repeated scan leaves the
lock unchanged (idempotent). Rollback restores the recorded original
fragments — one per patch, plus the legacy integrity-table entry — so a
`pdm.lock` the tool rewrote returns byte-for-byte to its pre-scan state.
Refused before any write: a `[[package]]` locked at several versions (a marker
fork), a user-authored `url`/`path`/VCS/`editable` source, an unsupported
`lock_version` or `strategy`, hash-less `files`, malformed hashes, and a wheel
whose filename does not match the locked package.

## Installer boundaries (measured)

| PDM | `lock_version` | Hosted | Vendored | Agent | Verifies the lock hash on install | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 0.12 | 2 | supported | supported | supported | yes | `pdm sync`; `pdm install` may regenerate the lock (freshness bug). |
| 1.0 – 1.4 | 2 | supported | supported | supported | yes | as 0.12; 1.0 cannot self-install a dev-group project natively. |
| 1.8 – 1.15 | 3.1 | refused | refused | supported | — | native install of the original registry lock is unaffected. |
| 2.0 – 2.7 | 4.0–4.2 | refused | refused | supported | — | same identity-loss boundary. |
| 2.8 – current | 4.3–4.5.1 | supported | supported | supported | yes | `pdm sync` + `pdm install --check`; static_urls, extras, markers, multi-target and PEP 735 dependency-groups all pass. |

Measured details:

- **A relock discards a lock-only patch on every release.** `pdm lock`,
  `pdm lock --refresh` and `pdm update <pkg>` re-resolve the entry back to the
  registry source. `content_hash` is unchanged by that, so `pdm lock --check`
  cannot detect the loss: re-run `socket-patch scan --mode …` after any of them,
  or gate CI on `socket-patch vex`. A re-scan after a relock re-applies the
  patch and **rebases** the ledger's recorded edits onto the relocked text
  (pristine → current, never an appended chain), so `rollback` still lands on the
  pristine lock afterwards. This matters most for CRLF locks, which PDM
  re-renders to a different byte layout on relock.
- **Hosted mode verifies the lock's file hash** on install for every supported
  release (tamper the hash and `pdm sync` fails closed). Vendored mode's
  protection is the committed wheel bytes, verified by the same hash.
- **`__pypackages__` (PEP 582) projects are not covered.** PDM 0.x/1.x default
  to `__pypackages__`, and 2.x does so under `python.use_venv = false`; the
  installed-set crawler probes virtualenvs (`VIRTUAL_ENV`, `./.venv`), so agent
  and vendored mode need a virtualenv install. Run PDM with `python.use_venv`
  on, or use hosted mode.
- **A non-default lock filename (`pdm lock -L custom.lock`) is invisible** to the
  scan, which only reads `pdm.lock`. A package locked at two versions (a marker
  fork) is refused (`pypi_pdm_lock_forked_package` / a version-mismatch refusal),
  leaving the lock unchanged.
- Precedence when several Python lockfiles coexist: `uv.lock` and `poetry.lock`
  drive hosted PyPI redirects ahead of `pdm.lock`, so a leftover `pdm.lock`
  beside them neither blocks nor is attested; it is rewritten only when it is the
  project's PyPI install driver.

## Mode notes

- **Hosted** (`scan --mode hosted`) rewrites `pdm.lock` in place and needs no
  install; it works from a lock-only checkout.
- **Vendored** (`scan --mode vendored`) commits a rebuilt wheel under
  `.socket/vendor/pypi/<uuid>/` and points the lock's `path` at it; the package
  must be resolvable so its wheel can be rebuilt.
- **Agent** mode patches the interpreter the crawler finds.
- `rollback` (or `remove <purl>`) restores the pristine lock and drops the
  ledger/manifest state for all three modes.

## Backtest harness

`scripts/backtest-pdm.py` bootstraps each pinned PDM release with uv, generates a
project per shape (direct, transitive/override, dev and optional groups, extras,
markers, platform markers, CRLF, `static_urls`, PEP 735 dependency-groups,
multi-target, Unicode paths), runs each of hosted/vendored/agent, and asserts:
the patch applies exactly once, a re-scan is byte-idempotent, `pdm sync` installs
the patched `urllib3/response.py` (git-blob SHA-256 matches the ledger
`afterHash`), ordinary `pdm install` keeps the lock stable, a tampered hash is
rejected, a relock-then-rescan keeps rollback invertible, and rollback restores
the lock and `pyproject.toml` byte for byte. `.github/workflows/pdm-compatibility.yml`
runs it on Linux, Windows and macOS across every PDM major family. The matrix
needs no Socket API token (the `urllib3@1.26.18` patch is a free tier).

<!-- GENERATED:BEGIN — printed by `python3 scripts/backtest-pdm.py --render-doc-table docs/testing/pdm-compatibility/results.json`;
     regenerate after a matrix run instead of editing by hand. -->

Run captured 2026-09-17 on macOS-26.6.2-arm64-arm-64bit-Mach-O with socket-patch `socket-patch 4.0.0` (source `fixed`, binary sha256 `99a0977e83aad0d01371b41147104a123f7eaa8bfb3f85ac1b2dc64a5b6f093d`), 25 PDM releases, shapes: direct, transitive, dev, optional, extras, marker, marker-excluded, platform-linux, platform-windows, crlf, static-urls, space-unicode, dependency-groups, multi-target, two-versions, custom-lockfile, pep582.

| PDM | Python | lock_version | hosted | vendored | agent | tamper rejected (H/V) | `pdm install` keeps lock (H/V) | relock keeps patch (H/V) | notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0.8.7 | 3.8 | — | refused (11 shapes) | 10/11 (11 shapes) | 7/8 (8 shapes) | n/a / n/a | n/a / n/a | n/a / n/a | lock_version absent unsupported: refused before any write, native install intact; `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); agent mode on a `__pypackages__` project patched the PATH interpreter's site-packages; refused vendored scan still writes a `.socket/manifest.json` record; lock-only checkout (nothing installed) is not redirected |
| 0.12.3 | 3.8 | 2 | pass (12 shapes) | 11/12 (12 shapes) | 8/9 (9 shapes) | yes / yes | yes / yes | false / false | `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); agent mode on a `__pypackages__` project patched the PATH interpreter's site-packages; relock dropped urllib3 1.26.18 (`transitive`: pinned resolution, no overrides on this release); re-scan then has nothing to redirect and rollback of the stale ledger exits 0/1; `pdm install` re-locked (extras,marker,marker-excluded,platform-linux,platform-windows): PDM's own freshness check flags its freshly generated lock as stale; patched install afterwards=false/true; use `pdm sync` |
| 1.0.0 | 3.8 | 2 | pass (12 shapes) | 11/12 (12 shapes) | 8/9 (9 shapes) | yes / yes | yes / yes | false / false | `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); agent mode on a `__pypackages__` project patched the PATH interpreter's site-packages; relock dropped urllib3 1.26.18 (`transitive`: pinned resolution, no overrides on this release); re-scan then has nothing to redirect and rollback of the stale ledger exits 0/1 |
| 1.4.5 | 3.8 | 2 | pass (12 shapes) | 11/12 (12 shapes) | 8/9 (9 shapes) | yes / yes | yes / yes | false / false | `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); agent mode on a `__pypackages__` project patched the PATH interpreter's site-packages; relock dropped urllib3 1.26.18 (`transitive`: pinned resolution, no overrides on this release); re-scan then has nothing to redirect and rollback of the stale ledger exits 0/1 |
| 1.8.5 | 3.8 | 3.1 | refused (11 shapes) | 10/11 (11 shapes) | 7/8 (8 shapes) | n/a / n/a | n/a / n/a | n/a / n/a | lock_version 3.1 unsupported: refused before any write, native install intact; `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); agent mode on a `__pypackages__` project patched the PATH interpreter's site-packages; refused vendored scan still writes a `.socket/manifest.json` record; lock-only checkout (nothing installed) is not redirected |
| 1.12.8 | 3.8 | 3.1 | refused (12 shapes) | 11/12 (12 shapes) | 8/9 (9 shapes) | n/a / n/a | n/a / n/a | n/a / n/a | lock_version 3.1 unsupported: refused before any write, native install intact; `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); agent mode on a `__pypackages__` project patched the PATH interpreter's site-packages; refused vendored scan still writes a `.socket/manifest.json` record; lock-only checkout (nothing installed) is not redirected |
| 1.15.5 | 3.8 | 3.1 | refused (12 shapes) | 12/13 (13 shapes) | 8/9 (9 shapes) | n/a / n/a | n/a / n/a | n/a / n/a | lock_version 3.1 unsupported: refused before any write, native install intact; `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); refused vendored scan still writes a `.socket/manifest.json` record; lock-only checkout (nothing installed) is not redirected |
| 2.0.3 | 3.11 | 4.0 | refused (12 shapes) | 12/13 (13 shapes) | 8/9 (9 shapes) | n/a / n/a | n/a / n/a | n/a / n/a | lock_version 4.0 unsupported: refused before any write, native install intact; `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); refused vendored scan still writes a `.socket/manifest.json` record; lock-only checkout (nothing installed) is not redirected |
| 2.1.5 | 3.11 | 4.0 | refused (12 shapes) | 12/13 (13 shapes) | 8/9 (9 shapes) | n/a / n/a | n/a / n/a | n/a / n/a | lock_version 4.0 unsupported: refused before any write, native install intact; `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); refused vendored scan still writes a `.socket/manifest.json` record; lock-only checkout (nothing installed) is not redirected |
| 2.2.1 | 3.11 | 4.0 | refused (12 shapes) | 12/13 (13 shapes) | 8/9 (9 shapes) | n/a / n/a | n/a / n/a | n/a / n/a | lock_version 4.0 unsupported: refused before any write, native install intact; `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); refused vendored scan still writes a `.socket/manifest.json` record; lock-only checkout (nothing installed) is not redirected |
| 2.3.4 | 3.11 | 4.1 | refused (12 shapes) | 12/13 (13 shapes) | 8/9 (9 shapes) | n/a / n/a | n/a / n/a | n/a / n/a | lock_version 4.1 unsupported: refused before any write, native install intact; `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); refused vendored scan still writes a `.socket/manifest.json` record; lock-only checkout (nothing installed) is not redirected |
| 2.6.1 | 3.11 | 4.2 | refused (12 shapes) | 12/13 (13 shapes) | 8/9 (9 shapes) | n/a / n/a | n/a / n/a | n/a / n/a | lock_version 4.2 unsupported: refused before any write, native install intact; `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); refused vendored scan still writes a `.socket/manifest.json` record; lock-only checkout (nothing installed) is not redirected |
| 2.7.4 | 3.11 | 4.2 | refused (12 shapes) | 12/13 (13 shapes) | 8/9 (9 shapes) | n/a / n/a | n/a / n/a | n/a / n/a | lock_version 4.2 unsupported: refused before any write, native install intact; `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); refused vendored scan still writes a `.socket/manifest.json` record; lock-only checkout (nothing installed) is not redirected |
| 2.8.2 | 3.11 | 4.3 | pass (13 shapes) | 12/13 (13 shapes) | 8/9 (9 shapes) | yes / yes | yes / yes | false / false | `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); refused vendored scan still writes a `.socket/manifest.json` record |
| 2.9.3 | 3.11 | 4.3 | pass (13 shapes) | 12/13 (13 shapes) | 8/9 (9 shapes) | yes / yes | yes / yes | false / false | `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); refused vendored scan still writes a `.socket/manifest.json` record |
| 2.10.4 | 3.11 | 4.4 | pass (13 shapes) | 12/13 (13 shapes) | 8/9 (9 shapes) | yes / yes | yes / yes | false / false | `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); refused vendored scan still writes a `.socket/manifest.json` record |
| 2.11.2 | 3.11 | 4.4.1 | pass (14 shapes) | 13/14 (14 shapes) | 9/10 (10 shapes) | yes / yes | yes / yes | false / false | `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); refused vendored scan still writes a `.socket/manifest.json` record |
| 2.12.4 | 3.11 | 4.4.1 | pass (14 shapes) | 13/14 (14 shapes) | 9/10 (10 shapes) | yes / yes | yes / yes | false / false | `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); refused vendored scan still writes a `.socket/manifest.json` record |
| 2.15.4 | 3.11 | 4.4.1 | pass (14 shapes) | 13/14 (14 shapes) | 9/10 (10 shapes) | yes / yes | yes / yes | false / false | `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); refused vendored scan still writes a `.socket/manifest.json` record |
| 2.17.3 | 3.11 | 4.5.0 | pass (16 shapes) | 15/16 (16 shapes) | 10/11 (11 shapes) | yes / yes | yes / yes | false / false | `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); refused vendored scan still writes a `.socket/manifest.json` record |
| 2.20.1 | 3.11 | 4.5.0 | pass (17 shapes) | 16/17 (17 shapes) | 11/12 (12 shapes) | yes / yes | yes / yes | false / false | `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); refused vendored scan still writes a `.socket/manifest.json` record |
| 2.22.4 | 3.12 | — | n/a | n/a | n/a | n/a / n/a | n/a / n/a | n/a / n/a | lock_version absent |
| 2.25.9 | 3.12 | — | n/a | n/a | n/a | n/a / n/a | n/a / n/a | n/a / n/a | lock_version absent |
| 2.27.0 | 3.13 | 4.5.0 | pass (17 shapes) | 16/17 (17 shapes) | 11/12 (12 shapes) | yes / yes | yes / yes | false / false | `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); refused vendored scan still writes a `.socket/manifest.json` record |
| 2.29.2 | 3.13 | 4.5.1 | pass (17 shapes) | 16/17 (17 shapes) | 11/12 (12 shapes) | yes / yes | yes / yes | false / false | `__pypackages__` layout: crawler does not see it (falls through to the PATH interpreter); refused vendored scan still writes a `.socket/manifest.json` record |

<!-- GENERATED:END -->
