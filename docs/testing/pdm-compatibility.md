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
| PDM 2.8.0 | `4.3` | **Accepted but not installable.** 2.8.0 writes the `4.3` grammar yet still loses `url`/`path` candidate identity (fixed in 2.8.1), so `pdm sync` on the rewritten lock crashes with `KeyError`. A 2.8.0 lock is byte-identical to a 2.8.1 lock and records no PDM version, so the rewriter cannot refuse it by format — upgrade to ≥ 2.8.1. | Same crash. |
| PDM 2.8.1 – current | `4.3` / `4.4` / `4.4.1` / `4.5.0` / `4.5.1` | `url` + single `{file, hash}`; `static_urls` locks keep their `{url, hash}` file shape. | Local-file `path` + `{file, hash}`. |
| Any future `lock_version` | unknown | **Refused** until the format is tested (fail-closed). | Refused. |

Both modes retain the package version, extras, groups, markers and the
`content_hash`; no `pyproject.toml` edit is required. A repeated scan leaves the
lock unchanged (idempotent). Vendored rollback restores recorded fragments.
Hosted rollback reconstructs
upstream entries from registry metadata and may refuse after incompatible relocks;
it does not keep the original lockfile bytes.
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
| 2.8.0 | 4.3 | crashes | crashes | supported | — | rewrite accepted but `pdm sync`/`pdm install` raise `KeyError` (identity loss, fixed in 2.8.1); agent mode is unaffected. Upgrade to ≥ 2.8.1. |
| 2.8.1 – current | 4.3–4.5.1 | supported | supported | supported | yes | `pdm sync` + `pdm install --check`; static_urls, extras, markers, multi-target and PEP 735 dependency-groups all pass. |

Measured details:

- **A relock discards a lock-only patch on every release.** `pdm lock`,
  `pdm lock --refresh` and `pdm update <pkg>` re-resolve the entry back to the
  registry source. `content_hash` is unchanged by that, so `pdm lock --check`
  cannot detect the loss: re-run `socket-patch scan --mode …` after any of them,
  or gate CI on `socket-patch vex`. Re-scan after a relock to restore patch references.
  Vendored state records
  reversible edits; hosted state is the lock itself, and reversal resolves
  upstream metadata.
- **Hosted mode verifies the lock's file hash** on install for every supported
  release (tamper the hash and `pdm sync` fails closed). Vendored mode's
  protection is the committed wheel bytes, verified by the same hash.
- **The installed env is the one PDM records.** The crawler follows the
  interpreter in `.pdm-python` (`[python] path` in `.pdm.toml` on older PDM),
  ahead of an activated venv or a stray `./.venv`. That covers an out-of-tree
  venv (`venv.in_project = false`) and one bound with `pdm use <venv>`. When
  the interpreter is a base Python, or a PDM 0.x/1.x project saved none, the
  env is `__pypackages__/<X.Y>/lib` (PEP 582; PDM 2.x under
  `python.use_venv = false`). Agent mode patches it there, and the hosted
  stale-install warning and `vex` check it.
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
runs it on Linux and macOS across every PDM major family. It does not run on
Windows: the harness bootstraps PDM through a POSIX venv layout (`bin/pdm`), so
every Windows cell used to skip, and a run whose cells all skip or whose PDM
bootstrap fails is now an error. The matrix needs no Socket API token (the
`urllib3@1.26.18` patch is a free tier).

Full run results belong with the source revision and toolchain versions in CI
artifacts or a local output directory. See the [testing guide](README.md#ci-and-results).
