# uv vendored-wheel spike fixtures

Generated 2026-06-09 with **uv 0.11.19 (7b2cff1c3 2026-06-03 aarch64-apple-darwin)**, CPython 3.14.3 (macOS arm64).
De-risking spike for `socket-patch vendor`: vendoring a patched wheel at
`.socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl`
and rewriting `pyproject.toml` + `uv.lock` so the project consumes it.

Each directory is a `pyproject.toml` + `uv.lock` pair, all uv-generated (never hand-written),
except where noted. All locks: `version = 1`, `revision = 3`.

## Fixture pairs

| dir | shows |
| --- | --- |
| `direct-registry/` | BEFORE: direct dep `six==1.16.0` from PyPI. requires-dist keeps `specifier = "==1.16.0"`; six `source = { registry = ... }` with `sdist` + url/size/upload-time wheels. |
| `direct-path-wheel/` | AFTER: `[tool.uv.sources] six = { path = ... }`. six becomes `source = { path = "<relpath>" }`; wheels element is `{ filename, hash }` ONLY (no url/size/upload-time/path); `sdist` line dropped; `version` retained; requires-dist becomes `{ name = "six", path = "<relpath>" }` — **specifier is dropped, not kept alongside**. |
| `transitive-registry/` | BEFORE: direct dep `python-dateutil==2.8.2`; six is transitive and resolves to 1.17.0 from registry. |
| `transitive-promoted/` | AFTER: six promoted into `[project] dependencies` (`"six==1.16.0"`) + sources path entry. Root `dependencies` gains `{ name = "six" }`; requires-dist gains `{ name = "six", path = ... }` (dateutil entry keeps its specifier); six entry switches to path source, pinned down 1.17.0 → 1.16.0. |
| `override-transitive/` | ALTERNATIVE (no promotion): `[tool.uv] override-dependencies = ["six==1.16.0"]` + sources entry, six NOT in project.dependencies. Lock gains `[manifest]` with `overrides = [{ name = "six", path = ... }]` (path replaces specifier there too); six entry is the same path shape; requires-dist untouched. Installs from the vendored wheel; byte-stable under plain `uv sync`. |

## Key behaviors observed (claim numbers from the spike)

1. Path-wheel lock shape: see `direct-path-wheel/uv.lock` lines for six.
2. Surgical text edit of the registry lock reproduced the uv-generated path lock
   **byte-identically**; `uv lock --check` exit 0, `uv sync --locked` installs from the
   vendored wheel, plain `uv sync` leaves the lock byte-identical (sha256 stable).
3. Fresh checkout (only pyproject/uv.lock/.socket), fresh `UV_CACHE_DIR`,
   `uv sync --frozen --offline` → installs the patched wheel; marker visible in
   site-packages `six.py`. (Wheel was repacked with a marker + RECORD fixed; lock hash
   refreshed via `uv lock --upgrade-package six` — see surprise below.)
4. Tamper: valid-zip content change → `uv sync --frozen` fails
   "Hash mismatch ... Expected: sha256:<lock> Computed: sha256:<file>", exit 1.
   A raw byte-flip fails earlier with "deflate decompression error: invalid distances set".
5. Promotion (transitive → direct + source) works; `uv sync --locked` ok; plain sync byte-stable.
6. Lock-only edit (path source written ONLY into six's `[[package]]`, pyproject untouched):
   `uv lock --check`, `uv sync --locked`, `--frozen`, plain `uv sync`, even plain `uv lock`
   ALL pass and preserve it — but `uv lock --upgrade`/`--upgrade-package six` silently
   reverts to registry six 1.17.0.
7. `[tool.uv.sources]` entry for a package not in any direct declaration: **silently
   ignored** (exit 0, no warning), whether the package is transitive or absent entirely.
8. Sources DO apply to `override-dependencies` (see `override-transitive/`).
9. Silent-revert risk is real: registry pyproject + path lock → plain `uv sync` re-resolves
   and rewrites the lock back to registry source, exit 0, no warning, registry wheel
   installed. `uv lock --check` on that combo DOES fail ("The lockfile at `uv.lock` needs
   to be updated, but `--check` was provided.").
10. Single-project locks have NO `[manifest]` section (no `members` key); `[manifest]`
    appears only to carry resolver inputs (e.g. `overrides`). Virtual root:
    `source = { virtual = "." }`; packaged (build-system) root: `source = { editable = "." }`.

## Surprise / implementation hazard

Replacing the vendored wheel's bytes at an unchanged path does NOT refresh the lock hash:
plain `uv lock` keeps the stale hash (lock validation never re-hashes files). Use
`uv lock --upgrade-package <name>`, delete+regenerate, or write the new sha256 surgically.
