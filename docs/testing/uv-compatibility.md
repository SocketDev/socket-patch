# uv compatibility and production backtests

`socket-patch` supports hosted and vendored Python patches in native uv locks,
PEP 723 script locks, PEP 751 locks, and `requirements.txt`. The tests use real
uv binaries, real PyPI artifacts, and the public Socket patch service. Successful
rewriting alone is not an installation result: the backtest reinstalls from the
rewritten files and compares the installed bytes with the published patch.

This supplements the existing [hosted](hosted-production-e2e.md) and
[vendored](vendored-production-e2e.md) production suites. See the
[ecosystem matrix](../ecosystems.md#mode--ecosystem-matrix) for other package
managers.

## Formats and rewrite behavior

| Input | Hosted | Vendored |
|-------|--------|----------|
| `requirements.txt`, including uv-generated hash continuations | Exact version pins become direct artifact URLs with the patched SHA-256. Extras and markers are retained; hashes for the replaced artifact are removed. | Requirements refer to a committed wheel under `.socket/vendor/pypi/` with its hash. |
| `uv.lock`, native `version = 1`, `[[package]]` | The package source and artifact entry agree on the hosted URL and hash. A paired `pyproject.toml` receives the corresponding uv source configuration. | The package source refers to the committed wheel. The paired `pyproject.toml` records that source. |
| `uv.lock`, experimental `[[distribution]]` (uv 0.1.45–0.2.34) | Follows the entry's own shape: `direct+` string or `{ url = … }` table source, `[[distribution.wheel]]` sub-table or inline `wheels` entry, and source-qualified dependency references where the lock carries them. | Refused (`pypi_uv_legacy_lock_unsupported`): the experimental grammar cannot carry a portable local wheel — through 0.2.6 a relative path source does not parse, and on 0.2.17–0.2.34 `--locked` rejects it while `uv lock` and plain `uv sync` absolutize it. Use uv 0.2.35 or newer. |
| `*.py.lock` with its PEP 723 `*.py` script | Rewrites the lock and the script's uv source metadata together. | Rewrites the lock and script metadata together and commits the patched wheel. |
| `pylock.toml` and `pylock.<name>.toml`, PEP 751 `lock-version = "1.0"` | Uses one `archive` URL with the patched SHA-256. | Uses one `archive` path with the committed wheel's SHA-256. |

Replacing a wheel removes stale sdist entries, sizes, and upload times. A source
archive occupies an sdist/archive entry rather than a wheel entry. Native uv
dependency references are updated when they identify the replaced source.

The native project and script metadata edits matter for ordinary resolution:
changing only the lock's source can make `uv sync --locked` reject the lock, or
let an ordinary `uv sync` restore the registry source. The backtest records
frozen, locked, and ordinary installation outcomes separately where supported.

## Limits

- The installed env is the one uv syncs into. With `UV_PROJECT_ENVIRONMENT` set
  (absolute, or relative to the project), the crawler uses that env in place of
  `./.venv` or an activated `VIRTUAL_ENV`, as `uv sync` / `uv run` do. This
  holds for a project with `uv.lock`, or a `pyproject.toml` that no other
  manager's lock claims. Agent mode patches that env, and the hosted
  stale-install warning and `vex` check it. Run the scan with the same
  `UV_PROJECT_ENVIRONMENT` that `uv sync` used.
- uv 0.0 has no native `uv.lock`; its compatibility lane is compiled requirements.
  `uv pip sync` rejects the bare local wheel paths emitted by vendored
  requirements through uv 0.1.23 (`Unexpected '.', expected '-c', '-e', '-r'
  or the start of a requirement`) and accepts them from 0.1.24; use hosted mode
  or upgrade uv for older binaries.
- `uv lock` itself has a boundary: the subcommand appears in 0.1.42 but panics
  (`not yet implemented`) through 0.1.44 and first writes a lock at 0.1.45,
  the last 0.1 release. Below that, hosted mode covers uv through compiled
  requirements (from 0.0.5).
- uv 0.1.45–0.2.34 write the experimental `[[distribution]]` lock
  grammar; `[[package]]` starts at 0.2.35. The grammar went through three
  shapes, and the hosted rewriter follows the entry's own shape on each axis:
  string sources with sub-table artifacts (`source = "registry+…"`,
  `[distribution.sdist]`, `[[distribution.wheel]]`, source-qualified
  `[[distribution.dependencies]]`) through 0.2.5; string sources with inline
  artifacts (`sdist = { … }`, `wheels = [ … ]`) from 0.2.6 through 0.2.17; and
  inline-table sources (`source = { registry = … }`) from 0.2.18. Emitting the
  wrong shape is not a parse error the user sees: 0.2.18–0.2.34 reject the
  string source and silently ignore the lock (`--frozen` / `--locked` fail,
  an ordinary `uv sync` still installs the patch via the pyproject source),
  and 0.2.6–0.2.17 ignore an unexpected `[[distribution.wheel]]` and try to
  build the direct wheel URL as a source archive. The `[[distribution]]`
  grammar is hosted-only: vendored native wiring is refused with
  `pypi_uv_legacy_lock_unsupported`. The refusal is kept because no spelling of
  a committed wheel is stable across that era: through 0.2.6 a relative path
  source cannot be parsed at all (`path+<rel>` is an invalid URL, `path+file:`
  forms resolve against the filesystem root or panic); 0.2.17–0.2.34 install a
  relative `{ path = … }` source under `--frozen` and plain `uv sync`, but
  `--locked` rejects the non-canonical spelling, `uv lock` and plain `uv sync`
  rewrite the path to an absolute one, resolution is relative to the current
  directory rather than the project, and hashes are not verified before
  0.2.34. Use uv 0.2.35 or newer for native vendoring; vendored requirements
  work on the same binaries.
- Vendored native wiring covers every `[[package]]`-grammar release, uv 0.2.35
  onward. uv 0.2.35 and 0.2.36 wrote no root `[package.metadata]` yet (it
  arrived in 0.2.37); on those locks the requires-dist repoint is skipped
  rather than refused, and the package source plus the pyproject
  `[tool.uv.sources]` entry carry the redirect (verified with `--frozen`,
  `--locked`, and ordinary installs). A lock that has metadata but no entry
  for the package is stale and is still refused with
  `pypi_uv_lock_package_missing`.
- Native lock versions other than `version = 1`, and PEP 751 versions other than
  `lock-version = "1.0"`, are refused. Lock `revision` values 1 (0.6.0–0.6.14),
  2 (0.6.15–0.8.3) and 3 (0.8.4 onward) are covered by the release-family runner.
- Command availability boundaries observed with real binaries: `uv lock`
  writes a lock from 0.1.45 (see above); `uv export` from 0.4.1, its
  `--output-file` flag from 0.4.7 (the harness reads the export from stdout
  below that); `uv lock --script` from 0.5.17; PEP 751 `uv pip compile
  --output-file pylock.toml` from 0.6.15. Earlier binaries record those lanes
  as unavailable, not as failures.
- `[tool.uv] dev-dependencies` (the pre-PEP 735 dev group) is classified as a
  direct dependency, and every duplicate `requires-dist` / `requires-dev`
  entry for the package (extras, markers) is repointed, so `uv sync --locked`
  accepts the lock. The hosted unwind (`rollback`, `remove`, the hosted →
  vendored takeover) puts each entry's specifier back from the declaration
  uv lowered it from, so one package declared with different specifiers in
  `dependencies`, extras or marker-split lines, or reached through a PEP 735
  `include-group`, rolls back byte for byte (the `extras` and
  `include-group` lanes of `e2e_redirect_uv_build`, uv ≥ 0.4.27). An entry
  whose marker matches no declaration is still refused. Declaration-owned
  simple equality markers (`extra == 'name'`) are matched explicitly. More
  complex `extra` predicates with differing version clauses remain refused,
  as do declarations whose lowered markers are indistinguishable: hosted
  URLs erase the specifiers needed to recover their provenance. Refusals
  leave the lock and paired metadata unchanged. `[tool.uv] constraint-dependencies` /
  `build-constraint-dependencies` naming the package are repointed in the
  lock's `[manifest]` `constraints` / `build-constraints` entries, which uv
  ≥ 0.5.6 serializes with the package's source. uv 0.2.37–0.5.3 serialize
  constraints as `{ name, specifier }` regardless of sources, so on those
  releases the repointed entry makes `uv sync --locked` fail (`--frozen` and
  a plain `uv sync` still install the patch; the plain sync rewrites the
  entry back). The CLI cannot tell those binaries apart from the lock, so the
  repoint emits the advisory `pypi_uv_constraints_require_uv_0_5_6`. The
  project-variant lane below exercises both shapes. Measured with the real
  0.5.4 and 0.5.5 binaries (`scripts/uv-vex-matrix.sh`): 0.5.4 still rejects
  the repointed entry under `--locked`, 0.5.5 accepts it — the effective
  boundary is 0.5.5; the advisory keeps its `0_5_6` name.
- Transitive targets are wired through `[tool.uv] override-dependencies` plus
  a `[tool.uv.sources]` entry. uv applies sources to overrides only from
  0.5.6: on 0.2.35–0.5.3 `--frozen` installs the patched wheel from the lock,
  but a plain `uv sync` re-resolves the override against the registry and
  reinstalls the pristine wheel (and rewrites the lock). The CLI cannot tell
  those binaries apart from the lock, so the override branch emits the
  advisory warning `pypi_uv_override_requires_uv_0_5_6` instead of refusing.
  Measured with the real binaries: 0.5.4 still re-resolves the override,
  0.5.5 already keeps it (effective boundary 0.5.5). When the environment
  already holds the patched install (a `--frozen` sync ran first), 0.2.37 –
  0.5.4 leave that same-version install in place while rewriting the lock to
  the registry, so only the NEXT install from the lock is pristine;
  manifest-less VEX follows the lock and stops attesting either way.
- Symlinked `uv.lock`, `pyproject.toml`, `pylock*.toml`, `*.py.lock` and
  script files are discovered for inventory and `repair`, but every writer
  refuses before touching anything with `redirect_symlinked_file_unsupported`
  (the one symlink code, hosted and vendored alike) — because uv writes through the link
  while socket-patch's atomic stage-and-rename would replace the link with a
  regular file, leaving the target unpatched and the checkout with a type
  change. A symlink that is not one of the files to be written does not block
  vendoring its regular siblings.
- Vendored requirements install on uv ≥ 0.1.24 (the bare `./wheel` path
  grammar). The `--hash` on that line is enforced only by `uv pip sync
  --require-hashes`, which exists from 0.1.32, and by default from 0.5.x;
  through 0.1.29 uv silently ignores hashes. uv ≤ 0.1.23 has no local path
  grammar at all — hosted requirements work there.
- Both uv backends preserve CRLF line endings: the hosted rewriter and the
  vendored `uv.lock` / `pyproject.toml` writer (including the appended
  `[manifest]` and `[package.metadata]` fragments and their revert) keep the
  file's convention.
- A script lock requires its paired script and a valid PEP 723 metadata block.
  Missing metadata or an incompatible existing source is reported before either
  file is rewritten.
- Native projects and scripts resolving multiple versions of the same package
  are refused when a global uv source would replace another version. Supporting
  those cases requires marker-specific source mappings. Standalone PEP 751
  rewriting selects the exact package version; duplicate entries for the same
  name and version are refused when source selection is ambiguous.
- Lock-only discovery (a fresh checkout, no venv) queries the patch API with
  every PEP 440 spelling of an exact pure-release pin as well as the one
  written (`six==1.16` asks for `@1.16` and `@1.16.0`; `==1.16.0` also asks for
  `@1.16`), so it finds the patch the registry keys under its own spelling, as a
  venv-backed run does, and reports the package as not installed (#604).
- Hosted requirements select exact `==`/`===` pins or identifiable archive URLs.
  Other versions remain unchanged. A bare requirement is rewritten only when
  one row and one override version identify the selection. Ranges, wildcard
  pins, opaque URLs, and ambiguous unpinned rows are reported as
  `redirect_requirements_version_ambiguous` and preserved.
- A script lock does not replace the main project's lockfile selection merely
  by sharing its directory: its packages supplement the `poetry.lock` or
  `requirements.txt` inventory rather than hiding it, and an unrelated script
  lock does not block vendoring a package from the project's requirements or
  Poetry lock. `uv.lock` keeps its exclusive precedence. When multiple
  applicable package-manager locks coexist, the CLI reports its precedence
  choice and the locks it leaves unchanged.
- Vendored installation needs the committed artifact tree. uv 0.2.35–0.3.5
  cannot build the ROOT fixture from an empty cache under `--offline`
  (`setuptools>=40.8.0` is a build dependency of the fixture, not of the
  patched wheel). `uv sync --no-install-project` exists from 0.3.3 and the
  harness passes it whenever `sync --help` lists it, which is why the 0.3.5
  row passes cold; from 0.4.0 uv no longer builds a root without a
  `[build-system]`, so ≥ 0.4.0 passes regardless; ≤ 0.2.34 vendoring is
  refused, so the case is never exercised there. On 0.2.35–0.3.0 the harness
  retries the install with network access and records it as
  `project-vendored-frozen-sync-root-build-networked`, distinct from any
  failure to install the patched wheel.
- `vendor --revert` refuses to delete a vendored Python wheel while `uv.lock`,
  a PEP 751 lock, a script, or `requirements.txt` still references it and the
  ledger entry has no wiring to replay (the shape `socket-patch repair`
  rebuilds when `state.json` is lost); `vendor_wiring_unknown_revert_blocked`
  names the file. Restore the pre-vendor files (or re-lock) first.

Revert state retains the original wiring. Script and lock edits are treated as a
pair: conflicting changes preserve both files and their recovery state rather
than restoring only one side. When any uv.lock or pyproject.toml record has
drifted, neither file is written. A relock that only re-serializes an array
around socket-patch's unchanged element is not drift: `uv add --dev x` rewrites
the dev group's `requires-dev` line, and `uv add y` sorts `[manifest] overrides`
into its multi-line form. Revert restores or removes just that element.
A path source records no specifier, so changing the vendored package's own
declaration (`uv add "six>=1.16"`) leaves uv.lock unchanged. Revert then
restores the `requires-dist`, `requires-dev` and `[manifest] constraints`
entries with the specifier pyproject.toml declares at revert time, not the one
recorded when vendoring. When uv's spelling can't be derived, as with a
multi-clause range (uv orders clauses differently across releases), the edit is
treated as drift and both files are kept. Tests also cover restoring one package while
preserving another package's vendored entries.

## Reproduce the release-family matrix

The matrix pins 42 binaries: the first and the latest release of every uv 0.x
family (0.0 through 0.12), plus the releases on either side of every behaviour
boundary the probes found — `0.1.23`/`0.1.24` (local wheel paths in
requirements), `0.1.44`/`0.1.45` (`uv lock` writes a lock; the subcommand
exists from 0.1.42 and panics `not yet implemented` through 0.1.44),
`0.2.5`/`0.2.6` (sub-table → inline lock artifacts),
`0.2.17`/`0.2.18` (string → inline-table lock sources),
`0.2.34`/`0.2.35` (`[[distribution]]` → `[[package]]`), `0.2.36`/`0.2.37`
(root `[package.metadata]` appears),
`0.4.0`/`0.4.1` (`uv export`), `0.5.16`/`0.5.17` (`uv lock --script`),
`0.6.14`/`0.6.15` (PEP 751 export; lock revision 2) and `0.8.3`/`0.8.4` (lock
revision 3). The full list is `VERSIONS` in `scripts/backtest-uv.py`; the
boundaries were bisected with `scripts/probe-uv-boundaries.py`, which records
the lock grammar, lock revision, command availability (including whether the
`uv lock` subcommand exists and actually writes a lock, and whether `uv export`
accepts `--output-file`), and local-wheel requirement support of any set of uv
releases. The one probe-pinned boundary the matrix does not bracket is the
`uv export --output-file` flag (0.4.6/0.4.7): the harness reads the export
from stdout, so it is a harness detail rather than a compatibility boundary.
This is release-family plus boundary coverage, not a claim that every patch
release was tested.

From the repository root on macOS or Linux:

```sh
cargo build -p socket-patch-cli
cp target/debug/socket-patch /tmp/socket-patch-backtest-bin
python3 scripts/backtest-uv.py \
  --socket-patch /tmp/socket-patch-backtest-bin \
  --socket-patch-revision "$(git rev-parse HEAD)" \
  --python /path/to/python3 \
  --output /tmp/socket-patch-uv-backtest
```

Use Python 3.9 to match the recorded probes; the fixtures declare it as their
minimum. Copy the CLI out of `target/` first so a rebuild cannot swap the binary
under a running matrix. The default list takes roughly half an hour with the
harness's four workers; `--versions` selects a smaller diagnostic run. The
script downloads pinned uv binaries and the pristine urllib3 wheel from PyPI and
verifies their registry hashes. It runs against the public patch proxy without
an API token.

For each binary, the run records command lines, exit codes, output, artifact
hashes, and installed `urllib3/response.py` hashes. It exercises native locks,
plain and hashed requirements, requirements/PEP 751 exports, standalone PEP 751
compilation, and script locks where the uv binary provides those commands.
Unsupported commands remain visible in the results; they are not counted as
successful installation tests. A successful CLI exit with a refusal warning is
also not counted as a successful rewrite.

On every `[[package]]`-grammar binary (uv ≥ 0.2.35) the run adds a
project-variant lane (`variant_matrix` in the script, `variant-<name>-<mode>-*`
cases in `results.json`). Five pyproject shapes are locked fresh, scanned in
hosted and vendored mode, and installed from the patched lock into a fresh
environment with `uv sync --frozen`, `uv sync --locked` (where the binary has
it) and a plain `uv sync`, recording the exit code, whether the lock survived
untouched, and the installed bytes:

- `tool-uv-dev` — `dependencies = []` plus `[tool.uv] dev-dependencies`;
- `dependency-groups` — `dependencies = []` plus PEP 735 `[dependency-groups]`
  `dev` (honoured from uv 0.4.27; older binaries lock an empty project and the
  row records `formatSupported: false`);
- `extras-duplicate` — the package both in `dependencies` and in
  `[project.optional-dependencies]`, so the lock carries two `requires-dist`
  entries for it;
- `constraints` — the package in `dependencies` plus `[tool.uv]
  constraint-dependencies`, giving the lock a `[manifest]` constraints entry
  (skipped as unsupported when the binary records none);
- `transitive` — `requests==2.28.2` with `[tool.uv] exclude-newer =
  "2024-01-01T00:00:00Z"` so urllib3 resolves to 1.26.18 as a transitive
  dependency; the CLI takes the override-dependencies branch, and on uv
  < 0.5.6 the plain `uv sync` row is expected to reinstall the pristine wheel
  (recorded as `installedPatch: false`, see Limits).

A plain `uv sync` that rewrites the lock is recorded (`lockUnchanged: false`),
not raised: it is a real observation, not a harness error. No export or PEP 751
lanes run for the variants. Each version row in `results.json` carries a
`variants` summary. Render a summary alongside the run's output with
`--render-doc-table`:

```sh
python3 scripts/backtest-uv.py --render-doc-table /tmp/socket-patch-uv-backtest/results.json
```

Keep live download grants out of committed evidence. Published patch UUIDs,
archive filenames, hashes, uv versions, and redacted command results are enough
to identify a run. Compare the fresh installed bytes with the patched artifact,
not just with a URL or a success message.

## Manifest-less VEX

Hosted and vendored checkouts carry no `.socket/manifest.json`; `socket-patch
vex` discovers the patch from the wiring files (`uv.lock` + `pyproject.toml`,
`<script>.py.lock` + the script's PEP 723 block, `pylock*.toml`), takes the
record from the ledgers or the patch API, and verifies the installed tree
(hosted) or the committed wheel (vendored). Three layers cover it:

- `crates/socket-patch-cli/tests/e2e_vex_lockfile/uv.rs` — hermetic, every OS:
  every lock shape × hosted / vendored, online / offline / 404, ledger without
  manifest, reverted and half-reverted pairs (including script pairs),
  tampered installed trees and wheel members, spoofed hosts and vendor paths,
  record mismatches, and the embedded `apply --vex` / `vendor --vex` /
  `scan --mode hosted|vendored --vex` paths.
- `e2e_redirect_uv_build` (hosted, wiremock patch API serving the patched
  wheel) and `e2e_vendor_pypi_build` (vendored) — the REAL uv under test
  (`SOCKET_PATCH_UV_E2E_BIN` / `_VERSION` / `_PYTHON` / `_REQUIRED`) builds
  each lane (project, constraints, transitive override, script lock,
  `uv export` / `uv pip compile` / `pip lock` pylock), our CLI wires it, a
  fresh checkout installs from an empty cache and imports the patched bytes,
  then VEX runs with the manifest deleted, with the ledgers deleted, offline
  (`record_unavailable`, zero requests), embedded, and after the wiring is
  reverted with the ledgers left behind (not attested, `--no-verify` too).
  `scripts/uv-vex-matrix.sh` runs every uv 0.N line (0.1.45, 0.2.37, 0.3.5,
  0.4.30, 0.5.3–0.5.6, 0.6.17, 0.7.22, 0.8.24, 0.9.30, 0.10.12, 0.11.33,
  0.12.17) through both suites, plus the live-production uv legs with
  `UV_VEX_MATRIX_PRODUCTION=1`.
- This backtest's `vex_matrix` phase (`vex-backtest.json`): the same steps over
  the installed production cases (`project`, `export-pylock`, `pylock-direct`),
  recording `vexAttested`, `vexMarkers` and `vexSkip` per row.

Lanes a release lacks are reported `n/a`: uv 0.1.45 writes the
`[[distribution]]` grammar (hosted only; vendored is refused as above), script
locks need `uv lock --script` (0.5.17), pylock lanes need `uv pip sync
pylock.toml` (0.7).

Full run results belong with the source revision and toolchain versions in CI
artifacts or a local output directory. See the [testing guide](README.md#ci-and-results).
