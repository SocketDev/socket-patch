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
  2 (0.6.15–0.8.3) and 3 (0.8.4 onward) are all covered by the matrix below.
- Command availability boundaries observed with real binaries: `uv lock`
  writes a lock from 0.1.45 (see above); `uv export` from 0.4.1, its
  `--output-file` flag from 0.4.7 (the harness reads the export from stdout
  below that); `uv lock --script` from 0.5.17; PEP 751 `uv pip compile
  --output-file pylock.toml` from 0.6.15. Earlier binaries record those lanes
  as unavailable, not as failures.
- `[tool.uv] dev-dependencies` (the pre-PEP 735 dev group) is classified as a
  direct dependency, and every duplicate `requires-dist` / `requires-dev`
  entry for the package (extras, markers) is repointed, so `uv sync --locked`
  accepts the lock. `[tool.uv] constraint-dependencies` /
  `build-constraint-dependencies` naming the package are repointed in the
  lock's `[manifest]` `constraints` / `build-constraints` entries, which uv
  ≥ 0.5.6 serializes with the package's source. The project-variant lane
  below exercises both.
- Transitive targets are wired through `[tool.uv] override-dependencies` plus
  a `[tool.uv.sources]` entry. uv applies sources to overrides only from
  0.5.6: on 0.2.35–0.5.3 `--frozen` installs the patched wheel from the lock,
  but a plain `uv sync` re-resolves the override against the registry and
  reinstalls the pristine wheel (and rewrites the lock). The CLI cannot tell
  those binaries apart from the lock, so the override branch emits the
  advisory warning `pypi_uv_override_requires_uv_0_5_6` instead of refusing.
- Symlinked `uv.lock`, `pyproject.toml`, `pylock*.toml`, `*.py.lock` and
  script files are discovered for inventory and `repair`, but every writer
  refuses before touching anything — hosted
  `redirect_symlinked_file_unsupported`, vendored `pypi_uv_symlink_unsupported`
  / `pypi_lock_symlink_unsupported` — because uv writes through the link
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
than restoring only one side. Tests also cover restoring one package while
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
`variants` summary; the tables below are printed from that file with
`--render-doc-table` (see the markers in the results section), so the doc can be
regenerated after a full run without hand-editing:

```sh
python3 scripts/backtest-uv.py --render-doc-table /tmp/socket-patch-uv-backtest/results.json
```

Keep live download grants out of committed evidence. Published patch UUIDs,
archive filenames, hashes, uv versions, and redacted command results are enough
to identify a run. Compare the fresh installed bytes with the patched artifact,
not just with a URL or a success message.

## Full matrix results

<!-- GENERATED:BEGIN — everything down to GENERATED:END is printed by
     `python3 scripts/backtest-uv.py --render-doc-table <output>/results.json`;
     regenerate it after a matrix run instead of editing by hand. -->
The complete run finished on **2026-09-15**, using
**macOS-26.6.2-arm64-arm-64bit** and Python **3.9.6**. It tested
socket-patch source commit `310b9042abc8803aa5e302a5902b9f53584f6908`
(`socket-patch 4.0.0`), with binary SHA-256:

```text
79e900f11714ee1575b57e7f494364094ca7d0ff953abddef597b839c5211379
```

**583 installed-byte comparisons** ran, with **0 mismatches**. **240
lock-preservation checks** were recorded — every install attempt against a
patched lock (`--frozen` and `--locked` where the binary provides them, plain
`uv sync` where it does not, `uv run --frozen --script`, `uv pip sync
pylock.toml`, and the project-variant installs), including failed installs whose
lock was left untouched — and **0 changed the lock**. `--frozen` never writes
the lock, so the 101 `--locked` rows are the ones that measure preservation; 101
of them exited 0. The [machine-readable results](uv-compatibility/results.json)
contain all 1324 observations and their command definitions. The [binary
catalog](uv-compatibility/binaries.json) records each uv wheel's public PyPI
source and verified hash.

Each paired result below is **hosted / vendored**. “Pass” means the installed
`urllib3/response.py` matched the published patch; “—” means that uv binary did
not provide the format or command. Requirements include plain and hashed
compilation. PEP 751 covers both standalone locks and exported locks.

| uv | Native grammar | Native H/V | Requirements H/V | Requirements export H/V | Scripts H/V | PEP 751 H/V | Verified installs |
|----|----------------|------------|------------------|-------------------------|-------------|-------------|-------------------|
| 0.0.5 | No native lock | — / — | Pass / rejected path | — / — | — / — | — / — | 2 |
| 0.1.0 | No native lock | — / — | Pass / rejected path | — / — | — / — | — / — | 2 |
| 0.1.23 | No native lock | — / — | Pass / rejected path | — / — | — / — | — / — | 2 |
| 0.1.24 | No native lock | — / — | Pass / Pass | — / — | — / — | — / — | 4 |
| 0.1.45 | `distribution`, v1 | Pass / refused | Pass / Pass | — / — | — / — | — / — | 6 |
| 0.2.0 | `distribution`, v1 | Pass / refused | Pass / Pass | — / — | — / — | — / — | 6 |
| 0.2.5 | `distribution`, v1 | Pass / refused | Pass / Pass | — / — | — / — | — / — | 6 |
| 0.2.6 | `distribution`, v1 | Pass / refused | Pass / Pass | — / — | — / — | — / — | 6 |
| 0.2.17 | `distribution`, v1 | Pass / refused | Pass / Pass | — / — | — / — | — / — | 6 |
| 0.2.18 | `distribution`, v1 | Pass / refused | Pass / Pass | — / — | — / — | — / — | 6 |
| 0.2.34 | `distribution`, v1 | Pass / refused | Pass / Pass | — / — | — / — | — / — | 7 |
| 0.2.35 | `package`, v1 | Pass / Pass¹ | Pass / Pass | — / — | — / — | — / — | 10 |
| 0.2.36 | `package`, v1 | Pass / Pass¹ | Pass / Pass | — / — | — / — | — / — | 10 |
| 0.2.37 | `package`, v1 | Pass / Pass¹ | Pass / Pass | — / — | — / — | — / — | 10 |
| 0.3.0 | `package`, v1 | Pass / Pass¹ | Pass / Pass | — / — | — / — | — / — | 10 |
| 0.3.5 | `package`, v1 | Pass / Pass | Pass / Pass | — / — | — / — | — / — | 10 |
| 0.4.0 | `package`, v1 | Pass / Pass | Pass / Pass | — / — | — / — | — / — | 10 |
| 0.4.1 | `package`, v1 | Pass / Pass | Pass / Pass | — / — | — / — | — / — | 10 |
| 0.4.30 | `package`, v1 | Pass / Pass | Pass / Pass | Pass / Pass | — / — | — / — | 12 |
| 0.5.0 | `package`, v1 | Pass / Pass | Pass / Pass | Pass / Pass | — / — | — / — | 12 |
| 0.5.16 | `package`, v1 | Pass / Pass | Pass / Pass | Pass / Pass | — / — | — / — | 12 |
| 0.5.17 | `package`, v1 | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | — / — | 18 |
| 0.5.31 | `package`, v1 | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | — / — | 18 |
| 0.6.0 | `package`, v1 r1 | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | — / — | 18 |
| 0.6.14 | `package`, v1 r1 | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | — / — | 18 |
| 0.6.15 | `package`, v1 r2 | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | 22 |
| 0.6.17 | `package`, v1 r2 | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | 22 |
| 0.7.0 | `package`, v1 r2 | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | 22 |
| 0.7.22 | `package`, v1 r2 | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | 22 |
| 0.8.0 | `package`, v1 r2 | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | 22 |
| 0.8.3 | `package`, v1 r2 | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | 22 |
| 0.8.4 | `package`, v1 r3 | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | 22 |
| 0.8.24 | `package`, v1 r3 | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | 22 |
| 0.9.0 | `package`, v1 r3 | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | 22 |
| 0.9.30 | `package`, v1 r3 | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | 22 |
| 0.10.0 | `package`, v1 r3 | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | 22 |
| 0.10.12 | `package`, v1 r3 | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | 22 |
| 0.11.0 | `package`, v1 r3 | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | 22 |
| 0.11.33 | `package`, v1 r3 | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | 22 |
| 0.12.0 | `package`, v1 r3 | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | 22 |
| 0.12.15 | `package`, v1 r3 | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | Pass / Pass | 22 |

### Project variants (uv ≥ 0.2.35)

Each `[[package]]`-grammar binary also locks five further project shapes
(`variant-*` cases in the results), scans them in both modes, and installs from
the patched lock with `--frozen`, `--locked` (where available) and a plain `uv
sync`, each into a fresh environment. “Pass” requires the patched bytes from
every executed install and an untouched lock after `--locked`; “Fail: …” names
the installs that missed; “refused” means the CLI reported the shape unsupported
and left the lock unpatched; “—” means the binary cannot lock that shape (no
`[dependency-groups]`, no `[manifest]` constraints, or no `exclude-newer`
setting).

_This results.json predates the project-variant lane; rerun the matrix to populate this table._
<!-- GENERATED:END -->

Nonzero outcomes in this run, and what each one is:

- uv 0.0.5 through 0.1.23 rejected vendored requirements' local wheel path
  syntax (`Unexpected '.', expected '-c', '-e', '-r' or the start of a
  requirement`); 0.1.24 onward accepted it. Both hosted requirements variants
  installed the patch on every binary.
- Native vendoring on every `[[distribution]]`-grammar binary (0.1.45 through
  0.2.34) was refused with `pypi_uv_legacy_lock_unsupported`; hosted native
  installs — in all three shapes: sub-table artifacts (through 0.2.5), inline
  artifacts with string sources (0.2.6–0.2.17), and inline-table sources
  (0.2.18–0.2.34) — and both requirements modes installed the patch.
- ¹ uv 0.2.35, 0.2.36, 0.2.37 and 0.3.0 cannot build the root fixture from an empty
  cache under `--offline` (`setuptools>=40.8.0` was absent). The
  network-enabled retry (`project-vendored-frozen-sync-root-build-networked`)
  installed the patched wheel; the subsequent locked and ordinary installation
  checks also passed.
- Export, script-lock, and PEP 751 commands unavailable in older binaries were
  recorded as unavailable, not installation successes (`uv export` from 0.4.1,
  `uv lock --script` from 0.5.17, PEP 751 compilation from 0.6.15). Some older
  uv binaries accepted an output filename ending in `pylock.toml` but emitted
  requirements text; those results have `formatSupported: false`.
- The 0.4.1 export rows (`project-*-export-*`, exit 2, `unexpected argument
  '--output-file'`) are a harness gap, not a uv boundary: `uv export` exists on
  0.4.1 but its `--output-file` flag only from 0.4.7, and this run passed the
  flag. The harness now reads the export from stdout; on the next run the
  0.4.1 "Requirements export" cell records the real install result (a
  diagnostic run against the fixed harness installed the patched wheel in both
  modes).
- The project-variant table is empty for this run because the lane was added
  afterwards. A diagnostic run of the lane against the same CLI build on uv
  0.12.15 and 0.2.37 found the defects it was written to catch: vendored
  `[tool.uv] dev-dependencies` and duplicate `requires-dist` entries and both
  modes of `[manifest]` constraints failed `uv sync --locked` (`a hash was
  expected but one was not found`), and on 0.2.37 the `[tool.uv]
  dev-dependencies` and transitive fixtures also had a plain `uv sync` reinstall
  the pristine wheel. The full rerun after the fixes replaces this note with
  the table.

## Completed conditional-requirements and refusal checks

The following checks ran on 2026-09-14 with uv `0.12.13`, Python `3.9.6`, the
rebuilt CLI, real PyPI distributions, and the public Socket patch service.
Their [sanitized command evidence](uv-compatibility/conditional-probes.json)
records both the installed hashes and the byte-preservation assertions. These
supplemental probes were captured during implementation; their individual CLI
binary hashes were not recorded, so they are kept separate from the exact-source
matrix above.

| Case | Observed result |
|------|-----------------|
| `urllib3==1.26.18` for Python below 3.10; `urllib3==2.6.3` for Python 3.10 and newer | Only 1.26.18 received a patch. The complete 2.6.3 requirement and original hash continuations remained byte-identical. Fresh hash-verified installation succeeded. |
| The same markers selecting 1.26.18 and 2.0.0, both with published patches | Each version received its own artifact URL and hash. A repeated scan and fresh hash-verified installation succeeded; one override did not replace the other's version. |
| Hashed `urllib3[socks]==1.26.18` with a platform marker | Extras and the marker survived the rewrite; unrelated dependency hashes were preserved. Fresh hash-verified installation succeeded. |
| A PEP 723 script locking both 1.26.18 and 2.0.0 | Hosted and vendored scans reported the competing-version refusal. Both the script and its lock remained byte-identical. |
| A native project locking both 1.26.18 and 2.0.0 | Hosted scan reported the competing-version refusal. Both `pyproject.toml` and `uv.lock` remained byte-identical. |

The requirements inputs were generated with real uv compilation, including:

```sh
uv pip compile requirements.in \
  --universal --python-version 3.9 \
  --generate-hashes --no-strip-markers \
  --output-file requirements.txt
socket-patch scan --mode hosted --json --yes --no-telemetry
uv venv .venv-sync --python /path/to/python3.9
uv pip sync --python .venv-sync/bin/python \
  --require-hashes requirements.txt
```

The extras case also used `--no-strip-extras`. For the selected 1.26.18 patch,
UUID `e828efa5-5c6d-43f3-9909-03f5ac232b98`, the freshly installed
`urllib3/response.py` matched the published patched wheel's SHA-256:

```text
21d9a7810de52973c88d9170f437e98921456bce445ab0618576987478a6a6e4
```

This hash records the patch selected for that run. Production patch ordering
can change; a later run must compare against the artifact it actually selects.
