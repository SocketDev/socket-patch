# Changelog

All notable changes to socket-patch are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-v3.0 entries are concise summaries derived from each tag's commit
history. For full per-release detail, see the
[GitHub releases page](https://github.com/SocketDev/socket-patch/releases).

Add entries under `[Unreleased]`; its `###` headings set the next version's
bump (Breaking/Removed → major, Added/Changed/Deprecated → minor, anything
else → patch). Releases are cut by the release train
([docs/release-train/DESIGN.md](docs/release-train/DESIGN.md)) with
`scripts/release.py`: a release candidate's `[Unreleased]` entries become a
`## [X.Y.Z-rc.N]` section, the rolling `release-sync` PR brings each cut
section and version back to main, and promoting an rc folds its rc sections
into one `## [X.Y.Z]` section. `scripts/release-lint.sh` refuses to release
a version without a non-empty section in this file.

## [Unreleased]

v5 centers the workflow on `scan` (hosted patches), `vex` (OpenVEX attestations),
and `vendor` (committed patched packages), with `list` for inspection. See the
[v5 migration guide](docs/migrating-to-v5.md) before updating existing automation.

### Breaking changes

- `scan` and `get` default to hosted mode. `scan` never prompts, and hosted or
  vendored `get` selects without an interactive menu. Explicit `--mode agent`
  retains in-place patching; `get --save-only` and global targeting select agent
  behavior by default. A mode-less global scan or `scan --prune` does not acquire
  new patches, though `--prune` still cleans up obsolete state.
- Hosted mode writes no ledger. `list`, VEX, and update discovery read the live
  dependency references. `rollback` and `remove` restore upstream registry entries
  rather than replaying saved edits, and refuse where restoration is unavailable
  (including offline operation and binary `bun.lockb`). Legacy hosted ledgers are
  read only for compatibility and removed by full rollback.
- `rollback` restores dependencies and removes patch records and unused artifacts.
  `--preserve-state`, also available on `remove`, keeps local state for reuse.
  Hosted state has no local artifact to preserve.
- Vendored scans and targeted gets are manifest-free. The vendor ledger embeds
  patch records; `repair` no longer reconstructs a missing ledger from lockfiles.
  `vendor` can eject hosted pins when no agent manifest exists. Reverting an
  ejected package restores upstream dependencies.
- Vendored Cargo patches use workspace-root `Cargo.toml` wiring and tagged
  `<version>+socket.<uuid>` versions, visible to `CARGO_PKG_VERSION`. Re-running
  vendoring or repair migrates older config-file wiring and untagged copies.
- `socket.yml` policy now constrains scans. Invalid patch policy fails before
  requests or writes. Discovered test and fixture projects are excluded by
  default; literal project targets skip those defaults. Hosted/vendored PATHs
  outside the repository are rejected.
- Automatic patch selection prefers the highest severity, then the most advisories
  fixed, then publication date. Existing patches change only when the new patch
  outranks them; tier/UUID tie-breaking alone does not trigger replacement.
- `setup`, its publishing helpers, and the PyPI/RubyGems CLI distributions are
  removed. Standalone binaries, Cargo, and npm remain supported; Python and Ruby
  project support is unchanged. Remove old hooks using the migration guide.
- Removed `scan --redirect`, `scan --detached`, mode aliases `host`/`redirect`/
  `vendor`, the unimplemented `--one-off` flags, and the three legacy
  `SOCKET_PATCH_*` environment aliases listed in the migration guide.
  `.socket/packages/` archives are no longer consumed; cleanup removes leftovers.
- `list` on an empty project exits 0; `get` usage errors exit 2. Human help and
  output are grouped by task, with diagnostic codes retained in JSON and verbose
  output. Hosted JSON identifies lockfiles instead of a ledger; rollback's
  `vendored` results contain vendor-owned entries only. See the
  [CLI contract](crates/socket-patch-cli/CLI_CONTRACT.md) for exact schemas.
- VEX requires live hosted/vendored wiring and reports corrupt vendor ledgers.
  Verified agent patches no longer require a `setup` hook for attestation.
- The core crate removes setup-related modules, obsolete public helpers, and the
  unused `DepOverride::berry_zip_url` field. Patch references containing
  `berryZipUrl` still parse.

### Added

- Vendored Maven reactors and Gradle builds, with committed repositories,
  reversible wiring, repair, rollback, and VEX. Reactors use suffixed versions;
  Gradle preserves coordinates and lockfiles, checks artifact hashes, and updates
  existing verification metadata. `vendor --check` audits artifacts and wiring
  offline; `--local-repo` checks Maven cache conflicts and `--maven-config=none`
  selects the fallback file repository. Single-POM vendoring is unchanged.
- `socket.yml` patch policy for paths, ecosystems, packages, severity, and per-run
  limits. `scan --package`, `--min-severity`, `--max-new-patches`, and
  `--no-socket-yml` support targeted and gradual rollout. Already-patched packages
  retain protection when excluded; updates do not spend the new-patch budget.
  Disk scans and the in-memory hosted engine share these rules.
- Manifest-free VEX discovery from hosted and vendored references, including fresh
  checkouts. Product inference covers Go, Composer, Maven, NuGet, and RubyGems in
  addition to existing formats. Embedded VEX supports the same evidence checks.
- vlt support across agent, hosted, and vendored workflows, with native installer
  coverage and explicit version/layout refusals.
- Native binary `bun.lockb` reading and rewriting, alongside text `bun.lock`,
  without invoking Bun or converting binary locks to text.
- Expanded Python lockfile support for uv, Poetry, PDM, and Pipenv, including
  lock-only inventory, supported multi-version/marker shapes, and stale-install
  diagnostics. Unsupported installer formats are refused before writes.
- npm 12 hosted `allow-remote` configuration and dual-lock handling, plus pnpm
  trust-lockfile configuration. Explicit user settings are respected.
- Path targeting on scan and rollback, hosted update detection from lockfiles,
  and configurable API request concurrency.

See [ecosystem support](docs/ecosystems.md) and the
[compatibility guides](docs/testing/README.md) for format boundaries, integrity
limits, and required install commands.

### Fixed

- `scan --vex` in hosted mode no longer attests an npm patch as
  `not_affected` when `package-lock.json` also lists a bundled copy of the
  same `name@version` (`inBundle`, or `bundled` in a v1 lock). npm unpacks
  that copy from its parent's tarball, so it stays unpatched; the run
  already warned `redirect_npm_bundled_instance_skipped` and now leaves the
  patch out of its attestation, like a standalone `vex` run (#325). When a
  `packages` map exists, stale bundled flags in the legacy `dependencies`
  mirror do not suppress an attestation for the actual install tree.
- `vex` no longer attests an npm or Bun patch as `not_affected` while a
  second entry for the same `name@version` in the same lockfile still
  resolves from the registry (for example a workspace member added after
  vendoring). That copy installs unpatched, so the patch is now reported
  as contested. `vendor --check` reports the same lockfile entry as drift
  (#588).
- Global mode (`-g`) finds npm, yarn, pnpm, bun, RubyGems and Composer on
  Windows, where they install as `.cmd` / `.bat` shims, instead of reporting
  an empty scan. The yarn and npm-family global lookups no longer run from the
  scanned project, so a Yarn Berry project's `global` script can't run or pick
  the directory treated as the global install. Composer's global home also
  falls back to `%APPDATA%\Composer` and `$XDG_CONFIG_HOME/composer`.
- Agent-mode PyPI `apply` patches every installed copy of a release, not just
  the first one found. A Pipenv project with both a WORKON_HOME venv and a
  `./.venv`, or a global install with the same release in the user site and a
  system dir, no longer keeps the copy Python imports unpatched while `vex`
  attests it (#529, #501).
- Gem hosted and vendored modes wire only the manifest Bundler loads. A `gems.rb`
  twin or a `BUNDLE_GEMFILE` setting (environment or `.bundle/config`) no longer
  leads to an edit of an ignored `Gemfile` that reports success and attests an
  unpatched gem; unsupported layouts are refused before any write (#341, #390).
- Gem modes read Bundler settings in Bundler's own priority. A `BUNDLE_GEMFILE`
  in `.bundle/config` now outranks the environment variable, so a dual-boot
  project with an exported `BUNDLE_GEMFILE=Gemfile` is no longer wired through
  the `Gemfile` Bundler ignores (#507). The hosted stale-install guard checks
  the committed archive in Bundler's configured cache dir (`cache_path` /
  `BUNDLE_CACHE_PATH`) instead of always `vendor/cache`, so a stale archive
  there now warns and keeps the same run's VEX from attesting it (#483).
  Both settings skip `.bundle/config` under `BUNDLE_IGNORE_CONFIG`, as Bundler
  does.
- **npm dependencies installed from git, a URL or `file:` are no longer
  reported patched.** npm installs such a dependency from the dependent's
  spec (`github:user/repo`, `https://…/x.tgz`, `file:…`) and ignores the
  lock entry's `resolved`, so `npm ci` kept installing the original bytes
  after `scan --mode hosted` or `vendor` rewired the entry and `vex`
  attested it. Both modes now skip such an entry with a loud
  stays-UNPATCHED warning (`redirect_npm_non_registry_entry_skipped` /
  `vendor_non_registry_entry_skipped`; vendoring refuses with
  `vendor_lock_entry_not_rewritable` when no registry copy is left), and
  `vex` attests nothing for a `name@version` while such a copy is in the
  lock (#326). A dependency the project's `overrides` send back to a
  registry version is not one of these: npm installs the override's
  registry release, so hosted and vendored modes patch it again, and
  `vex` attests it (#490).
- **Agent mode finds Poetry's virtualenv in more setups.** Three cases
  missed the virtualenv Poetry installed into. Each fell back to the
  wrong interpreter, skipped the patch as `package_not_installed` and
  still exited 0:
  - a nameless `package-mode = false` project (Poetry names its env
    `non-package-mode-…`);
  - a Poetry 2 project with both `[project] name` and
    `[tool.poetry] name` (Poetry uses `[project] name`);
  - an explicit `virtualenvs.in-project = false` next to a stray `./.venv`.

  Every Windows project missed it too, because the cwd hash included the
  `\\?\` prefix that path canonicalization adds (#327, #329).
- Hosted Maven warns `redirect_maven_trusted_checksums_unenforced` when
  `.mvn/wrapper/maven-wrapper.properties` pins a Maven older than 3.9.4. Maven
  3.9.0–3.9.3 never enforce the Trusted Checksums pin that hosted mode writes;
  the 4.0.0 notes and docs wrongly said every 3.9 release does. The version
  suffix still fails closed. CI runs the real-Maven hosted capstone on 3.9.3 and
  3.9.4 (#258).
- Patch application, reversal, and cleanup handle missing files, release variants,
  corrupt state, newer ledger formats, and unsafe manifest paths without silently
  dropping protection. File ownership restoration failures produce warnings.
- Hosted Cargo handles v1 locks, CRLF files, and repeated declarations, and refuses
  transitive dependencies its registry pin cannot reach. Vendored Cargo preserves
  multiple versions and warns about old-toolchain limitations.
- Go preserves user-authored replacements, handles `+incompatible` versions,
  restores checksums, and unwinds hosted references during vendoring. Registry
  fetches honor `GOPROXY` and private-module settings.
- Yarn Berry preserves supported line endings and checksum spellings. Mode
  preflights, including Bun's, run before discarding existing protection.
- Yarn Berry hosted references no longer send npm registry credentials to the
  patch server. The old `npm:` locator made yarn attach `npmAuthToken` /
  `YARN_NPM_AUTH_TOKEN` to scoped packages (and to every package under
  `npmAlwaysAuth`). Hosted mode now pins the way yarn does for a root
  `resolutions` entry: `package.json` routes the locked descriptor to the
  hosted tarball and the lock entry is keyed by it, which also passes yarn's
  hardened mode (on by default for public pull request CI). A user-authored
  `resolutions` entry for the package is never overwritten. Locks pinned by
  earlier releases are re-pinned on the next hosted `scan`.
- Composer hosted references remove upstream source fallbacks and mirrors;
  RubyGems hosted locks preserve source order; NuGet edits use the active config
  and survive `<clear />` entries.
- Python rewrites preserve supported markers, groups, extras, source metadata, and
  integrity pins. Relocks, out-of-tree environments, and lock-only VEX are handled
  consistently with each installer's supported behavior.
- Hosted Pipenv scans read the `Pipfile`, so a conflicting `Pipfile.lock` entry
  refuses the patch project-wide instead of half-redirecting a sibling
  `requirements.txt` (#333).
- Vendoring reuses valid committed artifacts during service outages. Updates do
  not build from a previous patch's modified bytes. Verified service artifacts
  keep their identity; integrity failures do not fall through to a local rebuild.
  Repair rebuilds against recorded pins and reports unavailable inputs.
- VEX no longer attests an npm package that also ships a bundled, unpatched
  copy of the same `name@version` (`inBundle: true`, or v1 `bundled: true`).
  npm unpacks that copy from the parent's tarball, so no rewire reaches it; the
  reference is now reported `patched_ref_unattributable`, naming the bundled
  copy, in hosted and vendored mode (#325).
- API throttling uses bounded retries, failed queries appear in JSON diagnostics,
  and hosted reference resolution handles batches larger than 500 patches.
- Transient apply locks are removed on normal command exit; no-op scans and full
  reversal avoid leaving unused `.socket/` state. Terminal output, telemetry
  timeouts, and update-check handling are more consistent.
- Agent mode finds transitive npm packages in npm's linked store
  (`install-strategy=linked`, `node_modules/.store`) and in a relocated pnpm
  `virtualStoreDir`, instead of reporting them `package_not_installed` (#359,
  #362). A store outside the project, such as pnpm's global virtual store, is
  shared with other projects and is still not patched in place.
- Agent mode and `vex` find packages installed under pnpm's `modulesDir`
  (`modulesDir:` in `pnpm-workspace.yaml`, or `modules-dir` in `.npmrc`).
  From pnpm 10.12 the virtual store moves there (`<modulesDir>/.pnpm`), so
  `apply` exited 0 with the package unpatched as "not installed", and
  hosted `vex` attested `not_affected` over the unpatched install. Hosted
  `vex` also no longer attests a pinned npm package the crawler cannot see
  because pnpm keeps the installed store outside the project (#661, #696).
- npm locks keep their own layout when edited. `scan --mode hosted`,
  `scan --mode vendored`, `rollback` and `vendor --revert`
  re-serialized `package-lock.json` / `npm-shrinkwrap.json` with LF line
  endings (and, in hosted mode, a fixed 2-space indent), so a CRLF or
  tab-indented lock got a whole-file diff and the undo did not restore its
  bytes. A lock with a UTF-8 BOM, which npm installs from, was skipped as
  unparseable (hosted) or refused as `vendor_lockfile_version_unsupported`
  (vendored). The lock now keeps its BOM, indent and line endings, and the
  undo is byte-exact (#324).
- Agent mode no longer patches other projects through a store they share.
  PDM 2.0–2.12 with `install.cache` and `cache_method = symlink` links
  `site-packages/<pkg>` into its package cache, and pnpm's global virtual
  store (`enableGlobalVirtualStore`) links `node_modules/<dep>` into
  `<store>/links`. `apply` (also `-g`) wrote the patch into that shared
  directory, so every project using it was patched, and a `rollback` in one
  project silently unpatched the rest. `apply` and `rollback` now fail on
  such a package, naming the store and how to get a private copy
  (#332, #361).
- `vendor` under `--global` / `--global-prefix` (or `SOCKET_GLOBAL` /
  `SOCKET_GLOBAL_PREFIX`) is now a usage error (exit 2,
  `global_scope_unsupported`), like `scan` and `get` with `--mode vendored`.
  Run inside a project, `vendor -g` vendored the manifest's records into that
  project and rewired its lockfile, and `vendor --revert -g` unwound the
  project's vendoring, so its next frozen install was silently unpatched.
  Global installs have no project lockfile to vendor into (#498).
- Patch API requests (`scan`, `get`, `apply` and `vex` lookups, and blob and
  diff downloads) no longer hang forever on a stalled proxy, load balancer or
  half-open connection. A connect now fails after 10 s, and a connection that
  sends nothing for 60 s fails as a network error. Downloads that keep
  streaming are not cut off (#570).
- Patch blob and diff downloads stream straight to the `.socket` cache instead
  of being held in memory whole first, so a large patch artifact no longer
  costs its full size in RAM during `apply`, `get`, `repair` or `rollback`
  (#571).

### Maintenance

- Shared format models, project snapshots, ledger views, and a vendored backend
  consolidate discovery and lifecycle handling. Grouped writes and bounded
  concurrency reduce repeated disk and network work.
- CI reuses compiled test binaries and splits broader compatibility matrices into
  dedicated jobs. Release publishing uses separate Cargo and npm workflows.
- Documentation now separates usage, configuration, migration, compatibility, and
  development guidance; completed plans, prototype research, and historical run
  reports are removed from the maintained docs.

## [4.0.0] — 2026-08-20

v4.0 is the three-modes release. What began as an agent-style tool that
patches installed packages in place now offers three deployment modes,
selected with `scan --mode <agent|vendored|hosted>` (each mode's detailed
entries follow below; per-ecosystem mechanics live in `docs/ecosystems.md`):

- **Agent mode** (the default, and the original behavior): `apply` patches
  installed packages in place on the current machine — `node_modules/`,
  site-packages, the cargo registry cache, and so on — tracked in the local
  `.socket/` manifest and re-applied after installs by the hooks `setup`
  configures. Requires socket-patch (and Socket API access, or pre-fetched
  blobs) on every machine that installs dependencies.

- **Vendored mode** (`vendor`, or `scan --mode vendored`): ejects each
  patched package into a committed
  `.socket/vendor/<ecosystem>/<patch-uuid>/<artifact>` and rewires the
  ecosystem's lockfile so the project consumes the vendored copy. After
  committing, a fresh checkout builds with the patched dependency on
  machines with no socket-patch installed and no Socket API access — fully
  offline/airgap-friendly, and the strictest install flags (`npm ci`,
  `--frozen-lockfile`, `--locked`, `--deploy`, …) verify the vendored
  artifact like any other. A committed ledger records the verbatim original
  lockfile fragments, so `vendor --revert` restores them byte-exactly.
  Covered in v4.0: the whole npm family (npm, yarn classic, yarn berry
  node-modules, pnpm, bun), pypi (uv, requirements, poetry, pdm, pipenv),
  cargo, go, composer, gem, maven, and nuget.

- **Hosted mode** (`scan --mode hosted`, new in v4.0): rewrites lockfiles /
  registry configs so ONLY the patched dependencies resolve to
  Socket-hosted, integrity-pinned artifacts on patch.socket.dev — no
  artifact bytes land in the repo and no CI changes are needed. The package
  manager's own integrity checking pins the patched bytes (tamper fails the
  native install), and re-runs are idempotent. Covered in v4.0: the npm
  family (package-lock/shrinkwrap, pnpm — including Rush monorepos — yarn
  classic, yarn berry, bun), pypi (requirements, uv), cargo, composer, gem,
  nuget, maven (fail-closed version suffixing + Trusted Checksums), and
  golang for references carrying a `goproxy` registry override (free tier;
  otherwise Go stays vendored — see the documented NO-GO analysis).

All three modes feed VEX attestation, with a provenance marker per mode:
plain (agent), `(vendored)`, and `(redirected)` (hosted).

### Removed (BREAKING)

- **The `unlock` subcommand.** Folded into `repair`, which now deletes the
  leftover `<.socket>/apply.lock` file as its final housekeeping step (skipped
  under `--dry-run`, refused with `lock_held` while another live socket-patch
  process holds the lock). Rationale: a leftover lock file from a crashed run
  never blocked acquisition in the first place — the OS releases a dead
  holder's advisory lock along with its file handle — so `unlock`'s inspect
  path had no recovery scenario, and its `--release` file deletion is now
  automatic. Migration: `unlock --release` → `repair`; the probe-style
  "is anything holding the lock?" check → run the mutating command (optionally
  with `--lock-timeout`) and branch on `errorCode: lock_held`.
  `SOCKET_UNLOCK_RELEASE` is gone with the subcommand, and the
  `patch_unlocked` / `patch_unlock_failed` telemetry events are retired.
- **The global `--break-lock` flag and `SOCKET_BREAK_LOCK` env var.** It never
  stole a live holder's lock (deliberately, since that defeats mutual
  exclusion) and a stale file never contends, so all it did was emit a
  `lock_broken` audit event for a reclaim that plain acquisition performs
  anyway. The `lock_broken` warning event and rollback's `warnings[]`
  `lock_broken` entry are no longer emitted (`warnings` stays present, now
  always empty). The `lock_held` stderr hint now advises waiting /
  `--lock-timeout` instead of pointing at the removed commands.

### Changed (BREAKING)

- **`--help` command order** is now workflow-first: `scan`, `apply`, `vex`,
  `vendor`, `setup`, then `rollback`, `get`, `list`, `remove`, `repair`.

### Added

- **`get --mode <hosted|vendored|agent>` — per-advisory hosted/vendored
  patching.** `get` (fetch/apply a single patch by CVE/GHSA id, patch UUID,
  or package name) now honors the same mode selector as `scan`: hosted
  rewrites lockfiles for just the selected patches through scan's redirect
  engine verbatim; vendored routes through scan's vendor step with scan's
  save-only download posture. CVE/GHSA fan-outs are narrowed to versions
  actually installed (disk ∪ manifest, plus the lockfile inventory and
  vendor ledger in hosted/vendored modes); when narrowing leaves nothing,
  the new additive `not_installed` status reports it at exit 0. Exempt from
  narrowing: UUID ids, exact-versioned purls, `--save-only`,
  `--all-releases`, and the package-name path.
- **Hosted mode for Go (free tier).** `scan --mode hosted` now redirects
  golang dependencies when the reference carries a `goproxy` registry
  override: a fork-style
  `replace <mod> <ver> => patch.socket.dev/gopatch/<uuid> <ver>-socketpatch.<n>`
  in `go.mod` plus the socket module's two `h1:` lines in `go.sum` (and the
  replaced original's lines pruned — the tidy-stable state). Day-2 machines
  need no configuration: go consults the checksum database only for modules
  absent from `go.sum`, so the committed pair is the whole redirect —
  validated end-to-end in `e2e_golang_hosted_build.rs` (fresh caches, bogus
  `GOSUMDB` tripwire, `go mod tidy` byte-level no-op, tampered-hash
  `SECURITY ERROR`). Fails closed (per-dep `redirect_golang_*` warnings, no
  partial writes) on missing hashes, an out-of-namespace module path, a
  require-version mismatch, or a user-authored replace conflict; references
  without the override keep the historical `redirect_golang_unsupported`
  warning (paid tier stays vendored — see `docs/ecosystems.md#go-directory-replaces-and-gosum`).
  Wire schema gains `integrity.goModH1` and
  `registryOverride.identifiers.goModuleVersion` (additive). Requires
  server-side publication of the grant-free `gopatch` artifact flavor —
  production publishes no golang hosted modules yet, so behavior is unchanged
  until it does.
- **Version-bump automation + release-readiness gate.**
  `scripts/bump-version.sh <X.Y.Z> --pr` performs the whole bump chore —
  stamps every packaging site via `version-sync.sh`, rolls `[Unreleased]`
  into a dated `## [X.Y.Z]` CHANGELOG section, and opens the `release/vX.Y.Z`
  PR (also dispatchable from the Actions tab as the **Version Bump**
  workflow). A new `release-readiness` CI job runs `scripts/release-lint.sh`
  on every PR: version-coherence always (version-sync must be a no-op, so a
  hand-edited version in any one packaging site fails CI), plus the full
  gate — non-empty CHANGELOG section, no pre-existing tag — on PRs that bump
  the workspace version. The `Release` workflow's `version` job now runs the
  same script, so the publish gate and the PR gate cannot drift. Playbook:
  docs/releasing.md.
- **`socket-patch --update` — self-update.** Downloads the release for the
  compiled target from GitHub Releases, verifies it against the published
  `SHA256SUMS` before extraction, sanity-execs the staged binary, and
  atomically swaps it in place (Windows uses the rename-dance via
  `self-replace`; a setuid/setgid install is refused). `--update 3.4.0`
  (or `SOCKET_PATCH_VERSION`) pins a version, up or down; bare `--update`
  never downgrades; `--force` reinstalls. `--dry-run` is a check-only
  probe (zero downloads, `updateAvailable` in the `--json` details).
  Package-manager-managed installs (npm, pip, cargo, the gem launcher
  cache, Homebrew) are detected from the canonicalized executable
  path and refused with that manager's own upgrade command; `--force`
  overrides. `--offline` refuses up front and `--force` cannot bypass it.
  Concurrent updates are single-flighted via an advisory lock; every
  failure path leaves the installed binary untouched.
- **Passive update notice.** Interactive runs mention a newer release at
  most once a day, on stderr only, after the command's own output:
  suppressed under `--json`/`--silent`/`--offline`, in CI, when stderr is
  not a terminal, or with `SOCKET_NO_UPDATE_CHECK=1` (suppressed means
  zero network I/O). The background check can never alter a command's
  exit code, stdout, or add more than ~500 ms; state corruption degrades
  to "never checked". An explicit `--update` refreshes the notice's cache.
- **`shellcheck scripts/install.sh` in CI** (and a fix for the SC2144
  glob-with-`-e` musl-loader probe it found).
- **`socket login` now configures socket-patch.** The JS Socket CLI's
  persisted config (`<data dir>/socket/settings/config.json`) is read —
  never written — as a fallback layer below env vars for `apiToken`,
  `defaultOrg`, and `apiBaseUrl`: precedence per key is CLI flag > env var
  > socket-cli config > built-in default. Four `SOCKET_CLI_*` env names
  are accepted as silent peer aliases (`SOCKET_CLI_API_TOKEN`,
  `SOCKET_CLI_ORG_SLUG`, `SOCKET_CLI_API_BASE_URL`,
  `SOCKET_CLI_NO_API_TOKEN`); the canonical `SOCKET_*` names win. Two new
  env-only toggles: `SOCKET_NO_API_TOKEN` ignores ambient tokens (env +
  config; an explicit `--api-token` still authenticates) and
  `SOCKET_NO_CONFIG` disables the config layer. A corrupt config file
  warns once on stderr and is ignored; `--json` stdout is unaffected. The
  telemetry endpoint now resolves the API base through the same chain as
  client construction, so a config-supplied `apiBaseUrl` applies to both.
  Design notes: `docs/configuration.md`.


- **Hosted patch mode: `scan --mode hosted` (a.k.a. the hidden `--redirect`).**
  The third patch-application mode: instead of applying in place (agent) or
  committing artifacts (vendored), `scan` rewrites lockfiles / registry
  configs so ONLY the patched dependencies resolve to Socket-hosted,
  integrity-pinned packages on patch.socket.dev — no artifact bytes land in
  the repo and no CI changes are needed. Per ecosystem: npm rewrites
  `package-lock.json`/`npm-shrinkwrap.json` `resolved`+`integrity` (v2 legacy
  `dependencies` mirror included), `pnpm-lock.yaml` inline resolutions, and
  yarn classic `resolved`/`integrity` blocks; pypi rewrites `requirements.txt`
  pins to `name @ <url> --hash=sha256:…` (pip-compile continuation lines are
  refused rather than corrupted) and `uv.lock` wheel entries; cargo defines a
  per-patch sparse registry in `.cargo/config.toml` plus `Cargo.toml`
  `registry =` keys and Cargo.lock `source`/`checksum` surgery; composer
  rewrites the lock entry's `dist` url/shasum; nuget adds a `nuget.config`
  source + `packageSourceMapping` and repins `packages.lock.json`
  `contentHash`; gem adds a per-dep `source` block + a `CHECKSUMS` pin
  (bundler ≥ 2.6). A dep counts as redirected only when its hosted URL (or
  per-dep registry index) actually landed in a project file; re-runs are
  idempotent (zero new edits over already-rewritten output). The Rust
  rewriters are held byte-identical to the depscan backend's TS twins (the
  GitHub-app hosted PR flow) by shared golden fixtures under
  `tests/fixtures/redirect/`. JSON output gains a `redirect` sub-object with
  `mode: "hosted"`, `redirected`, `rewrittenFiles`, `skipped`, `warnings`.
- **`scan --mode <hosted|vendored|agent>`: the documented mode selector.** One
  value-enum flag replaces the boolean spellings (`--redirect` == hosted,
  `--vendor` == vendored, `--apply`/`--sync` == agent), which remain supported
  as aliases. Combining `--mode` with a boolean of a DIFFERENT mode is a
  usage error (exit 2); the same mode spelled both ways is accepted, and
  `--detached` now requires vendored mode in either spelling.
- **VEX support for hosted mode: the `(redirected)` provenance marker + the
  redirect ledger.** `scan --mode hosted` persists its recorded file edits and
  the full patch records (file hashes + vulnerabilities) into
  `.socket/vendor/redirect-state.json` (merge-on-rewrite, append-only edits —
  the pre-redirect originals a future revert needs are never clobbered).
  Redirected patches carry the impact-statement marker "Patched via Socket
  patch `<uuid>` (redirected)", completing the provenance trio (plain =
  agent, `(vendored)`, `(redirected)`). In-run `scan --mode hosted --vex`
  attests confirmed redirects from the ledger WITHOUT hash verification (the
  bytes are fetched at install time; the JSON `vex` summary carries
  `verified: false`), while a post-install `socket-patch vex` reads the ledger
  back and hash-verifies the redirected patches against the installed tree.
  A confirmed redirect whose record fetch failed surfaces a
  `record_fetch_failed` warning (the patch is missing from VEX until a
  re-run).
- **NuGet + Maven vendor backends (`vendor` / `scan --mode vendored`).**
  NuGet: the uuid dir is a committed *folder feed* holding a deterministically
  rebuilt `.nupkg` (embedded signature dropped; unsigned is accepted under
  NuGet's default validation), wired via a `nuget.config` source +
  `packageSourceMapping` and a `packages.lock.json` `contentHash` repin —
  `dotnet restore --locked-mode` then fails NU1403 on tamper. Maven: the uuid
  dir is a committed *maven2 `file://` repository* (rebuilt `.jar` + the
  verbatim upstream pom so transitives survive + `.sha1` sidecars), wired via
  a `pom.xml` `<repository>` with `checksumPolicy=fail`; multi-module
  aggregator poms (`vendor_maven_multimodule_unsupported`) and gradle-only
  projects (`vendor_gradle_unsupported`) are refused fail-closed, and the
  always-on `vendor_maven_local_cache_shadow` advisory carries the
  `mvn dependency:purge-local-repository` one-liner (a warm `~/.m2` copy
  silently shadows any repository). Both are proven by docker capstones
  against the real .NET SDK / Apache Maven (cold-cache, `--network none`,
  RED + TAMPER probes). `nuget` and `maven` are now DEFAULT compile features;
  the `SOCKET_EXPERIMENTAL_NUGET` / `SOCKET_EXPERIMENTAL_MAVEN` runtime
  opt-ins that briefly gated in-place agent apply were retired later in this
  cycle (see the "promoted to fully available" entry under Changed). The vendored
  path convention + uuid recovery rule now covers `nuget` and `maven` dirs,
  and `--vendor-source` prebuilt downloads cover nuget.
- **Maven hosted rewriter (pom projects) — fail-closed version suffixing +
  Trusted Checksums.** Hosted mode's maven leg pins the patched jar the only
  way a lockfile-less ecosystem can: the serve route exposes the patch under a
  Socket-only `<version>-socket.<hex8>` suffix (existing ONLY on the injected
  `socket-patch-<uuid>` repository), and the rewriter pins that version
  explicitly — it rewrites the literal `<version>`, or (for a transitive /
  managed dependency with no literal version) adds a `<dependencyManagement>`
  entry — alongside the `<repository>` insert (releases enabled,
  `checksumPolicy=fail`, snapshots disabled). An outage or tamper on the Socket
  repo then HARD-FAILS the build: the suffixed version resolves nowhere else,
  so there is no silent fall-through to Central (the base version 404s). A
  `${property}` version is refused (`redirect_maven_dep_unpinned` — a literal
  edit would break the reference and a depMgmt pin could strand sibling
  artifacts); a literal version matching neither the base nor the suffixed
  value is skipped (`redirect_maven_dep_version_mismatch`); a non-jar `<type>`
  is skipped (`redirect_maven_unsupported_packaging`). When the serve route
  supplies both the jar and pom sha256, the rewriter also emits Maven 3.9+
  Trusted Checksums files — `.mvn/maven.config` resolver args (`originAware=false`,
  `failIfMissing=false`) + `.mvn/checksums/checksums.sha256` entries pinning
  both artifacts under the suffixed version's local-repo path, merging into any
  pre-existing user config / checksum set (a conflicting value is never
  overridden — `redirect_maven_trusted_checksums_conflict`). The `.mvn/*` files
  are silently inert below Maven 3.9 (the version suffixing is still fail-closed
  on its own); on 3.9.0–3.9.8 a mismatch is enforced but reported unclearly
  (readability fixed in 3.9.9, MNG-8182). When the upstream pom is unavailable /
  unsuffixable the rewriter falls back to the legacy same-GAV repository
  injection with a `redirect_maven_same_gav_fallback` warning (NOT fail-closed:
  a Socket-repo failure falls back to the unpatched artifact). Gradle build
  scripts are never edited: a present `build.gradle*` / `settings.gradle*`
  emits a paste-able `exclusiveContent` snippet carrying the suffixed version
  (`redirect_gradle_manual_snippet`) plus a reminder to bump the dependency
  declaration — fail-closed by repository exclusivity.
- **Hosted mode now rewrites yarn-berry and bun lockfiles.** The hosted npm
  family gains two flavors beyond package-lock / pnpm / yarn-classic. **yarn
  berry** (`__metadata:` v2+ lock): the rewriter edits ONLY the lock entry —
  `resolution:` gains yarn's own `::__archiveUrl=<encodeURIComponent(url)>`
  binding and `checksum:` becomes the precomputed `yarnBerry10c0` cache-zip
  sha512 — leaving the descriptor key and `package.json` untouched, so `yarn
  install --immutable --check-cache` passes and tamper fails YN0018. Whole-file
  gates refuse a `cacheKey ≠ 10c0` or a `.yarnrc.yml compressionLevel ≠ 0`
  (`redirect_yarn_berry_cache_unsupported`) — no offline-reproducible checksum.
  Validated e2e against real `corepack yarn@4.12.0` on the node-modules linker;
  PnP is not exercised for hosted (the lock rewrite fires, but PnP's
  `.yarn/cache` resolution is untested). **bun** (text `bun.lock` v1): the
  packages-entry registry 4-tuple `["name@ver","<reg>",{deps},"sha512-…"]` is
  rewritten to a URL 3-tuple `["name@<url>",{deps},"sha512-…"]`, fail-closed on
  any grammar deviation; `bun install --frozen-lockfile` then installs the
  hosted bytes and tamper fails the integrity check. A binary `bun.lockb` with
  no text lock is auto-migrated first via the user's own `bun install
  --save-text-lockfile --frozen-lockfile --lockfile-only` (deletes `bun.lockb`,
  recorded as a `removed` ledger edit, offline, fails closed;
  `redirect_bun_lockb_would_migrate` on `--dry-run`,
  `redirect_bun_lockb_unsupported` if the migration is unavailable). The Rust
  rewriters are byte-identical to the depscan backend's TS twins via shared
  golden fixtures.
- **Hosted mode supports Rush monorepos.** A Rush repo has no root
  `package.json`/lockfile pair — its pnpm source-of-truth lock lives at
  `common/config/rush/pnpm-lock.yaml` (plus one per subspace under
  `common/config/subspaces/<name>/`). `scan --mode hosted` discovers those
  locks when `rush.json` is present and repoints them in place (the pnpm
  rewriter is now basename-generalized, so nested locks rewrite path-generically).
  Editing a Rush lock outside `rush update` desyncs the `pnpmShrinkwrapHash` in
  `common/config/rush/repo-state.json`, so a `redirect_rush_repo_state_stale`
  warning fires when a lock was touched and that file exists — `rush install`
  fails under `preventManualShrinkwrapChanges` until `rush update` refreshes it,
  but the redirect survives the refresh (pnpm keeps locked resolutions for
  unchanged specifiers). Agent mode already works through Rush's generated
  project symlink farm; vendored mode is refused (`vendor_rush_unsupported`)
  because `rush install` copies the lock into `common/temp`, so vendor's
  relative `file:` specs can't survive — the refusal routes to hosted mode.
- **pnpm hosted rewriter generalized to nested lockfiles.** The
  `pnpm-lock.yaml` rewriter now matches any `pnpm-lock.yaml` at the project
  root OR at any nested path (`*/pnpm-lock.yaml`), so Rush subspace locks and
  other nested-lock layouts are rewritten in place under their repo-relative
  keys. Write-back and confirmed-redirect gating are path-generic.
- **Golang hosted mode is a documented NO-GO.** Hosted redirect for Go is
  deliberately unsupported — sumdb hard-fails the patched pseudo-version on
  every day-2 machine and the only escapes are uncommittable machine-local
  config; Go's module-path identity would force per-grant artifacts against
  the build-once converter; and the default `GOPROXY` chain would leak
  licensed bytes / tokened URLs to the public mirror. The full analysis lives
  in `docs/ecosystems.md#go-directory-replaces-and-gosum`; both the CLI rewriter and the
  depscan backend twin emit `redirect_golang_unsupported` naming the remedy
  (use vendored mode, which gives Go everything hosted promises elsewhere).
  The one sanctioned exception — an ephemeral-CI GOPROXY recipe — is
  documentation-only and never written into a repository.

- **`vendor` now supports every major npm and pypi package manager.** The npm
  ecosystem gained four lockfile flavors beyond `package-lock.json` — yarn
  classic (`yarn.lock` v1), yarn berry with the node-modules linker
  (`resolutions` + a cache-zip `10c0` checksum reproduced offline from the
  vendored tarball), pnpm (`pnpm.overrides` + `pnpm-lock.yaml` surgery, pnpm 9
  & 10), and bun (`bun.lock`) — all sharing the one vendored tarball and
  selected by a content-sniffing probe (yarn-berry PnP and bun's binary
  `bun.lockb` are refused with pointers to the native flow). The pypi
  ecosystem gained poetry, pdm, and pipenv (lock-only `[[package]]` / entry
  splices, like the existing uv/requirements flavors). Every lockfile
  checksum/reference field for a vendored package is now recomputed
  coherently (the v2 "update checksums and references" directive); the gem
  backend handles bundler ≥ 2.6's optional `CHECKSUMS` section; composer's
  `dist.reference` carries the patch UUID into `installed.json`. Each flavor
  has a real-package-manager build-proof capstone (fresh-checkout, cold-cache,
  strictest-install — `--frozen`/`--immutable`/`--deploy`/`--locked` — with
  byte-identical revert). `vendor --force`/`--revert` accept empty env vars
  (`SOCKET_FORCE=`) as false, matching the global-flag contract.

- **New `vendor` subcommand: committable vendoring of patched dependencies.**
  Where `apply` patches installed packages in place (machine-local state),
  `socket-patch vendor` ejects each patched package into a committed
  `.socket/vendor/<ecosystem>/<patch-uuid>/<artifact>` and rewires the
  ecosystem's lockfile so the project consumes the vendored copy — after
  committing, a fresh checkout builds with the patched dependency on machines
  with no socket-patch installed and no Socket API access. Per ecosystem
  (each mechanism validated against the real package manager): npm rewrites
  `package-lock.json` only (deterministic patched tarball, recomputed
  integrity, `npm ci`-verified); cargo writes a `[patch.crates-io]` entry in
  `.cargo/config.toml` plus surgical Cargo.lock edits so `cargo build
  --locked --offline` works; golang reuses the `replace`-directive engine
  pointed at the vendor tree; composer rewrites the lock entry to a
  `dist: path` copy; gem edits the Gemfile + Gemfile.lock pair in bundler's
  canonical form; pypi rebuilds a valid wheel (regenerated RECORD) wired
  through uv's `pyproject.toml`/`uv.lock` pair (uv-first) or
  requirements.txt (`pip` / `uv pip`). The patch UUID is recoverable from the
  lockfile path string alone (a documented convention for external tools), a
  committed `.socket/vendor/state.json` ledger records the verbatim original
  lockfile fragments, and `vendor --revert` restores them byte-exactly.
  `vendor --vex` mirrors `apply --vex`; VEX generation attests vendored
  patches by hashing the committed artifacts, and `apply` yields ownership of
  vendored packages (`vendored` skip reason).


- **Cargo support (`cargo` is now a default feature).** `apply` patches a Rust
  dependency **in place** wherever the crawler finds it — the project `vendor/`
  directory or the shared `$CARGO_HOME` registry cache — rewriting the crate's
  `.cargo-checksum.json` sidecar so `cargo build` accepts the modified files.
  `rollback` restores the original bytes from the `beforeHash` blobs, like
  npm/PyPI/gem. `cargo` ships on by default (alongside the always-on npm + PyPI
  + Ruby gems support), so released binaries and a plain `cargo install
  socket-patch-cli` patch Rust dependencies out of the box;
  `maven`/`composer`/`nuget`/`deno` remain opt-in.
- **Project-local Go `replace`-redirect backend (`golang`, default feature).**
  The Go module cache is shared, read-only and checksum-verified, so in-place
  patching would fail `go.sum` at build time. Instead `apply` writes a
  project-local patched **copy** under `.socket/go-patches/<module>@<version>/`
  and a managed `replace` directive in the project `go.mod`, so the patch is
  project-scoped and the cache stays pristine for sibling projects. `rollback`
  cleanly drops the `replace` directive + copy. `apply --check` is a read-only,
  lock-free, offline auditor that verifies the committed redirects match the
  manifest, exiting non-zero on drift (for CI / GitHub-App use).
- **Inline OpenVEX generation on `apply` and `scan` via `--vex <path>`.** A
  single successful `apply`/`scan` can now both patch and emit the OpenVEX
  0.2.0 attestation, instead of requiring a separate `socket-patch vex` step.
  The `--vex-product` / `--vex-no-verify` / `--vex-doc-id` / `--vex-compact`
  flags mirror the standalone `vex` knobs (and reuse the `SOCKET_VEX_*` env
  vars). The document is always written to the given path (never stdout, so it
  never races `--json`), built from the post-run manifest and verified against
  on-disk state. JSON output gains a top-level `vex` summary
  (`{ path, statements, format }`). A requested-but-failed VEX makes the
  command exit non-zero even when the apply/scan itself succeeded, surfacing a
  stable error code in the envelope.

### Changed

- **`install.sh` can install without reaching github.com.** New
  `SOCKET_PATCH_BASE_URL` points the archive downloads at any releases base that
  answers GitHub's two asset paths — notably
  `https://install.socket.dev/patch/SocketDev/socket-patch/releases`, which relays them
  from the GitHub release, so one URL template covers either origin. A new
  release needs no publish for this: the origin resolves "latest" per request.
  `socket-patch --update` can use the same host today through the
  `SOCKET_UPDATE_BASE_URL` override it already has. Also new:
  `SOCKET_PATCH_INSTALL_DIR` to choose the install directory explicitly instead
  of taking `/usr/local/bin` or `~/.local/bin`. The default download origin is
  still GitHub — see `docs/installer-hosting.md`.

- **The documented one-liner installs from `https://install.socket.dev/patch`.**
  The previous URL was `raw.githubusercontent.com`, which asks users to trust a
  third-party CDN for a script they pipe into a shell and is the first URL a
  locked-down egress policy blocks. The hosted copy is byte-for-byte
  `scripts/install.sh`, with its SHA-256 published at
  `install.socket.dev/patch.sha256`; the GitHub raw URL keeps working and serves
  the same bytes. Binaries are still downloaded from the GitHub release and
  verified against its `SHA256SUMS` — the trust model is unchanged, only the
  script's origin moved. New: `docs/installer-hosting.md` (how the copy is
  published), a CI step that runs the installer end to end instead of only
  linting it, and an `installer-drift` workflow that checks the hosted copy
  against this repository weekly.

- **Maven and NuGet promoted to fully available — the
  `SOCKET_EXPERIMENTAL_MAVEN` / `SOCKET_EXPERIMENTAL_NUGET` runtime gates
  are retired.** Every flow (`scan` in all modes, `apply`, `get`,
  `rollback`, `vendor`, `repair`, `vex`, `setup`) now discovers and
  patches installed Maven and NuGet packages unconditionally; the
  "N patch(es) skipped — support is experimental" warnings are gone, and
  the previously `#[ignore]`d maven/nuget dispatch e2e tests now gate CI.
  Setting the old env vars is harmless but does nothing. Behavior notes:
  a default `scan` now walks the local Maven repository (`~/.m2` /
  `MAVEN_REPO_LOCAL`) and the NuGet caches, and `scan --prune`/`--sync`
  now judges maven/nuget manifest entries like any other ecosystem's
  (previously they were exempt from pruning while the gate was closed).
  The in-place sidecar caveat is unchanged and now documented per mode in
  `docs/ecosystems.md`: agent-mode patching leaves Maven's
  `.jar.sha1`/`.jar.md5` stale and NuGet's fixup deletes
  `.nupkg.metadata` + advises on `.nupkg.sha512`; the vendored/hosted
  modes never touch the caches.

- **Release workflow consolidated into a single `release.yml`.** One
  dispatch now publishes every package — crates.io, npm, PyPI, and
  RubyGems (both gems), all via OIDC trusted publishing — with the
  launcher-gem job gated on the GitHub release existing. The separate
  `release-ecosystems.yml` workflow is removed (its `release: published`
  trigger never fired: the release is created with `GITHUB_TOKEN`, which
  suppresses downstream workflow events). The CLI is distributed via
  GitHub releases, npm, PyPI, crates.io, and RubyGems only — the
  Composer/Packagist, Maven Central, and NuGet launcher channels drafted
  earlier in this cycle were dropped before ever shipping in a release.
- `--api-url` / `--proxy-url` no longer carry clap-level defaults: with
  neither flag nor env var set they parse as unset and the documented
  default URLs are applied at API-client construction (after the
  socket-cli config layer). Observable behavior is unchanged unless a
  socket-cli login exists.
- **All ecosystem feature flags removed — every ecosystem is always compiled
  in.** The `cargo`, `golang`, `maven`, `composer`, `nuget`, and `deno` Cargo
  features are gone from both crates; npm, PyPI, Ruby gems, Go, Cargo, NuGet,
  Maven, Composer, and Deno support is now unconditional. Builds that passed
  `--features <eco>` will get an "unknown feature" error and should simply
  drop the flag; `--no-default-features` no longer produces a minimal binary
  (there is nothing left to strip). The `SOCKET_EXPERIMENTAL_MAVEN` /
  `SOCKET_EXPERIMENTAL_NUGET` runtime gates outlived this entry only briefly —
  they are retired in the same release (see the "promoted to fully available"
  entry under Changed). The only remaining features are the
  test-suite gates `docker-e2e` and `setup-e2e` on `socket-patch-cli`. (MAJOR
  for anyone scripting `--features`; no behavior change for default builds
  beyond composer/deno support now being present.)

- **Token-less `scan` now batch-queries the public proxy.** Proxy-mode scans
  POST `{proxy}/patch/batch` (one request per `--batch-size` chunk, mirroring
  the authenticated `/v0/orgs/{slug}/patches/batch` endpoint) instead of
  issuing one `GET /patch/by-package/:purl` per package. The client
  transparently degrades to the legacy per-package GET path against proxies
  that predate the batch endpoint, and when the all-or-nothing batch
  validation rejects a chunk (e.g. a crawled PURL type the server doesn't
  recognize, such as `pkg:jsr/…` — per-package queries tolerate those
  individually, so one exotic package can't fail a whole scan). Rate limits
  and over-capacity 503s still surface instead of silently degrading. (MINOR)

### Fixed

- **bun 1.4 lockfiles are accepted again.** bun 1.4.0 bumped `bun.lock`
  `lockfileVersion` to 2 while leaving the emitted grammar unchanged; the
  shared version gate refused everything but 1, so hosted and vendored
  modes refused every lock written by bun ≥ 1.4
  (`redirect_bun_lock_unsupported` / `vendor_lockfile_version_unsupported`).
  The gate now accepts versions 1 and 2 and keeps failing closed on
  anything else; new shared golden fixture `npm/bun/lock-v2` (the depscan
  TS twin needs the matching acceptance + fixture sync).
- **gem: every coexisting installed copy is patched.** Bundler's scoped
  `<engine>/<abi>/gems` and flat `gems/` stores can coexist under one
  `BUNDLE_PATH` root, each holding a real copy of the same gem@version;
  first-wins resolution patched one store and reported success while the
  other bundler loaded pristine (vulnerable) bytes. `apply` now fans out
  per copy (per-copy `Applied` events, each counted in `summary.applied`),
  bundle-path roots are crawled in bundler precedence order, and
  config-sourced roots are contained. The `gem_bundle_config_path_ignored`
  warning also prints the skipped path verbatim instead of
  backslash-escaped.
- **npm `@socketsecurity/socket-patch`: the `./schema` export is now built
  at publish.** The subpath pointed at a gitignored `dist/` directory that
  nothing built during release, so it shipped broken; a `prepack` script
  now compiles it as part of `npm publish`.
- **Release workflow tag-guard and idempotency fixes.** The
  tag-already-exists guard never fired (it ran `git rev-parse` in a
  shallow, tagless checkout) — it is now a stateless `git ls-remote` check
  that still permits same-commit retries; the GitHub-release step re-runs
  cleanly instead of hard-failing when the release already exists; and the
  cargo/PyPI/gem publish jobs skip already-published versions, so
  "Re-run failed jobs" can resume a partial release safely.
- **NuGet hosted rewriter: creating a `packageSourceMapping` from scratch now
  emits a catch-all for pre-existing sources.** `packageSourceMapping` is
  exclusive — once ANY mapping exists, every package must match some source's
  pattern or restore hard-fails NU1100. A redirect into a `nuget.config` with
  no prior mapping previously routed only the patched id, breaking every
  OTHER package's restore; the rewriter now fans a `<package pattern="*" />`
  mapping out to each pre-existing package source (longest-prefix match still
  routes the patched id to the Socket source). Golden fixtures updated on
  both the Rust and TS sides.

- **VEX now attests Go `replace`-redirect patches.** `socket-patch vex`
  previously verified golang patches against the pristine module cache
  instead of the patched `.socket/go-patches/` copy, so redirect-applied
  patches were silently omitted from the document (reported `not_applied`,
  or `package_not_found` on cache-less CI). Verification now follows the
  managed `replace` directive to the committed copy.

- **`repair` on a hosted-only project is an informational no-op.** Hosted
  (`--mode hosted`) mode leaves no local artifacts to repair — the lockfiles
  point at `patch.socket.dev` URLs, and there is no manifest or vendor ledger.
  A project whose only `.socket/` trace is `redirect-state.json` (no manifest,
  no vendor ledger, no vendored lockfile references) previously errored with
  `manifest_not_found` (exit 1); it now exits 0 with a `redirect_only_project`
  skip pointing at `scan --mode hosted`. Repair still errors on a bare
  directory with no traces at all.

## [3.2.0] — 2026-05-29

A repo-wide correctness, security, and filesystem-safety hardening pass: every
source file in both crates was reviewed line by line, the bugs found were fixed,
and regression tests were added throughout (the lib + integration suites grow by
~10k lines of mostly tests). The audit harness used to drive the review lives in
`scripts/study-crates.ts`.

### Security

- **Path-traversal in archive extraction.** `read_archive_to_map`
  (`patch/package.rs`) validated the raw tar entry path but returned the
  `package/`-stripped path, so an entry like `package//etc/passwd` passed every
  check and then resolved to an absolute `/etc/passwd` that `Path::join`
  writes outside the package tree. Validation now runs on the normalized path
  actually written to disk.
- **Unbounded preallocation from an untrusted delta header.** `apply_diff`
  (`patch/diff.rs`) reserved a `Vec` sized from the bsdiff target-size header,
  which qbsdiff never validates — a tiny hostile delta could claim up to
  `i64::MAX` and abort the process. The hint is now clamped to 64 MiB.
- **Evidence-free VEX attestation.** `verify_patch_record` (`vex/verify.rs`)
  returned `applied` for a patch touching zero files, producing a
  `not_affected` statement with no on-disk evidence; zero-file records are now
  omitted (`no_files`).

### Fixed — filesystem safety, atomicity & rollback

- **`apply` could not write into read-only directories** (Go module cache marks
  dirs `0o555`); added a `DirWriteGuard` that temporarily grants write on the
  parent dir around the CoW-break + atomic rename and restores its exact mode.
- **`apply` stripped setuid/setgid bits** on every patched file because `chown`
  ran after `chmod`; reordered to chown-before-chmod, plus a parent-dir `fsync`
  so the rename survives a crash.
- **Non-atomic symlink break** (`patch/cow.rs`) removed the file before staging
  its replacement, destroying it with no rollback on a failed write; now
  rename-over the link, matching the hardlink path. Stage files are cleaned up
  on every error arm.
- **`rollback` used an unsafe in-place write**; it now delegates to the hardened
  `apply_file_patch` (atomic, CoW-safe, validate-before-write, permission
  restore). Also: a GC'd before-blob no longer shadows the already-original
  short-circuit, and new-file deletion works inside read-only directories.
- **Hash integrity:** `compute_file_git_sha256` (`patch/file_hash.rs`) opened
  and stat'd the path separately (TOCTOU) and never checked the target was a
  regular file (a directory hashed as the empty blob); now opens once, fstats
  the descriptor, and rejects non-regular files. `compute_git_sha256_from_reader`
  now errors when the streamed byte count disagrees with the declared size.
- **Sidecar writes in read-only caches:** the cargo `.cargo-checksum.json`
  rewrite and the NuGet `.nupkg.metadata` delete used bare, non-atomic I/O that
  failed `EACCES` in the locked-down registry trees they exist to serve; both
  now go through the hardened write/`DirWriteGuard` paths.
- **Blob cleanup** (`utils/cleanup_blobs.rs`) aborted the whole sweep on one
  dangling symlink and inflated the "checked" count with subdirs/dotfiles; now
  uses `symlink_metadata`, skips stat errors, and counts only real blobs.
- **Lock acquisition** (`patch/apply_lock.rs`) mapped every `flock` error to
  `Held` (masking `ENOLCK`/`EACCES`/unsupported-FS and busy-waiting through the
  whole timeout) and overshot sub-100 ms waits; genuine faults now surface
  immediately and the sleep is clamped to the remaining budget.

### Fixed — crawlers (on-disk layout & metadata)

- **Composer:** normalize the `v`-prefixed `installed.json` version against bare
  PURLs, tolerate a single malformed entry instead of dropping the file, and
  skip packages absent on disk.
- **Go:** only skip `cache/` at the module-cache root (not at any depth),
  decode/encode case-escaped versions (`v1.0.0-RC1` ↔ `…-!r!c1`), treat `GOPATH`
  as a path list, and reject malformed/empty `module` directives.
- **npm:** follow symlinked directories during the global-fallback walk
  (`DirEntry::metadata()` doesn't follow links) and guard nested recursion so it
  doesn't descend through symlinked packages.
- **NuGet:** lowercase the version directory (not just the id) when resolving the
  global packages folder, so prerelease-cased versions resolve.
- **Python:** the macOS framework `Versions/` layout uses bare `3.11` dirs, and a
  package with missing/malformed `METADATA` now falls back to its
  `<name>-<version>.dist-info` directory name instead of vanishing.
- **Deno:** correct the macOS cache path (`~/Library/Caches/deno`), honor
  `XDG_CACHE_HOME` on Linux, and treat an empty `DENO_DIR` as unset.
- **Maven:** strip XML comments before tag matching and handle self-closing /
  inline skip-sections so a commented or oddly-formatted POM can't leak a
  plugin's coordinates as the project's.
- **Cargo:** tolerate `[package]` headers with comments/whitespace and split
  `<name>-<version>` dirs at the dotted version (handles numeric pre-releases).
- **Shared:** `utils/fs::entry_is_dir` now follows symlinks, fixing symlinked
  package-dir discovery across every dir-walking crawler at once.

### Fixed — API client, commands & misc

- **API client:** honor a `--proxy-url` override on binary downloads (was
  re-derived from env), and make org selection, patch titles, and the
  individual-query batch capability flag deterministic / order-independent;
  hash comparison is now case-insensitive.
- **Version reporting:** `USER_AGENT` and telemetry `context.version` were
  hardcoded to `1.0`/`1.0.0`; both now derive from `CARGO_PKG_VERSION`.
- **`apply`** no longer emits a spurious `Failed` envelope event for a
  release-variant whose first file is `NotFound`.
- **UTF-8 safety:** `get`/`scan`/`remove` truncated display strings with raw
  byte slices that panic on multi-byte API text; all use char-safe truncation.
- **Exit codes:** `setup` now exits non-zero (not `already_configured`) when a
  `package.json` fails to parse, and `repair` exits non-zero and fires failure
  telemetry on a partial download failure (also gates the offline dry-run
  "would download" event and threads through `bytes_freed`).
- **`rollback`** no longer miscounts zero-file records as already-original or
  double-counts no-ops in dry-run; **`unlock`** reports `released` from a
  pre-`acquire` snapshot so a probe-created lock file isn't reported as removed.
- **`vex`** resolves qualified PyPI/Gem/Maven PURLs via the rollback-aware
  resolver so those patches are no longer dropped as `package_not_found`.
- **`package.json` handling:** no longer panics on a non-object root or
  non-object `scripts`, de-dups overlapping workspace patterns, handles bare
  `*`/`**`/deep globs, strips inline YAML comments, and preserves top-level key
  order (enabled `serde_json`'s `preserve_order`).
- Smaller fixes: deterministic `list` output ordering, case-insensitive
  `fuzzy_match` tie-break, `json_envelope` status-invariant enforcement +
  `oldUuid` field, `lock_cli` sub-second timeout message, blob-fetcher
  all-skipped formatting, VEX `Statement.timestamp` made optional per OpenVEX
  0.2.0, and VEX git-remote `url` parsing.

### Tests & tooling

- Hundreds of regression tests added across the patch engine, crawlers, API
  client, manifest, `package.json`, VEX, and CLI command layers; the stale
  `repair`/`python_crawler` e2e expectations were updated to the corrected
  contracts. Full suite green (`--features cargo`).
- Added the `scripts/study-crates.ts` per-file audit harness (with an example
  prompt config) used to drive this review.

## [3.1.0] — 2026-05-26

### Added

- **Telemetry coverage for read-side + housekeeping + attestation commands.**
  `scan`, `get`, `list`, `setup`, `repair`, `unlock`, and the new `vex`
  command each emit a `patch_<action>` (and matching `*_failed`) event
  through the existing send path, joining the apply/remove/rollback
  trio that already shipped. The `scan` event carries per-tier counts
  (`free_patches`/`paid_patches`/`can_access_paid`), the ecosystems
  filter, and a `fallback_to_proxy` flag; `get` carries
  `uuid`/`tier`/`ecosystem`/`download_mode`/`fallback_to_proxy`.

- **`scan` + `get` automatically fall back to the public proxy on
  401/403** from the authenticated endpoint. A stale or revoked
  token no longer blocks access to free patches — the CLI logs a
  warning to stderr, swaps to the proxy, retries once, and tags the
  resulting telemetry event with `fallback_to_proxy: true`. The
  classifier is deliberately narrow: 404, 5xx, network, and rate-limit
  errors do NOT trigger fallback so backend issues stay visible.
  `apply`/`remove`/`rollback`/`vex` keep their fail-loud semantics.

- **`SOCKET_OFFLINE` (airgap mode) now disables telemetry universally.**
  `is_telemetry_disabled()` honors the same `SOCKET_OFFLINE=1|true`
  signal `--offline` uses for network suppression, so apply (and
  every future command) no longer attempts a 5-second telemetry POST
  against `https://api.socket.dev` when the operator explicitly
  requested airgap.

### Tests

- New `tests/cli/telemetry_e2e.rs` end-to-end behavioral coverage:
  apply/scan/get/list emit telemetry against a wiremock recorder;
  `SOCKET_OFFLINE=1` produces zero telemetry POSTs across all four;
  scan falls back on 401 + tags the resulting event; scan does NOT
  fall back on 500 (conservative classifier).
- New `scan_invariants` cases for the patch-management lifecycle:
  withdrawn patches keep their entry when the package is still
  installed but API is silent; entries for uninstalled packages get
  pruned; `scan` without `--apply` is read-only against the manifest
  and blobs even when an update is detected.

## [3.0.0] — 2026-05-22

### Breaking

- **`--offline` semantics unified** to strict airgap on every subcommand.
  Previously meant three different things across `apply` (strict airgap),
  `repair` (skip downloads / cleanup-only), and `rollback` (fail when blobs
  missing). All three now mean the same thing: never contact the network,
  fail loudly when a required local source is missing.
- **`repair --download-mode` default** changed from `file` to `diff` to
  match every other subcommand. Users who need the legacy per-file blob
  behavior must now opt in with `--download-mode file`.
- **`repair --offline` is mutually exclusive with `--download-only`** —
  passing both exits with code 2.
- **Env vars renamed.** The three remaining `SOCKET_PATCH_*` env vars now
  use the `SOCKET_*` prefix:
  - `SOCKET_PATCH_PROXY_URL` → `SOCKET_PROXY_URL`
  - `SOCKET_PATCH_DEBUG` → `SOCKET_DEBUG`
  - `SOCKET_PATCH_TELEMETRY_DISABLED` → `SOCKET_TELEMETRY_DISABLED`

  The legacy names are still honored at runtime but emit a one-shot
  deprecation warning to stderr (the warning fires even under `--silent`
  and `--json` because the transition signal must reach scripts and CI
  logs). Legacy names will be removed in v4.

### Added

- Shared `GlobalArgs` clap struct `#[command(flatten)]`-ed into every
  subcommand. Every flag is now accepted on every subcommand (silently
  no-op'd where the subcommand doesn't consume it). Every flag has a
  matching `SOCKET_*` env-var binding with precedence
  `CLI arg > env var > default`. See `CLI_CONTRACT.md` for the full
  global-arguments table.
- `apply` and `repair` accept `--api-url`, `--api-token`, `--org` via the
  global flatten (previously env-var only — telemetry would silently fall
  back to the public proxy when the CLI was the only way to set these).
- New global flags `--debug` and `--no-telemetry`, promoted from env-only
  toggles.
- `--proxy-url` (env: `SOCKET_PROXY_URL`) as an explicit CLI knob for the
  public patch proxy.
- New CI guard in the `Release` workflow: the workflow fails before tag
  creation if `CHANGELOG.md` lacks an entry for the version in
  `Cargo.toml`. Blocks every downstream publish (cargo, npm, pypi).

### Changed

- Garbage collection moved out of `apply`. Use `scan --prune`,
  `scan --sync`, or `repair` / `gc` instead. `apply` is now strictly
  non-mutating against `.socket/`: when blobs need to be fetched they go
  to a temp overlay; the persistent cache is never written to.
- Unified JSON envelope (`command` / `status` / `events` / `summary`) for
  `apply`, `list`, `remove`, `repair`. Other subcommands keep their
  pre-v3 ad-hoc shapes for now; see `CLI_CONTRACT.md` for migration status.

## [2.1.4] — 2026-04-09

- Release workflow tolerates already-published npm packages so a partial
  publish can be retried without re-tagging.

## [2.1.3] — 2026-04-08

- Pin Node `22.22.1` in the release workflow to dodge a broken
  upstream npm.

## [2.1.2] — 2026-04-08

- Harden core error handling, blob verification, and `--force` reporting.
- Surface `find_by_purls` errors instead of silently swallowing them.
- Add diagnostics to `apply` for silent no-op failures in CI.
- Add explicit Node typings for TypeScript 6 compatibility in the npm
  wrapper.

## [2.1.1] — 2026-04-02

- Simplify release to `workflow_dispatch` only (no bot commits).
- Split release into PR-based version prep + auto-publish on dispatch.
- Prioritize `pnpm-workspace.yaml` detection and restrict `setup` to root
  `package.json` for pnpm monorepos.
- Harden GitHub Actions workflows per `zizmor` audit.
- Unflag Ruby gem (`gem`) support and add e2e bundler tests.
- Use `npx @socketsecurity/socket-patch` for the generated postinstall
  command.

## [2.1.0] — 2026-03-10

- Full glibc/musl support across all Linux architectures (16 platform
  combinations now published per release).

## [2.0.0] — 2026-03-06

- Interactive prompts and smart patch selection when multiple patches
  match a query.

## [1.7.1] — 2026-03-06

- Ensure the binary has execute permission in the PyPI wrapper.
- Restore `bin` and `optionalDependencies` to the npm wrapper
  `package.json`.

## [1.7.0] — 2026-03-06

- Expand ecosystem support: rough-in for composer, go, maven, nuget, ruby.
- Add a TypeScript schema library to the npm wrapper.
- Treat empty `SOCKET_API_TOKEN` as unset.

## [1.6.3] — 2026-03-05

- Maintenance release.

## [1.6.2] — 2026-03-05

- Maintenance release (version sync).

## [1.6.1] — 2026-03-05

- Switch to per-platform `optionalDependencies` for the npm package.
- Add macOS global-package crawling fallbacks and pyenv support.

## [1.6.0] — 2026-03-04

- Add support for more platforms; fix pypi and npm publish flows.

## [1.5.0] — 2026-03-04

- Fix trusted publishing setup for npm and PyPI.

## [1.4.0] — 2026-03-04

- Update PyPI publish action and add npm provenance permissions.

## [1.3.1] — 2026-03-04

- Fix action image references in the publish workflow.

## [1.3.0] — 2026-03-04

- Add `apply --force`; rename `--no-apply` to `--save-only` (the old name
  remains as a hidden alias).
- Cargo/Rust crate patching support behind a feature flag.
- Auto-resolve org slug from API token when `SOCKET_ORG_SLUG` is unset.

## [1.2.0] — 2026-01-10

- Fix publish workflow to checkout the bumped version.

## [1.1.0] — 2026-01-10

- Pin GitHub Actions to full commit SHAs and wire up version-bump
  support in the publish workflow.
