# Ecosystem & platform support

This is the detailed support matrix for `socket-patch`: which package ecosystems work
with which [patch mode](../README.md#patch-modes), the per-ecosystem caveats, and
the platforms the binary ships for.

For what the three modes *are* and how to choose between them, see
[Patch modes](../README.md#patch-modes) in the README.

## Mode × ecosystem matrix

The backticked slug in each row is the value `-e`/`--ecosystems` accepts (e.g.
`--ecosystems npm,pypi,golang`).

For a project that Bazel builds, see
[Bazel workspaces: what is supported](#bazel-workspaces-what-is-supported): the table
below is about what a package manager installs and builds.

| Ecosystem | agent (`--mode agent`) | vendored (`--mode vendored`) | hosted (`--mode hosted`) |
|-----------|------------------------|------------------------------|--------------------------|
| npm (`npm`) — pnpm / yarn / berry / bun / vlt | ✅ any install layout, vlt's `node_modules/.vlt` store included (every store copy, copy-on-write) | ✅ seven lockfile flavors: package-lock, yarn classic, yarn berry (node-modules linker; PnP refused), pnpm v9, pnpm legacy v5.4/v6.0 (`pnpm 7/8` — frozen installs are path-bound because those majors absolutize `file:` override specifiers; moved checkouts run one `pnpm install --offline --no-frozen-lockfile`, surfaced as `vendor_pnpm_legacy_absolute_specifier`), bun text `bun.lock` lockfileVersion 0/1/2/3 and native binary `bun.lockb` revisions 1/2/3 (binary locks stay binary; text workspace vendoring requires lockfileVersion 2 — see [Bun compatibility](testing/bun-compatibility.md)), vlt `vlt-lock.json` lockfileVersion 0/1 (patched package directories for direct dependencies of the root or a workspace member; transitive targets refused — see [vlt notes](#npm-vlt-notes)). Rush monorepos on pnpm 9 and newer are wired through `pnpm-config.json` and each directly-depending project's `package.json` — see [Rush notes](#npm-rush-monorepos) | ✅ package-lock / npm-shrinkwrap, pnpm-lock.yaml and legacy shrinkwrap.yaml (pnpm majors 1–12; block and flow resolutions), yarn classic, yarn berry, bun, vlt (`vlt-lock.json` without `lockfileVersion`, 0 or 1) — pnpm, berry, bun and vlt carry constraints, see [npm hosted-mode notes](#npm-hosted-mode-notes) and [vlt notes](#npm-vlt-notes) |
| PyPI (`pypi`) — uv / poetry / pdm / pipenv / pip | ✅ in place | ✅ uv project/script locks, PEP 751 `pylock.toml` / `pylock.<name>.toml`, poetry, pdm, pipenv (Pipenv 2018 or later — every `Pipfile.lock` category is rewired, lock-only checkouts included; Pipenv 2023+ does not hash-check local wheels — `vendor_integrity_unverified`; Pipenv 2023.7.9+ exports the vendored wheel without a hash, so `pipenv requirements --hash` output fails pip's hash-checking mode — `pypi_pipenv_hash_export_unsupported`; a venv still holding the upstream release is reported as `pypi_pipenv_stale_install`; see [Pipenv compatibility](testing/pipenv-compatibility.md)), and requirements.txt. Native uv vendoring requires uv ≥ 0.2.35 (the `[[package]]` lock grammar); hosted mode covers native `uv.lock` from uv 0.1.45 (the first release whose `uv lock` writes one) and requirements from uv 0.0.5; see [uv compatibility](testing/uv-compatibility.md). Declined where a rules_python hub of a Bazel workspace reads the file, see [Bazel workspaces: PyPI and RubyGems vendored mode](#bazel-workspaces-pypi-and-rubygems-vendored-mode) | ✅ requirements.txt including hash continuations, uv project/script locks, and PEP 751 locks. Version/source ambiguity is refused; see [uv compatibility](testing/uv-compatibility.md). Poetry 1.x and 2.x locks are supported; Poetry 0.x ignores URL sources and is refused. See [Poetry compatibility](testing/poetry-compatibility.md). Pipenv `Pipfile.lock` (pipfile-spec 6 — Pipenv 7 and later; `path` references for 7–11, `file` from 2018; lock-only checkouts and Pipenv's out-of-tree venv are discovered; a warm venv that Pipenv will not reinstall over warns `redirect_pypi_stale_install`; see [Pipenv compatibility](testing/pipenv-compatibility.md)). `pdm.lock` is supported for the lock formats PDM 0.12–1.4 and 2.8.1+ write (`lock_version` 2 / 4.3–4.5.1); the identity-losing 3.1 / 4.0–4.2 formats (PDM 1.8–2.7) are refused. PDM 2.8.0 writes an indistinguishable `4.3` lock but shares that identity-loss bug, so a rewritten 2.8.0 lock crashes `pdm sync` — upgrade to ≥ 2.8.1. See [PDM compatibility](testing/pdm-compatibility.md). |
| pixi (`pypi`) — the Python packages of a pixi project, from conda channels or PyPI | ✅ in place, in every environment under `.pixi/envs`: PyPI wheels and pure-Python conda packages (compiled conda packages are not supported yet and are skipped) — see [PyPI: pixi projects](#pypi-pixi-projects) | ❌ refused (`pypi_no_requirements` / `pypi_pyproject_only`, which name agent mode) | ❌ nothing rewritten (`redirect_pypi_pixi_project` names agent mode) |
| Cargo (`cargo`) | ✅ in-place + `.cargo-checksum.json` rewrite (shared registry-cache caveat — see [Cargo: shared registry cache](#cargo-shared-registry-cache)) | ✅ `[patch.crates-io]` path entry in the root `Cargo.toml` (v5; per-version Socket keys; pre-v5 `.cargo/config*` wiring migrates on re-run) | ✅ per-patch sparse registry (`[registries.socket-patch-<uuid>]` + Cargo.lock source/checksum); needs cargo 1.68+ (sparse registries) — a project whose `rust-version` or `rust-toolchain[.toml]` declares an older cargo is refused (`redirect_cargo_old_cargo`), use `--mode vendored`; direct dependencies only — a crate another dependency also pulls in is refused, use `--mode vendored`; a crate the user overrides with `[patch]` (path, git or another registry) is refused too, the override is left alone; a `cargo vendor` or `cargo local-registry` project (crates.io replaced by an on-disk source in the project's, a parent directory's or `$CARGO_HOME`'s `.cargo/config*`) is refused, use agent mode; with no `Cargo.lock` the graph is unknown, so only a project whose sole dependency is the patched crate is redirected; in a Bazel workspace a crate is not pinned while a rules_rust hub reads the project's Cargo files without its cargo config (`redirect_cargo_bazel_config_unread`), see [Bazel workspaces: Cargo](#bazel-workspaces-cargo) |
| RubyGems (`gem`) | ✅ in place | ✅ Gemfile + Gemfile.lock path pair (a CRLF `Gemfile.lock`, as a `core.autocrlf` checkout leaves it, is edited and reverted in its own line ending, and a lock mixing CRLF and LF fails closed; a gem locked as precompiled platform gems is vendored from prebuilt patched platform gems, see [Ruby gems: native extensions](#ruby-gems-native-extensions); `Gemfile` spelling only — a `gems.rb` twin, which bundler ≥ 2 loads instead, or a `BUNDLE_GEMFILE`-configured manifest makes vendoring refuse with `gemfile_not_loaded` before any write); declined where a rules_ruby hub of a Bazel workspace reads the pair, see [Bazel workspaces: PyPI and RubyGems vendored mode](#bazel-workspaces-pypi-and-rubygems-vendored-mode) | ✅ a `source:` option on the gem's own declaration, the lock converged to match (see [Ruby gems: hosted mode](#ruby-gems-hosted-mode)) — edits `gems.rb` + `gems.locked` or `Gemfile` + `Gemfile.lock`, whichever the project holds (a `Gemfile` + `gems.rb` twin is refused with `redirect_gem_twin_manifest_ambiguous`: bundler 1.x loads the `Gemfile`, bundler ≥ 2 loads `gems.rb`, and nothing in the project says which bundler installs it; bundler 4's `BUNDLE_LOCKFILE` (environment, app config or global config) naming any other lock is refused with `redirect_gem_bundle_lockfile_unsupported`, as is vendoring with `gemfile_not_loaded`; spellings that diverge beyond Socket's own edits fail closed with `redirect_gem_gemfile_spellings_diverge`; `BUNDLE_GEMFILE` from `.bundle/config` (which outranks the environment, as in bundler), the environment, or the global `~/.bundle/config` / `$BUNDLE_USER_CONFIG` (lowest, as in bundler) is followed when it names the project's `Gemfile` / `gems.rb`, and any other configured manifest is refused with `redirect_gem_bundle_gemfile_unsupported`); a Bundler all-source, exact-source or hostname mirror in app config or the scan environment can capture the patch registry, so the redirect is refused with `redirect_gem_mirror_overrides_source` without printing mirror URLs (scope mirrors to `mirror.https://rubygems.org`; user-global config and mirrors set only in a later install environment are not inspected); the `CHECKSUMS` pin needs bundler ≥ 2.6 (an older lock is still pinned by source and installs frozen; the run says once, with `redirect_gem_no_checksums_section`, that it cannot record the checksums); a stale pre-redirect materialization that `bundle install` would reuse instead of refetching is replaced with the verified patched gem when it is the project's own, else flagged `redirect_gem_stale_install` with the remedy (see "Ruby gems: gems already installed" below and CLI_CONTRACT.md's "Gem stale-install guard"). In a Bazel workspace whose rules_ruby call holds the gem to another sha256 in `gem_checksums`, or has a `gem_checksums` that is not written out in the call, nothing is written for it (`redirect_bazel_gem_checksums_pinned`); see [Bazel workspaces: RubyGems](#bazel-workspaces-rubygems) |
| Go (`golang`) | ✅ `go.mod` `replace` → `.socket/go-patches/` — see [Go: directory replaces and go.sum](#go-directory-replaces-and-gosum) | ✅ `replace` → the committed vendor tree | ✅ (free tier) fork-style `replace` → `patch.socket.dev/gopatch/<uuid>` + committed `go.sum` pin; see [Go notes](#go-directory-replaces-and-gosum). Paid hosted patches are unsupported; `redirect_golang_unsupported` names the vendored remedy |
| Maven (`maven`) — Maven and Gradle | ✅ in place in every copy the build consumes: each `~/.m2` copy it reads and each Gradle `files-2.1` copy; `~/.m2` `.sha1`/`.md5` sidecars are rewritten, Gradle copies get advisories; jar-member records swap in the patch service's whole jar — prefer vendored / hosted, see [Maven & NuGet caveats](#maven--nuget-caveats) and [Gradle](#gradle) | ✅ suffixed Maven repository (`<version>-socket.<hex8>` pin + `.mvn/maven.config` + fallback file repository) for every pom root, single-module or reactor, or Gradle 6.8+ same-GAV repository with settings wiring and SHA-256 checks (a root with both `pom.xml` and a Gradle build wires both); see [JVM vendoring](design/maven-vendoring.md) and [Gradle](#gradle) | ✅ fail-closed by a Socket-only `<version>-socket.<hex8>` suffix: pom projects get a pinned `<version>` (`${property}` versions are refused); Gradle 6.8+ builds get an owned settings script, lock-entry rewrites and a resolution tripwire — see [Maven & NuGet caveats](#maven--nuget-caveats) and [Gradle](#gradle) |
| sbt / Mill / scala-cli (`maven`) | ✅ Coursier caches (sbt 1.3+, sbt 2, Mill, scala-cli) and Ivy caches (sbt 0.13–1.2, `useCoursier := false`) patched in place, Coursier checksum sidecars resynced — see [Scala build tools](#scala-build-tools-sbt-mill-scala-cli) | ✅ sbt 0.13.18+: generated `socket-patch-vendor.sbt` over the committed suffixed `.socket/vendor/maven2` tree; scala-cli directory builds: owned `socket-patch.scala` + same-GAV `.socket/vendor/coursier` tree (Linux / macOS); Mill: not wired (agent or hosted guidance) | ✅ sbt 0.13.18+: one generated `socket-patch.sbt`, gated on sbt's own `sbt update` records; Mill / scala-cli: paste-able snippets only (`redirect_mill_manual_snippet`, `redirect_scala_cli_manual_snippet`) |
| NuGet (`nuget`) | ✅ in-place patching deletes `.nupkg.metadata` and advises on the `.nupkg.sha512` tamper-evidence sidecar — prefer vendored / hosted, see [Maven & NuGet caveats](#maven--nuget-caveats) | ✅ committed folder feed (its `.gitignore` re-includes the nupkg against `*.nupkg` rules) + `packageSourceMapping` + `packages.lock.json` contentHash pin | ✅ `nuget.config` source + source-mapping, `packages.lock.json` contentHash rewrite. See the locked-mode note in [Maven & NuGet caveats](#maven--nuget-caveats). In a Bazel workspace whose rules_csharp `nuget.from_lock` hub would not take the pin (it reads the lock and not that `nuget.config`, or has the package from a lock the run does not re-pin), nothing is written (`redirect_bazel_nuget_config_undeclared`, `redirect_bazel_nuget_lock_not_repinned`); see [Bazel workspaces: NuGet](#bazel-workspaces-nuget) |
| Composer (`composer`) | ✅ in place (`vendor/`) | ✅ `composer.lock` `dist: path` rewrite; declined in a Bazel workspace, see [Bazel workspaces: Composer](#bazel-workspaces-composer) | ✅ `composer.lock` dist url + shasum rewrite; the entry's `source` and `dist.mirrors` are removed. See [composer-compatibility.md](testing/composer-compatibility.md) |
| Deno (`deno`) | ✅ in place (the only mode for Deno) | ❌ refused (`vendor_unsupported_ecosystem`) | ❌ not supported |

> **Maven / NuGet sidecar caveat**: Maven and NuGet are fully enabled in every mode.
> In-place (agent-mode) patching writes into shared caches: NuGet's post-apply fixup
> deletes `.nupkg.metadata` and raises an advisory for the signed-package
> `.nupkg.sha512` tamper marker it cannot honestly rewrite. A `~/.m2` copy's
> `.jar.sha1`/`.jar.md5` that described the pre-patch bytes are rewritten to the patched
> bytes (and back on rollback); one that already disagreed is left alone. A Gradle
> `files-2.1` copy has no checksum file (its directory names the download's sha1), so
> each patched copy gets advisories instead: `gradle_refresh_reverts`,
> `gradle_daemon_stale` and `gradle_global_cache_shared` (see [Gradle](#gradle)). The
> copy-out modes — `vendor`, `scan --mode vendored`, `scan --mode hosted` — never write
> into the caches and avoid the issue entirely.

## v5 support tiers

The matrix above lists what each mode handles. This table says how much that support
is worth for v5.x. v5 removes no format or mode: everything in the matrix works in v5.0
and keeps working through v5.x.

| Tier | Meaning |
|---|---|
| **Supported** | The default. Covered by CI. A regression is a release blocker. |
| **Beta** | Works for the build shapes documented on this page and is tested in CI. Some shapes outside them are refused, and the open issues for that ecosystem describe shapes that are patched incompletely. Preview with `--dry-run` and confirm with a real build before you commit the result. |
| **Legacy** | A format that the package manager itself has retired. socket-patch keeps reading and writing it in v5 and still fixes its bugs, but adds no new features for it. Prefer the upgrade path in the table below. |
| **Not supported** | Refused with an error code that names the remedy. |

| Ecosystem / format | agent | vendored | hosted |
|---|---|---|---|
| npm: package-lock / npm-shrinkwrap, yarn classic, yarn berry, pnpm lock v9, text `bun.lock`, vlt lock eras C–F | Supported | Supported | Supported |
| npm: binary `bun.lockb` | Supported (agent mode patches `node_modules`, not the lock) | Legacy | Legacy |
| npm: pnpm 7/8 locks (lockfileVersion 5.4 / 6.0) | Supported | Legacy | Supported |
| npm: older pnpm locks (pnpm 1–6, `shrinkwrap.yaml`) | Supported | Not supported | Supported (see [npm hosted-mode notes](#npm-hosted-mode-notes) for the version floors) |
| npm: vlt lock eras A0–B (before 1.0.0-rc.15) | Supported | Legacy (A0 is refused) | Legacy |
| PyPI, Cargo, RubyGems, Go, NuGet, Composer | Supported | Supported | Supported, with the per-ecosystem limits in the matrix |
| Maven (`pom.xml` builds) | Supported, with the [sidecar caveats](#maven--nuget-caveats) | Beta | Beta |
| Gradle | Supported, with the [`files-2.1` advisories](#gradle) | Beta (Gradle 6.8+) | Beta (Gradle 6.8+) |
| sbt / Mill / scala-cli | Beta | Beta (sbt and scala-cli directory builds; Mill is not wired) | Beta (Mill and scala-cli get manual snippets only) |
| Deno | Supported | Not supported | Not supported |

**Hosted and vendored Maven and Gradle are Beta in v5.** Each wiring is built to fail
closed: hosted mode and vendored Maven pin a Socket-only `-socket.<hex8>` version, and
vendored Gradle checks the SHA-256 of the vendored artifact, so a build that cannot get
the patched artifact fails instead of silently building the upstream jar. But the pom
and Gradle rewriters still have open gaps. For example: multi-module builds, `<classifier>`
dependencies, dependencies declared inside profiles, plugins or comments, `${property}`
coordinates, imported BOMs, and repository mirrors. The open
[`pm:maven`](https://github.com/SocketDev/socket-patch/issues?q=is%3Aissue+is%3Aopen+label%3Apm%3Amaven)
and [`pm:gradle`](https://github.com/SocketDev/socket-patch/issues?q=is%3Aissue+is%3Aopen+label%3Apm%3Agradle)
issues track them. Before you rely on a JVM `--vex` attestation, run the build and check
that it resolves the patched artifact of each patched dependency.

### Legacy formats: upgrade and undo

Each Legacy format has an upgrade path and an undo path. Both work in v5:

| Format | Leave the legacy format | Undo socket-patch's changes |
|---|---|---|
| Binary `bun.lockb` | Bun 1.2+ writes text `bun.lock` by default. Undo socket-patch's changes (next column), convert with `bun install --save-text-lockfile --frozen-lockfile --lockfile-only`, delete `bun.lockb`, then rerun `socket-patch scan --mode <mode>` with the mode you used before | Vendored: `socket-patch rollback`. Hosted: `rollback` refuses a hosted `bun.lockb` pin, because the binary lock cannot be re-derived. Restore the lock from version control (`git checkout -- bun.lockb`), as the refusal says |
| pnpm 7/8 lock, vendored | Run `socket-patch rollback`, re-lock with pnpm 9 or later, then rerun `socket-patch scan --mode vendored`. A pnpm 9+ lock is not path-bound (see `vendor_pnpm_legacy_absolute_specifier` in the matrix) | `socket-patch rollback` |
| vlt eras A0–B | Run `socket-patch rollback`, re-lock with vlt 1.0 or later, then rerun `socket-patch scan --mode <mode>` with the mode you used before | `socket-patch rollback` |

### Support policy

- **v5.x minor and patch releases** do not remove a format or mode from the matrix,
  and do not make a format refuse that v5.0 accepts. Bug fixes can still refuse a
  specific input that would otherwise produce a wrong result. Each refusal has an error
  code and a remedy.
- **A tier can move up** (Beta to Supported) in any release. A move down, or a new
  Legacy entry, is announced in the release notes and on this page.
- **Removing write support for a Legacy format** can happen only in a major release.
  The removed path becomes a refusal with an error code and a re-lock remedy. socket-patch
  keeps reading the format for `list`, `vex` and `rollback`, so state that an older
  socket-patch wrote can still be undone (or is refused with a version-control remedy,
  as hosted `bun.lockb` is today).

## npm hosted-mode notes

- **npm (package-lock.json / npm-shrinkwrap.json)** — every present npm lock is
  rewritten (npm <= 11 installs from a committed shrinkwrap, npm 12 only from
  package-lock.json). npm 12 never reads npm-shrinkwrap.json: on a
  shrinkwrap-only project it resolves the tree from the registry and writes a
  fresh package-lock.json, so the patch reaches npm <= 11 only. Hosted and
  vendored runs still rewire the shrinkwrap but warn
  (`redirect_npm_shrinkwrap_only` / `vendor_npm_shrinkwrap_only`), and `vex`
  omits those patches (`vex_npm_shrinkwrap_only`) while `list`, `rollback` and
  `remove` still manage them; rename the lock to package-lock.json (or commit
  a copy under that name) and re-run. A project whose own rc file tells the
  package manager not to read the lock (npm `package-lock=false`, yarn 1
  `--install.no-lockfile`, a yarn berry `lockfileFilename` naming another
  file) installs from the registry whatever the lock pins: `vex` then attests
  a hosted pin only from an installed tree that verifies, and omits a
  vendored pin (`vex_lock_not_read`). A Deno project's `deno install` reads
  only `deno.lock`, never an npm-family lock, so a hosted or vendored npm pin
  of a `name@version` that `deno.lock` also locks warns
  (`redirect_npm_deno_lock` / `vendor_npm_deno_lock`) and `vex` omits it
  (`vex_deno_lock_copy`); patch Deno installs with `--mode agent` after
  `deno install`. npm 12 defaults `allow-remote=none` and refuses the
  redirected tarballs (EALLOWREMOTE) unless the project `.npmrc` sets
  `allow-remote=all`, so the hosted run writes it (new file, or one appended
  line; once `rollback` / `remove` / the vendored takeover has restored the last
  hosted lock entry, a file holding only that line is deleted, otherwise the line
  stays with an `npm_allow_remote_left` warning) and always warns
  `redirect_npm_allow_remote` with the tradeoff (any url-resolved dependency is
  then admitted; sha512 pins stay enforced). Commit `.npmrc` with the lock. An
  explicit user `allow-remote=none` / `root` is respected (never rewritten or
  overridden) — in the project `.npmrc`, the user / global / builtin npm config,
  or an `npm_config_allow_remote` environment variable — and
  `--no-npm-allow-remote-config` opts out (install with
  `npm ci --allow-remote=all`). Vendored `file:` tarballs are unaffected by
  `allow-remote`: npm >= 11.14 gates them by `allow-file` (default `all`). An
  explicit `allow-file=none`, or `allow-file=root` while a vendored copy is
  transitive, makes every install fail EALLOWFILE; the vendored run keeps the
  setting, warns `vendor_npm_allow_file` with the remedy (`allow-file=all` in
  `.npmrc`, or `npm ci --allow-file=all`), and `vendor --check` fails. npm >= 8's
  `replace-registry-host` set to `always` (or to the hosted patch host) makes npm
  rewrite the hosted pins to the configured registry, so every install fails
  E404: the hosted run reads it from the same env / project / user / global /
  builtin layers and warns `redirect_npm_replace_registry_host` (set
  `replace-registry-host=npmjs` in the project `.npmrc`, or use vendored mode).
  npm >= 8's `omit-lockfile-registry-resolved=true` makes the next lock save
  (any `npm install`) drop the hosted pins' `resolved` URLs but keep their
  patched `integrity`, so every cold-cache install fails EINTEGRITY: the hosted
  run reads it from the same layers and warns
  `redirect_npm_omit_lockfile_registry_resolved` (set
  `omit-lockfile-registry-resolved=false` in the project `.npmrc`, or use
  vendored mode; a hosted re-run re-pins a stripped lock).
  npm 12 runs a dependency's install script only when `package.json`
  `allowScripts` approves it, and matches a version-pinned key
  (`"esbuild@0.19.12": true`, what `npm approve-scripts` writes) only against a
  registry tarball URL. Hosted and vendored lock entries are not one, so when a
  patched package with an install script is approved only by version, the run
  leaves the policy alone and warns `redirect_npm_allow_scripts` /
  `vendor_npm_allow_scripts`: approve it by name (`"esbuild": true`) to keep
  the script running (#1595).
  npm 6 ignores `resolved` for registry
  dependencies, so a redirected lockfileVersion 1 lock fails closed with
  EINTEGRITY under npm 6 (`redirect_npm_legacy_client`) and installs under npm
  >= 7. A lockfileVersion 2 lock's legacy `dependencies` mirror is rewired with
  `packages`, npm alias nodes (`"lp": {"version": "npm:left-pad@1.3.0"}`)
  included. npm 6 installs an aliased dependency from the configured registry
  whatever its `resolved` says, so under npm 6 an aliased hosted pin in a v2
  lock fails closed with EINTEGRITY too (`redirect_npm_legacy_alias_client`).
  Lockfile-only `vex` attests nothing for a package whose `packages` entry is
  wired while the v2 mirror still resolves it from the registry. A mirror
  node with no `resolved` but the patched `integrity` (what npm 7–12
  `npm install` leaves on a vendored v2 lock, since npm never writes a
  `file:` `resolved` there) still counts as wired for `vex` and
  `vendor --check`: npm 6 fails closed on that pin. Vendoring
  needs a lockfileVersion 2/3 lock (npm 6 still installs a vendored v2 lock
  from its legacy mirror, alias nodes included) and rewires both locks in npm
  12's dual-lock state. Majors 6–12 are measured in
  [npm compatibility](testing/npm-compatibility.md).
- **pnpm** — hosted rewriting supports legacy `shrinkwrap.yaml` (pnpm 1/2; never
  rewritten beside a `pnpm-lock.yaml`, which pnpm >= 3 reads instead; a
  project pinning pnpm 1/2 keeps `shrinkwrap.yaml` and leaves the stray lock),
  lockfileVersion 5.x (pnpm 3–7), 6.0 (pnpm 8), and 9.0 (pnpm 9–12).
  Early pnpm 1 locks with shrinkwrapVersion 3 and no positive minor version
  are refused because those installers discard hosted URLs; the tested
  pnpm 1 floor is 1.43.1. Upgrade and regenerate that lock, or use agent mode.
  Block and flow resolutions, scoped names, aliases, nested peer contexts,
  workspaces, nested Rush locks, and LF/CRLF line endings are handled. Every
  matching package instance is rewritten; an unsupported instance prevents
  confirming that dependency across the lockfile set. Rollback preserves the
  original resolution fragments.
  A `file:` directory or tarball dependency on the same `name@version` (a
  workspace member depending on `file:../../forks/left-pad` beside another
  member's registry `left-pad@1.3.0`) keeps installing the user's own bytes:
  no pin or `overrides` entry reaches it. The registry entry is still wired,
  and the scan names the copy (`redirect_copy_unpatched` in hosted mode,
  `vendor_copy_unpatched` in vendored mode); `vex` attests nothing for the
  package while the copy is in the lock. A directory's version is read from
  its `package.json` (#935); one that cannot be read (outside the project,
  missing) may be any version, so `vex` withholds every pin of the package
  the lock keys it by. The same holds for a copy pnpm fetches from a git
  remote or a url tarball (`left-pad@git+https://…` with its `version:`
  line), and, in pnpm 8 and older locks, for a second registry key of the
  same `name@version` (one per peer set) left on the registry.
  A workspace with `sharedWorkspaceLockfile: false` (`shared-workspace-lockfile=false`
  in `.npmrc` on pnpm 10 and older) installs each member from its own lock:
  run from the workspace root, every `packages:` member's `pnpm-lock.yaml` is
  pinned beside the root's (pnpm 7 writes no root lock at all), and `list`,
  `vex` and `rollback` read the member locks too. Member locks beside a root
  lock that lists member importers are stale and ignored. A member list the
  CLI cannot read (including a `pnpm-workspace.yaml` with no `packages:` key)
  is refused with `redirect_pnpm_member_locks_unresolved`.
  With `gitBranchLockfile` on (`git-branch-lockfile=true` in `.npmrc` on
  pnpm 10 and older), pnpm installs a branch from its own
  `pnpm-lock.<branch>.yaml` (in each member's directory too, when members
  keep their own locks), which neither mode can pin: while such a lock
  exists, hosted mode refuses the pnpm pins with
  `redirect_pnpm_git_branch_lockfile` and vendored mode with
  `vendor_pnpm_git_branch_lockfile`. Turn the setting off and run
  `pnpm install --merge-git-branch-lockfiles`, then re-run. With no branch
  lock, `pnpm-lock.yaml` is the lock pnpm installs from and is pinned as usual.
  With the `lockfile` setting off (`lockfile: false` in `pnpm-workspace.yaml`
  on pnpm 11 and newer, `lockfile=false` in `.npmrc` on pnpm 10 and older,
  or npm's `package-lock=false` that pnpm falls back to),
  pnpm never reads `pnpm-lock.yaml` and installs from the registry, so hosted
  mode refuses the pnpm pins with `redirect_pnpm_lockfile_disabled` and
  lock-only `vex` attests no hosted pin from that lock. Use `--mode vendored`,
  which pnpm applies through `overrides` without a lock; `vex` attests such a
  vendored pin only while the override map that pnpm reads still routes the
  package to its artifact, and omits it otherwise (`vex_lock_not_read`).
  pnpm >=11 checks every lock entry that records a tarball URL against a
  registry, so a hosted pin needs a setting in the root `pnpm-workspace.yaml`.
  For 9.0 root or member locks the CLI writes one of two, unless opted out
  with `--no-trust-lockfile-config`.
  **The registry route.** The patch service answers an npm registry document
  for each patch, in the directory the patch's tarball is served from. That
  directory is the patch's registry address: it never changes for the life of
  the patch and answers for that one package only. When every hosted pin of
  those locks has such an address (the patch service granted it one in this
  run, or an earlier run routed the pin and the files still route it), and
  every pnpm pin of the project (the same sources as the pnpm 9.0–10.4 rule
  below, at least one present) proves pnpm 11.20 or newer, the CLI declares
  one named registry per patch and routes each patched release to its own:

  ```yaml
  namedRegistries:
    socket-1417d719: https://patch.socket.dev/patch/npm/@a2ui/web_core/0.9.2/<token>/1417d719-…/
    socket-58f14d5a: https://patch.socket.dev/patch/npm/picomatch/2.3.1/<token>/58f14d5a-…/
  overrides:
    '@a2ui/web_core@0.9.2': 'socket-1417d719:0.9.2'
    'picomatch@2.3.1': 'socket-58f14d5a:2.3.1'
  ```

  The declaration lets pnpm verify the patched entries against the patch
  server while it keeps verifying every other entry, so nothing is trusted
  blindly. The override makes pnpm resolve the package there whenever it
  resolves again, so `pnpm add`, `pnpm update` and `pnpm dedupe` keep the
  patched tarball. pnpm writes an overridden release under its own key
  (`picomatch@socket-58f14d5a:2.3.1`) and records the overrides in the lock,
  so the CLI rewrites `pnpm-lock.yaml` to exactly that shape; a real pnpm
  re-locks it without changing a byte. Commit both files.

  A registry is named after its patch: `socket-` and the first eight hex
  digits of the patch UUID. If two patches of the project start with the same
  eight digits, or the project already has a registry of its own under that
  name, the name takes four more digits at a time until it is free.

  When a patch is replaced by a newer one for the same release, the new patch
  has a new UUID, so its registry has a new name and a new address. The next
  scan then changes the `namedRegistries` line, the override's value and, in
  the lock, the `overrides:` record and every key and reference of that
  release (`picomatch@socket-58f14d5a:2.3.1` becomes
  `picomatch@socket-<new id>:2.3.1`), along with the tarball and its
  integrity. Expect that diff, and commit it like any other scan result.

  What is yours stays yours. Your own `namedRegistries` and `overrides`
  entries are kept byte for byte, including a registry of yours named
  `socket` or one that happens to have a name of the CLI's shape: a registry
  is the CLI's only when its name is `socket-` plus the leading digits of a
  patch UUID and its address is that patch's directory on the patch server.
  If you override a package the CLI would route (by any selector for that
  package), your override is left alone and the run uses `trustLockfile`
  instead, and says so. A package you install from a registry of your own
  is yours whatever the registry is called: `leaf@socket:1.0.0` from a
  registry you named `socket` is never taken for npm's `leaf@1.0.0`.

  The route is cleaned up automatically when a patch is no longer needed, so
  nothing of it is left for you to delete. Cleanup is per patch: a patch's
  registry, its override and the lock's record of that override go together.
  They are unused once no lockfile resolves that release through the
  registry: you removed the dependency, upgraded it past the patched release,
  the patch was withdrawn or replaced, you ran `remove`, or the project left
  hosted mode. These commands take unused entries out:

  - `socket-patch scan` in hosted mode, on every run and with no extra flag.
    It drops the registry and the override of a package that left the lock
    from the workspace file and the lock together, and restores a withdrawn
    patch's release to the public registry.
  - `socket-patch repair`, in its cleanup phase. It reads only
    `pnpm-workspace.yaml` and the pnpm locks, so it works offline
    (`repair --offline`) and in CI without a token. It cannot know that a
    patch was withdrawn; that is the next scan's to restore.
    `repair --download-only` skips the cleanup.
    If your patches come from a patch server other than Socket's own, tell
    this command and `scan --prune` which one with `--patch-server-url`
    (or `SOCKET_PATCH_SERVER_URL`): they have no patch service answer to
    recognise it by. Without it they leave that server's registries
    alone, and say so, naming the host and that setting.
  - `socket-patch scan --prune` in any other mode or with no `--mode`, in the
    same pass that prunes `.socket/`.
  - `rollback`, `remove` and a switch to `--mode vendored`, for the packages
    they restore: the lock keys, the importer specifiers and the upstream
    resolution come back, and the package's registry, its override and the
    lock's record of it go in the same run. Other patches are not touched.

  `--prune` with `--mode hosted` adds nothing to remove: hosted mode keeps no
  `.socket/` state, which is what the flag sweeps in the other modes (the run
  says so), and the registry entries already go on every hosted scan. With
  the flag, `--json` output also counts them in `gc.removedRegistryEntries`.

  Every one of these lists what it removes (one line per entry, or one
  `registry_entry_unused` event under `--json`), and `--dry-run` lists the
  same and writes nothing. A registry's address is never printed, because it
  contains your access token for the patch. The workspace file and the lock
  always change together, so `pnpm install --frozen-lockfile` keeps passing.
  With several locks under one workspace file
  (`sharedWorkspaceLockfile: false`) an entry goes only when none of them
  uses it. Your own registries and overrides are never touched. A
  `pnpm-workspace.yaml` the CLI created is deleted, by whichever of these
  commands takes the last of the route out, once nothing else is in it; a
  file of yours gets its own bytes back. If a later scan finds that the
  project no longer qualifies (for example a new patch that has no registry
  address yet), it converts the project back to `trustLockfile` in the same
  run rather than leave a lock that is half routed. A scan that is granted
  only some of the project's patches (a scan of one subtree, a search that
  lists fewer patches) does not do that: the packages it was not granted stay
  routed as they are.

  Switching the project to agent mode (`scan --mode agent`) does not undo
  hosted patches: the lockfile keeps installing them through their
  registries, so the route stays too, and the run warns
  `hosted_wiring_retained` with the packages it concerns. To leave hosted
  mode, run `socket-patch rollback` (or `remove <package>`), or switch with
  `scan --mode vendored`; each takes the pins and their route out together.
  Anything left unused afterwards is removed by `repair` or `scan --prune`.

  Two things to know before you rely on the route. While a release is
  routed, its override holds every dependent whose range admits the patched
  version at exactly that version, so `pnpm update` does not move the package
  past it until a later scan finds a patch for the newer release or you run
  `socket-patch remove <package>`. It also reaches a dependent that is
  locked on a newer release today: if one package needs `leaf` at exactly
  the patched `1.0.0` and another asks for `^1.0.0` and is locked on `1.5.0`,
  the scan routes `1.0.0`, leaves the other on `1.5.0`, and tells you so in
  a note; the next `pnpm update` or `pnpm dedupe` (and `pnpm add` on pnpm
  11) then moves that package to the patched `1.0.0` as well. Installs from
  the committed lock are not affected. And two lock shapes stay on
  `trustLockfile`, because pnpm 11 and pnpm 12 lock them differently or
  resolve them around an override: a package installed both with and without
  the patched release as its peer, and a patched release that is another
  package's optional peer.

  A `trustLockfile: true` that an earlier run wrote is removed in the run that
  takes the route, when the file is still exactly what that run wrote (the
  file it creates, or a comments-only file plus the lines it adds); any other
  one is left alone, and the warning says the hosted patches no longer need
  it. A `trustLockfile: false` or a `pnpm_config_trust_lockfile` variable does
  not matter here. An address is only ever declared as a named registry: it
  answers for its one patched package and nothing else. Its version document
  is dated by the upstream release (or undated when that is unknown), so
  pnpm's default `minimumReleaseAge` does not hold back a new patch. A pin
  proves pnpm 11.20 when the lowest version it admits is 11.20 or higher
  (`11.28.13`, `^11.20.0`, `>=12`). Older pnpm 11 releases write a different
  lock for the same override, and a registry declaration without the override
  loses patched packages when pnpm resolves again (the measurements are in
  [pnpm hosted compatibility](testing/pnpm-compatibility.md)).
  **`trustLockfile: true`.** In every other case the CLI configures
  `trustLockfile: true`, which switches pnpm's lockfile verification off for
  the whole lock. When the patch service gave at least one pin a registry
  address, the warning names what kept the project off the registry route: the
  packages that have no address (one is enough), pnpm pins that do not prove
  11.20, a Bazel hub that reads the lock
  ([Bazel workspaces: npm](#bazel-workspaces-npm)), an override of yours for a
  patched package, a workspace file or a lock entry the edit cannot follow. A project with no pnpm pin is told that
  pinning pnpm 11.20 or later (for example with `packageManager`) and
  re-running the scan switches it to the registry route (not under
  `--no-trust-lockfile-config`, which writes neither setting). The key goes in
  the root `pnpm-workspace.yaml` unless
  explicitly disabled by the project or, for pnpm >=11, by a
  `pnpm_config_trust_lockfile=false` environment variable the scan runs with
  (pnpm reads it ahead of the file, so nothing is written and the warning names
  the variable). pnpm >=11 reads a `pnpm_config_*` variable only when it is
  `true` or `false` (pnpm 12 trims surrounding spaces first, pnpm 11 does
  not); any other value (empty, `null`, `undefined`, `0`) is ignored for the
  file, so the CLI ignores it too and writes the key.
  This skips registry re-verification for the whole lock; tarball integrity
  remains enforced. pnpm <=10 needs neither setting. For both, an existing
  `pnpm-workspace.yaml` with no keys (empty or only comments) gets the
  root-only `packages:` list with the key, because pnpm 8–10.4 refuse a
  workspace file that has keys but no `packages`. When the lock lists
  workspace members (pnpm 8–10.4 read a keyless file as every nested
  package), the file is left alone. A project with no
  `pnpm-workspace.yaml` (or a keyless one) that pins pnpm 9.0–10.4 (`packageManager`,
  `devEngines`, `engines.pnpm`, or the pnpm that last installed
  `node_modules`) gets no file: there a root-only workspace makes
  `pnpm add <pkg>` fail with `ERR_PNPM_ADDING_TO_ROOT`. Re-run the scan after
  upgrading to pnpm >=11. When no pin says which pnpm runs, the file is
  created, and pnpm 9.0–10.4 then need `pnpm add -w <pkg>`. Vendored mode
  follows the same rule for its `overrides:` mirror.
  **Vendored build approvals (#1597):** pnpm 10.34.2+ and 11.5.3+ match
  `allowBuilds` / `onlyBuiltDependencies` against the id a package installs
  as, and a vendored package installs as `name@file:.socket/vendor/npm/…`.
  A decision keyed by the name (`sp-build`, `sp-build@1.0.0`) would stop
  applying: pnpm 10 skips the approved script, pnpm 11 and 12 fail every
  install with `ERR_PNPM_IGNORED_BUILDS`. Vendoring adds the same decision
  under the vendored key next to the user's entry (`pnpm-workspace.yaml`, or
  `package.json#pnpm` for pnpm 10), replaces a key an older patch left, and
  revert removes it. The key is written only when the project's pnpm pins
  (`packageManager`, `devEngines`, `engines.pnpm`, or the pnpm that last
  installed `node_modules`) say 10.34.2+ (within 10.x), 11.5.3+ (within 11.x) or
  12+: pnpm 10.20–10.34.1 and 11.0–11.5.2 refuse such a key (`ERR_PNPM_INVALID_VERSION_UNION`) and still match the name, so
  nothing is needed there. Without a usable pin, or for a decision the
  rewriter can't extend (a flow-style value such as
  `onlyBuiltDependencies: [pkg]`, a non-boolean `allowBuilds` value), the
  setting is left alone with the `vendor_pnpm_build_approval_lost` warning
  naming the key to add. Re-run the scan after upgrading pnpm past 10.34.1 or 11.5.2.
  **Reinstall after redirecting:** a successful warm-cache install can retain
  upstream bytes. Use a clean install tree and an empty store; `--force` is not
  a reliable substitute. Run `socket-patch vex` after installation to verify
  the patched files. See the [compatibility matrix and workflow](testing/pnpm-compatibility.md).
- **yarn classic** — the `yarn.lock` entry's `resolved` / `integrity` are
  rewritten to the hosted tarball. `resolved` always carries the tarball's
  `#<sha1>` fragment: yarn 1 names its cache slot after it, so a fragmentless
  URL would share the slot of an unpatched copy of the same version and a warm
  cache would install those bytes (or fail the integrity check). For an entry it
  hasn't pinned yet (or a grant with no sha1), the scan downloads the served
  tarball and checks it against the grant's sha512. It pins the sha1 of those
  bytes when the grant has none, and it compares the tarball's own
  `package.json` with the lock: yarn 1 installs only the dependencies the lock
  names, so when the patch adds a dependency (or changes a range) that no
  `yarn.lock` block locks, the pin is refused with
  `redirect_yarn_classic_dep_manifest_unlocked` (lock the new descriptor first,
  for example with `yarn add`, then re-run). A dependency the entry's sub-map
  already names is left alone even when no block is keyed by it: yarn keys
  those blocks by the registry metadata's ranges, which can differ from the
  tarball's `package.json`. When every descriptor is already locked, the
  entry's dependency sub-maps are rewritten to match, normalised the way yarn
  1 writes them (`redirect_yarn_classic_dep_manifest_rewritten`). Vendored mode refuses the
  same case with `vendor_dep_manifest_unlocked`. If the download, the check or
  the `package.json` read fails, the patch is skipped as
  `npm_tarball_unavailable`. A project that sets `yarn-offline-mirror`
  is refused with `redirect_yarn_classic_offline_mirror`. The mirror is
  resolved the way yarn 1 resolves it: the project's `.yarnrc` / `.npmrc`,
  the user's (`~/.yarnrc`, which `yarn config set` writes, and `~/.npmrc`),
  `<prefix>/etc/yarnrc` / `npmrc`, every ancestor directory's, and the
  `YARN_*` / `npm_config_*` environment variables. A file saved with a UTF-8
  BOM counts too, and `false` in a higher-precedence layer turns the mirror
  off. In a workspace, a mirror that yarn 1 run in a member directory
  would use is refused the same way, since installs run there read the
  root's lock. Such a run reads the member's own `.yarnrc` / `.npmrc` as
  the project files and the root's only as an ancestor's, below the user
  and global ones, so a root `false` does not turn off a user mirror for
  it; set `false` in the member too. Yarn looks mirror tarballs up by
  file name, and the hosted tarball has the same name as the upstream one
  already in the mirror, so installs would get the unpatched bytes and fail
  the integrity check. Use `--mode vendored` there; it works with a mirror.
- **yarn berry** — the redirect pins the way yarn does for a root `resolutions`
  entry (cacheKey `10c0` / yarn 4): `package.json` routes the locked descriptor
  (`"left-pad@npm:^1.3.0"`) to the hosted tarball and only that `yarn.lock` entry
  is re-keyed by it. A dependency declared through a yarn catalog (`"catalog:"`,
  yarn 4.10+) is matched before yarn expands the catalog, so each `.yarnrc.yml`
  catalog that resolves to the locked range is routed too (`"left-pad@catalog:"`,
  `"left-pad@catalog:<name>"`). Yarn then fetches it without npm registry credentials and
  hardened mode accepts it. The re-keyed entry is written the way yarn writes
  it, with its fields in yarn's order and its `bin:` map taken from the served
  tarball's own `package.json`. Yarn's npm resolver gives a package that runs
  `node-gyp` in a script (every package shipping a `binding.gyp`: nan,
  bufferutil, utf-8-validate, …) an implicit `node-gyp: "npm:latest"`
  dependency, which yarn never gives a tarball entry, so the pin drops it and,
  when nothing else needs node-gyp, the lock entries only it reached; vendored
  mode does the same, and `vendor --revert` puts them back. Hosted `rollback`
  puts the dependency back while the lock still resolves node-gyp; otherwise it
  warns `yarn_berry_node_gyp_unresolved` (run `yarn install` once). For an entry
  that has a `bin:` map or that implicit dependency, the scan
  downloads the served tarball to read it. If that download fails, the patch
  is skipped as `npm_manifest_unavailable`. A user-authored `resolutions` entry for the package
  is never overwritten (`redirect_yarn_berry_resolutions_conflict`), and
  `.yarnrc.yml`'s `compressionLevel` must stay 0. A range of the package
  added after the pin (say a workspace member's `"left-pad": "1.3.0"`) is not
  routed by any selector, so yarn locks it as a separate registry entry and
  installs that copy unpatched; re-running `scan --mode hosted` adds a selector
  for it and folds its entry into the pinned one. `rollback` and `remove` merge
  the restored registry entry into such an entry (or into an `npm:` alias entry
  of the package), as yarn writes two entries with one resolution, so
  `--immutable` installs keep passing; `vendor --revert` does the same for a
  vendored package. The node-modules linker
  is e2e-covered; PnP is untested for hosted — the lock rewrite fires, but PnP's
  `.yarn/cache` resolution isn't exercised. CRLF locks — what yarn writes on Windows,
  and what a `core.autocrlf` checkout produces anywhere — are rewritten in their own
  line ending (a BOM is kept); a lock or root `package.json` mixing CRLF and LF is
  refused (`redirect_yarn_berry_mixed_line_endings`, the same decision vendored mode
  takes) until `yarn install` normalizes it. See
  [yarn berry compatibility](testing/yarn-berry-compatibility.md).
- **yarn `npm:` aliases (classic & berry)** — a lock entry that consumes the patched
  package only through an alias descriptor (`"safe-pad@npm:left-pad@^1.3.0"`) is left
  untouched, with a `redirect_yarn_classic_alias_skipped` /
  `redirect_yarn_berry_alias_skipped` warning naming the entry — that copy keeps the
  unpatched artifact. The reverse shape — an alias of the patched NAME pointing at a
  different package (`"left-pad@npm:some-fork@^1.3.0"`, the fork-substitution idiom) —
  is never rewritten: it resolves a different package.
- **yarn copies under another dependency name (classic & berry)** — yarn keys a `file:`
  tarball or directory, a URL tarball and a berry `portal:` / `link:` / `exec:` / git
  dependency by the name the depender gave it: `"lp2": "file:./left-pad-1.3.0.tgz"` locks as `lp2@file:…`,
  while `node_modules/lp2` is left-pad@1.3.0. No pin or vendored wiring of `left-pad`
  reaches that copy, so it stays unpatched. Which package such a copy is comes from the
  copy itself (the tarball's or directory's `package.json`, or the registry package a
  URL's path names; a berry `portal:` / `link:` target's `package.json` also gives the
  version, since the lock records `0.0.0-use.local`). The copy is read wherever yarn
  installs it from, including a `file:` path outside the project (`file:../shared/lp`),
  and a tarball's `package.json` is found under whatever top-level directory it has, as
  yarn strips the first path segment. A copy whose package can't be read (a non-registry
  URL, a missing directory, a berry `exec:` script or a berry git remote such as
  `git+ssh://…`, which hold no package until yarn builds or clones them) is treated as
  possibly any package at its lock version: it
  is named as a copy it may be, and `vex` attests nothing that lock wires at that
  version. An absolute path (`portal:/home/me/lp`, `file:/abs/lp.tgz`) is never read, as
  the lock is untrusted input; a `portal:` / `link:` copy whose `package.json` isn't
  read (an absolute path, or a relative target that is missing or empty, such as a git
  submodule CI didn't check out, or whose `package.json` is no JSON, such as a Git LFS
  pointer, or whose `package.json` names no package) has no version either, so it may
  be any version of any package and `vex` attests nothing that lock wires. One whose
  `package.json` names a package but no version may be any version of that package. An
  empty `name`, or one no npm package can carry (`"../x"`, `" left-pad"`), names no
  package, and an empty or non-semver `version` (`""`, `"v1.3.0"`) names no version, for
  every copy whose `package.json` is read (#1598). A
  `portal:` to a directory with no `package.json` (a `.gitkeep` placeholder a fetch step
  fills) is unknown too, since yarn refuses to install a portal without one; only a
  `link:` to a non-empty directory with no `package.json` is not a package copy. Use a
  relative path to let the copy be read. Hosted mode still pins the
  registry entry and names the copy (`redirect_copy_unpatched`, unless a yarn classic
  skip warning already names it); vendored mode still wires the registry entry and names
  it (`vendor_copy_unpatched` for berry; the yarn classic codes below for classic); and
  `vex` never attests the package from that lock while the copy is there. When the
  package is installed only through such copies, vendoring refuses with
  `vendor_lock_entry_not_rewritable` naming them, since `yarn install` can't help.
- **yarn classic and yarn 2+** — installing with yarn 2+ (berry) migrates a classic (v1)
  `yarn.lock` and re-resolves every entry from the registry, dropping hosted pins and
  vendored wiring alike, so the packages install unpatched. A run that leaves such a pin
  warns (`redirect_yarn_classic_berry_migration_risk` / `yarn_classic_berry_migration_risk`)
  unless `package.json` pins yarn classic through `"packageManager": "yarn@1…"`.
- **yarn classic workspaces, vendored** — vendored mode wires
  `resolved "file:./.socket/vendor/…"`, relative to the workspace root. Yarn 1 looks a
  relative `file:` tarball up from the directory it runs in, so on a cold yarn cache
  `yarn install`, `yarn add` or `yarn workspace <name> …` run from a member directory
  fails ("Tarball is not in network and can not be located in cache"), whether or not the
  member depends on the patched package (yarn 1.7.0, 1.10.1 and 1.22.22; no relative
  spelling installs from both). Installs from the workspace root work, as does
  `yarn install --cwd <workspace root>` run from a member directory, and either warms the
  cache for later member-directory commands. Vendoring adds nothing to the members to
  change this: yarn fetches the whole workspace from any member, so a tarball copy would
  be needed in every one of them. A vendored run in such a project warns
  `yarn_classic_workspace_member_install_risk`; hosted mode, which pins an absolute URL,
  is not affected.
- **yarn classic git dependencies** — yarn 1 fetches a git pattern (`git+https:`,
  `git+ssh:`, `git:`, `ssh:`, a `….git` url, or a bare `https://github.com/<owner>/<repo>`)
  with git, using the lock entry's `resolved` as the remote, so a rewritten `resolved`
  breaks every install. Hosted and vendored modes leave such an entry untouched
  (`redirect_yarn_classic_git_skipped` / `vendor_yarn_classic_git_entry_skipped`) and
  that copy stays unpatched; `vex` never attests the package from that lock while the
  git copy is there, and rollback refuses a hosted pin an older release wrote on one.
- **yarn classic non-registry tarballs** — a `file:` tarball (`left-pad@file:./x.tgz`),
  a URL (`left-pad@https://host/fork.tgz`) or a hosted-git shorthand (`owner/repo`,
  `github:owner/repo`, which yarn locks to a GitHub codeload tarball) is the project's
  own artifact, not the registry package the patch is built for. Hosted and vendored
  modes both pin to Socket's build of the registry package, so they leave such an
  entry untouched (`redirect_yarn_classic_non_registry_entry_skipped` /
  `vendor_yarn_classic_non_registry_entry_skipped`) and that copy stays unpatched;
  rollback refuses a hosted pin an older release wrote on one, since its original
  `resolved` was never recorded. Such a copy an older release already pinned installs
  Socket's build, not an unpatched one: a hosted re-run names it
  (`redirect_yarn_classic_non_registry_legacy_pin`, restore `yarn.lock` from version
  control to undo it), and a vendored re-run keeps the existing wiring in sync and names
  it (`vendor_yarn_classic_non_registry_legacy_wiring`, undone by `vendor --revert`).
- **yarn classic entries with no `resolved`** — a registry entry with no `resolved`
  line is a stale lock with no tarball to repoint; `yarn install` re-locks it from the
  registry. Hosted mode leaves it untouched and names it
  (`redirect_yarn_classic_unresolved_entry_skipped`); vendored mode skips it
  (`vendor_link_entry_skipped`).
- **yarn classic `file:` directory dependencies** — yarn 1 copies a `file:` directory
  (an entry with no `resolved` tarball) into `node_modules`, so no lock rewrite reaches
  that copy. Hosted and vendored modes leave the entry untouched
  (`redirect_yarn_classic_directory_skipped` / `vendor_link_entry_skipped`, naming it) and
  that copy stays unpatched; `vex` never attests the package from that lock while the
  copy is there. This holds whatever dependency name the project gives the copy: yarn 1
  locks `"lp2": "file:./lpdir"` as `lp2@file:./lpdir`, so which package it is comes from
  the directory's `package.json` (or a `file:` tarball's manifest, or a registry tarball
  URL's path; hosted scans name a URL copy with
  `redirect_yarn_classic_non_registry_entry_skipped` and a `file:` tarball copy with
  `redirect_copy_unpatched`, and vendored scans name either with
  `vendor_yarn_classic_non_registry_entry_skipped`). A git copy under another name
  records no package name in the lock and is not detected. When every entry of the package is such a copy (git, `file:` directory,
  non-registry tarball or `link:`), vendoring refuses with `vendor_lock_entry_not_rewritable` naming them,
  since `yarn install` can't help.
- **yarn classic bundled copies** — yarn 1 unpacks a package's `bundleDependencies`
  from its tarball into the package's own `node_modules` and `yarn.lock` records
  nothing about them (#758), so no pin or vendored wiring reaches such a copy. When
  `yarn.lock` holds a Socket wiring, the installed `node_modules` is read for them:
  hosted scans name a bundled copy of the patched `name@version` with
  `redirect_copy_unpatched`, vendored scans with `vendor_bundled_instance_skipped`, and
  `vex` attests nothing for the package while the copy is installed. A lock-only `vex`
  (no `node_modules`) can't see the copy.
- **bun** — text `bun.lock` lockfileVersion 0 to 3: 0 is the `--save-text-lockfile`
  opt-in lock of Bun 1.1.39–1.1.45, 1 the 1.2–1.3 default, 2 the 1.4+ default, and 3 what
  Bun 1.4+ writes when `package.json` has a nested override or a yarn-style path
  resolution (only the lock's head differs); all four
  emit one `packages` grammar, so registry entries rewrite identically. Any other or
  missing version, or a `packages` section outside bun's single-line grammar, is refused
  `redirect_bun_lock_unsupported` (a newer version means "update socket-patch" — re-locking
  would reproduce it). A version-0 lock holding `workspace:` packages is refused
  `redirect_bun_workspace_unsupported`: frozen installs of that grammar cannot keep the
  hosted tuple; delete `bun.lock` and re-lock with Bun ≥ 1.2 (which writes lockfileVersion
  1, accepted) — a plain in-place `bun install` bumps the version only when a workspace
  depends on another workspace (root → member), otherwise Bun 1.2.0 keeps version 0 and
  1.2.23+ fail to resolve. Version-1 and version-2 workspace locks (nested versions included)
  are rewritten. Binary `bun.lockb` files are read and patched natively in
  hosted and vendored modes, including lockfile-only discovery. The CLI updates
  package resolutions, integrity records and Bun's metadata hash without spawning
  Bun or creating a text lock. Text `bun.lock` takes precedence when both exist;
  malformed binary locks fail closed before patching. Hosted → vendored and
  vendored → hosted conversions both work
  in place (mode takeover) — on a lock the vendored backend refuses (a pre-version-2
  `workspace:` lock) `vendor` reports the refusal before the upstream restore and leaves the
  purl hosted-patched — and `rollback <purl>` / `remove <purl>` restore one of several
  hosted bun packages to its upstream registry entry. A hosted `bun.lockb` entry is not
  rolled back (v5.0 keeps no hosted ledger, and a rebuilt binary record is not byte-exact
  for every lock): rollback and remove refuse it with the `git checkout -- bun.lockb`
  remedy (then `bun install --force`: a plain install keeps the patched copy), while the hosted → vendored takeover rebuilds its npm registry record natively
  and vendors over it. Each restore reads the package's version document from the
  registry Bun resolves it against (`.npmrc` / `bunfig.toml` scope and default
  registries, `BUN_CONFIG_REGISTRY` / `NPM_CONFIG_REGISTRY`), read from the project's
  files and the user's own: `$XDG_CONFIG_HOME/.npmrc` or `~/.npmrc`, and the global
  `$XDG_CONFIG_HOME/.bunfig.toml` or `~/.bunfig.toml` (#1276). Bun ≥ 1.4 takes a bunfig
  key over an `.npmrc` one and Bun ≤ 1.3 the reverse, so when they disagree on a package
  of a lockfileVersion-0/1 `bun.lock` or a `bun.lockb` (either Bun may install it) the
  restore refuses that pin with the checkout remedy. It sends the credentials
  those settings give it — a bunfig `token` or `username` / `password` (`$VAR`
  expanded only for `NPM_TOKEN`, `NODE_AUTH_TOKEN` and `BUN_AUTH_TOKEN` in the project's
  files, any variable in the user's own; any other
  variable expands to nothing, so a project's config cannot send other secrets; in a
  registry URL only its `user:password@` part expands, which is sent as the
  `Authorization` header and never printed or written into the lock), else the `.npmrc` `//host/path/:_authToken` / `_auth` / `username` +
  `_password` covering the registry URL (`BUN_CONFIG_TOKEN` is not read); a registry
  that still cannot be read falls back to the default registry's document with an
  `upstream_registry_fallback` warning. Bun's hoisted linker keeps an installed copy whose lock entry
  returns to the registry record (a plain `bun install` reports no changes), so after
  `rollback`, `remove` or `vendor --revert` the patched bytes stay in `node_modules` until
  `bun install --force` (or deleting `node_modules`); `redirect_bun_reinstall_required` /
  `vendor_bun_reinstall_required` say so whenever such a copy may be installed.
  Bun verifies the sha512 of URL and local-tarball tuples only from 1.3.10 (registry
  tuples from 1.2.0), so on 1.1.39–1.3.9 a hosted or vendored rewrite removes digest
  enforcement for the patched package. Every boundary here is measured against real
  Bun releases — see [Bun compatibility](testing/bun-compatibility.md).

  Four things to know when a Bun project is patched in hosted or vendored mode
  (details and measurements on the compatibility page):

  - **`bun update` removes the patch.** A bare `bun update`, or `bun update <patched
    package>`, re-resolves the entry from the registry and writes the registry tuple
    back, with exit 0 and no warning, even when the version does not change. Every other
    everyday command keeps the pin: `bun install` (plain, `--force`, `--frozen-lockfile`,
    `--production`), `bun ci`, and `bun add` / `bun remove` / `bun update` of *other*
    packages. Run `socket-patch scan` again after a `bun update`. In vendored mode
    `socket-patch vendor --check` exits 1 when a committed patch is no longer wired, so a
    CI step catches it; hosted mode keeps no record to compare against, so there the
    lockfile diff is the only signal.
  - **Packages with install scripts on Bun's default trusted list** (`sqlite3`,
    `better-sqlite3`, `sharp`, `esbuild`, …) are patched only when `package.json` declares
    `trustedDependencies`. Bun 1.3.5+ trusts a default-listed package only while it
    resolves from the npm registry, so pointing it at a patched tarball would make
    `bun install` skip its install script and exit 0. Such a package is left on the
    registry with `redirect_bun_default_trust_skipped` (vendored:
    `vendor_bun_default_trust_refused`); add it to `trustedDependencies` and re-run, or
    use agent mode.
  - **Copies bundled inside another package's tarball are not patched.** A dependency
    that ships its own dependencies (`npm` does, so anything that depends on `npm`, such
    as `semantic-release`, has a few hundred) is unpacked from that tarball, whatever the
    lock says. Those copies are reported (`redirect_bun_bundled_instance_skipped`,
    `vendor_bundled_instance_skipped`) and never attested by `vex`; agent mode patches
    them where they are installed.
  - **A hosted or vendored package disappears from `bun audit` and `bun outdated`.** Bun
    checks registry resolutions only, so it stops reporting the package at all, including
    advisories the applied patch does not fix. `socket-patch scan` counts those on the
    package's row (`2 unpatched`) and names them under `--verbose`.

  In vendored mode the patched tarballs are files in the repository, so a build that
  copies only `package.json` and `bun.lock` before `bun install` (a common Dockerfile
  layer) fails with `ENOENT extracting tarball`: copy `.socket/vendor/` (and, for a
  binary-lock workspace, each member's `.socket/vendor/`) in the same step.
- **vlt** — `vlt-lock.json` default-registry nodes of the patched `name@version` keep
  their DepID and get the patched sha512 in slot [2] and the hosted URL in slot [3]; see
  [vlt notes](#npm-vlt-notes).

## npm: which `node_modules` trees are crawled

A local scan collects the project root's `node_modules` and every
`node_modules` found in the directories below it (workspace members, nested
projects), at any depth. The walk does not descend into symlinked
directories, hidden directories (`.git`, `.cache`, ...), `node_modules`
itself (packages are read from it, not searched for workspaces), or
directories named `dist`, `build`, `coverage`, `tmp`, `temp`, `__pycache__`
or `vendor`, except that a workspace member the root `package.json`
`workspaces` field declares (a directory holding a `package.json` that any
of npm, yarn or Bun reads the patterns as listing, such as `packages/build`,
`vendor/lib`, or a GitHub Action kept at `.github/actions/<name>`) still has
its own `node_modules` crawled. A hidden directory counts only where a
pattern spells its dot (`.github/actions/*`, `.config/tool`); a wildcard
alone never reaches one. npm, yarn and
Bun install a member's unhoistable dependencies there from the root lock.
It also prunes every directory that carries a
[Cache Directory Tagging](https://bford.info/cachedir/) `CACHEDIR.TAG` file
beginning with the standard signature — a cargo `target/`, and caches of
other tools that follow the convention: neither that directory's own
`node_modules` nor anything below it is crawled. The scan root is always
crawled, even when it is tagged itself. A `CACHEDIR.TAG` that lacks the
signature, is a directory or is a symlink prunes nothing.

Agent and report-only scans patch every crawled copy in place. Hosted and
vendored scans rewire only the scan root's lockfiles, so a patched package
that only a nested, independent npm project installs (a directory below
the root with its own lockfile, such as `tools/x/` holding
`package-lock.json`, that is not a workspace member installed from the
root's lock; or one with a `package.json` and `node_modules` installed
without a lockfile, such as under `package-lock=false`, that no workspace
lists) is left alone with a `nested_project_skipped` warning. The
warning names the project directory; pass it as a PATH
(`socket-patch scan --mode vendored tools/x`) to patch that project. A
project without a lockfile needs one first (`npm install
--package-lock` there), or can be patched in place with
`socket-patch scan --mode agent tools/x`.

Inside each `node_modules`, the package stores of isolated layouts are
walked too, since they are the only home of transitive dependencies:
pnpm's virtual store (`node_modules/.pnpm`, pnpm <= 3's
`node_modules/.registry.*`, or the directory a `virtualStoreDir` setting
moved it to, as recorded in `node_modules/.modules.yaml`), vlt's
`node_modules/.vlt`, Bun's isolated-linker store `node_modules/.bun`,
Deno's isolated `nodeModulesDir` store `node_modules/.deno`, and
`node_modules/.store`, written by npm's `install-strategy=linked` and by
Yarn 4's pnpm linker (where each entry's `package/` dir is the copy), or
the folder a Yarn `pnpmStoreFolder` setting moved that store to (from the
nearest `.yarnrc.yml` that sets it, the home `.yarnrc.yml`, or
`YARN_PNPM_STORE_FOLDER`, while the active linker is `pnpm`).
pnpm 7–12 keep the entry of a removed or upgraded-away package for a
while after `pnpm remove` or an upgrade (pnpm 7–11 for up to 7 days, pnpm
12 until `pnpm prune`). Scans skip such an entry when the current
lockfile pnpm writes in the store (`node_modules/.pnpm/lock.yaml`) no
longer lists its package, so a vendored scan does not fail on a package
the install dropped. `rollback` still reaches it. A recorded virtual store outside the project is not
listed: other projects on the machine load the same files, so patching it
in place would patch them as well. For pnpm's global virtual store
(`enableGlobalVirtualStore`, `<store>/v<N>/links` under the pnpm store
directory), only the entries this project reaches are walked: its
`node_modules/<dep>` links into the store, and each entry's dependency
links on to other entries. A workspace member's `node_modules` has no
`.modules.yaml` of its own (pnpm writes it only at the workspace root), so
the root's record is used, and the member's own links seed the walk. Agent-mode `apply` and `rollback` then fail on
those copies, direct and transitive alike, instead of writing through
them, and never report a transitive one as "not installed". Bun's global
store (`[install] globalStore = true` in `bunfig.toml`, or
`BUN_INSTALL_GLOBAL_STORE=1`, Bun 1.3.14 and later) is handled the same
way: each `node_modules/.bun/<entry>` is then a link into
`<cache>/links/<entry>-<hash>` in Bun's install cache, and those linked
entries are walked (so `vex` checks their bytes) but refused by agent-mode
`apply` and `rollback`. PDM's symlink install
cache gets the same treatment: with `install.cache` and
`cache_method = symlink` (PDM 2.0–2.12), `site-packages/<pkg>` links into
`<cache>/packages/<wheel>/lib`, and that package is refused too. The error
names the store and how to get a private copy (disable the global virtual
store or Bun's `globalStore`, or `pdm config install.cache_method
hardlink`, then reinstall), or
use hosted or vendored mode.

Agent-mode `apply` and `rollback` also fail, dry run included, on a
`node_modules/<dep>` (or `node_modules/@scope/<dep>`) link whose real path
is outside every `node_modules` tree. Package managers link that way only
to first-party source: an npm, Yarn, pnpm or Bun workspace member, a
`file:` or `link:` directory dependency, or an `npm link` target. That
source is not an installed copy of the registry package, and no reinstall
restores it, so it is never overwritten. Patch it directly instead (vendored
mode refuses it the same way, with `vendor_workspace_member`; when an npm lock
also holds a registry copy of the same `name@version`, that copy is still
vendored and the local source is skipped with `vendor_workspace_member_skipped`).
Links into a store inside a `node_modules` tree, including a workspace member's link
into the root `node_modules/.pnpm`, are patched as usual. So are links into
Yarn's pnpm-linker store relocated outside `node_modules`, but only for an
active Yarn pnpm install (a `yarn.lock`, and `nodeLinker: pnpm` with a
`pnpmStoreFolder`, each read from the environment, the nearest
`.yarnrc.yml` that sets it, or the home `.yarnrc.yml`, as Yarn reads
them), only to the
`<store>/<entry>/package` directory of a package Yarn installs as a copy
(`npm:`, peer-instantiated `virtual:`, a `file:` tarball, `patch:`, a URL or
git; never `workspace:`, `portal:` or `link:`), and only when that store
does not contain the project.

The same rule covers every ecosystem, as a containment check rather than a
list of known stores: agent-mode `apply` and `rollback` refuse, dry run
included, any directory they would write into that resolves outside the
install tree it was found in. Each directory a patch writes into must
resolve inside the package directory (a `flit install --symlink` package
linked from `site-packages` into its source is refused), and a Composer
package must resolve inside its vendor dir: a Composer path repository
symlinks `vendor/<ns>/<name>` to your own source by default, and that
source is patched directly, or installed as a copy with the repository's
`symlink` option set to `false`. A package that a package manager links into
`site-packages` from its own prefix (Homebrew links formula Python packages
in from the Cellar, Nix from the store) resolves outside the install tree
too and is refused the same way; install it into a virtualenv to patch it.
`rollback` refuses the same directories: a file an older socket-patch
patched in place there is restored from that source's version control.

Every command that looks for installed npm copies walks these same trees, not
only `scan`. A package installed only under a pruned directory is therefore
"not installed" to `scan --prune` / `--sync`, which garbage-collect its
manifest entry and blobs unless a lockfile still resolves it, and `apply`,
`rollback`, `remove`, `repair`, `vendor` and `vex` do not find that copy:
`remove` drops the manifest entry but leaves the copy's patched files in
place.

## npm: Rush monorepos

A Rush repo has no root `package.json`/lockfile pair — its pnpm source-of-truth locks
live at `common/config/rush/pnpm-lock.yaml` (plus one per subspace under
`common/config/subspaces/<name>/`).

- **Hosted** ✅ — `scan --mode hosted` discovers and repoints those locks in place
  (subspaces included). On pnpm >=11 the install needs extra Rush settings (below).
- **Agent** ✅ — works through the generated project symlink farm.
- **Vendored** ✅ — on lockfileVersion 9.0 (pnpm 9 and newer) with pnpm workspaces
  (`useWorkspaces: true`), subspaces included. Run it from the folder that holds
  `rush.json`. It edits project `package.json` files for direct dependencies (below).

### Vendored mode in a Rush repo

`rush install` copies each lock into `common/temp` (a subspace's into
`common/temp/<name>`) and runs pnpm there, so the lock spells the vendored tarball
relative to that folder (`file:../../.socket/vendor/npm/<uuid>/…`). Vendoring commits the
tarball and edits three kinds of file:

- **The Rush lock(s) that install the package.** The entry is rekeyed to the tarball, the
  same fragments as in a plain pnpm project.
- **`pnpm-config.json`** (the subspace's own, else `common/config/rush/`). Each package
  that depends on the patched one gets a `globalOverrides` entry,
  `"<parent>@<version>><name>@<version>"`. Rush hands these to pnpm, so the patch survives
  `rush update` and `rush update --full`. Every lock that reads the same config gets the
  entry in its `overrides:` too, as Rush itself writes it.
- **The `package.json` of every project that lists the package itself.** Its spec becomes
  `file:<path to the tarball from that project>`.

That last edit is specific to Rush. `rush install` compares each project's `package.json`
with the lockfile and fails when they differ, so a direct dependency cannot be redirected by
an override alone, the way it is in a plain pnpm project. The run names the files it edited
(`vendor_rush_package_json_edited`), and `vendor --revert` puts the registry versions back.
Things to know:

- **Published projects.** A project the repo publishes (`shouldPublish` or a version policy
  in `rush.json`) would publish the `file:` spec, which its consumers cannot install. The
  warning names such projects: depend on a fixed release there.
- **`ensureConsistentVersions`.** A `file:` spec is relative to each project's folder, so
  projects at different folder depths get different spellings, which that policy rejects.
  Vendoring refuses this case (`vendor_rush_inconsistent_versions`) and writes nothing. List
  the specs it names under `allowedAlternativeVersions` in `common-versions.json` and run it
  again. A `preferredVersions` entry for the package counts as one more spec.
- **Peer dependencies.** A project that lists the package under `peerDependencies` gets it
  installed by pnpm and locked under `dependencies`, with or without a `devDependencies`
  spec beside it. The project has no spec vendoring can move, so the package is refused
  (`vendor_rush_project_manifest`). Hosted mode covers it.
- **Subspaces that share a `pnpm-config.json`.** The overrides go to every lock that reads
  the config. When another of those locks resolves the package to a different release for
  the same dependent, pnpm would move it to the vendored release the next time it resolves,
  so vendoring refuses (`vendor_rush_unsupported`). Give one subspace its own
  `pnpm-config.json`.
- **`extends` in `pnpm-config.json`.** Rush replaces an inherited `globalOverrides` table
  with the one the extending file declares. Vendoring writes only into a table the file
  already has, and refuses otherwise (`vendor_rush_unsupported`): add the table, holding the
  entries the file inherits.
- **New dependents.** A project or package that starts depending on the patched version
  later installs the registry copy until `socket-patch scan --mode vendored` runs again.
  Installs keep working in the meantime, and `vex` and `vendor --check` report the
  unpatched copy.

- **Build scripts.** A decision in `pnpm-config.json` that lets the package run (or
  forbids) its install scripts by name (`globalOnlyBuiltDependencies`,
  `globalNeverBuiltDependencies`, `globalAllowBuilds`) stops matching once the package
  installs from the tarball. Vendoring does not carry it over; the
  `vendor_pnpm_build_approval_lost` warning names the id to add.

With `preventManualShrinkwrapChanges` on, run `rush update` once after vendoring. It refreshes
the lock hash in `repo-state.json` and changes nothing else (`vendor_rush_repo_state_stale`).
The same holds for a repo with injected workspace dependencies when a project behind one of
them got its spec edited: Rush hashes those `package.json` files in `repo-state.json` too.

`vendor --revert` refuses (`vendor_lock_still_wired_revert_blocked`) while a Rush lock the vendoring never wrote,
such as a subspace added since, still installs the tarball.

Not wired, and refused before anything is written: a Rush repo that installs with npm or
yarn, one with no pnpm lock yet, installs without pnpm workspaces (`vendor_rush_unsupported`),
and pnpm 8 or older locks (`vendor_lockfile_version_unsupported`). Hosted mode covers those.
Each wired shape is what Rush 5.182.1 itself writes, byte for byte, on pnpm 9.15.9, 10.34.9,
11.28.12 and 12.21.0.

### Hosted mode in a Rush repo

Editing a Rush lock outside `rush update` desyncs the `pnpmShrinkwrapHash` in
`common/config/rush/repo-state.json` (with subspaces enabled, in the
`common/config/subspaces/<name>/repo-state.json` beside each subspace lock), so when `preventManualShrinkwrapChanges` is enabled
`rush install` fails until `rush update` refreshes it (a `redirect_rush_repo_state_stale`
warning flags this; the redirect survives the refresh — pnpm keeps locked resolutions for
unchanged specifiers).

On pnpm >=11 a repointed lock does not install under Rush's default flow: `rush install`
either fails (`ERR_PNPM_TARBALL_URL_MISMATCH` /
`ERR_PNPM_LOCKFILE_RESOLUTION_VERIFICATION`) or, on pnpm 11, exits 0 after silently
re-resolving the patched entries to the upstream registry. Rush runs pnpm in `common/temp`
with a `pnpm-workspace.yaml` it generates, so neither the registry route nor
`trustLockfile` are written in a Rush repo; the `redirect_pnpm_trust_lockfile` warning gives
the Rush remedy instead
(verified with Rush 5.180.0):

- pnpm 12: install with `pnpm_config_trust_lockfile=true rush install` (set it in CI too).
- pnpm 11: also set `"usePnpmFrozenLockfileForRushInstall": true` in
  `common/config/rush/experiments.json`, so `rush install` stops passing
  `--no-prefer-frozen-lockfile`.
- pnpm <=10: nothing extra.

Run `rush purge` before `rush install` so a warm store or old `node_modules` can't serve the
upstream files, then verify with `socket-patch vex`. Don't rebuild the lock
(`rush update --full`): that discards the hosted patches.

## npm: vlt notes

[vlt](https://www.vlt.sh) is supported in agent and hosted mode on every release from
0.0.0-1 to 1.2.0, and in vendored mode from 0.0.0-19 (the first release whose lock has a
`lockfileVersion`; older locks are refused with `vendor_lockfile_version_unsupported`),
excluding the broken and never-published releases listed in
[vlt compatibility](testing/vlt-compatibility.md#releases). vlt's lock is
`vlt-lock.json`; its installed tree is `node_modules/.vlt/<DepID>/node_modules/<name>`
plus the hidden lock `node_modules/.vlt-lock.json`, which vlt trusts as the installed
graph. From 1.2.0 vlt also keeps a machine-wide content store (`store-linker`, hardlinked
on Linux by default).

**Eras.** The lock format and the DepID grammar changed several times, and every mode
reads all of them:

| Era | Releases | `lockfileVersion` | DepIDs |
|---|---|---|---|
| A0 | 0.0.0-1, 0.0.0-11 … 0.0.0-18 | absent | legacy `·`/`§` (`··name@ver`) |
| A | 0.0.0-19 … 1.0.0-rc.8 | `0` | legacy, default registry `''` |
| B | 1.0.0-rc.9 … rc.14 | `0` | legacy, default registry `npm` |
| C | rc.15 … rc.32 | `1` | tilde (`~npm~name@ver`), 3-tuples |
| D | rc.33 … 1.0.7 | `1` | tilde, the registry URL in slot [3] |
| E | 1.0.8 … 1.1.1 | `1` | tilde, hashed peer extras (`~peer.<hex>`) |
| F | 1.2.0 | `1` | as E, plus the global store |

A lock socket-patch cannot read exactly as vlt does (a UTF-8 BOM, another
`lockfileVersion`, a `nodes` section outside vlt's one-node-per-line layout) is refused:
`redirect_vlt_lock_unsupported` (hosted) or `vendor_lockfile_version_unsupported`
(vendored). Agent mode never needs the lock.

**Hosted: the slot rewrite.** Only nodes on vlt's default registry (the `''` / `npm`
segment, or a URL segment equal to the lock's scalar `registry`) are redirected, every
peer and modifier variant of the `name@version` included. Instances under a named alias,
a scoped registry or jsr stay untouched (`redirect_vlt_custom_registry_skipped`) and keep
the run's `--vex` from attesting the package. `options` is never edited: vlt fails `vlt
ci` on any change there. vlt hashes the raw response body against the pinned sha512, so
the patch server sends artifacts unencoded (`Cache-Control: no-transform`); the scan
itself never downloads them.

**Hosted: which lock confirms.** vlt drives a project when its install state
(`node_modules/.vlt-lock.json` or `node_modules/.vlt/`) is present or no other npm-family
lock is. Then only `vlt-lock.json` can confirm a redirect, and a dependency vlt refuses is
refused for every lock. With a sibling `package-lock.json` (or another npm-family lock)
and no vlt install state, both are rewritten and `redirect_vlt_sibling_lockfiles` asks you
to delete the lock your installs do not use.

**Hosted: reinstall and heal.** vlt never re-extracts an installed package when only its
lock integrity or URL changes, so after a rewrite the installed tree is stale. `scan` and
`get --mode hosted` remove `node_modules/.vlt-lock.json` and each stale
`node_modules/.vlt/<DepID>` of a Socket-owned node, so the next `vlt install` extracts the
patched packages; `rollback` and `remove` do the same for the registry bytes. Nothing
outside the project, no link target and no copy socket-patch cannot judge is ever
removed. A stale copy of an optional dependency is kept, because `vlt install` does not
put back a removed optional dependency; the advisory says to run `vlt ci` instead, and to
upgrade to vlt 1.0.5 first when every dependency is optional (vlt 0.0.0-30 … 1.0.4 install
no optional dependency from the lock of such a project; mixed projects install it on every
release). The advisory names the kept copies by what they are: unpatched copies after
`scan`/`get`, patched copies after `rollback`/`remove`, and, after a hosted → vendored
takeover, the installed copies of the now-vendored optional dependencies (whatever bytes
the hosted pin left installed). `--no-vlt-install-cleanup` (or
`SOCKET_NO_VLT_INSTALL_CLEANUP`) keeps the tree. `redirect_vlt_reinstall_required` says
what happened and what to run; a stale or unchecked copy is never attested by the run's
`--vex`.

**Hosted: vlt behaviors to know.**
- The pin survives `vlt ci`, frozen installs and `vlt install <new>`, except that
  1.0.0-rc.6 … rc.17 drop slot [3] of every default-registry node on a re-save and keep
  the patched integrity: the next `vlt ci` then fails `EINTEGRITY` (loudly, never
  silently unpatched) until `scan --mode hosted` re-pins, and `rollback` reports drift
  with that remedy.
- `vlt update` re-resolves an unchanged exact spec from 1.0.8 on, dropping the redirect
  (and the run's VEX then no longer attests it); 0.0.0-20 … 1.0.7 keep the locked node.
- vlt enforces tarball integrity only on a cold fetch (every release except 0.0.0-1): a
  warm cache keyed by URL serves stale bytes even when the integrity differs. Hosted
  artifact URLs are immutable per artifact for that reason.
- 0.0.0-16 … 0.0.0-24 ignore `vlt-lock.json` unless `vlt.json` declares `"modifiers": {}`
  (`redirect_vlt_old_lockfile_ignored`), rc.7 … rc.29 re-resolve from public npm when a
  scalar `registry` is configured (`redirect_vlt_scalar_registry_ignored`), and a lock
  with no `lockfileVersion` is silently re-resolved by vlt ≥ rc.15
  (`redirect_vlt_lockfile_version_missing`). Each keeps the run's VEX from attesting.
- **Documented gap:** a `lockfileVersion` 1 lock that sets both `registry` and
  `registries.npm` may come from rc.15 … rc.29 (which ignore the lock) or from ≥ rc.30
  (which do not); the lock cannot tell them apart, and 1.x users commonly set both, so
  no warning fires for it.
- From rc.33 every install, `vlt ci` included, needs registry config (`vlt.json`
  `config.registries.npm` / `config.registry`, `VLT_REGISTRY`, or `vlt setup`), and from
  1.0.5 `registries.npm` specifically. socket-patch never writes `vlt.json`.

**Vendored: directory artifacts (the D19 layout).** A direct dependency of the root or of
a workspace member is vendored as a patched package directory,
`.socket/vendor/npm/<uuid>/<name>-<version>/node_modules/<name>/`, never a tarball: vlt
links a `file:` directory in place, and the extra `node_modules/<name>` level lets a
package that `require()`s its own name resolve itself. The payload's `devDependencies`
are dropped from its `package.json` (vlt would otherwise try to install them). The uuid
directory carries a `.gitignore` that re-includes the payload (`!*`) against the project's
own ignores (`node_modules`, `dist/`, `*.map`, …) while ignoring the links vlt creates
inside it, and a `.gitattributes` (`* -text -filter -ident -working-tree-encoding`) that
turns off EOL conversion and overrides the project's clean/smudge filters, such as a Git
LFS `*.tgz` rule, so an `autocrlf` or LFS-less checkout stays byte-exact (#1541). A tarball
an older release already committed as an LFS pointer stays one until it is re-added:
after the next vendored run or `socket-patch repair`, `git add --renormalize
.socket/vendor/npm` and commit. The lock's node becomes a `file` node, the importer edges and the
importers' `package.json` specs move to the `file:` path, and every moved entry is placed
where vlt's own serializer puts it, so `vlt ci` keeps the lock byte-identical. Transitive
targets are refused (`vendor_vlt_transitive_unsupported`: vlt silently reverts
transitive lock surgery), as are several instances of one `name@version`, modifier
variants, importer peer edges, foreign registries, a git, remote-tarball or local-directory
node of the same package and a dependency declared in several fields
(`vendor_lock_entry_unsupported`), and a package with a `preinstall`, `install`,
`postinstall`, `preprepare`, `prepare` or `postprepare` script or a `binding.gyp`, which
`vlt build` would build inside the committed directory (`vendor_vlt_build_scripts_unsupported`,
also when an earlier release already vendored it); use hosted mode for those. From vlt 1.0.8 a root
dependency with resolved peers carries a `~peer.<hex>` extra even with one peer context (a
workspace member's a `~peer.N` one from rc.15): vendored mode writes its `file` node
without the extra, exactly as vlt writes a `file:` dependency, keeps its peer edges, and
`vendor --revert` restores the extra. vlt 0.0.0-31 … rc.5 cannot reinstall a vendored
`file:` dependency without the lock (`vendor_vlt_legacy_lockfile` on era-A locks: `··` ids,
or URL-segment ids equal to a scalar `registry`), and A0 locks are refused. From 0.0.0-30 a
plain `vlt install` keeps an optional dependency's installed upstream copy after
vendoring; `vendor_vlt_reinstall_required` says to run `vlt ci` (or delete `node_modules`
and run `vlt install`) to link the vendored directory, and to upgrade to vlt 1.0.5 first
when every dependency is optional (0.0.0-30 … 1.0.4 install none from the lock). The same advisory names any dependency whose
`node_modules` link still resolves to vlt's store, and `vendor --revert` repeats it for an
optional dependency (a plain `vlt install` keeps the link to the removed vendored
directory) or a link still into the vendored directory.

`vendor --revert` undoes every recorded surface or none, and removes the directory only
when nothing the project installs from still names it. A lock edge the ledger never
recorded that still reaches the vendored node, such as the edge of a workspace that was
pointed at the vendored copy after vendoring, leaves the whole revert alone as drift
(`vendor_lock_entry_drifted` names the edge and its `package.json`): undoing the node
under it would leave that edge dangling. Anything else that still names the uuid
directory (an importer `package.json` with no lock edge behind it yet) keeps the directory
and the ledger entry (`vendor_revert_residual_reference` names it) with the recorded
wiring restored.
`vendor --revert --dry-run` replays the same records without writing, so it reports the
same keeps, failures and reinstall advice as the real run.

A workspace directory that is a symbolic link is never written through: vendoring refuses
the package (`vendor_lock_entry_unsupported`) before anything is staged, and a revert
leaves a record for its `package.json` alone as drift. The `nodes` and `edges` sections are
edited line by line, so a lock is taken as canonical only when the lines found for them
are the top-level members themselves; one with a same-named member nested elsewhere at
that indent is refused (`vendor_lockfile_version_unsupported`) by vendoring and revert
alike.

**Workspace members.** vlt installs a workspace member from the root's `vlt-lock.json`
and ignores any lock in the member, so a hosted or vendored run from a member is refused
(`redirect_workspace_lockfile_elsewhere`, `vendor_lockfile_missing`) and names the root
to run from. The root lists its members in `vlt.json` `workspaces`; when that field is
absent, in `package.json` `workspaces`; and from vlt 1.4, when both are absent, in the
`packages:` of `pnpm-workspace.yaml`. vlt 1.3.8 and older ignore `pnpm-workspace.yaml`,
so its directories count as members only when the root lock has an edge from one of them,
which only vlt 1.4 writes (#1564).

**Agent mode.** `apply` and `rollback` patch every store copy of a `name@version`
(legacy and tilde DepIDs, peer and modifier variants, transitive-only packages) and
replace each file instead of writing through it, so vlt 1.2's shared store (hardlinked on
Linux) and every other project linked to it keep their bytes. A patch survives `vlt
install`, `install <new>`, `uninstall` and frozen installs; `vlt ci` and deleting
`node_modules` restore the upstream bytes; run `socket-patch apply` after them.

**Locale.** vlt sorts its lock with the process locale for one key, so byte-stability is
claimed only for `en`-equivalent locales (`LANG` unset, `C`, `POSIX` or `en_US`); every vlt
test job sets `LANG=C` and `LC_ALL=C`. Vendored ownership and revert match by entry text,
so they do not depend on the order.

**Compatibility of ledgers.** vlt vendor ledgers (`flavor: "vlt"` entries) require the
socket-patch release that adds vlt support: an older release does not understand them.
Hosted vlt pins need no ledger (v5.0): `rollback` restores them from the npm registry.

## PyPI: projects without a virtualenv

A Python project with no environment of its own (no `.venv` or `venv`, no
activated environment, no environment its manager created) installs into
the interpreter on `PATH`. socket-patch reads that interpreter: it asks
`python3` (else `python`, else `py`), run from the project directory, for
its site-packages and user site, and reads only those directories.

An interpreter on `PATH` that sits in a virtualenv (a Docker image's
`ENV PATH=/opt/venv/bin:$PATH`) or in a conda environment other than the
root is the project's own environment, like an activated one, and
everything in it is the project's.

Any other interpreter is shared, the conda root (`base`) included.
Homebrew formulae, distro packages, conda's own dependencies and other
projects install into it too, so a package being installed there does not
make it this project's. `scan` keeps only:

- the packages the project declares: every requirement in a
  `*requirements*.txt` or `*requirements*.in` file at the top level or one
  directory down (`docs/requirements.txt`), in a `.txt` or `.in` file of a
  top-level `requirements/` directory and in their `-r` includes, plus the
  `[project]` `dependencies` and `optional-dependencies` and the
  `[dependency-groups]` of `pyproject.toml`;
- the installed packages those require, through their `Requires-Dist`
  metadata. A requirement behind an extra counts only when that extra is
  asked for (`requests[socks]`). Other markers, such as a platform test,
  are not evaluated;
- the packages `.socket/manifest.json` records a patch for, declared or
  not: `socket-patch get <name>` patched them on purpose.

A project that declares nothing, or whose declared packages are not
installed, has no packages there. Install them first
(`pip install -r requirements.txt`), preferably into a virtualenv. When
the interpreter does hold packages and the project declares none of them,
the scan ends with `No packages found: the N packages installed in the
Python on PATH are not ones this project declares`.

The filter is skipped, and every package in the interpreter is reported,
when nothing states the project's dependencies (its only marker is a
`pyproject.toml` that configures tools, and it has no requirements file in
the places above) and when socket-patch cannot read every declaration: a `setup.py` or
`setup.cfg`, a `poetry.lock`, `pdm.lock`, `uv.lock` or PEP 751 lock,
`dynamic` dependencies, dependencies in a `[tool.poetry]`, `[tool.pdm]`,
`[tool.uv]`, `[tool.rye]` or `[tool.flit]` table, Hatch environments
(`hatch.toml` or a `[tool.hatch.envs]` table), a requirement on a local
directory other than the project itself or on an archive that is not a
wheel, a `${VAR}` in a requirements line, or a declaration that cannot be
read.

The other interpreters on the machine, and the environments tools keep for
themselves (`uv tool install`, pipx apps, the Poetry installer, PDM's
global project), are never read for a project. Use `--global` to patch
those.

`apply`, `rollback` and `vex` find the packages of recorded patches by name
and version in the same interpreter, and `socket-patch get <name>` and
`socket-patch show <name>` resolve a name among everything installed there. The filter applies to `scan`
discovery only.

`scan --prune` does not drop the record of a patch whose package is no
longer reported while an installed copy is still patched
(`pypi_installed_patch_kept`): the record holds the only data that can
restore that copy. `socket-patch rollback <purl>` restores it and drops the
record; add `--global` when the copy is in another interpreter or a tool's
environment. Copies outside the interpreter are looked for only when the
project installs into a shared one. A `--prune` that is skipped because
the scan found nothing reports the same warning, and drops no record.

## PyPI: pixi projects

[pixi](https://pixi.sh) installs a project's packages into conda environments of its
own, one per environment of the workspace, under `.pixi/envs/<name>`. Most Python
packages of a pixi project come from conda channels (conda-forge repackages the PyPI
release), and the rest are PyPI wheels pixi installs with uv. Both kinds land in the
environment's `site-packages` with their `.dist-info` (or `.egg-info`) metadata, and
both are patched in place by **agent mode**:

```sh
pixi install                       # or any pixi command that installs the environment
socket-patch scan --mode agent     # records the patches in .socket/ and applies them
git add .socket && git commit      # keep the patches
# afterwards, locally and in CI:
pixi install && socket-patch apply
```

- **Discovery needs no activation.** `scan`, `apply`, `rollback`, `remove`, `repair`
  and `vex` find every environment under `.pixi/envs/` from the project root, without
  `pixi run` or `pixi shell`. With pixi's `detached-environments` setting the
  environments live under pixi's cache and `.pixi/envs` is a link to them, which is
  followed (pixi leaves no such link on Windows; run socket-patch through `pixi run`
  there, which names the activated environment). A venv another tool keeps in the same
  project (`./.venv`, an activated `VIRTUAL_ENV`) is still crawled, ahead of pixi's
  environments. `scan --global` also reads the tool environments `pixi global install`
  creates under `$PIXI_HOME/envs` (default `~/.pixi/envs`).
- **A project only pixi installs never falls back to the Python on `PATH`.** With a
  `pixi.toml` or `pixi.lock` at the root and no environment installed, nothing is
  installed for the project; the scan says so instead of crawling the system
  interpreter. A file pip installs from beside pixi's files keeps that fallback,
  because the interpreter on `PATH` may then hold the project's packages (a container
  image that runs `pip install -r requirements.txt`, a library that keeps pixi for
  development and is `pip install`ed in CI): a `requirements.txt`, `setup.py` or
  `setup.cfg`, or a `pyproject.toml` with a `[build-system]` table. A `pyproject.toml`
  that only holds project metadata or tool settings does not.
- **Environments are a project's only beside pixi's files.** `.pixi/envs` is read
  where a `pixi.toml` or `pixi.lock` is. In the home directory the same path holds
  the tool environments of `pixi global install`, which only `--global` reads.
- **From a workspace member directory, use `pixi run`.** The environments are under the
  workspace root's `.pixi/envs`. Run from a member directory (one with a `pixi.toml` of
  its own and no environments of its own), socket-patch uses the environment `pixi
  run` or `pixi shell` activated for that workspace; without an activation it finds
  none there. A directory below the root that is not a pixi project (another tool's
  project in the same tree) is not given the workspace's environment.
- **A venv layered on a pixi environment** (`--system-site-packages`, built on the
  environment's Python) hides, for its own interpreter, the packages it installs too.
  The environment's copies are still patched: `pixi run` imports them.
- **A conda build is patched only as the PyPI release it repackages.** A patch is
  made from a PyPI release and records the hash of each file it replaces there. A
  copy conda built (its `INSTALLER` says `conda`, or it has none) takes that patch
  only when all of this holds, and no flag changes it, `--force` and
  `--allow-patch-conflicts` included:
  - the copy holds no compiled code: its `WHEEL` says `Root-Is-Purelib: true`, or,
    for an install without one (`.egg-info`), the conda package's own file list
    (its record in the environment's `conda-meta`) holds no shared library. When no
    record there lists the copy, the files of its top-level modules are looked at
    instead, and a shared library among them counts as its own;
  - the patch is not for a platform wheel;
  - every file the patch replaces has the release's bytes, and the patch replaces at
    least one file. A file that differs (a recipe that changes the source) is never
    overwritten, and nothing of the copy is changed.

- **Compiled conda packages are not supported yet, and are skipped.** A compiled
  conda package (`pillow`, `numpy`, `brotli-python`) is built separately from the
  PyPI wheel and links conda's own libraries, so it is never that release, even
  when the Python file a patch touches is identical. Nothing is written to one, and
  it never fails a run:
  - `scan --mode agent` and `get <purl>` leave its patch out when every installed
    copy of the package is one, with the warning `conda_build_not_pypi_release`;
    nothing is recorded and the exit status is unchanged. A package that also has a
    copy pip or uv installed keeps its patch, for that copy. (`get <uuid>` names one
    patch, so it records it; its apply then skips the copy.)
  - `apply` skips the copy when its patch is in the manifest already (recorded on
    another machine, or for another copy of the package): a `Warning:` line with the
    same code, `N not supported` in the summary, a `skipped` event under `--json`,
    and the exit status unchanged. `apply --check` does not report the copy as out
    of sync.
  - The package stays unpatched in that environment, so `vex` does not attest it
    as patched there.

  A pure-Python conda build that cannot take a patch already in the manifest still
  makes `apply` fail for that copy: with `conda_build_not_pypi_release` for a
  platform wheel's record on its own (the error names `socket-patch remove`, which
  drops the record), or with `no matching variant found` when a replaced file
  differs. A copy that already holds the patch, as one an earlier release patched
  does, has nothing written to it and is reported as already patched, compiled or
  not. A release with a platform wheel beside its
  pure-Python one has a record for each: on a pure-Python conda build the pure
  wheel's record patches the copy, and the platform wheel's is not an error there
  (it reads as already patched, as its file is). A copy that fails is reported
  once. `--strict` is as strict as anywhere else. A wheel
  that pip or uv installed into the environment (`[pypi-dependencies]`, or `pip
  install` in a conda environment) is the PyPI release itself and is patched as
  anywhere else. **Not compared:** the files a patch leaves alone. A patch record
  holds no hashes for them, so a recipe that changes another module of an otherwise
  identical build is not seen. In one project's 51 pure-Python conda-forge packages,
  45 were the PyPI wheel byte for byte and 6 differed in a file (a generated version
  file in most; one module in `setuptools`).
- **What undoes a patch.** `pixi install` and `pixi run` leave an installed
  environment's files alone, so a patch survives them. `pixi reinstall`, `pixi clean`,
  a deleted `.pixi/` and any change that makes pixi relink the package restore the
  upstream files; `socket-patch apply` puts the patch back. pixi links an
  environment's files from its package cache: a patch replaces the environment's file
  with a new one, so the cache and every other environment built from it keep the
  upstream bytes.
- **Hosted and vendored mode do not support pixi.** pixi installs from its own lock
  (`pixi.lock`), and a package a conda channel provides cannot be pointed at a patched
  PyPI wheel: pixi keeps the conda package and ignores a PyPI source for the same
  name. `scan` in its default hosted mode therefore changes nothing in a pixi project
  and warns `redirect_pypi_pixi_project`, which names the agent-mode steps above
  (exit 0). `scan --mode vendored` refuses each patch (`pypi_no_requirements`, or
  `pypi_pyproject_only` when the project keeps a `pyproject.toml`), writes nothing and
  exits 1; its message names agent mode too. `pixi.lock` is not read as a lockfile: a
  fresh checkout has no packages until `pixi install` has run. A project that also
  has a lock another tool installs from (a `uv.lock` for a `.venv` beside pixi's
  environments) is still rewired for that tool; the copy in the pixi environment is
  then reported as `redirect_pypi_stale_install`, whose remedy names agent mode.
- **Tested against real pixi.** `scripts/backtest-pixi.py` runs these flows on pinned
  pixi releases; see [pixi compatibility](testing/pixi-compatibility.md).

## Maven & NuGet caveats

Honest limits of the Maven and NuGet flows — documented behavior, not bugs:

* **Fail-closed by version suffixing (hosted Maven).** Maven has no lockfile, so hosted
  mode pins the patch a different way: the Socket patch server (`patch.socket.dev`)
  exposes the patched jar
  under a globally-unique `<version>-socket.<hex8>` suffix that exists **only** on the
  injected `socket-patch-<uuid>` repository. The rewriter pins that suffixed version
  explicitly — it rewrites the literal `<version>`, or (for a transitive / managed
  dependency with no literal version in your pom) adds a `<dependencyManagement>` entry —
  so a resolver that can't reach the Socket repo, or is handed different bytes, has
  nowhere to fall through to: the build **hard-fails** instead of silently resolving the
  unpatched upstream artifact. The `<repository>`'s `checksumPolicy=fail` still verifies
  the transport-level `.jar.sha1` sidecar on top. A `${property}` version is patched
  without stranding an artifact that shares the property (see **Property versions**
  below). A literal version
  that matches neither the base nor the suffixed value is skipped
  (`redirect_maven_dep_version_mismatch`). A `<base>-socket.<hex8>` literal left by an
  earlier hosted patch for the same release (the pom declares that patch's
  `socket-patch-<uuid>` repository) is re-pinned to the new suffix: the superseded
  `socket-patch-<uuid>` repository and its Trusted Checksums entries are removed, and a
  repository whose grant URL changed (a rotated token) is refreshed in place. A suffixed
  literal no hosted repository in the pom minted (a vendored `socket-patch-vendor-<uuid>`
  pin, say) is still a mismatch and is skipped.
  The rewriter reads the pom the way Maven builds the project: markup inside comments,
  CDATA, `<build>` / `<reporting>` (plugin classpaths), `<pluginRepositories>`,
  `<distributionManagement>` and `<profiles>` is never matched or edited, and the
  repository and `<dependencyManagement>` pin always land in the project's own top-level
  sections (an existing self-closed `<repositories/>` or `<dependencyManagement/>` is
  expanded in place, so Maven never sees a duplicated tag). A GA declared only in such
  markup counts as transitive and gets the top-level pin; a versioned declaration inside
  `<profiles>` (a literal or a `${property}`) is left as-is and reported
  (`redirect_maven_profile_dependency_unpatched`), because an active profile's version
  beats the pin, and when a profile holds the GA's only declaration nothing is pinned.
  A `${property}` groupId or artifactId is resolved from the pom's own `<properties>`
  before matching, so `<groupId>${ct.group}</groupId>` is rewritten like a literal. One
  the pom does not define (a parent's) may be the patched GA, and then its own version
  wins: the dep is refused and the run writes nothing for it
  (`redirect_maven_coordinate_unresolved`), and `vex` does not attest a pin past such a
  declaration.
  The grant serves the main jar only: a `<classifier>` variant keeps its version
  (`redirect_maven_classifier_unsupported`), and the literal-or-pin decision is made from
  the classifier-less declarations. A `sources` / `javadoc` variant at the patched release
  only warns; any other variant there (tests, a native build) would keep unpatched code on
  a classpath, so the dep is not redirected.
* **A pin follows the version Maven selects (hosted and vendored Maven).** A
  `<dependencyManagement>` pin makes every occurrence of an artifact one version, so it
  is written only where Maven selects the patch's base version already. The scan reads
  what Maven selects from the project's poms and the poms the Maven local repository
  holds, module by module, without running Maven: the nearest declaration wins, the
  first declared on a tie; the project's own management overrides transitive versions;
  an `<exclusion>` removes what is below it; a range takes the highest version the
  cached `maven-metadata-*.xml` lists. When the build selects another version (a newer
  or older one nearer the root, the project's own declaration, an excluded path, a
  range), or does not resolve the artifact at all, the patch for that base version has
  nothing to patch: the run writes nothing for it, exits 0, and one line names the version
  Maven selects instead (`redirect_maven_version_not_selected`, vendored
  `vendor_maven_version_not_selected`). A patch for the version that is selected is
  still looked up and applied. When the selection cannot be read (most often because
  the project was never resolved, so the local repository lacks its poms; one pom
  missing among what a module resolves holds back every new pin in that module, since
  it may hold a version range and a range binds at any depth), a
  declaration that already names the base version is still rewritten where it stands,
  and no new pin is written (`redirect_maven_selection_undetermined`, vendored
  `vendor_maven_selection_undetermined`): the line names the remedy, `mvn -q
  dependency:resolve` and a re-scan when a pom is missing from the local repository,
  else a declaration of the artifact at the patched version. Vendored pins are placed
  when a patch is first wired and stay where they are on every machine afterwards; a
  pin for a version the build no longer selects is removed on the next run. Agent mode patches a cached jar in place under its own coordinates, which
  cannot change what a build resolves; a version Maven only read the pom of has no jar
  to patch and is left out of an agent scan. Maven 4 builds, profiles that declare
  dependencies or management, relocations and dependency cycles are not modelled: the
  artifacts they touch count as not readable.
* **Multi-module reactors (hosted Maven).** A root that declares `<modules>` or
  `<subprojects>` (directly or in a profile, or a Maven 4 root whose subprojects Maven
  discovers) is patched module by module, with pom edits only, by the planner vendored
  mode uses. A declaration that names the patched version is rewritten where it stands,
  in whichever pom holds it. The `<dependencyManagement>` pin goes in the highest pom
  whose modules all resolve the artifact at that version or not at all: the root when
  the whole reactor agrees, else the modules that do, down to one module's own
  `pom.xml`. A module that resolves another version is never reached and resolves what
  it resolved before. Such a pin carries the comment vendored pins carry
  (`<!-- socket-patch <uuid>: g:a:v -->`), which is how a later run tells it from the
  project's own management. The `<repository>` goes in the local root every wired pom
  inherits (a module whose parent is not in the checkout gets its own), and the Trusted
  Checksums stay in the project root's `.mvn/`, which Maven also reads when it is
  started in a module directory or with `-f`; a module with a `.mvn` of its own is
  reported (`redirect_maven_trusted_checksums_unenforced`), since a Maven started there
  reads that one. When a pom of a reactor cannot be read, the run writes nothing for the
  patch (`redirect_maven_multimodule_unsupported`, with the reason). A pom that is there
  but is not UTF-8 text (re-saved as Latin-1 or UTF-16, say) is never taken for a missing
  one: the scan refuses the run and names it (`candidate_file_unreadable`), `vex` reports
  it as unreadable and attests no pin of that reactor, and `rollback` / `remove` change
  nothing until it is UTF-8 again, since it may hold part of a pin. The plan for a patch is
  written whole or not at all: a pom is never left naming a patched version without the
  repository that serves it, its checksum lines, and wiring a rollback can find. So a
  declaration only a `<profile>` holds is not rewritten on its own
  (`redirect_maven_profile_dependency_unpatched`), and neither is anything when the pom
  that must take the repository cannot (`redirect_maven_pom_unreadable`), or when a
  rollback could not put a pom back exactly (`redirect_maven_edit_not_reversible`). When
  a later scan takes out the last pin of a patch (the module it reached moved to another
  version), the repository and the checksum lines go with it. `vex` attests the patch
  only when every module that resolves the patched version, or may, is reached by a pin
  or a declaration; otherwise it withholds the statement and names the module
  (`vex_maven_reactor_root`). `rollback` and `remove` undo the wiring in every pom that
  carries part of it, or in none, and restore each byte for byte.
* **Property versions (hosted Maven).** A declaration whose `<version>` is a
  `${property}` is patched in one of two ways, and neither moves another artifact. When
  the reactor's own poms define the property once and nothing but declarations of the
  patched artifact reads it, the property's value takes the patched version and the
  declarations keep their text. Otherwise (a sibling artifact reads it too, a profile or
  `.mvn/maven.config` may redefine it, or a parent pom outside the checkout defines it)
  the one declaration takes the literal patched version, and the text it replaced is
  recorded in a comment right after it:
  `<version>1.2-socket.0a1b2c3d</version><!-- socket-patch:version ${lib.version} -->`.
  Rollback reads that comment back, so the declaration returns to its `${...}` text
  exactly. Such a declaration no longer follows the property: bump the property and the
  patched artifact stays where it is until the next `scan`. A property no pom of the
  checkout defines is read from what Maven selects for the modules that read the
  declaration; when that cannot be told (the parent pom is not in the local Maven
  repository yet) the declaration is left as it is (`redirect_maven_dep_unpinned`).
  A version-less declaration a parent or BOM manages needs no edit of its own: the
  `<dependencyManagement>` pin overrides the management. A single pom that inherits
  from a parent pom inside the checkout is read together with it: a property that parent
  defines is rewritten there, and the repository goes in the parent the pom inherits it
  from; `list`, `vex`, `rollback` and `remove` read both poms.
* **A parent pom can override a managed pin (hosted Maven).** For a dependency with no
  literal `<version>` in the root pom (a transitive one, or one whose version a parent
  manages), hosted mode pins it in the root pom's `<dependencyManagement>`
  (`redirect_maven_dep_management_added`). Maven applies a managed version only to a
  dependency that declares none, and a pom inherits its parents' `<dependencies>`: when a
  parent pom declares the package with a version, the build resolves that version and
  the pin does nothing. `vex` follows the parent chain through the checkout and writes no
  statement in that case (`vex_maven_parent_declares`, naming the parent pom). Declare
  the package in the root pom's `<dependencies>` with no `<version>`: its own
  declaration replaces the inherited one, and the pin then governs it. When the parent is
  not in the checkout (`<relativePath/>`, as Spring Initializr writes it, or a parent
  resolved from a repository), `vex` cannot read what it declares, so a managed-only pin
  is attested only after a build has resolved the patched version: until then it is
  omitted as `package_not_found`. A pin on the root pom's own declaration is not
  affected.
* **Trusted Checksums reinforcement (hosted Maven, 3.9.4+).** When the patch server
  supplies both the jar and pom sha256, the rewriter also emits Maven
  [Trusted Checksums](https://maven.apache.org/resolver/expected-checksums.html) files —
  `.mvn/maven.config` resolver args plus `.mvn/checksums/checksums.sha256` entries
  pinning both artifacts under the suffixed version's local-repo path (merging into any
  pre-existing user config / checksum set; a conflicting value is never overridden and
  surfaces `redirect_maven_trusted_checksums_conflict`). This is an **independent
  client-side content pin** on top of the transport check. It requires **Maven 3.9.4+**.
  Older releases leave the `.mvn/*` files inert, and only the transport `.sha1` check
  guards the Socket-served bytes. The version suffixing above still fails closed on its
  own.
  - **3.9.0 / 3.9.1** do not interpolate the basedir the config uses, so the summary
    file is never found.
  - **3.9.2 / 3.9.3** ignore `checksumAlgorithms=SHA-256` and check SHA-1 only.
  - **Below 3.9** there is no Trusted Checksums post-processor.
  - **Maven 4** enforces the pin only in a project that declares Maven 4 (below).

  **How the directory is named.** Maven reads a relative `basedir` from the local
  repository, so the config names `.mvn/checksums` through a property, and no property
  is right on every Maven:
  - `${maven.multiModuleProjectDirectory}/.mvn/checksums` is what hosted mode writes by
    default. Every Maven 3 launcher defines it wherever the build is started (the
    project root, a module directory, `mvn -f <project>/pom.xml` from another
    directory), so the line breaks no build and the pin is enforced from 3.9.4 on.
    Maven 4 does not interpolate it: a Maven 4 build of such a project runs as if the
    pin were not there.
  - `${session.rootDirectory}/.mvn/checksums` is written for a project that declares
    Maven 4: its Maven Wrapper pins Apache Maven 4, or its root `pom.xml` is of a model
    newer than 4.0.0 (its `<modelVersion>`, or with none, the version its namespace
    names; `<modelVersion>4.0.0</modelVersion>` under the 4.1.0 namespace is a 4.0.0 pom,
    which Maven 3 builds). Maven 4 defines the property in every invocation. Releases up
    to 5.1.0 wrote this form for every project, which stopped **Maven 3.9.2 to 3.9.8**
    from starting at all with `-f` from outside the project (`Illegal use of undefined
    property: session.rootDirectory`).

  If Maven 4 builds your project and nothing in the checkout says so, declare it: with
  the default form a Maven 4 build does not enforce the pin, and the CLI cannot see
  which Maven you run.

  **A project wired by an earlier release is healed.** Every `scan --mode hosted` that
  finds the six settings standing together as hosted mode wrote them, in the spelling
  that is not this project's, rewrites that one line in place (`redirect_maven_config`,
  `rewritten`, `key: "trustedChecksumsDirectory"`). It does so whatever the scan
  redirects: when no patch applies any more (a dependency bumped past its patched
  version), in a reactor root, when no checksum line is left, when a later line switches
  the pin off. A scan with nothing to redirect reads `.mvn/maven.config` for this alone
  and takes the write lock for the change when it can. The heal never fails a run: when
  the lock is held elsewhere, or `.mvn/maven.config` is a symbolic link, the line is
  left for a later scan. `rollback` and `remove` do the same to a config they leave in
  place. A directory line you wrote yourself (one
  that stands apart from the other five) is yours and is left alone, as is any other
  setting; `rollback` and `remove` recognise either form.

  The heal can trade something away, and says so. Taking `${session.rootDirectory}` out
  of a project that declares no Maven means a Maven 4 build of it no longer enforces the
  pin (Maven 3.9.4 and later 3.x still do). The run that changes the line warns
  `redirect_maven_trusted_checksums_maven3_only` (`maven_trusted_checksums_maven3_only`
  from `rollback` / `remove`). Declare Maven 4 and scan again to get the form Maven 4
  reads back.

  When the Maven the project declares does not enforce the pin as the config stands, the
  rewriter still writes the files and warns `redirect_maven_trusted_checksums_unenforced`,
  on every scan while that holds:
  - `.mvn/wrapper/maven-wrapper.properties` pins a Maven older than 3.9.4 (upgrade the
    wrapper);
  - the project declares Maven 4 and the directory line is one you wrote in the
    launcher's spelling, which Maven 4 does not read (set it to
    `${session.rootDirectory}/.mvn/checksums`). The scan that first meets that line also
    reports it as `redirect_maven_trusted_checksums_conflict`.

  Without a Maven Wrapper or a newer model, the CLI can't tell which Maven builds the
  project, so it doesn't warn.
  On Maven **3.9.4–3.9.8** a *mismatch* is enforced but reported unclearly; the
  readability fix landed in **3.9.9**
  ([MNG-8182](https://issues.apache.org/jira/browse/MNG-8182)). The args are
  `originAware=false` and `failIfMissing=false`, so one checksum matches the artifact
  from any repository and a dependency with no committed checksum still resolves — only a
  *mismatch* fails. A grant whose sha256 is not 64 hex digits writes no checksum line
  and warns `redirect_maven_trusted_checksums_invalid_hash`; a line an earlier run wrote
  for that suffixed version goes once the pin lands or is in place, and stays untouched
  for a dep the run refuses or skips. `vex` takes a pin's checksum as the
  content the project pins only when the pin is known to be enforced: `maven.config`
  enforces the file as Maven 3.9+ reads it (all five settings above with the values
  hosted writes, the directory in either form; `failIfMissing` aside), and the Maven the
  project declares reads the directory as the config spells it (a wrapper that pins
  Maven 3.9.4 or later, and below Maven 4 for the default form; Maven 4, by the wrapper
  or the model, for the `${session.rootDirectory}` form). A project that declares no
  Maven and carries the default form is enforced by Maven 3 only, so its checksum is not
  taken; the statement itself does not depend on it, since the suffixed version is the
  pin.
* **A Maven project's scan is scoped to its dependency graph.** The Maven local
  repository is shared by every project on the machine, so in project mode (no
  `--global` / `--global-prefix`) a Maven build's crawl (a `pom.xml`, no Gradle or
  sbt / Mill / scala-cli build beside it) keeps only the coordinates its poms reach:
  every reactor declaration (modules and profiles included, any scope), then each
  artifact's own non-optional `compile` / `runtime` dependencies, read from the poms the
  repository already holds, with versions from properties, parents, management and
  imported BOMs (the reactor's management applies to transitives, as in Maven). A
  version that cannot be determined (an undefined property, a range, a pom not in the
  repository) admits every cached version of that artifact. Artifacts another project
  cached are not scanned, so hosted mode never pins them and `vex` never attests them.
  A project that has never been resolved therefore finds nothing; resolve it once
  (`mvn -q dependency:resolve`) and scan again. An unreadable root `pom.xml` leaves the
  crawl unscoped.
* **Local-repository discovery reads coordinates from the path.** `scan` (and every
  other crawl of `~/.m2/repository`) takes a POM's groupId / artifactId / version from
  its directory when the file sits at the canonical
  `<group path>/<artifactId>/<version>/<artifactId>-<version>.pom` — the only place Maven
  writes one — without opening it. The path spells the group relative to the scan root,
  so each top-level group directory (`org/`, `com/`, ...) is confirmed first: the first
  canonical POM under it whose contents parse must name the coordinates its path does.
  A directory that fails that check — all of them when `--global-prefix` /
  `SOCKET_GLOBAL_PREFIX` / `MAVEN_REPO_LOCAL` names a directory above or inside the
  repository rather than the repository itself — is read content-first, as before. Any
  other `.pom` (a SNAPSHOT dir's timestamped POM, a hand-placed `extra.pom`, a group
  directory whose name holds a `.`) is parsed as before, falling back to the directory
  path when the POM names no usable coordinates. The one visible consequence: under a
  confirmed directory, a POM at a canonical path whose contents disagree with its
  directory (hand-placed, or a legacy upstream POM with mismatched coordinates) reports
  the directory's coordinates.
* **Warm `~/.m2` copies.** Vendored and hosted Maven both pin a suffixed
  `<version>-socket.<hex8>`, so a cached copy of the original version in `~/.m2` cannot
  shadow the patch. Audit conflicting copies of that suffix with
  `vendor --check --local-repo <path>`. A project vendored before v5 (the same-GAV
  `<repository>` wiring, which a warm `~/.m2` could shadow) is refused with
  `legacy_maven_root` until you run `socket-patch vendor --revert` and vendor again.
* **No Maven Wrapper (vendored).** Without `.mvn/wrapper/maven-wrapper.properties` the
  CLI can't tell which Maven builds the project, so `vendor` warns `vendor_jvm_degraded`
  twice: `maven_f_outside_root` (Maven 3.9.2–3.9.8 can't read the vendored tree with
  `-f` from outside the project) and `maven_mirror_of_all` (Maven before 3.9.2 reads the
  fallback file repository, which a `mirrorOf *` mirror captures). The patch is still
  applied. To clear them, add a Maven Wrapper pinned to Maven 3.9.9 or later, or make
  sure your `settings.xml` mirrors exclude `socket-patch-vendor` (for example
  `<mirrorOf>external:*</mirrorOf>` or `<mirrorOf>*,!socket-patch-vendor</mirrorOf>`).
* **`mirrorOf` mirrors (hosted Maven).** A `settings.xml` `<mirror>` whose
  `<mirrorOf>` is `*` or `external:*` (common in corporate environments) sends *every*
  repository to the mirror, the `socket-patch-<uuid>` repository hosted mode adds
  included. The patch resolves only at its suffixed version, which the mirror does not
  hold, so a project wired behind such a mirror **fails to build**. `scan --mode hosted`
  therefore reads the Maven settings of the machine it runs on before it writes a Maven
  pin, and wires nothing for a patch whose repository a mirror would take over: the run
  writes nothing for it (no pin in a pom, no line or file under `.mvn/`), exits 0, and
  `redirect_maven_mirror_captures_repository` names the mirror, the settings file that
  declares it, and the two ways forward:
  - **Leave the repository out of the mirror.** Add `!socket-patch-<uuid>` to its
    `<mirrorOf>` (`<mirrorOf>*,!socket-patch-<uuid></mirrorOf>`), with no space around
    it, on every machine that builds, then scan again. Maven compares whole repository
    ids: there is no pattern for "every Socket repository" (`!socket-patch-*` excludes
    nothing), and each patch has its own id, so each new patch needs its own exclusion.
  - **Use vendored mode, on Maven 3.9.2 or later.** `scan --mode vendored` commits the
    patched artifact and reads it through `maven.repo.local.tail`, which no mirror
    redirects. Maven reads that setting from 3.9.2 on. An older Maven reads a vendored
    patch through the `socket-patch-vendor` file repository, which a mirror of everything
    takes as well, so there vendored mode needs the mirror to leave `socket-patch-vendor`
    out (one id for every vendored patch). The warning says which applies: when the
    project's Maven Wrapper pins a Maven older than 3.9.2 it does not offer vendored mode
    as the project stands.

  What is read: the user settings (`-s` / `--settings` in `MAVEN_ARGS`, then in
  `.mvn/maven.config`, else `~/.m2/settings.xml`) merged over the global settings (`-gs`
  / `--global-settings` likewise, else `conf/settings.xml` of the Maven Wrapper's
  unpacked distribution, of the `mvn` on `PATH`, or, with none there, of `$MAVEN_HOME`
  / `$M2_HOME`), and a `.mvn/settings.xml` the project keeps. `.mvn/maven.config` is
  read as the project's Maven reads it: one argument per line from Maven 3.9 on (so a
  settings path may hold spaces), split on whitespace before; the Maven Wrapper's
  release decides, and without a wrapper both readings are weighed. The matching is
  Maven's own: a mirror whose `<mirrorOf>` names the repository's id, alone or in a list
  (`central,socket-patch-<uuid>`), was written for that repository and is not a reason
  to skip; a mirror with no `<id>` counts under Maven's default id; `external:http:*` (the blocker Maven ships) never matches the
  HTTPS Socket repository; `<mirrorOfLayouts>` is honoured. **Only the scanning
  machine's settings are known.** A build machine with another `settings.xml` (a CI
  image, a colleague's laptop) is not seen: a project wired here still fails there
  behind a mirror that takes every repository, and a project skipped here may have built
  there. The in-memory engine (a Socket-opened pull request) reads no settings at all.
  A project an earlier scan wired is left as it is and reported the same way, and is no
  longer counted as redirected or attested by that scan's `--vex`. Its warning also says
  that the earlier wiring is still in the poms, that a build behind the mirror fails on
  it, and how to take it out (`socket-patch rollback <purl>`). The skip is only for
  a patch that would get the repository: one the scan would not wire anyway (the build
  selects another version) is reported under its own reason.
* **Gradle (hosted Maven).** Gradle builds get automated wiring, not a pasted snippet:
  an owned settings script pins the suffixed version, every lock file is rewritten,
  and a tripwire fails the build if the base version still resolves. See
  [Gradle](#gradle) for the rules and refusals; `redirect_gradle_manual_snippet` now
  appears only beside a refusal.
* **NuGet locked mode (hosted + vendored).** With a `packages.lock.json` and
  `dotnet restore --locked-mode`, the rewritten `contentHash` pins the patched `.nupkg` —
  a tampered or wrong package fails restore with `NU1403`. Without a lockfile there is no
  client-side content pin (vendored surfaces this as a `vendor_nuget_no_lockfile`
  warning; the feed + source mapping still force the patched copy).

* **NuGet package signatures.** The server constructs the patched `.nupkg` and removes invalidated upstream signatures. The CLI verifies and stores the served archive without repacking it. Vendoring uses a folder feed with source mapping; installations requiring signed packages need an appropriate server artifact and signing policy.

## Bazel workspaces: NuGet

rules_csharp's `nuget.from_lock` tag (in `MODULE.bazel`) downloads every package of a
`packages.lock.json` and fails the build on a file that does not match the lock's `contentHash`.
All the `nuget.from_lock` tags of a workspace make one hub (rules_csharp 0.5.0):

- It has one list of package sources, which it asks before nuget.org. Each tag in turn puts
  its `feeds` in the place of that list, and then the sources of the `nuget.config` it names
  as `nuget_config`. So the last tag that has either decides.
- It holds a package to the `contentHash` of the first lock that names it.

Hosted mode re-pins the `contentHash` of a patched package in the project's locks and names the
Socket source of the patch in the project's `nuget.config`. A hub that reads a re-pinned lock
and not that file downloads the upstream package and refuses it. A hub that reads the file and
has the package from a lock the run did not re-pin downloads the patched package and refuses
that. Either way the next `bazel build` fails with "the downloaded package does not match its
contentHash in packages.lock.json".

So `scan --mode hosted` and `get --mode hosted` read the tags, and write nothing for a NuGet
package that the hub would not take: no `nuget.config`, no re-pinned lock. The package is
`skipped` (`redirect_unconfirmed`), the run exits 0 as for any other package hosted mode does
not pin, and one warning per package names the tag by its file and line and the way on.

### The hub does not read the config

`redirect_bazel_nuget_config_undeclared`. The common case is a tag that names no
`nuget_config`, and the warning names the attribute to put on it:

```starlark
nuget.from_lock(
    nuget_config = "//:nuget.config",
    packages_lock_json = "//:packages.lock.json",
)
```

With the attribute, the same command names the Socket source in that `nuget.config`, which it
creates where the project has none, and re-pins the lock, and the next build takes the patched
package from the Socket source (rules_csharp 0.5.0 on Bazel 9.3.2, 8.8.2 and 7.7.2). That
build updates `MODULE.bazel.lock`, which records the two files: commit all three with
`MODULE.bazel`. The label is the one of the project's own config, in the package of the lock's
label: the file of NuGet's spellings (`nuget.config`, `NuGet.config`, `NuGet.Config`) that the
project directory holds, as the directory spells it, or `nuget.config` where it holds none.
Where the tag does not name its lock as a label in a plain string, or the config lies outside
the package of that label, the warning names the file and leaves the label to you.

The other cases, each with its own way on in the warning:

- **The tag that decides names another file.** Where that file is a NuGet config in a directory
  above the project, as with one `nuget.config` for several projects, run the command in that
  directory (`--cwd`): hosted mode then writes the file the tag reads. Otherwise put the
  attribute on that tag and name in the project's config the package sources of the other file
  that the build needs, because the hub takes its sources from one file.
- **The tag that decides has `feeds` and no `nuget_config`.** Put the attribute on it and name
  its feeds in the project's config: the sources of a `nuget_config` stand in the place of
  `feeds`.
- **A tag has `feeds`, and the config names no package source.** A config without a source
  leaves the `feeds` of the tags as they are; the first source in it takes their place. So
  hosted mode does not name the Socket source there until the config names those feeds: name
  them and run the command again.
- **A tag is not written out:** it stands in a comprehension or a condition, passes `**`, or
  has a `nuget_config` that is a constant or an expression. socket-patch evaluates nothing, so
  it cannot tell which file the hub reads, and a build that may break outranks a patch that is
  missed and explained. Write the tag as a call of its own, with the attribute in a plain
  string.

### Another lock holds the package

`redirect_bazel_nuget_lock_not_repinned`. A hosted run re-pins the locks of the projects in the
directory it runs in. Where another tag reads a lock outside that run which holds the package
at the same version with another `contentHash`, and the hub reads that lock first, the hub
would hold the patched package to the upstream `contentHash`. Hosted mode then writes nothing
for the package and names the tag and the lock. Run the command in a directory above both
locks (`--cwd`) that holds a solution file or a `nuget.config`, which is what makes hosted mode
look for projects below it: there it re-pins the lock of every project. Where the tags are in
more than one file their order is not known, and such a lock stands against the pin wherever
its tag is; a lock that cannot be read counts as one that holds the package. So does the lock
of a tag that does not name it as a label in a plain string, beside a tag that names a lock of
the project: the warning says to write that label out.

### What is read, and what is not

The tags are read from the checkout: the root `MODULE.bazel` and the files it includes, under
whatever name the file gives the `nuget` extension of `rules_csharp`, and the locks the tags
name. Nothing is evaluated and no Bazel is run.

- **Nothing changes** for a project in no Bazel workspace (the rule is under
  [Bazel workspaces: `.bazelignore`](#bazel-workspaces-bazelignore)), for one that restores
  into no lock file, and for one whose locks no `nuget.from_lock` call names, which Bazel does
  not build. A tag whose `packages_lock_json` is not a label in a plain string may name any
  lock, and counts as one that names the project's where no tag names a lock of the project.
  Nothing changes either for a package that no lock of the project which a tag reads holds:
  the hub does not build it from this project.
- **Hosted mode writes** when every `nuget.from_lock` is a call of its own and the last one
  that has a `nuget_config` or `feeds` names the project's config as a label in a plain string
  (`//:nuget.config`, `@//:nuget.config`, or with the root module's own name; in another case
  too, unless the directory holds both spellings, or one that is not NuGet's on a disk that
  does not fold case, beside which hosted mode writes a file of its own). Where the tags are
  in more than one file,
  every tag that has either must name the config. A tag that reads another lock and names the
  config serves, unless its lock holds the package as above.
- **A part of `MODULE.bazel` that socket-patch cannot read** (a `bazel_dep` whose name is an
  expression, an `include` it cannot follow) can hide a tag and changes nothing else: where
  the tags that are read show that the hub reads the config, hosted mode writes.
- **Not seen:** a tag of another Bazel module, whose sources and locks the hub takes as well; a
  tag that an unreadable part of `MODULE.bazel` hides; a lock in another repository; what the
  command line or an rc file tells Bazel; and what a directory of `local_package_dirs` holds.
  The hub asks those directories before every source, so with the upstream package in one the
  build fails on a re-pinned lock (measured on Bazel 9.3.2). The warning says so in a workspace
  that has the attribute; where the tags show that the hub reads the config, hosted mode
  writes as it does without Bazel.
- **Not covered:** a release of rules_csharp after 0.5.0 that gives each `name` of
  `nuget.from_lock` a hub of its own, where the two rules above hold per name and the tags are
  still read as one hub; a Bazel workspace below the directory of the run, whose tags are not
  read while the locks of its projects are re-pinned with the others; a project below the root
  of a workspace that is in no git checkout, because a workspace is looked for only up to the
  root of the project's checkout; and a project whose own locks no tag reads while a tag names
  its `nuget.config` and reads another lock that holds the package. Hosted mode writes in each
  as it does without Bazel.
- A pin that an earlier release wrote in such a workspace stays in the two files: `socket-patch
  rollback` takes it out, and the attribute makes the build read it.

## Gradle

Gradle builds are part of the `maven` ecosystem: patches are Maven PURLs and every
mode works on Gradle 6.8 or newer with Groovy or Kotlin DSL. The test grid covers
Gradle 6.9.4, 7.6.6, 8.14.3 and 9.8.0 on Linux, macOS and Windows (see
[testing](testing/README.md#gradle)). The machine-readable contract, with every code,
is the "Gradle builds" section of
[CLI_CONTRACT.md](../crates/socket-patch-cli/CLI_CONTRACT.md#gradle-builds-v50).

**Which mode to pick.** Hosted and vendored mode change files you commit, so every
checkout and CI runner builds the patched jar. Agent mode rewrites the Gradle cache
of one machine: it is undone by `--refresh-dependencies`, shared by every build that
uses the same Gradle user home, and refused when the build verifies its
dependencies. Prefer hosted or vendored for Gradle.

### Discovery

`scan` reads Gradle's cache (`<Gradle user home>/caches/modules-2/files-2.1`, plus the
read-only cache in `$GRADLE_RO_DEP_CACHE`) before `~/.m2`. The user home is found the
way Gradle finds it: `-Dgradle.user.home` in `GRADLE_OPTS`, then `GRADLE_USER_HOME`,
then `.gradle` in the account's home directory. On Unix that is the passwd entry, not
`$HOME`; when they differ, scan notes `gradle_user_home_differs`.

`~/.m2` here means the Maven local repository, found the way Maven finds it:
`MAVEN_REPO_LOCAL`, then `-Dmaven.repo.local` in `MAVEN_ARGS` (the command line), in
the project's `.mvn/maven.config`, or in `MAVEN_OPTS`, in that order, then
`<localRepository>` in `~/.m2/settings.xml`, then in the install's `conf/settings.xml`
(`MAVEN_HOME` or `M2_HOME`), then `.m2/repository` in `user.home`. `M2_HOME` itself
never names a local repository. On Windows `user.home` is `USERPROFILE`, not `HOME`.

`.mvn/maven.config` is read only for a Maven build, where Maven itself reads it: a
project with a `pom.xml` and no Gradle or Scala-tool build beside it. A Gradle
build's `mavenLocal()` never reads the file, so a Gradle project below a directory
that holds one keeps the environment's repository. The file is the one Maven's
launcher finds from the project directory: in the nearest directory at or above it
that holds a `.mvn` directory. It is read the way the project's Maven reads it:

- Maven before 3.9 splits the whole file on whitespace and fills in nothing.
- Maven 3.9 and later takes each line as one argument (`#` starts a comment), so a
  value runs to the end of its line, and from 3.9.2 fills in
  `${session.rootDirectory}`, `${session.topDirectory}`, `${user.home}` and
  `${env.NAME}`.

For both, the last `-Dmaven.repo.local=` wins, a placeholder nothing defines stays in
the path as written, and a relative path (an empty one included) is taken from the
project directory, where Maven runs. The Maven Wrapper's version says which reading
applies. Without a wrapper, when the two readings differ, the one whose directory
exists is used. When both exist no repository is guessed at: nothing in `~/.m2` is
scanned or patched and the run warns `maven_local_repository_undetermined`; set
`MAVEN_REPO_LOCAL` to choose. A `--global` run reads no project's config. Maven
before 3.9 does not read `MAVEN_ARGS`; socket-patch reads it whatever Maven is
installed.

This means a project's `.mvn/maven.config` chooses where agent mode writes. It can
point `apply`, `rollback` and `remove` at any directory laid out as a Maven
repository, including one outside the project and outside your home directory, exactly
as it points Maven there when the project is built. In that directory socket-patch
does what it does in `~/.m2`: it replaces a jar that matches the known original of a
patch with the patch service's build of it, rewrites the checksum files beside it
(`.sha1`, `.md5`), and restores both on rollback. Set `MAVEN_REPO_LOCAL` to name the
repository yourself, whatever the project's config says.

A Gradle-only build reads `~/.m2` only through `mavenLocal()`. Scan looks for it in
every settings, build, `buildSrc`, included-build, applied and init script, including
the wrapper distribution's `init.d`. Without it, `~/.m2` is not scanned, and modules
found only there are listed in a `gradle_build_ignores_m2` warning. When a script
cannot be read literally, `~/.m2` stays in the scan and scan notes
`gradle_maven_local_undetermined`. In JSON, packages from the Gradle cache carry
`inLock` when the build's lock files were read.

### Agent mode

`apply` patches every copy the build consumes. Gradle keeps one hash directory per
download of a version, and each one holding the patched files is patched. Records
keyed by members inside a jar swap in the patch service's build of the whole jar, so
they need network access (`jvm_agent_service_required` offline). Before the swap the
service's jar is compared with the installed one member by member: everything the
JVM would load outside the patched members and signature files must be identical, or
that copy is left alone (`jvm_agent_service_jar_mismatch`, naming the members). A
signed jar the patch service signed again (a security provider such as Bouncy
Castle's) may also differ in its manifest, as that signing leaves it: digest lines
changed for the patched members and added for the others, and sections added for
entries the manifest did not list. Nothing else of the manifest may differ; the CLI
contract has the rule. Jars
of up to 200,000 entries and 1 GiB inflated are handled; one past that is
`jvm_jar_too_large`. The original is
backed up under `.socket/jvm-originals/` and `rollback` restores from it. A `~/.m2`
jar that another project (or an earlier workspace over a cached `~/.m2`) patched has
no backup in this project: online, `rollback` downloads the original from the
registry and uses it only when it matches the registry's checksum and is the jar the
copy was patched from; otherwise it fails with `jvm_jar_backup_missing` and says how
to recover (roll back from the project that applied the patch, or delete the version
directory so the build downloads the jar again). `rollback`
and `remove` restore every patched writable copy, including a `~/.m2` copy the build
no longer reads (an earlier apply patched it while `mavenLocal()` was declared).
Such a copy never fails the run: one another build re-patched or rebuilt, or whose
original this project never backed up, is left as it is with
`gradle_m2_copy_not_restored`.
Guards:

- `gradle/verification-metadata.xml` present: refused
  (`gradle_verification_metadata_present`). Gradle would reject the rewritten bytes,
  so use hosted or vendored mode.
- The only copy is in `~/.m2`, which the build never reads: refused
  (`gradle_build_ignores_m2`). Build once so Gradle caches the jar, then apply.
- The only copy is in `~/.m2` and the build declares `mavenLocal()`: patched, with
  the warning `gradle_m2_may_be_unconsumed`. When another repository comes before
  `mavenLocal()`, Gradle downloads the module from it instead; build once and apply
  again.
- **Read-only cache shadowing.** A copy in `$GRADLE_RO_DEP_CACHE` is never written,
  and Gradle may read it first. The writable copies are patched but the run fails
  (`gradle_ro_cache_shadows`). Rebuild the read-only cache from a patched user home.
- A cache copy whose bytes are not the ones the patch was made for is left alone and
  fails the run (`gradle_copy_unexpected_bytes`).
- **Transform-copy staleness.** Gradle keeps derived copies of jars
  (`caches/transforms-*`, `caches/jars-*`, instrumented build-logic jars). One proven
  to come from the unpatched jar fails that copy (`gradle_transform_copy_stale`); one
  that cannot be matched is reported (`gradle_transform_copy_unverified`). Run
  `gradle --stop`, delete the named directories, and apply again.
- On Windows a jar held open by a daemon is reported as `gradle_jar_locked_by_daemon`.
  Run `gradle --stop` and retry.

Each patched Gradle copy also gets informational advisories:
`gradle_refresh_reverts` (`--refresh-dependencies` downloads a fresh, unpatched copy;
apply again), `gradle_daemon_stale` (a running daemon may still hold the old classes)
and `gradle_global_cache_shared` (every build of that user home sees the patch).

### Hosted mode

`scan --mode hosted` pins the patched jar at its Socket-only
`<version>-socket.<hex8>` version and writes, for you to commit:

- `.socket/gradle/socket-patch.hosted.settings.gradle`, an owned script whose bytes
  change only with a CLI release, and its data, `.socket/gradle/hosted-index.tsv`;
- one `apply from` line in every settings file of the checkout's builds: the root,
  `buildSrc` and each literal `includeBuild`. A missing settings file is created and
  marked so that `rollback` deletes only files it created;
- every `gradle.lockfile`, `buildscript-gradle.lockfile` and legacy
  `gradle/dependency-locks/*.lockfile` entry of the patched GA, moved to the suffixed
  version;
- the suffixed component in an existing `gradle/verification-metadata.xml`.

The script routes the suffixed version to the Socket repository only
(`exclusiveContent`). It substitutes every request that would select the patched base
version, including transitive requests, ranges, dynamic (`1.+`) and rich versions. It
rejects other versions at or below the base and fails the build if one still
resolves. It also checks the jar's sha256. A request whose selector does not admit the
base (an explicit newer version, a lock or `strictly` above the base, a transitive
bump) is left alone, so a version *above* the base still resolves and an upstream fix
is never downgraded. `vex` withholds the statement when a lock file records such a
version (`vex_gradle_lock_above_base`), while `list`, `rollback` and `remove` still
find the pin; without dependency locking it judges the installed suffixed copies. A
dynamic or range selector that admits the base is pinned like a lock: it keeps
resolving the patched version after a newer upstream release appears
(`redirect_gradle_dynamic_selector_pinned`); declare the newer version to move past
the patch. A `latest.release` / `latest.integration` request is refused
(`redirect_gradle_latest_selector`): the script cannot rewrite it, and with every
upstream version at or below the base rejected it would not resolve until upstream
ships a newer release. The apply line carries a digest of the index, so a changed pin set
invalidates the configuration cache.

**Detached configurations.** Every project and buildscript configuration is pinned.
Configurations a plugin creates with `configurations.detachedConfiguration` are not
reached and may resolve the upstream version. Every hosted run says so
(`redirect_gradle_detached_configs_unguarded`).

**Gradle module metadata.** When the Socket repository serves a suffixed `.module`,
the wiring uses it silently. A deployment that does not serve one warns
`redirect_gradle_module_metadata_unavailable`; Gradle then resolves the suffixed pom,
so variants and capabilities that only the upstream `.module` declares are not
applied.

A dep is refused, with nothing written for it, when the build is outside what the
script can pin: a wrapper below 6.8, Android or Kotlin Multiplatform plugins, an
`includeBuild` the CLI cannot follow, a custom `lockFile`, the GA on a
settings-script classpath (declared, or in a `settings-gradle.lockfile`), a
classifier declaration, a `latest.*` request, a `strictly` constraint admitting only
versions below the base, a user `exclusiveContent` rule claiming the group, a lock entry below the base
(re-lock first), a GA that is vendored, or a grant that serves the original
coordinates. Each refusal has its own `redirect_gradle_*` code and is followed by
`redirect_gradle_manual_snippet`, a paste-able snippet in the build's DSL that applies
the owned script's rules (it adds no dependency, and versions above the base still
resolve).

`rollback` and `remove` restore without the network, using only the index. `list`,
`vex` and the other readers re-run the planner's build-level checks, so a build changed
after the scan in a way the pin cannot reach (a settings-classpath declaration, an
`includeBuild` the CLI cannot follow, …) stops attesting. A vendored Gradle package is
taken over only when the hosted planner would accept it. Otherwise it keeps its
vendored patch.

### Vendored mode

See [JVM vendoring](design/maven-vendoring.md#gradle). In short: the original GAV is
committed under `.socket/vendor/gradle/`, a settings script serves it with
`exclusiveContent` and verifies its sha256, and lock files and build scripts stay
unchanged. Run it from the build root: a subproject directory is refused
(`not_build_root`). A root with both `pom.xml` and a Gradle build wires both.
Classifier jars a build declares are vendored too, and a derived `maven-metadata.xml`
keeps ranges on the vendored version. Existing pgp-only verification entries, and the
classifier jars the tree serves, get a checksum. Refusals use `vendor_jvm_shape_unsupported` /
`vendor_jvm_upstream_unavailable`, and partial wiring uses `vendor_jvm_degraded`
(VEX withheld). Each detail starts with `reason: <reason>:`. The tree root owns a
`.gitignore` (`!*`) so a `*.jar` rule (GitHub's stock Java.gitignore) cannot drop the
vendored jars from the commit; a rule that ignores `.socket/` itself is refused
(`vendor_artifact_gitignored`) before anything is written.

In a Bazel workspace whose rules_jvm_external hub builds the artifact from a lock, vendored
mode also commits the jar for that hub, and it is the only thing it does in a checkout that
has no Maven, Gradle, sbt or scala-cli build: see
[Bazel workspaces: Maven](#bazel-workspaces-maven).

### VEX

`vex` re-hashes every copy a build may load: the `~/.m2` copies it reads, every
Gradle hash directory, and the suffixed copies of a hosted pin. A derived copy proven
to come from the unpatched jar, or an older one that does not match the patched jar,
withholds the statement (`vex_gradle_unpatched_copy`). A derived-cache walk cut short
on a very large cache warns `vex_gradle_derived_cache_unchecked` and does not
withhold; a derived-cache check that does not finish at all withholds the statement
(`vex_gradle_derived_cache_check_failed`).

## Scala build tools: sbt, Mill, scala-cli

sbt, Mill and scala-cli resolve `pkg:maven` artifacts, so they are build shapes
inside the `maven` ecosystem, not an ecosystem of their own: `--ecosystems maven`
covers them, and their PURLs, rollout budgets and ledgers are Maven's. A root
holding `build.sbt`, `build.mill`, `build.mill.yaml`, `build.sc` or
`project.scala` counts as a Maven project for discovery. Design, probes and the
exact generated bytes: [sbt, Mill and scala-cli support](design/sbt-support.md);
the tested versions: [sbt compatibility](testing/sbt-compatibility.md).

| Tool | Agent | Hosted | Vendored |
|---|---|---|---|
| sbt 0.13.18 – 1.2 (Ivy) | Ivy cache | `socket-patch.sbt` | `socket-patch-vendor.sbt` + suffixed tree |
| sbt 1.3 – 1.13, 2.0 (Coursier) | Coursier cache | `socket-patch.sbt` | `socket-patch-vendor.sbt` + suffixed tree |
| sbt older than 0.13.18 | Ivy cache (untested) | refused (`redirect_sbt_unsupported_version`) | refused (`vendor_sbt_unsupported_version`) |
| Mill 0.11 – 1.x | Coursier cache | snippet | not wired |
| scala-cli, directory build | Coursier cache | snippet | owned files + same-GAV tree |
| scala-cli, single file | Coursier cache | snippet | pass the tree with `-r` (below) |

Tested: sbt 0.13.18, 1.2.8, 1.3.13, 1.9.9, 1.13.0 and 2.0.9 in every sbt mode
(JDK 8 up to 1.3.x, 17 after), Mill 1.1.10 and scala-cli 1.17.1. sbt 2.1 and
later is wired with a `*_version_untested` warning.

### Agent mode: Coursier and Ivy caches

Agent mode patches the shared caches the tools resolve into, next to `~/.m2`
(only for an sbt, Mill or scala-cli project: a Maven or Gradle project keeps
crawling `~/.m2` alone; `--global` crawls every cache):

- **Coursier** (sbt 1.3+, sbt 2, Mill, scala-cli): `$COURSIER_CACHE`, a
  `-Dcoursier.cache=` in `JAVA_OPTS` / `SBT_OPTS` / `.jvmopts` / `.sbtopts`,
  `-Dsbt.coursier.home`, then the OS default (`~/.cache/coursier/v1`,
  `~/Library/Caches/Coursier/v1`, `%LOCALAPPDATA%\Coursier\cache\v1`).
  Coursier keeps hidden checksum files beside each cached file and silently
  re-downloads a file that disagrees with them, so `apply` and `rollback`
  rewrite them to the new bytes (the envelope's `sidecars[]` lists them).
- **Ivy** (sbt 0.13 – 1.2, or `useCoursier := false`): `-Dsbt.ivy.home` /
  `-Divy.home`, then `~/.ivy2/cache`.

The crawl is not scoped to the build: as with `~/.m2`, every cached GAV is
queried (a Coursier directory holding only the `.pom` of a version it
considered but did not pick is no copy), and a GAV cached in several roots is
patched (and restored) in every one, since the build loads whichever copy its
resolver picks: the same every-copy fan-out as [Gradle](#gradle), and `vex`
re-hashes each copy. An Ivy module's sources jar under `srcs/` is found for a
`?classifier=sources` patch. Every project on
the machine sees the patch. A running sbt server, Bloop or Metals holds the old
classpath: restart it after `apply`. Agent patches are matched as whole jar
files.

### Hosted mode: `socket-patch.sbt`

`scan` (hosted is the default) and `get --mode hosted` wire an sbt build root
(`project/build.properties` naming `sbt.version` 0.13.18 or later) through one
generated root file, `socket-patch.sbt`. No user file is edited. For each
patched GA it:

- forces the Socket-only `<base>-socket.<hex8>` version build-wide with
  `dependencyOverrides`;
- adds a `file:` resolver over the gitignored `.socket/sbt-hosted/maven2/`,
  moved ahead of the default repositories on sbt 0.13 / 1.x, and downloads the
  sha256-pinned jar and pom there on the first sbt load;
- installs a load-time verifier that fails `sbt update` when a project
  resolves another version or a pinned artifact whose bytes are not pinned,
  or declares the GA at a version newer than the patched base (the override
  would otherwise force it back down).

Commit `socket-patch.sbt`. The first load after a fresh checkout needs to reach
the patch server; later loads work offline from the downloaded copies.

A new pin is gated on what sbt itself resolved, read from `target/` (never by
running sbt): **run `sbt update` (for the whole build) before
`socket-patch scan`.** With no evidence, or any project's evidence older than
the build files, nothing is written and the run warns once
(`redirect_sbt_no_resolution_evidence`, `redirect_sbt_resolution_stale`) and
exits 0. A patch whose GA some project
resolves at another version, the Scala runtime, or a build that reassigns
`dependencyOverrides` / `resolvers` (`:=`, `~=`) is refused. Re-runs re-check
existing pins against fresh evidence: after a dependency edit, `sbt update`
then a re-run re-verifies the pin and records the build's new dependency
digest; a build that now declares the GA newer than the patched base is
refused (`redirect_sbt_pin_declared_newer`: roll the patch back, or declare
the base again). `rollback` / `remove` restore the file
offline. `vex` attests a pin that post-wiring evidence verifies, or else from
the copy sbt downloaded into `.socket/sbt-hosted/`, but never one whose bytes
the build provably does not use: a `dependencyOverrides` reassignment, an
`onLoad` reassignment that drops the generated load-time verifier, or
evidence recorded after the wiring that still resolves the base version or other bytes
(`vex_sbt_pin_bypassed`). The full code list is in
[`CLI_CONTRACT.md`](../crates/socket-patch-cli/CLI_CONTRACT.md) (**Hosted
sbt**).

### Vendored mode: `socket-patch-vendor.sbt`

`vendor` / `scan --mode vendored` write the patched jar and its pom into the
committed tree `.socket/vendor/maven2/<g>/<a>/<base>-socket.<hex8>/` and one
generated root file, `socket-patch-vendor.sbt`, which pins every tree file's
sha256, resolves from the tree (ahead of the default repositories on 0.13 /
1.x, so the build resolves the patch with the network down) and forces the
suffixed version. Its load-time check fails the sbt build closed on a tampered
tree or a replaced pin. Commit both (`socket-patch-vendor.sbt` and
`.socket/vendor/`: without the root file the build resolves the unpatched
upstream), then run `sbt update`; the tree carries its own `.gitignore`
(`!*`, so a `*.jar` rule cannot drop the jar) and `.gitattributes`. The same
`sbt update` evidence gate as hosted applies (`vendor_sbt_*` codes; a skip is
reported `skipped`, exit 0). Vendoring over a hosted pin runs the gate before
the hosted pin is restored, so a pin the gate would stop stays hosted. The hosted
and vendored files never pin the same GA. Revert, `rollback`, `vendor --check`
and `repair` cover the generated file and tree.

### scala-cli directory builds (vendored)

A root holding `project.scala` and no `pom.xml`, Gradle or Mill build is a
scala-cli directory build. `vendor` writes only files socket-patch owns: a root
`socket-patch.scala` that includes a guard inside the committed same-GAV tree
`.socket/vendor/coursier/`, plus `.socket/vendor/coursier-index.tsv`. Deleting
the tree fails the build (`File not found`) instead of resolving upstream. The
gate reads scala-cli's Bloop project files under `.scala-build/.bloop/`: run
`scala-cli compile --test .` (with the default Bloop server) first. A build
that declares its own repository (`//> using repository`, `-r`) is refused,
because scala-cli would consult it before the tree; move it to
`COURSIER_REPOSITORIES`, which is consulted after. Windows and project paths
holding `%` or a non-ASCII character are refused.

**Single-file runs** (`scala-cli run main.scala`) ignore the directory wiring.
After vendoring the directory, pass the tree explicitly:
`scala-cli run main.scala -r file://$PWD/.socket/vendor/coursier`.

### Mill

Mill builds get agent mode and, in hosted mode, a paste-able snippet per patch
(`redirect_mill_manual_snippet`): a repository plus the forced suffixed version
(Mill 1.x: `repositories` + `depManagement`, each appended to the module's own
inside `Task { … }`; 0.11 / 0.12: `repositoriesTask` + `.forceVersion()`). Nothing is written. `vendor` does not wire a Mill build: the
only committable mechanism found edits the user's `.mill-jvm-opts` and replaces
the repository list, so it is left as a
[documented manual recipe](design/sbt-support.md#mill-vendored-mode-deferred).

### Limitations

- Pins need fresh `sbt update` evidence for every declared project; a build
  whose project definitions cannot be read statically is skipped
  (`*_resolution_incomplete`).
- `-Dsbt.override.build.repos=true` drops the build's resolvers, so the
  generated file fails the load (warned at wiring time).
- A `build.sbt.lock` (sbt-dependency-lock) is refused; run
  `sbt dependencyLockWrite` after wiring by hand.
- Classified artifacts other than `sources` / `javadoc`, and the Scala runtime
  (`org.scala-lang`), are refused.
- The in-memory hosted engine (GitHub App) has no `target/` evidence, so it
  never wires sbt.
- Vendored sbt VEX attests through the vendor ledger; the generated file alone
  is not a VEX reference. The ledger entry needs the same `target/` evidence
  as a hosted pin, and is omitted as `vex_sbt_resolution_unverified` while
  that evidence does not show the build resolving the pinned bytes: before
  `sbt update` has run since vendoring or since a build source changed,
  while a build source reassigns `dependencyOverrides` / a resolver setting with
  `:=`, `~=` or `--=`, or a `build.sbt.lock` exists, while something forces another
  version, and always for a build whose projects cannot be read statically
  (`projectMatrix`, `crossProject`, a computed `Project(...)`). The note
  names the cause and its remedy.

## Bazel workspaces: what is supported

A Bazel build takes each package from what a ruleset reads in the checkout (a lock, a call in
`MODULE.bazel`), in a repository of Bazel's own, and not from the copies a package manager
installed. So the [matrix at the top](#mode--ecosystem-matrix) does not carry over to a
project that Bazel builds: this table takes its place there. A project that sits in a Bazel
workspace and that Bazel does not build keeps the matrix at the top.

| Ecosystem, and how Bazel takes its packages | Hosted | Vendored | Agent | VEX |
|---|---|---|---|---|
| npm: aspect_rules_js `npm.npm_translate_lock` over a pnpm lock | Supported with `pnpm-workspace.yaml` in the `data` of a hub that runs pnpm 11 or later | Supported | Not supported | Supported |
| PyPI: rules_python `pip.parse` over a requirements file | Supported | Supported with rules_python 2.5.0 | Not supported | Supported |
| Go: gazelle `go_deps.from_file` over `go.mod` | Supported | Supported | Not supported | Supported with a hosted or vendored patch |
| RubyGems: rules_ruby `ruby.bundle_fetch` over `Gemfile.lock` | Supported with no `gem_checksums` on the call, or with one written out in the call that does not name the gem or holds it to the patched gem's sha256 | Not supported | Not supported | Supported |
| Cargo: rules_rust `crate.from_cargo` over `Cargo.lock` | Supported with `cargo_config` on the hub | Supported | Not supported | Supported with a hosted or vendored patch |
| NuGet: rules_csharp `nuget.from_lock` over `packages.lock.json` | Supported with `nuget_config` on the tag | Not supported | Not supported | Supported with no restored copy on the machine |
| Composer: a rule of your own that runs `composer install` from `composer.lock` | Supported | Not supported | Not supported | Supported with a hosted patch |
| Maven: rules_jvm_external `maven.install` with a `lock_file` | Supported with Bazel 7.4.0 or later | Supported with Bazel 7.4.0 or later | Not supported | Supported with a hosted or vendored patch |

These words are the table's own, not the [v5 support tiers](#v5-support-tiers). In
particular "Not supported" does not mean that the command refuses: in several cells it runs,
exits 0 and leaves a build that fails (the known problems below). What a cell says:

- **Supported**, for hosted and vendored mode: after the one command of the mode
  (`scan --mode hosted` or `scan --mode vendored`; for Maven
  `get <purl> --mode hosted` or `get <purl> --mode vendored` at the Bazel root), the next
  `bazel build` takes the patched package with no other step, and the undo (`rollback`,
  `vendor --revert`) brings the upstream build back. The one exception is a build that may
  not update Bazel's own lock (see below). A test builds exactly that on a real Bazel, for
  the shape the list below names.
- **Not supported**: socket-patch promises nothing about what a Bazel build holds after the
  mode ran, so do not use it for a package that Bazel builds. In most of these cells the
  patch does not reach the build, or the build breaks (see the known problems below).
  Vendored mode for PyPI, RubyGems and Composer declines instead: the command exits 1 and
  writes nothing. For PyPI and RubyGems that is where the call of the row reads a file the
  run would rewrite
  ([Bazel workspaces: PyPI and RubyGems vendored mode](#bazel-workspaces-pypi-and-rubygems-vendored-mode)),
  for Composer in every Bazel workspace ([Bazel workspaces: Composer](#bazel-workspaces-composer)).
  For PyPI it declines outside the condition of its cell, which
  [Bazel workspaces: PyPI vendored mode as a download cache](#bazel-workspaces-pypi-vendored-mode-as-a-download-cache)
  spells out.
- **Supported**, for VEX: `socket-patch vex` and `--vex` say `not_affected` of a package the
  Bazel build takes patched, and `affected` of one whose patch Bazel does not build.
  [Bazel workspaces: VEX](#bazel-workspaces-vex) has the cases and the limits; a vendored gem
  is one of the limits.
- **Supported with a condition**, for VEX: under the condition the cell names, the document
  says `not_affected` of a package the Bazel build takes patched, and a test holds it to
  that (for a hosted Maven patch a test without Bazel). It does not say `affected` of a
  package whose patch is in no build of Bazel's, one that is only in an installed copy, say:
  of that package it still says `not_affected`. Do not publish that document. For Maven,
  [Bazel workspaces: Maven](#bazel-workspaces-maven) says what `vex` checks of the hub before
  it attests an entry.

**Agent mode is not supported for Bazel builds, in any ecosystem.** Agent mode is made for
the copies a package manager installed: `socket-patch apply` patches them after each install.
A Bazel build takes its packages from what its rulesets read and runs no such step. Whether
an agent-mode patch reaches a Bazel build differs from one ruleset to the next, and no
release promises it for any of them. Use hosted mode for a package that Bazel builds, or
vendored mode where the table lists it. Agent mode stays what it is for whatever uses the
installed copies outside Bazel.

What the table was tested with:

- **Bazel** 9.3.2, 8.8.2 and 7.7.2 on Linux, and 9.3.2 on macOS (not Composer); Maven also
  on 7.4.0. Every row is a workspace under Bzlmod (`MODULE.bazel`): nothing is tested for
  dependencies that a `WORKSPACE` file declares.
- **npm**: aspect_rules_js 3.6.0, `npm.npm_translate_lock(pnpm_lock = "//:pnpm-lock.yaml")`
  without `update_pnpm_lock`, and a lock of `lockfileVersion: '9.0'`. Hosted mode also with
  `update_pnpm_lock = True`, where rules_js runs a pnpm of its own: with the pnpm it picks
  itself (10.34.9) and no `data`, and with pnpm 11.28.10 and `pnpm-workspace.yaml` in `data`.
  [Bazel workspaces: npm](#bazel-workspaces-npm) says what hosted mode does on such a hub.
- **PyPI**: rules_python 2.5.0-rc4, `pip.parse(requirements_lock = "//:requirements.txt")`,
  and a root `requirements.txt` with hashes. Vendored mode pins the wheel by its URL, as
  hosted mode does, commits it, and makes Bazel take the committed copy with a `--distdir`
  line in [`.bazelrc`](#bazel-workspaces-pypi-vendored-mode-as-a-download-cache); the test
  builds it with the patch host stopped.
- **Go**: gazelle 0.54.0 with rules_go 0.65.0 (Bazel 9 and 8) and gazelle 0.45.0 with
  rules_go 0.53.0 (Bazel 7), `go_deps.from_file(go_mod = "//:go.mod")` with
  `go_deps.config(check_direct_dependencies = "error")`, and the module required directly in
  `go.mod`. Vendored mode keeps its copy out of Bazel's packages with
  [`.bazelignore`](#bazel-workspaces-bazelignore). Hosted mode for Go has the limit of the
  matrix at the top: free-tier patches.
- **RubyGems**: rules_ruby 1.0.0-rc2, `ruby.bundle_fetch` with `gemfile` and `gemfile_lock`,
  with no `gem_checksums` or with one written out in the call that does not name the gem or
  holds it to the sha256 of the patched gem, and a `Gemfile.lock` that has a `CHECKSUMS`
  section. That section is what holds the patched gem to its sha256, in Bundler's step of
  the build: with a lock that has none the build takes whatever the patch registry serves.
  A gem that `gem_checksums` names is left as it is until its entry holds the sha256 of the
  patched gem, and so is every gem beside a `gem_checksums` that is not written out in the
  call: see [Bazel workspaces: RubyGems](#bazel-workspaces-rubygems).
- **Cargo**: rules_rust 0.75.0 (Bazel 9 and 8) and 0.56.0 (Bazel 7), `crate.from_cargo` with
  `cargo_lockfile = "//:Cargo.lock"`, `manifests = ["//:Cargo.toml"]` and
  `cargo_config = "//:.cargo/config.toml"`, and no cargo-bazel lock (`lockfile`).
- **NuGet**: rules_csharp 0.5.0, `nuget.from_lock` with
  `packages_lock_json = "//:packages.lock.json"` and `nuget_config = "//:nuget.config"`.
  `scan` finds a NuGet package only where a restore unpacked it (NuGet's global packages
  folder, a folder that an `obj/project.assets.json` records, or a `packages` folder): on a
  machine where only Bazel ever ran it finds none, exits 0 and writes nothing.
- **Composer**: no ruleset builds PHP, so the two shapes are rules a project writes itself: a
  repository rule that runs `composer install` from the committed `composer.lock` and takes
  the lock with `rctx.read`, and a genrule that runs it in a build action. Composer 2 and PHP
  are the machine's own. Run the command in the project's directory. A project that commits
  its `vendor/` tree for Bazel to read is not one of the two.
- **Maven**: rules_jvm_external 7.2 (Bazel 9), 6.9 (Bazel 8) and 6.5 (Bazel 7), a hub with a
  `lock_file`. [Bazel workspaces: Maven](#bazel-workspaces-maven) says what the command
  writes and when it declines; a hosted `scan` at the Bazel root finds a hub's artifacts, a
  vendored one does not. Vendored mode keeps the committed jar out of Bazel's packages with
  [`.bazelignore`](#bazel-workspaces-bazelignore). Bazel checks no digest of that jar when
  it builds: `socket-patch vendor --check` does, so run it in CI.

A ruleset, a release of one or a way of calling it that the list does not name is not tested.
Treat it as not supported until a build after the command has shown you the patched package.

Bazel's own lock: a command or an undo leaves `MODULE.bazel.lock` stale for PyPI on Bazel 8.5
and later (hosted and vendored mode), for NuGet, and for Cargo under rules_rust 0.75.0. A build that may not update the
lock (`--lockfile_mode=error`) fails until one that may, or
`bazel mod deps --lockfile_mode=update`, has rewritten it. Commit the rewritten lock with the
patch. The same holds for the file of hashes that rules_js keeps under `.aspect/` for a hub
with `update_pnpm_lock`: a build that may not update it (`ASPECT_RULES_JS_FROZEN_PNPM_LOCK`)
fails until one that may has rewritten it.

Known problems. In each of these a command exits 0 today and the next Bazel build fails:

- **Vendored mode for NuGet.** The path of the committed copy means nothing where Bazel
  runs: rules_csharp reads it as a URL (`Bad URL`, or a crash of Bazel 9.3.2). Run
  `socket-patch vendor --revert`, then `socket-patch scan --mode hosted`. Measured by hand on
  the three Bazel releases; no test of this repository runs that build.
- **Vendored mode for Composer, where its refusal is lifted or does not apply.** In a Bazel
  workspace vendored mode declines a Composer package:
  [Bazel workspaces: Composer](#bazel-workspaces-composer) has the refusal, what lifts it and
  the cases it does not see. In those cases the command exits 0, and a Composer that a Bazel
  rule runs in another directory fails the build with `Source path ... is not found`. Run
  `socket-patch vendor --revert`, then `socket-patch scan --mode hosted`. A test of this
  repository builds that failure on the three Bazel releases.
- **Hosted Cargo on a hub without `cargo_config`**, which is the hub as the rules_rust README
  shows it: the hub's cargo does not see the patch registry that `.cargo/config.toml` defines
  (`registry index was not found in any configuration`). Add
  `cargo_config = "//:.cargo/config.toml"` to the `crate.from_cargo` call and commit that
  file, or use vendored mode, or run `socket-patch rollback`.
- **Cargo on a hub with a cargo-bazel lock** (`lockfile`), in hosted and vendored mode: the
  build stops at ``The current `lockfile` is out of date`` until the repin that message names
  (`CARGO_BAZEL_REPIN=true bazel build ...`). After it the build is the patched one; in
  hosted mode the hub needs `cargo_config` as well.
- **Hosted NuGet on a tag without `nuget_config`**: Bazel asks nuget.org alone and the
  package fails the lock (`does not match its contentHash in packages.lock.json`). Give the
  tag `nuget_config = "//:nuget.config"` and commit that file, which is the shape the table
  lists; or run `socket-patch rollback`, which restores the lock and leaves the
  `nuget.config` it created behind.
- **`rollback` of a hosted gem whose `gem_checksums` entry you changed** to the sha256 of
  the patched gem, as the scan's warning says to: the undo restores `Gemfile` and
  `Gemfile.lock` and leaves the call, which then holds the upstream gem to the wrong sha256
  (`Bundler found mismatched checksums`, or `Checksum was ... but wanted ...` on a machine
  with an empty repository cache). Put the old sha256 back in the entry. See
  [Bazel workspaces: RubyGems](#bazel-workspaces-rubygems).
- **A hosted gem that a call socket-patch does not read holds in `gem_checksums`** (a part
  of `MODULE.bazel` it cannot read, and the cases under *Not seen* and *Not covered* of
  [Bazel workspaces: RubyGems](#bazel-workspaces-rubygems)): the scan pins the gem as it
  does without Bazel, and the build fails in the same two ways, or, with a lock that has no
  `CHECKSUMS` section, keeps the upstream gem. Change the entry by hand to the sha256 of
  the patched gem (the scan wrote it for the gem in the lock's `CHECKSUMS` section, where
  the lock has one), or run `socket-patch rollback`.
- **Vendored npm on a hub with `update_pnpm_lock = True`** (measured with pnpm 9 and 10):
  the pnpm that Bazel runs does not see `.socket/vendor`. Use hosted mode there.
- **Hosted npm on such a hub with a pnpm of 11 or later, when hosted mode is told not to
  write `trustLockfile: true`** (`--no-trust-lockfile-config`): the lock is pinned, with the
  warning that pnpm 11 rejects it, and the pnpm that Bazel runs does
  (`ERR_PNPM_TARBALL_URL_MISMATCH`; measured by hand with the option on Bazel 9.3.2). Run
  `socket-patch rollback`, and scan again without the option. A `trustLockfile: false` of
  the project's own is not this case: hosted mode pins nothing beside it (see
  [Bazel workspaces: npm](#bazel-workspaces-npm)).
- **`rollback` of a hosted npm pin on such a hub that an earlier release wrote, where the
  `pnpm-workspace.yaml` the hub lists holds only what hosted mode writes**: the undo removes
  the file, and the call then names a missing one. Put the file back with a comment line in
  it. Hosted mode pins nothing beside such a file now.
- **Vendored Go with gazelle 0.36.0 or older**: `go_deps` rejects the directory `replace`
  (`local file path not supported in replace directive`). Use hosted mode, or a gazelle of
  the list above.

In these a command exits 0 and the Bazel build passes on the unpatched package:

- **Hosted NuGet on a machine without a restore.** `scan` reads no package out of
  `packages.lock.json`, so where only Bazel ever ran it finds none and writes nothing. Run it
  where `dotnet restore` has run.
- **Go, when another Bazel module of the build requires a higher version** of the patched
  module: gazelle builds that version and drops the replacement. With
  `go_deps.config(check_direct_dependencies = "error")` and the module required directly in
  `go.mod`, as in the list above, gazelle fails the build instead.
- **Hosted PyPI, when `pip.parse` takes the requirements of the build's platform from
  another file** than the one socket-patch rewrote (`requirements_by_platform`,
  `requirements_linux` and its siblings).

[Bazel workspaces: VEX](#bazel-workspaces-vex) lists what the document says in such cases.

And four that concern neither:

- **Vendored PyPI is a download cache, not a lock that names the copy.** The line of
  `requirements.txt` is the hosted one, so pip outside Bazel asks the patch host for the
  wheel; Bazel replaces a changed or missing copy from the patch host, without a message,
  when it can reach it (it never builds other bytes than the pinned wheel's); and a
  downloader config that blocks the patch host fails the build although the copy is
  committed, which is why vendored mode declines where an rc file of the checkout names
  one or imports a file from outside the checkout. `socket-patch vendor --check` is what
  holds the committed wheel to the patch: run it in CI.
- **Vendored Cargo under rules_rust 0.75.0**: a build writes a `BUILD.bazel` into the
  committed copy, and right after it `vendor --check` exits 1 (`vendor_inventory_mismatch`)
  and `vex` writes no document, although the build is the patched one. A second
  `scan --mode vendored` puts the copy right.
- **`vex` for a hosted NuGet patch**, on a machine whose NuGet folder still holds the
  unpatched package, as the one that ran the scan does: it writes no document and exits 1
  (`not_applied`), although the Bazel build is the patched one. Where that folder holds
  nothing, as on a runner that only ran Bazel, it attests the package.
- **Hosted NuGet prints the access token of the patch in the build's output.** rules_csharp
  asks the Socket source for every package of the lock, and Bazel prints a warning with that
  source's URL, the token in it, for each package the source does not hold.

## Bazel workspaces: npm

aspect_rules_js reads the pnpm lock itself, so a hosted pin in `pnpm-lock.yaml` is what the
build links, and no pnpm runs. One wiring differs. With `update_pnpm_lock = True` on
`npm.npm_translate_lock`, rules_js runs a pnpm of its own during the build whenever the lock
or a `package.json` is not what the hashes it keeps under `.aspect/` say:
`pnpm install --lockfile-only`, in a directory that holds the lock, the `package.json` files
and what the call lists as `data`, and nothing else of the checkout.

pnpm 11 and later reject a lock that names the patch server unless `pnpm-workspace.yaml`
holds `trustLockfile: true`, which hosted mode writes. A hub that does not list that file
hides the setting from its pnpm, and the build fails (`ERR_PNPM_TARBALL_URL_MISMATCH`). For
such a hub hosted mode therefore writes nothing for the project's root pnpm lock:
`scan --mode hosted` and `get --mode hosted` exit 0, report each npm package of that lock as
skipped (`redirect_unconfirmed`) and warn `redirect_pnpm_bazel_workspace_hidden`. A project
that also has a lock of npm's gets no pin there either: a package that the unpinned pnpm
lock still names is skipped as `redirect_unattributable`. The members' own locks of a
workspace that keeps one lock per member (`sharedWorkspaceLockfile: false`) are pinned as
without Bazel: the hub reads the root lock alone. The build stays the unpatched one that
passes. The warning names the call by its file and line, as the file writes it, and the line
to add to it; for a project below the Bazel root it says that its paths are from that root:

```starlark
npm.npm_translate_lock(
    name = "npm",
    data = ["//:pnpm-workspace.yaml"],
    pnpm_lock = "//:pnpm-lock.yaml",
    update_pnpm_lock = True,
)
```

Run the command again after that: it pins the lock, and the next build takes the patched
package. rules_js asks for this `data` itself (`docs/pnpm.md`, "update_pnpm_lock").

**No named registries for a lock that a hub reads.** For pnpm 11.20 and later hosted mode
can route a patched release through a named registry of `pnpm-workspace.yaml` in place of
`trustLockfile` (see pnpm above). It never does for a lock that a rules_js hub reads: one
that an `npm.npm_translate_lock` names in a plain string, the root lock or a member's own,
or a call whose `pnpm_lock` is not written out, whatever else the call says. In a Bazel
workspace it takes the route only where it is certain that no hub reads the lock, so what
the reader could not see counts as a hub that may: a file that `MODULE.bazel` includes and
that is missing or unreadable, a use of the extension that is not a plain call of a tag,
and a `WORKSPACE` file that cannot be read or that brings in rules_js (a `load` from
`@aspect_rules_js`, a `load` of `npm_translate_lock`, or a call of that rule), whose
repositories are not looked through. A `WORKSPACE` file that is about something else
blocks nothing. Unlike the answer above, which passes over what it cannot see so that no
project loses a patch, declining the route costs nothing: the project gets the same pin as
before, and the warning names what was not read ("… because a Bazel hub may read the pnpm
lock (WORKSPACE:3: it brings in rules_js, …) …"). The lock
reader of rules_js is not the reason: it takes a routed lock (measured on macOS: rules_js
3.6.0 on Bazel 9.3.2 builds one for a hub without `update_pnpm_lock`, and the packages it
builds hold the patched bytes; rules_js 2.9.3 on Bazel 8.8.2 does too). The pnpm that a
hub runs with `update_pnpm_lock` is. It sees `pnpm-workspace.yaml` only where the call
lists it, and it may be older than pnpm 11.20: rules_js picks a pnpm 10 where the
workspace states none. Run as the hub runs it (`pnpm install --lockfile-only` beside the
lock and `package.json`, without the workspace file), pnpm 11.28.13 and 12.22.0 reject a
routed lock (`ERR_PNPM_MISSING_NAMED_REGISTRY`, measured). No Bazel test leg builds a
routed lock with `update_pnpm_lock` yet, so for now every such project is pinned exactly
as it is on a patch service that offers no registry, which is the pin the Bazel legs
build, and the `redirect_pnpm_trust_lockfile` warning names the call ("… because a Bazel
hub reads the pnpm lock (MODULE.bazel:7), and a lock that a hub reads is not routed
yet …"). For a project below the Bazel root it says, as the warning above does, that its
paths are from that root. A project that was routed before the
hub was there leaves the route on its next scan, the lock and the workspace file together.
Where hosted mode writes nothing for the root lock (the hub above), a route of an earlier
run is left exactly as it is, in the workspace file and in every lock, and a
`pnpm-workspace.yaml` that holds nothing but such a route counts as a file that holds only
what hosted mode writes. That holds for every hosted scan, whatever it was granted: one
with a patch for a package of the lock, one with none and one that crawled nothing all
leave the files and give the same warning. `repair`, `scan --prune` with no mode,
`rollback` and `remove` settle a route from the lockfiles alone and work as without Bazel.
They read no Bazel file, for this route as for any other hosted pin: under a hub whose
`data` lists a `pnpm-workspace.yaml` that a routed scan created, they still delete that
file with the last of the route, and the build is then handed a missing file. Put a
comment line in the file first, as the warning of a hosted scan says; a hosted scan itself
never deletes the file under a hub that reads, or may read, the lock.

The file the hub lists has to be one that a pin and its undo leave standing, so hosted mode
also writes nothing for a hub that lists it in two cases, and the warning then names what
the file needs and no label:

- **The file would hold only what hosted mode writes**: there is none, or it is empty, or
  holds only `packages:` and `- '.'`, or is the file an earlier hosted run created. Hosted
  mode would create or fill it, but `rollback` removes a file that holds nothing else (it
  cannot tell it from one hosted mode created), and the call would then name a file that is
  not there, which fails the build. Put a comment line in the file, creating it where there
  is none. The same step comes first, before the label, where the hub does not list the
  file yet.
- **Hosted mode does not write the setting to the file**: it says `trustLockfile: false`
  (or any value but `true`), which hosted mode leaves as it is, or it is YAML that a line
  cannot be added to (a flow-style root, several documents). The pnpm of the hub would read
  the file and still reject the lock. Set `trustLockfile: true` in it yourself.

Hosted mode withholds when one call names the project's `pnpm-lock.yaml` in a plain string
and all three hold for it:

- `update_pnpm_lock` is `True`, or is not written out as `True` or `False`.
- `data` is not a list of strings that holds the label of the `pnpm-workspace.yaml` beside
  the lock, or it is and the file is one of the two cases above.
- The pnpm it runs is stated as 11 or later, or in a way that is no version (`latest`, a
  constant, a `package.json` that cannot be read). That pnpm is the repository `use_pnpm`
  names, `@pnpm` without one, and a `pnpm.pnpm` tag of that `name` states its release: in
  `pnpm_version`, or in the `packageManager` of the `package.json` that `pnpm_version_from`
  names; of several tags the newest release counts. Where the workspace states none,
  rules_js runs one it picks: its newest pnpm 8 through 2.9.3, its newest pnpm 10 from
  3.0.0 through 3.6.0 and at 4.0.0-alpha.0 and 4.0.0-alpha.1 (read in its source). Those
  take a pinned lock, so nothing is withheld for a release of aspect_rules_js of 1, 2 or 3
  and for those two: the release the root module asks for with `bazel_dep`, or pins with a
  `single_version_override`, and the one `MODULE.bazel.lock` selected, where that file is
  there. For any later release, for a version that is not written out and for a ruleset
  that an override takes from elsewhere than a registry, the choice is not known and
  counts as a pnpm that may be 11 or later; a `pnpm.pnpm` tag that states the release
  settles it.
  A `use_pnpm` is followed to such a tag only where a `use_repo` takes its repository by
  position, under the tag's own name. One that names a repository `use_repo` renames
  (`use_repo(pnpm, eleven = "pnpm")`, which runs the pnpm of the tag `pnpm`), or a
  repository of another extension or rule, is read as no version.

What is not written out counts against writing, because a failing build is worse than a
patch that a warning explains. So a hub whose `data` is a constant gets no new hosted pin
until the list is written out in the call, also where the constant lists the file and the
build would take the pin (measured); the warning then says to write `data` out as a list
that holds the label. A hub whose `update_pnpm_lock` is a constant is taken as one that
keeps the lock up to date, whatever the constant holds. A lock that is pinned already stays
pinned. Everything else is as it is without Bazel: a hub without `update_pnpm_lock`, one
that runs pnpm 10, one that lists a file of your own that takes the setting, a project whose
lock no call names, and a project in no Bazel workspace.

Not read, so that the lock is pinned as it is without Bazel: a `WORKSPACE` file; a hub in a
workspace file that cannot be read; a pnpm release that another Bazel module of the build
asks for; and a repository named `pnpm` that another extension makes and a `use_pnpm`
names. Where the pnpm of such a build is 11 or later and does not read the setting, the
build fails as above. Not read either is a `trustLockfile` that reaches the pnpm of the
build another way (`pnpm_config_trust_lockfile` in Bazel's environment): hosted mode
withholds there as well. Not read either: a hub that names the lock of a workspace member
(`pnpm_lock = "//packages/a:pnpm-lock.yaml"`), which is pinned as without Bazel. The
in-memory engine reads the Bazel files beside the lock or beside a `pnpm-workspace.yaml`
(`MODULE.bazel`, the `*.MODULE.bazel` files it can include and the `WORKSPACE` files) and
gives the answer of a checkout with the same files; it sees no Bazel root above the
project, for the pin and for the route through a named registry alike (a project in a
directory of a Bazel workspace is routed in memory where a checkout is not), and no
`MODULE.bazel.lock`, and a `pnpm_version_from` file that is not among the project's own
manifests reads there as a release that is not written out, so a lock that a checkout pins
can be left as it is in memory. Nor does hosted mode look at `--no-trust-lockfile-config`
when it decides this: see the known problems of
[Bazel workspaces: what is supported](#bazel-workspaces-what-is-supported).

## Bazel workspaces: Maven

A rules_jvm_external hub (`maven.install` in `MODULE.bazel`) builds the jars that its own lock,
`maven_install.json`, names, each at the sha256 the lock holds. It reads no `pom.xml` and no
Gradle file. A lock with `m2local` takes a jar that none of its repositories lists from the
Maven local repository, at the lock's sha256 too. So a patch in a `pom.xml`, a Gradle build or
an installed jar does not reach what Bazel builds.

Hosted mode patches a pinned hub. The hub fetches each jar through a repository of its own,
and Bazel's `override_repo` (7.4.0 and later) puts another repository in its place. A hosted
`socket-patch scan` or `socket-patch get <purl> --mode hosted`, run at the Bazel root, appends
one block to the root `MODULE.bazel`, after one blank line:

```
# >>> socket-patch: Maven patches for Bazel (managed block: socket-patch writes and removes it) >>>
socket_patch_http_file = use_repo_rule("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")

socket_patch_maven = use_extension("@rules_jvm_external//:extensions.bzl", "maven")

# pkg:maven/<group>/<artifact>@<version>, Socket patch <uuid>
socket_patch_http_file(
    name = "socket_patch_<repository>",
    downloaded_file_path = "v1/<group path>/<artifact>/<version>/<artifact>-<version>.jar",
    sha256 = "<sha256 of the patched jar>",
    urls = ["<the patched jar on the Socket patch host>"],
)

# If Bazel stops at the next line ("does not generate repository"), the hub's lock no longer pins
# <group>:<artifact> at <version>: run `socket-patch rollback pkg:maven/<group>/<artifact>@<version>`.
# Do not change it to inject_repo(): the build would pass without the patch.
override_repo(
    socket_patch_maven,
    <repository> = "socket_patch_<repository>",
)
# <<< socket-patch <<<
```

`<repository>` is the name the ruleset gives the artifact's repository: group, artifact and
version joined by `_`, with `_` for each `.` and `-`. The label of `use_extension` is the one
the checkout's own hub is made with. There is one entry per patch, from its `# pkg:maven/` line
to the `)` of its `override_repo`, and the entries stand in the order of their repository names.

- **What changes.** `MODULE.bazel` alone. The hub, `maven_install.json`, every label, the
  artifact's dependencies and `MODULE.bazel.lock` stay as they are: a build under
  `--lockfile_mode=error` passes, the ruleset's relock (`REPIN=1 bazel run @<hub>//:pin`) leaves
  the lock as it is, and `bazel mod tidy` leaves the block as it is. Commit `MODULE.bazel`. The
  URL holds the token of the patch, as a hosted pin in `pom.xml` does.
- **The build.** Bazel downloads the patched jar from the Socket patch host and checks its
  sha256. A machine that cannot reach the host, or a host that serves other bytes, fails the
  build: it never falls back to the upstream jar.
- **A project that Maven or Gradle builds too.** The same run pins both: `pom.xml` (or the
  Gradle files) and `MODULE.bazel`. The patch counts as `applied` when either build took it,
  and the warning below says when the Bazel build did not.
- **The undo.** `socket-patch rollback` and `socket-patch remove` take the entry out, and with
  the last entry the block and the blank line before it: the file is then byte for byte what it
  was. A new block is written in the line break of the file, the more frequent one when the
  file has both. `socket-patch list` shows the pin with `MODULE.bazel` as its file, and
  `socket-patch vex` attests it while a pinned hub fetches the jar at the entry's version and
  no rc file of the checkout switches the entry off, on whatever line, or cannot be read.
- **A version bump of a patched artifact.** The relock passes. Then every Bazel command that
  evaluates the hub stops at the entry's `override_repo(` with `does not generate repository
  "<repository>", yet it is overridden via override_repo()`, until `socket-patch rollback
  <purl>` has taken the entry out; the comment above that line says so. A dependency bot's bump
  of a patched artifact stays red until then. `socket-patch vex` attests nothing for such an
  entry. Bazel has nothing softer: with `inject_repo`, which its message suggests, the build
  passes on the upstream jar.
- **A block that was changed by hand**, also in its first line alone, is neither written to
  nor trusted: the run gives `maven_bazel_unreadable` with its line, and `rollback`, `remove`
  and `list` refuse (`hosted_wiring_contested`) and name `git checkout -- MODULE.bazel`. A
  block is socket-patch's when it is, byte for byte, what socket-patch writes for the patches
  it names, in one kind of line break.

Vendored mode patches a pinned hub through the same block, with the jar in the checkout.
`socket-patch get <purl> --mode vendored`, `scan --mode vendored` and `vendor`, run at the Bazel
root, download the patched jar once, from Socket's patch service, and write:

```
.socket/vendor/maven/<patch uuid>/REPO.bazel          # makes the directory a Bazel repository
.socket/vendor/maven/<patch uuid>/file/BUILD.bazel    # one public filegroup named `file`
.socket/vendor/maven/<patch uuid>/file/<artifact>-<version>.jar
.socket/vendor/maven/<patch uuid>/.gitignore          # `!*`: a `*.jar` rule must not drop the jar
```

and, in the block, an entry whose repository is that directory:

```starlark
socket_patch_local_repository = use_repo_rule("@bazel_tools//tools/build_defs/repo:local.bzl", "local_repository")

# pkg:maven/<group>/<artifact>@<version>, Socket patch <uuid>
socket_patch_local_repository(
    name = "socket_patch_<repository>",
    path = ".socket/vendor/maven/<uuid>",
)
```

with the same comment and `override_repo` as a hosted entry. The hub takes the jar of a
repository by its target `//file`, which is what the BUILD file gives it. Bazel's
`local_repository` (in `@bazel_tools` at 7.4.0, 7.7.2, 8.8.2 and 9.3.2) links to the directory
where it is, by its path from the workspace root: nothing is downloaded or copied, the
repository cache holds no copy of the jar, and a checkout builds patched with no host to ask.

- **What changes.** `MODULE.bazel`, the directory, one line of `.bazelignore` (below) and the
  vendor ledger, `.socket/vendor/state.json`. Commit all of it. `MODULE.bazel.lock` and
  `maven_install.json` stay as they are, as in hosted mode. No token is written anywhere.
- **`.bazelignore`.** A BUILD file under `.socket` is a package of the workspace (`bazel query
  //...` lists `//.socket/vendor/maven/<uuid>/file:file`), so the command names
  `.socket/vendor/maven` in the root's `.bazelignore`, under a comment line of its own, by the
  rules of [Bazel workspaces: `.bazelignore`](#bazel-workspaces-bazelignore). The build is the
  same with the line and without it.
- **Nothing checks the jar at build time.** An `http_file` checks a sha256; a repository over a
  directory has none to check, and Bazel builds whatever jar is committed there. The check is
  `socket-patch vendor --check`. It fails when the jar that Bazel builds is not, byte for byte,
  the vendored jar whose sha256 the ledger records; when `REPO.bazel` or `file/BUILD.bazel` is
  not the file socket-patch wrote; when the block no longer names the directory, or was changed
  by hand; and when the entry is one a build stops at or may pass without (no pinned hub takes
  the jar at that version any more, for which it names `socket-patch rollback <purl>`, or an
  rc file switches the entry off). Run it in CI. `socket-patch vex` hashes the same jar before
  it attests the patch. A later `vendor` takes the committed jar as it is only when the ledger
  records its bytes: any other jar at that path, also one that carries the patch's files, is
  replaced by the patch's own. `socket-patch repair` puts back a jar that is lost or changed,
  and with it the other files of a directory that was lost whole.
- **One entry per jar.** A vendored run puts its entry in the place of a hosted one for the
  same jar, and a hosted run in the place of a vendored one. The hosted run removes what
  vendored mode kept for the hub: the directory, its `.bazelignore` line and, for a patch that
  only the hub took, the ledger entry. Neither leaves both. Beside a Maven build the vendored
  tree of that build stays through a hosted run, as it does without the workspace. The entry
  of a later patch of the jar takes the place of the earlier one in the same way: the run
  that writes it removes each directory under `.socket/vendor/maven` that `MODULE.bazel` no
  longer names and no ledger entry records (`cleanup_failed` when it cannot).
- **A project that Maven or Gradle builds too.** That build is vendored exactly as without the
  workspace (the suffixed tree under `.socket/vendor/maven2`, the pom pin, and so on), and the
  hub gets a copy of the same jar in its own directory. The ledger entry is the Maven or
  Gradle one, and the hub's copy is that entry's jar byte for byte: `vendor --check` holds the
  copy to the same sha256, and the entry of the block to the rules above. A later `vendor`
  that finds the copy missing or changed, or the entry gone, writes them again and says so
  (`vendor_artifact_rebuilt`). The hub's directory has to survive the commit like the tree
  beside it: where a rule of the checkout makes git ignore it, the run writes nothing for
  the hub and warns `maven_bazel_hub_unpatched` with that rule.
- **The undo.** `vendor --revert`, `rollback` and `remove` take the entry out, then the
  directory, and the `.bazelignore` line goes with the last directory: every file is the one of
  before, byte for byte, but for a `.bazelignore` that was an empty file of yours, which is
  deleted with the last line, as for the Go lines. A `MODULE.bazel` that names the directory
  outside an entry of the block (a block changed by hand) fails the undo before anything is
  removed, because Bazel stops at a `local_repository` whose directory is gone.
  Beside a Maven or Gradle build the undo writes that build's files and `MODULE.bazel`
  together: one that cannot be written fails the undo with every file as it was, and the
  vendored tree, the hub's directory and the ledger entry go only after all of them are
  written. A run that is killed between two of those files has removed nothing and leaves
  `.socket/vendor/.commit-journal.json`: the next socket-patch command in the project
  finishes the files from it, and the undo run again removes the rest.
- **Where no entry can be written**, the reasons and codes are those of hosted mode below,
  but for `maven_bazel_download`: the jar is in the checkout, so an option about downloads
  does not stand against it. In a tree only Bazel builds the patch then fails with that code
  (exit 1, as a vendored refusal does) and nothing is written; beside a Maven or Gradle build
  that was vendored, it is a warning with that code and the patch is `applied`. A `vendor`
  over a hosted entry it would not replace is refused whole, before it asks any service, and
  the entry stays (`kept hosted: ...`). `--allow-vendored-in-bazel` does not lift these
  declines: they say that no entry could be shown to work, and there is nothing else to
  write for a hub.

Everything is read from the checkout: the root `MODULE.bazel` and the files it includes, for
the tags of the `maven` extension of `rules_jvm_external` under whatever name the file gives
the ruleset and the extension (a hub is the `install`, `artifact` and `from_toml` tags of one
`name`); the lock each hub names with `lock_file` (format 2 or 3, up to 16 MiB, each lock once
for all the hubs that name it; each other file up to 1 MiB); `.bazeliskrc`, `.bazelversion`, `MODULE.bazel.lock` and `.bazelrc` with the files
it imports (`import`, `try-import` and `try-import-if-bazel-version`, whose condition is not
evaluated; a path under `%workspace%/`, or a relative one, which is read from the Bazel root).
An rc file is read as Bazel reads one: a `\` before a line break joins two lines, a `#`
outside quotes starts a comment, a word loses its quotes and the `\` before an escaped
character, and the first word of a line is its command, not an option.
Nothing is evaluated and no Bazel is run. When the project is in
no Bazel workspace (the rule is under
[Bazel workspaces: `.bazelignore`](#bazel-workspaces-bazelignore)), or no hub holds the artifact
as a jar without a classifier at the patch's version and every hub was read, nothing is read
further, said or written: the run is the one it was.

A hosted `scan` at the Bazel root takes the jars that the pinned hubs fetch for packages of
the project, beside the ones it finds installed, so it finds their patches in a tree that has
no `pom.xml` and no Gradle build. A hub's jar is the one without a classifier of an artifact in
the hub's lock, when the lock has a sha256 for it, does not skip it, and lists it under a
repository (or takes it from the Maven local repository under `m2local`). Its version is the
lock's: the one Bazel builds, whatever a `pom.xml` beside the hub selects. A jar whose
repository has no known name is a package too: a patch found for it gets no entry, and
`maven_bazel_artifact` below says why.

- **In the output.** Such a package counts in `scannedPackages`, and unless a crawl found that
  version installed also in `lockfileOnlyPackages`, with `notInstalled` on its `packages[]`
  entry. A hosted `get <advisory>` keeps the releases that a pinned hub fetches the same way,
  and names a hub that was not read only when the advisory has a patch of a Maven artifact.
- **What was not read.** No jar is guessed. When something of the hubs could not be read with
  certainty (a hub without a `lock_file`, a lock or a tag that cannot be read, a `maven_install`
  of a `WORKSPACE` file that Bazel may read, a block that was changed by hand), the scan says so
  once, with the file, the line and the reason: `maven_bazel_hub_not_read` in `warnings[]`, a
  `Warning:` line for a person, who reads "No packages found (see the warning)." when there is
  no package at all. The jars of the hubs that were read are still looked up. A patch found
  for one of them gets no entry while the doubt stands (`maven_bazel_not_pinned` or
  `maven_bazel_unreadable` below). The warning is for a workspace that has to do with the
  ruleset: a call in `MODULE.bazel` or a file it includes names `rules_jvm_external`, the
  `WORKSPACE` file calls `maven_install`, or a `maven_install.json` lies at the Bazel root. In
  another Bazel workspace a file that cannot be read is about no hub, and the scan is the one
  without the workspace.
- **How much is read.** A scan takes its packages from up to 64 MiB of hub locks in one
  workspace. The first lock that does not fit is not taken, no lock after it is read, and the
  warning above names it ("the locks of the workspace are larger than 64 MiB in all"). That
  bound is the scan's alone: a patch that is found is pinned as `get <purl>` pins it, which
  reads each lock it needs up to 16 MiB.
- **A stale entry.** When the lock of a hub moves on (a version bump, an artifact that was
  removed), the entry for the release it held is stale: Bazel stops at it ("does not generate
  repository"). A hosted scan takes such an entry out as `socket-patch rollback <purl>` does,
  before it pins the patch of the release the lock holds now. It reports a `rolledBack` event
  (`verified` in a dry run) with the reason `maven_bazel_entry_stale`, and a person reads a
  `Note:` and "Restored <purl> to its upstream registry entry". With the last entry the block
  goes, and `MODULE.bazel` is the file of before its first patch. An entry is stale only when
  every hub was read and none fetches the jar at the entry's version: while something is in
  doubt it stays. The `socket.yml` policy holds such an entry as it holds a package of the
  run: a scan of a root that the policy filters, or one whose policy filters the package,
  leaves it. Only the entry goes. A pin of the same patch that another build of the checkout
  holds stays (a `pom.xml`; the hosted Gradle pin, also where the Gradle build has no such
  artifact), since nothing in the checkout says that the other build is done with the
  release: `socket-patch list` shows it and `socket-patch rollback <purl>` takes it out.
  While a Gradle pin of the old release stays, the Gradle lane declines a patch of another
  release of the artifact (`redirect_gradle_version_conflict`); the entry of the block is
  written all the same.
- **Beside another build.** A hub's jar with a patch is a patch of the run like any other, so a
  hosted scan writes for it what `get <purl> --mode hosted` writes in that checkout. Beside a
  Gradle build that is the Gradle pin too (`settings.gradle` and three files under
  `.socket/gradle/`, with the warnings of that pin), whether or not the Gradle build has the
  artifact. Beside a `pom.xml`, the pom lane pins the release Maven selects and says of any
  other what it always says: `redirect_maven_version_not_selected` where Maven selects another
  release, `redirect_maven_selection_undetermined` where it cannot tell. Those two speak of
  `pom.xml` alone: the hub's jar has its entry.
- **A root above other projects.** A bare `scan` covers the project directories below `--cwd`,
  and `--cwd` when it is a project. The root of a Bazel workspace needs no lockfile or build
  file of its own for that: a hosted scan covers it, under the heading `== . ==`, when its hubs
  have jars, something of them was not read, or the block has a stale entry. That section is a
  scan of `--cwd` like any other: it also counts the packages a crawl from the root finds
  installed in the projects below.
- **Not for another scan.** A scan in vendored or agent mode, one whose `--ecosystems` leaves
  Maven out, a `--global` one, and one of a project below the Bazel root take no package from a
  hub, give no `maven_bazel_hub_not_read` and take no stale entry out: their packages are those
  of the scan without the workspace.

A hosted run writes no entry where it cannot show from the checkout that the block works. It
then gives one warning, which says why and that the Bazel build keeps the upstream jar. In a
tree that only Bazel builds the patch is `skipped` (`redirect_unconfirmed`) and the warning
stands in the place of `redirect_maven_no_pom`; beside a `pom.xml` or Gradle pin that landed,
the patch is `applied` and the warning stands beside it. The exit code is 0 either way.

The last sentence of the warning says what the block of the root holds for the jar, also for a
project below the root, whose warning names the file as "the MODULE.bazel at the root":

- nothing: "socket-patch wrote nothing to MODULE.bazel for it, so the Bazel build keeps the
  upstream jar";
- the entry of this patch, from an earlier run: that entry stays, the patch is `applied`, and
  the warning ends "socket-patch left the entry that MODULE.bazel holds for it as it is". When
  the reason is one that leaves an entry without effect (`maven_bazel_no_effect`: an rc file
  that switches the block off, a `maven.override` of the jar), the patch is not `applied`, and
  the warning goes on "and while that stands the entry has no effect: the Bazel build keeps
  the upstream jar";
- the entry of another patch of the same jar: it is not this run's to take out, and the
  warning ends "socket-patch wrote nothing to MODULE.bazel for it: the entry of patch <id>
  remains there, and where the block is in effect the Bazel build takes that patch's jar".

| Code | When |
|---|---|
| `maven_bazel_not_at_root` | The project is below the root of its Bazel workspace. The block belongs in the root's `MODULE.bazel`: run the command there. |
| `maven_bazel_not_pinned` | A hub has no `lock_file` (also one that only `maven.artifact` or `maven.from_toml` tags make): Bazel resolves its jars when it builds. Also beside a pinned hub that holds the artifact, because the hub without a lock may build the upstream jar. Give it a `lock_file` and pin it. |
| `maven_bazel_unreadable` | Something could not be read with certainty: a `maven.install` whose `name` or `lock_file` is not a plain string, `install` tags of one hub that name different locks, a construct of `MODULE.bazel` the reader does not follow, a lock that is missing, empty, not format 2 or 3, larger than 16 MiB or no JSON, a `WORKSPACE` file that calls `maven_install` while Bazel may read it, a hub on a `use_extension` with `isolate`, an rc file that cannot be read (also one that an import takes from outside the workspace by a relative path, and one with a line whose reading Bazel's own source calls an oversight: a quote that is never closed, a `\` with nothing after it; the warning names the line), a `MODULE.bazel` that is a symbolic link, or a block that was changed by hand. |
| `maven_bazel_release` | The Bazel or the ruleset release is not known to be one the block works with. Bazel: `.bazeliskrc` or `.bazelversion` names a release before 7.4.0, or neither names a release of three numbers and `MODULE.bazel.lock` is missing or older than the format Bazel 7.5.0 writes (add a `.bazelversion`). Ruleset: `MODULE.bazel.lock` does not hold the `source.json` of exactly one rules_jvm_external release (build once), that release is not one of 6.4 to 7.2 (update socket-patch), or the lock holds another release than `MODULE.bazel` now takes: an older one than its `bazel_dep` asks for, or any other than the one a `single_version_override` of the ruleset pins (build once). Versions are compared as Bazel compares them (`7.2` is below `7.2.1`). The `bazel_dep` line alone is not taken: Bazel can select a newer release, and a `single_version_override` with a version that the lock agrees with can pin an older one. An `archive_override`, `git_override`, `local_path_override` or `multiple_version_override` of the ruleset, and a `single_version_override` whose version is no plain string, leave the release unknown: the warning names the override's line. |
| `maven_bazel_artifact` | The repository of this jar has no known name (a character other than letters, digits, `.`, `_` and `-` in its group, artifact or version), the lock lists no repository for the jar (it comes from the Maven local repository under `m2local`), or the patch comes without its served version or a sha256. |
| `maven_bazel_no_effect` | The build would pass on the upstream jar with the block in place: the root has a `maven.override` for the artifact, or an rc file of the checkout names `--ignore_dev_dependency` without switching it off, or names `enable_bzlmod` other than switched on (`--noenable_bzlmod`, `--enable_bzlmod=false`, and Bazel's other words for it: `0`, `no`, `f`, `n`, in any case) while the checkout names no Bazel 9 or later. |
| `maven_bazel_download` | Hosted mode only. An rc file of the checkout names a downloader config, `--repository_disable_download` or `--vendor_dir`: Bazel may not be able to download the patched jar. Vendored mode keeps the jar in the checkout. |

A vendored run that writes no entry for a jar a hub builds leaves the block as it is: a hosted
entry that is there stays, and the Bazel build keeps the patched jar. Beside a Maven or Gradle
build it warns, once per artifact, with the code and the reason of the table, or with
`maven_bazel_hub_unpatched` when it could have written the entry and vendored nothing for the
package (the Maven or Gradle build failed first). It also warns `maven_bazel_no_effect` for
an entry that is there and that the checkout leaves without effect: the Bazel build takes the
upstream jar past it. A dry run warns of the declines alone.

Agent mode patches no hub, and leaves the block as it is. An `apply` that has a Maven patch
(also `get` and `scan` in agent mode) reads the same files and says when a hub builds the
artifact:

- `maven_bazel_hub_unpatched`: a pinned hub fetches the jar of the artifact at the patch's
  version, and the block holds no entry for it. One warning per artifact names the lock, the
  hub, the file and line of its `maven.install`, and the hosted command that patches a pinned
  hub. The events, the exit code and every file the command writes are those of the same run
  without the workspace.
- `maven_bazel_unreadable`: whether a hub builds the jar could not be told, for one of the
  reasons above that concern reading the hubs. The warning names the file, the line and the
  reason.
- Nothing is said for a jar the block patches, under `--global`, and by a `vendor` whose
  `--ecosystems` leaves Maven out.

The Bazel release is the one that `.bazeliskrc` (`USE_BAZEL_VERSION`) or else `.bazelversion`
at the Bazel root names, read as bazelisk reads them: the last `USE_BAZEL_VERSION` line counts,
without the blanks around the name and the value, and an empty one leaves it to the first line
of `.bazelversion`, taken as it is written. Only one release of three numbers (`9.3.2`) names a
release: with `latest`, `9.x`, a release candidate, a fork's release, or a file that cannot be
read, the `WORKSPACE` file counts as one Bazel may read, and the Bazel release is taken from
`MODULE.bazel.lock`.

Limits:

- Not patched: a hub without a lock, a `maven_install` of a `WORKSPACE` file, Bazel before
  7.4.0, rules_jvm_external before 6.4 or after 7.2, and a hub in agent mode. Each is said as
  above.
- Vendored mode, beside a Maven or Gradle build: the hub gets its jar only in a run that
  vendored the patch for that build. An artifact that the build does not use at the patch's
  version (`vendor_maven_version_not_selected`) and the hub does is skipped as before; hosted
  mode patches that hub. A `vendor` there does not eject a hosted pin that only the block
  wires: the entry stays hosted, unless the same run vendors that patch for the Maven or
  Gradle build (a patch of the manifest, or a pin that the build's own files hold too). The
  hub's entry is then the vendored one, and `vendor --revert` takes it out. And
  `socket-patch vex` hashes the jar of the Maven or Gradle tree, as before, not the hub's copy
  of it, which `vendor --check` holds to the same bytes.
- Not looked at: a patch of a jar with a classifier, or of another packaging than `jar`. A lock
  names the plain jar by group and artifact alone, so such a patch gets no entry and no word
  about the hub: the run is the one without the workspace.
- A hosted `scan` at the Bazel root finds the artifacts of the pinned hubs and takes a stale
  entry of hosted mode out; `rollback` and `remove` take out a stale entry of either mode.
  `get <purl> --mode hosted` pins the purl it is given and leaves a stale entry of another
  release where it is, so the build still stops there until one of those three ran.
- A vendored `scan` does not look for the artifacts of a hub: it vendors a hub's jar when the
  package is one it found elsewhere (a `pom.xml`, a Gradle build). `get <purl> --mode vendored`
  takes any purl, and `vendor` takes the patches of a manifest and, in a checkout that only
  Bazel builds, the hosted patches of the block: there a hosted `scan` and then `vendor`
  vendor what the hubs build. No scan takes a stale entry of vendored mode out: `vendor
  --check` names it, and `rollback` or `remove` take it out with its directory.
- The in-memory hosted engine (GitHub App) reads no hub and writes no block.
- Not seen: a hub or a `maven.override` that another Bazel module declares (its hub takes the
  root's entry where it pins the same version, so an entry that is stale for the root's hubs
  may still patch that one: a hosted scan takes it out all the same), a hub that the root only
  takes with `use_repo` and other modules fill, a `maven_install` inside a function of a `.bzl`
  file, a jar that reaches Bazel without a hub (`http_jar`, a checked-in jar, the target of a
  `maven.override`), what the command line or an rc file outside the checkout tells Bazel
  (`--ignore_dev_dependency`, `--override_repository`; the machine's and the home directory's
  rc files, and one that an rc file imports by an absolute path), a second `override_repo` or
  `inject_repo` of the same repository outside the block, and a `USE_BAZEL_VERSION` of the
  environment or of the `.bazeliskrc` in the home directory, which a bazelisk asks before
  `.bazelversion`.
- A scanner that reads only `maven_install.json` keeps reporting the advisory: the lock names
  the upstream version on purpose. The patch shows in `MODULE.bazel` and in `socket-patch vex`.
- An agent `get` that fails before it patches anything says what it said before: in a tree
  that only Bazel builds that is `package_not_installed`. A vendored `get` of a jar that no hub
  builds there fails with `vendor_jvm_shape_unsupported`, as before. So does a `vendor` that is
  refused before it vendors anything (a ledger that cannot be read, or one that git ignores).
- `socket-patch vex` looks at the hub only for the block's entries: a patch that only the
  `pom.xml` pin or a patched jar attests is attested, although the Bazel build does not have it.

## Bazel workspaces: Cargo

A crate_universe hub of rules_rust (`crate.from_cargo` in `MODULE.bazel`, `crates_repository`
in a `WORKSPACE` file) builds its crates from the `Cargo.toml` files and the `Cargo.lock` it
names. Its tool, cargo-bazel, links what stands beside each of those `Cargo.toml` files into a
directory of its own, writes a root manifest of its own there and runs cargo there. Of the
cargo configs of the checkout that cargo gets one: the file the hub names as `cargo_config`,
and none when the hub names none (rules_rust 0.56.0 and 0.75.0). The hub of the rules_rust
README names none.

Hosted mode pins a crate in three files: it defines a registry in the project's
`.cargo/config.toml`, names it on the dependency in `Cargo.toml`
(`registry = "socket-patch-<uuid>"`) and repoints the entry of `Cargo.lock`. On a hub with
`cargo_config = "//:.cargo/config.toml"` the next `bazel build` builds the patched crate, and
vendored mode builds patched there too (both tested on real Bazel 9.3.2 and 8.8.2 with
rules_rust 0.75.0 and on 7.7.2 with 0.56.0, for a hub without a cargo-bazel lock).

A hub that reads the manifest and not that config fails on the pin, and every `bazel build`
that needs the hub fails with it:

```
error: failed to parse manifest at .../Cargo.toml
Caused by:
  registry index was not found in any configuration: `socket-patch-<uuid>`
```

So in a Bazel workspace `scan --mode hosted` and `get --mode hosted` write no pin for a crate
while such a hub is in the way. Nothing is written for the crate, it is `skipped`
(`redirect_unconfirmed`), the exit code is 0 as for the other crates hosted mode leaves out,
and one warning per crate says why (`redirect_cargo_bazel_config_unread`):

```
Warning: cfg-if@1.0.4: the rules_rust hub at MODULE.bazel:10 reads the Cargo files of this project, and it names no `cargo_config`. cargo-bazel hands the cargo it runs no cargo config but the one its hub names, and without .cargo/config.toml, where hosted mode defines the patch registry, that cargo fails on the pinned Cargo.toml (`registry index was not found in any configuration`) and `bazel build` with it; dependency skipped (nothing rewritten). Commit .cargo/config.toml (where the project has none, create it with a comment line in it: `rollback` deletes a config it leaves empty, and a hub that names a missing file fails), give the hub `cargo_config = "//:.cargo/config.toml"`, the label of that file as one string, and run this command again; or use `--mode vendored`, which commits the patched crate and needs no registry
```

The two ways on, both tested on the hub of the README on the three releases, from the refused
scan to the patched build:

- Commit `.cargo/config.toml` and give the hub the attribute, then run the same command: it
  pins the crate, and the build is the patched one. The file comes first. A project that has
  none creates it with a comment line in it: a hub that names a missing file fails, and
  `rollback` deletes a cargo config it leaves empty, which a comment line prevents. The
  warning writes the label in the package of the hub's own labels: for a hub that names
  `//:svc/app/Cargo.toml` it is `//:svc/app/.cargo/config.toml`.
- Use `--mode vendored`. It commits the patched crate under `.socket/vendor/cargo`, points a
  `[patch.crates-io]` entry at it and needs no registry.

Where the reason is a line that may hide a hub, the hub that is seen may name the config
already, and there may be no other. The warning then names that line and no attribute:

```
Warning: cfg-if@1.0.4: MODULE.bazel:17: `crate` is used other than to call a tag, so a rules_rust hub that socket-patch cannot read may take the Cargo files of this project. [...] dependency skipped (nothing rewritten). Write that line as the call of a tag (`crate.from_cargo(...)`) or as `use_repo(...)` and run this command again: it then pins the crate, or names the hub that is in the way; or use `--mode vendored`, which commits the patched crate and needs no registry
```

A hub that names the config is still in the way while that file is there and holds nothing
but white space. The pin would be written into it, a later `rollback` would delete the file it
leaves empty, and the hub would fail on the missing file. The warning asks for a comment line:

```
Warning: cfg-if@1.0.4: the rules_rust hub at MODULE.bazel:10 reads the Cargo files of this project and names .cargo/config.toml, which holds nothing: the `rollback` of a pin deletes a cargo config it leaves empty, and the hub then fails on the missing file, and `bazel build` with it; dependency skipped (nothing rewritten). Put a comment line in .cargo/config.toml and run this command again; or use `--mode vendored`, which commits the patched crate and needs no registry
```

A vendored crate that a hosted scan would take over stays vendored and patched
(`redirect_takeover_kept_vendored`). A pin that an earlier run wrote stays as it is: the
command reports it applied, as before, and writes nothing. On such a hub that build is
failing already: give the hub the attribute, or `socket-patch rollback`.

Everything is read from the checkout, and nothing is evaluated: `MODULE.bazel` and the files
it includes, for the `from_cargo` tags of the `crate` extension of rules_rust
(`//crate_universe:extensions.bzl`, and `extension.bzl`, which hands it on) under whatever
name the file gives the ruleset and the extension; the `WORKSPACE` file, for calls of
`crates_repository`, also under the name a `load` of that file gives the rule; `.bazeliskrc`
and `.bazelversion`, for the Bazel release; and the cargo config a hub names, for whether it
holds anything.

- A hub concerns the project when a label of its `cargo_lockfile` or its `manifests` is the
  project's `Cargo.lock`, its `Cargo.toml` or the `Cargo.toml` of a workspace member below
  it. `@<name of the root module>//` is the checkout, and so is `@<name>//` in a `WORKSPACE`
  file whose `workspace(name = "<name>")` says so. Where that name is not written out as a
  string, any `@name//` label of a lock or a manifest may be the checkout, and none is taken
  for the checkout as a `cargo_config`. A label of another repository is no file of the
  project.
- A hub that concerns the project is in the way unless its `cargo_config` is one string, the
  label of the config hosted mode writes: the project's `.cargo/config.toml`, or its
  `.cargo/config` where the project has that file. Another config is not enough, whatever it
  holds: the registry is defined in the project's own, and the settings of the other file
  belong there. A list of one label is not one string.
- A reading that is not certain withholds the pin where a hub, or a use of the extension
  through a name bound to it, is seen: a patch that waits for one line of yours weighs less
  than a build that fails.
  - A `cargo_lockfile` or `manifests` that is not written out as a string or a list of strings
    (a constant, a concatenation, an attribute left to `**`): the hub may read the project's
    files. Its warning says "may read".
  - A `cargo_config` that is not written out as one string is not taken for the right file.
  - A call that is not a statement of its own (in a conditional, in a comprehension) counts:
    it may run.
  - A use of the extension that may hide a call (the name bound to it used for anything but
    a tag or `use_repo`): a hub that cannot be read may take the project's files. The warning
    names the line to rewrite.
  - A `crates_repository` of the `WORKSPACE` file counts when no `crate.from_cargo` hub of the
    module files concerns the project, unless `.bazeliskrc` or `.bazelversion` names Bazel
    9.0.0 or later, which never reads that file. Bazel 7 reads it beside the module files, and
    Bazel 8 when it is told to. So a `WORKSPACE` file that a move to Bzlmod left behind can
    withhold a pin on Bazel 8 where the module files make no hub for the project: give its
    call the attribute, or delete the call.
- Nothing changes where no hub is seen to concern the project: in no Bazel workspace (the rule
  is under [Bazel workspaces: `.bazelignore`](#bazel-workspaces-bazelignore)), in a workspace
  without a crate_universe hub, for a hub that names the config, for a hub whose labels are all
  written out and name other files (another project of the checkout, another repository), and
  for a tag of the same name of another ruleset. The run is then the one it was: the same
  output, and the same files byte for byte.

Limits:

- Not seen, so that the run is the one it was and a hub without the config fails as before:
  - a hub that another Bazel module declares;
  - a `crates_repository` inside a `.bzl` file that the `WORKSPACE` file loads, or called
    under a name that no `load` of the `WORKSPACE` file gives it;
  - where no hub is seen: a tag called on `use_extension(...)` itself, with no name bound to
    it; a `MODULE.bazel` that cannot be read (a link that leads out of the Bazel root, a file
    past the reader's bounds); and what else the module files hide from every reading (a file
    they include that cannot be read, a `use_extension` that is not written out);
  - what Bazel is told by flags and rc files. None is read, in the checkout or outside it:
    `--noenable_bzlmod` has Bazel read the `WORKSPACE` file in place of module files that make
    a hub;
  - a Bazel root above a project that is in no git checkout: there only the project's own
    directory is looked at for a workspace file.
- Not read: a project the in-memory hosted engine rewrites. It is handed the project's files
  and reads no Bazel file, so its run is the one it was.
- Not looked at: `crate.from_specs` hubs, which take no `Cargo.toml`, and `crates_vendor`
  targets.
- A hub with a cargo-bazel lock (`lockfile`) asks for a repin after every change of
  `Cargo.lock`, a pin of either mode included (`CARGO_BAZEL_REPIN=true bazel build ...`). That
  is the ruleset's own rule, and this check does not look at it.
- `socket-patch vex` attests a hosted pin from the three files alone. It does not look at the
  hub.
- A hub that names a cargo config which is not there yet gets the pin, which creates the
  file. A later `rollback` deletes the file again, and the hub fails on the missing file as it
  did before the pin. Create the file with a comment line in it first.

## Cargo: shared registry cache

Agent mode patches the crate in place wherever the crawler finds it. For a non-vendored
crate that means the **shared** `$CARGO_HOME/registry` cache: the patch affects every
project on the machine, and is silently reset by `cargo clean` or a cache prune. Use
`--mode vendored` for a project-local, committable patch. With `CARGO_HOME` unset the
cache is `<home>/.cargo/registry`, with `<home>` found the way cargo finds it: `HOME`
(`USERPROFILE` on Windows), then, on Unix, the account's passwd entry, so a run with
`HOME` unset or empty still patches the copy cargo builds.

The cache holds one extracted copy of a crate per registry index directory under
`registry/src` (cargo 1.70–1.84 and cargo 1.85+ use different ones), so two toolchains
sharing a `CARGO_HOME` each build their own copy. `apply`, `apply --check`, `vex` and
`rollback` cover every copy: an unpatched one fails the check and keeps `vex` from
attesting the patch.

Nothing deletes a crate from the cache when the project stops using it, so the
manifest record stays the only way to restore that copy: `rollback` (and `remove`)
also restore it after the crate was moved to vendored mode, and `scan --prune` /
`--sync` keep the record of a crate the lock no longer resolves while its cache copy
is still patched (`cargo_cache_patch_kept`; `socket-patch rollback <purl>` restores
the copy and drops the record).

Cargo never re-checks a registry or `cargo vendor` crate's source files: it reuses the
crate's compiled artifacts while the package id is unchanged. So after `apply` or
`rollback` changes a crate's bytes, socket-patch deletes that crate's fingerprints
(`.fingerprint/<crate>-<hash>/`, or `build/<crate>/<hash>/fingerprint/` in the newer
build-dir layout; every version, profile and target triple) in the
project's build directories, and the next `cargo build` recompiles it and relinks its
dependents. Those directories are `CARGO_TARGET_DIR` / `CARGO_BUILD_TARGET_DIR`,
`CARGO_BUILD_BUILD_DIR`, `build.target-dir` / `build.build-dir` from the project's
`.cargo/config.toml` files and `$CARGO_HOME/config.toml`, and `<workspace root>/target`.
A fingerprint that can't be removed, or a `build.build-dir` using
`{workspace-path-hash}`, adds a `cargo_build_cache_stale` warning that names the crates
to `cargo clean -p`. Other projects that share the registry cache keep their own build
caches: run `cargo clean -p <crate>` there too.

Run `cargo fetch` before `apply` on a fresh checkout or CI runner. Cargo unpacks a
locked crate into `registry/src` only when it fetches or builds, so on a cold or pruned
cache there is nothing to patch, and the next `cargo build` would compile the pristine
crate. `apply` therefore treats a crate that `Cargo.lock` resolves but that is not
unpacked as not installed, not as a calm lockfile-only skip: a run where no targeted
patch matched exits 1 and names `cargo fetch` as the remedy.

Agent mode patches only crates that `Cargo.lock` takes from a registry. When the lock
takes a crate from a path, a git repository, a `[patch]` entry or a `[replace]` entry
(a registry entry whose `replace` key names the copy cargo builds), cargo never builds
the registry cache's copy, even if another project left one there. So `apply` doesn't
patch that copy, and `vex` doesn't attest it (#506). A user-authored `[patch]` or
`[replace]` entry is reported as `user_patch_conflict`, unless `--allow-patch-conflicts`
lets apply try it. That case, a git dependency and a `path` dependency are reported as
`package_not_installed`. A run where no targeted patch matched exits 1.

## Cargo: vendored wiring in Cargo.toml

Vendored mode (v5+) wires a patched crate with a `[patch.crates-io]` path
entry in the **workspace-root `Cargo.toml`** (the manifest beside the
`Cargo.lock` it detaches) plus the lock surgery that drops the crate's
`source`/`checksum` and records the copy's **tagged version**:

```toml
[patch.crates-io]
cfg-if-socket-9f6b2c4e = { package = "cfg-if", path = ".socket/vendor/cargo/<uuid>/cfg-if-1.0.4" }
# a second vendored version of the same crate (needs cargo 1.45+):
cfg-if-socket-0a1b2c3d = { package = "cfg-if", path = ".socket/vendor/cargo/<uuid2>/cfg-if-0.1.10" }
```

```toml
# Cargo.lock
[[package]]
name = "cfg-if"
version = "1.0.4+socket.<uuid>"
```

- **Tagged versions.** The vendored copy's own `Cargo.toml` version is
  rewritten to `<version>+socket.<uuid>` (a version with build metadata
  keeps it: `2.0.1+zstd.1.5.2` → `2.0.1+zstd.1.5.2.socket.<uuid>`), and the
  detached lock entry carries the same tagged version — the lock cargo
  itself writes for the tagged copy. Cargo ignores build metadata when
  matching requirements, so `1.0.4`, `=1.0.4`, `1`, `^1` in any dependent
  still select the copy. The lock alone therefore names the patch uuid of
  the copy cargo builds (a `[patch]` override elsewhere changes the locked
  version), and stripping the tag gives the purl version. Every lock
  reference that spells the version (`"cfg-if 1.0.4"`, v1's full ids) is
  rewritten with it, in lock formats v1–v4; a lock that cannot be kept
  consistent refuses with `cargo_lock_untaggable` before any write.
  **The patched crate sees the tag in `CARGO_PKG_VERSION`** — e.g. a
  vendored binary crate's `--version` output shows it; requirement
  matching (`semver::VersionReq`) is unaffected, but string comparisons
  and equality / ordering on a parsed `semver::Version` (which compares
  build metadata) see it. Revert restores the original lock byte for
  byte — including when you later lock your own same-version path crate
  beside the copy: that entry is left alone and the registry entry comes
  back under its full id, as cargo writes it. Copies and locks vendored
  before tagged versions are tagged by the next re-run or `repair`
  (`cargo_version_tagged`; a dry run says "would tag"). For VEX, an
  untagged detached lock entry counts only beside an untagged (pre-tag)
  copy, and a copy whose `Cargo.toml` is tagged for another uuid than its
  path is dead wiring.
- **Why the manifest.** Socket's scanners already ingest `Cargo.toml`, so
  the patch uuid in the path is recoverable for SBOM annotation without
  uploading `.cargo/config*` (which can hold registry tokens), and manifest
  `[patch]` builds on cargo older than 1.56, the floor of config-file
  `[patch]` (proven by the old-toolchain e2e tests, which build and run
  the patched copy with no network on the cargo 1.41 and 1.56 docker
  images — the CI `cargo-old-toolchains` leg; without the images a local
  run falls back to type-checking on rustup toolchains).
  **Two vendored versions of ONE crate need cargo 1.45 or newer.** Cargo
  before 1.45 resolves every source-less `Cargo.lock` entry for a crate
  through ONE `[patch.crates-io]` path — the entry whose KEY sorts last —
  so with two vendored versions one of the two lock entries is pinned to
  the other version's copy and `cargo build --locked` fails closed with
  ``patch for `<crate>` … did not resolve to any crates``. A populated
  crates.io index in `$CARGO_HOME` does not help; whether a given pair of
  patch uuids happens to build there is an accident of how their keys
  sort. The floor was measured on one two-version fixture in both key
  orders (`cargo check --locked --offline`, empty `$CARGO_HOME`): 1.41.1,
  1.42, 1.43 and 1.44 refuse the adversarial order; 1.45, 1.49, 1.53, 1.56
  and current stable resolve either order, each lock entry to its own copy.
  Vendoring a second version of a crate therefore warns
  (`cargo_multi_version_old_cargo`) unless the project's `rust-version`
  (its own, or `[workspace.package]`'s through `rust-version.workspace =
  true`) or `rust-toolchain[.toml]` promises cargo 1.45+ — socket-patch never runs
  `cargo`, so those files are the only signal it has. On an old cargo,
  `cargo build --offline` from an empty `$CARGO_HOME` is enough; without
  `--offline` it loads the crates.io index first and fails when that is
  unreachable. Current stable needs neither. A SINGLE vendored version
  still builds on 1.41. Each clause is asserted by the old-toolchain e2e
  test, in both directions, with the adversarial key order.
- **Keys.** Always the Socket-owned `<name>-socket-<first 8 hex of the
  uuid>` with `package = "<name>"` (the full uuid hex if that key is
  taken), never the bare crate name: cargo lets a config-file `[patch]`
  item — the project's, an ancestor directory's, or `$CARGO_HOME`'s —
  replace the manifest item with the same key whatever its version, so a
  crate-named key could be silently shadowed by your own config. Keys any
  of those config files already use are avoided. Every lookup (re-run,
  revert, VEX discovery) is key-agnostic: an entry belongs to
  `name@version` when its crate (`package`, else the key) is `name` and its
  path is `.socket/vendor/cargo/<uuid>/<name>-<version>`. The key is a
  function of the patch uuid, so the order two versions' keys sort in is
  arbitrary — which is why cargo below 1.45 cannot be relied on for a
  multi-version project (above).
- **Your entries.** User-authored `[patch.crates-io]` entries are never
  modified. One — in `Cargo.toml` or any cargo config file cargo merges
  (project, ancestors, `$CARGO_HOME`) — that patches the same crate and is
  not provably another version (a git/registry patch, or a path whose
  `Cargo.toml` version is unreadable or equal) refuses the vendor with
  `user_authored_patch_entry`.
- **Refusals.** `cargo_manifest_not_workspace_root`: run from a workspace
  member (cargo ignores `[patch]` outside the workspace-root manifest) —
  run from the root. `cargo_manifest_patch_source_alias`: the manifest also
  has a `[patch."https://github.com/rust-lang/crates.io-index"]` table,
  which cargo lets replace `[patch.crates-io]` wholesale — move its entries
  under `[patch.crates-io]`. Also `cargo_manifest_unreadable`,
  `cargo_manifest_unparseable`, and `redirect_symlinked_file_unsupported` for a
  symlinked `Cargo.toml` (the one symlink code every mode uses).
- **Formatting.** Comments, ordering, CRLF / mixed line endings, a UTF-8
  BOM and the trailing-newline state are preserved; a revert with nothing
  else changed restores `Cargo.toml` byte for byte, and keeps your own
  `[patch]` / `[patch.crates-io]` headers (an explicit `[patch]`, or a
  `[patch.crates-io]` that another table follows or that carries a
  comment).
- **Migration.** Projects vendored by an older release carry the entry in
  `.cargo/config.toml` (or `.cargo/config`). Re-running `vendor`,
  `scan`/`get --mode vendored`, or `repair` moves it into `Cargo.toml`
  (`cargo_wiring_migrated`), updates the vendor ledger, and deletes a config
  file (and `.cargo/`) the move emptied; a legacy entry that cannot be
  removed fails the run with nothing changed (`cargo_legacy_wiring_kept`).
  A project hit by the old multi-version overwrite (a second vendored
  version repointed the crate-named config key, leaving the first
  version's lock entry detached and unwired) is healed the same way
  (`cargo_wiring_restored`). The same re-run or `repair` also tags an
  untagged copy and lock entry (`cargo_version_tagged`). Every revert
  removes both spellings.

## Cargo: what `vex` attests from the lock

`vex` attests a hosted or vendored crate only from files cargo acts on.

- **A hosted lock entry needs a declaration that routes it.** Cargo resolves a
  dependency from the source its declaration names. A `Cargo.lock` entry sourced
  from a Socket patch registry therefore counts only while a declaration cargo
  honors sends that version there: a dependency in the root `Cargo.toml` or a
  workspace member's with `registry = "socket-patch-<uuid>"` and a requirement
  that accepts the locked version (what hosted scan writes), or a hand-written
  `[patch.<source>]` entry with that registry in the root manifest or the project
  cargo config. Without one, cargo takes the crate from crates.io and rewrites the
  lock, or fails under `--locked`. So `vex` attests nothing for a crate that only
  registry dependents declare, for a registry named only on a `[patch]` entry
  cargo ignores (a `[patch."https://github.com/rust-lang/crates.io-index"]` table
  replaces `[patch.crates-io]`) or on a `[workspace.dependencies]` entry nothing
  inherits, or for a lock with no readable `Cargo.toml` beside it. The run warns
  `patched_ref_unattributable` and names the lock entry; `rollback` and `remove`
  still restore it.
- **Run it from the workspace root.** Cargo ignores `[patch]` in a workspace
  member and reads `Cargo.lock` only at the workspace root. Run from a member (a
  directory an ancestor `[workspace]` does not `exclude`, or a package with
  `package.workspace`), `vex` reads no cargo wiring: a `[patch]` path entry, a
  registry pin and a `Cargo.lock` left beside the member attest nothing. Each
  member file that names a Socket patch gets a `patched_ref_unattributable`
  warning that names the workspace root; `rollback` and `remove` still unwind a
  hosted pin left there. Hosted scan and `vendor` refuse the same directories
  (`cargo_manifest_not_workspace_root`).

## Bazel workspaces: the build file in a vendored crate

A rules_rust crate hub (`crate.from_cargo`) builds a vendored crate from its copy under
`.socket/vendor/cargo`: the build after `scan --mode vendored` is the patched one, with no
repin. From rules_rust 0.59.0 on, the hub's tool, cargo-bazel, also writes a `BUILD.bazel`
into the copy's own directory each time Bazel evaluates the hub, as it does for every crate
a Cargo workspace takes from a path. The scan recorded no such file, and Bazel reads it as
a package of your workspace.

socket-patch does two things about that file, both only where the Bazel workspace has a hub
of the project's crates: `MODULE.bazel` at the Bazel root (see
[`.bazelignore`](#bazel-workspaces-bazelignore) for where that is, and for the checkouts in
which no root is looked for), or a file it includes, calls `from_cargo` on the extension
`crate` of `@rules_rust//crate_universe:extensions.bzl` (or of `extension.bzl`, its older
name), and that call

- is a statement of its own: one in a comprehension, behind an `and` or in a condition may
  never run, and is passed over;
- names the project's `Cargo.lock` as its `cargo_lockfile`, or the project's root
  `Cargo.toml` among its `manifests`, by a label of your own repository that is written
  out as a string (`"//:Cargo.lock"`, `"//services/api:Cargo.toml"`).

A hub that names the files of another Cargo workspace of the checkout, or names its files
through a constant, is not taken for a hub of this project: socket-patch then does neither
of the two things, and what follows a build is what is described under "Limits".

**Bazel is kept out of the copies.** While the project has vendored crates, the
`.bazelignore` at the Bazel root holds the line `.socket/vendor/cargo` (after the project's
path from that root, for a project below it), under the comment line
`# socket-patch: patched crate copies, not Bazel packages (to opt out, comment out the next line)`.
`scan --mode vendored` writes the two lines and `vendor --revert` takes them away; every
rule of the Go lines in [Bazel workspaces: `.bazelignore`](#bazel-workspaces-bazelignore)
holds for them: which commands bring the file in line, what covers a directory, the opt-out,
the warning `bazelignore_not_updated`. A command whose `--ecosystems` leaves `cargo` out
adds no line. What the line is for, measured with rules_rust 0.75.0 on Bazel 9.3.2 and 8.8.2
(with rules_rust 0.56.0, on 7.7.2, a build writes no file):

- The hub does not build the crate from the file in the checkout. It reads the copy by its
  path, copies the directory into a repository of its own and renders the build file there
  again. So the build with the line is the same patched one, and another file under the
  same banner does not change what the crate is built from.
- Without the line the file makes the copy a package of your workspace: `bazel query //...`
  lists its targets, and `bazel build //...` builds those not tagged `manual` (cargo-bazel
  tags the crate's library so). That package names repositories only the hub sees, so for a
  vendored crate with a dependency the commands that analyse every target fail on it:
  `bazel cquery //...` and `bazel query 'deps(//...)'` end with `No repository visible as
  '@crates__<dependency>' from main repository`, or with the same words about `@platforms`,
  which the file names too: Bazel reports the first of the two that it meets. With the line
  both pass, and `//...` holds your own targets alone.

**Under that line, the file is no change of the copy.** `vendor --check` passes, `vex`
attests the crate, `repair` has nothing to restore, and a second `scan --mode vendored`
reports the copy `already_vendored` and downloads nothing. socket-patch never writes the
file, and removes it only with the copy: on `vendor --revert`, or when it replaces a copy
that is changed in another way. Only this file is left out of the comparison with the
ledger's inventory:

- a regular file named `BUILD.bazel` in the copy's own directory that the inventory does
  not list (a build file the crate ships is listed, and is held to the crate's bytes);
- that starts with the banner of every file cargo-bazel renders: a line of `#`, the line
  `# @generated`, and a line that starts with `# DO NOT MODIFY: This file is auto-generated
  by a crate_universe tool.`;
- in a project whose Bazel workspace has a hub of its crates, as above;
- in a copy that a line of the root's `.bazelignore` covers: the line socket-patch writes,
  or one of your own for the directory or one above it (`.socket`).

In any other case a file like it is a changed copy, as before (`vendor_inventory_mismatch`).
Every recorded file is still held to its bytes, any other file the scan did not record is
still a changed copy, and a download that `repair` or a scan stages for a copy is held to
the inventory alone. Of the build file itself socket-patch reads the banner and nothing
after it: the rest differs from one machine and one ruleset release to the next, so no
recorded copy of it could be compared. That is why the line is part of the rule: a
`BUILD.bazel` that someone else puts into a copy under the same banner is let through only
where Bazel reads no package there, and where Bazel does read it, it is a changed copy.

Limits:

- With the path line commented out (the opt-out), or where the line could not be written
  (`bazelignore_not_updated`), or in a checkout vendored by an earlier release until a
  command that writes the line has run (`scan --mode vendored`, `repair`, `apply`), the copy
  is a package again and cargo-bazel's file is a changed copy again: after the next build
  those two commands fail, `vendor --check` exits 1, `vex` leaves the patch out, and the
  next vendored scan downloads the crate again.
- Both parts need the Bazel root, which is looked for as the `.bazelignore` section says:
  above the project's own directory only up to the root of its git checkout, and only when
  that checkout's `.git` belongs to you, to root, or to the user `sudo` ran for. A project
  that is a checkout of its own below the root (a submodule), or a checkout that a CI
  container mounts from another user, has no Bazel root for socket-patch: both parts are
  off there, and the commands above fail after a build although they pass on a developer's
  machine.
- A workspace whose module files make no hub of the project's crates gets neither: no line
  is written, and a `BUILD.bazel` in a copy is a changed copy. That holds for a hub of the
  older `WORKSPACE` system (`crates_repository`) and for rules_rust's `crates_vendor`. By
  rules_rust's source, which no build here has run, `crates_vendor` with `mode = "local"`
  renders build files into the checkout that name a path crate by its package: there the
  file in the copy is what Bazel builds the crate from, and a `.bazelignore` line would take
  the crate out of the build. A workspace that has both such a vendor target and a hub over
  the same Cargo workspace must comment the line out.
- Bazel leaves an ignored directory out of every `glob()` of a package above it. A target
  that hands the project's files to a `cargo` of its own through such a glob no longer
  receives the copies. From rules_rust 0.59.0 on, the build file that cargo-bazel writes
  into a copy takes that copy out of the glob in the same way.
- Not covered: a crate that ships a `BUILD.bazel` of its own. By its source, which no build
  here has run for such a crate, cargo-bazel writes its file over that one. The inventory
  lists the crate's, so the copy reads as changed after a build, as it did before, until a
  second `scan --mode vendored` or `repair` restores the crate's file.

## Go: directory replaces and go.sum

Both Go modes work through a `go.mod` `replace` directive pointing at a committed
directory — `.socket/go-patches/<module>@<version>/` in agent mode,
`.socket/vendor/golang/<uuid>/<module>@<version>/` in vendored mode — because the module
cache is `go.sum`-verified, so patching it in place can't build. Go **never verifies a
directory `replace` target against `go.sum`** — that is by design (it's how local module
development works), and it means the committed patched tree itself is the protection:
commit it, and review it like any other vendored code. The wiring survives
`go mod tidy`, and `apply --check` gives CI a read-only audit that the committed
redirects still match the manifest.

Reinstalling the same module version (`go clean -modcache`, `go mod download`,
`go get module@version`, and `go mod tidy`) preserves the local replacement.
Agent reapplication can reuse the committed copy after cache removal, but only
after verifying its patch hashes and replacement wiring. Changing the required
module version needs a matching patch for that version; the old version-pinned
replacement does not patch a different release.

Local modes keep the replaced module's original checksum lines in
`.upstream-go.sum` beside the patched module tree. Commit that file with `.socket/`:
rollback restores those lines offline even after `go mod tidy` removes them from
`go.sum`. A conflicting checksum fails rollback without removing the replacement.
Projects patched by older releases without this backup may still need
`go mod download <module>@<version>` after rollback.

When native Go vendoring is active, VEX and the audit commands also verify
`vendor/`, including the workspace vendor tree. A pristine or modified runtime
file there fails verification even when the `.socket` copy remains intact.
Regenerate it with `go mod vendor` or `go work vendor`.

Hosted mode uses a fork-style module replacement and two committed checksums:

```text
# go.mod
replace example.com/module v1.4.2 => patch.socket.dev/gopatch/<uuid> v1.4.2-socketpatch.1

# go.sum
patch.socket.dev/gopatch/<uuid> v1.4.2-socketpatch.1 h1:<module-zip-hash>
patch.socket.dev/gopatch/<uuid> v1.4.2-socketpatch.1/go.mod h1:<module-file-hash>
```

The service supplies the replacement path, version, and both hashes; the example
version is illustrative. Both hashes must be present before the CLI writes the
replacement. Go uses committed `go.sum` entries without consulting the checksum
database for those entries, so a fresh checkout needs no per-machine checksum
exemption. A mismatched checksum still fails the build. The rewriter removes the
replaced version's original sum lines to keep the result stable under `go mod tidy`.
When no package of the patched module is imported, `go mod tidy` drops the zip-hash
line and the build still works; re-running `scan --mode hosted` writes it back, so a
later import of the module builds without a `missing go.sum entry` error.
In a `go.work` workspace `vex` does not attest a pin with only the `/go.mod` line:
go builds a workspace without keeping each member's `go.mod` complete, so a member's
dependency can select a newer version of the module that no committed file shows.
`vex` then needs the patched module in the module cache to attest it.
A re-pin to a newer patch (a superseding patch uuid, or the same patch republished
at a new `-socketpatch.<n>` version) also removes the previous Socket module's sum
lines, so `go mod tidy -diff` stays clean after a patch update.

This requires a free, publicly retrievable patch reference carrying a `goproxy`
override. CLI support does not imply a patch is published for a particular module.

### Global mode: tools built with `go install`

With `--global` / `--global-prefix` there is no project to redirect, so `apply`
patches the module cache copy (`$GOMODCACHE/<module>@<version>/`) in place. That
changes what the next build compiles, and nothing else: a tool installed earlier
with `go install pkg@version` is a static binary that keeps running the unpatched
code. After a global apply, socket-patch reads the build info of the binaries in
`$GOBIN` (else `bin/` of each `GOPATH` entry, default `~/go/bin`, plus
`<root>/bin` for a cache at `<root>/pkg/mod`) with `go version -m`, and warns
`go_installed_tool_stale` for each one built from a patched module before it was
patched, with the command that rebuilds it:

```sh
go install example.com/tool@v1.0.0   # rebuilds from the patched cache
```

`vex -g` omits the patch with the same code while such a tool remains. A binary
copied out of those directories can't be found; rebuild it the same way. While
the cache copy stays patched, `go mod verify` reports `dir has been modified`
for it until `rollback -g`.

### Files go derives from go.mod

Two files the go command derives from `go.mod` can disagree with a new or removed
socket `replace`, and go then refuses to build. socket-patch does not regenerate
them (that needs the go toolchain and the whole module graph); `apply`, `vendor`
(including `vendor --revert`), `rollback`, `remove` and `scan --mode hosted` warn
with the command that does, and
`apply --check` / `vendor --check` report the disagreement as drift until it is run:

| Warning code | When | Fix |
| --- | --- | --- |
| `go_vendor_modules_txt_out_of_sync` | A committed `vendor/` directory (`go mod vendor`; `go work vendor` for a workspace) whose `vendor/modules.txt` does not record a socket `replace`, or still records one that was removed. go builds with `-mod=vendor` and fails with "inconsistent vendoring" | `go mod vendor` (or `go work vendor`), then commit `vendor/` |
| `go_requirements_out_of_sync` | The patched module's own `go.mod` requires a dependency at a version above the one the project's `go.mod` lists (agent and vendored modes; `apply` also reports a requirement the patch added). The default `-mod=readonly` build fails with "updates to go.mod needed" or "missing go.sum entry" | `go mod tidy`, then commit `go.mod` and `go.sum` |

### Bazel workspaces: `.bazelignore`

In a Bazel workspace the module copies of vendored and agent mode are directories that Bazel
and gazelle walk like any other. A BUILD file in a copy (one the module ships, or the one
`bazel run //:gazelle` writes there) is then a package of the workspace, gazelle's `go_deps`
copies the directory with that file, and every target that uses the module fails to load
(`No repository visible as '@rules_go'`). So socket-patch keeps the copies out of the
workspace's packages with `.bazelignore`. Agent mode is
[not supported for Bazel builds](#bazel-workspaces-what-is-supported); its copies get the
line all the same, so that they cannot break the workspace.

A project is in a Bazel workspace when its directory, or one above it up to the root of its git
checkout, holds a regular file `MODULE.bazel`, `REPO.bazel`, `WORKSPACE` or `WORKSPACE.bazel`
(the names Bazel itself looks for); the nearest such directory is the Bazel root. The checkout
is the one the `socket.yml` lookup takes for the repository root: on Unix its `.git` belongs to
you, to root, or to the user `sudo` ran for (a root process takes any owner's). A project in no
such checkout is looked for in its own directory only: nothing above it is read or written. In
a Bazel workspace, every command that can write or remove a copy (`scan`, `get`, `apply`,
`vendor`, `vendor --revert`, `rollback`, `remove`, `repair`) ends by bringing the root's
`.bazelignore` in line with the copies on disk, unless it is a dry run. A command whose
`--ecosystems` leaves `golang` out adds no line; it still takes away the pair of a copy that is
gone:

- While `<project>/.socket/vendor/golang` (vendored mode) or `<project>/.socket/go-patches`
  (agent mode) exists, the file names that directory by its path from the Bazel root, on a line
  of its own under the comment line
  `# socket-patch: patched Go module copies, not Bazel packages (to opt out, comment out the next line)`.
  The two lines are added at the end of the file, in its line breaks, and the file is created
  when it is missing. Nothing is added when a line already covers the directory: its path or a
  directory above it. Bazel reads a line literally, so a pattern, or a line with a space before
  or after it, covers nothing.
- Once the directory is gone, the pair is removed, and the file is the one of before, byte for
  byte: a last line that had no line break has none again. A file that is left empty is
  deleted, also when it was an empty file of yours. socket-patch knows its pair by the start
  of the comment line, `# socket-patch:`: a path line under a line that starts so is its own,
  whatever the rest of that line says, and a line without one above it is never changed. Only a
  directory that is not there is gone: one that cannot be looked at (a directory above it that
  you may not search) keeps its pair, and gets none. `rollback --preserve-state` keeps a
  vendored copy on disk, and with it the line.
- To keep the copies visible to Bazel (see the first limit below), comment the path line out
  and leave the comment line above it: `# .socket/vendor/golang`. socket-patch then adds no
  line for that directory, gives no warning about it, and never touches the two lines again.
  The commented path may end in one `/` or start with `./`. Deleting both lines is no opt-out:
  the next command writes them back. Neither is commenting out both lines, or a path line
  changed in any other way (a space after it, a second `#`, a blank line above it).

Commit `.bazelignore` with `go.mod` and the copy. A command that changed the file says so
(`Updated <path>` or `Removed <path>`, on stdout, not under `--json` or `--silent`). With a
`--manifest-path` into another project, the agent copies are those of `--cwd` and the vendored
ones those of the manifest's project, and the command brings the file of each project's Bazel
root in line. Bazel 8 and 9 also take `ignore_directories` in `REPO.bazel`, which socket-patch
does not read: a workspace that ignores `.socket` there gets the line as well, and both
together are fine.

When the file cannot be written (a symbolic link or a directory in its place, a read-only
directory, a read-only file, which is neither replaced nor deleted), the command still succeeds
and warns `bazelignore_not_updated` with the line to add, or, for a copy that is gone, that its
two lines can be deleted.

The same commands keep one more pair by the same rules, for Maven: while
`<project>/.socket/vendor/maven` exists, which holds the jars vendored mode commits for a
rules_jvm_external hub ([Bazel workspaces: Maven](#bazel-workspaces-maven)), the file names it
under the comment line
`# socket-patch: patched Maven jars for a Bazel hub, not Bazel packages (to opt out, comment out the next line)`.
A command whose `--ecosystems` leaves `maven` out adds no such line. The opt-out, the removal
and the warning are as above; a command that changed the file for it says `Updated <path>` or
`Removed <path>` with what the line is for.

Side effects and limits:

- Bazel leaves an ignored directory out of every `glob()` of a package above it as well. A
  target that hands the project's Go files to a `go` command of its own through such a glob (a
  `genrule` that runs `go build`, a source archive, an image layer) no longer receives the
  copies, and its `go build` fails in the sandbox:
  `replacement directory ./.socket/vendor/golang/... does not exist` (Bazel 9.3.2). Without the
  line the same target builds until the first `bazel run //:gazelle`, whose BUILD file in the
  copy takes the copy out of the glob in the same way. With the line it builds when it names
  the files of the copy one by one beside the glob, or runs outside the sandbox. Such a
  workspace can opt out as above.
- Only Go module copies are covered, and the vendored crates of a workspace with a
  rules_rust crate hub, which have a comment line of their own (see
  [Bazel workspaces: the build file in a vendored crate](#bazel-workspaces-the-build-file-in-a-vendored-crate)).
  The unpacked packages other ecosystems keep under `.socket/vendor/` get no line.
- A Bazel root that socket-patch does not look for gets no line, and no warning is given: add
  the line by hand, with the directory's path from that root. That is a root above the root of
  the project's git checkout (the project is a git submodule, or several checkouts sit below
  one Bazel workspace), and a root above a project that is in no git checkout (a Docker build
  context, an unpacked source archive) or in a checkout of another user. Nothing outside the
  checkout, or above such a project, is read.
- The Bazel root is the nearest directory with a workspace file. When that workspace is nested
  in a larger one (`outer/MODULE.bazel`, `outer/inner/MODULE.bazel`, the project in `inner`),
  the line is in `inner/.bazelignore`, which only a Bazel or gazelle run from `inner` reads. A
  run from `outer` takes `inner` for part of its own tree (Bazel 9.3.2, gazelle 0.54.0):
  `bazel build //...` loads the packages under `inner`, a BUILD file in the copy among them,
  and `bazel run //:gazelle` writes a `BUILD.bazel` into the copy, after which the build in
  `inner` fails as above. Unless `outer/.bazelignore` already names `inner`, add the line there
  with the path from the outer root: `inner/.socket/vendor/golang`.
- A project patched by an earlier socket-patch gets its line from the next `scan` or `get`
  that patches in the project's mode, `repair`, `rollback`, `remove` or `vendor --revert`, and
  from `apply` or `vendor` where the project has a manifest (a project that is only vendored
  has none, and both end before this step). A `scan` that writes nothing else (hosted mode with
  nothing to pin, `patches.enabled: false` in `socket.yml`) does not write this file either,
  and `list`, `vex` and the `--check` audits never do. So the first such command after an
  upgrade changes `.bazelignore` in a workspace that already has a copy: commit it. The line
  does not undo what gazelle wrote before: a gazelle run may have left a `BUILD.bazel` inside
  the copy, and the build stays broken until that file is gone. In vendored mode the next
  `scan --mode vendored` rebuilds the copy; in agent mode delete the `BUILD.bazel` files under
  `.socket/go-patches` by hand.
- `scan --prune` removes vendored copies the project no longer uses after the scan's own step
  has brought the file in line, and then takes away the pair of a copy it removed. A warning
  the scan gave for that copy before is then out of date, and a file that pass cannot write is
  reported by the next command.
- Two projects under one Bazel root share the file. Each command edits it under an advisory
  lock on the root directory itself (no lock file is made anywhere, and a command with nothing
  to change takes no lock), so commands that run at the same moment each keep their lines.
  Without the lock (on Windows, where a directory cannot be locked this way; on a file system
  without such locks; when the lock stays held for a second) a pair that one project adds while
  another project's pair is removed can be lost until the next command in that project. Pairs
  that are only added are safe without it: each is one write at the end of the file. A command
  that fails after it removed a copy can leave the pair of that copy behind, which ignores
  nothing; the next command removes it.
- A project directory whose path from the Bazel root starts with `#` or white space, or holds
  `*`, `?` or `[`, cannot be named in `.bazelignore`: the line is written, and Bazel or gazelle
  does not honour it.

### Go workspaces (go.work)

Every Go path (`apply`, `vendor`, `scan --mode hosted`, `vex`, `list`,
`rollback`) reads the workspace the way go does. The `go.work` in effect is
`GOWORK` when it names an absolute file, none under `GOWORK=off`, and
otherwise (`GOWORK` unset, empty or `auto`) the nearest `go.work` at or
above the project. A relative `GOWORK` makes go fail
(`invalid GOWORK: not an absolute path`), so socket-patch writes nothing for
it and attests nothing. `vex` reads the same workspace, members outside the
project included: a Socket replace that workspace overrides, ignores or
rejects (the check the writers run before writing one), or one in the
project's own `go.work` while go builds another, stays listed, so `list`,
`rollback` and `remove` find it, but is not attested
(`go_workspace_override`).

`GOFLAGS` is read the same way (the environment, then the `go env -w`
file). A `-modfile` in it that names any file other than the project's
`go.mod` makes go build from that file and its `.sum` and ignore `go.mod`'s
replaces, and in workspace mode go refuses `-modfile` outright. socket-patch
then writes no replace, `apply --check` and `vendor --check` fail on one
already written, and `vex` attests none of the project's Go patches. A
relative `-modfile` is taken from the project directory, where go is
assumed to run. Unset it (`go env -u GOFLAGS` if `go env -w` set it) and
re-run.

In workspace mode go reads `replace` directives from `go.work` and from the
`go.mod` of each module it `use`s. Run in the directory holding `go.work`,
`apply`, `vendor` and `scan --mode hosted` write the `replace` of a module
the workspace shares into `go.work`, as `go work edit -replace` would: when
that directory has no `go.mod` of its own (the usual layout), when another
`use` member lists the module (requires it, or for a go < 1.17 member has its
zip line in `go.sum`), or when `go.work` already holds a Socket replace of it.
The last two need `go.work` to `use` that directory's own module: for one it
doesn't use, a `go.work` replace would patch the members and never the
module, so the `go.mod` replace is refused (below). A replace onto a
`.socket/` copy that `go.mod` holds from before another member listed the
module moves into `go.work` the next time `apply` or `vendor` writes it (a
`vendor` takeover then deletes the `.socket/go-patches/` copy no file names
any more); a hosted pin there stays, its sum lines beside it, and in
workspace mode the `go.work` replace overrides it.
Only the directory's own `go.work` counts: when `GOWORK` names another file
in it (say `ci.work`), go doesn't read `go.work`, so socket-patch never
writes the replace there. It treats that file like a workspace file in
another directory: a module it `use`s takes the replace in its own `go.mod`,
and a directory with no module is refused ("has nowhere to go").
One `go.work` replace applies to every member. Member replaces of one
project-local copy would not: go resolves each against its own member
directory, sees two targets and refuses the workspace. The target is
relative to the `go.work` directory, where the copy lives
(`./.socket/go-patches/…` for `apply`, `./.socket/vendor/golang/<uuid>/…` for
`vendor`). A hosted pin is version-specific (`replace M v =>
patch.socket.dev/gopatch/<uuid> <sver>`) and its two sum lines go into
`go.work.sum`; the members' `go.mod` and `go.sum` are left as they are, so
their upstream sum lines stay for a `GOWORK=off` build. A `go.work` replace
does nothing for a build that doesn't read that `go.work` (`GOWORK=off`, or a
member copied out of the workspace): such a build links the upstream module,
and `vex` under `GOWORK=off` doesn't attest it.

Before writing a `go.work` replace socket-patch refuses one that would not do
what it says: `go.work` already replaces that version of the module (or every
version) with something else, or a member's own `replace` of it would be
overridden for every member. Run elsewhere, socket-patch writes its `replace`
into the module's own `go.mod` and first checks how the workspace treats it
(Go 1.26 precedence). A member `go.mod` replace does nothing, or breaks the
build, when:

- `go.work` replaces the same version of the module, or every version
  (`replace M => …`). go reads that replace before any member's, so the build
  links the go.work target. A go.work replace of *another* version does not
  override the member's replace of this one;
- `go.work` doesn't `use` the project, so workspace builds ignore its `go.mod`;
- another `use` member already replaces the same `module@version` with a
  different target, so go refuses the workspace ("conflicting replacements").
  A hosted replace names the same Socket module in every member and doesn't
  conflict. Run socket-patch in the directory holding `go.work` instead,
  which replaces the module once there;
- another `use` member replaces every version of the module
  (`replace M => …`) with a different target. Depending on the `use` order,
  go then links that target or refuses the workspace.

`apply`, `vendor` and `scan --mode hosted` refuse to write such a replace and
say which case applies (hosted: `redirect_golang_workspace_conflict`, nothing
written and the patch not reported redirected). A replace written before the
`go.work` changed is reported as `go_workspace_replace_ineffective` by
`apply`, `vendor` and `scan --mode hosted`, fails `apply --check` and
`vendor --check`, and `vex` leaves the patch out (`go_workspace_override`).

The build list of a workspace is the union of every `use` member's
requirements, so another member can require a higher version of the patched
module and make a replace pinned to the lower one inert. go doesn't keep
member `go.mod` files tidy in workspace mode, so a member's dependency can
raise the module too, with no member's `require` showing it. socket-patch
works out which version the workspace selects the way go does: minimal
version selection over each member's `require`s and the `go.mod` of every
dependency go loads, read from the dependency's replacement directory or the
module cache (`$GOMODCACHE/cache/download`). `go.sum` and `go.work.sum` are
not evidence: go only ever appends to `go.work.sum`, so it keeps the line of
a version nothing requires any more. When a `go.mod` it needs is missing
(a fresh clone before `go mod download`, or a member's `go.mod` it can't
read) and nothing it did read already shows a higher version, the answer is
unknown: `apply` still writes the replace, but `apply --check` fails, `vex`
leaves the patch out (`go_version_not_selected`) and hosted mode writes
nothing (`redirect_golang_not_in_module_graph`) until `go mod download` puts
the files in the module cache. For the same reason `vex` never attests a
hosted pin in a workspace from its `/go.mod` go.sum line alone; it needs the
Socket module's zip line.

A module that is itself a `use` member (a local checkout of a dependency,
`use ./dep`) is built from that directory and go ignores every `replace` of
it. `apply`, `vendor` and `scan --mode hosted` refuse to replace it and say
so; patch the checkout itself instead.

Every mode records and discovers what it wrote in `go.work`: `apply --check`,
`vendor --check`, `list` and `vex` read the `go.work` replaces (`vex` with
source `go.work`, hosted pins checked against `go.work.sum`), `remove` and
`vendor --revert` drop the replace from `go.work` byte for byte (the vendored
ledger records the wiring file as `go.work`), and `rollback` of a hosted pin
removes the `go.work` replace and the Socket lines of `go.work.sum`, deletes a
`go.work.sum` those lines leave empty (hosted mode keeps no record of whether
the file existed before the pin; go never writes an empty one, so only a
`go.work.sum` you created empty yourself is lost), and puts the upstream pair back only
where no sum file still holds it (a member's `go.mod` pin rolled back with it
gets the pair back in that member's `go.sum`, as every `go.mod` pin does). A committed workspace `vendor/` directory
needs `go work vendor` after any of these
(`go_vendor_modules_txt_out_of_sync`). Discovery also reads each in-root
member's `go.mod` at a `go.work` root without one of its own (pins an older
release wrote there), and `rollback` removes those too.

A `replace` names an exact module version, so it only works while the build
selects that version. socket-patch reads which version that is from `go.mod`
and `go.sum` (every workspace member's in workspace mode): the `require` line in a go 1.17+ module, or, in an older module
(whose `require` lists only lower bounds and leaves out transitive modules),
the highest of the required version and the versions `go.sum` has a module
zip line for. `apply` and `scan --mode hosted` refuse to write a replace for
any other version. In a workspace the build takes the highest version any
`use` member selects, so `apply`, `vendor`, `apply --check`, `vex` and
`scan --mode hosted` read every member's `go.mod` and `go.sum` too: a member
that requires a newer version makes a replace pinned to the older one inert.
A hosted rescan removes a pin it wrote once another member outranks it.
After an upgrade such as `go get M@v1.0.1`, `apply --check` fails and `vex`
leaves the patch out (`go_version_not_selected`) until you get a patch for the
new version.

A module the build uses only as the target of another module's replacement
(`replace other.com/fork => example.com/upstream v1.0.0`) is not patched
either. go downloads the target and records its `go.sum` lines under the
target's own path, but the build list holds only `other.com/fork`, and go
doesn't apply a replace to a replacement. So a zip line at the target's version
doesn't count: `apply`, `vendor` and `scan --mode hosted` refuse the patch
(hosted: `redirect_golang_not_in_module_graph`), and a replace written before
the fork replace appeared fails `apply --check` and is left out of `vex`
(`go_version_not_selected`).

Paid hosted Go references are unsupported: embedding credentials in module paths
would expose them to module proxies and change module identity. Use vendored mode
for those patches; the CLI reports `redirect_golang_unsupported` when the required
hosted reference is absent.

Important limits:

- A replacement targets an exact original module version. Updating the `require`
  can leave it unused; re-scan and regenerate VEX after dependency updates.
- An internal `GOPROXY` must be able to serve or forward the Socket module path.
  Comma-separated proxy fallbacks do not recover from every HTTP error.
- User-authored conflicting replacements are preserved and the patch is refused.
  Missing module metadata, untrusted Socket module paths, or missing integrity
  values are also refused before writing.
- Local directory replacements in agent and vendored mode are not checked against
  `go.sum`; commit and review those trees. Hosted replacements use the module
  checksum mechanism above.

The implemented hosted shape and fresh-checkout behavior are exercised by
[`e2e_golang_hosted_build.rs`](../crates/socket-patch-cli/tests/e2e_golang_hosted_build.rs).

## Bazel workspaces: Composer

No Bazel ruleset builds PHP or takes Composer packages, so a PHP project in a Bazel workspace
brings its packages into the build with a few lines of its own: a repository rule or a genrule
that runs `composer install` from the committed `composer.lock`, or a committed `vendor/` tree
that Bazel reads as source files. Hosted mode patches the first two when Bazel runs the rule
or the action again: Composer runs on the lock that socket-patch rewrote and fetches the
patched archive. For the third, see vendored mode with the flag below. Agent mode is not
supported in a Bazel workspace.

Vendored mode is declined there by default. It makes `composer.lock` name the patched copy by
a path relative to the directory Composer runs in
(`.socket/vendor/composer/<uuid>/<vendor>/<name>@<version>`). A rule or a build action runs
Composer in a directory of Bazel's that holds `composer.json` and `composer.lock` and nothing
else, so Composer fails with `Source path "..." is not found for package ...`, and the build
fails with it, after a command that exited 0 (Bazel 9.3.2, 8.8.2 and 7.7.2). What a workspace's
rules do with the lock cannot be read from its files: a rule may take the lock through a glob,
or live in another module, and a committed `vendor/` tree does not show that no rule runs
Composer somewhere else as well. So socket-patch does not try to.

A project is in a Bazel workspace by the lookup of
[Bazel workspaces: `.bazelignore`](#bazel-workspaces-bazelignore): its directory, or one above
it up to the root of its git checkout, holds `MODULE.bazel`, `REPO.bazel`, `WORKSPACE` or
`WORKSPACE.bazel`. There, every command that would vendor a Composer package reports the
package `failed` with `vendor_composer_bazel_workspace` and exits 1: `scan --mode vendored`,
`get --mode vendored` and `vendor`. It writes nothing and downloads no patch, and a
package that is pinned hosted stays pinned. With `--dry-run`, `scan` and `get` list the package
as one the run would refuse and exit 0; `vendor --dry-run` reports the refusal and exits 1, as
it does for any package it could not vendor. The message names the Bazel root and the mode
that writes no such path: `--mode hosted`.

Vendored mode goes on when you say so, with `--allow-vendored-in-bazel` or
`SOCKET_ALLOW_VENDORED_IN_BAZEL=1`. That is for a project where Composer only runs in the
project's directory, or where the build finds the copy all the same:

- A project that Bazel does not build: a Dockerfile runs `composer install` in it.
- A project that commits its `vendor/` tree, when no rule of the workspace installs from the
  lock as well. The build is the patched one after your next `composer install` in the
  project, which copies the package from `.socket/vendor`, as in a project without Bazel.
- A project whose rule brings the project's `.socket` directory to where it runs Composer.

socket-patch checks none of these. The switch is not Composer's alone: it lets vendored mode
write for any package it would decline because the project is in a Bazel workspace, where the
build may not find the vendored copy. PyPI and RubyGems have such a refusal too, for a project
whose lock a hub of the workspace reads: see
[Bazel workspaces: PyPI and RubyGems vendored mode](#bazel-workspaces-pypi-and-rubygems-vendored-mode).

`vendor --revert` is never declined. Neither is a package that is already vendored: where
`composer.lock` already names the copy of the same patch, a vendored run leaves the lock as it
is. So a project that was vendored with the flag, or by an earlier release, keeps passing its
runs without the flag, a `scan` or `get` with no `--mode` included, which runs in vendored mode
there. A new patch for that package, or another package, is declined until the run has the
flag.

Limits:

- A project in a Bazel workspace that Bazel does not build, and one that commits its `vendor/`
  tree, are declined like any other until they have the flag.
- A Bazel root that the lookup does not reach is not seen, and vendored mode goes on there as
  before: one above the git checkout (a project that is a checkout of its own, such as a
  submodule, in a Bazel repository), one above a project that is in no checkout or whose
  checkout's `.git` belongs to another user, and the home directory itself for a project
  below it.
- Hosted mode, which the message names, changes `composer.lock` and nothing else. It patches
  the build when Bazel runs Composer on that lock again. A repository rule that links the lock
  with `rctx.symlink` is not run again on Bazel 8 and 9 until its repository is fetched again,
  and a workspace that takes the package without the lock (an `http_archive` of its archive)
  never reads it: there the hosted run exits 0 and the build stays the unpatched one.

[`e2e_bazel_build/composer.rs`](../crates/socket-patch-cli/tests/e2e_bazel_build/composer.rs)
runs these flows on a real Bazel.

## Bazel workspaces: PyPI and RubyGems vendored mode

Two rulesets hand a lock of the checkout to Bazel through one call, a hub: rules_python's
`pip.parse` reads requirements files, and rules_ruby's `ruby.bundle_fetch` reads a `Gemfile` and
its lock. Each fetches what the file names into repositories of Bazel's own and builds from
there. Vendored mode makes that file name the patched copy by a path under `.socket/vendor`,
and neither ruleset builds from such a file:

- **PyPI.** The package's line of `requirements.txt` becomes
  `./.socket/vendor/pypi/<uuid>/<wheel> --hash=sha256:...`. rules_python 2.5.0-rc4 makes the
  name of a repository from that path, and the build of everything the hub serves fails with
  `invalid user-provided repo name 'pip_311__/_socket/vendor/pypi/<uuid>/<wheel>'`.
- **RubyGems.** The gem's declaration in `Gemfile` gets a `path:` and its entry of
  `Gemfile.lock` moves into a `PATH` section. rules_ruby 1.0.0-rc2 copies the two files into a
  repository of Bazel's and runs `bundle install` there, which fails with
  `The path .../.socket/vendor/gem/<uuid>/<name>-<version> does not exist.`

Both were measured on Bazel 9.3.2, 8.8.2 and 7.7.2, after a `scan --mode vendored` that exited
0 and reported the package vendored. So vendored mode now declines such a package, where the
files of the workspace show that a hub reads the file it would rewrite. For a PyPI package it
first asks whether the checkout shows that another form works, in which the build takes the
committed wheel, and writes that one where it does:
[Bazel workspaces: PyPI vendored mode as a download cache](#bazel-workspaces-pypi-vendored-mode-as-a-download-cache).
What follows is what happens everywhere else.

**What is read.** The project is in a Bazel workspace by the lookup of
[Bazel workspaces: `.bazelignore`](#bazel-workspaces-bazelignore). There socket-patch reads
`MODULE.bazel` and the files it includes, and the `WORKSPACE` file, as
[Bazel workspaces: VEX](#bazel-workspaces-vex) describes; nothing is evaluated and no Bazel is
run. A package is declined when one of these calls names, by a label written out as a string,
a file of the package's project that the vendored run for that package would point at a copy:

| Call | Attributes | Files of the project that count |
|---|---|---|
| rules_python `pip.parse` | `requirements_lock`, `requirements_by_platform`, `requirements_darwin`, `requirements_linux`, `requirements_windows`, `uv_lock` | `requirements.txt` and each file it includes with `-r` (in the project), as one set, where the run writes a requirements file; `uv.lock` in a uv project |
| rules_ruby `ruby.bundle_fetch` | `gemfile_lock`, `gemfile` | `Gemfile`, `Gemfile.lock` |
| any call of the `WORKSPACE` file that passes one of those attributes (`pip_parse`, `rb_bundle_fetch`) | the same; a label `@<name>//...` names the main repository where the file says `workspace(name = "<name>")` | the same |

Which files a run writes depends on the tool that locks the Python project, as in the matrix
at the top:

- A project with no tool lock is wired through its requirements files. They count as one
  set: a package is declined when the hub reads any file of the set, also one that does not
  pin it, because that file can bring in the rewritten one with `-r`.
- A uv, Pipenv or PEP 751 lock is wired together with a pin of the same package in the
  requirements files beside it. So those files count for a package they name, and not for
  one they do not name.
- A Poetry or PDM lock is wired alone. A hub that reads the requirements file exported from
  it stands in no run's way, and the package is vendored as it is without Bazel. Bazel goes on
  building the registry's package from that file; `socket-patch vex` does not say so yet (see
  the limits of [Bazel workspaces: VEX](#bazel-workspaces-vex)). The one exception is a
  requirements file that holds the package by a URL, which is what a hosted pin is: a
  vendored run that takes the pin over restores that line, so the files count and the
  package is declined.

Every such call counts, also one that may not run (in a comprehension, behind an `and`). The
refusal is for every package whose run would write a file the call names, since the lock is
the project's, with one exception: a package that is already vendored (see below).

**What an uncertain reading does.** Where something of the workspace's files cannot be read
with certainty, and a call of the hub may be behind that, every package whose run would write
one of the files above is declined, in every project of the workspace, because the call may
read its lock. That is:

- a call of the hub whose file is not a plain string (a constant, a concatenation), or one
  that passes `*` or `**`;
- a hub proxy that is handed to anything but `use_repo` or `inject_repo`;
- a module file that is missing or cannot be read, or a statement of one that cannot be
  read, where the workspace calls the hub or a file that was read names its ruleset (a
  `bazel_dep` on rules_python or rules_ruby, or a `use_extension` of the hub's `.bzl` file);
- a root `MODULE.bazel` or a `WORKSPACE` file that cannot be read at all.

A file cannot be read here when one byte of it is not UTF-8 (a name in a comment is enough),
or when it is larger than 1 MiB; Bazel builds both. Going on there can leave a broken build
behind a command that exited 0; declining costs a vendored run, which the switch below brings
back. A workspace whose root `MODULE.bazel` and `WORKSPACE` file were read (or are not
there), and in which no file that was read calls the hub or names its ruleset, is never
declined for it, whatever else cannot be read.

**What you see.** Every command that would vendor the package reports it `failed` with
`vendor_pypi_bazel_hub` or `vendor_gem_bazel_hub` and exits 1: `scan --mode vendored`,
`get --mode vendored` and `vendor`. It writes nothing and downloads no patch, and a
package that is pinned hosted stays pinned (`vendor` reports `eject_refused`). With
`--dry-run`, `scan` and `get` list the package as one the run would refuse and exit 0;
`vendor --dry-run` reports the refusal and exits 1. The message names the call with its file
and line, the lock, and the mode to use instead:

```
`pip.parse` (MODULE.bazel:15) of the Bazel workspace at /repo names requirements.txt; vendored mode makes the lock name the patched copy by a path under .socket/vendor, and rules_python fails the build on such a lock; use `--mode hosted`, which names the patched package by a URL that rules_python fetches, or pass `--allow-vendored-in-bazel` if no build takes the packages of this project from rules_python
```

For an uncertain reading the message names the file, the line and the reason where the
call stands. For a PyPI package whose hub was read with certainty the message goes on with
why the download cache is not written
([the conditions](#bazel-workspaces-pypi-vendored-mode-as-a-download-cache)). Hosted mode pins the patch in the same file, as a wheel URL with its sha256 or
as a gem source, and both rulesets build it: that is tested on the three Bazel releases, in
the checkout where vendored mode was declined. For a gem that holds for a
`ruby.bundle_fetch` without `gem_checksums`, as the message for a gem says. Where a
`gem_checksums` of the call holds the gem to another sha256, or is not written out in the
call, hosted mode writes nothing for the gem and its warning names the way on: see
[Bazel workspaces: RubyGems](#bazel-workspaces-rubygems).

**Where nothing changes.** A project in no Bazel workspace, a workspace that calls neither
hub, and a package whose run writes no file that a call names are vendored as before, with
the same output and the same files: a Python or Ruby project beside the one whose lock the
hub reads, a Poetry or PDM project whose exported requirements file the hub reads, or a
project that keeps a `requirements.txt` for pip while the hub reads a `requirements_lock.txt`
that socket-patch does not rewrite. In the last two cases Bazel goes on building the
unpatched package from its own file, as before.

Vendored mode goes on when you say so, with `--allow-vendored-in-bazel` or
`SOCKET_ALLOW_VENDORED_IN_BAZEL=1`: for a hub that no build of yours uses, for a `WORKSPACE`
file that your Bazel no longer reads (Bazel 9 never reads it, Bazel 8 only with
`--enable_workspace`), or for a `ruby.bundle_fetch` to which you add every file of the
vendored gem as `srcs`, which rules_ruby copies beside the Gemfile (no test here builds
that). socket-patch checks none of these. It is the switch of
[Bazel workspaces: Composer](#bazel-workspaces-composer).

`vendor --revert` is never declined. Neither is a package that is already vendored: where
the file that the call names already names the copy of the same patch
(`.socket/vendor/pypi/<uuid>/`, `.socket/vendor/gem/<uuid>/`), a vendored run adds nothing to
what the hub reads. So a project that was vendored with the switch, or by an earlier release,
keeps passing its runs without the switch, a `scan` or `get` with no `--mode` included, which
runs in vendored mode there. A new patch for that package, or another package, is declined
until the run has the switch. Where the calls name more than one file of the project, each
of them that holds the package has to name the copy: a `uv.lock` that was locked again
beside a vendored requirements file does not, and the package is declined. Where the reading
is uncertain no file is known to be the hub's, so nothing is let through: every vendored run
there needs the switch.

Passing such a run does not mean that the build is the patched one. A build that takes the
project's packages from the hub fails on a vendored PyPI package, and on a vendored gem
unless the call lists the copy's files. For a PyPI package `vex` says of that state that the
package is `affected` ([Bazel workspaces: VEX](#bazel-workspaces-vex)); the way out is
`vendor --revert`, then `scan --mode hosted`.

Limits:

- Not seen, so vendored mode goes on as before and the build can break: a hub call in a
  `.bzl` file that a `WORKSPACE` file loads, a hub that another Bazel module declares,
  another tag or another ruleset that reads the same file under Bzlmod (rules_ruby's older
  `ruby.bundle`, rules_pycross, aspect_rules_py), a `WORKSPACE` call that hides its
  arguments behind `**`, the `pip_install(requirements = ...)` of an older rules_python in a
  `WORKSPACE` file, a Bazel root that the lookup does not reach, and a hub whose call
  and whose `bazel_dep` are both in an included file that cannot be read, while the files
  that were read name neither.
- Declined although the build would pass: a `WORKSPACE` file that names the lock while the
  Bazel in use does not read that file, a hub call that never runs, and a workspace that
  does not use the ruleset while its root `MODULE.bazel` or its `WORKSPACE` file cannot be
  read here, or while a file that was read names the ruleset and another cannot be read.
- Declined although the run would write nothing to the file the call names: a package that
  is already vendored where the file that names its copy is not the one the call names (a
  requirements file that the named one includes with `-r`; the `Gemfile` when the call names
  the lock too and the lock does not name the copy), any already vendored package where the
  reading is uncertain, a package of a uv, Pipenv or PEP 751 project that the
  requirements file names in a form that is not wired with the lock (a range, extras), and a
  package of a project with no tool lock where the hub reads a file of the requirements set
  that neither pins the package nor brings in the file that does.
- Only the `Gemfile` spelling is looked for, as vendored mode wires no `gems.rb` project.
- A `pip.parse` that names a `uv.lock` is declined by the rule above, not by a measurement:
  no build was run on a vendored `uv.lock`.
- `repair` is not gated: it replaces a damaged copy of a package that is vendored already,
  and leaves the lock as it is.

[`e2e_bazel_build/pypi.rs`](../crates/socket-patch-cli/tests/e2e_bazel_build/pypi.rs) and
[`ruby.rs`](../crates/socket-patch-cli/tests/e2e_bazel_build/ruby.rs) run the refusal, the
switch and hosted mode on a real Bazel.

## Bazel workspaces: PyPI vendored mode as a download cache

Where a rules_python `pip.parse` hub reads the project's `requirements.txt`, the path line of
vendored mode breaks the build
([Bazel workspaces: PyPI and RubyGems vendored mode](#bazel-workspaces-pypi-and-rubygems-vendored-mode)).
The line of hosted mode does not: the hub fetches a wheel that a requirement names by its URL
with Bazel's own downloader, by the sha256 of the line. And before Bazel downloads a file
that has a checksum, it looks in every `--distdir` for a file of that name and checksum. So
in such a project `scan --mode vendored` (and `get --mode vendored`, and `vendor`) writes
three things:

1. **The package's line of `requirements.txt`, exactly as hosted mode writes it**:
   `<name> @ <URL of the patched wheel on the patch host> --hash=sha256:<hex>`.
2. **The patched wheel**, downloaded once, at `.socket/vendor/pypi/<uuid>/<wheel>`, under the
   file name its URL ends in, with the files vendored mode keeps beside every wheel and its
   entry in `.socket/vendor/state.json`.
3. **One line in the `.bazelrc` at the Bazel root**, under a comment line of socket-patch's
   own:

   ```
   # socket-patch: the committed copy of a patched wheel, for Bazel's downloads (to opt out, comment out the next line)
   common --distdir=.socket/vendor/pypi/<uuid>
   ```

   The directory is written from the Bazel root (`svc/.socket/vendor/pypi/<uuid>` for a
   project in `svc`): Bazel reads a relative `--distdir` from the workspace root, from any
   directory a command runs in, and does not expand `%workspace%` in this option.

Commit all of it. The build then takes the committed wheel and asks no host. Measured with
rules_python 2.5.0-rc4 on Bazel 9.3.2, 8.8.2 and 7.7.2: a fresh clone builds the patched
package with the patch host stopped, a new output base and no copy of the wheel in Bazel's
repository cache, also from a sub-directory and beside a `--distdir` of your own.
[`e2e_bazel_build/pypi.rs`](../crates/socket-patch-cli/tests/e2e_bazel_build/pypi.rs) builds
that on the three releases, in a checkout whose `.bazelrc` has a `--distdir` line of its own.

Each patch gets a line for its own directory. A `--distdir` is one flat directory that Bazel
searches by file name, two patches of one release have wheels of one name, and the directory
of a patch is what vendored mode writes, checks and removes as a unit.

**When it is written.** Only where the files of the checkout show that it works. Each
condition that fails declines the package with `vendor_pypi_bazel_hub`, as before, and the
message ends with the one that failed:

- The project pins in `requirements.txt` alone (no uv, Pipenv, Poetry, PDM or PEP 751 lock
  holds the package), and that file is in pip's hash-checking mode: Bazel takes a committed
  file only for a download that has a checksum.
- The package's requirement is one exact pin with its hashes, which is what hosted mode
  rewrites; extras, an environment marker, an option, a comment or an indent on it decline,
  because the form was measured with the plain line.
- A `pip.parse` names that file by `requirements_lock`, and names no other file of the
  project by any attribute (a `requirements_linux` or `requirements_by_platform` beside it
  would build some platform from a file that is not written). Every call of the hub is
  written out and runs, nothing of the module files is in doubt, and no `WORKSPACE` file
  defines repositories.
- Bazel selected rules_python 2.5.0 (or 2.5.0-rc4, the same commit). socket-patch reads that
  as it reads the release of rules_jvm_external: from the one `source.json` of the ruleset
  that `MODULE.bazel.lock` records, checked against what `MODULE.bazel` asks for. A checkout
  without that lock, or with a stale one, is declined: build once, so that Bazel writes it.
  Other releases fetch a wheel through other code, which no build here has run.
- The checkout names Bazel 7, 8 or 9 (`.bazeliskrc`, `.bazelversion`); or it names none and
  its `MODULE.bazel.lock` has a version that Bazel 7.5.0 to 9.3.2 write.
- No rc file of the checkout (`.bazelrc` and what it imports) names a downloader config
  (`--downloader_config`, `--experimental_downloader_config`), `--repository_disable_download`
  or a remote downloader, and all of them can be read. Bazel refuses a download that such a
  config blocks before it looks in a `--distdir`. An `import` or `try-import` of an absolute
  path declines as well: that file is outside the checkout, socket-patch does not read it,
  and it is where the settings of a site's mirror usually are.
- The line can be written: `.bazelrc` is no symbolic link and not read-only, and the
  project's path from the Bazel root holds no blank, quote, backslash or `#`.

Three more are seen only later. A requirement that names the package by a URL of the user's
own, and not by a version, is declined before anything is fetched (no scan finds a package in
such a line; `get` for the release does). A hub that names a file which brings
`requirements.txt` in with `-r` is declined, whichever of several hubs is written first. And
what the patch service serves must be a wheel for every platform (`-none-any.whl`): for a
source distribution or a wheel of one platform the run fails after its download
(`apply_failed`, with an error that starts `vendor_pypi_bazel_hub:`), writes no line and
keeps a wheel that an earlier run committed.

With `--allow-vendored-in-bazel` vendored mode writes the path line instead, here too: the
switch says that no build takes the project's packages from the hub.

**What it does not do.** The command says the first two in a warning
(`vendor_pypi_bazel_download_cache`) when it writes the form:

- pip outside Bazel reads the same line, and asks the patch host for the wheel. It does not
  take the committed copy.
- With the patch host unreachable, a changed or missing copy fails the build. With the host
  reachable, Bazel passes over such a copy without a message and downloads the pinned wheel:
  it never builds other bytes, and it never says that the committed copy is wrong.
  `socket-patch vendor --check` is what holds the committed wheel to the patch, so run it
  in CI. A machine whose repository cache already holds the wheel does not read the copy at
  all.
- A relock (`pip-compile`, a version bump) writes the registry's pin back over the line. The
  build is then green and unpatched, and the copy and its `.bazelrc` line stay behind
  without effect. `socket-patch vendor --check` fails on that, and the next scan pins the
  package again. That scan asks the patch service for the wheel once more, also where the
  committed copy is intact: the line holds the URL the service grants, and a run takes it
  from the grant.
- A downloader config that the files of the checkout do not show is not seen: one given on
  the command line, in the rc file of the home directory or of the machine, or in a file
  that a `try-import` names and this checkout does not have (a `user.bazelrc` that is not
  committed). Where it blocks the patch host the build fails although the copy is
  committed, as it fails on a hosted pin.
- A build that may not update Bazel's lock (`--lockfile_mode=error`) fails right after the
  command on Bazel 8.5 and later, until a build that may update `MODULE.bazel.lock` has
  run, as in hosted mode. Commit the updated lock with the patch.
- A Bazel command that reads no workspace rc file (`--ignore_all_rc_files`,
  `--noworkspace_rc`) does not see the line, and asks the patch host (by Bazel's
  documentation of the two options; not run).
- Not measured: a second Python version in the hub, Linux and Windows (every run was on
  macOS; CI runs the test on Linux), and remote execution.

**The `.bazelrc` lines.** They are kept as the `.bazelignore` lines of
[Bazel workspaces: `.bazelignore`](#bazel-workspaces-bazelignore) are, by the same commands
(every one that can write or remove a copy ends by bringing the file in line, unless it is a
dry run; one whose `--ecosystems` leaves `pypi` out adds no line). A line is added at the
end of the file for the directory of each such wheel while it exists, and the pair is taken
away once the directory is gone, which leaves the file as it was, byte for byte; a `.bazelrc`
left empty is removed, also when it was an empty file of yours. Your own lines are never
touched. To decline a line, put a `#` before it and leave socket-patch's comment above it:
nothing is added for that directory again, and the two lines stay yours. A `.bazelrc` that is
a link or read-only declines the package before anything is written (the conditions above).
A file that cannot be written when the command gets to it (it became read-only since, the
root directory takes no new file, or an undo finds its pair in a file it may not change) is
a warning, `bazelrc_not_updated`, that names the line to add or the pair that can be
deleted; without the line the build downloads the wheel from the patch host, as in hosted
mode.

**The other commands.** `list` shows the package as vendored, and `vex` attests it as a
vendored package whose committed wheel holds the patch (`not_affected`): the hub builds that
wheel, by the sha256 of the line. `vendor --check` verifies the committed wheel against the
patch and that `requirements.txt` still holds the line. `vendor --revert`, `rollback` and
`remove` put the pin back as it was, delete the directory and take the pair out of
`.bazelrc`; none of them needs a host. A later run in the same mode writes nothing, while
`requirements.txt` holds the line as the run wrote it. A line that has been changed since
(by hand: a comment after it, its hash moved to a line of its own) declines the package
with `vendor_pypi_bazel_hub` before anything is fetched, and the committed wheel and its
`.bazelrc` line stay: put the line back, or run `socket-patch vendor --revert` and vendor
again. A `scan --mode hosted` takes the package over: the line stays, and the copy and its
`.bazelrc` pair go. A newer patch of the package replaces the line, the wheel and the pair.

## Ruby gems: hosted mode

`scan --mode hosted` makes Bundler install a patched gem from that patch's own gem source on
the patch registry. It edits the `Gemfile` (or `gems.rb`) and its lock, and nothing else.

**The Gemfile.** The gem's declaration gains one option, `source:`, after its last argument.
The rest of the declaration stays byte for byte: the version requirement, the other options,
the quoting, the comment, the indentation and the `group` block around it.

```ruby
# before
gem "rack", "~> 2.2.3"       # web server interface
# after
gem "rack", "~> 2.2.3", source: "https://patch.socket.dev/patch-registry/gem/<token>/<patch-uuid>/"       # web server interface
```

The same goes for a declaration in parentheses (`gem("rack", "2.2.3")`), one that continues
over several lines (the option goes after the last argument, on that argument's line), one with
a trailing `if` / `unless` modifier (the option goes before the modifier), and one followed by
another statement after a `;`.

A patched gem the Gemfile does not declare (a dependency of another gem) gets one line at the
end of the file, after one blank line:

```ruby
gem "nokogiri", "1.13.6", source: "https://patch.socket.dev/patch-registry/gem/<token>/<patch-uuid>/", require: false # added by socket-patch (transitive dependency)
```

`require: false` keeps `Bundler.require` from loading the gem at boot, which it did not do
before the line was there; the gems that depend on it load it as they always did. The line is in
the default group, so `bundle install` installs the gem in every environment, including one that
leaves out the group of the only gem that depends on it.

**The lock.** The lock is edited to what Bundler itself writes for that Gemfile, so the pair
installs under frozen and deployment mode (`BUNDLE_FROZEN=true`, `bundle install --deployment`,
`bundle config set frozen true`) as it is committed:

- the gem's spec moves to a `GEM` section whose `remote:` is the patch's source (a lock written
  by Bundler 2.2 or later), or that source joins the `remote:` lines of the lock's one `GEM`
  section (a lock written by Bundler 1.17 to 2.1);
- its `DEPENDENCIES` entry keeps the requirement the Gemfile declares and gains `!`
  (`rack (~> 2.2.3)!`); a transitive gem gets the entry `nokogiri (= 1.13.6)!`;
- where the lock has a `CHECKSUMS` section (Bundler 2.6 and later), the gem's entry holds the
  sha256 of the patched gem. A lock without the section cannot record it: the gem is pinned by
  its source alone, and the scan says so once (`redirect_gem_no_checksums_section`).

A lock records the Bundler that wrote it (`BUNDLED WITH`), not the one that installs it, so the
lock is converged for the one that wrote it. For a lock written by Bundler 1.17 to 2.1 the scan
says which Bundler the pair is for (`redirect_gem_merged_lock_layout`): later Bundlers deprecate a
`GEM` section with several remotes and from 2.5 on refuse it under frozen mode. If a newer
Bundler installs the project, run `bundle lock` with it and re-run the scan.

The scan output names what it changed:

```text
Added `source:` to 2 gem declarations in Gemfile (puma and rack); added 1 line for the transitive dependency nokogiri.
```

**A patched gem stays at its version.** The patch's source serves the patched version and no
other, and it is now the gem's only source. So Bundler sees nothing newer for that gem:
`bundle outdated` no longer lists it and `bundle update`, with or without the gem's name, leaves
it where it is, even when the Gemfile requirement is a range (`"~> 3.1"`) and upstream has
released a later version. A gem that was a transitive dependency no longer floats with the gems
that depend on it either: its added line pins the exact version, so a later release of a parent
gem that needs a newer version of it is held back too, or fails to resolve. Gems that do not
depend on a patched gem update as before.

The run says which gems it now holds when it wires them, on stdout under the line above:

```text
Bundler now takes rack from its Socket patch source only, which serves the patched version and no other: `bundle outdated` no longer lists it and `bundle update` cannot move it. To move it to a newer release, run `socket-patch rollback pkg:gem/rack@3.1.8`, then `bundle update rack`, then `socket-patch scan` again.
```

To take a newer upstream release of a patched gem (a later security release included), undo that
gem's pin, update it, and scan again, which patches the new version if it still needs a patch:

```sh
socket-patch rollback pkg:gem/rack@3.1.8
bundle update rack
socket-patch scan
```

Name the gem: `socket-patch rollback` with no argument undoes every patch in the project. The
line is printed by the run that wires the gem (`--dry-run` prints what the run would hold,
without the steps); a re-scan that changes nothing does not repeat it, and `--json` output does
not carry it. `socket-patch list` shows the gems on a hosted patch at any time.

**When a gem is left alone.** The scan never writes a pair Bundler would refuse. A gem it cannot
wire is skipped, neither file changes for it, and the warning says why and what to do:

| Warning | The gem is skipped when |
|---|---|
| `redirect_gem_unrecognized_declaration` | its declaration cannot be edited in place: a heredoc or a `do` block among its arguments, other code before it on its line, a last argument that may be an options hash (`gem "rack", OPTS`). Write it as one `gem "<name>", …` call with literal arguments on a line of its own. |
| `redirect_gem_source_option` | the declaration already selects a source (`source:`, `git:`, `github:`, `path:`, a `**opts` splat that may hold one), sits inside a `source` / `git` / `github` / `path` block, or the lock resolves the gem from a `GIT` / `PATH` section. Bundler allows one source per gem. |
| `redirect_gem_declared_more_than_once` | the Gemfile declares it more than once. Merge the declarations into one. |
| `redirect_gem_declaration_not_visible` | the lock lists it as a direct dependency, but it is declared where the scan cannot edit: an `eval_gemfile`d file, a loop, a gemspec. Declare it with a literal `gem "<name>"` line in the Gemfile, in place of any other `gem` call that declares it (a gemspec's development dependency stays), or patch it with `--mode agent`. Vendored mode refuses it for the same reason. |
| `redirect_gem_dependency_not_locked` | the Gemfile declares it and the lock's `DEPENDENCIES` does not list it. Run `bundle lock` and re-run. |
| `redirect_gem_lock_unconvergeable` | the lock cannot be brought in line with the Gemfile: it has no `BUNDLED WITH` section to say which layout its Bundler accepts, or a Bundler < 2.2 lock lists its sources in an order the Gemfile's `source` lines do not explain. Run `bundle lock` with your current Bundler and re-run. Also a Gemfile with more than one top-level `source` line: Bundler 2.2 to 2.7 lock all its gems in one `GEM` section that names every source, which hosted mode does not rewrite, and `bundle lock` writes the same lock again. Keep the source that serves the gem as the one top-level `source` and move each other one into a `source "<url>" do … end` block around the gems that come from it (Bundler's own deprecation warning asks for the same), then run `bundle lock` and re-run; or use `--mode agent`. A Bundler 2.2 release before 2.2.25 keeps the one section even then, so run that `bundle lock` with a later Bundler; the warning says so when the lock was written by one. |
| `redirect_gem_platform_unsupported` | the lock holds a platform-specific build of the gem (`nokogiri (1.18.10-x86_64-linux-gnu)`) that the patch has no patched build for. The warning names the builds the lock holds, the ones that are missing, and what the patch registry serves. See "Precompiled platform gems" below. |

`--mode agent` can still patch a gem hosted mode skips. `--mode vendored` can too, unless it
refuses the gem itself (see "Ruby gems: gems vendored mode refuses").

**Precompiled platform gems.** Bundler installs a gem such as nokogiri as a precompiled platform
gem, and the lock then has one entry per platform the project supports, usually with no plain
`nokogiri (1.18.10)`:

```text
    nokogiri (1.18.10-arm64-darwin)
      racc (~> 1.4)
    nokogiri (1.18.10-x86_64-linux-gnu)
      racc (~> 1.4)
```

For such a gem the patch registry serves a patched platform gem (a "prebuild") per platform: the
upstream platform gem with the patch's files replaced, under the same file name. When the patch
has a prebuild for every platform the lock names, the scan wires the gem like any other. The
Gemfile edit is the same, every platform entry moves to the patch registry's `GEM` section with
its dependency lines (and a plain `nokogiri (1.18.10)` entry beside them moves too),
`DEPENDENCIES` gains the `!`, and each `CHECKSUMS` entry takes the sha256 of its own prebuild.
`bundle install` then fetches the one patched platform gem of the machine it runs on and
compiles nothing, in frozen and deployment mode too.

When the patch has no prebuild for one of the locked platforms, the gem is skipped with
`redirect_gem_platform_unsupported` and neither file changes: a machine of that platform would
otherwise be sent to a registry that has no gem for it. Remove the platform from the lock if the
project does not need it (`bundle lock --remove-platform <platform>`) and re-run, or wait for the
prebuild.

**Undoing it.** `rollback` and `remove` take the option (or the added line) off again and
restore the lock: the pair is the pre-scan pair byte for byte, with LF or CRLF line endings.

**Projects pinned by socket-patch 5.0 or 5.1.** Those releases replaced the declaration with a
`source "<url>" do … end` block that declares the exact version. Such a pin keeps working: a
re-scan leaves the block as it is (and brings a lock that never followed it in line), and
`list` and `vex` read it. The block does not hold the declaration it replaced, so `rollback` /
`remove` bring the gem back as the exact pin `gem "<name>", "<version>"` and say so
(`upstream_gem_declaration_pinned`): if the requirement was a range such as `~> 2.2`, put it
back by hand and run `bundle lock`.

**Keep the Gemfile and the lock together.** Bundler takes a gem from the source its Gemfile
declaration names; a lock that names another source is out of date to it. If the Gemfile loses
the `source:` option while the lock keeps the patch's `GEM` section (a `git checkout` of one
file, or a merge that took the other side of the Gemfile), a frozen install fails with "the list
of sources changed" and an ordinary `bundle install` rewrites the lock and installs the
unpatched gem (Bundler 1.17.2, 2.1.4, 2.4.22, 2.5.23 and 4.0.15 all do; the same holds for a
vendored gem whose Gemfile loses its `path:`). `vex` therefore attests a gem only when the
Gemfile (or `gems.rb`) beside the lock gives it the source the lock resolves it from. Otherwise
it warns `patched_ref_unattributable`, naming the gem and what the Gemfile says instead, and
writes no statement for it. To patch the gem again, run `bundle install` once without frozen
mode so the lock follows the Gemfile, then re-run `socket-patch scan` (or `vendor`): a hosted
scan skips a gem whose lock entry is still pinned to a source (`redirect_gem_source_option`).
`rollback` and `remove` still see and unwind a hosted lock section left this way.

## Ruby gems: gems already installed

Bundler keeps a gem it has already installed, whatever source `Gemfile.lock` names for it. After
a hosted scan repoints the lock at the patched gem, `bundle install` still prints `Using rack
2.2.3` and "Bundle complete!" over the unpatched copy, and `bundle install --redownload` and
`bundle pristine` reinstall from the unpatched archive RubyGems kept beside it (Bundler 2.6 and
later refuse it instead, on the lock's checksum). A `vendor/cache` filled by `bundle cache` has the
same problem on every fresh checkout.

So hosted mode (`scan` / `get --mode hosted`) replaces those copies itself, right after it
rewrites the lock:

- an installed gem whose gem home is inside the project (`vendor/bundle`, a `BUNDLE_PATH` or
  `GEM_HOME` under the project), together with the `.gem` archive RubyGems reinstalls it from;
- an archive in Bundler's cache dir (`vendor/cache`, or the configured `cache_path`). It is a
  committed file: the run lists it with the files to commit.

A gem that agent mode patched in place (`scan --mode agent`, `apply`) counts too. Its files are
already the patched ones, but the archive RubyGems kept beside it is still the upstream one, and
`bundle pristine` and `bundle install --redownload` reinstall from that archive: with a
`CHECKSUMS` section in the lock Bundler removes the gem and fails on the checksum, without one it
brings the unpatched gem back. So that archive is replaced with the patched one. The installed
files are left as they are.

They are replaced with the patched `.gem` the lock pins, checked against that sha256 first. A gem
with a native extension is installed into a staging directory by RubyGems, with the Ruby that
owns the installed copy, and swapped in once it has compiled; with no such Ruby, or with
`--no-gem-native-rebuild`, it is left alone. After the scan `bundle exec` runs the patched code,
and every kind of reinstall keeps it. `rollback` and `remove` do the same with the upstream gem.
That holds in a gem home with no `cache/` directory too (Bundler 4.1's `prune` setting, an image
that deletes it, `gem cleanup`): with no archive to compare, the installed files are checked
against the patch itself, in both directions. If the patch can't be looked up during a `rollback`
or `remove`, the copy is left alone and the run warns (`upstream_gem_stale_install`), naming the
files to remove before `bundle install`.
Vendoring a gem that was hosted (`vendor`, `scan --mode vendored`) leaves the installed copies as
they are: Bundler loads the vendored copy from then on. When that vendored gem is later unwound
(`rollback`, `remove`, `vendor --revert`), Bundler loads the installed copy again, so the unwind
puts the upstream gem back there too (for a gem locked as precompiled platform gems, the upstream
platform gem of the build that is installed). The same holds for a gem that agent mode patched in place
before `scan --mode vendored` (or `get --mode vendored`) took it over: the unwind reinstalls the
upstream gem over the patched files in the project's own gem home, and warns about a copy it
leaves (a shared gem home, `--no-gem-install-refresh`). A gem that was only ever vendored still
has the upstream build installed, and its unwind changes nothing in the gem home. When
`rollback` can prove that (the installed copy's archive in the gem home is the upstream gem
from rubygems.org, and the files the patch changes are unpatched), it does not count the gem in
its "keeps its patched bytes in installed trees" note or its `reinstall_required` warning:
there is nothing to reinstall.

Nothing is changed when the patched gem cannot be downloaded or verified: the run still exits 0
and warns (`redirect_gem_stale_install`), naming the files to remove by hand. `--dry-run` only
says what it would replace. `--no-gem-install-refresh` (or `SOCKET_NO_GEM_INSTALL_REFRESH=1`)
turns the refresh off.

Removing those files can leave a gem directory behind with no gemspec: after a project moves from
a precompiled build to the `ruby` platform build, `gems/nokogiri-1.16.0-x86_64-linux/` stays next
to the patched `gems/nokogiri-1.16.0/`. RubyGems and Bundler load a gem by its
`specifications/` entry, so nothing loads that directory, and `socket-patch vex` and
`apply --check` don't count it as an installed copy. `bundle clean --force` deletes it.

Gems in a gem home **outside** the project (the system gems, `~/.gem`, an rbenv or asdf home) are
not touched: another project on the machine may use the same copy. The run prints one warning
naming them. Either install the project's gems into the project, where Bundler fetches the patched
ones:

```
bundle config set --local path vendor/bundle && bundle install
```

or re-run with `--gem-refresh-shared` (or `SOCKET_GEM_REFRESH_SHARED=1`) to replace the copies in
the shared gem home. Another project that pins the upstream build of the same gem version then
loads the patched code too, and its `bundle pristine` fails on the checksum until it is patched
as well.

`rollback` and `remove` take `--gem-refresh-shared` as well, on the run that removes the patch:
it then puts the upstream gem back in the shared gem home. Without it the run warns that the
shared copy still holds the patched build. Running the command again doesn't help, because the
patch is already removed and there is nothing left to roll back. The warning names what to run
instead: the `bundle config` line above, or an `rm -f` of the gem's `specifications/` entry and
its `cache/` archive followed by `bundle install`, which fetches the upstream gem into the shared
gem home. Another project that still pins the patched build of that gem version then loads the
upstream code; a `socket-patch scan` there reports it, and `--gem-refresh-shared` on that scan
puts the patched build back.

A shared gem home also holds gem versions this project doesn't use: the gems Ruby ships (`rake`,
`rexml`, ...) and the versions other projects installed. Hosted and vendored mode patch what
`Gemfile.lock` resolves, so a version the lock doesn't list is skipped, never a failure: hosted
mode warns `redirect_gem_version_not_locked`, vendored mode reports a `skipped` event with
`vendor_gem_version_not_locked` and doesn't download its patch. The run exits 0.

## Ruby gems: gems vendored mode refuses

Vendored mode rewrites one top-level `gem` line to a `path:` source, and Bundler builds nothing
for a path-sourced gem. It refuses a gem that doesn't fit and changes nothing for it; the other
gems of the run are still vendored, and the run exits 1. These four refusals name another mode
that can patch the gem:

| Code | The gem | What the error offers |
|---|---|---|
| `gemfile_declaration_not_editable` ("is indented") | is declared inside a block: `group :test do`, `platforms … do`, a conditional. Every Rails Gemfile declares its development and test gems this way. | Move the declaration to the top level (for a plain `group` block the error spells the option that replaces it, `group: :test`), or patch the gem with `--mode hosted`, which edits a declaration where it is. Inside a `source`, `git`, `github` or `path` block hosted mode refuses the gem too, and the error names `--mode agent`. |
| `gemfile_declaration_not_editable` ("as a direct dependency") | is a direct dependency the Gemfile declares out of sight: in a gemspec (a gem library's development dependency), an `eval_gemfile`d file, a loop. | Declare it with one literal `gem "<name>"` line in the Gemfile (above `gemspec`, where the Gemfile has that directive), in place of any other `gem` call that declares it, or patch the gem with `--mode agent`. Hosted mode refuses a gem declared in those places too. |
| `native_extensions_unsupported` | builds a native extension (puma, bootsnap). | `--mode hosted` or `--mode agent`. Both build the extension. Only `--mode agent` when the declaration picks the gem's source (a `source`, `git`, `github` or `path` block or option), which hosted mode refuses. |
| `platform_gem_unsupported` | is installed as a precompiled platform build (`nokogiri-1.18.3-x86_64-linux-gnu`). | `--mode agent`. Hosted mode refuses a precompiled build too. |

To patch one gem in another mode, name it: `socket-patch get <gem> --mode hosted`. A whole-project
`scan --mode hosted` leaves vendored gems as they are, but it moves the vendored patches of the
other ecosystems (npm, PyPI, Cargo, Go, Composer, Gradle) to hosted mode. Once a project holds
patches of two modes, a `scan` with no `--mode` stops and asks which mode to use, so pass `--mode`
on later runs.

## Ruby gems: native extensions

Some gem fixes change only what a native extension is built from: its C sources
(`ext/**/*.c`, `*.h`, `extconf.rb`), or the files its build script reads (nokogiri builds its
vendored libxml2 from `patches/libxml2/*.patch`). Ruby never loads those files. It loads the
shared object RubyGems compiled when it installed the gem, or, for a precompiled platform gem
(`nokogiri-1.18.3-x86_64-linux-gnu`, the default install of nokogiri), the binary the gem ships.
How each mode gets the patched code running:

| Mode | What happens |
|---|---|
| Hosted | Bundler installs the patched `.gem` from the patch registry, and RubyGems compiles it like any registry gem. A gem the lock pins as precompiled platform gems (`x86_64-linux-gnu`) is installed from the patched platform gem the registry serves for that platform, with nothing to compile; it is skipped with `redirect_gem_platform_unsupported` only while the patch has no patched build for one of the locked platforms. |
| Vendored | A gem `Gemfile.lock` pins as precompiled platform gems (one entry per platform, such as `nokogiri (1.18.10-x86_64-linux-gnu)`) is vendored from prebuilt patched platform gems. The patch service builds one for each platform, and the vendored directory holds each of them unpacked (`<name>-<version>/<platform>/`), so Bundler loads the one for the platform it runs on and builds nothing. Every platform in the lock needs one. While the patch service has none for one of them the gem is skipped with `vendor_prebuilt_platform_pending`, which names the platforms that have none: the run does not fail, nothing is written, a patch that is already vendored stays in place, and a later run vendors the gem once every platform has one. A lock that also holds the plain `nokogiri (1.18.10)` entry of the `ruby` platform is refused with `platform_gem_unsupported`, and so is a lock written by a Bundler older than 2.3 (its `BUNDLED WITH`), the oldest version the layout is verified on. The vendored directory carries its own `.gitignore` and `.gitattributes`, so a project rule such as `*.so` or a Git LFS filter does not keep the prebuilt binaries out of the commit or change their bytes. Bundler cannot add a platform the vendored directory has no gem for: to add one later, revert the gem (`vendor --revert`), run `bundle lock --add-platform <platform>` and vendor again. A gem with a native extension that is locked for the `ruby` platform alone is refused (`native_extensions_unsupported`, or `platform_gem_unsupported` when the installed copy is a precompiled one): Bundler builds no extensions for path-sourced gems. Use hosted or agent mode for that gem. |
| Agent (`apply`) | The extension is rebuilt from the gem's source archive with the patch laid over it, using RubyGems' builder and the Ruby that owns the install, and the build is put where Ruby loads it: the extension directory of a gem RubyGems built, the prebuilt binary of a precompiled gem. |

`apply` takes the source gem (`<name>-<version>.gem`) from the gem home's `cache/` directory,
where RubyGems and Bundler keep it for a gem they built. For a precompiled gem, or a pruned cache,
it downloads the archive from rubygems.org and checks it against the sha256 the registry's index
records. Your `Gemfile.lock` never chooses where the archive comes from; a gem it resolves from
another source (a private gem server, a git source) is not downloaded. Before anything of the
archive is built, `apply` checks that it is the installed gem's own source: every file the two
share must be identical. With no usable archive (`--offline` and nothing cached, a private gem),
or when the build from it fails, a gem RubyGems built is rebuilt from its installed tree instead,
as in 5.1.0, and a precompiled gem is refused with `native_extensions_unsupported`: run `apply`
once with network access, or put the source gem in that `cache/` directory. If you install from a
mirror of rubygems.org, set `SOCKET_RUBYGEMS_URL` to it. The mirror must be reached over `https`
(plain `http` is accepted only for a mirror on the same machine, such as `http://localhost:9292`,
and such a request never goes through a proxy): the gem's build scripts run, so its archive and
checksum are not fetched over a connection someone else could rewrite. Credentials in the URL
are never printed.

JRuby is different. It installs a gem's `java` build (`nokogiri-1.18.10-java`), which runs jars
and has no C extension, so `apply` builds nothing there and needs no compiler. (A `java` gem that
does compile something when it is installed, such as jruby-launcher, is rebuilt like any other
gem with an extension.) Patches are written for the gem's `ruby` build, and on JRuby `apply`
takes from such a patch what is part of the `java` build:

- A file the patch changes is updated when the installed gem has it: the gem's Ruby code, and
  also a C source the `java` gem ships, though nothing on JRuby compiles it.
- A file that only a C build reads is skipped when the installed gem doesn't have it: a C
  source or build file, or anything under `ext/`, `patches/` or `ports/`. So is a new file of
  that kind, such as a new C source or a new `patches/libxml2/*.patch`.
- Every other file the patch changes must be there. A Ruby file that is missing from the
  installed gem is an error, as it is in any other gem: `apply` fails and changes nothing.

The patch then counts as applied: `apply --check` reports it in sync, `vex` attests it, and
`rollback` restores the files `apply` changed. When no file of a patch is part of the `java`
build (a patch to the libxml2 that nokogiri packs for its C extension), the vulnerable code is not
in that build at all. `apply` exits 0, changes nothing and prints a note saying so (a `skipped`
event with `not_in_platform_build` under `--json`). Nothing was patched, so `vex` says what is
true instead: the vulnerability is `not_affected` with the justification
`vulnerable_code_not_present`. `rollback` reports that there was nothing to restore.

The one exception is a patch that changes what the gem's jars are built from (a Java, Kotlin or
Scala source, or a Maven, Ant or Gradle build file) and doesn't bring the rebuilt jars. `apply`
can't rebuild a jar, so that patch is incomplete: `apply` writes the patch's files, leaves them
written, and exits 1 with an error that says the jars are not the patch's
(`native_extension_not_rebuilt`). Neither `apply --check` nor `vex` reports the gem as patched.
A patch that replaces a jar itself is different: the patched jar is what JRuby loads, so the
patch is applied and attested like any other, along with any source it changes beside the jar.

A patch written for the `java` build itself (its purl carries `?platform=java`) is applied whole,
like a patch for any other gem: every file it changes must be in the installed gem. When the
manifest has both that patch and the one for the gem's `ruby` build, only the `java` one belongs
to a JRuby install. `apply` doesn't apply the other one there, and `apply --check`, `vex` and
`rollback` don't look for it there either.

A gem that builds a library into its own directory and loads it from there (an FFI gem such as
scrypt or argon2, a Rakefile build such as digest-crc) is always rebuilt from its installed tree.
The libraries the gem's build makes there are removed first, as a fresh install has none of them,
so a build script that would take an existing library for current compiles the patched source.
The files the gem ships that its first build used up are put back from the source gem for the
build, so a build script that can only run once (argon2's renames a file it ships) runs again;
those the build leaves untouched are removed again afterwards. When `apply` has no source gem to
compare with, it can do neither: a build script that needs a file that is gone fails, and a build
that exits without changing any compiled code is not taken for one. Either way the package fails
with `native_extension_build_failed` instead of being reported as patched, and the gem is left as
it was.

Ruby files are never build inputs outside `ext/` and a build script's directory: a patch that only
changes `.rb` or `.rbs` files needs no compiler, wherever the gem keeps them.

A rebuild is only taken for a build of the patch when it read at least one of the files the
patch changes and left compiled code. How a gem builds depends on its configuration: nokogiri
installed with `--use-system-libraries` links the operating system's libxml2 and never opens the
copy it packs, so a patch that only adds a fix to that packed copy changes nothing there. A gem
whose build script downloads the binary it runs (passenger's agent) compiles nothing at all.
The patch is then incomplete, and `apply` says so instead of reporting a patch that is in no
compiled code. It writes the patch's files, leaves the compiled code as it was installed, and
exits 1 with `Error: Patch of <package> is incomplete: …` (`native_extension_not_rebuilt`):

- The patch's files stay written: its Ruby files are in effect, and a source the gem compiles
  later on its own is the patched one. Nothing is rolled back for you; `rollback` undoes it.
- `apply --check` reports the package as not in sync, and `vex` does not attest the patch.
- A gem installed in more than one place counts as patched only when no copy is incomplete.
- On a system-libraries install the library is the operating system's package, and updating
  that package is what fixes it.
- `scan --mode agent` and `get` exit 1 for such a patch as well, and keep it recorded.

A patch to the gem's own C sources is rebuilt as usual. On Linux the check asks the kernel which
files the build opened. Elsewhere it needs a filesystem that records file reads; on one that
does not (a `noatime` mount, Windows by default) the build is taken as it is.

A build can take many minutes. `apply` prints a line to stderr when one starts and another when
it ends (not under `--json` or `--silent`).

A gem RubyGems compiled is rebuilt with the build arguments RubyGems recorded when it was
installed. A precompiled gem is rebuilt with none: arguments Bundler recorded for it (a
`build.nokogiri --use-system-libraries` setting kept from before nokogiri shipped precompiled
gems) were never used to build it, and following them would replace the libraries the gem ships.

The build happens in a stage directory inside the gem home (`.socket-patch-build/`), which is
removed afterwards. A gem the build needs that the install lacks (a precompiled nokogiri has no
`mini_portile2`) is installed into that stage, never into your gem home. The installed gem is not
touched until the build has finished.

An agent-mode rebuild needs a compiler toolchain and the Ruby headers (`ruby-dev` /
`ruby-devel` on Linux distributions, the Xcode command line tools on macOS), the same
requirements as `gem install` for the ruby-platform gem. It takes as long as that install: about
a minute for nokogiri. A precompiled gem (`pg`, `nokogiri`, `ffi` and most others install that way)
was never built on your machine, so its rebuild is the first time the gem's own build dependencies
are needed: the libraries and headers it compiles against (`libpq-dev` for `pg`), which `bundle
install` did without. When the build fails, the installed gem is left as it was and the package
fails with `native_extension_build_failed`, showing the tail of the build output: the lines that
say what failed, without mkmf's list of configuration options or its pointer to an `mkmf.log`,
which is removed with the failed build. When it can't
rebuild at all (a Bundler git checkout, no matching Ruby, no source gem for a precompiled gem),
nothing is written and the package fails with `native_extensions_unsupported`.

The rebuild runs the gem's own build scripts (`extconf.rb`, `make`), as `gem install` did, and
only after the patch's files verified against the installed gem and against the source gem.
Nothing of the gem is run before that: `apply --dry-run` starts no Ruby, downloads nothing, and
reports that a rebuild is pending. Ruby and the build run without the Socket token in their
environment.

A tool that compiles the extension itself after `apply` (as the patches evaluation harness does)
passes `--no-gem-native-rebuild` (or `SOCKET_NO_GEM_NATIVE_REBUILD=1`): the sources are written
without a rebuild, with a `native_extension_not_rebuilt` warning, and `vex` does not attest them.

`apply` keeps the original compiled code in `.socket-patch-native-orig/` inside the gem
directory (the install-time build, a precompiled gem's prebuilt binary, and every file a rebuild
in the installed tree replaced there), so `rollback`
restores it byte for byte without recompiling, and records what it built in
`.socket-patch-native-build.json`. `vex` attests the patch only while that record matches the
installed binary: after `gem pristine` or a reinstall, run `apply` again.

A precompiled gem ships one binary for each Ruby version it supports, and `apply` rebuilds the one
for the Ruby it runs with, the way `gem install` builds a gem for the Ruby that installs it.
`vex` attests the patch from then on. If a second Ruby version uses the same gem home, run
`apply` with that Ruby as well: it rebuilds that version's binary beside the first, and
`rollback` restores both.

Interrupting `apply` during a rebuild (Ctrl-C, a cancelled CI job) stops the build with it. A
build from the source gem had not touched the installed gem yet, so the gem is as it was; the
stage directory it leaves is removed by the next `apply` or `rollback`. A rebuild from the
installed tree leaves the gem with its patched sources and no finished extension until Socket
Patch runs again: `apply` puts the previous build back and completes the rebuild, and `rollback`
restores the original sources and build.

## Bazel workspaces: RubyGems

rules_ruby's `ruby.bundle_fetch` tag (in `MODULE.bazel`) downloads every gem of its
`gemfile_lock` with Bazel's downloader. Its `gem_checksums` names a sha256 per gem, under
`<name>-<version>` (the words of the gem's line in the lock, so `<version>-<platform>` for a
platform build), and Bazel holds a gem the dict names to it. The lock's `CHECKSUMS` section is
Bundler's: it holds the downloaded files to it afterwards, in the `bundle install` step of the
build. A build of such a hub prints the dict to add, so many workspaces have one that names
every gem.

Hosted mode points a gem at the patch registry in `Gemfile` and `Gemfile.lock` and records the
sha256 of the patched gem in `CHECKSUMS`. It does not edit `MODULE.bazel`. An entry that still
holds the sha256 of the upstream gem then fails the next build: Bazel takes the upstream gem
from its repository cache and Bundler refuses it (`Bundler found mismatched checksums`), or,
with an empty cache, Bazel refuses the patched gem (`Checksum was ... but wanted ...`). Where
the lock has no `CHECKSUMS` section the build can also pass, on the upstream gem.

So `scan --mode hosted` and `get --mode hosted` read the calls, and write nothing for a gem
that a call which may read the project's lock holds to another sha256 than the patched gem
has: no `source:` option, no change to the lock. The gem is `skipped` (`redirect_unconfirmed`),
the run exits 0 as for any other gem hosted mode does not pin, the other gems of the run are
rewritten, and one warning per gem (`redirect_bazel_gem_checksums_pinned`) names the call by
its file and line, the entry, and the way on; where more than one call holds the gem, it
names the others too:

- **Change the entry** to the sha256 the warning gives, which is the one of the patched gem,
  and run the command again. It then rewrites the two files, and the next build takes the
  patched gem, which Bazel holds to that sha256.
- **Or delete the gem from the dict**, where the lock has a `CHECKSUMS` section: Bundler then
  holds the gem to the sha256 of that section, as in a workspace without `gem_checksums`. The
  warning does not offer this for a lock without the section, where nothing would hold the
  gem to a sha256.

A test does both on Bazel 9.3.2, 8.8.2 and 7.7.2 with rules_ruby 1.0.0-rc2. The build after
either changes no file of the checkout: a `MODULE.bazel.lock` that is there stays as it is.

socket-patch never edits the call, in `rollback` and `remove` either. After one of them an
entry you changed still holds the sha256 of the patched gem, and the build fails on it until
the old value is back (the known problem above). A gem you deleted from the dict needs nothing.
With `--vex`, a run that leaves its only gem as it is has nothing to attest and exits 1
(`manifest_not_found`), like any run that pins nothing.

What is read, and what is not:

- **Read from the checkout:** the root `MODULE.bazel` and the files it includes, under
  whatever name the file gives the `ruby` extension of `rules_ruby`. Nothing is evaluated and
  no Bazel is run.
- **Nothing changes** for a project in no Bazel workspace (the rule is under
  [Bazel workspaces: `.bazelignore`](#bazel-workspaces-bazelignore)), for one whose lock no
  call may read, beside a call without `gem_checksums`, and for a gem that the dict does not
  name or holds to the sha256 of the patched gem already, in upper or lower case, or to an
  empty string, for which rules_ruby gives Bazel no sha256. The Bundler pair is the one
  hosted mode rewrites: `gems.locked` where the project has a `gems.rb`.
- **A call that is not written out stands against the gem all the same**, because a build
  that fails outranks a patch that is missed and explained. That is a call in a comprehension
  or a condition, which may run; one whose `gemfile_lock` is not a label in a plain string,
  which may be this lock; and a `gem_checksums` that is a constant, an expression or a `**`
  argument, which may name the gem. For the last the warning says to write the dict out in
  the call. Two shapes built the patched gem before and are left alone now: a constant
  that does not name the gem, and a second call on the same lock that holds the gem while
  the targets you build use the hub of the call without the entry. Every call that may read
  the lock counts, whichever hub your targets use.
- **A part of `MODULE.bazel` that socket-patch cannot read** (an `include` it cannot follow,
  a `bazel_dep` whose name is an expression) can hide a call and changes nothing else. The
  calls that are read decide, and where none of them may read the lock hosted mode writes as
  it does without Bazel. Withholding there instead would take hosted mode from every gem of
  such a workspace, also where no rules_ruby hub reads the lock.
- **`rb_bundle_fetch` in a `WORKSPACE` file** (`WORKSPACE.bzlmod`, `WORKSPACE.bazel`) counts
  like the tag unless a `ruby.bundle_fetch` of the module files names the lock in a plain
  string. Bazel 7 reads that file, Bazel 8 when it is told to and Bazel 9 never, and
  socket-patch does not know which Bazel runs, so the call counts on each. In that file the
  name that `workspace(name = "shop")` gives is the main repository, so
  `@shop//:Gemfile.lock` is the root's lock, and under a name that is not written out any
  repository may be. Beside a tag that names the lock the file is taken for a leftover of a
  migration and not looked at. No test builds such a hub; the failing build was measured by
  hand on Bazel 7.7.2 with rules_ruby 0.21.1.
- **Not seen:** a call of another Bazel module; a macro of a `.bzl` file that makes the call;
  `rb_bundle_fetch` loaded under another name; an `rb_bundle_fetch` of the `WORKSPACE` file
  beside a tag that names the lock, where Bazel 7 reads both and your targets use the hub of
  that file; a label that spells the lock's name in another case; and what the command line
  or an rc file tells Bazel. Hosted mode writes in each as it does without Bazel.
- **Not covered:** a project below the root of a workspace that is in no git checkout, or
  that is a git checkout of its own (a submodule), because a workspace is looked for only up
  to the root of the project's checkout; and a project whose directory the call names
  through a symbolic link, because the lock is compared by the path the directory really
  has. And the in-memory engine (a Socket-opened pull request) reads the calls only where
  the project's directory is the Bazel root, and only from workspace files that are files of
  the repository themselves: for a project below the root it is not given the files of the
  workspace, and a `MODULE.bazel` or `WORKSPACE` that is a symbolic link is not read.
- A pin that an earlier release wrote beside such an entry stays in the two files, and the
  build keeps failing on it, or keeps the upstream gem. The scan now names the entry in a
  warning that says the pin is left as it is, and still counts the gem as hosted, because
  the pin is in the lock; `--vex` attests it for the same reason, which is not true of that
  build. Change the entry and run the scan again, or take the pin out with
  `socket-patch rollback pkg:gem/<name>@<version>`, as the warning says (a bare `rollback`
  would unwind every patch of the project).

## Bazel workspaces: VEX

`vex` and `--vex` read what socket-patch wrote and what the project's own package manager
installed. In a Bazel workspace (the Bazel root of the section on `.bazelignore` above) they
also read `MODULE.bazel` and the files it includes, for the calls of three rulesets that hand
a lock to Bazel:

| Call | Files it names |
|---|---|
| aspect_rules_js `npm.npm_translate_lock` | `pnpm_lock` |
| rules_python `pip.parse` | `requirements_lock`, `requirements_by_platform`, `requirements_darwin`, `requirements_linux`, `requirements_windows` |
| rules_ruby `ruby.bundle_fetch` | `gemfile_lock`, `gemfile` |

Each of them builds a package from what those files name, in a repository of Bazel's own,
and never from `node_modules`, a virtualenv or a gem home. So two kinds of patch are in no
build of Bazel's, and the document says of their package that it is `affected`, not that it
is patched:

- **A patch in the installed copy** (agent mode) of an npm, PyPI or RubyGems package, when
  such a call names the project's own lock and that lock lists the package at that version
  without naming the patch. The project's own lock is the one in the project's directory, or
  the lock of a pnpm workspace above it that names that directory among its `importers`.
  Measured for rules_js 3.6.0 on Bazel 9.3.2, 8.8.2 and 7.7.2: the build prints the
  unpatched package before `scan --mode agent` and after it.
- **A PyPI patch committed under `.socket/vendor`** (vendored mode), when such a call names
  the file that points at the copy. rules_python 2.5.0-rc4 takes the path of the line for
  the name of a project, and the build of everything the hub serves fails (same three
  releases). A vendored npm tarball is built by rules_js and keeps its statement. So does a
  vendored gem, for another reason: rules_ruby builds one only when the call lists every
  file of the copy among its `srcs`, which is not read, so nothing is said of it.
  Vendored mode declines both by default where the hub reads the file
  ([Bazel workspaces: PyPI and RubyGems vendored mode](#bazel-workspaces-pypi-and-rubygems-vendored-mode)),
  so this is the state of a project vendored with `--allow-vendored-in-bazel` or by an
  earlier release. A wheel that vendored mode committed as a
  [download cache](#bazel-workspaces-pypi-vendored-mode-as-a-download-cache) is not such a
  copy: the file the hub reads names it by its URL and sha256, as a hosted pin does, and the
  package keeps its `not_affected` statement.

Each advisory of such a patch gets a statement of the package's own with the status
`affected`. It names that package alone under the product, and its `action_statement` says
what Bazel builds the package from and what to run so that the build holds the patch. It
has no `justification` and no `impact_statement`. Packages that share an advisory are not
merged into one such statement, so each action statement is about one package; the
`not_affected` statement of the advisory, for the packages that are patched, comes first:

```json
{
  "vulnerability": { "name": "GHSA-xxxx-xxxx-xxxx", "aliases": ["CVE-2024-0001"] },
  "timestamp": "2026-11-19T15:14:47Z",
  "products": [
    { "@id": "pkg:npm/shop@1.0.0", "subcomponents": [{ "@id": "pkg:npm/left-pad@1.3.0" }] }
  ],
  "status": "affected",
  "action_statement": "Bazel builds this package from pnpm-lock.yaml (`npm.npm_translate_lock`, MODULE.bazel:6), which does not name Socket patch 7a11e000-...: the patch is only in the installed copy. Run `socket-patch scan --mode hosted` in the directory of that lock to pin the patch there. If what you ship is the installed tree and not what Bazel builds, pass `--no-bazel` (`--vex-no-bazel` on scan, apply and vendor)."
}
```

The last sentence is for a repository that ships the installed tree (see `--no-bazel` below).
For a vendored PyPI package the action statement does not have it, since the installed tree is
not the patched one there either:

```
Bazel builds no package from the line of requirements.txt that points at the copy of Socket patch 7a11e000-... under .socket/vendor (`pip.parse`, MODULE.bazel:15): the build fails, or takes the registry's package. Run `socket-patch vendor --revert`, then `socket-patch scan --mode hosted`.
```

Both ways out are tested on real Bazel: after the hosted scan the build prints the patched
package and the document says `not_affected`.

A run tells a person the same in a warning (`vex_bazel_not_in_build`, one per package):

```
Warning: pkg:npm/left-pad@1.3.0: the VEX document says affected. Bazel builds this package from pnpm-lock.yaml (`npm.npm_translate_lock`, MODULE.bazel:6), which does not name Socket patch 7a11e000-...: the patch is only in the installed copy. Run `socket-patch scan --mode hosted` in the directory of that lock to pin the patch there. If what you ship is the installed tree and not what Bazel builds, pass `--no-bazel` (`--vex-no-bazel` on scan, apply and vendor).
```

Nothing is left out of the document for this reason, so the document is always written:
`vex` exits 0 with it, also when every statement says `affected`, and `scan --vex`,
`apply --vex` and `vendor --vex` write it and keep their exit code. No run reports such a
package as patched. `vex --json` reports each `affected` statement as a `skipped` event with
`errorCode: "vex_bazel_not_in_build"` and `details.status: "affected"`, beside the
`verified` events of the `not_affected` ones. `summary.verified` counts only those, and the
envelope's `status` is `partialFailure`, as for every run that leaves a patch unattested. A
command run with `--vex` keeps its own status, and the `vex` object of its envelope says
how many statements were written (`statements`) and how many of them say `affected`
(`affected`, left out when none does), with the warning in `vex.warnings`. The line a
person reads counts them too: `Wrote OpenVEX document with 2 statements (1 affected) to
out.json`. `--no-verify` changes none of this.

When a hub reads the project's own lock, the document describes what Bazel builds from that
lock. A repository that ships what its package manager installed (a container image built
with `pnpm install` and `socket-patch apply`, say) and keeps the hub for something else, such
as its tests, says so with `--no-bazel` on `vex`, with `--vex-no-bazel` on `scan`, `apply` and
`vendor`, or with `SOCKET_VEX_NO_BAZEL=1` in the environment. The Bazel workspace is then not
read: the document describes the installed tree, and it, the warnings, the exit code and
every line of the run are those of the same checkout without its Bazel files. The option
changes nothing outside a Bazel workspace.

Nothing changes where the files do not show such a call: outside a Bazel workspace, in a
`--global` run, for a hosted pin, for a project whose own lock no call names, and wherever
the workspace is not read with certainty: the statement is then `not_affected`, as without
Bazel. A lock elsewhere that lists the same package is the
lock of another project and decides nothing for this one: in a directory beside the project,
below it, or above it without naming it among the importers of a pnpm workspace (a pnpm app
beside a Java build; a project with a lock of its own under a root whose lock a hub reads; a
Python or Ruby project below the directory of the file a hub reads). The workspace is not
read with certainty when a module file is missing, cannot be read or holds a statement the
reader does not follow (a `load`, an `if`, a hub proxy handed to anything but `use_repo` or
`inject_repo`); when the call gives its file as anything but a plain string label of the
main repository, passes `*` or `**`, or is a `pip.parse` with `uv_lock`, whose packages
rules_python 2.2.0 and later can take from that file; when the lock cannot be read, is
larger than 64 MiB, or is a link that leads out of the Bazel root (Bazel follows such a
link; socket-patch reads no file outside the root); and when a `WORKSPACE`,
`WORKSPACE.bazel` or `WORKSPACE.bzlmod` at the root holds more than a `workspace(...)` call.
Bazel 7 reads that file beside `MODULE.bazel`, and its calls are not read yet; Bazel 9 never
reads it, so a workspace on Bazel 9 that still has such a file keeps its `not_affected`
statements although nothing builds the patched copy. A workspace without a `MODULE.bazel`
is not read at all. In each of these the document is the one of a
project without Bazel. Flags outside the committed files (`--override_repository`, an rc
file) and BUILD files are not read either.

Three more things change no statement. A call counts only when it is a statement of its own,
which Bazel runs once: one in a comprehension, behind an `and`, in a conditional or in the
arguments of another call may never run. Of a pnpm lock the project documents are read: a
package that only the document pnpm 11 keeps for its own configuration lists is not one
rules_js links. And a patch whose record names no advisory gets no statement from any run,
so it is not looked at here: a run over such a patch alone ends as it does without Bazel.

The document and the build are tested to agree on real Bazel 9.3.2, 8.8.2 and
7.7.2 for four shapes, all under Bzlmod: Go through gazelle's
`go_deps.from_file(go_mod = "//:go.mod")` with
`go_deps.config(check_direct_dependencies = "error")` and the module required directly in
`go.mod` (hosted and vendored mode), npm through
aspect_rules_js's `npm.npm_translate_lock(pnpm_lock = "//:pnpm-lock.yaml")` (hosted and
vendored), PyPI through rules_python's `pip.parse(requirements_lock = "//:requirements.txt")`
(hosted, and vendored as a download cache), and RubyGems through rules_ruby's
`ruby.bundle_fetch(gemfile_lock = "//:Gemfile.lock")` without `gem_checksums` (hosted). There
the build prints the patched package, and the document of the run (`--vex`), of `vex` and of
`vex --no-verify` is one `not_affected` statement that names the package and the patch; the
first two are the same in a checkout with the same files that Bazel has not built in, and
after the undo `vex` writes no document. For PyPI on Bazel 8.5 and later a hosted scan leaves
`MODULE.bazel.lock` stale, so the document is there before a frozen build passes: a build with
`--lockfile_mode=error` fails until a build that may update the lock has run, and the updated
lock has to be committed.

Three more flows hold the document of `vex` to their patched build on the same releases,
after a hosted scan: Cargo through rules_rust's `crate.from_cargo` with `cargo_config` (and
after a vendored scan), Composer through a rule or a genrule of the project's own that runs
`composer install` from the lock, and NuGet through rules_csharp's `nuget.from_lock` with
`nuget_config`, on a machine whose NuGet folder does not hold the package. For these, and
for a Maven entry in `MODULE.bazel`,
[Bazel workspaces: what is supported](#bazel-workspaces-what-is-supported) says what the
document does not show.

For no other Bazel shape do these pages say that the document and the build agree, and in
these the document is still wrong (`not_affected` while Bazel builds the unpatched package, or while
the build is broken):

- **Agent mode beside rules_js, rules_python or rules_ruby**, wherever the statement does
  not say `affected` above. `npm_translate_lock` is given an `npm_package_lock` or a
  `yarn_lock`, which are not read, or `pip.parse` a `uv_lock`. The hub reads a lock above
  the project that does not name the project among its importers. The hub reads a lock
  below the directory the command runs in: a run at the repository root while the hub reads
  `web/pnpm-lock.yaml`. A Python or Ruby project lies below the directory of the file the
  hub reads. The call is not a statement of its own, or passes `*` or `**`. A `WORKSPACE`
  file at the root defines something, or the workspace has no `MODULE.bazel`. Measured for
  rules_js, which builds from the lock and never reads the patched `node_modules`.
- **Vendored mode for PyPI**, where the workspace is not read with certainty: a
  `WORKSPACE` file that defines something, no `MODULE.bazel`, a call that is not a statement
  of its own, a file that is not given as a plain string label. And where the line that
  points at the copy is in a requirements file that the file the call names brings in with
  `-r`. Measured for PyPI, where the build fails.
- **Vendored mode for RubyGems** beside `ruby.bundle_fetch`. rules_ruby 1.0.0-rc2 runs
  `bundle install` in a repository that holds the Gemfile, its lock and the files the call
  lists as `srcs`, so the path of the copy does not exist there unless every file of the copy
  is listed. Measured on the three releases: the build fails, and the statement still says
  `not_affected`. Vendored mode declines such a gem by default, so this is the state of a
  project vendored with `--allow-vendored-in-bazel` or by an earlier release.
- **A vendored package whose own files the hub does not read**, while the lock the hub does
  read still lists the registry's package: a uv or Poetry project vendored through
  `pyproject.toml` and its lock while `pip.parse` reads a requirements file exported before;
  an npm package vendored through `package-lock.json` while `npm_translate_lock` reads a
  `pnpm-lock.yaml`. Bazel builds the registry's package. The check of an installed copy is
  not applied to them yet: rules_js can rewrite the pnpm lock from the other files under
  `update_pnpm_lock`, `npm_package_lock` or `yarn_lock`, and rules_python can take the
  packages from `uv_lock`, so the lock a call names does not always decide.
- **Hosted mode for PyPI**, when a `pip.parse` or `pip_parse` takes the requirements of the
  build's platform from another file than the one socket-patch rewrote.
- **Go** under a `go_repository` rule of a `WORKSPACE`, in hosted and vendored mode; and
  under `go_deps` when another Bazel module of the build requires a higher version of the
  patched module, because gazelle then builds that version and drops the replacement.

Do not publish a document for an artifact that Bazel built outside the shapes listed above
as tested. A project that Bazel does not build is not concerned: beside a Bazel workspace
whose files name none of its locks, `vex` says what it says without Bazel.

## Supported platforms

Prebuilt binaries are published for:

| Platform | Architecture |
|----------|-------------|
| macOS | ARM64 (Apple Silicon), x86_64 (Intel) |
| Linux | x86_64, ARM64, 32-bit ARM hard-float (`arm-unknown-linux-gnueabihf` / `-musleabihf`), i686 |
| Windows | x86_64, ARM64, i686 |
| Android | ARM64 |

## Existing project patches

Socket Patch treats declared project patches as a separate source of ownership.
`scan` and `apply` skip their packages and report `user_patch_conflict`;
explicit `get` and `vendor` refuse the conflict before patching. Use
`--allow-patch-conflicts` only after reviewing how the fixes interact. This flag
permits an attempt; it does not merge diffs or bypass unsupported backend cases.
Installed file content that matches neither the original nor Socket-patched hash
also fails by default. See the [CLI contract](../crates/socket-patch-cli/CLI_CONTRACT.md#existing-project-patches)
for exact matching rules, diagnostics and detection limits.

The protection applies before any comparison of changed filenames. Two fixes can
interact even when their diffs do not overlap, and a package manager may reapply
its own diff after Socket changes the dependency source.

| Mechanism | Research and interaction |
| --- | --- |
| pnpm | [`pnpm patch`](https://pnpm.io/cli/patch) records `patchedDependencies`; selectors can be exact versions, ranges, or bare names. Configuration moved into [`pnpm-workspace.yaml`](https://pnpm.io/settings). pnpm's [selector grouping](https://github.com/pnpm/pnpm/blob/v10.20.0/patching/config/src/groupPatchedDependencies.ts) treats `*` as all versions, including prereleases. Both declarations and lock markers matter, including before installation. |
| Yarn | [`patch:`](https://yarnpkg.com/protocol/patch) changes package source at fetch time. [`yarn patch`](https://yarnpkg.com/features/patching) keeps the diff separately; replacing a locator is not a merge of that diff with Socket's artifact. Yarn builtin compatibility patches are distinguished from user patch paths. |
| `patch-package` | Its [documented workflow](https://github.com/ds300/patch-package) applies diffs after installation, supports workspace-local setups and `--patch-dir`. Its [filename parser](https://github.com/ds300/patch-package/blob/master/src/PackageDetails.ts) identifies scoped/nested targets, patch sequences and dev-only patches. Looking only for a dependency on `patch-package` is insufficient. |
| npm / Bun | [npm patch](https://docs.npmjs.com/cli/v12/commands/npm-patch/) and [Bun patch](https://bun.sh/docs/pm/cli/patch) persist project diffs. Socket's pre-existing native npm/Bun backend refusals remain in force after consent; a successful source rewrite alone does not establish that the user's diff was preserved. |
| Composer | [Composer Patches](https://docs.cweagans.net/composer-patches/usage/defining-patches/) accepts inline and external definitions. [Configuration](https://docs.cweagans.net/composer-patches/usage/configuration/) can relocate that file, and dependencies can provide patches. [`patches.lock.json`](https://docs.cweagans.net/composer-patches/api/patches-lock-json/) is additional read-only evidence. |
| Cargo / Go | Cargo's [`[patch]`, `[replace]`, and `paths`](https://doc.rust-lang.org/cargo/reference/overriding-dependencies.html) and Go's [`replace`](https://go.dev/ref/mod#go-mod-file-replace) can select a user fork or directory. These source choices must not be treated as pristine registry copies. Socket-owned wiring is distinguished from user replacements. |

Python local/VCS sources, Ruby path/git dependencies, JVM dependency substitutions,
NuGet source choices, and custom build hooks do not share a portable diff registry.
Their existing source/layout restrictions still apply; the consent detector does
not claim to interpret every possible plugin, script or external patch pipeline.
Unknown edits in a file Socket would replace are protected by the default hash
mismatch refusal. A separate, untouched file with an unrecorded local fix cannot
be detected by that hash check.

Patch declarations and diffs remain the user's files. Consent is not persisted in
`socket.yml`, the manifest, or an environment variable; an automated hook must
specify it deliberately on each invocation if the project intends to combine
patches. Review the resulting installation and run the project's own tests.
