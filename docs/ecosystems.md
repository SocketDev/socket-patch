# Ecosystem & platform support

This is the detailed support matrix for `socket-patch`: which package ecosystems work
with which [patch mode](../README.md#patch-modes), the per-ecosystem caveats, and
the platforms the binary ships for.

For what the three modes *are* and how to choose between them, see
[Patch modes](../README.md#patch-modes) in the README.

## Mode × ecosystem matrix

The backticked slug in each row is the value `-e`/`--ecosystems` accepts (e.g.
`--ecosystems npm,pypi,golang`).

| Ecosystem | agent (`--mode agent`) | vendored (`--mode vendored`) | hosted (`--mode hosted`) |
|-----------|------------------------|------------------------------|--------------------------|
| npm (`npm`) — pnpm / yarn / berry / bun / vlt | ✅ any install layout, vlt's `node_modules/.vlt` store included (every store copy, copy-on-write) | ✅ seven lockfile flavors: package-lock, yarn classic, yarn berry (node-modules linker; PnP refused), pnpm v9, pnpm legacy v5.4/v6.0 (`pnpm 7/8` — frozen installs are path-bound because those majors absolutize `file:` override specifiers; moved checkouts run one `pnpm install --offline --no-frozen-lockfile`, surfaced as `vendor_pnpm_legacy_absolute_specifier`), bun text `bun.lock` lockfileVersion 0/1/2 and native binary `bun.lockb` revisions 1/2/3 (binary locks stay binary; text workspace vendoring requires lockfileVersion 2 — see [Bun compatibility](testing/bun-compatibility.md)), vlt `vlt-lock.json` lockfileVersion 0/1 (patched package directories for direct dependencies of the root or a workspace member; transitive targets refused — see [vlt notes](#npm-vlt-notes)). Rush monorepos refused (`vendor_rush_unsupported`) — see [Rush notes](#npm-rush-monorepos) | ✅ package-lock / npm-shrinkwrap, pnpm-lock.yaml and legacy shrinkwrap.yaml (pnpm majors 1–12; block and flow resolutions), yarn classic, yarn berry, bun, vlt (`vlt-lock.json` without `lockfileVersion`, 0 or 1) — pnpm, berry, bun and vlt carry constraints, see [npm hosted-mode notes](#npm-hosted-mode-notes) and [vlt notes](#npm-vlt-notes) |
| PyPI (`pypi`) — uv / poetry / pdm / pipenv / pip | ✅ in place | ✅ uv project/script locks, PEP 751 `pylock.toml` / `pylock.<name>.toml`, poetry, pdm, pipenv (Pipenv 2018 or later — every `Pipfile.lock` category is rewired, lock-only checkouts included; Pipenv 2023+ does not hash-check local wheels — `vendor_integrity_unverified`; a venv still holding the upstream release is reported as `pypi_pipenv_stale_install`; see [Pipenv compatibility](testing/pipenv-compatibility.md)), and requirements.txt. Native uv vendoring requires uv ≥ 0.2.35 (the `[[package]]` lock grammar); hosted mode covers native `uv.lock` from uv 0.1.45 (the first release whose `uv lock` writes one) and requirements from uv 0.0.5; see [uv compatibility](testing/uv-compatibility.md). | ✅ requirements.txt including hash continuations, uv project/script locks, and PEP 751 locks. Version/source ambiguity is refused; see [uv compatibility](testing/uv-compatibility.md). Poetry 1.x and 2.x locks are supported; Poetry 0.x ignores URL sources and is refused. See [Poetry compatibility](testing/poetry-compatibility.md). Pipenv `Pipfile.lock` (pipfile-spec 6 — Pipenv 7 and later; `path` references for 7–11, `file` from 2018; lock-only checkouts and Pipenv's out-of-tree venv are discovered; a warm venv that Pipenv will not reinstall over warns `redirect_pypi_stale_install`; see [Pipenv compatibility](testing/pipenv-compatibility.md)). `pdm.lock` is supported for the lock formats PDM 0.12–1.4 and 2.8.1+ write (`lock_version` 2 / 4.3–4.5.1); the identity-losing 3.1 / 4.0–4.2 formats (PDM 1.8–2.7) are refused. PDM 2.8.0 writes an indistinguishable `4.3` lock but shares that identity-loss bug, so a rewritten 2.8.0 lock crashes `pdm sync` — upgrade to ≥ 2.8.1. See [PDM compatibility](testing/pdm-compatibility.md). |
| Cargo (`cargo`) | ✅ in-place + `.cargo-checksum.json` rewrite (shared registry-cache caveat — see [Cargo: shared registry cache](#cargo-shared-registry-cache)) | ✅ `[patch.crates-io]` path entry in the root `Cargo.toml` (v5; per-version Socket keys; pre-v5 `.cargo/config*` wiring migrates on re-run) | ✅ per-patch sparse registry (`[registries.socket-patch-<uuid>]` + Cargo.lock source/checksum); direct dependencies only — a crate another dependency also pulls in is refused, use `--mode vendored`; a crate the user overrides with `[patch]` (path, git or another registry) is refused too, the override is left alone; with no `Cargo.lock` the graph is unknown, so only a project whose sole dependency is the patched crate is redirected |
| RubyGems (`gem`) | ✅ in place | ✅ Gemfile + Gemfile.lock path pair (`Gemfile` spelling only — a `gems.rb` twin, which bundler ≥ 2 loads instead, or a `BUNDLE_GEMFILE`-configured manifest makes vendoring refuse with `gemfile_not_loaded` before any write) | ✅ per-dep `source` block — edits `gems.rb` + `gems.locked` or `Gemfile` + `Gemfile.lock`, whichever the project holds (a `Gemfile` + `gems.rb` twin is refused with `redirect_gem_twin_manifest_ambiguous`: bundler 1.x loads the `Gemfile`, bundler ≥ 2 loads `gems.rb`, and nothing in the project says which bundler installs it; bundler 4's `BUNDLE_LOCKFILE` (environment, app config or global config) naming any other lock is refused with `redirect_gem_bundle_lockfile_unsupported`, as is vendoring with `gemfile_not_loaded`; spellings that diverge beyond Socket's own edits fail closed with `redirect_gem_gemfile_spellings_diverge`; `BUNDLE_GEMFILE` from `.bundle/config` (which outranks the environment, as in bundler), the environment, or the global `~/.bundle/config` / `$BUNDLE_USER_CONFIG` (lowest, as in bundler) is followed when it names the project's `Gemfile` / `gems.rb`, and any other configured manifest is refused with `redirect_gem_bundle_gemfile_unsupported`); a Bundler all-source, exact-source or hostname mirror in app config or the scan environment can capture the patch registry, so the redirect is refused with `redirect_gem_mirror_overrides_source` without printing mirror URLs (scope mirrors to `mirror.https://rubygems.org`; user-global config and mirrors set only in a later install environment are not inspected); the `CHECKSUMS` pin needs bundler ≥ 2.6 (older locks get a `redirect_gem_no_checksums_section` warning); a stale pre-redirect materialization that `bundle install` would reuse instead of refetching is flagged `redirect_gem_stale_install` with a prescriptive remedy (see CLI_CONTRACT.md's "Gem stale-install guard") |
| Go (`golang`) | ✅ `go.mod` `replace` → `.socket/go-patches/` — see [Go: directory replaces and go.sum](#go-directory-replaces-and-gosum) | ✅ `replace` → the committed vendor tree | ✅ (free tier) fork-style `replace` → `patch.socket.dev/gopatch/<uuid>` + committed `go.sum` pin; see [Go notes](#go-directory-replaces-and-gosum). Paid hosted patches are unsupported; `redirect_golang_unsupported` names the vendored remedy |
| Maven (`maven`) — Maven and Gradle | ✅ in place in every copy the build consumes: each `~/.m2` copy it reads and each Gradle `files-2.1` copy; `~/.m2` `.sha1`/`.md5` sidecars are rewritten, Gradle copies get advisories; jar-member records swap in the patch service's whole jar — prefer vendored / hosted, see [Maven & NuGet caveats](#maven--nuget-caveats) and [Gradle](#gradle) | ✅ suffixed Maven repository (`<version>-socket.<hex8>` pin + `.mvn/maven.config` + fallback file repository) for every pom root, single-module or reactor, or Gradle 6.8+ same-GAV repository with settings wiring and SHA-256 checks (a root with both `pom.xml` and a Gradle build wires both); see [JVM vendoring](design/maven-vendoring.md) and [Gradle](#gradle) | ✅ fail-closed by a Socket-only `<version>-socket.<hex8>` suffix: pom projects get a pinned `<version>` (`${property}` versions are refused); Gradle 6.8+ builds get an owned settings script, lock-entry rewrites and a resolution tripwire — see [Maven & NuGet caveats](#maven--nuget-caveats) and [Gradle](#gradle) |
| sbt / Mill / scala-cli (`maven`) | ✅ Coursier caches (sbt 1.3+, sbt 2, Mill, scala-cli) and Ivy caches (sbt 0.13–1.2, `useCoursier := false`) patched in place, Coursier checksum sidecars resynced — see [Scala build tools](#scala-build-tools-sbt-mill-scala-cli) | ✅ sbt 0.13.18+: generated `socket-patch-vendor.sbt` over the committed suffixed `.socket/vendor/maven2` tree; scala-cli directory builds: owned `socket-patch.scala` + same-GAV `.socket/vendor/coursier` tree (Linux / macOS); Mill: not wired (agent or hosted guidance) | ✅ sbt 0.13.18+: one generated `socket-patch.sbt`, gated on sbt's own `sbt update` records; Mill / scala-cli: paste-able snippets only (`redirect_mill_manual_snippet`, `redirect_scala_cli_manual_snippet`) |
| NuGet (`nuget`) | ✅ in-place patching deletes `.nupkg.metadata` and advises on the `.nupkg.sha512` tamper-evidence sidecar — prefer vendored / hosted, see [Maven & NuGet caveats](#maven--nuget-caveats) | ✅ committed folder feed + `packageSourceMapping` + `packages.lock.json` contentHash pin | ✅ `nuget.config` source + source-mapping, `packages.lock.json` contentHash rewrite. See the locked-mode note in [Maven & NuGet caveats](#maven--nuget-caveats) |
| Composer (`composer`) | ✅ in place (`vendor/`) | ✅ `composer.lock` `dist: path` rewrite | ✅ `composer.lock` dist url + shasum rewrite; the entry's `source` and `dist.mirrors` are removed. See [composer-compatibility.md](testing/composer-compatibility.md) |
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
  a copy under that name) and re-run. npm 12 defaults `allow-remote=none` and refuses the
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
- **pnpm** — hosted rewriting supports legacy `shrinkwrap.yaml` (pnpm 1/2),
  lockfileVersion 5.x (pnpm 3–7), 6.0 (pnpm 8), and 9.0 (pnpm 9–12).
  Early pnpm 1 locks with shrinkwrapVersion 3 and no positive minor version
  are refused because those installers discard hosted URLs; the tested
  pnpm 1 floor is 1.43.1. Upgrade and regenerate that lock, or use agent mode.
  Block and flow resolutions, scoped names, aliases, nested peer contexts,
  workspaces, nested Rush locks, and LF/CRLF line endings are handled. Every
  matching package instance is rewritten; an unsupported instance prevents
  confirming that dependency across the lockfile set. Rollback preserves the
  original resolution fragments.
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
  For 9.0 root or member locks, the CLI configures `trustLockfile: true` in
  the root `pnpm-workspace.yaml` unless opted out with `--no-trust-lockfile-config` or
  explicitly disabled by the project. pnpm >=11 needs this for hosted URLs.
  This skips registry re-verification for the whole lock; tarball integrity
  remains enforced. pnpm <=10 does not need the setting. A project with no
  `pnpm-workspace.yaml` that pins pnpm 9.0–10.4 (`packageManager`,
  `devEngines`, `engines.pnpm`, or the pnpm that last installed
  `node_modules`) gets no file: there a root-only workspace makes
  `pnpm add <pkg>` fail with `ERR_PNPM_ADDING_TO_ROOT`. Re-run the scan after
  upgrading to pnpm >=11. When no pin says which pnpm runs, the file is
  created, and pnpm 9.0–10.4 then need `pnpm add -w <pkg>`. Vendored mode
  follows the same rule for its `overrides:` mirror.
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
  for example with `yarn add`, then re-run). When every descriptor is already
  locked, the entry's dependency sub-maps are rewritten to match
  (`redirect_yarn_classic_dep_manifest_rewritten`). Vendored mode refuses the
  same case with `vendor_dep_manifest_unlocked`. If the download, the check or
  the `package.json` read fails, the patch is skipped as
  `npm_tarball_unavailable`. A project that sets `yarn-offline-mirror`
  is refused with `redirect_yarn_classic_offline_mirror`. The mirror is
  resolved the way yarn 1 resolves it: the project's `.yarnrc` / `.npmrc`,
  the user's (`~/.yarnrc`, which `yarn config set` writes, and `~/.npmrc`),
  `<prefix>/etc/yarnrc` / `npmrc`, every ancestor directory's, and the
  `YARN_*` / `npm_config_*` environment variables. A file saved with a UTF-8
  BOM counts too, and `false` in a higher-precedence layer turns the mirror
  off. Yarn looks mirror tarballs up by
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
  `.yarnrc.yml`'s `compressionLevel` must stay 0. The node-modules linker
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
- **yarn classic and yarn 2+** — installing with yarn 2+ (berry) migrates a classic (v1)
  `yarn.lock` and re-resolves every entry from the registry, dropping hosted pins and
  vendored wiring alike, so the packages install unpatched. A run that leaves such a pin
  warns (`redirect_yarn_classic_berry_migration_risk` / `yarn_classic_berry_migration_risk`)
  unless `package.json` pins yarn classic through `"packageManager": "yarn@1…"`.
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
  the directory's `package.json` (and, for `vex`, a `file:` tarball's manifest or a
  registry tarball URL's path; hosted and vendored scans name a URL copy with
  `redirect_yarn_classic_non_registry_entry_skipped` /
  `vendor_yarn_classic_non_registry_entry_skipped`). A git copy under another name
  records no package name in the lock and is not detected. When every entry of the package is such a copy (git, `file:` directory,
  non-registry tarball or `link:`), vendoring refuses with `vendor_lock_entry_not_rewritable` naming them,
  since `yarn install` can't help.
- **bun** — text `bun.lock` lockfileVersion 0, 1 or 2: 0 is the `--save-text-lockfile`
  opt-in lock of Bun 1.1.39–1.1.45, 1 the 1.2–1.3 default, 2 the 1.4+ default; all three
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
or `vendor`. It also prunes every directory that carries a
[Cache Directory Tagging](https://bford.info/cachedir/) `CACHEDIR.TAG` file
beginning with the standard signature — a cargo `target/`, and caches of
other tools that follow the convention: neither that directory's own
`node_modules` nor anything below it is crawled. The scan root is always
crawled, even when it is tagged itself. A `CACHEDIR.TAG` that lacks the
signature, is a directory or is a symlink prunes nothing.

Inside each `node_modules`, the package stores of isolated layouts are
walked too, since they are the only home of transitive dependencies:
pnpm's virtual store (`node_modules/.pnpm`, pnpm <= 3's
`node_modules/.registry.*`, or the directory a `virtualStoreDir` setting
moved it to, as recorded in `node_modules/.modules.yaml`), vlt's
`node_modules/.vlt`, Bun's isolated-linker store `node_modules/.bun`,
Deno's isolated `nodeModulesDir` store `node_modules/.deno`, and
`node_modules/.store`, written by npm's `install-strategy=linked` and by
Yarn 4's pnpm linker (where each entry's `package/` dir is the copy). A recorded virtual store outside the project is not
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
active Yarn pnpm install (a `yarn.lock`, and `nodeLinker: pnpm` with
`pnpmStoreFolder` in the nearest `.yarnrc.yml`), only to the
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
- **Vendored** ❌ — refused (`vendor_rush_unsupported`): `rush install` copies the lock
  into `common/temp` and runs pnpm there, so vendor's relative `file:` specs can't
  survive the copy — the refusal routes you to hosted mode.

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
with a `pnpm-workspace.yaml` it generates, so the `trustLockfile` auto-config is not written
in a Rush repo; the `redirect_pnpm_trust_lockfile` warning gives the Rush remedy instead
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
ci` on any change there. Before anything is written, each artifact is fetched the way
vlt fetches it (`accept-encoding: gzip;q=1.0, identity;q=0.5`, raw body hashed); vlt
fails `EINTEGRITY` on a content-encoded response, so such a dependency is withheld
(`redirect_vlt_artifact_unverifiable`) instead of pinning a lock `vlt ci` cannot install.

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
inside it, and a `.gitattributes` that turns EOL conversion off so an `autocrlf` checkout
stays byte-exact. The lock's node becomes a `file` node, the importer edges and the
importers' `package.json` specs move to the `file:` path, and every moved entry is placed
where vlt's own serializer puts it, so `vlt ci` keeps the lock byte-identical. Transitive
targets are refused (`vendor_vlt_transitive_unsupported`: vlt silently reverts
transitive lock surgery), as are several instances of one `name@version`, modifier
variants, importer peer edges, foreign registries, a git, remote-tarball or local-directory
node of the same package and a dependency declared in several fields
(`vendor_lock_entry_unsupported`), and a package with a `preinstall`, `install`,
`postinstall` or `prepare` script or a `binding.gyp`, which `vlt build` would build inside
the committed directory (`vendor_vlt_build_scripts_unsupported`); use hosted mode for those. From vlt 1.0.8 a root
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
  the transport-level `.jar.sha1` sidecar on top. A `${property}` version is refused
  (`redirect_maven_dep_unpinned`) — a literal edit would break the property reference and
  a depMgmt pin could strand sibling artifacts sharing the property. A literal version
  that matches neither the base nor the suffixed value is skipped
  (`redirect_maven_dep_version_mismatch`). A `<base>-socket.<hex8>` literal left by an
  earlier hosted patch for the same release (the pom declares that patch's
  `socket-patch-<uuid>` repository) is re-pinned to the new suffix: the superseded
  `socket-patch-<uuid>` repository and its Trusted Checksums entries are removed, and a
  repository whose grant URL changed (a rotated token) is refreshed in place. A suffixed
  literal no hosted repository in the pom minted (a vendored `socket-patch-vendor-<uuid>`
  pin, say) is still a mismatch and is skipped.
* **Multi-module reactors are vendored-only (hosted Maven).** Hosted mode reads only
  the root `pom.xml`, and a module's own literal `<version>` always beats a root
  `<dependencyManagement>` pin, so a root pin would leave that module on the unpatched
  upstream jar. A root that declares `<modules>` or `<subprojects>` (directly or in a
  profile) is therefore refused with `redirect_maven_multimodule_unsupported` (`pom.xml` and
  `.mvn/` are left untouched and the dep is not counted as redirected); use `scan --mode vendored`, whose reactor planner rewrites each module's
  declaration. `vex` likewise does not attest a hosted pin found in a reactor root.
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
  - **3.9.0 / 3.9.1** do not interpolate the `${session.rootDirectory}` basedir the config
    uses, so the summary file is never found.
  - **3.9.2 / 3.9.3** ignore `checksumAlgorithms=SHA-256` and check SHA-1 only.
  - **Below 3.9** there is no Trusted Checksums post-processor.

  When `.mvn/wrapper/maven-wrapper.properties` pins a Maven older than 3.9.4, the rewriter
  still writes the files and warns `redirect_maven_trusted_checksums_unenforced`. Without
  a Maven Wrapper, the CLI can't tell which Maven builds the project, so it doesn't warn.
  On Maven **3.9.4–3.9.8** a *mismatch* is enforced but reported unclearly; the
  readability fix landed in **3.9.9**
  ([MNG-8182](https://issues.apache.org/jira/browse/MNG-8182)). The args are
  `originAware=false` and `failIfMissing=false`, so one checksum matches the artifact
  from any repository and a dependency with no committed checksum still resolves — only a
  *mismatch* fails.
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
* **`mirrorOf` mirrors (hosted Maven).** A `settings.xml` `<mirror>` with
  `<mirrorOf>*</mirrorOf>` (common in corporate environments) reroutes *all* repositories
  — including the injected `socket-patch-<uuid>` repository — through the mirror. Because
  the patch resolves only at the suffixed version, the mirror (which does not carry it)
  can't serve it and the **build fails loudly** rather than silently going unpatched.
  Scope the mirror to exclude the Socket repos (e.g.
  `<mirrorOf>*,!socket-patch-*</mirrorOf>`) so the redirect resolves; the
  `originAware=false` Trusted Checksums act as a backstop when present.
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
they need network access (`jvm_agent_service_required` offline). The original is
backed up under `.socket/jvm-originals/` and `rollback` restores from it. `rollback`
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
(VEX withheld). Each detail starts with `reason: <reason>:`.

### VEX

`vex` re-hashes every copy a build may load: the `~/.m2` copies it reads, every
Gradle hash directory, and the suffixed copies of a hosted pin. A derived copy proven
to come from the unpatched jar, or an older one that does not match the patched jar,
withholds the statement (`vex_gradle_unpatched_copy`). A derived-cache walk cut short
on a very large cache warns `vex_gradle_derived_cache_unchecked` and does not
withhold.

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
offline. The full code list is in
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
  is not a VEX reference.

## Cargo: shared registry cache

Agent mode patches the crate in place wherever the crawler finds it. For a non-vendored
crate that means the **shared** `$CARGO_HOME/registry` cache: the patch affects every
project on the machine, and is silently reset by `cargo clean` or a cache prune. Use
`--mode vendored` for a project-local, committable patch.

Run `cargo fetch` before `apply` on a fresh checkout or CI runner. Cargo unpacks a
locked crate into `registry/src` only when it fetches or builds, so on a cold or pruned
cache there is nothing to patch, and the next `cargo build` would compile the pristine
crate. `apply` therefore treats a crate that `Cargo.lock` resolves but that is not
unpacked as not installed, not as a calm lockfile-only skip: a run where no targeted
patch matched exits 1 and names `cargo fetch` as the remedy.

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
  (`cargo_multi_version_old_cargo`) unless the project's `rust-version` or
  `rust-toolchain[.toml]` promises cargo 1.45+ — socket-patch never runs
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
A re-pin to a newer patch (a superseding patch uuid, or the same patch republished
at a new `-socketpatch.<n>` version) also removes the previous Socket module's sum
lines, so `go mod tidy -diff` stays clean after a patch update.

This requires a free, publicly retrievable patch reference carrying a `goproxy`
override. CLI support does not imply a patch is published for a particular module.
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

## Supported platforms

Prebuilt binaries are published for:

| Platform | Architecture |
|----------|-------------|
| macOS | ARM64 (Apple Silicon), x86_64 (Intel) |
| Linux | x86_64, ARM64, 32-bit ARM hard-float (`arm-unknown-linux-gnueabihf` / `-musleabihf`), i686 |
| Windows | x86_64, ARM64, i686 |
| Android | ARM64 |
