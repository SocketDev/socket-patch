# Ecosystem & platform support

This is the detailed support matrix for `socket-patch`: which package ecosystems work
with which [patch mode](../README.md#three-patch-modes), the per-ecosystem caveats, and
the platforms the binary ships for.

For what the three modes *are* and how to choose between them, see
[How Socket Patch works](../README.md#how-socket-patch-works) in the README.

## Mode × ecosystem matrix

The backticked slug in each row is the value `-e`/`--ecosystems` accepts (e.g.
`--ecosystems npm,pypi,golang`).

| Ecosystem | agent (`--mode agent`) | vendored (`--mode vendored`) | hosted (`--mode hosted`) |
|-----------|------------------------|------------------------------|--------------------------|
| npm (`npm`) — pnpm / yarn / berry / bun | ✅ any install layout; `setup` postinstall hook | ✅ five lockfile flavors: package-lock, yarn classic, yarn berry (node-modules linker; PnP refused), pnpm v9, bun `bun.lock` (binary `bun.lockb` refused with a `--save-text-lockfile` pointer). Rush monorepos refused (`vendor_rush_unsupported`) — see [Rush notes](#npm-rush-monorepos) | ✅ package-lock / npm-shrinkwrap, pnpm-lock.yaml (pnpm v9), yarn classic, yarn berry, bun — pnpm, berry, and bun carry constraints, see [npm hosted-mode notes](#npm-hosted-mode-notes) |
| PyPI (`pypi`) — uv / poetry / pdm / pipenv / pip | ✅ `.pth` startup hook via `setup` | ✅ five lockfile flavors: uv, poetry, pdm, pipenv (lock rewired, but pipenv doesn't hash-check file entries — `vendor_integrity_unverified` warning; the committed wheel bytes are the protection), and requirements.txt (consumed by pip or `uv pip`) | ✅ requirements.txt + uv.lock. **poetry / pdm / pipenv locks are not rewritten** — use vendored |
| Cargo (`cargo`) | ✅ in-place + `.cargo-checksum.json` rewrite (shared registry-cache caveat — see [Cargo: shared registry cache](#cargo-shared-registry-cache)) | ✅ `[patch.crates-io]` path entry | ✅ per-patch sparse registry (`[registries.socket-patch-<uuid>]` + Cargo.lock source/checksum) |
| RubyGems (`gem`) | ✅ Bundler plugin via `setup` — needs bundler ≥ 2.2 (1.x cannot load `plugin ... path:` directives; `setup` refuses below the floor and `setup --check` red-flags a wired 1.x project) | ✅ Gemfile + Gemfile.lock path pair (`Gemfile` spelling only — a `gems.rb` project cannot vendor yet) | ✅ per-dep `source` block — edits `gems.rb` + `gems.locked` when present (bundler prefers them over `Gemfile`; spellings that diverge beyond Socket's own edits fail closed with `redirect_gem_gemfile_spellings_diverge`); the `CHECKSUMS` pin needs bundler ≥ 2.6 (older locks get a `redirect_gem_no_checksums_section` warning) |
| Go (`golang`) | ✅ `go.mod` `replace` → `.socket/go-patches/` — see [Go: directory replaces and go.sum](#go-directory-replaces-and-gosum) | ✅ `replace` → the committed vendor tree | ✅ (free tier) fork-style `replace` → `patch.socket.dev/gopatch/<uuid>` + committed `go.sum` pin; see [golang-hosted.md](design/golang-hosted.md). Paid tier stays ❌ ([golang-hosted-no-go.md](design/golang-hosted-no-go.md)); `redirect_golang_unsupported` names the vendored remedy |
| Maven (`maven`) | ✅ apply-only (no `setup` hook — reports `no_files`); in-place jar patching leaves the `~/.m2` checksum sidecars stale — prefer vendored / hosted, see [Maven & NuGet caveats](#maven--nuget-caveats) | ✅ committed maven2 `file://` repository. A root pom declaring `<modules>` (multi-module aggregator) is refused (`vendor_maven_multimodule_unsupported`), and a gradle-only project is refused (`vendor_gradle_unsupported`) | ✅ **pom projects only, fail-closed** — the patched jar is pinned at a Socket-only `<version>-socket.<hex8>` suffix; `${property}` versions are refused; Gradle gets a manual `exclusiveContent` snippet — see [Maven & NuGet caveats](#maven--nuget-caveats) |
| NuGet (`nuget`) | ✅ apply-only (no `setup` hook — reports `no_files`); in-place patching deletes `.nupkg.metadata` and advises on the `.nupkg.sha512` tamper-evidence sidecar — prefer vendored / hosted, see [Maven & NuGet caveats](#maven--nuget-caveats) | ✅ committed folder feed + `packageSourceMapping` + `packages.lock.json` contentHash pin | ✅ `nuget.config` source + source-mapping, `packages.lock.json` contentHash rewrite. See the locked-mode note in [Maven & NuGet caveats](#maven--nuget-caveats) |
| Composer (`composer`) | ✅ post-install script events | ✅ `composer.lock` `dist: path` rewrite | ✅ `composer.lock` dist url + shasum rewrite |
| Deno (`deno`) | ✅ apply-only — no install hook (`setup` reports `no_files`); declare in `setup.manual` for VEX coverage | ❌ refused (`vendor_unsupported_ecosystem`) | ❌ not supported |

> **Maven / NuGet sidecar caveat**: Maven and NuGet are fully enabled in every mode (the
> old `SOCKET_EXPERIMENTAL_MAVEN` / `SOCKET_EXPERIMENTAL_NUGET` opt-ins are retired).
> In-place (agent-mode) patching leaves the caches' own checksum sidecars stale: NuGet's
> post-apply fixup deletes `.nupkg.metadata` and raises an advisory for the
> signed-package `.nupkg.sha512` tamper marker it cannot honestly rewrite; Maven's
> `.jar.sha1`/`.jar.md5` are left as-is. The copy-out modes — `vendor`,
> `scan --mode vendored`, `scan --mode hosted` — never write into the caches and avoid
> the issue entirely.

## npm hosted-mode notes

- **pnpm** — lockfileVersion 9 (`pnpm >=9`). Older lock grammars carry `packages:` keys
  the rewrite cannot repoint — v6 embeds resolved peers in the key itself
  (`/name@1.0.0(peer@2.0.0)`) and v5.x is path-style (`/name/1.0.0`). A dep that
  resolves through any such key is refused outright
  (`redirect_pnpm_unsupported_lock_key` names the key and the lock), never partially
  rewritten: regenerate the lock with pnpm ≥ 9 and re-run.
- **yarn berry** — the redirect edits the `yarn.lock` entry only (cacheKey `10c0` /
  yarn 4), and `.yarnrc.yml`'s `compressionLevel` must stay 0. The node-modules linker
  is e2e-covered; PnP is untested for hosted — the lock rewrite fires, but PnP's
  `.yarn/cache` resolution isn't exercised.
- **yarn `npm:` aliases (classic & berry)** — a lock entry that consumes the patched
  package only through an alias descriptor (`"safe-pad@npm:left-pad@^1.3.0"`) is left
  untouched, with a `redirect_yarn_classic_alias_skipped` /
  `redirect_yarn_berry_alias_skipped` warning naming the entry — that copy keeps the
  unpatched artifact. The reverse shape — an alias of the patched NAME pointing at a
  different package (`"left-pad@npm:some-fork@^1.3.0"`, the fork-substitution idiom) —
  is never rewritten: it resolves a different package.
- **bun** — text `bun.lock` v1 only. A binary `bun.lockb` with no text lock beside it
  is auto-migrated first: the CLI runs your installed `bun`
  (`bun install --save-text-lockfile --frozen-lockfile --lockfile-only`) before reading
  the lock — `redirect_bun_lockb_would_migrate` on `--dry-run`,
  `redirect_bun_lockb_unsupported` when `bun` is unavailable. (Contrast vendored mode,
  which refuses `bun.lockb` and leaves you to run the migration yourself.)

## npm: Rush monorepos

A Rush repo has no root `package.json`/lockfile pair — its pnpm source-of-truth locks
live at `common/config/rush/pnpm-lock.yaml` (plus one per subspace under
`common/config/subspaces/<name>/`).

- **Hosted** ✅ — `scan --mode hosted` discovers and repoints those locks in place
  (subspaces included).
- **Agent** ✅ — works through the generated project symlink farm.
- **Vendored** ❌ — refused (`vendor_rush_unsupported`): `rush install` copies the lock
  into `common/temp` and runs pnpm there, so vendor's relative `file:` specs can't
  survive the copy — the refusal routes you to hosted mode.

Editing a Rush lock outside `rush update` desyncs the `pnpmShrinkwrapHash` in
`common/config/rush/repo-state.json`, so when `preventManualShrinkwrapChanges` is enabled
`rush install` fails until `rush update` refreshes it (a `redirect_rush_repo_state_stale`
warning flags this; the redirect survives the refresh — pnpm keeps locked resolutions for
unchanged specifiers).

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
  (`redirect_maven_dep_version_mismatch`).
* **Trusted Checksums reinforcement (hosted Maven, 3.9+).** When the patch server
  supplies both the jar and pom sha256, the rewriter also emits Maven
  [Trusted Checksums](https://maven.apache.org/resolver/expected-checksums.html) files —
  `.mvn/maven.config` resolver args plus `.mvn/checksums/checksums.sha256` entries
  pinning both artifacts under the suffixed version's local-repo path (merging into any
  pre-existing user config / checksum set; a conflicting value is never overridden and
  surfaces `redirect_maven_trusted_checksums_conflict`). This is an **independent
  client-side content pin** on top of the transport check. It requires **Maven 3.9+**
  (the resolver post-processor and the `${session.rootDirectory}` basedir expression the
  config uses); on older Maven the `.mvn/*` files are silently inert — the
  version-suffixing above is still fail-closed on its own. On Maven **3.9.0–3.9.8** a
  *mismatch* is enforced but reported unclearly; the readability fix landed in **3.9.9**
  ([MNG-8182](https://issues.apache.org/jira/browse/MNG-8182)). The args are
  `originAware=false` and `failIfMissing=false`, so one checksum matches the artifact
  from any repository and a dependency with no committed checksum still resolves — only a
  *mismatch* fails.
* **Warm `~/.m2` shadowing (vendored Maven only).** Maven consults the *local repository*
  before any configured `<repository>`, so with vendored mode a warm `~/.m2` copy of the
  same GAV silently wins over the committed `file://` repository — the build succeeds
  with **unpatched** bytes. Purge it with:
  `mvn dependency:purge-local-repository -DmanualInclude=<groupId>:<artifactId>`
  (the always-on `vendor_maven_local_cache_shadow` warning carries the same one-liner).
  Hosted mode is **not** affected: the patched jar lives at the suffixed version, which
  no warm `~/.m2` entry can hold.
* **`mirrorOf` mirrors (hosted Maven).** A `settings.xml` `<mirror>` with
  `<mirrorOf>*</mirrorOf>` (common in corporate environments) reroutes *all* repositories
  — including the injected `socket-patch-<uuid>` repository — through the mirror. Because
  the patch resolves only at the suffixed version, the mirror (which does not carry it)
  can't serve it and the **build fails loudly** rather than silently going unpatched.
  Scope the mirror to exclude the Socket repos (e.g.
  `<mirrorOf>*,!socket-patch-*</mirrorOf>`) so the redirect resolves; the
  `originAware=false` Trusted Checksums act as a backstop when present.
* **Gradle (hosted Maven).** Gradle build scripts are never edited. A present
  `build.gradle*` / `settings.gradle*` gets a paste-able `exclusiveContent { … }` snippet
  (a `redirect_gradle_manual_snippet` warning) that carries the **suffixed** version —
  and you must bump the `groupId:artifactId` dependency declaration to that suffixed
  version yourself. It is fail-closed by repository exclusivity: the `exclusiveContent`
  filter routes only the suffixed version to the Socket repo, which is the only place it
  exists.
* **NuGet locked mode (hosted + vendored).** With a `packages.lock.json` and
  `dotnet restore --locked-mode`, the rewritten `contentHash` pins the patched `.nupkg` —
  a tampered or wrong package fails restore with `NU1403`. Without a lockfile there is no
  client-side content pin (vendored surfaces this as a `vendor_nuget_no_lockfile`
  warning; the feed + source mapping still force the patched copy).

## Cargo: shared registry cache

Agent mode patches the crate in place wherever the crawler finds it. For a non-vendored
crate that means the **shared** `$CARGO_HOME/registry` cache: the patch affects every
project on the machine, and is silently reset by `cargo clean` or a cache prune. Use
`--mode vendored` for a project-local, committable patch.

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

Hosted mode uses Go's other native `replace` form — a fork-style
module-to-module directive onto a Socket-published, content-addressed module
(`replace <mod> <ver> => patch.socket.dev/gopatch/<uuid> <ver>-socketpatch.<n>`)
plus the module's two committed `go.sum` lines. Because go consults the
checksum database only for modules *absent* from `go.sum`, the committed pair
is the complete day-2 state: fresh clones and CI build the patched module with
no machine-local configuration, and a tampered hash still fails closed with
go's checksum `SECURITY ERROR`. Free tier only; the paid-tier analysis (and
the ephemeral-CI workaround) is in
[golang-hosted-no-go.md](design/golang-hosted-no-go.md), the full free-tier
design in [golang-hosted.md](design/golang-hosted.md).

## Supported platforms

Prebuilt binaries are published for:

| Platform | Architecture |
|----------|-------------|
| macOS | ARM64 (Apple Silicon), x86_64 (Intel) |
| Linux | x86_64, ARM64, 32-bit ARM hard-float (`arm-unknown-linux-gnueabihf` / `-musleabihf`), i686 |
| Windows | x86_64, ARM64, i686 |
| Android | ARM64 |
