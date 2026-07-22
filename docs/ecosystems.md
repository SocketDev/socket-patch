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
| npm (`npm`) — pnpm / yarn / berry / bun | ✅ any install layout; `setup` postinstall hook | ✅ five lockfile flavors: package-lock, yarn classic, yarn berry (node-modules linker; PnP refused), pnpm v9, bun `bun.lock` (binary `bun.lockb` refused with a `--save-text-lockfile` pointer). Rush monorepos refused (`vendor_rush_unsupported`) — see [Rush notes](#npm-rush-monorepos) | ✅ package-lock / npm-shrinkwrap, pnpm-lock.yaml, yarn classic, yarn berry, bun — berry and bun carry constraints, see [npm hosted-mode notes](#npm-hosted-mode-notes) |
| PyPI (`pypi`) — uv / poetry / pdm / pipenv / pip | ✅ `.pth` startup hook via `setup` | ✅ five lockfile flavors: uv, poetry, pdm, pipenv (lock rewired, but pipenv doesn't hash-check file entries — `vendor_integrity_unverified` warning; the committed wheel bytes are the protection), and requirements.txt (consumed by pip or `uv pip`) | ✅ requirements.txt + uv.lock. **poetry / pdm / pipenv locks are not rewritten** — use vendored |
| Cargo (`cargo`) | ✅ in-place + `.cargo-checksum.json` rewrite (shared registry-cache caveat — see [Cargo: shared registry cache](#cargo-shared-registry-cache)) | ✅ `[patch.crates-io]` path entry | ✅ per-patch sparse registry (`[registries.socket-patch-<uuid>]` + Cargo.lock source/checksum) |
| RubyGems (`gem`) | ✅ Bundler plugin via `setup` | ✅ Gemfile + Gemfile.lock path pair | ✅ per-dep `source` block; the `CHECKSUMS` pin needs bundler ≥ 2.6 (older locks get a `redirect_gem_no_checksums_section` warning) |
| Go (`golang`) | ✅ `go.mod` `replace` → `.socket/go-patches/` — see [Go: directory replaces and go.sum](#go-directory-replaces-and-gosum) | ✅ `replace` → the committed vendor tree | ❌ **not possible** — sumdb, module-path identity, and default-GOPROXY leakage each rule it out; see [golang-hosted-no-go.md](design/golang-hosted-no-go.md). **Use vendored** (`redirect_golang_unsupported` names the remedy) |
| Maven (`maven`) | ⚠️ experimental, apply-only (no `setup` hook — reports `no_files`) — gated behind `SOCKET_EXPERIMENTAL_MAVEN=1` (in-place jar patching corrupts the `~/.m2` checksum sidecars); prefer vendored / hosted | ✅ committed maven2 `file://` repository. A root pom declaring `<modules>` (multi-module aggregator) is refused (`vendor_maven_multimodule_unsupported`), and a gradle-only project is refused (`vendor_gradle_unsupported`) | ✅ **pom projects only, fail-closed** — the patched jar is pinned at a Socket-only `<version>-socket.<hex8>` suffix; `${property}` versions are refused; Gradle gets a manual `exclusiveContent` snippet — see [Maven & NuGet caveats](#maven--nuget-caveats) |
| NuGet (`nuget`) | ⚠️ experimental, apply-only (no `setup` hook — reports `no_files`) — gated behind `SOCKET_EXPERIMENTAL_NUGET=1` (in-place patching breaks the `.nupkg.sha512` tamper-evidence sidecar); prefer vendored / hosted | ✅ committed folder feed + `packageSourceMapping` + `packages.lock.json` contentHash pin | ✅ `nuget.config` source + source-mapping, `packages.lock.json` contentHash rewrite. See the locked-mode note in [Maven & NuGet caveats](#maven--nuget-caveats) |
| Composer (`composer`) | ✅ post-install script events | ✅ `composer.lock` `dist: path` rewrite | ✅ `composer.lock` dist url + shasum rewrite |
| Deno (`deno`) | ✅ apply-only — no install hook (`setup` reports `no_files`); declare in `setup.manual` for VEX coverage | ❌ refused (`vendor_unsupported_ecosystem`) | ❌ not supported |

> **Maven / NuGet discovery gate**: discovering *installed* Maven and NuGet packages (the
> crawl behind `scan` / `apply` / `vendor`) currently requires the same
> `SOCKET_EXPERIMENTAL_MAVEN=1` / `SOCKET_EXPERIMENTAL_NUGET=1` opt-in in every mode. The
> vendored/hosted wiring itself is safe — the gate guards the agent-mode sidecar risk.

## npm hosted-mode notes

- **yarn berry** — the redirect edits the `yarn.lock` entry only (cacheKey `10c0` /
  yarn 4), and `.yarnrc.yml`'s `compressionLevel` must stay 0. The node-modules linker
  is e2e-covered; PnP is untested for hosted — the lock rewrite fires, but PnP's
  `.yarn/cache` resolution isn't exercised.
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

Hosted mode is a hard ❌ for Go — sumdb verification, module-path identity, and
default-GOPROXY leakage each independently rule it out; the full analysis is in
[golang-hosted-no-go.md](design/golang-hosted-no-go.md).

## Supported platforms

Prebuilt binaries are published for:

| Platform | Architecture |
|----------|-------------|
| macOS | ARM64 (Apple Silicon), x86_64 (Intel) |
| Linux | x86_64, ARM64, 32-bit ARM hard-float (`arm-unknown-linux-gnueabihf` / `-musleabihf`), i686 |
| Windows | x86_64, ARM64, i686 |
| Android | ARM64 |
