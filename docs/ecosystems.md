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
| npm (`npm`) — pnpm / yarn / berry / bun / vlt | ✅ any install layout, vlt's `node_modules/.vlt` store included (every store copy, copy-on-write); `setup` postinstall hook | ✅ seven lockfile flavors: package-lock, yarn classic, yarn berry (node-modules linker; PnP refused), pnpm v9, pnpm legacy v5.4/v6.0 (`pnpm 7/8` — frozen installs are path-bound because those majors absolutize `file:` override specifiers; moved checkouts run one `pnpm install --offline --no-frozen-lockfile`, surfaced as `vendor_pnpm_legacy_absolute_specifier`), bun text `bun.lock` lockfileVersion 0/1/2 and native binary `bun.lockb` revisions 1/2/3 (binary locks stay binary; text workspace vendoring requires lockfileVersion 2 — see [Bun compatibility](testing/bun-compatibility.md)), vlt `vlt-lock.json` lockfileVersion 0/1 (patched package directories for direct dependencies of the root or a workspace member; transitive targets refused — see [vlt notes](#npm-vlt-notes)). Rush monorepos refused (`vendor_rush_unsupported`) — see [Rush notes](#npm-rush-monorepos) | ✅ package-lock / npm-shrinkwrap, pnpm-lock.yaml and legacy shrinkwrap.yaml (pnpm majors 1–12; block and flow resolutions), yarn classic, yarn berry, bun, vlt (`vlt-lock.json` without `lockfileVersion`, 0 or 1) — pnpm, berry, bun and vlt carry constraints, see [npm hosted-mode notes](#npm-hosted-mode-notes) and [vlt notes](#npm-vlt-notes) |
| PyPI (`pypi`) — uv / poetry / pdm / pipenv / pip | ✅ `.pth` startup hook via `setup` | ✅ uv project/script locks, PEP 751 `pylock.toml` / `pylock.<name>.toml`, poetry, pdm, pipenv (Pipenv 2018 or later — every `Pipfile.lock` category is rewired, lock-only checkouts included; Pipenv 2023+ does not hash-check local wheels — `vendor_integrity_unverified`; a venv still holding the upstream release is reported as `pypi_pipenv_stale_install`; see [Pipenv compatibility](testing/pipenv-compatibility.md)), and requirements.txt. Native uv vendoring requires uv ≥ 0.2.35 (the `[[package]]` lock grammar); hosted mode covers native `uv.lock` from uv 0.1.45 (the first release whose `uv lock` writes one) and requirements from uv 0.0.5; see [uv compatibility](testing/uv-compatibility.md). | ✅ requirements.txt including hash continuations, uv project/script locks, and PEP 751 locks. Version/source ambiguity is refused; see [uv compatibility](testing/uv-compatibility.md). Poetry 1.x and 2.x locks are supported; Poetry 0.x ignores URL sources and is refused. See [Poetry compatibility](testing/poetry-compatibility.md). Pipenv `Pipfile.lock` (pipfile-spec 6 — Pipenv 7 and later; `path` references for 7–11, `file` from 2018; lock-only checkouts and Pipenv's out-of-tree venv are discovered; a warm venv that Pipenv will not reinstall over warns `redirect_pypi_stale_install`; see [Pipenv compatibility](testing/pipenv-compatibility.md)). `pdm.lock` is supported for the lock formats PDM 0.12–1.4 and 2.8.1+ write (`lock_version` 2 / 4.3–4.5.1); the identity-losing 3.1 / 4.0–4.2 formats (PDM 1.8–2.7) are refused. PDM 2.8.0 writes an indistinguishable `4.3` lock but shares that identity-loss bug, so a rewritten 2.8.0 lock crashes `pdm sync` — upgrade to ≥ 2.8.1. See [PDM compatibility](testing/pdm-compatibility.md). |
| Cargo (`cargo`) | ✅ in-place + `.cargo-checksum.json` rewrite (shared registry-cache caveat — see [Cargo: shared registry cache](#cargo-shared-registry-cache)) | ✅ `[patch.crates-io]` path entry in the root `Cargo.toml` (v5; per-version Socket keys; pre-v5 `.cargo/config*` wiring migrates on re-run) | ✅ per-patch sparse registry (`[registries.socket-patch-<uuid>]` + Cargo.lock source/checksum); direct dependencies only — a crate another dependency also pulls in is refused, use `--mode vendored`; with no `Cargo.lock` the graph is unknown, so only a project whose sole dependency is the patched crate is redirected |
| RubyGems (`gem`) | ✅ Bundler plugin via `setup` — needs bundler ≥ 2.2 (1.x cannot load `plugin ... path:` directives; `setup` refuses below the floor and `setup --check` red-flags a wired 1.x project) | ✅ Gemfile + Gemfile.lock path pair (`Gemfile` spelling only — a `gems.rb` project cannot vendor yet) | ✅ per-dep `source` block — edits `gems.rb` + `gems.locked` when present (bundler prefers them over `Gemfile`; spellings that diverge beyond Socket's own edits fail closed with `redirect_gem_gemfile_spellings_diverge`); the `CHECKSUMS` pin needs bundler ≥ 2.6 (older locks get a `redirect_gem_no_checksums_section` warning); a stale pre-redirect materialization that `bundle install` would reuse instead of refetching is flagged `redirect_gem_stale_install` with a prescriptive remedy (see CLI_CONTRACT.md's "Gem stale-install guard") |
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

- **npm (package-lock.json / npm-shrinkwrap.json)** — every present npm lock is
  rewritten (npm 12 installs from the package-lock.json twin it keeps beside a
  committed shrinkwrap). npm 12 defaults `allow-remote=none` and refuses the
  redirected tarballs (EALLOWREMOTE) unless the project `.npmrc` sets
  `allow-remote=all`, so the hosted run writes it (new file, or one appended
  line; ledger-recorded as `redirect_npmrc_allow_remote` and removed again by
  `rollback` / `remove` / the vendored takeover) and always warns
  `redirect_npm_allow_remote` with the tradeoff (any url-resolved dependency is
  then admitted; sha512 pins stay enforced). Commit `.npmrc` with the lock. An
  explicit user `allow-remote=none` / `root` is respected (never rewritten or
  overridden) — in the project `.npmrc`, the user / global / builtin npm config,
  or an `npm_config_allow_remote` environment variable — and
  `--no-npm-allow-remote-config` opts out (install with
  `npm ci --allow-remote=all`). Vendored `file:` tarballs are unaffected (npm
  gates them by `allow-file`, default `all`). npm 6 ignores `resolved` for registry
  dependencies, so a redirected lockfileVersion 1 lock fails closed with
  EINTEGRITY under npm 6 (`redirect_npm_legacy_client`) and installs under npm
  >= 7. Vendoring needs a lockfileVersion 2/3 lock (npm 6 still installs a
  vendored v2 lock from its legacy mirror) and rewires both locks in npm 12's
  dual-lock state. Majors 6–12 are measured in
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
  For root 9.0 locks, the CLI configures `trustLockfile: true` in
  `pnpm-workspace.yaml` unless opted out with `--no-trust-lockfile-config` or
  explicitly disabled by the project. pnpm >=11 needs this for hosted URLs.
  This skips registry re-verification for the whole lock; tarball integrity
  remains enforced. pnpm <=10 does not need the setting.
  **Reinstall after redirecting:** a successful warm-cache install can retain
  upstream bytes. Use a clean install tree and an empty store; `--force` is not
  a reliable substitute. Run `socket-patch vex` after installation to verify
  the patched files. See the [compatibility matrix and workflow](testing/pnpm-compatibility.md).
- **yarn berry** — the redirect edits the `yarn.lock` entry only (cacheKey `10c0` /
  yarn 4), and `.yarnrc.yml`'s `compressionLevel` must stay 0. The node-modules linker
  is e2e-covered; PnP is untested for hosted — the lock rewrite fires, but PnP's
  `.yarn/cache` resolution isn't exercised. CRLF locks — what yarn writes on Windows,
  and what a `core.autocrlf` checkout produces anywhere — are rewritten in their own
  line ending (a BOM is kept); a lock mixing CRLF and LF is refused
  (`redirect_yarn_berry_mixed_line_endings`) until `yarn install` normalizes it. See
  [yarn berry compatibility](testing/yarn-berry-compatibility.md).
- **yarn `npm:` aliases (classic & berry)** — a lock entry that consumes the patched
  package only through an alias descriptor (`"safe-pad@npm:left-pad@^1.3.0"`) is left
  untouched, with a `redirect_yarn_classic_alias_skipped` /
  `redirect_yarn_berry_alias_skipped` warning naming the entry — that copy keeps the
  unpatched artifact. The reverse shape — an alias of the patched NAME pointing at a
  different package (`"left-pad@npm:some-fork@^1.3.0"`, the fork-substitution idiom) —
  is never rewritten: it resolves a different package.
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
  `workspace:` lock) `vendor` reports the refusal before the hosted revert and leaves the
  purl hosted-patched — and `rollback <purl>` / `remove <purl>` unwind one of several
  hosted bun redirects.
  Bun verifies the sha512 of URL and local-tarball tuples only from 1.3.10 (registry
  tuples from 1.2.0), so on 1.1.39–1.3.9 a hosted or vendored rewrite removes digest
  enforcement for the patched package. Every boundary here is measured against real
  Bun releases — see [Bun compatibility](testing/bun-compatibility.md).
- **vlt** — `vlt-lock.json` default-registry nodes of the patched `name@version` keep
  their DepID and get the patched sha512 in slot [2] and the hosted URL in slot [3]; see
  [vlt notes](#npm-vlt-notes).

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
upgrade to vlt 1.0.5 first when every dependency is optional (earlier releases install no
optional dependency from the lock of such a project). `--no-vlt-install-cleanup` (or
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
transitive lock surgery), as are peer or modifier variants, importer peer edges, foreign
registries and a dependency declared in several fields (`vendor_lock_entry_unsupported`);
use hosted mode for those. From vlt 1.0.8 a root dependency with resolved peers carries a
`~peer.<hex>` extra even with one peer context (a workspace member's from rc.15), and
vendored mode refuses such a variant instance today. Before rc.6 vlt cannot reinstall a
vendored `file:` dependency without the lock (`vendor_vlt_legacy_lockfile` on era-A
locks), and A0 locks are refused. From 0.0.0-30 a plain `vlt install` keeps an optional
dependency's installed upstream copy after vendoring; run `vlt ci` to link the vendored
directory.

**Agent mode.** `apply` and `rollback` patch every store copy of a `name@version`
(legacy and tilde DepIDs, peer and modifier variants, transitive-only packages) and
replace each file instead of writing through it, so vlt 1.2's shared store (hardlinked on
Linux) and every other project linked to it keep their bytes. A patch survives `vlt
install`, `install <new>`, `uninstall` and frozen installs; `vlt ci` and deleting
`node_modules` restore the upstream bytes, which is what the setup hook is for.

**Setup.** vlt gets npm's `npx @socketsecurity/socket-patch apply --silent --ecosystems
npm` postinstall hook, wired at the workspace root only (vlt runs the root hook once per
install that changes the graph, never on a no-op install). vlt before 1.0.0-rc.13 never
runs a root `postinstall` without an `install` script: `setup` still wires it and warns
`vlt_root_scripts_not_run`. A failing hook aborts and rolls back the whole `vlt install`.

**Locale.** vlt sorts its lock with the process locale for one key, so byte-stability is
claimed only for `en`-equivalent locales (`LANG` unset, `C`, `POSIX` or `en_US`); every vlt
test job sets `LANG=C` and `LC_ALL=C`. Vendored ownership and revert match by entry text,
so they do not depend on the order.

**Compatibility of ledgers.** vlt ledgers (`redirect_vlt_lock_node` hosted edits and
`flavor: "vlt"` vendored entries) require the socket-patch release that adds vlt support:
an older release does not understand them.

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
  `cargo_manifest_unparseable`, `cargo_manifest_symlink_unsupported`.
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
