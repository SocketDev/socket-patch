# Socket Patch CLI

Apply security patches to your dependencies — npm, PyPI, Cargo, Go, Ruby gems, and more — without waiting for upstream fixes.

## Choosing a patch mode

socket-patch delivers the same patched bytes three different ways. The modes differ in *where the patch lives* and *what must happen at install time*; pick one per project (`scan --mode <name>` drives exactly one mode per run).

| Mode | Mechanism | User-code changes | CI changes | Offline / airgap | Integrity story | Future GitHub-app default |
|------|-----------|-------------------|------------|------------------|-----------------|---------------------------|
| **hosted** — `scan --mode hosted` | Lockfiles / registry configs are rewritten so **only** the patched dependencies resolve to Socket-hosted, integrity-pinned packages on `patch.socket.dev` | Minimal: lockfile (+ small registry-config) edits; no artifact bytes land in the repo | **None** — your existing install commands pick up the patched packages | ❌ installs must be able to reach `patch.socket.dev` | The package manager's own lockfile verification (sha512 / sha256 / contentHash / CHECKSUMS) pins the hosted bytes. Maven has no lockfile, so it pins by serving the patch under a Socket-only version suffix — fail-closed by repository exclusivity, optionally reinforced with Trusted Checksums (see [Maven & NuGet caveats](#maven--nuget-caveats)) | ✅ planned default for GitHub-app patch PRs — keeps the PR diff small |
| **vendored** — `scan --mode vendored` (or the standalone [`vendor`](#vendor)) | Patched artifacts are committed under `.socket/vendor/` and the lockfile is rewired to consume them | Committed artifacts (the repo grows by the patched package sizes) | **None** | ✅ fully airgapped; no dependency on Socket infrastructure uptime | Committed bytes + recomputed lockfile hashes, verified by the package manager at install time | — |
| **agent** — `scan --mode agent` (or [`apply`](#apply)) | `.socket/manifest.json` + patch blobs are committed; the socket-patch CLI re-applies the patches in CI / postinstall | `.socket/` manifest + blobs committed | **Required** — wire install hooks with [`setup`](#setup) or run `socket-patch apply` in CI | ✅ once blobs are committed (`apply --offline`) | The CLI verifies per-file before/after git-sha256 hashes on every apply | Today's default (the original method) |

**agent** is the original method and remains fully supported, but it is the only mode that requires CI / install-hook modification — **new projects should prefer hosted or vendored**.

### Mode × ecosystem support

| Ecosystem | agent (`--mode agent`) | vendored (`--mode vendored`) | hosted (`--mode hosted`) |
|-----------|------------------------|------------------------------|--------------------------|
| npm (pnpm / yarn / berry / bun) | ✅ any install layout; `setup` postinstall hook | ✅ five lockfile flavors: package-lock, yarn classic, yarn berry (node-modules linker; PnP refused), pnpm v9, bun `bun.lock` (binary `bun.lockb` refused with a `--save-text-lockfile` pointer) | ✅ package-lock / npm-shrinkwrap, pnpm-lock.yaml, yarn classic, **yarn berry** (`yarn.lock` entry only — cacheKey `10c0` / yarn 4, `.yarnrc.yml compressionLevel` must stay 0; node-modules linker is e2e-covered, PnP is untested for hosted — the lock rewrite fires but PnP's `.yarn/cache` resolution isn't exercised), **bun** (text `bun.lock` v1; a binary `bun.lockb` is auto-migrated to text first via your own `bun install --save-text-lockfile`) |
| pypi (uv / poetry / pdm / pipenv / pip) | ✅ `.pth` startup hook via `setup` | ✅ six flavors: uv, poetry, pdm, pipenv, requirements.txt (pip / `uv pip`) | ✅ requirements.txt + uv.lock. **poetry / pdm / pipenv locks are not rewritten** — use vendored |
| cargo | ✅ in-place + `.cargo-checksum.json` rewrite (shared registry-cache caveat — see [`setup`](#setup)) | ✅ `[patch.crates-io]` path entry | ✅ per-patch sparse registry (`[registries.socket-patch-<uuid>]` + Cargo.lock source/checksum) |
| gem | ✅ Bundler plugin via `setup` | ✅ Gemfile + Gemfile.lock path pair | ✅ per-dep `source` block; the `CHECKSUMS` pin needs bundler ≥ 2.6 (older locks get a `redirect_gem_no_checksums_section` warning) |
| golang | ✅ `go.mod` `replace` → `.socket/go-patches/` | ✅ `replace` → the committed vendor tree | ❌ **not possible** — sumdb, module-path identity, and default-GOPROXY leakage each rule it out; see [docs/design/golang-hosted-no-go.md](docs/design/golang-hosted-no-go.md). **Use vendored** (`redirect_golang_unsupported` names the remedy) |
| maven | ⚠️ experimental — gated behind `SOCKET_EXPERIMENTAL_MAVEN=1` (in-place jar patching corrupts the `~/.m2` checksum sidecars); prefer vendored / hosted | ✅ **new** — committed maven2 `file://` repository. A root pom declaring `<modules>` (multi-module aggregator) is refused (`vendor_maven_multimodule_unsupported`), and a gradle-only project is refused (`vendor_gradle_unsupported`) | ✅ **pom projects only, fail-closed** — the patched jar is served under a Socket-only `<version>-socket.<hex8>` suffix, so the rewriter pins that version (rewrite the literal `<version>`, or add a `<dependencyManagement>` entry for a transitive) alongside the `<repository>` insert (`checksumPolicy=fail`). An outage or tamper on the Socket repo then hard-fails the build — the suffixed version exists nowhere else, so there is no silent fall-through to Central. Optionally emits Maven 3.9+ Trusted Checksums files pinning the jar + pom sha256. `${property}` versions are refused. Gradle builds get a paste-able `exclusiveContent` snippet (`redirect_gradle_manual_snippet`); no build script is edited. See [Maven & NuGet caveats](#maven--nuget-caveats) |
| nuget | ⚠️ experimental — gated behind `SOCKET_EXPERIMENTAL_NUGET=1` (in-place patching breaks the `.nupkg.sha512` tamper-evidence sidecar); prefer vendored / hosted | ✅ **new** — committed folder feed + `packageSourceMapping` + `packages.lock.json` contentHash pin | ✅ `nuget.config` source + source-mapping, `packages.lock.json` contentHash rewrite. See the locked-mode note in [Maven & NuGet caveats](#maven--nuget-caveats) |
| composer | ✅ post-install script events (opt-in `composer` compile feature) | ✅ `composer.lock` `dist: path` rewrite | ✅ `composer.lock` dist url + shasum rewrite |

> **Maven / NuGet discovery gate**: discovering *installed* Maven and NuGet packages (the crawl behind `scan` / `apply` / `vendor`) currently requires the same `SOCKET_EXPERIMENTAL_MAVEN=1` / `SOCKET_EXPERIMENTAL_NUGET=1` opt-in in every mode. The vendored/hosted wiring itself is safe — the gate guards the agent-mode sidecar risk.

> **Rush monorepos** (npm): a Rush repo has no root `package.json`/lockfile pair — its single pnpm source-of-truth lock lives at `common/config/rush/pnpm-lock.yaml` (plus one per subspace under `common/config/subspaces/<name>/`). **Hosted** ✅ — `scan --mode hosted` discovers and repoints those locks in place (subspaces included). **Agent** ✅ works through the generated project symlink farm. **Vendored** is refused (`vendor_rush_unsupported`): `rush install` copies the lock into `common/temp` and runs pnpm there, so vendor's relative `file:` specs can't survive the copy — the refusal routes you to hosted mode. Editing a Rush lock outside `rush update` desyncs the `pnpmShrinkwrapHash` in `common/config/rush/repo-state.json`, so when `preventManualShrinkwrapChanges` is enabled `rush install` fails until `rush update` refreshes it (a `redirect_rush_repo_state_stale` warning flags this; the redirect survives the refresh — pnpm keeps locked resolutions for unchanged specifiers).

### Maven & NuGet caveats

Honest limits of the maven and nuget flows — documented behavior, not bugs:

* **Fail-closed by version suffixing (hosted maven).** Maven has no lockfile, so hosted mode pins the patch a different way: the Socket serve route exposes the patched jar under a globally-unique `<version>-socket.<hex8>` suffix that exists **only** on the injected `socket-patch-<uuid>` repository. The rewriter pins that suffixed version explicitly — it rewrites the literal `<version>`, or (for a transitive / managed dependency with no literal version in your pom) adds a `<dependencyManagement>` entry — so a resolver that can't reach the Socket repo, or is handed different bytes, has nowhere to fall through to: the build **hard-fails** instead of silently resolving the unpatched upstream artifact. The `<repository>`'s `checksumPolicy=fail` still verifies the transport-level `.jar.sha1` sidecar on top. A `${property}` version is refused (`redirect_maven_dep_unpinned`) — a literal edit would break the property reference and a depMgmt pin could strand sibling artifacts sharing the property. A literal version that matches neither the base nor the suffixed value is skipped (`redirect_maven_dep_version_mismatch`).
* **Trusted Checksums reinforcement (hosted maven, Maven 3.9+).** When the serve route supplies both the jar and pom sha256, the rewriter also emits Maven [Trusted Checksums](https://maven.apache.org/resolver/expected-checksums.html) files — `.mvn/maven.config` resolver args plus `.mvn/checksums/checksums.sha256` entries pinning both artifacts under the suffixed version's local-repo path (merging into any pre-existing user config / checksum set; a conflicting value is never overridden and surfaces `redirect_maven_trusted_checksums_conflict`). This is an **independent client-side content pin** on top of the transport check. It requires **Maven 3.9+** (the resolver post-processor and the `${session.rootDirectory}` basedir expression the config uses); on older Maven the `.mvn/*` files are silently inert — the version-suffixing above is still fail-closed on its own. On Maven **3.9.0–3.9.8** a *mismatch* is enforced but reported unclearly; the readability fix landed in **3.9.9** ([MNG-8182](https://issues.apache.org/jira/browse/MNG-8182)). The args are `originAware=false` and `failIfMissing=false`, so one checksum matches the artifact from any repository and a dependency with no committed checksum still resolves — only a *mismatch* fails.
* **Warm `~/.m2` shadowing (vendored maven only).** Maven consults the *local repository* before any configured `<repository>`, so with vendored mode a warm `~/.m2` copy of the same GAV silently wins over the committed `file://` repository — the build succeeds with **unpatched** bytes. Purge it with:
  `mvn dependency:purge-local-repository -DmanualInclude=<groupId>:<artifactId>`
  (the always-on `vendor_maven_local_cache_shadow` warning carries the same one-liner). Hosted mode is **not** affected: the patched jar lives at the suffixed version, which no warm `~/.m2` entry can hold.
* **`mirrorOf` mirrors (hosted maven).** A `settings.xml` `<mirror>` with `<mirrorOf>*</mirrorOf>` (common in corporate environments) reroutes *all* repositories — including the injected `socket-patch-<uuid>` repository — through the mirror. Because the patch resolves only at the suffixed version, the mirror (which does not carry it) can't serve it and the **build fails loudly** rather than silently going unpatched. Scope the mirror to exclude the Socket repos (e.g. `<mirrorOf>*,!socket-patch-*</mirrorOf>`) so the redirect resolves; the `originAware=false` Trusted Checksums act as a backstop when present.
* **Gradle (hosted maven).** Gradle build scripts are never edited. A present `build.gradle*` / `settings.gradle*` gets a paste-able `exclusiveContent { … }` snippet (a `redirect_gradle_manual_snippet` warning) that carries the **suffixed** version — and you must bump the `groupId:artifactId` dependency declaration to that suffixed version yourself. It is fail-closed by repository exclusivity: the `exclusiveContent` filter routes only the suffixed version to the Socket repo, which is the only place it exists.
* **NuGet locked mode (hosted + vendored).** With a `packages.lock.json` and `dotnet restore --locked-mode`, the rewritten `contentHash` pins the patched `.nupkg` — a tampered or wrong package fails restore with `NU1403`. Without a lockfile there is no client-side content pin (vendored surfaces this as a `vendor_nuget_no_lockfile` warning; the feed + source mapping still force the patched copy).

## Installation

### One-line install (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/SocketDev/socket-patch/main/scripts/install.sh | sh
```

Detects your platform (macOS/Linux, x64/ARM64), downloads the latest binary, and installs to `/usr/local/bin` or `~/.local/bin`. Use `sudo sh` instead of `sh` if `/usr/local/bin` requires root.

<details>
<summary>Manual download</summary>

Download a prebuilt binary from the [latest release](https://github.com/SocketDev/socket-patch/releases/latest):

```bash
# macOS (Apple Silicon)
curl -fsSL https://github.com/SocketDev/socket-patch/releases/latest/download/socket-patch-aarch64-apple-darwin.tar.gz | tar xz

# macOS (Intel)
curl -fsSL https://github.com/SocketDev/socket-patch/releases/latest/download/socket-patch-x86_64-apple-darwin.tar.gz | tar xz

# Linux (x86_64)
curl -fsSL https://github.com/SocketDev/socket-patch/releases/latest/download/socket-patch-x86_64-unknown-linux-musl.tar.gz | tar xz

# Linux (ARM64)
curl -fsSL https://github.com/SocketDev/socket-patch/releases/latest/download/socket-patch-aarch64-unknown-linux-gnu.tar.gz | tar xz
```

Then move the binary onto your `PATH`:

```bash
sudo mv socket-patch /usr/local/bin/
```

</details>

### npm

```bash
npx @socketsecurity/socket-patch
```

Or install globally:

```bash
npm install -g @socketsecurity/socket-patch
```

### pip

```bash
pip install socket-patch
```

### Cargo

```bash
cargo install socket-patch-cli
```

By default this builds with npm, PyPI, and Cargo support. For additional
ecosystems:

```bash
cargo install socket-patch-cli --features golang,maven,composer,nuget,deno
```

### RubyGems

```bash
gem install socket-patch
```

A thin launcher gem: on first run it downloads the prebuilt binary for your
platform from the matching GitHub release, verifies its SHA-256, caches it, and
execs it. Set `SOCKET_PATCH_BIN` to an existing binary to skip the download.

### Composer

```bash
composer require socketsecurity/socket-patch
vendor/bin/socket-patch --help
```

Same launcher model as the RubyGems package (download-on-first-run, cached,
`SOCKET_PATCH_BIN` to bypass).

## Quick Start

You can pass a patch UUID directly to `socket-patch` as a shortcut:

```bash
socket-patch 550e8400-e29b-41d4-a716-446655440000
# equivalent to: socket-patch get 550e8400-e29b-41d4-a716-446655440000
```

## Global Options

These flags are accepted by **every** subcommand — they are flattened into each command's argument set, so `socket-patch <command> --json --cwd ./app` works uniformly. A command silently ignores any global flag it doesn't use (e.g. `list --global` parses fine and the flag is a no-op).

Each flag has a matching `SOCKET_*` environment variable. **Precedence is CLI arg > env var > default**, so a flag on the command line always wins over the environment.

| Flag | Env var | Description |
|------|---------|-------------|
| `--cwd <dir>` | `SOCKET_CWD` | Working directory (default: `.`). The manifest path is resolved relative to this. |
| `-m, --manifest-path <path>` | `SOCKET_MANIFEST_PATH` | Path to the patch manifest, resolved relative to `--cwd` (default: `.socket/manifest.json`). |
| `--api-url <url>` | `SOCKET_API_URL` | Socket API URL for the authenticated endpoint (default: `https://api.socket.dev`). |
| `--api-token <token>` | `SOCKET_API_TOKEN` | Socket API token. When omitted, the public patch proxy is used. |
| `-o, --org <slug>` | `SOCKET_ORG_SLUG` | Organization slug. Auto-resolved when omitted and a token is set. |
| `--proxy-url <url>` | `SOCKET_PROXY_URL` | Public proxy URL used when no API token is set. |
| `-e, --ecosystems <list>` | `SOCKET_ECOSYSTEMS` | Restrict to specific ecosystems (comma-separated, e.g. `npm,pypi`). |
| `--download-mode <mode>` | `SOCKET_DOWNLOAD_MODE` | Artifact to fetch when local files are missing: `diff` (default, smallest delta), `package` (full per-package tarball), or `file` (legacy per-file blobs). |
| `--vendor-source <mode>` | `SOCKET_VENDOR_SOURCE` | How `vendor` acquires the installable artifact: `auto` (default — download the prebuilt package from patch.socket.dev, fall back to a local build on any miss), `service` (require the service, fail-closed), or `build` (always build locally). Covers npm, pypi, cargo, golang, composer, gem, and nuget (maven attempts the prebuilt download under `auto` but is not covered by fail-closed `service`). |
| `--vendor-url <url>` | `SOCKET_VENDOR_URL` | Base host for the vendoring service's package-reference request (default: the active `--api-url`/`--proxy-url` base). Point at staging / local dev for testing. |
| `--patch-server-url <url>` | `SOCKET_PATCH_SERVER_URL` | Override the host of the prebuilt-archive download URL the service returns (default: as returned). Mainly for local-dev / testing. |
| `--offline` | `SOCKET_OFFLINE` | Strict airgap: never contact the network. Operations that need remote data fail loudly. |
| `-g, --global` | `SOCKET_GLOBAL` | Operate on globally-installed packages. |
| `--global-prefix <path>` | `SOCKET_GLOBAL_PREFIX` | Override the path used to discover globally-installed packages. |
| `-j, --json` | `SOCKET_JSON` | Emit machine-readable JSON output. Every JSON response includes a `"status"` field (`"success"`, `"error"`, `"no_manifest"`, etc.) for reliable programmatic consumption. |
| `-v, --verbose` | `SOCKET_VERBOSE` | Show extra detail in human-readable output. |
| `-s, --silent` | `SOCKET_SILENT` | Suppress non-error output. |
| `--dry-run` | `SOCKET_DRY_RUN` | Preview the operation without making any mutations. |
| `-y, --yes` | `SOCKET_YES` | Skip interactive confirmation prompts. |
| `--lock-timeout <secs>` | `SOCKET_LOCK_TIMEOUT` | Seconds to wait for `.socket/apply.lock` before giving up. `0`/unset = a single non-blocking try; a positive value retries with backoff. Only meaningful for mutating commands (`apply`, `rollback`, `repair`, `remove`). |
| `--break-lock` | `SOCKET_BREAK_LOCK` | Force-remove a stale `.socket/apply.lock` before acquiring it. Use only when no other socket-patch process is running; emits an auditable `lock_broken` event in the JSON envelope. |
| `--debug` | `SOCKET_DEBUG` | Emit verbose debug logs to stderr. |
| `--no-telemetry` | `SOCKET_TELEMETRY_DISABLED` | Disable anonymous usage telemetry. |

## Commands

The tables below list only the **command-specific** flags. Every command also accepts the [Global Options](#global-options) above.

### `get`

Get security patches from Socket API and apply them. Accepts a UUID, CVE ID, GHSA ID, PURL, or package name. The identifier type is auto-detected but can be forced with a flag.

Alias: `download`

**Usage:**
```bash
socket-patch get <identifier> [options]
```

**Command-specific options** (plus all [Global Options](#global-options)):
| Flag | Description |
|------|-------------|
| `--id` | Force identifier to be treated as a UUID |
| `--cve` | Force identifier to be treated as a CVE ID |
| `--ghsa` | Force identifier to be treated as a GHSA ID |
| `-p, --package` | Force identifier to be treated as a package name |
| `--save-only` | Download patch without applying it (alias: `--no-apply`) |
| `--one-off` | Apply patch immediately without saving to the `.socket` folder |
| `--all-releases` | Download patches for every release/distribution variant of a matched package (PyPI wheel/sdist, RubyGems platform, Maven classifier), not just the installed one |

> Authenticated lookups require an org: pass `--org <slug>` (or set `SOCKET_ORG_SLUG`) when using `SOCKET_API_TOKEN`.

**Examples:**
```bash
# Get patch by UUID
socket-patch get 550e8400-e29b-41d4-a716-446655440000

# Get patch by CVE
socket-patch get CVE-2024-12345

# Get patch by GHSA
socket-patch get GHSA-xxxx-yyyy-zzzz

# Get patch by package name (fuzzy matches installed packages)
socket-patch get lodash

# Download only, don't apply
socket-patch get CVE-2024-12345 --save-only

# Apply to global packages
socket-patch get lodash -g

# JSON output for scripting
socket-patch get CVE-2024-12345 --json -y
```

### `scan`

Scan installed packages for available security patches. `scan --mode agent --prune` is the single command bots need for full auto-update: it discovers patches, applies them, and garbage-collects orphan blob files plus manifest entries for uninstalled packages — all in one invocation.

`scan` is also the entry point for all three [patch modes](#choosing-a-patch-mode): `--mode agent` applies in place, `--mode vendored` commits artifacts, `--mode hosted` rewrites lockfiles to Socket-hosted packages.

**Usage:**
```bash
socket-patch scan [options]
```

**Command-specific options** (plus all [Global Options](#global-options)):
| Flag | Description |
|------|-------------|
| `--mode <hosted\|vendored\|agent>` | The selector for the three [patch modes](#choosing-a-patch-mode). `agent` downloads and applies selected patches in place (non-interactive; without it, `scan --json` is read-only); `vendored` discovers, downloads, and builds + wires the committable `.socket/vendor/` artifacts in one pass (re-vendors automatically when a newer patch is selected); `hosted` rewrites lockfiles / registry configs so **only** the patched dependencies resolve to Socket-hosted, integrity-pinned packages (no artifact bytes land in the repo; the recorded edits + patch records go to the `.socket/vendor/redirect-state.json` ledger so a post-install [`vex`](#vex) can attest them). Combining `--mode` with a legacy boolean flag of a *different* mode is an error (exit 2); the same mode spelled both ways is accepted. Legacy boolean spellings (`--apply` == agent, `--vendor` == vendored, `--sync` == agent + prune) remain supported for back-compat. |
| `--prune` | Garbage-collect after the scan: remove manifest entries for uninstalled packages and orphan blob/diff/package-archive files. Off by default. [Vendored](#vendor) packages are never pruned. Orthogonal to `--mode` — combines with any mode. |
| `--detached` | With `--mode vendored`: skip all `.socket/manifest.json` writes — the vendor ledger embeds the patch records instead. For projects that want the vendored patches *only* in the lockfile + `.socket/vendor/`. |
| `--batch-size <n>` | Packages per API request (default: `100`) |
| `--all-releases` | Store patches for every release/distribution variant, not just the installed one — makes the manifest portable across environments (e.g. cross-platform CI caches) |
| `--vex <path>` | On a successful scan, also write an OpenVEX 0.2.0 document to this path. See [Inline VEX generation](#inline-vex-on-apply--scan--vendor). (env: `SOCKET_VEX`) |
| `--vex-product`, `--vex-no-verify`, `--vex-doc-id`, `--vex-compact` | Passthrough to the embedded VEX builder; mirror the standalone [`vex`](#vex) knobs. Inert unless `--vex` is set. |

> Use `--dry-run` to preview what a `--mode agent` / `--mode vendored` / `--mode hosted` run (with or without `--prune`) would do without mutating disk.

**Examples:**
```bash
# Scan local project (interactive prompt to apply)
socket-patch scan

# Scan with JSON output (discover + updates, no mutation)
socket-patch scan --json

# Agent mode: discover + apply patches in place (non-interactive)
socket-patch scan --json --mode agent --yes

# Bot mode: discover, apply, prune, sweep — all in one
socket-patch scan --json --mode agent --prune --yes

# Preview an agent-mode + prune run without mutating disk
socket-patch scan --json --mode agent --prune --yes --dry-run

# Scan only npm packages
socket-patch scan --ecosystems npm

# Scan global packages
socket-patch scan -g

# Agent mode + emit an OpenVEX attestation in one pass
socket-patch scan --json --mode agent --prune --yes --vex socket.vex.json

# Vendored mode: build + commit every patched dependency (see the vendor
# command). Works on a completely fresh clone: dependencies listed in the
# lockfile but not yet installed are fetched pristine from their registry and
# integrity-verified against the lockfile before vendoring.
socket-patch scan --json --mode vendored --yes

# Same, but keep the manifest out of it entirely
socket-patch scan --json --mode vendored --detached --yes

# Preview a vendored run (would_vendor / would_revendor / already_vendored)
socket-patch scan --json --mode vendored --yes --dry-run

# Hosted mode: rewrite lockfiles so patched deps resolve to Socket-hosted
# integrity-pinned packages — no artifact bytes in the repo, no CI changes.
socket-patch scan --json --mode hosted --yes
```

> Already-vendored packages are **skipped by plain `--mode agent`** (the committed artifact
> is the patch); a newer available patch still appears in the JSON `updates[]` array — re-run
> `scan --mode vendored` to take it.

### `apply`

Apply security patches from the local manifest.

**Usage:**
```bash
socket-patch apply [options]
```

**Command-specific options** (plus all [Global Options](#global-options)):
| Flag | Description |
|------|-------------|
| `-f, --force` | Skip pre-application hash verification (apply even if package version differs) |
| `--vex <path>` | On a successful apply, also write an OpenVEX 0.2.0 document to this path. See [Inline VEX generation](#inline-vex-on-apply--scan--vendor). (env: `SOCKET_VEX`) |
| `--vex-product`, `--vex-no-verify`, `--vex-doc-id`, `--vex-compact` | Passthrough to the embedded VEX builder; mirror the standalone [`vex`](#vex) knobs. Inert unless `--vex` is set. |

**Examples:**
```bash
# Apply patches
socket-patch apply

# Dry run
socket-patch apply --dry-run

# Apply only npm patches
socket-patch apply --ecosystems npm

# Apply in offline mode
socket-patch apply --offline

# JSON output for CI/CD
socket-patch apply --json

# Apply and emit an OpenVEX attestation in one step
socket-patch apply --vex socket.vex.json
```

> Packages managed by [`vendor`](#vendor) are skipped (`skipped`/`vendored` in JSON): the
> committed vendored artifact is the patch, so there is nothing for `apply` to do — even when
> the installed tree (e.g. `node_modules/`) is absent.

### `vendor`

`apply`'s **committable** sibling — the standalone command behind
[vendored mode](#choosing-a-patch-mode) (`scan --mode vendored` runs discovery + this engine in
one pass). Instead of patching installed packages in place
(machine-local state), `vendor` ejects each patched package into
`.socket/vendor/<ecosystem>/<patch-uuid>/…` and rewires your lockfile so the project consumes
the vendored copy. Commit `.socket/vendor/` plus the lockfile edits and **every fresh checkout
builds with the patched dependency** — no `socket-patch` binary, no Socket API access, no
install hook required on the consuming machine.

Supported ecosystems: **npm** (package-lock / yarn classic / yarn berry / pnpm / bun), **PyPI**
(uv / poetry / pdm / pipenv / requirements.txt), **RubyGems**, **Cargo**, **Go**,
**Composer**, **Maven** (single-module pom projects — multi-module aggregators and gradle-only
projects are refused), and **NuGet**. Vendoring is per-patch: only dependencies with a Socket
patch are vendored.

**Usage:**
```bash
socket-patch vendor [options]
```

**Command-specific options** (plus all [Global Options](#global-options)):
| Flag | Description |
|------|-------------|
| `-f, --force` | Skip pre-vendor hash verification (vendor even if the installed files differ from the patch's `beforeHash`) |
| `--revert` | Undo vendoring: restore the recorded original lockfile fragments byte-for-byte and remove the `.socket/vendor/` artifacts. Works without a manifest |
| `--vex <path>` | On a successful vendor, also write an OpenVEX 0.2.0 document to this path (env: `SOCKET_VEX`) |
| `--vex-product`, `--vex-no-verify`, `--vex-doc-id`, `--vex-compact` | Passthrough to the embedded VEX builder. Inert unless `--vex` is set. |

**How it interacts with the rest of the CLI** — once a package is vendored, `vendor` owns it:

- [`apply`](#apply) and [`rollback`](#rollback) skip vendored packages (they never touch a
  vendor-owned tree or lockfile entry).
- [`remove`](#remove) **reverts the vendoring** as part of removing the patch — lockfile
  restored, artifact deleted — so one command fully undoes it.
- [`scan`](#scan) skips downloading/applying patches for vendored packages and never prunes
  their manifest entries; newer patches show up in `updates[]` as the signal to re-run
  `scan --mode vendored`.
- [`vex`](#vex) attests vendored patches by verifying the **committed artifact** (marked
  `(vendored)` in the impact statement) — no `setup` install hook needed, because the lockfile
  wiring *is* the persistence mechanism.
- Re-running `vendor` is idempotent; patches dropped from the manifest are auto-reverted on the
  next run.

**Examples:**
```bash
# Vendor every patched dependency listed in the manifest
socket-patch vendor

# Preview without writing anything
socket-patch vendor --dry-run

# Then make it stick: commit the artifacts and the rewired lockfile
git add .socket/vendor package-lock.json && git commit -m "vendor Socket patches"

# Undo everything (restores the original lockfile byte-for-byte)
socket-patch vendor --revert

# JSON output for scripting
socket-patch vendor --json
```

> Prefer one command? [`scan --mode vendored`](#scan) discovers, downloads, *and* vendors in a single
> pass.

### `rollback`

Rollback patches to restore original files. If no identifier is given, all patches are rolled back. Packages managed by [`vendor`](#vendor) are excluded — their patch lives in the committed artifact, not the installed tree — and are listed in the JSON output's `vendored` array (use `remove` or `vendor --revert` to undo them).

**Usage:**
```bash
socket-patch rollback [identifier] [options]
```

**Command-specific options** (plus all [Global Options](#global-options)):
| Flag | Description |
|------|-------------|
| `--one-off` | Rollback by fetching original (`beforeHash`) files from the API — no manifest required |

**Examples:**
```bash
# Rollback all patches
socket-patch rollback

# Rollback a specific package
socket-patch rollback "pkg:npm/lodash@4.17.20"

# Rollback by UUID
socket-patch rollback 550e8400-e29b-41d4-a716-446655440000

# Dry run
socket-patch rollback --dry-run

# JSON output
socket-patch rollback --json
```

### `list`

List all patches in the local manifest.

**Usage:**
```bash
socket-patch list [options]
```

No command-specific options — see [Global Options](#global-options) (`--json`, `--manifest-path`, `--cwd` are the relevant ones).

**Examples:**
```bash
# List patches
socket-patch list

# JSON output
socket-patch list --json
```

**Sample Output:**
```
Found 2 patch(es):

Package: pkg:npm/lodash@4.17.20
  UUID: 550e8400-e29b-41d4-a716-446655440000
  Tier: free
  License: MIT
  Vulnerabilities (1):
    - GHSA-xxxx-yyyy-zzzz (CVE-2024-12345)
      Severity: high
      Summary: Prototype pollution in lodash
  Files patched (1):
    - lodash.js
```

### `remove`

Remove a patch from the manifest (rolls back files first by default). If the package is [vendored](#vendor), `remove` also **reverts the vendoring** — the lockfile is restored byte-for-byte and the `.socket/vendor/` artifact is deleted — so the patch is fully gone in one command. Detached-vendored patches (from `scan --mode vendored --detached`) are removable by PURL or UUID too, even though they have no manifest entry.

**Usage:**
```bash
socket-patch remove <identifier> [options]
```

**Arguments:**
- `identifier` - Package PURL (e.g., `pkg:npm/package@version`) or patch UUID

**Command-specific options** (plus all [Global Options](#global-options)):
| Flag | Description |
|------|-------------|
| `--skip-rollback` | Only update manifest, do not restore original files (for vendored packages this also leaves the vendor wiring + artifact in place) |

**Examples:**
```bash
# Remove by PURL
socket-patch remove "pkg:npm/lodash@4.17.20"

# Remove by UUID
socket-patch remove 550e8400-e29b-41d4-a716-446655440000

# Remove without rolling back files
socket-patch remove "pkg:npm/lodash@4.17.20" --skip-rollback

# JSON output
socket-patch remove "pkg:npm/lodash@4.17.20" --json
```

### `repair`

Download missing blobs and clean up unused blobs.

Alias: `gc`

`repair` cleans up the `.socket/` directory without running a scan — useful when you've manually adjusted the manifest, recovered from a partial-failure state, or just want to free space. For the combined workflow (discover + apply + GC in one pass), use `scan --mode agent --prune --json --yes` instead.

**Usage:**
```bash
socket-patch repair [options]
```

**Command-specific options** (plus all [Global Options](#global-options)):
| Flag | Description |
|------|-------------|
| `--download-only` | Only download missing artifacts, do not clean up (incompatible with `--offline`) |

**Examples:**
```bash
# Full repair (download missing + clean up unused)
socket-patch repair

# Cleanup only, no downloads
socket-patch repair --offline

# Download missing blobs only
socket-patch repair --download-only

# JSON output for scripting
socket-patch repair --json
```

### `unlock`

Inspect — and optionally release — the `.socket/apply.lock` advisory lock that the mutating commands (`apply`, `rollback`, `repair`, `remove`, `vendor`) take. Exits `0` when the lock is free and `1` when another socket-patch process holds it, so CI gates and monitoring can pattern-match the exit code without parsing JSON.

Reach for it when recovering from a crashed run that left a stale `apply.lock` behind: `unlock` tells you whether anything still holds the lock, and `unlock --release` deletes the file once it's confirmed free. A held lock is never released — for that scenario re-run the failing mutating command with [`--break-lock`](#global-options) (or wait for the holder with `--lock-timeout`).

**Usage:**
```bash
socket-patch unlock [options]
```

**Command-specific options** (plus all [Global Options](#global-options)):
| Flag | Description |
|------|-------------|
| `--release` | When the lock is free, also delete the lock file (it is normally retained across runs). Refused when the lock is held. (env: `SOCKET_UNLOCK_RELEASE`) |

**Examples:**
```bash
# Is anything holding the lock?
socket-patch unlock

# Free a stale lock left by a crashed run
socket-patch unlock --release

# JSON output for scripting
socket-patch unlock --json
```

### `setup`

Configure your project so patches are **re-applied automatically after install** — no manual `socket-patch apply` step in CI. `setup` is a one-time operation: run it, commit the change together with your `.socket/` patches, and every later install handles the rest. It is strictly **opt-in** — nothing is hooked unless you run `setup` and commit the result.

- **npm / yarn / pnpm / bun** — writes a `postinstall` script into `package.json` so any install re-applies patches (pnpm: root package only).
- **Python (pip / uv / poetry / pdm / hatch)** — Python has no universal post-install hook, so `setup` instead commits a **`socket-patch[hook]`** dependency (for classic Poetry, the equivalent `socket-patch = { extras = ["hook"] }`). Installing it lays down a startup `.pth` (shipped by the small `socket-patch-hook` wheel) that re-applies your committed `.socket/` patches the next time the interpreter runs. It is package-manager-agnostic (it rides the interpreter, not any one installer) and **fail-open** — a hook error can never break interpreter startup.
- **Ruby gems (Bundler)** — adds a managed `plugin "socket-patch"` block to the `Gemfile` and commits an in-tree Bundler plugin under `.socket/bundler-plugin/`. It re-applies patches on every `bundle install` (cached *and* fresh). (Requires the `socket-patch` CLI on `PATH`.)
- **Composer (PHP)** *(opt-in `composer` feature)* — appends `socket-patch apply` to `composer.json`'s `post-install-cmd` / `post-update-cmd` script events, so patches re-apply on every `composer install` / `composer update`. Only available in a build compiled with `--features composer`. (Requires the `socket-patch` CLI on `PATH`.)
- **Cargo & Go** — *apply-only, no `setup` hook.* A one-click auto-repatch-on-build isn't possible for these, so `setup` skips them. Patch with `socket-patch apply` directly: **cargo** patches the crate in place (in `vendor/` or the registry cache, rewriting `.cargo-checksum.json` so `cargo build` accepts it); **go** writes a project-local patched copy under `.socket/go-patches/` plus a `go.mod` `replace` directive (the module cache is `go.sum`-verified, so in-place patching can't build). Commit `go.mod` + `.socket/go-patches/` so a clone builds the patched bytes. Declare them in `setup.manual` for VEX attestation.
- **Apply-only ecosystems** (nuget · maven · deno) — no native install hook to wire, so `setup` reports `no_files`; patch them on demand with `socket-patch apply`.

**Usage:**
```bash
socket-patch setup            # configure (interactive)
socket-patch setup --check    # verify configured; non-zero exit if not (CI gate)
socket-patch setup --remove   # revert what setup added
```

**Command-specific options** (plus all [Global Options](#global-options) — `--dry-run`, `--yes`, `--json`, `--cwd`):
| Flag | Description |
|------|-------------|
| `--check` | Read-only verification that every manifest is configured; exits non-zero if any still needs setup. Never writes (safe in CI). Conflicts with `--remove`. |
| `--remove` | Revert the install hooks `setup` added (npm `package.json` scripts, the Python `socket-patch[hook]` dependency, and the gem Bundler plugin wiring). |

#### Disabling / opting out (Python hook)

The Python hook is designed to be easy to skip or remove:

- **Per interpreter / CI step:** set `SOCKET_PATCH_HOOK=off` (or `SOCKET_NO_HOOK=1`). This is checked *before any hook code runs*, so it fully bypasses the hook for that process.
- **Remove from a project:** `socket-patch setup --remove`, then `pip uninstall socket-patch-hook`.
- **Never opted in:** if you don't run `setup`, there is no hook — it is opt-in by design.

#### What the Python hook does, and its safety model

On interpreter startup, *only when the set of installed packages changed*, the hook runs `socket-patch apply --offline --ecosystems pypi` for the project that owns the current virtualenv, re-applying only the patches committed in that project's `.socket/`. Specifically:

- It is **anchored to the virtualenv** it is installed in (not the working directory), so a `python` started from an unrelated directory cannot pull in a foreign `.socket/manifest.json`.
- It **verifies each file's hash before patching** and **never writes outside the installed package directory** (path-escaping manifest keys are refused).
- It resolves the `socket-patch` binary from the **installed `socket-patch` package** (not from `PATH`), so an unexpected binary on `PATH` is not executed.
- It runs **offline** (no network at startup) and is **fail-open** (any error is swallowed; it can never abort the interpreter).

**Examples:**
```bash
# Interactive setup (all detected ecosystems, auto-detected)
socket-patch setup

# Non-interactive
socket-patch setup -y

# Preview changes
socket-patch setup --dry-run

# Verify configuration in CI (exits non-zero if not set up)
socket-patch setup --check

# JSON output for scripting
socket-patch setup --json -y
```

### `vex`

Generate an [OpenVEX](https://github.com/openvex) 0.2.0 attestation describing the vulnerabilities that the applied patches have mitigated. See [OpenVEX attestations](#openvex-attestations) below for the full workflow.

**Usage:**
```bash
socket-patch vex [options]
```

**Command-specific options** (plus all [Global Options](#global-options)):
| Flag | Description |
|------|-------------|
| `-O, --output <path>` | Write the VEX document to this path instead of stdout. Required when combined with `--json`. (env: `SOCKET_VEX_OUTPUT`) |
| `--product <id>` | Override the auto-detected top-level product PURL/identifier. (env: `SOCKET_VEX_PRODUCT`) |
| `--no-verify` | Skip the on-disk file-hash check and trust the manifest — useful on a build machine that doesn't have the patched files laid out. (env: `SOCKET_VEX_NO_VERIFY`) |
| `--doc-id <id>` | Override the document `@id`. Default is a random `urn:uuid:<v4>` regenerated each run; pin this for a reproducible identifier. (env: `SOCKET_VEX_DOC_ID`) |
| `--compact` | Emit compact JSON instead of pretty-printed. (env: `SOCKET_VEX_COMPACT`) |

**Examples:**
```bash
# Print a VEX document to stdout (human-readable status goes to stderr)
socket-patch vex

# Write the document to a file
socket-patch vex --output socket.vex.json

# CI shape: VEX doc to file, machine-readable envelope to stdout
socket-patch vex --json --output socket.vex.json

# Generate on a build box without verifying on-disk files
socket-patch vex --no-verify --output socket.vex.json
```

### Undoing things

Six commands undo different layers of socket-patch state — pick by what you want back:

| Command | What it undoes |
|---------|----------------|
| [`rollback`](#rollback) | Restores the original file bytes but **keeps the manifest entry** — the next `apply` re-applies the patch |
| [`remove`](#remove) | Rollback **plus** deletes the manifest entry and reverts any vendoring — **permanent**, the patch is fully gone in one command |
| [`vendor --revert`](#vendor) | **Un-vendors wholesale**: restores the recorded original lockfile fragments byte-for-byte and removes the `.socket/vendor/` artifacts — works without a manifest |
| [`scan --prune`](#scan) | **Reconciles, doesn't reverse**: drops manifest entries for packages no longer installed and garbage-collects orphan blob/diff/archive files — installed patches stay |
| [`repair`](#repair) (alias `gc`) | **Restores health, not originals**: re-downloads missing blobs, rebuilds missing/corrupt vendored artifacts, and cleans up unused ones |
| [`unlock --release`](#unlock) | **Frees a stale lock** left by a crashed run — never touches patches or the manifest, and refuses while the lock is held |

## OpenVEX attestations

`socket-patch vex` turns your local manifest into a signed-off statement of *which known vulnerabilities no longer affect your build* because a Socket patch has been applied. This lets vulnerability scanners stop flagging CVEs that you've already remediated in place — without bumping the package version.

**How it works**

1. Reads `.socket/manifest.json` and, unless `--no-verify` is passed, re-checks each patched file's hash on disk so the attestation only covers patches that are actually applied. [Vendored](#vendor) patches are verified against the **committed artifact** instead of the installed tree (their impact statement carries a `(vendored)` marker), and need no `setup` install hook to be attested — the lockfile wiring is the persistence mechanism. Detached-vendored patches (`scan --mode vendored --detached`) attest from the vendor ledger's embedded records, and [hosted-mode](#choosing-a-patch-mode) patches attest from the redirect ledger (`.socket/vendor/redirect-state.json`, marker `(redirected)` — hash-verified against the installed tree post-install), so `vex` works even with no manifest file at all.
2. Auto-detects the top-level **product** identifier (override with `--product`), probing in order:
   - `.git/config` `[remote "origin"]` → `pkg:github/<owner>/<repo>` (similar for GitLab/Bitbucket; raw URL otherwise)
   - `package.json` → `pkg:npm/<name>@<version>`
   - `pyproject.toml` → `pkg:pypi/<name>@<version>`
   - `Cargo.toml` → `pkg:cargo/<name>@<version>`
3. Emits an OpenVEX 0.2.0 document whose statements mark each mitigated vulnerability as `not_affected` (justification: the patch is present), suitable for piping into `vexctl`, Grype, Trivy, and similar tools.

**Provenance markers**

Each statement's impact string records *how* the patch is persisted — one marker per [patch mode](#choosing-a-patch-mode):

| Impact statement | Mode | What the evidence is | What a consumer should do |
|---|---|---|---|
| `Patched via Socket patch <uuid>` | agent | The installed tree: every patched file's hash was verified against the manifest's `afterHash` | Trust the statement as long as the agent install hook (or a CI `apply`) keeps re-applying; ecosystems without a hook must be declared in `setup.manual` |
| `Patched via Socket patch <uuid> (vendored)` | vendored | The **committed** `.socket/vendor/` artifact was hash-verified — no install hook needed; the lockfile wiring is the persistence mechanism | Trust it on any checkout; the committed bytes are the patch |
| `Patched via Socket patch <uuid> (redirected)` | hosted | The lockfile's integrity pin points at the Socket-hosted patched package. When emitted in-run by `scan --mode hosted --vex`, the statement is attested **from the redirect ledger without hash verification** (the bytes are fetched at install time — the JSON `vex` summary carries `verified: false`) | Ensure installs still resolve from `patch.socket.dev` (the lockfile edit is intact), and run `socket-patch vex` **after installing** — it re-reads the ledger and hash-verifies the redirected patches against the installed tree |

The markers are stable strings (see `CLI_CONTRACT.md`); scanners and policy engines may match on them.

**Output channels**

| Invocation | VEX document | stdout |
|------------|--------------|--------|
| _default_ (no `--output`, no `--json`) | stdout | human-readable status on stderr |
| `--output <path>` | the file | one-line summary |
| `--json --output <path>` | the file | machine-readable envelope (the CI shape) |

`--json` requires `--output`, since the VEX document is itself JSON and would otherwise collide with the envelope on stdout.

**Using it with a scanner**

```bash
# Generate the attestation as part of CI, then hand it to a scanner
socket-patch vex --output socket.vex.json

# Suppress already-patched findings in Grype
grype <image-or-dir> --vex socket.vex.json

# Or with Trivy
trivy image --vex socket.vex.json <image>
```

Run `socket-patch get` or `socket-patch scan --mode agent --prune` first — `vex` errors with `no_patches` when there is nothing to attest (an empty manifest and no detached-vendored patches).

### Inline VEX on `apply` / `scan` / `vendor`

You don't need a separate `vex` invocation: pass `--vex <path>` to `apply`, `scan`, or `vendor` and the same OpenVEX document is generated as a side-effect of a successful run.

```bash
# Patch and attest in one step
socket-patch apply --vex socket.vex.json

# Discover, apply, prune, and attest — the full bot-mode pass
socket-patch scan --json --mode agent --prune --yes --vex socket.vex.json

# Vendor and attest — works manifest-less with --detached too
socket-patch scan --json --mode vendored --yes --vex socket.vex.json
```

The `--vex-product`, `--vex-no-verify`, `--vex-doc-id`, and `--vex-compact` flags mirror the standalone command's `--product` / `--no-verify` / `--doc-id` / `--compact` knobs.

Contract:

- The document is **always written to the file** (never stdout), so it never collides with the command's own `--json` output. JSON mode adds a top-level `vex` summary — `{ path, statements, format }` — to the envelope (`apply`) / result (`scan`).
- It's built from the manifest **as it stands after the run** (including any `--mode agent` writes, with or without `--prune`) and verified against on-disk state unless `--vex-no-verify` is set. Generated for real applies, `--dry-run`, and read-only scans alike.
- **Fail-the-command:** if `--vex` was requested but generation fails (no detectable product, empty/missing manifest, nothing verified, unwritable path), the command exits non-zero **even when the apply/scan itself succeeded**, with a stable error code in the JSON output.

## Scripting & CI/CD

All commands support `--json` for machine-readable output. JSON responses always include a `"status"` field for easy error detection:

```bash
# Check for available patches in CI (read-only)
result=$(socket-patch scan --json --ecosystems npm)
patches=$(echo "$result" | jq '.totalPatches')

# Auto-update bot mode: discover, apply, prune, sweep in one pass
socket-patch scan --json --mode agent --prune --yes | jq '{
  applied:     [.apply.patches[] | select(.action == "added" or .action == "updated") | .purl],
  pruned:      .gc.prunedManifestEntries,
  bytes_freed: .gc.bytesFreed
}'
# Pipe this into peter-evans/create-pull-request to open a PR with the changes.

# Apply patches and check result
socket-patch apply --json | jq '.status'
# "success", "partial_failure", "no_manifest", or "error"
```

When stdin is not a TTY (e.g., in CI pipelines), interactive prompts auto-proceed instead of blocking. Progress indicators and ANSI colors are automatically suppressed when output is piped.

## Environment Variables

Every [Global Option](#global-options) has a matching `SOCKET_*` environment variable (listed in that table), and `vex`-specific flags map to `SOCKET_VEX_*`. The most commonly used variables are:

| Variable | Description |
|----------|-------------|
| `SOCKET_API_TOKEN` | API authentication token. Use the raw token (`sktsec_<...>_api`) shown when it was generated, **not** the SHA-512 hash (`sha512-...`) that the dashboard may also display for identification. |
| `SOCKET_ORG_SLUG` | Default organization slug |
| `SOCKET_API_URL` | API base URL (default: `https://api.socket.dev`) |

## Manifest Format

Downloaded patches are stored in `.socket/manifest.json`:

```json
{
  "patches": {
    "pkg:npm/package-name@1.0.0": {
      "uuid": "unique-patch-id",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {
        "path/to/file.js": {
          "beforeHash": "git-sha256-before",
          "afterHash": "git-sha256-after"
        }
      },
      "vulnerabilities": {
        "GHSA-xxxx-xxxx-xxxx": {
          "cves": ["CVE-2024-12345"],
          "summary": "Vulnerability summary",
          "severity": "high",
          "description": "Detailed description"
        }
      },
      "description": "Patch description",
      "license": "MIT",
      "tier": "free"
    }
  }
}
```

Patched file contents are in `.socket/blob/` (named by git SHA256 hash).

## Supported Platforms

| Platform | Architecture |
|----------|-------------|
| macOS | ARM64 (Apple Silicon), x86_64 (Intel) |
| Linux | x86_64, ARM64, ARMv7, i686 |
| Windows | x86_64, ARM64, i686 |
| Android | ARM64 |
