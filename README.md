# Socket Patch CLI

Fix known vulnerabilities in the dependencies you already have — without waiting for an
upstream release, and without a risky version bump.

Socket's security team backports minimal fixes to the *exact versions* of packages you
have installed. The `socket-patch` CLI finds which of your dependencies have a patch
available and applies it, verifying every changed file by hash. It works across npm,
PyPI, Cargo, Go, RubyGems, Maven, Composer, NuGet, and Deno, and it can persist the patches
whichever way fits your workflow: re-applied by the CLI, committed to your repo, or
pinned in your lockfile. When you're done, it can emit an [OpenVEX
attestation](#openvex-attestations) so your vulnerability scanner stops flagging the
CVEs you've already fixed.

**Contents:** [Installation](#installation) · [Five-minute tutorial](#five-minute-tutorial)
· [How it works](#how-socket-patch-works) · [Common tasks](#common-tasks)
· [Command reference](#command-reference) · [OpenVEX](#openvex-attestations)
· [Scripting & CI/CD](#scripting--cicd) · [Manifest format](#manifest-format)
· [Ecosystem support →](docs/ecosystems.md)

## Installation

One-line install (macOS / Linux):

```bash
curl -fsSL https://raw.githubusercontent.com/SocketDev/socket-patch/main/scripts/install.sh | sh
```

Detects your platform (macOS/Linux, x64/ARM64), downloads the latest binary, and installs
to `/usr/local/bin` or `~/.local/bin`. Use `sudo sh` instead of `sh` if `/usr/local/bin`
requires root.

On Windows, install via npm (below) or grab a prebuilt `socket-patch-*-pc-windows-msvc.zip`
from the [latest release](https://github.com/SocketDev/socket-patch/releases/latest).

Or install through your package manager:

| Package manager | Command |
|-----------------|---------|
| npm | `npm install -g @socketsecurity/socket-patch` (or one-shot: `npx @socketsecurity/socket-patch`) |
| pip | `pip install socket-patch` |
| cargo | `cargo install socket-patch-cli` (builds from source with every ecosystem compiled in) |
| gem | `gem install socket-patch` |
| composer | `composer require socketsecurity/socket-patch` (run as `vendor/bin/socket-patch`) |

The gem and composer packages are thin launchers: on first run they download the prebuilt
binary for your platform from the matching GitHub release, verify its SHA-256, cache it,
and exec it. Set `SOCKET_PATCH_BIN` to an existing binary to skip the download.

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
curl -fsSL https://github.com/SocketDev/socket-patch/releases/latest/download/socket-patch-aarch64-unknown-linux-musl.tar.gz | tar xz
```

The musl builds are fully static and run on any distro; glibc (`-gnu`) variants are also
on the releases page, alongside Windows (`socket-patch-x86_64-pc-windows-msvc.zip`) and
other targets.

Then move the binary onto your `PATH`:

```bash
sudo mv socket-patch /usr/local/bin/
```

The full list of prebuilt targets (Windows, 32-bit ARM, i686, Android) is in
[docs/ecosystems.md](docs/ecosystems.md#supported-platforms).

</details>

## Five-minute tutorial

No account or token is needed to follow along — without an API token the CLI talks to
Socket's public patch proxy, which serves the free tier of patches anonymously. (An API
token unlocks your organization's patch tier; if you've already run `socket login` with
the [Socket CLI](https://docs.socket.dev/docs/socket-cli), socket-patch picks it up
automatically — see [Configuration sources](#configuration-sources).)

**1. Scan your project.** From your project root, ask Socket which of your installed
dependencies have patches available:

```bash
cd your-project
socket-patch scan
```

`scan` crawls the installed packages it finds (`node_modules/`, virtualenvs, the cargo
registry cache, and so on), queries the patch database, prints each available patch with
its package, severity, and CVE/GHSA identifiers, and asks whether to apply. Say yes and
the vulnerable files are rewritten in place — each file is hash-verified before and after
the edit.

> If it prints `No patches available for installed packages.`, none of your installed
> dependency versions currently has a Socket patch — the good outcome, with nothing to
> apply. To walk the rest of the loop anyway, make a scratch project pinned to a version
> that has a free patch — at the time of writing, `flatted@3.3.1`:
>
> ```bash
> mkdir demo && cd demo && git init -q && npm init -y && npm install flatted@3.3.1 && socket-patch scan
> ```
>
> (The patch catalog changes over time; if that finds nothing, pick another patched
> version.)

**2. See what you have.** The applied patches are recorded in `.socket/manifest.json`:

```bash
socket-patch list
```

```
Found 1 patch(es):

Package: pkg:npm/flatted@3.3.1
  UUID: 5cac955f-eab1-4d29-8f4f-c408a6cc9647
  ...
  Vulnerabilities (1):
    - GHSA-25h7-pfq9-p65f (CVE-2026-32141)
      Severity: HIGH
```

**3. Make it stick.** Patches applied in place don't survive a reinstall — the next
`npm install` (or `pip install`, `bundle install`, …) restores the vulnerable upstream
bytes. Commit the `.socket/` directory and wire an install hook so patches re-apply
automatically:

```bash
socket-patch setup           # e.g. adds a postinstall script for npm projects
echo '.socket/apply.lock' >> .gitignore   # lock state, not part of the patch record
git add .gitignore .socket package.json   # npm example — setup prints which files it changed
git commit -m "apply Socket security patches"
```

From now on, every install — yours, your teammates', CI's — re-applies the patches. You
can also re-apply manually at any time with `socket-patch apply` (it's idempotent).

**4. Undo, if you want.** Remove a patch completely (restores the original files and
deletes the manifest entry):

```bash
socket-patch remove "pkg:npm/flatted@3.3.1"
```

That's the whole loop: **scan → apply when prompted → setup → commit**. This tutorial used the default
*agent* mode, where the CLI re-applies patches after each install. There are two other
ways to persist patches — committing the patched packages themselves (*vendored*) or
pinning them in your lockfile (*hosted*) — and choosing between the three is the next
section.

## How Socket Patch works

**A patch** is a minimal fix — usually the upstream security fix, backported — for one
exact published version of a package. Socket distributes it as per-file edits: for each
touched file, the hash of the expected original (`beforeHash`), the hash of the patched
result (`afterHash`), and the replacement content. By default, a file whose current
content matches neither the expected original nor the patched result is overwritten with
the full verified patched content plus a stderr warning (`content_mismatch_overwritten`);
pass `--strict` (a [global option](#global-options)) to fail closed on mismatch instead,
or `apply --force` to skip pre-application hash verification entirely (see
[`apply`](#apply)). Either way the CLI verifies the result after writing. Patches are looked up by package URL
([PURL](https://github.com/package-url/purl-spec)) — e.g. `pkg:npm/lodash@4.17.20` — so
everything is keyed to exact versions.

**Local state lives in `.socket/`** at your project root, and is designed to be
committed:

| Path | Contents |
|------|----------|
| `.socket/manifest.json` | The record of downloaded patches: PURLs, file hashes, vulnerability metadata ([format](#manifest-format)) |
| `.socket/blobs/` | Patched file contents, named by git-sha256 hash |
| `.socket/vendor/` | Vendored package artifacts and the vendor/redirect ledgers (only in vendored/hosted modes) |

> Mutating commands also leave a `.socket/apply.lock` file there between runs. It is
> lock state, not part of the patch record — add it to your `.gitignore`
> ([`repair`](#repair) deletes it).

### Three patch modes

The same patched bytes can reach your build three different ways. The modes differ in
*where the patch lives* and *what must happen at install time*; pick one per project
(`scan --mode <name>` drives exactly one mode per run).

| Mode | Where the patch lives | Install-time requirement | Trade-off |
|------|----------------------|--------------------------|-----------|
| **agent** — `scan --mode agent` (or [`apply`](#apply)) | `.socket/` manifest + blobs, committed; the CLI re-applies after each install | The `socket-patch` CLI must run (install hook via [`setup`](#setup), or an `apply` step in CI) | Small repo footprint (per-file blobs, not whole packages); no lockfile edits; the only mode that needs CI / install-hook changes |
| **vendored** — `scan --mode vendored` (or [`vendor`](#vendor)) | Patched packages committed under `.socket/vendor/`; the lockfile is rewired to consume them | **None** — the package manager installs the committed bytes | Fully airgapped and hermetic, at the cost of repo size |
| **hosted** — `scan --mode hosted` | No patched bytes in your repo: the lockfile is rewritten so **only** the patched dependencies resolve to Socket-hosted, integrity-pinned packages on `patch.socket.dev`; the edits + patch records are ledgered in `.socket/vendor/redirect-state.json` (commit it — [`vex`](#vex) reads it, and it records the pre-redirect originals a future revert feature will need; hosted has no CLI revert yet, see [Undo things](#undo-things)) | Installs must be able to reach `patch.socket.dev` (no CLI, no install hook) | Smallest possible diff (lockfile + ledger); not for airgapped installs |

Every mode pins the patched bytes: in agent mode the CLI verifies every file on each
apply; vendored and hosted modes lean on your package manager's own lockfile integrity
checks (sha512 / sha256 / contentHash / CHECKSUMS) where the ecosystem enforces them —
hosted Maven, which has no lockfile, gets a fail-closed version-suffixing scheme instead.
A few combinations have weaker install-time pins (vendored Maven, NuGet without a
lockfile, Go's directory replaces, pipenv's Pipfile.lock) — there the committed bytes
are the protection; see the [per-ecosystem caveats](docs/ecosystems.md).

**Choosing:** *agent* is the original method and remains fully supported, but it is the
only mode that requires CI / install-hook modification — **new projects should prefer
hosted or vendored**. Pick *vendored* if your builds are airgapped or you don't want an
infrastructure dependency; pick *hosted* if you want the smallest diff and your installs
can reach `patch.socket.dev`. (Hosted is the planned default for GitHub-app patch PRs —
it keeps the PR diff small.)

Mode support varies by ecosystem — e.g. Go can't do hosted, Rush monorepos can't do
vendored. See the full **[mode × ecosystem matrix](docs/ecosystems.md#mode--ecosystem-matrix)**
for details and per-ecosystem caveats.

## Common tasks

### Patch everything that can be patched

```bash
socket-patch scan              # interactive: prompts before applying
socket-patch scan --json --mode agent --yes    # non-interactive (CI, scripts)
```

### Patch one specific CVE, advisory, or package

```bash
socket-patch get CVE-2024-12345
socket-patch get GHSA-xxxx-yyyy-zzzz
socket-patch get lodash                  # fuzzy-matches installed packages
socket-patch get "pkg:npm/lodash@4.17.20"
```

`socket-patch <uuid>` with a bare patch UUID is a shortcut for `get <uuid>`.

### Keep patches applied across installs

```bash
socket-patch setup             # wire install hooks (npm postinstall, Python .pth, …)
socket-patch setup --check     # CI gate: exit non-zero if hooks are missing or a patch drifted
```

See [`setup`](#setup) for what gets wired per ecosystem — and which ecosystems (Cargo,
Go, Maven, NuGet, Deno) have no hook and are patched on demand instead.

### Persist patches with no CI or install-hook changes (vendored / hosted)

```bash
# Vendored: commit the patched packages themselves (airgap-friendly)
socket-patch scan --json --mode vendored --yes
echo '.socket/apply.lock' >> .gitignore
git add .gitignore .socket package-lock.json # your lockfile may differ

# Hosted: smallest diff — patched deps resolve from patch.socket.dev
socket-patch scan --json --mode hosted --yes
git add .socket/vendor/redirect-state.json package-lock.json
```

No `setup` hook or CI `apply` step is needed — the package manager installs the patched
bytes. See [Three patch modes](#three-patch-modes) to choose, and the
[mode × ecosystem matrix](docs/ecosystems.md#mode--ecosystem-matrix) for what your
ecosystem supports.

### Run an auto-update bot in CI

One command discovers, applies, and garbage-collects in a single pass:

```bash
socket-patch scan --json --mode agent --prune --yes
```

The working-tree changes (the `.socket/` directory — plus lockfile edits if your bot
runs `--mode vendored` or `--mode hosted`) are what your PR tooling commits — e.g.
`peter-evans/create-pull-request` picks them up automatically; use the JSON summary for
the PR title/body. See [Scripting & CI/CD](#scripting--cicd).

### Tell your vulnerability scanner about the patches

```bash
socket-patch vex --output socket.vex.json
grype <image-or-dir> --vex socket.vex.json     # or trivy image --vex ...
```

The OpenVEX document marks each patched CVE `not_affected`, so scanners stop flagging
vulnerabilities you've already remediated. You can also emit it inline from `apply` /
`scan` / `vendor` with `--vex <path>`. Details in [OpenVEX
attestations](#openvex-attestations).

### Work offline / airgapped

Vendored mode needs no Socket infrastructure and no `socket-patch` binary at install
time — the patched packages install from the committed bytes (other, unvendored
dependencies still resolve from your registry or mirror as usual). Agent mode works
offline once the blobs are committed:

```bash
socket-patch apply --offline   # strict airgap: fails loudly if anything needs the network
```

`scan` and `get` inherently need the network and refuse to run with `--offline`.

### Undo things

Five commands clean up different layers — the first three undo, the last two reconcile
and repair; pick by what you want back:

| Command | What it does |
|---------|--------------|
| [`rollback`](#rollback) | Restores the original file bytes but **keeps the manifest entry** — the next `apply` re-applies the patch |
| [`remove`](#remove) | Everything `rollback` does, **plus** it deletes the manifest entry and reverts any vendoring — **permanent**, the patch is fully gone in one command |
| [`vendor --revert`](#vendor) | **Un-vendors wholesale**: restores the recorded original lockfile fragments byte-for-byte and removes the `.socket/vendor/` artifacts — works without a manifest |
| [`scan --prune`](#scan) | **Reconciles, doesn't reverse**: drops manifest entries for packages that have left the project and garbage-collects orphan blob/diff/archive files — installed patches stay |
| [`repair`](#repair) (alias `gc`) | **Restores health, not originals**: re-downloads missing blobs, rebuilds missing/corrupt vendored artifacts, cleans up unused ones, and removes the leftover `apply.lock` file (housekeeping — mutating commands leave it behind after every run) |

And `setup --remove` reverts the install hooks that `setup` added.

> Hosted mode has no CLI revert yet: `scan --mode hosted` makes plain lockfile /
> registry-config edits, so undo them with your version control (e.g.
> `git checkout -- <lockfile>`) and delete the `.socket/vendor/redirect-state.json`
> ledger — once you've reverted by hand, its recorded original fragments are stale, and
> a leftover ledger would still let [`vex`](#vex) attest the removed redirects.

## Command reference

| Command | What it does |
|---------|--------------|
| [`scan`](#scan) | Scan installed packages for available security patches |
| [`apply`](#apply) | Apply security patches from the local manifest |
| [`vex`](#vex) | Generate an OpenVEX attestation for the applied patches |
| [`vendor`](#vendor) | Eject patched dependencies into committable `.socket/vendor/` |
| [`setup`](#setup) | Wire install hooks so patches re-apply automatically |
| [`rollback`](#rollback) | Restore original files (keeps the manifest) |
| [`get`](#get) | Fetch and apply a patch by UUID / CVE / GHSA / PURL / name (alias: `download`) |
| [`list`](#list) | List all patches in the local manifest |
| [`remove`](#remove) | Remove a patch: roll back files + delete the manifest entry |
| [`repair`](#repair) | Download missing blobs, clean up unused ones, tidy lock state (alias: `gc`) |

### Global options

These flags are accepted by **every** subcommand and go after the command name —
`socket-patch <command> --json --cwd ./app` works uniformly (`socket-patch --json
<command>` is a parse error). A command silently ignores any global flag it doesn't use
(e.g. `list --global` parses fine and the flag is a no-op).

Each flag has a matching `SOCKET_*` environment variable, listed in the table;
command-specific flags list theirs in each command's own table. **Precedence is CLI arg
> env var > default** — with one extra fallback layer for the three authentication
settings, described next.

### Configuration sources

For the three authentication settings, the [Socket CLI](https://docs.socket.dev/docs/socket-cli)'s
persisted login sits between the env var and the built-in default — run `socket login`
(or `socket config set apiToken` / `defaultOrg`) once and socket-patch picks it up too.
Resolution is per key, and an empty value means "unset" at every layer:

```
--api-token / --org / --api-url
  1. CLI flag
  2. Env var           SOCKET_API_TOKEN / SOCKET_ORG_SLUG / SOCKET_API_URL
  3. Peer alias env    SOCKET_CLI_API_TOKEN / SOCKET_CLI_ORG_SLUG / SOCKET_CLI_API_BASE_URL
  4. socket-cli config <data dir>/socket/settings/config.json — read-only
                       (Linux: ~/.local/share; macOS: ~/Library/Application Support
                        then legacy ~/.local/share, both after $XDG_DATA_HOME;
                        Windows: %LOCALAPPDATA%)
  5. Built-in default  no token → public proxy; org → auto-resolve; https://api.socket.dev
```

Two env-only toggles adjust this: `SOCKET_NO_API_TOKEN=1` ignores ambient tokens (env +
config; an explicit `--api-token` still wins) — useful to force the anonymous public
proxy in CI or a test run — and `SOCKET_NO_CONFIG=1` disables the config-file layer
entirely. socket-patch never *writes* the config file, and a corrupt one only produces a
stderr warning — it never breaks a command or pollutes `--json` output. socket-patch
does **not** read `.env` files or any per-repository config for endpoints or
credentials: a cloned repo must never be able to redirect where patches come from or
spend your token. (Full rationale: [docs/design/configuration.md](docs/design/configuration.md).)

| Flag | Env var | Description |
|------|---------|-------------|
| `--cwd <dir>` | `SOCKET_CWD` | Working directory (default: `.`). The manifest path is resolved relative to this. |
| `--manifest-path <path>` | `SOCKET_MANIFEST_PATH` | Path to the patch manifest, resolved relative to `--cwd` (default: `.socket/manifest.json`). |
| `--api-url <url>` | `SOCKET_API_URL` | Socket API URL for the authenticated endpoint (default: `https://api.socket.dev`). |
| `--api-token <token>` | `SOCKET_API_TOKEN` | Socket API token — optional. The easiest setup is `socket login` with the [Socket CLI](https://docs.socket.dev/docs/socket-cli) (see [Configuration sources](#configuration-sources)); to set it directly, create a token in the [Socket dashboard](https://socket.dev) under your organization's API tokens settings and use the raw token (`sktsec_<...>_api`) shown at generation time, **not** the `sha512-...` display hash. When no token resolves from any source, the anonymous public patch proxy is used (free patches). |
| `-o, --org <slug>` | `SOCKET_ORG_SLUG` | Organization slug. Auto-resolved when omitted and a token is set. |
| `--proxy-url <url>` | `SOCKET_PROXY_URL` | Public proxy URL used when no API token is set (default: `https://patches-api.socket.dev`). |
| `-e, --ecosystems <list>` | `SOCKET_ECOSYSTEMS` | Restrict to specific ecosystems (comma-separated, e.g. `npm,pypi`). Unknown names are rejected. |
| `--download-mode <mode>` | `SOCKET_DOWNLOAD_MODE` | Artifact to fetch when local files are missing: `diff` (default, smallest delta), `package` (full per-package tarball), or `file` (legacy per-file blobs). |
| `--vendor-source <mode>` | `SOCKET_VENDOR_SOURCE` | How `vendor` acquires the installable artifact: `auto` (default — download the prebuilt package from patch.socket.dev, fall back to a local build on any miss), `service` (require the service, fail-closed), or `build` (always build locally). Covers npm, pypi, cargo, golang, composer, gem, nuget, and maven. |
| `--vendor-url <url>` | `SOCKET_VENDOR_URL` | Base host for the vendoring service's package-reference request (default: the active `--api-url`/`--proxy-url` base). Point at staging / local dev for testing. |
| `--patch-server-url <url>` | `SOCKET_PATCH_SERVER_URL` | Override the host of the prebuilt-archive download URL the service returns (default: as returned). Mainly for local-dev / testing. |
| `--offline` | `SOCKET_OFFLINE` | Strict airgap: never contact the network. Operations that need remote data fail loudly. |
| `--strict` | `SOCKET_STRICT` | Fail-closed on before-hash mismatches instead of the default warn-and-overwrite: a file whose current content matches neither `beforeHash` nor `afterHash` aborts that package's apply. Overridden by `--force`. |
| `-g, --global` | `SOCKET_GLOBAL` | Operate on globally-installed packages. |
| `--global-prefix <path>` | `SOCKET_GLOBAL_PREFIX` | Override the path used to discover globally-installed packages. |
| `-j, --json` | `SOCKET_JSON` | Emit machine-readable JSON output. Every JSON response includes a `"status"` field — camelCase on the envelope commands (`"success"`, `"error"`, `"noManifest"`, `"partialFailure"`, `"paidRequired"`, `"notFound"`; apply/list/repair/remove/vendor), snake_case on the legacy shapes (`"partial_failure"`, `"not_found"`; get/scan/rollback/setup). See [CLI_CONTRACT.md](crates/socket-patch-cli/CLI_CONTRACT.md) for the exact shapes. |
| `-v, --verbose` | `SOCKET_VERBOSE` | Show extra detail in human-readable output. |
| `-s, --silent` | `SOCKET_SILENT` | Suppress non-error output. |
| `--dry-run` | `SOCKET_DRY_RUN` | Preview the operation without making any mutations. |
| `-y, --yes` | `SOCKET_YES` | Skip interactive confirmation prompts. |
| `--lock-timeout <secs>` | `SOCKET_LOCK_TIMEOUT` | Seconds to wait for `.socket/apply.lock` before giving up. `0`/unset = a single non-blocking try; a positive value retries with backoff. Only meaningful for mutating commands (`apply`, `rollback`, `repair`, `remove`). |
| `--debug` | `SOCKET_DEBUG` | Emit verbose debug logs to stderr. |
| `--no-telemetry` | `SOCKET_TELEMETRY_DISABLED` | Disable anonymous usage telemetry. |

The sections below list only each command's **command-specific** flags.

### `scan`

Scan installed packages for available security patches — and, with `--mode`, act on what
it finds. `scan` is the entry point for all three [patch modes](#three-patch-modes):

- `--mode agent` downloads and applies the selected patches in place;
- `--mode vendored` discovers, downloads, and builds + wires the committable
  `.socket/vendor/` artifacts in one pass (re-vendoring automatically when a newer patch
  is selected);
- `--mode hosted` rewrites lockfiles / registry configs so only the patched dependencies
  resolve to Socket-hosted packages.

Without a mode, interactive `scan` prompts before applying, and `scan --json` is
read-only (discovery plus an `updates[]` array; no mutation).

`scan --mode agent --prune` is the single command bots need for full auto-update: it
discovers patches, applies them, and garbage-collects orphan blob files plus manifest
entries for uninstalled packages — all in one invocation.

**Usage:**
```bash
socket-patch scan [options]
```

**Command-specific options** (plus all [Global options](#global-options)):
| Flag | Env var | Description |
|------|---------|-------------|
| `--mode <hosted\|vendored\|agent>` | — | Selects one of the three [patch modes](#three-patch-modes), summarized above. Combining `--mode` with a legacy boolean flag of a *different* mode is an error (exit 2); the same mode spelled both ways is accepted. |
| `--prune` | — | Garbage-collect after the scan: remove manifest entries for packages no longer present in the crawl (installed trees + lockfiles — a wiped `node_modules` alone doesn't prune lockfile-listed entries) and delete orphan blob/diff/package-archive files. Off by default. [Vendored](#vendor) packages are exempt from the crawl-based prune (an absent installed copy is their normal state), but a vendored entry whose dependency has left the lockfile is reverted and its manifest entry dropped. Orthogonal to `--mode` — combines with any mode. |
| `--detached` | — | With `--mode vendored`: skip all `.socket/manifest.json` writes — the vendor ledger embeds the patch records instead. For projects that want the vendored patches *only* in the lockfile + `.socket/vendor/`. Detached patches are invisible to `apply`/`rollback`/`repair`; undo them with `remove <purl>` or `vendor --revert`. |
| `--batch-size <n>` | `SOCKET_BATCH_SIZE` | Packages per API request (default: `100`). |
| `--all-releases` | `SOCKET_ALL_RELEASES` | Store patches for every release/distribution variant, not just the installed one — PyPI wheel/sdist, RubyGems platform, Maven classifier. Makes the manifest portable across environments (e.g. cross-platform CI caches). |
| `--vex <path>` | `SOCKET_VEX` | On a successful scan, also write an OpenVEX 0.2.0 document to this path. See [Inline VEX generation](#inline-vex-on-apply--scan--vendor). |
| `--vex-product`, `--vex-no-verify`, `--vex-doc-id`, `--vex-compact` | `SOCKET_VEX_*` | Passthrough to the embedded VEX builder; mirror the standalone [`vex`](#vex) knobs. Inert unless `--vex` is set. |

> Deprecated boolean spellings of `--mode` remain supported for back-compat: `--apply`
> (== `--mode agent`) and `--vendor` (== `--mode vendored`); prefer `--mode`. `--sync`
> is not deprecated — it is convenience sugar for `--mode agent` + `--prune`, the
> single-flag bot invocation (`scan --json --sync --yes`).

> Use `--dry-run` to preview what any moded run (with or without `--prune`) would do
> without mutating disk.

**Examples:**
```bash
# Scan local project (interactive prompt to apply)
socket-patch scan

# Scan with JSON output (discover + updates, no mutation)
socket-patch scan --json

# Agent mode: discover + apply patches in place (non-interactive)
socket-patch scan --json --mode agent --yes

# Auto-update bot: discover, apply, garbage-collect — all in one
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

> Already-vendored packages are **skipped by plain `--mode agent`** (the committed
> artifact is the patch); a newer available patch still appears in the JSON `updates[]`
> array — re-run `scan --mode vendored` to take it.

### `apply`

Apply security patches from the local manifest. Idempotent — safe to run from install
hooks and CI on every build.

**Usage:**
```bash
socket-patch apply [options]
```

**Command-specific options** (plus all [Global options](#global-options)):
| Flag | Env var | Description |
|------|---------|-------------|
| `-f, --force` | `SOCKET_FORCE` | Skip pre-application hash verification (apply even if package version differs). |
| `--check` | — | Read-only audit that the committed **Go** `replace`-redirects match the manifest (for CI / GitHub-App auditing) — Go only, since cargo patches in place and has no redirect to audit. Lock-free, crawl-free, and offline-safe: exits 0 in sync, 1 on drift. Vendored modules are excluded from the audit. |
| `--vex <path>` | `SOCKET_VEX` | On a successful apply, also write an OpenVEX 0.2.0 document to this path. See [Inline VEX generation](#inline-vex-on-apply--scan--vendor). |
| `--vex-product`, `--vex-no-verify`, `--vex-doc-id`, `--vex-compact` | `SOCKET_VEX_*` | Passthrough to the embedded VEX builder; mirror the standalone [`vex`](#vex) knobs. Inert unless `--vex` is set. |

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
> committed vendored artifact is the patch, so there is nothing for `apply` to do — even
> when the installed tree (e.g. `node_modules/`) is absent.

### `vex`

Generate an [OpenVEX](https://github.com/openvex) 0.2.0 attestation describing the
vulnerabilities that the applied patches have mitigated. See [OpenVEX
attestations](#openvex-attestations) below for the full workflow.

**Usage:**
```bash
socket-patch vex [options]
```

**Command-specific options** (plus all [Global options](#global-options)):
| Flag | Env var | Description |
|------|---------|-------------|
| `-O, --output <path>` | `SOCKET_VEX_OUTPUT` | Write the VEX document to this path instead of stdout. Required when combined with `--json`. |
| `--product <id>` | `SOCKET_VEX_PRODUCT` | Override the auto-detected top-level product PURL/identifier. |
| `--no-verify` | `SOCKET_VEX_NO_VERIFY` | Skip the on-disk file-hash check and trust the manifest — useful on a build machine that doesn't have the patched files laid out. |
| `--doc-id <id>` | `SOCKET_VEX_DOC_ID` | Override the document `@id`. Default is a random `urn:uuid:<v4>` regenerated each run; pin this for a reproducible identifier. |
| `--compact` | `SOCKET_VEX_COMPACT` | Emit compact JSON instead of pretty-printed. |

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

### `vendor`

`apply`'s **committable** sibling — the standalone command behind
[vendored mode](#three-patch-modes) (`scan --mode vendored` runs discovery + this engine
in one pass). Instead of patching installed packages in place (machine-local state),
`vendor` ejects each patched package into `.socket/vendor/<ecosystem>/<patch-uuid>/…` and
rewires your lockfile so the project consumes the vendored copy. Commit `.socket/` — the
vendored artifacts plus the manifest that [`vex`](#vex), [`list`](#list), and
[`repair`](#repair) read — along with the lockfile edits, and **every fresh checkout
builds with the patched dependency**: no `socket-patch` binary, no Socket API access, no
install hook required on the consuming machine.

Vendoring is per-patch: only dependencies with a Socket patch are vendored. For the
lockfile flavors each ecosystem supports, see the
[mode × ecosystem matrix](docs/ecosystems.md#mode--ecosystem-matrix).

**Usage:**
```bash
socket-patch vendor [options]
```

**Command-specific options** (plus all [Global options](#global-options)):
| Flag | Env var | Description |
|------|---------|-------------|
| `-f, --force` | `SOCKET_FORCE` | Tolerate *missing* patch-target files in the staged copy (skipped instead of failing the vendor) and bypass the variant probe for multi-release ecosystems. A plain before-hash mismatch doesn't need this: vendor staging always overwrites mismatched content with the verified patched bytes (surfaced as a `vendor_content_mismatch_overwritten` warning). |
| `--revert` | `SOCKET_VENDOR_REVERT` | Undo vendoring: restore the recorded original lockfile fragments byte-for-byte and remove the `.socket/vendor/` artifacts. Works without a manifest. |
| `--vex <path>` | `SOCKET_VEX` | On a successful vendor, also write an OpenVEX 0.2.0 document to this path. |
| `--vex-product`, `--vex-no-verify`, `--vex-doc-id`, `--vex-compact` | `SOCKET_VEX_*` | Passthrough to the embedded VEX builder. Inert unless `--vex` is set. |

**How it interacts with the rest of the CLI** — once a package is vendored, `vendor` owns
it:

- [`apply`](#apply) and [`rollback`](#rollback) skip vendored packages (they never touch
  a vendor-owned tree or lockfile entry).
- [`remove`](#remove) **reverts the vendoring** as part of removing the patch — lockfile
  restored, artifact deleted — so one command fully undoes it.
- [`scan`](#scan) skips downloading/applying patches for vendored packages, and
  `--prune` exempts them from its crawl-based prune (though a vendored entry whose
  dependency has left the lockfile is reverted and dropped); newer patches show up in
  `updates[]` as the signal to re-run `scan --mode vendored`.
- [`vex`](#vex) attests vendored patches by verifying the **committed artifact** (marked
  `(vendored)` in the impact statement) — no `setup` install hook needed.
- Re-running `vendor` is idempotent; patches dropped from the manifest are auto-reverted
  on the next run.

**Examples:**
```bash
# Vendor every patched dependency listed in the manifest
socket-patch vendor

# Preview without writing anything
socket-patch vendor --dry-run

# Then make it stick: commit .socket/ (vendor artifacts + manifest) and the lockfile
# (gitignore .socket/apply.lock — see "How Socket Patch works")
git add .socket package-lock.json && git commit -m "vendor Socket patches"

# Undo everything (restores the original lockfile byte-for-byte)
socket-patch vendor --revert

# JSON output for scripting
socket-patch vendor --json
```

> Prefer one command? [`scan --mode vendored`](#scan) discovers, downloads, *and* vendors
> in a single pass.

### `setup`

Configure your project so patches are **re-applied automatically after install** — no
manual `socket-patch apply` step in CI. `setup` is a one-time operation: run it, commit
the change together with your `.socket/` patches, and every later install handles the
rest. It is strictly **opt-in** — nothing is hooked unless you run `setup` and commit the
result.

What gets wired, per ecosystem:

- **npm / yarn / pnpm / bun** — writes `postinstall` and `dependencies` scripts into
  `package.json` so any install — including `npm install <pkg>` — re-applies patches
  (pnpm: root package only).
- **Python (pip / uv / poetry / pdm / hatch)** — Python has no universal post-install
  hook, so `setup` instead adds a **`socket-patch[hook]`** dependency to your manifest
  (`pyproject.toml` / `requirements.txt`; for classic Poetry, the equivalent
  `socket-patch = { extras = ["hook"] }`). Installing it lays down
  a startup `.pth` (shipped by the small `socket-patch-hook` wheel) that re-applies your
  committed `.socket/` patches the next time the interpreter runs. It is
  package-manager-agnostic (it rides the interpreter, not any one installer) and
  **fail-open** — a hook error can never break interpreter startup. Details below.
- **RubyGems (Bundler)** — adds a managed `plugin "socket-patch"` block to the `Gemfile`
  and generates an in-tree Bundler plugin under `.socket/bundler-plugin/`. It re-applies
  patches on every `bundle install` (cached *and* fresh). (Requires the `socket-patch`
  CLI on `PATH`.)
- **Composer (PHP)** — appends `socket-patch apply` to `composer.json`'s
  `post-install-cmd` / `post-update-cmd` script events, so patches re-apply on every
  `composer install` / `composer update`. (Requires the `socket-patch` CLI on `PATH`.)
- **Cargo & Go** — *apply-only, no `setup` hook.* A one-click auto-repatch-on-build isn't
  possible for these, so `setup` skips them. Patch with `socket-patch apply` directly:
  **cargo** patches the crate in place (in `vendor/` or the registry cache, rewriting
  `.cargo-checksum.json` so `cargo build` accepts it) — note that a non-vendored crate
  patches the **shared** `$CARGO_HOME/registry` cache, which affects every project on
  the machine and is silently reset by `cargo clean` or a cache prune; vendor the
  dependency (`--mode vendored`) for a project-local, committable patch. **go** writes a
  project-local patched copy under `.socket/go-patches/` plus a `go.mod` `replace`
  directive (the module cache is `go.sum`-verified, so in-place patching can't build);
  commit `go.mod` + `.socket/go-patches/` so a clone builds the patched bytes. To have
  [`vex`](#vex) still attest these hand-applied patches, add a `setup.manual` array to
  `.socket/manifest.json` by hand (there is no CLI flag for it yet):
  `"setup": { "manual": ["cargo", "golang"] }`.
- **Maven / NuGet / Deno** — also apply-only: no native install hook exists to wire, so
  `setup` reports `no_files`; patch them on demand with `socket-patch apply`, and declare
  them in `setup.manual` (the same hand-edit as the Cargo & Go note above, e.g.
  `"setup": { "manual": ["deno"] }`) so [`vex`](#vex) still attests the hand-applied
  patches — this matters most for Deno, which has no vendored or hosted alternative.
  For Maven
  and NuGet, discovery of installed packages is experimental and off by default (opt in
  with `SOCKET_EXPERIMENTAL_MAVEN=1` / `SOCKET_EXPERIMENTAL_NUGET=1`), and in-place
  patching corrupts their cache checksum sidecars — prefer `--mode vendored` or
  `--mode hosted`; see [ecosystems.md](docs/ecosystems.md#maven--nuget-caveats).

**Usage:**
```bash
socket-patch setup            # configure (interactive)
socket-patch setup --check    # verify configured; non-zero exit if not (CI gate)
socket-patch setup --remove   # revert what setup added
```

**Command-specific options** (plus all [Global options](#global-options) — `--dry-run`,
`--yes`, `--json`, `--cwd` are the most relevant):
| Flag | Env var | Description |
|------|---------|-------------|
| `--check` | — | Read-only verification that every manifest is configured **and** every installed patch is still applied on disk (each file matches its recorded `afterHash`); exits non-zero if any manifest still needs setup or a patch has drifted. Never writes (safe in CI). Conflicts with `--remove`. |
| `--remove` | — | Revert every install hook `setup` added (npm `package.json` scripts, the Python `socket-patch[hook]` dependency, the gem Bundler plugin wiring, and the Composer `post-install-cmd`/`post-update-cmd` script entries). |
| `--exclude <paths>` | `SOCKET_SETUP_EXCLUDE` | Workspace-member path(s) to exclude from setup (comma-separated, relative to the repo root). The exclusion is persisted in `.socket/manifest.json`, so `setup --check` and a fresh clone honor it without re-passing the flag. |

#### Disabling / opting out (Python hook)

The Python hook is designed to be easy to skip or remove:

- **Per interpreter / CI step:** set `SOCKET_PATCH_HOOK=off` (or `SOCKET_NO_HOOK=1`).
  This is checked *before any hook code runs*, so it fully bypasses the hook for that
  process.
- **Remove from a project:** `socket-patch setup --remove`, then
  `pip uninstall socket-patch-hook`.
- **Never opted in:** if you don't run `setup`, there is no hook — it is opt-in by
  design.

#### What the Python hook does, and its safety model

On interpreter startup, *only when the set of installed packages changed*, the hook runs
`socket-patch apply --offline --ecosystems pypi` for the project that owns the current
virtualenv, re-applying only the patches committed in that project's `.socket/`.
Specifically:

- It is **anchored to the virtualenv** it is installed in (not the working directory), so
  a `python` started from an unrelated directory cannot pull in a foreign
  `.socket/manifest.json`.
- It **verifies each file's hash before patching** and **never writes outside the
  installed package directory** (path-escaping manifest keys are refused).
- It **prefers the binary shipped in the installed `socket-patch` package** over `PATH`,
  so a binary planted earlier on `PATH` cannot shadow it; `PATH` is consulted only as a
  fallback when that package isn't installed.
- It runs **offline** (no network at startup) and is **fail-open** (any error is
  swallowed; it can never abort the interpreter).

**Examples:**
```bash
# Interactive setup (all detected ecosystems, auto-detected)
socket-patch setup

# Non-interactive
socket-patch setup -y

# Preview changes
socket-patch setup --dry-run

# Verify configuration in CI (exits non-zero if not set up or a patch has drifted)
socket-patch setup --check

# JSON output for scripting
socket-patch setup --json -y
```

### `rollback`

Roll back patches to restore the original files. If no identifier is given, all patches
are rolled back. The manifest entries are kept, so a later `apply` re-applies the patches
— use [`remove`](#remove) to delete a patch permanently.

Packages managed by [`vendor`](#vendor) are excluded — their patch lives in the committed
artifact, not the installed tree — and are listed in the JSON output's `vendored` array
(use `remove` or `vendor --revert` to undo them).

**Usage:**
```bash
socket-patch rollback [identifier] [options]
```

**Arguments:**
- `identifier` — package PURL or patch UUID to roll back. Omit to roll back all patches.

**Command-specific options** (plus all [Global options](#global-options)):
| Flag | Env var | Description |
|------|---------|-------------|
| `--one-off` | `SOCKET_ONE_OFF` | Reserved: rollback by fetching original (`beforeHash`) files from the API, no manifest required. **Not yet implemented** — the command currently errors up front. |

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

### `get`

Get a security patch from the Socket API and apply it. Accepts a UUID, CVE ID, GHSA ID,
PURL, or package name. The identifier type is auto-detected but can be forced with a
flag.

Alias: `download`. And as a shortcut, `socket-patch <uuid>` with a bare patch UUID is
rewritten to `socket-patch get <uuid>`.

**Usage:**
```bash
socket-patch get <identifier> [options]
```

**Arguments:**
- `identifier` — patch UUID, CVE ID, GHSA ID, package PURL, or package name. Type is
  auto-detected; force it with `--id` / `--cve` / `--ghsa` / `--package`.

**Command-specific options** (plus all [Global options](#global-options)):
| Flag | Env var | Description |
|------|---------|-------------|
| `--id` | — | Force identifier to be treated as a UUID. |
| `--cve` | — | Force identifier to be treated as a CVE ID. |
| `--ghsa` | — | Force identifier to be treated as a GHSA ID. |
| `-p, --package` | — | Force identifier to be treated as a package name. |
| `--save-only` | `SOCKET_SAVE_ONLY` | Download the patch without applying it (alias: `--no-apply`). |
| `--one-off` | `SOCKET_ONE_OFF` | Reserved: apply the patch immediately without saving to the `.socket` folder. **Not yet implemented** — the command currently errors up front. |
| `--all-releases` | `SOCKET_ALL_RELEASES` | Download patches for every release/distribution variant of a matched package (PyPI wheel/sdist, RubyGems platform, Maven classifier), not just the installed one. |

> Authenticated lookups run against an org. The slug is auto-resolved from your token
> when omitted; pass `--org <slug>` (or set `SOCKET_ORG_SLUG`) to pick one explicitly —
> useful when the token belongs to multiple orgs.

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

### `list`

List all patches in the local manifest.

**Usage:**
```bash
socket-patch list [options]
```

No command-specific options — see [Global options](#global-options) (`--json`,
`--manifest-path`, `--cwd` are the relevant ones).

**Examples:**
```bash
# List patches
socket-patch list

# JSON output
socket-patch list --json
```

**Sample output:**
```
Found 1 patch(es):

Package: pkg:npm/flatted@3.3.1
  UUID: 5cac955f-eab1-4d29-8f4f-c408a6cc9647
  Tier: free
  License: MIT
  Exported: Wed, 18 Mar 2026 22:53:26 GMT
  Vulnerabilities (1):
    - GHSA-25h7-pfq9-p65f (CVE-2026-32141)
      Severity: HIGH
      Summary: flatted vulnerable to unbounded recursion DoS in parse() revive phase
  Files patched (6):
    - package/cjs/index.js
    - package/es.js
    ...
```

### `remove`

Remove a patch from the manifest (rolls back files first by default). If the package is
[vendored](#vendor), `remove` also **reverts the vendoring** — the lockfile is restored
byte-for-byte and the `.socket/vendor/` artifact is deleted — so the patch is fully gone
in one command. Detached-vendored patches (from `scan --mode vendored --detached`) are
removable by PURL or UUID too, even though they have no manifest entry.

**Usage:**
```bash
socket-patch remove <identifier> [options]
```

**Arguments:**
- `identifier` — package PURL (e.g. `pkg:npm/package@version`) or patch UUID.

**Command-specific options** (plus all [Global options](#global-options)):
| Flag | Env var | Description |
|------|---------|-------------|
| `--skip-rollback` | `SOCKET_SKIP_ROLLBACK` | Only update the manifest, do not restore original files (for vendored packages this also leaves the vendor wiring + artifact in place). |

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

Download missing blobs, clean up unused blobs, and reset the advisory lock state.

Alias: `gc`

`repair` cleans up the `.socket/` directory without running a scan — useful when you've
manually adjusted the manifest, recovered from a partial-failure state, or just want to
free space. It also rebuilds missing or corrupt vendored artifacts. For the combined
workflow (discover + apply + GC in one pass), use
`scan --json --mode agent --prune --yes` instead.

As its final step, `repair` removes the leftover `.socket/apply.lock` file that mutating
commands retain between runs (skipped under `--dry-run`). A leftover file from a crashed
run never blocks anything — the OS releases a dead process's lock automatically — so this
is pure housekeeping. If another `socket-patch` process is actively running, `repair`
refuses up front with `lock_held` (exit 1); it never steals a live lock — wait for the
other process to finish, or budget a wait with `--lock-timeout`.

**Usage:**
```bash
socket-patch repair [options]
```

**Command-specific options** (plus all [Global options](#global-options)):
| Flag | Env var | Description |
|------|---------|-------------|
| `--download-only` | `SOCKET_DOWNLOAD_ONLY` | Only download missing artifacts, do not clean up (incompatible with `--offline`). |

**Examples:**
```bash
# Full repair (download missing + clean up unused)
socket-patch repair

# Repair without network access (missing blobs fail per-entry instead of downloading)
socket-patch repair --offline

# Download missing blobs only
socket-patch repair --download-only

# JSON output for scripting
socket-patch repair --json
```

## OpenVEX attestations

`socket-patch vex` turns your local manifest into a machine-readable statement of *which
known vulnerabilities no longer affect your build* because a Socket patch has been applied.
This lets vulnerability scanners stop flagging CVEs that you've already remediated in
place — without bumping the package version.

**How it works**

1. Reads `.socket/manifest.json` and, unless `--no-verify` is passed, re-checks each
   patched file's hash on disk so the attestation only covers patches that are actually
   applied. [Vendored](#vendor) patches are verified against the **committed artifact**
   instead of the installed tree (their impact statement carries a `(vendored)` marker),
   and need no `setup` install hook to be attested. Detached-vendored patches
   (`scan --mode vendored --detached`)
   attest from the vendor ledger's embedded records, and
   [hosted-mode](#three-patch-modes) patches attest from the redirect ledger
   (`.socket/vendor/redirect-state.json`, marker `(redirected)` — hash-verified against
   the installed tree post-install), so `vex` works even with no manifest file at all.
2. Auto-detects the top-level **product** identifier (override with `--product`), probing
   in order:
   - `.git/config` `[remote "origin"]` → `pkg:github/<owner>/<repo>` (similar for
     GitLab/Bitbucket; raw URL otherwise)
   - `package.json` → `pkg:npm/<name>@<version>`
   - `pyproject.toml` → `pkg:pypi/<name>@<version>`
   - `Cargo.toml` → `pkg:cargo/<name>@<version>`
3. Emits an OpenVEX 0.2.0 document whose statements mark each mitigated vulnerability as
   `not_affected` (justification: the patch is present), suitable for piping into
   `vexctl`, Grype, Trivy, and similar tools.

**Provenance markers**

Each statement's impact string records *how* the patch is persisted — one marker per
[patch mode](#three-patch-modes):

| Impact statement | Mode | What the evidence is | What a consumer should do |
|---|---|---|---|
| `Patched via Socket patch <uuid>` | agent | The installed tree: every patched file's hash was verified against the manifest's `afterHash` | Trust the statement as long as the agent install hook (or a CI `apply`) keeps re-applying; ecosystems without a hook must be declared in `setup.manual` |
| `Patched via Socket patch <uuid> (vendored)` | vendored | The **committed** `.socket/vendor/` artifact was hash-verified — no install hook needed; the lockfile wiring is the persistence mechanism | Trust it on any checkout; the committed bytes are the patch |
| `Patched via Socket patch <uuid> (redirected)` | hosted | The lockfile's integrity pin points at the Socket-hosted patched package. When emitted in-run by `scan --mode hosted --vex`, the statement is attested **from the redirect ledger without hash verification** (the bytes are fetched at install time — the JSON `vex` summary carries `verified: false`) | Ensure installs still resolve from `patch.socket.dev` (the lockfile edit is intact), and run `socket-patch vex` **after installing** — it re-reads the ledger and hash-verifies the redirected patches against the installed tree |

The markers are stable strings (see
[CLI_CONTRACT.md](crates/socket-patch-cli/CLI_CONTRACT.md)); scanners and policy engines
may match on them.

**Output channels**

| Invocation | VEX document | Status / summary |
|------------|--------------|------------------|
| _default_ (no `--output`, no `--json`) | stdout | one-line summary (stderr) |
| `--output <path>` | the file | one-line summary (stdout) |
| `--json --output <path>` | the file | machine-readable envelope on stdout (the CI shape) |

`--json` requires `--output`, since the VEX document is itself JSON and would otherwise
collide with the envelope on stdout.

**Using it with a scanner**

```bash
# Generate the attestation as part of CI, then hand it to a scanner
socket-patch vex --output socket.vex.json

# Suppress already-patched findings in Grype
grype <image-or-dir> --vex socket.vex.json

# Or with Trivy
trivy image --vex socket.vex.json <image>
```

Apply patches first (in any mode) — `vex` errors with `no_patches` when there is nothing
to attest (an empty manifest, no detached-vendored patches, and no hosted redirect
records).

### Inline VEX on `apply` / `scan` / `vendor`

You don't need a separate `vex` invocation: pass `--vex <path>` to `apply`, `scan`, or
`vendor` and the same OpenVEX document is generated as a side-effect of a successful run.

```bash
# Patch and attest in one step
socket-patch apply --vex socket.vex.json

# Discover, apply, prune, and attest — the full auto-update-bot pass
socket-patch scan --json --mode agent --prune --yes --vex socket.vex.json

# Vendor and attest — works manifest-less with --detached too
socket-patch scan --json --mode vendored --yes --vex socket.vex.json
```

The `--vex-product`, `--vex-no-verify`, `--vex-doc-id`, and `--vex-compact` flags mirror
the standalone command's `--product` / `--no-verify` / `--doc-id` / `--compact` knobs.

Contract:

- The document is **always written to the file** (never stdout), so it never collides
  with the command's own `--json` output. JSON mode adds a top-level `vex` summary —
  `{ path, statements, format }` — to the envelope (`apply`) / result (`scan`).
- It's built from the manifest **as it stands after the run** (including any
  `--mode agent` writes, with or without `--prune`) and verified against on-disk state
  unless `--vex-no-verify` is set. Generated for real applies, `--dry-run`, and read-only
  scans alike.
- **Fail-the-command:** if `--vex` was requested but generation fails (no detectable
  product, empty/missing manifest, nothing verified, unwritable path), the command exits
  non-zero **even when the apply/scan itself succeeded**, with a stable error code in the
  JSON output.

## Scripting & CI/CD

All commands support `--json` for machine-readable output. JSON responses always include
a `"status"` field for easy error detection:

```bash
# Check for available patches in CI (read-only)
result=$(socket-patch scan --json --ecosystems npm)
patches=$(echo "$result" | jq '.totalPatches')

# Auto-update bot: discover, apply, and garbage-collect in one pass
socket-patch scan --json --mode agent --prune --yes | jq '{
  applied:     [.apply.patches[]? | select(.action == "added" or .action == "updated") | .purl],
  pruned:      (.gc.prunedManifestEntries // []),
  bytes_freed: (.gc.bytesFreed // 0)
}'
# The PR action (e.g. peter-evans/create-pull-request) commits the working-tree
# changes; use this summary as the PR body.

# Apply patches and check result
socket-patch apply --json | jq '.status'
# "success", "partialFailure", "noManifest", or "error"
```

When stdin is not a TTY (e.g. in CI pipelines), interactive prompts auto-proceed instead
of blocking. Progress indicators and ANSI colors are automatically suppressed when output
is piped.

The exact JSON shapes, exit codes, and stability guarantees are specified in
[CLI_CONTRACT.md](crates/socket-patch-cli/CLI_CONTRACT.md).

## Manifest format

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

Patched file contents are in `.socket/blobs/` (named by git SHA256 hash).

The manifest may also carry an optional top-level `"setup"` key persisting setup state —
`"setup": { "manual": ["cargo"], "exclude": ["packages/legacy"] }` — where `manual`
lists ecosystems you patch by hand so [`vex`](#vex) still attests them (see
[`setup`](#setup)), and `exclude` lists workspace members excluded from setup (written
by `setup --exclude`).

## Further reading

- **[Ecosystem & platform support](docs/ecosystems.md)** — the full mode × ecosystem
  matrix, per-ecosystem caveats (Maven, NuGet, Rush monorepos, Go), and supported
  platforms.
- **[CLI contract](crates/socket-patch-cli/CLI_CONTRACT.md)** — the machine-readable
  surface: exact JSON shapes, exit codes, flag/env bindings, and the semver policy that
  governs them.
- **[Design notes](docs/design/)** — e.g. [the configuration model](docs/design/configuration.md)
  and [why hosted mode is impossible for Go](docs/design/golang-hosted-no-go.md).
- **[Changelog](CHANGELOG.md)**
