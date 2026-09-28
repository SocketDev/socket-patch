# Socket Patch CLI

Fix known vulnerabilities in the dependencies you already have — without waiting for an
upstream release, and without a risky version bump.

Socket's security team backports minimal fixes to the *exact versions* of packages you
use. `socket-patch scan` finds which of your dependencies have a patch and rewrites your
lockfile so that only those dependencies resolve to Socket-hosted, integrity-pinned
patched packages. Your package manager then installs the fix like any other dependency:
no install hook, no CI changes. It works across npm, PyPI, Cargo, Go, RubyGems, Maven,
Composer, NuGet, and Deno. `socket-patch vex` then emits an [OpenVEX
attestation](#openvex-attestations) so your vulnerability scanner stops flagging the CVEs
you've fixed, and `socket-patch scan --mode vendored` commits the patched packages into
your repo when installs must work offline.

**Contents:** [Installation](#installation) · [Five-minute tutorial](#five-minute-tutorial)
· [How it works](#how-socket-patch-works) · [Common tasks](#common-tasks)
· [Command reference](#command-reference) · [OpenVEX](#openvex-attestations)
· [Scripting & CI/CD](#scripting--cicd) · [Manifest format](#manifest-format)
· [Ecosystem support →](docs/ecosystems.md)

## Installation

One-line install (macOS / Linux):

```bash
curl -fsSL https://install.socket.dev/patch | sh
```

Detects your platform (macOS/Linux, x64/ARM64), downloads the latest binary, verifies it
against the release's `SHA256SUMS`, and installs to `/usr/local/bin` or `~/.local/bin`.
Use `sudo sh` instead of `sh` if `/usr/local/bin` requires root. Pin a version with
`SOCKET_PATCH_VERSION=3.3.0 sh` instead of plain `sh`.

On a network that blocks or distrusts `github.com`, set `SOCKET_PATCH_BASE_URL` so the
archives come from Socket too — `install.socket.dev` relays them from the GitHub release,
checksums included:

```bash
curl -fsSL https://install.socket.dev/patch \
  | SOCKET_PATCH_BASE_URL=https://install.socket.dev/patch/SocketDev/socket-patch/releases sh
```

`install.socket.dev` serves a copy of [`scripts/install.sh`](scripts/install.sh) from
this repository — read it before you run it, either there or at
[install.socket.dev/patch](https://install.socket.dev/patch). If you would rather not
depend on the Socket domain, `curl -fsSL
https://raw.githubusercontent.com/SocketDev/socket-patch/main/scripts/install.sh | sh`
does the same thing from the same bytes. See
[docs/installer-hosting.md](docs/installer-hosting.md) for how the hosted copy is
published.

On Windows, install via npm (below), or grab a prebuilt
`socket-patch-*-pc-windows-msvc.zip` from the
[latest release](https://github.com/SocketDev/socket-patch/releases/latest).

Or install through your package manager:

| Package manager | Command |
|-----------------|---------|
| npm | `npm install -g @socketsecurity/socket-patch` (or one-shot: `npx @socketsecurity/socket-patch`) |
| pip | `pip install socket-patch` |
| cargo | `cargo install socket-patch-cli` (builds from source with every ecosystem compiled in) |
| gem | `gem install socket-patch` |

The gem package is a thin launcher: on first run it downloads the prebuilt binary for
your platform from the matching GitHub release, verifies its SHA-256, caches it, and
execs it. Set `SOCKET_PATCH_BIN` to an existing binary to skip the download.

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

### Updating

If you installed via the one-liner or a manual download, the CLI updates itself:

```bash
socket-patch --update            # latest release (--update 3.4.0 pins a version)
```

It downloads the release for your platform, verifies its SHA-256 against the
published `SHA256SUMS`, and atomically swaps the binary in place. Package-manager
installs are detected and pointed at their own upgrade command instead (e.g.
`npm update -g @socketsecurity/socket-patch`). When a newer release exists,
interactive runs print a once-a-day reminder on stderr — set
`SOCKET_NO_UPDATE_CHECK=1` to turn that off.

## Five-minute tutorial

No account or token is needed to follow along — without an API token `socket-patch`
talks to Socket's public patch proxy, which serves the free tier of patches anonymously.
(An API token unlocks your organization's patch tier; if you've already run
`socket login` with the separate [Socket CLI](https://docs.socket.dev/docs/socket-cli),
`socket-patch` picks it up automatically — see
[Configuration sources](#configuration-sources).)

**1. Scan.** From your project root:

```bash
cd your-project
socket-patch scan
```

`scan` reads your lockfiles and installed packages, asks Socket which dependency
versions have a patch, prints each one with its severity and CVE/GHSA identifiers, and
patches them in **hosted mode**: it rewrites the lockfile so only the patched
dependencies resolve to Socket-hosted, integrity-pinned packages on `patch.socket.dev`.
It never prompts. The patch records go in `.socket/vendor/redirect-state.json`, and the
run ends by listing the files it changed. (Add `--dry-run` to preview without writing.)

> If it prints `No patches available for installed packages.`, none of your dependency
> versions currently has a Socket patch — the good outcome, with nothing to do. To walk
> the rest of the loop anyway, make a scratch project pinned to a version that has a free
> patch — at the time of writing, `flatted@3.3.1`:
>
> ```bash
> mkdir demo && cd demo && git init -q && npm init -y && npm install flatted@3.3.1 && socket-patch scan
> ```
>
> (The patch catalog changes over time; if that finds nothing, pick another patched
> version.)

**2. Commit.** The lockfile edit *is* the patch, so commit it with the redirect ledger
(`rollback` and `vex` read it):

```bash
git add package-lock.json .socket/vendor/redirect-state.json .npmrc   # npm example
git commit -m "apply Socket security patches"
```

The exact files depend on your package manager — `scan` names them. For npm it also
writes `allow-remote=all` to `.npmrc`, which npm 12 needs to install from
`patch.socket.dev` (see [npm: hosted mode and npm 12](#npm-hosted-mode-and-npm-12));
for pnpm 9+ locks it sets `trustLockfile: true` in `pnpm-workspace.yaml`
([pnpm](#pnpm)).

**3. Reinstall.** A clean install fetches the patched packages and checks them against
the lockfile's integrity pins:

```bash
npm ci        # or pnpm install, yarn install, pip install -r ..., uv sync, bundle install, ...
```

Every later install — yours, your teammates', CI's — does the same. There is no hook to
wire and nothing to add to CI.

**4. Tell your scanner.** Emit an OpenVEX document that marks each patched CVE
`not_affected`, and hand it to Grype, Trivy or any other VEX-aware scanner:

```bash
socket-patch vex --output socket.vex.json
grype . --vex socket.vex.json
```

**5. Go offline, if you need to.** Hosted installs must reach `patch.socket.dev`. For
airgapped builds, switch to vendored mode: it copies the patched packages into
`.socket/vendor/`, points the lockfile at them, and reverts the hosted edits:

```bash
socket-patch scan --mode vendored
git add .socket/vendor package-lock.json .npmrc && git commit -m "vendor Socket patches"
```

(Vendored npm installs don't need the `.npmrc` line, so the switch removes it again.)

**6. See what you have.** `list` shows each patch and the mode that holds it
(`Mode: vendored` after step 5):

```bash
socket-patch list
```

```
Found 1 patch:

Package: pkg:npm/flatted@3.3.1
  UUID: 5cac955f-eab1-4d29-8f4f-c408a6cc9647
  Mode: hosted (recorded in .socket/vendor/redirect-state.json)
  ...
  Vulnerabilities (1):
    - GHSA-25h7-pfq9-p65f (CVE-2026-32141)
      Severity: HIGH
```

To undo everything, run `socket-patch rollback`: it restores the original lockfile
entries and drops the records.

That's the whole loop: **scan → commit → reinstall → vex**, with `scan --mode vendored`
when installs must be offline. The older *agent* mode, which patches installed files in
place and needs `socket-patch apply` after every install, is still supported; the next section
compares the three.

## How Socket Patch works

**A patch** is a minimal fix — usually the upstream security fix, backported — for one
exact published version of a package. Socket distributes it as per-file edits: for each
touched file, the hash of the expected original (`beforeHash`), the hash of the patched
result (`afterHash`), and the replacement content. Patches are looked up by package URL
([PURL](https://github.com/package-url/purl-spec)) — e.g. `pkg:npm/lodash@4.17.20` — so
everything is keyed to exact versions. In hosted and vendored mode your package manager
installs a patched copy of the package, pinned by the lockfile's integrity check; in
agent mode the CLI edits
the installed files itself and verifies every hash before and after (a file matching
neither hash is overwritten with the verified patched content plus a
`content_mismatch_overwritten` warning, unless `--strict` is set).

### Which patch is picked

A package version can have several patches (one per advisory, or a later *merged* patch
that folds several advisories into one). `scan` and `get` apply exactly one, chosen
the same way everywhere, from the patches your account can download:

1. the newest **merged** patch (one covering two or more advisories) wins, regardless of
   severity — it is the cumulative fix;
2. otherwise the patch with the worst severity it fixes (critical > high > medium > low),
   then the newest;
3. paid tier, then UUID, only break exact ties.

"Newest" is when the patch was published, not the package version. When a better patch
appears for a package you already patched, the JSON `updates[]` array lists it and the
next `scan` in the same mode takes it.

### State in `.socket/`

Local state lives in `.socket/` at your project root, and is designed to be committed:

| Path | Contents |
|------|----------|
| `.socket/vendor/redirect-state.json` | Hosted mode: the patch records plus the original lockfile / registry-config fragments each redirect replaced (what [`rollback`](#rollback) replays) |
| `.socket/vendor/state.json` + `.socket/vendor/<ecosystem>/…` | Vendored mode: the ledger (with embedded patch records) and the patched package artifacts |
| `.socket/manifest.json` | Agent mode only: the record of downloaded patches — PURLs, file hashes, vulnerability metadata ([format](#manifest-format)) |
| `.socket/blobs/` | Agent mode only: patched file contents, named by git-sha256 hash |

Hosted and vendored mode never write `manifest.json`.

> While a command runs it holds a transient advisory lock, `.socket/apply.lock`, and
> removes it when it finishes — the file never outlives the command, so there is nothing
> to `.gitignore`. A crashed run can leave one behind; the next command reclaims and
> removes it. Nothing in the table is written until there is something to record: a
> report-only `scan`, a `--dry-run`, or a run that changes nothing leaves no `.socket/` at
> all, and a full [`rollback`](#rollback) removes everything it created (only the
> zero-patch `manifest.json` stays).

### Three patch modes

The same patched bytes can reach your build three ways. The modes differ in *where the
patch lives* and *what must happen at install time*. `scan --mode <name>` picks one per
run; a bare `scan` is hosted.

| Mode | Where the patch lives | Install-time requirement | Trade-off |
|------|----------------------|--------------------------|-----------|
| **hosted** (default) — `scan` | Nowhere in your repo: the lockfile is rewritten so **only** the patched dependencies resolve to Socket-hosted, integrity-pinned packages on `patch.socket.dev`; the edits and patch records are ledgered in `.socket/vendor/redirect-state.json` | Installs must be able to reach `patch.socket.dev` (no CLI, no install hook) | Smallest possible diff (lockfile + ledger); not for airgapped installs |
| **vendored** — `scan --mode vendored` (or [`vendor`](#vendor)) | Patched packages committed under `.socket/vendor/`, with the lockfile rewired to consume them | **None** — the package manager installs the committed bytes | Fully airgapped and hermetic, at the cost of repo size |
| **agent** (older) — `scan --mode agent`, [`get`](#get), [`apply`](#apply) | `.socket/manifest.json` + blobs, committed; the CLI patches installed files in place | The `socket-patch` CLI must run after every install (an `apply` step in CI; see [Agent mode in CI](#agent-mode-in-ci)) | No lockfile edits and a small repo footprint, but the only mode that needs CI changes |

Every mode pins the patched bytes: vendored and hosted modes lean on your package
manager's own lockfile integrity checks (sha512 / sha256 / contentHash / CHECKSUMS) where
the ecosystem enforces them — hosted Maven, which has no lockfile, gets a fail-closed
version-suffixing scheme instead — and agent mode verifies every file on each apply. A
few combinations have weaker install-time pins (vendored Maven, NuGet without a lockfile,
Go's directory replaces, pipenv's Pipfile.lock) — there the committed bytes are the
protection; see the [per-ecosystem caveats](docs/ecosystems.md).

**Choosing:** use *hosted* unless your installs can't reach `patch.socket.dev`; then
use *vendored*. *Agent* mode remains fully supported for projects already built around
it, and for Deno, which has no hosted or vendored mode.

Mode support varies by ecosystem — e.g. Rush monorepos can't do vendored, and Go hosted
mode covers the free tier only. See the full
**[mode × ecosystem matrix](docs/ecosystems.md#mode--ecosystem-matrix)** for details.

### Package-manager notes

#### npm: hosted mode and npm 12

npm 12 defaults to `allow-remote=none` and refuses (`EALLOWREMOTE`) any lockfile
entry whose tarball is not served by your configured registry — which is what a
hosted redirect writes. So when a hosted `scan` (or `get --mode hosted`) leaves a
`package-lock.json` / `npm-shrinkwrap.json` pointing at `patch.socket.dev`, it also
writes `allow-remote=all` to the project `.npmrc` (creating it, or appending one line
and keeping everything else byte-for-byte) and warns `redirect_npm_allow_remote`.
Commit the `.npmrc` with the lock; a plain `npm ci` then installs the patched
packages on every npm from 7 to 12. The tradeoff: `allow-remote=all` lets npm install
**any** URL-resolved dependency, not just Socket's patched ones — the per-entry sha512
integrity pins are still enforced. An explicit `allow-remote=none` / `root` of yours is
never changed or overridden — whether it sits in the project `.npmrc`, in your user
(`~/.npmrc`), global or builtin npm config, or in an `npm_config_allow_remote`
environment variable (the warning names where it found it and how to install anyway),
`--no-npm-allow-remote-config`
(`SOCKET_NO_NPM_ALLOW_REMOTE_CONFIG`) turns the write off (install with
`npm ci --allow-remote=all` instead), and `rollback` / `remove` / switching to vendored
mode remove exactly the line or file the run added. Vendored mode needs none of this:
npm treats its `file:` tarballs under `allow-file`, which defaults to `all`. See
[npm compatibility](docs/testing/npm-compatibility.md) for the tested majors.

#### pnpm

For a lockfileVersion 9 `pnpm-lock.yaml`, hosted mode also sets `trustLockfile: true` in
`pnpm-workspace.yaml` (pnpm 11+ rejects the redirected lock without it; commit the file
with the lock) unless the project disables it or you pass `--no-trust-lockfile-config`.
It skips pnpm's registry re-verification for the whole lock, while tarball integrity
stays enforced. A warm store can keep serving the upstream bytes, so reinstall from a
clean tree and an empty store, then check with `socket-patch vex`. See
[pnpm compatibility](docs/testing/pnpm-compatibility.md).

#### Bun

Both text `bun.lock` and binary `bun.lockb` support hosted and vendored
patches, mode switching, repair, and rollback. Binary locks are read and
patched natively: Socket Patch does not need Bun installed to discover or
rewrite them, and does not convert them to text. If both filenames exist,
`bun.lock` takes precedence. See [Bun compatibility](docs/testing/bun-compatibility.md)
for the tested versions, workspace behavior, and installer integrity limits.

#### vlt

[vlt](https://www.vlt.sh) projects (`vlt-lock.json`) work in agent and hosted mode on
every vlt release from 0.0.0-1 to 1.2.0, and in vendored mode on locks with
`lockfileVersion` 0 or 1 (0.0.0-19 and later; older locks are refused with
`vendor_lockfile_version_unsupported`). Hosted mode checks that each artifact is served
the way vlt can verify and removes stale installed copies so the next `vlt install`
fetches the patched packages. Vendored mode covers direct dependencies of the root or a
workspace member (transitive dependencies need hosted mode); after vendoring an optional
dependency run `vlt ci`. See [vlt notes](docs/ecosystems.md#npm-vlt-notes) for the
caveats and [vlt compatibility](docs/testing/vlt-compatibility.md) for the tested
releases.

#### Pipenv

Hosted mode rewrites every `Pipfile.lock` category that pins the patched release and
keeps the Pipfile, its content hash, markers and unrelated entries, so `pipenv install
--deploy`, `pipenv sync` and `pipenv verify` keep passing (Pipenv 7 and later; older
lock formats are refused unchanged). Socket Patch probes `pipenv --version` once per run
to pick the reference shape; `SOCKET_PIPENV_MAJOR=<major>` pins it on machines without
pipenv. Vendored mode requires Pipenv 2018 or later; Pipenv 2023+ does not hash-check
local wheels, so commit the wheel and run `socket-patch vex --product <purl>` (a Pipfile
names no project). A clone with only `Pipfile` + `Pipfile.lock` works in every mode.

Pipenv never reinstalls a release that is already present, so a rewrite protects fresh
installs, and Socket Patch warns (`redirect_pypi_stale_install` /
`pypi_pipenv_stale_install`) when a venv still holds the upstream release, with the
remedy `pipenv run pip uninstall -y <pkg> && pipenv sync`. Don't use `pipenv uninstall
<pkg>` for this — it re-locks the patch away — and re-run `scan` after `pipenv lock` /
`pipenv update`, which regenerate the entry to its registry reference. Measured
boundaries are in [Pipenv compatibility](docs/testing/pipenv-compatibility.md).

## Common tasks

### Patch everything that can be patched

```bash
socket-patch scan                    # hosted mode: rewrite lockfiles (never prompts)
socket-patch scan --dry-run          # preview what it would change
socket-patch scan --json             # same run, machine-readable result
```

### Patch only some packages, or some projects in a monorepo

```bash
socket-patch scan --package lodash --package pkg:pypi/requests   # or --package lodash,requests
socket-patch scan apps/web apps/api                              # each PATH is a project directory
socket-patch scan 'services/*'                                   # directory globs work too
```

`--package` takes a name (case-insensitive) or a purl with or without its version. In
hosted and vendored mode each PATH is a project directory, scanned as if it were
`--cwd` under an `== <dir> ==` header; the worst exit code wins.

### Patch one specific CVE or advisory

```bash
socket-patch get CVE-2024-12345 --mode hosted
socket-patch get GHSA-xxxx-yyyy-zzzz --mode hosted
```

Like `scan`, `get` defaults to hosted mode; `--mode vendored` or `--mode agent`
(in-place apply, also implied by `--save-only` and `--global`) picks the others.

### Check for patches in CI without changing anything

```bash
socket-patch scan --json --dry-run | jq '{patches: .totalPatches, updates: (.updates | length)}'
```

### Run an auto-update bot in CI

```bash
socket-patch scan --json
```

A hosted scan takes new patches and newer versions of the ones already applied. Your PR
tooling (e.g. `peter-evans/create-pull-request`) commits the changed lockfiles and
`.socket/vendor/`; use the JSON result for the PR title/body. See
[Scripting & CI/CD](#scripting--cicd), including how to supply `SOCKET_API_TOKEN` for
org-tier patches.

### Tell your vulnerability scanner about the patches

```bash
socket-patch vex --output socket.vex.json
grype <image-or-dir> --vex socket.vex.json     # or trivy image --vex ...
```

The OpenVEX document marks each patched CVE `not_affected`. Run it after installing, so
hosted patches are hash-verified against the installed copies. You can also emit it
inline with `scan --vex <path>`. Details in [OpenVEX attestations](#openvex-attestations).

### Work offline / airgapped

```bash
socket-patch scan --mode vendored
git add .socket/vendor <your lockfile>
```

Vendored mode needs no Socket infrastructure and no `socket-patch` binary at install
time — the patched packages install from the committed bytes (other, unvendored
dependencies still resolve from your registry or mirror as usual). Agent mode also works
offline once its blobs are committed (`socket-patch apply --offline`). `scan` and `get`
need the network and refuse to run with `--offline`.

### Undo things

| Command | What it does |
|---------|--------------|
| [`rollback`](#rollback) | **Fully unpatches, in every mode**: unwinds hosted redirects (replaying the originals recorded in `redirect-state.json`) and vendored lockfile wiring, restores in-place files, and drops the records — everything, or just the given targets; `--preserve-state` keeps the local patch state for a later re-apply |
| [`remove`](#remove) | The single-patch form of `rollback`: restore, unwind, drop the record and GC for one PURL/UUID |
| [`vendor --revert`](#vendor) | **Un-vendors wholesale**: restores the recorded original lockfile fragments byte-for-byte and removes the `.socket/vendor/` artifacts |
| [`scan --prune`](#scan) | Agent mode: **reconciles, doesn't reverse** — drops manifest entries for packages that have left the project and garbage-collects orphan blob/diff/archive files |
| [`repair`](#repair) (alias `gc`) | **Restores health, not originals**: re-downloads missing blobs, re-vendors missing/corrupt vendored artifacts, and cleans up unused ones |

> If you revert a hosted edit by hand instead (e.g. `git checkout -- <lockfile>`), also
> delete `.socket/vendor/redirect-state.json` — its recorded originals are then stale. A
> leftover ledger does not make [`vex`](#vex) attest the removed redirects: a record
> attests only while a lockfile still wires its hosted patch.

## Command reference

| Command | What it does |
|---------|--------------|
| [`scan`](#scan) | Find patches for your dependencies and apply them — by default by rewriting lockfiles to Socket-hosted patched packages |
| [`vex`](#vex) | Generate an OpenVEX document for the vulnerabilities the project's patches fix |
| [`vendor`](#vendor) | Eject patched dependencies into committable `.socket/vendor/` and rewire lockfiles to use them (`--revert` undoes it) |
| [`list`](#list) | List the patches in this project: hosted and vendored records plus any agent-mode manifest entries |
| **Agent mode (older commands)** | |
| [`get`](#get) | Fetch and apply one patch by UUID / CVE / GHSA / PURL / name (alias: `download`) |
| [`apply`](#apply) | Apply the patches in `.socket/manifest.json` in place |
| [`rollback`](#rollback) | Undo patches in every mode: restore original files and unwind hosted or vendored lockfile wiring |
| [`remove`](#remove) | Remove one patch by PURL or UUID (rolls back first) |
| [`repair`](#repair) | Download missing patch artifacts, re-vendor broken vendored artifacts, clean up unused ones (alias: `gc`) |

`socket-patch --update` updates the CLI itself (see [Updating](#updating)).

### Global options

These flags are accepted by **every** subcommand and go after the command name —
`socket-patch <command> --json --cwd ./app` works uniformly (`socket-patch --json
<command>` is a parse error). A command silently ignores any global flag it doesn't use
(e.g. `list --global` parses fine and the flag is a no-op).

Each flag has a matching `SOCKET_*` environment variable, listed in the table;
command-specific flags list theirs in each command's own table. **Precedence is CLI arg
> env var > default** — with one extra fallback layer for the three authentication
settings, described in [Configuration sources](#configuration-sources) below.

| Flag | Env var | Description |
|------|---------|-------------|
| `--cwd <dir>` | `SOCKET_CWD` | Working directory (default: `.`). The manifest path is resolved relative to this. |
| `--manifest-path <path>` | `SOCKET_MANIFEST_PATH` | Path to the patch manifest, resolved relative to `--cwd` (default: `.socket/manifest.json`). |
| `--api-url <url>` | `SOCKET_API_URL` | Socket API URL for the authenticated endpoint (default: `https://api.socket.dev`). |
| `--api-token <token>` | `SOCKET_API_TOKEN` | Socket API token — optional. When no token resolves from any source, the anonymous public patch proxy is used (free patches). See [Configuration sources](#configuration-sources) for how to obtain and persist one. |
| `-o, --org <slug>` | `SOCKET_ORG_SLUG` | Organization slug. Auto-resolved when omitted and a token is set. |
| `--proxy-url <url>` | `SOCKET_PROXY_URL` | Public proxy URL used when no API token is set (default: `https://patches-api.socket.dev`). |
| `-e, --ecosystems <list>` | `SOCKET_ECOSYSTEMS` | Restrict to specific ecosystems (comma-separated, e.g. `npm,pypi`). Unknown names are rejected. |
| `--download-mode <mode>` | `SOCKET_DOWNLOAD_MODE` | Artifact to fetch when local files are missing: `diff` (default, smallest delta) or `file` (legacy per-file blobs). |
| `--vendor-source <mode>` | `SOCKET_VENDOR_SOURCE` | How vendored mode acquires the installable artifact: `auto` (default — download the prebuilt package from patch.socket.dev, fall back to a local build on any miss), `service` (require the service, fail-closed), or `build` (always build locally). Covers npm, pypi, cargo, golang, composer, gem, nuget, and maven. |
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
| `-y, --yes` | `SOCKET_YES` | Skip confirmation prompts (`get`, `rollback`, `remove`, `--update`). `scan` never prompts, so it ignores this flag. |
| `--lock-timeout <secs>` | `SOCKET_LOCK_TIMEOUT` | Seconds to wait for `.socket/apply.lock` before giving up. `0`/unset = a single non-blocking try; a positive value retries with backoff. Only meaningful for the commands that take the lock — `apply`, `rollback`, `repair`, `remove`, `vendor`, and `scan`/`get` whenever they write (agent-mode download + apply, vendored, hosted). The lock file exists only while a command runs. |
| `--debug` | `SOCKET_DEBUG` | Emit verbose debug logs to stderr. |
| `--no-telemetry` | `SOCKET_TELEMETRY_DISABLED` | Disable anonymous usage telemetry. |
| `--no-npm-allow-remote-config` | `SOCKET_NO_NPM_ALLOW_REMOTE_CONFIG` | Hosted mode: don't write `allow-remote=all` to the project `.npmrc` (see [npm compatibility](#npm-hosted-mode-and-npm-12)). |
| `--no-trust-lockfile-config` | `SOCKET_NO_TRUST_LOCKFILE_CONFIG` | Hosted mode: don't set `trustLockfile: true` in `pnpm-workspace.yaml` for a lockfileVersion 9 pnpm lock (pnpm 11+ then needs `pnpm install --trust-lockfile`). |
| `--no-vlt-install-cleanup` | `SOCKET_NO_VLT_INSTALL_CLEANUP` | Hosted mode: don't remove stale vlt installed copies after `vlt-lock.json` is repointed or restored (run `vlt ci` instead). |

#### Configuration sources

For the three authentication settings, the [Socket CLI](https://docs.socket.dev/docs/socket-cli)'s
persisted login sits between the env var and the built-in default — run `socket login`
(or `socket config set apiToken` / `defaultOrg`) once and `socket-patch` picks it up
too. The `SOCKET_CLI_*` env vars the JS CLI reads are honored as peer aliases as well,
so one export configures both tools. To set a token directly instead, create one in the
[Socket dashboard](https://socket.dev) under your organization's API tokens settings and
use the raw token (`sktsec_<...>_api`) shown at generation time, **not** the
`sha512-...` display hash. Resolution is per key, and an empty value means "unset" at
every layer:

```
--api-token / --org / --api-url
  1. CLI flag
  2. Env var           SOCKET_API_TOKEN / SOCKET_ORG_SLUG / SOCKET_API_URL — or the
                       SOCKET_CLI_* peer aliases (SOCKET_CLI_API_TOKEN /
                       SOCKET_CLI_ORG_SLUG / SOCKET_CLI_API_BASE_URL); the
                       canonical name wins when both are set
  3. socket-cli config <data dir>/socket/settings/config.json — read-only
                       (Linux: $XDG_DATA_HOME, else ~/.local/share;
                        macOS: $XDG_DATA_HOME, else ~/Library/Application Support,
                        then legacy ~/.local/share; Windows: %LOCALAPPDATA%)
  4. Built-in default  no token → public proxy; org → auto-resolve;
                       url → https://api.socket.dev
```

Two env-only toggles adjust this. `SOCKET_NO_API_TOKEN=1` ignores ambient tokens (env +
config; an explicit `--api-token` still wins) — useful to force the anonymous public
proxy in CI or a test run. `SOCKET_NO_CONFIG=1` disables the config-file layer entirely.
`socket-patch` never *writes* the config file, and a corrupt one only produces a stderr
warning — it never breaks a command or pollutes `--json` output. `socket-patch` does
**not** read `.env` files or any per-repository config for endpoints or credentials: a
cloned repo must never be able to redirect where patches come from or spend your token.
(Full rationale: [docs/design/configuration.md](docs/design/configuration.md).)

Three env-only knobs tune pacing rather than routing:

- `SOCKET_API_CONCURRENCY=<n>` (clamped to `1`-`32`) caps in-flight patch-API requests.
  By default `scan` runs a quarter of a step's requests at once, between 8 and 32, against
  the authenticated API, and 4 against the public proxy (where the knob can only lower
  it); `vex` record fetches run up to 10 (4 on the proxy). Lower it when a self-hosted
  `--api-url`, corporate proxy, WAF or CDN caps requests per client and a scan starts
  reporting fewer patches than it should.
- `SOCKET_API_MAX_RETRIES=<n>` (`0`-`10`, default 3) sets how often a `429` / `503`
  answer is retried. Retries honor `Retry-After` (a wait over 30 s gives up at once) or
  back off 0.5 s, 1 s, 2 s with jitter, and all retries in a run must finish within 60 s.
  Other errors are never retried. A query still failing is reported, never dropped
  (`Warning: API batch <n> of <total> failed: …`, or `api_batch_failed` /
  `patch_details_failed` in `--json` `warnings[]`); if every query fails the scan exits 1.
- `SOCKET_WALK_THREADS=<n>` (clamped to `1`-`16` and the CPU count; default 4, fewer on small machines) sizes the
  thread pool for the `node_modules` and Maven repository walks. A soft open-file limit
  below 128 forces one thread.

An unset, empty or non-numeric value leaves the default in place.

The sections below list only each command's **command-specific** flags.

### `scan`

Find patches for your dependencies and apply them. `scan` is the entry point for all
three [patch modes](#three-patch-modes):

- **hosted** (the default — a bare `scan`, `scan --json` included) rewrites lockfiles /
  registry configs so only the patched dependencies resolve to Socket-hosted packages,
  and records the edits in `.socket/vendor/redirect-state.json`;
- `--mode vendored` discovers, downloads, and builds + wires the committable
  `.socket/vendor/` artifacts in one pass (re-vendoring automatically when a newer patch
  is selected), writing no `.socket/manifest.json`. It works on a fresh clone:
  dependencies listed in the lockfile but not yet installed are fetched pristine from
  their registry and integrity-verified against the lockfile before vendoring;
- `--mode agent` downloads the selected patches into `.socket/manifest.json` + blobs and
  applies them to the installed files in place.

`scan` never prompts, in any mode — `--yes` changes nothing. Use `--dry-run` to preview
any run. A `--prune` or `--global` / `--global-prefix` scan with no mode is the one
report-only case: it lists what it found (plus, with `--prune`, runs the agent-mode
garbage collection) and prints `To apply these patches in place, run: socket-patch scan
--mode agent [PATHS]`. Hosted mode cannot be combined with `--global`.

When a package has several patches, `scan` applies the one described in
[Which patch is picked](#which-patch-is-picked). The JSON `updates[]` array lists
packages whose recorded patch has been superseded — agent manifest entries, vendored
entries, and hosted pins read from the redirect ledger and the lockfiles — and the next
`scan` in that mode takes the newer patch.

**Usage:**
```bash
socket-patch scan [PATHS]... [options]
```

**Arguments:**
- `PATHS` — restrict the scan. In hosted and vendored mode each PATH (or directory glob,
  e.g. `apps/*`) is a **project directory**, scanned on its own as if it were `--cwd`,
  under an `== <dir> ==` header; the worst exit code wins. A PATH that is not a
  directory exits 2, and `--json` accepts only one directory. In agent mode PATHS are
  globs over **installed package paths** (a bare directory scopes its whole subtree;
  `--prune` still considers the whole project, and lockfile-only packages are left out
  with a warning).

**Command-specific options** (plus all [Global options](#global-options)):
| Flag | Env var | Description |
|------|---------|-------------|
| `--mode <hosted\|vendored\|agent>` | — | Selects one of the three [patch modes](#three-patch-modes) (default: `hosted`). Combining `--mode` with a legacy boolean flag of a *different* mode is an error (exit 2); the same mode spelled both ways is accepted. |
| `--package <name\|purl>` | `SOCKET_SCAN_PACKAGES` | Only scan these packages: a name (`lodash`, `@scope/pkg`, `requests`; case-insensitive) or a purl with or without its version (`pkg:npm/lodash`, `pkg:pypi/requests@2.31.0`). Repeat the flag or separate with commas. |
| `--prune` | — | Agent-mode garbage collection after the scan: remove manifest entries for packages no longer present in the crawl (installed trees + lockfiles — a wiped `node_modules` alone doesn't prune lockfile-listed entries) and delete orphan blob/diff/package-archive files. [Vendored](#vendor) packages are exempt from the crawl-based prune, but a vendored entry whose dependency has left the lockfile is reverted. Ignored, with a `redirect_prune_ignored` warning, in hosted mode; without a mode the scan is report-only. |
| `--sync` | — | Shorthand for `--mode agent --prune`: the one-flag agent-mode auto-update run. |
| `--batch-size <n>` | `SOCKET_BATCH_SIZE` | Packages per API request (default: `500` on the authenticated API, `100` on the public proxy). A request whose body would exceed 256 KiB is split into smaller ones. |
| `--all-releases` | `SOCKET_ALL_RELEASES` | Store patches for every release/distribution variant, not just the installed one — PyPI wheel/sdist, RubyGems platform, Maven classifier. Makes the manifest portable across environments (e.g. cross-platform CI caches). |
| `--vex <path>` | `SOCKET_VEX` | On a successful scan, also write an OpenVEX 0.2.0 document to this path. See [Inline VEX](#inline-vex-on-apply--scan--vendor). |
| `--vex-product`, `--vex-no-verify`, `--vex-doc-id`, `--vex-compact` | `SOCKET_VEX_*` | Passthrough to the embedded VEX builder; mirror the standalone [`vex`](#vex) knobs. Inert unless `--vex` is set. |

> Deprecated, hidden spellings (still accepted): `--apply` (== `--mode agent`) and
> `--vendor` (== `--mode vendored`). `--detached` is a hidden no-op kept for compatibility (vendored mode is
> always manifest-free); it is still an error without vendored mode.

**Examples:**
```bash
# Hosted mode (default): rewrite lockfiles to Socket-hosted patched packages
socket-patch scan

# Same, JSON output
socket-patch scan --json

# Preview without writing anything
socket-patch scan --json --dry-run

# Only npm packages / only one package
socket-patch scan --ecosystems npm
socket-patch scan --package lodash

# Two projects of a monorepo
socket-patch scan apps/web apps/api

# Vendored mode: build + commit every patched dependency
socket-patch scan --json --mode vendored

# Agent mode: patch installed files in place
socket-patch scan --json --mode agent

# Agent-mode auto-update: discover, apply, garbage-collect
socket-patch scan --json --sync

# Report-only scan of global packages
socket-patch scan -g

# Hosted mode + an OpenVEX attestation in one pass
socket-patch scan --vex socket.vex.json
```

> Already-vendored packages are **skipped by an agent-mode scan** (the committed
> artifact is the patch); a newer available patch still appears in `updates[]` — re-run
> `scan --mode vendored` to take it.

### `vex`

Generate an [OpenVEX](https://github.com/openvex) 0.2.0 attestation describing the
vulnerabilities that the applied patches have mitigated — agent-mode patches from the
manifest, and hosted / vendored patches straight from the lockfiles (no manifest needed).
See [OpenVEX attestations](#openvex-attestations) below for the full workflow.

**Usage:**
```bash
socket-patch vex [options]
```

**Command-specific options** (plus all [Global options](#global-options)):
| Flag | Env var | Description |
|------|---------|-------------|
| `-O, --output <path>` | `SOCKET_VEX_OUTPUT` | Write the VEX document to this path instead of stdout. Required when combined with `--json`. |
| `--product <id>` | `SOCKET_VEX_PRODUCT` | Override the auto-detected top-level product PURL/identifier. |
| `--no-verify` | `SOCKET_VEX_NO_VERIFY` | Skip the on-disk file-hash check and trust the patch records — useful on a build machine that doesn't have the patched files laid out. The wiring checks still apply: a hosted/vendored ledger record the lockfile no longer wires, or a lockfile reference whose record is unavailable or names another package, is omitted either way. |
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

The command behind [vendored mode](#three-patch-modes). Instead of patching installed
packages in place, it ejects each patched package into
`.socket/vendor/<ecosystem>/<patch-uuid>/…` and rewires your lockfile so the project
consumes the vendored copy. Commit `.socket/vendor/` (the artifacts plus the ledger whose
embedded patch records [`vex`](#vex), [`list`](#list) and [`repair`](#repair) read)
along with the lockfile edits, and **every fresh checkout builds with the patched
dependency**: no `socket-patch` binary, no Socket API access and no install hook on the
consuming machine.

There are two ways in:

- **`socket-patch scan --mode vendored`** discovers, downloads and vendors in one pass,
  writes no `.socket/manifest.json`, and takes over packages a hosted scan redirected
  (their hosted lockfile edits are reverted first). This is the way to move a hosted
  project offline.
- **`socket-patch vendor`** vendors the agent-mode patches listed in
  `.socket/manifest.json`. With no manifest (a hosted or `scan --mode vendored` project)
  it has nothing to vendor and says so; `vendor --revert` works either way.

Vendoring is per-patch: only dependencies with a Socket patch are vendored. For the
lockfile flavors each ecosystem supports, see the
[mode × ecosystem matrix](docs/ecosystems.md#mode--ecosystem-matrix).

**Usage:**
```bash
socket-patch vendor [options]
socket-patch scan --mode vendored [PATHS]... [options]
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
- An agent-mode [`scan`](#scan) skips vendored packages, and `--prune` exempts them
  from its crawl-based prune (though a vendored entry whose dependency has left the
  lockfile is reverted and dropped); newer patches show up in `updates[]` as the signal
  to re-run `scan --mode vendored`.
- [`vex`](#vex) attests vendored patches by verifying the **committed artifact** (marked
  `(vendored)` in the impact statement) — no install step needed.
- Re-running either form is idempotent. Patches dropped from `.socket/manifest.json`
  are auto-reverted on the next `vendor` run; on a project vendored by
  `scan --mode vendored`, use [`repair`](#repair) to verify or rebuild the committed
  artifacts.

**Examples:**
```bash
# Discover, download and vendor every patchable dependency (takes over hosted redirects)
socket-patch scan --mode vendored

# Preview it (would_vendor / would_revendor / already_vendored)
socket-patch scan --json --mode vendored --dry-run

# Vendor the agent-mode patches listed in .socket/manifest.json
socket-patch vendor

# Preview without writing anything
socket-patch vendor --dry-run

# Then make it stick: commit .socket/ (vendor artifacts + ledger) and the lockfile
git add .socket package-lock.json && git commit -m "vendor Socket patches"

# Undo everything (restores the original lockfile byte-for-byte)
socket-patch vendor --revert

# JSON output for scripting
socket-patch vendor --json
```

### `list`

List the patches in this project: the hosted ledger's records (labeled
`Mode: hosted`), the vendor ledger's (`Mode: vendored`), and any agent-mode entries in
`.socket/manifest.json`. A project with none prints `No patches in this project. Run
\`socket-patch scan\`.` (exit 1 when there is no manifest or ledger record at all, 0 for
an empty manifest).

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
Found 1 patch:

Package: pkg:npm/flatted@3.3.1
  UUID: 5cac955f-eab1-4d29-8f4f-c408a6cc9647
  Mode: hosted (recorded in .socket/vendor/redirect-state.json)
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

### Agent mode (older commands)

Agent mode keeps patches in `.socket/manifest.json` + `.socket/blobs/` and edits the
installed files in place, so the CLI has to run again after every install. These
commands drive it. `rollback` also undoes hosted and vendored patches.

### `get`

Get one security patch from the Socket API and apply it. Accepts a UUID, CVE ID, GHSA
ID, PURL, or package name. The identifier type is auto-detected but can be forced with a
flag. Like `scan`, `get` defaults to hosted mode; pass `--mode vendored`, or
`--mode agent` for the manifest + in-place apply (implied by `--save-only` and
`--global`). When a package has
several patches, `get` picks the same one `scan` does (see
[Which patch is picked](#which-patch-is-picked)). Hosted and vendored `get` never
prompt, like `scan`; agent-mode `get` asks before applying (`--yes` or a non-TTY stdin
accepts).

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
| `--one-off` | `SOCKET_ONE_OFF` | Reserved (hidden from `--help`): apply the patch immediately without saving to the `.socket` folder. **Not yet implemented** — the command currently errors up front. |
| `--all-releases` | `SOCKET_ALL_RELEASES` | Download patches for every release/distribution variant of a matched package (PyPI wheel/sdist, RubyGems platform, Maven classifier), not just the installed one. |
| `--mode <hosted\|vendored\|agent>` | — | How to consume the patch; the same modes as `scan --mode` (default: `agent`). |

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

# Consume the patch in hosted mode (lockfile rewrite) instead of in place
socket-patch get CVE-2024-12345 --mode hosted

# Download only, don't apply
socket-patch get CVE-2024-12345 --save-only

# Apply to global packages
socket-patch get lodash -g

# JSON output for scripting
socket-patch get CVE-2024-12345 --json -y
```

### `apply`

Apply the patches in `.socket/manifest.json` to the installed files in place. Idempotent — safe to run from install
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

### Agent mode in CI

Agent mode patches the installed files in place, so every fresh dependency install
reverts the patches until `socket-patch apply` runs again. (Hosted and vendored projects
need no such step: the lockfile already names the patched packages.) Commit
`.socket/manifest.json` and its blobs, then run `apply` in CI after every install:

```bash
# once, locally: record the patches (commit .socket/)
socket-patch scan --mode agent

# in CI, after `npm ci` / `pip install` / `bundle install` / ...
socket-patch apply
```

> **v5.0: `setup` was removed.** It used to wire install hooks (npm `postinstall` /
> `dependencies` scripts, the `socket-patch[hook]` Python `.pth` wheel, a Bundler plugin,
> Composer script events) that ran `apply` for you. Hooks an earlier release committed
> keep working — they call `socket-patch apply`, which still exists — until you delete
> them by hand: the `package.json` scripts, the `socket-patch[hook]` dependency (the
> `socket-patch-hook` wheel is no longer published; `pip uninstall socket-patch-hook`),
> the managed `plugin "socket-patch"` Gemfile block and `.socket/bundler-plugin/`, and
> the `composer.json` script entries.

Per-ecosystem notes for in-place patching:

- **Cargo** patches the crate in place (in `vendor/` or the registry cache, rewriting
  `.cargo-checksum.json` so `cargo build` accepts it) — note that a non-vendored crate
  patches the **shared** `$CARGO_HOME/registry` cache, which affects every project on
  the machine and is silently reset by `cargo clean` or a cache prune; vendor the
  dependency (`--mode vendored`) for a project-local, committable patch.
- **Go** writes a project-local patched copy under `.socket/go-patches/` plus a `go.mod`
  `replace` directive (the module cache is `go.sum`-verified, so in-place patching can't
  build); commit `go.mod` + `.socket/go-patches/` so a clone builds the patched bytes.
- **Maven / NuGet**: in-place patching leaves the caches' own checksum sidecars stale
  (NuGet's fixup deletes `.nupkg.metadata` and raises an advisory for the signed-package
  `.nupkg.sha512` marker; Maven's `.jar.sha1`/`.jar.md5` are left as-is) — the copy-out
  modes, `scan --mode vendored` and `scan --mode hosted`, never touch the caches and
  avoid the issue entirely. See
  [ecosystems.md](docs/ecosystems.md#maven--nuget-caveats).
- **Deno** has no hosted or vendored mode, so agent mode is the only way to patch it.

### `rollback`

Roll back patches to restore the system to unpatched. If no target is given, everything
is rolled back, across all three modes: in-place file restores (agent), vendored unwire +
artifact deletion + ledger-entry drop, and hosted lockfile-redirect unwind + record drop.
The rolled-back entries are then removed from `.socket/manifest.json` (a zero-patch
`{"patches": {}}` husk stays) and their blobs are garbage-collected — a later `apply` has
nothing to re-apply. Pass `--preserve-state` to keep the local patch state (manifest
entries, vendored artifacts + ledger entries) for a later re-apply; use
[`remove`](#remove) for a single patch.

A wet run confirms once (auto-accepted under `--yes`/`--json`/non-TTY). Vendor-owned purls
the run did NOT act on (a corrupt vendor ledger) are listed in the JSON output's
`vendored` array; acted-on entries ride `vendoredReverted` / `vendoredPreserved` /
`vendoredKept`.

**Usage:**
```bash
socket-patch rollback [targets]... [options]
```

**Arguments:**
- `targets` — zero or more package PURLs, patch UUIDs or path globs (unioned). Omit to roll
  back everything.

**Command-specific options** (plus all [Global options](#global-options)):
| Flag | Env var | Description |
|------|---------|-------------|
| `--preserve-state` | `SOCKET_PRESERVE_STATE` | Unpatch the system but keep the local patch state — manifest entries, vendored artifacts + ledger entries — for a later re-apply, and skip GC. Hosted redirects have no preservable state and are unwound either way. |
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

### `remove`

Remove a patch from the manifest (rolls back files first by default). If the package is
[vendored](#vendor), `remove` also **reverts the vendoring** — the lockfile is restored
byte-for-byte and the `.socket/vendor/` artifact is deleted — so the patch is fully gone
in one command. Patches vendored by `scan --mode vendored` have no manifest entry and are
removable by PURL or UUID all the same (reverting the vendoring *is* the removal, so
`--skip-rollback` is refused for them).

**Usage:**
```bash
socket-patch remove <identifier> [options]
```

**Arguments:**
- `identifier` — package PURL (e.g. `pkg:npm/package@version`) or patch UUID.

**Command-specific options** (plus all [Global options](#global-options)):
| Flag | Env var | Description |
|------|---------|-------------|
| `--preserve-state` | `SOCKET_PRESERVE_STATE` | Restore the files and lockfiles but keep the patch's local state (manifest entry, vendored artifact + ledger entry) for a later re-apply, and skip blob cleanup — the single-patch twin of `rollback --preserve-state`. Conflicts with `--skip-rollback`. |
| `--skip-rollback` | `SOCKET_SKIP_ROLLBACK` | Only update the manifest, do not restore original files (for a vendored package that still has a manifest entry this also leaves the vendor wiring + artifact in place; refused for manifest-less vendored patches, where the revert *is* the removal). |

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

Download missing blobs, re-vendor missing or corrupt vendored artifacts, and clean up unused
blobs.

Alias: `gc`

`repair` cleans up the `.socket/` directory without running a scan — useful when you've
manually adjusted the manifest, recovered from a partial-failure state, or just want to
free space. It also re-vendors missing or corrupt vendored artifacts the same way `vendor`
does (the patch service's prebuilt artifact first, a local build as the fallback), checked
against `.socket/vendor/state.json`. `repair` does not recreate a lost `state.json`: if a
lockfile points into `.socket/vendor/` and the ledger has no entry for it, `repair` fails with
`vendor_ledger_missing` — restore `state.json` from version control. For the combined
agent-mode workflow (discover + apply + GC in one pass), use `scan --sync` instead.

Like every other mutating command, `repair` takes the `.socket/apply.lock` advisory lock
while it runs and removes it when it finishes. If another `socket-patch` process is
actively running, `repair` refuses up front with `lock_held` (exit 1); it never steals a
live lock — wait for the other process to finish, or budget a wait with `--lock-timeout`.

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

# Cleanup only — missing blobs are warned about and skipped, never downloaded
socket-patch repair --offline

# Download missing blobs only
socket-patch repair --download-only

# JSON output for scripting
socket-patch repair --json
```

## OpenVEX attestations

`socket-patch vex` turns the patches your project carries into a machine-readable statement of *which
known vulnerabilities no longer affect your build* because a Socket patch has been applied.
This lets vulnerability scanners stop flagging CVEs that you've already remediated in
place — without bumping the package version.

**How it works**

1. Gathers every patch the project can prove: agent-mode patches from
   `.socket/manifest.json`, and [vendored](#vendor) / [hosted](#three-patch-modes) patches
   from the wiring in your **lockfiles** (plus the `.socket/vendor` ledgers when they are
   committed). See [No manifest needed for hosted and vendored
   patches](#no-manifest-needed-for-hosted-and-vendored-patches).
2. Unless `--no-verify` is passed, re-checks each patch's bytes so the attestation only
   covers patches that are actually applied: agent patches against the installed tree,
   vendored patches against the **committed artifact** (marker `(vendored)`), and hosted
   patches against the installed copy the build consumes — or, before any install, against
   the lockfile's integrity pin (marker `(redirected)`). Whatever `--no-verify` says, a ledger record the
   lockfile no longer wires is never attested.
3. Auto-detects the top-level **product** identifier (override with `--product`), probing
   in order:
   - `.git/config` `[remote "origin"]` → `pkg:github/<owner>/<repo>` (similar for
     GitLab/Bitbucket; raw URL otherwise)
   - `package.json` → `pkg:npm/<name>@<version>`
   - `pyproject.toml` → `pkg:pypi/<name>@<version>`
   - `Cargo.toml` → `pkg:cargo/<name>@<version>`
   - `go.mod` → `pkg:golang/<module>`
   - `composer.json` → `pkg:composer/<vendor>/<name>[@<version>]`
   - `pom.xml` → `pkg:maven/<groupId>/<artifactId>[@<version>]`
   - the root's single `*.csproj` → `pkg:nuget/<id>[@<version>]`
   - the root's single `*.gemspec` → `pkg:gem/<name>[@<version>]`
4. Emits an OpenVEX 0.2.0 document whose statements mark each mitigated vulnerability as
   `not_affected` (justification: the patch is present), suitable for piping into
   `vexctl`, Grype, Trivy, and similar tools.

**Provenance markers**

Each statement's impact string records *how* the patch is persisted — one marker per
[patch mode](#three-patch-modes):

| Impact statement | Mode | What the evidence is | What a consumer should do |
|---|---|---|---|
| `Patched via Socket patch <uuid>` | agent | The installed tree: every patched file's hash was verified against the manifest's `afterHash` | Trust the statement as long as a CI `apply` keeps re-applying after every install |
| `Patched via Socket patch <uuid> (vendored)` | vendored | The **committed** `.socket/vendor/` artifact was hash-verified — no install hook needed; the lockfile wiring is the persistence mechanism | Trust it on any checkout; the committed bytes are the patch |
| `Patched via Socket patch <uuid> (redirected)` | hosted | The lockfile's integrity pin points at the Socket-hosted patched package. A post-install `socket-patch vex` hash-verifies the installed copy; before any install it attests from the pin. When emitted in-run by a hosted `scan --vex`, the statement is attested **without hash verification** (the bytes are fetched at install time — the JSON `vex` summary carries `verified: false`) | Ensure installs still resolve from `patch.socket.dev` (the lockfile edit is intact), and run `socket-patch vex` **after installing** to have the redirected patches hash-verified against the installed tree |

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

Patch first (in any mode). When nothing names a patch anywhere — no manifest
entry, no `.socket/vendor` ledger entry, no hosted or vendored lockfile reference — `vex`
errors with `no_patches` (exit 1) when the manifest file exists but is empty, or with
`manifest_not_found` (exit 2) when there is no manifest either. When there are patches but
none can be attested, it exits 1 with `no_applicable_patches`, and each omission is listed
with its reason: `hash_mismatch`, `record_unavailable`, `redirect_unwired`, and so on.

### No manifest needed for hosted and vendored patches

A hosted or vendored checkout needs no `.socket/manifest.json`, and no `.socket/vendor`
ledgers either. This covers a depscan-opened PR, a clone of a repo that never committed its
ledgers, and a fresh hosted `scan`. `vex` reads the patch reference out of each root
lockfile or config: a `patch.socket.dev` URL or a `.socket/vendor/<eco>/<uuid>/…` path
carries the patch uuid. It then finds that patch's record in the manifest or ledgers, or
fetches it from the patch API. The references it accepts are what socket-patch's own
rewriters write: a URL on any other host, or an entry the package manager would not
install from, is ignored.

```bash
# Fresh clone of a hosted or vendored project: nothing installed, no .socket/manifest.json
socket-patch vex --output socket.vex.json
```

Behavior worth knowing:

- **Network.** Without a local record, `vex` fetches the patch by uuid from the patch API.
  With `--offline`, or when the fetch fails or the patch is paid and not entitled, the patch
  is omitted as `record_unavailable`. Commit the ledgers, or keep the manifest, to attest
  offline.
- **Liveness.** A ledger entry attests only while a lockfile still wires it. Otherwise it is
  omitted as `vendor_unwired` or `redirect_unwired`, even under `--no-verify`. Lockfiles
  that wire one package to different patches (`wiring_conflict`) attest none of them. A
  package that one lock wires to a patch while another lock resolves it from the registry
  is not attested either.
- **Diagnostics.** A lockfile that cannot be read or parsed, or a Socket reference that
  fails validation, is reported as a warning (`lockfile_unparseable`, `patched_ref_invalid`,
  …) and never aborts the run. With `--json` these go in `warnings[]`.
- **Scope.** Only the project root is read (plus Rush's `common/config` pnpm locks). Nested
  workspace-member lockfiles are not.

| Ecosystem | Files read (project root) | Limitations |
|---|---|---|
| npm | `package-lock.json`, `npm-shrinkwrap.json` (both) | `link` / bundled entries never count |
| pnpm | `pnpm-lock.yaml` (all generations), `shrinkwrap.yaml` (pnpm 1/2), Rush locks | Aliased / nested `resolution` shapes are diagnosed, not attested; `overrides` alone prove nothing |
| yarn | `yarn.lock` (classic + berry) | Berry vendored entries also need the root `package.json` `resolutions` mapping; member locks are not read |
| bun | `bun.lock`, else `bun.lockb` | A hosted entry that Bun < 1.3.10 re-saved without its sha512 attests only after install |
| vlt | `vlt-lock.json` (`lockfileVersion` absent, 0 or 1) | A BOM-prefixed or other-version lock wires nothing; a same-version instance on another registry keeps a hosted pin from attesting before install; a vendored directory whose `package.json` patch lost its devDependencies needs the patched blob in `.socket/blobs` without the vendor ledger |
| cargo | `Cargo.lock`, `Cargo.toml`, `.cargo/config[.toml]` | Root manifest + project config only (no `$CARGO_HOME` / parent configs); vendored `[patch.crates-io]` entries are read from `Cargo.toml` first (v5), the project config for pre-v5 projects, and must agree with the detached lock entry's tagged version `<version>+socket.<uuid>` (a tag for another uuid — in the lock or in the copy's own `Cargo.toml` — is dead wiring; an untagged detached entry counts only beside an untagged, pre-tag copy); a manifest entry cargo ignores (a same-key project-config item, or a URL-spelled crates.io `[patch]` table) is not attested; a lockless hosted pin needs the redirect ledger's record |
| golang | `go.mod`, `go.work`, `go.sum`, `go.work.sum` | A replace that `require` no longer selects is inert; `vendor/modules.txt` is not read |
| pypi | `uv.lock`, `*.py.lock`, `pylock*.toml`, `poetry.lock`, `pdm.lock`, `Pipfile.lock`, `requirements.txt` (+ `-r` includes), `pyproject.toml` / `hatch.toml` | A `uv.lock` beside a `pyproject.toml` must agree with its `[tool.uv.sources]`; PDM 3.1 / 4.0–4.2 locks are refused; a Pipenv project needs `--product` (or a git remote) |
| gem | `Gemfile.lock`, `gems.locked` | Platform gems unsupported; a Gemfile-only (pre-bundler-2.6, not yet locked) wiring needs the redirect ledger |
| composer | `composer.lock` | `installed.json` and `COMPOSER=`-renamed locks are not read |
| maven | `pom.xml` (+ `.mvn/` checksums) | Root pom only (no parents / submodules, no Gradle); legacy same-GAV hosted repositories cannot be attributed |
| nuget | `nuget.config`, `packages.lock.json` | Hosted needs a `packages.lock.json` entry for the id (with no lock at all, an exclusive exact-id mapping still keeps the redirect ledger's record live); root config only |
| deno | none | No hosted or vendored mode exists; Deno patches attest only through the manifest (agent mode) |

The full recognition rules are in
[CLI_CONTRACT.md](crates/socket-patch-cli/CLI_CONTRACT.md) ("Manifest-less VEX").

### Inline VEX on `apply` / `scan` / `vendor`

You don't need a separate `vex` invocation: pass `--vex <path>` to `apply`, `scan`, or
`vendor` and the same OpenVEX document is generated as a side-effect of a successful run.

```bash
# Hosted scan and attest in one step (not hash-verified until installed: re-run `vex` then)
socket-patch scan --vex socket.vex.json

# Vendor and attest — manifest-less by construction
socket-patch scan --json --mode vendored --vex socket.vex.json

# Agent mode: patch in place and attest
socket-patch apply --vex socket.vex.json
socket-patch scan --json --sync --vex socket.vex.json
```

The `--vex-product`, `--vex-no-verify`, `--vex-doc-id`, and `--vex-compact` flags mirror
the standalone command's `--product` / `--no-verify` / `--doc-id` / `--compact` knobs.

Contract:

- The document is **always written to the file** (never stdout), so it never collides
  with the command's own `--json` output. JSON mode adds a top-level `vex` summary —
  `{ path, statements, format }` — to the envelope (`apply`) / result (`scan`).
- It's built from the project **as it stands after the run** — the manifest (including
  any `--mode agent` writes), the `.socket/vendor` ledgers, and the lockfile wiring — and
  verified against on-disk state unless `--vex-no-verify` is set. Generated for real runs
  and report-only scans alike; `--dry-run` skips it (nothing was changed, so nothing is
  attested).
- `apply --vex` and `vendor --vex` with **no manifest** still attest what the lockfiles and
  ledgers wire. A project with nothing wired anywhere keeps the calm exit 0 and writes no
  document. `apply --check` never generates one.
- **Fail-the-command:** if `--vex` was requested but generation fails (no detectable
  product, nothing attestable, a corrupt ledger, unwritable path), the command exits
  non-zero **even when the apply/scan itself succeeded**, with a stable error code in the
  JSON output.

## Scripting & CI/CD

All commands support `--json` for machine-readable output. JSON responses always include
a `"status"` field for easy error detection.

**Authentication in CI:** a runner has no `socket login` state — if your organization
has org-tier patches, provide the token as a CI secret via `SOCKET_API_TOKEN` (without
it, runs silently fall back to the anonymous public proxy and see free patches only, and
paid-tier blob downloads report `paidRequired`). To deliberately pin a run to the
anonymous free tier, set `SOCKET_NO_API_TOKEN=1`. See
[Configuration sources](#configuration-sources).

```bash
# Read-only check: what would a hosted scan patch? (writes nothing)
result=$(socket-patch scan --json --dry-run --ecosystems npm)
echo "$result" | jq '{patches: .totalPatches, redirected: .redirect.redirected, updates: (.updates | length)}'

# Auto-update bot (hosted): take new and newer patches, then let the PR action commit
socket-patch scan --json | jq '{redirected: .redirect.redirected, files: .redirect.rewrittenFiles}'
# The PR action (e.g. peter-evans/create-pull-request) commits the working-tree
# changes (lockfiles + .socket/vendor/); use this summary as the PR body.

# Agent-mode bot: discover, apply, and garbage-collect in one pass
socket-patch scan --json --sync | jq '{
  applied:     [.apply.patches[]? | select(.action == "added" or .action == "updated") | .purl],
  pruned:      (.gc.prunedManifestEntries // []),
  bytes_freed: (.gc.bytesFreed // 0)
}'

# Agent mode: re-apply committed patches and check the result
socket-patch apply --json | jq '.status'
# "success", "partialFailure", "noManifest", or "error"
```

`scan` and hosted/vendored `get` never prompt, so CI needs no `--yes` for them. The
commands that do confirm (agent-mode `get`, `rollback`, `remove`) auto-proceed when stdin is not a TTY. Progress
indicators and ANSI colors are automatically suppressed when output is piped.

The exact JSON shapes, exit codes, and stability guarantees are specified in
[CLI_CONTRACT.md](crates/socket-patch-cli/CLI_CONTRACT.md).

## Manifest format

Agent mode records downloaded patches in `.socket/manifest.json` (hosted and vendored
mode never write it):

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

A manifest written by an earlier release may also carry a top-level `"setup"` key
(`manual`, `exclude`) from the removed `setup` command; v5 keeps it on rewrite but
ignores it.

## Further reading

- **[Ecosystem & platform support](docs/ecosystems.md)** — the full mode × ecosystem
  matrix, per-ecosystem caveats (Maven, NuGet, Rush monorepos, Go), and supported
  platforms.
- **[CLI contract](crates/socket-patch-cli/CLI_CONTRACT.md)** — the machine-readable
  surface: exact JSON shapes, exit codes, flag/env bindings, and the semver policy that
  governs them.
- **[Design notes](docs/design/)** — e.g. [the configuration model](docs/design/configuration.md)
  and [hosted mode for Go](docs/design/golang-hosted.md) (free tier; the
  [paid-tier no-go analysis](docs/design/golang-hosted-no-go.md) it supersedes).
- **[Changelog](CHANGELOG.md)**
