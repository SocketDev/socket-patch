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
> apply.
> To walk the rest of the loop anyway, make a scratch project pinned to a version
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
Found 1 patch:

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
git add .socket package.json # npm example — setup prints which files it changed
git commit -m "apply Socket security patches"
```

From now on, every install — yours, your teammates', CI's — re-applies the patches. You
can also re-apply manually at any time with `socket-patch apply` (it's idempotent).

**4. Undo, if you want.** Remove a patch completely (restores the original files and
deletes the manifest entry):

```bash
socket-patch remove "pkg:npm/flatted@3.3.1"
```

That's the whole loop: **scan → apply when prompted → setup → commit**. This tutorial
used the default *agent* mode, where the CLI re-applies patches after each install.
There are two other ways to persist patches — committing the patched packages themselves
(*vendored*) or pinning them in your lockfile (*hosted*) — and choosing between the
three is the next section.

## How Socket Patch works

**A patch** is a minimal fix — usually the upstream security fix, backported — for one
exact published version of a package. Socket distributes it as per-file edits: for each
touched file, the hash of the expected original (`beforeHash`), the hash of the patched
result (`afterHash`), and the replacement content. By default, a file whose current
content matches neither the expected original nor the patched result is overwritten with
the full verified patched content plus a stderr warning (`content_mismatch_overwritten`);
pass `--strict` (a [global option](#global-options)) to fail closed on mismatch instead,
or `apply --force` to skip pre-application hash verification entirely (see
[`apply`](#apply)). Either way the CLI verifies the result after writing. Patches are
looked up by package URL ([PURL](https://github.com/package-url/purl-spec)) — e.g.
`pkg:npm/lodash@4.17.20` — so everything is keyed to exact versions.

**Local state lives in `.socket/`** at your project root, and is designed to be
committed:

| Path | Contents |
|------|----------|
| `.socket/manifest.json` | Agent mode: the record of downloaded patches — PURLs, file hashes, vulnerability metadata ([format](#manifest-format)) |
| `.socket/blobs/` | Agent mode: patched file contents, named by git-sha256 hash |
| `.socket/vendor/` | Vendored package artifacts and the vendor/redirect ledgers — the **only** state vendored and hosted modes write (the vendor ledger embeds the patch records; neither mode touches `manifest.json`) |

> While a command runs it holds a transient advisory lock, `.socket/apply.lock`, and
> removes it when it finishes — the file never outlives the command, so there is nothing
> to `.gitignore`. A crashed run can leave one behind; the next command reclaims and
> removes it. Nothing in the table is written until there is something to record: a
> report-only `scan`, a `--dry-run`, or a run that changes nothing leaves no `.socket/` at
> all, and a full [`rollback`](#rollback) removes everything it created (only the
> zero-patch `manifest.json` and any [`setup`](#setup) files stay).

### Three patch modes

The same patched bytes can reach your build three different ways. The modes differ in
*where the patch lives* and *what must happen at install time*; pick one per project
(`scan --mode <name>` drives exactly one mode per run).

| Mode | Where the patch lives | Install-time requirement | Trade-off |
|------|----------------------|--------------------------|-----------|
| **agent** — `scan --mode agent` (or [`apply`](#apply)) | `.socket/` manifest + blobs, committed; the CLI re-applies after each install | The `socket-patch` CLI must run (install hook via [`setup`](#setup), or an `apply` step in CI) | Small repo footprint (per-file blobs, not whole packages); no lockfile edits; the only mode that needs CI / install-hook changes |
| **vendored** — `scan --mode vendored` (or [`vendor`](#vendor)) | Patched packages committed under `.socket/vendor/` (with a ledger that embeds the patch records — `scan --mode vendored` writes no manifest; the standalone `vendor` command is manifest-driven and keeps only a fallback copy in the ledger); the lockfile is rewired to consume them | **None** — the package manager installs the committed bytes | Fully airgapped and hermetic, at the cost of repo size |
| **hosted** — `scan --mode hosted` | No patched bytes in your repo: the lockfile is rewritten so **only** the patched dependencies resolve to Socket-hosted, integrity-pinned packages on `patch.socket.dev`; the edits + patch records are ledgered in `.socket/vendor/redirect-state.json` (commit it — [`rollback`](#rollback) replays its recorded pre-redirect originals to unwind the redirect, see [Undo things](#undo-things), and [`vex`](#vex) uses its records offline; `vex` also works from the rewritten lockfile alone) | Installs must be able to reach `patch.socket.dev` (no CLI, no install hook) | Smallest possible diff (lockfile + ledger); not for airgapped installs |

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

### npm compatibility (hosted mode and npm 12)

npm 12 defaults to `allow-remote=none` and refuses (`EALLOWREMOTE`) any lockfile
entry whose tarball is not served by your configured registry — which is what a
hosted redirect writes. So when `scan --mode hosted` (or `get --mode hosted`) leaves a
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

### Bun compatibility

Both text `bun.lock` and binary `bun.lockb` support hosted and vendored
patches, mode switching, repair, and rollback. Binary locks are read and
patched natively: Socket Patch does not need Bun installed to discover or
rewrite them, and does not convert them to text. If both filenames exist,
`bun.lock` takes precedence. See [Bun compatibility](docs/testing/bun-compatibility.md)
for the tested versions, workspace behavior, and installer integrity limits.

### vlt compatibility

[vlt](https://www.vlt.sh) projects (`vlt-lock.json`) work in every mode, on every vlt
release from 0.0.0-1 to 1.2.0 (both DepID grammars and every `lockfileVersion`).
Agent mode patches each copy in `node_modules/.vlt` without writing through vlt 1.2's
shared store. Hosted mode repoints the patched nodes' integrity and URL, first checks
that each artifact is served the way vlt can verify, and removes stale installed copies
so the next `vlt install` fetches the patched packages. Vendored mode commits a patched
package directory for each direct dependency of the root or a workspace member
(transitive dependencies need hosted mode). vlt is detected ahead of every other
npm-family package manager. vlt ledgers require the socket-patch release that adds vlt support.
See [vlt notes](docs/ecosystems.md#npm-vlt-notes) for the caveats (`vlt update`, optional
dependencies, registry configuration) and [vlt compatibility](docs/testing/vlt-compatibility.md)
for the tested releases.

### Pipenv compatibility

Hosted mode rewrites every `Pipfile.lock` category that pins the patched
release (`default`, `develop`, and Pipenv 2022+ named categories) and
preserves the Pipfile, its content hash, markers, extras, and unrelated lock
entries, so `pipenv install --deploy`, `pipenv sync` and `pipenv verify` keep
passing. The reference shape follows the installing Pipenv: releases 7–11
need `path` references, 2018 and later use `file` references, and lock
formats before `pipfile-spec: 6` (Pipenv 0–6) are refused without changing
the lock. Socket Patch probes `pipenv --version` once per run (only when a
patch targets the lock); `SOCKET_PIPENV_MAJOR=<major>` pins the answer for
machines without pipenv on PATH. Hosted references carry both the `#sha256=`
URL fragment (verified by Pipenv 2023+) and a `hashes` entry (verified by
2018–2022; Pipenv 11 verifies either), so a tampered lock fails to install
on every supported release.

Vendored mode requires Pipenv 2018 or later. Wheels with extras use `path`
references to avoid Pipenv 2022's local-file URL parsing bug. Pipenv 2023+
does not enforce hashes on local wheels; commit the wheel and run
`socket-patch vex --product <purl>` (a Pipfile names no project, so pass the
product purl explicitly).

Fresh checkouts work in every mode: a clone with only `Pipfile` +
`Pipfile.lock` is discovered from the lock (hosted redirects it, vendored
fetches the pristine wheel by one of the lock's recorded digests), and agent
mode finds Pipenv's default out-of-tree virtualenv under `WORKON_HOME`
without `pipenv run`.

Pipenv never reinstalls a release that is already present: `pipenv install`,
`pipenv install --deploy` and `pipenv sync` all exit 0 and keep the installed
bytes, on every Pipenv major. A hosted or vendored rewrite therefore
protects fresh installs, and Socket Patch warns
(`redirect_pypi_stale_install` / `pypi_pipenv_stale_install`) when a venv
still holds the upstream release, with the verified remedy:
`pipenv run pip uninstall -y <pkg> && pipenv sync` (or `pipenv --rm &&
pipenv sync`). Do not use `pipenv uninstall <pkg>` for this — it rewrites the
Pipfile and re-locks the patch away. `pipenv lock` / `pipenv update`
regenerate the entry to its registry reference (a silent unpatch): re-run
Socket Patch afterwards; `rollback` retires the stale record cleanly.

`scripts/backtest-pipenv.py` drives the real CLI and the last stable release
of every published Pipenv major through hosted, vendored, agent and
out-of-tree agent mode, and `docs/testing/pipenv-compatibility.md` holds the
measured boundaries and results.

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
git add .socket package-lock.json            # your lockfile may differ

# Hosted: smallest diff — patched deps resolve from patch.socket.dev
socket-patch scan --json --mode hosted --yes
git add .socket/vendor/redirect-state.json package-lock.json .npmrc # .npmrc: npm 12 allow-remote
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
the PR title/body. See [Scripting & CI/CD](#scripting--cicd), including how to supply
`SOCKET_API_TOKEN` for org-tier patches.

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
| [`rollback`](#rollback) | **Fully unpatches, in every mode**: restores the original file bytes, unwinds vendored and hosted lockfile wiring, removes the rolled-back entries from the manifest (a zero-patch `{"patches": {}}` husk stays) and garbage-collects their blobs — everything, or just the given targets; `--preserve-state` keeps the local patch state for a later re-apply |
| [`remove`](#remove) | The single-patch dual of `rollback`: everything `rollback <id>` does for one PURL/UUID (restore, unwind its vendoring or hosted redirect, drop the entry, GC), plus `--skip-rollback` to drop only the record — **permanent**, the patch is fully gone in one command |
| [`vendor --revert`](#vendor) | **Un-vendors wholesale**: restores the recorded original lockfile fragments byte-for-byte and removes the `.socket/vendor/` artifacts — works without a manifest |
| [`scan --prune`](#scan) | **Reconciles, doesn't reverse**: drops manifest entries for packages that have left the project and garbage-collects orphan blob/diff/archive files — installed patches stay |
| [`repair`](#repair) (alias `gc`) | **Restores health, not originals**: re-downloads missing blobs, rebuilds missing/corrupt vendored artifacts, and cleans up unused ones |

And `setup --remove` reverts the install hooks that `setup` added.

> Hosted mode is unwound by [`rollback`](#rollback), which replays the original
> lockfile / registry-config fragments recorded in `.socket/vendor/redirect-state.json`
> and drops the redirect records. If you revert a hosted edit by hand instead (e.g.
> `git checkout -- <lockfile>`), also delete that ledger — its recorded originals are
> then stale. (A leftover ledger no longer makes [`vex`](#vex) attest the removed
> redirects: a record attests only while a lockfile still wires its hosted patch, and is
> otherwise omitted as `redirect_unwired`.)

## Command reference

| Command | What it does |
|---------|--------------|
| [`scan`](#scan) | Scan installed packages for available security patches |
| [`apply`](#apply) | Apply security patches from the local manifest |
| [`vex`](#vex) | Generate an OpenVEX attestation for the applied patches |
| [`vendor`](#vendor) | Eject patched dependencies into committable `.socket/vendor/` |
| [`setup`](#setup) | Wire install hooks so patches re-apply automatically |
| [`rollback`](#rollback) | Fully unpatch everything (or the given targets) in every mode and drop the rolled-back manifest entries (`--preserve-state` keeps them) |
| [`get`](#get) | Fetch and apply a patch by UUID / CVE / GHSA / PURL / name (alias: `download`) |
| [`list`](#list) | List recorded patches: manifest entries plus vendor-ledger and redirect-ledger records |
| [`remove`](#remove) | Remove a patch: roll back files + delete the manifest entry |
| [`repair`](#repair) | Download missing blobs, rebuild vendored artifacts, clean up unused ones (alias: `gc`) |

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
| `--lock-timeout <secs>` | `SOCKET_LOCK_TIMEOUT` | Seconds to wait for `.socket/apply.lock` before giving up. `0`/unset = a single non-blocking try; a positive value retries with backoff. Only meaningful for the commands that take the lock — `apply`, `rollback`, `repair`, `remove`, `vendor`, `setup` (while persisting `--exclude`), and `scan`/`get` whenever they write (agent-mode download + apply, vendored, hosted). The lock file exists only while a command runs. |
| `--debug` | `SOCKET_DEBUG` | Emit verbose debug logs to stderr. |
| `--no-telemetry` | `SOCKET_TELEMETRY_DISABLED` | Disable anonymous usage telemetry. |

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

The sections below list only each command's **command-specific** flags.

### `scan`

Scan installed packages for available security patches — and, with `--mode`, act on what
it finds. `scan` is the entry point for all three [patch modes](#three-patch-modes):

- `--mode agent` downloads and applies the selected patches in place;
- `--mode vendored` discovers, downloads, and builds + wires the committable
  `.socket/vendor/` artifacts in one pass (re-vendoring automatically when a newer patch
  is selected); it is manifest-free — the vendor ledger embeds the patch records and
  nothing else is written under `.socket/`;
- `--mode hosted` rewrites lockfiles / registry configs so only the patched dependencies
  resolve to Socket-hosted packages.

Without a mode, interactive `scan` prompts before applying (in a TTY — when stdin is not a
TTY and neither `--yes` nor a mode/`--prune` flag is given, it is report-only: it prints what
it found plus the "To apply a single patch, run: …" hint, writes nothing, and exits 0), and
`scan --json` is read-only (discovery plus an `updates[]` array; no mutation).

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
| `--prune` | — | Garbage-collect after the scan: remove manifest entries for packages no longer present in the crawl (installed trees + lockfiles — a wiped `node_modules` alone doesn't prune lockfile-listed entries) and delete orphan blob/diff/package-archive files. Off by default. [Vendored](#vendor) packages are exempt from the crawl-based prune (an absent installed copy is their normal state), but a vendored entry whose dependency has left the lockfile is reverted (and any manifest entry it still had dropped). Orthogonal to `--mode` — combines with any mode. |
| `--detached` | — | Hidden compatibility no-op. Vendored mode is manifest-free by default: the vendor ledger (`.socket/vendor/state.json`) embeds the patch records and `.socket/manifest.json` is never written, so this former opt-in changes nothing. Still an error without `--mode vendored`. |
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

# Preview a vendored run (would_vendor / would_revendor / already_vendored)
socket-patch scan --json --mode vendored --yes --dry-run

# Hosted mode: rewrite lockfiles so patched deps resolve to Socket-hosted
# integrity-pinned packages — no artifact bytes in the repo, no CI changes.
socket-patch scan --json --mode hosted --yes
```

> Already-vendored packages are **skipped by plain `--mode agent`** (the committed
> artifact is the patch); a newer available patch still appears in the JSON `updates[]`
> array — re-run `scan --mode vendored` to take it.
>
> Hosted-managed dependencies get the same signal: `updates[]` also consults the
> `.socket/vendor/redirect-state.json` ledger, so a superseded hosted patch shows up in
> read-only `scan --json` — re-run `scan --mode hosted` to take it.

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

`apply`'s **committable** sibling — the standalone command behind
[vendored mode](#three-patch-modes) (`scan --mode vendored` runs discovery + this engine
in one pass). Instead of patching installed packages in place (machine-local state),
`vendor` ejects each patched package into `.socket/vendor/<ecosystem>/<patch-uuid>/…` and
rewires your lockfile so the project consumes the vendored copy. Commit `.socket/vendor/` —
the vendored artifacts plus the ledger whose embedded patch records [`vex`](#vex),
[`list`](#list), and [`repair`](#repair) read (vendored mode writes nothing else under
`.socket/`; `vex` can also attest from the lockfile wiring alone) — along with the lockfile
edits, and **every fresh checkout
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
- Re-running `vendor` is idempotent. Standalone `vendor` (no flags) is driven by
  `.socket/manifest.json` — patches dropped from that manifest are auto-reverted on the
  next run — so on a project vendored by `scan --mode vendored` (no manifest) it is a
  clean no-op; use [`repair`](#repair) to verify or rebuild the committed artifacts there.

**Examples:**
```bash
# Vendor every patched dependency listed in the manifest
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

> Prefer one command? [`scan --mode vendored`](#scan) discovers, downloads, *and* vendors
> in a single pass.

### `setup`

Configure your project so patches are **re-applied automatically after install** — no
manual `socket-patch apply` step in CI. `setup` is a one-time operation: run it, commit
the change together with your `.socket/` patches, and every later install handles the
rest. It is strictly **opt-in** — nothing is hooked unless you run `setup` and commit the
result.

What gets wired, per ecosystem:

- **npm / yarn / pnpm / bun / vlt** — writes `postinstall` and `dependencies` scripts into
  `package.json` so any install — including `npm install <pkg>` — re-applies patches
  (pnpm and vlt: root package only). vlt uses the same `npx` hook, runs it on every
  install that changes the tree (never on a no-op install), and aborts the install when
  it fails; vlt before 1.0.0-rc.13 never runs a root `postinstall`, which `setup` warns
  about (`vlt_root_scripts_not_run`).
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
  CLI on `PATH`, and **bundler >= 2.2**: bundler 1.x cannot load a `plugin ... path:`
  directive — it resolves it as an ordinary gem and every later `bundle install` fails —
  so `setup` refuses to wire a project whose lock or `bundle --version` reports an older
  bundler, and `setup --check` red-flags a wired project that lands in that state.)
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
  and NuGet, note that in-place patching leaves the caches' own checksum sidecars stale
  (NuGet's fixup deletes `.nupkg.metadata` and raises an advisory for the signed-package
  `.nupkg.sha512` marker; Maven's `.jar.sha1`/`.jar.md5` are left as-is) — the copy-out
  modes, `scan --mode vendored` and `scan --mode hosted`, never touch the caches and
  avoid the issue entirely. See
  [ecosystems.md](docs/ecosystems.md#maven--nuget-caveats).

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
| `--remove` | — | Revert every install hook `setup` added (npm `package.json` scripts, the Python `socket-patch[hook]` dependency, the gem Bundler plugin wiring — including bundler's machine-local `.bundle/plugin` registration, so later `bundle install`s don't warn about the unwired plugin — and the Composer `post-install-cmd`/`post-update-cmd` script entries). If the registration can't be cleared automatically (unexpected index format), the error names the fallback: `bundler plugin uninstall socket-patch`. |
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

Roll back patches to restore the system to unpatched. If no target is given, everything
is rolled back, across all three modes: in-place file restores (agent), vendored unwire +
artifact deletion + ledger-entry drop, and hosted lockfile-redirect unwind + record drop.
The rolled-back entries are then removed from `.socket/manifest.json` (a zero-patch
`{"patches": {}}` husk stays) and their blobs are garbage-collected — a later `apply` has
nothing to re-apply. Pass `--preserve-state` to keep the local patch state (manifest
entries, vendored artifacts + ledger entries) for a later re-apply; use
[`remove`](#remove) for a single patch.

A wet run confirms once (auto-accepted under `--yes`/`--json`/non-TTY). Vendor-owned purls
the run did NOT act on (today: a corrupt vendor ledger) are listed in the JSON output's
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
| `--one-off` | `SOCKET_ONE_OFF` | Reserved (hidden from `--help`): apply the patch immediately without saving to the `.socket` folder. **Not yet implemented** — the command currently errors up front. |
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

List all patches recorded locally: the manifest's entries plus the vendor ledger's
(labeled `Mode: vendored`) and the hosted redirect ledger's records, so it works on
manifest-less vendored or hosted projects too.

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

Download missing blobs, rebuild missing or corrupt vendored artifacts, and clean up unused
blobs.

Alias: `gc`

`repair` cleans up the `.socket/` directory without running a scan — useful when you've
manually adjusted the manifest, recovered from a partial-failure state, or just want to
free space. It also rebuilds missing or corrupt vendored artifacts. For the combined
workflow (discover + apply + GC in one pass), use
`scan --json --mode agent --prune --yes` instead.

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
   the lockfile's integrity pin (marker `(redirected)`). Vendored and hosted patches need
   no `setup` install hook to be attested. Whatever `--no-verify` says, a ledger record the
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
| `Patched via Socket patch <uuid>` | agent | The installed tree: every patched file's hash was verified against the manifest's `afterHash` | Trust the statement as long as the agent install hook (or a CI `apply`) keeps re-applying; ecosystems without a hook must be declared in `setup.manual` |
| `Patched via Socket patch <uuid> (vendored)` | vendored | The **committed** `.socket/vendor/` artifact was hash-verified — no install hook needed; the lockfile wiring is the persistence mechanism | Trust it on any checkout; the committed bytes are the patch |
| `Patched via Socket patch <uuid> (redirected)` | hosted | The lockfile's integrity pin points at the Socket-hosted patched package. A post-install `socket-patch vex` hash-verifies the installed copy; before any install it attests from the pin. When emitted in-run by `scan --mode hosted --vex`, the statement is attested **without hash verification** (the bytes are fetched at install time — the JSON `vex` summary carries `verified: false`) | Ensure installs still resolve from `patch.socket.dev` (the lockfile edit is intact), and run `socket-patch vex` **after installing** to have the redirected patches hash-verified against the installed tree |

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

Apply patches first (in any mode). When nothing names a patch anywhere — no manifest
entry, no `.socket/vendor` ledger entry, no hosted or vendored lockfile reference — `vex`
errors with `no_patches` (exit 1) when the manifest file exists but is empty, or with
`manifest_not_found` (exit 2) when there is no manifest either. When there are patches but
none can be attested, it exits 1 with `no_applicable_patches`, and each omission is listed
with its reason: `hash_mismatch`, `record_unavailable`, `redirect_unwired`, and so on.

### No manifest needed for hosted and vendored patches

A hosted or vendored checkout needs no `.socket/manifest.json`, and no `.socket/vendor`
ledgers either. This covers a depscan-opened PR, a clone of a repo that never committed its
ledgers, and a `scan --mode hosted` run. `vex` reads the patch reference out of each root
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
| deno | none | No hosted or vendored mode exists; Deno patches attest only through the manifest (agent mode + `setup.manual`) |

The full recognition rules are in
[CLI_CONTRACT.md](crates/socket-patch-cli/CLI_CONTRACT.md) ("Manifest-less VEX").

### Inline VEX on `apply` / `scan` / `vendor`

You don't need a separate `vex` invocation: pass `--vex <path>` to `apply`, `scan`, or
`vendor` and the same OpenVEX document is generated as a side-effect of a successful run.

```bash
# Patch and attest in one step
socket-patch apply --vex socket.vex.json

# Discover, apply, prune, and attest — the full auto-update-bot pass
socket-patch scan --json --mode agent --prune --yes --vex socket.vex.json

# Vendor and attest — manifest-less by construction
socket-patch scan --json --mode vendored --yes --vex socket.vex.json
```

The `--vex-product`, `--vex-no-verify`, `--vex-doc-id`, and `--vex-compact` flags mirror
the standalone command's `--product` / `--no-verify` / `--doc-id` / `--compact` knobs.

Contract:

- The document is **always written to the file** (never stdout), so it never collides
  with the command's own `--json` output. JSON mode adds a top-level `vex` summary —
  `{ path, statements, format }` — to the envelope (`apply`) / result (`scan`).
- It's built from the project **as it stands after the run** — the manifest (including
  any `--mode agent` writes, with or without `--prune`), the `.socket/vendor` ledgers, and
  the lockfile wiring — and verified against on-disk state unless `--vex-no-verify` is set.
  Generated for real applies and read-only scans alike; `--dry-run` skips it (nothing was
  changed, so nothing is attested).
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
of blocking — with one deliberate exception: a plain `scan` (no `--mode`/`--apply`/`--sync`/
`--vendor`/`--prune` and no `--yes`) is report-only there. It prints what it found and the
"To apply a single patch, run: …" hint, writes nothing, and exits 0; add `--yes` or a mode flag
to mutate. Progress indicators and ANSI colors are automatically suppressed when output
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
  and [hosted mode for Go](docs/design/golang-hosted.md) (free tier; the
  [paid-tier no-go analysis](docs/design/golang-hosted-no-go.md) it supersedes).
- **[Changelog](CHANGELOG.md)**
