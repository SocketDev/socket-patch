# Socket Patch CLI

Apply security patches to npm and Python dependencies without waiting for upstream fixes.

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

By default this builds with npm and PyPI support. For additional ecosystems:

```bash
cargo install socket-patch-cli --features cargo,golang,maven,composer,nuget
```

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

Scan installed packages for available security patches. Since v3.0 `scan --sync` is the single command bots need for full auto-update: it discovers patches, applies them, and garbage-collects orphan blob files plus manifest entries for uninstalled packages — all in one invocation.

**Usage:**
```bash
socket-patch scan [options]
```

**Command-specific options** (plus all [Global Options](#global-options)):
| Flag | Description |
|------|-------------|
| `--apply` | Download and apply selected patches in JSON mode (non-interactive). Without it, `scan --json` is read-only. |
| `--prune` | Garbage-collect after the scan: remove manifest entries for uninstalled packages and orphan blob/diff/package-archive files. Off by default. |
| `--sync` | Sugar for `--apply --prune`. The canonical bot-mode flag. |
| `--batch-size <n>` | Packages per API request (default: `100`) |
| `--all-releases` | Store patches for every release/distribution variant, not just the installed one — makes the manifest portable across environments (e.g. cross-platform CI caches) |
| `--vex <path>` | On a successful scan, also write an OpenVEX 0.2.0 document to this path. See [Inline VEX generation](#inline-vex-on-apply--scan). (env: `SOCKET_VEX`) |
| `--vex-product`, `--vex-no-verify`, `--vex-doc-id`, `--vex-compact` | Passthrough to the embedded VEX builder; mirror the standalone [`vex`](#vex) knobs. Inert unless `--vex` is set. |

> Use `--dry-run` to preview what `--apply`/`--prune`/`--sync` would do without mutating disk.

**Examples:**
```bash
# Scan local project (interactive prompt to apply)
socket-patch scan

# Scan with JSON output (discover + updates, no mutation)
socket-patch scan --json

# Bot mode: discover, apply, prune, sweep — all in one
socket-patch scan --json --sync --yes

# Apply without pruning manifest entries (default)
socket-patch scan --apply --yes

# Apply + prune explicitly (equivalent to --sync)
socket-patch scan --json --apply --prune --yes

# Preview a full sync without mutating disk
socket-patch scan --json --sync --yes --dry-run

# Scan only npm packages
socket-patch scan --ecosystems npm

# Scan global packages
socket-patch scan -g

# Scan + apply + emit an OpenVEX attestation in one pass
socket-patch scan --json --sync --yes --vex socket.vex.json
```

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
| `--vex <path>` | On a successful apply, also write an OpenVEX 0.2.0 document to this path. See [Inline VEX generation](#inline-vex-on-apply--scan). (env: `SOCKET_VEX`) |
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

### `rollback`

Rollback patches to restore original files. If no identifier is given, all patches are rolled back.

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

Remove a patch from the manifest (rolls back files first by default).

**Usage:**
```bash
socket-patch remove <identifier> [options]
```

**Arguments:**
- `identifier` - Package PURL (e.g., `pkg:npm/package@version`) or patch UUID

**Command-specific options** (plus all [Global Options](#global-options)):
| Flag | Description |
|------|-------------|
| `--skip-rollback` | Only update manifest, do not restore original files |

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

`repair` cleans up the `.socket/` directory without running a scan — useful when you've manually adjusted the manifest, recovered from a partial-failure state, or just want to free space. For the combined workflow (discover + apply + GC in one pass), use `scan --sync --json --yes` instead.

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

### `setup`

Configure `package.json` postinstall scripts to automatically apply patches after `npm install`.

**Usage:**
```bash
socket-patch setup [options]
```

No command-specific options — see [Global Options](#global-options) (`--dry-run`, `--yes`, `--json`, `--cwd` are the relevant ones).

**Examples:**
```bash
# Interactive setup
socket-patch setup

# Non-interactive
socket-patch setup -y

# Preview changes
socket-patch setup --dry-run

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

## OpenVEX attestations

`socket-patch vex` turns your local manifest into a signed-off statement of *which known vulnerabilities no longer affect your build* because a Socket patch has been applied. This lets vulnerability scanners stop flagging CVEs that you've already remediated in place — without bumping the package version.

**How it works**

1. Reads `.socket/manifest.json` and, unless `--no-verify` is passed, re-checks each patched file's hash on disk so the attestation only covers patches that are actually applied.
2. Auto-detects the top-level **product** identifier (override with `--product`), probing in order:
   - `.git/config` `[remote "origin"]` → `pkg:github/<owner>/<repo>` (similar for GitLab/Bitbucket; raw URL otherwise)
   - `package.json` → `pkg:npm/<name>@<version>`
   - `pyproject.toml` → `pkg:pypi/<name>@<version>`
   - `Cargo.toml` → `pkg:cargo/<name>@<version>`
3. Emits an OpenVEX 0.2.0 document whose statements mark each mitigated vulnerability as `not_affected` (justification: the patch is present), suitable for piping into `vexctl`, Grype, Trivy, and similar tools.

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

Run `socket-patch get` or `socket-patch scan --sync` first — `vex` errors with `no_patches` against an empty manifest.

### Inline VEX on `apply` / `scan`

You don't need a separate `vex` invocation: pass `--vex <path>` to `apply` or `scan` and the same OpenVEX document is generated as a side-effect of a successful run.

```bash
# Patch and attest in one step
socket-patch apply --vex socket.vex.json

# Discover, apply, prune, and attest — the full bot-mode pass
socket-patch scan --json --sync --yes --vex socket.vex.json
```

The `--vex-product`, `--vex-no-verify`, `--vex-doc-id`, and `--vex-compact` flags mirror the standalone command's `--product` / `--no-verify` / `--doc-id` / `--compact` knobs.

Contract:

- The document is **always written to the file** (never stdout), so it never collides with the command's own `--json` output. JSON mode adds a top-level `vex` summary — `{ path, statements, format }` — to the envelope (`apply`) / result (`scan`).
- It's built from the manifest **as it stands after the run** (including any `--apply`/`--sync` writes) and verified against on-disk state unless `--vex-no-verify` is set. Generated for real applies, `--dry-run`, and read-only scans alike.
- **Fail-the-command:** if `--vex` was requested but generation fails (no detectable product, empty/missing manifest, nothing verified, unwritable path), the command exits non-zero **even when the apply/scan itself succeeded**, with a stable error code in the JSON output.

## Scripting & CI/CD

All commands support `--json` for machine-readable output. JSON responses always include a `"status"` field for easy error detection:

```bash
# Check for available patches in CI (read-only)
result=$(socket-patch scan --json --ecosystems npm)
patches=$(echo "$result" | jq '.totalPatches')

# Auto-update bot mode: discover, apply, prune, sweep in one pass
socket-patch scan --json --sync --yes | jq '{
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
