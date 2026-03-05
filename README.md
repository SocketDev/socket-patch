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
cargo install socket-patch-cli --features cargo,golang,maven,gem,composer,nuget
```

## Quick Start

You can pass a patch UUID directly to `socket-patch` as a shortcut:

```bash
socket-patch 550e8400-e29b-41d4-a716-446655440000
# equivalent to: socket-patch get 550e8400-e29b-41d4-a716-446655440000
```

## Commands

All commands support `--json` for structured JSON output and `--cwd <dir>` to set the working directory (default: `.`). Every JSON response includes a `"status"` field (`"success"`, `"error"`, `"no_manifest"`, etc.) for reliable programmatic consumption.

### `get`

Get security patches from Socket API and apply them. Accepts a UUID, CVE ID, GHSA ID, PURL, or package name. The identifier type is auto-detected but can be forced with a flag.

Alias: `download`

**Usage:**
```bash
socket-patch get <identifier> [options]
```

**Options:**
| Flag | Description |
|------|-------------|
| `--org <slug>` | Organization slug (required when using `SOCKET_API_TOKEN`) |
| `--id` | Force identifier to be treated as a UUID |
| `--cve` | Force identifier to be treated as a CVE ID |
| `--ghsa` | Force identifier to be treated as a GHSA ID |
| `-p, --package` | Force identifier to be treated as a package name |
| `-y, --yes` | Skip confirmation prompt for multiple patches |
| `--save-only` | Download patch without applying it (alias: `--no-apply`) |
| `--one-off` | Apply patch immediately without saving to `.socket` folder |
| `-g, --global` | Apply to globally installed packages |
| `--global-prefix <path>` | Custom path to global `node_modules` |
| `--json` | Output results as JSON |
| `--api-token <token>` | Socket API token (overrides `SOCKET_API_TOKEN`) |
| `--api-url <url>` | Socket API URL (overrides `SOCKET_API_URL`) |
| `--cwd <dir>` | Working directory (default: `.`) |

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

Scan installed packages for available security patches.

**Usage:**
```bash
socket-patch scan [options]
```

**Options:**
| Flag | Description |
|------|-------------|
| `--org <slug>` | Organization slug |
| `--json` | Output results as JSON |
| `--ecosystems <list>` | Restrict to specific ecosystems (comma-separated, e.g. `npm,pypi`) |
| `-g, --global` | Scan globally installed packages |
| `--global-prefix <path>` | Custom path to global `node_modules` |
| `--batch-size <n>` | Packages per API request (default: `100`) |
| `--api-token <token>` | Socket API token (overrides `SOCKET_API_TOKEN`) |
| `--api-url <url>` | Socket API URL (overrides `SOCKET_API_URL`) |
| `--cwd <dir>` | Working directory (default: `.`) |

**Examples:**
```bash
# Scan local project
socket-patch scan

# Scan with JSON output
socket-patch scan --json

# Scan only npm packages
socket-patch scan --ecosystems npm

# Scan global packages
socket-patch scan -g
```

### `apply`

Apply security patches from the local manifest.

**Usage:**
```bash
socket-patch apply [options]
```

**Options:**
| Flag | Description |
|------|-------------|
| `-d, --dry-run` | Verify patches without modifying files |
| `-s, --silent` | Only output errors |
| `-f, --force` | Skip pre-application hash verification (apply even if package version differs) |
| `-m, --manifest-path <path>` | Path to manifest (default: `.socket/manifest.json`) |
| `--offline` | Do not download missing blobs; fail if any are missing |
| `-g, --global` | Apply to globally installed packages |
| `--global-prefix <path>` | Custom path to global `node_modules` |
| `--ecosystems <list>` | Restrict to specific ecosystems (comma-separated, e.g. `npm,pypi`) |
| `--json` | Output results as JSON |
| `-v, --verbose` | Show detailed per-file verification information |
| `--cwd <dir>` | Working directory (default: `.`) |

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
```

### `rollback`

Rollback patches to restore original files. If no identifier is given, all patches are rolled back.

**Usage:**
```bash
socket-patch rollback [identifier] [options]
```

**Options:**
| Flag | Description |
|------|-------------|
| `-d, --dry-run` | Verify rollback without modifying files |
| `-s, --silent` | Only output errors |
| `-m, --manifest-path <path>` | Path to manifest (default: `.socket/manifest.json`) |
| `--offline` | Do not download missing blobs; fail if any are missing |
| `-g, --global` | Rollback globally installed packages |
| `--global-prefix <path>` | Custom path to global `node_modules` |
| `--one-off` | Rollback by fetching original files from API (no manifest required) |
| `--ecosystems <list>` | Restrict to specific ecosystems (comma-separated) |
| `--json` | Output results as JSON |
| `-v, --verbose` | Show detailed per-file verification information |
| `--org <slug>` | Organization slug |
| `--api-token <token>` | Socket API token (overrides `SOCKET_API_TOKEN`) |
| `--api-url <url>` | Socket API URL (overrides `SOCKET_API_URL`) |
| `--cwd <dir>` | Working directory (default: `.`) |

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

**Options:**
| Flag | Description |
|------|-------------|
| `--json` | Output as JSON |
| `-m, --manifest-path <path>` | Path to manifest (default: `.socket/manifest.json`) |
| `--cwd <dir>` | Working directory (default: `.`) |

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

**Options:**
| Flag | Description |
|------|-------------|
| `--skip-rollback` | Only update manifest, do not restore original files |
| `-g, --global` | Remove from globally installed packages |
| `--global-prefix <path>` | Custom path to global `node_modules` |
| `--json` | Output results as JSON |
| `-m, --manifest-path <path>` | Path to manifest (default: `.socket/manifest.json`) |
| `--cwd <dir>` | Working directory (default: `.`) |

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

### `setup`

Configure `package.json` postinstall scripts to automatically apply patches after `npm install`.

**Usage:**
```bash
socket-patch setup [options]
```

**Options:**
| Flag | Description |
|------|-------------|
| `-d, --dry-run` | Preview changes without modifying files |
| `-y, --yes` | Skip confirmation prompt |
| `--json` | Output results as JSON |
| `--cwd <dir>` | Working directory (default: `.`) |

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

### `repair`

Download missing blobs and clean up unused blobs.

Alias: `gc`

**Usage:**
```bash
socket-patch repair [options]
```

**Options:**
| Flag | Description |
|------|-------------|
| `-d, --dry-run` | Show what would be done without doing it |
| `--offline` | Skip network operations (cleanup only) |
| `--download-only` | Only download missing blobs, do not clean up |
| `--json` | Output results as JSON |
| `-m, --manifest-path <path>` | Path to manifest (default: `.socket/manifest.json`) |
| `--cwd <dir>` | Working directory (default: `.`) |

**Examples:**
```bash
# Repair (download missing + clean up unused)
socket-patch repair

# Cleanup only, no downloads
socket-patch repair --offline

# Download missing blobs only
socket-patch repair --download-only

# JSON output
socket-patch repair --json
```

## Scripting & CI/CD

All commands support `--json` for machine-readable output. JSON responses always include a `"status"` field for easy error detection:

```bash
# Check for available patches in CI
result=$(socket-patch scan --json --ecosystems npm)
patches=$(echo "$result" | jq '.totalPatches')

# Apply patches and check result
socket-patch apply --json | jq '.status'
# "success", "partial_failure", "no_manifest", or "error"
```

When stdin is not a TTY (e.g., in CI pipelines), interactive prompts auto-proceed instead of blocking. Progress indicators and ANSI colors are automatically suppressed when output is piped.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SOCKET_API_TOKEN` | API authentication token |
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
