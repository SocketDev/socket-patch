# Socket Patch CLI

Apply security patches to npm dependencies without waiting for upstream fixes.

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

### Cargo

```bash
cargo install socket-patch-cli
```

## Commands

### `apply`

Apply security patches from manifest.

**Usage:**
```bash
npx @socketsecurity/socket-patch apply [options]
```

**Options:**
- `--cwd` - Working directory (default: current directory)
- `-d, --dry-run` - Verify patches without modifying files
- `-s, --silent` - Only output errors
- `-m, --manifest-path` - Path to manifest (default: `.socket/manifest.json`)

**Examples:**
```bash
# Apply patches
npx @socketsecurity/socket-patch apply

# Dry run
npx @socketsecurity/socket-patch apply --dry-run

# Custom manifest
npx @socketsecurity/socket-patch apply -m /path/to/manifest.json
```

### `download`

Download patch from Socket API.

**Usage:**
```bash
npx @socketsecurity/socket-patch download --uuid <uuid> --org <org> [options]
```

**Options:**
- `--uuid` - Patch UUID (required)
- `--org` - Organization slug (required)
- `--api-token` - API token (or use `SOCKET_API_TOKEN` env var)
- `--api-url` - API URL (default: `https://api.socket.dev`)
- `--cwd` - Working directory
- `-m, --manifest-path` - Path to manifest

**Examples:**
```bash
# Download patch
export SOCKET_API_TOKEN="your-token"
npx @socketsecurity/socket-patch download --uuid "550e8400-e29b-41d4-a716-446655440000" --org "my-org"

# With explicit token
npx @socketsecurity/socket-patch download --uuid "..." --org "my-org" --api-token "token"
```

### `list`

List patches in manifest.

**Usage:**
```bash
npx @socketsecurity/socket-patch list [options]
```

**Options:**
- `--cwd` - Working directory
- `-m, --manifest-path` - Path to manifest
- `--json` - Output as JSON

**Examples:**
```bash
# List patches
npx @socketsecurity/socket-patch list

# JSON output
npx @socketsecurity/socket-patch list --json
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

Remove patch from manifest.

**Usage:**
```bash
npx @socketsecurity/socket-patch remove <identifier> [options]
```

**Arguments:**
- `identifier` - Package PURL (e.g., `pkg:npm/package@version`) or patch UUID

**Options:**
- `--cwd` - Working directory
- `-m, --manifest-path` - Path to manifest

**Examples:**
```bash
# Remove by PURL
npx @socketsecurity/socket-patch remove "pkg:npm/lodash@4.17.20"

# Remove by UUID
npx @socketsecurity/socket-patch remove "550e8400-e29b-41d4-a716-446655440000"
```

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
      }
    }
  }
}
```

Patched file contents are in `.socket/blobs/` (named by git SHA256 hash).
