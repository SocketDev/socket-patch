# Socket Patch CLI

CLI tool for applying security patches to dependencies.

## Setup

```bash
# Install dependencies
npm install

# Build the project
npm run build
```

## Usage

```bash
# Apply patches from manifest (default: .socket/manifest.json)
socket-patch apply

# Apply patches with custom manifest path
socket-patch apply --manifest-path /path/to/manifest.json

# Dry run (verify patches can be applied without modifying files)
socket-patch apply --dry-run

# Silent mode (only output errors)
socket-patch apply --silent

# Custom working directory
socket-patch apply --cwd /path/to/project
```

## Development

```bash
# Watch mode for development
npm run dev
```

## Project Structure

```
src/
├── cli.ts              # Main CLI entry point
├── commands/
│   └── apply.ts        # Apply patch command
├── schema/
│   └── manifest-schema.ts  # Patch manifest schema (Zod)
├── hash/
│   └── git-sha256.ts   # Git-compatible SHA256 hashing
├── patch/
│   ├── file-hash.ts    # File hashing utilities
│   └── apply.ts        # Core patch application logic
├── types.ts            # TypeScript type definitions
├── utils.ts            # Utility functions
└── index.ts            # Library exports
```

## Commands

### apply

Apply security patches to dependencies from a manifest file.

**Options:**
- `--cwd` - Working directory (default: current directory)
- `-d, --dry-run` - Verify patches can be applied without modifying files
- `-s, --silent` - Only output errors
- `-m, --manifest-path` - Path to patch manifest file (default: `.socket/manifest.json`)
- `-h, --help` - Show help
- `-v, --version` - Show version

**Exit Codes:**
- `0` - Success (patches applied or already applied)
- `1` - Error (manifest not found, verification failed, or patch application failed)

## Manifest Format

The manifest file (`.socket/manifest.json`) contains patch definitions:

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

Patched file contents are stored in `.socket/blobs/` directory, named by their Git-compatible SHA256 hash.

## Library Usage

The socket-patch CLI can also be used as a library:

```typescript
import {
  PatchManifest,
  PatchManifestSchema,
  computeGitSHA256FromBuffer,
  computeGitSHA256FromChunks,
  applyPackagePatch,
  findNodeModules,
} from '@socketsecurity/socket-patch-cli'

// Validate manifest
const manifest = PatchManifestSchema.parse(manifestData)

// Compute file hashes
const hash = computeGitSHA256FromBuffer(fileBuffer)

// Apply patches programmatically
const result = await applyPackagePatch(
  packageKey,
  packagePath,
  files,
  blobsPath,
  dryRun,
)
```
