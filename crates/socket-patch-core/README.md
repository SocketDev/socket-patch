# socket-patch-core

Core library for [socket-patch](https://github.com/SocketDev/socket-patch) — a CLI tool that applies security patches to npm, Python, and Cargo dependencies without waiting for upstream fixes.

## What this crate provides

- **Manifest management** — read, write, and validate `.socket/manifest.json` patch manifests
- **Patch engine** — apply and rollback file-level patches using git SHA-256 content hashes
- **Crawlers** — discover installed packages across npm, PyPI, and Cargo ecosystems
- **API client** — fetch patches from the Socket API
- **Utilities** — PURL parsing, blob storage, hash verification, fuzzy matching

## Usage

This crate is used internally by the [`socket-patch-cli`](https://crates.io/crates/socket-patch-cli) binary. If you need the CLI, install that instead:

```bash
cargo install socket-patch-cli
```

## License

MIT
