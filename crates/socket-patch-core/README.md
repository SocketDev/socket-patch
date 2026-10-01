# socket-patch-core

Core library for [socket-patch](https://github.com/SocketDev/socket-patch) — a CLI tool that applies security patches to npm, Python, Ruby, Cargo, Go, Maven, Composer, NuGet, and Deno dependencies without waiting for upstream fixes.

## What this crate provides

- Dependency discovery from installed packages and lockfiles.
- Hosted dependency rewriting, including the in-memory engine used by the Node bindings.
- Selection policy and gradual rollout shared across disk and in-memory scans.
- Vendored artifact acquisition, verification, wiring, and reversal.
- Agent patch manifests and file-level apply/rollback with content-hash checks.
- Socket API access and OpenVEX generation from patch records and live references.

See the repository's [development guide](../../docs/development.md) for the code map
and [ecosystem matrix](../../docs/ecosystems.md) for supported formats and limits.

## Usage

This crate is used internally by the [`socket-patch-cli`](https://crates.io/crates/socket-patch-cli) binary. If you need the CLI, install that instead:

```bash
cargo install socket-patch-cli
```

## License

MIT
