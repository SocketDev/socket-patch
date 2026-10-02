# Development

Socket Patch discovers dependency versions, selects available Socket patches, and
makes those patches consumable through hosted references, committed artifacts, or
in-place application. The [README](../README.md) describes the user workflow; the
[CLI contract](../crates/socket-patch-cli/CLI_CONTRACT.md) specifies public behavior.

## Build

Use Rust's stable toolchain and Cargo from the repository root:

```sh
cargo build --locked -p socket-patch-cli
./target/debug/socket-patch --help
```

`Cargo.toml` is the source of the binary's version. The v5 prerelease branch can
still carry the previous version until the release bump; use a binary built from
this checkout when verifying branch behavior.

The workspace's `.cargo/config.toml` disables persisted Socket login and passive
update checks for Cargo runs. This keeps tests independent of a developer's account.
Override `SOCKET_NO_CONFIG=0` explicitly when a manual `cargo run` should use the
persisted login.

## Code map

| Component | Responsibility |
| --- | --- |
| [`socket-patch-cli`](../crates/socket-patch-cli/src/) | Arguments, command orchestration, terminal output, and JSON responses |
| [`socket-patch-core`](../crates/socket-patch-core/src/) | API access, discovery, selection policy, patching, format handling, vendoring, and VEX |
| [`socket-patch-node`](../crates/socket-patch-node/) | Node bindings for the in-memory hosted engine |
| [`socket-patch-bench`](../crates/socket-patch-bench/) | `scan` benchmarks and the CI performance gate (not published) |
| [`scripts/`](../scripts/) | Installers, release tooling, compatibility runners, and performance tools |
| [`tests/docker/`](../tests/docker/README.md) | Container fixtures for native package-manager integration tests |

Within core, start with `crawlers/` and `vendor/lock_inventory/` for package
inventory, `formats/` for shared format models, `api/ranking.rs` for patch ranking,
`policy/` and `rollout/` for selection, `hosted/` for the hosted engine,
`patch/redirect/` for dependency rewrites and upstream restoration, `vendor/` for
artifact backends, and `vex/` for attestation.

### State and command boundaries

- **Hosted state** is derived from dependency files. The lockfiles and related
  manifests/configs identify the patch and the source the package manager consumes.
  The CLI fetches patch metadata as needed; it writes no hosted ledger.
- **Vendored state** pairs `.socket/vendor/state.json` with its artifacts. Entries
  carry patch records, fingerprints, and reversible edits. A ledger is required for
  repair and managed reversal; discovering a reference is not enough to rebuild it.
- **Agent state** uses `.socket/manifest.json` and patch data. Agent commands apply
  and verify file-level changes against installed packages.
- **Legacy hosted records** can supplement metadata while migrating old projects.
  They do not prove a patch is still wired into the project.

CLI commands share [`ProjectContext`](../crates/socket-patch-cli/src/commands/context.rs)
for lazy ledger, inventory, and reference discovery. Its disk snapshot gives readers
the same file contents. Writers reload mutable state under the apply lock; embedded
VEX reloads the result after writes. Vendored commands share
[`VendoredBackend`](../crates/socket-patch-cli/src/commands/vendored_backend/).
The in-memory hosted engine operates on supplied files, and parity tests compare
its results with the disk path.

Keep these boundaries when extending the project:

- A repository policy can narrow or pace selection, but cannot set credentials,
  endpoints, or bypass safety checks. See [configuration](configuration.md).
- Presence in a manifest or ledger is separate from whether the package manager
  consumes a patch. VEX checks live references and available evidence.
- Preserve unrelated dependency-file edits. Refuse unsupported formats or unsafe
  drift instead of claiming a patch is applied.
- Test the files and bytes the native installer consumes, including fresh checkouts
  and relevant warm caches. A successful rewrite alone does not prove delivery.

## Validation

Choose checks for the affected behavior:

```sh
cargo test --locked -p socket-patch-core --lib
cargo test --locked -p socket-patch-cli --test cli_parse_scan --test cli_parse_get
python3 -B -m unittest discover -s scripts/tests -v
cargo clippy --workspace --all-features -- -D warnings
```

The parser suites cover the public CLI. Core unit tests and committed fixtures cover
format handling. Integration suites cover lifecycle, failures, and native installers;
see the [testing guide](testing/README.md) for toolchains and opt-in network tests.
Update relevant contract entries and tests when changing flags, defaults, output,
exit codes, or supported formats.

Compatibility tables describe support boundaries and reproducible checks. In
particular, the vlt tables and `vlt-coverage.json` are inputs to validation scripts:
keep them in sync with tests and workflows. Store individual experiment logs and
full backtest results as run artifacts, not as new product documentation.

For performance work, use the [`scan` benchmarks](../crates/socket-patch-bench/README.md):
synthetic projects for every package manager against a local patch API, with each
run validated. CI compares every pull request against its base with them and fails
on a significant slowdown, more API requests, or a scan that stops doing its work.
To measure against real API traffic, use the [record/replay harness](../scripts/perf/README.md).
For publishing, follow the [release runbook](releasing.md) and
[installer hosting guide](installer-hosting.md).
