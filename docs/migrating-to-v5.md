# Migrating to v5

v5 makes hosted patching the default workflow. Review these changes before running
existing scripts against the new CLI; the [changelog](../CHANGELOG.md) and
[CLI contract](../crates/socket-patch-cli/CLI_CONTRACT.md) cover the full release.

## Defaults and stored state

- Bare `scan` and `get` now patch in hosted mode. `scan` never prompts;
  hosted and vendored `get` do not prompt either. Use `scan --dry-run` for a preview
  or `--mode agent` to retain in-place patching. Global scans and a mode-less
  `scan --prune` do not acquire new patches; `--prune` still performs cleanup.
- Hosted state lives in dependency files. No command writes
  `.socket/vendor/redirect-state.json`. Legacy hosted records can still supply
  metadata, but do not replace live references.
- Hosted `rollback` and `remove` reconstruct upstream registry entries and
  generally need network access. They refuse unsupported restoration, including
  binary `bun.lockb`, with a version-control recovery hint.
- `rollback` now removes patch records and unused artifacts as well as restoring
  dependencies. Pass `--preserve-state` to retain local state for reuse.
- `scan` / `get --mode vendored` need no agent manifest. Commit
  `.socket/vendor/state.json` with the artifacts. `repair` no longer reconstructs
  a missing ledger from lockfiles.
- Vendored Cargo patches move into workspace-root `Cargo.toml` and use
  `<version>+socket.<uuid>` versions. Re-running vendoring or repair migrates
  older wiring. The tag is visible in `CARGO_PKG_VERSION`; see
  [Cargo details](ecosystems.md#cargo-vendored-wiring-in-cargotoml).
- `list` succeeds on an empty project. Hosted results identify lockfiles instead
  of a hosted ledger. Scripts must use the updated
  [JSON shapes and exit codes](../crates/socket-patch-cli/CLI_CONTRACT.md#json-output-shapes).

## Installation channels

v5 distributes standalone binaries, Cargo crates, and npm packages. The PyPI and
RubyGems CLI distributions and the `socket-patch-hook` / `socket-patch-bundler`
helpers are no longer published. Python and Ruby projects remain supported.

Remove the old CLI with the manager that installed it (`pip uninstall socket-patch`,
`pipx uninstall socket-patch`, or `gem uninstall socket-patch`). Install through a
[supported channel](../README.md#installation), update CI bootstrap commands, and
run `socket-patch --version` to check which binary your shell finds.

## Retire `setup` hooks

`socket-patch setup` is removed. Existing hooks may still call `apply`, but v5 no
longer creates or maintains them.

To move an agent project to hosted mode, run `socket-patch rollback`, then
`socket-patch scan`, review and commit the changes, and reinstall dependencies.
To stay in agent mode, retain `.socket/` and explicitly run `socket-patch apply`
after dependency installs in CI.

Remove only the Socket-managed portions of old hooks, preserving other commands:

| Ecosystem | Cleanup |
| --- | --- |
| npm / pnpm / yarn / bun | Remove the Socket Patch `apply --silent --ecosystems npm` command from `package.json`'s `postinstall` and `dependencies` scripts; remove empty script keys |
| Composer | Remove `socket-patch apply --offline --silent --ecosystems composer` from `post-install-cmd` and `post-update-cmd` |
| Python | Remove `socket-patch[hook]` from requirements or project dependencies, and uninstall `socket-patch-hook` in affected environments |
| Bundler | Remove the managed `plugin "socket-patch", path: ...` Gemfile block; run `bundle plugin uninstall socket-patch`; remove `.socket/bundler-plugin/`, `.socket/gem-plugin-stamp`, and its `.socket/.gitignore` entry |

Use `socket-patch list` to inspect the remaining patch set. For agent projects,
run `socket-patch apply` once after migration to confirm the manifest still applies.

## Retired spellings

| Removed | Replacement |
| --- | --- |
| `scan --redirect` | `scan --mode hosted` |
| `scan --detached` | `scan --mode vendored` is already manifest-free |
| `--mode host`, `--mode redirect`, `--mode vendor` | `hosted`, `hosted`, `vendored` respectively |
| `get --one-off`, `rollback --one-off`, `SOCKET_ONE_OFF` | No replacement; these had no implementation |
| `SOCKET_PATCH_PROXY_URL` | `SOCKET_PROXY_URL` |
| `SOCKET_PATCH_DEBUG` | `SOCKET_DEBUG` |
| `SOCKET_PATCH_TELEMETRY_DISABLED` | `SOCKET_TELEMETRY_DISABLED` |
| `scan --apply` | `scan --mode agent` |
| `scan --vendor` | `scan --mode vendored` |
| `get --no-apply` | `get --save-only` (`SOCKET_SAVE_ONLY` is unchanged) |
| `socket-patch download` | `socket-patch get` |
| `socket-patch gc` | `socket-patch repair` |
| `SOCKET_FORCE` | Pass `--force` to the one command that needs it (`apply`, `vendor`, `--update`); the variable is now ignored |

A removed spelling is a usage error (exit 2). `scan --sync` stays as the
shorthand for `scan --mode agent --prune`.

Legacy `.socket/packages/` archives are no longer read. Patch data uses diff
archives or blobs; cleanup commands remove obsolete package archives.
