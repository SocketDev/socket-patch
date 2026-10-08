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

## Vendored Maven

v5 vendors every Maven project through the suffixed backend that reactors
already used. A single-module `pom.xml` is now handled as a reactor of one.
Vendoring it changes these files:

- `pom.xml`: the dependency's `<version>` becomes `<version>-socket.<hex8>`. A
  `<dependencyManagement>` pin is added, and a `socket-patch-vendor` fallback
  `<repository>` inside `<!-- socket-patch:begin -->` / `<!-- socket-patch:end -->`
  markers.
- `.mvn/maven.config`: two lines that let Maven 3.9.2+ read the committed tree.
- `.socket/vendor/maven2/<group-path>/<artifact>/<version>-socket.<hex8>/`: the
  patched jar, its pom and checksums. This replaces `.socket/vendor/maven/<uuid>/`.

A project vendored before v5 still has the old wiring: a
`socket-patch-vendor-<uuid>` `<repository>` in `pom.xml` and a
`maven_pom_repository` entry in `.socket/vendor/state.json`. v5 does not
migrate it. `vendor`, `scan --mode vendored` and `get --mode vendored` refuse
that project with `vendor_jvm_shape_unsupported` (reason `legacy_maven_root`)
and change nothing. Migrate it once:

```sh
socket-patch vendor --revert   # restores pom.xml byte for byte
socket-patch vendor            # or: socket-patch scan --mode vendored
```

`remove`, `rollback` and switching to hosted mode still unwind the old wiring.

`socket-patch vex` attests a single-module project vendored by v5 from
`.socket/vendor/state.json`, as it already did for reactors. Commit that file:
without it the suffixed pin is not attested. The pre-v5 `<repository>` wiring
was also attested from `pom.xml` alone.

Without a Maven Wrapper (`.mvn/wrapper/maven-wrapper.properties`) the CLI can't
tell which Maven builds the project, so `vendor` reports two
`vendor_jvm_degraded` warnings, `maven_f_outside_root` and
`maven_mirror_of_all`. The patch is still applied. To clear them, add a Maven
Wrapper pinned to Maven 3.9.9 or later. On older Maven, make sure no
`mirrorOf *` mirror captures the `socket-patch-vendor` repository.

These codes are no longer emitted: `vendor_maven_local_cache_shadow` (a cached
original version can't shadow the suffixed pin),
`vendor_maven_multimodule_unsupported`, `vendor_maven_pom_project_missing` and
`vendor_gradle_unsupported` (a root with no JVM build is now
`vendor_jvm_shape_unsupported` with reason `no_build_file`),
`vendor_maven_pom_unreadable`, `vendor_maven_pom_unavailable` and
`vendor_maven_pom_downloaded`. `legacy_maven_root` is now a refusal for the
whole root, not a `vendor_jvm_degraded` warning on mixed Maven + Gradle roots.

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
| `SOCKET_FORCE` | Pass `--force` to the one command that needs it (`apply`, `vendor`, `--update`); the variable is now ignored |

Legacy `.socket/packages/` archives are no longer read. Patch data uses diff
archives or blobs; cleanup commands remove obsolete package archives.
