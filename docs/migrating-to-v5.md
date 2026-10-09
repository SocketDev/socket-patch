# Migrating to v5

v5 makes hosted patching the default workflow. Review these changes before running
existing scripts against the new CLI; the [changelog](../CHANGELOG.md) and
[CLI contract](../crates/socket-patch-cli/CLI_CONTRACT.md) cover the full release.

## Defaults and stored state

- Bare `scan` and `get` now patch in hosted mode when the project has no patch
  state yet. `scan` never prompts; hosted and vendored `get` do not prompt either.
  `scan` discovers patches from project dependency files and writes hosted
  references. Supported lockfiles work from a fresh checkout before installing
  dependencies; install or resolve first where the selected
  [mode or ecosystem](ecosystems.md) requires it, such as agent mode or
  sbt / scala-cli. Use `scan --dry-run` for a preview or `--mode agent` to retain
  in-place patching.
- A bare `scan` or `get` keeps the mode a project already uses: a project with a
  vendor ledger (`.socket/vendor/state.json`) stays vendored, and one whose
  `.socket/manifest.json` holds patches stays in agent mode. Switching modes needs an
  explicit `--mode` (for example `scan --mode hosted` converts a vendored project in
  place). A project holding both agent and vendored patches must pass `--mode`
  (`mode_ambiguous`, exit 2). Global scans and a mode-less
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
  `.socket/vendor/state.json` with the artifacts. `repair` restores missing agent
  patch data or missing/corrupt vendored artifacts using existing records. It no
  longer reconstructs a missing vendor ledger from lockfiles; restore the ledger
  from version control.
- Vendored Cargo patches move into workspace-root `Cargo.toml` and use
  `<version>+socket.<uuid>` versions. Re-running vendoring or repair migrates
  older wiring. The tag is visible in `CARGO_PKG_VERSION`; see
  [Cargo details](ecosystems.md#cargo-vendored-wiring-in-cargotoml).
- `list` succeeds on an empty project. Hosted results identify lockfiles instead
  of a hosted ledger. Scripts must use the updated
  [JSON shapes and exit codes](../crates/socket-patch-cli/CLI_CONTRACT.md#json-output-shapes).
- A token whose organization cannot be resolved no longer queries
  `/v0/orgs/default/…`. When no `--org`, `SOCKET_ORG_SLUG` or socket-cli
  `defaultOrg` is set and `GET /v0/organizations` fails, the whole run uses the
  public proxy anonymously (free patches only) and warns once; `scan --json`,
  `get --json` and `vex --json` report it as `api_auth_fallback` in `warnings[]`. Set `--org` or
  `SOCKET_ORG_SLUG` to get org patches. The org is resolved once per run, so an
  embedded `--vex` no longer resolves it again.

## Service-only vendoring

v4 could build patched artifacts locally, with `auto` as the default acquisition
policy. v5 downloads new artifacts only from the patch service:

- `--vendor-source build` and `SOCKET_VENDOR_SOURCE=build` are rejected as usage
  errors (exit 2). Remove that configuration or change it to `service`.
- `service` is the new default. `--vendor-source auto` and
  `SOCKET_VENDOR_SOURCE=auto` remain compatibility aliases for `service`; they no
  longer select a local build fallback.
- Missing or pending service artifacts, network errors, and integrity mismatches
  do not trigger a local build fallback, even when the original package is installed.

Healthy committed artifacts can still be reused offline. Commit `.socket/vendor/`,
including `state.json`, and the dependency-file changes the CLI reports. Installing
those patched packages needs neither Socket API access nor the Socket Patch CLI;
unpatched dependencies still need their normal registry, mirror, or cache.
Fetching a new artifact or redownloading a missing or corrupt one requires service
access. See [vendoring and offline installs](usage.md#vendoring-and-offline-installs).

## JSON output

Every `--json` failure now reports its top-level `error` as an object,
`{"code": "...", "message": "..."}`, on every command. `apply`, `list`, `remove`,
`repair`, `vendor` and `vex` already did; `scan`, `get` and `rollback` change:

- Read `.error.message` where you read `.error`, and route on `.error.code`.
- The top-level `errorCode` key is gone. Read `.error.code` instead. This affects
  `get`'s and hosted `scan`'s `lock_held` / `lock_io`, hosted `scan` refusals,
  `scan`'s socket.yml refusals (`socket_yml_invalid`, `socket_yml_ambiguous`) and
  the nested-apply error `get` and `scan --mode agent` report.
- Per-record keys do not change: `patches[*].error`, `patches[*].errorCode` and
  rollback's `results[*].error` stay strings.
- Usage errors (exit 2) that `scan`, `remove` and `rollback` enforce themselves
  now print the coded error on stdout under `--json`, as `get`, `repair`,
  `vendor` and `vex` do. Clap's own parse errors, and the check that a
  `--cwd`, `--global-prefix` or `--manifest-path` names something, still print
  nothing on stdout.

```bash
socket-patch scan --json | jq -r 'select(.status == "error") | .error.code'
```

The codes are listed in the
[CLI contract](../crates/socket-patch-cli/CLI_CONTRACT.md#top-level-envelopeerror-codes).

## Installation channels

v5 distributes standalone binaries, Cargo crates, and npm packages. The PyPI and
RubyGems CLI distributions and the `socket-patch-hook` / `socket-patch-bundler`
helpers are no longer published. Python and Ruby projects remain supported.

Remove the old CLI with the manager that installed it (`pip uninstall socket-patch`,
`pipx uninstall socket-patch`, or `gem uninstall socket-patch`). Install through a
[supported channel](../README.md#installation), update CI bootstrap commands, and
run `socket-patch --version` to check which binary your shell finds.

## Support tiers

v5 keeps every lockfile format in the support matrix, including the ones the package
managers have retired. The [v5 support tiers](ecosystems.md#v5-support-tiers) say how
mature each one is.

- **Beta:** Maven and Gradle in hosted and vendored mode, and sbt / Mill / scala-cli.
  They work for the documented build shapes. Run the build before you rely on the
  result or on a `--vex` document.
- **Legacy:** binary `bun.lockb` (hosted and vendored), vendored pnpm 7/8 locks
  (lockfileVersion 5.4 / 6.0) and vlt locks from before 1.0.0-rc.15. They keep
  working in v5, with an upgrade path and an undo path for each. Plan to move to text
  `bun.lock`, pnpm 9+ or vlt 1.0+; a future major release may stop writing these
  formats.
- No v5.x minor or patch release removes a format or makes one refuse that v5.0
  accepts. See the [support policy](ecosystems.md#support-policy).

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
| Bundler | Remove the managed `plugin "socket-patch", path: ...` Gemfile block; remove `.socket/bundler-plugin/`, `.socket/gem-plugin-stamp`, and its `.socket/.gitignore` entry. Then, in **every** checkout that ran `bundle install` under v4 (each developer machine and persistent CI runner, not only yours), run `bundle plugin uninstall socket-patch` or delete `.bundle/plugin/`: the registration lives in the uncommitted `.bundle/`, and once the plugin directory is gone Bundler 2.3–2.5 fail every `bundle install` with a `LoadError` (2.6+ warn on each run). `scan` and `apply` report a leftover registration as `gem_bundler_plugin_stale` |

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
| `scan --apply` | `scan --mode agent` |
| `scan --vendor` | `scan --mode vendored` |
| `get --no-apply` | `get --save-only` (`SOCKET_SAVE_ONLY` is unchanged) |
| `--vendor-source build`, `SOCKET_VENDOR_SOURCE=build` | Remove the setting or use `service`; `auto` is now a service-only alias |
| `socket-patch download` | `socket-patch get` |
| `socket-patch gc` | `socket-patch repair` |
| `--download-mode`, `SOCKET_DOWNLOAD_MODE` | No replacement; patch content is always fetched as per-file blobs |
| `SOCKET_FORCE` | Pass `--force` to the one command that needs it (`apply`, `vendor`, `--update`); the variable is now ignored |

A removed spelling is a usage error (exit 2). `scan --sync` stays as the
shorthand for `scan --mode agent --prune`.

Legacy `.socket/packages/` and `.socket/diffs/` archives are no longer read.
Patch data uses per-file blobs (`.socket/blobs/`); cleanup commands remove the
obsolete archives.
