# Socket Patch

Apply security fixes to the dependency versions your project already uses,
without waiting for an upstream release or upgrading the dependency.
Socket Patch updates dependency files to use patched packages, which you install
with your normal package manager.

> This branch documents the v5 prerelease. Installation commands below select the
> latest published release, which may have different behavior. To try this branch,
> [build from source](docs/development.md#build). Existing users should read the
> [v5 migration guide](docs/migrating-to-v5.md).

## Installation

Install a standalone binary on macOS or Linux:

```sh
curl -fsSL https://install.socket.dev/patch | sh
```

The installer verifies release checksums and installs in `/usr/local/bin` or
`~/.local/bin`. See the [installer options](scripts/install.sh) for a custom
directory or version, and [mirror setup](docs/installer-hosting.md).

On Windows, extract a `socket-patch-*-pc-windows-msvc.zip` archive from
[GitHub Releases](https://github.com/SocketDev/socket-patch/releases) into a directory
on your `PATH`, or install through npm:

```sh
npm install -g @socketsecurity/socket-patch
```

Cargo users can run `cargo install socket-patch-cli`. The standalone binary
requires neither Node.js nor Rust. All installation methods support the same
ecosystems; see the [support matrix](docs/ecosystems.md) for platform details.

For standalone installs, run `socket-patch --update` to update. For npm or Cargo
installs, use that package manager's update command.

## Quick start

From the root of a project with a supported lockfile, including a fresh checkout
before dependencies are installed:

```sh
socket-patch scan --dry-run       # preview available patches and edits
socket-patch scan                 # update dependency files; never prompts
```

Review and commit the dependency and configuration files the scan reports. Then
install the patched packages and generate OpenVEX for your vulnerability scanner:

```sh
npm ci                           # use your project's normal install command
socket-patch vex --output socket.vex.json
socket-patch list
```

Follow any reinstall warning from the CLI: some package managers reuse cached
upstream packages. Agent mode needs installed packages; sbt and scala-cli need
resolution records first. See the [ecosystem notes](docs/ecosystems.md).

Free patches need no token. For organization patches, set `SOCKET_API_TOKEN` or
use the separate Socket CLI's `socket login`. See [configuration](docs/configuration.md).
A scan with no available patches does **not** mean the project has no vulnerabilities.

## Patch modes

| Mode | Command | What to commit | What installs need |
| --- | --- | --- | --- |
| Hosted (default for a new project) | `socket-patch scan` | Changed lockfiles, manifests, and registry configuration | Access to Socket's patch server |
| Vendored | `socket-patch scan --mode vendored` | Changed dependency files and `.socket/vendor/` (artifacts and ledger) | The committed patched packages |
| Agent | `socket-patch scan --mode agent` | `.socket/manifest.json` and patch data; Go also uses a committed patched tree | `socket-patch apply` after dependency installs |

Vendored mode stores **patched dependencies**, not the entire dependency graph.
Other dependencies still need their normal registry, mirror, or offline cache.
Hosted and vendored installs do not need an install hook or the Socket Patch CLI.
Once a project holds vendored or agent-mode patches, a bare `scan` or `get` keeps
that mode; pass `--mode` to switch.

Supported ecosystems include npm, PyPI, Cargo, Go, RubyGems, Maven, Composer,
NuGet, and Deno. Check the [support matrix](docs/ecosystems.md) for available
modes and package-manager limitations.

## Common commands

```sh
socket-patch scan --package lodash         # limit selection to a package
socket-patch scan --max-new-patches 5       # introduce at most five new patches
socket-patch scan 'apps/*'                  # scan projects in a monorepo
socket-patch get pkg:npm/lodash@4.17.20      # target one package version
socket-patch vendor                        # eject an existing hosted patch set
socket-patch repair                        # restore agent or vendored patch artifacts
socket-patch rollback lodash               # restore one package to upstream
socket-patch rollback                      # restore upstream dependencies
```

`get` also accepts a CVE, GHSA, patch UUID, or exact package name. Hosted rollback
generally needs network access; some formats require restoring files from version
control. See [usage and recovery](docs/usage.md).

Use `socket-patch <command> --help` for options and
[`socket.yml`](docs/configuration.md#repository-patch-policy) for a shared rollout policy.

## Documentation

- [Usage](docs/usage.md): targeting, CI, vendoring, agent mode, VEX, and recovery.
- [Configuration](docs/configuration.md): authentication, environment, and rollout policy.
- [Ecosystem support](docs/ecosystems.md): package-manager formats and limitations.
- [Migrating to v5](docs/migrating-to-v5.md): changed defaults and retired install hooks.
- [CLI contract](crates/socket-patch-cli/CLI_CONTRACT.md): flags, JSON, diagnostics, and exit codes.
- [Development](docs/development.md): code map, builds, and test entry points.
- [Release runbook](docs/releasing.md) and [changelog](CHANGELOG.md).
