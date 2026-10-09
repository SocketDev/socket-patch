# Socket Patch

Apply security fixes to the dependency versions your project already uses.
Socket provides patches for specific package versions so you can address known
vulnerabilities without waiting for an upstream release or upgrading the dependency.

The default workflow is **scan → install → vex**:

- `socket-patch scan` finds available patches from project dependency files and
  updates them to use Socket-hosted patched packages.
- Your package manager installs those packages using the updated references and
  integrity pins. Commit the files that `scan` reports.
- `socket-patch vex` produces an OpenVEX document describing the vulnerabilities
  addressed by those patches.

Use `socket-patch vendor` to put the selected patched packages in your repository
when installs must work without Socket's patch server.

> This branch documents the v5 prerelease. Installation commands below select the
> latest published release, which may have different behavior. To try this branch,
> [build from source](docs/development.md#build). Existing users should read the
> [v5 migration guide](docs/migrating-to-v5.md).

## Installation

Install a standalone binary on macOS or Linux:

```sh
curl -fsSL https://install.socket.dev/patch | sh
```

The installer verifies the download against the release's `SHA256SUMS` and installs
in `/usr/local/bin` or `~/.local/bin`. To choose a directory or release, pass
`SOCKET_PATCH_INSTALL_DIR` or `SOCKET_PATCH_VERSION` to `sh` after the pipe.
See the [installer source](scripts/install.sh) and
[mirror configuration](docs/installer-hosting.md).

On Windows, extract a `socket-patch-*-pc-windows-msvc.zip` archive from
[GitHub Releases](https://github.com/SocketDev/socket-patch/releases) into a directory
on your `PATH`, or install through npm:

```sh
npm install -g @socketsecurity/socket-patch
```

Cargo users can build and install the published CLI with
`cargo install socket-patch-cli`. All distributions support the same ecosystems;
you do not need Node.js or Rust to use the standalone binary.

For standalone installs, run `socket-patch --update` to update. For npm or Cargo
installs, use that package manager's update command. The
[platform matrix](docs/ecosystems.md#supported-platforms) lists release targets.

## Quick start

From the root of a project with a supported lockfile, including a fresh checkout
before dependencies are installed:

```sh
socket-patch scan --dry-run       # preview available patches and edits
socket-patch scan                 # apply hosted references; never prompts
```

Agent mode needs installed packages. Some ecosystems need build-tool resolution
records first, such as sbt and scala-cli; see the
[ecosystem notes](docs/ecosystems.md).

Without an API token, the CLI uses Socket's public proxy for free patches.
To use your organization's patch tier, set `SOCKET_API_TOKEN`, or sign in with the
separate Socket CLI using `socket login`. See [configuration](docs/configuration.md).

A scan with no available patches means the catalog has no applicable patch for
this run. It is **not** a finding that the project has no vulnerabilities.

Review and commit the files the scan changed. Hosted mode keeps no patch ledger;
its state is in the project's lockfiles, manifests, and package-manager configuration.
For example, an npm project may change both `package-lock.json` and `.npmrc`:

```sh
git diff
git add package-lock.json .npmrc
git commit -m "Apply Socket security patches"
npm ci
socket-patch vex --output socket.vex.json
socket-patch list
```

Use your project's normal install command in place of `npm ci`. Some package
managers reuse installed or cached upstream packages; follow any reinstall warning
from the CLI and the [ecosystem notes](docs/ecosystems.md). Generate VEX after
installing to verify the copies your build consumes, then pass the document to your
VEX-aware vulnerability scanner.

## Patch modes

| Mode | Command | What to commit | What installs need |
| --- | --- | --- | --- |
| Hosted (default) | `socket-patch scan` | Changed lockfiles, manifests, and registry configuration | Access to Socket's patch server |
| Vendored | `socket-patch scan --mode vendored` | Changed dependency files and `.socket/vendor/` (artifacts and ledger) | The committed patched packages |
| Agent | `socket-patch scan --mode agent` | `.socket/manifest.json` and patch data; Go also uses a committed patched tree | `socket-patch apply` after dependency installs |

Vendored mode stores **patched dependencies**, not the entire dependency graph.
Other dependencies still need their normal registry, mirror, or offline cache.
Hosted and vendored installs do not need an install hook or the Socket Patch CLI.

The CLI supports npm, PyPI, Cargo, Go, RubyGems, Maven (including sbt, Mill and
scala-cli builds), Composer, NuGet, and Deno.
Mode and package-manager support vary: Deno uses agent mode, for example. Check the
[ecosystem support matrix](docs/ecosystems.md) before choosing a mode.

Vendored Maven reactors and Gradle 6.8+ builds are supported. See
[JVM vendoring](docs/design/maven-vendoring.md) for supported project shapes,
cache behavior, and offline checks. sbt 0.13.18+ builds are wired through one
generated `socket-patch.sbt` (hosted) or `socket-patch-vendor.sbt` (vendored);
see [Scala build tools](docs/ecosystems.md#scala-build-tools-sbt-mill-scala-cli).

## Common commands

```sh
socket-patch scan --package lodash          # limit selection to a package
socket-patch scan --max-new-patches 5        # introduce at most five new patches
socket-patch scan 'apps/*'                  # scan project directories in a monorepo
socket-patch get CVE-2024-12345              # target an advisory; hosted by default
socket-patch vendor                        # eject an existing hosted patch set
socket-patch repair                        # restore agent or vendored patch artifacts
socket-patch rollback                      # restore upstream dependencies
```

`get` also accepts a GHSA, patch UUID, PURL, or exact package name (every installed
version of that name is searched; near names are only suggested). `scan` selects from
patches your account can download, preferring the highest severity, then the most
advisories fixed, then the newest publication date. Existing patches are upgraded
only by a better-ranked patch.

Hosted rollback resolves upstream metadata and generally needs network access.
Where restoration is unsupported, including hosted binary `bun.lockb`, the CLI
refuses the change and gives a version-control recovery hint. See
[usage and recovery](docs/usage.md).

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
