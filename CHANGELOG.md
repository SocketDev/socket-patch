# Changelog

All notable changes to socket-patch are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-v3.0 entries are concise summaries derived from each tag's commit
history. For full per-release detail, see the
[GitHub releases page](https://github.com/SocketDev/socket-patch/releases).

The `Release` workflow refuses to publish a version that does not appear
in this file — see `.github/workflows/release.yml` (`version` job).

## [Unreleased]

## [3.0.0] — 2026-05-22

### Breaking

- **`--offline` semantics unified** to strict airgap on every subcommand.
  Previously meant three different things across `apply` (strict airgap),
  `repair` (skip downloads / cleanup-only), and `rollback` (fail when blobs
  missing). All three now mean the same thing: never contact the network,
  fail loudly when a required local source is missing.
- **`repair --download-mode` default** changed from `file` to `diff` to
  match every other subcommand. Users who need the legacy per-file blob
  behavior must now opt in with `--download-mode file`.
- **`repair --offline` is mutually exclusive with `--download-only`** —
  passing both exits with code 2.
- **Env vars renamed.** The three remaining `SOCKET_PATCH_*` env vars now
  use the `SOCKET_*` prefix:
  - `SOCKET_PATCH_PROXY_URL` → `SOCKET_PROXY_URL`
  - `SOCKET_PATCH_DEBUG` → `SOCKET_DEBUG`
  - `SOCKET_PATCH_TELEMETRY_DISABLED` → `SOCKET_TELEMETRY_DISABLED`

  The legacy names are still honored at runtime but emit a one-shot
  deprecation warning to stderr (the warning fires even under `--silent`
  and `--json` because the transition signal must reach scripts and CI
  logs). Legacy names will be removed in v4.

### Added

- Shared `GlobalArgs` clap struct `#[command(flatten)]`-ed into every
  subcommand. Every flag is now accepted on every subcommand (silently
  no-op'd where the subcommand doesn't consume it). Every flag has a
  matching `SOCKET_*` env-var binding with precedence
  `CLI arg > env var > default`. See `CLI_CONTRACT.md` for the full
  global-arguments table.
- `apply` and `repair` accept `--api-url`, `--api-token`, `--org` via the
  global flatten (previously env-var only — telemetry would silently fall
  back to the public proxy when the CLI was the only way to set these).
- New global flags `--debug` and `--no-telemetry`, promoted from env-only
  toggles.
- `--proxy-url` (env: `SOCKET_PROXY_URL`) as an explicit CLI knob for the
  public patch proxy.
- New CI guard in the `Release` workflow: the workflow fails before tag
  creation if `CHANGELOG.md` lacks an entry for the version in
  `Cargo.toml`. Blocks every downstream publish (cargo, npm, pypi).

### Changed

- Garbage collection moved out of `apply`. Use `scan --prune`,
  `scan --sync`, or `repair` / `gc` instead. `apply` is now strictly
  non-mutating against `.socket/`: when blobs need to be fetched they go
  to a temp overlay; the persistent cache is never written to.
- Unified JSON envelope (`command` / `status` / `events` / `summary`) for
  `apply`, `list`, `remove`, `repair`. Other subcommands keep their
  pre-v3 ad-hoc shapes for now; see `CLI_CONTRACT.md` for migration status.

## [2.1.4] — 2026-04-09

- Release workflow tolerates already-published npm packages so a partial
  publish can be retried without re-tagging.

## [2.1.3] — 2026-04-08

- Pin Node `22.22.1` in the release workflow to dodge a broken
  upstream npm.

## [2.1.2] — 2026-04-08

- Harden core error handling, blob verification, and `--force` reporting.
- Surface `find_by_purls` errors instead of silently swallowing them.
- Add diagnostics to `apply` for silent no-op failures in CI.
- Add explicit Node typings for TypeScript 6 compatibility in the npm
  wrapper.

## [2.1.1] — 2026-04-02

- Simplify release to `workflow_dispatch` only (no bot commits).
- Split release into PR-based version prep + auto-publish on dispatch.
- Prioritize `pnpm-workspace.yaml` detection and restrict `setup` to root
  `package.json` for pnpm monorepos.
- Harden GitHub Actions workflows per `zizmor` audit.
- Unflag Ruby gem (`gem`) support and add e2e bundler tests.
- Use `npx @socketsecurity/socket-patch` for the generated postinstall
  command.

## [2.1.0] — 2026-03-10

- Full glibc/musl support across all Linux architectures (16 platform
  combinations now published per release).

## [2.0.0] — 2026-03-06

- Interactive prompts and smart patch selection when multiple patches
  match a query.

## [1.7.1] — 2026-03-06

- Ensure the binary has execute permission in the PyPI wrapper.
- Restore `bin` and `optionalDependencies` to the npm wrapper
  `package.json`.

## [1.7.0] — 2026-03-06

- Expand ecosystem support: rough-in for composer, go, maven, nuget, ruby.
- Add a TypeScript schema library to the npm wrapper.
- Treat empty `SOCKET_API_TOKEN` as unset.

## [1.6.3] — 2026-03-05

- Maintenance release.

## [1.6.2] — 2026-03-05

- Maintenance release (version sync).

## [1.6.1] — 2026-03-05

- Switch to per-platform `optionalDependencies` for the npm package.
- Add macOS global-package crawling fallbacks and pyenv support.

## [1.6.0] — 2026-03-04

- Add support for more platforms; fix pypi and npm publish flows.

## [1.5.0] — 2026-03-04

- Fix trusted publishing setup for npm and PyPI.

## [1.4.0] — 2026-03-04

- Update PyPI publish action and add npm provenance permissions.

## [1.3.1] — 2026-03-04

- Fix action image references in the publish workflow.

## [1.3.0] — 2026-03-04

- Add `apply --force`; rename `--no-apply` to `--save-only` (the old name
  remains as a hidden alias).
- Cargo/Rust crate patching support behind a feature flag.
- Auto-resolve org slug from API token when `SOCKET_ORG_SLUG` is unset.

## [1.2.0] — 2026-01-10

- Fix publish workflow to checkout the bumped version.

## [1.1.0] — 2026-01-10

- Pin GitHub Actions to full commit SHAs and wire up version-bump
  support in the publish workflow.
