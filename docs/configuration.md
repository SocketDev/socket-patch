# Configuration

Socket Patch reads command-line flags, environment variables, the Socket CLI's
persisted login, and repository patch-selection policy. For the complete flag and
environment-variable tables, see the
[CLI contract](../crates/socket-patch-cli/CLI_CONTRACT.md#environment-variables).

## Authentication and endpoints

Without a token, Socket Patch uses `https://patches-api.socket.dev` to access the
free patch catalog. With a token, it uses `https://api.socket.dev` and your
organization's patch entitlement.

For the token, organization, and authenticated API URL, precedence is:

1. Command-line flag.
2. Canonical environment variable, then its Socket CLI alias.
3. Socket CLI's persisted `config.json`.
4. Built-in default.

| Setting | Flag | Environment variable | Socket CLI alias | Persisted key |
| --- | --- | --- | --- | --- |
| Token | `--api-token` | `SOCKET_API_TOKEN` | `SOCKET_CLI_API_TOKEN` | `apiToken` |
| Organization | `--org` | `SOCKET_ORG_SLUG` | `SOCKET_CLI_ORG_SLUG` | `defaultOrg` (also accepts `org`) |
| Authenticated API | `--api-url` | `SOCKET_API_URL` | `SOCKET_CLI_API_BASE_URL` | `apiBaseUrl` |

With a token but no organization from any of these sources, Socket Patch asks
the API for it (`GET /v0/organizations`) once per run, the first time the run
needs the patch API. If that fails, the whole run uses the public patch API
without the token (free patches only) and warns; set `--org` or
`SOCKET_ORG_SLUG` to use your organization's patches. `apply`, `rollback`,
`remove`, and `repair` set the API client up only when they have a patch file
to download, so a run that finds everything on disk makes no API request and
prints no API notice; `list` and `apply --check` never contact the API. (One
exception: an `apply` with Maven patches in scope always sets the client up,
because a Maven patch may need its patched jar from the patch service.)

The separate Socket CLI writes that file through `socket login` or `socket config`.
Socket Patch only reads it. Missing configuration is silent; an unreadable or
invalid login file produces a warning and falls back to the other sources.
Empty environment values are treated as unset.

- `SOCKET_NO_CONFIG=1` disables persisted configuration.
- `SOCKET_NO_API_TOKEN=1` ignores ambient tokens from the environment and login
  file; an explicit `--api-token` still wins. `SOCKET_CLI_NO_API_TOKEN` is an alias.
- `--proxy-url` / `SOCKET_PROXY_URL` selects the public patch API endpoint. It is
  distinct from an HTTP forward proxy: use `HTTP_PROXY`, `HTTPS_PROXY`, and
  `NO_PROXY` for those.
- HTTPS connections trust the bundled Mozilla (webpki) roots plus the operating
  system's trust store (macOS keychain, Windows certificate store, the distro
  bundle on Linux). `SSL_CERT_FILE` / `SSL_CERT_DIR` replace the system store
  with the named bundle or directory, which is how to trust a TLS-inspecting
  proxy's private CA. Certificate verification is never disabled.
- `--offline` prohibits network access. `scan` and `get` require the patch API
  and refuse offline operation. Other commands can use locally available state;
  missing records or artifacts can still prevent completion.
- `SOCKET_NO_UPDATE_CHECK=1` disables the passive update notice.

For other settings, precedence is flag → environment → default, except for the
repository policy scalars below. Socket Patch does not automatically load `.env`
files, and repository files cannot set credentials, API endpoints, or safety options.

## Telemetry

Telemetry is on by default. Each command reports its outcome to Socket as one
JSON event (two for a `scan` or `get` that also applies patches).

### What is sent

Every event has these fields:

| Field | Value |
| --- | --- |
| `event_type` | One of the event names in the table below |
| `event_sender_created_at` | UTC timestamp of the event |
| `session_id` | A random UUID generated for that one run. It is not stored, so it links the events of a single run and nothing else |
| `context.version` | The Socket Patch version |
| `context.platform`, `context.arch` | Operating system and CPU architecture (for example `linux`, `x86_64`) |
| `context.command` | The subcommand (`scan`, `apply`, …) |
| `metadata` | The per-event fields in the table below, and nothing else |
| `error.type`, `error.message` | Failure events only. URLs in the message are redacted (credentials, grant tokens, signed query values) and your home directory is replaced by `~`. The message can still quote a package name or a path in the project |

| Command | Event on success | Event on failure | `metadata` fields |
| --- | --- | --- | --- |
| `scan` | `patch_scanned` | `patch_scan_failed` | `packages_scanned`, `free_patches`, `paid_patches`, `can_access_paid`, `ecosystems` (names such as `npm`, not packages), `fallback_to_proxy`, `mode`, `project_modes` |
| `scan` / `get` in hosted mode | `patch_applied` | `patch_apply_failed` | `mode` (`hosted`), `patches_count`, `files_count`, `dry_run` |
| `apply`, and `scan` / `get` in agent mode | `patch_applied` | `patch_apply_failed` | `mode` (`agent`), `patches_count`, `dry_run` |
| `vendor`, and `scan` / `get` in vendored mode | `patch_vendored` | `patch_vendor_failed` | `patches_count`, `dry_run` |
| `get` | `patch_fetched` | `patch_fetch_failed` | `uuid` (the patch UUID), `tier`, `ecosystem`, `download_mode`, `fallback_to_proxy` |
| `remove` | `patch_removed` | `patch_remove_failed` | `removed_count` |
| `rollback` | `patch_rolled_back` | `patch_rollback_failed` | `rolled_back_count` |
| `list` | `patch_listed` | — | `patches_count` |
| `repair` | `patch_repaired` | `patch_repair_failed` | `blobs_added`, `blobs_removed`, `bytes_freed` |
| `vex` | `vex_generated` | `vex_failed` | `advisories_count`, `format`, `output_kind` |
| `--update` | `cli_updated` | `cli_update_failed` | `from_version`, `to_version`, `channel`, `pinned`, `forced`; on failure `error_code` |

A failure event carries the subset of its row's fields known when it failed;
`patch_fetch_failed` reports `uuid` only when you asked for a patch by UUID.

An event carries no dependency list, no file contents, and no machine
identifier. The HTTP request has a `User-Agent` of `SocketPatchCLI/<version>`
and, like any request, shows the server your IP address.

### Where it goes

With an API token and an organization, events are sent to
`https://api.socket.dev/v0/orgs/<org>/telemetry`, authenticated with the token,
so they are attributable to your organization. Otherwise they are sent without
credentials to `https://patches-api.socket.dev/patch/telemetry`.
`--api-url` / `SOCKET_API_URL` and `--proxy-url` / `SOCKET_PROXY_URL` move both.

A run that never contacts the patch API (see
[Authentication and endpoints](#authentication-and-endpoints)) does not look
your organization up just to report: with a token but no `--org`,
`SOCKET_ORG_SLUG`, or `socket login` organization, its event goes to the
anonymous endpoint.

### It never holds a command up

Events are sent in the background while the command works. A command does not
wait for telemetry before printing or prompting, and a failed send changes no
output and no exit code (`--debug` shows it). When the command is done, it
waits at most 300 ms for an event still being sent, then exits; an unreachable
or stalled endpoint cannot add more than that. An event that is not delivered
in time is dropped.

### Turning it off

Any one of these disables telemetry:

- `--no-telemetry` on the command line.
- `SOCKET_TELEMETRY_DISABLED=1` (also `true`, `yes`, `on`).
- `DO_NOT_TRACK=1` (any value except `0`, `false`, or empty).
- `SOCKET_PATCH_TELEMETRY_DISABLED=1`, the name Socket Patch v4 and earlier used.
- `--offline` / `SOCKET_OFFLINE=1`, which prohibits all network access.

Telemetry is also off when `VITEST=true`, so the Socket CLI's own test suite
never reports.

## Repository patch policy

Commit a root `socket.yml` to control what `scan` may patch:

```yaml
version: 2
patches:
  enabled: true
  ecosystems: [npm, pypi]
  minSeverity: high
  maxNewPatches: 5
  includePaths: ["apps/**", "services/**"]
  ignorePaths: ["services/legacy/**"]
  ignorePackages: ["pkg:npm/example-package"]
```

Omit lists you do not need. The policy narrows selection; it does not choose a patch
mode or add dependencies. Socket Patch reads only `projectIgnorePaths` and the
`patches` block from the shared Socket configuration, plus the `version` needed to
validate that block.

| Key under `patches` | Meaning |
| --- | --- |
| `enabled` | `false` reports candidates without changing patches or running prune |
| `ecosystems` | Limit selection to ecosystem slugs from the [support matrix](ecosystems.md) |
| `includePaths` / `ignorePaths` | Include or exclude project roots by their dependency-file paths |
| `packages` / `ignorePackages` | Include or exclude package names or PURLs, optionally with exact versions |
| `minSeverity` | Minimum severity: `critical`, `high`, `medium` (`moderate`), or `low`; omit for no floor |
| `maxNewPatches` | Maximum newly patched package identities per invocation; integer from 0 to 4294967295; omit for unlimited |

A package already patched but now excluded is retained unchanged. Narrowing policy
never unpatches it. Use `rollback` or `remove` to remove a patch.

### Precedence and scope

CLI list filters (`--ecosystems`, `--package`, and PATHs) intersect with the file's
lists. Scalar settings follow flag → environment → file → default:

```sh
socket-patch scan --min-severity critical
socket-patch scan --max-new-patches 2
socket-patch scan --no-socket-yml
```

The scalar environment variables are `SOCKET_MIN_SEVERITY` and
`SOCKET_MAX_NEW_PATCHES`. `--no-socket-yml` / `SOCKET_NO_SOCKET_YML` bypasses the file;
built-in discovery exclusions still apply.

Policy applies to every `scan` mode, including previews, and to the in-memory hosted
engine. `get` is an explicit selection: it bypasses policy and warns when a valid
policy would exclude its target. `apply`, `list`, `vex`, `vendor`, `repair`, `rollback`,
and `remove` do not apply selection policy to existing patches.

Only the repository root's `socket.yml` or `socket.yaml` is read, not a file per
subdirectory. Repository lookup starts at `--cwd` and uses the nearest trusted `.git`
ancestor; without one it uses `--cwd`. Global scans read no repository policy.
If both filenames exist, their policies must agree. Invalid patch policy fails the
scan before network requests or writes rather than silently broadening selection.
See the [exact lookup and validation rules](../crates/socket-patch-cli/CLI_CONTRACT.md#socketyml-patch-policy-v50).

### Paths and monorepos

Path lists use case-insensitive gitignore semantics, relative to the repository
root. Later matches win; `!` negates, but cannot re-include a child of an ignored
directory. A root is excluded only when all of its dependency markers are ignored;
`includePaths` admits it when any marker matches. A workspace member sharing the
root's lockfile is part of that project: use package filters to restrict its patches.

Discovered project roots under `test/`, `tests/`, `fixtures/`, `__fixtures__/`, and
`testdata/` are excluded by default. An explicitly named root (`--cwd` or a literal
PATH) skips these defaults, but still follows repository policy. A file pattern can
re-include a default, for example `ignorePaths: ["!/e2e/tests/"]`.

```sh
socket-patch scan --cwd apps/web
socket-patch scan 'apps/*' --mode hosted
```

Each PATH in hosted or vendored mode is a project directory. Paths outside the
repository are rejected. For JSON output, scan one project per invocation.

An agent-mode scan from the repository root also patches nested projects'
`node_modules`. Each installed copy follows its own project root (the nearest
directory with a lockfile), so these filters skip nested projects too. A package
an included project also installs is patched in every copy, because patches are
recorded per package version; the scan warns `policy_shared_copy` when that reaches
a skipped project.

### Gradual rollout

```sh
socket-patch scan --max-new-patches 5       # add at most five newly patched packages
socket-patch scan --max-new-patches 0       # upgrade existing patches only
socket-patch scan --max-new-patches none    # remove the cap for this run
```

New patches are prioritized by severity, then advisory count, with deterministic
tie-breaking. Updates of already patched packages do not consume the cap. Multiple
project directories in one invocation share the budget and are visited in sorted
order; the same admitted package identity does not spend it twice. Separate commands
have separate budgets.

A preview reports what would be admitted or deferred. JSON results include `policy`
and `rollout` summaries. Repeated scans advance against the state from previous runs;
in a PR workflow, merge the changed dependency files before expecting a fresh
checkout to advance to the next batch. The CLI does not schedule runs or count open
PRs.
