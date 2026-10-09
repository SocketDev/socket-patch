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
the API for it (`GET /v0/organizations`) once per run. If that fails, the whole
run uses the public patch API without the token (free patches only) and warns;
set `--org` or `SOCKET_ORG_SLUG` to use your organization's patches.

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
