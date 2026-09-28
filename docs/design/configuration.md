# Configuration design: env vars, the socket-cli config file, and what we deliberately don't read

Status: **implemented** (v3.5); section 4 (`socket.yml` patch policy) is
**planned** for v5.0 (see `staged-rollout.md`). This document records the
settled design so future configuration surface grows inside it instead of
inventing new mechanisms.

## Problem

socket-patch's configuration was flags + `SOCKET_*` env vars only. That
architecture is correct for a CLI in the package-manager class, but it had
no story for "configure once, use everywhere": a user who ran
`socket login` with the JS Socket CLI still had to export
`SOCKET_API_TOKEN` for socket-patch. Meanwhile `.env`-style repo-local
config kept coming up as a "simpler setup" suggestion.

## Decisions

### 1. Flag > env > socket-cli config > default — per key

Every flag keeps its clap `env =` binding (`SOCKET_*` prefix, CLI arg wins).
For exactly three settings the JS socket-cli's persisted login state is a
fallback layer between env and default:

```
apiToken / org / apiBaseUrl:
  1. CLI flag              --api-token / --org / --api-url
  2. Canonical env         SOCKET_API_TOKEN / SOCKET_ORG_SLUG / SOCKET_API_URL
  3. Peer alias env        SOCKET_CLI_API_TOKEN / SOCKET_CLI_ORG_SLUG / SOCKET_CLI_API_BASE_URL
                           (silent in-process promotion before clap; canonical wins)
  4. socket-cli config     <data dir>/socket/settings/config.json  (READ-ONLY)
                           keys: apiToken, defaultOrg (accepts alias "org"), apiBaseUrl
  5. Built-in default      no token → public proxy; org → auto-resolve;
                           url → https://api.socket.dev

Vetoes:
  SOCKET_NO_API_TOKEN (alias SOCKET_CLI_NO_API_TOKEN) — ambient tokens
    (layers 2–4) yield none; an explicit --api-token flag still wins.
  SOCKET_NO_CONFIG — layer 4 disabled entirely (also the test-hermeticity
    switch; the workspace .cargo/config.toml exports it for all cargo runs).

Empty string == unset at every layer (repo-wide rule).
```

Implementation: `socket_patch_core::utils::socket_cli_config` (path
resolution mirrors socket-cli's `getSocketAppDataPath` — plus, on macOS, a
second probe of the legacy `~/.local/share` location that older socket-cli
releases wrote on every platform; lenient base64→JSON→plain-JSON decode,
allowlist copy, `OnceLock` disk cache with the gate checked per call),
consumed by `get_api_client_with_overrides`
(`api/client.rs`) and — for `apiBaseUrl` — by the shared
`resolve_api_base_url()` that the telemetry endpoint resolver also uses, so
client and telemetry can never disagree about the API host. The
`--api-url`/`--proxy-url` clap defaults were removed (fields are
`Option<String>`) so the layer isn't dead code; the documented defaults are
applied at client construction.

### 2. The file is socket-cli's; we only read it

No `socket-patch login`, no `socket-patch config set`, no writes ever. The
file (base64-encoded JSON) is written by `socket login` / `socket config
set`. Corrupt or unreadable → one-shot stderr warning naming the path, then
treated as absent; missing → silent. `--json` stdout purity holds because
all diagnostics are stderr-only. Keys other than the three above
(`apiProxy`, `enforcedOrgs`, `skipAskToPersistDefaultOrg`) are socket-cli
UX policy and are ignored.

### 3. Alignment across Socket tools

- The python `socketsecurity` CLI already accepts `SOCKET_API_TOKEN`, so
  the canonical names are the cross-tool bridge; no `SOCKET_SECURITY_*`
  aliases were added.
- `socket.yml` is shared with the scanning product (projectIgnorePaths /
  triggerPaths / issueRules / githubApp). As of v5.0 socket-patch reads
  exactly two of its keys, `projectIgnorePaths` and a new `patches` block,
  and nothing else (section 4).
- `SOCKET_PROXY_URL` (the public patch **endpoint**) must never be
  conflated with socket-cli's `apiProxy` (an HTTP **forward proxy**).
  Forward-proxy behavior comes from the standard
  `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` vars, which reqwest honors.

### 4. `socket.yml` carries patch selection policy, never settings (v5.0)

Revisits the v3.5 position that socket-patch does not read `socket.yml`.
Staged rollout needs a repo-owned, reviewable place to say which projects,
ecosystems and packages may be patched, a severity floor and a per-run cap
on new patches (`staged-rollout.md`). `socket.yml` is where Socket users
already express repo policy, it lives at the repo root, and a new
top-level `patches:` key is stripped or ignored by every existing parser.

The trust boundary is unchanged and gains its positive half:

- A repository file may **narrow or pace** what `scan` patches. It may
  never widen it, name an endpoint or credential, choose a mode or download
  format, or disable a safety interlock. The parser has no fields for any
  of those; such keys are unknown keys and fail validation.
- Because the file only narrows, an unreadable file or an invalid
  `patches` block fails closed (exit 1, `socket_yml_invalid`, nothing
  written) instead of being treated as absent. (A repo with no `patches`
  block and a malformed `projectIgnorePaths` gets a warning, so repos that
  never opted in do not start failing.) This is the opposite of the socket-cli `config.json` rule above
  (corrupt → warn and ignore), and deliberately so: ignoring a broken
  user-level login file loses a convenience; ignoring a broken repo policy
  widens the rollout.
- Lookup is bounded to the repository (nearest `.git` ancestor of
  `--cwd` owned by the user, honoring `GIT_CEILING_DIRECTORIES`, else
  `--cwd`), root files only, regular files only.
- Flags and env vars still win over the file for scalars (CLI > env >
  file > default) and intersect with it for list filters;
  `--no-socket-yml` / `SOCKET_NO_SOCKET_YML` ignores the file.
- Only `scan` (every mode) and the in-memory engine honor it. Commands
  that report, attest or undo existing state (`list`, `vex`, `rollback`,
  `remove`, `repair`, `apply`, `vendor`) ignore it; `get` bypasses it with
  a warning.

## Explicitly rejected

| Idea | Why not |
|---|---|
| Auto-loading `.env` / `.env.local` | Trust boundary: the tool mutates installed packages while holding an API token; a file in a *cloned repo* must never redirect endpoints, disable interlocks, or spend the token. Also the wrong convention class — npm/cargo/pip/git read no `.env`; dotenv is an app-runtime convention. Users who want it have direnv/mise/dotenvx. |
| A new socket-patch config file (`.socket/config.toml`, …) | Duplicates socket-cli's persisted config; one more file format to trust, document, and migrate. |
| Writing to socket-cli's `config.json` | No login flow here; shared mutable state and format drift for zero benefit. |
| Honoring endpoints/credentials/interlock switches from repo-level files (manifest, socket.yml) | Same trust boundary as `.env`. Stated as a contract property in `CLI_CONTRACT.md`. Selection policy that only narrows is the one exception (section 4). |
| A `version: 3` socket.yml for the `patches` block | socket-cli rejects any version but 2; older ajv parsers would treat 3 as 2 anyway. The block is additive under `version: 2`. |
| Per-directory `socket.yml` files | No existing consumer supports them; one root file with `includePaths` covers monorepos. |
| `SOCKET_CLI_CONFIG` (ephemeral full-JSON config override) | Imports socket-cli's whole config vocabulary as a permanent compat contract. |
| Mapping `apiProxy` → anything | Forward-proxy vs patch-endpoint semantic trap; `HTTP_PROXY` et al. already work. |
| `enforcedOrgs` / `skipAskToPersistDefaultOrg` | Interactive socket-cli UX policy with no socket-patch analog. |

## Deferred (designated homes, no implementation yet)

- **Project-level behavioral defaults** (`downloadMode`, `vendorSource`,
  mode): not planned. The v3.5 idea of a manifest `setup.defaults` block is
  obsolete in v5 (hosted and vendored projects have no manifest and `setup`
  is removed). Selection policy (ecosystems, packages, paths, severity,
  per-run cap) went to `socket.yml` `patches` instead (section 4). Anything
  that is not pure narrowing stays out of repo files.
- **Env cleanup sweep**: core's direct env readers (`SOCKET_OFFLINE` in
  `utils/env_compat.rs`, `SOCKET_TELEMETRY_DISABLED` in `telemetry.rs`)
  still match only `1|true`, unlike `parse_bool_flag`'s vocabulary (the CLI
  mirrors `--offline` into `SOCKET_OFFLINE=1`, so only a hand-set env value
  sees the narrower dialect); consider `FORCE_COLOR` as an alias for `CLICOLOR_FORCE` in
  `ui::color_enabled` (which already honors `NO_COLOR`, `CLICOLOR`,
  `CLICOLOR_FORCE` and `TERM=dumb`); document
  `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` support in the README.
- **`SOCKET_API_TOKEN_FILE` / keychain sourcing** for the token — the
  conventional next step for secret hygiene; not urgent now that the
  config-file path exists.

## Test strategy (how this stays true)

- `tests/cli_config_fallback.rs` spawns the binary against fixture
  `config.json` files (fresh process per case — the disk read is cached per
  process) and pins: config token/apiBaseUrl authenticate, `defaultOrg`
  skips org auto-resolve with telemetry following the config host+token,
  env-beats-config per key, alias honored with canonical winning, corrupt
  config warns while `--json` stdout parses, both toggles, and the
  missing-file silence.
- Hermeticity: `.cargo/config.toml` `[env]` exports `SOCKET_NO_CONFIG=1` so
  a developer's real login can never authenticate a test; the e2e env
  scrub loops deliberately skip that variable so the guard survives into
  spawned binaries.
