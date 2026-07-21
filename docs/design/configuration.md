# Configuration design: env vars, the socket-cli config file, and what we deliberately don't read

Status: **implemented** (v3.5). This document records the settled design so
future configuration surface grows inside it instead of inventing new
mechanisms.

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
resolution mirrors socket-cli's `getSocketAppDataPath`, lenient
base64→JSON→plain-JSON decode, allowlist copy, `OnceLock` disk cache with
the gate checked per call), consumed by `get_api_client_with_overrides`
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
- `socket.yml` stays a scanning-product surface (projectIgnorePaths /
  issueRules / githubApp); socket-patch does not read it.
- `SOCKET_PROXY_URL` (the public patch **endpoint**) must never be
  conflated with socket-cli's `apiProxy` (an HTTP **forward proxy**).
  Forward-proxy behavior comes from the standard
  `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` vars, which reqwest honors.

## Explicitly rejected

| Idea | Why not |
|---|---|
| Auto-loading `.env` / `.env.local` | Trust boundary: the tool mutates installed packages while holding an API token; a file in a *cloned repo* must never redirect endpoints, disable interlocks, or spend the token. Also the wrong convention class — npm/cargo/pip/git read no `.env`; dotenv is an app-runtime convention. Users who want it have direnv/mise/dotenvx. |
| A new socket-patch config file (`.socket/config.toml`, …) | Duplicates socket-cli's persisted config; one more file format to trust, document, and migrate. |
| Writing to socket-cli's `config.json` | No login flow here; shared mutable state and format drift for zero benefit. |
| Honoring endpoints/credentials from repo-level files (manifest, socket.yml) | Same trust boundary as `.env`. Stated as a contract property in `CLI_CONTRACT.md`. |
| `SOCKET_CLI_CONFIG` (ephemeral full-JSON config override) | Imports socket-cli's whole config vocabulary as a permanent compat contract. |
| Mapping `apiProxy` → anything | Forward-proxy vs patch-endpoint semantic trap; `HTTP_PROXY` et al. already work. |
| `enforcedOrgs` / `skipAskToPersistDefaultOrg` | Interactive socket-cli UX policy with no socket-patch analog. |

## Deferred (designated homes, no implementation yet)

- **Project-level behavioral defaults** (`ecosystems`, `downloadMode`,
  `vendorSource`): if demand materializes, they go in the manifest `setup`
  block (`setup.defaults`, camelCase) — the manifest already controls what
  gets patched, so behavioral defaults there grant no new capability, and
  the serde struct simply has no fields for URLs/credentials/interlocks.
  Requires teaching the TS zod twin
  (`npm/socket-patch/src/schema/manifest-schema.ts`) to model `setup`.
  Precedence would be flag > env > `setup.defaults` > default.
- **Env cleanup sweep** (separate task, agreed 2026-07-21): unify the four
  bool-parsing dialects (`parse_bool_flag` vs stock `BoolishValueParser` on
  `--all-releases`, bare clap bool on `get --one-off`, `env_truthy`'s
  `1|true`-only match on the experimental gates and core's `SOCKET_OFFLINE`
  reader); honor `NO_COLOR` (and `FORCE_COLOR`/`CLICOLOR_FORCE`) in
  `output.rs`, which today keys only off `is_terminal()`; document
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
