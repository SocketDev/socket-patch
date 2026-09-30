# Vendored production tests

[`e2e_vendored_production.rs`](../../crates/socket-patch-cli/tests/e2e_vendored_production.rs)
uses the public patch service and real upstream registries to test committed
patched artifacts. It complements the [hosted suite](hosted-production-e2e.md)
and controlled-input vendor tests.

## What it proves

Each install-proof case starts with pristine installed bytes, runs
`scan --mode vendored`, and checks the artifact, ledger, and dependency edits.
It copies only committable project files to a fresh checkout, isolates caches,
installs from the committed artifacts, and checks the patched bytes. Reruns,
reversal, and manifest-free VEX exercise the rest of the lifecycle.

This tests patch delivery, not exploit efficacy. The fixture determines which
other dependencies must be available during installation; vendoring patched
packages does not itself make every dependency offline.

## Catalog fixtures and coverage

The test source defines required PURLs, accepted patch UUIDs, byte markers, and
preflight checks. It shares the npm, PyPI, and RubyGems fixture families with the
hosted suite. Follow its [withdrawn-patch procedure](hosted-production-e2e.md#if-a-required-patch-is-withdrawn)
when the catalog changes, updating both suites.

| Coverage | Cases |
| --- | --- |
| Native production installs | npm, pnpm, Yarn Classic, Yarn Berry with node-modules, Bun text locks, vlt, pip requirements, uv, and Bundler |
| Catalog canaries | Cargo, Maven, NuGet, and Composer; require a published free fixture before adding full install proofs |
| Go / Deno | Catalog/unsupported-mode assertions, not production vendor install proofs |

The vlt case installs a committed directory artifact with `vlt ci`. The CLI
decodes the service download before vendoring it, so the hosted vlt
[serve-encoding gate](hosted-production-e2e.md#vlt-the-serve-encoding-gate) does
not prevent this proof. Per-release coverage lives in the
[compatibility guides](README.md#package-manager-guides).

### RubyGems artifact validation

A vendored Bundler path source needs the server's valid stub gemspec. The CLI downloads and validates it with the archive. Missing or invalid server stubs fail closed; there is no local gem build fallback.

## Running

```sh
cargo test --locked -p socket-patch-cli --test e2e_vendored_production -- \
  --ignored --test-threads=1

# Require the toolchains instead of allowing local skips:
SOCKET_PATCH_VENDORED_E2E_STRICT=1 \
  cargo test --locked -p socket-patch-cli --test e2e_vendored_production -- \
  --ignored --test-threads=1
```

The suite is opt-in. Single-threaded execution avoids competing native installs.
It clears ambient Socket credentials and disables persisted login; no API token
is needed.

| Variable | Effect |
| --- | --- |
| `SOCKET_PATCH_VENDORED_E2E_STRICT=1` | Fail instead of skipping missing required toolchains |
| `SOCKET_PATCH_VENDORED_E2E_CANARY_STRICT=1` | Fail when a watched ecosystem gains a free fixture |
| `SOCKET_PATCH_VLT_E2E_JS` / `SOCKET_PATCH_VLT_E2E_VERSION` | Select the version-pinned vlt executable |

Tools include npm, pnpm, Corepack for Yarn, Bun, vlt, uv, Python/pip, Ruby/Bundler,
and Go. Networked fixture preparation requires Socket's API and patch server plus
npm, PyPI, and RubyGems. CI versions and triggers are defined in the
[main workflow](../../.github/workflows/ci.yml) and package-manager workflows.
The main `hosted-e2e` job includes the vendored vlt proof; it does not imply that
every vendored production case ran.
