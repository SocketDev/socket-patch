# Hosted production tests

[`e2e_hosted_production.rs`](../../crates/socket-patch-cli/tests/e2e_hosted_production.rs)
exercises hosted patching against Socket's production public proxy, patch server,
and upstream registries. It complements controlled-input native installer suites,
which can validate rewrite behavior without detecting production-service drift.

## What it proves

Each install-proof case installs a pinned upstream package, checks that its bytes
are pristine, runs a hosted scan, and verifies the new reference and integrity pin.
It then removes the installed tree, installs from the changed dependency files with
fresh caches, and verifies patched bytes. The suite also exercises manifest-free
VEX. This proves delivery of the selected patch; it does not test exploit efficacy.

## Catalog fixtures and coverage

The test's catalog constants and preflight checks are authoritative for required
PURLs, patch UUIDs, and byte markers. They use free patches through
`patches-api.socket.dev`, with ambient authentication scrubbed. Catalog contents
can change independently of this repository; do not treat a past run as a current
publication guarantee.

| Coverage | Cases |
| --- | --- |
| Native production installs | npm/shrinkwrap, pnpm, Yarn Classic, Yarn Berry with node-modules, Bun, pip requirements, uv, and Bundler |
| Conditional production proof | vlt: validates the served encoding before attempting installation |
| Catalog canaries | Cargo, Maven, NuGet, and Composer: detect when a free fixture becomes available; do not prove an install |
| Go | Validates the required hosted reference shape; see [Go support](../ecosystems.md#go-directory-replaces-and-gosum) |
| Unsupported mode | Deno hosted refusal |

Poetry, PDM, and Pipenv production installers are covered by their
[release backtests](README.md#package-manager-guides). Rush and Yarn PnP are not
production install-proof cases in this suite. Controlled fixtures and production
coverage are distinct; neither should be inferred from the other.

### If a required patch is withdrawn

1. Choose a published free patch in the same ecosystem, preferably a small package
   supported by each affected installer.
2. Update the catalog constants, accepted patch set, and patched-byte marker in
   both production suites. Read the selected record rather than assuming the
   catalog's ranking is unchanged.
3. Run preflight and every affected native install proof. Keep the production
   fixtures and assertions consistent; a missing fixture must not silently turn a
   required install check into a pass.

To promote a canary into installation coverage, add its catalog fixture, preflight
registration, install-proof test, and CI toolchain. Update this coverage table and
the [vendored suite](vendored-production-e2e.md) together.

## vlt: the serve-encoding gate

vlt verifies the raw response body. If the patch server returns a content-encoded
artifact, the hosted CLI refuses it with `redirect_vlt_artifact_unverifiable` and
leaves the lock unchanged. The production leg probes the artifact using vlt's
request headers and asserts either that refusal or, for identity encoding, the
full fresh-checkout `vlt ci` proof.

`SOCKET_PATCH_VLT_HOSTED_PRODUCTION_REQUIRED=1` requires the install branch and
fails on an encoded response. The
[serve watchdog](../../.github/workflows/vlt-serve-watchdog.yml) monitors this
boundary; the current run's probe, not a dated note, determines server behavior.
The [vlt guide](vlt-compatibility.md) defines the required leg reporting.

## Running

```sh
cargo test --locked -p socket-patch-cli --test e2e_hosted_production -- --ignored

# One install proof:
cargo test --locked -p socket-patch-cli --test e2e_hosted_production -- \
  --ignored yarn_berry_hosted_install_proof --nocapture
```

The suite is opt-in. Missing tools can skip local cases; use strict mode when
coverage is required.

| Variable | Effect |
| --- | --- |
| `SOCKET_PATCH_HOSTED_E2E_STRICT=1` | Fail instead of skipping missing required toolchains |
| `SOCKET_PATCH_HOSTED_E2E_CANARY_STRICT=1` | Fail when a watched ecosystem gains a free fixture, prompting promotion |
| `SOCKET_PATCH_VLT_E2E_JS` / `SOCKET_PATCH_VLT_E2E_VERSION` | Select an installed, version-pinned vlt executable |
| `SOCKET_PATCH_VLT_HOSTED_PRODUCTION_REQUIRED=1` | Require vlt's actual install proof rather than its encoding refusal |

Tools include npm, Corepack for pnpm/Yarn, Bun, uv, Go, and Ruby/Bundler. The gem
proof requires Bundler 2.6+ for lockfile checksums. vlt requires its configured
Node runtime and executable. The workflow pins and provisions CI versions.
Network access includes Socket's public API and patch server, npm, PyPI, and
RubyGems registries.

## CI and service outages

The [`hosted-e2e` job](../../.github/workflows/ci.yml) runs independently of the
other test jobs and retries production failures up to three times. It also runs
the vendored vlt production proof and validates vlt leg output. Branch protection
settings are configured separately from the workflow.

During a production outage, maintainers can set the repository Actions variable
`HOSTED_E2E_DISABLED` to exactly `true`, then rerun affected jobs. The steps report
**BYPASSED** in the job summary; that successful job is not test evidence. Delete
the variable to restore coverage. Manual workflow dispatch accepts `hosted_e2e`
values `force` (ignore the variable) or `skip` (bypass that run).
