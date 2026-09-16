# pnpm hosted compatibility

Hosted mode changes the locked artifact URL and integrity while keeping the
package's name and version. Installing that artifact, verifying its files,
recognizing it in an SBOM, and changing an alert's policy/count are separate
operations. This repository tests the first two; these tests do not assert
Socket dashboard detection or alert resolution.

## Required matrix

`.github/workflows/pnpm-compatibility.yml` runs on pull requests and pushes to
`main`. It compiles the CLI/test once, installs the exact package-manager
versions below, and treats missing tools and failed fixture installs as errors.
The matrix needs no Socket API token. The package managers are real; patch
discovery and tarball endpoints are local test servers.

| pnpm versions | Node | Lock format |
| --- | --- | --- |
| 1.0.0 | 10.24.1 | Expected refusal: shrinkwrapVersion 3 without a minor version discards hosted URLs |
| 1.43.1, 2.0.0, 2.25.7 | 10.24.1 | shrinkwrapVersion 3 with a minor version, `shrinkwrap.yaml`, block resolutions |
| 3.0.0, 3.8.1 | 10.24.1 | 5.1, block resolutions |
| 4.0.0, 4.14.4, 5.0.0, 5.18.11 | 16.20.2 | 5.1 / 5.2, block resolutions |
| 6.0.0, 6.35.1 | 16.20.2 | 5.3 |
| 7.0.0, 7.33.7 | 16.20.2 | 5.4 |
| 8.0.0, 8.15.9 | 16.20.2 | 6.0, per-peer package resolutions |
| 9.0.0, 9.15.9 | 24.11.1 | 9.0, packages/snapshots split |
| 10.0.0, 10.33.0, 10.34.5 | 24.11.1 | 9.0 |
| 11.0.0, 11.27.0, 12.0.0, 12.4.2 | 24.11.1 | 9.0, hosted URLs require lockfile trust |

This samples each released major from 1 through 12 and important major
boundaries; it is not an exhaustive test of every historical patch release or
future release. Pre-lockfile releases cannot use hosted lockfile redirection.
Vendored mode has a separate compatibility contract in `docs/ecosystems.md`.

The 24 supported versions exercise scan and explicit-UUID hosted entry points, idempotency,
warm installs, verified VEX, a clean reinstall, a fresh frozen install with a
dead registry and empty store, an ordinary install, byte-exact rollback,
lock-only discovery, and rejection of tampered hosted tarballs. pnpm >=6 also
gets a local-registry workspace fixture with a scoped package, an npm alias,
two peer contexts, and peer dependencies of peers. Legacy workspace behavior
before pnpm 6 is not covered by that fixture.

The remaining row, pnpm 1.0.0, verifies an explicit refusal with the lockfile
unchanged and no successful redirect recorded. Its installer removes the
hosted URL even on a frozen install. For early shrinkwrapVersion 3 locks with
no positive minor version, upgrade to a tested release (1.43.1 or newer) and
regenerate the lock before redirecting, or use installed-file agent mode.

Captured locks under `crates/socket-patch-core/tests/fixtures/pnpm-hosted/`
keep grammar coverage in ordinary offline tests. Additional tests cover
LF/CRLF, nested peer suffixes, quoted keys and URLs, unrelated versions,
malformed mappings, and refusal across multiple locks. A CLI regression test
ensures a hosted URL in one instance cannot confirm a partially patched package.

## Reliable installation

`scan --mode hosted` changes lockfiles; it does not replace already installed
files. Several pnpm versions reuse the original files from an existing install
or store even when installation succeeds. `--force` alone is not portable and
can re-resolve upstream artifacts on pnpm 12.

For CI, install the **patched branch** in a clean checkout without any
`node_modules` directories, using a new empty store for the post-patch install:

```sh
pnpm install --frozen-lockfile --store-dir "$RUNNER_TEMP/socket-patch-store-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
socket-patch vex --output socket-patches.openvex.json
```

The store path must be empty and must not be restored from a cache. On pnpm
1–4 use `--store`; pnpm 1–3 can silently ignore `--store-dir`, and early pnpm 4
rejects it. For a workspace, the clean checkout requirement includes
member `node_modules` trees. Keep the redirected lockfile and any generated
`pnpm-workspace.yaml`; do not delete or regenerate the lock to work around an
installation error. VEX uses installed-file verification by default; exporting
VEX does not automatically upload it or change Socket alert counts.

## Run locally

```sh
cargo test -p socket-patch-core --test pnpm_hosted --test redirect_golden
cargo test -p socket-patch-cli --test in_process_redirect_pnpm

# Provision the chosen pnpm executable and a compatible Node on PATH first.
SOCKET_PATCH_PNPM_E2E_BIN=/absolute/path/to/pnpm \
SOCKET_PATCH_PNPM_E2E_VERSION=10.33.0 \
SOCKET_PATCH_PNPM_E2E_REQUIRED=1 \
cargo test -p socket-patch-cli --test e2e_redirect_pnpm_build \
  pnpm_pinned_matrix -- --ignored --nocapture

# Separate production-service proof, with pnpm on PATH; no API token needed.
SOCKET_PATCH_HOSTED_E2E_STRICT=1 \
cargo test -p socket-patch-cli --test e2e_hosted_production \
  pnpm_hosted_install_proof -- --ignored --nocapture
```

The required test verifies the reported pnpm version. In particular, an
unavailable legacy runtime must fail setup rather than remove a matrix row
from coverage. Hosted tests isolate package-manager caches and allocate
independent empty stores for each installation proof.
