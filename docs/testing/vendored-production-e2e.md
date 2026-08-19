# Vendored-mode production e2e

`crates/socket-patch-cli/tests/e2e_vendored_production.rs` is the vendored-mode
counterpart to [`hosted-production-e2e.md`](./hosted-production-e2e.md). The
synthetic `e2e_vendor_*_build.rs` capstones prove the vendoring *mechanism* with
a hand-staged `.socket/` blob and `vendor --offline`; they never contact
production. This suite is the opposite: it drives `scan --mode vendored` against
the **real** Socket production service and the **real** upstream registries with
**no mocking anywhere**, on the anonymous **free public proxy** (no API token).

## What it proves

For each ecosystem × package manager:

1. install a pinned, known-vulnerable dependency from its **real** upstream
   registry with the **real** package manager;
2. assert the installed bytes are pristine (anti-vacuity);
3. `socket-patch scan --mode vendored --json --yes` — resolves a free patch from
   `patches-api.socket.dev`, materializes the patched package into the
   committable `.socket/vendor/<eco>/<uuid>/` tree, and rewires the lockfile /
   manifest to consume it;
4. assert the vendor landed (`summary.applied >= 1`, `failed == 0`, expected
   patch UUID present, artifact on disk, lock rewired);
5. **DELIVERY proof** — copy ONLY the committable files (project manifest +
   lockfile + `.socket/` + any PM config) into a fresh dir, point every cache
   var at a fresh EMPTY dir, run the package manager's clean-install offline,
   and assert the installed bytes are the VENDORED (patched) bytes, NOT the
   pristine registry bytes;
6. idempotency (a second run is an `already_vendored` no-op with a byte-stable
   lock) and `vendor --revert` byte-restores.

Step 5 is the point. It is the only place in this repo where a third-party
package manager installs, from a genuinely cold cache and with only the
committable files, a package vendored from a **real** Socket production patch.

This suite proves **byte delivery** — the bytes the vendored patch produced are
the bytes the package manager installs. It does NOT assert CVE efficacy;
whether the fix content actually closes the advisory is a separate concern, and
several production patches are byte-valid but that is a different question. This
matches how the `e2e_vendor_*_build.rs` capstones assert.

## Required production patches

Pinned to these free-tier patches; they must stay published on
`patches-api.socket.dev`. `preflight_required_patches_are_published` checks all
four every run and fails first with the offending PURL named.

| Ecosystem | PURL | Patch UUID | Marker in the patched bytes |
|-----------|------|------------|-----------------------------|
| npm | `pkg:npm/minimist@1.2.2` | `80630680-4da6-45f9-bba8-b888e0ffd58c` | `Socket Community Patch` header |
| PyPI | `pkg:pypi/urllib3@1.26.18` | one of three (server-ordered) | `Socket Community Patch` header |
| Cargo | `pkg:cargo/traitobject@0.1.1` | `cf2e6f58-d9fa-4096-9151-c34afa717f89` | advisory id `GHSA-pp8r-vv2j-9j5v` |
| RubyGems | `pkg:gem/activestorage@6.0.3` | `15e960b5-f432-4b6c-b8aa-534a2b419323` | `Socket Community Patch` header |

If a required patch is withdrawn, update the catalog constants at the top of
`e2e_vendored_production.rs` **and** the table above (same procedure as the
hosted suite).

## Coverage: PM × proof

| Package manager | Fixture | Delivery install (cold, offline, committable-only) | Status |
|-----------------|---------|-----------------------------------------------------|--------|
| npm | minimist@1.2.2 | `npm ci` | ✅ full |
| pnpm | minimist@1.2.2 | `pnpm install --frozen-lockfile --offline` | ✅ full |
| yarn classic | minimist@1.2.2 | `yarn install --frozen-lockfile --offline` | ✅ full |
| yarn berry (node-modules) | minimist@1.2.2 | `yarn install --immutable --check-cache` | ✅ full |
| bun (text lockfile) | minimist@1.2.2 | `bun install --frozen-lockfile` | ✅ full |
| pip (requirements.txt) | urllib3@1.26.18 | `pip install --no-index -r requirements.txt` | ✅ full |
| uv (uv.lock) | urllib3@1.26.18 | `uv sync --frozen --offline` | ✅ full |
| cargo (`[patch.crates-io]`) | traitobject@0.1.1 | `cargo fetch --offline --locked` (see note) | ✅ full |
| bundler | activestorage@6.0.3 | frozen `bundle install`, fresh empty `BUNDLE_PATH` | ✅ full |
| go | — | — | zero-patch assertion (no free golang patches) |
| deno | — | — | negative assertion (unsupported) |
| maven / nuget / composer | — | — | canary (no free production patches) |

The cargo delivery proof uses `cargo fetch --offline`, not `cargo build`,
because the production traitobject patch injects a `compile_error!` unless the
`allow-unmaintained` Cargo feature is enabled — the patch's whole point is to
make the unmaintained crate refuse to compile. That is patch *content*, not a
vendoring defect; the leg proves the artifact resolves entirely from the
committable files with zero registry downloads, and byte-checks the vendored
directory.

## Known issues this suite surfaced

All were found against real production + real toolchains; none is a test bug.
The first two are fixed; the third is mitigated CLI-side (the served artifact
is still defective server-side).

### 1. `pnpm` >= 11 — vendored `overrides` land in the wrong file (CLI) — FIXED

pnpm 11 stopped reading `overrides` from `package.json`'s `pnpm` field — it
moved to `pnpm-workspace.yaml` (https://pnpm.io/settings). The CLI used to write
only `package.json` `pnpm.overrides`, so pnpm 11 ignored it and a frozen install
refused with `ERR_PNPM_LOCKFILE_CONFIG_MISMATCH`, even though the vendored
tarball and lock were correct (the lockfile passes pnpm's supply-chain policy).

**Fixed** (`fix/pnpm11-overrides-location`): the pnpm vendor backend now
mirrors the same versioned `<name>@<version>` → `file:` override into
`pnpm-workspace.yaml` (creating the file with a root-only `packages: ['.']`
list — pnpm 9 refuses a workspace file with no `packages` field — when the
project has none), alongside the existing `package.json` `pnpm.overrides` for
pnpm 9/10. The committable set installs cleanly on pnpm 9/10/11 with no config
mismatch, and `vendor --revert` deletes a file it created (or splices its
override back out of one it edited). This leg now asserts the frozen install
succeeds directly, with no workaround.

### 2. `gem` — vendoring the platform-qualified purl was unsupported (CLI) — FIXED

`scan --mode vendored` resolved and downloaded the activestorage patch, but the
vendor backend refused the platform-qualified purl
(`pkg:gem/activestorage@…?platform=ruby` — the spelling production publishes)
with `platform_gem_unsupported`, so `summary.applied == 0`, `failed == 1`, and
the run exited non-zero with `"status": "partial_failure"`.

**Fixed** (PR #172): the gate in `vendor/gem.rs` now refuses only non-empty,
non-`ruby` platform qualifiers — `?platform=ruby` is the portable default and
vendors like a bare purl. The suite's original pin
(`activestorage@7.0.2.2` / `2535d43d-67ce-4944-be27-c19e113997fb`) was
withdrawn on 2026-08-14; the 2026-08-18 catalog republish REPLACED it, and the
suite was re-pinned to `activestorage@6.0.3` /
`15e960b5-f432-4b6c-b8aa-534a2b419323`. The vendor succeeds live and the leg
was upgraded to the full fresh-dir `bundle install` delivery proof
(`gem_bundler_vendored_install_proof`), retiring its failure-tolerance branch
and its `SOCKET_PATCH_VENDORED_E2E_GEM_STRICT` knob.

### 3. `gem` — the served gem-stub gemspec is invalid (SERVER; CLI mitigated)

Discovered 2026-08-19 while upgrading the gem leg to a full delivery proof:
the gem-stub-gemspec artifact production serves is invalid — it is missing
`summary`/`authors`, which rubygems validation requires — so writing it
verbatim makes bundler reject the vendored `path:` source and
`bundle install` exit 1 on every bundler major.

**Mitigated CLI-side**: the gem vendor backend now validates the served stub
(conservative textual check for the required assignment lines).
`--vendor-source auto` detects the defect, warns
(`vendor_prebuilt_stub_invalid`), and falls back to the local build — which is
how `gem_bundler_vendored_install_proof` passes against production today —
while explicit `--vendor-source service` refuses with
`vendor_prebuilt_stub_invalid`. The server-side stub-generator fix plus the
rebuild of all published gem artifacts are tracked in depscan; once deployed,
the same leg exercises the service artifact directly.

## Running

```sh
# everything, soft-skipping legs whose toolchain is absent
cargo test -p socket-patch-cli --test e2e_vendored_production -- --ignored --test-threads=1

# CI: turn every "toolchain missing" soft-skip into a hard failure
SOCKET_PATCH_VENDORED_E2E_STRICT=1 \
  cargo test -p socket-patch-cli --test e2e_vendored_production -- --ignored --test-threads=1
```

The suite is `#[ignore]`-gated, so it stays out of the `test` and `e2e` jobs and
runs only where it is explicitly asked for. `--test-threads=1` keeps the real
installs from contending on the shared cache sandbox.

### Environment knobs

| Variable | Effect |
|----------|--------|
| `SOCKET_PATCH_VENDORED_E2E_STRICT=1` | Turn every "toolchain missing" soft-skip into a hard failure. |
| `SOCKET_PATCH_VENDORED_E2E_CANARY_STRICT=1` | Fail when maven/nuget/composer gain their first free published patch. |

The suite forces `SOCKET_NO_CONFIG=true` and scrubs every ambient `SOCKET_*`
var, planting hostile seeds so a dropped scrub reddens the suite instead of
letting a developer's socket-cli login move the run onto the org catalog. No API
token is used.

### Toolchains

`npm`, `pnpm`, `corepack` (yarn classic + berry), `bun`, `uv`, `python3` (pip),
`cargo`, `ruby` + `bundle`, `go`.

### Network egress

`patches-api.socket.dev`, `patch.socket.dev`, `registry.npmjs.org`, `pypi.org`,
`files.pythonhosted.org`, `static.crates.io`, `index.crates.io`,
`rubygems.org`.
