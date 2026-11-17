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
| Catalog canaries | Cargo, NuGet, and Composer: detect when a free fixture becomes available; do not prove an install |
| Go | pgx/v5 v5.7.0: get and scan, decoder regression, fresh-cache readonly build; requires the `/v5` hosted artifact |
| Maven | jackson-databind 2.7.9.2: a fresh checkout's Maven build downloads the patched jar from the Socket repository, a JVM loads the patched class, the drop-in check, `rollback` and `remove` ([details](#maven)) |
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

The canary never fails a run: it prints a `NOTE` line naming the ecosystem and the
patch (it fails only under `SOCKET_PATCH_HOSTED_E2E_CANARY_STRICT=1`, which no
workflow sets). Maven's first free patch was reported that way from 2026-10-23
until its legs were added on 2026-11-17.

## vlt: the serve-encoding gate

vlt verifies the raw response body, so a content-encoded artifact fails
`EINTEGRITY` at install time. The patch server sends archives with
`Cache-Control: no-transform`, and the hosted CLI pins them without downloading
them. The production leg asserts the pin and the full fresh-checkout `vlt ci`
proof. The [serve watchdog](../../.github/workflows/vlt-serve-watchdog.yml)
monitors the server's encoding.
The [vlt guide](vlt-compatibility.md) defines the required leg reporting.

## Maven

Production has published one free Maven patch since 2026-10-23:
`pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.7.9.2`
(GHSA-qr7j-h6gg-jmgc / CVE-2018-11307), which replaces one class. One fixture,
[`maven_production/mod.rs`](../../crates/socket-patch-cli/tests/maven_production/mod.rs),
covers all three modes: hosted in this suite, vendored and agent in the
[vendored suite](vendored-production-e2e.md). Each leg:

1. Builds a project that depends on the package with real Maven from Maven Central,
   and runs the project's own class on the classpath Maven resolved: the class is
   the upstream one and the fix is absent.
2. Applies the patch with `get <uuid> --mode <mode>` and builds again: hosted and
   vendored from a fresh checkout of the committable files (vendored with `mvn -o`),
   agent with `mvn -C -U`. Maven must resolve the same artifacts as before, byte for
   byte, except the patched jar. That jar must differ from the original only in the
   members the patch record names, each matching the record's `afterHash`. The JVM
   must load the patched class from it, with the fix active.
3. Runs the drop-in check below.
4. Undoes with `rollback`, applies again with `scan --package`, and undoes with
   `remove`. Each undo must restore every file byte for byte, and Maven must resolve
   the original artifacts again. In agent mode that covers the cached jar and its
   `.sha1`; the project keeps an empty manifest and the backup of the original jar.

`get` pins the patch by UUID, so a patch published later for the same release does
not change what step 2 applies. `scan` in step 4 selects for itself; if it picks a
different patch, the leg prints a `NOTE` and holds the undo to the same standard.

### The drop-in check

A patched jar must work wherever the jar it replaces worked. On each JDK the run
provides, the leg loads and links every class of the original jar and of the
applied jar beside the same dependency jars
([`DropIn.java`](../../crates/socket-patch-cli/tests/maven_production/DropIn.java),
compiled by that JDK itself) and requires identical results: the same classes
link, the same ones fail with the same error, and each replaced class initializes
and keeps its public and protected members. Each replaced class must also keep
the class-file version of the class it replaces (50, Java 6, for this patch).

`SOCKET_PATCH_MAVEN_E2E_JAVA` lists the Java feature releases the check must run
on. Each is read from `JAVA_HOME_<n>_<arch>`, and a missing one fails the leg. When
it is unset, the check runs on every `JAVA_HOME_<n>_<arch>` in the environment,
`JAVA_HOME` and the JDK Maven runs on.

CI runs the check on Java 8, 11, 17, 21 and 25, the JDKs of GitHub's Ubuntu 24.04
runner image (`actions/setup-java` installs any the runner lacks). Java 8 is the
oldest runtime CI has: no `setup-java` distribution offers Java 6 or 7 for Linux
x64. In CI the Java 6 level of this jar is therefore checked by class-file version,
not by running on Java 6. To run on an older runtime, point `JAVA_HOME_6_X64` at a
Java 6 JDK (any directory with `bin/java` and `bin/javac`) and add `6` to the list.

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
| `SOCKET_PATCH_MAVEN_E2E_MVN` / `SOCKET_PATCH_MAVEN_E2E_VERSION` | Select the Maven launcher (default `mvn` on `PATH`) and the version it must report |
| `SOCKET_PATCH_MAVEN_E2E_JAVA` | Java feature releases the Maven [drop-in check](#the-drop-in-check) must run on, e.g. `8,11,17,21,25` |

Tools include npm, Corepack for pnpm/Yarn, Bun, uv, Go, Ruby/Bundler, and Maven
with a JDK. The gem proof requires Bundler 2.6+ for lockfile checksums. vlt
requires its configured Node runtime and executable. The workflow pins and
provisions CI versions. Network access includes Socket's public API and patch
server, npm, PyPI, RubyGems, and Maven Central.

## CI and service outages

The [`hosted-e2e` job](../../.github/workflows/ci.yml) runs independently of the
other test jobs and retries production failures up to three times. It also runs
the vendored vlt production proof, validates vlt leg output, and runs the Maven
vendored and agent legs. Branch protection settings are configured separately
from the workflow.

The job runs on every push to `main`, on pull requests that are not drafts, in the
merge queue, nightly, and on manual dispatch (unless the dispatch selects only
Windows or macOS). It installs every toolchain and sets the strict flags, so a
missing tool or an unreachable upstream registry (npm, PyPI, RubyGems, Maven
Central) fails the attempt instead of skipping the leg.

During a production outage, maintainers can set the repository Actions variable
`HOSTED_E2E_DISABLED` to exactly `true`, then rerun affected jobs. The steps report
**BYPASSED** in the job summary; that successful job is not test evidence. Delete
the variable to restore coverage. Manual workflow dispatch accepts `hosted_e2e`
values `force` (ignore the variable) or `skip` (bypass that run).
