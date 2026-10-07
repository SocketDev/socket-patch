# Testing

Tests should establish that a package manager consumes the intended patched bytes,
that VEX describes the resulting state, and that reruns and reversal preserve
unrelated project data. See [development](../development.md#validation) for basic
Rust and Python checks.

## Test layers

| Layer | Location / entry point | Purpose |
| --- | --- | --- |
| Core unit tests and fixtures | `cargo test --locked -p socket-patch-core --lib`; core `tests/fixtures/` | Parsers, rewrites, integrity checks, and refusal cases |
| CLI parser and in-process tests | `crates/socket-patch-cli/tests/cli_parse_*.rs`, `in_process_*`, command suites | Flags, defaults, output, lifecycle, and failures |
| Native package-manager suites | CLI `e2e_redirect_*_build`, `e2e_vendor_*_build`, and VEX suites | Real installs against controlled patch inputs |
| Production suites | [Hosted](hosted-production-e2e.md), [vendored](vendored-production-e2e.md) | Real patch-service responses and artifact delivery |
| Release compatibility backtests | Package-manager guides below and `scripts/backtest-*.py` | Format and installer boundaries across published releases |
| Container suites | [Docker guide](../../tests/docker/README.md) | Toolchain isolation and offline installs |
| Performance benchmarks | [`crates/socket-patch-bench`](../../crates/socket-patch-bench/README.md), `.github/workflows/bench.yml` | `scan` timings, memory and API request counts per package manager, compared against the base on every PR |

Native suites require the tools named in their guide. Opt-in or unavailable-toolchain
skips are not installation evidence. Use the suite's `*_REQUIRED` or `*_STRICT`
setting when that toolchain is required for the check.

## Package-manager guides

| Ecosystem | Guides |
| --- | --- |
| npm family | [npm](npm-compatibility.md), [pnpm](pnpm-compatibility.md), [Yarn Berry](yarn-berry-compatibility.md), [Bun](bun-compatibility.md), [vlt](vlt-compatibility.md) |
| Python | [uv](uv-compatibility.md), [Poetry](poetry-compatibility.md), [PDM](pdm-compatibility.md), [Pipenv](pipenv-compatibility.md), [Hatch](hatch.md) |
| PHP | [Composer](composer-compatibility.md) |
| JVM | [Maven reactor and Gradle vendoring](../design/maven-vendoring.md#validation-and-remaining-scope), [Gradle in every mode](#gradle), [sbt, Mill and scala-cli](sbt-compatibility.md) |

Other ecosystems have Rust and container suites listed in
[ecosystem support](../ecosystems.md) and the Docker guide.

## Gradle

Four suites run real Gradle, selected by test-name prefix
(`scripts/ci-e2e-bundle.py --check` keeps each prefix in its suite):

| Mode | Suites | `--ignored` filter |
| --- | --- | --- |
| agent | `e2e_gradle_discovery_build`, `e2e_gradle_agent_build` | `gradle_agent_` |
| hosted | `e2e_redirect_gradle_build` | `gradle_hosted_` |
| vendored | `e2e_vendor_gradle_build`, `e2e_vendor_jvm_build` | `gradle_vendor_`, `gradle_multi_project` |

Hermetic CLI suites (`gradle_agent_cli`, `vendor_jvm_cli`, the hosted planner's core
unit tests) cover the same rules without Gradle and run in every PR. Most real-Gradle
tests resolve against a local fake Maven Central (`tests/jvm_fixture_repo`) and a
fake hosted registry; the multi-project vendored capstone and the real-Central rows
reach Maven Central.
`gradle_vendor_395` also needs Maven; nothing else does.

**Matrix.**

| Tier | Where | Cells |
| --- | --- | --- |
| PR | `ci.yml` `e2e` job | ubuntu × {6.9.4 / JDK 11, 7.6.6 / JDK 17, 8.14.3 / JDK 21, 9.8.0 / JDK 21} × {agent + hosted, vendored + multi-project}, plus Windows 8.14.3 multi-project |
| Full | [`gradle-compatibility.yml`](../../.github/workflows/gradle-compatibility.yml) (path-filtered PRs, nightly, manual) | {ubuntu, macOS arm64, Windows} × the four lines × {agent, hosted, vendored} = 36 cells; JDK ceilings (6.9 on 15, 7.6 on 19, 8.14 on 24); `--configuration-cache` (9.8.0 hosted and vendored); Isolated Projects (9.8.0 hosted, recording only); real Maven Central (8.14.3, #511 and #487) |

Every full-tier cell uploads JSON probe reports (Gradle and JDK version, resolved jar
path and sha256, hash-directory naming, refresh, read-only cache and transform-cache
canaries) as `gradle-probe-*` artifacts.

**Local runs.** The suites drive the Gradle named by these variables:

| Variable | Meaning |
| --- | --- |
| `SOCKET_PATCH_GRADLE_E2E_GRADLE` | Gradle launcher (default `gradle` on `PATH`) |
| `SOCKET_PATCH_GRADLE_E2E_VERSION` | The version the launcher must report |
| `SOCKET_PATCH_GRADLE_E2E_REQUIRED` | `1`: fail instead of skipping when Gradle is missing |
| `SOCKET_PATCH_GRADLE_E2E_ARGS` | Extra Gradle arguments for every run, e.g. `--configuration-cache` |
| `SOCKET_PATCH_GRADLE_E2E_REAL_CENTRAL` | `1`: the real-Central variants mirror to Maven Central |
| `SOCKET_PATCH_MAVEN_E2E_MVN` | Maven launcher for `gradle_vendor_395` |

Use a JDK the Gradle line supports: 11 for 6.9.4, 17 for 7.6.6, 21 for 8.14.3 and
9.8.0. Point `JAVA_HOME` at it. Each run gets its own Gradle user home and no daemon,
so your own `~/.gradle` is never read or written. For example:

```sh
cargo test -p socket-patch-cli --test e2e_redirect_gradle_build --no-run
JAVA_HOME=/path/to/jdk-17 \
SOCKET_PATCH_GRADLE_E2E_GRADLE=/path/to/gradle-7.6.6/bin/gradle \
SOCKET_PATCH_GRADLE_E2E_VERSION=7.6.6 SOCKET_PATCH_GRADLE_E2E_REQUIRED=1 \
  cargo test -p socket-patch-cli --test e2e_redirect_gradle_build -- --ignored gradle_hosted_
```

Gradle runs are memory- and disk-heavy. When several worktrees test on one machine,
give each its own target directory (never share `CARGO_TARGET_DIR` between
worktrees) and run the real-Gradle suites one at a time behind a shared lock file.

## CI and results

[CI](../../.github/workflows/ci.yml) separates normal PR coverage from broader
release, main-branch, nightly, and manual matrices. Package-manager compatibility
workflows define additional matrices. Read the workflow for the authoritative
versions, triggers, required flags, and artifact names.

The vlt [compatibility tables](vlt-compatibility.md) define a generated leg manifest;
[`vlt-coverage.json`](vlt-coverage.json) maps diagnostics to tests. These are
executable specifications and are checked by `scripts/tests/`, not historical
reports.

Backtest runners write JSON results and can render summary tables. Keep each run's
results, binary versions, source revision, and logs together in CI artifacts or a
local output directory. Update the maintained compatibility boundaries when new
evidence changes them. A past successful run or catalog snapshot is not a claim
that the current branch or production service passes today.
