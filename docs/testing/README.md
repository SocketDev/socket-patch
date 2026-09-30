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

Native suites require the tools named in their guide. Opt-in or unavailable-toolchain
skips are not installation evidence. Use the suite's `*_REQUIRED` or `*_STRICT`
setting when that toolchain is required for the check.

## Package-manager guides

| Ecosystem | Guides |
| --- | --- |
| npm family | [npm](npm-compatibility.md), [pnpm](pnpm-compatibility.md), [Yarn Berry](yarn-berry-compatibility.md), [Bun](bun-compatibility.md), [vlt](vlt-compatibility.md) |
| Python | [uv](uv-compatibility.md), [Poetry](poetry-compatibility.md), [PDM](pdm-compatibility.md), [Pipenv](pipenv-compatibility.md), [Hatch](hatch.md) |
| PHP | [Composer](composer-compatibility.md) |
| JVM | [Maven reactor and Gradle vendoring](../design/maven-vendoring.md#validation-and-remaining-scope) |

Other ecosystems have Rust and container suites listed in
[ecosystem support](../ecosystems.md) and the Docker guide.

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
