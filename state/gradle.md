[agent] Progress ledger for the scheduled Gradle bug-hunt routine (label pm:gradle).

Last updated: 2026-09-30 (run 1), main `f6b7fb9`, latest release v4.0.0 (the Gradle snippet first shipped in v4.0.0).

## Coverage matrix

Hosted cells: the real CLI prints the snippet against a local mock API, it's pasted verbatim into a real Gradle build, and a `file://` repo stands in for patch.socket.dev.

| OS | Gradle (JDK) | Discovery (scan, gradle-only) | Agent apply | Hosted Groovy, direct | Hosted Groovy, + transitive base | Hosted Kotlin DSL | Vendored refusal | Locking / verification-metadata | Version catalog |
|---|---|---|---|---|---|---|---|---|---|
| Linux | 6.9.4 (11) | fail #349 | fail #349 | pass | fail #347 | fail #348 | untested | untested | untested |
| Linux | 7.6.6 (17) | fail #349 | fail #349 | pass | fail #347 | fail #348 | untested | untested | untested |
| Linux | 8.14.3 (21) | fail #349 | fail #349 | pass | fail #347 | fail #348 | blocked (#349 / mock) | untested | untested |
| Linux | 9.8.0 (21) | fail #349 | fail #349 | pass | fail #347 | fail #348 | untested | untested | untested |
| macOS | any | untested (OS-independent) | untested | untested | untested (OS-independent) | untested (OS-independent) | untested | untested | untested |
| Windows | any | untested (OS-independent) | untested | untested | untested (OS-independent) | untested (OS-independent) | untested | untested | untested |

## Backlog
1. `vendor_gradle_unsupported`: fires on gradle-only and not on mixed pom + Gradle (mock with `--vendor-source build` + `blobContent`).
2. Snippet with `verification-metadata.xml` and `gradle.lockfile` (strict / lenient). Loud vs silent.
3. Version catalogs, `settings.gradle` `dependencyResolutionManagement` + `FAIL_ON_PROJECT_REPOS`, and multi-project builds.
4. Mixed pom.xml + build.gradle: pom edit + snippet together, VEX attestation.
5. Agent `--global-prefix` on the Gradle cache (the `<sha1>` directory layout), and Windows `GRADLE_USER_HOME` with spaces (probe branch).

## Known non-bugs
- The sandbox can't reach `patches-api.socket.dev` / `api.socket.dev`. Use a local mock API (`--api-url … --org test-org --api-token fake`).
- Gradle build scripts are never edited in hosted mode; the snippet is the documented path.
- Vendoring a gradle-only project is refused (`vendor_gradle_unsupported`). Documented.
- Maven Central HTTP 429 during rapid Gradle matrix runs is rate limiting. Rerun slowly.
- A mock vendored run ending in `no_local_source` is a mock artifact.
