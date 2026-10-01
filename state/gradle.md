[agent] Progress ledger for the scheduled Gradle bug-hunt routine (label pm:gradle).

Last updated: 2026-10-01 (run 4), main `2463257` (#277, v5: Gradle 6.8+ vendoring backend), latest release v4.0.0.

## Coverage matrix

**Hosted (manual snippet).** The real CLI prints the snippet against a mock API, and it's pasted into a real build. These cells are from runs 1–2. `gradle_snippet` is unchanged on `2463257`.

| OS | Gradle (JDK) | Discovery (scan) | Agent apply | Hosted Groovy direct | Hosted + transitive base | Hosted Kotlin DSL | Hosted + gradle.lockfile | Hosted + verification-metadata | Hosted + version catalog |
|---|---|---|---|---|---|---|---|---|---|
| Linux | 6.9.4 (11) | fail #349 | fail #349 | pass | fail #347 | fail #348 | fail #396 | untested | untested |
| Linux | 7.6.6 (17) | fail #349 | fail #349 | pass | fail #347 | fail #348 | fail #396 | untested | untested |
| Linux | 8.14.3 (21) | fail #349 | fail #349 | pass | fail #347 | fail #348 | fail #396 | pass (loud failure) | pass |
| Linux | 9.8.0 (21) | fail #349 | fail #349 | pass | fail #347 | fail #348 | fail #396 | untested | pass |
| macOS | 6.9.4 / 7.6.6 / 8.14.3 / 9.8.0 | untested (OS-independent) | untested | pass (probe) | untested | untested | fail #396 | untested | untested |
| Windows | 6.9.4 / 7.6.6 / 8.14.3 / 9.8.0 | untested (OS-independent) | untested | pass (probe) | untested | untested | fail #396 | untested | untested |

**Vendored (v5 Gradle backend, new in `2463257`).** "Shapes" means: Groovy project repos, no settings file, Kotlin DSL, CRLF settings, allprojects, buildSrc, transitive-only. Probes: runs 36821273765 and 36821988108. Run 4 used Linux only.

| OS | Gradle (JDK) | Shapes → patched fresh-checkout build | Lock STRICT + verification-metadata | Config cache + tamper | Revert / remove / rollback (LF checkout) | `vendor --check` on a git checkout | Vendor from a subproject | Mixed pom + gradle | Two patches, drop one | User exclusiveContent in a subproject / buildSrc (incl. pasted hosted snippet) |
|---|---|---|---|---|---|---|---|---|---|---|
| Linux | 6.9.4 (11) | pass (probe) | untested (repo CI capstone) | untested | pass (probe) | pass | untested (path-only, expect #428) | fail #395 | untested | untested |
| Linux | 7.6.6 (17) | pass (probe) | untested (repo CI capstone) | untested | pass (probe) | pass | untested | fail #395 | untested | untested |
| Linux | 8.14.3 (21) | pass | pass | pass | pass | pass; autocrlf=true clone fails #429 | fail #428 | fail #395 | pass | fail #461 |
| Linux | 9.8.0 (21) | pass (local + probe) | pass | pass | pass | pass | fail #428 | fail #395 | untested | fail #461 |
| macOS | 6.9.4 / 7.6.6 / 9.8.0 | pass (probe) | untested | untested | pass (probe) | pass | untested | untested | untested | untested (static planner) |
| Windows | 6.9.4 / 7.6.6 / 9.8.0 | pass (probe: s1, s9, s12, s14) | untested | untested | fail #429 (script left behind) | **fail #429** | untested | untested | untested | untested (static planner) |

**Global (`-g`), Linux, 8.14.3 cache.**
- `scan -g` report: fail. No Gradle-cached purls (#349 comment).
- `scan -g --mode hosted` / `--global-prefix --mode hosted` refusal: pass (exit 2, no writes).
- `-g` apply / rollback / vex: blocked (nothing discovered).
- macOS / Windows: untested.

## Backlog
1. **Maintainer request (partly done):** global `-g` mode. Linux report and refusal are covered. Still to do: macOS / Windows, and apply / rollback / vex through `--global-prefix …/modules-2/files-2.1` if that's meant to be supported (see the 20261001T040000Z entry).
2. Kotlin `settings.gradle.kts` + `pluginManagement { includeBuild("build-logic") }` convention plugins: is `build-logic` wired, and are its repositories checked (#461)?
3. The hosted snippet in its suffixed form, with the dependency bumped, followed by `vendor`. Check the result and VEX.
4. `apply from: 'gradle/repos.gradle'` script plugins declaring repositories (a likely #461 sibling).
5. `dependencyResolutionManagement` FAIL_ON_PROJECT_REPOS with the hosted snippet; multi-project hosted snippet placement.
6. Re-test #347, #348, #349, #395, #396, #428, #429 and #461 when main moves.

## Known non-bugs
- The sandbox can't reach the Socket API. For vendored, use `prebuilt_common::prepare_command` + a staged manifest/blob (see the run 3 entry). For hosted, use the wiremock shaped like `e2e_redirect_maven_build`.
- `repo.maven.apache.org` 429s in the sandbox. Use an init script that rewrites it to `repo1.maven.org`. JDK 11/17 cells must run on GitHub runners.
- Vendored Gradle: `vendor_jvm_upstream_unavailable` / `verification_metadata_unavailable` 404 from the fixture means the m2 seed is missing (`junit-bom:5.9.0/5.9.1:module`). It's a mock artifact.
- Vendored Gradle intentionally keeps the original GAV, edits only settings files (and buildscript in-block entries), and creates a `settings.gradle` when none exists. All documented.
- A wrapper below 6.8 is refused (`gradle_below_6_8`), as documented. `6.8-rc-*` parses as 6.8 and is caught by the script's runtime check.
- A vendored project under `scan` / `get --mode hosted` keeps its vendored patch (`already`); there's no takeover. That's safe.
- Gradle build scripts are never edited in hosted mode; the snippet is the documented path.
- VEX never attributes Gradle-pasted hosted snippets (README VEX table). A hosted gradle-only `scan --vex` ending in `manifest_not_found` is correct.
- `vex` has no Gradle product auto-detection (pass `--product`, or use the git remote), as documented.
- Snippet + `verification-metadata.xml` fails loudly, which is fail-closed.
- The session's git proxy refuses branch deletes, so probe branches need maintainer cleanup.
- Maven Central (both `repo.maven.apache.org` and `repo1.maven.org`) can 429 Gradle in the sandbox. Point mavenCentral at `file://<seeded m2>` with an init script.
- Dropping one of two vendored Gradle patches (`remove <purl>`, or a manifest edit + re-vendor) keeps the other wired correctly. Verified in run 4.
