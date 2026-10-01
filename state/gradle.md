[agent] Progress ledger for the scheduled Gradle bug-hunt routine (label pm:gradle).

Last updated: 2026-09-30 (run 2), main `f6b7fb9`, latest release v4.0.0 (the Gradle snippet first shipped in v4.0.0).

## Coverage matrix

Hosted cells: the real CLI prints the snippet against a local mock API, it's pasted verbatim into a real Gradle build, and a `file://` repo stands in for patch.socket.dev. Probe run: https://github.com/SocketDev/socket-patch/actions/runs/36791121715

| OS | Gradle (JDK) | Discovery (scan) | Agent apply | Hosted Groovy direct | Hosted + transitive base | Hosted Kotlin DSL | Hosted + gradle.lockfile | Hosted + verification-metadata | Hosted + version catalog | Vendored gradle-only refusal | Vendored mixed pom+gradle |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Linux | 6.9.4 (11) | fail #349 | fail #349 | pass | fail #347 | fail #348 | fail #396 | untested | untested | pass (OS/version-independent) | fail #395 (version-independent) |
| Linux | 7.6.6 (17) | fail #349 | fail #349 | pass | fail #347 | fail #348 | fail #396 | untested | untested | pass | fail #395 |
| Linux | 8.14.3 (21) | fail #349 | fail #349 | pass | fail #347 | fail #348 | fail #396 | pass (loud failure) | pass | pass | fail #395 |
| Linux | 9.8.0 (21) | fail #349 | fail #349 | pass | fail #347 | fail #348 | fail #396 | untested | pass | pass | fail #395 |
| macOS | 6.9.4 / 7.6.6 / 8.14.3 / 9.8.0 | untested (OS-independent) | untested | pass (probe) | untested (OS-independent) | untested (OS-independent) | fail #396 | untested | untested | untested | untested |
| Windows | 6.9.4 / 7.6.6 / 8.14.3 / 9.8.0 | untested (OS-independent) | untested | pass (probe) | untested (OS-independent) | untested (OS-independent) | fail #396 | untested | untested | untested | untested |

## Backlog
1. **Maintainer request:** test global (`-g`) mode for hosted patches on Linux, macOS and Windows across every major Gradle version. `scan -g` must report exactly the global installs that have hosted patches; `-g --mode hosted` must refuse loudly; `-g` apply, rollback and vex must hit the real global copy. Full checklist in the 20261001T040000Z entry on this discussion.
2. `dependencyResolutionManagement` with `FAIL_ON_PROJECT_REPOS` / `PREFER_SETTINGS`: snippet placement, loud vs silent.
3. Multi-project builds (snippet in a subproject vs root, `allprojects {}`).
4. Kotlin DSL combined with locking and catalogs.
5. Agent mode on the Gradle cache `<sha1>` layout via `--global-prefix` (blocked by #349), and Windows `GRADLE_USER_HOME` with spaces.
6. `release/v5-prerelease` Gradle vendoring (#287) once it lands on main.

## Known non-bugs
- The sandbox can't reach `patches-api.socket.dev` / `api.socket.dev`. Use a local mock API (`--api-url … --org test-org --api-token fake`). For vendored, key the view by jar member (`META-INF/NOTICE.txt`) with `blobContent`, otherwise the run ends in `no_local_source` / `apply_failed`, which are mock artifacts.
- Gradle build scripts are never edited in hosted mode; the snippet is the documented path.
- Vendoring a gradle-only project is refused (`vendor_gradle_unsupported`). Documented, and verified correct.
- VEX never attributes Gradle-pasted snippets (README VEX table: maven "no Gradle"). A hosted gradle-only `scan --vex` ends in `manifest_not_found`, which is correct: nothing is attested.
- Snippet + `verification-metadata.xml` fails loudly (missing checksum for the suffixed artifact). That's fail-closed, not a silent bypass.
- Maven Central HTTP 429 during rapid Gradle runs is rate limiting. Sandbox curl to Central and Adoptium is blocked (403/429), so use GitHub runners for JDK 11/17.
- The session's git proxy refuses branch deletes (HTTP 403), so probe branches may need maintainer cleanup.
