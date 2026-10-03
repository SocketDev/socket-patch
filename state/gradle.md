[agent] Progress ledger for the scheduled Gradle bug-hunt routine (label pm:gradle).

Last updated: 2026-10-03 (run 12), main `045d7ec` (no Gradle/JVM code changes since `2463257` / #277), latest release v4.0.0. #551 and #349 were re-confirmed on `045d7ec` in run 10. Run 8 filed #551, run 9 filed nothing, run 10 filed #620, run 11 filed #656 and commented on #511, and run 12 commented on #620.

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

**Vendored, run 5 cells (Linux).**

| Gradle (JDK) | `.module` artifact (jackson-core) | Version catalog | Kotlin settings + `includeBuild("build-logic")` | Subproject buildscript classpath | `apply from:` script with exclusiveContent | verify-signatures, pgp-only chain entry | verify-signatures, trusted-keys only | Isolated projects |
|---|---|---|---|---|---|---|---|---|
| 8.14.3 (21) | pass | pass | pass | pass | fail #461 | **fail #487** | pass | untested |
| 9.8.0 (21) | untested | untested | untested | untested | untested | **fail #487** | untested | pass |
| 6.9.4 / 7.6.6, macOS, Windows | untested | untested | untested | untested | untested | untested | untested | untested |

**Vendored, run 6 cells (Linux).**

| Gradle (JDK) | Range `[1.9,1.10.0]` | Rich `strictly` range + `prefer` | Strict exact `1.10.0!!` | `1.+` / `latest.release` | `vendor --check` on pgp verification-metadata | `vendor --revert` on pgp verification-metadata |
|---|---|---|---|---|---|---|
| 8.14.3 (21) | **fail #511** | **fail #511** | pass | unaffected | passes on a broken tree (#487) | pass |
| 9.8.0 (21) | **fail #511** | **fail #511** | untested | untested | untested | untested |
| 6.9.4 / 7.6.6, macOS, Windows | untested | untested | untested | untested | untested | untested |

**Hosted snippet vs settings `dependencyResolutionManagement` (run 6, Linux, 8.14.3 / 9.8.0).** Pasted in `build.gradle` under FAIL_ON_PROJECT_REPOS / PREFER_SETTINGS / PREFER_PROJECT: loud failure in each mode (fail-closed). Wrapped inside settings DRM `repositories`: pass.

**Vendored, run 7 cells (Linux).**

| Gradle (JDK) | `:tests` classifier dep | Kotlin `classifier =` | IDE sources query | Catalog `require` range | Range + gradle.lockfile |
|---|---|---|---|---|---|
| 8.14.3 (21) | **fail #533** | untested | **fail #533** | **fail #511** | pass (lock masks it) |
| 9.8.0 (21) | **fail #533** | **fail #533** | untested | untested | untested |
| 6.9.4 / 7.6.6, macOS, Windows | untested | untested | untested | untested | untested |

**Vendored vs corporate init scripts, run 9 (Linux, 8.14.3, fresh clone).**
- Gradle-docs enterprise-repository plugin (removes non-mirror repos): pass (fail-closed, exclusivity survives the removal).
- `afterEvaluate { repositories.clear() }`: pass (fail-closed). `repositories.clear()` before the build script: pass (patched).
- Repositories only from init.d (`allprojects`, `settingsEvaluated` / `beforeSettings` → settings DRM): pass (patched).
- Gradle 6 / 7 / 9, macOS, Windows: untested.

**Vendored, run 10 cells (Linux).**
- `.gitignore` with `*.jar` (github Java template), then vendor, commit, fresh clone: **fail #620** on 8.14.3 (Groovy) and 9.8.0 (Kotlin). vendor and `--check` exit 0, the jar is never committed, and the fresh build fails loudly. In the fresh clone, `--check` and `vex` correctly refuse.
- Init-script cells (`repositories.clear()` before / `afterEvaluate`, enterprise plugin) on 9.8.0: pass, the same as 8.14.3.
- A project path with a space, unicode, `%41` and `#`, on 8.14.3 and 9.8.0: pass.
- Gradle 6 / 7, macOS, Windows: untested.

**Vendored, run 11 cells (Linux).**
- A stray `.DS_Store` in the vendored version directory: **fail #656** on 8.14.3 (Groovy) and 9.8.0 (Kotlin). The build fails, and `vendor` / `repair` report success without removing the file.
- The vendored jar deleted, then `vendor` re-run: pass (`rebuilt`).
- A transitive range from a dependency's POM: **fail #511** on 8.14.3 (downgrades to 1.9).
- macOS / Windows, Gradle 6 / 7: untested.

**Vendored, run 12 cells (Linux).**
- `.gitignore` with `vendor/`: **fail #620** on 8.14.3. The whole `.socket/vendor/` tree, including the index, is never committed, and vendor and `--check` exit 0.
- Android Studio template with catalog `alias(...)` plugin ids: the `android_or_kmp` refusal doesn't fire (vendor exits 0). The build is untested because dl.google.com is blocked. KMP wizard-style (`jvm()`) with catalog aliases: vendor exits 0, and the fresh build is patched (pass).
- 9.8.0: Kotlin settings + catalog + `pluginManagement { includeBuild("build-logic") }` + subproject buildscript classpath, fresh clone: pass (all three classpaths patched). `vendor --revert`: byte-exact (pass).
- macOS / Windows, Gradle 6 / 7: untested.

**Agent mode, run 8 (Linux, 8.14.3).**
- Gradle-only project (`mavenCentral()`) with the same GAV in `~/.m2`: `apply` patches m2, `vex` says `not_affected`, and the build uses the unpatched cache jar. **fail #551**.
- The same with `mavenLocal()` first (+ `-Dmaven.repo.local`): pass (control).
- Re-confirmed on `bf0e0d1` (run 9), after #486's shared-store refusal: still **fail #551**.
- `apply --global-prefix …/modules-2/files-2.1`: loud `package_not_installed`, exit 1 (pass, fail-loud; #349 layout gap).
- macOS / Windows, Gradle 6 / 7 / 9: untested.

**Global (`-g`), Linux, 8.14.3 cache.**
- `scan -g` report: fail. No Gradle-cached purls (#349 comment).
- `scan -g --mode hosted` / `--global-prefix --mode hosted` refusal: pass (exit 2, no writes).
- `-g` apply / rollback / vex: blocked (nothing discovered).
- `-g` commands run inside a vendored Gradle project leave the project byte-unchanged (pass, run 5, after #446).
- macOS / Windows: untested.

## Backlog
1. **Android catalog-alias template** on a GitHub ubuntu runner (it has the SDK). Vendor bypasses `android_or_kmp` there (run 12). Build it and file only if AGP fails or resolves the unpatched jar.
2. **Maintainer request (partly done):** global `-g` mode. Linux is covered (the report, the refusal, no project leakage, and `--global-prefix` apply failing loudly). Still to do: macOS / Windows, and `apply -g` / `rollback -g` / `vex -g` with the GAV in `~/.m2` (see the 20261001T040000Z entry).
3. #487, #511, #533, #620 and #656 on Gradle 6.9.4 / 7.6.6 (a JDK 11/17 probe), plus `verify-signatures` with `.module` artifacts and imported BOMs.
4. The `.module` artifact (jackson-core) cell on 9.8.0. It needs a second patch fixture.
5. #511 with catalog `strictly` / `prefer`.
6. The hosted snippet in its suffixed form, with the dependency bumped and then `vendor`. Check the result and VEX. Also the hosted snippet plus a classifier dependency (the hosted analogue of #533).
7. Agent `apply` + `vex` when `GRADLE_USER_HOME` and `~/.m2` hold different versions (a #551 variant).
8. Re-test #347, #348, #349, #395, #396, #428, #429, #461, #487, #511, #533, #551, #620 and #656 when `vendor/jvm/`, `maven_crawler.rs` or `gradle_snippet` change.

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
- A UTF-8 BOM in a Groovy `settings.gradle` is rejected by Gradle itself; it isn't a valid fixture.
- `vex -g` attests the cwd project's vendored or hosted state by design (`vex.rs:1013`).
- Agent-mode Maven patches whole jar files. A manifest keyed by a jar *member* (the vendored fixture format) fails `apply` with "File not found", which is a fixture error.
- Under isolated projects, harness init scripts must avoid `allprojects`; the vendored script itself is IP-compatible on 9.8.0.
- The hosted snippet pasted into `build.gradle` of a settings-DRM build fails loudly in every `repositoriesMode`. It works when wrapped inside `dependencyResolutionManagement { repositories { … } }`. That's placement, not a silent bypass.
- `1.+` / `latest.release` declarations resolve the newest release before and after vendoring, so a base-version patch correctly doesn't apply. That isn't #511.
- `vendor --revert` is byte-exact on a verification-metadata file with pgp entries (run 6).
- A `mvn`-seeded `file://` m2 has no `maven-metadata.xml`, so range or dynamic-version cells fail before vendoring too. Use real Central for those.
- A `gradle.lockfile` written before vendoring masks #511: the range resolves to the locked, vendored version (run 7).
- Gradle's `mavenLocal()` ignores the `MAVEN_REPO_LOCAL` env var. It uses `-Dmaven.repo.local` or settings.xml, so a harness must pass the system property (run 8).
- A repository-stripping corporate init script (the Gradle-docs enterprise plugin, or `repositories.clear()`) doesn't make vendored Gradle fail open. Gradle keeps the exclusiveContent exclusivity after the vendored repository is removed, so the build fails loudly (run 9).
- In init scripts, compare repository URLs via `File.toURI()`, not `file://` strings: Gradle normalizes `file:///x` to `file:/x/` (run 9 harness note).
- Gradle can throw `InvalidPathException` on non-ASCII project paths in the sandbox because there's no UTF-8 locale. Export `LC_ALL=C.UTF-8` (run 10).
- `gradle::wired()` accepts the apply line in either `settings.gradle` or `settings.gradle.kts`. Gradle reads the Groovy file when both exist, and the planner targets it too, so a mismatch only happens if someone hand-moves the line. That's contrived, so it hasn't been filed (run 10).
- Kotlin DSL harness note: inside `build.gradle.kts` with the `java` plugin applied, `java.util.…` resolves `java` to the extension. Use a top-level `import` (run 11).
- A vendored Gradle build failing on a *missing* vendored file is healed by re-running `vendor` (`rebuilt`). Only *extra* files hit #656 (run 11).
- `android_or_kmp` only matches literal plugin ids (`gradle.rs:1043`), so catalog `alias(...)` builds aren't refused. On a KMP `jvm()` build the vendored jar is correctly on the classpath, so that's not filed unless an Android build shows harm (run 12).
- Precompiled `build-logic` `*.gradle.kts` scripts hit the same `java.` extension shadowing as build scripts. Use top-level imports (run 12).
