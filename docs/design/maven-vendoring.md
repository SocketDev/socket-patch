# socket-patch v5: vendored mode for Maven and Gradle

> Target path: `docs/design/maven-vendoring.md`. Status: **REVISED after adversarial review.** This document merges four candidate designs (A–D), three judges and five adversarial reviews.
>
> Evidence labels:
> - **V**: verified with real tools. The source is a design (A–D), a judge (J1–J3), the research corpus, or a reviewer: **M** (Maven empirical), **G** (Gradle empirical), **S** (security), **C** (state/revert/code) or **P** (scope/cost).
> - **R**: verified by the earlier research.
> - **I**: inferred, not yet run. Every I that matters is a Phase-0 or capstone item (§12).
> - **X**: refuted by review. The design has been changed to match.

---

## 1. Status and context

**What ships today** (branch `v5/maven-vendoring`, HEAD 8ae7dc3):
- Vendored Maven works for one single-module `pom.xml`.
- The patched jar keeps its original GAV under `.socket/vendor/maven/<uuid>/`.
- The root pom gets `<repository id="socket-patch-vendor-<uuid>">` at `file://${project.basedir}/…`.
- **No `.mvn/maven.config` is written.**
- CI runs 3.6.3, 3.8.9, 3.9.16 and 4.0.0-rc-6 on Ubuntu, and 3.9.16 on macOS.
- Gradle builds and multi-module reactors are refused.

**Known defects in the current code:**

| # | Defect | Severity | Evidence |
|---|---|---|---|
| 1 | When `state.json` is missing, the orphan sweep deletes a vendored directory that `pom.xml` still references. NuGet has the same bug: `nuget.config` is not in `WIRING_FILES`. | high | V (C); NuGet INFERRED |
| 2 | `repair` does not rebuild Maven ledger entries. This is by design under v5-plan WS5: repair re-downloads, then `vendor` re-wires. | – | V (C) |
| 3 | A cold-cache re-vendor trips `debug_assert!` (`vendor.rs:170-175`). It panics **in debug builds only**; a release build gives `vendor_maven_jar_not_found` for a stale artifact. | low | V (C) |
| 4 | Vendoring from a submodule silently loses to its siblings. | medium | V (C) |
| 5 | A patch update (new uuid) followed by `--revert` leaves the old `socket-patch-vendor-<uuid>` block pointing at a deleted directory. Cause: `carry_forward_wiring` takes the whole-file `original` from the already-wired pom. | medium | V (C) |
| – | Shadowing: a warm `~/.m2` copy of the same GAV beats the vendored jar. Maven 3 then poisons other projects; Maven 4 overwrites the copy. | high | R ×3 |

**What depscan provides:**
- `POST /patches/package` returns `artifacts[0].integrity{sha256,sha512}` and `registryOverride.identifiers{mavenSuffixedVersion, mavenPomSha256}`.
- A hosted maven2 slice (six files at `<v>-socket.<hex8>`) and a direct jar download at the base filename.
- Server jars come from archiver 7.0.1 `repackDirToZip`: stored entries, 1980-01-01 dates, upstream entry order, no directory entries, no extra fields, and `META-INF/*.SF|RSA|DSA|EC` stripped.
- `build_failed` rows, classifier and non-jar artifacts, and mixed-case coordinates are never built.

**Owner constraints:**

| # | Constraint | Where it is met |
|---|---|---|
| 1 | No regression of supported Maven versions or shapes | §2.1, §4, §9. One exposure remains: `-f` from outside the Maven root on 3.9.2–3.9.8 (§4.2). |
| 2 | Reactors and Gradle | §4, §5 |
| 3 | Strong pinning | §6. Gradle layer 1 always runs. Maven relies on `vendor --check` in v5.0; build-time pins are opt-in in v5.x. |
| 4 | Small diff, byte-exact revert | §3, §7 |
| 5 | Low CI friction | §2.1 (pins opt-in), §5.3 |
| 6 | depscan read-only | §11: v5 needs no depscan change |
| 7 | Fewer refusal codes | §8, counted honestly |

**Scope:** jar artifacts without a classifier. Android and Kotlin Multiplatform are refused. Hosted mode is unchanged, except that `vendor` ejects it (WS2).

**Plan conflict.** `docs/design/v5-plan.md` lists "a better vendored Maven story" as "Future work (not v5)… do not invest further now". This document proposes changing that scope. **Owner sign-off (Q0) gates Phase 0.**

---

## 2. Decisions

### 2.1 v5 scope vs later

Review showed that trusted checksums, if on by default, cause new failures:
- the D6 compile crash, including on `${revision}` reactors;
- an NPE on `system`-scope dependencies;
- an NPE that hides every "artifact not found" message on 3.9.0–3.9.9;
- deny failures on common plugin classpaths.

They also enforce nothing on 3.9.2–3.9.3, and only a narrow subset of builds gets a working pin. **v5.0 therefore ships wiring plus offline checks; build-time Maven pins become opt-in in v5.x.**

| Area | **v5.0 (this release)** | **v5.x (opt-in or deferred)** |
|---|---|---|
| Maven identity | SV = `<base>-socket.<hex8>`; `maven2/` tree; byte-identical local rebuild (D7) | — |
| How Maven finds the tree | 2-line `maven.config` (offline protocols and tail); fallback repository per local root; `--maven-config=none` | Q11: carry the tail in `jvm.config` |
| Maven declarations | Local-root pins; rewrites of literals and local `${p}`; un-pin on a conflicting literal; `property_unresolved` and `range` are **warnings** | Maven ranges through GA metadata (Q3) |
| Maven build-time pin | None. `vendor --check` (offline) is the pin on every version. | `--maven-pin=auto\|strict`: trusted checksums (7 lines), deny lines, the D6 unsafe-reactor rule, `--maven-allow-unpatched` |
| Maven 4 implicit subprojects | Not detected (I; release candidate only) | Detected |
| Gradle | Same-GAV tree; static script with the layer-1 self-check; Gradle-only index; apply lines in the root, buildSrc and literal `includeBuild` settings; in-block `pluginManagement` entry for settings plugins | — |
| Gradle verification file | **If one already exists:** replace the hash and add parent-chain components. This is required, because without it the build breaks. | Create a scoped file, behind `--gradle-verification=create`, in canonical form |
| Gradle extras | — | GA-level `maven-metadata.xml` for dynamic versions; vendoring `-sources`/`-javadoc` |
| Checks | `vendor --check`, offline, including `--local-repo` | `--check --online`, `--check --resolve` |
| Version detection | Wrapper `distributionUrl` only | — |
| State | Fragment-only records; peer-aware revert of shared fragments; ecosystem `jvm`; repair = re-download and re-wire | — |
| Migration | Reactors and Gradle go to the new backend. Single-pom projects migrate only once the capstone matrix is green (Phase 4). | — |

### 2.2 Decision record

**D1. Each tool gets its own identity.** Maven uses `SV = <base>-socket.<hex8>`; Gradle keeps the same GAV.
- **Maven:** the same GAV shadows, poisons and overwrites (R ×3). SV sorts above the base and below the next release on 3.6.3–4-rc-7 under both version schemes (V, critic), and it is exactly what the server serves.
- **Gradle:** file repositories are never copied into `modules-2` (R), so the same GAV leaves lockfiles, catalogs, `strictly` and platforms untouched. A `-socket.x` version would also sort **below** the base in Gradle.
- **Rejected:**
  - **B** (`-0.socket` for both): equals the base on 3.6.3, and Gradle needs rewrites.
  - **D** (same GAV on Maven): a warm cache breaks the build again and again.
  - **C** (WorkspaceReader): fails open on 3.6, and is fatal on 3.8–3.9.1 unless the extension is published to Central. Kept as Q7.
- **Correction (M, P):** "SV is unique, so nothing is shadowed" was **X**. SV encodes the patch uuid, not the jar bytes. When one SV has two byte sets, 3.9.x strict fails and 3.8.8 silently uses the other project's bytes (V). D7 now guarantees one SV = one byte sequence.

**D2. Maven finds the tree in two ways that coexist.**
- **3.9.2+ and 4:** `-Dmaven.repo.local.tail=${session.rootDirectory}/.socket/vendor/maven2` in `.mvn/maven.config`. The tail copies nothing into `~/.m2` (V, M, every run), and mirrors do not apply to it.
- **Every version:** a fallback `<repository>` at `file://${maven.multiModuleProjectDirectory}/.socket/vendor/maven2` in each local root. On 3.6.3, 3.8.8 and 3.9.0 it copies SV into `~/.m2` (V, M).
- **Correction (M):** with `${session.rootDirectory}` in `maven.config`, **3.9.2–3.9.8 cannot run `mvn -f <root>/pom.xml` from outside the Maven root.** V: rc=1 on 3.9.2 and 3.9.6–3.9.8; rc=0 on 3.9.1, 3.9.9, 3.9.11 and 4-rc-7. No expression works on both 3.9.2–3.9.8 and 4, because 4 does not interpolate `${maven.multiModuleProjectDirectory}` (R).
- **Decision: keep the tail.** It is the only mechanism that survives `mirrorOf *` and enforcer repository bans on 3.9.2+. In addition:
  - warn `maven_f_outside_root` when the Maven root is not the VCS root and the wrapper does not prove a version outside 3.9.2–3.9.8;
  - offer `--maven-config=none`, recorded in the ledger, which relies on the fallback repository only and is safe because of D7.
- Hosted mode already ships the same lines (§11 #1).

**D3. Pins go into local roots; conflicting declarations are rewritten in place.**
- **Local root:** walk each reactor module's `<parent>` chain while the parent file is in the checkout and its GAV matches. The topmost pom reached is the local root. A `relativePath` that names a directory gets `/pom.xml` appended (V, M).
- **Rewrite scope:** every reactor pom **and every in-checkout pom on any reactor module's parent chain**, profiles included.
  - Correction (M): a middle local parent outside `<modules>` kept its literal management. That beat the root pin: silently on 3.6.3, and as a deny failure on 3.9.11 (V).
- **Pin:** each local root gets a `<dependencyManagement>` entry for SV. Literal and locally resolved `${p}` declarations of the base become the literal SV.
- **Verified on six versions (M):** the local-parent pin beats a module's own imported BOM and covers transitive use, and a remote-parent module's own pin wins.

**D4. Gradle is wired by one owned static settings script.**
- One apply line goes into the root settings file, `buildSrc`, and the settings file of each literal `includeBuild`.
- **When a settings file has settings-level `plugins{}`, it also gets one in-block `pluginManagement.repositories` entry per patched GAV** (§5.1).
- **Correction (G):** a settings plugin whose dependencies include the patched GAV (foojay 0.8.0 → gson 2.10.1) silently unpatched buildSrc, build-logic and root-script classes on 7.6.4 (V). The in-block entry fixed it (V, 7.6.4).
- The main matrix passed 24/24: 2 DSLs × 3 `repositoriesMode` values × 6.9.4, 7.6.4, 8.14.3 and 9.8.0 (V, G).

**D5. The deny line moves to v5.x strict mode, 3.9.4+ only.**
- **What it catches:** missed declarations, and relocations on 3.9.11 and 4 (V, S).
- **Where it breaks builds:** plugin classpaths that project dependency management cannot reach, for example `spotbugs-maven-plugin:4.7.3.6:check` and `dependency:go-offline` (V, M). The only escape, `--maven-allow-unpatched`, drops the guard for the whole purl.
- **What it misses:** graph-only tools such as `dependency:tree` (V, M).
- **In strict mode:** vendor warns about the known plugin failures, and `vendor_jvm_upstream_unavailable` recommends `mvn dependency:resolve`.
- The resolver has no opt-out scoped to a plugin.

**D6. The pin-unsafe reactor rule (v5.x strict only).** The trusted-checksum post-processor has two crashes:
- It fails `compile` and `test` with `IOException: Is a directory` when it hashes a sibling module's `target/classes`. V: D, J1, J2, M, P; it also happens on 3.9.0, which closes Q4.
- It throws `NullPointerException: artifactRepository is null` on any `system`-scope dependency, direct or transitive. V (S): 3.9.6, 3.9.9, 3.9.11 and 4-rc-7.

A reactor is **pin-unsafe** when either condition holds:
- **(a)** both of these are true:
  - a module's effective version does not end in `-SNAPSHOT`, **or contains `${`**. Correction (M, P): `-Drevision=1.2.3 test` crashes a reactor whose version looks like `1-SNAPSHOT` (V).
  - some module has a sibling dependency of type `jar` or `test-jar`, or one with a classifier. Dependencies with `type=pom` or `scope=import`, and plugin `<dependencies>`, do not crash (V, M).
- **(b)** any reactor pom, profiles included, has a `system`-scope dependency.

**Modes:**
- `--maven-pin=auto` falls back to the v5.0 wiring and warns `reactor_release_compile` or `system_scope`.
- `--maven-pin=strict` pins anyway, for teams that only run `package` and later phases.

A transitive `system` dependency cannot be detected statically. It fails closed, and this is documented.

**D7. One SV = one byte sequence.**
- **Server jar first:** the server jar is used whenever the service has built it, and `mavenPomSha256` verifies the pom.
- **Same recipe locally:** the local rebuild reproduces the server recipe from §1: stored entries, 1980-01-01 dates, upstream order, no directory entries, no extra fields. The old Deflate rebuild made byte identity **X** (C, M). A conformance test against server jars (§12.4) keeps this at I until it is green.
- **Which bytes are kept:**
  - `source:"service"` bytes are kept for the life of the uuid.
  - `source:"local"` bytes are **replaced by service bytes** on the first online run where they differ. This one-time change closes the cross-project collision (M, P) and the `--check --online` evasion (S).
- **Rejected:** a per-project repository id (P). It fixes 3.9.11, but 3.8.8 still keeps the other project's bytes (V, P).

**D8. `.socket/vendor/gradle-index.tsv` is a derived index, for Gradle only.**
- **Format:** columns GAV, path, sha256 and uuid; header `#socket-patch-gradle-index 1`; rows sorted; LF line endings.
- **Regeneration:** rebuilt on every run from the ledger and the markers.
- **Maven rows were dropped (P):** the script ignored them, and Maven liveness comes from the ledger, the markers and SV references.

**D9. Gradle integrity.**
- **Layer 1 (always on).** At configuration time the script:
  - streams a sha256 of every index row. Correction (G): `f.bytes` ran out of heap on a 388 MB jar at the default 512 MB heap (V).
  - requires a jar row and a pom row per GAV.
  - fails on any file in a version directory that is not in the index. Correction (S): a deleted row let a foreign jar through (V).
  - rejects version-selector syntax. Correction (S): `includeVersion` treats `+` and `[1,3)` as selectors (V).

  Layer 1 still runs with lenient or off verification (V, G, S) and with `GRADLE_USER_HOME` overrides. A tamper invalidates the configuration cache (V, G: 7.6.4, 8.14.3, 9.8.0).
- **Layer 2, v5.0: update an existing `gradle/verification-metadata.xml`.** Replace the jar hash, and add `<component>` entries for the vendored pom's parent chain and import-scope BOMs.
  - Correction (G): without these entries, every `.module`-publishing dependency failed on all four versions (V). With them, it passed on 8.14.3 (V).
- **Creating a scoped file moves to v5.x** (`--gradle-verification=create`), for three reasons:
  - Renovate rewrites it on every Gradle PR (P, V);
  - it silently cancels out a later adoption of verification (P, S, V);
  - when a settings plugin is missed, it breaks the build in a way that re-vendoring cannot fix (G, V).
- **Rejected:** B's `afterResolve` guard, because `exclusiveContent` already blocks upstream in wired scopes. A conflict that picks a newer vulnerable version (S-F10) belongs to `--check --resolve`.

**D10. Lockfiles, catalogs and `build.gradle*` are never edited.** Lockfiles stay byte-unchanged on all four Gradle versions, including after configuration-cache and isolated-projects runs (V, G). A Maven range on the patched GA is **warned, not refused** (C, P): the declaration is left alone and is probably unpatched.

**D11. Keep the CLI port of `suffixMavenPom`.** The offline capstone and the Docker `--network none` leg depend on it. It shares golden test files with depscan's `maven-suffix.ts`.

**D12. Maven version detection reads only the wrapper** (`.mvn/wrapper/maven-wrapper.properties`, `distributionUrl`), and only to produce warnings. The `mvn -v` probe is dropped (P). The wiring is the same on every version.

**D13. Migration is automatic but phased by shape (§7.6). Revert is byte-exact and independent of order (§7.3).**

**D14. Every owned tree root gets a `.gitattributes` containing `* -text`.**
- **Where:** `.socket/vendor/maven2/`, `.socket/vendor/gradle/`, and `.mvn/checksums/` in v5.x.
- **Correction (G):** a `core.autocrlf=true` clone (the Git for Windows default) put CRLF line endings into `.pom` and `.module` files, and layer 1 failed. With `* -text` it passed (V).
- This mirrors npm's `UUID_GITATTRIBUTES` (`npm_dir.rs:47`). Index parsers strip a trailing `\r`.

**D15. `unsafe_coordinates` gets a JVM grammar.**
- g and a must match `^[A-Za-z0-9_.-]+$`.
- v must contain no whitespace, no control characters and none of `"<>|?*[](),\`. It must not end in `+` or start with `latest.`.
- Before this, `is_safe_single_segment` accepted `+$(|"<&`, tab and newline, which allowed row injection and regex escapes (S).

---

## 3. On-disk layout

Everything below is committed. Files are created only for the tool that is detected.

```
.socket/
  vendor/
    state.json                          # existing ledger; new entries use ecosystem "jvm" (§7.1)
    gradle-index.tsv                    # Gradle only; derived (D8)
    maven2/                             # Maven only; RESERVED name for the sweep
      .gitattributes                    # "* -text\n" (D14)
      org/apache/commons/commons-text/1.10.0-socket.abcd1234/
        commons-text-1.10.0-socket.abcd1234.jar       # server bytes, or local rebuild with the same recipe (D7)
        commons-text-1.10.0-socket.abcd1234.jar.sha1  # bare 40-hex, no newline (fallback repository; Maven 4 requires it)
        commons-text-1.10.0-socket.abcd1234.pom       # server suffixed pom, or CLI port output
        commons-text-1.10.0-socket.abcd1234.pom.sha1
        socket-patch.vendor.json                       # marker
    gradle/                             # Gradle only; RESERVED name
      .gitattributes
      com/google/code/gson/gson/2.10.1/
        gson-2.10.1.jar  gson-2.10.1.pom  [gson-2.10.1.module]  socket-patch.vendor.json
  gradle/socket-patch.settings.gradle   # static owned script (§5.2)
.mvn/maven.config                       # +2 lines (v5.0); +7 more in v5.x strict
<each local root>/pom.xml               # 1 shared <repository> + 1 depMgmt entry per patch
<pom on a reactor parent chain>/pom.xml # in-place <version> rewrites, only where needed
settings.gradle(.kts), buildSrc/…, <includeBuild>/…   # +1 apply line; +1 in-block entry per patched GAV when the file has plugins{}
gradle/verification-metadata.xml        # only if it already exists: hash replaced, parent-chain components added
```

- **The two trees are never shared.** If the Maven fallback repository could see a same-GAV jar, it would copy it into `~/.m2` and poison other projects.
- **No other sidecars are written:** no `.md5`, `.sha256`, `.asc` or `_remote.repositories`.
- **Marker `socket-patch.vendor.json`:** sorted keys, 2-space indent, trailing newline. Fields:
  - `schema`, `uuid`, `purl`, `tool`, `version`;
  - `source`: `service`, `local` or `local-unverified`;
  - `files{name:{sha256,size}}`;
  - `replaced`: the verbatim original verification `<artifact>` element, used for revert without a ledger.
- **Index row:** `com.google.code.gson:gson:2.10.1<TAB>com/google/code/gson/gson/2.10.1/gson-2.10.1.jar<TAB><sha256><TAB><uuid>`.

**Committed diff for one patch in v5.0** (P, V):
- **20-module reactor with parent = root:** about 30 lines to review by hand (root pom +15, 1 line per literal module, 2 `maven.config` lines) plus a 5-file tree. The worst case is a remote parent in every module: 20 local roots × about 15 lines.
- **10-project Gradle build:** about 65 lines in 7 files (1 settings line, the 60-line static script, 2–3 index rows) plus a 4-file tree.

---

## 4. Maven wiring

### 4.1 Discovery (static; never runs Maven)

- **Build root:** the cwd, which must hold `pom.xml`. If the cwd pom's `<parent>` resolves to a pom above it whose `<modules>` lists the cwd, refuse with `not_build_root` and the root path. This fixes bug #4.
- **Reactor:** the recursive union of `<modules>` and Maven 4 `<subprojects>`, including those inside every `<profile>`. Taking a superset is safe.
- **Parser:** the existing comment and profile masking (`maven_repo.rs:1138-1216`) plus CDATA masking (`maven_pom.rs:204-240`), extended to record byte spans.
- **Parents:** `relativePath` defaults to `../pom.xml`. A directory gets `/pom.xml` appended. `<relativePath/>` means the parent is remote. A parent is local only if its file is in the checkout and its GAV matches.
- **Refused with `vendor_jvm_shape_unsupported`:**
  - `module_outside_root`;
  - `module_path_unresolvable` (a `${` in `<module>`, or a missing pom);
  - `nested_mvn_dir`;
  - `build_file_unreadable`;
  - `build_file_outside_root`: a symlink that leaves the checkout. Symlinks inside the checkout are followed, as today.
- **Also computed:**
  - pin-unsafe (D6, v5.x);
  - enforcer `requireNoRepositories` / `bannedRepositories`;
  - `<distributionManagement>`;
  - classifier declarations of a patched GA. These warn `classifier_declared`, because the classifier variant bypasses the pin (S).

### 4.2 `.mvn/maven.config`

**v5.0: 2 lines.** V on 3.6.3, 3.8.8, 3.9.0, 3.9.2, 3.9.11 and 4-rc-7 (A, M), except `-f` from outside the root (see the table below).
```
-Daether.offline.protocols=file
-Dmaven.repo.local.tail=${session.rootDirectory}/.socket/vendor/maven2
```

**v5.x strict: 7 more lines.** The `record=false` line is new (S):
- Without it, a `settings.xml` profile, `MAVEN_OPTS` or Maven 4's `~/.m2/maven-user.properties` can set `record=true`. A tampered jar then passes, and the committed pins are rewritten to the attacker's hash (V on 3.9.11 and 4-rc-7).
- User properties from `maven.config` take precedence over all three channels (V, S).
```
-Daether.trustedChecksumsSource.summaryFile=true
-Daether.trustedChecksumsSource.summaryFile.basedir=${session.rootDirectory}/.mvn/checksums
-Daether.trustedChecksumsSource.summaryFile.originAware=false
-Daether.artifactResolver.postProcessor.trustedChecksums=true
-Daether.artifactResolver.postProcessor.trustedChecksums.checksumAlgorithms=SHA-256
-Daether.artifactResolver.postProcessor.trustedChecksums.failIfMissing=false
-Daether.artifactResolver.postProcessor.trustedChecksums.record=false
```

**Behaviour by Maven version:**

| Version | Tail | `-f <root>/pom.xml` from outside the root | Strict pins |
|---|---|---|---|
| 3.6.3, 3.8.x | ignored; the fallback repository is used | OK (V) | ignored |
| 3.9.0–3.9.1 | the literal string is not interpolated, so it has no effect; the fallback is used | OK (V) | not enforced (the basedir stays literal), but the D6 crash and the §10 #9 NPE still happen (V, 3.9.0) |
| 3.9.2–3.9.3 | used | **fails**: `Illegal use of undefined property: session.rootDirectory` (V 3.9.2; I 3.9.3) | **not enforced**: tamper and deny both pass (V, M and S). The change is between resolver 1.9.13 and 1.9.14. |
| 3.9.4–3.9.8 | used | **fails** (V: 3.9.6–3.9.8) | enforced (V: 3.9.4–3.9.6) |
| 3.9.9+ | used | OK (V: 3.9.9, 3.9.11) | enforced (V) |
| 4.0.0-rc-7 | used | OK (V) | enforced (V) |

**Merge rules.** `maven.config` has no comment syntax (3.9.0 and 3.9.1 reject `#` lines), so our lines are identified by their exact text.
- **An identical line is already present** (from hosted mode or another JVM entry): record it as a shared fragment this entry depends on (`adopt`, §7.3). Never duplicate it.
- **An existing `-Dmaven.repo.local.tail=X`:** rewrite it to `X,${session.rootDirectory}/.socket/vendor/maven2` and record the original. The list form is V on 3.9.11 and 4.
- **An existing trusted-checksum configuration (strict):**
  - with `originAware=false` and a basedir we can resolve: reuse it;
  - with `originAware=true`: add nothing and warn `trusted_checksums_origin_aware`.
- **No trailing newline:** add one and record `addedLeadingNewline`.
- **User lines** such as `-T4`, `-ntp` and `--fail-at-end` coexist on every version (V, M).

### 4.3 `.mvn/checksums/checksums.sha256` (v5.x strict only)

- **Per patch:** a jar pin, a pom pin and a deny line (the deny line is omitted with `--maven-allow-unpatched`).
- **Format:** lines are sorted by path, with exactly **two spaces** between hash and path. With one space, 3.9.11 silently stops enforcing (V, M). Golden tests enforce the format.
- **No header comment:** hosted `merge_checksums` (`redirect/mod.rs:7068-7090`) deletes it (C), and its text blamed tampering when the real cause was an SV collision (M). This makes Q5 moot.

```
2ec2d4b2…25f6  org/apache/commons/commons-text/1.10.0-socket.abcd1234/commons-text-1.10.0-socket.abcd1234.jar
<sha256>  org/apache/commons/commons-text/1.10.0-socket.abcd1234/commons-text-1.10.0-socket.abcd1234.pom
socket-patch-refuses-unpatched-org.apache.commons:commons-text:1.10.0  org/apache/commons/commons-text/1.10.0/commons-text-1.10.0.jar
```

### 4.4 Fallback repository

There is one block per local root, shared by all patches, with id `socket-patch-vendor`.
- **Placement:** inside an existing top-level `<repositories>`, or in a new one before `</project>`. The existing `build_repo_edit` anchor logic does the insertion, with indentation detected from the file.
- **Markers:** the begin and end comment lines let revert cut the block without a ledger.

```xml
    <!-- socket-patch:begin -->
    <repository>
      <id>socket-patch-vendor</id>
      <url>file://${maven.multiModuleProjectDirectory}/.socket/vendor/maven2</url>
      <releases><enabled>true</enabled><updatePolicy>always</updatePolicy><checksumPolicy>fail</checksumPolicy></releases>
      <snapshots><enabled>false</enabled></snapshots>
    </repository>
    <!-- socket-patch:end -->
```

- `updatePolicy=always` defeats negative caching left by runs before vendoring (R).
- **Enforcer bans repositories:** the block is omitted, with warning `maven_fallback_omitted`. These projects need 3.9.2+.
- **`mirrorOf *`:** vendor reads `~/.m2/settings.xml` and `$MAVEN_HOME/conf/settings.xml` (read-only). It warns `maven_mirror_of_all` for a `mirrorOf *` mirror (but not `external:*`):
  - before 3.9.2 the build fails with "Could not find …-socket…";
  - the fix is `external:*` or `*,!socket-patch-vendor`;
  - today such builds are green but silently unpatched, so this loud change is deliberate and goes in the CHANGELOG (P).

### 4.5 Pin and declaration rewrites

**Pin.** The pin goes into each local root's top-level `<dependencyManagement><dependencies>`.
- If an entry for g:a already exists (type jar, no classifier) and its version is the literal base or a local `${p}` equal to the base, rewrite its `<version>` to SV.
- Otherwise insert the entry as the first child. If the section is missing, create it before `<dependencies>`, `<build>` or `</project>`, in that order of preference.

```xml
      <!-- socket-patch 1d3c1fd2-…: org.apache.commons:commons-text:1.10.0 -->
      <dependency>
        <groupId>org.apache.commons</groupId>
        <artifactId>commons-text</artifactId>
        <version>1.10.0-socket.abcd1234</version>
      </dependency>
```

**Declaration rewrites.** The scope is D3's: every reactor pom and every in-checkout pom on any reactor parent chain, profiles included. `<plugin><dependencies>` is excluded.

| Declared version of g:a (type jar, no classifier) | Action |
|---|---|
| Literal base | Rewrite to SV (V). |
| `${p}` that resolves to the base (own properties, then local parents, then `-D` values in `.mvn/maven.config`) | Rewrite that `<version>` to the literal SV. The property itself is left alone (V). |
| `${p}` that cannot be resolved in the checkout | Leave it, and warn `property_unresolved{file,line}`. This used to be a refusal (C, P). |
| Range, `LATEST` or `RELEASE` | Leave it, and warn `range{file,line}`. This used to be a refusal. |
| A different literal | Leave it, **do not pin that module's local root**, and warn `conflicting_literal_version{file,line}`. |

A rewritten SV contains the base (`<base>-socket.<hex8>`), so revert can restore it even without a ledger.

### 4.6 Per shape

| Shape | Edits |
|---|---|
| Single pom | 2 `maven.config` lines, 1 repository, 1 pin (+1 rewrite if the version is a literal) |
| Reactor, parent = root | 1 local root |
| Aggregator separate from the parent | The pin goes in `parent/pom.xml`; the aggregator is untouched (V) |
| Middle local parent not in `<modules>` | Its literals are rewritten (D3) |
| Remote parent (Boot-style) | Each module is its own local root (V) |
| Wrapper | Uses the same `.mvn/` and behaves like the Maven version it pins (V, M: 3.9.11, including `mvnw -f` from outside the root) |

---

## 5. Gradle wiring

### 5.1 Apply lines and the in-block entry

| File | Line (appended as the last line) |
|---|---|
| Root `settings.gradle` | `apply from: '.socket/gradle/socket-patch.settings.gradle'` |
| Root `settings.gradle.kts` | `apply(from = ".socket/gradle/socket-patch.settings.gradle")` |
| `buildSrc/settings.gradle(.kts)`, created if missing, with the DSL taken from `buildSrc/build.gradle*` | Same form, with a `../` prefix |
| Each literal `includeBuild('<p>')`, including inside `pluginManagement{}`, found recursively, with a target inside the root | Same form, with the computed relative prefix |

**In-block entry.** When a settings file has settings-level `plugins{}`, one line per patched GAV becomes the **first** statement of `pluginManagement { repositories { … } }`.
- If the file had no `pluginManagement` repositories, the block is created with our entry followed by `gradlePluginPortal()`. That keeps Gradle's default of an implicit Plugin Portal.
- The static script later finds `socketPatchVendor` in that handler and skips it.
- V on 7.6.4 with Groovy (G). The Kotlin form and 6.9.4, 8.14.3 and 9.8.0 are I (P2).

```groovy
    exclusiveContent { forRepository { maven { name = 'socketPatchVendor'; url = new File(settingsDir, '.socket/vendor/gradle').toURI() } }; filter { includeVersion('com.google.code.gson', 'gson', '2.10.1') } } // socket-patch
```

**Other cases:**
- **Settings `buildscript{}`:** a literal patched GA is refused (`gradle_settings_classpath`). Otherwise the same line goes into its `repositories{}`, which is non-empty whenever a classpath is declared (I).
- **Non-literal `includeBuild`, or a target outside the root:** warn `unwired_build_logic`. That scope is silently unpatched in v5.0; the v5.x created verification file makes it fail closed.
- **No settings file:** create one that contains only the apply line.
- **An ancestor settings file includes this directory:** refuse `not_build_root`.
- **Project-level `plugins{}` with the default Plugin Portal only:** patched with no extra wiring, because `socketFollow(p.buildscript.repositories)` sees the repositories Gradle adds for plugin resolution (V, G and P: all four versions).

### 5.2 Owned script `.socket/gradle/socket-patch.settings.gradle`

The script is static: its bytes change only with a CLI release. The earlier version was V (24/24, G). The streaming digest, the path checks and the unindexed-file check are new, so this revision stays **I until P2**.

```groovy
// Generated by socket-patch (vendored mode). Do not edit.
// Data: .socket/vendor/gradle-index.tsv. Remove with `socket-patch vendor --revert`.
import java.security.MessageDigest
if (org.gradle.util.GradleVersion.current() < org.gradle.util.GradleVersion.version('6.8')) {
  throw new GradleException('socket-patch: vendored dependencies need Gradle 6.8+')
}
def socketDir = buildscript.sourceFile.parentFile.parentFile
def socketRepoDir = new File(socketDir, 'vendor/gradle')
def socketIndex = new File(socketDir, 'vendor/gradle-index.tsv')
def socketFail = { String m ->
  throw new GradleException("socket-patch: ${m}. Restore it from git or re-run `socket-patch vendor`.")
}
if (!socketIndex.isFile()) { socketFail("${socketIndex} missing") }
def socketRows = socketIndex.readLines('UTF-8')
if (socketRows.isEmpty() || socketRows[0] != '#socket-patch-gradle-index 1') { socketFail("${socketIndex} has an unknown header") }
def socketModules = [:] as LinkedHashMap
def socketListed = [:]
socketRows.drop(1).each { String row ->
  if (row.isEmpty()) { return }
  def c = row.split('\t', -1)
  def gav = c.length == 4 ? c[0].split(':', -1) : [] as String[]
  if (gav.length != 3 || !(gav[0] ==~ /[A-Za-z0-9_.-]+/) || !(gav[1] ==~ /[A-Za-z0-9_.-]+/) ||
      !(gav[2] ==~ /[A-Za-z0-9_.+-]+/) || gav[2].endsWith('+') || gav[2].startsWith('latest.') ||
      !(c[2] ==~ /[0-9a-f]{64}/)) {
    socketFail("malformed row in ${socketIndex}: ${row}")
  }
  def dir = "${gav[0].replace('.', '/')}/${gav[1]}/${gav[2]}"
  def name = c[1].startsWith(dir + '/') ? c[1].substring(dir.length() + 1) : ''
  if (!name.startsWith("${gav[1]}-${gav[2]}") || name.contains('/')) { socketFail("row path ${c[1]} does not match ${c[0]}") }
  def f = new File(socketRepoDir, c[1])
  if (!f.isFile()) { socketFail("vendored file missing: ${f}") }
  def md = MessageDigest.getInstance('SHA-256')
  f.withInputStream { s -> byte[] b = new byte[65536]; int n; while ((n = s.read(b)) > 0) { md.update(b, 0, n) } }
  def got = md.digest().encodeHex().toString()
  if (got != c[2]) { socketFail("${f} has sha256 ${got}, pinned ${c[2]}") }
  socketModules[c[0]] = gav
  socketListed.get(dir, [] as Set) << name
}
socketListed.each { String dir, Set names ->
  def (a, v) = dir.split('/')[-2..-1]
  if (!names.contains("${a}-${v}.jar".toString()) || !names.contains("${a}-${v}.pom".toString())) { socketFail("jar or pom row missing for ${dir}") }
  def extra = new File(socketRepoDir, dir).list().findAll { it != 'socket-patch.vendor.json' && !names.contains(it) }
  if (extra) { socketFail("unindexed files in ${dir}: ${extra}") }
}
def socketName = 'socketPatchVendor'
def socketWire = { RepositoryHandler repos ->
  if (repos.findByName(socketName) != null) { return }
  repos.exclusiveContent {
    forRepository { repos.maven { name = socketName; url = socketRepoDir.toURI() } }
    filter { socketModules.values().each { m -> includeVersion(m[0], m[1], m[2]) } }
  }
}
def socketFollow = { RepositoryHandler repos ->
  if (repos.any { it.name != socketName }) { socketWire(repos) }
  repos.whenObjectAdded { ArtifactRepository r -> if (r.name != socketName) { socketWire(repos) } }
}
def socketDrm = settings.dependencyResolutionManagement
socketWire(socketDrm.repositories)
socketFollow(settings.pluginManagement.repositories)
settings.gradle.beforeProject { Project p ->
  socketFollow(p.buildscript.repositories)
  if (socketDrm.repositoriesMode.getOrElse(RepositoriesMode.PREFER_PROJECT) == RepositoriesMode.PREFER_PROJECT) {
    socketFollow(p.repositories)
  }
}
```

**Rules and their evidence:**
- **`includeVersion`, not `includeModule`**, so upgrades still come from the user's own repositories.
- **Never add our repository to an empty handler.** Doing so would switch off the settings repositories, or drop the implicit Plugin Portal.
- **`File.toURI()`** avoids the Kotlin per-project `uri()` trap and Windows drive-letter URLs.
- **Only `name =` assignment syntax is used**, so there are no deprecations on 9.8.0 (V, G: the warning set is identical to the baseline).
- **`repositoriesMode` is never set.**
- **Isolated projects:** no problems reported (V, G: 8.14.3 and 9.8.0).
- **Cost:** the script hashes every row once per settings evaluation (root, buildSrc and each included build). That is negligible at normal artifact sizes (V, G). Q12 covers hashing only in the root build.

### 5.3 Existing `gradle/verification-metadata.xml` (v5.0)

- **Jar entry:** in the `<component>` for g:a:v, the whole `<artifact name="a-v.jar">` element is replaced by a multi-line element in Gradle's canonical format with the patched sha256. The original element is recorded verbatim, in the ledger and in the marker's `replaced` field.
- **Parent chain and BOMs** (when `<verify-metadata>true`):
  - insert any missing `<component>` for the vendored pom's parents and import-scope BOMs, each with a `.pom` entry and, when published, a `.module` entry;
  - hashes come from `modules-2`, `~/.m2` or Central, verified as in §6.1;
  - each insert is recorded in the ledger.
- **Missing component for the patched GAV:** insert a sorted `<component>` with jar, pom and (if present) `.module` entries.
- **Never touched:** `<trusted-artifacts>` and keys. A PGP-trusted setup still verifies the sha256 (V, S).
- **Identifying our entries:** by component GAV, artifact name and a sha256 equal to the marker's, **not** by the `origin` attribute. `--write-verification-metadata` and Renovate rewrite `origin` (P).
- **Warnings:** a user trust rule matching g:a:v gives `gradle_trusted_by_user_rule`, and `org.gradle.dependency.verification=lenient|off` gives `gradle_verification_lenient`. Layer 1 still pins in both cases.
- **The v5.x created file** will:
  - use Gradle's canonical order and formatting, with a golden test that asserts `--write-verification-metadata sha256` changes nothing;
  - quote regexes with `\Q…\E`, use one alternation per g:a (`^(?!\Q1.0\E$|\Q2.0\E$).*$`) and XML-escape attributes. S, V: escaping only `.` as `[.]` trusted `1.0+1`, and separate version rules trusted each other;
  - have no `file=` sources rule.

### 5.4 Per shape

- **Supported (V, §9):** Groovy and Kotlin DSL, every `repositoriesMode`, catalogs, locking, configuration cache, isolated projects, buildSrc, included build-logic and the root buildscript.
- **Nothing to edit (I):** `platform`, `enforcedPlatform`, `strictly` and Spring dependency-management.
- **Classifier artifacts of a patched GAV** (`-sources`, `-javadoc`, native classifiers) are routed to our repository and are not found there (V, G):
  - IDE "download sources" returns nothing;
  - a native classifier fails loudly with "Could not find".

  This is documented. Vendoring the upstream classifiers verbatim is v5.x.
- **A user `exclusiveContent` that includes the patched GA:** refused when a literal scan finds it; otherwise "Could not find" (R).
- **Android (`com.android.*`), KMP, or a `.module` with `available-at`:** refused with `android_or_kmp`.

---

## 6. Integrity

### 6.1 Install time

| Path | Checks |
|---|---|
| Maven, server | GET `<indexUrl>/<g>/<a>/<SV>/{a-SV.jar, .jar.sha1, a-SV.pom, .pom.sha1}`. The jar must match `integrity.sha256` and `integrity.sha512`, the pom must match `mavenPomSha256`, and each sidecar must match the recomputed sha1. Any mismatch fails with `vendor_prebuilt_integrity_mismatch` and nothing is written. |
| Gradle, server | The jar comes from the direct base-filename URL and is checked the same way. The upstream `.pom`, `.module`, parent-chain poms and BOM poms come from `modules-2`, `~/.m2` or Central. **When online, each is verified against Central's `.sha512` (falling back to `.sha1`) over TLS, whatever its source** (S: cache directory names and sidecars vouch only for themselves). Offline, the file is accepted and marked `source:"local-unverified"`; `--check` reports it, and the next online run re-verifies. The `.module` is copied when the pom carries `published-with-gradle-metadata`. If that `.module` cannot be obtained, refuse `vendor_jvm_upstream_unavailable`, because the dependency graph would change (R). |
| Local rebuild (service off, offline, `pending_build`, or no SV) | When online, the **base jar** is verified against Central's `.sha512`/`.sha1` (today there is no check at all: `maven_repo.rs:776-805`). Patched members must match the manifest `afterHash`. Signatures are stripped, and the server recipe is reproduced (D7). For Maven, the pom comes from the CLI port. |

### 6.2 Build time

| Tool / version | v5.0 default | v5.x strict |
|---|---|---|
| Maven 3.6.3–3.9.1 | The fallback `.sha1` with `checksumPolicy=fail` checks the first copy only; `~/.m2` copies are not re-checked | not enforced; on 3.9.0–3.9.1 the D6 crash and the NPE still happen (V) |
| Maven 3.9.2–3.9.3 | Tail, with no build-time check. A poisoned SV copy in the `~/.m2` head wins (V, S). | **not enforced** (V); vendor warns `maven_version_lt_3_9_4` |
| Maven 3.9.4+, 4-rc | Same as 3.9.2–3.9.3 | sha256 of the SV jar and pom on every resolution, including hits in the `~/.m2` head (V); the deny line fails on the unpatched base (V) |
| Gradle 6.8–9.x | Layer 1 on every configuration (V); layer 2 when the user already has a verification file (V) | plus the created scoped file |

On every Maven version, `vendor --check` is the content pin in v5.0 (§6.3).

### 6.3 `vendor --check` (v5.0, offline)

- **Consistency:** the index, ledger, markers, file hashes, `maven.config` lines, pom fragments, apply lines, in-block entries, `.gitattributes` files and verification entries all agree, and no `<also-trust>` sits under a component we own.
- **`--local-repo`:** every SV copy in the effective local repository (`settings.xml <localRepository>`, `-Dmaven.repo.local` or `~/.m2`) must hash to the committed bytes. This detects poisoned or colliding copies (M, P, S).
- **Degraded options are reported:** `--maven-config=none`, `--maven-allow-unpatched`, `--no-gradle-verification`, auto-degrade and `local-unverified`. `--check --strict` exits non-zero on any of them, because each is a one-line ledger edit (S).
- **v5.x `--online`:** for every entry the server has built, compare against `/patches/package` integrity **whatever the recorded `source`**. Fail when the server has bytes but the marker claims `local` (S).
- **v5.x `--resolve`:** run `dependency:list` / `dependencies` to catch:
  - transitive-only mismatches;
  - graph-only reports of the unpatched version;
  - Gradle conflicts that pick a newer vulnerable version.

### 6.4 Threats

**Scope.** The threat model covers content poisoning of committed files, of `~/.m2/repository` and of `modules-2`. Code execution through `~/.m2/extensions.xml` (Maven 4), `GRADLE_USER_HOME/init.d` or `gradle.properties` is **out of scope**. Gradle layer 1 is the control that still works when `GRADLE_USER_HOME` overrides are present.

| # | Threat | Defence |
|---|---|---|
| 1 | Jar replaced and every pin updated in the same PR | No pin inside the repo can catch this. Use CODEOWNERS on `.socket/**`, `.mvn/**` and `gradle/verification-metadata.xml` (vendor output suggests it), plus `vendor --check --strict` in CI. v5.x adds `--online`. |
| 2 | Poisoned `~/.m2` or CI cache holding the SV | Undetected at build time in v5.0 on every version; detected by `vendor --check --local-repo`. Advice: exclude `**/*-socket.*` from CI cache paths. In v5.x, strict mode on 3.9.4+ fails the build (V). |
| 3 | Another project on the same machine plants the SV (the SV is public and deterministic) | Same as #2. D7 removes the harmless version of this, where two projects hold different bytes for one SV. |
| 4 | Poisoned cache at vendor time | §6.1 verifies against Central over TLS; offline results are marked `local-unverified`. |
| 5 | Bypass switches (`record=true`, `trustedChecksums=false`, `--dependency-verification=off`) | Strict mode pins `record=false` in `maven.config`. The others cannot be prevented. Gradle layer 1 still runs. `--check` flags committed forms, including a `record` setting in `.mvn/jvm.config`. |
| 6 | Stale patch | A new uuid gives a new SV and a new directory. The old one is swept once nothing live references it. |

---

## 7. State, ledger, revert, repair and migration

### 7.1 Ledger entries and records

- **New entries use ecosystem `jvm` (C).**
  - Older binaries then fail closed at `vendor.rs:247` ("no vendor backend"). Without this they treat unknown kinds as drift and silently drop the entry (the drop is V, C).
  - `--ecosystems maven|gradle` maps to `jvm`, filtered by `tool`; `ecosystem_in_scope` follows.
- **Records keep the `WiringRecord{file, kind, action, key, original, new}` struct.**
  - `action` stays `Added` or `Rewritten`. There is no new enum variant, so v4 can still parse the ledger.
  - **Fragments only:** `original` and `new` never hold a whole file, and no JVM kind is in `WHOLE_FILE_KINDS`. P, C, V: whole-file records gave a 42 KB ledger for a 10 KB pom with 2 patches.
  - Ops are stored as JSON in `new`.

| Kind | File | Shared or per patch | Ops in `new` |
|---|---|---|---|
| `maven_pom_fragment` | each edited pom | repository block and created sections: shared; pin and rewrites: per patch | `insert_block{anchorKey,text}`, `rewrite_version{depKey,from,to}`, `create_section{name}` |
| `maven_config_line` | `.mvn/maven.config` | shared | `add{line}`, `rewrite{from,to}`, `adopt{line}` (line already present; revert does nothing) |
| `maven_checksums_line` (v5.x) | `.mvn/checksums/checksums.sha256` | per patch | `add{line}` |
| `gradle_settings_fragment` | each settings file | shared | `add{line}`, `create_file`, `create_block{text}` |
| `jvm_owned_file` | script, index, `.gitattributes` | shared | `create` (the index is regenerated) |
| `gradle_verification_fragment` | verification file | jar: per patch; parent-chain components: shared | `replace{original}`, `insert{text}` |
| `jvm_vendor_tree` | tree files and markers | per patch | — |
| `created_dir` | `.mvn`, `.mvn/checksums`, `.socket/gradle` | shared | — |
| `jvm_option` | — | per patch or shared | `maven_config_none`, `maven_pin`, `maven_allow_unpatched`, `no_gradle_verification` |

### 7.2 Write path

Writes go through the existing **GroupCommit** journal (`utils/group_commit.rs`), not ad-hoc temp-file-and-rename (C).
- **Captured set:** extended to `.socket/vendor/gradle-index.tsv`, `.socket/gradle/socket-patch.settings.gradle` and the trees' `.gitattributes`, with the journal-replay path filter to match. Before this, these files were written before the commit point.
- **Planning:** all JVM entries of a run are planned **before** the vendor loop. One JVM refusal refuses every JVM entry, so a pom never ends up with legacy and v5 wiring side by side.
- **Finalize hook:** after the loop, and at every revert site, derived files are regenerated from the live entries in memory. Derived files are the index, the script's presence and, in v5.x, the trust rules.
- **Legacy directory deletion:** runs after `group.commit()`, through a new post-commit cleanup reason, `migrated_legacy_uuid_dir`. The existing `stale_artifacts` deferral only fires when the uuid changes.

### 7.3 Byte-exact revert, independent of order

The previously cited "liveness contract" (`mod.rs:801-898`) covers only one entry. Under that model, reverting in the order the entries were vendored left 2 lines behind (C, V by model). It is replaced by:
1. **Each JVM entry records every shared fragment it relies on:** the repository block, created sections, `maven.config` lines, apply lines, in-block entries, owned files and created directories. Each record is a full copy of the insertion record from the entry that created it.
2. **`RevertOpts` gains `live_peers: &[VendorEntry]`:** the in-memory state after the entries being reverted have been removed. A shared fragment is removed only when no peer lists it, so the result does not depend on revert order.
3. **Every caller passes peers:**
   - `run_revert`, `reconcile_dropped` and both legs of `run_vendor_gc`;
   - the vendored leg of rollback (`rollback.rs:879`);
   - both `remove` paths, and repair.

   Entries reverted in one invocation are never live, with or without `--preserve-state`.
4. **Undoing an op:**
   - an insertion (always whole lines) is cut by its exact text;
   - `rewrite_version` restores `from` only where the live text is exactly SV;
   - a created section is removed when only our children remain in it;
   - directories are pruned only if we created them and they are empty.
5. **Missing or edited fragment:** emit `vendor_lock_entry_drifted{file,line}` and keep the artifacts while any live file references them.
6. **Verification file reformatted by Gradle:** our entries are removed by meaning rather than by exact text (§5.3).
7. **Order:** references first, then derived files, then trees.

**Revert with no ledger** (the bug #1 case) cuts self-delimiting fragments and never reconstructs a ledger:
- `socket-patch:begin/end` blocks and `socket-patch <uuid>` comment tags;
- exact `maven.config` lines;
- `-socket.<hex8>` stripped from rewritten versions;
- settings lines ending in `// socket-patch`;
- the marker's `replaced` element.

### 7.4 References, sweep and repair

- **A separate JVM reference scanner** reads the index, markers, pom comment tags and SV strings. `scan_vendor_references` and `parse_vendor_path` stay path-based for the other ecosystems (C). **This is a stated CLI_CONTRACT change:** a JVM directory's uuid cannot be recovered from its path.
- **Liveness:** a version directory is live if any of these references it:
  - the ledger;
  - an index row;
  - an SV string in a pom or checksum file;
  - a verification component whose hash equals the marker's.
- **Reserved names:** `maven2/` and `gradle/` are reserved, and the existing sweeps already skip them because `ECOSYSTEM_DIRS` lists only `maven` (V, C). `sweep_stale_artifact` gains the new trees.
- **Phase-1 legacy fix (bug #1):**
  - add `pom.xml` and `nuget.config` to `WIRING_FILES`;
  - add `<` to the scan terminators;
  - accept `<eco>/<uuid>` references without a leaf for maven and nuget.
- **`repair`** follows WS5: re-download, then a normal `vendor` re-wire. **There is no ledger reconstruction** (P).
- **Cold-cache re-vendor (bug #3):** the backend accepts `PackageSource::Deferred`.
  - committed files that match: `already_vendored`, with no network;
  - stale and online: re-fetch;
  - stale and offline: `vendor_artifact_kept`.
- **Drift on re-runs:**
  - pins are re-derived on every run;
  - a fragment the user edited is warned about and treated as not wired;
  - a declaration the user moved to a new literal gets the §4.5 un-pin.

### 7.5 Patch update (bug #5)

- **Same uuid:** `carry_forward_wiring` drops the legacy `maven_pom_repository` records during migration, the same way the cargo special case does (`state.rs:486-488`).
- **New uuid:** fragments are per patch, so there is no whole-file original to carry forward.
- **Orphans:** migration always cuts orphan `socket-patch-vendor-<uuid>` blocks, whether or not a ledger exists.

### 7.6 Migration from the legacy layout

The legacy state is:
- `.socket/vendor/maven/<uuid>/<g>/<a>/<v>/…`;
- `<repository id="socket-patch-vendor-<uuid>">` using `${project.basedir}`;
- ledger kind `maven_pom_repository`.

| Phase | Behaviour |
|---|---|
| 2–3 | The `jvm` backend takes **only shapes refused today**: Gradle and multi-module reactors (branch points `maven_repo.rs:251` and `:263`). Single-pom projects stay on the legacy path, so **nothing accepted today changes** (C). |
| 4 | Single-pom migration, gated on the full capstone matrix and the byte-identity conformance test. If those are not green, it waits for v5.x. |

Phase-4 steps:
1. **Plan in memory:** undo the legacy wiring with `revert_repo_record` (fixed per §7.5), then compute the v5 plan on the post-undo text. If the plan refuses, write nothing and report `migration: blocked`.
2. **Get the SV slice:** use the server slice when online. Offline, use the legacy committed jar if it matches the ledger sha256, re-spell its pom with the CLI port, and mark it `source:"local"`. It is replaced on the next online run (D7).
3. **Commit** through GroupCommit, then delete the legacy directory as post-commit cleanup.
4. **No ledger:** cut blocks matching `socket-patch-vendor-[0-9a-f-]{36}` and `/.socket/vendor/maven/<uuid>`. The uuid and purl come from the marker.
5. **Local cache:** emit `vendor_legacy_layout_migrated{localCacheHint}` when `_remote.repositories` names a legacy id. The CLI never touches the user's cache.
6. **Hosted-mode projects:** `vendor` ejects them per WS2, removing the hosted Maven wiring through the WS1 restore, then applies the vendored wiring. Identical lines are adopted, not duplicated (P).
7. **Downgrade:** a v4 CLI fails closed on `jvm` entries. Documented: run `vendor --revert` with v5 first.

---

## 8. Refusal and warning codes

### 8.1 New list

**JVM refusals (3 codes).** Each is decided before any write and carries `file`/`line` plus a fix.

| Code | Reasons (and fix) |
|---|---|
| `unsafe_coordinates` (kept) | Coordinate grammar tightened (D15). |
| `vendor_jvm_shape_unsupported{reason}` | `no_build_file` (run where `pom.xml` or `settings.gradle*` lives) · `build_file_unreadable` · `not_build_root` (run from `<path>`) · `nested_mvn_dir` (remove or merge `<module>/.mvn`) · `build_file_outside_root` · `module_outside_root` · `module_path_unresolvable` (make `<module>` a literal) · `gradle_below_6_8` (`gradle wrapper --gradle-version 8.14.3`) · `gradle_settings_classpath` · `gradle_exclusive_content_conflict` (drop g:a from your rule) · `gradle_verification_unparseable` · `android_or_kmp` (use hosted mode) |
| `vendor_jvm_upstream_unavailable{reason}` | `no_base_jar` · `pom_unavailable` · `module_unavailable` · `upstream_checksum_mismatch` · `suffix_unavailable` (the upstream pom computes its own version). Fix: run one online build (`mvn dependency:resolve` or `./gradlew dependencies`), or enable the service. |

**JVM warnings (3 codes):**

| Code | Reasons |
|---|---|
| `vendor_jvm_degraded{reason}` | **v5.0:** `maven_f_outside_root` · `maven_config_omitted` · `maven_fallback_omitted` · `maven_mirror_of_all` · `property_unresolved` · `range` · `conflicting_literal_version` · `classifier_declared` · `publishes_suffixed_poms` · `gradle_trusted_by_user_rule` · `gradle_verification_lenient` · `unwired_build_logic` · `upstream_unverified`. **v5.x:** `reactor_release_compile` · `system_scope` · `trusted_checksums_origin_aware` · `maven_version_lt_3_9_4` · `deny_disabled` · `deny_plugin_classpath` · `gradle_verification_skipped` |
| `vendor_artifact_rebuilt` (kept) | Also emitted with `detail:migrated`. |
| `vendor_lock_entry_drifted` (kept) | Now also emitted by `maven.config`, settings and verification revert. |

**Shared (10, unchanged):**
- `vendor_artifact_kept`
- `vendor_marker_write_failed`
- `vendor_content_mismatch_overwritten`
- `vendor_service_offline_conflict`
- `vendor_prebuilt_required`
- `vendor_prebuilt_integrity_mismatch`
- `vendor_prebuilt_layout_mismatch`
- `vendor_prebuilt_pending`
- `vendor_prebuilt_unavailable`
- `vendor_prebuilt_downloaded`

**Events (not codes):** `pom_fetched`, `vendor_legacy_layout_migrated{localCacheHint}`.

**Honest totals (P).** The number of codes falls, but the number of conditions rises, because more shapes are now handled:

| | Today | v5.0 |
|---|---|---|
| Codes | 21 | **16** |
| JVM refusal conditions | 7 | 1 + 12 + 5 = 18 |
| JVM warning conditions | 4 | 13 + 2 kept |
| All user-visible conditions | 21 | about 43 |

CLI_CONTRACT will report reasons as the metric.

**Inputs accepted today that v5.0 refuses** (intentional; listed in the CHANGELOG):
- `not_build_root` when run from a submodule. Today this case is silently broken (bug #4).
- `build_file_outside_root` for a symlink that leaves the checkout.
- Coordinates that fail the D15 grammar.
- `suffix_unavailable`, for single-pom projects in Phase 4 only. It is rare, and depscan proposal 5 removes it.

`property_unresolved` and `range` were downgraded to warnings to keep this list short.

### 8.2 Mapping from the current 21

| # | Current | Fate |
|---|---|---|
| 1 | `unsafe_coordinates` | kept (grammar tightened) |
| 2 | `vendor_maven_pom_unreadable` | → `vendor_jvm_shape_unsupported{build_file_unreadable}` |
| 3 | `vendor_gradle_unsupported` | removed; the remaining cases are `android_or_kmp` and `gradle_below_6_8` |
| 4 | `vendor_maven_pom_project_missing` | → `vendor_jvm_shape_unsupported{no_build_file}` |
| 5 | `vendor_maven_multimodule_unsupported` | removed |
| 6 | `vendor_maven_jar_not_found` | → `vendor_jvm_upstream_unavailable{no_base_jar}` |
| 7 | `vendor_maven_pom_unavailable` | → `vendor_jvm_upstream_unavailable{pom_unavailable}` |
| 8 | `vendor_maven_local_cache_shadow` | removed: SV is never the base GAV, and D7 makes one SV one set of bytes. A foreign copy is caught by `--check --local-repo`. |
| 9 | `vendor_maven_pom_downloaded` | → the `pom_fetched` event |
| 10 | `vendor_artifact_rebuilt` | kept |
| 11 | `vendor_lock_entry_drifted` | kept |
| 12–21 | shared | kept |
| new | `vendor_jvm_shape_unsupported`, `vendor_jvm_upstream_unavailable`, `vendor_jvm_degraded` | added |

Entries on the legacy path (Phases 2–3) keep emitting codes 2–9 until Phase 4. Hosted `redirect_*` codes are untouched.

---

## 9. Supported shapes matrix

Legend:
- **OK**: patched, with no build-time Maven pin (the v5.0 default; `vendor --check` is the pin).
- **P**: patched and pinned at build time.
- **Ps**: pinned at build time only with v5.x strict mode.
- **W**: works, with a warning.
- **L**: fails loudly.
- **S**: silently unpatched.
- **R(x)**: refused with reason x.
- The V/R/I evidence label follows each cell.

### Maven

| Shape | 3.6.3 | 3.8.x | 3.9.0–3.9.1 | 3.9.2–3.9.3 | 3.9.4+ | 4.0.0-rc |
|---|---|---|---|---|---|---|
| Single pom | OK V | OK V | OK V | OK V | OK/Ps V | OK/Ps V |
| Reactor, parent = root, SNAPSHOT | OK V | OK V | OK V | OK V | OK/Ps V | OK/Ps V |
| Aggregator separate from parent | OK V | OK V | OK V | OK V | OK/Ps V | OK/Ps V |
| Middle local parent not in `<modules>` | OK I (X before the fix) | OK I | OK I | OK I | OK I | OK I |
| Remote parent, module-level pin | OK V | OK V | OK V | OK V | OK/Ps V | OK/Ps V |
| Module imports its own BOM | OK V | OK V | OK V | OK V | OK/Ps V | OK/Ps V |
| Transitive only | OK V | OK V | OK V | OK V | OK/Ps V | OK/Ps V |
| `${prop}` resolved locally | OK V | OK V | OK V | OK V | OK/Ps V | OK/Ps V |
| Literal inside a profile | OK V | OK V | OK V | OK V | OK/Ps V | OK/Ps V |
| `${prop}` not resolvable locally | W(property_unresolved) S I | same | same | same | same; strict deny gives L | same |
| Range, LATEST, RELEASE | W(range) S I | same | same | same | same | same |
| Release reactor + sibling dependency, `compile`/`test` | OK V | OK V | OK V | OK V | OK V; strict auto-degrades (crash V) | OK V; same |
| CI-friendly `${revision}` reactor, `-Drevision=` | OK I | OK I | OK I | OK I | OK I; strict auto-degrades (crash V) | same |
| `system`-scope dependency | OK I | OK I | OK I | OK V (control run) | OK V; strict auto-degrades (NPE V) | OK V; same |
| Root, `cd module`, `-pl x -am`, `-o` | V | V | V | V | V | V |
| `-f <root>/pom.xml` from outside the root | OK V | OK V | OK V | **L V** (W: maven_f_outside_root) | **L V on 3.9.4–3.9.8**; OK V on 3.9.9+ | OK V |
| … the same, with `--maven-config=none` | OK I | OK I | OK I | OK I | OK I | OK I |
| Wrapper | behaves as the Maven version it pins (V, 3.9.11) | | | | | |
| `mirrorOf *` | L V (W) | L I | L I | OK V | OK V | OK V |
| Enforcer bans repositories | L (W) | L | L | OK R | OK R | OK R |
| Tampered SV jar and sidecar | `--check` | `--check` | `--check` | `--check`; strict **not enforced** V | `--check`; strict L V | `--check`; strict L V |
| Poisoned SV copy in `~/.m2` | used V; `--check --local-repo` | same | same | used V; same | used V; strict L V | used V; strict L V |
| Missed declaration resolves the base | S | S | S | S (strict too, V) | S; strict L V | S; strict L V |
| Relocation to the base | S | S V | S | S | S; strict L V | S; strict L V |
| Nested `.mvn`, symlink outside, module outside root, run from submodule | R | R | R | R | R | R |
| Library reactor that deploys | W(publishes_suffixed_poms) | same | same | same | same | same |
| Classifier or non-jar | refused server-side | same | same | same | same | same |

### Gradle

| Shape | 6.9.4 | 7.6.4 | 8.14.3 | 9.8.0 |
|---|---|---|---|---|
| Groovy and Kotlin, 3 `repositoriesMode` values, multi-project | P V | P V | P V | P V |
| buildSrc, `pluginManagement{includeBuild}` build-logic, root `buildscript{}` | P V | P V | P V | P V |
| Settings `plugins{}` whose dependencies include the patched GAV | P I (S before the fix) | P V (S V before the fix) | P I | P I |
| Patched GA declared literally on the settings classpath | R | R | R | R |
| Project `plugins{}`, Plugin Portal only | P V | P V | P V | P V |
| Non-literal `includeBuild` | S, W | S, W | S, W | S, W |
| Version catalog | n/a | P V | P V | P V |
| Locking STRICT, lockfiles byte-unchanged | P V | P V | P V | P V |
| Existing verification file, pom-only dependency | P V | P V | P V | P V |
| Existing verification file, `.module` dependency | P I (L V before the fix) | P I (L V) | P V (L V) | P I (L V) |
| Verification lenient or off | P (layer 1) I | P V | P V | P V |
| `--offline`, including a CI cache warmed before vendoring | V | V | V (both) | V |
| Configuration cache store, reuse, tamper | n/a | P V | P V | P V |
| Isolated projects | n/a | n/a | P V | P V |
| `core.autocrlf=true` clone | P I | P I | P V (L V before) | P I |
| Jar over 300 MB with the default 512 MB heap | P I | P I | P I | P I (L V before the streaming fix) |
| Classifier of a patched GAV (`sources`, natives) | L V | L I | L V | L V |
| Range or dynamic version resolving to the patched version | v5.x | v5.x | v5.x (V with GA metadata) | v5.x |
| `platform`, `enforcedPlatform`, `strictly`, Spring dependency-management | P I | P I | P I | P I |
| User `exclusiveContent` for the GA | R when detected, else L | same | same | same |
| Android / KMP | R | R | R | R |
| Gradle below 6.8 | R, and the script throws | – | – | – |
| Mixed pom.xml and Gradle in one root | both wired, separate trees (I) | | | |

---

## 10. Failure modes

| # | Situation | Surfaces as | User action |
|---|---|---|---|
| 1 | `mvn -f <root>/pom.xml` from outside the Maven root on 3.9.2–3.9.8 | `Illegal use of undefined property: session.rootDirectory` (warned at vendor time) | Run from inside the root, use 3.9.9+, or re-vendor with `--maven-config=none` |
| 2 | Missed declaration | silently unpatched in v5.0; deny failure in strict mode on 3.9.4+ | `vendor --check`; make the declaration discoverable |
| 3 | Unresolvable `${p}` or a range on the patched GA | warned at vendor time; probably unpatched | Make it a literal, or define it locally |
| 4 | Stale manifest while a module declares another literal | its local root is not pinned (`conflicting_literal_version`) | Update the patch or the declaration |
| 5 | Stale manifest, transitive-only use of another version | a silently forced version (hosted mode has the same flaw) | v5.x `--check --resolve` |
| 6 | `mirrorOf *` before 3.9.2 | `Could not find …-socket…` (warned) | `external:*` or `*,!socket-patch-vendor` |
| 7 | Enforcer bans repositories before 3.9.2 | loud (warned) | Use 3.9.2+ |
| 8 | Poisoned or colliding SV in `~/.m2` | the foreign bytes are used | `vendor --check --local-repo`; delete the copy; exclude `**/*-socket.*` from CI caches |
| 9 | Strict mode on 3.9.0–3.9.9, with any dependency that cannot be resolved | `Cannot invoke "…Artifact.isSnapshot()" … null` (V, M) | Vendor output and docs say: rerun with `-Daether.artifactResolver.postProcessor.trustedChecksums=false` to see the real missing artifact |
| 10 | Strict mode, and a plugin needs the base (spotbugs `check`, `dependency:go-offline`) | deny failure | `--maven-allow-unpatched <purl>` (covers the whole purl; no plugin-scoped opt-out exists) |
| 11 | Strict mode on 3.9.2–3.9.3 | nothing is enforced (warned) | Use 3.9.4+ |
| 12 | Strict mode, transitive `system`-scope dependency | NPE `artifactRepository is null` | `--maven-pin=auto`, or drop strict mode |
| 13 | Library reactor deploys | consumers cannot resolve SV | Warned; do not vendor into published libraries (Q6) |
| 14 | IDE import ignores `maven.config` | the fallback repository resolves SV (I) | none |
| 15 | Gradle vendored file tampered, missing or not in the index | `socket-patch: …` at configuration time | Restore it from git, or re-vendor |
| 16 | Gradle non-literal `includeBuild` | silently unpatched in that build (warned) | Make it literal, or use v5.x `--gradle-verification=create` |
| 17 | Gradle `.module` dependency with an existing verification file whose parent entries were removed by the user | `N artifacts failed verification … jackson-base…pom` | Re-run `vendor` |
| 18 | Gradle classifier of a patched GAV | `Could not find a-v-classifier.jar`; the IDE shows no sources | Documented; v5.x vendors the classifiers |
| 19 | Renovate or `--write-verification-metadata` rewrites the verification file | `--check` compares by meaning and passes; the `origin` attribute is lost, which is harmless | none |
| 20 | CRLF checkout after our `.gitattributes` was deleted | layer-1 hash mismatch | Restore `.gitattributes` (`--check` flags it) |
| 21 | Crash mid-vendor | GroupCommit replays or rolls back | Re-run `vendor` |
| 22 | Windows, Maven `file://${maven.multiModuleProjectDirectory}` URL | untested (I) | Q8 |
| 23 | A bot bumps the version to 1.10.1 | Maven: the SV literal is edited, which shows as drift, and the tree is swept later. Gradle: resolves upstream, as it should. | Normal upgrade flow |
| 24 | v4 CLI run on a v5 checkout | fails closed: "no vendor backend for ecosystem jvm" | Use v5 |

---

## 11. Server/CLI split

**v5.0 needs no depscan changes.**
- The CLI does discovery, fetch and verification (against Central's `.sha512`/`.sha1` over TLS for upstream files), writes the trees, makes all edits, and handles the ledger, revert, VEX discovery and `vendor --check`.
- Maven uses the hosted SV slice as it is.
- Gradle uses the direct jar plus upstream metadata.

**Degraded without server changes:**
- Trust in Gradle's upstream metadata rests on Central over TLS.
- Byte identity of the local rebuild rests on reproducing the server recipe, guarded by the conformance test (D7).
- `suffix_unavailable` remains.
- Mixed-case coordinates only get a local rebuild.

**Proposed depscan changes**, ordered by value (none is required):

| # | Change | Where | Why |
|---|---|---|---|
| 1 | Hosted mode has the same Maven hazards. (a) Add `-Daether.artifactResolver.postProcessor.trustedChecksums.record=false` to `MVN_CONFIG_ARGS`. (b) Skip, or document, the six trusted-checksum lines when the reactor is pin-unsafe: a release or `${` version with a jar sibling, or `system` scope. (c) Document that nothing is enforced on 3.9.2–3.9.3, that the NPE hides missing-artifact messages on 3.9.0–3.9.9, and that `-f` from outside the root fails on 3.9.2–3.9.8. | `workspaces/app/src/patches/registry-rewrite/maven-pom.ts:61-70`; detection next to `maven-pom-scan.ts` | S-F2, S-F3, M-F1, M-F2, M-F3 (all V) |
| 2 | Publish the repack recipe as a versioned contract with a conformance fixture: archiver version, options, and a sample input with its jar sha256. | `patches/src/repack/repackers/maven.ts:138-206`, `patches-shared/src/archive/repack-utils.ts:696-724` | Locks D7 byte identity against server drift |
| 3 | Attest upstream metadata (`upstreamPomSha256`, `upstreamModuleSha256\|null`, `gradleMetadataMarker`, and the parent-chain and BOM pom hashes), and serve the verbatim upstream pom and `.module` on the direct route. | `api-v0/src/endpoints/orgs/patches/package.ts`; `package_maven_pom` storage | Removes Central from the Gradle trust chain (S-F6) |
| 4 | Serve `.sha256` and `.sha512` sidecars on the hosted route. | hosted maven2 route | The values are already stored |
| 5 | Suffix `${…}`-versioned poms by pinning the literal. | `workspaces/app/src/patches/maven-suffix.ts` (`suffixMavenPom`) | Removes `suffix_unavailable` |
| 6 | Replace the hosted Gradle snippet's "bump the version" advice (`-socket.x` sorts below the base in Gradle) with the same-GAV settings-script approach. | `registry-rewrite/maven-pom.ts:362-383` | Not fail-closed today |
| 7 | Stop lowercasing Maven purls. | `patches/src/repack/upstream/maven.ts:44-50` | Mixed-case coordinates are never built |

---

## 12. Test plan

All tests follow the repository rules: real files, real tools wherever behaviour depends on the tool, no mocking of owned modules, and the external API only through the existing wiremock harness.

### 12.1 Phase-0 prototypes: exactly two shapes (shell fixtures, before the Rust work)

The review harnesses already cover most of both shapes. Phase 0 turns them into two committed fixture scripts and re-runs them as the gate. Rows marked "already V" become regression assertions; the rest must pass before Phase 2.

**P1: multi-module Maven reactor.**

- **Fixture:**
  - an aggregator with a separate corp parent;
  - a **middle local parent that is not a module**, reached through a directory `relativePath`, that manages the base literally;
  - a module importing its own BOM that manages 1.9;
  - a module that uses the library only transitively;
  - a standalone module that is its own local root;
  - a remote-parent module with a property version;
  - a sibling dependency, plus a `type=pom` sibling and a plugin-dependency sibling;
  - a literal inside a profile;
  - a planted base literal;
  - a `system`-scope dependency.
- **Variants:** SNAPSHOT, release, and `${revision}`.
- **Maven versions:** 3.6.3, 3.8.8, 3.9.0, 3.9.3, 3.9.4, 3.9.8, 3.9.9, 3.9.11 and 4.0.0-rc-7 (plus 4 GA when it is released).
- **Invocations:** root, `cd a`, `-pl e -am`, `-pl a,e`, `-f` from outside the root, `cd c`, and `./mvnw`.
- **Each invocation runs** `compile`, `test` and `package`, offline with a warm upstream `~/.m2`, and online under `mirrorOf *`.

| Assertion | State |
|---|---|
| 2-line config: patched in every invocation and variant, except `-f` from outside on 3.9.2–3.9.8 | already V (M), except `${revision}` and `system` (I) |
| The middle local parent is rewritten, so the patched class is on the classpath | I (the fix) |
| `--maven-config=none`: patched on every version and invocation, including `-f` | I |
| No SV copy in `~/.m2` on 3.9.2+ with the tail | already V |
| `mirrorOf *`: OK on 3.9.2+; loud on 3.6.3 and 3.9.0 with the 2-line config | V; I for 3.9.0 with 2 lines |
| Strict: tamper, deny, relocation and `record=true` attacks fail on 3.9.4+ and pass on 3.9.3 | already V (M, S) |
| Strict: the D6 rule flags release+sibling, `${revision}` and `system`, but not `type=pom` or plugin siblings | the classifier logic is I; the crash shapes are already V |
| Revert is byte-exact (`cmp`) after vendoring 2 patches, in both revert orders, and with the ledger deleted | I |

**P2: Gradle multi-project with dependency locking.**

- **Fixture:**
  - `app` and `lib`, in Groovy and Kotlin DSL;
  - `repositoriesMode` set to FAIL_ON_PROJECT_REPOS, PREFER_PROJECT and PREFER_SETTINGS;
  - `lockAllConfigurations()` STRICT, with existing `gradle.lockfile`, `buildscript-gradle.lockfile` and `settings-gradle.lockfile`;
  - a version catalog;
  - buildSrc;
  - `pluginManagement{includeBuild('build-logic')}`;
  - settings `plugins{ foojay-resolver-convention }` (0.8.0 on 7.6.4, whose dependencies include the patched gson);
  - root `buildscript{ classpath gson }`;
  - patched gson (pom only) and jackson-databind (with `.module`);
  - a variant with an existing verification file.
- **Gradle versions:** 6.9.4 (JDK 11), 7.6.4 (JDK 17), and 8.14.3 and 9.8.0 (JDK 21).
- **Runs:** online and `--offline`, with configuration-cache store, reuse and tamper, and isolated projects on 8 and 9.

| Assertion | State |
|---|---|
| Every scope is PATCHED; lockfiles are byte-unchanged (md5) | already V (G) |
| The revised §5.2 script (streaming, path derivation, unindexed-file check) behaves like the old one; a deleted row plus a foreign jar fails; `+` and range versions are rejected | I |
| In-block `pluginManagement` entry: foojay's dependencies are PATCHED in buildSrc, build-logic and root, in both DSLs | V on 7.6.4 Groovy; I elsewhere |
| Existing verification file with parent-chain and BOM components: the `.module` dependency passes | V on 8.14.3; I on 6.9.4, 7.6.4 and 9.8.0 |
| A `core.autocrlf=true` clone passes with the trees' `.gitattributes` | V on 8.14.3 (G); I elsewhere |
| Layer 1 fails a tamper under `--dependency-verification=lenient`, and the configuration cache is invalidated | already V |
| No new deprecations on 9.8.0 with `--warning-mode all` | already V |
| An index row for a 400 MB jar passes with `-Xmx512m` | I |
| Revert is byte-exact (`cmp`), including the in-block entry and the verification inserts | I |

### 12.2 Unit tests (pure, I/O-free)

- **Pom span parser:** comments, CDATA, profiles, model 4.1.0, namespaces, CRLF, tabs and directory `relativePath`.
- **Classifiers:** local-root and parent-chain scope, the property chain including `maven.config` `-D` values, and the D6 pin-unsafe rule.
- **Planners:** pin and rewrite planning, including the conflicting-literal un-pin and the warnings.
- **`suffixMavenPom` port:** golden files shared with depscan's `maven-suffix.ts`.
- **`maven.config` merge:** tail list, `adopt`, originAware, no trailing newline. **Checksum format:** exactly two spaces.
- **Gradle edits:** apply-line and in-block placement in both DSLs, settings-file creation, and verification XML replace, insert, parent-chain insert and semantic revert. Also v5.x `\Q…\E` regex generation.
- **Parsing:** the D15 grammar; index writer and parser rejections, including a trailing `\r`.
- **Peer-aware revert:** a property test over N entries and every permutation of revert order, asserting byte-exact results with user edits in between.

### 12.3 In-process tests (CLI over real temp directories)

- **Core flows:** vendor, repair, sweep and revert across the fixtures.
- **Bug regressions:**
  - #1 for Maven and NuGet (sweep with `state.json` deleted);
  - #3 (cold-cache `already_vendored`);
  - #4 (`not_build_root`);
  - #5 (uuid update, then byte-exact revert).
- **Ledger schema:**
  - `legacy_ledgers_revert_byte_for_byte` stays green;
  - `new_ledgers_compact…` is updated for fragment records and passes in both revert orders;
  - a v4 binary fails closed on a `jvm` ledger.
- **GroupCommit:** kill the process after each commit point; replay covers the index and the script.
- **Phase-4 migration** from `fixtures/legacy-ledgers/maven/wired`, with and without a ledger, and the `migration: blocked` path.
- **Service suites** (existing wiremock harness): integrity mismatch, `pending_build`, null suffix, local→service byte upgrade, and offline `local-unverified`.

### 12.4 Real-tool capstones (`#[ignore]`, CI matrix)

- **`e2e_vendor_maven_build.rs`:**
  - keep the single-pom chain on 3.6.3, 3.8.9, 3.9.16, 4.0.0-rc-6 and macOS 3.9.16;
  - **add legs** for 3.9.0 (fallback), 3.9.3 (tail with no enforcement), 3.9.8 (the `-f` warning path) and 3.9.9;
  - add the P1 reactor, with `cmp` revert.
- **New `e2e_vendor_gradle_build.rs`:** gated by `SOCKET_PATCH_GRADLE_E2E_{GRADLE,VERSION,REQUIRED}`; runs the P2 matrix in both DSLs, with `cmp` revert.
- **Byte-identity conformance** (online, gated): for a set of published patches, a local rebuild from Central's base jar plus the manifest must equal the server jar's sha256. Until this is green, D7 stays I and Phase 4 is blocked.
- **Docker `--network none`:** add a reactor case to `docker_e2e_vendor_maven.rs`, and add a Gradle `--offline` twin.
- **Must stay green, unchanged:**
  - the hosted redirect goldens;
  - `e2e_redirect_maven_build.rs`, `e2e_maven.rs` and `crawler_maven_e2e.rs`;
  - `e2e_vex_lockfile/maven.rs` and `vex-discover-golden`;
  - until Phase 4, every legacy-layout test: 74 in `maven_repo.rs`, 31 in `vex/discover/maven.rs`, the capstones, and `setup_matrix_maven.rs`.

---

## 13. Implementation plan and phases

Paths are under `crates/`. LOC figures are production code only. They are revised upward per review C-F7, and reduced by moving work to v5.x.

| # | Module | v5.0 LOC | Contents |
|---|---|---|---|
| 1 | `socket-patch-core/src/vendor/jvm/mod.rs` (new) | ~450 | Backend for ecosystem `jvm`. Plans all entries before the loop, runs refusals before any write, runs the finalize hook, accepts `PackageSource::Deferred`. |
| 2 | `jvm/acquire.rs` (new) | ~650 | SV slice and direct jar with integrity checks; upstream metadata verified against Central's `.sha512`/`.sha1`; local rebuild with the server recipe; the local→service upgrade. |
| 3 | `jvm/maven_suffix.rs` (new) | ~150 | Port of `suffixMavenPom`. |
| 4 | `jvm/maven_reactor.rs` (new) | ~850 | Span-preserving model of the reactor, parent chain, properties and declarations; local roots; enforcer, `distributionManagement` and classifier detection. |
| 5 | `jvm/maven_wiring.rs` (new) | ~650 | Pins, rewrites, repository block, `maven.config` merge, `settings.xml` mirror check, fragment ops and cuts. |
| 6 | `jvm/gradle_settings.rs` (new) | ~650 | Settings discovery with a lexer that understands strings and comments; apply lines; the in-block entry; settings creation; the Android/KMP, settings-classpath and `exclusiveContent` scans. |
| 7 | `jvm/gradle_verification.rs` (new) | ~450 | Replace in an existing file, parent-chain and BOM inserts, semantic revert. |
| 8 | `jvm/gradle_index.rs` + `assets/socket-patch.settings.gradle` | ~150 | Deterministic index; the script embedded with `include_str!`. |
| 9 | `jvm/legacy.rs` | ~350 | Legacy undo and migration (Phase 4). Legacy revert and legacy VEX stay. |
| 10 | `state.rs`, `ledger_snapshots.rs`, the revert API | ~600 | Fragment records; `live_peers` on `RevertOpts` at every caller; the `carry_forward_wiring` fix (bug #5). |
| 11 | `path.rs`, `repair_vendor.rs`, the JVM reference scanner | ~500 | Reserved names; JVM liveness; the Phase-1 `WIRING_FILES` fix for Maven and NuGet. |
| 12 | `utils/group_commit.rs`, `commands/vendor.rs` post-commit | ~150 | Captured set, replay filter, `migrated_legacy_uuid_dir`. |
| 13 | `verify.rs`, `vex/discover/maven.rs` | ~350 | New trees; Gradle through the index. |
| 14 | CLI `commands/vendor.rs` | ~600 | Dispatch; `--maven-config=none`; `vendor --check [--local-repo] [--strict]`; new codes; `--ecosystems` mapping. |
| 15 | `crawlers/maven_crawler.rs` | ~250 | modules-2 as a source; honour `settings.xml <localRepository>` and `-Dmaven.repo.local`; stop treating `M2_HOME` as a repository. |

**Totals:**
- **v5.0:** about 6.9k LOC of new or changed production code, 12–15k LOC of tests (a 1:2 ratio, like the repo's existing backends), and about 1k LOC deleted (Phase 4 only).
- **v5.x:** about 1.6k LOC more: strict pins ~450, the created verification file ~350, `--check --online/--resolve` ~500, classifier vendoring and GA metadata ~300.

**Docs:**
- `ecosystems.md`;
- `CLI_CONTRACT.md`: the vendored row, codes and reasons, flags, the JVM path-recovery contract change, and VEX scope;
- CHANGELOG: the intentional refusals, and `mirrorOf *` now failing loudly;
- CODEOWNERS guidance;
- the CI snippet `socket-patch vendor --check --strict --local-repo`.

**Phases** (each is its own reviewable PR):

| Phase | Content | Gate |
|---|---|---|
| 0 | P1 and P2 fixture scripts (§12.1) | Owner sign-off (Q0). Every I row in §12.1 passes, or its decision is reopened. |
| 1 | Shared infrastructure on the legacy path: bugs #1 (Maven and NuGet), #3, #4 and #5; fragment records; the peer-aware revert API; the GroupCommit captured set; ecosystem `jvm`; D15 | Mergeable on its own; every existing test green |
| 2 | Gradle backend (items 6–8, and the Gradle parts of 2 and 13–15) | P2 capstone matrix and the Docker twin |
| 3 | Maven reactors on the `jvm` backend (items 3–5, and the Maven parts of 2 and 13); single-pom stays on the legacy path | P1 capstone and the new CI legs |
| 4 | Single-pom migration (item 9) | Full capstone matrix and byte-identity conformance green; otherwise this moves to v5.x |
| 5 (v5.x) | Strict pins, the created verification file, `--check --online/--resolve`, classifier vendoring, GA metadata, Maven 4 implicit subprojects | Evidence for Q1 and Q13 |

---

## 14. Panel scoring

Each judge weighted the criteria differently, so compare scores within a column, not across columns.

| Design | Judge 1 (/100) | Judge 2 (integrity ×3, /100) | Judge 3 (CI, cost, revert, diff ×2, /120) | Rank |
|---|---|---|---|---|
| **A: per-tool native** (SV for Maven, same GAV for Gradle) | **85** | **69** | **77** | **1st, unanimous** |
| D: config only, same GAV, Maven tail | 76 | 67 | 76 | 2nd |
| B: unified `-0.socket` suffix | 76 | 62.5 | 70 | 3rd / 3rd / 4th |
| C: resolver core extension | 65 | 57 | 71 | 4th / 4th / 3rd |

- **Why A won:** it is the only design that meets constraint 1 (no regression across 3.6.3–4-rc) together with constraint 5 (no recurring cache problem), and it fails closed on both tools.
- **Ideas taken from the other designs:**
  - from D: crash detection, the tail, and the reserved-name sweep rules;
  - from B: the Gradle configuration-time self-check and anchoring with `sourceFile`;
  - from C: a derived, line-oriented index.
- **After the adversarial review:** A's identity and wiring held up, and were verified on 6 Maven and 4 Gradle versions. A's default integrity layer (the deny line and trusted checksums on by default) did not hold up, and moved to v5.x. Judge 2's integrity weighting therefore overstated what A delivers by default. D's "warn only" position on the crash is closer to what v5.0 ships.

---

## 15. Adversarial review

There were five reviewers:
- **M:** Maven empirical, 3.6.3–4-rc-7, 14 versions;
- **G:** Gradle empirical, 6.9.4–9.8.0;
- **S:** security;
- **C:** state, revert and code;
- **P:** scope and cost.

| ID | Sev | Finding | Evidence | Disposition |
|---|---|---|---|---|
| M-F1 | blocker | `-f <root>/pom.xml` from outside the root fails on 3.9.2–3.9.8 when `maven.config` contains `${session.rootDirectory}` | V | **Partly accepted.** No expression works on both 3.9.2–3.9.8 and 4, so the tail stays for `mirrorOf *` and enforcer bans. Added the `maven_f_outside_root` warning, `--maven-config=none`, CI legs for 3.9.8 and 3.9.9, a corrected matrix, and depscan #1. Writing no `maven.config` by default was rejected, because it loses `mirrorOf *` on 3.9.2+. |
| M-F2, S-F1 | major, blocker | Trusted checksums enforce nothing on 3.9.2–3.9.3 | V | Accepted. The threshold is 3.9.4 everywhere; new warning `maven_version_lt_3_9_4`; a 3.9.3 CI leg. |
| M-F3 | major | 3.9.0 crashes too (Q4). With the post-processor on, 3.9.0–3.9.9 turn every missing artifact into an `isSnapshot()` NPE. | V | Accepted. Pins are opt-in (v5.x), so default users are unaffected; failure mode #9 carries the hint; depscan #1. Q4 is closed. |
| M-F4, P-F1 | major | One SV can name two byte sets (local rebuild vs server), giving false mismatches or silently foreign bytes | V | Accepted. D7: byte-identical rebuild plus the local→service upgrade, and `--check --local-repo`. A per-project repository id was rejected because it does not fix 3.8.8 (V). |
| M-F5 | major | The deny line fires on the spotbugs and `go-offline` plugin classpaths | V | Accepted. Deny lines only in v5.x strict mode, with a warning and docs; the remediation text now says `dependency:resolve`. Running `resolve-plugins` at vendor time was rejected (it runs the user's Maven, over the network). |
| M-F6, P-F2 | major | `${revision}` with `-Drevision=1.2.3 test` crashes a reactor that D6 classed as safe | V | Accepted. A version containing `${` counts as unsafe; `-D` values in `maven.config` are read. |
| M-F7 | major | A middle local parent outside the rewrite scope defeats the pin | V | Accepted. The scope is every in-checkout pom on a reactor parent chain; a directory `relativePath` is handled. |
| M-F8 | minor | The matrix said the wrapper is refused | V | Fixed. |
| M-F9 | minor | D6 false positives on `type=pom` and plugin-dependency siblings | V | Accepted. |
| M-F10 | minor | The deny line does not cover graph-only tools | V | Documented; `--check --resolve` in v5.x. |
| G-F1 | major | A settings plugin's dependencies silently unpatch build logic, and a created verification file then breaks the build in a way re-vendoring cannot fix | V | Accepted. In-block `pluginManagement` entry (V on 7.6.4); the created file moved to v5.x. |
| G-F2 | major | An existing verification file fails for `.module`-publishing dependencies, because the parent and BOM poms are missing | V | Accepted. Parent-chain and BOM components are inserted (V on 8.14.3). |
| G-F3 | major | `core.autocrlf=true` breaks the vendored `.pom` and `.module` | V | Accepted. D14. |
| G-F4 | major | `f.bytes` runs out of heap on large jars | V | Accepted. Streaming digest. |
| G-F5 | minor | Classifier artifacts of a patched GAV become unresolvable, and the `file=` rule does nothing | V | Documented; classifier vendoring in v5.x; the `file=` rule is dropped. |
| G-F6, P-F9 | minor | Project-level `plugins{}` with only the Plugin Portal is patched, not a loud failure | V | Matrix now says P V. |
| S-F2 | major | Leaving `record` unset lets `settings.xml`, `MAVEN_OPTS` or `maven-user.properties` switch off pins and rewrite them | V | Accepted. `record=false` in strict mode; `--check` flags `jvm.config`; depscan #1. |
| S-F3 | major | Trusted checksums throw an NPE on `system`-scope dependencies | V | Accepted. The default is unaffected (V control run); strict auto-degrades (`system_scope`); the transitive case is documented. |
| S-F4 | major | A poisoned `~/.m2` beats the tail; other projects can plant the SV | V | Accepted. Claims corrected; `--check --local-repo`; cache-exclusion advice; D7. |
| S-F5 | major | The trust regex escapes only `.`, and separate version rules trust each other | V | Accepted. `\Q…\E`, one alternation per g:a and XML escaping (v5.x); the D15 grammar (v5.0). |
| S-F6 | major | The trust roots at vendor time are caches that vouch only for themselves | INFERRED | Accepted. Every upstream file and the base jar are verified against Central's `.sha512`/`.sha1` over TLS; offline results are `local-unverified`. Making depscan #3 required was rejected (constraint 6). |
| S-F7 | major | `--check --online` can be evaded by marking an entry `source:local`, and degraded options are one-line edits | INFERRED | Accepted. D7 makes local bytes equal the service's; `--online` compares whatever the recorded source; `--check --strict` fails on degraded options. |
| S-F8 | minor/major | Layer 1 checks only the rows it is given, and `includeVersion` accepts selectors | V | Accepted. Path derivation, required jar and pom rows, the unindexed-file check and selector rejection. |
| S-F9 | minor | Relocations and classifier variants bypass the pin | V (3.8.8) | Documented; `classifier_declared` warning. |
| S-F10 | minor | A newer vulnerable version wins through Gradle conflict resolution | INFERRED | `--check --resolve` in v5.x. |
| S-F11 | minor | The threat model overstated the `~/.m2` and `GRADLE_USER_HOME` defences | documented | Accepted. §6.4 scope statement. |
| S-F12, P-F5 | minor | A created scoped file silently cancels out later adoption of verification | V | Creation moved to v5.x, where `--check` warns about it. |
| C-F1 | blocker | Shared fragments cannot be reverted through the single-entry API; reverting in vendor order leaves lines behind | V (model) | Accepted. Peer-aware revert (§7.3) at every caller; a property test over every revert order. |
| C-F2 | major | An older binary silently drops v5 entries | V | Accepted. Ecosystem `jvm`, which makes old binaries fail closed. |
| C-F3 | major | The rewrite of references and liveness is bigger than claimed, and breaks the path-recovery contract | code | Accepted. A separate JVM scanner; a stated contract change; the Phase-1 legacy fix. |
| C-F4 | major | The design ignored GroupCommit, and migration runs per package | code | Accepted. §7.2. |
| C-F5 | major | `carry_forward_wiring` works against migration, and today a legacy revert after a uuid update is not byte-exact | V | Accepted. New bug #5; §7.5. |
| C-F6, P-F7 | major | "No accepted input becomes refused" is false, and counting codes hides conditions | code, V | Accepted. `property_unresolved` and `range` are warnings; a symlink is refused only when it leaves the checkout; the remaining new refusals are listed; totals are honest. |
| C-F7 | major | LOC was underestimated (tests at 1:0.64) | code | Accepted. Re-estimated in §13. |
| C-F8, P-F8 | minor | Whole-file originals bloat the ledger, and `pre_existing` is not a valid action | V | Accepted. Fragment-only records; an `adopt` op inside `Added`. |
| C-F9 | minor | Wrong CDATA citation | code | Fixed (`maven_pom.rs:204-240`). |
| C-F10 | minor | Bug #3 panics only in debug builds | V | Severity corrected. |
| C-F11 | minor | Bug #1 also affects NuGet | INFERRED | Fixed in Phase 1. |
| C-F12 | minor | Hosted `merge_checksums` drops the header | code | Header removed; Q5 is moot. |
| C-F13, P-F6 | major | Conflicts with the v5 plan (vendored Maven is future work; repair re-synthesis was cut) | doc | Repair re-synthesis dropped. Owner sign-off is Q0, and it gates Phase 0. |
| P-F3 | major | Pins on by default protect a small subset of builds at a high cost | V | Accepted. Strict pins are opt-in in v5.x (§2.1). The cheaper "source lines only" alternative does not trigger the deny line (V, P). |
| P-F4 | major | A created verification file makes Renovate rewrite it on every Gradle PR | V (source and simulation) | Accepted. Creation is v5.x, in canonical form, with a golden test that asserts no change; our entries are identified by hash, not `origin`. |
| P-F10 | minor | The `mvn -v` probe is gold-plating | — | Accepted. Wrapper only. |
| P-F11 | minor | Before 3.9.2, migration turns green (silently unpatched) `mirrorOf *` builds red | INFERRED | Accepted. `maven_mirror_of_all` warning and a CHANGELOG entry; the loud failure is intended. |
| P-F12 | minor | Leaving the hosted repository in place (old §11.8) conflicted with the WS2 eject | doc | Accepted. Follow WS2 (§7.6 step 6). |
| P-F13 | minor | The same facts were stored in three places | — | Accepted. The index is Gradle-only. |

**Claims the reviewers tried and failed to refute** (these are now stronger; all V):

| Area | Claim |
|---|---|
| Maven wiring | The 2-line and 8-line configs patch root, `cd module`, `-pl -am`, `-f` from outside and `-o` builds on 3.6.3, 3.8.8, 3.9.0, 3.9.11 and 4-rc-7, including literals inside profiles. The only exception is `-f` on 3.9.2–3.9.8. |
| D3 precedence | On six versions: the local-parent pin beats an imported BOM, it covers transitive use, and a remote-parent module's own pin wins. |
| Tail | No SV copy lands in `~/.m2` on 3.9.2+ and 4, and the tail survives `mirrorOf *` there. |
| `maven.config` | No warnings on 3.6.3, 3.8.8 or 3.9.0. It coexists with user lines. Its user properties take precedence over settings profiles, `MAVEN_OPTS` and `maven-user.properties`. |
| Strict mode on 3.9.4+ and 4 | Tamper, deny and relocation are all detected, including under `-T4`, and the deny message names the label. Unrelated bumps and new dependencies still pass (`failIfMissing=false`). The D6 crash and the degrade both reproduce, and `package` and `verify` pass even with pins on. Dependabot ignores `file://` repositories. |
| Gradle | 24/24 matrix rows. Lockfiles stay byte-unchanged on four versions. The end-of-file apply line works with FAIL_ON_PROJECT_REPOS and with settings `plugins{}`. `sourceFile` anchoring works from Kotlin settings. Isolated projects work. Configuration-cache store, reuse and tamper work. Layer 1 works under lenient verification. No deprecations on 9.8.0. Offline works against a cache warmed before vendoring. Unrelated additions and bumps pass. PGP-trusted files still verify the sha256. Index fields cannot inject Groovy. Diffs do not grow with project count. |
| State | Existing sweeps ignore `maven2/` and `gradle/`. Old binaries parse the new kind strings. Legacy revert of the two-entry fixture stays byte-exact. |

---

## 16. Open questions

| # | Question |
|---|---|
| Q0 | **Owner re-scope:** approve moving vendored Maven and Gradle from "future work" in the v5 plan into v5, with the §2.1 cut. This gates Phase 0. |
| Q1 | The resolver's `Is a directory` crash and `system`-scope NPE: file maven-resolver issues using the P1 fixture. If a 3.9.x or 4.0 GA resolver fixes them, gate D6 on the version read from the wrapper. |
| Q2 | `vendor --check --resolve` (v5.x): should it run `mvn -q dependency:list` / `./gradlew dependencies`, opt-in and over the network, to catch transitive and graph-only mismatches and Gradle conflict upgrades? |
| Q3 | Maven ranges: does a GA-level `maven-metadata.xml` in `maven2/` let ranges resolve SV offline on every version? If so, drop the `range` warning. |
| Q6 | Publishing reactors: should they be refused rather than warned? The current answer is to warn, because internal deploy-to-Nexus flows exist. |
| Q7 | Is there demand for C's WorkspaceReader as an opt-in layer for 3.9.2+ users who want no pom edits at all? |
| Q8 | Add a Windows CI leg for the Maven `file://${maven.multiModuleProjectDirectory}` URL and the Gradle `toURI()` form. |
| Q9 | Gradle reports the base version (same GAV). Should VEX emission be mandatory for Gradle-vendored projects? |
| Q10 | Re-run P1 on Maven 4 GA: the tail, `${session.rootDirectory}`, deny behaviour and implicit subprojects. |
| Q11 | Can `.mvn/jvm.config`, with the launcher substituting the project base directory, carry the tail on 3.9.2–3.9.8 without the `-f` failure, and still work on 4? This is unverified. If it works, it replaces `maven_f_outside_root`. |
| Q12 | Gradle layer 1 in included builds and buildSrc: should it hash only in the root build (`gradle.parent == null`), once the order in which 6.x and 7.x evaluate buildSrc has been checked? |
| Q13 | What is the root cause of the missing enforcement on 3.9.2–3.9.3 (resolver 1.9.13 → 1.9.14)? Knowing it would let the 3.9.4 threshold rest on a documented change. |

Q4 (does 3.9.0 crash? yes, V) and Q5 (the header was dropped) are closed.
---

## 17. Prototype status (this branch)

The prototype lives in `crates/socket-patch-core/src/vendor/jvm/`. It runs only when `SOCKET_PATCH_EXPERIMENTAL_JVM_VENDOR=1` is set, and only for shapes the legacy backend refuses: a root `pom.xml` with `<modules>`, or a Gradle-only root. With the variable unset, every shape behaves exactly as before. After an entry exists, its re-runs and reverts follow the ledger even without the variable.

| Area | Covered |
|---|---|
| Maven reactor (§4) | Discovery; parent chains, including a middle local parent reached by a directory `relativePath`; local roots; pins; literal and `${p}` rewrites, including profiles and `.mvn/maven.config` `-D` values; the conflicting-literal un-pin; the shared fallback repository; the 2-line `maven.config`; the SV tree with a port of `suffixMavenPom`; enforcer and classifier warnings |
| Gradle (§5) | Static script with layer-1 hashing; index; apply lines for root, buildSrc and literal `includeBuild` settings in both DSLs; the in-block `pluginManagement` entry; hash replace or insert in an existing verification file; the Android/KMP, `exclusiveContent` and settings-classpath refusals |
| State (§7) | Per-fragment records. Shared fragments are removed only when no other patch still references them, so revert order does not matter. Also covered: same-uuid re-runs; patch updates with the stale-tree sweep; `--preserve-state`; the cold-cache in-sync fast path; VEX liveness and repair of a deleted tree jar |
| Safety | Every path resolves inside the checkout (a symlink that leaves it is refused); recorded paths are whitelisted per record kind; the D15 coordinate grammar is enforced |

**Evidence:**
- **Unit tests:** 113 in `vendor::jvm`.
- **Subprocess tests:** 6 in `crates/socket-patch-cli/tests/vendor_jvm_cli.rs`: two patches reverted in either order, patch update, cold cache plus VEX plus repair, `--preserve-state`, forged ledgers, and escaping symlinks.
- **Real-tool capstones:** 2 in `crates/socket-patch-cli/tests/e2e_vendor_jvm_build.rs`. The reactor test is a fresh checkout built offline from the root and from `cd module`, followed by a byte-exact revert. The Gradle test covers Kotlin DSL, FAIL_ON_PROJECT_REPOS and STRICT locking: lockfiles stay byte-unchanged, `--offline` works, a tamper fails, and revert is byte-exact.
- **Versions:** the capstones pass on Maven 3.8.8, 3.9.2, 3.9.11 and 4.0.0-rc-7, and on Gradle 6.9.4, 7.6.4, 8.14.3 and 9.8.0. A wider reactor fixture built patched in all 42 cells: Maven 3.6.3, 3.8.8, 3.9.0, 3.9.2, 3.9.11 and 4.0.0-rc-7, each with 7 invocations.

**Not yet implemented** (differences from this design):
- Ledger entries still use ecosystem `maven`, not `jvm`.
- Shared-fragment liveness comes from what the project files still reference, not from `RevertOpts.live_peers`.
- There is no revert without a ledger.
- GroupCommit does not capture the index, the script or `.gitattributes`.
- Entries are not all planned before the vendor loop.
- Maven:
  - `not_build_root`;
  - the `maven_f_outside_root` and `maven_mirror_of_all` warnings;
  - wrapper detection;
  - `--maven-config=none`;
  - Maven 4 implicit subprojects.
- Gradle: the settings `buildscript{}` in-block entry, parent-chain and BOM components in the verification file (only warned), and `gradle_below_6_8`.
- `vendor --check`, the D7 byte-identity conformance test, and install-time checks against Central checksums.
