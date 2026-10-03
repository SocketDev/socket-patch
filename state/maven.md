[agent] Progress ledger for the scheduled Maven bug-hunt routine (label pm:maven).

Last updated: 2026-10-03 (run 12), main `045d7ec`, latest release 4.0.0. Maven 3.9.16 (newest 3.9) and 4.0.0-rc-7 (newest 4.x) are still the newest releases.

## Coverage matrix

Oracles: a real Maven resolve, plus a marker in the patched member (jar or pom). Global `-g` cells use real Maven installs into the local repository and a stub patch API (`/tmp`-local Python stub serving batch / by-package / view / blob). v5 vendored cells use the repo capstones (`e2e_vendor_jvm_build`, `e2e_vendor_maven_build`, `e2e_redirect_maven_build`) and local, uncommitted variants of them. Linux runs use JDK 21; the macOS / Windows probes use the runner's default JDK. From run 6, variant fixtures resolve through a local caching mirror of Central (`mirrorOf central`) to avoid 429s.

### v5 global mode (`-g`)

| OS | Maven | scan -g default | M2_HOME set | settings.xml `<localRepository>` | Windows HOME≠USERPROFILE | `-g --mode hosted` refusal | agent apply / vex / rollback | read-only global dir |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 3.6.3 / 3.8.8 / 3.9.11 / 4.0.0-rc-7 | pass | fail #423 (re-checked run 6) | fail #423 (re-checked run 6) | n/a | pass (3.9.11) | pass (3.9.11); rollback -g under M2_HOME drops the record, fail #423 | human pass / JSON fail #424 |
| macOS | 3.6.3 / 3.9.11 / 4.0.0-rc-7 | pass (probe) | fail #423 | fail #423 | n/a | untested | untested | untested |
| Windows | 3.6.3 / 3.9.11 / 4.0.0-rc-7 | pass (probe) | fail #423 | fail #423 | fail #423 | untested | untested | untested |

### v5 vendored / hosted (Linux unless noted)

| Maven | reactor capstone (auto) | reactor `--maven-config=none`: `-o` | `none`: `cd module` | `none`: `-f root` from outside | reactor path with `,` / space / `%2F` | reactor + existing `maven.config` (CRLF / no EOL / user tail) | reactor + `aether.checksums.algorithms=SHA-256` | reactor profile-overridden `${prop}` | single-POM `%XX` path | hosted `<repositories/>` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 3.6.3 | pass (run 6) | blocked | blocked | untested | untested | untested | n/a | blocked (429) | untested on v5 | untested on v5 |
| 3.8.8 | blocked (429) | blocked | blocked | untested | untested | untested | untested | blocked (429) | untested on v5 | untested on v5 |
| 3.9.11 | pass | fail #430 | fail #430 | pass | pass (comma: fallback repo) | pass | pass | fail #459 | fail #350 | fail #342 |
| 4.0.0-rc-7 | pass | fail #430 | pass | pass | untested | untested | pass | fail #459 | untested on v5 | fail #342 |

### v5 vendored reactor: external version management (runs 5–6, Linux)

| Maven | BOM import = base | BOM import ≠ base | external parent ≠ base | external `${prop}` overridden ≠ base in local root | BOM bump after vendoring | external-parent `${prop}` = base | 4.1.0 `<parent/>` + root `${prop}` | 4.1.0 `<parent/>` literal / versionless | #459 reverse (profile = base) | single-POM BOM ≠ base |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 3.6.3 | untested | fail #488 | fail #488 | fail #488 | untested | fail #513 | n/a | n/a | untested | untested |
| 3.8.8 | untested | fail #488 | fail #488 | fail #488 | untested | fail #513 | n/a | n/a | untested | untested |
| 3.9.11 | pass | fail #488 | fail #488 | fail #488 | fail #488 | fail #513 | n/a | n/a | degraded (unpatched, warned, VEX refuses) | no downgrade |
| 4.0.0-rc-7 | pass | fail #488 | fail #488 | fail #488 | fail #488 | fail #513 | fail #513 | pass | untested | no downgrade |

### v5 vendored reactor: maven.config user properties and VEX / `--check` (run 7, Linux)

| Maven | maven.config `--define=k=v` overrides pom prop | maven.config `-D k=v` | maven.config `-Dk=v` (control) | `vex` / `vendor --check`, `relativePath` = directory | `relativePath ..` | `relativePath` = file |
| --- | --- | --- | --- | --- | --- | --- |
| 3.6.3 | fail #535 | fail #535 | pass | fail #534 | untested | untested |
| 3.8.8 | fail #535 | fail #535 | pass | fail #534 | untested | untested |
| 3.9.11 | fail #535 | fail #535 | pass | fail #534 | fail #534 | pass |
| 4.0.0-rc-7 | fail #535 | n/a (Maven 4 ignores the form) | pass | fail #534 | untested | untested |

### v5 vendored reactor: maven.config `#` comment lines (run 8, Linux)

| Maven | `# -Dct.version=<base>` over newer pom prop | `# -Dct.version=<newer>` over base pom prop | controls (no config / `# note`) | stock capstones (reactor, single-POM, hosted) |
| --- | --- | --- | --- | --- |
| 3.6.3 | n/a (Maven rejects `#`) | n/a | n/a | reactor pass; single-POM blocked (network) |
| 3.8.8 | n/a (Maven rejects `#`) | n/a | n/a | reactor blocked (network) |
| 3.9.11 | fail #550 | fail #550 | pass | pass (earlier runs) |
| 3.9.16 | fail #550 | fail #550 | pass | pass / pass / pass |
| 4.0.0-rc-7 | fail #550 | fail #550 | pass | pass (earlier runs) |

### v5 vendored reactor: post-vendor drift and remove (run 9, Linux)

| Maven | module added after vendoring: `vendor --check` | same: `vex` | same: re-vendor | `remove <purl>` after a user edit to the wired parent |
| --- | --- | --- | --- | --- |
| 3.6.3 | untested | untested | untested | untested |
| 3.8.8 | pass (drift detected) | fail #584 | pass | untested |
| 3.9.16 | pass (drift detected) | fail #584 | pass | pass |
| 4.0.0-rc-7 | pass (drift detected) | fail #584 | pass | untested |

### v5 vendored reactor: version boundaries, CI-friendly versions, implicit subprojects, #584 siblings (run 10, Linux)

| Maven | `.gitignore *.jar` (handover from gradle) | stock reactor capstone | `${revision}` root + `-Drevision` in maven.config | #584 sibling: literal added to `b` | #584 sibling: module under second local root added later | second local root at vendor time | 4.1.0 implicit subprojects (no `<subprojects>`) | explicit `<subprojects>` control |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 3.6.3 | untested | pass | blocked (429) | untested | fail #584 | pass | n/a | n/a |
| 3.8.8 | untested | pass | untested | untested | untested | untested | n/a | n/a |
| 3.9.0 / 3.9.1 / 3.9.2 | untested | pass | untested | untested | untested | untested | n/a | n/a |
| 3.9.16 | fail #620 (comment) | pass | pass | fail #584 | fail #584 | pass | n/a | n/a |
| 4.0.0-rc-7 | untested | pass | pass | untested | fail #584 | pass | fail #622 | pass |

### v5 vendored reactor: interpolated dependency coordinates (run 11, Linux)

| Maven | `${prop}` groupId (local parent prop) | `${prop}` artifactId | literal control (file-form `relativePath`) |
| --- | --- | --- | --- |
| 3.6.3 | fail #655 | untested | pass |
| 3.9.11 | fail #655 | fail #655 | pass |
| 3.9.16 | fail #655 | untested | pass |
| 4.0.0-rc-7 | fail #655 | untested | pass |

### v5 hosted: dependency coordinate matching (run 12, Linux)

| Maven | `${prop}` groupId | `${prop}` artifactId | `<exclusions>` before `<groupId>` | literal control |
| --- | --- | --- | --- | --- |
| 3.6.3 | fail #683 | fail #683 | fail #683 | untested |
| 3.9.11 | fail #683 | fail #683 | fail #683 | pass |
| 3.9.16 | fail #683 | fail #683 | fail #683 | untested |
| 4.0.0-rc-7 | fail #683 | fail #683 | fail #683 | untested |

### v5 hosted Trusted Checksums boundary (#258, run 5, Linux)

| Maven | `e2e_redirect_maven_build` (unenforced warning ⇔ tamper enforcement) |
| --- | --- |
| 3.6.3 | pass (run 6) |
| 3.8.8 | pass (run 6) |
| 3.9.3 | pass |
| 3.9.4 | pass |
| 4.0.0-rc-7 | pass |

### v4.0.0 results (runs 1–2, main `f6b7fb9`; not re-run on v5 unless shown above)

| OS | Maven | Vendored plain / space / unicode path | Vendored `%XX` in path | Vendored `<repositories/>` | Hosted direct / transitive (depMgmt) | Hosted `<repositories/>`, `<dependencyManagement/>`, comment in depMgmt | Hosted re-run idempotent | Hosted → vendored takeover | Vendored + SHA-256/512-only checksums | Vendored re-run / revert / remove / rollback |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 3.6.3 | pass | fail #350 | fail #342 | pass | fail #342 | untested | untested | pass (property ignored) | untested |
| Linux | 3.8.8 | pass (unicode) | fail #350 | fail #342 | pass | fail #342 | untested | untested | fail #394 | untested |
| Linux | 3.9.11 | pass | fail #350 | fail #342 | pass | fail #342 | pass | no revert (#271) | fail #394 | pass |
| Linux | 4.0.0-rc-7 | pass | fail #350 | fail #342 | pass | fail #342 | untested | untested | fail #394 (build breaks) | untested |
| macOS | 3.6.3 / 3.9.11 / 4.0.0-rc-7 | pass (probe) | fail #350 | fail #342 | untested | untested | untested | untested | untested | untested |
| Windows | 3.6.3 / 3.9.11 / 4.0.0-rc-7 | pass (probe) | fail #350 | fail #342 | untested | untested | untested | untested | untested | untested |

## Backlog

0. **Maintainer request (global `-g`)**: mostly covered in run 3 (see the matrix and the 20261001T061707Z entry). Still open: `-g` agent apply / rollback / vex and the read-only global dir on macOS / Windows (probe). Keep this item until those cells pass or fail. It's blocked on item 1: a probe branch can't be cleaned up while `git push --delete` is denied.
1. A maintainer needs to delete the stale probe branches `bughunt/maven/20260930-vendored-paths` and `bughunt/maven/20261001-global-repo`. `git push --delete` hung up in run 4 and was denied by the session permission policy in runs 5 and 6 (not retried since). Probe commits must use the default (signed) git identity. Don't override `user.email`.
2. #655 siblings: a `${prop}` groupId in the root `dependencyManagement`. #683 siblings (hosted): `${project.groupId}`; `<type>` / `<classifier>` before `<groupId>`; rollback / re-run after a shadowed dM pin. Low-yield (untested): the single-POM vendored backend + `${prop}` groupId (it injects only a `<repository>` and matches no declarations).
2b. #622 follow-ups: `scan --mode vendored` / `get --mode vendored` on the implicit-subproject layout; an implicit layout with a nested aggregator; `vendor --revert` on it.
3. Hosted: a pre-existing `.mvn/maven.config` with `failIfMissing=true` plus a user `checksums.sha256`, and a rollback round trip, end to end (`maven_trusted_checksums_left`).
4. Other user-property sources vs the reactor planner (#535 / #550 family): `-D` values containing `${...}` (Maven 4 interpolation).
5. `${revision}`, the #584-sibling cells and the single-POM vendored capstone on 3.6.3 / 3.8.8 through a caching mirror (the harness warm-up has no mirror hook; a local variant with `mirrorOf central` → localhost works).
6. The #459 reverse case and BOM bump on 3.6.3 / 3.8.8 / 4.0.0-rc-7.
7. Windows long paths + CRLF checkout of `.socket/vendor/maven2` (the `* -text` `.gitattributes`).
8. The reactor capstone variants from run 4 on 4.0.0-rc-7 (comma / `%2F` paths, existing CRLF `maven.config`).
9. The v4.0.0-era cells on 3.9.16 (hosted re-run idempotency, `%XX` path, `<repositories/>`).

## Known non-bugs

- `patches-api.socket.dev` / `patch.socket.dev` aren't used. Stage manifests locally, or use the Python / wiremock stubs.
- `maven-dependency-plugin:3.6.1` depends on commons-text 1.10.0, so fixtures that patch commons-text 1.10.0 get the plugin realm's Central copy in the local repository (the same effect as #274). Use plugin 3.1.2 for the resolve oracle.
- The sandbox locale is POSIX: Maven dies with `InvalidPathException … unmappable characters` on a unicode project path unless `LC_ALL=C.UTF-8`. That's a sandbox artifact, not a socket-patch bug.
- Hosted literal version range `<version>[1.10.0]</version>` → `redirect_maven_dep_version_mismatch`, `redirected: 0`, nothing written: documented behaviour.
- Central 429 bodies cached as `.pom` files ("Non-parseable POM … Your…") are rate-limit artifacts. Delete poms under 200 bytes from the seed repo and retry.
- Maven 4 explicit `<subprojects>` aggregator: planned as a reactor on v5 (pass, run 10). The *implicit* case (no `<subprojects>`) is #622.
- Linux sandbox: Java's `user.home` comes from passwd, not `$HOME`. Pass `-Duser.home=$HOME` to Maven when faking a home directory.
- `--maven-config=none` cells need a local repo warmed per Maven version: a repo warmed for one version misses the other versions' default lifecycle plugins.
- Offline `rollback -g` without the before-blob → loud exit 1 "--offline prevents fetching": documented.
- Already filed elsewhere; don't re-file: #258–#275 (comment/profile/plugin markup #259, multi-module #261, classifier #262, repository order / mirrors #263, crawler lists all of ~/.m2 #265, no re-pin #266, CI matrix #267, no hosted revert #271, lowercased GAV #272, CRLF #273, plugin shadow #274).
- A UTF-8 BOM in an existing `.mvn/maven.config`: Maven 3.9.11 and 4.0.0-rc-7 refuse the file themselves ("Unrecognized maven.config file entries"). Not caused by socket-patch.
- Reactor checkout path containing a comma: `maven.repo.local.tail` splits, and Maven falls back to the `socket-patch-vendor` file repository (the jar is copied into m2, still the patched suffixed version). Degraded but fail-closed, not filed.
- Hosted `merge_checksums` drops non-`<sha>  <path>` lines (`#` comments) and re-sorts a user's `checksums.sha256`. Maven ignores those lines, so this is cosmetic and not filed.
- v5 `vendor` has no local artifact building: without a patch service it fails `vendor_service_offline_conflict`. Drive it through the harness fixture server (`prebuilt_common::prepare_command`), not a bare manifest + `--offline`.
- #459 reverse case (top-level version ≠ base, active profile = base): unpatched but warned, and VEX refuses (`vendor_unwired`). Recorded on #459, not re-filed.
- Single-POM vendored + a BOM managing a different version: no downgrade (repository only). VEX lists the unused base version `not_affected`, which is the #265 family. Not filed.
- Hosted single-POM with a versionless dep + a BOM managing another version: the hosted dM insertion overrides the BOM (a downgrade), which #265 already names. Don't re-file.
- `.mvn/maven.config` `--define k=v` on one line: Maven 3.9.11 / 4.0.0-rc-7 reject it themselves ("Unrecognized option"). A quoted `-Dk="v"` fails the build on every Maven line. Not socket-patch.
- maven.config `-D k=v` (separate tokens) is ignored by Maven 4.0.0-rc-7 itself, so the #535 cell is n/a on Maven 4.
- `#` comment lines in `.mvn/maven.config` on Maven 3.6.3 / 3.8.8: Maven itself rejects them. Only 3.9+ / 4.x treat them as comments (#550).
- Hosted `merge_mvn_config`: a user's own `trustedChecksums=false`, `checksumAlgorithms=SHA-512` or `summaryFile.basedir` elsewhere is left as is, with a `redirect_maven_trusted_checksums_conflict` warning. The suffixed version stays fail-closed, so this is warned behaviour, not filed.
- The JVM capstone's module `b` uses the directory-form `relativePath ../corp-parent`, so any variant oracle hits #534 in `vendor --check` / `vex`. Rewrite it to `../corp-parent/pom.xml` first.
- Harness: in one test process, a second `vendor` through `prebuilt_common::prepare_command` can fail `vendor_prebuilt_required` ("package response missing a result"). Run each fixture case in its own process.
- `cd <module>` offline in a reactor whose module depends on an uninstalled sibling fails in Maven itself (the sibling isn't in the local repo). Pick a leaf module for `cd` oracles.
