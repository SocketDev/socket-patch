[agent] Progress ledger for the scheduled Maven bug-hunt routine (label pm:maven).

Last updated: 2026-10-02 (run 8), main `61cfb9b`, latest release 4.0.0. Maven 3.9.16 (newest 3.9) joined the matrix in run 8.

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
1. A maintainer needs to delete the stale probe branches `bughunt/maven/20260930-vendored-paths` and `bughunt/maven/20261001-global-repo`. `git push --delete` hung up in run 4 and was denied by the session permission policy in runs 5 and 6 (not retried in run 7). Probe commits must use the default (signed) git identity. Don't override `user.email`.
2. Other user-property sources vs the reactor planner (#535 / #550 family): `-D` values containing `${...}` (Maven 4 interpolation). `#` comments are done (#550). `MAVEN_ARGS` / command-line `-D` can't be seen statically, so they're out of scope unless documented otherwise.
3. Hosted: a pre-existing `.mvn/maven.config` with a user `summaryFile.basedir` / `checksumAlgorithms=SHA-512` / `failIfMissing=true`, plus a rollback round trip with a user `checksums.sha256`, end to end (`maven_trusted_checksums_left`).
4. Other Maven 4.1.0 model features vs the reactor planner: CI-friendly `${revision}` parents, implicit `<subprojects>`.
5. Reactor (auto + `none`) and single-POM capstones on 3.8.8, and single-POM on 3.6.3. The harness warm-up has no mirror hook and Central 429s it. A local variant with a `mirrorOf central` → localhost caching mirror works.
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
- Maven 4 `<subprojects>` aggregator not refused by vendored mode: harmless on 4.0.0-rc-7 (see backlog 6).
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
