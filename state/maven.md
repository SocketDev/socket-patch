[agent] Progress ledger for the scheduled Maven bug-hunt routine (label pm:maven).

Last updated: 2026-10-01 (run 5), main `c7af4df`, latest release 4.0.0.

## Coverage matrix

Oracles: a real Maven resolve, plus a marker in the patched member (jar or pom). Global `-g` cells use real Maven installs into the local repository and a stub patch API (`/tmp`-local Python stub serving batch / by-package / view / blob). v5 vendored cells use the repo capstones (`e2e_vendor_jvm_build`, `e2e_vendor_maven_build`, `e2e_redirect_maven_build`) and local, uncommitted variants of them. Linux runs use JDK 21; the macOS / Windows probes use the runner's default JDK.

### v5 global mode (`-g`)

| OS | Maven | scan -g default | M2_HOME set | settings.xml `<localRepository>` | Windows HOME≠USERPROFILE | `-g --mode hosted` refusal | agent apply / vex / rollback | read-only global dir |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 3.6.3 / 3.8.8 / 3.9.11 / 4.0.0-rc-7 | pass | fail #423 | fail #423 | n/a | pass (3.9.11) | pass (3.9.11); rollback -g under M2_HOME drops the record, fail #423 | human pass / JSON fail #424 |
| macOS | 3.6.3 / 3.9.11 / 4.0.0-rc-7 | pass (probe) | fail #423 | fail #423 | n/a | untested | untested | untested |
| Windows | 3.6.3 / 3.9.11 / 4.0.0-rc-7 | pass (probe) | fail #423 | fail #423 | fail #423 | untested | untested | untested |

### v5 vendored / hosted (Linux unless noted)

| Maven | reactor capstone (auto) | reactor `--maven-config=none`: `-o` | `none`: `cd module` | `none`: `-f root` from outside | reactor path with `,` / space / `%2F` | reactor + existing `maven.config` (CRLF / no EOL / user tail) | reactor + `aether.checksums.algorithms=SHA-256` | reactor profile-overridden `${prop}` | single-POM `%XX` path | hosted `<repositories/>` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 3.6.3 | blocked (429) | blocked | blocked | untested | untested | untested | n/a | blocked (429) | untested on v5 | untested on v5 |
| 3.8.8 | blocked (429) | blocked | blocked | untested | untested | untested | untested | blocked (429) | untested on v5 | untested on v5 |
| 3.9.11 | pass | fail #430 | fail #430 | pass | pass (comma: fallback repo) | pass | pass | fail #459 | fail #350 | fail #342 |
| 4.0.0-rc-7 | pass | fail #430 | pass | pass | untested | untested | pass | fail #459 | untested on v5 | fail #342 |

### v5 vendored reactor: external version management (run 5, Linux)

| Maven | BOM import = base | BOM import ≠ base | external parent ≠ base | BOM bump after vendoring | #459 reverse (profile = base) | single-POM BOM ≠ base |
| --- | --- | --- | --- | --- | --- | --- |
| 3.6.3 / 3.8.8 | blocked (429) | blocked (429) | blocked (429) | untested | untested | untested |
| 3.9.11 | pass | fail #488 | fail #488 | fail #488 | degraded (unpatched, warned, VEX refuses) | no downgrade |
| 4.0.0-rc-7 | pass | fail #488 | fail #488 | fail #488 | untested | no downgrade |

### v5 hosted Trusted Checksums boundary (#258, run 5, Linux)

| Maven | `e2e_redirect_maven_build` (unenforced warning ⇔ tamper enforcement) |
| --- | --- |
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

0. **Maintainer request (global `-g`)**: mostly covered in run 3 (see the matrix and the 20261001T061707Z entry). Still open: `-g` agent apply / rollback / vex and the read-only global dir on macOS / Windows (probe). Keep this item until those cells pass or fail.
1. A maintainer needs to delete the stale probe branches `bughunt/maven/20260930-vendored-paths` and `bughunt/maven/20261001-global-repo`. `git push --delete` hung up from the sandbox in run 4 and was denied by the session permission policy in run 5. Probe commits must use the default (signed) git identity. Don't override `user.email`.
2. Re-run the reactor capstone (auto + `none`), the hosted capstone and the #459 / #488 fixtures on 3.6.3 / 3.8.8 when Central isn't throttling (the fallback-repo-only path). Warm the m2 in an early, separate step.
3. Hosted single-POM + BOM import / external parent managing a different version (a downgrade via the added dM entry, or covered by #265?), and hosted `-o` on a fresh checkout.
4. #488 sibling: an external parent's `<properties>` overridden in the reactor root, and `spring-boot-starter-parent`-style property-driven management.
5. Hosted: a pre-existing user `.mvn/maven.config` plus `checksums.sha256` round trip through rollback (`maven_trusted_checksums_left`).
6. Windows long paths + CRLF checkout of `.socket/vendor/maven2` (the `* -text` `.gitattributes`).
7. The reactor capstone variants from run 4 on 4.0.0-rc-7 (comma / `%2F` paths, existing CRLF `maven.config`).

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
