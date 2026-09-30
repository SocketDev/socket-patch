[agent] Progress ledger for the scheduled Maven bug-hunt routine (label pm:maven).

Last updated: 2026-09-30 (run 1), main `f6b7fb9` (CLI 4.0.0), latest release 4.0.0.

## Coverage matrix

Cells are "pass", "fail #N" or "untested". Every cell uses a real Maven resolve (`maven-dependency-plugin:3.1.2:copy-dependencies`, fresh local repository) plus a jar oracle: the patch appends a marker to `META-INF/NOTICE.txt` of `org.apache.commons:commons-text:1.10.0`. Vendored mode uses a hand-staged `.socket/manifest.json` + blob, then `vendor --offline`, then deletes the manifest and blobs (a fresh checkout). Hosted mode uses a local Python stub of the patch API + Socket maven2 repository. It serves the same grant as `tests/e2e_redirect_maven_build.rs` (suffix `1.10.0-socket.4d5e6f70`), with a `settings.xml` mirror of `socket-patch-<uuid>` onto the stub. Use plugin 3.1.2, not 3.6.1: 3.6.1 itself depends on commons-text 1.10.0 and pollutes the local repo (#274). Linux runs use JDK 21. The macOS / Windows probes use the runner's default JDK (17).

| OS | Maven | Vendored plain / space / unicode path | Vendored `%XX` in path | Vendored `<repositories/>` | Hosted direct / transitive (depMgmt) | Hosted `<repositories/>`, `<dependencyManagement/>`, comment in depMgmt | Hosted re-run idempotent | Hosted → vendored takeover |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux | 3.6.3 | pass | fail #350 | fail #342 | pass | fail #342 | untested | untested |
| Linux | 3.8.8 | pass (unicode) | fail #350 | fail #342 | pass | fail #342 | untested | untested |
| Linux | 3.9.11 | pass | fail #350 | fail #342 | pass | fail #342 | pass | no revert, dead vendored wiring (commented on #271) |
| Linux | 4.0.0-rc-7 | pass | fail #350 | fail #342 | pass | fail #342 | untested | untested |
| macOS | 3.6.3 / 3.9.11 / 4.0.0-rc-7 | pass (probe; plain + space) | fail #350 (probe) | fail #342 (probe) | untested | untested | untested | untested |
| Windows | 3.6.3 / 3.9.11 / 4.0.0-rc-7 | pass (probe; plain + space, `file://D:\...` resolves) | fail #350 (probe) | fail #342 (probe) | untested | untested | untested | untested |

## Backlog

1. Vendored Maven + `aether.checksums.algorithms=SHA-512` (or `SHA-256`, or `SHA-512,SHA-256`) on Maven 3.9.x. The vendored tree has only `.sha1` sidecars, so with `checksumPolicy=fail` the `file://` repo is rejected and Maven silently resolves the pristine jar from Central (exit 0, PRISTINE, reproduced via `-D` and `.mvn/maven.config` on 3.9.11). Maven 4.0.0-rc-7 fails the whole build on Central instead, and 3.8.8 gave odd results. Before filing, confirm the 3.8.8 behaviour, check whether it's worth it given that the setting also warns on every Central artifact, and check the hosted equivalent (does patch.socket.dev serve `.sha256` / `.sha512`?).
0. Delete the stale probe branch `bughunt/maven/20260930-vendored-paths`: the git proxy refused `git push --delete` (remote hung up) in run 1. A maintainer needs to delete it.
2. Windows vendored Maven: long paths (> 260 chars) under `.socket/vendor/maven/<uuid>/<group path>/…`, and a CRLF checkout (`core.autocrlf=true`) of the committed `.pom` / `.sha1` sidecars. Does `checksumPolicy=fail` reject a CRLF-converted `.pom`? The probe script is in the run 1 entry.
3. Hosted Maven on macOS / Windows, and on Maven 3.6.3 / 3.8.8 / 4.0.0-rc-7 (only 3.9.11 so far), for the plain direct + transitive cells.
4. Hosted: `<dependency>` blocks inside `<exclusions>`-heavy poms with unusual child order (groupId after exclusions); BOM `import` scope for the patched GA; `<type>jar</type>` + `<classifier>` (see #262); `-o` offline fresh checkout (should fail loudly).
5. VEX: vendored with the `%XX` path (#350) attests `not_affected` offline. Check whether an online `vex` catches the fall-through.
6. Maven 4 `<subprojects>` aggregators (model 4.1.0) aren't refused by `vendor_maven_multimodule_unsupported`, but on rc-7 the child still resolves the patched jar (Maven 4 interpolates the inherited `${project.basedir}` to the root). That's pass, not a bug, today. Re-check on Maven 4.0.0 GA and with `-pl child` on a cold cache.

## Known non-bugs

- `patches-api.socket.dev` / `patch.socket.dev` aren't used. Stage manifests locally, or use the Python / wiremock stubs.
- `maven-dependency-plugin:3.6.1` depends on commons-text 1.10.0, so fixtures that patch commons-text 1.10.0 get the plugin realm's Central copy in the local repository (the same effect as #274). Use plugin 3.1.2 for the resolve oracle.
- The sandbox locale is POSIX: Maven dies with `InvalidPathException … unmappable characters` on a unicode project path unless `LC_ALL=C.UTF-8`. That's a sandbox artifact, not a socket-patch bug.
- Hosted literal version range `<version>[1.10.0]</version>` → `redirect_maven_dep_version_mismatch`, `redirected: 0`, nothing written: documented behaviour.
- Maven 4 `<subprojects>` aggregator not refused by vendored mode: harmless on 4.0.0-rc-7 (see backlog 6).
- Already filed elsewhere; don't re-file: #258–#275 (comment/profile/plugin markup #259, multi-module #261, classifier #262, repository order / mirrors #263, crawler lists all of ~/.m2 #265, no re-pin #266, CI matrix #267, no hosted revert #271, lowercased GAV #272, CRLF #273, plugin shadow #274).
