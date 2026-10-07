# sbt, Mill and scala-cli compatibility

This guide covers the real-tool suites for sbt (agent, hosted and vendored
modes), Mill (agent mode) and scala-cli (agent and vendored modes), and the one
script that runs them, [`scripts/sbt-compat-matrix.sh`](../../scripts/sbt-compat-matrix.sh).
The design and its probes are in [sbt support](../design/sbt-support.md),
[the template probe](../design/sbt-template-probe.md) and
[the evidence probe](../design/sbt-evidence-probe.md); the user-facing contract
is the sbt sections of [`CLI_CONTRACT.md`](../../crates/socket-patch-cli/CLI_CONTRACT.md).

The hermetic suites (`e2e_sbt`, `e2e_sbt_hosted`, `e2e_sbt_vendor`,
`e2e_scala_cli_vendor`, `e2e_vex_lockfile` `sbt::` / `sbt_vendored::`,
`redirect_sbt_golden`) need no JVM and run in the normal `cargo test` job.
Everything below needs Docker.

## The matrix script

```sh
scripts/sbt-compat-matrix.sh --group <agent|hosted|vendored|scala-cli|mill> \
    [--version <tool version>] [--jdk <8|17|21>] [--filter <test name substring>] \
    [--rebuild-image] [--skip-build] [--list]
```

It does three things, the same locally and in CI:

1. **Builds the Linux binaries once.** A pinned `rust` 1.93.1 container builds
   `socket-patch` and the four real-tool test binaries (`e2e_sbt_build`,
   `e2e_sbt_vendor_build`, `e2e_scala_cli_vendor`, and `docker_e2e_sbt` with
   `--features docker-e2e`) into `target/linux`
   (`SBT_MATRIX_TARGET`), with the cargo registry in the Docker volume
   `socket-patch-sbt-matrix-cargo`. Cargo's own freshness checks make later
   runs cheap. The repository is mounted at its own absolute path, so the
   paths compiled into the test binaries are valid inside the run containers.
   `--skip-build` reuses what is there.
2. **Uses the `tests/docker/Dockerfile.sbt` image** (`socket-patch-test-sbt:latest`,
   or `SBT_MATRIX_IMAGE`), building it (and `socket-patch-test-base`) when it is
   missing or `--rebuild-image` is given. The image holds JDK 8, 17 and 21
   (`/opt/jdk<N>`), the sbt 1.13.0 launcher (it runs any `sbt.version`), Mill
   0.11.13 / 0.12.17 / 1.1.10 and scala-cli 1.17.1, and bakes warm caches for
   sbt 0.13.18, 1.2.8, 1.13.0 and 2.0.9 under `/root`. An unwarmed Ivy line
   resolves its build definition from the network, serially, into each test's
   private Ivy home: sbt 0.13.18 took ~1380 s for the hosted group and ~930 s
   for the vendored one that way, ~420 s / ~100 s warm. The Coursier lines
   boot quickly cold (~140 s / ~90 s).
3. **Runs one group** for one tool version and JDK and prints one line per
   test, then a summary line:

   ```
   PASS e2e_sbt_vendor_build[1.13.0,jdk17] sbt_vendor_offline_fresh_checkout
   FAIL docker_e2e_sbt[1.2.8,jdk8] agent_sbt_versions_patch_in_place
   SKIP …        (an #[ignore]d test the group did not select)
   NOTE …        (a SKIP line the suite printed itself)
   RESULT PASS vendored 1.13.0 jdk17
   ```

   The exit status is non-zero when any test failed or none ran. Raw logs are
   in `target/linux/sbt-matrix-logs/<group>-<suite>-<version>-jdk<N>.log`.

| Group | Suite | Where it runs | `--version` |
|---|---|---|---|
| `agent` | `docker_e2e_sbt` `agent_sbt_*` (`--features docker-e2e`): the tool resolves into its cache, then `scan --sync` patches the cache copy and `rollback` restores it, Coursier sidecars included; the `useCoursier := false` cell runs on sbt 1.3 – 1.x only (older lines resolve through Ivy already; sbt 2 has no Ivy) | on the host: the prebuilt test binary on Linux, else `cargo test`; each cell is a container with the Linux binary mounted (`SOCKET_PATCH_DOCKER_BIN`) | any sbt (default 1.13.0) |
| `hosted` | `e2e_sbt_build`: `get --mode hosted` writes `socket-patch.sbt`, real sbt resolves it | the whole test binary inside the image, sbt native there | any sbt (default 1.13.0) |
| `vendored` | `e2e_sbt_vendor_build`: `vendor` writes `socket-patch-vendor.sbt` over the committed tree, real sbt resolves it | the whole test binary inside the image | any sbt (default 1.13.0) |
| `scala-cli` | the scala-cli agent cell, then `e2e_scala_cli_vendor`'s real-tool test | host cell, then inside the image | 1.17.1 only (the image's) |
| `mill` | the Mill agent cell (`build.sc` + `ivyDeps` on 0.11 / 0.12, `build.mill` + `mvnDeps` on 1.x) | host cell | 0.11.13, 0.12.17 or 1.1.10 (default 1.1.10) |

The default JDK is 8 for sbt 1.3.x and older, 17 otherwise; `--jdk` overrides
it for every cell of the run (`SOCKET_PATCH_SBT_DOCKER_JDK` in the agent
suite). `--filter` narrows to tests whose name contains the string.

Other settings: `SBT_MATRIX_JOBS` (cargo jobs, default 4), `SBT_MATRIX_MEMORY`
(`docker -m` of every run container, default `2g`), `SBT_MATRIX_BUILD_MEMORY`
(the build container, default `4g`), `SBT_MATRIX_RUST_IMAGE`,
`SBT_MATRIX_LOG_DIR`, and `SBT_MATRIX_SEED` (the warm cache handed to the
in-image suites, default `/root`; `none` runs cold).

### In CI

```yaml
- run: scripts/sbt-compat-matrix.sh --group vendored --version ${{ matrix.sbt }} --jdk ${{ matrix.jdk }} --skip-build
```

On Linux every group needs only Docker (the host side of `docker_e2e_sbt`
runs the prebuilt test binary); elsewhere the agent, `scala-cli` and `mill`
groups build it with the host Rust toolchain. On a Linux host the script hands `target/linux` back to the
calling user after the root build container. `--build-only` stops after the
build and prints the absolute paths of what it built, so one job can build
and every leg reuse the files with `--skip-build`.

[`sbt-compatibility.yml`](../../.github/workflows/sbt-compatibility.yml) runs
the full matrix on PRs touching the sbt modules, their tests, this script or
`Dockerfile.sbt`, and on every push to main:

| Job | Legs |
|---|---|
| `image`, `linux-bins` | build `socket-patch-test-sbt` and the Linux binaries once (`--build-only`), as artifacts |
| `docker` | {agent, hosted, vendored} x sbt 0.13.18, 1.2.8, 1.3.13 (JDK 8), 1.9.9, 1.13.0, 2.0.9 (JDK 17), plus JDK 21 legs for 1.13.0 and 2.0.9: 24 legs |
| `scala-tools` | `--group mill` on Mill 0.11.13, 0.12.17 and 1.1.10, `--group scala-cli` |
| `native` | `e2e_sbt_build` and `e2e_sbt_vendor_build` on sbt 1.13.0, JDK 17, on macOS and Windows: `actions/setup-java` plus `sbt/setup-sbt`, sbt on the host |

`ci.yml` runs a small blocking slice on every PR: `coverage-docker` (and the
nightly `e2e-docker`) runs `docker_e2e_sbt`'s `agent_sbt_` cells on 1.2.8
and 1.13.0 (the nightly adds the Mill and scala-cli cells), and the `e2e` job
runs `e2e_sbt_build` and `e2e_sbt_vendor_build` on sbt 1.13.0 on ubuntu.

The host legs (`native`, `e2e`) warm a seed first with
[`scripts/sbt-warm-seed.sh`](../../scripts/sbt-warm-seed.sh)` <sbt.version> <dir>`:
it boots that sbt once through the `sbt` launcher on `PATH` (`sbt.bat` on
Windows) into the flat seed layout and prints `SOCKET_PATCH_SBT_E2E_SEED` and
`SOCKET_PATCH_SBT_E2E_SBT` for `$GITHUB_ENV`. Without it every test boots sbt
from the network.

## The suites' own settings

The script sets these; a suite can also be run by hand with them.

| Variable | Read by | Meaning |
|---|---|---|
| `SOCKET_PATCH_SBT_E2E_SBT` | hosted, vendored | the sbt launcher (`…/bin/sbt`); unset = `sbt` on `PATH` |
| `SOCKET_PATCH_SBT_E2E_VERSION` | hosted, vendored | the `sbt.version` every fixture pins (default 1.13.0) |
| `SOCKET_PATCH_SBT_E2E_REQUIRED` | hosted, vendored | non-empty: a missing toolchain is a failure, not a printed SKIP |
| `SOCKET_PATCH_SBT_E2E_SEED` | hosted, vendored | a warm cache: a home (`.cache/coursier/v1`, `.ivy2`, `.sbt/boot`) or a flat directory (`coursier/v1`, `ivy2`, `boot`) |
| `SOCKET_PATCH_SBT_E2E_DOCKER` | hosted | run sbt in this image instead, the host CLI reading what it wrote (needs `SOCKET_PATCH_SBT_E2E_SBT` = a launcher directory on the host) |
| `SOCKET_PATCH_SBT_DOCKER_VERSIONS` / `_IMAGE` / `_JDK` | agent | the sbt versions, image and JDK of the cells |
| `SOCKET_PATCH_MILL_DOCKER_VERSIONS` | mill | the Mill versions of the cells (default 1.1.10) |
| `SOCKET_PATCH_DOCKER_BIN` | agent | a Linux `socket-patch` mounted over the image's |
| `SOCKET_PATCH_DOCKER_E2E_REQUIRED` | agent | `1`: a missing image is a failure |
| `SOCKET_PATCH_SCALA_CLI_E2E_{BIN,REQUIRED,CACHE}` | scala-cli vendored | the scala-cli binary, strictness, and the Coursier cache it resolves into (vendoring reads the installed copy there) |

Both real-sbt drivers (`tests/sbt_build_common` for hosted,
`tests/sbt_vendor_build_common` for vendored) share this contract through
`tests/sbt_e2e_shared`: one seed reader, one hermetic native sbt command and
group-killing timeout, the path spelling Java accepts (no Windows `\\?\`
prefix; `file:///C:/…` repository URLs), one `export` classpath parser. The
vendored driver runs sbt natively only. Both link the seed's Coursier and Ivy
caches into each test and share its boot directory.

Every sbt run is hermetic: its own home (`HOME`, `-Duser.home`, so
`mavenLocal` is the test's own `~/.m2`), global base, boot directory, Ivy
home and `COURSIER_CACHE`; `SBT_OPTS`, `JAVA_OPTS`, `JAVA_TOOL_OPTIONS`,
`COURSIER_*`, `SOCKET_*` and CI markers scrubbed; a 300 s timeout that kills
the whole process group. Installed packages are found the way a user's are: the agent
crawler reads the test home's Coursier or Ivy cache.

## Results on this branch

Run with this script on 2026-10-02 (Docker Desktop, arm64), after the review fixes:

| Group | Versions (JDK) | Result per version |
|---|---|---|
| hosted | 0.13.18, 1.2.8, 1.3.13 (8); 1.9.9, 1.13.0, 2.0.9 (17) | 14/14 PASS (with `sbt_hosted_declared_bump_fails_closed`; 0.13.18 in ~120 s on the warmed image, ~1380 s before) |
| vendored | 0.13.18, 1.2.8, 1.3.13 (8); 1.9.9, 1.13.0, 2.0.9 (17) | 8/8 PASS (with `sbt_vendor_declared_bump_fails_closed`), the offline test blocking the network on every line |
| agent | 0.13.18, 1.3.13 (8); 1.13.0, 2.0.9 (17) | the version cell PASS on each; the `useCoursier := false` cell PASS on 1.3.13 and 1.13.0, skipped (no such setting) on 0.13.18 and 2.0.9 |
| mill | 0.11.13, 0.12.17, 1.1.10 (17) | 1/1 PASS each |
| scala-cli | 1.17.1 (17) | 2/2 PASS (agent cell, vendored real-tool test) |

The hosted and vendored rows ran the template with V's declared-version
check (`docs/design/sbt-template-probe.md`, item 8) on all six lines.

See the design docs for the probed version boundaries; a past run is not a
claim that the current branch passes today.

## Known limits

- **sbt 1.0–1.2 offline (Ivy)** used to fail: Ivy aborts on the first
  unreachable repository listed before socket-patch's. The 0.13 / 1.x
  installers now move socket-patch's resolvers first
  ([template probe, case o](../design/sbt-template-probe.md#offline-resolution-on-sbt-1012)),
  and `sbt_vendor_offline_fresh_checkout` blocks the network on every line.
- **Mill** has agent mode only (vendored Mill is deferred,
  [design](../design/sbt-support.md)); the matrix covers the image's Mill
  0.11.13, 0.12.17 and 1.1.10.
- **scala-cli** is pinned to the image's 1.17.1.
- **The `native` macOS / Windows legs** and the JDK 21 legs had not run when
  the workflow was added; Windows drives `sbt.bat` from the Rust test
  drivers, whose timeout kill is process-group based on Unix only.
