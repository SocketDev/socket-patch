# sbt evidence probe (lane L2, step 0)

This probe checks the evidence shapes that `formats/sbt/evidence.rs` and
`crawlers/sbt_evidence.rs` parse but the scoping probe
(`docs/design/sbt-support.md`) had not yet exercised. It ran on 2026-10-02
against sbt 0.13.18, 1.2.8 and 1.3.13 (`eclipse-temurin:8-jdk`) and 1.9.9,
1.13.0 and 2.0.9 (`eclipse-temurin:17-jdk`), each in its own container with
`docker run --rm -m 2g`, and against scala-cli 1.17.1 (`eclipse-temurin:17-jdk`).
The minified outputs are committed under
`crates/socket-patch-core/tests/fixtures/sbt/evidence/<ver>/<scenario>/`; their
README describes the pruning. The scratch harness is not in the repository.

The main build (`matrix/`) is a root `x` that aggregates three projects:

- `a`: commons-text 1.9;
- `d`: `crossPaths := false` and `autoScalaLibrary := false`, with gson 2.8.9;
- `e`: `crossScalaVersions` 2.12/2.13 (2.10/2.11 on 0.13, 3.3.4/3.8.4 on sbt 2),
  with commons-lang3 3.11 plus its `tests` classifier.

It ran `update` and then `+e/update`.

## Results

| Case | Result | Code consequence |
|---|---|---|
| `crossPaths := false` | 1.3+ writes `<P>/target/update/update_cache/output`. 0.13–1.2 write `<P>/target/streams/$global/update/$global/streams/update_cache/output`, with the Ivy reports in `<P>/target/resolution-cache/reports/`. **sbt 2 writes `target/out/jvm/u/<id>/update/update_cache/output`**, so the Scala segment is `u`, not `scala-*` | The sbt 2 pattern accepts any Scala segment and both `update_cache` spellings |
| `+update` cross-build | There is one record per Scala binary: `scala-2.12/…_2.12` and `scala-2.13/…_2.13` on 1.x, streams `update_cache_2.12` / `_2.13` on 1.2, and `scala-3.3.4/e` / `scala-3.8.4/e` (both `update_cache_3`) on sbt 2. On 0.13, `+e/update` crosses with the root's versions; `project e` then `+update` writes `scala-2.10` and `scala-2.11` reports (`0.13.18/cross/`) | The union over every record is the resolution |
| `useCoursier := false` (1.9.9, 1.3.13, 1.13.0) | Ivy reports appear under `<P>/target/scala-2.12/resolution-cache/reports/`, the JSON stays at its 1.3+ path, and the artifact paths point into `~/.ivy2/cache`. sbt 2 has no `useCoursier` setting (load error) | Both formats are read |
| `inputs` mtime | On every version, `update` rewrites each resolved project's `output` even when its `inputs` hash is unchanged (touching `build.sbt` refreshed every `output` mtime; `inputs` changed only when the dependencies did). A record the run did not resolve (the second Scala version of `e`) keeps its old mtime | `stale` compares the build sources with the newest `output` / `inputs` over the whole build |
| Load without `update` (review re-probe on 0.13.18, 1.9.9 and 2.0.9: `sbt projects` / `sbt "show name"` after touching `build.sbt`) | Every sbt load rewrites the meta-build's `output` (`project/target/…` on 0.13–1.x, `target/out/jvm/scala-*/<root>-build/` on sbt 2); the libraries' `output` and every `inputs` keep their mtimes | The meta-build's records never date the evidence: only library records count for `stale` and `wiring_newer` |
| sbt 2 project named `x-build` in root `x` | The user project and the meta-build write the same `target/out/jvm/scala-3.8.4/x-build/` directory; the record held the user project after `update` | That id is always meta-build: the project's evidence counts as missing, so the gate returns `Incomplete` |
| sbt 2 implicit root | A root `My_Proj.1` with no declared root project gets the id `my_proj-1` and the meta-build id `my_proj-1-build` (`Project.normalizeModuleID`) | `evidence::sbt_id` maps the id to `.` |
| Classifier JSON | `artifacts[][0].classifier` is `"tests"`, beside a plain jar entry. The Ivy report has `<artifact extra-classifier="tests">`. sbt 2 wraps the cached-file URI as `artifacts[][1] = {"first": uri, "second": 0}` | Both shapes are parsed |
| `build.sbt.lock` (sbt-dependency-lock 1.5.1) | With a `ThisBuild / dependencyOverrides +=` added after `dependencyLockWrite`, `update` and `compile` still succeed and only warn ("Dependency lockfile is outdated"), because the default `dependencyLockAutoCheck` is `WarnOnError`. `dependencyLockCheck` fails with exit 1 and reports `3.11 -> 3.10`. Every project gets a lock (`build.sbt.lock`, `a/build.sbt.lock`). The plugin does not load on 1.2.8 | `*_dependency_lock_present` stays a refusal. The remedy is `sbt update` and then `sbt dependencyLockWrite` |
| scala-cli 1.17.1 directory mode | With the Bloop server (the default), `scala-cli compile .` writes `.scala-build/.bloop/<name>_<hash>.json`, and `--test` writes `<name>_<hash>-test.json`. `project.resolution.modules[]` lists every transitive module with `artifacts[].path`. **`--server=false` writes no Bloop file** | `crawlers/scala_evidence.rs` reads them. No Bloop file means no evidence |

The meta-build shapes are as follows:

- **1.x:** `project/target/scala-2.12/sbt-1.0/update/update_cache_2.12/output`. Its modules (Scala tooling) all show up in the libraries' `scala-tool` configuration too.
- **0.13:** `project/target/scala-2.10/sbt-0.13/resolution-cache/reports/default-x-build-*.xml`.
- **sbt 2:** `target/out/jvm/scala-<v>/<root>-build/`, which holds the sbt plugin classpath (for example jackson).

`meta_build` is therefore "meta-build GAs that no library configuration in
`CONFIGS` resolves". A `-build` id that no declared project uses is also
treated as meta-build, which covers a root directory renamed after sbt ran.
