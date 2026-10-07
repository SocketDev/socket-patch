# sbt resolution evidence fixtures

Real `target/` trees from the sbt scoping probe (docker, `eclipse-temurin:8`
for 0.13.18 / 1.2.8 / 1.3.13 and `:17` for 1.9.9 / 1.13.0 / 2.0.9), one
directory per sbt version:

- `test-compile/` — after `sbt test:compile` (`Test/compile` on 1.x/2.x):
  every configuration of every project resolved.
- `gson-bump/` — then `b`'s gson edited 2.8.9 → 2.10.1 and
  `export b/compile:dependencyClasspath` run: only `b`'s files were rewritten.

The build (`build.sbt`, identical in every directory) is a root aggregating
`a`, `b`, `c`:

| project | dependencies |
|---|---|
| root | commons-text 1.9 |
| a | commons-text 1.9 (→ commons-lang3 3.11) + junit 4.13.2 % Test (→ hamcrest-core 1.3) |
| b | commons-text 1.10.0 + gson (b only) |
| c | commons-text 1.9 + commons-lang3 3.12.0 (evicts 3.11) |

Only the files the evidence parser reads are kept: `build.sbt`, the Ivy XML
reports (`resolution-cache/reports/*.xml`) and each `update_cache*/output`
plus its sibling `inputs`. `project/build.properties` was written to name the
version. JSON update caches were minified and pruned to the fields the parser
reads (module coordinates, `evicted`/`evictedReason`, artifact
name/type/extension/classifier/url and the cached-file URI, `details`); the
0.13 update cache is binary sbinary and kept verbatim. Absolute paths
(`/work/<ver>/<scenario>/…`, `/root/.cache/coursier/v1/…`,
`/root/.ivy2/cache/…`) are the container's.

## L2 evidence probe scenarios

These come from the L2 evidence probe (`docs/design/sbt-evidence-probe.md`). Each probe root was named `x` unless noted otherwise, so on sbt 2 the meta-build id is `x-build`:

- `matrix/` (all six versions): a root aggregating three projects, after `update` then `+e/update`.
  - `a`: commons-text 1.9.
  - `d`: `crossPaths := false`, gson 2.8.9.
  - `e`: cross-built, commons-lang3 3.11 plus its `tests` classifier.
  - The meta-build records (`project/target/…`, sbt 2 `x-build`) are kept, except 0.13's binary one.
- `0.13.18/cross/` (root `x13`): `project e` then `+update`, with Scala 2.10 and 2.11 reports.
- `2.0.9/x-build/`: a user project `Project("x-build", file("xb"))` in root `x`, which shares the meta-build's record directory.
- `{1.9.9,2.0.9}/implicit-root/` (root `My_Proj.1`): no declared root project.
- `1.9.9/use-coursier-false/`: Ivy reports plus JSON, with artifacts in `~/.ivy2/cache`.
- `1.9.9/dependency-lock/`: the `build.sbt.lock` files that sbt-dependency-lock 1.5.1 wrote. No `target/` is kept.
- `scala-cli-1.17.1/directory/`: the Bloop project files of a scala-cli directory build.
  - Main and `--test` files, written with the Bloop server.
  - Pruned to `project.{name,directory,resolution}`.

Ivy reports are minified: only the `ivy-report`, `info`, `module`, `revision` and `artifact` elements are kept, with the attributes the parser reads. The `docs`, `sources`, `pom`, `plugin` and `scala-tool` reports are dropped.
