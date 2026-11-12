# Light fixture workspaces

Bazel workspaces for the rulesets whose proof needs no language toolchain to
fetch: rules_js, rules_jvm_external, rules_ruby, rules_dotnet and rules_csharp.
`e2e_bazel_build` copies one into a scratch directory, adds
`common/probe.bzl` and runs real Bazel in it; `e2e_bazel` reads the same trees
without Bazel. Nothing here is built in place.

```
light/
  registry/<host>/<path>             the registry files the fixtures pin, by URL
  <ruleset>/MATRIX.json              the fixtures of the ruleset and the Bazel versions each is claimed on
  <ruleset>/<bzlmod|workspace>/<era>[-<variant>]/   one workspace
  <ruleset>/.../locks/v<N>/MODULE.bazel.lock        a committed lock, where the fixture's shape is a fact of the lock
```

An era names the Bazel line a fixture is written for (`e9` 9.x and 8.x, `e7`
7.7, `e6` 6.6 to 7.1) and pins the ruleset release that runs there. Every
workspace defines `//:socket_probe` (proof tiers 0 and 1) and `//:consumer`
(tier 2, a program in the ruleset's language), pins its ruleset with
`single_version_override` at the `bazel_dep` version, and keeps production
host names in every committed file.

## Where the files come from

Each file is what the probe workspaces of the Bazel-support campaign ran,
with one edit: the gem and NuGet files were captured against a fixture host
and name `rubygems.org` and `api.nuget.org` here.

| Files | Written by |
|---|---|
| `pnpm-lock.yaml` 9.0, 6.0, 5.4 | pnpm 12.18.0, 8.15.9, 7.33.7 |
| `package-lock.json` | npm (lockfileVersion 3) |
| `.aspect/rules/external_repository_action_cache/*` | rules_js 3.6.0, on the first build with `update_pnpm_lock` |
| `maven_install.json`, `other_install.json` | `@maven//:pin` of rules_jvm_external 7.2, 6.10 and 6.5 |
| `Gemfile.lock` | Bundler 4.0.15 |
| `rules_dotnet/bzlmod/e9/deps/paket.main*.bzl` | by hand, then matched byte for byte by `paket2bazel` of rules_dotnet 0.22.2 |
| `rules_dotnet/bzlmod/e7/deps/paket.main*.bzl` | by hand, in the shape `paket2bazel` of rules_dotnet 0.13 and 0.14 generates |
| `rules_dotnet/bzlmod/e7/locks/v13/MODULE.bazel.lock` | `bazel mod deps --lockfile_mode=update` under Bazel 7.7.2 against `https://bcr.bazel.build/` |
| `Gemfile`, `paket.dependencies`, `paket.lock`, `nuget.config`, `packages.lock.json`, `App.csproj` | by hand, for the fixture packages |

`registry/` holds the bytes those locks pin:

- npm and Maven: the upstream release files of `left-pad` 1.3.0,
  `@tootallnate/once` 2.0.0 and `slf4j-api` 1.7.36 (with the POMs and `.md5`
  files Coursier asks for), unchanged.
- gem and NuGet: synthetic packages (`sp-victim`, `sp-other`, `sp-parent`;
  `SP.Victim`, `SP.Other`) that exist on no real registry. `sp-parent` depends
  on `sp-victim`. The NuGet assemblies are placeholder bytes: they prove which
  package Bazel unpacked, not that it compiles.
- `api.nuget.org/v3/index.json`: a service index that names the production
  flat container and nothing else.

`baseline_light.rs` checks without Bazel that every fixture pins the digest of
its mirrored artifact.

The upstream files are redistributed unchanged under their own licenses:

| File | From | License | sha256 |
|---|---|---|---|
| `left-pad-1.3.0.tgz` | `https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz` | WTFPL (`COPYING` in the tarball) | `870c0fe1096223a58d4f8832d08a7e651ea2fcadb8e6877b2fdc26b662d481dd` |
| `once-2.0.0.tgz` | `https://registry.npmjs.org/@tootallnate/once/-/once-2.0.0.tgz` | MIT (`LICENSE` in the tarball) | `cfd126e31fc0549c41626d3388647f3d90aaa480850a9efcdea861475cfe7bbf` |
| `slf4j-api-1.7.36.jar`, its POM and `slf4j-parent-1.7.36.pom` | `https://repo1.maven.org/maven2/org/slf4j/` | MIT (named in the parent POM; text at `https://www.slf4j.org/license.html`) | jar `d3ef575e3e4979678dc01bf1dcce51021493b4d11fb7f1be8ad982877c16a1c0` |

## Fetching

Locks keep production URLs, so the fixture server has to be in the way. The
registry modules under `tests/bazel_build_common/registry/` serve `registry/`
on the loopback server and return the URL scopes they own; a test sends those
scopes there with a downloader config. Three fetch paths do not go through
Bazel's downloader and need more:

- A pnpm that Bazel runs (`update_pnpm_lock` with a stale hash file) asks the
  registry for package documents itself. `npm::mount` serves them; the test
  points pnpm at `npm::loopback_registry` through a declared `.npmrc`. The
  `e9-upl-*` and `e7-upl` fixtures commit a hash file that matches, so their
  baseline runs no pnpm.
- Coursier, in the unpinned hub of `rules_jvm_external/bzlmod/e9-unpinned`,
  reads the repository named in `MODULE.bazel`. That fixture commits
  `http://127.0.0.1:18731/maven2`; a test serves the mirror there
  (`maven::mount_loopback`) and writes its own port into its copy.
- rules_ruby also downloads the Bundler gem the lock names, from the real
  `rubygems.org`, under a checksum it ships. The gem scopes cover the fixture
  gems only.

## MATRIX.json

```
group, ruleset      "light" and the directory name
registries          the registry modules that serve the ruleset's packages
probe               what //:socket_probe holds: one anchor per file, by kind
                    (integrity, sha256, file_jar, unpacked) with its path in registry/
fixtures[]
  path, test        the workspace and its bazel_canary_baseline_* test
  system            bzlmod or workspace
  pins              ruleset name -> the version the fixture is written for
  shape             what sets the fixture apart
  cells[]           bazel (a version of scripts/bazel-pins.txt), tier (nightly or pr),
                    outcome (optional: the class the hosted lane must reach there)
  module_lock       optional: Bazel version -> committed lock to start from
  recorded_extension  optional: a moduleExtensions key the lock must hold after a build
  probe             optional: replaces the ruleset's probe for this fixture
  loopback_repository  optional: the one loopback URL the fixture commits
```

A fixture is listed on a Bazel version only when its canary built it there.
The `e6` rules_js fixtures (pnpm lock 6.0 and rules_js 1.x) are on 6.6.0,
7.0.2 and 7.1.2 only; no cell ran them on a later line. Unknown keys fail
the suite.

## Adding a fixture

Add the workspace, its `MATRIX.json` entry and one line to `canaries!` in
`tests/e2e_bazel_build/baseline_light.rs`; the hermetic tests there fail until
the three agree. Run the canary on each Bazel version of the new cells before
listing them.
