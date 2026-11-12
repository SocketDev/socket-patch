# `MODULE.bazel.lock` fixtures

Locks that real Bazel wrote, for the tests of `socket_patch_core::bazel::module_lock` and
`bazel::ruleset_version`. Nothing here was written by socket-patch.

- Captured 2026-11-11 on one macOS arm64 machine (Darwin 27.0.0) with bazelisk 1.30.0,
  `--nohome_rc --nosystem_rc`, one output base per cell. `eval-factors/` also has entries that a
  Linux arm64 container wrote. Nothing ran on Linux x86_64 or on Windows.
- Each file is a byte-for-byte copy from the campaign's probe directories, which are outside this
  repository. The one exception is `paket/dn-7.7.2-0.14.0.reduced.MODULE.bazel.lock` (below).
  No file holds a machine path.
- No file has the literal name of a Bazel boundary file: a `MODULE.bazel` is committed as
  `root.MODULE.bazel` or `<name>.MODULE.bazel`, a lock as `<name>.MODULE.bazel.lock`. A test maps
  the name back when it builds a workspace view.
- `.gitattributes` marks the directory `-text`. A recorded digest is the SHA-256 of a file's
  bytes, so a line-ending conversion on checkout would stale every lock here.
- `SHA256SUMS` lists every file but itself (`shasum -a 256 -c SHA256SUMS`); a unit test checks it.

The 34 recorded-input vectors of the lockfile probe (one byte-real lock per `lockFileVersion`
3, 6, 11, 13, 16, 18, 24, 26 and 28, fresh and stale), its CRLF pair and the X4 vectors are in
`../probe_vectors/`, where the probe-vectors package committed them. The tests read them from
there; they are not copied here.

## `gv3/`: a family-B lock cannot be proven fresh

Probe L7 gv3 (`versions-hybrid/RESULTS.md` 2.3). Root module `mvs_lift`: `gazelle 0.36.0`,
`rules_go 0.61.1`, `bazel_skylib 1.5.0`. rules_go lifts gazelle to 0.51.3.

| File | What |
|---|---|
| `fresh.MODULE.bazel` | the root file both locks were written for |
| `7.7.2.MODULE.bazel.lock`, `9.3.2.MODULE.bazel.lock` | the locks (versions 13 and 28): one `.../modules/gazelle/0.51.3/source.json` key |
| `lower.MODULE.bazel` | the `rules_go` line deleted, lock untouched. `bazel mod graph` then selects `gazelle@0.36.0` on both releases, and the lock still says 0.51.3 and passes every static check |
| `raise.MODULE.bazel` | `gazelle` raised to 0.54.0, lock untouched: declared above locked, which a static check does see |

Source: `versions-hybrid/vectors/locks/mvs-lift/<bazel>/` and `.../stale/9.3.2/{lower,raise}/`.

## `facts/`: the top-level `facts` of Bazel 8.5 and later

Probe L3 (`lockfile/RESULTS.md`, section L3). Every lock is version 28 and has no
`moduleExtensions` entry for the extension whose facts it holds.

| Directory | Cell | Files |
|---|---|---|
| `pip-v1/` | rules_python 2.0.3 on Bazel 8.8.2, `fact_version` `v1` (bare hex) | `baseline`: 32 packages for a two-package requirements file, `six` with four members (another module's hub pins 1.16.0). `bazel-repaired`: after the `six` line became a direct reference and `bazel mod deps --lockfile_mode=update` ran; two members removed, `six` kept |
| `pip-v2/` | rules_python 2.5.0-rc4 on Bazel 9.3.2, `fact_version` `v2` (`sha256:<hex>`) | `baseline`, and `bazel-repaired`, where `six` is gone |
| `go-deps/` | gazelle 2.0.0-beta.2, rules_go 0.65.0 on Bazel 9.3.2 | `baseline`: 172 list members. `bazel-repaired`: 173, after `replace github.com/pkg/errors => github.com/pkg/errors v0.8.1` (`after-rewrite.go.mod`, `after-rewrite.go.sum`); a member was added, none replaced. Both also hold rules_go's `go_sdk` facts |
| `toy/` | a root-module extension that returns facts (`ext.bzl`), Bazel 8.8.2 | `baseline`, and `hand-repaired` with the `dep_a@index` key deleted, which Bazel accepted (`after-rewrite.dep.lock` is the input in that state) |

Source: `lockfile/vectors/facts/l3-rp2.0.3-b8.8.2/`, `l3-rp2.5.0-rc4-b9.3.2/`,
`l3-gz2.0.0-beta.2-b9.3.2/` (its `final` lock is `bazel-repaired` here) and `l3-toy-8.8.2/`.

## `stale-repair/`: a forged digest

Probe L1 (`lockfile/RESULTS.md`, steps S0, S5, S6), on Bazel 7.0.2 (lock version 3), 7.7.2 (13)
and 9.3.2 (28). The toy extension (`ext.bzl`, `root.MODULE.bazel`) reads `//:dep.lock` and makes
one repository per line.

| File | What |
|---|---|
| `dep.lock.before`, `dep.lock.after` | the input before and after `dep_a=upstream-a-1.0` became `dep_a=socket-patched-a-1.0` |
| `baseline.MODULE.bazel.lock` | written for `dep.lock.before` |
| `updated.MODULE.bazel.lock` | what `--lockfile_mode=update` wrote for `dep.lock.after`: the new digest and `"content": "socket-patched-a-1.0"` in the repository spec |
| `forged.MODULE.bazel.lock` | `baseline` with only the digest replaced by hand. `--lockfile_mode=error` exits 0 on it and the build consumes `upstream-a-1.0`; `bazel mod deps --lockfile_mode=update` leaves it as it is |

Source: `lockfile/vectors/stale-repair/bazel-<version>/`.

## `eval-factors/`: entries per platform

Probe L4.a (`lockfile/RESULTS.md`, section L4), Bazel 9.3.2, the toy extension declared
`os_dependent` and `arch_dependent`, one workspace shared by the macOS host and a Linux arm64
container. The input is `stale-repair/bazel-9.3.2/dep.lock.{before,after}`.

| File | What |
|---|---|
| `9.3.2.two-platforms.MODULE.bazel.lock` | entries `os:osx,arch:aarch64` and `os:linux,arch:aarch64`, both for `dep.lock.before` |
| `9.3.2.after-macos-repair.MODULE.bazel.lock` | after the rewrite and `bazel mod deps --lockfile_mode=update` on macOS only: the Linux entry keeps the old digest and the old repository spec, and the Linux `error`-mode build exits 1 |

Source: `lockfile/vectors/eval-factors/l4-linux-9.3.2/`.

## `paket/`: an entry that goes stale through `bzlTransitiveDigest`

Probes U3 and B2 (`ruby-dotnet/RESULTS.md` 2.6). A generated paket extension that does not
return `reproducible = True` has a lock entry, keyed without `@@`, and records no file: editing
the `paket.<group>.bzl` it loads fails `--lockfile_mode=error` with `... or one of its transitive
.bzl files has changed`.

| File | What |
|---|---|
| `dn-9.3.2-0.22.2.MODULE.bazel.lock`, `.MODULE.bazel` | rules_dotnet 0.22.2 on Bazel 9.3.2, lock version 28. Entry `//deps:paket.oldgen_extension.bzl%oldgen_extension` (the pre-0.19 generated shape); the 0.22.2-shape `main_extension` is reproducible and has none |
| `dn-7.7.2-0.14.0.MODULE.bazel` | the root file of the 7.7.2 cell, rules_dotnet 0.14.0 |
| `dn-7.7.2-0.14.0.reduced.MODULE.bazel.lock` | **not byte-real.** The lock of that cell (version 13, 616,839 bytes, SHA-256 `9ef5a1949cae974001b4050c14dfbed43dd9dd406f4a2807acfe7085203dd0ec`) without five `moduleExtensions` members of other modules: rules_dotnet's `paket2bazel_dependencies_extension` and `rules_dotnet_nuget_packages_extension`, rules_jvm_external's `maven` and `non_module_deps`, rules_python's `internal_deps`. Everything else, entry `//deps:paket.main_extension.bzl%main_extension` included, is the text Bazel wrote: the file was parsed and written back with two-space indentation, which reproduces the full lock byte for byte before the five members are removed |

The Socket URLs in these two locks are fixture values (`33333333-...`, `6c6c6c6c-...`).

Source: `ruby-dotnet/dn-9.3.2-0.22.2/`, `ruby-dotnet/dn-7.7.2-0.14.0/`.
