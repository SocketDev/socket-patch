# Committed registry subset

What the toy core fixture (`../core`) needs from the Bazel Central Registry so that a
`bazel_core_` cell resolves Bazel's own modules without the network. Written and checked by
`scripts/bazel-fixture-registry.py` (its docstring has the commands; `check` runs in
`scripts/tests/test_bazel_fixture_registry.py`). Do not edit a file here by hand, except this
one: then replace its line in `SHA256SUMS` (`shasum -a 256 README.md`), which the check compares.

| Path | What |
|---|---|
| `bazel_registry.json`, `modules/**` | The registry files, passed as `--registry=file://`. One tree: the union over the Bazel versions of `MANIFEST.json`, not a directory per version. A version reads only the files its own entry accounts for. |
| `distdir/<bazel version>/` | The module archives a cold build of the toy fixture fetches, passed as `--distdir`. Only where they are small. Bazel 8.8.2 fetches 12.4 MB, so it has no directory and its cells take the archives from a repository cache. |
| `MANIFEST.json` | Per Bazel version: where the file list comes from, and the archives. |
| `SHA256SUMS` | Every file here but itself. |

No `modules/<name>/metadata.json` is mirrored. It is the yanked-version list, the one registry
file upstream rewrites; a registry without it yanks nothing.

## Where each version's file list comes from

| Bazel | Source | What vouches for a file |
|---|---|---|
| 7.7.2, 8.8.2, 9.3.2 | `lock`: the committed `core/bzlmod/<era>/locks/v<N>/MODULE.bazel.lock`, made by `bazel mod deps --lockfile_mode=update` under that Bazel against `https://bcr.bazel.build/` | the sha256 the lock's `registryFileHashes` pins |
| 6.6.0, 7.0.2, 7.1.2 | `recorded`: the registry files that cold builds of `core/bzlmod/<era>` and `core/hybrid/<era>` asked for, taken from a checkout of bazel-central-registry | the sha256 the checkout had, written into the entry with the checkout's commit. Where a lock above pins the same file the two must agree (more than half of each list); the rest stand on the record |

The three older versions write a lock with no `registryFileHashes`, and their lock names the
registry it was made against (`flags.cmdRegistries`; under a `file://` registry also absolute
paths in `repoSpec`). A lock made against the central registry therefore fails
`--lockfile_mode=error` here (`the value of --registry flag has been modified`, exit 48), and
one made here cannot be committed. Their fixtures commit no lock: every cell on them makes its
lock in the test.

A patch file and a module archive are vouched for by the `integrity` values of the module's
`source.json`, itself one of the files above.

## Provenance

Recorded on 2026-11-12 on macOS arm64. The registry files are copies from
`https://github.com/bazelbuild/bazel-central-registry` at commit
`bdcd0450114ec0a66c22d43c9fe74996ad3f508e`; the archives are the files each `source.json`
names, as Bazel downloaded them from `github.com` into an empty repository cache. Nothing ran
on Linux x86_64 or Windows.
