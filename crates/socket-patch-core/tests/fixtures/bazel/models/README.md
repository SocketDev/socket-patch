# Module and WORKSPACE model fixtures

Inputs and goldens for the unit tests of the two file models of `socket_patch_core::bazel`:
`module_file.rs` (the root `MODULE.bazel` and its `include()` closure) and
`workspace_file.rs` (the `WORKSPACE` family, one level of macros, and `governing`). Nothing
here was written by socket-patch and nothing here is built: the workspace files of each
probe cell are strings inside a JSON file, so no file in this directory has the name of a
Bazel boundary file and the directory is not a Bazel workspace. A test builds each cell's
root in memory from its `files` map.

`.gitattributes` marks the directory `-text`. `SHA256SUMS` lists every file here but itself
and the `*.golden` files (`shasum -a 256 -c SHA256SUMS`); the test
`the_model_vectors_are_the_bytes_that_were_committed` of `workspace_file` compares each file
with its line, so a changed or added input needs its line there.

## Vectors captured from real Bazel

The first three come from the Bazel-support campaign's probes: 2026-11-11, one macOS arm64
machine (Darwin 27.0.0), bazelisk 1.30.0; nothing ran on Linux or Windows. The drivers, the
per-cell logs and the reports are in the campaign's probe directory, outside this
repository. `python3 reduce.py <campaign probes directory> .` rewrites the three files byte
for byte.

| File | Probe | What a cell holds |
|---|---|---|
| `s1c.json` | S1c, `starlark-include/RESULTS.md` section 2.1: 35 spellings and placements of `include()` and of the included file, through `bazel mod graph` on nine releases from 6.6.0 to 10.0.0rc3 | `files`: the root `MODULE.bazel` and the segments. `directories`: a path that is a directory where a file is expected. `bazel`: per release `ok` (the segment's `bazel_dep` is in the graph), `skipped` (exit 0 without it, under `--ignore_dev_dependency`), `error`, or `timeout` (no answer in 45 seconds: the self-including segment on 7.2.0 to 8.8.2) |
| `s2.json` | S2, the same report, section 2.2: 30 root and segment pairs on 7.2.0, 7.7.2, 8.8.2, 9.3.2 and 10.0.0rc3 | `files`; `flags`: the Bazel flags of the cell's commands; `bazel`: per release whether the cell passed and `seen`, the tags the probe's extension printed for the root module, one list per evaluation (`"a(dev)"` is a tag of a dev proxy) |
| `ws-order.json` | S6, `versions-hybrid/RESULTS.md` section 2.5: 20 `WORKSPACE` shapes that define the repository `dep` more than once, by literal rules, `maybe` and macros | `files`: the `WORKSPACE` and the macro files beside it (`macros/deps.bzl` belongs to another repository, `@macros`, and must not be read); `built`: the archive every one of the seven `runs` built (5.4.1 to 8.8.2, with and without Bzlmod); `query_shows`: what `bazel query --output=build //external:dep` printed, which differs from `built` in 7 cases |

### `ws-shapes.json`: shapes beyond S6

18 more `WORKSPACE` shapes, built by `ws_shapes.py` (in this directory) on 2026-11-12, on the
same machine and launcher, during the audit of the model readers: Bazel 5.4.1, 6.6.0, 7.7.2
`--enable_workspace --noenable_bzlmod`, 7.7.2 `--enable_workspace` with an empty
`MODULE.bazel` (Bzlmod on), and 8.8.2 `--enable_workspace --noenable_bzlmod`. The driver takes
the archives and the `BUILD` file of the S6 fixture (`versions-hybrid/fixtures/ws-order` of
the campaign's probes) and a Bazel launcher; `ws_shapes.py merge` over the five
`cases-*.json` files it wrote gives `ws-shapes.json` byte for byte. Nothing ran on Linux or
Windows.

A cell holds `files` (the `WORKSPACE` and every macro file of the run directory; `elsewhere/`
is another repository) and `built`: per run the content of `@dep//:marker.txt` that
`//:show` copied, or `null` when the build failed. `rule` and `inner` are what the probe's
own repository rule writes; `v1` and `v2` are the archives.

| Cases | Shape | What every run did |
|---|---|---|
| `s1a` - `s1d` | `http_archive` loaded by two `load` statements of one label | built as with one `load`; the order rule of S6 holds across them |
| `s2a` - `s2g` | a `name = repository_rule(...)` of a main-repository file, called at the top level and through `maybe` | the call defines the repository of its `name` and no other, under the order rule |
| `s2h` | a macro that calls a repository rule of its own file | the macro's rule is built |
| `s3a` | `workspace(name = "ws_shapes")`, then `load("@ws_shapes//:deps_plain.bzl", ...)` in a later chunk | the main repository's file is loaded |
| `s3b` | the same `load` in the chunk of the `workspace()` call | the build fails (Bazel reports a cycle) |
| `s3c` | `local_repository(name = "ws_shapes")` in the chunk of the `workspace()` call, then the `load` | 5.4.1 loads the file of that repository (`v2`); 6.6.0 and later the main repository's (`v1`) |
| `s3d` | the `local_repository` and no `workspace()` call | the file of that repository is loaded |
| `s3e`, `s3f` | a macro that calls a macro | the inner macro's rule is built, under the order rule |

One more cell was built by hand on the same day and is not in the file, because the reader
of a `WORKSPACE` file never sees the module: Bzlmod on, a root `MODULE.bazel` of
`bazel_dep(name = "ws_shapes")` and `local_path_override(module_name = "ws_shapes", path =
"elsewhere")`, `elsewhere/MODULE.bazel` of `module(name = "ws_shapes")`, and the `WORKSPACE`
of `s3a`. Bazel 6.6.0 `--enable_bzlmod`, 7.7.2 and 8.8.2 `--enable_workspace` each loaded the
main repository's file (`v1`): the name `workspace()` gives outranks a `bazel_dep` of the
same name.

## Real files

Each is a byte-for-byte copy of a file of a public repository at the tag given, and keeps the
licence of that repository (Apache-2.0).

| File | Source | Why it is here |
|---|---|---|
| `rules_rust-0.49.3-crate_universe.WORKSPACE` | bazelbuild/rules_rust `0.49.3` (`5f03718156f4`): `examples/crate_universe/WORKSPACE.bazel` | 19 `crates_repository` hubs whose arguments call `crate.annotation`, `crate.spec`, `render_config` and `splicing_config`, each followed by the `crate_repositories()` of its generated `defs.bzl` |
| `rules_rust-0.49.3-crate_universe-third_party_deps.bzl` | the same tag: `examples/crate_universe/multi_package/3rdparty/third_party_deps.bzl` | the example's own macro, which declares a repository under a name computed from its parameter |

## Goldens

What the readers produce, compared by the tests and regenerated with

    SOCKET_PATCH_BLESS_GOLDEN=1 cargo test -p socket-patch-core --lib -- bazel::module_file bazel::workspace_file

after an intended change (review the diff).

| File | Test | Content |
|---|---|---|
| `s1c.golden` | `module_file`: `s1c_cells_read_to_their_goldens_and_agree_with_bazel` | the model of each S1c cell: files, declarations and gaps |
| `s2.golden` | `module_file`: `s2_cells_read_to_their_goldens_and_agree_with_bazel` | the model of each S2 cell. The test also holds the tags of each cell against `seen` |
| `corpus-modules.golden` | `module_file`: `real_module_files_read` | counts for the 16 real `MODULE.bazel` files of `../starlark/corpus/` |
| `ws-order.golden` | `workspace_file`: `governing_gives_the_definition_bazel_built_for_the_20_s6_cases` | per S6 case what Bazel built, what `bazel query` showed, and the verdict of `governing("dep")` |
| `corpus-workspaces.golden` | `workspace_file`: `real_workspace_files_read` | counts for the 7 real `WORKSPACE` files of `../starlark/corpus/` |
| `ws-shapes.golden` | `workspace_file`: `governing_gives_the_definition_bazel_built_for_the_ws_shapes_cases` | per `ws-shapes` case what each of the five runs built and the verdict of `governing("dep")` |
