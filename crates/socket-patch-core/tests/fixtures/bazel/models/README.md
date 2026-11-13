# Module and WORKSPACE model fixtures

Inputs and goldens for the unit tests of the two file models of `socket_patch_core::bazel`:
`module_file.rs` (the root `MODULE.bazel` and its `include()` closure) and
`workspace_file.rs` (the `WORKSPACE` family, one level of macros, and `governing`). Nothing
here was written by socket-patch and nothing here is built: the workspace files of each
probe cell are strings inside a JSON file, so no file in this directory has the name of a
Bazel boundary file and the directory is not a Bazel workspace. A test builds each cell's
root in memory from its `files` map.

`.gitattributes` marks the directory `-text`.

## Vectors captured from real Bazel

All three come from the Bazel-support campaign's probes: 2026-11-11, one macOS arm64
machine (Darwin 27.0.0), bazelisk 1.30.0; nothing ran on Linux or Windows. The drivers, the
per-cell logs and the reports are in the campaign's probe directory, outside this
repository. `python3 reduce.py <campaign probes directory> .` rewrites the three files byte
for byte.

| File | Probe | What a cell holds |
|---|---|---|
| `s1c.json` | S1c, `starlark-include/RESULTS.md` section 2.1: 35 spellings and placements of `include()` and of the included file, through `bazel mod graph` on nine releases from 6.6.0 to 10.0.0rc3 | `files`: the root `MODULE.bazel` and the segments. `directories`: a path that is a directory where a file is expected. `bazel`: per release `ok` (the segment's `bazel_dep` is in the graph), `skipped` (exit 0 without it, under `--ignore_dev_dependency`), `error`, or `timeout` (no answer in 45 seconds: the self-including segment on 7.2.0 to 8.8.2) |
| `s2.json` | S2, the same report, section 2.2: 30 root and segment pairs on 7.2.0, 7.7.2, 8.8.2, 9.3.2 and 10.0.0rc3 | `files`; `flags`: the Bazel flags of the cell's commands; `bazel`: per release whether the cell passed and `seen`, the tags the probe's extension printed for the root module, one list per evaluation (`"a(dev)"` is a tag of a dev proxy) |
| `ws-order.json` | S6, `versions-hybrid/RESULTS.md` section 2.5: 20 `WORKSPACE` shapes that define the repository `dep` more than once, by literal rules, `maybe` and macros | `files`: the `WORKSPACE` and the macro files beside it (`macros/deps.bzl` belongs to another repository, `@macros`, and must not be read); `built`: the archive every one of the seven `runs` built (5.4.1 to 8.8.2, with and without Bzlmod); `query_shows`: what `bazel query --output=build //external:dep` printed, which differs from `built` in 7 cases |

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
| `corpus-workspaces.golden` | `workspace_file`: `real_workspace_files_read` | counts for the 8 real `WORKSPACE` files of `../starlark/corpus/` |
