# Workspace shapes for the detection cross test

Inputs and the golden of `tests/bazel_golden/detect_fixtures.rs`. Each `*.txt` file is one
Bazel workspace: a comment, then the files of the workspace, each after a line
`=== <path relative to the Bazel root>`. The test stages a workspace into a temporary
directory and reads it from disk, as a run does. A workspace is kept in one text file so that
no file in this directory has the name of a Bazel boundary file: the directory is not a Bazel
workspace, and nothing here is built.

`.gitattributes` marks the directory `-text`.

## What is here, and why it is not a real-Bazel fixture

The workspaces the real-Bazel cells build are under
`crates/socket-patch-cli/tests/fixtures/bazel/{core,light,heavy}`; the cross test reads
those too. This directory holds the shapes no cell builds, written by hand from the rulesets'
documentation and from the recognizers' own unit tests:

| Files | Shape |
|---|---|
| `row<NN>-*.txt` | a row of the outcome table (design 4.2) that every mode refuses, or a `WORKSPACE` signature of design 2.7 with no cell: import mode, `npm_install`, `multi_pip_parse`, `pip_install`, rules_pycross over `pdm.lock` and a generated `.bzl`, `maven_install`, `crates_repository`, `crate.from_specs`, `crates_vendor`, cargo-raze, `rb_bundle` and `ruby_bundle`, the paket files in a `WORKSPACE`, and the report-only shapes |
| `dynamic-*.txt` | declarations that cannot be followed: a computed lock label or hub name, a hub behind another repository's function, a computed `use_extension` label |

No lock in a workspace is a real one: each holds the few bytes a recognizer reads (a
`lockfileVersion` line, an empty JSON object), because the cross test is about which
declaration names which file, not about what the lock pins.

## The golden

`expected.golden` is the model of every workspace here as the test renders it: the Bazel
line, the dependency system, each hub with its shape, liveness, ruleset version and files,
each signal, and the governance of every ecosystem and project that is not ungoverned.
Regenerate it after an intended change and review the diff:

    SOCKET_PATCH_BLESS_GOLDEN=1 cargo test -p socket-patch-core --test bazel_golden detect_fixtures

The tables in the test (`SIGNATURES`, `ROWS`) hold whatever the golden says: each signature
of design 2.7 is found on its workspace, each row of design 4.2 has a workspace of its shape,
and the dynamic workspaces are incomplete and undetermined.
