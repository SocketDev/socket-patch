# Bazel design-probe vectors (X2, X3, X4)

Evidence captured from real Bazel for the three probes the Bazel-support design adds (its
section "Probes this design adds"). Nothing here was written by socket-patch. The files are
test inputs for the pure Bazel readers of `socket_patch_core::bazel`, and the record of why
three design hypotheses stand or fall.

- Captured 2026-11-11 / 2026-11-12 on one macOS arm64 machine (Darwin 27.0.0), bazelisk
  1.30.0, each cell from `env -i` with an empty `HOME`, `--nohome_rc --nosystem_rc`, and
  its own output base. Nothing ran on Linux or Windows.
- The driver scripts, the cell workspaces, every command's log and the full report
  (`RESULTS.md`) are in the campaign's probe directory `design-x`, outside this
  repository. `*/vectors.json` repeats each cell's exit codes and first error line.
- Machine paths are replaced with `<PROBE>`, `<OUTPUT_BASE>` and `<CAMPAIGN>` in every
  text that had one. The byte-real files had none.

Check the tree with `shasum -a 256 -c SHA256SUMS` in this directory. `SHA256SUMS` lists
every file here but itself. `.gitattributes` marks the directory `-text`: the CRLF, BOM
and no-final-newline inputs are the point, and a line-ending conversion on checkout would
break both the digests in the locks and the checksum file.

## Verdicts

| Probe | Hypothesis | Verdict |
|---|---|---|
| X4 | A recorded `MODULE.bazel.lock` input digest is the SHA-256 of the file's bytes on disk | Confirmed on Bazel 6.6.0, 7.0.2, 7.1.2, 7.4.1, 7.7.2, 8.0.0, 8.4.2, 8.7.0, 8.8.2, 9.1.1, 9.3.2 and 10.0.0rc3 (lock versions 3, 6, 11, 13, 16, 18, 24, 26, 28), nine inputs each. Refuted under a non-default `--digest_function` startup option (7.7.2, 8.8.2, 9.3.2): the value is then that function's digest |
| X2 | Under Bzlmod a crate_universe hub exposes `BUILD.<name>-<version>.bazel`, so a spoke can be replaced with `override_repo` and nothing else | The hub file does not exist (rules_rust 0.75.0 on 7.7.2, 8.8.2, 9.3.2). `override_repo` itself leaves `cargo-bazel-lock.json` and `MODULE.bazel.lock` byte-identical and needs no repin. A substitute built from a copy of the spoke's BUILD file works for a crate with no crate dependency, fails for one that has any (unless the root module imports each dependency spoke), and breaks `bazel query 'deps(...)'`. A stale override after a version bump is a hard error |
| X3 | The output base holds the result of a reproducible extension, and gazelle's lock facts name the selected Go module version | Bazel 8.8.2 and 9.3.2 keep `<output_base>/MODULE.bazel.lock` in the workspace lock's format; its `go_deps` entry names version, sum and replacement of the selected module. 7.7.2 has no such file and nothing else that names the version. gazelle's facts are not a selection proof: they list the Socket module at its pin while Bazel builds an unpatched higher version, and after the replace is removed |

## X4: `x4/`

A root-module extension (`workspace/ext.bzl`, tagged in `workspace/x4.MODULE.bazel`) reads
nine files with `module_ctx.read` and is not reproducible, so the lock records each one.

| Path | What |
|---|---|
| `inputs/lf.lock`, `crlf.lock` | the same text with LF and with CRLF |
| `inputs/bom-crlf.lock`, `no-eol.lock`, `empty.lock`, `latin1.lock` | UTF-8 BOM + CRLF; no final newline; zero bytes; bytes that are not UTF-8 |
| `inputs/sub/pkg/nested.lock`, `inputs/sub/pkg/deep/dir/file.lock` | a file in a subpackage, and one in a subdirectory of that package (label `//sub/pkg:deep/dir/file.lock`) |
| `inputs/with space.lock` | a space in the name, which shows the key escaping |
| `locks/<bazel>.MODULE.bazel.lock` | the lock that Bazel wrote, byte for byte, for 6.6.0 and 7.0.2 (version 3, `accumulatedFileDigests`), 7.7.2 (13, `recordedFileInputs`), 9.1.1 (26) and 8.8.2, 9.3.2 (28, `recordedInputs`). The workspace had `inputs/` at its root, so `@@//lf.lock` is `inputs/lf.lock` here |
| `vectors.json` | per version: lock version, family, container, the JSON path, key and value of every input with its on-disk SHA-256; what a LF to CRLF rewrite and a byte-exact restore did; the `--digest_function` rows; a static cross-check against real-ruleset locks. Versions without a file under `locks/` have rows only |

Key spellings (`vectors.json` `key_rules`): `@@//sub/pkg:deep/dir/file.lock` in
`accumulatedFileDigests`; `@@//sub/pkg/deep/dir/file.lock` in `recordedFileInputs`;
`FILE:@@//with\sspace.lock <hex>` strings in `recordedInputs` (backslash, newline and space
are escaped).

## X2: `x2/`

Fixture: a `rust_binary` on `cfg-if = "=1.0.0"`, hub `crates` from `crate.from_cargo` with
a `lockfile`. `vectors.json` has, per Bazel line, the hub's file list and targets and every
step's exit code and first error.

| Path | What |
|---|---|
| `hub.BUILD.bazel`, `hub.defs.bzl` | the generated hub files (identical on the three lines) |
| `spoke.cfg-if-1.0.0.BUILD.bazel`, `spoke.instant-0.1.13.BUILD.bazel` | generated spoke BUILD files; the second names its dependency as `@crates__cfg-if-1.0.0//:cfg_if` |
| `cargo-bazel-lock.json` | the crate lock the substitution left untouched |
| `module/*.MODULE.bazel` | the five root module files tried: `build_file` from the hub (fails), from a committed copy (works), an `http_archive` substitute, and the two dependent-crate cases |

## X3: `x3/`

Fixture: a root `go.mod` requiring `github.com/jackc/pgx/v5 v5.7.0` and
`github.com/google/go-cmp v0.5.9`, gazelle 0.54.0 and 2.0.0-beta.2 with rules_go 0.65.0.
States, applied in order to one workspace: `baseline`, `dir` (a directory replace), `hosted`
(the production Socket fork replace), `skew` (`hosted` plus a second Bazel module that
requires pgx v5.7.1), `restored` (the baseline files again).

| Path | What |
|---|---|
| `fixture/<state>.go.mod`, `<state>.go.sum`, `othermod.go.mod` | the inputs; `skew` and `restored` reuse `hosted` and `baseline` |
| `hidden/<cell>.<state>.reduced.json` | the hidden lockfile **cut down** to the `go_deps` entry, the two watched repository specs, the `go.mod` / `go.sum` recorded inputs and the watched facts rows. Not byte-real: the real files are 0.6 to 0.76 MB. Key order and values are the file's own |
| `locks/gz2.0.0-beta.2-b9.3.2.skew.MODULE.bazel.lock` | one byte-real workspace lock with gazelle facts: the state where the facts name the Socket module while the build selects upstream v5.7.1 |
| `vectors.json` | per cell and state: the hidden lockfile's shape, size and digest, the two specs, the workspace facts rows and their count, whether the fetched pgx tree holds the patched bytes, and gazelle's version-conflict notes |

Bazel 8.8.2 writes empty-string attributes in a repository spec (`"replace": ""`); 9.3.2
omits them.

## Rules for tests that read these files

- Read bytes, never text with newline translation, and never rewrite a file in place.
- Do not derive a CRLF twin from `lf.lock`: `crlf.lock` is the twin, and both digests are
  in every lock.
- A file added here needs its line in `SHA256SUMS`.
