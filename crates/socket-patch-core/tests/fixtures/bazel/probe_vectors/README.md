# Bazel probe vectors (X2, X3, X4, and the lockfile group's L1 / L6)

Evidence captured from real Bazel for the three probes the Bazel-support design adds (its
section "Probes this design adds"), and the `MODULE.bazel.lock` vectors of the campaign's
lockfile probe group that the same section names. Nothing here was written by socket-patch.
The files are test inputs for the pure Bazel readers of `socket_patch_core::bazel`, and the
record of why the design hypotheses stand or fall.

- Captured 2026-11-11 / 2026-11-12 on one macOS arm64 machine (Darwin 27.0.0), bazelisk
  1.30.0, each cell from `env -i` with an empty `HOME`, `--nohome_rc --nosystem_rc`, and
  its own output base. Nothing ran on Linux or Windows.
- Test mode. While X2 - X4 were captured the campaign's Bazel launcher exported
  `TEST_TMPDIR` on every command, and a Bazel server started with that variable runs in
  test mode. Every X2 - X4 cell therefore also set `ENABLE_BUG_REPORT_LOGGING_IN_TEST=1`
  and `NO_CRASH_ON_LOGGING_IN_TEST=1`, Bazel's own switches for production behaviour.
  Without them Bazel 7.7.2 answers the two failing `build` steps of X2
  (`stale_override_after_bump.build_without_repin` and `.build`) with `FATAL: bazel crashed
  due to an internal error` and exit 37; they are recorded here with exit 1, which is what
  a user sees. X2 and X4 ran both ways: nothing else differs, and the X4 locks are
  byte-identical (`x2/vectors.json` `environment`). A test that reruns a cell either keeps
  `TEST_TMPDIR` out of Bazel's environment or sets both variables. The lockfile group ran
  earlier on 2026-11-11, before the launcher exported the variable.
- The driver scripts, the cell workspaces, every command's log and the full reports are in
  the campaign's probe directories, outside this repository: `design-x/RESULTS.md` for
  X2 - X4, `lockfile/RESULTS.md` (rows L1.g and L6.a, sections L6 and 5) for `lockfile/`.
  `*/vectors.json` repeats each cell's exit codes and first error line.
- Machine paths are replaced with `<PROBE>`, `<OUTPUT_BASE>` and `<CAMPAIGN>` in every
  text that had one. The byte-real files had none.
- No file here has the literal name of a Bazel boundary file. A `MODULE.bazel`,
  `MODULE.bazel.lock`, `BUILD.bazel` or `WORKSPACE` of a probe workspace is committed with a
  prefix (`root.MODULE.bazel`, `9.3.2.MODULE.bazel.lock`, `sub-pkg.BUILD.bazel`), and the
  `workspace.files`, `fixture.files` or `file_names` member of the `vectors.json` beside it
  gives its path in the workspace. A test that needs the workspace copies the files to a
  temporary directory under those paths.

Check the tree in this directory with

    shasum -a 256 -c SHA256SUMS
    python3 check.py

`SHA256SUMS` lists every file here but itself. `check.py` (standard library, no Bazel)
checks what the checksums cannot: that every file is listed, that every file a
`vectors.json` names is there, that every workspace file a committed lock records (main
repository and `othermod`) has its bytes committed, and that the locks still show each
verdict below. `.gitattributes` marks the
directory `-text`: the CRLF, BOM and no-final-newline inputs are the point, and a
line-ending conversion on checkout would break both the digests in the locks and the
checksum file.

## Verdicts

| Probe | Hypothesis | Verdict |
|---|---|---|
| X4 | A recorded `MODULE.bazel.lock` input digest is the SHA-256 of the file's bytes on disk | Confirmed on Bazel 6.6.0, 7.0.2, 7.1.2, 7.4.1, 7.7.2, 8.0.0, 8.4.2, 8.7.0, 8.8.2, 9.1.1, 9.3.2 and 10.0.0rc3 (lock versions 3, 6, 11, 13, 16, 18, 24, 26, 28), nine inputs each. Refuted under a non-default `--digest_function` startup option (7.7.2, 8.8.2, 9.3.2): the value is then that function's digest, 40 hex digits for SHA-1 and 64 for BLAKE3 |
| X2 | Under Bzlmod a crate_universe hub exposes `BUILD.<name>-<version>.bazel`, so a spoke can be replaced with `override_repo` and nothing else | The hub file does not exist (rules_rust 0.75.0 on 7.7.2, 8.8.2, 9.3.2). `override_repo` itself leaves `cargo-bazel-lock.json` byte-identical and needs no repin. `MODULE.bazel.lock` is byte-identical too, but only because the `crate` extension has no entry in it: with `lockfile` and `cargo_lockfile` both set, as here, rules_rust reports the extension reproducible. For an extension that has an entry `override_repo` changes its `usagesDigest`, and `--lockfile_mode=error` fails until the lock is refreshed (campaign probe S10 and the starlark-include lock-touch table, toy extensions; not run here on a recorded hub). A substitute built from a copy of the spoke's BUILD file works for a crate with no crate dependency, fails for one that has any (unless the root module imports each dependency spoke), and breaks `bazel query 'deps(...)'`. A stale override after a version bump is a hard error |
| X3 | The output base holds the result of a reproducible extension, and gazelle's lock facts name the selected Go module version | Bazel 8.8.2 and 9.3.2 keep `<output_base>/MODULE.bazel.lock` in the workspace lock's format; its `go_deps` entry names version, sum and replacement of the selected module. 7.7.2 has no such file and nothing else that names the version. gazelle's facts are not a selection proof: they list the Socket module at its pin while Bazel builds an unpatched higher version, and after the replace is removed. The recorded root `go.mod` / `go.sum` digests are not a sufficient freshness test for that entry: `hosted` and `skew` record the same two digests and select different versions (below) |
| L1.g, L6.a (lockfile group) | A static reader that compares each recorded main-repository input with the SHA-256 of the file predicts Bazel's `error`-mode verdict | 34 of 34 vectors on 17 releases from 6.5.0 to 10.0.0rc3, fresh and stale. A CRLF copy of an input stales the entry (6.6.0, 7.0.2, 7.1.2, 7.7.2, 8.8.2, 9.3.2, 10.0.0rc3). A CRLF-encoded `MODULE.bazel.lock` is accepted in `error` mode and left CRLF by `update` on 7.7.2 and 9.3.2; the cells of the other five stopped early and recorded the acceptance only |

## X4: `x4/`

A root-module extension (`workspace/ext.bzl`, tagged in `workspace/x4.MODULE.bazel`) reads
nine files with `module_ctx.read` and is not reproducible, so the lock records each one.

| Path | What |
|---|---|
| `inputs/lf.lock`, `crlf.lock` | the same text with LF and with CRLF |
| `inputs/bom-crlf.lock`, `no-eol.lock`, `empty.lock`, `latin1.lock` | UTF-8 BOM + CRLF; no final newline; zero bytes; bytes that are not UTF-8 |
| `inputs/sub/pkg/nested.lock`, `inputs/sub/pkg/deep/dir/file.lock` | a file in a subpackage, and one in a subdirectory of that package (label `//sub/pkg:deep/dir/file.lock`) |
| `inputs/with space.lock` | a space in the name, which shows the key escaping |
| `workspace/x4.MODULE.bazel`, `ext.bzl`, `root.BUILD.bazel`, `sub-pkg.BUILD.bazel` | the workspace: `MODULE.bazel`, `ext.bzl`, `BUILD.bazel` and `sub/pkg/BUILD.bazel`. The last one makes `sub/pkg` a package; without it the two `//sub/pkg:` labels do not load and Bazel records nothing for the extension. With every `inputs/<path>` at `<path>`, `bazel mod deps --lockfile_mode=update` writes the committed lock byte for byte. Bazel 6.6.0 also needs an empty `WORKSPACE` at the root and `--enable_bzlmod` |
| `locks/<bazel>.MODULE.bazel.lock` | the lock that Bazel wrote, byte for byte, for 6.6.0 and 7.0.2 (version 3, `accumulatedFileDigests`), 7.7.2 (13, `recordedFileInputs`), 9.1.1 (26) and 8.8.2, 9.3.2 (28, `recordedInputs`). The workspace had `inputs/` at its root, so `@@//lf.lock` is `inputs/lf.lock` here |
| `locks/9.3.2.digest-sha1.MODULE.bazel.lock`, `locks/9.3.2.digest-blake3.MODULE.bazel.lock` | the lock Bazel 9.3.2 wrote for the same workspace under `--digest_function=sha1` and `=blake3`: no recorded value is the SHA-256 of its file. The SHA-1 values are 40 hex digits. The BLAKE3 values are 64, so length does not tell them from SHA-256; the lock does not name the function. A 9.3.2 server with the default function refuses both locks in `error` mode (exit 2) |
| `vectors.json` | per version: lock version, family, container, the JSON path, key and value of every input with its on-disk SHA-256; what a LF to CRLF rewrite and a byte-exact restore did; the `--digest_function` rows; a static cross-check against real-ruleset locks. Versions without a file under `locks/` have rows only (`lock_file` is null): 7.1.2, 7.4.1, 8.0.0, 8.4.2, 8.7.0 and 10.0.0rc3, for whose lock versions `lockfile/` has a byte-real lock, and the digest-function rows of 7.7.2 and 8.8.2 |

Key spellings (`vectors.json` `key_rules`): `@@//sub/pkg:deep/dir/file.lock` in
`accumulatedFileDigests`; `@@//sub/pkg/deep/dir/file.lock` in `recordedFileInputs`;
`FILE:@@//with\sspace.lock <hex>` strings in `recordedInputs` (backslash, newline and space
are escaped).

## X2: `x2/`

Fixture: a `rust_binary` on `cfg-if = "=1.0.0"`, hub `crates` from `crate.from_cargo` with
a `lockfile` and a `cargo_lockfile`. `vectors.json` has, per Bazel line, the hub's file
list and targets and every step's exit code and first error.

| Path | What |
|---|---|
| `hub.BUILD.bazel`, `hub.defs.bzl` | the generated hub files (identical on the three lines) |
| `spoke.cfg-if-1.0.0.BUILD.bazel`, `spoke.instant-0.1.13.BUILD.bazel` | generated spoke BUILD files; the second names its dependency as `@crates__cfg-if-1.0.0//:cfg_if` |
| `cargo-bazel-lock.json` | the crate lock the substitution left untouched |
| `locks/rr0.75.0-b9.3.2.baseline.MODULE.bazel.lock` | the workspace lock of the 9.3.2 cell before any override, byte for byte. Its only rules_rust entry is `internal_extensions.bzl%cu_nr`; `crate_universe:extensions.bzl%crate` is absent, which is why every `module_lock_unchanged: true` in `vectors.json` says nothing about a recorded hub (`module_lock_note`, `cells[].crate_extension_in_module_lock`) |
| `module/*.MODULE.bazel` | the five root module files tried: `build_file` from the hub (fails), from a committed copy (works), an `http_archive` substitute, and the two dependent-crate cases |

## X3: `x3/`

Fixture: a root `go.mod` requiring `github.com/jackc/pgx/v5 v5.7.0` and
`github.com/google/go-cmp v0.5.9`, gazelle 0.54.0 and 2.0.0-beta.2 with rules_go 0.65.0.
States, applied in order to one workspace: `baseline`, `dir` (a directory replace), `hosted`
(the production Socket fork replace), `skew` (`hosted` plus a second Bazel module that
requires pgx v5.7.1), `restored` (the baseline files again). The second module, `othermod`,
is reached with `local_path_override(path = "../othermod")`: its directory is beside the
workspace in every state, not in the output base.

| Path | What |
|---|---|
| `fixture/<state>.go.mod`, `<state>.go.sum` | the root's inputs; `skew` and `restored` reuse `hosted` and `baseline` |
| `fixture/othermod.go.mod`, `othermod.go.sum` | `../othermod/go.mod` and `go.sum`, both recorded by every `skew` entry (`FILE:@@othermod+//go.mod`, `FILE:@@othermod+//go.sum`) |
| `fixture/hosted.gz2.0.0-beta.2.MODULE.bazel`, `skew.gz2.0.0-beta.2.MODULE.bazel` | the root `MODULE.bazel` with gazelle 2.0.0-beta.2: every state but `skew`, and `skew`. `skew` is `hosted` plus three lines (a blank line, the `bazel_dep` on `othermod` and its `local_path_override`). The lock under `locks/` was written for the `skew` file; it has a `registryFileHashes` key for the `MODULE.bazel` of rules_go and gazelle and none for `othermod` |
| `fixture/othermod.gz2.0.0-beta.2.MODULE.bazel` | `../othermod/MODULE.bazel` of that cell |
| `hidden/<cell>.<state>.reduced.json` | the hidden lockfile **cut down** to the `go_deps` entry, the two watched repository specs, the `go.mod` / `go.sum` recorded inputs and the watched facts rows. Not byte-real: the real files are 0.6 to 0.76 MB. Key order and values are the file's own |
| `locks/gz2.0.0-beta.2-b9.3.2.skew.MODULE.bazel.lock` | one byte-real workspace lock with gazelle facts: the state where the facts name the Socket module while the build selects upstream v5.7.1 |
| `vectors.json` | per cell and state: the hidden lockfile's shape, size and digest, the two specs, the workspace facts rows and their count, whether the fetched pgx tree holds the patched bytes, and gazelle's version-conflict notes; `freshness_by_root_go_mod_digest[]` per cell with a hidden lockfile |

`main.go`, `../othermod/lib.go` and the BUILD files are not committed: no lock records them.

Bazel 8.8.2 writes empty-string attributes in a repository spec (`"replace": ""`); 9.3.2
omits them.

**The root pair is not a freshness test.** In all four cells with a hidden lockfile the
`hosted` and `skew` entries record the same `FILE:@@//go.mod` and `FILE:@@//go.sum` digests,
while the selected pgx is `v5.7.0-socketpatch.1` with the Socket replace in `hosted` (patched
tree fetched) and upstream `v5.7.1` in `skew` (unpatched tree). The two states differ on
disk in `MODULE.bazel` alone. Every recorded input of the `hosted` entry is also in the
`skew` entry (compared on the full files, `freshness_by_root_go_mod_digest[]`), so a
`hosted` entry left on disk after that edit, or after a branch switch, has no row that
fails, while the next build selects the unpatched version. What differs is `usagesDigest`,
which a static reader cannot recompute, and the two `FILE:@@othermod+//` rows that only
the `skew` entry has; `bzlTransitiveDigest` and `registryFileHashes` are equal. So neither
the root pair nor all the recorded rows together show that an entry belongs to the module
graph on disk. This is read off the recorded rows: no cell left a stale hidden lockfile on
disk and read it back.

## Lockfile group vectors: `lockfile/`

Imported byte for byte from the campaign's lockfile probe group (2026-11-11, same machine;
its `RESULTS.md` rows L1.g and L6.a, sections L6 and 5). A toy root-module extension
(`workspace/ext.bzl`, not reproducible) reads each tagged file with `module_ctx.read` and
makes one repository per `name=content` line; `//:consume` copies one of them.

| Path | What |
|---|---|
| `workspace/ext.bzl`, `root.BUILD.bazel`, `third_party-py.BUILD.bazel`, `other.BUILD.bazel`, `dep2.lock`, `a.patch` | the workspace sources shared by every vector and by the L6 cell: `ext.bzl`, `BUILD.bazel`, `third_party/py/BUILD.bazel`, `other/BUILD.bazel`, `dep2.lock`, `a.patch` (the L6 workspace has no `third_party/py`) |
| `recorded-inputs/bazel-<ver>/fresh/` | for 17 releases (6.5.0, 6.6.0, 7.0.2, 7.1.2, 7.2.0, 7.4.1, 7.7.2, 8.0.0, 8.1.0, 8.4.2, 8.6.0, 8.7.0, 8.8.2, 9.0.2, 9.1.1, 9.3.2, 10.0.0rc3; lock versions 3, 6, 11, 13, 16, 18, 24, 26, 28): `root.MODULE.bazel`, the two inputs `dep.lock` and `third_party/py/requirements lock.txt` (a subpackage, a space in the name), `root.MODULE.bazel.lock` as that release wrote it with `bazel build //:consume --lockfile_mode=update`, and `expected.json` |
| `recorded-inputs/bazel-<ver>/stale/` | the same with `requirements lock.txt` rewritten and the lock left alone |
| `expected.json` | the lockfile group's static reading of the lock (rows `key`, `path`, `recorded`, `actual`, `state`; `moduleFileHash` where the lock has one) and `bazel_error_mode_build_exit`, the exit code of `bazel build //:consume --lockfile_mode=error` in that state: 0 for every `fresh`, 1 for every `stale`. Its `key` is unescaped; `vectors.json` has the spelling in the lock |
| `l6-crlf-pair/bazel-7.0.2/` | one input with LF and with CRLF, and the lock for each (lock version 3). `lf/root.MODULE.bazel.lock` is what Bazel 7.0.2 wrote for `lf/dep.lock`. `crlf/root.MODULE.bazel.lock` is what it wrote after the input became `crlf/dep.lock`, with every LF of the lock then rewritten to CRLF by the probe driver; Bazel accepted that file in `error` mode (exit 0). With LF line endings it differs from the LF lock in one line, the recorded digest. `root.MODULE.bazel` is the module file of both |
| `vectors.json` | the index: per release the lock version, family, container, key spellings, exit codes and lock digest; the L6 pair with its digests and steps, and the exit codes of the same steps on the other releases the group ran (6.6.0, 7.1.2, 7.7.2, 8.8.2, 9.3.2, 10.0.0rc3; 8.4.2 ran the baseline only) |

This directory alone has a byte-real lock for each of the nine lock versions the releases
run here write (3, 6, 11, 13, 16, 18, 24, 26, 28). Versions 6, 11, 16, 18 and 24 are
nowhere else in this tree; 6 and 18 are what Bazel 7.1.2 and 8.4.2 write.

## Reruns from the committed files

The X4 workspace (6.6.0, 7.1.2, 9.3.2, and 9.3.2 under each digest function), three
recorded-input vectors (7.1.2, 8.4.2, 9.3.2) and the L6 pair (7.0.2) were rebuilt from the
files of this directory alone and run again on 2026-11-12: each wrote the lock recorded
here (byte for byte where the lock is committed, by its SHA-256 for X4 on 7.1.2) and
exited as recorded (`design-x/verify/result.json`, section 7 of the report). The X3 lock
cannot be reproduced that way: gazelle's facts keep rows from the states that came before
`skew`.

## Rules for tests that read these files

- Read bytes, never text with newline translation, and never rewrite a file in place.
- Do not derive a CRLF twin from `lf.lock`: `crlf.lock` is the twin, and both digests are
  in every lock. The same holds for `lockfile/l6-crlf-pair/`.
- Do not give a copy inside this repository the literal name `MODULE.bazel`, `BUILD.bazel`,
  `WORKSPACE` or `MODULE.bazel.lock`; rename only in a temporary directory.
- A file added here needs its line in `SHA256SUMS`, and `check.py` must still pass.
