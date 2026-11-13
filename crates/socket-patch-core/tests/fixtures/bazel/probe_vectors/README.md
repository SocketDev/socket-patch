# Bazel probe vectors (X2, X3, X4, the lockfile group's L1 / L6, and the output-tree layouts)

Evidence captured from real Bazel for the three probes the Bazel-support design adds (its
section "Probes this design adds"), the `MODULE.bazel.lock` vectors of the campaign's
lockfile probe group that the same section names, and the on-disk layouts of Bazel-owned
trees that four other probe groups recorded (the design's section "Output-tree
classifier"). Nothing here was written by socket-patch. The files are test inputs for the
pure Bazel readers of `socket_patch_core::bazel`, and the record of why the design
hypotheses stand or fall.

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
  `TEST_TMPDIR` out of Bazel's environment or sets both variables. The lockfile group and
  the four groups of the output-tree layouts ran earlier on 2026-11-11, before the
  launcher exported the variable.
- The driver scripts, the cell workspaces, every command's log and the full reports are in
  the campaign's probe directories, outside this repository: `design-x/RESULTS.md` for
  X2 - X4, `lockfile/RESULTS.md` (rows L1.g and L6.a, sections L6 and 5) for `lockfile/`,
  and the `RESULTS.md` of `core-external-edits`, `core-output-base` and `platform-server`
  (each one's section 5, "Test vectors written") and of `test-infra-offline` (sections
  2.6 and 5) for the output-tree layouts.
  `*/vectors.json` repeats each cell's exit codes and first error line.
- Machine paths are replaced with `<PROBE>`, `<OUTPUT_BASE>` and `<CAMPAIGN>` in every
  text that had one. The byte-real files had none. The layout vectors also carried the
  machine's host and user names in two file names, replaced with `host` and `user`
  ("Output-tree layouts" below). The URLs of the repository-cache sample are public
  registry and release URLs, as Bazel requested them.
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
repository and `othermod`) has its bytes committed, that the locks still show each
verdict below, that every recorded layout still gives its recorded classification, and
that the repository-cache sample still holds each shape it was taken for.
`.gitattributes` marks the
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
| Output-tree layouts (`core-external-edits`, `core-output-base`, `platform-server`, `test-infra-offline` groups) | A tree Bazel owns is known by a marker Bazel writes and never by a name; a convenience link names its output base when its target is cut at the segment `execroot`; the path of a repository-cache entry and the name of its `id-` file follow from the checksum and the canonical id; an entry need not have an `id-` file | The groups' prototypes agree with the real trees: 42 of 42 query paths over 10 layouts (5.4.1 to 10.0.0rc3), 24 of 24 links, 35 of 35 cache entries (6.6.0, 7.7.2, 9.3.2). Of the 842 cached downloads of five more runs (6.6.0, 7.7.2, 8.8.2, 9.3.2) 797 have no `id-` file and one is under `sha384`; where a file is there it is the hash of the URL, 45 of 45. These are recordings for the classifier's tests, not a run of socket-patch |

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

## Output-tree layouts: `core-external-edits/`, `core-output-base/`, `platform-server/`, `test-infra-offline/`

What real Bazel left on disk in the kinds of tree the output-tree classifier
(`socket_patch_core::bazel::output_tree`) has to recognise: an output base, an entry of the
repo contents cache, a vendor directory, the convenience links, and the repository cache.
Four other probe groups of the campaign recorded them on 2026-11-11 on the same machine,
each with its own harness, which its report describes (not the `env -i` cells above). The
classifier's tests fabricate their trees; these files are the shapes Bazel itself made,
for the tests that need no Bazel.

Each file keeps its path under the campaign's probes directory, so a citation of the
design names the file here; the one sample (`observed.sample.json`, below) stands beside
the path of the probe file it was taken from. `import_layouts.py <probes directory>`
wrote them. It pins the SHA-256 of each probe file. In the twelve files it copies it
changes three things, all of which named the capture machine:

- the campaign directory is `<CAMPAIGN>` (the two `detect` fields below, and every path
  of `link_route.json`);
- the log file of a Bazel server, `java.log.<host>.<user>.log.java.<time>.<pid>` in the
  top level of each recorded output base, is `java.log.host.user.log.java.<time>.<pid>`;
- the directory `_bazel_<user>` of an output user root is `_bazel_user` (twelve paths of
  `link_route.json`).

`repo_cache_vectors.json` had none of them and is the probe's file byte for byte. The
rows of `observed.sample.json` had none either and are the probe's rows unchanged; the
import refuses a row that one of the three rewrites would touch.

| Path | What |
|---|---|
| `core-external-edits/vectors/detect/<bazel>-<cfg>.json` | ten layouts of one fixture: an archive consumed as `dep_http` (`http_archive`) and as `dep_plain` (a repository rule that never enters the contents cache). `<cfg>` is `default` (5.4.1, 6.6.0, 7.7.2, 8.8.2: no flag), `cc` (8.3.1, 8.8.2, 9.3.2, 10.0.0rc3: `--repo_contents_cache=<CACHE>`) or `vendor` (7.7.2, 9.3.2: `bazel vendor` of both repositories, then a build with `--vendor_dir=vendor_src`) |
| its `tree` | the entries a classifier can ask about, each with `path`, `type` (`file`, `dir`, `symlink`), `mode`, the `target` of a link, and the `content` of the files whose bytes matter: `DO_NOT_BUILD_HERE` (the workspace path), `<entry>.recorded_inputs`, `@<repo>.marker`, `VENDOR.bazel`. It covers the top level of the output base, `execroot/DO_NOT_BUILD_HERE`, every entry of `external/`, the two repositories in full wherever they live, the files in the root of the contents cache, the workspace's links and the vendor directory. A path can be listed twice, with the same entry |
| its `expect` | four or five query paths (42 in all), each with `kinds`, the `canonical` path with every link followed, and the `output_base`, `cache_entry` and `vendor_dir` the markers name, or null |
| `core-output-base/proto/vectors/link_route.json` | 24 convenience links in six sets of four (`out`, `bin`, `testlogs`, the workspace's name): the default prefix on 9.3.2 and on 7.7.2; `dist/` as the prefix (7.7.2); after an upgrade from 8.8.2 to 9.3.2, where the links name the 9.3.2 base under `$HOME/Library/Caches/bazel` while the 8.8.2 base of the same name was still on disk under another root; a `startup --output_base` shared by two workspaces (7.7.2); and `--output_base=<workspace>/out` (7.7.2), a base inside the checkout. Each row has the `workspace`, the `link` name under it with its `prefix`, the `readlink` `target`, the `expected_output_base`, and `marker`, the content of `DO_NOT_BUILD_HERE` in that base |
| `platform-server/vectors/repo_cache_vectors.json` | 35 entries found in the repository caches Bazel 6.6.0, 7.7.2 and 9.3.2 wrote for downloads from a local fake server (the URLs carry made-up tokens). `entry_dir` is the entry under the cache root, `content_addressable/sha256/<64 hex>` (27) or `content_addressable/sha512/<128 hex>` (8, where `checksum` is an SRI `sha512-` string); the payload is the file named `file` in it, and `observed_id_marker` is the empty `id-<hex>` file beside it: the entry's own hash function over `canonical_id`, which in every row is the URL list joined by one space |
| `test-infra-offline/vectors/repo_cache/observed.sample.json` | a **sample** of the probe's `observed.json` (880 rows, 0.5 MB, not committed; `source` has its path and SHA-256): every URL that five runs fetched through the group's recording server and that was answered, each looked up afterwards in the repository cache of its run. A `run` is `<fixture>-<bazel>`: `skylib` (a `bazel_dep` on bazel_skylib 1.8.2) on 6.6.0, 7.7.2 and 9.3.2, `js` (aspect_rules_js 3.6.0, two npm packages) and `jvm` (rules_jvm_external 7.2 with a `maven_install.json`) on 8.8.2. Unlike the 35 entries above these were not collected from `id-` files |
| its `rows` | 39 rows of the probe, unchanged and in its order: the first three of each of the 14 shapes (run, host of the URL, `key_type`, whether an `id-` file is there). `cache_file` is the payload under the cache root, `content_addressable/<key_type>/<hex>/file`: the probe hashed the bytes the server sent with each function and looked for the entry, so `key_type` is the kind it was found under and `integrity` the SRI form of that digest; `bytes` is the size; `id_markers_present` lists the `id-` files beside the payload, none or one; `id_marker_if_canonical_id_is_url` is the file a caller that passes the URL as canonical id would leave, and `canonical_id_is_url` says whether that file is the one there. The three rows with `key_type` null have none of these members: the 6.6.0 run left the registry's files in no cache directory |
| its `source_shapes`, `source_totals` | the row count of each shape in the whole probe file, and the sums: 842 downloads in a cache directory (839 under `sha256`, 2 under `sha512`, 1 under `sha384`), 45 with an `id-` file, 797 without, 38 in no cache directory. The import refuses the probe file unless each of the 842 is where its checksum puts it and each `id-` file is the hash of the URL |

Tokens in a `detect` vector: `<OB>` the output base, `<WS>` the workspace, `<CACHE>` the
root of the repo contents cache, `<INSTALL>` the directory of install bases. A test picks
a directory for each, in memory or on disk. `<CAMPAIGN>` appears in two fields that no
rule reads: `workspace_path_hashed` and the `FILE:` line of a `.marker`. In
`link_route.json` every path starts with `<CAMPAIGN>`.

The `kinds` are the prototype's names for the classifier's classes, and a path can have
several because it is judged as spelled and as resolved:

| `kinds` value | Rule the prototype applied |
|---|---|
| `bazel_output_base` | an ancestor holds a regular file `DO_NOT_BUILD_HERE`, and the path is under its `external` or `execroot` |
| `bazel_repo_contents_cache` | an ancestor `E` has a sibling file `E.recorded_inputs` whose first line is the 64-hex name of `E`'s parent directory. The entry is named by a UUID, or by a counter on 8.3.1 (`1`) |
| `bazel_vendor_dir` | an ancestor holds a file `VENDOR.bazel` |
| `via_link` | the path as spelled crosses a link: `bazel-bin` into the output base, `external/<repo>` out of it into the contents cache or the vendor directory |

Limits of what was recorded:

- `workspace_md5_is_output_base_name` is the MD5 of the path in `workspace_path_hashed` as
  it was on the capture machine, and each base of `link_route.json` that is named by 32
  hex digits is the MD5 of its `workspace` in the same way. The import checks both on the
  probe files; the committed paths start with `<CAMPAIGN>` and no longer hash to them.
- The prototype's fifth kind, `hardlinked` (a file with more than one link), is in no
  vector: the trees record no link count.
- Every `detect` layout is the state right after a build: `execroot/DO_NOT_BUILD_HERE` is
  there. None is the state after `bazel clean` and a build, where only the marker of the
  base remains, and none has a vendor directory that holds `.vendorignore` alone.
- Every marker names its own workspace, the shared base of `link_route.json` included, and
  every path is ASCII. A marker that names another workspace, and one whose bytes are not
  the canonical path, are not recorded.
- Every entry of `repo_cache_vectors.json` has an `id-` file, because those vectors were
  collected from the files, and sits under `sha256` or `sha512`. The entries with no
  `id-` file are in `observed.sample.json` (19 of its 36 cached rows): registry files of
  the four runs on 7.7.2, 8.8.2 and 9.3.2; the three archives of the 6.6.0 run, each of
  which the 7.7.2 run left in the same entry directory with an `id-` file; and four
  tools the `js` run on 8.8.2 fetched from GitHub releases (three binaries and an
  archive). One of those four is the only entry under `sha384`, a `yq` binary. Which
  rule fetched the four, and with what arguments, is not recorded. No entry is under
  `sha1` or `blake3`, and none was written by Bazel 5: a test of those shapes fabricates
  them.
- The sample records which `id-` files were beside a payload, not the whole entry
  directory, and nothing of a cache that two releases shared: each run had its own
  (`--repository_cache` under its state directory).
- When the sample was taken (2026-11-12) the caches of the three `skylib` runs were
  still in the probe directory, and its 15 cached rows of those runs were compared with
  them again: each payload is there with the recorded size, with the recorded `id-`
  file or, in the 6.6.0 cache, alone in its directory. The caches of the `js` and `jvm`
  runs had been deleted, so their 21 rows, the `sha384` one among them, rest on the
  probe's file and its report.
- macOS arm64 only (`darwin_arm64-fastbuild`). No Windows junction and no Linux layout.

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
- A layout vector is a description, not a tree: put a directory in place of every token
  (`<OB>`, `<WS>`, `<CACHE>`, `<INSTALL>`, `<CAMPAIGN>`) before a path is used, and build
  the tree in memory or in a temporary directory, never here. Its `expect` rows are what
  a prototype answered; the classifier's own classes and precedence are the design's.
- A repository-cache row names an entry under a cache root the test picks; its URL is a
  name and is never fetched. Skip the rows of `observed.sample.json` whose `key_type` is
  null, and do not edit that file by hand: `import_layouts.py` writes it from the probe
  file, and `check.py` pins the counts.
- A file added here needs its line in `SHA256SUMS`, and `check.py` must still pass.
