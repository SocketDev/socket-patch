# `.bazelignore` vectors and gazelle-rewired BUILD files

Test inputs for `socket_patch_core::bazel::ignore`: what real Bazel did with a
`.bazelignore`, byte for byte, and what real gazelle wrote into a user's BUILD file after it
found a socket-patch tree. Nothing here was written by socket-patch.

- Captured 2026-11-11 and 2026-11-12 on one macOS arm64 machine (Darwin 27.0.0, APFS, which
  is case-insensitive). Nothing ran on Linux or Windows.
- The driver scripts, workspaces and logs are in the Bazel-support campaign's probe
  directories, outside this repository: group `baseline` (probe B3) and group
  `rc-ignore-substitution` (probe S9).
- No file has the literal name of a Bazel boundary file: a `BUILD.bazel` is committed as
  `<what>.BUILD.bazel`.
- `.gitattributes` marks the directory `-text`. The CRLF, lone-CR, byte-order-mark and
  no-final-newline inputs are the point, and `SHA256SUMS` lists every file but itself
  (`shasum -a 256 -c SHA256SUMS`; the unit tests check it too).

## `b3/`: 168 cells on six Bazel releases

Bazel 5.4.1, 6.6.0, 7.7.2, 8.8.2, 9.3.2 and 10.0.0rc3. The workspace held an agent-mode Go
tree at `.socket/go-patches` whose `BUILD.bazel` cannot load.

| Path | What |
|---|---|
| `cases/*.bazelignore` | 13 files, exact bytes. `h6_absolute` holds the placeholder `<WORKSPACE>` where the run had the workspace's absolute path |
| `expected.json` | per case and release: `hidden` (`bazel query //...` lists only the user's targets), `exposed` (it fails on the tree) or `error` (it fails on the ignore file). 14 cases, one of them with no file: 84 cells |
| `multi.bazelignore`, `multi-expected.json` | 13 line forms over 14 directories in one `bazel query --keep_going //...` per release; a directory named in an `error loading package` line is visible. 84 cells |

What the cells show: LF, CRLF, a missing final newline, `./x/`, `x//y`, `x/y/../z`, a name
with a space, comments and blank lines are read. A trailing space or tab, a leading space, a
byte-order mark, quotes, a glob, a backslash, another case, a partial segment and a line
glued to an unterminated one hide nothing. A leading `/` hides nothing on 5.4.1, 6.6.0 and
7.7.2 and fails every command on 8.8.2, 9.3.2 and 10.0.0rc3
(`Invalid path in <ws>/.bazelignore: '/.socket/go-patches': cannot be an absolute path`).

## `s9-hygiene.json`: 43 cells on three releases

Probe S9 put a tree at `.socket/vendor/golang/uuid-1/example.com/m@v1.0.0` and ran
`bazel query //...` per byte string: 25 cases on 8.8.2, 10 on 7.7.2 and 8 on 9.3.2. The file
joins the byte strings of the probe's `run.py` (`bytes_hex`; `bytes_repr` is for the reader)
with the outcome and exit code in its run logs. Cases the probe listed and never ran are left
out. It adds what B3 does not have: a **lone CR ends a line** (`cr_only`,
`app2\r.socket/vendor\r`: hidden on 8.8.2), `a/../x` is resolved (`dotdot`), an inline
`# comment` is part of the path (`inline_comment`), and `**` is no glob.

## `gazelle/`: a user's BUILD file after gazelle found the tree

The S9 walker fixture: a Go module `example.com/app` whose `go.mod` has
`replace example.com/m => ./.socket/go-patches/example.com/m@v1.0.0`, the agent-mode tree
with the upstream module's own `BUILD.bazel`, and no `.bazelignore`.

| Path | What |
|---|---|
| `before.root.BUILD.bazel` | the root `BUILD.bazel` before: one gazelle directive |
| `rewired.root.BUILD.bazel` | the same file after `gazelle update -repo_root .`: the user's `go_library` has `deps = ["//.socket/go-patches/example.com/m@v1.0.0:m"]`. Byte-identical from gazelle v0.26.0 and v0.47.0 |
| `rewired.svc.BUILD.bazel` | the same project one directory below the Bazel root (`svc/BUILD.bazel`, gazelle v0.47.0): the label is `//svc/.socket/go-patches/...` |

The probe recorded the label lines only (its `results-walkers.json`, `root_build_deps`).
The files here were regenerated for this fixture on 2026-11-12 with the probe's own gazelle
binaries (built by `go install github.com/bazelbuild/bazel-gazelle/cmd/gazelle@<version>`)
over the probe's fixture files, with `GOPROXY=off`; the four label lines agree with the
probe's record. A `.bazelignore` line for the tree turns that label into
`Package is considered deleted`, which is why an existing tree is scanned before its line is
written.

## Not covered by any cell

The reader takes each of these as "hides nothing", and the writer never writes one:

- a line with a byte outside ASCII, other than the byte-order mark case above;
- a line that normalises to nothing (`.`, `a/..`), which Bazel's source reads as "ignore the
  whole repository";
- a line holding a NUL, which Bazel 7 and later reject through `Path.of` according to
  their source;
- anything on Windows, where `Path.of` rejects more characters and a backslash separates;
- Bazel 8.0.x, where the source turns an absolute line into a crash instead of the error.
