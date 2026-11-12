# Bazel rc, launcher and downloader vectors

Test inputs for three pure readers of `socket_patch_core::bazel`: `rc.rs` (the `.bazelrc`
reader), `version.rs` (the `.bazelversion` / `.bazeliskrc` reader and Bazel's module version
ordering) and `downloader_cfg.rs` (the downloader config). Every expected value here was
observed by running real Bazel or the real bazelisk, on one macOS arm64 machine (Darwin
27.0.0), 2026-11-11, bazelisk 1.30.0. Nothing ran on Linux or Windows. Nothing here was written
by socket-patch.

The files are reductions of the vectors of the Bazel-support campaign's probe groups, which
live outside this repository with their driver scripts, logs and reports. A reduction keeps
each case's input and what Bazel did with it, and drops what a test cannot use: the port's own
predictions, full error texts, timestamps and machine paths.

| File | Probe | What |
|---|---|---|
| `s8-lexer.json` | S8, `rc-ignore-substitution/s8/vectors/` | 31 rc files as bytes, with the words the Bazel client reported for each section: through the build event protocol on 6.2.1, 6.6.0, 7.7.2, 8.6.0, 9.0.2 and 9.3.2 (identical on all six), and joined under `--announce_rc` on 10.0.0rc3 |
| `s8-invocations.json` | S8, the same vectors | `order`: 15 whole invocations (`build`, `query`, `version`, `mod`; 6.2.1, 6.6.0, 7.7.2, 9.0.2, 10.0.0rc3) with every rc file they read and the order in which Bazel applied the tagged lines, the `try-import-if-bazel-version` cells included. `startup`: which `startup:<os>` lines four releases applied. `effective`: the `--lockfile_mode` Bazel 7.7.2 reported for the rules_js rc shape under `--config=ci` |
| `bazelversion.json` | C15, `core-output-base/proto/vectors/bazelversion.json` | 35 `.bazelversion` / `.bazeliskrc` inputs with the label bazelisk took and what it then ran, online and offline |
| `url-rewriter-cases.json` | T3, `test-infra-offline/vectors/url_rewriter/cases.json` | 34 downloader configs with the URLs Bazel asked for and the URLs it fetched or the error it printed, 5.4.1 to 10.0.0rc3. The 34 cases are the probe's, field for field; only the `source` / `note` header is added |
| `version-order.json` | L7 gv11, `versions-hybrid/vectors/version-order.json` | 28 pairs of module versions with the one `bazel mod graph` selected on 14 runs (6.6.0 to 10.0.0rc3). The pair with a `+build` part is marked `skip`: Bazel releases disagree about it |

Reading the files:

- `rc_hex` and `bazelversion_hex` are the file's bytes. The BOM, CRLF, lone CR, vertical
  tab and missing final newline of several cases are their point.
- In `s8-lexer.json` every character of a `tokens` string is one byte (Latin-1), so a word
  that is not UTF-8 survives JSON. `announce_rc_10.0.0rc3` is text as Bazel printed it.
- In `s8-invocations.json` the home rc is the file `HOME/.bazelrc`; `tops` lists the rc files
  the client read, in its order. `$BAZELRC` (`env.rc`) is listed only for the releases that
  read it (9.0.0 and later).
- Two launcher vectors need more than their bytes: `subdir-wins` ran in `sub/` beside a
  `sub/.bazelversion` of `8.8.2`, and in `dir-named-bazelversion` a directory has the file's
  name. `env-over-all` and `fallback-error` depend on the environment, which socket-patch
  never reads: the tests assert what the files alone say.

`reduce.py <campaign probes directory> .` is how the five JSON files were made: run again on
the campaign's vectors it rewrites them byte for byte, and then `SHA256SUMS`.

`SHA256SUMS` lists every file here but itself (`shasum -a 256 -c SHA256SUMS`), and
`.gitattributes` marks the directory `-text` so a checkout cannot change the bytes it sums.
A changed or added file needs its line there; a unit test of `rc.rs` compares each file with
its line.
