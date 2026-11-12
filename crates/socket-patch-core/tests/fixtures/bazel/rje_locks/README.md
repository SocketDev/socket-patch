# rules_jvm_external locks and Starlark hash vectors

Test inputs for `socket_patch_core::bazel::rje_lock` (the `maven_install.json` reader) and
`socket_patch_core::bazel::java_hash` (Starlark `hash` and `repr`). Nothing here was written
by socket-patch. Every file is byte-real: several locks are CRLF on purpose and one hash input
is a tarball, so `.gitattributes` turns line-ending conversion off for the directory and
`SHA256SUMS` lists every file but itself.

Check the tree with

    shasum -a 256 -c SHA256SUMS
    cargo test -p socket-patch-core --lib bazel::rje_lock
    cargo test -p socket-patch-core --lib bazel::java_hash

The first test of `bazel::rje_lock` fails when a lock is committed without a row in
`expected.tsv`, and the second when a file differs from its checksum or is not listed.

## `upstream/`: locks rules_jvm_external wrote

42 files taken with `git show <tag>:<path>` from
<https://github.com/bazel-contrib/rules_jvm_external> (Apache-2.0). The file name is
`<tag>__<path with / as _>`, and the `source` column of `expected.tsv` gives the tag and the
path exactly. Each lock stores the `__RESOLVED_ARTIFACTS_HASH` its own release computed, so
reproducing it checks the port against rules_jvm_external itself.

Chosen: the root lock of tags 4.0, 4.2, 4.5, 5.3, 6.0, 6.5, 6.7, 6.9 and 6.10, and every
distinct lock of the 7.2 tree up to 45 kB, plus
`tests/custom_maven_install/regression_testing_coursier_install.json` (300 kB), the one lock
that combines dependency cycles, three repositories and the insertion flavor. Left out:
byte-identical copies (the root lock is the same at 3.3 and 4.0, at 4.3 and 4.5, at 5.0 and
5.3, and at 7.0, 7.1 and 7.2; two pairs inside the 7.2 tree) and the other files of the 7.2
tree over 45 kB.

| Format | Locks | Notes |
|---|---|---|
| v1 (`dependency_tree`) | 3 | 4.0 keeps the hash under the banner key; 4.2 and 4.5 under `__RESOLVED_ARTIFACTS_HASH` |
| v2 | 15 | 5.3 to 6.9 root locks and the v2 locks the 7.2 tree still tests with |
| v3, both flavors | 19 | `7.2__maven_install.json` is the root lock with ten mutual dependencies between the netty-tcnative classifier jars; `regression_testing_gradle_install.json` has `null` checksums |
| v3, sorted flavor only | 1 | `multi_repo_hash_install.json` |
| v3, insertion flavor only | 3 | `legacy_multi_repo_hash_install.json`, `from_files_install.json`, `regression_testing_coursier_install.json` |
| not a lock | 1 | `regression_testing_gradle_index.json`, a resolver index file |

## `probe/`: locks real Bazel wrote, accepted or rejected

22 files from the Bazel-support campaign's rules_jvm_external probe group, run 2026-11-11 on
one macOS arm64 machine. Nothing ran on Linux or Windows.

| Files | What they are |
|---|---|
| `pin-*` | written by the pin of the named rules_jvm_external release on the named Bazel release. For 4.5 the content and both hashes are the repository rule's own output, and the last step of its pin script, one `jq` filter, was run by hand: the bundled `jq` is an x86-64 binary |
| `hosted-rje4.5-v1-suffixed`, `hosted-rje5.3-v2`, `hosted-rje6.5-v2`, `hosted-rje6.10-v3-insertion-2repo`, `hosted-rje7.2-v3-sorted-2repo`, `hosted-rje7.2-v3-sources-drop` | a pinned lock rewritten by the probe's prototype to a patched artifact, with the hash recomputed; a build without `REPIN` accepted each one (4.5 on Bazel 5.4.1, 5.3 on 6.6.0, 6.5 on 7.7.2, 6.10 and 7.2 on 8.8.2) |
| `hosted-rje6.10-lock-rehashed-sorted-REJECTED-by-6.10` | a 6.10 lock re-hashed in the sorted flavor: 6.10 fails with `invalid signature` |
| `hosted-rje7.2-lock-rehashed-insertion-ACCEPTED-with-note` | a 7.2 lock re-hashed in the insertion flavor: 7.2 builds and prints a note |
| `m4ok-lock-*` | CRLF line endings and a repository URL with non-ASCII characters, hashed over the UTF-8 bytes: accepted by Bazel 8.8.2 (v3) and 7.7.2 (v2) |
| `m4-lock-*-nonascii` | the same locks with the hash over UTF-16 units stored: rejected, and the message names the value Bazel computed (`1490333282 vs 838865874` on 8.8.2, `expected 1519755856 and got 350241632` on 7.7.2, `expected 385063259 and got 832349099` on 6.6.0; 9.3.2 printed the 8.8.2 pair for a one-repository variant that is not committed) |
| `m4-lock-rje4.5-v1-crlf` | a v1 lock with CRLF line endings: accepted by Bazel 5.4.1 |
| `CRASH-rje7.2-v3-dangling-repositories-key` | `repositories` lists a key no artifact produces: rules_jvm_external crashes with `key "org.slf4j:slf4j-api:jar:sources" not found in dictionary` |

The `hosted-*` and `m4*` locks name a fixture server on `127.0.0.1` with made-up identifiers
(`22222222-2222-4222-8222-222222222222`); no real token is in this directory.

## `expected.tsv`

One row per lock: path, format, verdict, source. The verdict is the list of hash flavors that
reproduce the stored value (`v1`, `v1-legacy`, `v2`, `v3-sorted`, `v3-insertion`, joined with
`+`), or `mismatch`, `dangling` or `not-a-lock`. It was written from the probe group's own
Python port of the algorithms (its `MANIFEST.json`, bytes model), not from the Rust reader, so
the test compares two independent ports with each other and with the stored values.

## `hash_file/rules_js-v3.6.0/`: the rules_js hash file

`npm_translate_lock_LTE4Nzc1MDcwNjU=` is the file rules_js commits for its own repository at
tag `v3.6.0` (<https://github.com/aspect-build/rules_js>, Apache-2.0;
`.aspect/rules/external_repository_action_cache/`). Each of its 21 `path=hash` lines is the
Java `String.hashCode` of the file, one char per byte. `inputs/` holds those 21 files from
the same tag, one of them a binary tarball (`lodash-4.17.21.tgz`, MIT). An input is named
after its path with `/` written as `__` and `.in` appended, so that no file here has the name
of a package manifest, a lock or an ignored archive:
`npm/private/test/package.json` is `inputs/npm__private__test__package.json.in`.
