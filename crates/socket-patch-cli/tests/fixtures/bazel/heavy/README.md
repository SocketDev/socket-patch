# Heavy fixture workspaces

Bazel workspaces for the rulesets that need a language toolchain or a package
manager to fetch: the Python family (rules_python, its `uv_lock` mode,
aspect_rules_py, rules_pycross), gazelle (Bzlmod `go_deps`, the directory
replace shape, WORKSPACE `go_repository`) and Rust (rules_rust crate_universe,
rules_rs). The baseline canaries in `tests/e2e_bazel_build/baseline_heavy.rs`
build each one on real Bazel; the lane and guard tests of later packages run
socket-patch on the same trees.

## Layout

```
heavy/<ruleset>/MATRIX.json            the fixtures of one ruleset and the cells each runs in
heavy/<ruleset>/<system>/<era>[-<variant>]/   one workspace; <system> is bzlmod or workspace
heavy/registry/                        the synthetic packages, served by the fixture server
```

An era names the Bazel line the pins were chosen for (`e9` 9.3.2, `e8` 8.8.2,
`e7` 7.7.2). A fixture runs on every line its `cells` list, and on no other: a
test on another Bazel release prints `SKIP (n/a)`.

## Rules every workspace follows

The tests in `baseline_heavy.rs` that need no Bazel enforce these.

- `//:socket_probe` (the shared `probe.bzl`, installed by the harness: a
  fixture never ships its own) and `//:consumer`, a program in the ruleset's
  language that prints a marker.
- Under Bzlmod each pinned ruleset has a `bazel_dep` and a
  `single_version_override` of the same version. Another module can lift a
  declared version, and Bazel 9.3.2 rejects an override below the declared one.
- No `MODULE.bazel.lock` and no `bazel-*` link in a workspace: Bazel owns both.
- No loopback address in a committed file. Where a tool that is not Bazel's
  downloader needs the fixture server (pip's `--index-url`), the file holds
  `http://socket-fixture.invalid` and names itself under `substitute` in
  `MATRIX.json`; the harness writes the server's address into the workspace
  copy.
- Locks keep production URLs (`https://pypi.org/simple`,
  `https://files.pythonhosted.org/...`, `proxy.golang.org` through `GOPROXY`).

## `MATRIX.json`

One object per fixture: the test that builds it, its dependency system, the
ruleset versions the build must resolve (`pins`; a canary fails when `bazel mod
graph`, or the WORKSPACE repository rule, says otherwise), the registry
emulations it needs, who fetches its packages (`fetch`: Bazel's `downloader`,
or a `tool` that needs a loopback origin in the hosted cells), the hosts a cold
run contacts, the tier-0 anchor (`probe`), the consumer's marker, the language
toolchains the fetch itself pulls in (`toolchains`: an empty list is asserted
too), and its `cells`. A cell is one Bazel release with the highest proof tier
the baseline climbs there (0 fetch, 1 build the probe, 2 run the consumer), its
CI tier and its evidence: the probe cell that ran the pairing, or `unverified`
when the canary is the first evidence.

## The registry tree

| Path | What | Origin |
|---|---|---|
| `registry/pypi/spvictim/`, `registry/pypi/spdep/` | `spvictim` 1.0.0 (prints `vulnerable`; depends on `spdep`) and `spdep` 2.0.0, pure-Python wheels of five files each | built deterministically for the rules-python probe group (`build_wheels.py`, fixed timestamps) |
| `registry/goproxy/example.com/upstream/@v/` | `example.com/upstream` v1.0.0 (`Greeting()` returns `PRISTINE`) in GOPROXY layout | built for the gazelle-go probe group; its `h1:` hashes in every `go.sum` here were written by the real `go` |

`registry/SHA256SUMS` lists every file. The bytes are committed and never
rebuilt: a hashed requirements file, a `uv.lock` and a `go.sum` pin their
digests. The Rust fixtures use the real crates `cfg-if` and `itoa` from
crates.io, because under crate_universe cargo itself reads the index and no
rewrite reaches it; `gazelle_workspace/workspace/e7-seed` uses the real module
`github.com/pmezard/go-difflib`, which is the point of that fixture.
