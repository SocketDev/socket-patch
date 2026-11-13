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
- Under Bzlmod every ruleset a workspace depends on (a `bazel_dep` named
  `rules_*`, `gazelle` or `aspect_rules_py`) is listed under `pins` and has a
  `single_version_override` of the same version, not only the ruleset the
  fixture is named for. Another module can lift a declared version (Bazel 9.3.2
  lifts a bare `rules_python` 1.0.0 to 1.7.0), and Bazel 9.3.2 rejects an
  override below the declared one.
- No `MODULE.bazel.lock` and no `bazel-*` link at the root of a workspace:
  Bazel owns both. No fixture commits a lock today. One that a test needs goes
  to `locks/v<lockFileVersion>[/<os>]/MODULE.bazel.lock`. It is written by
  `bazel mod deps --lockfile_mode=update` under the exact Bazel release, against
  `https://bcr.bazel.build/`, once per OS key its cells run, and never taken
  from a build or from a run against a `file://` mirror. Bazel 7.7.0 is never
  used for it: that release writes absolute `file:///` registry keys.
- No loopback address in a committed file. Where a tool that is not Bazel's
  downloader needs the fixture server (pip's `--index-url`, also the one
  pip-compile gets through `extra_args`), the file holds
  `http://socket-fixture.invalid` and names itself under `substitute` in
  `MATRIX.json`; the harness writes the server's address into the workspace
  copy.
- pip gets its index from a committed `--index-url`, never from
  `--repo_env=PIP_INDEX_URL=` alone: pip runs `--isolated` and ignores the
  variable. The pip-mode fixtures here use the placeholder above. A pin with
  `envsubst` (probed on rules_python 1.9.2 only) may instead commit `envsubst =
  ["PIP_INDEX_URL"]` with `${PIP_INDEX_URL:-https://pypi.org/simple}`; the
  harness passes the variable to such a fixture and to no other.
- Locks keep production URLs (`https://pypi.org/simple`,
  `https://files.pythonhosted.org/...`, `proxy.golang.org` through `GOPROXY`).
- A rules_python >= 2.0 fixture lists `pypi.org` under `hosts`: the pip
  extension reads the index pages of rules_python's own
  `rules_python_publish_deps` hub (about 31) from the real index, which no stub
  serves.
- A cell is a pairing that ran. rules_pycross 2.x has no cell below Bazel 8 and
  rules_rs none below 8.4 (neither loads there); a pairing no probe ran
  (aspect_rules_py outside 8.8.2 and 9.3.2, rules_rs outside 9.3.2) carries the
  evidence `unverified`. A fixture on rules_go 0.65.0 downloads Go SDK 1.26.0.

## `MATRIX.json`

One object per fixture: the test that builds it, its dependency system, the
ruleset versions the build must resolve (`pins`; a canary fails when `bazel mod
graph`, or the WORKSPACE repository rule, says otherwise), the registry
emulations it needs, who fetches its packages, the hosts a cold run contacts,
the tier-0 anchor (`probe`), the consumer's marker, the language toolchains the
fetch itself pulls in (`toolchains`: an empty list is asserted too), and its
`cells`. A cell is one Bazel release with the highest proof tier the baseline
climbs there (0 fetch, 1 build the probe, 2 run the consumer), its CI tier and
its evidence: the probe cell that ran the pairing, or `unverified` when the
canary is the first evidence.

The fetcher is stated per phase. `fetch` is who fetches the packages of the
fixture as committed: Bazel's `downloader`, or a `tool` (pip, go, cargo).
`hosted_fetch` is who fetches a hosted reference after socket-patch rewrote the
fixture; it is written only where the two differ. On rules_python 1.3.0 and
1.4.2 under Bzlmod pip installs a registry requirement, and Bazel's downloader
fetches the hashed direct reference a hosted rewrite leaves. A hosted cell hands
out a loopback origin only where the hosted fetcher is a `tool`: a loopback URL
must never reach a file the downloader reads or records.

Optional members:

- `substitute`: the files that hold the origin placeholder (above).
- `test_targets`: test targets that pass on the fixture as committed. The
  baseline runs them, so a later test that expects one to turn red starts from a
  green one. `rules_python/bzlmod/e9-compile` lists `//:requirements.test`.
- `lock`: what `MODULE.bazel.lock` says about the fixture's extension after the
  builds, for a fixture whose shape is a statement about the lock. Either
  `{"records": {"extension": "//:extensions.bzl%go_deps", "files": ["go.mod",
  "go.sum"]}}` (the lock holds the extension's result and lists those files as
  recorded inputs) or `{"not_recorded": "<extension>"}`. The extension is named
  by label and name without its repository, whose spelling differs per Bazel
  line (`gazelle~`, `gazelle+`), and must be one the `MODULE.bazel` uses.
- `lanes`: the tests of a lane package that run on the fixture, each as
  `{"test": "bazel_hosted_...", "cells": [...]}`. The test starts with
  `bazel_guard_`, `bazel_agent_`, `bazel_hosted_`, `bazel_vendor_` or
  `bazel_canary_` (and is no `bazel_canary_baseline_`), is declared once with a
  plain `fn`, in a module of the suite other than `baseline_heavy.rs`, and is
  listed once in the heavy matrices. A lane cell has the members of a baseline
  cell, on a Bazel release the fixture's own cells list: `evidence` then names
  the probe cell that showed the lane's outcome on that pairing, or
  `unverified`. No baseline runs a lane test; the lane's module does.

A cell may also say `"cache": "restored"`, and nothing else under `cache`: the
cell counts on the repository cache CI restores for it. CI restores one for the
cell of a lane test and never for a canary, the baselines included, so only a
lane cell says it. It is what lets a fixture whose fetch needs the Go SDK or a
Rust toolchain into the `pr` tier: a lane cell of such a fixture is `pr` only
with `"cache": "restored"`, and its baseline is always `nightly`.

Every report of a Bzlmod cell lists the extensions the lock records
(`recorded_extensions`, `lock_facts`); a report's `hosts` names `127.0.0.1` for
the requests a tool sent straight to the fixture server (pip's index).

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

`rules_rs/bzlmod/e9-multi` holds two registry versions of `itoa`. Its targets
reach 1.0.15 through the plain hub alias `@crates//:itoa`, which rules_rs gives
to the highest version a workspace member depends on, and 0.4.8 through
`@crates//:itoa-0.4.8`. Vendoring a crate retags its version and with it the
versioned alias, so the same tree serves both cells of the vendored lane: a
vendored 1.0.15 beside a registry 0.4.8 leaves every label valid, and a vendored
0.4.8 would break one.

A fake Socket API that grants the Go module takes the artifact's `integrity`
from `goproxy::Module::grant_integrity` (`sha512`, without which a vendored
grant is refused, and the two `go.sum` hashes the hosted rewriter needs).
