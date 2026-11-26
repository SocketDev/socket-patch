[agent] Progress ledger for the scheduled Bazel workspaces bug-hunt routine (label pm:bazel).

Last run: 2026-11-26, main `cfc870f`, release v5.1.0, newest Bazel pin 9.3.2. Real Bazel builds are blocked in the sandbox (see backlog item 1), so no Hosted, Vendored, Agent or VEX cell has been tested yet.

Bazel support is experimental. The rows below are the rows of "Bazel workspaces: what is supported" in `docs/ecosystems.md`, which says what each cell promises and with which conditions. A cell here records what this routine saw on a real Bazel build: pass (Bazel release, date), fail (issue number), blocked (why) or untested.

## Coverage matrix

| Ecosystem, and how Bazel takes its packages | Hosted | Vendored | Agent (not supported: the build must still pass) | VEX | Nightly CI legs on `main` |
|---|---|---|---|---|---|
| npm: aspect_rules_js over a pnpm lock | untested | untested | untested | untested | green 23, 24 and 25 Nov (2026-11-26) |
| PyPI: rules_python `pip.parse` over a requirements file | untested | untested | untested | untested | green 23, 24 and 25 Nov (2026-11-26) |
| Go: gazelle `go_deps.from_file` over `go.mod` | untested | untested | untested | untested | green 23, 24 and 25 Nov (2026-11-26) |
| RubyGems: rules_ruby `ruby.bundle_fetch` over `Gemfile.lock` | untested | untested | untested | untested | green 23, 24 and 25 Nov (2026-11-26) |
| Cargo: rules_rust `crate.from_cargo` over `Cargo.lock` | untested | untested | untested | untested | green 23, 24 and 25 Nov (2026-11-26) |
| NuGet: `nuget.from_lock` over `packages.lock.json` | untested | untested | untested | untested | green 23, 24 and 25 Nov (2026-11-26) |
| Composer: a rule that runs `composer install` from `composer.lock` | untested | untested (declines by design) | untested | untested | green 23, 24 and 25 Nov (2026-11-26) |
| Maven: rules_jvm_external `maven.install` with a `lock_file` | untested | untested | untested | untested | green 23, 24 and 25 Nov (2026-11-26) |

| Outside a Bazel build | Result |
|---|---|
| A project in no Bazel workspace behaves exactly as v5.1.0 did | npm (pnpm lock v9): pass, main `cfc870f` against v5.1.0, 2026-11-26: same files and exit codes; output differs only by changes that are not Bazel's. Other ecosystems untested |
| A project in a Bazel workspace that Bazel does not build | npm: pass under a `MODULE.bazel` with no hub and under a leftover `WORKSPACE`, 2026-11-26. Other ecosystems untested |

## Backlog
1. Feasibility: **blocked, 2026-11-26.** `bazel build` of a fixture stops at module resolution: the sandbox's network policy refuses `bcr.bazel.build` (HTTP 403 from the egress proxy). Also refused: `releases.bazel.build` (9.3.2 installed only from an existing cache), `mirror.bazel.build`, `patches-api.socket.dev`, `api.socket.dev`, `patch.socket.dev`. Reachable: `github.com`, `registry.npmjs.org`, `nodejs.org`. Each run: try one fixture build first (`cargo test -p socket-patch-cli --test e2e_bazel_build -- --ignored --exact npm::hosted_npm_translate_lock`, about 10 minutes to compile); while it fails on the registry, do only items 2, 3 and 8.
2. The latest nightly run of each `bazel-*.yml` workflow on `main`: which legs are red, and whether an open issue covers each.
3. A project in no Bazel workspace, and one in a workspace that Bazel does not build: main against v5.1.0. npm is done; next PyPI (requirements file), then Go, RubyGems, Cargo, NuGet, Composer, Maven. No public patch API here: use a loopback stand-in shaped like `tests/hosted_memory_common/mod.rs` (`--api-url`, `--org test-org`, `SOCKET_PATCH_SERVER_URL`).
4. Hosted mode, one ecosystem per run, in the order of the table (npm first): the mode's one command, `bazel build`, the patched package in the build, `vex`, the undo, `bazel build` again.
5. Vendored mode, the same way, for the rows the docs list as Supported; for the rows that decline, the command exits 1, writes nothing and the build still passes.
6. Agent mode in a Bazel workspace: the message says what to use instead, and the build still passes.
7. `vex` in each row: `not_affected` only for a package the Bazel build takes patched.
8. The docs table against what you saw: a cell that promises more than the build holds.
9. Shapes, npm first: a committed `MODULE.bazel.lock` with `--lockfile_mode=error`, two hubs, a monorepo Bazel builds in part, a `.bazelrc` with a repository cache or a downloader config, a `WORKSPACE` file beside `MODULE.bazel`.

## Known non-bugs
See `known-non-bugs/bazel.md` (3 entries, all artifacts of a home-made stand-in API or output changes that are not Bazel's).
