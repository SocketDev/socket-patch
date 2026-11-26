[agent] Progress ledger for the scheduled Bazel workspaces bug-hunt routine (label pm:bazel).

Last run: none yet (routine created 2026-11-26).

Bazel support is experimental. The rows below are the rows of "Bazel workspaces: what is supported" in `docs/ecosystems.md`, which says what each cell promises and with which conditions. A cell here records what this routine saw on a real Bazel build: pass (Bazel release, date), fail (issue number), blocked (why) or untested.

## Coverage matrix

| Ecosystem, and how Bazel takes its packages | Hosted | Vendored | Agent (not supported: the build must still pass) | VEX | Nightly CI legs on `main` |
|---|---|---|---|---|---|
| npm: aspect_rules_js over a pnpm lock | untested | untested | untested | untested | unchecked |
| PyPI: rules_python `pip.parse` over a requirements file | untested | untested | untested | untested | unchecked |
| Go: gazelle `go_deps.from_file` over `go.mod` | untested | untested | untested | untested | unchecked |
| RubyGems: rules_ruby `ruby.bundle_fetch` over `Gemfile.lock` | untested | untested | untested | untested | unchecked |
| Cargo: rules_rust `crate.from_cargo` over `Cargo.lock` | untested | untested | untested | untested | unchecked |
| NuGet: `nuget.from_lock` over `packages.lock.json` | untested | untested | untested | untested | unchecked |
| Composer: a rule that runs `composer install` from `composer.lock` | untested | untested (declines by design) | untested | untested | unchecked |
| Maven: rules_jvm_external `maven.install` with a `lock_file` | untested | untested | untested | untested | unchecked |

| Outside a Bazel build | Result |
|---|---|
| A project in no Bazel workspace behaves exactly as v5.1.0 did | untested |
| A project in a Bazel workspace that Bazel does not build | untested |

## Backlog
1. Feasibility: install a pinned Bazel with `scripts/install-bazel.sh` and build one fixture workspace under `crates/socket-patch-cli/tests/fixtures/bazel`. Record every host the sandbox can't reach.
2. The latest nightly run of each `bazel-*.yml` workflow on `main`: which legs are red, and whether an open issue covers each.
3. A project in no Bazel workspace: the same commands on `main` and on v5.1.0 give the same files, output and exit codes.
4. Hosted mode, one ecosystem per run, in the order of the table: the mode's one command, `bazel build`, the patched package in the build, `vex`, the undo, `bazel build` again.
5. Vendored mode, the same way, for the rows the docs list as Supported; for the rows that decline, the command exits 1, writes nothing and the build still passes.
6. Agent mode in a Bazel workspace: the message says what to use instead, and the build still passes.
7. `vex` in each row: `not_affected` only for a package the Bazel build takes patched.
8. The docs table against what you saw: a cell that promises more than the build holds.

## Known non-bugs
See `known-non-bugs/bazel.md` (none yet).
