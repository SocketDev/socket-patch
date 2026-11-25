<!-- arch-audit-register -->
## Register

[agent] This comment is the register for the architecture refactor routine. It is rendered from `register/10-refactor.md` on the [`arch-audit/ledger`](https://github.com/SocketDev/socket-patch/tree/arch-audit/ledger) branch, and the routine updates it on every run.

_Last updated 2026-11-25 · 2 runs under this charter · `main` at 0a391c1 when examined._

### In flight
| PR | Issue | State |
|---|---|---|
| #2250 | #2249 (`remove` / `rollback <target>` said "No patch found" over an unreadable vendor ledger) | ready, awaiting review |
| #2246 | #1910 (the prune GC's keep cause and failure reason) | ready, awaiting review. On merge: remove `agent:claimed` from #1910, which stays open for L21 and L22. |
| #2241 | #1959 (T55 slice 1) | ready. Opened by the last run under the old charter: it deletes test-helper copies that agree, so it isn't a real-problem PR. A maintainer decides whether it merges. Don't extend it, and don't take further T55 slices. |

Three are open, so the next run opens no PR and verifies leads instead (step 3).

### Merged
_None under this charter. The 2026-10/11 sweep PRs are listed in `review/2026-11-v2/register/90-refactor.md`._

### Leads
L01 to L18 were carried from the previous thread's notes: automated audits wrote them and no person has checked them. The later rows come from this routine's own runs. A row is a hypothesis until its Status says it ran: prove it or reject it.

| ID | Problem | Where | Status |
|---|---|---|---|
| L01–L03 | (three rows collapsed) | core `utils/` and `vex/product.rs` | rejected; each ran and needs an input no real project produces (entry of 2026-11-25T16:22Z) |
| L04 | `vlt_heal` swallows `load_state` and lock read errors and proceeds | CLI `commands/vlt_heal.rs` | to verify |
| L05 | the gem stale-install probe dedups by purl and drops the platform suffix, so a platform gem is judged by the ruby gem | gem stale probe (hosted) | to verify |
| L06 | `hatch::require_pip_installer_documents` ignores the `envs` override | core `utils/hatch.rs` | to verify |
| L07 | `scan --prune`: `has_ledger` probes `--cwd`, but `run_vendor_gc` reads `project_root()` | CLI `scan/gc.rs` | to verify; read, not run: `has_ledger` still probes `--cwd` while `run_vendor_gc` re-roots at the manifest's project (#745), so a vendor-only prune with `--manifest-path` into another project returns early. Reached only on an empty crawl |
| L08 | `ui::shell_word` doesn't quote `"` or `%VAR%` for cmd.exe, so a printed remedy can't be pasted | CLI `ui/text.rs` | to verify |
| L09 | `api/client.rs` runs two retry policies that disagree on statuses, counts, jitter and an over-cap `Retry-After`; blob GETs and the upstream registry client retry nothing | core `api/` | to verify |
| L10 | warning sinks disagree on `--silent`/`--json`: some print to stderr under `--json`, some drop warnings under `--silent` | CLI `scan/mod.rs`, `list.rs`, `user_patches.rs`, `scan/withdrawn.rs` | to verify |
| L11, L12 | (two rows collapsed) | CLI `commands/vex.rs`; the repository-root walks | already fixed; `vex.rs` withholds the purl on a join error since #2132 (its twin in `apply.rs` is L19), and the walks go through `utils::repo_root` |
| L13 | six Windows verbatim-prefix strippers disagree on UNC and `\\?\Volume{…}` paths | core `utils/`, `pnpm_workspace` | to verify |
| L14 | sbt and scala-cli `discover` collapse unreadable files and cap breaches into `None`, so the user is told to run `sbt update`/`scala-cli compile` | core JVM crawlers | to verify; read, not run: the sbt callers now use `scan()` and keep the reason. scala-cli `discover` still returns `None` for an over-cap or foreign `.bloop` file, and the gate then says to run `scala-cli compile` |
| L15 | `list::sanitize` and `StatusPrinter::println` keep bidi and zero-width characters that core `policy::strip_unsafe` removes | CLI `list.rs`, `ui/status.rs` | to verify |
| L16 | `SOCKET_UPDATE_TIMEOUT_MS` is parsed twice; core caps `connect` at 10 s and the update notifier doesn't | core `UpdateTimeouts`, CLI `update_notifier.rs` | to verify |
| L17 | three hand scanners for Ruby `=begin` blocks; the heredoc heuristic misreads `x <<FLAG` and indented `<<~ID` terminators | `vendor/gem.rs`, `vex/discover/gem.rs`, `redirect/upstream/gem.rs` | to verify; read, not run: `formats/gem/ruby.rs` now masks heredocs for the Gemfile readers, but `formats/gem/manifest.rs` `code_lines` keeps its own `heredoc_ids`, which takes `x <<FLAG` as a heredoc |
| L18 | `assert_proxy_served_scans` counts 404s as served, so a wrong mount path stays green | `tests/common/scan_proxy.rs` | to verify |
| L19 | `check_derived_copies` turns a join error of the Gradle derived-copy check into "no stale copies", so `apply` reports a clean success; vex's twin withholds | CLI `commands/apply.rs` | to verify; read twice: `derived_copies_in` and `DerivedIndex` have no panic path of their own, so only an injected panic shows it. Draft #2247 edits `apply.rs` |
| L20 | a keep for a removed dependency (`vendor_lock_entry_removed` while a lockfile still mentions the artifact) has no cause of its own: `KeepCause::of` calls it a drift, so `remove`, `rollback`, `vendor` and the prune GC all say the lock drifted | CLI `vendored_backend/mod.rs`, core `npm_flavor::keep_artifact_while_lock_references_it` | to verify; from the review of #2246, read, not run |
| L21 | the prune GC drops the orphan sweep's still-wired set, which `vendor --revert`, `remove` and `rollback` report | CLI `vendor.rs` `run_vendor_gc` (#1910) | to verify |
| L23 | `scan --prune`'s `has_ledger` takes any stat error on the vendor ledger for "no ledger" (`metadata().is_ok()`); #2250 fixed that probe in `remove`, `rollback` and `repair` | CLI `scan/gc.rs` | to verify; from the review of #2250, read, not run. #2246 changes the file |
| L24 | plain `vendor` with no manifest and an unreadable ledger exits 0: human mode warns, `--json` is `noManifest` with no `warnings[]`. The contract row for `vendor_state_unreadable` says `vendor` refuses, exit 1 | CLI `vendor.rs` | to verify; ran it at 0a391c1. Which `vendor` paths the row covers needs reading. #2246 changes the file |
| L22 | the prune GC raises no Go undo warning after it reverts a vendored Go module, so a committed `vendor/modules.txt` still records the replace and the next build fails unannounced | CLI `vendor.rs` `run_vendor_gc` (#1910) | to verify |

Open `arch-audit` issues whose titles claim a real defect, so check them first: #1970 (all-zeros `beforeHash` + `--force` in 8 docker suites), #1982 (Gradle `--global-prefix` tests pass without the flag), #1950 (`formats::xml::attr` matches inside another attribute's value), #1926 (the "copy may still hold the patch" rule drifted), #1014 (a scala-cli build with no `project.scala` finds no Coursier cache), #1917, #1912, #1899, #1887, #1069, #882.

Issues looked at:

| Issue | Status |
|---|---|
| #1910 | in PR #2246; two of its claims ran true (a reference keep reported as drift, a failed revert's reason dropped). The rest is L21 and L22 |
| #1861 | out of charter; true by reading (`remove` has no arm for a dry run with `--preserve-state`, `rollback` has), but the contract doesn't settle what `remove` should emit there (`rollback`: `verified` + `details.preserved`; `remove` wet: `skipped` / `vendor_state_preserved`). It needs a decision |
| #1969 | out of charter; read: the `--offline` in those calls is lifecycle setup, and the tests named `*offline*` assert a package manager's offline install or something else (CRLF, drift). No test found that asserts an offline gate through this harness |
| #1114 | another agent's #2229, merged 2026-11-25, targets it |
| #2249 | in PR #2250 |
| #1963 | rejected and closed; ran the two wrapper tests: both Gradle 6.8 gates read through `wrapper_distribution_version` since #2052 |
| #1927 | out of charter; true by reading (`omission_phrase` has no arm for `gradle_unpatched_copy`), but about 15 documented `failed[].reason` tags share the generic phrase and each comes with a run warning naming the cause |
| #1877 | out of charter; true by reading (`apply` / `vendor --vex --dry-run --json` add no `vex_skipped_dry_run` warning, `scan` does), but the contract states it for `scan` only, so it needs a decision |

### Areas examined
| Area | Date | `main` | Found |
|---|---|---|---|
| `scan --prune` vendored GC (CLI `vendor.rs` `run_vendor_gc`, `scan/gc.rs`) | 2026-11-25 | 332b3e8 | a reference keep reported as drift, a failed revert's reason dropped: #2246. L21 and L22 not run |
| vendored revert classification (CLI `vendored_backend/mod.rs`) | 2026-11-25 | 332b3e8 | two causes for three kinds of keep: L20 |
| core `utils/redact.rs`, `utils/npm_range.rs` | 2026-11-25 | 332b3e8 | L01 to L03 ran; nothing a real project can produce |
| repository-root walks (core `utils/repo_root.rs` and its callers) | 2026-11-25 | 332b3e8 | read only; L12 is fixed |
| an unreadable vendor ledger on every command that reads it | 2026-11-25 | 0a391c1 | `remove` / `rollback <target>` said "No patch found", `remove` restored files before refusing, three stat probes took an error for absence: #2250. Also L23, L24 |
| `--json` / `--silent` output of 19 commands over 5 small projects (285 runs of the built binary) | 2026-11-25 | 0a391c1 | stdout is one JSON document under `--json` and empty under `--silent` in every run |
| Gradle derived-copy checks (CLI `apply.rs`, core `jvm_jar.rs`, `gradle_cache.rs` `DerivedIndex`) | 2026-11-25 | 0a391c1 | L19 holds by reading; nothing a real cache triggers |

### Notes
- Build with `CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0` to save disk. CI's clippy job runs without `--tests`.
- Clap field doc comments are `--help` output: leave them alone.
- `--cwd` defaults to `.`: absolutize it before walking `ancestors()`, and test via chdir under `#[serial]`.
- Test runners that pin `--cwd` must not also set the child's cwd to the project, or a crawler that reads the process cwd passes by accident.
- Making a `pub` core item private can leave rustdoc links to it; unlink them in the same commit.
- The checkout is shallow (50 commits), so `git log -S` can't reach an older fix. The contract's `#NNN` references name the fix instead, or deepen the clone.
- A write that returns 5xx may still have landed (a claim comment was posted twice on 2026-11-25) or not (PR creation failed three times, then worked). List before you retry.
- The harness appends the "Generated by Claude Code" footer to comments and PR bodies itself. `bugbot run` still triggers with it.
- To test the prune GC over a real revert without a toolchain, hand-build a requirements-flavor ledger entry: `seed_dropped_pypi_entry_with_an_export` in the `scan/gc.rs` tests.
- `cargo clippy -p socket-patch-cli --all-targets` takes about 8 minutes cold; the CLI unit tests take about 4 to build and 4 seconds to run.
- Run the built binary over small broken projects (no manifest, a corrupt manifest, a corrupt ledger) and compare the commands: that found #2249 in minutes. Set `SOCKET_TELEMETRY_DISABLED=1`.
- Run `/code-review high` again after fixing its findings. On #2250 the second pass found a contract sentence the first fixes had made false.
- `git fetch --deepen=2500 origin main` takes seconds and makes `git log -S` usable.
- This sandbox has node, npm, pnpm, yarn 1, bun, uv, poetry, ruby and bundler, composer, java 21, mvn, gradle and the docker CLI. It has no go, dotnet, sbt or deno.
- CI's clippy is `cargo clippy --locked --workspace --all-features -- -D warnings`. With `--all-targets` it fails on `main` in `tests/common` and `tests/prebuilt_common`.
- Root-sandbox failures that pass in CI: the chmod tests in `tests/repair` (2) and `in_process_redirect` (3), core `copy_tree` with a symlinked root, `vlt_heal` with an unremovable lock, and the `pypi_poetry`/`pypi_requirements` wire-failure tests.
