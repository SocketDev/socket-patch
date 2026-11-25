<!-- arch-audit-register -->
## Register

[agent] This comment is the register for the architecture refactor routine. It is rendered from `register/10-refactor.md` on the [`arch-audit/ledger`](https://github.com/SocketDev/socket-patch/tree/arch-audit/ledger) branch, and the routine updates it on every run.

_Last updated 2026-11-25 · 3 runs under this charter · `main` at da012af when examined._

### In flight
| PR | Issue | State |
|---|---|---|
| #2250 | #2249 (`remove` / `rollback <target>` said "No patch found" over an unreadable vendor ledger) | ready, awaiting review |
| #2246 | #1910 (the prune GC's keep cause and failure reason) | ready, awaiting review. On merge: remove `agent:claimed` from #1910, which stays open for L21 and L22. |
| #2241 | #1959 (T55 slice 1) | ready. From the old charter: it deletes test-helper copies that agree, so it isn't a real-problem PR. A maintainer decides whether it merges. Don't extend it, and take no further T55 slices. |

While three are open, a run opens no PR and verifies leads instead (step 3).

**Next PR when a slot opens**, in this order. Each has a failing test or mutation on `main` in its issue:
1. #2254: one file (`vlt_heal.rs`), which no open PR changes.
2. #1982: three Gradle test files, which no open routine PR changes.
3. #2253: after #2246 merges, since it changes the same two files (`vendor.rs`, `scan/gc.rs`).

### Merged
_None under this charter. The 2026-10/11 sweep PRs are listed in `review/2026-11-v2/register/90-refactor.md`._

### Leads
L01 to L18 came from the previous thread's automated audits and the later rows from this routine's runs. No person has checked them: a row is a hypothesis until its Status says it ran.

| ID | Problem | Where | Status |
|---|---|---|---|
| L01–L03, L05, L11, L12 | (six rows collapsed) | core `utils/`, `vex/product.rs`, the gem stale probe, CLI `vex.rs`, the repository-root walks | rejected (L01–L03: each ran and needs an input no real project produces) or already fixed (L05: the stale guard looks each build up under its own leaf, and `stale_guard_follows_the_builds_the_lock_names_in_a_home_with_both` passes at da012af; L11 since #2132; L12 through `utils::repo_root`) |
| L04 | `vlt_heal` swallows `load_state` and lock read errors and proceeds | CLI `commands/vlt_heal.rs` | filed #2254; ran a probe. The claim is false: the heal reads no ledger, an unreadable `vlt-lock.json` marks the copy stale and removes it, and an unreadable hidden lock is reported as unchecked. But that report prints the hosted text after a rollback or a takeover |
| L06 | `hatch::require_pip_installer_documents` ignores the `envs` override | core `utils/hatch.rs` | to verify |
| L07 | `scan --prune`: `has_ledger` probes `--cwd`, but `run_vendor_gc` reads `project_root()` | CLI `scan/gc.rs` | to verify; read, not run: a vendor-only prune with `--manifest-path` into another project returns early. Reached only on an empty crawl |
| L08 | `ui::shell_word` doesn't quote `"` or `%VAR%` for cmd.exe, so a printed remedy can't be pasted | CLI `ui/text.rs` | to verify |
| L09 | `api/client.rs` runs two retry policies that disagree on statuses, counts, jitter and an over-cap `Retry-After`; blob GETs and the upstream registry client retry nothing | core `api/` | to verify |
| L10 | warning sinks disagree on `--silent`/`--json` | CLI `scan/mod.rs`, `list.rs`, `user_patches.rs`, `scan/withdrawn.rs` | to verify |
| L13 | six Windows verbatim-prefix strippers disagree on UNC and `\\?\Volume{…}` paths | core `utils/`, `pnpm_workspace` | to verify |
| L14 | scala-cli `discover` collapses unreadable files and cap breaches into `None`, so the user is told to run `scala-cli compile` | core JVM crawlers | to verify; read, not run: the sbt callers keep the reason since they use `scan()`; scala-cli still returns `None` for an over-cap or foreign `.bloop` file |
| L15 | `list::sanitize` and `StatusPrinter::println` keep bidi and zero-width characters that core `policy::strip_unsafe` removes | CLI `list.rs`, `ui/status.rs` | to verify; read at da012af: still true. Whether a real manifest carries such text is the open question |
| L16 | `SOCKET_UPDATE_TIMEOUT_MS` is parsed twice; core caps `connect` at 10 s and the update notifier doesn't | core `UpdateTimeouts`, CLI `update_notifier.rs` | to verify |
| L17 | three hand scanners for Ruby `=begin` blocks; the heredoc heuristic misreads `x <<FLAG` | `vendor/gem.rs`, `vex/discover/gem.rs`, `redirect/upstream/gem.rs` | to verify; read, not run: `formats/gem/manifest.rs` `code_lines` keeps its own `heredoc_ids`, which takes `x <<FLAG` as a heredoc |
| L18 | `assert_proxy_served_scans` counts 404s as served, so a wrong mount path stays green | `tests/common/scan_proxy.rs` | to verify; read: true, but the guard claims hermeticity, which a 404 from the mock still proves |
| L19 | `check_derived_copies` turns a join error of the Gradle derived-copy check into "no stale copies"; vex's twin withholds | CLI `commands/apply.rs` | to verify; read twice: only an injected panic shows it |
| L20 | a keep for a removed dependency has no cause of its own: `KeepCause::of` calls it a drift in `remove`, `rollback`, `vendor` and the prune GC | CLI `vendored_backend/mod.rs` | to verify; from the review of #2246, read, not run |
| L21 | the prune GC drops the orphan sweep's still-wired set, which `vendor --revert`, `remove` and `rollback` report | CLI `vendor.rs` `run_vendor_gc` (#1910) | to verify |
| L22 | the prune GC raises no Go undo warning after it reverts a vendored Go module | CLI `vendor.rs` `run_vendor_gc` (#1910) | to verify; the sandbox has no Go |
| L23 | `scan --prune`'s `has_ledger` takes any stat error on the vendor ledger for "no ledger" | CLI `scan/gc.rs` | filed #2253; ran it with `state.json` as a symlink to itself: a clean `success`. The larger drop is in `run_vendor_gc`, which returns an empty summary for a ledger it cannot parse |
| L24 | plain `vendor` with no manifest and an unreadable ledger warns in human mode and says nothing under `--json` | CLI `vendor.rs` | filed #2253; ran it at da012af. Exit 0 is the contract's "clean exit-0 no-op"; the missing `warnings[]` entry is the defect, as it was for `list --json` |

Open `arch-audit` issues whose titles claim a real defect, so check them first: #1950 (`formats::xml::attr` matches inside another attribute's value; read: the matcher does, but whether a real file puts free text ahead of the attribute it reads is unchecked), #1926 (the "copy may still hold the patch" rule drifted; read, not run), #1917, #1912, #1899, #1887, #1069, #882.

Issues looked at:

| Issue | Status |
|---|---|
| #1910 | in PR #2246; the rest is L21 and L22 |
| #2249 | in PR #2250 |
| #2253 | filed this thread (L23, L24): `scan --prune` and `vendor --json` say nothing about a ledger they could not read |
| #2254 | filed this thread (L04): the vlt heal's "could not check" text is the hosted one after a rollback or takeover |
| #1982 | confirmed by mutation at da012af, and it passes the gate: three Gradle `--global-prefix` tests pass with the flag dropped or its handling broken. Evidence in a comment on the issue |
| #1970 | to verify; read at da012af: eight docker suites still serve a 64-zero `beforeHash` and apply with `--force`. Only CI can run them |
| #1014 | to verify; read at da012af: looks fixed, since `is_jvm_project` goes through `layout::is_jvm_build`, which has the root-relative markers. Run the issue's probe before closing, and check who commented |
| #1861, #1877 | out of charter; true by reading, but each needs a decision the contract doesn't settle (`remove`'s dry-run event with `--preserve-state`; the dry-run VEX warning outside `scan`) |
| #1927, #1969 | out of charter; #1927: about 15 `failed[].reason` tags share the generic phrase. #1969: the dropped `--offline` is lifecycle setup |
| #1963 | rejected and closed; both Gradle 6.8 gates read through `wrapper_distribution_version` since #2052 |
| #1114 | another agent's #2229 merged for it |

### Areas examined
| Area | Date | `main` | Found |
|---|---|---|---|
| `scan --prune` vendored GC, vendored revert classification | 2026-11-25 | 332b3e8 | #2246; L20 to L22 |
| core `utils/redact.rs`, `utils/npm_range.rs`, the repository-root walks | 2026-11-25 | 332b3e8 | nothing a real project can produce |
| an unreadable vendor ledger on every command that reads it | 2026-11-25 | 0a391c1, da012af | #2250, then #2253 (`scan --prune`, `vendor --json`) |
| `--json` / `--silent` output of 19 commands over 5 small projects (285 runs) | 2026-11-25 | 0a391c1 | stdout is one JSON document under `--json` and empty under `--silent` in every run |
| Gradle derived-copy checks (CLI `apply.rs`, core `jvm_jar.rs`, `gradle_cache.rs`) | 2026-11-25 | 0a391c1 | L19 holds by reading; nothing a real cache triggers |
| vlt heal (CLI and core `vlt_heal.rs`) | 2026-11-25 | da012af | #2254. Read errors are handled in the safe direction |
| gem stale-install guard over platform builds (CLI `gem_refresh.rs`) | 2026-11-25 | da012af | clean: builds are judged by leaf |
| Gradle `--global-prefix` tests (three CLI suites) | 2026-11-25 | da012af | #1982 confirmed. `scan --global-prefix` is covered; `apply`, `vex` and `rollback` are not |

### Notes
- Build with `CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0` on every cargo call, or the next one rebuilds everything. A cold CLI build takes 3 minutes, one test binary 2, a rebuild after an edit 25 seconds.
- CI's clippy is `cargo clippy --locked --workspace --all-features -- -D warnings`. With `--all-targets` it fails on `main` in `tests/common` and `tests/prebuilt_common`.
- Clap field doc comments are `--help` output: leave them alone.
- `--cwd` defaults to `.`: absolutize it before walking `ancestors()`, and test via chdir under `#[serial]`. A test runner that pins `--cwd` must not also set the child's cwd to the project.
- Making a `pub` core item private can leave rustdoc links to it; unlink them in the same commit.
- `git fetch --deepen=2500 origin main` takes seconds and makes `git log -S` usable on the shallow checkout.
- A write that returns 5xx may still have landed. List before you retry.
- The harness appends the "Generated by Claude Code" footer to issues, comments and PR bodies itself.
- Run the built binary over small broken projects and compare the commands: that found #2249 and #2253 in minutes. Set `SOCKET_TELEMETRY_DISABLED=1 SOCKET_NO_CONFIG=1`. For `scan`, a 30-line Python `http.server` that answers `POST /patch/batch` with `{"packages":[],"canAccessPaidPatches":false}` stands in for the patch API: pass it as `--proxy-url` with `NO_PROXY=127.0.0.1`.
- A throwaway probe test that prints what a function returns for the lead's input settles a lead in one rebuild, and can find the real defect next to a false claim (#2254).
- Run `/code-review high` again after fixing its findings.
- This sandbox has node, npm, pnpm, yarn 1, bun, uv, poetry, ruby and bundler, composer, java 21, mvn, gradle 8.14.3 and the docker CLI. It has no docker daemon, go, dotnet, sbt or deno. Real-Gradle tests run: `SOCKET_PATCH_GRADLE_E2E_REQUIRED=1 cargo test --test e2e_gradle_agent_build -- --ignored <name>` takes 35 seconds.
- Root-sandbox failures that pass in CI: the chmod tests in `tests/repair` (2) and `in_process_redirect` (3), core `copy_tree` with a symlinked root, `vlt_heal` with an unremovable lock, and the `pypi_poetry`/`pypi_requirements` wire-failure tests.
- To make a stat fail as root, use a symlink to itself (`ELOOP`); chmod doesn't stop root.
- To test the prune GC over a real revert without a toolchain, hand-build a ledger entry as `apply_gc_reports_drift_kept_vendored_entry` in `scan/gc.rs` does.
