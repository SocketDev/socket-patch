<!-- arch-audit-register -->
## Register

[agent] This comment is the register for the architecture refactor routine. It is rendered from `register/10-refactor.md` on the [`arch-audit/ledger`](https://github.com/SocketDev/socket-patch/tree/arch-audit/ledger) branch, and the routine updates it on every run.

_Last updated 2026-11-25 · 1 run under this charter · `main` at 332b3e8 when examined._

### In flight
| PR | Issue | State |
|---|---|---|
| #2246 | #1910 (the prune GC's keep cause and failure reason) | ready, awaiting review. On merge: remove `agent:claimed` from #1910, which stays open for L21 and L22. |
| #2241 | #1959 (T55 slice 1) | ready. Opened by the last run under the old charter: it deletes test-helper copies that agree, so it isn't a real-problem PR. A maintainer decides whether it merges. Don't extend it, and don't take further T55 slices. |

### Merged
_None under this charter. The 2026-10/11 sweep PRs are listed in `review/2026-11-v2/register/90-refactor.md`._

### Leads
L01 to L18 were carried from the previous thread's notes: automated audits wrote them and no person has checked them. The later rows come from this routine's own runs. A row is a hypothesis until its Status says it ran: prove it or reject it.

| ID | Problem | Where | Status |
|---|---|---|---|
| L01 | npm `upstream_registry_fallback` may print a registry URL with `?token=` unredacted; `redact_urls_in` exists | core npm upstream registry client | rejected; ran it: the fallback warning does print `?token=` unredacted, but the client appends `/name/version` after the query, so a registry base with a query string serves nothing and no project has one |
| L02 | `strip_url_userinfo`'s scp-style branch keeps `user:pass@` | `vex/product.rs` | rejected; ran it: only a scheme-less `user:pass@host/path` keeps its userinfo, and git has no such remote form (scp style carries no password, and `scheme://` URLs are stripped) |
| L03 | `npm_range_admits(">=", v)` admits every version | core `utils/npm_range.rs` | rejected; ran it against node-semver: `>=`, `<` and `>=1.0.0 <` return `Some(true)` where npm says invalid, but no lock or manifest that npm or yarn accepts carries one, and 2 of the 3 callers treat "undecided" as admit anyway |
| L04 | `vlt_heal` swallows `load_state` and lock read errors and proceeds | CLI `commands/vlt_heal.rs` | to verify |
| L05 | the gem stale-install probe dedups by purl and drops the platform suffix, so a platform gem is judged by the ruby gem | gem stale probe (hosted) | to verify |
| L06 | `hatch::require_pip_installer_documents` ignores the `envs` override | core `utils/hatch.rs` | to verify |
| L07 | `scan --prune`: `has_ledger` probes `--cwd`, but `run_vendor_gc` reads `project_root()` | CLI `scan/gc.rs` | to verify; read, not run: `has_ledger` still probes `--cwd` while `run_vendor_gc` re-roots at the manifest's project (#745), so a vendor-only prune with `--manifest-path` into another project returns early. Reached only on an empty crawl |
| L08 | `ui::shell_word` doesn't quote `"` or `%VAR%` for cmd.exe, so a printed remedy can't be pasted | CLI `ui/text.rs` | to verify |
| L09 | `api/client.rs` runs two retry policies that disagree on statuses, counts, jitter and an over-cap `Retry-After`; blob GETs and the upstream registry client retry nothing | core `api/` | to verify |
| L10 | warning sinks disagree on `--silent`/`--json`: some print to stderr under `--json`, some drop warnings under `--silent` | CLI `scan/mod.rs`, `list.rs`, `user_patches.rs`, `scan/withdrawn.rs` | to verify |
| L11 | `.await.ok().flatten()` turns a `spawn_blocking` panic into "skip" (fails open) | CLI `commands/vex.rs` | already fixed; `vex.rs` withholds the purl on a join error since #2132 (`vex_gradle_derived_cache_check_failed`). Its twin in `apply.rs` is L19 |
| L12 | three hand-written repository-root walks ignore `GIT_CEILING_DIRECTORIES`; `utils::repo_root` honors it | core and CLI | already fixed; read: the core and CLI walks go through `utils::repo_root`. The one hand walk left, `governing_root::vlt_project_root`, mirrors vlt's own rule, which has no ceiling |
| L13 | six Windows verbatim-prefix strippers disagree on UNC and `\\?\Volume{…}` paths | core `utils/`, `pnpm_workspace` | to verify |
| L14 | sbt and scala-cli `discover` collapse unreadable files and cap breaches into `None`, so the user is told to run `sbt update`/`scala-cli compile` | core JVM crawlers | to verify; read, not run: the sbt callers now use `scan()` and keep the reason. scala-cli `discover` still returns `None` for an over-cap or foreign `.bloop` file, and the gate then says to run `scala-cli compile` |
| L15 | `list::sanitize` and `StatusPrinter::println` keep bidi and zero-width characters that core `policy::strip_unsafe` removes | CLI `list.rs`, `ui/status.rs` | to verify |
| L16 | `SOCKET_UPDATE_TIMEOUT_MS` is parsed twice; core caps `connect` at 10 s and the update notifier doesn't | core `UpdateTimeouts`, CLI `update_notifier.rs` | to verify |
| L17 | three hand scanners for Ruby `=begin` blocks; the heredoc heuristic misreads `x <<FLAG` and indented `<<~ID` terminators | `vendor/gem.rs`, `vex/discover/gem.rs`, `redirect/upstream/gem.rs` | to verify; read, not run: `formats/gem/ruby.rs` now masks heredocs for the Gemfile readers, but `formats/gem/manifest.rs` `code_lines` keeps its own `heredoc_ids`, which takes `x <<FLAG` as a heredoc |
| L18 | `assert_proxy_served_scans` counts 404s as served, so a wrong mount path stays green | `tests/common/scan_proxy.rs` | to verify |
| L19 | `check_derived_copies` turns a join error of the Gradle derived-copy check into "no stale copies" (`spawn_blocking(probe).await.ok().flatten()`), so `apply` reports a clean success; vex's twin withholds | CLI `commands/apply.rs` | to verify; read, not run: needs an injected panic, as vex's test does |
| L20 | a keep for a removed dependency (`vendor_lock_entry_removed` while a lockfile still mentions the artifact) has no cause of its own: `KeepCause::of` calls it a drift, so `remove`, `rollback`, `vendor` and the prune GC all say the lock drifted | CLI `vendored_backend/mod.rs`, core `npm_flavor::keep_artifact_while_lock_references_it` | to verify; from the review of #2246, read, not run |
| L21 | the prune GC drops the orphan sweep's still-wired set, which `vendor --revert`, `remove` and `rollback` report | CLI `vendor.rs` `run_vendor_gc` (#1910) | to verify |
| L22 | the prune GC raises no Go undo warning after it reverts a vendored Go module, so a committed `vendor/modules.txt` still records the replace and the next build fails unannounced | CLI `vendor.rs` `run_vendor_gc` (#1910) | to verify |

Open `arch-audit` issues whose titles claim a real defect, so check them first: #1970 (all-zeros `beforeHash` + `--force` in 8 docker suites), #1982 (Gradle `--global-prefix` tests pass without the flag), #1950 (`formats::xml::attr` matches inside another attribute's value), #1926 (the "copy may still hold the patch" rule drifted), #1927 (`gradle_unpatched_copy` has no phrase), #1899, #1887, #1069, #882.

Issues looked at:

| Issue | Status |
|---|---|
| #1910 | in PR #2246; two of its claims ran true (a reference keep reported as drift, a failed revert's reason dropped). The rest is L21 and L22 |
| #1861 | out of charter; true by reading (`remove` has no arm for a dry run with `--preserve-state`, `rollback` has), but the contract doesn't settle what `remove` should emit there (`rollback`: `verified` + `details.preserved`; `remove` wet: `skipped` / `vendor_state_preserved`). It needs a decision |
| #1969 | to verify; the filter is real (`prebuilt_common::prepare_command` drops `--offline` for `vendor` and `repair`, on purpose per its doc comment). It passes the gate only for a test that claims offline behavior, and needs the bun and composer toolchains to run |
| #1114 | another agent's #2229, merged 2026-11-25, targets it |

### Areas examined
| Area | Date | `main` | Found |
|---|---|---|---|
| `scan --prune` vendored GC (CLI `vendor.rs` `run_vendor_gc`, `scan/gc.rs`) | 2026-11-25 | 332b3e8 | a reference keep reported as drift, a failed revert's reason dropped: #2246. L21 and L22 not run |
| vendored revert classification (CLI `vendored_backend/mod.rs`) | 2026-11-25 | 332b3e8 | two causes for three kinds of keep: L20 |
| core `utils/redact.rs`, `utils/npm_range.rs` | 2026-11-25 | 332b3e8 | L01 to L03 ran; nothing a real project can produce |
| repository-root walks (core `utils/repo_root.rs` and its callers) | 2026-11-25 | 332b3e8 | read only; L12 is fixed |

### Rejected
L01, L02 and L03 (2026-11-25): each ran, and each needs an input no real project produces. Their rows say what ran.

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
- Root-sandbox failures that pass in CI: the chmod tests in `tests/repair` and `in_process_redirect`, core `copy_tree` with a symlinked root, `vlt_heal` with an unremovable lock, and the `pypi_poetry`/`pypi_requirements` wire-failure tests.
