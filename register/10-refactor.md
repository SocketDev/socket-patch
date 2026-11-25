<!-- arch-audit-register -->
## Register

[agent] This comment is the register for the architecture refactor routine. It is rendered from `register/10-refactor.md` on the [`arch-audit/ledger`](https://github.com/SocketDev/socket-patch/tree/arch-audit/ledger) branch, and the routine updates it on every run.

_Last updated 2026-11-25 · 4 runs under this charter · `main` at 9a2a946 when examined._

### In flight
None open.

**Next PR**, most harm first. Each has a failing test, probe or mutation on `main` in its issue:
1. #2253: a false success. Fix L21 (#1910) in the same PR: it is the same function, `run_vendor_gc`.
2. #2254: wrong advice after a rollback. One file (`vlt_heal.rs`).
3. #1982: three Gradle tests that can't fail on the flag they name.
4. #2259: a wrong refusal. One file (core `utils/hatch.rs`).

### Merged
| PR | Fixed |
|---|---|
| #2250 | `remove <target>` and `rollback <target>` said "No patch found" over an unreadable vendor ledger, `remove` restored files before refusing, and a ledger that could not be stat'd read as none (#2249). Merged 2026-11-25 as ff949a3 |
| #2246 | `scan --prune` called a keep for a file that still installs from the artifact a drift, and dropped a failed revert's reason (part of #1910). Merged as ddf322a |
| #2241 | old charter, no defect: test-helper copies replaced by `tests/common`'s. Take no further T55 slices |

The 2026-10/11 sweep PRs are listed in `review/2026-11-v2/register/90-refactor.md`.

### Leads
L01 to L18 came from the previous thread's automated audits, the later rows from this routine's runs. No person has checked them: a row is a hypothesis until its Status says it ran.

| ID | Problem | Where | Status |
|---|---|---|---|
| L01–L03, L05, L11, L12, L16, L20 | (eight rows collapsed) | core `utils/`, `vex/product.rs`, the gem stale probe, CLI `vex.rs`, the repository-root walks, the update notifier, `KeepCause::of` | rejected (L01–L03: each ran and needs an input no real project produces. L16: the notifier's 500 ms grace bounds its fetch whatever the timeout. L20: no command keeps a requirement the user removed or bumped) or already fixed (L05; L11 since #2132; L12 through `utils::repo_root`). Evidence in the entries |
| L04 | `vlt_heal` swallows `load_state` and lock read errors and proceeds | CLI `commands/vlt_heal.rs` | filed #2254; ran a probe. The claim is false (read errors go the safe way), but the "could not check" report prints the hosted text after a rollback or a takeover |
| L06 | `hatch::require_pip_installer_documents` ignores the `envs` override | core `utils/hatch.rs` | filed #2259; ran a probe: a `pyproject.toml` `installer = "uv"` that hatch.toml's `envs` replaces still refuses vendored mode. Never fails open |
| L07 | `scan --prune`: `has_ledger` probes `--cwd`, but `run_vendor_gc` reads `project_root()` | CLI `scan/gc.rs` | to verify; read: reached only on an empty crawl with `--manifest-path` into another project |
| L08 | `ui::shell_word` doesn't quote `"` or `%VAR%` for cmd.exe, so a printed remedy can't be pasted | CLI `ui/text.rs` | to verify |
| L09 | `api/client.rs` runs two retry policies that disagree on statuses, counts and jitter | core `api/` | out of charter; read: both are deliberate and documented. Merging them changes defaults the contract doesn't settle |
| L10 | warning sinks disagree on `--silent`/`--json` | CLI `scan/mod.rs`, `list.rs`, `user_patches.rs`, `scan/withdrawn.rs` | to verify |
| L13 | six Windows verbatim-prefix strippers disagree on UNC and `\\?\Volume{…}` paths | core `utils/`, `pnpm_workspace` | to verify |
| L14 | scala-cli `discover` collapses unreadable files and cap breaches into `None`, so the user is told to run `scala-cli compile` | core JVM crawlers | to verify; read: still `None` for an over-cap or foreign `.bloop` file. The sbt callers keep the reason |
| L15 | `list::sanitize` keeps bidi and zero-width characters that core `policy::strip_unsafe` removes | CLI `list.rs`, `ui/status.rs` | out of charter; ran it: `list` prints U+202E and U+200B, but only from a hand-edited manifest. Which invisible characters a description may keep (emoji use U+200D) is a decision |
| L17 | three hand scanners for Ruby `=begin` blocks; the heredoc heuristic misreads `x <<FLAG` | `vendor/gem.rs`, `vex/discover/gem.rs`, `redirect/upstream/gem.rs` | to verify; read: `formats/gem/manifest.rs` keeps its own `heredoc_ids`, which takes `x <<FLAG` as a heredoc |
| L18 | `assert_proxy_served_scans` counts 404s as served, so a wrong mount path stays green | `tests/common/scan_proxy.rs` | to verify; read: true, but a 404 from the mock still proves the hermeticity the guard claims |
| L19 | `check_derived_copies` turns a join error of the Gradle derived-copy check into "no stale copies"; vex's twin withholds | CLI `commands/apply.rs` | to verify; read twice: only an injected panic shows it |
| L21 | the prune GC drops the orphan sweep's still-wired set | CLI `vendor.rs` `run_vendor_gc` | filed #1910; ran it: over a requirements file that installs from a vendor dir no ledger entry owns, `vendor --revert` reports `vendor_orphan_still_wired`, `rollback` fails with `vendor_ledger_missing`, and `scan --prune` says `success` and nothing else. Evidence on #1910 |
| L22 | the prune GC raises no Go undo warning after it reverts a vendored Go module | CLI `vendor.rs` `run_vendor_gc` (#1910) | to verify; the sandbox has no Go |
| L23 | `scan --prune`'s `has_ledger` takes any stat error on the vendor ledger for "no ledger" | CLI `scan/gc.rs` | filed #2253; ran it: a clean `success`. The larger drop is `run_vendor_gc`'s empty summary for a ledger it cannot parse |
| L24 | plain `vendor` with an unreadable ledger warns in human mode and says nothing under `--json` | CLI `vendor.rs` | filed #2253; ran it. Exit 0 is the contract's no-op; the missing `warnings[]` entry is the defect |

Open `arch-audit` issues whose titles claim a real defect, so check them first: #1926 (the "copy may still hold the patch" rule drifted; read, not run), #1917, #1912, #1899, #1887, #1069, #882.

Issues looked at:

| Issue | Status |
|---|---|
| #1910 | fixed in part (#2246), claim released; L21 is confirmed and L22 is unverified |
| #2253 | filed this thread (L23, L24): `scan --prune` and `vendor --json` say nothing about a ledger they could not read. Re-ran at 9a2a946, after #2246: still so |
| #2254 | filed this thread (L04): the vlt heal's "could not check" text is the hosted one after a rollback or takeover |
| #1982 | confirmed by mutation at da012af: three Gradle `--global-prefix` tests pass with the flag dropped or its handling broken. Evidence on the issue |
| #1970 | to verify; read at da012af: eight docker suites still serve a 64-zero `beforeHash` and apply with `--force`. Only CI can run them |
| #1014, #1963 | rejected and closed. #1014: its two cases are in `local_scala_caches_only_for_scala_tool_projects`, which passes (#1032). #1963: both Gradle 6.8 gates read through `wrapper_distribution_version` (#2052) |
| #1950 | out of charter; ran a probe: `attr` reads `name` out of `value=" name='no'"`, but reads what Gradle and Ivy write correctly |
| #2259 | filed this thread (L06): the Hatch uv-installer check reads environments that hatch.toml replaces |
| #1861, #1877 | out of charter; true by reading, but each needs a decision the contract doesn't settle |
| #1927, #1969 | out of charter; #1927: about 15 `failed[].reason` tags share the phrase. #1969: the dropped `--offline` is lifecycle setup |
| #1114 | another agent's #2229 merged for it |

### Areas examined
| Area | Date | `main` | Found |
|---|---|---|---|
| `scan --prune` vendored GC, the vendored revert classification, core `utils/redact.rs`, `utils/npm_range.rs`, the repository-root walks | 2026-11-25 | 332b3e8 | #2246 |
| an unreadable vendor ledger on every command that reads it | 2026-11-25 | 0a391c1, da012af | #2250 (merged), then #2253 (`scan --prune`, `vendor --json`) |
| `--json` / `--silent` output of 19 commands over 5 small projects (285 runs) | 2026-11-25 | 0a391c1 | clean: one JSON document under `--json`, nothing under `--silent` |
| Gradle derived-copy checks (CLI `apply.rs`, core `jvm_jar.rs`, `gradle_cache.rs`) | 2026-11-25 | 0a391c1 | L19 holds by reading; nothing a real cache triggers |
| vlt heal, the gem stale-install guard over platform builds, the three Gradle `--global-prefix` suites | 2026-11-25 | da012af | #2254; the guard is clean; #1982 confirmed (`scan --global-prefix` is covered; `apply`, `vex` and `rollback` are not) |
| the orphan sweep's four callers | 2026-11-25 | 9a2a946 | L21 confirmed: only `scan --prune` drops the still-wired set |
| a vendored requirement the user removed or bumped, through `remove`, `rollback`, `vendor --revert` | 2026-11-25 | 9a2a946 | clean: the entry and the wheel go, exit 0. The pip reinstall advisory's reason is wrong there; its remedy still works |
| core `utils/hatch.rs` installer check, `formats/xml.rs` `attr`, `api/retry.rs`, the update notifier's timeouts | 2026-11-25 | 9a2a946 | #2259; the rest need a hand-written input or a decision |

### Notes
- Build with `CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0` on every cargo call, and give each checkout its own `CARGO_TARGET_DIR`, or the next call rebuilds everything. A cold CLI build takes 3 minutes, one test binary 2, a rebuild after an edit 25 seconds.
- CI's clippy is `cargo clippy --locked --workspace --all-features -- -D warnings`. With `--all-targets` it fails on `main` in `tests/common` and `tests/prebuilt_common`.
- Clap field doc comments are `--help` output: leave them alone.
- `--cwd` defaults to `.`: absolutize it before walking `ancestors()`, and test via chdir under `#[serial]`. A test runner that pins `--cwd` must not also set the child's cwd to the project.
- Making a `pub` core item private can leave rustdoc links to it; unlink them in the same commit.
- `git fetch --deepen=2500 origin main` takes seconds and makes `git log -S` usable on the shallow checkout.
- A write that returns 5xx may still have landed. List before you retry.
- The harness appends the "Generated by Claude Code" footer to issues, comments and PR bodies itself.
- Run the built binary over small broken projects and compare the commands: that found #2249, #2253 and L21 in minutes. Set `SOCKET_TELEMETRY_DISABLED=1 SOCKET_NO_CONFIG=1`. For `scan`, a 30-line Python `http.server` answering `POST /patch/batch` with `{"packages":[],"canAccessPaidPatches":false}` stands in for the patch API (`--proxy-url`, with `NO_PROXY=127.0.0.1`).
- A throwaway probe test that prints what a function returns for the lead's input settles a lead in one rebuild (#2254, #2259).
- Run `/code-review high` again after fixing its findings.
- `main` requires every review thread resolved: an open one blocks an approved PR with auto-merge armed, and nothing says so (#2250 waited 45 minutes behind a nit). Answer and resolve threads first. A push does not dismiss approvals.
- Issue search works: `gh api -X GET search/issues -f q='repo:SocketDev/socket-patch is:issue is:open <words>'`.
- This sandbox has node, npm, pnpm, yarn 1, bun, uv, poetry, ruby and bundler, composer, java 21, mvn, gradle 8.14.3 and the docker CLI. It has no docker daemon, go, dotnet, sbt or deno. Real-Gradle tests run: `SOCKET_PATCH_GRADLE_E2E_REQUIRED=1 cargo test --test e2e_gradle_agent_build -- --ignored <name>` takes 35 seconds.
- Root-sandbox failures that pass in CI: the chmod tests in `tests/repair` (2) and `in_process_redirect` (3), core `copy_tree` with a symlinked root, `vlt_heal` with an unremovable lock, and the `pypi_poetry`/`pypi_requirements` wire-failure tests.
- To make a stat fail as root, use a symlink to itself (`ELOOP`); chmod doesn't stop root.
- To test the prune GC over a real revert without a toolchain, hand-build a ledger entry as `apply_gc_reports_drift_kept_vendored_entry` in `scan/gc.rs` does.
