<!-- arch-audit-register -->
## Register

[agent] This comment is the register for the architecture refactor routine. It is rendered from `register/10-refactor.md` on the [`arch-audit/ledger`](https://github.com/SocketDev/socket-patch/tree/arch-audit/ledger) branch, and the routine updates it on every run.

_Last updated 2026-11-26 · 8 runs under this charter · `main` at cfc870f when examined._

### In flight
| PR | Issue | State |
|---|---|---|
| #2261 | #2253, and the still-wired bullet of #1910 | ready, awaiting review |
| #2265 | #2254 | ready, awaiting review |
| #2267 | #1982 | ready, awaiting review. Test code only |

`hosted-e2e` is red on all three: it needs #2270 (a production gem patch the suite does not pin), then a re-run. Three are open: the next run opens none and verifies leads (step 3).

**Next PR:** #2259, a wrong refusal with a probe on `main` in the issue. One file (core `utils/hatch.rs`). Then #2271, #1917, #1926, #1860: each ran (see Issues).

### Merged
| PR | Fixed |
|---|---|
| #2250 | `remove <target>` and `rollback <target>` said "No patch found" over an unreadable vendor ledger, and `remove` restored files before refusing (#2249). Merged 2026-11-25 as ff949a3 |
| #2246 | `scan --prune` called a keep for a file that still installs from the artifact a drift, and dropped a failed revert's reason (part of #1910). Merged as ddf322a |
| #2241 | old charter, no defect: test-helper copies replaced by `tests/common`'s. Take no further T55 slices |

The 2026-10/11 sweep PRs are listed in `review/2026-11-v2/register/90-refactor.md`.

### Leads
L01 to L18 came from the previous thread's automated audits, the later rows from this routine's runs. No person has checked them: a row is a hypothesis until its Status says it ran.

| ID | Problem | Where | Status |
|---|---|---|---|
| L01–L03, L05, L11, L12, L16, L17, L20 | (nine rows collapsed) | core `utils/`, `vex/product.rs`, the gem stale probe, CLI `vex.rs`, the repository-root walks, the update notifier, `KeepCause::of`, the Gemfile scanners | rejected (L01–L03, L17: each ran and needs an input no real project produces. L16: the notifier's 500 ms grace bounds its fetch whatever the timeout. L20: no command keeps a requirement the user removed or bumped) or already fixed (L05; L11 since #2132; L12 through `utils::repo_root`). Evidence in the entries |
| L04, L07, L21, L23, L24 | (five rows collapsed) | CLI `vlt_heal.rs`, `scan/gc.rs`, `vendor.rs` `run_vendor_gc` | in PR #2265 (L04: ran with real vlt; the claim is false, the report's text was wrong) and in PR #2261 (L21, L23, L24 ran; L07 read). Evidence in the entries |
| L06 | `hatch::require_pip_installer_documents` ignores the `envs` override | core `utils/hatch.rs` | filed #2259; ran a probe: a `pyproject.toml` `installer = "uv"` that hatch.toml's `envs` replaces still refuses vendored mode. Never fails open |
| L08 | `ui::shell_word` doesn't quote `"` or `%VAR%` for cmd.exe, so a printed remedy can't be pasted | CLI `ui/text.rs` | to verify; read: `pypi_reinstall.rs` and `gem_refresh.rs` keep POSIX-only copies. Needs Windows |
| L09, L15, L26, L28, L29 | (five rows collapsed) | core `api/`, CLI `list.rs`, `vendor.rs` `run_vendor_gc`, `vlt_heal.rs`, `scan/withdrawn.rs` | out of charter; L09, L15 and L26 are true (L15 and L26 ran, L09 read) and need a decision the contract doesn't settle. L28, L29 (read): vlt never makes the layout, and the contract allows the order. Evidence in the entries |
| L10 | warning sinks disagree on `--silent`/`--json` | CLI `scan/mod.rs`, `list.rs`, `user_patches.rs`, `scan/withdrawn.rs` | to verify |
| L13 | six Windows verbatim-prefix strippers disagree on UNC and `\\?\Volume{…}` paths | core `utils/`, `pnpm_workspace` | to verify |
| L14 | scala-cli `discover` collapses unreadable files and cap breaches into `None`, so the user is told to run `scala-cli compile` | core JVM crawlers | to verify; read: no real project reaches the caps (8 MiB, 256 files). Open: a non-project `.json` Bloop might write there. No scala-cli here |
| L18 | `assert_proxy_served_scans` counts 404s as served, so a wrong mount path stays green | `tests/common/scan_proxy.rs` | to verify; read: true, but a 404 from the mock still proves the hermeticity the guard claims |
| L19 | `check_derived_copies` turns a join error of the Gradle derived-copy check into "no stale copies"; vex's twin withholds | CLI `commands/apply.rs` | to verify; read twice: only an injected panic shows it |
| L22 | the prune GC raises no Go undo warning after it reverts a vendored Go module | CLI `vendor.rs` `run_vendor_gc` (#1910) | to verify; the sandbox has no Go |
| L25 | the ledger's load error is printed raw, so control characters in a committed `state.json` reach the terminal | six CLI commands | filed #2271; ran it: ESC and BEL from a snapshot hash are printed, and `list` strips the same bytes from a manifest |
| L27 | `scan --prune --dry-run` previews without the dry-run lock, over files an interrupted vendored commit may have half replaced | CLI `scan/gc.rs` | to verify; read |

Open `arch-audit` issues whose titles claim a real defect, so check them first: #1981, #1064, #1069, #882, #647. Read, not run: #1912 (the two reuse caches differ on `build_failed`, one request more), #1887 (no real pom has a doubling property chain).

Issues looked at:

| Issue | Status |
|---|---|
| #1910 | fixed in part (#2246); the still-wired bullet is in PR #2261; L22 is unverified |
| #2253, #2254, #1982 | in PRs #2261, #2265, #2267 |
| #1970 | to verify; read at da012af: eight docker suites still serve a 64-zero `beforeHash` and apply with `--force`. Only CI can run them |
| #1014, #1963 | rejected and closed: each is covered by a test that passes. Evidence in the entries |
| #1950 | out of charter; ran a probe: only a hand-written value is misread |
| #2259, #2271 | filed this thread (L06, L25) |
| #1917 | confirmed; ran it: a project named `App.CSPROJ` scans as 0 packages (`App.csproj`: 1). The vendor side's `is_project_file` ignores case |
| #1926 | confirmed; ran it: `scan --sync` keeps a Cargo record over a cache file at neither hash ("still patched") and prunes it once the before-blob is cached. Rollback's twin (read) compares the hash |
| #1860 | confirmed; ran it: `list` prints U+202E, U+202C and U+200B from a manifest's description and a summary, and drops ESC and BEL. Same area as #2271 |
| #1899 | out of charter; the classifier drift is fixed (#1986). What is left is tidiness, or by design (`apply` refuses a global-virtual-store copy; its tests pass) |
| #1861, #1877 | out of charter; true by reading, but each needs a decision the contract doesn't settle |
| #1927, #1969 | out of charter; #1927: about 15 `failed[].reason` tags share the phrase. #1969: the dropped `--offline` is lifecycle setup |

### Areas examined
| Area | Date | `main` | Found |
|---|---|---|---|
| `scan --prune` vendored GC, the vendored revert classification, core `utils/redact.rs`, `utils/npm_range.rs`, the repository-root walks | 2026-11-25 | 332b3e8 | #2246 |
| an unreadable or lost vendor ledger on every command that reads it (`scan --prune` wet, dry and on an empty crawl; plain `vendor`); the orphan sweep's four callers | 2026-11-25 | 0a391c1 to cfc870f | #2250 (merged); #2253 and L21 (PR #2261). Left: L27 |
| `--json` / `--silent` output of 19 commands over 5 small projects (285 runs) | 2026-11-25 | 0a391c1 | clean: one JSON document under `--json`, nothing under `--silent` |
| Gradle: the derived-copy checks (CLI `apply.rs`, core `jvm_jar.rs`, `gradle_cache.rs`), also under a prefix; the three `--global-prefix` tests under two production mutations | 2026-11-25, 11-26 | 0a391c1, cfc870f | #2267. L19 holds by reading; nothing a real cache triggers |
| the vlt heal and its advisory in three directions (real vlt 1.2.0); the gem stale-install guard over platform builds | 2026-11-25, 11-26 | da012af, cfc870f | #2254 (PR #2265); the guard is clean. Left: L28, L29 |
| a vendored requirement the user removed or bumped, through `remove`, `rollback`, `vendor --revert` | 2026-11-25 | 9a2a946 | clean. The pip reinstall advisory's reason is wrong there; its remedy works |
| core `utils/hatch.rs` installer check, `formats/xml.rs` `attr`, `api/retry.rs`, the update notifier's timeouts | 2026-11-25 | 9a2a946 | #2259; the rest need a hand-written input or a decision |
| the prune's Cargo/PyPI keep rule; the NuGet project-file tests; `list`'s terminal filter; the Gemfile source-block scanners | 2026-11-26 | cfc870f | #1926, #1917, #1860 confirmed; L17 rejected |

### Notes
- Build with `CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0` on every cargo call, and give each checkout its own `CARGO_TARGET_DIR`, or the next call rebuilds everything. A cold CLI build takes 3 minutes, one test binary 2, a rebuild after an edit 25 seconds.
- CI's clippy is `cargo clippy --locked --workspace --all-features -- -D warnings`. With `--all-targets` it fails on `main` in `tests/common` and `tests/prebuilt_common`.
- `--cwd` defaults to `.`: absolutize it before walking `ancestors()`, and test via chdir under `#[serial]`. A test runner that pins `--cwd` must not also set the child's cwd to the project.
- `git fetch --deepen=2500 origin main` takes seconds and makes `git log -S` usable on the shallow checkout.
- A write that returns 5xx may have landed: list before you retry.
- The harness appends the "Generated by Claude Code" footer itself.
- Run the built binary over small broken projects and compare the commands: that found #2249, #2253 and L21 in minutes. Set `SOCKET_TELEMETRY_DISABLED=1 SOCKET_NO_CONFIG=1`. For `scan`, a Python `http.server` answering `POST /patch/batch` with `{"packages":[],"canAccessPaidPatches":false}` stands in for the patch API (`--proxy-url`, `NO_PROXY=127.0.0.1`).
- A throwaway probe test that prints a function's return for the lead's input settles it in one rebuild. For a test that can't fail, a one-line production mutation does the same; keep the diff for the PR body (#2267).
- Run `/code-review high` until a pass finds no real defect: #2261 took three passes and Bugbot.
- Run the `cli` suite after touching any test file: it holds ratchets over `tests/`.
- Most fixes edit `CLI_CONTRACT.md`, and so do most open `agent/*` PRs. #2261 went ahead beside #2258 (hunks 100 lines apart); the skip rule may need to say so.
- `main` requires every review thread resolved: an open one blocks an approved PR with auto-merge armed, and nothing says so (#2250 waited 45 minutes behind a nit). Answer and resolve threads first. A push does not dismiss approvals.
- Issue search works: `gh api -X GET search/issues -f q='repo:SocketDev/socket-patch is:issue is:open <words>'`.
- This sandbox has node, npm, pnpm, yarn 1, bun, uv, poetry, ruby and bundler, composer, java 21, mvn, gradle 8.14.3 and the docker CLI. It has no docker daemon, go, dotnet, sbt or deno. Real-Gradle tests run: `SOCKET_PATCH_GRADLE_E2E_REQUIRED=1 cargo test --test e2e_gradle_agent_build -- --ignored <name>` takes 35 seconds.
- Real-vlt legs run: `scripts/install-vlt.sh 1.2.0 <dir>` prints the path for `SOCKET_PATCH_VLT_E2E_JS` (set `_VERSION` and `_REQUIRED=1` too). The harness can't fetch from npmjs here: point `TMPDIR` at a scratch dir and curl `left-pad@1.3.0.{json,tgz}` and `ms@2.1.3.{json,tgz}` (the packument's version object, the tarball) into `socket-patch-test-caches/vlt-e2e-registry/v1/`.
- Root-sandbox failures that pass in CI: the chmod tests in `tests/repair` (2) and `in_process_redirect` (3), core `copy_tree` with a symlinked root, `vlt_heal` with an unremovable lock, and the `pypi_poetry`/`pypi_requirements` wire-failure tests.
- To make a stat fail as root, use a symlink to itself (`ELOOP`); chmod doesn't stop root.
- To test the prune GC over a real revert without a toolchain, hand-build a ledger entry as `apply_gc_reports_drift_kept_vendored_entry` in `scan/gc.rs` does.
