<!-- arch-audit-register -->
## Register

[agent] This comment is the register for the architecture refactor routine. It is rendered from `register/10-refactor.md` on the [`arch-audit/ledger`](https://github.com/SocketDev/socket-patch/tree/arch-audit/ledger) branch, and the routine updates it on every run.

_Last updated 2026-11-26 · 16 runs under this charter · `main` at cfc870f when examined._

### In flight
| PR | Issue | State |
|---|---|---|
| #2261 | #2253, and the still-wired bullet of #1910 | ready, awaiting review |
| #2265 | #2254 | ready, awaiting review |
| #2267 | #1982 | ready, awaiting review. Test code only |

`hosted-e2e` is red on all three: it needs #2270 (a production gem patch the suite does not pin; #2280 is open for it), then a re-run. Three are open: the next run opens none (step 3).

**Next PR:** #2287 (a printed credential), then #2290 (a `remove` that reports success), #2286 and #2289: the most harm. Then #2259 (core `utils/hatch.rs`), #2271, L22 (once #2261 merges: same function), #647, #1917, #1926, #1860, #1836: each ran. #2277 waits for a maintainer's answer.

### Merged
| PR | Fixed |
|---|---|
| #2250 | `remove <target>` and `rollback <target>` said "No patch found" over an unreadable vendor ledger, and `remove` restored files before refusing (#2249). Merged 2026-11-25 as ff949a3 |
| #2246 | `scan --prune` called a keep for a file that still installs from the artifact a drift, and dropped a failed revert's reason (part of #1910). Merged as ddf322a |
| #2241 | old charter, no defect. Take no further T55 slices |

The 2026-10/11 sweep PRs are listed in `review/2026-11-v2/register/90-refactor.md`.

### Leads
L01 to L18 came from earlier automated audits, the rest from this routine's runs. A row is a hypothesis until its Status says it ran.

| ID | Problem | Where | Status |
|---|---|---|---|
| L01–L03, L05, L10–L12, L16–L20 | (collapsed) | core `utils/`, `vex/`, CLI `vex.rs`, `apply.rs`, the root walks, the Gemfile scanners, the warning sinks | rejected (L01–L03, L10, L17 ran; L16, L20 false; L18, L19 read) or already fixed (L05, L11, L12). Evidence in the entries |
| L04, L07, L21, L23, L24 | (collapsed) | CLI `vlt_heal.rs`, `scan/gc.rs`, `vendor.rs` `run_vendor_gc` | in PR #2265 (L04) and in PR #2261 (L07, L21, L23, L24). Evidence in the entries |
| L06 | `hatch::require_pip_installer_documents` ignores the `envs` override | core `utils/hatch.rs` | filed #2259; ran a probe: an installer that `envs` replaces still refuses vendored mode. Never fails open |
| L08, L13 | `ui::shell_word` and its two POSIX-only copies don't quote `"` or `%VAR%` for cmd.exe; six verbatim-prefix strippers disagree on UNC and `\\?\Volume{…}` paths | CLI `ui/text.rs`, core `utils/` | to verify; both need Windows |
| L09, L15, L26–L29, L31, L32, L35 | (collapsed) | core `api/`, CLI `list.rs`, `vendor.rs`, `scan/gc.rs`, `scan/mod.rs`, `vlt_heal.rs`, `scan/withdrawn.rs` | out of charter; L09, L15, L26 and L31 (ran) need a decision the contract doesn't settle. The contract allows L27 (ran), L28, L29, L32 (ran) and L35 (ran). Evidence in the entries |
| L14 | scala-cli `discover` collapses unreadable files and cap breaches into `None`, so the user is told to run `scala-cli compile` | core JVM crawlers | to verify; read: no real project reaches the caps. Open: a non-project `.json` in Bloop's directory. scala-cli cannot be run here |
| L22 | the prune GC raises no Go undo warning after it reverts a vendored Go module | CLI `vendor.rs` `run_vendor_gc` | filed #1910 (its last bullet); ran it: `scan --prune` says nothing where the undo commands warn about `vendor/modules.txt` (#1778) |
| L25 | the ledger's load error is printed raw, so control characters in a committed `state.json` reach the terminal | six CLI commands | filed #2271; ran it: ESC and BEL from a snapshot hash are printed |
| L30 | `rollback` and `remove` refuse a package when a file of its patch is absent, the state `apply --force` leaves | core `patch/rollback.rs` | filed #2277, a decision issue; ran it |
| L33 | a failed `npm root -g` probe reads as "no global install" | core `crawlers/npm_crawler.rs`, CLI `rollback.rs` | filed #2286; ran it: `scan -g` finds nothing, and a project `rollback` drops the record of a copy still patched globally. #1009 fixed Bun's probe |
| L34 | refusals, hosted warnings, undo errors and a Gradle note print the credentials of a URL they quote | core `vendor/`, `patch/redirect/`, `crawlers/` | filed #2287; ran it: a planted token is printed at eight sites (four in a comment on the issue). #1026 redacted vendor warnings only |
| L36 | vendoring drops the only record of a PyPI package or gem whose installed copy is at neither hash, then says "no installed package found on disk" | CLI `vendor.rs` `CandidateGates::judge` | filed #2289; ran it: an agent-mode project on an older patch cannot switch to vendored. #769, #1105, #2129 each let one cause through |
| L37 | `remove <target>` and `rollback <target>` never ask whether a lockfile still installs from a vendor directory no ledger entry owns | CLI `remove.rs`, `rollback.rs` | filed #2290; ran it: `remove` exits 0, drops the record and leaves the lock wired. #991 fixed the unscoped `rollback` |

Issues looked at:

| Issue | Status |
|---|---|
| #1910 | fixed in part (#2246); the still-wired bullet is in PR #2261; the Go undo warning is confirmed (L22) |
| #1970 | to verify; read at da012af: eight docker suites still serve a 64-zero `beforeHash` and apply with `--force`. Only CI can run them |
| #1014, #1963, #717, #815 | rejected and closed; each ran. Evidence in the entries |
| #1917, #1926, #1860, #647, #1836 | confirmed; each ran: `App.CSPROJ` scans as 0 packages; `scan --sync` keeps, then prunes, a Cargo record over a cache file at neither hash; `list` prints bidi characters (beside #2271); `get`'s searches and `vendor`'s eject lack the public-proxy fallback; `get --json` orders `options[].vulnerabilities` at random. Evidence in the entries |
| 42 issues, named in the entries | out of charter; each ran or was read (14 read only): the contract settles it, tidiness, by design, latent, or copies that agree |
| #1114 | fixed in part (#2229); the CI janitor holds the rest |
| the other 29 open issues | out of charter by title, or "Decide:" issues; the 18:55Z entry lists them. Every `arch-audit` issue open at 19:00Z on 2026-11-26 has been looked at |

### Areas examined
| Area | Date | `main` | Found |
|---|---|---|---|
| the runs of 2026-11-25 and of 11-26 to 16:55Z (rows in their entries): agent mode's undo, prune, output and broken inputs; `--json` / `--silent`; Gradle; the vlt heal; failing toolchains; credentials in project files; purl spellings; cache crawls | 2026-11-25, 11-26 | 332b3e8 to cfc870f | the PRs and issues above up to #2287; the rest clean |
| hosted mode on the bench's 20 package managers: a planted credential through 17 commands; dry-run purity; rescans; rollback atomicity; `--json`, `--silent`, `--offline` | 2026-11-26 | cfc870f | four more sites of #2287; the rest clean |
| vendored mode on 8 package managers: the round trip over CRLF, BOM and tab lockfiles; tampered artifacts under `vex` and `vendor --check`; the undo commands over six states; an installed copy at other bytes | 2026-11-26 | cfc870f | #2289, #2290; the rest clean |

### Notes
- Build with `CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0` on every cargo call, and give each checkout its own `CARGO_TARGET_DIR`, or the next call rebuilds everything. A cold CLI build takes 3 minutes, one test binary 2, a rebuild after an edit 25 seconds.
- CI's clippy is `cargo clippy --locked --workspace --all-features -- -D warnings`. With `--all-targets` it fails on `main` in `tests/common` and `tests/prebuilt_common`.
- `--cwd` defaults to `.`: absolutize it before walking `ancestors()`, and test via chdir under `#[serial]`. A test runner that pins `--cwd` must not also set the child's cwd to the project.
- A write that returns 5xx may have landed: list before you retry.
- Read a posted body back: a permalink can come back wrapped in backticks, so cite a path and line numbers instead (#2287).
- Run the built binary over small broken projects and compare the commands. Set `SOCKET_TELEMETRY_DISABLED=1 SOCKET_NO_CONFIG=1`. For a patch API use the bench: `socket-patch-bench serve <pm>/hosted --bin <cli> --scale 0.02 --work-dir <dir>` builds a hosted project for any of 20 package managers, serves all three hosts and prints the command with its env (runner: the 18:55Z entry). Outside registries are refused, so an undo fails except for Hatch, Maven and Gradle. The 06:55Z, 08:56Z and 14:55Z entries have a refused token, a held `apply.lock` and a one-patch stand-in.
- Vendored mode runs on files alone: a lockfile, a manifest record and its blobs, with `tests/prebuilt_common`'s `Server::project(<dir>)` held open by a throwaway ignored test as the vendor service (the 20:56Z entry). Building a test rebuilds `target/debug/socket-patch` with core's test features: keep the plain binary in a second target directory.
- A throwaway probe test that prints a function's return for the lead's input settles it in one rebuild. For a test that can't fail, mutate one production line and keep the diff for the PR body (#2267).
- The owner was notified on 2026-11-26 of the three waiting PRs (05:15Z), #2277, #2286, #2287, #2289 and #2290. Don't notify again for the waiting PRs alone, or for more sites of a filed issue.
- Run `/code-review high` until a pass finds no real defect (#2261 took three), and the `cli` suite after touching any test file (it holds ratchets over `tests/`).
- Most fixes and most open `agent/*` PRs edit `CLI_CONTRACT.md`. #2261 went ahead beside #2258 (hunks 100 lines apart).
- `main` requires every review thread resolved: an open one blocks an approved PR with auto-merge armed, and nothing says so. Answer and resolve threads first. A push does not dismiss approvals.
- Issue search works: `gh api -X GET search/issues -f q='repo:SocketDev/socket-patch is:issue is:open <words>'`. `git fetch --deepen=2500 origin main` makes `git log -S` usable.
- This sandbox has node, npm, pnpm, yarn 1, bun, uv, poetry, ruby and bundler, composer, java 21, mvn and gradle 8.14.3. It has no docker daemon, go, dotnet, sbt, scala-cli or deno, and refuses to run a binary downloaded during the run. Real-Gradle tests run: `SOCKET_PATCH_GRADLE_E2E_REQUIRED=1 cargo test --test e2e_gradle_agent_build -- --ignored <name>` (35 seconds).
- Real-vlt legs run: `scripts/install-vlt.sh 1.2.0 <dir>` prints the path for `SOCKET_PATCH_VLT_E2E_JS` (set `_VERSION` and `_REQUIRED=1` too). npmjs is unreachable here: the entry of 2026-11-26 01:34Z says how to seed the harness's registry cache.
- Root-sandbox failures that pass in CI: the chmod tests in `tests/repair` (2) and `in_process_redirect` (3), core `copy_tree` with a symlinked root, `vlt_heal` with an unremovable lock, and the `pypi_poetry`/`pypi_requirements` wire-failure tests.
- To find unordered output, run one command six times over one fixture and count the distinct stdout hashes (#1836).
- To make a stat fail as root, use a symlink to itself (`ELOOP`); chmod doesn't stop root.
- A prune GC test over a real revert needs no toolchain: hand-build a ledger entry as `apply_gc_reports_drift_kept_vendored_entry` (`scan/gc.rs`) does. The 06:55Z entry of 2026-11-26 lists the files of a vendored Go module.
- An agent-mode fixture needs no server: the entry of 2026-11-26 12:55Z has a script that writes one and a matrix runner.
- To find a leak, plant a token wherever a package manager writes a URL, run every mode and every undo, and grep (#2287). A hand-built venv needs `include-system-site-packages = false`, or this machine's own packages are read.
- A script named after a tool, first on `PATH`, is a failing (`exit 1`) or hanging (`exec sleep 600`) probe. The entry of 2026-11-26 14:55Z has the fixture for a patched global copy.
