<!-- arch-audit-register -->
## Register

[agent] The register of the architecture refactor routine, rendered from `register/10-refactor.md` on the [`arch-audit/ledger`](https://github.com/SocketDev/socket-patch/tree/arch-audit/ledger) branch on every run.

_Last updated 2026-11-28 · 36 runs under this charter · `main` at cfc870f when examined._

### In flight
| PR | Issue | State |
|---|---|---|
| #2261 | #2253, and the still-wired bullet of #1910 | ready, awaiting review |
| #2265 | #2254 | ready, awaiting review |
| #2267 | #1982 | ready, awaiting review. Test code only |

`hosted-e2e` is red on all three: it needs #2270 (#2280 is open for it), then a re-run.

**Next PR:** #2301 (a cleanup deletes the project's files), then #2303, #2305, #2308, #2310, #2312, #2314 and #2317 (seven tools' copies; #2312 and #2314 share a fix), #2287 (a printed credential), #2330 and #2332 (a tampered tarball or jar passes), #2290, #2299, #2327 with #2334, #2318, #2321, #2286, #2289, #2315 (a stale VEX document), #2336 and #2337 (a token copy left for `git add`). Then #2259, #2294, #2296, #2271, L22 (after #2261), #647, #1917, #1926, #1860, #1836, #2306, #2322, #2324, #2328 (low), #2319 and #2333 (test only). #2277, #2297 and #2309 wait for a maintainer's answer.

### Merged
| PR | Fixed |
|---|---|
| #2250 | `remove <target>` and `rollback <target>` said "No patch found" over an unreadable vendor ledger, and `remove` restored files before refusing (#2249). Merged as ff949a3 |
| #2246 | `scan --prune` called a keep for a file that still installs from the artifact a drift, and dropped a failed revert's reason (part of #1910). Merged as ddf322a |
| #2241 | old charter, no defect. Take no further T55 slices |

Earlier sweep PRs: `review/2026-11-v2/register/90-refactor.md`.

### Leads
L01 to L18 came from earlier audits, the rest from this routine. A row is a hypothesis until its Status says it ran.

| ID | Problem | Where | Status |
|---|---|---|---|
| L01–L03, L05, L10–L12, L16–L20 | (collapsed) | core and CLI: named in the entries | rejected (L01–L03, L10, L17 ran; L16, L20 false; L18, L19 read) or already fixed (L05, L11, L12) |
| L04, L07, L21, L23, L24 | (collapsed) | CLI `vlt_heal.rs`, `scan/gc.rs`, `vendor.rs` | in PR #2265 (L04) and in PR #2261 (the rest) |
| L08, L13 | `ui::shell_word` and its two POSIX-only copies don't quote `"` or `%VAR%` for cmd.exe; six verbatim-prefix strippers disagree on UNC and `\\?\Volume{…}` paths | CLI `ui/text.rs`, core `utils/` | to verify; both need Windows |
| L09, L15, L26–L29, L31, L32, L35, L39, L45, L62, L66, L70 | (collapsed) | core and CLI: named in the entries | out of charter; L09, L15, L26 and L31 need a decision the contract doesn't settle. The contract allows L27 to L29, L32, L35 and L45. L39: the contract's telemetry list omits a `ci` flag. L62: a Node addon latency test mostly passes without its race. L66: no test names the blob download's hash check (#2333). L70: a hosted `rollback` killed mid-write leaves Gradle wiring no command lists; the contract leaves a kill uncovered. All ran but L28 and L29 |
| L14 | scala-cli `discover` collapses unreadable files and cap breaches into `None`, so the user is told to run `scala-cli compile` | core JVM crawlers | to verify; read: no real project reaches the caps. Open: a non-project `.json` in Bloop's directory. Needs scala-cli |
| L22 | the prune GC raises no Go undo warning after it reverts a vendored Go module | CLI `vendor.rs` `run_vendor_gc` | filed #1910 (its last bullet); ran it: `scan --prune` says nothing where the undo commands warn (#1778) |
| L06, L25, L30, L33, L34, L36–L38, L40–L44, L46–L61, L63–L65, L67–L69 | (collapsed) | CLI and core: named in the issues | filed #2259, #2271, #2277, #2286, #2287, #2289, #2290, #2294, #2296, #2297, #2299, #2301, #2303, #2305, #2306, #2308 to #2310, #2312, #2314, #2315, #2317 to #2319, #2321, #2322, #2324, #2327, #2328, #2330, #2332 to #2334, #2336, #2337; each ran |

Issues looked at:

| Issue | Status |
|---|---|
| #1910 | fixed in part (#2246); the still-wired bullet is in PR #2261; the Go undo warning is confirmed (L22) |
| #1970 | to verify; read at da012af: eight docker suites still serve a 64-zero `beforeHash` and apply with `--force`. Only CI can run them |
| #1014, #1963, #717, #815 | rejected and closed; each ran |
| #1917, #1926, #1860, #647, #1836 | confirmed; each ran |
| 42 issues, named in the entries | out of charter; each ran or was read (14 read only) |
| #1114 | fixed in part (#2229); the CI janitor holds the rest |
| the other 29 open issues | out of charter by title, or "Decide:" issues (the 18:55Z entry). Every `arch-audit` issue open at 12:55Z of 11-28 has been looked at |

### Areas examined
| Area | Date | `main` | Found |
|---|---|---|---|
| agent mode's undo, prune, output and broken inputs; `--json` / `--silent`; Gradle; the vlt heal; failing toolchains; credentials in project files; purl spellings; cache crawls; hosted mode on the bench's 20 package managers, vendored on 8; the `socket.yml` policy and filter; telemetry; `vex --grype-config`; the socket-cli config; a monorepo; the patch API failing mid-run; `report`; `--update`; a newer patch; linked `.socket/` stores; the contract's `jq` recipes; undo targets; a manifest outside `.socket/`; the in-memory hosted engine; the update notice; partial hosted writes; the project-patch gate; Cargo's agent mode; a native-extension gem; the copy each real tool loads; the VEX flags; `--vex` after a failed host command; the entrypoint command; closed pipes; the rollout limit; undo, lock and drift flags; wrong blobs; linked installs; `-g` with seven real tools; a Git checkout of each committed tree; 44 gate mutants; the patch mirror; failing writes; version and range readers; escaping paths; the Node addon; boolean env spellings; the pnpm route's cleanup; size limits; tarball and jar readers; VEX product detection; a merge conflict in five locks; path arguments and `--cwd` spellings; `--prune` under filters; modes and owners of rewritten files; kills and signals at random moments, agent and hosted | 2026-11-25 to 11-28 | 332b3e8 to cfc870f | the PRs and the issues up to #2337 in the Leads rows; the rest clean |

### Notes
- Build with `CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0`. Leave `CARGO_TARGET_DIR` unset: the Cargo suites' `apply` deletes fingerprints in it, and the next call rebuilds. A cold CLI build takes 3 minutes, core's unit tests 4 and 9 GB: never during a test run.
- CI's clippy is `cargo clippy --locked --workspace --all-features -- -D warnings`. With `--all-targets` it fails on `main` in `tests/common` and `tests/prebuilt_common`.
- `--cwd` defaults to `.`: absolutize it before walking `ancestors()`, and test via chdir under `#[serial]`. A test runner that pins `--cwd` must not also set the child's cwd to the project. Run a path argument relative, as `.` and absolute with no `--cwd` (#2336).
- A write that returns 5xx may have landed: list first.
- Cite a path and line numbers, not a permalink (#2287).
- Run the built binary over small broken projects. Set `SOCKET_TELEMETRY_DISABLED=1 SOCKET_NO_CONFIG=1`. For a patch API use the bench: `socket-patch-bench serve <pm>/hosted --bin <cli> --scale 0.02 --work-dir <dir>` builds a hosted project for any of 20 package managers and prints its command (runner: the 18:55Z entry). Its env refuses outside registries, so an undo fails except for Hatch, Maven and Gradle. Fixtures: a held `apply.lock` (08:56Z of 11-26), a stand-in API (22:56Z), failure rules (00:55Z of 11-27), real-tool layouts (08:55Z), wrong blobs (18:56Z).
- Vendored mode runs on files alone, with `tests/prebuilt_common`'s `Server::project(<dir>)` held open by a throwaway ignored test as the vendor service (the 20:56Z entry). Building a test rebuilds `target/debug/socket-patch` with core's test features: copy the plain binary aside first.
- A throwaway probe test over the lead's input settles it in one rebuild. For a test that can't fail, mutate production and keep the diff (#2267). Many mutants fit one build behind an env variable (20:56Z of 11-27). Mutate the call site, and call none a survivor before every suite naming its ecosystem ran (06:55Z of 11-28).
- For a crash, signal the built binary at a random moment in a loop and classify the tree (12:55Z of 11-28); debug builds also stop at `SOCKET_PATCH_FAILPOINT` names. Package stages age by ctime: `touch` cannot age them.
- The owner was notified of the three waiting PRs and of each issue from #2277 to #2337 (not #2319, #2324, #2328 or #2333: low harm). Don't notify again for the waiting PRs alone or for more sites of a filed issue.
- Run `/code-review high` until a pass finds no real defect (#2261 took three), and the `cli` suite after touching any test file (it holds ratchets over `tests/`).
- Most open `agent/*` PRs edit `CLI_CONTRACT.md`: far-apart hunks are fine (#2261).
- `main` requires every review thread resolved: an open one silently blocks an approved PR. A push does not dismiss approvals.
- Issue search: `gh api -X GET search/issues -f q='repo:SocketDev/socket-patch is:issue <words>'`. Other routines file `bughunt` issues: search before filing. `git fetch --deepen=2500 origin main` makes `git log -S` work.
- This sandbox has node, npm, pnpm 10.28, yarn 1, bun, uv, poetry, ruby and bundler, composer, java 21, mvn, gradle 8.14.3, go 1.24.7, gcc, and cargo 1.97.0 outside the repository (1.93.1 inside). PDM, Pipenv and Hatch install from PyPI as CI's suites do (pins: the 10:56Z entry of 11-27); read `ci.yml` before writing "needs X". It has no docker daemon, dotnet, sbt, scala-cli, deno, bazel, conda or route to the public patch API, and won't run a downloaded tool.
- Real-vlt legs: `scripts/install-vlt.sh 1.2.0 <dir>` prints the path for `SOCKET_PATCH_VLT_E2E_JS` (set `_VERSION` and `_REQUIRED=1`; registry cache: the 01:34Z entry of 11-26). Real-Gradle tests: `SOCKET_PATCH_GRADLE_E2E_REQUIRED=1` and `--ignored`.
- Root-sandbox failures that pass in CI: the chmod tests in `tests/repair` (2) and `in_process_redirect` (3), core `copy_tree` with a symlinked root, `vlt_heal` with an unremovable lock, and the `pypi_poetry`/`pypi_requirements` wire-failure tests.
- To make a stat fail as root, use a symlink to itself; chmod doesn't stop root.
- A real `mvn` run caches `commons-text` 1.10.0 and `commons-parent` 54, which three `vendor::maven_repo` tests then read: remove them from `~/.m2`, or test under an empty `MAVEN_REPO_LOCAL`.
- Ask the package manager what it reads, then compare: `cargo metadata` names the copy cargo builds (#2305), `uv run python -c 'import x; print(x.__file__)'` the one Python imports (#2308), `bundle exec ruby -e` with `$LOADED_FEATURES` the gem (#2317). Run it from a workspace member and with another virtualenv activated. An agent-mode or `-g` Python run can write the OS Python: use `--dry-run`, or roll back and run `dpkg --verify`. Run every spelling of a key (#2306). Scan before asking: `pdm run` saves `.pdm-python` again (#2310). As root, `yarn global add` and `bundle install` write outside `HOME`: uninstall after.
- A prune GC test over a real revert needs no toolchain: hand-build a ledger entry as `apply_gc_reports_drift_kept_vendored_entry` (`scan/gc.rs`) does.
- A script named after a tool, first on `PATH`, is a failing or hanging probe.
- Before filing a drift between lock readers, read `docs/design/lock-model-divergences.md`: the owner's decided list.
- Recipes, in their issues: unordered output (#1836), a stale output file (#2315), the user's files beside a layout (#2301), subsets of a run's writes (#2303), a planted token (#2287), an autocrlf clone (#2318), a mirror stand-in and a failing write (the 22:56Z entry), a reader against its tool's library (00:56Z of 11-28), the Node addon and route states from the golden fixtures (02:55Z), a merge conflict (#2334), a tarball the installers read past (#2330), a jar's repeated name and hash chain (#2332).
