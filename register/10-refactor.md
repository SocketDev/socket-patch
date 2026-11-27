<!-- arch-audit-register -->
## Register

[agent] This comment is the register for the architecture refactor routine. It is rendered from `register/10-refactor.md` on the [`arch-audit/ledger`](https://github.com/SocketDev/socket-patch/tree/arch-audit/ledger) branch, and the routine updates it on every run.

_Last updated 2026-11-27 · 24 runs under this charter · `main` at cfc870f when examined._

### In flight
| PR | Issue | State |
|---|---|---|
| #2261 | #2253, and the still-wired bullet of #1910 | ready, awaiting review |
| #2265 | #2254 | ready, awaiting review |
| #2267 | #1982 | ready, awaiting review. Test code only |

`hosted-e2e` is red on all three: it needs #2270 (a production gem patch the suite does not pin; #2280 is open for it), then a re-run.

**Next PR:** #2301 (a cleanup that deletes the project's own files), then #2303, #2305, #2308, #2310 and #2312 (a gem, a crate, a uv workspace member, a PDM project and a Maven jar reported as patched and not patched), #2287 (a printed credential), #2290 (a `remove` that reports success), #2299 (a failed upgrade that strands the project), #2286 and #2289: the most harm. Then #2259, #2294, #2296, #2271, L22 (once #2261 merges: same function), #647, #1917, #1926, #1860, #1836, #2306: each ran. #2277, #2297 and #2309 wait for a maintainer's answer.

### Merged
| PR | Fixed |
|---|---|
| #2250 | `remove <target>` and `rollback <target>` said "No patch found" over an unreadable vendor ledger, and `remove` restored files before refusing (#2249). Merged 2026-11-25 as ff949a3 |
| #2246 | `scan --prune` called a keep for a file that still installs from the artifact a drift, and dropped a failed revert's reason (part of #1910). Merged as ddf322a |
| #2241 | old charter, no defect. Take no further T55 slices |

The earlier sweep PRs: `review/2026-11-v2/register/90-refactor.md`.

### Leads
L01 to L18 came from earlier audits, the rest from this routine. A row is a hypothesis until its Status says it ran.

| ID | Problem | Where | Status |
|---|---|---|---|
| L01–L03, L05, L10–L12, L16–L20 | (collapsed) | core and CLI: named in the entries | rejected (L01–L03, L10, L17 ran; L16, L20 false; L18, L19 read) or already fixed (L05, L11, L12). Evidence in the entries |
| L04, L07, L21, L23, L24 | (collapsed) | CLI `vlt_heal.rs`, `scan/gc.rs`, `vendor.rs` | in PR #2265 (L04) and in PR #2261 (the rest) |
| L06 | `hatch::require_pip_installer_documents` ignores the `envs` override | core `utils/hatch.rs` | filed #2259; ran a probe: an installer that `envs` replaces still refuses vendored mode |
| L08, L13 | `ui::shell_word` and its two POSIX-only copies don't quote `"` or `%VAR%` for cmd.exe; six verbatim-prefix strippers disagree on UNC and `\\?\Volume{…}` paths | CLI `ui/text.rs`, core `utils/` | to verify; both need Windows |
| L09, L15, L26–L29, L31, L32, L35, L39, L45 | (collapsed) | core and CLI: named in the entries | out of charter; L09, L15, L26 and L31 need a decision the contract doesn't settle. The contract allows L27 to L29, L32, L35 and L45 (a hosted rescan leaves a `pom.xml` pin's lost `.mvn/` checksum files). L39: the contract's telemetry list omits a `ci` flag. All ran but L28 and L29. Evidence in the entries |
| L14 | scala-cli `discover` collapses unreadable files and cap breaches into `None`, so the user is told to run `scala-cli compile` | core JVM crawlers | to verify; read: no real project reaches the caps. Open: a non-project `.json` in Bloop's directory. Needs scala-cli |
| L22 | the prune GC raises no Go undo warning after it reverts a vendored Go module | CLI `vendor.rs` `run_vendor_gc` | filed #1910 (its last bullet); ran it: `scan --prune` says nothing where the undo commands warn (#1778) |
| L25, L30, L33, L34, L36–L38, L40–L44, L46–L51 | (collapsed) | CLI commands; core `patch/`, `crawlers/`, `vendor/`, `policy/`, `manifest/`, `formats/cargo/`: named in the issues | filed #2271, #2277, #2286, #2287, #2289, #2290, #2294, #2296, #2297, #2299, #2301, #2303, #2305, #2306, #2308, #2309, #2310, #2312, in lead order (#2277, #2297 and #2309 are decision issues); each ran. Evidence in the issues |

Issues looked at:

| Issue | Status |
|---|---|
| #1910 | fixed in part (#2246); the still-wired bullet is in PR #2261; the Go undo warning is confirmed (L22) |
| #1970 | to verify; read at da012af: eight docker suites still serve a 64-zero `beforeHash` and apply with `--force`. Only CI can run them |
| #1014, #1963, #717, #815 | rejected and closed; each ran. Evidence in the entries |
| #1917, #1926, #1860, #647, #1836 | confirmed; each ran: `App.CSPROJ` scans as 0 packages; `scan --sync` keeps, then prunes, a Cargo record; `list` prints bidi characters; `get` and the eject lack the public-proxy fallback; `get --json` output is unordered |
| 42 issues, named in the entries | out of charter; each ran or was read (14 read only) |
| #1114 | fixed in part (#2229); the CI janitor holds the rest |
| the other 29 open issues | out of charter by title, or "Decide:" issues (the 18:55Z entry). Every `arch-audit` issue open at 10:56Z on 2026-11-27 has been looked at |

### Areas examined
| Area | Date | `main` | Found |
|---|---|---|---|
| agent mode's undo, prune, output and broken inputs; `--json` / `--silent`; Gradle; the vlt heal; failing toolchains; credentials in project files; purl spellings; cache crawls | 2026-11-25, 11-26 | 332b3e8 to cfc870f | the PRs and issues up to #2287; the rest clean |
| hosted mode on the bench's 20 package managers and vendored mode on 8 (a planted credential, dry runs, rescans, the undo commands, CRLF, BOM and tab lockfiles, tampered artifacts, `--json`, `--silent`, `--offline`); the `socket.yml` policy and the selection filter; telemetry; `vex --grype-config`; the socket-cli config file; a monorepo | 2026-11-26 | cfc870f | four more sites of #2287; #2289, #2290, #2294, #2296, #2297; the rest clean |
| the patch API failing mid-run; `report`; `--update`; a newer patch for a patched package; linked `.socket/` stores; the contract's `jq` recipes; undo targets; a manifest outside `.socket/`; the in-memory hosted engine against the disk scan; the update notice; each partial state of a hosted scan's writes; the project-patch gate and Cargo's agent mode against real pnpm, Bun and cargo 1.97; a native-extension gem under a real Ruby; agent mode against the copy the real tool loads, over 75 layouts of Poetry, uv, PDM, Pipenv, Hatch, Bundler, Composer, pnpm, Bun and npm, 24 Maven states and 10 Go layouts | 2026-11-27 | cfc870f | #2299, #2301, #2303, #2305, #2306, #2308, #2309, #2310, #2312; the rest clean |

### Notes
- Build with `CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0` on every cargo call, and give each checkout its own `CARGO_TARGET_DIR`, or the next call rebuilds everything. A cold CLI build takes 3 minutes, core's unit tests 4, a rebuild 25 seconds.
- CI's clippy is `cargo clippy --locked --workspace --all-features -- -D warnings`. With `--all-targets` it fails on `main` in `tests/common` and `tests/prebuilt_common`.
- `--cwd` defaults to `.`: absolutize it before walking `ancestors()`, and test via chdir under `#[serial]`. A test runner that pins `--cwd` must not also set the child's cwd to the project.
- A write that returns 5xx may have landed: list before you retry.
- Cite a path and line numbers, not a permalink (#2287).
- Run the built binary over small broken projects and compare the commands. Set `SOCKET_TELEMETRY_DISABLED=1 SOCKET_NO_CONFIG=1`. For a patch API use the bench: `socket-patch-bench serve <pm>/hosted --bin <cli> --scale 0.02 --work-dir <dir>` builds a hosted project for any of 20 package managers, serves all three hosts and prints the command with its env (runner: the 18:55Z entry). Its env refuses outside registries, so an undo fails except for Hatch, Maven and Gradle. Fixtures, by entry: a refused token (06:55Z), a held `apply.lock` (08:56Z), a stand-in API (22:56Z), failure rules and a mock release host (00:55Z of 11-27), real cargo and a native gem (06:55Z), real-tool layouts (08:55Z).
- Vendored mode runs on files alone, with `tests/prebuilt_common`'s `Server::project(<dir>)` held open by a throwaway ignored test as the vendor service (the 20:56Z entry). Building a test rebuilds `target/debug/socket-patch` with core's test features: keep the plain binary in a second target directory.
- A throwaway probe test over the lead's input settles it in one rebuild. For a test that can't fail, mutate one production line and keep the diff (#2267).
- The owner was notified of the three waiting PRs (2026-11-26 05:15Z) and of each issue filed from #2277 to #2312. Don't notify again for the waiting PRs alone, or for more sites of a filed issue.
- Run `/code-review high` until a pass finds no real defect (#2261 took three), and the `cli` suite after touching any test file (it holds ratchets over `tests/`).
- Most open `agent/*` PRs edit `CLI_CONTRACT.md`: far-apart hunks are fine (#2261).
- `main` requires every review thread resolved: an open one silently blocks an approved PR with auto-merge armed. Answer and resolve threads first. A push does not dismiss approvals.
- Issue search: `gh api -X GET search/issues -f q='repo:SocketDev/socket-patch is:issue <words>'`. A PDM routine files `bughunt` issues (#2293): search before filing. `git fetch --deepen=2500 origin main` makes `git log -S` work.
- This sandbox has node, npm, pnpm, yarn 1, bun, uv, poetry, ruby and bundler, composer, java 21, mvn, gradle 8.14.3, go 1.24.7, gcc, PyYAML, and cargo 1.97.0 outside the repository (1.93.1 inside). PDM, Pipenv and Hatch install from PyPI as CI's suites do (pins: the 10:56Z entry of 11-27); read `ci.yml` before writing "needs X". It has no docker daemon, dotnet, sbt, scala-cli or deno, and refuses to run a tool downloaded during the run (a binary, `npx`, a Maven zip). Real-Gradle tests run: `SOCKET_PATCH_GRADLE_E2E_REQUIRED=1 cargo test --test e2e_gradle_agent_build -- --ignored <name>` (35 seconds).
- Real-vlt legs run: `scripts/install-vlt.sh 1.2.0 <dir>` prints the path for `SOCKET_PATCH_VLT_E2E_JS` (set `_VERSION` and `_REQUIRED=1` too). The 01:34Z entry of 2026-11-26 seeds the harness's registry cache.
- Root-sandbox failures that pass in CI: the chmod tests in `tests/repair` (2) and `in_process_redirect` (3), core `copy_tree` with a symlinked root, `vlt_heal` with an unremovable lock, and the `pypi_poetry`/`pypi_requirements` wire-failure tests.
- Unordered output: run a command six times and count distinct stdout hashes (#1836).
- Run each layout the contract documents with the user's own files beside it (#2301), and each proper subset of a command's writes as a merge would leave them (#2303; the loop and a disk-against-memory runner: the 04:55Z entry of 11-27).
- To make a stat fail as root, use a symlink to itself; chmod doesn't stop root.
- Ask the package manager what it reads, then compare: `cargo metadata` names the copy cargo builds (#2305), `uv run python -c 'import x; print(x.__file__)'` the one Python imports (#2308). Run it from a workspace member and with another virtualenv activated. An agent-mode Python run can write the OS Python: use `--dry-run`, or roll back and check `dpkg --verify python3-six`. Run every spelling the real tool takes of a key (#2306). Scan before asking: `pdm run` saves `.pdm-python` again (#2310). `mvn -q dependency:build-classpath -Dmdep.outputFile=/dev/stdout` names Maven's jar, `go list -m -json` Go's; a JVM's home is the passwd one (#2312).
- A prune GC test over a real revert needs no toolchain: hand-build a ledger entry as `apply_gc_reports_drift_kept_vendored_entry` (`scan/gc.rs`) does.
- To find a leak, plant a token wherever a package manager writes a URL, run every mode and every undo, and grep (#2287). A hand-built venv needs `include-system-site-packages = false`.
- A script named after a tool, first on `PATH`, is a failing (`exit 1`) or hanging (`exec sleep 600`) probe. A patched global copy: the 14:55Z entry.
