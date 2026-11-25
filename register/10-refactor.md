<!-- arch-audit-register -->
## Register

[agent] This comment is the register for the architecture refactor routine. It is rendered from `register/10-refactor.md` on the [`arch-audit/ledger`](https://github.com/SocketDev/socket-patch/tree/arch-audit/ledger) branch, and the routine updates it on every run.

_Last updated 2026-11-25 · reset; no runs yet under this charter._

### In flight
| PR | Issue | State |
|---|---|---|
| #2241 | #1959 (T55 slice 1) | ready. Opened by the last run under the old charter: it deletes test-helper copies that agree, so it isn't a real-problem PR. A maintainer decides whether it merges. Don't extend it, and don't take further T55 slices. |

### Merged
_None under this charter. The 2026-10/11 sweep PRs are listed in `review/2026-11-v2/register/90-refactor.md`._

### Leads
Carried from the previous thread's notes. Automated audits wrote these, no person has checked them, and none has been run on the current `main`. Each is a hypothesis: prove it or reject it.

| ID | Problem | Where | Status |
|---|---|---|---|
| L01 | npm `upstream_registry_fallback` may print a registry URL with `?token=` unredacted; `redact_urls_in` exists | core npm upstream registry client | to verify |
| L02 | `strip_url_userinfo`'s scp-style branch keeps `user:pass@` | `vex/product.rs` | to verify |
| L03 | `npm_range_admits(">=", v)` admits every version | core `utils/npm_range.rs` | to verify |
| L04 | `vlt_heal` swallows `load_state` and lock read errors and proceeds | CLI `commands/vlt_heal.rs` | to verify |
| L05 | the gem stale-install probe dedups by purl and drops the platform suffix, so a platform gem is judged by the ruby gem | gem stale probe (hosted) | to verify |
| L06 | `hatch::require_pip_installer_documents` ignores the `envs` override | core `utils/hatch.rs` | to verify |
| L07 | `scan --prune`: `has_ledger` probes `--cwd`, but `run_vendor_gc` reads `project_root()` | CLI `scan/gc.rs` | to verify |
| L08 | `ui::shell_word` doesn't quote `"` or `%VAR%` for cmd.exe, so a printed remedy can't be pasted | CLI `ui/text.rs` | to verify |
| L09 | `api/client.rs` runs two retry policies that disagree on statuses, counts, jitter and an over-cap `Retry-After`; blob GETs and the upstream registry client retry nothing | core `api/` | to verify |
| L10 | warning sinks disagree on `--silent`/`--json`: some print to stderr under `--json`, some drop warnings under `--silent` | CLI `scan/mod.rs`, `list.rs`, `user_patches.rs`, `scan/withdrawn.rs` | to verify |
| L11 | `.await.ok().flatten()` turns a `spawn_blocking` panic into "skip" (fails open) | CLI `commands/vex.rs` | to verify |
| L12 | three hand-written repository-root walks ignore `GIT_CEILING_DIRECTORIES`; `utils::repo_root` honors it | core and CLI | to verify |
| L13 | six Windows verbatim-prefix strippers disagree on UNC and `\\?\Volume{…}` paths | core `utils/`, `pnpm_workspace` | to verify |
| L14 | sbt and scala-cli `discover` collapse unreadable files and cap breaches into `None`, so the user is told to run `sbt update`/`scala-cli compile` | core JVM crawlers | to verify |
| L15 | `list::sanitize` and `StatusPrinter::println` keep bidi and zero-width characters that core `policy::strip_unsafe` removes | CLI `list.rs`, `ui/status.rs` | to verify |
| L16 | `SOCKET_UPDATE_TIMEOUT_MS` is parsed twice; core caps `connect` at 10 s and the update notifier doesn't | core `UpdateTimeouts`, CLI `update_notifier.rs` | to verify |
| L17 | three hand scanners for Ruby `=begin` blocks; the heredoc heuristic misreads `x <<FLAG` and indented `<<~ID` terminators | `vendor/gem.rs`, `vex/discover/gem.rs`, `redirect/upstream/gem.rs` | to verify |
| L18 | `assert_proxy_served_scans` counts 404s as served, so a wrong mount path stays green | `tests/common/scan_proxy.rs` | to verify |

Open `arch-audit` issues whose titles claim a real defect, so check them first: #1969 (`--offline` dropped, so 49 offline tests test nothing), #1970 (all-zeros `beforeHash` + `--force` in 8 docker suites), #1982 (Gradle `--global-prefix` tests pass without the flag), #1950 (`formats::xml::attr` matches inside another attribute's value), #1926 (the "copy may still hold the patch" rule drifted), #1899, #1887, #1861, #1114, #1069, #882.

### Areas examined
_None yet._

### Rejected
_None yet._

### Notes
- Build with `CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0` to save disk. CI's clippy job runs without `--tests`.
- Clap field doc comments are `--help` output: leave them alone.
- `--cwd` defaults to `.`: absolutize it before walking `ancestors()`, and test via chdir under `#[serial]`.
- Test runners that pin `--cwd` must not also set the child's cwd to the project, or a crawler that reads the process cwd passes by accident.
- Making a `pub` core item private can leave rustdoc links to it; unlink them in the same commit.
- Root-sandbox failures that pass in CI: the chmod tests in `tests/repair` and `in_process_redirect`, core `copy_tree` with a symlinked root, `vlt_heal` with an unremovable lock, and the `pypi_poetry`/`pypi_requirements` wire-failure tests.
