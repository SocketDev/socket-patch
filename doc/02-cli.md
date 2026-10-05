> [agent] **Part 2 of 9** of the living socket-patch architecture document. The summary and ranked recommendations are in the top post. Originally written against `2463257`; the routines update this part as the code changes.

## Part 2: CLI command layer and user experience

_Last checked against main @ 045d7ec on 2026-10-05 by audit-core. Owner: audit-core._

> Scope: `crates/socket-patch-cli/src/` — `args.rs`, `lib.rs`/`main.rs`, `ecosystem_dispatch.rs`, `json_envelope.rs`, `ui/*`, `update_notifier.rs`, and every `commands/*` module.

### 2.1 Headline numbers

| Metric | Value |
|---|---|
| CLI `src/` | 59,450 lines = **~33.7K production + ~25.8K inline tests** |
| Production functions | 707 fns hold 25.6K lines; **41 fns ≥100 lines hold 52% of the code; 8 fns ≥500 lines hold 27%** |
| Subcommands | 9 visible + 2 hidden (`self-update`, `hosted-bundle`), 2 visible aliases (`download`, `gc`), a `<UUID>` shortcut, and a root `--update` argv rewrite |
| Flags | **57 visible long flags** + 3 hidden. `GlobalArgs` flattens **27 flags into every subcommand** (26 env-bound) |
| Env vars | 43 clap `env =` bindings + 2 read by hand. The contract names **71** `SOCKET_*` vars; source references 84 |
| Error vocabulary | **156 stable `errorCode` tags** + 12 `EnvelopeError` codes in the contract; ~570 distinct code-shaped strings in source |
| `--help` | 150–219 lines per subcommand (measured on a debug build). `list --help` shows 27 options, **most of which do nothing for `list`** (`--dry-run`, `--yes`, `--strict`, `--download-mode`, `--vendor-source`, `--maven-config`, `--lock-timeout`, the three hosted `--no-*` opt-outs, …) |

### 2.2 God functions

| Function | Location | Lines |
|---|---|---:|
| `run_scan` | `scan/mod.rs:1429–2968` | **1,540** |
| `rollback::run` | `rollback.rs:1069–2052` | 984 |
| `vendor_records_reusing` | `vendor.rs:1971–2932` | 962 |
| `run_redirect_selected` | `scan/hosted.rs:639–1474` | 836 |
| `remove::run` | `remove.rs:315–1111` | 797 |
| `get::run` | `get.rs:2507–3141` | 635 |
| `rollback_patches_inner` | `rollback.rs:2059–2658` | 600 |
| `apply_patches_inner` | `apply.rs:1633–2205` | 573 |

`run_scan` does all of this in one function body:
- mode folding and socket.yml policy loading;
- the PATH fan-out, path-scope parsing, the rollout cap and the offline check;
- the crawl, the lockfile supplement, ledger loads and filters;
- concurrent batch API calls with proxy fallback, then telemetry;
- **a JSON arm and a human arm that each dispatch all three modes again**: `run_redirect` @2187 vs `boxed_run_redirect_selected` @2675, `boxed_vendor_json_path` @2375 vs `boxed_vendor_interactive_path` @2912, `download_and_apply_patches_with` @2339 vs @2931 (re-checked on `045d7ec`; the split is tracked phase by phase). {{C11}}

Mode is three booleans (`apply`/`vendor`/`hosted`). They are referenced 91 times inside the function, across about 27 conditional branches.

**The root cause is that output mode leaks into the engine.** For example, `discover_selected` (`scan/mod.rs:484`) takes `show_progress`, `warn`, `detail_error_line` and `json_warnings: Option<&mut Value>`.

### 2.3 No service layer: commands call each other

Command modules double as libraries and form a dense web:
- **get ↔ scan cycle:** `get.rs` references `super::scan::` 28 times (hosted engine, vendor step, `ScanMode`), and scan's agent mode imports `get::download_and_apply_patches_with`/`DownloadParams`/`DownloadRun`.
- **Other edges:** remove→rollback (8 refs), vendor→vex (8), apply→vex (6), vendor↔rollback, repair→rollback+list, vex_sources→get.
- **`get` runs the agent apply by building fake CLI args:** `ApplyArgs { nested: Some(NestedApply{..}) }`, then calling `apply::run_locked` (`get.rs:2314–2341`).
- **A lossy argument round trip:** GlobalArgs → `DownloadParams` → GlobalArgs.
  - `DownloadParams` re-declares 10 `GlobalArgs` fields.
  - `nested_apply_args_from_params` rebuilds the args with `..GlobalArgs::default()`, resetting `offline`, `patch_server_url`, `no_vlt_install_cleanup` and others.
  - Re-checked on `045d7ec`: this is inert. The nested apply runs on the caller's client (`DownloadRun`), the hosted opt-outs and `debug`/telemetry reach core through `apply_env_toggles` and process env, and `apply` reads only `offline` of the reset fields, which `get`/`scan` refuse up front. The remaining defect is the cycle itself (C12). {{C06}}

### 2.4 Shared abstractions exist but are bypassed

- **`ProjectContext`.** Its doc says "`scan`, `vendor`, `vex`, `list` and `get` read these through one ProjectContext". It actually has **3 call sites** (list, scan, get). `vex` calls `LoadedLedgers::load` directly; `vendor` calls `inventory_project*` and `discover_wiring` directly. `load_state(` appears 27 times across 12 command files, and `read_manifest(` 15 times across 9.
- **`VendoredBackend`** ("the one vendored-mode backend") has 8 users, but `run_vendor_gc` (`vendor.rs:3400, 3436`) and the hosted takeover (`scan/hosted.rs:1700, 1733`) call `dispatch_revert_one` directly.
- **A bug caused by the bypass (verified by reading).**
  - Core's `RevertOutcome.kept_artifact` (`core/vendor/mod.rs:664–673`) says that after a drift-keep, callers "must ALSO keep the state.json entry".
  - `vendored_takeover` (`scan/hosted.rs:1732–1790`) never reads `kept_artifact`. On success it drops the ledger entry, saves, and emits `redirect_takeover_reverted_vendored` ("reverted its vendored wiring, ledger entry, and committed artifact"). Reproduced on `1169ae6`: after the takeover the ledger entry is gone and the artifact dir is still there. {{C03}}
  - On a drifted lock this orphans the artifact and loses the only recorded originals.
  - Every other revert caller handles the flag (vendor.rs ×6, gc.rs, `vendored_backend`).
  - Needs a regression test.

### 2.5 Configuration flows through process environment

`apply_env_toggles` (`args.rs:559-575`) writes parsed flags back into `SOCKET_OFFLINE`, `SOCKET_DEBUG`, `SOCKET_TELEMETRY_DISABLED`, `SOCKET_API_URL` and `SOCKET_PROXY_URL`, so that core (51 production env reads) can see them.
- Its own doc comment records the bug this caused: an on-prem `--api-url` run "POSTed the event — Bearer token included — to the default `api.socket.dev`".
- It is called separately in 10 command entry points rather than once in `main`, and `vendor --check` returns before calling it.
- It is why the test suites carry **993 `#[serial]` attributes** in `tests/` (plus 185 in `src`), counted on `045d7ec`; the review counted 553 + 182.
- The lock timeout is converted by hand at 12 sites, and the API client is built at 13 production sites.
- **Fix:** an explicit `RunCtx { config, client, telemetry, lock }` built once in `main` and passed down. Core should not read ambient env except at the edge. {{C10}}

### 2.6 Structural duplication

A sliding-window copy-paste detector finds little *literal* duplication. **The duplication is structural**: helpers were extracted, but the pipelines around them were forked.

| Duplicate | Evidence |
|---|---|
| JSON vs human agent pipeline in `run_scan` | `discover_selected` @2226/2246 vs @2489; `classified_rows` @2265/2510; `partition_agent_selection` @2282/2702; `plan_kept_rows` @2283/2730 (on `045d7ec`) |
| `remove` vs `rollback` | `remove::run` (797) + `remove_hosted_only` (94) + `remove_ledger_only` (127) vs `rollback::run` (984). Both run agent leg → vendored leg → hosted leg → manifest cleanup → GC over the same primitives. The contract itself says "remove parity" repeatedly. |
| `get` agent mode, twice | `save_and_apply_patch` (UUID path, `get.rs:3365`) vs `download_and_apply_patches_with` (search path, `:2343`) |
| Vendored revert ×4 | `VendoredBackend::revert`, `vendor.rs:3400`, `vendor.rs:3436`, `hosted.rs:1700/1733` |
| 401/403 → public-proxy fallback ×3 | `scan/mod.rs:2014–2035`, `get.rs:2625–2647` (UUID path only), `vex_sources.rs:944–970`. **`get`'s CVE/GHSA/PURL/name search path has none**, and neither do `apply`, `rollback`, `repair` or `vendor` eject, whose blob, diff and view fetches fail on a stale token (verified by execution on `045d7ec`). {{C09}} {{C39}} |
| Lock acquisition ×2 families | `acquire_or_emit` in 5 envelope commands vs `acquire_with_status` + bespoke rendering in 7 sites. `Duration::from_secs(lock_timeout.unwrap_or(0))` appears 11 times. |
| "Which origins count as hosted" ×3, **divergent** | `discover_options` and `rollback::patch_server_origins` use only `patch_server_url`; `scan/hosted/vlt.rs:69` also adds `api_url` |
| Ecosystem filter ×4, **divergent** | `GlobalArgs::ecosystem_selected` treats an empty list as "all"; `crawl_selects` treats `Some(empty)` as "none" |
| Vulnerability label / max severity, **divergent** | `get.rs:511/114` vs `scan/render.rs:327–360`: get drops unknown severities, render doesn't |
| Generic utilities in the wrong place | `join_clauses`/`capitalize_first`/`as_question` in `rollback.rs` (with `capitalize_first` again in `update.rs`); a text-wrapping warning formatter private to `hosted.rs:1911–2033` |
| Telemetry plumbing | 46 `track_*` call sites and **125 references threading token/org through signatures**. `remove` and `rollback` build a full API client (an org-slug network round trip) *only for telemetry*, although `telemetry_credentials()` exists to avoid exactly that. |
| Ad-hoc JSON | `json!(` appears 47× in `get.rs` and 16× in `rollback.rs`, versus typed `Envelope` operations in apply/vendor/remove/repair |

### 2.7 Flag and surface sprawl

- **Every global flag is silently accepted by every command.** `list --download-mode bogus --strict --yes --lock-timeout 9 --maven-config none --no-vlt-install-cleanup --dry-run` exits 0. `--update --ecosystems npm --manifest-path x.json --strict --global` parses.
- **Dead or vestigial flags:**
  - `--vendor-source`: core's `VendorSource` has **one variant**, and `build` is an error.
  - `--download-mode` is an unvalidated `String`, checked only where it is used. That breaks the "fail loud on typo" posture the same file applies to `--ecosystems`. On `045d7ec` a bad value fails `apply` and `repair` with exit 1 and `apply_failed`/`repair_failed`, while `apply --check`, `rollback`, `list` and `vendor` exit 0; `--vendor-source bogus` is a clap usage error (exit 2). {{C45}}
- **Deprecated spellings and aliases:** `scan --apply` (hidden), `scan --vendor` (hidden), `--sync`, `get --no-apply`, and the `download` and `gc` aliases. `resolve_mode_flags` (`scan/mod.rs:205–255`) exists mainly to reconcile these.
- **Name collisions:**
  - `--package` is a value list on `scan` but a boolean type-forcer (`-p`) on `get`.
  - `--check` on `apply` audits *Go `replace` redirects only*; on `vendor` it audits artifacts and JVM wiring.
  - **`SOCKET_FORCE` is bound to three unrelated `--force` flags** (`vendor.rs:80`, `apply.rs:339`, `update.rs:61`; verified on `045d7ec`). Exporting it to force a self-update also forces `apply` and `vendor`. {{C05}}
- **VEX passthroughs:** 5 `--vex-*` flags × 3 host commands = 15 flag instances, with the env vars bound twice.
- **Hosted-only opt-outs are globals:** `--no-trust-lockfile-config`, `--no-npm-allow-remote-config` and `--no-vlt-install-cleanup` appear on `apply`, `list`, `vex`, `repair` and the rest.
- **Two env mechanisms:** clap `env=` vs manual reads in `rollout_args.rs`/`socket_yml_args.rs`. `SOCKET_NO_SOCKET_YML` is missing from `LOCAL_ARG_ENV_VARS`, which is meant to be the single source of truth.

### 2.8 Inconsistent JSON (verified against the binary)

```text
$ socket-patch remove pkg:npm/nope@1.0.0 --json      → {"command":"remove","status":"error",…,"error":{"code":"manifest_not_found","message":…}}
$ socket-patch rollback pkg:npm/nope@1.0.0 --json    → {"status":"error","error":"Manifest not found","path":…}
$ socket-patch scan --offline --json                 → {"status":"error","error":"scan requires network access…", "scannedPackages":0, …}
$ socket-patch get nope --offline --json             → {"status":"error","error":"Fetching patches needs network access…"}
```

- `repair`, `remove` and `vex` use the envelope, with an `error` object that carries a stable `code`.
- `scan`, `get` and `rollback` have no fixed `error` type. `rollback` always emits a bare string, but `scan` and `get` each emit a bare string on some paths and a `{code, message}` object on others (scan's embedded-VEX failure, get's vendored failure); `get`'s lock failure adds a sibling `errorCode`. A script must type-check `.error` before reading it. {{C14}}
- Status is `partialFailure` in the envelope but `partial_failure` in the legacy shapes.
- `get --mode vendored` nests an `Envelope` inside a legacy object.
- The contract's "Migration status (v3.0)" section still says scan, get and rollback "will migrate in a follow-up PR". That was two majors ago.

### 2.9 UX: the command model is the real problem

1. **Defaults change with unrelated flags.**
   - `scan` is hosted by default, but `--prune` or `--global` makes it report-only.
   - `get` is hosted by default, but `--save-only` or `--global` makes it agent mode.
   - So `get -g x` patches files in place while `scan -g` only reports.
   - The PATH positionals mean *project directories* in hosted and vendored mode but *installed-path globs* in agent mode.
2. **The verb `scan` writes to lockfiles by default.** Most users and most CI templates expect a "scan" to be read-only. The safe preview is opt-in (`--dry-run`).
3. **Mode is not project state.**
   - `mode` is deliberately rejected in socket.yml.
   - Bare `scan` is hosted, and the hosted path performs the vendored→hosted takeover for npm, cargo and golang. This is documented ("vendored → hosted conversions both work in place").
   - So a project vendored for airgapped installs silently becomes hosted the next time someone runs the quick-start command.
   - `rollback` and `list`, by contrast, infer mode from on-disk state.
4. **Overlapping verbs:**
   - `get <pkg>` ≈ `scan --package <pkg>`;
   - `remove <id>` ≈ `rollback <id>`;
   - `vendor` ≈ `scan --mode vendored` (plus eject);
   - `vendor --revert` ≈ `rollback` of vendored state;
   - `repair` (alias `gc`) is *not* the `scan --prune` GC.
   - Top-level help files `repair` under "Agent mode", but it also rebuilds vendored artifacts.
5. **Two styles of usage error:** clap's `error: the argument '--apply' cannot be used with '--vendor'` and the custom `Error: --mode hosted cannot be used with --vendor…`.
6. **Warnings render differently:** hosted mode wraps and bullets them; other commands print a raw `Warning: {detail}`.

**A simpler command model:**

| Proposed | Replaces | Notes |
|---|---|---|
| `socket-patch scan` | `scan --dry-run` | **Read-only** report of available patches and current state. Safe default. |
| `socket-patch fix [TARGET…] [--mode M]` | `scan` (write), `get` | No target means everything; a target can be a package, CVE, GHSA or UUID. **Mode is inferred from existing project state.** `--mode` is only needed to choose or switch, and switching a project's mode should require `--mode` explicitly. |
| `socket-patch undo [TARGET…] [--keep-state \| --forget]` | `rollback`, `remove`, `vendor --revert` | One reversal engine. `remove` stays as an alias that requires one target. |
| `socket-patch sync` | `apply`, `repair`, `scan --prune` | The agent-mode re-apply after install, plus artifact repair and GC. |
| `socket-patch check` | `vendor --check`, `apply --check` | All read-only verifiers, CI-friendly exit codes. |
| `socket-patch list`, `socket-patch vex` | (unchanged) | |

That is **7 verbs instead of 9 visible + 2 hidden + 2 aliases + 3 hidden flag spellings**, with one rule for mode ("whatever the project is, unless you say otherwise").

### 2.10 Recommendations

| # | Change | Est. LOC | Risk |
|---|---|---:|---|
| R1 | Route every vendored revert through `VendoredBackend` (takeover, `run_vendor_gc`); add a drift-keep regression test | −120 | Low; fixes the `kept_artifact` bug |
| R2 | The fallback moves into `ApiClient` itself (a one-shot downgrade), so scan, get, vex, apply, rollback, repair and eject all get it | −60 | Low; fixes get's and the blob-download gaps {{C09}} |
| R3 | `RunCtx { config, client, telemetry, lock }` built once in `main`; delete `apply_env_toggles` and the telemetry plumbing | −300 to −400 | Low–Med; unblocks test-binary merging |
| R4 | Finish the envelope migration for scan/get/rollback: one error shape, `{code, message}` | −300 to −600 net | MAJOR |
| R5 | Split `run_scan` into discover → select → `ModeBackend::consume`, rendering JSON/human only at the end | −500 to −800 | Medium |
| R6 | Fold `remove` into `rollback`/`undo` | −900 to −1,200 | Medium; contract change |
| R7 | Fold get's agent UUID path into the selection pipeline; replace `DownloadParams` with `&GlobalArgs` | −250 | Low |
| R8 | Per-command flags: delete `--vendor-source`; move hosted `--no-*`, vendor and agent knobs to the commands that read them; validate `--download-mode` at parse time; reject unused flags (warn for one minor first) | −150 | MAJOR |
| R9 | Drop deprecated spellings (`--apply`, `--vendor`, `--no-apply`, `download`, `gc`); give `SOCKET_FORCE` per-command names | −100 + tests | MAJOR |
| R10 | Drop embedded `--vex` in favor of `fix && vex -O` | −600 and 15 flag instances | MAJOR, technically low |
| R11 | Move `ecosystem_dispatch` (816 production lines of pure crawler fan-out), `vendor_records_reusing` and the disk hosted orchestration into core behind one orchestrator over `ProjectView` | −2K to −4K over time | High; incremental |

### New findings since the review

- {{C39}} The stale-token fallback is wider than get's search gap: `apply`, `rollback` and `repair` blob/diff downloads and `vendor` eject view fetches never fall back, although `CLI_CONTRACT.md` promises eject the same fallback as `get`. On `045d7ec`, with the auth API answering 401, `apply` reported `sources_download_failed` without trying the proxy; without a token, the same run fetched from the proxy.

- {{C43}} `--manifest-path` interleaves two projects' state. `GlobalArgs::project_root()` documents that every multi-store command derives its stores from the manifest's project, and `list`, `apply` and `vendor --check` do. But `rollback`, `remove`, `repair`, `apply --check`, `vex`, `scan` and `get` load the vendored ledger from `--cwd`. `rollback` also locks the manifest's `.socket/` while writing the cwd ledger. On `045d7ec`, with a corrupt ledger in `--cwd` and `--manifest-path ../b/.socket/manifest.json`, `list` succeeded while `vex`, `rollback` and `repair` failed on the cwd ledger; with the corruption moved to `b`, the results inverted.

- {{C44}} The ecosystem-name parser is written three times. `--ecosystems`/`SOCKET_ECOSYSTEMS` require an exact, case-sensitive `cli_name()` with no trim, socket.yml `patches.ecosystems` trims and lowercases, and `vendor::ecosystem_in_scope` has its own exact lookup. On `045d7ec`, `-e NPM`, `-e "npm, pypi"` and `SOCKET_ECOSYSTEMS=PyPI` exit 2, while `ecosystems: [NPM, pypi]` parses. `--min-severity` and `minSeverity` already share one parser.

- {{C45}} `--download-mode` typos are runtime failures in two commands only (see 2.7): `apply`/`repair` exit 1 with a generic command code, and the rest accept them. This narrows the review's R8 note to a non-breaking fix (a typed clap parser).

(The `C38` pacing finding is in Part 7.)

---
_Generated by [Claude Code](https://claude.ai/code)_
