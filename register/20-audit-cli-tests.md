### CLI and tests audit (T rows)
_Last updated 2026-10-29T21:55Z · main @ c8e26f6 · owner: audit-cli-tests_

| ID | P | Problem | Issues | Status |
|---|---|---|---|---|
| T01 | 2 | `get <uuid>` agent mode re-implements `download_and_apply_patches_into` (`save_patch_record` + `save_and_apply_patch`, ~240 lines). Drifted on the no-files and blob-failure messages, unchanged-record re-apply and `persist_blobs`. | #1835 | filed #1835 |
| T02 | 2 | The vulnerability JSON object is hand-built 3× (`patch_event_metadata`, `list.rs`, get `options[]`). get's copy is unsorted (HashMap order) and drops `description`; list drops top-level `severity`. | #1836 | filed #1836 |
| T03 | 2 | `GLOBAL_ARG_ENV_VARS`/`LOCAL_ARG_ENV_VARS` are hand copies of clap `env` bindings and miss `SOCKET_NO_SOCKET_YML`, so the hermetic test scrub lets it through. The "invariant tests" iterate their own hand lists. | #1837 | filed #1837 |
| T04 | 3 | `fetch_stage` copies core `blob_fetcher` fetch-summary formatters; the copy is unsorted, shows raw errors and always appends `...`. | #1838 | filed #1838 |
| T05 | 2 | Bun and vlt vendored preflights run back to back at every caller (agent_download, get, scan vendor_flow ×2, vendor), each with its own per-purl glue; the callers disagree on the root (`project_root` vs `cwd`). | #1839 | filed #1839 |
| T06 | 2 | CLI `apply::representative_file` + `variant_matches_installed` ([apply.rs L761-L788](https://github.com/SocketDev/socket-patch/blob/c07af61ffa3ac6240aae408c4e1ba3606bfe52ca/crates/socket-patch-cli/src/commands/apply.rs#L761-L788)) copy core `patch::apply::variant_installed_at` (private); recombined with `verify_file_patch` at apply.rs L2579, L3214 and vendor.rs L2837, L3347. |  | to verify |
| T07 | 3 | The `VexSummary { format: "openvex-0.2.0", .. }` literal is hand-built 7× (apply ×2, vendor ×3, scan, scan/hosted); `expect("vex_result is Some…")` 3× in apply. Wants a `VexSummary::written` constructor. |  | to verify |
| T08 | 3 | Gem build-sibling rule twice: `apply::has_build_sibling` (L98) counts any other copy in the gem home, rollback.rs L2932-L2941 only a variant-matched one and checks `pkg:gem/` by string (drift). Verbose verification printer twice (apply.rs L2092, rollback.rs L2419): same output (core never sends an empty hash), labels from a `match` vs `.replace('_',' ')`. Folds into C24/#771. | #771 | to verify |
| T09 | 3 | Lock acquire open-coded 9× beside `acquire_or_emit` (5 callers, all passing the same `GlobalArgs` fields); `Duration::from_secs(lock_timeout.unwrap_or(0))` 14×; `lock_held` rendered 3 ways for humans; scan/hosted prints the human error under `--json`; `report_lock_failure` lives in agent_download. | #1858 | filed #1858 |
| T10 | 3 | The severity ladder is single (core `ranking::severity_order`), but the "worst label" picker is written 3× (scan/mod.rs L3150, scan/render.rs L396, `agent_download::max_vuln_severity`) and drifted on unknown labels (scan returns them, agent_download `None`); ui/mod.rs L238 and core client.rs L3175 cite a moved `get.rs severity_rank`. |  | to verify |
| T11 | 3 | `DownloadParams` copies 10 `GlobalArgs` fields (filled field by field in get and scan) and `nested_apply_args_from_params` rebuilds a `GlobalArgs` from them: a translation layer. Overlaps C10/#793. | #793 | to verify |
| T12 | 3 | `composer_hints::vendored_composer_packages` parses composer.lock in the CLI and re-derives vendored-path detection by prefix instead of core `vendor::path::parse_vendor_reference` (drifted: no `../` workspace refs, no uuid check). |  | to verify |
| T13 | 3 | Overlay staging twice: `fetch_stage::overlay_dir` stages in system tmp (so hardlinks fail across filesystems and the blob cache is copied), rollback.rs L3016 stages in `.socket`. |  | to verify |
| T14 | 3 | Mode resolution (explicit / state-inferred / foreign-manifest / global conflict) is written in get (L1077-L1126) and scan (mod.rs L270-L308, L1737-L1772) with the checks in a different order. |  | to verify |
| T15 | 3 | Per-purl top-ranked selection 4× (get `select_patches`, scan/policy.rs L556 and L830, core rollout/stage.rs L77); the `tier == "free" \|\| can_access_paid` filter 3×. |  | to verify |
| T16 | 2 | remove and rollback each render `VendorRevertStep` in their own loop (vendor.rs classifies it twice more); drifted on `--preserve-state --dry-run` (remove previews a full revert), go-undo warnings, drift-keep text and stop-at-first-failure. | #1861 | filed #1861 |
| T17 | 2 | The "no manifest" gate is written 3× (remove.rs L367-L416, repair.rs L61-L156, rollback.rs L1437-L1547) and drifted: unledgered `.socket/vendor` wiring, a legacy `redirect-state.json`, contested hosted wiring and the global-scope check each give different outcomes; the `manifest_not_found` envelope differs in message and `path`. Overlaps C74/#1352. |  | to verify |
| T18 | 3 | `scan/discovery.rs` keeps a private `shell_word` beside `ui::shell_word`; it quotes POSIX-style on Windows and leaves `%` bare. | #1859 | filed #1859 |
| T19 | 3 | GC reporting still differs past C79's JSON fix: repair records `cleanup_failed` as a `Skipped` event (others: run warning), its labels say "diff"/"package" (others plural), and the human text has 4 renderers (remove `format_blob_sweep` says "would be freed", core says "freed" on a dry run, rollback its own line). |  | to verify |
| T20 | 3 | The "JSON envelope or stderr" error emit is hand-written ~6× (remove.rs L122, rollback.rs L947, repair.rs L78/L143/L257, list.rs L219, scan/mod.rs L1530); rollback also open-codes 4 more branches beside its own helper. Wants `json_envelope::emit_error`. |  | to verify |
| T21 | 3 | The warning sink (`--json` → `warnings[]`, else stderr) is hand-rolled per command (list.rs ×3, user_patches.rs L122, scan/withdrawn.rs L126); withdrawn prints under `--silent`, the others don't; 40 `RunWarning {` literals vs 17 `RunWarning::new`. |  | to verify |
| T22 | 3 | rollback's before-blob gate (`get_missing_before_blobs` L677-L687, recheck L3184-L3189) uses `metadata().is_err()`, which follows symlinks and accepts directories, while core `verify_file_rollback` requires `symlink_metadata().is_file()`: a planted link/dir counts as present, the self-heal download is skipped and the run fails `missing_blob`. Fails closed. Unexecuted. |  | to verify |
| T23 | 3 | The terminal-safe text filter is written 3× (list.rs `sanitize`, ui/status.rs `println`, core `policy::strip_unsafe`); only core drops bidi overrides and zero-width characters, so `list` prints them from API text. | #1860 | filed #1860 |

#### Handed off
_None._

#### Rejected
_None._
