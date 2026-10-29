### CLI and tests audit (T rows)
_Last updated 2026-10-29T16:20Z · main @ c07af61 · owner: audit-cli-tests_

| ID | P | Problem | Issues | Status |
|---|---|---|---|---|
| T01 | 2 | `get <uuid>` agent mode re-implements `download_and_apply_patches_into` (`save_patch_record` + `save_and_apply_patch`, ~240 lines). Drifted on the no-files and blob-failure messages, unchanged-record re-apply and `persist_blobs`. | #1835 | filed #1835 |
| T02 | 2 | The vulnerability JSON object is hand-built 3× (`patch_event_metadata`, `list.rs`, get `options[]`). get's copy is unsorted (HashMap order) and drops `description`; list drops top-level `severity`. | #1836 | filed #1836 |
| T03 | 2 | `GLOBAL_ARG_ENV_VARS`/`LOCAL_ARG_ENV_VARS` are hand copies of clap `env` bindings and miss `SOCKET_NO_SOCKET_YML`, so the hermetic test scrub lets it through. The "invariant tests" iterate their own hand lists. | #1837 | filed #1837 |
| T04 | 3 | `fetch_stage` copies core `blob_fetcher` fetch-summary formatters; the copy is unsorted, shows raw errors and always appends `...`. | #1838 | filed #1838 |
| T05 | 2 | Bun and vlt vendored preflights run back to back at every caller (agent_download, get, scan vendor_flow ×2, vendor), each with its own per-purl glue; the callers disagree on the root (`project_root` vs `cwd`). | #1839 | filed #1839 |
| T06 | 2 | CLI `apply::representative_file` + `variant_matches_installed` ([apply.rs L761-L788](https://github.com/SocketDev/socket-patch/blob/c07af61ffa3ac6240aae408c4e1ba3606bfe52ca/crates/socket-patch-cli/src/commands/apply.rs#L761-L788)) copy core `patch::apply::variant_installed_at` (private); recombined with `verify_file_patch` at apply.rs L2579, L3214 and vendor.rs L2837, L3347. |  | to verify |
| T07 | 3 | The `VexSummary { format: "openvex-0.2.0", .. }` literal is hand-built 7× (apply ×2, vendor ×3, scan, scan/hosted); `expect("vex_result is Some…")` 3× in apply. Wants a `VexSummary::written` constructor. |  | to verify |
| T08 | 3 | Gem build-sibling rule twice: `apply::has_build_sibling` (L98) and inline in rollback.rs L2936, which also requires every purl to be `pkg:gem/` (drift). Verbose verification printer twice (apply.rs L2092, rollback.rs L2420): apply prints `(new file)` for an empty hash, rollback a blank. Folds into C24/#771. | #771 | to verify |
| T09 | 3 | Lock acquire + `Duration::from_secs(lock_timeout.unwrap_or(0))` + `lock_failure` open-coded ~8×, the `Duration` conversion 14× in the CLI; `report_lock_failure` lives in agent_download, not lock_cli. Wants `GlobalArgs::lock_timeout()`. |  | to verify |
| T10 | 3 | Severity ladder 3×: `agent_download::severity_rank`/`max_vuln_severity`, core `api::ranking::max_severity_order`, scan/discovery.rs L577. ui/mod.rs L238 and core client.rs L3177 point at a "get.rs severity_rank" that moved. |  | to verify |
| T11 | 3 | `DownloadParams` copies 10 `GlobalArgs` fields (filled field by field in get and scan) and `nested_apply_args_from_params` rebuilds a `GlobalArgs` from them: a translation layer. Overlaps C10/#793. | #793 | to verify |
| T12 | 3 | `composer_hints::vendored_composer_packages` parses composer.lock in the CLI and re-derives vendored-path detection by prefix instead of core `vendor::path::parse_vendor_reference` (drifted: no `../` workspace refs, no uuid check). |  | to verify |
| T13 | 3 | Overlay staging twice: `fetch_stage::overlay_dir` stages in system tmp (so hardlinks fail across filesystems and the blob cache is copied), rollback.rs L3016 stages in `.socket`. |  | to verify |
| T14 | 3 | Mode resolution (explicit / state-inferred / foreign-manifest / global conflict) is written in get (L1077-L1126) and scan (mod.rs L270-L308, L1737-L1772) with the checks in a different order. |  | to verify |
| T15 | 3 | Per-purl top-ranked selection 4× (get `select_patches`, scan/policy.rs L556 and L830, core rollout/stage.rs L77); the `tier == "free" \|\| can_access_paid` filter 3×. |  | to verify |

#### Handed off
_None._

#### Rejected
_None._
