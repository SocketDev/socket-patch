### CLI and tests audit (T rows)
_Last updated 2026-11-02T03:52Z · main @ cbbbdb9 · owner: audit-cli-tests_

| ID | P | Problem | Issues | Status |
|---|---|---|---|---|
| T01 | 2 | `get <uuid>` agent mode re-implements `download_and_apply_patches_into` (~240 lines); drifted on messages, unchanged-record re-apply and `persist_blobs`. | #1835 | filed #1835 |
| T02 | 2 | The vulnerability JSON object is hand-built 3× (`patch_event_metadata`, `list.rs`, get `options[]`). get's copy is unsorted (HashMap order) and drops `description`; list drops top-level `severity`. | #1836 | filed #1836 |
| T03 | 2 | `GLOBAL_ARG_ENV_VARS`/`LOCAL_ARG_ENV_VARS` are hand copies of clap `env` bindings and miss `SOCKET_NO_SOCKET_YML`, so the hermetic test scrub lets it through. The "invariant tests" iterate their own hand lists. | #1837 | filed #1837 |
| T04 | 3 | `fetch_stage` copies core `blob_fetcher` fetch-summary formatters; the copy is unsorted, shows raw errors and always appends `...`. | #1838 | filed #1838 |
| T05 | 2 | Bun and vlt vendored preflights run back to back at every caller with per-purl glue; callers disagree on the root (`project_root` vs `cwd`). | #1839 | filed #1839 |
| T06 | 2 | CLI `apply::representative_file` + `variant_matches_installed` (apply.rs L761-L788) copy core `patch::apply::variant_installed_at` (private); recombined with `verify_file_patch` at apply.rs L2579, L3214 and vendor.rs L2837, L3347. |  | to verify |
| T07 | 3 | The `VexSummary { format: "openvex-0.2.0", .. }` literal is hand-built 7× (apply ×2, vendor ×3, scan, scan/hosted); `expect("vex_result is Some…")` 3× in apply. Folded into T25. | #1877 | filed #1877 |
| T08 | 3 | Gem build-sibling rule twice (`apply::has_build_sibling` any copy vs rollback.rs L2932 variant-matched, string `pkg:gem/` check); verbose verification printer twice (apply.rs L2092, rollback.rs L2419). Folds into C24/#771. | #771 | to verify |
| T09 | 3 | Lock acquire open-coded 9× beside `acquire_or_emit`; `from_secs(lock_timeout.unwrap_or(0))` 14×; `lock_held` rendered 3 ways. | #1858 | filed #1858 |
| T10 | 3 | The severity ladder is single (core `ranking::severity_order`), but the "worst label" picker is written 3× (scan/mod.rs L3150, scan/render.rs L396, `agent_download::max_vuln_severity`) and drifted on unknown labels (scan returns them, agent_download `None`); ui/mod.rs L238 and core client.rs L3175 cite a moved `get.rs severity_rank`. |  | to verify |
| T11 | 3 | `DownloadParams` copies 10 `GlobalArgs` fields (filled field by field in get and scan) and `nested_apply_args_from_params` rebuilds a `GlobalArgs` from them: a translation layer. Overlaps C10/#793. | #793 | to verify |
| T12 | 3 | `composer_hints::vendored_composer_packages` parses composer.lock in the CLI and re-derives vendored-path detection by prefix instead of core `vendor::path::parse_vendor_reference` (drifted: no `../` workspace refs, no uuid check). |  | to verify |
| T13 | 3 | Overlay staging twice: `fetch_stage::overlay_dir` stages in system tmp (so hardlinks fail across filesystems and the blob cache is copied), rollback.rs L3016 stages in `.socket`. |  | to verify |
| T14 | 3 | Mode resolution (explicit / state-inferred / foreign-manifest / global conflict) is written in get (L1077-L1126) and scan (mod.rs L270-L308, L1737-L1772) with the checks in a different order. |  | to verify |
| T15 | 2 | Per-purl top-ranked selection 5× (get, scan/policy ×2, core rollout/stage, core memory `select_with_policy`); socket.yml floor 3×; tier filter 4×. |  | to verify |
| T16 | 2 | remove and rollback each render `VendorRevertStep` in their own loop (vendor.rs classifies it twice more); drifted on `--preserve-state --dry-run` (remove previews a full revert), go-undo warnings, drift-keep text and stop-at-first-failure. | #1861 | filed #1861 |
| T17 | 2 | The "no manifest" gate is written 3× (remove, repair, rollback), drifted on vendor wiring, legacy state, hosted wiring, global scope and message. Overlaps C74/#1352. |  | to verify |
| T18 | 3 | `scan/discovery.rs` keeps a private `shell_word` beside `ui::shell_word`; it quotes POSIX-style on Windows and leaves `%` bare. | #1859 | in PR #1884 |
| T19 | 3 | GC reporting differs past C79: repair records `cleanup_failed` as `Skipped` (others: warning), singular labels, and 4 human renderers (remove says "would be freed", core "freed" on a dry run). |  | to verify |
| T20 | 3 | The "JSON envelope or stderr" error emit is hand-written ~6× (remove, rollback, repair ×3, list, scan) plus 4 open-coded rollback branches. Wants `json_envelope::emit_error`. | #1924 | filed #1924 |
| T21 | 3 | The warning sink (`--json` → `warnings[]`, else stderr) is hand-rolled per command (list.rs ×3, user_patches.rs L122, scan/withdrawn.rs L126); withdrawn prints under `--silent`, the others don't; 40 `RunWarning {` literals vs 17 `RunWarning::new`. |  | to verify |
| T22 | 3 | rollback's before-blob gate (L677, L3184) uses `metadata().is_err()` vs core `symlink_metadata().is_file()`: a planted link/dir counts as present; fails closed `missing_blob`. Unexecuted. |  | to verify |
| T23 | 3 | The terminal-safe text filter is written 3× (list.rs `sanitize`, ui/status.rs `println`, core `policy::strip_unsafe`); only core drops bidi overrides and zero-width characters, so `list` prints them from API text. | #1860 | filed #1860 |
| T24 | 2 | Disk hosted scan (`run_redirect_selected_untracked`, 1,233 lines) hand-copies core's in-memory pipeline (memory/stages.rs); drifted: `governing_root::refusal` disk-only, warning order. Child of C12. | #894 | to verify |
| T25 | 2 | The `--vex` embed step is hand-written ~8× (scan ×4, apply ×2, vendor ×3); only scan reports `vex_skipped_dry_run` under `--json`, and fold order differs. Absorbs T07. | #1877 | filed #1877 |
| T26 | 2 | Pipenv stale-install remedy written twice (hosted `scan/hosted/python.rs` L134-L205, core `vendor/pypi.rs` L786-L860); drifted on per-site vs aggregated warnings, suffix wording (`<purl>` placeholder) and name parsing. | #1878 | in PR #1883 |
| T27 | 3 | Hosted stale-install and takeover warnings are built as `serde_json::Value` (hosted, python, nuget, takeover, vlt_heal) and parsed back by `run_warning_of` with `unwrap_or_default`. Part of T21. | #1879 | filed #1879 |
| T28 | 3 | The vulnerability label rule (CVEs else advisory id) is written 4× (render.rs L385, get.rs L222 and L372, list.rs L284); drifted on order, dedup and severity case. | #1880 | filed #1880 |
| T29 | 2 | The hosted `redirect` JSON block has two shapes (disk `{mode, rewrittenFiles}` vs core `redirect_json_block`'s 7 keys), while core's doc claims one. Decision. | #1881 | decision #1881 |
| T30 | 3 | Snapshot/put-back of files the group commit doesn't capture is written twice (`scan/hosted.rs` `commit_hosted_writes` L2093-L2190, `vendor.rs` L1701-L1758); hosted drops put-back errors (`let _ =` L2183) yet says "nothing was changed". |  | to verify |
| T31 | 3 | The project-root marker predicate is written twice (`scan/policy.rs` `lock_markers` L105-L121, core `hosted/memory/roots.rs` `root_markers` L41-L58); disk adds a manifest fallback the memory engine lacks (its doc admits the verdicts differ). Unexecuted. |  | to verify |
| T32 | 3 | The agent dry-run preview event is built 3× (scan/mod.rs L2896-L2917, get.rs L1868-L1894, agent_download.rs L1089) and the already-recorded check re-derived a 4th time (scan/mod.rs L3322) beside `decide_patch_action`. |  | to verify |
| T33 | 3 | Suspected: the hosted takeover plans one ledger entry (`lookup_entry`, takeover.rs L119) but `finish` removes every `PurlKey::same` entry (L410-L414), so a second variant of the release would leave the ledger unreverted. Unexecuted. |  | to verify |
| T34 | 3 | Warning text is sentence-cased and wrapped only in `scan/hosted.rs` (`format_warning`/`wrap_words`, L2213-L2307); ~84 other `Warning: {detail}` prints do neither, and policy vs rollout warnings use two prefixes. Belongs in `ui::text`. Part of T21. |  | to verify |
| T35 | 2 | scan's vendored planning and preview each run the whole refusal preflight set; planning skips `pypi_refusals`, so a refused PyPI patch takes a `--max-new-patches` slot. Overlaps T05. | #1908 | in PR #1930 |
| T36 | 2 | `vendor.rs` `plan_service_downloads` (L2786-L2930) re-walks the vendor loop's candidate selection (L3303-L3420); the plan skips the vlt refusal and `vendor_variant_ambiguous`. Related to T06. | #1909 | in PR #1947 |
| T37 | 2 | `run_vendor_gc` (`scan --prune`) reverts via `dispatch_revert_one` instead of `VendoredBackend::revert`: drops `outcome.error`, saves the ledger once, ignores `still_wired`. Child of T16. | #1910 | filed #1910 |
| T38 | 3 | The user-patches gate loop is written 5×; scan skips the ecosystem filter and uuid, vendor dedups unsorted. | #1911 | filed #1911 |
| T39 | 3 | `PackageVendorResult.status` is an untyped string read 4× (core client.rs L1340, vendor_prefetch L439, scan/withdrawn.rs L57-L91, scan/hosted.rs L2343); the two reuse caches disagree on "settled" (`build_failed`). | #1912 | filed #1912 |
| T40 | 3 | The Go consumer-sync audit is invoked and rendered at 8 sites; forward vendor sends it to `warnings[]`, `vendor --revert` to Skipped events. |  | to verify |
| T41 | 3 | The "lockfile wiring with no ledger entry" remedy is written 5× under two codes (`vendor_ledger_missing` vs `vendor_ledger_entry_missing`). Near T17. |  | to verify |
| T42 | 3 | The "(eco, uuid) owned by no ledger entry" predicate is written 4× (vendor_orphans.rs L54-L62, vendored_backend/repair.rs L192-L206 and L698-L704, rollback.rs L919-L930); rollback treats a uuid under any ecosystem as owned. Unexecuted. |  | to verify |
| T43 | 3 | `ui::print_json` is "the one `--json` writer" but has 3 callers; 43 production sites in 9 commands print `println!("{}", env.to_pretty_json())` and `usage_error` hand-writes a third copy. | #1925 | filed #1925 |
| T44 | 3 | "Copy may still hold the patch" from `verify_file_rollback` is written twice (ecosystem_dispatch.rs L64-L84, rollback.rs L324-L345); drifted on `MissingBlob` with a third hash (A keeps, B drops). | #1926 | filed #1926 |
| T45 | 3 | vex omission tags are untyped strings; `gradle_unpatched_copy` has no `omission_phrase` arm and prints "the patch could not be verified" (executed); the tag test iterates a hand list. Part of C13. | #1927 | filed #1927 |
| T46 | 3 | Go "version-pinned replace may be ignored" mapping written 3× (vex.rs L1001-L1081, core golang_local.rs L591-L610 and L693-L715); drifted on `Unknown` inside go.work; ~250 lines of vex Go gates belong in core. Child of #855. |  | to verify |
| T47 | 3 | The `--ecosystems` selected check is copied ≥7× with two readings of `Some([])` (latent: the parser never yields it). |  | to verify |
| T48 | 3 | vex_consumed re-derives core rules (Go hosted uuid suffix, Maven `-socket.{hex8}`, cargo registry prefix ×3, `PRODUCT_MANIFESTS`). Child of #855. |  | to verify |
| T49 | 3 | vlt naming is crossed between CLI `vlt_preflight.rs`, core `redirect::vlt_preflight` and `vlt_heal.rs`; `redirect_vlt_reinstall_required` returns in 3 shapes. Part of T27/T05. |  | to verify |
| T50 | 3 | Toolchain e2e gate `required()`/`skip()` hand-written per suite (15 / 8 defs); drifted: `=0` required for golang/sbt/npm/nuget/deno, not cargo/uv/bundler; docker accepts only `"1"`. | #1940 | filed #1940 |
| T51 | 3 | 9 `tests/apply` suites re-write `apply_fixture`'s manifest/blob/package/gem/event helpers in the same binary; `apply_fixture` and `common::write_minimal_manifest` are two writers; gem_stale_bundler_plugin skips the `BUNDLE_*` scrub. | #1941 | in PR #1944 |
| T52 | 3 | PTY runner (openpty, spawn, feed, collect) copied 7× beside `common/pty_io.rs`; only 2 copies set `TERM`. | #1942, #1955 | in PR #1955 |
| T53 | 3 | `hermetic::command` removes `SOCKET_PROXY_URL`, so a fetch with no mock reaches the live public proxy: `apply_invariants` L355 does (executed). |  | to verify |
| T54 | 3 | The `--json` reader ratchet (`envelope_helper_copies`) is name-based: misses 7 `fn envelope(` parsers; stale allowlist entries pass. Part of C32. | #1089 | to verify |
| T55 | 3 | Suites that include `common` keep their own `has_command` ×9, `sha256_hex` ×16, `git_sha256_file`/`assert_run_ok` ×4, `npm_run` ×3; `stderr_chatter` ×5 + inline ×6 is a dead filter (executed); `rollback_json` copies 4 envelope readers (drifted). | #1959 | filed #1959 |
| T56 | 3 | Parse-suite env scrub 4 ways (`EnvScrub` ×4, hand lists, `with_clean_env`, none in list/remove/main: `SOCKET_JSON=true` fails 3, executed); hand `Snap` mirrors miss 1-9 fields. | #1956 | filed #1956 |
| T57 | 3 | The `cli_parse_<cmd>` suites re-pin flattened `GlobalArgs` one test per flag (~85 tests) beside `cli_global_args`' every-flag × every-subcommand matrix; their field lists drift (apply/rollback `bool_flags` lack 5). Follows T56. |  | to verify |
| T58 | 3 | 21 `tests/common` selftests run in each of ~104 includers (~2K redundant runs; 14 binaries include `cache_env` twice); the "no `cfg(test)` in integration crates" comment ×3 is false (executed). | #1957 | filed #1957 |
| T59 | 3 | `hermetic::command` leaves `CLICOLOR_FORCE`/`NO_COLOR`/`COLUMNS`/`CI` ambient (`CLICOLOR_FORCE=1` fails a list test, executed); `HOSTILE_SEEDS` seed then remove the same list (can't catch anything); HOME pin only on `common::run`. | #1958, #1964 | in PR #1964 |
| T60 | 3 | Docker suites copy their harness: `cov_docker_args` ×10, `skip_if_no_image` ×11 (7 ungated; deno reads `SOCKET_PATCH_REQUIRE_DOCKER`, set nowhere; CI exports REQUIRED only in the `sbt)` arm), `run_container` ×5, `assert_vex_agent_attested` ×8, git-blob hasher ×4; gem's `"applied": 1` grep matches 10 (executed). | #1968 | filed #1968 |
| T61 | 3 | `prebuilt_common::prepare_command` filters `--offline` out of vendor/repair args; 49 `"--offline"` calls in 16 suites run online, and comments claim offline runs. | #1969 | filed #1969 |
| T62 | 3 | 8 of 9 docker agent suites serve a zero `beforeHash` and `apply --force`, so only the force path is proven (gem's doc says so); port gem's real-hash probe. | #1970 | filed #1970 |
| T63 | 3 | Docker vendor capstones: `assert_vex_attested_from_host` ×4 checks only `contains("(vendored)")` beside `vex_e2e_common::assert_attested`; `render` ×5; stage-3 bash ×5; 4 manifest-less VEX mechanisms (host, bash grep, python, in-container Ruby API). |  | to verify |
| T64 | 3 | Test fs/scan plumbing copied: `copy_tree`/`copy_dir_recursive` ~20+ (drifted on skip lists, missing src), `start_proxy`+`assert_proxy_served_scans` ×4 (gem drifted), `hosted_pin_count` ×8 beside `envelope::hosted_pins`, manifest-removed ×5 beside `rollback_json::manifest_removed`. Near T55. |  | to verify |
#### Handed off
_None._

#### Rejected
_None._
