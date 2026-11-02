### CLI and tests audit (T rows)
_Last updated 2026-11-02T09:51Z · main @ cbbbdb9 · owner: audit-cli-tests_

| ID | P | Problem | Issues | Status |
|---|---|---|---|---|
| T01 | 2 | `get <uuid>` agent mode re-implements `download_and_apply_patches_into` (~240 lines), drifted on messages and `persist_blobs`. | #1835 | filed #1835 |
| T02 | 2 | The vulnerability JSON object is hand-built 3× (`patch_event_metadata`, list, get `options[]`); get's copy is unsorted and drops `description`. | #1836 | filed #1836 |
| T03 | 2 | `GLOBAL_ARG_ENV_VARS`/`LOCAL_ARG_ENV_VARS` hand-copy clap `env` bindings and miss `SOCKET_NO_SOCKET_YML`; the invariant tests iterate their own lists. | #1837 | filed #1837 |
| T04 | 3 | `fetch_stage` copies core `blob_fetcher` fetch-summary formatters; the copy is unsorted, shows raw errors and always appends `...`. | #1838 | filed #1838 |
| T05 | 2 | Bun and vlt vendored preflights run back to back at every caller with per-purl glue; callers disagree on the root (`project_root` vs `cwd`). | #1839 | filed #1839 |
| T06 | 2 | CLI `apply::representative_file` + `variant_matches_installed` (apply.rs L761-L788) copy core `patch::apply::variant_installed_at` (private); recombined with `verify_file_patch` at apply.rs L2579, L3214 and vendor.rs L2837, L3347. |  | to verify |
| T07 | 3 | The `VexSummary { format: "openvex-0.2.0", .. }` literal is hand-built 7× (apply ×2, vendor ×3, scan, scan/hosted); `expect("vex_result is Some…")` 3× in apply. Folded into T25. | #1877 | filed #1877 |
| T08 | 3 | Gem build-sibling rule twice (`apply::has_build_sibling` any copy vs rollback.rs L2932 variant-matched, string `pkg:gem/` check); verbose verification printer twice (apply.rs L2092, rollback.rs L2419). C24. | #771 | to verify |
| T09 | 3 | Lock acquire open-coded 9× beside `acquire_or_emit`; `from_secs(lock_timeout.unwrap_or(0))` 14×; `lock_held` rendered 3 ways. | #1858 | filed #1858 |
| T10 | 3 | The "worst severity label" picker is written 3× (scan/mod.rs L3150, render.rs L396, `agent_download::max_vuln_severity`), drifted on unknown labels. |  | to verify |
| T11 | 3 | `DownloadParams` copies 10 `GlobalArgs` fields (filled field by field in get and scan) and `nested_apply_args_from_params` rebuilds a `GlobalArgs` from them: a translation layer. C10. | #793 | to verify |
| T12 | 3 | `composer_hints::vendored_composer_packages` parses composer.lock in the CLI and re-derives vendored-path detection by prefix instead of core `vendor::path::parse_vendor_reference` (drifted: no `../` workspace refs, no uuid check). |  | to verify |
| T13 | 3 | Overlay staging twice: `fetch_stage::overlay_dir` stages in system tmp (so hardlinks fail across filesystems and the blob cache is copied), rollback.rs L3016 stages in `.socket`. |  | to verify |
| T14 | 3 | Mode resolution (explicit / state-inferred / foreign-manifest / global conflict) is written in get (L1077-L1126) and scan (mod.rs L270-L308, L1737-L1772) with the checks in a different order. |  | to verify |
| T15 | 2 | Per-purl top-ranked selection 5× (get, scan/policy ×2, core rollout, core memory); socket.yml floor 3×; tier filter 4×. |  | to verify |
| T16 | 2 | remove and rollback each render `VendorRevertStep` in their own loop (vendor.rs classifies it twice more); drifted on `--preserve-state --dry-run` (remove previews a full revert), go-undo warnings, drift-keep text and stop-at-first-failure. | #1861 | filed #1861 |
| T17 | 2 | The "no manifest" gate is written 3× (remove, repair, rollback), drifted on vendor wiring, legacy state, hosted wiring, global scope and message. C74. |  | to verify |
| T18 | 3 | `scan/discovery.rs` keeps a private `shell_word` beside `ui::shell_word`; it quotes POSIX-style on Windows and leaves `%` bare. | #1859 | in PR #1884 |
| T19 | 3 | GC reporting differs past C79: repair records `cleanup_failed` as `Skipped` (others: warning), singular labels, and 4 human renderers (remove says "would be freed", core "freed" on a dry run). |  | to verify |
| T20 | 3 | The "JSON envelope or stderr" error emit is hand-written ~6× (remove, rollback, repair ×3, list, scan) plus 4 open-coded rollback branches. Wants `json_envelope::emit_error`. | #1924 | filed #1924 |
| T21 | 3 | The warning sink (`--json` → `warnings[]`, else stderr) is hand-rolled per command (list.rs ×3, user_patches.rs L122, scan/withdrawn.rs L126); withdrawn prints under `--silent`, the others don't; 40 `RunWarning {` literals vs 17 `RunWarning::new`. |  | to verify |
| T22 | 3 | rollback's before-blob gate (L677, L3184) uses `metadata().is_err()` vs core `symlink_metadata().is_file()`: a planted link/dir counts as present; fails closed `missing_blob`. Unexecuted. |  | to verify |
| T23 | 3 | The terminal-safe text filter is written 3× (list.rs `sanitize`, ui/status.rs `println`, core `policy::strip_unsafe`); only core drops bidi overrides and zero-width characters, so `list` prints them from API text. | #1860 | filed #1860 |
| T24 | 2 | Disk hosted scan (`run_redirect_selected_untracked`, 1,233 lines) hand-copies core's in-memory pipeline; drifted (`governing_root::refusal` disk-only). Child of C12. | #894 | to verify |
| T25 | 2 | The `--vex` embed step is hand-written ~8× (scan ×4, apply ×2, vendor ×3); only scan reports `vex_skipped_dry_run` under `--json`, and fold order differs. Absorbs T07. | #1877 | filed #1877 |
| T26 | 2 | Pipenv stale-install remedy written twice (hosted `scan/hosted/python.rs` L134-L205, core `vendor/pypi.rs` L786-L860); drifted on per-site vs aggregated warnings, suffix wording (`<purl>` placeholder) and name parsing. | #1878 | in PR #1883 |
| T27 | 3 | Hosted stale-install and takeover warnings are built as `serde_json::Value` (hosted, python, nuget, takeover, vlt_heal) and parsed back by `run_warning_of` with `unwrap_or_default`. Part of T21. | #1879 | filed #1879 |
| T28 | 3 | The vulnerability label rule (CVEs else advisory id) is written 4× (render.rs L385, get.rs L222 and L372, list.rs L284); drifted on order, dedup and severity case. | #1880 | filed #1880 |
| T29 | 2 | The hosted `redirect` JSON block has two shapes (disk `{mode, rewrittenFiles}` vs core's 7 keys). Decision. | #1881 | decision #1881 |
| T30 | 3 | Snapshot/put-back of files the group commit doesn't capture is written twice (`scan/hosted.rs` `commit_hosted_writes` L2093-L2190, `vendor.rs` L1701-L1758); hosted drops put-back errors (`let _ =` L2183) yet says "nothing was changed". |  | to verify |
| T31 | 3 | The project-root marker predicate is written twice (`scan/policy.rs` `lock_markers` L105-L121, core `hosted/memory/roots.rs` `root_markers` L41-L58); disk adds a manifest fallback the memory engine lacks (its doc admits the verdicts differ). Unexecuted. |  | to verify |
| T32 | 3 | The agent dry-run preview event is built 3× (scan/mod.rs L2896-L2917, get.rs L1868-L1894, agent_download.rs L1089) and the already-recorded check re-derived a 4th time (scan/mod.rs L3322) beside `decide_patch_action`. |  | to verify |
| T33 | 3 | Suspected: hosted takeover plans one ledger entry (takeover.rs L119) but `finish` removes every `PurlKey::same` entry (L410). Unexecuted. |  | to verify |
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
| T55 | 3 | Suites that include `common` keep their own `has_command` ×9, `sha256_hex` ×16, `git_sha256_file`/`assert_run_ok` ×4, `npm_run` ×3; dead `stderr_chatter` filter (executed); `rollback_json` copies 4 envelope readers. | #1959 | filed #1959 |
| T56 | 3 | Parse-suite env scrub written 4 ways (`EnvScrub` ×4, hand lists, `with_clean_env`, none); `SOCKET_JSON=true` fails 3 (executed). | #1956 | in PR #1978 |
| T57 | 3 | The `cli_parse_<cmd>` suites re-pin flattened `GlobalArgs` one test per flag (~85 tests) beside `cli_global_args`' every-flag × every-subcommand matrix; their field lists drift (apply/rollback `bool_flags` lack 5). Follows T56. |  | to verify |
| T58 | 3 | 21 `tests/common` selftests run in each of ~104 includers (~2K redundant runs; 14 binaries include `cache_env` twice); the "no `cfg(test)` in integration crates" comment ×3 is false (executed). | #1957 | filed #1957 |
| T59 | 3 | `hermetic::command` leaves `CLICOLOR_FORCE`/`NO_COLOR`/`COLUMNS`/`CI` ambient (executed); `HOSTILE_SEEDS` seed then remove the same list. | #1958, #1964 | in PR #1964 |
| T60 | 3 | Docker suites copy their harness (`cov_docker_args` ×10, `skip_if_no_image` ×11 mostly ungated, `run_container` ×5, `assert_vex_agent_attested` ×8); CI exports REQUIRED only in the `sbt)` arm. | #1968, #1972 | in PR #1972 |
| T61 | 3 | `prebuilt_common::prepare_command` filters `--offline` out of vendor/repair args; 49 `"--offline"` calls in 16 suites run online, and comments claim offline runs. | #1969 | filed #1969 |
| T62 | 3 | 8 of 9 docker agent suites serve a zero `beforeHash` and `apply --force`, so only the force path is proven (gem's doc says so); port gem's real-hash probe. | #1970 | filed #1970 |
| T63 | 3 | Docker vendor capstones: `assert_vex_attested_from_host` ×4 checks only `(vendored)` beside `assert_attested`; `render` ×5; stage-3 bash ×5; 4 manifest-less VEX mechanisms. |  | to verify |
| T64 | 3 | Test fs/scan plumbing copied: 38 recursive `copy_tree`/`copy_dir_recursive` (20 identical), `start_proxy`+`assert_proxy_served_scans` ×4, `hosted_pin_count` ×8 beside `envelope::hosted_pins`. | #1979 | filed #1979 |
| T65 | 3 | Go e2e harness copied across 5 suites beside `golang_e2e_matrix`: `go()` ×4 (drifted on `GOFLAGS`/`GOWORK`), file-proxy publish+zip ×5, `ChmodGuard` ×2 (md5-identical), `harvest_sums` ×2, grant/sumdb mocks ×3, gopatch literal ×6 files. | #1980 | filed #1980 |
| T66 | 3 | `hermetic` has no Go `Extra`: children inherit `GOFLAGS`/`GOENV`/`GOWORK`/`GOPATH`/`GOMODCACHE`; Go suites `set_var` unrestored; hosted-production golang/deno tests can't fail. | #1981 | filed #1981 |
| T67 | 3 | Gradle `--global-prefix` tests pass without the flag: `isolate_cli`/`socket()` always set `GRADLE_USER_HOME`, which silences `gradle_user_home_differs` (executed); no test asserts the warning fires. | #1982 | filed #1982 |
| T68 | 3 | `e2e_hosted_production`/`e2e_vendored_production` near-fork: 11 md5-identical helpers, 8 drifted, copied catalog; hosted re-writes `hosted_pins`, `assert_no_hosted_ledger`, `assert_attested`. | #1983 | filed #1983 |
| T69 | 3 | Scan e2e counts by substring: nuget `scannedPackages: {n}` unterminated (10–19 pass n=1); `!a && !a` ×5 (cargo, maven, nuget); hosted_state asserts on a never-written ledger (×2). Near C32. |  | to verify |
#### Handed off
_None._

#### Rejected
_None._
