## Part 5

_Last checked against main @ 5ca5623 on 2026-10-30 by audit-core._

 Tests:Fake tests (asserting on their own mocks, recomputing expected values with the code under test, unable to fail, claiming more than they check), mock overuse where a tempdir or a real install is cheap, sentence-matching assertions, duplicate tests, and real coverage gaps. Per-directory tallies and the fixes that landed.

### Findings
- **Tally for `utils/` (first 28 files): 17 fake or weak tests.**
  - Tautologies: `constants.rs` ×3.
  - The expected value is recomputed with the code under test: `concurrent` per-window cap.
  - The test name overclaims:
    - `durability` vanished-file test;
    - `group_commit` journal test;
    - `http` `production_builder_builds`;
    - `go_installed_tools` unlistable-dir test (asserts the opposite when `go` is on PATH).
  - Duplicates:
    - `pipenv` ×3, copying `process.rs` tests;
    - `pdm_lock` shape-change test, copying a `lock_fragments` test;
    - `fs` `entry_file_type` ×2, which only exercise tokio.
  - Sentence matching where a typed error exists: `http` cap tests.
  - Only `is_err()` asserted: `pdm_lock` unsafe-sources test.
- **Root-skip tests** pass silently under root (`group_commit` ×2, `fs` ×3).
- **Coverage gaps:**
  - `http` mid-stream cap and `Truncated`;
  - `cargo_build_cache` warning text;
  - the cargo config precedence, now covered by {{A01}}'s acceptance criteria.
- **Tally for `crates/socket-patch-cli/src` (first 8 files): about 38 fake, duplicate or misplaced tests.**
  - Duplicates of core tests: get's 10 `detect_*` (core `target.rs`) and 9 `select_*` ranking tests (core `ranking.rs`).
  - Duplicates of `tests/cli_global_args.rs`: 6 inline tests in `args.rs`.
  - Can't fail: `fetch_stage` obsolete diff/package archive tests ×2; `get` `apply_failed_line_is_an_error_even_when_silent` (a const equals its literal); `args` env-list and `VendorSource` tests ×3.
  - Name overclaims: get `select_json_mode_multi_free_options_serialize_vulnerabilities` asserts only `Err(1)`. {{T02}}
  - Misplaced: ~63 `agent_download` tests (~2,800 lines) live in `get.rs`.
- **Coverage gaps:** no assert on any Gradle detail text in apply (a broken string continuation at apply.rs L3111 ships 17-space runs); no 401 test on get's search path; no test ties the env lists to clap. {{T03}}
- **Tally for the rest of `utils/` (20 files): 23 fake or weak tests.**
  - Tautologies: `purl.rs` ×15 (7 `test_build_*_purl`, 7 `*_round_trip`, `test_is_purl`); `process.rs` ×2 (assert std's `Command::new`).
  - Expected value recomputed with the code under test: `purl_key` `nuget_key_agrees_with_the_vendored_version_match`.
  - Duplicates: `poetry_lock` shape-change test (third copy) {{A05}}; `uri.rs`'s asserts repeated byte for byte in `yarn_berry_lock.rs`.
  - Weak asserts: `poetry_lock` malformed-integrity (`!err.is_empty()`), `python_lock` "ours" test (`is_ok()` passes on `Ok(None)`).
  - Misplaced: `purl_key_nuget_vendor_tests.rs` (an end-to-end vendor test), `redact`'s lint of `vendor/service_fetch.rs`.
- **Coverage gaps:** `python_script` `refuse_uv_no_binary`/`no_sources` (project form) have no unit test.
- **Tally for `crates/socket-patch-cli/src/commands` (next 10 files): about 30 fake, duplicate or misplaced tests.**
  - Can't fail: `list` `ordering_is_deterministic_across_builds` (iterates one HashMap twice); remove `dry_run_footer_matches_repair` and repair's `HOSTED_ONLY_REASON` assert (a const equals its literal).
  - Asserts the test's own stub: rollback `rollback_patches_missing_manifest_is_identifier_error` (the message comes from the test helper's `ok_or_else`).
  - Duplicates of core tests: discovery's 5 `severity_order` tests (core `ranking.rs`), 4 `candidate_supersedes` and 1 `unsupported_layout_warnings` test of core functions; ~5 remove `remove_matching` tests repeat core `Target` tests.
  - Subset or overclaiming tests: lock_cli ×4, repair ×3, mod.rs ×3 (only `is_err()` or a `.contains` that a sibling message also satisfies).
- **Coverage gaps:** no test of `remove --preserve-state --dry-run` over a vendored entry {{T16}}; no test that `scan --json` keeps stderr empty on a held lock {{T09}}; no bidi/zero-width test for `list` {{T23}}.
- **Tally for `api/` and `cargo_crawler*`: about 40 fake, duplicate or misplaced tests.**
  - Tautologies: `ranking` `merged_coverage_is_the_advisory_count` (identity fn) and `same_patch_dates_across_different_packages_do_not_interact` (the key has no purl); `date` `parsed_order_is_chronological_in_both_formats`'s monotonic assert (its own loop counter); `types` `published_at_is_per_patch_not_per_package` (its own fixture); `tests/api_timeout_e2e.rs` const == literal.
  - Duplicates: `types` ×10 serde serialize/roundtrip tests; `ranking` ×4 rung tests; `blob_fetcher` ×5 format tests.
  - Misplaced: `client.rs` tests `is_hex` ×5, `severity_order` ×2, `is_uuid_shaped` ×2; `cargo_crawler` tests `package_name_version` ×7 (covered in `formats/cargo/manifest.rs`).
  - Env mutation without a guard: `client` `test_get_api_client_from_env_no_token` (and it reads the user's socket-cli config).
  - Test scaffolding: four xorshift64* RNGs and eight legacy crawler oracles. {{A29}}
- **Strong:** `vendor_prefetch`'s serial-differential tests and `client`'s wiremock retry tests assert request counts and outcomes, not mocks.
