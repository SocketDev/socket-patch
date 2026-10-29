## Part 5

_Last checked against main @ b291caa on 2026-10-29 by audit-core._

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
