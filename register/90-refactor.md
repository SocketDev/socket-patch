### Refactor routine (`refactor`, hourly, highest leverage first)
_Last updated 2026-10-09T13:45Z · main @ a80b89e_

**In flight:**
- [#1272](https://github.com/SocketDev/socket-patch/pull/1272): `tests/common/envelope.rs` owns the `--json` envelope readers (parse, `events`, `find_event`, event/warning codes); ~25 private copies in 24 test files deleted, ratchet `cli/envelope_helper_copies.rs`. #1089 child 1 helpers (C32). 0 prod. `state: ready`.
- [#1264](https://github.com/SocketDev/socket-patch/pull/1264): Gradle (vendored + hosted) and the Maven reactor pick inserted-line terminators through `line_endings::terminator`; `gradle/eol.rs` deleted (`eol_eq` and `respell` in `line_endings`). #815 slice 3 (E16). +67/−97 prod, +67/−37 tests. `state: ready`.
- [#1262](https://github.com/SocketDev/socket-patch/pull/1262): the OpenVEX document is written through `utils::fs::write_user_output` (stage + rename; links through, devices in place). #1144 (C77). +57/−1 prod, +185 tests; CI green, Bugbot clean. `state: ready`.
- [#1258](https://github.com/SocketDev/socket-patch/pull/1258): 40 more CLI test files import `tests/common`'s `binary()` / `git_sha256` (31 + 25 copies deleted). #824 children 2–3 slice 2 (C30). +142/−401 tests, 0 prod. `state: ready`.
- [#1253](https://github.com/SocketDev/socket-patch/pull/1253): agent-mode `jvm_jar::verify_member_bytes` streams members through `hash::git_sha256::zip_member_git_sha256` (302 → 30 MiB peak on a 256 MiB member). #914 slice (C51); `vendor/common.rs` caller is free since #1227 merged; it needs #1253's helper. +17/−11 prod, +85 tests. `state: ready`.
- [#1245](https://github.com/SocketDev/socket-patch/pull/1245): `vendor::revert::finish` + `KeepPolicy` (`OnDrift`, `OnDriftWhileReferenced`, `NpmFamily`); gem, composer, Maven legacy, NuGet and pnpm finish through it. #989 item 1 slice (E24). +133/−157 prod (helper 90), +271 tests. `state: ready`.
- [#1239](https://github.com/SocketDev/socket-patch/pull/1239): NuGet crawler `find_by_purls` looks up the global folder and legacy `<Id>.<Version>/` folders by the normalized version (`1.0.0.0` = `1.0.0`) through `normalize_nuget_version`. #1202 crawler slice (E93). +47/−19 prod, +116/−4 tests. `state: ready`.
- [#1188](https://github.com/SocketDev/socket-patch/pull/1188): one `Pipfile.lock` writer (`formats::pipenv::splice_entry`, `formats::json`). Issue #1128 (E14). +303/−235 production. `redirect/mod.rs` wrapper `pipenv_reserialized_around_reference` left for when that file is free. `state: ready`.
- [#1126](https://github.com/SocketDev/socket-patch/pull/1126): 7 inline purl-type checks through `Ecosystem::from_purl` + guard. Issue #747 (C20, slice 1). `state: ready`.
- Maintainer draft: #1049 (#792).

**Merged:** #1227 (E16 slice 2), #1221 (E19 hosted gem), #1230 (E93 `PurlKey`), #1217/#1209/#1205/#1183 (E05 Deno, Go, cargo, NuGet crawls); 32 earlier PRs (#572 … #1191, see `entries/refactor/`). Leftovers: `blob_hash_matches` (#1163), dead `eco == "maven2"` arm in `commands/vendor.rs` (#1015).

**Queue** (score = 3B + 2U + 2D + S − risk). Standalone refactor issues closed `not_planned` live on as tracker checklist items; rank the tracker's next item.

| # | Candidate | B | U | D | R | Score | Note |
|---|---|:-:|:-:|:-:|:-:|:-:|---|
| 1 | #1089 child 1 (C32): shared `common::envelope` readers | 0 | 1 | ≈25 (tests) | L | ≈12 | **taken: #1272**; remove covgap file waits on #1258 |
| 2 | #905 slice 4 (E64): `formats/pnpm/lines.rs`, `redirect/npmrc.rs`, `vex/discover/pypi_other.rs` onto `formats::text` | 0 | 0 | ≈3 | L | ≈6 | free |
| 3 | #1098 (E90): one Bundler-homes answer in `ruby_crawler.rs` | 1 | 0 | ≈1 | M | ≈3 | free in core; `vex_consumed.rs`/`ecosystem_dispatch.rs` busy |
| 4 | #931 + #998 + #1063 + #1123: one manifest load + error mapper | 4 | 1 | ≈6 | M | ≈24 | skipped: `apply.rs`, `vendor.rs`, `rollback.rs`, `remove.rs`, `repair.rs` (#1009, #1034, #1049) |
| 5 | #761/#836 (C69, S 3): parse/serialize the cargo and uv locks once per run | 0 | 0 | ≈2 | M | ≈5+S | skipped: `redirect/mod.rs` (6 PRs) |

Re-ranked 2026-10-09T13:00Z at `a80b89e` against 35 open PRs (144 production files). Still skipped by file overlap: #705, #717, #882 (E63), #823, #675, #1220, #1114, #1129, #1098's CLI half. #1270 (E95) is a pure fix for the fixer. Free but low: E37 composer `normalize_version`, C17 `yarn_berry_lock.rs` digest.

**Notes:**
- CLI tests read `--json` through `common::envelope` since #1272 (`parse_json_envelope`, strict `events`, `find_event`, `event_triples`, lenient `event_codes`/`codes_in`, recursive `all_codes`); `cli/envelope_helper_copies.rs` fails on new private copies, stale entries allowed.
- Gradle line endings (#1264): `gradle::eol` is gone; Gradle writers insert with `line_endings::terminator` and find what they wrote with `line_endings::respell(text, terminator(current))`, compare owned files with `line_endings::eol_eq`. Keep forward and revert on the same rule.
- User-named output paths (`--output`, `--vex <path>`) go through `utils::fs::write_user_output` since #1262; do not stage-and-rename over `/dev/stdout` or a FIFO with the commit-point writers. `RLIMIT_FSIZE` + ignored `SIGXFSZ` in `pre_exec` gives a root-proof part-way write failure; set `LLVM_PROFILE_FILE=/dev/null` on that child or `coverage` fails on a truncated `.profraw`.
- Revert finish (#1245): new backends end their revert with `revert::finish(outcome, root, rel, opts, KeepPolicy::…)`; the npm family keeps its bare `cannot remove <rel>` failure (warnings dropped), the rest keep warnings with `failed to remove <abs>`. Yarn berry/classic and npm add a still-wired refusal before the delete: extend the policy, do not re-copy the sequence.
- `bench.yml` gates +10% per scenario: time a per-dep reader (hosted converge) in release against `main` before pushing.
- Gem lock edits locate through `formats::gem::parse` since #1221: `Section::lines()` / `end`, `remote_line_nos`, `GemfileLock::dependencies` (entries with one name rule). Whitespace-only lines are blank separators. The vendored slice should read the same fields, not add a fourth walker.
- `golang_rewrite.golden`'s go.sum generator injects a stray CRLF line, so its inputs are mixed even with the `line_endings` mixer off; any terminator-rule change re-blesses it.
- Crawl scopes (#1205 cargo, #1209 Go, #1217 Deno): only a parseable `<cwd>` lock (`Cargo.lock`; `go.sum` with no workspace; `deno.lock` with `version`) scopes. "Only the crawl vouches" fixtures must lock the cached package (cargo: put it in `vendor/`) or drop the lock; narrowing a crawl changes `scan --prune`.
- `Pipfile.lock` edits go through `formats::pipenv::splice_entry` since #1188: sort the value (`sort_all_objects`) before splicing; never re-serialize the whole lock.
- NuGet crawl scope (#1183): only a `cwd` with a project file is scoped; a solution root keeps the walk (restores at any depth). Extend through `PackageRoots::scope`, not a second assets reader.
- A hash read from a manifest is lowercase after #1163; `api::blob_fetcher::blob_hash_matches` and vendored `eq_ignore_ascii_case` sites become plain `==` once their files are free (#707 remainder).
- `formats::xml` (#1145) is the shared XML element scanner (comment + CDATA blanking, `elements`, `children`, `attr`); route new XML readers (NuGet, pom writers) through it instead of a private masker.
- The skip rule names `arch-refactor/*` and `agent/fix-*` PRs only; still check `arch-fix/*` and `ci*` hunks before touching the same lines.
- Test-helper migrations (#824): directory binaries import via `crate::common`. `spawn_env_hygiene` scans test text, literals included: never spell a bare binary spawn in a new test file; run it before pushing.
- Equivalence goldens (`tests/equivalence/*.golden`, bless with `SOCKET_PATCH_BLESS_GOLDEN=1`) include mixed-ending inputs: prove only mixed cases move before re-blessing a line-ending change.
- The sandbox runs as root, so 4 core lib tests fail on main and on branches alike: `copy_tree::relax_loop_must_not_traverse_symlinked_root`, `vlt_heal::an_unremovable_hidden_lock_keeps_every_store_entry`, `pypi_poetry::wire_write_failure_maps_error_and_leaves_lock_untouched`, `pypi_requirements::wire_failure_rolls_back_already_written_files`.
- `redirect/pipenv.rs`, `vendor/pypi.rs` and `vendor/lock_inventory/vlt.rs` aren't rustfmt-clean on main: format only your own hunks there. Check `rustfmt --check` on the `main` copy before formatting a whole file.
- `lock_inventory/mod.rs` `architecture_tests` forbid `hosted_patch_uuid*` in a format file's model section. Origin-policy helpers go after the `// ── registry view ──` marker.
- NuGet identity (#1230): `PurlKey` folds versions through `vendor::nuget_feed::normalize_nuget_version` (a utils→vendor import until `nuget_feed.rs` frees for the `formats::nuget` move). `test_support::service_fixture` builds its NuGet grant from `<id>.<purl version>.nupkg`, so a test vendoring a non-normalized version needs that file too.
- NuGet crawl identity (#1239): `find_by_purls` runs main's probes first (`<id>/<as-written>`, exact legacy, case-insensitive legacy) and the normalized ones only after (`<id>/<normalized>`, `legacy_dir_is`), so a cache with two spellings keeps main's pick. The `oracle.rs` equivalence keeps main's rule; its randomized versions are all normalized, so it still agrees.
- Steering (2026-10-02, #569/#571): no size caps on trusted upstream data; stream, don't buffer.
- `tests/spawn_env_hygiene.rs` allowlists (`PENDING_RAW_SPAWNS` / `PENDING_SCRUB_COPIES`) fail on new **and** stale entries: drop a file when you migrate it.
- Probe spawns go through `utils::process::output_within` since #886 (blocking; async callers wrap it in `utils::fs::run_blocking`). It nulls stderr; don't add a new `tokio::time::timeout` + `kill_on_drop` site.
