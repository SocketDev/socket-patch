## Part 3

_Last checked against main @ 5ca5623 on 2026-10-30 by audit-core._

 Duplicated business logic:One bullet per rule that has more than one implementation: the copies (permalinks), whether they have drifted, the register token, and the target home. Rules carried over from the first thread stay in the carried registers until reconciled.

### Findings
- **Cargo config chain:** read by `cargo_build_cache::ConfigDirs::read` and by `source_replacement::config_layer_paths`. The two have drifted on which file wins, which is a bug. {{A01}}
- **Segment glob matching:** three matchers (`cargo_workspace::wildcard_match`, `workspace_globs::segment_glob_matches`, `hatch_workspace::fnmatch`). The cargo one lacks classes, which is a bug. {{A02}}
- **GOMODCACHE/GOPATH default:** `go_crawler` and `go_installed_tools` have drifted. {{A03}}
- **Fragment pairing and the pdm/poetry rewrite triad:** in `lock_fragments`, `pdm_lock` and `poetry_lock`. {{A05}}
- **Hex digest validators:** written at about 10 sites. `vendor/jvm` reuses `digest`'s names for computations. {{A06}}
- **Tool `--version` probe:** written in `utils/pipenv.rs` and `vendor/pypi_hatch.rs`, with different hardening. {{A11}}
- **Prune-empty-dirs loops:** three copies, and they disagree on whether the bound is inclusive. {{A12}}
- **Yarn major from `packageManager`:** parsed twice. {{A13}}
- **Agent download engine:** `get <uuid>` re-implements `download_and_apply_patches_into` for one patch, and the two have drifted. {{T01}}
- **Vulnerability JSON:** built 3× (`agent_download`, `list`, `get`); get's copy is unsorted and drops `description`. {{T02}}
- **Blob fetch-summary text:** `fetch_stage` copies core `blob_fetcher`'s formatters, drifted. {{T04}}
- **Bun/vlt vendored preflight glue:** five callers, each with its own per-purl lookup. {{T05}}
- **Release-variant gating:** the CLI copies core's private `variant_installed_at`. {{T06}}
- **Apply/rollback mirror pieces:** gem build-sibling rule (drifted: any copy vs variant-matched copy) and verbose verification printer (same output, two label sources). {{T08}}
- **Worst-severity label picker:** 3 copies, drifted on unknown labels (the ladder itself is single). {{T10}} **Top-ranked patch per purl:** 4 copies. {{T15}} **Overlay staging:** 2 copies with different staging roots. {{T13}}
- **Mode resolution** in `get` and `scan`, checks in different orders. {{T14}}
- **purl `name@version` split:** about 12 hand copies, 3 in `purl.rs` alone, disagreeing on empty parts. {{A14}}
- **Uuid shape:** 4 checks; `python_script`'s `Uuid::parse_str` accepts forms the others reject. {{A15}}
- **pnpm `packages:` membership:** `lists_member` refuses brace/class globs that hosted reads with a second reader; the lock-member detector is written twice. {{A17}}
- **Poetry lock writer < 1.4:** hosted and vendored copies; the shared reader is dead. {{A18}}
- **uv settings file and `no-binary` precedence:** `python_script` and `redirect/upstream/uv`. {{A22}}
- **requirements.txt logical lines:** hosted keeps its own lexer and comment split. {{A23}}
- **"Our earlier hosted pin":** pdm/poetry vs uv/pylock rules. {{A24}}
- **PEP 508 leading name:** 3 scanners. {{A25}}
- **Vendored revert rendering:** remove and rollback each turn `VendorRevertStep` into events in their own loop (vendor.rs twice more); drifted on `--preserve-state --dry-run`, go-undo warnings, keep text and failure handling. {{T16}}
- **"No manifest" gate:** remove, repair and rollback, drifted on unledgered vendor wiring, a legacy redirect ledger, contested hosted wiring and global scope. {{T17}}
- **GC human text and warning channel:** 4 renderers; repair counts `cleanup_failed` as a skipped event. {{T19}}
- **uuid-only `PatchRecord`:** core `ledgers::uuid_only_record` beside 3 literals (list.rs L81, commands/mod.rs L388, core vendor/mod.rs L943). Local notes.
- **`--global`/`--global-prefix` flag text:** `commands::global_scope_flag` vs `ui::global_scope_arg`, drifted when both are set. Local note on `commands/mod.rs`.
- **purl shape rule:** CLI `scan/discovery::crawled_from_purl` and core `hosted::memory::discover::supplement_purl` (identical today; the core test asserts literals, not the CLI function). Part of {{A14}}.
- **Civil-date math:** `days_from_civil` in `api/date.rs` and `formats/cargo/floor.rs`, the inverse in `vex/time.rs` (which claims to be the only copy). Same values today. {{A26}}
- **Serve-URL GET and retry loops:** `download_vendor_archive_once` vs `download_artifact_capped_once` (drifted cap-breach variant and status text); 4 retry loops under 2 policies. {{A27}}
- **Service-archive integrity gate:** `vendor_prefetch::ride_along` re-implements `service_fetch::fetch_verified_archive`'s sha512 + `h1:` checks. Local note.
- **Worst-severity label picker:** a fourth copy in core `client.rs::convert_search_result_to_batch_info` (handed to audit-cli-tests for {{T10}}).
