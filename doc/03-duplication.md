## Part 3

_Last checked against main @ c07af61 on 2026-10-29 by audit-cli-tests._

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
- **Apply/rollback mirror pieces:** gem build-sibling rule and verbose verification printer, both drifted. {{T08}}
- **Severity ladder:** 3 copies. {{T10}} **Top-ranked patch per purl:** 4 copies. {{T15}} **Overlay staging:** 2 copies with different staging roots. {{T13}}
- **Mode resolution** in `get` and `scan`, checks in different orders. {{T14}}
