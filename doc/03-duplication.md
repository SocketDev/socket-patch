## Part 3

_Last checked against main @ b291caa on 2026-10-29 by audit-core._

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
