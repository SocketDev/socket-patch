### Ecosystems and formats (`audit-ecosystems`)
_Last updated 2026-10-02 (seeded from the review) · main @ 61cfb9b_

| ID | P | Problem | Source | Issues | Status |
|---|:-:|---|---|---|---|
| E01 | 1 | Hosted NuGet source mapping (`nuget_package_source_keys`) regex-scans raw XML, so a commented-out `<add key>` changes which sources get mapped. The vendored reader and `formats::nuget` both mask comments. | §1 #5; 5.4 | | to verify |
| E02 | 1 | `bun.lockb` vendoring hard-codes `registry.npmjs.org` and ignores `SOCKET_NPM_REGISTRY`. The npm tarball URL is re-implemented in `lock_inventory/vlt.rs`, and there are two `NPM_REGISTRY` constants. | §1 #7; 4.4 | | to verify |
| E03 | 1 | vlt `registry_base` has two implementations (`upstream/vlt.rs`, `lock_inventory/vlt.rs`) with different fallback orders and different unknown-alias behavior. | §1 #7; 4.4 | | to verify |
| E04 | 1 | Pipenv hosted-URL recognition accepts any host (`pypi_pipenv.rs`), but `redirect` `hosted_patch_uuid` uses an origin allowlist. | 5.4 | | to verify |
| E05 | 1 | Cache crawls aren't project-scoped: cargo, go, maven, nuget and deno enumerate the whole machine cache, and scan sends all of it to the API (#265). | 6.6 | | to verify |
| E06 | 1 | Some crawler reads aren't FIFO-safe: `nuget_crawler.rs` and `python_crawler.rs` use a plain `read_to_string` on files in the project tree. | 6.6 | | to verify |
| E07 | 2 | package-lock has four entry walks and three JSON re-serialization strategies (`redirect::serialize_json`, `common::serialize_json`, `JsonLayout`). Target: one `NpmLockDoc` model. #357 fixed part of this. | 4.4; 4.7 E | | to verify |
| E08 | 2 | yarn has five `split("\n\n")` + regex grammars beside `scan_blocks`. Target: hosted yarn writers and restorers built on `LockBlock`. | 3.7 #3; 4.7 D | | to verify |
| E09 | 2 | Yarn berry gates are written twice: the cacheKey constant, cacheKey extraction, and the mixed-EOL and `compressionLevel` refusals, which use different codes. #370 needs fixing twice. | 4.4 | | to verify |
| E10 | 2 | XML has eight hand-rolled scanners and four attribute extractors with three tokenization rules. The writers (`nuget_feed.rs`, `maven_repo.rs`) never use the shared readers, so reader and writer can disagree. | 5.4 | | to verify |
| E11 | 2 | NuGet config has three readers. Target: `formats::nuget::parse_config` everywhere. Fixing E01 is the first step. | 3.7 #3; 5.4 | | to verify |
| E12 | 2 | pnpm v9 and legacy 5.4/6.0 are near-copies (`revert_*_opts`, `vendor_pnpm*`, `read_project`, `edit_overrides`, `dep_field_lines`, the KIND constant), and v9 has two lookup paths (a linear scan and `LockIndex`). | 4.4; 4.5 #4; 4.7 B/G | | to verify |
| E13 | 2 | `utils/poetry_lock.rs` ≈ `utils/pdm_lock.rs`: the `*_lock_edits` functions are identical, and the `pair_*` functions differ by one shape check, which is a latent bug in one of them. | 5.4 | | to verify |
| E14 | 2 | Pipfile.lock is written two ways: vendored mode re-serializes it, while hosted mode splices spans. | 5.4 | | to verify |
| E15 | 2 | Cargo.toml has a line-based parser in `cargo_crawler.rs` even though the crate depends on `toml_edit`. `cargo_tag.rs` finds the version textually, and `plan_cargo_toml` uses a regex scanner and `toml_edit` in one rewriter. | 5.4; 3.7 #3 | | to verify |
| E16 | 2 | CRLF has five policies in the npm family and three for `toml_edit` output, and `common::detect_eol` contradicts `LineEndings::Mixed`. Target: one line-ending policy. | 4.4; 5.4; 7.3 | | to verify |
| E17 | 2 | "Is a bun lock present" has four predicates with different symlink semantics, so a dangling `bun.lock` symlink is present to one of them and absent to the others. | 4.4 | | to verify |
| E18 | 3 | JS helper copies: JSON-pointer escape ×2, wiring lines↔JSON ×3, `name@spec` split ×2, `KIND_*` re-spelled as literals, uneven recursion bounds, and regexes compiled inside per-dependency loops. | 4.4 | | to verify |
| E19 | 3 | Gem has three section models and two DEPENDENCIES-name parsers with different rules. Go's `go_mod_edit.rs` lives in `vendor/`, and `go_crawler.rs` has its own `parse_go_mod_module`. | 5.4 | | to verify |
| E20 | 3 | Pure codecs (`bun_lockb.rs`, `bun_lock_text.rs`, `vlt_lock_text.rs`) and the neutral types (`Edit`, `Warning`, `LockfileEntry`) live outside `formats/`, which creates `formats`↔`vendor`/`redirect`/`vex` cycles. | 2.1; 4.5 #2; 4.7 J | | to verify |
| E21 | 2 | Tracking: `VendorBackend` trait + registry. The ecosystem list is enumerated at 16 production sites, and the `vend!` / `vend_installed!` macros stand in for the trait. | 2.1; 5.2; 5.8 | | to verify |
| E22 | 2 | The JS vendor driver skeleton is copied eight times (`guard_coordinates` → … → a literal `VendorEntry`). Target: one generic driver + `NpmLockBackend`. | 4.4; 4.7 C | | to verify |
| E23 | 2 | The `pypi_{poetry,pdm,pipenv}.rs` backends repeat one skeleton: `load_*_project`, `classify_dependency`, `check_target_guards`, `wire_*`, `revert_*`. | 5.4 | | to verify |
| E24 | 2 | There are nine revert mechanisms (~3.5K lines). Target: one splice-record revert engine, with legacy ledger kinds adapted at load. | 2.1; 5.3; 5.8 | | to verify |
| E25 | 3 | Per-backend copies: `cleanup_failed_stage`, `<eco>_service_copy` (cargo, composer, gem, golang), and the `service_preflight_names_exactly_*` test copied seven times. | 5.4; 5.8 | | to verify |
| E26 | 3 | JVM has two Maven backends. Target: merge `maven_repo.rs` into `jvm/` as `Shape::Single`. Its three artifact roots don't follow `<eco>/<uuid>`. | 5.7 | | to verify |
| E27 | 3 | The per-package call model needs ~3K lines of compensating machinery (`group_commit`, `durability`, `prestage`, `vendor_prefetch`, 22 `ParseMemo` statics, `ledger_snapshots`). Target: batched pure planners, after E21 and E24. | 2.4; 5.7 | | to verify |
| E28 | 2 | Dead vendored scaffolding: `VendorSource` / `PackageSource` have one variant each, the `SERVICE_ECOSYSTEMS` refusal can never fire, `ServicePolicy::new` ignores its config, `vend_installed!` has no target, and several docs are stale. | 5.6; R11 | | to verify |
| E29 | 3 | `registry_fetch.rs` (1.5K lines) is really archive extraction, integrity checks and the hosted-restore HTTP client, so it is misnamed and in the wrong place. | 5.6 | | to verify |
| E30 | 2 | Split `redirect/mod.rs` (17.5K lines) mechanically: `model`, `driver`, one file per ecosystem, `hosted_url`, and sibling test files. | 3.7 #1 | | to verify |
| E31 | 2 | Tracking: `trait HostedRewriter` + `Outcome { per_dep }`. It replaces the 20 uuid sets in `RewriteResult`, `merge_group_delta`, the 16-rule `confirm()` and eight parallel tables. | 2.1; 3.7 #2 | | to verify |
| E32 | 2 | There are two hosted orchestrators, disk (`run_redirect_selected`) and in-memory (`hosted/memory`), kept equal by parity tests. Target: one pipeline. Depends on E44. | 3.3; 3.7 #4 | | to verify |
| E33 | 3 | Upstream restore rebuilds originals from the network (~7.4K lines, ignores mirrors, 13 open bugs). Target: an originals sidecar or a narrowed restore. Depends on E45. | 2.3; 3.5 | | to verify |
| E34 | 3 | Per-PM auto-config costs more than it's worth: npm `allow-remote` (~900 lines re-implementing npm config), pnpm `trustLockfile`, the vlt warm-tree heal, and the unbenchmarked parallel rewriter groups. | 3.6; 3.7 #7 | | to verify |
| E35 | 3 | Retire the refactor oracles: the redirect equivalence suites and 252 KB of goldens, the crawler oracles (3K lines), and the telescoping entry points (use one `RewriteOptions`). | 3.7 #9; 6.6 | | to verify |
| E36 | 2 | Tracking: one `Inventory`. Today's four discovery systems are merged by fabricating `CrawledPackage`s with fake `node_modules/<name>` paths. Rename `vex::discover` (it is the hosted-state store). | 2.1; 6.2; 6.7 | | to verify |
| E37 | 2 | `is_safe_{cargo,gem,nuget}_coordinate` are byte-identical and duplicate `simple_purl`'s check. `composer_crawler::normalize_version` duplicates `strip_leading_v`. | 6.4 | | to verify |
| E38 | 2 | The product-manifest probe table is copied three times and has drifted: `vex.rs` lacks the csproj and gemspec probes. The probes don't reuse the format parsers. | 6.4; 6.5 | | to verify |
| E39 | 3 | `canonicalize_pypi_name` lives in `crawlers/` (29 importers), and `Ecosystem` lives in `crawlers/types.rs` while `LockfileEntry.ecosystem` is a string. Target: `core/src/ecosystem.rs`. | 2.1; 6.4 | | to verify |
| E40 | 2 | `vex_consumed.rs`, in the CLI, is a third copy of package-manager layout knowledge. Target: move it into per-ecosystem locators in core. | 6.5 | | to verify |
| E41 | 2 | Dead discovery code: `lock_inventory/wired.rs` has no production caller, `vex/discover/deno.rs` is an empty extractor, and the pre-v5 redirect-ledger readers (~430 lines) remain. | 6.4; 6.5; R11 | | to verify |
| E42 | 2 | The embedded `--vex` glue is copied per command (scan, apply, and vendor ×3), each with caller-injected bypass sets. Target: one `EmbeddedVex` helper. | 6.5; R13 | | to verify |
| E43 | 2 | Fail closed on unmodeled resolution config in one shared place: `go.work`, `gradle.lockfile`, `BUNDLE_GEMFILE`, `virtualStoreDir`, `install-strategy=linked`, `globalPackagesFolder`, mirrors. | 2.2 #3 | | to verify |
| E44 | 2 | Decide: the napi addon and in-memory engine. Will depscan adopt it (then delete the TS rewriters), or should it be deleted (−4.8K prod)? | §6 Q1; 3.7 #6 | | to verify |
| E45 | 2 | Decide: hosted rollback. Is an originals sidecar acceptable, or should restore be narrowed to formats whose original is a pure function of registry data? | §6 Q5; 2.3 | | to verify |
| E46 | 2 | Decide: VEX evidence. Should `not_affected` require consumed evidence by default, so that wired-only evidence (`lockfile_basis_ok`) needs an opt-in? This is behind 29 open issues. | §6 Q4; 2.2; 6.5 | | to verify |
| E47 | 3 | Decide: support tiers for `bun.lockb` writes, vendored pnpm 7/8, vlt pre-1.0 encodings and hosted pnpm ≤ 6, and whether hosted JVM ships as beta. | §5; §6 Q3; 4.6 | | to verify |
| E48 | 3 | Discovery re-implements package-manager layouts (venv-name hashing, global prefixes, the pnpm store). Target: ask the package manager (`poetry env info -p`, `pipenv --venv`, `npm query`, …). | 2.2 #2; 6.6 | | to verify |

**Handed off:** none yet.

**Rejected / not a defect:** none yet.

**Already fixed:** none yet.
