> [agent] **Part 6 of 9** of the living socket-patch architecture document. The summary and ranked recommendations are in the top post. Originally written against `2463257`; the routines update this part as the code changes.

## Part 6: Discovery, inventory and VEX

_Last checked against main @ ea09714 on 2026-10-08 by audit-ecosystems (6.2 discovery systems, the fabricated scan paths and the `vex::discover` importers re-checked for E36; PyPI lock precedence in the inventory checked for E91; 6.5 VEX attestation after #1033). Earlier: `e61a845` on 2026-10-08 by audit-ecosystems (gem home selection in the crawler, the stale guard and the `vex` installed lookup checked for E90; the lockfile basis checked for E46; 6.4 coordinate guards and the product probe table re-checked). Earlier: `05ecc6e` on 2026-10-07 by audit-ecosystems (PyPI pure-wheel selection in `lock_inventory` and ledger recovery checked for E89). Earlier: `431b818` by the October 7 reconciliation (extractor count and the false-attestation backlog re-checked; this part does not yet cover the JVM-cache crawl or `formats::registry`). Earlier: `db83f01` by audit-ecosystems (6.6 JVM crawler build-tool markers and npm alias discovery re-checked at `db83f01`; 6.4 layering inversion and the Bundler lock rule re-checked at `9c43dfc`; 6.5 `vex_consumed.rs` and npm alias discovery as of `4646693`; as of `045d7ec`: gem lock selection, the go.mod row, 6.4 dead code and the product probe table re-checked). Owner: `audit-ecosystems`._

> Scope: `vex/**` (incl. `vex/discover/*`), `crawlers/**`, `formats/**`, `vendor/lock_inventory/*`, and the CLI consumers `vex.rs`, `vex_sources.rs`, `vex_consumed.rs`, `scan/discovery.rs`, `context.rs`, `list.rs`, `ecosystem_dispatch.rs`.

### 6.1 Size

| Area | Total | Production | Notes |
|---|---:|---:|---|
| `vex/` | 28,788 | ~10,040 | `discover/` alone is 8,499 production lines, 27% of them comments |
| `crawlers/` | 23,739 | 8,930 | 3,007 test-only oracle/equivalence lines; 32% of production lines are comments |
| `formats/` | 5,131 | 4,650 | |
| `vendor/lock_inventory/` | 7,605 | 3,659 | |
| CLI consumers | — | 4,798 | `vex.rs` 1,334, `vex_sources.rs` 976, `vex_consumed.rs` 596, `ecosystem_dispatch.rs` 816 |

The VEX stack is about **13K production lines tested by about 59K test lines**: ~11K of core crawler tests and ~40K of CLI `*vex*` end-to-end tests.

### 6.2 Four discovery systems

| System | Entry point | Reads | Returns |
|---|---|---|---|
| **A. Crawlers** | `crawl_every_ecosystem` (`ecosystem_dispatch.rs:860`); nine crawlers in a `tokio::join!` | installed trees (`node_modules`, `site-packages`, `vendor/composer/installed.json`) **and whole machine caches**: `$CARGO_HOME/registry/src`, `GOMODCACHE`, `~/.m2`, `~/.nuget/packages`, `DENO_DIR` | `CrawledPackage {name, version, namespace, purl, path}` |
| **B. Lock inventory** | `inventory_project_diagnosed_in` / `union_views_in` (`lock_inventory/mod.rs:273-330`) | one lockfile per ecosystem, chosen by precedence (shrinkwrap wins; uv is exclusive; poetry → pdm → Pipfile). **No Maven, NuGet or Deno.** | `LockfileEntry {ecosystem: &'static str, name, version, purl, resolved, integrity, source_kind}` |
| **C. Wiring discovery** | `discover_with_ctx` (`vex/discover/mod.rs:1000-1022`); 15 extractors in fixed order (13 at review), then `contest_across_locks` | **every** lock/config present ("rule 1: never apply precedence"), each swept for Socket identities | `Discovery {refs: Vec<PatchedRef>, diagnostics, recognized, unlocked_pins, elsewhere}` |
| **D. Vendor-ledger supplement** | `vendored_ledger_supplement` (`scan/discovery.rs:141`) | `.socket/vendor/state.json` + artifacts | fabricated `CrawledPackage`s |

How `scan` combines them (`scan/mod.rs:1589-1660`):
1. **Crawl first, in every mode.**
2. Append lockfile-only entries as fabricated `CrawledPackage`s. `crawled_from_purl` (`discovery.rs:113-133`) sets `path: cwd.join("node_modules").join(name_part)` **for every ecosystem**, including cargo and pypi. The caller keeps a side set, `supplement_purls` (`scan/mod.rs:1807-1835`), so that the PATH-scope filter can skip the fake paths. {{E36}}
3. Append ledger-only entries.
4. Fold hosted pins from C into update detection.

**Overlaps:**
- B and C walk the same per-format entries. B keeps registry entries; C classifies the Socket-owned ones *and* emits `ResolvedElsewhere`, which is a second registry view.
- Liveness then calls B a **third** time, straight from disk (`inventory_project_every_lock(root)`, `vex/discover/mod.rs:1898`), bypassing the shared `DiskSnapshot`.
- B has two parallel modes, `Instances::Every` and `Instances::Collapsed`, with an if/else for every format.
- A is unrelated to B and C.

**This could be one pass**, because the per-format parsers are already mostly shared. What is duplicated is the *classification and selection layer*. One model would replace all of them:

```rust
struct Instance {
    purl: CanonicalPurl,
    declared_in: Option<Rel>,
    resolution: Registry { url, integrity, source_kind }
              | Hosted { uuid, url, integrity, required }
              | Vendored { uuid, artifact_rel, integrity }
              | Other,
    installed_at: Vec<PathBuf>,   // filled in by locators (ex-crawlers)
}
```

From that model:
- `LockfileEntry` is the Registry instances, filtered by precedence and deduplicated;
- `PatchedRef` and `HostedPin` are the Hosted and Vendored instances;
- `ResolvedElsewhere` is the Registry and Other instances;
- the scan supplement is instances with an empty `installed_at`, which removes the fake `node_modules` path.

`formats/mod.rs:1-25` already documents this target (`entries()`, `wired_refs()`, `plan_hosted()`), but `entries()` exists only for composer, pnpm, gem and cargo, and `wired_refs()` only for pnpm.

### 6.3 Format × subsystem matrix (abridged)

| Format | Shared read model | Writers with their own walk |
|---|---|---|
| package-lock | `lock_inventory::npm_lock_nodes` | vendored `scan_lock_matches`, hosted `mod.rs:837`, upstream `npm_lock_hits` |
| Pipfile.lock | `lock_inventory::pypi::pipfile_lock_entries` | vendored `pypi_pipenv.rs` (×3), hosted `redirect/pipenv.rs:98`; the crawler re-implements Pipenv venv hashing |
| Cargo.toml | — | hand-rolled **twice** (`cargo_crawler.rs:21`, `vex/product.rs:167/380`) despite `toml_edit` |
| go.mod | `go_mod_edit` | `module` directive read through `go_mod_edit::module_path` by `product.rs` `parse_go_mod` (single-line and block form) since #870 {{E19}} |
| NuGet | `formats::nuget::parse_open_tag` | vendored has its own XML scanner. The crawler reads `obj/project.assets.json` **only for `packageFolders`**, never `libraries`/`targets`, then enumerates the global `~/.nuget/packages` |
| Maven | `formats::maven::parse_pom` | vendored `jvm/maven_reactor.rs` `Doc::parse` and `gradle.rs`; hosted's own tag scanner; the crawler's own XML parser; `product.rs` again |

Across the repo that is **eight hand-rolled XML scanners**, 4–5 independent walks of package-lock `packages`, and 3 of Pipfile.lock categories.

### 6.4 Recurring helpers (confirmed)

- **`utils/purl.rs` contains two purl-builder families.**
  - The unchecked `build_{gem,maven,golang,composer,jsr,nuget,cargo}_purl`, used by crawlers and `vendor/*`.
  - The validating `npm_purl`, `pypi_purl`, `simple_purl`, `golang_purl`, `composer_purl` and `maven_purl`, used by inventory and VEX.
  - On top of those: `build_npm_purl` in `npm_crawler.rs`, 13 inline `format!("pkg:…")` in `product.rs`, and **78 hand-built purl strings outside `purl.rs`** in total.
- **The crawlers re-implement the validators.** `is_safe_cargo_coordinate`, `is_safe_gem_coordinate` and `is_safe_nuget_coordinate` have byte-identical bodies and equal `simple_purl`'s check; `utils::purl::maven_purl` and `vendor/maven_repo.rs` import `crawlers::maven_crawler::is_safe_maven_coordinate`. {{E37}}
- **`composer_crawler::normalize_version`** behaves exactly like `utils/composer_version::strip_leading_v`, and `formats::composer` and `upstream::composer` import the crawler copy (a `formats` → `crawlers` edge). {{E37}}
- **Layering inversion.** `canonicalize_pypi_name` lives in `crawlers/python_crawler.rs` and is imported by **29 files outside `crawlers/`** (checked on `9c43dfc`), including `lock_inventory`, `vex::discover`, `utils::purl` and `patch::redirect`. The leading PEP 508 name scan is written four times (`vendor::common::pep508_name` plus three inline copies; two of them require an alphanumeric first character). {{E39}} `Ecosystem` itself lives in `crawlers/types.rs`, while `LockfileEntry.ecosystem` is a string tag beside it.
- **The product-manifest probe table is copied three times, and has drifted.** `vex.rs:1118 PRODUCT_MANIFESTS` copies `product.rs:80-87` but lacks the csproj and gemspec probes. The `--product` help text is a third copy (up to date today). Proved on `045d7ec`: a lone `Tool.csproj` that `parse_csproj` rejects yields a bare `product_undetected` message, while a `package.json` without a version is named in it. {{E38}}
- **Test RNG.** xorshift is implemented four times.

**Dead code:**
- `lock_inventory/wired.rs` (`wired_vendor_integrity`, 221 production lines) has **no production caller** (verified); only tests use it. That matches the v5 migration note "`repair` no longer reconstructs a missing ledger from lockfiles". The module docs at `lock_inventory/mod.rs:13-15` are stale. Its only consumer, `formats::pnpm::PnpmLock::wired_integrity`, is dead with it, and it imports `vex::discover` (a `vendor` → `vex` edge). {{E41}}
- `vex/discover/deno.rs` is an empty extractor, by design: its module doc keeps per-ecosystem coverage explicit. Not a defect.

### 6.5 VEX design

- **`verify.rs` is small** (346 production lines): a hash check per record, the vendored artifact basis, and `HostedCopies`. The complexity lives elsewhere:
  - **`vex_sources.rs`** (976) merges five sources: manifest, vendor ledger, *legacy* redirect ledger, discovery refs and API-fetched records. It has 5 omission gates, 7 note codes and 3 `Basis` kinds.
  - **`vex_consumed.rs`** (1,173 lines on `4646693`, up from 596) decides "which installed copy the hosted build consumes". That covers cargo registry host-hash matching, Maven `-socket.<hex8>` dirs, the Go replacement module, and npm alias and store variants. **This is a third copy of package-manager layout knowledge** (after the crawlers and `vendor/*`), and it lives in the CLI. Its npm alias walk now duplicates the core resolver's `alias_copies` (#738), and the Maven suffix is rebuilt beside two core builders and three parsers of the same grammar. {{E40}}
  - **Discovery liveness** (`discover/mod.rs:1490-1990`, ~500 lines), including the raw-text fallbacks `vendored_wiring_in_files` and `hosted_wiring_in_files`.
- **`product.rs`** (659 production lines) only auto-detects the top-level product purl:
  - ~200 lines parse the git `origin` remote;
  - 8 manifest probes each have their own parser, and none reuses `formats::maven`, `toml_edit` or `go_mod_edit`;
  - `--product` overrides the result anyway.
- **"Wired" vs "consumed" evidence.**
  - *Wired* means a lockfile pin on an allowlisted host plus an integrity pin. `lockfile_basis_ok` lets an attestation stand with no installed bytes.
  - *Consumed* means hashing the installed copy that the wiring routes to.
  - **This is where the open "VEX attests not_affected while unpatched" bugs come from** (16 at review, about 46 on 2026-10-07; #1033 fixed the yarn PnP, pnpm-bundled and standalone deno groups, and #940 targets the same-lock group). {{E72}} Requiring consumed evidence by default is open decision E46 {{E46}}. The wired basis assumes the package manager honors the pin. Every package-manager quirk that breaks that assumption becomes a false attestation:
    - warm caches (#352);
    - a `go.work` override (#393);
    - Bun's isolated linker (#405);
    - `deno.lock` (#406);
    - `--system-site-packages` (#409);
    - Gradle locking (#396);
    - Maven mirrors (#263).
  - See the appendix for the architectural fix.
- **Standalone vs embedded `--vex`.** Generation is shared: apply, vendor and scan call the same `generate_vex_*` functions. Two problems remain:
  - Embedded runs inject bypass sets (`assume_applied`, `known_stale`, `hosted_records`, `npm_prior`), which couples VEX correctness to each caller.
  - The rendering glue is duplicated per command: dry-run skip, JSON folding, "nothing to attest", exit codes. It appears in `scan/mod.rs:360-470` and `apply.rs:790-860`, and in three variants inside `vendor.rs`.
- **Low-value paths:**
  - The pre-v5 redirect-ledger path. No command writes it (`state.rs:148`: "socket-patch v5 never writes this file"), yet it still drives `redirect_record_live`/`LedgerLiveness`, `hosted_wiring_in_files` and `HostedFileRole` (~430 lines), plus the CLI-side handling.
  - **Naming:** `vex::discover` is really the v5 *hosted-state store*. On `ea09714`, 42 files outside `vex/` import it, including six `formats/` modules (a `formats` → `vex` edge). It is not VEX-specific. {{E36}}

### 6.6 Crawlers

- **Oracles.** The npm "oracle" is the pre-parallel crawler, "kept verbatim as the equivalence oracle" (1,846 lines, test-only). Six more oracles plus `oracle_support.rs` and `maven_pom_equivalence_tests.rs` bring this to 3,007 lines. The parallel walk has shipped, so retire them.
- **`walk_pool.rs`** (338 production lines) adds a rayon pool with an fd budget, an 8 MiB stack, a 16-thread ceiling and a performance-core probe. It is justified by its benchmark table, but sized for npm only.
- **Global mode** (`--global`/`--global-prefix`) adds a branch to every crawler. The npm/yarn/pnpm/bun global-prefix probes alone are ~240 lines of subprocess spawning.
- **Python environment discovery** is ~1,060 of `python_crawler.rs`'s 1,616 production lines:
  - `VIRTUAL_ENV`, `.venv`, `venv` and nested venvs;
  - pyenv, conda, Homebrew and uv tools;
  - re-implementations of **Poetry's and Pipenv's venv-name hashing**;
  - a **fallback to global site-packages** when no venv exists.

  The open issues #327, #329, #334 and #384 are all this re-implementation diverging from the real tools. Asking the tool instead (`poetry env info -p`, `pipenv --venv`, `uv python find`) is cheaper and correct by construction.
- **Cache crawls are not project-scoped.** In local mode, cargo, go, maven, nuget and deno enumerate the **entire machine cache** as soon as a marker file exists (`cargo_crawler.rs:144-183`, `go_crawler.rs:133-158`, `maven_crawler.rs:565-607`, `nuget_crawler.rs:37-90`, `deno_crawler.rs:65-81`). Scan then sends all of it to the API. {{E05}}
  - Hosted mode can only act on lock entries, so the rest becomes "unconfirmed" noise.
  - For Maven and NuGet this crawl is the *only* discovery. Issue #265 ("Maven hosted scan pins, and VEX attests, artifacts the project doesn't depend on, because the crawler lists all of `~/.m2`") is this bug.
- **FIFO safety.** Crawler reads of project-tree files go through the FIFO-safe `utils::fs::read_regular_to_string{,_sync}` readers: `nuget_crawler.rs` (`obj/project.assets.json`), both cargo `vendor/<crate>/Cargo.toml` reads (`verify_crate_at_path`, `read_crate_cargo_toml`) and the Python `.venv` read. A FIFO there is skipped, not blocked on. `crawlers::architecture_tests::crawlers_read_project_files_fifo_safely` fails on any bare `fs::read_to_string(`, `fs::read(` or `File::open(` in crawler production code. The only allowlisted reads are the two machine-repository Maven POM reads in `maven_crawler.rs`. {{E06}}

**Are crawlers needed in hosted and vendored modes? Only as *locators*, not enumerators.**
- **Vendored:** artifacts come from the service ("backends never construct an archive locally"); the installed tree is an "optional installed location used for identity and release-variant probes".
- **Hosted:** it needs `get_site_packages_paths` / `get_gem_paths` for stale-install probes and copy lookups for VEX. Candidate discovery should be inventory-driven.
- **Enumeration (`crawl_all`)** is genuinely needed only for agent mode, `--global`, `get <name>`, and projects with no lockfile.

### 6.7 Target layout

```
core/src/ecosystem.rs       Ecosystem + tag/cli/purl-type maps (from crawlers/types.rs, vendor/path.rs)
core/src/purl/              ONE validating builder set; pep503 name; composer identity; go case-encoding
core/src/formats/<fmt>/     pure model per lock/manifest: parse → entries() (with key/pointer + resolution) → plan_hosted / plan_vendored / restore
core/src/inventory/         Inventory { instances, diagnostics, recognized, unlocked_pins }
    read.rs                 file selection over ProjectView + guarded reads + identity sweep
    classify.rs             Registry | Hosted | Vendored | Other
    views.rs                registry_view (= LockfileEntry), wiring_view (= PatchedRef/HostedPin), contest, liveness
core/src/locate/            ex-crawlers: per-ecosystem find(purl) incl. "consumed copy" rules (from vex_consumed.rs);
                            enumerate() only for project trees / --global; env/ (python, ruby, npm-global)
core/src/vex/               schema, build, time, verify, product (reusing formats)
cli: ProjectContext owns ONE Inventory; one EmbeddedVex helper
```

**Risks.** Discovery is fail-closed, security-sensitive code. The golden snapshots and the ~40K lines of end-to-end tests are the safety net, so migrate one format at a time behind them. The `CLI_CONTRACT` warning codes must not change. Scoping the cache crawls changes output for lockless cargo, Gradle and NuGet projects, so keep a fallback flag for those.

### New findings since the review

- "Is this an sbt / Mill / scala-cli build?" has six marker lists since #690 (`JVM_PROJECT_MARKERS`, `SCALA_TOOL_MARKERS`, `is_sbt_build`, `sbt_evidence::cache_roots`, `MILL_MARKERS` and scala-cli's `MILL_MARKERS` minus `.mill-version`). The agent JVM crawl gates on the narrow list before the wide one, so a scala-cli directory with only `.scala-build`, or an sbt root with only `project/build.properties`, gets no Coursier roots, while `m2_gate`, vendored `sbt::detect` and hosted `is_sbt_build` treat it as a Scala build (executed). {{E69}}

- npm alias discovery is written twice: core `NpmCrawler::alias_copies` (apply, rollback, the VEX installed lookup) and the CLI's `vex_consumed` walk (hosted VEX). They have drifted on case: on Linux, an alias dir whose name differs from the package only by case is a copy for VEX but invisible to apply (proven by execution). This is behind #851 and #852. {{E40}}

- {{E72}} October 7: VEX attested over yarn Plug'n'Play loaders, pnpm bundled copies and deno.lock npm copies. Standalone `vex` no longer does (#1033, fixing #519). The in-run `scan --mode hosted --vex` path still attests a deno project's `package-lock.json` pin (#406), and npm and vlt still emit their own bundled-copy diagnostics.
- {{E87}} Product detection has no Gradle or sbt probe, and `scan --vex` resolves the product only after writing.
- {{E89}} The pure-wheel rule is written four times: lock inventory and ledger recovery use `ends_with("-none-any.whl")` instead of the shared `wheel_platform_from_filename` (so the #1053 fix won't reach them), and recovery re-parses the uv.lock unit with a string scanner that paired a hashless pure wheel with the next wheel's hash (executed twice).
- {{E91}} PyPI tool-lock precedence is written twice since #1044: the lock inventory keys on "the lock yielded entries", the vendored router on presence. With a package-less `poetry.lock` or `pdm.lock` beside a pinned `requirements.txt`, scan offers a package that vendored then refuses with `pypi_poetry_lock_package_missing` (executed twice).
- {{E90}} Which gem homes Bundler loads has two answers since #1002: the stale guard uses `bundler_install_homes`, while `vex` (and agent `apply`) still use `get_gem_paths`, which keeps the `gem env` homes under an explicit Bundler `path`. An unused, unpatched system-home copy then blocks standalone `vex` from attesting (proven by execution).

- One rule now picks the live Bundler lock: lock inventory and VEX discovery follow Bundler's loaded pair (`gems.rb` → `gems.locked`, a stale `Gemfile.lock` twin ignored), as hosted, vendored and the crawler do through `LoadedManifest::pair` (#750). {{E56}}

---
_Generated by [Claude Code](https://claude.ai/code)_
