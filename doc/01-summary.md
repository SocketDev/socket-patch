> [!NOTE]
> [agent] **This is a living document.** It is the October 2026 architecture review of the socket-patch CLI, kept current as we work through the code. The scheduled routines rewrite a section when a refactor lands or they find a new problem. Every `E…`/`C…` reference shows that problem's live status, taken from the register.
>
> {{PROGRESS}}
>
> - **Register:** the [first comment below](https://github.com/SocketDev/socket-patch/discussions/560#discussioncomment-18716819) tracks every problem with its issue and status.
> - **Detail:** Parts 2–9 follow as comments, and they are living too.
> - **Log:** after Part 9, every routine run posts an entry.
> - **Work items:** [issues labelled `arch-audit`](https://github.com/SocketDev/socket-patch/issues?q=label%3Aarch-audit) · [refactoring PRs labelled `arch-refactor`](https://github.com/SocketDev/socket-patch/pulls?q=label%3Aarch-refactor)
> - **Steering:** reply here or on an issue. The routines read maintainers' replies on their next run.
>
> - **October 7 campaign:** a one-day pass fixed the audit's critical defects and its duplicated business logic, one draft PR per seam, each deleting the duplicate copies it replaces: credentials redaction (#1026, C59), trust signals (#1029, merged; C61), JVM layout (#1032, merged; E77), VEX attestation over PnP/bundled/deno copies (#1033, merged; E72), one target grammar (#1034, merged; C62), the supersede lifecycle (#1035, merged; E71), paths and repo roots (#1038, merged; C64), an atomic takeover (#1039, merged; E70), `.socket` containment (#1042, merged; C60), command cycles and remedy text (#1043, merged; C65), governing locks (#1044, merged; E75), `PurlKey` (#1045, merged; C63), test hygiene (#1046, merged; C66), vendored liveness (#1050, merged; E74), the yarn grammar (#1057, merged; E08/E76) and one pinned check (#1058, merged; E73). Main went green again with #1016 (stale digest entries); #1018 adds a merge queue and per-SHA push concurrency so it stays green (C67). On 2026-10-08 a maintainer closed about 40 refactor issues as not planned, folding most into their trackers' "Consolidated work" checklists (for example #727 into #793, #895 into #894) and deferring the rest (#649, #706, #770, #773, #871). Maintainer decisions still open: #704 exit policy, #966 Q2 (embedded `--vex`), C34, E44 (#1200, the napi addon and in-memory engine), E45 (#1130), E46 (#1099) and E47 (#1156, support tiers).
>
> _Rendered {{UPDATED}} from `doc/` on the [`arch-audit/ledger`](https://github.com/SocketDev/socket-patch/tree/arch-audit/ledger) branch. The original snapshot is in `review/2026-10/` on the same branch._

# Architecture review of socket-patch v5: what to cut, combine, refactor and simplify

> **Originally written against** `main` @ `2463257` ("feat!: consolidate the v5 patching workflow (#277)") on 2026-10-01. Since then, sections are updated as the code changes, and each part says when it was last checked against `main`.
> **Method:** a read-only review split into seven areas: the CLI layer, hosted mode, JS lockfiles, vendored backends, discovery/VEX, core infrastructure and agent mode, and tests/CI/docs. Every area was measured with scripts: production and test lines are split at each file's inline `#[cfg(test)] mod`, and function lengths come from a brace-matcher that understands string literals. The highest-impact claims were then re-checked by hand against the source and a debug build. The 88 issues open at the snapshot were cross-referenced to architectural causes (Appendix A); on 2026-10-07 about 300 are open.
> **Layout:** this post is the executive summary. The detailed findings, each with `file:line` evidence, are in the comments below:
> - Part 2: CLI layer and UX
> - Part 3: hosted mode
> - Part 4: JS lockfiles
> - Part 5: vendored mode
> - Part 6: discovery and VEX
> - Part 7: core infrastructure and agent mode
> - Part 8: tests, CI and docs
> - Appendix: open-issue analysis and methodology
>
> All LOC numbers are measured or estimated as stated. Savings estimates come from the per-area reviews and overlap somewhat.

---

## TL;DR

1. **socket-patch is a product matrix implemented cell by cell.** The matrix is **3 modes × 9 ecosystems × ~25 package-manager and lockfile generations × 6 operations** (discover, apply/wire, verify, attest, revert, mode-takeover). There is no shared abstraction on any axis:
   - no lockfile codec;
   - no mode backend;
   - no vendor-backend trait;
   - no hosted-rewriter trait;
   - no single inventory.

   Each cell is hand-written text surgery. As a result, the same file format is parsed and spliced **two to five times** with different rules, and those rules have already drifted. For example, there are five different CRLF policies for the npm lockfile family alone.

2. **Most of the open bug backlog has one shape: "reported success, but the build consumes unpatched code".** Of the 88 issues open at the snapshot, roughly 29 were a success or a `not_affected` VEX attestation that the installed bytes don't back up (about 46 such false attestations are open on 2026-10-07; #1033 and #940 address the largest groups). Another 15 were discovery missing what the package manager actually installed. The root cause is architectural:
   - the tool **re-implements package-manager behavior** (install layouts, venv naming, config layering, resolution precedence);
   - it then **reports success based on its own model of what the package manager will do**;
   - every package-manager release or config knob it doesn't model becomes a silent false negative.

3. **Support breadth has outrun the architecture.** The long tail is disproportionately expensive:

   | Long-tail target | Cost |
   |---|---|
   | vlt | ~6.5K production lines, ~22K total, ~123 CI jobs per push |
   | JVM (Maven/Gradle) | ~9K production lines, 22 of the 88 open bugs |
   | `bun.lockb` | ~2.8K production lines for a format Bun itself replaced |
   | vendored pnpm 7/8 | 1.85K lines, ~96% a copy of the v9 backend |

   **A support-tier policy would let the core get simpler.**

4. **The code is large for what it does, and much of the size is duplication and scaffolding.**
   - ~134K lines of production code on `9c43dfc` (~118K at the snapshot, plus 35K comment lines then).
   - ~450K lines of tests.
   - Nine functions over 500 lines; `run_scan` alone is 1,540 (on `045d7ec`).
   - A 21.9K-line `redirect/mod.rs` on `db83f01` (17.5K at the snapshot). {{E30}}
   - Two hosted orchestrators kept equal by parity tests.
   - Four discovery systems.
   - Nine different revert mechanisms. {{E24}}
   - Two JSON envelope shapes, 27 global flags silently accepted by every command, and 156 documented error codes.

   **We estimate 25–35K production lines (20–30%) and 50K+ test lines could go.** Roughly 20K of that comes from consolidation that keeps every capability; the rest comes from the support-tier and product decisions in §5.

5. **The user model is harder than it needs to be.** It has:
   - 9 verbs, 2 hidden subcommands, 2 aliases and 3 hidden flag spellings;
   - defaults that change with unrelated flags;
   - `scan` writing lockfiles by default;
   - mode that is not project state: a plain `scan` performs the documented "mode takeover" and switches vendored npm, Cargo, Go, PyPI and Gradle-built Maven packages back to hosted (made atomic in #1039, E70);
   - `remove`, `rollback` and `vendor --revert` as three ways to undo.

   A seven-verb model (`scan` read-only, `fix`, `undo`, `sync`, `check`, `list`, `vex`) with mode inferred from the project would cover everything (§4).

6. **There are a few real defects to fix now** (§1), regardless of any refactor:
   - no HTTP timeouts on the main API client (fixed, #581);
   - a ledger-loss bug in the vendored→hosted takeover (fixed, #708);
   - a planted-binary spawn (fixed, #617);
   - a comment-blind NuGet config reader (fixed, #597);
   - a stale digest ratchet that turned `main` red for every PR (fixed, #1016; a merge queue follows in #1018).

   The October 7 audit added credential leaks (C59), `.socket` containment (C60) and the non-atomic takeover (E70); each has a PR. `SOCKET_FORCE` (#615, PR #1021) and the `bun.lockb` registry override (E02, fixed by #574) are no longer open defects.

---

## 0. The numbers

| | Value |
|---|---|
| Production code (non-blank, non-comment) | **134.5K lines** in `socket-patch-core` + `socket-patch-cli` on `9c43dfc` (2026-10-06; the same script gives 117.8K at the snapshot, which the review reported as 117.6K + 34.8K comment + 9K blank). The growth is mostly the Gradle landing (#646) |
| Inline `#[cfg(test)]` code in `src/` | ~228K lines on `9c43dfc` (~197K at the snapshot) |
| Integration tests (`crates/*/tests`) | ~298K lines in **240 separate test executables** in core + CLI (37 core, 203 CLI: top-level files plus 12 directory binaries; recounted at `f3c6313`, 2026-10-09; 235 at `b762f41`; ~296K at `05ecc6e`; 224 and ~283K at `9c43dfc`; ~255K at the snapshot) |
| Test : production ratio | ~2.8 : 1 overall; ~7 : 1 for the CLI crate |
| Largest file | `patch/redirect/mod.rs`: 23,913 lines at `f3c6313` (2026-10-09; 22,272 at `b762f41`; 21,936 at `db83f01`; 7.6K production, 14.3K inline tests; 17,517 at the snapshot, 6.2K production then) |
| Functions > 200 / > 500 lines | 74 / 11 at `1c6c509` (61 / 9 at the snapshot: `run_scan` 1,540 on `045d7ec`, now 1,577; `rollback::run` 984, `vendor_records_reusing` 962, `run_redirect_selected` 836, `remove::run` 797, `get::run` 635, memory `engine` 604, …) |
| CLI surface | 9 visible + 2 hidden subcommands; 57 visible long flags; 27 globals on every command; 43 env bindings (84 `SOCKET_*` names in source); 156 documented `errorCode`s; ~570 code-like strings in source |
| `--help` | 150–219 lines per subcommand; `list --help` lists 27 options, most of which do nothing for `list` |
| CI per push | ~516 jobs; the CI workflow alone is 237 jobs and 348 runner-minutes; Windows `test` is the 28-minute critical path |
| `CLI_CONTRACT.md` | 460 KB (459,861 bytes) at `f3c6313` (2026-10-09; 423 KB at `b762f41`, 2026-10-08; 417 KB at `431b818`; 415 KB at `c5be5d1`, 332 KB at the snapshot); the longest *line* is 12,077 characters at `c5be5d1` |
| Open issues | 287 on 2026-10-09 at 03:40Z (180 `bughunt`, 80 `arch-audit`; about 320 on 2026-10-08; 322 on 2026-10-07). At the snapshot: 88, filed mostly in the last 5 days by a bug hunt; JS 26, JVM 22, Python 18, Go 6, Cargo 5, NuGet 5, Ruby 3, Composer 3 |
| PR size | Recent squash merges of +53K, +85K and +94K lines |

---

## 1. Fix now (small, independent of any refactor)

| # | Defect | Evidence | Fix | Status |
|---|---|---|---|---|
| 1 | **Zip member inflate on committed artifacts** (fixed) | `zip_bytes_match_after_hashes` now streams each member through the Git SHA-256 reader with an 8 KiB buffer and checks the declared length against the bytes read, instead of inflating it into a `Vec` (#587). The maintainer ruled that this data is trusted not to be too big, so the goal was streaming, not a cap. | The three archive caps (512/256/128 MiB) remain; see C15/C21. | {{C01}} |
| 2 | **No HTTP timeouts on the main API paths** (fixed) | Both `ApiClient` reqwest clients now take `api::retry::ApiTimeouts` (10 s connect, 60 s idle read), and a stalled JSON body reports `ApiError::Network` (#581). Blob/diff downloads still have **no retry**. | One retry and timeout primitive for every HTTP path (Part 7). | {{C02}} |
| 3 | **Vendored→hosted takeover drops the ledger entry on a drift-keep** (fixed) | `vendored_takeover` now checks `revert_keeps_wiring` (`kept_artifact`, drift skips, residual references) after each revert and refuses the purl while keeping the ledger entry, like every other revert caller (#708). | The takeover still calls `dispatch_revert_one` directly rather than `VendoredBackend` (Part 2.4). | {{C03}} |
| 4 | **Planted-binary spawn** (fixed) | Vendored Hatch now resolves `hatch` through `utils::process::resolve_tool_with` and spawns it with `command_for`, so a `hatch` planted in the scanned repo no longer runs (#617). On `0d302dc` no production bare-name `Command::new("<tool>")` remains. | Keep every spawn on `resolve_tool` (Part 7). | {{C04}} |
| 5 | **Comment-blind NuGet config reader in hosted mode** (fixed) | Hosted routing and its splice anchors now read `nuget.config` through `formats::nuget::parse_config`, so commented-out `<add key>` entries are ignored (#597). The vendored `nuget_feed.rs` reader remains. | Move the vendored reader onto `formats::nuget` too (E10, #594). | {{E01}} |
| 6 | **`SOCKET_FORCE` is bound to three unrelated flags** (decided) | `vendor --force`, `apply --force` and `self-update --force`. Exporting it to force a self-update also forces `apply`/`vendor` past hash checks. | Decided (#615): the `SOCKET_FORCE` binding is removed and `--force` is flag-only; the change is in PR #1021. | {{C05}} |
| 7 | **`bun.lockb` registry override** (fixed) | The duplicated npm tarball URL and `NPM_REGISTRY` spellings are now one helper, and vlt's two `registry_base` copies are one (#574). The format-1 URL that `bun_lockb.rs` synthesizes is lock semantics and is never fetched, so that part is not a defect. | — | {{E02,E03}} |
| 9 | **Credentials leak to logs, `--json`, telemetry and the patch host** (October 7) | Hosted Composer keeps `transport-options` auth (#399); grant tokens and URL userinfo appear in warnings and debug output; the VEX product `@id` carries git-remote credentials. | One `utils::redact` for every URL shown or logged (PR #1026). | {{C59}} |
| 10 | **`.socket` links and agent writes escape the project** (October 7) | The symlink guard starts below `.socket` and guards deletes only (#887); `get` writes inline blobs through a planted link (#726); agent writes follow links out of the package. | One containment helper for every write (#1042, merged; #887 closed). Agent-mode manifest and blob writes under a linked `.socket` still follow the link, which #1042 records as a known gap. | {{C60}} |
| 11 | **The vendored→hosted takeover reverts before it plans** (October 7) | A refused rewrite leaves the package patched in neither mode, and `--dry-run` predicts success. | Stage the revert, rewrite against the overlay, commit both together (PR #1039). | {{E70}} |
| 8 | **Repo hygiene** | A stray `.github/actions/actions/cache/<sha>/.vscode/launch.json` (accidentally committed in #358); 2 dead CI path filters (CI janitor); 39 references in 20 files to a "DESIGN §x.y" document that isn't in this repository. The README now says plainly that its installer selects the latest release (verified on `045d7ec`). | Delete or fix. | {{C08}} |

---

## 2. The big picture: why the code is the size and shape it is

### 2.1 No abstraction on any axis of the matrix

| Axis | What exists today | What's missing |
|---|---|---|
| **Format** (package-lock, pnpm, yarn, bun, vlt, uv, poetry, pdm, pipenv, pylock, requirements, Cargo, Gemfile, composer, go.mod, NuGet, pom/Gradle) | A half-finished `formats/` layer. Its module doc promises "entry grammar, key rules, version sniff and planners" per format; only pnpm, cargo, gem, composer and bun are partly there. | One codec per format: `parse → model (with byte spans) → entries() / wired_refs() / splice(edits)`, used by **every** mode. Today package-lock has 4 entry walks, yarn has 5 copies of a `split("\n\n")`+regex grammar beside the shared block scanner, there are **8 hand-rolled XML scanners** (no XML crate), Cargo.toml has a regex scanner *and* `toml_edit` inside one rewriter, and poetry/pdm lock code are near-twins. |
| **Mode backend** (hosted/vendored/agent) | Three booleans in `run_scan`, referenced 91 times; JSON and human arms that each re-dispatch all three modes. | `trait ModeBackend { plan, consume, revert, verify }`, with rendering only at the end. |
| **Vendored backend** (per ecosystem) | Naming conventions plus two macros (`vend!`, `vend_installed!`). The ecosystem list is enumerated at **16 production sites**. Nine different revert mechanisms (~3.5K lines). | `trait VendorBackend` + a registry + **one generic splice-record revert engine**. The JVM planner (`jvm/mod.rs`) already is this design; copy it. |
| **Hosted rewriter** | Free functions in a hand-wired `Vec<Box<dyn Fn>>`. Results flow through a `RewriteResult` with **27 per-ecosystem uuid sets** (20 at the review) and a 25-outcome `confirm()` if-chain. {{E31}} **Eight parallel tables** must be edited to add an ecosystem. | `trait HostedRewriter { drives(), rewrite() -> Outcome { per_dep: Map<Uuid, DepStatus> } }` |
| **Inventory** | **Four discovery systems:** crawlers, lock inventory, wiring discovery (`vex::discover`) and a ledger supplement. They are merged by fabricating `CrawledPackage`s with a fake `node_modules/<name>` path *for every ecosystem*. | One `Inventory { instances: purl × declared_in × resolution (Registry/Hosted/Vendored) × installed_at }`. Crawlers become *locators*. |
| **Configuration** | Parsed flags are written back into process env (`args.rs:559 apply_env_toggles`) so core can read them. Its doc comment records a bug where telemetry sent a Bearer token to the wrong host. This also forces **993 `#[serial]`** test attributes (plus 185 in `src`). {{C10}} | An explicit `RunCtx { config, client, telemetry, lock }` built once in `main`. |

**Layering is inverted and cyclic** (production `crate::X::` reference counts):

| From → To | Refs | Reverse | Refs |
|---|---:|---|---:|
| redirect → vendor | 49 | vendor → redirect | 10 |
| vex → redirect | 16 | redirect → vex | 5 |
| redirect → formats | 19 | formats → redirect | 5 |

Other examples:
- 50 non-vendor files import `crate::vendor::*`, so `vendor/` has become the codec library.
- `Ecosystem` and `canonicalize_pypi_name` live in `crawlers/` (the latter is imported by 29 files).
- The "pure" `formats/pnpm/hosted.rs` imports the hosted engine's `RewriteResult`.

**The CLI holds engine code.**
- `vendor_records_reusing` (962 lines) is the vendored orchestrator.
- `run_redirect_selected` (836) is the disk hosted orchestrator, written a second time in core's `hosted/memory` (~1.3K lines of orchestration).
- `ecosystem_dispatch.rs` is 816 lines of crawler fan-out.

**Commands call each other as libraries.**
- There is a `get` ↔ `scan` cycle.
- `get` builds a fake `ApplyArgs` and calls `apply::run_locked`.
- Arguments round-trip GlobalArgs → `DownloadParams` → `..GlobalArgs::default()`. On `045d7ec` the reset fields are inert: the nested apply reads none of them except `offline`, which `get` and `scan` refuse up front.

### 2.2 The correctness model: "wired" is treated as "consumed"

The tool decides that a patch is applied, and VEX marks it `not_affected`, mostly from **what it wrote**. It does not check **what the package manager will install**:
- `PatchedRef::lockfile_basis_ok` lets an attestation stand with no installed bytes;
- agent mode patches the copy *it* located;
- hosted mode confirms the pin *it* spliced.

Every package-manager behavior outside that model becomes a silent false negative. The open backlog, by title, includes:
- warm caches shadowing the patch (#352);
- `go.work` replaces overriding go.mod (#393);
- Bun's isolated linker (#405);
- `deno.lock` taking precedence over package-lock (#406);
- `--system-site-packages` (#409);
- Gradle dependency locking (#396);
- Maven mirrors (#263);
- `BUNDLE_GEMFILE` (#390);
- `gems.rb` beside `Gemfile` (#341);
- cargo reusing cached rlibs (#387);
- npm aliases (#356) and `inBundle` copies (#325);
- NuGet `globalPackagesFolder` (#397).

**Patching each case individually makes the model ever larger.** Structural options, which can be combined:

1. **Verify what the package manager consumes, not what we wrote.**
   - Make the VEX default require *consumed* evidence: hash the copy the package manager actually resolved.
   - Downgrade wired-only evidence to "omitted, with a note", or put it behind an explicit `--allow-wired-basis` flag.
   - A false `not_affected` is worse than no statement, because the whole point of VEX is that scanners trust it.
2. **Ask the package manager instead of re-implementing it** wherever possible:
   - `poetry env info -p`, `pipenv --venv`, `uv python find`;
   - `npm query`/`npm ls --json`, `pnpm list --json`;
   - `go list -m -json all`, `cargo metadata`;
   - `mvn dependency:list`, `dotnet list package --include-transitive`.

   Today the crawlers re-implement Poetry's and Pipenv's venv-name hashing, npm/pnpm/yarn/bun global-prefix discovery, and the pnpm store layout, and those re-implementations are the source of the agent-mode discovery bugs (#327, #329, #334, #362, #366, #373, #384).
3. **Fail closed on unmodeled configuration.** Detect the knobs that change resolution (`go.work`, `gradle.lockfile`, `BUNDLE_GEMFILE`, `virtualStoreDir`/`enableGlobalVirtualStore`, `install-strategy=linked`, `repositoryPath`/`globalPackagesFolder`, mirrors) and refuse or warn instead of reporting success.
4. **Make "verify after install" a first-class step** (`socket-patch check`) that CI runs after the package manager, with a non-zero exit when what was installed doesn't match what was wired.

### 2.3 Hosted rollback rebuilds data it threw away

v5 dropped the hosted ledger, so `rollback`/`remove` reconstruct the original lock entries **from the network**. That is ~7.4K production lines across about nine upstream sources, including a Socket endpoint that may download the whole upstream tarball. Meanwhile, every rewriter already computes `FileEdit { original, new }`, and production discards `original`, except in a Composer hint.

Failure modes:
- refused when offline;
- **private registries and mirrors are ignored** (npm restore always uses the public registry or `SOCKET_NPM_REGISTRY`);
- heuristic re-derivation of uv/poetry/pdm spelling;
- `bun.lockb` always refused.

That is 13 open rollback/takeover bugs (#271, #331, #382, #385, #407, #408, #410, #411, …).

**Options:**
- **(a)** Keep the originals in a tiny content-addressed sidecar, so rollback is byte-exact and offline. That is the same "record → splice back" model vendored mode uses.
- **(b)** Restore only where the original is a pure function of registry data (npm/pnpm/bun-text `resolved`+`integrity`, cargo `cksum`, go.sum, gem/composer/nuget hashes; ~2.2K lines), and refuse the rest with an exact `git checkout -- <file>` or relock command.

Either removes ~3.3K production lines.

### 2.4 Machinery that compensates for the per-package call model

Vendored backends are invoked **once per package**, and each call re-reads, re-parses and durably re-writes the same lockfile and ledger. Several mechanisms exist to make that fast and crash-safe again:
- `group_commit.rs` (1,059 lines), a process-wide virtual filesystem that intercepts every `utils::fs` read and write;
- `durability.rs`;
- `prestage.rs`;
- `api/vendor_prefetch.rs`;
- 22 process-global `ParseMemo` statics;
- `ledger_snapshots.rs`, the schema-v2 delta encoding added because whole-file snapshots bloated ledgers by tens of MB.

Together that is **~3K production lines**. Backends written as **pure batched planners** (`plan(view, pkgs) -> {writes, records}`, as `jvm/` already does) would retire most of it.

### 2.5 Process smell: nothing gets deleted

Several patterns show code that outlived its purpose:
- **Refactor oracles kept forever:** the verbatim 1,846-line old npm crawler, six more crawler oracles, 2.6K lines of redirect equivalence tests and 252 KB of goldens.
- **Parity suites** that exist only because two orchestrators exist.
- **Covgap tests:** 402 tests (26.9K lines), 136 of them asserting human text.
- **Exact-sentence assertions:** 328 of them. The output-polish PR touched 65 test files.
- **Dead flags and vestigial abstractions:** `--vendor-source` (one valid value), `VendorSource`/`PackageSource` (one variant each), `PatchSources::mem_blobs` (never `Some`; {{C23}}), `lock_inventory/wired.rs` (no production caller), pre-v5 redirect-ledger readers.
- **History in reference docs:** 177 `v5.0` annotations in the contract.
- **Very large squash merges:** +53K, +85K and +94K lines.

**Suggested norms:**
- delete the oracle in the PR that lands the refactor;
- comments explain *why*; history lives in git and PR descriptions, and the CHANGELOG is written only when a release is cut;
- generate reference docs from code;
- cap PR size, or at least split mechanical moves from behavior changes.

---

## 3. Ranked recommendations

**C** = cut, **M** = combine/merge, **R** = refactor, **S** = simplify. LOC are production lines unless noted. Risk: L/M/H.

| # | Type | Recommendation | Est. savings | Risk | Detail | Status |
|---:|:--:|---|---|:--:|---|---|
| 1 | M | **One codec per format in `formats/`** (package-lock → yarn → XML for NuGet/Maven/Gradle → requirements → Cargo.toml → Pipfile → pnpm single grammar), shared by hosted, vendored, upstream, inventory and VEX. Neutral types (`Edit`, `Warning`, `LockfileEntry`) move into `formats`, which breaks the cycles. | 3–5K prod; **removes the CRLF/indent/comment/divergent-gate bug class** | M | Parts 3, 4, 5, 6 | {{E07-E20}} |
| 2 | R | **`VendorBackend` trait + registry + one generic splice-record revert engine**, with backends as batched pure planners (the JVM pattern). Legacy ledger kinds are adapted at load time. | 6–8K prod (incl. ~2K of the group-commit/prestage/memo machinery) | M | Part 5 | {{E21,E22,E23,E24,E25,E27}} |
| 3 | M | **One `Inventory`** fusing lock inventory, wiring discovery and the ledger supplement. Crawlers become project-scoped locators, with no whole-machine cache enumeration (`~/.m2`, `~/.nuget/packages`, `$CARGO_HOME`, `GOMODCACHE`). Rename `vex::discover` to `inventory::wiring`. | 2–3K prod; fewer API calls; fixes #265-class bugs | M-H | Part 6 | {{E05,E36,E37,E38,E39,E40,E41}} |
| 4 | C/S | **Hosted rollback: an originals sidecar, or restore only pure-function formats** and refuse the rest with an exact remedy | ~3.3K prod, ~2K test | M | Part 3 | {{E33,E45}} |
| 5 | M | **One hosted pipeline for disk and memory** (`DiskSnapshot` → `MemoryProject` → `redirect_root(view, selected, api, hooks)`); parity suites become ordinary tests. **Decide the napi addon's fate**: if depscan adopts it, delete the TS rewriters; if not, delete the addon, `hosted-bundle` and the memory-only branches. | 0.8K, or up to 4.8K prod + 4.6K test | M | Part 3 | {{E32,E44}} |
| 6 | R | **Split `run_scan` into discover → select → consume → render**; a `RunCtx` built once; a service layer in core so commands stop calling each other; `HostedRewriter` + `Outcome`; mechanical split of `redirect/mod.rs`. | 1.5–2.5K prod | M | Parts 2, 3 | {{C10,C11,C12,E30,E31}} |
| 7 | S | **Command model** (§4): read-only `scan`, `fix`, `undo` (folds `remove` + `rollback` + `vendor --revert`), `sync`, `check`; mode inferred from project state; per-command flags; delete deprecated spellings. | 1.5–2.5K prod | M (MAJOR) | Part 2 | {{C34}} |
| 8 | S | **One JSON envelope and error shape** (every top-level `error` is `{code, message}` since #1027; {{C14}}); **a typed code registry** (`enum Reason × Ecosystem`) that generates the contract's code tables, with a freshness test. | 0.3–0.6K prod; fixes ~43 undocumented codes (re-measured on `9c43dfc`) and 1 phantom | L-M (MAJOR) | Parts 2, 8 | {{C13,C14}} |
| 9 | C | **Support tiers** (§5): `bun.lockb` write support → refuse with remedy; vendored pnpm 7/8 → refuse (or a dialect of v9); vlt pre-1.0 encodings; Maven single-POM backend retired; single poms go through the `jvm/` planner (decided #973). | 5–8K prod, 8–12K test | M (product) | Parts 4, 5 | {{E26,E47}} |
| 10 | C | **Retire `--download-mode` and the diff path** (decided #792, v5): `diff` re-downloads every blob anyway on a cold cache; delete the diff machinery, the flag and `qbsdiff`. | ~0.4K prod, 1K test, −1 dep | L | Part 7 | {{C25}} |
| 11 | C | **Delete verified dead/vestigial code:** `--vendor-source`, `VendorSource`, `PackageSource`, `vend_installed!`, `mem_blobs`, `lock_inventory/wired.rs`, dead vlt ledger helpers, `save_redirect_state` + its group-commit entry, the empty Deno extractor, the `switched_off("group_commit")` oracle path. | ~1K prod, ~1K test | L | Parts 4–7 | {{E28,E41,C23}} |
| 12 | M | **Utility consolidation:** one HTTP retry/timeout primitive; one validated purl builder family (42 hand-built `format!("pkg:…")` and 24 prefix checks in production code); one digest/SRI helper set (fixing the `sha256_hex` name collision: one copy validates, three compute); one line-ending policy; one env-truthiness vocabulary (there are three); one UUID grammar (there are four). | 1–1.5K prod | L | Parts 4, 7 | {{C15,C17,C18,C19,C20,E16}} |
| 13 | C | **Embedded `--vex`** (15 flag instances on 3 commands, ~600 lines of glue, plus bypass sets that couple VEX correctness to each caller) → `fix && vex -O`. | 0.6K prod | L (MAJOR) | Parts 2, 6 | {{E42,C05}} (spellings half removed, #1031) |
| 14 | S | **Simplify per-package-manager auto-config:** npm `allow-remote` (re-implements npm's `ini` and config layering, ~900 lines), pnpm `trustLockfile` (~450; three open corruption bugs), the vlt warm-tree heal (installed-tree surgery in a lockfile-only mode), parallel rewriter groups (benchmark them or drop them). | 1–1.5K prod | M | Part 3 | {{E34}} |
| 15 | C | **Self-update:** keep the binary swap and the notifier (decided #983); harden it: retry, stall timeout, streaming download, live post-release test. **Telemetry:** one `track(Event)` + a shared client instead of 19 wrappers and ~45 token/org call sites. | ~0.3K prod | L | Parts 2, 7 | {{C22,C36}} |
| 16 | M | **Tests:** 207 → ~25 binaries (needs `RunCtx` first, to drop the env-mutating `#[serial]`); a `socket-patch-test-support` crate (`binary()` is defined in 103 files, `git_sha256` in 86, 14 divergent `scrub_socket_env`, and 10 test files with no env scrub at all); retire the oracles; triage covgap; snapshots instead of 328 sentence assertions. | 15–25K test lines; minutes off the Windows critical path | M | Part 8 | {{C30,C31,C32,E35}} |
| 17 | C | **CI:** de-instrument the coverage legs and drop the LTO `docker-base` build where it gates nothing, **keeping** the gating Linux tests and the per-PR Docker e2e on PRs; PR e2e 157 legs → ~50 boundary versions; reusable compat workflow; no per-leg compiles; required checks plus a merge queue (#1018). | ~150 fewer jobs per PR | L | Part 8 | handed off to the CI janitor; merge queue {{C67}} |
| 18 | S | **Docs:** a generated CLI reference plus ≤300 lines of contract prose; move ecosystem narratives into `ecosystems.md` and version history into `docs/migrating-to-v5.md`; decouple `docs/testing` from validation scripts. | — | L | Part 8 | {{C33}} |

**Estimated total:** ~25–35K production lines (20–30%) and 50K+ test lines. About 20K is pure consolidation (recommendations 1–3, 6, 8, 10–12, 14); the rest depends on the tier and product decisions (recommendations 4, 5, 9, 13; the self-update half of 15 was decided as keep, #983). Agent mode stays for every ecosystem (#1000), so its ~10K is not on the table. The per-recommendation numbers overlap: for example, recommendation 1 shares work with 2 and 9.

---

## 4. User experience: a simpler model

Today a new user has to learn:
- **three modes**;
- **mode-dependent meanings** of positional PATHs (project directories in hosted/vendored, installed-path globs in agent);
- **defaults that shift with unrelated flags:**
  - `scan --prune` and `scan --global` become report-only;
  - `get --save-only` and `get --global` become agent mode;
  - so `get -g x` patches files in place while `scan -g` only reports;
- **`scan` mutating lockfiles by default;**
- **three ways to undo:** `remove`, `rollback`, `vendor --revert`;
- **two GCs that are different things:** `repair` (alias `gc`), filed under "Agent mode" in help but also repairing vendored artifacts, and `scan --prune`;
- **27 options on every `--help`**, most of them no-ops for that command;
- **two JSON shapes and two styles of usage error.**

**Proposed command model:**

| Command | Does | Replaces |
|---|---|---|
| `socket-patch scan` | **Read-only** report: available patches, the project's current mode and state, stale or unverified wiring. Safe in any CI step. | `scan --dry-run`, `list` partially |
| `socket-patch fix [TARGET…] [--mode hosted\|vendored\|agent]` | Applies patches. No target means all; a target can be a package, PURL, CVE, GHSA or UUID. **Mode is inferred from project state** (hosted pins, vendor ledger, agent manifest); `--mode` chooses it for a fresh project, and **switching an existing project's mode requires `--mode` explicitly**. | `scan` (write), `get`, `vendor` (eject) |
| `socket-patch undo [TARGET…] [--keep-state\|--forget]` | One reversal engine for every mode. | `rollback`, `remove`, `vendor --revert` |
| `socket-patch sync` | After-install step for agent mode: re-apply, repair artifacts, prune. | `apply`, `repair`/`gc`, `scan --prune` |
| `socket-patch check` | Every read-only verifier, including "does what the package manager installed match what we wired" (§2.2). Non-zero on drift. | `vendor --check`, `apply --check` |
| `socket-patch list`, `socket-patch vex` | Unchanged; VEX defaults to consumed evidence. | |

On top of that:
- per-command flags only, so a global flag that a command ignores becomes an error;
- one JSON envelope with a typed `errorCode`;
- a short, generated reference.

This is a MAJOR change. Because v5 is still a prerelease, **now is the cheapest time to make it.**

---

## 5. Support tiers (product decisions needed)

| Candidate | Prod / test LOC | Signal | Proposal |
|---|---|---|---|
| `bun.lockb` writing (hosted + vendored) {{E47}} | ~2.7K / ~3K + 1.6K CLI | The repo itself labels it "binary, legacy"; Bun ≥ 1.2 writes text `bun.lock`. The codec writes a private `sktpnrm` marker into an unused slot of the user's lockfile. | Refuse, with the remedy `bun install --save-text-lockfile --frozen-lockfile --lockfile-only`; keep a ~300-line read-only parser if inventory needs it. |
| Vendored pnpm lockfile 5.4/6.0 (pnpm 7/8, both out of maintenance) | 1.85K / 3.2K | ~96% a copy of the v9 backend. The absolute specifier means `--frozen-lockfile` only passes at the original checkout path, which undercuts the point of vendoring. | Refuse with "re-lock with pnpm ≥ 9", or merge it as a `PnpmDialect`. |
| vlt | ~6.5K / ~6.1K + ~9.3K CLI; ~123 CI jobs per push | A very new package manager; supports pre-1.0 RC encodings. Architecturally the cleanest JS format (one codec). | Drop the pre-1.0 encodings now. Gate vendored vlt (the dir-artifact backend + heal, ~3K) on telemetry. Move the vlt sweeps to nightly. |
| JVM: two Maven backends + Gradle | ~7.5K vendored + ~1.5K hosted/crawler | 22 of the 88 open issues (25%), mostly XML text surgery and resolution semantics (mirrors, locking, checksums, multi-module). | Merge `maven_repo.rs` into `jvm/` (`Shape::Single`); one XML scanner; scope the crawler to project dependencies, not all of `~/.m2`. Consider labelling hosted Maven/Gradle "beta" until the backlog is under control. |
| Agent mode overall | ~6.4K CLI + ~3.5K core | v5 defaults to hosted. ~15 open issues (appendix category B) come from re-implementing package-manager install layouts, mostly in agent mode. | Decided (#1000): keep agent mode for every ecosystem for now (status quo). Layout bugs are fixed one at a time; asking the package manager for layouts (§2.2) is a separate, unadopted proposal. {{C55}} |
| In-memory engine + napi addon {{E44}} | ~4.5K / ~4.7K | `"private": true`, never released, built and smoke-tested on every PR. The contract names a future GitHub App as its caller (#1029). | Decision #1200: make it the one hosted pipeline if it is a supported product; otherwise delete it. |
| Self-update binary swap | ~1–2K / 3–5K | Only the standalone channel can use it, and it is the only updater for the Windows zip, which has no installer. | **Keep (decided #983).** Self-update is a first-class update path and the only updater for the Windows zip; improve it rather than remove it. {{C36}} |

---

## 6. Suggested sequencing

- **Phase 0, this week: no behavior change except bug fixes.**
  - §1 fixes 1–11 (the October 7 campaign PRs).
  - Recommendation 11 (dead code).
  - Required checks and a merge queue (#1018), then the CI cost cuts (recommendation 17).
  - Re-triage the open issues that still describe the removed `setup` command (#351, #390, #403).
- **Phase 1, v5.x minors: internal restructuring behind the existing goldens and e2e suites.**
  1. `formats/` codecs, one format per PR, each PR deleting the duplicate walks it replaces.
  2. `RunCtx`, which also unblocks the test-binary merge.
  3. `VendorBackend` + revert engine.
  4. `HostedRewriter` + `Outcome` + the `redirect/mod.rs` split.
  5. One `Inventory`.
  6. The test-support crate and binary merge.
  7. The generated contract reference.
- **Phase 2, v6 MAJOR (or before v5 GA, since it's still a prerelease): the user-facing changes.**
  1. The command model and per-command flags.
  2. One JSON envelope.
  3. Removing deprecated spellings and embedded `--vex`.
  4. `file` as the default download mode.
  5. Support-tier refusals.
  6. Hosted rollback via the sidecar or narrowed restore.
  7. The VEX consumed-evidence default.
  8. The self-update scope decision.

**Questions for owners:**
1. Is the in-memory engine and napi addon a supported product (the contract now names a future GitHub App as its caller)? That decides ~4.5K production lines. {{E44}}
2. What is agent mode's future?
3. Do we have telemetry on vlt, `bun.lockb`, pnpm ≤ 8 and Gradle usage, to set tiers?
4. Is wired-only VEX attestation an acceptable default? {{E46}}
5. Is a hosted-originals sidecar acceptable, or is "no `.socket/` in hosted mode" a hard requirement?
6. Can v5 GA absorb the command-model change?

---
_Generated by [Claude Code](https://claude.ai/code)_
