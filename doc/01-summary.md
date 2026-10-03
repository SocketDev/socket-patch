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
> _Rendered {{UPDATED}} from `doc/` on the [`arch-audit/ledger`](https://github.com/SocketDev/socket-patch/tree/arch-audit/ledger) branch. The original snapshot is in `review/2026-10/` on the same branch._

# Architecture review of socket-patch v5: what to cut, combine, refactor and simplify

> **Originally written against** `main` @ `2463257` ("feat!: consolidate the v5 patching workflow (#277)") on 2026-10-01. Since then, sections are updated as the code changes, and each part says when it was last checked against `main`.
> **Method:** a read-only review split into seven areas: the CLI layer, hosted mode, JS lockfiles, vendored backends, discovery/VEX, core infrastructure and agent mode, and tests/CI/docs. Every area was measured with scripts: production and test lines are split at each file's inline `#[cfg(test)] mod`, and function lengths come from a brace-matcher that understands string literals. The highest-impact claims were then re-checked by hand against the source and a debug build. The 88 open issues were cross-referenced to architectural causes.
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

2. **Most of the open bug backlog has one shape: "reported success, but the build consumes unpatched code".** Of 88 open issues, roughly 29 are a success or a `not_affected` VEX attestation that the installed bytes don't back up. Another 15 are discovery missing what the package manager actually installed. The root cause is architectural:
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
   - ~118K lines of production code plus 35K comment lines.
   - ~450K lines of tests.
   - Nine functions over 500 lines; `run_scan` alone is 1,499.
   - A 17.5K-line `redirect/mod.rs`.
   - Two hosted orchestrators kept equal by parity tests.
   - Four discovery systems.
   - Nine different revert mechanisms.
   - Two JSON envelope shapes, 27 global flags silently accepted by every command, and 156 documented error codes.

   **We estimate 25–35K production lines (20–30%) and 50K+ test lines could go.** Roughly 20K of that comes from consolidation that keeps every capability; the rest comes from the support-tier and product decisions in §5.

5. **The user model is harder than it needs to be.** It has:
   - 9 verbs, 2 hidden subcommands, 2 aliases and 3 hidden flag spellings;
   - defaults that change with unrelated flags;
   - `scan` writing lockfiles by default;
   - mode that is not project state: a plain `scan` performs the documented "mode takeover" and switches vendored npm, Cargo and Go packages back to hosted;
   - `remove`, `rollback` and `vendor --revert` as three ways to undo.

   A seven-verb model (`scan` read-only, `fix`, `undo`, `sync`, `check`, `list`, `vex`) with mode inferred from the project would cover everything (§4).

6. **There are a few real defects to fix now** (§1), regardless of any refactor:
   - no HTTP timeouts on the main API client;
   - a ledger-loss bug in the vendored→hosted takeover;
   - a planted-binary spawn;
   - a comment-blind NuGet config reader;
   - `SOCKET_FORCE` bound to three unrelated `--force` flags.

---

## 0. The numbers

| | Value |
|---|---|
| Production code (non-blank, non-comment) | **117.6K lines** + 34.8K comment lines + 9K blank |
| Inline `#[cfg(test)]` code in `src/` | ~194K lines |
| Integration tests (`crates/*/tests`) | ~255K lines in **212 separate test executables** (201 top-level files + 11 directory binaries; recounted at `045d7ec`, 2026-10-03) |
| Test : production ratio | ~2.8 : 1 overall; ~7 : 1 for the CLI crate |
| Largest file | `patch/redirect/mod.rs`: 19,571 lines at `045d7ec` (2026-10-03; 17,517 at the snapshot, 6.2K production then) |
| Functions > 200 / > 500 lines | 61 / 9 (`run_scan` 1,499, `rollback::run` 984, `vendor_records_reusing` 962, `run_redirect_selected` 836, `remove::run` 797, `get::run` 635, memory `engine` 604, …) |
| CLI surface | 9 visible + 2 hidden subcommands; 57 visible long flags; 27 globals on every command; 43 env bindings (84 `SOCKET_*` names in source); 156 documented `errorCode`s; ~570 code-like strings in source |
| `--help` | 150–219 lines per subcommand; `list --help` lists 27 options, most of which do nothing for `list` |
| CI per push | ~516 jobs; the CI workflow alone is 237 jobs and 348 runner-minutes; Windows `test` is the 28-minute critical path |
| `CLI_CONTRACT.md` | 343 KB; the longest *line* is 10,530 characters (at `045d7ec`, 2026-10-03; 332 KB / 9,320 at the snapshot) |
| Open issues | 176 on 2026-10-03 (166 labelled `bug`). At the snapshot: 88, filed mostly in the last 5 days by a bug hunt; JS 26, JVM 22, Python 18, Go 6, Cargo 5, NuGet 5, Ruby 3, Composer 3 |
| PR size | Recent squash merges of +53K, +85K and +94K lines |

---

## 1. Fix now (small, independent of any refactor)

| # | Defect | Evidence | Fix | Status |
|---|---|---|---|---|
| 1 | **Zip member inflate on committed artifacts** (fixed) | `zip_bytes_match_after_hashes` now streams each member through the Git SHA-256 reader with an 8 KiB buffer and checks the declared length against the bytes read, instead of inflating it into a `Vec` (#587). The maintainer ruled that this data is trusted not to be too big, so the goal was streaming, not a cap. | The three archive caps (512/256/128 MiB) remain; see C15/C21. | {{C01}} |
| 2 | **No HTTP timeouts on the main API paths** (fixed) | Both `ApiClient` reqwest clients now take `api::retry::ApiTimeouts` (10 s connect, 60 s idle read), and a stalled JSON body reports `ApiError::Network` (#581). Blob/diff downloads still have **no retry**. | One retry and timeout primitive for every HTTP path (Part 7). | {{C02}} |
| 3 | **Vendored→hosted takeover drops the ledger entry on a drift-keep** | `RevertOutcome.kept_artifact` says callers "must ALSO keep the state.json entry" (`core/vendor/mod.rs:664-673`). `vendored_takeover` (`cli/scan/hosted.rs:1732-1790`) never reads it, deletes the entry, and tells the user that the "committed artifact" was reverted. Every other revert caller honors the flag. | Route takeover through `VendoredBackend`, and add a regression test. | {{C03}} |
| 4 | **Planted-binary spawn** | `vendor/pypi_hatch.rs:118` runs `Command::new("hatch").current_dir(root)`. That is exactly the pattern `utils/process.rs:23-33` documents as unsafe: a relative `PATH` entry executes a `hatch` planted in the scanned repo. It is the only production bare-name spawn. Reproduced on `045d7ec`: with `PATH=.:…`, a planted `hatch` runs and its fake version passes the `>=1.2` gate. | Use `process::resolve_tool`. | {{C04}} |
| 5 | **Comment-blind NuGet config reader in hosted mode** | `redirect/mod.rs:4302 nuget_package_source_keys` regex-scans raw XML without masking `<!-- -->`. A commented-out `<add key>` changes which sources get mapped. The vendored and `formats::nuget` readers both mask comments. | Use `formats::nuget::parse_config`. | {{E01}} |
| 6 | **`SOCKET_FORCE` is bound to three unrelated flags** | `vendor --force`, `apply --force` and `--update --force` (`vendor.rs:80`, `apply.rs:339`, `update.rs:61` at `045d7ec`). Exporting it to force a self-update also forces `apply`/`vendor` past hash checks. | Per-command env names. | {{C05}} |
| 7 | **`bun.lockb` ignores the registry override** | `vendor/bun_lockb.rs:235` hard-codes `registry.npmjs.org` instead of `registry_fetch::npm_tarball_url`, ignoring `SOCKET_NPM_REGISTRY`. vlt has two divergent `registry_base` implementations. | Use the shared helpers. | {{E02,E03}} |
| 8 | **Repo hygiene** | A stray `.github/actions/actions/cache/<sha>/.vscode/launch.json` (accidentally committed in #358); 2 dead CI path filters (CI janitor); 39 references in 20 files to a "DESIGN §x.y" document that isn't in this repository. The README now says plainly that its installer selects the latest release (verified on `045d7ec`). | Delete or fix. | {{C08}} |

---

## 2. The big picture: why the code is the size and shape it is

### 2.1 No abstraction on any axis of the matrix

| Axis | What exists today | What's missing |
|---|---|---|
| **Format** (package-lock, pnpm, yarn, bun, vlt, uv, poetry, pdm, pipenv, pylock, requirements, Cargo, Gemfile, composer, go.mod, NuGet, pom/Gradle) | A half-finished `formats/` layer. Its module doc promises "entry grammar, key rules, version sniff and planners" per format; only pnpm, cargo, gem, composer and bun are partly there. | One codec per format: `parse → model (with byte spans) → entries() / wired_refs() / splice(edits)`, used by **every** mode. Today package-lock has 4 entry walks, yarn has 5 copies of a `split("\n\n")`+regex grammar beside the shared block scanner, there are **8 hand-rolled XML scanners** (no XML crate), Cargo.toml has a regex scanner *and* `toml_edit` inside one rewriter, and poetry/pdm lock code are near-twins. |
| **Mode backend** (hosted/vendored/agent) | Three booleans in `run_scan`, referenced 91 times; JSON and human arms that each re-dispatch all three modes. | `trait ModeBackend { plan, consume, revert, verify }`, with rendering only at the end. |
| **Vendored backend** (per ecosystem) | Naming conventions plus two macros (`vend!`, `vend_installed!`). The ecosystem list is enumerated at **16 production sites**. Nine different revert mechanisms (~3.5K lines). | `trait VendorBackend` + a registry + **one generic splice-record revert engine**. The JVM planner (`jvm/mod.rs`) already is this design; copy it. |
| **Hosted rewriter** | Free functions in a hand-wired `Vec<Box<dyn Fn>>`. Results flow through a `RewriteResult` with **20 per-ecosystem uuid sets** and a 16-rule `confirm()` if-chain. **Eight parallel tables** must be edited to add an ecosystem. | `trait HostedRewriter { drives(), rewrite() -> Outcome { per_dep: Map<Uuid, DepStatus> } }` |
| **Inventory** | **Four discovery systems:** crawlers, lock inventory, wiring discovery (`vex::discover`) and a ledger supplement. They are merged by fabricating `CrawledPackage`s with a fake `node_modules/<name>` path *for every ecosystem*. | One `Inventory { instances: purl × declared_in × resolution (Registry/Hosted/Vendored) × installed_at }`. Crawlers become *locators*. |
| **Configuration** | Parsed flags are written back into process env (`args.rs:559 apply_env_toggles`) so core can read them. Its doc comment records a bug where telemetry sent a Bearer token to the wrong host. This also forces **553 `#[serial]`** test attributes. | An explicit `RunCtx { config, client, telemetry, lock }` built once in `main`. |

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
- **Dead flags and vestigial abstractions:** `--vendor-source` (one valid value), `VendorSource`/`PackageSource` (one variant each), `PatchSources::mem_blobs` (never `Some`), `lock_inventory/wired.rs` (no production caller), pre-v5 redirect-ledger readers.
- **History in reference docs:** 177 `v5.0` annotations in the contract.
- **Very large squash merges:** +53K, +85K and +94K lines.

**Suggested norms:**
- delete the oracle in the PR that lands the refactor;
- comments explain *why* and history goes in the CHANGELOG;
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
| 8 | S | **One JSON envelope and error shape** (`scan`/`get`/`rollback` still emit a bare-string `error`); **a typed code registry** (`enum Reason × Ecosystem`) that generates the contract's code tables, with a freshness test. | 0.3–0.6K prod; fixes ~65 undocumented and 1 phantom code | L-M (MAJOR) | Parts 2, 8 | {{C13,C14}} |
| 9 | C | **Support tiers** (§5): `bun.lockb` write support → refuse with remedy; vendored pnpm 7/8 → refuse (or a dialect of v9); vlt pre-1.0 encodings; Maven single-POM backend merged into `jvm/`. | 5–8K prod, 8–12K test | M (product) | Parts 4, 5 | {{E26,E47}} |
| 10 | C | **`--download-mode` default `file`**: `diff` re-downloads every blob anyway on a cold cache (`fetch_stage.rs:377`); delete the diff machinery and `qbsdiff`. | 0.6K prod, 1K test, −1 dep | L | Part 7 | {{C25}} |
| 11 | C | **Delete verified dead/vestigial code:** `--vendor-source`, `VendorSource`, `PackageSource`, `vend_installed!`, `mem_blobs`, `lock_inventory/wired.rs`, dead vlt ledger helpers, `save_redirect_state` + its group-commit entry, `Pypi`/`LauncherCache` update channels, the empty Deno extractor, the `switched_off("group_commit")` oracle path. | ~1K prod, ~1K test | L | Parts 4–7 | {{E28,E41,C23}} |
| 12 | M | **Utility consolidation:** one HTTP retry/timeout primitive; one validated purl builder family (78 hand-built `format!("pkg:…")`, 58 prefix checks); one digest/SRI helper set (fixing the `sha256_hex` name collision: one copy validates, three compute); one line-ending policy; one env-truthiness vocabulary (there are three); one UUID grammar (there are four). | 1–1.5K prod | L | Parts 4, 7 | {{C15,C17,C18,C19,C20,E16}} |
| 13 | C | **Embedded `--vex`** (15 flag instances on 3 commands, ~600 lines of glue, plus bypass sets that couple VEX correctness to each caller) → `fix && vex -O`. | 0.6K prod | L (MAJOR) | Parts 2, 6 | {{E42,C35}} |
| 14 | S | **Simplify per-package-manager auto-config:** npm `allow-remote` (re-implements npm's `ini` and config layering, ~900 lines), pnpm `trustLockfile` (~450; three open corruption bugs), the vlt warm-tree heal (installed-tree surgery in a lockfile-only mode), parallel rewriter groups (benchmark them or drop them). | 1–1.5K prod | M | Part 3 | {{E34}} |
| 15 | C | **Self-update:** keep the notifier; replace the binary swap with "re-run install.sh" (only the standalone channel can self-update). **Telemetry:** one `track(Event)` + a shared client instead of 17 wrappers and 125 token/org plumbing sites. | 1.3–2.3K prod, 3K+ test | L-M (product) | Parts 2, 7 | {{C22,C36}} |
| 16 | M | **Tests:** 207 → ~25 binaries (needs `RunCtx` first, to drop the env-mutating `#[serial]`); a `socket-patch-test-support` crate (`binary()` is defined in 102 files, `git_sha256` in 84, and 14 divergent `scrub_socket_env`); retire the oracles; triage covgap; snapshots instead of 328 sentence assertions. | 15–25K test lines; minutes off the Windows critical path | M | Part 8 | {{C30,C31,C32,E35}} |
| 17 | C | **CI:** report-only coverage + LTO `docker-base` off PRs (≈74 runner-min/run); PR e2e 148 legs → ~50 boundary versions; reusable compat workflow; no per-leg compiles. | ~200 fewer jobs per PR | L | Part 8 | handed off to the CI janitor |
| 18 | S | **Docs:** a generated CLI reference plus ≤300 lines of contract prose; move ecosystem narratives into `ecosystems.md` and history into the CHANGELOG; decouple `docs/testing` from validation scripts. | — | L | Part 8 | {{C33}} |

**Estimated total:** ~25–35K production lines (20–30%) and 50K+ test lines. About 20K is pure consolidation (recommendations 1–3, 6, 8, 10–12, 14); the rest depends on the tier and product decisions (recommendations 4, 5, 9, 13, 15). That is before any decision to deprecate agent mode, which would remove another ~10K. The per-recommendation numbers overlap: for example, recommendation 1 shares work with 2 and 9.

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
| `bun.lockb` writing (hosted + vendored) | ~2.8K / ~3K + 1.6K CLI | The repo itself labels it "binary, legacy"; Bun ≥ 1.2 writes text `bun.lock`. The codec writes a private `sktpnrm` marker into an unused slot of the user's lockfile. | Refuse, with the remedy `bun install --save-text-lockfile --frozen-lockfile --lockfile-only`; keep a ~300-line read-only parser if inventory needs it. |
| Vendored pnpm lockfile 5.4/6.0 (pnpm 7/8, both out of maintenance) | 1.85K / 3.2K | ~96% a copy of the v9 backend. The absolute specifier means `--frozen-lockfile` only passes at the original checkout path, which undercuts the point of vendoring. | Refuse with "re-lock with pnpm ≥ 9", or merge it as a `PnpmDialect`. |
| vlt | ~6.5K / ~6.1K + ~9.3K CLI; ~123 CI jobs per push | A very new package manager; supports pre-1.0 RC encodings. Architecturally the cleanest JS format (one codec). | Drop the pre-1.0 encodings now. Gate vendored vlt (the dir-artifact backend + heal, ~3K) on telemetry. Move the vlt sweeps to nightly. |
| JVM: two Maven backends + Gradle | ~7.5K vendored + ~1.5K hosted/crawler | 22 of the 88 open issues (25%), mostly XML text surgery and resolution semantics (mirrors, locking, checksums, multi-module). | Merge `maven_repo.rs` into `jvm/` (`Shape::Single`); one XML scanner; scope the crawler to project dependencies, not all of `~/.m2`. Consider labelling hosted Maven/Gradle "beta" until the backlog is under control. |
| Agent mode overall | ~6.4K CLI + ~3.5K core | v5 defaults to hosted. ~15 open issues (appendix category B) come from re-implementing package-manager install layouts, mostly in agent mode. | Decide: freeze agent mode to the ecosystems that need it (Deno; Go's local `replace`), or keep it and **ask the package manager** for layouts (§2.2). |
| In-memory engine + napi addon | ~4.8K / ~4.6K | `"private": true`, never released, built and smoke-tested on every PR. | Keep it only if the depscan backend replaces its TS rewriters with it; otherwise delete it. |
| Self-update binary swap | ~1–2K / 3–5K | Only the standalone channel can use it. | Keep the notifier; make `--update` print or run the installer one-liner. |

---

## 6. Suggested sequencing

- **Phase 0, this week: no behavior change except bug fixes.**
  - §1 fixes 1–8.
  - Recommendation 11 (dead code).
  - CI cost cuts (recommendation 17).
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
1. Will depscan adopt the napi engine? That decides ~5K production lines.
2. What is agent mode's future?
3. Do we have telemetry on vlt, `bun.lockb`, pnpm ≤ 8 and Gradle usage, to set tiers?
4. Is wired-only VEX attestation an acceptable default?
5. Is a hosted-originals sidecar acceptable, or is "no `.socket/` in hosted mode" a hard requirement?
6. Can v5 GA absorb the command-model change?

---
_Generated by [Claude Code](https://claude.ai/code)_
