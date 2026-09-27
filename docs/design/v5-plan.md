# v5 plan (branch `release/v5-prerelease`, PR #277)

Decided 2026-09-27 by the project owner. Each workstream is its own branch
cut from `release/v5-prerelease` and its own PR back into it. Signed commits,
explicit push refspecs (`git push origin HEAD:refs/heads/<branch>`), never
push to `main`.

Supporting analysis (session reports, summarized here): stale-doc audit
(567 findings, fixed), complexity-vs-value inventory, duplicated-code map,
patch-UI review.

## Product decisions

- **Workflow:** `scan` (hosted, default, no prompts) → `vex` → `vendor`
  (eject to `.socket/vendor/` for offline) + `list`. `get` defaults to hosted
  too (done).
- **vlt stays** in every mode (hosted, vendored, agent). Not a cut candidate.
- **Every package-manager version we support stays** (pnpm 1–10 incl. 7/8
  vendored, bun.lockb, yarn classic + berry, pipenv/pdm/poetry/hatch/uv,
  bundler eras, …). Version support is not negotiable.
- **Agent mode** is deprecated over time but stays in v5. **`setup` is
  removed in v5** (install hooks: npm postinstall, the pypi `.pth` hook
  wheel, the Bundler plugin gem, Composer). `apply` stays (users wire it
  into CI themselves).
- **Hosted ledger (`.socket/vendor/redirect-state.json`) is removed.**
  `scan`/`get` hosted write only lockfile edits. Rollback of hosted wiring
  no longer replays recorded fragments.
- **In-place vendored ledger re-synthesis in `repair` is cut**; repair
  re-downloads artifacts from the remote instead (see WS5 caveat).
- **Future work (not v5):** a better vendored story for Maven and NuGet
  (vendored Maven refuses multi-module/Gradle; NuGet feed is fragile).
  Keep the current behavior; do not invest further now.

## Workstreams (ordered; WS1–WS3 unblock the rest)

### WS1 — Ledger-free hosted mode + new rollback  *(branch `v5/ledger-free-hosted`)*
- Start from local WIP `wip/v5-ledger-free-hosted` (6426bd68: scan stops
  writing the ledger; broke ~230 hosted round-trip tests).
- Hosted rollback/remove: for each hosted pin discovered from lockfiles
  (`vex::discover` refs), restore the **default upstream** entry: re-resolve
  the registry artifact for `name@version` (npm registry tarball + integrity,
  PyPI JSON, crates index, rubygems, packagist, proxy.golang.org, maven
  central, nuget v3) and rewrite the lock entry with the same per-format
  writer used for hosted (WS3 LockModel). Where that is impossible
  (formats with non-derivable fields, offline), refuse with a clear
  `git checkout -- <lockfile>` remedy. No fragment replay.
- Keep *reading* a legacy `redirect-state.json` only for migration (list/vex
  may show its records; rollback may delete it). Never write it.
- vex/list/vendor/scan-updates derive hosted state from lockfiles only.
- Rewrite the ~230 affected tests to the new contract; update
  CLI_CONTRACT/README/CHANGELOG.

### WS2 — `vendor` ejects hosted projects  *(branch `v5/vendor-eject`)*
- Standalone `vendor` today no-ops without `.socket/manifest.json`
  (vendor.rs ~672). New behavior: with no manifest, take the patch set from
  the hosted pins in the lockfiles (uuid in the hosted URL), fetch records
  from the API, vendor each into `.socket/vendor/`, and rewire the lock
  from hosted → vendored (reuse `scan --mode vendored` takeover path, or
  WS1's upstream-restore + vendored rewrite).
- `vendor --revert` → back to upstream (WS1 mechanism), not hosted.
- `lib.rs` after_help line "socket-patch vendor  Eject…" becomes true;
  README tutorial/“Work offline” switch back to `socket-patch vendor`.

### WS3 — One lockfile model per ecosystem  *(branch `v5/lock-models`)*
- Today pnpm-lock.yaml has 7 readers (redirect/mod.rs pnpm, vendor/pnpm_lock,
  pnpm_lock_legacy, lock_inventory/pnpm, lock_inventory/wired+recover,
  get.rs:1511 heuristic, repair_vendor scan_vendor_references); cargo 3
  grammars (redirect/mod.rs:1059–3261, vendor/cargo_lock+cargo_manifest,
  takeover.rs); gem 2; composer 3; yarn/bun partially shared.
- Target: `core/formats/<fmt>` per lock format, parse once, exposing
  `entries()` (inventory), `wired_refs()` (vex discover + repair),
  `plan_hosted()`, `plan_vendored()`, `restore_upstream()` (WS1), `in_use()`.
  Follow the `utils/python_lock.rs` pattern (already shared by disk + memory).
- One PR per family: pnpm (incl. legacy — support must stay) → cargo → gem →
  composer → yarn/bun/npm/vlt → go/maven/nuget.
- Gate: redirect golden fixtures (shared with depscan TS), the
  `*_equivalence_tests`, vex discover goldens, lock_inventory tests,
  byte-exact CRLF output.
- Also unify the 4 "which files carry wiring" lists into `formats::registry()`.

### WS4 — One hosted engine, disk + memory  *(branch `v5/one-hosted-engine`)*
- Both functions stay: disk `scan/get --mode hosted` and the in-memory
  engine (`hosted_memory/`, used by `socket-patch-node` and `hosted-bundle`).
- Extract plan → rewrite → edits from `run_redirect_selected`
  (scan/hosted.rs:1205–3358, 2.1k LOC) into a pure core function over
  `ProjectView`; `hosted_memory` calls it (delete its redirect.rs/ledger.rs
  copies, ~2.5k LOC); disk keeps only lock, probes, symlink guard, commit.
  Move the engine to core so `socket-patch-node` stops depending on the CLI
  crate. Keep `hosted_memory_parity` green until the final commit.
- Depends on WS1 (no ledger delta to merge) and benefits from WS3.

### WS5 — Consolidate vendored apply/revert wrappers + cut ledger rebuild  *(branch `v5/vendor-backend`)*
- Apply wrappers (4): `vendor.rs run/run_vendor`, `scan/vendor_flow.rs`
  (json/interactive/preview/legacy + 7 `boxed_*` shims), `get.rs
  run_get_vendored`, `repair_vendor.rs` (1.2k-LOC fn). Revert wrappers (3):
  `vendor.rs run_revert`, `rollback.rs run_vendored_leg`, `remove.rs
  revert_vendored_matches`. → one `VendoredBackend { apply, revert, repair }`.
- Cut `repair`'s vendored-ledger re-synthesis from lockfiles; repair
  re-downloads missing/corrupt artifacts from the vendoring service/remote.
- **Caveat to verify first:** the local rebuild path (`vendor/npm_pack.rs`,
  `pypi_wheel.rs`, `berry_zip.rs`, `registry_fetch.rs`, `prestage.rs`) may be
  what depscan's server-side vendoring uses via the CLI for packing. Check
  `../depscan` (grep for `socket-patch`, `vendor-source`, `npm_pack`,
  `hosted-bundle`, napi usage) before deleting anything; if used, keep it as
  a library path.

### WS6 — Unified ledgers/context  *(branch `v5/project-context`)*
- After WS1 only two stores remain (manifest for agent mode, vendor
  `state.json`). One `Ledgers` view with one owner-precedence rule replaces
  the 7 merge implementations (list combined_entries, fold_vendor_records,
  scan merge_ledger_records_for_updates, vex_sources plan/build_candidates,
  classify_overlap_takeover, rollback, remove) and the 61 load sites.
- `ProjectContext` (crawl snapshot, lock set, ledgers; lazy) shared by
  scan/vendor/vex/list/get; `get` reuses scan's discovery instead of
  get.rs:1583.

### WS7 — Remove `setup`  *(branch `v5/remove-setup`)*
- Delete the `setup` subcommand, core/setup/**, package_json/** helpers only
  setup uses, the setup-matrix CI job, and the Bundler plugin gem +
  `socket-patch-hook` wheel publishing (or mark them deprecated/unpublished;
  confirm with owner before deleting release workflows). Keep `apply`.
  Docs: agent mode = `scan --mode agent` + `socket-patch apply` in CI.
- **Status (branch `v5/remove-setup-and-ui`):** subcommand, core `setup/` +
  `package_json/`, setup tests, `setup-e2e` feature, setup-matrix CI job,
  `tests/setup_matrix/`, `scripts/setup-matrix.sh` and the setup-only
  `Dockerfile.gem-b1`/`gem-b4` are deleted. vex's "Property 7" filter went
  with it (agent patches attest on verification; `setup.manual` is parsed
  but ignored). The `socket-patch-hook` wheel and `socket-patch-bundler` gem
  are out of `publish-pypi.yml` / `publish-rubygems.yml`,
  `build-pypi-wheels.py` and `version-sync.sh`, and the `socket-patch[hook]`
  extra is dropped. **Owner decision pending:** `pypi/socket-patch-hook/`
  and `gem/socket-patch-bundler/` sources are kept (frozen, README marked
  deprecated) — delete them, and optionally yank/deprecate the published
  packages and remove their PyPI/RubyGems trusted publishers, once confirmed.

### WS8 — Patch UI streamlining  *(branch `v5/ui`)*
- `-h` shows ~8 options (hide_short_help for the rest); hide deprecated
  `--apply/--vendor`; one-line npm allow-remote note; no `(code)` tags in
  human warnings; "hosted" not "redirect" in human text; one shared
  Next-steps renderer; hosted/vendored `get` without prompts; `list` without
  manifest says "No patches in this project"; unify cancel/upsell strings;
  exit 2 for all usage errors; scan/get JSON onto `json_envelope`.
- Full item list: 22 findings from the UI review (sizes S/M/L, contract flags).
- **Status (branch `v5/remove-setup-and-ui`):** done — short `-h`
  (`cli_command()` hides the rest; `--help` unchanged), hidden
  `scan --apply/--vendor`, one-line npm allow-remote note (`--verbose`/JSON
  keep the detail), code-free `Warning:`/`GC: skipped:` lines (error lines keep their code),
  "hosted" wording in human text, `ui::next_steps` shared by hosted and
  vendored, prompt-free hosted/vendored `get` (JSON too), `list`'s
  `No patches in this project.` line (exit codes unchanged: 1 missing,
  0 empty), `ui::CANCELLED` / `ui::PAID_UPGRADE`, exit 2 for `get` and
  `rollback --one-off` usage errors. **Not done:** scan/get JSON onto
  `json_envelope` (larger contract change; deferred). Per-row
  `[error] <purl> (<code>)` / `[would-refuse]` lines keep their codes
  (grep-able under `--silent`).

## Remaining small follow-ups
*(All done on `v5/remove-setup-and-ui`: the vacuous rows are dropped,
GEM_PATCHES has both patches, `tool_command` and the deprecated aliases —
plus the CI grep that guarded them — are removed, and the backtest label is
retired.)*
- ci.yml `e2e_cargo`/`e2e_golang` rows select `--ignored` but have no ignored
  tests (vacuous legs) → give them `--include-ignored` or drop the rows.
- `e2e_vendored_production` GEM_PATCHES lacks merged `01019627` (v5 ranking
  picks it) and `9c2b4925`.
- `utils::process::tool_command` has no prod callers.
- Deprecated re-export aliases in core (`patch/mod.rs`, `lib.rs`,
  `utils/mod.rs`) — drop in v5.
- `scripts/backtest-poetry.py:541` "known crawler gap" label.
