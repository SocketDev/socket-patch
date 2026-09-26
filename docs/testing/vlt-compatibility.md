# vlt patch compatibility

`socket-patch` supports hosted, vendored and agent-mode npm patches in
[vlt](https://www.vlt.sh) projects (`vlt-lock.json`, the `node_modules/.vlt`
store and, from vlt 1.2.0, the global content store). This page records the
real-vlt evidence: which releases are supported, which capstone legs run on
which release, and the vlt behaviors the legs pin. What each mode does with a
vlt project, and the caveats users meet, are in
[vlt notes](../ecosystems.md#npm-vlt-notes).

## Formats

| Era | Releases | `lockfileVersion` | DepID grammar | Default-registry node slot [3] |
|---|---|---|---|---|
| A0 | 0.0.0-1, 0.0.0-11 … 0.0.0-18 | absent | `·` / `§` + `encodeURIComponent` (`··name@ver`) | absent |
| A | 0.0.0-19 … 1.0.0-rc.8 | `0` | as A0; `ṗ:N` peer extras from rc.6 | absent (3-tuples) |
| B | 1.0.0-rc.9 … 1.0.0-rc.14 | `0` | as A, default segment `npm` (`·npm·name@ver`) | absent |
| C | 1.0.0-rc.15 … 1.0.0-rc.32 | `1` | `~` / `+` + `_x` escapes (`~npm~name@ver`), `peer.N` | absent |
| D | 1.0.0-rc.33 … 1.0.7 | `1` | as C | the registry URL |
| E | 1.0.8 … 1.1.1 | `1` | as C, `peer.<16 hex>` | the registry URL |
| F | 1.2.0 | `1` | as E; the global store (`store-linker`) | the registry URL |

Hosted mode writes the patched sha512 into slot [2] and the hosted URL into
slot [3] of every default-registry node (appending slot [3] to a 3-tuple);
vendored mode turns the node into a `file` node for the D19 directory
`.socket/vendor/npm/<uuid>/<name>-<version>/node_modules/<name>`. vlt reads
CRLF locks and writes LF; a BOM-prefixed lock is unreadable by vlt and by
socket-patch alike.

## What is verified where

| Layer | Where | What it proves |
|---|---|---|
| Unit and golden | `socket-patch-core` lib tests; `tests/redirect_golden.rs` (`npm/vlt/*`, shared with depscan's TS rewriter), `tests/redirect_golden_reverse_replay.rs`, `tests/vlt_locks.rs` (captured locks of every era, and vendored wiring byte for byte against what real `vlt ci`, `vlt install --frozen-lockfile` and `vlt install <new>` keep on 1.2.0, 1.0.10, 1.0.4, 1.0.0-rc.32 and 1.0.0-rc.14) | DepID codec, collation (`tests/fixtures/vlt/collation-golden.json`), the node-line grammar, the hosted slot rewrite and its slot revert, vendored lock surgery and its inverse, lock inventory, VEX discovery |
| Hermetic suites | `in_process_redirect`, `in_process_vendor`, `in_process_rollback_hosted`, `in_process_vendor_bun_takeover`, `repair_vendor_flavors_e2e`, `e2e_vex_lockfile`, `setup_invariants`, … (the 3-OS `test` job) | every code of the vlt support, the artifact preflight against a wiremock server, the heal, takeovers, repair, the CLI surface |
| Real-vlt capstones | the five binaries below plus the vlt legs of `e2e_hosted_production` / `e2e_vendored_production` | real installs: `vlt ci` and frozen installs of patched locks, byte-stable locks, integrity enforcement, the heal on a warm tree, re-saves, upgrades, the hardlinked global store, the setup hook |
| Native backtest | `scripts/backtest-vlt.py` | the production service end to end, per release, mode and project shape, against an oracle of the documented boundaries |

`docs/testing/vlt-coverage.json` maps every vlt code and advisory variant,
every mode × command cell and every era × OS cell to the tests or CI rows that
assert it; `scripts/tests/test_vlt_coverage.py` checks that each code is
asserted and each named test or row exists.

## CI wiring

- **Required:** ci.yml's `e2e` job has 35 vlt rows (`vlt:` pins the release,
  `vlt_store_linker:` / `vlt_upgrade:` the knobs; `test_filter:
  --include-ignored vlt_pinned_matrix`). "Setup vlt" packs the release,
  checks its sha512 against the registry and `scripts/vlt-historical-integrity.json`
  (`scripts/install-vlt.sh`), installs it under a prefix and exports
  `SOCKET_PATCH_VLT_E2E_JS` / `_VERSION` / `_REQUIRED=1` with `LANG=C`. Every
  row's output goes through `scripts/check-vlt-legs.py`.
  `scripts/tests/test_ci_vlt_rows.py` (run by `lint-ecosystems`) pins the rows.
- **Required:** `hosted-e2e` installs vlt 1.2.0 the same way, runs
  `vlt_pinned_matrix_production_hosted_install_proof` inside the production
  suite (probe-driven: the clean refusal while patch.socket.dev re-encodes the
  artifact, the full install proof once it does not) and
  `vlt_pinned_matrix_production_vendored_install_proof`, both through the leg
  checker. `SOCKET_PATCH_VLT_HOSTED_PRODUCTION_REQUIRED` stays unset until the
  serve fix is verified.
- **Advisory:** `.github/workflows/vlt-compatibility.yml` (path-filtered pull
  requests and pushes to main, nightly, and `workflow_dispatch` with
  `versions` / `shapes` / `modes`). A path-filtered workflow cannot be a
  required check. Jobs: `build` (the capstones and the CLI, once per OS);
  `install-proof` (every capstone on 31 Linux, 11 macOS and 15 Windows
  releases, the Node engine floors 22.22.0 / 22.9.0 / 22.0.0 with the collation
  golden, and the store linkers auto / hardlink / copy / unpack / a `/dev/shm`
  cache root); `native` (the backtest against production, artifacts
  `vlt-results-<os>-<vlt>` in depscan's capture `result.json` shape);
  `lock-diff` (the same cell's `vlt-lock.json` must be byte-identical on Linux,
  macOS and Windows); `matrix-coverage` (every era × suite × OS).
- **Nightly:** `canary` runs every capstone on `vlt@latest` on 3 OS (only the
  exact-version pin is relaxed), fails when npm lists a vlt release that the
  Releases table below neither supports nor excludes, and, once a release
  writes a `lockfileVersion` other than 0 or 1, requires hosted mode to refuse
  it (`redirect_vlt_lock_unsupported`). `downgrade` (advisory) has the latest
  published socket-patch run `rollback` and `vendor --revert` on vlt ledgers
  written by the build: each must leave the project untouched or fully
  reverted, never half-reverted.
- **Watchdog:** `.github/workflows/vlt-serve-watchdog.yml` probes the public
  minimist artifact every 6 hours as vlt fetches it and fails on a
  content-encoded response or a sha512 other than the API's. It is
  `continue-on-error` until the serve fix is verified in production.

## Running locally

```sh
export SOCKET_PATCH_VLT_E2E_JS=$(scripts/install-vlt.sh 1.2.0 /tmp/vlt-1.2.0)
export SOCKET_PATCH_VLT_E2E_VERSION=1.2.0 SOCKET_PATCH_VLT_E2E_REQUIRED=1 LANG=C LC_ALL=C
for s in e2e_redirect_vlt_build e2e_vendor_vlt_build mode_migration_vlt e2e_safety_vlt e2e_vlt; do
  cargo test -p socket-patch-cli --test $s -- --include-ignored vlt_pinned_matrix 2>&1 | tee vlt-leg.log
  python3 scripts/check-vlt-legs.py --manifest crates/socket-patch-cli/tests/vlt-leg-manifest.json vlt-leg.log
done

# The production backtest (no Socket API token needed):
python3 scripts/backtest-vlt.py --cli target/debug/socket-patch \
  --versions 1.2.0 1.0.0-rc.14 --modes hosted vendored agent --jobs 2 --out /tmp/vlt-bt
```

The backtest writes `captures/<vlt>-<mode>-<shape>/{result.json,cli-output.json,tree/,logs/}`
and `summary.{json,md}`, and exits non-zero when any cell's verdict differs
from the oracle. While patch.socket.dev re-encodes the artifact, hosted cells
record `blocked-by-server-encoding`, and only when the cell's own probe saw a
non-identity `Content-Encoding` and the CLI refused cleanly. A blocked cell
must carry only `redirect_vlt_artifact_unverifiable`: the withheld dependency
never reaches a rewriter, so its lock-level and vendored codes are not due.
`--identity-mirror` previews the hosted proof through a loopback mirror that
fetches the artifact un-encoded (never an import source). `--serve-probe` is
the watchdog's probe, `--canary-checks` the canary's watchdogs, and
`--downgrade-cli <published socket-patch>` the downgrade scenario.

## The capstone registry harness

The capstones serve npmjs bytes from a local wiremock registry `R` and write
`vlt.json` per era, because before rc.33 bare specs ignore `registries.npm`:

| Era window | vlt.json | Hermetic | Notes |
|---|---|---|---|
| ≤ 0.0.0-13 | flat `{"registry": R}` | yes | `vlt-workspaces.json` for workspaces ≤ 0.0.0-12 |
| 0.0.0-14 … rc.6 | `{"config":{"registry": R}}` (+ `"modifiers":{}` for 0.0.0-16 … 24, except the ignored-lock leg) | yes | URL-segment DepIDs carry R's port |
| rc.7 … rc.29 | `{"config":{"registry": "https://registry.npmjs.org/"}}` | no: lock-driven installs reach public npm | the dead-registry assertions log `skip:non-hermetic-registry`; the patch service stays local |
| rc.30 … rc.32 | `{"config":{"registry": R}}` | yes | URL-segment DepIDs |
| ≥ rc.33 | `{"config":{"registries":{"npm": R}}}` (+ `config.registry = R` for rc.33 … 1.0.4) | yes | |

`scripts/backtest-vlt.py`'s `write_vlt_json` follows the same table against
public npm (a `registry` equal to vlt's npmjs default is left out: vlt strips
it from the lock anyway).

## depscan parity

depscan's TypeScript rewriter (`registry-rewrite/vlt.ts`) and its SBOM
recognition implement the same spec.
`crates/socket-patch-core/tests/fixtures/redirect/npm/vlt/*` is the single source of truth: depscan runs every case through its golden
test from the `submodules/socket-patch` pin, with **no** `TS_LAGGING` or
`TS_WARNING_DRIFT` entry for vlt, and `redirect_golden_reverse_replay.rs`
proves that socket-patch rolls back what either implementation wrote. The
`vlt-results-*` artifacts and the cross-OS locks are imported into depscan's
fixtures (`audit-captures.py`, `generate-fixtures.py --captures`) once the serve
fix is live.

## Real-vlt capstones

Five `#[ignore]`-gated test binaries drive the REAL vlt under test
(`SOCKET_PATCH_VLT_E2E_JS=<path to vlt.js>`, `SOCKET_PATCH_VLT_E2E_VERSION`
for an exact `--version` match) against a local npm registry (bytes fetched
once from npmjs, or built by the harness for the synthetic packages) and a
mock patch service, plus one leg in each production suite:

```sh
cargo test -p socket-patch-cli --test e2e_redirect_vlt_build -- --include-ignored vlt_pinned_matrix 2>&1 \
  | tee vlt-leg.log
python3 scripts/check-vlt-legs.py --manifest crates/socket-patch-cli/tests/vlt-leg-manifest.json vlt-leg.log
```

Every leg is a test named `vlt_pinned_matrix_<suite>_<leg>` that prints one
`VLT-LEG <vlt-version> <os> <suite> <leg> ran|skip:<reason>` line.
`scripts/check-vlt-legs.py` fails a run on `0 passed`, on a binary that
prints no `test result:` line (a crash), on a missing `ran`, on a skip the
manifest does not predict, and on an unknown leg. The manifest
`crates/socket-patch-cli/tests/vlt-leg-manifest.json` is generated from the
three tables below (`python3 scripts/check-vlt-legs.py --derive
docs/testing/vlt-compatibility.md`), never written by hand;
`scripts/tests/test_check_vlt_legs.py` re-derives it and diffs.

Knobs (applied after the harness scrubs the ambient `VLT_*` environment):
`SOCKET_PATCH_VLT_E2E_STORE_LINKER` ∈ {auto, hardlink, copy, unpack},
`SOCKET_PATCH_VLT_E2E_CACHE_ROOT` (a cache on another filesystem),
`SOCKET_PATCH_VLT_E2E_UPGRADE_JS` / `_UPGRADE_VERSION` (the second vlt of the
upgrade legs) and `SOCKET_PATCH_VLT_E2E_SOCKET_BIN`. A set `_JS` makes every
toolchain problem a failure, and so does `CI=true` with `_JS` unset.

## Releases

| Status | Versions |
|---|---|
| supported | `0.0.0-1`, `0.0.0-11`, `0.0.0-12`, `0.0.0-13`, `0.0.0-14`, `0.0.0-15`, `0.0.0-16`, `0.0.0-17`, `0.0.0-18`, `0.0.0-19`, `0.0.0-20`, `0.0.0-21`, `0.0.0-23`, `0.0.0-24`, `0.0.0-25`, `0.0.0-26`, `0.0.0-27`, `0.0.0-28`, `0.0.0-29`, `0.0.0-30`, `0.0.0-31`, `0.0.0-32` |
| supported | `1.0.0-rc.1`, `1.0.0-rc.2`, `1.0.0-rc.3`, `1.0.0-rc.4`, `1.0.0-rc.5`, `1.0.0-rc.6`, `1.0.0-rc.7`, `1.0.0-rc.8`, `1.0.0-rc.9`, `1.0.0-rc.10`, `1.0.0-rc.11`, `1.0.0-rc.12`, `1.0.0-rc.13`, `1.0.0-rc.14`, `1.0.0-rc.15`, `1.0.0-rc.16`, `1.0.0-rc.17`, `1.0.0-rc.18` |
| supported | `1.0.0-rc.22`, `1.0.0-rc.23`, `1.0.0-rc.24`, `1.0.0-rc.25`, `1.0.0-rc.26`, `1.0.0-rc.27`, `1.0.0-rc.28`, `1.0.0-rc.29`, `1.0.0-rc.30`, `1.0.0-rc.31`, `1.0.0-rc.32`, `1.0.0-rc.33`, `1.0.0-rc.34` |
| supported | `1.0.1`, `1.0.2`, `1.0.3`, `1.0.4`, `1.0.5`, `1.0.6`, `1.0.7`, `1.0.8`, `1.0.9`, `1.0.10`, `1.1.0`, `1.1.1`, `1.2.0` |
| excluded (broken install) | `0.0.0-0` |
| excluded (Deno-compiled wrappers) | `0.0.0-2`, `0.0.0-3`, `0.0.0-4`, `0.0.0-5`, `0.0.0-6`, `0.0.0-7`, `0.0.0-8`, `0.0.0-9`, `0.0.0-10` |
| excluded (`vlt install` exits 13 on Node 24 after "Done") | `0.0.0-22` |
| excluded (never published) | `1.0.0-rc.19`, `1.0.0-rc.20`, `1.0.0-rc.21` |
| excluded (unrelated 2017 publishes) | `0.0.1`, `1.0.0` |

`0.0.0-0.<timestamp>` builds are excluded too. Every supported release was
run through all five capstones on macOS during SP-9 (the CI matrix samples
them per OS).

## Leg inventory

| Binary | Suite | Legs |
|---|---|---|
| `e2e_redirect_vlt_build` | `hosted` | `scan_fresh_ci`, `frozen_dead_registry`, `ordinary_install_stable`, `get_uuid_fresh_ci`, `tamper_cold_eintegrity`, `rollback_byte_exact`, `rerun_noop`, `warm_tree_invalidates`, `no_cleanup_stays_stale`, `heal_rule_b_hidden_lock_without_node`, `heal_rule_c_no_hidden_lock`, `heal_rule_c_no_record`, `scoped`, `peer_workspace_instances`, `install_newdep_preserves`, `update_drops`, `resave_install_rollback`, `resave_crlf_rollback`, `resave_update_rollback`, `crlf_lock`, `mirror_registries_npm`, `scalar_registry`, `named_alias_untouched`, `scoped_registry_untouched`, `jsr_untouched`, `default_registry_alias`, `registry_from_env`, `registry_from_user_config`, `content_encoding_refused`, `old_lockfile_ignored`, `warm_cache_hazard`, `idempotence`, `manifestless_vex`, `ts_written_lock`, `optional_dependency_heal`, `then_vendored_optional_takeover`, `platform_optional_skipped` |
| `e2e_vendor_vlt_build` | `vendored` | `scan_fresh_ci`, `get_build_fresh_ci`, `get_service_fresh_ci`, `durability`, `workspace_member_selfref`, `alias_selfref`, `peer_root_selfref`, `peer_member_selfref`, `single_peer_context`, `optional_warm_reinstall`, `dep_with_deps`, `hostile_gitignore`, `autocrlf_checkout`, `bin_bearing`, `package_json_devdeps_patch`, `repair_rebuilds`, `idempotency`, `revert_byte_exact`, `resave_install_revert`, `resave_uninstall_revert`, `resave_crlf_revert`, `tamper_planted_file`, `tamper_file_content`, `tamper_payload_package_json`, `tamper_symlink_outside`, `tamper_deleted_gitignore`, `tamper_lock_file_node_path`, `transitive_refused`, `legacy_lockfile_warning`, `absent_version_refused`, `lockless_reinstall`, `manifestless_vex` |
| `mode_migration_vlt` | `migration` | `vendored_then_hosted`, `hosted_then_vendored`, `dry_run_parity`, `scoped_unwind_one_of_two`, `rollback_from_mixed`, `agent_apply_yields_to_vendored`, `agent_apply_after_hosted`, `hosted_scan_keeps_agent_patched_tree`, `agent_rollback_after_takeovers`, `pm_switch_npm_to_vlt`, `pm_switch_vlt_to_npm`, `flavor_changed`, `upgrade_hosted`, `upgrade_vendored` |
| `e2e_safety_vlt` | `safety` | `linux_auto`, `explicit_hardlink`, `private_copies`, `cross_device_cache`, `agent_rollback`, `peer_fanout`, `hosted_heal`, `vendored_build`, `vendor_revert_and_repair`, `layout_note` |
| `e2e_vlt` | `agent` | `scan_apply_rollback_list`, `get_and_remove`, `install_then_apply_patches_file`, `transitive_only_dep_apply_patches_store`, `lockfile_supplement`, `launcher`, `persistence_survives`, `persistence_reverted_by_reinstall`, `reruns_and_vex` |
| `e2e_vlt` | `setup` | `hook_fires_per_reify`, `root_scripts_advisory`, `workspace_root_only`, `twice_no_duplicate`, `hook_failure`, `hook_abort_leaves_no_staging` |
| `e2e_hosted_production` | `production` | `hosted_install_proof` |
| `e2e_vendored_production` | `production` | `vendored_install_proof` |

## Boundary table

The DESIGN §1.1 boundaries, extended with what SP-9 measured on every
supported release. A row with a skip reason is a manifest rule: the first
row matching a leg, the vlt version, the OS and the knobs decides that leg's
`skip:<reason>` (rows are ordered the way the legs test them); every other
leg must print `ran`. Rows without a skip reason are behaviors the legs
assert in place.

Versions: `< V`, `<= V`, `> V`, `>= V`, `== V`, `A … B` (inclusive) or
`all`. Conditions: `os` (`linux`, `macos`, `windows`), `linker` (the
store-linker knob, `unset` when not given), `cache_root` and `upgrade`
(`set`/`unset`), and `upgrade<V` (the upgrade vlt's version); `in` / `notin` take `+`-separated values and `,` joins conditions.

| Boundary | Versions | Condition | Suite | Legs | Skip reason |
|---|---|---|---|---|---|
| A0 locks (no `lockfileVersion`) are refused by vendored mode | `<= 0.0.0-18` | — | vendored | `*` except `absent_version_refused` | `a0-vendored-unsupported` |
| A0 locks are refused by vendored mode | `<= 0.0.0-18` | — | migration | `*` | `a0-vendored-unsupported` |
| A0 locks are refused by vendored mode | `<= 0.0.0-18` | — | production | `vendored_install_proof` | `a0-vendored-unsupported` |
| the global store and `store-linker` | `< 1.2.0` | — | safety | `*` | `no-global-store` |
| `vlt ci`, `--frozen-lockfile`, `--expect-lockfile` exist | `< 0.0.0-19` | — | hosted | `frozen_dead_registry`, `optional_dependency_heal`, `then_vendored_optional_takeover` | `no-vlt-ci` |
| a scalar `registry` makes lock-driven installs re-resolve from public npm | `1.0.0-rc.7 … 1.0.0-rc.29` | — | hosted | `frozen_dead_registry` | `non-hermetic-registry` |
| registry tarball integrity is not enforced on a cold fetch | `== 0.0.0-1` | — | hosted | `tamper_cold_eintegrity` | `integrity-unenforced` |
| bare specs honor `registries.npm` | `< 1.0.0-rc.33` | — | hosted | `mirror_registries_npm` | `registries-npm-ignored` |
| named registry specs (`acme:x@1`), scoped registries and URL-segment DepIDs exist (flat-config releases record every registry node under the default segment) | `< 0.0.0-14` | — | hosted | `named_alias_untouched` | `no-named-registry-specs` |
| as above | `< 0.0.0-14` | — | hosted | `scoped_registry_untouched`, `jsr_untouched` | `registry-not-in-dep-id` |
| `jsr:` specs resolve through `jsr-registries` (0.0.0-14 … rc.6 send the `@jsr` scope to npm.jsr.io; rc.7 … rc.32 cannot run the leg hermetically, below) | `< 1.0.0-rc.7` | — | hosted | `jsr_untouched` | `jsr-registry-not-configurable` |
| a scalar `registry` makes lock-driven installs re-resolve from public npm | `1.0.0-rc.7 … 1.0.0-rc.29` | — | hosted | `jsr_untouched` | `non-hermetic-registry` |
| `npm:` alias specs resolve against public npm even with `registries.npm` | `1.0.0-rc.30 … 1.0.0-rc.32` | — | hosted | `jsr_untouched` | `non-hermetic-registry` |
| `default-registry-alias` exists | `< 1.0.0-rc.33` | — | hosted | `default_registry_alias` | `no-default-registry-alias` |
| the lock is ignored unless vlt.json declares `"modifiers": {}` | `< 0.0.0-16` | — | hosted | `old_lockfile_ignored` | `lock-not-ignored` |
| as above | `> 0.0.0-24` | — | hosted | `old_lockfile_ignored` | `lock-not-ignored` |
| `vlt update` exists | `< 0.0.0-20` | — | hosted | `update_drops`, `resave_update_rollback` | `no-vlt-update` |
| the golden `basic` lock (`registries.npm`, no scalar `registry`) is what the release writes | `< 1.0.5` | — | hosted | `ts_written_lock` | `golden-grammar` |
| a platform-skipped optional dependency makes the install fail (`Dependency node could not be found`) | `0.0.0-31 … 1.0.0-rc.1` | — | hosted | `platform_optional_skipped` | `vlt-platform-optional-bug` |
| a scalar `registry` makes lock-driven installs re-resolve from public npm | `1.0.0-rc.7 … 1.0.0-rc.29` | — | vendored | `workspace_member_selfref`, `alias_selfref` | `non-hermetic-registry` |
| `npm:` alias specs resolve against public npm even with `registries.npm` | `1.0.0-rc.30 … 1.0.0-rc.32` | — | vendored | `alias_selfref` | `npm-alias-non-hermetic` |
| era A (`··` ids, or scalar-registry URL-segment ids with no `·npm·` id): `vendor_vlt_legacy_lockfile` | `> 1.0.0-rc.8` | — | vendored | `legacy_lockfile_warning` | `not-legacy-lockfile` |
| `lockfileVersion` is written | `>= 0.0.0-19` | — | vendored | `absent_version_refused` | `lockfile-version-present` |
| the upgrade legs need a second vlt | `all` | `upgrade=unset` | migration | `upgrade_hosted`, `upgrade_vendored` | `no-upgrade-vlt` |
| only a v0 lock (0.0.0-19 … rc.14) meets a grammar change | `> 1.0.0-rc.14` | — | migration | `upgrade_hosted`, `upgrade_vendored` | `no-grammar-upgrade` |
| the upgrade vlt must check `lockfileVersion` | `all` | `upgrade<1.0.0-rc.15` | migration | `upgrade_hosted`, `upgrade_vendored` | `no-grammar-upgrade` |
| `store-linker=auto` hardlinks on Linux only | `all` | `os!=linux` | safety | `linux_auto` | `not-linux-auto` |
| as above | `all` | `linker notin unset+auto` | safety | `linux_auto` | `not-linux-auto` |
| as above | `all` | `cache_root=set` | safety | `linux_auto` | `not-linux-auto` |
| the explicit hardlink leg | `all` | `linker!=hardlink` | safety | `explicit_hardlink` | `store-linker-not-hardlink` |
| as above | `all` | `cache_root=set` | safety | `explicit_hardlink` | `store-linker-not-hardlink` |
| the store is hardlinked | `all` | `linker=hardlink, cache_root=unset` | safety | `private_copies` | `store-linker-hardlinks` |
| as above | `all` | `linker in unset+auto, os=linux, cache_root=unset` | safety | `private_copies` | `store-linker-hardlinks` |
| a cache on another filesystem falls back to copies | `all` | `cache_root=set` | safety | `private_copies` | `store-linker-hardlinks` |
| as above | `all` | `cache_root=unset` | safety | `cross_device_cache` | `no-cache-root` |
| a scalar `registry` makes lock-driven installs re-resolve from public npm | `1.0.0-rc.7 … 1.0.0-rc.29` | — | agent | `scan_apply_rollback_list`, `launcher` | `non-hermetic-registry` |
| `npm:` alias specs resolve against public npm even with `registries.npm` | `1.0.0-rc.30 … 1.0.0-rc.32` | — | agent | `scan_apply_rollback_list` | `non-hermetic-registry` |
| root `pre*`/`post*` scripts run without an `install` script | `< 1.0.0-rc.13` | — | setup | `hook_fires_per_reify`, `workspace_root_only`, `hook_failure` | `root-postinstall-not-run` |
| a failing hook's abort on Windows (rollback EBUSY fix from 1.0.5) | `all` | `os!=windows` | setup | `hook_abort_leaves_no_staging` | `windows-only` |
| as above | `< 1.0.5` | — | setup | `hook_abort_leaves_no_staging` | `pre-ebusy-fix` |
| `lockfileVersion` 0 with legacy (`·`/`§`) DepIDs | `0.0.0-19 … 1.0.0-rc.14` | — | — | — | — |
| `lockfileVersion` 1, tilde DepIDs | `>= 1.0.0-rc.15` | — | — | — | — |
| a plain `vlt install` re-extracts a stale installed copy (`no_cleanup_stays_stale` expects the patch there) | `== 0.0.0-14` | — | — | — | — |
| an optional-only project: installs from the lock | `<= 0.0.0-23` | — | — | — | — |
| an optional-only project: the first install writes no `vlt-lock.json` | `0.0.0-24 … 0.0.0-29` | — | — | — | — |
| an optional-only project: lock-driven installs install nothing | `0.0.0-30 … 1.0.4` | — | — | — | — |
| an optional-only project installs from the lock again | `>= 1.0.5` | — | — | — | — |
| after a hosted→vendored takeover a plain `vlt install` already links the vendored dir | `<= 0.0.0-29` | — | — | — | — |
| a plain `vlt install` keeps an installed optional dependency whose spec moved to a vendored `file:` directory (the upstream copy stays linked until `vlt ci`); vendored mode says so with `vendor_vlt_reinstall_required`, which `optional_warm_reinstall` pins | `>= 0.0.0-30` | — | — | — | — |
| lockless `file:` directory dependencies fail to resolve | `0.0.0-31 … 1.0.0-rc.5` | — | — | — | — |
| a re-save (`vlt install <new>`) drops slot [3] of default-registry nodes (the hosted URL; the patched integrity stays, so `vlt ci` fails `EINTEGRITY` until a rescan re-pins, and rollback reports drift) | `1.0.0-rc.6 … 1.0.0-rc.17` | — | — | — | — |
| a warm cache re-fetches a changed tarball and fails its integrity (no stale-bytes hazard) | `1.0.0-rc.27 … 1.0.2` | — | — | — | — |
| `vlt update` re-resolves an unchanged exact spec (dropping a hosted pin); earlier releases keep the locked node | `>= 1.0.8` | — | — | — | — |
| vlt.json spells the scope map `scoped-registries` (`scope-registries` before) | `>= 1.0.0-rc.28` | — | — | — | — |
| a workspace member's direct dependency with resolved peers (use-sync-external-store beside react) gets a peer extra (`~peer.1`); vendored mode writes its `file` node without the extra, as vlt writes `file:` dependencies, and `single_peer_context` / `peer_member_selfref` pin the lock byte-stable through `vlt ci`, `vlt install --frozen-lockfile` and `vlt install <new>` | `>= 1.0.0-rc.15` | — | — | — | — |
| the root importer's direct dependency with resolved peers gets a peer extra (`~peer.<16 hex>`); vendored mode drops it the same way (`single_peer_context`, `peer_root_selfref`) | `>= 1.0.8` | — | — | — | — |
| two workspaces with use-sync-external-store beside react 17 and react 18 share ONE peer instance (`peer_workspace_instances` pins the count); no real-vlt shape was found that writes several instances of one name@version, so multi-instance pinning is covered by the in-process goldens only | `all` | — | — | — | — |

## OS coverage

The legs run on Linux, macOS and Windows. The Linux-default `auto` store
linker (hardlinks, `safety/linux_auto`) cannot run on macOS or Windows; it is
covered on Linux by the CI `e2e` row `e2e_safety_vlt` on ubuntu with vlt
1.2.0 and by `vlt-compatibility.yml`'s store-linker rows, and was also run
locally in `node:24-slim` under Docker. Windows-only legs
(`setup/hook_abort_leaves_no_staging`, the junction and dir-symlink store
cases) run on the Windows rows.
