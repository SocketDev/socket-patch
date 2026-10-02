> **Part 7 of 9** of the socket-patch architecture review (snapshot `2463257`). The executive summary and ranked recommendations are in the top post.

## Part 7: Core infrastructure and agent (in-place) mode

> Scope: `api/*`, `manifest/*`, `ledgers.rs`, `constants.rs`, `patch/` (excluding `redirect/`), `policy/*`, `rollout*`, `update/*`, the CLI `update_notifier.rs`/`update.rs`, `telemetry.rs`, and the generic `utils/*` and `hash/*`.

### 7.1 Size

| Area | Prod | Inline tests | Main external tests |
|---|---:|---:|---|
| `api/*` (`client.rs` alone: 2,839 / 3,038) | 5,028 | 6,434 | retry e2e 787, proxy batch 326, blob fetcher 1,307 |
| `patch/*` without `redirect/` | 3,734 | 7,572 | apply/ + rollback/ 8,719, e2e_safety_* 4,362 |
| generic `utils/*` | ~3,730 | ~3,400 | — |
| `policy/*` | 1,942 | 1,186 | socket.yml e2e 1,025 |
| `update/*` + notifier + `commands/update.rs` | 2,351 | 2,378 | 3,311 |
| telemetry | 891 | 540 | 324 |
| rollout (core + CLI) | ~1,090 | ~950 | 1,688 |

That is about **19.6K production lines.** Comments are a large share of them: 25% of `client.rs`, 34% of `apply.rs`, 38% of `fs.rs` and 48% of `apply_lock.rs`.

### 7.2 API client

**Why `client.rs` is 2,839 production lines:**
- **~950 lines: the vendoring service**, which is not the patch API. The two-step grant + download (`fetch_vendor_package` → `download_artifact_resuming`), its types, and `download_artifact_capped`.
- **~320 lines: credentials.** Env/config resolution, a token-shape lint, org auto-resolve.
- **~200 lines: legacy proxy fallback.** The per-package GET path, `is_batch_unsupported`.
- **~80 lines: debug-ordering machinery.** A `task_local` buffer plus `HeldBack`/`hold_back_debug`, with 45 call sites in 11 files. Its only purpose is to make `--debug` output byte-identical to what a serial loop would print.
- **~650 lines: the patch API itself.**

**Three retry systems in one module:**

| Path | Policy | Retry-After | Jitter |
|---|---|---|---|
| JSON calls (`send_json_request`) | `api::retry`: 429/503 only, run-wide 60 s window | seconds or HTTP-date, via a **206-line hand-rolled HTTP-date parser** (`api/date.rs`) | seeded SplitMix |
| Vendor POST/GET (`VendorRetryPolicy`) | 429/500/502/503/504 + transport, 3 attempts | seconds only | a second `jitter_sample`, ±25% |
| Blob and diff fetch (`fetch_binary`) | **none** | — | — |

The vendor policy also has three separate hand-written retry loops, plus a first-attempt/resume split that exists only to keep the request sequence identical under prefetch. Two near-identical downloaders (`download_vendor_archive_once` and `download_artifact_capped_once`) differ only in return type and message strings.

**Three URL builders with two different policies.** `patches_path` sends an authenticated client without an org slug to `/v0/orgs/default/...`, but `binary_url` and `vendor_package_url` send the same client to the public proxy. Telemetry has a fourth copy of the decision. So when org auto-resolve fails, JSON calls go to the "default" org while blob downloads silently go to the proxy.

**No timeouts on the main paths (verified).**
- `ApiClient::new` (`client.rs:393-396`) and `plain_client()` (`:1912`) build reqwest clients with no timeout, and reqwest's default is none.
- All six timeouts in `api/` are on vendoring-service paths.
- The CLI has no wrapper around `get_json`, `post_json`, `proxy_batch_post` or `fetch_binary`.
- So `scan`, `get` and `apply` can hang indefinitely on a stalled server. **That is a real CI risk.**

**Batching is split across two crates.** The CLI owns the batch sizes (500 authenticated, 100 proxy, the 256 KiB body cap). `search_patches_batch` documents "Maximum 500" but does not enforce it.

**Other HTTP stacks** keep TLS and proxy settings consistent but diverge on timeouts, retry and error formatting:
- `RegistryClient`: 60 s timeout, no retry.
- `maven_repo.rs`: builds a fresh client for every fetch.
- Self-update: its own clients with a custom redirect policy and no retry.
- Telemetry: a new client for every event.

**Target.** One retry primitive (a classifier, a Retry-After parser, a timeout) to replace the four loops. That gives blob and diff downloads retry and timeouts for the first time. Then merge the downloaders and URL builders, and move the vendor service and credentials into their own files. `client.rs` would drop to about 1.4K lines.

### 7.3 Duplicated utilities (verified)

- **Hashing:**
  - About 30 production sites inline `hex::encode(Sha256::digest(..))`.
  - Private `sha256_hex` copies exist in `ledger_snapshots.rs`, `jvm/mod.rs` and `group_commit.rs`, and `sha1_hex` copies in `maven_repo.rs` and `jvm/mod.rs`.
  - **Name collision:** `utils::digest::sha256_hex` *validates* that a string is 64-hex, while the copies *compute* a digest. Same name, different meaning.
  - `sha512_sri` is public in `redirect/vlt_preflight.rs`, yet two vendor files re-inline it, and six test modules each define their own.
- **UUID checks:** four grammars. `client.rs` has one, with a byte-identical copy in CLI `lib.rs`; `path_safety.rs` accepts lowercase only; `apply.rs` accepts any alphanumeric plus `-` and `_`.
- **Line endings:** `utils/line_endings.rs` has 7 users, but `python_lock`, `vendor/common::detect_eol` (which contradicts `LineEndings::Mixed`), `redirect::crlf_to_lf` and `poetry_lock` each implement their own rules.
- **Purls:** `utils/purl.rs` has two builder families (unvalidated `build_*` and validated `*_purl`). `vex/product.rs` hand-rolls a third. 48 production `format!("pkg:…")` sites and 58 `starts_with("pkg:<type>/")` checks bypass `Ecosystem::from_purl`.
- **Env truthiness:** three vocabularies.
  - `"1"|"true"` in `env_compat.rs`;
  - `"1"|"true"` separately in `telemetry.rs`;
  - `1|true|yes|on|y|t` in `socket_cli_config::env_truthy`, which `update_notifier` imports.

  There are also 37 inline "empty means unset" reads in 22 files and at least four home-directory resolvers.
- **Atomic writes:** `utils/fs.rs` has six writers. `atomic_write_sync` re-implements `stage_and_rename` + `commit_stage` in blocking form. Separate stage+rename code also exists in `blob_fetcher`, `update/download.rs` and `update/swap.rs`.
- **Process spawning** is well centralized in `process.rs::resolve_tool`/`command_for`, with one exception: `vendor/pypi_hatch.rs:118` runs `Command::new("hatch").current_dir(root)` (verified). That is exactly the planted-binary pattern `process.rs:23-33` documents as unsafe: "a bare `Command::new("git")` would execute a `git` planted in the repository being scanned".

### 7.4 Agent mode

**Footprint:**
- core: apply 1,132, rollback 617, sidecars 708, diff 100, package 333, blob_fetcher 603, manifest 507;
- CLI: apply 2,237, fetch_stage 440, repair 784;
- the multi-mode rollback (2,660) and remove (1,571) carry agent legs;
- over 13K dedicated test lines.

Counting the agent arms in `scan`, `get` and `rollback`, agent mode is **about 6.4K CLI production lines** plus ~3.5K in core.

**The safety model is sound and worth keeping:**
- every manifest path is escape-checked;
- blob hashes must be 64-hex, and blob entries are read with lstat and FIFO-safe;
- patched bytes are hash-verified *before* any write;
- writes are stage + fsync + rename (which keeps pnpm, uv and Go cache hardlinks safe);
- read-only parent directories are relaxed and restored, and mode and uid/gid are preserved.

The default `MismatchPolicy::Warn` silently overwrites locally modified dependency files with the verified content; `--strict` is opt-in.

**Apply and rollback are mirror images.** `VerifyStatus`/`VerifyResult` and `VerifyRollbackStatus`/`VerifyRollbackResult` have identical fields. `fold_copy_result`, the pnpm peer-copy fan-out and the sidecar boundary are each written twice. Rollback is apply with before/after swapped, plus deleting files the patch created, and could be one engine.

**`--download-mode diff` is the default and is a net loss (verified).** On a cold cache it fetches every diff archive *and then every blob anyway*:
- `blob_scope = manifest` whenever any archive was missing (`fetch_stage.rs:377-385`);
- the CLI even prints "Also fetching N per-file blobs (used where a diff does not apply)";
- everything is staged in a tempdir and thrown away after the run.

So diff only saves bytes when a user commits `.socket/diffs` but not `.socket/blobs`. The diff fetch is also sequential with no retry, and it is the only user of the `qbsdiff` dependency. Blob downloads are sequential with no retry too, while the JSON calls run 32 at a time.
- **Recommendation:** make `file` the default (keep `diff` as an alias for one major), then delete `patch/diff.rs`, the diff branches in `blob_fetcher`/`fetch_stage`/`repair`, and `qbsdiff`.
- **Saving:** about 600 production and 1,000 test lines, plus one dependency.

**Sidecars** (`patch/sidecars/`, 708 production / 1,312 test lines) are post-apply fixes for package-manager checksum files:
- cargo: rewrite `.cargo-checksum.json`;
- NuGet: delete `.nupkg.metadata`;
- PyPI, gem and Go: advisory text only.

Maven sidecars are not handled at all. This code exists only for in-place mode.

**`apply.lock`** is 554 production lines. Most of that complexity comes from *deleting* the lock file on exit: unlinking while it is held, identity checks, Windows delete-pending handling. Lock acquisition also replays the vendored group-commit journal, which couples vendored crash recovery into every command's lock. Leaving a gitignored lock file on disk (the convention every package manager uses) would cut about 150 lines.

**Dead path (verified):** `PatchSources::mem_blobs` is never `Some` in production, but its doc still says vendor flows stage content there.

### 7.5 Features with questionable value

| Feature | Prod / tests | Verdict |
|---|---|---|
| **Self-update + passive notifier** | 2,351 / 5,689 | Only `Standalone` installs self-update; npm, cargo and brew are redirected to their own tools. Still detects `Pypi` and `LauncherCache` channels that v5 no longer publishes. Two metadata strategies, a separate lock, and its own stage writer. **Keep the notifier; replace `--update` with "re-run install.sh"** (or keep a much thinner swap). Up to −1K production and −3K test lines. |
| **Telemetry** | 891 / 864 | 17 near-identical `track_*` wrappers (~450 lines); a new HTTP client per event; endpoint logic duplicated; the CLI threads token/org through 125 signature sites. **Collapse to one `track(Event)` with a shared client** (~−300). |
| **Failpoints** | 65 | Fine (compiled out of release). But `switched_off("group_commit")` keeps the *old non-group-commit path* alive as a test oracle. |
| **group_commit + durability** | 1,376 / 1,287 | A process-wide virtual filesystem: every `utils::fs` read and write consults it. It renders typed values lazily via `Any`, does three-way hand-edit reconciliation in `recover`, and still journals `redirect-state.json`, which nothing writes. Writes that bypass `utils::fs` are silently not captured. High-cost machinery for a vendored-run speedup; see 5.7 for the root-cause fix. |
| **socket.yml policy** | 1,942 / 2,211 | Real value. But `socket_yml.rs` builds its own YAML node tree on serde-saphyr's *event* parser (`:36-320`) to read **8 keys**, with edit-distance "did you mean" hints and repository-ownership trust checks. The `deserialize` feature is enabled, but nothing uses it through serde. **Replace with serde + `deny_unknown_fields`** plus a small strictness check (~−500). |
| **Rollout / `--max-new-patches`** | ~1,090 / ~2,640 | Pure planning, threaded through the hosted `Gate`, the agent stage and a cross-directory carry. The in-memory engine (PR bots) uses it. Keep it in socket.yml; consider dropping the flag and env layering. |
| **socket-cli config reuse** | 232 / 1,022 | Cheap and valuable. Keep. |
| **Legacy redirect ledger** | spread across vex, rollback, group_commit | Read-only since v5. Set a sunset date. |

### 7.6 Recommendations

1. **Make `file` the default download mode** and delete the diff machinery: −600 production, −1K tests, −1 dependency. Low risk.
2. **One retry and timeout primitive** across every HTTP path, so the JSON and blob paths get timeouts: −200 production. **Fixes possible indefinite hangs.** Medium risk, because tests pin the current semantics.
3. **Delete the verified dead and legacy code:** `mem_blobs`, `save_redirect_state` and its group-commit `LEDGERS` entry, the `Pypi`/`LauncherCache` update channels, and the `switched_off("group_commit")` oracle path. −150 production, −300 tests.
4. **Fold rollback into the apply engine** (swap hashes, keep a delete branch for created files): −300 production.
5. **One telemetry `track(Event)`** with a shared client: −300.
6. **One validated purl builder family**, and `Ecosystem::from_purl` for type checks: −250.
7. **Small helper consolidation:**
   - digest compute vs. validate;
   - SRI;
   - hex and UUID checks;
   - line endings;
   - env truthiness;
   - home dir;
   - **fix the bare `hatch` spawn**.

   Saves about −200.
8. **Split `client.rs`** into client, vendor_service and credentials, and give it a single auth-vs-proxy URL policy.
9. **Replace the hand-rolled socket.yml tree with serde:** −500.
10. **Re-scope self-update:** keep the notifier, consider dropping the binary swap.

---
_Generated by [Claude Code](https://claude.ai/code)_
