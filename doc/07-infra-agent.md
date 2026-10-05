> [agent] **Part 7 of 9** of the living socket-patch architecture document. The summary and ranked recommendations are in the top post. Originally written against `2463257`; the routines update this part as the code changes.

## Part 7: Core infrastructure and agent (in-place) mode

_Last checked against main @ 0d302dc on 2026-10-05 by audit-core. Owner: audit-core._ Re-checked on `0d302dc`: the `api/*` size row, the `client.rs` breakdown, the retry table, the registry-client timeout, process spawning and hash case. The timeout, blob/diff body, zip-read, process-spawning, API-pacing, URL-builder, retry, batching, hashing, UUID, env/home-dir, atomic-write, purl, dead-code, telemetry, apply/rollback-engine, diff-download, `apply.lock`, Maven-sidecar, group-commit-reader, socket.yml and spawn-deadline passages were re-checked on `045d7ec`; the rest is as of `2463257`.

> Scope: `api/*`, `manifest/*`, `ledgers.rs`, `constants.rs`, `patch/` (excluding `redirect/`), `policy/*`, `rollout*`, `update/*`, the CLI `update_notifier.rs`/`update.rs`, `telemetry.rs`, and the generic `utils/*` and `hash/*`.

### 7.1 Size

| Area | Prod | Inline tests | Main external tests |
|---|---:|---:|---|
| `api/*` (`client.rs` alone: 2,918 / 3,115 on `0d302dc`) | 5,208 | 6,613 | retry e2e 787, proxy batch 326, blob fetcher 1,307 |
| `patch/*` without `redirect/` | 3,734 | 7,572 | apply/ + rollback/ 8,719, e2e_safety_* 4,362 |
| generic `utils/*` | ~3,730 | ~3,400 | — |
| `policy/*` | 1,942 | 1,186 | socket.yml e2e 1,025 |
| `update/*` + notifier + `commands/update.rs` | 2,351 | 2,378 | 3,311 |
| telemetry | 891 | 540 | 324 |
| rollout (core + CLI) | ~1,090 | ~950 | 1,688 |

That is about **19.6K production lines.** Comments are a large share of them: 25% of `client.rs`, 34% of `apply.rs`, 38% of `fs.rs` and 48% of `apply_lock.rs`.

### 7.2 API client

**Why `client.rs` is 2,918 production lines** (on `0d302dc`; moving the vendor service out is {{C29}}):
- **~950 lines: the vendoring service**, which is not the patch API. The two-step grant + download (`fetch_vendor_package` → `download_artifact_resuming`), its types, and `download_artifact_capped`.
- **~320 lines: credentials.** Env/config resolution, a token-shape lint, org auto-resolve.
- **~200 lines: legacy proxy fallback.** The per-package GET path, `is_batch_unsupported`.
- **~80 lines: debug-ordering machinery.** A `task_local` buffer plus `HeldBack`/`hold_back_debug`, with 45 call sites in 11 files. Its only purpose is to make `--debug` output byte-identical to what a serial loop would print.
- **~650 lines: the patch API itself.**

**Three retry systems in one module:** {{C15}}

| Path | Policy | Retry-After | Jitter |
|---|---|---|---|
| JSON calls (`send_json_request`) | `api::retry`: 429/503 only, run-wide 60 s window | seconds or HTTP-date, via a **206-line hand-rolled HTTP-date parser** (`api/date.rs`) | seeded SplitMix |
| Vendor POST/GET (`VendorRetryPolicy`) | 429/500/502/503/504 + transport, 3 attempts | seconds only (an HTTP-date is ignored, shown by execution on `045d7ec`) | a second `jitter_sample`, ±25% |
| Blob and diff fetch (`fetch_binary`) | **none** | — | — |

The vendor policy also has three separate hand-written retry loops, plus a first-attempt/resume split that exists only to keep the request sequence identical under prefetch. Two near-identical downloaders (`download_vendor_archive_once` and `download_artifact_capped_once`) differ only in return type and message strings.

**Three URL builders with two different policies.** `patches_path` sends an authenticated client without an org slug to `/v0/orgs/default/...`, but `binary_url` and `vendor_package_url` send the same client to the public proxy. Telemetry has a fourth copy of the decision. So when org auto-resolve fails, JSON calls go to the "default" org while blob downloads silently go to the proxy. Re-verified by execution on `045d7ec`: view and batch go to `/v0/orgs/default/patches/…` with the bearer, while blob, diff, vendor references and telemetry go anonymously to `patches-api.socket.dev/patch/…`. {{C07}}

**Timeouts on the main paths (#581).**
- `ApiClient::new` and `plain_client()` build both reqwest clients through one policy, `api::retry::ApiTimeouts`: `API_CONNECT_TIMEOUT` (10 s) and `API_READ_TIMEOUT` (60 s of silence, reset per chunk), with no total deadline. Tests override it with `ApiClient::with_api_timeouts`. {{C02}}
- A stall before the headers or mid-body fails as `ApiError::Network`; the three JSON readers share `json_response_error`, so a stalled body keeps its transport cause and only complete malformed JSON is `Parse`.
- The vendoring service keeps its own per-attempt deadlines and retries on top. Blob/diff fetches still have no retry (C15).

**Batching is defined three times.** The CLI owns the batch sizes (500 authenticated, 100 proxy, the 256 KiB body cap) and accepts any `--batch-size`. The in-memory hosted engine keeps its own copy (default 100 on either endpoint, max 500, no body-cap split, a second `MAX_REFERENCE_BATCH`). `search_patches_batch` documents "Maximum 500" but does not enforce it, while `fetch_registry_references` chunks itself. {{C16}}

**Other HTTP stacks** keep TLS and proxy settings consistent but diverge on timeouts, retry and error formatting:
- `RegistryClient` (hosted upstream restore) and vendored Maven's per-fetch client: a 60 s *whole-request* deadline and no connect bound, so a slow but progressing artifact download is aborted at 60 s (shown by execution on `0d302dc`); no retry. `registry_fetch::download` hand-rolls `read_capped`. {{C49}}
- `maven_repo.rs`: builds a fresh client for every fetch.
- Self-update: its own clients with a custom redirect policy and no retry.
- Telemetry: a new client for every event.

**Target.** One retry primitive (a classifier, a Retry-After parser, a timeout) to replace the four loops. That gives blob and diff downloads retry and timeouts for the first time. Then merge the downloaders and URL builders, and move the vendor service and credentials into their own files. `client.rs` would drop to about 1.4K lines.

### 7.3 Duplicated utilities (verified)

- **Hashing:**
  - About 23 production sites inline `hex::encode(Sha256::digest(..))`, and 3 inline `hex::encode(Sha1::digest(..))`. {{C17}}
  - Private `sha256_hex` copies exist in `ledger_snapshots.rs`, `jvm/mod.rs` and `group_commit.rs`, and `sha1_hex` copies in `maven_repo.rs` and `jvm/mod.rs`.
  - **Name collision:** `utils::digest::sha256_hex` *validates* that a string is 64-hex, while the copies *compute* a digest. Same name, different meaning.
  - `sha512_sri` is public in `redirect/vlt_preflight.rs`, yet two vendor files re-inline it, and six test modules each define their own.
  - The 64-hex validator exists three times: `apply::is_valid_blob_hash`, `client::is_valid_sha256_hex` and `digest::is_hex(s, 64)`.
- **UUID checks:** five grammars. `client.rs` has one, with a near byte-identical copy in CLI `lib.rs`; `path_safety.rs` accepts lowercase only; `apply.rs` accepts any alphanumeric plus `-` and `_`; `utils/python_script.rs` uses `uuid::Uuid::parse_str`, which also takes simple, braced and `urn:uuid:` forms. {{C18}}
- **Line endings:** `utils/line_endings.rs` has 7 users, but `python_lock`, `vendor/common::detect_eol` (which contradicts `LineEndings::Mixed`), `redirect::crlf_to_lf` and `poetry_lock` each implement their own rules.
- **Purls:** `utils/purl.rs` has two builder families (7 unvalidated `build_*` with 21 production callers, and the validated `*_purl`). `vex/product.rs` hand-rolls a third. 42 production `format!("pkg:…")` sites outside `utils/purl.rs` and 24 `starts_with("pkg:<type>/")` checks outside `Ecosystem::from_purl` (counted at `045d7ec`, production code only). The type checks agree today, but the builders already disagree on canonicalization (PyPI names and composer case). {{C20}}
- **Env truthiness:** three vocabularies, plus a fourth rule in `update_notifier::in_ci`. {{C19}}
  - `"1"|"true"` in `env_compat.rs` (`SOCKET_DEBUG`, `SOCKET_OFFLINE`);
  - `"1"|"true"` separately in `telemetry.rs`;
  - `1|true|yes|on|y|t` in `socket_cli_config::env_truthy`, which `update_notifier` imports, and the same set in the CLI's clap `parse_bool_flag`.

  The narrow core match stays correct only because `apply_env_toggles` rewrites every truthy flag back into the env as `"1"`; all ten command entry points call it on `045d7ec`. "Empty means unset" is one private helper (`socket_cli_config::env_non_empty`) plus about 29 inline copies in 16 files. In this area there are at least six home-directory resolvers, and they disagree: `policy::home_dir` reads only `USERPROFILE` on Windows, while `utils::fs::home_dir` prefers `HOME`. The crawlers keep further variants.
- **Atomic writes:** `utils/fs.rs` has six writers, which are four boolean policies (capture, fsync, keep mode, durability record) spelled as separate functions. `atomic_write_sync` re-implements `stage_and_rename` + `create_stage` + `commit_stage` in blocking form, with no drift yet. `blob_fetcher::write_cache_entry_atomic` is a third, deliberately non-fsyncing stage+rename. The self-update stage (`update/download.rs`, `update/swap.rs`) is legitimately separate. Correction: the artifact writers inside `utils::fs` don't capture into a group commit either, so bypassing `utils::fs` isn't itself a group-commit escape. {{C21}} `get` writes `.socket/blobs/<hash>` with neither: it uses an in-place `fs::write` and doesn't check the content's hash ({{C42}}).
- **Process spawning** is centralized in `process.rs::resolve_tool`/`command_for`; on `0d302dc` no production `Command::new("<tool>")` remains. Vendored Hatch now resolves `hatch` through `resolve_tool_with` instead of a bare spawn in the project root (#617). {{C04}} Spawn *deadlines* are not centralized: the shared probe runners (`gem env`, `python --version`, `npm root -g`, …) have none, while four sites hand-roll `timeout` + `kill_on_drop` with 10/10/10/30–60 s budgets; on `045d7ec` a hung `gem` shim hung a local `scan` indefinitely. {{C48}}

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

**Apply and rollback are mirror images.** `VerifyStatus`/`VerifyResult` and `VerifyRollbackStatus`/`VerifyRollbackResult` have identical fields. `fold_copy_result`, the pnpm peer-copy fan-out and the sidecar boundary are each written twice, and the two folds have already drifted: apply carries only the ownership advisory, rollback any advisory, and both drop the copy's per-file records, so a run that writes only a store copy reports `already_patched`/`already_original` (#756). Rollback is apply with before/after swapped, plus deleting files the patch created, and could be one engine. {{C24}}

**`--download-mode diff` is the default and is a net loss (verified).** On a cold cache it fetches every diff archive *and then every blob anyway*:
- `blob_scope = manifest` whenever any archive was missing (`fetch_stage.rs:377-385`);
- the CLI even prints "Also fetching N per-file blobs (used where a diff does not apply)";
- everything is staged in a tempdir and thrown away after the run.

So diff only saves bytes when a user commits `.socket/diffs` but not `.socket/blobs`. The diff fetch is also sequential with no retry, and it is the only user of the `qbsdiff` dependency. Blob downloads are sequential with no retry too, while the JSON calls run 32 at a time.
- **Recommendation:** make `file` the default (keep `diff` as an alias for one major), then delete `patch/diff.rs`, the diff branches in `blob_fetcher`/`fetch_stage`/`repair`, and `qbsdiff`.
- **Saving:** about 600 production and 1,000 test lines, plus one dependency. Re-verified on `045d7ec` (top-up at `fetch_stage.rs:377-398`; diff-only code includes `patch/diff.rs` (99 production lines) and `patch/package.rs` (332)). The default change is a contract MAJOR, so it is filed as a decision. {{C25}}

**Sidecars** (`patch/sidecars/`, 708 production / 1,312 test lines) are post-apply fixes for package-manager checksum files:
- cargo: rewrite `.cargo-checksum.json`;
- NuGet: delete `.nupkg.metadata`;
- PyPI, gem and Go: advisory text only.

Agent mode writes no Maven sidecar, and needs none: Maven 3.9.11 doesn't verify the local repository's `.sha1` files, so a jar patched in place under a stale `.jar.sha1` still builds and runs (checked on `045d7ec`; the review's concern is rejected). The real Gradle gap is that the crawler patches `~/.m2`, which a Gradle-only build never reads (#551). {{C27}} This code exists only for in-place mode.

**`apply.lock`** is 553 production lines (re-checked on `045d7ec`). Most of that complexity comes from *deleting* the lock file on exit: unlinking while it is held, identity checks, Windows delete-pending handling. Lock acquisition also replays the vendored group-commit journal, which couples vendored crash recovery into every command's lock. Leaving a gitignored lock file on disk (the convention every package manager uses), or locking a file outside the project, would cut about 200 lines; the v5.0 contract promises the transient file, so this is a decision. Moving the journal replay and the durability barrier out of the lock primitive changes no behavior. {{C26}}

**Dead path (verified):** `PatchSources::mem_blobs` is never `Some` in production, but its doc still says vendor flows stage content there. {{C23}}

### 7.5 Features with questionable value

| Feature | Prod / tests | Verdict |
|---|---|---|
| **Self-update + passive notifier** | 2,351 / 5,689 | Only `Standalone` installs self-update; npm, cargo and brew are redirected to their own tools. Still detects the pre-v5 `Pypi` and `LauncherCache` channels, which is a live refusal for old installs, not dead code. Two metadata strategies, a separate lock, and its own stage writer. **Keep the notifier; replace `--update` with "re-run install.sh"** (or keep a much thinner swap). Up to −1K production and −3K test lines. |
| **Telemetry** | 891 / 864 | 19 near-identical public wrappers (17 `track_*` + 2 `spawn_*`, ~450 lines); a new HTTP client per event; endpoint logic duplicated. The CLI passes token/org at ~45 call sites in 10 command files, plus 5 helper signatures (not 125), and resolves them two ways: `telemetry_credentials()` in `list`/`vex`, the API client's getters elsewhere. **Collapse to one `Telemetry` handle with `track(Event)` and a shared client** (~−300). {{C22}} |
| **Failpoints** | 65 | Fine (compiled out of release). But `switched_off("group_commit")` keeps the *old non-group-commit path* alive as a test oracle. |
| **group_commit + durability** | 1,376 / 1,287 | A process-wide virtual filesystem: every `utils::fs` read and write consults it. It renders typed values lazily via `Any`, does three-way hand-edit reconciliation in `recover`, and still journals `redirect-state.json`, which nothing writes. Writes that bypass `utils::fs` are silently not captured. High-cost machinery for a vendored-run speedup; see 5.7 for the root-cause fix. |
| **socket.yml policy** | 1,942 / 2,211 | Real value. `socket_yml.rs` builds its own YAML node tree on serde-saphyr's *event* parser (`:36-320`, ~285 lines) to read **8 keys**. Re-checked on `045d7ec`: the tree is what implements the contract's validation rules (CLI_CONTRACT "Validation (fail closed)"): no alias expansion outside the keys read, anchors, aliases, merge keys and custom tags refused only inside `patches`/`projectIgnorePaths`, YAML 1.2 core-schema scalars (`enabled: yes` is an error), and per-key paths with did-you-mean hints. serde with `deny_unknown_fields` can't scope those refusals to one subtree of a file other Socket tools share, and the ~300 lines of validators would stay. Not a defect. {{C28}} |
| **Rollout / `--max-new-patches`** | ~1,090 / ~2,640 | Pure planning, threaded through the hosted `Gate`, the agent stage and a cross-directory carry. The in-memory engine (PR bots) uses it. Keep it in socket.yml; consider dropping the flag and env layering. |
| **socket-cli config reuse** | 232 / 1,022 | Cheap and valuable. Keep. |
| **Legacy redirect ledger** | spread across vex, rollback, group_commit | Read-only since v5. Set a sunset date. |

### 7.6 Recommendations

1. **Make `file` the default download mode** and delete the diff machinery: −600 production, −1K tests, −1 dependency. Low risk.
2. **One retry and timeout primitive** across every HTTP path, so the JSON and blob paths get timeouts: −200 production. **Fixes possible indefinite hangs.** Medium risk, because tests pin the current semantics.
3. **Delete the verified dead and legacy code:** `mem_blobs`, the always-true `VendorSource` predicates, the `redirect-state.json` group-commit `LEDGERS` entry, and the `switched_off("group_commit")` oracle path. About −60 production, −350 tests. {{C23}} (The `Pypi`/`LauncherCache` update channels are *not* dead: they make `--update` refuse to swap a pre-v5 pip/gem-owned binary and print a migration hint.)
4. **Fold rollback into the apply engine** (swap hashes, keep a delete branch for created files): −300 production. {{C24}}
5. **One telemetry `track(Event)`** with a shared client: −300. {{C22}}
6. **One validated purl builder family**, and `Ecosystem::from_purl` for type checks: −250.
7. **Small helper consolidation:**
   - digest compute vs. validate;
   - SRI;
   - hex and UUID checks;
   - line endings;
   - env truthiness;
   - home dir;
   - (the bare `hatch` spawn is already fixed, #617).

   Saves about −200.
8. **Split `client.rs`** into client, vendor_service and credentials, and give it a single auth-vs-proxy URL policy.
9. **Keep the socket.yml event tree:** on re-check it is the contract's validator, so serde would save little and lose the scoped refusals. {{C28}}
10. **Re-scope self-update:** keep the notifier, consider dropping the binary swap.

### New findings since the review

- {{C37}} Patch blob and diff downloads (`fetch_blob` / `fetch_diff`, via `fetch_binary`) return a `BinaryBody` stream, and one `blob_fetcher::download_entries` loop stages each body chunk by chunk to disk (`stage_body`), verifies blobs against their git-sha256 name and renames into place; no artifact body is held in memory, per the maintainer's stream-don't-cap steering. Vendor and self-update downloads keep the shared `read_capped` (256 MiB).
- {{C38}} API pacing has one policy (`utils::concurrent`: proxy cap 4, `SOCKET_API_CONCURRENCY` override, fd-limit rule), and every CLI window uses it, except the client's own public-proxy per-package fallback. That fallback keeps a private `PROXY_BATCH_PATH_CONCURRENCY = 10`, and on `045d7ec` it ran 10 GETs in flight with `SOCKET_API_CONCURRENCY=1`. `registry_concurrency()` has no caller.
- {{C41}} Hash case policy is decided per site. Blob download compares case-insensitively on purpose (`blob_hash_matches`), and the blob-name validators accept uppercase, but agent-mode apply and rollback verify with exact `==` against the lowercase computed hash; vendored verify sites are split the same way. On `045d7ec` an uppercased manifest hash downloaded and passed `is_valid_blob_hash`, then failed both apply and rollback verification with `HashMismatch`.
- {{C42}} `.socket/blobs/<hash>` has two writers. The fetch path verifies the git-sha256 and stages+renames, because `get_missing_blobs` trusts presence. `get::write_blob_entry` stores a patch view's inline `blobContent` under its claimed hash without checking it, truncate-writes in place, and overwrites an existing verified blob; it also hand-rolls base64 although the crate is a dependency. On `045d7ec` a verified `blobs/<H>` was replaced with bytes that don't hash to `H`.
- {{C46}} The vendored group-commit journal is replayed only inside `apply_lock::acquire`, so the lock-free readers never see a pending commit: after a crash past the journal, `vendor --check` fails every patch with `vendor_ledger_missing` (whose documented remedy is restoring `state.json` by hand) and pnpm `vex` omits the packages, while one locked command rolls the commit forward to the uninterrupted result (proved twice with `group_commit_file@1`).
- {{C49}} Registry downloads (`build_registry_client`, `maven_repo::fetch_registry_bytes`) use a 60 s total deadline instead of `ApiTimeouts`' 10 s connect + 60 s idle bound. On `0d302dc`, a body trickling 64 KiB/s was aborted at 60.0 s after 3.9 MB by the registry client, while an `ApiTimeouts` client read all 4.6 MB in 69 s (twice). Hosted upstream restore and vendored Maven jar fetches go through it.
- {{C48}} Child processes have no shared deadline. `SystemCommandRunner`/`GlobalProbeRunner` call `output()` unbounded, while `pipenv`, `hatch`, self-update `sanity_exec` and the `git check-ignore` exchange each hand-roll a timeout. On `045d7ec`, a `gem` shim that never answers made `scan --json` in a Bundler project hang with no output (killed at 45 s and at 90 s); with the real `gem` it finished in 1 s.

---
_Generated by [Claude Code](https://claude.ai/code)_
