> [agent] **Part 7 of 9** of the living socket-patch architecture document. The summary and ranked recommendations are in the top post. Originally written against `2463257`; the routines update this part as the code changes.

## Part 7: Core infrastructure and agent (in-place) mode

_Last checked against main @ 31383f5 on 2026-10-09 by audit-core. Owner: audit-core._ Re-checked on `31383f5` (15:40Z run): the UUID grammars after #1034 and the VEX write after #1262. Re-checked on `a80b89e` (09:40Z run): the URL-builder passage after #1041 (one `ApiRoute` per run, client construction per command), HTTP body reads (only the self-update, vendor, Maven and vlt downloads are capped; uncapped blob/JSON bodies are the maintainer's #571 call), production process spawns (all bounded) and the failpoint/switch-off hooks (debug or `failpoints`-feature builds only). Re-checked on `f3c6313` (03:40Z run): public-registry fan-out against `utils::concurrent` (C78), and dead `pub fn`s in `utils/`, `api/` and `update/`. Re-checked on `830749f` (21:40Z run): `apply.lock` after #1030 (interrupt cleanup), the HTTP client builders and timeouts, the FIFO-safe readers of every `.socket` store, and lock acquisition per command (all through `lock_cli`). Re-checked on `823810a` (15:40Z run): production file writes outside `utils::fs` (only the VEX document, C77, plus self-update, `apply.lock` and blob-fetch staging), PATH resolution of spawned tools (all through `resolve_tool`), the GC retention split (C50, unchanged), and the C60/C63 passages after #887's close and #1045. Re-checked on `b96a785` (09:40Z run): env truthiness and home-directory resolvers after #1038, and the test-telemetry boundary after #1046. Re-checked on `b762f41` (03:40Z run): 7.3 atomic writes and the 7.7 containment and credentials rows after #1042 and #1070, hash-case verify sites, and the TLS trust roots of every HTTP client (C75). Earlier: `431b818` by the October 7 reconciliation (7.3 spawn deadlines, the 7.4 safety model and the new 7.7 security boundaries); `c5be5d1` by audit-core. Re-checked on `c5be5d1` (15:50Z run): 7.2 retry table and registry timeouts after #889 and #876. Re-checked on `9c43dfc` (09:56Z run): the 7.4 agent-mode footprint, the sidecar list (Maven rewriter from #646) and which ecosystems need agent mode. Re-checked on `9c43dfc`: the self-update footprint and its overlap with `install.sh` (7.5), the credentials block of `client.rs`, agent-mode jar member verification, the apply/rollback store-copy fold and the artifact-retention (GC) policies. Re-checked on `0d302dc`: the `api/*` size row, the `client.rs` breakdown, the retry table, the registry-client timeout, process spawning and hash case. The timeout, blob/diff body, zip-read, process-spawning, API-pacing, URL-builder, retry, batching, hashing, UUID, env/home-dir, atomic-write, purl, dead-code, telemetry, apply/rollback-engine, diff-download, `apply.lock`, Maven-sidecar, group-commit-reader, socket.yml and spawn-deadline passages were re-checked on `045d7ec`; the rest is as of `2463257`. 2026-10-07 14:00Z: 7.2, 7.4, 7.5 and 7.6 record the maintainer's decisions on #648, #792, #808, #983 and #1000 (no code re-check).

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
- **~330 lines: credentials** (L2039–L2368 on `9c43dfc`). Env/config resolution, a token-shape lint, org auto-resolve and the proxy-fallback client builder; moving them out is the second C29 issue, #913. Per #648 the org-resolve step will produce the run's single route, so #913 and the #648 PR rebase on each other.
- **~200 lines: legacy proxy fallback.** The per-package GET path, `is_batch_unsupported`.
- **~80 lines: debug-ordering machinery.** A `task_local` buffer plus `HeldBack`/`hold_back_debug`, with 45 call sites in 11 files. Its only purpose is to make `--debug` output byte-identical to what a serial loop would print.
- **~650 lines: the patch API itself.**

**Three retry systems in one module:** {{C15}}

| Path | Policy | Retry-After | Jitter |
|---|---|---|---|
| JSON calls (`send_json_request`) | `api::retry`: 429/503 only, run-wide 60 s window | seconds or HTTP-date, via a **206-line hand-rolled HTTP-date parser** (`api/date.rs`) | seeded SplitMix |
| Vendor POST/GET (`VendorRetryPolicy`) | 429/500/502/503/504 + transport, 3 attempts | seconds or HTTP-date through the shared `api::retry::parse_retry_after` (#889) | `api::retry::jitter_sample`, ±25% |
| Blob and diff fetch (`fetch_binary`) | **none** | — | — |

The vendor policy also has three separate hand-written retry loops, plus a first-attempt/resume split that exists only to keep the request sequence identical under prefetch. Two near-identical downloaders (`download_vendor_archive_once` and `download_artifact_capped_once`) differ only in return type and message strings.

**One API route per run (#1041).** `get_api_client_with_overrides` resolves the org once, when the run's client is built, into one `ApiRoute` (`Org{slug}` or `Proxy`). `patches_path`, the batch 404 message, `binary_url`, `vendor_package_url` and telemetry (`TelemetryAuth::for_client`) all read it. A token whose org auto-resolve fails sends the whole run to the public proxy anonymously (a proxy client never keeps the token), with one stderr warning and an `api_auth_fallback` entry in `warnings[]`, never `/v0/orgs/default`. Embedded `--vex` reuses the host's client. On `a80b89e` every command builds at most one client per run (`repair`, vendored repair and `rollback` build theirs lazily or pass it down). Commands with no client (`list`, standalone `vex` before a fetch) route telemetry through `GlobalArgs::telemetry_auth`, which still depends on `apply_env_toggles` mirroring `--api-url`/`--proxy-url` (C10). The mid-run 401/403 proxy swap is separate (C09). {{C07}}

**Timeouts on the main paths (#581).**
- `ApiClient::new` and `plain_client()` build both reqwest clients through one policy, `api::retry::ApiTimeouts`: `API_CONNECT_TIMEOUT` (10 s) and `API_READ_TIMEOUT` (60 s of silence, reset per chunk), with no total deadline. Tests override it with `ApiClient::with_api_timeouts`. {{C02}}
- A stall before the headers or mid-body fails as `ApiError::Network`; the three JSON readers share `json_response_error`, so a stalled body keeps its transport cause and only complete malformed JSON is `Parse`.
- The vendoring service keeps its own per-attempt deadlines and retries on top. Blob/diff fetches still have no retry (C15).

**Batching is defined three times.** The CLI owns the batch sizes (500 authenticated, 100 proxy, the 256 KiB body cap) and accepts any `--batch-size`. The in-memory hosted engine keeps its own copy (default 100 on either endpoint, max 500, no body-cap split, a second `MAX_REFERENCE_BATCH`). `search_patches_batch` documents "Maximum 500" but does not enforce it, while `fetch_registry_references` chunks itself. {{C16}}

**Other HTTP stacks** keep TLS and proxy settings consistent but diverge on timeouts, retry and error formatting:
- `RegistryClient` (hosted upstream restore) and vendored Maven's per-fetch client are built by one `registry_client_builder` on `ApiTimeouts` (10 s connect, 60 s idle), and `registry_fetch::download` reads through the shared `read_capped` (#876); no retry. {{C49}}
- `maven_repo.rs`: builds a fresh client for every fetch.
- Self-update: its own clients with a custom redirect policy and no retry.
- Telemetry: a new client for every event.

**Target.** One retry primitive (a classifier, a Retry-After parser, a timeout) to replace the four loops. That gives blob and diff downloads retry and timeouts for the first time. Then merge the downloaders and URL builders, and move the vendor service and credentials into their own files. `client.rs` would drop to about 1.4K lines.

### 7.3 Duplicated utilities (verified)

- **Hashing:**
  - Since #865, `utils::digest` holds the computations beside the validators: `sha256_hex_of`, `sha1_hex_of`, `sha512_base64_of` and `sha512_sri_of`. Production code in 14 files goes through them, and the ratchet test `production_digests_go_through_the_helpers` fails on a new inline copy. {{C17}}
  - Six production files still compute inline (its `PENDING_INLINE_DIGESTS` list; the 2026-10-08 backlog review deferred this slice, #706): `group_commit.rs`, `jvm/mod.rs`, `maven_repo.rs`, `pypi.rs`, `redownload.rs` and `yarn_berry_lock.rs`. Private `sha256_hex` copies remain in `jvm/mod.rs` and `group_commit.rs`, and `sha1_hex` copies in `maven_repo.rs` and `jvm/mod.rs`.
  - **Name collision:** `utils::digest::sha256_hex` still *validates* a 64-hex string, while the `jvm` and `group_commit` copies *compute* a digest. The new helpers avoid it with an `_of` suffix.
  - `vlt_preflight::sha512_sri` and the inline SRI blocks in `npm_pack` and `bun_lock` are gone; test modules still define their own.
  - The 64-hex validator exists twice: `apply::is_valid_blob_hash` and `digest::is_hex(s, 64)` (`client::is_valid_sha256_hex` was folded into the latter by #865).
- **UUID checks:** four grammars. `api/client.rs` and CLI `lib.rs` share `utils::target::is_uuid_shaped` (8-4-4-4-12 hex, any case) since #1034; `path_safety.rs` accepts lowercase only; `apply.rs` accepts any alphanumeric plus `-` and `_`; `utils/python_script.rs` uses `uuid::Uuid::parse_str`, which also takes simple, braced and `urn:uuid:` forms. {{C18}}
- **Line endings:** `utils/line_endings.rs` has 7 users, but `python_lock`, `vendor/common::detect_eol` (which contradicts `LineEndings::Mixed`), `redirect::crlf_to_lf` and `poetry_lock` each implement their own rules.
- **Purls:** `utils/purl.rs` has two builder families (7 unvalidated `build_*` with 21 production callers, and the validated `*_purl`). `vex/product.rs` hand-rolls a third. 42 production `format!("pkg:…")` sites outside `utils/purl.rs` and 24 `starts_with("pkg:<type>/")` checks outside `Ecosystem::from_purl` (counted at `045d7ec`, production code only). The type checks agree today, but the builders already disagree on canonicalization (PyPI names and composer case). {{C20}}
- **Purl identity:** one `utils::purl_key::PurlKey` (qualifiers and subpath stripped, percent-decoded, PEP 503 PyPI names, NuGet and Composer case-folded) since #1045, which deleted the other ten equality relations and ownership matchers; vendored key sets are `HashSet<PurlKey>`. {{C63}}
- **Env truthiness:** three vocabularies, plus a fourth rule in `update_notifier::in_ci`. {{C19}}
  - `"1"|"true"` in `env_compat.rs` (`SOCKET_DEBUG`, `SOCKET_OFFLINE`);
  - `"1"|"true"` separately in `telemetry.rs`;
  - `1|true|yes|on|y|t` in `socket_cli_config::env_truthy`, which `update_notifier` imports, and the same set in the CLI's clap `parse_bool_flag`.

  The narrow core match stays correct only because `apply_env_toggles` rewrites every truthy flag back into the env as `"1"`; all ten command entry points call it on `045d7ec`. "Empty means unset" is one private helper (`socket_cli_config::env_non_empty`) plus about 29 inline copies in 16 files. Home directories now resolve through one `utils::fs::home_dir`, which returns `Option<PathBuf>` and accepts only a rooted `HOME`/`USERPROFILE` (#1038); the remaining resolvers take an injected env on purpose (`hatch_env`, `python_crawler`, `npmrc`), and the npm crawler's macOS fallback still reads `HOME` raw.
- **Atomic writes:** `utils/fs.rs` has six public writers. Each is a named `WriteOpts` policy: capture, durable (barrier + fsync + dir fsync), keep mode, and durability record. They all run one blocking core, `stage_and_rename_blocking`; the async writers run it through `run_blocking`, and `atomic_write_sync` is the core itself (#858). One `stage_path` builds every stage name: `.socket-stage-` for these writers and `.socket-dl-` for the blob cache, whose streaming writer verifies the hash between stage and rename and keeps its own body. The self-update stage (`update/download.rs`, `update/swap.rs`) is legitimately separate. The artifact writers don't capture into a group commit, so bypassing `utils::fs` isn't itself a group-commit escape. {{C21}} `get`'s inline blobs go through `blob_fetcher::store_verified_blob`, which refuses a linked level, checks the git-sha256 and stages+renames; it shares the guard and hash rule with the streaming writer but keeps its own stage-and-rename code (#1042). {{C42}}
- **Process spawning** is centralized in `process.rs::resolve_tool`/`command_for`; on `0d302dc` no production `Command::new("<tool>")` remains. Vendored Hatch now resolves `hatch` through `resolve_tool_with` instead of a bare spawn in the project root (#617). {{C04}} Spawn deadlines go through one `utils::process::output_within` (#886): every crawler probe (`run_resolved`: `gem env`, `python --version`, `npm root -g`, …) runs under `PROBE_TIMEOUT` (10 s), as do Pipenv, Hatch and the self-update `sanity_exec`, whose hand-rolled `timeout` + `kill_on_drop` blocks were deleted. The PDM site probe (`crawlers/python_crawler/pdm_site.rs`) moved onto `output_within` too (#1106), and `tests/child_deadline_guard.rs` rejects new production `kill_on_drop` spawns. One hand-rolled deadline remains: the vendored npm `git check-ignore` exchange (30 s and 60 s), on the guard's pending list (#1067). {{C48}}

### 7.4 Agent mode

**Footprint:**
- core (re-measured on `9c43dfc`): apply 1,230, rollback 751, sidecars 1,107, store_copies 332, shared_store 332, diff 99, package 332, blob_fetcher 603, manifest 578. `patch/apply.rs`, `package.rs` and `manifest/` are shared with vendored staging; the agent-only part is about 3.2K;
- CLI (on `9c43dfc`): apply 2,963 (2,237 at the review), fetch_stage 437, repair 785;
- the multi-mode rollback (2,660) and remove (1,571) carry agent legs;
- over 13K dedicated test lines.

Counting the agent arms in `scan`, `get` and `rollback`, agent mode is **about 6.4K CLI production lines** plus ~3.5K in core (review numbers; the CLI `apply.rs` has grown ~700 lines since). Deno (its only mode) and `--global` installs (hosted and vendored act on project lockfiles) have no other mode; Go's agent mode writes a `.socket/go-patches/` replace, which vendored also covers. About 29 of the open `bug` issues are agent-mode-specific, roughly twice the review's ~15. The maintainer decided to keep agent mode for every ecosystem for now (#1000, option A); its open bugs are tracked and fixed individually. {{C55}}

**The safety model is worth keeping, but it was not complete** (see 7.7: the `.socket` link guard, the inline-blob writer and agent writes through links were gaps; PR #1042 closes them):
- every manifest path is escape-checked;
- blob hashes must be 64-hex, and blob entries are read with lstat and FIFO-safe;
- patched bytes are hash-verified *before* any write;
- writes are stage + fsync + rename (which keeps pnpm, uv and Go cache hardlinks safe);
- read-only parent directories are relaxed and restored, and mode and uid/gid are preserved.

The default `MismatchPolicy::Warn` silently overwrites locally modified dependency files with the verified content; `--strict` is opt-in.

**Apply and rollback are mirror images.** `VerifyStatus`/`VerifyResult` and `VerifyRollbackStatus`/`VerifyRollbackResult` still have identical fields, and the sidecar boundary is still written twice. The pnpm/vlt store-copy fan-out and its fold are now shared (`patch/store_copies.rs::fan_out`), merging each copy's per-file records under the copy's path; both directions carry only the ownership advisory from a copy (#774, fixing #756). Rollback is apply with before/after swapped, plus deleting files the patch created, and could be one engine. {{C24}}

**`--download-mode diff` is the default and is a net loss (verified).** On a cold cache it fetches every diff archive *and then every blob anyway*:
- `blob_scope = manifest` whenever any archive was missing (`fetch_stage.rs:377-385`);
- the CLI even prints "Also fetching N per-file blobs (used where a diff does not apply)";
- everything is staged in a tempdir and thrown away after the run.

So diff only saves bytes when a user commits `.socket/diffs` but not `.socket/blobs`. The diff fetch is also sequential with no retry, and it is the only user of the `qbsdiff` dependency. Blob downloads are sequential with no retry too, while the JSON calls run 32 at a time.
- **Decided (#792):** v5 removes the diff download path and the `--download-mode` / `SOCKET_DOWNLOAD_MODE` option outright (no alias). Blobs are the only patch-content source, and `.socket/diffs/` is swept as obsolete like `.socket/packages/`.
- **Saving:** about 600 production and 1,000 test lines, plus one dependency. Re-verified on `045d7ec` (top-up at `fetch_stage.rs:377-398`; diff-only code is `patch/diff.rs` (99 production lines), `read_archive_filtered`, `resolve_from_diff`/`AppliedVia::Diff`, `fetch_diff`, the diff fetch/coverage code in `blob_fetcher`/`fetch_stage`/`repair` and `qbsdiff`). `patch/package.rs` is not diff-only on current main: vendor/*, `hosted/npm_manifest.rs` and `redirect/vlt_heal.rs` use its readers, so it stays and the saving is nearer 400 production lines. {{C25}}

**Sidecars** (`patch/sidecars/`, 1,107 production lines on `9c43dfc`; 708 at the review) are post-apply fixes for package-manager checksum files:
- cargo: rewrite `.cargo-checksum.json`;
- Maven: rewrite a `~/.m2` `.sha1`/`.md5` that described the pre-patch bytes, and put it back on rollback; Gradle `files-2.1` copies get advisories (#646);
- NuGet: delete `.nupkg.metadata`;
- PyPI, gem and Go: advisory text only.

Maven 3.9.11 doesn't verify the local repository's `.sha1` files by default, so the review's stale-checksum concern was rejected on `045d7ec`; since #646 the Maven sidecar rewrites them anyway (for `mvn -C` and mirror tooling), and agent mode patches each Gradle `files-2.1` copy the build reads, which fixed #551. {{C27}} This code exists only for in-place mode.

**`apply.lock`** is 903 production lines on `830749f` (553 on `045d7ec`). Most of that complexity comes from *deleting* the lock file on exit: unlinking while it is held, identity checks, Windows delete-pending handling, and, since #1030, an async-signal-safe table of held locks that the CLI's SIGINT/SIGTERM/SIGHUP and Windows console handlers (`interrupt.rs`) clear before the process dies. Lock acquisition also replays the vendored group-commit journal, which couples vendored crash recovery into every command's lock. Decided in #808: the lock stays transient. socket-patch never leaves a lock file in the project, and a persistent lock, if ever needed, would live outside it (home/cache dir or a configurable path), so the deletion machinery stays. An interrupted run no longer leaves `apply.lock` (#1030); only an uncatchable kill can, and the next lock-taking command reclaims it. Moving the journal replay and the durability barrier out of the lock primitive changes no behavior (tracked by #809 and #793). {{C26}}

**Dead path (verified):** `PatchSources::mem_blobs` is never `Some` in production (still on `830749f`), but its doc still says vendor flows stage content there. The hosted-vlt redirect-ledger helpers were deleted by #1141. {{C23}}

### 7.5 Features with questionable value

| Feature | Prod / tests | Verdict |
|---|---|---|
| **Self-update + passive notifier** | 2,351 / 5,689 | Only `Standalone` installs self-update; npm, cargo and brew are redirected to their own tools. Still detects the pre-v5 `Pypi` and `LauncherCache` channels, which is a live refusal for old installs, not dead code. Two metadata strategies, a separate lock, and its own stage writer. **Keep both (decided #983).** The maintainer treats self-update as essential. Follow-ups: retry on transient failures, an idle timeout instead of the 300 s whole-download budget, streaming the archive to disk instead of a 256 MiB in-memory `read_capped`, and a live post-release `--update` test. Re-checked on `9c43dfc`: still 2,350 production lines; `install.sh` has no Windows rows and the README sends Windows zip users to `--update`, so replacing the swap drops their only updater. {{C36}} |
| **Telemetry** | 891 / 864 | 19 near-identical public wrappers (17 `track_*` + 2 `spawn_*`, ~450 lines); a new HTTP client per event; endpoint logic duplicated. The CLI passes token/org at ~45 call sites in 10 command files, plus 5 helper signatures (not 125), and resolves them two ways: `telemetry_credentials()` in `list`/`vex`, the API client's getters elsewhere. **Collapse to one `Telemetry` handle with `track(Event)` and a shared client** (~−300). {{C22}} |
| **Failpoints** | 65 | Fine (compiled out of release). But `switched_off("group_commit")` keeps the *old non-group-commit path* alive as a test oracle. |
| **group_commit + durability** | 1,376 / 1,287 | A process-wide virtual filesystem: every `utils::fs` read and write consults it. It renders typed values lazily via `Any`, does three-way hand-edit reconciliation in `recover`, and still journals `redirect-state.json`, which nothing writes. Writes that bypass `utils::fs` are silently not captured. High-cost machinery for a vendored-run speedup; see 5.7 for the root-cause fix. |
| **socket.yml policy** | 1,942 / 2,211 | Real value. `socket_yml.rs` builds its own YAML node tree on serde-saphyr's *event* parser (`:36-320`, ~285 lines) to read **8 keys**. Re-checked on `045d7ec`: the tree is what implements the contract's validation rules (CLI_CONTRACT "Validation (fail closed)"): no alias expansion outside the keys read, anchors, aliases, merge keys and custom tags refused only inside `patches`/`projectIgnorePaths`, YAML 1.2 core-schema scalars (`enabled: yes` is an error), and per-key paths with did-you-mean hints. serde with `deny_unknown_fields` can't scope those refusals to one subtree of a file other Socket tools share, and the ~300 lines of validators would stay. Not a defect. {{C28}} |
| **Rollout / `--max-new-patches`** | ~1,090 / ~2,640 | Pure planning, threaded through the hosted `Gate`, the agent stage and a cross-directory carry. The in-memory engine (PR bots) uses it. Keep it in socket.yml; consider dropping the flag and env layering. |
| **socket-cli config reuse** | 232 / 1,022 | Cheap and valuable. Keep. |
| **Legacy redirect ledger** | spread across vex, rollback, group_commit | Read-only since v5. Set a sunset date. |

### 7.6 Recommendations

1. **Remove `--download-mode` and the diff machinery** (decided #792, v5): about −400 production, −1K tests, −1 dependency. Low risk. {{C25}}
2. **One retry and timeout primitive** across every HTTP path, so the JSON and blob paths get timeouts: −200 production. **Fixes possible indefinite hangs.** Medium risk, because tests pin the current semantics. The self-update clients are now in scope too (#983 keeps the swap).
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
   - home dir (done, #1038);
   - (the bare `hatch` spawn is already fixed, #617).

   Saves about −200.
8. **Split `client.rs`** into client, vendor_service and credentials, and give it a single auth-vs-proxy URL policy.
9. **Keep the socket.yml event tree:** on re-check it is the contract's validator, so serde would save little and lose the scoped refusals. {{C28}}
10. **Harden self-update** (kept per #983): shared retry, idle timeout, streamed download, live post-release test. {{C36}}

### 7.7 Security boundaries

Added on 2026-10-07 by the October 7 reconciliation; owned by `audit-core`. These are the trust boundaries the CLI must hold, with their current state:

| Boundary | Rule | State |
|---|---|---|
| **Credentials never leave their origin** | Registry auth, grant tokens and URL userinfo must not reach the patch host, logs, `--json`, telemetry or VEX ids. | Hosted Composer kept `transport-options` (#399); warnings, debug output and telemetry carried raw URLs; the VEX product `@id` carried git-remote credentials (fixed by #1070). One `utils::redact` in PR #1026. Hosted rewriters' guidance snippets still need a review. {{C59}} |
| **Writes stay inside the project** | Every vendored and hosted write under `.socket/`, and every agent write, must stay inside the tree it was found in; links are refused, not followed. | One helper, `utils::containment`, now lstats every level from the project root: vendored writes, reverts and ledgers refuse a linked `.socket` (`vendor_dir_symlink_unsupported`), `get` hash-checks and stages inline blobs (#726), and agent writes that resolve outside the package are refused as `OutsideInstallTree` (#1042). #887 is closed as fixed by #1042. Remaining: agent-mode manifest and blob writes still follow a linked `.socket` (a known gap #1042 names), and rollback of an overwritten new file needs a pre-image store. {{C60}} |
| **Bytes are verified before they are trusted** | Patched content is hash-checked before any write; downloaded and inline blobs are checked against their name. | Agent apply verifies before writing; the inline-blob writer did not (fixed in PR #1042). Hosted rollback re-pins integrity from the registry (trust-on-rollback, E33/E45). |
| **No planted binaries** | Tools are resolved with `resolve_tool`, never by bare name in the scanned repo. | Fixed (#617). {{C04}} |
| **Untrusted archives are streamed** | Committed and service archives are hashed by streaming, never inflated into memory by their own header. | Vendored verify streams (#587); agent-mode jar verification streams too since #1253 (C51). {{C01}} |
| **Updates are authentic** | Self-update and `install.sh` should verify a signature or attestation, not only a same-origin checksum. | Only a same-origin `SHA256SUMS`; immutable releases stop swaps of a published release, not a malicious new one. {{C72}} |
| **Tests never reach production** | Test children must not send telemetry or call production endpoints. | The workspace `[env]` table, `hermetic::command` and every workflow env block set `SOCKET_TELEMETRY_DISABLED`, and a test keeps the workflow copies in step (#1046). {{C66}} |

### New findings since the review

- {{C37}} Patch blob and diff downloads (`fetch_blob` / `fetch_diff`, via `fetch_binary`) return a `BinaryBody` stream, and one `blob_fetcher::download_entries` loop stages each body chunk by chunk to disk (`stage_body`), verifies blobs against their git-sha256 name and renames into place; no artifact body is held in memory, per the maintainer's stream-don't-cap steering. Vendor and self-update downloads keep the shared `read_capped` (256 MiB).
- {{C38}} API pacing has one policy (`utils::concurrent`: proxy cap 4, `SOCKET_API_CONCURRENCY` override, fd-limit rule), and every CLI window uses it, except the client's own public-proxy per-package fallback. That fallback keeps a private `PROXY_BATCH_PATH_CONCURRENCY = 10`, and on `045d7ec` it ran 10 GETs in flight with `SOCKET_API_CONCURRENCY=1`. `registry_concurrency()` has no caller (C78).
- {{C41}} Manifest hashes load as lowercase hex (`manifest::schema` `deserialize_hash`, #1163), so agent-mode apply and rollback `==` checks, blob names and vendored pins share one case rule and an uppercase manifest applies and is written back lowercase. `api::blob_fetcher::blob_hash_matches` still compares case-insensitively; it becomes plain `==` once its file is free.
- {{C42}} `get` stored a patch view's inline `blobContent` under its claimed hash without checking it, in place; both `.socket/blobs` writers now verify and stage, and the hand-rolled base64 decoder is gone (#1042).
- {{C75}} Every HTTP client (API, plain proxy, telemetry, self-update metadata and download, registry fetch) trusts only reqwest's bundled webpki roots: no platform store, `SSL_CERT_FILE` or extra-CA knob. Behind a TLS-inspecting proxy, the documented `HTTPS_PROXY` route fails with `UnknownIssuer` while curl, `install.sh` and the spawned package managers succeed. Target: one client constructor with webpki ∪ native roots.
- {{C26}} The vendored group-commit journal is replayed only inside `apply_lock::acquire`, so the lock-free readers never see a pending commit: after a crash past the journal, `vendor --check` fails every patch with `vendor_ledger_missing` (whose documented remedy is restoring `state.json` by hand) and pnpm `vex` omits the packages, while one locked command rolls the commit forward to the uninterrupted result (proved twice with `group_commit_file@1`).
- {{C49}} Registry downloads (`build_registry_client`, `maven_repo::fetch_registry_bytes`) now share `ApiTimeouts`' 10 s connect + 60 s idle bound instead of a 60 s total deadline, so a slow but progressing artifact download completes (#876).
- {{C50}} Artifact GC has two retention policies. `ArtifactReferences::after_removal` (rollback, remove) keeps every active patch's beforeHash blobs so offline rollback keeps working (#600), while `for_apply` (repair, `scan --prune`) keeps only afterHash blobs. On `9c43dfc`, `repair --offline` deleted an active patch's original, and `rollback --offline` then exited 1 (twice), telling the user to run `repair`, which only ever downloads afterHash blobs. `cleanup_unused_blobs`/`_archives` and `format_cleanup_result` have no production caller.
- {{C51}} Agent-mode jar verification (`jvm_jar::verify_member_bytes`, used by `apply`, `rollback` and `vex` for Maven/Gradle member records) streams each patched member through `hash::git_sha256::zip_member_git_sha256` since #1253 (302 → 30 MiB peak RSS on a 256 MiB member). The vendored twin `zip_bytes_match_after_hashes` still has its own lookup-and-hash loop; moving it onto the helper is the remaining slice.
- {{C48}} Child processes share one deadline: `utils::process::output_within` bounds the crawler probe runners (`run_resolved`, `PROBE_TIMEOUT` 10 s), `pipenv`, `hatch`, the self-update `sanity_exec` (#886) and the PDM site probe (#1106), so a `gem` shim that never answers no longer hangs a local `scan`. Only the `git check-ignore` exchange in `vendor/npm_dir.rs` still hand-rolls its timeout (#1067).
- {{C77}} The OpenVEX document (`vex --output` and the embedded `--vex`) is written through `utils::fs::write_user_output` (stage + rename) since #1262, so a failed write leaves the previous file, and every CLI write now goes through `utils::fs`.
- {{C78}} The hosted upstream restore (`rollback`/`remove` of hosted pins, the hosted → vendored takeover and eject) re-resolves every pin from the public registry with an unbounded `join_all` in five formats (npm/vlt, PyPI, cargo, Go, Composer), while `utils::concurrent::registry_concurrency()` (cap 4; 1 under a tight fd limit), added for public registries in #1039, has no caller. On `f3c6313`, 40 npm pins put 40 requests in flight (twice); the registry client has no 429 handling.

---
_Generated by [Claude Code](https://claude.ai/code)_
