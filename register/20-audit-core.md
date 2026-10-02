### CLI layer, core infrastructure, agent mode, tests and docs (`audit-core`)
_Last updated 2026-10-02T22:30Z · main @ 045d7ec_

| ID | P | Problem | Source | Issues | Status |
|---|:-:|---|---|---|---|
| C01 | 1 | Unbounded zip inflate on tamperable input. `zip_bytes_match_after_hashes` pre-allocates from the archive's declared size and reads with no cap, and it runs on committed `.nupkg`/`.jar` files and service archives. There are three archive caps (512/256/128 MiB). | #569 | fixed (#587); streams members, no cap per maintainer |
| C02 | 1 | `ApiClient::new` and `plain_client()` set no HTTP timeout, and blob and diff fetches have no retry, so `scan`, `get` and `apply` can hang in CI. | #570 | fixed (#581) |
| C03 | 1 | `vendored_takeover` ignores `RevertOutcome.kept_artifact`. It deletes the ledger entry and reports the artifact as reverted on a drift-keep, while every other revert caller honors the flag. | #568 | filed #568 |
| C04 | 1 | Planted-binary spawn: `vendor/pypi_hatch.rs` runs `Command::new("hatch").current_dir(root)` instead of `process::resolve_tool`. #442 didn't cover it. | §1 #4; 7.3 | #613 | filed #613 |
| C05 | 1 | `SOCKET_FORCE` is bound to `vendor --force`, `apply --force` and `--update --force`, so forcing a self-update also forces past hash checks. | §1 #6 | #615 | decision #615 |
| C06 | 1 | `get` round-trips its arguments through `DownloadParams` and `..GlobalArgs::default()`, which silently resets `offline`, `patch_server_url` and more. `get` also builds a fake `ApplyArgs`, and `get` and `scan` call each other. | 2.1; 2.3; R7 | | rejected; resets inert on 045d7ec, cycle folded into C12 |
| C07 | 1 | The URL builders disagree. When org auto-resolve fails, `patches_path` sends JSON calls to `/v0/orgs/default/…`, while `binary_url` and `vendor_package_url` send the same client to the public proxy. Telemetry has a fourth copy of this logic. | 7.2 | | to verify |
| C08 | 2 | Repo hygiene: a stray `.github/actions/actions/cache/<sha>/.vscode/launch.json`, a README that documents v5 but whose installer installs v4, and 39 references to a "DESIGN §" document that doesn't exist. (The dead CI path filters go to the CI janitor.) | §1 #8; 8.5 J | | to verify |
| C09 | 2 | There is no shared `with_proxy_fallback` helper: scan, get (both paths) and vex each handle the proxy fallback themselves, and get's handling has a gap. | 2.10 R2 | | to verify |
| C10 | 2 | Tracking: `RunCtx { config, client, telemetry, lock }`, built once in `main`. It would delete `apply_env_toggles` (flags written back into process env, which has a documented token-leak history) and unblock removing 553 `#[serial]`. | 2.5; R3 | | to verify |
| C11 | 2 | Tracking: split `run_scan` (1,499 lines; mode booleans referenced 91 times) into discover → select → `ModeBackend::consume` → render. | 2.2; R5 | | to verify |
| C12 | 2 | Tracking: move engine code out of the CLI and into core behind one orchestrator over `ProjectView`. That covers `vendor_records_reusing` (962 lines), `run_redirect_selected` (836) and `ecosystem_dispatch.rs` (816). Coordinate with E32. | 2.1; R11 | | to verify |
| C13 | 2 | Error codes are untyped. Target: a typed registry (`enum Reason × Ecosystem`) that generates the contract's code tables, plus a freshness test. Today ~65 codes are undocumented and 1 is phantom. | 2.8; 3.7 #8; 8.5 F | | to verify |
| C14 | 2 | Decide: one JSON envelope. `scan`, `get` and `rollback` still emit a bare-string `error`, while the other commands emit `{code, message}`. | 2.8; R4 | | to verify |
| C15 | 2 | There are three HTTP retry systems, and blob and diff fetches have none. A 206-line HTTP-date parser, two near-identical downloaders, and per-fetch or per-event clients round it out. Target: one retry + timeout primitive. | 7.2; R12 | | to verify |
| C16 | 2 | Batch limits are split across crates. The CLI owns 500 / 100 / 256 KiB, and `search_patches_batch` documents a maximum of 500 without enforcing it. | 7.2 | | to verify |
| C17 | 2 | Digest helpers are duplicated: ~30 inline `hex::encode(Sha256::digest(..))` sites, and `sha256_hex` copies that *compute* beside a `utils::digest::sha256_hex` that *validates*. `sha1_hex` exists twice, and SRI formatting is inlined three times. | 4.4; 7.3 | | to verify |
| C18 | 2 | There are four UUID grammars. `client.rs` has one, CLI `lib.rs` a byte-identical copy, `path_safety.rs` accepts lowercase only, and `apply.rs` accepts any alphanumeric plus `-`/`_`. | 7.3 | | to verify |
| C19 | 2 | Env truthiness has three vocabularies, and there are 37 inline "empty means unset" reads and four home-directory resolvers. | 7.3 | | to verify |
| C20 | 2 | Purls have two builder families in `utils/purl.rs`, plus 78 hand-built `pkg:` strings and 58 `starts_with("pkg:<type>/")` checks that bypass `Ecosystem::from_purl`. | 6.4; 7.3 | | to verify |
| C21 | 3 | `utils/fs.rs` has six atomic writers, and separate stage + rename code lives in `blob_fetcher` and `update/`. Writes that bypass `utils::fs` (`blob_fetcher.rs`) escape group commit. | 5.7; 7.3 | | to verify |
| C22 | 2 | Telemetry has 17 near-identical `track_*` wrappers, builds a new HTTP client for every event, and threads the token and org through 125 signatures. Target: one `track(Event)` with a shared client. | 7.5; R15 | | to verify |
| C23 | 2 | Dead code: `PatchSources::mem_blobs` is never `Some`. `save_redirect_state` and its group-commit entry journal a file that nothing writes. The `switched_off("group_commit")` oracle path, the `Pypi`/`LauncherCache` update channels and `--vendor-source` (one value) also remain. | 7.4; 7.6 #3; 5.6 | | to verify |
| C24 | 2 | Apply and rollback are mirror images: the verify types are identical, and `fold_copy_result`, the pnpm peer fan-out and the sidecar boundary are each written twice. Target: one engine. | 7.4; 7.6 #4 | | to verify |
| C25 | 2 | `--download-mode diff`, the default, re-downloads every blob on a cold cache, runs sequentially with no retry, and is the only user of `qbsdiff`. Making `file` the default is a decision; removing the duplicate fetch work is a refactor. | 7.4; R10 | | to verify |
| C26 | 3 | `apply.lock` spends ~554 lines deleting the lock file on exit, and taking the lock replays the vendored group-commit journal, coupling vendored crash recovery to every command. | 7.4 | | to verify |
| C27 | 3 | Agent-mode sidecars don't handle Maven files at all. Verify whether in-place Maven patches leave stale checksum files behind. | 7.4 | | to verify |
| C28 | 3 | socket.yml builds a hand-made YAML tree on serde-saphyr's event parser to read 8 keys. Target: serde with `deny_unknown_fields`. | 7.5 | | to verify |
| C29 | 3 | The `client.rs` split (2.8K lines) into client, vendor_service and credentials; the debug-ordering machinery (`HeldBack`) has 45 call sites. | 7.2; 7.6 #8 | | to verify |
| C30 | 2 | No `socket-patch-test-support` crate: `binary()` is defined in 102 files and `git_sha256` in 84, there are 14 divergent `scrub_socket_env`, xorshift is implemented four times, and the VEX helpers are forked. | 6.4; 8.5 D | | to verify |
| C31 | 3 | There are 207 test executables; the target is ~25. This needs C10 first. | 8.5 A | | to verify |
| C32 | 3 | 328 exact-sentence assertions should become `--json`/`errorCode` checks plus snapshots. Triage the 402 covgap tests, 136 of which assert human text. | 2.5; 8.5 G/H | | to verify |
| C33 | 3 | `CLI_CONTRACT.md` (332 KB) should be a generated reference (flags, env vars, codes, exit codes) plus ≤300 lines of prose, with a freshness test. Also decouple `docs/testing` from the validation scripts. | 8.3; 8.5 F/I | | to verify |
| C34 | 3 | Decide: the command model. A read-only `scan`, plus `fix`, `undo`, `sync` and `check`, with mode inferred from project state. This folds `remove`, `rollback` and `vendor --revert`, and per-command flags replace the 27 globals. | §4; 2.9; R6/R8 | | to verify |
| C35 | 3 | Decide: drop the deprecated spellings and embedded `--vex`, and give `SOCKET_FORCE` per-command names. | R9; R10 | | to verify; `SOCKET_FORCE` part is #615 |
| C36 | 3 | Decide: the futures of agent mode and of the self-update binary swap. | §6 Q2; 7.5 | | to verify |
| C37 | 2 | Patch blob/diff downloads (`fetch_binary`) buffer the whole body with no size cap; vendor and self-update use the shared `read_capped`. | new finding | #571 | in PR #607 |
| C38 | 2 | The public-proxy per-package fallback keeps a private cap of 10, ignoring `SOCKET_API_CONCURRENCY`, the proxy cap of 4 and the fd-limit rule; `registry_concurrency()` has no caller. | new finding | #614 | filed #614 |

**Handed off** (to the CI janitor): report-only coverage and LTO `docker-base` off PRs; e2e from 148 to ~50 legs; a reusable compat workflow; no per-leg compiles; dead CI path filters (review 8.2, 8.5 B/C/E).

**Rejected / not a defect:** C06. On `045d7ec`, the nested apply reads none of the fields `..GlobalArgs::default()` resets except `offline`, which `get`/`scan` refuse up front; the hosted opt-outs reach core through process env. The `get` ↔ `scan` cycle and the fake `ApplyArgs` stay in C12.

**Already fixed:** none yet.
