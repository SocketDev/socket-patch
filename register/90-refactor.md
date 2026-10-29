### Refactor routine
_Last updated 2026-10-29T21:15Z · main @ c8e26f6_

#### In flight
| PR | Kind | Scope | State |
|---|---|---|---|
| [#1842](https://github.com/SocketDev/socket-patch/pull/1842) | sweep | `cli/src/args.rs` (+ the Deno guard moved into `lib.rs`) | ready |
| [#1855](https://github.com/SocketDev/socket-patch/pull/1855) | sweep | `cli/src/commands/{bun_preflight,composer_hints,context,fetch_stage}.rs` | ready; Bugbot clean; CI lost Depot runners twice (0 steps), needs a fresh run |
| [#1849](https://github.com/SocketDev/socket-patch/pull/1849) | structural | A01 [#1832](https://github.com/SocketDev/socket-patch/issues/1832): `utils/cargo_build_cache.rs` | ready; Bugbot clean; CI on 2c715eb needs a re-run (Depot runners lost twice, no test failed) |

#### Merged
_None._

#### Queue
Structural candidates, scored `3·B + 2·U + 2·D + 2·C − risk`:
1. A02 [#1833](https://github.com/SocketDev/socket-patch/issues/1833), three segment glob matchers (bug): B1 D1 C1, risk L. **7** (blocked while #1829 touches `workspace_globs.rs` / `npm_crawler.rs`)
2. T01 [#1835](https://github.com/SocketDev/socket-patch/issues/1835), `get <uuid>` re-implements `download_and_apply_patches_into`: D2.2 C2, risk M. **~6.4** (blocked while #1698 touches `get.rs` / `agent_download.rs`)
3. A03 [#1834](https://github.com/SocketDev/socket-patch/issues/1834), GOMODCACHE rule twice: D1 C1, risk L. **4**
4. T03 [#1837](https://github.com/SocketDev/socket-patch/issues/1837), hand-written env var lists: D1 C1, risk L. **4**
5. A05 [#1844](https://github.com/SocketDev/socket-patch/issues/1844), `lock_fragments` pairing loops ×3: D1 C1, risk M. **~2**

The next run is structural (this run was a sweep). Next sweep files, in order: `core/constants.rs`, `core/lib.rs`, `core/utils/cargo_home.rs`, `core/utils/cargo_workspace.rs` (skip `cargo_build_cache.rs` while #1849 is open). Skip `agent_download.rs`, `apply.rs`, `get.rs` and `vendor.rs` while #1698 is open.

#### Notes
- The PRs of the first thread (`arch-refactor/<issue>-*`) are listed in `review/2026-10-v1/register/90-refactor.md`.
- The `args.rs` note "drop api_client_overrides empty filter" was wrong: core `build_proxy_fallback_client` uses `overrides.proxy_url` unfiltered, so the CLI filter is load-bearing. Check every "redundant filter" note against all consumers of the value.
- Field doc comments on clap structs are `--help` output. Trimming them changes output bytes, so sweeps leave them alone.
- `--cwd` defaults to `.`, and `Path::new(".").ancestors()` stops at `.`. Any core walk up from the cwd must absolutize it first (`cargo_crawler::resolve_for` and `nuget_config` do; `cargo_build_cache` didn't until #1849). A test that spells the cwd as a relative path *with* components can't catch this: chdir under `#[serial]` and pass `"."`.
- `vendor/cargo_config.rs` (~L165-L190) keeps a third, async copy of the `.cargo/config` pick, with canonical dedup. It agrees on precedence; fold it into `config_layer_paths` when that file is swept.
- #1698 also touches `vendor.rs`, so the three `bun_vendor_preflight*` entry points (callers in `get.rs`, `agent_download.rs`, `vendor.rs`) and `StageOutcome::Unavailable`'s payload (caller `apply.rs`) wait until it merges. Check every caller file against open PRs, not only the swept file.
