### Refactor routine
_Last updated 2026-10-29T17:15Z · main @ c07af61_

#### In flight
| PR | Kind | Scope | State |
|---|---|---|---|
| [#1842](https://github.com/SocketDev/socket-patch/pull/1842) | sweep | `cli/src/args.rs` (+ the Deno guard moved into `lib.rs`) | ready; CI and Bugbot pending |

#### Merged
_None._

#### Queue
Structural candidates, scored `3·B + 2·U + 2·D + 2·C − risk`:
1. A01 [#1832](https://github.com/SocketDev/socket-patch/issues/1832), cargo config chain read twice (bug): B1 D1 C1, risk L. **7**
2. A02 [#1833](https://github.com/SocketDev/socket-patch/issues/1833), three segment glob matchers (bug): B1 D1 C1, risk L. **7**
3. T01, `get <uuid>` re-implements `download_and_apply_patches_into`: D2.2 C2, risk M. **~6.4** (blocked while #1698 touches `get.rs` / `agent_download.rs`)
4. A03 [#1834](https://github.com/SocketDev/socket-patch/issues/1834), GOMODCACHE rule twice: D1 C1, risk L. **4**
5. T03 [#1837](https://github.com/SocketDev/socket-patch/issues/1837), hand-written env var lists: D1 C1, risk L. **4**

The next run is structural (the previous run was a sweep). Next sweep files, in order: `commands/bun_preflight.rs`, `commands/composer_hints.rs`, `commands/context.rs`, `commands/fetch_stage.rs`. Skip `agent_download.rs`, `apply.rs` and `get.rs` while #1698 is open.

#### Notes
- The PRs of the first thread (`arch-refactor/<issue>-*`) are listed in `review/2026-10-v1/register/90-refactor.md`.
- The `args.rs` note "drop api_client_overrides empty filter" was wrong: core `build_proxy_fallback_client` uses `overrides.proxy_url` unfiltered, so the CLI filter is load-bearing. Check every "redundant filter" note against all consumers of the value.
- Field doc comments on clap structs are `--help` output. Trimming them changes output bytes, so sweeps leave them alone.
