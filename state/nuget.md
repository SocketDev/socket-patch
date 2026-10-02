[agent] Progress ledger for the scheduled NuGet / dotnet bug-hunt routine (label pm:nuget).

Last run: 2026-10-02 23:50 UTC, main `045d7ec`, release v4.0.0.

## Coverage matrix

Cells: OS × SDK × mode. "warm" means the global packages folder already holds the upstream package; "sln" means the lock sits in `src/<Project>/`. "agent custom gpf" means `globalPackagesFolder` / `RestorePackagesPath` is set.

| OS | SDK | agent | agent custom gpf | vendored (cold, root lock) | vendored warm cache | vendored sln | vendored inherited sources | hosted |
|---|---|---|---|---|---|---|---|---|
| Linux | 6.0.428 | untested | fail #397 | pass | fail #352 | fail #353 | untested | untested |
| Linux | 7.0.410 | untested | untested | pass | fail #352 | fail #353 | untested | untested |
| Linux | 8.0.131 / 8.0.425 | pass (apply, rollback, remove, repair, --json, locked restore; unwritable folder fails loudly) | fail #397 | pass (+ `<clear/>`, CPM, re-run, revert); user exact-id mapping: config tie #462 | fail #352 (v5 too) | fail #353 | fail #354 | cold pass (suite); warm fail #352 (v5 too); sln fail #353; inherited fail #354; user exact-id mapping fail #462 |
| Linux | 9.0.318 | untested | fail #397 | pass | fail #352 | fail #353 | untested | untested |
| Linux | 10.0.401 | untested | fail #397 | pass | fail #352 | fail #353 | untested | untested |
| macOS | 8.0.425 | untested | fail #397 | pass | fail #352 | fail #353 | untested | untested |
| macOS | 9.0.318 | untested | fail #397 | pass | fail #352 | fail #353 | untested | untested |
| Windows | 8.0.425 | untested | fail #397 | pass | fail #352 | fail #353 | untested | untested |
| Windows | 9.0.318 | untested | fail #397 | pass | fail #352 | fail #353 | untested | untested |
| Windows | nuget.exe 7.9 / packages.config | pass (`packages/`) | fail #398 (`repositoryPath`) | untested | untested | untested | untested | untested |

Per-project lock `packages.<Project>.lock.json` (vendored + hosted): fail #514 (Linux 8; vendored also on ubuntu/macOS/Windows × SDK 8/10). Custom `NuGetLockFilePath` (vendored): fail #514 (all 3 OSes × SDK 8/10).

Vendored revert on a `core.autocrlf=true` checkout (`vendor --revert`, `remove`, `rollback`, rescan→revert): fail #537 on Linux 8/10, macOS 8 and Windows 8/10 (macOS 10 not inspected). Without autocrlf: pass. Vendored, then `dotnet nuget add source` (re-serialized config), then revert: pass (Linux 8). Self-closing `<packageSourceMapping />` and a `Newtonsoft.*` prefix mapping: pass (Linux 8, vendored + hosted).

Mode takeovers (Linux 8): hosted → vendored via `scan --mode vendored`: fail #553 (no takeover, purl case mismatch; autocrlf on and off; http and patch.socket.dev URLs). Via `vendor`: pass. `remove`/`rollback` with the mixed-case purl on a hosted project: fail #553. Vendored → hosted: no NuGet takeover by design (stays vendored, patched).

Hosted with a commented-out `<packageSources>` or `<packageSourceMapping>` block (Linux 8): fail #585 (splice lands inside the comment; v4.0.0 too). Vendored with the same configs: pass. `get --mode vendored` over a hosted project: fail #553.

CPM with `CentralPackageTransitivePinningEnabled` (`CentralTransitive` lock entry), Linux 8: hosted pass, vendored pass.

BOM `packages.lock.json`, Linux 8: hosted fail #623 (exit 0, nothing wired), vendored fail #623 (`apply_failed`). Hosted BOM + CRLF `nuget.config`: pass.

Hosted unwind (`remove`, `rollback <purl>`, hosted → `vendor` takeover → `vendor --revert`), Linux 8: fail #624 (lock gets the catalog `packageHash`, NU1403 on every restore; since `de316b4`). Config side is byte-exact for LF / CRLF / BOM. Vendored `remove`/`rollback` with a lowercase purl: `not_found` (the inverse of #553; commented there).

Project-mode agent scan (no `-g`) patches unrelated cached packages and VEX attests them: fail #427 (Linux 8; v4.0.0 too).

### Global mode (`-g`)

"default" = `~/.nuget/packages`, "tool" = `dotnet tool install -g` (`~/.dotnet/tools/.store`), "user gpf" = `globalPackagesFolder` in the user-level NuGet.Config.

| OS | SDK | scan -g default | scan -g tool | scan -g user gpf | apply/rollback/vex -g default | apply -g user gpf | hosted refusal | unwritable dir |
|---|---|---|---|---|---|---|---|---|
| Linux | 8.0.131 | pass | fail #426 (+ `--tool-path`) | fail #397 | pass (build + byte-exact rollback) | fail #397 | pass | pass (non-root user, rc 1, nothing written) |
| Linux | 6.0.x | pass | fail #426 | fail #397 | untested | fail #397 | untested | untested |
| Linux | 9.0.x | pass | fail #426 | fail #397 | untested | fail #397 | untested | untested |
| Linux | 10.0.x | pass | fail #426 | fail #397 | untested | fail #397 | untested | untested |
| macOS | 8.0.x | pass | fail #426 | fail #397 | untested | fail #397 | untested | untested |
| macOS | 9.0.x | pass | fail #426 | fail #397 | untested | fail #397 | untested | untested |
| Windows | 8.0.x | pass | fail #426 | fail #397 | untested | fail #397 | untested | untested |
| Windows | 9.0.x | pass | fail #426 | fail #397 | untested | fail #397 | untested | untested |
| Windows | 10.0.x | pass | fail #426 | fail #397 | untested | fail #397 | untested | untested |

`-g` run from inside a vendored project (`scan -g --mode agent` → `rollback -g`): Linux 8 fail #489 (vendored: regression from #446, `551c362`; hosted: pre-existing; still failing on `6cd3754`). macOS / Windows untested.

Also passed on Linux 8: `SOCKET_GLOBAL=1`, `SOCKET_GLOBAL_PREFIX`, `--global-prefix` with spaces + unicode, and `-g` from inside a packages.config project (no leak).

## Backlog

0. #624 follow-ups: an unsigned-package hash path and the `--offline` refusal; #623 on Windows with a PowerShell-written lock.
1. #553's case sensitivity in `vex` (no `--package` flag exists; check `vex` output purls) and `list`.
2. #585 follow-ups: a real `<packageSourceMapping>` placed after a commented one (expect NU1403 with a lock), plus hosted revert after a hand-fixed config.
3. #489 / #462 / #353 / #354 on macOS / Windows and SDK 6/9/10 (probe harness: `scratch_serve` + `SCRATCH_SCRIPT`; vendored legs need `--vendor-source service --patch-server-url`; hosted unwind probes must sed the feed URL to `https://patch.socket.dev`). Local SDK installs beyond apt 8.0 are blocked (dotnet-install 403), so this needs a probe branch.
4. Local tools (`dotnet-tools.json`); `apply -g` / `remove -g <purl>` from a vendored project; unwritable folder on macOS / Windows; apply/rollback/vex `-g` on macOS / Windows.
5. Mapping edge cases: a case-variant exact id, and two Socket patches for different ids.
6. Vendored/hosted with packages.config (windows-latest probe with nuget.exe).
7. #427 on macOS / Windows; unicode / space paths and Windows long paths.
8. Probe-branch cleanup: deleting branches is blocked from the sandbox, so 5 `bughunt/nuget/*` branches are still on the remote and need a maintainer.

Also passed on Linux 8 (no issue): vendored with a BOM + CRLF `NuGet.Config` (+ byte-exact revert), multi-TFM + `RestoreLockedMode`, a transitive-only patched package, and `rollback -g` alone from a v5 vendored project (no manifest → refused, nothing touched).

## Known non-bugs

- (Superseded in v5.0: hosted NuGet `remove`/`rollback` now unwind manifest-less, see #624.) A hosted unwind probe against the `http://127.0.0.1` stand-in gives `manifest_not_found`, because lockfile discovery only recognises `https://patch.socket.dev` feeds. That's a harness artifact; sed the URL first.
- Without a lockfile there's no client-side content pin (`vendor_nuget_no_lockfile`). The missing pin is documented. The false claim that the feed "forces" the patched copy is not; that's #352.
- Hosted and VEX read only the project-root `nuget.config` / `packages.lock.json` (CLI_CONTRACT.md, README VEX table). Root-only scope is documented. Wiring the root config without pinning the member locks is #353.
- Staged manifests must use sha256 git-blob hashes (64 hex). A sha1 blob is refused on purpose.
- Agent `apply` deletes `.nupkg.metadata`. That's documented, and a later restore rewrites it without reverting the patch.
- `rollback` with no targets drops every manifest entry and GCs the blobs (README command table), so a later `remove <purl>` reports `not_found`. That's documented.
- `scan -g --mode hosted` / `--global-prefix --mode hosted` refuse with exit 2 by design (CLI_CONTRACT.md).
- `apply -g` on a global tool fails loudly (rc 1, not found). The silent part is `scan -g` (#426).
- A vendored `NuGet.Config` with CRLF gets LF-terminated inserted lines (mixed endings). NuGet parses it fine, and revert is byte-exact, so it's cosmetic.
- A partial apply (EACCES midway through a multi-file patch) leaves the earlier files patched. That's intended (apply.rs retry design). It's loud (rc 1 `partialFailure`), VEX omits it, and rollback restores it.
- Vendored/hosted with a self-closing `<packageSourceMapping />` appends a second mapping section. NuGet merges them, so it's cosmetic.
- `vex -o` is `--org`; the output flag is `-O` / `--output`. Not a bug.
- After a drift-path (excision) vendored revert, the `*`→nuget.org catch-all mapping that vendor created stays in `nuget.config`. That's intentional (`revert_config_record` doc) and harmless.
- `vendor -g` / `vendor --revert -g` rewiring the cwd project is the generic #498, not NuGet-specific.
- `scan --mode hosted` over a vendored NuGet project doesn't take over (`takeover_capable` = cargo/npm/golang): `redirected: 0`, `already: 1`, and it stays vendored and patched. Not a bug. On an autocrlf checkout, a later revert hits #537.
- #486's shared-store guard (PDM cache, pnpm GVS) doesn't cover `~/.nuget/packages`. NuGet agent mode patches the global packages folder by design, so that's not a bug.
- A version bump after vendoring/hosting fails NU1102: the exclusive id-level `packageSourceMapping` routes the id only to a feed holding the patched version. This is a design limitation; unwind first.
