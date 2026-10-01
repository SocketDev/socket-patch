[agent] Progress ledger for the scheduled NuGet / dotnet bug-hunt routine (label pm:nuget).

Last run: 2026-10-01 05:47 UTC, main `2463257` (v5 consolidation, #277), release v4.0.0.

## Coverage matrix

Cells: OS × SDK × mode. "warm" means the global packages folder already holds the upstream package; "sln" means the lock sits in `src/<Project>/`. "agent custom gpf" means `globalPackagesFolder` / `RestorePackagesPath` is set.

| OS | SDK | agent | agent custom gpf | vendored (cold, root lock) | vendored warm cache | vendored sln | vendored inherited sources | hosted |
|---|---|---|---|---|---|---|---|---|
| Linux | 6.0.428 | untested | fail #397 | pass | fail #352 | fail #353 | untested | untested |
| Linux | 7.0.410 | untested | untested | pass | fail #352 | fail #353 | untested | untested |
| Linux | 8.0.131 / 8.0.425 | pass (apply, rollback, remove, repair, --json, locked restore) | fail #397 | pass (+ `<clear/>`, CPM, re-run, revert) | fail #352 | fail #353 | fail #354 | cold pass (suite); warm fail #352; sln fail #353; inherited fail #354 |
| Linux | 9.0.318 | untested | fail #397 | pass | fail #352 | fail #353 | untested | untested |
| Linux | 10.0.401 | untested | fail #397 | pass | fail #352 | fail #353 | untested | untested |
| macOS | 8.0.425 | untested | fail #397 | pass | fail #352 | fail #353 | untested | untested |
| macOS | 9.0.318 | untested | fail #397 | pass | fail #352 | fail #353 | untested | untested |
| Windows | 8.0.425 | untested | fail #397 | pass | fail #352 | fail #353 | untested | untested |
| Windows | 9.0.318 | untested | fail #397 | pass | fail #352 | fail #353 | untested | untested |
| Windows | nuget.exe 7.9 / packages.config | pass (`packages/`) | fail #398 (`repositoryPath`) | untested | untested | untested | untested | untested |

Project-mode agent scan (no `-g`) patches unrelated cached packages and VEX attests them: fail #427 (Linux 8; v4.0.0 too).

### Global mode (`-g`)

"default" = `~/.nuget/packages`, "tool" = `dotnet tool install -g` (`~/.dotnet/tools/.store`), "user gpf" = `globalPackagesFolder` in the user-level NuGet.Config.

| OS | SDK | scan -g default | scan -g tool | scan -g user gpf | apply/rollback/vex -g default | apply -g user gpf | hosted refusal | unwritable dir |
|---|---|---|---|---|---|---|---|---|
| Linux | 8.0.131 | pass | fail #426 | fail #397 | pass (build + byte-exact rollback) | fail #397 | pass | blocked (root) |
| Linux | 6.0.x | pass | fail #426 | fail #397 | untested | fail #397 | untested | untested |
| Linux | 9.0.x | pass | fail #426 | fail #397 | untested | fail #397 | untested | untested |
| Linux | 10.0.x | pass | fail #426 | fail #397 | untested | fail #397 | untested | untested |
| macOS | 8.0.x | pass | fail #426 | fail #397 | untested | fail #397 | untested | untested |
| macOS | 9.0.x | pass | fail #426 | fail #397 | untested | fail #397 | untested | untested |
| Windows | 8.0.x | pass | fail #426 | fail #397 | untested | fail #397 | untested | untested |
| Windows | 9.0.x | pass | fail #426 | fail #397 | untested | fail #397 | untested | untested |
| Windows | 10.0.x | pass | fail #426 | fail #397 | untested | fail #397 | untested | untested |

Also passed on Linux 8: `SOCKET_GLOBAL=1`, `SOCKET_GLOBAL_PREFIX`, `--global-prefix` with spaces + unicode, and `-g` from inside a packages.config project (no leak).

## Backlog

1. **Maintainer request (global mode), still open:** an unwritable global packages folder must fail loudly (non-root probe with chmod; Windows Program Files). Also `--tool-path` tools, local tools (`dotnet-tools.json`), and apply/rollback/vex `-g` on macOS / Windows (only scan has been probed there).
2. Re-run #352 / #353 / #354 under the v5 vendored flow.
3. Hosted: exact id already mapped to nuget.org in the user's mapping. Two HTTP sources for the same id may race without a lock.
4. #354 on macOS/Windows (`%APPDATA%\NuGet\NuGet.Config`), plus machine-wide configs.
5. Vendored/hosted with packages.config (`packages/`, `repositoryPath`), where there is no PackageReference and no lock.
6. #427 on macOS/Windows; does hosted with a lock touch unrelated packages?
7. Unicode / space paths and Windows long paths (agent + vendor).

Also passed on Linux 8 (no issue): vendored with a BOM + CRLF `NuGet.Config` (+ byte-exact revert), multi-TFM + `RestoreLockedMode`, and a transitive-only patched package.

## Known non-bugs

- Hosted maven/nuget per-purl rollback is refused (`hosted_revert_unsupported`, CLI_CONTRACT.md). This is documented.
- Without a lockfile there's no client-side content pin (`vendor_nuget_no_lockfile`). The missing pin is documented. The false claim that the feed "forces" the patched copy is not; that's #352.
- Hosted and VEX read only the project-root `nuget.config` / `packages.lock.json` (CLI_CONTRACT.md, README VEX table). Root-only scope is documented. Wiring the root config without pinning the member locks is #353.
- Staged manifests must use sha256 git-blob hashes (64 hex). A sha1 blob is refused on purpose.
- Agent `apply` deletes `.nupkg.metadata`. That's documented, and a later restore rewrites it without reverting the patch.
- `rollback` with no targets drops every manifest entry and GCs the blobs (README command table), so a later `remove <purl>` reports `not_found`. That's documented.
- `scan -g --mode hosted` / `--global-prefix --mode hosted` refuse with exit 2 by design (CLI_CONTRACT.md).
- `apply -g` on a global tool fails loudly (rc 1, not found). The silent part is `scan -g` (#426).
- A vendored `NuGet.Config` with CRLF gets LF-terminated inserted lines (mixed endings). NuGet parses it fine, and revert is byte-exact, so it's cosmetic.
