[agent] Progress ledger for the scheduled NuGet / dotnet bug-hunt routine (label pm:nuget).

Last run: 2026-09-30, main `f6b7fb9`, release v4.0.0.

## Coverage matrix

Cells: OS × SDK × mode. "warm" means the global packages folder already holds the upstream package; "sln" means the lock sits in `src/<Project>/`.

| OS | SDK | agent | vendored (cold, root lock) | vendored warm cache | vendored sln | vendored inherited sources | hosted |
|---|---|---|---|---|---|---|---|
| Linux | 6.0.428 | untested | pass | fail #352 | fail #353 | untested | untested |
| Linux | 7.0.410 | untested | pass | fail #352 | fail #353 | untested | untested |
| Linux | 8.0.131 / 8.0.425 | pass (apply + locked restore) | pass (+ `<clear/>`, CPM, re-run, revert) | fail #352 | fail #353 | fail #354 | cold pass (suite); warm fail #352; sln fail #353; inherited fail #354 |
| Linux | 9.0.318 | untested | pass | fail #352 | fail #353 | untested | untested |
| Linux | 10.0.401 | untested | pass | fail #352 | fail #353 | untested | untested |
| macOS | 8.0.425 | untested | pass | fail #352 | fail #353 | untested | untested |
| macOS | 9.0.318 | untested | pass | fail #352 | fail #353 | untested | untested |
| Windows | 8.0.425 | untested | pass | fail #352 | fail #353 | untested | untested |
| Windows | 9.0.318 | untested | pass | fail #352 | fail #353 | untested | untested |
| Windows | nuget.exe / packages.config | untested | untested | untested | untested | untested | untested |

## Backlog

1. Hosted: exact id already mapped to nuget.org in the user's mapping. Two HTTP sources for the same id may race without a lock.
2. #354 on macOS/Windows (`%APPDATA%\NuGet\NuGet.Config`), plus machine-wide configs.
3. packages.config / `packages/` (nuget.exe, msbuild `-t:restore -p:RestorePackagesConfig=true`, `repositoryPath`) on the Windows runner.
4. `globalPackagesFolder` / `RestorePackagesPath` in `nuget.config` with projects two levels deep (the agent crawler reads `obj/project.assets.json` one level only).
5. Multi-TFM locks; `RestoreLockedMode=true` in the csproj; transitive-only patched package.
6. Agent-mode rollback / remove / repair and `--json` shapes; the `.nupkg.sha512` advisory.
7. CRLF / BOM `nuget.config` (the Windows default from `dotnet new nugetconfig`), unicode and space paths, long paths.
8. Legacy `packages/<Id>.<Version>` parse with numeric id segments during `scan`.

## Known non-bugs

- Hosted maven/nuget per-purl rollback is refused (`hosted_revert_unsupported`, CLI_CONTRACT.md). This is documented.
- Without a lockfile there's no client-side content pin (`vendor_nuget_no_lockfile`). The missing pin is documented. The false claim that the feed "forces" the patched copy is not; that's #352.
- Hosted and VEX read only the project-root `nuget.config` / `packages.lock.json` (CLI_CONTRACT.md, README VEX table). Root-only scope is documented. Wiring the root config without pinning the member locks is #353.
- Staged manifests must use sha256 git-blob hashes (64 hex). A sha1 blob is refused on purpose.
- Agent `apply` deletes `.nupkg.metadata`. That's documented, and a later restore rewrites it without reverting the patch.
