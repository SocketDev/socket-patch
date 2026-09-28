# NuGet vendoring across project shapes: findings

All tests ran on .NET SDK 8.0.131 on Linux. Each experiment had its own HOME, NUGET_PACKAGES and NUGET_HTTP_CACHE_PATH under `exp/<name>/`. Patched packages were built by `mkpatch.py`: it appends `SOCKETPATCHED` to the netstandard2.0 dll, adds `socket-patched.txt`, drops the signature and can rewrite the nuspec `<version>`.

The main test solution has three projects:
- **Lib** references Newtonsoft.Json 13.0.1 directly.
- **App** has a ProjectReference to Lib.
- **Tool** references Newtonsoft.Json.Bson 1.0.2, which pulls in Newtonsoft.Json ≥12.0.1, resolved as 12.0.1.

Full notes are in `<scratch>/research/shapes/FINDINGS.md`. The templates, `env.sh`, `mkpatch.py` and the feeds are in the same directory.

## 1. Multi-project solution with PackageReference and lock files

**VERIFIED:** each project's lock lists the package itself:
- Lib: `"type": "Direct", "requested": "[13.0.1, )"`.
- App: `"Transitive"`, with its own contentHash, plus a `lib` entry of `"type": "Project"` whose dependencies are `{"Newtonsoft.Json": "[13.0.1, )"}`.
- Tool: `Transitive 12.0.1`.

So one package id shows up in every lock in the closure, and it can resolve to a different version in each project.

**A (same id+version):**
- **Source mapping works per package id, not per version.**
  - VERIFIED: once Newtonsoft.Json was mapped only to the local feed, Tool failed with `NU1102 Unable to find package Newtonsoft.Json with version (>= 12.0.1) … Versions from nuget.org were not considered`.
  - Every version of that id used anywhere in the repo has to be in the local feed, or the id has to be mapped to both sources.
  - VERIFIED: mapping to both worked 3 out of 3 times, and the local feed won each time.
  - DOCS: which source wins when both hold the same version is not guaranteed.
- **Every project in the closure needs its lock contentHash rewritten.**
  - VERIFIED: without it, Lib and App failed with `NU1403 Package content hash validation failed`.
  - For an unsigned rebuilt package, contentHash = base64(sha512(nupkg)). VERIFIED: restore passed after rewriting it that way.
- **Global cache poisoning is fatal.** VERIFIED: with upstream 13.0.1 already in the global packages folder, restore failed with `NU1403`, even with `--force`.
- **No-op restore can hide the problem.** VERIFIED: with `obj/` left from an earlier good restore, restore did nothing and hid the poisoned cache.
- **The patched copy leaks into other repos.** VERIFIED: an unrelated project with no lock file, using only nuget.org and sharing the same cache, silently got the patched 13.0.1.
- **Keeping the original signature does not work.** VERIFIED: `NU3005 … signature file entry is invalid … compression method (8)`.
- **Pack is correct.** VERIFIED: the nuspec says `version="13.0.1"`, so there is no leak.

**B (unique version):**
- **A prerelease suffix is ruled out.**
  - VERIFIED: `-socket.1` sorts below the release. It triggered a false vulnerability warning, `NU1903 … 13.0.1-socket.1 has a known high severity vulnerability`.
  - VERIFIED: next to a dependency that needs ≥12.0.1 it fails with `NU1605 Detected package downgrade: … from 12.0.1 to 12.0.1-socket.1`.
- **Build metadata does not create a new identity.** VERIFIED: `13.0.1+socket.1` is stripped and resolves as 13.0.1, which is the same as A.
- **A 4th version part works.** VERIFIED: `12.0.1.1` / `13.0.1.1` had no NU1605 and no false NU1903.
- **Metadata conditions must go inside a target.** VERIFIED: a `%(Version)` condition on an item Update outside a target fails with `MSB4191`.
- **Working repo-wide redirect, no csproj edits** (VERIFIED):
  - `Directory.Build.targets` imports `.socket/vendor/nuget/socket.targets`.
  - That file has a target with `BeforeTargets="CollectPackageReferences"`, which rewrites any PackageReference with `'%(Identity)'=='Newtonsoft.Json' and '%(Version)'=='13.0.1'` to `13.0.1.1`.
  - Resulting locks: Lib Direct `[13.0.1.1, )`; App Transitive 13.0.1.1, with its `lib` project entry changed to `[13.0.1.1, )`; a project with a direct 13.0.3 is left alone.
  - Then a `--locked-mode` restore with an empty cache passes, and build/publish output contains the patched dll.
- **Old locks fail and must be regenerated for the whole closure.** VERIFIED: `NU1004 The package reference … version has changed`, and on App `NU1004 The project references lib whose dependencies has changed`.
- **If the vendor feed is unusable, restore silently moves to a different version.**
  - VERIFIED: with a ≥13.0.1.1 reference and the feed unmapped, NuGet picked 13.0.2 from nuget.org with only `NU1601 … ended up with Newtonsoft.Json 13.0.2`.
  - VERIFIED: exact brackets `[13.0.1.1]` turn this into a hard `NU1102`.
- **`RestoreAdditionalProjectSources` only helps when the repo has no source mapping.**
  - VERIFIED: set from an imported props file, it adds the feed without touching nuget.config.
  - VERIFIED: when the repo has source mapping, that feed is used only if mapped by its **absolute path**. A relative key failed (NU1102). So nuget.config has to be edited anyway.
- **Pack leaks the new version to consumers.**
  - VERIFIED: the nuspec gets `version="13.0.1.1"` (or `[13.0.1.1]` with brackets).
  - VERIFIED: a consumer with an empty cache then fails with `NU1102`. Without brackets it would drift to 13.0.2 with NU1601.
  - VERIFIED: a transitive redirect with PrivateAssets=all does not leak.

**C (repo-local package folder):**
- **`RestorePackagesPath` in Directory.Build.props wins.**
  - VERIFIED: `RestorePackagesPath=$(MSBuildThisFileDirectory).socket/nuget-packages` beat the NUGET_PACKAGES env var (the env cache stayed empty).
  - VERIFIED: a pre-extracted patched `newtonsoft.json/13.0.1` was used as is; other packages were downloaded into the repo folder.
- **The seed can be minimal.** VERIFIED: `.nupkg.metadata` + nuspec + lib/ is enough; the .nupkg and .sha512 are not needed and NuGet does not re-hash the files.
- **The seed can carry the upstream hash, so the locks stay as they are.** VERIFIED: a `.nupkg.metadata` with the upstream contentHash, with locks untouched, passed `--locked-mode` and the patched dll was built.
- **It survives forced restores.** VERIFIED: `restore --force --no-cache` left the seed in place.
- **A CI override bypasses it.**
  - VERIFIED: with `-p:RestorePackagesPath=…` and the upstream hash in the locks, restore silently downloads the unpatched package.
  - VERIFIED: with the patched hash in the locks, it fails closed with NU1403.
- **Fallback folders are unsafe.** VERIFIED: `RestoreFallbackFolders` works with an empty cache, but if the cache already holds upstream 13.0.1, the cache wins and the result is silently unpatched.
- **Folder name and CI cost** (DOCS): a dot-prefixed folder is excluded from SDK default globs. Every package then lives in the repo, so a `.gitignore` with negation rules is needed and CI caching of the global folder stops helping.
- **Pack is correct.** VERIFIED: the nuspec says 13.0.1.

## 2. Central Package Management

- **Lock entry types** (VERIFIED):
  - Transitive packages that have a PackageVersion appear as `"CentralTransitive"` even with pinning off.
  - Tool showed `requested [13.0.1, )` but `resolved 12.0.1`.
  - A project with a VersionOverride shows as Direct.
- **Turning pinning on changes nothing until locks are re-evaluated.** VERIFIED: with existing locks, both `--locked-mode` and a plain restore passed and kept Tool at 12.0.1. Only `--force-evaluate` moved it to 13.0.1.
- **Redirect without editing Directory.Packages.props** (VERIFIED):
  - A `<PackageVersion Update="Newtonsoft.Json" Condition="'@(PackageVersion->WithMetadataValue('Identity','Newtonsoft.Json')->WithMetadataValue('Version','13.0.1'))' != ''" Version="13.0.1.1"/>` in the imported targets file works. A non-matching version check did not redirect.
  - Lib and App moved to 13.0.1.1. The VersionOverride project was untouched.
  - Without pinning, Tool's requested range became `[13.0.1.1, )` but it still resolved 12.0.1.
  - With pinning, Tool moved to 13.0.1.1.
  - Old locks fail with `NU1004 Mistmatch between the requestedVersion of a lock file dependency marked as CentralTransitive…`.
- **Transitive-only project without pinning** (VERIFIED):
  - Needs `<PackageReference Include=… VersionOverride="12.0.1.1" PrivateAssets="all"/>` scoped to that project.
  - `Version=` fails with `NU1008`. If the repo sets `CentralPackageVersionOverrideEnabled=false`, it fails with `NU1013`.
- **Pinning should not be the patch mechanism.** CPM allows one PackageVersion per id (DOCS). Turning pinning on changes other projects' versions: VERIFIED, Tool went from 12.0.1 to 13.0.1.
- **Answer to "only Directory.Packages.props?"** No. An imported targets file can do the redirect, but every lock in the closure still has to change.

## 3. packages.config

- **Not testable here.** VERIFIED: `which mono nuget` finds nothing. `dotnet restore` on the solution, on the csproj, and `msbuild -t:restore -p:RestorePackagesConfig=true` all print `Nothing to do. None of the projects specified contain packages to restore.`
- **How nuget.exe works** (DOCS):
  - It restores to `<solutionDir>/packages/<Id>.<Version>/`, or to `repositoryPath` if set in nuget.config.
  - There is no lock file and no contentHash; projects reference dlls through HintPath.
  - It skips any folder that already holds `<Id>.<Version>.nupkg`.
- **Verdicts:**
  - C (pre-seed or commit the `packages/` folder) is the practical option.
  - B needs every packages.config and HintPath edited.
  - A with a folder feed works, but the packages/ folder poisons it the same way the global cache does.

## 4. Directory.Build.props/targets injection

- **Only the nearest file is imported.**
  - VERIFIED: a nested `src/Directory.Build.props` hides the root one.
  - VERIFIED: chaining with `$([MSBuild]::GetPathOfFileAbove(Directory.Build.props, $(MSBuildThisFileDirectory)..))` restores it.
  - VERIFIED: the root .targets file is still found independently of the .props.
  - So the injector must add its Import to the nearest existing file for every project.
- **A separate imported file works.** VERIFIED: an Exists-guarded `.socket/vendor/nuget/socket.props|targets` worked for all the properties and items above.
- **Limits outside MSBuild** (DOCS): source mapping can only be set in nuget.config. `Directory.Build.rsp` affects the msbuild CLI only.

## 5. Transitive redirect

VERIFIED: a per-project PackageReference with PrivateAssets=all (or VersionOverride under CPM) changes the lock entry from Transitive or CentralTransitive to Direct, with the new requested range. The parent's dependency line stays the same (Bson still lists `"Newtonsoft.Json": "12.0.1"`). No csproj edits are needed.

## 6. Build, publish and pack

- **Build and publish:** VERIFIED patched dll in the output for A, B (4th part) and C.
- **Pack:** VERIFIED A and C are correct. B leaks the new version into the nuspec whenever the package is a direct dependency of a packable project.

## 7. Floating versions and ranges

- **Resolution:** VERIFIED `13.0.*` and `13.*` resolve 13.0.4 today; `[13.0.1,14.0)` resolves 13.0.1.
- **Lock files win:** VERIFIED a plain restore with an existing lock keeps the locked versions.
- **4th-part versions are not picked up on their own:** VERIFIED 13.0.1.1 was not chosen for the range with `--force-evaluate`, so B has to replace the floating spec with the exact version.
- **A and C patch whatever the lock resolved:** DOCS/inferred, re-evaluating after upstream publishes a newer version silently drops the patch.

## Verdicts

| Shape | A (same version) | B (4th-part version + redirect) | C (repo-local packages folder) |
|---|---|---|---|
| Multi-project sln | Fragile: id-wide mapping, hash rewrite in every lock, cache poisoning and leaks to other repos | Works with the imported-targets redirect and exact brackets; locks must be regenerated; pack leaks | Works and is isolated from the global cache; a CI override bypasses it |
| CPM | Same as sln | Works with a PackageVersion Update; transitive-only projects need VersionOverride; the pinning trap | Works |
| packages.config | Poor | Heavy edits | Best (seed `packages/`) |
| Transitive-only | Automatic (id-based) | Per-project redirect, lock type becomes Direct | Automatic |
| pack/consumers | Correct | Leaks the new version | Correct |
| Floating/ranges | Tied to the lock | Must pin exactly | Tied to the lock |

## What this means for a patched copy with the upstream id+version

- **Same id+version is inherently unsafe in any shared cache.** Both the global packages folder and the packages/ folder are keyed on id/version alone. Every A failure seen here comes from that: NU1403 poisoning, silent leaks into other repos, per-id mapping breaking other versions.
- **The same identity is only safe in a cache the repo owns (C).**
  - Recommended form: an Exists-guarded `RestorePackagesPath` import chained into every nearest Directory.Build.props.
  - Seed a minimal extracted package.
  - Write the patched contentHash into both `.nupkg.metadata` and the locks, so that bypassing the folder fails closed (NU1403) instead of silently restoring upstream.
  - Do not use fallback folders.
- **If a unique version (B) is used:**
  - Use a 4th version part, never a prerelease suffix or `+metadata`.
  - Pin it with exact brackets.
  - Apply the redirect through an imported targets file, not csproj edits.
  - Regenerate the locks for the whole closure.
  - Handle the pack leak, for example by limiting B to non-packable projects.