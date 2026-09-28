# Adversarial review: NuGet vendoring v2 (unique-version fallback seed), project shapes

**Environment.** .NET SDK 8.0.131 on Linux, with HOME, NUGET_PACKAGES, NUGET_HTTP_CACHE_PATH, TMPDIR and DOTNET_CLI_HOME isolated per experiment. I ran one dotnet process at a time.

**Where everything is.** Experiments are under `<scratch>/adv-shapes/exp/e{1,2,3,5,7,8,9}`. The generator is `adv-shapes/gen.py`: it renders the §6.3 targets as the design wrote them (guard, SOCKETPATCH001, pack guard) using design-D's real seeds (`13.0.1.1843260417`, `12.0.1.1843260417`). Lock "after" states come from `restore --force-evaluate`, which is the ideal output the CLI's edits would have to match.

**Labels.** VERIFIED means I ran it. REASONED means I did not.

## What held up (VERIFIED)
- The §6.3 guard works as written, with no MSB4096 metadata errors.
  - SOCKETPATCH002 fires on a tampered dll that is consumed, and on a tampered seed file that is not.
  - SOCKETPATCH005 fires.
  - `GetFileHash` keeps the custom `Sha256` metadata.
- SOCKETPATCH001 (`BeforeTargets=CollectPackageReferences`) fires in normal restore and in static-graph restore, with and without `--locked-mode`. That covers part of G4.
- CPM with transitive pinning on, under a static-graph `--locked-mode` restore, passes (part of G7).
- The pack range restore fixes both a direct CPM reference and a CentralTransitive pin: the nuspec says `13.0.1`.
- Package ids that differ only in case are redirected (`newtonsoft.JSON`). F# (`.fsproj`) works. GlobalPackageReference and nuget.g.targets are imported before DBT, so `Update` reaches them.

---

## Blockers

### B1. An exact `[V′]` spreads through ProjectReference and breaks projects the closure never sees (VERIFIED, e2)
**Setup.** Lib has Newtonsoft 13.0.1 (patched). Lib12 has 12.0.1 (patched). Lib3 has 13.0.3 (unpatched).
- AppA references Lib and Lib3. It resolved 13.0.3 before vendoring.
- AppB references Lib and Lib12. It resolved 13.0.1.
- AppC has a direct 13.0.3 reference and references Lib.

**Results after vendoring:**
- **AppA:** `NU1107 Version conflict: AppA -> Lib -> Newtonsoft.Json (= 13.0.1.1843260417) / AppA -> Lib3 -> (>= 13.0.3)`. This is a hard restore failure. AppA is not in the closure, because it resolves 13.0.3, not V, so the prelude never checks it.
- **AppB:** `NU1107` between `(= 13.0.1.N)` and `(= 12.0.1.N)`. Patching two versions of one id breaks any project that reaches both. This is exactly the "multi-version of the same id" shape the design says is Supported.
- **AppC:** `NU1608` (Lib requires `= 13.0.1.N` but 13.0.3 resolved). This breaks the build under `TreatWarningsAsErrors`.
- **Locks outside the closure change too.** AppA's and AppC's `packages.lock.json` Project entries (`"Newtonsoft.Json": "[13.0.1, )"` → `"[13.0.1.N, 13.0.1.N]"`) change even though those projects are not in the closure. The CLI only edits locks in the closure, so AppC gets **`NU1004 ... references lib whose dependencies has changed`** in locked mode.

**Fix (the range part is VERIFIED):**
1. Redirect to `[V′, )` instead of `[V′]`. After that change:
   - AppA resolves 13.0.3, as before.
   - AppB resolves 13.0.1.N (lowest applicable).
   - AppC resolves 13.0.3, with no NU1608.
   - Lib and Lib12 resolve V′.
   - No NU1107.
2. Close the drift that `[V′, )` opens with a new guard, SOCKETPATCH006. Put a marker item (`<SocketPatchRedirect Include="newtonsoft.json/13.0.1.N"/>`) inside the same conditioned ItemGroup as the redirect. The guard fails if a project where the redirect engaged resolved the id at anything other than V′. Do not make NU1603 a repo-wide error: that would break existing builds that already have approximate matches on other packages.
3. The planner must edit the `Project`-entry range in **every** lock whose graph includes a redirected project, not only locks in the closure. Record each edit for revert.
4. Update the range-restore replace string to the `[V′, )` form.

### B2. With chained nested DBT files, the once-guard imports the targets too early (VERIFIED, e7)
**Setup.** A common pattern: `src/Directory.Build.targets` imports the root DBT on its first line through `GetPathOfFileAbove`, then declares `<PackageReference Include="Newtonsoft.Json" Version="13.0.1"/>`.

**Why it breaks.** The root DBT's import runs first and sets `SocketPatchNuGetTargetsImported`. The import the design injects as the last child of `src/Directory.Build.targets` is then skipped. The redirect ItemGroup is therefore evaluated before the PackageReference exists.

**Results:**
- Restore resolves **upstream 13.0.1**.
- The build fails with SOCKETPATCH005, so it is loud. In locked mode it fails NU1004 against the edited lock.
- When the project was planned as `pin`, the misfire is worse. The pin condition `@(PackageReference…)==''` is true at that point, so the pin is added next to the later Include. The result is `NU1504 Duplicate 'PackageReference'`, and the version that wins is arbitrary.

**Fix (VERIFIED on SDK 8).** Stop injecting into DBT files. Put one line in the root, or nearest, `Directory.Build.props`:
```xml
<CustomAfterDirectoryBuildTargets>$(CustomAfterDirectoryBuildTargets);$(MSBuildThisFileDirectory).socket/vendor/nuget/socket-patch.targets</CustomAfterDirectoryBuildTargets>
```
- `Microsoft.Common.targets:55` imports that property after the whole DBT chain, so ordering no longer matters. With this line the redirect applied and the build passed.
- It is also imported without the `ImportDirectoryBuildTargets` condition, so `vendor_nuget_dbt_disabled` becomes unnecessary.
- This needs a gating experiment on SDK 6 and 7 (MSBuild 17.0 to 17.7) to confirm the property exists there.

### B3. Windows `core.autocrlf=true`, the Git for Windows default, breaks every build (VERIFIED by simulation, e1/clone)
**Cause.** An extracted seed contains text files: `.nuspec`, `lib/**/*.xml`, `LICENSE.md`, `.nupkg.metadata`, and content, build and props files. With `autocrlf=true`, git rewrites them to CRLF on checkout.

**Result.** Every affected project fails with `SOCKETPATCH002 vendored NuGet seed file modified`. Today's layout commits a binary `.nupkg` and is immune, so this is a regression specific to the new layout.

**Fix (VERIFIED: the clone builds).** Generate `.socket/vendor/nuget/.gitattributes` containing `* -text -diff -merge`, and treat it as a reserved name. Also decide how to handle a root `.gitattributes` that puts `*.dll` under git LFS: a clone without LFS gets pointer files and fails SOCKETPATCH002. Either add `-filter` or refuse with `vendor_artifact_lfs`.

---

## Major

### M1. A multi-target transitive pin is not conditioned on TFM (VERIFIED, e3)
**Setup.** ToolA targets `net8.0;netstandard2.0`. Bson is referenced only for netstandard2.0.

**Result.** The §6.3 pin has no `$(TargetFramework)` condition. It adds `Newtonsoft.Json [12.0.1.N]` as a new **Direct** dependency to `net8.0`, which previously had `{}`.
- The CLI plans edits only for the TFMs where the id resolves, so locked mode fails NU1004.
- Lockless builds start shipping a new dll for net8.0.
- If the other TFM resolved a higher version, this becomes an NU1605 downgrade.

**Fix.**
- Add `and '$(TargetFramework)' == '<alias>'` to each pin condition.
- Map aliases to lock keys. The lock uses `.NETStandard,Version=v2.0`, not `netstandard2.0` (VERIFIED), so this needs a real alias-to-framework mapping. Refuse custom aliases.

### M2. A consumer outside the `.socket` root breaks, and the B1 fix would make it silent (VERIFIED, e8)
**Setup.** A project outside the root (a sibling repo, or a monorepo where `.socket` lives in a subdirectory) references the patched Lib through ProjectReference.

**Results:**
- With `[V′]`: `NU1102 Unable to find Newtonsoft.Json (= 13.0.1.N)`. The consumer does not import the targets, so it has no fallback folder.
- With `[V′, )`: `NU1603` and a silent resolve of **13.0.2**.

**Fix.**
- The planner walks ProjectReferences in both directions. It refuses (`vendor_nuget_external_consumer`) when a project outside the root references a redirected project, or when a redirected project is listed in a `.sln` or `.slnf` above the root.
- Document that `.socket` must sit at the root of the solution.

### M3. SOCKETPATCH004 fires after the leaking `.nupkg` is already written (VERIFIED, e5)
**Result.** With range restore disabled, `dotnet pack -o out3` fails SOCKETPATCH004, but `out3/Lib.1.0.0.nupkg` already exists and has `<dependency id="Newtonsoft.Json" version="[13.0.1.1843260417]"/>`. PackTask writes the nuspec and the nupkg in the same step. A later `nuget push out/*.nupkg`, or a retry, publishes a package that consumers cannot restore. The "fail-closed" claim is false.

**Fix.**
- Add a pre-check `BeforeTargets="GenerateNuspec"` against the rewritten pack assets.
- On a post-check failure, delete `@(NuGetPackOutput)` before raising the error.

### M4. The pack guard fails with MSB4184 when `obj` holds more than one nuspec (VERIFIED, e5)
**Result.** Pack once, then again with `-p:Version=1.0.1`. `$(NuspecOutputAbsolutePath)*.nuspec` matches both `Lib.1.0.0.nuspec` and `Lib.1.0.1.nuspec`, and `ReadAllText("a;b")` fails the pack. Local and CI version bumps hit this routinely.

**Fix.** Read exactly `$(NuspecOutputAbsolutePath)$(PackageId).$(PackageVersion).nuspec`, or filter `@(NuGetPackOutput)` by extension.

### M5. The guard does not run for non-SDK csproj files that use PackageReference (REASONED; no mono here)
**Cause.** Legacy WPF and WinForms csproj files with PackageReference import DBT, so the redirect applies. They do not have `ResolvePackageAssets` or `RuntimeCopyLocalItems`, so SOCKETPATCH002, 003 and 005 silently never run.

**Fix.** Detect a project with no `Sdk` that uses PackageReference, and refuse it or route it to legacy. Alternatively, hook `ResolveNuGetPackageAssets` and `@(ReferenceCopyLocalPaths)` and gate that on the Windows leg (G8).

### M6. NuGetAudit still flags V′ (VERIFIED, e1)
**Result.** `warning NU1903: Package 'Newtonsoft.Json' 12.0.1.1843260417 has a known high severity vulnerability`. §2.3's "no false NU1903" holds only when the advisory's fixed version is V's own next patch. Here the fix is in 13.0.1, so `12.0.1.N` still falls inside `< 13.0.1`.
- Repos that treat NU1903 as an error stay broken after patching.
- NuGetAuditSuppress is out of the prototype's scope and needs NuGet 6.11 or later (SDK 8.0.4xx). The 8.0.1xx SDK here cannot use it.

**Fix.** State the limitation in the design. Ship NuGetAuditSuppress with the prototype. On older SDKs, emit an informational `vendor_nuget_audit_still_flags`.

### M7. The closure planner misses whole project types and version spellings (VERIFIED and REASONED)
- **VERIFIED (e9):** `Version="13.0.1.0"` means the same to NuGet as 13.0.1, but the literal redirect does not match it. The result is SOCKETPATCH005, and NU1004 if the CLI edited the lock. Render one condition per recorded literal spelling, or refuse the non-canonical spelling.
- **REASONED:** the enumerator looks only at `*.csproj|fsproj|vbproj`. It misses NoTargets and Traversal `.proj` files (from `global.json` `msbuild-sdks`), `.sqlproj`, `.esproj`, and others. They import DBT, so they get redirected with no lock edits. Enumerate `*.*proj` plus the projects listed in the sln.
- **REASONED:** property-expanded versions (Arcade `eng/Versions.props`) and `NuGetLockFilePath=$(MSBuildProjectDirectory)/…` depend on `dotnet msbuild -getItem`/`-getProperty`, which need MSBuild 17.8, i.e. SDK 8. Repos whose `global.json` pins SDK 6 or 7 get refused. Also, a `global.json` SDK that is not installed on the vendoring machine breaks every `dotnet msbuild` call.

---

## Minor

1. **The lock golden table is wrong for CPM with pinning on (VERIFIED, e5).** With the uniform `PackageVersion Update`, the entry stays `CentralTransitive` and only `requested` becomes `[V′, V′]`. It does not turn into Direct.
2. **Pin conversion reorders lock entries (VERIFIED, e3).** NuGet writes Direct entries first. Plain and locked restores do not rewrite a lock whose order differs, but `--force-evaluate`, Dependabot relocks, and the `--nuget-relock` text-diff check all see churn. Compare semantically, and write the canonical order.
3. **One tampered seed file fails every project (VERIFIED, e1).** The whole-inventory `SocketPatchSeedFile` hash made Tool, which only uses the 12.0.1 seed, fail for a tampered 13.0.1 seed. The cost also scales with the total seed size times the number of projects; think of native-heavy packages such as SkiaSharp. Filter on `PackageKey` for the packages this project resolved.
4. **An exact-bracket declared literal `[13.0.1]` is widened by pack range restore to `[13.0.1, )` (REASONED).** Render the replacement from the recorded literal.
5. **F# FSharp.Core and other implicit, SDK-versioned references drift across SDK versions (REASONED; props file checked).** Their version comes from the SDK that `global.json` resolves (`Microsoft.FSharp.NetSdk.props:95`). Refuse ids with `IsImplicitlyDefined`.
6. **The `vendor_nuget_tool_manifest` refusal is aimed at the wrong thing (REASONED).** `dotnet-tools.json` lists tool packages, and their dependencies are bundled inside those packages. MSBuild never resolves them. Say that tools cannot be patched, and keep the crawler from reporting that they are covered.
7. **RID lock sections list only packages with RID-specific assets (VERIFIED, e3/Rid).** Newtonsoft is absent from `net8.0/linux-x64`. RID edits matter only for packages that ship `runtimes/`. Add goldens for such a package, for example SqlClient.
8. **Windows MAX_PATH.** A 36-character uuid directory plus a long id plus a 4-part V′ is about 225 characters under `C:\agent\_work\1\s`. Use a short uuid8 directory.
9. **Analyzer-only packages are invisible to the guard (G1 still open).**

---

## How the verdict changes

The D base is sound for GPF safety, source mapping, and CPM with static-graph restore. It is **not** ready for its own "Supported" rows:
- multiple versions of one id;
- a patched library consumed next to a higher-versioned sibling;
- nested DBT chaining;
- multi-TFM transitive-only projects;
- Windows checkouts.

**Minimum changes before prototype acceptance:**
1. `[V′, )` redirect plus SOCKETPATCH006.
2. Project-range edits in every lock that consumes a redirected project.
3. Injection through `CustomAfterDirectoryBuildTargets`.
4. TFM-conditioned pins.
5. The seed `.gitattributes`.
6. Pack guard pre-check, deletion of the bad nupkg, and an exact nuspec path.
7. The external-consumer refusal.

Add e2, e3, e7 and the autocrlf clone as docker and e2e legs.