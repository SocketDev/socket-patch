# NuGet vendoring research: critic pass (contradictions, verified gaps, open questions)

I ran six experiments myself on SDK 8.0.131. Two results change the design:
- **A committed repo-local package folder only survives if it is set through `RestorePackagesPath`.** If it is set through `nuget.config` `globalPackagesFolder`, a user's `dotnet nuget locals --clear` deletes it.
- **Once a package is in that folder, NuGet never looks at sources or `packageSourceMapping` for it.** That makes the folder the only offline mechanism that does not depend on source mapping. The catch is that it also skips signature checks.

Full notes are in `<scratch>/research/critic/FINDINGS.md`, with the helpers (`env.sh`, `mkpatch.py`) and `seed/`, `tmpl/`, `exp/` next to it. In the text below, "package folder" means NuGet's global packages folder (normally `~/.nuget/packages`), and "seed" means a patched package pre-extracted into a repo-local package folder.

**Isolation incident.** My first experiment ran `dotnet nuget locals all --clear` before I had set `TMPDIR`. It cleared the shared `/tmp/NuGetScratchroot`, which is NuGet's temp directory. A restore running in another agent at that moment could have failed. `env.sh` now sets `TMPDIR`, and every later experiment used it.

## 1. Contradictions and tensions between reports

1. **Option C, the repo-local package folder, conflicts with the signing report.**
   - The shapes and lock-cache reports recommend seeding a repo-local package folder.
   - The signing report verified that anything already extracted into a package folder skips signature validation, even under `signatureValidationMode=require`. It says this "quietly gets around enterprise policy; should not document it".
   - Consequence: if we adopt option C, the tool itself has to check the effective signature policy. It should refuse, or require a Socket author signer, when the policy is `require`. It cannot rely on NuGet to enforce it.
2. **Which unique-version form to use.**
   - The sources report recommends `X.Y.Z.N-socket.M`; the shapes and lock-cache reports recommend `X.Y.Z.N`.
   - The trade-off: plain `X.Y.Z.N` collides with a real upstream 4-part version. The prerelease form never collides, but `pack` warns about it: **VERIFIED** `warning NU5104: A stable release of a package should not have a prerelease dependency` for `[13.0.3.1-socket.1]`, and no warning for `[13.0.3.1]`.
   - Both forms leak into the nuspec of a packed library: **VERIFIED** `version="[13.0.3.1-socket.1]"` and `version="[13.0.3.1]"`.
3. **How serious NU3005 is.**
   - The shapes report says keeping the signature "does not work" and cites NU3005.
   - The lock-cache and signing reports verified that NU3005 is only a warning and the package installs as unsigned.
   - Reconciled: a malformed signature entry means "treated as unsigned". It fails only under `require` (NU3004) or when warnings are treated as errors (DOCS).
4. **Whether NuGet trusts `.nupkg.sha512`.**
   - The sources report says its content is ignored in a hierarchical feed; the lock-cache report says its text is copied when `.nupkg.metadata` is rebuilt for an unsigned package in the package folder.
   - Both are correct, in different contexts. Either way the file is not a trust anchor.
5. **Implications across reports for today's code.**
   - The code map says vendoring appends an exact-id mapping to our feed. The shapes report verified that id-wide mapping breaks every other version of that id in the repo (NU1102 for Tool's 12.0.1). So current vendoring likely breaks multi-version repos whenever `nuget.config` already has a mapping.
   - The hosted lock rewrite matches on id regardless of version (`redirect/mod.rs:5431`). Combined with the shapes finding that one id resolves to different versions per project, this would rewrite the wrong versions' entries.
6. **Different bytes from the two build routes.**
   - depscan repacks STORE-only; the local rebuild uses its own deterministic re-zip. The signing report verified that every layout change changes `contentHash`.
   - So the service route and the local route give different lock pins. Verify and revert must hash the committed artifact, never a rebuild.

## 2. DOCS claims worth verifying

| Claim | Status |
|---|---|
| A dot-prefixed folder is excluded from SDK default globs (shapes) | **VERIFIED.** `.socket/nuget-packages/zz/1.0.0/Broken.cs` under a root-level csproj: `-getItem:Compile` lists only `Program.cs` and the build succeeds. Control: the same file in `pkgs-visible/` fails with `error CS1040`. |
| Local folder feeds are not HTTP-cached (lock-cache) | **VERIFIED (partial).** After restoring from a folder feed there are no newtonsoft entries in `NUGET_HTTP_CACHE_PATH`, and `.nupkg.metadata` `source` is the folder path. |
| An exact `[x]` dependency against a 4-part version gives NU1608 | Not verified. It needs a real package with an exact-version dependency. It matters for option B together with `TreatWarningsAsErrors`. |
| CPM allows one `PackageVersion` per id | Not verified. Cheap to check. |
| `require` mode has no per-package exemption; an untimestamped signature expires with its certificate | Not verified. The first is probably right given the NU3004 behaviour. |
| nuget.exe behaviour for packages.config | Unverifiable here (see §4). |

## 3. Research topics nobody covered, and my results

Of the topics on the list, only packages.config is still open (§4). The rest are covered at least partly. These next ones were not on the list; the first four are now answered:

- **V1: `dotnet nuget locals --clear` against a committed seed.**
  - With `RestorePackagesPath=$(MSBuildThisFileDirectory).socket/nuget-packages` in `Directory.Build.props`, `locals all --list` does not show the repo folder, and `--clear` leaves the seed in place. **VERIFIED**
  - With `nuget.config` `<add key="globalPackagesFolder" value=".socket/nuget-packages"/>` it printed `Clearing NuGet global packages folder: .../r/.socket/nuget-packages` and **deleted the committed seed**. **VERIFIED**
  - Design rule: never point `globalPackagesFolder` in `nuget.config` at committed data.
- **V2: a seed bypasses sources and mapping.**
  - The mapping mapped only `Humanizer.*` to nuget.org and left Newtonsoft.Json unmapped: restore succeeded, with no NU1100, from the seed. **VERIFIED**
  - The only source was `./does-not-exist`, `obj/` was deleted, and `dotnet restore --locked-mode` printed `Restored ... (in 252 ms)`. `dotnet run` printed `{"a":1}` and the output dll ends with `SOCKETPATCHED`. **VERIFIED**
  - This confirms the lock-cache claim that mapping is never consulted once a package is in the folder.
- **V2b: restore does not touch the seed.** `diff -r` of the seed before and after restore, build and run found no differences, so the git tree stays clean. **VERIFIED**
- **V3: dot-folder globbing.** See the table in §2. A repo-local folder under a root csproj must be dot-prefixed, or covered by `DefaultItemExcludes`. **VERIFIED**
- **Still uncovered:**
  - `NuGetLockFilePath` and the `RestoreLockedMode` property
  - static-graph restore (`RestoreUseStaticGraphEvaluation`)
  - whether Visual Studio or nuget.exe honour `RestorePackagesPath`
  - `dotnet test` with a repo-local folder
  - macOS and Windows case-insensitivity for the seed path
  - Dependabot/Renovate rewriting the version or lock

## 4. Remaining unknowns

- **packages.config.** A legacy csproj that imports `Microsoft.Common.targets` with a `packages.config`, run through `dotnet msbuild -t:restore -p:RestorePackagesConfig=true`, printed `Nothing to do. None of the projects specified contain packages to restore.` **VERIFIED.** DOCS: packages.config restore exists only in desktop MSBuild or nuget.exe. mono and nuget.exe are not installed, so it cannot be tested on this machine; it needs a Windows or mono CI leg.
- **CI overrides.** A CI job that passes `-p:RestorePackagesPath` or `--packages` bypasses the seed. With the upstream hash in the lock this silently gives an unpatched build; with the patched hash it fails with NU1403 (shapes, VERIFIED). There is no way to prevent it, only to fail closed.
- **Signature policy with a seed** (see §1.1). We would need a detection rule for an effective `require` policy across the user, machine and repo configs.
- **Pack leak for option B.** There is no verified mitigation other than limiting option B to non-packable projects or transitive `PrivateAssets=all` redirects.

## 5. Implications for vendoring a patched package with the upstream id+version

1. The id+version can stay the same **only inside a package folder the repo owns**:
   - **Location:** `RestorePackagesPath=$(MSBuildThisFileDirectory).socket/nuget-packages`. Import it from an Exists-guarded `.socket` props file that is chained into every nearest `Directory.Build.props`. The folder must be dot-prefixed (V3) and must not be set through `nuget.config` (V1).
   - **Seed contents:** `<idlower>/<vernorm>/` holding `.nupkg.metadata`, the lowercase nuspec and `lib/`. No `.nupkg` or `.sha512` is needed. Git sees no changes after a restore (V2b).
   - **Lock pin:** put the patched hash in both `.nupkg.metadata` and every lock in the closure, so bypassing the folder fails closed with NU1403.
   - **Cost:** every other package also downloads into the repo folder, so `.gitignore` needs negation rules for the seed.
2. With the seed in place, **no `nuget.config` edit is needed for the patched package** (V2). That removes the fragile source-mapping surgery, including the catch-all `*` and the multi-version NU1102 breakage. Revert is: delete the seed, restore the original lock hashes, and remove the props import. There is no global-cache eviction, because the shared package folder is never used.
3. The seed skips signature validation. The tool must detect an effective `signatureValidationMode=require` and refuse, or sign the package and document the `<author>` signer entry. Otherwise the tool silently weakens the organisation's policy.
4. Any shared-cache variant, meaning today's folder feed plus mapping, cannot be made safe. All reports agree on this: the first copy written wins, the wrong copy leaks both ways, and NU1403 repeats until the entry is evicted.