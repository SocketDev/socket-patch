# Adversarial review: NuGet vendoring v2 (unique-version fallback seed) on real environments and CI

I found one blocker and seven majors. The blocker is that git line-ending normalization breaks the committed seed. On a fresh CI clone the build fails with SOCKETPATCH002, while it still passes on the author's machine. The design's core behaviour survived the attacks I ran: the redirects, SOCKETPATCH005, the Docker-style bypass and symlinked checkouts all behaved as designed.

**How I tested.** SDK 8.0.131 with HOME, NUGET_PACKAGES, NUGET_HTTP_CACHE_PATH, TMPDIR and DOTNET_CLI_HOME isolated under `scratchpad/adv-env/`, one dotnet process at a time. I built a Lib/App sln fixture with locks. `adv-env/r1/.socket/vendor/nuget/socket-patch.targets` is the §6.3 targets file rendered almost exactly (seed-presence check, direct redirect and the full guard). I added only two `Message` lines for diagnostics. The seed is the design-D 13.0.1 seed under a uuid root. Clones of the fixture are in `adv-env/c1`, `c2` and `c3`. Git experiments are in `adv-env/git1`.

Labels: **VERIFIED** means I ran it here. **REASONED** means I did not run it.

---

## BLOCKER

### B1. Git EOL normalization changes seed bytes, so every fresh clone fails SOCKETPATCH002 (VERIFIED)
- **Scenario.**
  - The repo has `* text=auto` in `.gitattributes`. That is the Visual Studio template default and is common in .NET repos.
  - Newtonsoft's nuspec, `LICENSE.md` and `lib/*/Newtonsoft.Json.xml` are CRLF. I checked: 38/38, 20/20 and 11305/11305 lines are CRLF.
  - Git stores them as LF in the index. The author's working tree stays CRLF and `git status` is clean, so every local build passes.
- **Wrong outcome.**
  - On a fresh CI clone the files check out as LF. The inventory check then fails:
    - `error SOCKETPATCH002: seed modified: …/13.0.1.1843260417/LICENSE.md`
  - VERIFIED in `adv-env/c1`, built after `git clone`.
  - The same class of failure also occurs with:
    - `core.autocrlf=true` (the Git for Windows installer default): LF text files become CRLF on checkout. VERIFIED: a committed LF `x.json` came back `\r\n` in the autocrlf clone.
    - `core.autocrlf=input` on the author's machine.
    - `*.xml text eol=crlf` rules.
    - A root LFS rule such as `*.dll filter=lfs`. With `actions/checkout`'s default `lfs: false`, CI gets pointer files and fails SOCKETPATCH002. That failure is loud, but it is a surprise.
- **Fix.**
  - The CLI writes `.socket/vendor/nuget/.gitattributes` **before** the user's first `git add`:
    ```
    /*-*-*-*-*/** -text -filter -diff -merge
    socket-patch.targets text eol=lf
    .gitignore text eol=lf
    ```
  - VERIFIED: `git check-attr` shows text, filter and eol all unset under a hostile root file (`* text=auto`, `*.dll filter=lfs`, `*.xml text eol=crlf`). An autocrlf=true clone then passes the hash check, and `dotnet build` succeeds (`adv-env/c2`).
  - Blobs committed before the attribute existed stay normalized. I had to `git rm --cached` and re-add them.
  - So `vendor --check` must compare the inventory against the committed blobs (`git cat-file` of `HEAD:<path>`), not the working tree. It should also check `git ls-files --eol` and refuse or fix with `vendor_nuget_eol_normalized`. Otherwise the author's green local run hides the CI failure.
  - Add a golden-image e2e leg: commit, then `git clone`, then build. Run it with both `text=auto` and `autocrlf=true`.

---

## MAJOR

### M1. The same V′ in the GPF (same bytes) fails SOCKETPATCH003 and prints destructive advice (VERIFIED)
- **Scenario.** A shared machine or self-hosted runner with a shared `~/.nuget/packages`, where one repo uses the feed tier (§10) or, later, hosted V′ (§11.2) for the same patch. Those tiers extract `<idl>/<V′>/` into the GPF, and the GPF beats fallback folders at asset resolution.
- **Wrong outcome.**
  - The fallback-tier repo resolves the GPF copy and fails:
    - `error SOCKETPATCH003: foreign …/gpf/newtonsoft.json/13.0.1.1843260417/lib/netstandard2.0/Newtonsoft.Json.dll`
  - This happens even with byte-identical files. VERIFIED in `adv-env/c2`: I copied the seed into the GPF, `restore --locked-mode` succeeded, and the build failed.
  - The error text says "Delete that package folder". Doing that breaks the other repo, which re-extracts the package, and the two repos keep undoing each other.
  - This contradicts the design's own rule that one V′ is always one byte sequence (§6.1).
- **Fix.**
  - Key `SocketPatchNuGetHashes` by `<idl>/<V′>/<relpath>`, not by `<uuid>/…`. Hash the consumed files wherever they resolved.
  - Accept files from a foreign root when all of them match the inventory. Fail SOCKETPATCH003 only when they differ. This is also the feed-tier guard, so the two tiers share one code path.
  - Alternatively, add a tier bit to V′ so fallback V′ never appears in any feed. That costs a bit of the 29-bit uuid space.

### M2. The guard runs in design-time builds, contrary to §9 and G9 (VERIFIED)
- **Scenario.** VS, Rider or C# Dev Kit run a design-time build (`ResolveAssemblyReferencesDesignTime`, `DesignTimeBuild=true`).
- **Wrong outcome.**
  - `ResolvePackageAssets` runs, so the `AfterTargets` guard runs too. VERIFIED: `SPGUARD-RAN DesignTimeBuild='true'`.
  - Any SOCKETPATCH001/002/003/005 condition, such as a stale restore right after `git pull`, fails the design-time build. IntelliSense then shows "project load" errors and references go unresolved on every edit.
  - §9 states "The guard runs only in real builds", which is incorrect.
- **Fix.** Add `and '$(DesignTimeBuild)' != 'true'` to the guard condition. Optionally, emit SOCKETPATCH005/003 as warnings when `$(BuildingInsideVisualStudio)` is true and keep the errors for the command line. Fix the §9 text.

### M3. Windows paths are about 80 characters deeper than the GPF (REASONED, lengths computed)
- **Scenario.** The seed sits at `.socket\vendor\nuget\<36-char uuid>\<idlower>\<V′ with a 10-digit part>\…`.
  - Under the GitHub Actions workspace, `D:\a\my-service-repo\my-service-repo\` plus the Microsoft.Extensions.DependencyInjection.Abstractions `lib/netstandard2.1/*.xml` gives **242** characters.
  - The repo-relative part is only 205, so the §9 warning ("seed path > 240") never fires.
  - `runtimes/<rid>/native/…` and satellite paths are deeper still.
- **Wrong outcome.**
  - Git for Windows (`core.longpaths` is false by default) fails checkout with "Filename too long".
  - MSBuild.exe on .NET Framework and some tools hit MAX_PATH. The same package works fine from `%USERPROFILE%\.nuget\packages`.
- **Fix.**
  - Use a uuid8 directory name (with collision refusal).
  - Compute the warning on an **absolute** path under a pessimistic prefix: 60 characters for CI, or the real root.
  - Refuse above 250 unless `--allow-long-paths`.
  - Document `git config core.longpaths true`.
  - Add the Windows leg to the prototype acceptance criteria, not only to promotion.

### M4. EOL-sensitive byte comparisons in the hot path, `--check` and revert break on Windows and on mixed teams (REASONED; the conversion is VERIFIED in B1)
- **Scenario.** `fallback_in_sync` and `--check` require the targets file and `.gitignore` to be byte-equal to a fresh render. Lock and import records compare the live text with the recorded `new` or `original`.
  - With autocrlf=true, a Windows checkout turns LF-committed files into CRLF (VERIFIED for `.json`).
- **Wrong outcome.**
  - `vendor --check` fails on every Windows CI job.
  - The hot path re-renders on every run.
  - Lock and import revert on Windows treats every record as drift. It keeps the seed, and the revert is not clean.
- **Fix.**
  - Pin `eol=lf` on the generated files via B1's `.gitattributes`.
  - For user-tree files (locks, `Directory.Build.targets`), compare after normalizing CRLF to LF. Splice using the live file's detected EOL.
  - Store records as EOL-neutral text plus the observed EOL.

### M5. Mixed packages.config and SDK repos are left undefined (REASONED)
- **Scenario.** An enterprise solution has old packages.config web apps and new SDK libraries that use the same id@V. This is very common.
- **Wrong outcome.**
  - §5 and §7.1 route packages.config to legacy and allow one tier per repo. `vendor_nuget_layout_mixed` refuses a same-id legacy entry.
  - So either the whole patch is refused, or the legacy path runs. The legacy path brings back the nuget.config catch-all mapping and same-version GPF poisoning for the whole machine, which is exactly what v2 set out to remove.
  - The design never says which of the two happens.
- **Fix.**
  - Define a single entry with two wiring sets: the legacy feed for packages.config projects only, and the fallback tier for SDK projects.
  - Alternatively, refuse explicitly with `vendor_nuget_mixed_project_styles` and describe the options.
  - Either way, add a docker leg that uses nuget.exe under mono (for example the `mono` image), since no packages.config coverage exists today.

### M6. `vendor --check` and the hot path depend on restore outputs (REASONED)
- **Scenario.** A typical CI job runs `git clean -fdx` (or starts from a fresh checkout), then `socket-patch vendor --check`, then `dotnet restore`.
- **Wrong outcome.**
  - Lockless projects have no `obj/project.assets.json`.
  - `plan_closure` then refuses with `vendor_nuget_unrestored`, or reports `closure_changed`, so the pre-restore check fails for no real reason.
- **Fix.**
  - Persist the closure in state and make `--check` validate against it.
  - Recompute the closure only when assets are present.
  - Add a fallback that plans from `dotnet msbuild -getItem:PackageReference` without a restore.

### M7. Renovate and Dependabot rewrite or misread the generated targets file (REASONED)
- **Renovate.** Renovate's nuget manager matches `\.(props|targets)$` and parses `PackageReference Update=… Version=`. It can propose `[13.0.1.N]` → `[13.0.3]` in `socket-patch.targets`.
  - Renovate's default `ignorePaths` (`**/vendor/**`, dot-matching) probably covers `.socket/vendor/nuget/`.
  - But any repo that sets `ignorePaths` replaces that default and is then exposed.
- **Dependabot.** Dependabot's native (MSBuild-evaluating) updater sees the evaluated version V′ and may try to edit the file where it is declared, or skip the dependency.
- **Wrong outcome.**
  - The redirect silently pins some other version.
  - `SocketPatchNuGetUpstream` only knows 13.0.1, so SOCKETPATCH005 does not fire.
  - The patch drops out, and only the lock diff and a later `--check` show it.
- **Fix.**
  - Put the versions in properties (`Version="$(_SpV_3f9a01bc)"`) so regex tools see no literal.
  - Add a render-hash self-check: a `SocketPatchTargetsHash` property that the CLI verifies, plus a SOCKETPATCH006 build warning when the file was edited.
  - Have `vendor` print or emit `ignorePaths: [".socket/**"]` for Renovate.
  - Add a Q3 experiment with the Dependabot nuget updater container.

---

## MINOR

| # | Scenario | Outcome | Fix |
|---|---|---|---|
| m1 | Sparse checkout in cone mode on monorepos: root files are included, root directories are not. | `.socket/` is absent and every build fails MSB4019. VERIFIED (`adv-env/c3`). Loud, but a friction failure mode for every sparse user. | Emit a comment above the Import that names `git sparse-checkout add .socket/vendor/nuget`. `vendor` prints it. Document it for Scalar users. |
| m2 | Declared literal `[13.0.1]` or `13.0.1.0` in a new project. | The redirect does not engage and SOCKETPATCH005 fires. VERIFIED for both. The failure is loud, but CLI planning treats it as "literal known". | Emit one redirect condition per observed normalized-equal literal (`13.0.1`, `13.0.1.0`, `[13.0.1]`, `[13.0.1, )`). |
| m3 | Docker `COPY *.csproj` → `restore` without DBT or `.socket` → `COPY . .` → `build --no-restore`. | SOCKETPATCH005, so fail-closed as designed. VERIFIED. Every Dockerfile needs `COPY Directory.Build.targets .socket/vendor/nuget`, and the layer cache is invalidated per patch. | Document it. `vendor` scans for `Dockerfile*` with `dotnet restore` and warns `vendor_nuget_dockerfile_copy`. |
| m4 | `git clean -fdx` after `vendor` but before commit. | The untracked seed and targets are deleted. The tracked DBT edit stays, giving MSB4019. | Print "commit `.socket/vendor/nuget`" in the outcome. `--check` detects untracked seeds. |
| m5 | Seeds for big packages (native runtimes, analyzers, satellites). | GitHub hard-limits files to 100 MB and warns at 50 MB. The whole package goes into history once per uuid, and org pre-receive hooks may demand LFS. | Cap file and seed size with `vendor_nuget_seed_too_large`. Record a per-repo LFS opt-in only with `checkout lfs:true` documented. Future G-experiment: prune the seed to the closure's TFMs and RIDs (contentHash comes only from `.nupkg.metadata`). |
| m6 | Seed entries that differ only by case, on macOS or Windows. | Checkout collision and SOCKETPATCH002. | Refuse at vendor time on a case-folded inventory collision. |
| m7 | Seed missing, VS restore (no SOCKETPATCH001 there), lockless, and a source that serves V′. V′ is predictable from the committed uuid. | An attacker's `build/*.targets` imports at evaluation, before any guard. This needs control of the id on a source (private or virtual feeds, unreserved ids). | The server-side collision check must cover the org's configured upstreams, not just nuget.org. Refuse the fallback tier for ids that are not prefix-reserved on multi-upstream feeds, or make redirects depend on `Exists(seed)` combined with a hard evaluation error. |
| m8 | GitHub dependency graph, Trivy and CycloneDX read `packages.lock.json`. | They see `12.0.1.N`, so alerts persist and Dependabot security PRs bump the version and drop the patch. Tools that fetch nuspec metadata from nuget.org for V′ fail. | depscan SBOM mapping (already a GA blocker). Document the alert behaviour. Consider emitting Dependabot `ignore` entries. |
| m9 | actions/setup-dotnet `cache: true` keys on the hash of the lock files. | One cache miss per vendor or revert. Also, `NUGET_PACKAGES=${{github.workspace}}/.nuget/packages` puts the GPF inside the repo, and `discover_projects` does not skip `.nuget/` (template packages contain `*.csproj`). | Skip every dot-directory and any directory that is a configured package folder during discovery. |
| m10 | Concurrent restores or builds. | No writes to seed roots, so this is safe (REASONED). The pack hook writes `obj/socket-patch-pack/`, per project. | None needed. Add one parallel `-m` sln leg to the docker suite. |

---

## Attacks that failed (the design holds)
- **Symlinked checkout path.** The resolved paths and `SocketPatchNuGetDir` stay consistent, so the guard passes. VERIFIED.
- **Guard cost.** 52 ms per project for the full 8.7 MB Newtonsoft seed, with `GetFileHash` at 10 ms. Stamp-free hashing is affordable. VERIFIED.
- **Guard targets as written.** They parse and work on SDK 8: the unquoted `StartsWith($(...))`, the `Substring` key and the `%(SpKey)` batching. That is partial G1 evidence, one root only. VERIFIED.
- **Direct redirect, auto-follow and locked-mode restore from the fallback root with a warm upstream 13.0.1 in the GPF.** VERIFIED.
- **Accepted from earlier research, not re-run here:** `NUGET_PACKAGES`, `--packages`, `RestorePackagesPath`, `locals all --clear` and offline for the patched package (VERIFIED-D and VERIFIED-C).

## Required design changes, in priority order
1. Write the nested `.gitattributes` from B1, and have `--check` compare against committed blobs.
2. Make the hash guard location-independent, as in M1.
3. Skip the guard in design-time builds.
4. Use a uuid8 directory and compute the MAX_PATH check on absolute paths.
5. Compare EOL-neutrally in the hot path, `--check` and revert.
6. Define the mixed packages.config policy.
7. Make `--check` work before any restore.
8. Stop exposing literal versions in the targets file, and add a render-hash check.
9. Add real-clone e2e legs (`text=auto`, `autocrlf=true`, sparse, Windows) to the **prototype** acceptance criteria.