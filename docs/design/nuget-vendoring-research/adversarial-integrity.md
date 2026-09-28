# Adversarial integrity review: NuGet vendoring v2 (unique-version fallback seed)

**Verdict: not ready.** The design's integrity story has one gap that decides everything else. Nothing pins the set of files in the committed seed, and every check (lock `contentHash`, the `SOCKETPATCH002` tables, `.nupkg.metadata`, `state.json` `fileInventory`) points back at other files in the same repo. I proved these gaps with dotnet runs:
- a tampered seed, or one with files added, passes `--locked-mode`;
- files added to the seed run as MSBuild code before the guard runs, and can switch the guard off;
- an environment variable switches the guard off;
- a nested `Directory.Build.targets` added later silently builds upstream;
- git's `* text=auto` rewrites seed bytes, so `SOCKETPATCH002` fails on every clean clone.

Most fixes are cheap.

**Setup.** .NET SDK 8.0.131. HOME, NUGET_PACKAGES, NUGET_HTTP_CACHE_PATH, TMPDIR and DOTNET_CLI_HOME were isolated under `<scratch>/adv-integrity/` (`env.sh`). The package feed was an offline local folder holding upstream Newtonsoft.Json 13.0.1. The seed was the design-D e1 seed `13.0.1.1843260417`, placed at `.socket/vendor/nuget/u1/`. The fixture repo is `adv-integrity/base`. It uses the design's §6.3 guard logic (redirect, `SOCKETPATCH005`/`003`/`002`, and the `SocketPatchSeedFile` hash check) almost unchanged. The other experiments ran in `x0` to `x5`.

Labels: **VERIFIED** means I ran it here. **REASONED** means it follows from verified facts or from the code but I did not run it. **DOCS** means it comes from documentation only.

---

## Blockers

### B1. The seed's file set is not pinned. Added files are consumed, run before the guard, and can turn it off. The lock pins nothing.
- **Scenario.** A PR, a bad merge, or a compromised dependency bot changes a seed dll. It also adds `build/netstandard2.0/Newtonsoft.Json.props` and `.targets`, which are not in the nuspec, not in `fileInventory`, and not in `SocketPatchSeedFile`.
- **Result (VERIFIED, `x1`).**
  - On a fresh clone, `dotnet restore --locked-mode` succeeds with the tampered dll. The lock `contentHash` is compared only with `.nupkg.metadata`, and that file sits in the seed and was not changed.
  - NuGet enumerates the seed directory, so the added `build/` files go into `project.assets.json` and are imported: the props through `nuget.g.props`, the targets through `nuget.g.targets`.
  - The props set `SocketPatchNuGetGuard=false`. `dotnet build` then prints `EVIL: injected seed build/ code executed` and `Build succeeded`. No `SOCKETPATCH002` is raised, even though the dll was changed.
- **What this means.**
  - In the fallback tier the lock gives version identity only, not integrity. The claim in §2.5/§4 that the patched package is integrity-pinned is overstated.
  - The design's inventory check hashes only the files it lists, never "these files and no others". It also runs only when `_SpLocal != ''`.
  - A single added file in a large, binary-heavy seed diff is easy for a reviewer to miss.
- **Severity: blocker.**
- **Fixes (all needed):**
  1. **Set-equality check at restore time.** Add a target at `BeforeTargets="_GenerateRestoreGraph;CollectPackageReferences"` that globs `$(SocketPatchNuGetDir)<uuid>/**` (including dotfiles) and fails if the glob differs from the inventory or any hash differs. Restore runs in its own evaluation before `nuget.g.*` is regenerated, so on a clean CI checkout the check runs before the planted code is imported. Run it unconditionally, not gated on `_SpLocal`.
  2. **The CLI checks set equality too.** `fallback_in_sync`, `verify.rs` and `vendor --check` should walk the directory, reject any extra file, symlink or non-regular file, and compare against `fileInventory`.
  3. **Anchor the seed outside the repo.** Add `vendor --check --online`, which rebuilds the expected tree from an independent source and diffs the committed seed against it byte for byte. The source is either the SRI-checked service `nupkg-socket-version`, or the upstream nupkg (with its signature or depscan `upstreamSha512` checked) plus the patch afterHashes. Recommend it as the CI gate. Without it, every pin is self-referential (see M6).
  4. **Harden the guard property.** Covered in M1.

### B2. Git line-ending normalisation changes seed bytes, so SOCKETPATCH002 fails on clean clones.
- **Scenario.** The repo has `* text=auto` in `.gitattributes`, as the common VisualStudio template does, or a developer uses `core.autocrlf=true`, the Git for Windows default.
- **Result (VERIFIED, `x5`, `x4`).**
  - With `* text=auto`, `git add` normalises CRLF to LF in `newtonsoft.json.nuspec`, `LICENSE.md` and `lib/*/Newtonsoft.Json.xml`. The clone's hashes differ from the originals (for example the nuspec goes from `a1d0fb81…` to `2fd73470…`). The dll is unchanged.
  - With `autocrlf=true`, LF-only text members such as `socket-patched.txt` are rewritten on checkout.
- **Wrong outcome.**
  - The developer who vendored still has the original bytes and passes. Every other clone and CI fails `SOCKETPATCH002` on the `SocketPatchSeedFile` rows.
  - The hot path always sees drift, so `vendor` rewrites the seed every run.
  - Legacy mode never hit this, because a `.nupkg` is binary to git.
- **Severity: blocker** (correctness and CI friction; it makes the integrity guard useless in practice).
- **Fix.**
  - Generate `.socket/vendor/nuget/.gitattributes` containing `* -text -diff -merge -filter`. This also turns off LFS.
  - After writing, run `git check-attr text eol filter -- <seed files>`. Refuse with `vendor_artifact_git_transformed` if any file is still text or filtered.
  - Add a case to the Docker test: a repo with `* text=auto`, then clone and build.
  - If `*.dll filter=lfs` survives (the negation does not win), LFS pointer files in the checkout give a loud `SOCKETPATCH002` rather than a silent failure, but refuse at vendor time anyway.

---

## Major

### M1. The guard can be turned off by an environment variable, package props, or a Directory.Build.rsp.
- **VERIFIED (`x3`):**
  - `SocketPatchNuGetGuard=false dotnet build` with a tampered seed dll ends in `Build succeeded`. MSBuild reads environment variables as properties. One stray variable in a CI template turns off every guard in the org.
  - B1 showed that package-level props can do the same.
- **REASONED:** a committed `Directory.Build.rsp` containing `-p:SocketPatchNuGetGuard=false`, or `SocketPatchNuGetAllowUnpatched=true` in the environment, does the same thing and is easy to miss in review.
- **Fix (VERIFIED, `x1` second run).**
  - Assign `<SocketPatchNuGetGuard>true</SocketPatchNuGetGuard>` unconditionally in `socket-patch.targets`. The `-pp` output shows `Directory.Build.targets` imported after the package `build/*.targets` (line 9218 vs 9173). A project or package cannot override that assignment, and neither can an environment variable. Only a global `-p:` can. With this change, the props attack was stopped and `SOCKETPATCH002` fired.
  - Because our file is imported last, our `SocketPatchNuGetGuard` target definition also wins over a package that redefines the target (VERIFIED). A `BeforeTargets` hook in the planted code is still arbitrary code, which is why B1's restore-time check is the real defence.
  - Replace the free `SocketPatchNuGetAllowUnpatched` property with a project allowlist generated by the CLI from `state.json`.
  - Make `vendor --check` flag `Directory.Build.rsp` and `MSBuild.rsp` files that mention `SocketPatch*`.

### M2. A nested Directory.Build.targets added later hides the import. The project builds upstream silently and SOCKETPATCH005 never runs.
- **VERIFIED (`x3`).**
  - Adding `src/Directory.Build.targets`, which does not chain to the root, plus a new `src/New/New.csproj` that references 13.0.1, gives `Build succeeded`.
  - A new lock is created with `resolved: 13.0.1` and the upstream hash. No `SOCKETPATCH*` error appears.
- **Why the design misses it.** §4 and §9 say `SOCKETPATCH005` covers new projects. It covers them only if the import is reached. `ImportDirectoryBuildTargets=false` added later behaves the same way.
- **Severity: major.** The build silently ships the known-vulnerable version.
- **Fix.**
  - `vendor --check` (the CI gate) evaluates every discovered project with `dotnet msbuild -getProperty:SocketPatchNuGetTargetsImported` (batched, or with `-graph` from the sln). It fails if any project that resolves the patched id at V is missing the import.
  - Also, when writing a nested DBT, prefer adding the `GetPathOfFileAbove` chain line.
  - Document that the protection holds only up to the next nested DBT.

### M3. A copy of V′ in the global packages folder takes priority over the committed seed.
The global packages folder (GPF) is NuGet's shared package cache.
- **VERIFIED (`x2`).**
  - When `$NUGET_PACKAGES/newtonsoft.json/13.0.1.1843260417/` holds different dll bytes and a copy of the seed's `.nupkg.metadata`, `restore --locked-mode` succeeds and resolves from the GPF.
  - The guard then fires `SOCKETPATCH003` correctly.
  - If that GPF copy also carries a `build/*.props` that sets `SocketPatchNuGetGuard=false`, the build ends in `Build succeeded` with the other bytes in `bin/`.
- **Consequences.**
  - (a) §9's "NU1403 when locked" holds only when the planted `.nupkg.metadata` hash differs. A copied directory, for example from a cache-sync tool, passes. With M1's fix, `SOCKETPATCH003` still catches it.
  - (b) **Cross-tier false positive (REASONED from the verified priority).** Once any feed-tier repo, or the future hosted V′ (§11.2), puts builder-0 V′ into a shared CI or developer GPF, every fallback-tier repo using that uuid fails `SOCKETPATCH003` on that machine, although the bytes are identical. The GPF is never refreshed, so the failure persists until someone deletes the entry by hand.
- **Fix.**
  - Make the resolved-root check depend on content. Accept a foreign root when the package's whole file set hashes equal the inventory (same set-equality as B1), and fail otherwise.
  - Also narrow the `StartsWith` prefix from `SocketPatchNuGetDir` to the exact `<uuid>` root. Today one uuid's V′ served from a different uuid directory passes (minor).

### M4. Builder bit 1 does not map to a single byte sequence. In the feed tier this gives persistent NU1403 on a shared GPF.
- **REASONED.** Builder 1 covers three different byte producers:
  - the CLI re-versioning the same-version service nupkg;
  - `local_rebuild` from upstream;
  - either of those produced by a different CLI version, where zip writer details change.
- **Consequence.** The §6.1 promise that one V′ equals one byte sequence everywhere is false for builder 1.
  - In the feed tier on a shared runner GPF, the first writer wins. The second repo gets NU1403 on every locked restore on that runner. The research also verified that a failed locked restore still writes to the GPF, so the failure persists.
  - Lockless projects silently use the other repo's bytes. `SOCKETPATCH002` catches this only if the table covers every consumed file.
  - In the fallback tier the only cost is lock churn between developers.
- **Severity: major for the feed tier, minor for the fallback tier.**
- **Fix, any one of:**
  - the feed tier requires builder 0 (service bytes) only;
  - for local builds, derive N from the V′ nupkg's sha512 instead of the uuid, and record the uuid in state and in a nuspec field;
  - freeze `reversion_nupkg` output with a cross-version golden, and forbid `local_rebuild` under builder 1 (give it a third code).

### M5. Revert drift repair "from the signed-content-hash of a GPF copy" trusts a poisoned cache.
- **REASONED from the verified facts (first writer wins; the legacy layout wrote patched same-version bytes to `<idl>/<V>/`).**
  - After legacy use, or on any shared or poisoned GPF, §7.4 step 1 computes the "upstream" hash from patched or tampered bytes and writes it into the committed lock under upstream V.
  - The local locked restore then passes against the poisoned cache, which blesses it. CI either gets NU1403, or, if CI shares the cache, keeps the bad bytes.
- **Fix.**
  - Repair only from depscan `upstreamContentHash`, or from a freshly downloaded nuget.org nupkg whose repository signature has been checked.
  - Never repair from the GPF. If a GPF copy is used at all, require `.nupkg.metadata.source` to be nuget.org, a valid `.signature.p7s`, and `dotnet nuget verify` to pass.

### M6. Provenance of the unpatched files is lost, and verify has no external anchor.
- **REASONED.**
  - A normal restore checks nuget.org's repository signature on every extraction.
  - Vendoring drops the signature once (it has to; NU3008). The fallback tier then never checks anything again (VERIFIED earlier: V-D9 and signing §b).
  - For the unpatched members of the seed, integrity therefore rests on one HTTPS download on the vendoring machine.
  - `verify` and `--check` compare state against seed against lock against targets. All of these are repo data. Only afterHashes (patched files only) come from the server.
- **Fix.**
  - At vendor time, check the upstream nupkg's repository signature, or its sha512 against depscan `upstreamSha512` or the nuget.org catalog `packageHash`.
  - Record `upstreamSha512` and afterHashes in state.
  - `--check --online` (B1 fix 3) recomputes the full expected tree.
  - Make depscan item #3 a GA requirement, not only a revert aid.

### M7. Feed-tier trust: a repo-level, self-signed author trustedSigner applies to every package id.
- **DOCS and VERIFIED mechanics.** The signing research verified that trustedSigners merge across config levels and that `allowUntrustedRoot` passes `require`. NuGet documentation says `<author>` trust has no `owners` or id scope.
- **Scenario.** Whoever holds the pfx (§10) can sign any package id, with any content, and it passes the enterprise's `require` in this repo. The design also normalises repos extending enterprise trust. A contributor could equally add their own fingerprint, and it would look like routine socket-patch churn.
- **Fix.**
  - Generate an ephemeral key per uuid, sign, and destroy the private key before writing the fingerprint, so the trust covers exactly the bytes already signed.
  - Better: never write trustedSigners. Print the `<author>` block for the admin to add to machine-level config, or wait for depscan's CA-issued certificate with an RFC 3161 timestamp (item #8) and trust Socket's certificate once at org level.
  - `vendor --check` flags any repo trustedSigner not recorded in state.

### M8. Name handling: percent-decoding after validation allows path traversal; MSBuild metacharacters allow injection.
- **REASONED from the code.**
  - `read_zip_members` (`crates/socket-patch-core/src/vendor/common.rs:336`) checks the **raw** name with `is_safe_relative_subpath`. §6.2 then percent-decodes. `%2E%2E%2Fx`, `lib%2F..%2F..%2Fx`, or `%5C` passes the raw check and decodes to traversal. Decoded names can also collide (`a%20b` and `a b`) or differ only in case.
  - `is_plain_archive_name` allows `$ @ % ; ' ( )`. These are interpolated into `Include=`, `Condition=` and the `;path=hash;` `Contains` tables. `%XX` is unescaped by MSBuild, `;` splits items, `@(...)` and `$(Prop.Method())` are expanded. The result is a broken or forgeable inventory (a crafted name containing `=HASH;` can satisfy `Contains`) and property expansion at evaluation.
  - `state.json` fields (id, versions, uuid, project paths) are rendered into the targets file by `regenerate_shared` straight from disk.
- **Fix.**
  - Decode, then re-run `is_safe_relative_subpath`, `is_plain_archive_name` and `names_are_unambiguous`, case-folded.
  - Refuse names containing `$ @ % ; ' = ( )`. Otherwise MSBuild-escape (`%24 %40 %25 %3B %27`) and XML-escape every interpolated value.
  - Check id against `^[A-Za-z0-9_.-]+$`, versions against the parser, uuids against strict UUID format, and project paths on every render, not only in the prelude.
  - Zip-bomb protection is already there (`MAX_ENTRIES`, per-entry and total caps enforced against the actual decompressed size). Reuse it and keep it.

### M9. Guard coverage: packages without lib or ref assets are not checked at all.
- **REASONED.**
  - `_SpCand` is built only from runtime, compile, native and resource items. For an analyzer-only or build-only package (source generators, SourceLink, MSBuild task packages), `_SpLocal` is empty.
  - Then nothing is hashed, the `SocketPatchSeedFile` check is skipped (gated on `_SpLocal`), and `SOCKETPATCH003`/`005` never run.
  - Even for lib packages, analyzers and `build/` files are not in `_SpCand`, although they run inside the compiler and MSBuild.
- **Fix.**
  - Decide "patched package present" from the `project.assets.json` `libraries` and `targets` keys, not from asset items.
  - Add `@(Analyzer)` to the candidates.
  - Run the full-inventory check (B1) unconditionally at restore.
  - Gate G1 on an analyzer-only fixture.

---

## Minor

- **m1. Symlinks (REASONED).**
  - Committed symlinks inside the seed, or on its ancestors (`.socket`, `vendor`, `nuget`, `<uuid>`), pass `SOCKETPATCH003`, because that check compares path strings without resolving symlinks. A seed linked outside the repo also opens a check-then-use race between hashing and compilation.
  - Revert's "delete the seed and prune" through a symlinked ancestor deletes outside the repo. Rust's `remove_dir_all` does not follow a symlink passed as its own argument, but it does traverse symlinked ancestors in the path.
  - Fix: apply the existing `refuse_symlinked`/`first_symlink` to the seed and all its ancestors in apply, verify and revert, and refuse non-regular files in the inventory walk.
- **m2. The signature policy is checked only at vendor time (REASONED).** A `require` added later to a repo, ancestor or user config is bypassed silently. The design documents only the CI-only case. Fix: `vendor --check` probes the policy again, and the restore-time target warns when it can see `signatureValidationMode` in `$(RestoreConfigFile)` or repo configs.
- **m3. Seed nuspec edits.** An added `<dependency>` in the nuspec pulls in a new package. That is loud under locked mode (NU1004) and silent when lockless. B1's set-and-hash check at restore closes it. The current design only checks the nuspec after resolution, and only when `_SpLocal` is non-empty.
- **m4. Wording in §9.** "V′ present elsewhere → NU1403 when locked" holds only when the planted `.nupkg.metadata` hash differs (VERIFIED `x2`). The row should say that `SOCKETPATCH003`/`002` is the actual defence.
- **m5. Stale `obj/` (REASONED, low).** A pre-vendor `project.assets.json` followed by `build --no-restore` is caught by `SOCKETPATCH005`. After a revert, a stale assets file pointing at a deleted seed gives a loud missing-file error. Both are fine; keep them as test legs.
- **m6. Hash tables.** They depend on `GetFileHash` giving uppercase hex and on case-sensitive `String.Contains`. This works (VERIFIED `x0`: the metadata comparison passes, and editing `.nupkg.metadata` gives `SOCKETPATCH002`). Pin it with a golden test so a lowercase render never ships.

---

## Verified experiment log

| ID | Where | Result |
|---|---|---|
| x0 | `adv-integrity/x0` | Baseline passes: locked restore, `packageFolders` = GPF then the seed, guard `ok local=2`. The `SocketPatchSeedFile` hash check works: editing `.nupkg.metadata` gives `SOCKETPATCH002`. |
| x1 | `x1` | Tampered dll plus unlisted `build/*.props`/`.targets` in the seed: locked restore passes, the planted targets run, the guard is off, `Build succeeded`. With an unconditional `SocketPatchNuGetGuard=true` in our targets: `SOCKETPATCH002` fires, and a planted redefinition of the guard target is ignored. The `-pp` output shows the DBT imported after the package `build/*.targets`. |
| x2 | `x2` | V′ in the GPF with a copied `.nupkg.metadata` and other bytes: locked restore passes and resolves from the GPF, `SOCKETPATCH003` fires. Adding planted props that disable the guard: `Build succeeded` with the other bytes. |
| x3 | `x3` | A new nested `src/Directory.Build.targets` that does not chain: the new project builds upstream 13.0.1, a new lock is written, no error. The environment variable `SocketPatchNuGetGuard=false` hides a tampered seed. |
| x4/x5 | `x4`, `x5c` | `* text=auto` changes the hashes of the nuspec, LICENSE and xml members; `autocrlf=true` changes LF-only text members; the dll is unchanged. |

## Priority fixes before the prototype is accepted
1. Restore-time full-set check of the seed, plus a CLI set-equality walk (B1).
2. Generated `.gitattributes` with `* -text -diff -merge -filter`, plus a `git check-attr` probe (B2).
3. Unconditional guard assignment and a CLI-managed allowlist (M1).
4. `vendor --check` evaluates every project for the import (M2) and supports `--online` rebuild verification (B1, M6).
5. A resolved-root check that also compares content hashes (M3).
6. Decode-then-validate names and escape MSBuild metacharacters (M8).
7. Candidates chosen from the assets file, including analyzers (M9).
8. Remove GPF-based drift repair (M5).
9. For the feed tier: builder 0 only, or content-derived V′ (M4), and no pfx-holder trust written at repo level (M7).