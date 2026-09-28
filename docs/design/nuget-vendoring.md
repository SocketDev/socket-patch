# NuGet vendoring v2: unique-version fallback seed

**Status:** draft, revision 3. Revision 2 added the four adversarial reviews (§16). Revision 3 records where the prototype on this branch overrides the design (§0).

---

## 0. Where the prototype overrides this design

The prototype in this PR was built after the design review. Building it and testing it against real `dotnet` changed several decisions. When anything below conflicts with this table, **this table wins**. The full list is in §17.

| Design text | Prototype (authoritative) | Why |
|---|---|---|
| `.socket/vendor/nuget` is listed as an "anchor" fallback folder, so restore fails with NU1301 when it is missing (§6.3, G12) | **Removed.** The DBP block now holds a `SocketPatchNuGetImportCheck` target that fails restore with **SOCKETPATCH007** when `socket-patch.targets` was not imported | With the anchor, anyone could plant `<id>/<ver>/` next to the uuid dirs and NuGet would restore it under `--locked-mode` with no seed check. The security review reproduced this on SDK 8. SOCKETPATCH007 is proven by e2e for both locked and unlocked restore. |
| V′ carries a builder bit: `N = 2^30 + ((u32 >> 3) << 1) + builder` (§6.1) | `N = 2^30 + (u32(uuid[0..8]) >> 2)`, with **no builder bit** | contentHash is `base64(sha512(canonical zip of the seed file set))`. It does not depend on whether the bytes came from the service or a local rebuild, so one uuid gives one V′ and one hash. |
| Seed dirs named by uuid8 (§6.2) | Full canonical uuid: `.socket/vendor/nuget/<uuid>/<idlower>/<V′>/` | Keeps `vendor_uuid_dir_rel`, the orphan sweep and the path parsers unchanged. Long Windows paths are still an open item (G8). |
| `--nuget-layout` flag on `GlobalArgs`, and a `nugetShared` ledger section (§5, §6.7) | Opt in with `SOCKET_PATCH_NUGET_LAYOUT=fallback`, or automatically once the ledger has a `nuget-fallback` entry. A purl the ledger holds as a legacy feed entry keeps the feed layout. Shared outputs are rendered from the per-uuid markers, using the ledger `fileInventory` when there is one. | Keeps the prototype contained in the core backend with a few CLI routing lines. It needs no new ledger schema. |
| Lock revert from per-edit records (§6.5, §7.4) | One `nuget_lock_file_v2` record per lock. Revert **unsplices only this entry's V′ values**, back to the recorded originals. | Seeds that share a lock can be reverted in any order, and edits made after vendoring are kept. |
| SOCKETPATCH003/004/006, per-project transitive pins, `--check`, pack range restore, VEX extractor | Not in the prototype. Transitive-only use refuses with `vendor_nuget_transitive_only` (CPM with transitive pinning is supported). | Scope (§15 was too large for one PR). |

## 1. Status and summary

**Status.** Proposed. This design ships as an opt-in layout, `--nuget-layout=fallback`, next to today's feed layout. Today's layout stays the default until the promotion criteria in §15 are met. Hosted mode is unchanged. packages.config projects stay on the legacy layout. A repo that has both packages.config and SDK projects using the same id@V is refused (§5).

**Summary.** The patched package gets its own version, V′, that nothing else can produce. For a stable 3-part upstream version, V′ adds a 4th part derived from the patch uuid, for example `13.0.1` → `13.0.1.1340506222`. The package is committed already extracted, as a NuGet fallback package folder at `.socket/vendor/nuget/<uuid8>/<idlower>/<V′>/`.

The CLI adds one generated block to the nearest `Directory.Build.props` (DBP) of every SDK project. The block has three parts:
- It appends `.socket/vendor/nuget/socket-patch.targets` to `CustomAfterDirectoryBuildTargets`. MSBuild imports that property after the whole `Directory.Build.targets` chain.
- It adds a restore-time `SocketPatchNuGetImportCheck` target. If the targets file was not imported, for example because `.socket/vendor/nuget` is missing, restore fails with SOCKETPATCH007. (§0: this replaces the original anchor fallback folder.)
- It adds one literal uuid comment per patch.

The generated targets file does five things:
1. It adds each uuid8 directory to `RestoreAdditionalProjectFallbackFolders`.
2. It redirects the planned references to the floor range `[V′, )`, using evaluation-time `Update` and `Include` items. Direct references, CPM `PackageVersion`, and TFM-conditioned transitive pins are all handled. An exact `[V′]` is not used, because it spreads through ProjectReference (§16, S-B1).
3. At restore time, it checks that the files in the seed are exactly the recorded set and have the recorded hashes (SOCKETPATCH001/002).
4. At build time, it checks the files that were actually consumed:
   - where they resolved from, and whether their content matches (SOCKETPATCH003);
   - whether the project resolved the unpatched V (SOCKETPATCH005);
   - whether a project where a redirect engaged resolved anything other than V′ (SOCKETPATCH006).
5. It writes the original version range back into packed nuspecs, checks the nuspec before and after pack, and deletes a nupkg that leaks V′ (SOCKETPATCH004).

The CLI also edits, entry by entry, every lock whose graph contains a redirected project. It writes `.socket/vendor/nuget/.gitattributes` so that git stores the seed bytes exactly as written.

**Why this shape:**
- The global packages folder (GPF) is never read or written for the patched package. Every other package keeps its normal GPF and caches.
- `nuget.config` is never edited in the fallback tier.
- Source mapping, user, CI and ancestor configs, `--source`, `NUGET_PACKAGES`, `--packages` and `locals --clear` do not affect the patched package.
- Revert is deterministic: remove the generated block, restore the recorded lock entries, delete the seed. No cache eviction is needed.

**What the lock gives, and what it does not.** In the fallback tier the lock `contentHash` is compared only with the committed `.nupkg.metadata`, so it pins version identity only. Byte integrity comes from three checks:
- the restore-time set-and-hash check of the seed;
- the build-time check of consumed files;
- `vendor --check --online`, which rebuilds the expected seed from an anchor outside the repo (§7.3).

**Enterprise `signatureValidationMode=require`.** A fallback folder is never signature-verified. These repos need the feed tier (§10). That tier is out of prototype scope and waits on depscan's CA-issued signing.

## 2. Background: verified NuGet facts

The research reports cited below, for example `lock-cache §c`, `sources §b` and `adv-env`, are committed in [`nuget-vendoring-research/`](nuget-vendoring-research/). They are the raw notes of the parallel research agents and the adversarial reviewers. `<scratch>` paths in them refer to the throwaway sandbox the experiments ran in.

All runs used .NET SDK 8.0.131 (NuGet 6.8.2) on Linux. Labels:
- **VERIFIED**: run in the original research; the report is cited.
- **VERIFIED-D / -C**: run by the candidate authors.
- **VERIFIED-ADV**: run by the adversarial reviewers: `adv-shapes eN`, `adv-env`, `adv-integrity xN`, `adv-lifecycle VN`.
- **DOCS**: documentation only.
- **REASONED**: inferred from code or from verified facts; not run.
- **UNVERIFIED**: a proposal waiting on a gating experiment (§14).

### 2.1 Why the same id+version cannot be made safe
| Fact | Status |
|---|---|
| The GPF is keyed by id/version only. The first writer wins, and the entry is never refreshed, even with `--force --no-cache --force-evaluate`. | VERIFIED lock-cache §c, sources §a |
| A failed `--locked-mode` restore (NU1403) still extracts the wrong copy into the GPF. | VERIFIED lock-cache §b |
| Lock `contentHash` is compared only with `.nupkg.metadata`. A tampered dll passes locked restore. | VERIFIED lock-cache §b/§c; VERIFIED-ADV x1 (a seed) |
| Patched bytes leak to other lockless projects on the same GPF, and the reverse happens too. | VERIFIED lock-cache §c, shapes §1A |
| For the **same** id+version, the GPF beats a fallback folder. This is also true for V′: a GPF copy of V′ wins over the seed. | VERIFIED lock-cache §e; VERIFIED-ADV x2, adv-env M1 |
| A fallback folder is used in place and never copied into the GPF. The minimum content is `.nupkg.metadata`, the nuspec and `lib/`. NuGet enumerates the whole directory, so extra `build/` files are imported. | VERIFIED lock-cache §e; VERIFIED-D V-D1/2; VERIFIED-ADV x1 |
| A missing folder in `RestoreAdditionalProjectFallbackFolders` gives NU1301 in every project that imports it. | VERIFIED-ADV V2 |
| Restore ignores missing imports. It rewrites locks to upstream, and only `build` fails with MSB4019. | VERIFIED-ADV V3 |

### 2.2 Source routing is fragile
| Fact | Status |
|---|---|
| Source mapping is exclusive and matches by id, not version. Mapping an id to a local feed breaks the id's other versions (NU1102). | VERIFIED sources §b |
| When two sources hold the same id+version, the first to respond wins, so the result is nondeterministic. | VERIFIED sources §d |
| A user-level mapping hides an unmapped repo source. A nearer file replaces a farther file's patterns for the same key. `<clear/>` drops farther levels. | VERIFIED sources §b/§c |
| Config probing covers 3 spellings in every ancestor, then user, `config/*.config` and machine files. | VERIFIED sources §c |

### 2.3 Version identity
| Fact | Status |
|---|---|
| `X.Y.Z+meta` collides with X.Y.Z. `X.Y.Z-socket.N` sorts below X.Y.Z, which gives NU1605 and a false NU1903. | VERIFIED lock-cache §g, shapes §1B |
| A 4-part `X.Y.Z.N` gets its own GPF directory and sorts above X.Y.Z. It works as a direct reference and as a CentralTransitive pin. | VERIFIED lock-cache §g, shapes §1B |
| NuGetAudit still flags V′ whenever the advisory's vulnerable range includes V′. Example: `12.0.1.N` against the `< 13.0.1` advisory. "No false NU1903" holds only when the fix is V's next release. | VERIFIED-ADV e1, V1 (this corrects revision 1) |
| An exact `[V′]` spreads through ProjectReference. It causes NU1107 against a sibling's `>= 13.0.3`, NU1107 across two patched versions of one id, and NU1608 in consumers. | VERIFIED-ADV e2 |
| With `[V′, )` the declaring project resolves V′, AppA/AppC resolve 13.0.3 as before, and AppB resolves 13.0.1.N. No NU1107 or NU1608. | VERIFIED-ADV e2 |
| When V′ is unreachable (an external consumer), `[V′, )` silently resolves the next higher version (NU1603). | VERIFIED-ADV e8 |
| Floating ranges never select a 4th-part version. | VERIFIED shapes §7 |
| A unique version leaks into packed nuspecs. | VERIFIED shapes §1B |
| `Version="13.0.1.0"` means the same as 13.0.1 to NuGet but does not match the literal condition. | VERIFIED-ADV e9 |

### 2.4 MSBuild and injection
| Fact | Status |
|---|---|
| Only the nearest DBP/DBT is imported. Chaining with `GetPathOfFileAbove` works. | VERIFIED shapes §4 |
| With chained DBTs, an import at the end of a nested DBT runs too early when it has a once-guard, so the redirect misses items declared later. | VERIFIED-ADV e7 |
| `CustomAfterDirectoryBuildTargets`, set in DBP, is imported after the whole DBT chain (`Microsoft.Common.targets:55`), without the `ImportDirectoryBuildTargets` condition. | VERIFIED-ADV e7 (SDK 8 only) |
| Our file, imported after DBT, comes after package `build/*.targets`. An unconditional property assignment there beats env vars and package props; only a global `-p:` beats it. | VERIFIED-ADV x1 |
| `@(Item->WithMetadataValue(...))` conditions on evaluation-time ItemGroups work for PackageReference and PackageVersion Update. GlobalPackageReference and case-variant ids are covered. | VERIFIED shapes §2; VERIFIED-D e1/e7; VERIFIED-ADV (shapes) |
| A PrivateAssets=all pin becomes a Direct lock entry and does not leak into pack. Without `Publish="true"` the dll is missing from publish output. | VERIFIED shapes §5; VERIFIED-D V-D11 |
| A pin without a `$(TargetFramework)` condition adds a new Direct dependency to every TFM. | VERIFIED-ADV e3 |
| The `AfterTargets=ResolvePackageAssets` guard runs in design-time builds. | VERIFIED-ADV (adv-env M2) |
| Evaluation-time redirects work under static-graph restore (sln, and CPM with pinning on). SOCKETPATCH001 at `BeforeTargets=CollectPackageReferences` fires in normal and static-graph restore. | VERIFIED-D V-D3b; VERIFIED-ADV (shapes) |
| The guard as written runs cleanly: it parses, batches, and preserves `GetFileHash` metadata. Cost is 52 ms per project for an 8.7 MB seed. | VERIFIED-ADV (shapes, env) |

### 2.5 Integrity, signing and git
| Fact | Status |
|---|---|
| For an unsigned nupkg, contentHash = base64(sha512(file)). For a signed nupkg it is computed with `.signature.p7s` removed. Signing never changes contentHash. | VERIFIED lock-cache §a, signing §e |
| depscan's SRI with `sha512-` removed equals the unsigned contentHash. | VERIFIED depscan §1 |
| Keeping the upstream signature on changed bytes gives NU3008. An unsigned package under `require` gives NU3004. Package and fallback folders are never verified. | VERIFIED signing §a/§b; VERIFIED-D V-D9 |
| A self-signed author cert plus `<author allowUntrustedRoot>` passes `require`. `<author>` trust has no id scope. | VERIFIED signing §b/§c; DOCS |
| `* text=auto`, `core.autocrlf=true` and `eol` rules rewrite seed text members. The author's tree stays clean, and every clone gets different bytes. | VERIFIED-ADV adv-env B1, x4/x5, V4 |
| A nested `.gitattributes` with `* -text -diff -merge -filter` gives byte-identical clones under hostile root rules. | VERIFIED-ADV adv-env c2, V4 |
| Seed files added outside the nuspec are imported and can disable a guard whose assignment is conditional. | VERIFIED-ADV x1 |

## 3. Candidates considered

| Key | Summary | Judge mean (/100) |
|---|---|---|
| A (feed hardened) | Same-version local feed, chain-aware mapping, pins in every lock, gitignored per-generation `RestorePackagesPath` | 59.6 |
| B (unique version via feed) | `X.Y.Z.(D+1)-socket.p<uuid8>.<rev>` in a local feed, with per-project redirects | 70.5 |
| C (repo-local seed) | Same id+version seeded into a committed repo-wide `RestorePackagesPath` | 70.2 |
| D (unique-version fallback seed) | 4th-part V′ in a committed fallback folder; no config edits | **76.3** (chosen by 2 of 3 judges) |

Mean judge scores per criterion (1–10; the total is out of 100, with correctness, GPF safety and integrity weighted double). Each judge scored through a different lens: shapes and environments, integrity and supply chain, and operability.

| Candidate | correctness | integrity | gpf safety | diff size | revert | ci friction | impl cost | server side | total |
|---|---|---|---|---|---|---|---|---|---|
| A-feed-hardened | 5.7 | 7.0 | 7.7 | 5.7 | 6.3 | 3.7 | 3.7 | 5.7 | 59.6 |
| B-unique-version | 6.3 | 7.7 | 9.7 | 5.7 | 8.0 | 5.3 | 2.7 | 8.3 | 70.5 |
| C-repo-local-seed | 7.7 | 7.3 | 9.3 | 4.3 | 8.0 | 4.0 | 6.3 | 5.7 | 70.2 |
| D-wildcard | 7.7 | 7.3 | 9.7 | 5.7 | 8.7 | 8.3 | 4.7 | 7.7 | 76.3 |

## 4. Decision

**D is the base.** The grafts from the other candidates:
- **From C:** the resolved-root and consumed-file hash guard, now content-aware; `.gitignore` negations checked with `git check-ignore`; eviction of GPF entries leaked by the legacy layout, identified through `.nupkg.metadata` `source`.
- **From B:** an invertible V′ derivation shared with depscan; the declared-version guard; refusal when a dependency constraint excludes V′; server-recorded upstream hashes; a sandboxed relock; the pack-roots policy; NuGetAuditSuppress.
- **From A:** version-precise pins in every affected lock; config-chain discovery, used for signature policy only; the WIRING_FILES and sweep fix; the fix for the id-only hosted lock match at `redirect/mod.rs:5431`.

**C was rejected** because a repo-wide `RestorePackagesPath` moves every package into the repo. That throws away the CI and developer GPF caches and breaks Docker layers and scripts, which is an operational regression for every repo.

**Structural changes after adversarial review:**
1. The floor range `[V′, )` replaces `[V′]`. SOCKETPATCH006 is added, and lock edits reach every consumer of a redirected project.
2. The injection point moves from a DBT Import line to a DBP `CustomAfterDirectoryBuildTargets` block.
3. A generated `.gitattributes` is added, and `--check` compares against committed blobs.
4. A restore-time set-equality check of the seed is added. The guard property is assigned unconditionally. Exemptions come from a CLI-managed allowlist.
5. The foreign-root check depends on content, and hash keys are `<idl>/<V′>/<rel>`.
6. Shared outputs are regenerated by a CLI finalize hook (`sync_shared`) that runs after every ledger mutation. Removing the block needs no records.
7. Patch updates, revert ordering, migration ordering and v4 compatibility are specified (§7.4–§7.7).
8. Directories are named by uuid8, and the long-path check uses absolute paths.

## 5. Tiers and layout selection

| Tier | When | Mechanism |
|---|---|---|
| **fallback** | SDK-style PackageReference projects with no visible require policy | Committed extracted seed. Prototype scope. |
| **feed** | A require policy is visible, the depscan org policy says require, or `--nuget-tier=feed` | Signed V′ nupkg in a per-uuid flat feed. Builder 0 (service bytes) only. Post-prototype, blocked on G6 and depscan #8 (§10). |
| **legacy** | packages.config-only repos, `--nuget-layout=feed`, and existing legacy entries | Today's `nuget_feed.rs`, unchanged. |

**Selection rules:**
- The layout is selected by `--nuget-layout <feed|fallback>` on `GlobalArgs`, so it applies to vendor, scan, get and repair. The environment variable is `SOCKET_NUGET_LAYOUT`. The default is `feed` until promotion.
- **Inference:** if any `nuget-fallback` entry exists, or the top-level optional `state.nugetLayout == "fallback"`, new NuGet entries use fallback whatever the flag says. The first fallback vendor sets `nugetLayout`.
- **Hybrid router:** an entry whose `flavor` is `nuget-fallback`, or that carries `nuget_lock_entry_v2` records, always routes to the fallback backend. This covers entries that an older binary relabelled (§11.3).
- **Refusals:**
  - `vendor_nuget_tier_mixed`: more than one tier per repo.
  - `vendor_nuget_mixed_project_styles`: packages.config and SDK projects resolve the same id@V. A dual-wiring entry is open question Q5.

## 6. Mechanism

### 6.1 Deriving V′
The function is pure and must be identical in `vendor/nuget_version.rs` and in depscan `lib/src/nuget/socket-version.ts`, with shared golden vectors. Its inputs are the normalized upstream V, the uuid, and the builder (service = 0, local = 1).

| Upstream V | V′ | Status |
|---|---|---|
| Stable, ≤ 3 parts or zero 4th part | `V.N`, where `N = 2^30 + ((u32(uuid[0..8]) >> 3) << 1) + builder`, in [2^30, 2^31−1] | Form VERIFIED-D (e1/e7) |
| 4-part with D > 0 | `A.B.C.(D+1)-socket.p<uuid8>.<builder>` | Refused (`vendor_nuget_version_unsuffixable`) until G5 |
| Prerelease | `X.Y.Z-pre.socket.p<uuid8>.<builder>` | Refused until G5 |

- **Example:** uuid `3f9a01bc-…` gives `13.0.1.1340506222` for a service build, and `…223` for a local build.
- **Collision refusals:**
  - `vendor_nuget_version_collision`: two entries for the same id@V derive the same V′.
  - `vendor_nuget_version_gap`: a published version of the id lies in (V, V′]. For example, an upstream 4-part `13.0.1.5` would change floor-range resolution. The server checks nuget.org and the org's configured upstreams (adv-env m7). The CLI repeats the check against the flatcontainer index when it is online.
- **One V′, one byte sequence:** service artifacts are write-once per uuid. Builder 1 is not a single byte producer (adv-integrity M4), but in the fallback tier V′ bytes exist only in the committed seed, so the only cost is lock churn. The feed tier accepts builder 0 only.
- The hot path accepts either builder for an existing uuid. The builder changes only with `--nuget-rebuild-service` (Q4).

### 6.2 On-disk layout (fallback tier)
```
Directory.Build.props                  EDITED (socket-patch block) or CREATED
src/Directory.Build.props              EDITED where it is the nearest DBP of an SDK project
src/Lib/packages.lock.json             EDITED (entries for id@V and Project ranges only)
src/AppA/packages.lock.json            EDITED (Project range only: consumer of a redirected project)
.socket/vendor/state.json              flavor "nuget-fallback", nugetLayout, nugetShared
.socket/vendor/nuget/
  socket-patch.targets                 GENERATED by sync_shared (LF, -text)
  .gitignore                           GENERATED (negations)
  .gitattributes                       GENERATED
  3f9a01bc/                            fallback root (uuid8; full uuid in marker + state)
    socket-patch.vendor.json
    newtonsoft.json/13.0.1.1340506222/
      .nupkg.metadata                  {"version":2,"contentHash":"<b64 sha512 of V′ nupkg>","source":null}
      newtonsoft.json.nuspec
      lib/netstandard2.0/Newtonsoft.Json.dll   (patched)
      …
```

**`.gitattributes`:**
```
* -text -diff -merge -filter
/socket-patch.targets -text diff
/.gitignore -text diff
/.gitattributes -text diff
```

**`.gitignore`:**
```
!/3f9a01bc/
!/3f9a01bc/**
!/socket-patch.targets
!/.gitattributes
```

**Post-write checks.** After writing, the CLI runs:
- `git check-ignore` on the seed files, refusing with `vendor_artifact_gitignored`;
- `git check-attr text eol filter` on the seed files, refusing with `vendor_artifact_git_transformed`, for example when a root LFS rule survives.

**Seed extraction.** The seed is extracted from the V′ nupkg following NuGet's own rules:
- entry names are percent-decoded, **then** validated with `is_safe_relative_subpath`, `is_plain_archive_name` and `names_are_unambiguous`, compared case-folded;
- names containing any of `$ @ % ; ' = ( )` are refused (`vendor_nuget_unsafe_member`);
- OPC parts and `.signature.p7s` are dropped;
- the nuspec is renamed to `<idlower>.nuspec`;
- no `.nupkg` or `.sha512` is written;
- the existing zip-bomb caps (`MAX_ENTRIES`, per-entry and total limits) are reused.

**Size and path limits:**
- `vendor_nuget_seed_too_large` if any file is over 50 MB or the seed is over 200 MB (configurable).
- `vendor_nuget_long_path` warns when the absolute path, under a pessimistic 60-character CI prefix or the real root, exceeds 240 characters. Above 250 characters the CLI refuses unless `--allow-long-paths` is given.

### 6.3 Directory.Build.props block
```xml
  <!-- socket-patch:begin (generated; run `socket-patch vendor --revert` to remove) -->
  <!-- socket-patch: .socket/vendor/nuget/3f9a01bc uuid=3f9a01bc-… -->
  <PropertyGroup Label="socket-patch">
    <CustomAfterDirectoryBuildTargets Condition="!$(CustomAfterDirectoryBuildTargets.Contains('socket-patch.targets'))">$(CustomAfterDirectoryBuildTargets);$(MSBuildThisFileDirectory).socket/vendor/nuget/socket-patch.targets</CustomAfterDirectoryBuildTargets>
    <RestoreAdditionalProjectFallbackFolders>$(RestoreAdditionalProjectFallbackFolders);$(MSBuildThisFileDirectory).socket/vendor/nuget</RestoreAdditionalProjectFallbackFolders>
  </PropertyGroup>
  <!-- socket-patch:end -->
```

**Placement.** The block goes in the nearest DBP of **every** SDK project in the same git worktree, including projects that do not use the patched package. That lets SOCKETPATCH005 and 006 cover projects added later. Submodules, template content (`PackageType=Template`) and dot-directories are skipped, with warning `vendor_nuget_import_skipped`. Nested files use a relative `../` path. If the root has no DBP, the CLI creates `<Project>` containing the block and nothing else.

**What the block does:**
- **Import ordering.** The targets are imported after the entire DBT chain, which fixes the nested-chain misfire (VERIFIED-ADV e7, SDK 8). The `Contains` guard dedupes chained DBPs. Whether the property exists on SDK 6 and 7 is G10.
- **Restore fail-closed.** Superseded (§0). The anchor folder let anyone plant packages. The prototype's `SocketPatchNuGetImportCheck` target fails restore with SOCKETPATCH007 instead. VERIFIED in the e2e.
- **v4 compatibility.** The literal uuid comments let v4 drift-keep and VEX liveness see the uuid (§11.3).

**Refusals:**
- `vendor_nuget_dbp_disabled`: a project sets `ImportDirectoryBuildProps=false`.
- `vendor_nuget_non_sdk_project`: a non-SDK project uses PackageReference, because the guard would never run there (adv-shapes M5).

### 6.4 `socket-patch.targets` (generated; illustrative, deterministic, sorted)
The example repo:
- Lib has a direct 13.0.1 reference.
- AppA references Lib and Lib3 (13.0.3).
- Tool gets 12.0.1 through Bson, for netstandard2.0 only.
- Web uses CPM.

```xml
<Project>
  <!-- Generated by socket-patch from .socket/vendor/state.json; render sha256 recorded in state. Do not edit. -->
  <!-- socket-patch: .socket/vendor/nuget/3f9a01bc  .socket/vendor/nuget/7c21d0e4 -->
  <PropertyGroup>
    <SocketPatchNuGetTargetsImported>true</SocketPatchNuGetTargetsImported>
    <SocketPatchNuGetGuard>true</SocketPatchNuGetGuard>
    <SocketPatchNuGetDir>$([MSBuild]::NormalizeDirectory('$(MSBuildThisFileDirectory)'))</SocketPatchNuGetDir>
    <SocketPatchRepoRoot>$([MSBuild]::NormalizeDirectory('$(MSBuildThisFileDirectory)', '..', '..', '..'))</SocketPatchRepoRoot>
    <SocketPatchProject>$([MSBuild]::MakeRelative('$(SocketPatchRepoRoot)', '$(MSBuildProjectFullPath)').Replace('\', '/'))</SocketPatchProject>
    <_SpV_3f9a01bc>13.0.1.1340506222</_SpV_3f9a01bc>
    <_SpV_7c21d0e4>12.0.1.1994350720</_SpV_7c21d0e4>
    <RestoreAdditionalProjectFallbackFolders>$(RestoreAdditionalProjectFallbackFolders);$(SocketPatchNuGetDir)3f9a01bc;$(SocketPatchNuGetDir)7c21d0e4</RestoreAdditionalProjectFallbackFolders>
    <_SpPatched>;newtonsoft.json/$(_SpV_3f9a01bc);newtonsoft.json/$(_SpV_7c21d0e4);</_SpPatched>
    <_SpUpstream>;newtonsoft.json/13.0.1;newtonsoft.json/12.0.1;</_SpUpstream>
    <_SpAllowUnpatched>;src/Legacy/Legacy.csproj;</_SpAllowUnpatched>
    <_SpHashes>;newtonsoft.json/13.0.1.1340506222/lib/netstandard2.0/newtonsoft.json.dll=4F33…BD;…;</_SpHashes>
  </PropertyGroup>

  <!-- 3f9a01bc: Newtonsoft.Json 13.0.1 -> V′; one condition per recorded spelling of 13.0.1 -->
  <ItemGroup Condition="'@(PackageReference->WithMetadataValue('Identity','Newtonsoft.Json')->WithMetadataValue('Version','13.0.1'))' != '' or '@(PackageReference->WithMetadataValue('Identity','Newtonsoft.Json')->WithMetadataValue('Version','13.0.1.0'))' != ''">
    <PackageReference Update="Newtonsoft.Json" Version="[$(_SpV_3f9a01bc), )" />
    <SocketPatchRedirect Include="newtonsoft.json/$(_SpV_3f9a01bc)" />
    <NuGetAuditSuppress Include="https://github.com/advisories/GHSA-5crp-9r3c-p9vr" />
  </ItemGroup>
  <ItemGroup Condition="'$(ManagePackageVersionsCentrally)' == 'true' and '@(PackageVersion->WithMetadataValue('Identity','Newtonsoft.Json')->WithMetadataValue('Version','13.0.1'))' != ''">
    <PackageVersion Update="Newtonsoft.Json" Version="[$(_SpV_3f9a01bc), )" />
    <SocketPatchRedirect Include="newtonsoft.json/$(_SpV_3f9a01bc)" />
  </ItemGroup>

  <!-- 7c21d0e4: 12.0.1 transitive-only in Tool, netstandard2.0 only, while its direct parent Bson is still referenced -->
  <ItemGroup Condition="'$(SocketPatchProject)' == 'src/Tool/Tool.csproj' and '$(TargetFramework)' == 'netstandard2.0' and '@(PackageReference->WithMetadataValue('Identity','Newtonsoft.Json'))' == '' and '@(PackageReference->WithMetadataValue('Identity','Newtonsoft.Json.Bson'))' != ''">
    <PackageReference Include="Newtonsoft.Json" Version="[$(_SpV_7c21d0e4), )" PrivateAssets="all" Publish="true" />
    <SocketPatchRedirect Include="newtonsoft.json/$(_SpV_7c21d0e4)" />
  </ItemGroup>

  <ItemGroup>
    <SocketPatchSeedFile Include="$(SocketPatchNuGetDir)3f9a01bc/newtonsoft.json/13.0.1.1340506222/.nupkg.metadata" Sha256="C3E7…AF" PackageKey="newtonsoft.json/13.0.1.1340506222" />
    <!-- … one row per seed file, every uuid -->
  </ItemGroup>

  <!-- restore time: the seed must be exactly the inventory (SOCKETPATCH001), with the recorded hashes (SOCKETPATCH002) -->
  <Target Name="SocketPatchNuGetSeedCheck" BeforeTargets="_GenerateRestoreGraph;CollectPackageReferences" Condition="'$(SocketPatchNuGetGuard)' != 'false' and '$(_SpSeedChecked)' != 'true'">
    <ItemGroup>
      <_SpOnDisk Include="$(SocketPatchNuGetDir)3f9a01bc/**;$(SocketPatchNuGetDir)7c21d0e4/**" Exclude="$(SocketPatchNuGetDir)*/socket-patch.vendor.json" />
      <_SpExtra Include="@(_SpOnDisk)" Exclude="@(SocketPatchSeedFile)" />
      <_SpMissing Include="@(SocketPatchSeedFile)" Condition="!Exists('%(FullPath)')" />
    </ItemGroup>
    <Error Condition="'@(_SpMissing)@(_SpExtra)' != ''" Code="SOCKETPATCH001" Text="socket-patch: vendored NuGet seed does not match its inventory (missing: @(_SpMissing); unexpected: @(_SpExtra)). Run 'git checkout -- .socket/vendor/nuget' or 'socket-patch vendor'." />
    <GetFileHash Files="@(SocketPatchSeedFile)" Algorithm="SHA256"><Output TaskParameter="Items" ItemName="_SpSeedHashed" /></GetFileHash>
    <Error Condition="'%(_SpSeedHashed.FileHash)' != '%(_SpSeedHashed.Sha256)'" Code="SOCKETPATCH002" Text="socket-patch: vendored NuGet seed file modified: %(_SpSeedHashed.Identity)." />
    <PropertyGroup><_SpSeedChecked>true</_SpSeedChecked></PropertyGroup>
  </Target>

  <!-- build time: consumed files (G1). Skipped in design-time builds. -->
  <Target Name="SocketPatchNuGetGuard" AfterTargets="ResolvePackageAssets" Condition="'$(SocketPatchNuGetGuard)' != 'false' and '$(DesignTimeBuild)' != 'true'">
    <ItemGroup>
      <_SpCand Include="@(RuntimeCopyLocalItems);@(ResolvedCompileFileDefinitions);@(RuntimeTargetsCopyLocalItems);@(NativeCopyLocalItems);@(ResourceCopyLocalItems);@(Analyzer)"
               SpKey=";$([System.String]::Copy('%(NuGetPackageId)/%(NuGetPackageVersion)').ToLowerInvariant());" />
      <_SpPatched Include="@(_SpCand)" Condition="$(_SpPatched.Contains('%(SpKey)'))" />
      <_SpUnpatched Include="@(_SpCand)" Condition="$(_SpUpstream.Contains('%(SpKey)'))" />
      <_SpDrift Include="@(_SpCand)" Condition="'@(SocketPatchRedirect)' != '' and '%(NuGetPackageId)' != '' and $([System.String]::Copy('@(SocketPatchRedirect)').ToLowerInvariant().Contains('$([System.String]::Copy('%(NuGetPackageId)').ToLowerInvariant())/')) and !$(_SpPatched.Contains('%(SpKey)'))" />
    </ItemGroup>
    <Error Condition="'@(_SpUnpatched)' != '' and !$(_SpAllowUnpatched.Contains(';$(SocketPatchProject);'))" Code="SOCKETPATCH005" Text="socket-patch: $(SocketPatchProject) resolved UNPATCHED %(_SpUnpatched.NuGetPackageId) %(_SpUnpatched.NuGetPackageVersion), which is vendored-patched in this repo. Run 'socket-patch vendor'." />
    <Error Condition="'@(_SpDrift)' != ''" Code="SOCKETPATCH006" Text="socket-patch: $(SocketPatchProject) redirects %(_SpDrift.NuGetPackageId) to the Socket-patched version but resolved %(_SpDrift.NuGetPackageVersion). Run 'socket-patch vendor' to re-plan." />
    <GetFileHash Files="@(_SpPatched)" Algorithm="SHA256" Condition="'@(_SpPatched)' != ''"><Output TaskParameter="Items" ItemName="_SpHashed" /></GetFileHash>
    <ItemGroup>
      <_SpBad Include="@(_SpHashed)" Condition="!$(_SpHashes.Contains(';%(SpKeyPath)=%(FileHash);'))" />
    </ItemGroup>
    <Error Condition="'@(_SpBad)' != ''" Code="SOCKETPATCH003" Text="socket-patch: %(_SpBad.NuGetPackageId) %(_SpBad.NuGetPackageVersion) resolved from '%(_SpBad.FullPath)' with content that differs from the vendored patch. Another tool placed a different copy of this version in a package folder; remove it only if no other repo relies on it." />
  </Target>
  <!-- pack targets: §6.6 -->
</Project>
```

**Notes on the file:**
- **Content-aware foreign root.** `SpKeyPath` is `<idl>/<V′>/<rel>`, computed from the path relative to the package root it resolved in. The mechanics are G15. A byte-identical copy in the GPF passes. A different copy fails SOCKETPATCH003. The error message no longer tells the user to delete the folder.
- **Package presence.** Presence is decided from `@(_SpCand)`, which now includes `@(Analyzer)`. For packages with no lib, ref or analyzer assets, the guard also reads the `libraries` keys of `project.assets.json` (G1).
- **Guard escape hatch.** `SocketPatchNuGetGuard` is assigned unconditionally, so the only way to turn it off is a global `-p:SocketPatchNuGetGuard=false`. `vendor --check` flags `*.rsp` files that mention `SocketPatch*`.
- **SOCKETPATCH005 exemptions.** Projects are exempted only through `_SpAllowUnpatched`, which is rendered from `state.nuget.allowUnpatched` (`socket-patch vendor --nuget-allow-unpatched <proj>`). There is no free-form property any more.
- **Versions behind properties.** Versions sit in `_SpV_*` properties, so regex updaters see no literals. If a bot edits them anyway, SOCKETPATCH006 fires, and `--check` compares the render sha.
- **Split CPM.** When one central PackageVersion resolves differently across projects, the CLI emits the per-project form `('$(SocketPatchProject)'=='a' or …)` (VERIFIED-D e7). A CPM transitive-only project gets a Version-less `Include` pin plus `Publish="true"`. A `VersionOverride` equal to V gets `VersionOverride="[V′, )"`. VersionOverrides to other versions are left alone.
- **TFM conditions.** Pin TFM conditions use the alias taken from assets `project.frameworks`. A multi-TFM pin with no assets file, or with a custom alias, is refused (`vendor_nuget_tfm_alias_unknown`).

### 6.5 Lock edits
**Which lock.** For each project, in order:
1. a static `NuGetLockFilePath` (a dynamic value is refused with `vendor_nuget_lockpath_dynamic`);
2. `packages.<Project>.lock.json`;
3. `packages.lock.json`.

**Edits.** Splices are byte-preserving and TFM/RID-scoped. The exact `[V′, )` text is G11; the goldens are re-captured from `--force-evaluate`.

| Project role | Before | After |
|---|---|---|
| Direct / CPM direct | `Direct`, `requested "[13.0.1, )"`, `resolved 13.0.1` | `Direct`, `requested "[V′, )"`, `resolved V′`, `contentHash <seed>` |
| CPM uniform, pinning on (CentralTransitive) | `CentralTransitive`, `requested "[13.0.1, )"` | stays `CentralTransitive`; `requested "[V′, )"` plus new resolved and hash (VERIFIED-ADV e5 corrects revision 1) |
| Transitive pin | `Transitive` | `Direct` with `requested` inserted. Written in NuGet's canonical order: Direct entries first (VERIFIED-ADV e3). |
| Auto-follow consumer that resolved V | `Transitive 13.0.1` | `Transitive V′` plus hash |
| Consumer that resolved R > V (AppA/AppC) | unchanged | unchanged. Its resolution is R because R > V′ is guaranteed by the gap check. |
| `Project` entry listing a redirected project | `"[13.0.1, )"` | `"[V′, )"`, in **every** lock whose graph contains that project |

**Records.**
- One record per edit: `nuget_lock_entry_v2` (key `<lockrel>#<tfm>[/<rid>]#<id>`) or `nuget_lock_project_range`.
- Records are stored EOL-neutral, together with the observed EOL.
- Live-text comparisons normalize CRLF to LF, and splices use the live file's EOL.
- Relock comparison is semantic (parsed JSON), not textual.

### 6.6 Pack
- **Range restore** (`AfterTargets=_GetAbsoluteOutputPathsForPack`, VERIFIED-D V-D6 and VERIFIED-ADV e5): `"[V′, )"` is replaced with the **recorded original literal range**, for example `[13.0.1]` stays exact.
- **Pre-check**, `BeforeTargets=GenerateNuspec`: fail SOCKETPATCH004 if the rewritten assets still contain any V′.
- **Post-check**, `AfterTargets=GenerateNuspec`: read exactly `$(NuspecOutputAbsolutePath)$(PackageId).$(PackageVersion).nuspec`. This avoids MSB4184 when several nuspecs are present (VERIFIED-ADV e5). On failure, `<Delete Files="@(NuGetPackOutput)"/>` runs before the error, because the nupkg was already written (VERIFIED-ADV e5).
- Both checks are G2. If G2 fails on any supported SDK, packable projects with a direct patched reference are refused (`vendor_nuget_packable_direct`). Opt-in: `--nuget-pack-policy=roots`.

### 6.7 State
```json
{"ecosystem":"nuget","flavor":"nuget-fallback","basePurl":"pkg:nuget/Newtonsoft.Json@13.0.1","uuid":"3f9a01bc-…",
 "artifact":{"path":".socket/vendor/nuget/3f9a01bc/newtonsoft.json/13.0.1.1340506222","sha256":"",
   "fileInventory":{"lib/netstandard2.0/Newtonsoft.Json.dll":"4f33…","…":"…"}},
 "nuget":{"tier":"fallback","wired":true,"upstreamVersion":"13.0.1","patchedVersion":"13.0.1.1340506222",
   "builder":"local","contentHash":"FRVi…","upstreamSha512":"…","upstreamContentHash":"…","packPolicy":"restore-ranges",
   "literals":["13.0.1","13.0.1.0"],"allowUnpatched":[],
   "projects":[{"path":"src/Lib/Lib.csproj","role":"direct","declared":"13.0.1","tfms":["net8.0"]},
               {"path":"src/AppA/AppA.csproj","role":"range-consumer","tfms":["net8.0"]}]},
 "wiring":[
   {"file":"src/Lib/packages.lock.json","kind":"nuget_lock_entry_v2","key":"…#net8.0#Newtonsoft.Json","original":"…","new":"…"},
   {"file":"Directory.Build.props","kind":"nuget_uuid_anchor","action":"Referenced"}]}
```
Top-level additions to `VendorState`, all additive and optional:
- `nugetLayout`;
- `nugetShared`: `{renderSha256, props:[{file, created, original}]}`.

**Rules:**
- The DBP block is owned by the state, not by any entry. `nuget_uuid_anchor` is a reference only: v5 never reverts from it, and it exists so v4 sees the file (§11.3).
- `nuget.projects` is the authoritative closure (§7.2).
- `wired=false` marks Preserved or Kept entries. `sync_shared` never renders them.
- `fileInventory` intactness replaces the existence-only `ledger_covers` check for directory artifacts.

## 7. Algorithms

### 7.1 Apply (`vendor_nuget_fallback`)
1. **Prelude** (`fallback_prelude`, shared with `service_preflight`). It refuses on:
   - unsafe coordinates;
   - `version_unsuffixable`, `version_gap`, `version_collision`;
   - signature policy: config chain for every project directory, plus `DOTNET_NUGET_SIGNATURE_VERIFICATION`;
   - `mixed_project_styles`, `dbp_disabled`, `non_sdk_project`;
   - `external_consumer`: a project outside the root references a redirected project, or an `.sln`/`.slnf` above the root lists one;
   - `exact_dependency`: a dependency constraint excludes V′;
   - `version_literal_unknown`: property-expanded versions on an SDK without `-getItem` (< 8), which are refused;
   - `sdk_unavailable`: the SDK that `global.json` pins is not installed;
   - `implicit_reference`: `IsImplicitlyDefined`, for example FSharp.Core;
   - `tool_only`: tool packages cannot be patched this way, and the crawler must not claim that they are covered;
   - `tier_mixed`, `layout_mixed`.

   Entries that share this entry's ledger key or basePurl are excluded from the duplicate and collision checks.
2. **Closure plan** (`plan_closure`):
   - Enumerate `*.*proj` plus the projects listed in the sln. Skip dot-directories, `bin`, `obj`, `node_modules` and configured package folders.
   - Read assets, or else the lock, or else csproj and CPM text.
   - Count a `resolved` that decodes (`parse_socket_nuget_version`) to (id, V) as V.
   - Roles: `direct`, `cpm-uniform`, `cpm-split`, `auto-follow`, `pin`, and `range-consumer`. A range-consumer is any project whose graph reaches a redirected project; ProjectReferences are walked in both directions.
   - Projects that are already planned and have no assets are not refused. `vendor_nuget_unrestored` applies only to **new** projects with neither a lock nor assets.
3. **Materialise the V′ nupkg:**
   - from the service `nupkg-socket-version` artifact (builder 0), or
   - by running `reversion_nupkg` on the SRI-verified same-version service nupkg or on `local_rebuild` output (builder 1).

   The upstream is verified by its repository signature, or by sha512 against depscan `upstreamSha512`. Every patched member is checked against its afterHash.
4. **Stage everything in memory:** the seed tree, all lock splices, and the new DBP blocks.
5. **Write, with snapshots:**
   - Write the seed atomically (temp directory, then rename). Reuse it if it already matches `fileInventory`.
   - Snapshot the bytes of every file about to be touched, then write the locks and DBPs, each by temp file and rename.
6. Optional `--nuget-relock`: a sandboxed `--force-evaluate` run with a throwaway `NUGET_PACKAGES`, then a semantic diff against the planned key set.
7. **Unwind** on any failure in steps 5–6: restore every snapshot, and delete the seed only if this run created it.
8. Return `VendorOutcome::Done`. The CLI then persists the entry, sweeps stale artifacts, and calls **`sync_shared`**.

### 7.2 `sync_shared(cwd, &VendorState)`, the CLI finalize hook
It is called after every ledger mutation: `run_vendor` (after persist and sweep), revert, rollback, remove, gc, repair, and scan/get in vendored mode. It runs:
- in memory during `--dry-run`;
- idempotently; on failure it reports `vendor_nuget_shared_sync_failed` and exits non-zero.

What it does:
1. It selects entries that are `nuget-fallback`, `wired`, and whose seed directory is present. For an entry that is wired but has a missing seed, it warns and does not render it.
2. If the selection is non-empty:
   - it renders `socket-patch.targets`, `.gitignore` and `.gitattributes`, and writes the DBP blocks into every nearest DBP;
   - it refuses without `--force` when the on-disk targets differ from `nugetShared.renderSha256` (`vendor_nuget_targets_edited`).
3. If the selection is empty:
   - it removes the block from every discovered DBP, plus every DBP listed in `nugetShared.props`, without needing any per-entry records;
   - it deletes a DBP whose text equals the created text; otherwise it restores `original` when the rest of the file is unchanged;
   - it deletes the targets file only after every block is gone. If any excision drifts, it writes a stub `<Project/>` targets file instead;
   - it deletes `.gitignore` and `.gitattributes` last.

### 7.3 Hot path, `--check`, `--check --online`
**In sync**, which returns `AlreadyPatched`, requires all of:
- the seed file set equals `fileInventory`, with no extra, symlinked or non-regular files, and the hashes match;
- `.nupkg.metadata` equals the recorded contentHash;
- the shared outputs are byte-equal to the render (they are `-text`, so this is safe);
- every lock record's live text equals `new`, compared EOL-neutral;
- a re-plan from csproj, CPM and locks, with V′ counted as V, matches `nuget.projects`.

A changed closure is re-planned and re-keyed, and warns `vendor_nuget_closure_changed`.

**`--check`** does everything above, plus:
- it compares seed hashes against the **committed** blobs (`git cat-file HEAD:<path>`) and checks `git ls-files --eol`, reporting `vendor_nuget_eol_normalized`;
- it evaluates every discovered project with `dotnet msbuild -getProperty:SocketPatchNuGetTargetsImported` (batched). Any project that resolves the id at V without importing the targets fails (`vendor_nuget_project_uncovered`);
- it probes the signature policy again;
- it flags repo trustedSigners that are not in state, and `.rsp` overrides;
- it reports untracked seeds, stale keys, unused entries and orphaned pins.

It works before any restore, because it relies on the persisted closure.

**`--check --online`** also rebuilds the expected tree from an anchor outside the repo and diffs it byte for byte. The anchor is either the service artifact (SRI) or upstream plus afterHashes. This is the recommended required CI step.

### 7.4 Revert
Steps, in order:
1. **Lock records.**
   - Live text equal to `new`: splice `original` back.
   - Live text equal to `original`: the record is done.
   - Otherwise it is drift. Drift is repaired **only** from depscan `upstreamContentHash`, or from a freshly downloaded nuget.org nupkg whose repository signature was checked. It is never repaired from the GPF (adv-integrity M5).
2. **keep** = any drifted record whose live text still contains V′. If keep is set, the entry becomes `wired=true`, `kept_artifact`, and the process stops here.
3. The CLI drops the entry, or marks it `wired=false` for Preserved, then saves state and runs `sync_shared`. That regenerates the targets or removes the blocks, deleting the targets only after the blocks are gone.
4. It deletes the seed and prunes empty levels. It first runs `refuse_symlinked`/`first_symlink` on the seed and all its ancestors.
5. No GPF eviction is needed (VERIFIED-D V-D12).

### 7.5 Patch update (a new uuid for the same purl)
- The planner treats the old V′a as V (step 2). Lock edits V′a → V′b record `original: None`, so `carry_forward_wiring` fills in A's true upstream original. The key has no uuid in it.
- `carry_forward_wiring` merges import state across uuids implicitly, because that state now lives in the state-level `nugetShared`.
- The old entry is excluded from the prelude checks. The CLI replaces the entry, sweeps A's seed, and then runs `sync_shared`, which renders only B.
- Docker leg: vendor A, update to B, locked restore, revert, then `git diff --exit-code`.

### 7.6 Migration from the legacy layout (`--migrate-nuget`)
1. Run `fallback_prelude` and `plan_closure` first. A refusal leaves legacy intact.
2. Materialise V′ by running `reversion_nupkg` on the **committed legacy `.nupkg`** (builder 1), and verify the afterHashes. Local rebuild is not used, because the GPF holds patched bytes.
3. As one unwindable unit: run the legacy revert (config, catch-all when the live text equals the legacy `new`, root lock), then apply fallback.
4. Opt-in `--nuget-evict-legacy-cache`: delete `<idl>/<V>/` GPF entries whose `.nupkg.metadata` `source` is a `.socket/vendor/nuget/<uuid>` path, and print the command for CI caches.

### 7.7 Pristine source on clean machines
When the GPF never holds upstream V, a rung fetches `https://api.nuget.org/v3-flatcontainer/<idl>/<v>/<idl>.<v>.nupkg`. It verifies the result fail-closed against the upstream contentHash recorded in the ledger (the `original` of any `nuget_lock_entry_v2`), using the signed-content hash. Repair, patch update and `--offline` use this rung.

For fallback entries, `vend_installed!` no longer `debug_assert`s `Installed`, and the hot path never reads `installed_dir`.

### 7.8 Crawler, VEX, in-use
- **Crawler:** `nuget_crawler.rs` skips `.socket/vendor/nuget/**` packageFolders and maps V′ to (upstream purl, uuid).
- **VEX:** the fallback extractor parses `socket-patch.targets` (literal uuid comments and `_SpV_*`) and the discovered locks (V′ decoded). The nuget probe files gain the targets file, the DBPs and the locks.
- **In use:** an entry is in use when a lock or assets file resolves V′ for a reason other than our own pin. A pin with no remaining parent edge gives `vendor_nuget_pin_orphaned` and is dropped on the next `vendor`.

## 8. Supported shapes (fallback tier)

| Shape | Status | Evidence / notes |
|---|---|---|
| SDK sln, per-project locks, `--locked-mode`, warm or cold GPF | Supported | VERIFIED-D V-D3/V-D10, VERIFIED-ADV (env). Goldens for the `[V′, )` form: G11. |
| Patched library consumed next to a higher sibling (AppA/AppC) | Supported | `[V′, )` plus Project-range edits in every consumer lock (VERIFIED-ADV e2) |
| Multiple patched versions of one id reached by one project | Supported | Resolves the higher V′ (VERIFIED-ADV e2) |
| CPM, pinning off/on, VersionOverride | Supported | VERIFIED-D V-D7; static graph with pinning on VERIFIED-ADV |
| Transitive-only, multi-TFM | Supported | TFM-conditioned pin (VERIFIED-ADV e3 shows the need; the fix is G11) |
| Nested and chained DBT/DBP | Supported | `CustomAfterDirectoryBuildTargets` (VERIFIED-ADV e7 on SDK 8; SDK 6/7 is G10) |
| No lockfile | Supported, warning `vendor_nuget_no_lockfile` | 001/002/003/005/006 |
| Spelling variants `13.0.1.0`, `[13.0.1]` | Supported | One condition per recorded spelling. A new spelling in a new project gives loud 005. |
| `*.proj` NoTargets/Traversal, `.fsproj`, `.sqlproj` | Supported if SDK-style | Enumerated through `*.*proj` plus the sln |
| Any source mapping, `<clear/>`, `--source`, `NUGET_PACKAGES`, `--packages`, `locals --clear` | Supported | VERIFIED-D V-D2/4/5b/9 |
| Byte-identical V′ in a shared GPF | Supported | Content-aware 003 (G15) |
| Windows checkout with `autocrlf`, `* text=auto`, LFS rules | Supported | `.gitattributes` (VERIFIED-ADV c2/V4). A surviving LFS rule is refused. |
| Packable library with a direct patched dependency | Supported with warning, or refused until G2 | §6.6 |
| Project outside the `.socket` root referencing a redirected project | Refused: `vendor_nuget_external_consumer` | VERIFIED-ADV e8 |
| Non-SDK csproj with PackageReference | Refused: `vendor_nuget_non_sdk_project` | REASONED (no mono) |
| Mixed packages.config and SDK on the same id@V | Refused: `vendor_nuget_mixed_project_styles` | Q5 |
| packages.config only | Legacy layout | |
| Property-expanded version on SDK < 8, or `global.json` SDK missing | Refused | REASONED |
| Implicit SDK references (FSharp.Core) | Refused | REASONED |
| 4-part non-zero or prerelease upstream | Refused until G5 | |
| `require` policy visible | Refused (fallback tier) | Feed tier is post-prototype |
| Submodules, template content | Skipped with warning | |

## 9. Failure modes

| Situation | Result | Loud? |
|---|---|---|
| Seed file missing or added (for example planted `build/*.props`) | SOCKETPATCH001 at restore, before `nuget.g.*` is regenerated on a clean checkout | Yes (G13) |
| Seed file edited | SOCKETPATCH002 at restore and build | Yes |
| All of `.socket/vendor/nuget` missing | SOCKETPATCH007 at restore (prototype, VERIFIED in the e2e), then MSB4019 at build | Yes |
| Only `socket-patch.targets` missing | Restore **succeeds and rewrites locks to upstream** (V3). Build gives MSB4019, and `--check` fails. | Build only; the CI gate is `--check` |
| V′ elsewhere, different bytes | SOCKETPATCH003. NU1403 applies only if `.nupkg.metadata` differs (VERIFIED-ADV x2). | Yes |
| V′ elsewhere, same bytes | Accepted | — |
| New or renamed project that imports the targets | SOCKETPATCH005, and NU1004 when locked | Yes |
| New nested DBP that does not chain to the root | **Silent at build** (VERIFIED-ADV x3, DBT analogue). Caught by `--check` import evaluation. | CI gate |
| Redirect engaged but drifted (bot edit, parent bump, NU1603) | SOCKETPATCH006 | Yes |
| Bot bumps the declared version | Redirect disengages; the lock diff shows V′ → new; `--check` flags the unused entry | In PR |
| Env var or package props setting `SocketPatchNuGetGuard=false` | Ignored (unconditional assignment) | — |
| Global `-p:SocketPatchNuGetGuard=false` | Guards off (escape hatch) | User choice |
| Planted `build/*.targets` on a dev machine that already restored | Arbitrary code before the guard; residual risk | Accepted; mitigated by `--check --online` in CI |
| Design-time build | Redirects apply; the guard is skipped | — (G16) |
| Docker `COPY *.csproj` without DBP/.socket | Locked: NU1004. Lockless: SOCKETPATCH005 at full build. `vendor` warns `vendor_nuget_dockerfile_copy`. | Yes |
| Sparse checkout without `.socket/` | NU1301/MSB4019. The block comment names `git sparse-checkout add .socket/vendor/nuget`. | Yes |
| CI-only `require` policy | Silently bypassed; closed by depscan org policy #6 | No (accepted gap) |
| NuGetAudit when V′ is still in an advisory range | NuGetAuditSuppress (NuGet ≥ 6.11). Older SDKs emit info `vendor_nuget_audit_still_flags`. | Parity with pre-patch |
| SBOM and dependency-graph tools reading locks | They see V′; depscan mapping (#4); document Dependabot alert behaviour | Docs |
| Missing seed + VS nomination restore + lockless + attacker feed serving V′ | Possible code execution | Accepted residual. Server gap check covers org upstreams. |

## 10. Signing and enterprise policy (feed tier; post-prototype)

- **Fallback tier:** it never claims signature enforcement. It refuses under a visible `require`, never writes `accept`, and never sets `DOTNET_NUGET_SIGNATURE_VERIFICATION`.
- **Feed tier:**
  - Builder 0 only, so shared GPFs stay safe (adv-integrity M4).
  - It adds exactly one `<add>` for the per-uuid feed. Id-exact mapping is added only where a repo mapping already exists. It refuses with `vendor_nuget_feed_mapping_conflict` when the only mapping is outside the repo and the repo uses several versions of the id.
  - **Trust:** it never writes a pfx-holder `<author>` to repo config by default. The default path is depscan's CA-issued certificate plus RFC3161 timestamp (#8), trusted once at org or machine level. The opt-in `--nuget-sign-ephemeral` generates a per-uuid key, signs, destroys the key, then writes the fingerprint, so trust covers exactly the bytes already signed. `--check` flags unrecorded trustedSigners.
  - **Guard:** the same content-aware 003/002 as the fallback tier.
  - Gated by G6.

## 11. Compatibility

### 11.1 Hosted
- Unchanged until WS1 (`hosted_revert_unsupported`).
- Later, hosted can serve V′ from v3 and reuse the targets file.
- Independent fix: version-precise hosted lock matching at `redirect/mod.rs:5431`.

### 11.2 Repair and sweep
- WIRING_FILES gains the three `nuget.config` spellings, the discovered DBP and DBT files, and `packages*.lock.json`.
- Reserved names: `socket-patch.targets`, `.gitignore`, `.gitattributes`.
- A wiring file that names a uuid directory makes that directory live.

### 11.3 Older binaries (v4.0.0 is released)
- **The risk (REASONED from code).** Without mitigation, v4's revert deletes the seed while the locks and targets still reference it. v4's vendor applies a legacy layout on top.
- **Mitigations:**
  - The literal `.socket/vendor/nuget/<uuid>` comments in the root DBP block, plus a `nuget_uuid_anchor` record, make v4's drift-keep keep the seed and the entry (fail-safe).
  - The v5 hybrid router (§5) and a heal step: detect a legacy `socket-patch-<uuid>` source next to a fallback seed, remove it, and restore the lock.
  - `revert_nuget_opts` fails closed on an unknown flavor (v5).
  - The minimum version is documented.
- **Test:** G14 runs the real v4 binary against a fallback repo.

## 12. Server/CLI split (depscan)

| # | depscan addition | Needed for |
|---|---|---|
| 1 | `lib/src/nuget/socket-version.ts` derive/parse, with golden vectors shared with Rust | GA |
| 2 | `nuget-socket-version` repacker (V′ nuspec, STORE-only, deterministic, write-once). Refuses versions in (V, V′] on nuget.org **and the org's configured upstreams**. | GA |
| 3 | `artifacts[].kind="nupkg-socket-version"`, `nugetPatchedVersion`, `upstreamContentHash`, `upstreamSha512` | **GA** (provenance, drift repair, `--check --online`) |
| 4 | SBOM mapping V′ → upstream purl plus uuid; recognise the fallback folders. Bump task versions, run `generate-task-metadata`, use `RunTask` helpers. | **GA blocker** |
| 5 | Fixed-advisory GHSA list per patch (NuGetAuditSuppress) | Prototype nice-to-have; the CLI can fall back to local advisory data |
| 6 | Org `nugetSignaturePolicy: require` | GA for enterprises |
| 7 | `nuget-seed` artifact (extracted layout plus inventory), tested with real dotnet | Post-GA |
| 8 | CA-issued Socket author signing plus timestamp | Feed tier |
| 9 | Hosted V′ in flat and registration indexes | Later |

Identity and bytes (about 30% of the logic) belong to the server. All repo and machine wiring is 100% CLI.

## 13. Test plan

**Hermetic unit tests** (`cargo test -p socket-patch-core --lib nuget_`):
- `nuget_version`: vectors, round-trip, gap refusal.
- `nuget_lock`: goldens from real `--force-evaluate` output for `[V′, )`, covering:
  - each role, including CentralTransitive with pinning on, range-consumers and canonical Direct ordering;
  - CRLF and no trailing newline;
  - RID goldens for a `runtimes/` package (SqlClient);
  - EOL-neutral revert and drift.
- `nuget_targets`: render golden with uppercase-hex pinning; XML and MSBuild escaping; DBP block inject and excise on CRLF, BOM, `<Project/>`, chained DBPs; stub rendering.
- `nuget_seed`: decode-then-validate traversal cases (`%2E%2E%2F`, `%5C`), metacharacter refusal, case-fold collisions, OPC drops, `reversion_nupkg` determinism.
- `nuget_projects`: closure on fixtures (e2 AppA/AppB/AppC, multi-TFM e3, external consumer e8, spellings e9, submodule, template).
- `nuget_policy`: chain merge.
- `sync_shared`: update, revert order, Preserved, dry run.

**Real-dotnet e2e** (`e2e_nuget_dotnet_build.rs`; SDK 6–10 ubuntu, 8 macOS, **windows-latest**). Legs:
- `sln_locked`, `cpm_locked`;
- warm GPF;
- `RestorePackagesPath`/`NUGET_PACKAGES`;
- `locals --clear`;
- tamper (002) and planted file (001);
- env-var disable ignored;
- pack (range restore, 004 pre and post, output deleted);
- revert plus `git diff --exit-code`.

**Docker** (`docker_e2e_vendor_nuget.rs`):
- static graph; no lockfile;
- 005 rename; 006 bot edit;
- anchor NU1301; `--packages` then `--no-restore`;
- hostile user mapping;
- require refusal;
- migration plus eviction;
- idempotence;
- G3 two roots;
- e2/e3/e7/e8 fixtures;
- same-bytes V′ in the GPF (003 passes) and different bytes (003 fails);
- patch update A→B then revert;
- two-id revert in both orders;
- crash between write and save (resume via `sync_shared`);
- v4 binary (G14);
- parallel `-m`;
- mono image for the packages.config refusal.

**Real-clone legs** (prototype acceptance): commit, `git clone`, build under `* text=auto`, `autocrlf=true`, a `*.dll filter=lfs` root rule, and sparse checkout.

**Regression:** every existing `nuget_feed` test passes unchanged with the default layout.

## 14. Gating experiments and open questions

| ID | Question | Blocks |
|---|---|---|
| G1 | Content-aware guard with multiple roots; `@(Analyzer)`; analyzer-only and build-only packages via the assets `libraries` | Prototype |
| G2 | Pack pre/post checks and `@(NuGetPackOutput)` deletion on SDK 6–10 | Packable support |
| G3 | Multiple uuid roots plus the anchor root together | Prototype |
| G4 | SOCKETPATCH005/006 on renamed projects (001 is VERIFIED-ADV) | Prototype |
| G5 | Prerelease-tagged V′ forms | 4-part/prerelease |
| G6 | Feed tier with V′ under `require`; shared GPF across repos | Feed tier |
| G7 | Static graph plus `dotnet test` across CPM variants | Promotion |
| G8 | macOS/Windows path case; nuget.exe packages.config | Promotion |
| G9 | VS/Rider design-time restore honours redirects | Docs |
| G10 | `CustomAfterDirectoryBuildTargets` on SDK 6/7; chained-DBP dedupe | **Prototype** |
| G11 | `[V′, )` lock goldens, TFM-conditioned pins, no NU1603 when the seed is present | **Prototype** |
| G12 | The anchor fallback folder gives NU1301 at restore when `.socket/vendor/nuget` is missing, and nothing when present | **Prototype** |
| G13 | Restore-time set check: glob includes dotfiles, runs under static graph, runs before a planted `build/` file on a clean checkout | **Prototype** |
| G14 | v4.0.0 revert and vendor against a fallback repo keep the seed (fail-safe) | **Prototype** |
| G15 | `SpKeyPath` computation for GPF-resolved files | Prototype |
| G16 | Guard skipped when `DesignTimeBuild=true` in VS, Rider and C# Dev Kit | Promotion |
| Q1 | Should SOCKETPATCH005/006 be warnings for one release? | Product |
| Q2 | Is org require policy (#6) enough, or should the feed tier be default for paid orgs? | Product |
| Q3 | Renovate and Dependabot behaviour on the targets file; emit `ignorePaths: [".socket/**"]`? | Docs |
| Q4 | Re-vendor builder-1 seeds to builder 0 once the service artifact ships? | Post-GA |
| Q5 | Dual wiring (legacy for packages.config plus fallback for SDK) for mixed repos? | Post-prototype |

## 15. Prototype scope

**Goal.** A working prototype for SDK sln with locks in locked mode, and for CPM, with no change to default behaviour.

**Gating.**
- `--nuget-layout` on `GlobalArgs`, with the inference rules from §5.
- `layout_for(entry, state, run)` is used by `dispatch_vendor_one` (callers at `vendor.rs:2636` and `repair_vendor.rs:1632`, and via `vendor_records`).
- `service_preflight` changes signature to take `&VendorState`.
- The revert arm uses the hybrid router.

**In scope:**
- Fallback tier; 3-part V′.
- All roles, including range-consumers.
- The DBP block, the anchor, and `sync_shared`.
- `.gitattributes` with probes.
- Guards 001–006 and the pack checks.
- NuGetAuditSuppress.
- Hot path, `--check` (including `--online`), revert.
- Patch update.
- The pristine fetch rung.
- VEX extractor, crawler skip, in-use probe.
- v4 anchor and hybrid router.
- Flavor gate, WIRING_FILES, sweep.
- Name validation and escaping.

**Out of scope:** the feed tier and signing; 4-part and prerelease upstreams; packages.config (legacy, and mixed repos are refused); `--nuget-relock`; migration (refused with `vendor_nuget_layout_mixed`); hosted, apart from the `:5431` fix.

**Modules** (under `crates/socket-patch-core/src/vendor/` unless noted):

| Module | Items |
|---|---|
| `nuget_version.rs` | `NugetBuilder`, `SocketNugetVersion`, `socket_nuget_version`, `parse_socket_nuget_version`, `check_version_gap` |
| `nuget_projects.rs` | `NugetProject`, `discover_projects` (`*.*proj`, sln, worktree-bounded), `plan_closure` (V′-aware, bidirectional), `ProjectRole::{Direct, CpmUniform, CpmSplit, AutoFollow, Pin{tfm_alias, parent}, RangeConsumer}`, `excluding_constraints`, `external_consumers` |
| `nuget_lock.rs` | `LockEntryEdit`, `plan_lock_edits`, `splice` (EOL-aware), `revert_lock_entry_record`, `semantic_eq` |
| `nuget_seed.rs` | `reversion_nupkg`, `extract_seed` (decode then validate), `seed_inventory`, `walk_seed_strict`, `write_seed_atomic` |
| `nuget_targets.rs` | `render_targets`, `render_gitignore`, `render_gitattributes`, `render_dbp_block`, `inject_block`, `excise_block`, `msbuild_escape` |
| `nuget_shared.rs` | `sync_shared(cwd, &VendorState, dry_run)` |
| `nuget_policy.rs` | `effective_signature_mode` |
| `nuget_fallback.rs` | `vendor_nuget_fallback`, `revert_nuget_fallback_opts`, `service_preflight`, `fallback_prelude`, `fallback_in_sync`, `layout_for`, `fetch_pristine` |
| `state.rs` | `NugetMeta` (with `wired`, `literals`, `allowUnpatched`, upstream hashes), `nugetLayout`, `nugetShared`, `fileInventory` intactness in `ledger_covers` |
| `ledger_snapshots.rs`, `path.rs`, `verify.rs` | new kinds; uuid8 nested leaf parser; reserved names; set-equality verify |
| `nuget_feed.rs` | flavor gate; `CONFIG_NAMES` |
| `crawlers/nuget_crawler.rs`, `vex/discover/nuget.rs`, `vex/discover/mod.rs:1750` | skip seeds; fallback extractor; probe files |
| CLI `vendor.rs`, `rollback.rs`, `remove`, `gc`, `repair_vendor.rs`, scan/get | `sync_shared` calls; `vend_installed!` fix; in-use probe; `GlobalArgs` flag |

The CLI and VEX work adds roughly 30–40% over the revision 1 estimate.

**Prototype acceptance:**
- the §13 unit goldens;
- sln and CPM e2e on SDK 6–10, plus Windows and macOS;
- the docker suite and the real-clone legs;
- G1, G3, G4, G10–G15;
- zero changes to existing NuGet test outcomes.

**Promotion to default** additionally requires G2, G7, G8 and G16; depscan #2–#4; and one release as opt-in.

## 16. Adversarial review

Dispositions: **Fixed** (design changed), **Refused** (moved to refused shapes), **Accepted** (risk kept, with rationale), **Open** (gating experiment or question).

### Shapes
| ID | Finding | Disposition |
|---|---|---|
| S-B1 | `[V′]` spreads via ProjectReference (NU1107, NU1608, NU1004 outside the closure) | **Fixed:** `[V′, )`, SOCKETPATCH006, range-consumer lock edits, gap check (§6.1, §6.4, §6.5). Goldens G11. |
| S-B2 | Once-guard on a chained DBT imports too early; pin gives NU1504 | **Fixed:** DBP `CustomAfterDirectoryBuildTargets` (§6.3). SDK 6/7 is G10. |
| S-B3 | autocrlf breaks the seed | **Fixed:** generated `.gitattributes` plus `check-attr`; LFS refused (§6.2) |
| S-M1 | Pins not TFM-conditioned | **Fixed:** alias condition from assets; unknown alias refused |
| S-M2 | Consumer outside the root breaks, or goes silent under `[V′, )` | **Refused:** `vendor_nuget_external_consumer`; 006 covers in-root drift |
| S-M3 | 004 fires after the nupkg is written | **Fixed:** pre-check plus deletion of `NuGetPackOutput` (G2) |
| S-M4 | Several nuspecs give MSB4184 | **Fixed:** exact nuspec path |
| S-M5 | Non-SDK PackageReference projects are unguarded | **Refused:** `vendor_nuget_non_sdk_project` |
| S-M6 | NU1903 still fires on V′ | **Fixed:** §2.3 corrected; NuGetAuditSuppress in prototype; info code on < 6.11 |
| S-M7 | Literal spellings, `*.proj` types, SDK < 8 `-getItem` | **Fixed:** one condition per spelling, `*.*proj` plus sln; SDK < 8 property versions and missing SDK refused |
| S-minor | CPM golden, canonical order, per-package seed hashing, exact literal in pack, implicit refs, tool wording, RID goldens, MAX_PATH, analyzers | **Fixed:** §6.5, §6.6, §7.1, §13, uuid8. Seed hashing moved to a once-per-restore check (`_SpSeedChecked`). Analyzers are G1. |

### Environments and CI
| ID | Finding | Disposition |
|---|---|---|
| E-B1 | EOL normalization fails fresh clones | **Fixed:** `.gitattributes`, `--check` against HEAD blobs, `ls-files --eol`, clone legs in acceptance |
| E-M1 | Same-bytes V′ in the GPF fails 003 with destructive advice | **Fixed:** content-aware 003, `<idl>/<V′>` keys, new message (G15) |
| E-M2 | Guard runs in design-time builds | **Fixed:** `DesignTimeBuild` condition; §9 corrected (G16) |
| E-M3 | Windows path depth | **Fixed:** uuid8 directory, absolute-path check with refusal, Windows leg in prototype |
| E-M4 | EOL-sensitive comparisons | **Fixed:** generated files `-text`; EOL-neutral records and splices |
| E-M5 | Mixed packages.config/SDK undefined | **Refused:** `vendor_nuget_mixed_project_styles`; dual wiring is Q5 |
| E-M6 | `--check` needs restore outputs | **Fixed:** persisted closure is authoritative; unrestored applies only to new projects |
| E-M7 | Renovate/Dependabot edit the targets | **Fixed:** property-indirected versions, render sha, 006 catches edits. Q3 stays open. |
| E-minor | Sparse checkout, Docker COPY, `git clean`, seed size, case collisions, predictable-V′ attack, SBOM alerts, setup-dotnet cache, concurrency | **Fixed/Accepted:** block comment; `vendor_nuget_dockerfile_copy`; untracked-seed check; size caps; case-fold refusal; server gap check over org upstreams (residual accepted, §9); depscan #4; dot-directory skip; no fix needed for concurrency |

### Integrity
| ID | Finding | Disposition |
|---|---|---|
| I-B1 | Seed file set unpinned; planted files disable the guard; lock pins nothing | **Fixed:** restore-time set and hash check (G13), strict CLI walk, `--check --online`, unconditional guard. §1 wording narrowed. **Accepted residual:** a dev machine that already restored a planted seed runs its code; CI `--online` is the defence. |
| I-B2 | Git transforms seed bytes | **Fixed** (same as E-B1) |
| I-M1 | Env var, props or rsp disable the guard | **Fixed:** unconditional assignment (VERIFIED-ADV x1), CLI allowlist, rsp flagging |
| I-M2 | New nested DBT hides the import silently | **Fixed/Accepted:** `--check` evaluates every project's import; documented as the CI gate. Build-time silence is accepted. |
| I-M3 | GPF V′ beats the seed | **Fixed:** content-aware 003; §9 wording corrected; exact per-uuid root is no longer needed because keys are content-based |
| I-M4 | Builder 1 is not one byte sequence | **Fixed:** feed tier accepts builder 0 only. **Accepted** for the fallback tier: only lock churn. |
| I-M5 | Drift repair from a poisoned GPF | **Fixed:** repair only from depscan or a signature-verified download |
| I-M6 | Upstream provenance lost | **Fixed:** signature or sha512 check at vendor; `upstreamSha512` recorded; depscan #3 is GA |
| I-M7 | Repo-level pfx author trust is id-unscoped | **Fixed:** feed tier defaults to CA cert; ephemeral-key opt-in; `--check` flags trustedSigners |
| I-M8 | Percent-decoding traversal and MSBuild injection | **Fixed:** decode then validate, metacharacter refusal, escaping, strict validation at render |
| I-M9 | Analyzer and build-only packages unguarded | **Fixed:** `@(Analyzer)`, assets `libraries`, unconditional restore check (G1) |
| I-minor | Symlinks, late `require`, nuspec edits, §9 wording, stale obj, hex-case golden | **Fixed:** symlink refusal on ancestors; `--check` policy re-probe; set check; wording; test legs; golden |

### Lifecycle
| ID | Finding | Disposition |
|---|---|---|
| L-B1 | Patch update renders both uuids, pins a dead V′, breaks revert | **Fixed:** `sync_shared` after persist and sweep; V′-aware planner; `original: None` carry-forward; replaced entry excluded (§7.5) |
| L-B2 | Import records lost across uuids, order and crashes | **Fixed:** state-owned block, record-free excision, blocks removed before the targets, stub on drift (§7.2) |
| L-B3 | Seed not byte-stable through git | **Fixed** (E-B1) |
| L-M1 | Preserved or Kept entries re-wired | **Fixed:** `wired` flag; missing seeds are never rendered |
| L-M2 | Revert order defeats drift-keep | **Fixed:** §7.4 order |
| L-M3 | No pristine source on clean machines; `debug_assert` panic | **Fixed:** fetch rung verified against ledger hashes; assert removed for fallback (§7.7) |
| L-M4 | Hot path and `--check` before restore; re-plan misreads V′ | **Fixed:** persisted plan; V′ decoded as V |
| L-M5 | v4 binaries corrupt fallback entries | **Fixed/Open:** literal uuid anchor, hybrid router, heal step; G14 |
| L-M6 | VEX silently drops fallback patches | **Fixed:** extractor and probe files in prototype scope |
| L-M7 | Unsafe unwind of shared outputs and reused seeds | **Fixed:** staged writes, snapshots, delete only what this run created |
| L-M8 | Migration destroys its own source | **Fixed:** prelude first, re-version the committed legacy nupkg, one atomic unit (§7.6) |
| L-M9 | Restore does not fail closed on a missing targets file | **Fixed/Accepted:** anchor NU1301 when `.socket` is gone (G12); targets-only deletion accepted, with `--check` as CI gate; §9 corrected |
| L-M10 | Transitive pins keep themselves alive | **Fixed:** pin conditioned on the direct parent; in-use probe excludes self-edges; `pin_orphaned` |
| L-M11 | Layout choice does not persist | **Fixed:** `GlobalArgs` flag, inference, `nugetLayout` |
| L-P1 | Prototype needs CLI hooks not in §15 | **Fixed:** §15 scope and module table extended (+30–40%) |
| L-minor | User edits of the targets, submodules/templates, builder churn, dry run, directory `ledger_covers`, NU1903 | **Fixed:** render sha plus `targets_edited`; worktree bound plus skip; builder sticky; in-memory render; inventory intactness; S-M6 |

## 17. Prototype on this branch: what was built and how it deviates

**Code:** `crates/socket-patch-core/src/vendor/nuget_{version,seed,lock,targets,fallback}.rs`, plus small routing hooks in `vendor/mod.rs`, `commands/vendor.rs` and `commands/repair_vendor.rs`.

**Tests:**
- unit tests in each module;
- lock fixtures captured from real `dotnet` in `crates/socket-patch-core/tests/fixtures/nuget-fallback/{sln,cpm,cpmpin,cpm-tool}`. NuGet's own `--force-evaluate` output is the golden for the splice;
- `crates/socket-patch-cli/tests/e2e_nuget_fallback_dotnet.rs`, which is `#[ignore]` and runs against the real SDK and nuget.org. Its legs are `sln_locked`, `cpm_locked`, `cpm_pinning` and `sln_patch_update`.

The default layout is unchanged: every existing NuGet test passes untouched.

Implementation: `crates/socket-patch-core/src/vendor/nuget_{version,lock,seed,targets,fallback}.rs`.

### Behaviour deviations (deliberate)

1. **Lock rule for a range at V that resolved elsewhere.** The spec only edits entries whose `resolved` is V. NuGet also rewrites `requested "[V, )"` → `"[V′, )"` on a `CentralTransitive` (or `Direct`) entry that resolved to some other version (cpm-tool `Tool`: `resolved 12.0.1`). Without this edit, `--locked-mode` fails NU1004. The splice now makes the requested-only edit (`resolved` and `contentHash` are left unchanged), and the golden `cpm-tool` fixture proves it.
2. **`CentralTransitive` at V counts for transitive-only too.** Under CPM *without* pinning, a `CentralTransitive` V entry is refused `vendor_nuget_transitive_only` when the project has no `Project` reference to a redirected project. This follows from NuGet itself: without pinning the central version is not applied, so the entry resolves upstream V and the build guard would fire. With `CentralPackageTransitivePinningEnabled` it is redirected. Pinning is detected by a repo-global text scan.
3. **Layout selection is per purl.** The env var or any `nuget-fallback` ledger entry selects the fallback layout, except for a purl the ledger already holds as a legacy feed entry: that purl keeps routing to `nuget_feed` (vendor and service preflight), so an in-sync legacy entry never fails `vendor_nuget_layout_mixed` once the repo opts in. The refusal stays in the backend for direct callers. The earlier "targets file exists" signal was dropped: `.socket/` writes are outside the group commit, so a failed or crashed run could leave the targets behind and silently opt the repo in.
4. **DBP block text.**
   - The begin comment is `(generated; remove with: socket-patch vendor revert)`. An XML comment cannot contain `--`, and a DBP that fails to load is silently ignored by restore.
   - `<rel>` is rendered with its trailing slash (`""` / `../`), which gives `$(MSBuildThisFileDirectory).socket/...` and never `//.socket`.
   - **The anchor line is gone.** Registering `.socket/vendor/nuget` itself as a fallback folder let anyone plant `<id>/<ver>/` beside the uuid dirs and have NuGet restore it under `--locked-mode` with no seed check (security review, reproduced on SDK 8). The block now holds a `SocketPatchNuGetImportCheck` target instead (`BeforeTargets="_GenerateRestoreGraph;CollectPackageReferences"`, condition `'$(SocketPatchNuGetTargetsImported)' != 'true'`), which fails restore with **SOCKETPATCH007** when the targets were not imported (the vendored tree is missing; restore ignores the missing import). The e2e proves it for locked and unlocked restore. `-p:SocketPatchNuGetGuard=false` disables it like the other guards.
   - A props file socket-patch **created** carries `socket-patch:begin created` on its begin line. Only such a file is deleted on the last revert, when nothing but its block was added (compared with BOM and CRLF normalised). A user's own `<Project>\n</Project>\n` is kept, and a CRLF checkout of a created file is still deleted. Re-rendering a block keeps the tag.
   - The `</Project>` insertion point (and a self-closing `<Project/>`) is found with comments blanked, so a `</Project>` inside a trailing comment is never used.
5. **The render inputs live in the marker.**
   - `socket-patch.vendor.json` gains an optional `nuget` section: `id`, `version`, `socketVersion`, `contentHash`, `spellings`, `inventory`, and `wired` (default true).
   - `sync_shared` renders the seed inventory from the marker, never from the disk, so a tampered seed is never re-baselined.
   - The marker is not trusted alone: when the ledger has a `nuget-fallback` entry for the uuid, its `artifact.file_inventory` replaces the marker's inventory in the render. The one exception is the seed the current vendor run just wrote (`RenderScope::fresh`). The markers are also diffable in `.gitattributes` (`/*/socket-patch.vendor.json -text diff`), so a changed hash shows in review.
   - The `AlreadyPatched` fast path also requires every patched file in the seed to hash to its `afterHash`.
   - A `--preserve-state` revert (`keep_artifact`) writes `wired: false`. The seed stays on disk but is no longer rendered into the targets.
6. **Extra refusal codes** beyond the spec list:
   - `vendor_nuget_nuspec_patched`: the patch rewrites the root nuspec, which the layout re-versions.
   - `vendor_nuget_version_literal_unknown`: a `$(Property)` or item version for the id.
   - `vendor_nuget_lock_unreadable`: an unparseable or unreadable lock.
   - `vendor_nuget_seed_failed`: the canonical zip failed.
   - `vendor_nuget_symlink_unsupported`: a project file, `Directory.Build.props` or `packages.lock.json` under the root is a symlink (an atomic rewrite would replace the link, and a skipped linked props file would silently shadow the wiring). `sync_shared` and revert refuse the same way before writing anything.
   - `vendor_nuget_repo_too_large`: the discovery walk hit its 100,000-entry cap. Vendor refuses, and `sync_shared` / revert fail before writing, instead of silently wiring only part of the tree.
   - Coordinates containing `--` refuse `unsafe_coordinates` (they are rendered into XML comments); `.` / `..` and `--` never render from a marker either.
   - Floating (`*`) or bracketed ranges naming V in csproj/props text refuse `vendor_nuget_range_unsupported`, the same code as lock ranges.
7. **Member-name validation.**
   - Names are percent-decoded first.
   - They must then pass `is_safe_relative_subpath` + `is_plain_archive_name` + `names_are_unambiguous` (printable ASCII; no `\ : * ? " < > |`; no case-fold collisions).
   - Names containing `$ @ % ; '` are refused instead of escaped.
   - Members named `.nupkg.metadata`, `*.nupkg` or `*.nupkg.sha512` are refused.
   - OPC parts (`[Content_Types].xml`, `_rels/`, `package/`) and `.signature.p7s` are dropped, compared case-insensitively.
   - The nuspec `<id>` must match the purl id.
8. **`vendor_nuget_no_lockfile`** is emitted when **no** discovered `packages.lock.json` references the id (at V, V′ or an older Socket version of V), not per project.
9. **Signature policy is conservative.**
   - The CLI refuses if *any* config sets `signatureValidationMode=require`. It checks every dir from each SDK project dir up to the root, the root and its ancestors (all three config spellings), `~/.nuget/NuGet/NuGet.Config`, and `%APPDATA%/NuGet/NuGet.Config`.
   - NuGet's nearest-wins override is not modelled, and `DOTNET_NUGET_SIGNATURE_VERIFICATION` is not read.
10. **contentHash bytes.** The canonical zip is built with the existing `write_zip_entries` (zip-crate deflate level 6, fixed DOS time, mode 0644), so its hash differs from the Python-built fixture hash (`DDiM…`). NuGet only string-compares lock ↔ `.nupkg.metadata`, and the real-dotnet e2e proves the Rust value works.
11. **Wiring record shape and per-entry revert.**
    - One `nuget_lock_file_v2` record per lock that pins the id after the splice (edited now or already spliced): `key` is the id, `original` and `new` hold the whole text. Recording unchanged-but-spliced locks keeps their revert across a partial re-vendor.
    - The kind is registered in `ledger_snapshots::WHOLE_FILE_KINDS`, so large `new` values are diff-encoded (ledger version 2).
    - When the pre-edit lock already names a Socket version of V anywhere (a re-vendor, same or older uuid), `original` is `None` and `carry_forward_wiring` fills it from the replaced entry.
    - **The revert does not restore whole files.** `nuget_lock::unsplice_lock` puts back only this entry's values (V′ in `resolved`, `requested`, Project `[V′, )` ranges, and the matching `contentHash`), each to the value the recorded `original` held at the same JSON path (else plain V / `[V, )`; a hash only from `original`). Another seed's splice, a package or framework added since, and EOLs are untouched, so seeds sharing a lock revert in any order and a stale carried-forward original cannot discard later edits. When no upstream hash is recorded the entry is left at V′ and reported `vendor_lock_entry_drifted` (the seed is then kept).
12. **Seed rebuild.** An existing but stale seed dir for the same uuid is rebuilt through `<uuid>.socket-stage` + `swap_stage_into_place`. If a later step fails, the unwind deletes the seed only when this run created it, so a replaced stale seed is not restored.
13. **Self-closing `<Project/>` DBP.** It is expanded to `<Project>…</Project>`, and excision leaves `<Project>\n</Project>` rather than byte-restoring the self-closing spelling (the file is kept, never deleted, since socket-patch did not create it). The same applies to a `</Project>` sharing a line with other content, where one extra EOL remains.
14. **Seed materialisation.**
    - The new `nuget_feed::patched_nupkg_bytes` wraps the unchanged `materialise_patched_nupkg` (service download → local rebuild) in a private temp stage.
    - `config_wired=true` is passed only so a failed build does not prune the stage's parents.
    - The seed is then extracted from those same-version bytes.
15. **Patch update (new uuid).** `splice_lock` treats any value at an *older* Socket version of the same V (resolved, requested, Project range) as a re-splice target and moves it to the new V′ and hash. The vendor run leaves the superseded uuid's seed out of the render (`RenderScope::exclude`), and the CLI re-runs `sync_shared` after `sweep_stale_artifact` deletes the old uuid dir. The new `sln_patch_update` e2e leg proves the flow with real dotnet.

### Verified with real dotnet (SDK 8.0.131, nuget.org)
`e2e_nuget_fallback_dotnet` covers `sln_locked`, `cpm_locked`, `cpm_pinning` and `sln_patch_update`. The first three each do the following:
- runs the real `socket-patch scan --mode vendored --vendor-source build` with `SOCKET_PATCH_NUGET_LAYOUT=fallback`;
- on a fresh copy, runs `restore --locked-mode` with a cold GPF: the locks are unchanged and the App (and Tool) bin dll carries the patched bytes;
- does the same with a warm GPF that holds upstream 13.0.1;
- tampers a seed file and checks for `SOCKETPATCH002`, then restores the committed bytes and checks that restore passes;
- removes `.socket/vendor/nuget` from a checkout and checks that locked and unlocked restore fail `SOCKETPATCH007`;
- re-runs vendor **without** the env var (the ledger alone selects the layout) and checks that no project file changes;
- runs `vendor --revert` without the env var and checks that the tree outside `.socket/` is byte-identical and no `.socket/vendor/` remains;
- runs a locked restore and build of the reverted tree and checks that the pristine dll is back.

`sln_patch_update` vendors uuid 1, then a newer patch (uuid 2) without the env var, and checks: no `vendor_nuget_no_lockfile`, both locks at V′₂ only, the targets name only uuid 2, the uuid 1 dir is gone, a cold locked restore leaves the locks unchanged and builds the uuid 2 bytes, and `vendor --revert` restores the pre-vendor tree byte for byte.

### Known gaps (out of scope / follow-ups)
- The following are not implemented:
  - SOCKETPATCH003/004/006, pack range restore, per-project transitive pins, packages.config, the feed tier and signing, migration from the legacy layout (refused as `vendor_nuget_layout_mixed` for the same purl only), and `--check`.
  - Post-write git probes: `vendor_artifact_gitignored` / `_git_transformed`.
  - Long-path warning, size caps beyond the existing zip-bomb caps, and the version-gap/collision checks against nuget.org.
- **Lock discovery** reads only `<projdir>/packages.lock.json`. `NuGetLockFilePath` and `packages.<Project>.lock.json` are ignored.
- **Version literals** are found only as `Version=` attributes or `<Version>` children of `PackageReference` / `PackageVersion` / `GlobalPackageReference` in `*.csproj|fsproj|vbproj|props|targets` text. MSBuild evaluation is not used.
- **DBP placement** only considers DBPs inside the root. A `Directory.Build.props` *above* the repo root that a project relied on is shadowed by the created root DBP, because the created file does not import the parent.
- **Repair.** It can re-synthesise a fallback entry from the targets file (flavor stamped `nuget-fallback`), but not its lock wiring records. A revert of such a reconstructed entry deletes the seed and leaves the locks spliced.
- **Service download path.** Every e2e vendor uses `--vendor-source build`; the fallback's use of a downloaded service artifact (`patched_nupkg_bytes` → service copy, fallback `service_preflight`) is covered only by unit tests of the shared feed pipeline.
- **SOCKETPATCH005** (the build guard) is not exercised by the e2e.
- **Marker trust.** A uuid dir with no ledger entry (state.json lost, or before the entry is committed) still renders from its own marker.
- **Orphan sweep.** It now treats uuid dirs named in `socket-patch.targets` as wired.
- **Migration.** A purl held by a legacy feed entry keeps the feed layout even with the env var set; migrating it needs a `vendor --revert` first.
- **VEX.** There is no fallback extractor. Discovery returns nothing for fallback repos (the golden `vex-discover-golden/nuget-fallback.json` records empty results; there is no crash). Ledger-based VEX verifies the seed dir through the existing dir-artifact path, members plus `fileInventory`.
- **Crawler.** After a restore, `obj/project.assets.json` lists the fallback folder as a package folder, so the crawler may report `newtonsoft.json@13.0.1.<N>` as an installed package. This is not mapped back to the upstream purl.
- **Pre-existing failures, unrelated.**
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings` fails only in the untouched `crates/socket-patch-cli/tests/covgap_commands_rollback.rs:152` (dead fields `before_hash`/`after_hash`).
  - 9 core lib tests fail in this environment regardless of this change (it runs as root: read-only-permission tests and an RSS measurement).
  - `cargo fmt --all` reformats ~75 unrelated files on HEAD. Those changes were reverted; only the files touched here are rustfmt-clean.

