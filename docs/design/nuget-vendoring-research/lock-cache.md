# NuGet lock-file and package-cache research (SDK 8.0.131, Linux)

Every experiment ran with its own fresh HOME, NUGET_PACKAGES and NUGET_HTTP_CACHE_PATH under `<scratch>/research/lock-cache/exp/<name>/`. Full notes, commands and outputs are in `<scratch>/research/lock-cache/FINDINGS.md`. The helper scripts (`env.sh`, `mkapp.sh`, `lockhash.sh`, `work/mkver.py`) and the test feeds are in the same directory.

Terms used below:
- **GPF** is the global packages folder, normally `~/.nuget/packages`.
- **Patched** means a copy of Newtonsoft.Json 13.0.3 with bytes appended to `lib/net6.0/Newtonsoft.Json.dll` and a `SOCKET_PATCHED.txt` file added.
- **Upstream** means the unmodified package from nuget.org.

## (a) What the lock file contains
- **VERIFIED:** For a signed package, `contentHash` is the base64 sha512 of the .nupkg with the `.signature.p7s` entry removed. It is not the hash of the file as downloaded. `zip -d t.nupkg .signature.p7s; openssl dgst -sha512 -binary t.nupkg | base64` gave `HrC5BXdl…`, which matches the lock file. The hash of the raw file is `mbJSvHfR…`, which is what the GPF's `newtonsoft.json.13.0.3.nupkg.sha512` holds.
- **VERIFIED:** For an unsigned package, `contentHash` is the sha512 of the file bytes (`hNLqr27u…` for the patched copy, both ways).
- **VERIFIED:** `.nupkg.metadata` in the GPF holds `{"version":2,"contentHash":<same kind of hash as the lock>,"source":<feed>}`.
- **VERIFIED** entry shapes:
  - Direct: `{"type":"Direct","requested":"[13.0.3, )","resolved":"13.0.3","contentHash":…,"dependencies":{…}}`
  - Transitive: `{"type":"Transitive","resolved","contentHash"}`
  - Project: `{"type":"Project","dependencies":{"Humanizer.Core":"[2.14.1, )"}}`, with no hash
  - CentralTransitive: `{"type":"CentralTransitive","requested":"[13.0.3.1, )",…}`. This needs Central Package Management with `CentralPackageTransitivePinningEnabled`.

## (b) What restore does when hashes don't match
- **VERIFIED, cold cache:** Empty GPF, feed has the patched package, lock pins the upstream hash, `--locked-mode`. It fails with `error NU1403: Package content hash validation failed for Newtonsoft.Json.13.0.3. The package is different than the last restore.` But the patched package has already been fully extracted into the GPF, `.nupkg.metadata` included. **A failed restore still poisons the cache.**
- **VERIFIED:** GPF has upstream, lock pins patched, feed has patched: NU1403. Nothing is re-downloaded and the GPF is unchanged.
- **VERIFIED:** GPF has patched, lock pins upstream: NU1403.
- **VERIFIED, what NuGet compares against:**
  - I left the upstream bytes in the GPF and edited only the `contentHash` in `.nupkg.metadata` to the patched hash. A locked restore against the patched lock **succeeded**.
  - Editing only `.nupkg.sha512` still gave NU1403.
  - So when a package is already in the GPF, NuGet compares the lock hash with the `.nupkg.metadata` value only. It never rehashes the .nupkg, the extracted files, or the feed bytes.
- **VERIFIED:** NU1403 also happens **without** `--locked-mode` whenever a `packages.lock.json` exists and its hash differs.
- **VERIFIED, other error codes:**
  - NU1004: locked mode after a PackageReference changed (`The package references have changed for net8.0…`).
  - NU1605: a direct reference to 13.0.3-socket.1 while a dependency needs >=13.0.3 (`Detected package downgrade: Newtonsoft.Json from 13.0.3 to 13.0.3-socket.1`). The SDK treats this warning as an error, yet the lock file was still rewritten.
  - NU1102: the lock pins a version the feed doesn't have.
- **VERIFIED, signatures:**
  - Keeping a stale signature that is well-formed and is the last zip entry gives `error NU3008: The package integrity check failed. The package has changed since it was signed.`
  - A misplaced or malformed signature entry gives only `warning NU3005` and the restore continues.
  - Signatures are checked only when a package is extracted, not when it is already in the GPF.

## (c) The GPF never refreshes an existing package
- **VERIFIED:** I tampered with a dll inside the GPF. The locked restore passed and the tampered dll was used.
- **VERIFIED:** `.nupkg.metadata` is the marker that a package is complete.
  - Delete it but keep `.sha512`: NuGet recreates `.nupkg.metadata` from the local files (`"source": null`) and does not re-extract.
  - How it recreates the hash: for a signed package it recomputes the hash from the .nupkg; for an unsigned one it copies the text of `.sha512`.
  - Delete both files: the package is downloaded and extracted again (the tampered dll went back to its original size).
- **VERIFIED:** `dotnet restore --no-cache --force --force-evaluate` does not refresh a GPF entry.
- **VERIFIED, stale copies leak both ways without a lock file:**
  - After the failed restore above left the patched copy in the GPF, an unrelated nuget.org project with no lock file built against it (its output dll ends in `SOCKETPATCH`).
  - The other way round: GPF has upstream, feed has patched, no lock. Restore quietly used upstream and wrote a lock with the upstream hash.

## (d) Repo-local GPF
- **VERIFIED:** A relative `globalPackagesFolder` in nuget.config resolves relative to the nuget.config file, not the current directory. Restoring the solution from `src/app` created the folder at the solution root.
- **VERIFIED:** Restore, build and publish all used it (`project.assets.json` packageFolders and `NuGetPackageRoot` in `nuget.g.props`). `$HOME/.nuget/packages` was never created. `dotnet test` was not run.
- **VERIFIED, which setting wins:** `RestorePackagesPath` (MSBuild property) beats the `NUGET_PACKAGES` env var, which beats nuget.config. So a CI job that sets `NUGET_PACKAGES` overrides a nuget.config setting, but not a `Directory.Build.props` property.
- **VERIFIED:** A relative `RestorePackagesPath` in `Directory.Build.props` resolves per project directory, giving one GPF per project. Use `$(MSBuildThisFileDirectory)`.
- **DOCS:** The HTTP cache stays machine-wide. Local folder feeds are not HTTP-cached.

## (e) Fallback folders
- **VERIFIED:** I pointed nuget.config's `<fallbackPackageFolders>` at a folder holding the extracted patched package. It was used in place and not copied to the GPF (the GPF stayed empty), and the built dll was the patched one. The lock hash came from the fallback's `.nupkg.metadata` and was byte-identical to the lock produced from a feed.
- **VERIFIED:** The minimum a fallback entry needs is `.nupkg.metadata`, the nuspec and `lib/`. It needs neither the .nupkg nor `.sha512`, and it worked with the only source pointing at a folder that doesn't exist. Without `.nupkg.metadata` the entry is ignored and NuGet goes to the source (NU1301).
- **VERIFIED:** An upstream lock against a patched fallback gives NU1403. The hash check only trusts the value written in `.nupkg.metadata`.
- **VERIFIED, the GPF beats fallback folders:** if the GPF already holds upstream 13.0.3, a patched lock fails with NU1403, and with no lock the upstream copy is used silently. A committed fallback folder is therefore not a vendoring mechanism on its own. It only works together with an isolated GPF.

## (f) The lock doesn't record the source
- **VERIFIED:** A lock generated from nuget.org passed a locked restore from a local folder feed holding the same bytes, and the lock stayed byte-identical. The lock only pins id, version and contentHash.

## (g) Version suffixes
- **VERIFIED:** `13.0.3+socket.1` collides completely with 13.0.3.
  - The GPF path is `newtonsoft.json/13.0.3`, the lock says `resolved "13.0.3"`, and it says `requested "[13.0.3, )"` even when the csproj says `Version="13.0.3+socket.1"`.
  - A second nuget.org project on the same GPF then built against the patched dll.
- **VERIFIED:** `13.0.3-socket.1` gets its own GPF folder, but it sorts below 13.0.3. That causes NU1605 whenever something needs >=13.0.3.
- **VERIFIED:** A four-part `13.0.3.1` gets its own GPF folder and sorts above 13.0.3, so there's no downgrade error. It works as a direct reference and as a CentralTransitive pin.
- **DOCS:** A dependency with an exact `[13.0.3]` range would give NU1608. A real upstream 13.0.3.1 would collide, but that's rare.

## What this means for vendoring a patched copy with the same id+version as upstream
1. **A shared GPF can't be made safe.** The first copy written wins and is never refreshed. Patched bytes leak to other projects and CI caches, and upstream bytes leak in. A failed locked restore still leaves the wrong copy behind.
2. **The lock hash detects the problem but can't fix it.** It only compares against `.nupkg.metadata`. The only recovery is deleting that GPF entry, so hosted or cached-CI revert needs cache eviction as well as rewriting the lock.
3. **Robust options:**
   - **(a) Repo-local GPF** set with `RestorePackagesPath=$(MSBuildThisFileDirectory)…` in `Directory.Build.props`. It beats `NUGET_PACKAGES` and covers restore, build and publish. It could be pre-seeded with the extracted patched package (a `.nupkg.metadata` file plus a minimal file set) and gitignore everything else.
   - **(b) A distinct four-part version** such as 13.0.3.1, with Central Package Management transitive pinning. This removes the collision entirely. Don't use `+metadata` (it collides) or `-prerelease` (NU1605).
   - **(c) A committed fallback folder.** It gives offline use without copying into the GPF, but only if the GPF doesn't already have that id+version, so it depends on (a).
4. **Always drop `.signature.p7s`** (otherwise NU3008). The patched package's lock hash is then just the sha512 of the rebuilt file, and the current rewrite of the lock `contentHash` must use that.
5. **The current design's catch-all `*` source mapping doesn't help.** Once the package is in any GPF, the mapping is never consulted.