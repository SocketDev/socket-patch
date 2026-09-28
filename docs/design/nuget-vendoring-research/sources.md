# NuGet sources, packageSourceMapping and nuget.config research (SDK 8.0.131, NuGet 6.8.2)

The tool harness refused to let me write `FINDINGS.md`, so the notes are below instead of in that file. The experiment dirs, helpers (`env.sh`), test packages and the delayed-HTTP feed server are under `<scratch>/research/sources/` (in `exp/`, `pkgs/` and `httpfeed/server.py`). Every experiment ran with a fresh HOME, NUGET_PACKAGES, NUGET_HTTP_CACHE_PATH and DOTNET_CLI_HOME.

To tell which bytes won, I read `gpf/<id>/<ver>/SOCKET_PATCHED.txt` and the `source` field in `.nupkg.metadata`. "gpf" below means the global packages folder (`~/.nuget/packages`).

**Command not available:** `dotnet nuget config paths` does not exist in 8.0.131. It fails with `error: Unrecognized command or argument 'config'` (VERIFIED). I used `dotnet restore -v:n` (the "NuGet Config files used" and "Feeds used" lines) and strace instead.

## (a) Local folder feeds

**Flat feed**
- A file named `<id>.*.nupkg` resolves. The filename match is case-insensitive (`Newtonsoft.Json.13.0.3.nupkg`, lowercase and UPPERCASE all worked). Even `Newtonsoft.Json.13.0.3-whatever.nupkg` worked, because the version comes from the nuspec inside the package (VERIFIED).
- These fail with NU1101 (VERIFIED):
  - `zzz-random.nupkg`
  - `Newtonsoft.Json.nupkg`
  - a nupkg in a subdirectory (the flat feed is not recursive)

**Hierarchical feed (`<id>/<ver>/`)** (VERIFIED)
- It needs three files:
  - the lowercase nupkg,
  - `.nupkg.sha512`, which acts as the existence marker (nupkg + nuspec without it gives NU1101),
  - `<id>.nuspec` (nupkg + sha512 without it gives `error NU5037: The package is missing the required nuspec file`).
- **Linux needs lowercase.** A `Newtonsoft.Json/13.0.3/Newtonsoft.Json.13.0.3.nupkg` layout gives NU1101.
- **The `.sha512` content is not trusted.** I put garbage in it, and the gpf and lock contentHash still came out as the real SHA512 of the nupkg (`dkeh7b…`). NuGet re-hashes the package on install.
- **Dependencies come from the loose `.nuspec`, not the one inside the nupkg.** A loose nuspec with an extra dependency made restore pull Humanizer.Core. The nuspec extracted into gpf had no such dependency. So the loose nuspec must be byte-identical to the inner one.

**`dotnet nuget push -s <dir>`** (VERIFIED)
- An empty dir gets a flat file, `Newtonsoft.Json.13.0.3.nupkg`.
- A dir that already has one full hierarchical entry (nupkg + nuspec + sha512) gets a full expanded entry: lowercase dirs, `.nupkg.sha512`, nuspec, `.nupkg.metadata` and all extracted files. It is not a `nuget add`-style minimal entry.

**Performance:** a flat feed with 1 vs 201 `Newtonsoft.Json.*` files restored in 236–263 ms either way (VERIFIED). The difference doesn't matter at our scale.

**Signatures**
- Keeping the original `.signature.p7s` on modified contents gives `error NU3008: The package integrity check failed. The package has changed since it was signed.` This happens even under the default `accept` mode (VERIFIED). The signature must be dropped.
- An unsigned package under `signatureValidationMode=require` gives `error NU3004 ... this package is unsigned` (VERIFIED).

**Global packages folder poisoning** (VERIFIED)
- I restored upstream 13.0.3, then switched the config to only the patched feed and ran `restore --force`. There was no error, the gpf entry stayed upstream (`source: https://api.nuget.org/...`), and the assets file kept the upstream hash. A matching id+version in gpf means the feeds are never asked.
- With the patched contentHash in the lock file, `--locked-mode` gives `error NU1403: Package content hash validation failed ... different than the last restore`. Upstream was still written to gpf. After that, restoring with the patched feed also fails NU1403 until the gpf entry is deleted.

## (b) packageSourceMapping

**Exclusivity** (VERIFIED)
- Once any mapping exists, a package that no pattern matches fails: `error NU1100: Unable to resolve 'Humanizer.Core (>= 2.14.1)' ... PackageSourceMapping is enabled, the following source(s) were not considered: loc, nuget.org.`
- The catch-all is skipped for an id that a more specific pattern matches. With `nuget.org:*`, `loc:Newtonsoft.Json` and an empty loc, the result is `NU1101 ... No packages exist with this id in source(s): loc ... not considered: nuget.org`. There is no fallback.

**Pattern precedence** (VERIFIED)
- The longest prefix wins: `Newtonsoft.Js*` on loc beats `Newtonsoft.*` on nuget.org.
- An exact id beats a prefix: `Newtonsoft.Json` on nuget.org beats `Newtonsoft.*` on loc.
- If the same pattern is on two sources, both are eligible. With loc empty it silently falls back to nuget.org; with both holding the package, it becomes the race described in (d).
- Pattern matching is case-insensitive. The source key is case-sensitive: a mapping for `LOC` against a source `loc` gives NU1100.

**Missing or disabled source** (VERIFIED)
- A mapping to a key with no `<add>` entry gives NU1100.
- A mapping to a source that exists but is disabled also gives NU1100.

**Multiple config files** (VERIFIED)
- **A user-level mapping silently hides a repo source that has no mapping.** User `~/.nuget/NuGet/NuGet.Config` mapped `nuget.org:*`; the repo added `loc` with no mapping. Upstream was installed with no error.
- **Different keys combine across files.** User `nuget.org:*` plus repo `loc:Newtonsoft.Json` gave the patched package.
- **The same key in a nearer file replaces the farther file's patterns.** User `nuget.org:{*, Newtonsoft.Json}` plus repo `nuget.org:{Humanizer.*}` made Newtonsoft.Json fail NU1100.
- **`<clear/>` inside `<packageSourceMapping>` drops the user-level mappings.** Anything the repo file doesn't map then fails NU1100.

## (c) nuget.config precedence

**Discovery** (VERIFIED, strace): NuGet probes `nuget.config`, `NuGet.config` and `NuGet.Config` in every ancestor directory up to `/`. It then reads:
- `$HOME/.nuget/NuGet/NuGet.Config`
- `$HOME/.nuget/NuGet/config/` (a directory of extra user-level configs)
- `/etc/opt/NuGet/Config/` (machine-wide)
- `/etc/opt/NuGet/NuGetDefaults.config`

**File-name casing on Linux** (VERIFIED)
- `nuget.config`, `NuGet.config` and `NuGet.Config` all work. `NUGET.CONFIG` and `Nuget.Config` are ignored.
- If several are in one directory, only one is read, in the order `nuget.config` > `NuGet.config` > `NuGet.Config`.

**Merging** (VERIFIED)
- Configs are merged and applied from farthest to nearest.
- `<clear/>` in `packageSources` removes only sources from farther files. In the child it removes the parent's and the user's sources; in the parent it removes only the user's.
- A relative source value (`./feed`) resolves against the directory of the config file that declares it.

**`--source` and `RestoreSources`** (VERIFIED)
- Both replace the configured sources, but the mapping still applies.
- A `--source` value equal to a configured source's value takes that source's key and mapping.
- An unconfigured path is named by its path, so it matches no mapping and fails NU1100 (`not considered: /other, nuget.org`).
- `-p:RestoreSources=<nuget.org URL>` drops loc, so Newtonsoft.Json fails NU1100.

## (d) Same id+version from two sources, no mapping (VERIFIED)
- **Local folder vs nuget.org:** the local folder won every time, in both config orders and with a cold or warm HTTP cache (4 runs each).
- **Two local folders:** the first-listed one won 6/6 times, and swapping the order flipped the result.
- **Local HTTP feed:** with 0 s delay it won in both orders. With 3 s delay it lost to nuget.org in both orders.

Conclusion: the first source to respond wins, so the result depends on timing and is nondeterministic on real networks.

## (e) RestoreAdditionalProjectSources in Directory.Build.props (VERIFIED)
- **With no mapping anywhere:** the source is added (it shows in "Feeds used") and joins the race.
- **With any mapping** (e.g. `nuget.org:*`): it is ignored and upstream is installed silently.
- **A mapping keyed by the absolute path works.** A relative value is named by its resolved absolute path, so a mapping keyed `feed` fails NU1100. This setup can't be committed portably.

## (f) Giving the patched package a unique version

**It resolves only from our feed** (VERIFIED)
- `13.0.3-socket.1` resolved from loc with no mapping.
- `13.0.3.1-socket.1` resolved from an HTTP feed with 3 s delay even though nuget.org was faster (restore took 9.95 s). There is no race when only one source has the version.

**When our feed is missing** (VERIFIED)
- An exact `[13.0.3.1]` or `[13.0.3-socket.1]` gives `error NU1102: Unable to find package Newtonsoft.Json with version (= 13.0.3.1) - Found 0 version(s) in loc - Found 86 version(s) in nuget.org [ Nearest version: 13.0.4-beta1 ]`.
- A plain `13.0.3-socket.1` gives `warning NU1603 ... approximate best match of Newtonsoft.Json 13.0.3 was resolved` (upstream, silently).
- A plain `13.0.3.1` gives NU1603 and resolves upstream **13.0.4**.

**Interaction with other packages' dependency ranges** (VERIFIED)
- A dependency asking `>=13.0.1` plus a direct `13.0.3-socket.1` is fine.
- A dependency asking `>=13.0.3` plus a direct `13.0.3-socket.1` gives `error NU1605: Warning As Error: Detected package downgrade: Newtonsoft.Json from 13.0.3 to 13.0.3-socket.1`. A prerelease sorts below its base version.
- A dependency asking `>=13.0.3` works with a direct `13.0.3.1` and with `13.0.3.1-socket.1`. The latter sorts above 13.0.3 and below 13.0.4, and also below any future upstream 13.0.3.1.
- `13.0.3+socket.1` (build metadata) is treated as 13.0.3 and came from nuget.org, so it is useless.

**Transitive-only use needs a pin** (VERIFIED)
- If only a dependency references it (`>=13.0.1`), restore picks upstream 13.0.1.
- Central Package Management works: `ManagePackageVersionsCentrally` + `CentralPackageTransitivePinningEnabled` + `PackageVersion 13.0.3.1-socket.1` gave the patched package with no direct reference.

**No cache collision:** the unique version gets its own gpf dir (`newtonsoft.json/13.0.3.1-socket.1`), so it can't collide with a cached upstream 13.0.3 (VERIFIED).

## What this means for vendoring a patched copy with the same id+version

1. **Same id+version can't be made robust.**
   - gpf wins silently, even with `--force` (VERIFIED).
   - A poisoned gpf, CI cache or shared runner gives permanent NU1403 or silent unpatched builds (VERIFIED).
   - Without a mapping the winner is timing-dependent (VERIFIED).
   - A mapping can be undone by a user-level, CI or ancestor-dir config: an unmapped repo source, a replaced pattern list for the same key, `<clear/>`, or `--source` / `RestoreSources` (all VERIFIED).
   - The current catch-all `*` workaround turns every package no pattern matches into an NU1100 risk once another config adds its own mapping.
2. **A unique version is deterministic** and needs no `packageSourceMapping`. Use `X.Y.Z.N-socket.M` (4-part base plus prerelease tag), not `X.Y.Z-socket.N` (NU1605 against any `>=X.Y.Z` dependency) and not `+meta` (same identity as upstream).
   - Reference it with an exact bracket `[v]` (via `Directory.Packages.props` with transitive pinning, or a direct PackageReference), so a missing vendor dir fails hard with NU1102 instead of the NU1603 silent upgrade to upstream (VERIFIED).
   - Revert is just restoring the original version string; no gpf cleanup is needed.
   - Trade-offs (DOCS/inference): the lock file changes version and contentHash, and packable libraries would publish a dependency on a version consumers can't get.
3. **Feed format:** prefer a flat folder with `<id>.<ver>.nupkg`, which needs no sidecar files (VERIFIED). A hierarchical feed needs a lowercase path, a `.sha512` marker (its content is ignored) and a loose nuspec byte-identical to the inner one (VERIFIED). Declare the feed with a relative path in a lowercase `nuget.config` at the repo root (VERIFIED). Don't use `RestoreAdditionalProjectSources` (VERIFIED).
4. **Signatures:** always strip `.signature.p7s` (NU3008 otherwise). Repos using `signatureValidationMode=require` will reject any rebuilt package (NU3004), so detect that and refuse.