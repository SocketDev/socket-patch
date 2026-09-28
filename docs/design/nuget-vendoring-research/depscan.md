# depscan backend research for NuGet vendoring (for socket-patch v5)

## TL;DR
- depscan already builds **one prebuilt patched `.nupkg` per patch**. It keeps the **same id and version as upstream**, repacks the zip STORE-only, strips `.signature.p7s` and adds no signature. The bytes are written once to object storage, and their **sha512 SRI** is saved as `package_integrity`.
- You can get it two ways:
  - **Artifact route:** `/patch/nuget/...`. The vendoring service (`POST /v0/orgs/{org}/patches/package`) returns this URL, and socket-patch's `service_fetch.rs` already downloads and checks it.
  - **Single-package NuGet v3 feed:** `/patch-registry/nuget/{token}/{uuid}/index.json`, used by hosted mode.
- **For unsigned packages, NuGet's `contentHash` is the base64 sha512 of the nupkg bytes.** That equals `package_integrity` with the `sha512-` prefix removed. A dotnet e2e test proves this.
- **A patched-version suffix exists for Maven (`<base>-socket.<hex8>`) and Go (`<base>-socketpatch.<n>`). NuGet has none.** NuGet is always served under the upstream id+version.
- **Nothing is signed anywhere.** `sign.ts` is an identity stub, and there is no key custody.
- **No NuGet-specific vendoring artifact exists server-side**, beyond the plain `.nupkg`. For comparison, gem has a stub gemspec, Go has the gopatch zip and npm has a berry zip.

---

## 1. Hosted NuGet serving (patch-server)

**Server entry:** `depscan/workspaces/patches/src/services/patch-serving/server.ts:65-80` registers three route families:
- `/patch/...`: `registerPatchServeRoute` in `serve-route.ts`
- `/patch-registry/...`: `registerPatchRegistryRoutes` in `registry-routes.ts:32`, one regex route that parses `req.path`
- `/gopatch/...`

**URL grammar:** `depscan/workspaces/lib/src/socket-patch/patch-url.ts:1-23`. These parsers are shared by the server and SBOM recognition.
- Artifact URL: `https://{host}/patch/{eco}/{name}/{version}/{token}/{patch-uuid}/{filename}` (`parsePatchServeUrl`, :82)
- Registry URL: `https://{host}/patch-registry/{eco}/{token}/{patch-uuid}/<tail>` (`parsePatchRegistryUrl`, :156)
- Vendored path: `file:.socket/vendor/{eco}/{patch-uuid}/{leaf}` (`parseSocketVendorPath`, :253, a TS port of socket-patch `vendor/path.rs`)

**NuGet v3 feed:** `nugetDecision` in `patch-serving/registry-decision.ts:361-427`. This is a pure function. It serves a feed containing exactly one package version, pinned by the uuid in the URL:

| tail | response |
|---|---|
| `index.json` | Service index with only two resources: `PackageBaseAddress/3.0.0` → `{base}/flat/` and `RegistrationsBaseUrl/3.6.0` → `{base}/reg/` (:370-387). No search, autocomplete or catalog. |
| `flat/{idLower}/index.json` | `{versions:[verNorm]}` (:389-396) |
| `flat/{idLower}/{verNorm}/{idLower}.{verNorm}.nupkg` | Streams the object-store bytes with `ETag: "<sha512 SRI>"` (:397-406) |
| `reg/{idLower}/index.json` | Minimal registration: one page, one leaf, with `catalogEntry:{id,version}` and `packageContent`. **No `packageHash`, no dependency groups, no `listed`** (:407-425) |

**Gates, before any of the above** (`evaluateRegistryDecision`, :190-222):
- `unpublished_at` set → 410
- ecosystem mismatch → 404
- `package_status !== 'built'` → 408, or 404 if the build failed

**Artifact headers:** `archive-response-headers.ts:11`
- `Cache-Control: public, max-age=3600, no-transform`, deliberately not `immutable`, so that revoking a grant still has an effect.
- There is no `X-Socket-Patch-Unsigned` header, although `sign.ts` suggests one.

**Bytes served:** the output of `nugetRepacker` in `patches/src/repack/repackers/nuget.ts:35-69`:
- Unzips the upstream nupkg and substitutes the patched files.
- Leaves the nuspec, id and version unchanged.
- Removes `.signature.p7s` via `stripSignedArchiveMetadata` (`patches-shared/src/archive/repack-utils.ts:1290-1314`).
- Re-zips with `store: true`, level 0 (`repack-utils.ts:696-701`).
- The doc comment (:24-33) says unsigned output is the "current v1 contract".

**Upstream fetch:** `patches/src/repack/upstream/nuget.ts:13-62`.
- Downloads from `api.nuget.org/v3-flatcontainer` using the lowercased id and normalized version.
- Does **not** verify against the registry `packageHash`. Per the comment at :49-59, only the per-file `before_sha` check applies.

**Hash computation:** `patches/src/services/patch-package/build.ts:309-320`.
- Computes `sha512-<b64>` (`package_integrity`), sha256 (`package_blob_file_hash`), sha1 and md5 over the archive.
- Storage is write-once (:235-240); `gcs-store.ts:194-205` re-hashes on read-back.

**Proof that `contentHash` equals `package_integrity` without the prefix:** `patches/src/test/integration/installers/nuget.installer.e2e.test.ts:1-36, 166-261`.
- Uses a real `dotnet restore` against a folder feed with `<clear/>`.
- Runs `--locked-mode` with fresh `NUGET_PACKAGES` and `NUGET_HTTP_CACHE_PATH`.
- A negative leg swaps in the upstream package and expects NU1403.
- Note: the test isolates the global packages folder precisely **because** the same id+version collides in the global packages cache.

## 2. Vendoring service contract (server ↔ client pairing)

**Endpoint:** `POST /v0/orgs/{org_slug}/patches/package`, defined in `depscan/workspaces/api-v0/src/endpoints/orgs/patches/package.ts:252-258` (operationId `getPatchPackages`).
- **Request** (:37-42): `{uuids[], freeOnly}`.
- **Response** (:137-169): `results[uuid] = {status, url, purl, artifacts[], registryOverride}`.
  - `status` is one of `granted | reused | pending_build | build_failed | withdrawn | forbidden | not_found`.
  - `artifacts[].kind` is one of `tarball | yarn-berry-zip | gem-stub-gemspec` (:121-134).
  - Integrity fields: `{sha512, sha256, sha1, md5, dirhashH1, goModH1, yarnBerry10c0}` (:46-62).

**Public proxy:** `POST /patch/package` in `depscan/workspaces/patches-api-proxy/src/server.ts:1003-1030` forwards to the same endpoint and forces `freeOnly`.

**Core logic:** `depscan/workspaces/app/src/patches/patch-package-references.ts`
- `getPatchPackageReferences` (:933).
- `buildPatchPackageArtifacts` (:469-530): the tarball comes first and carries sha512, sha256, sha1 and md5. For NuGet that is the only artifact; it points at the `/patch/nuget/...` serve URL.
- `buildRegistryOverride` for NuGet (:668-683) returns:
  - `kind: 'nuget-v3'`
  - `indexUrl: {base}/index.json`
  - `nugetIdLower` and `nugetVersionNorm`
  - **no hash** in the identifiers; the rewriter uses the artifact's sha512.

**Client side (socket-patch):**

| Step | File and lines |
|---|---|
| Choose endpoint: authenticated vs `/patch/package` proxy | `crates/socket-patch-core/src/api/client.rs:742-743`, `vendor_package_url` :1373-1386 |
| Two-step request, then download; `patch_server_url` rewrites the download host | `fetch_vendor_package` :1115-1160, `_once` :1242-1350 |
| Secondary artifacts | client.rs :1310-1348 |
| Checks the sha512 SRI floor (plus Go `h1:`) and fails closed on mismatch | `vendor/service_fetch.rs:88-138` (`fetch_verified_archive`) |
| Maven/NuGet path: service first, else local rebuild; `--vendor-source=service` hard-fails | `service_fetch.rs:170-200` (`service_archive_copy`) |
| NuGet vendoring calls it | `vendor/nuget_feed.rs:906` |
| Hosted-mode rewriter reads `nuget_id_lower` / `nuget_version_norm` | `patch/redirect/mod.rs:126-127, 449, 5126-5280` |

The hosted-mode rewriter is mirrored in depscan: `depscan/workspaces/app/src/patches/registry-rewrite/nuget.ts:1-232`. It:
- adds a source plus a `packageSourceMapping`, with a catch-all for existing sources (:160-211);
- sets `contentHash` to the sha512 without the prefix and `resolved` to `nugetVersionNorm` (:69-112).

**Answer to (2): yes, a prebuilt patched `.nupkg` is already available for vendoring.** socket-patch already consumes it through `service_fetch`. There is no NuGet-specific variant: no renamed or re-versioned build and no signed build.

## 3. Patched-version suffix and distinct-identity precedents

**Maven: `<base>-socket.<first-8-hex-of-uuid>`**
- Derivation: `depscan/workspaces/app/src/patches/maven-suffix.ts:1-65`. `suffixMavenPom` rewrites the pom's `<version>` and literalizes `${project.version}`, or returns null so the caller falls back to the same GAV.
- Serve: `registry-decision.ts:~430-470`. When the pom rewrite succeeds, the artifact is served only under the suffixed version and the bare-upstream paths return 404. There is deliberately no `maven-metadata.xml`, so version ranges cannot resolve it (fail-closed).
- The pom's sha256 is published as `mavenPomSha256` (`package.ts:93-101`) for a trusted-checksum pin.
- Note: the jar bytes themselves are not re-versioned; only the pom is.

**Go: `<base>-socketpatch.<n>`, with the module re-homed to `patch.socket.dev/gopatch/<uuid>`**
- `depscan/workspaces/lib/src/go/gopatch.ts:21-64`.
- `GopatchFlavor` (`repack/ecosystem-repacker.ts:65-80`) is a **second stored artifact** with its own sha512 and `h1:`, stored in `build.ts:395-405, 485-500`.
- Changed content must bump `<n>`, never reuse a version (`build.ts:487-491`; `patch-sync/import-db.ts:56`).

**Other secondary vendoring artifacts:**
- gem stub gemspec: `repackers/gem-stub-gemspec.ts`, stored in `build.ts:412-419`.
- npm yarn-berry cache zip: `build.ts:344-390`.

**NuGet:** none. There is no `-socket.N` prerelease, no `+socket` metadata and no distinct id. `normalizeNuGetVersion` actually **drops** `+metadata` (`repack/nuget-version.ts:1-35`). That makes `+socket` useless as a distinguisher, because NuGet also ignores build metadata for identity and for the global packages cache path.

**Other ecosystems' vendored artifacts server-side:**
- There is exactly one pipeline: the converter build in `services/patch-package/build.ts` feeding the `published_patches.package_*` columns (`queue.ts:410`), then the serve route.
- There is no separate "vendor" build; vendoring reuses the hosted tarball.

## 4. NuGet identity in depscan

**PURL:** `depscan/workspaces/lib/src/purl/schema/nuget.ts:1-25`.
- `pkg:nuget/<name>@<version>`, with no namespace.
- The name keeps its case (spec: case-sensitive in the archive, case-insensitive for lookup).
- `purl-full-name.ts:258-263` sets namespace to null.

**Version normalization (three implementations kept in sync):**
- `patches/src/repack/nuget-version.ts:15-35`: lowercase, drop `+meta`, strip leading zeros, pad to 3 parts, drop a zero 4th part.
- `app/src/patches/patch-package-references.ts:555-590`.
- socket-patch `vendor/nuget_feed.rs`.

Serve paths, the upstream fetch and `nugetVersionNorm` all use the normalized form. The serve decision checks the tail against the row using `idLower` and `verNorm`.

**SBOM:** the pipeline NuGet tasks (`pipeline/src/task/cs/nuget/**`) have **no Socket-patch reference detection**. That detection exists for npm, pypi and gem only (grep of `detectSocketPatchReference`/`parseSocketVendorPath` in `pipeline/src`). A patched NuGet dependency therefore shows up as plain upstream `name@version`. If the NuGet package id or version changed, SBOM/purl mapping would need new detection.

## 5. Signing

- `patches/src/repack/sign.ts:1-38`: `defaultSign` returns null.
- The comments list a future `authenticode-p7s` kind for NuGet, but state "no key custody / KMS / HSM exists yet".
- Columns `package_signature` and `package_signature_kind` exist (`ecosystem-repacker.ts:55-62`; `queue.ts:410-411`) and are always null.
- There are **no repository or author signatures** for any ecosystem.
- Consequence: consumers using `signatureValidationMode=require` or `<trustedSigners>` will reject Socket nupkgs. The nuget repacker comment (:27-31) acknowledges this.

---

## What could live server-side for NuGet vendoring

1. **Keep today's prebuilt `.nupkg` and add the missing integrity pieces.**
   - Feasibility: exists; the additions are trivial.
   - The artifact and its sha512 are already served. `contentHash` is the sha512 payload of that artifact.
   - Cheap additions:
     - put `packageHash`/`packageHashAlgorithm` into the registration leaf in `registry-decision.ts:407-425`;
     - add dependency groups taken from the nuspec so the registration is spec-complete.
   - This does not remove the global-packages-cache collision.

2. **A Socket-suffixed NuGet flavor, `<ver>-socket.<hex8>` (prerelease), as a second artifact.**
   - Feasibility: moderate. The Maven and Go flavors are close templates: `GopatchFlavor` storage in `build.ts:395-500`, and the fail-closed serve/404 pattern for bare paths in `mavenDecision`.
   - Work required:
     - rewrite `<version>` in the nuspec;
     - rename the entry `{id}.nuspec` and possibly rebuild `[Content_Types].xml`/`_rels`;
     - the flat path, registration and `normalizeNuGetVersion` then handle the new version as-is;
     - add `nugetSuffixedVersion` to `RegistryOverrideIdentifiers` and a new `artifacts[].kind` (for example `nupkg-socket`).
   - Benefit: removes the global-packages-cache collision, source-mapping ambiguity and fall-through to nuget.org.
   - Costs:
     - a prerelease version changes resolution semantics: floating ranges ignore prereleases, NU5104 warnings appear, and transitive `>= x` constraints are still satisfied;
     - the consumer must change `<PackageReference Version>` or use central package management (CPM) / `Directory.Packages.props`;
     - SBOM must learn to map `-socket.` back to the upstream purl (see §4).
   - Using `+socket` metadata instead of a prerelease is **not viable**, because NuGet drops it for identity.

3. **A distinct package id, e.g. `Socket.Patched.<Id>`.**
   - Feasibility: low.
   - Assembly and type identity would not change, but every transitive dependent still references the original id. It would need a shim or `PackageReference` aliasing that NuGet does not support. Not recommended.

4. **Serve the vendored feed metadata server-side.**
   - Feasibility: exists for hosted mode.
   - The single-package v3 feed can be "ejected": socket-patch already gets the bytes. A local feed only needs the nupkg (a folder feed needs no metadata). Nothing extra is needed from the server.

5. **Repository signature (`.signature.p7s`) with a Socket certificate.**
   - Feasibility: not feasible now. There is no key custody (`sign.ts`).
   - It would also make `contentHash` follow the signed-package rules, so it would no longer equal the plain sha512. The e2e test's claim would change.

6. **Upstream `packageHash` recording, for the restore-upstream / revert of workstream WS1.**
   - Feasibility: small to moderate.
   - The server does not fetch or store the upstream nuget.org `packageHash` (`upstream/nuget.ts:49-59` skips it).
   - Persisting the upstream sha512 and signed `contentHash` would let the CLI restore the original `packages.lock.json` entry offline. This addresses "hosted revert unsupported".

7. **SBOM recognition of patched NuGet dependencies.**
   - Feasibility: moderate. It does not exist today for NuGet.
   - Needed if option 2 or 3 ships. It is useful even for same-version packages, via the `nuget.config` source URL or a `.socket/vendor/nuget/<uuid>` path.

**Items that do not exist anywhere in depscan:**
- a NuGet version suffix or distinct id;
- any signing;
- `packageHash` in the served registration;
- an upstream NuGet digest check;
- a vendoring-specific NuGet artifact;
- NuGet patch detection in SBOM.