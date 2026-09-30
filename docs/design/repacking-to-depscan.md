# Repacking moves to depscan (server-primary, one local class)

> Reference copy of PR #286, which was closed without merging. Each
> finding's owner (workstream, in-flight PR or owner decision) is in
> the [triage map](https://github.com/SocketDev/socket-patch/pull/286#issuecomment-5869109317).

Status: chosen design, pending owner sign-off on the open questions (last
section). Baseline: socket-patch `release/v5-prerelease` at 8ae7dc37,
depscan `master` at 93e149c9ba. Supporting evidence: the repacking inventory
of both repos and the verified waste findings (cited as F01–F80). Line
numbers are at those baselines; depscan paths carry a `depscan:` prefix.
Where a claim rests on an in-flight v5 branch, the branch is named.

## Summary

- **depscan becomes the producer of installable patched bytes** for every
  vendorable ecosystem except maven/nuget (frozen, unchanged). The CLI
  resolves, downloads, verifies, and wires. It computes no lock pin except
  the one class below, and a pin it does compute is always cross-checked
  against the server's value where one exists.
- **Exactly one local builder stays**: the pypi wheel built from the
  installed dist (`pypi_wheel.rs`). It runs only when the server returns a
  terminal `refused { localBuild: "allowed" }` verdict: releases with no
  servable wheel for the requested tags (the installed binary was
  necessarily built on the user's machine), or an upstream file over the
  serve cap. The verdict is keyed on (uuid, requested wheel) and carries a
  TTL, because PyPI can add wheels to a release later; the ledger's
  `producer` keeps the choice sticky. It never runs because of an outage.
- **One producer per artifact, and the ledger keeps it sticky.** Vendor
  `state.json` records `producer`, `recipe`, `generation`, and
  `statementDigest`. Outages, 5xx responses and `pending_build` fail
  retryably and leave the lock untouched. The integrity flip that #250 and
  `reuse.rs` exist to hide can no longer happen. Reuse stays, as the
  network-free re-run path.
- **Contract v2 is additive, on the existing endpoint** `POST
  /v0/orgs/{slug}/patches/package` (and its anonymous twin `POST
  /patch/package`). It adds per-uuid `refused`, `format`, `generation`,
  `retryAfterSeconds`, pypi wheel variants, and a detached signed
  statement (DSSE over JCS). Offline use gets a content-addressed user
  cache and a signed export bundle. v1 stays schema-compatible: the only
  changes are `yarn-berry-zip.url` becoming null and an additive
  `yarnBerry10c0` on the tarball integrity.
- **Sequencing respects WS5.** Everything before step 24 is additive and
  flag-gated. Flipping the default (step 24) and deleting the builders
  (Phase 4; about 2,050 CLI src LOC and about 1,260 test LOC) both need
  the owner to reverse the WS5 caveat after #283 merges; step 24 also
  needs 30 days of telemetry. CI minutes saved: about 0. This is a
  correctness and maintenance change, not a CI lever. The CI levers are
  F51 (≈280 job-min), F41, F52, F53 and F55 (see v5-waste-review.md
  Top-10); F78, which contains F63, is a transient saving during the v5
  draft train.

## Current state

### Who builds what

LOC counts treat `#[cfg(test)] mod` as the boundary between src and test.
"Byte-identical" means the CLI's local build equals the server artifact.

| Flavor (all PM versions stay) | Server artifact (depscan:workspaces/patches/src/repack) | Server src/test LOC | CLI local build | CLI build src/test LOC | Lock pin (vendored) | Byte-identical? |
|---|---|---|---|---|---|---|
| npm, pnpm 1–10 incl. legacy, bun.lock/bun.lockb | tgz, `repackers/npm.ts` (upstream order, mtime 0, zlib default; depscan:workspaces/patches-shared/src/archive/repack-utils.ts:597-660) | 557 / 467 (npm incl. berry) | `npm_pack.rs:73-177` (sorted, mtime 499162500, flate2 level 6) plus `npm_common.rs:248-396` stage branch | 177 / 247 plus about 149 | sha512 SRI | **No** |
| yarn classic | same tgz | — | same | — | sha1 `#hash` plus integrity | **No** |
| yarn berry | tgz plus `yarnBerry10c0` (`berry-cache-zip.ts`, a TS port of `berry_zip.rs`); `.berry.zip` sidecar stored and never read (F33) | 353 / 167 | `berry_zip.rs` recompute over the local tgz | 333 / 320 | `checksum 10c0/…` plus `hash=` (first 6 hex of tgz sha512, `yarn_berry_lock.rs:272-277`) | Recipe yes; input tgz differs, so **no** in practice |
| vlt | same tgz | — | `npm_dir.rs` `stage_patch_dir` local branch (about 594-730) | about 137 | none vendored (directory); hosted pins raw sha512 | n/a (extracted) |
| pypi: uv, poetry, pdm, pipenv, requirements, hatch | wheel only with `artifact_id`/`packaging=wheel` qualifier, else the sdist (`pypiPurlWantsWheel`); bz2/xz sdists refused after download (`repackers/pypi.ts:131-138`, F69) | 411 / 816 | `pypi_wheel.rs` from installed site-packages RECORD, Deflated zip | 696 / 1,288 | wheel sha256 | **No** |
| gem (Bundler, all eras) | `.gem` plus stub `.gemspec`; platform gems refused | 777 / 768 | `gem.rs` `materialise_patched_copy` (1192-1339) | 148 | none (PATH source, CHECKSUMS stripped) | n/a (extracted) |
| cargo (lock v1–v4) | `.crate` plus sparse-index line | 982 / 976 | `cargo.rs` `copy_and_patch` | 86 | none (path dep, `.cargo-checksum.json` dropped at `cargo.rs:394`) | n/a (extracted) |
| golang | module zip plus gopatch zip plus go.mod, dirhashH1; no-go.mod modules refused (depscan:…/repackers/golang.ts:109-115) | 792 / 485 | FallBack arm (`golang.rs` about 291-354) into `patch/redirect/golang_local.rs` (agent-mode code, stays) | about 64 | none (dir `replace`, no go.sum) | n/a (extracted, h1 verified) |
| composer | dist zip (STORE) | 308 / 352 | `composer_lock.rs` `copy_and_patch` | 60 | none (path dist) | n/a (extracted) |
| maven | jar (STORE) plus pom | 483 / 523 | `local_rebuild_jar`/`rebuild_jar_bytes` (Deflate, `maven_repo.rs:776-862`; the byte difference is shown by the test at :4112) | about 160 | `.sha1` sidecars | **No** (frozen) |
| nuget | nupkg (STORE, unsigned) | 167 / 187 | `nuget_feed.rs` `local_rebuild` | 130 | contentHash = b64(sha512) | untested (frozen) |

Shared machinery:
- CLI side:
  - `registry_fetch.rs`: 2,316 src and 2,914 test LOC. It holds the
    pristine ladder, the verifiers and the extractors.
  - `source.rs`: 222 / 135.
  - `reuse.rs`: 382 / 741.
  - `service_fetch.rs`: 321 / 564.
  - `prestage.rs`: service-only, despite being listed in WS5.
- Server side:
  - `upstream/*`: about 3,043 LOC including tests.
  - `patches-shared/src/archive`: 2,041 / 1,894.
  - `services/patch-package`: 3,031 / 646.
  - repack overall: 6,015 / 4,976, 133 tap tests.
- Churn:
  - The CLI builders are cold: npm_pack 4 commits, berry_zip 4,
    pypi_wheel 7.
  - The server repack is under active hardening: 31 commits, including
    #22388, #23523, #25259, #26792 and #26857.
- Bug history:
  - CLI builders: no packing-specific fix commit. The npm_pack (4),
    berry_zip (4) and pypi_wheel (7) commits are all omnibus or feature
    PRs.
  - Shared machinery: registry_fetch has 11 commits (16 with `--follow`,
    15 of them fix-matching), including #175 (bundler audit, 13 bugs),
    #241 (poetry) and #242 (pipenv). service_fetch has #249 (trust
    hardening) and #194 (cargo fail-closed); reuse.rs came from #250.
  - Server `pypi.ts`: 5 fix subjects (#21508 sdist reliability, #22724
    src-layout rescue, #22752 version spelling, #23523 artifact
    integrity, #25259 bz2/xz).

**Integrity today:**
- **Hosted mode already derives no pin.** Every value comes from the
  server (`scan/hosted.rs:1282-1318`). The CLI hashes only to verify: vlt
  preflight, wheel METADATA, and gem stale-cache warnings.
- **Vendored mode produces pins locally** whenever `auto` falls back:
  - The fallback triggers on Pending, Unavailable, Failed, layout or
    afterHash mismatch, or no client (`service_fetch.rs:170-265`).
    `IntegrityMismatch` is always a hard failure.
  - The CLI ignores the server's `yarnBerry10c0` (`api/client.rs:1278-1280`).
  - Repair on the base branch is build-only (`commands/vendor.rs:123-126`).
  - A pypi dry run always previews the local build (`pypi.rs:1807-1809`).

**Waste the two producers cause:**
- `reuse.rs:1-12` says in its own header that it exists so "a prebuilt ↔
  local source flip between two runs (a service outage, or its recovery)"
  does not rewrite the lock.
- The Auto/Service policy is hand-rolled in 7 backends (F32; 35-45
  duplicated lines each). The shared `service_archive_copy` serves only
  maven and nuget.
- Every vendored reference is one POST per uuid at quota 20 each
  (`client.rs:1429-1437`, F28).
- Qualifier-less pypi purls are a guaranteed service miss, downloaded in
  full before being rejected (F70, F71).
- The 12 `e2e_vendor_*_build.rs` capstones (15,853 LOC, about 92 tests) and
  the 58 `--vendor-source build` call sites (in 36 test files at 8ae7dc37;
  the same on v5/integration) test only the local builder.

**Unmeasured:** the real service-hit versus local-fallback rate. CLI
telemetry does not record the vendor source. `patch_vendored` is also
unclassified server-side, and its endpoint sunsets on 2026-12-31 (F22).

### WS5 caveat answer: does depscan use CLI packing code?

**No.** depscan has:
- no napi or FFI link to socket-patch-core;
- no crate dependency;
- no subprocess packing.

It imports only the `@socketsecurity/socket-patch/schema` TS types
(depscan:workspaces/lib/src/socket-patch/manifest-schema.ts:9). The CLI
binary runs in depscan only in tests and tools, plus `socket-patch apply`
in the autotester image (depscan:docker/Dockerfile.autotester-worker:19-25)
and the pipeline postinstall `pnpm dlx @socketsecurity/socket-patch@4.0.0
apply` (depscan:workspaces/pipeline/package.json:15-16). Both are
agent-mode apply, not vendoring.
`berry-cache-zip.ts` is a port of `berry_zip.rs`, not a consumer of it.
Deleting the CLI builders is therefore a CLI-only product decision.

Two couplings are still real:
1. **depscan api-v0 e2e vendor suites 89-94** run in `auto` and silently
   fall back to the local builder on a service miss. Removing the builder
   weakens them without failing them.
2. **WS1 (#280) consumes CLI helpers.** It consumes `registry_fetch` and
   `berry_zip` (origin/v5/ledger-free-hosted
   `patch/redirect/upstream/client.rs:11,204,256-257,361-369,500-504,592`,
   `upstream/vlt.rs:76`, `upstream/npm.rs:432`). Those helpers stay (see
   What must stay).

`prestage.rs` is not a local-rebuild file: it pre-extracts service
archives.

## Design

### Principles

1. **One producer per (uuid, variant).** The server's verdict decides it,
   never availability. The verdict is terminal; the ledger's recorded
   `producer` keeps it sticky across runs.
2. **The CLI computes a pin only for `producer = local`.** Otherwise the pin
   is copied from the reference and cross-checked against the verified
   bytes. The two must agree, or the result is `IntegrityMismatch`.
3. **Acquire before wiring.** Every artifact in the run is acquired and
   verified into the cache before any project file is written. Per-package
   failures leave that package's lock untouched.
4. **Trust decisions happen in one verify step.** It never falls back to
   another source on mismatch.
5. **maven and nuget keep today's artifact acquisition and wiring
   byte-for-byte:** `service_archive_copy`, the local rebuild, and
   `--vendor-source build`. They do take part in the batch reference POST
   (step 1), which is behavior-neutral. Under contract 2 the CLI maps a
   `refused` answer for a maven/nuget uuid onto the existing v1
   `build_failed`/fallback arm (or requests those uuids under contract 1),
   so `service_archive_copy` behavior is unchanged.

### When the one local build is allowed

A class may build locally only when all three of these hold:
- (a) the server's refusal is terminal for the requested artifact (for
  pypi: the uuid plus the requested filename or tags; see the TTL note
  below the table);
- (b) the correct bytes depend on the user's machine;
- (c) the CLI can build deterministically from local state.

| Class | Resolution |
|---|---|
| npm family, berry, vlt | server only; local packing deleted |
| gem (ruby platform), cargo, composer | server only; `copy_and_patch` arms deleted |
| gem platform | refused on both sides (`gem.rs:209-237`); unchanged |
| golang without go.mod | server synthesizes `module <path>` as proxy.golang.org does; lifts golang.ts:109-115 |
| pypi, upstream wheel exists (bare or sdist purl) | server builds the wheel variant the lock pins |
| pypi, no servable wheel (sdist-only, no tag match, bz2/xz-only) | `refused {code: pypi_no_servable_wheel, localBuild: allowed}` → `pypi_wheel.rs` from the installed dist |
| pypi, upstream file larger than the serve cap (torch, tensorflow, jaxlib, `nvidia-*` wheels) | `refused {code: artifact_too_large, localBuild: allowed}`, emitted before download from the size in the PyPI JSON → `pypi_wheel.rs` (no cap on the installed dist) |
| npm family, upstream tarball larger than the serve cap | `refused {code: artifact_too_large, localBuild: forbidden}`, emitted before download from the packument; an accepted regression (Open questions) |
| output exceeds the CLI's extraction caps | `refused {code: artifact_exceeds_client_caps, localBuild: forbidden}` (see Risks) |
| maven ext/classifier, all maven/nuget | frozen: current behavior, including `auto` fallback |

The serve cap is `MAX_SERVABLE_ARCHIVE_BYTES` = 100 MiB
(depscan:workspaces/patches/src/services/patch-package/build.ts:37-44), and
upstream downloads are capped at 256 MiB
(depscan:workspaces/patches-shared/src/archive/repack-utils.ts:23). Today
the output-size check runs after the build, as a deterministic
`build_failed`; without the pre-download refusal, large pypi releases
would lose their only working path.

`pypi_no_servable_wheel` is not immutable: PyPI accepts new wheels for an
existing release at any time (late cp313 or musllinux wheels are common),
and "no tag match" depends on the requester's platform. The refusal is
keyed on (uuid, requested filename or tags) and carries a TTL. Flips are
prevented by the ledger: once an artifact is recorded as
`producer = local`, later runs keep it until `--repin`.

The retained recipe is versioned as `local:pypi-wheel/1`. It pins today's
bytes: lexicographic order, RECORD last, and fixed stamps, via
`common.rs:248` Deflated.

`Cargo.lock:457-465` shows flate2 1.1.9 pulling both `miniz_oxide` and
`zlib-rs`, so a dependency bump could silently change the bytes. To guard
against that:
- a committed golden vector asserts the output bytes;
- the backend is pinned explicitly;
- any byte change bumps the recipe id.

Bytes built under an old id stay reusable. Repairing one under a new CLI
fails closed with a `--repin` remedy.

### API contract (depscan)

**Endpoints.**
- Authenticated: `POST /v0/orgs/{slug}/patches/package`
  (depscan:workspaces/api-v0/src/endpoints/orgs/patches/package.ts, quota 20
  at :293, max 500 uuids at :330). It is backed by
  depscan:workspaces/app/src/patches/patch-package-references.ts.
- Anonymous: `POST /patch/package` in
  depscan:workspaces/patches-api-proxy/src/server.ts:1003. It already
  forwards the parsed body verbatim except for forcing `freeOnly`
  (:1043-1066), and it caps bodies at 256 KiB
  (`MAX_PATCH_PROXY_BODY_BYTES`, :199).
  depscan:workspaces/purl-api-proxy/routes/patch.ts is a pass-through
  `/patch/*` alias (including `package`) with its own 1 MB cap.
- **Body size.** A 500-uuid request with `variants` must fit the 256 KiB
  cap. The CLI caps `variants` per request and chunks at fewer than 500
  uuids when variants are present.
- No new artifact routes. Bytes stay on patch.socket.dev.

**Request (v2).** Additions are marked `+`.

```
{ "uuids": ["<uuid>", …],                  // ≤ 500
  "freeOnly": false,
+ "contract": 2,
+ "variants": { "<uuid>": {
+     "pypiWheelFilename": "foo-1.2.3-cp311-cp311-manylinux_2_17_x86_64.whl",
+     "pypiUpstreamSha256": ["<hex>", …],
+     "pypiWheelTags": ["cp311-cp311-manylinux_2_17_x86_64"],
+     "generation": 1 } } }                 // optional; repair only
```

`pypiWheelFilename` is the upstream file the project's lock pins (uv, pdm
and poetry list per-file hashes). `pypiUpstreamSha256` covers locks that
pin hashes with no filenames (Pipfile.lock, `requirements --hash`): the
server maps each hash to the upstream file through the PyPI JSON it
already reads, so those flavors need no installed dist and the CLI keeps
no hash-to-URL resolver. `pypiWheelTags` is the last fallback: it comes
from the installed `*.dist-info/WHEEL` when the lock pins neither, for
example requirements without hashes. `generation` lets repair request the
generation its ledger recorded.

**Response (v2).** The endpoint returns `{ results: { <uuid>: … } }`
(depscan:workspaces/api-v0/src/endpoints/orgs/patches/package.ts:147-174,
343-372). The sketch is one value of that map; additions are marked `+`.

```
{ + "contract": 2,
    "results": { "<uuid>": {
      "status": "granted" | "reused" | "pending_build" | "build_failed"
              | "refused" (+, v2 only) | "withdrawn" | "forbidden" | "not_found",
      "url": "…" | null,                     // tarball URL; unchanged
      "purl": "…" | null,                    // unchanged
  +   "retryAfterSeconds": 20,               // pending_build only
  +   "failureCode": "UNSUPPORTED_ARCHIVE_FORMAT", // build_failed only; static
  +   "refusal": { "code": "pypi_no_servable_wheel" | "artifact_too_large"
  +                      | "artifact_exceeds_client_caps" | "gem_platform"
  +                      | "maven_classifier",
  +                "localBuild": "allowed" | "forbidden" },  // refused only
  +   "generation": 1,
      "artifacts": [{
        "kind": "tarball" | "gem-stub-gemspec",
  +     "format": "npm-tgz" | "whl" | "sdist-tgz" | "sdist-zip" | "gem"
  +             | "crate" | "go-zip" | "composer-zip" | "jar" | "nupkg",
  +     "variant": "default" | "<upstream wheel filename>",
  +     "filename": "…",
        "url": "…", "contentType": "…", "sizeBytes": 123,
  +     "recipe": "depscan-repack/npm@1",
        "integrity": { "sha512": "sha512-…", "sha256": "…", "sha1": "…",
                       "md5": "…", "dirhashH1": "h1:…", "goModH1": "h1:…",
                       "yarnBerry10c0": "10c0/…" } }],  // 10c0 now on the tarball
  +   "statement": { "payloadType": "application/vnd.in-toto+json",
  +                  "payload": "<b64 JCS statement>",
  +                  "signatures": [{ "keyid": "sp-2026-1", "sig": "<b64>" }] }
  +              | null,                     // null until backfilled
      "registryOverride": { … } } } }        // unchanged (hosted mode)
```

Schema notes: `status` and `kind` are `SEnum`s (package.ts:128-131,
148-159), so the status enum gains `refused`, emitted under contract 2
only. Every new field is a nullable `SStruct` member. PEP 658 metadata
(F60: `pypiMetadata: { url, sha256 }` per wheel artifact, so hosted scan
stops downloading whole wheels) is a later additive v2 field and is not
in this plan.

**Versioning rules:**
- **v1 stays schema-compatible.** With `contract` absent or equal to 1,
  the response is today's except that, after step 4, `yarn-berry-zip.url`
  is null (the schema already allows it, depscan:…/package.ts:124-133; no
  CLI reads it, F33), and `yarnBerry10c0` is also added to the tarball's
  integrity (additive; old hosted CLIs pick it up through
  `integrity.clone()`):
  - `kind: "tarball"` stays the authored variant, so v4 and v5.0 CLIs keep
    their `find(kind == "tarball")` (`client.rs:1279-1283`) and their
    `auto` fallback.
  - `refused` is reported as `build_failed`.
  - The `yarn-berry-zip` entry `{url: null, integrity.yarnBerry10c0}` keeps
    being emitted until v1 itself sunsets. v4/v5.0 hosted scan
    (`scan/hosted.rs:1290-1300`), `hosted_memory/redirect.rs:110-151` and
    depscan's GitHub-app hosted PR flow
    (depscan:workspaces/app/src/autopatch-pr/github-patch-pr-hosted.ts:400-426)
    read the 10c0 checksum only from that entry; without it their berry
    rewriter fails closed ("has no yarnBerry10c0",
    depscan:workspaces/app/src/patches/registry-rewrite/yarn-berry.ts:139-143).
  - `r{n}` URLs are never sent to v1 callers. For a uuid with a
    generation ≥ 2, v1 is answered with the gen-1 artifact and its hashes
    under the legacy URL. Old Rust and TS path parsers (vex discover,
    rollback, list; depscan:workspaces/lib/src/socket-patch/patch-url.ts)
    do not know the segment.
- **v2 changes:** `yarnBerry10c0` is on the tarball's integrity, and
  `yarn-berry-zip` is not emitted. `r{n}` URLs appear only in contract-2
  responses.
- **Unknown fields are ignored.** The CLI response types derive
  `Deserialize` without `deny_unknown_fields` (`api/types.rs`).
- **Negotiation.** The CLI sends the highest contract it supports. The
  server answers `min(requested, supported)` and echoes `contract` in the
  response. A breaking change needs contract 3.
- **Failure strings are static and low-cardinality**, per depscan
  AGENTS.md; per-call detail goes to `logContext`.
  - Deterministic statuses (`build_failed`, `refused`) never carry
    `retryAfterSeconds`.
  - Only `pending_build` and transient upstream failures are retryable.
- **Generations are immutable.** `generation` bumps only on an admin
  regenerate, and the old generation's bytes stay served. Each generation
  is a row in a per-generation table (step 7), so older URLs, hashes and
  statements stay resolvable.

**Signed statement (in-toto v1, JCS-canonical, DSSE-wrapped).**

```
{ "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "<filename>",
                "digest": { "sha512": "<hex>", "sha256": "<hex>" } }],
  "predicateType": "https://socket.dev/patch-artifact/v1",
  "predicate": {
    "uuid": "…", "purl": "…", "ecosystem": "npm", "variant": "default",
    "generation": 1, "recipe": "depscan-repack/npm@1",
    "upstream": { "filename": "…", "url": "…", "sha512": "sha512-…" },
    "patchRecordDigest": "sha256:<hex of JCS(record projection)>",
    "pins": { "sri": "sha512-…", "sha1": "…", "sha256": "…",
              "yarnBerry10c0": "10c0/…", "dirhashH1": "h1:…",
              "goModH1": "h1:…", "cargoCksum": "…",
              "gemChecksumSha256": "…" } } }
```

- **DSSE binding.** `payloadType` is `application/vnd.in-toto+json`, as the
  in-toto Statement v1 binding requires, so standard in-toto, sigstore
  and cosign tooling can verify it. The socket-specific version lives in
  `predicateType` (`https://socket.dev/patch-artifact/v1`).
- **`patchRecordDigest`.** The CLI's `.socket/manifest.json` record and
  the server's DB row carry different field sets, so the digest is over
  an explicit minimal projection:
  `{uuid, purl, files: [{path, beforeHash, afterHash}] sorted by path}`.
  The predicate schema specifies it, and a shared golden vector is used by
  both the Rust verifier and the TS signer.
- **`upstream.sha512`** is the registry digest where one exists. Where
  none does (GitHub-backed composer dists, legacy npm packages), it is the
  server's own hash of the downloaded bytes, and beforeSha is the only
  upstream anchor.

**Signing:**
- The signer runs at build time with a GCP KMS asymmetric key (Ed25519 or
  P-256, non-exportable). It is *detached*: it never touches archive
  bytes.
- The in-format seam `depscan:workspaces/patches/src/repack/sign.ts`
  (`defaultSign` always returns null) is deleted, as F38 recommends.
  Statements are a separate build step after the write-once store.
- **Backfill.** Existing built rows get statements from their persisted
  digests and columns, with no rebuild. An unsigned legacy row is never
  made unvendorable.
- **Revocation.** `GET https://patch.socket.dev/.well-known/socket-patch-keys.json`
  serves the key list plus a revocation list. The list is signed by an
  offline root key whose public half is embedded in the CLI.
- **The CLI never trusts a key fetched at runtime.** Signing keys are
  embedded (current plus next); the fetched document only *revokes*
  embedded keys.

### CLI flow (vendor, scan --mode vendored, get vendored, repair, WS2 eject)

The flow is one shared `acquire_service_artifact` inside #283's
`VendoredBackend`, replacing the 7 hand-rolled policies (F32). maven and
nuget stay on `service_archive_copy`.

1. **Plan.**
   - Collect records from one of three places:
     - `.socket/manifest.json`;
     - hosted pins (WS2 eject);
     - a bundle.
   - Compute selection keys: for pypi, the lock's wheel filename, else
     the lock's pinned sha256 hashes (Pipfile.lock, `requirements
     --hash`), else the installed `WHEEL` tags. No other ecosystem needs a
     key or an installed copy.
2. **Reuse, with no network.** Use `reuse::verify_committed_artifact`
   (`reuse.rs:212-318`) or `reusable_committed_dir` against the ledger.
   An in-sync artifact is finished here. This is a hard contract:
   `vendor_rerun_no_network_e2e.rs` stays.
3. **Resolve.** Send one batch POST per 500 uuids (fewer when `variants`
   would push the body past the proxy's 256 KiB cap) with `contract: 2`
   plus `variants` (F28). `hosted.rs:1244` gets the same 500-chunking, because
   it gets a 400 above 500 today.
4. **Decide.** The action depends on the reference answer and on the
   producer recorded in the ledger:

| Reference answer | Ledger producer | Action |
|---|---|---|
| granted / reused | any or none | acquire → verify → wire; same sha as the ledger means no lock change |
| granted, same uuid, new `generation` | service | `vendor_artifact_regenerated`: keep the committed bytes; `--repin` adopts the new ones |
| pending_build | – | poll with `retryAfterSeconds` plus jitter up to `--vendor-wait` (default 120 s interactive, 0 in CI), then `vendor_artifact_pending` (retryable) |
| refused, localBuild=allowed | – or local | local `pypi_wheel` from the installed dist; if not installed: "install, then re-run" |
| refused, localBuild=forbidden | – | `vendor_unsupported_variant` (hard) |
| build_failed | – | `vendor_prebuilt_unavailable` (hard, no local build) |
| granted, but the bytes fail layout or afterHash membership (server defect, #23144) | any | `vendor_prebuilt_defective` (hard, no local build); server-side metric |
| granted gem, stub gemspec missing or invalid (#221; pre-stub-rollout rows) | any | `vendor_prebuilt_stub_missing` / `vendor_prebuilt_stub_invalid` (hard); a server backfill (regenerate) of pre-stub rows is a prerequisite for the gem flip. Native-extension gems get no stub by design (gem.rs:922-926), so the server should answer them with a `refused` code instead |
| granted npm, berry lock, `yarnBerry10c0` null (the error-isolated berry rebuild failed, depscan build.ts:364-382) | any | `vendor_berry_checksum_unavailable` (hard) |
| network error, 5xx, timeout | local | local pypi rebuild (ledger stickiness: `producer = local` is kept); a result whose sha256 differs from the ledger fails closed with a `--repin` remedy |
| network error, 5xx, timeout | service, legacy-local, or none | `vendor_service_unavailable` (retryable); the lock is untouched |
| withdrawn / not_found | any | refuse to wire; report existing wiring for `vendor --revert` |
| any digest or signature mismatch | any | `IntegrityMismatch`, hard; never retried from another source |

5. **Acquire** from the first source that has the bytes:
   - (a) `--bundle <dir|tar>` (repeatable) or `SOCKET_PATCH_BUNDLE`;
   - (b) the user cache `$XDG_CACHE_HOME/socket-patch/artifacts/sha512/<h2>/<hex>`,
     with the reference and statement indexed under
     `index/<uuid>/<generation>/<variant>.json`;
   - (c) the service GET through the `vendor_prefetch` download window
     (F28), capped by `MAX_VENDOR_PACKAGE_BYTES`.

   `--offline` stops after (b).
6. **Verify**, in this order:
   - (i) the statement signature, if present; it is required for bundle
     sources and, after backfill, everywhere (see Rollout);
   - (ii) size, sha512 and sha256 against the reference *and* the
     statement subject (`fetch_verified_archive`,
     `service_fetch.rs:89-142`);
   - (iii) canonical decode and afterHash membership (#249):
     `tgz_bytes_match_after_hashes` (`npm_common.rs:658`), or
     `zip_bytes_match_after_hashes` / `copy_matches_after_hashes`
     (`common.rs`);
   - (iv) go h1 via `verify_go_h1` (`registry_fetch.rs:1507`);
   - (v) `patchRecordDigest` equals the digest of the projection of the
     record being wired;
   - (vi) berry only: `berry_cache_checksum_10c0` recomputed over the
     verified tgz must equal the server value. This turns the Rust/TS
     twin (F35) into a runtime tripwire.
7. **Gate.**
   - By default, packages that failed are listed with their class, and
     packages that verified are wired.
   - `--require-all` refuses to wire anything if any required artifact is
     missing. It is the plan-then-commit mode for CI that wants
     all-or-nothing.
   - Exit codes separate retryable (pending or unavailable) from hard
     failures.
8. **Wire.**
   - Directory flavors are extracted through the existing validators and
     caps (`prestage.rs` pool, `registry_fetch.rs` `extract_*`/`validate_*`).
   - Lock writers are unchanged; WS3 owns them.
   - Pins come from the reference or statement. Local compute is allowed
     only for `producer = local`.
9. **Ledger.**
   - The `state.json` entry gains
     `{producer, recipe, generation, statementDigest}`.
   - Missing fields on old entries read as `legacy-local` or
     `legacy-service`, inferred from the existing source code.
   - The statement is written as `<artifact>.statement.json` next to the
     vendored artifact, so `vex` can attest offline.

**Dry run.** A dry run calls the reference API only, with no GET, and
prints the real pins. It previews a local build only for
`refused/localBuild=allowed`. This fixes `pypi.rs:1807-1809` and
`npm_common.rs` "a dry run previews the local build".

**Repair (#283).** Repair re-acquires through (a)→(b)→(c) from the ledger's
producer:
- A missing `legacy-local` artifact is re-pinned to service bytes. Only
  the integrity and URL slots are spliced (the #269 vlt precedent), and
  repair emits `vendor_repinned_to_service`. #283's fail-closed ledger
  check (`vendored_backend/repair.rs:1-24` on origin/v5/vendor-backend)
  gains this arm instead of refusing.
- Nothing else re-pins silently. `vendor --repin` does it on purpose.

**Flags:**
- `--vendor-source` stays parseable in v5, because depscan
  `99_socket-patch-cargo-modes.js:205,552` passes it.
  - `auto` (the default) follows the table above.
  - `service` is strict: no local bytes ever, so it also refuses
    `localBuild=allowed` and the local-producer outage row.
  - `build` stays valid only for maven and nuget. Anywhere else it exits 2
    with `vendor_source_build_removed` after deletion.
- New flags: `--bundle`, `--export-bundle`, `--prefetch` (fill the cache,
  no wiring), `--vendor-wait`, `--require-all`, `--repin`.
- WS8 hides the rarely used ones from `-h`.

### Per-format integrity after the change

| Flavor | Bytes on disk | CLI verifies before write | Lock pin | Pin source |
|---|---|---|---|---|
| npm, pnpm 1–10, bun.lock/bun.lockb | served tgz verbatim | sha512 + sha256 vs reference and statement; tgz afterHash | sha512 SRI | reference; `PackedTarball::from_bytes` (`npm_pack.rs:47-60`) must agree; `bun_lock.rs:403` rehash stays verify-only |
| yarn classic | same | same | sha1 `#hash` plus integrity | reference sha1, cross-checked |
| yarn berry | same | same plus the 10c0 tripwire | `10c0/…` plus `hash=` | reference `yarnBerry10c0`; hash6 sliced from the verified sha512 |
| vlt (vendored) | tgz extracted to dir (`npm_dir` `try_service_dir`, 890-970) | tgz digests plus tree afterHash | none | — |
| pypi (service) | served wheel verbatim | sha256 + sha512; zip afterHash | wheel sha256 | reference |
| pypi (local class) | `local:pypi-wheel/1` build | afterHash of staged tree | wheel sha256 | local; ledger `producer = local` |
| gem | `.gem` → data.tar.gz dir plus served stub gemspec | digests; gem data validators; stub validity | none | — |
| cargo | `.crate` extracted; `.cargo-checksum.json` dropped; `cargo_tag` | digests | none | — |
| golang | module zip extracted; dir `replace` | digests plus `verify_go_h1` against dirhashH1 | none (no go.sum) | — |
| composer | dist zip extracted; path dist | digests (no upstream digest exists; beforeSha anchors server-side) | none | — |
| maven, nuget | unchanged | unchanged | unchanged | unchanged |

## Offline / airgap

- **A committed `.socket/vendor/` is the offline store.** Installs never
  need Socket, and re-runs and repair of in-sync artifacts make no network
  calls. Both are unchanged.
- **Cache.** The user cache is immutable and sha512-keyed, so CI can share
  it across projects (actions/cache or an equivalent).
- **First vendoring or repair on an air-gapped machine uses a bundle:**
  - On a connected machine, `socket-patch vendor --export-bundle <dir>`
    reads only the manifest and lockfiles and writes nothing into the
    project. All pypi variants are included by default, so the bundle does
    not depend on the target platform.
  - On the air-gapped machine: `vendor --offline --bundle <dir>`.
  - The layout doubles as a mirror an operator can host (internal HTTP,
    Artifactory generic):

    ```
    <dir>/bundle.json                  {schema:1, createdAt, apiBase, org, cliVersion, keysetVersion}
    <dir>/index/<uuid>.json            {record, reference (contract-2 entry), statement}
    <dir>/cas/sha512/<h[0:2]>/<hex>    artifact bytes
    <dir>/keys.json                    signed revocation list at export time
    ```
  - Records are carried too, so WS2 eject works offline.
  - Bundles carry no maven/nuget artifacts. Those frozen ecosystems keep
    today's `--offline --vendor-source build` path.
  - Bundle entries **must** carry a valid statement. The statement binds
    the record digest and the artifact digests, so the carrier is
    untrusted.
- **What is lost.** A new, non-pypi patch cannot be vendored with no
  network, no cache and no bundle. Today that case builds locally
  (`--offline --vendor-source build`). The pypi local class and
  local-producer artifacts still work offline. This is an explicit owner
  decision (Open questions).

## Outage behavior & idempotence

| Situation | Result |
|---|---|
| Service down; committed artifacts in sync | success, no network (reuse); unchanged |
| Service down; artifact in cache or bundle | success, fully verified |
| Service down; nothing local; producer service, legacy or none | per-package `vendor_service_unavailable` (retryable); lock untouched; remedy: retry, or `--export-bundle` elsewhere plus `--bundle` |
| Service down; producer local (pypi class) | local rebuild, same recipe id. Byte identity holds only on the same machine with the same installed dist: an sdist-only C extension compiles differently per machine. A rebuild whose sha256 differs from the ledger fails closed with a `--repin` remedy |
| `pending_build` | `--vendor-wait` polling, then retryable exit |
| Recovery storm | `retryAfterSeconds` plus client jitter plus the per-uuid breaker kept on the download step (F28) |
| Admin regenerate | new generation row, new object key; old generations stay resolvable through the per-generation table; CLI keeps committed bytes (`vendor_artifact_regenerated`), and repair of a missing artifact requests the ledger's generation |
| CDN re-encodes a body | hard `IntegrityMismatch`; `no-transform` stays on every artifact byte response (depscan:…/patch-serving/archive-response-headers.ts:11) |

**Relation to #250 and `reuse.rs`:**
- #250 (e0246295) added reuse because the auto fallback flipped between two
  producers across an outage and its recovery.
- With R1 (the verdict decides the producer) and R3 (an outage is not a
  refusal), no run can pick a different producer than the ledger
  recorded. Service bytes are write-once per (uuid, generation), so a
  re-acquire returns identical bytes.
- `reuse.rs` stays for network-free re-runs, and its header is rewritten.
  `select_prior_entry` loses its flip-hiding reason and can shrink after
  deletion; that saving is unmeasured and not counted.
- A new invariant test runs every fixture capstone twice, the second time
  with reuse disabled, and asserts byte-identical locks and artifacts.

**Server side:**
- **Write-once stays** (`STORED_OBJECT_CONFLICT`,
  depscan:workspaces/patches/src/services/patch-package/build.ts:425-470).
- **Regenerate never deletes in place.** All three regenerate/reset paths
  fold into `resetOne()` (F39) and mint generation N+1 under a new object
  key. `deleteGcsObject` is retired for referenced keys.
- **Hosted URLs become immutable too.** Hosted installer URLs gain an
  optional `r{n}` segment, emitted only for generation ≥ 2 and only in
  contract-2 responses. A URL without it means generation 1 forever, and
  v1 callers keep getting the gen-1 artifact under that URL. The Rust path
  parser learns it in the same step, with a shared redirect golden that
  includes an `r{n}` case in the TS_LAGGING/RUST_IMPLEMENTED lists.
- **Per-generation storage.** `published_patches` is one row per patch
  with a single `package_object_key`, `package_integrity` and
  `package_size_bytes`, and the serve route resolves URL to object key
  through that row
  (depscan:workspaces/patches/src/services/patch-serving/serve-route.ts:125-140).
  A scalar generation column cannot keep old generations served. A table
  `published_patch_generations(uuid, variant, generation, object_key,
  digests, size, statement)` holds one row per generation; serve-decision
  resolves (uuid, generation parsed from `r{n}`, defaulting to 1) through
  it.

## Integrity, provenance & signing

Chain of trust:
1. **Upstream digest verified server-side**
   (depscan:workspaces/patches/src/repack/upstream/*: packument
   integrity, PyPI sha256, crates cksum, sumdb h1, maven sha1) and
   persisted as `upstreamIntegrity`. Coverage is not universal:
   - composer: sha1 when Packagist supplies `dist.shasum`, else beforeSha
     only (GitHub-backed dists; upstream/composer.ts:65-71);
   - npm: packument integrity or shasum, else beforeSha only (legacy
     packages; upstream/npm.ts:125-130).
2. **Each patched file** is anchored by beforeSha in
   `substitutePatchedFiles`.
3. **The repack is built once**, written write-once and read back. The
   publish-time dry run builds the same bytes only on the same host and
   zlib build. F61: have the converter adopt that build instead of
   rebuilding (optional).
4. **The detached statement** binds uuid → purl → upstream digest → record
   digest → artifact digests → pins, signed through KMS.
5. **The CLI verifies** the signature, then the digests, then the
   afterHash, then the berry tripwire (verify step 6). Only
   `producer = local` pins are computed locally.

Ride-along fixes:
- **Wheel signatures.** Strip `RECORD.jws` and `RECORD.p7s` in
  `regenerateWheelRecord`
  (depscan:workspaces/patches-shared/src/archive/repack-utils.ts:~1330,
  F38). With a single producer, the served wheel must match what
  `pypi_wheel.rs:570-585` already does. This is a behavior change and
  bumps the converter version. It applies to new builds only; existing
  bytes are immutable.
- **Dead signature columns.** `package_signature` and
  `package_signature_kind` are always null and read only by the admin
  package-job API
  (depscan:workspaces/next-app/src/pages/api/admin/patches/package-job.ts:88-89,114).
  They are also written by patch-sync (patch-sync/import.ts:174-175) and
  queue.ts (:410-411, :733-734). Step 13b stops the writes and drops them
  with a safe migration; statements live in the per-generation table.
- **Maven.** The `META-INF/*.SF` gap is recorded only (maven is frozen).

**Provenance on disk.** The ledger holds
`producer/recipe/generation/statementDigest`, and
`<artifact>.statement.json` sits next to each vendored artifact.

**Audit.** A depscan CI golden re-runs the repackers offline over the
shared fixture corpus, split by format. The gzip bytes are
zlib-build-sensitive and differ between a dev machine and the CI runner
(depscan:workspaces/patches-shared/src/archive/repack-utils.ts:632-640),
so:
- gzip-bearing artifacts (npm tgz, pypi sdist tar.gz, the `.gem`'s
  data.tar.gz, cargo `.crate`): the golden pins the sha256 of the
  decompressed tar stream plus per-member afterHashes, and treats the
  committed bundle bytes as opaque signed inputs, not re-derived outputs;
- STORE-zip formats (wheel, go module zip, composer zip, jar, nupkg) and
  `yarnBerry10c0`: the golden asserts byte-exact digest reproduction.

## Cache/CDN/storage cost

**Build:**
- The default artifact costs nothing new; the converter already builds
  every published row after publish.
- Added: pypi wheel variants, built lazily, keyed by
  `(uuid, upstream filename)` that a client actually requested. Cost is
  bounded by real demand, not by wheel-matrix width.
- Added: go no-go.mod builds, which are rare.
- Removed: the `.berry.zip` store and read-back per npm patch. The zip
  rebuild stays, because it is the 10c0 source: the `berryChecksum10c0`
  and `berryZip` locals (build.ts:349-350), the `rebuildBerryCacheZip`
  call and the sha512 at :373-387 are kept.

**Storage:**
- One fewer GCS object per npm patch (F33). Berry zips use STORE, so each
  is likely larger than its tgz (inference, unmeasured).
- Added: the variant wheels.
- A regenerate adds a generation instead of replacing one. Old
  generations are kept, because committed pins may reference them and the
  server cannot know.

**Origin I/O.** Send crc32c/md5 on the PUT and read back only on a 412
(F34; md5 is already computed at build.ts:315/532). This removes 1–4 full
GETs per build.

**Egress:**
- Vendoring downloads once per (project, patch), then reuses git, the
  cache or a bundle.
- The CLI's eager pristine fetches from public registries disappear (F80).
- The wasted sdist downloads disappear, up to the 256 MiB cap each
  (F70, F71).
- Quota drops from N×20 to ceil(N/500)×20 per run (F28).

**CDN:**
- Keep `public, max-age=3600, no-transform` on artifact bytes.
- The per-org token in the path fragments edge keys, and revocation must
  bite, so no `immutable`.
- Revisit `immutable` for generation-keyed URLs only after infra confirms
  patch.socket.dev's edge-cache and auth behavior. Metadata and
  go-import responses keep their current headers (F37 verification: that is
  intentional).

**Sizing.** Before step 11 (pypi variant queue), a read-only query
through the Grafana skill: count built pypi rows by selected artifact
kind, plus wheels per release from the PyPI JSON. This query is an
explicit gate on step 11.

**Unmeasured:** variant-wheel storage, the berry.zip bytes removed, and
the egress delta. The step 5 dashboards and the pre-step-11 sizing query
produce them, and the owner reviews them before enabling
`patchPypiVariants`.

## What gets deleted

Deletion happens after the gate, at Phase 4. The numbers are measured by
line span at 8ae7dc37. Rows marked ~ are re-measured after #283 and #280
land, because WS5 rewrites vendor.rs by ±318 lines.

| Item | Files | src LOC | test LOC |
|---|---|---:|---:|
| npm_pack `pack_deterministic`, `pack_to_bytes`, `collect_regular_files`, `NPM_PACK_MTIME` (keep `from_bytes`) | `vendor/npm_pack.rs:73-177` | 105 | ~210 of 247 |
| npm_common local stage-and-pack branch | `vendor/npm_common.rs:248-396` | ~149 | in-file tests edited |
| vlt local stage branch in `stage_patch_dir` | `vendor/npm_dir.rs:~594-730` | ~137 | edited |
| registry_fetch pristine ladder: `FetchedPackage`, `fetch_and_stage`, `fetch_{npm,npm_inner,cargo,golang,composer,gem,pypi}`, `resolve_pypi_url_by_hash`, `crates_registry_base`, `stage_local_artifact(_dir)`, `fetch_npm_unverified` (**not** the WS1 keep-list) | `vendor/registry_fetch.rs` | ~700 | ~650 |
| `PackageSource` Pending/Deferred (keep the `path()` naming query) | `vendor/source.rs` | ~200 of 222 | 135 |
| cargo `copy_and_patch` | `vendor/cargo.rs` | 86 | edited |
| composer `copy_and_patch` | `vendor/composer_lock.rs` | 60 | edited |
| gem `materialise_patched_copy` | `vendor/gem.rs:1192-1339` | 148 | edited |
| golang vendored FallBack arm (`golang_local.rs` stays) | `vendor/golang.rs:~291-354` | ~64 | edited |
| Auto/Service policy arms in 7 backends, collapsed into one mapping (F32; 35-45 lines each) | 7 backends | ~220 net | edited |
| vendor.rs pristine ladder: `fetch_pristine_package`, `missing_local_rung`, `MissingRung::Fetch` | `commands/vendor.rs` | ~147 | — |
| `VendorSource::Build` outside maven/nuget, args plumbing | `vendor/mod.rs`, `args.rs` | ~30 | — |
| `berry_zip_url` plumbing (F33; re-measure on #280, which adds another `berry_zip_url: None` site at upstream/bun_lockb.rs:154) | redirect/hosted | ~3 | 41 |
| Pristine fetch-order e2e | `tests/vendor/vendor_pristine_fetch_order_e2e.rs` | — | 228 |
| **Total (CLI)** | | **~2,050** | **~1,260** |

Rewritten, not deleted or counted:
- the 12 capstones (15,853 LOC), which move onto fixture bundles;
- the 58 `--vendor-source build` call sites (8ae7dc37), which become
  `auto` against bundles (maven and nuget keep `build`);
- the fallback assertions in the in-process and covgap tests;
- `yarn_layering_tests.rs:114`;
- the pypi `in_sync_local_rebuild` tests.

CLI additions (estimated):
- src, about 900: the acquire mapping, the cache, bundle import and
  export, statement verification with the embedded keyset, ledger fields,
  and the decision table.
- tests, about 900.
- Net src change: about −1,150.

**CI.** No job is deleted, and about 0 job-minutes are saved per run.
- These keep running because they test wiring across every PM version,
  which the owner keeps:
  - the 58 vendored e2e legs (about 177 job-min; the 5 maven legs stay on
    `build`, and the other 53 switch to fixture bundles);
  - cargo-vex-matrix (18 legs);
  - docker vendor jobs.
- The non-maven legs switch from local builds to fixture bundles at
  similar cost.
- One test binary goes (`vendor_pristine_fetch_order_e2e`).
- depscan adds a fixture-freshness golden of about 1–2 min.
- The CI levers are F51 (≈280 job-min), F41, F52, F53 and F55 (see
  v5-waste-review.md Top-10); F78, which contains F63, is a transient
  saving during the v5 draft train. None is credited here.

depscan changes:

| Change | LOC | Source |
|---|---:|---|
| Deleted: `.berry.zip` store/read-back/serve/reset branches (build.ts:351-353 object key/size/integrity locals, :473-482 `storeSidecarObject`; serve-decision.ts:45-50, :145-157; serve-route.ts:136-137). The `rebuildBerryCacheZip` call and the sha512 at build.ts:373-387 stay | ~150 | F33 |
| Deleted: dead `sign.ts` seam plus threads (convert-patch.ts:220, run-repack-cli.ts:371) | ~60 | F38 |
| Deleted (co-landing in step 9): serve-route stream-pump duplication; admin reset paths onto `resetOne` | ~100 + ~45 | F37, F39 |
| Added (estimate): contract v2 ~150; verdict columns, per-generation table plus batched backfill and patch-sync ~220; generation-in-key, serve-decision through the generation table, and `r{n}` ~170; pypi variant queue ~450; go no-go.mod ~80; statements plus keys route plus backfill ~350; fixture exporter plus golden ~200; metrics ~60 | ~1,680 | — |

### What must stay

- **Verifiers:**
  - `artifact_matches_integrity`, `verify_integrity` and `verify_sri`
    (`registry_fetch.rs:1931-2058`);
  - `go_h1_of_zip` and `verify_go_h1` (1342-1524).
    `verify_sri` and `go_h1_of_zip` are private at 8ae7dc37; WS1 makes
    them `pub(crate)` and calls them (origin/v5/ledger-free-hosted
    `upstream/client.rs:257,367`);
  - `PackedTarball::from_bytes`;
  - `zip_bytes_match_after_hashes` and `copy_matches_after_hashes`
    (`common.rs`);
  - `tgz_bytes_match_after_hashes`.
- **`berry_zip.rs` (333 / 320), permanently.** It is a verifier
  (`registry_fetch.rs:1943`, `artifact_matches_integrity`; the :1719 call
  sits inside the pristine npm fetch that step 27 deletes) and the runtime
  10c0 tripwire, and WS1 calls `berry_cache_checksum_10c0`
  (`upstream/npm.rs:432`).
- **The WS1 keep-list in `registry_fetch.rs`:**
  - `download`, `MAX_DOWNLOAD_BYTES`, `DEFAULT_NPM_REGISTRY` (WS1
    `upstream/npm.rs:239`);
  - `build_registry_client`, `RegistryClient`, `npm_registry_base`,
    `npm_tarball_url`, `pypi_json_api_base`;
  - `goproxy_base`, `go_match_prefix_patterns` and `go_glob_match`.

  WS1 imports all of them on origin/v5/ledger-free-hosted. Ownership
  moves with F16's shared registry module if that lands.
- **Acquisition and verification plumbing:** all `extract_*`/`validate_*`
  functions and the caps; `service_fetch.rs`; `prestage.rs`;
  `reuse.rs` (`verify_committed_artifact`); `vendor_prefetch.rs` as a
  download-only window.
- **`pypi_wheel.rs` (696 / 1,288).** It is the one local class.
- **`golang_local.rs`.** It is agent-mode redirect (`apply.rs:14`), not
  vendoring.
- **Everything maven/nuget:** `local_rebuild_jar`, the nuget
  `local_rebuild`, `common.rs` `rebuild_zip` and the memory repack (about
  150 src), `service_archive_copy`, and their legs.
- **depscan:** `berry-cache-zip.ts` and its test (the 10c0 source), and
  the zip rebuild in build.ts.

## Migration plan

Prerequisites:
- **Phase 3 step 24 and Phase 4 need the owner's reversal.** After #283
  (WS5) merges, the owner reverses the WS5 caveat for non-maven/nuget
  ecosystems, with the Phase 0 data in hand. Step 24 removes the local
  rebuild from the default path, so it cannot land while WS5 keeps it.
- **depscan gitlink bumps** follow F79's three steps:
  1. release tip;
  2. v5/integration (#279+#281+#283), with 89-94 required not to skip;
  3. past #280, together with the GitHub-app ledger change.

  This plan's bumps come after step 3, and each one is pre-flighted with
  the `socket_patch_ref` workflow input.

Flags:
- depscan (feature_flags table): `patchPackageContractV2`,
  `patchPypiVariants`, `patchArtifactStatements`,
  `patchGenerationKeys`.
- CLI: `SOCKET_VENDOR_POLICY=legacy|server-primary` and
  `SOCKET_PATCH_REQUIRE_STATEMENT`.

Server steps always deploy before the CLI step that needs them.

| # | Repo | Scope (one PR) | Gate | Rollback | Coordinates with |
|---|---|---|---|---|---|
| **Phase 0: independent wins and measurement (no policy change)** | | | | | |
| 1 | CLI | Batch reference resolution, chunked at 500 (F28); chunk `hosted.rs:1244`. maven/nuget uuids take part in the batch POST (behavior-neutral; their acquisition and wiring are unchanged) | in_process_vendor, vendor_prefetch, hosted e2e green | revert | WS4 #282 (hosted engine moves; land on whichever is first, port the other) |
| 2 | CLI | Single `acquire_service_artifact` in `VendoredBackend` (F32); warning codes kept as parameters | all vendored e2e legs byte-identical output | revert | after #283 merges |
| 3 | CLI | Drop `berry_zip_url` (F33); decide `.whl` before download (F70/F71) | unit plus pypi e2e | revert | WS3 #281 touches the same files |
| 4 | depscan | Stop storing/serving `.berry.zip` after a log check for GETs (F33), keeping the v1 `yarn-berry-zip` entry with `url: null` and adding `yarnBerry10c0` to the tarball integrity; update the v1 response snapshot; RECORD.jws/.p7s strip (F38); upload checksums (F34) | patch-package tests, installer e2e; Grafana check of `.berry.zip` requests | revert; zip columns kept until a later drop | — |
| 5 | depscan | `patch_package_reference_status_total{ecosystem,status}`, `package_status` gauges, gate counters for the future hard codes (defective afterHash/layout, missing or invalid gem stub, null berry 10c0, over-cap outputs), `/patches/package` SLO alert in workspaces/grafana-dashboards; classify `patch_vendored` (F22) | dashboards render | revert | F22 sunset 2026-12-31 |
| 6 | CLI | `patch_vendored` carries `source=reuse|cache|bundle|service|local` plus a static reason | telemetry e2e | revert | WS8 (no user-visible change) |
| **Phase 1: server contract v2 (additive)** | | | | | |
| 7 | depscan | Nullable column `package_refusal_code` (plain ADD COLUMN); table `published_patch_generations(uuid, variant, generation, object_key, digests, size, statement)` with CONCURRENTLY indexes; batched background backfill (one generation-1 row per built patch, refusal codes from build state); patch-sync import/export of the new column and table; regenerate DB types | migration on a staging copy; no long locks | columns unused, harmless | — |
| 8 | depscan | Contract v2 in patch-package-references.ts and package.ts; `refused` (SEnum, v2 only), `format`, `variant`, `generation`, `recipe`, `retryAfterSeconds`; `variants.pypiUpstreamSha256` and per-uuid `generation`; static refusals `artifact_too_large` (before download, from the upstream size) and `artifact_exceeds_client_caps` against a caps fixture shared with the CLI; github-patch-pr-hosted.ts reads 10c0 from the tarball integrity | v1 response snapshot unchanged relative to post-step-4 master; flag `patchPackageContractV2` | flag off | — |
| 9 | depscan | Generation-in-key; serve-decision resolves (uuid, generation from `r{n}`, default 1) through `published_patch_generations`; admin routes onto `resetOne` (F39); serve-route onto `serveStoredArtifact` (F37); `r{n}` URL segment, emitted in contract-2 responses only (v1 keeps gen 1 under the legacy URL), plus the lib patch-url.ts grammar | serve integration tests; regenerate-immutability test (gen-1 URL and hashes still served after gen 2); flag `patchGenerationKeys` | flag off (gen 1 only) | CLI step 10 must parse `r{n}` before any gen ≥ 2 is minted |
| 10 | CLI | Path parser accepts `r{n}`; shared redirect golden with an `r{n}` case in TS_LAGGING/RUST_IMPLEMENTED | redirect goldens (shared with depscan golden.test.ts) | revert | WS3 #281 goldens |
| 11 | depscan | pypi variant queue `published_patch_variants` (index CONCURRENTLY; claim with `UPDATE … RETURNING` plus `FOR UPDATE SKIP LOCKED`); per-variant static failure codes; `refused pypi_no_servable_wheel` keyed on (uuid, requested filename/tags) with a TTL; `refused artifact_too_large` (localBuild allowed) | pre-step-11 sizing query reviewed; real-Postgres integration harness; installer e2e for uv/pip/poetry | flag `patchPypiVariants` off | — |
| 12 | depscan | go no-go.mod synthesis matching proxy.golang.org bytes; bz2/xz sdists rejected before download (F69) | golang repack tests; hosted go e2e | revert | — |
| 13 | depscan | Statement signer (KMS) post-store, `payloadType` `application/vnd.in-toto+json`, `patchRecordDigest` over the minimal record projection with a golden vector shared with the Rust verifier; backfill statements for built rows from persisted digests; `.well-known/socket-patch-keys.json`; delete the `sign.ts` seam | real file-backed test key (a KMS double needs explicit approval); flag `patchArtifactStatements` | flag off (`statement: null`) | — |
| 13b | depscan | Stop writing `package_signature*` (queue.ts:410-411, :733-734; patch-sync/import.ts:174-175) and drop them from the admin package-job API (next-app package-job.ts:88-89,114); after one deploy, drop both columns (the drop needs no long lock); regenerate DB types | migration on a staging copy | revert before the drop | — |
| 14 | depscan | Fixture exporter: `run-repack-cli --patched-dir` over one patch per flavor → bundle layout signed with a test key, committed to socket-patch `crates/socket-patch-core/tests/fixtures/served/`; depscan golden split by format (gzip-bearing: gunzipped-tar sha256 plus per-member afterHashes, committed bytes opaque; STORE zips and 10c0: byte-exact digests); berry 10c0 vectors including sorted-vs-upstream order, CRLF, exec bits, tombstones and the Rust fail-closed cases (F35) | golden green in both repos | revert | submodule bump |
| **Phase 2: CLI consumes v2 (additive, v5.x minor)** | | | | | |
| 15 | CLI | Contract v2 client; format-before-download; `variants.pypiWheelFilename`/`pypiUpstreamSha256`/tags, chunked under the 256 KiB proxy cap; for maven/nuget uuids, v2 `refused` maps onto the existing v1 `build_failed`/fallback arm (or those uuids are requested under contract 1), so `service_archive_copy` behavior is unchanged | fixture-bundle tests; api-v0 e2e | revert | WS3 python family |
| 16 | CLI | Ledger fields `producer/recipe/generation/statementDigest`; legacy inference | ledger round-trip tests; old state.json reads | fields ignored by old code | WS6 `Ledgers` view |
| 17 | CLI | User CAS cache, `--prefetch`, `--offline` source order | offline e2e | revert | — |
| 18 | CLI | Statement verification, embedded keyset plus signed revocation list; `<artifact>.statement.json`; vex reads it | tamper tests (bad sig, revoked key, digest swap) | revert | vex (WS1 discover) |
| 19 | CLI | `--export-bundle` / `--bundle` (records included; WS2 eject offline) | export → import round trip, air-gap e2e | revert | WS2 |
| 20a/b/c | CLI | Re-point capstones to fixture bundles: npm family (npm, pnpm, yarn classic/berry, bun, vlt); pypi; gem/cargo/composer/golang | every PM-version leg green; no change to maven/nuget legs | revert per family | compatibility workflows unchanged |
| 21 | CLI | Berry tripwire; pin `local:pypi-wheel/1` deflate backend plus a golden byte vector | berry e2e matrix (7 legs); pypi goldens | revert | — |
| **Phase 3: policy flip** | | | | | |
| 22 | CLI | §Decide table behind `SOCKET_VENDOR_POLICY=server-primary`; repin arms (`--repin`, repair `vendor_repinned_to_service`); dry-run parity; `--vendor-wait`; `--require-all` | reuse-disabled idempotence invariant; decision-table unit tests; regenerate test | env back to `legacy` | #283 repair.rs |
| 23 | depscan | Submodule bump with 89-94 pinned to require no skip, a strict `service` leg added, and 99 cargo-modes dropping `build` | depscan pre-flight green | revert gitlink | F79 step order |
| 24 | CLI | Flip the default to `server-primary` once the Phase 0 gate holds (30 days, per-ecosystem `pending + build_failed + fallback` < owner threshold); CLI_CONTRACT, CHANGELOG, README "Work offline" | gate data reviewed by owner; WS5 caveat reversed by owner (Open question 1) | set default back | release notes |
| 25 | CLI | `SOCKET_PATCH_REQUIRE_STATEMENT` default on, after the step 13 backfill is complete and one release has passed | zero `statement: null` in reference metrics | default off | — |
| **Phase 4: delete (one release after 24, zero `legacy` policy use in telemetry, WS5 caveat reversed)** | | | | | |
| 26 | CLI | npm-family local packers (npm_pack pack fns, npm_common/npm_dir local branches) | all npm-family legs | git revert (irreversible for users only after release) | — |
| 27 | CLI | registry_fetch ladder minus the WS1 keep-list; `source.rs`; vendor.rs ladder; `vendor_pristine_fetch_order_e2e.rs` | WS1 hosted restore tests green | git revert | #280 merged first |
| 28 | CLI | Directory-backend local arms (cargo, composer, gem, golang FallBack); collapse FallBack variants; `--vendor-source build` exits 2 outside maven/nuget | all vendored legs; cargo-vex-matrix | git revert | WS8 exit-2 convention |
| 29 | depscan | Submodule bump; api-v0 vendor suites updated | pre-flight | revert gitlink | — |
| **Phase 5 (optional)** | | | | | |
| 30 | depscan | Sandboxed sdist→wheel for pure `py3-none-any` results (autotester container infra), shrinking the pypi local class to C-extension sdist-only releases | installer e2e | flag | owner decision |

Release boundary:
- Phases 0–3 ship in v5.x minors, except that step 24 is itself a
  behavior change (the default stops building locally on outages,
  `pending_build` and `build_failed`) and needs the same v5.x-vs-v6 owner
  call as Phase 4.
- Phase 4 changes CLI behavior (`build` refused, `--offline` narrower).
  Ship it in v5.x with one release of deprecation warnings, or in v6
  (owner call).
- Removing the `--vendor-source` flag itself is v6.

## Risks & mitigations

| Risk | Mitigation |
|---|---|
| First vendoring of a new patch depends on the server | committed artifacts, cache, bundles; retryable exits; SLO alert; `--vendor-wait` |
| Server defects ship to every vendored user (#23144 defective rebuilds; #24466 invalid gem stub, which #221 papered over with a local fallback) | CLI keeps afterHash and stub-validity checks, which fail closed with specific codes; depscan installer e2e plus the fixture golden; generation-in-key rolls fixes out without breaking pins |
| Hit rate is unknown | Phase 0 metrics; flip gated on 30 days per ecosystem |
| Locks that pin locally built bytes (F72 blocker 3) | reuse keeps them; re-pin only on `--repin` or when repair finds the artifact missing; one notice code |
| Air-gapped users lose ad-hoc local builds | bundles and mirror layout; pypi local class stays; owner decision |
| pypi variant fan-out | lazy, keyed by requested filename; sizing SQL first; berry.zip removal offsets storage |
| `r{n}` grammar change touches hosted URLs | only minted for gen ≥ 2 after the CLI parser ships (step 10 before step 9's flag), and only in contract-2 responses: v4/v5.0 CLIs on v1 keep getting gen 1 under the legacy URL; shared golden with an `r{n}` case |
| Server and CLI extraction caps differ: the server allows 200,000 entries and 256 MiB (depscan:…/repack-utils.ts:23,30); the CLI extractors allow 60,000 entries and 128 MiB per entry (`registry_fetch.rs:41-47`, used by `cargo.rs` extract_tgz, `golang.rs`, `common.rs`), and `patch/package.rs` is stricter still. With no local path, the server can serve an artifact the CLI must refuse | Phase 1 (step 8): the server emits static `artifact_exceeds_client_caps` when the output exceeds the CLI's published caps, checked against one caps fixture shared by both repos (or the CLI caps are raised to match) |
| Large upstream artifacts exceed the 100 MiB serve cap | `artifact_too_large` refusal before download; pypi falls back to the local class; npm family is an accepted regression (Open questions) |
| KMS or key custody | non-exportable KMS key; embedded current plus next key; signed revocation from an offline root; statements optional online until step 25 |
| Retained pypi recipe drifts on a dependency bump | golden byte vector, pinned backend, versioned recipe id |
| Old CLIs | v1 contract schema-compatible (only `yarn-berry-zip.url` becomes null; the entry and its 10c0 stay until v1 sunsets); `tarball` stays the authored variant; no `r{n}` URLs on v1 |
| depscan 89-94 masked a divergence via silent fallback | step 23 pins service mode and fails on skips |
| WS1 breakage from deletions | the WS1 keep-list is carved out; step 27 runs after #280 with its tests as the gate |
| Test doubles | capstones use committed bundles on the real import path, not a loopback service; depscan uses real Postgres, the file store and a file-backed key; any KMS or registry double needs explicit approval |

## Design panel (record)

Four variants were scored by three judges (integrity, ops, delivery), on a
0–10 scale:

| Variant | Integrity | Ops | Delivery | Total | Claimed CLI src/test deleted |
|---|---:|---:|---:|---:|---|
| A: server-only plus signed bundle | **8** | 6 | 6.5 | 20.5 | 3,400 / 2,580 |
| **B: server-primary, minimal fallback (winner)** | 7 | **8** | **7.5** | **22.5** | 2,200 / 1,200 |
| C: content-addressed store plus signed manifests | 7 | 6.5 | 5.5 | 19.0 | 3,090 / 2,820 |
| D: spec-first shared builder (crate plus wasm) | 6 | 6 | 5 | 17.0 | 950 / 1,200 |

**Why B won** (two of three lenses, highest total):
- It prevents flip-flop structurally, with sticky producers and "an outage
  is not a refusal", instead of hiding it.
- It keeps the one local build that has no server substitute, so there is
  no pypi airgap regression and no new sdist lock-writer arm.
- It is the smallest correct server change.
- It has an honest rollback at every phase, and it keeps `berry_zip` for
  WS1.

**Corrections applied to B:**
- The registry_fetch row now carves out the WS1 keep-list (`download`,
  `goproxy_base`, `go_match_prefix_patterns`, `MAX_DOWNLOAD_BYTES`,
  `npm_tarball_url`, …) and is re-measured down to about 700.
- The policy-duplication citation is F32 (220), not F31.
- `no-transform` applies to artifact bytes only (F37 verification).

**Grafted:**
- from A: the user CAS cache; bundle export and import carrying records;
  the SLO and gauges; acquire-before-wire with opt-in `--require-all`;
  `<artifact>.statement.json`; the fixture-bundle capstones instead of a
  loopback service double; the v1 compatibility rule; the note to
  re-measure after #283;
- from C: JCS canonicalization; the backfill of verdicts, generations and
  statements for existing rows; the mirror layout; `r{n}` immutable
  hosted URLs; upload checksums; F37 and F39 co-landing;
- from A and the integrity judge: signing promoted from optional to
  planned (step 13), with a signed revocation list;
- from D: the flate2 backend caveat applied to the retained pypi recipe,
  and a fixture golden as a reproducibility audit.

**Rejected alternatives:**
- **A as a whole.** It deletes `berry_zip` and the WS1 helpers. Old rows
  fail closed without statements, and there is no backfill. Its
  all-or-nothing default is harsh. Eager variant fan-out is costly. It
  needs a new sdist lock arm.
- **C as a whole.** It has the largest blast radius: hosted serving is
  re-routed through a new CAS. It deletes `berry_zip`, which breaks WS1.
  It accepts JWKS keys over TLS, which collapses trust back to TLS. A
  1-year digest-keyed shared cache plus `stale-if-error` weakens
  revocation. Its automatic one-time re-pin in `vendor` is a silent
  substitution path.
- **D.** Byte identity across 5 targets plus wasm is unproven, and the
  fallback profile is 3–5× larger. It adds a permanent cross-repo crate
  and wasm release chain. It has no signing, deletes the least code (about
  300 net src), and covers only npm and pypi.

## Open questions for the owner

1. Reverse the WS5 caveat (drop the local rebuild everywhere except the
   pypi class, and except maven/nuget) once the Phase 0 gate passes? What
   per-ecosystem thresholds?
2. Ship Phase 4 in v5.x after one deprecation release, or in v6?
3. Accept the narrower `--offline`: reuse, cache, bundle, and the pypi
   local class only. Today `--offline` builds locally for every ecosystem.
   Also accept that npm-family packages whose upstream tarball exceeds the
   100 MiB serve cap become unvendorable (`artifact_too_large`, no local
   build)?
4. Signing: approve KMS key custody, the offline root key for revocation,
   and making statements mandatory online (step 25).
5. Accept the optional `r{n}` hosted URL segment, which is a URL grammar
   change shared with the depscan TS parser and the goldens.
6. pypi variant caps: is lazy on-request enough, or should pure wheels
   also be built eagerly for faster first vendoring?
7. Phase 5 sandboxed sdist→wheel builds: worth the autotester-infra
   dependency?
8. Telemetry: move `patch_vendored` to `/v1/orgs/{slug}/events` or extend
   the 2026-12-31 sunset (F22)? The Phase 0 gate depends on it.
