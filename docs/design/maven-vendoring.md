# Vendored Maven reactors and Gradle in v5

The JVM backend in `crates/socket-patch-core/src/vendor/jvm/` is enabled by
build shape. No experimental environment variable is required. Maven reactors
use suffixed coordinates; Gradle keeps the original coordinates. Both commit a
local repository so another checkout can build without socket-patch or the
Socket service.

The existing single-POM backend remains supported. This change adds reactor and
Gradle support without automatically migrating existing single-POM repositories.
Hosted mode keeps its existing behavior.

## Commands

```sh
socket-patch vendor
socket-patch vendor --offline
socket-patch vendor --check
socket-patch vendor --check --local-repo /path/to/maven/repository
socket-patch vendor --maven-config=none
socket-patch vendor --revert
```

`scan --mode vendored`, `get --mode vendored`, `vendor`, `repair`, `remove` and
`rollback` share the v5 vendored backend. Maven discovery still uses the Maven
local repository; a Gradle-only cache is not a Maven discovery source. An online
service-backed vendoring request can obtain the upstream POM and Gradle module
metadata from the registry when they are not cached locally.

`vendor --check` is read-only and offline even without `--offline`. It checks
artifact hashes, recorded tree files, wiring, Gradle's index and script, and
unindexed files. `--local-repo` also detects a suffixed Maven jar or POM whose
bytes conflict with the committed copy. Failures produce per-package
`vendor_check_failed` events and exit 1. A patch without a ledger entry fails
with `vendor_ledger_missing`. Offline upstream metadata is identified by the
`vendor_jvm_upstream_unverified` warning; run vendor online to authenticate it
against registry checksums.

## Maven

Supported reactors have an explicit root `pom.xml` and `<modules>` or
`<subprojects>` declarations, including declarations in profiles. Run vendoring
from the reactor root. A discovered ancestor reactor produces `not_build_root`
instead of allowing a partial submodule edit.

The patched version is `<base>-socket.<first-eight-uuid-hex>`, matching the patch
service. A warm cache of the original version cannot shadow that coordinate.
The backend writes:

- `.socket/vendor/maven2/<group-path>/<artifact>/<suffixed-version>/`: patched
  jar, suffixed POM, SHA-1 sidecars, and an ownership marker.
- `.socket/vendor/maven2/.gitattributes`: disables line-ending conversion of
  committed repository bytes.
- A shared file repository and dependency-management pins in each local root.
- Rewrites of conflicting base-version literals and resolved local properties,
  including profiles and local parent POMs outside the module list.
- Two lines in `.mvn/maven.config`: offline file protocol access and the local
  repository tail at `${session.rootDirectory}/.socket/vendor/maven2`.

Parent chains must remain within the checkout. Local parent coordinates are
checked before using their properties. Range selectors, unresolved properties,
classifier declarations, conflicting explicit versions and publishing POMs
produce specific warnings; the backend does not silently claim those
unsupported declarations are patched. An enforcer repository ban omits the
fallback repository and warns that the tail requires Maven 3.9.2 or newer.

Maven 3.9.2+ can read the repository tail without copying jars into `~/.m2` and
without routing through mirrors. Older Maven versions use the fallback file
repository, which copies the suffixed artifact into the local cache. A
`mirrorOf=*` configuration must exclude `socket-patch-vendor` on that fallback
path.

Maven 3.9.2–3.9.8 has a known interpolation limitation when `-f` is invoked from
outside the root. Use Maven from the root or select `--maven-config=none` on the
first vendoring run. That option uses the fallback file repository only, is
recorded in the ledger, and remains in effect on later runs and repair. Revert
existing auto-config wiring before changing to `none`. Combining `none` with a
repository ban is refused. Version detection reads wrapper properties only;
it never executes Maven.

## Gradle

Gradle 6.8+ is supported, including Groovy and Kotlin settings, multi-project
builds, buildSrc, and literal `includeBuild` paths inside the checkout. A
wrapper proving a version below 6.8 is refused before writes; the generated
script also checks the running Gradle version.

The original GAV is retained under
`.socket/vendor/gradle/<group-path>/<artifact>/<version>/`. Lockfiles, version
catalogs and project build scripts stay unchanged. Settings files receive an
apply line for `.socket/gradle/socket-patch.settings.gradle`. Settings plugin
and buildscript classpaths receive an in-block exclusive repository entry
because those classpaths resolve before the apply line runs.

The static script:

- Reads `.socket/vendor/gradle-index.tsv`, with sorted GAV/path/SHA-256/UUID rows.
- Hashes files as streams and requires jar and POM rows for every GAV.
- Rejects unsafe coordinates, selectors, mismatched paths and unindexed files.
- Adds an `exclusiveContent` file repository for the patched coordinates to
  the relevant repository handlers while respecting repository mode.
- Fails configuration if a vendored artifact no longer matches its index.

When `gradle/verification-metadata.xml` already exists, vendoring updates the
patched jar's checksum and, when metadata verification is enabled, adds missing
POM and module entries for the artifact, its parents and imported BOMs.
Metadata traversal is bounded and covers parent defaults and child property overrides. The backend
records supplementary entries as shared fragments so either patch can be
reverted first. Existing verification policy and unrelated checksums are kept.
A verification file is never created automatically.

Android, Kotlin Multiplatform, `available-at` module redirects, conflicting
exclusive-content rules and paths leaving the checkout are refused. Nonliteral
included builds are warned about rather than evaluated. The backend never
executes user build code to discover settings or metadata.

## Artifact identity and integrity

Service artifacts pass the existing download-integrity and patched-member
checks. Local jar rebuilds reproduce the server's stored ZIP encoding: upstream
entry order, executable bits, fixed 1980 timestamps, no directory entries or
extra fields, sorted additions, and stripped signature metadata. A checked-in
fixture generated by archiver 7.0.1 tests byte identity, including Unicode paths
and executable entries. The generator is beside the fixture under
`src/vendor/jvm/fixtures/repack/`.

Online JVM vendoring checks upstream jar and metadata bytes against registry
SHA-512 sidecars, falling back to SHA-1, independently of local cache sidecars.
Offline metadata is accepted with its trust status recorded in the ledger.
Registry metadata fetches use a separate HTTP client and never send Socket API
credentials. `SOCKET_MAVEN_REGISTRY` supports a private mirror.

Maven v5 does not enable Resolver trusted-checksum processors at build time.
Those processors crash some release reactors and system-scope dependencies,
and do not reliably enforce pins on all supported Resolver versions.
`vendor --check` supplies the offline integrity audit. Gradle always performs
its index check at configuration time; this is separate from Gradle's own
optional dependency-verification policy.

## Transactions, state and reversal

New entries use ecosystem `jvm` with Maven PURLs. Old binaries refuse their
revert rather than interpreting them as legacy whole-POM edits. Existing
prototype entries identified by their JVM wiring kinds remain readable.

The planners return complete file writes and fragment records. The v5 group
commit captures build-file edits, the Gradle index, the owned settings script,
repository `.gitattributes`, and the vendor ledger. Artifact bytes are made
durable before those commit points. All vendor entry points use the same
transaction and recovery mechanism. Ordinary vendoring retains v5's per-patch
success/failure contract; hosted ejection retains its all-or-nothing contract.

Revert restores per-patch fragments, keeps shared wiring while other patches
still consume it, and preserves user edits that no longer match recorded
fragments. `--preserve-state` restores wiring while retaining artifacts and the
ledger. Patch updates remove superseded Maven trees after the new wiring is
committed. Gradle updates keep the same artifact paths. Unrecognized or forged
paths cannot direct writes outside the backend's allowed files.

`repair` reconstructs missing/corrupt artifacts using the same backend. The
ledger is required for exact reversal; restore a deleted ledger from version
control. In-place ledger reconstruction remains outside v5's repair contract.

## Validation and remaining scope

The implementation is covered by planner, disk-safety, lifecycle and command
integration tests. Real-tool capstones exercise a Maven reactor from fresh
checkouts, root and module invocations, Gradle strict locking and repository
mode, existing verification metadata, offline builds, tamper detection and
byte-exact revert. CI pins Maven 3.6.3, 3.8.9, 3.9.2, 3.9.16 and 4.0.0-rc-6,
and Gradle 6.9.4, 7.6.4, 8.14.3 and 9.8.0, with macOS and Windows coverage.

Automatic single-POM migration, Maven 4 implicit subproject discovery,
build-time Maven strict pins, dynamic-version repository metadata, classifier
artifacts, creating Gradle verification policy, and online dependency-graph
resolution checks remain separate work. They are not enabled by this release.
