# Vendored Maven reactors and Gradle in v5

The JVM backend in `crates/socket-patch-core/src/vendor/jvm/` is enabled by
build shape. No experimental environment variable is required. Maven reactors
use suffixed coordinates; Gradle keeps the original coordinates. Both commit a
local repository so another checkout can build without socket-patch or the
Socket service.

The existing single-POM backend remains supported. This change adds reactor and
Gradle support without automatically migrating existing single-POM repositories.
Hosted Gradle wiring is a separate backend; see
[ecosystem support](../ecosystems.md#gradle).

sbt build roots and scala-cli directory builds use the same backend and ledger
ecosystem (`jvm`): sbt through a generated `socket-patch-vendor.sbt` over the
reactor-style suffixed `.socket/vendor/maven2` tree, scala-cli through owned
files over a same-GAV `.socket/vendor/coursier` tree. Mill is not wired. See
[sbt, Mill and scala-cli support](sbt-support.md).

## Commands

```sh
socket-patch vendor
socket-patch vendor --check
socket-patch vendor --check --local-repo /path/to/maven/repository
socket-patch vendor --maven-config=none
socket-patch vendor --revert
```

`scan --mode vendored`, `get --mode vendored`, `vendor`, `repair`, `remove` and
`rollback` share the v5 vendored backend. Discovery reads the Maven local
repository and the Gradle cache (`<Gradle user home>/caches/modules-2/files-2.1`,
plus the read-only cache); Gradle-only builds use the Maven local repository
only when the build can consume it. Upstream POMs, Gradle module metadata and
classifier jars are taken from any local cache (a Gradle copy must hash to its
hash directory, a Maven copy with a `.sha1` sidecar must match it); an online
service-backed request downloads what no cache holds and checks every file
against the registry's checksums.

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

Run vendoring from the Gradle root. A directory an ancestor settings file
includes (literally, through a relocated `projectDir`, or possibly, when its
includes cannot be read literally), and a project without a settings file of
its own below an ancestor settings file, produce `not_build_root`; nothing is
written, and `repair` refuses there too. A root holding both a `pom.xml` and a
Gradle build vendors both, in one ledger entry: the Maven half as a one-POM
reactor (suffixed tree, pin, `maven.config`), the Gradle half as below. A
refusal of either half writes nothing, and `--check`, `vex`, revert and repair
always handle both. A single-POM root whose ledger already holds a single-POM
(`<repository>`) entry stays on the single-POM backend, with a
`legacy_maven_root` degraded warning that the Gradle build stays unpatched:
nothing migrates that wiring, so revert and vendor again to wire both builds.

The original GAV is retained under
`.socket/vendor/gradle/<group-path>/<artifact>/<version>/`, with the jar, the
upstream POM and module, and every classifier jar a build script or catalog
declares (plus the `sources` jar when a cache or the registry has it, so IDE
source attachment keeps working). A declared classifier that cannot be sourced
refuses with `classifier_unavailable`: `exclusiveContent` claims every file of
the GAV, so a missing one would stop resolving. A classifier jar that carries
an unpatched copy of a patched member is degraded (`classifier_unpatched_copy`).
The tree marker lists the patched members beside classifier jars, so `vex`
re-runs that check from the committed tree and withholds attestation.

Each vendored GA also gets `.socket/vendor/gradle/<group-path>/<artifact>/maven-metadata.xml`,
derived from the index: every vendored version in Gradle's version order, the
highest as latest and release, and no `lastUpdated`. Range, prefix and rich
selectors list versions from it, so vendoring never changes the version Gradle
selects (`range_declared` notes such a declaration). A declaration set in which
no selector admits the vendored version is refused with
`gradle_range_excludes_vendored`. The file is recomputed when a version is
reverted and removed with the GA's last one.

Lockfiles, version catalogs and project build scripts stay unchanged. Settings
files receive an apply line for `.socket/gradle/socket-patch.settings.gradle`.
Settings plugin and buildscript classpaths receive an in-block exclusive
repository entry because those classpaths resolve before the apply line runs.

The script, the index, the derived metadata and the `.gitattributes` files are
owned text and are compared line-ending blind, so a `core.autocrlf` checkout
passes `--check` and reverts clean. `.socket/gradle/.gitattributes` (`* -text`,
kept while a hosted script remains) and `.socket/vendor/.gitattributes`
(`gradle-index.tsv -text`, merged into an existing file) keep them out of EOL
conversion on new checkouts. A settings file vendor created is deleted on
revert once only whitespace is left of it.

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
An existing entry that holds only a `<pgp>` signature gets a `sha256` beside
it: the vendored repository has no signatures, so Gradle falls back to
checksums. With metadata verification on, `--check` and the parent-chain
check require a checksum, so a tree vendored before this rule fails `--check`.
Metadata traversal is bounded and covers parent defaults and child property overrides. The backend
records supplementary entries as shared fragments so either patch can be
reverted first. Existing verification policy and unrelated checksums are kept.
A verification file is never created automatically.

The checks read the whole statically known script graph: settings, every
project's build script, buildSrc and included builds with their convention
plugins and plugin sources, `apply from` targets and version catalogs.
Android and Kotlin Multiplatform plugins anywhere, `available-at` module
redirects, a user `exclusiveContent` rule claiming the patched module
(`gradle_exclusive_content_conflict`, naming the file; group, subgroup, regex,
module and version rules) and paths leaving the checkout are refused. Build
logic the graph cannot follow (a computed `apply from`, a script that is not
UTF-8) is degraded as `gradle_unscanned_build_logic`, and nonliteral included
builds as `unwired_build_logic`. A settings file that is not UTF-8 is refused;
one with a byte-order mark keeps it. The backend never executes user build
code to discover settings or metadata.

`vex` attests a Gradle entry only while its wiring is live: the apply line and
index rows are present, the script is intact, and a re-plan over the committed
tree is refused nowhere and degraded nowhere.

## Artifact identity and integrity

Service jars pass transfer-integrity and patched-member checks. The server constructs jars and strips invalidated signatures; the CLI never rebuilds jar archives. Online vendoring authenticates upstream POM and Gradle module metadata against registry sidecars. Metadata fetches use a separate HTTP client and do not send Socket API credentials. `SOCKET_MAVEN_REGISTRY` supports a private mirror.

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

`repair` redownloads the exact recorded jar and checks regenerated repository metadata against the ledger, preserving project wiring. A missing classifier jar, POM or derived `maven-metadata.xml` also triggers it: classifier jars are downloaded and checked against registry checksums, a mixed root's two trees come back from one download, and the derived metadata and the owned `.gitattributes` are rewritten when missing (for an otherwise healthy entry too, without a download). Tree directories reached through a link out of the checkout are refused (`vendor_path_unsafe`). Offline repair cannot restore missing or corrupt artifacts. The
ledger is required for exact reversal; restore a deleted ledger from version
control. In-place ledger reconstruction remains outside v5's repair contract.

## Validation and remaining scope

The implementation is covered by planner, disk-safety, lifecycle and command
integration tests. Real-tool capstones exercise a Maven reactor from fresh
checkouts, root and module invocations, Gradle strict locking and repository
mode, existing verification metadata, offline builds, tamper detection and
byte-exact revert; `e2e_vendor_gradle_build` covers each Gradle rule above
against a fake Central, asserting on the jar Gradle actually consumes. The PR
tier pins Maven 3.6.3, 3.8.9, 3.9.2, 3.9.16 and 4.0.0-rc-6 (macOS and Windows on
3.9.16), and Gradle 6.9.4, 7.6.6, 8.14.3 and 9.8.0 on Linux, plus a Windows
8.14.3 row; `gradle-compatibility.yml` runs every Gradle version on Linux,
macOS and Windows nightly.

Automatic single-POM migration, Maven 4 implicit subproject discovery,
build-time Maven strict pins, creating Gradle verification policy, and online
dependency-graph resolution checks remain separate work. They are not enabled
by this release.
