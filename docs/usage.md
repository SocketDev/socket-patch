# Using Socket Patch

Start with the [README quick start](../README.md#quick-start). This guide covers
selection, automation, offline preparation, attestations, and recovery. Detailed
flags, response fields, and diagnostic codes live in the
[CLI contract](../crates/socket-patch-cli/CLI_CONTRACT.md).

## Select patches

A bare `scan` applies hosted patches without prompting. Use `--dry-run` to inspect
what it would change, and `--json` for a machine-readable result:

```sh
socket-patch scan --dry-run --json
socket-patch scan --package lodash --package pkg:pypi/requests
socket-patch scan --ecosystems npm,pypi
socket-patch scan apps/web apps/api
```

Package filters accept names or PURLs, with or without an exact version, and can be
repeated or comma-separated. Hosted and vendored PATH arguments name project
directories; quote globs to let the CLI expand them. Use one directory per invocation
with `--json`. Use one project and a distinct output path per `scan --vex` run.

To make selection consistent across contributors and CI, commit a
[repository policy](configuration.md#repository-patch-policy). To target a specific
advisory or patch:

```sh
socket-patch get CVE-2024-12345 --mode hosted
socket-patch get GHSA-xxxx-yyyy-zzzz --mode vendored
socket-patch get pkg:npm/lodash@4.17.20 --mode agent
```

Replace the example identifiers with the advisory or package you need. `get` also
accepts a patch UUID or an exact package name, which covers every installed version
of that package. `remove` and `rollback` take the same names. A short name that
names several packages (`core` for `@angular/core` and `@babel/core`) is refused:
use the full name or a purl. `get` defaults to hosted mode; `--save-only` and
global targeting default to agent mode instead. Hosted and vendored `get` do not
prompt. Agent-mode searches can offer an interactive choice.

For each package version, automatic selection prefers the highest severity among
downloadable patches, then the most distinct advisories fixed, then the newest
publication date. Exact ties use tier and UUID. A rerun replaces a recorded patch
only with one that outranks it by severity, advisory count, or date; tier and UUID
tie-breaking alone does not cause a replacement. The
[ranking contract](../crates/socket-patch-cli/CLI_CONTRACT.md#which-patch-gets-selected)
details selection and upgrades.

## CI and automation

Hosted and vendored projects use their normal dependency install step. Run scans
in a job that reviews and commits dependency-file changes, then install and verify
that result. Supply `SOCKET_API_TOKEN` through your CI secret store for organization
patches; a token is not needed for the free catalog.

```sh
socket-patch scan --json > scan-result.json
```

Check the command's exit status before processing the result. A preview reports
patch availability; it does not fail merely because patches exist. JSON schemas
vary by command: use the [output reference](../crates/socket-patch-cli/CLI_CONTRACT.md#json-output-shapes)
rather than parsing human output. A pipeline that uses `jq` should preserve the
CLI's exit status, for example with Bash's `set -o pipefail`.

`scan --max-new-patches 5` limits new patches per run; it does not limit updates to
existing patches. See [gradual rollout](configuration.md#gradual-rollout).

## Vendoring and offline installs

For an existing hosted project without an agent manifest:

```sh
socket-patch vendor --dry-run
socket-patch vendor
```

`vendor` ejects the patches referenced by the project's hosted dependency files.
When an agent manifest exists, it uses that manifest's patch set. To discover and
vendor available patches in one run, use:

```sh
socket-patch scan --mode vendored
```

Commit `.socket/vendor/`, including `state.json`, and every dependency or config
file the CLI reports. The ledger stores patch records, artifact fingerprints, and
reversal information. A checkout can install the committed patched packages without
Socket API access or a Socket Patch binary.

This does not vendor unpatched dependencies. Provision those through your normal
mirror or package-manager cache, and test a clean offline install before relying
on an airgapped build. Integrity enforcement and cache behavior differ by package
manager; see [ecosystem support](ecosystems.md).

Vendoring downloads prebuilt artifacts from the patch service and verifies
archive integrity and patched file hashes before installation. The service
owns archive construction, including Yarn Berry cache checksums. Python
vendoring accepts both wheels and source distributions supplied by the service.

`--vendor-source service` is the default. `auto` remains an alias for the same
behavior; `build` is rejected. A missing artifact, pending build, network error,
or integrity mismatch fails without a local build fallback. Healthy committed
artifacts can be reused offline.

`repair` redownloads missing or corrupt artifacts and checks them against the
existing ledger before replacement. It preserves project wiring and recorded
integrity; different archive bytes require an explicit new vendoring operation.
Repair cannot reconstruct a lost vendor ledger. Restore it from version control.

The N-API crate and in-memory patch engine remain available for hosted GitHub
App workflows. Removing local vendoring builders does not remove those APIs.

### Maven reactors and Gradle

Maven reactors use suffixed versions in `.socket/vendor/maven2`; Gradle 6.8+
keeps its coordinates and lockfiles, with settings wiring and a configuration-time
SHA-256 check. Existing Gradle verification files are updated. Single-POM Maven
projects retain their existing vendoring behavior.

```sh
socket-patch vendor --check                       # read-only offline artifact and wiring audit
socket-patch vendor --check --local-repo ~/.m2/repository  # also check Maven cache conflicts
socket-patch scan --mode vendored --maven-config=none     # use only the fallback file repository
```

`--maven-config=auto` (the default) writes a Maven repository tail; `none` disables
that tail. The choice persists in the ledger. See [JVM vendoring](design/maven-vendoring.md)
for supported shapes, committed files, Maven mirror and `-f` limitations, and
offline operation.

### sbt and scala-cli

sbt and scala-cli builds are Maven projects to the CLI. Both modes read what the
tool itself resolved, so resolve first:

```sh
sbt update                          # sbt: record the resolution under target/
socket-patch scan                   # hosted: writes socket-patch.sbt
socket-patch scan --mode vendored   # or vendored: socket-patch-vendor.sbt + .socket/vendor/maven2

scala-cli compile --test .          # scala-cli directory build (Bloop records the resolution)
socket-patch scan --mode vendored   # socket-patch.scala + .socket/vendor/coursier
```

Commit the generated root file with `.socket/`. No user build file is edited.
With no or stale resolution records the run warns once, writes nothing and
exits 0; resolve again and re-run. Mill builds get agent mode or a hosted
snippet to paste. See [Scala build tools](ecosystems.md#scala-build-tools-sbt-mill-scala-cli).

## OpenVEX

Generate an attestation after installing the patched dependencies:

```sh
socket-patch vex --output socket.vex.json
socket-patch vex --json --output socket.vex.json
```

The document marks vulnerabilities covered by verified Socket patches as
`not_affected`. It does not assess other vulnerabilities. A VEX-aware scanner must
be configured to consume the resulting file.

| Patch mode | Evidence used by VEX |
| --- | --- |
| Agent | Installed patched files, checked against the manifest's hashes |
| Vendored | Committed artifacts and live dependency-file references |
| Hosted | Live hosted references and their integrity pins; installed copies are verified when available |

Before installation, hosted VEX can describe the pinned dependency state without
verifying installed bytes. `scan --vex socket.vex.json` also emits hosted VEX before
installation; rerun standalone `vex` afterward. Impact statements include the patch
UUID; vendored and hosted statements add `(vendored)` and `(redirected)` respectively.
Exact strings are in the [provenance contract](../crates/socket-patch-cli/CLI_CONTRACT.md#vex-provenance-markers-contract).

`vex` reads patch records from local state or fetches them from the API. Without a
local record, `--offline` omits the patch as `record_unavailable`. Commit the vendor
ledger when offline attestation is required. A reference no longer used by the
project is excluded even with `--no-verify`; that flag bypasses file-hash checks,
not reference validation. A patch record alone does not prove it is consumed.

The product identifier is inferred from the Git origin or project metadata. Use
`--product <identifier>` when inference is unavailable or unsuitable. `--json`
requires `--output` so the document and command result do not share stdout.

`scan`, `apply`, and `vendor` accept `--vex <path>` plus `--vex-product`,
`--vex-no-verify`, `--vex-doc-id`, and `--vex-compact`. Embedded generation is skipped
for `--dry-run`; an attestation failure makes the command fail even if patching
succeeded. See the [VEX contract](../crates/socket-patch-cli/CLI_CONTRACT.md#embedded-vex-apply---vex--scan---vex--vendor---vex)
for output and empty-project behavior.

## Agent mode

Agent mode records patches and applies them to installed files:

```sh
socket-patch scan --mode agent
# Commit .socket/ and any project wiring the command reports.

# After every fresh install, locally and in CI:
socket-patch apply
```

Once the required patch data is committed, `socket-patch apply --offline` works
without downloading it again. `get <identifier> --save-only` records a patch without
applying it. `apply` skips packages owned by the vendor ledger.

Deno uses agent mode. Cargo agent patches can affect a shared registry cache; so
do Maven ones in `~/.m2` and the Coursier and Ivy caches sbt, Mill and
scala-cli resolve into (restart a running sbt server, Bloop or Metals after
`apply`). Go uses project-local copies and `replace` directives. Read the
[ecosystem caveats](ecosystems.md) before using agent mode in shared environments.
The removed `setup` command is covered in the [migration guide](migrating-to-v5.md).

## Inspect, undo, and repair

| Command | Effect |
| --- | --- |
| `list` | Show agent records, vendor records, and hosted pins; an empty project succeeds |
| `rollback [PURL\|UUID\|PATH]...` | Restore selected patches, or all patches when no target is given, and remove their local state |
| `remove <PURL\|UUID>` | Restore and remove one patch |
| `vendor --revert` | Undo vendoring from its recorded edits and remove the vendored artifacts |
| `repair` | Restore missing patch data or damaged vendored artifacts and clean unused data |
| `scan --mode agent --prune` | Patch discovered packages and remove records for dependencies that left the project |

Use `--dry-run` to preview. `rollback --preserve-state` and
`remove --preserve-state` restore dependencies while keeping local patch records
and artifacts for later reuse. Hosted pins have no local state to preserve.
`remove --skip-rollback` removes tracking without restoring installed files and
cannot be combined with `--preserve-state`.

Hosted reversal resolves original registry entries; it does not replay saved file
snapshots. It needs upstream access and can refuse an unsupported or drifted entry.
Hosted binary `bun.lockb` reversal requires restoring the lockfile from version
control. Review and restore any companion manifest or registry-config changes too.
A package converted from hosted to vendored returns to upstream on `vendor --revert`.

Vendored reversal preserves unrelated edits and refuses unsafe drift. Keep its
ledger with the artifacts. Full details and per-ecosystem restoration limits are in
the [rollback contract](../crates/socket-patch-cli/CLI_CONTRACT.md#rollback-command-contract-v50).
