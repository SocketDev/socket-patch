# Using Socket Patch

Start with the [README quick start](../README.md#quick-start). This guide covers
selection, automation, offline preparation, attestations, and recovery. Detailed
flags, response fields, and diagnostic codes live in the
[CLI contract](../crates/socket-patch-cli/CLI_CONTRACT.md).

## Select patches

A bare `scan` discovers patches from project dependency files and applies them
without prompting, in the mode the project already uses: hosted (writing hosted
references) for a new project, vendored or agent if `.socket/` already holds
patches in that mode. Pass `--mode` to choose or switch modes. Supported lockfiles
work from a fresh checkout before installing dependencies. Agent mode needs
installed packages, and some ecosystems need resolution records first (see
[sbt and scala-cli](#sbt-and-scala-cli) and the [ecosystem notes](ecosystems.md)).
Use `--dry-run` to inspect what would change, and `--json` for a machine-readable
result:

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

In a monorepo, run `scan` from the repository root. With no PATH, a hosted or vendored
scan covers every project directory in the git checkout at or below the current
directory: each directory with its own lockfile is scanned as its own project, under a
`== <dir> ==` heading. Test and fixture directories are left out unless you name them,
and `socket.yml` path filters apply. `--json` and `--vex` still report on one directory:
they scan the current one and list the others in a `projects_not_scanned` warning.
An agent-mode scan patches the packages installed for the project in the current
directory only. When project directories below it have installed packages it did not
reach (their own `vendor/bundle` or `.venv`, for example), it lists them in the same
warning with the command to run for one of them
(`socket-patch scan --mode agent --cwd <dir>`). Run it once per directory.

A scan of several project directories crawls them all at once and asks the patch
service about each package once for the whole run, then reports the directories one
by one, in order.

What that scan patched can be seen and undone from the same directory. `list` shows
the patches of the current directory (headed `== . ==`, as in the scan) and of each
patched project directory below it, and `rollback` with no target rolls all of them
back after one confirmation that names them. `rollback --json` reports on one project
directory and never changes another: it rolls back the current one and names the
others in a warning. A rollback from an agent-mode project also covers that project
alone, as a scan from it does. Submodules and nested clones are other repositories:
run socket-patch inside them. `vex`, `apply`, `repair`, `remove` and
`rollback <target>` still act on one project: when the current directory holds nothing
for them, they name the project directories below that do and the `--cwd <dir>` command
for each.

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
use the full name or a purl. Near names are only suggestions, and `--ecosystems`
scopes both `get` searches and UUID selection. See the
[v5 targeting changes](migrating-to-v5.md#package-targeting) for target forms,
ambiguity rules, and no-match statuses. `get` defaults to hosted mode; `--save-only`
and global targeting default to agent mode instead. Hosted and vendored `get` do
not prompt. Agent-mode searches can offer an interactive choice.

Automatic selection ranks downloadable patches by severity, advisory count, then
publication date. Reruns upgrade existing patches only when a better-ranked patch
is available. See the [ranking contract](../crates/socket-patch-cli/CLI_CONTRACT.md#which-patch-gets-selected)
for tie-breaking and upgrade rules.

One patch is applied per package version. When a package version has several
advisories, Socket publishes a merged patch that fixes them together: one for its
critical advisories, which is free, and one for all of them, which needs a paid plan
(see [free and paid patches](configuration.md#free-and-paid-patches)). A merged patch
is published after the single patches it combines. Until it is ready, `scan` applies
the top-ranked single patch. Each patched package gets one row (its severity, what
the patch fixes, and how many advisories stay unpatched), and the run closes with its
totals:

```text
Switched 1 package to hosted patches; rewrote 1 file.
  CRITICAL  crypto-js@3.1.2  CVE-2026-71851  1 unpatched

Patched 1 package, fixing 1 vulnerability (1 critical).
Saved about 2 hours of engineering time (1 package upgrade at ~2 hours).
1 vulnerability left to patch (50%): 1 awaits a merged patch.
1 merged patch is not ready yet: Socket is still processing it.
Run `socket-patch scan` again later to apply it.
```

The `left to patch` line says why each advisory is left:

| Reason | What it means | What to do |
| --- | --- | --- |
| `await a merged patch` | Another patch you can download fixes it, and Socket is still processing the merged patch that fixes it together with the one applied | Run `socket-patch scan` again later; a rerun moves the package to the merged patch |
| `need a paid Socket plan` | Only the paid tier fixes it: a paid patch, or the paid tier's merged patch when the fix is a free patch for an advisory that is not critical | Use a token for an organization on a paid Socket plan |
| `need a package upgrade` | A patch you can download fixes it, but the patch selected for the package leaves it out, for example under a [selection filter](selection-filter.md) | Upgrade the package |
| `in packages this run did not patch` | The run did not patch the package: a skip, a failure, a rollout limit or a policy | Read the run's output for that package |

`get` reports a merged patch that is not ready the same way, under the patch it
selected, and names the package and the advisories that stay unpatched until then.

`--verbose` names the unpatched advisories under the row, grouped by reason
(`waiting on a merged patch: <ids>`, `needs a paid Socket plan: <ids>`), and
`scan --json` lists the same ids as `packages[].fixedIds`, `packages[].unfixedIds`
and `packages[].mergePendingIds` (the unfixed ids waiting on a merged patch). With
several project directories the totals count every one (`Patched 22 packages in 3
projects, ...`): a package patched in three projects counts three times. "Left to
patch" counts only advisories Socket has a patch for; it says nothing about
vulnerabilities with no patch.

The `Saved about N hours` line is an estimate of the upgrade work the patches stood
in for: two hours for each patched package in each project directory. The two hours
are an assumption (finding a fixed release, moving to it, fixing what else changed,
review), not a measurement of your project.

On a terminal, `scan` also shows what Socket measured about each patch (the exploits
of the fixed advisories blocked, the package's own tests passing) in its row and in a
`Verified:` closing line. `socket-patch show <patch>` prints the full measurements and
the patch's diff.

A package your project already patches itself (pnpm `patchedDependencies`, a Yarn
`patch:` entry, patch-package, a Cargo `[patch]`, a Go `replace`, Composer patches) is
left alone, and the scan says so in one note that names the files and the first few
packages:

```text
Note: skipped 3 packages covered by this project's own patches (pnpm-workspace.yaml): next@16.4.5, next-auth@4.24.15, ts-node@10.9.2.
  --allow-patch-conflicts patches them too.
```

`--verbose` lists every package of a longer note. `--allow-patch-conflicts` applies
Socket's patch on top of yours; review and test the result.

## CI and automation

Hosted and vendored projects use their normal dependency install step. Run scans
in a job that reviews and commits dependency-file changes, then install and verify
that result. Supply `SOCKET_API_TOKEN` through your CI secret store for organization
patches; a token is not needed for the free catalog.

```sh
socket-patch scan --json > scan-result.json
```

Check the command's exit status before processing the result. A preview reports
patch availability; it does not fail merely because patches exist. Commands share
a JSON envelope with `command`, `status`, `dryRun`, `events`, and `summary`;
see the [output reference](../crates/socket-patch-cli/CLI_CONTRACT.md#json-output-shapes)
for command-specific fields. A pipeline that uses `jq` should preserve the CLI's
exit status, for example with Bash's `set -o pipefail`.

`scan --max-new-patches 5` limits new patches per run; it does not limit updates to
existing patches. See [gradual rollout](configuration.md#gradual-rollout).

## Vendoring and offline installs

For an existing hosted project, including a clean checkout with no dependencies installed:

```sh
socket-patch vendor --dry-run
socket-patch vendor
```

`vendor` reads the hosted patch pins from the project's lockfiles, downloads their
prebuilt patched artifacts, and rewrites the dependency files to use `.socket/vendor/`.
An agent manifest or an installed package tree does not change that selection.
When no hosted patches are in scope, it retains the legacy fallback to the agent
manifest. To discover and vendor available patches in one run, use:

```sh
socket-patch scan --mode vendored
```

Commit `.socket/vendor/`, including `state.json`, and every dependency or config
file the CLI reports. The ledger stores patch records, artifact fingerprints, and
reversal information. A checkout can install the committed patched packages without
Socket API access or a Socket Patch binary.

The ledger holds no credentials: a `nuget.config` is recorded without its
`<packageSourceCredentials>`, API keys, passwords and URL user info. Because the
ledger is committed, a revert (`vendor --revert`, `remove`, `rollback`, `scan --prune`)
treats it as untrusted: it only undoes the edits vendoring makes, in the files
vendoring edits, and fails a package whose ledger entry describes anything else
without writing to it. Restore the ledger from version control if that happens.

This does not vendor unpatched dependencies. Provision those through your normal
mirror or package-manager cache, and test a clean offline install before relying
on an airgapped build. Integrity enforcement and cache behavior differ by package
manager; see [ecosystem support](ecosystems.md).

Vendoring verifies downloaded archives and patched file hashes. Healthy committed
artifacts can be reused offline; new artifacts require the patch service. For
changes to v4's local artifact building, see the [migration guide](migrating-to-v5.md#service-only-vendoring).

`repair` redownloads missing or corrupt artifacts and checks them against the
existing ledger before replacement. It preserves project wiring and recorded
integrity; different archive bytes require an explicit new vendoring operation.
Repair cannot reconstruct a lost vendor ledger. Restore it from version control.

### Maven and Gradle

Maven projects, single-module or reactor, use suffixed versions in
`.socket/vendor/maven2`; Gradle 6.8+ keeps its coordinates and lockfiles, with
settings wiring and a configuration-time SHA-256 check. Existing Gradle
verification files are updated. A project vendored before v5 through the
single-POM `<repository>` wiring must run `socket-patch vendor --revert` before
vendoring again.

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
be configured to consume the resulting file:

```sh
trivy fs --vex socket.vex.json --show-suppressed .
grype dir:. --vex socket.vex.json --show-suppressed
```

Each statement names the project as its product, with the patched packages as its
subcomponents, and names each patched package again as a product of its own, which
is how Trivy and Grype look a finding up. A package is named by its PURL and by the
forms those scanners report it under: without qualifiers, and for a gem built for a
platform, also as `name@version-platform`. A form that would also stand for an
unpatched copy of the package in the same document is left out, so the scanner
keeps reporting that copy.

| Patch mode | Evidence used by VEX |
| --- | --- |
| Agent | Installed patched files, checked against the manifest's hashes |
| Vendored | Committed artifacts and live dependency-file references |
| Hosted | Live hosted references and their integrity pins; installed copies are verified when available |

Before installation, hosted VEX can describe the pinned dependency state without
verifying installed bytes. `scan --vex socket.vex.json` also emits hosted VEX before
installation; rerun standalone `vex` afterward.

`vex` reads patch records from local state or fetches them from the API. Without a
local record, `--offline` omits the patch as `record_unavailable`. Commit the vendor
ledger when offline attestation is required. A reference no longer used by the
project is excluded even with `--no-verify`; that flag bypasses file-hash checks,
not reference validation. A patch record alone does not prove it is consumed.

A patch that cannot be attested is left out of the document, and the run says which
and why on stderr, one line per reason:

```text
Warning: omitting 82 packages from VEX: the patched files still hold the original content (not_applied): @sigstore/core@1.1.0, @sigstore/core@2.0.0, @simple-git/argv-parser@1.1.1 and 79 more (--verbose lists them all)
Error: No applied patches with vulnerability metadata to attest.
The patched packages are not installed yet: the installed copies still hold their original files. Reinstall from the lockfile (hosted or vendored patches) or run `socket-patch apply` (agent-mode patches), then run `socket-patch vex` again.
```

For a hosted gem the last line names `socket-patch scan` instead of a reinstall.
Bundler keeps a gem it has already installed, so a checkout that had its gems before
it pulled the hosted `Gemfile.lock` still runs the upstream copies, and
`bundle install`, `bundle install --redownload` and `bundle pristine` don't change
that. The scan replaces the installed copies; see
[Ruby gems: gems already installed](ecosystems.md#ruby-gems-gems-already-installed).
In a project that also holds agent-mode or vendored patches, where a scan with no
`--mode` is not a hosted one, the line names the files to remove before
`bundle install` instead.

`--verbose` prints a line per patch, and `--json` reports each one as its own
`skipped` event. Warnings of one kind are folded the same way: the first in full,
then a line naming the packages the rest are about.

`--no-verify` (or `SOCKET_VEX_NO_VERIFY` in the environment) attests without checking
any file, so it also attests an agent-mode patch whose files are unpatched or missing.
It never does so silently: the run warns how many statements it emitted that way, and
each one ends its impact statement with `; not verified on disk`.

In a Bazel workspace (experimental) the document describes what Bazel builds from the
project's lock, and says `affected` of a package whose patch is only in the installed copy (see
[Bazel workspaces: VEX](ecosystems.md#bazel-workspaces-vex)). `--no-bazel` (`--vex-no-bazel`
on `scan`, `apply` and `vendor`, or `SOCKET_VEX_NO_BAZEL` in the environment) makes it describe
what the package manager installed; use it when the installed tree is what you ship.

The product identifier is inferred from the Git origin or project metadata. Use
`--product <identifier>` when inference is unavailable or unsuitable. A project
with neither (an application with no Git remote and no named project file) must
pass one; the error suggests `--product pkg:generic/<directory name>`. `--json`
requires `--output` so the document and command result do not share stdout.

`scan`, `apply`, and `vendor` accept `--vex <path>`. Generation is skipped for
`--dry-run`; an attestation failure makes the command fail even if patching
succeeded. See the [VEX contract](../crates/socket-patch-cli/CLI_CONTRACT.md#embedded-vex-apply---vex--scan---vex--vendor---vex)
for options, output, and empty-project behavior.

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

What socket-patch does in a Bazel workspace is experimental
([Bazel workspaces: what is supported](ecosystems.md#bazel-workspaces-what-is-supported)).
Agent mode is not supported for a package that Bazel builds: Bazel takes its packages from
what its rulesets read, and runs no `socket-patch apply`. Use hosted mode there, or vendored
mode where [Bazel workspaces: what is supported](ecosystems.md#bazel-workspaces-what-is-supported)
lists it.

## Inspect, undo, and repair

| Command | Effect |
| --- | --- |
| `list` | Show agent records, vendor records, and hosted pins; an empty project succeeds. On a terminal: a full-screen table of the patches, with what was measured about each, to open one from (see below) |
| `show <UUID\|PURL\|NAME\|CVE\|GHSA>` | Look inside one patch without applying it: the advisories it fixes, what Socket measured about it (exploits blocked, tests passing, size, run-time cost), the files it changes and their diffs |
| `rollback [NAME\|PURL\|UUID\|PATH]...` | Restore selected patches, or all patches when no target is given, and remove their local state |
| `remove <NAME\|PURL\|UUID>` | Restore and remove matching patches; a name or versionless PURL selects every recorded version |
| `report <UUID\|PURL\|NAME>...` | Tell Socket that a patch broke the build, the tests or the application |
| `vendor --revert` | Undo vendoring from its recorded edits and remove the vendored artifacts |
| `repair` | Restore missing or corrupt agent patch data and vendored artifacts using existing records, and clean unused data, including the pnpm registry entries of hosted patches that no lockfile uses any more |
| `scan --mode agent --prune` | Patch discovered packages and remove records for dependencies that left the project |
| `scan` (hosted mode) | Also removes, on every run, the pnpm registry entries of hosted patches that are no longer needed |

`show` reads the patch from the patch service and changes nothing. In a terminal it
opens the patch full-screen: the fixes, what Socket measured (exploits blocked, tests
passing before and after, size, run-time cost) and then the diff of every file. Scroll
with the arrow keys or `j`/`k`, page with PgUp/PgDn, step between files with `n` and
`p`, shift long lines with the left and right arrows, and leave with `q`. `--stat`
stops after the summary, `--file <path>` picks files, and `--no-pager` (or a pipe)
prints everything at once.

In a terminal, `list` shows the project's patches as a full-screen table: severity
(colored), package, the advisories fixed, and, filled in from the patch service as it
answers, exploits blocked, tests passing, lines changed, run-time cost and the date
the patch was published. Move with the arrow keys or `j`/`k`, page with PgUp/PgDn,
press Enter to open a patch (the same page `show` opens) and `q` or Esc to leave. The
table follows the terminal's size, and leaving it prints the rows so the listing
stays on screen. `list --verbose`, `list --yes` and a piped `list` print every
patch's full entry instead and ask the patch service nothing; so does `--offline`,
which browses what the project records.

If a patch breaks your project, tell Socket so the patch can be fixed or withdrawn:

```sh
socket-patch report lodash --reason tests --message "jest: TypeError in merge()"
```

`--reason` is `build`, `tests`, `runtime` or `other` (the default), and `--message`
adds one in your own words. A package name or PURL names the patch this project holds
for it; a patch UUID names any patch, so you can report one after rolling it back (a
`rollback` of named patches prints the command). The report carries the patch's id,
its ecosystem and patch mode, the reason, your message, and the CLI's version and
platform: no package names, paths or file contents. It is sent because you ran it,
so the telemetry opt-outs do not apply to it; `--offline` sends nothing, and
`--dry-run` shows the whole report as it would be sent. One report names up to 50
patches. `report` changes nothing in the project.

Use `--dry-run` to preview. `rollback --preserve-state` and
`remove --preserve-state` restore dependencies while keeping local patch records
and artifacts for later reuse. Hosted pins have no local state to preserve.
`remove --skip-rollback` removes tracking without restoring installed files and
cannot be combined with `--preserve-state`.

Hosted mode keeps its state in the lockfiles, so there is no `.socket/` data for
`--prune` to sweep in that mode (`scan --mode hosted --prune` says so). What a
hosted patch adds beside the lock, its `socket-<id>` named registry and its
override in a pnpm project, is cleaned up automatically once no lockfile uses it: by every
hosted `scan`, by `repair` (offline, from the files alone), and by `scan --prune`
in the other modes. See [pnpm hosted mode](ecosystems.md) for the details.

Hosted reversal resolves original registry entries; it does not replay saved file
snapshots. It needs upstream access and can refuse an unsupported or drifted entry.
Hosted binary `bun.lockb` reversal requires restoring the lockfile from version
control. Review and restore any companion manifest or registry-config changes too.
A package converted from hosted to vendored returns to upstream on `vendor --revert`.

Vendored reversal preserves unrelated edits and refuses unsafe drift. Keep its
ledger with the artifacts. Full details and per-ecosystem restoration limits are in
the [rollback contract](../crates/socket-patch-cli/CLI_CONTRACT.md#rollback-command-contract-v50).

## Packages you already patch

By default, `scan` skips packages with declared project patches (pnpm, Yarn,
`patch-package`, native npm/Bun, Composer, Cargo or Go) and reports where the
patch was found, and `apply` leaves them out while applying everything else.
Explicit `get` and `vendor` refuse those conflicts.
A user patch is protected even if it changes a different file than Socket's fix.

With `--json`, a skipped package has an `action: "skipped"` event, a stable
`errorCode` such as `user_patch_conflict`, and a `reason` explaining the conflict
and where it was found. It is not counted in `summary.applied`, including when
the conflict appears after selection while a patch is downloading.

After reviewing the interaction, you can explicitly approve an attempt:

```sh
socket-patch scan --package minimist --mode agent --allow-patch-conflicts
socket-patch apply --allow-patch-conflicts --strict
```

The second form still refuses modified file content. Without `--strict`, explicit
consent permits replacing a mismatched file with Socket's verified content; it
does not merge your changes. Without consent, mismatched files fail by default,
unless they hold an earlier Socket patch's content (a patch update).
`--yes` and `--force` do not approve combining declared project patches. Some
package-manager combinations remain unsupported even with consent: a package
patched with npm's or Bun's own `patchedDependencies` stays unwired in hosted
mode and is refused in vendored mode.
With consent, hosted and vendored mode do wire a package patched with pnpm's
`patchedDependencies`, a Yarn `patch:` descriptor or `patch-package` (Yarn
classic and vlt have no patch mechanism of their own, so `patch-package` is how
those projects patch). The package manager then applies your patch on top of
Socket's, so `vex` never attests that package while your patch is declared.
The in-memory hosted engine has no consent option and always skips such a
package (`user_patch_conflict`). See
[existing project patches](ecosystems.md#existing-project-patches) for the
mechanisms checked and the limitations.
