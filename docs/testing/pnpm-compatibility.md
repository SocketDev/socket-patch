# pnpm hosted compatibility

Hosted mode changes the locked artifact URL and integrity while keeping the
package's name and version. Installing that artifact, verifying its files,
recognizing it in an SBOM, and changing an alert's policy/count are separate
operations. This repository tests the first two; these tests do not assert
Socket dashboard detection or alert resolution.

## Required matrix

`.github/workflows/pnpm-compatibility.yml` runs on pull requests and pushes to
`main`. It compiles the CLI/test once, installs the exact package-manager
versions below, and treats missing tools and failed fixture installs as errors.
The matrix needs no Socket API token. The package managers are real; patch
discovery and tarball endpoints are local test servers.

| pnpm versions | Node | Lock format |
| --- | --- | --- |
| 1.0.0 | 10.24.1 | Expected refusal: shrinkwrapVersion 3 without a minor version discards hosted URLs |
| 1.43.1, 2.0.0, 2.25.7 | 10.24.1 | shrinkwrapVersion 3 with a minor version, `shrinkwrap.yaml`, block resolutions |
| 3.0.0, 3.8.1 | 10.24.1 | 5.1, block resolutions |
| 4.0.0, 4.14.4, 5.0.0, 5.18.11 | 16.20.2 | 5.1 / 5.2, block resolutions |
| 6.0.0, 6.35.1 | 16.20.2 | 5.3 |
| 7.0.0, 7.33.7 | 16.20.2 | 5.4 |
| 8.0.0, 8.15.9 | 16.20.2 | 6.0, per-peer package resolutions |
| 9.0.0, 9.15.9 | 24.11.1 | 9.0, packages/snapshots split |
| 10.0.0, 10.33.0, 10.34.5 | 24.11.1 | 9.0 |
| 11.0.0, 11.27.0, 12.0.0, 12.4.2 | 24.11.1 | 9.0, hosted URLs require lockfile trust or the registry route |

This samples each released major from 1 through 12 and important major
boundaries; it is not an exhaustive test of every historical patch release or
future release. Pre-lockfile releases cannot use hosted lockfile redirection.
Vendored mode has a separate compatibility contract in `docs/ecosystems.md`.

The 24 supported versions exercise scan and explicit-UUID hosted entry points, idempotency,
warm installs, verified VEX, a clean reinstall, a fresh frozen install with a
dead registry and empty store, an ordinary install, byte-exact rollback,
lock-only discovery, and rejection of tampered hosted tarballs. pnpm >=6 also
gets a local-registry workspace fixture with a scoped package, an npm alias,
two peer contexts, and peer dependencies of peers. Legacy workspace behavior
before pnpm 6 is not covered by that fixture.

The remaining row, pnpm 1.0.0, verifies an explicit refusal with the lockfile
unchanged and no successful redirect recorded. Its installer removes the
hosted URL even on a frozen install. For early shrinkwrapVersion 3 locks with
no positive minor version, upgrade to a tested release (1.43.1 or newer) and
regenerate the lock before redirecting, or use installed-file agent mode.

Captured locks under `crates/socket-patch-core/tests/fixtures/pnpm-hosted/`
keep grammar coverage in ordinary offline tests. Additional tests cover
LF/CRLF, nested peer suffixes, quoted keys and URLs, unrelated versions,
malformed mappings, and refusal across multiple locks. A CLI regression test
ensures a hosted URL in one instance cannot confirm a partially patched package.

## The registry route

On pnpm 11.20 and newer, hosted mode can have pnpm verify the patched entries
instead of trusting the whole lock. When the patch service gives every hosted
pin a registry address (the directory the patch's tarball is served from) and
every pnpm pin of the project proves pnpm 11.20 or newer, the scan declares
one registry per patch under `namedRegistries` in `pnpm-workspace.yaml`
(`socket-<first digits of the patch UUID>`), routes each patched release to
its own under `overrides`, rewrites `pnpm-lock.yaml` to the shape pnpm writes
for that, and writes no `trustLockfile` (see `docs/ecosystems.md`). The matrix
above installs through `trustLockfile`: its fixture grants carry no registry
address.

### Why the registry is not only declared

pnpm verifies a lock entry against a declared registry from 11.10 on, and
frozen installs pass with a declaration alone on every release from 11.10.0
through 12.22.0. A declaration does not survive a command that resolves again,
though: pnpm asks the default registry and puts the upstream tarball back.
Measured on a lock with hosted entries, with the registry only declared:

| pnpm | `pnpm add` of another package | `pnpm update`, `pnpm dedupe`, `install --fix-lockfile` |
| --- | --- | --- |
| 11.10.0, 11.20.0, 11.25.0, 11.28.13 | hosted entries re-resolved to the upstream tarball | hosted entries re-resolved |
| 12.0.0, 12.4.2, 12.10.0, 12.16.0 | hosted entries kept | hosted entries re-resolved |
| 12.19.0, 12.21.0, 12.22.0 | kept, except a hosted package with peer dependencies in its subtree (its own, or a dependency's), which is re-resolved | hosted entries re-resolved |

(`trustLockfile: true` keeps hosted entries across `pnpm add` on 11.28.13 and
12.x, and loses them on 11.10.0 through 11.25.0.)

### What the override changes

With `'<name>@<version>': 'socket-<id>:<version>'` beside the declaration of
the patch's registry `socket-<id>`, pnpm resolves the package from that
registry every time. Measured with real pnpm against a stand-in patch server
that serves one registry per patch, for packages with and without peer
dependencies:

| pnpm | lock written for the routed project | fresh-store frozen install | `pnpm add` | `pnpm update` | `pnpm dedupe` | `install --fix-lockfile` |
| --- | --- | --- | --- | --- | --- | --- |
| 11.10.0, 11.15.0 | another lock | | | | | |
| 11.20.0, 11.25.0, 11.28.13 | byte-identical | passes | kept | kept | kept | kept |
| 12.0.0 | byte-identical | passes | kept | kept | kept | this release has no such flag |
| 12.4.2, 12.10.0, 12.16.0, 12.19.0, 12.21.0, 12.22.0 | byte-identical | passes | kept | kept | kept | kept |

"Byte-identical" is across these releases and with the lock the scan writes:
the golden fixtures under
`crates/socket-patch-core/tests/fixtures/pnpm-registry-overrides/` hold, for
each project shape, the lock real pnpm resolves once the workspace file routes
the patches, and the scan must write the same bytes. They were generated with
pnpm 12.22.0 and are identical on 11.20.0, 11.25.0, 11.28.13, 12.0.0, 12.4.2,
12.10.0, 12.16.0, 12.19.0 and 12.21.0 (`scripts/gen-pnpm-registry-override-golden.mjs`
regenerates them and fails when two releases disagree). They cover a
transitive leaf, a scoped direct dependency, a package with its own peer
dependencies, a package under a peer-suffixed parent, a patched package that
is itself a peer, both at once, two versions of one package (one or both
patched), several importers, members with their own locks
(`sharedWorkspaceLockfile: false`, where every lock records the overrides), a
project with overrides of its own, a project with registries of its own named
`socket` and with the very name a patch's registry would take (the patch's
then takes four more digits), two patches whose UUIDs start with the same
eight digits, several patches at once, a patched release whose upstream
deprecation message spans several lines, and pnpm 12's two-document lock.

pnpm locks a deprecation message of several lines as a block scalar
(`deprecated: |-` and the message's lines, more deeply indented), and the
routed entry carries none of it: the patch server's registry document has no
`deprecated`. A message of several paragraphs is locked with an empty line
inside the entry (`deprecated: |`), and one that ends in line breaks keeps
them (`deprecated: |+`). The scan's lock edits move an entry as one run of
lines, so a lock that holds either is kept on `trustLockfile`, with that
reason.

Two shapes are in the fixtures as refusals, because pnpm does not lock them as
a respelling of the plain lock; the scan keeps such a project on
`trustLockfile` and says why:

* a package installed both with and without the patched release as its peer
  (two importers resolving the peer differently): pnpm 12 records no
  `version:` line for that package, pnpm 11 does;
* the patched release installed as another package's optional peer: pnpm
  resolves the copy of an importer that does not depend on the release
  directly from the default registry, around the override, so that copy would
  stay unpatched.

One consequence of the override is pnpm's own: `<name>@<version>` matches every
dependency range that admits that version, so a dependent that had resolved a
newer version through such a range moves to the patched one the next time pnpm
resolves. The scan refuses the route when an importer of the project is in that
position (the lock records importers' ranges); for transitive dependents the
lock does not record the range, and the lock the scan writes is what pnpm
installs frozen.

Measured with real pnpm on a project where one package depends on `leaf` at
exactly `1.0.0` (patched) and another through `^1.0.0`, locked on `1.5.0`. The
scan routes `leaf@1.0.0`, leaves the other dependent on `1.5.0`, and notes
that the lock also holds `1.5.0` in range. Then:

| pnpm | frozen install, `pnpm install`, `install --lockfile-only` | `pnpm add <another package>` | `pnpm update`, `pnpm dedupe` |
| --- | --- | --- | --- |
| 11.20.0, 11.25.0, 11.28.13 | the scan's lock, byte for byte; the dependent keeps 1.5.0 | the dependent moves to the patched 1.0.0 | the dependent moves to the patched 1.0.0 |
| 12.0.0, 12.4.2, 12.10.0, 12.16.0, 12.19.0, 12.21.0, 12.22.0 | the scan's lock, byte for byte; the dependent keeps 1.5.0 | the dependent keeps 1.5.0 | the dependent moves to the patched 1.0.0 |

So the lock the scan writes is not the one pnpm writes the next time it
resolves the whole project: `leaf@1.5.0` leaves the lock and its dependent
installs the patched `1.0.0`. The routed release itself is kept in every case.
The scan does not refuse the route for this (the range is not in the lock to
check); it names the package and both versions in a note of its pnpm guidance
whenever a governing lock holds a newer release of a routed package within the
routed release's caret range (the same major, or the same minor below 1.0).

### Where an override can come from

The route is refused when the user overrides a patched package, and the scan
looks for such an override in `pnpm-workspace.yaml`. That is the only place
the gated releases read one from. Measured on pnpm 11.20.0, 11.25.0, 11.28.13,
12.0.0, 12.4.2, 12.10.0, 12.16.0, 12.19.0, 12.21.0 and 12.22.0: `pnpm.overrides`
in package.json is ignored with a warning ("The "pnpm" field in package.json is
no longer read by pnpm"), `resolutions` is ignored silently, the lock records no
`overrides:` for either, and the dependency resolves as without them.

### The pin rule

A pin proves pnpm 11.20 when the lowest version it admits is 11.20 or higher
(`11.28.13`, `^11.20.0`, `>=12`, `12 || 13`); `>=11`, an unreadable range, pins
that disagree, or no pin leave the project on `trustLockfile`. With no pin at
all, and a registry address for every hosted pin, the warning adds that
pinning pnpm 11.20 or later (for example with `packageManager`) and re-running
the scan switches the project over.

The registry's version documents are dated by the upstream release of the
version, or carry no date when it is unknown, so pnpm's default one-day
`minimumReleaseAge` does not hold back a freshly published patch.

### A routed lock without its workspace file

A routed lock needs the `pnpm-workspace.yaml` that declares its registries. Measured with
pnpm 11.28.13 and 12.22.0: `pnpm install --lockfile-only` in a directory that holds the
routed lock and `package.json` and no workspace file fails with
`ERR_PNPM_MISSING_NAMED_REGISTRY` ("has registry prefix 'socket-…:', which is not declared
by the registries setting") and leaves the lock as it is. That directory is what a
rules_js hub of a Bazel workspace gives the pnpm it runs for `update_pnpm_lock` when the
hub does not list the file. The lock reader of rules_js itself takes a routed lock:
measured on macOS, rules_js 3.6.0 on Bazel 9.3.2 builds one for a hub without
`update_pnpm_lock`, with the patched bytes in the built packages, and rules_js 2.9.3 on
Bazel 8.8.2 does too. Until a Bazel leg builds a routed lock with `update_pnpm_lock`, the
scan does not take the route for a lock that a hub reads (see "Bazel workspaces: npm" in
[ecosystems](../ecosystems.md)).

### Tests

`pnpm12_registry_route_survives_resolution_and_cleans_up` and its pnpm 11
twin run with the other real-pnpm legs of `e2e_redirect_pnpm_build`, on the
pnpm 12 and pnpm 11 that Corepack provides, with no network beyond two
loopback servers (a default registry of synthetic packages, and the patch
server on its own origin, since pnpm keys its metadata cache by host). Over a
project with a peer-dependent package and a transitive leaf, both patched,
each leg checks that `pnpm install --lockfile-only` leaves the scan's lock
byte for byte; that a fresh checkout frozen-installs the patched bytes from an
empty store with no flags, asking each patch's own registry for its package;
that `pnpm add`, `pnpm update`, `pnpm dedupe` and `pnpm install
--fix-lockfile` keep both packages routed and patched; and that after each
cleanup (a
rollback of one package, the re-scan that routes it again, the fall back to
`trustLockfile` when a grant loses its address, a full rollback) a frozen
install from an empty store still accepts the workspace file and the lock
together.

`pnpm12_registry_route_reaches_a_newer_release_in_range` and its pnpm 11 twin
pin the two measurements above: what each pnpm command does with a newer
release in range of a routed one, and that an override in package.json reaches
no lock.

`pnpm12_registry_route_is_left_for_a_bazel_hub_added_later` and its pnpm 11
twin route a project, add a rules_js hub to its `MODULE.bazel` and scan again,
with no Bazel. Where the hub keeps the lock up to date with a pnpm 11 that
does not see the workspace file, the scan changes neither file; where the hub
only reads the lock, the scan takes the registry, the override, the lock's
record and the registry keys out in one run and pins the release on
`trustLockfile`. A fresh checkout frozen-installs the patched bytes from an
empty store after either.

`pnpm12_registry_route_is_cleaned_up_when_a_patch_is_not_needed` and its pnpm
11 twin run in the same suite, against the same two loopback servers. They
check out the routed project once per case, change it with the real pnpm the
way a user would, and run the command that cleans up: the dependency removed
(`pnpm remove`), then `scan`, `repair --offline` and `scan --prune` each; the
dependency upgraded past the patched release (`pnpm add <name>@2.0.0`), then
`scan` and `repair --offline` each; every patched dependency removed, then
`scan` and `repair --offline` each; the patch of one package withdrawn, then of
both, then `scan`. Each command first runs with `--dry-run`, which must leave
`pnpm-workspace.yaml` and the lock byte for byte. After each wet run the two
files are compared with what is expected, `pnpm install --lockfile-only`
re-locks them without changing a byte, and a fresh checkout installs with
`--frozen-lockfile` from an empty store. `scan`, `repair` and `scan --prune`
must leave the same bytes; `repair` runs with no patch service to reach.

Offline tests cover the workspace-file edit
(`formats::pnpm::named_registries`), the lock rewrite against the golden
fixtures (`formats::pnpm::registry_alias`), the choice between the two
settings and every cleanup (`hosted::engine`), the cleanup `repair` and a
`--prune` pass run from the files alone
(`patch::redirect::upstream::route_sweep_tests`), the scan, `rollback`,
`remove` and the vendored takeover end to end (`in_process_redirect_pnpm`,
`in_process_vendor_pnpm_takeover`), and each command's cleanup of unused
registry entries, with its dry run and its JSON report
(`in_process_pnpm_registry_cleanup`).

## Reliable installation

`scan --mode hosted` changes lockfiles; it does not replace already installed
files. Several pnpm versions reuse the original files from an existing install
or store even when installation succeeds. `--force` alone is not portable and
can re-resolve upstream artifacts on pnpm 12.

For CI, install the **patched branch** in a clean checkout without any
`node_modules` directories, using a new empty store for the post-patch install:

```sh
pnpm install --frozen-lockfile --store-dir "$RUNNER_TEMP/socket-patch-store-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
socket-patch vex --output socket-patches.openvex.json
```

The store path must be empty and must not be restored from a cache. On pnpm
1–4 use `--store`; pnpm 1–3 can silently ignore `--store-dir`, and early pnpm 4
rejects it. For a workspace, the clean checkout requirement includes
member `node_modules` trees. Keep the redirected lockfile and any generated
`pnpm-workspace.yaml`; do not delete or regenerate the lock to work around an
installation error. VEX uses installed-file verification by default; exporting
VEX does not automatically upload it or change Socket alert counts.

A generated `pnpm-workspace.yaml` (`packages: ['.']` plus `trustLockfile: true`,
the hosted `namedRegistries:` and `overrides:`, or the vendored `overrides:`)
makes a
single-package project a root-only workspace. pnpm 9.0.0–10.4.x then refuse
`pnpm add <pkg>` with
`ERR_PNPM_ADDING_TO_ROOT` unless given `-w`; 10.5.0 and later add normally. So
neither mode creates the file when every pnpm pin of the project (the
`node_modules/.modules.yaml` install record, package.json `packageManager`,
`devEngines.packageManager`, `engines.pnpm`) names 9.0–10.4, which read neither
setting from it. With no pin, or any pin that may be a later pnpm, the file is
created as before.

## Run locally

```sh
cargo test -p socket-patch-core --test pnpm_hosted --test redirect_golden
cargo test -p socket-patch-cli --test in_process_redirect_pnpm \
  --test in_process_pnpm_registry_cleanup

# Provision the chosen pnpm executable and a compatible Node on PATH first.
SOCKET_PATCH_PNPM_E2E_BIN=/absolute/path/to/pnpm \
SOCKET_PATCH_PNPM_E2E_VERSION=10.33.0 \
SOCKET_PATCH_PNPM_E2E_REQUIRED=1 \
cargo test -p socket-patch-cli --test e2e_redirect_pnpm_build \
  pnpm_pinned_matrix -- --ignored --nocapture

# Separate production-service proof, with pnpm on PATH; no API token needed.
SOCKET_PATCH_HOSTED_E2E_STRICT=1 \
cargo test -p socket-patch-cli --test e2e_hosted_production \
  pnpm_hosted_install_proof -- --ignored --nocapture
```

The required test verifies the reported pnpm version. In particular, an
unavailable legacy runtime must fail setup rather than remove a matrix row
from coverage. Hosted tests isolate package-manager caches and allocate
independent empty stores for each installation proof.
