# Where the readers and modes disagree

Companion to [lock-model-unification.md](lock-model-unification.md). Each
row is a question that discovery (VEX), the lock inventory, hosted mode and
vendored mode answer differently today, with its resolution under that
document's [principles](lock-model-unification.md#principles-owner-decisions-2026-11-04).
Paths are relative to `crates/socket-patch-core/src/`. Line numbers are from
the survey of 2026-11-04 and will drift.

Flags:

* **false attestation**: a reader attests a copy the install may not use
  today. Fixing these is a correctness priority.
* **needs owner**: following hosted would be unsafe or would delete a
  working feature. Listed under "Calls that go against hosted" for the
  owner to decide.
* **target-specific**: the difference comes from where the entry points
  (a Socket URL or a committed path) and stays.

## Calls that go against hosted (owner decided 2026-11-04 and 2026-11-05)

Owner: the false Maven attestations get fixed, the modes are ground truth
over the readers, and the vendored mode's profile, reactor and scala-cli
support is back-ported so hosted gains it as the planners merge. P3 and P4
follow from the install-tree decision. N11 was decided on 2026-11-05.

"(draft)" after a PR number means that PR is open and not merged yet.

| # | Question | Hosted today | Decision |
|---|---|---|---|
| J1 | Does a base-version Maven dependency declared in a `<profiles>` block block attestation? | Warns, still pins the top level and counts the package as redirected (`patch/redirect/mod.rs` ~8744) | Vendored's rule: any profile declaration at the base version makes the ref unattested (fixed now in discovery), and the merged planner rewrites profile declarations in both modes. |
| J3 | Which Maven poms count? | Refuses a reactor root (~8572) | The reactor reader becomes the shared core, so hosted gains reactor support. |
| J12 | scala-cli | Guidance only (`patch/redirect/scala_guidance.rs`) | Back-port: hosted wires scala-cli through the merged planner (a same-GAV Socket repository instead of a suffixed version). |
| P3 | Is a shadowed `pdm.lock` rewritten? | Only when it governs (`pdm_drives`, ~564) | Rewrite it like every other tree, per the install-tree decision. |
| P4 | Are `-r` includes of `requirements.txt` rewritten? | Root file only (`patch/redirect/requirements.rs` ~208) | Follow includes, per the install-tree decision. An include outside the repository root stays bounded in workspace runs: never read or rewritten (owner, 2026-11-05; #2025 (draft)). |
| N11 | Is a `shrinkwrap.yaml` beside `pnpm-lock.yaml` rewritten? | Yes; its all-or-nothing gate covers both files | **Owner decision (2026-11-05): shadowed.** Swept for stale identities, never written, and out of the all-or-nothing gate. pnpm never reads it, and an unparseable debris key in it can refuse the dependency in every lock. When the project's pnpm evidence pins pnpm 1 / 2, `shrinkwrap.yaml` governs instead and vendored mode refuses. Fixed in #2029 (draft). |

## JVM

| # | Question | Today | Resolution | Flag |
|---|---|---|---|---|
| J2 | Does an executable classifier variant (`tests`, native) of the patched package block attestation? | Hosted skips the dependency. Discovery marks it unattested. Vendored only warns, then `entry_wired_checked` attests (`vendor/jvm/maven_reactor.rs` ~1884, `vendor/jvm/apply.rs` ~1042). | Hosted | false attestation |
| J4 | How are `${prop}` versions resolved, and does `.mvn/maven.config` win? | Discovery: one level of pom properties, no `-D` user properties. Hosted refuses `${…}`. Vendored: user properties, parent chain, profiles, depth 16. | One interpolator (vendored's). Hosted's refusal stays a writer policy. | false attestation |
| J5 | Do Gradle lockfiles gate liveness? | Hosted and discovery check every lock. Vendored reads none (`vendor/jvm/gradle.rs` ~1227). | Hosted | false attestation |
| J6 | Is sbt resolution evidence required before attesting? | Hosted: no integrity without verified evidence. Vendored: `wired_checked` only checks the owned-file row; discovery's `vendored_check` diagnostics are never consumed. | Hosted. One evidence route (`ResolutionDoc` + `gate::check_new`). | false attestation |
| J7 | Another version of a mapped NuGet id is locked | Both writers refuse. Discovery emits a ref per locked version, keyed by raw text, not `normalize_nuget_version`. | Hosted: a diagnostic, no ref | false attestation |
| J8 | What counts as "wired" for vendored Maven liveness and GC? | Vendored: substring match on masked text, so a suffix in `<build>`, a profile or `<properties>` counts. Discovery and hosted use the scoped `PomScope`. | Scoped reader | |
| J9 | `checksums.sha256` and the `TRUSTED_CHECKSUMS_ON` switch | Four readers with different splitting and switch tests. Hosted's merge silently drops lines it can't split on two spaces. | One reader with the hosted grammar. The merge keeps lines it can't parse. Fixed in #2016 (draft). | |
| J10 | Gradle Socket index rows | Two parsers. Hosted validates the uuid, URL and hashes; vendored accepts any token and uses a raw `split('\t')`. Vendored checks only root settings; hosted checks every build. | One row grammar, hosted's validation | |
| J11 | `verification-metadata.xml` | Two editors, no reader | One editor; a reader for the inventory | |
| J13 | NuGet config scope | Writers read inherited parent configs; discovery doesn't. Discovery refuses a disabled Socket source; the writers don't check `<disabledPackageSources>`. | Shared inheritance read, bounded to the repository root in workspace runs; global runs, and runs without a git checkout, read parent configs as before (owner, 2026-11-05; #2025 (draft)). The writers adopt the disabled-source refusal. | |
| J14 | NuGet lock enumeration | In-memory views fall back to the root lock. The unwind bypasses the snapshot view (`governed_locks_on_disk`). | One enumeration over `ProjectView` | |
| J15 | JVM liveness on a read error | `entry_wired` is `unwrap_or(true)` for `scan`/`vendor`; `vex` uses the checked variant | Fail closed everywhere | false attestation |

## Python

| # | Question | Today | Resolution | Flag |
|---|---|---|---|---|
| P1 | Which files count? | Hosted rewrites every file except a non-governing `pdm.lock`. Vendored picks one winner and warns that the rest stay unpatched. The inventory uses a chain. Discovery reads every lock with the cross-lock contest. `formats/governing_locks.rs` still gates four callers. | One tree per tool lock (owner decision). Vendored wires every tree. `governing_locks` goes. | |
| P5 | Does the inventory list Socket entries? | It keeps hosted entries (with the patched artifact's URL and hash) but drops vendored uv path sources | Keep both, read as the package they replace. Check that vendor's pristine fetch and `repair` never take patched bytes from a hosted entry. | |
| P6 | What counts as Socket wiring? | Discovery and the unwind use the host allowlist. The inventory accepts any host. Ledger liveness uses `resolved.contains(uuid)`. `poetry_lock::lock_wiring` uses `contains("/patch/pypi/")`. | The `origin` allowlist everywhere | false attestation (liveness substring) |
| P7 | uv workspace roots | Hosted refuses members only. Vendored refuses roots too. | Vendored wires roots, after a test that a member's own `[tool.uv.sources]` can't override the root | |
| P8 | `uv.lock` without `pyproject.toml` | Hosted edits the lock; discovery attests it. Vendored refuses. | Vendored proceeds | |
| P9 | uv 0.2 `[[distribution]]` locks | Hosted rewrites. Vendored refuses (no portable path). The unwind refuses to restore them. | Vendored's refusal is target-specific and stays. The unwind must restore what hosted writes (#2014 (draft)). | target-specific |
| P13 | PDM `lock_version` | Writers use an allowlist; discovery a denylist; the inventory checks nothing | The allowlist everywhere | |
| P14 | `pipfile-spec` | Writers require 6; discovery and the inventory accept any | 6 everywhere | |

## Cargo, Go, Ruby, Composer

| # | Question | Today | Resolution | Flag |
|---|---|---|---|---|
| G1 | Which `go.work` and members count? | Discovery: a root `go.work` and in-root members only, ignoring an ancestor `go.work`, `GOWORK` and `-modfile`. Hosted and vendored resolve the workspace go would use (`vendor/go_workspace.rs`). | `go_workspace::load` everywhere (discovery: #2011 (draft)). In workspace runs it never reads above the repository root, and a `go.work` there makes the modes refuse and discovery withhold; global runs, and runs without a git checkout, find the ancestor `go.work` as before (owner, 2026-11-05; #2025 (draft)). | false attestation |
| G16 | Go inventory | Root `go.sum` only, lenient parse, lists `patch.socket.dev/gopatch/<uuid>` lines as packages | Discovery's model and workspace | |
| C2 | Which manifests decide whether a Cargo lock entry is used? | Hosted pins root and member manifests; vendored reads members. Discovery reads only the root `Cargo.toml`. | Members everywhere | false attestation |
| C11 | `cargo vendor` / local-registry source replacement | Hosted refuses; vendored and discovery ignore it | Stays | target-specific |
| R10 | `gems.rb` / `gems.locked` | Hosted wires the pair bundler loads. Vendored refuses any `gems.rb`. | Vendored supports it | |
| R15 | Malformed Gemfile.lock | Discovery reports it unparseable; the inventory lists what parsed | Discovery's rule everywhere | |
| X12 | `composer.lock` with a BOM | Discovery strips it. The inventory drops the file. Vendored refuses to plan, errors on revert, and reports nothing stranded. | Strip one BOM everywhere. Check that GC never trusts the empty "stranded" answer. The inventory part in #2017 (draft). | |

## npm family

| # | Question | Today | Resolution | Flag |
|---|---|---|---|---|
| N1 | pnpm `gitBranchLockfile` with a branch lock present: is the root lock the install tree? | Hosted withholds the root locks and refuses (`hosted/engine.rs` ~930). Vendored refuses. Discovery and the inventory never check the setting. | Hosted. Discovery withholds pnpm root and member-lock attestations whenever any `pnpm-lock.<branch>.yaml` exists, whatever the settings or environment say (owner, 2026-11-05; #2010 (draft)). | false attestation |
| N2 | npm user patches (#711) and `bun patch` (#367) | Hosted skips that one dependency and records it as refused. Vendored refuses the whole npm v4 lock, or the one bun dependency. Discovery never reads `patchedDependencies` / `"patched"` and attests a pre-#711 hosted pin. | Hosted's per-dependency skip, in discovery too, for every package manager's user patches (owner decision; #2010 (draft) for npm and bun, #2018 (draft) for pnpm, yarn and vlt). The override is the existing `--allow-patch-conflicts`; `vex` never attests under a user patch, even with it. | false attestation |
| N3 | A workspace member's stray npm/bun/vlt lock | Discovery treats it as absent. Hosted and vendored refuse. The inventory reads it as the project's lock. | The inventory ignores it | |
| N4 | pnpm 11's env-lockfile document | See [Decisions](lock-model-unification.md#decisions-under-the-hosted-rule). `main_document` takes the text after the last `---`, so a crafted multi-document lock chooses its own "project". | Its own tree; documents identified by content, not position. **Resolved in PR 2a (#2009)**: every reader reads both documents through `PnpmLock`, each entry tagged by document; discovery records carry the env document's install tree (`TreePart::PnpmEnv`) beside the real lock path, and that tree neither contests nor is contested by the project document or another lock; the env document is the FIRST document when its importers carry only `configDependencies` / `packageManagerDependencies` (pnpm's own position rule), and every other document is read as the project. | |
| N5 | What counts as Socket wiring | Discovery and the unwind use the allowlist. The inventory records hosted URLs on any host. `parse_vendor_path` accepts `.socket/vendor/` anywhere, so a `../.socket/vendor/…` entry from a sibling checkout is "ours" to the vendored writer and reverter. The hosted pnpm "vendored?" check is a substring heuristic. | The `origin` classifier everywhere. The vendored writers, reverters and GC claim only this project's vendor paths in #2025 (draft). pnpm part **resolved in PR 2a (#2009)**: the hosted pnpm "vendored?" check reads the rekeyed packages entry with `origin::vendor_ref`; the planner follows in #2029 (draft). | revert could rewrite another project's wiring |
| N6 | `npm-shrinkwrap.json` and `package-lock.json` | Hosted, vendored and discovery read both, with a contest. The inventory reads the shrinkwrap only. | Both, everywhere | |
| N7 | npm lockfileVersion | Hosted rewrites v1 and v4. Vendored accepts v2/v3 only. The inventory ignores v1. Discovery reads v1 and v2+. | Hosted, once vendored `file:` wiring under npm 6 and npm 12.1 v4 has fixtures | |
| N8 | npm `file:` directory link identity (#1481) | Hosted and discovery give a versionless link its source directory's `name@version`. Vendored matches the entry's own version, wiring the registry copies with no warning. | Hosted | silent vendored success |
| N9 | yarn classic blocks reached only through an alias | Hosted skips them. Vendored rewrites them. Discovery counts an alias block as an install of the real package. | Back-port: hosted rewrites alias blocks (vendored supports what hosted lacks) | |
| N10 | Locks of several npm-family package managers in one project | Hosted rewrites every family; discovery reads every family with the contest. The inventory and vendored pick one family (vlt > bun > pnpm > yarn > npm). | Union (separate trees) | |
| N11 | `shrinkwrap.yaml` beside `pnpm-lock.yaml` | Hosted reads and splices it, and its all-or-nothing gate covers both. Discovery sweeps it as ignored. The inventory reads it only as a fallback. Vendored never reads it. | Shadowed (owner, 2026-11-05; see above). Fixed in #2029 (draft). | |
| N12 | Rush common and subspace locks | Hosted and discovery always read them. The inventory reads them only when there is no root lock (#2003 aligns the listing itself). Vendored refuses Rush. | Always read. Vendored's refusal stays. **Resolved in PR 2a (#2009)** (the inventory reads them whenever `rush.json` exists). | target-specific (vendored) |
| N13 | Plug'n'Play | Vendored refuses. The hosted berry preflight has no PnP gate. The inventory returns an error, so `scan` sees nothing in a project hosted pinned. | The inventory reads PnP locks. Vendored keeps its refusal. | target-specific (vendored) |
| N14 | pnpm `lockfile=false` | Hosted refuses. Discovery withholds hosted refs, keeps vendored ones. Vendored proceeds. The inventory ignores the setting. | The modes stay as they are; the inventory follows discovery. **Resolved in PR 2a (#2009)**: under the setting (not under Rush), the inventory keeps a Socket-hosted pnpm entry but drops its integrity, as discovery withholds the lock pin. | target-specific |
| N15 | CRLF `pnpm-lock.yaml` / `pnpm-workspace.yaml` | Vendored refuses; the rest handle it | Handle it everywhere | |
| N16 | Lock versions | pnpm: vendored accepts only 5.4/6.0/9.0; hosted any but early shrinkwrap. vlt: vendored refuses a lock with no version; hosted rewrites and warns. | Hosted | |
| N17 | Bun workspaces, yarn classic offline mirror | Refused differently by the two modes | Stays | target-specific |
| N18 | An unparseable npm lock | Hosted warns and skips. Vendored refuses the primary lock. Discovery diagnoses. The inventory returns nothing silently. | Discovery's diagnostic, surfaced by every consumer | |
| N19 | yarn.lock with a stray top-level line | Discovery rejects the file; hosted and the inventory scan its blocks | Discovery's rule | |
| N20 | Yarn's last-block-wins (`live`) | Discovery respects it; the inventory and both hosted yarn rewriters don't | Respect it everywhere | |
| N21 | Accepted npm-family integrity | The inventory records any string as SRI; discovery requires an SRI pin (`sha1-` included) | Discovery's check | |

## Fixes for false attestations on main

These are fixed directly against `main`, ahead of the stack, in their own PRs.
The stack rebases over them.

| # | Fix | PRs |
|---|---|---|
| J1, J4 | Maven discovery: a profile declaration or a `.mvn/maven.config` user property that resolves the base version leaves the ref unattested | #2005, #2020, #2026 (draft) |
| J2, J8, J15 | Vendored Maven liveness: executable classifiers block, "wired" is read from scoped declarations, read errors fail closed | #2006 (draft) |
| J5 | Vendored Gradle liveness reads the lock files | #2004 (draft) |
| J6 | Vendored sbt attestation requires resolution evidence | #2008, #2030 (draft) |
| J7 | NuGet discovery: no ref for a version the writers refuse | #2007 (draft) |
| N1, N2 | pnpm branch locks and npm/bun user patches in discovery; pnpm, yarn and vlt user patches everywhere | #2010, #2018 (draft) |
| G1 | Go discovery reads the governing `go.work` | #2011 (draft) |
| C2, P6 | Cargo members in discovery; liveness matches uuids by origin, not by substring | #2012, #2019, #2024 (draft) |
| G1, J13, P4, N5 | Reads bounded to the repository root in workspace runs (owner, 2026-11-05) | #2025 (draft) |

## Planner merges (hosted and vendored)

Estimated implementation lines removable by giving each format one planner
whose only parameter is the target:

| Format | Today | Estimate |
|---|---|---|
| uv.lock | Vendored's text surgery in `vendor/pypi_uv.rs` duplicates hosted's `PythonLockSession` | 1,000–1,400 |
| NuGet | `add_nuget_source` / `rewrite_nuget` against `vendor/nuget_feed.rs`'s config edit, which says it mirrors it | ~400 |
| Gradle | Build discovery, apply-line helpers, index parse and merge, owned script, verification edits | 500–700 |
| Maven | Hosted is a root-only subset of the reactor planner. Four pom parsers collapse to one (`maven_reactor::Doc` survives). | largest; split readers first |
| sbt | Build-source refusals and per-pin decisions; one evidence route | 150–250 |
| Python router | `detect_pypi_flavor` and hosted's fixed chain become one query over trees | ~300 |
| requirements, Pipenv, Poetry, PDM | Shared lexers or rewriters already; preflight and matchers duplicated | a few hundred |
| Cargo | Dependency-table walk, member enumeration, CRLF handling | a few hundred |
| Go | Version-selected and in-graph checks | ~100 |
| Gem | Pair selection and spec-block moves | a few hundred |
| Composer | Regex splice against JSON re-serialization; one locator and one splice | ~300 |
| Unwind | The hosted `upstream/*` modules mirror the vendored unplans and become one unplan per format | follows the planner merges |
