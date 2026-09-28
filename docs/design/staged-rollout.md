# Staged patch rollout: `socket.yml` patch policy + `scan --max-new-patches`

Status: **planned** (v5.0). Target branch `release/v5-prerelease`.
Two work items, built in parallel: **A** (policy file + filters) and
**B** (per-run limit + ordering + reporting). Section 9 specifies both.

## 1. Goal

Make it easy to roll Socket patches out gradually:

1. **Repo policy in `socket.yml`.** Say which projects, ecosystems and
   packages socket-patch may patch, and a severity floor. Defaults apply
   when the file or the block is absent. The hard-coded repo-path filter
   that exists today moves here as an overridable default.
2. **A per-run cap on new patches.** `scan` adds at most N patches to
   packages that have none yet, most severe first. Repeated runs converge:
   each run lands the next N.

Non-goals: open-PR accounting (a CLI patching a working tree has no PR
state; that stays in depscan), schedules, release-age cooldowns (security
fixes are exempt from cooldowns in Dependabot and Renovate too), and
per-directory `socket.yml` files.

## 2. What exists today (research summary)

### 2.1 `socket.yml` v2 and its consumers

| Parser | Where | Unknown top-level keys | Wrong type on a known key |
|---|---|---|---|
| P1 `@socketsecurity/config` 3.0.1 (archived; bundled in `socket` 1.x) | `socket-config-js/index.js:30-88` | stripped (ajv `removeAdditional: 'failing'`, `additionalProperties: false` at top level and under `githubApp`) | file rejected |
| P2 depscan copy (GitHub App, fix-PR) | `workspaces/lib/src/config-js/socket-yaml-schema.ts`, `parse-socket-yaml.ts` | stripped (same ajv options) | whole file rejected; PR check goes neutral with "error processing the socket.yml" (`diff-report-runner/index.ts:441-464`) |
| P3 socket-cli 2.x | `src/util/socket-yaml.mts` | ignored (hand-written picker) | that key dropped |
| P4 Coana | not available | unverified | reads `projectIgnorePaths` only |

- Keys in the wild: `version` (integer; P1/P2 accept any integer, P3
  rejects anything but 2), `projectIgnorePaths`, `triggerPaths`,
  `issueRules`, `githubApp.*`. Nothing mentions patches.
- **A new top-level `patches:` key breaks no parser** as long as the file
  keeps `version: 2`. P1/P2 strip it, P3 ignores it. None of them will
  ever see it; socket-patch is its only reader.
- Lookup: the GitHub App reads only the repo-root `socket.yml` /
  `socket.yaml` at the scanned commit, and when both exist `socket.yaml`
  wins (git tree order, `get-socket-repo-config.ts:96-120`). socket-cli
  walks up from cwd and prefers `socket.yml`. The docs say `socket.yml`
  wins. Nobody merges multiple files; there are no per-directory files.
- Glob semantics (backend): the `ignore` npm package, i.e. **gitignore
  rules**, case-insensitive (`list-files.ts:476-507`). A leading `/` or a
  middle `/` anchors to the repo root, a bare name matches at any depth, a
  trailing `/` matches directories only, `!` negates, last match wins, a
  child of an excluded directory cannot be re-included.
- An unquoted `**` entry is a YAML error. Case-insensitivity and the
  "excluded parent" rule are the two things users trip over.

### 2.2 socket-patch v5 today

- Selection per package: `socket_patch_core::api::ranking`
  (`ranking.rs:85`): merged patches (>= 2 advisories) newest first, then
  severity, then publish date, then tier/uuid. `RankKey.severity` is forced
  to 0 for merged patches, so it is **not** the patch's real severity.
  `severity_order` (`ranking.rs:41`) and `max_severity_order` are.
- Per-patch data: severity (max, uppercase), advisory ids, tier, optional
  `publishedAt` (batch endpoint usually lacks it). No CVSS, EPSS, KEV,
  reachability or direct/transitive information anywhere.
- Scan selects patches in five disk call sites plus one in the in-memory
  engine: `discover_selected` (`scan/mod.rs:553`, called from `mod.rs:1999`,
  `hosted.rs:1063`, `vendor_flow.rs:459`, `mod.rs:2349`), the human
  agent/vendored arm (`mod.rs:2386-2402` via `get.rs:1097`), and
  `hosted_memory/discover.rs:286` (`select_top_ranked`, called at
  `hosted_memory/mod.rs:537`).
- Existing filters: `--ecosystems`, `--package` (`package_spec_matches`,
  `mod.rs:383`), PATH globs (`path_scope.rs`), all applied after the prune
  universe is captured (`mod.rs:1480`).
- Recorded state: `merge_ledger_records_for_updates` (`discovery.rs:412`,
  manifest > hosted lockfile pins > vendor ledger) and `detect_updates`
  (`discovery.rs:452`) with `batch_supersedes` (`ranking.rs:157`). The
  in-memory engine has **no** hosted-pin discovery.
- `docs/design/configuration.md` said socket-patch never reads
  `socket.yml`. This plan reverses that (section 3); the doc is updated in
  the same PR.

### 2.3 Hard-coded filtering inventory

socket-patch (paths relative to `crates/`):

| # | Location | What | Verdict |
|---|---|---|---|
| H1 | `socket-patch-cli/src/hosted_memory/roots.rs:56-67` `EXCLUDED_ROOT_SEGMENTS` | the in-memory engine never detects a project root under `node_modules .git .socket .yarn vendor test tests fixtures __fixtures__ testdata` | **Move** `test tests fixtures __fixtures__ testdata` to the overridable default `ignorePaths` (section 4.3), applied on disk too. Keep `node_modules .git .socket .yarn vendor` structural. |
| H2 | `socket-patch-core/src/crawlers/npm_crawler.rs:19-27` `SKIP_DIRS` (dist build coverage tmp temp `__pycache__` vendor) | npm workspace walk looking for nested `node_modules` | Stays: crawler heuristic, not selection policy |
| H3 | `socket-patch-cli/src/hosted_memory/select.rs:46,53-70` | cargo `target/` and `cargo vendor` output skipped | Stays: correctness |
| H4 | `socket-patch-cli/src/hosted_memory/roots.rs:40-53` | maven/nuget unsupported in memory | Stays: capability |
| H5 | `socket-patch-cli/src/hosted_memory/mod.rs:274` `ecosystem_allowed` | `options.ecosystems` | Stays: the in-memory `--ecosystems`; intersects with the file |
| H6 | `crawlers/python_crawler.rs:288`, dot-dir skips in `cargo_crawler.rs:373`, `go_crawler.rs:344`, `nuget_crawler.rs:236`, `ruby_crawler.rs:576` | discovery locations | Stays: crawler heuristics |
| H7 | `ruby_crawler.rs:823` BUNDLE_PATH containment | refuse config roots outside the project | Stays: **safety** |
| H8 | `scan/mod.rs:596-603`, `get.rs:1101-1107` tier filter | paid patches for free orgs | Stays: entitlement |
| H9 | `scan/mod.rs:723-762` agent partition | vendored / not-installed skips | Stays: ownership safety |
| H10 | `scan/hosted.rs:1256-1296` non-granted references | not_found, forbidden, pending_build, build_failed, withdrawn | Stays: server truth |
| H11 | `hosted.rs:1352-1402`, `hosted.rs:1448`, core rewriter refusals, vendor revert allowlists, `vlt_lock_text.rs:311` | write safety, format gates, ledger-poisoning guards | Stays: **safety** |

No package-name, uuid or repo denylists exist anywhere in socket-patch.

depscan (`feat/socket-patch-cli-autopatch`, PR #26860; `workspaces/app/src/autopatch-pr/cli/` unless noted):

| # | Location | What | Verdict |
|---|---|---|---|
| D1 | `run-job.ts:94-102,293`; `next-app/.../socket-patch-cli/enqueue.ts:104` | per-org `socketPatchCliAutopatch` flag | Server (kill switch) |
| D2 | `provider/create-patch-provider.ts:189-279` | `enablePatchesAccess`, paid entitlement | Server (entitlement) |
| D3 | `lib/src/socket-patch/autopatch-job.ts:152-169` | per-job admin `config.ecosystems` allowlist, `batchSize` (lookup batch, not a patch cap) | Server; ecosystems **intersect** with `patches.ecosystems` |
| D4 | `repo-files.ts:290-513` | tree/path/size/depth caps, unsafe path drops | Server (safety) |
| D5 | `pull-request-rules.ts:473-491` | fork/default/protected heads are check-only | Server (safety) |
| D6 | `next-app/src/lib/admin/autopatch/socket-patch-cli-branches.ts:10-31` | branch-name guards | Server |
| D7 | legacy `patch-pr-worker.ts:65-109`, `github-patch-pr.ts:262-283,1598-1740`, `github-patch-pr-hosted.ts:196-486`, `compute-full-patch-set.ts:41-273` | already-applied, not-in-SBOM, unpublished, deprecated, vlt gates | Server (correctness); not policy |

Nothing in depscan filters by repo path, package or severity, and nothing
caps patches per PR. The only repo-path policy in the whole system is H1,
and it lives in the engine. It is the one hard-coded filter that moves.

### 2.4 Prior art (vocabulary borrowed, complexity not)

| Tool | Limit | Counts | Order when capped |
|---|---|---|---|
| Dependabot | `open-pull-requests-limit` (5; security updates exempt) | open PRs | undocumented; shuffled |
| Renovate | `prConcurrentLimit`, `prHourlyLimit` (security fixes bypass) | open PRs / new per hour | vulnerability, `prPriority`, update type, title |
| Snyk | 5 open upgrade PRs; backlog "one PR a day, top vulnerability" | open PRs / per day | priority score |
| GitLab auto-remediation | 10 open MRs, "three vulnerabilities at a time, highest severity first", `high` threshold | open MRs + per run | severity |
| OSV-Scanner | `--apply-top=N`, `--min-severity` | per run | fixed |

Borrowed: gitignore paths (`projectIgnorePaths`), `include`/`ignore`
pairs, `enabled`, a severity floor spelled as a minimum (`--min-severity`,
Snyk/GitLab/OSV), a per-run new-item cap (GitLab/OSV/Snyk backlog), a
fixed total order (not Dependabot's shuffle), deny-wins.

## 3. Trust boundary (decision)

The rule in `CLI_CONTRACT.md` ("Repo-level files never carry endpoints,
credentials, or interlock-disablers") stays and gains its positive half:

> A repository file may **narrow or pace** what `scan` patches. It may
> never widen it, name an endpoint or credential, pick a mode, or turn off
> a safety check.

Every `patches:` key only removes candidates (`enabled`, `includePaths`,
`ignorePaths`, `ecosystems`, `packages`, `ignorePackages`, `minSeverity`)
or delays them (`maxNewPatches`). No key can add a package, bypass the tier
filter, the agent partition, reference grants, containment checks or any
refusal in H7-H11. The parser has no fields for URLs, tokens, org, mode,
download mode or any `--no-*` safety switch; such keys are unknown keys and
fail validation (4.4).

Failure direction follows from that: because the file only narrows, an
unreadable or invalid policy must not mean "no policy". It fails closed.

## 4. `socket.yml` grammar (work item A)

### 4.1 Keys

```yaml
version: 2                     # required for socket-patch to honor `patches`
projectIgnorePaths:            # existing scanner key; socket-patch honors it too
  - "crates/*/tests/fixtures/**"
patches:                       # new; every key optional
  enabled: true                # bool. Default true. false = report only.
  includePaths: ["/services/payments/"]   # gitignore list. Absent = every project.
  ignorePaths: ["/legacy/"]    # gitignore list, added after the defaults. Default [].
  ecosystems: [npm, pypi]      # allowlist of --ecosystems names. Absent = all.
  packages: ["lodash"]         # allowlist of --package specs. Absent = all.
  ignorePackages: ["pkg:npm/left-pad"]  # denylist of --package specs. Default [].
  minSeverity: high            # critical|high|medium|moderate|low. Absent = no floor.
  maxNewPatches: 5             # integer >= 0. Absent = unlimited. 0 = upgrades only.
```

- camelCase, like every existing socket.yml key.
- Ecosystem names are `Ecosystem::cli_name()`: `npm pypi cargo gem golang
  maven composer nuget deno`, case-insensitive.
- Package specs use exactly the `--package` grammar and matcher
  (`package_spec_matches`): a name (full or last segment,
  case-insensitive) or a purl with or without a version; qualifiers
  ignored.
- `moderate` is an alias of `medium`, as in `severity_order`.
- Deny wins: `ignorePackages` beats `packages`, ignore paths beat
  `includePaths`.

### 4.2 Precedence against flags and env

| Setting | Rule |
|---|---|
| List filters (`includePaths`/`ignorePaths`/`projectIgnorePaths` vs PATH args; `ecosystems` vs `--ecosystems`; `packages`/`ignorePackages` vs `--package`) | **intersect**: flags narrow further, never widen |
| `minSeverity` | `--min-severity <critical\|high\|medium\|low\|none>` > `SOCKET_MIN_SEVERITY` > file > no floor |
| `maxNewPatches` | `--max-new-patches <N\|none>` > `SOCKET_MAX_NEW_PATCHES` > file > unlimited |
| whole file | `--no-socket-yml` / `SOCKET_NO_SOCKET_YML` skips the file (built-in default path ignores still apply) |

Scalars follow the contract's CLI > env > default order, with the file as
the layer above the default. The person running the CLI is trusted; the
file is the repo's default. (depscan adds its own server ceiling, section
7.) Every new flag has an env binding, as the contract requires.

### 4.3 Paths

- **Subject.** Path rules decide which *project roots* are patched: the
  directory holding the lockfile/manifest, relative to the repo root, with
  `/` separators, tested as a directory. The rule is the same in every
  mode, including agent mode (its project is `--cwd`).
- **Semantics.** gitignore, identical to the backend's `ignore` package:
  Rust `ignore::gitignore::GitignoreBuilder` with `case_insensitive(true)`,
  anchored at the repo root, `matched_path_or_any_parents` so a directory
  pattern covers everything under it.
- **Repo-root project.** gitignore cannot match the empty path, so in
  `patches.includePaths` / `patches.ignorePaths` the literal entry `/`
  (and `!/`) means "the repository-root project". It has no meaning in
  `projectIgnorePaths`, which stays scanner semantics.
- **Evaluation order** (last match wins):
  1. built-in defaults: `test/ tests/ fixtures/ __fixtures__/ testdata/`
  2. `projectIgnorePaths`
  3. `patches.ignorePaths`

  A user re-includes a default with a negation, e.g.
  `ignorePaths: ["!/e2e/tests/"]`. Adding an unrelated ignore never
  silently re-enables fixtures.
- **Admission.** A root is admitted iff it is not ignored by the list
  above AND (`includePaths` is absent OR `includePaths` matches it).
- **Defaults apply to discovered roots only.** Built-in defaults (step 1)
  prune roots the tool discovers (in-memory root detection; disk PATH-glob
  expansion). A directory the user names explicitly (`--cwd`, a literal
  PATH) is exempt from step 1 but not from steps 2-3 or `includePaths`.
- **Structural excludes** (`node_modules .git .socket .yarn vendor`) stay
  hard-coded and cannot be negated.
- **Granularity.** A workspace member that shares the root lockfile is part
  of the root project; exclude it with `ignorePackages`, not paths.
  Documented.
- A root excluded by the policy is reported as filtered (4.6) with the
  pattern that decided it and the list it came from.

### 4.4 Validation (fail closed)

socket-patch validates only what it reads: `version`, `projectIgnorePaths`
and `patches`. Other top-level keys are never inspected.

| Situation | Behavior |
|---|---|
| No file | Defaults. |
| YAML syntax error, duplicate key, top level not a mapping, file over 64 KiB, symlink resolving outside the repo root | **Error** `socket_yml_invalid` |
| `patches` present and `version` is not `2` (integer 2 or the string `"2"`, matching ajv coercion), including a missing `version` | **Error** `socket_yml_invalid` ("patches requires version: 2") |
| No `patches` and `version` is not 2 | File ignored (a v1 or future file is not ours to judge); warning `socket_yml_unsupported_version` |
| Unknown key under `patches` | **Error**, with a did-you-mean hint when one key is within edit distance 2 |
| Wrong type (no coercion: `"false"` is not a bool; YAML 1.2 so `no` is a string), unknown ecosystem or severity, `maxNewPatches` negative or non-integer, invalid glob or package spec, `projectIgnorePaths` not a list of strings | **Error** naming the key path (`patches.minSeverity`) and the file |
| Top-level key equal to `patch`/`patches` ignoring case but not exactly `patches` (`Patches:`, `PATCH:`, `patch:`) | **Error**: a misspelled block must not silently mean "no policy" |
| Both `socket.yml` and `socket.yaml` at the root | Parse both. If the parts socket-patch reads (`projectIgnorePaths`, `patches`) are equal, use them; otherwise **error** `socket_yml_ambiguous` naming both. The existing consumers disagree on which file wins, so we refuse to pick. |

**Error behavior:** before any write, `scan` exits **1** with
`errorCode: socket_yml_invalid` (or `socket_yml_ambiguous`), a human
message naming file, key path and remedy (fix the file, or
`--no-socket-yml`), `--json` stdout still a valid envelope. Exit 1, not 2:
it is a bad input file, like an invalid manifest, not a usage error.

**Forward compatibility.** A strict parser means an older pinned CLI fails
on a key a newer CLI understands. That is deliberate (the alternative is a
silently wider rollout); the error text says "unknown key … (a newer
socket-patch may support it; upgrade or remove it)". The contract documents
that keys are only ever added in minor releases and never change meaning.

### 4.5 Lookup

1. Repo root := the nearest ancestor of `--cwd` (inclusive) containing
   `.git` (a directory, or a file for worktrees and submodules). With no
   `.git` ancestor, repo root := `--cwd` (never the home directory or
   filesystem root; socket-cli's unbounded walk could pick up an untrusted
   `/tmp/socket.yml`).
2. Read `<repo root>/socket.yml` and `<repo root>/socket.yaml` only.
   Nested `socket.yml` files are not read. One file per repo, as in the
   GitHub App.
3. The in-memory engine's repo root is the tree root it was given.
4. `--global` / `--global-prefix` scans have no repo and ignore the file.

### 4.6 Commands

| Command | Policy |
|---|---|
| `scan` (hosted, vendored, agent; wet and `--dry-run`), `hosted-bundle`, the napi engine | honor filters and limit |
| `get` | explicit intent: ignores filters and limit; warns `policy_bypassed` when the target would have been filtered |
| `apply`, `list`, `vex`, `rollback`, `remove`, `repair`, `vendor` (eject/revert) | ignore it: they report, attest or undo existing state |

**Narrowing never removes.** The policy runs after the prune universe is
captured (`mod.rs:1480`), so `--prune` still judges the full crawl. A
package that already has a recorded patch but is now excluded by paths,
ecosystems, packages or `enabled: false` is **retained**: not passed to the
hosted rewriters, vendor engine or agent apply; not upgraded; not taken
over; left byte-identical. It is reported under `policy.retained[]` with
`upgradeAvailable`. Removing a patch is only ever `rollback`/`remove`, or
the dependency leaving the lockfile.

`minSeverity` filters **candidates** before per-package ranking (so a
lower-ranked patch above the floor can still win), using the patch's real
severity (`severity_order` on `BatchPatchInfo.severity`, or
`max_severity_order` over `vulnerabilities`), never `RankKey.severity`.
With a floor set, a patch with unknown severity is filtered (fail closed).
A recorded patch below the floor stays in place; it is replaced only when a
candidate above the floor supersedes it under the existing
`batch_supersedes` rule, which is an ordinary upgrade.

`enabled: false`: discovery and the table still run; nothing is written;
every candidate is reported filtered with `policy_disabled`; warning
`patches_disabled`; exit 0. Upgrades are frozen too.

### 4.7 JSON (`policy` block, owned by A)

Additive top-level key on every `scan --json` result (MINOR), always
present:

```json
"policy": {
  "source": "file",                     // "none" | "file" | "bypassed"
  "path": "socket.yml",                 // repo-relative; null unless source=file
  "sha256": "…",                        // of the file bytes; null unless source=file
  "enabled": true,
  "minSeverity": {"value": "high", "source": "file"},   // value null = no floor; source flag|env|file|default
  "counts": {"filtered": 3, "retained": 1},
  "filtered": [
    {"purl": "pkg:npm/qs@6.5.2", "uuid": "…", "project": "services/legacy",
     "reason": "policy_path_excluded", "detail": "/legacy/ (patches.ignorePaths)"}
  ],
  "retained": [
    {"purl": "pkg:npm/lodash@4.17.20", "project": ".", "recordedUuid": "…",
     "reason": "policy_package_ignored", "upgradeAvailable": true}
  ]
}
```

- `uuid` is null when the package was filtered before any patch was looked
  up (path, ecosystem, package reasons).
- Reason codes (stable): `policy_disabled`, `policy_path_excluded`,
  `policy_path_not_included`, `policy_ecosystem`,
  `policy_package_not_listed`, `policy_package_ignored`, `policy_severity`
  (detail `unknown < high` or `medium < high`).
- A root filtered as a whole is one entry with `purl: null`.
- Human output: one line, e.g.
  `Policy (socket.yml): 3 skipped by filters, 1 patched package held.`
  and `--verbose` lists them.

## 5. Per-run limit (work item B)

### 5.1 Classification

After filtering and per-package selection, each selected `(project root,
purl, uuid)` row is classified against that project's recorded view
(`merge_ledger_records_for_updates`: manifest > hosted lockfile pins >
vendor ledger), with `detect_updates`' qualifier-twin handling:

| Class | Rule | Counts toward the cap |
|---|---|---|
| ALREADY | recorded uuid == selected uuid, or recorded uuid kept because the selection does not supersede it (`batch_supersedes`) | no; hosted re-confirms it idempotently as today |
| UPGRADE | recorded uuid differs and the selection supersedes it (existing `detect_updates` rule, including "recorded patch no longer offered") | no |
| NEW | no patch recorded for this base purl **in this project root** | **yes** |

- NEW is per project root. Widening `includePaths` from a pilot directory
  to more services makes piloted packages NEW in the added roots, and they
  go through the cap again. A patch already in another project is not a
  free pass.
- UPGRADEs are exempt (decision): rollout risk is about whether a package
  runs patched code at all, and an upgrade fixes more in a package that is
  already patched. Capping upgrades would leave known-superseded patches in
  place. To freeze everything, use `enabled: false`; `maxNewPatches: 0`
  freezes new packages only.

### 5.2 Budget and ordering

- **Unit:** a distinct **base purl** (ecosystem + name + version,
  qualifiers stripped) among NEW rows, run-wide: across every project root
  of one invocation (disk multi-directory human runs, every root of the
  in-memory engine). Admitting a base purl admits all of its NEW rows in
  every root. One package patched in ten roots costs 1.
- **Order** (ascending; a total order with no time-dependent keys):
  1. in-flight first (in-memory option `inFlightPatches` only, 7.2;
     absent on the CLI)
  2. real severity of the selected patch (`severity_order`: critical,
     high, medium, low, unknown)
  3. advisory count, descending (merged patches first within a severity)
  4. ecosystem `cli_name`, ascending
  5. canonical base purl, ascending bytewise (one shared core
     normalization function, used by disk and memory)
  6. uuid, ascending

  A base purl present in several roots uses the minimum key of its rows.
  `publishedAt` is deliberately **not** a key: the batch endpoint omits it,
  so using it would reorder the top N between runs and between the disk
  and memory engines. Per-package ranking (which patch a package gets)
  still uses `publishedAt` as today; this order only decides which
  packages go first.
- **Eligibility before budget.** A row consumes budget only if it can land
  this run: it passed the tier filter, the agent partition (vendored /
  not installed), the vendored preflight and, in hosted mode, its reference
  grant came back `granted`. Rows that cannot land (withdrawn,
  build_failed, pending_build, not_found, forbidden, refused) keep their
  existing skip reasons and do not hold a slot, so a permanently broken
  patch can never stall the rollout. Implementations may fetch references
  for every NEW candidate, or in rank-ordered batches until the budget is
  full; the resulting plan must be identical.
- **Write failures** after admission consume budget (the run stays bounded;
  no backfill within a run). They are reported as failures, as today.
- **`maxNewPatches: 0`** admits no NEW rows; ALREADY and UPGRADE proceed.
- Everything NEW beyond the budget is **deferred**: not written, not
  downloaded, not vendored, reported with its rank.

### 5.3 Convergence and determinism

- Same inputs, same plan, same bytes. The limit is stateless: run k lands
  the top N; on run k+1 they are ALREADY and the next N land. M waiting
  patches take ceil(M/N) committed runs.
- A newly published or re-scored higher-severity patch moves ahead of the
  queue. That is intended ("most critical first") and is visible because
  every deferred entry carries its rank and severity.
- Low-severity patches can wait indefinitely while higher ones keep
  arriving. Documented; it is the point of severity ordering.
- **CI that does not commit** the scan's result never advances recorded
  state, so a cap there means "only the top N, every run". Documented in
  the recipes: commit the lockfile changes (or use a PR bot), or do not set
  a cap in non-committing jobs.
- `pending_build` references are transient: a row can be ineligible one
  run and eligible the next. The plan is still a function of the inputs.

### 5.4 Modes

| Mode | Recorded state | NEW/ALREADY/UPGRADE source | Deferred rows |
|---|---|---|---|
| hosted (disk) | lockfile hosted pins (`HostedPin`) | recorded view | never granted, never rewritten; mirrored into `redirect.skipped[]` with reason `rollout_deferred` |
| vendored | `.socket/vendor/state.json` | ALREADY = `already_vendored`, UPGRADE = `would_revendor` | never downloaded or vendored |
| agent | `.socket/manifest.json` | ALREADY = `skipped`, UPGRADE = `updated` | never downloaded; not in `apply.patches[]` |
| in-memory (napi, hosted-bundle) | hosted pins discovered from the in-memory lockfiles (**new**, B) | same | in `ProjectResult.deferred[]` and `skipped[]` with `rollout_deferred` |

`--dry-run` makes exactly the same decisions and reports them the same way.
A takeover of an existing vendored or hosted entry counts as recorded, not
NEW.

### 5.5 JSON (`rollout` block, owned by B)

Additive top-level key on every `scan --json` result (MINOR), always
present:

```json
"rollout": {
  "maxNewPatches": {"value": 5, "source": "file"},   // value null = unlimited; source flag|env|file|default|cap
  "counts": {"new": 5, "deferred": 9, "upgrade": 1, "already": 12},
  "deferred": [
    {"purl": "pkg:npm/minimist@1.2.5", "uuid": "…", "severity": "critical",
     "advisoryCount": 1, "projects": ["services/api", "services/web"], "rank": 6}
  ]
}
```

- `counts.new` is the number of NEW base purls admitted this run
  (landed, or would land under `--dry-run`); `deferred` lists the rest in
  rank order; `rank` is 1-based across all NEW candidates.
- Human output (hosted/vendored/agent summary, then the Next-steps
  renderer):

  ```
  Rollout: 5 of 14 new patches applied (maxNewPatches=5 from socket.yml); 1 upgrade, 12 already applied.
  Next steps:
    9 new patches deferred; commit these changes and run scan again to apply the next 5.
    Next up: minimist@1.2.5 (critical), qs@6.5.2 (high), …
  ```
- Exit code unchanged (0) when patches are deferred or filtered.
- `jq` recipe for CI: `jq '.rollout.counts.deferred'`.

## 6. Rollout recipes

```yaml
# R1 Canary: one new patch per run
version: 2
patches:
  maxNewPatches: 1
```

```yaml
# R2 Critical first: critical only, then widen by editing one line
version: 2
patches:
  minSeverity: critical   # later: high, then remove
  maxNewPatches: 5
```

```yaml
# R3 One directory first (monorepo)
version: 2
patches:
  includePaths:
    - "/services/payments/"
    # add "/services/checkout/" next sprint
  maxNewPatches: 5
```

```yaml
# R4 One ecosystem, hold one package
version: 2
patches:
  ecosystems: [npm]
  ignorePackages: ["pkg:npm/left-pad"]
```

```yaml
# R5 Weekly drip with the depscan autopatch PR
version: 2
patches:
  maxNewPatches: 5        # the PR keeps the same 5 until merged, then the next 5
```

```yaml
# R6 Pause
version: 2
patches:
  enabled: false          # report only; existing patches stay in place
# or keep upgrades flowing but add nothing new:
#   maxNewPatches: 0
```

One-off overrides from the command line: `socket-patch scan
--max-new-patches none` (drain the queue this run), `--min-severity none`,
`--no-socket-yml` (ignore the file entirely).

## 7. depscan autopatch service

### 7.1 Behavior with the new engine

- `repo` jobs rebuild one commit from the base SHA each run. With
  `maxNewPatches: 5`, "recorded" means pinned on the **base** branch, so
  every rebuild proposes the same top 5 until the PR merges, then the next
  5. No churn, no new PR per batch.
- `pull_request` jobs honor the filters but pass `maxNewPatches: "none"`:
  deferring there would leave the check permanently showing work.
- socket.yml is read from the same commit as the tree (base SHA for `repo`
  jobs, head SHA for `pull_request` jobs), through the engine: the file is
  one of the paths the engine asks for, so there is no second parser.
- Effective limit = min(repo value or override, server cap). The server
  can tighten, never loosen. Org-level kill switches, entitlement and
  safety (D1-D6) always win.

### 7.2 Engine API changes (napi `HostedScanOptions` / result, and the `hosted-bundle` harness)

| Owner | Change |
|---|---|
| A | `selectHostedScanPaths` returns root `socket.yml` / `socket.yaml` when present in the tree listing (one phase: the file is small and root-only; roots the policy excludes are simply not processed) |
| A | options `noSocketYml?: boolean`, `minSeverity?: "critical"\|"high"\|"medium"\|"low"\|"none"` |
| A | result: session-level `policy` block (4.7) and `policyError?: {code, detail}`; on error no project is processed and no files change; `skipped[].reason` gains the `policy_*` codes |
| B | options `maxNewPatches?: number \| "none"`, `maxNewPatchesCap?: number`, `inFlightPatches?: string[]` (uuids already in the open PR; ranked first so a reviewed patch is not displaced by a newly published one mid-review) |
| B | result: session-level `rollout` block (5.5); `ProjectResult.deferred[]`; `skipped[]` rows with `rollout_deferred` |
| B | hosted-pin discovery over the in-memory lockfiles (the memory twin of `HostedPin::all(discover_wiring(..))`), so NEW/ALREADY/UPGRADE work in memory. A finite cap must never ship in the engine without it: every merged pin would look NEW and the rollout would stall at N. |
| B | restructure the per-root loop at `hosted_memory/mod.rs:537` into collect all roots → plan once → apply, so the budget is run-wide |

`hosted-bundle` rejects unknown fields, so each owner adds its fields there
too.

### 7.3 depscan follow-up (after A and B merge; separate PR in depscan)

1. Bump the socket-patch submodule and rebuild the addon.
2. Pass `inFlightPatches` (uuids in the open patch-all PR) and, for
   `pull_request` jobs, `maxNewPatches: "none"`.
3. New job outcome `policy_invalid` (from `policyError`): leave the
   existing PR untouched, surface the error on the admin page and in the
   job's check-run text.
4. Render a "Deferred (next batch)" table and severity/rank columns in the
   PR body; add `patchesDeferred` to stats.
5. Optional server cap per org (future org setting), passed as
   `maxNewPatchesCap`; intersect the admin `config.ecosystems` (D3) with
   the file by passing it as `ecosystems` as today.
6. Do **not** add `patches` to the ajv schema in
   `socket-yaml-schema.ts` with strict types: a typo would reject the whole
   file and turn PR checks neutral. If documentation value is wanted, add
   it as a permissive `{type: object}`.
7. Docs repo: add a `patches` section to the socket.yml page, and fix the
   two stale statements found in research (which file wins when both
   exist; v1 files are rejected by the GitHub App).

A closed/rejected rolling PR re-proposes the same patches next run;
document `ignorePackages` as the way to decline one.

## 8. Decisions log

| # | Decision | Why |
|---|---|---|
| 1 | Top-level `patches:` in socket.yml v2; no `version: 3` | breaks no parser (P1/P2 strip, P3 ignores); P3 rejects any version but 2 |
| 2 | socket-patch reads socket.yml (reverses configuration.md) | owner request; policy that only narrows fits the trust boundary |
| 3 | Keys `enabled includePaths ignorePaths ecosystems packages ignorePackages minSeverity maxNewPatches` | include/ignore pairs mirror existing keys; `packages` allowlist covers single-package pilots; `maxNewPatches` says it counts new patches only |
| 4 | gitignore semantics via the `ignore` crate, case-insensitive, anchored at repo root | identical to `projectIgnorePaths` in the backend |
| 5 | socket-patch also honors `projectIgnorePaths` | users expect one ignore list; every other consumer already honors it |
| 6 | Defaults `test/ tests/ fixtures/ __fixtures__/ testdata/` evaluated first, overridden by `!`; discovered roots only | moves H1; replace-on-set would re-enable fixtures when someone adds one unrelated pattern |
| 7 | Strict validation, fail closed, exit 1 `socket_yml_invalid` | a broken narrowing rule must not widen the rollout |
| 8 | Both files: error only if the parts we read differ | existing consumers disagree on precedence; repos that already have both keep working |
| 9 | Repo root = nearest `.git` ancestor, else `--cwd`; root files only | matches the GitHub App; memory engine can mirror it; never reads outside the checkout |
| 10 | Flags intersect lists; scalars CLI > env > file > default; `--no-socket-yml` with env | contract precedence and "every flag has an env var" |
| 11 | `maxNewPatches: 0` = upgrades only; absent / `none` = unlimited | literal meaning; avoids the Dependabot/Renovate 0 disagreement |
| 12 | Unknown severity is filtered when a floor is set | fail closed |
| 13 | NEW per (project root, base purl); budget per base purl run-wide | a widened pilot re-enters the cap; one package in many roots costs 1 |
| 14 | Upgrades exempt from the cap | rollout risk is per package; keeps patched packages current |
| 15 | Order: severity, advisory count, ecosystem, base purl, uuid; no `publishedAt` | total and time-independent; batch lacks the date |
| 16 | Budget after eligibility (grants, partition, preflight) | a withdrawn/broken patch never holds a slot |
| 17 | Filtered packages with recorded patches are retained, never removed or upgraded | narrowing freezes, never removes |
| 18 | `get` bypasses the policy with a warning | explicit intent |
| 19 | Separate `policy` (A) and `rollout` (B) JSON blocks | clean ownership seam; both additive |
| 20 | Everything ships in 5.0 | honoring `projectIgnorePaths`, disk default ignores and fail-closed file errors change scan's default behavior (MAJOR) |

## 9. Work items

Both items branch from `release/v5-prerelease` (suggested branches
`v5/rollout-policy` for A, `v5/rollout-limit` for B). **Merge order: A,
then B.**
B rebases onto A and owns the final integration (section 9.3). Neither
item depends on the other's types: the only exchanged values are plain
`Option<u32>` / `Option<u8>` and the pipeline order below.

### 9.0 Shared contract (frozen by this plan)

Scan pipeline, in order (disk and memory):

1. load policy (A) — fail closed before any write
2. crawl; capture the prune universe (unchanged)
3. root filter, ecosystem/package filter, retained set (A)
4. batch API (unchanged)
5. candidate severity filter (A)
6. per-package ranking (unchanged `ranking`)
7. classify NEW/ALREADY/UPGRADE, eligibility, budget, deferral (B)
8. writers (unchanged; receive only admitted rows)

```rust
// crates/socket-patch-core/src/policy/mod.rs — OWNER A
pub struct SelectionPolicy { /* private fields */ }
pub enum PolicySource { None, File { path: String, sha256: String }, Bypassed }
pub enum FilterReason {
    Disabled, PathExcluded { pattern: String, list: &'static str }, PathNotIncluded,
    Ecosystem, PackageNotListed, PackageIgnored { spec: String },
    Severity { found: Option<String>, floor: String },
}
impl FilterReason { pub fn code(&self) -> &'static str; pub fn detail(&self) -> String; }
pub enum PolicyError { Invalid { file: String, key: String, message: String }, Ambiguous { files: [String; 2] } }
impl PolicyError { pub fn code(&self) -> &'static str; } // socket_yml_invalid | socket_yml_ambiguous
pub trait PolicyFs { fn read_root_file(&self, name: &str, cap: usize) -> std::io::Result<Option<Vec<u8>>>; }
pub struct PolicyOverrides { pub bypass: bool, pub min_severity: Option<Option<u8>> } // Some(None) = "none"
impl SelectionPolicy {
    pub fn unrestricted() -> Self;                         // defaults (built-in path ignores only)
    pub fn load(fs: &dyn PolicyFs, o: &PolicyOverrides) -> Result<Self, PolicyError>;
    pub fn source(&self) -> &PolicySource;
    pub fn enabled(&self) -> bool;
    pub fn admits_root(&self, rel_dir: &str, explicit: bool) -> Result<(), FilterReason>;
    pub fn admits_purl(&self, purl: &str) -> Result<(), FilterReason>;       // ecosystem + packages
    pub fn admits_severity(&self, severity_order: u8) -> Result<(), FilterReason>;
    pub fn max_new_patches(&self) -> Option<u32>;          // the FILE value only; B resolves precedence
}

// crates/socket-patch-core/src/rollout.rs — OWNER B
pub enum Recorded { None, Same, Kept { uuid: String }, Superseded { old_uuid: String } }
pub struct Candidate {
    pub project: String, pub purl: String, pub base_purl: String, pub uuid: String,
    pub ecosystem: &'static str, pub severity_order: u8, pub advisory_count: usize,
    pub recorded: Recorded, pub eligible: bool, pub in_flight: bool,
}
pub enum MaxNewSource { Flag, Env, File, Default, Cap }
pub struct MaxNew { pub value: Option<u32>, pub source: MaxNewSource }
pub fn resolve_max_new(flag: Option<Option<u32>>, env: Option<Option<u32>>,
                       file: Option<u32>, cap: Option<u32>) -> MaxNew;
pub fn canonical_base_purl(purl: &str) -> String;
pub fn rollout_cmp(a: &Candidate, b: &Candidate) -> std::cmp::Ordering;
pub struct RolloutPlan { pub admitted: Vec<Candidate>, pub deferred: Vec<(Candidate, u32)>, pub counts: RolloutCounts }
pub fn plan_rollout(candidates: Vec<Candidate>, max_new: &MaxNew) -> RolloutPlan; // pure
```

Rules both items follow:
- Severity input is always the patch's real severity (`severity_order` /
  `max_severity_order`), never `RankKey.severity`.
- Skip-reason strings are the stable codes in 4.7 and 5.5.
- JSON: A owns the top-level `policy` block; B owns the top-level
  `rollout` block. Neither edits the other's.
- CLI args: A adds a `#[command(flatten)]` `SocketYmlArgs` (`--no-socket-yml`,
  `--min-severity`) in `scan/socket_yml_args.rs`; B adds a flattened
  `RolloutArgs` (`--max-new-patches`) in `scan/rollout_args.rs`. Both
  derive `Default`; each adds its field to the ~18 `ScanArgs` struct
  literals. The resulting adjacent-line conflicts are resolved by B on
  rebase.

### 9.1 Work item A — socket.yml loading and filtering

Scope:
- `crates/socket-patch-core/src/policy/{mod.rs, socket_yml.rs, paths.rs}`;
  `pub mod policy;` in `crates/socket-patch-core/src/lib.rs`.
- Dependencies, exact-pinned in `Cargo.toml`: a maintained YAML 1.2 serde
  crate that reports duplicate keys (e.g. `serde_norway`; verify
  duplicate-key rejection with a test, reject it otherwise), and `ignore`
  (gitignore matcher). No other new deps.
- Loader: lookup (4.5), size and symlink confinement, both-files rule,
  strict validation with key paths and did-you-mean (4.4), `PolicyFs` for
  disk and for the in-memory engine.
- Filters, wired at the pipeline points in 9.0:
  - disk: root filter in `project_dirs` / `run_project_dirs`
    (`scan/mod.rs:1268-1320`) and the agent project; `admits_purl` next to
    `--package` (`scan/mod.rs:1490-1511`); severity filter on batch
    candidates after `scan/mod.rs:1801` and on by-package candidates before
    `select_patches` in the human arm; retained set computed from the
    recorded view and excluded from writers.
  - memory: root filter in `hosted_memory/roots.rs` root detection;
    `admits_purl` at `hosted_memory/mod.rs:428-432`; severity filter before
    `select_top_ranked`.
- Move `test tests fixtures __fixtures__ testdata` out of
  `EXCLUDED_ROOT_SEGMENTS` (`hosted_memory/roots.rs:56-67`) into the
  built-in default ignores, and apply them to disk PATH-glob expansion.
- `enabled: false` report-only path; `get`'s `policy_bypassed` warning;
  `--global` ignores the file.
- Flags: `--no-socket-yml`/`SOCKET_NO_SOCKET_YML`,
  `--min-severity`/`SOCKET_MIN_SEVERITY` (`SocketYmlArgs`).
- napi + hosted-bundle: `selectHostedScanPaths` includes root
  `socket.yml`/`socket.yaml`; options `noSocketYml`, `minSeverity`; result
  `policy` and `policyError`; `npm/index.d.ts` types.
- JSON `policy` block (4.7), human policy line, error envelopes for
  `socket_yml_invalid` / `socket_yml_ambiguous`, warnings
  `socket_yml_unsupported_version`, `patches_disabled`, `policy_bypassed`.

Tests:
- Unit (core, table-driven): every row of 4.4; gitignore cases (anchoring,
  bare names, trailing `/`, `!` and the excluded-parent rule, case
  insensitivity, the `/` root form, defaults + negation); package specs;
  severity floor incl. unknown and `moderate`; both-files equal/different;
  lookup with `.git` dir, `.git` file, no git.
- Parser contract: `tests/cli_parse_scan.rs` rows for the two flags and
  env vars.
- E2E (wiremock, `tests/in_process_scan.rs` style): hosted, vendored,
  agent and `--dry-run` with a socket.yml that filters by path, ecosystem,
  package and severity; invalid file → exit 1, no bytes changed;
  `--no-socket-yml` bypass; narrowing after a patch is applied leaves the
  pinned package byte-identical in hosted, vendored and agent modes
  (retained); `--prune` universe unchanged.
- Parity: `tests/hosted_memory_parity.rs` gains a socket.yml fixture; disk
  and memory filter the same roots and packages.
- This repo's own `socket.yml` keeps working (its `projectIgnorePaths`
  now also excludes the fixtures from patching).

Docs (A): `CLI_CONTRACT.md` (new "socket.yml patch policy" section:
grammar, precedence, lookup, validation, commands; flag + env rows; error
codes; `policy` JSON block; the trust-boundary bullet gains the "narrow or
pace" sentence), README (scan section: "Roll out gradually" with recipes
R1-R4, R6), CHANGELOG `[Unreleased]` (Added: socket.yml patch policy;
Changed (BREAKING): scan honors `projectIgnorePaths`, default test/fixture
ignores on discovered roots, invalid socket.yml fails scan).

### 9.2 Work item B — limit, ordering, reporting

Scope:
- `crates/socket-patch-core/src/rollout.rs`; `pub mod rollout;` in
  `crates/socket-patch-core/src/lib.rs`.
- Make `discover_selected` (`scan/mod.rs:553`) the single disk selection
  point: route the human agent/vendored arm (`mod.rs:2386-2402`) through
  it, and have it return `{selected, deferred}` so hosted
  (`run_redirect_selected`, `hosted.rs:1196`), vendored and agent writers
  receive only admitted rows.
- Classification from `merge_ledger_records_for_updates` /
  `detect_updates` per project root; eligibility (tier, agent partition,
  vendored preflight, hosted reference grants — grants fetched for NEW
  candidates in rank order, identical result either way); `plan_rollout`
  with one run-wide budget across `run_project_dirs`.
- In-memory engine: hosted-pin discovery over in-memory lockfiles;
  collect → plan → apply restructure around `hosted_memory/mod.rs:537`;
  options `maxNewPatches`, `maxNewPatchesCap`, `inFlightPatches`; result
  `rollout`, `ProjectResult.deferred[]`, `rollout_deferred` skips;
  `npm/index.d.ts`; hosted-bundle fields.
- Flag: `--max-new-patches <N|none>`/`SOCKET_MAX_NEW_PATCHES`
  (`RolloutArgs`); `resolve_max_new` precedence including the file value
  from A (9.3).
- JSON `rollout` block (5.5), `redirect.skipped[]` mirror, human
  "Rollout:" line and the Next-steps deferred line (hosted
  `format_next_steps`, `hosted.rs:3457`, and the agent/vendored
  summaries).

Tests:
- Unit (core): `rollout_cmp` total order (property: sorting any
  permutation gives the same result); `plan_rollout` caps only NEW,
  counts base purls run-wide, one package across roots costs 1, 0 = no
  NEW, `none` = unlimited, ineligible rows hold no slot, in-flight first;
  `resolve_max_new` precedence table incl. cap; `canonical_base_purl`
  twins.
- E2E (wiremock): hosted, vendored, agent, `--dry-run`: 9 candidates with
  `--max-new-patches 3` apply the 3 most severe; rerun on the result
  applies the next 3; a third run the last 3; a fourth run changes nothing
  (convergence); upgrades land regardless of the cap; a withdrawn
  top-ranked patch does not consume budget; JSON `rollout` and
  `redirect.skipped[]` contents; exit 0.
- Parity: `hosted_memory_parity.rs` cap fixture — disk and memory admit
  and defer the same rows; memory rerun with pins in the lockfiles lands
  the next N (needs pin discovery).
- Parser contract rows for the flag and env var.

Docs (B): `CLI_CONTRACT.md` (limit semantics: classification, unit,
order, eligibility, convergence, starvation and non-committing-CI notes;
flag + env rows; `rollout` block; `rollout_deferred`; `jq` recipe; the
"Which patch gets selected" section notes the separate cross-package
order), README (recipe R5, `--max-new-patches`), CHANGELOG `[Unreleased]`
Added.

### 9.3 Integration (B, after rebasing on A)

- Pass `policy.max_new_patches()` as the `file` layer of `resolve_max_new`.
- Resolve the `ScanArgs` struct-literal conflicts (both flattened fields
  present).
- Combined e2e: a socket.yml with `includePaths`, `minSeverity: high` and
  `maxNewPatches: 2` over a two-root fixture, disk and memory, three runs to
  convergence; `--no-socket-yml` drops the file's cap but keeps a flag cap.
- If B is ready before A merges, B ships with the file layer passed as
  `None` and a follow-up commit on its branch wires it once A lands.

## 10. Open questions (decided by default, revisit with evidence)

- A separate upgrade cap (`maxUpgrades`) if server-side republishes rotate
  too many pins at once. Default: none.
- CVSS/EPSS/KEV or reachability as ordering keys once the patch API
  exposes them; they would slot between severity and advisory count.
- A generated JSON Schema for the `patches` block, shared with depscan and
  the docs, to keep validators from drifting.
