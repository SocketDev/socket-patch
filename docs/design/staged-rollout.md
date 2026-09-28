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
  rules**, case-insensitive, tested against each manifest **file** path
  (`list-files.ts:476-507`). A leading `/` or a
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
> never name an endpoint or credential, pick a mode or download format,
> turn off a safety check, or make `scan` patch anything it would not
> patch with no file present. The one exception is negating the built-in
> test/fixture path ignores (4.3), which are repo policy by nature.

Every `patches:` key only removes candidates (`enabled`, `includePaths`,
`ignorePaths`, `ecosystems`, `packages`, `ignorePackages`, `minSeverity`)
or delays them (`maxNewPatches`). No key can add a package, bypass the tier
filter, the agent partition, reference grants, containment checks or any
refusal in H7-H11. The parser has no fields for URLs, tokens, org, mode,
download mode or any `--no-*` safety switch; such keys are unknown keys and
fail validation (4.4).

Failure direction follows from that: because the file only narrows, an
unreadable or invalid policy must not mean "no policy". It fails closed.
And because a policy can hide security fixes, what it hides is always
reported (4.7, 7.3), never silent.

## 4. `socket.yml` grammar (work item A)

### 4.1 Keys

```yaml
version: 2                     # required for socket-patch to honor `patches`
projectIgnorePaths:            # existing scanner key; socket-patch honors it too
  - "crates/*/tests/fixtures/**"
patches:                       # new; every key optional
  enabled: true                # bool. Default true. false = report only.
  includePaths: ["/services/payments/"]   # gitignore list. Absent = every project.
  ignorePaths: ["/legacy/"]    # gitignore list, evaluated after the defaults. Default [].
  ecosystems: [npm, pypi]      # allowlist of --ecosystems names. Absent = all.
  packages: ["pkg:npm/lodash"] # allowlist of --package specs. Absent = all.
  ignorePackages: ["pkg:npm/left-pad"]  # denylist of --package specs. Default [].
  minSeverity: high            # critical|high|medium|moderate|low. Absent = no floor.
  maxNewPatches: 5             # integer 0..=4294967295. Absent = unlimited. 0 = upgrades only.
```

- camelCase, like every existing socket.yml key.
- Ecosystem names are any `Ecosystem::cli_name()` (`npm pypi cargo gem
  golang maven composer nuget deno`), case-insensitive, valid whatever the
  build supports; an unsupported ecosystem simply matches nothing.
- Package specs use exactly the `--package` grammar and matcher
  (`package_spec_matches`, moved from the cli crate to core by A): a name
  (full or last segment, case-insensitive) or a purl with or without a
  version; qualifiers ignored. A bare name matches across ecosystems and
  by last segment (`core` matches `@babel/core`), so the docs recommend
  purls in `packages`/`ignorePackages`. Invalid spec: empty, or `pkg:`
  without a type and name.
- `moderate` is an alias of `medium` everywhere (file, flag, env, napi).
- An empty allowlist (`includePaths: []`, `ecosystems: []`,
  `packages: []`) is an error ("use `enabled: false`"), never "all".
- Deny wins: `ignorePackages` beats `packages`, ignore paths beat
  `includePaths`.

### 4.2 Precedence against flags and env

| Setting | Rule |
|---|---|
| List filters (paths vs PATH args; `ecosystems` vs `--ecosystems`; `packages`/`ignorePackages` vs `--package`) | **intersect**: flags narrow further, never widen |
| `minSeverity` | `--min-severity <critical\|high\|medium\|moderate\|low\|none>` > `SOCKET_MIN_SEVERITY` > file > no floor |
| `maxNewPatches` | `--max-new-patches <N\|none>` > `SOCKET_MAX_NEW_PATCHES` > file > unlimited |
| whole file | `--no-socket-yml` / `SOCKET_NO_SOCKET_YML` (bool, the contract's spellings) skips the file; built-in default path ignores still apply |

Scalars follow the contract's CLI > env > default order, with the file as
the layer above the default. The person running the CLI is trusted; the
file is the repo's default. Every new flag has an env binding. An empty env
value is unset (repo-wide rule); a malformed flag or env value is a usage
error (exit 2). depscan adds its own server ceiling (7.1).

### 4.3 Paths

- **Subject: marker files.** The backend tests `projectIgnorePaths`
  against manifest file paths, so socket-patch does the same for every
  path list. A project root's **markers** are the lockfile/manifest files
  in its directory that the engine reads for it (disk: the root's
  lockfiles per the formats registry, plus its manifest; memory:
  `hosted_memory/roots.rs` marker files). Paths are repo-relative with `/`
  separators, e.g. `services/api/package-lock.json`, `package-lock.json`
  for the repo-root project.
  - A root is **ignored** iff **every** marker is ignored.
  - With `includePaths` set, a root is **included** iff **any** marker
    matches `includePaths`.
  - Admitted iff included and not ignored.
  This makes `/package-lock.json`, `**/yarn.lock`, `examples/**` and
  `crates/x/fixtures/**` mean what they mean to the scanner, and needs no
  special form for the repo-root project (target only it with
  `includePaths: ["/*", "!/*/"]`).
- **Semantics: npm `ignore` exactly.** gitignore rules, case-insensitive,
  anchored at the repo root: a leading or middle `/` anchors, a bare name
  matches at any depth, a trailing `/` matches directories only, `!`
  negates, last match wins. Evaluation walks **top-down**: for
  `a/b/c.lock`, test `a/`, then `a/b/`, then the file; the first ignored
  ancestor decides and a negation cannot re-include anything under it
  (`fixtures/` + `!/a/fixtures/keep/` leaves `keep` ignored, as in the
  backend). Do not use `ignore::gitignore`'s `matched_path_or_any_parents`
  as-is: it walks bottom-up and would re-include. Implement the walk over
  `Gitignore::matched(path, is_dir)`. `includePaths` uses the same walk
  with "matched" in place of "ignored".
- A golden fixture of (patterns, path, expected) generated from the npm
  `ignore` package is checked into the tests; the Rust matcher must agree
  on all of it.
- **Pattern hygiene.** Reject (4.4) patterns that contain a `..` segment, a
  drive letter, NUL, or exceed 1024 bytes. Backslash is gitignore's escape
  character, not a separator (documented).
- **Evaluation order** of the ignore lists (one combined list, last match
  wins within a path, top-down across ancestors):
  1. built-in defaults: `test/ tests/ fixtures/ __fixtures__/ testdata/`
  2. `projectIgnorePaths`
  3. `patches.ignorePaths`

  Re-include a default with a negation: `ignorePaths: ["!/e2e/tests/"]`.
  Adding an unrelated ignore never re-enables fixtures. The defaults are
  now case-insensitive (`Test/` too), unlike H1. The backend's own
  scanner defaults (`coverage`, `bower_components`, …) are not mirrored:
  those are not dependency roots socket-patch would find.
- **Defaults apply to discovered roots only.** Step 1 never applies to a
  root the user named explicitly:

  | Mode / entry point | Explicit roots | Discovered roots |
  |---|---|---|
  | disk hosted/vendored | `--cwd` with no PATH; a literal (non-glob) PATH | PATH-glob matches (`run_project_dirs` carries the flag per directory) |
  | disk agent | `--cwd` (its only project; agent PATHs are package globs, not roots) | none |
  | in-memory | roots given in `projectRoots` | roots found by detection |

  Steps 2-3 and `includePaths` apply to every root.
- **Structural excludes** (`node_modules .git .socket .yarn vendor`) stay
  hard-coded and cannot be negated.
- **Granularity.** A workspace member that shares the root lockfile is part
  of the root project; exclude it with `ignorePackages`, not paths.
- **Outside the repo.** Roots are canonicalized; a PATH that resolves
  outside the repo root (4.5) is a usage error (exit 2). One policy per
  invocation.

### 4.4 Validation (fail closed)

socket-patch validates `version`, `projectIgnorePaths` and `patches`, and
checks top-level key names for case variants of `patches`. It does not
validate any other key.

Checks run in this order: file access, encoding, YAML, top-level shape,
case-variant check, version gate, keys.

| Situation | Behavior |
|---|---|
| No file; empty or comment-only file | no file: defaults |
| Not a regular file after resolving (directory, FIFO, device), resolves outside the repo root, larger than 64 KiB (read at most 64 KiB + 1 from the opened handle; metadata from the same handle) | **error** |
| Invalid UTF-8, UTF-16, NUL bytes (a UTF-8 BOM is stripped; CRLF is fine) | **error** |
| YAML syntax error, duplicate key, top level not a mapping, nesting deeper than 32 | **error** |
| An anchor, alias or merge key (`<<`) inside `patches` or `projectIgnorePaths` | **error** (bounds expansion; nobody needs them here) |
| Top-level key equal to `patch` or `patches` ignoring case but not exactly `patches` | **error**: a misspelled block must not mean "no policy" |
| `patches` present and `version` is not 2 (integer 2 or string `"2"`, as ajv coerces), including missing | **error** ("patches requires version: 2") |
| `patches: null` or `patches: {}` | defaults |
| Unknown key under `patches` | **error**, with a did-you-mean hint (edit distance <= 2) and "a newer socket-patch may support it; upgrade or remove it" |
| Wrong type (no coercion: `"false"` is not a bool; YAML 1.2, so `no` is a string), unknown severity, `maxNewPatches` not an integer in range, empty allowlist, invalid pattern or spec, a list over 1000 entries, an entry over 1024 bytes | **error** naming the key path (`patches.minSeverity`) |
| `projectIgnorePaths` with a `patches` block present: a string is coerced to a one-element list (as ajv does); anything else not a list of strings is an **error** | |
| `projectIgnorePaths` with **no** `patches` block: same coercion; otherwise warning `socket_yml_ignored_value` and the key is ignored | repos that never opted in do not start failing on a scanner key |
| No `patches` block, any `version` | `projectIgnorePaths` honored whatever the version, as the backend (P2) does |
| Both `socket.yml` and `socket.yaml` at the root | validate both (either invalid is an error). If their `projectIgnorePaths` and `patches` are equal as parsed values (order-sensitive), use `socket.yml`; otherwise **error** `socket_yml_ambiguous`. The existing consumers disagree on which file wins, so we refuse to pick. |
| Only a case variant exists (`Socket.yml`) | not read (the name must match a directory entry exactly, via `read_dir`, so case-insensitive disks behave like the memory tree); warning `socket_yml_name_case` |

**Error behavior.** Before any write, `scan` fails with exit **1** and
`errorCode: socket_yml_invalid` (or `socket_yml_ambiguous`). The message
names the file, the key path and the remedy (fix the file, or
`--no-socket-yml`). Exit 1, not 2: it is a bad input file, like an invalid
manifest. Scan's JSON is still the legacy shape (not the unified envelope):
the error output is scan's existing error object `{"status": "error",
"error": "<message>"}` plus an additive `"errorCode"`; no `policy` or
`rollout` block is emitted on error.

Every string copied from the file into output (patterns, specs, key names)
is truncated to 200 characters with control characters stripped; depscan
additionally renders them as escaped code spans (7.3).

Keys are only ever added in minor releases and never change meaning. An
older pinned CLI fails on a newer key by design, and the error says so.

### 4.5 Lookup

1. Canonicalize `--cwd`. Repo root := the nearest ancestor (inclusive)
   containing `.git` (a directory, or a file for worktrees and submodules),
   not walking past any directory in `GIT_CEILING_DIRECTORIES`, and, on
   Unix, only if `.git` is owned by the current user or root (git's
   safe.directory spirit; otherwise warning `socket_yml_repo_untrusted`
   and the walk stops). With no qualifying `.git`, repo root := `--cwd`.
   Never the home directory unless `--cwd` is it; never above `--cwd`
   without a `.git`.
2. Read `<repo root>/socket.yml` and `<repo root>/socket.yaml` only.
   Nested files are never read (one file per repo, as in the GitHub App).
   A symlinked socket.yml is followed only if it resolves to a regular
   file inside the repo root.
3. In memory, the repo root is the tree root; the file must arrive with
   content (7.2). A socket.yml the tree lists but the engine never
   receives, or receives only as present-without-content (symlink,
   oversize, LFS pointer, binary), is `socket_yml_invalid`, never absent.
4. `--global` / `--global-prefix` scans have no repo and ignore the file.

### 4.6 Commands

| Command | Policy |
|---|---|
| `scan` (hosted, vendored, agent; wet and `--dry-run`), `hosted-bundle`, the napi engine | honor filters and limit |
| `get` | explicit intent: ignores filters and limit; warns `policy_bypassed` when the target would have been filtered; never fails on the policy (an invalid file just skips the warning) |
| `apply`, `list`, `vex`, `rollback`, `remove`, `repair`, `vendor` (eject/revert) | ignore it: they report, attest or undo existing state |

**Narrowing never removes.** The policy runs after the prune universe is
captured (`mod.rs:1480`), so `--prune` still judges the full crawl. A
package that already has a recorded patch but is now excluded by paths,
ecosystems, packages or `enabled: false` is **retained**: not passed to the
hosted rewriters, vendor engine or agent apply; not upgraded; not taken
over; left byte-identical. It is reported under `policy.retained[]` with
`upgradeAvailable`. Removing a patch is only ever `rollback`/`remove`, or
the dependency leaving the lockfile.

**Severity floor.** One data source: the by-package records the selector
already fetches (`fetch_patch_details` on disk, the provider's by-package
lookup in memory), severity = `max_severity_order` over the patch's
`vulnerabilities`, never `RankKey.severity` (forced to 0 for merged
patches) and never the batch list. The floor restricts which candidates
may **win** per-package ranking; a lower-ranked patch above the floor can
still win. With a floor set, unknown severity is filtered (fail closed;
note `minSeverity: low` therefore drops unknown-severity patches, which the
recipes say). Supersession of a recorded patch is judged against the
**unfiltered** offer list (5.1): the floor never turns a recorded patch
into "no longer offered". A recorded package with no candidate above the
floor keeps its recorded patch (ALREADY).

`enabled: false`: discovery and the table still run; nothing is written;
every candidate is reported filtered with `policy_disabled`; warning
`patches_disabled`; exit 0. Upgrades are frozen too.

### 4.7 JSON (`policy` block, owned by A)

Additive top-level key on every successful `scan --json` result (MINOR),
always present. Policy warnings go to scan's top-level `warnings[]`.

```json
"policy": {
  "source": "file",
  "path": "socket.yml",
  "sha256": "…",
  "enabled": true,
  "minSeverity": {"value": "high", "source": "file"},
  "counts": {"filtered": 3, "retained": 1},
  "filtered": [
    {"purl": "pkg:npm/qs@6.5.2", "uuid": null, "project": "services/legacy",
     "reason": "policy_path_excluded", "detail": "/legacy/ (patches.ignorePaths)"}
  ],
  "retained": [
    {"purl": "pkg:npm/lodash@4.17.20", "project": "", "recordedUuid": "…",
     "reason": "policy_package_ignored", "upgradeAvailable": true}
  ]
}
```

| `source` | When | `path` / `sha256` |
|---|---|---|
| `none` | no file, empty file, file ignored (`--global`), or only a case variant | null |
| `file` | a root file was read (with or without a `patches` block) | the file used (`socket.yml` when both are equal) / its bytes' hash |
| `bypassed` | `--no-socket-yml` / `SOCKET_NO_SOCKET_YML` | null |

- `project` is the repo-relative root directory; the repo root is `""`
  (the memory engine's spelling) everywhere.
- `minSeverity.source` is `flag|env|file|default`; `value` null = no floor.
- `uuid` is null when the package was filtered before any patch lookup
  (path, ecosystem, package reasons). A root filtered as a whole is one
  entry with `purl: null`.
- `counts.filtered` counts entries of `filtered[]`; `counts.retained`
  counts entries of `retained[]`.
- Reason codes (stable): `policy_disabled`, `policy_path_excluded`,
  `policy_path_not_included`, `policy_ecosystem`,
  `policy_package_not_listed`, `policy_package_ignored`, `policy_severity`
  (detail `unknown < high` or `medium < high`).
- Human output: one line, e.g. `Policy (socket.yml): 3 skipped by filters,
  1 patched package held.` Filtered critical/high candidates are always
  named on the human path (a policy must not silently hide them);
  `--verbose` lists everything.

## 5. Per-run limit (work item B)

### 5.1 Classification

**Recorded view.** Always the merged view, in every mode and both engines:
`merge_ledger_records_for_updates` (manifest > hosted lockfile pins >
vendor ledger), scoped to the lockfiles and state files of the project
root being written. The in-memory engine reads the same three stores from
the tree (`.socket/manifest.json`, `.socket/vendor/state.json`, hosted
pins discovered from the in-memory lockfiles; new, B). When the lockfiles
of one root pin a purl to different uuids, the recorded uuid is the
selected uuid if it is among them, else the smallest (today's rule).

**Supersession** uses the by-package records (the same data as selection
and the severity floor), with the `batch_supersedes` rungs applied to
them: merged over unmerged, higher severity between unmerged, a real,
strictly later publish date. It is judged against the **unfiltered** offer
list. B adds the by-package twin of `batch_supersedes` in `ranking.rs`;
`detect_updates` and scan's `updates[]` switch to it so classification,
selection and reporting can never disagree.

After filtering and per-package selection, each selected `(project root,
purl)` row is:

| Class | Rule | Counts toward the cap | Writer receives |
|---|---|---|---|
| ALREADY | recorded uuid == selected uuid, or the selection does not supersede the recorded uuid | no | the **recorded** uuid (re-confirmed idempotently) |
| UPGRADE | the selection supersedes the recorded uuid, or the recorded uuid is no longer offered at all (unfiltered) | no | the selected uuid |
| NEW | nothing recorded for this base purl in this project root | **yes** | the selected uuid, if admitted |
| ALREADY (kept) | recorded, offers exist in `Offers.unfiltered` but none survive the floor | no | the recorded uuid (counted in `counts.already`) |

- NEW is per project root. Widening `includePaths` makes piloted packages
  NEW in the added roots, so they go through the cap again.
- UPGRADEs are exempt (decision): rollout risk is about whether a package
  runs patched code at all, and an upgrade fixes more in an already-patched
  package. `enabled: false` freezes everything; `maxNewPatches: 0` freezes
  new packages only.
- **Known limit: version bumps.** When a dependency moves to a new version
  its hosted pin goes with the old lockfile entry, so the new version is
  NEW and goes through the cap. (Hosted state cannot tell a bump from a new
  package.) Documented.
- **Qualifier twins** (wheel/sdist, gem platforms) share a base purl. If
  one twin lands and another was ineligible, the next run sees the base
  purl as recorded and the late twin lands as ALREADY/UPGRADE, uncapped.
  Documented; it is one package.

### 5.2 Eligibility, budget and ordering

- **Eligibility is decided by the planning pass**, the same pass
  `--dry-run` runs, before any budget is spent. A NEW row is eligible only
  if every check that can be decided without writing passes:
  - tier filter;
  - agent partition (vendored / not installed);
  - vendored preflight;
  - hosted reference grant `granted`, with a usable purl and url;
  - vlt artifact preflight;
  - symlink refusals;
  - rewriter planning shows at least one lockfile edit that would pin it
    (no refusal, entry found).

  Ineligible rows keep their existing skip reasons and never hold a slot,
  so a patch that cannot land can never stall the rollout.
- **One fetch strategy.** References are requested for every eligible-so-far
  candidate (NEW, UPGRADE and ALREADY) in the run's normal batches, before
  budgeting; never lazily in rank order. A reference or lookup failure that
  affects only rows that end up deferred never fails the run or the root;
  it becomes warning `rollout_reference_failed`.
- **Incomplete data.** With a finite cap, if any batch, detail or reference
  lookup failed for a package that could have been NEW, no NEW row is
  admitted this run (all NEW rows deferred) and warning
  `rollout_incomplete_lookup` is emitted. Otherwise a failure would let
  lower-ranked patches take the missing ones' slots. ALREADY and UPGRADE
  rows proceed as today.
- **Unit:** a distinct **base purl** (ecosystem + name + version,
  qualifiers stripped, via one shared core function `canonical_base_purl`)
  among eligible NEW rows. Admitting a base purl admits all of its eligible
  NEW rows in every root of the invocation; it costs 1 slot.
- **Scope of the budget:**
  - in-memory engine: one budget across all roots (collect, plan, apply);
  - disk: one budget per invocation. `run_project_dirs` visits
    directories in sorted order and passes the **remaining** budget to
    each, together with the set of base purls already admitted (a base
    purl admitted in an earlier directory is admitted free in later ones);
    each directory spends the budget in rank order. `scan --json` accepts one
    directory, so a CI job per directory gets N per directory. Documented.
- **Order** (ascending; total; no time-dependent keys):
  1. in-flight first (in-memory option `inFlightPatches` only, matched by
     base purl; absent on the CLI)
  2. severity of the selected patch (`max_severity_order`: critical, high,
     medium, low, unknown)
  3. advisory count, descending (merged patches first within a severity)
  4. ecosystem `cli_name`, ascending
  5. canonical base purl, ascending bytewise
  6. smallest selected uuid across the base purl's rows, ascending

  A base purl in several roots uses the minimum key over its rows.
  `publishedAt` is not a key: it would reorder the queue whenever a date is
  missing. Per-package ranking (which patch a package gets) still uses
  `publishedAt` as today; this order only decides which packages go first.
- **Write failures** after admission (I/O at commit time) consume budget
  and are reported as failures. No backfill within a run, so `--dry-run`
  predicts the wet run exactly.
- **`maxNewPatches: 0`** admits no NEW rows; ALREADY and UPGRADE proceed.
- Everything eligible and NEW beyond the budget is **deferred**: not
  written, not downloaded, not vendored, reported with its rank.

### 5.3 Convergence and determinism

- Same inputs, same plan, same bytes. The limit is stateless: run k lands
  the top N; on run k+1 they are ALREADY and the next N land. M waiting
  patches take **at most** ceil(M/N) committed runs, absent new or
  ineligible patches.
- A newly published or re-scored higher-severity patch moves ahead of the
  queue. That is intended ("most critical first") and visible, because
  every deferred entry carries its rank and severity.
- Low-severity patches can wait indefinitely while higher ones keep
  arriving. Documented; it is the point of severity ordering.
- **CI that does not commit** the scan's result never advances recorded
  state, so a cap there means "only the top N, every run". The recipes
  say: commit the lockfile changes (or use a PR bot), or set no cap in
  non-committing jobs.
- `pending_build` references are transient: a row can be ineligible one
  run and eligible the next. The plan is still a function of the inputs.
- `--dry-run` fetches reference grants like a wet run (it must, to decide
  eligibility), so it has the same server-side effects a dry run has
  today.

### 5.4 Modes

| Mode | ALREADY / UPGRADE surface | Deferred rows |
|---|---|---|
| hosted (disk) | re-confirmed / rewritten, as today | never rewritten; mirrored into `redirect.skipped[]` with reason `rollout_deferred` |
| vendored | `already_vendored` / `would_revendor` | never downloaded or vendored |
| agent | `skipped` / `updated` | never downloaded; not in `apply.patches[]` |
| in-memory (napi, hosted-bundle) | as hosted | in `ProjectResult.deferred[]` and `skipped[]` with `rollout_deferred` |

Recorded state is the merged view (5.1) in every row. A takeover of an
existing vendored or hosted entry counts as recorded, not NEW. `--dry-run`
makes exactly the same decisions.

### 5.5 JSON (`rollout` block, owned by B)

Additive top-level key on every successful `scan --json` result (MINOR),
always present:

```json
"rollout": {
  "maxNewPatches": {"value": 5, "source": "file"},
  "counts": {"new": 5, "deferred": 9, "upgrade": 1, "already": 12},
  "deferred": [
    {"purl": "pkg:npm/minimist@1.2.5", "uuids": ["…"], "severity": "critical",
     "advisoryCount": 1, "projects": ["services/api", "services/web"], "rank": 6}
  ]
}
```

- `maxNewPatches.value` null = unlimited; `source` is
  `flag|env|file|default|cap`.
- `counts.new` and `counts.deferred` count base purls (admitted this run,
  or would be under `--dry-run`; deferred). `counts.upgrade` and
  `counts.already` count `(project, purl)` rows.
- `deferred[]` is in rank order; `purl` is the base purl; `uuids` lists
  the distinct selected uuids across its rows and qualifier twins; `rank`
  is 1-based among **eligible** NEW base purls. Ineligible rows are not
  ranked; they appear under their existing skip reasons.
- Human output (after the mode's summary, then the Next-steps renderer):

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
# R2 Critical first: widen by editing one line
version: 2
patches:
  minSeverity: critical   # later: high, then low, then remove the key
  maxNewPatches: 5        # (low still skips patches whose severity is unknown)
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

A cap only advances when the scan's changes are committed (or merged by a
PR bot). In a CI job that scans without committing, set no cap.

One-off overrides from the command line: `socket-patch scan
--max-new-patches none` (drain the queue this run), `--min-severity none`,
`--no-socket-yml` (ignore the file entirely).

## 7. depscan autopatch service

### 7.1 Behavior with the new engine

- `repo` jobs rebuild one commit from the base SHA each run. With
  `maxNewPatches: 5`, "recorded" means recorded on the **base** branch, so
  every rebuild proposes the same top 5 until the PR merges, then the next
  5. `inFlightPatches` (the base purls already in the open PR) keeps a
  reviewed patch from being displaced by a newly published one mid-review.
- **Policy source.** Both job kinds read socket.yml from the **base** SHA:
  the reviewed, merged policy. A pull request cannot loosen the policy
  that judges its own check (for example by adding `ignorePackages` for
  the vulnerable dependency it introduces). If the PR head changes
  `patches` or `projectIgnorePaths`, the check run says so and lists what
  the head's policy would additionally filter.
- `pull_request` jobs honor the filters and pass `maxNewPatches: "none"`
  and **no** `maxNewPatchesCap`: deferring there would leave the check
  permanently showing work.
- Effective limit for `repo` jobs = min(repo value, `maxNewPatchesCap`).
  The server can tighten, never loosen; the cap applies to every value
  including `"none"`. Org-level kill switches, entitlement and safety
  (D1-D6) always win.

### 7.2 Engine API changes (napi `HostedScanOptions` / result, and the `hosted-bundle` harness)

| Owner | Change |
|---|---|
| A | `selectHostedScanPaths` also returns root `socket.yml` / `socket.yaml` when listed, and returns the list of policy paths it selected; it applies only the **built-in** default ignores (it cannot see file contents); the session fails `socket_yml_invalid` if a selected policy path never arrives with content or arrives present-without-content |
| A | the session applies the full policy to detected roots **before** the `max_projects` check (`hosted_memory/mod.rs:377`) |
| A | options `noSocketYml?: boolean`, `minSeverity?: "critical"\|"high"\|"medium"\|"moderate"\|"low"\|"none"` |
| A | result: session-level `policy` block (4.7) and `policyError?: {code, detail}`; on error no root is processed and no files change; `skipped[].reason` gains the `policy_*` codes |
| B | options `maxNewPatches?: number \| "none"`, `maxNewPatchesCap?: number`, `inFlightPatches?: string[]` (base purls) |
| B | result: session-level `rollout` block (5.5); `ProjectResult.deferred[]`; `skipped[]` rows with `rollout_deferred` |
| B | hosted-pin discovery over the in-memory lockfiles and reading `.socket/manifest.json` / `.socket/vendor/state.json` from the tree, for the merged recorded view. A finite cap must never ship in the engine without it: every merged pin would look NEW and the rollout would stall at N. |
| B | restructure the per-root loop around `hosted_memory/mod.rs:537` into collect all roots → plan once → apply, so the budget is run-wide |

`hosted-bundle` rejects unknown fields, so each owner adds its fields there
too.

### 7.3 depscan follow-up (after A and B merge; separate PR in depscan)

1. Bump the socket-patch submodule and rebuild the addon.
2. Stream root socket.yml content from the **base** SHA for both job kinds
   (for `repo` jobs that is the tree being scanned; for `pull_request`
   jobs push the base-SHA blob under the policy path the engine selected).
   Never let the file be dropped by the size/path caps silently: the
   engine turns a missing policy blob into `policyError`.
3. Pass `inFlightPatches` (base purls in the open patch-all PR); for
   `pull_request` jobs pass `maxNewPatches: "none"` and no cap.
4. New job outcome `policy_invalid` (from `policyError`): leave the
   existing PR untouched, surface the error on the admin page and in the
   check-run text.
5. PR body and check run: a "Deferred (next batch)" table with severity
   and rank; `policy.filtered`/`retained` counts, naming every critical or
   high candidate the policy suppressed; a note when the PR head changes
   the policy. Render every file-derived string as an escaped code span,
   truncated.
6. Stats: `patchesDeferred`, `patchesFiltered`.
7. Optional server cap per org (future setting) passed as
   `maxNewPatchesCap`; keep passing the admin `config.ecosystems` (D3) as
   `ecosystems`, which intersects with the file.
8. Do **not** add `patches` with strict types to the ajv schema in
   `socket-yaml-schema.ts`: a typo there rejects the whole file and turns
   PR checks neutral. If wanted for docs, add a permissive `{type: object}`.
9. Docs repo: a `patches` section on the socket.yml page; fix the two
   stale statements found in research (which file wins when both exist;
   v1 files are rejected by the GitHub App).

A closed or rejected rolling PR re-proposes the same patches next run;
`ignorePackages` is the documented way to decline one.

## 8. Decisions log

| # | Decision | Why |
|---|---|---|
| 1 | Top-level `patches:` in socket.yml v2; no `version: 3` | breaks no parser (P1/P2 strip, P3 ignores); P3 rejects any version but 2 |
| 2 | socket-patch reads socket.yml (reverses configuration.md) | owner request; policy that only narrows fits the trust boundary |
| 3 | Keys `enabled includePaths ignorePaths ecosystems packages ignorePackages minSeverity maxNewPatches` | include/ignore pairs mirror existing keys; `packages` covers single-package pilots; `maxNewPatches` says it counts new patches only |
| 4 | Paths match marker **files**, npm-`ignore` semantics, top-down, case-insensitive; golden parity fixture | identical meaning to `projectIgnorePaths` in the backend; no root special form |
| 5 | socket-patch also honors `projectIgnorePaths` (leniently when there is no `patches` block) | users expect one ignore list; repos that never opted in do not start failing |
| 6 | Defaults `test/ tests/ fixtures/ __fixtures__/ testdata/` first, overridden by `!`; discovered roots only | moves H1; replace-on-set would re-enable fixtures on any unrelated edit |
| 7 | Strict validation of `patches`, fail closed, exit 1 `socket_yml_invalid` | a broken narrowing rule must not widen the rollout |
| 8 | Both files: error only if the parts we read differ | consumers disagree on precedence; repos that have both keep working |
| 9 | Repo root = nearest trusted `.git` ancestor (ceiling dirs honored), else `--cwd`; root files only; PATHs outside it are exit 2 | matches the GitHub App; memory can mirror it; never reads outside the checkout |
| 10 | Flags intersect lists; scalars CLI > env > file > default; `--no-socket-yml` with env | contract precedence and "every flag has an env var" |
| 11 | `maxNewPatches: 0` = upgrades only; absent / `none` = unlimited | literal meaning; avoids the Dependabot/Renovate 0 disagreement |
| 12 | Unknown severity is filtered when a floor is set | fail closed |
| 13 | One data source (by-package records) for floor, supersession, classification and order | selection, classification and reporting can never disagree |
| 14 | NEW per (project root, base purl); budget per base purl; memory run-wide, disk per invocation carried across directories | a widened pilot re-enters the cap; one package in many roots costs 1 |
| 15 | Upgrades exempt from the cap | rollout risk is per package; keeps patched packages current |
| 16 | Order: severity, advisory count, ecosystem, base purl, uuid; no `publishedAt` | total and time-independent |
| 17 | Eligibility = everything the planning pass can decide; fetch-all references; incomplete lookups admit no NEW rows | a broken patch never holds a slot; failures never reshuffle the queue |
| 18 | Filtered packages with recorded patches are retained, never removed or upgraded | narrowing freezes, never removes |
| 19 | `get` bypasses the policy with a warning | explicit intent |
| 20 | Separate `policy` (A) and `rollout` (B) JSON blocks | clean ownership seam; both additive |
| 21 | depscan reads the policy from the base SHA for PR jobs too | a PR cannot loosen the policy judging it |
| 22 | Everything ships in 5.0 | honoring `projectIgnorePaths`, disk default ignores and fail-closed file errors change scan's default behavior (MAJOR) |

## 9. Work items

Both items branch from `release/v5-prerelease` (suggested branches
`v5/rollout-policy` for A, `v5/rollout-limit` for B). **Merge order: A,
then B.** B rebases onto A and owns the final integration (9.3). The
seams are small and listed in 9.0: the step 5 → step 7 `Offers` struct
(A), the repo-relative path helpers (A), the file's `maxNewPatches` value
(A → B), and the pipeline order.

### 9.0 Shared contract (frozen by this plan)

Scan pipeline, in order (disk and memory):

1. load policy (A); fail closed before any write
2. crawl; capture the prune universe (unchanged)
3. root filter, ecosystem/package filter, retained set (A)
4. batch API, by-package details (unchanged fetches)
5. candidate severity filter on by-package records (A); `discover_selected`
   returns `Offers` (below) so B sees both the unfiltered and the
   floor-filtered candidates
6. per-package ranking (unchanged `ranking`)
7. classify, planning pass for eligibility, budget, deferral (B)
8. writers (receive only admitted NEW rows, ALREADY rows with the recorded
   uuid, and UPGRADE rows)

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
pub enum PolicyError {
    Invalid { file: String, key: String, message: String },
    Ambiguous { files: [String; 2] },
}
impl PolicyError { pub fn code(&self) -> &'static str; } // socket_yml_invalid | socket_yml_ambiguous
pub enum RootFile { Absent, Present(Vec<u8>), PresentWithoutContent }
pub trait PolicyFs { fn read_root_file(&self, name: &str, cap: usize) -> std::io::Result<RootFile>; }
pub enum OverrideSource { Flag, Env }
pub struct PolicyOverrides { pub bypass: bool, pub min_severity: Option<(Option<u8>, OverrideSource)> } // (None, _) = "none"
pub struct PolicyWarning { pub code: &'static str, pub detail: String }
pub struct Root<'a> { pub rel_dir: &'a str, pub markers: &'a [String], pub explicit: bool }
impl SelectionPolicy {
    pub fn unrestricted() -> Self;                          // built-in default ignores only
    pub fn load(fs: &dyn PolicyFs, o: &PolicyOverrides) -> Result<(Self, Vec<PolicyWarning>), PolicyError>;
    pub fn source(&self) -> &PolicySource;
    pub fn enabled(&self) -> bool;
    pub fn admits_root(&self, root: &Root) -> Result<(), FilterReason>;
    pub fn admits_purl(&self, purl: &str) -> Result<(), FilterReason>;        // ecosystem + packages
    pub fn admits_severity(&self, severity_order: u8) -> Result<(), FilterReason>;
    pub fn max_new_patches(&self) -> Option<u32>;  // the file's value; None when source() is None or Bypassed, or the key is absent
}
pub fn package_spec_matches(spec: &str, purl: &str) -> bool; // moved from cli scan/mod.rs:383
pub fn find_repo_root(cwd: &Path) -> PathBuf;                // 4.5
pub fn repo_relative(repo_root: &Path, dir: &Path) -> String; // "" for the repo root, `/` separators

// crates/socket-patch-core/src/policy/mod.rs — OWNER A (the step 5 → 7 seam)
pub struct Offers {
    pub unfiltered: BTreeMap<String, Vec<PatchSearchResult>>, // purl → every offer (after tier)
    pub selected: BTreeMap<String, PatchSearchResult>,        // purl → winner among floor-admitted offers
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
pub struct RolloutCounts { pub new: u32, pub deferred: u32, pub upgrade: u32, pub already: u32 }
pub struct RolloutPlan {
    pub admitted: Vec<Candidate>, pub deferred: Vec<(Candidate, u32)>,
    pub counts: RolloutCounts,
    pub remaining: Option<u32>,                       // carried to the next directory
    pub admitted_base_purls: BTreeSet<String>,        // carried too
}
// Rows whose base_purl is in `already_admitted` are admitted without spending budget.
pub fn plan_rollout(candidates: Vec<Candidate>, max_new: &MaxNew, incomplete: bool,
                    already_admitted: &BTreeSet<String>) -> RolloutPlan; // pure

// crates/socket-patch-core/src/api/ranking.rs — OWNER B (addition)
pub fn search_result_supersedes(candidate: &PatchSearchResult, recorded: &PatchSearchResult) -> bool;
```

Rules both items follow:
- Severity input is always `max_severity_order` over the by-package
  record's `vulnerabilities`, never `RankKey.severity`, never the batch
  list.
- Skip-reason strings are the stable codes in 4.7 and 5.5; warnings go to
  scan's top-level `warnings[]`.
- JSON: A owns the top-level `policy` block; B owns the top-level
  `rollout` block. Neither edits the other's.
- CLI args: A adds a `#[command(flatten)]` `SocketYmlArgs`
  (`--no-socket-yml`, `--min-severity`) in `scan/socket_yml_args.rs`; B
  adds a flattened `RolloutArgs` (`--max-new-patches`) in
  `scan/rollout_args.rs`. Both derive `Default`; each adds its field to
  the ~18 `ScanArgs` struct literals. B resolves the adjacent-line
  conflicts on rebase.
- `run_project_dirs` changes: A adds the per-directory `explicit` flag;
  B adds the carried remaining budget. B resolves the overlap on rebase.

### 9.1 Work item A — socket.yml loading and filtering

Scope:
- `crates/socket-patch-core/src/policy/{mod.rs, socket_yml.rs, paths.rs}`;
  `pub mod policy;` in `crates/socket-patch-core/src/lib.rs`; move
  `package_spec_matches` to core (the cli re-uses it).
- Dependencies, exact-pinned in `Cargo.toml`: a maintained YAML 1.2 serde
  crate that reports duplicate keys and can refuse aliases and bound depth
  (e.g. `serde_norway`; prove each property with a test, pick another
  crate otherwise), and `ignore` (for `Gitignore::matched`; the top-down
  walk is ours). No other new deps.
- Loader: lookup (4.5, incl. ceiling dirs and ownership), regular-file,
  size and symlink confinement on the opened handle, exact-name match,
  encoding, both-files rule, strict validation with key paths and
  did-you-mean (4.4), `PolicyFs` for disk and memory.
- Path matcher (4.3): marker-file subject, npm-`ignore` top-down
  semantics, defaults + lists in order, `includePaths`, pattern hygiene;
  golden fixture generated from npm `ignore` (commit the generator script
  under `scripts/` and the fixture under `crates/socket-patch-core/tests/`).
- Filters at the pipeline points in 9.0:
  - disk: root filter in `project_dirs` / `run_project_dirs`
    (`scan/mod.rs:1268-1320`, carrying `explicit`) and the agent project;
    `admits_purl` next to `--package` (`scan/mod.rs:1490-1511`); severity
    filter on by-package candidates before `select_patches`
    (`discover_selected`, `scan/mod.rs:553`, and the human arm,
    `mod.rs:2386-2402`); retained set computed from the recorded view and
    excluded from writers.
  - memory: built-in defaults in `selectHostedScanPaths`
    (`hosted_memory/select.rs`); full root filter in the session before
    `max_projects` (`hosted_memory/mod.rs:377`); `admits_purl` at
    `hosted_memory/mod.rs:428-432`; severity filter before
    `select_top_ranked`.
- Move `test tests fixtures __fixtures__ testdata` out of
  `EXCLUDED_ROOT_SEGMENTS` (`hosted_memory/roots.rs:56-67`) into the
  built-in default ignores, and apply them to disk PATH-glob expansion.
- `enabled: false` report-only path; `get`'s `policy_bypassed` warning;
  `--global` ignores the file; PATHs outside the repo root → exit 2.
- Flags: `--no-socket-yml`/`SOCKET_NO_SOCKET_YML`,
  `--min-severity`/`SOCKET_MIN_SEVERITY` (`SocketYmlArgs`).
- napi + hosted-bundle (7.2, A rows); `npm/index.d.ts` types.
- JSON `policy` block (4.7), human policy line (naming suppressed
  critical/high), error output with `errorCode`, warnings
  `socket_yml_ignored_value`, `socket_yml_name_case`,
  `socket_yml_repo_untrusted`, `patches_disabled`, `policy_bypassed`;
  output string hygiene.

Tests:
- Unit (core, table-driven): every row of 4.4 in order; the npm-`ignore`
  golden fixture (anchoring, bare names, trailing `/`, `!`, excluded
  parents, case); marker rule (all markers ignored / any included);
  defaults + negation; explicit vs discovered; package specs incl.
  invalid ones; severity floor incl. unknown and `moderate`; both-files
  equal / different / one invalid; lookup with `.git` dir, `.git` file,
  none, `GIT_CEILING_DIRECTORIES`, foreign-owned `.git`; symlink inside
  and outside, directory, FIFO; alias bomb; oversize; BOM, CRLF, UTF-16.
- Parser contract: `tests/cli_parse_scan.rs` rows for both flags and env
  vars (empty = unset, malformed = exit 2).
- E2E (wiremock, `tests/in_process_scan.rs` style): hosted, vendored,
  agent and `--dry-run` with a socket.yml filtering by path, ecosystem,
  package and severity; invalid file → exit 1, `errorCode`, no bytes
  changed; `--no-socket-yml`; narrowing after a patch is applied leaves the
  pinned package byte-identical in all three modes (retained); a recorded
  merged patch below a new floor is kept, not replaced; `--prune` universe
  unchanged; PATH outside the repo → exit 2.
- Parity: `tests/hosted_memory_parity.rs` gains a socket.yml fixture
  (single-lockfile roots) where disk and memory filter the same roots and
  packages; a memory test where the tree lists socket.yml but its content
  is withheld → `policyError`.
- This repo's own `socket.yml` keeps working (its `projectIgnorePaths`
  now also excludes the fixtures from patching).

Docs (A): `CLI_CONTRACT.md` (new "socket.yml patch policy" section:
grammar, precedence, paths, lookup, validation, commands; flag + env rows;
error codes; `policy` JSON block; the trust-boundary bullet gains the
"narrow or pace" sentence), README (scan section: "Roll out gradually"
with recipes R1-R4, R6), CHANGELOG `[Unreleased]` (Added: socket.yml
patch policy; Changed (BREAKING): scan honors `projectIgnorePaths`,
default test/fixture ignores on discovered roots, invalid socket.yml with
a `patches` block fails scan).

### 9.2 Work item B — limit, ordering, reporting

Scope:
- `crates/socket-patch-core/src/rollout.rs`; `pub mod rollout;` in
  `crates/socket-patch-core/src/lib.rs`; `search_result_supersedes` in
  `ranking.rs`, and `detect_updates` / `updates[]` switched to by-package
  supersession; move the `detect_updates` call (today `scan/mod.rs:1912`,
  on batch data) after `discover_selected` so it receives the by-package
  offers.
- Make `discover_selected` (`scan/mod.rs:553`) the single disk selection
  point: route the human agent/vendored arm (`mod.rs:2386-2402`) through
  it, and add the step-7 stage after it (classify its `Offers`, planning
  pass, `plan_rollout`) yielding `{admitted, deferred}`, so hosted
  (`run_redirect_selected`, `hosted.rs:1196`), vendored and agent writers
  receive only the rows 9.0 step 8 allows (ALREADY with the recorded
  uuid). `discover_selected`'s return type is A's `Offers`.
- Classification from the merged recorded view (5.1); the planning pass
  for eligibility (hosted: grants, purl/url, vlt preflight, symlink
  refusals, rewriter planning; vendored: preflight; agent: partition);
  fetch-all references; `rollout_reference_failed` and
  `rollout_incomplete_lookup`; `plan_rollout`; the remaining budget
  carried through `run_project_dirs` in sorted directory order.
- In-memory engine (7.2, B rows): pin discovery and state-file reads,
  collect → plan → apply, options and result fields, `npm/index.d.ts`,
  hosted-bundle fields.
- Flag: `--max-new-patches <N|none>`/`SOCKET_MAX_NEW_PATCHES`
  (`RolloutArgs`); `resolve_max_new` including the file value from A
  (9.3).
- JSON `rollout` block (5.5), `redirect.skipped[]` mirror, human
  "Rollout:" line and the Next-steps deferred line (hosted
  `format_next_steps`, `hosted.rs:3457`, and the agent/vendored
  summaries).

Tests:
- Unit (core): `rollout_cmp` total order (property test: every
  permutation sorts the same); `plan_rollout` caps only eligible NEW,
  counts base purls, one package across roots costs 1, 0 = no NEW, `none`
  = unlimited, ineligible rows hold no slot, `incomplete` admits nothing
  NEW, in-flight first, remaining budget; `resolve_max_new` precedence
  table incl. cap on `none`; `canonical_base_purl` twins;
  `search_result_supersedes` rungs.
- E2E (wiremock): hosted, vendored, agent, `--dry-run`: 9 candidates with
  `--max-new-patches 3` apply the 3 most severe; a rerun on the result
  applies the next 3; a third run the last 3; a fourth changes nothing;
  dry-run output equals the wet run's decisions; upgrades land regardless
  of the cap; a withdrawn, a `bad_purl` and a vlt-withheld top-ranked
  patch hold no slot; a failed detail lookup with a cap admits nothing
  NEW; two PATH directories share one budget in sorted order; JSON
  `rollout` and `redirect.skipped[]`; exit 0.
- Parity: `hosted_memory_parity.rs` single-root cap fixture: disk and
  memory admit and defer the same rows. Two-root fixture: assert memory's
  run-wide order and disk's per-directory order separately (they differ by
  design, 5.2). A memory rerun with pins (and with a committed
  manifest / vendor state) lands the next N.
- Parser contract rows for the flag and env var.

Docs (B): `CLI_CONTRACT.md` (limit semantics: classification,
eligibility, unit, budget scope, order, convergence, version-bump and
twin notes, starvation and non-committing CI; flag + env rows; `rollout`
block; `rollout_deferred`; warnings; `jq` recipe; "Which patch gets
selected" gains the cross-package order and the by-package supersession
change), README (recipe R5, `--max-new-patches`), CHANGELOG
`[Unreleased]` Added (and Changed: `updates[]` uses by-package data).

### 9.3 Integration (B, after rebasing on A)

- Pass `policy.max_new_patches()` as the `file` layer of `resolve_max_new`.
- Resolve the `ScanArgs` struct-literal and `run_project_dirs` conflicts.
- Combined e2e: a socket.yml with `includePaths`, `minSeverity: high` and
  `maxNewPatches: 2` over a two-root fixture, disk and memory, three runs to
  convergence, asserting each engine's own budget scope (5.2);
  `--no-socket-yml` drops the file's cap but keeps a flag cap.
- Switch `Candidate.project` to A's `repo_relative` and consume A's
  `Offers` (before A lands, B uses canonical `--cwd` as the repo root and
  treats the selected offers as the unfiltered list).
- If B is ready before A merges, B ships with the file layer passed as
  `None` and wires it in a follow-up commit on its branch once A lands.

## 10. Open questions (decided by default, revisit with evidence)

- A separate upgrade cap (`maxUpgrades`) if server-side republishes rotate
  too many pins at once. Default: none.
- CVSS/EPSS/KEV or reachability as ordering keys once the patch API
  exposes them; they would slot between severity and advisory count.
- A generated JSON Schema for the `patches` block, shared with depscan and
  the docs, to keep validators from drifting.
- Recognizing a dependency version bump of an already-patched package as
  exempt from the cap (needs state hosted mode does not keep).
