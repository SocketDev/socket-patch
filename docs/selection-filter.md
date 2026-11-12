# Selection filter

`socket-patch scan --selection-filter <FILE>` reads a JSON file that says what
one scan need not patch: project roots, packages and advisories to skip, and the
results of a reachability analysis. The scan then leaves a package unpatched only
when every vulnerability its patches fix is skipped or unreachable.

This is an internal interface for Socket's own remediation tooling (`socket fix`
pull requests). The flag is hidden from `--help`, and the file is versioned
instead of being covered by the CLI's semver policy.

- [Using it](#using-it)
- [File format](#file-format)
- [How a scan applies it](#how-a-scan-applies-it)
- [Reading the result](#reading-the-result)
- [Errors and limits](#errors-and-limits)
- [Recipes](#recipes)

## Using it

```bash
socket-patch scan --json --mode hosted --selection-filter filter.json
```

- The environment variable `SOCKET_SELECTION_FILTER` is the flag's twin. The
  flag wins; an empty value is unset.
- A relative path is relative to the working directory of the process, not to
  `--cwd`.
- Every scan mode reads it (hosted, vendored, agent, and a report-only scan),
  wet or `--dry-run`. No other command does, and the in-memory engine behind the
  Node addon does not take one yet.
- The filter applies beside the repository's `socket.yml` policy: both narrow
  the run. `--no-socket-yml` drops the `socket.yml` file, never the filter.

## File format

A UTF-8 JSON object. Only `version` is required.

```json
{
  "version": 1,
  "skip": {
    "paths": ["services/legacy/"],
    "packages": ["pkg:npm/left-pad"],
    "advisories": ["GHSA-jf85-cpcp-j695", "CVE-2021-23337"]
  },
  "reachability": [
    { "advisory": "GHSA-35jh-r3h4-6jhm", "package": "pkg:npm/lodash@4.17.20", "state": "reachable" },
    { "advisory": "GHSA-p6mc-m468-83gw", "state": "unreachable" },
    { "package": "pkg:npm/minimist@1.2.5", "state": "unreachable" }
  ],
  "unlistedAdvisories": "patch"
}
```

The JSON Schema is [`selection-filter.schema.json`](selection-filter.schema.json)
(draft 2020-12). The same shape as a TypeScript type:

```ts
interface SelectionFilter {
  version: 1
  skip?: {
    paths?: string[]
    packages?: string[]
    advisories?: string[]
  }
  reachability?: Finding[]
  unlistedAdvisories?: 'patch' | 'skip' // default 'patch'
}

// A finding names an advisory, a package, or both.
type Finding =
  | { advisory: string; package?: string; state: State }
  | { package: string; state: State }

type State = 'reachable' | 'unreachable' | 'unknown'
```

### Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `version` | `1` | The format version. Required. |
| `skip.paths` | path pattern list | Project roots to leave alone. |
| `skip.packages` | package spec list | Packages to leave alone. |
| `skip.advisories` | advisory id list | Advisories that need no fix. |
| `reachability` | finding list | What the reachability analysis found. |
| `reachability[].advisory` | advisory id | The advisory the finding is about. |
| `reachability[].package` | package spec | The package the finding is about. |
| `reachability[].state` | `reachable`, `unreachable` or `unknown` | The result. Required. `unknown` counts as reachable. |
| `unlistedAdvisories` | `patch` or `skip` | What an advisory no finding covers needs. Default `patch`. |

A finding needs an `advisory`, a `package`, or both:

| Finding names | It covers |
| --- | --- |
| `advisory` and `package` | That advisory in that package. |
| `advisory` only | That advisory in every package. |
| `package` only | Every advisory in that package. |

### Value grammars

**Advisory id.** A GHSA id (`GHSA-xxxx-xxxx-xxxx`) or a CVE id
(`CVE-2024-1234`), in any letter case. An id matches an advisory by its id or by
one of its CVE aliases, so either spelling of the same advisory works.

**Package spec.** The grammar of `scan --package`:

- A purl with a version names that release: `pkg:npm/lodash@4.17.20`.
- A purl without a version names every version: `pkg:npm/lodash`.
- A bare name names the package in every ecosystem, by its full name or its
  last segment: `lodash`, `@scope/pkg`. Prefer purls: `core` also matches
  `@babel/core`. A bare name takes no version: `lodash@4.17.20` is an error,
  write `pkg:npm/lodash@4.17.20`.

Qualifiers are ignored and names compare case-insensitively.

**Path pattern.** A gitignore pattern, with the semantics of `socket.yml`'s
[`patches.ignorePaths`](configuration.md#paths-and-monorepos):

- Patterns are relative to the repository root: the git checkout around
  `--cwd`, or `--cwd` itself when it is not inside a trusted checkout.
- They are matched against the lockfiles of each project root, and a root is
  skipped when every lockfile in it matches. So `services/legacy/` skips the
  project in that directory, and `**/yarn.lock` skips each project whose only
  lockfile is a `yarn.lock`.
- A leading `!` re-includes what an earlier pattern of this list skipped. It
  cannot re-include a root that `socket.yml` ignores.
- A leading `#` would make the line a gitignore comment, so it is an error.
  Write `\#` for a literal one.

### Strictness

The file only ever narrows a scan, so a file the scan cannot honor is an error,
never "no filter". These all fail the run before it makes a request or writes a
file (see [Errors and limits](#errors-and-limits)):

- an unknown key, at any level;
- a duplicate key;
- a value of the wrong type, including an array where an object belongs;
- an unknown `state` or `unlistedAdvisories` value;
- a `version` other than `1`;
- a finding with neither `advisory` nor `package`;
- an invalid advisory id, package spec or path pattern, including one that
  could never match (a bare package name with a version, a pattern gitignore
  reads as a comment).

## How a scan applies it

### 1. Skipped roots and packages

A project root that `skip.paths` matches is not patched. This holds for a root
the run names (`--cwd`, a PATH argument) as well as one it discovers, and an
agent scan judges each nested project by its own root.

A package that `skip.packages` matches is not patched, and it is not looked up
at the patch service unless it already carries a patch.

### 2. Which advisories need a fix

For every patch the patch service offers, the scan judges each advisory the
patch fixes, for the package the patch is for:

1. An advisory listed in `skip.advisories` needs no fix.
2. Otherwise the most specific finding that covers it decides: a finding naming
   the advisory and the package, else one naming the advisory, else one naming
   the package. `unreachable` needs no fix; `reachable` and `unknown` need one.
3. When no finding covers it, `unlistedAdvisories` decides: `patch` means it
   needs a fix, `skip` means it needs none.

When several equally specific findings cover the same advisory, the most
cautious wins: `reachable`, then `unknown`, then `unreachable`. A monorepo that
reaches the code from one workspace and not from another therefore gets the fix.

### 3. Which patches are applied

A patch is withheld only when **no** advisory it fixes needs a fix. A patch that
fixes at least one advisory that needs a fix is applied whole. A merged patch
therefore brings its fixes for unreachable or skipped advisories along.

So a package is left unpatched only when every advisory its patches fix is
unreachable or skipped.

The filter never changes how patches rank. One patch is applied per package
version, and among the patches that are not withheld the
[usual ranking](../crates/socket-patch-cli/CLI_CONTRACT.md#which-patch-gets-selected)
picks it: severity, then advisory count, then publish date, counted over
everything each patch fixes. The severity floor (`--min-severity`,
`patches.minSeverity`) also judges the whole patch.

One preference comes before the ranking. When exactly one advisory of the
package needs a fix, and a patch fixes that advisory and nothing else, that
single-advisory patch is applied instead of a merged one: it is the smallest
change that fixes what is reachable. The preference picks among patches the
severity floor admits, so a single-advisory patch below the floor does not keep
a merged patch above it from being applied.

Take a package with advisories A (critical), B (high) and C (low):

| Patches offered | Filter | Result |
| --- | --- | --- |
| One merged patch fixing A and B | A unreachable | The merged patch is applied. It fixes B, and A's fix comes with it. |
| One merged patch fixing A and B | A and B unreachable | No patch: `filter_not_needed`. |
| One patch fixing A, one fixing B | A unreachable | The patch for B is applied. The patch for A fixes nothing that needs a fix. |
| One patch fixing A, one fixing B | no finding for either | The patch for A is applied: the usual ranking puts the critical first. |
| A merged patch fixing A and B, one patch fixing B | A unreachable | The patch for B is applied: B is the only advisory that needs a fix, and that patch fixes it alone. |
| A merged patch fixing A and B, one patch fixing B | no finding for either | The merged patch is applied: two advisories need a fix, so the usual ranking decides. |
| A merged patch fixing A and C, one patch fixing B | A unreachable | The merged patch is applied: two advisories need a fix (B and C), and it ranks first as a critical patch. B stays unfixed and is listed in `unfixedIds`. |

### 4. Packages that are already patched

The filter never removes a patch. Removing one is `rollback` or `remove`.

- A patched package that the filter now skips, by path or by package, is held in
  place: not upgraded, not rewritten, and listed in `policy.retained[]`.
- A patched package whose patches are now all withheld keeps its recorded patch.
- A recorded patch that is itself withheld gives way to a patch that is not,
  even when the recorded patch ranks higher. The patch that fixes something
  reachable therefore lands whether or not the package was patched before, and
  the replacement is reported in `updates[]`.
- A package already on a merged patch that fixes the one advisory that needs a
  fix follows the usual ranking alone: it is not traded for the
  single-advisory patch, and it still upgrades to a better merged patch. A
  recorded single-advisory patch stays, and is not upgraded to a merged one
  while the filter is in effect.

## Reading the result

Run with `--json`. The filter's effect shows in three places.

**`policy.selectionFilter`** echoes the file the run honored: the SHA-256 of its
bytes and its entry counts as written (a repeated entry counts each time). The
key is absent on a run without a filter.

```json
"selectionFilter": {
  "sha256": "9f2c…",
  "skip": { "paths": 1, "packages": 1, "advisories": 2 },
  "reachability": 3,
  "unlistedAdvisories": "patch"
}
```

**`policy.filtered[]`** lists what the run left unpatched and why. The filter
adds three reasons to the ones `socket.yml` has:

| `reason` | Meaning | `detail` |
| --- | --- | --- |
| `filter_path_skipped` | The project root matches `skip.paths`. `purl` and `uuid` are null. | The pattern: `/services/legacy/ (skip.paths)`. |
| `filter_package_skipped` | The package matches `skip.packages`. `uuid` is null, because the package was not looked up. | The spec: `pkg:npm/left-pad (skip.packages)`. |
| `filter_not_needed` | No patch for the package could be selected, and the filter withholds its top-ranked one. The package is unpatched, or keeps the patch it had. `uuid` is the withheld patch. | Each advisory that patch fixes and why it needs no fix: `GHSA-… unreachable, GHSA-… skipped`. The words are `unreachable`, `skipped` and `unlisted`; at most five advisories are named. |

```json
"filtered": [
  { "purl": "pkg:npm/lodash@4.17.20", "uuid": "a1a1a1a1-…", "project": "services/web",
    "reason": "filter_not_needed", "detail": "GHSA-p6mc-m468-83gw unreachable" },
  { "purl": "pkg:npm/left-pad@1.3.0", "uuid": null, "project": "services/web",
    "reason": "filter_package_skipped", "detail": "pkg:npm/left-pad (skip.packages)" }
]
```

A bare scan that searches a checkout for project directories does not visit a
root that `skip.paths` matches, so that root has no `filtered[]` entry. It is
counted in the scan's "under ignored paths" note instead.

**`packages[]`** says what was selected for each package, as on any scan:
`selectedUuids` is the patch, `fixedIds` every advisory and CVE id it fixes
(including unreachable ones that came with a merged patch), and `unfixedIds` the
ids only the package's other patches fix. A package the run selected nothing
for carries none of the three keys.

Whether a selected patch landed is its event in `events[]`, as on any scan. The
exit code does not change because something was filtered.

In human output, the policy line names the filter:

```text
Policy (socket.yml + selection filter): 3 skipped by filters, 0 patched packages held.
  skipped pkg:npm/lodash@4.17.20 (critical): GHSA-p6mc-m468-83gw unreachable
```

## Errors and limits

A file that cannot be read or honored is a usage error. The run exits **2**
before any request or write, with the entry at fault named in the message (the
envelope's other keys are left out here):

```json
{
  "command": "scan",
  "status": "error",
  "error": {
    "code": "filter_invalid",
    "message": "selection filter filter.json: reachability[3].package: purl spec needs a type and a name (`pkg:npm/lodash`): `pkg:npm`"
  }
}
```

| Limit | Value |
| --- | --- |
| File size | 16 MiB |
| `skip.paths` entries | 1,000 |
| `skip.packages` entries | 1,000 |
| `skip.advisories` entries | 100,000 |
| `reachability` entries | 100,000 |
| One path pattern or package spec | 1,024 bytes |

Findings that name an advisory are looked up by its id and cost nothing extra.
Findings that name only a package are compared one by one with every package
that has a patch: 10,000 of them over 200 such packages add about a quarter of
a second. A caller with many results should name the advisory in each.

## Recipes

**Turn reachability results into findings.** Write one finding per analyzed
vulnerability, with its advisory id and the package's purl. Map a definite
"not reachable" to `unreachable`. Map every other result (an error, an
unsupported ecosystem, a pending analysis) to `unknown`, or leave the finding
out: both mean the advisory needs a fix.

**Open a pull request that fixes chosen advisories only.** List them as
`reachable` and set `unlistedAdvisories` to `skip`. Every other advisory then
needs no fix, and only packages with a patch for a listed advisory are patched.

```json
{
  "version": 1,
  "unlistedAdvisories": "skip",
  "reachability": [{ "advisory": "GHSA-35jh-r3h4-6jhm", "state": "reachable" }]
}
```

**Leave advisories to a dependency upgrade.** List them in `skip.advisories`. A
package is then patched only if one of its patches fixes some other advisory
that needs a fix. To keep a package out of the run entirely, list it in
`skip.packages`.

**Preview.** Add `--dry-run`: the run writes nothing and reports what it would
select, with the same `policy` block.
