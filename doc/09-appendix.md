> [agent] **Part 9 of 9** of the living socket-patch architecture document. The summary and ranked recommendations are in the top post. Originally written against `2463257`; the routines update this part as the code changes.

## Appendix A: The open-issue backlog, mapped to architecture

_Last checked against `main`: not yet re-checked; the content is as of `2463257`. Owner: `audit-core and audit-ecosystems`._

The repository had **88 open issues** when this review was written. Most were filed between 2026-09-26 and 2026-10-01 by a bug hunt (`bughunt` label). They are classified below **by title** into the architectural cause they point to. The classification is the reviewer's judgment and is approximate. Several issues fit more than one bucket; each is listed once, under its dominant cause.

### By ecosystem

| Ecosystem | Open | Share | Notes |
|---|---:|---:|---|
| JS (npm, pnpm, yarn, bun, vlt, deno) | 26 | 30% | |
| JVM (Maven, Gradle) | 22 | **25%** | Disproportionate to usage: JVM is ~9K production lines out of 118K |
| Python (pip, uv, pdm, pipenv, poetry, hatch) | 18 | 20% | |
| Go | 6 | 7% | |
| Cargo | 5 | 6% | |
| NuGet | 5 | 6% | |
| Ruby | 3 | 3% | |
| Composer | 3 | 3% | |

### By architectural cause

| # | Cause | Count | Issues | Structural fix (see main post) |
|---|---|---:|---|---|
| A | **Success or `not_affected` claimed from what we wrote, not from what the package manager consumes** | 29 | #409, #406, #405, #397, #396, #395, #394, #393, #392, #391, #390, #387, #367, #356, #352, #350, #341, #339, #338, #336, #335, #326, #325, #272, #265, #263, #261, #260, #258 | §2.2: VEX requires consumed evidence by default; `check` after install; fail closed on configuration we don't model |
| B | **Discovery re-implements the package manager's install layout or resolution and misses copies (exit 0, unpatched)** | 15 | #412, #398, #384, #374, #373, #366, #362, #361, #359, #349, #334, #332, #329, #327, #264 | §2.2: ask the package manager (`poetry env info -p`, `pipenv --venv`, `pnpm list --json`, `npm query`, …); project-scoped locators (Part 6) |
| C | **Rewrites that break installs because package-manager semantics aren't modeled** (including new lock-format revisions refused, e.g. #372) | 16 | #403, #386, #372, #371, #368, #364, #363, #360, #355, #354, #353, #347, #346, #344, #343, #333 | Same as above, plus refusing on unmodeled configuration |
| D | **Hand-rolled text surgery corrupts or reformats user files** | 12 | #402, #400, #376, #370, #351, #348, #342, #340, #324, #273, #262, #259 | Recommendation 1: one codec per format with byte spans and a single line-ending, indent and comment policy |
| E | **Reversal and mode takeover (upstream restore, revert, re-pin)** | 13 | #411, #410, #408, #407, #401, #385, #382, #369, #331, #328, #271, #266, #274 | Recommendation 4: an originals sidecar or narrowed restore; recommendation 2: one revert engine |
| F | **Credentials sent to the patch host** | 2 | #404 (yarn berry sends the npm auth token), #399 (composer `transport-options` auth headers) | Hosted rewrites should strip or scope per-entry auth config. This is worth a dedicated security review of every hosted rewriter. |
| G | **CI matrix gaps** | 1 | #267 | — |

**What the backlog says about the design:**
- About **two-thirds of the backlog (A + B + C = 60)** is one problem: the tool's *model* of the package manager diverges from the package manager's *behavior*, and the tool trusts its model. More per-package-manager special cases make that model bigger, and every new special case is another place to diverge. The leverage is in (i) verifying outcomes against what the package manager actually consumes, and (ii) delegating layout and resolution questions to the package manager wherever it can answer them.
- **D and E (25 issues)** are what you get from parsing each format several times with different rules and from reconstructing originals instead of recording them. Both have direct structural fixes, listed above.
- **Re-triage needed:**
  - #351, #390 and #403 describe the `setup` command and setup hooks, which #277 removed. Parts of them may be obsolete; the apply exit-code part of #403 probably is not.
  - #258–#274 predate #277 and should be re-checked against `main`.

---

## Appendix B: Methodology and measurement notes

**Sizing.**
- Each `.rs` file was split into production and test code by lexing it (strings, chars and comments blanked so braces inside them are ignored). Every `#[cfg(test)]` item was masked, and files that are test-only by name were excluded: `*_tests.rs`, `tests.rs`, `test_support*`, `testing/`, `golden.rs`, `test_rng.rs`.
- Result: **117,630 code, 34,764 comment and 9,051 blank production lines**; 4,369 production functions (median 13 lines; 201 over 100 lines; 61 over 200 lines; 27 over 300 lines).
- Per-area reviewers used the same "split at the first top-level `#[cfg(test)] mod`" convention, so their production numbers include comment lines.

**Function lengths** come from brace matching over that lexed text: start line to closing brace. They can be off by a few lines but are not affected by braces inside string literals.

**Duplicates** were found three ways:
1. Function names defined in several files (`restore` in 16 files, `crawl_all`/`find_by_purls` in 15, `preflight_packages` in 9, `service_preflight` in 8, `read_project` in 7, `sha256_hex` in 5).
2. A diff of the candidate pairs.
3. A sliding-window copy-paste detector, which found little *literal* duplication. **The duplication in this codebase is structural (parallel pipelines over shared helpers), not copy-paste.**

**CLI surface** was measured on a debug build: `--help` line counts per subcommand; JSON error shapes for `remove`, `rollback`, `scan --offline`, `get --offline`, `repair` and `vex`; silent acceptance of unused globals.

**CI numbers** are from the GitHub Actions run for `2463257` on `main` (CI workflow run 36798097960), plus the matrix definitions for workflows whose runs were not fetched.

**Verified by hand** (not just reported by an area reviewer):
- the unbounded zip inflate and its callers;
- no timeout on `ApiClient`/`plain_client`;
- the takeover ignoring `kept_artifact`;
- the bare `hatch` spawn and the project's own rule against it;
- the comment-blind `nuget_package_source_keys`;
- `SOCKET_FORCE` on three flags;
- `--download-mode diff` re-fetching all blobs when any archive is missing;
- `mem_blobs` never `Some` in production;
- `wired_vendor_integrity` with no production caller;
- `apply_env_toggles` and its documented token-leak history;
- the inconsistent JSON error shapes (binary output);
- the global flags on `list --help`;
- `severity_order` delegation;
- the duplicated `sha256_hex`/`sha1_hex` helpers.

**Not verified by execution:** the per-area reviewers' "probable bug" readings beyond those listed (they are labelled as such in each part), and every LOC *savings* estimate. Those are engineering estimates, not measurements.

**Read-only:** no code was changed. The review text lives under `docs/reviews/2026-10-architecture-review/` on branch `claude/wonderful-bardeen-g5cw88`.

---
_Generated by [Claude Code](https://claude.ai/code)_
