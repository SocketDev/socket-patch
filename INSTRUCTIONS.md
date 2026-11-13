# Bug-hunt routine instructions

These are the shared operating instructions for the scheduled socket-patch
bug-hunt routines, one per package manager. Each routine's prompt defines
`{SLUG}` (for example `pnpm`), `{NAME}` (for example `pnpm`), `{ECO}` (its
ecosystem) and `{DISC}` (its ledger discussion number), plus the version range,
the docs and the focus areas. Substitute them everywhere below. Maintainers
edit this file to retune every routine at once.

Never edit `CHANGELOG.md` or suggest changelog entries in issues. Release
notes are written only by the release agent when a release is cut.

Deno is out of scope (maintainer decision, 2026-10-28). Don't hunt, probe,
file or re-triage Deno bugs, including Deno behavior you come across while
hunting another package manager. Leave existing `pm:deno` issues alone.

The product's first rule is "do no harm": a project that installed and built
cleanly before socket-patch touched it must still do so afterwards. A finding
that breaks a user's install, build or CI ranks above one that misses a patch.

## GitHub access
GraphQL is blocked in cloud sessions (HTTP 403), so `gh issue ...`, `gh pr ...`
and `gh api graphql` fail. Don't try them. Use REST through `gh api`, or the
GitHub MCP tools your session provides:
- List: `gh api 'repos/SocketDev/socket-patch/issues?state=all&labels=pm:{SLUG}&per_page=100'`
  (the list includes PRs; drop items that have a `pull_request` key).
- Search: `gh api -X GET search/issues -f q='repo:SocketDev/socket-patch <keywords>'`.
- File: `gh api -X POST repos/SocketDev/socket-patch/issues -f title=... -F body=@issue.md -f 'labels[]=bug' -f 'labels[]=bughunt' -f 'labels[]=pm:{SLUG}'`.
- Comment: `-X POST repos/SocketDev/socket-patch/issues/N/comments -F body=@c.md`.
  Close: `-X PATCH repos/SocketDev/socket-patch/issues/N -f state=closed -f state_reason=completed|not_planned`.
Every agent in this repo shares one GitHub API budget. Print compact fields
with `--jq` instead of whole JSON bodies, don't paginate without a cap, and
on a 403 or 429 that mentions a rate limit stop calling GitHub and finish
with what you have.

## Ledger mechanics
Cloud sessions can't write to GitHub Discussions, so the ledger lives on this
orphan branch (`bughunt/ledger`), and `.github/workflows/bughunt-ledger.yml`
mirrors it:
- Every new `entries/{SLUG}/*.md` file is posted as a comment on discussion #{DISC}.
- `state/{SLUG}.md` is copied into the discussion body whenever it changes.
- `known-non-bugs/{SLUG}.md` is not mirrored. It is a reference file you search.

Keep the ledger small. Every run pays to read it.
- `state/{SLUG}.md` is a summary of where things stand now, not a log. Keep it
  under 15 KB. Rewrite cells and backlog items in place; never append a
  per-run section or a per-run paragraph to it.
- Read only `state/{SLUG}.md` and the two newest files in `entries/{SLUG}/`.
  Never read the older entries or all of `known-non-bugs/{SLUG}.md`; search
  them with `git grep` when you need to know whether something was covered or
  ruled out before.
- If your state file is over 15 KB (it predates this rule), compact it this
  run: move its "Known non-bugs" bullets into `known-non-bugs/{SLUG}.md`,
  reduce the coverage matrix to one row per workflow, and drop the per-run
  narrative. The old version stays in the branch history.

## Each run
1. **Load state.** `git fetch origin bughunt/ledger main`, then read
   `state/{SLUG}.md` and the two newest entries with `git show`. List the open
   issues labelled `pm:{SLUG}` (numbers, titles and labels only).
2. **Update to main.** Check out `origin/main` and note its SHA and the latest
   release tag. If the state file records the same SHA, no new {NAME} release
   has come out since, and the backlog is empty, there is nothing new to
   test: update the `Last run` line in the state file, push, and stop without
   adding an entry. Otherwise build the CLI
   (`cargo build --release -p socket-patch-cli`). When you need to find the
   first bad version of a regression, install the latest published release as
   well.
3. **Re-triage (keep this short).** Re-check up to 2 open `bughunt` +
   `pm:{SLUG}` issues on the current main, oldest first, skipping any labelled
   `agent:needs-human`.
   - Fixed: comment with the evidence (the commit or PR, and the command
     output) and close it.
   - One of your own earlier issues turns out to be a false positive: comment
     to explain why, add `invalid`, close it, and add one line to
     `known-non-bugs/{SLUG}.md`.
   - Never close or relabel an issue that doesn't carry `bughunt`; leave a
     comment on it instead.
4. **Hunt.** Take the next items from the backlog in the state file, in
   order. When the backlog runs low, add to it from these axes:
   - {NAME} version, and the runtime version where it matters: the oldest
     supported release, each major, the newest release, and any boundary
     version the docs name.
   - Mode: agent, vendored, hosted.
   - Command: scan, get, apply, vendor, rollback, remove, repair, setup, vex.
     Also switching modes on one project, re-runs (idempotency) and `--json`
     output.
   - Project shapes: workspaces and monorepos, CRLF / BOM / mixed line
     endings, paths with spaces or unicode, symlinks, scoped or aliased names,
     every lockfile format version, frozen / offline / locked installs, warm
     and cold caches, lockfile-only checkouts, interrupted runs.
   - Always prove a failure with the **real {NAME} install and build**, never
     by reading source alone. A rewrite that looks right but makes the next
     frozen install fail, silently reinstalls unpatched bytes or loses
     integrity pinning is a bug. So is a VEX statement for a patch that isn't
     applied.
   - For patch data, prefer the repo's own e2e harnesses and fixtures
     (`crates/*/tests`, `tests/`, `scripts/`). Free public patches are fine
     when the sandbox can reach the API. No Socket API key or other secret is
     available; don't look for one.
5. **Linux only.** The sandbox runs Linux, and the probe workflows that used
   to cover macOS and Windows are switched off on purpose (they starved the
   shared runners). Don't push probe branches or any branch other than
   `bughunt/ledger`, don't open PRs, and don't modify workflows. When a bug
   plausibly behaves differently on macOS or Windows, say so in the issue.
6. **Filing bar.** Before opening an issue, every one of these must hold:
   - (a) It reproduces at least twice on the current main, with a minimal repro.
   - (b) It isn't a documented limitation or refusal. A refusal that fires when
     it shouldn't, or fails to fire when it should, IS a bug.
   - (c) It isn't an environment or network flake, or a sandbox artifact
     (running as root, no network).
   - (d) No issue or PR, open or closed, already covers it (search by error
     code, symptom and file), and `git grep` over `known-non-bugs/{SLUG}.md`
     doesn't list it.
   If an existing issue covers it and you have new information (another
   version, or the first bad version), add one comment to that issue instead.
   If the bug belongs to a different package manager, don't file it; hand it
   over by adding `entries/<their-slug>/<YYYYMMDDTHHMMSSZ>-from-{SLUG}.md` with
   the evidence (the slugs are the keys of `discussions.json`). File at most 3
   new issues per run. Quality matters more than volume: a false report costs
   a fixer run to disprove.
7. **Issue format.** A plain-sentence title stating the defect (for example
   "Hosted pnpm 9 redirect drops trustLockfile when pnpm-workspace.yaml uses
   CRLF"). The body:
   - First line: `[agent] Found by the scheduled {NAME} bug-hunt routine (ledger #{DISC}).`
   - A summary, the impact on the user, and a repro script.
   - Expected and actual behavior, citing the docs or
     `crates/socket-patch-cli/CLI_CONTRACT.md` for "expected".
   - A table of the versions where it reproduces and where it doesn't.
   - The first bad release or commit, if you found one.
   - The suspect code location (`path:line`).
   - Labels: `bug`, `bughunt`, `pm:{SLUG}`.
   Don't fix code or open PRs.
8. **Update the ledger.** Work in a separate worktree of
   `origin/bughunt/ledger`.
   - Add exactly one new file, `entries/{SLUG}/<YYYYMMDDTHHMMSSZ>.md`, at most
     60 lines. It becomes the discussion comment. Its first line is
     `[agent] <UTC date>: {NAME} bug-hunt run`. Include the main SHA and
     release you tested, the cells you covered (pass, fail or blocked), the
     issues you filed, commented on or closed (with links), and the false
     positives you ruled out.
   - Rewrite `state/{SLUG}.md` in place. Its first line is
     `[agent] Progress ledger for the scheduled {NAME} bug-hunt routine (label pm:{SLUG}).`
     Then a `Last run:` line (date, main SHA, release, newest {NAME} version),
     and three sections: `## Coverage matrix` (one row per workflow, one
     column per mode; each cell is pass with the versions and date, fail with
     the issue number, or untested), `## Backlog` (the next 5 to 10 items, most
     valuable first) and `## Known non-bugs` (a pointer to
     `known-non-bugs/{SLUG}.md`, plus at most the 10 entries most likely to be
     re-filed).
   - Append one line per newly ruled-out false positive or documented
     limitation to `known-non-bugs/{SLUG}.md`.
   - Touch no other file, except a handover entry for a sibling. Commit with a
     short message and push with
     `git push origin HEAD:refs/heads/bughunt/ledger`. If the push is rejected
     because a sibling pushed first, `git pull --rebase origin bughunt/ledger`
     and push again. Never force-push.
   - Check that the latest "bughunt ledger to discussions" workflow run on the
     branch succeeded
     (`gh api 'repos/SocketDev/socket-patch/actions/workflows/bughunt-ledger.yml/runs?per_page=1'`).
     If it failed, say so in your final message.

Time-box the run to about 90 minutes. End with a short summary: what you
tested, what you found, and the links.
