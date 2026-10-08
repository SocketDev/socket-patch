# Agent instructions

## CHANGELOG.md is written only at release time

Don't add, edit or delete entries in `CHANGELOG.md` in a feature, fix,
refactor, CI or docs PR, even if a doc, template or reviewer asks for one.
The `[Unreleased]` section is written when a release is cut, by the release
agent, from the PRs merged since the last tag and the code itself. Put the
details of a change in its commit messages and PR description instead.

If a PR you work on already changes `CHANGELOG.md`, restore that file to its
merge-base version. The only exceptions are release PRs: a `release/v*`
branch, or the release train's `release-sync` PR.

## Wait on CI with a monitor, not a polling loop

To wait on a PR's checks or its trip through the merge queue, run
`scripts/ci-watch.sh` under the Monitor tool instead of looping on `sleep` and
`gh pr checks`, or polling with `/loop`. The script stays silent while
nothing changes and prints one line per event: a start summary, each failed
check by name, progress, queue position, and a final `DONE ...` line when it
exits.

```
scripts/ci-watch.sh [PR]            # until every check settles (exit 0 pass, 1 fail)
scripts/ci-watch.sh [PR] --merge    # through the merge queue (exit 0 merged, 1 closed/dequeued)
```

PR defaults to the current branch's. Give Monitor the maximum `timeout_ms`
and re-arm it when it expires before `DONE`. Act on a `fail:` line as soon as
it arrives; there's no need to wait for the remaining checks. If a session
has no Monitor tool, run the script with Bash `run_in_background` and read
its output when it exits.

## Run /code-review before a PR leaves draft

Before you mark a PR ready for review or add it to the merge queue, run
`/code-review high` on its diff. Fix every confirmed finding
(`/code-review high --fix` applies them) and push the fixes before going on.
For a finding you decide not to fix, say why in the PR description. When you
review someone else's PR, use `/code-review <PR> --comment` to post the
findings as inline comments.

## Share the GitHub API budget

Every agent and routine here calls GitHub as the same account, so all of
them share one budget of 5,000 REST requests and 5,000 GraphQL points
per hour. When it runs out, every agent stalls until the hourly reset.

- Before a read of more than ~20 requests, check what is left with
  `gh api -i repos/SocketDev/socket-patch | grep -i '^x-ratelimit-remaining'`.
  Trust that header over `gh api rate_limit`. Below 1,000, do only your
  most important write and finish early.
- Never `--paginate` over Actions runs, jobs or issues without a date
  filter and a page cap, and never run more than 2 GitHub requests in
  parallel.
- On a 403 or 429 that mentions a rate limit, stop calling GitHub and
  report what you have. Don't retry in a loop, and don't schedule a
  reminder just to retry after the reset.
- Keep at most one pending re-check reminder per PR, at least 30 minutes
  out.
