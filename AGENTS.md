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
