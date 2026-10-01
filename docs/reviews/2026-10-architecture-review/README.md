# socket-patch architecture review (October 2026)

A read-only architecture review of `main` at `2463257` ("feat!: consolidate the v5 patching workflow (#277)").
It covers architectural defects, duplicated code, features whose complexity outweighs their value, and user experience, with concrete cut / combine / refactor / simplify recommendations.

These files are written to be posted as a **GitHub Discussion**:

| File | Post as |
|---|---|
| [`01-summary.md`](01-summary.md) | The discussion body (executive summary, fix-now list, ranked recommendations, UX proposal, support tiers, sequencing, open questions) |
| [`02-cli.md`](02-cli.md) | Comment: CLI command layer and user experience |
| [`03-hosted.md`](03-hosted.md) | Comment: hosted mode (redirect, hosted engine, upstream restore, Node addon) |
| [`04-js-lockfiles.md`](04-js-lockfiles.md) | Comment: JavaScript lockfiles (npm, pnpm, yarn, bun, vlt) |
| [`05-vendored.md`](05-vendored.md) | Comment: vendored mode and non-JS backends |
| [`06-discovery-vex.md`](06-discovery-vex.md) | Comment: discovery, inventory and VEX |
| [`07-infra-agent.md`](07-infra-agent.md) | Comment: core infrastructure and agent mode |
| [`08-tests-ci-docs.md`](08-tests-ci-docs.md) | Comment: tests, CI, docs and distribution |
| [`09-appendix.md`](09-appendix.md) | Comment: open-issue backlog mapped to architecture; methodology |

Each file is under GitHub's 65,536-character limit for a discussion body or comment.
No code was changed by this review.
