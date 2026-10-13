# Releasing socket-patch — publish runbook

> **Being replaced.** The weekly release train
> ([docs/release-train/DESIGN.md](release-train/DESIGN.md)) replaces this
> process as its PRs land; this runbook is rewritten for it at the end. The
> version-bump script and workflow are already gone — step 2 below does the
> same chores with `scripts/release.py`.

One release = one version-bump PR + one dispatch of the **Release** workflow.
The CLI publishes to three channels, all from that single dispatch:

| Channel | Package(s) | Auth |
|---------|------------|------|
| Standalone binary (preferred) | GitHub release archives for 14 targets + `SHA256SUMS`; installed via `install.socket.dev/patch`, updated with `--update` | workflow `GITHUB_TOKEN` |
| crates.io | `socket-patch-core`, `socket-patch-cli` | OIDC trusted publishing, no environment |
| npm | `@socketsecurity/socket-patch` + 14 platform packages | OIDC via `npm stage publish`; **manual 2FA approval** |

The npm distribution is also required by the official Socket CLI. v5 no longer
builds or publishes the PyPI and RubyGems CLI packages or their install hooks.
See the [migration instructions](migrating-to-v5.md#installation-channels).

## 1. Write the release notes

Release notes are written only at release time: PRs never touch
`CHANGELOG.md`. The release agent (the release-train routine's `release-sync`
PR, or whoever cuts the release by hand) writes the `[Unreleased]` section from
the PRs merged since the last tag (`git log --first-parent <last-tag>..origin/main`)
and from reading the code they changed. Describe user-visible behavior, not
implementation details. `release.py changelog cut` refuses to run if the
section is empty, and `release-lint.sh` blocks a release whose CHANGELOG
section is missing or empty.

## 2. Open the version-bump PR

From a developer machine, on a branch off the default branch:

```sh
python3 scripts/release.py changelog cut --version 5.0.0 --date "$(date -u +%F)"
scripts/version-sync.sh 5.0.0
git commit -am "chore(release): 5.0.0" && gh pr create --fill
```

`changelog cut` rolls `[Unreleased]` into a dated `## [5.0.0]` section;
`scripts/version-sync.sh` (the offline `release.py stamp`) stamps `5.0.0` into
every packaging site: `Cargo.toml`, `Cargo.lock`'s workspace entries, the npm
main + platform packages and the npm lockfile. This legacy workflow publishes
stable versions only (`release-lint.sh --stable-only`).

CI's `release-readiness` job runs the full release gate on the bump PR
(`scripts/release-lint.sh`): version coherence across all packaging sites,
a non-empty CHANGELOG section for the new version, and no pre-existing tag.
On every *other* PR the same job runs the coherence check only, so a
hand-edited version in any single site fails CI immediately.

## 3. Merge, then dispatch **Release**

Actions → **Release** → Run workflow (on the default branch). Optionally run
once with `dry-run: true` — that builds all 14 targets but skips tagging and
publishing.

The real run: re-verifies the release gate → builds the matrix → creates and
pushes `v<version>` → creates the GitHub release with `SHA256SUMS` → publishes
to crates.io and npm in parallel (both use OIDC trusted publishing; no
long-lived registry secrets). The npm publish is the release run's own
`npm-publish` job. The crates.io leg is its own workflow (`publish-cargo.yml`),
dispatched at the release tag by the release run and watched to completion,
so the job graph still reflects its outcome (the `cargo-publish` step summary
links the leg run). The `release.yml` header records why npm runs inline and
crates.io is dispatched (registries match the trusted publisher on the
top-level workflow filename; npm allows one publisher per package).

## 4. Approve npm (the one manual step)

The npm leg *stages* rather than publishes. Approve with 2FA — **platform
packages first, then `@socketsecurity/socket-patch`** — so
optionalDependencies resolution never sees the main package without its
binaries. Approve from the release run's `npm-publish` job summary links, the
[org staged-packages dashboard](https://www.npmjs.com/settings/socketsecurity/staged-packages),
or the CLI (`npm stage list` / `npm stage approve <stage-id>`, npm 11.15+).

The standalone binaries and Cargo crates go live without human action.

## 5. Verify

```sh
V=5.0.0
gh release view "v$V" --repo SocketDev/socket-patch          # binaries + SHA256SUMS
cargo info socket-patch-cli | grep "$V"                      # crates.io
npm view "@socketsecurity/socket-patch@$V" version           # npm (after approval)
```

End-to-end smoke test of the installer path:

```sh
curl -fsSL https://install.socket.dev/patch | sh && socket-patch --version
```

## If a job fails mid-release

Two ways back, both safe — every job is idempotent: the tag re-push is a
no-op, the GitHub release re-uploads with `--clobber`, and each registry job
probes for an already-published (or already-staged) version and skips it. A
partial release never requires deleting tags or re-bumping.

1. **"Re-run failed jobs"** on the release run — right when the failure was
   transient (network, registry hiccup) and no workflow change is needed.
   Re-running `npm-publish` re-stages from the same run; re-running
   `cargo-publish` dispatches a fresh run of `publish-cargo.yml` *as of the
   tag*. A re-run never picks up workflow edits.
2. **Retry just the failed registry** — right when the fix needed a change
   (registry-side config such as a trusted publisher, or a workflow edit
   landed on the default branch), or the release run is gone:
   - **npm:** Actions → **Release** → Run workflow with `npm-retry-version`
     set to the release version (`X.Y.Z`, no `v`). Every other job is
     skipped; `npm-publish` re-stages from the existing release.
   - **crates.io:** Actions → **Publish crates.io** → Run workflow, entering
     the release version and leaving `distinct-id` blank.

   Both run the workflow as it exists on the dispatched branch (default: the
   default branch), so workflow fixes apply. Nothing rebuilds: each checks
   out the `v<version>` tag, and npm takes the prebuilt binaries from the
   GitHub release's assets, verified against `SHA256SUMS` — the same inputs
   the release run would have published. The GitHub release must exist with
   all assets, so failures in `build`, `tag`, or `github-release` itself are
   still fixed via the release run.

## One-time registry setup

Both registries authenticate via OIDC trusted publishing, so a missing or
misconfigured trusted publisher **fails that channel's job** — configure it
before dispatching a real release. Neither workflow uses a deployment environment.

Each trusted publisher is registered against repo `SocketDev/socket-patch` +
the filename of the **top-level** workflow that publishes, because both
registries match the OIDC token's `workflow_ref` claim:

| Registry | Publisher workflow |
|----------|--------------------|
| crates.io (`socket-patch-core`, `socket-patch-cli`) | `publish-cargo.yml` |
| npm (main + 14 platform packages) | `release.yml` |

npm allows only **one** trusted publisher per package, so npm publishes from
a job of `release.yml` itself — the release run and an `npm-retry-version`
retry both run as `release.yml`. The crates.io leg always runs as a
top-level `workflow_dispatch` run of `publish-cargo.yml`, whether the release
run dispatched it or a maintainer did. crates.io allows several publishers
per crate, so an old `release.yml` registration there can stay or go.
