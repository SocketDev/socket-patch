# Releasing socket-patch

One release = one version-bump PR + one dispatch of the **Release** workflow.
Every ecosystem package (crates.io, npm, PyPI, RubyGems ×2, Packagist, Maven
Central, NuGet) publishes from that single dispatch.

## 1. Open the version-bump PR

From a developer machine (preferred — CI runs on the PR normally):

```sh
scripts/bump-version.sh 3.4.0 --pr
```

This stamps `3.4.0` into every packaging site (`scripts/version-sync.sh`),
rolls `CHANGELOG.md`'s `[Unreleased]` notes into a dated `## [3.4.0]` section
(it refuses to run if `[Unreleased]` is empty — write the notes first), and
opens a `release/v3.4.0` PR whose body carries the rolled-over notes.

Alternatively, dispatch the **Version Bump** workflow from the Actions tab
(input: the new version). Caveat: a PR opened by a workflow's `GITHUB_TOKEN`
does not trigger `pull_request` CI — close/reopen the PR (or push any commit
to its branch) to kick the checks.

CI's `release-readiness` job runs the full release gate on the bump PR
(`scripts/release-lint.sh`): version coherence across all packaging sites,
a non-empty CHANGELOG section for the new version, and no pre-existing tag.
On every *other* PR the same job runs the coherence check only, so a
hand-edited version in any single site fails CI immediately.

## 2. Merge, then dispatch **Release**

Actions → **Release** → Run workflow (on the default branch). Optionally run
once with `dry-run: true` — that builds all 14 targets but skips tagging and
publishing.

The real run: re-verifies the release gate → builds the matrix → creates and
pushes `v<version>` → creates the GitHub release with `SHA256SUMS` → fans out
to all registries in parallel (OIDC everywhere except Maven Central, which
has no trusted-publishing option and uses the portal token + GPG key from the
`maven-central` environment).

## 3. Approve npm (the one manual step)

The npm job *stages* rather than publishes. Approve with 2FA — **platform
packages first, then `@socketsecurity/socket-patch`** — via the link in the
run's step summary, so optionalDependencies resolution never sees the main
package without its binaries. The launcher channels (gem, composer, maven,
nuget) go live without human action: they fetch binaries from the GitHub
release at run time.

## If a job fails mid-release

Fix the cause and use **"Re-run failed jobs"** on the same run. Every job is
idempotent: the tag re-push is a no-op, the GitHub release re-uploads with
`--clobber`, and each registry job probes for an already-published version
and skips it. A partial release never requires deleting tags or re-bumping.

## One-time registry setup

Environments, trusted publishers, the `dev.socket` namespace claim, the GPG
key, and the nuget.org policy are listed in the checklist of
[PR #138](https://github.com/SocketDev/socket-patch/pull/138). Until a
registry's credentials exist, its job skips with a `::notice` instead of
failing the release.
