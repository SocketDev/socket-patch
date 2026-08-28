# Releasing socket-patch — publish runbook

One release = one version-bump PR + one dispatch of the **Release** workflow.
The CLI publishes to five channels, all from that single dispatch:

| Channel | Package(s) | Auth |
|---------|------------|------|
| GitHub release | prebuilt binaries for 14 targets + `SHA256SUMS` (also feeds `install.socket.dev` / `scripts/install.sh`, `--update`, and the gem launcher) | workflow `GITHUB_TOKEN` |
| crates.io | `socket-patch-core`, `socket-patch-cli` | OIDC trusted publishing, no environment |
| npm | `@socketsecurity/socket-patch` + 14 platform packages | OIDC via `npm stage publish`; **manual 2FA approval** |
| PyPI | `socket-patch`, `socket-patch-hook` | OIDC trusted publishing; environment `pypi` |
| RubyGems | `socket-patch` (launcher gem), `socket-patch-bundler` | OIDC trusted publishing; environment `rubygems` |

## 1. Write the release notes

Make sure `CHANGELOG.md`'s `[Unreleased]` section describes this release —
`bump-version.sh` refuses to run if it is empty, and `release-lint.sh` blocks
a release whose CHANGELOG section is missing or empty.

## 2. Open the version-bump PR

From a developer machine (preferred — CI runs on the PR normally):

```sh
scripts/bump-version.sh 3.4.0 --pr
```

This stamps `3.4.0` into every packaging site (`scripts/version-sync.sh`:
`Cargo.toml`, the npm main + platform packages and lockfile, both PyPI
`pyproject.toml`s, both gemspecs and the gem launcher constant), rolls
`[Unreleased]` into a dated `## [3.4.0]` section, and opens a
`release/v3.4.0` PR whose body carries the rolled-over notes.

Alternatively, dispatch the **Version Bump** workflow from the Actions tab
(input: the new version). Caveat: a PR opened by a workflow's `GITHUB_TOKEN`
does not trigger `pull_request` CI — close/reopen the PR (or push any commit
to its branch) to kick the checks.

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
pushes `v<version>` → creates the GitHub release with `SHA256SUMS` → fans out
to crates.io, npm, PyPI, and RubyGems in parallel (all OIDC trusted
publishing; no long-lived registry secrets). Each registry leg is its own
workflow (`publish-cargo.yml`, `publish-npm.yml`, `publish-pypi.yml`,
`publish-rubygems.yml`), dispatched at the release tag by the release run
and watched to completion, so the release run's job graph still reflects
each registry's outcome (its step summaries link the four leg runs) — and
each leg can equally be dispatched by hand (see "If a job fails
mid-release"). The `release.yml` header records why the legs are dispatched
runs rather than reusable workflows (registry trusted-publisher filename
matching; npm allows one publisher per package).

## 4. Approve npm (the one manual step)

The npm leg *stages* rather than publishes. Approve with 2FA — **platform
packages first, then `@socketsecurity/socket-patch`** — so
optionalDependencies resolution never sees the main package without its
binaries. Approve from the **Publish npm** run's step summary links (the
release run's `npm-publish` job summary links to that run), the
[org staged-packages dashboard](https://www.npmjs.com/settings/socketsecurity/staged-packages),
or the CLI (`npm stage list` / `npm stage approve <stage-id>`, npm 11.15+).

The other channels go live without human action; the RubyGems launcher gem
fetches its binary from the GitHub release at run time.

## 5. Verify

```sh
V=3.4.0
gh release view "v$V" --repo SocketDev/socket-patch          # binaries + SHA256SUMS
cargo info socket-patch-cli | grep "$V"                      # crates.io
npm view "@socketsecurity/socket-patch@$V" version           # npm (after approval)
curl -sf "https://pypi.org/pypi/socket-patch/$V/json" >/dev/null && echo pypi ok
curl -sf "https://pypi.org/pypi/socket-patch-hook/$V/json" >/dev/null && echo hook ok
gem list --remote --exact --all socket-patch | grep "$V"     # rubygems
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
   Re-running a failed fan-out job dispatches a fresh run of that registry's
   publish workflow *as of the tag* (a re-run never picks up workflow edits).
2. **Dispatch the failed registry's own workflow** — right when the fix
   needed a change (registry-side config such as a trusted publisher, or a
   workflow edit landed on the default branch): Actions → **Publish
   crates.io** / **Publish npm** / **Publish PyPI** / **Publish RubyGems** →
   Run workflow, entering the release version (`X.Y.Z`, no `v`) and leaving
   the other inputs blank. This runs the publish workflow as it exists on the
   dispatched branch (default: the default branch), so workflow fixes apply.
   Nothing rebuilds: each publish workflow checks out the `v<version>` tag
   and (npm/PyPI) takes the prebuilt binaries from the GitHub release's
   assets, verified against `SHA256SUMS` — the same inputs the release run
   would have published. The GitHub release must exist with all assets, so
   failures in `build`, `tag`, or `github-release` itself are still fixed
   via the release run.

## One-time registry setup

Deployment environments (`pypi`, `rubygems`) and each registry's trusted
publisher are listed in the checklist of
[PR #138](https://github.com/SocketDev/socket-patch/pull/138). All four
registry channels authenticate via OIDC trusted publishing, so a missing or
misconfigured trusted publisher (or environment) **fails that channel's
job** — configure it before dispatching a real release. The one
non-blocking push is the `socket-patch-bundler` gem (`continue-on-error`
Phase-2 scaffolding).

Since the publish legs moved into their own workflow files, each trusted
publisher is registered against repo `SocketDev/socket-patch` + **the
publish workflow's filename** (not `release.yml`). The legs only ever run
as top-level `workflow_dispatch` runs of their own file — whether the
release run dispatched them or a maintainer did — so the OIDC token's
`workflow_ref` and `job_workflow_ref` claims both name that file, and one
registration per package satisfies every registry's matching rule (npm and
crates.io match the top-level workflow; PyPI and RubyGems match the
job-defining workflow).

| Registry | Publisher workflow | Environment |
|----------|--------------------|-------------|
| crates.io (`socket-patch-core`, `socket-patch-cli`) | `publish-cargo.yml` | — |
| npm (main + 14 platform packages) | `publish-npm.yml` | — |
| PyPI (`socket-patch`, `socket-patch-hook`) | `publish-pypi.yml` | `pypi` |
| RubyGems (`socket-patch`, `socket-patch-bundler`) | `publish-rubygems.yml` | `rubygems` |

**Migration from the `release.yml` publishers:** crates.io (up to 5 configs
per crate), PyPI, and RubyGems (both: multiple publishers per package) can
carry the old `release.yml` publisher alongside the new one until every
release run predating this split — whose re-run legs still authenticate as
`release.yml` — has fully landed; then delete the `release.yml` publishers.
npm allows only **one** trusted publisher per package, so its cutover is
atomic: edit each package's publisher from `release.yml` to
`publish-npm.yml` once no pre-split npm job may need re-running (approving
already-staged versions needs no OIDC, only re-staging does).
