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
publishing; no long-lived registry secrets).

## 4. Approve npm (the one manual step)

The npm job *stages* rather than publishes. Approve with 2FA — **platform
packages first, then `@socketsecurity/socket-patch`** — so
optionalDependencies resolution never sees the main package without its
binaries. Approve from the run's step summary links, the
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
gem list --remote --exact --all socket-patch | grep "$V"     # rubygems
```

End-to-end smoke test of the installer path:

```sh
curl -fsSL https://install.socket.dev/patch | sh && socket-patch --version
```

## If a job fails mid-release

Fix the cause and use **"Re-run failed jobs"** on the same run. Every job is
idempotent: the tag re-push is a no-op, the GitHub release re-uploads with
`--clobber`, and each registry job probes for an already-published version
and skips it. A partial release never requires deleting tags or re-bumping.

## One-time registry setup

Deployment environments (`pypi`, `rubygems`) and each registry's trusted
publisher (repo `SocketDev/socket-patch` + workflow `release.yml`, plus the
environment where one is named above) are listed in the checklist of
[PR #138](https://github.com/SocketDev/socket-patch/pull/138). Until a
registry's credentials exist, its job skips with a `::notice` instead of
failing the release.
