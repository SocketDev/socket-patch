# Hosted-mode production e2e

`crates/socket-patch-cli/tests/e2e_hosted_production.rs` is the only test suite
in this repo that exercises [hosted mode](../ecosystems.md#mode--ecosystem-matrix)
(`scan --mode hosted`) against the **real** Socket production service with **no
mocking anywhere**. Every other hosted-mode capstone (`e2e_redirect_*_build.rs`)
serves the patch artifact from a local wiremock, which proves the CLI's rewrite
grammar but cannot notice production drifting away from it.

## What it proves

For each ecosystem × package manager:

1. install a pinned, known-vulnerable dependency from its **real** upstream
   registry with the **real** package manager;
2. assert the installed bytes are pristine (anti-vacuity);
3. `socket-patch scan --mode hosted --json --yes` — resolves a hosted patch
   reference from `patches-api.socket.dev` and rewrites the lockfile / registry
   config to point at `patch.socket.dev`;
4. assert the rewrite landed (patch host + patch UUID present, integrity pin
   replaced);
5. **wipe the install tree and reinstall from the rewritten lock alone** — the
   package manager itself fetches from `patch.socket.dev` and verifies the
   integrity pin it was handed;
6. assert the reinstalled bytes carry the patch.

Step 5 is the point. It is the only place in this repo where a third-party
package manager — not socket-patch — downloads a Socket-hosted artifact and
independently verifies its checksum.

## Required production patches

The suite is pinned to these patches. They must stay **published** and
**free-tier** on `patches-api.socket.dev`; the suite runs against the
unauthenticated public proxy on purpose, because that is the surface every user
without a token gets. No API token is used, and `SOCKET_API_TOKEN` is scrubbed
from the child environment.

| Ecosystem | PURL | Patch UUID | Advisory | Used by |
|-----------|------|------------|----------|---------|
| npm | `pkg:npm/minimist@1.2.2` | `80630680-4da6-45f9-bba8-b888e0ffd58c` | GHSA-xvch-5gv4-984h / CVE-2021-44906 | all five npm-family legs |
| PyPI | `pkg:pypi/urllib3@1.26.18` | `de58c8b8-796c-4b6d-8a48-539b5563db76`, `26242e35-f867-4da8-8789-f0d2ea49e0f1`, `e828efa5-5c6d-43f3-9909-03f5ac232b98` | GHSA-38jv-5279-wg99, GHSA-2xpw-w6gg-jr37, GHSA-gm62-xv2j-4w53 | requirements.txt, uv.lock |
| Cargo | `pkg:cargo/traitobject@0.1.1` | `cf2e6f58-d9fa-4096-9151-c34afa717f89` | GHSA-pp8r-vv2j-9j5v | cargo sparse-registry leg |
| RubyGems | `pkg:gem/activestorage@6.0.3` | any of `15e960b5-f432-4b6c-b8aa-534a2b419323` (GHSA-m42x-37p3-fv5w / CVE-2020-8162), `6c4141c5-1535-4fd2-9db1-b5f8e4834bdb` (GHSA-w749-p3v6-hccq / CVE-2022-21831, published 2026-08-19) | see UUID column | bundler leg |

urllib3 1.26.18 carries **three** distinct free patches, one per advisory. Which
one the resolver returns is a server-side ordering detail, so the suite accepts
any of the three rather than pinning one — pinning would go red on an unrelated
server-side reorder.

`preflight_required_patches_are_published` checks all four every run and fails
first with the offending PURL named, so a withdrawn patch produces one clear
failure instead of N confusing ones that look like CLI regressions.

### If a required patch is withdrawn

1. Find a replacement in the same ecosystem:
   ```sh
   # version-less lookup lists every patched version of a package
   curl -s 'https://patches-api.socket.dev/patch/by-package/pkg%3Anpm%2Flodash' | jq
   ```
   Prefer a package that is small, dependency-free, and installable by every
   package manager in that ecosystem's leg.
2. Update the catalog constants at the top of `e2e_hosted_production.rs`
   (`*_PURL`, `*_NAME`, `*_VERSION`, `*_UUID`) **and** the table above.
3. If the new patch does not inject the `// Socket Community Patch` header
   (Cargo crates do not), pick a marker unique to the patch and set the
   ecosystem's `*_MARKER` constant.

## Ecosystem coverage, and the honest gaps

| Ecosystem | Hosted mode | Free patches in production | Suite coverage |
|-----------|-------------|----------------------------|----------------|
| npm | ✅ | ✅ many | ✅ npm, npm-shrinkwrap, pnpm, yarn classic, yarn berry, bun |
| PyPI | ✅ (requirements.txt + uv.lock only) | ✅ many | ✅ requirements.txt, uv.lock |
| Cargo | ✅ | ✅ 1 crate | ✅ sparse registry |
| RubyGems | ✅ | ✅ (this suite pins one purl/UUID: `activestorage@6.0.3`; the 2026-08-18 republish covers more versions) | ✅ full bundler install proof |
| Maven | ✅ | ❌ **none** | canary only |
| NuGet | ✅ | ❌ **none** | canary only |
| Composer | ✅ | ❌ **none** | canary only |
| Go | ✅ free tier [by design](../design/golang-hosted.md) (paid: ❌ [analysis](../design/golang-hosted-no-go.md)) | ❌ none published yet | shape guard (redirects only via `goproxy` override) |
| Deno | ❌ not supported | — | negative assertion |

Maven, NuGet and Composer all *implement* hosted mode, but production publishes
**zero** free-tier patches for them, so there is nothing real to redirect to.
Rather than skipping silently, `canary_unpublished_ecosystems` probes production
every run and reports the moment that changes, so coverage can be extended
deliberately. It does not fail when patches appear — production publishing a
patch is not a socket-patch regression — but
`SOCKET_PATCH_HOSTED_E2E_CANARY_STRICT=1` makes it fail, for use in a scheduled
nag run.

PyPI's poetry / pdm / pipenv locks are **not** rewritten by hosted mode (see the
[matrix](../ecosystems.md#mode--ecosystem-matrix)); those flavors are vendored-mode
only, so there is no hosted leg to write for them.

Two supported hosted shapes are deliberately **not** covered here:

* **npm Rush monorepos** — hosted mode supports them (`common/config/rush/pnpm-lock.yaml`
  plus per-subspace locks), but a faithful leg needs a real `rush install`, which
  is a much heavier fixture than everything else in this file. It also inherits
  the pnpm issue below. Covered by `e2e_redirect_rush_sim.rs` against a mock.
* **yarn berry with the PnP linker** — documented as untested for hosted mode
  (the lock rewrite fires, but PnP's `.yarn/cache` resolution is not exercised).
  The berry leg here pins `nodeLinker: node-modules`, matching the documented
  support boundary.

## Known issues this suite surfaced

All were found by running against real production; none is a test bug.

### 1. `gem` — hosted mode was unusable for gems with dependencies (SERVER) — FIXED

Socket's gem patch-registry used to serve a compact index whose `/info/<gem>`
line declared **no runtime dependencies** while the `.gem` it served declared
several, so bundler's `ensure_same_dependencies` check failed closed with
`Bundler::APIResponseMismatchError` — hosted gem mode was unusable for any gem
with runtime dependencies. (The suite's original pin, activestorage@7.0.2.2 /
`2535d43d-…` / GHSA-w749-p3v6-hccq, was unpublished on 2026-08-14 pending the
fix.)

**Fixed by the 2026-08-18 gem catalog republish**: the patch-registry's compact
index now serves the gemspec's runtime dependencies (verified against
activestorage@6.0.3: `/versions` 200, `/info/activestorage` 200 with the full
dep list). The leg's probe-based tolerance — pass on a non-2xx `/versions`,
enforce on 2xx — retired itself as designed and was deleted along with its
`SOCKET_PATCH_HOSTED_E2E_GEM_STRICT` knob; the leg is now the unconditional
`gem_bundler_hosted_install_proof`.

**Latent, still open (server)**: the registry's `/api/v1/dependencies` route
answers 200 with an empty body. Unreachable today — bundler only falls back to
the Dependency fetcher when the compact index is unavailable — but it would
resurface as a confusing Marshal error if the compact index ever broke again.

### 2. `pnpm` — pnpm 11 rejects hosted lockfiles by default (CLI UX gap)

pnpm 11 added a lockfile supply-chain policy that compares every entry's tarball
URL against the registry's published metadata. Hosted mode deliberately rewrites
that URL, so the policy rejects the lockfile:

```
[ERR_PNPM_TARBALL_URL_MISMATCH] minimist@1.2.2 has a tarball URL
(https://patch.socket.dev/...) that does not match the registry's published
metadata (https://registry.npmjs.org/minimist/-/minimist-1.2.2.tgz)
```

`pnpm install --trust-lockfile` is pnpm's documented opt-out and works (verified:
the patched artifact installs cleanly). Neither `--trust-policy-exclude` nor
`--no-verify-store-integrity` helps — this is a distinct check.

**Fix belongs in the CLI**: `scan --mode hosted` should emit a `redirect_pnpm_*`
warning naming `--trust-lockfile` when it rewrites a `pnpm-lock.yaml`, the way it
already warns for `redirect_gem_no_checksums_section` and
`redirect_rush_repo_state_stale`. The suite currently retries with the flag and
reports the gap loudly.

### 3. `uv.lock` — the `sdist` entry is rewritten to a wheel URL (CLI, minor)

The uv.lock rewriter points the `sdist` entry at the patched **wheel** and keeps
the original sdist's `size`, producing an entry whose URL, hash and size are
mutually inconsistent:

```toml
# pristine
sdist  = { url = ".../urllib3-1.26.18.tar.gz",            hash = "sha256:f8ecc1bb…", size = 305687 }
wheels = [{ url = ".../urllib3-1.26.18-py2.py3-none-any.whl", hash = "sha256:34b97092…", size = 143835 }]

# after scan --mode hosted
sdist  = { url = "…patch.socket.dev/…-py2.py3-none-any.whl", hash = "sha256:ccc9a9e0…", size = 305687 }
wheels = [{ url = "…patch.socket.dev/…-py2.py3-none-any.whl", hash = "sha256:ccc9a9e0…", size = 143835 }]
```

uv tolerates it today because it prefers the wheel, so the leg passes. It would
bite on a `--no-binary` resolve or a platform with no matching wheel. The
rewriter should either leave `sdist` alone or update its `size` alongside the
URL and hash.

## Running

```sh
# everything, soft-skipping legs whose toolchain is absent
cargo test -p socket-patch-cli --test e2e_hosted_production -- --ignored

# one leg
cargo test -p socket-patch-cli --test e2e_hosted_production -- --ignored \
  yarn_berry_hosted_install_proof --nocapture
```

The suite is `#[ignore]`-gated, so it stays out of the `test` and `e2e` jobs and
runs only where it is explicitly asked for.

### Environment knobs

| Variable | Effect |
|----------|--------|
| `SOCKET_PATCH_HOSTED_E2E_STRICT=1` | Turn every "toolchain missing" soft-skip into a hard failure. **CI sets this** — a required check must never report green on an unexercised leg. |
| `SOCKET_PATCH_HOSTED_E2E_CANARY_STRICT=1` | Fail when maven/nuget/composer gain their first free published patch. |

### Toolchains

`npm`, `corepack` (pnpm + yarn classic + yarn berry), `bun`, `uv`, `cargo`,
`ruby` + `bundle` (**≥ 2.6** — `bundle lock --add-checksums` emits the CHECKSUMS
section the gem rewrite pins into), `go`.

### Network egress

`patches-api.socket.dev`, `patch.socket.dev`, `registry.npmjs.org`, `pypi.org`,
`files.pythonhosted.org`, `static.crates.io`, `index.crates.io`, `rubygems.org`.

## CI: the `hosted-e2e` job

Defined in `.github/workflows/ci.yml`. It is intended to be a **required** status
check in branch protection, registered under exactly the name `hosted-e2e`.

The job deliberately has **no** job-level `if:`, **no** `needs:`, **no** matrix
and **no** `continue-on-error`. A *skipped* required check is ambiguous to branch
protection and can wedge a PR at "Expected — waiting for status", so the job
always runs and always reaches success or failure; the kill switch gates the
*steps*, not the job.

It retries the suite up to three times with backoff, because the public proxy
intermittently returns 503 "Service temporarily over capacity" — the documented
reason the older live-API suites were pulled from the PR matrix.

### Escape hatch — production is down and this is blocking merges

Set a repository variable (Settings → Secrets and variables → Actions →
Variables):

```
HOSTED_E2E_DISABLED = true
```

then hit **Re-run failed jobs** on any blocked PR. `vars` is read at job-run
time, so no commit and no push is needed: the job goes green with a loud
`::warning::` and a **BYPASSED** banner in the job summary, and every open PR
clears on its next re-run.

**Delete the variable to re-arm.** Any value other than exactly `true` (including
`yes`, `1`, `True`) leaves the suite armed — a typo must not silently disable
production coverage.

For a single run without touching the variable: **Actions → CI → Run workflow**,
then `hosted_e2e = force` (ignore the variable) or `skip` (bypass this run).

### Turning it on

The job runs as soon as this lands. Making it *required* is a one-time repo
setting, done after the first green run on `main`:

> Settings → Branches → branch protection rule for `main` → Require status
> checks to pass → add **`hosted-e2e`**.
