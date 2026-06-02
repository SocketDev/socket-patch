# `setup`-flow test matrix (experimental)

This suite verifies the **intended** end-to-end behavior of
`socket-patch setup`: that after `setup` configures a project, a normal
package-manager install applies the project's patches *on its own*, with
no explicit `scan`/`apply` step.

It is **experimental and non-blocking**. `setup` only configures
npm-family install hooks today, so most non-npm cases are *expected to
fail*. The suite encodes the **aspirational** end state and records a
per-case **baseline** of what works now — the failing cases are a TODO
list for `setup`, not a broken test.

## The flow (per case)

Every case runs the same four steps via the bash driver `run-case.sh`:

0. **prepare** a throwaway project: declare the dependency and commit a
   patch set (`.socket/manifest.json` + `.socket/blobs/<hash>`).
1. **`socket-patch setup`** — configure install hooks (skipped in the
   `no_setup_control` scenario).
2. **native install** — `npm install` / `pip install` / `cargo fetch` /
   … for the package manager under test.
3. **check** — is the patch's marker now on disk in the installed file?

The apply step is fully offline (`SOCKET_OFFLINE=1 SOCKET_FORCE=1`,
inherited by the hook), so the only network use is the real package
install. No Socket API is contacted.

## Dimensions

`ecosystem × package-manager × scenario` — see `matrix.json` (the single
source of truth, consumed by both the runner script and the Rust
wrappers).

- **Package managers:** npm, yarn, pnpm, bun · pip, uv, poetry, pdm,
  hatch · cargo · bundler · go · mvn · composer · dotnet · deno.
- **Scenarios (single-project):**
  - `baseline_with_setup` — setup + install ⇒ patch applied *(ideal)*.
  - `no_setup_control` — install only ⇒ NOT applied *(the hook is the cause)*.
  - `empty_patchset` — empty manifest ⇒ NOT applied.
  - `wrong_target_patchset` — manifest targets a different package ⇒ NOT applied.
  - `alt_content_patchset` — a second patch set ⇒ its marker applied *(content tracks the manifest)*.

## Layouts

The driver's `SM_LAYOUT` selects the project shape (each layout has its
own `*_targets` / `*_scenarios` sections in `matrix.json`):

- **`single`** *(default)* — one project, one dependency. The 16-PM grid above.
- **`workspace`** — a **nested workspace/monorepo**: a root + several
  members (incl. a deeply-nested one and a member that does *not* use the
  patched package). Models real-world monorepo deployments and exercises
  `setup`'s workspace handling — npm/yarn write the hook to **every**
  member, pnpm only to the **root** — plus the cross-workspace apply on a
  single root install. Covered PMs: **npm, pnpm, yarn** (apply; the
  dependency hoists / lands in the pnpm store and is patched once) and
  **pip** (nested `requirements.txt` files) + **uv** (uv workspace, one
  shared `.venv`) as Python gaps. Scenarios: `workspace_with_setup`,
  `workspace_no_setup`.
- **`monorepo`** — a **polyglot all-ecosystem repo**: an npm workspace
  alongside python/rust/go/php/ruby/nuget/deno manifests. Confirms `setup`
  works in a mixed environment — it must configure the npm hooks and
  **not choke** on the foreign manifests; a root `npm install` then
  patches the npm slice. Runs in the npm image (the only one with the npm
  toolchain), so the foreign manifests are present to test setup's
  robustness, not installed. Scenarios: `monorepo_with_setup`,
  `monorepo_no_setup`.

> Real-world wiring note surfaced by the workspace layout: the install
> hook's `apply` must run with the package manager's per-script cwd (root
> for the project, the member dir for each member) — so member
> postinstalls find no manifest and no-op while the root applies. Forcing
> a single cwd makes every member target the root manifest and fail
> mid-install with "no packages found on disk". The driver therefore does
> **not** pin `SOCKET_CWD`.

## Result classification

Each case's `actual` is compared against both the aspirational `expect`
and the recorded `baseline`:

| classification | meaning |
|---|---|
| `pass`       | meets the ideal and matches the baseline |
| `known_gap`  | fails the ideal, exactly as recorded — expected today, non-blocking |
| `progress`   | better than the recorded baseline — update `baseline_supported` in `matrix.json`! |
| `regression` | diverged from the baseline the wrong way — the only thing that fails the runner |
| `error`      | the driver produced no parseable result |

The Rust wrappers (`tests/setup_matrix_<eco>.rs`) assert the **ideal**
(`actual == expect`), so they are red for `known_gap` cases — that is the
intended "TODO list" view. The `scripts/setup-matrix.sh` runner uses the
**baseline** view and only exits non-zero on a `regression`.

## Running it

Requires a Docker daemon (default) or host-installed toolchains
(`SOCKET_PATCH_TEST_HOST=1`).

```sh
# Build the shared base + a per-ecosystem image.
scripts/setup-matrix.sh build --ecosystem npm

# Run all npm-family cases and write a JSON report.
scripts/setup-matrix.sh run --ecosystem npm

# Filter to a single package manager / scenario.
scripts/setup-matrix.sh run --ecosystem pypi --pm uv
scripts/setup-matrix.sh run --scenario no_setup_control

# Run the nested-workspace and polyglot-monorepo cases.
scripts/setup-matrix.sh run --scenario workspace_with_setup
scripts/setup-matrix.sh run --scenario monorepo_with_setup

# Query the last results (agent-friendly JSON).
scripts/setup-matrix.sh query --status known_gap
scripts/setup-matrix.sh query --status regression
scripts/setup-matrix.sh query --layout workspace
scripts/setup-matrix.sh list --json

# Host mode (no Docker; needs the toolchains + a built binary on PATH).
SOCKET_PATCH_TEST_HOST=1 scripts/setup-matrix.sh run --ecosystem npm --host
```

Or via `cargo test` (the aspirational view; gated by the `setup-e2e`
feature; soft-skips when the image isn't built):

```sh
cargo test -p socket-patch-cli --features setup-e2e --test setup_matrix_npm
SOCKET_PATCH_TEST_HOST=1 cargo test -p socket-patch-cli --features setup-e2e --test setup_matrix_npm
```

## Files

- `matrix.json` — declarative case list: `targets`×`scenarios` (single),
  `workspace_targets`×`workspace_scenarios`, `monorepo_targets`×`monorepo_scenarios`, + markers.
- `run-case.sh` — self-contained flow driver (one case → JSON result),
  layout-aware (`SM_LAYOUT=single|workspace|monorepo`); generates the
  runner shims inline so it can be piped into a container.
- `shims/{npx,pnpm}` — reference copies of the PATH shims that route
  `npx`/`pnpm dlx @socketsecurity/socket-patch` to the locally-built
  binary (so the hook runs the binary under test, not a registry fetch).
- `results/latest.json` — most recent aggregate report (git-ignored).
- `../docker/Dockerfile.{npm,pypi,…}` — the per-ecosystem images
  (npm/pypi extended with the extra package managers).
- `../../crates/socket-patch-cli/tests/setup_matrix_<eco>.rs` — thin Rust
  wrappers around the same driver (incl. `setup_matrix_monorepo.rs`; the
  npm/pypi wrappers add `*_workspace` tests).

## Adding a package manager / ecosystem

1. Add a `targets[]` entry to `matrix.json` (image, package, purl,
   manifest key, whether `setup` supports it today via
   `baseline_supported`).
2. Teach `run-case.sh` how to scaffold + install + resolve the target
   file for the new `pm` (the `scaffold_project` / `run_install` /
   `resolve_target` case statements).
3. If a new toolchain is needed, add it to the relevant
   `tests/docker/Dockerfile.<eco>`.
4. Add a `#[test]` for the `pm` in the matching `setup_matrix_<eco>.rs`.
