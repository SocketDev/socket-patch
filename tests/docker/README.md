# Docker-driven e2e tests

This directory contains the Dockerfiles and per-ecosystem fixtures used
by the `tests/docker_e2e_*.rs` integration tests. Each test installs a
real package via its native package manager inside a Linux container
and drives the full `socket-patch scan` → `apply` chain against a
wiremock-served patch fixture, verifying the patched bytes on disk.

## What's tested

| Ecosystem | Real installer command                                       | Test depth                |
|-----------|---------------------------------------------------------------|---------------------------|
| npm       | `npm install minimist@1.2.2`                                  | install + scan + apply + rollback |
| pypi      | `pip install six==1.16.0` (venv + system site-packages)       | install + scan + apply + verify |
| gem       | `gem install colorize -v 1.1.0` (vendor/bundle + system)      | install + scan + apply + verify |
| cargo     | `cargo fetch` with `cfg-if = "=1.0.0"` in Cargo.toml          | install + scan + apply + verify |
| golang    | `go mod download github.com/gin-gonic/gin@v1.9.1`             | install + scan + apply + verify |
| maven     | `mvn dependency:get -Dartifact=org.apache.commons:commons-lang3:3.12.0` | install + scan + apply + verify |
| composer  | `composer require monolog/monolog:3.5.0` (local + global)     | install + scan + apply + verify |
| nuget     | `dotnet add package Newtonsoft.Json --version 13.0.3` (local + global) | install + scan + apply + verify |
| deno      | `deno install` of `minimist@1.2.2` into `node_modules/`, plus a synthetic JSR cache layout | install + scan + apply; JSR layout scan discovery |

Each suite asserts the installed-package layout is what the crawler
expects, that scan discovers the patch from the (mocked) Socket API, and
that apply overwrites the installed file with the patched bytes (a
`SOCKET-PATCH-E2E-MARKER` grep on disk). The vendor capstones are
described below.

## Running locally

Prereqs: a running Docker daemon. (Tests run `docker build` + `docker run`.)

```sh
# One-time: build the shared base layer (~3 min the first time;
# subsequent builds are layer-cached and complete in seconds).
docker build -f tests/docker/Dockerfile.base -t socket-patch-test-base:latest .

# Build the ecosystem image(s) you want to test.
docker build -f tests/docker/Dockerfile.npm -t socket-patch-test-npm:latest .

# Run a single ecosystem test:
cargo test -p socket-patch-cli --features docker-e2e --test docker_e2e_npm

# Run all 9 ecosystem tests (slow):
for eco in npm pypi gem cargo golang maven composer nuget deno; do
  docker build -f tests/docker/Dockerfile.$eco -t socket-patch-test-$eco:latest .
done
cargo test -p socket-patch-cli --features docker-e2e \
  --test docker_e2e_npm --test docker_e2e_pypi --test docker_e2e_gem \
  --test docker_e2e_cargo --test docker_e2e_golang --test docker_e2e_maven \
  --test docker_e2e_composer --test docker_e2e_nuget --test docker_e2e_deno
```

A default `cargo test` (no `--features docker-e2e`) skips this entire
suite. Developers who aren't editing the test infra never need Docker.

## Vendor capstone suites (`docker_e2e_vendor_*`)

Five suites prove the CLI_CONTRACT "Vendor command contract" rows against
the real package managers, each in its ecosystem's image:

| Suite | Image | Tooling |
|-------|-------|---------|
| `docker_e2e_vendor_composer` | `composer` | composer 2, psr/log 3.0.x |
| `docker_e2e_vendor_gem` | `gem` | bundler ~> 2.7, rack ~> 3.1 |
| `docker_e2e_vendor_maven` | `maven` | Apache Maven + JDK, commons-text 1.10.0 |
| `docker_e2e_vendor_nuget` | `nuget` | .NET SDK 8.0, Newtonsoft.Json 13.0.3 |
| `docker_e2e_vendor_pypi_pm` | `pypi` | poetry, pdm, pipenv on six 1.16.0 |

CI's `e2e-docker` job runs the composer, nuget and pypi_pm capstones;
`coverage-docker` runs all five. Unlike the scan→apply suites they are MULTI-STAGE: a host
tempdir is bind-mounted at `/workspace` and shared across three `docker run`s
(networked fixture install + offline `socket-patch vendor`; then a
fresh-checkout install under `--network none` with cold caches; then
idempotent re-vendor / `--revert` / re-vendor). Shared helpers live in
`tests/docker_vendor_common/mod.rs`. They reuse the same images and run the
same way:

```sh
docker build -f tests/docker/Dockerfile.base -t socket-patch-test-base:latest .
docker build -f tests/docker/Dockerfile.composer -t socket-patch-test-composer:latest .
docker build -f tests/docker/Dockerfile.gem -t socket-patch-test-gem:latest .
cargo test -p socket-patch-cli --features docker-e2e \
  --test docker_e2e_vendor_composer --test docker_e2e_vendor_gem
```

Because the vendor capstones exercise the binary BAKED into the base image,
rebuild `Dockerfile.base` after changing vendor code or the runs test a
stale binary. Note `Dockerfile.gem` is built on the official ruby image with
bundler pinned `~> 2.7` (the series the gem vendor lock grammar was
spike-validated against; bundler >= 2.7 needs ruby >= 3.2, newer than
Debian 12's apt ruby). The gem suite covers both the default no-CHECKSUMS
lock and a `lockfile_checksums` twin (`bundle lock --add-checksums`).

## Bundler-version matrix images (`Dockerfile.gem-b1`, `Dockerfile.gem-b4`)

The plain `Dockerfile.gem` pins bundler `~> 2.7`. Two sibling images cover
the ends of the bundler spectrum. Only `gem-b1` feeds a gated leg (in
`crates/socket-patch-cli/tests/setup_matrix_gem.rs`); `gem-b4` is a manual
bundler-4 image with no gated leg:

- `Dockerfile.gem-b1` — ruby 3.1 + **bundler 1.17.3** (last 1.x). Drives the
  bundler `>= 2.2` plugin floor: gem `setup` must refuse to wire a 1.x
  project (bundler 1.x cannot load `plugin ... path:` directives) and
  `bundle install` must keep working after the refusal.
- `Dockerfile.gem-b4` — ruby 3.4 + **bundler ~> 4.0** (current major, bare
  `bundle --version` output, CHECKSUMS locks by default).

These images are NOT built in CI (the CI `setup-matrix` job drives
`scripts/setup-matrix.sh` against the plain `gem` image only). Build them
locally before running the gated legs:

```sh
docker build -f tests/docker/Dockerfile.base -t socket-patch-test-base:latest .
docker build -f tests/docker/Dockerfile.gem-b1 -t socket-patch-test-gem-b1:latest .
docker build -f tests/docker/Dockerfile.gem-b4 -t socket-patch-test-gem-b4:latest .
cargo test -p socket-patch-cli --features setup-e2e --test setup_matrix_gem
```

The legs soft-skip (loudly) when Docker or the image is absent. Both
Dockerfiles take a `BASE_IMAGE` build-arg so a binary under test can be baked
in without overwriting the shared `:latest` tags; the test honors a
`SOCKET_PATCH_GEM_B1_IMAGE` env var to point at such a uniquely-tagged image.
NOTE: the legs run the binary BAKED INTO the image — rebuild base + image
after changing setup code or they test a stale binary.

## Host mode (no Docker)

Set `SOCKET_PATCH_TEST_HOST=1` to run the tests against host-installed
toolchains instead of containers. Tests assume the relevant package
manager (`npm`, `pip`, `gem`, `cargo`, `go`, `mvn`, `composer`,
`dotnet`) is on `$PATH`. Useful for iterating on a single ecosystem's
test logic without paying the docker-spin-up cost on every edit.

```sh
SOCKET_PATCH_TEST_HOST=1 cargo test -p socket-patch-cli \
  --features docker-e2e --test docker_e2e_npm
```

## CI

`.github/workflows/ci.yml` runs an `e2e-docker` matrix across all 9
ecosystems on every PR. Each matrix slot:
1. Builds the base image (no GitHub Actions cache — left out on purpose
   because of zizmor's cache-poisoning audit).
2. Builds the per-ecosystem image.
3. Runs the matching `docker_e2e_<eco>` test, plus that ecosystem's vendor
   capstone where it has one in this job (composer, nuget, pypi_pm).

The separate `e2e` job is the per-PR real-toolchain host matrix. The
live-API smoke suites (`e2e_npm`, `e2e_pypi`, `e2e_gem`, `e2e_scan`) are
not in CI; run them by hand with `--ignored`.

## Adding a new ecosystem

1. Add `tests/docker/Dockerfile.<eco>` — `FROM socket-patch-test-base:latest`
   plus the toolchain install.
2. Add `tests/docker_e2e_<eco>.rs` — copy any existing test, swap the
   PURL/UUID, install command, and `--ecosystems <eco>` flag.
3. Add `<eco>` to the matrix in `.github/workflows/ci.yml`'s
   `e2e-docker` job.

## How fixtures are served

Each test starts a `wiremock::MockServer` bound to `0.0.0.0` on a random
port. The container runs with
`--add-host=host.docker.internal:host-gateway`, then the test passes
`http://host.docker.internal:<port>` as `SOCKET_API_URL`. The
wiremock returns canned responses for the 3 endpoints scan/get/apply
exercise:
- `POST /v0/orgs/<org>/patches/batch` — discovery
- `GET /v0/orgs/<org>/patches/by-package/<encoded>` — per-package
- `GET /v0/orgs/<org>/patches/view/<uuid>` — full patch with inline
  base64 `blobContent` (consumed by the apply path)

Fixtures are synthetic. Real Socket patches are not required to exist
for the tested PURLs — what's validated is that the crawler discovers
real installed packages and the CLI dispatches correctly through the
ecosystem.

## Related: the `setup`-flow matrix

A separate, **experimental** suite lives under `tests/setup_matrix/` and
reuses these same per-ecosystem images. Where `docker_e2e_*` drives
`scan → apply` explicitly, the setup-matrix instead runs `socket-patch
setup` and then a *native install* to check whether the configured
install hook applies the patch on its own — the thing `setup` is meant
to enable. It also adds the npm-family package managers (pnpm/yarn via
corepack, and vlt 1.2.0 via `npm install -g`) and the Python ones
(uv/poetry/pdm/hatch), which is why `Dockerfile.npm` and `Dockerfile.pypi`
install those tools. `Dockerfile.npm` is on Node 22 (>= 22.22, vlt 1.2.0's
engine floor) and sets `VLT_TELEMETRY=0`. The vlt cases are non-gating
extras: the gating vlt `setup` assertions run against real vlt releases in
`crates/socket-patch-cli/tests/e2e_vlt.rs`. See
`tests/setup_matrix/README.md` for details and the
`scripts/setup-matrix.sh` runner. That suite's CI job (`setup-matrix`)
is **non-blocking** (`continue-on-error: true`) and is expected to fail
for ecosystems whose hooks `setup` does not yet configure.
