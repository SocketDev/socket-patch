# Docker-driven e2e tests

This directory contains the Dockerfiles and per-ecosystem fixtures used
by the `tests/docker_e2e_*.rs` integration tests. Each test installs a
real package via its native package manager inside a Linux container
and runs `socket-patch scan` (and, for npm, the full apply chain)
against a wiremock-served patch fixture.

## What's tested

| Ecosystem | Real installer command                                       | Test depth                |
|-----------|---------------------------------------------------------------|---------------------------|
| npm       | `npm install minimist@1.2.2`                                  | install + scan + apply + verify patched marker on disk |
| pypi      | `pip install pydantic-ai==0.0.36` (in venv)                  | install + scan discovery  |
| gem       | `gem install activestorage -v 5.2.0` (vendor/bundle)         | install + scan discovery  |
| composer (vendor) | `composer update` (psr/log 3.0.x)                     | `docker_e2e_vendor_composer`: vendor → fresh-checkout `composer install --network none` → revert (see below) |
| gem (vendor) | `bundle install` (rack ~> 3.1, bundler ~> 2.7)             | `docker_e2e_vendor_gem`: vendor → fresh-checkout frozen `bundle install --network none` → revert (see below) |
| cargo     | `cargo fetch` with `serde = "=1.0.200"` in Cargo.toml         | install + scan discovery  |
| golang    | `go mod download github.com/gin-gonic/gin@v1.9.1`             | install + scan discovery  |
| maven     | `mvn dependency:get -Dartifact=org.apache.commons:commons-lang3:3.12.0` | install + scan discovery  |
| composer  | `composer require monolog/monolog:3.5.0`                      | install + scan discovery  |
| nuget     | `dotnet add package Newtonsoft.Json --version 13.0.3`         | install + scan discovery  |

The "scan discovery" tests assert that:
1. The package manager's installed-package layout is what we expect.
2. socket-patch's crawler discovers that layout.
3. The crawler reports the installed PURL to the (mocked) Socket API.
4. The wiremock's batch-search response flows back into scan's
   discovery output (`packagesWithPatches >= 1`).

The npm test goes further and asserts the file on disk has been
overwritten with the patched bytes.

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

# Run all 8 ecosystem tests (slow — ~3 min total):
for eco in npm pypi gem cargo golang maven composer nuget; do
  docker build -f tests/docker/Dockerfile.$eco -t socket-patch-test-$eco:latest .
done
cargo test -p socket-patch-cli --features docker-e2e \
  --test docker_e2e_npm --test docker_e2e_pypi --test docker_e2e_gem \
  --test docker_e2e_cargo --test docker_e2e_golang --test docker_e2e_maven \
  --test docker_e2e_composer --test docker_e2e_nuget
```

A default `cargo test` (no `--features docker-e2e`) skips this entire
suite. Developers who aren't editing the test infra never need Docker.

## Vendor capstone suites (`docker_e2e_vendor_*`)

`tests/docker_e2e_vendor_composer.rs` and `tests/docker_e2e_vendor_gem.rs`
prove the CLI_CONTRACT "Vendor command contract" rows against the real
package managers. Unlike the scan→apply suites they are MULTI-STAGE: a host
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
Debian 12's apt ruby). The gem suite runs against the default no-CHECKSUMS
lock — the bundler >= 2.6 `lockfile_checksums` variant is a follow-up
(see the TODO in `docker_e2e_vendor_gem.rs`).

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

`.github/workflows/ci.yml` runs an `e2e-docker` matrix across all 8
ecosystems on every PR. Each matrix slot:
1. Builds the base image (cached via GitHub Actions cache,
   `type=gha,scope=test-base`).
2. Builds the per-ecosystem image (cached per ecosystem).
3. Runs the matching `docker_e2e_<eco>` test.

The existing `e2e` job (which hits the real Socket API) stays for
manual / scheduled real-API smoke runs.

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
corepack) and the Python ones (uv/poetry/pdm/hatch), which is why
`Dockerfile.npm` and `Dockerfile.pypi` install those tools. See
`tests/setup_matrix/README.md` for details and the
`scripts/setup-matrix.sh` runner. That suite's CI job (`setup-matrix`)
is **non-blocking** (`continue-on-error: true`) and is expected to fail
for ecosystems whose hooks `setup` does not yet configure.
