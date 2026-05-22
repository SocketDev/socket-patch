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
