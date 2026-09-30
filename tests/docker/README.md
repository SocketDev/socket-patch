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

CI's `coverage-docker` job runs all five on every push; the nightly
`e2e-docker` job runs the composer, nuget and pypi_pm capstones against
the release binary. Unlike the scan→apply suites they are MULTI-STAGE: a host
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

Fixtures are synthetic. Real Socket patches are not required to exist
for the tested PURLs — what's validated is that the crawler discovers
real installed packages and the CLI dispatches correctly through the
ecosystem.

