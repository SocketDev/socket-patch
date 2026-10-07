#!/usr/bin/env bash
# Warm an sbt cache for the real-sbt suites (SOCKET_PATCH_SBT_E2E_SEED) on a
# host runner, then print the variables a CI step appends to $GITHUB_ENV.
#
#   scripts/sbt-warm-seed.sh <sbt.version> <seed dir>
#
# Boots <sbt.version> once through the `sbt` launcher on PATH (`sbt.bat` on
# Windows) and resolves the same tiny Java-only build tests/docker/Dockerfile.sbt
# warms its image with, into the flat seed layout `sbt_e2e_shared::Seed` reads:
# <seed>/coursier/v1, <seed>/ivy2 and <seed>/boot. Without a seed every test
# boots sbt from the network on its own (~1 min each). The suites hard-link
# the seed into each test's private caches, so it is never written by a test.
#
# Prints (stdout):
#   SOCKET_PATCH_SBT_E2E_SEED=<seed>
#   SOCKET_PATCH_SBT_E2E_SBT=<absolute launcher path>
set -euo pipefail

if [ $# -ne 2 ]; then
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
fi
VERSION="$1"
SEED="$2"

windows=""
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) windows=1 ;; esac

native() {
  # A path the JVM and the Rust test binaries accept.
  if [ -n "$windows" ]; then cygpath -m "$1"; else printf '%s\n' "$1"; fi
}

if [ -n "$windows" ]; then
  launcher="$(command -v sbt.bat || true)"
else
  launcher="$(command -v sbt || true)"
fi
[ -n "$launcher" ] || { echo "sbt-warm-seed: no sbt launcher on PATH" >&2; exit 1; }

mkdir -p "$SEED/coursier/v1" "$SEED/ivy2" "$SEED/boot" "$SEED/global"
seed="$(cd "$SEED" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/project"
echo "sbt.version=$VERSION" > "$work/project/build.properties"
printf '%s\n' 'autoScalaLibrary := false' 'crossPaths := false' \
  'libraryDependencies += "org.apache.commons" % "commons-lang3" % "3.11"' > "$work/build.sbt"

extra=()
case "$VERSION" in 2.*) extra=(--server) ;; esac

# The same scrub the suites apply: nothing ambient steers this boot.
unset SBT_OPTS JAVA_OPTS JVM_OPTS JAVA_TOOL_OPTIONS _JAVA_OPTIONS JDK_JAVA_OPTIONS SBT_NATIVE_CLIENT
while IFS= read -r var; do unset "$var"; done < <(env | sed -n 's/^\(COURSIER_[A-Za-z0-9_]*\)=.*/\1/p')

(
  cd "$work"
  COURSIER_CACHE="$(native "$seed/coursier/v1")" "$launcher" -batch -no-colors \
    -Dsbt.server.autostart=false \
    "-Dsbt.global.base=$(native "$seed/global")" \
    "-Dsbt.boot.directory=$(native "$seed/boot")" \
    "-Dsbt.ivy.home=$(native "$seed/ivy2")" \
    ${extra[@]+"${extra[@]}"} update >&2
)
# global/ holds sbt's per-machine state (server sockets, compiled plugins);
# the suites never read it from a seed.
rm -rf "$seed/global"

echo "SOCKET_PATCH_SBT_E2E_SEED=$(native "$seed")"
echo "SOCKET_PATCH_SBT_E2E_SBT=$(native "$launcher")"
