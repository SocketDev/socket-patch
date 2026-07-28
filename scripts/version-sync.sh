#!/usr/bin/env bash
# Stamps the release version into every packaging artifact that carries one:
#   - Cargo.toml (workspace version + socket-patch-core exact pin)
#   - npm/socket-patch/package.json (+ optionalDependencies, package-lock.json)
#   - npm/socket-patch-*/package.json (per-platform packages)
#   - pypi/socket-patch/pyproject.toml + pypi/socket-patch-hook/pyproject.toml
#   - gem/socket-patch-bundler/socket-patch-bundler.gemspec
#   - gem/socket-patch/socket-patch.gemspec + lib/socket_patch/launcher.rb
#   - composer/socket-patch/bin/socket-patch (SP_VERSION constant)
#   - maven/socket-patch/pom.xml + src/main/java/dev/socket/socketpatch/Launcher.java
#   - nuget/socket-patch/SocketSecurity.SocketPatch.csproj + Program.cs
set -euo pipefail

VERSION="${1:?Usage: version-sync.sh <version>}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Update workspace Cargo.toml version
sed -i.bak "s/^version = \".*\"/version = \"$VERSION\"/" "$REPO_ROOT/Cargo.toml"
rm -f "$REPO_ROOT/Cargo.toml.bak"

# Update socket-patch-core workspace dependency version (needed for cargo publish).
# The version spec is exact-pinned with a leading "=" per the repo's pinning policy.
sed -i.bak "s/socket-patch-core = { path = \"crates\/socket-patch-core\", version = \".*\" }/socket-patch-core = { path = \"crates\/socket-patch-core\", version = \"=$VERSION\" }/" "$REPO_ROOT/Cargo.toml"
rm -f "$REPO_ROOT/Cargo.toml.bak"

# Update npm main package version and optionalDependencies versions
pkg_json="$REPO_ROOT/npm/socket-patch/package.json"
node -e "
  const fs = require('fs');
  const pkg = JSON.parse(fs.readFileSync('$pkg_json', 'utf8'));
  pkg.version = '$VERSION';
  if (pkg.optionalDependencies) {
    for (const dep of Object.keys(pkg.optionalDependencies)) {
      pkg.optionalDependencies[dep] = '$VERSION';
    }
  }
  fs.writeFileSync('$pkg_json', JSON.stringify(pkg, null, 2) + '\n');
"

# Refresh the npm wrapper lockfile so package-lock.json stays in sync with the
# bumped package.json (own version, optionalDependencies). Uses --package-lock-only
# so node_modules is untouched.
(
  cd "$REPO_ROOT/npm/socket-patch"
  npm install --package-lock-only --ignore-scripts >/dev/null
)

# Update all per-platform npm package versions
for platform_dir in "$REPO_ROOT"/npm/socket-patch-*/; do
  platform_pkg="$platform_dir/package.json"
  if [ -f "$platform_pkg" ]; then
    node -e "
      const fs = require('fs');
      const pkg = JSON.parse(fs.readFileSync('$platform_pkg', 'utf8'));
      pkg.version = '$VERSION';
      fs.writeFileSync('$platform_pkg', JSON.stringify(pkg, null, 2) + '\n');
    "
  fi
done

# Update PyPI package version
pyproject="$REPO_ROOT/pypi/socket-patch/pyproject.toml"
sed -i.bak "s/^version = \".*\"/version = \"$VERSION\"/" "$pyproject"
rm -f "$pyproject.bak"

# Update the PyPI hook package version. The release build (build-pypi-wheels.py)
# injects --version at wheel-build time, so this keeps the source-of-truth
# pyproject.toml in sync for local builds and avoids a stale version field.
hook_pyproject="$REPO_ROOT/pypi/socket-patch-hook/pyproject.toml"
sed -i.bak "s/^version = \".*\"/version = \"$VERSION\"/" "$hook_pyproject"
rm -f "$hook_pyproject.bak"

# Update the Ruby Bundler-plugin gem version (Phase 2 scaffolding). The in-tree
# plugin is the active mechanism today; keep the published gem's version in sync
# so a release publishes a version matching the CLI.
gemspec="$REPO_ROOT/gem/socket-patch-bundler/socket-patch-bundler.gemspec"
if [ -f "$gemspec" ]; then
  sed -i.bak "s/s\.version *= *\".*\"/s.version     = \"$VERSION\"/" "$gemspec"
  rm -f "$gemspec.bak"
fi

# Update the RubyGems CLI launcher gem (gemspec version + the VERSION constant
# the launcher uses to pick the matching GitHub release binary).
ruby_cli_gemspec="$REPO_ROOT/gem/socket-patch/socket-patch.gemspec"
if [ -f "$ruby_cli_gemspec" ]; then
  sed -i.bak "s/s\.version *= *\".*\"/s.version     = \"$VERSION\"/" "$ruby_cli_gemspec"
  rm -f "$ruby_cli_gemspec.bak"
fi
ruby_cli_launcher="$REPO_ROOT/gem/socket-patch/lib/socket_patch/launcher.rb"
if [ -f "$ruby_cli_launcher" ]; then
  sed -i.bak "s/VERSION = \".*\"/VERSION = \"$VERSION\"/" "$ruby_cli_launcher"
  rm -f "$ruby_cli_launcher.bak"
fi

# Update the Composer CLI launcher's baked-in version (the release it fetches).
# Packagist derives the package version from the git tag, so composer.json has
# no version field — only the launcher constant needs syncing.
composer_cli_bin="$REPO_ROOT/composer/socket-patch/bin/socket-patch"
if [ -f "$composer_cli_bin" ]; then
  sed -i.bak "s/const SP_VERSION = '.*';/const SP_VERSION = '$VERSION';/" "$composer_cli_bin"
  rm -f "$composer_cli_bin.bak"
fi

# Update the Maven Central launcher pom. The sed is anchored on the literal
# x-version-sync marker comment so ONLY the project's own <version> line is
# rewritten — the pom carries other <version> elements for build plugins.
maven_pom="$REPO_ROOT/maven/socket-patch/pom.xml"
if [ -f "$maven_pom" ]; then
  sed -i.bak "s|<version>.*</version><!-- x-version-sync -->|<version>$VERSION</version><!-- x-version-sync -->|" "$maven_pom"
  rm -f "$maven_pom.bak"
fi

# Update the Maven launcher's fallback VERSION constant (the launcher prefers
# the jar manifest's Implementation-Version; this constant covers running from
# exploded classes, where no manifest is available).
maven_launcher="$REPO_ROOT/maven/socket-patch/src/main/java/dev/socket/socketpatch/Launcher.java"
if [ -f "$maven_launcher" ]; then
  sed -i.bak "s/VERSION = \".*\"/VERSION = \"$VERSION\"/" "$maven_launcher"
  rm -f "$maven_launcher.bak"
fi

# Update the NuGet .NET-tool launcher package version. The csproj has exactly
# one <Version> element; the informational version derives from it, so a
# single stamp keeps package and assembly versions equal.
nuget_csproj="$REPO_ROOT/nuget/socket-patch/SocketSecurity.SocketPatch.csproj"
if [ -f "$nuget_csproj" ]; then
  sed -i.bak "s|<Version>.*</Version>|<Version>$VERSION</Version>|" "$nuget_csproj"
  rm -f "$nuget_csproj.bak"
fi

# Update the NuGet launcher's fallback version constant (the launcher prefers
# the assembly's informational version; this constant covers builds where the
# attribute is unavailable).
nuget_program="$REPO_ROOT/nuget/socket-patch/Program.cs"
if [ -f "$nuget_program" ]; then
  sed -i.bak "s/FallbackVersion = \".*\"/FallbackVersion = \"$VERSION\"/" "$nuget_program"
  rm -f "$nuget_program.bak"
fi

echo "Synced version to $VERSION"
