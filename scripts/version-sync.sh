#!/usr/bin/env bash
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

echo "Synced version to $VERSION"
