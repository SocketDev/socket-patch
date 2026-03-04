#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?Usage: version-sync.sh <version>}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Update workspace Cargo.toml version
sed -i.bak "s/^version = \".*\"/version = \"$VERSION\"/" "$REPO_ROOT/Cargo.toml"
rm -f "$REPO_ROOT/Cargo.toml.bak"

# Update socket-patch-core workspace dependency version (needed for cargo publish)
sed -i.bak "s/socket-patch-core = { path = \"crates\/socket-patch-core\", version = \".*\" }/socket-patch-core = { path = \"crates\/socket-patch-core\", version = \"$VERSION\" }/" "$REPO_ROOT/Cargo.toml"
rm -f "$REPO_ROOT/Cargo.toml.bak"

# Update npm package version
pkg_json="$REPO_ROOT/npm/socket-patch/package.json"
node -e "
  const fs = require('fs');
  const pkg = JSON.parse(fs.readFileSync('$pkg_json', 'utf8'));
  pkg.version = '$VERSION';
  fs.writeFileSync('$pkg_json', JSON.stringify(pkg, null, 2) + '\n');
"

# Update PyPI package version
pyproject="$REPO_ROOT/pypi/socket-patch/pyproject.toml"
sed -i.bak "s/^version = \".*\"/version = \"$VERSION\"/" "$pyproject"
rm -f "$pyproject.bak"

echo "Synced version to $VERSION"
