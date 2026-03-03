#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?Usage: version-sync.sh <version>}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Update workspace Cargo.toml version
sed -i.bak "s/^version = \".*\"/version = \"$VERSION\"/" "$REPO_ROOT/Cargo.toml"
rm -f "$REPO_ROOT/Cargo.toml.bak"

# Update npm package version
pkg_json="$REPO_ROOT/npm/socket-patch/package.json"
node -e "
  const fs = require('fs');
  const pkg = JSON.parse(fs.readFileSync('$pkg_json', 'utf8'));
  pkg.version = '$VERSION';
  fs.writeFileSync('$pkg_json', JSON.stringify(pkg, null, 2) + '\n');
"

echo "Synced version to $VERSION"
