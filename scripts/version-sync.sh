#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?Usage: version-sync.sh <version>}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Update workspace Cargo.toml version
sed -i.bak "s/^version = \".*\"/version = \"$VERSION\"/" "$REPO_ROOT/Cargo.toml"
rm -f "$REPO_ROOT/Cargo.toml.bak"

PLATFORM_PKGS=(
  "socket-patch-darwin-arm64"
  "socket-patch-darwin-x64"
  "socket-patch-linux-x64"
  "socket-patch-linux-arm64"
  "socket-patch-win32-x64"
)

# Update each platform package version
for pkg in "${PLATFORM_PKGS[@]}"; do
  pkg_json="$REPO_ROOT/npm/$pkg/package.json"
  tmp=$(mktemp)
  node -e "
    const fs = require('fs');
    const pkg = JSON.parse(fs.readFileSync('$pkg_json', 'utf8'));
    pkg.version = '$VERSION';
    fs.writeFileSync('$pkg_json', JSON.stringify(pkg, null, 2) + '\n');
  "
done

# Update root wrapper package version + optionalDependencies versions
root_json="$REPO_ROOT/npm/socket-patch/package.json"
node -e "
  const fs = require('fs');
  const pkg = JSON.parse(fs.readFileSync('$root_json', 'utf8'));
  pkg.version = '$VERSION';
  if (pkg.optionalDependencies) {
    for (const dep of Object.keys(pkg.optionalDependencies)) {
      pkg.optionalDependencies[dep] = '$VERSION';
    }
  }
  fs.writeFileSync('$root_json', JSON.stringify(pkg, null, 2) + '\n');
"

echo "Synced version to $VERSION"
