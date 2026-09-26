#!/usr/bin/env bash
# Install one vlt release for the real-vlt suites and print its vlt.js path.
#
#   scripts/install-vlt.sh <version|latest> <prefix>
#
# `npm pack` (5 attempts), then the tarball's sha512 must equal the registry's
# `dist.integrity` and, when scripts/vlt-historical-integrity.json lists the
# release, that committed pin too (fail closed). The tarball is installed
# with `npm install --prefix <prefix> --ignore-scripts`, and `node vlt.js
# --version` must print the release. Finally the running Node must meet the
# release's engine floor (DESIGN §1.1): >=22 through 1.0.0-rc.9, >=22.9.0 for
# rc.10 … rc.18, >=22.22.0 from rc.22.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <version|latest> <prefix>" >&2
  exit 2
fi
requested=$1
prefix=$2
here=$(cd "$(dirname "$0")" && pwd)

version=$requested
if [ "$requested" = latest ]; then
  version=$(npm view vlt@latest version)
fi
mkdir -p "$prefix"
tarball=""
for attempt in 1 2 3 4 5; do
  if name=$(npm pack "vlt@$version" --pack-destination "$prefix" --silent); then
    tarball="$prefix/$(printf '%s\n' "$name" | tail -n 1)"
    break
  fi
  if [ "$attempt" = 5 ]; then
    echo "npm pack vlt@$version failed on all 5 attempts" >&2
    exit 1
  fi
  sleep $((attempt * 5))
done

expected=$(npm view "vlt@$version" dist.integrity)
# shellcheck disable=SC2016 # JavaScript, not shell
VLT_TARBALL=$tarball VLT_EXPECTED=$expected VLT_VERSION=$version \
  VLT_PINS="$here/vlt-historical-integrity.json" node -e '
const fs = require("fs");
const crypto = require("crypto");
const actual = "sha512-" + crypto.createHash("sha512")
  .update(fs.readFileSync(process.env.VLT_TARBALL)).digest("base64");
const expected = process.env.VLT_EXPECTED;
let pinned;
try {
  pinned = JSON.parse(fs.readFileSync(process.env.VLT_PINS, "utf8"))[process.env.VLT_VERSION];
} catch (e) {
  pinned = undefined;
}
if (actual !== expected || (pinned !== undefined && pinned !== expected)) {
  console.error(`vlt@${process.env.VLT_VERSION}: tarball ${actual}, registry ${expected}` +
    (pinned === undefined ? "" : `, pinned ${pinned}`));
  process.exit(1);
}
'

npm install --prefix "$prefix" --no-audit --no-fund --ignore-scripts --no-package-lock "$tarball" >&2
rm -f "$tarball"
js="$prefix/node_modules/vlt/vlt.js"
actual=$(node --no-warnings "$js" --version)
if [ "$actual" != "$version" ]; then
  echo "expected vlt $version at $js, got $actual" >&2
  exit 1
fi

# shellcheck disable=SC2016 # JavaScript, not shell
VLT_VERSION=$version node -e '
const v = process.env.VLT_VERSION;
const m = /^(\d+)\.(\d+)\.(\d+)(?:-(rc\.)?(\d+))?$/.exec(v);
if (!m) { console.error(`not a vlt release: ${v}`); process.exit(1); }
const rc = m[4] ? Number(m[5]) : null;
let floor = "22.22.0";
if (m[1] === "0" || (rc !== null && rc <= 9)) floor = "22.0.0";
else if (rc !== null && rc <= 18) floor = "22.9.0";
const have = process.versions.node.split(".").map(Number);
const need = floor.split(".").map(Number);
for (let i = 0; i < 3; i++) {
  if (have[i] > need[i]) break;
  if (have[i] < need[i]) {
    console.error(`vlt ${v} needs Node >= ${floor}; running ${process.versions.node}`);
    process.exit(1);
  }
}
'
printf '%s\n' "$js"
