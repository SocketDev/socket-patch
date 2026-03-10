import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(__dirname, "socket-patch"), "utf8");

// Extract the PLATFORMS object from the source
const match = src.match(/const PLATFORMS = \{([\s\S]*?)\};/);
assert.ok(match, "PLATFORMS object not found in socket-patch");

// Parse keys and array values from the object literal
// Matches: "key": ["value1", "value2"] or "key": ["value1"]
const entries = [];
const entryRegex = /"([^"]+)":\s*\[([\s\S]*?)\]/g;
let m;
while ((m = entryRegex.exec(match[1])) !== null) {
  const key = m[1];
  const values = [...m[2].matchAll(/"([^"]+)"/g)].map(([, v]) => v);
  entries.push([key, values]);
}
const PLATFORMS = Object.fromEntries(entries);

const EXPECTED_KEYS = [
  "darwin arm64",
  "darwin x64",
  "linux x64",
  "linux arm64",
  "linux arm",
  "linux ia32",
  "win32 x64",
  "win32 ia32",
  "win32 arm64",
  "android arm64",
];

describe("npm platform dispatch", () => {
  it("has all expected platform keys", () => {
    for (const key of EXPECTED_KEYS) {
      assert.ok(PLATFORMS[key], `missing platform key: ${key}`);
    }
  });

  it("has no unexpected platform keys", () => {
    for (const key of Object.keys(PLATFORMS)) {
      assert.ok(EXPECTED_KEYS.includes(key), `unexpected platform key: ${key}`);
    }
  });

  it("non-Linux package names follow @socketsecurity/socket-patch-<platform>-<arch> convention", () => {
    for (const [key, candidates] of Object.entries(PLATFORMS)) {
      if (key.startsWith("linux ")) continue;
      const [platform, arch] = key.split(" ");
      assert.equal(candidates.length, 1, `expected 1 candidate for ${key}`);
      const expected = `@socketsecurity/socket-patch-${platform}-${arch}`;
      assert.equal(candidates[0], expected, `package name mismatch for ${key}`);
    }
  });

  it("Linux entries have both glibc and musl candidates", () => {
    for (const [key, candidates] of Object.entries(PLATFORMS)) {
      if (!key.startsWith("linux ")) continue;
      const [, arch] = key.split(" ");
      assert.equal(candidates.length, 2, `expected 2 candidates for ${key}`);
      const gnuPkg = `@socketsecurity/socket-patch-linux-${arch}-gnu`;
      const muslPkg = `@socketsecurity/socket-patch-linux-${arch}-musl`;
      assert.equal(candidates[0], gnuPkg, `first candidate for ${key} should be gnu`);
      assert.equal(candidates[1], muslPkg, `second candidate for ${key} should be musl`);
    }
  });
});
