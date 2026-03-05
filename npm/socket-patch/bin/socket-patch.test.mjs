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

// Parse keys and values from the object literal
const entries = [...match[1].matchAll(/"([^"]+)":\s*"([^"]+)"/g)].map(
  ([, key, value]) => [key, value]
);
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

  it("package names follow @socketsecurity/socket-patch-<platform>-<arch> convention", () => {
    for (const [key, pkg] of Object.entries(PLATFORMS)) {
      const [platform, arch] = key.split(" ");
      const expected = `@socketsecurity/socket-patch-${platform}-${arch}`;
      assert.equal(pkg, expected, `package name mismatch for ${key}`);
    }
  });
});
