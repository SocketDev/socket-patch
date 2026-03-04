import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(__dirname, "socket-patch"), "utf8");

// Extract the BINARIES object from the source
const match = src.match(/const BINARIES = \{([\s\S]*?)\};/);
assert.ok(match, "BINARIES object not found in socket-patch");

// Parse keys and values from the object literal
const entries = [...match[1].matchAll(/"([^"]+)":\s*"([^"]+)"/g)].map(
  ([, key, value]) => [key, value]
);
const BINARIES = Object.fromEntries(entries);

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
      assert.ok(BINARIES[key], `missing platform key: ${key}`);
    }
  });

  it("has no unexpected platform keys", () => {
    for (const key of Object.keys(BINARIES)) {
      assert.ok(EXPECTED_KEYS.includes(key), `unexpected platform key: ${key}`);
    }
  });

  it("binary names follow socket-patch-<platform>-<arch>[.exe] convention", () => {
    for (const [key, bin] of Object.entries(BINARIES)) {
      const [platform, arch] = key.split(" ");
      const expected = platform === "win32"
        ? `socket-patch-${platform}-${arch}.exe`
        : `socket-patch-${platform}-${arch}`;
      assert.equal(bin, expected, `binary name mismatch for ${key}`);
    }
  });

  it("windows entries end in .exe", () => {
    for (const [key, bin] of Object.entries(BINARIES)) {
      if (key.startsWith("win32")) {
        assert.ok(bin.endsWith(".exe"), `${key} should end in .exe`);
      }
    }
  });

  it("non-windows entries do not end in .exe", () => {
    for (const [key, bin] of Object.entries(BINARIES)) {
      if (!key.startsWith("win32")) {
        assert.ok(!bin.endsWith(".exe"), `${key} should not end in .exe`);
      }
    }
  });
});
