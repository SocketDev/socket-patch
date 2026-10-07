import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
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

// Regression tests for #974: installers that ignore `libc` (yarn classic)
// install both the -gnu and -musl packages, so the wrapper must pick the
// one that can run on this host and must never exit silently.

const wrapperPath = join(__dirname, "socket-patch");
const wrapper = createRequire(import.meta.url)(wrapperPath);

describe("npm wrapper libc selection (#974)", () => {
  it("does not run the CLI when required as a module", () => {
    assert.equal(typeof wrapper.orderCandidates, "function");
    assert.equal(typeof wrapper.detectLibc, "function");
    assert.equal(typeof wrapper.runFirstUsable, "function");
  });

  it("detects musl when the Node runtime reports no glibc", () => {
    const libc = wrapper.detectLibc({
      platform: "linux",
      getReport: () => ({ header: {} }),
      listDir: () => ["ld-musl-x86_64.so.1", "libc.musl-x86_64.so.1"],
    });
    assert.equal(libc, "musl");
  });

  it("detects glibc from the runtime report even if a musl loader exists", () => {
    const libc = wrapper.detectLibc({
      platform: "linux",
      getReport: () => ({ header: { glibcVersionRuntime: "2.36" } }),
      listDir: () => ["ld-musl-x86_64.so.1"],
    });
    assert.equal(libc, "glibc");
  });

  it("returns null off Linux", () => {
    assert.equal(
      wrapper.detectLibc({
        platform: "darwin",
        getReport: () => ({ header: {} }),
        listDir: () => [],
      }),
      null,
    );
  });

  for (const key of ["linux x64", "linux arm64", "linux arm", "linux ia32"]) {
    it(`prefers the musl package on a musl host (${key})`, () => {
      const ordered = wrapper.orderCandidates(PLATFORMS[key], "musl");
      assert.match(ordered[0], /-musl$/);
      assert.match(ordered[1], /-gnu$/);
    });

    it(`keeps gnu first on a glibc host (${key})`, () => {
      assert.deepEqual(wrapper.orderCandidates(PLATFORMS[key], "glibc"), PLATFORMS[key]);
    });
  }

  it("falls back to the next binary when the first cannot be spawned", () => {
    const calls = [];
    const enoent = Object.assign(new Error("spawnSync gnu ENOENT"), { code: "ENOENT" });
    const status = wrapper.runFirstUsable(["/gnu", "/musl"], ["--version"], {
      spawn: (bin) => {
        calls.push(bin);
        return bin === "/gnu" ? { status: null, error: enoent } : { status: 0 };
      },
      log: () => {},
    });
    assert.equal(status, 0);
    assert.deepEqual(calls, ["/gnu", "/musl"]);
  });

  it("prints why it failed instead of exiting silently", () => {
    const logs = [];
    const enoent = Object.assign(new Error("spawnSync /gnu ENOENT"), { code: "ENOENT" });
    const status = wrapper.runFirstUsable(["/gnu"], [], {
      spawn: () => ({ status: null, error: enoent }),
      log: (msg) => logs.push(msg),
    });
    assert.equal(status, 1);
    assert.equal(logs.length, 1);
    assert.match(logs[0], /\/gnu/);
    assert.match(logs[0], /ENOENT/);
  });

  it("propagates the exit status of a binary that ran", () => {
    const status = wrapper.runFirstUsable(["/gnu", "/musl"], [], {
      spawn: () => ({ status: 3 }),
      log: () => {},
    });
    assert.equal(status, 3);
  });

  // A binary killed by a signal has `status: null`; the wrapper must
  // report it the way a shell does (128 + signal number), not as 1.
  for (const [signal, code] of [["SIGINT", 130], ["SIGTERM", 143], ["SIGKILL", 137]]) {
    it(`reports a ${signal} death as exit ${code}`, () => {
      const logs = [];
      const status = wrapper.runFirstUsable(["/gnu", "/musl"], [], {
        spawn: () => ({ status: null, signal }),
        log: (msg) => logs.push(msg),
      });
      assert.equal(status, code);
      assert.deepEqual(logs, []);
    });
  }

  // End to end: a node_modules tree like yarn classic leaves on Alpine,
  // with both platform packages installed and the gnu binary unable to
  // start. The wrapper must run the musl binary instead of exiting 1
  // with no output.
  it(
    "runs the musl binary when the gnu one cannot start (yarn classic layout)",
    { skip: process.platform !== "linux" || !PLATFORMS[`linux ${process.arch}`] },
    () => {
      const root = mkdtempSync(join(tmpdir(), "sp-wrapper-"));
      try {
        const scope = join(root, "node_modules", "@socketsecurity");
        const binDir = join(scope, "socket-patch", "bin");
        mkdirSync(binDir, { recursive: true });
        writeFileSync(join(binDir, "socket-patch"), readFileSync(wrapperPath));
        for (const pkg of PLATFORMS[`linux ${process.arch}`]) {
          const dir = join(root, "node_modules", pkg);
          mkdirSync(dir, { recursive: true });
          writeFileSync(join(dir, "package.json"), JSON.stringify({ name: pkg, version: "0.0.0" }));
          const exe = join(dir, "socket-patch");
          if (pkg.endsWith("-gnu")) {
            // A binary whose ELF interpreter is missing fails exactly like
            // a glibc binary on musl: spawn reports ENOENT.
            writeFileSync(exe, "#!/nonexistent/ld-linux.so.2\n");
          } else {
            writeFileSync(exe, "#!/bin/sh\necho \"musl-binary $*\"\n");
          }
          chmodSync(exe, 0o755);
        }
        const result = spawnSync(process.execPath, [join(binDir, "socket-patch"), "--version"], {
          encoding: "utf8",
        });
        assert.equal(result.status, 0, `stderr: ${result.stderr}`);
        assert.equal(result.stdout.trim(), "musl-binary --version");
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
    },
  );
});

describe("npm package contents", () => {
  const pkgDir = join(__dirname, "..");
  const npm = spawnSync("npm", ["--version"], { encoding: "utf8" });

  it(
    "publishes the wrapper and the compiled schema, not sources or tests",
    { skip: npm.status !== 0 && "npm is not on PATH" },
    () => {
      const result = spawnSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
        cwd: pkgDir,
        encoding: "utf8",
      });
      assert.equal(result.status, 0, `stderr: ${result.stderr}`);
      const files = JSON.parse(result.stdout)[0].files.map((f) => f.path);
      assert.ok(files.includes("bin/socket-patch"), files.join(", "));
      assert.ok(files.includes("package.json"), files.join(", "));
      // The `./schema` export points at dist/; once it is built, both
      // compiled files must ship or the export resolves to nothing.
      if (existsSync(join(pkgDir, "dist", "schema", "manifest-schema.js"))) {
        assert.ok(files.includes("dist/schema/manifest-schema.js"), files.join(", "));
        assert.ok(files.includes("dist/schema/manifest-schema.d.ts"), files.join(", "));
      }
      for (const file of files) {
        assert.doesNotMatch(file, /\.test\.|^src\/|tsconfig|tsbuildinfo/, `unexpected file in the tarball: ${file}`);
        assert.ok(
          file === "package.json" || file === "README.md" || file.startsWith("bin/socket-patch") || /^dist\/schema\/manifest-schema\.(js|d\.ts)$/.test(file),
          `unexpected file in the tarball: ${file}`,
        );
      }
    },
  );
});
