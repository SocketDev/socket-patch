//! Helpers shared across the CLI test suites: the binary under test and
//! the Git-blob hash oracle (`oracle`), `run` / `assert_run_ok`, and the
//! synthetic manifest writers and package-manager runners the e2e suites
//! need. Test files use these instead of private copies;
//! `cli/shared_helper_copies.rs` enforces that for `binary` and
//! `git_sha256` (#824).
//!
//! Each test file pulls this in with `#[path = "common/mod.rs"] mod common;`.
//!
//! `#![allow(dead_code)]` because each test file uses a different
//! subset of these helpers; the unused ones would otherwise produce
//! warnings under `-D warnings`.

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

/// Cache isolation for the package managers these helpers spawn. Files
/// that don't need the rest of this module pull it in on its own with
/// `#[path = "common/cache_env.rs"] mod cache_env;`.
pub mod cache_env;

/// JVM build-tool env scrub + stand-in home for the CLI children (shared
/// with `prebuilt_common`).
pub mod jvm_env;

/// The hermetic `SOCKET_*` environment every test child is spawned with.
/// Files that don't need the rest of this module pull it in on its own with
/// `#[path = "common/hermetic.rs"] mod hermetic;`.
pub mod hermetic;

pub use hermetic::command as hermetic_command;

/// Readers for the `--json` envelope (parse, `events[]`, error and warning
/// codes).
pub mod envelope;

// Not every includer reads envelopes.
#[allow(unused_imports)]
pub use envelope::{envelope_error_code, envelope_error_message, json_string, parse_json_envelope};

/// The binary under test and the Git-blob hash oracle. Shared modules
/// whose includers don't all declare `mod common` pull it in on its own
/// with `#[path = "../common/oracle.rs"] mod oracle;`.
pub mod oracle;

pub use oracle::{binary, git_sha256};

/// Recursive fixture copy. Shared modules whose includers don't all
/// declare `mod common` pull it in with
/// `#[path = "../common/fs_tree.rs"] mod fs_tree;`.
pub mod fs_tree;

/// The mock public proxy the hermetic `scan` suites answer with.
pub mod scan_proxy;

// ── Binary discovery + invocation ─────────────────────────────────────

/// Quick check whether `cmd` is on PATH. Used to soft-skip
/// toolchain-dependent tests when the toolchain isn't installed
/// (CI gates the toolchain at the workflow level; this is a
/// belt-and-braces guard for local runs).
pub fn has_command(cmd: &str) -> bool {
    let mut probe = Command::new(cmd);
    probe.arg("--version");
    cache_env::isolate(&mut probe);
    probe
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Run the CLI binary with `args`, working dir `cwd`. Returns
/// `(exit_code, stdout, stderr)`. Scrubs the ambient `SOCKET_*`
/// environment (see `run_with_env`) so apply paths default to the
/// public proxy and only the flags each test passes are in effect.
pub fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    run_with_env(cwd, args, &[])
}

/// `run` + child-only env-var injection. Useful for tests that need
/// to override discovery roots (`NUGET_PACKAGES`, `GOMODCACHE`) without
/// touching the parent process's environment — keeps tests parallel-safe.
pub fn run_with_env(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    run_bin_with_env(&binary(), cwd, args, env)
}

/// The scrub-and-run core of [`run_with_env`], parameterized over the
/// binary path so the self-update suites can spawn a *copy* of the built
/// binary (staged into a tempdir) under the exact same hermetic env as
/// every other e2e test. `CARGO_BIN_EXE_socket-patch` itself must never
/// be the target of an `--update` swap.
pub fn run_bin_with_env(
    bin: &Path,
    cwd: &Path,
    args: &[&str],
    env: &[(&str, &str)],
) -> (i32, String, String) {
    let mut cmd = hermetic_command(bin);
    cmd.args(args).current_dir(cwd);
    // No ambient Gradle / JVM options and no real home: the JVM crawlers
    // would otherwise read the developer's `~/.gradle` / `~/.m2` (and any
    // `GRADLE_USER_HOME` / `GRADLE_RO_DEP_CACHE`) into every test.
    jvm_env::isolate_cli(&mut cmd);
    // Caller-supplied env lands last so explicit injections (runtime
    // gates, discovery roots) survive the scrub.
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out: Output = cmd.output().expect("failed to execute socket-patch binary");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (code, stdout, stderr)
}

/// `run` + assertion that exit code is 0. Returns `(stdout, stderr)`
/// on success; panics with a context message + both streams on
/// failure (so test logs show exactly what the binary printed).
pub fn assert_run_ok(cwd: &Path, args: &[&str], context: &str) -> (String, String) {
    let (code, stdout, stderr) = run(cwd, args);
    assert_eq!(
        code, 0,
        "{context} failed (exit {code}).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    (stdout, stderr)
}

// ── Hashing ───────────────────────────────────────────────────────────

/// Git-SHA-256 of the file at `path`. Panics if the file can't be
/// read — tests use this on paths they know exist.
pub fn git_sha256_file(path: &Path) -> String {
    let content = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    git_sha256(&content)
}

/// Raw lowercase-hex SHA-256 (no Git blob framing). Used by the
/// Cargo sidecar which embeds plain digests in
/// `.cargo-checksum.json`.
pub fn sha256_hex(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    format!("{:x}", hasher.finalize())
}

// ── Toolchain runners ─────────────────────────────────────────────────

/// Run `npm` in `cwd`, panic on non-zero exit with full output.
pub fn npm_run(cwd: &Path, args: &[&str]) {
    run_toolchain(cwd, "npm", args, &[]);
}

/// Run `pnpm` in `cwd`. Same shape as `npm_run`; `extra_env` lets
/// the caller force store-dir overrides etc.
pub fn pnpm_run(cwd: &Path, args: &[&str], extra_env: &[(&str, &str)]) {
    run_toolchain(cwd, "pnpm", args, extra_env);
}

/// Run `cargo` in `cwd`. Returns the raw Output so callers can
/// inspect stdout/stderr/exit on either pass or fail — the cargo
/// e2e test wants both passing and failing cases (negative control).
///
/// Caches are sandboxed by [`cache_env::isolate`] before `extra_env`
/// is applied, so a caller that pins its own `CARGO_HOME` still wins.
pub fn cargo_run(cwd: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("cargo");
    cmd.args(args).current_dir(cwd);
    cache_env::isolate(&mut cmd);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to run cargo")
}

/// Preloaded into every harness vlt run (`--import`, so vlt's own
/// children do not inherit it). vlt finishes work in detached, unref'd
/// children after the command returns: the global-store explode and the
/// cache unzip (`cache-unzip`, spawned on `beforeExit`), the deletion of
/// `.VLT.DELETE.*` staging dirs (`rollback-remove`) and cache
/// revalidation. The legs assert the tree vlt leaves once that work is
/// done, so where vlt would exit (`beforeExit` with nothing left to run,
/// or an explicit `process.exit`) the hook closes those children's stdin,
/// as the exit would (0.0.0-1 never ends it), and exits only after they
/// have. Children are spawned exactly as vlt asks. One still running after
/// 120 s (`SOCKET_PATCH_VLT_SETTLE_CAP_MS`) is no longer awaited, and the
/// hook says so on stderr: a leg that then sees a half-finished tree names
/// the child it stopped waiting for.
const VLT_SETTLE_JS: &str = r#"import cp from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
const spawn = cp.spawn;
const pending = new Set();
const capMs = Number(process.env.SOCKET_PATCH_VLT_SETTLE_CAP_MS) || 120000;
let spawned = 0;
let settled = -1;
cp.spawn = function (file, args, opts) {
  const child = spawn.apply(this, arguments);
  const o = Array.isArray(args) ? opts : args;
  if (!o || !o.detached || child.pid === undefined) return child;
  spawned++;
  pending.add(child);
  const cap = setTimeout(() => {
    pending.delete(child);
    process.stderr.write(`vlt-settle: stopped waiting for detached child ${child.pid} (${file} ${Array.isArray(args) ? args.join(' ') : ''}) after ${capMs} ms\n`);
  }, capMs);
  cap.unref();
  child.once('exit', () => { clearTimeout(cap); pending.delete(child); });
  return child;
};
syncBuiltinESMExports();
const drain = (done) => {
  settled = spawned;
  for (const c of pending) {
    try { if (c.stdin && !c.stdin.writableEnded) c.stdin.end(); } catch {}
  }
  const wait = () => {
    if (pending.size) setTimeout(wait, 20);
    else done();
  };
  wait();
};
process.on('beforeExit', () => {
  if (settled !== spawned || pending.size) setImmediate(() => drain(() => {}));
});
const exit = process.exit;
process.exit = function (code) {
  if (!pending.size) return exit.call(process, code);
  if (code !== undefined && code !== null) process.exitCode = code;
  drain(() => exit.call(process, process.exitCode));
};
"#;

/// [`VLT_SETTLE_JS`] as a `data:` URL for `node --import`.
fn vlt_settle_import() -> String {
    let mut url = String::from("data:text/javascript,");
    for b in VLT_SETTLE_JS.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            url.push(char::from(b));
        } else {
            url.push_str(&format!("%{b:02X}"));
        }
    }
    url
}

/// Run the vlt at `vlt_js` (`node --no-warnings <vlt.js> <args>`) in
/// `cwd`: ambient vlt/npm/socket config scrubbed, caches sandboxed,
/// telemetry off and the `C` locale (vlt's edge order follows it), then
/// `extra_env`. Spawning `node` directly keeps Windows off the `vlt.cmd`
/// shim `Command::new` cannot see. The run returns once vlt's background
/// children have exited too ([`VLT_SETTLE_JS`]).
pub fn vlt_run(cwd: &Path, vlt_js: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("node");
    cmd.arg("--no-warnings")
        .arg("--import")
        .arg(vlt_settle_import())
        .arg(vlt_js)
        .args(args)
        .current_dir(cwd);
    cache_env::scrub_ambient_vlt_env(&mut cmd);
    cache_env::isolate(&mut cmd);
    cmd.env("VLT_TELEMETRY", "0")
        .env("NO_COLOR", "1")
        .env("LANG", "C")
        .env("LC_ALL", "C");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to run node vlt.js")
}

fn run_toolchain(cwd: &Path, exe: &str, args: &[&str], extra_env: &[(&str, &str)]) {
    let mut cmd = hermetic::tool_command(exe);
    cmd.args(args).current_dir(cwd);
    // Sandbox the caches first so `extra_env` can still override any
    // individual one (`Command` env ops are last-write-wins per name).
    cache_env::isolate(&mut cmd);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("failed to run {exe}: {e}"));
    assert!(
        out.status.success(),
        "{exe} {args:?} failed (exit {:?}).\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

// ── Project scaffolding ───────────────────────────────────────────────

/// Write a minimal package.json. Avoids `npm init -y` which rejects
/// temp dir names that start with `.` or contain invalid chars.
pub fn write_package_json(cwd: &Path) {
    std::fs::write(
        cwd.join("package.json"),
        r#"{"name":"e2e-test","version":"0.0.0","private":true}"#,
    )
    .expect("write package.json");
}

// ── Synthetic manifest + blob construction ────────────────────────────

/// Describe a single patched-file row in a synthetic manifest.
pub struct PatchEntry<'a> {
    /// File path as recorded by the manifest (may include the
    /// `package/` prefix used by the API; apply strips it before
    /// resolving against pkg_path).
    pub file_name: &'a str,
    pub before_hash: &'a str,
    pub after_hash: &'a str,
}

/// Write a minimal `.socket/manifest.json` at `socket_dir/manifest.json`
/// describing one patch for `purl` with the given `uuid` and `files`.
///
/// Returns the path to the manifest file.
///
/// Does NOT write the `after_hash` blobs — that's `write_blob`'s
/// job, and the test gets to decide which blobs to omit (e.g. to
/// force an offline-apply failure).
pub fn write_minimal_manifest(
    socket_dir: &Path,
    purl: &str,
    uuid: &str,
    files: &[PatchEntry<'_>],
) -> PathBuf {
    std::fs::create_dir_all(socket_dir).expect("create .socket dir");
    let mut files_map = serde_json::Map::new();
    for f in files {
        files_map.insert(
            f.file_name.to_string(),
            serde_json::json!({
                "beforeHash": f.before_hash,
                "afterHash": f.after_hash,
            }),
        );
    }
    let manifest = serde_json::json!({
        "patches": {
            purl: {
                "uuid": uuid,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": files_map,
                "vulnerabilities": {},
                "description": "synthetic test patch",
                "license": "MIT",
                "tier": "free",
            }
        }
    });
    let path = socket_dir.join("manifest.json");
    std::fs::write(&path, serde_json::to_string_pretty(&manifest).unwrap())
        .expect("write manifest.json");
    path
}

/// Write a hosted redirect ledger (`.socket/vendor/redirect-state.json`)
/// under `root` with the given PURL → record entries — the records-only
/// shape `scan --mode hosted` persists (tests that need recorded `edits`
/// add them to the returned-state shape themselves before writing, or
/// keep their own writer). Serializes through the real `RedirectState`
/// type so the fixture can never drift from the on-disk schema.
pub fn write_redirect_ledger(
    root: &Path,
    records: &[(&str, socket_patch_core::manifest::schema::PatchRecord)],
) {
    let mut state = socket_patch_core::patch::redirect::RedirectState::new();
    for (purl, record) in records {
        state.records.insert((*purl).to_string(), record.clone());
    }
    let vendor_dir = root.join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).expect("create .socket/vendor dir");
    std::fs::write(
        vendor_dir.join("redirect-state.json"),
        serde_json::to_string_pretty(&state).expect("serialize redirect ledger"),
    )
    .expect("write redirect-state.json");
}

/// Drop `content` at `<socket_dir>/blobs/<hash>`. Used to stage the
/// `after_hash` blob a synthetic manifest references so apply can
/// run fully offline.
pub fn write_blob(socket_dir: &Path, hash: &str, content: &[u8]) {
    let blobs = socket_dir.join("blobs");
    std::fs::create_dir_all(&blobs).expect("create .socket/blobs");
    std::fs::write(blobs.join(hash), content).expect("write blob");
}

/// Map a slice of `(env-var-name, env-var-value)` tuples into a
/// HashMap for callers that want a stable container.
pub fn env_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}
