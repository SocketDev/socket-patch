//! Helpers shared across the e2e-safety test suites.
//!
//! The original e2e files (`e2e_npm.rs`, `e2e_pypi.rs`, `e2e_gem.rs`)
//! each carry their own copy of the same `binary` / `run` /
//! `assert_run_ok` / `git_sha256` helpers. Rather than refactor those
//! files in this PR, this module is an additive landing place for the
//! same surface plus the new helpers the safety suites need
//! (synthetic manifest writers, pnpm runners, cargo runners). Existing
//! suites can migrate in a follow-up.
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

// ── Binary discovery + invocation ─────────────────────────────────────

/// Absolute path to the built `socket-patch` binary that cargo
/// provides via the `CARGO_BIN_EXE_*` env var. Available because
/// these tests live in the same crate that produces the binary.
pub fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Quick check whether `cmd` is on PATH. Used to soft-skip
/// toolchain-dependent tests when the toolchain isn't installed
/// (CI gates the toolchain at the workflow level; this is a
/// belt-and-braces guard for local runs).
pub fn has_command(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
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
/// to flip the per-ecosystem runtime gates (`SOCKET_EXPERIMENTAL_NUGET`)
/// or override discovery roots (`NUGET_PACKAGES`, `GOMODCACHE`) without
/// touching the parent process's environment — keeps tests parallel-safe.
pub fn run_with_env(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    // The binary binds a wide `SOCKET_*` env surface (SOCKET_CWD,
    // SOCKET_DRY_RUN, SOCKET_STRICT, SOCKET_GLOBAL, SOCKET_MANIFEST_PATH,
    // ...). An ambient value silently changes what these tests exercise —
    // SOCKET_DRY_RUN=true turns every real apply into a no-op,
    // SOCKET_GLOBAL_PREFIX flips commands into global mode (aiming
    // mutations at the host's *real* global caches), and the output-mode
    // trio (SOCKET_JSON / SOCKET_SILENT / SOCKET_VERBOSE) silently flips
    // which printer a test's assertions run against. The highest-risk
    // vars are seeded with hostile values and then scrubbed — `env_remove`
    // clears the seed too, so the child never sees it, but if a scrub line
    // is ever dropped the seed (rather than a developer's ambient shell,
    // which this suite can't rely on) turns the tests red immediately.
    cmd.env("SOCKET_GLOBAL", "true")
        .env("SOCKET_GLOBAL_PREFIX", "/nonexistent")
        .env("SOCKET_DRY_RUN", "true")
        .env("SOCKET_MANIFEST_PATH", "/nonexistent/manifest.json")
        .env("SOCKET_JSON", "true")
        .env("SOCKET_SILENT", "true")
        .env("SOCKET_VERBOSE", "true")
        .env_remove("SOCKET_GLOBAL")
        .env_remove("SOCKET_GLOBAL_PREFIX")
        .env_remove("SOCKET_DRY_RUN")
        .env_remove("SOCKET_MANIFEST_PATH")
        .env_remove("SOCKET_JSON")
        .env_remove("SOCKET_SILENT")
        .env_remove("SOCKET_VERBOSE")
        .env_remove("SOCKET_API_TOKEN");
    // Prefix-scrub whatever else the ambient shell carries; removing
    // SOCKET_API_TOKEN also forces the public proxy (free-tier).
    // Telemetry opt-outs are deliberately kept so an opted-out dev
    // stays opted out.
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("SOCKET_") && !name.contains("TELEMETRY") && name != "SOCKET_NO_CONFIG"
        {
            cmd.env_remove(&key);
        }
    }
    // Belt-and-braces on top of the `.cargo/config.toml` `[env]` default:
    // a developer's real `socket login` (the socket-cli config.json token
    // fallback) must never authenticate a test child — it would flip every
    // "no token → public proxy" assertion onto the authed path.
    cmd.env("SOCKET_NO_CONFIG", "1");
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

/// Compute Git-flavored SHA-256: `SHA256("blob <len>\0" ++ content)`.
/// This is the hash socket-patch records in manifests under
/// `before_hash` / `after_hash`.
pub fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

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
pub fn cargo_run(cwd: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("cargo");
    cmd.args(args).current_dir(cwd);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to run cargo")
}

fn run_toolchain(cwd: &Path, exe: &str, args: &[&str], extra_env: &[(&str, &str)]) {
    let mut cmd = Command::new(exe);
    cmd.args(args).current_dir(cwd);
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

/// Drop `content` at `<socket_dir>/blobs/<hash>`. Used to stage the
/// `after_hash` blob a synthetic manifest references so apply can
/// run fully offline.
pub fn write_blob(socket_dir: &Path, hash: &str, content: &[u8]) {
    let blobs = socket_dir.join("blobs");
    std::fs::create_dir_all(&blobs).expect("create .socket/blobs");
    std::fs::write(blobs.join(hash), content).expect("write blob");
}

/// Parse `--json` apply output, returning the top-level JSON object
/// or panicking with the raw text on parse failure. Most safety tests
/// want to assert on specific fields (`errorCode`, `status`, etc.).
pub fn parse_json_envelope(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("failed to parse JSON envelope: {e}\nstdout:\n{stdout}"))
}

/// Extract a stringified field from a parsed JSON envelope, or None
/// if the field is missing / not a string. Convenience for the
/// `status` checks the safety tests do repeatedly.
pub fn json_string<'a>(env: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    env.get(key).and_then(|v| v.as_str())
}

/// Extract `env.error.code` from a parsed envelope. The v3.0
/// envelope shape nests the error under a top-level `error` object
/// (`{"error": {"code": "lock_held", "message": "..."}}`), not at
/// the top level. This helper centralises that lookup so individual
/// tests can stay terse.
pub fn envelope_error_code(env: &serde_json::Value) -> Option<&str> {
    env.get("error")?.get("code")?.as_str()
}

/// Extract `env.error.message` from a parsed envelope. Companion to
/// [`envelope_error_code`].
pub fn envelope_error_message(env: &serde_json::Value) -> Option<&str> {
    env.get("error")?.get("message")?.as_str()
}

/// Map a slice of `(env-var-name, env-var-value)` tuples into a
/// HashMap for callers that want a stable container.
pub fn env_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

// ── Self-tests for the shared oracle ──────────────────────────────────
//
// This module is the trust anchor for every safety suite: consuming
// tests call `git_sha256` BOTH to populate `after_hash` in their
// synthetic manifests AND to verify the bytes apply leaves on disk.
// That makes `git_sha256` a single point of failure — if it ever
// drifted from the canonical Git-blob hash (drop the `\0`, drop the
// length header, uppercase the hex, …), both sides of every consumer's
// round-trip would drift together and the suites would stay green while
// guarding nothing.
//
// These self-tests pin the oracle so it can never be silently weakened:
//   * golden constants derived independently (Python `hashlib`), NOT by
//     re-running the helper against itself, and
//   * an equality check against the *production* hash
//     (`compute_git_sha256_from_bytes`) that apply actually verifies
//     against — so the harness and production can never disagree
//     unnoticed.
//
// Integration-test crates do NOT have `cfg(test)` set (only a crate's own
// unit tests do), so this module must NOT be gated behind `#[cfg(test)]` —
// doing so silently excludes it from every consuming binary and the
// self-tests never run. Left ungated, its `#[test]` fns are collected once
// in every test binary that pulls in `common`.
mod oracle_selftests {
    use super::*;
    use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;

    // Independently computed: sha256(b"blob <len>\0" + content).
    const GIT_BLOB_EMPTY: &str = "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813";
    const GIT_BLOB_HELLO: &str = "8aec4e4876f854f688d0ebfc8f37598f38e5fd6903cccc850ca36591175aeb60";
    // Independently computed: bare sha256(content), no Git framing.
    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const SHA256_HELLO: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    #[test]
    fn git_sha256_matches_independent_golden() {
        assert_eq!(
            git_sha256(b""),
            GIT_BLOB_EMPTY,
            "git_sha256 oracle drifted from the canonical Git-blob hash of empty content"
        );
        assert_eq!(
            git_sha256(b"hello"),
            GIT_BLOB_HELLO,
            "git_sha256 oracle drifted from the canonical Git-blob hash of b\"hello\""
        );
    }

    #[test]
    fn git_sha256_agrees_with_production_hash() {
        // The harness oracle MUST equal the hash apply actually verifies
        // against; otherwise the circular round-trip in every consumer
        // can agree with a broken implementation. Cover empty, ASCII,
        // multi-byte (so the length header is exercised in bytes not
        // chars), and raw binary.
        for content in [
            &b""[..],
            b"hello",
            b"socket-patch test\n",
            "é multibyte".as_bytes(),
            &[0u8, 1, 2, 255, 254, 0, 42],
        ] {
            assert_eq!(
                git_sha256(content),
                compute_git_sha256_from_bytes(content),
                "harness git_sha256 disagrees with production compute_git_sha256_from_bytes \
                 for {content:?}"
            );
        }
    }

    #[test]
    fn git_framing_is_actually_applied() {
        // Guard against the framing being silently stripped: the Git
        // blob hash must differ from a bare sha256, must be lowercase
        // hex, and must depend on content length (the `<len>` header),
        // not just the bytes.
        assert_ne!(
            git_sha256(b"hello"),
            sha256_hex(b"hello"),
            "git_sha256 must include the `blob <len>\\0` framing, not bare sha256"
        );

        // Reconstruct the framing independently (manual byte concatenation
        // fed through the un-framed `sha256_hex`) and pin git_sha256 to it.
        // This proves the EXACT framing — `blob ` + decimal length + NUL +
        // content — without re-deriving it from `git_sha256` itself.
        //
        // The previous check here (`git_sha256(b"ab") != git_sha256(b"a\0b")`)
        // was confounded: those inputs differ in *content* as well as length,
        // so it passed even for an impl that dropped the length header
        // entirely. We instead compare against framing that omits the length,
        // which differs in nothing BUT the length digits.
        let content = b"socket-patch length-header probe";
        let mut framed_with_len = Vec::new();
        framed_with_len.extend_from_slice(format!("blob {}\0", content.len()).as_bytes());
        framed_with_len.extend_from_slice(content);
        assert_eq!(
            git_sha256(content),
            sha256_hex(&framed_with_len),
            "git_sha256 must equal the bare sha256 of `blob <len>\\0` ++ content"
        );
        let mut framed_no_len = Vec::new();
        framed_no_len.extend_from_slice(b"blob \0");
        framed_no_len.extend_from_slice(content);
        assert_ne!(
            git_sha256(content),
            sha256_hex(&framed_no_len),
            "git_sha256 must hash the content LENGTH in the header, not a fixed `blob \\0`"
        );
        // Belt-and-braces: changing only the length (same trailing bytes) must
        // change the hash. `b"a"` and `b"aa"` share the same first byte but
        // frame at lengths 1 and 2.
        assert_ne!(
            git_sha256(b"a"),
            git_sha256(b"aa"),
            "git_sha256 of distinct-length inputs must differ"
        );

        let h = git_sha256(b"hello");
        assert_eq!(h.len(), 64, "hash must be 32 bytes of hex");
        assert!(
            h.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "hash must be lowercase hex, got {h}"
        );
    }

    #[test]
    fn sha256_hex_matches_independent_golden() {
        assert_eq!(sha256_hex(b""), SHA256_EMPTY);
        assert_eq!(sha256_hex(b"hello"), SHA256_HELLO);
        // Must be the un-framed digest, distinct from the Git-blob form.
        assert_ne!(sha256_hex(b"hello"), git_sha256(b"hello"));
    }

    #[test]
    fn git_sha256_file_hashes_real_bytes() {
        // `git_sha256_file` must hash exactly what is on disk — read it
        // back and confirm it equals hashing the same bytes in memory,
        // and that distinct contents produce distinct hashes (i.e. it
        // isn't returning a constant or hashing the path).
        let dir = std::env::temp_dir();
        let unique = format!("socket-patch-oracle-{}", std::process::id());
        let p1 = dir.join(format!("{unique}-a.bin"));
        let p2 = dir.join(format!("{unique}-b.bin"));
        let content_a = b"alpha-content\n";
        let content_b = b"beta-content\n";
        std::fs::write(&p1, content_a).expect("write temp a");
        std::fs::write(&p2, content_b).expect("write temp b");

        assert_eq!(git_sha256_file(&p1), git_sha256(content_a));
        assert_eq!(git_sha256_file(&p2), git_sha256(content_b));
        assert_ne!(
            git_sha256_file(&p1),
            git_sha256_file(&p2),
            "git_sha256_file must reflect file contents"
        );

        let _ = std::fs::remove_file(&p1);
        let _ = std::fs::remove_file(&p2);
    }

    // Unique temp dir per (pid, callsite) so the fixture-builder self-tests
    // never collide with each other or across parallel test binaries.
    fn scratch_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "socket-patch-oracle-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn write_minimal_manifest_emits_apply_compatible_shape() {
        // `write_minimal_manifest` is the fixture builder behind every safety
        // suite — if its emitted schema silently drifted (snake_case keys,
        // wrong nesting, missing uuid/files), apply would stop matching and
        // the suites would pass while exercising nothing. Pin the exact shape
        // apply consumes: `patches.<purl>.{uuid,files.<file>.{beforeHash,
        // afterHash}}`, all camelCase.
        let root = scratch_dir("manifest");
        let socket_dir = root.join(".socket");
        let purl = "pkg:npm/dummy@1.0.0";
        let uuid = "11111111-1111-4111-8111-111111111111";
        let path = write_minimal_manifest(
            &socket_dir,
            purl,
            uuid,
            &[PatchEntry {
                file_name: "package/index.js",
                before_hash: "beforehash000",
                after_hash: "afterhash111",
            }],
        );

        assert_eq!(
            path,
            socket_dir.join("manifest.json"),
            "manifest must land at <socket_dir>/manifest.json"
        );
        let raw = std::fs::read_to_string(&path).expect("manifest written");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("manifest must be valid JSON");

        let patch = v
            .get("patches")
            .and_then(|p| p.get(purl))
            .unwrap_or_else(|| panic!("manifest must key the patch by purl\n{raw}"));
        assert_eq!(
            patch.get("uuid").and_then(|x| x.as_str()),
            Some(uuid),
            "patch must carry the supplied uuid"
        );
        let file = patch
            .get("files")
            .and_then(|f| f.get("package/index.js"))
            .unwrap_or_else(|| panic!("files must be keyed by file_name\n{raw}"));
        assert_eq!(
            file.get("beforeHash").and_then(|x| x.as_str()),
            Some("beforehash000"),
            "file entry must use camelCase `beforeHash` (the key apply reads)"
        );
        assert_eq!(
            file.get("afterHash").and_then(|x| x.as_str()),
            Some("afterhash111"),
            "file entry must use camelCase `afterHash` (the key apply reads)"
        );
        // The builder documents that it does NOT stage the after blob — that
        // is `write_blob`'s job, and several tests rely on the blob being
        // absent to force an offline-apply failure.
        assert!(
            !socket_dir.join("blobs").join("afterhash111").exists(),
            "write_minimal_manifest must not stage after_hash blobs"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn write_blob_stages_exact_bytes_at_hash_path() {
        // The companion fixture builder: apply resolves `after_hash` blobs at
        // `<socket_dir>/blobs/<hash>` and verifies their bytes. If write_blob
        // wrote the wrong path or mangled the bytes, "offline apply succeeds"
        // tests would silently fall back to a network path or fail to match.
        let root = scratch_dir("blob");
        let socket_dir = root.join(".socket");
        let hash = "deadbeefcafef00d";
        let payload = &[0u8, 1, 2, 255, b'p', b'a', b't', b'c', b'h', 0, 42];
        write_blob(&socket_dir, hash, payload);

        let blob_path = socket_dir.join("blobs").join(hash);
        assert!(
            blob_path.is_file(),
            "blob must be written at <socket_dir>/blobs/<hash>: {}",
            blob_path.display()
        );
        assert_eq!(
            std::fs::read(&blob_path).expect("blob readable"),
            payload,
            "write_blob must stage the exact bytes, byte-for-byte"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn envelope_helpers_read_the_v3_shapes() {
        // The envelope accessors are how every safety suite reads apply's
        // `--json` output. Pin them to the real v3 shapes: `error.code` /
        // `error.message` nested under a top-level `error` object, top-level
        // string fields via `json_string`, and graceful `None` (never a
        // panic or a wrong-key hit) on absent / non-string / non-object
        // fields — so a consumer's negative assertion can't pass vacuously.
        let env = parse_json_envelope(
            r#"{"status":"error","command":"apply","count":3,
                "error":{"code":"lock_held","message":"another run holds the lock"}}"#,
        );
        assert_eq!(json_string(&env, "status"), Some("error"));
        assert_eq!(json_string(&env, "command"), Some("apply"));
        // Non-string and absent top-level fields must yield None, not a coerced
        // value — otherwise `assert_eq!(json_string(..), Some(..))` could be
        // dodged or a missing field read as empty.
        assert_eq!(
            json_string(&env, "count"),
            None,
            "numeric field is not a string"
        );
        assert_eq!(json_string(&env, "missing"), None);
        assert_eq!(envelope_error_code(&env), Some("lock_held"));
        assert_eq!(
            envelope_error_message(&env),
            Some("another run holds the lock")
        );

        // No `error` object → both error accessors return None (not a panic,
        // not a stale hit), so success-path consumers asserting `None` stay
        // honest.
        let ok = parse_json_envelope(r#"{"status":"success","command":"list"}"#);
        assert_eq!(envelope_error_code(&ok), None);
        assert_eq!(envelope_error_message(&ok), None);

        // The accessors must look under the nested `error` object, NOT at a
        // flat top-level `code`/`message`. A flat-keyed envelope must read as
        // absent so the helper can't accidentally satisfy a nested-shape
        // assertion against the wrong layout.
        let flat = parse_json_envelope(r#"{"code":"nope","message":"flat"}"#);
        assert_eq!(
            envelope_error_code(&flat),
            None,
            "error.code must be nested under `error`, not read from top-level `code`"
        );
        assert_eq!(envelope_error_message(&flat), None);
    }
}
