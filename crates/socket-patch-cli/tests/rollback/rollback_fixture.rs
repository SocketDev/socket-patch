//! Shared fixtures for `rollback`'s `--json` failure paths
//! (`rollback_failure_paths.rs`) and its render suite (`rollback_render.rs`),
//! #1089.
//!
//! Binary-driven throughout: hermetic child processes via `common::run`,
//! hand-written camelCase manifests, the git-sha256 oracle and `--offline`
//! everywhere except the hosted leg. v5 hosted state is the lockfile pins
//! themselves, and their rollback restores the upstream registry entry from
//! a mock npm registry (`SOCKET_NPM_REGISTRY`, see [`NpmRegistry`]).

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::common;
use crate::common::git_sha256;
use crate::prebuilt_common;

// ───────────────────────── vendored-leg fixture ─────────────────────────

pub const V_UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
pub const V_PURL: &str = "pkg:npm/left-pad@1.3.0";
pub const ORIG_INDEX: &[u8] = b"module.exports = () => 'orig';\n";
pub const PATCHED_INDEX: &[u8] = b"module.exports = () => 'patched';\n";

// ───────────────────────── hosted-leg fixture ─────────────────────────
//
// v5 hosted mode keeps no ledger: the hosted pins are discovered from the
// lockfiles (on `--patch-server-url`'s origin for these mock-host URLs) and
// rollback restores each pin's DEFAULT UPSTREAM registry entry, re-resolved
// from the (mocked) npm registry. A pre-v5 ledger is never replayed; it is
// retired once no hosted pin remains.

pub const LP_PURL: &str = "pkg:npm/left-pad@1.2.3";
pub const LP_HOSTED_URL: &str = "http://patch.test/patch/npm/left-pad/1.2.3/66666666-6666-4666-8666-666666666666/55555555-5555-4555-8555-555555555555/left-pad-1.2.3.tgz";
pub const IO_PURL: &str = "pkg:npm/is-odd@3.0.1";
pub const IO_HOSTED_URL: &str = "http://patch.test/patch/npm/is-odd/3.0.1/66666666-6666-4666-8666-666666666666/99999999-9999-4999-8999-999999999999/is-odd-3.0.1.tgz";
pub const PATCH_SERVER: &str = "http://patch.test";
pub const UPSTREAM_INTEGRITY: &str = "sha512-UPSTREAMupstream==";

pub const VLT_UUID: &str = "88888888-8888-4888-8888-888888888888";
pub const VLT_ID: &str = "~npm~left-pad@1.3.0";
pub const VLT_PATCHED_SHA: &str = "sha512-PATCHED==";

// ───────────────────────── helpers ─────────────────────────

pub fn run(root: &Path, args: &[&str]) -> (i32, String, String) {
    if args.first() == Some(&"vendor") {
        let fixture = prebuilt_common::Server::project(root);
        let args: Vec<_> = args
            .iter()
            .copied()
            .filter(|arg| *arg != "--offline")
            .collect();
        common::run_with_env(root, &args, &[("SOCKET_VENDOR_URL", &fixture.uri)])
    } else {
        common::run(root, args)
    }
}

/// One hand-written camelCase manifest entry (single `package/index.js`
/// file row), matching the TS-compatible on-disk schema.
pub fn manifest_entry(purl: &str, uuid: &str, before_hash: &str, after_hash: &str) -> String {
    format!(
        r#""{purl}": {{
      "uuid": "{uuid}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "package/index.js": {{
          "beforeHash": "{before_hash}",
          "afterHash": "{after_hash}"
        }}
      }},
      "vulnerabilities": {{}},
      "description": "synthetic covgap test patch",
      "license": "MIT",
      "tier": "free"
    }}"#
    )
}

/// Write `.socket/manifest.json` from pre-rendered entries; returns the
/// `.socket` dir.
pub fn write_socket_manifest(root: &Path, entries: &[String]) -> PathBuf {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    let patches = entries.join(",\n    ");
    std::fs::write(
        socket.join("manifest.json"),
        format!("{{\n  \"patches\": {{\n    {patches}\n  }}\n}}"),
    )
    .expect("write manifest");
    socket
}

/// Install a fake npm package at `<root>/<nm_rel>/<name>` with the given
/// `index.js` bytes and version.
pub fn install_npm_pkg(
    root: &Path,
    nm_rel: &str,
    name: &str,
    version: &str,
    index_js: &[u8],
) -> PathBuf {
    let pkg_dir = root.join(nm_rel).join(name);
    std::fs::create_dir_all(&pkg_dir).expect("create package dir");
    std::fs::write(
        pkg_dir.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
    )
    .expect("write package.json");
    std::fs::write(pkg_dir.join("index.js"), index_js).expect("write index.js");
    pkg_dir
}

pub fn write_root_package_json(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "covgap-rollback-root", "version": "0.0.0" }"#,
    )
    .expect("write root package.json");
}

pub fn stage_blob(socket: &Path, hash: &str, content: &[u8]) {
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).expect("create blobs dir");
    std::fs::write(blobs.join(hash), content).expect("stage blob");
}

/// Stage `<uuid>.tar.gz` in both archive stores so the GC has something
/// sweepable to preview/free.
pub fn stage_archives(socket: &Path, uuid: &str) {
    for dir in ["diffs", "packages"] {
        let path = socket.join(dir).join(format!("{uuid}.tar.gz"));
        std::fs::create_dir_all(path.parent().expect("archive path has a parent"))
            .expect("create archive dir");
        std::fs::write(path, b"synthetic-archive-bytes").expect("stage archive");
    }
}

/// The default single-package patched fixture: an installed npm package
/// whose `index.js` holds the PATCHED bytes, one manifest entry, both
/// blobs staged, both archives staged.
pub struct PatchedFixture {
    pub root: tempfile::TempDir,
    pub socket: PathBuf,
    pub pkg_dir: PathBuf,
    pub purl: &'static str,
    pub before: &'static [u8],
    pub after: &'static [u8],
}

pub fn patched_fixture() -> PatchedFixture {
    let before: &[u8] = b"covgap-original-content\n";
    let after: &[u8] = b"covgap-patched-content\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(after);
    let purl = "pkg:npm/covgap-target@1.0.0";
    let uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

    let root = tempfile::tempdir().expect("tempdir");
    write_root_package_json(root.path());
    let pkg_dir = install_npm_pkg(root.path(), "node_modules", "covgap-target", "1.0.0", after);
    let socket = write_socket_manifest(
        root.path(),
        &[manifest_entry(purl, uuid, &before_hash, &after_hash)],
    );
    stage_blob(&socket, &before_hash, before);
    stage_blob(&socket, &after_hash, after);
    stage_archives(&socket, uuid);

    PatchedFixture {
        root,
        socket,
        pkg_dir,
        purl,
        before,
        after,
    }
}

/// Restore a directory's mode on drop, so a failed assertion never leaks a
/// read-only tree into TMPDIR.
#[cfg(unix)]
pub struct DirModeGuard {
    pub path: PathBuf,
    pub restore_mode: u32,
}

#[cfg(unix)]
impl DirModeGuard {
    pub fn chmod(path: &Path, mode: u32, restore_mode: u32) -> Self {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .expect("chmod fixture dir");
        Self {
            path: path.to_path_buf(),
            restore_mode,
        }
    }
    pub fn restore(&self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            &self.path,
            std::fs::Permissions::from_mode(self.restore_mode),
        );
    }
}

#[cfg(unix)]
impl Drop for DirModeGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Probe whether permission bits are enforced for this process; root (or
/// CAP_DAC_OVERRIDE containers) bypasses them, making read-only-dir tests
/// fail spuriously. Returns false (and logs a skip) when they are not.
#[cfg(unix)]
pub fn readonly_dir_enforced(dir: &Path) -> bool {
    let probe = dir.join(".covgap-write-probe");
    if std::fs::write(&probe, b"x").is_ok() {
        let _ = std::fs::remove_file(&probe);
        eprintln!("skipping: permission bits not enforced (running as root?)");
        return false;
    }
    true
}

/// Spawn the binary WITHOUT waiting (the lock-choreography tests mutate
/// the fixture while the child is blocked on the apply lock), with the
/// same hermetic `SOCKET_*` environment as `common::run` (not its JVM
/// isolation; no test here spawns a JVM fixture this way).
pub fn spawn_scrubbed(cwd: &Path, args: &[&str]) -> std::process::Child {
    let mut cmd = common::hermetic_command(&common::binary());
    cmd.args(args).current_dir(cwd);
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    cmd.spawn().expect("spawn socket-patch binary")
}

/// One self-contained npm project ready to `vendor`: root package.json, a
/// v3 package-lock with a registry-resolved `left-pad`, the installed
/// package, and a `.socket/` manifest + after-hash blob (offline source) —
/// the `in_process_rollback_vendored.rs` fixture, subprocess-driven.
pub struct VendorFixture {
    pub tmp: tempfile::TempDir,
    pub original_lock: Vec<u8>,
}

impl VendorFixture {
    pub fn root(&self) -> &Path {
        self.tmp.path()
    }
    pub fn lock_bytes(&self) -> Vec<u8> {
        std::fs::read(self.root().join("package-lock.json")).expect("read package-lock.json")
    }
    pub fn state_path(&self) -> PathBuf {
        self.root().join(".socket/vendor/state.json")
    }
    pub fn tgz_path(&self) -> PathBuf {
        self.root()
            .join(format!(".socket/vendor/npm/{V_UUID}/left-pad-1.3.0.tgz"))
    }
    pub fn manifest_json(&self) -> Value {
        serde_json::from_slice(
            &std::fs::read(self.root().join(".socket/manifest.json")).expect("read manifest"),
        )
        .expect("manifest is JSON")
    }
}

pub fn vendor_fixture() -> VendorFixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();

    let pkg = root.join("node_modules/left-pad");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        br#"{"name":"left-pad","version":"1.3.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), ORIG_INDEX).unwrap();

    std::fs::write(
        root.join("package.json"),
        br#"{"name":"fixture","version":"1.0.0","private":true}"#,
    )
    .unwrap();
    let lock = json!({
        "name": "fixture",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": "fixture",
                "version": "1.0.0",
                "dependencies": { "left-pad": "^1.3.0" }
            },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                "integrity": "sha512-orig==",
                "license": "WTFPL"
            }
        }
    });
    let mut original_lock = serde_json::to_vec_pretty(&lock).unwrap();
    original_lock.push(b'\n');
    std::fs::write(root.join("package-lock.json"), &original_lock).unwrap();

    let before_hash = git_sha256(ORIG_INDEX);
    let after_hash = git_sha256(PATCHED_INDEX);
    let manifest = json!({
        "patches": {
            V_PURL: {
                "uuid": V_UUID,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": {
                    "package/index.js": { "beforeHash": before_hash, "afterHash": after_hash }
                },
                "vulnerabilities": {},
                "description": "synthetic vendored covgap patch",
                "license": "MIT",
                "tier": "free"
            }
        }
    });
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let mut manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    manifest_bytes.push(b'\n');
    std::fs::write(socket.join("manifest.json"), &manifest_bytes).unwrap();
    std::fs::write(socket.join("blobs").join(&after_hash), PATCHED_INDEX).unwrap();

    VendorFixture { tmp, original_lock }
}

/// Vendor the fixture through the binary (offline, staged blob source).
pub fn vendor(fx: &VendorFixture) {
    let (code, stdout, stderr) = run(
        fx.root(),
        &[
            "vendor",
            "--json",
            "--silent",
            "--offline",
            "--lock-timeout",
            "5",
        ],
    );
    assert_eq!(
        code, 0,
        "fixture vendor must succeed; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert_ne!(
        fx.lock_bytes(),
        fx.original_lock,
        "sanity: vendor must rewire the lock"
    );
    assert!(fx.tgz_path().is_file(), "sanity: artifact written");
}

/// A mock npm registry (the `SOCKET_NPM_REGISTRY` override the upstream
/// restore reads) serving the version document of each `(name, version)`
/// it was started with; everything else is a 404. The server runs on
/// wiremock's own thread; the runtime is kept only to own it.
pub struct NpmRegistry {
    pub server: wiremock::MockServer,
    _rt: tokio::runtime::Runtime,
}

impl NpmRegistry {
    pub fn start(served: &[(&str, &str)]) -> Self {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let server = rt.block_on(async {
            let server = MockServer::start().await;
            for (name, version) in served {
                Mock::given(method("GET"))
                    .and(path(format!("/npm/{name}/{version}")))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                        "name": name,
                        "version": version,
                        "dist": {
                            "tarball": format!(
                                "https://registry.yarnpkg.com/{name}/-/{name}-{version}.tgz"
                            ),
                            "shasum": "aaaa",
                            "integrity": UPSTREAM_INTEGRITY,
                        }
                    })))
                    .mount(&server)
                    .await;
            }
            server
        });
        Self { server, _rt: rt }
    }

    pub fn base(&self) -> String {
        format!("{}/npm", self.server.uri())
    }

    pub fn request_count(&self) -> usize {
        self._rt
            .block_on(self.server.received_requests())
            .map(|r| r.len())
            .unwrap_or(0)
    }
}

/// `common::run` with the mock patch host recognized as hosted
/// (`--patch-server-url`) and, when given, the npm registry pointed at the
/// mock.
pub fn run_hosted(
    cwd: &Path,
    args: &[&str],
    registry: Option<&NpmRegistry>,
) -> (i32, String, String) {
    let mut full: Vec<&str> = args.to_vec();
    full.extend(["--patch-server-url", PATCH_SERVER]);
    match registry {
        Some(r) => {
            let base = r.base();
            common::run_with_env(cwd, &full, &[("SOCKET_NPM_REGISTRY", base.as_str())])
        }
        None => run(cwd, &full),
    }
}

pub fn ledger_path(root: &Path) -> PathBuf {
    root.join(".socket/vendor/redirect-state.json")
}

/// Write a pre-v5 hosted ledger (v5 never writes one) with the given raw
/// `edits`, exactly as an old release serialized it.
pub fn write_legacy_ledger(root: &Path, edits: Value) {
    let vendor_dir = root.join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).expect("create .socket/vendor");
    let ledger = json!({
        "version": 1,
        "mode": "hosted",
        "edits": edits,
        "records": {},
    });
    let mut bytes = serde_json::to_vec_pretty(&ledger).expect("serialize ledger");
    bytes.push(b'\n');
    std::fs::write(vendor_dir.join("redirect-state.json"), bytes).expect("write ledger");
}

pub fn yarn_block_for(name: &str, version: &str, resolved: &str, integrity: &str) -> String {
    format!(
        "{name}@{version}:\n  version \"{version}\"\n  resolved \"{resolved}\"\n  integrity {integrity}"
    )
}

pub fn yarn_upstream_block_for(name: &str, version: &str) -> String {
    yarn_block_for(
        name,
        version,
        &format!("https://registry.yarnpkg.com/{name}/-/{name}-{version}.tgz#aaaa"),
        UPSTREAM_INTEGRITY,
    )
}

pub fn yarn_original_block() -> String {
    yarn_upstream_block_for("left-pad", "1.2.3")
}

pub fn yarn_redirected_block() -> String {
    yarn_block_for(
        "left-pad",
        "1.2.3",
        LP_HOSTED_URL,
        "sha512-PATCHEDpatched==",
    )
}

pub fn yarn_lock_content(block: &str) -> String {
    format!(
        "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
         # yarn lockfile v1\n\n\n{block}\n"
    )
}

/// Single-pin npm fixture: a yarn.lock hosted-wired to the mock patch host.
pub fn write_single_npm_fixture(root: &Path) {
    std::fs::write(
        root.join("yarn.lock"),
        yarn_lock_content(&yarn_redirected_block()),
    )
    .unwrap();
}

pub fn bun_original_line() -> String {
    format!(r#"    "left-pad": ["left-pad@1.2.3", "", {{}}, "{UPSTREAM_INTEGRITY}"],"#)
}

/// The engine's real redirected shape: registry 4-tuple → URL 3-tuple
/// `["name@<url>", {deps}, "sha512-…"]` (the registry slot is dropped).
pub fn bun_redirected_line() -> String {
    format!(r#"    "left-pad": ["left-pad@{LP_HOSTED_URL}", {{}}, "sha512-PATCHEDpatched=="],"#)
}

pub fn bun_lock(line: &str) -> String {
    format!("{{\n  \"lockfileVersion\": 1,\n  \"packages\": {{\n{line}\n  }}\n}}\n")
}

/// One camelCase manifest patch entry as a JSON value (the string helper
/// above pins `package/index.js`; these fixtures pick their own file key).
pub fn patch_entry_value(uuid: &str, file: &str, before_hash: &str, after_hash: &str) -> Value {
    json!({
        "uuid": uuid,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": {
            file: { "beforeHash": before_hash, "afterHash": after_hash }
        },
        "vulnerabilities": {},
        "description": "synthetic covgap test patch",
        "license": "MIT",
        "tier": "free"
    })
}

pub fn vlt_entry(sha: &str, url: &str) -> String {
    format!("\"{VLT_ID}\": [0,\"left-pad\",\"{sha}\",\"{url}\"]")
}

pub fn vlt_lock_text(entry: &str) -> String {
    format!(
        "{{\n  \"lockfileVersion\": 1,\n  \"options\": {{}},\n  \"nodes\": {{\n    {entry}\n  }},\n  \"edges\": {{}}\n}}\n"
    )
}

/// A redirected vlt project whose store holds the patched copy `vlt
/// install` extracted, with the hidden lock recording the hosted pin (on
/// Socket's own patch host, so discovery needs no `--patch-server-url`).
/// Returns the store path.
pub fn write_vlt_hosted_fixture(root: &Path) -> PathBuf {
    let hosted = vlt_entry(
        VLT_PATCHED_SHA,
        &format!("https://patch.socket.dev/patch/npm/t/{VLT_UUID}/left-pad-1.3.0.tgz"),
    );
    std::fs::write(root.join("vlt-lock.json"), vlt_lock_text(&hosted)).unwrap();
    let store = root
        .join("node_modules/.vlt")
        .join(VLT_ID)
        .join("node_modules/left-pad");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(store.join("index.js"), b"patched").unwrap();
    std::fs::write(
        root.join("node_modules/.vlt-lock.json"),
        vlt_lock_text(&hosted),
    )
    .unwrap();
    store
}

/// `chflags uchg` on a file until dropped: macOS's immutable flag makes the
/// manifest write fail even for root.
#[cfg(target_os = "macos")]
pub struct ChflagsGuard(PathBuf);

#[cfg(target_os = "macos")]
impl ChflagsGuard {
    pub fn set(path: &Path) -> Self {
        let status = std::process::Command::new("chflags")
            .arg("uchg")
            .arg(path)
            .status()
            .expect("run chflags uchg");
        assert!(status.success(), "chflags uchg must succeed");
        Self(path.to_path_buf())
    }
    pub fn release(&self) {
        let _ = std::process::Command::new("chflags")
            .arg("nouchg")
            .arg(&self.0)
            .status();
    }
}

#[cfg(target_os = "macos")]
impl Drop for ChflagsGuard {
    fn drop(&mut self) {
        self.release();
    }
}

/// One manifest entry whose `.socket/blobs` is a regular FILE: the wet
/// run's shape probe refuses that corrupt state up front.
pub fn blobs_path_as_file_fixture() -> tempfile::TempDir {
    let before_hash = git_sha256(b"blobfile-original\n");
    let after_hash = git_sha256(b"blobfile-patched\n");
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = write_socket_manifest(
        tmp.path(),
        &[manifest_entry(
            "pkg:npm/covgap-blobfile@1.0.0",
            "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            &before_hash,
            &after_hash,
        )],
    );
    std::fs::write(socket.join("blobs"), b"not a directory").expect("write blobs file");
    tmp
}

/// Point the vendored entry's ledger record at `ecosystem` (one with no
/// vendor backend in this build fails its revert).
pub fn rewrite_vendored_ecosystem(fx: &VendorFixture, ecosystem: &str) {
    let mut state: Value =
        serde_json::from_slice(&std::fs::read(fx.state_path()).unwrap()).unwrap();
    state["entries"][V_PURL]["ecosystem"] = json!(ecosystem);
    std::fs::write(fx.state_path(), serde_json::to_vec_pretty(&state).unwrap()).unwrap();
}

/// Replace the vendor ledger with bytes that are not JSON.
pub fn corrupt_vendor_ledger(fx: &VendorFixture) {
    std::fs::create_dir_all(fx.root().join(".socket/vendor")).unwrap();
    std::fs::write(fx.state_path(), b"garbage not json").unwrap();
}

/// A pre-v5 ledger's only edit, naming an unsafe path (the old replay
/// refused such a group).
pub fn unsafe_legacy_edits() -> Value {
    json!([{
        "path": "../evil.lock",
        "kind": "redirect_yarn_classic_entry",
        "action": "rewritten",
        "key": "left-pad@1.2.3",
        "original": yarn_original_block(),
        "new": yarn_redirected_block(),
    }])
}

/// A project whose only state is a garbage pre-v5 hosted ledger.
pub fn corrupt_legacy_ledger_project() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("tempdir");
    let vendor_dir = tmp.path().join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    std::fs::write(vendor_dir.join("redirect-state.json"), b"garbage not json").unwrap();
    tmp
}

/// A bun.lock hosted-wired for left-pad; with `installed`, a hoisted
/// `node_modules/left-pad` copy too.
pub fn bun_hosted_project(installed: bool) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        tmp.path().join("bun.lock"),
        bun_lock(&bun_redirected_line()),
    )
    .unwrap();
    if installed {
        let pkg = tmp.path().join("node_modules/left-pad");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(pkg.join("index.js"), "// PATCHED\n").unwrap();
    }
    tmp
}
