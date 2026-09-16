//! `scan --mode hosted` against project files that are NOT plain regular
//! files: symbolic links and FIFOs.
//!
//! Policy (PR #239 review): symlinked project files are DISCOVERED (the
//! Python lock discovery follows links) but never REWRITTEN in place — every
//! writer stages a replacement next to the path and renames over it, which
//! replaces the link with a detached regular copy, leaves the link target
//! stale (uv itself writes THROUGH the link) and makes a later revert
//! restore bytes but never the link (git: a 120000→100644 typechange). The
//! hosted REVERT side already refuses symlinked files fail-closed; these
//! tests pin the WRITE side to the same policy: the whole (transactional)
//! rewrite is refused with a stable code, before the ledger and before any
//! file write.
//!
//! A FIFO planted under a candidate name (`pyproject.toml`) must be skipped
//! like an unreadable file, never opened with a blocking `open(2)` that waits
//! for a writer forever.
//!
//! Everything runs the built binary as a subprocess via
//! `common::run_with_env` (hermetic `SOCKET_*` scrub) against a wiremock
//! patch API, so the JSON envelope and the human stderr can both be read.

#![cfg(unix)]

use std::path::Path;

use serde_json::{json, Value};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/mod.rs"]
mod common;

const ORG: &str = "test-org";
const CODE: &str = "redirect_symlinked_file_unsupported";
const LEDGER_REL: &str = ".socket/vendor/redirect-state.json";

// npm fixture (the covgap hosted shape).
const NPM_NAME: &str = "symlink-hosted";
const NPM_VERSION: &str = "1.0.0";
const NPM_PURL: &str = "pkg:npm/symlink-hosted@1.0.0";
const NPM_UUID: &str = "11111111-1111-4111-8111-111111111111";
const NPM_HOSTED_URL: &str = "http://patch.test/patch/npm/symlink-hosted/1.0.0/22222222-2222-4222-8222-222222222222/11111111-1111-4111-8111-111111111111/symlink-hosted-1.0.0.tgz";
const PATCHED_SHA512: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789==";
const UPSTREAM_SHA512: &str = "sha512-UPSTREAMupstream==";

// pypi fixture: the real `uv lock` output of uv 0.12.15 for a project
// depending on `urllib3==1.26.18` (the public free-tier patch target).
const PYPI_NAME: &str = "urllib3";
const PYPI_VERSION: &str = "1.26.18";
const PYPI_PURL: &str = "pkg:pypi/urllib3@1.26.18";
const PYPI_UUID: &str = "33333333-3333-4333-8333-333333333333";
const PYPROJECT: &str = "[project]\nname = \"socket-uv-patch-fixture\"\nversion = \"0.1.0\"\nrequires-python = \">=3.9\"\ndependencies = [\"urllib3==1.26.18\"]\n";
const UV_LOCK: &str = r#"version = 1
revision = 3
requires-python = ">=3.9"

[[package]]
name = "socket-uv-patch-fixture"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "urllib3" },
]

[package.metadata]
requires-dist = [{ name = "urllib3", specifier = "==1.26.18" }]

[[package]]
name = "urllib3"
version = "1.26.18"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/0c/39/64487bf07df2ed854cc06078c27c0d0abc59bd27b32232876e403c333a08/urllib3-1.26.18.tar.gz", hash = "sha256:f8ecc1bba5667413457c529ab955bf8c67b45db799d159066261719e328580a0", size = 305687, upload-time = "2023-10-17T17:47:03.986Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/b0/53/aa91e163dcfd1e5b82d8a890ecf13314e3e149c05270cc644581f77f17fd/urllib3-1.26.18-py2.py3-none-any.whl", hash = "sha256:34b97092d7e0a3a8cf7cd10e386f401b3737364026c45e622aa02903dffe0f07", size = 143835, upload-time = "2023-10-17T17:47:01.725Z" },
]
"#;

// ───────────────────────────── API mocks ─────────────────────────────

/// Batch discovery + per-package search for one `(purl, uuid)` pair.
async fn mock_discovery(server: &MockServer, purl: &str, uuid: &str) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": uuid, "purl": purl, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "symlink hosted fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "patches": [{
                "uuid": uuid, "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uuid": uuid,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {},
            "vulnerabilities": {},
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(server)
        .await;
}

/// A granted reference whose single `tarball` artifact carries `integrity`.
async fn mock_granted_reference(
    server: &MockServer,
    uuid: &str,
    purl: &str,
    url: &str,
    integrity: Value,
) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": {
                uuid: {
                    "status": "granted",
                    "url": url,
                    "purl": purl,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": url,
                        "integrity": integrity
                    }],
                    "registryOverride": null
                }
            }
        })))
        .mount(server)
        .await;
}

/// A minimal but valid wheel: `<name>-<version>.dist-info/METADATA` with the
/// three required core-metadata headers. Returns the bytes and their sha256.
fn build_wheel(name: &str, version: &str) -> (Vec<u8>, String) {
    use std::io::Write as _;
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer
            .start_file(format!("{name}-{version}.dist-info/METADATA"), opts)
            .unwrap();
        writer
            .write_all(format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n").as_bytes())
            .unwrap();
        writer.finish().unwrap();
    }
    let bytes = buf.into_inner();
    let sha = common::sha256_hex(&bytes);
    (bytes, sha)
}

/// Serve the wheel at `/wheels/<file>` and return its full URL.
async fn mock_wheel(server: &MockServer, file: &str, bytes: Vec<u8>) -> String {
    Mock::given(method("GET"))
        .and(path(format!("/wheels/{file}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
        .mount(server)
        .await;
    format!("{}/wheels/{file}", server.uri())
}

// ─────────────────────────── project fixtures ───────────────────────────

/// npm project: package.json + installed node_modules copy + a
/// lockfileVersion-3 package-lock.json resolving `name` upstream.
fn write_npm_project(root: &Path) {
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(
        root.join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NPM_NAME}": "{NPM_VERSION}" }} }}"#
        ),
    )
    .unwrap();
    let pkg = root.join("node_modules").join(NPM_NAME);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{NPM_NAME}", "version": "{NPM_VERSION}" }}"#),
    )
    .unwrap();
    std::fs::write(
        root.join("package-lock.json"),
        format!(
            r#"{{
  "name": "consumer",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {{
    "": {{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NPM_NAME}": "{NPM_VERSION}" }} }},
    "node_modules/{NPM_NAME}": {{
      "version": "{NPM_VERSION}",
      "resolved": "https://registry.npmjs.org/{NPM_NAME}/-/{NPM_NAME}-{NPM_VERSION}.tgz",
      "integrity": "{UPSTREAM_SHA512}"
    }}
  }}
}}
"#
        ),
    )
    .unwrap();
}

/// uv project: pyproject.toml + the real 0.12.15 uv.lock + a fabricated
/// `.venv` install the python crawler discovers (`<name>-<version>.dist-info`
/// under the POSIX site-packages layout — this file is unix-only).
fn write_uv_project(root: &Path) {
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(root.join("pyproject.toml"), PYPROJECT).unwrap();
    std::fs::write(root.join("uv.lock"), UV_LOCK).unwrap();
    let site = root
        .join(".venv")
        .join("lib")
        .join("python3.11")
        .join("site-packages");
    let dist = site.join(format!("{PYPI_NAME}-{PYPI_VERSION}.dist-info"));
    std::fs::create_dir_all(&dist).unwrap();
    std::fs::write(
        dist.join("METADATA"),
        format!("Metadata-Version: 2.1\nName: {PYPI_NAME}\nVersion: {PYPI_VERSION}\n"),
    )
    .unwrap();
    std::fs::create_dir_all(site.join(PYPI_NAME)).unwrap();
    std::fs::write(site.join(PYPI_NAME).join("__init__.py"), "# upstream\n").unwrap();
}

/// Move `<root>/<name>` to `<shared>/<name>` and leave a RELATIVE symlink in
/// its place (the checked-in shared-lock layout). Returns the target path.
fn symlink_away(root: &Path, shared: &Path, name: &str) -> std::path::PathBuf {
    std::fs::create_dir_all(shared).unwrap();
    let target = shared.join(name);
    std::fs::rename(root.join(name), &target).unwrap();
    let rel = format!("../{}/{name}", shared.file_name().unwrap().to_str().unwrap());
    std::os::unix::fs::symlink(&rel, root.join(name)).unwrap();
    assert!(is_symlink(&root.join(name)) && root.join(name).exists());
    target
}

fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

fn mkfifo(path: &Path) {
    use std::os::unix::ffi::OsStrExt as _;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
    assert_eq!(rc, 0, "mkfifo(2): {}", std::io::Error::last_os_error());
}

// ───────────────────────────── runners ─────────────────────────────

fn scan_hosted(cwd: &Path, api_url: &str, extra: &[&str]) -> (i32, String, String) {
    let cwd_s = cwd.to_str().unwrap().to_string();
    let mut args = vec![
        "scan",
        "--mode",
        "hosted",
        "--yes",
        "--cwd",
        &cwd_s,
        "--api-url",
        api_url,
        "--org",
        ORG,
        "--api-token",
        "fake",
    ];
    args.extend_from_slice(extra);
    common::run_with_env(cwd, &args, &[])
}

fn scan_hosted_json(cwd: &Path, api_url: &str) -> (i32, Value, String) {
    let (code, stdout, stderr) = scan_hosted(cwd, api_url, &["--json"]);
    let doc = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("stdout must be the JSON envelope ({e});\nstdout=\n{stdout}\nstderr=\n{stderr}")
    });
    (code, doc, stderr)
}

/// The shared refusal contract: exit 1, `status: error`, the stable code,
/// the detail names the linked file, and NOTHING was written — the link is
/// still a link, its target is byte-identical, no ledger exists.
fn assert_refused_untouched(
    code: i32,
    doc: &Value,
    root: &Path,
    linked: &str,
    target: &Path,
    target_before: &[u8],
) {
    assert_eq!(code, 1, "a symlinked rewrite target must fail the run: {doc:#}");
    assert_eq!(doc["status"], "error", "{doc:#}");
    assert_eq!(doc["errorCode"], CODE, "{doc:#}");
    let message = doc["error"].as_str().unwrap_or_else(|| panic!("{doc:#}"));
    assert!(
        message.contains(linked) && message.contains("symbolic link"),
        "the error must name the linked file: {message}"
    );
    assert!(
        message.contains("atomic rename") && message.contains("re-run"),
        "the error must explain the rename-over hazard and the remedy: {message}"
    );
    assert!(
        is_symlink(&root.join(linked)),
        "{linked} must still be a symlink: a rename-over would have detached it"
    );
    assert_eq!(
        std::fs::read(target).unwrap(),
        target_before,
        "the link target must stay byte-identical"
    );
    assert!(
        !root.join(LEDGER_REL).exists(),
        "a refused rewrite must not write a redirect ledger"
    );
}

// ───────────────────────────── tests ─────────────────────────────

/// uv project whose `uv.lock` is a symlink into a shared directory (the
/// exact layout reproduced against uv 0.12.15: uv writes THROUGH the link,
/// socket-patch's rename-over replaced it with a detached regular copy).
/// The rewrite plan touches pyproject.toml (regular) AND uv.lock (link);
/// the whole plan is refused before the ledger and before either write.
#[tokio::test]
async fn hosted_refuses_symlinked_lock_before_ledger_write() {
    let server = MockServer::start().await;
    mock_discovery(&server, PYPI_PURL, PYPI_UUID).await;
    let (wheel, sha256) = build_wheel(PYPI_NAME, PYPI_VERSION);
    let wheel_url = mock_wheel(
        &server,
        &format!("{PYPI_NAME}-{PYPI_VERSION}-py2.py3-none-any.whl"),
        wheel,
    )
    .await;
    mock_granted_reference(
        &server,
        PYPI_UUID,
        PYPI_PURL,
        &wheel_url,
        json!({ "sha256": sha256 }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("proj");
    write_uv_project(&root);
    let target = symlink_away(&root, &tmp.path().join("shared"), "uv.lock");
    let lock_before = std::fs::read(&target).unwrap();

    let (code, doc, _stderr) = scan_hosted_json(&root, &server.uri());
    assert_refused_untouched(code, &doc, &root, "uv.lock", &target, &lock_before);
    assert_eq!(
        std::fs::read_to_string(root.join("pyproject.toml")).unwrap(),
        PYPROJECT,
        "the regular sibling in the same plan must not be written either: hosted \
         rewrites are transactional"
    );
    assert!(
        !root.join(".socket").exists(),
        "nothing under .socket/ may be created by a refused rewrite"
    );
}

/// The same defect exists for every ecosystem: a symlinked package-lock.json
/// is refused identically. The human (non-JSON) run prints the same code
/// and message on stderr and leaves the tree untouched too.
#[tokio::test]
async fn hosted_refuses_symlinked_package_lock_before_ledger_write() {
    let server = MockServer::start().await;
    mock_discovery(&server, NPM_PURL, NPM_UUID).await;
    mock_granted_reference(
        &server,
        NPM_UUID,
        NPM_PURL,
        NPM_HOSTED_URL,
        json!({ "sha512": PATCHED_SHA512 }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("proj");
    write_npm_project(&root);
    let target = symlink_away(&root, &tmp.path().join("shared"), "package-lock.json");
    let lock_before = std::fs::read(&target).unwrap();

    let (code, doc, _stderr) = scan_hosted_json(&root, &server.uri());
    assert_refused_untouched(
        code,
        &doc,
        &root,
        "package-lock.json",
        &target,
        &lock_before,
    );

    let (code, _stdout, stderr) = scan_hosted(&root, &server.uri(), &[]);
    assert_eq!(code, 1, "human run must fail the same way:\n{stderr}");
    assert!(
        stderr.contains(CODE) && stderr.contains("package-lock.json is a symbolic link"),
        "the human run must print the stable code and the linked file:\n{stderr}"
    );
    assert!(is_symlink(&root.join("package-lock.json")));
    assert_eq!(std::fs::read(&target).unwrap(), lock_before);
    assert!(!root.join(LEDGER_REL).exists());
}

/// Control: with the link replaced by a regular file the identical project
/// redirects normally — the refusal is about the LINK, not the layout.
#[tokio::test]
async fn hosted_rewrites_the_same_lock_once_it_is_a_regular_file() {
    let server = MockServer::start().await;
    mock_discovery(&server, NPM_PURL, NPM_UUID).await;
    mock_granted_reference(
        &server,
        NPM_UUID,
        NPM_PURL,
        NPM_HOSTED_URL,
        json!({ "sha512": PATCHED_SHA512 }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("proj");
    write_npm_project(&root);
    let target = symlink_away(&root, &tmp.path().join("shared"), "package-lock.json");
    std::fs::remove_file(root.join("package-lock.json")).unwrap();
    std::fs::copy(&target, root.join("package-lock.json")).unwrap();

    let (code, doc, stderr) = scan_hosted_json(&root, &server.uri());
    assert_eq!(code, 0, "{doc:#}\n{stderr}");
    assert_eq!(doc["redirect"]["redirected"], 1, "{doc:#}");
    assert!(
        std::fs::read_to_string(root.join("package-lock.json"))
            .unwrap()
            .contains(NPM_HOSTED_URL)
    );
    assert!(root.join(LEDGER_REL).exists());
}

/// A FIFO planted as `pyproject.toml` beside a real uv.lock: the candidate
/// collection must SKIP it (like any unreadable candidate) and the scan must
/// return. Before the fix the raw `read_to_string` wedged forever in
/// `open(2)` waiting for a writer — reproduced for `scan --mode hosted` and
/// `get --mode hosted`.
#[tokio::test]
async fn hosted_scan_returns_with_fifo_candidate() {
    let server = MockServer::start().await;
    mock_discovery(&server, PYPI_PURL, PYPI_UUID).await;
    let (wheel, sha256) = build_wheel(PYPI_NAME, PYPI_VERSION);
    let wheel_url = mock_wheel(
        &server,
        &format!("{PYPI_NAME}-{PYPI_VERSION}-py2.py3-none-any.whl"),
        wheel,
    )
    .await;
    mock_granted_reference(
        &server,
        PYPI_UUID,
        PYPI_PURL,
        &wheel_url,
        json!({ "sha256": sha256 }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("proj");
    write_uv_project(&root);
    std::fs::remove_file(root.join("pyproject.toml")).unwrap();
    let fifo = root.join("pyproject.toml");
    mkfifo(&fifo);

    let (tx, rx) = std::sync::mpsc::channel();
    let api = server.uri();
    let run_root = root.clone();
    std::thread::spawn(move || {
        let _ = tx.send(scan_hosted(&run_root, &api, &["--json"]));
    });
    // A healthy run finishes in seconds; a wedged one never returns. On
    // timeout connect a writer to the FIFO so the wedged `open(2)` releases
    // and the child exits, then FAIL — never hang the suite.
    let deadline = std::time::Duration::from_secs(90);
    let (code, stdout, stderr) = match rx.recv_timeout(deadline) {
        Ok(result) => result,
        Err(_) => {
            use std::os::unix::fs::OpenOptionsExt as _;
            let released = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&fifo)
                .is_ok();
            panic!(
                "scan --mode hosted wedged on a FIFO pyproject.toml for {deadline:?} \
                 (a reader was blocked in open(2): {released})"
            );
        }
    };
    assert!(
        code == 0 || code == 1,
        "the run must complete with a real exit status, got {code}:\n{stdout}\n{stderr}"
    );
    let doc: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("JSON envelope expected ({e}):\n{stdout}\n{stderr}"));
    assert!(
        doc["status"] == "success" || doc["status"] == "error",
        "{doc:#}"
    );
    // The FIFO itself is left in place (nothing ever wrote to that name).
    let meta = std::fs::symlink_metadata(&fifo).unwrap();
    assert!(
        std::os::unix::fs::FileTypeExt::is_fifo(&meta.file_type()),
        "the FIFO must not be replaced by a rewrite"
    );
}
