//! Hermetic hosted → vendored takeover tests through the built binary for
//! PyPI projects whose shape a vendored backend refuses although hosted
//! mode accepts it (#944): a uv project whose `pyproject.toml` carries an
//! inline `[tool.uv] sources = { … }` table, and a `uv pip compile
//! --universal` requirements.txt whose package is split by markers across
//! two exact pins (#928).
//!
//! `scan --mode vendored` over such a hosted pin used to commit the
//! upstream restore FIRST and only then reach the backend's refusal, so the
//! run failed with the hosted pin already gone: six was left neither
//! hosted nor vendored, and the next `uv sync` installed the unpatched
//! release. The package must stay patched in one mode or the other.
//!
//! The patch API, the hosted wheel and PyPI's JSON API are wiremock; no
//! Python toolchain is needed.

#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::io::Write as _;
use std::path::Path;
use std::process::Command;

use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const UUID: &str = "5c3e1a2b-7d4f-4e6a-9b8c-1d2e3f4a5b6c";
const PURL: &str = "pkg:pypi/six@1.16.0";
const WHEEL: &str = "six-1.16.0-py2.py3-none-any.whl";
const ORIG: &[u8] = b"# six\nVERSION = '1.16.0'\n";
const PATCHED: &[u8] = b"# six\nVERSION = '1.16.0'\nSOCKET_PATCHED = 1\n";
const WHEEL_SHA: &str = "8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254";
const SDIST_SHA: &str = "1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926";
const WHEEL_URL: &str = "https://files.pythonhosted.org/packages/d9/5a/e7c31adbe875f2abbb91bd84cf2dc52d792b5a01506781dbcf25c91daf11/six-1.16.0-py2.py3-none-any.whl";
const SDIST_URL: &str = "https://files.pythonhosted.org/packages/71/39/171f1c67cd00715f190ba0b100d606d440a28c93c7714febeca8b79af85e/six-1.16.0.tar.gz";

// ───────────────────────────── fixture ─────────────────────────────

/// The hosted wheel: a pure-Python wheel carrying the patched module.
fn hosted_wheel() -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    for (name, content) in [
        ("six.py", PATCHED),
        (
            "six-1.16.0.dist-info/METADATA",
            b"Metadata-Version: 2.1\nName: six\nVersion: 1.16.0\n\n".as_slice(),
        ),
        (
            "six-1.16.0.dist-info/WHEEL",
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py2-none-any\nTag: py3-none-any\n"
                .as_slice(),
        ),
        (
            "six-1.16.0.dist-info/RECORD",
            b"six.py,,\nsix-1.16.0.dist-info/METADATA,,\nsix-1.16.0.dist-info/WHEEL,,\nsix-1.16.0.dist-info/RECORD,,\n"
                .as_slice(),
        ),
    ] {
        zip.start_file(name, opts).unwrap();
        zip.write_all(content).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

fn patch_view() -> Value {
    json!({
        "uuid": UUID,
        "purl": PURL,
        "publishedAt": "2026-01-01T00:00:00Z",
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": { "six.py": {
            "beforeHash": compute_git_sha256_from_bytes(ORIG),
            "afterHash": compute_git_sha256_from_bytes(PATCHED),
            "blobContent": base64::engine::general_purpose::STANDARD.encode(PATCHED),
        }},
        "vulnerabilities": {},
        "description": "pypi hosted → vendored takeover fixture",
        "license": "MIT",
        "tier": "free"
    })
}

/// The patch API (discovery, grant, view), the hosted wheel, and PyPI's
/// JSON API document the upstream restore re-derives six's files from.
/// Returns the hosted wheel's URL.
async fn mount_api(server: &MockServer) -> String {
    let wheel = hosted_wheel();
    let sha = hex::encode(Sha256::digest(&wheel));
    let route =
        format!("/patch/pypi/six/1.16.0/33333333-3333-4333-8333-333333333333/{UUID}/{WHEEL}");
    let hosted_url = format!("{}{route}", server.uri());
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [{ "purl": PURL, "patches": [{
                "uuid": UUID, "purl": PURL, "tier": "free", "cveIds": [], "ghsaIds": [],
                "severity": "high", "title": "pypi takeover fixture"
            }]}],
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
                "uuid": UUID, "purl": PURL, "publishedAt": "2026-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free", "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": { UUID: {
                "status": "granted", "url": hosted_url, "purl": PURL,
                "artifacts": [{ "kind": "tarball", "url": hosted_url,
                                "integrity": { "sha256": sha } }],
                "registryOverride": null
            }}
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(patch_view()))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(wheel))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/pypi/six/1.16.0/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "urls": [
            { "filename": WHEEL, "url": WHEEL_URL, "digests": { "sha256": WHEEL_SHA },
              "size": 11053, "upload_time_iso_8601": "2021-05-05T14:18:17.237Z" },
            { "filename": "six-1.16.0.tar.gz", "url": SDIST_URL,
              "digests": { "sha256": SDIST_SHA },
              "size": 34041, "upload_time_iso_8601": "2021-05-05T14:18:18.379Z" },
        ]})))
        .mount(server)
        .await;
    hosted_url
}

const UV_LOCK: &str = r#"version = 1
revision = 2
requires-python = ">=3.9"

[[package]]
name = "attrs"
version = "25.3.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/5a/b0/1367933a8532ee6ff8d63537de4f1177af4bff9f3e829baf7331f595bb24/attrs-25.3.0.tar.gz", hash = "sha256:75d7cefc7fb576747b2c81b4442d4d4a1ce0900973527c011d1030fd3bf4af1b", size = 812032, upload-time = "2025-03-13T11:10:22.779Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/77/06/bb80f5f86020c4551da315d78b3ab75e8228f89f0162f2c3a819e407941a/attrs-25.3.0-py3-none-any.whl", hash = "sha256:427318ce031701fea540783410126f03899a97ffc6f61596ad581ac2e40e3bc3", size = 63815, upload-time = "2025-03-13T11:10:21.14Z" },
]

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "attrs" },
    { name = "six" },
]

[package.metadata]
requires-dist = [
    { name = "attrs", index = "https://pypi.org/simple" },
    { name = "six", specifier = "==1.16.0" },
]

[[package]]
name = "six"
version = "1.16.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "SDIST_URL", hash = "sha256:SDIST_SHA", size = 34041, upload-time = "2021-05-05T14:18:18.379Z" }
wheels = [
    { url = "WHEEL_URL", hash = "sha256:WHEEL_SHA", size = 11053, upload-time = "2021-05-05T14:18:17.237Z" },
]
"#;

/// #944 trigger 1: a uv project whose `[tool.uv]` names its sources as an
/// inline table, which the uv vendored backend refuses and hosted mode
/// grows in place. Returns its wiring files.
fn stage_uv_inline_sources(root: &Path) -> &'static [&'static str] {
    std::fs::write(
        root.join("pyproject.toml"),
        "[project]\nname = \"demo\"\nversion = \"0.1.0\"\nrequires-python = \">=3.9\"\n\
         dependencies = [\"six==1.16.0\", \"attrs\"]\n\n\
         [tool.uv]\nsources = { attrs = { index = \"pypi\" } }\n\n\
         [[tool.uv.index]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("uv.lock"),
        UV_LOCK
            .replace("SDIST_URL", SDIST_URL)
            .replace("WHEEL_URL", WHEEL_URL)
            .replace("WHEEL_SHA", WHEEL_SHA)
            .replace("SDIST_SHA", SDIST_SHA),
    )
    .unwrap();
    &["uv.lock", "pyproject.toml"]
}

/// #944 trigger 2 (#928's shape): `uv pip compile --universal` output that
/// pins six to 1.16.0 below Python 3.12 and to 1.17.0 from it.
fn stage_requirements_marker_split(root: &Path) -> &'static [&'static str] {
    std::fs::write(
        root.join("requirements.txt"),
        "six==1.16.0 ; python_full_version < '3.12'\n\
         six==1.17.0 ; python_full_version >= '3.12'\n",
    )
    .unwrap();
    &["requirements.txt"]
}

/// `.socket/manifest.json` plus the after-hash blob, from which the
/// prebuilt fixture server builds the vendored wheel.
fn stage_manifest(root: &Path) {
    let after = compute_git_sha256_from_bytes(PATCHED);
    let manifest = json!({ "patches": { PURL: {
        "uuid": UUID,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": { "six.py": {
            "beforeHash": compute_git_sha256_from_bytes(ORIG),
            "afterHash": after,
        }},
        "vulnerabilities": {},
        "description": "pypi hosted → vendored takeover fixture",
        "license": "MIT",
        "tier": "free"
    }}});
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(after), PATCHED).unwrap();
}

// ───────────────────────── subprocess runner ─────────────────────────

/// The built binary with every ambient `SOCKET_*` var scrubbed, PyPI's JSON
/// API pointed at the mock, and a `VIRTUAL_ENV` holding the unpatched six
/// so the installed-tree probes stay off the host's Python. `vendored` runs
/// get the prebuilt fixture server, which builds the vendored wheel from
/// that installed copy.
fn run_scan(root: &Path, server: &MockServer, mode: &str, extra: &[&str]) -> (i32, Value) {
    let venv = root.join("../venv");
    let site = venv.join(if cfg!(windows) {
        "Lib/site-packages"
    } else {
        "lib/python3.11/site-packages"
    });
    let info = site.join("six-1.16.0.dist-info");
    std::fs::create_dir_all(&info).unwrap();
    std::fs::write(site.join("six.py"), ORIG).unwrap();
    std::fs::write(
        info.join("METADATA"),
        "Metadata-Version: 2.1\nName: six\nVersion: 1.16.0\n\n",
    )
    .unwrap();
    std::fs::write(info.join("RECORD"), "six.py,,\n").unwrap();
    let uri = server.uri();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    cmd.args([
        "scan",
        "--mode",
        mode,
        "--json",
        "--yes",
        "--api-url",
        &uri,
        "--org",
        ORG,
        "--api-token",
        "fake-token",
        "--patch-server-url",
        &uri,
    ])
    .args(extra)
    .arg("--cwd")
    .arg(root)
    .current_dir(root);
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") {
            cmd.env_remove(key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_PYPI_JSON_API", format!("{uri}/pypi"))
        .env("VIRTUAL_ENV", &venv)
        .env("PIPENV_IGNORE_VIRTUALENVS", "0");
    let fixture = (mode == "vendored").then(|| {
        prebuilt_common::Server::project_with_env(root, &[("VIRTUAL_ENV", venv.to_str().unwrap())])
    });
    if let Some(fixture) = &fixture {
        cmd.arg("--vendor-url").arg(&fixture.uri);
    }
    let out = cmd.output().expect("spawn socket-patch");
    drop(fixture);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let env = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json must emit an envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    (out.status.code().unwrap_or(-1), env)
}

fn project() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("proj");
    std::fs::create_dir_all(&root).unwrap();
    (tmp, root)
}

fn snapshot(root: &Path, files: &[&str]) -> Vec<String> {
    files
        .iter()
        .map(|f| std::fs::read_to_string(root.join(f)).unwrap())
        .collect()
}

/// Host the staged project, then run `scan --mode vendored` (dry run
/// first) over it. Returns `(hosted wiring, exit, envelope)`.
async fn host_then_vendor(root: &Path, files: &[&str]) -> (Vec<String>, i32, Value) {
    let server = MockServer::start().await;
    let hosted_url = mount_api(&server).await;
    let (code, env) = run_scan(root, &server, "hosted", &[]);
    assert_eq!(code, 0, "hosted scan: {env:#}");
    let hosted = snapshot(root, files);
    assert!(
        hosted.iter().any(|t| t.contains(&hosted_url)),
        "hosted mode must pin six: {hosted:#?}\n{env:#}"
    );

    stage_manifest(root);
    let (_, env) = run_scan(root, &server, "vendored", &["--dry-run"]);
    assert_eq!(
        snapshot(root, files),
        hosted,
        "the dry run writes nothing: {env:#}"
    );

    let (exit, env) = run_scan(root, &server, "vendored", &[]);
    (hosted, exit, env)
}

fn has_code(env: &Value, code: &str) -> bool {
    env.to_string().contains(&format!("\"{code}\""))
}

// ───────────────────────────── scenarios ─────────────────────────────

/// #944: a uv project with an inline `[tool.uv] sources` table, which the
/// uv vendored backend refuses after the takeover restored the PyPI entry.
/// Whatever refuses the purl after the restore (here the run can also stop
/// at the prebuilt download), the hosted pin in `pyproject.toml` and
/// `uv.lock` must stay byte-for-byte.
#[tokio::test(flavor = "multi_thread")]
async fn scan_vendored_over_hosted_uv_inline_sources_keeps_the_hosted_pin() {
    let (_tmp, root) = project();
    let files = stage_uv_inline_sources(&root);
    let (hosted, exit, env) = host_then_vendor(&root, files).await;
    assert_eq!(exit, 1, "the refusal fails the run: {env:#}");
    assert!(
        !has_code(&env, "vendor_takeover_reverted_redirect"),
        "a refused purl must not be reported as restored: {env:#}"
    );
    assert_eq!(
        snapshot(&root, files),
        hosted,
        "the hosted pin stays byte-for-byte: {env:#}"
    );
    assert!(!root.join(format!(".socket/vendor/pypi/{UUID}")).exists());
}

/// #944 (#928's shape): whatever the requirements backend decides about a
/// marker-split pin, six is never left un-hosted and unvendored: either the
/// takeover vendors it, or it fails and the hosted line stays as hosted
/// mode wrote it.
#[tokio::test(flavor = "multi_thread")]
async fn scan_vendored_over_hosted_marker_split_requirements_never_unpatches() {
    let (_tmp, root) = project();
    let files = stage_requirements_marker_split(&root);
    let (hosted, exit, env) = host_then_vendor(&root, files).await;
    let now = snapshot(&root, files);
    if exit == 0 {
        assert!(
            now[0].contains(&format!(".socket/vendor/pypi/{UUID}/")),
            "a successful takeover wires the vendored wheel:\n{}\n{env:#}",
            now[0]
        );
    } else {
        assert!(
            !has_code(&env, "vendor_takeover_reverted_redirect"),
            "a refused purl must not be reported as restored: {env:#}"
        );
        assert_eq!(now, hosted, "the hosted pin stays byte-for-byte: {env:#}");
    }
}
