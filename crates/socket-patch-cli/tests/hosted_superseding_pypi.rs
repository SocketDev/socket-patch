//! A superseding PyPI patch re-pins a hosted uv or Hatch project (#742,
//! #650). When the patch API stops offering the uuid an earlier
//! `scan --mode hosted` wired and offers a newer one for the same package
//! and version, the next hosted scan lists the UPGRADE row in `updates[]`
//! and must hand the writer the new uuid. Before the fix the uv
//! `[tool.uv.sources]` writer and the Hatch direct-reference writer treated
//! socket-patch's own earlier pin as a user source: exit 0, `success`,
//! `redirect_uv_project_unsupported` / `redirect_uv_script_unsupported` /
//! `redirect_hatch_unsupported`, and the project kept installing the old
//! patch.
//!
//! Hermetic: the patch API and both hosted wheels are a wiremock.

use std::io::Write as _;
use std::path::Path;
use std::process::Command;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const PURL: &str = "pkg:pypi/six@1.16.0";
const WHEEL: &str = "six-1.16.0-py2.py3-none-any.whl";
const UUID_A: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const UUID_B: &str = "aaaaaaaa-0000-4000-8000-000000000004";
const GRANT_A: &str = "11111111-1111-4111-8111-111111111111";
const GRANT_B: &str = "22222222-2222-4222-8222-222222222222";
const WHEEL_SHA: &str = "8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254";

/// A pure-Python patched wheel; `generation` makes each patch's bytes (and
/// so its sha256) distinct.
fn hosted_wheel(generation: u8) -> Vec<u8> {
    let module = format!("# six\nVERSION = '1.16.0'\nSOCKET_PATCHED = {generation}\n");
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    for (name, content) in [
        ("six.py", module.as_bytes()),
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

/// Mount a patch API that offers only `uuid` for six 1.16.0, granted at
/// `grant`, plus the hosted wheel itself. Returns the hosted URL.
async fn offer(server: &MockServer, uuid: &str, grant: &str, generation: u8) -> String {
    server.reset().await;
    let wheel = hosted_wheel(generation);
    let sha = hex::encode(Sha256::digest(&wheel));
    let route = format!("/patch/pypi/six/1.16.0/{grant}/{uuid}/{WHEEL}");
    let hosted_url = format!("{}{route}", server.uri());
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [{ "purl": PURL, "patches": [{
                "uuid": uuid, "purl": PURL, "tier": "free", "cveIds": [], "ghsaIds": [],
                "severity": "high", "title": "superseding pypi fixture"
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
                "uuid": uuid, "purl": PURL, "publishedAt": "2026-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free", "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": { uuid: {
                "status": "granted", "url": hosted_url, "purl": PURL,
                "artifacts": [{ "kind": "tarball", "url": hosted_url,
                                "integrity": { "sha256": sha } }],
                "registryOverride": null
            }}
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(wheel))
        .mount(server)
        .await;
    hosted_url
}

/// `scan --mode hosted --json` with every ambient `SOCKET_*` var scrubbed.
/// `VIRTUAL_ENV` points at the fixture venv ([`project`]), which keeps the
/// installed-tree probes off the host's Python.
fn hosted_scan(root: &Path, server: &MockServer) -> (i32, Value) {
    let venv = root.join("../venv");
    let uri = server.uri();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    cmd.args([
        "scan",
        "--mode",
        "hosted",
        "--yes",
        "--json",
        "--api-url",
        &uri,
        "--org",
        ORG,
        "--api-token",
        "fake-token",
        "--patch-server-url",
        &uri,
        "--ecosystems",
        "pypi",
    ])
    .arg("--cwd")
    .arg(root)
    .current_dir(root);
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") {
            cmd.env_remove(key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("VIRTUAL_ENV", &venv);
    let out = cmd.output().expect("spawn socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let env = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "--json must emit an envelope: {e}\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out.status.code().unwrap_or(-1), env)
}

fn project(files: &[(&str, String)]) -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("proj");
    std::fs::create_dir_all(&root).unwrap();
    for (name, text) in files {
        std::fs::write(root.join(name), text).unwrap();
    }
    // An installed six 1.16.0 (what `hatch env create` leaves behind) for
    // lockless discovery; the uv lanes discover it from their locks.
    let site = tmp.path().join("venv").join(if cfg!(windows) {
        "Lib/site-packages"
    } else {
        "lib/python3.11/site-packages"
    });
    let dist = site.join("six-1.16.0.dist-info");
    std::fs::create_dir_all(&dist).unwrap();
    std::fs::write(
        dist.join("METADATA"),
        "Metadata-Version: 2.1\nName: six\nVersion: 1.16.0\n",
    )
    .unwrap();
    std::fs::write(site.join("six.py"), "VERSION = '1.16.0'\n").unwrap();
    (tmp, root)
}

/// Wire uuid A, then switch the API to uuid B and scan again: the UPGRADE
/// must land in every wiring file `files`, with no writer refusal.
async fn assert_superseded(root: &Path, files: &[&str]) {
    let server = MockServer::start().await;
    let url_a = offer(&server, UUID_A, GRANT_A, 1).await;
    let (code, env) = hosted_scan(root, &server);
    assert_eq!(code, 0, "first hosted scan: {env:#}");
    assert_eq!(env["summary"]["applied"], 1, "first hosted scan: {env:#}");
    for f in files {
        let text = std::fs::read_to_string(root.join(f)).unwrap();
        assert!(text.contains(&url_a), "{f} wired to uuid A:\n{text}");
    }

    let url_b = offer(&server, UUID_B, GRANT_B, 2).await;
    let (code, env) = hosted_scan(root, &server);
    assert_eq!(code, 0, "superseding hosted scan: {env:#}");
    let updates = env["updates"].as_array().cloned().unwrap_or_default();
    assert!(
        updates
            .iter()
            .any(|u| u["oldUuid"] == UUID_A && u["newUuid"] == UUID_B),
        "the UPGRADE row is reported: {env:#}"
    );
    let rendered = env.to_string();
    for code in [
        "redirect_uv_project_unsupported",
        "redirect_uv_script_unsupported",
        "redirect_hatch_unsupported",
    ] {
        assert!(
            !rendered.contains(code),
            "{code} refused the upgrade: {env:#}"
        );
    }
    assert_eq!(env["summary"]["applied"], 1, "re-pinned: {env:#}");
    for f in files {
        let text = std::fs::read_to_string(root.join(f)).unwrap();
        assert!(text.contains(&url_b), "{f} re-pinned to uuid B:\n{text}");
        assert!(!text.contains(UUID_A), "{f} kept uuid A:\n{text}");
    }
}

const UV_LOCK: &str = r#"version = 1
revision = 2
requires-python = ">=3.9"

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "six" },
]

[package.metadata]
requires-dist = [{ name = "six", specifier = "==1.16.0" }]

[[package]]
name = "six"
version = "1.16.0"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/d9/5a/e7c31adbe875f2abbb91bd84cf2dc52d792b5a01506781dbcf25c91daf11/six-1.16.0-py2.py3-none-any.whl", hash = "sha256:WHEEL_SHA", size = 11053, upload-time = "2021-05-05T14:18:17.237Z" },
]
"#;

const SCRIPT_LOCK: &str = r#"version = 1
revision = 2
requires-python = ">=3.9"

[manifest]
requirements = [{ name = "six", specifier = "==1.16.0" }]

[[package]]
name = "six"
version = "1.16.0"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/d9/5a/e7c31adbe875f2abbb91bd84cf2dc52d792b5a01506781dbcf25c91daf11/six-1.16.0-py2.py3-none-any.whl", hash = "sha256:WHEEL_SHA", size = 11053, upload-time = "2021-05-05T14:18:17.237Z" },
]
"#;

/// #742: uv project (`pyproject.toml` + `uv.lock`).
#[tokio::test]
async fn uv_project_repins_superseding_patch() {
    let (_tmp, root) = project(&[
        (
            "pyproject.toml",
            "[project]\nname = \"demo\"\nversion = \"0.1.0\"\nrequires-python = \">=3.9\"\ndependencies = [\"six==1.16.0\"]\n".into(),
        ),
        ("uv.lock", UV_LOCK.replace("WHEEL_SHA", WHEEL_SHA)),
    ]);
    assert_superseded(&root, &["pyproject.toml", "uv.lock"]).await;
}

/// #742: uv PEP 723 script lock (`tool.py` + `tool.py.lock`).
#[tokio::test]
async fn uv_script_lock_repins_superseding_patch() {
    let (_tmp, root) = project(&[
        (
            "tool.py",
            "# /// script\n# requires-python = \">=3.9\"\n# dependencies = [\"six==1.16.0\"]\n# ///\nimport six\n".into(),
        ),
        ("tool.py.lock", SCRIPT_LOCK.replace("WHEEL_SHA", WHEEL_SHA)),
    ]);
    assert_superseded(&root, &["tool.py", "tool.py.lock"]).await;
}

/// #650: Hatch project, project dependency and env table in pyproject.toml.
#[tokio::test]
async fn hatch_pyproject_repins_superseding_patch() {
    let (_tmp, root) = project(&[(
        "pyproject.toml",
        "[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n\n[project]\nname = \"demo\"\nversion = \"0.1.0\"\ndependencies = [\"six==1.16.0\"]\n\n[tool.hatch.envs.default]\ndependencies = [\"six==1.16.0\"]\n".into(),
    )]);
    assert_superseded(&root, &["pyproject.toml"]).await;
}

/// #650: Hatch env dependencies declared in hatch.toml.
#[tokio::test]
async fn hatch_toml_repins_superseding_patch() {
    let (_tmp, root) = project(&[
        (
            "pyproject.toml",
            "[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n\n[project]\nname = \"demo\"\nversion = \"0.1.0\"\ndependencies = []\n".into(),
        ),
        (
            "hatch.toml",
            "[envs.default]\ndependencies = [\"six==1.16.0\"]\n".into(),
        ),
    ]);
    assert_superseded(&root, &["hatch.toml"]).await;
}
