//! socket.yml package specs and `scan --package` name PyPI projects by
//! their PEP 503 canonical name (#910). Every PyPI purl socket-patch builds
//! is canonical (`pkg:pypi/typing-extensions`), so before the fix a spec
//! spelled the way `requirements.txt` or `import` spells it
//! (`typing_extensions`, `typing.extensions`) never matched:
//! `ignorePackages` silently stopped excluding the package (the hosted scan
//! still rewrote requirements.txt), while `packages` and `--package`
//! silently selected nothing.
//!
//! Hermetic: the patch API and the hosted wheel are a wiremock.

#[path = "common/hermetic.rs"]
mod hermetic;

use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const PURL: &str = "pkg:pypi/typing-extensions@4.12.2";
const WHEEL: &str = "typing_extensions-4.12.2-py3-none-any.whl";
const UUID: &str = "aaaaaaaa-0000-4000-8000-000000000910";
const GRANT: &str = "11111111-1111-4111-8111-111111111910";
const REQUIREMENTS: &str = "typing_extensions==4.12.2\n";

fn hosted_wheel() -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    for (name, content) in [
        ("typing_extensions.py", "SOCKET_PATCHED = 1\n"),
        (
            "typing_extensions-4.12.2.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: typing_extensions\nVersion: 4.12.2\n\n",
        ),
        (
            "typing_extensions-4.12.2.dist-info/WHEEL",
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        ),
        (
            "typing_extensions-4.12.2.dist-info/RECORD",
            "typing_extensions.py,,\ntyping_extensions-4.12.2.dist-info/METADATA,,\n\
             typing_extensions-4.12.2.dist-info/WHEEL,,\ntyping_extensions-4.12.2.dist-info/RECORD,,\n",
        ),
    ] {
        zip.start_file(name, opts).unwrap();
        zip.write_all(content.as_bytes()).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

/// A patch API offering one free patch for typing-extensions 4.12.2.
async fn api() -> MockServer {
    let server = MockServer::start().await;
    let wheel = hosted_wheel();
    let sha = hex::encode(Sha256::digest(&wheel));
    let route = format!("/patch/pypi/typing-extensions/4.12.2/{GRANT}/{UUID}/{WHEEL}");
    let hosted_url = format!("{}{route}", server.uri());
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [{ "purl": PURL, "patches": [{
                "uuid": UUID, "purl": PURL, "tier": "free", "cveIds": [], "ghsaIds": [],
                "severity": "high", "title": "pep 503 policy fixture"
            }]}],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
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
        .mount(&server)
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
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(wheel))
        .mount(&server)
        .await;
    server
}

/// A pip project (`requirements.txt`) with typing_extensions 4.12.2
/// installed in a fixture venv, plus an optional socket.yml.
fn project(socket_yml: Option<&str>) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("proj");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("requirements.txt"), REQUIREMENTS).unwrap();
    if let Some(yml) = socket_yml {
        std::fs::write(root.join("socket.yml"), yml).unwrap();
    }
    let site = tmp.path().join("venv").join(if cfg!(windows) {
        "Lib/site-packages"
    } else {
        "lib/python3.11/site-packages"
    });
    let dist = site.join("typing_extensions-4.12.2.dist-info");
    std::fs::create_dir_all(&dist).unwrap();
    std::fs::write(
        dist.join("METADATA"),
        "Metadata-Version: 2.1\nName: typing_extensions\nVersion: 4.12.2\n",
    )
    .unwrap();
    std::fs::write(site.join("typing_extensions.py"), "\n").unwrap();
    (tmp, root)
}

/// `scan --json` through the hermetic test environment, with
/// `VIRTUAL_ENV` at the fixture venv.
fn scan(root: &Path, server: &MockServer, extra: &[&str]) -> (i32, Value) {
    let uri = server.uri();
    let mut cmd = hermetic::binary_command();
    cmd.args([
        "scan",
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
    .args(extra)
    .arg("--cwd")
    .arg(root)
    .current_dir(root);
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("VIRTUAL_ENV", root.join("../venv"));
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

fn filtered_reasons(env: &Value) -> Vec<String> {
    env["policy"]["filtered"]
        .as_array()
        .map(|f| {
            f.iter()
                .filter(|e| e["purl"] == PURL)
                .filter_map(|e| e["reason"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn requirements(root: &Path) -> String {
    std::fs::read_to_string(root.join("requirements.txt")).unwrap()
}

/// Control: the canonical spelling was always honored.
#[tokio::test]
async fn hosted_ignore_packages_canonical_spelling_excludes() {
    let server = api().await;
    let (_tmp, root) = project(Some(
        "version: 2\npatches:\n  ignorePackages: [\"typing-extensions\"]\n",
    ));
    let (code, env) = scan(&root, &server, &["--mode", "hosted"]);
    assert_eq!(code, 0, "{env:#}");
    assert_eq!(
        filtered_reasons(&env),
        ["policy_package_ignored"],
        "{env:#}"
    );
    assert_eq!(requirements(&root), REQUIREMENTS);
}

/// #910: every PEP 503-equivalent spelling excludes the package.
#[tokio::test]
async fn hosted_ignore_packages_matches_pep503_spellings() {
    let server = api().await;
    for spec in [
        "typing_extensions",
        "Typing_Extensions",
        "typing.extensions",
        "pkg:pypi/typing_extensions",
    ] {
        let (_tmp, root) = project(Some(&format!(
            "version: 2\npatches:\n  ignorePackages: [\"{spec}\"]\n"
        )));
        let (code, env) = scan(&root, &server, &["--mode", "hosted"]);
        assert_eq!(code, 0, "{spec}: {env:#}");
        assert_eq!(
            filtered_reasons(&env),
            ["policy_package_ignored"],
            "{spec} must exclude {PURL}: {env:#}"
        );
        assert_eq!(
            requirements(&root),
            REQUIREMENTS,
            "{spec}: requirements.txt must stay untouched"
        );
    }
}

/// #910: the agent-mode policy evaluation drops the ignored package too.
#[tokio::test]
async fn agent_ignore_packages_matches_pep503_spelling() {
    let server = api().await;
    let (_tmp, root) = project(Some(
        "version: 2\npatches:\n  ignorePackages: [\"typing_extensions\"]\n",
    ));
    let (code, env) = scan(&root, &server, &["--mode", "agent", "--dry-run"]);
    assert_eq!(code, 0, "{env:#}");
    assert_eq!(
        filtered_reasons(&env),
        ["policy_package_ignored"],
        "{env:#}"
    );
}

/// #910: the `packages` allowlist admits a PEP 503-equivalent spelling.
#[tokio::test]
async fn hosted_packages_allowlist_matches_pep503_spelling() {
    let server = api().await;
    let (_tmp, root) = project(Some(
        "version: 2\npatches:\n  packages: [\"typing_extensions\"]\n",
    ));
    let (code, env) = scan(&root, &server, &["--mode", "hosted"]);
    assert_eq!(code, 0, "{env:#}");
    assert!(filtered_reasons(&env).is_empty(), "{env:#}");
    assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
    assert!(
        requirements(&root).contains(UUID),
        "{}",
        requirements(&root)
    );
}

/// #910: `scan --package` selects a PEP 503-equivalent spelling.
#[tokio::test]
async fn hosted_scan_package_flag_matches_pep503_spelling() {
    let server = api().await;
    let (_tmp, root) = project(None);
    let (code, env) = scan(
        &root,
        &server,
        &["--mode", "hosted", "--package", "typing_extensions"],
    );
    assert_eq!(code, 0, "{env:#}");
    assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
    assert!(
        requirements(&root).contains(UUID),
        "{}",
        requirements(&root)
    );
}
