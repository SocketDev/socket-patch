//! v5 WS2 eject from a FRESH hosted checkout: only the committed manifests
//! and lockfiles exist — no `node_modules`, no Cargo home, no `.socket/`.
//!
//! The eject is lockfile-only by contract: it restores each hosted pin's
//! upstream registry metadata for reversal, then downloads the prebuilt
//! patched artifact. Every registry and API endpoint is a wiremock.

#[path = "common/hermetic.rs"]
mod hermetic;
#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::io::Write as _;
use std::path::Path;
use std::process::Command;

use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";

/// A tar.gz with every file under a single `{prefix}/` top-level dir (an
/// npm tarball uses `package/`, a `.crate` uses `{name}-{version}/`).
fn tgz(prefix: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (rel, content) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, format!("{prefix}/{rel}"), *content)
            .unwrap();
    }
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&builder.into_inner().unwrap()).unwrap();
    enc.finish().unwrap()
}

async fn mock_view(
    server: &MockServer,
    uuid: &str,
    purl: &str,
    file: &str,
    orig: &[u8],
    patched: &[u8],
) {
    let archive_view = json!({
        "uuid": uuid,
        "purl": purl,
        "publishedAt": "2026-01-01T00:00:00Z",
        "files": {
            file: {
                "beforeHash": compute_git_sha256_from_bytes(orig),
                "afterHash": compute_git_sha256_from_bytes(patched),
                "blobContent": base64::engine::general_purpose::STANDARD.encode(patched)
            }
        },
        "vulnerabilities": {},
        "description": "eject fixture",
        "license": "MIT",
        "tier": "free"
    });
    prebuilt_common::mount_view(server, &archive_view, None).await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(archive_view))
        .mount(server)
        .await;
}

/// Run the binary in the hermetic `SOCKET_*` environment, with an empty
/// `CARGO_HOME`, and the API / registries / patch origin on `server`.
fn run_json(root: &Path, server: &MockServer, args: &[&str]) -> (i32, Value) {
    run_json_with(root, server, args, &[])
}

fn run_json_with(
    root: &Path,
    server: &MockServer,
    args: &[&str],
    extra: &[(&str, String)],
) -> (i32, Value) {
    let mut cmd = command(root, server, extra);
    let out = cmd
        .args(args)
        .arg("--json")
        .arg("--cwd")
        .arg(root)
        .output()
        .expect("spawn socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let env = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "--json must emit an envelope: {e}\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out.status.code().unwrap_or(-1), env)
}

/// The binary in `root` (the caller adds the args, then `--cwd`), in the
/// hermetic `SOCKET_*` environment, with an empty `CARGO_HOME` and the
/// API / registries / patch origin on `server`.
fn command(root: &Path, server: &MockServer, extra: &[(&str, String)]) -> Command {
    let cargo_home = root.join("../cargo-home");
    std::fs::create_dir_all(&cargo_home).unwrap();
    let mut cmd = hermetic::binary_command();
    cmd.current_dir(root);
    let uri = server.uri();
    cmd.env("SOCKET_API_URL", &uri)
        .env("SOCKET_API_TOKEN", "fake-token")
        .env("SOCKET_ORG_SLUG", ORG)
        .env("SOCKET_NPM_REGISTRY", &uri)
        .env("SOCKET_CRATES_INDEX", format!("{uri}/index"))
        .env("SOCKET_CRATES_REGISTRY", format!("{uri}/crates"))
        .env("SOCKET_PATCH_SERVER_URL", &uri)
        .env("SOCKET_VENDOR_SOURCE", "service")
        .env("CARGO_HOME", &cargo_home)
        .envs(extra.iter().map(|(k, v)| (*k, v.as_str())));
    cmd
}

fn applied(env: &Value, purl: &str) -> bool {
    env["events"].as_array().is_some_and(|events| {
        events
            .iter()
            .any(|e| e["action"] == "applied" && e["purl"] == purl)
    })
}

/// npm: a hosted package-lock.json with NO `node_modules`.
#[tokio::test]
async fn npm_eject_needs_no_installed_tree() {
    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const PURL: &str = "pkg:npm/left-pad@1.3.0";
    const ORIG: &[u8] = b"module.exports = () => 'orig';\n";
    const PATCHED: &[u8] = b"module.exports = () => 'patched';\n";
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("proj");
    std::fs::create_dir_all(&root).unwrap();

    let tarball = tgz(
        "package",
        &[
            ("package.json", br#"{"name":"left-pad","version":"1.3.0"}"#),
            ("index.js", ORIG),
        ],
    );
    let integrity = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&tarball))
    );
    let upstream = format!("{}/left-pad/-/left-pad-1.3.0.tgz", server.uri());
    Mock::given(method("GET"))
        .and(path("/left-pad/1.3.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "left-pad",
            "version": "1.3.0",
            "dist": { "tarball": upstream, "integrity": integrity }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/left-pad/-/left-pad-1.3.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball))
        .mount(&server)
        .await;
    mock_view(&server, UUID, PURL, "package/index.js", ORIG, PATCHED).await;

    std::fs::write(
        root.join("package.json"),
        br#"{"name":"fixture","version":"1.0.0","private":true,"dependencies":{"left-pad":"1.3.0"}}"#,
    )
    .unwrap();
    let hosted = format!(
        "{}/patch/npm/left-pad/1.3.0/55555555-5555-4555-8555-555555555555/{UUID}/left-pad-1.3.0.tgz",
        server.uri()
    );
    let lock = json!({
        "name": "fixture", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
        "packages": {
            "": { "name": "fixture", "version": "1.0.0", "dependencies": { "left-pad": "1.3.0" } },
            "node_modules/left-pad": {
                "version": "1.3.0", "resolved": hosted,
                "integrity": "sha512-HOSTEDpatchedHOSTEDpatched==", "license": "WTFPL"
            }
        }
    });
    std::fs::write(
        root.join("package-lock.json"),
        serde_json::to_string_pretty(&lock).unwrap() + "\n",
    )
    .unwrap();
    assert!(!root.join("node_modules").exists());

    let (code, env) = run_json(&root, &server, &["vendor"]);
    assert_eq!(code, 0, "a fresh hosted checkout ejects: {env:#}");
    assert!(applied(&env, PURL), "{env:#}");
    let artifact = root.join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"));
    assert!(artifact.is_file(), "the artifact lands in .socket/vendor/");
    let lock = std::fs::read_to_string(root.join("package-lock.json")).unwrap();
    assert!(
        lock.contains(&format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz")),
        "{lock}"
    );
    assert!(!lock.contains(&hosted), "no hosted residue: {lock}");
}

#[tokio::test]
async fn npm_eject_downloads_every_hosted_patch_from_the_lockfile() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("proj");
    std::fs::create_dir(&root).unwrap();
    let patches = [
        ("left-pad", "1.3.0", "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f"),
        ("ms", "2.1.3", "2b1f6c1e-8d3a-4f6b-9c2d-7e5a9b1c3d11"),
    ];
    let mut lock = json!({
        "lockfileVersion": 3,
        "packages": {
            "": { "dependencies": { "left-pad": "1.3.0", "ms": "2.1.3", "unpatched": "1.0.0" } },
            "node_modules/unpatched": { "version": "1.0.0", "resolved": "https://registry.npmjs.org/unpatched/-/unpatched-1.0.0.tgz" }
        }
    });
    let untouched = lock["packages"]["node_modules/unpatched"].clone();
    for (name, version, uuid) in patches {
        let purl = format!("pkg:npm/{name}@{version}");
        mock_view(
            &server,
            uuid,
            &purl,
            "package/index.js",
            b"original\n",
            b"patched\n",
        )
        .await;
        Mock::given(method("GET"))
            .and(path(format!("/{name}/{version}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "name": name, "version": version,
                "dist": {
                    "tarball": format!("{}/{name}/-/{name}-{version}.tgz", server.uri()),
                    "integrity": "sha512-UPSTREAMupstreamUPSTREAM=="
                }
            })))
            .mount(&server)
            .await;
        // No upstream tarball endpoint: vendor needs only its metadata
        // for --revert, and downloads the patched service artifact.
        lock["packages"][format!("node_modules/{name}")] = json!({
            "version": version,
            "resolved": format!("{}/patch/npm/{name}/{version}/55555555-5555-4555-8555-555555555555/{uuid}/{name}-{version}.tgz", server.uri()),
            "integrity": "sha512-HOSTEDpatchedHOSTEDpatched=="
        });
    }
    std::fs::write(root.join("package.json"), serde_json::to_vec(&json!({
        "name": "fixture", "version": "1.0.0", "dependencies": lock["packages"][""]["dependencies"]
    })).unwrap()).unwrap();
    std::fs::write(
        root.join("package-lock.json"),
        serde_json::to_vec(&lock).unwrap(),
    )
    .unwrap();

    let (code, env) = run_json(&root, &server, &["vendor"]);
    assert_eq!(code, 0, "{env:#}");
    assert_eq!(env["summary"]["applied"], 2, "{env:#}");
    let lock: Value =
        serde_json::from_slice(&std::fs::read(root.join("package-lock.json")).unwrap()).unwrap();
    let requests = server.received_requests().await.unwrap();
    for (name, version, uuid) in patches {
        assert!(
            applied(&env, &format!("pkg:npm/{name}@{version}")),
            "{env:#}"
        );
        let relative = format!(".socket/vendor/npm/{uuid}/{name}-{version}.tgz");
        let bytes = std::fs::read(root.join(&relative)).unwrap();
        let entry = &lock["packages"][format!("node_modules/{name}")];
        assert_eq!(entry["resolved"], format!("file:{relative}"));
        assert_eq!(
            entry["integrity"],
            format!(
                "sha512-{}",
                base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&bytes))
            )
        );
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(bytes.as_slice()));
        let mut patched = archive
            .entries()
            .unwrap()
            .map(Result::unwrap)
            .find(|file| file.path().unwrap() == Path::new("package/index.js"))
            .unwrap();
        let mut content = Vec::new();
        std::io::Read::read_to_end(&mut patched, &mut content).unwrap();
        assert_eq!(content, b"patched\n");
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.url.path() == format!("/v0/orgs/{ORG}/patches/view/{uuid}"))
                .count(),
            1
        );
        assert!(!requests
            .iter()
            .any(|r| r.url.path() == format!("/{name}/-/{name}-{version}.tgz")));
    }
    assert_eq!(lock["packages"]["node_modules/unpatched"], untouched);
    assert!(!root.join("node_modules").exists());
    assert!(!root.join(".socket/manifest.json").exists());
}

/// cargo: the hosted `Cargo.lock` / `Cargo.toml` pin with an EMPTY Cargo
/// home. The restore re-resolves the crates.io checksum from the sparse
/// index for reversal; the service supplies the patched crate.
#[tokio::test]
async fn cargo_eject_needs_no_cargo_home() {
    const UUID: &str = "55555555-5555-5555-5555-555555555555";
    const TOKEN: &str = "11111111-1111-1111-1111-111111111111";
    const PURL: &str = "pkg:cargo/serde@1.0.190";
    const ORIG: &[u8] = b"pub fn serde() {}\n";
    const PATCHED: &[u8] = b"pub fn serde() { /* patched */ }\n";
    const TOML: &[u8] = b"[package]\nname = \"serde\"\nversion = \"1.0.190\"\n";
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("proj");
    std::fs::create_dir_all(&root).unwrap();

    let krate = tgz(
        "serde-1.0.190",
        &[("Cargo.toml", TOML), ("src/lib.rs", ORIG)],
    );
    let checksum = hex::encode(Sha256::digest(&krate));
    Mock::given(method("GET"))
        .and(path("/index/se/rd/serde"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            json!({"name": "serde", "vers": "1.0.190", "cksum": checksum}).to_string(),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/crates/serde/serde-1.0.190.crate"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(krate))
        .mount(&server)
        .await;
    mock_view(&server, UUID, PURL, "package/src/lib.rs", ORIG, PATCHED).await;

    // What `scan --mode hosted` leaves behind (the redirect golden
    // `cargo/cargo/basic/expected`, minus the unrelated anyhow dep).
    std::fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"myapp\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [dependencies]\nserde = {{ version = \"1.0.190\", registry = \"socket-patch-{UUID}\" }}\n"
        ),
    )
    .unwrap();
    let index =
        format!("sparse+https://patch.socket.dev/patch-registry/cargo/{TOKEN}/{UUID}/index/");
    std::fs::write(
        root.join("Cargo.lock"),
        format!(
            "version = 3\n\n[[package]]\nname = \"myapp\"\nversion = \"0.1.0\"\n\
             dependencies = [\n \"serde\",\n]\n\n[[package]]\nname = \"serde\"\n\
             version = \"1.0.190\"\nsource = \"{index}\"\nchecksum = \"{}\"\n",
            "de".repeat(32)
        ),
    )
    .unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();

    let (code, env) = run_json(&root, &server, &["vendor"]);
    assert_eq!(code, 0, "a fresh hosted cargo checkout ejects: {env:#}");
    assert!(applied(&env, PURL), "{env:#}");
    let toml = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let lock = std::fs::read_to_string(root.join("Cargo.lock")).unwrap();
    assert!(
        !toml.contains("socket-patch-"),
        "hosted registry key removed: {toml}"
    );
    assert!(
        !lock.contains("patch.socket.dev"),
        "no hosted residue: {lock}"
    );
    assert!(
        std::fs::read_dir(root.join(".socket/vendor/cargo"))
            .map(|mut d| d.next().is_some())
            .unwrap_or(false),
        "the crate is vendored under .socket/vendor/cargo"
    );
}

/// A pure-Python wheel: the unzipped layout is site-packages.
fn wheel(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    for (name, content) in files {
        zip.start_file(*name, opts).unwrap();
        zip.write_all(content).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

/// pypi: a hash-pinned hosted `requirements.txt` with NO virtualenv. The
/// restore re-resolves the release file hash from the PyPI JSON API for
/// reversal; the service supplies the patched wheel.
#[tokio::test]
async fn pypi_eject_needs_no_virtualenv() {
    pypi_eject_with_virtualenv(false).await;
}

/// An unrelated environment must not select or reject a patch already
/// identified by the project's lockfile, even if it has the same release.
#[tokio::test]
async fn pypi_eject_ignores_unrelated_virtualenv() {
    pypi_eject_with_virtualenv(true).await;
}

async fn pypi_eject_with_virtualenv(unrelated_install: bool) {
    const UUID: &str = "2b1f6c1e-8d3a-4f6b-9c2d-7e5a9b1c3d11";
    const PURL: &str = "pkg:pypi/six@1.16.0";
    const WHEEL: &str = "six-1.16.0-py2.py3-none-any.whl";
    const ORIG: &[u8] = b"# six\nVERSION = '1.16.0'\n";
    const PATCHED: &[u8] = b"# six\nVERSION = '1.16.0'\nSAFE = True\n";
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("proj");
    std::fs::create_dir_all(&root).unwrap();

    let whl = wheel(&[
        ("six.py", ORIG),
        (
            "six-1.16.0.dist-info/METADATA",
            b"Metadata-Version: 2.1\nName: six\nVersion: 1.16.0\n\nbody\n",
        ),
        (
            "six-1.16.0.dist-info/WHEEL",
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py2-none-any\nTag: py3-none-any\n",
        ),
        (
            "six-1.16.0.dist-info/RECORD",
            b"six.py,,\nsix-1.16.0.dist-info/METADATA,,\nsix-1.16.0.dist-info/WHEEL,,\nsix-1.16.0.dist-info/RECORD,,\n",
        ),
    ]);
    let sha = hex::encode(Sha256::digest(&whl));
    let size = whl.len();
    Mock::given(method("GET"))
        .and(path("/pypi/six/1.16.0/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "urls": [{
                "filename": WHEEL,
                "url": format!("{}/files/{WHEEL}", server.uri()),
                "digests": { "sha256": sha },
                "size": size,
                "upload_time_iso_8601": "2021-05-05T14:18:17.000000Z"
            }]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/files/{WHEEL}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(whl))
        .mount(&server)
        .await;
    mock_view(&server, UUID, PURL, "six.py", ORIG, PATCHED).await;

    let hosted = format!(
        "https://patch.socket.dev/patch/pypi/six/1.16.0/11111111-1111-1111-1111-111111111111/{UUID}/{WHEEL}"
    );
    std::fs::write(
        root.join("requirements.txt"),
        // An unpatched hash-pinned sibling: it makes pip's hash-checking
        // mode derivable, so the hosted line can be restored as `==` + hash.
        format!(
            "flask==2.0.1 --hash=sha256:{}\nsix @ {hosted} --hash=sha256:{}\n",
            "cd".repeat(32),
            "ab".repeat(32)
        ),
    )
    .unwrap();

    // Nothing is installed in the project. An ambient VIRTUAL_ENV may
    // belong to another project and contain unrelated bytes for six.
    let venv = tmp.path().join("ambient-venv");
    let site = venv.join(if cfg!(windows) {
        "Lib/site-packages"
    } else {
        "lib/python3.11/site-packages"
    });
    std::fs::create_dir_all(&site).unwrap();
    if unrelated_install {
        let metadata = site.join("six-1.16.0.dist-info");
        std::fs::create_dir(&metadata).unwrap();
        std::fs::write(metadata.join("METADATA"), "Name: six\nVersion: 1.16.0\n").unwrap();
        std::fs::write(site.join("six.py"), b"# unrelated installation\n").unwrap();
    }
    let (code, env) = run_json_with(
        &root,
        &server,
        &["vendor"],
        &[
            ("SOCKET_PYPI_JSON_API", format!("{}/pypi", server.uri())),
            ("VIRTUAL_ENV", venv.display().to_string()),
        ],
    );
    assert_eq!(code, 0, "a fresh hosted pypi checkout ejects: {env:#}");
    assert!(applied(&env, PURL), "{env:#}");
    if unrelated_install {
        assert_eq!(
            std::fs::read(site.join("six.py")).unwrap(),
            b"# unrelated installation\n"
        );
    }
    let reqs = std::fs::read_to_string(root.join("requirements.txt")).unwrap();
    assert!(
        !reqs.contains("patch.socket.dev"),
        "no hosted residue: {reqs}"
    );
    assert!(
        reqs.contains(&format!(".socket/vendor/pypi/{UUID}/")),
        "the requirement is wired to the vendored wheel: {reqs}"
    );
}

/// #1005: an eject where one package vendors and another fails is rolled
/// back whole, and the report says so. The human run prints the
/// `eject_rolled_back` warning, never "Vendored 1 package" or the advice to
/// commit `.socket/vendor/`; the JSON envelope does not count the
/// rolled-back package as applied.
#[tokio::test]
async fn rolled_back_eject_reports_nothing_vendored() {
    const LEFT_PAD_UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const MS_UUID: &str = "7a1e3c5b-2d4f-4a6b-9c8d-0e1f2a3b4c5d";
    const LEFT_PAD: &str = "pkg:npm/left-pad@1.3.0";
    const MS: &str = "pkg:npm/ms@2.1.3";
    const ORIG: &[u8] = b"module.exports = () => 'orig';\n";
    const PATCHED: &[u8] = b"module.exports = () => 'patched';\n";
    let server = MockServer::start().await;
    let uri = server.uri();

    // left-pad vendors: packument, pristine tarball and service artifact.
    let tarball = tgz(
        "package",
        &[
            ("package.json", br#"{"name":"left-pad","version":"1.3.0"}"#),
            ("index.js", ORIG),
        ],
    );
    let integrity = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&tarball))
    );
    Mock::given(method("GET"))
        .and(path("/left-pad/1.3.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "left-pad",
            "version": "1.3.0",
            "dist": { "tarball": format!("{uri}/left-pad/-/left-pad-1.3.0.tgz"), "integrity": integrity }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/left-pad/-/left-pad-1.3.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball))
        .mount(&server)
        .await;
    mock_view(
        &server,
        LEFT_PAD_UUID,
        LEFT_PAD,
        "package/index.js",
        ORIG,
        PATCHED,
    )
    .await;

    // ms restores upstream (its packument resolves) but cannot vendor: its
    // record has no service artifact and its pristine tarball is a 500.
    Mock::given(method("GET"))
        .and(path("/ms/2.1.3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "ms",
            "version": "2.1.3",
            "dist": {
                "tarball": format!("{uri}/ms/-/ms-2.1.3.tgz"),
                "integrity": "sha512-msUPSTREAMmsUPSTREAM=="
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/ms/-/ms-2.1.3.tgz"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{MS_UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uuid": MS_UUID,
            "purl": MS,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": compute_git_sha256_from_bytes(ORIG),
                    "afterHash": compute_git_sha256_from_bytes(PATCHED)
                }
            },
            "vulnerabilities": {},
            "description": "eject fixture",
            "license": "MIT",
            "tier": "free"
        })))
        .mount(&server)
        .await;

    let hosted = |name: &str, uuid: &str, version: &str| {
        format!(
            "{uri}/patch/npm/{name}/{version}/55555555-5555-4555-8555-555555555555/{uuid}/{name}-{version}.tgz"
        )
    };
    let lock = serde_json::to_string_pretty(&json!({
        "name": "fixture", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
        "packages": {
            "": {
                "name": "fixture", "version": "1.0.0",
                "dependencies": { "left-pad": "1.3.0", "ms": "2.1.3" }
            },
            "node_modules/left-pad": {
                "version": "1.3.0", "resolved": hosted("left-pad", LEFT_PAD_UUID, "1.3.0"),
                "integrity": "sha512-HOSTEDpatchedHOSTEDpatched==", "license": "WTFPL"
            },
            "node_modules/ms": {
                "version": "2.1.3", "resolved": hosted("ms", MS_UUID, "2.1.3"),
                "integrity": "sha512-HOSTEDmsHOSTEDms==", "license": "MIT"
            }
        }
    }))
    .unwrap()
        + "\n";
    let tmp = tempfile::tempdir().unwrap();
    let fresh = |name: &str| {
        let root = tmp.path().join(name);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("package.json"),
            br#"{"name":"fixture","version":"1.0.0","private":true,"dependencies":{"left-pad":"1.3.0","ms":"2.1.3"}}"#,
        )
        .unwrap();
        std::fs::write(root.join("package-lock.json"), &lock).unwrap();
        root
    };
    let still_hosted = |root: &Path| {
        assert_eq!(
            std::fs::read_to_string(root.join("package-lock.json")).unwrap(),
            lock,
            "the eject is rolled back"
        );
        assert!(
            std::fs::read_dir(root.join(".socket/vendor"))
                .map(|mut d| d.next().is_none())
                .unwrap_or(true),
            "no vendored residue"
        );
    };

    let root = fresh("json");
    let (code, env) = run_json(&root, &server, &["vendor"]);
    assert_eq!(code, 1, "{env:#}");
    still_hosted(&root);
    assert!(
        env["warnings"]
            .as_array()
            .is_some_and(|w| w.iter().any(|w| w["code"] == "eject_rolled_back")),
        "{env:#}"
    );
    assert!(
        !applied(&env, LEFT_PAD),
        "rolled back, not applied: {env:#}"
    );
    assert_eq!(env["summary"]["applied"], 0, "{env:#}");
    assert!(
        env["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["purl"] == LEFT_PAD
                && e["action"] == "skipped"
                && e["errorCode"] == "eject_rolled_back"),
        "{env:#}"
    );
    assert!(
        env["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["purl"] == MS && e["action"] == "failed"),
        "{env:#}"
    );

    let root = fresh("human");
    let out = command(&root, &server, &[])
        .args(["vendor", "--cwd"])
        .arg(&root)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stdout}\n{stderr}");
    still_hosted(&root);
    assert!(
        stderr.contains("the project is still hosted, exactly as before"),
        "the rollback is announced: {stdout}\n{stderr}"
    );
    assert!(
        !stdout.contains("Vendored") && !stdout.contains("Next steps"),
        "nothing was vendored: {stdout}\n{stderr}"
    );
}
