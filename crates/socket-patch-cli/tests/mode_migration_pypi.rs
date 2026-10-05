//! PyPI vendored → hosted mode takeover (#328): `scan --mode hosted` over a
//! project socket-patch itself vendored must revert its own vendored wiring
//! (the per-purl `vendor --revert` machinery) and then redirect, leaving the
//! project FULLY hosted. Before the fix the takeover gate admitted only
//! cargo / npm / golang purls, so every PyPI hosted rewriter saw the
//! vendored source socket-patch wrote as a user-authored one and refused it
//! (`redirected: 0`, exit 0, the project left vendored).
//!
//! One lane per Python lock socket-patch vendors — requirements.txt,
//! Poetry, Pipenv, uv and Hatch. Hermetic: the vendored wheel is built
//! from the staged manifest by the prebuilt fixture server, and the hosted
//! API + hosted wheel are a wiremock.

#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::io::Write as _;
use std::path::Path;
use std::process::Command;

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

/// Stage `.socket/manifest.json` + the after-hash blob so `vendor` builds
/// the vendored wheel from the prebuilt fixture server, offline.
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
        "description": "pypi mode takeover fixture",
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

/// The built binary with every ambient `SOCKET_*` var scrubbed. An EMPTY
/// `VIRTUAL_ENV` keeps the installed-tree probes off the host's Python
/// (Ubuntu's apt ships a python3-six 1.16.0 whose bytes are not ours).
fn run_cli(root: &Path, args: &[&str], extra: &[(&str, &str)]) -> (i32, Value) {
    let mut json_args = args.to_vec();
    json_args.push("--json");
    let (code, stdout, stderr) = run_raw(root, &json_args, extra);
    let env = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("--json must emit an envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    (code, env)
}

/// [`run_cli`] without `--json`: `(exit code, stdout, stderr)`.
fn run_raw(root: &Path, args: &[&str], extra: &[(&str, &str)]) -> (i32, String, String) {
    let venv = root.join("../empty-venv");
    std::fs::create_dir_all(venv.join(if cfg!(windows) {
        "Lib/site-packages"
    } else {
        "lib/python3.11/site-packages"
    }))
    .unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    cmd.args(args).arg("--cwd").arg(root).current_dir(root);
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") {
            cmd.env_remove(key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("VIRTUAL_ENV", &venv)
        .env("PIPENV_IGNORE_VIRTUALENVS", "0")
        .envs(extra.iter().copied());
    let fixture = (args.first() == Some(&"vendor")).then(|| {
        let server = prebuilt_common::Server::project(root);
        server.command(&mut cmd);
        server
    });
    let out = cmd.output().expect("spawn socket-patch");
    drop(fixture);
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The hosted API: discovery (`batch` / `by-package`), the grant naming the
/// hosted wheel, and the wheel itself (its METADATA feeds the lock
/// rewriters) — or, with `wheel_served: false`, a 404 for it. Returns the
/// hosted URL.
async fn mount_hosted_api(server: &MockServer, wheel_served: bool) -> String {
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
    let wheel_response = if wheel_served {
        ResponseTemplate::new(200).set_body_bytes(wheel)
    } else {
        ResponseTemplate::new(404)
    };
    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(wheel_response)
        .mount(server)
        .await;
    hosted_url
}

/// Stage the manifest and vendor the project; `files` carry the wiring.
fn vendor_project(root: &Path, files: &[&str]) {
    stage_manifest(root);
    let (code, env) = run_cli(root, &["vendor"], &[]);
    assert_eq!(code, 0, "vendor: {env:#}");
    let vendored: Vec<String> = files
        .iter()
        .map(|f| std::fs::read_to_string(root.join(f)).unwrap())
        .collect();
    assert!(
        vendored
            .iter()
            .any(|t| t.contains(&format!(".socket/vendor/pypi/{UUID}/"))),
        "vendored first: {vendored:#?}"
    );
}

/// `scan --mode hosted` against `server`.
fn hosted_scan(root: &Path, server: &MockServer) -> (i32, Value) {
    let uri = server.uri();
    run_cli(root, &hosted_scan_args(&uri), &[])
}

fn hosted_scan_args(uri: &str) -> Vec<&str> {
    vec![
        "scan",
        "--mode",
        "hosted",
        "--yes",
        "--api-url",
        uri,
        "--org",
        ORG,
        "--api-token",
        "fake-token",
        "--patch-server-url",
        uri,
    ]
}

/// Vendor the staged project, then `scan --mode hosted` over it: the
/// takeover must report `redirect_takeover_reverted_vendored`, redirect the
/// purl, and leave every wiring file hosted with no `.socket/vendor/`
/// reference or artifact behind. `files` are the project files that carry
/// the wiring.
async fn assert_vendored_to_hosted(root: &Path, files: &[&str]) {
    vendor_project(root, files);
    let server = MockServer::start().await;
    let hosted_url = mount_hosted_api(&server, true).await;
    let (code, env) = hosted_scan(root, &server);
    assert_eq!(code, 0, "hosted scan over the vendored project: {env:#}");
    assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
    assert!(
        env.to_string()
            .contains("redirect_takeover_reverted_vendored"),
        "the takeover is surfaced: {env:#}"
    );
    let mut hosted_seen = false;
    for f in files {
        let text = std::fs::read_to_string(root.join(f)).unwrap();
        assert!(
            !text.contains(".socket/vendor/"),
            "{f}: no vendored residue after the takeover:\n{text}"
        );
        hosted_seen |= text.contains(&hosted_url);
    }
    assert!(hosted_seen, "the hosted wheel is wired into {files:?}");
    assert!(
        !root.join(format!(".socket/vendor/pypi/{UUID}")).exists(),
        "the vendored artifact is reclaimed"
    );
}

fn project() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("proj");
    std::fs::create_dir_all(&root).unwrap();
    (tmp, root)
}

const POETRY_LOCK: &str = r#"# This file is automatically @generated by Poetry 2.4.1 and should not be changed by hand.

[[package]]
name = "six"
version = "1.16.0"
description = "Python 2 and 3 compatibility utilities"
optional = false
python-versions = ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*"
groups = ["main"]
files = [
    {file = "six-1.16.0-py2.py3-none-any.whl", hash = "sha256:WHEEL_SHA"},
    {file = "six-1.16.0.tar.gz", hash = "sha256:SDIST_SHA"},
]

[metadata]
lock-version = "2.1"
python-versions = ">=3.9"
content-hash = "4b42a89b7ff7b26511b06acdc458dbd85312e5083db8f212b017482bc68cdd01"
"#;

#[tokio::test]
async fn requirements_vendored_to_hosted() {
    let (_tmp, root) = project();
    std::fs::write(root.join("requirements.txt"), "idna==3.7\nsix==1.16.0\n").unwrap();
    assert_vendored_to_hosted(&root, &["requirements.txt"]).await;
}

#[tokio::test]
async fn requirements_sole_pin_vendored_to_hosted() {
    let (_tmp, root) = project();
    std::fs::write(root.join("requirements.txt"), "six==1.16.0\n").unwrap();
    assert_vendored_to_hosted(&root, &["requirements.txt"]).await;
}

#[tokio::test]
async fn poetry_vendored_to_hosted() {
    let (_tmp, root) = project();
    std::fs::write(
        root.join("pyproject.toml"),
        "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\ndescription = \"\"\nauthors = [\"x <x@x>\"]\npackage-mode = false\n\n[tool.poetry.dependencies]\npython = \">=3.9\"\nsix = \"1.16.0\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("poetry.lock"),
        POETRY_LOCK
            .replace("WHEEL_SHA", WHEEL_SHA)
            .replace("SDIST_SHA", SDIST_SHA),
    )
    .unwrap();
    assert_vendored_to_hosted(&root, &["poetry.lock", "pyproject.toml"]).await;
}

const PIPFILE: &str = "[[source]]\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\nname = \"pypi\"\n\n[packages]\nsix = \"==1.16.0\"\n\n[requires]\npython_version = \"3.11\"\n";

#[tokio::test]
async fn pipenv_vendored_to_hosted() {
    let (_tmp, root) = project();
    std::fs::write(root.join("Pipfile"), PIPFILE).unwrap();
    let lock = json!({
        "_meta": {
            "hash": { "sha256": "ab".repeat(32) },
            "pipfile-spec": 6,
            "requires": { "python_version": "3.11" },
            "sources": [{ "name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": true }]
        },
        "default": {
            "six": {
                "hashes": [format!("sha256:{WHEEL_SHA}"), format!("sha256:{SDIST_SHA}")],
                "index": "pypi",
                "markers": "python_version >= '2.7' and python_version not in '3.0, 3.1, 3.2'",
                "version": "==1.16.0"
            }
        },
        "develop": {}
    });
    let mut text = serde_json::to_string_pretty(&lock).unwrap();
    text.push('\n');
    std::fs::write(root.join("Pipfile.lock"), text).unwrap();
    assert_vendored_to_hosted(&root, &["Pipfile.lock"]).await;
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
sdist = { url = "https://files.pythonhosted.org/packages/71/39/171f1c67cd00715f190ba0b100d606d440a28c93c7714febeca8b79af85e/six-1.16.0.tar.gz", hash = "sha256:SDIST_SHA", size = 34041, upload-time = "2021-05-05T14:18:18.379Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/d9/5a/e7c31adbe875f2abbb91bd84cf2dc52d792b5a01506781dbcf25c91daf11/six-1.16.0-py2.py3-none-any.whl", hash = "sha256:WHEEL_SHA", size = 11053, upload-time = "2021-05-05T14:18:17.237Z" },
]
"#;

#[tokio::test]
async fn uv_vendored_to_hosted() {
    let (_tmp, root) = project();
    std::fs::write(
        root.join("pyproject.toml"),
        "[project]\nname = \"demo\"\nversion = \"0.1.0\"\nrequires-python = \">=3.9\"\ndependencies = [\"six==1.16.0\"]\n",
    )
    .unwrap();
    std::fs::write(
        root.join("uv.lock"),
        UV_LOCK
            .replace("WHEEL_SHA", WHEEL_SHA)
            .replace("SDIST_SHA", SDIST_SHA),
    )
    .unwrap();
    assert_vendored_to_hosted(&root, &["uv.lock", "pyproject.toml"]).await;
}

#[tokio::test]
async fn hatch_vendored_to_hosted() {
    let (_tmp, root) = project();
    std::fs::write(
        root.join("pyproject.toml"),
        "[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n\n[project]\nname = \"demo\"\nversion = \"0.1.0\"\ndependencies = [\"six==1.16.0\"]\n",
    )
    .unwrap();
    assert_vendored_to_hosted(&root, &["pyproject.toml"]).await;
}

/// The uv lock rewrite needs the hosted wheel's METADATA, fetched only
/// after the takeover reverted the vendored wiring. When it is unavailable
/// the package is left on the unpatched registry release in both modes, so
/// the run must fail loudly instead of reporting success.
/// A vendored uv project whose hosted wheel the API cannot serve.
async fn stranded_uv_project() -> (tempfile::TempDir, std::path::PathBuf, MockServer) {
    let (tmp, root) = project();
    std::fs::write(
        root.join("pyproject.toml"),
        "[project]\nname = \"demo\"\nversion = \"0.1.0\"\nrequires-python = \">=3.9\"\ndependencies = [\"six==1.16.0\"]\n",
    )
    .unwrap();
    std::fs::write(
        root.join("uv.lock"),
        UV_LOCK
            .replace("WHEEL_SHA", WHEEL_SHA)
            .replace("SDIST_SHA", SDIST_SHA),
    )
    .unwrap();
    vendor_project(&root, &["uv.lock"]);
    let server = MockServer::start().await;
    mount_hosted_api(&server, false).await;
    (tmp, root, server)
}

#[tokio::test]
async fn uv_takeover_without_wheel_metadata_fails_loudly() {
    let (_tmp, root, server) = stranded_uv_project().await;
    let (code, env) = hosted_scan(&root, &server);
    assert_eq!(code, 1, "a stranded takeover is a failure: {env:#}");
    assert_eq!(env["status"], "partial_failure", "{env:#}");
    assert_eq!(env["redirect"]["redirected"], 0, "{env:#}");
    assert!(
        env.to_string().contains("redirect_takeover_unpatched"),
        "the unpatched package is named: {env:#}"
    );
}

/// A vendored requirements line edited since vendoring is left in place by
/// the revert (the artifact and ledger entry are kept). The takeover must
/// then refuse — keeping the ledger — rather than drop the entry and leave
/// the project half vendored with no record of it.
#[tokio::test]
async fn drifted_vendored_line_refuses_takeover() {
    let (_tmp, root) = project();
    std::fs::write(root.join("requirements.txt"), "idna==3.7\nsix==1.16.0\n").unwrap();
    vendor_project(&root, &["requirements.txt"]);
    let reqs = root.join("requirements.txt");
    let vendored = std::fs::read_to_string(&reqs).unwrap();
    let drifted = vendored.replacen(
        &format!("six-1.16.0-py3-none-any.whl"),
        "six-1.16.0-py3-none-any.whl ; python_version >= \"3\"",
        1,
    );
    assert_ne!(drifted, vendored, "the fixture edits the vendored line");
    std::fs::write(&reqs, &drifted).unwrap();
    let state = root.join(".socket/vendor/state.json");
    assert!(state.exists());

    let server = MockServer::start().await;
    mount_hosted_api(&server, true).await;
    let (code, env) = hosted_scan(&root, &server);
    let text = env.to_string();
    assert!(
        !text.contains("redirect_takeover_reverted_vendored"),
        "no takeover is announced over drifted wiring: {env:#}"
    );
    assert!(text.contains("redirect_vendored_revert_failed"), "{env:#}");
    assert_eq!(env["redirect"]["redirected"], 0, "{env:#}");
    assert_eq!(
        code, 0,
        "a refused takeover keeps the package vendored: {env:#}"
    );
    assert!(
        std::fs::read_to_string(&state).unwrap().contains(UUID),
        "the ledger entry is kept"
    );
    assert!(
        root.join(format!(".socket/vendor/pypi/{UUID}")).exists(),
        "the vendored artifact is kept"
    );
}

/// Human output for a stranded takeover: no "Migrated … to hosted" progress
/// line and no "keep the hosted patches" next steps, only the warning.
#[tokio::test]
async fn stranded_takeover_human_output_is_not_a_migration() {
    let (_tmp, root, server) = stranded_uv_project().await;
    let uri = server.uri();
    let (code, stdout, stderr) = run_raw(&root, &hosted_scan_args(&uri), &[]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        !stderr.contains("Migrated pkg:pypi/six@1.16.0"),
        "a stranded package is not reported migrated:\n{stderr}"
    );
    assert!(
        !stdout.contains("keep the hosted patches") && !stdout.contains("Reinstall"),
        "no next steps for a stranded takeover:\n{stdout}"
    );
    assert!(stderr.contains("UNPATCHED"), "{stderr}");
}

/// `--silent` keeps errors: the stranded takeover's exit 1 is explained.
#[tokio::test]
async fn stranded_takeover_is_reported_under_silent() {
    let (_tmp, root, server) = stranded_uv_project().await;
    let uri = server.uri();
    let mut args = hosted_scan_args(&uri);
    args.push("--silent");
    let (code, stdout, stderr) = run_raw(&root, &args, &[]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("UNPATCHED") && stderr.contains("pkg:pypi/six@1.16.0"),
        "the failure is diagnosable under --silent:\n{stderr}"
    );
}

/// `--dry-run` predicts the drifted-wiring refusal instead of previewing a
/// takeover the wet run would refuse.
#[tokio::test]
async fn dry_run_predicts_drifted_takeover_refusal() {
    let (_tmp, root) = project();
    std::fs::write(root.join("requirements.txt"), "idna==3.7\nsix==1.16.0\n").unwrap();
    vendor_project(&root, &["requirements.txt"]);
    let reqs = root.join("requirements.txt");
    let vendored = std::fs::read_to_string(&reqs).unwrap();
    let drifted = vendored.replacen(
        "six-1.16.0-py3-none-any.whl",
        "six-1.16.0-py3-none-any.whl ; python_version >= \"3\"",
        1,
    );
    std::fs::write(&reqs, &drifted).unwrap();

    let server = MockServer::start().await;
    mount_hosted_api(&server, true).await;
    let uri = server.uri();
    let mut args = hosted_scan_args(&uri);
    args.push("--dry-run");
    let (_, env) = run_cli(&root, &args, &[]);
    let text = env.to_string();
    assert!(
        !text.contains("redirect_would_revert_vendored"),
        "no takeover is previewed over drifted wiring: {env:#}"
    );
    assert!(text.contains("redirect_vendored_revert_failed"), "{env:#}");
    assert_eq!(env["redirect"]["redirected"], 0, "{env:#}");
    assert_eq!(
        std::fs::read_to_string(&reqs).unwrap(),
        drifted,
        "dry run writes nothing"
    );
}

/// The revert succeeds but the vendored ledger cannot be updated (a
/// read-only `.socket/vendor/`): the wiring and wheel are already gone,
/// so the package is unpatched in both modes. That is a stranded takeover
/// (exit 1, `partial_failure`, `redirect_takeover_unpatched`), never a
/// success.
#[cfg(unix)]
#[tokio::test]
async fn ledger_update_failure_after_revert_is_stranded() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_tmp, root) = project();
    std::fs::write(root.join("requirements.txt"), "six==1.16.0\n").unwrap();
    vendor_project(&root, &["requirements.txt"]);
    let vendor_dir = root.join(".socket/vendor");
    let set_mode = |mode| {
        std::fs::set_permissions(&vendor_dir, std::fs::Permissions::from_mode(mode)).unwrap()
    };
    set_mode(0o555);
    let probe = vendor_dir.join(".probe");
    if std::fs::write(&probe, b"").is_ok() {
        // Permissions are not enforced (running as root): the ledger write
        // cannot be made to fail this way.
        let _ = std::fs::remove_file(&probe);
        set_mode(0o755);
        eprintln!("skipped: directory permissions are not enforced for this user");
        return;
    }

    let server = MockServer::start().await;
    mount_hosted_api(&server, true).await;
    let (code, env) = hosted_scan(&root, &server);
    set_mode(0o755);
    let text = env.to_string();
    assert!(text.contains("redirect_vendored_revert_failed"), "{env:#}");
    assert!(text.contains("redirect_takeover_unpatched"), "{env:#}");
    assert_eq!(env["status"], "partial_failure", "{env:#}");
    assert_eq!(code, 1, "{env:#}");
}

/// #699: hosted mode rewrites only the ROOT `requirements.txt`, while
/// vendored mode also wires a pin in a `-r` include or appends a managed
/// `(transitive)` line. A vendored → hosted takeover of such a pin used to
/// revert the vendored wiring first and then find no root entry to pin,
/// stranding the package unpatched (exit 1). It must be refused BEFORE the
/// revert — the vendored patch, ledger entry and wheel are kept — and the
/// dry run must predict that refusal instead of a clean takeover.
async fn assert_unreachable_takeover_refused(root: &Path, wired: &str, dry_run: bool) {
    let before = std::fs::read_to_string(root.join(wired)).unwrap();
    let root_before = std::fs::read_to_string(root.join("requirements.txt")).unwrap();
    let state = root.join(".socket/vendor/state.json");
    let server = MockServer::start().await;
    mount_hosted_api(&server, true).await;
    let uri = server.uri();
    let mut args = hosted_scan_args(&uri);
    if dry_run {
        args.push("--dry-run");
    }
    let (code, env) = run_cli(root, &args, &[]);
    let text = env.to_string();
    assert!(
        !text.contains("redirect_would_revert_vendored")
            && !text.contains("redirect_takeover_reverted_vendored"),
        "no takeover over an entry hosted mode cannot pin: {env:#}"
    );
    assert!(
        !text.contains("redirect_takeover_unpatched"),
        "the package is never stranded: {env:#}"
    );
    assert!(
        text.contains("redirect_requirements_takeover_unreachable"),
        "the refusal is named: {env:#}"
    );
    assert_eq!(env["redirect"]["redirected"], 0, "{env:#}");
    assert_eq!(
        code, 0,
        "a refused takeover keeps the package vendored: {env:#}"
    );
    assert_eq!(
        std::fs::read_to_string(root.join(wired)).unwrap(),
        before,
        "{wired}: the vendored line is kept"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("requirements.txt")).unwrap(),
        root_before,
        "requirements.txt is untouched"
    );
    assert!(
        std::fs::read_to_string(&state).unwrap().contains(UUID),
        "the ledger entry is kept"
    );
    assert!(
        root.join(format!(".socket/vendor/pypi/{UUID}")).exists(),
        "the vendored artifact is kept"
    );
}

fn include_project() -> (tempfile::TempDir, std::path::PathBuf) {
    let (tmp, root) = project();
    std::fs::write(root.join("requirements.txt"), "-r base.txt\nidna==3.7\n").unwrap();
    std::fs::write(root.join("base.txt"), "six==1.16.0\n").unwrap();
    vendor_project(&root, &["base.txt"]);
    (tmp, root)
}

fn transitive_project() -> (tempfile::TempDir, std::path::PathBuf) {
    let (tmp, root) = project();
    std::fs::write(root.join("requirements.txt"), "idna==3.7\n").unwrap();
    std::fs::write(root.join("requirements-dev.txt"), "six==1.16.0\n").unwrap();
    vendor_project(&root, &["requirements.txt"]);
    assert!(
        std::fs::read_to_string(root.join("requirements.txt"))
            .unwrap()
            .contains("(transitive)"),
        "vendor appended a managed transitive line"
    );
    (tmp, root)
}

#[tokio::test]
async fn include_pin_takeover_is_refused_before_revert() {
    let (_tmp, root) = include_project();
    assert_unreachable_takeover_refused(&root, "base.txt", false).await;
}

#[tokio::test]
async fn dry_run_predicts_include_pin_takeover_refusal() {
    let (_tmp, root) = include_project();
    assert_unreachable_takeover_refused(&root, "base.txt", true).await;
}

#[tokio::test]
async fn transitive_line_takeover_is_refused_before_revert() {
    let (_tmp, root) = transitive_project();
    assert_unreachable_takeover_refused(&root, "requirements.txt", false).await;
}

#[tokio::test]
async fn dry_run_predicts_transitive_line_takeover_refusal() {
    let (_tmp, root) = transitive_project();
    assert_unreachable_takeover_refused(&root, "requirements.txt", true).await;
}

/// Control for #699: a vendored pin in the root file is still taken over,
/// and the dry run still previews it.
#[tokio::test]
async fn dry_run_previews_root_pin_takeover() {
    let (_tmp, root) = project();
    std::fs::write(root.join("requirements.txt"), "idna==3.7\nsix==1.16.0\n").unwrap();
    vendor_project(&root, &["requirements.txt"]);
    let server = MockServer::start().await;
    mount_hosted_api(&server, true).await;
    let uri = server.uri();
    let mut args = hosted_scan_args(&uri);
    args.push("--dry-run");
    let (code, env) = run_cli(&root, &args, &[]);
    assert_eq!(code, 0, "{env:#}");
    assert!(
        env.to_string().contains("redirect_would_revert_vendored"),
        "{env:#}"
    );
    assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
}
