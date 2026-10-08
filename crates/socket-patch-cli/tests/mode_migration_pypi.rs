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
    stage_manifest_with(root, UUID, PATCHED);
}

/// [`stage_manifest`] for patch `uuid` whose patched `six.py` is `patched`.
fn stage_manifest_with(root: &Path, uuid: &str, patched: &[u8]) {
    let after = compute_git_sha256_from_bytes(patched);
    let manifest = json!({ "patches": { PURL: {
        "uuid": uuid,
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
    std::fs::write(socket.join("blobs").join(after), patched).unwrap();
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
    mount_hosted_api_serving(server, wheel_served, WHEEL).await
}

/// [`mount_hosted_api`] with the grant naming the wheel file `wheel_name`.
async fn mount_hosted_api_serving(
    server: &MockServer,
    wheel_served: bool,
    wheel_name: &str,
) -> String {
    let wheel = hosted_wheel();
    let sha = hex::encode(Sha256::digest(&wheel));
    let route =
        format!("/patch/pypi/six/1.16.0/33333333-3333-4333-8333-333333333333/{UUID}/{wheel_name}");
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

/// A requirements.txt project; returns its wiring files.
fn stage_requirements(root: &Path) -> &'static [&'static str] {
    std::fs::write(root.join("requirements.txt"), "idna==3.7\nsix==1.16.0\n").unwrap();
    &["requirements.txt"]
}

/// #765: a vendored requirements.txt picks up a superseding patch. The
/// manifest moves `six` from patch A to patch B (different patched bytes);
/// the next `vendor` must re-wire the requirements line to B's wheel in
/// place, remove A's uuid dir (`vendor_stale_artifact_removed`) and exit 0.
/// Before the fix it failed `pypi_requirements_already_vendored` (exit 1)
/// and pip kept installing patch A. `vendor --revert` afterwards restores
/// the user's original pin, so the carried-over ledger record is intact.
#[tokio::test]
async fn requirements_vendored_revendors_superseding_patch() {
    const UUID_B: &str = "5c3e1a2b-7d4f-4e6a-9b8c-1d2e3f4a5b6d";
    const PATCHED_B: &[u8] = b"# six\nVERSION = '1.16.0'\nSOCKET_PATCHED = 2\n";
    for original in [
        "idna==3.7\nsix==1.16.0\n".to_string(),
        format!(
            "idna==3.7 --hash=sha256:{}\nsix==1.16.0 ; python_version >= \"3\" \\\n    --hash=sha256:{WHEEL_SHA}\n",
            "1".repeat(64)
        ),
    ] {
        let (_tmp, root) = project();
        std::fs::write(root.join("requirements.txt"), &original).unwrap();
        vendor_project(&root, &["requirements.txt"]);
        let wired_a = std::fs::read_to_string(root.join("requirements.txt")).unwrap();

        stage_manifest_with(&root, UUID_B, PATCHED_B);
        let (code, env) = run_cli(&root, &["vendor"], &[]);
        assert_eq!(code, 0, "re-vendor to the superseding patch: {env:#}");
        let rendered = env.to_string();
        assert!(
            !rendered.contains("pypi_requirements_already_vendored"),
            "{env:#}"
        );
        assert!(
            rendered.contains("vendor_stale_artifact_removed"),
            "patch A's artifact is reclaimed: {env:#}"
        );
        let wired_b = std::fs::read_to_string(root.join("requirements.txt")).unwrap();
        assert!(!wired_b.contains(UUID), "uuid A is gone:\n{wired_b}");
        assert_eq!(
            wired_b.matches(&format!(".socket/vendor/pypi/{UUID_B}/")).count(),
            1,
            "one six line, on patch B:\n{wired_b}"
        );
        assert_eq!(
            wired_b.lines().count(),
            wired_a.lines().count(),
            "re-wired in place:\n{wired_a}\n{wired_b}"
        );
        assert_eq!(
            wired_b.contains("--hash="),
            original.contains("--hash="),
            "hash mode kept:\n{wired_b}"
        );
        assert!(!root.join(format!(".socket/vendor/pypi/{UUID}")).exists());
        let wheel_b = wired_b
            .split_whitespace()
            .find(|t| t.contains(UUID_B))
            .unwrap();
        assert!(root.join(wheel_b).is_file(), "patch B's wheel: {wheel_b}");
        let ledger = std::fs::read_to_string(root.join(".socket/vendor/state.json")).unwrap();
        assert!(ledger.contains(UUID_B) && !ledger.contains(UUID), "{ledger}");

        // Re-running is settled: in sync, nothing rewritten.
        let (code, env) = run_cli(&root, &["vendor"], &[]);
        assert_eq!(code, 0, "{env:#}");
        assert_eq!(
            std::fs::read_to_string(root.join("requirements.txt")).unwrap(),
            wired_b
        );

        let (code, env) = run_cli(&root, &["vendor", "--revert"], &[]);
        assert_eq!(code, 0, "revert after the re-vendor: {env:#}");
        assert_eq!(
            std::fs::read_to_string(root.join("requirements.txt")).unwrap(),
            original,
            "the user's own pin is restored"
        );
        assert!(!root.join(format!(".socket/vendor/pypi/{UUID_B}")).exists());
    }
}

#[tokio::test]
async fn requirements_vendored_to_hosted() {
    let (_tmp, root) = project();
    let files = stage_requirements(&root);
    assert_vendored_to_hosted(&root, files).await;
}

#[tokio::test]
async fn requirements_sole_pin_vendored_to_hosted() {
    let (_tmp, root) = project();
    std::fs::write(root.join("requirements.txt"), "six==1.16.0\n").unwrap();
    assert_vendored_to_hosted(&root, &["requirements.txt"]).await;
}

/// #410: a requirements.txt in which every requirement is the hosted pin
/// (a lone `six==1.16.0`, or one beside `-e .`) can be unwound again.
/// Hosted `rollback`, `remove` and the hosted → vendored takeover restore
/// the pin to its unhashed registry spelling. Before the fix they all
/// refused: no other line said whether the original used `--hash`.
async fn assert_all_hosted_requirements_unwind(pristine: &str) {
    let server = MockServer::start().await;
    let hosted_url = mount_hosted_api(&server, true).await;
    let uri = server.uri();
    for unwind in [
        vec!["rollback", "--yes", "--offline"],
        vec!["remove", PURL, "--yes", "--offline"],
        // The fixture server builds the vendored wheel.
        vec!["vendor"],
    ] {
        let (_tmp, root) = project();
        std::fs::write(root.join("requirements.txt"), pristine).unwrap();
        let (code, env) = hosted_scan(&root, &server);
        assert_eq!(code, 0, "hosted scan: {env:#}");
        assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
        let wired = std::fs::read_to_string(root.join("requirements.txt")).unwrap();
        assert!(wired.contains(&hosted_url), "hosted first:\n{wired}");

        if unwind[0] == "vendor" {
            stage_manifest(&root);
            // `--patch-server-url` (which names the hosted origin to take
            // over) also moves the vendored download onto this server.
            prebuilt_common::mount_project(&server, &root).await;
        }
        let mut args = unwind.clone();
        args.extend(["--patch-server-url", uri.as_str()]);
        let (code, env) = run_cli(&root, &args, &[]);
        assert_eq!(code, 0, "{unwind:?} over {pristine:?}: {env:#}");
        let after = std::fs::read_to_string(root.join("requirements.txt")).unwrap();
        if unwind[0] == "vendor" {
            assert!(
                after.contains(&format!(".socket/vendor/pypi/{UUID}/"))
                    && !after.contains(&hosted_url),
                "the takeover leaves the project vendored:\n{after}"
            );
        } else {
            assert_eq!(after, pristine, "{unwind:?} restores the pristine file");
        }
    }
}

#[tokio::test]
async fn requirements_sole_hosted_pin_unwinds() {
    assert_all_hosted_requirements_unwind("six==1.16.0\n").await;
}

#[tokio::test]
async fn requirements_editable_beside_hosted_pin_unwinds() {
    assert_all_hosted_requirements_unwind("-e .\nsix==1.16.0\n").await;
}

/// A Poetry project; returns its wiring files.
fn stage_poetry(root: &Path) -> &'static [&'static str] {
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
    &["poetry.lock", "pyproject.toml"]
}

#[tokio::test]
async fn poetry_vendored_to_hosted() {
    let (_tmp, root) = project();
    let files = stage_poetry(&root);
    assert_vendored_to_hosted(&root, files).await;
}

const PIPFILE: &str = "[[source]]\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\nname = \"pypi\"\n\n[packages]\nsix = \"==1.16.0\"\n\n[requires]\npython_version = \"3.11\"\n";

/// A Pipenv project; returns its wiring files.
fn stage_pipenv(root: &Path) -> &'static [&'static str] {
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
    &["Pipfile.lock"]
}

#[tokio::test]
async fn pipenv_vendored_to_hosted() {
    let (_tmp, root) = project();
    let files = stage_pipenv(&root);
    assert_vendored_to_hosted(&root, files).await;
}

/// A vendored Pipenv project beside a requirements `-r` include the hosted
/// rewriter does not reach (the #567 shape). The attribution gate would
/// veto the Pipfile.lock pin as contested, but a wet takeover has already
/// reverted the vendored wiring by then: dropping it would strand the
/// package on the unpatched registry release (exit 1) while the dry run
/// reported success. A takeover keeps the rewriters' verdict, so the dry
/// run and the wet run agree and the package is never left unpatched.
#[tokio::test]
async fn pipenv_takeover_beside_an_unreached_include_is_never_stranded() {
    let (_tmp, root) = project();
    let files = stage_pipenv(&root);
    vendor_project(&root, files);
    std::fs::write(root.join("requirements.txt"), "-r req/base.txt\n").unwrap();
    std::fs::create_dir_all(root.join("req")).unwrap();
    std::fs::write(root.join("req/base.txt"), "six==1.16.0\n").unwrap();
    let vendored_lock = std::fs::read_to_string(root.join("Pipfile.lock")).unwrap();
    let server = MockServer::start().await;
    let hosted_url = mount_hosted_api(&server, true).await;
    let uri = server.uri();

    let mut dry = hosted_scan_args(&uri);
    dry.push("--dry-run");
    let (dry_code, dry_env) = run_cli(&root, &dry, &[]);
    assert_eq!(
        std::fs::read_to_string(root.join("Pipfile.lock")).unwrap(),
        vendored_lock,
        "a dry run writes nothing"
    );

    let (code, env) = hosted_scan(&root, &server);
    assert_eq!(code, 0, "the takeover is not stranded: {env:#}");
    assert!(
        !env.to_string().contains("redirect_takeover_unpatched"),
        "{env:#}"
    );
    assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
    let lock = std::fs::read_to_string(root.join("Pipfile.lock")).unwrap();
    assert!(
        lock.contains(&hosted_url),
        "six is pinned to the patch:\n{lock}"
    );
    assert!(!lock.contains(".socket/vendor/"), "{lock}");
    assert_eq!(
        (dry_code, &dry_env["redirect"]["redirected"]),
        (code, &env["redirect"]["redirected"]),
        "the dry run predicts the wet run: {dry_env:#}"
    );
}

/// #567 without a takeover: the Pipfile.lock pin the hosted rewriter would
/// land is contested by an `-r` include it does not reach, so the patch is
/// left out — reported in `redirect.skipped[]` as `redirect_unattributable`
/// with discovery's finding — nothing is written and the exit code is 0.
#[tokio::test]
async fn pipenv_redirect_beside_an_unreached_include_is_skipped_unattributable() {
    let (_tmp, root) = project();
    stage_pipenv(&root);
    std::fs::write(root.join("requirements.txt"), "-r req/base.txt\n").unwrap();
    std::fs::create_dir_all(root.join("req")).unwrap();
    std::fs::write(root.join("req/base.txt"), "six==1.16.0\n").unwrap();
    let pristine = std::fs::read_to_string(root.join("Pipfile.lock")).unwrap();
    let server = MockServer::start().await;
    mount_hosted_api(&server, true).await;

    let (code, env) = hosted_scan(&root, &server);
    assert_eq!(
        code, 0,
        "an unattributable pin is a skip, not a failure: {env:#}"
    );
    assert_eq!(env["redirect"]["redirected"], 0, "{env:#}");
    let skipped = env["redirect"]["skipped"].as_array().expect("skipped[]");
    assert_eq!(skipped.len(), 1, "{env:#}");
    assert_eq!(skipped[0]["purl"], PURL, "{env:#}");
    assert_eq!(skipped[0]["reason"], "redirect_unattributable", "{env:#}");
    assert!(
        skipped[0]["detail"]
            .as_str()
            .is_some_and(|d| d.contains("req/base.txt")),
        "the detail names the contesting file: {env:#}"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("Pipfile.lock")).unwrap(),
        pristine,
        "nothing is written for it"
    );
}

/// A superseding patch for the same release (a fixed patch, or one
/// covering more CVEs).
const UUID_B: &str = "6d4f2b3c-8e5a-4f7b-9c9d-2e3f4a5b6c7d";
const PATCHED_B: &[u8] = b"# six\nVERSION = '1.16.0'\nSOCKET_PATCHED = 2\n";

/// A virtualenv whose six was installed from the vendored wheel of patch
/// A (`pipenv sync` after the first vendor): its files are A's patched
/// bytes, not the pristine release patch B is diffed against.
fn venv_installed_from_patch_a(venv: &Path) {
    let site = venv.join("lib/python3.11/site-packages");
    let dist = site.join("six-1.16.0.dist-info");
    std::fs::create_dir_all(&dist).unwrap();
    std::fs::write(site.join("six.py"), PATCHED).unwrap();
    std::fs::write(
        dist.join("METADATA"),
        "Metadata-Version: 2.1\nName: six\nVersion: 1.16.0\n\n",
    )
    .unwrap();
    std::fs::write(
        dist.join("WHEEL"),
        "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py2-none-any\nTag: py3-none-any\n",
    )
    .unwrap();
    std::fs::write(dist.join("INSTALLER"), "pip\n").unwrap();
    std::fs::write(
        dist.join("RECORD"),
        "six.py,,\nsix-1.16.0.dist-info/METADATA,,\nsix-1.16.0.dist-info/WHEEL,,\nsix-1.16.0.dist-info/INSTALLER,,\nsix-1.16.0.dist-info/RECORD,,\n",
    )
    .unwrap();
}

/// #769: a Pipenv project vendored at patch A moves to the superseding
/// patch B when the manifest offers it, as the `would_revendor` preview
/// and the CLI contract promise, whether the checkout is lock-only or its
/// venv was installed from A's vendored wheel. Pipfile.lock is rewired to
/// B, A's artifact is swept, and reverting B restores the registry pin.
#[tokio::test]
async fn pipenv_revendors_to_a_superseding_patch() {
    for venv_present in [false, true] {
        let lane = if venv_present {
            "venv from A"
        } else {
            "lock-only"
        };
        let (_tmp, root) = project();
        stage_pipenv(&root);
        let registry = std::fs::read_to_string(root.join("Pipfile.lock")).unwrap();
        vendor_project(&root, &["Pipfile.lock"]);

        let venv = root.join("../patched-venv");
        let mut extra: Vec<(&str, &str)> = Vec::new();
        if venv_present {
            venv_installed_from_patch_a(&venv);
            extra.push(("VIRTUAL_ENV", venv.to_str().unwrap()));
        }
        stage_manifest_with(&root, UUID_B, PATCHED_B);
        let (code, env) = run_cli(&root, &["vendor"], &extra);
        assert_eq!(code, 0, "{lane}: re-vendor to B: {env:#}");
        assert!(
            env.to_string().contains("vendor_stale_artifact_removed"),
            "{lane}: A's artifact is swept: {env:#}"
        );
        let lock = std::fs::read_to_string(root.join("Pipfile.lock")).unwrap();
        assert!(
            lock.contains(&format!(".socket/vendor/pypi/{UUID_B}/")) && !lock.contains(UUID),
            "{lane}: Pipfile.lock is rewired to B:\n{lock}"
        );
        assert!(!root.join(format!(".socket/vendor/pypi/{UUID}")).exists());
        let wheels: Vec<_> = std::fs::read_dir(root.join(format!(".socket/vendor/pypi/{UUID_B}")))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".whl"))
            .collect();
        assert_eq!(wheels.len(), 1, "{lane}: B's wheel is vendored");

        let (code, env) = run_cli(&root, &["vendor", "--revert"], &extra);
        assert_eq!(code, 0, "{lane}: revert B: {env:#}");
        let reverted: Value =
            serde_json::from_str(&std::fs::read_to_string(root.join("Pipfile.lock")).unwrap())
                .unwrap();
        let registry: Value = serde_json::from_str(&registry).unwrap();
        assert_eq!(
            reverted, registry,
            "{lane}: revert restores the registry pin"
        );
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
sdist = { url = "https://files.pythonhosted.org/packages/71/39/171f1c67cd00715f190ba0b100d606d440a28c93c7714febeca8b79af85e/six-1.16.0.tar.gz", hash = "sha256:SDIST_SHA", size = 34041, upload-time = "2021-05-05T14:18:18.379Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/d9/5a/e7c31adbe875f2abbb91bd84cf2dc52d792b5a01506781dbcf25c91daf11/six-1.16.0-py2.py3-none-any.whl", hash = "sha256:WHEEL_SHA", size = 11053, upload-time = "2021-05-05T14:18:17.237Z" },
]
"#;

/// A uv project; returns its wiring files.
fn stage_uv(root: &Path) -> &'static [&'static str] {
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
    &["uv.lock", "pyproject.toml"]
}

#[tokio::test]
async fn uv_vendored_to_hosted() {
    let (_tmp, root) = project();
    let files = stage_uv(&root);
    assert_vendored_to_hosted(&root, files).await;
}

/// A Hatch project; returns its wiring files.
fn stage_hatch(root: &Path) -> &'static [&'static str] {
    std::fs::write(
        root.join("pyproject.toml"),
        "[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n\n[project]\nname = \"demo\"\nversion = \"0.1.0\"\ndependencies = [\"six==1.16.0\"]\n",
    )
    .unwrap();
    &["pyproject.toml"]
}

#[tokio::test]
async fn hatch_vendored_to_hosted() {
    let (_tmp, root) = project();
    let files = stage_hatch(&root);
    assert_vendored_to_hosted(&root, files).await;
}

/// Stages one flavor's project files; returns its wiring files.
type StageFn = fn(&Path) -> &'static [&'static str];

/// A uv PEP 723 script with its `.py.lock`; returns its wiring files.
fn stage_script_lock(root: &Path) -> &'static [&'static str] {
    std::fs::write(
        root.join("job.py"),
        "# /// script\n# requires-python = \">=3.9\"\n# dependencies = [\"six==1.16.0\"]\n# ///\nimport six\n",
    )
    .unwrap();
    std::fs::write(
        root.join("job.py.lock"),
        format!(
            "version = 1\nrevision = 3\nrequires-python = \">=3.9\"\n\n[manifest]\nrequirements = [{{name = \"six\", specifier = \"==1.16.0\"}}]\n\n[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nsource = {{registry = \"https://pypi.org/simple\"}}\nwheels = [{{url = \"https://files.pythonhosted.org/six-1.16.0-py2.py3-none-any.whl\", hash = \"sha256:{WHEEL_SHA}\"}}]\n"
        ),
    )
    .unwrap();
    &["job.py", "job.py.lock"]
}

/// #742 / #650: a vendored uv project, uv script lock and Hatch project pick
/// up a superseding patch. The manifest moves `six` from patch A to patch B
/// (different patched bytes); the next `vendor` must wire B's wheel, remove
/// A's uuid dir (`vendor_stale_artifact_removed`) and exit 0. Before the fix
/// it failed `pypi_uv_source_already_exists`,
/// `pypi_lock_source_already_exists` or `pypi_hatch_unsupported` (exit 1)
/// and the project kept installing patch A. `vendor --revert` afterwards
/// restores the user's original files byte for byte.
#[tokio::test]
async fn pyproject_flavors_vendored_revendor_superseding_patch() {
    const UUID_B: &str = "5c3e1a2b-7d4f-4e6a-9b8c-1d2e3f4a5b6d";
    const PATCHED_B: &[u8] = b"# six\nVERSION = '1.16.0'\nSOCKET_PATCHED = 2\n";
    let stages: [(&str, StageFn); 3] = [
        ("uv", stage_uv),
        ("script lock", stage_script_lock),
        ("hatch", stage_hatch),
    ];
    for (flavor, stage) in stages {
        let (_tmp, root) = project();
        let files = stage(&root);
        let originals: Vec<String> = files
            .iter()
            .map(|f| std::fs::read_to_string(root.join(f)).unwrap())
            .collect();
        vendor_project(&root, files);

        stage_manifest_with(&root, UUID_B, PATCHED_B);
        let (code, env) = run_cli(&root, &["vendor"], &[]);
        assert_eq!(
            code, 0,
            "{flavor}: re-vendor to the superseding patch: {env:#}"
        );
        let rendered = env.to_string();
        assert!(!rendered.contains("already_exists"), "{flavor}: {env:#}");
        assert!(
            rendered.contains("vendor_stale_artifact_removed"),
            "{flavor}: patch A's artifact is reclaimed: {env:#}"
        );
        let wired_b: Vec<String> = files
            .iter()
            .map(|f| std::fs::read_to_string(root.join(f)).unwrap())
            .collect();
        for (f, text) in files.iter().zip(&wired_b) {
            assert!(!text.contains(UUID), "{flavor}: {f} kept uuid A:\n{text}");
        }
        assert!(
            wired_b
                .iter()
                .any(|t| t.contains(&format!(".socket/vendor/pypi/{UUID_B}/"))),
            "{flavor}: wired to patch B: {wired_b:#?}"
        );
        assert!(
            !root.join(format!(".socket/vendor/pypi/{UUID}")).exists(),
            "{flavor}"
        );
        assert!(
            root.join(format!(".socket/vendor/pypi/{UUID_B}")).is_dir(),
            "{flavor}"
        );
        let ledger = std::fs::read_to_string(root.join(".socket/vendor/state.json")).unwrap();
        assert!(
            ledger.contains(UUID_B) && !ledger.contains(UUID),
            "{flavor}: {ledger}"
        );

        // Re-running is settled: in sync, nothing rewritten.
        let (code, env) = run_cli(&root, &["vendor"], &[]);
        assert_eq!(code, 0, "{flavor}: {env:#}");
        for (f, text) in files.iter().zip(&wired_b) {
            assert_eq!(
                &std::fs::read_to_string(root.join(f)).unwrap(),
                text,
                "{flavor}: {f}"
            );
        }

        let (code, env) = run_cli(&root, &["vendor", "--revert"], &[]);
        assert_eq!(code, 0, "{flavor}: revert after the re-vendor: {env:#}");
        for (f, text) in files.iter().zip(&originals) {
            assert_eq!(
                &std::fs::read_to_string(root.join(f)).unwrap(),
                text,
                "{flavor}: {f} restored to the user's original"
            );
        }
        assert!(
            !root.join(format!(".socket/vendor/pypi/{UUID_B}")).exists(),
            "{flavor}"
        );
    }
}

/// A Hatch guard unrelated to the old wiring (here the uv installer, which
/// Hatch reports under the same `pypi_hatch_unsupported` code, selected by
/// environment variable or by an environment's `installer` / `uv-path`
/// setting) refuses the superseding patch BEFORE patch A's wiring is
/// unwound: the project files, the ledger and patch A's artifact are left
/// exactly as they were, and no patch B wheel is built.
#[tokio::test]
async fn hatch_unrelated_guard_refuses_superseding_patch_before_unwinding() {
    const UUID_B: &str = "5c3e1a2b-7d4f-4e6a-9b8c-1d2e3f4a5b6d";
    const PATCHED_B: &[u8] = b"# six\nVERSION = '1.16.0'\nSOCKET_PATCHED = 2\n";
    const UV_PATH: &[(&str, &str)] = &[("HATCH_ENV_TYPE_VIRTUAL_UV_PATH", "/usr/bin/uv")];
    let cases = [
        ("env var", "", UV_PATH),
        (
            "installer",
            "\n[tool.hatch.envs.default]\ninstaller = \"uv\"\n",
            &[],
        ),
        (
            "uv-path",
            "\n[tool.hatch.envs.default]\nuv-path = \"/usr/bin/uv\"\n",
            &[],
        ),
    ];
    for (case, setting, extra) in cases {
        let (_tmp, root) = project();
        let files = stage_hatch(&root);
        vendor_project(&root, files);
        if !setting.is_empty() {
            let path = root.join("pyproject.toml");
            let wired = std::fs::read_to_string(&path).unwrap();
            std::fs::write(&path, wired + setting).unwrap();
        }
        let wired_a: Vec<String> = files
            .iter()
            .map(|f| std::fs::read_to_string(root.join(f)).unwrap())
            .collect();
        let ledger_a = std::fs::read_to_string(root.join(".socket/vendor/state.json")).unwrap();

        stage_manifest_with(&root, UUID_B, PATCHED_B);
        let (code, env) = run_cli(&root, &["vendor"], extra);
        assert_eq!(code, 1, "{case}: {env:#}");
        let rendered = env.to_string();
        assert!(
            rendered.contains("pypi_hatch_unsupported") && rendered.contains("pip installer"),
            "{case}: the installer guard is the reported refusal: {env:#}"
        );
        for (f, text) in files.iter().zip(&wired_a) {
            assert_eq!(
                &std::fs::read_to_string(root.join(f)).unwrap(),
                text,
                "{case}: {f} untouched"
            );
        }
        assert_eq!(
            std::fs::read_to_string(root.join(".socket/vendor/state.json")).unwrap(),
            ledger_a,
            "{case}"
        );
        assert!(
            root.join(format!(".socket/vendor/pypi/{UUID}")).is_dir(),
            "{case}"
        );
        assert!(
            !root.join(format!(".socket/vendor/pypi/{UUID_B}")).exists(),
            "{case}"
        );
    }
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

// ── `vendor --check` wiring audit (#725) ─────────────────────────────────

/// Vendor the staged project, confirm `vendor --check` passes, then put
/// the wiring files back to their pre-vendor bytes — what `pipenv lock`,
/// `poetry lock`, `uv lock` or a hand-edited requirements.txt leave behind —
/// and require `vendor --check` to fail: the committed wheel is intact, but
/// nothing installs it any more, so a fresh install is unpatched.
fn assert_check_catches_relock(root: &Path, files: &[&str]) {
    let pristine: Vec<Vec<u8>> = files
        .iter()
        .map(|f| std::fs::read(root.join(f)).unwrap())
        .collect();
    vendor_project(root, files);

    let (code, env) = run_cli(root, &["vendor", "--check"], &[]);
    assert_eq!(code, 0, "wired project passes: {env:#}");
    assert_eq!(env["events"][0]["errorCode"], "vendor_check_ok", "{env:#}");

    for (f, bytes) in files.iter().zip(&pristine) {
        std::fs::write(root.join(f), bytes).unwrap();
    }
    let (code, env) = run_cli(root, &["vendor", "--check"], &[]);
    assert_eq!(code, 1, "{files:?} no longer wire the artifact: {env:#}");
    let event = &env["events"][0];
    assert_eq!(event["action"], "failed", "{env:#}");
    assert_eq!(event["errorCode"], "vendor_check_failed", "{env:#}");
    assert!(
        event["reason"]
            .as_str()
            .is_some_and(|r| r.contains("wiring")),
        "the failure names the missing wiring: {env:#}"
    );
    assert_eq!(env["summary"]["failed"], 1, "{env:#}");
}

#[tokio::test]
async fn vendor_check_fails_after_pipenv_relock() {
    let (_tmp, root) = project();
    let files = stage_pipenv(&root);
    assert_check_catches_relock(&root, files);

    // Human mode must not claim the wiring was verified.
    let (code, stdout, stderr) = run_raw(&root, &["vendor", "--check"], &[]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        !stdout.contains("wiring verified"),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[tokio::test]
async fn vendor_check_fails_after_requirements_rewrite() {
    let (_tmp, root) = project();
    let files = stage_requirements(&root);
    assert_check_catches_relock(&root, files);
}

#[tokio::test]
async fn vendor_check_fails_after_poetry_relock() {
    let (_tmp, root) = project();
    let files = stage_poetry(&root);
    assert_check_catches_relock(&root, files);
}

#[tokio::test]
async fn vendor_check_fails_after_uv_relock() {
    let (_tmp, root) = project();
    let files = stage_uv(&root);
    assert_check_catches_relock(&root, files);
}

#[tokio::test]
async fn vendor_check_fails_after_hatch_dependency_reset() {
    let (_tmp, root) = project();
    let files = stage_hatch(&root);
    assert_check_catches_relock(&root, files);
}

/// #699: hosted mode rewrites only the ROOT `requirements.txt`, while
/// vendored mode also wires a pin in a `-r` include or appends a managed
/// `(transitive)` line. A vendored → hosted takeover of such a pin used to
/// revert the vendored wiring first and then find no root entry to pin,
/// stranding the package unpatched (exit 1). It must be refused BEFORE the
/// revert — the vendored patch, ledger entry and wheel are kept — and the
/// dry run must predict that refusal instead of a clean takeover.
async fn assert_unreachable_takeover_refused(root: &Path, wired: &str, dry_run: bool) {
    assert_takeover_refused(
        root,
        &[wired, "requirements.txt"],
        "redirect_requirements_takeover_unreachable",
        dry_run,
    )
    .await;
}

/// A vendored → hosted takeover the hosted rewriter cannot carry through
/// is refused BEFORE the revert, in the wet run and the dry run alike:
/// the refusal `code` is named, nothing is redirected, the run exits 0,
/// and every wiring file in `files`, the ledger entry and the vendored
/// wheel are kept byte for byte.
async fn assert_takeover_refused(root: &Path, files: &[&str], code_name: &str, dry_run: bool) {
    assert_takeover_refused_serving(root, files, code_name, dry_run, WHEEL).await;
}

/// [`assert_takeover_refused`] with the hosted API granting `wheel_name`.
async fn assert_takeover_refused_serving(
    root: &Path,
    files: &[&str],
    code_name: &str,
    dry_run: bool,
    wheel_name: &str,
) {
    let before: Vec<String> = files
        .iter()
        .map(|f| std::fs::read_to_string(root.join(f)).unwrap())
        .collect();
    let state = root.join(".socket/vendor/state.json");
    let server = MockServer::start().await;
    mount_hosted_api_serving(&server, true, wheel_name).await;
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
    assert!(text.contains(code_name), "the refusal is named: {env:#}");
    assert_eq!(env["redirect"]["redirected"], 0, "{env:#}");
    assert_eq!(
        code, 0,
        "a refused takeover keeps the package vendored: {env:#}"
    );
    for (f, before) in files.iter().zip(&before) {
        assert_eq!(
            &std::fs::read_to_string(root.join(f)).unwrap(),
            before,
            "{f}: the vendored wiring is kept"
        );
    }
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

/// uv.lock resolving `six` 1.17.0, either as a direct `six>=1.15` or
/// through `python-dateutil`. Vendoring the manifest's `six@1.16.0` pins
/// the lock entry down to 1.16.0, so the revert brings 1.17.0 back.
const UV_LOCK_DRIFTED_DIRECT: &str = r#"version = 1
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
requires-dist = [{ name = "six", specifier = ">=1.15" }]

[[package]]
name = "six"
version = "1.17.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/94/e7/b2c673351809dca68a0e064b6af791aa332cf192da575fd474ed7d6f16a2/six-1.17.0.tar.gz", hash = "sha256:ff70335d468e7eb6ec65b95b99d3a2836546063f63acc5171de367e834932a81", size = 34031, upload-time = "2024-12-04T17:35:28.174Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl", hash = "sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274", size = 11050, upload-time = "2024-12-04T17:35:26.475Z" },
]
"#;

const UV_LOCK_DRIFTED_TRANSITIVE: &str = r#"version = 1
revision = 2
requires-python = ">=3.9"

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "python-dateutil" },
]

[package.metadata]
requires-dist = [{ name = "python-dateutil", specifier = "==2.9.0.post0" }]

[[package]]
name = "python-dateutil"
version = "2.9.0.post0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "six" },
]
sdist = { url = "https://files.pythonhosted.org/packages/66/c0/0c8b6ad9f17a802ee498c46e004a0eb49bc148f2fd230864601a86dcf6db/python-dateutil-2.9.0.post0.tar.gz", hash = "sha256:37dd54208da7e1cd875388217d5e00ebd4179249f90fb72437e91a35459a0ad3", size = 342432, upload-time = "2024-03-01T18:36:20.211Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/ec/57/56b9bcc3c9c6a792fcbaf139543cee77261f3651ca9da0c93f5c1221264b/python_dateutil-2.9.0.post0-py2.py3-none-any.whl", hash = "sha256:a8b2bc7bffae282281c8140a97d3aa9c14da0b136dfe83f850eea9a5f7470427", size = 229892, upload-time = "2024-03-01T18:36:18.57Z" },
]

[[package]]
name = "six"
version = "1.17.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/94/e7/b2c673351809dca68a0e064b6af791aa332cf192da575fd474ed7d6f16a2/six-1.17.0.tar.gz", hash = "sha256:ff70335d468e7eb6ec65b95b99d3a2836546063f63acc5171de367e834932a81", size = 34031, upload-time = "2024-12-04T17:35:28.174Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl", hash = "sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274", size = 11050, upload-time = "2024-12-04T17:35:26.475Z" },
]
"#;

/// #723: vendor a uv project whose lock resolves `six` 1.17.0 while the
/// manifest patches `six@1.16.0`; vendored uv pins the lock down to the
/// patch version.
fn drifted_uv_project(dependency: &str, lock: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let (tmp, root) = project();
    std::fs::write(
        root.join("pyproject.toml"),
        format!(
            "[project]\nname = \"demo\"\nversion = \"0.1.0\"\nrequires-python = \">=3.9\"\ndependencies = [\"{dependency}\"]\n"
        ),
    )
    .unwrap();
    std::fs::write(root.join("uv.lock"), lock).unwrap();
    vendor_project(&root, &["uv.lock", "pyproject.toml"]);
    (tmp, root)
}

fn drifted_uv_direct() -> (tempfile::TempDir, std::path::PathBuf) {
    drifted_uv_project("six>=1.15", UV_LOCK_DRIFTED_DIRECT)
}

fn drifted_uv_transitive() -> (tempfile::TempDir, std::path::PathBuf) {
    drifted_uv_project("python-dateutil==2.9.0.post0", UV_LOCK_DRIFTED_TRANSITIVE)
}

#[tokio::test]
async fn uv_pinned_down_direct_takeover_is_refused_before_revert() {
    let (_tmp, root) = drifted_uv_direct();
    assert_takeover_refused(
        &root,
        &["uv.lock", "pyproject.toml"],
        "redirect_uv_takeover_version_unreachable",
        false,
    )
    .await;
}

#[tokio::test]
async fn dry_run_predicts_uv_pinned_down_direct_takeover_refusal() {
    let (_tmp, root) = drifted_uv_direct();
    assert_takeover_refused(
        &root,
        &["uv.lock", "pyproject.toml"],
        "redirect_uv_takeover_version_unreachable",
        true,
    )
    .await;
}

#[tokio::test]
async fn uv_pinned_down_transitive_takeover_is_refused_before_revert() {
    let (_tmp, root) = drifted_uv_transitive();
    assert_takeover_refused(
        &root,
        &["uv.lock", "pyproject.toml"],
        "redirect_uv_takeover_version_unreachable",
        false,
    )
    .await;
}

#[tokio::test]
async fn dry_run_predicts_uv_pinned_down_transitive_takeover_refusal() {
    let (_tmp, root) = drifted_uv_transitive();
    assert_takeover_refused(
        &root,
        &["uv.lock", "pyproject.toml"],
        "redirect_uv_takeover_version_unreachable",
        true,
    )
    .await;
}

/// A Poetry 0.12 lock: no `lock-version`, hashes in `[metadata.hashes]`.
const POETRY_0_LOCK: &str = r#"[[package]]
category = "main"
description = "Python 2 and 3 compatibility utilities"
name = "six"
optional = false
python-versions = ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*"
version = "1.16.0"

[metadata]
content-hash = "4b42a89b7ff7b26511b06acdc458dbd85312e5083db8f212b017482bc68cdd01"
python-versions = ">=3.9"

[metadata.hashes]
six = ["sha256:WHEEL_SHA", "sha256:SDIST_SHA"]
"#;

/// #945: vendored mode supports a Poetry 0.12 lock, hosted mode refuses
/// every one of them.
fn poetry_0_project() -> (tempfile::TempDir, std::path::PathBuf) {
    let (tmp, root) = project();
    let files = stage_poetry(&root);
    std::fs::write(
        root.join("poetry.lock"),
        POETRY_0_LOCK
            .replace("WHEEL_SHA", WHEEL_SHA)
            .replace("SDIST_SHA", SDIST_SHA),
    )
    .unwrap();
    vendor_project(&root, files);
    (tmp, root)
}

#[tokio::test]
async fn poetry_0_lock_takeover_is_refused_before_revert() {
    let (_tmp, root) = poetry_0_project();
    assert_takeover_refused(
        &root,
        &["poetry.lock", "pyproject.toml"],
        "redirect_poetry_lock_unsupported",
        false,
    )
    .await;
}

#[tokio::test]
async fn dry_run_predicts_poetry_0_lock_takeover_refusal() {
    let (_tmp, root) = poetry_0_project();
    assert_takeover_refused(
        &root,
        &["poetry.lock", "pyproject.toml"],
        "redirect_poetry_lock_unsupported",
        true,
    )
    .await;
}

/// #701 / #932: a hosted grant that is a platform-tagged wheel is never
/// pinned, so a vendored → hosted takeover onto it must be refused BEFORE
/// the revert (keeping the vendored patch) instead of stranding the
/// package unpatched — on the dry run too.
#[tokio::test]
async fn platform_wheel_takeover_is_refused_before_revert() {
    const PLATFORM: &str = "six-1.16.0-cp311-cp311-manylinux_2_17_x86_64.whl";
    for dry_run in [true, false] {
        let (_tmp, root) = project();
        let files = stage_requirements(&root);
        vendor_project(&root, files);
        assert_takeover_refused_serving(
            &root,
            &["requirements.txt"],
            "redirect_pypi_platform_wheel",
            dry_run,
            PLATFORM,
        )
        .await;
    }
}
