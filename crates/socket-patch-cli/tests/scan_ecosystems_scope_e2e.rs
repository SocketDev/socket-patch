//! `scan --ecosystems` crawls only the named ecosystems unless the run
//! garbage-collects.
//!
//! Without `--prune`/`--sync`, every output of the run is already narrowed
//! to the selected ecosystems, so the other crawlers are not run at all.
//! The one output that used to see past the filter is the lockfile-only
//! count: a selected-ecosystem scan counted the OTHER ecosystems'
//! uninstalled lockfile entries too. A scoped run cannot tell whether a
//! skipped ecosystem's entry is installed, so `lockfileOnlyPackages` now
//! counts the selected ecosystems only. A GC run still crawls everything —
//! the prune judges every manifest entry against the full installed set —
//! and keeps the old count.
//!
//! The fixture: an npm project (one installed package, one lockfile-only)
//! that also carries a `Cargo.lock` whose one crates.io crate is not
//! installed (`CARGO_HOME` points at an empty dir, so the cargo crawl finds
//! nothing — hermetic, and a lockfile-only cargo entry either way).

use std::path::{Path, PathBuf};
use std::process::Command;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const ORG: &str = "test-org";
const INSTALLED_PURL: &str = "pkg:npm/installed-dep@1.0.0";
const NPM_LOCK_ONLY: &str = "lock-only-dep";
const CARGO_LOCK_ONLY: &str = "lockonly-crate";

/// `scan --json` against `api_url` with the `SOCKET_*` environment
/// scrubbed (except the workspace-pinned `SOCKET_NO_CONFIG`), `VIRTUAL_ENV`
/// removed (the python crawler honors it first) and `CARGO_HOME` pinned to
/// an empty dir under `cwd`.
fn run_scan(cwd: &Path, api_url: &str, extra: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.arg("scan").current_dir(cwd);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SOCKET_")
            && key.to_string_lossy() != "SOCKET_NO_CONFIG"
        {
            cmd.env_remove(&key);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env("CARGO_HOME", cwd.join(".cargo-home"));
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd
        .args([
            "--json",
            "--api-url",
            api_url,
            "--api-token",
            "fake-token-for-test",
            "--org",
            ORG,
        ])
        .args(extra)
        .output()
        .expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn stage_project(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "scope-root", "version": "0.0.0",
             "dependencies": { "installed-dep": "^1.0.0", "lock-only-dep": "^1.0.0" } }"#,
    )
    .unwrap();
    let pkg = root.join("node_modules").join("installed-dep");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        r#"{ "name": "installed-dep", "version": "1.0.0" }"#,
    )
    .unwrap();
    let entry = |name: &str| {
        serde_json::json!({
            "version": "1.0.0",
            "resolved": format!("https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz"),
            "integrity": "sha512-fake==",
            "license": "MIT"
        })
    };
    let lock = serde_json::json!({
        "name": "scope-root",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": "scope-root",
                "version": "0.0.0",
                "dependencies": { "installed-dep": "^1.0.0", "lock-only-dep": "^1.0.0" }
            },
            "node_modules/installed-dep": entry("installed-dep"),
            "node_modules/lock-only-dep": entry(NPM_LOCK_ONLY),
        }
    });
    std::fs::write(
        root.join("package-lock.json"),
        serde_json::to_vec_pretty(&lock).unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join("Cargo.lock"),
        format!(
            "version = 3\n\n[[package]]\nname = \"{CARGO_LOCK_ONLY}\"\nversion = \"0.1.0\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"{}\"\n",
            "ab".repeat(32)
        ),
    )
    .unwrap();
}

async fn mock_batch_empty(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [], "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
}

/// Run one scan against a fresh mock and hand back its envelope plus the
/// concatenated batch request bodies.
async fn scan(root: &Path, extra: &[&str]) -> (serde_json::Value, String) {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    let (code, stdout, stderr) = run_scan(root, &server.uri(), extra);
    assert_eq!(code, 0, "{extra:?}: stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("{extra:?}: not a JSON envelope ({e}): {stdout}"));
    let bodies = server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path().ends_with("/patches/batch"))
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect::<Vec<_>>()
        .join("\n");
    (v, bodies)
}

/// Without a GC, `-e npm` counts, queries and flags npm alone: the
/// lockfile-only count no longer includes the cargo crate the (skipped)
/// cargo crawl would have had to vouch for.
#[tokio::test]
async fn scoped_scan_counts_only_the_selected_ecosystems() {
    let tmp = tempfile::tempdir().unwrap();
    stage_project(tmp.path());

    for extra in [
        &["-e", "npm"][..],
        &["--ecosystems", "npm", "--dry-run"][..],
    ] {
        let (v, bodies) = scan(tmp.path(), extra).await;
        assert_eq!(v["status"], "success", "{extra:?}: {v}");
        assert_eq!(
            v["scannedPackages"], 2,
            "{extra:?}: the installed npm package plus the npm lockfile-only one: {v}"
        );
        assert_eq!(
            v["lockfileOnlyPackages"], 1,
            "{extra:?}: only the npm lockfile-only entry counts: {v}"
        );
        assert!(bodies.contains(INSTALLED_PURL), "{extra:?}: {bodies}");
        assert!(bodies.contains(NPM_LOCK_ONLY), "{extra:?}: {bodies}");
        assert!(!bodies.contains(CARGO_LOCK_ONLY), "{extra:?}: {bodies}");
    }

    // Selecting cargo too brings its lockfile-only crate back, crawled.
    let (v, bodies) = scan(tmp.path(), &["-e", "npm,cargo"]).await;
    assert_eq!(v["scannedPackages"], 3, "{v}");
    assert_eq!(v["lockfileOnlyPackages"], 2, "{v}");
    assert!(bodies.contains(CARGO_LOCK_ONLY), "{bodies}");
}

/// A GC run (`--prune`, or `--sync`, which implies it) still crawls every
/// ecosystem, so the lockfile-only count keeps seeing past the filter
/// exactly as before, while what is counted, queried and shown stays npm.
#[tokio::test]
async fn gc_scan_still_crawls_every_ecosystem() {
    let tmp = tempfile::tempdir().unwrap();
    stage_project(tmp.path());

    for extra in [
        &["-e", "npm", "--prune", "--dry-run"][..],
        &["-e", "npm", "--sync", "--dry-run"][..],
    ] {
        let (v, bodies) = scan(tmp.path(), extra).await;
        assert_eq!(v["status"], "success", "{extra:?}: {v}");
        assert_eq!(v["scannedPackages"], 2, "{extra:?}: {v}");
        assert_eq!(
            v["lockfileOnlyPackages"], 2,
            "{extra:?}: the full crawl also counts the cargo lockfile-only crate: {v}"
        );
        assert!(!bodies.contains(CARGO_LOCK_ONLY), "{extra:?}: {bodies}");
    }
}

/// Without `--ecosystems` nothing changes: every ecosystem is crawled,
/// counted and queried.
#[tokio::test]
async fn unfiltered_scan_crawls_every_ecosystem() {
    let tmp = tempfile::tempdir().unwrap();
    stage_project(tmp.path());

    let (v, bodies) = scan(tmp.path(), &[]).await;
    assert_eq!(v["scannedPackages"], 3, "{v}");
    assert_eq!(v["lockfileOnlyPackages"], 2, "{v}");
    assert!(bodies.contains(CARGO_LOCK_ONLY), "{bodies}");
}
