//! `scan` with the default `--cwd .` must not walk a pnpm `virtualStoreDir`
//! outside the project.
//!
//! The default cwd makes the importer the empty relative path, which a
//! bare `strip_prefix` accepts as a prefix of every path: an absolute
//! recorded store (pnpm's global virtual store, `<store-dir>/v10/links`,
//! shared by every project on the machine) then passed the in-project
//! check and was crawled, so `apply` would patch the other projects too
//! (#361). A store inside the project is still walked from the same cwd,
//! whether it is recorded relative or absolute.

use std::path::{Path, PathBuf};
use std::process::Command;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn write_pkg(dir: &Path, name: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "1.0.0" }}"#),
    )
    .unwrap();
}

/// A project under `tmp/proj` whose `.modules.yaml` records
/// `virtual_store_dir`, plus a pnpm-shaped store entry for `name` at
/// `store`.
fn stage(tmp: &Path, virtual_store_dir: &str, store: &Path, name: &str) -> PathBuf {
    let proj = tmp.join("proj");
    std::fs::create_dir_all(proj.join("node_modules")).unwrap();
    std::fs::write(
        proj.join("package.json"),
        r#"{ "name": "cwd-root", "version": "0.0.0" }"#,
    )
    .unwrap();
    std::fs::write(
        proj.join("node_modules/.modules.yaml"),
        serde_json::to_string(&serde_json::json!({
            "layoutVersion": 5,
            "virtualStoreDir": virtual_store_dir,
        }))
        .unwrap(),
    )
    .unwrap();
    write_pkg(
        &store.join(format!("{name}@1.0.0/node_modules/{name}")),
        name,
    );
    proj
}

/// `scan --json` from `cwd` with no `--cwd` flag, returning the batch
/// request bodies the crawl produced.
async fn scan_bodies(cwd: &Path) -> String {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [], "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
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
            "-e",
            "npm",
            "--api-url",
            &server.uri(),
            "--api-token",
            "fake-token-for-test",
            "--org",
            ORG,
        ])
        .output()
        .expect("run socket-patch");
    assert!(
        out.status.success(),
        "stdout={}; stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path().ends_with("/patches/batch"))
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

#[tokio::test]
async fn default_cwd_scan_skips_an_absolute_store_outside_the_project() {
    let tmp = tempfile::tempdir().unwrap();
    let global = tmp.path().join("pnpm-store/v10/links");
    let proj = stage(
        tmp.path(),
        &global.display().to_string(),
        &global,
        "shared-dep",
    );
    let bodies = scan_bodies(&proj).await;
    assert!(!bodies.contains("shared-dep"), "{bodies}");
}

#[tokio::test]
async fn default_cwd_scan_walks_a_store_inside_the_project() {
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("proj/.vstore");
    let proj = stage(tmp.path(), "../.vstore", &store, "inproj-dep");
    let bodies = scan_bodies(&proj).await;
    assert!(bodies.contains("pkg:npm/inproj-dep@1.0.0"), "{bodies}");
}

/// Old pnpm records `virtualStoreDir` as an absolute path. From the
/// default cwd the importer is the empty path, which is no lexical prefix
/// of an absolute store, but a store inside the project is still walked.
#[tokio::test]
async fn default_cwd_scan_walks_an_absolute_store_inside_the_project() {
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("proj/.vstore");
    let proj = stage(
        tmp.path(),
        &store.display().to_string(),
        &store,
        "absolute-dep",
    );
    let bodies = scan_bodies(&proj).await;
    assert!(bodies.contains("pkg:npm/absolute-dep@1.0.0"), "{bodies}");
}
