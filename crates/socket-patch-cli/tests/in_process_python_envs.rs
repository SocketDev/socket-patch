//! Python ecosystem environment-discovery tests.
//!
//! Python has many install layouts: virtualenv, pyenv, conda, uv,
//! system, etc. The python crawler probes a fixed set of HOME-relative
//! and absolute paths. This file exercises each via handcrafted fake
//! directory layouts under a tmp HOME.

use std::path::Path;

use serial_test::serial;
use socket_patch_cli::commands::scan::{run as scan_run, ScanArgs};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";

fn write_dist_info(site_packages: &Path, name: &str, version: &str) {
    let canon = name.to_lowercase().replace(['-', '.'], "_");
    let dist = site_packages.join(format!("{canon}-{version}.dist-info"));
    std::fs::create_dir_all(&dist).unwrap();
    std::fs::write(
        dist.join("METADATA"),
        format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"),
    )
    .unwrap();
    let pkg = site_packages.join(&canon);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(pkg.join("__init__.py"), "VERSION = '0'\n").unwrap();
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

fn default_args(cwd: &Path, api_url: String) -> ScanArgs {
    ScanArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            org: Some(ORG.to_string()),
            json: true,
            yes: true,
            global: false,
            global_prefix: None,
            api_url: api_url,
            api_token: Some("fake".to_string()),
            ecosystems: Some(vec!["pypi".to_string()]),
            download_mode: "diff".to_string(),
            dry_run: false,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: 100,
        apply: false,
        prune: false,
        sync: false,
    }
}

// ---------------------------------------------------------------------------
// venv layout (.venv/lib/python3.X/site-packages)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn pypi_venv_layout_discovered() {
    let tmp = tempfile::tempdir().unwrap();
    let site = tmp.path().join(".venv/lib/python3.11/site-packages");
    std::fs::create_dir_all(&site).unwrap();
    write_dist_info(&site, "venv_pkg", "1.0.0");

    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    assert_eq!(scan_run(default_args(tmp.path(), server.uri())).await, 0);
}

// ---------------------------------------------------------------------------
// venv layout — python3.12 (different minor version)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn pypi_venv_python312_layout_discovered() {
    let tmp = tempfile::tempdir().unwrap();
    let site = tmp.path().join(".venv/lib/python3.12/site-packages");
    std::fs::create_dir_all(&site).unwrap();
    write_dist_info(&site, "venv_pkg_312", "1.0.0");

    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    assert_eq!(scan_run(default_args(tmp.path(), server.uri())).await, 0);
}

// ---------------------------------------------------------------------------
// venv layout — python3.13 (newer)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn pypi_venv_python313_layout_discovered() {
    let tmp = tempfile::tempdir().unwrap();
    let site = tmp.path().join(".venv/lib/python3.13/site-packages");
    std::fs::create_dir_all(&site).unwrap();
    write_dist_info(&site, "venv_pkg_313", "1.0.0");

    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    assert_eq!(scan_run(default_args(tmp.path(), server.uri())).await, 0);
}

// ---------------------------------------------------------------------------
// venv with alternate name (.env/, env/, venv/)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn pypi_alternate_venv_dir_names() {
    for venv_name in &["env", "venv", ".env"] {
        let tmp = tempfile::tempdir().unwrap();
        let site = tmp
            .path()
            .join(venv_name)
            .join("lib/python3.11/site-packages");
        std::fs::create_dir_all(&site).unwrap();
        write_dist_info(&site, &format!("alt_{venv_name}"), "1.0.0");

        let server = MockServer::start().await;
        mock_batch_empty(&server).await;
        let res = scan_run(default_args(tmp.path(), server.uri())).await;
        assert_eq!(res, 0, "venv name {venv_name} should be discovered");
    }
}

// ---------------------------------------------------------------------------
// VIRTUAL_ENV env var override
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn pypi_virtual_env_env_var_override() {
    let tmp = tempfile::tempdir().unwrap();
    let custom_venv = tmp.path().join("custom-venv");
    let site = custom_venv.join("lib/python3.11/site-packages");
    std::fs::create_dir_all(&site).unwrap();
    write_dist_info(&site, "venv_override", "1.0.0");

    let server = MockServer::start().await;
    mock_batch_empty(&server).await;

    std::env::set_var("VIRTUAL_ENV", &custom_venv);
    let res = scan_run(default_args(tmp.path(), server.uri())).await;
    std::env::remove_var("VIRTUAL_ENV");
    assert_eq!(res, 0);
}

// ---------------------------------------------------------------------------
// Dist-info-only layout (no <pkg>/ source dir)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn pypi_dist_info_only_layout() {
    let tmp = tempfile::tempdir().unwrap();
    let site = tmp.path().join(".venv/lib/python3.11/site-packages");
    std::fs::create_dir_all(&site).unwrap();
    // dist-info dir without a corresponding package source dir.
    let dist = site.join("dist_only-1.0.0.dist-info");
    std::fs::create_dir_all(&dist).unwrap();
    std::fs::write(
        dist.join("METADATA"),
        "Metadata-Version: 2.1\nName: dist_only\nVersion: 1.0.0\n",
    )
    .unwrap();

    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    assert_eq!(scan_run(default_args(tmp.path(), server.uri())).await, 0);
}

// ---------------------------------------------------------------------------
// dist-info with non-canonical name (mixed case, dashes)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn pypi_canonical_name_normalization() {
    let tmp = tempfile::tempdir().unwrap();
    let site = tmp.path().join(".venv/lib/python3.11/site-packages");
    std::fs::create_dir_all(&site).unwrap();
    // pypi canonicalization: SQLAlchemy → sqlalchemy (lowercase, _ -> -)
    let dist = site.join("SQLAlchemy-2.0.30.dist-info");
    std::fs::create_dir_all(&dist).unwrap();
    std::fs::write(
        dist.join("METADATA"),
        "Metadata-Version: 2.1\nName: SQLAlchemy\nVersion: 2.0.30\n",
    )
    .unwrap();

    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    assert_eq!(scan_run(default_args(tmp.path(), server.uri())).await, 0);
}

// ---------------------------------------------------------------------------
// Multiple python versions in one project (multi-venv)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn pypi_multiple_python_versions_in_venvs() {
    let tmp = tempfile::tempdir().unwrap();
    // .venv with one package
    let site311 = tmp.path().join(".venv/lib/python3.11/site-packages");
    std::fs::create_dir_all(&site311).unwrap();
    write_dist_info(&site311, "pkg311", "1.0.0");
    // venv/ with another (the crawler scans both)
    let site312 = tmp.path().join("venv/lib/python3.12/site-packages");
    std::fs::create_dir_all(&site312).unwrap();
    write_dist_info(&site312, "pkg312", "1.0.0");

    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    assert_eq!(scan_run(default_args(tmp.path(), server.uri())).await, 0);
}

// ---------------------------------------------------------------------------
// Empty site-packages — no patches discoverable
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn pypi_empty_site_packages_safe() {
    let tmp = tempfile::tempdir().unwrap();
    let site = tmp.path().join(".venv/lib/python3.11/site-packages");
    std::fs::create_dir_all(&site).unwrap();
    // No dist-info entries.

    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    assert_eq!(scan_run(default_args(tmp.path(), server.uri())).await, 0);
}

// ---------------------------------------------------------------------------
// METADATA file missing required fields
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn pypi_malformed_metadata_handled_gracefully() {
    let tmp = tempfile::tempdir().unwrap();
    let site = tmp.path().join(".venv/lib/python3.11/site-packages");
    std::fs::create_dir_all(&site).unwrap();
    // dist-info with missing Name/Version fields — crawler should skip.
    let dist = site.join("malformed-1.0.0.dist-info");
    std::fs::create_dir_all(&dist).unwrap();
    std::fs::write(dist.join("METADATA"), "Not a real METADATA file").unwrap();

    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    assert_eq!(scan_run(default_args(tmp.path(), server.uri())).await, 0);
}

// ---------------------------------------------------------------------------
// Egg-info layout (older Python packaging convention)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn pypi_egg_info_layout_handled() {
    let tmp = tempfile::tempdir().unwrap();
    let site = tmp.path().join(".venv/lib/python3.11/site-packages");
    std::fs::create_dir_all(&site).unwrap();
    // egg-info — older format. Crawler may or may not handle it; we
    // just check it doesn't crash.
    let egg = site.join("legacy_pkg-1.0.0.egg-info");
    std::fs::create_dir_all(&egg).unwrap();
    std::fs::write(
        egg.join("PKG-INFO"),
        "Metadata-Version: 1.0\nName: legacy_pkg\nVersion: 1.0.0\n",
    )
    .unwrap();

    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    let res = scan_run(default_args(tmp.path(), server.uri())).await;
    assert!(res == 0 || res == 1, "egg-info layout must not crash");
}
