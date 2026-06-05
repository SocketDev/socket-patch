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

/// Collect the raw bodies of every POST to the batch search endpoint.
///
/// `scan` exits 0 even when it discovers nothing, so the exit code alone
/// never proves the crawler found the planted package. The observable
/// proof of discovery is the PURL the crawler ships to `/patches/batch`;
/// these helpers assert on that instead of trusting the exit code.
async fn batch_bodies(server: &MockServer) -> Vec<String> {
    let requests = server
        .received_requests()
        .await
        .expect("wiremock request recording is enabled by default");
    requests
        .iter()
        .filter(|r| r.url.path() == format!("/v0/orgs/{ORG}/patches/batch"))
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect()
}

/// Assert the crawler discovered `purl` and sent it to the batch endpoint.
fn assert_discovered(bodies: &[String], purl: &str) {
    assert!(
        !bodies.is_empty(),
        "crawler never queried the batch endpoint — nothing was discovered \
         (expected PURL {purl})"
    );
    assert!(
        bodies.iter().any(|b| b.contains(purl)),
        "batch request did not include discovered PURL {purl}; bodies: {bodies:?}"
    );
}

/// Assert `needle` was NOT shipped to the batch endpoint (nothing spurious
/// discovered). `needle` may be a full PURL or a `pkg:pypi/` prefix.
fn assert_not_discovered(bodies: &[String], needle: &str) {
    assert!(
        !bodies.iter().any(|b| b.contains(needle)),
        "unexpectedly discovered {needle}; bodies: {bodies:?}"
    );
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
        all_releases: false,
        vex: Default::default(),
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
    assert_discovered(&batch_bodies(&server).await, "pkg:pypi/venv-pkg@1.0.0");
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
    assert_discovered(
        &batch_bodies(&server).await,
        "pkg:pypi/venv-pkg-312@1.0.0",
    );
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
    assert_discovered(
        &batch_bodies(&server).await,
        "pkg:pypi/venv-pkg-313@1.0.0",
    );
}

// ---------------------------------------------------------------------------
// venv with alternate name (.env/, env/, venv/)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn pypi_alternate_venv_dir_names() {
    // Contract per the crawler's documented search list (VIRTUAL_ENV,
    // `.venv`, `venv`): ONLY `venv` here is a recognized local venv dir
    // name. `env` and `.env` are NOT scanned, so their packages must not
    // be discovered. (The original test claimed all three were discovered
    // but only asserted exit 0, which is always true regardless.)
    //
    // (venv dir name, PEP 503 canonical PURL, whether it should be found).
    // `alt_env`/`alt_.env` both canonicalize to `alt-env`.
    for (venv_name, expected_purl, should_find) in &[
        ("env", "pkg:pypi/alt-env@1.0.0", false),
        ("venv", "pkg:pypi/alt-venv@1.0.0", true),
        (".env", "pkg:pypi/alt-env@1.0.0", false),
    ] {
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
        assert_eq!(res, 0, "venv name {venv_name} should scan cleanly");

        let bodies = batch_bodies(&server).await;
        if *should_find {
            assert_discovered(&bodies, expected_purl);
        } else {
            assert_not_discovered(&bodies, expected_purl);
        }
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
    // `custom-venv` is not one of the standard scanned dir names, so the
    // package can only be found by honoring $VIRTUAL_ENV. Discovery of its
    // PURL is the proof that the override path actually ran.
    assert_discovered(
        &batch_bodies(&server).await,
        "pkg:pypi/venv-override@1.0.0",
    );
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
    // A package with no source dir is still a real install and must be
    // discovered from its dist-info alone.
    assert_discovered(&batch_bodies(&server).await, "pkg:pypi/dist-only@1.0.0");
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
    let bodies = batch_bodies(&server).await;
    // Must be canonicalized to lowercase before hitting the API...
    assert_discovered(&bodies, "pkg:pypi/sqlalchemy@2.0.30");
    // ...and the raw mixed-case form must NOT leak through.
    assert_not_discovered(&bodies, "pkg:pypi/SQLAlchemy@2.0.30");
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
    // BOTH venvs must be scanned — discovering only one would still exit 0.
    let bodies = batch_bodies(&server).await;
    assert_discovered(&bodies, "pkg:pypi/pkg311@1.0.0");
    assert_discovered(&bodies, "pkg:pypi/pkg312@1.0.0");
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
    // Nothing on disk => nothing may be shipped to the API. Guards against
    // a crawler that invents phantom packages from an empty site-packages.
    assert_not_discovered(&batch_bodies(&server).await, "pkg:pypi/");
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
    // dist-info with a METADATA file that has no Name/Version headers.
    // The crawler does NOT skip it: by design it falls back to parsing the
    // `<name>-<version>.dist-info` directory name so a corrupt/partial
    // install stays visible to a tool whose job is to patch it. So
    // `malformed-1.0.0.dist-info` is still discovered as
    // `pkg:pypi/malformed@1.0.0`.
    let dist = site.join("malformed-1.0.0.dist-info");
    std::fs::create_dir_all(&dist).unwrap();
    std::fs::write(dist.join("METADATA"), "Not a real METADATA file").unwrap();

    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    assert_eq!(scan_run(default_args(tmp.path(), server.uri())).await, 0);
    assert_discovered(&batch_bodies(&server).await, "pkg:pypi/malformed@1.0.0");
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
    // egg-info — older format. The crawler only recognizes `.dist-info`
    // dirs, so the egg-info package is NOT discovered. Pin that current
    // contract: scan exits cleanly (like the empty-site-packages case) and
    // ships no PURL for it. If egg-info support is added later this fails
    // loudly and the assertion should be flipped to `assert_discovered`.
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
    assert_eq!(res, 0, "egg-info layout must scan cleanly without crashing");
    // Not discovered today; neither the canonical nor raw name may appear.
    let bodies = batch_bodies(&server).await;
    assert_not_discovered(&bodies, "pkg:pypi/legacy-pkg@1.0.0");
    assert_not_discovered(&bodies, "pkg:pypi/legacy_pkg@1.0.0");
}
