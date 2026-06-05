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

/// Build the `site-packages` path the production crawler actually probes on
/// this platform: `<venv_root>/Lib/site-packages` on Windows,
/// `<venv_root>/lib/<py_ver>/site-packages` on Unix (see
/// `find_site_packages_under` in `python_crawler.rs`). The `py_ver` segment is
/// Unix-only — Windows venvs have no per-version directory — but it is kept as
/// a parameter so the python3.12 / python3.13 layout tests still stage (and so
/// document) the version their names claim on Unix.
fn venv_site_packages(venv_root: &Path, py_ver: &str) -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let _ = py_ver;
        venv_root.join("Lib").join("site-packages")
    }
    #[cfg(not(windows))]
    {
        venv_root.join("lib").join(py_ver).join("site-packages")
    }
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
    let site = venv_site_packages(&tmp.path().join(".venv"), "python3.11");
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
    let site = venv_site_packages(&tmp.path().join(".venv"), "python3.12");
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
    let site = venv_site_packages(&tmp.path().join(".venv"), "python3.13");
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
        let site = venv_site_packages(&tmp.path().join(venv_name), "python3.11");
        std::fs::create_dir_all(&site).unwrap();
        write_dist_info(&site, &format!("alt_{venv_name}"), "1.0.0");

        // Positive control: a package in a recognized `.venv` dir in the
        // SAME project. The crawler must always discover this. Without it,
        // the `should_find == false` branch below is vacuous — it passes
        // even if the crawler silently stopped probing site-packages, or
        // (worse) fell through to a non-deterministic host-wide scan that
        // happens to miss the planted package. With the control present,
        // `.venv` is found, the early-return short-circuits any host scan,
        // and a clean negative for `env`/`.env` proves they were genuinely
        // skipped rather than never reached.
        let control_site = venv_site_packages(&tmp.path().join(".venv"), "python3.11");
        std::fs::create_dir_all(&control_site).unwrap();
        write_dist_info(&control_site, "alt_control", "9.9.9");

        let server = MockServer::start().await;
        mock_batch_empty(&server).await;
        let res = scan_run(default_args(tmp.path(), server.uri())).await;
        assert_eq!(res, 0, "venv name {venv_name} should scan cleanly");

        let bodies = batch_bodies(&server).await;
        assert_discovered(&bodies, "pkg:pypi/alt-control@9.9.9");
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
    let site = venv_site_packages(&custom_venv, "python3.11");
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
    let site = venv_site_packages(&tmp.path().join(".venv"), "python3.11");
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
    let site = venv_site_packages(&tmp.path().join(".venv"), "python3.11");
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
    let site311 = venv_site_packages(&tmp.path().join(".venv"), "python3.11");
    std::fs::create_dir_all(&site311).unwrap();
    write_dist_info(&site311, "pkg311", "1.0.0");
    // venv/ with another (the crawler scans both)
    let site312 = venv_site_packages(&tmp.path().join("venv"), "python3.12");
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
    // Empty `.venv` site-packages — no dist-info entries.
    let empty_site = venv_site_packages(&tmp.path().join(".venv"), "python3.11");
    std::fs::create_dir_all(&empty_site).unwrap();
    // A second recognized venv (`venv/`) holds exactly one real package.
    // It serves as a positive control: the crawler scans both `.venv` and
    // `venv`, so its discovery proves scanning actually ran. The empty
    // `.venv` must contribute NOTHING on top of it.
    let control_site = venv_site_packages(&tmp.path().join("venv"), "python3.11");
    std::fs::create_dir_all(&control_site).unwrap();
    write_dist_info(&control_site, "only_real", "3.2.1");

    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    assert_eq!(scan_run(default_args(tmp.path(), server.uri())).await, 0);

    let bodies = batch_bodies(&server).await;
    // The one real package must be discovered (proves the crawl happened).
    assert_discovered(&bodies, "pkg:pypi/only-real@3.2.1");
    // ...and it must be the ONLY pypi PURL shipped. An empty site-packages
    // must invent no phantom packages; the exact-count check fails if the
    // crawler conjures anything from the empty `.venv`.
    let total_pypi_purls: usize = bodies
        .iter()
        .map(|b| b.matches("pkg:pypi/").count())
        .sum();
    assert_eq!(
        total_pypi_purls, 1,
        "exactly one pypi PURL (the control) expected; empty site-packages \
         must not produce phantom packages. bodies: {bodies:?}"
    );
}

// ---------------------------------------------------------------------------
// METADATA file missing required fields
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn pypi_malformed_metadata_handled_gracefully() {
    let tmp = tempfile::tempdir().unwrap();
    let site = venv_site_packages(&tmp.path().join(".venv"), "python3.11");
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
    let site = venv_site_packages(&tmp.path().join(".venv"), "python3.11");
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

    // Positive control in the SAME site-packages: a real `.dist-info`
    // package the crawler must discover. Without it, the negative
    // assertions below are vacuous — they pass even if the crawler never
    // walked this directory at all (e.g. a regression that stops probing
    // `.venv`). The control proves the dir WAS walked, so a missing
    // `legacy_pkg` means egg-info was specifically not recognized, not that
    // scanning silently no-op'd.
    write_dist_info(&site, "modern_sibling", "2.0.0");

    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    let res = scan_run(default_args(tmp.path(), server.uri())).await;
    assert_eq!(res, 0, "egg-info layout must scan cleanly without crashing");
    let bodies = batch_bodies(&server).await;
    // Control: proves the crawler genuinely walked this site-packages dir.
    assert_discovered(&bodies, "pkg:pypi/modern-sibling@2.0.0");
    // Not discovered today; neither the canonical nor raw name may appear.
    assert_not_discovered(&bodies, "pkg:pypi/legacy-pkg@1.0.0");
    assert_not_discovered(&bodies, "pkg:pypi/legacy_pkg@1.0.0");
}
