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

/// Run `scan` with the ambient `VIRTUAL_ENV` scrubbed first.
///
/// `find_local_venv_site_packages` honors `VIRTUAL_ENV` FIRST and, when it
/// yields a site-packages dir, early-returns WITHOUT scanning `.venv`/`venv`
/// in the cwd. Running this suite from an activated virtualenv (or under
/// direnv auto-activation) therefore made every test scan the shell's venv
/// instead of the planted fixture — false reds across the whole file. Tests
/// are `#[serial]`, so the scrub cannot race another test;
/// `pypi_virtual_env_env_var_override` sets the var deliberately and calls
/// `scan_run` directly.
async fn scan_scrubbed(args: ScanArgs) -> i32 {
    std::env::remove_var("VIRTUAL_ENV");
    std::env::remove_var("UV_PROJECT_ENVIRONMENT");
    scan_run(args).await
}

fn default_args(cwd: &Path, api_url: String) -> ScanArgs {
    ScanArgs {
        socket_yml: Default::default(),
        paths: Vec::new(),
        packages: Vec::new(),
        common: socket_patch_cli::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            org: Some(ORG.to_string()),
            json: true,
            yes: true,
            global: false,
            global_prefix: None,
            api_url: Some(api_url),
            api_token: Some("fake".to_string()),
            ecosystems: Some(vec!["pypi".to_string()]),
            download_mode: "diff".to_string(),
            dry_run: false,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: Some(100),
        apply: false,
        prune: false,
        sync: false,
        vendor: false,
        mode: None,
        all_releases: false,
        vex: Default::default(),
        rollout: Default::default(),
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
    assert_eq!(
        scan_scrubbed(default_args(tmp.path(), server.uri())).await,
        0
    );
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
    assert_eq!(
        scan_scrubbed(default_args(tmp.path(), server.uri())).await,
        0
    );
    assert_discovered(&batch_bodies(&server).await, "pkg:pypi/venv-pkg-312@1.0.0");
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
    assert_eq!(
        scan_scrubbed(default_args(tmp.path(), server.uri())).await,
        0
    );
    assert_discovered(&batch_bodies(&server).await, "pkg:pypi/venv-pkg-313@1.0.0");
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
        let res = scan_scrubbed(default_args(tmp.path(), server.uri())).await;
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

    // Deliberately NOT `scan_scrubbed`: this test IS the VIRTUAL_ENV path.
    std::env::set_var("VIRTUAL_ENV", &custom_venv);
    let res = scan_run(default_args(tmp.path(), server.uri())).await;
    std::env::remove_var("VIRTUAL_ENV");
    assert_eq!(res, 0);
    // `custom-venv` is not one of the standard scanned dir names, so the
    // package can only be found by honoring $VIRTUAL_ENV. Discovery of its
    // PURL is the proof that the override path actually ran.
    assert_discovered(&batch_bodies(&server).await, "pkg:pypi/venv-override@1.0.0");
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
    assert_eq!(
        scan_scrubbed(default_args(tmp.path(), server.uri())).await,
        0
    );
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
    assert_eq!(
        scan_scrubbed(default_args(tmp.path(), server.uri())).await,
        0
    );
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
    assert_eq!(
        scan_scrubbed(default_args(tmp.path(), server.uri())).await,
        0
    );
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
    assert_eq!(
        scan_scrubbed(default_args(tmp.path(), server.uri())).await,
        0
    );

    let bodies = batch_bodies(&server).await;
    // The one real package must be discovered (proves the crawl happened).
    assert_discovered(&bodies, "pkg:pypi/only-real@3.2.1");
    // ...and it must be the ONLY pypi PURL shipped. An empty site-packages
    // must invent no phantom packages; the exact-count check fails if the
    // crawler conjures anything from the empty `.venv`.
    let total_pypi_purls: usize = bodies.iter().map(|b| b.matches("pkg:pypi/").count()).sum();
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
    assert_eq!(
        scan_scrubbed(default_args(tmp.path(), server.uri())).await,
        0
    );
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
    // egg-info — the legacy layout pip < 23.1 writes for an sdist built
    // without `wheel` (and distutils / distro packages write as a bare
    // FILE). It is a real, importable install, so the crawler must report
    // it (#447). Three shapes: a `-pyX.Y`-suffixed directory with
    // `PKG-INFO`, a bare `.egg-info` file, and a directory whose PKG-INFO
    // is missing (the filename carries the identity).
    let egg = site.join("legacy_pkg-1.0.0-py3.11.egg-info");
    std::fs::create_dir_all(&egg).unwrap();
    std::fs::write(
        egg.join("PKG-INFO"),
        "Metadata-Version: 1.0\nName: legacy_pkg\nVersion: 1.0.0\n",
    )
    .unwrap();
    std::fs::write(
        site.join("distro_pkg-2.1.egg-info"),
        "Metadata-Version: 1.1\nName: distro-pkg\nVersion: 2.1\n",
    )
    .unwrap();
    std::fs::create_dir_all(site.join("bare_dir_pkg-0.3-py3.11.egg-info")).unwrap();

    // A `.dist-info` sibling in the SAME site-packages: both layouts are
    // listed side by side.
    write_dist_info(&site, "modern_sibling", "2.0.0");

    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    let res = scan_scrubbed(default_args(tmp.path(), server.uri())).await;
    assert_eq!(res, 0, "egg-info layout must scan cleanly");
    let bodies = batch_bodies(&server).await;
    assert_discovered(&bodies, "pkg:pypi/modern-sibling@2.0.0");
    assert_discovered(&bodies, "pkg:pypi/legacy-pkg@1.0.0");
    assert_discovered(&bodies, "pkg:pypi/distro-pkg@2.1");
    assert_discovered(&bodies, "pkg:pypi/bare-dir-pkg@0.3");
    // The `-pyX.Y` suffix is not part of the version.
    assert_not_discovered(&bodies, "py3.11");
}

// ---------------------------------------------------------------------------
// Ambient VIRTUAL_ENV (activated shell venv) must not hijack the suite
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn pypi_ambient_virtual_env_does_not_hijack_scan() {
    // Simulate running the suite from an activated venv: VIRTUAL_ENV points
    // at a populated venv OUTSIDE the project. Without the scrub in
    // `scan_scrubbed`, the crawler early-returns with the ambient venv's
    // site-packages and never reaches the project's `.venv` — the decoy is
    // discovered and the local package is not (this reddened 9 of 11 tests
    // in this file before the scrub existed). This guard fails if
    // `scan_scrubbed` ever stops scrubbing.
    let shell = tempfile::tempdir().unwrap();
    let decoy_site = venv_site_packages(&shell.path().join("shell-venv"), "python3.11");
    std::fs::create_dir_all(&decoy_site).unwrap();
    write_dist_info(&decoy_site, "ambient_decoy", "6.6.6");
    std::env::set_var("VIRTUAL_ENV", shell.path().join("shell-venv"));

    let tmp = tempfile::tempdir().unwrap();
    let site = venv_site_packages(&tmp.path().join(".venv"), "python3.11");
    std::fs::create_dir_all(&site).unwrap();
    write_dist_info(&site, "local_pkg", "1.0.0");

    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    assert_eq!(
        scan_scrubbed(default_args(tmp.path(), server.uri())).await,
        0
    );
    let bodies = batch_bodies(&server).await;
    assert_discovered(&bodies, "pkg:pypi/local-pkg@1.0.0");
    assert_not_discovered(&bodies, "pkg:pypi/ambient-decoy@6.6.6");
}

// ---------------------------------------------------------------------------
// Pipenv projects: the venv Pipenv resolves, not the generic probe order
// ---------------------------------------------------------------------------

/// Pipenv's environment knobs, cleared before each Pipenv test and after it
/// so ambient values (a `pipenv shell`, CI images) cannot leak in or out.
const PIPENV_VARS: &[&str] = &[
    "VIRTUAL_ENV",
    "WORKON_HOME",
    "PIPENV_ACTIVE",
    "PIPENV_IGNORE_VIRTUALENVS",
    "PIPENV_NO_IGNORE_VIRTUALENVS",
    "PIPENV_VENV_IN_PROJECT",
    "PIPENV_NO_VENV_IN_PROJECT",
    "PIPENV_CUSTOM_VENV_NAME",
    "PIPENV_PIPFILE",
    "PIPENV_DONT_LOAD_ENV",
    "PIPENV_DOTENV_LOCATION",
];

/// Run `scan` with exactly `env` set among [`PIPENV_VARS`].
async fn scan_with_pipenv_env(args: ScanArgs, env: &[(&str, &Path)]) -> i32 {
    for name in PIPENV_VARS {
        std::env::remove_var(name);
    }
    for (name, value) in env {
        std::env::set_var(name, value);
    }
    let code = scan_run(args).await;
    for name in PIPENV_VARS {
        std::env::remove_var(name);
    }
    code
}

/// A Pipenv project (`<tmp>/proj` with a Pipfile) whose Pipenv venv is
/// `<tmp>/wh/proj-env` (named through `PIPENV_CUSTOM_VENV_NAME`) holding
/// `pipenv_pkg 1.0.0`. Returns `(tmp, project, workon_home)`.
fn pipenv_project() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("Pipfile"), "[packages]\npipenv-pkg = \"*\"\n").unwrap();
    let workon = tmp.path().join("wh");
    let site = venv_site_packages(&workon.join("proj-env"), "python3.12");
    std::fs::create_dir_all(&site).unwrap();
    write_dist_info(&site, "pipenv_pkg", "1.0.0");
    (tmp, project, workon)
}

/// #384: with `PIPENV_IGNORE_VIRTUALENVS` or `PIPENV_ACTIVE` set, Pipenv
/// ignores the activated `VIRTUAL_ENV`, so scan must look at Pipenv's own
/// venv and leave the activated one (another project's, a tool venv) alone.
#[tokio::test]
#[serial]
async fn pipenv_opt_outs_keep_activated_virtual_env_from_hijacking_scan() {
    let other = tempfile::tempdir().unwrap();
    let decoy = other.path().join("tool-venv");
    let decoy_site = venv_site_packages(&decoy, "python3.12");
    std::fs::create_dir_all(&decoy_site).unwrap();
    write_dist_info(&decoy_site, "activated_decoy", "6.6.6");

    for opt_out in ["PIPENV_IGNORE_VIRTUALENVS", "PIPENV_ACTIVE"] {
        let (_tmp, project, workon) = pipenv_project();
        let server = MockServer::start().await;
        mock_batch_empty(&server).await;
        let one = Path::new("1");
        let code = scan_with_pipenv_env(
            default_args(&project, server.uri()),
            &[
                ("VIRTUAL_ENV", &decoy),
                ("WORKON_HOME", &workon),
                ("PIPENV_CUSTOM_VENV_NAME", Path::new("proj-env")),
                (opt_out, one),
            ],
        )
        .await;
        assert_eq!(code, 0, "{opt_out}");
        let bodies = batch_bodies(&server).await;
        assert_discovered(&bodies, "pkg:pypi/pipenv-pkg@1.0.0");
        assert_not_discovered(&bodies, "pkg:pypi/activated-decoy@6.6.6");
    }
}

/// #334: Pipenv never uses `venv/`, so it may not shadow Pipenv's venv.
#[tokio::test]
#[serial]
async fn pipenv_stray_venv_dirs_do_not_shadow_the_pipenv_venv() {
    let (_tmp, project, workon) = pipenv_project();
    let stray_site = venv_site_packages(&project.join("venv"), "python3.12");
    std::fs::create_dir_all(&stray_site).unwrap();
    write_dist_info(&stray_site, "stray_decoy", "6.6.6");
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    let env: Vec<(&str, &Path)> = vec![
        ("WORKON_HOME", &workon),
        ("PIPENV_CUSTOM_VENV_NAME", Path::new("proj-env")),
    ];
    let code = scan_with_pipenv_env(default_args(&project, server.uri()), &env).await;
    assert_eq!(code, 0);
    let bodies = batch_bodies(&server).await;
    assert_discovered(&bodies, "pkg:pypi/pipenv-pkg@1.0.0");
    assert_not_discovered(&bodies, "pkg:pypi/stray-decoy@6.6.6");
}

/// #645: with `PIPENV_VENV_IN_PROJECT=0` (or `PIPENV_NO_VENV_IN_PROJECT=1`)
/// only Pipenv 2023.11.14+ ignores a `./.venv` directory; 2018.11 through
/// 2023.10.24 still use it. Both venvs are scanned, so whichever one the
/// installed Pipenv uses is patched.
#[tokio::test]
#[serial]
async fn pipenv_explicit_not_in_project_still_scans_dot_venv() {
    for (name, value) in [
        ("PIPENV_VENV_IN_PROJECT", "0"),
        ("PIPENV_NO_VENV_IN_PROJECT", "1"),
    ] {
        let (_tmp, project, workon) = pipenv_project();
        let dot_site = venv_site_packages(&project.join(".venv"), "python3.12");
        std::fs::create_dir_all(&dot_site).unwrap();
        write_dist_info(&dot_site, "dot_venv_pkg", "1.0.0");
        let server = MockServer::start().await;
        mock_batch_empty(&server).await;
        let env: Vec<(&str, &Path)> = vec![
            ("WORKON_HOME", &workon),
            ("PIPENV_CUSTOM_VENV_NAME", Path::new("proj-env")),
            (name, Path::new(value)),
        ];
        let code = scan_with_pipenv_env(default_args(&project, server.uri()), &env).await;
        assert_eq!(code, 0, "{name}={value}");
        let bodies = batch_bodies(&server).await;
        assert_discovered(&bodies, "pkg:pypi/pipenv-pkg@1.0.0");
        assert_discovered(&bodies, "pkg:pypi/dot-venv-pkg@1.0.0");
    }
}

/// #546: Pipenv loads the project's `.env` before it picks the venv, so a
/// `PIPENV_CUSTOM_VENV_NAME` or `WORKON_HOME` there decides which venv is
/// scanned (and `PIPENV_DONT_LOAD_ENV` turns that off).
#[tokio::test]
#[serial]
async fn pipenv_dotenv_settings_pick_the_scanned_venv() {
    // Name in .env, WORKON_HOME exported.
    let (_tmp, project, workon) = pipenv_project();
    std::fs::write(project.join(".env"), "PIPENV_CUSTOM_VENV_NAME=proj-env\n").unwrap();
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    let code = scan_with_pipenv_env(
        default_args(&project, server.uri()),
        &[("WORKON_HOME", &workon)],
    )
    .await;
    assert_eq!(code, 0);
    assert_discovered(&batch_bodies(&server).await, "pkg:pypi/pipenv-pkg@1.0.0");

    // Both in .env, nothing exported.
    std::fs::write(
        project.join(".env"),
        format!(
            "export WORKON_HOME=\"{}\"\nPIPENV_CUSTOM_VENV_NAME=proj-env # named\n",
            workon.display()
        ),
    )
    .unwrap();
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    let code = scan_with_pipenv_env(default_args(&project, server.uri()), &[]).await;
    assert_eq!(code, 0);
    assert_discovered(&batch_bodies(&server).await, "pkg:pypi/pipenv-pkg@1.0.0");

    // PIPENV_DONT_LOAD_ENV: Pipenv ignores .env, and so does discovery.
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    let code = scan_with_pipenv_env(
        default_args(&project, server.uri()),
        &[("PIPENV_DONT_LOAD_ENV", Path::new("1"))],
    )
    .await;
    assert_eq!(code, 0);
    assert_not_discovered(&batch_bodies(&server).await, "pkg:pypi/pipenv-pkg@1.0.0");
}

// ---------------------------------------------------------------------------
// Package-manager-recorded envs: PDM's saved interpreter / PEP 582, and uv's
// UV_PROJECT_ENVIRONMENT, ahead of a stray `./.venv` the manager never uses
// ---------------------------------------------------------------------------

/// A project at `<tmp>/app` with `pyproject` and an in-project `.venv`
/// holding `stray_decoy 6.6.6` that the project's manager does not use.
fn project_with_stray_venv(pyproject: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("app");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("pyproject.toml"), pyproject).unwrap();
    let stray = venv_site_packages(&project.join(".venv"), "python3.12");
    std::fs::create_dir_all(&stray).unwrap();
    write_dist_info(&stray, "stray_decoy", "6.6.6");
    (tmp, project)
}

/// A venv at `root` holding `pkg 1.0.0`; returns its interpreter path.
fn venv_with(root: &Path, pkg: &str) -> std::path::PathBuf {
    let site = venv_site_packages(root, "python3.12");
    std::fs::create_dir_all(&site).unwrap();
    write_dist_info(&site, pkg, "1.0.0");
    std::fs::write(root.join("pyvenv.cfg"), "home = /usr/bin\n").unwrap();
    if cfg!(windows) {
        root.join("Scripts").join("python.exe")
    } else {
        root.join("bin").join("python")
    }
}

async fn assert_scan_finds(project: &Path, wanted: &str) {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    assert_eq!(scan_scrubbed(default_args(project, server.uri())).await, 0);
    let bodies = batch_bodies(&server).await;
    assert_discovered(&bodies, wanted);
    assert_not_discovered(&bodies, "pkg:pypi/stray-decoy@6.6.6");
}

/// #502: PDM's `.pdm-python` names an out-of-tree venv
/// (`venv.in_project = false`, or `pdm use <venv>`); that is the env scanned.
#[tokio::test]
#[serial]
async fn pdm_saved_interpreter_venv_is_scanned_not_a_stray_dot_venv() {
    let (tmp, project) =
        project_with_stray_venv("[project]\nname = \"app\"\n[tool.pdm]\ndistribution = false\n");
    std::fs::write(project.join("pdm.lock"), "[metadata]\n").unwrap();
    let python = venv_with(
        &tmp.path().join("pdm").join("venvs").join("app-AbCd-3.12"),
        "pdm_pkg",
    );
    std::fs::write(project.join(".pdm-python"), python.display().to_string()).unwrap();
    assert_scan_finds(&project, "pkg:pypi/pdm-pkg@1.0.0").await;
}

/// #528: a PEP 582 PDM project installs into `__pypackages__/<X.Y>/lib`.
#[tokio::test]
#[serial]
async fn pdm_pep582_pypackages_is_scanned_not_a_stray_dot_venv() {
    let (tmp, project) = project_with_stray_venv("[project]\nname = \"app\"\n");
    std::fs::write(project.join("pdm.lock"), "[metadata]\n").unwrap();
    let lib = project.join("__pypackages__").join("3.11").join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    write_dist_info(&lib, "pep582_pkg", "1.0.0");
    // The saved interpreter is a base Python, not a venv, and the project
    // turned PDM's venvs off (`pdm config -l python.use_venv false`).
    let base = tmp.path().join("usr").join("bin").join("python3.11");
    std::fs::write(project.join(".pdm-python"), base.display().to_string()).unwrap();
    std::fs::write(project.join("pdm.toml"), "[python]\nuse_venv = false\n").unwrap();
    assert_scan_finds(&project, "pkg:pypi/pep582-pkg@1.0.0").await;
}

/// #525: uv syncs into `UV_PROJECT_ENVIRONMENT`, absolute or relative to the
/// project, and ignores an activated `VIRTUAL_ENV` for project commands.
#[tokio::test]
#[serial]
async fn uv_project_environment_is_scanned_not_a_stray_dot_venv() {
    let other = tempfile::tempdir().unwrap();
    let decoy = other.path().join("tool-venv");
    let decoy_site = venv_site_packages(&decoy, "python3.12");
    std::fs::create_dir_all(&decoy_site).unwrap();
    write_dist_info(&decoy_site, "activated_decoy", "6.6.6");

    for relative in [false, true] {
        let (tmp, project) = project_with_stray_venv("[project]\nname = \"app\"\n");
        std::fs::write(project.join("uv.lock"), "version = 1\n").unwrap();
        let env = if relative {
            project.join(".venv-ci")
        } else {
            tmp.path().join("opt").join("venv")
        };
        venv_with(&env, "uv_pkg");
        let server = MockServer::start().await;
        mock_batch_empty(&server).await;
        std::env::set_var("VIRTUAL_ENV", &decoy);
        if relative {
            std::env::set_var("UV_PROJECT_ENVIRONMENT", ".venv-ci");
        } else {
            std::env::set_var("UV_PROJECT_ENVIRONMENT", &env);
        }
        let code = scan_run(default_args(&project, server.uri())).await;
        std::env::remove_var("VIRTUAL_ENV");
        std::env::remove_var("UV_PROJECT_ENVIRONMENT");
        assert_eq!(code, 0);
        let bodies = batch_bodies(&server).await;
        assert_discovered(&bodies, "pkg:pypi/uv-pkg@1.0.0");
        assert_not_discovered(&bodies, "pkg:pypi/stray-decoy@6.6.6");
        assert_not_discovered(&bodies, "pkg:pypi/activated-decoy@6.6.6");
    }
}
