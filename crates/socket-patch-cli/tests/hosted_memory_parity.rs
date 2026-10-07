//! Parity: the in-memory hosted engine over a file set produces the same
//! changed bytes, ledger bytes and `redirect` block as `scan --mode hosted
//! --json` over a checkout of the same files (the disk run goes through
//! the real binary under a scrubbed environment, so crawlers, host caches
//! and subprocesses contribute nothing on either side).

use std::collections::BTreeMap;

use base64::Engine;
use serde_json::Value;
use wiremock::MockServer;

#[path = "hosted_memory_common/mod.rs"]
mod common;

use common::*;

struct Case {
    /// Fixture dir under `crates/socket-patch-core/tests/fixtures/redirect`.
    fixture: &'static str,
    /// Extra files layered over the fixture input.
    extra: Vec<(&'static str, Vec<u8>)>,
    /// Require at least one redirect (a parity of two no-ops proves
    /// nothing for the formats the engine must rewrite).
    expect_redirect: bool,
    dry_run: bool,
}

fn case(fixture: &'static str) -> Case {
    Case {
        fixture,
        extra: Vec::new(),
        expect_redirect: true,
        dry_run: false,
    }
}

/// Returns the (shared) `redirect` block so a case can assert on it too.
async fn assert_parity(case: Case) -> Value {
    let dir = fixtures_root().join("redirect").join(case.fixture);
    let server = MockServer::start().await;
    let patches = patches_from_overrides(&dir.join("overrides.json"), Some(&server.uri()));
    mount_api(&server, &patches).await;
    let mut files = fixture_files(&dir.join("input"));
    for (rel, bytes) in &case.extra {
        files.insert((*rel).to_string(), bytes.clone());
    }

    let disk = run_disk(&server, &files, case.dry_run);
    let input = build_input(&files, &[], options(case.dry_run));
    let memory = run_engine(&server, input).await;

    assert_eq!(memory.projects.len(), 1, "{}: one root", case.fixture);
    let project = &memory.projects[0];
    assert_eq!(project.root, "");
    assert!(
        project.error.is_none(),
        "{}: {:?}",
        case.fixture,
        project.error
    );
    let disk_redirect = disk
        .envelope
        .get("redirect")
        .cloned()
        .unwrap_or(Value::Null);
    assert_eq!(
        project.redirect, disk_redirect,
        "{}: redirect block differs\nmemory: {:#}\ndisk: {:#}\nstderr: {}",
        case.fixture, project.redirect, disk_redirect, disk.stderr
    );
    let memory_changed = engine_changed(&memory);
    let expected_changed = if case.dry_run {
        assert!(
            disk.changed.is_empty(),
            "{}: a disk dry run wrote files",
            case.fixture
        );
        let mut wet = run_disk(&server, &files, false).changed;
        wet.remove(".socket/vendor/redirect-state.json");
        wet
    } else {
        disk.changed.clone()
    };
    assert_eq!(
        memory_changed.keys().collect::<Vec<_>>(),
        expected_changed.keys().collect::<Vec<_>>(),
        "{}: changed file sets differ\nmemory:\n{}\ndisk:\n{}",
        case.fixture,
        describe(&memory_changed),
        describe(&expected_changed)
    );
    for (rel, bytes) in &expected_changed {
        assert_eq!(
            String::from_utf8_lossy(&memory_changed[rel]),
            String::from_utf8_lossy(bytes),
            "{}: {rel} differs",
            case.fixture
        );
    }
    let redirected = disk_redirect["redirected"].as_u64().unwrap_or(0);
    assert_eq!(redirected as usize, project.redirected.len());
    if case.expect_redirect {
        assert!(
            redirected > 0,
            "{}: the fixture redirected nothing: {disk_redirect:#}\n{}",
            case.fixture,
            disk.stderr
        );
    }
    assert!(
        project.summary.scanned_packages >= redirected,
        "{}",
        case.fixture
    );
    disk_redirect
}

#[tokio::test]
async fn parity_package_lock() {
    assert_parity(case("npm/package-lock-v3/basic")).await;
}

#[tokio::test]
async fn parity_package_lock_dry_run() {
    assert_parity(Case {
        dry_run: true,
        ..case("npm/package-lock-v3/basic")
    })
    .await;
}

#[tokio::test]
async fn parity_pnpm_v9_trust_lockfile() {
    assert_parity(case("npm/pnpm/basic")).await;
}

#[tokio::test]
async fn parity_pnpm_existing_workspace() {
    assert_parity(Case {
        extra: vec![("pnpm-workspace.yaml", b"packages:\n  - 'apps/*'\n".to_vec())],
        ..case("npm/pnpm/basic")
    })
    .await;
}

#[tokio::test]
async fn parity_yarn_classic() {
    assert_parity(case("npm/yarn-classic/basic")).await;
}

#[tokio::test]
async fn parity_yarn_berry() {
    assert_parity(case("npm/yarn-berry/basic")).await;
}

#[tokio::test]
async fn parity_bun_text_lock() {
    assert_parity(case("npm/bun/basic")).await;
}

#[tokio::test]
async fn parity_rush() {
    assert_parity(Case {
        extra: vec![
            ("rush.json", b"{}\n".to_vec()),
            ("common/config/rush/repo-state.json", b"{}\n".to_vec()),
        ],
        ..case("npm/pnpm/nested-rush-lock")
    })
    .await;
}

/// Rush subspaces keep a repo-state.json (the pnpmShrinkwrapHash carrier)
/// next to each subspace lock, and there is no common one (#714). Both the
/// disk run and the in-memory selector must see it, so both emit the
/// stale-hash warning; parity alone would pass with neither emitting it.
#[tokio::test]
async fn parity_rush_subspace() {
    let lock = std::fs::read(
        fixtures_root()
            .join("redirect/npm/pnpm/nested-rush-lock/input/common/config/rush/pnpm-lock.yaml"),
    )
    .unwrap();
    let redirect = assert_parity(Case {
        extra: vec![
            ("rush.json", b"{}\n".to_vec()),
            ("common/config/subspaces/x/pnpm-lock.yaml", lock),
            (
                "common/config/subspaces/x/repo-state.json",
                b"{}\n".to_vec(),
            ),
        ],
        ..case("npm/pnpm/nested-rush-lock")
    })
    .await;
    let codes: Vec<&str> = redirect["warnings"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|w| w["code"].as_str()).collect())
        .unwrap_or_default();
    assert!(
        codes.contains(&"redirect_rush_repo_state_stale"),
        "a subspace repo-state.json must trigger the stale-hash warning; got {codes:?}"
    );
}

#[tokio::test]
async fn parity_uv() {
    assert_parity(Case {
        expect_redirect: false,
        ..case("pypi/uv/basic")
    })
    .await;
}

#[tokio::test]
async fn parity_requirements() {
    assert_parity(case("pypi/requirements/basic")).await;
}

#[tokio::test]
async fn parity_cargo() {
    assert_parity(case("cargo/cargo/basic")).await;
}

#[tokio::test]
async fn parity_cargo_workspace() {
    assert_parity(case("cargo/cargo/workspace-member")).await;
}

#[tokio::test]
async fn parity_composer() {
    assert_parity(case("composer/composer-lock/basic")).await;
}

#[tokio::test]
async fn parity_gemfile() {
    assert_parity(case("gem/bundler/basic")).await;
}

#[tokio::test]
async fn parity_golang() {
    assert_parity(case("golang/gomod/basic")).await;
}

/// Formats with no golden redirect fixture: a committed native lock plus a
/// synthetic override for one of its packages.
async fn assert_native_parity(
    files: BTreeMap<String, Vec<u8>>,
    overrides: Value,
    expect_redirect: bool,
) {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("overrides.json"), overrides.to_string()).unwrap();
    let server = MockServer::start().await;
    let patches = patches_from_overrides(&tmp.path().join("overrides.json"), Some(&server.uri()));
    mount_api(&server, &patches).await;
    let disk = run_disk(&server, &files, false);
    let memory = run_engine(&server, build_input(&files, &[], options(false))).await;
    let project = &memory.projects[0];
    assert!(project.error.is_none(), "{:?}", project.error);
    assert_eq!(
        without_pipenv_advice(&project.redirect),
        without_pipenv_advice(&disk.envelope["redirect"]),
        "{}",
        disk.stderr
    );
    let memory_changed = engine_changed(&memory);
    assert_eq!(
        memory_changed,
        disk.changed,
        "memory:\n{}\ndisk:\n{}",
        describe(&memory_changed),
        describe(&disk.changed)
    );
    if expect_redirect {
        assert!(!project.redirected.is_empty(), "{:#}", project.redirect);
    }
}

/// The in-memory engine cannot find Pipenv on PATH, so its
/// `redirect_pipenv_installer_unknown` advice names the `pipenvMajor`
/// option instead of the disk run's PATH/env remedy.
fn without_pipenv_advice(redirect: &Value) -> Value {
    let mut redirect = redirect.clone();
    if let Some(warnings) = redirect.get_mut("warnings").and_then(Value::as_array_mut) {
        for warning in warnings.iter_mut() {
            if warning["code"] == "redirect_pipenv_installer_unknown" {
                warning["detail"] = Value::Null;
            }
        }
    }
    redirect
}

fn read_fixture(rel: &str) -> Vec<u8> {
    std::fs::read(fixtures_root().join(rel)).unwrap()
}

#[tokio::test]
async fn parity_poetry() {
    let files = BTreeMap::from([
        (
            "poetry.lock".to_string(),
            read_fixture("poetry/2.4.3/poetry.lock"),
        ),
        (
            "pyproject.toml".to_string(),
            read_fixture("poetry/2.4.3/pyproject.toml"),
        ),
    ]);
    let overrides = serde_json::json!([{
        "ecosystem": "pypi", "name": "urllib3", "version": "1.26.18",
        "token": "22222222-2222-4222-8222-222222222222",
        "patchUuid": "e828efa5-5c6d-43f3-9909-03f5ac232b98",
        "artifactUrl": "https://patch.socket.dev/patch/pypi/urllib3/1.26.18/22222222-2222-4222-8222-222222222222/e828efa5-5c6d-43f3-9909-03f5ac232b98/urllib3-1.26.18-py2.py3-none-any.whl",
        "integrity": {"sha256": "c".repeat(64)}
    }]);
    assert_native_parity(files, overrides, true).await;
}

#[tokio::test]
async fn parity_pipfile() {
    let files = BTreeMap::from([
        (
            "Pipfile.lock".to_string(),
            read_fixture("pipenv/2026.8.0/Pipfile.lock"),
        ),
        (
            "Pipfile".to_string(),
            read_fixture("pipenv/2026.8.0/Pipfile"),
        ),
    ]);
    let lock: Value = serde_json::from_slice(&files["Pipfile.lock"]).unwrap();
    let (name, entry) = lock["default"]
        .as_object()
        .and_then(|m| m.iter().next())
        .expect("a default package");
    let version = entry["version"].as_str().unwrap().trim_start_matches("==");
    let overrides = serde_json::json!([{
        "ecosystem": "pypi", "name": name, "version": version,
        "token": "22222222-2222-4222-8222-222222222222",
        "patchUuid": "e828efa5-5c6d-43f3-9909-03f5ac232b98",
        "artifactUrl": format!("https://patch.socket.dev/patch/pypi/{name}/{version}/22222222-2222-4222-8222-222222222222/e828efa5-5c6d-43f3-9909-03f5ac232b98/{name}-{version}-py3-none-any.whl"),
        "integrity": {"sha256": "c".repeat(64)}
    }]);
    assert_native_parity(files, overrides, true).await;
}

#[tokio::test]
async fn parity_bun_binary_lock() {
    let files = BTreeMap::from([
        (
            "bun.lockb".to_string(),
            read_fixture("bun-lockb/1.1.45/bun.lockb"),
        ),
        (
            "package.json".to_string(),
            read_fixture("bun-lockb/1.1.45/package.json"),
        ),
    ]);
    let overrides = serde_json::json!([{
        "ecosystem": "npm", "name": "minimist", "version": "1.2.2",
        "token": "22222222-2222-4222-8222-222222222222",
        "patchUuid": "33333333-3333-4333-8333-333333333333",
        "artifactUrl": "https://patch.socket.dev/patch/npm/minimist/1.2.2/22222222-2222-4222-8222-222222222222/33333333-3333-4333-8333-333333333333/minimist-1.2.2.tgz",
        "integrity": {"sha512": format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode([0x5au8; 64])
        )}
    }]);
    assert_native_parity(files, overrides, true).await;
}

#[tokio::test]
async fn parity_nested_monorepo_roots_match_their_own_disk_runs() {
    let npm = fixtures_root().join("redirect/npm/package-lock-v3/basic");
    let cargo = fixtures_root().join("redirect/cargo/cargo/basic");
    let server = MockServer::start().await;
    let mut patches = patches_from_overrides(&npm.join("overrides.json"), None);
    patches.extend(patches_from_overrides(&cargo.join("overrides.json"), None));
    mount_api(&server, &patches).await;
    let web = fixture_files(&npm.join("input"));
    let svc = fixture_files(&cargo.join("input"));
    let mut repo: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (rel, bytes) in &web {
        repo.insert(format!("apps/web/{rel}"), bytes.clone());
    }
    for (rel, bytes) in &svc {
        repo.insert(format!("services/api/{rel}"), bytes.clone());
    }
    let memory = run_engine(&server, build_input(&repo, &[], options(false))).await;
    let roots: Vec<&str> = memory.projects.iter().map(|p| p.root.as_str()).collect();
    assert_eq!(roots, vec!["apps/web", "services/api"]);
    let changed = engine_changed(&memory);
    for (root, files) in [("apps/web", &web), ("services/api", &svc)] {
        let disk = run_disk(&server, files, false);
        let project = memory.projects.iter().find(|p| p.root == root).unwrap();
        assert_eq!(project.redirect, disk.envelope["redirect"], "{root}");
        let prefixed: BTreeMap<String, Vec<u8>> = changed
            .iter()
            .filter_map(|(k, v)| {
                k.strip_prefix(&format!("{root}/"))
                    .map(|rel| (rel.to_string(), v.clone()))
            })
            .collect();
        assert_eq!(prefixed, disk.changed, "{root}");
    }
}

fn wheel(name: &str, version: &str) -> Vec<u8> {
    use std::io::Write;
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file(format!("{name}-{version}.dist-info/METADATA"), options)
            .unwrap();
        write!(
            zip,
            "Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n"
        )
        .unwrap();
        zip.finish().unwrap();
    }
    buf.into_inner()
}

#[tokio::test]
async fn parity_uv_with_hosted_wheel_metadata() {
    use sha2::Digest;
    let dir = fixtures_root().join("redirect/pypi/uv/basic");
    let server = MockServer::start().await;
    let bytes = wheel("click", "8.1.7");
    let sha = hex::encode(sha2::Sha256::digest(&bytes));
    let tmp = tempfile::tempdir().unwrap();
    let mut overrides: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("overrides.json")).unwrap())
            .unwrap();
    overrides[0]["integrity"]["sha256"] = Value::String(sha);
    std::fs::write(tmp.path().join("overrides.json"), overrides.to_string()).unwrap();
    let patches = patches_from_overrides(&tmp.path().join("overrides.json"), Some(&server.uri()));
    mount_api(&server, &patches).await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path_regex("^/patch/pypi/.+\\.whl$"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(bytes))
        .mount(&server)
        .await;
    let files = fixture_files(&dir.join("input"));
    let disk = run_disk(&server, &files, false);
    let memory = run_engine(&server, build_input(&files, &[], options(false))).await;
    let project = &memory.projects[0];
    assert_eq!(
        project.redirect, disk.envelope["redirect"],
        "{}",
        disk.stderr
    );
    assert_eq!(engine_changed(&memory), disk.changed);
    assert_eq!(project.redirected.len(), 1, "{:#}", project.redirect);
    assert_eq!(
        memory.stats.provider_calls.get("downloadArtifact"),
        Some(&1)
    );
}

/// `files` narrowed to what [`select_paths`] asks the host to stream
/// (presence-only paths marked present), so the parity covers selection.
fn selected_input(
    files: &BTreeMap<String, Vec<u8>>,
) -> socket_patch_cli::hosted_memory::HostedScanInput {
    use socket_patch_cli::hosted_memory::{select_paths, SelectOptions, TreeEntryInput};
    let entries: Vec<TreeEntryInput> = files
        .iter()
        .map(|(p, bytes)| TreeEntryInput {
            path: p.clone(),
            mode: "100644".into(),
            kind: "blob".into(),
            size: Some(bytes.len() as u64),
        })
        .collect();
    let selection = select_paths(&entries, &SelectOptions::default());
    let fetched: BTreeMap<String, Vec<u8>> = selection
        .fetch_text
        .iter()
        .chain(selection.fetch_binary.iter())
        .map(|p| (p.clone(), files[p].clone()))
        .collect();
    let present: Vec<&str> = selection.present_only.iter().map(String::as_str).collect();
    let mut opts = options(false);
    opts.project_roots = Some(selection.roots.clone());
    build_input(&fetched, &present, opts)
}

#[tokio::test]
async fn parity_cargo_patch_path_under_vendor_through_selection() {
    let dir = fixtures_root().join("redirect/cargo/cargo/workspace-member");
    let server = MockServer::start().await;
    let patches = patches_from_overrides(&dir.join("overrides.json"), Some(&server.uri()));
    mount_api(&server, &patches).await;
    let mut files = fixture_files(&dir.join("input"));
    let mut manifest = String::from_utf8(files["Cargo.toml"].clone()).unwrap();
    manifest.push_str("\n[patch.crates-io]\nfoo = { path = \"vendor/foo\" }\n");
    files.insert("Cargo.toml".into(), manifest.into_bytes());
    let mut lock = String::from_utf8(files["Cargo.lock"].clone()).unwrap();
    lock.push_str(
        "\n[[package]]\nname = \"foo\"\nversion = \"0.1.0\"\ndependencies = [\n \"serde\",\n]\n",
    );
    files.insert("Cargo.lock".into(), lock.into_bytes());
    files.insert(
        "vendor/foo/Cargo.toml".into(),
        b"[package]\nname = \"foo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.190\"\n"
            .to_vec(),
    );
    files.insert(
        "tests/fixtures/other/Cargo.toml".into(),
        b"[package]\nname = \"other\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\n"
            .to_vec(),
    );

    let disk = run_disk(&server, &files, false);
    assert!(
        disk.changed.contains_key("vendor/foo/Cargo.toml"),
        "disk pins the [patch] path crate: {}\n{}",
        describe(&disk.changed),
        disk.stderr
    );
    let memory = run_engine(&server, selected_input(&files)).await;
    let project = &memory.projects[0];
    assert!(project.error.is_none(), "{:?}", project.error);
    assert_eq!(
        project.redirect, disk.envelope["redirect"],
        "{}",
        disk.stderr
    );
    let memory_changed = engine_changed(&memory);
    assert_eq!(
        memory_changed,
        disk.changed,
        "memory:\n{}\ndisk:\n{}",
        describe(&memory_changed),
        describe(&disk.changed)
    );
    assert_eq!(project.redirected.len(), 1, "{:#}", project.redirect);
}

/// `cargo vendor` output (`.cargo-checksum.json` in every crate) sits under
/// `vendor/` with a `[patch]`-free workspace: disk never reads it, and
/// selection must not fetch it either.
fn with_cargo_vendor_tree(files: &mut BTreeMap<String, Vec<u8>>) {
    for krate in ["serde", "itoa"] {
        files.insert(
            format!("vendor/{krate}/Cargo.toml"),
            format!("[package]\nname = \"{krate}\"\nversion = \"1.0.190\"\n").into_bytes(),
        );
        files.insert(
            format!("vendor/{krate}/.cargo-checksum.json"),
            b"{\"files\":{},\"package\":\"00\"}".to_vec(),
        );
        files.insert(
            format!("vendor/{krate}/tests/ui/Cargo.toml"),
            b"[package]\nname = \"ui\"\nversion = \"0.0.0\"\n".to_vec(),
        );
    }
}

fn selected_paths(files: &BTreeMap<String, Vec<u8>>) -> Vec<String> {
    use socket_patch_cli::hosted_memory::{select_paths, SelectOptions, TreeEntryInput};
    let entries: Vec<TreeEntryInput> = files
        .keys()
        .map(|p| TreeEntryInput {
            path: p.clone(),
            mode: "100644".into(),
            kind: "blob".into(),
            size: Some(1),
        })
        .collect();
    let selection = select_paths(&entries, &SelectOptions::default());
    selection
        .fetch_text
        .into_iter()
        .chain(selection.fetch_binary)
        .chain(selection.present_only)
        .collect()
}

#[tokio::test]
async fn parity_cargo_vendor_tree_is_not_fetched() {
    let dir = fixtures_root().join("redirect/cargo/cargo/workspace-member");
    let server = MockServer::start().await;
    let patches = patches_from_overrides(&dir.join("overrides.json"), Some(&server.uri()));
    mount_api(&server, &patches).await;
    let mut files = fixture_files(&dir.join("input"));
    with_cargo_vendor_tree(&mut files);

    let selected = selected_paths(&files);
    assert!(
        !selected.iter().any(|p| p.starts_with("vendor/")),
        "{selected:?}"
    );
    let disk = run_disk(&server, &files, false);
    assert!(
        !disk.changed.keys().any(|p| p.starts_with("vendor/")),
        "{}",
        describe(&disk.changed)
    );
    let memory = run_engine(&server, selected_input(&files)).await;
    let project = &memory.projects[0];
    assert!(project.error.is_none(), "{:?}", project.error);
    assert_eq!(
        project.redirect, disk.envelope["redirect"],
        "{}",
        disk.stderr
    );
    let memory_changed = engine_changed(&memory);
    assert_eq!(
        memory_changed,
        disk.changed,
        "memory:\n{}\ndisk:\n{}",
        describe(&memory_changed),
        describe(&disk.changed)
    );
    assert!(!project.redirected.is_empty(), "{:#}", project.redirect);
}

#[tokio::test]
async fn cargo_patch_path_into_vendor_tree_fails_closed() {
    let dir = fixtures_root().join("redirect/cargo/cargo/workspace-member");
    let server = MockServer::start().await;
    let patches = patches_from_overrides(&dir.join("overrides.json"), Some(&server.uri()));
    mount_api(&server, &patches).await;
    let mut files = fixture_files(&dir.join("input"));
    let mut manifest = String::from_utf8(files["Cargo.toml"].clone()).unwrap();
    manifest.push_str("\n[patch.crates-io]\nfoo = { path = \"vendor/foo\" }\n");
    files.insert("Cargo.toml".into(), manifest.into_bytes());
    let mut lock = String::from_utf8(files["Cargo.lock"].clone()).unwrap();
    lock.push_str(
        "\n[[package]]\nname = \"foo\"\nversion = \"0.1.0\"\ndependencies = [\n \"serde\",\n]\n",
    );
    files.insert("Cargo.lock".into(), lock.into_bytes());
    files.insert(
        "vendor/foo/Cargo.toml".into(),
        b"[package]\nname = \"foo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.190\"\n"
            .to_vec(),
    );
    files.insert(
        "vendor/foo/.cargo-checksum.json".into(),
        b"{\"files\":{},\"package\":\"00\"}".to_vec(),
    );

    let memory = run_engine(&server, selected_input(&files)).await;
    let project = &memory.projects[0];
    assert!(project.error.is_none(), "{:?}", project.error);
    assert!(project.redirected.is_empty(), "{:#}", project.redirect);
    assert!(
        engine_changed(&memory).is_empty(),
        "{}",
        describe(&engine_changed(&memory))
    );
    assert!(
        project
            .redirect
            .to_string()
            .contains("redirect_cargo_transitive_dependents"),
        "{:#}",
        project.redirect
    );
}

#[tokio::test]
async fn pipfile_advice_names_the_pipenv_major_option() {
    let files = BTreeMap::from([
        (
            "Pipfile.lock".to_string(),
            read_fixture("pipenv/2026.8.0/Pipfile.lock"),
        ),
        (
            "Pipfile".to_string(),
            read_fixture("pipenv/2026.8.0/Pipfile"),
        ),
    ]);
    let lock: Value = serde_json::from_slice(&files["Pipfile.lock"]).unwrap();
    let (name, entry) = lock["default"]
        .as_object()
        .and_then(|m| m.iter().next())
        .expect("a default package");
    let version = entry["version"].as_str().unwrap().trim_start_matches("==");
    let overrides = serde_json::json!([{
        "ecosystem": "pypi", "name": name, "version": version,
        "token": "22222222-2222-4222-8222-222222222222",
        "patchUuid": "e828efa5-5c6d-43f3-9909-03f5ac232b98",
        "artifactUrl": format!("https://patch.socket.dev/patch/pypi/{name}/{version}/22222222-2222-4222-8222-222222222222/e828efa5-5c6d-43f3-9909-03f5ac232b98/{name}-{version}-py3-none-any.whl"),
        "integrity": {"sha256": "c".repeat(64)}
    }]);
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("overrides.json"), overrides.to_string()).unwrap();
    let server = MockServer::start().await;
    let patches = patches_from_overrides(&tmp.path().join("overrides.json"), Some(&server.uri()));
    mount_api(&server, &patches).await;
    let memory = run_engine(&server, build_input(&files, &[], options(false))).await;
    let detail = memory.projects[0].redirect["warnings"]
        .as_array()
        .and_then(|w| {
            w.iter()
                .find(|x| x["code"] == "redirect_pipenv_installer_unknown")
        })
        .and_then(|w| w["detail"].as_str())
        .expect("pipenv advice warning")
        .to_string();
    assert!(detail.contains("`pipenvMajor`"), "{detail}");
    assert!(!detail.contains("PATH"), "{detail}");
}

#[tokio::test]
async fn excluded_nested_cargo_project_is_its_own_root_through_selection() {
    let ws = fixtures_root().join("redirect/cargo/cargo/workspace-member");
    let standalone = fixtures_root().join("redirect/cargo/cargo/basic");
    let server = MockServer::start().await;
    let mut patches = patches_from_overrides(&ws.join("overrides.json"), Some(&server.uri()));
    patches.extend(patches_from_overrides(
        &standalone.join("overrides.json"),
        Some(&server.uri()),
    ));
    mount_api(&server, &patches).await;

    let mut repo = fixture_files(&ws.join("input"));
    let manifest = String::from_utf8(repo["Cargo.toml"].clone())
        .unwrap()
        .replacen(
            "[workspace]\n",
            "[workspace]\nexclude = [\"tools/fuzz\"]\n",
            1,
        );
    repo.insert("Cargo.toml".into(), manifest.into_bytes());
    let stale_member_lock = repo["Cargo.lock"].clone();
    repo.insert("a/Cargo.lock".into(), stale_member_lock);
    let fuzz = fixture_files(&standalone.join("input"));
    for (rel, bytes) in &fuzz {
        repo.insert(format!("tools/fuzz/{rel}"), bytes.clone());
    }

    let memory = run_engine(&server, selected_input(&repo)).await;
    let roots: Vec<&str> = memory.projects.iter().map(|p| p.root.as_str()).collect();
    assert!(roots.contains(&"tools/fuzz"), "{roots:?}");
    let changed = engine_changed(&memory);

    let disk = run_disk(&server, &fuzz, false);
    let fuzz_project = memory
        .projects
        .iter()
        .find(|p| p.root == "tools/fuzz")
        .unwrap();
    assert!(fuzz_project.error.is_none(), "{:?}", fuzz_project.error);
    assert_eq!(fuzz_project.redirect, disk.envelope["redirect"]);
    let fuzz_changed: BTreeMap<String, Vec<u8>> = changed
        .iter()
        .filter_map(|(k, v)| {
            k.strip_prefix("tools/fuzz/")
                .map(|rel| (rel.to_string(), v.clone()))
        })
        .collect();
    assert_eq!(fuzz_changed, disk.changed);
    assert!(
        !fuzz_project.redirected.is_empty(),
        "{:#}",
        fuzz_project.redirect
    );

    let workspace = memory.projects.iter().find(|p| p.root.is_empty()).unwrap();
    assert!(!workspace.redirected.is_empty(), "{:#}", workspace.redirect);
    assert!(
        !changed.contains_key("a/Cargo.lock"),
        "{}",
        describe(&changed)
    );
    assert!(
        memory.warnings.iter().any(
            |w| w.code == "cargo_member_lock_ignored" && w.project_root.as_deref() == Some("a")
        ),
        "{:?}",
        memory.warnings
    );
}

/// A three-root repo with a root socket.yml: two copies of the npm
/// fixture and the cargo fixture.
fn policy_repo(socket_yml: &str) -> (Vec<Patch>, BTreeMap<String, Vec<u8>>) {
    let npm = fixtures_root().join("redirect/npm/package-lock-v3/basic");
    let cargo = fixtures_root().join("redirect/cargo/cargo/basic");
    let mut patches = patches_from_overrides(&npm.join("overrides.json"), None);
    patches.extend(patches_from_overrides(&cargo.join("overrides.json"), None));
    let mut repo: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (root, dir) in [("apps/web", &npm), ("apps/legacy", &npm), ("services/api", &cargo)] {
        for (rel, bytes) in fixture_files(&dir.join("input")) {
            repo.insert(format!("{root}/{rel}"), bytes);
        }
    }
    repo.insert("socket.yml".to_string(), socket_yml.as_bytes().to_vec());
    (patches, repo)
}

/// The host's two-phase flow: fetch the root policy files, select with
/// their text, stream what selection asks for (presence-only paths marked
/// present) and pass selection's policy outputs to the session.
fn two_phase(
    files: &BTreeMap<String, Vec<u8>>,
    mut opts: socket_patch_cli::hosted_memory::HostedScanOptions,
) -> (
    socket_patch_cli::hosted_memory::PathSelection,
    socket_patch_cli::hosted_memory::HostedScanInput,
) {
    use socket_patch_cli::hosted_memory::{select_paths, PolicyFileInput, SelectOptions, TreeEntryInput};
    let entries: Vec<TreeEntryInput> = files
        .iter()
        .map(|(p, bytes)| TreeEntryInput {
            path: p.clone(),
            mode: "100644".into(),
            kind: "blob".into(),
            size: Some(bytes.len() as u64),
        })
        .collect();
    let policy_files: Vec<PolicyFileInput> = ["socket.yml", "socket.yaml"]
        .iter()
        .filter_map(|name| {
            files.get(*name).map(|bytes| PolicyFileInput {
                path: name.to_string(),
                text: Some(String::from_utf8(bytes.clone()).unwrap()),
                missing: None,
            })
        })
        .collect();
    let selection = select_paths(
        &entries,
        &SelectOptions {
            policy_files: Some(policy_files),
            no_socket_yml: opts.no_socket_yml,
            ..SelectOptions::default()
        },
    );
    let fetched: BTreeMap<String, Vec<u8>> = selection
        .fetch_text
        .iter()
        .chain(selection.fetch_binary.iter())
        .map(|p| (p.clone(), files[p].clone()))
        .collect();
    let present: Vec<&str> = selection.present_only.iter().map(String::as_str).collect();
    opts.policy_paths = Some(selection.policy_paths.clone());
    opts.policy_sha256 = selection.policy_sha256.clone();
    let input = build_input(&fetched, &present, opts);
    (selection, input)
}

fn policy_input(files: &BTreeMap<String, Vec<u8>>) -> socket_patch_cli::hosted_memory::HostedScanInput {
    let (selection, input) = two_phase(files, options(false));
    assert!(selection.policy_error.is_none(), "{:?}", selection.policy_error);
    input
}

/// Session options as selection of `files` would hand them over, without
/// going through selection (for inputs a host may get wrong).
fn policy_options(files: &BTreeMap<String, Vec<u8>>) -> socket_patch_cli::hosted_memory::HostedScanOptions {
    let (selection, _) = two_phase(files, options(false));
    let mut opts = options(false);
    opts.policy_paths = Some(selection.policy_paths);
    opts.policy_sha256 = selection.policy_sha256;
    opts
}

/// `(project, purl, reason)` of a `policy.filtered[]` list.
fn filtered_set(policy: &Value) -> std::collections::BTreeSet<(String, Option<String>, String)> {
    policy["filtered"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["project"].as_str().unwrap().to_string(),
                f["purl"].as_str().map(str::to_string),
                f["reason"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[tokio::test]
async fn parity_socket_yml_filters_the_same_roots_and_packages() {
    let (patches, repo) = policy_repo(
        "version: 2\npatches:\n  ignorePaths: [\"/apps/legacy/\"]\n  ignorePackages: [\"pkg:cargo/serde\"]\n",
    );
    let server = MockServer::start().await;
    mount_api(&server, &patches).await;
    let (selection, input) = two_phase(&repo, options(false));
    assert!(selection.policy_error.is_none(), "{:?}", selection.policy_error);
    let memory = run_engine(&server, input).await;
    assert!(memory.policy_error.is_none(), "{:?}", memory.policy_error);
    let roots: Vec<&str> = memory.projects.iter().map(|p| p.root.as_str()).collect();
    assert_eq!(roots, vec!["apps/web", "services/api"], "the ignored root is not processed");
    // Selection reports the root it excluded; nothing of it is streamed.
    assert!(selection
        .ignored_sample
        .iter()
        .any(|i| i.path == "apps/legacy/package-lock.json" && i.reason == "policy_path_excluded"));
    assert!(!selection.fetch_text.iter().chain(&selection.present_only).any(|p| p.starts_with("apps/legacy/")));
    let memory_policy = memory.policy.clone().expect("policy block");
    assert_eq!(memory_policy["source"], "file");

    let mut disk_filtered = std::collections::BTreeSet::new();
    for root in ["apps/web", "apps/legacy", "services/api"] {
        let disk = run_disk_in(&server, &repo, root, false);
        assert_eq!(disk.envelope["status"], "success", "{root}: {}", disk.stderr);
        assert_eq!(disk.envelope["policy"]["sha256"], memory_policy["sha256"], "{root}");
        disk_filtered.extend(filtered_set(&disk.envelope["policy"]));
        if let Some(project) = memory.projects.iter().find(|p| p.root == root) {
            assert_eq!(project.redirect, disk.envelope["redirect"], "{root}");
            let prefix = format!("{root}/");
            let memory_changed: BTreeMap<String, Vec<u8>> = engine_changed(&memory)
                .into_iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .collect();
            assert_eq!(memory_changed, disk.changed, "{root}");
        } else {
            assert!(disk.changed.is_empty(), "{root}: an ignored root changes nothing");
        }
    }
    let mut memory_filtered = filtered_set(&memory_policy);
    memory_filtered.insert(("apps/legacy".to_string(), None, "policy_path_excluded".to_string()));
    assert_eq!(memory_filtered, disk_filtered);
    assert!(disk_filtered.contains(&("apps/legacy".to_string(), None, "policy_path_excluded".to_string())));
    assert!(disk_filtered.contains(&(
        "services/api".to_string(),
        Some("pkg:cargo/serde@1.0.190".to_string()),
        "policy_package_ignored".to_string()
    )));
}

#[tokio::test]
async fn parity_socket_yml_severity_floor() {
    let (patches, repo) = policy_repo("version: 2\npatches:\n  minSeverity: critical\n");
    let server = MockServer::start().await;
    mount_api(&server, &patches).await;
    let memory = run_engine(&server, policy_input(&repo)).await;
    let web = memory.projects.iter().find(|p| p.root == "apps/web").unwrap();
    assert!(web.redirected.is_empty(), "{:#}", web.redirect);
    assert!(web.skipped.iter().any(|s| s.reason == "policy_severity"), "{:?}", web.skipped);
    assert!(engine_changed(&memory).is_empty());
    let disk = run_disk_in(&server, &repo, "apps/web", false);
    assert!(disk.changed.is_empty());
    assert_eq!(disk.envelope["redirect"], web.redirect);
    let memory_web: std::collections::BTreeSet<_> = filtered_set(memory.policy.as_ref().unwrap())
        .into_iter()
        .filter(|(project, _, _)| project == "apps/web")
        .collect();
    assert_eq!(memory_web, filtered_set(&disk.envelope["policy"]));
}

#[tokio::test]
async fn memory_policy_file_withheld_or_invalid_is_a_policy_error() {
    let (patches, repo) = policy_repo("version: 2\npatches:\n  maxNewPatches: 1\n");
    let server = MockServer::start().await;
    mount_api(&server, &patches).await;
    let opts = policy_options(&repo);
    // Listed by selection but never streamed.
    let mut withheld = repo.clone();
    withheld.remove("socket.yml");
    let out = run_engine(&server, build_input(&withheld, &[], opts.clone())).await;
    let err = out.policy_error.expect("policyError");
    assert_eq!(err.code, "socket_yml_invalid");
    assert!(out.projects.is_empty() && out.changed_files.is_empty() && out.policy.is_none());
    // Streamed present-without-content.
    let out = run_engine(&server, build_input(&withheld, &["socket.yml"], opts.clone())).await;
    assert_eq!(out.policy_error.expect("policyError").code, "socket_yml_invalid");
    // Content other than what selection read.
    let mut changed = repo.clone();
    changed.insert("socket.yml".to_string(), b"version: 2\n".to_vec());
    let out = run_engine(&server, build_input(&changed, &[], opts.clone())).await;
    let err = out.policy_error.expect("policyError");
    assert!(err.detail.contains("differs"), "{}", err.detail);
    // The file streamed without selection's policySha256.
    let mut no_sha = opts.clone();
    no_sha.policy_sha256 = None;
    let out = run_engine(&server, build_input(&repo, &[], no_sha)).await;
    assert_eq!(out.policy_error.expect("policyError").code, "socket_yml_invalid");
    // Invalid content: selection refuses it before anything is fetched.
    let (_, bad) = policy_repo("version: 2\npatches:\n  apiUrl: https://evil.example\n");
    let (selection, _) = two_phase(&bad, options(false));
    let err = selection.policy_error.expect("selection policyError");
    assert!(err.detail.contains("patches.apiUrl"), "{}", err.detail);
    assert!(selection.roots.is_empty() && selection.fetch_text.is_empty());
    let out = run_engine(&server, build_input(&bad, &[], opts.clone())).await;
    let err = out.policy_error.expect("policyError");
    assert!(err.detail.contains("patches.apiUrl"), "{}", err.detail);
    assert!(out.changed_files.is_empty());
    // A bypassed session with a selection that applied the file.
    let mut half = opts.clone();
    half.no_socket_yml = Some(true);
    let out = run_engine(&server, build_input(&repo, &[], half)).await;
    assert_eq!(out.policy_error.expect("policyError").code, "socket_yml_invalid");
    // noSocketYml skips it on both sides.
    let mut bypass = options(false);
    bypass.no_socket_yml = Some(true);
    let (selection, input) = two_phase(&bad, bypass);
    assert!(selection.policy_error.is_none() && selection.policy_sha256.is_none());
    let out = run_engine(&server, input).await;
    assert!(out.policy_error.is_none());
    assert_eq!(out.policy.unwrap()["source"], "bypassed");
}

#[tokio::test]
async fn memory_min_severity_option_beats_the_file() {
    let (patches, repo) = policy_repo("version: 2\npatches:\n  minSeverity: critical\n");
    let server = MockServer::start().await;
    mount_api(&server, &patches).await;
    let mut opts = options(false);
    opts.min_severity = Some("none".to_string());
    let (_, input) = two_phase(&repo, opts);
    let out = run_engine(&server, input).await;
    let policy = out.policy.unwrap();
    assert_eq!(policy["minSeverity"], serde_json::json!({"value": null, "source": "flag"}));
    assert!(out.projects.iter().any(|p| !p.redirected.is_empty()));
    let mut bad = options(false);
    bad.min_severity = Some("severe".to_string());
    assert!(socket_patch_cli::hosted_memory::SessionBuilder::new(bad).is_err());
}

#[test]
fn selection_applies_the_path_policy_and_fails_closed() {
    use socket_patch_cli::hosted_memory::{select_paths, PolicyFileInput, SelectOptions, TreeEntryInput};
    let blob = |path: &str, mode: &str| TreeEntryInput {
        path: path.to_string(),
        mode: mode.to_string(),
        kind: "blob".into(),
        size: Some(1),
    };
    let text = |path: &str, text: &str| PolicyFileInput {
        path: path.to_string(),
        text: Some(text.to_string()),
        missing: None,
    };
    let mut entries = vec![
        blob("socket.yml", "100644"),
        blob("Socket.yml", "100644"),
        blob("apps/web/package-lock.json", "100644"),
        blob("apps/web/tests/app/package-lock.json", "100644"),
        blob("Fixtures/x/yarn.lock", "100644"),
        blob("apps/old/yarn.lock", "100644"),
    ];
    let with = |files: Vec<PolicyFileInput>| SelectOptions {
        policy_files: Some(files),
        ..SelectOptions::default()
    };
    let yml = "version: 2\npatches:\n  ignorePaths: [\"/apps/old/\"]\n";
    let selection = select_paths(&entries, &with(vec![text("socket.yml", yml)]));
    assert!(selection.policy_error.is_none(), "{:?}", selection.policy_error);
    assert_eq!(selection.policy_paths, vec!["socket.yml"]);
    assert_eq!(selection.policy_sha256.as_ref().map(String::len), Some(64));
    assert!(selection.fetch_text.contains(&"socket.yml".to_string()));
    assert_eq!(selection.roots, vec!["apps/web"]);
    // Excluded roots (file list and built-in ignores, any case) are
    // reported and never streamed.
    for path in ["apps/old/yarn.lock", "apps/web/tests/app/package-lock.json", "Fixtures/x/yarn.lock"] {
        assert!(
            selection.ignored_sample.iter().any(|i| i.path == path && i.reason == "policy_path_excluded"),
            "{path}: {selection:?}"
        );
        assert!(!selection.fetch_text.contains(&path.to_string()) && !selection.present_only.contains(&path.to_string()), "{path}");
    }
    // Named roots are explicit: the built-in ignores do not apply.
    let named = select_paths(
        &entries,
        &SelectOptions {
            project_roots: Some(vec!["apps/web/tests/app".to_string()]),
            ..with(vec![text("socket.yml", yml)])
        },
    );
    assert_eq!(named.roots, vec!["apps/web/tests/app"]);
    // A listed policy file with no text, `missing`, or invalid text fails
    // closed: nothing is selected.
    let missing = PolicyFileInput {
        path: "socket.yml".to_string(),
        text: None,
        missing: Some(true),
    };
    for files in [vec![], vec![missing], vec![text("socket.yml", "version: 2\npatches:\n  apiUrl: x\n")]] {
        let out = select_paths(&entries, &with(files));
        assert_eq!(out.policy_error.as_ref().map(|e| e.code.as_str()), Some("socket_yml_invalid"));
        assert!(out.roots.is_empty() && out.fetch_text.is_empty(), "{out:?}");
        assert_eq!(out.policy_paths, vec!["socket.yml"]);
    }
    let out = select_paths(&entries, &with(vec![text("nested/socket.yml", yml)]));
    assert!(out.policy_error.is_some());
    // A symlinked policy file is never read.
    entries.push(blob("socket.yaml", "120000"));
    let out = select_paths(&entries, &with(vec![text("socket.yml", yml), text("socket.yaml", yml)]));
    assert_eq!(out.policy_error.map(|e| e.code), Some("socket_yml_invalid".to_string()));
    // noSocketYml: only the built-in ignores; the file need not be passed.
    let out = select_paths(
        &entries,
        &SelectOptions {
            no_socket_yml: Some(true),
            ..SelectOptions::default()
        },
    );
    assert!(out.policy_error.is_none() && out.policy_sha256.is_none());
    assert_eq!(out.roots, vec!["apps/old", "apps/web"]);
}

#[tokio::test]
async fn memory_negation_reincludes_a_default_ignored_root() {
    let npm = fixtures_root().join("redirect/npm/package-lock-v3/basic");
    let patches = patches_from_overrides(&npm.join("overrides.json"), None);
    let server = MockServer::start().await;
    mount_api(&server, &patches).await;
    let mut repo: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for root in ["e2e/tests", "x/tests"] {
        for (rel, bytes) in fixture_files(&npm.join("input")) {
            repo.insert(format!("{root}/{rel}"), bytes);
        }
    }
    repo.insert(
        "socket.yml".to_string(),
        b"version: 2\npatches:\n  ignorePaths: [\"!/e2e/tests/\"]\n".to_vec(),
    );
    let (selection, input) = two_phase(&repo, options(false));
    assert_eq!(selection.roots, vec!["e2e/tests"]);
    assert!(selection.fetch_text.contains(&"e2e/tests/package-lock.json".to_string()));
    assert!(!selection.fetch_text.iter().any(|p| p.starts_with("x/")), "{selection:?}");
    assert!(selection
        .ignored_sample
        .iter()
        .any(|i| i.path == "x/tests/package-lock.json" && i.reason == "policy_path_excluded"));
    let memory = run_engine(&server, input).await;
    let roots: Vec<&str> = memory.projects.iter().map(|p| p.root.as_str()).collect();
    assert_eq!(roots, vec!["e2e/tests"]);
    assert!(!memory.projects[0].redirected.is_empty(), "{:#}", memory.projects[0].redirect);

    // Given every root anyway, the session applies the same filter itself.
    let direct = run_engine(&server, build_input(&repo, &[], policy_options(&repo))).await;
    let roots: Vec<&str> = direct.projects.iter().map(|p| p.root.as_str()).collect();
    assert_eq!(roots, vec!["e2e/tests"]);
    let entry = &direct.policy.as_ref().unwrap()["filtered"][0];
    assert_eq!((entry["project"].as_str(), entry["detail"].as_str()), (Some("x/tests"), Some("tests/ (built-in default)")));

    // Disk patches the same root the same way.
    let disk = run_disk_in(&server, &repo, "e2e/tests", false);
    assert_eq!(disk.envelope["status"], "success", "{}", disk.stderr);
    assert_eq!(memory.projects[0].redirect, disk.envelope["redirect"]);
    let memory_changed = engine_changed(&memory);
    assert_eq!(memory_changed, disk.changed, "{}", describe(&memory_changed));
}
