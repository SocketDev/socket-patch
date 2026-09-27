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

async fn assert_parity(case: Case) {
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
