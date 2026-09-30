//! Prebuilt artifacts for CLI lifecycle tests. The bytes are fixed on first
//! publication of a fixture UUID; later repairs cannot rebuild from local edits.
#![allow(dead_code)]
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex, OnceLock};

use base64::Engine as _;
use sha2::{Digest, Sha512};
use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::patch::apply::PatchSources;
use socket_patch_core::vendor::test_support::service_fixture::{
    archive, berry_checksum, Secondary,
};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

type Package = (String, Vec<u8>, Secondary);
static PUBLISHED: OnceLock<Mutex<HashMap<(PathBuf, String), Package>>> = OnceLock::new();
static MAVEN_METADATA: OnceLock<Mutex<HashMap<PathBuf, HashMap<String, Vec<u8>>>>> =
    OnceLock::new();

pub struct Server {
    pub uri: String,
    stop: Option<mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
impl Server {
    pub fn view(view: serde_json::Value) -> Self {
        let (ready_tx, ready_rx) = mpsc::channel();
        let (stop, stopped) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let server = MockServer::start().await;
                mount_view(&server, &view, None).await;
                ready_tx.send(server.uri()).unwrap();
                let _ = stopped.recv();
                drop(server);
            });
        });
        Self {
            uri: ready_rx.recv().unwrap(),
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    pub fn project(root: &Path) -> Self {
        Self::project_with_env(root, &[])
    }

    pub fn project_with_env(root: &Path, env: &[(&str, &str)]) -> Self {
        Self::project_with_bind(root, env, false)
    }

    pub fn docker_project(root: &Path, env: &[(&str, &str)]) -> Self {
        Self::project_with_bind(root, env, true)
    }

    pub fn docker_uri(&self) -> String {
        format!(
            "http://host.docker.internal:{}",
            self.uri.rsplit(':').next().unwrap()
        )
    }

    fn project_with_bind(root: &Path, env: &[(&str, &str)], docker: bool) -> Self {
        let root = root.to_path_buf();
        let extra: Vec<_> = env
            .iter()
            .filter(|(k, _)| {
                matches!(
                    *k,
                    "CARGO_HOME"
                        | "GOMODCACHE"
                        | "MAVEN_REPO_LOCAL"
                        | "NUGET_PACKAGES"
                        | "GEM_HOME"
                        | "VIRTUAL_ENV"
                        | "BUNDLE_PATH"
                )
            })
            .map(|(_, v)| PathBuf::from(v))
            .collect();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (stop, stopped) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let address = if docker { "0.0.0.0:0" } else { "127.0.0.1:0" };
                let listener = std::net::TcpListener::bind(address).unwrap();
                let server = MockServer::builder().listener(listener).start().await;
                mount_project_with_roots(&server, &root, extra).await;
                ready_tx.send(server.uri()).unwrap();
                // The HTTP worker runs on the runtime's worker thread.
                let _ = stopped.recv();
                drop(server);
            });
        });
        Self {
            uri: ready_rx.recv().expect("fixture server started"),
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    pub fn configure(&self, common: &mut socket_patch_cli::args::GlobalArgs) {
        common.vendor_url = Some(self.uri.clone());
    }

    pub fn command(&self, command: &mut std::process::Command) {
        command
            .env("SOCKET_VENDOR_URL", &self.uri)
            .env("SOCKET_MAVEN_REGISTRY", &self.uri);
    }
}

pub async fn mount_project(server: &MockServer, root: &Path) {
    mount_project_with_roots(server, root, Vec::new()).await;
}

async fn mount_project_with_roots(server: &MockServer, root: &Path, extra: Vec<PathBuf>) {
    let mut records = std::fs::read(root.join(".socket/manifest.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<PatchManifest>(&b).ok())
        .map(|m| m.patches)
        .unwrap_or_default();
    if let Ok(state) = socket_patch_core::vendor::load_state(&root).await {
        for entry in state.entries.values() {
            if let Some(record) = &entry.record {
                records
                    .entry(entry.base_purl.clone())
                    .or_insert_with(|| record.clone());
            }
        }
    }
    let mut results = serde_json::Map::new();
    let blobs = root.join(".socket/blobs");
    let sources = PatchSources {
        blobs_path: &blobs,
        diffs_path: None,
        mem_blobs: None,
    };
    let mut roots = vec![root.to_path_buf()];
    let store = root.with_file_name("store");
    if store.is_dir() {
        roots.push(store);
    }
    let repositories = extra.clone();
    roots.extend(extra);
    let paths = list_dirs(&roots);
    let mut metadata = MAVEN_METADATA
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .get(root)
        .cloned()
        .unwrap_or_default();
    for repository in repositories {
        for directory in list_dirs(&[repository.clone()]) {
            for entry in std::fs::read_dir(directory).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_file()
                    && matches!(
                        path.extension().and_then(|e| e.to_str()),
                        Some("pom" | "module" | "jar")
                    )
                {
                    if let Ok(relative) = path.strip_prefix(&repository) {
                        metadata
                            .entry(format!(
                                "/{}",
                                relative.to_string_lossy().replace('\\', "/")
                            ))
                            .or_insert_with(|| std::fs::read(path).unwrap());
                    }
                }
            }
        }
    }
    MAVEN_METADATA
        .get()
        .unwrap()
        .lock()
        .unwrap()
        .insert(root.to_path_buf(), metadata.clone());
    for (route, bytes) in metadata {
        for (algorithm, digest) in [
            ("sha512", hex::encode(Sha512::digest(&bytes))),
            ("sha1", hex::encode(sha1::Sha1::digest(&bytes))),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("{route}.{algorithm}")))
                .respond_with(ResponseTemplate::new(200).set_body_string(digest))
                .with_priority(1)
                .mount(server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
            .with_priority(1)
            .mount(server)
            .await;
    }
    for (purl, record) in records {
        if purl.starts_with("pkg:jsr/") {
            continue;
        }
        let key = (root.to_path_buf(), record.uuid.clone());
        let cached = PUBLISHED
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .get(&key)
            .cloned();
        let package = match cached {
            Some(package) => package,
            None => {
                let source = source_dir(&root, &paths, &purl);
                let fallback = (!source.is_dir()).then(|| package_layout(&purl));
                let source = fallback.as_ref().map(|tmp| tmp.path()).unwrap_or(&source);
                let Ok(package) = archive(&purl, &source, &record, &sources).await else {
                    continue;
                };
                PUBLISHED
                    .get()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .insert(key, package.clone());
                package
            }
        };
        mount_package(&server, &purl, &record, package, &mut results).await;
        if purl.starts_with("pkg:maven/") {
            let source = source_dir(&root, &paths, &purl);
            let gav = purl
                .trim_start_matches("pkg:maven/")
                .split('?')
                .next()
                .unwrap();
            if let Some((ga, v)) = gav.rsplit_once('@') {
                if let Some((g, a)) = ga.split_once('/') {
                    for ext in ["pom", "module", "jar"] {
                        if let Ok(bytes) = std::fs::read(source.join(format!("{a}-{v}.{ext}"))) {
                            let route = format!("/{}/{a}/{v}/{a}-{v}.{ext}", g.replace('.', "/"));
                            Mock::given(method("GET"))
                                .and(path(format!("{route}.sha512")))
                                .respond_with(
                                    ResponseTemplate::new(200)
                                        .set_body_string(hex::encode(Sha512::digest(&bytes))),
                                )
                                .mount(server)
                                .await;
                            Mock::given(method("GET"))
                                .and(path(route))
                                .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
                                .mount(server)
                                .await;
                        }
                    }
                }
            }
        }
    }
    Mock::given(method("POST"))
        .and(path_regex(r"/(patch|patches)/package$"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"results":results})),
        )
        .with_priority(1)
        .mount(server)
        .await;
}

pub async fn mount_record(
    server: &MockServer,
    purl: &str,
    record: &PatchRecord,
    dir: &Path,
    sources: &PatchSources<'_>,
) {
    let package = archive(purl, dir, record, sources).await.unwrap();
    let mut results = serde_json::Map::new();
    mount_package(server, purl, record, package, &mut results).await;
    Mock::given(method("POST"))
        .and(path_regex(r"/(patch|patches)/package$"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"results":results})),
        )
        .with_priority(1)
        .mount(server)
        .await;
}

async fn mount_package(
    server: &MockServer,
    purl: &str,
    record: &PatchRecord,
    (leaf, bytes, secondary): Package,
    results: &mut serde_json::Map<String, serde_json::Value>,
) {
    let route = format!("/artifacts/{}/{leaf}", record.uuid);
    let url = format!("{}{route}", server.uri());
    let mut artifacts =
        vec![serde_json::json!({"kind":"tarball","url":url,"integrity":{"sha512":sri(&bytes)}})];
    if let Some(npm) = purl.strip_prefix("pkg:npm/") {
        if let Some((name, _)) = npm.rsplit_once('@') {
            if let Some(sum) = berry_checksum(&bytes, name) {
                artifacts.push(
                    serde_json::json!({"kind":"yarn-berry-zip","integrity":{"yarnBerry10c0":sum}}),
                );
            }
        }
    }
    for (kind, leaf, data) in secondary {
        let route = format!("/artifacts/{}/{leaf}", record.uuid);
        artifacts.push(serde_json::json!({"kind":kind,"url":format!("{}{route}",server.uri()),"integrity":{"sha512":sri(&data)}}));
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(data))
            .mount(server)
            .await;
    }
    results.insert(
        record.uuid.clone(),
        serde_json::json!({"status":"granted","purl":purl,"url":url,"artifacts":artifacts}),
    );
    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
        .mount(server)
        .await;
}

fn sri(bytes: &[u8]) -> String {
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
    )
}

fn list_dirs(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = roots.to_vec();
    while let Some(dir) = pending.pop() {
        if found.len() > 10000 {
            break;
        }
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|t| t.is_dir())
                    && !matches!(
                        entry.file_name().to_str(),
                        Some(".socket" | ".git" | "target")
                    )
                {
                    pending.push(entry.path());
                }
            }
        }
        found.push(dir);
    }
    found.sort();
    found
}

fn package_layout(purl: &str) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let Some((_, coords)) = purl.split('?').next().unwrap().split_once('/') else {
        return tmp;
    };
    let Some((name, version)) = coords.rsplit_once('@') else {
        return tmp;
    };
    let name = name.replace("%40", "@");
    let version = version.replace("%2B", "+").replace("%2b", "+");
    if purl.starts_with("pkg:npm/") {
        std::fs::write(
            tmp.path().join("package.json"),
            serde_json::to_vec(&serde_json::json!({"name": name, "version": version})).unwrap(),
        )
        .unwrap();
    } else if purl.starts_with("pkg:cargo/") {
        std::fs::write(
            tmp.path().join("Cargo.toml"),
            format!("[package]\nname = {name:?}\nversion = {version:?}\n"),
        )
        .unwrap();
    } else if purl.starts_with("pkg:golang/") {
        std::fs::write(tmp.path().join("go.mod"), format!("module {name}\n")).unwrap();
    } else if purl.starts_with("pkg:pypi/") {
        let info = tmp
            .path()
            .join(format!("{}-{version}.dist-info", name.replace('-', "_")));
        std::fs::create_dir_all(&info).unwrap();
        std::fs::write(
            info.join("WHEEL"),
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        .unwrap();
        std::fs::write(
            info.join("METADATA"),
            format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n"),
        )
        .unwrap();
    }
    tmp
}

fn source_dir(root: &Path, paths: &[PathBuf], purl: &str) -> PathBuf {
    let raw = purl.split('?').next().unwrap();
    let Some((kind, nv)) = raw.trim_start_matches("pkg:").split_once('/') else {
        return root.join("missing");
    };
    let Some((name, version)) = nv.rsplit_once('@') else {
        return root.join("missing");
    };
    let decoded = name
        .replace("%40", "@")
        .replace("%2F", "/")
        .replace("%2f", "/");
    let name = decoded.as_str();
    let version = version.replace("%2B", "+").replace("%2b", "+");
    if kind == "npm" {
        let direct = root.join("node_modules").join(name);
        let version_matches = std::fs::read(direct.join("package.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .is_none_or(|package| package["version"].as_str().is_none_or(|v| v == version));
        if direct.is_dir() && version_matches {
            return direct;
        }
    }
    for dir in paths {
        let leaf = dir.file_name().and_then(|v| v.to_str()).unwrap_or("");
        let matches = match kind {
            "npm" | "composer" => std::fs::read(dir.join(if kind == "npm" {
                "package.json"
            } else {
                "composer.json"
            }))
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .is_some_and(|p| {
                p["name"].as_str() == Some(name)
                    && (kind != "npm" || p["version"].as_str().is_none_or(|v| v == version))
            }),
            "pypi" => {
                leaf == "site-packages"
                    && dir
                        .join(format!("{}-{}.dist-info", name.replace('-', "_"), version))
                        .is_dir()
            }
            "cargo" | "gem" => leaf == format!("{name}-{version}"),
            "golang" => dir
                .to_string_lossy()
                .ends_with(&format!("{name}@{version}")),
            "maven" => dir
                .join(format!(
                    "{}-{version}.jar",
                    name.rsplit('/').next().unwrap()
                ))
                .is_file(),
            "nuget" => dir
                .join(format!("{}.{}.nupkg", name.to_lowercase(), version))
                .is_file(),
            _ => false,
        };
        if matches {
            return dir.clone();
        }
    }
    root.join("missing")
}

pub async fn mount_view(server: &MockServer, view: &serde_json::Value, gemspec: Option<&[u8]>) {
    mount_view_from_source(server, view, gemspec, None).await;
}

pub async fn mount_view_from_source(
    server: &MockServer,
    view: &serde_json::Value,
    gemspec: Option<&[u8]>,
    installed: Option<&Path>,
) {
    let purl = view["purl"].as_str().unwrap();
    let mut manifest_record = view.clone();
    manifest_record["exportedAt"] = view["publishedAt"].clone();
    let record: PatchRecord = serde_json::from_value(manifest_record).unwrap();
    let mut blobs = HashMap::new();
    for info in view["files"].as_object().unwrap().values() {
        if let Some(encoded) = info["blobContent"].as_str() {
            blobs.insert(
                info["afterHash"].as_str().unwrap().to_string(),
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .unwrap(),
            );
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("gems/package");
    std::fs::create_dir_all(&source).unwrap();
    let package = purl.split('?').next().unwrap().split_once('/').unwrap().1;
    let (name, version) = package.rsplit_once('@').unwrap();
    let name = name.replace("%40", "@");
    let layout = package_layout(purl);
    copy_tree(installed.unwrap_or(layout.path()), &source);
    if let Some(gemspec) = gemspec {
        std::fs::create_dir_all(tmp.path().join("specifications")).unwrap();
        std::fs::write(
            tmp.path()
                .join("specifications")
                .join(format!("{name}-{version}.gemspec")),
            gemspec,
        )
        .unwrap();
    }
    let sources = PatchSources {
        blobs_path: tmp.path(),
        diffs_path: None,
        mem_blobs: Some(&blobs),
    };
    let package = archive(purl, &source, &record, &sources).await.unwrap();
    let mut results = serde_json::Map::new();
    mount_package(server, purl, &record, package, &mut results).await;
    type Grants = Arc<Mutex<serde_json::Map<String, serde_json::Value>>>;
    static GRANTS: OnceLock<Mutex<HashMap<String, Grants>>> = OnceLock::new();
    let grants = GRANTS
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .entry(server.uri())
        .or_default()
        .clone();
    grants.lock().unwrap().extend(results);
    Mock::given(method("POST"))
        .and(path_regex(r"/(patch|patches)/package$"))
        .respond_with(move |request: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let all = grants.lock().unwrap();
            let results: serde_json::Map<String, serde_json::Value> = body["uuids"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|v| {
                    let uuid = v.as_str()?;
                    all.get(uuid).map(|grant| (uuid.to_string(), grant.clone()))
                })
                .collect();
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"results":results}))
        })
        .with_priority(1)
        .mount(server)
        .await;
}

/// Download fixtures for lifecycle setup. Package-manager offline checks are
/// separate commands and retain their original flags.
pub fn prepare_command(
    command: &mut std::process::Command,
    root: &Path,
    args: &[&str],
    env: &[(&str, &str)],
) -> Option<Server> {
    let download =
        matches!(args.first(), Some(&"vendor") | Some(&"repair")) && !args.contains(&"--revert");
    if download {
        if let Some(i) = args.iter().position(|a| *a == "--patch-server-url") {
            command.args(args).args(["--vendor-url", args[i + 1]]);
            return None;
        }
        let fixture = Server::project_with_env(root, env);
        command.args(args.iter().copied().filter(|a| *a != "--offline"));
        fixture.command(command);
        Some(fixture)
    } else {
        command.args(args);
        None
    }
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &dest);
        } else {
            std::fs::copy(entry.path(), dest).unwrap();
        }
    }
}

pub async fn mount_download(server: &MockServer, purl: &str, uuid: &str, leaf: &str, bytes: &[u8]) {
    let record: PatchRecord = serde_json::from_value(serde_json::json!({
        "uuid": uuid, "exportedAt": "2026-01-01T00:00:00Z", "files": {},
        "vulnerabilities": {}, "description": "fixture", "license": "MIT", "tier": "free"
    }))
    .unwrap();
    let mut grants = serde_json::Map::new();
    mount_package(
        server,
        purl,
        &record,
        (leaf.into(), bytes.to_vec(), Vec::new()),
        &mut grants,
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/patch/package"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "results": grants })),
        )
        .mount(server)
        .await;
}
