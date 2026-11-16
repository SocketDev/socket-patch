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

#[allow(clippy::duplicate_mod)]
#[path = "../common/fs_tree.rs"]
mod fs_tree;

#[path = "../common/jvm_env.rs"]
pub mod jvm_env;

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
        // Each cache the test hands over, with the purl type it holds.
        let extra: Vec<CacheRoot> = env
            .iter()
            .filter_map(|(k, v)| {
                let dir = PathBuf::from(v);
                Some(match *k {
                    "CARGO_HOME" => ("cargo", dir),
                    "GOMODCACHE" => ("golang", dir),
                    "MAVEN_REPO_LOCAL" => ("maven", dir),
                    "NUGET_PACKAGES" => ("nuget", dir),
                    "GEM_HOME" | "BUNDLE_PATH" => ("gem", dir),
                    "VIRTUAL_ENV" => ("pypi", dir),
                    // The explicit JVM caches (`jvm_env::EXPLICIT`) are served
                    // as maven2 repositories from their `files-2.1` trees.
                    "GRADLE_USER_HOME" => ("maven", dir.join(GRADLE_FILES21)),
                    "GRADLE_RO_DEP_CACHE" => ("maven", dir.join(RO_FILES21)),
                    // sbt: "COURSIER_CACHE" => …
                    _ => return None,
                })
            })
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

/// A package cache a test handed to the fixture server: the purl type it
/// holds, and its directory.
type CacheRoot = (&'static str, PathBuf);

async fn mount_project_with_roots(server: &MockServer, root: &Path, extra: Vec<CacheRoot>) {
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
        mem_blobs: None,
    };
    let mut roots = vec![root.to_path_buf()];
    let store = root.with_file_name("store");
    if store.is_dir() {
        roots.push(store);
    }
    let repositories: Vec<PathBuf> = extra.iter().map(|(_, dir)| dir.clone()).collect();
    roots.extend(repositories.iter().cloned());
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
                        let relative = relative.to_string_lossy().replace('\\', "/");
                        let route = if repository.ends_with(GRADLE_FILES21_LEAF) {
                            files21_route(&relative)
                        } else {
                            Some(format!("/{relative}"))
                        };
                        if let Some(route) = route {
                            metadata
                                .entry(route)
                                .or_insert_with(|| std::fs::read(path).unwrap());
                        }
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
                if fallback.is_some() {
                    if let Some(notice) = stand_in_notice(&purl, &extra) {
                        eprintln!("{notice}");
                    }
                }
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
                        let file = maven_sibling(&source, &format!("{a}-{v}.{ext}"));
                        if let Some(bytes) = file.and_then(|f| std::fs::read(f).ok()) {
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
            "golang" => is_go_module_dir(dir, name, &version),
            "maven" => {
                let jar = format!("{}-{version}.jar", name.rsplit('/').next().unwrap());
                if dir.join(&jar).is_file() {
                    true
                } else if let Some(child) = files21_hash_child(dir, &jar) {
                    // A Gradle `files-2.1` version dir: the jar sits in its
                    // `<sha1>/` child, which is the archive source.
                    return child;
                } else {
                    false
                }
            }
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

/// Whether `dir` is where Go's module cache keeps `module@version`: the
/// path's last components spell the module path and the version, both
/// case-escaped, starting at a component boundary (the directory of
/// `sigs.k8s.io/x` is not that of `k8s.io/x`). The purl spells the module
/// path with `/`, whatever the platform separates the cache's directories
/// with.
fn is_go_module_dir(dir: &Path, module: &str, version: &str) -> bool {
    let wanted = format!("{}@{}", go_case_escape(module), go_case_escape(version));
    dir.to_string_lossy()
        .replace('\\', "/")
        .strip_suffix(&wanted)
        .is_some_and(|before| before.is_empty() || before.ends_with('/'))
}

/// Go's module cache spells an upper-case ASCII letter as `!` and its
/// lower-case form (`github.com/Azure` is `github.com/!azure`), in a module
/// path and in a version alike. The same rule as the product's
/// `socket_patch_core::crawlers::go_crawler::encode_module_path`, written
/// out here so the fixture does not take the rule from the code under test.
fn go_case_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_ascii_uppercase() {
            escaped.push('!');
        }
        escaped.push(ch.to_ascii_lowercase());
    }
    escaped
}

/// The line the fixture server prints when it archives the stand-in of
/// `package_layout` for `purl` although the test handed it a cache for
/// that ecosystem; `None` when no such cache was handed over (the
/// stand-in is then the intended source). It is printed once per package
/// of a project: a later server for the same project serves the archive
/// already published. The stand-in holds the patched files and none of
/// the package's own, so a package that is installed and that `source_dir`
/// failed to find shows up far away, as a build that misses a file: the
/// line names the cause in that test's output. It is a notice and not a
/// failure because two tests hand over, on purpose, a Cargo home that
/// holds no crate, for a crate that is locked or patched and not
/// installed (`vendor_rerun_no_network_e2e`).
fn stand_in_notice(purl: &str, handed: &[CacheRoot]) -> Option<String> {
    let kind = purl
        .trim_start_matches("pkg:")
        .split('/')
        .next()
        .unwrap_or_default();
    let caches: Vec<String> = handed
        .iter()
        .filter(|(holds, _)| *holds == kind)
        .map(|(_, dir)| dir.display().to_string())
        .collect();
    (!caches.is_empty()).then(|| {
        format!(
            "prebuilt fixture: {purl} was not found in the project or under the cache \
             handed over ({}); serving the stand-in of package_layout",
            caches.join(", ")
        )
    })
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
    fs_tree::copy_tree(installed.unwrap_or(layout.path()), &source);
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
/// separate commands and retain their original flags. Every command also
/// gets the JVM isolation of `jvm_env::isolate_cli`: ambient Gradle / JVM
/// options scrubbed, `HOME` / `USERPROFILE` pinned to an empty stand-in, and
/// only the `jvm_env::EXPLICIT` caches named in `env` passed through.
pub fn prepare_command(
    command: &mut std::process::Command,
    root: &Path,
    args: &[&str],
    env: &[(&str, &str)],
) -> Option<Server> {
    // No ambient Gradle / JVM options and no real home (`common/jvm_env.rs`);
    // the explicit JVM caches a test hands over are kept.
    jvm_env::isolate_cli(command);
    for (key, value) in env {
        if jvm_env::EXPLICIT.contains(key) {
            command.env(key, value);
        }
    }
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

// ── Gradle `files-2.1` caches ─────────────────────────────────────────

/// The `files-2.1` tree under a `GRADLE_USER_HOME`.
pub const GRADLE_FILES21: &str = "caches/modules-2/files-2.1";
/// The `files-2.1` tree under a `GRADLE_RO_DEP_CACHE`.
pub const RO_FILES21: &str = "modules-2/files-2.1";
const GRADLE_FILES21_LEAF: &str = "files-2.1";

/// A `files-2.1` hash-dir name: 1-40 lowercase hex (Gradle may drop the
/// sha1's leading zeros).
pub fn is_sha1_dir(name: &str) -> bool {
    (1..=40).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `<group>/<artifact>/<version>/<sha1>/<leaf>` (relative to `files-2.1`)
/// → the maven2 route `/<group path>/<artifact>/<version>/<leaf>`.
fn files21_route(relative: &str) -> Option<String> {
    let parts: Vec<&str> = relative.split('/').collect();
    let [group, artifact, version, hash, leaf] = parts.as_slice() else {
        return None;
    };
    is_sha1_dir(hash).then(|| format!("/{}/{artifact}/{version}/{leaf}", group.replace('.', "/")))
}

/// The `<sha1>/` child of a `files-2.1` version dir that holds `leaf`.
fn files21_hash_child(dir: &Path, leaf: &str) -> Option<PathBuf> {
    let mut children: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| e.file_name().to_str().is_some_and(is_sha1_dir))
        .map(|e| e.path())
        .filter(|p| p.join(leaf).is_file())
        .collect();
    children.sort();
    children.into_iter().next()
}

/// `leaf` beside an installed jar: in `source` itself, or — for a
/// `files-2.1` hash dir — in a sibling hash dir of the same version.
fn maven_sibling(source: &Path, leaf: &str) -> Option<PathBuf> {
    let direct = source.join(leaf);
    if direct.is_file() {
        return Some(direct);
    }
    let name = source.file_name()?.to_str()?;
    if !is_sha1_dir(name) {
        return None;
    }
    files21_hash_child(source.parent()?, leaf).map(|dir| dir.join(leaf))
}

fn sha1_hex(bytes: &[u8]) -> String {
    hex::encode(sha1::Sha1::digest(bytes))
}

/// Lay `files` (`(leaf, bytes)`) out the way Gradle caches a download:
/// `<home>/caches/modules-2/files-2.1/<group>/<artifact>/<version>/<sha1>/<leaf>`,
/// each file under its own real sha1. `gav` is `group:artifact:version`.
/// Returns the version dir (what the crawler reports as the package path).
pub fn fabricate_files21(home: &Path, gav: &str, files: &[(&str, &[u8])]) -> PathBuf {
    fabricate_files21_named(home, gav, files, |sha1| sha1.to_string())
}

/// [`fabricate_files21`] with the hash dirs named the way Gradle releases
/// that format the sha1 as a number do: leading zeros dropped.
pub fn fabricate_files21_unpadded(home: &Path, gav: &str, files: &[(&str, &[u8])]) -> PathBuf {
    fabricate_files21_named(home, gav, files, |sha1| {
        let trimmed = sha1.trim_start_matches('0');
        if trimmed.is_empty() { "0" } else { trimmed }.to_string()
    })
}

fn fabricate_files21_named(
    home: &Path,
    gav: &str,
    files: &[(&str, &[u8])],
    name: impl Fn(&str) -> String,
) -> PathBuf {
    let mut parts = gav.splitn(3, ':');
    let (Some(group), Some(artifact), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        panic!("fabricate_files21: `{gav}` is not group:artifact:version");
    };
    let dir = home
        .join(GRADLE_FILES21)
        .join(group)
        .join(artifact)
        .join(version);
    for (leaf, bytes) in files {
        let hash_dir = dir.join(name(&sha1_hex(bytes)));
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(hash_dir.join(leaf), bytes).unwrap();
    }
    dir
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

// ── self-tests (integration crates get no cfg(test)) ───────────────────

mod prebuilt_common_selftests {
    use super::*;

    fn envs(cmd: &std::process::Command) -> HashMap<String, Option<String>> {
        cmd.get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect()
    }

    /// A stray GRADLE_OPTS (`-Dgradle.user.home` beats GRADLE_USER_HOME)
    /// never reaches the CLI; HOME is the empty stand-in; an explicit
    /// GRADLE_USER_HOME handed to `prepare_command` survives.
    #[test]
    fn prepare_command_scrubs_a_stray_gradle_opts() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cmd = std::process::Command::new("socket-patch");
        cmd.env("GRADLE_OPTS", "-Dgradle.user.home=/real/.gradle")
            .env("GRADLE_USER_HOME", "/real/.gradle")
            .env("JAVA_OPTS", "-Xmx1g");
        let gradle_home = tmp.path().join("gradle-home");
        let fixture = prepare_command(
            &mut cmd,
            tmp.path(),
            &["scan", "--json"],
            &[("GRADLE_USER_HOME", gradle_home.to_str().unwrap())],
        );
        assert!(fixture.is_none(), "scan needs no fixture server");
        let envs = envs(&cmd);
        assert_eq!(envs["GRADLE_OPTS"], None);
        assert_eq!(envs["JAVA_OPTS"], None);
        assert_eq!(envs["GRADLE_RO_DEP_CACHE"], None);
        assert_eq!(
            envs["GRADLE_USER_HOME"].as_deref(),
            gradle_home.to_str(),
            "the explicit cache wins"
        );
        let home = jvm_env::stand_in_home().to_string_lossy().into_owned();
        assert_eq!(envs["HOME"].as_deref(), Some(home.as_str()));
        assert_eq!(envs["USERPROFILE"].as_deref(), Some(home.as_str()));
        let args: Vec<_> = cmd.get_args().collect();
        assert_eq!(args, ["scan", "--json"]);
    }

    /// A purl spells a Go module path with `/`, and Windows lists the
    /// module cache with `\` (behind `\\?\` when the cache path was
    /// canonicalized). Under either separator the module's directory is
    /// the archive source: without it the fixture serves the stand-in of
    /// `package_layout`, which holds the patched files and none of the
    /// module's own.
    #[test]
    fn a_go_module_directory_is_found_under_either_path_separator() {
        let purl = "pkg:golang/example.com/m@v1.0.0";
        let root = Path::new("project");
        for found in [
            "/tmp/modcache/example.com/m@v1.0.0",
            r"C:\Temp\modcache\example.com\m@v1.0.0",
            r"\\?\C:\Temp\modcache\example.com\m@v1.0.0",
        ] {
            let listed = ["/tmp/modcache/example.com/m@v1.0.1", found].map(PathBuf::from);
            let source = source_dir(root, &listed, purl);
            assert_eq!(source, PathBuf::from(found), "{found}");
        }
        // Another version of the module is not its source.
        let other = [PathBuf::from(r"C:\Temp\modcache\example.com\m@v1.0.1")];
        assert_eq!(source_dir(root, &other, purl), root.join("missing"));
    }

    /// The module path is matched from a path-component boundary: the
    /// directory of a module on a longer host name (`sigs.k8s.io/x` beside
    /// `k8s.io/x`) ends with the same text and is another module.
    #[test]
    fn a_go_module_on_a_longer_host_is_not_taken() {
        let root = Path::new("project");
        for (purl, longer, own) in [
            (
                "pkg:golang/example.com/m@v1.0.0",
                "/tmp/modcache/notexample.com/m@v1.0.0",
                "/tmp/modcache/example.com/m@v1.0.0",
            ),
            (
                "pkg:golang/k8s.io/x@v0.1.0",
                r"C:\Temp\modcache\sigs.k8s.io\x@v0.1.0",
                r"C:\Temp\modcache\k8s.io\x@v0.1.0",
            ),
        ] {
            let alone = [PathBuf::from(longer)];
            assert_eq!(
                source_dir(root, &alone, purl),
                root.join("missing"),
                "{longer}"
            );
            let both = [longer, own].map(PathBuf::from);
            assert_eq!(source_dir(root, &both, purl), PathBuf::from(own), "{own}");
        }
        // A listed path that is the module directory and nothing more.
        let bare = [PathBuf::from("example.com/m@v1.0.0")];
        let purl = "pkg:golang/example.com/m@v1.0.0";
        assert_eq!(source_dir(root, &bare, purl), bare[0]);
    }

    /// Go's module cache spells an upper-case letter as `!` and its
    /// lower-case form, in the module path and in the version, and a purl
    /// keeps the letter: the escaped directory is the module's.
    #[test]
    fn a_go_module_directory_is_found_under_its_case_escaped_name() {
        assert_eq!(
            go_case_escape("github.com/Azure/go-autorest"),
            "github.com/!azure/go-autorest"
        );
        assert_eq!(go_case_escape("v1.0.0-RC1"), "v1.0.0-!r!c1");
        assert_eq!(go_case_escape("example.com/m"), "example.com/m");
        let root = Path::new("project");
        for (purl, found) in [
            (
                "pkg:golang/github.com/Azure/go-autorest@v14.2.0%2Bincompatible",
                "/tmp/modcache/github.com/!azure/go-autorest@v14.2.0+incompatible",
            ),
            (
                "pkg:golang/github.com/BurntSushi/toml@v1.3.2",
                r"C:\Temp\modcache\github.com\!burnt!sushi\toml@v1.3.2",
            ),
            (
                "pkg:golang/example.com/m@v1.0.0-RC1",
                "/tmp/modcache/example.com/m@v1.0.0-!r!c1",
            ),
        ] {
            let listed = [PathBuf::from(found)];
            assert_eq!(source_dir(root, &listed, purl), listed[0], "{purl}");
        }
        // The cache never holds the unescaped spelling; it is not matched.
        let unescaped = [PathBuf::from(
            "/tmp/modcache/github.com/Azure/go-autorest@v14.2.0",
        )];
        let purl = "pkg:golang/github.com/Azure/go-autorest@v14.2.0";
        assert_eq!(source_dir(root, &unescaped, purl), root.join("missing"));
    }

    /// The stand-in served for a package of an ecosystem the test handed a
    /// cache over for is announced with the purl and every such cache;
    /// with no cache for that ecosystem the stand-in is the intended
    /// source and nothing is said.
    #[test]
    fn a_stand_in_served_despite_a_handed_cache_is_announced() {
        let purl = "pkg:maven/com.example/lib@1.0.0";
        let (m2, gradle) = (PathBuf::from("m2-repo"), PathBuf::from("gradle-files"));
        assert_eq!(stand_in_notice(purl, &[]), None);
        assert_eq!(stand_in_notice(purl, &[("cargo", m2.clone())]), None);
        let handed = [
            ("maven", m2),
            ("golang", "modcache".into()),
            ("maven", gradle),
        ];
        let notice = stand_in_notice(purl, &handed).expect("two Maven caches were handed over");
        for part in [purl, "m2-repo", "gradle-files", "stand-in"] {
            assert!(notice.contains(part), "{part} is missing from: {notice}");
        }
        assert!(
            !notice.contains("modcache") && !notice.contains('\n'),
            "{notice}"
        );
    }

    #[test]
    fn files21_layout_routes_and_install_detection() {
        assert!(is_sha1_dir("0a1b") && is_sha1_dir(&"f".repeat(40)));
        assert!(!is_sha1_dir("") && !is_sha1_dir(&"a".repeat(41)) && !is_sha1_dir("ABC"));
        assert_eq!(
            files21_route("com.socketfixture/victim/1.10.0/0abc/victim-1.10.0.jar").as_deref(),
            Some("/com/socketfixture/victim/1.10.0/victim-1.10.0.jar")
        );
        assert_eq!(
            files21_route("com.socketfixture/victim/1.10.0/victim.jar"),
            None
        );
        assert_eq!(files21_route("g/a/v/not-a-hash/a-v.jar"), None);

        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("gradle-home");
        let jar: &[u8] = b"jar bytes";
        let pom: &[u8] = b"<project/>";
        let version_dir = fabricate_files21(
            &home,
            "com.socketfixture:victim:1.10.0",
            &[("victim-1.10.0.jar", jar), ("victim-1.10.0.pom", pom)],
        );
        assert_eq!(
            version_dir,
            home.join("caches/modules-2/files-2.1/com.socketfixture/victim/1.10.0")
        );
        let jar_dir = version_dir.join(sha1_hex(jar));
        assert_eq!(
            std::fs::read(jar_dir.join("victim-1.10.0.jar")).unwrap(),
            jar
        );
        assert!(version_dir
            .join(sha1_hex(pom))
            .join("victim-1.10.0.pom")
            .is_file());

        // The version dir resolves to the jar's hash dir, and the pom is
        // found beside it in its own hash dir.
        let purl = "pkg:maven/com.socketfixture/victim@1.10.0";
        let found = source_dir(tmp.path(), std::slice::from_ref(&version_dir), purl);
        assert_eq!(found, jar_dir);
        assert_eq!(
            maven_sibling(&found, "victim-1.10.0.pom"),
            Some(version_dir.join(sha1_hex(pom)).join("victim-1.10.0.pom"))
        );
        assert_eq!(maven_sibling(&found, "victim-1.10.0.module"), None);

        // Unpadded naming drops the sha1's leading zeros.
        let unpadded = fabricate_files21_unpadded(&home, "g:a:1", &[("a-1.jar", jar)]);
        let want = sha1_hex(jar).trim_start_matches('0').to_string();
        assert!(unpadded.join(want).join("a-1.jar").is_file());
    }
}
