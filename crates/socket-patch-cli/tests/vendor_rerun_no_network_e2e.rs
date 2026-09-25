//! An already-vendored project re-runs `vendor` with no network.
//!
//! The fresh-clone case: `.socket/vendor/` and the wired lockfile are
//! committed, the package itself is not installed (no `bundle install`, no
//! venv, an empty module/registry cache). The missing purl used to go
//! through the pristine-source ladder BEFORE the backend's in-sync check —
//! recovering the pre-vendor registry resolution from the ledger and
//! downloading the pristine artifact just to hand the backend a tree it
//! never reads on that path. With no network the download failed and so
//! did the run, for every already-vendored pypi, cargo, go and
//! lockfile-only gem package.
//!
//! The ladder now defers that download to the backend branch that reads
//! the tree, for a purl whose ledger entry records the record's patch uuid
//! and whose committed artifact is on disk. The backend's hot path answers
//! from the committed bytes, so the re-run is green (`already_vendored`),
//! makes no registry request, and no longer reports a
//! `vendor_fetched_missing` fetch it did not need — both with the registry
//! unreachable and under `--offline`.
//!
//! Hermetic: every registry base and the patch API point at a
//! guaranteed-dead local endpoint, and patch staging reads `.socket/blobs`.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn git_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("blob {}\0", content.len()).as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// A guaranteed-unreachable local endpoint: bind an ephemeral port, then
/// release it, so every request fails fast with connection-refused.
fn dead_endpoint() -> String {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    format!("http://127.0.0.1:{port}")
}

/// `.socket/manifest.json` with one patch and its after-blob.
fn write_manifest(root: &Path, purl: &str, uuid: &str, file: &str, before: &[u8], after: &[u8]) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let manifest = serde_json::json!({
        "patches": {
            purl: {
                "uuid": uuid,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": {
                    file: {
                        "beforeHash": git_sha256(before),
                        "afterHash": git_sha256(after),
                    }
                },
                "vulnerabilities": {},
                "description": "synthetic offline re-run patch",
                "license": "MIT",
                "tier": "free"
            }
        }
    });
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(git_sha256(after)), after).unwrap();
}

/// `vendor --json --vendor-source build` through the built binary with
/// every ambient `SOCKET_*` var scrubbed, the API and every registry base
/// pointed at `dead`, and `env` on top.
fn run_vendor(
    root: &Path,
    dead: &str,
    extra: &[&str],
    env: &[(&str, &str)],
) -> (i32, serde_json::Value, String) {
    let mut cmd = Command::new(binary());
    cmd.args([
        "vendor",
        "--json",
        "--vendor-source",
        "build",
        "--api-url",
        dead,
        "--proxy-url",
        dead,
        "--api-token",
        "fake-token",
        "--org",
        "test-org",
    ])
    .args(extra)
    .current_dir(root);
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
            cmd.env_remove(key);
        }
    }
    for var in ["VIRTUAL_ENV", "CONDA_PREFIX", "BUNDLE_PATH", "GEM_HOME"] {
        cmd.env_remove(var);
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_CRATES_REGISTRY", dead)
        .env("SOCKET_GOPROXY", dead)
        .env("SOCKET_PYPI_JSON_API", dead)
        .env("SOCKET_NPM_REGISTRY", dead)
        .env("GOFLAGS", "-mod=mod")
        .envs(env.iter().copied());
    let out = cmd.output().expect("run socket-patch vendor");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("vendor --json must emit JSON: {e}\n{stdout}\n{stderr}"));
    (out.status.code().unwrap_or(-1), v, stderr)
}

/// `(action, errorCode)` of every event for `purl`, in order.
fn purl_events<'a>(v: &'a serde_json::Value, purl: &str) -> Vec<(&'a str, &'a str)> {
    v["events"]
        .as_array()
        .expect("events array")
        .iter()
        .filter(|e| e["purl"] == purl)
        .map(|e| {
            (
                e["action"].as_str().unwrap_or_default(),
                e["errorCode"].as_str().unwrap_or_default(),
            )
        })
        .collect()
}

/// Vendor with the package installed, take the installed copy away, then
/// re-run twice — registry unreachable, and `--offline` — and require the
/// in-sync outcome with nothing fetched and nothing rewritten.
fn assert_rerun_green_without_network(
    root: &Path,
    purl: &str,
    uninstall: impl FnOnce(&Path),
    env: &[(&str, &str)],
) {
    let dead = dead_endpoint();
    let (code, v, stderr) = run_vendor(root, &dead, &[], env);
    assert_eq!(
        code, 0,
        "run 1 vendors the installed package: {v:#}\n{stderr}"
    );
    assert!(
        purl_events(&v, purl).contains(&("applied", "")),
        "run 1 must vendor {purl}: {v:#}"
    );
    let snapshot = snapshot_tree(root);

    // Fresh clone: the committed artifact + wired lock, nothing installed.
    uninstall(root);
    let snapshot_after_uninstall = snapshot_tree(root);

    for extra in [&[][..], &["--offline"][..]] {
        let (code, v, stderr) = run_vendor(root, &dead, extra, env);
        assert_eq!(
            code, 0,
            "an in-sync re-run needs no network ({extra:?}): {v:#}\n{stderr}"
        );
        assert_eq!(v["status"], "success", "{extra:?}: {v:#}");
        assert_eq!(
            purl_events(&v, purl),
            vec![("skipped", "already_vendored")],
            "the hot path answers from the committed artifact; no fetch is \
             attempted or reported ({extra:?}): {v:#}"
        );
        assert_eq!(
            snapshot_tree(root),
            snapshot_after_uninstall,
            "an in-sync re-run writes nothing ({extra:?})"
        );
    }
    // The run-1 artifact and wiring are what the re-runs found in place.
    for (rel, bytes) in &snapshot {
        if rel.starts_with(".socket/") {
            assert_eq!(
                std::fs::read(root.join(rel)).ok().as_ref(),
                Some(bytes),
                "{rel} changed across the re-runs"
            );
        }
    }
}

/// Every regular file under `root` (relative path → bytes), sorted.
fn snapshot_tree(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let ft = entry.file_type().unwrap();
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                let rel = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, std::fs::read(&path).unwrap()));
            }
        }
    }
    out.sort();
    out
}

// ── pypi ────────────────────────────────────────────────────────────────

#[test]
fn pypi_rerun_without_network_is_in_sync() {
    const PURL: &str = "pkg:pypi/six@1.16.0";
    const UUID: &str = "2b1f6c1e-8d3a-4f6b-9c2d-7e5a9b1c3d01";
    const ORIG: &[u8] = b"# six\nVERSION = '1.16.0'\n";
    const PATCHED: &[u8] = b"# six\nVERSION = '1.16.0'\nSAFE = True\n";
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // A hash-pinned requirement: the ledger-recovered pre-vendor line is
    // then fetchable, so the old ladder really went to the registry.
    std::fs::write(
        root.join("requirements.txt"),
        format!("six==1.16.0 --hash=sha256:{}\n", "a".repeat(64)),
    )
    .unwrap();
    let sp = if cfg!(windows) {
        root.join(".venv/Lib/site-packages")
    } else {
        root.join(".venv/lib/python3.12/site-packages")
    };
    let di = sp.join("six-1.16.0.dist-info");
    std::fs::create_dir_all(&di).unwrap();
    std::fs::write(sp.join("six.py"), ORIG).unwrap();
    std::fs::write(
        di.join("METADATA"),
        "Metadata-Version: 2.1\nName: six\nVersion: 1.16.0\n\nbody\n",
    )
    .unwrap();
    std::fs::write(
        di.join("WHEEL"),
        "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py2-none-any\nTag: py3-none-any\n",
    )
    .unwrap();
    std::fs::write(
        di.join("RECORD"),
        "six.py,sha256=AAAA,20\nsix-1.16.0.dist-info/METADATA,,\n\
         six-1.16.0.dist-info/WHEEL,,\nsix-1.16.0.dist-info/RECORD,,\n",
    )
    .unwrap();
    write_manifest(root, PURL, UUID, "six.py", ORIG, PATCHED);

    assert_rerun_green_without_network(
        root,
        PURL,
        |root| std::fs::remove_dir_all(root.join(".venv")).unwrap(),
        &[],
    );
}

// ── cargo ───────────────────────────────────────────────────────────────

#[test]
fn cargo_rerun_without_network_is_in_sync() {
    const PURL: &str = "pkg:cargo/cfg-if@1.0.4";
    const UUID: &str = "2b1f6c1e-8d3a-4f6b-9c2d-7e5a9b1c3d02";
    const PRISTINE: &[u8] = b"pub fn cfg() {}\n";
    const PATCHED: &[u8] = b"pub fn cfg() { /* patched */ }\n";
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("proj");
    let cargo_home = tmp.path().join("cargo-home");
    let krate = cargo_home.join("registry/src/index.crates.io-6f17d22bba15001f/cfg-if-1.0.4");
    std::fs::create_dir_all(krate.join("src")).unwrap();
    std::fs::write(krate.join("src/lib.rs"), PRISTINE).unwrap();
    std::fs::write(
        krate.join("Cargo.toml"),
        "[package]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n",
    )
    .unwrap();
    std::fs::write(krate.join(".cargo-checksum.json"), "{\"files\":{}}").unwrap();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ncfg-if = \"1\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("Cargo.lock"),
        format!(
            "# This file is automatically @generated by Cargo.\n\
             # It is not intended for manual editing.\n\
             version = 4\n\n\
             [[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
             dependencies = [\n \"cfg-if\",\n]\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"{}\"\n",
            "9".repeat(64)
        ),
    )
    .unwrap();
    write_manifest(&root, PURL, UUID, "package/src/lib.rs", PRISTINE, PATCHED);

    let home = cargo_home.to_string_lossy().into_owned();
    assert_rerun_green_without_network(
        &root,
        PURL,
        |_| std::fs::remove_dir_all(&krate).unwrap(),
        &[("CARGO_HOME", home.as_str())],
    );
}

// ── golang ──────────────────────────────────────────────────────────────

/// The go.sum `h1:` dirhash of a module zip holding `files` under the
/// `<module>@<version>/` prefix.
fn go_h1(module: &str, version: &str, files: &[(&str, &[u8])]) -> String {
    use base64::Engine as _;
    let mut lines: Vec<String> = files
        .iter()
        .map(|(name, bytes)| {
            format!(
                "{}  {module}@{version}/{name}\n",
                hex::encode(Sha256::digest(bytes))
            )
        })
        .collect();
    lines.sort();
    let summary = Sha256::digest(lines.concat().as_bytes());
    format!(
        "h1:{}",
        base64::engine::general_purpose::STANDARD.encode(summary)
    )
}

#[test]
fn golang_rerun_without_network_is_in_sync() {
    const MODULE: &str = "github.com/foo/bar";
    const VERSION: &str = "v1.4.2";
    const PURL: &str = "pkg:golang/github.com/foo/bar@v1.4.2";
    const UUID: &str = "2b1f6c1e-8d3a-4f6b-9c2d-7e5a9b1c3d03";
    const PRISTINE: &[u8] = b"package bar\n\nfunc Hello() string { return \"hi\" }\n";
    const PATCHED: &[u8] = b"package bar\n\nfunc Hello() string { return \"patched\" }\n";
    const MOD: &[u8] = b"module github.com/foo/bar\n\ngo 1.21\n";
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("proj");
    let modcache = tmp.path().join("modcache");
    let module_dir = modcache.join(format!("{MODULE}@{VERSION}"));
    std::fs::create_dir_all(&module_dir).unwrap();
    std::fs::write(module_dir.join("bar.go"), PRISTINE).unwrap();
    std::fs::write(module_dir.join("go.mod"), MOD).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("go.mod"),
        format!("module example.com/app\n\ngo 1.21\n\nrequire {MODULE} {VERSION}\n"),
    )
    .unwrap();
    // A verifiable go.sum pin: the old ladder fetched it from GOPROXY.
    std::fs::write(
        root.join("go.sum"),
        format!(
            "{MODULE} {VERSION} {}\n",
            go_h1(MODULE, VERSION, &[("bar.go", PRISTINE), ("go.mod", MOD)])
        ),
    )
    .unwrap();
    write_manifest(&root, PURL, UUID, "package/bar.go", PRISTINE, PATCHED);

    let cache = modcache.to_string_lossy().into_owned();
    assert_rerun_green_without_network(
        &root,
        PURL,
        |_| std::fs::remove_dir_all(&module_dir).unwrap(),
        &[("GOMODCACHE", cache.as_str())],
    );
}

// ── gem (lockfile-only) ─────────────────────────────────────────────────

const GEM_NAME: &str = "socketfixturegem";
const GEM_VERSION: &str = "1.0.0";
const GEM_PURL: &str = "pkg:gem/socketfixturegem@1.0.0";
const GEM_LIB: &str = "lib/socketfixturegem.rb";
const GEM_PRISTINE: &[u8] = b"module SocketFixtureGem; VERSION = '1.0.0'; end\n";
const GEM_PATCHED: &[u8] = b"module SocketFixtureGem; VERSION = '1.0.0'; SAFE = true; end\n";

/// Gemfile + a bundler >= 2.6 Gemfile.lock (CHECKSUMS pin, so the gem is
/// fetchable from `remote`) + the manifest.
fn write_gem_project(root: &Path, remote: &str, uuid: &str) {
    std::fs::write(
        root.join("Gemfile"),
        format!("source \"{remote}\"\ngem \"{GEM_NAME}\"\n"),
    )
    .unwrap();
    std::fs::write(
        root.join("Gemfile.lock"),
        format!(
            "GEM\n  remote: {remote}\n  specs:\n    {GEM_NAME} ({GEM_VERSION})\n\n\
             PLATFORMS\n  ruby\n\n\
             DEPENDENCIES\n  {GEM_NAME}\n\n\
             CHECKSUMS\n  {GEM_NAME} ({GEM_VERSION}) sha256={}\n\n\
             BUNDLED WITH\n   2.6.2\n",
            "b".repeat(64)
        ),
    )
    .unwrap();
    write_manifest(root, GEM_PURL, uuid, GEM_LIB, GEM_PRISTINE, GEM_PATCHED);
}

/// A `bundle install --path vendor/bundle` deployment of the gem: the
/// unpacked gem and the eval-able stub rubygems writes beside it.
fn install_gem(root: &Path) {
    let leaf = format!("{GEM_NAME}-{GEM_VERSION}");
    let bundle = root.join("vendor").join("bundle");
    let gem_dir = bundle.join("gems").join(&leaf);
    std::fs::create_dir_all(gem_dir.join("lib")).unwrap();
    std::fs::write(gem_dir.join(GEM_LIB), GEM_PRISTINE).unwrap();
    let specs = bundle.join("specifications");
    std::fs::create_dir_all(&specs).unwrap();
    std::fs::write(
        specs.join(format!("{leaf}.gemspec")),
        format!(
            "Gem::Specification.new do |s|\n  s.name = \"{GEM_NAME}\"\n  \
             s.version = \"{GEM_VERSION}\"\n  s.summary = \"a synthetic fixture gem\"\n  \
             s.authors = [\"Socket\"]\n  s.require_paths = [\"lib\"]\nend\n"
        ),
    )
    .unwrap();
}

#[test]
fn gem_rerun_without_network_is_in_sync() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let remote = dead_endpoint();
    write_gem_project(root, &remote, "2b1f6c1e-8d3a-4f6b-9c2d-7e5a9b1c3d04");
    install_gem(root);

    assert_rerun_green_without_network(
        root,
        GEM_PURL,
        |root| std::fs::remove_dir_all(root.join("vendor")).unwrap(),
        &[],
    );
}

/// A not-installed gem that a lock CAN verify, and that no ledger entry
/// covers, cannot be vendored by a local build (no stub gemspec comes with
/// a downloaded `.gem`): build mode refuses it `gem_spec_missing` BEFORE
/// downloading it, instead of downloading it and then refusing.
#[tokio::test]
async fn gem_build_mode_refuses_a_lockfile_only_gem_before_downloading_it() {
    use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};
    let registry = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"not a gem".to_vec()))
        .mount(&registry)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_gem_project(
        root,
        &registry.uri(),
        "2b1f6c1e-8d3a-4f6b-9c2d-7e5a9b1c3d05",
    );

    let (code, v, stderr) = run_vendor(root, &dead_endpoint(), &[], &[]);

    assert_eq!(code, 1, "{v:#}\n{stderr}");
    assert!(
        registry
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "build mode cannot use a fetched gem, so it must not download one"
    );
    assert_eq!(
        purl_events(&v, GEM_PURL),
        vec![("failed", "gem_spec_missing")],
        "{v:#}"
    );
    assert!(!root.join(".socket/vendor").exists(), "nothing is written");
}

/// The deferral only moves the download; it never hides one the backend
/// needs. A committed copy that no longer verifies is rebuilt from the
/// pristine source, so that re-run fetches — and with the registry
/// unreachable reports the same `vendor_fetch_failed` the eager ladder
/// did, leaving the tampered copy for `repair`; under `--offline` the same
/// calm `package_not_installed` skip.
#[test]
fn cargo_rerun_over_a_drifted_copy_still_fetches_and_reports_it() {
    const PURL: &str = "pkg:cargo/cfg-if@1.0.4";
    const UUID: &str = "2b1f6c1e-8d3a-4f6b-9c2d-7e5a9b1c3d06";
    const PRISTINE: &[u8] = b"pub fn cfg() {}\n";
    const PATCHED: &[u8] = b"pub fn cfg() { /* patched */ }\n";
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("proj");
    let cargo_home = tmp.path().join("cargo-home");
    let krate = cargo_home.join("registry/src/index.crates.io-6f17d22bba15001f/cfg-if-1.0.4");
    std::fs::create_dir_all(krate.join("src")).unwrap();
    std::fs::write(krate.join("src/lib.rs"), PRISTINE).unwrap();
    std::fs::write(
        krate.join("Cargo.toml"),
        "[package]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ncfg-if = \"1\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("Cargo.lock"),
        format!(
            "version = 4\n\n\
             [[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
             dependencies = [\n \"cfg-if\",\n]\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"{}\"\n",
            "9".repeat(64)
        ),
    )
    .unwrap();
    write_manifest(&root, PURL, UUID, "package/src/lib.rs", PRISTINE, PATCHED);
    let home = cargo_home.to_string_lossy().into_owned();
    let env = [("CARGO_HOME", home.as_str())];
    let dead = dead_endpoint();

    let (code, v, stderr) = run_vendor(&root, &dead, &[], &env);
    assert_eq!(code, 0, "{v:#}\n{stderr}");
    std::fs::remove_dir_all(&krate).unwrap();
    let copy_lib = root.join(format!(
        ".socket/vendor/cargo/{UUID}/cfg-if-1.0.4/src/lib.rs"
    ));
    std::fs::write(&copy_lib, b"tampered\n").unwrap();

    let (code, v, stderr) = run_vendor(&root, &dead, &[], &env);
    assert_eq!(code, 1, "{v:#}\n{stderr}");
    assert_eq!(
        purl_events(&v, PURL),
        vec![("failed", "vendor_fetch_failed")],
        "{v:#}"
    );
    assert_eq!(std::fs::read(&copy_lib).unwrap(), b"tampered\n");

    let (code, v, stderr) = run_vendor(&root, &dead, &["--offline"], &env);
    assert_eq!(code, 1, "{v:#}\n{stderr}");
    assert_eq!(
        purl_events(&v, PURL),
        vec![("skipped", "package_not_installed")],
        "{v:#}"
    );
}

// ── cargo: the service path needs no pristine source ─────────────────────

/// A `.crate`: a tar.gz with a single `{prefix}/` top-level dir.
fn make_crate(prefix: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write as _;
    let mut builder = tar::Builder::new(Vec::new());
    for (rel, content) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, format!("{prefix}/{rel}"), *content)
            .unwrap();
    }
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&builder.into_inner().unwrap()).unwrap();
    enc.finish().unwrap()
}

/// A lockfile-only cargo crate the patch service serves prebuilt: the
/// backend reads the pristine source only once `cargo_service_copy` falls
/// back to the local build, so the registry download is deferred until
/// then — here, never. (The eager ladder downloaded and verified the
/// pristine `.crate` first, and reported `vendor_fetched_missing` for it.)
#[tokio::test]
async fn cargo_service_vendor_never_downloads_the_pristine_crate() {
    use base64::Engine as _;
    use sha2::Sha512;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    const PURL: &str = "pkg:cargo/cfg-if@1.0.4";
    const UUID: &str = "2b1f6c1e-8d3a-4f6b-9c2d-7e5a9b1c3d07";
    const PRISTINE: &[u8] = b"pub fn cfg() {}\n";
    const PATCHED: &[u8] = b"pub fn cfg() { /* patched */ }\n";
    const TOML: &[u8] = b"[package]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n";

    let registry = MockServer::start().await;
    let pristine = make_crate(
        "cfg-if-1.0.4",
        &[("Cargo.toml", TOML), ("src/lib.rs", PRISTINE)],
    );
    let checksum = hex::encode(Sha256::digest(&pristine));
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(pristine))
        .mount(&registry)
        .await;

    let api = MockServer::start().await;
    let prebuilt = make_crate(
        "cfg-if-1.0.4",
        &[("Cargo.toml", TOML), ("src/lib.rs", PATCHED)],
    );
    let sha512 = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&prebuilt))
    );
    let serve_path = format!("/patch/cargo/cfg-if/1.0.4/tok/{UUID}/cfg-if-1.0.4.crate");
    let serve_url = format!("{}{serve_path}", api.uri());
    Mock::given(method("POST"))
        .and(path("/v0/orgs/acme/patches/package"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": { UUID: {
                "status": "granted", "url": serve_url, "purl": PURL,
                "artifacts": [{ "kind": "tarball", "url": serve_url,
                                "integrity": { "sha512": sha512 } }]
            }}
        })))
        .mount(&api)
        .await;
    Mock::given(method("GET"))
        .and(path(serve_path))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(prebuilt))
        .mount(&api)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("proj");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ncfg-if = \"1\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("Cargo.lock"),
        format!(
            "version = 4\n\n\
             [[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
             dependencies = [\n \"cfg-if\",\n]\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"{checksum}\"\n"
        ),
    )
    .unwrap();
    write_manifest(&root, PURL, UUID, "package/src/lib.rs", PRISTINE, PATCHED);
    let empty_home = tmp.path().join("cargo-home");
    std::fs::create_dir_all(&empty_home).unwrap();

    let mut cmd = Command::new(binary());
    cmd.args([
        "vendor",
        "--json",
        "--vendor-source",
        "auto",
        "--api-url",
        &api.uri(),
        "--api-token",
        "sktsec_placeholder_value_for_tests_api",
        "--org",
        "acme",
    ])
    .current_dir(&root);
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
            cmd.env_remove(key);
        }
    }
    let out = cmd
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_CRATES_REGISTRY", registry.uri())
        .env("CARGO_HOME", &empty_home)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("{e}: {stdout}\n{}", String::from_utf8_lossy(&out.stderr)));

    assert_eq!(out.status.code(), Some(0), "{v:#}");
    let events = purl_events(&v, PURL);
    assert!(events.contains(&("applied", "")), "{v:#}");
    assert!(
        !events.contains(&("skipped", "vendor_fetched_missing")),
        "no pristine fetch happened, so none is reported: {v:#}"
    );
    assert!(
        registry
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "the service served the crate; the registry was never asked"
    );
    assert_eq!(
        std::fs::read(root.join(format!(
            ".socket/vendor/cargo/{UUID}/cfg-if-1.0.4/src/lib.rs"
        )))
        .unwrap(),
        PATCHED
    );
}
