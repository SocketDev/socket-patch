//! Service vendoring of portable gems without a local install or registry fetch.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path as wm_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A name nothing on the developer's machine can have installed, so the
/// crawler always reports the package missing.
const NAME: &str = "socketfixturegem";
const VERSION: &str = "1.0.0";
const PURL: &str = "pkg:gem/socketfixturegem@1.0.0";
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const LIB: &str = "lib/socketfixturegem.rb";
const PRISTINE: &[u8] = b"module SocketFixtureGem; VERSION = '1.0.0'; end\n";
const PATCHED: &[u8] = b"module SocketFixtureGem; VERSION = '1.0.0'; SAFE = true; end\n";

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn git_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("blob {}\0", content.len()).as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// A minimal `.gem`: an uncompressed tar whose only entry the fetcher reads
/// is `data.tar.gz`, itself a gzipped tar of the gem's files at the root.
fn make_gem() -> Vec<u8> {
    let mut data = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(PRISTINE.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    data.append_data(&mut header, LIB, PRISTINE).unwrap();
    let data_tar = data.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut gz, &data_tar).unwrap();
    let data_tar_gz = gz.finish().unwrap();

    let mut gem = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(data_tar_gz.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    gem.append_data(&mut header, "data.tar.gz", data_tar_gz.as_slice())
        .unwrap();
    gem.into_inner().unwrap()
}

/// Gemfile + a bundler >= 2.6 Gemfile.lock resolving the gem against
/// `remote` with a CHECKSUMS pin (the fetch layer refuses an entry with no
/// verifier, so without this nothing would ever be downloaded), plus the
/// manifest and staged after-blob.
fn write_fixture(root: &Path, remote: &str, gem_sha256: &str) {
    std::fs::write(
        root.join("Gemfile"),
        format!("source \"{remote}\"\ngem \"{NAME}\"\n"),
    )
    .unwrap();
    std::fs::write(
        root.join("Gemfile.lock"),
        format!(
            "GEM\n  remote: {remote}\n  specs:\n    {NAME} ({VERSION})\n\n\
             PLATFORMS\n  ruby\n\n\
             DEPENDENCIES\n  {NAME}\n\n\
             CHECKSUMS\n  {NAME} ({VERSION}) sha256={gem_sha256}\n\n\
             BUNDLED WITH\n   2.6.2\n"
        ),
    )
    .unwrap();

    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let manifest = serde_json::json!({
        "patches": {
            PURL: {
                "uuid": UUID,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": {
                    LIB: {
                        "beforeHash": git_sha256(PRISTINE),
                        "afterHash": git_sha256(PATCHED),
                    }
                },
                "vulnerabilities": {},
                "description": "synthetic gem vendor test patch",
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
    std::fs::write(socket.join("blobs").join(git_sha256(PATCHED)), PATCHED).unwrap();
}

/// Install the gem the way a `bundle install --path vendor/bundle`
/// deployment does: the unpacked gem under `vendor/bundle/gems/<leaf>/` and
/// the eval-able stub rubygems writes beside it in
/// `vendor/bundle/specifications/<leaf>.gemspec` (with the `summary` +
/// `authors` rubygems requires, which the local-build write choke point
/// re-validates).
fn install_gem(root: &Path) {
    let leaf = format!("{NAME}-{VERSION}");
    let bundle = root.join("vendor").join("bundle");
    let gem_dir = bundle.join("gems").join(&leaf);
    std::fs::create_dir_all(gem_dir.join("lib")).unwrap();
    std::fs::write(gem_dir.join(LIB), PRISTINE).unwrap();
    let specs = bundle.join("specifications");
    std::fs::create_dir_all(&specs).unwrap();
    std::fs::write(
        specs.join(format!("{leaf}.gemspec")),
        format!(
            "Gem::Specification.new do |s|\n  s.name = \"{NAME}\"\n  \
             s.version = \"{VERSION}\"\n  s.summary = \"a synthetic fixture gem\"\n  \
             s.authors = [\"Socket\"]\n  s.require_paths = [\"lib\"]\nend\n"
        ),
    )
    .unwrap();
}

async fn mount_gem_download(mock: &MockServer, gem: Vec<u8>) {
    Mock::given(method("GET"))
        .and(wm_path(format!("/downloads/{NAME}-{VERSION}.gem")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(gem))
        .mount(mock)
        .await;
}

/// `vendor --json --vendor-source <source>` through the built binary, with
/// every ambient `SOCKET_*` var scrubbed and the API pointed at a
/// guaranteed-dead endpoint (patch staging is satisfied from
/// `.socket/blobs`, so nothing should reach it).
fn run_vendor(root: &Path, source: &str, api_url: &str) -> (i32, serde_json::Value, String) {
    let mut cmd = Command::new(binary());
    cmd.args([
        "vendor",
        "--json",
        "--vendor-source",
        source,
        "--api-url",
        api_url,
        "--proxy-url",
        api_url,
        "--api-token",
        "fake-token",
        "--org",
        "test-org",
    ])
    .current_dir(root);
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
            cmd.env_remove(key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let fixture = crate::prebuilt_common::Server::project(root);
    fixture.command(&mut cmd);
    let out = cmd.output().expect("run socket-patch vendor");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("vendor --json must emit JSON: {e}\n{stdout}\n{stderr}"));
    (out.status.code().unwrap_or(-1), v, stderr)
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

fn failed_event(v: &serde_json::Value) -> &serde_json::Value {
    v["events"]
        .as_array()
        .expect("events array")
        .iter()
        .find(|e| e["action"] == "failed")
        .unwrap_or_else(|| panic!("expected a failed event in:\n{v:#}"))
}

#[tokio::test]
async fn service_vendors_a_lockfile_only_gem_with_its_server_stub() {
    let mock = MockServer::start().await;
    mount_gem_download(&mock, make_gem()).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path(), &mock.uri(), &"0".repeat(64));
    let (code, v, stderr) = run_vendor(tmp.path(), "service", &dead_endpoint());
    assert_eq!(code, 0, "{v:#}\n{stderr}");
    let dir = tmp
        .path()
        .join(format!(".socket/vendor/gem/{UUID}/{NAME}-{VERSION}"));
    assert_eq!(std::fs::read(dir.join(LIB)).unwrap(), PATCHED);
    assert!(dir.join(format!("{NAME}.gemspec")).is_file());
    assert!(mock.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn auto_alias_does_not_fetch_the_registry_gem() {
    let mock = MockServer::start().await;
    mount_gem_download(&mock, make_gem()).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path(), &mock.uri(), &"0".repeat(64));
    let (code, v, stderr) = run_vendor(tmp.path(), "auto", &dead_endpoint());
    assert_eq!(code, 0, "{v:#}\n{stderr}");
    assert!(mock.received_requests().await.unwrap().is_empty());
}

#[test]
fn a_gem_without_a_lockfile_is_refused_before_downloading() {
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path(), "https://rubygems.org", &"0".repeat(64));
    std::fs::remove_file(tmp.path().join("Gemfile.lock")).unwrap();
    let (code, v, stderr) = run_vendor(tmp.path(), "service", &dead_endpoint());
    assert_eq!(code, 1, "{v:#}\n{stderr}");
    assert_eq!(
        failed_event(&v)["errorCode"],
        "vendor_lockfile_missing",
        "{v:#}"
    );
}

#[tokio::test]
async fn service_integrity_supports_old_bundler_locks_without_checksums() {
    let mock = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path(), &mock.uri(), &"0".repeat(64));
    let lock = tmp.path().join("Gemfile.lock");
    let text = std::fs::read_to_string(&lock).unwrap();
    let start = text.find("CHECKSUMS\n").unwrap();
    let end = text.find("BUNDLED WITH\n").unwrap();
    std::fs::write(&lock, format!("{}{}", &text[..start], &text[end..])).unwrap();
    let (code, v, stderr) = run_vendor(tmp.path(), "service", &dead_endpoint());
    assert_eq!(code, 0, "{v:#}\n{stderr}");
    assert!(mock.received_requests().await.unwrap().is_empty());
}

#[test]
fn an_already_vendored_gem_is_reused_without_an_installed_copy() {
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path(), &dead_endpoint(), &"0".repeat(64));
    install_gem(tmp.path());
    let (code, v, stderr) = run_vendor(tmp.path(), "service", &dead_endpoint());
    assert_eq!(code, 0, "{v:#}\n{stderr}");
    std::fs::remove_dir_all(tmp.path().join("vendor")).unwrap();
    let (code, v, stderr) = run_vendor(tmp.path(), "service", &dead_endpoint());
    assert_eq!(code, 0, "{v:#}\n{stderr}");
    assert!(
        v["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["errorCode"] == "already_vendored"),
        "{v:#}"
    );
}
