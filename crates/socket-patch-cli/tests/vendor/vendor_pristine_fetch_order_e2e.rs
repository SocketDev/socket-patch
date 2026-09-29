//! `vendor` over several lockfile-only packages: the pristine registry
//! fetches run concurrently, and every package's outcome must still be
//! exactly the one-at-a-time loop's — here with the registry answering the
//! later packages first and a mix of verified, tampered and unverifiable
//! lock entries. Mock registry + a real npm lockfile fixture, driven
//! through the built binary.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const BEFORE: &[u8] = b"before\n";
const AFTER: &[u8] = b"after\n";

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn sri_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::Sha512;
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
    )
}

/// A pristine registry tarball whose index.js carries the BEFORE bytes.
fn pristine_tgz(name: &str) -> Vec<u8> {
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    let pkg_json = format!(r#"{{"name":"{name}","version":"1.0.0"}}"#);
    for (path, bytes) in [
        ("package/package.json", pkg_json.as_bytes()),
        ("package/index.js", BEFORE),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, bytes).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// How the lockfile records one package.
enum Lock {
    /// The registry tarball's real integrity.
    Verified,
    /// An integrity the served bytes do not match (tampered).
    Tampered,
    /// No integrity at all (unverifiable).
    Missing,
}

#[tokio::test]
async fn lockfile_only_packages_fetch_concurrently_with_serial_outcomes() {
    let mock = MockServer::start().await;
    // Earlier packages answer last.
    let packages: [(&str, Lock, u64); 5] = [
        ("pa", Lock::Verified, 500),
        ("pb", Lock::Tampered, 400),
        ("pc", Lock::Verified, 300),
        ("pd", Lock::Missing, 200),
        ("pe", Lock::Verified, 0),
    ];
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let mut deps = serde_json::Map::new();
    let mut lock_packages = serde_json::Map::new();
    let mut patches = serde_json::Map::new();
    for (i, (name, lock, delay)) in packages.iter().enumerate() {
        let tgz = pristine_tgz(name);
        let tgz_path = format!("/{name}/-/{name}-1.0.0.tgz");
        let mut entry = serde_json::json!({
            "version": "1.0.0",
            "resolved": format!("{}{tgz_path}", mock.uri()),
        });
        match lock {
            Lock::Verified => entry["integrity"] = sri_of(&tgz).into(),
            Lock::Tampered => entry["integrity"] = sri_of(b"other bytes").into(),
            Lock::Missing => {}
        }
        Mock::given(method("GET"))
            .and(path(tgz_path))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(tgz)
                    .set_delay(Duration::from_millis(*delay)),
            )
            .mount(&mock)
            .await;
        deps.insert(name.to_string(), "^1.0.0".into());
        lock_packages.insert(format!("node_modules/{name}"), entry);
        patches.insert(
            format!("pkg:npm/{name}@1.0.0"),
            serde_json::json!({
                "uuid": format!("{i:08x}-1111-4111-8111-111111111111"),
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": { "package/index.js": {
                    "beforeHash": git_sha256(BEFORE),
                    "afterHash": git_sha256(AFTER),
                }},
                "vulnerabilities": {},
                "description": "synthetic",
                "license": "MIT",
                "tier": "free"
            }),
        );
    }
    let manifest =
        serde_json::json!({ "name": "order-test", "version": "0.0.0", "dependencies": deps });
    std::fs::write(root.join("package.json"), manifest.to_string()).unwrap();
    lock_packages.insert(
        String::new(),
        serde_json::json!({ "name": "order-test", "version": "0.0.0", "dependencies": deps }),
    );
    let lock = serde_json::json!({
        "name": "order-test",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": lock_packages,
    });
    std::fs::write(
        root.join("package-lock.json"),
        serde_json::to_vec_pretty(&lock).unwrap(),
    )
    .unwrap();
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({ "patches": patches })).unwrap(),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(git_sha256(AFTER)), AFTER).unwrap();

    let out = Command::new(binary())
        .args(["vendor", "--json", "--vendor-source", "build"])
        .current_dir(root)
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .output()
        .expect("run vendor");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "vendor --json must emit JSON: {e}\n{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    assert_ne!(
        out.status.code(),
        Some(0),
        "the tampered entry fails: {v:#}"
    );
    let events = v["events"].as_array().unwrap();
    let has = |purl: &str, action: &str, code: Option<&str>| {
        events.iter().any(|e| {
            e["purl"] == purl && e["action"] == action && code.is_none_or(|c| e["errorCode"] == c)
        })
    };
    for name in ["pa", "pc", "pe"] {
        let purl = format!("pkg:npm/{name}@1.0.0");
        assert!(has(&purl, "applied", None), "{purl}: {v:#}");
        assert!(
            events
                .iter()
                .any(|e| e["purl"] == purl.as_str() && e["errorCode"] == "vendor_fetched_missing"),
            "{purl}: {v:#}"
        );
        assert!(root
            .join(format!(
                ".socket/vendor/npm/{}/{name}-1.0.0.tgz",
                patches[&purl]["uuid"].as_str().unwrap()
            ))
            .is_file());
    }
    assert!(
        has("pkg:npm/pb@1.0.0", "failed", Some("vendor_fetch_failed")),
        "{v:#}"
    );
    assert!(
        events
            .iter()
            .any(|e| e["purl"] == "pkg:npm/pd@1.0.0"
                && e["errorCode"] == "vendor_fetch_unverifiable"),
        "{v:#}"
    );
    assert!(
        !has("pkg:npm/pb@1.0.0", "skipped", Some("package_not_installed")),
        "no duplicate not-installed skip for a failed fetch: {v:#}"
    );
    // Every package's fetch-phase outcome is reported exactly once.
    let fetch_phase: Vec<&str> = events
        .iter()
        .filter(|e| {
            matches!(
                e["errorCode"].as_str(),
                Some("vendor_fetched_missing" | "vendor_fetch_unverifiable")
            ) || (e["action"] == "failed" && e["errorCode"] == "vendor_fetch_failed")
        })
        .map(|e| e["purl"].as_str().unwrap())
        .collect();
    assert_eq!(fetch_phase.len(), 5, "{v:#}");
    assert!(!root.join("node_modules").exists());
    let requests = mock.received_requests().await.unwrap();
    assert_eq!(
        requests.len(),
        4,
        "one GET per fetchable entry (the integrity-less one is refused \
         before the network): {requests:?}"
    );
}
