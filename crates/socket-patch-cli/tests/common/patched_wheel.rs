//! A real patched wheel for the hosted Python stale-install probe, which
//! judges an installed copy against the wheel's own `RECORD`: the served
//! wheel, the grant that pins it, and the installed `WHEEL` file naming
//! the same build.

use std::io::Write as _;
use std::path::Path;

use base64::Engine as _;
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The `WHEEL` file of a pure `py2.py3-none-any` wheel.
pub const WHEEL: &str =
    "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py2-none-any\nTag: py3-none-any\n";

/// A wheel whose `dist_info` records `files` (paths relative to
/// site-packages) at their bytes.
pub fn build(dist_info: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
    let b64 = |bytes: &[u8]| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
    };
    let mut record = String::new();
    for (name, bytes) in files {
        record.push_str(&format!("{name},sha256={},{}\n", b64(bytes), bytes.len()));
    }
    record.push_str(&format!(
        "{dist_info}/WHEEL,sha256={},{}\n{dist_info}/RECORD,,\n",
        b64(WHEEL.as_bytes()),
        WHEEL.len()
    ));
    let mut out = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut out);
        let options = zip::write::SimpleFileOptions::default();
        let members = files
            .iter()
            .map(|(name, bytes)| (name.to_string(), bytes.to_vec()))
            .chain([
                (format!("{dist_info}/WHEEL"), WHEEL.as_bytes().to_vec()),
                (format!("{dist_info}/RECORD"), record.into_bytes()),
            ]);
        for (name, bytes) in members {
            zip.start_file(name, options).unwrap();
            zip.write_all(&bytes).unwrap();
        }
        zip.finish().unwrap();
    }
    out.into_inner()
}

/// The hex sha256 a grant pins `wheel` with.
pub fn sha256(wheel: &[u8]) -> String {
    hex::encode(Sha256::digest(wheel))
}

/// `<site>/<dist_info>/WHEEL`, as an installer keeps it from the wheel.
pub fn install_wheel_metadata(site: &Path, dist_info: &str) {
    let dir = site.join(dist_info);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("WHEEL"), WHEEL).unwrap();
}

/// Serve `wheel` at `wheel_path` on `server` and mount a priority-1 grant
/// for `uuid` that pins it, ahead of the suite's own grant. Returns the
/// served URL.
pub async fn mount_grant(
    server: &MockServer,
    org: &str,
    uuid: &str,
    purl: &str,
    wheel_path: &str,
    wheel: Vec<u8>,
) -> String {
    let url = format!("{}{wheel_path}", server.uri());
    let sha = sha256(&wheel);
    Mock::given(method("GET"))
        .and(path(wheel_path))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(wheel))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{org}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                uuid: {
                    "status": "granted",
                    "url": url,
                    "purl": purl,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": url,
                        "integrity": { "sha256": sha }
                    }],
                    "registryOverride": null
                }
            }
        })))
        .with_priority(1)
        .mount(server)
        .await;
    url
}
