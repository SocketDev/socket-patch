//! A sparse cargo registry on the fixture server: `config.json`, the
//! index files and the `.crate` downloads.
//!
//! Under crate_universe it is cargo that fetches (`cargo-bazel` runs it:
//! the index, `config.json` and the `.crate` arrive with a `cargo/<v>`
//! user agent), not Bazel's downloader, so no downloader rewrite reaches
//! those requests and a production URL in a `Cargo.lock` cannot be
//! redirected. What a test controls is the registry socket-patch points
//! cargo at: the fake Socket API hands out [`mount`]'s loopback URL as the
//! hosted origin, and cargo is served directly from here. The upstream
//! side of such a cell stays the real `index.crates.io`, which a baseline
//! needs reachable and lists in its hosts; rules_rs fixtures keep
//! production URLs throughout.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::super::fixture_server::FixtureServer;

/// One crate version the registry serves.
#[derive(Clone, Debug)]
pub struct Crate {
    pub name: String,
    pub version: String,
    /// The `.crate` file: a gzipped tar of `<name>-<version>/`.
    pub bytes: Vec<u8>,
    /// The `deps` array of the index line. Cargo resolves from the index,
    /// not from the manifest inside the `.crate`, so a crate with
    /// dependencies must list them here.
    pub deps: Vec<Value>,
}

impl Crate {
    /// A crate with no dependencies.
    pub fn new(name: &str, version: &str, bytes: Vec<u8>) -> Crate {
        Crate {
            name: name.to_string(),
            version: version.to_string(),
            bytes,
            deps: Vec::new(),
        }
    }

    /// The hex sha256 cargo verifies the download against: the `cksum` of
    /// the index line and the `checksum` of `Cargo.lock`.
    pub fn cksum(&self) -> String {
        hex::encode(Sha256::digest(&self.bytes))
    }

    /// The crate's line of its index file.
    pub fn index_line(&self) -> String {
        let line = json!({
            "name": self.name,
            "vers": self.version,
            "deps": self.deps,
            "cksum": self.cksum(),
            "features": {},
            "yanked": false,
        });
        line.to_string()
    }
}

/// Where the index keeps a crate's file: `1/<name>`, `2/<name>`,
/// `3/<first letter>/<name>`, else `<first two>/<next two>/<name>`, all in
/// lower case.
pub fn index_path(name: &str) -> String {
    let name = name.to_ascii_lowercase();
    match name.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", &name[..1]),
        _ => format!("{}/{}/{name}", &name[..2], &name[2..4]),
    }
}

/// The route of a crate's download in a registry mounted at `prefix`.
fn download_route(prefix: &str, name: &str, version: &str) -> String {
    format!("{prefix}/crates/{name}/{version}/download")
}

/// `Err` unless `prefix` is a plain relative path: a scheme or a `..`
/// would mount the registry somewhere the caller did not mean.
fn check_prefix(prefix: &str) -> Result<(), String> {
    let plain = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            && part != ".."
    };
    if !prefix.split('/').all(plain) {
        return Err(format!("{prefix:?} is not a plain route prefix"));
    }
    Ok(())
}

/// Serve `crates` as a sparse registry under `<loopback origin>/<prefix>`
/// and return its index URL (`sparse+http://127.0.0.1:<port>/<prefix>/index/`),
/// the value of a `[registries.<name>] index` or a `[source]` `registry`.
/// A loopback URL: it may reach a workspace copy and cargo, never a
/// committed file. `Err` (nothing served) for a name cargo would not ask
/// for, or the same version listed twice.
pub fn mount(server: &FixtureServer, prefix: &str, crates: &[Crate]) -> Result<String, String> {
    check_prefix(prefix)?;
    // Cargo asks this server directly, so a route is a path with no host
    // segment in front; only what cargo reads back carries the origin.
    let base = format!("{}/{prefix}", server.loopback_origin());
    let mut index: std::collections::BTreeMap<String, Vec<&Crate>> = Default::default();
    for krate in crates {
        let name = &krate.name;
        let valid = name.len() <= 64
            && name.starts_with(|c: char| c.is_ascii_alphabetic())
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !valid {
            return Err(format!("{name:?} is not a crate name"));
        }
        let versions = index.entry(index_path(name)).or_default();
        if versions.iter().any(|other| other.version == krate.version) {
            return Err(format!("{name} {} is listed twice", krate.version));
        }
        versions.push(krate);
    }
    // No `{crate}` marker in `dl`: cargo appends `/{crate}/{version}/download`.
    let config = json!({ "dl": format!("{base}/crates"), "api": base });
    server.serve_as(
        &format!("{prefix}/index/config.json"),
        "application/json",
        config.to_string(),
    );
    for (path, versions) in &index {
        let lines: String = versions.iter().map(|k| k.index_line() + "\n").collect();
        server.serve_as(&format!("{prefix}/index/{path}"), "text/plain", lines);
        for krate in versions {
            let route = download_route(prefix, &krate.name, &krate.version);
            server.serve(&route, krate.bytes.clone());
        }
    }
    Ok(format!("sparse+{base}/index/"))
}

/// Serve `krate`'s download with one byte flipped (the length is kept),
/// in the registry [`mount`]ed at `prefix`: the index still states the
/// real `cksum`, so cargo must refuse the bytes.
pub fn tamper(server: &FixtureServer, prefix: &str, krate: &Crate) -> Result<(), String> {
    check_prefix(prefix)?;
    let mut bytes = krate.bytes.clone();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    server.serve(&download_route(prefix, &krate.name, &krate.version), bytes);
    Ok(())
}

#[test]
fn crate_index_paths_follow_the_registry_layout() {
    let paths = ["a", "ab", "abc", "itoa", "cfg-if", "Serde_JSON"].map(index_path);
    assert_eq!(
        paths,
        [
            "1/a",
            "2/ab",
            "3/a/abc",
            "it/oa/itoa",
            "cf/g-/cfg-if",
            "se/rd/serde_json"
        ]
    );
    let server = FixtureServer::start();
    let one = Crate::new("spcrate", "1.0.0", b"x".to_vec());
    for prefix in ["", "/abs", "a/../b", "http://x", "a//b"] {
        assert!(
            mount(&server, prefix, std::slice::from_ref(&one)).is_err(),
            "{prefix:?} was mounted"
        );
    }
    let twice = mount(&server, "r", &[one.clone(), one.clone()]).unwrap_err();
    assert!(twice.contains("listed twice"), "{twice}");
    let bad = mount(
        &server,
        "r",
        &[Crate::new("1bad/name", "1.0.0", Vec::new())],
    )
    .unwrap_err();
    assert!(bad.contains("not a crate name"), "{bad}");
    assert!(server.requests().is_empty());
}

/// The registry against the real cargo: it resolves from the index,
/// downloads the `.crate`, records the `cksum` in `Cargo.lock`, and
/// refuses a tampered download. This is the claim "cargo is served
/// directly" checked with cargo itself, with no Bazel.
#[test]
fn cargo_fetches_from_the_sparse_registry_and_refuses_a_tampered_crate() {
    use std::io::Write;

    use crate::common;

    if !common::has_command("cargo") {
        println!("SKIP: no cargo on PATH");
        return;
    }
    // spcrate-1.0.0.crate: a manifest and one source file.
    let mut tarball = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    let manifest = "[package]\nname = \"spcrate\"\nversion = \"1.0.0\"\nedition = \"2021\"\n";
    for (path, text) in [
        ("Cargo.toml", manifest),
        ("src/lib.rs", "pub const VALUE: &str = \"vulnerable\";\n"),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(text.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tarball
            .append_data(
                &mut header,
                format!("spcrate-1.0.0/{path}"),
                text.as_bytes(),
            )
            .unwrap();
    }
    let mut gzip = tarball.into_inner().unwrap();
    gzip.flush().unwrap();
    let krate = Crate::new("spcrate", "1.0.0", gzip.finish().unwrap());

    let server = FixtureServer::start();
    let index = mount(&server, "socket/cargo", std::slice::from_ref(&krate)).unwrap();
    assert_eq!(
        index,
        format!("sparse+{}/socket/cargo/index/", server.loopback_origin())
    );

    let project = tempfile::tempdir().unwrap();
    let write = |rel: &str, text: &str| {
        let path = project.path().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    };
    write(
        ".cargo/config.toml",
        &format!("[registries.stub]\nindex = \"{index}\"\n"),
    );
    write(
        "Cargo.toml",
        "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n\
         spcrate = { version = \"1.0.0\", registry = \"stub\" }\n",
    );
    write(
        "src/lib.rs",
        "pub fn value() -> &'static str { spcrate::VALUE }\n",
    );
    let fetch = |home: &std::path::Path, args: &[&str]| {
        let home = home.to_string_lossy().into_owned();
        common::cargo_run(project.path(), args, &[("CARGO_HOME", home.as_str())])
    };

    let home = tempfile::tempdir().unwrap();
    let out = fetch(home.path(), &["fetch"]);
    assert!(
        out.status.success(),
        "cargo fetch: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lock = std::fs::read_to_string(project.path().join("Cargo.lock")).unwrap();
    assert!(
        lock.contains(&format!("checksum = \"{}\"", krate.cksum())),
        "{lock}"
    );
    let asked: Vec<String> = server.requests().into_iter().map(|r| r.url).collect();
    for route in [
        "index/config.json",
        "index/sp/cr/spcrate",
        "crates/spcrate/1.0.0/download",
    ] {
        let url = format!("socket/cargo/{route}");
        assert!(
            asked.contains(&url),
            "cargo never asked for {url}: {asked:?}"
        );
    }
    let by_cargo = |r: &super::super::fixture_server::Request| {
        r.headers
            .iter()
            .any(|(name, value)| name == "user-agent" && value.starts_with("cargo"))
    };
    assert!(
        server.requests().iter().all(by_cargo),
        "a request did not come from cargo"
    );

    // The twin: a cold cargo home, the locked checksum, flipped bytes.
    tamper(&server, "socket/cargo", &krate).unwrap();
    let cold = tempfile::tempdir().unwrap();
    let out = fetch(cold.path(), &["fetch", "--locked"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "cargo accepted a tampered crate:\n{stderr}"
    );
    assert!(stderr.contains("failed to verify the checksum"), "{stderr}");
}
