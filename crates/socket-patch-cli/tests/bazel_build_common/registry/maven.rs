//! Emulation of `repo1.maven.org`: the jars, POMs and checksum files a pinned
//! `maven_install.json` names, and the loopback repository of the unpinned-hub guard.
//!
//! The store is a mirror directory: every file under
//! `<mirror>/repo1.maven.org/maven2/` is served at its Maven Central URL, with the
//! `.sha1` sidecar Maven Central publishes beside it. Maven Central also publishes
//! an `.md5`, which Coursier asks for as well; nothing here can compute one, so a
//! mirror that serves Coursier carries those as files.
//!
//! A pinned hub fetches each jar through Bazel's downloader under the sha256 its lock
//! records, so [`mount`] and the downloader rewrite are all it needs, and a wrong byte
//! fails the fetch. An unpinned hub runs Coursier, which opens its own connections:
//! no downloader config reaches it, and neither a Coursier mirror file nor a shared
//! Coursier cache works under Bzlmod. Its fixture therefore commits a loopback
//! `repositories` URL, and [`mount_loopback`] serves the same files there. Coursier
//! checks what it downloads against the sidecars beside it; Bazel holds no checksum
//! for any of it.

use std::path::Path;

use super::super::fixture_server::FixtureServer;
use crate::bazel_common::snapshot::{snapshot, Entry};

/// The host a pinned lock's `repositories` key names.
pub const HOST: &str = "repo1.maven.org";

/// The repository root under [`HOST`], and under a loopback origin.
pub const ROOT: &str = "maven2";

/// Every `(path under the repository root, bytes)` to serve: the mirrored files and
/// a `.sha1` for each one that has none in the mirror.
fn files(mirror: &Path) -> Result<Vec<(String, Vec<u8>)>, String> {
    let root = mirror.join(HOST).join(ROOT);
    if !root.is_dir() {
        return Err(format!("no Maven mirror at {}", root.display()));
    }
    let tree = snapshot(&root);
    let mut out = Vec::new();
    for (path, entry) in &tree {
        let Entry::File { bytes, .. } = entry else {
            continue;
        };
        out.push((path.clone(), bytes.clone()));
        let sidecar = format!("{path}.sha1");
        let checksum = path.ends_with(".sha1") || path.ends_with(".md5");
        if !checksum && !tree.contains_key(&sidecar) {
            let digest = hex::encode(<sha1::Sha1 as sha1::Digest>::digest(bytes));
            out.push((sidecar, digest.into_bytes()));
        }
    }
    Ok(out)
}

/// Serve the mirror on `server` at its Maven Central URLs.
///
/// Returns the URL scopes this registry owns, for the downloader config: one prefix
/// per artifact version directory, so a request for a file the mirror lacks (a
/// classifier jar, a `.module`) is a 404 from the fixture server and never reaches
/// Maven Central.
pub fn mount(server: &FixtureServer, mirror: &Path) -> Result<Vec<String>, String> {
    let mut scopes = Vec::new();
    for (path, bytes) in files(mirror)? {
        server.serve(&format!("https://{HOST}/{ROOT}/{path}"), bytes);
        let directory = path.rsplit_once('/').map_or("", |(directory, _)| directory);
        let scope = format!("{HOST}/{ROOT}/{directory}/*");
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    Ok(scopes)
}

/// Serve the mirror on `server` as a repository of its own, for a client that reads
/// it directly, and return the URL to write as the hub's `repositories` value in the
/// workspace copy. Plain `http` on loopback is all Coursier needs; nothing Bazel's
/// downloader reads may carry this URL (without a checksum it is refused before
/// Bazel 10).
pub fn mount_loopback(server: &FixtureServer, mirror: &Path) -> Result<String, String> {
    for (path, bytes) in files(mirror)? {
        server.serve(&format!("{ROOT}/{path}"), bytes);
    }
    Ok(format!("{}/{ROOT}", server.loopback_origin()))
}
