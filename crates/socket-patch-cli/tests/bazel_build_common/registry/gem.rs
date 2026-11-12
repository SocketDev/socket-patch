//! Emulation of `rubygems.org`: `gems/<file>.gem` and the compact index, for the
//! rules_ruby fixtures.
//!
//! The store is a mirror directory: every file under `<mirror>/rubygems.org/` is
//! served at its production URL. rules_ruby's `bundle_fetch` reads `Gemfile.lock` in
//! Starlark and downloads `<remote>gems/<name>-<version>.gem` through Bazel's
//! downloader, so the gem files and the downloader rewrite are all it needs; it asks
//! for no index. A compact-index file (`versions`, `info/<name>`) placed in the
//! mirror is served like any other, for a cell where Bundler itself resolves.
//!
//! The host is shared with real content: `bundle_fetch` also downloads the Bundler
//! gem the lock names, from `rubygems.org`, under a checksum rules_ruby ships. The
//! scopes returned here therefore cover the mirrored gem names only, never the host.
//!
//! Bazel holds a checksum for a gem only when the fixture lists it in `gem_checksums`
//! (`CHECKSUMS` in `Gemfile.lock` is not read): only such a gem fails closed on a
//! wrong byte, and only such a gem is answered from a warm repository cache.

use std::path::Path;

use super::super::fixture_server::FixtureServer;
use crate::bazel_common::snapshot::{snapshot, Entry};

/// The host a `Gemfile.lock` `remote:` line names.
pub const HOST: &str = "rubygems.org";

/// rules_ruby takes a gem file of exactly this size for a gem without files and
/// skips unpacking it (`bundle_fetch.bzl`: `len(read) == 4096`), so a fixture gem
/// of that size would be fetched and then silently not looked at.
pub const SKIPPED_GEM_SIZE: usize = 4096;

/// `sp-victim` of `sp-victim-1.0.0.gem` and of `sp-victim-1.0.0-java.gem`: the
/// name ends before the first `-` that a digit follows.
fn gem_name(file: &str) -> Option<&str> {
    let stem = file.strip_suffix(".gem")?;
    let cut = stem
        .match_indices('-')
        .find(|(at, _)| stem[at + 1..].starts_with(|c: char| c.is_ascii_digit()))?
        .0;
    (cut > 0).then(|| &stem[..cut])
}

/// Serve the mirrored gem `file` (`sp-victim-1.0.0.gem`) at its production URL with
/// one byte in the middle flipped, for a tamper twin: the same length (so never
/// [`SKIPPED_GEM_SIZE`], which [`mount`] refuses), another digest, never an appended
/// byte. Bazel refuses it only when the fixture lists the gem in `gem_checksums`:
/// without the dict rules_ruby accepts a tampered gem at fetch, so a twin is claimed
/// on a `gem_checksums` fixture alone, and on an empty repository cache. Call it
/// after [`mount`]: it replaces the gem's route.
pub fn tamper(server: &FixtureServer, mirror: &Path, file: &str) -> Result<(), String> {
    let path = mirror.join(HOST).join("gems").join(file);
    let mut bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.is_empty() {
        return Err(format!("{}: nothing to tamper with", path.display()));
    }
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    server.serve(&format!("https://{HOST}/gems/{file}"), bytes);
    Ok(())
}

/// Serve the mirror on `server` at its production URLs. `Err` for a gem whose name
/// cannot be read, and for one of [`SKIPPED_GEM_SIZE`] bytes.
///
/// Returns the URL scopes this registry owns, for the downloader config: one prefix
/// per mirrored gem name (so another version of a fixture gem is a 404 from the
/// fixture server and never a file from the real registry), and each other mirrored
/// file by its exact URL.
pub fn mount(server: &FixtureServer, mirror: &Path) -> Result<Vec<String>, String> {
    let root = mirror.join(HOST);
    if !root.is_dir() {
        return Err(format!("no gem mirror at {}", root.display()));
    }
    let mut scopes = Vec::new();
    for (path, entry) in snapshot(&root) {
        let Entry::File { bytes, .. } = entry else {
            continue;
        };
        let scope = match path.strip_prefix("gems/") {
            Some(file) => {
                let Some(name) = gem_name(file) else {
                    return Err(format!(
                        "{path} in the gem mirror is not <name>-<version>.gem"
                    ));
                };
                if bytes.len() == SKIPPED_GEM_SIZE {
                    return Err(format!(
                        "{path} is {SKIPPED_GEM_SIZE} bytes: rules_ruby would skip it as a gem \
                         without files"
                    ));
                }
                format!("{HOST}/gems/{name}-*")
            }
            None => format!("{HOST}/{path}"),
        };
        server.serve(&format!("https://{HOST}/{path}"), bytes);
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    Ok(scopes)
}
