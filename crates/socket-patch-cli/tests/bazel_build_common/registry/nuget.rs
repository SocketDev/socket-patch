//! Emulation of `api.nuget.org`: the v3 service index (fetched without a checksum on
//! every cold output base) and the flat-container `.nupkg` files.
//!
//! The store is a mirror directory: `<mirror>/api.nuget.org/v3/index.json` and every
//! `<mirror>/api.nuget.org/v3-flatcontainer/<id>/<version>/<id>.<version>.nupkg` are
//! served at their production URLs, plus the version list of each mirrored id.
//!
//! rules_dotnet and rules_csharp read a source in two steps, both through Bazel's
//! downloader: the service index, with no checksum, on every repository fetch, and
//! then the `.nupkg` at the index's `PackageBaseAddress`, under the sha512 the
//! fixture pins. The mirrored index names the production flat container, so the
//! second URL is production-shaped too and reaches the fixture server through the
//! same rewrite. A real package that a ruleset fetches for itself (a targeting pack)
//! resolves through the same index and is left to the real host: the scopes returned
//! here cover the index and the mirrored ids, never the host.
//!
//! A source that fails is not skipped: a 403 or a 410 on a service index fails the
//! repository fetch even when another source holds the package. [`refuse`] makes a
//! feed answer a bare status for one package, under any flat container: the mirrored
//! one, or the feed of another host (the Socket feed asked for a package it does not
//! hold), at every URL a client tries there ([`nupkg_spellings`]).

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{json, Value};

use super::super::fixture_server::FixtureServer;
use crate::bazel_common::snapshot::{snapshot, Entry};

/// The host of the default NuGet source.
pub const HOST: &str = "api.nuget.org";

/// The service index every source line and `nuget.config` of a fixture names.
pub const INDEX_URL: &str = "https://api.nuget.org/v3/index.json";

/// The `PackageBaseAddress` the mirrored index must name.
pub const FLAT_CONTAINER_URL: &str = "https://api.nuget.org/v3-flatcontainer/";

const INDEX: &str = "v3/index.json";
const FLAT_CONTAINER: &str = "v3-flatcontainer";

/// The production URL of a package file. Ids and versions are lower-cased in the
/// flat container whatever case the fixture writes them in.
pub fn nupkg_url(id: &str, version: &str) -> String {
    let [lower, ..] = nupkg_spellings(FLAT_CONTAINER_URL, id, version);
    lower
}

/// Every URL a client asks the flat container at `base` for the package file of `id`
/// at `version`, in the order rules_csharp 0.5.0 tries them
/// (`csharp/private/nuget_repo.bzl`, `package_urls`): the lower-cased path, which is
/// the only one rules_dotnet asks for, the path in the case the lock writes, and the
/// v2 `Download` route. A feed that does not hold a package is asked all three before
/// the client moves to its next source.
pub fn nupkg_spellings(base: &str, id: &str, version: &str) -> [String; 3] {
    let base = base.trim_end_matches('/');
    let (lower_id, lower_version) = (id.to_lowercase(), version.to_lowercase());
    [
        format!("{base}/{lower_id}/{lower_version}/{lower_id}.{lower_version}.nupkg"),
        format!("{base}/{id}/{version}/{id}.{version}.nupkg"),
        format!("{base}/Download/{id}/{version}"),
    ]
}

/// The `PackageBaseAddress/3.0.0` resource of a service index.
fn package_base_address(index: &[u8]) -> Result<String, String> {
    let index: Value = serde_json::from_slice(index).map_err(|e| format!("{INDEX}: {e}"))?;
    let resources = index["resources"].as_array();
    let base = resources.into_iter().flatten().find_map(|resource| {
        (resource["@type"] == "PackageBaseAddress/3.0.0").then(|| resource["@id"].as_str())?
    });
    base.map(str::to_string)
        .ok_or_else(|| format!("{INDEX} names no PackageBaseAddress/3.0.0 resource"))
}

/// Serve the mirror on `server` at its production URLs. `Err` when the mirror has
/// no service index, when its index names another flat container than
/// [`FLAT_CONTAINER_URL`] (the package fetch would then leave the rewrite), or when
/// a mirrored file is not a package of the flat container.
///
/// Returns the URL scopes this registry owns, for the downloader config: the index
/// by its exact URL and one prefix per mirrored id, so a version the mirror lacks is
/// a 404 from the fixture server and never a file from the real feed.
pub fn mount(server: &FixtureServer, mirror: &Path) -> Result<Vec<String>, String> {
    let root = mirror.join(HOST);
    if !root.is_dir() {
        return Err(format!("no NuGet mirror at {}", root.display()));
    }
    let tree = snapshot(&root);
    let Some(Entry::File { bytes: index, .. }) = tree.get(INDEX) else {
        return Err(format!("the NuGet mirror has no {INDEX}"));
    };
    let base = package_base_address(index)?;
    if base != FLAT_CONTAINER_URL {
        return Err(format!(
            "{INDEX} names the flat container {base}, not {FLAT_CONTAINER_URL}"
        ));
    }
    server.serve_as(INDEX_URL, "application/json", index.clone());
    let mut scopes = vec![format!("{HOST}/{INDEX}")];
    let mut versions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (path, entry) in &tree {
        let Entry::File { bytes, .. } = entry else {
            continue;
        };
        if path == INDEX {
            continue;
        }
        let parts: Vec<&str> = path.split('/').collect();
        let package = match parts[..] {
            [FLAT_CONTAINER, id, version, file]
                if file == format!("{id}.{version}.nupkg") && *id == id.to_lowercase() =>
            {
                Some((id, version))
            }
            _ => None,
        };
        let Some((id, version)) = package else {
            return Err(format!(
                "{path} in the NuGet mirror is not {FLAT_CONTAINER}/<id>/<version>/<id>.<version>.nupkg \
                 in lower case"
            ));
        };
        server.serve(&nupkg_url(id, version), bytes.clone());
        versions
            .entry(id.to_string())
            .or_default()
            .push(version.to_string());
    }
    for (id, versions) in versions {
        let list = json!({ "versions": versions }).to_string();
        let url = format!("{FLAT_CONTAINER_URL}{id}/index.json");
        server.serve_as(&url, "application/json", list);
        scopes.push(format!("{HOST}/{FLAT_CONTAINER}/{id}/*"));
    }
    Ok(scopes)
}

/// Serve the mirrored package file of `id` at `version` at its production URL with
/// one byte in the middle flipped, for a tamper twin: the same length, another
/// digest, never an appended byte. The fixture still pins the mirrored sha512, so
/// Bazel's downloader must refuse what it gets; run the twin on an empty repository
/// cache, or no request is made. Call it after [`mount`]: it replaces the package's
/// route.
pub fn tamper(
    server: &FixtureServer,
    mirror: &Path,
    id: &str,
    version: &str,
) -> Result<(), String> {
    let url = nupkg_url(id, version);
    let file = mirror.join(url.trim_start_matches("https://"));
    let mut bytes = std::fs::read(&file).map_err(|e| format!("{}: {e}", file.display()))?;
    if bytes.is_empty() {
        return Err(format!("{}: nothing to tamper with", file.display()));
    }
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    server.serve(&url, bytes);
    Ok(())
}

/// Have the flat container at `base` answer a bare `status` (403, 503, or 410 for a
/// withdrawal) for the package file of `id` at `version`, at every spelling of
/// [`nupkg_spellings`]: what a feed does for a package it does not hold or no longer
/// serves. `base` is the URL the client joins a package path to: the feed's
/// `PackageBaseAddress` for rules_dotnet, the source URL without its `/index.json`
/// for rules_csharp. That is [`FLAT_CONTAINER_URL`] for the mirrored feed, or the
/// flat container of another feed, such as the Socket one asked for a foreign
/// package. Call it after [`mount`]: under the mirrored container it replaces the
/// package's route.
pub fn refuse(server: &FixtureServer, base: &str, id: &str, version: &str, status: u16) {
    for url in nupkg_spellings(base, id, version) {
        server.serve_status(&url, status);
    }
}
