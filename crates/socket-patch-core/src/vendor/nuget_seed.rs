//! The committed seed of the NuGet fallback layout
//! ([`super::nuget_fallback`]): the patched package extracted the way NuGet
//! extracts into a packages folder, at the Socket version `V′`.
//!
//! The seed is built from the SAME-version patched `.nupkg` the legacy feed
//! backend materialises (service artifact or local rebuild). Its member names
//! are percent-decoded (NuGet's OPC part names are URI-encoded) and then
//! validated with the shared archive-name guards; OPC bookkeeping
//! (`[Content_Types].xml`, `_rels/`, `package/`) and the package signature
//! are dropped; the nuspec is renamed `<idlower>.nuspec` and its `<version>`
//! element rewritten to `V′` (only that element's text changes). NuGet then
//! needs exactly `.nupkg.metadata` + the nuspec + the asset files to use the
//! folder in place.
//!
//! The `contentHash` NuGet compares against the lock (a plain string
//! comparison) is `base64(sha512(canonical nupkg))`, where the canonical
//! nupkg is a deterministic zip of the seed files (sorted names, fixed
//! timestamps and compression, [`write_zip_entries`]) — so it depends only
//! on the seed's content, never on which builder produced the bytes. The
//! canonical nupkg itself is never written.

use std::collections::BTreeMap;

use base64::Engine as _;
use sha2::{Digest as _, Sha256, Sha512};

use crate::patch::apply::is_safe_relative_subpath;

use super::common::{
    is_plain_archive_name, names_are_unambiguous, read_zip_members, write_zip_entries,
};

/// NuGet's per-package marker that makes a folder a usable package.
pub(crate) const METADATA_FILE: &str = ".nupkg.metadata";

/// Characters MSBuild items or NuGet treat specially; a member name carrying
/// one is refused rather than escaped into the generated targets.
const MSBUILD_SPECIAL: &[char] = &['$', '@', '%', ';', '\''];

/// The extracted, re-versioned package.
#[derive(Debug, Clone)]
pub(crate) struct Seed {
    pub(crate) id_lower: String,
    pub(crate) socket_version: String,
    /// Package-relative files, `.nupkg.metadata` excluded.
    pub(crate) files: BTreeMap<String, Vec<u8>>,
    /// `base64(sha512(canonical nupkg))`.
    pub(crate) content_hash: String,
}

impl Seed {
    /// The seed dir relative to the fallback folder: `<idlower>/<V′>`.
    pub(crate) fn dir_rel(&self) -> String {
        format!("{}/{}", self.id_lower, self.socket_version)
    }

    /// The `.nupkg.metadata` NuGet reads to accept the folder.
    pub(crate) fn metadata(&self) -> Vec<u8> {
        metadata_bytes(&self.content_hash)
    }

    /// Every file of the seed dir, `.nupkg.metadata` included.
    pub(crate) fn tree(&self) -> BTreeMap<String, Vec<u8>> {
        let mut tree = self.files.clone();
        tree.insert(METADATA_FILE.to_string(), self.metadata());
        tree
    }

    /// `path → sha256 hex` of [`Self::tree`] (the ledger's fileInventory).
    pub(crate) fn inventory(&self) -> BTreeMap<String, String> {
        self.tree()
            .iter()
            .map(|(k, v)| (k.clone(), hex::encode(Sha256::digest(v))))
            .collect()
    }
}

/// The `.nupkg.metadata` text for `content_hash`.
pub(crate) fn metadata_bytes(content_hash: &str) -> Vec<u8> {
    let hash = serde_json::to_string(content_hash).unwrap_or_default();
    format!("{{\n  \"version\": 2,\n  \"contentHash\": {hash},\n  \"source\": null\n}}")
        .into_bytes()
}

fn unsafe_member(detail: impl Into<String>) -> (&'static str, String) {
    ("vendor_nuget_unsafe_member", detail.into())
}

/// Decode `%XX` escapes (NuGet's OPC part names); `None` on a malformed
/// escape or a non-UTF-8 result.
pub(crate) fn percent_decode(name: &str) -> Option<String> {
    if !name.contains('%') {
        return Some(name.to_string());
    }
    let bytes = name.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = name.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The OPC bookkeeping and signature parts NuGet never extracts.
fn is_package_bookkeeping(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "[content_types].xml"
        || lower == ".signature.p7s"
        || lower.starts_with("_rels/")
        || lower.starts_with("package/")
}

/// The byte range of the text of the first `<tag>…</tag>` element inside
/// the nuspec's `<metadata>` element.
fn metadata_element(text: &str, tag: &str) -> Option<(usize, usize)> {
    let metadata = text.find("<metadata")?;
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = metadata + text[metadata..].find(&open)? + open.len();
    let end = start + text[start..].find(&close)?;
    Some((start, end))
}

/// Rewrite the nuspec's `<metadata><version>` text from `version_norm` to
/// `socket_version`, checking its `<id>` names `id`. Every other byte is
/// kept.
pub(crate) fn rewrite_nuspec_version(
    nuspec: &[u8],
    id: &str,
    version_norm: &str,
    socket_version: &str,
) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(nuspec).map_err(|_| "the nuspec is not UTF-8".to_string())?;
    let (id_start, id_end) =
        metadata_element(text, "id").ok_or_else(|| "the nuspec has no <id>".to_string())?;
    if !text[id_start..id_end].trim().eq_ignore_ascii_case(id) {
        return Err(format!(
            "the nuspec names {:?}, not {id}",
            text[id_start..id_end].trim()
        ));
    }
    let (start, end) = metadata_element(text, "version")
        .ok_or_else(|| "the nuspec has no <version>".to_string())?;
    let current = text[start..end].trim();
    if super::nuget_feed::normalize_nuget_version(current) != version_norm {
        return Err(format!(
            "the nuspec version {current:?} is not {version_norm}"
        ));
    }
    let mut out = String::with_capacity(text.len() + 16);
    out.push_str(&text[..start]);
    out.push_str(socket_version);
    out.push_str(&text[end..]);
    Ok(out.into_bytes())
}

/// Extract the seed from the patched same-version `nupkg` (see the module
/// doc). `Err((code, detail))` is a refusal.
pub(crate) fn build_seed(
    nupkg: &[u8],
    id: &str,
    version_norm: &str,
    socket_version: &str,
) -> Result<Seed, (&'static str, String)> {
    let id_lower = id.to_ascii_lowercase();
    let members = read_zip_members(nupkg).map_err(unsafe_member)?;
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut nuspec: Option<(String, Vec<u8>)> = None;
    for member in members {
        let raw = member.name().to_string();
        let name = percent_decode(&raw)
            .ok_or_else(|| unsafe_member(format!("malformed part name {raw:?}")))?;
        if is_package_bookkeeping(&name) {
            continue;
        }
        if !is_safe_relative_subpath(&name)
            || !is_plain_archive_name(&name)
            || name.contains(MSBUILD_SPECIAL)
        {
            return Err(unsafe_member(format!("unsafe member name {name:?}")));
        }
        let lower = name.to_ascii_lowercase();
        if lower == METADATA_FILE || lower.ends_with(".nupkg") || lower.ends_with(".nupkg.sha512") {
            return Err(unsafe_member(format!(
                "member {name:?} would shadow NuGet's package bookkeeping"
            )));
        }
        if !name.contains('/') && lower.ends_with(".nuspec") {
            if nuspec.is_some() {
                return Err(unsafe_member("more than one root nuspec"));
            }
            nuspec = Some((name, member.into_bytes()));
            continue;
        }
        if files.insert(name.clone(), member.into_bytes()).is_some() {
            return Err(unsafe_member(format!("duplicate member {name:?}")));
        }
    }
    let Some((nuspec_name, nuspec_bytes)) = nuspec else {
        return Err(unsafe_member("the package has no root nuspec"));
    };
    let rewritten = rewrite_nuspec_version(&nuspec_bytes, id, version_norm, socket_version)
        .map_err(|e| unsafe_member(format!("{nuspec_name}: {e}")))?;
    let nuspec_rel = format!("{id_lower}.nuspec");
    if files.insert(nuspec_rel.clone(), rewritten).is_some() {
        return Err(unsafe_member(format!("duplicate member {nuspec_rel:?}")));
    }
    if !names_are_unambiguous(files.keys().map(String::as_str), std::iter::empty()) {
        return Err(unsafe_member(
            "member names collide on a case-insensitive filesystem",
        ));
    }
    let content_hash = canonical_content_hash(&files)?;
    Ok(Seed {
        id_lower,
        socket_version: socket_version.to_string(),
        files,
        content_hash,
    })
}

/// `base64(sha512(canonical nupkg))` of a seed's files.
pub(crate) fn canonical_content_hash(
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<String, (&'static str, String)> {
    let entries: Vec<(String, Vec<u8>, u32)> = files
        .iter()
        .map(|(k, v)| (k.clone(), v.clone(), 0o644))
        .collect();
    let zip = write_zip_entries(&entries)
        .map_err(|e| ("vendor_nuget_seed_failed", format!("canonical nupkg: {e}")))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&zip)))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Write as _;

    use super::*;

    pub(crate) const NUSPEC: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<package \
        xmlns=\"http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd\">\n  <metadata \
        minClientVersion=\"2.12\">\n    <id>Newtonsoft.Json</id>\n    <version>13.0.1</version>\n    \
        <dependencies>\n      <group targetFramework=\".NETStandard2.0\" />\n    </dependencies>\n  \
        </metadata>\n</package>";

    /// A small nupkg shaped like nuget.org's: OPC parts, a signature, a
    /// percent-encoded name.
    pub(crate) fn nupkg(extra: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        let mut add = |name: &str, bytes: &[u8]| {
            w.start_file(name, opts).unwrap();
            w.write_all(bytes).unwrap();
        };
        add("_rels/.rels", b"rels");
        add("Newtonsoft.Json.nuspec", NUSPEC.as_bytes());
        add("lib/netstandard2.0/Newtonsoft.Json.dll", b"DLL");
        add("lib/netstandard2.0/Newtonsoft.Json.xml", b"XML");
        add("LICENSE.md", b"MIT");
        add("packageIcon%20small.png", b"PNG");
        add("[Content_Types].xml", b"types");
        add(
            "package/services/metadata/core-properties/x.psmdcp",
            b"props",
        );
        add(".signature.p7s", b"sig");
        for (name, bytes) in extra {
            add(name, bytes);
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn seed_drops_bookkeeping_and_reversions_the_nuspec() {
        let seed = build_seed(
            &nupkg(&[]),
            "Newtonsoft.Json",
            "13.0.1",
            "13.0.1.1340506223",
        )
        .unwrap();
        let names: Vec<&str> = seed.files.keys().map(String::as_str).collect();
        assert_eq!(
            names,
            [
                "LICENSE.md",
                "lib/netstandard2.0/Newtonsoft.Json.dll",
                "lib/netstandard2.0/Newtonsoft.Json.xml",
                "newtonsoft.json.nuspec",
                "packageIcon small.png",
            ]
        );
        let nuspec = std::str::from_utf8(&seed.files["newtonsoft.json.nuspec"]).unwrap();
        assert_eq!(
            nuspec,
            NUSPEC.replace(
                "<version>13.0.1</version>",
                "<version>13.0.1.1340506223</version>"
            )
        );
        assert_eq!(seed.dir_rel(), "newtonsoft.json/13.0.1.1340506223");
        let inventory = seed.inventory();
        assert!(inventory.contains_key(METADATA_FILE));
        assert_eq!(inventory.len(), 6);
        let meta: serde_json::Value = serde_json::from_slice(&seed.metadata()).unwrap();
        assert_eq!(meta["version"], 2);
        assert_eq!(meta["contentHash"], seed.content_hash.as_str());
        assert!(meta["source"].is_null());
    }

    #[test]
    fn content_hash_depends_only_on_the_seed_content() {
        let a = build_seed(
            &nupkg(&[]),
            "Newtonsoft.Json",
            "13.0.1",
            "13.0.1.1340506223",
        )
        .unwrap();
        // Same content, different archive order/compression → same hash.
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, bytes) in [
            ("packageIcon%20small.png", &b"PNG"[..]),
            ("LICENSE.md", b"MIT"),
            ("lib/netstandard2.0/Newtonsoft.Json.xml", b"XML"),
            ("lib/netstandard2.0/Newtonsoft.Json.dll", b"DLL"),
            ("Newtonsoft.Json.nuspec", NUSPEC.as_bytes()),
        ] {
            w.start_file(name, opts).unwrap();
            w.write_all(bytes).unwrap();
        }
        let b = build_seed(
            &w.finish().unwrap().into_inner(),
            "Newtonsoft.Json",
            "13.0.1",
            "13.0.1.1340506223",
        )
        .unwrap();
        assert_eq!(a.content_hash, b.content_hash);
        let c = build_seed(
            &nupkg(&[("extra.txt", b"x")]),
            "Newtonsoft.Json",
            "13.0.1",
            "13.0.1.1340506223",
        )
        .unwrap();
        assert_ne!(a.content_hash, c.content_hash);
    }

    #[test]
    fn unsafe_members_are_refused() {
        for bad in [
            "../evil.dll",
            "lib/%2E%2E/evil.dll",
            "lib/$(Evil).dll",
            "lib/a;b.dll",
            "lib/bad%zz.dll",
            ".nupkg.metadata",
            "lib/x.nupkg",
            "LICENSE.MD",
            "lib/a%3Ab.dll",
            "lib/tab%09.dll",
        ] {
            let err = build_seed(
                &nupkg(&[(bad, b"x")]),
                "Newtonsoft.Json",
                "13.0.1",
                "13.0.1.1340506223",
            )
            .unwrap_err();
            assert_eq!(err.0, "vendor_nuget_unsafe_member", "{bad}");
        }
    }

    #[test]
    fn nuspec_rewrite_checks_id_and_version() {
        let bytes = NUSPEC.as_bytes();
        assert!(rewrite_nuspec_version(bytes, "newtonsoft.json", "13.0.1", "13.0.1.5").is_ok());
        assert!(rewrite_nuspec_version(bytes, "Other", "13.0.1", "13.0.1.5").is_err());
        assert!(rewrite_nuspec_version(bytes, "Newtonsoft.Json", "13.0.2", "13.0.2.5").is_err());
        let bom = [&[0xEF, 0xBB, 0xBF][..], bytes].concat();
        let out = rewrite_nuspec_version(&bom, "Newtonsoft.Json", "13.0.1", "13.0.1.5").unwrap();
        assert!(out.starts_with(&[0xEF, 0xBB, 0xBF]));
        assert_eq!(out.len(), bom.len() + 2);
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%20b").as_deref(), Some("a b"));
        assert_eq!(percent_decode("plain").as_deref(), Some("plain"));
        assert_eq!(percent_decode("a%2").as_deref(), None);
        assert_eq!(percent_decode("a%C3%A9").as_deref(), Some("aé"));
        assert_eq!(percent_decode("a%FF"), None);
    }
}
