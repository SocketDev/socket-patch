//! Which package a yarn lock entry's own copy really installs, whatever
//! dependency name the entry is keyed by (#939, #1236).
//!
//! Yarn (classic and berry alike) keys a `file:` tarball or directory, a
//! url tarball and a berry `portal:` / `link:` dependency by the name the
//! depender gave it: `"lp2": "file:./left-pad-1.3.0.tgz"` locks as
//! `lp2@file:…`, while `node_modules/lp2` IS left-pad@1.3.0. No pin of
//! `left-pad` reaches that copy, so every reader that asks "does this lock
//! also install an unpatched copy of the patched `name@version`?" (lockfile
//! discovery, the vendored backends) reads the copy itself, through
//! [`CopyRef`], and so cannot disagree on which package it is.

use super::patterns::split_classic_pattern;
use super::source::{is_tarball_path, manifest_name, registry_tarball_name};

/// Where a yarn lock entry's copy comes from, read for the package it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CopyRef {
    /// A root-relative `file:` tarball: the package is the `package.json`
    /// inside it.
    Tarball(String),
    /// A root-relative `file:` directory yarn copies into `node_modules`:
    /// the package is its `package.json` `name`, at the lock's version.
    Directory(String),
    /// A root-relative berry `portal:` / `link:` directory yarn links into
    /// `node_modules`: the lock records the placeholder version
    /// `0.0.0-use.local`, so the package's name AND version are its
    /// `package.json`'s.
    Linked(String),
    /// A url tarball (`#` fragment dropped): the package is the registry
    /// package its `/<name>/-/<leaf>-<version>.tgz` path names.
    Url(String),
}

impl CopyRef {
    /// The root-relative file to read for [`CopyRef::identity`]: the tarball
    /// itself, or the directory's `package.json`. `None` for a url, which
    /// names its package in its path.
    ///
    /// `None` too for an absolute path: a lock is untrusted input, and an
    /// absolute spelling can name any file on the machine, or (a Windows
    /// UNC path) a network share. Such a copy is never read, so its package
    /// stays unknown (#1516).
    pub(crate) fn read_path(&self) -> Option<String> {
        if let CopyRef::Tarball(rel) | CopyRef::Directory(rel) | CopyRef::Linked(rel) = self {
            if crate::utils::relpath::is_anchored(rel) {
                return None;
            }
        }
        match self {
            CopyRef::Tarball(rel) => Some(rel.clone()),
            CopyRef::Directory(dir) | CopyRef::Linked(dir) => Some(if dir.is_empty() {
                "package.json".to_string()
            } else {
                format!("{dir}/package.json")
            }),
            CopyRef::Url(_) => None,
        }
    }

    /// The `(name, version)` this copy installs, given the lock entry's
    /// `version` and the bytes read at [`CopyRef::read_path`]. `None` when
    /// the copy does not say (an unreadable or nameless manifest, a
    /// non-registry url).
    pub(crate) fn identity(
        &self,
        lock_version: &str,
        bytes: Option<&[u8]>,
    ) -> Option<(String, String)> {
        let name = match self {
            CopyRef::Tarball(_) => tarball_manifest_name(bytes?)?,
            CopyRef::Directory(_) => manifest_name(bytes?)?,
            CopyRef::Linked(_) => {
                let manifest = parse_manifest(bytes?)?;
                let name = manifest.get("name")?.as_str()?.to_string();
                let version = manifest.get("version")?.as_str()?.to_string();
                return Some((name, version));
            }
            CopyRef::Url(url) => registry_tarball_name(url, lock_version)?,
        };
        Some((name, lock_version.to_string()))
    }

    /// Where the copy installs from, for a warning or diagnostic: "installs
    /// it from …" / "links it to …". A url is redacted, since the phrase
    /// may be published (a VEX document, a JSON envelope).
    pub(crate) fn how(&self) -> String {
        match self {
            CopyRef::Tarball(rel) | CopyRef::Directory(rel) => {
                format!("installs it from the user's file:{rel}")
            }
            CopyRef::Linked(rel) => {
                let rel = if rel.is_empty() { "." } else { rel };
                format!("links it to the user's directory {rel} (portal:/link:)")
            }
            CopyRef::Url(url) => format!(
                "installs it from {:?}",
                crate::utils::redact::redact_url(url)
            ),
        }
    }
}

/// The copy a classic block installs from its key patterns and `resolved`:
/// a `file:` path in a key pattern (relative to the root, where yarn 1
/// writes it, and read there even when it leaves the root: yarn installs
/// `file:../shared/left-pad` all the same, #1516), else an http(s)
/// `resolved`. `None` for anything else. The caller decides which blocks
/// are copies at all ([`super::source::classic_copy_source`]).
pub(crate) fn classic_copy_ref(patterns: &[String], resolved: Option<&str>) -> Option<CopyRef> {
    let file = patterns.iter().find_map(|p| {
        let (_, range) = split_classic_pattern(p)?;
        range.strip_prefix("file:")
    });
    match file {
        Some(path) => {
            let path = path.split('#').next().unwrap_or_default();
            let rel = copy_path("", path)?;
            Some(if is_tarball_path(path) {
                CopyRef::Tarball(rel)
            } else {
                CopyRef::Directory(rel)
            })
        }
        None => {
            let url = resolved?.split('#').next().unwrap_or_default();
            url.starts_with("http")
                .then(|| CopyRef::Url(url.to_string()))
        }
    }
}

/// The copy a berry locator `reference` installs from: a `file:` tarball or
/// directory, a `portal:` / `link:` directory (each relative to the
/// workspace its `locator=` binding names), or an http(s) url. `None` for
/// any other protocol (`npm:`, `workspace:`, `patch:`, `exec:`, git). A
/// path that leaves the root is still read there ([`copy_path`]).
pub(crate) fn berry_copy_ref(reference: &str) -> Option<CopyRef> {
    if reference.starts_with("http") {
        return Some(CopyRef::Url(
            reference.split('#').next().unwrap_or_default().to_string(),
        ));
    }
    let (path, linked) = if let Some(path) = reference.strip_prefix("file:") {
        (path, false)
    } else if let Some(path) = reference
        .strip_prefix("portal:")
        .or_else(|| reference.strip_prefix("link:"))
    {
        (path, true)
    } else {
        return None;
    };
    // Cut the `::locator=…` bindings and any `#` selector; a single `:` is
    // part of the path (a Windows drive, `portal:C:/Users/me/lp`).
    let path = path.split("::").next().unwrap_or_default();
    let path = path.split('#').next().unwrap_or_default();
    let rel = berry_copy_path(reference, path)?;
    Some(if linked {
        CopyRef::Linked(rel)
    } else if is_tarball_path(path) {
        CopyRef::Tarball(rel)
    } else {
        CopyRef::Directory(rel)
    })
}

/// The root-relative path a berry `file:` / `portal:` / `link:` reference
/// names: relative to the workspace in its `locator=` binding
/// (`b@workspace:packages/b`), or to the root when it has none
/// ([`copy_path`]).
fn berry_copy_path(reference: &str, path: &str) -> Option<String> {
    let workspace = reference
        .split_once("::")
        .and_then(|(_, bindings)| bindings.split('&').find_map(|b| b.strip_prefix("locator=")))
        .map(crate::utils::purl::percent_decode_purl_component)
        .and_then(|locator| {
            locator
                .split_once("@workspace:")
                .map(|(_, ws)| ws.to_string())
        })
        .unwrap_or_default();
    let workspace = if workspace == "." {
        String::new()
    } else {
        workspace
    };
    copy_path(&workspace, path)
}

/// Where a copy's `path`, relative to the root-relative directory `base`,
/// is read from: normalized and root-relative, keeping one leading `../`
/// per level it climbs above the root (`../shared/left-pad`), or as
/// spelled when it is absolute. yarn installs a copy from outside the
/// project as readily as one inside it, so dropping such a path would
/// leave the copy unread and its package unattributed (#1516). `None`
/// only for an empty path.
fn copy_path(base: &str, path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    if crate::utils::relpath::is_anchored(path) {
        return Some(path.to_string());
    }
    let joined = if base.is_empty() {
        path.to_string()
    } else {
        format!("{base}/{path}")
    };
    Some(crate::utils::relpath::normalize_rel_keeping_escapes(
        &joined,
    ))
}

/// Whether `bytes` parse as a JSON `package.json` (any content): a copy
/// whose manifest doesn't (a Git LFS pointer, an encrypted blob) can't be
/// read for its package (#1561).
pub(crate) fn is_json_manifest(bytes: &[u8]) -> bool {
    parse_manifest(bytes).is_some()
}

fn parse_manifest(bytes: &[u8]) -> Option<serde_json::Value> {
    let bytes = crate::formats::text::strip_bom_bytes(bytes);
    serde_json::from_slice::<serde_json::Value>(bytes).ok()
}

/// `name` of the `package.json` inside an npm tarball.
fn tarball_manifest_name(bytes: &[u8]) -> Option<String> {
    let map = crate::patch::package::read_archive_bytes_to_map_any_root(bytes).ok()?;
    manifest_name(map.get("package.json")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pats(p: &[&str]) -> Vec<String> {
        p.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn classic_refs_split_tarballs_directories_and_urls() {
        assert_eq!(
            classic_copy_ref(
                &pats(&["lp2@file:./forks/lp.tgz"]),
                Some("file:./forks/lp.tgz")
            ),
            Some(CopyRef::Tarball("forks/lp.tgz".into()))
        );
        assert_eq!(
            classic_copy_ref(&pats(&["lp2@file:./lpdir"]), None),
            Some(CopyRef::Directory("lpdir".into()))
        );
        assert_eq!(
            classic_copy_ref(
                &pats(&["lp2@https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"]),
                Some("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz#abc"),
            ),
            Some(CopyRef::Url(
                "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz".into()
            ))
        );
        // #1516: yarn installs a copy from outside the root all the same,
        // so it is read there, not dropped.
        assert_eq!(
            classic_copy_ref(&pats(&["lp2@file:../ext/lpdir"]), None),
            Some(CopyRef::Directory("../ext/lpdir".into()))
        );
        assert_eq!(
            classic_copy_ref(
                &pats(&["lp2@file:../shared/lp.tgz"]),
                Some("file:../shared/lp.tgz#abc")
            ),
            Some(CopyRef::Tarball("../shared/lp.tgz".into()))
        );
        let abs = classic_copy_ref(&pats(&["lp2@file:/abs/lpdir"]), None);
        assert_eq!(abs, Some(CopyRef::Directory("/abs/lpdir".into())));
        assert_eq!(
            abs.unwrap().read_path(),
            None,
            "an absolute path is never read"
        );
    }

    /// #1516: yarn strips a `file:` tarball's first path segment whatever
    /// its name, so a `git archive --prefix=left-pad-1.3.0/` tarball names
    /// its package like a `package/` one.
    #[test]
    fn tarball_identity_reads_any_root_directory() {
        let tarball = CopyRef::Tarball("lp.tgz".into());
        for root in ["package", "left-pad-1.3.0"] {
            let bytes = crate::vex::discover::testing::npm_tgz_rooted(root, "left-pad", "1.3.0");
            assert_eq!(
                tarball.identity("1.3.0", Some(&bytes)),
                Some(("left-pad".into(), "1.3.0".into())),
                "{root}/"
            );
        }
    }

    #[test]
    fn berry_refs_resolve_against_the_locator_workspace() {
        let ws = "::locator=b%40workspace%3Apackages%2Fb";
        assert_eq!(
            berry_copy_ref(&format!("file:../../forks/lp.tgz#../../forks/lp.tgz{ws}")),
            Some(CopyRef::Tarball("forks/lp.tgz".into()))
        );
        assert_eq!(
            berry_copy_ref(&format!("file:../../../lp.tgz#../../../lp.tgz{ws}")),
            Some(CopyRef::Tarball("../lp.tgz".into())),
            "three levels up from packages/b leaves the root, and is read there (#1516)"
        );
        assert_eq!(
            berry_copy_ref(&format!("file:../forks/lp.tgz#../forks/lp.tgz{ws}")),
            Some(CopyRef::Tarball("packages/forks/lp.tgz".into()))
        );
        assert_eq!(
            berry_copy_ref(&format!("file:../forks/lp#../forks/lp{ws}")),
            Some(CopyRef::Directory("packages/forks/lp".into()))
        );
        assert_eq!(
            berry_copy_ref(&format!("portal:../lp{ws}")),
            Some(CopyRef::Linked("packages/lp".into()))
        );
        assert_eq!(
            berry_copy_ref("link:./vend/lp::locator=app%40workspace%3A."),
            Some(CopyRef::Linked("vend/lp".into()))
        );
        assert_eq!(berry_copy_ref("npm:1.3.0"), None);
        assert_eq!(berry_copy_ref("workspace:packages/b"), None);
    }

    /// #1540: an absolute `portal:` / `link:` path keeps its whole spelling,
    /// a Windows drive's `:` included, and is never read.
    #[test]
    fn absolute_linked_refs_keep_the_path_and_are_unread() {
        let ws = "::locator=app%40workspace%3A.";
        for (reference, path) in [
            (format!("portal:/home/me/lp{ws}"), "/home/me/lp"),
            (format!("link:/home/me/lp{ws}"), "/home/me/lp"),
            (format!("portal:C:/Users/me/lp{ws}"), "C:/Users/me/lp"),
        ] {
            assert_eq!(
                berry_copy_ref(&reference),
                Some(CopyRef::Linked(path.into())),
                "{reference}"
            );
        }
        assert!(CopyRef::Linked("/home/me/lp".into()).read_path().is_none());
        assert_eq!(
            CopyRef::Linked("vend/lp".into()).read_path().as_deref(),
            Some("vend/lp/package.json")
        );
    }

    #[test]
    fn linked_identity_reads_name_and_version_from_the_manifest() {
        let linked = CopyRef::Linked("vend/lp".into());
        assert_eq!(linked.read_path().as_deref(), Some("vend/lp/package.json"));
        let manifest = br#"{"name":"left-pad","version":"1.3.0"}"#;
        assert_eq!(
            linked.identity("0.0.0-use.local", Some(manifest)),
            Some(("left-pad".into(), "1.3.0".into()))
        );
        assert_eq!(
            linked.identity("0.0.0-use.local", Some(br#"{"name":"x"}"#)),
            None
        );
        let dir = CopyRef::Directory("lpdir".into());
        assert_eq!(
            dir.identity("1.3.0", Some(br#"{"name":"left-pad","version":"9.9.9"}"#)),
            Some(("left-pad".into(), "1.3.0".into()))
        );
        assert_eq!(dir.identity("1.3.0", None), None);
    }
}
