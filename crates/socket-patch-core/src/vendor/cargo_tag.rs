//! Tagged vendored cargo versions (`<version>+socket.<uuid>`).
//!
//! A vendored copy's own `Cargo.toml` `[package] version` is rewritten to a
//! TAGGED version carrying the patch uuid as semver build metadata:
//!
//! * `1.0.4` → `1.0.4+socket.<uuid>`;
//! * a version that already has build metadata keeps it and appends the tag
//!   as two more identifiers (semver allows one `+`):
//!   `2.0.1+zstd.1.5.2` → `2.0.1+zstd.1.5.2.socket.<uuid>`.
//!
//! Cargo ignores build metadata when matching version requirements, so
//! every dependent's `=1.0.4` / `1` / `^1` still selects the copy, while the
//! resolver records the tagged version in `Cargo.lock` — the lock alone then
//! names the patch uuid of the copy cargo actually built (a config-level
//! `[patch]` pointing somewhere else changes the locked version). The
//! patched crate sees the tag in `CARGO_PKG_VERSION`.
//!
//! The tag is the LAST two build-metadata identifiers, `socket` and a
//! canonical lowercase uuid; stripping it restores the original version
//! string exactly (the purl version, the `<name>-<version>` copy directory,
//! the registry version the lock originally pinned).
//!
//! Manifest edits are textual: only the bytes of the `version` string
//! literal change, so tagging and untagging round-trip byte-identically
//! (comments, key order, line endings and the quote style survive).

use std::path::Path;

use crate::patch::apply::normalize_file_path;
use crate::patch::path_safety::is_canonical_uuid;
use crate::utils::fs::{atomic_write_bytes_preserving_mode, read_regular_to_string};

/// The build-metadata identifier that introduces the uuid.
pub const TAG_IDENT: &str = "socket";

/// The copy manifest the tag lives in.
const COPY_MANIFEST: &str = "Cargo.toml";

// ── versions and manifest text ───────────────────────────────────────────

/// `version` tagged with `uuid` (see the module docs). An already-tagged
/// `version` is re-tagged (its old tag replaced), so the result carries
/// exactly one Socket tag.
pub fn tag_version(version: &str, uuid: &str) -> String {
    let base = strip_tag(version);
    if base.contains('+') {
        format!("{base}.{TAG_IDENT}.{uuid}")
    } else {
        format!("{base}+{TAG_IDENT}.{uuid}")
    }
}

/// `(original version, uuid)` of a tagged version; `None` when `version`
/// carries no Socket tag (no build metadata, or metadata that does not end
/// in `socket.<canonical uuid>`).
pub fn split_tag(version: &str) -> Option<(&str, &str)> {
    let (core, meta) = version.split_once('+')?;
    let (rest, uuid) = meta.rsplit_once('.')?;
    if !is_canonical_uuid(uuid) {
        return None;
    }
    let prefix = if rest == TAG_IDENT {
        // `<core>+socket.<uuid>`: the original had no build metadata.
        return Some((core, uuid));
    } else {
        rest.strip_suffix(TAG_IDENT)?.strip_suffix('.')?
    };
    if prefix.is_empty() {
        return None;
    }
    // `<core>+<meta>.socket.<uuid>`: the original is `<core>+<meta>`.
    Some((&version[..core.len() + 1 + prefix.len()], uuid))
}

/// `version` without its Socket tag (itself when untagged).
pub fn strip_tag(version: &str) -> &str {
    split_tag(version).map_or(version, |(base, _)| base)
}

/// The uuid a tagged version carries.
pub fn tag_uuid(version: &str) -> Option<&str> {
    split_tag(version).map(|(_, uuid)| uuid)
}

/// Does the lock/manifest version `found` denote `version` — the version
/// itself, or any Socket-tagged spelling of it?
pub fn denotes(found: &str, version: &str) -> bool {
    strip_tag(found) == version
}

/// Why a copy manifest's `[package] version` cannot be (un)tagged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagError {
    /// Not TOML.
    Unparseable(String),
    /// No `[package] version` string literal (a workspace-inherited or
    /// missing version: never a crates.io-published manifest).
    NoVersion,
    /// The manifest names another version than the copy is for.
    VersionMismatch(String),
    /// The literal is spelled with escapes / a multi-line form the
    /// byte-exact rewrite does not reproduce.
    UnsupportedLiteral(String),
    Io(String),
}

impl std::fmt::Display for TagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unparseable(e) => write!(f, "the copy's Cargo.toml is not valid TOML: {e}"),
            Self::NoVersion => write!(
                f,
                "the copy's Cargo.toml has no literal `[package] version` string"
            ),
            Self::VersionMismatch(v) => write!(
                f,
                "the copy's Cargo.toml declares version {v:?}, not the vendored version"
            ),
            Self::UnsupportedLiteral(raw) => write!(
                f,
                "the copy's Cargo.toml spells its version as {raw}, which cannot be \
                 rewritten byte-exactly"
            ),
            Self::Io(e) => write!(f, "the copy's Cargo.toml: {e}"),
        }
    }
}

/// The `[package] version` string of `text`, with the byte range of its
/// literal (quotes included) and the quote character.
fn version_literal(text: &str) -> Result<(String, std::ops::Range<usize>, char), TagError> {
    let doc = toml_edit::Document::parse(text).map_err(|e| TagError::Unparseable(e.to_string()))?;
    let item = doc
        .get("package")
        .and_then(toml_edit::Item::as_table_like)
        .and_then(|p| p.get("version"))
        .ok_or(TagError::NoVersion)?;
    let value = item.as_str().ok_or(TagError::NoVersion)?.to_string();
    let span = item.span().ok_or(TagError::NoVersion)?;
    let raw = text.get(span.clone()).ok_or(TagError::NoVersion)?;
    // Only a plain one-line literal whose body IS the value round-trips
    // byte-exactly: `"1.0.4"` / `'1.0.4'`.
    let quote = raw.chars().next().unwrap_or('"');
    let plain = (quote == '"' || quote == '\'')
        && raw.len() == value.len() + 2
        && raw.ends_with(quote)
        && raw[1..raw.len() - 1] == value;
    if !plain {
        return Err(TagError::UnsupportedLiteral(raw.to_string()));
    }
    Ok((value, span, quote))
}

/// `text` (a vendored copy's `Cargo.toml`) with its `[package] version`
/// tagged for `uuid`. The version must denote `version` (untagged, or tagged
/// for any uuid — re-tagged). `Ok(None)`: already tagged for `uuid`.
pub fn tag_manifest_text(
    text: &str,
    version: &str,
    uuid: &str,
) -> Result<Option<String>, TagError> {
    let (found, span, quote) = version_literal(text)?;
    if !denotes(&found, version) {
        return Err(TagError::VersionMismatch(found));
    }
    let tagged = tag_version(version, uuid);
    if found == tagged {
        return Ok(None);
    }
    Ok(Some(splice(text, span, quote, &tagged)))
}

/// `text` with the Socket tag dropped from its `[package] version` —
/// byte-identical to the manifest before [`tag_manifest_text`]. `None` when
/// the version is untagged (or unreadable).
pub fn untag_manifest_text(text: &str) -> Option<String> {
    let (found, span, quote) = version_literal(text).ok()?;
    let (base, _) = split_tag(&found)?;
    Some(splice(text, span, quote, base))
}

/// The uuid the `[package] version` of a copy manifest is tagged with.
pub fn manifest_tag_uuid(text: &str) -> Option<String> {
    let (found, _, _) = version_literal(text).ok()?;
    tag_uuid(&found).map(str::to_string)
}

fn splice(text: &str, span: std::ops::Range<usize>, quote: char, value: &str) -> String {
    format!(
        "{}{quote}{value}{quote}{}",
        &text[..span.start],
        &text[span.end..]
    )
}

/// Is `file_key` (a patch record key) the copy's `Cargo.toml` — the one
/// patched file the tag rewrites after the patch applied?
pub fn is_copy_manifest_key(file_key: &str) -> bool {
    normalize_file_path(file_key) == COPY_MANIFEST
}

/// The bytes a patch record's `afterHash` covers for the copy manifest:
/// `bytes` with the Socket tag dropped (the tag is vendor wiring written
/// after the patch applied). `None` when `bytes` carries no tag.
pub fn untagged_manifest_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(bytes).ok()?;
    untag_manifest_text(text).map(String::into_bytes)
}

// ── copy edits ───────────────────────────────────────────────────────────

/// Tag the `Cargo.toml` of the copy at `copy_dir` for `uuid` (atomic,
/// mode-preserving). `Ok(true)` when it was rewritten, `Ok(false)` when it
/// already carried this tag.
pub async fn tag_copy_manifest(
    copy_dir: &Path,
    version: &str,
    uuid: &str,
) -> Result<bool, TagError> {
    let path = copy_dir.join(COPY_MANIFEST);
    let text = read_regular_to_string(&path)
        .await
        .map_err(|e| TagError::Io(e.to_string()))?;
    match tag_manifest_text(&text, version, uuid)? {
        None => Ok(false),
        Some(tagged) => {
            atomic_write_bytes_preserving_mode(&path, tagged.as_bytes())
                .await
                .map_err(|e| TagError::Io(e.to_string()))?;
            Ok(true)
        }
    }
}

/// Drop the tag from the copy manifest (best-effort undo of
/// [`tag_copy_manifest`] when a later step fails).
pub async fn untag_copy_manifest(copy_dir: &Path) {
    let path = copy_dir.join(COPY_MANIFEST);
    if let Ok(text) = read_regular_to_string(&path).await {
        if let Some(untagged) = untag_manifest_text(&text) {
            let _ = atomic_write_bytes_preserving_mode(&path, untagged.as_bytes()).await;
        }
    }
}

/// The uuid the copy manifest at `copy_dir` is tagged with, if any.
pub async fn copy_manifest_tag(copy_dir: &Path) -> Option<String> {
    let text = read_regular_to_string(&copy_dir.join(COPY_MANIFEST))
        .await
        .ok()?;
    manifest_tag_uuid(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const UUID2: &str = "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d";

    #[test]
    fn tags_plain_prerelease_and_build_metadata_versions() {
        for (version, tagged) in [
            ("1.0.4", format!("1.0.4+socket.{UUID}")),
            ("0.1.10", format!("0.1.10+socket.{UUID}")),
            ("1.0.0-rc.1", format!("1.0.0-rc.1+socket.{UUID}")),
            ("1.0.0-alpha+001", format!("1.0.0-alpha+001.socket.{UUID}")),
            (
                "2.0.1+zstd.1.5.2",
                format!("2.0.1+zstd.1.5.2.socket.{UUID}"),
            ),
            (
                "0.25.12+spec-1.1.0",
                format!("0.25.12+spec-1.1.0.socket.{UUID}"),
            ),
        ] {
            assert_eq!(tag_version(version, UUID), tagged, "{version}");
            assert_eq!(split_tag(&tagged), Some((version, UUID)), "{tagged}");
            assert_eq!(strip_tag(&tagged), version);
            assert_eq!(tag_uuid(&tagged), Some(UUID));
            assert!(denotes(&tagged, version) && denotes(version, version));
            assert_eq!(split_tag(version), None, "{version} is untagged");
            // Re-tagging replaces, never stacks.
            let retagged = tag_version(&tagged, UUID2);
            assert_eq!(split_tag(&retagged), Some((version, UUID2)));
            assert_eq!(retagged.matches("socket").count(), 1);
        }
    }

    #[test]
    fn split_rejects_look_alikes() {
        for v in [
            "1.0.4+socket",
            "1.0.4+socket.",
            "1.0.4+socket.not-a-uuid",
            "1.0.4+socket.9F6B2C4E-1D3A-4F6B-8C2D-7E5A9B1C3D5F",
            "1.0.4+xsocket.9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f",
            "1.0.4+.socket.9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f",
            "1.0.4+9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f",
            "1.0.4",
        ] {
            assert_eq!(split_tag(v), None, "{v}");
            assert_eq!(strip_tag(v), v);
        }
        assert!(!denotes("1.0.5", "1.0.4"));
        assert!(!denotes(&format!("1.0.5+socket.{UUID}"), "1.0.4"));
    }

    const CRATE_TOML: &str = "# THIS FILE IS AUTOMATICALLY GENERATED BY CARGO\r\n\r\n[package]\r\nedition = \"2018\"\r\nname = \"cfg-if\"\r\nversion = \"1.0.4\" # pinned\r\nauthors = [\"a\"]\r\n\r\n[dependencies.core]\r\nversion = \"1.0.0\"\r\n";

    #[test]
    fn manifest_tag_round_trips_byte_identically() {
        let tagged = tag_manifest_text(CRATE_TOML, "1.0.4", UUID)
            .unwrap()
            .unwrap();
        assert_eq!(
            tagged,
            CRATE_TOML.replace(
                "version = \"1.0.4\" #",
                &format!("version = \"1.0.4+socket.{UUID}\" #")
            ),
            "only the [package] version literal changes (CRLF, comments and the \
             dependency's own version kept)"
        );
        assert_eq!(manifest_tag_uuid(&tagged).as_deref(), Some(UUID));
        assert_eq!(tag_manifest_text(&tagged, "1.0.4", UUID).unwrap(), None);
        assert_eq!(untag_manifest_text(&tagged).as_deref(), Some(CRATE_TOML));
        assert_eq!(untag_manifest_text(CRATE_TOML), None);
        // Re-tag for a new uuid.
        let bumped = tag_manifest_text(&tagged, "1.0.4", UUID2).unwrap().unwrap();
        assert_eq!(manifest_tag_uuid(&bumped).as_deref(), Some(UUID2));
        assert_eq!(untag_manifest_text(&bumped).as_deref(), Some(CRATE_TOML));
    }

    #[test]
    fn manifest_tag_keeps_literal_quotes_and_existing_metadata() {
        let text = "[package]\nname = \"zstd-sys\"\nversion = '2.0.1+zstd.1.5.2'\n";
        let tagged = tag_manifest_text(text, "2.0.1+zstd.1.5.2", UUID)
            .unwrap()
            .unwrap();
        assert_eq!(
            tagged,
            format!("[package]\nname = \"zstd-sys\"\nversion = '2.0.1+zstd.1.5.2.socket.{UUID}'\n")
        );
        assert_eq!(untag_manifest_text(&tagged).as_deref(), Some(text));
        let inline = "package = { name = \"x\", version = \"1.0.0-rc.1\" }\n";
        let tagged = tag_manifest_text(inline, "1.0.0-rc.1", UUID)
            .unwrap()
            .unwrap();
        assert!(tagged.contains(&format!("\"1.0.0-rc.1+socket.{UUID}\"")));
        assert_eq!(untag_manifest_text(&tagged).as_deref(), Some(inline));
    }

    #[test]
    fn manifest_tag_refuses_unrecognized_shapes() {
        assert!(matches!(
            tag_manifest_text("[package]\nversion = \"2.0.0\"\n", "1.0.4", UUID),
            Err(TagError::VersionMismatch(v)) if v == "2.0.0"
        ));
        assert_eq!(
            tag_manifest_text("[package]\nname = \"x\"\n", "1.0.4", UUID),
            Err(TagError::NoVersion)
        );
        assert_eq!(
            tag_manifest_text("[package]\nversion.workspace = true\n", "1.0.4", UUID),
            Err(TagError::NoVersion)
        );
        assert!(matches!(
            tag_manifest_text("[package]\nversion = \"1.0.\\u0034\"\n", "1.0.4", UUID),
            Err(TagError::UnsupportedLiteral(_))
        ));
        assert!(matches!(
            tag_manifest_text("[package\n", "1.0.4", UUID),
            Err(TagError::Unparseable(_))
        ));
    }

    #[test]
    fn untagged_bytes_recover_the_patched_manifest() {
        let tagged = tag_manifest_text(CRATE_TOML, "1.0.4", UUID)
            .unwrap()
            .unwrap();
        assert_eq!(
            untagged_manifest_bytes(tagged.as_bytes()).as_deref(),
            Some(CRATE_TOML.as_bytes())
        );
        assert_eq!(untagged_manifest_bytes(CRATE_TOML.as_bytes()), None);
        assert!(is_copy_manifest_key("Cargo.toml"));
        assert!(is_copy_manifest_key("package/Cargo.toml"));
        assert!(!is_copy_manifest_key("src/Cargo.toml"));
        assert!(!is_copy_manifest_key("Cargo.toml.orig"));
    }

    #[tokio::test]
    async fn copy_manifest_edits_are_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), CRATE_TOML).unwrap();
        assert!(tag_copy_manifest(dir.path(), "1.0.4", UUID).await.unwrap());
        assert!(!tag_copy_manifest(dir.path(), "1.0.4", UUID).await.unwrap());
        assert_eq!(copy_manifest_tag(dir.path()).await.as_deref(), Some(UUID));
        untag_copy_manifest(dir.path()).await;
        assert_eq!(
            std::fs::read_to_string(dir.path().join("Cargo.toml")).unwrap(),
            CRATE_TOML
        );
        assert_eq!(copy_manifest_tag(dir.path()).await, None);
        let missing = tempfile::tempdir().unwrap();
        assert!(matches!(
            tag_copy_manifest(missing.path(), "1.0.4", UUID).await,
            Err(TagError::Io(_))
        ));
    }
}
