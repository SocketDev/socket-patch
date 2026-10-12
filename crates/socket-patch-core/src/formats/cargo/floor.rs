//! The lowest cargo a project TELLS us it builds on: the ONE reader of the
//! project's declared floor, shared by the vendored multi-version warning
//! and the hosted planner's sparse-registry gate.
//!
//! Read offline from the project itself, in this order: the workspace
//! root's `rust-version` (`[package]`, else `[workspace.package]`, and a
//! `rust-version.workspace = true` inheritor reads `[workspace.package]`),
//! else `rust-toolchain.toml`'s `[toolchain] channel`, else the legacy
//! `rust-toolchain` file (a bare channel name, or the same TOML form).
//!
//! Everything here is pure; the callers own the reads.

use toml_edit::{Document, Item};

use super::manifest::package_table;

/// The legacy extensionless toolchain file (rustup reads it when
/// [`TOOLCHAIN_TOML`] is absent).
pub(crate) const TOOLCHAIN_LEGACY: &str = "rust-toolchain";
/// The TOML toolchain file.
pub(crate) const TOOLCHAIN_TOML: &str = "rust-toolchain.toml";

/// The `1.<minor>` of a `rust-version` or toolchain channel (`1.67`,
/// `1.67.1`, `1.67-x86_64-unknown-linux-gnu`); `None` for a rolling channel
/// (`stable`, `nightly`, …) or anything else.
fn minor_of(spec: &str) -> Option<u32> {
    let spec = spec.trim().trim_matches('"');
    let rest = spec.strip_prefix("1.")?;
    rest.split(['.', '-', '+']).next()?.parse().ok()
}

/// The `rust-version` the root `Cargo.toml` declares. `[package]`'s own
/// string wins; a `rust-version.workspace = true` inheritor (any non-string
/// value) or a package without one reads `[workspace.package]`.
fn manifest_minor(text: &str) -> Option<u32> {
    let doc = Document::parse(text).ok()?;
    let root = doc.as_table();
    let own = package_table(root)
        .and_then(|p| p.get("rust-version"))
        .and_then(Item::as_str);
    let inherited = || {
        root.get("workspace")
            .and_then(|w| w.get("package"))
            .and_then(|p| p.get("rust-version"))
            .and_then(Item::as_str)
    };
    own.or_else(inherited).and_then(minor_of)
}

/// The `[toolchain] channel` of a TOML toolchain file.
fn toolchain_channel(text: &str) -> Option<String> {
    let doc = Document::parse(text).ok()?;
    doc.get("toolchain")
        .and_then(|t| t.get("channel"))
        .and_then(Item::as_str)
        .map(str::to_string)
}

/// The lowest cargo minor the project declares, from the root `Cargo.toml`,
/// `rust-toolchain.toml` and `rust-toolchain` texts (`None` for a file that
/// is absent or unreadable).
///
/// `None` when the project declares nothing, or pins a rolling channel —
/// socket-patch never runs `cargo`, so there is no other signal, and "no
/// declaration" is NOT evidence of a modern cargo.
pub(crate) fn declared_cargo_minor(
    manifest: Option<&str>,
    toolchain_toml: Option<&str>,
    toolchain_legacy: Option<&str>,
) -> Option<u32> {
    if let Some(minor) = manifest.and_then(manifest_minor) {
        return Some(minor);
    }
    if let Some(channel) = toolchain_toml.and_then(toolchain_channel) {
        return minor_of(&channel);
    }
    let legacy = toolchain_legacy?;
    match toolchain_channel(legacy) {
        Some(channel) => minor_of(&channel),
        None => minor_of(legacy),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_manifest(text: &str) -> Option<u32> {
        declared_cargo_minor(Some(text), None, None)
    }

    #[test]
    fn reads_package_and_workspace_rust_version() {
        assert_eq!(
            from_manifest("[package]\nname = \"a\"\nrust-version = \"1.70\"\n"),
            Some(70)
        );
        assert_eq!(
            from_manifest("\u{feff}[package]\nname = \"a\"\nrust-version = \"1.67.1\"\n"),
            Some(67)
        );
        assert_eq!(
            from_manifest("[workspace]\n\n[workspace.package]\nrust-version = \"1.60\"\n"),
            Some(60)
        );
        // The package's own value wins over the workspace default.
        assert_eq!(
            from_manifest(
                "[workspace.package]\nrust-version = \"1.60\"\n\n\
                 [package]\nname = \"a\"\nrust-version = \"1.75\"\n"
            ),
            Some(75)
        );
        assert_eq!(from_manifest("[package]\nname = \"a\"\n"), None);
        assert_eq!(from_manifest("not toml ["), None);
    }

    /// #651: `rust-version.workspace = true` inherits `[workspace.package]`
    /// — in the dotted spelling and the inline-table one.
    #[test]
    fn workspace_inheritor_reads_workspace_package() {
        for spelling in [
            "rust-version.workspace = true",
            "rust-version = { workspace = true }",
        ] {
            let text = format!(
                "[workspace]\n\n[workspace.package]\nrust-version = \"1.70\"\n\n\
                 [package]\nname = \"consumer\"\nversion = \"0.1.0\"\n{spelling}\n"
            );
            assert_eq!(from_manifest(&text), Some(70), "{spelling}");
        }
    }

    #[test]
    fn falls_back_to_toolchain_files() {
        let toml = "[toolchain]\nchannel = \"1.67.1\"\n";
        assert_eq!(declared_cargo_minor(None, Some(toml), None), Some(67));
        assert_eq!(declared_cargo_minor(None, None, Some("1.56.0\n")), Some(56));
        assert_eq!(declared_cargo_minor(None, None, Some(toml)), Some(67));
        assert_eq!(declared_cargo_minor(None, None, Some("stable\n")), None);
        // The TOML file is read first; a rolling channel there is final.
        let stable = "[toolchain]\nchannel = \"stable\"\n";
        assert_eq!(
            declared_cargo_minor(None, Some(stable), Some("1.50\n")),
            None
        );
        // `rust-version` wins over the toolchain files.
        assert_eq!(
            declared_cargo_minor(
                Some("[package]\nname = \"a\"\nrust-version = \"1.70\"\n"),
                Some(toml),
                None
            ),
            Some(70)
        );
    }
}
