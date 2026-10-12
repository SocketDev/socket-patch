//! The lowest cargo a project TELLS us it builds on: the ONE reader of the
//! project's declared floor, shared by the vendored multi-version warning
//! and the hosted planner's sparse-registry gate.
//!
//! Read offline from the project itself, in this order: the workspace
//! root's `rust-version` (`[package]`, else `[workspace.package]`, and a
//! `rust-version.workspace = true` inheritor reads `[workspace.package]`),
//! else the toolchain rustup picks from the root: the legacy
//! `rust-toolchain` file when it exists (rustup prefers it over
//! `rust-toolchain.toml`, with a warning), else `rust-toolchain.toml`'s
//! `[toolchain] channel`.
//!
//! Everything here is pure; the callers own the reads.

use toml_edit::{Document, Item, Table};

use super::manifest::package_table;

/// The legacy extensionless toolchain file (a bare channel name, or the
/// TOML form). rustup reads it in preference to [`TOOLCHAIN_TOML`].
pub(crate) const TOOLCHAIN_LEGACY: &str = "rust-toolchain";
/// The TOML toolchain file.
pub(crate) const TOOLCHAIN_TOML: &str = "rust-toolchain.toml";

/// Days from 1970-01-01 to a proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The minor of a dated `nightly-YYYY-MM-DD` / `beta-YYYY-MM-DD` channel.
/// Rust ships a stable release every six weeks (1.68 on 2023-03-09, 1.45
/// on 2020-07-16 — the train has not slipped since 1.0), and on that day
/// beta becomes the next minor and nightly the one after.
fn dated_channel_minor(spec: &str) -> Option<u32> {
    let (ahead, date) = if let Some(date) = spec.strip_prefix("nightly-") {
        (2, date)
    } else if let Some(date) = spec.strip_prefix("beta-") {
        (1, date)
    } else {
        return None;
    };
    let mut parts = date.get(..10)?.split('-').map(str::parse::<i64>);
    let (year, month, day) = (
        parts.next()?.ok()?,
        parts.next()?.ok()?,
        parts.next()?.ok()?,
    );
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let since = days_from_civil(year, month, day) - days_from_civil(2023, 3, 9);
    let stable = 68 + since.div_euclid(42);
    u32::try_from(stable + ahead).ok()
}

/// The `1.<minor>` of a `rust-version` or toolchain channel (`1.67`,
/// `1.67.1`, `1.67-x86_64-unknown-linux-gnu`, or a dated
/// `nightly-2022-06-01`); `None` for a rolling channel (`stable`,
/// `nightly`, …) or anything else.
fn minor_of(spec: &str) -> Option<u32> {
    let spec = spec.trim().trim_matches('"');
    let Some(rest) = spec.strip_prefix("1.") else {
        return dated_channel_minor(spec);
    };
    rest.split(['.', '-', '+']).next()?.parse().ok()
}

/// `[workspace.package].rust-version` of a parsed root manifest.
fn workspace_rust_version(root: &Table) -> Option<&str> {
    root.get("workspace")
        .and_then(|w| w.get("package"))
        .and_then(|p| p.get("rust-version"))
        .and_then(Item::as_str)
}

/// The package's own `rust-version`: `Ok(Some)` for a literal, `Err(())`
/// for an inheritor (`rust-version.workspace = true`, or any non-string
/// value), `Ok(None)` when it has none.
fn own_rust_version(root: &Table) -> Result<Option<&str>, ()> {
    match package_table(root).and_then(|p| p.get("rust-version")) {
        None => Ok(None),
        Some(item) => item.as_str().map(Some).ok_or(()),
    }
}

/// The `rust-version` the root `Cargo.toml` declares. `[package]`'s own
/// string wins; an inheritor, a package without one, or a virtual
/// workspace reads `[workspace.package]`.
pub(crate) fn root_manifest_minor(text: &str) -> Option<u32> {
    let doc = Document::parse(text).ok()?;
    let root = doc.as_table();
    match own_rust_version(root) {
        Ok(Some(own)) => Some(own),
        _ => workspace_rust_version(root),
    }
    .and_then(minor_of)
}

/// The `rust-version` a workspace member declares: its own literal, or the
/// root's `[workspace.package]` value when it inherits it. A member with
/// none declares nothing (cargo does not inherit implicitly).
pub(crate) fn member_manifest_minor(member: &str, root: Option<&str>) -> Option<u32> {
    let doc = Document::parse(member).ok()?;
    match own_rust_version(doc.as_table()) {
        Ok(Some(own)) => minor_of(own),
        Ok(None) => None,
        Err(()) => {
            let root = Document::parse(root?).ok()?;
            workspace_rust_version(root.as_table()).and_then(minor_of)
        }
    }
}

/// The `[toolchain] channel` of a TOML toolchain file.
fn toolchain_channel(text: &str) -> Option<String> {
    let doc = Document::parse(text).ok()?;
    doc.get("toolchain")
        .and_then(|t| t.get("channel"))
        .and_then(Item::as_str)
        .map(str::to_string)
}

/// The minor of the toolchain rustup picks from the root's toolchain files
/// (`None` for a file that is absent or unreadable): the legacy file when
/// it exists, else the TOML one. A blank legacy text names no toolchain
/// (the hosted engine records an unreadable in-memory entry as `""`), so
/// it does not hide the TOML file's channel.
pub(crate) fn toolchain_minor(
    toolchain_toml: Option<&str>,
    toolchain_legacy: Option<&str>,
) -> Option<u32> {
    if let Some(legacy) = toolchain_legacy.filter(|t| !t.trim().is_empty()) {
        return match toolchain_channel(legacy) {
            Some(channel) => minor_of(&channel),
            None => minor_of(legacy),
        };
    }
    minor_of(&toolchain_channel(toolchain_toml?)?)
}

/// The lowest cargo minor the project declares, from the root `Cargo.toml`
/// ([`root_manifest_minor`]), else its toolchain files
/// ([`toolchain_minor`]).
///
/// `None` when the project declares nothing, or pins a rolling channel —
/// socket-patch never runs `cargo`, so there is no other signal, and "no
/// declaration" is NOT evidence of a modern cargo.
pub(crate) fn declared_cargo_minor(
    manifest: Option<&str>,
    toolchain_toml: Option<&str>,
    toolchain_legacy: Option<&str>,
) -> Option<u32> {
    manifest
        .and_then(root_manifest_minor)
        .or_else(|| toolchain_minor(toolchain_toml, toolchain_legacy))
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
        // rustup prefers the legacy file when both exist.
        let stable = "[toolchain]\nchannel = \"stable\"\n";
        assert_eq!(
            declared_cargo_minor(None, Some(stable), Some("1.50\n")),
            Some(50)
        );
        assert_eq!(
            declared_cargo_minor(None, Some(toml), Some("stable\n")),
            None
        );
        // A blank legacy placeholder (an unreadable entry) is no toolchain.
        for blank in ["", " \n"] {
            assert_eq!(
                declared_cargo_minor(None, Some(toml), Some(blank)),
                Some(67)
            );
        }
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

    /// A dated nightly or beta pins the cargo of that day's release train.
    #[test]
    fn dated_channels_map_to_their_release_train() {
        let cases = [
            ("nightly-2022-06-01", Some(63)),
            ("beta-2022-06-01", Some(62)),
            // The day 1.68 shipped: nightly is 1.70, beta 1.69.
            ("nightly-2023-03-09", Some(70)),
            ("beta-2023-03-08", Some(68)),
            ("nightly-2020-07-16", Some(47)),
            ("nightly-2024-13-01", None),
            ("nightly", None),
            ("stable", None),
        ];
        for (channel, want) in cases {
            let toml = format!("[toolchain]\nchannel = \"{channel}\"\n");
            assert_eq!(
                declared_cargo_minor(None, Some(&toml), None),
                want,
                "{channel}"
            );
        }
    }

    #[test]
    fn a_member_declares_its_own_or_its_inherited_rust_version() {
        let root = "[workspace]\n\n[workspace.package]\nrust-version = \"1.60\"\n";
        let member = |rv: &str| format!("[package]\nname = \"m\"\n{rv}\n");
        assert_eq!(
            member_manifest_minor(&member("rust-version = \"1.64\""), Some(root)),
            Some(64)
        );
        assert_eq!(
            member_manifest_minor(&member("rust-version.workspace = true"), Some(root)),
            Some(60)
        );
        assert_eq!(member_manifest_minor(&member(""), Some(root)), None);
        assert_eq!(
            member_manifest_minor(&member("rust-version.workspace = true"), None),
            None
        );
    }
}
