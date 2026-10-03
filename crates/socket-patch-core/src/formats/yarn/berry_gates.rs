//! The yarn berry project gates: the refusals that hold for a whole
//! project, whatever the patched package — a `yarn.lock` or root
//! `package.json` whose line endings are mixed, a lock `cacheKey` whose
//! cache checksum cannot be reproduced offline, and a `.yarnrc.yml`
//! `compressionLevel` (or an unreadable `.yarnrc.yml`) that changes it.
//!
//! Pure: callers read the files and map a [`BerryGate`] onto their own
//! code prefix (`vendor_yarn_berry_*` for the vendored backend and its
//! hosted→vendored takeover preflight, `redirect_yarn_berry_*` for the
//! hosted rewriter, its vendored→hosted takeover preflight and the hosted
//! restore). Both modes edit the same two files, so they must take the
//! same decision on them; the detail text lives here so it reads the same
//! in either mode.

use crate::utils::line_endings::LineEndings;

/// The lock file the gates read.
pub const YARN_LOCK: &str = "yarn.lock";
/// The root manifest both modes edit (vendored `file:` wiring, hosted
/// `resolutions`).
pub const PACKAGE_JSON: &str = "package.json";
/// The yarn config whose `compressionLevel` the gates read.
pub const YARNRC: &str = ".yarnrc.yml";

/// The only cache key whose checksum reproduces offline: yarn 4's internal
/// cache version `10` with compressionLevel 0 (`c0`, stored zip entries).
pub const SUPPORTED_CACHE_KEY: &str = "10c0";

/// What the caller could read of the project's `.yarnrc.yml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Yarnrc<'a> {
    /// No `.yarnrc.yml` (yarn's defaults apply).
    Absent,
    /// The file's text.
    Text(&'a str),
    /// The file exists but could not be read; the error text.
    Unreadable(&'a str),
}

impl<'a> Yarnrc<'a> {
    /// `Text` for a read file, `Absent` for none.
    pub fn from_option(text: Option<&'a str>) -> Self {
        text.map_or(Self::Absent, Self::Text)
    }
}

/// Why a berry project is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BerryGate {
    /// `file` mixes CRLF and LF line endings, or holds a bare CR.
    MixedLineEndings { file: &'static str },
    /// The lock has no `__metadata:` block — not a berry lockfile.
    NoMetadata,
    /// The lock's `cacheKey` is not [`SUPPORTED_CACHE_KEY`]; `None` when
    /// the `__metadata` block carries no `cacheKey` line.
    CacheKey { found: Option<String> },
    /// `.yarnrc.yml` sets a `compressionLevel` other than 0.
    Compression { level: String },
    /// `.yarnrc.yml` exists but could not be read, so its
    /// `compressionLevel` cannot be verified.
    YarnrcUnreadable { error: String },
}

impl BerryGate {
    /// The refusal's code suffix after the mode's `*_yarn_berry_` prefix:
    /// `mixed_line_endings`, or `cache_unsupported` for every cache gate.
    /// [`BerryGate::NoMetadata`] maps to `cache_unsupported` too; the
    /// vendored backend reports it as `vendor_lockfile_version_unsupported`.
    pub fn code_suffix(&self) -> &'static str {
        match self {
            Self::MixedLineEndings { .. } => "mixed_line_endings",
            Self::NoMetadata
            | Self::CacheKey { .. }
            | Self::Compression { .. }
            | Self::YarnrcUnreadable { .. } => "cache_unsupported",
        }
    }

    /// The refusal's human-readable detail, the same in both modes.
    pub fn detail(&self) -> String {
        match self {
            Self::MixedLineEndings { file } => format!(
                "{file} mixes CRLF and LF line endings (or holds a bare carriage return), so \
                 no single line ending can be kept — yarn rewrites the file with one ending \
                 on its next install and rejects a lockfile like this under `--immutable` \
                 (YN0028); run `yarn install` once to normalize it, then re-run; leaving it \
                 untouched"
            ),
            Self::NoMetadata => {
                format!("{YARN_LOCK} has no `__metadata:` entry — not a yarn berry lockfile")
            }
            Self::CacheKey { found } => format!(
                "{YARN_LOCK} cacheKey is `{}`; only `{SUPPORTED_CACHE_KEY}` (yarn 4 with \
                 compressionLevel 0, the default) has an offline-reproducible cache checksum \
                 — remove custom compression settings and re-run `yarn install`",
                found.as_deref().unwrap_or("(missing)")
            ),
            Self::Compression { level } => format!(
                "{YARNRC} sets `compressionLevel: {level}`, which changes berry's cache \
                 checksums; only compressionLevel 0 (the yarn 4 default) is supported"
            ),
            Self::YarnrcUnreadable { error } => {
                format!("cannot read {YARNRC} to verify the cache configuration: {error}")
            }
        }
    }
}

/// Every project gate, in the order both modes raise them: the lock's line
/// endings, its `cacheKey`, the `.yarnrc.yml` compressionLevel, then the
/// root manifest's line endings (`manifest` is `None` when the caller has
/// no manifest to edit).
pub fn check(lock: &str, manifest: Option<&str>, yarnrc: Yarnrc<'_>) -> Result<(), BerryGate> {
    check_line_endings(YARN_LOCK, lock)?;
    check_cache_key(lock)?;
    check_yarnrc(yarnrc)?;
    if let Some(manifest) = manifest {
        check_line_endings(PACKAGE_JSON, manifest)?;
    }
    Ok(())
}

/// The line-ending gate for one file. yarn berry keeps ONE line ending per
/// file: a new file gets `os.EOL` (CRLF on Windows) and every later write
/// re-renders the whole file in its majority ending (`normalizeLineEndings`
/// in yarnpkg-fslib `FakeFS.ts`, used by `Project.persistLockfile` and
/// `Workspace.persistManifest`). A uniform CRLF or LF file is edited in its
/// own ending; a mixed one has no ending to keep — and `yarn install
/// --immutable` already rejects a mixed lock (YN0028), because the
/// re-render differs from the file. A leading BOM is not a line break.
pub fn check_line_endings(file: &'static str, text: &str) -> Result<(), BerryGate> {
    if LineEndings::of(text) == LineEndings::Mixed {
        return Err(BerryGate::MixedLineEndings { file });
    }
    Ok(())
}

/// The `__metadata` / `cacheKey` gate: a berry checksum is the sha512 of
/// the cache archive, whose bytes depend on the cache format version and
/// compression; only [`SUPPORTED_CACHE_KEY`] is reproducible offline, and a
/// guessed `checksum:` bricks installs (YN0018).
pub fn check_cache_key(lock: &str) -> Result<(), BerryGate> {
    let Some(mut fields) = metadata_fields(lock) else {
        return Err(BerryGate::NoMetadata);
    };
    let found = fields.find_map(|line| scalar_field(line, "cacheKey"));
    if found == Some(SUPPORTED_CACHE_KEY) {
        return Ok(());
    }
    Err(BerryGate::CacheKey {
        found: found.map(str::to_string),
    })
}

/// The `.yarnrc.yml` gate: any compressionLevel but 0 changes berry's
/// cache checksums, and an unreadable file cannot be verified.
pub fn check_yarnrc(yarnrc: Yarnrc<'_>) -> Result<(), BerryGate> {
    match yarnrc {
        Yarnrc::Absent => Ok(()),
        Yarnrc::Unreadable(error) => Err(BerryGate::YarnrcUnreadable {
            error: error.to_string(),
        }),
        Yarnrc::Text(rc) => match yarnrc_compression_level(rc) {
            Some(level) if level != "0" => Err(BerryGate::Compression {
                level: level.to_string(),
            }),
            _ => Ok(()),
        },
    }
}

/// The lock's `cacheKey` (berry writes it unquoted: `  cacheKey: 10c0`),
/// `None` without a `__metadata` block or a `cacheKey` line in it.
pub fn cache_key(lock: &str) -> Option<&str> {
    metadata_fields(lock)?.find_map(|line| scalar_field(line, "cacheKey"))
}

/// The `.yarnrc.yml` `compressionLevel` value, when set. A flat line scan is
/// enough: yarn writes the knob as a top-level scalar, and any
/// value we cannot positively read as `0` makes the caller refuse. /// CRLF lines split like LF ones (`str::lines`), and a leading BOM is
/// skipped the way yarn's YAML parser skips it — otherwise a knob on the
/// first line of a BOM'd file would read as unset (the offline-reproducible
/// default) while yarn applies it and every install fails YN0018.
///
/// The value is read as a YAML scalar: a quoted value ends at its closing
/// quote, and a plain value ends before a whitespace-separated `#` comment
/// (`compressionLevel: 0 # keep yarn default` is `0`, #370). A `#` with no
/// whitespace before it stays part of a plain value, as in YAML.
pub fn yarnrc_compression_level(rc: &str) -> Option<&str> {
    let rc = rc.strip_prefix('\u{feff}').unwrap_or(rc);
    rc.lines().find_map(|line| {
        let rest = line.strip_prefix("compressionLevel:")?.trim();
        if let Some(quote) = rest.chars().next().filter(|c| matches!(c, '\'' | '"')) {
            if let Some(end) = rest[1..].find(quote) {
                return Some(&rest[1..1 + end]);
            }
        }
        let value = rest
            .char_indices()
            .find(|&(i, c)| c == '#' && rest[..i].ends_with([' ', '\t']))
            .map_or(rest, |(i, _)| &rest[..i]);
        Some(value.trim_end().trim_matches(['\'', '"']))
    })
}

/// The body lines of the lock's column-0 `__metadata:` block (CRLF and a
/// leading BOM tolerated), up to the next blank or column-0 line; `None`
/// when there is no such block.
fn metadata_fields(lock: &str) -> Option<impl Iterator<Item = &str>> {
    let lock = lock.strip_prefix('\u{feff}').unwrap_or(lock);
    let mut lines = lock.lines();
    lines.find(|line| line.trim_end() == "__metadata:")?;
    Some(lines.take_while(|line| line.starts_with(' ')))
}

/// A 2-space body field `  <field>: <value>` (value possibly quoted).
/// Deeper sub-map lines are not body fields.
fn scalar_field<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    let rest = line.strip_prefix("  ")?;
    if rest.starts_with(' ') {
        return None;
    }
    let value = rest.strip_prefix(field)?.strip_prefix(':')?;
    Some(value.trim().trim_matches('"'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock(cache_key: &str) -> String {
        format!(
            "# yarn lockfile\n\n__metadata:\n  version: 8\n  cacheKey: {cache_key}\n\n\
             \"left-pad@npm:^1.3.0\":\n  version: 1.3.0\n  languageName: node\n"
        )
    }

    #[test]
    fn a_supported_project_passes_in_any_uniform_ending() {
        let lf = lock("10c0");
        let crlf = lf.replace('\n', "\r\n");
        let pkg = "{\r\n  \"name\": \"app\"\r\n}\r\n";
        for text in [&lf, &crlf, &format!("\u{feff}{crlf}")] {
            assert_eq!(check(text, Some(pkg), Yarnrc::Absent), Ok(()), "{text:?}");
        }
        assert_eq!(
            check(&lf, None, Yarnrc::Text("compressionLevel: 0 # default\n")),
            Ok(())
        );
        assert_eq!(cache_key(&crlf), Some("10c0"));
    }

    #[test]
    fn every_gate_names_its_cause() {
        let lf = lock("10c0");
        let mixed = format!("{{\r\n  \"name\": \"app\",\n  \"version\": \"1.0.0\"\r\n}}\r\n");
        assert_eq!(
            check(&lf.replacen('\n', "\r\n", 1), None, Yarnrc::Absent),
            Err(BerryGate::MixedLineEndings { file: YARN_LOCK })
        );
        assert_eq!(
            check(&lf, Some(&mixed), Yarnrc::Absent),
            Err(BerryGate::MixedLineEndings { file: PACKAGE_JSON })
        );
        assert_eq!(
            check(&lock("8"), None, Yarnrc::Absent),
            Err(BerryGate::CacheKey {
                found: Some("8".into())
            })
        );
        assert_eq!(
            check(&lf.replace("  cacheKey: 10c0\n", ""), None, Yarnrc::Absent),
            Err(BerryGate::CacheKey { found: None })
        );
        assert_eq!(
            check("\"a@npm:1\":\n  version: 1\n", None, Yarnrc::Absent),
            Err(BerryGate::NoMetadata)
        );
        assert_eq!(
            check(&lf, None, Yarnrc::Text("compressionLevel: mixed\n")),
            Err(BerryGate::Compression {
                level: "mixed".into()
            })
        );
        assert_eq!(
            check(&lf, None, Yarnrc::Unreadable("permission denied")),
            Err(BerryGate::YarnrcUnreadable {
                error: "permission denied".into()
            })
        );
        // The lock gates win over the manifest one, so a refusal names the
        // first file a yarn install would trip on.
        assert_eq!(
            check(&lock("8"), Some(&mixed), Yarnrc::Absent),
            Err(BerryGate::CacheKey {
                found: Some("8".into())
            })
        );
    }

    #[test]
    fn details_name_the_file_the_value_and_the_remedy() {
        let mixed = BerryGate::MixedLineEndings { file: PACKAGE_JSON }.detail();
        assert!(mixed.starts_with("package.json mixes") && mixed.contains("yarn install"));
        assert!(BerryGate::CacheKey { found: None }
            .detail()
            .contains("`(missing)`"));
        assert!(BerryGate::CacheKey {
            found: Some("8".into())
        }
        .detail()
        .contains("cacheKey is `8`"));
        assert_eq!(
            BerryGate::Compression { level: "9".into() }.code_suffix(),
            "cache_unsupported"
        );
    }

    #[test]
    fn a_sub_map_or_later_block_never_supplies_the_cache_key() {
        let text = "__metadata:\n  version: 8\n  nested:\n    cacheKey: 10c0\n\n\
                    \"x@npm:1\":\n  cacheKey: 10c0\n";
        assert_eq!(cache_key(text), None);
    }

    /// A `.yarnrc.yml` saved with a BOM (and CRLF) still has its first-line
    /// `compressionLevel` knob read — yarn applies it, so it must refuse.
    #[test]
    fn yarnrc_compression_level_reads_past_a_bom_and_crlf() {
        assert_eq!(
            yarnrc_compression_level("\u{feff}compressionLevel: mixed\r\nnodeLinker: pnp\r\n"),
            Some("mixed")
        );
        assert_eq!(
            yarnrc_compression_level("nodeLinker: pnp\r\ncompressionLevel: 0\r\n"),
            Some("0")
        );
        assert_eq!(
            yarnrc_compression_level("\u{feff}nodeLinker: pnp\r\n"),
            None
        );
    }

    /// A trailing YAML comment is not part of the scalar (#370): yarn reads
    /// `compressionLevel: 0 # keep yarn default` as `0`, quoted or not.
    #[test]
    fn yarnrc_compression_level_drops_a_trailing_comment() {
        for (rc, level) in [
            ("compressionLevel: 0 # keep yarn default\n", "0"),
            ("compressionLevel: 0\t# tab-separated\r\n", "0"),
            ("compressionLevel: 0   #\n", "0"),
            ("compressionLevel: \"0\" # quoted\n", "0"),
            ("compressionLevel: '0'# quoted, no gap\n", "0"),
            ("compressionLevel: mixed # not the default\n", "mixed"),
            ("compressionLevel: 9 #\r\n", "9"),
        ] {
            assert_eq!(yarnrc_compression_level(rc), Some(level), "{rc:?}");
        }
    }

    /// A `#` with no whitespace before it is part of a plain scalar in YAML,
    /// so `0#x` is not the default and must still refuse (fail closed).
    #[test]
    fn yarnrc_compression_level_keeps_an_unseparated_hash() {
        assert_eq!(
            yarnrc_compression_level("compressionLevel: 0#x\n"),
            Some("0#x")
        );
        assert_eq!(
            yarnrc_compression_level("compressionLevel: \"0 # in quotes\"\n"),
            Some("0 # in quotes")
        );
    }
}
