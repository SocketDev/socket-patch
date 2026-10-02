//! A Bundler lockfile (`Gemfile.lock` / `gems.locked`): the ONE read model
//! of the format, shared by every reader of one: the lock inventory
//! ([`GemfileLock::entries`]: the registry gems a lock resolves, their
//! `CHECKSUMS` pins and remotes), ledger recovery's remote set and lockfile
//! discovery (`vex::discover::gem`: the Socket-wired `GEM` / `PATH`
//! sections). One
//! parse means both agree on which section a spec belongs to, which remote
//! serves it and which checksum pins it.
//!
//! Grammar: column-0 headers open sections (`GEM`, `PATH`, `GIT`, `PLUGIN
//! SOURCE`, `PLATFORMS`, `DEPENDENCIES`, `CHECKSUMS`, `RUBY VERSION`,
//! `BUNDLED WITH`). A source section carries 2-space `remote:` (and
//! `revision:` / `glob:` …) keys, then `specs:` whose 4-space
//! `name (version[-platform])` entries are the locked gems (6-space lines
//! are their dependency constraints). CRLF is tolerated (bundler accepts a
//! CRLF lock). The parse never fails: what bundler itself would refuse
//! (conflict markers, indented text before the first header, no bundler
//! section at all) is collected in [`GemfileLock::problems`] for the
//! readers that must refuse such a lock.

pub(crate) mod hosted;
pub(crate) mod manifest;

use std::collections::{BTreeSet, HashMap};

use crate::utils::digest::sha256_hex;
use crate::utils::purl::simple_purl;
use crate::vendor::lock_inventory::{http_url, LockIntegrity, LockfileEntry, SourceKind};


/// The Bundler lockfiles, legacy spelling first: `Gemfile.lock` and
/// `gems.locked` (what bundler writes instead when the manifest is
/// `gems.rb`).
pub(crate) const BUNDLER_LOCKS: [&str; 2] = ["Gemfile.lock", "gems.locked"];

/// The manifest bundler resolved `lock` from: `gems.rb` for `gems.locked`,
/// `Gemfile` otherwise.
pub(crate) fn bundler_manifest_for(lock: &str) -> &'static str {
    if lock == "gems.locked" {
        "gems.rb"
    } else {
        "Gemfile"
    }
}

/// Remote URLs compared the way bundler normalizes them (trailing `/`).
pub(crate) fn same_remote(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

/// Section headers that carry `remote:` + `specs:`.
const SOURCE_HEADERS: [&str; 4] = ["GEM", "PATH", "GIT", "PLUGIN SOURCE"];

/// Headers that identify a text file as a bundler lock at all.
const BUNDLER_HEADERS: [&str; 9] = [
    "GEM",
    "PATH",
    "GIT",
    "PLUGIN SOURCE",
    "PLATFORMS",
    "DEPENDENCIES",
    "CHECKSUMS",
    "RUBY VERSION",
    "BUNDLED WITH",
];

/// Git merge-conflict markers (bundler refuses a lock carrying them).
const CONFLICT_MARKERS: [&str; 4] = ["<<<<<<<", "=======", ">>>>>>>", "|||||||"];

/// A parsed `name (version[-platform])` spec entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Spec<'t> {
    pub(crate) name: &'t str,
    pub(crate) version: &'t str,
    pub(crate) platform: Option<&'t str>,
}

/// One 4-space `specs:` line of a source section.
#[derive(Debug)]
pub(crate) struct SpecLine<'t> {
    pub(crate) line_no: usize,
    /// The entry text, trimmed.
    pub(crate) raw: &'t str,
    pub(crate) parsed: Option<Spec<'t>>,
}

/// One source section (`GEM`, `PATH`, `GIT`, `PLUGIN SOURCE`).
#[derive(Debug)]
pub(crate) struct Section<'t> {
    pub(crate) header: &'t str,
    pub(crate) line_no: usize,
    /// The section's `remote:` values, trimmed, as written.
    pub(crate) remotes: Vec<&'t str>,
    pub(crate) specs: Vec<SpecLine<'t>>,
}

impl<'t> Section<'t> {
    /// The section's remotes as download bases: trailing `/` trimmed, empty
    /// ones dropped, in lock order (duplicates kept).
    pub(crate) fn remote_bases(&self) -> impl Iterator<Item = &'t str> + '_ {
        self.remotes
            .iter()
            .map(|r| r.trim_end_matches('/'))
            .filter(|r| !r.is_empty())
    }
}

#[derive(Debug)]
pub(crate) struct GemfileLock<'t> {
    pub(crate) sections: Vec<Section<'t>>,
    /// `None` when the lock has no `CHECKSUMS` section (bundler < 2.6).
    /// Keyed by `(name, parenthesized token)`; the value is the entry's
    /// lowercase sha256, or `None` for a bare / malformed / conflicting one.
    pub(crate) checksums: Option<HashMap<(&'t str, &'t str), Option<String>>>,
    /// `DEPENDENCIES` entries bundler marks source-pinned (`name …!`).
    pub(crate) pinned: BTreeSet<&'t str>,
    /// Every `DEPENDENCIES` entry: the gems bundler treats as DIRECT
    /// dependencies, however the Gemfile declares them (`eval_gemfile`, a
    /// loop, a `gemspec` development dependency, a plain `gem` line).
    pub(crate) direct: BTreeSet<&'t str>,
    /// Why bundler would refuse this lock, first problem first.
    pub(crate) problems: Vec<String>,
}

impl<'t> GemfileLock<'t> {
    /// The `GEM` sections, in lock order.
    pub(crate) fn gem_sections(&self) -> impl Iterator<Item = &Section<'t>> {
        self.sections.iter().filter(|s| s.header == "GEM")
    }

    /// The DISTINCT [`Section::remote_bases`] across all `GEM` sections, in
    /// first-appearance order.
    pub(crate) fn gem_remote_bases(&self) -> Vec<&'t str> {
        let mut out: Vec<&'t str> = Vec::new();
        for base in self.gem_sections().flat_map(Section::remote_bases) {
            if !out.contains(&base) {
                out.push(base);
            }
        }
        out
    }

    /// The sha256 `CHECKSUMS` pins `name (token)`, if the lock records a
    /// valid, unambiguous one.
    pub(crate) fn checksum(&self, name: &'t str, token: &'t str) -> Option<&str> {
        self.checksums.as_ref()?.get(&(name, token))?.as_deref()
    }

    /// [`Self::checksum`] as the lock pin readers record: the valid sha256
    /// as [`LockIntegrity::Sha256Hex`], `None` when the lock pins nothing.
    pub(crate) fn integrity(&self, name: &'t str, token: &'t str) -> Option<LockIntegrity> {
        self.checksum(name, token)
            .map(|sha| LockIntegrity::Sha256Hex(sha.to_string()))
    }
}

impl<'t> GemfileLock<'t> {
    /// Parse a lock text ([`parse`]).
    pub fn parse(text: &'t str) -> Self {
        parse(text)
    }

    /// The registry inventory: `GEM`-section `specs:` entries plus the
    /// bundler >= 2.6 `CHECKSUMS` sha256 pins when present (older locks stay
    /// discovery-only). Platform-suffixed specs are skipped (platform gems
    /// are unsupported for vendoring). Each spec resolves against its OWN
    /// section's remote (bundler >= 2 emits one GEM section per source); a
    /// section with several distinct remotes (a legacy bundler 1.x
    /// multisource lock) leaves its specs without a resolved URL, fail
    /// closed. What bundler would refuse (`problems`) still inventories
    /// whatever parsed. `None` when nothing is inventoried.
    pub fn entries(&self) -> Option<Vec<LockfileEntry>> {
        let gem_sections: Vec<&Section<'_>> = self.gem_sections().collect();
        let mut out = Vec::new();
        for section in &gem_sections {
            let remotes: Vec<&str> = section.remote_bases().collect();
            for spec in section.specs.iter().filter_map(|line| line.parsed) {
                if spec.platform.is_some() {
                    continue;
                }
                let Some(purl) = simple_purl("gem", spec.name, spec.version) else {
                    continue;
                };
                let (name, version) = (spec.name, spec.version);
                let integrity = self.integrity(name, version).unwrap_or(LockIntegrity::None);
                let resolved = match remotes.as_slice() {
                    [base] => gem_download_url(base, name, version),
                    // No remote (a missing `remote:` line defaults to rubygems.org
                    // ONLY when the whole lock has one remote-less GEM section —
                    // the pre-multisource shape) or several remotes: fail closed.
                    [] if gem_sections.len() == 1 => {
                        gem_download_url("https://rubygems.org", name, version)
                    }
                    _ => None,
                };
                out.push(LockfileEntry {
                    ecosystem: "gem",
                    source_kind: SourceKind::Unspecified,
                    purl,
                    resolved,
                    name: name.to_string(),
                    version: version.to_string(),
                    integrity,
                });
            }
        }
        (!out.is_empty()).then_some(out)
    }
}


/// Where a rubygems-compatible registry at `base` (no trailing `/`) serves
/// `name`-`version`'s `.gem` — the inventory's resolved URL and ledger
/// recovery's fetch URL. `None` for a non-http(s) base.
pub(crate) fn gem_download_url(base: &str, name: &str, version: &str) -> Option<String> {
    http_url(&format!("{base}/downloads/{name}-{version}.gem"))
}

/// Parse a Bundler lock (see the module docs).
pub(crate) fn parse(text: &str) -> GemfileLock<'_> {
    let mut sections: Vec<Section<'_>> = Vec::new();
    let mut checksums: Option<HashMap<(&str, &str), Option<String>>> = None;
    let mut problems: Vec<String> = Vec::new();
    let mut current: Option<usize> = None;
    let mut in_specs = false;
    let mut in_checksums = false;
    let mut in_dependencies = false;
    let mut pinned: BTreeSet<&str> = BTreeSet::new();
    let mut direct: BTreeSet<&str> = BTreeSet::new();
    let mut seen_header = false;
    let mut bundler_shaped = false;

    for (idx, raw) in text.split('\n').enumerate() {
        let line_no = idx + 1;
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            let header = line.trim_end();
            if CONFLICT_MARKERS.iter().any(|m| header.starts_with(m)) {
                problems.push(format!("line {line_no} is a merge-conflict marker"));
            }
            seen_header = true;
            bundler_shaped |= BUNDLER_HEADERS.contains(&header);
            in_specs = false;
            in_checksums = header == "CHECKSUMS";
            in_dependencies = header == "DEPENDENCIES";
            if in_checksums && checksums.is_none() {
                checksums = Some(HashMap::new());
            }
            current = if SOURCE_HEADERS.contains(&header) {
                sections.push(Section {
                    header,
                    line_no,
                    remotes: Vec::new(),
                    specs: Vec::new(),
                });
                Some(sections.len() - 1)
            } else {
                None
            };
            continue;
        }
        if !seen_header {
            problems.push(format!(
                "line {line_no} is indented text before the first section header"
            ));
            continue;
        }
        let trimmed = line.trim_start().trim_end();
        let indent = line.len() - line.trim_start().len();
        if let Some(sec) = current.map(|i| &mut sections[i]) {
            match indent {
                2 => {
                    if let Some(remote) = trimmed.strip_prefix("remote:") {
                        sec.remotes.push(remote.trim());
                    }
                    in_specs = trimmed == "specs:";
                }
                4 if in_specs => sec.specs.push(SpecLine {
                    line_no,
                    raw: trimmed,
                    parsed: parse_spec(trimmed),
                }),
                _ => {}
            }
        } else if in_dependencies && indent == 2 {
            let name = trimmed.split([' ', '(', '!']).next().unwrap_or_default();
            if !name.is_empty() {
                direct.insert(name);
            }
            if let Some(entry) = trimmed.strip_suffix('!') {
                let name = entry.split([' ', '(']).next().unwrap_or_default();
                if !name.is_empty() {
                    pinned.insert(name);
                }
            }
        } else if in_checksums && indent == 2 {
            if let (Some(map), Some((key, sha))) = (checksums.as_mut(), parse_checksum(trimmed)) {
                map.entry(key)
                    .and_modify(|prev| {
                        if *prev != sha {
                            *prev = None;
                        }
                    })
                    .or_insert(sha);
            }
        }
    }
    if !bundler_shaped {
        problems.push("it has no Bundler lockfile sections".to_string());
    }
    GemfileLock {
        sections,
        checksums,
        pinned,
        direct,
        problems,
    }
}

/// Whether the Bundler lock `lock` lists `name` under `DEPENDENCIES`, i.e.
/// bundler resolved it as a DIRECT dependency of the Gemfile. The Gemfile
/// rewriters consult it before treating a gem they cannot see declared as
/// transitive: appending a declaration for a gem the Gemfile already
/// declares out of sight (`eval_gemfile`, a loop) leaves it declared twice,
/// and bundler refuses every install (#482).
pub(crate) fn lock_lists_direct_dependency(lock: &str, name: &str) -> bool {
    parse(lock).direct.contains(name)
}

/// The plain gem-token charset (letters, digits, `.`, `_`, `-`). The vendor
/// backend applies it before embedding coordinates into Ruby source and lock
/// line grammar (see the SECURITY note in `crate::vendor::gem`'s
/// `gem_prelude`, which [`crate::vendor::gem::vendor_gem`] runs first), so it
/// is deliberately stricter than the path-level segment guard.
pub(crate) fn is_plain_gem_token(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// `name (version)` / `name (version-platform)`, nothing after the `)`.
/// RubyGems versions never contain `-` (it is normalized to `.pre.`), so the
/// first `-` inside the parens starts the platform. Dependency lines (no
/// parens, range operators) yield `None`.
pub(crate) fn parse_spec(entry: &str) -> Option<Spec<'_>> {
    let Some((name, inner, "")) = split_entry(entry) else {
        return None;
    };
    if !is_plain_gem_token(name) || !is_plain_gem_token(inner) {
        return None;
    }
    let (version, platform) = match inner.split_once('-') {
        Some((version, platform)) => (version, Some(platform)),
        None => (inner, None),
    };
    if version.is_empty()
        || !version.starts_with(|c: char| c.is_ascii_digit())
        || platform.is_some_and(str::is_empty)
    {
        return None;
    }
    Some(Spec {
        name,
        version,
        platform,
    })
}

/// A lock entry with its indent stripped — `name (token)…`, a `specs:` or
/// `CHECKSUMS` line: the name, the parenthesized token (platform suffix
/// included) and the text after the first `)`. Name and token are non-empty;
/// nothing else is checked.
pub(crate) fn split_entry(entry: &str) -> Option<(&str, &str, &str)> {
    let (name, rest) = entry.split_once(" (")?;
    let (token, tail) = rest.split_once(')')?;
    (!name.is_empty() && !token.is_empty()).then_some((name, token, tail))
}

/// A `CHECKSUMS` entry: [`split_entry`] followed by nothing or by
/// space-separated `algo=digest` tokens (`sha256=<hex>` on registry
/// entries, nothing on path entries).
pub(crate) fn split_checksum_entry(entry: &str) -> Option<(&str, &str, &str)> {
    split_entry(entry).filter(|(_, _, tail)| tail.is_empty() || tail.starts_with(' '))
}

/// A 2-space `CHECKSUMS` entry ([`split_checksum_entry`]): the
/// `(name, token)` key and the valid lowercase sha256, if any.
fn parse_checksum(entry: &str) -> Option<((&str, &str), Option<String>)> {
    let (name, inner, tail) = split_checksum_entry(entry)?;
    let sha = tail
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("sha256="))
        .and_then(sha256_hex);
    Some(((name, inner), sha))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_and_checksum_grammar() {
        let sha = "deadbeef".repeat(8);
        assert_eq!(
            parse_spec("rails (7.0.0)"),
            Some(Spec {
                name: "rails",
                version: "7.0.0",
                platform: None
            })
        );
        assert_eq!(
            parse_spec("ffi (1.17.2-aarch64-linux-gnu)").and_then(|s| s.platform),
            Some("aarch64-linux-gnu")
        );
        for bad in [
            "rails",
            "rails (7.0.0) x",
            "rails (>= 7.0)",
            "rails ()",
            "rails (-x)",
            "rails (7.0.0-)",
            "(7.0.0)",
        ] {
            assert_eq!(parse_spec(bad), None, "{bad}");
        }
        assert_eq!(
            parse_checksum(&format!("rails (7.0.0) sha256={sha}")),
            Some((("rails", "7.0.0"), Some(sha.to_string())))
        );
        assert_eq!(
            parse_checksum("rails (7.0.0)"),
            Some((("rails", "7.0.0"), None))
        );
        assert_eq!(
            parse_checksum("rails (7.0.0) sha256=abc"),
            Some((("rails", "7.0.0"), None))
        );
    }

    #[test]
    fn sections_specs_checksums_and_pins() {
        let sha = "A".repeat(64);
        let text = format!(
            "GEM\r\n  remote: https://rubygems.org/\r\n  specs:\r\n    rails (7.1.0)\r\n      \
             rack (>= 2)\r\n    nokogiri (1.16.5-arm64-darwin)\r\n\r\nPATH\r\n  remote: \
             vendor/x\r\n  specs:\r\n    x (1.0.0)\r\n\r\nDEPENDENCIES\r\n  rails!\r\n  \
             x\r\n\r\nCHECKSUMS\r\n  rails (7.1.0) sha256={sha}\r\n  x (1.0.0)\r\n"
        );
        let lock = parse(&text);
        assert!(lock.problems.is_empty(), "{:?}", lock.problems);
        assert_eq!(lock.sections.len(), 2);
        let gem = lock.gem_sections().next().unwrap();
        assert_eq!(gem.remotes, ["https://rubygems.org/"]);
        let specs: Vec<Option<Spec<'_>>> = gem.specs.iter().map(|s| s.parsed).collect();
        assert_eq!(
            specs,
            [
                Some(Spec {
                    name: "rails",
                    version: "7.1.0",
                    platform: None
                }),
                Some(Spec {
                    name: "nokogiri",
                    version: "1.16.5",
                    platform: Some("arm64-darwin")
                }),
            ],
            "6-space dependency lines are not specs"
        );
        assert_eq!(
            lock.checksum("rails", "7.1.0"),
            Some("a".repeat(64).as_str())
        );
        assert_eq!(
            lock.checksum("x", "1.0.0"),
            None,
            "a bare entry pins nothing"
        );
        assert_eq!(lock.pinned.iter().copied().collect::<Vec<_>>(), ["rails"]);
    }

    #[test]
    fn conflicting_checksums_pin_nothing_and_problems_are_collected() {
        let text = format!(
            "GEM\n  specs:\n    a (1.0)\n\nCHECKSUMS\n  a (1.0) sha256={}\n  a (1.0) sha256={}\n",
            "1".repeat(64),
            "2".repeat(64)
        );
        let lock = parse(&text);
        assert_eq!(lock.checksum("a", "1.0"), None);
        assert!(lock.problems.is_empty());

        let lock = parse("  stray\nGEM\n<<<<<<< HEAD\n");
        assert_eq!(lock.problems.len(), 2, "{:?}", lock.problems);
        assert!(lock.problems[0].contains("before the first section header"));
        assert!(lock.problems[1].contains("merge-conflict marker"));
        assert!(
            !parse("just text\n").problems.is_empty(),
            "not a bundler lock"
        );
    }
}
