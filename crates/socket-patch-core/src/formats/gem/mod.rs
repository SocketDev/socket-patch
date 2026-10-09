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

pub(crate) mod gemfile;
pub(crate) mod hosted;
pub(crate) mod manifest;
pub(crate) mod mirror;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::OnceLock;

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

/// `CHECKSUMS` digests by gem name, then by parenthesized token.
type ChecksumMap = HashMap<String, Vec<(String, Option<String>)>>;

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
    /// The number of the section's last line: the line before the next
    /// column-0 header, or the file's last line (blank separators belong to
    /// the section they follow). As a 0-based index it is the exclusive end
    /// of [`Self::lines`].
    pub(crate) end: usize,
    /// The section's `remote:` values, trimmed, as written.
    pub(crate) remotes: Vec<&'t str>,
    /// The line number of each of [`Self::remotes`], in the same order.
    pub(crate) remote_line_nos: Vec<usize>,
    pub(crate) specs: Vec<SpecLine<'t>>,
}

impl<'t> Section<'t> {
    /// The section's lines as 0-based indices into the lock's
    /// `split_inclusive('\n')` lines: its header through its last line.
    pub(crate) fn lines(&self) -> std::ops::Range<usize> {
        self.line_no - 1..self.end
    }

    /// Bundler's source identifier for the section: its remotes joined by
    /// `", "`, the key `SourceList#lock_rubygems_sources` sorts `GEM`
    /// sections by.
    pub(crate) fn identifier(&self) -> String {
        self.remotes.join(", ")
    }

    /// The section's remotes as download bases: trailing `/` trimmed, empty
    /// ones dropped, in lock order (duplicates kept).
    pub(crate) fn remote_bases(&self) -> impl Iterator<Item = &'t str> + '_ {
        self.remotes
            .iter()
            .map(|r| r.trim_end_matches('/'))
            .filter(|r| !r.is_empty())
    }
}

/// One 2-space `DEPENDENCIES` entry (`rack`, `rack!`, `rack (~> 3.1)`,
/// `rack (= 3.2.6)!`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Dependency<'t> {
    pub(crate) line_no: usize,
    /// The gem name: the text before any space, `(` or `!`.
    pub(crate) name: &'t str,
    /// Whether bundler marks the entry source-pinned (a trailing `!`).
    pub(crate) pinned: bool,
}

/// The `DEPENDENCIES` section.
#[derive(Debug)]
pub(crate) struct Dependencies<'t> {
    /// The header's line number.
    pub(crate) line_no: usize,
    /// The section's last line number, as [`Section::end`].
    pub(crate) end: usize,
    /// Its entries, in lock order.
    pub(crate) entries: Vec<Dependency<'t>>,
}

#[derive(Debug)]
pub(crate) struct GemfileLock<'t> {
    pub(crate) sections: Vec<Section<'t>>,
    /// The (last) `DEPENDENCIES` section; `None` when the lock has none.
    pub(crate) dependencies: Option<Dependencies<'t>>,
    /// The `CHECKSUMS` section's 2-space entries, trimmed; `None` when the
    /// lock has no `CHECKSUMS` section (bundler < 2.6). Their digests are
    /// read only when a reader asks for one ([`Self::checksum`]): the
    /// hosted lock writer parses the lock once per converged gem and never
    /// does, and validating every digest dominates the parse.
    checksum_entries: Option<Vec<&'t str>>,
    /// [`Self::checksum_entries`] by name, then parenthesized token; the
    /// value is the entry's lowercase sha256, or `None` for a bare /
    /// malformed / conflicting one. Built on first use, with owned keys so
    /// the lock stays covariant in `'t`.
    checksums: OnceLock<ChecksumMap>,
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

    /// Every gem the non-registry source sections (`GIT`, `PATH`, `PLUGIN
    /// SOURCE`) list in their specs (any version), mapped to the first such
    /// section: bundler resolves those gems from there, not from a `GEM`
    /// remote.
    pub(crate) fn non_registry_sources(&self) -> HashMap<&'t str, &Section<'t>> {
        let mut out = HashMap::new();
        for section in self.sections.iter().filter(|s| s.header != "GEM") {
            for spec in section.specs.iter().filter_map(|l| l.parsed) {
                out.entry(spec.name).or_insert(section);
            }
        }
        out
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
        let entries = self.checksum_entries.as_ref()?;
        let checksums = self.checksums.get_or_init(|| {
            let mut map = ChecksumMap::new();
            for ((name, token), sha) in entries.iter().filter_map(|entry| parse_checksum(entry)) {
                let tokens = map.entry(name.to_string()).or_default();
                match tokens.iter_mut().find(|(t, _)| t == token) {
                    Some((_, prev)) if *prev != sha => *prev = None,
                    Some(_) => {}
                    None => tokens.push((token.to_string(), sha)),
                }
            }
            map
        });
        checksums
            .get(name)?
            .iter()
            .find(|(t, _)| t == token)?
            .1
            .as_deref()
    }

    /// Whether the lock has a `CHECKSUMS` section (bundler >= 2.6).
    pub(crate) fn has_checksums(&self) -> bool {
        self.checksum_entries.is_some()
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
    let mut checksum_entries: Option<Vec<&str>> = None;
    let mut problems: Vec<String> = Vec::new();
    let mut current: Option<usize> = None;
    let mut in_specs = false;
    let mut in_checksums = false;
    let mut in_dependencies = false;
    let mut pinned: BTreeSet<&str> = BTreeSet::new();
    let mut direct: BTreeSet<&str> = BTreeSet::new();
    let mut dependencies: Option<Dependencies<'_>> = None;
    let mut seen_header = false;
    let mut bundler_shaped = false;
    // The section or DEPENDENCIES block a column-0 header closes.
    let close = |sections: &mut Vec<Section<'_>>,
                 dependencies: &mut Option<Dependencies<'_>>,
                 current: Option<usize>,
                 in_dependencies: bool,
                 end: usize| {
        if let Some(i) = current {
            sections[i].end = end;
        } else if let Some(deps) = dependencies.as_mut().filter(|_| in_dependencies) {
            deps.end = end;
        }
    };

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
            close(
                &mut sections,
                &mut dependencies,
                current,
                in_dependencies,
                idx,
            );
            bundler_shaped |= BUNDLER_HEADERS.contains(&header);
            in_specs = false;
            in_checksums = header == "CHECKSUMS";
            in_dependencies = header == "DEPENDENCIES";
            if in_checksums && checksum_entries.is_none() {
                checksum_entries = Some(Vec::new());
            }
            if in_dependencies {
                dependencies = Some(Dependencies {
                    line_no,
                    end: line_no,
                    entries: Vec::new(),
                });
            }
            current = if SOURCE_HEADERS.contains(&header) {
                sections.push(Section {
                    header,
                    line_no,
                    end: line_no,
                    remotes: Vec::new(),
                    remote_line_nos: Vec::new(),
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
                        sec.remote_line_nos.push(line_no);
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
                let entry = Dependency {
                    line_no,
                    name,
                    pinned: trimmed.ends_with('!'),
                };
                direct.insert(name);
                if entry.pinned {
                    pinned.insert(name);
                }
                if let Some(deps) = dependencies.as_mut() {
                    deps.entries.push(entry);
                }
            }
        } else if in_checksums && indent == 2 {
            if let Some(entries) = checksum_entries.as_mut() {
                entries.push(trimmed);
            }
        }
    }
    let last_line = text.split_inclusive('\n').count();
    close(
        &mut sections,
        &mut dependencies,
        current,
        in_dependencies,
        last_line,
    );
    if !bundler_shaped {
        problems.push("it has no Bundler lockfile sections".to_string());
    }
    GemfileLock {
        sections,
        dependencies,
        checksum_entries,
        checksums: OnceLock::new(),
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

/// Every `name (version)` spec the `GEM` sections of the Bundler lock `lock`
/// list (any platform). Hosted mode only re-points what the lock resolves:
/// a version that is merely installed on the machine (another project's
/// copy in the shared gem home) must never be pinned (#1055).
pub(crate) fn locked_specs(lock: &str) -> HashSet<(&str, &str)> {
    parse(lock)
        .gem_sections()
        .flat_map(|s| s.specs.iter().filter_map(|l| l.parsed))
        .map(|spec| (spec.name, spec.version))
        .collect()
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

    /// Section spans, remote line numbers and DEPENDENCIES entries: what the
    /// hosted lock writer splices by. Blank (and whitespace-only) separator
    /// lines belong to the section they follow; a CRLF lock gives the same
    /// numbers as its LF spelling, and the last section runs to the last
    /// line whether or not the file ends with a newline.
    #[test]
    fn section_spans_remote_lines_and_dependency_entries() {
        let lf = "GEM\n  remote: https://a.example/\n  specs:\n    rack (3.1.0)\n\nGEM\n  remote: https://b.example/\n  specs:\n    rails (7.0.0)\n      rack\n \n\nPATH\n  remote: .\n  specs:\n    app (0.1.0)\n\nDEPENDENCIES\n  app!\n  rack\n  rack (~> 3.1)\n  rails (= 7.0.0)!\n   nested (1.0)\n\nBUNDLED WITH\n   2.6.2\n\n";
        for text in [
            lf.to_string(),
            lf.replace('\n', "\r\n"),
            lf.trim_end().to_string(),
        ] {
            let lock = parse(&text);
            let spans: Vec<_> = lock
                .sections
                .iter()
                .map(|s| {
                    (
                        s.header,
                        s.lines(),
                        s.remote_line_nos.clone(),
                        s.identifier(),
                    )
                })
                .collect();
            assert_eq!(
                spans,
                [
                    ("GEM", 0..5, vec![2], "https://a.example/".to_string()),
                    ("GEM", 5..12, vec![7], "https://b.example/".to_string()),
                    ("PATH", 12..17, vec![14], ".".to_string()),
                ]
            );
            let deps = lock.dependencies.as_ref().expect("DEPENDENCIES");
            assert_eq!((deps.line_no, deps.end), (18, 24));
            let entries: Vec<_> = deps
                .entries
                .iter()
                .map(|e| (e.line_no, e.name, e.pinned))
                .collect();
            assert_eq!(
                entries,
                [
                    (19, "app", true),
                    (20, "rack", false),
                    (21, "rack", false),
                    (22, "rails", true)
                ]
            );
            assert_eq!(
                lock.direct.iter().copied().collect::<Vec<_>>(),
                ["app", "rack", "rails"]
            );
            assert_eq!(
                lock.pinned.iter().copied().collect::<Vec<_>>(),
                ["app", "rails"]
            );
            let lines = text.split_inclusive('\n').count();
            assert_eq!(lines, if text.ends_with('\n') { 27 } else { 26 });
        }
        // The last section runs to the last line.
        let lock = parse("GEM\n  remote: https://a.example/\n  specs:\n    rack (3.1.0)\n\n");
        assert_eq!(lock.sections[0].lines(), 0..5);
        assert!(lock.dependencies.is_none());
        let lock = parse("DEPENDENCIES\n  rack");
        let deps = lock.dependencies.expect("DEPENDENCIES");
        assert_eq!((deps.line_no, deps.end, deps.entries.len()), (1, 2, 1));
    }

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
