//! The `.gem` archives a native extension is rebuilt from
//! ([`crate::patch::gem_ext`]): the source gem of the installed copy, and
//! the gems its build needs that are not installed.
//!
//! An installed gem does not hold everything its extension was built from.
//! nokogiri's `extconf.rb` deletes the vendored libxml2 and libxslt
//! tarballs (`ports/`) once the build is done, and a precompiled platform
//! gem ships neither the build scripts' inputs (`patches/`, `ports/`) nor a
//! build of its own. The complete inputs are in the ruby-platform source
//! archive, `<name>-<version>.gem`. This module finds it:
//!
//! 1. In the gem home's `cache/`, where RubyGems and Bundler keep the
//!    archive of every gem they install from source. It is used as it is,
//!    unless the project's lock pins a `CHECKSUMS` sha256 for the gem that
//!    it does not have. No network is involved.
//! 2. Else downloaded from the gem's source: the `remote:` of the lock's
//!    `GEM` section that lists the gem, else rubygems.org
//!    (`SOCKET_RUBYGEMS_URL`). The bytes must have the sha256 the lock's
//!    `CHECKSUMS` pins for the ruby-platform gem, else the one that source's
//!    compact index (`info/<name>`) records. An archive nothing pins is not
//!    used. `--offline` skips this step.
//!
//! A gem the build needs and the install lacks (a precompiled nokogiri has
//! no `mini_portile2`) is resolved from the same sources' compact index:
//! the newest ruby-platform release that meets the requirement and runs on
//! the building Ruby, verified against the index's checksum.

use std::cmp::Ordering;
use std::path::Path;

use crate::formats::gem::{self, BUNDLER_LOCKS};
use crate::patch::redirect::upstream::{compact_index_checksum, rubygems_base};
use crate::utils::digest::{sha256_hex, sha256_hex_of};
use crate::vendor::registry_fetch::{build_registry_client, download, RegistryClient};

/// The default gem source, as a lock's `remote:` spells it.
const RUBYGEMS_REMOTE: &str = "https://rubygems.org";

/// One gem release: `<name>-<version>[-<platform>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GemId {
    pub name: String,
    pub version: String,
    /// `None` for the `ruby` platform (the source gem).
    pub platform: Option<String>,
}

impl GemId {
    /// The release as a lock or a compact index names it: `<version>` or
    /// `<version>-<platform>`.
    pub(crate) fn token(&self) -> String {
        match &self.platform {
            Some(platform) => format!("{}-{platform}", self.version),
            None => self.version.clone(),
        }
    }

    /// `<name>-<version>[-<platform>]`, as its gem dir and archive are named.
    pub(crate) fn full_name(&self) -> String {
        format!("{}-{}", self.name, self.token())
    }

    /// Every part is a plain gem token: nothing that would change the
    /// meaning of a path or a URL it is put in.
    fn is_plain(&self) -> bool {
        gem::is_plain_gem_token(&self.name)
            && gem::is_plain_gem_token(&self.version)
            && self.platform.as_deref().is_none_or(gem::is_plain_gem_token)
    }
}

/// What the project's lock says about a gem release.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Locked {
    /// The remotes of the `GEM` sections that list the gem at this version
    /// (any platform of it), as download bases, in lock order.
    pub bases: Vec<String>,
    /// The sha256 `CHECKSUMS` pins for exactly this release.
    pub sha256: Option<String>,
}

/// Read [`Locked`] for `id` out of a Bundler lock's text.
pub(crate) fn locked(lock: &str, id: &GemId) -> Locked {
    let token = id.token();
    let text = crate::utils::line_endings::to_lf(lock);
    let parsed = gem::parse(&text);
    let mut bases: Vec<String> = Vec::new();
    for section in parsed.gem_sections() {
        let lists = section
            .specs
            .iter()
            .filter_map(|line| line.parsed)
            .any(|spec| spec.name == id.name && spec.version == id.version);
        if !lists {
            continue;
        }
        for base in section.remote_bases() {
            if !bases.iter().any(|b| b == base) {
                bases.push(base.to_string());
            }
        }
    }
    let sha256 = parsed.checksum(&id.name, &token).map(str::to_string);
    Locked { bases, sha256 }
}

/// The base a lock remote is downloaded from: rubygems.org goes through its
/// `SOCKET_RUBYGEMS_URL` stand-in (a mirror, a test server).
fn download_base(remote: &str) -> String {
    if gem::same_remote(remote, RUBYGEMS_REMOTE) {
        rubygems_base()
    } else {
        remote.trim_end_matches('/').to_string()
    }
}

/// Where gem archives come from in one run: the project's lock, read once,
/// and the registry client.
pub(crate) struct GemSource {
    lock: Option<String>,
    offline: bool,
    http: RegistryClient,
}

impl GemSource {
    /// The source for the project at `project` (its `Gemfile.lock` or
    /// `gems.locked`, when it has one).
    pub(crate) async fn of(project: &Path, offline: bool) -> GemSource {
        let mut lock = None;
        for file in BUNDLER_LOCKS {
            // Guarded: a FIFO squatting the lock path must not block.
            if let Ok(text) = crate::utils::fs::read_regular_to_string(&project.join(file)).await {
                lock = Some(text);
                break;
            }
        }
        GemSource {
            lock,
            offline,
            http: build_registry_client(),
        }
    }

    pub(crate) fn offline(&self) -> bool {
        self.offline
    }

    fn locked(&self, id: &GemId) -> Locked {
        self.lock
            .as_deref()
            .map(|lock| locked(lock, id))
            .unwrap_or_default()
    }

    /// The bases `id` may be downloaded from, best first: the lock's
    /// remotes for it, else the default registry.
    pub(crate) fn bases(&self, id: &GemId) -> Vec<String> {
        let mut bases: Vec<String> = Vec::new();
        for remote in self.locked(id).bases {
            let base = download_base(&remote);
            if !bases.contains(&base) {
                bases.push(base);
            }
        }
        if bases.is_empty() {
            bases.push(rubygems_base());
        }
        bases
    }

    /// The archive of `id` in the gem home `home`'s `cache/`, when it is
    /// there and is not one the lock's `CHECKSUMS` contradicts.
    pub(crate) async fn cached(&self, home: &Path, id: &GemId) -> Option<Vec<u8>> {
        if !id.is_plain() {
            return None;
        }
        let path = cache_path(home, id);
        let meta = tokio::fs::symlink_metadata(&path).await.ok()?;
        if !meta.is_file() || meta.len() > crate::vendor::registry_fetch::MAX_DOWNLOAD_BYTES {
            return None;
        }
        let bytes = crate::utils::fs::read_regular_to_bytes(&path).await.ok()?;
        match self.locked(id).sha256 {
            Some(pinned) if pinned != sha256_hex_of(&bytes) => None,
            _ => Some(bytes),
        }
    }

    /// Whether [`Self::archive`] can possibly produce `id` for `home`: its
    /// cached archive is there, or the run may download. Read-only, for a
    /// dry run's refusal.
    pub(crate) async fn may_have(&self, home: &Path, id: &GemId) -> bool {
        !self.offline || self.cached(home, id).await.is_some()
    }

    /// The archive of `id`, sha256-verified: the home's cached copy, else a
    /// download from its source. `Err` is why there is none.
    pub(crate) async fn archive(&self, home: &Path, id: &GemId) -> Result<Vec<u8>, String> {
        let file = format!("{}.gem", id.full_name());
        if !id.is_plain() {
            return Err(format!("{file} is not a plain gem archive name"));
        }
        if let Some(bytes) = self.cached(home, id).await {
            return Ok(bytes);
        }
        let cache = cache_path(home, id);
        if self.offline {
            return Err(format!(
                "{} is not there and this run is offline",
                cache.display()
            ));
        }
        let pinned = self.locked(id).sha256;
        let mut reasons: Vec<String> = Vec::new();
        for base in self.bases(id) {
            let want = match &pinned {
                Some(sha) => sha.clone(),
                None => match self.index_checksum(&base, id).await {
                    Ok(sha) => sha,
                    Err(why) => {
                        reasons.push(why);
                        continue;
                    }
                },
            };
            let url = format!("{base}/gems/{file}");
            match download(&self.http, &url).await {
                Ok(bytes) if sha256_hex_of(&bytes) == want => return Ok(bytes),
                Ok(_) => reasons.push(format!(
                    "{} does not have the sha256 {} pins for it",
                    crate::utils::redact::redact_urls_in(&url),
                    if pinned.is_some() {
                        "the lock's CHECKSUMS"
                    } else {
                        "its source's index"
                    }
                )),
                Err(why) => reasons.push(why),
            }
        }
        Err(format!(
            "{} is not there and it could not be downloaded ({})",
            cache.display(),
            reasons.join("; ")
        ))
    }

    /// The sha256 the compact index at `base` records for `id`.
    async fn index_checksum(&self, base: &str, id: &GemId) -> Result<String, String> {
        let url = format!("{base}/info/{}", id.name);
        let info = self.index(&url).await?;
        compact_index_checksum(&info, &id.token()).ok_or_else(|| {
            format!(
                "{} lists no {} with a checksum",
                crate::utils::redact::redact_urls_in(&url),
                id.token()
            )
        })
    }

    async fn index(&self, url: &str) -> Result<String, String> {
        let bytes = download(&self.http, url).await?;
        String::from_utf8(bytes)
            .map_err(|_| format!("{} is not UTF-8", crate::utils::redact::redact_urls_in(url)))
    }

    /// A ruby-platform release of the gem `name` that meets `requirement`
    /// (`~> 2.8.2`, `>= 1.0,< 3`) and runs on `ruby`, from the first of
    /// `bases` that has one: its id and its verified archive.
    pub(crate) async fn dependency(
        &self,
        bases: &[String],
        name: &str,
        requirement: &str,
        ruby: &RubyVersions,
    ) -> Result<(GemId, Vec<u8>), String> {
        if !gem::is_plain_gem_token(name) {
            return Err(format!("{name:?} is not a plain gem name"));
        }
        if self.offline {
            return Err("this run is offline".to_string());
        }
        let mut reasons: Vec<String> = Vec::new();
        for base in bases {
            let url = format!("{base}/info/{name}");
            let info = match self.index(&url).await {
                Ok(info) => info,
                Err(why) => {
                    reasons.push(why);
                    continue;
                }
            };
            let Some((version, sha)) = pick_release(&info, requirement, ruby) else {
                reasons.push(format!(
                    "{} lists no release that meets {requirement}",
                    crate::utils::redact::redact_urls_in(&url)
                ));
                continue;
            };
            let id = GemId {
                name: name.to_string(),
                version,
                platform: None,
            };
            if !id.is_plain() {
                continue;
            }
            let archive = format!("{base}/gems/{}.gem", id.full_name());
            match download(&self.http, &archive).await {
                Ok(bytes) if sha256_hex_of(&bytes) == sha => return Ok((id, bytes)),
                Ok(_) => reasons.push(format!(
                    "{} does not have the sha256 its source's index pins for it",
                    crate::utils::redact::redact_urls_in(&archive)
                )),
                Err(why) => reasons.push(why),
            }
        }
        Err(reasons.join("; "))
    }
}

/// `<home>/cache/<full name>.gem`.
pub(crate) fn cache_path(home: &Path, id: &GemId) -> std::path::PathBuf {
    home.join("cache").join(format!("{}.gem", id.full_name()))
}

/// The versions of the Ruby a gem is installed for, as its compact index
/// constrains them (`ruby:>= 3.1`, `rubygems:>= 3.3.22`). `None`: unknown,
/// not checked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RubyVersions {
    pub ruby: Option<String>,
    pub rubygems: Option<String>,
}

/// The newest ruby-platform release in a compact index `info/<name>` file
/// that meets `requirement` and whose `ruby:` / `rubygems:` constraints the
/// building Ruby meets: `(version, sha256)`. A prerelease is picked only
/// for a requirement that names one, as RubyGems resolves. Lines are
/// `<version>[-<platform>] <deps>|checksum:<hex>[,ruby:<req>][,rubygems:<req>]`.
pub(crate) fn pick_release(
    info: &str,
    requirement: &str,
    ruby: &RubyVersions,
) -> Option<(String, String)> {
    let wanted = Requirement::parse(requirement)?;
    let mut best: Option<(Version, String, String)> = None;
    for line in info.lines() {
        let Some((head, reqs)) = line.split_once('|') else {
            continue;
        };
        let token = head.split(' ').next().unwrap_or("");
        // A `-` starts a platform: only the source gem is installed.
        if token.is_empty() || token.contains('-') {
            continue;
        }
        let Some(version) = Version::parse(token) else {
            continue;
        };
        if version.is_prerelease() && !wanted.names_prerelease() {
            continue;
        }
        if !wanted.allows(&version) {
            continue;
        }
        let (mut sha, mut runs) = (None, true);
        for req in reqs.split(',') {
            let req = req.trim();
            if let Some(hex) = req.strip_prefix("checksum:") {
                sha = sha256_hex(hex);
            } else if let Some(constraint) = req.strip_prefix("ruby:") {
                runs &= meets(ruby.ruby.as_deref(), constraint);
            } else if let Some(constraint) = req.strip_prefix("rubygems:") {
                runs &= meets(ruby.rubygems.as_deref(), constraint);
            }
        }
        let Some(sha) = sha.filter(|_| runs) else {
            continue;
        };
        if best
            .as_ref()
            .is_none_or(|(have, _, _)| version.cmp(have) == Ordering::Greater)
        {
            best = Some((version, token.to_string(), sha));
        }
    }
    best.map(|(_, version, sha)| (version, sha))
}

/// Whether `version` meets a compact index constraint (`>= 2.3.0`, or
/// several joined by `&`). An unknown version, or a constraint that does
/// not parse, is not held against the release.
fn meets(version: Option<&str>, constraint: &str) -> bool {
    let Some(version) = version.and_then(Version::parse) else {
        return true;
    };
    constraint
        .split('&')
        .filter_map(Requirement::parse)
        .all(|req| req.allows(&version))
}

/// One segment of a gem version.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Number(u64),
    Text(String),
}

/// A gem version, ordered as `Gem::Version` orders it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Version {
    segments: Vec<Segment>,
}

impl Version {
    /// `Gem::Version.new`: runs of digits and of letters, separated by
    /// dots (or by nothing where a digit meets a letter). `None` for
    /// anything that is not a gem version.
    pub(crate) fn parse(text: &str) -> Option<Version> {
        let text = text.trim();
        let valid = !text.is_empty()
            && text.starts_with(|c: char| c.is_ascii_digit())
            && text
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
        if !valid {
            return None;
        }
        // RubyGems reads `1.0-rc1` as `1.0.pre.rc1`.
        let text = text.replace('-', ".pre.");
        let mut segments = Vec::new();
        let mut chars = text.chars().peekable();
        while let Some(&c) = chars.peek() {
            if c == '.' {
                chars.next();
                continue;
            }
            let digits = c.is_ascii_digit();
            let mut run = String::new();
            while let Some(&d) = chars.peek() {
                if d == '.' || d.is_ascii_digit() != digits {
                    break;
                }
                run.push(d);
                chars.next();
            }
            segments.push(if digits {
                Segment::Number(run.parse().ok()?)
            } else {
                Segment::Text(run)
            });
        }
        Some(Version { segments })
    }

    pub(crate) fn is_prerelease(&self) -> bool {
        self.segments.iter().any(|s| matches!(s, Segment::Text(_)))
    }

    /// The segments before the first letter run (`1.2.b1` → `1.2`).
    fn release(&self) -> Version {
        let segments = self
            .segments
            .iter()
            .take_while(|s| matches!(s, Segment::Number(_)))
            .cloned()
            .collect();
        Version { segments }
    }

    /// `Gem::Version#bump`: the release with its last segment dropped (when
    /// it has more than one) and the new last one incremented, the upper
    /// bound of `~>`.
    fn bump(&self) -> Version {
        let mut segments = self.release().segments;
        if segments.len() > 1 {
            segments.pop();
        }
        match segments.last_mut() {
            Some(Segment::Number(n)) => *n += 1,
            _ => segments.push(Segment::Number(1)),
        }
        Version { segments }
    }

    /// `Gem::Version#canonical_segments`: trailing zeros dropped from the
    /// numeric part and from the part that starts at the first letter run.
    fn canonical(&self) -> Vec<Segment> {
        let split = self
            .segments
            .iter()
            .position(|s| matches!(s, Segment::Text(_)))
            .unwrap_or(self.segments.len());
        let trim = |part: &[Segment]| {
            let mut part = part.to_vec();
            while matches!(part.last(), Some(Segment::Number(0))) {
                part.pop();
            }
            part
        };
        let mut out = trim(&self.segments[..split]);
        out.extend(trim(&self.segments[split..]));
        out
    }

    /// `Gem::Version#<=>`.
    pub(crate) fn cmp(&self, other: &Version) -> Ordering {
        let (lhs, rhs) = (self.canonical(), other.canonical());
        let zero = Segment::Number(0);
        for i in 0..lhs.len().max(rhs.len()) {
            let (l, r) = (lhs.get(i).unwrap_or(&zero), rhs.get(i).unwrap_or(&zero));
            let ordering = match (l, r) {
                (Segment::Number(l), Segment::Number(r)) => l.cmp(r),
                (Segment::Text(l), Segment::Text(r)) => l.cmp(r),
                (Segment::Text(_), Segment::Number(_)) => Ordering::Less,
                (Segment::Number(_), Segment::Text(_)) => Ordering::Greater,
            };
            if ordering != Ordering::Equal {
                return ordering;
            }
        }
        Ordering::Equal
    }
}

/// A `Gem::Requirement`: every clause must hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Requirement {
    clauses: Vec<(String, Version)>,
}

impl Requirement {
    /// Parse `~> 2.8.2`, `>= 1.0, < 3` or a bare `1.2` (`=`). `None` for an
    /// operator or version RubyGems would not accept.
    pub(crate) fn parse(text: &str) -> Option<Requirement> {
        let mut clauses = Vec::new();
        for clause in text.split(',') {
            let clause = clause.trim();
            if clause.is_empty() {
                continue;
            }
            let at = clause
                .find(|c: char| c.is_ascii_digit())
                .unwrap_or(clause.len());
            let (op, version) = (clause[..at].trim(), clause[at..].trim());
            let op = if op.is_empty() { "=" } else { op };
            if !["=", "!=", ">", "<", ">=", "<=", "~>"].contains(&op) {
                return None;
            }
            clauses.push((op.to_string(), Version::parse(version)?));
        }
        (!clauses.is_empty()).then_some(Requirement { clauses })
    }

    /// `Gem::Requirement#prerelease?`.
    fn names_prerelease(&self) -> bool {
        self.clauses.iter().any(|(_, v)| v.is_prerelease())
    }

    /// `Gem::Requirement#satisfied_by?`.
    pub(crate) fn allows(&self, version: &Version) -> bool {
        self.clauses.iter().all(|(op, wanted)| {
            let ordering = version.cmp(wanted);
            match op.as_str() {
                "=" => ordering == Ordering::Equal,
                "!=" => ordering != Ordering::Equal,
                ">" => ordering == Ordering::Greater,
                "<" => ordering == Ordering::Less,
                ">=" => ordering != Ordering::Less,
                "<=" => ordering != Ordering::Greater,
                _ => {
                    ordering != Ordering::Less
                        && version.release().cmp(&wanted.bump()) == Ordering::Less
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap_or_else(|| panic!("{text} is a version"))
    }

    fn id(name: &str, version: &str, platform: Option<&str>) -> GemId {
        GemId {
            name: name.to_string(),
            version: version.to_string(),
            platform: platform.map(str::to_string),
        }
    }

    #[test]
    fn versions_order_as_rubygems_orders_them() {
        for (lower, higher) in [
            ("1.0", "1.0.1"),
            ("1.9", "1.10"),
            ("2.8.2", "2.8.9"),
            ("1.0.0.pre", "1.0.0"),
            ("1.0.a", "1.0.b"),
            ("1.0.rc1", "1.0.rc2"),
            ("1.0.0.rc1", "1.0.1"),
            ("3.4.0.dev", "3.4.0"),
        ] {
            assert_eq!(v(lower).cmp(&v(higher)), Ordering::Less, "{lower} {higher}");
            assert_eq!(
                v(higher).cmp(&v(lower)),
                Ordering::Greater,
                "{higher} {lower}"
            );
        }
        for (a, b) in [("1.0", "1"), ("1.0.0", "1.0"), ("1.0.b1", "1.b1")] {
            assert_eq!(v(a).cmp(&v(b)), Ordering::Equal, "{a} {b}");
        }
        for bad in ["", "abc", "1.0 beta", "v1.0", "1..x!"] {
            assert!(Version::parse(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn requirements_match_as_rubygems_matches_them() {
        let allows =
            |req: &str, version: &str| Requirement::parse(req).unwrap().allows(&v(version));
        // The pessimistic operator: `~> 2.8.2` is `>= 2.8.2, < 2.9`.
        assert!(allows("~> 2.8.2", "2.8.2"));
        assert!(allows("~> 2.8.2", "2.8.9"));
        assert!(!allows("~> 2.8.2", "2.9.0"));
        assert!(!allows("~> 2.8.2", "2.8.1"));
        assert!(allows("~> 1.4", "1.8.1"));
        assert!(!allows("~> 1.4", "2.0"));
        assert!(allows("~> 2", "2.9"));
        assert!(!allows("~> 2", "3.0"));
        assert!(allows(">= 0", "0.0.1"));
        assert!(allows(">= 1.0,< 3", "2.5"));
        assert!(allows(">= 1.0, < 3", "2.5"));
        assert!(!allows(">= 1.0,< 3", "3.0"));
        assert!(allows("= 1.2", "1.2.0"));
        assert!(allows("1.2", "1.2"));
        assert!(allows("!= 1.2", "1.3"));
        assert!(!allows("> 1.2", "1.2"));
        assert!(allows("<= 1.2", "1.2"));
        // A prerelease of the next minor is outside `~>`.
        assert!(!allows("~> 2.8.2", "2.9.0.rc1"));
        for bad in ["", "=> 1", "~> x", "about 2"] {
            assert!(Requirement::parse(bad).is_none(), "{bad:?}");
        }
    }

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SHA_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    /// The newest ruby-platform release that meets the requirement and runs
    /// on the building Ruby is picked: no platform gem, no prerelease the
    /// requirement did not ask for, no release needing a newer Ruby.
    #[test]
    fn pick_release_takes_the_newest_release_that_fits() {
        let info = format!(
            "---\n2.8.2 |checksum:{SHA_A},ruby:>= 2.3.0\n\
             2.8.9 |checksum:{SHA_B},ruby:>= 2.3.0\n\
             2.8.10 |checksum:{SHA_C},ruby:>= 9.9\n\
             2.8.11.rc1 |checksum:{SHA_C}\n\
             2.8.12-java |checksum:{SHA_C}\n\
             2.9.0 |checksum:{SHA_C}\n\
             2.8.8 |ruby:>= 2.3.0\n"
        );
        let ruby = RubyVersions {
            ruby: Some("3.4.10".to_string()),
            rubygems: Some("3.6.9".to_string()),
        };
        assert_eq!(
            pick_release(&info, "~> 2.8.2", &ruby),
            Some(("2.8.9".to_string(), SHA_B.to_string()))
        );
        // An unknown Ruby holds no constraint against a release.
        assert_eq!(
            pick_release(&info, "~> 2.8.2", &RubyVersions::default()),
            Some(("2.8.10".to_string(), SHA_C.to_string()))
        );
        assert_eq!(
            pick_release(&info, "~> 2.8.11.rc1", &ruby),
            Some(("2.8.11.rc1".to_string(), SHA_C.to_string()))
        );
        assert_eq!(pick_release(&info, "~> 3.0", &ruby), None);
        // Several constraints on one line are joined by `&`.
        let ranged = format!("1.0.0 |checksum:{SHA_A},ruby:>= 2.0&< 3.0\n");
        assert_eq!(pick_release(&ranged, ">= 0", &ruby), None);
    }

    const LOCK: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    \
        nokogiri (1.18.3-arm64-darwin)\n      racc (~> 1.4)\n    \
        nokogiri (1.18.3-x86_64-linux-gnu)\n      racc (~> 1.4)\n    racc (1.8.1)\n\n\
        GEM\n  remote: https://gems.example.test/private/\n  specs:\n    inhouse (2.0.0)\n\n\
        PLATFORMS\n  arm64-darwin\n\nDEPENDENCIES\n  nokogiri (= 1.18.3)\n\n\
        CHECKSUMS\n  \
        nokogiri (1.18.3-arm64-darwin) sha256=ce088965cd424b8e752d82087dcf017069d55791f157098ed1f671d966857610\n  \
        racc (1.8.1) sha256=4a7f6929691dbec8b5209a0b373bc2614882b55fc5d2e447a21aaa691303d62f\n\n\
        BUNDLED WITH\n  4.0.15\n";

    /// A gem locked only as platform gems still names the source of its
    /// ruby-platform archive; a `CHECKSUMS` line pins only the release it
    /// names.
    #[test]
    fn locked_reads_the_gems_remote_and_its_own_checksum() {
        let source = locked(LOCK, &id("nokogiri", "1.18.3", None));
        assert_eq!(source.bases, ["https://rubygems.org"]);
        assert_eq!(source.sha256, None, "only the platform gem is pinned");
        let platform = locked(LOCK, &id("nokogiri", "1.18.3", Some("arm64-darwin")));
        assert_eq!(
            platform.sha256.as_deref(),
            Some("ce088965cd424b8e752d82087dcf017069d55791f157098ed1f671d966857610")
        );
        let racc = locked(&LOCK.replace('\n', "\r\n"), &id("racc", "1.8.1", None));
        assert_eq!(racc.bases, ["https://rubygems.org"]);
        assert!(racc.sha256.is_some());
        assert_eq!(
            locked(LOCK, &id("inhouse", "2.0.0", None)).bases,
            ["https://gems.example.test/private"]
        );
        // Another version of the gem, or a gem the lock does not list.
        assert_eq!(
            locked(LOCK, &id("nokogiri", "1.18.4", None)),
            Locked::default()
        );
        assert_eq!(locked(LOCK, &id("other", "1.0", None)), Locked::default());
    }

    #[test]
    fn gem_ids_name_their_archive() {
        assert_eq!(
            id("nokogiri", "1.18.3", None).full_name(),
            "nokogiri-1.18.3"
        );
        assert_eq!(
            id("nokogiri", "1.18.3", Some("java")).full_name(),
            "nokogiri-1.18.3-java"
        );
        assert!(!id("../x", "1.0", None).is_plain());
        assert!(!id("x", "1.0/..", None).is_plain());
    }

    /// The home's cached archive is used as it is, with no request made,
    /// unless the lock pins another sha256 for the gem; an offline run has
    /// nothing else to offer.
    #[tokio::test]
    async fn the_cached_archive_needs_no_network() {
        let tmp = tempfile::tempdir().unwrap();
        let (home, project) = (tmp.path().join("home"), tmp.path().join("proj"));
        std::fs::create_dir_all(home.join("cache")).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        let racc = id("racc", "1.8.1", None);
        std::fs::write(cache_path(&home, &racc), b"archive").unwrap();

        let source = GemSource::of(&project, true).await;
        assert_eq!(source.archive(&home, &racc).await.unwrap(), b"archive");
        assert!(source.may_have(&home, &racc).await);
        let missing = id("nokogiri", "1.18.3", None);
        assert!(!source.may_have(&home, &missing).await);
        let why = source.archive(&home, &missing).await.unwrap_err();
        assert!(why.contains("this run is offline"), "{why}");

        // The lock pins racc 1.8.1 to another sha256: not that archive.
        std::fs::write(project.join("Gemfile.lock"), LOCK).unwrap();
        let pinned = GemSource::of(&project, true).await;
        assert!(pinned.cached(&home, &racc).await.is_none());
        assert_eq!(pinned.bases(&racc), [rubygems_base()]);
    }
}
