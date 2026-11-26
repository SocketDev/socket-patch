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
//!    archive of every gem they install from source. No network is
//!    involved.
//! 2. Else downloaded from the default registry: rubygems.org, or the
//!    registry `SOCKET_RUBYGEMS_URL` names (a mirror). The URL is built
//!    from the gem's name and version, and the bytes are used only when
//!    their sha256 is the one that registry's compact index
//!    (`info/<name>`) records. `--offline` skips this step.
//!
//! The index vouches for the archive only when nobody on the network path
//! can rewrite both, and the archive's build scripts are about to run: the
//! registry is asked over `https`, or over plain `http` on this machine (a
//! local mirror, the hermetic tests), and over nothing else. A
//! `SOCKET_RUBYGEMS_URL` that is neither is refused before any request, and
//! so is a redirect that would leave `https`
//! ([`SecureRegistryClient`]); the gem then has no archive but a cached one.
//!
//! Wherever it comes from, the archive is only a candidate: before
//! anything of it is built, `gem_ext` proves it is the installed copy's
//! own source, file by file (`prove_own_source` there). That, not this
//! module, is what keeps another gem of the same name from being built.
//!
//! # What the lock is read for
//!
//! Nothing a lock entry holds drives a download: not its `remote:`, not
//! its `CHECKSUMS` (see `lock_pinned_locations_never_drive_a_download` in
//! `vendor::lock_inventory`). A lock entry may be Socket-hosted, where the
//! remote serves patched bytes and the checksum pins them, and a lock is a
//! file of the repository being scanned, which must not choose where code
//! that is about to be built comes from. The lock is read for one thing:
//! to *withhold* the download. A gem name the lock resolves from another
//! source at any version (a private gem server, a mirror, a git or path
//! source, Socket's patch registry) is not the registry's gem of that
//! name, so nothing is fetched for it ([`GemSource::withheld`]); its
//! cached archive is the only way to its source. The lock read is the one
//! at the project root, which is not always the lock that governs the gem
//! home (a monorepo member, `BUNDLE_GEMFILE`, a global home): withholding
//! is a courtesy to the registry and to the user's time, never the proof.
//!
//! A gem the build needs and the install lacks (a precompiled nokogiri has
//! no `mini_portile2`) is resolved from the registry's compact index the
//! same way: the newest ruby-platform release that meets the requirement
//! and runs on the building Ruby, verified against the index's checksum.
//! Its name comes from the proven source gem's own metadata.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

use crate::formats::gem::{self, BUNDLER_LOCKS};
use crate::patch::redirect::upstream::{
    compact_index_checksum, is_rubygems_remote, rubygems_base, rubygems_secure_base,
};
use crate::utils::digest::{sha256_hex, sha256_hex_of};
use crate::vendor::registry_fetch::SecureRegistryClient;

/// One gem release: `<name>-<version>[-<platform>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GemId {
    pub name: String,
    pub version: String,
    /// `None` for the `ruby` platform (the source gem).
    pub platform: Option<String>,
}

impl GemId {
    /// The release as a compact index names it: `<version>` or
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

/// Whether `source`, a lock's source as [`resolved_elsewhere`] names it,
/// is a gem server that could be a mirror of the registry and could be
/// named in `SOCKET_RUBYGEMS_URL`: reached over https (a download is taken
/// over nothing else), and not Socket's patch registry.
fn may_be_a_mirror(source: &str) -> bool {
    source.starts_with("https://") && !source.contains("/patch-registry/")
}

/// The gems a Bundler lock resolves from somewhere that is not the default
/// registry, each with that source as the lock names it (credentials
/// redacted): whatever version it pins, the registry's gem of that name is
/// not the project's. A `GEM` section counts as the registry only when
/// every one of its remotes is (a section with several remotes does not
/// say which serves a gem); a `GIT`, `PATH` or plugin section never does.
pub(crate) fn resolved_elsewhere(lock: &str) -> HashMap<String, String> {
    let text = crate::utils::line_endings::to_lf(lock);
    let parsed = gem::parse(&text);
    let mut out: HashMap<String, String> = HashMap::new();
    for section in &parsed.sections {
        let source = if section.header == "GEM" {
            match section
                .remote_bases()
                .find(|remote| !is_rubygems_remote(remote))
            {
                Some(remote) => crate::utils::redact::redact_urls_in(remote).into_owned(),
                None => continue,
            }
        } else {
            format!("a {} source", section.header.to_ascii_lowercase())
        };
        for spec in section.specs.iter().filter_map(|line| line.parsed) {
            out.entry(spec.name.to_string())
                .or_insert_with(|| source.clone());
        }
    }
    out
}

/// Where gem archives come from in one run: the gem homes' caches and the
/// default registry, with the project's lock (read and parsed once) to say
/// which gems are not the registry's.
pub(crate) struct GemSource {
    /// [`resolved_elsewhere`] of the project's lock.
    elsewhere: HashMap<String, String>,
    offline: bool,
    /// The default registry's base URL, or why nothing is downloaded from
    /// it: it is reached over plain http ([`rubygems_secure_base`]).
    registry: Result<String, String>,
    /// Built by the first download: a dry run, an offline run and a run
    /// that finds its archive cached never make one.
    http: OnceLock<SecureRegistryClient>,
}

impl GemSource {
    /// The source for the project at `project` (its `Gemfile.lock` or
    /// `gems.locked`, when it has one).
    pub(crate) async fn of(project: &Path, offline: bool) -> GemSource {
        let mut elsewhere = HashMap::new();
        for file in BUNDLER_LOCKS {
            // Guarded: a FIFO squatting the lock path must not block.
            if let Ok(text) = crate::utils::fs::read_regular_to_string(&project.join(file)).await {
                elsewhere = resolved_elsewhere(&text);
                break;
            }
        }
        GemSource {
            elsewhere,
            offline,
            registry: rubygems_secure_base(),
            http: OnceLock::new(),
        }
    }

    pub(crate) fn offline(&self) -> bool {
        self.offline
    }

    /// The registry as a message names it: its base URL with any
    /// credentials redacted (`SOCKET_RUBYGEMS_URL` may carry a mirror's
    /// `user:token@`, and these messages reach `--json` output and CI
    /// logs). Every message of this module that names the registry, or a
    /// URL under it, goes through [`shown`].
    fn registry_name(&self) -> String {
        match &self.registry {
            Ok(base) => shown(base),
            Err(_) => shown(&rubygems_base()),
        }
    }

    /// Why nothing is downloaded for the gem `name`: the lock resolves it
    /// from another source, the run is offline, or the registry is reached
    /// over plain http. `None` when the registry may be asked.
    fn withheld(&self, name: &str) -> Option<String> {
        if let Some(source) = self.elsewhere.get(name) {
            return Some(format!(
                "the project's lock resolves {name} from {source}, not from {}, so it is not \
                 downloaded",
                self.registry_name()
            ));
        }
        if self.offline {
            return Some("this run is offline".to_string());
        }
        self.registry.as_ref().err().cloned()
    }

    /// Whether the archive of `id` is in the gem home `home`'s `cache/`
    /// (its bytes are not read).
    async fn has_cached(&self, home: &Path, id: &GemId) -> bool {
        id.is_plain()
            && tokio::fs::symlink_metadata(cache_path(home, id))
                .await
                .is_ok_and(|meta| {
                    meta.is_file()
                        && meta.len() <= crate::vendor::registry_fetch::MAX_DOWNLOAD_BYTES
                })
    }

    /// The archive of `id` in the gem home `home`'s `cache/`, when it is
    /// there.
    pub(crate) async fn cached(&self, home: &Path, id: &GemId) -> Option<Vec<u8>> {
        if !self.has_cached(home, id).await {
            return None;
        }
        crate::utils::fs::read_regular_to_bytes(&cache_path(home, id))
            .await
            .ok()
    }

    /// Why [`Self::archive`] cannot produce `id` for `home`, as far as
    /// files alone tell: its cached archive is not there, and nothing may
    /// be downloaded for it. `None` when it is cached, or the registry may
    /// be asked. Read-only, for a refusal a dry run makes too.
    pub(crate) async fn out_of_reach(&self, home: &Path, id: &GemId) -> Option<String> {
        if self.has_cached(home, id).await {
            return None;
        }
        let withheld = self.withheld(&id.name)?;
        Some(format!(
            "{} is not there and {withheld}",
            cache_path(home, id).display()
        ))
    }

    /// What gets `id` within reach of [`Self::archive`] for `home`: the
    /// sentence a refusal ends with.
    pub(crate) fn remedy(&self, home: &Path, id: &GemId) -> String {
        let (file, cache) = (
            format!("{}.gem", id.full_name()),
            home.join("cache").display().to_string(),
        );
        if let Some(source) = self.elsewhere.get(&id.name) {
            // A gem server the lock names may be a mirror of the registry
            // (Artifactory, a pull-through cache): it serves this archive,
            // and only the user can say it is one. Said only where naming
            // it can work: a download is allowed in this run, and the
            // server is one a download is taken from (https, and not
            // Socket's patch registry, which serves patched gems only).
            let mirror = if !self.offline && may_be_a_mirror(source) {
                ", or, if that server is a mirror of rubygems.org, set SOCKET_RUBYGEMS_URL to \
                 its URL and apply again"
            } else {
                ""
            };
            return format!("Put {file} in {cache}{mirror}.");
        }
        match &self.registry {
            Ok(_) => format!(
                "Run `socket-patch apply` once with network access to {}, or put {file} in \
                 {cache}.",
                self.registry_name()
            ),
            Err(_) => format!(
                "With an https registry (or SOCKET_RUBYGEMS_URL unset), run `socket-patch \
                 apply` once with network access, or put {file} in {cache}."
            ),
        }
    }

    /// The archive of `id`: the home's cached copy, else a download from
    /// the default registry, verified against the sha256 its compact index
    /// records. `Err` is why there is none.
    pub(crate) async fn archive(&self, home: &Path, id: &GemId) -> Result<Vec<u8>, String> {
        if !id.is_plain() {
            return Err(format!(
                "{}.gem is not a plain gem archive name",
                id.full_name()
            ));
        }
        if let Some(bytes) = self.cached(home, id).await {
            return Ok(bytes);
        }
        let cache = cache_path(home, id);
        if let Some(withheld) = self.withheld(&id.name) {
            return Err(format!("{} is not there and {withheld}", cache.display()));
        }
        let fetched = async {
            let base = self.registry.as_ref().map_err(String::clone)?;
            let info = self.index(base, &id.name).await?;
            let want = compact_index_checksum(&info, &id.token()).ok_or_else(|| {
                format!("{base} lists no {} {} with a checksum", id.name, id.token())
            })?;
            self.fetch_verified(base, id, &want).await
        };
        fetched.await.map_err(|why: String| {
            format!(
                "{} is not there and it could not be downloaded ({})",
                cache.display(),
                shown(&why)
            )
        })
    }

    /// `url`'s bytes, from the registry and over a transport nobody can
    /// rewrite ([`SecureRegistryClient`]): the one way this module makes a
    /// request.
    async fn get(&self, url: &str) -> Result<Vec<u8>, String> {
        let registry = self.http.get_or_init(SecureRegistryClient::new);
        registry.download(url).await
    }

    /// The registry's compact index document of the gem `name`.
    async fn index(&self, base: &str, name: &str) -> Result<String, String> {
        let url = format!("{base}/info/{name}");
        let bytes = self.get(&url).await?;
        String::from_utf8(bytes).map_err(|_| format!("{url} is not UTF-8"))
    }

    /// The registry's archive of `id`, only when it has the sha256 `want`
    /// (what the registry's index records for it).
    async fn fetch_verified(&self, base: &str, id: &GemId, want: &str) -> Result<Vec<u8>, String> {
        let url = format!("{base}/gems/{}.gem", id.full_name());
        let bytes = self.get(&url).await?;
        if sha256_hex_of(&bytes) == want {
            Ok(bytes)
        } else {
            Err(format!(
                "{url} does not have the sha256 the registry's index records for it"
            ))
        }
    }

    /// A ruby-platform release of the gem `name` that meets `requirement`
    /// (`~> 2.8.2`, `>= 1.0,< 3`) and runs on `ruby`, from the default
    /// registry: its id and its archive, verified against the sha256 the
    /// registry's compact index records.
    pub(crate) async fn dependency(
        &self,
        name: &str,
        requirement: &str,
        ruby: &RubyVersions,
    ) -> Result<(GemId, Vec<u8>), String> {
        if !gem::is_plain_gem_token(name) {
            return Err(format!("{name:?} is not a plain gem name"));
        }
        if let Some(withheld) = self.withheld(name) {
            return Err(withheld);
        }
        let fetched = async {
            let base = self.registry.as_ref().map_err(String::clone)?;
            let info = self.index(base, name).await?;
            let (version, sha) = pick_release(&info, requirement, ruby).ok_or_else(|| {
                format!("{base} lists no release of {name} that meets {requirement}")
            })?;
            let id = GemId {
                name: name.to_string(),
                version,
                platform: None,
            };
            if !id.is_plain() {
                return Err(format!("{} is not a plain gem name", id.full_name()));
            }
            let bytes = self.fetch_verified(base, &id, &sha).await?;
            Ok((id, bytes))
        };
        fetched.await.map_err(|why: String| shown(&why))
    }
}

/// `text` as a message carries it: the credentials of every URL in it
/// redacted.
fn shown(text: &str) -> String {
    crate::utils::redact::redact_urls_in(text).into_owned()
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
        // #2285: an index built with `gem generate_index` writes the
        // digest as base64 (rack 3.2.9's line is the one it wrote), and
        // the release is picked with the hex the download is checked by.
        let base64 = "3.2.8 |checksum:AAAA\n\
                      3.2.9 |checksum:gjXB0I8MRhvtz/RBO766iIFz5bCeEzKulRyY8O5GDcw=,ruby:>= 2.4.0\n";
        assert_eq!(
            pick_release(base64, "~> 3.2", &ruby),
            Some((
                "3.2.9".to_string(),
                "8235c1d08f0c461bedcff4413bbeba888173e5b09e1332ae951c98f0ee460dcc".to_string()
            ))
        );
        // Several constraints on one line are joined by `&`.
        let ranged = format!("1.0.0 |checksum:{SHA_A},ruby:>= 2.0&< 3.0\n");
        assert_eq!(pick_release(&ranged, ">= 0", &ruby), None);
    }

    const LOCK: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    \
        nokogiri (1.18.3-arm64-darwin)\n      racc (~> 1.4)\n    \
        nokogiri (1.18.3-x86_64-linux-gnu)\n      racc (~> 1.4)\n    racc (1.8.1)\n\n\
        GEM\n  remote: https://user:secret@gems.example.test/private/\n  specs:\n    \
        inhouse (2.0.0)\n    sqlite3 (2.6.0-arm64-darwin)\n\n\
        GEM\n  remote: https://rubygems.org/\n  remote: https://patch.example.test/gem/\n  \
        specs:\n    merged (1.0.0)\n\n\
        GIT\n  remote: https://github.com/example/forked.git\n  revision: abc\n  specs:\n    \
        forked (0.1.0)\n\n\
        PLATFORMS\n  arm64-darwin\n\nDEPENDENCIES\n  nokogiri (= 1.18.3)\n\n\
        CHECKSUMS\n  \
        nokogiri (1.18.3-arm64-darwin) sha256=ce088965cd424b8e752d82087dcf017069d55791f157098ed1f671d966857610\n  \
        racc (1.8.1) sha256=4a7f6929691dbec8b5209a0b373bc2614882b55fc5d2e447a21aaa691303d62f\n\n\
        BUNDLED WITH\n  4.0.15\n";

    /// A lock names a gem server without the credentials
    /// `SOCKET_RUBYGEMS_URL` names it with, and the hint to name a mirror
    /// is for a server a download could be taken from.
    #[test]
    fn a_server_is_the_same_with_or_without_credentials() {
        for (with, without) in [
            (
                "https://user:tok@gems.example.test/api/gems/",
                "https://gems.example.test/api/gems/",
            ),
            ("https://tok@gems.example.test", "https://gems.example.test"),
            (
                "https://gems.example.test/a@b",
                "https://gems.example.test/a@b",
            ),
            ("not a url", "not a url"),
        ] {
            assert_eq!(crate::utils::redact::strip_url_userinfo(with), without);
        }
        assert!(may_be_a_mirror("https://gems.example.test/api/gems"));
        assert!(may_be_a_mirror(
            "https://<redacted>@gems.example.test/private"
        ));
        for source in [
            "http://gems.example.test",
            "a git source",
            "a path source",
            "https://patch.socket.dev/patch-registry/gem/token/uuid",
        ] {
            assert!(!may_be_a_mirror(source), "{source}");
        }
    }

    /// A gem locked only as platform gems is still the registry's gem, so
    /// its ruby-platform archive may be fetched there. A gem any section
    /// resolves from another source is not, whatever version is asked for:
    /// a private server, a section whose remotes are not all the registry
    /// (a merged Socket remote), a git source. Credentials in a remote are
    /// not repeated.
    #[test]
    fn the_lock_names_the_gems_that_are_not_the_registrys() {
        for lock in [LOCK.to_string(), LOCK.replace('\n', "\r\n")] {
            let elsewhere = resolved_elsewhere(&lock);
            let mut names: Vec<&str> = elsewhere.keys().map(String::as_str).collect();
            names.sort();
            assert_eq!(names, ["forked", "inhouse", "merged", "sqlite3"]);
            assert!(elsewhere["inhouse"].contains("gems.example.test"));
            assert!(!elsewhere["inhouse"].contains("secret"), "{elsewhere:?}");
            assert!(elsewhere["merged"].contains("patch.example.test"));
            assert_eq!(elsewhere["forked"], "a git source");
        }
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

    /// The home's cached archive is used as it is, with no request made.
    /// Without it, an offline run has nothing to offer, and neither has any
    /// run for a gem the lock resolves from another source: the registry's
    /// gem of that name is never fetched in its place.
    #[tokio::test]
    async fn the_cached_archive_needs_no_network() {
        let tmp = tempfile::tempdir().unwrap();
        let (home, project) = (tmp.path().join("home"), tmp.path().join("proj"));
        std::fs::create_dir_all(home.join("cache")).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        let racc = id("racc", "1.8.1", None);
        std::fs::write(cache_path(&home, &racc), b"archive").unwrap();

        let offline = GemSource::of(&project, true).await;
        assert_eq!(offline.archive(&home, &racc).await.unwrap(), b"archive");
        assert_eq!(offline.out_of_reach(&home, &racc).await, None);
        let missing = id("nokogiri", "1.18.3", None);
        let why = offline.out_of_reach(&home, &missing).await.unwrap();
        assert!(why.contains("this run is offline"), "{why}");
        let why = offline.archive(&home, &missing).await.unwrap_err();
        assert!(why.contains("this run is offline"), "{why}");
        let remedy = offline.remedy(&home, &missing);
        assert!(
            remedy.contains("with network access") && remedy.contains("nokogiri-1.18.3.gem"),
            "{remedy}"
        );

        // Online: the registry may be asked for its own gems only. The
        // lock is the cached archive's too: whatever `CHECKSUMS` says of
        // racc, the archive in the home is the one that is used.
        std::fs::write(project.join("Gemfile.lock"), LOCK).unwrap();
        let online = GemSource::of(&project, false).await;
        assert_eq!(online.archive(&home, &racc).await.unwrap(), b"archive");
        assert_eq!(online.out_of_reach(&home, &missing).await, None);
        // The lock pins inhouse 2.0.0; another version of that name is no
        // more the registry's gem than the pinned one.
        let private = id("inhouse", "9.9.9", None);
        for why in [
            online.out_of_reach(&home, &private).await.unwrap(),
            online.archive(&home, &private).await.unwrap_err(),
            online
                .dependency("inhouse", ">= 0", &RubyVersions::default())
                .await
                .unwrap_err(),
        ] {
            assert!(
                why.contains("gems.example.test") && why.contains("is not downloaded"),
                "{why}"
            );
            assert!(!why.contains("secret"), "{why}");
        }
        let remedy = online.remedy(&home, &private);
        assert!(!remedy.contains("network access"), "{remedy}");
        assert!(remedy.contains("inhouse-9.9.9.gem"), "{remedy}");
        // The lock names a gem server, which may be a mirror: the remedy
        // says how to name it.
        assert!(remedy.contains("SOCKET_RUBYGEMS_URL"), "{remedy}");
        assert!(!remedy.contains("secret"), "{remedy}");
        // In the home's cache, even a private gem's archive is its source.
        std::fs::write(cache_path(&home, &private), b"private").unwrap();
        assert_eq!(online.archive(&home, &private).await.unwrap(), b"private");
    }

    /// A source with nothing in its lock, online, asking `registry`.
    fn asking(registry: Result<String, String>) -> GemSource {
        GemSource {
            elsewhere: HashMap::new(),
            offline: false,
            registry,
            http: OnceLock::new(),
        }
    }

    /// A registry reached over plain http is never asked: whoever sits on
    /// the path would choose the archive and the checksum it is verified
    /// against, and the archive's build scripts run. The gem is as far out
    /// of reach as offline, the reason says to use https, and the home's
    /// cached archive is still its source.
    #[tokio::test]
    async fn a_registry_over_plain_http_is_never_asked() {
        use crate::patch::redirect::upstream::secure_gem_registry;
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir_all(home.join("cache")).unwrap();
        let racc = id("racc", "1.8.1", None);
        let nokogiri = id("nokogiri", "1.18.3", None);
        std::fs::write(cache_path(&home, &racc), b"archive").unwrap();

        // Nothing answers at this name: a request would fail on the lookup,
        // with another message.
        let base = "http://user:hunter2@gems.example.test/mirror".to_string();
        let gems = asking(secure_gem_registry(base));
        for why in [
            gems.out_of_reach(&home, &nokogiri).await.unwrap(),
            gems.archive(&home, &nokogiri).await.unwrap_err(),
            gems.dependency("mini_portile2", "~> 2.8.2", &RubyVersions::default())
                .await
                .unwrap_err(),
        ] {
            assert!(
                why.contains("SOCKET_RUBYGEMS_URL")
                    && why.contains("gems.example.test")
                    && why.contains("is not an https URL")
                    && why.contains("set it to an https URL"),
                "{why}"
            );
            assert!(!why.contains("hunter2"), "{why}");
        }
        let remedy = gems.remedy(&home, &nokogiri);
        assert!(
            remedy.contains("With an https registry") && remedy.contains("nokogiri-1.18.3.gem"),
            "{remedy}"
        );
        assert!(gems.http.get().is_none(), "no client was built");
        assert_eq!(gems.archive(&home, &racc).await.unwrap(), b"archive");
        assert_eq!(gems.out_of_reach(&home, &racc).await, None);
    }

    /// A registry on this machine (a local mirror, the hermetic tests) is
    /// asked over plain http: the archive is the one its index records.
    /// A redirect from it to a plain-http host elsewhere is not followed,
    /// for the index or for the archive. (The host "elsewhere" is
    /// `0.0.0.0`: no loopback address to the rule, and nothing sent to it
    /// leaves this machine, so the test is off the network even if the
    /// rule broke.)
    #[tokio::test]
    async fn a_loopback_registry_is_asked_and_no_redirect_leaves_it() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let serve = |from: &'static str, response: ResponseTemplate| {
            Mock::given(method("GET"))
                .and(path(from))
                .respond_with(response)
                .mount(&server)
        };
        let away = |to: &str| {
            ResponseTemplate::new(302)
                .insert_header("location", format!("http://0.0.0.0:9{to}").as_str())
        };
        let archive = b"the source gem".to_vec();
        let listed = |sha: &str| {
            ResponseTemplate::new(200).set_body_string(format!("---\n1.0.0 |checksum:{sha}\n"))
        };
        serve("/info/good", listed(&sha256_hex_of(&archive))).await;
        serve(
            "/gems/good-1.0.0.gem",
            ResponseTemplate::new(200).set_body_bytes(archive.clone()),
        )
        .await;
        // Its archive is not the one the index records.
        serve("/info/swapped", listed(SHA_A)).await;
        serve(
            "/gems/swapped-1.0.0.gem",
            ResponseTemplate::new(200).set_body_bytes(archive.clone()),
        )
        .await;
        // Its archive, and the other's index, are redirected elsewhere.
        serve("/info/moved", listed(&sha256_hex_of(&archive))).await;
        serve("/gems/moved-1.0.0.gem", away("/gems/moved-1.0.0.gem")).await;
        serve("/info/gone", away("/info/gone")).await;

        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let gems = asking(Ok(server.uri()));
        let of = |name: &str| id(name, "1.0.0", None);
        assert_eq!(gems.archive(&home, &of("good")).await.unwrap(), archive);
        let (picked, bytes) = gems
            .dependency("good", ">= 0", &RubyVersions::default())
            .await
            .unwrap();
        assert_eq!((picked, bytes), (of("good"), archive));

        let why = gems.archive(&home, &of("swapped")).await.unwrap_err();
        assert!(why.contains("does not have the sha256"), "{why}");
        for name in ["moved", "gone"] {
            let why = gems.archive(&home, &of(name)).await.unwrap_err();
            assert!(
                why.contains("refusing a redirect") && why.contains("0.0.0.0"),
                "{name}: {why}"
            );
            let why = gems
                .dependency(name, ">= 0", &RubyVersions::default())
                .await
                .unwrap_err();
            assert!(why.contains("refusing a redirect"), "{name}: {why}");
        }
    }

    /// `SOCKET_RUBYGEMS_URL` may carry a mirror's credentials. No message
    /// of this module repeats them: not the remedy, not a registry that
    /// lists no such gem, not an archive or an index that is not what it
    /// should be, not a gem the lock resolves elsewhere.
    #[tokio::test]
    async fn no_message_repeats_the_registrys_credentials() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let serve = |from: &'static str, response: ResponseTemplate| {
            Mock::given(method("GET"))
                .and(path(from))
                .respond_with(response)
                .mount(&server)
        };
        let listed =
            ResponseTemplate::new(200).set_body_string(format!("---\n1.0.0 |checksum:{SHA_A}\n"));
        serve("/mirror/info/listed", listed).await;
        serve(
            "/mirror/gems/listed-1.0.0.gem",
            ResponseTemplate::new(200).set_body_bytes(b"another archive".to_vec()),
        )
        .await;
        serve(
            "/mirror/info/garbled",
            ResponseTemplate::new(200).set_body_bytes(vec![0xff, 0xfe]),
        )
        .await;

        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let base = format!(
            "{}/mirror",
            server.uri().replace("http://", "http://deploy:hunter2@")
        );
        let mut gems = asking(Ok(base));
        gems.elsewhere
            .insert("inhouse".to_string(), "a git source".to_string());
        let of = |name: &str, version: &str| id(name, version, None);
        let any = RubyVersions::default();
        let said = [
            // The remedy of a refusal, and a gem the lock resolves elsewhere.
            gems.remedy(&home, &of("listed", "1.0.0")),
            gems.out_of_reach(&home, &of("inhouse", "1.0.0"))
                .await
                .unwrap(),
            // The registry lists no such release.
            gems.archive(&home, &of("listed", "2.0.0"))
                .await
                .unwrap_err(),
            gems.dependency("listed", "~> 9.0", &any).await.unwrap_err(),
            // Its archive is not the one its index records.
            gems.archive(&home, &of("listed", "1.0.0"))
                .await
                .unwrap_err(),
            gems.dependency("listed", ">= 0", &any).await.unwrap_err(),
            // Its index is not text; it has none (HTTP 404).
            gems.archive(&home, &of("garbled", "1.0.0"))
                .await
                .unwrap_err(),
            gems.dependency("absent", ">= 0", &any).await.unwrap_err(),
        ];
        for (text, expected) in said.iter().zip([
            "with network access to http://",
            "not from http://",
            "lists no listed 2.0.0 with a checksum",
            "lists no release of listed that meets ~> 9.0",
            "does not have the sha256",
            "does not have the sha256",
            "is not UTF-8",
            "HTTP 404",
        ]) {
            assert!(text.contains(expected), "no {expected:?} in {text}");
            assert!(
                text.contains("/mirror"),
                "the registry is still named: {text}"
            );
            for secret in ["hunter2", "deploy:"] {
                assert!(!text.contains(secret), "{secret} in {text}");
            }
        }
    }
}
