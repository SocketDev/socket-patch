//! sbt's own resolution records, parsed into a [`JvmResolution`].
//!
//! What sbt leaves under `target/` after `update` / `compile` /
//! `Test/compile` (fixtures: `tests/fixtures/sbt/evidence/<ver>/`; every
//! shape below is verified by probe on 0.13.18, 1.2.8, 1.3.13, 1.9.9,
//! 1.13.0 and 2.0.9, `docs/design/sbt-evidence-probe.md`):
//!
//! | Path | Kind |
//! |---|---|
//! | `target/out/*/{scala-*,u}/<id>/update/update_cache[_*]/output` (sbt 2) | [`EvidenceKind::UpdateCacheJson`]; meta-build iff `<id>` is the root's `-build` id |
//! | `[<P>/]target/scala-*/[sbt-*/]update/update_cache_*/output` (1.3+) | `UpdateCacheJson` |
//! | `[<P>/]target/update/update_cache/output` (1.3+, `crossPaths := false`) | `UpdateCacheJson` |
//! | `[<P>/]target/streams/$global/update/$global/streams/update_cache*/output` (0.13–1.2) | `UpdateCacheJson` (0.13: binary, [`EvidenceError::NotJson`]) |
//! | `[<P>/]target/[scala-*/[sbt-*/]]resolution-cache/reports/*.xml` (0.13–1.2, `useCoursier := false`) | [`EvidenceKind::IvyReportXml`] |
//!
//! Paths under `project/` are the meta-build: their GAs feed only
//! [`JvmResolution::meta_build`]. Every configuration feeds
//! [`JvmResolution::modules`] and [`JvmResolution::artifacts`]; only
//! [`CONFIGS`] feed [`JvmResolution::in_scope`] and
//! [`JvmResolution::classifiers`]. Evicted modules feed nothing: they are
//! on no classpath, and Coursier (sbt 1.3+) never records them, so
//! counting them would make an Ivy-era build refuse what a Coursier one
//! accepts.
//!
//! [`ResolutionDoc`] is the distilled form the hosted engine hands the pure
//! sbt rewriter (`hosted::sbt_reads`): one JSON document under the
//! synthetic candidate key.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use super::build::{BuildFindings, IMPLICIT_ROOT_ID};
use super::{Ga, JvmResolution};

/// The library configurations whose resolution a pin must cover.
pub const CONFIGS: &[&str] = &[
    "compile",
    "runtime",
    "test",
    "provided",
    "optional",
    "it",
    "compile-internal",
    "runtime-internal",
    "test-internal",
];

/// The format of one evidence file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    /// sjsonnew `UpdateReport` JSON (sbt 1.0–2.x).
    UpdateCacheJson,
    /// An Ivy resolution report (sbt 0.13–1.2, `useCoursier := false`).
    IvyReportXml,
}

/// A classified evidence path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidencePath {
    pub kind: EvidenceKind,
    /// The project it records: a root-relative base directory (`.` for the
    /// root) on sbt 0.13–1.x, the project id on sbt 2 (mapped to a
    /// directory through [`super::build::declared_projects`]).
    pub project: String,
    /// Whether `project` is an sbt 2 project id rather than a directory.
    pub project_is_id: bool,
    /// A meta-build (`project/`) record.
    pub meta: bool,
}

/// Why one evidence file was not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    /// The 0.13 binary update cache (the Ivy reports beside it are read).
    NotJson,
    Malformed(String),
}

/// sbt's project-id normalisation (`Project.normalizeModuleID`): lowercase,
/// every run of non-word characters a `-`. A build with no root project
/// gets its directory's name this way, and sbt 2 names the meta-build
/// `<it>-build` (probe: `My_Proj.1` → `my_proj-1`). Java's `\W` is ASCII:
/// a non-ASCII letter is a non-word character too.
pub fn sbt_id(name: &str) -> String {
    static NON_WORD: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"[^A-Za-z0-9_]+").expect("regex"));
    NON_WORD.replace_all(&name.to_lowercase(), "-").into_owned()
}

/// Classify a root-relative evidence path; `root_name` is the build root's
/// directory name (sbt 2 names the meta-build `<sanitized root>-build`).
/// `None` for anything that is not evidence (including the sibling
/// `inputs` files, which only date the evidence).
pub fn classify_path(rel: &str, root_name: &str) -> Option<EvidencePath> {
    let segments: Vec<&str> = rel.split('/').collect();
    if segments
        .iter()
        .any(|s| s.is_empty() || *s == "." || *s == "..")
    {
        return None;
    }
    // The first `target` segment: a project's own target directory (a
    // nested `target/…/target` is inside one, never a project of its own).
    let at = segments.iter().position(|s| *s == "target")?;
    let (prefix, tail) = (&segments[..at], &segments[at + 1..]);
    let meta = prefix.first() == Some(&"project");
    let dir = if prefix.is_empty() {
        ".".to_string()
    } else {
        prefix.join("/")
    };
    let scala = |s: &str| s.starts_with("scala-");
    let sbt = |s: &str| s.starts_with("sbt-");
    let cache = |s: &str| s.starts_with("update_cache_");
    let global = |s: &str| s == "$global" || s == "_global";
    let json = |project: String, project_is_id: bool, meta: bool| EvidencePath {
        kind: EvidenceKind::UpdateCacheJson,
        project,
        project_is_id,
        meta,
    };
    match tail {
        // sbt 2: every project under the root's `target/out`; the Scala
        // segment is `scala-<full>`, or `u` under `crossPaths := false`.
        ["out", _platform, _scala, id, "update", c, "output"]
            if *c == "update_cache" || cache(c) =>
        {
            if !prefix.is_empty() && !meta {
                return None;
            }
            let meta = meta || *id == format!("{}-build", sbt_id(root_name));
            Some(json(id.to_string(), true, meta))
        }
        [s, "update", c, "output"] if scala(s) && cache(c) => Some(json(dir, false, meta)),
        [s, p, "update", c, "output"] if scala(s) && sbt(p) && cache(c) => {
            Some(json(dir, false, meta))
        }
        ["update", "update_cache", "output"] => Some(json(dir, false, meta)),
        ["streams", g1, "update", g2, "streams", c, "output"]
            if global(g1) && global(g2) && (*c == "update_cache" || cache(c)) =>
        {
            Some(json(dir, false, meta))
        }
        [lead @ .., "resolution-cache", "reports", name]
            if name.ends_with(".xml")
                && match lead {
                    [] => true,
                    [s] => scala(s),
                    [s, p] => scala(s) && sbt(p),
                    _ => false,
                } =>
        {
            Some(EvidencePath {
                kind: EvidenceKind::IvyReportXml,
                project: dir,
                project_is_id: false,
                meta,
            })
        }
        _ => None,
    }
}

/// Fold one evidence file into `into`. The project is recorded in
/// [`JvmResolution::projects_seen`] as `path.project` (unless meta), so an
/// sbt 2 id should be mapped to its directory first ([`resolution`] does).
pub fn parse_into(
    path: &EvidencePath,
    rel: &str,
    bytes: &[u8],
    into: &mut JvmResolution,
) -> Result<(), EvidenceError> {
    let mut sink = Sink {
        rel,
        meta: path.meta,
        into,
    };
    match path.kind {
        EvidenceKind::UpdateCacheJson => parse_json(bytes, &mut sink)?,
        EvidenceKind::IvyReportXml => parse_ivy_xml(bytes, &mut sink)?,
    }
    if !path.meta {
        into.projects_seen.insert(path.project.clone());
    }
    Ok(())
}

/// Whether a classified record is the meta-build's, given the declared
/// projects (id → dir): [`EvidencePath::meta`], or an sbt 2 `-build` id no
/// declared project has (the root directory was renamed since sbt wrote
/// it). The implicit root project of a root directory itself named
/// `*-build` stays a library record.
pub fn is_meta_record(
    path: &EvidencePath,
    declared: Option<&BTreeMap<String, String>>,
    root_name: &str,
) -> bool {
    let known = declared.is_some_and(|d| {
        d.contains_key(&path.project)
            || (d.contains_key(IMPLICIT_ROOT_ID) && path.project == sbt_id(root_name))
    });
    path.meta || (path.project_is_id && path.project.ends_with("-build") && !known)
}

/// The build's resolution from its evidence files (`(rel, bytes)`), with
/// sbt 2 project ids mapped to directories through `declared` (id → dir;
/// an unknown id is kept as `id:<id>`, which matches no directory).
/// `None` when no file is evidence, and fail-closed `None` when an evidence
/// file is malformed (a truncated write, an unknown schema): a project
/// whose record cannot be read could hide a conflicting version.
pub fn resolution(
    files: &[(String, Vec<u8>)],
    declared: Option<&BTreeMap<String, String>>,
    root_name: &str,
) -> Option<JvmResolution> {
    let mut res = JvmResolution::default();
    let mut any = false;
    let implicit_root = sbt_id(root_name);
    for (rel, bytes) in files {
        let Some(mut path) = classify_path(rel, root_name) else {
            continue;
        };
        if path.project_is_id && !path.meta {
            path.meta = is_meta_record(&path, declared, root_name);
            let id = path.project.clone();
            let id = id.as_str();
            let dir = declared.and_then(|d| {
                d.get(id).cloned().or_else(|| {
                    (id == implicit_root && d.contains_key(IMPLICIT_ROOT_ID))
                        .then(|| ".".to_string())
                })
            });
            if !path.meta {
                path.project = dir.unwrap_or_else(|| format!("id:{id}"));
                path.project_is_id = false;
            }
        }
        match parse_into(&path, rel, bytes, &mut res) {
            Ok(()) => any = true,
            Err(EvidenceError::NotJson) => {}
            Err(EvidenceError::Malformed(_)) => return None,
        }
    }
    // "Only in the meta-build": a GA a library configuration resolves is
    // the libraries' (the tool configurations, `scala-doc-tool` and the
    // like, share most of the meta-build's classpath and do not count).
    let JvmResolution {
        in_scope,
        meta_build,
        ..
    } = &mut res;
    meta_build.retain(|ga| !in_scope.contains(ga));
    any.then_some(res)
}

/// Where parsed facts go: one file's evidence id prefix and meta flag.
struct Sink<'a> {
    rel: &'a str,
    meta: bool,
    into: &'a mut JvmResolution,
}

impl Sink<'_> {
    fn module(&mut self, config: &str, g: &str, a: &str, v: &str) {
        let ga: Ga = (g.to_string(), a.to_string());
        if self.meta {
            self.into.meta_build.insert(ga);
            return;
        }
        self.into
            .modules
            .entry(ga.clone())
            .or_default()
            .entry(v.to_string())
            .or_default()
            .insert(format!("{}:{config}", self.rel));
        if CONFIGS.contains(&config) {
            self.into.in_scope.insert(ga);
        }
    }

    fn artifact(&mut self, config: &str, g: &str, a: &str, v: &str, classifier: &str, loc: &str) {
        if self.meta {
            return;
        }
        if let Some(path) = location_path(loc) {
            self.into
                .artifacts
                .entry((g.to_string(), a.to_string(), v.to_string()))
                .or_default()
                .insert(path);
        }
        if !classifier.is_empty() && CONFIGS.contains(&config) {
            self.into
                .classifiers
                .entry((g.to_string(), a.to_string()))
                .or_default()
                .insert(classifier.to_string());
        }
    }
}

/// The sjsonnew `UpdateReport`: `configurations[].{configuration.name,
/// modules[].{module.{organization,name,revision}, evicted,
/// artifacts[][0].classifier, artifacts[][1]}}`, the cached file a `file:`
/// URI (sbt 2: `artifacts[][1].first`).
fn parse_json(bytes: &[u8], sink: &mut Sink<'_>) -> Result<(), EvidenceError> {
    use serde_json::Value;
    let first = bytes.iter().find(|b| !b.is_ascii_whitespace());
    if first != Some(&b'{') {
        return Err(EvidenceError::NotJson);
    }
    let rel = sink.rel;
    let malformed = |what: &str| EvidenceError::Malformed(format!("{rel}: {what}"));
    let doc: Value = serde_json::from_slice(bytes).map_err(|e| malformed(&e.to_string()))?;
    let configurations = doc
        .get("configurations")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("no `configurations` array"))?;
    let text = |v: &Value, key: &str| v.get(key).and_then(Value::as_str).map(str::to_string);
    for c in configurations {
        let config = c
            .get("configuration")
            .and_then(|n| text(n, "name"))
            .ok_or_else(|| malformed("a configuration without a name"))?;
        let modules = c
            .get("modules")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed("a configuration without `modules`"))?;
        for m in modules {
            let coords = m.get("module").and_then(|id| {
                Some((
                    text(id, "organization")?,
                    text(id, "name")?,
                    text(id, "revision")?,
                ))
            });
            let (g, a, v) = coords.ok_or_else(|| malformed("a module without coordinates"))?;
            if m.get("evicted").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            sink.module(&config, &g, &a, &v);
            for pair in m
                .get("artifacts")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let classifier = pair
                    .get(0)
                    .and_then(|art| text(art, "classifier"))
                    .unwrap_or_default();
                // sbt 2 wraps the URI: `{"first": uri, "second": 0}`.
                let loc = pair
                    .get(1)
                    .and_then(|f| f.as_str().or_else(|| f.get("first")?.as_str()))
                    .unwrap_or_default();
                sink.artifact(&config, &g, &a, &v, &classifier, loc);
            }
        }
    }
    Ok(())
}

/// An Ivy `ivy-report` (one per configuration, `<info conf>`), read by
/// regex: `<module organisation name>` / `<revision name [evicted]>` /
/// `<artifact [extra-classifier] location>`.
fn parse_ivy_xml(bytes: &[u8], sink: &mut Sink<'_>) -> Result<(), EvidenceError> {
    static TAG: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"<(/?)([A-Za-z][\w.:-]*)((?:[^>"]|"[^"]*")*?)(/?)>"#).expect("regex")
    });
    let rel = sink.rel;
    let malformed = |what: &str| EvidenceError::Malformed(format!("{rel}: {what}"));
    let text = std::str::from_utf8(bytes).map_err(|_| malformed("not UTF-8"))?;
    let mut config: Option<String> = None;
    let mut seen_report = false;
    let mut module: Option<(String, String)> = None;
    let mut revision: Option<String> = None;
    for caps in TAG.captures_iter(text) {
        let closing = !caps[1].is_empty();
        let self_closing = !caps[4].is_empty();
        let attrs = &caps[3];
        match (&caps[2], closing) {
            ("ivy-report", false) => seen_report = true,
            ("info", false) => config = attr(attrs, "conf"),
            ("module", false) => {
                module = attr(attrs, "organisation").zip(attr(attrs, "name"));
                revision = None;
            }
            ("module", true) => module = None,
            ("revision", false) => {
                let (Some((g, a)), Some(cfg)) = (&module, &config) else {
                    return Err(malformed("a revision outside a module"));
                };
                let v = attr(attrs, "name").ok_or_else(|| malformed("a revision without name"))?;
                if attr(attrs, "evicted").is_some() {
                    revision = None;
                } else {
                    sink.module(cfg, g, a, &v);
                    revision = (!self_closing).then_some(v);
                }
            }
            ("revision", true) => revision = None,
            ("artifact", false) => {
                if let (Some((g, a)), Some(v), Some(cfg)) = (&module, &revision, &config) {
                    let classifier = attr(attrs, "extra-classifier")
                        .or_else(|| attr(attrs, "m:classifier"))
                        .unwrap_or_default();
                    let loc = attr(attrs, "location").unwrap_or_default();
                    sink.artifact(cfg, g, a, v, &classifier, &loc);
                }
            }
            _ => {}
        }
    }
    if !seen_report || config.is_none() {
        return Err(malformed("not an ivy-report with an info conf"));
    }
    Ok(())
}

/// One XML attribute's decoded value.
fn attr(attrs: &str, name: &str) -> Option<String> {
    static ATTR: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"([\w.:-]+)\s*=\s*"([^"]*)""#).expect("regex"));
    ATTR.captures_iter(attrs)
        .find(|c| &c[1] == name)
        .map(|c| xml_unescape(&c[2]))
}

fn xml_unescape(raw: &str) -> String {
    if !raw.contains('&') {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let Some(end) = rest.find(';') else { break };
        let entity = &rest[1..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|d| d.parse().ok()))
                .and_then(char::from_u32),
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The local path an artifact location names: a `file:` URI (the JSON
/// report; percent-decoded, `file:///C:/…` on Windows) or a plain absolute
/// path (the Ivy report). `None` for anything else (`http:`, relative).
pub fn location_path(loc: &str) -> Option<PathBuf> {
    let raw = match loc.strip_prefix("file:") {
        Some(rest) => {
            let rest = rest.strip_prefix("//").unwrap_or(rest);
            let decoded = percent_decode(rest)?;
            // `file:///C:/x` → `C:/x`.
            let bytes = decoded.as_bytes();
            if bytes.len() >= 3
                && bytes[0] == b'/'
                && bytes[2] == b':'
                && bytes[1].is_ascii_alphabetic()
            {
                decoded[1..].to_string()
            } else {
                decoded
            }
        }
        None => loc.to_string(),
    };
    let is_abs = raw.starts_with('/')
        || (raw.len() >= 3 && raw.as_bytes()[1] == b':' && raw.as_bytes()[0].is_ascii_alphabetic());
    is_abs.then(|| PathBuf::from(raw))
}

fn percent_decode(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = raw.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The distilled evidence of one build, the JSON the hosted engine stores
/// under the synthetic candidate key for the pure sbt rewriter
/// (`hosted::sbt_reads::extra_resolution`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolutionDoc {
    /// The build root as the evidence's absolute paths spell it (the
    /// canonical root): a pin's repository is `<root>/<repo rel>` for
    /// [`super::gate::check_existing`].
    pub root: PathBuf,
    /// `None` = no evidence (or unreadable: see [`Self::read_error`]).
    pub resolution: Option<JvmResolution>,
    /// The declared project base directories, `None` when the definitions
    /// cannot be read statically.
    pub declared: Option<BTreeSet<String>>,
    /// A build source is newer than the newest evidence.
    pub stale: bool,
    /// A generated file (`socket-patch.sbt` / `socket-patch-vendor.sbt`)
    /// is newer than the newest evidence: sbt has not resolved since the
    /// last wiring, so the evidence predates the pins it holds.
    pub wiring_newer: bool,
    /// [`super::build::deps_digest`] of the build sources.
    pub deps_digest: String,
    /// Why the evidence could not be read (a cap, an unreadable file),
    /// for the run-level warning's detail.
    pub read_error: Option<String>,
    /// [`super::build::scan_build_sources`] over every build source the IO
    /// layer read (subproject `build.sbt`s and `project/*.scala`
    /// included), so the pure rewriter sees reassignments the
    /// candidate-file map does not carry. Absent on the wire = none.
    pub findings: BuildFindings,
    /// sha256 hex of the artifact files the evidence resolves at a
    /// Socket-suffixed version (a pin's), by the absolute path sbt
    /// recorded, as the IO layer hashed them (bounded; a file it could not
    /// or would not hash is absent). [`super::gate::check_existing`] accepts
    /// a pinned artifact outside the pin repository only when its bytes are
    /// the pin's ([`Self::holds_pinned_bytes`]).
    pub artifact_sha256: BTreeMap<PathBuf, String>,
    /// [`super::build::dependency_literals`] over every build source the IO
    /// layer read: an existing pin whose GA the build now declares newer
    /// than the pin's base is no longer honoured. Absent on the wire = none.
    pub declared_deps: BTreeSet<super::build::DepLiteral>,
}

/// [`ResolutionDoc`]'s wire shape: tuple-keyed maps as `[key, value]`
/// pairs (JSON objects only key by string).
#[derive(Serialize, Deserialize)]
struct WireDoc {
    v: u32,
    root: PathBuf,
    resolution: Option<WireResolution>,
    declared: Option<BTreeSet<String>>,
    stale: bool,
    #[serde(default)]
    wiring_newer: bool,
    deps_digest: String,
    #[serde(default)]
    read_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    findings: Option<WireFindings>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    artifact_sha256: Vec<(PathBuf, String)>,
    /// `[group, op, artifact, version]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    declared_deps: Vec<[String; 4]>,
}

#[derive(Serialize, Deserialize, Default)]
struct WireFindings {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    overrides_assignment: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    resolvers_assignment: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    override_build_repos: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    dependency_lock: Vec<String>,
}

type GavPaths = ((String, String, String), BTreeSet<PathBuf>);

#[derive(Serialize, Deserialize)]
struct WireResolution {
    modules: Vec<(Ga, BTreeMap<String, BTreeSet<String>>)>,
    artifacts: Vec<GavPaths>,
    classifiers: Vec<(Ga, BTreeSet<String>)>,
    in_scope: BTreeSet<Ga>,
    projects_seen: BTreeSet<String>,
    meta_build: BTreeSet<Ga>,
}

const WIRE_VERSION: u32 = 1;

impl ResolutionDoc {
    /// The document for a build from what the IO layer read: `resolution`
    /// (`None` = no evidence), `sources` every build source as
    /// `(root-relative path, text)` (anything
    /// [`super::build::source_kind`] does not classify is ignored), and the
    /// evidence's freshness. `read_error` is left unset.
    pub fn from_parts(
        root: PathBuf,
        resolution: Option<JvmResolution>,
        sources: &[(String, String)],
        stale: bool,
        wiring_newer: bool,
    ) -> Self {
        let sources: Vec<(String, String)> = sources
            .iter()
            .filter(|(rel, _)| super::build::source_kind(rel).is_some())
            .cloned()
            .collect();
        Self {
            root,
            resolution,
            declared: super::build::declared_projects(&sources)
                .map(|projects| projects.into_values().collect()),
            stale,
            wiring_newer,
            deps_digest: super::build::deps_digest(&sources),
            read_error: None,
            findings: super::build::scan_build_sources(&sources),
            artifact_sha256: BTreeMap::new(),
            declared_deps: super::build::dependency_literals(&sources),
        }
    }

    /// Whether the IO layer hashed `path` to the pin's `sha256` (hex, any
    /// case).
    pub fn holds_pinned_bytes(&self, path: &std::path::Path, sha256: &str) -> bool {
        self.artifact_sha256
            .get(path)
            .is_some_and(|h| h.eq_ignore_ascii_case(sha256))
    }

    pub fn to_json(&self) -> String {
        let resolution = self.resolution.as_ref().map(|r| WireResolution {
            modules: r.modules.clone().into_iter().collect(),
            artifacts: r.artifacts.clone().into_iter().collect(),
            classifiers: r.classifiers.clone().into_iter().collect(),
            in_scope: r.in_scope.clone(),
            projects_seen: r.projects_seen.clone(),
            meta_build: r.meta_build.clone(),
        });
        let wire = WireDoc {
            v: WIRE_VERSION,
            root: self.root.clone(),
            resolution,
            declared: self.declared.clone(),
            stale: self.stale,
            wiring_newer: self.wiring_newer,
            deps_digest: self.deps_digest.clone(),
            read_error: self.read_error.clone(),
            findings: (self.findings != BuildFindings::default()).then(|| {
                let f = &self.findings;
                WireFindings {
                    overrides_assignment: f.overrides_assignment.clone(),
                    resolvers_assignment: f.resolvers_assignment.clone(),
                    override_build_repos: f.override_build_repos.clone(),
                    dependency_lock: f.dependency_lock.clone(),
                }
            }),
            artifact_sha256: self.artifact_sha256.clone().into_iter().collect(),
            declared_deps: self
                .declared_deps
                .iter()
                .map(|l| {
                    [
                        l.group.clone(),
                        l.op.clone(),
                        l.artifact.clone(),
                        l.version.clone(),
                    ]
                })
                .collect(),
        };
        serde_json::to_string(&wire).expect("plain data serializes")
    }

    /// The document [`Self::to_json`] wrote; `None` for anything else (a
    /// newer wire version included), which the rewriter treats as no
    /// evidence.
    pub fn from_json(json: &str) -> Option<Self> {
        Self::parse(json).ok()
    }

    /// [`Self::from_json`], with the reason a text is not a document.
    pub fn parse(json: &str) -> Result<Self, String> {
        let wire: WireDoc = serde_json::from_str(json).map_err(|e| e.to_string())?;
        if wire.v != WIRE_VERSION {
            return Err(format!(
                "wire version {} (this build reads {WIRE_VERSION})",
                wire.v
            ));
        }
        let resolution = wire.resolution.map(|r| JvmResolution {
            modules: r.modules.into_iter().collect(),
            artifacts: r.artifacts.into_iter().collect(),
            classifiers: r.classifiers.into_iter().collect(),
            in_scope: r.in_scope,
            projects_seen: r.projects_seen,
            meta_build: r.meta_build,
        });
        let f = wire.findings.unwrap_or_default();
        Ok(Self {
            root: wire.root,
            resolution,
            declared: wire.declared,
            stale: wire.stale,
            wiring_newer: wire.wiring_newer,
            deps_digest: wire.deps_digest,
            read_error: wire.read_error,
            findings: BuildFindings {
                overrides_assignment: f.overrides_assignment,
                resolvers_assignment: f.resolvers_assignment,
                override_build_repos: f.override_build_repos,
                dependency_lock: f.dependency_lock,
            },
            artifact_sha256: wire.artifact_sha256.into_iter().collect(),
            declared_deps: wire
                .declared_deps
                .into_iter()
                .map(|[group, op, artifact, version]| super::build::DepLiteral {
                    group,
                    op,
                    artifact,
                    version,
                })
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    // Parser tests over the committed probe fixtures
    // (`tests/fixtures/sbt/evidence/<ver>/<scenario>/`, see its README).

    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::formats::sbt::build::declared_projects;
    use crate::formats::sbt::gate::{check_new, GateRefusal};

    const VERSIONS: &[&str] = &["0.13.18", "1.2.8", "1.3.13", "1.9.9", "1.13.0", "2.0.9"];
    const LANG3: (&str, &str) = ("org.apache.commons", "commons-lang3");
    const TEXT: (&str, &str) = ("org.apache.commons", "commons-text");
    const GSON: (&str, &str) = ("com.google.code.gson", "gson");

    fn fixture(ver: &str, scenario: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sbt/evidence")
            .join(ver)
            .join(scenario)
    }

    /// Every file under `dir` as `(rel, bytes)`, sorted.
    fn load(dir: &Path) -> Vec<(String, Vec<u8>)> {
        fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(root, &path, out);
                } else {
                    let rel = path.strip_prefix(root).unwrap().to_str().unwrap();
                    out.push((rel.replace('\\', "/"), std::fs::read(&path).unwrap()));
                }
            }
        }
        let mut out = Vec::new();
        walk(dir, dir, &mut out);
        out.sort();
        out
    }

    fn sources(files: &[(String, Vec<u8>)]) -> Vec<(String, String)> {
        files
            .iter()
            .filter(|(rel, _)| crate::formats::sbt::build::source_kind(rel).is_some())
            .map(|(rel, b)| (rel.clone(), String::from_utf8(b.clone()).unwrap()))
            .collect()
    }

    /// The resolution, declared map and declared dirs of a fixture whose probe
    /// root directory was `root_name`.
    fn resolve(
        ver: &str,
        scenario: &str,
        root_name: &str,
    ) -> (JvmResolution, BTreeMap<String, String>, BTreeSet<String>) {
        let files = load(&fixture(ver, scenario));
        let declared = declared_projects(&sources(&files)).expect("readable build");
        let res = resolution(&files, Some(&declared), root_name)
            .unwrap_or_else(|| panic!("{ver}/{scenario}: no evidence"));
        let dirs = declared.values().cloned().collect();
        (res, declared, dirs)
    }

    fn ga((g, a): (&str, &str)) -> Ga {
        (g.to_string(), a.to_string())
    }

    fn versions(res: &JvmResolution, coords: (&str, &str)) -> Vec<String> {
        res.versions(coords.0, coords.1)
            .into_iter()
            .map(str::to_string)
            .collect()
    }

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn configs_cover_the_library_scopes() {
        for c in ["compile", "runtime", "test", "provided", "optional"] {
            assert!(CONFIGS.contains(&c), "{c}");
        }
        for c in ["scala-tool", "sources", "docs", "pom", "plugin"] {
            assert!(!CONFIGS.contains(&c), "{c}");
        }
    }

    #[test]
    fn classify_every_probed_shape() {
        let json = |project: &str, is_id: bool, meta: bool| {
            Some(EvidencePath {
                kind: EvidenceKind::UpdateCacheJson,
                project: project.to_string(),
                project_is_id: is_id,
                meta,
            })
        };
        let xml = |project: &str, meta: bool| {
            Some(EvidencePath {
                kind: EvidenceKind::IvyReportXml,
                project: project.to_string(),
                project_is_id: false,
                meta,
            })
        };
        let cases: &[(&str, Option<EvidencePath>)] = &[
        // sbt 2: ids under the root's target/out; crossPaths := false
        // spells the Scala segment `u`.
        (
            "target/out/jvm/scala-3.8.4/a/update/update_cache_3/output",
            json("a", true, false),
        ),
        (
            "target/out/jvm/u/d/update/update_cache/output",
            json("d", true, false),
        ),
        (
            "target/out/jvm/scala-3.8.4/x-build/update/update_cache_3/output",
            json("x-build", true, true),
        ),
        (
            "a/target/out/jvm/scala-3.8.4/a/update/update_cache_3/output",
            None,
        ),
        // 1.3+.
        (
            "target/scala-2.12/update/update_cache_2.12/output",
            json(".", false, false),
        ),
        (
            "mods/a/target/scala-2.13/update/update_cache_2.13/output",
            json("mods/a", false, false),
        ),
        (
            "d/target/update/update_cache/output",
            json("d", false, false),
        ),
        (
            "project/target/scala-2.12/sbt-1.0/update/update_cache_2.12/output",
            json("project", false, true),
        ),
        // 0.13–1.2 streams (0.13's is binary: classified, then NotJson).
        (
            "a/target/streams/$global/update/$global/streams/update_cache_2.12/output",
            json("a", false, false),
        ),
        (
            "d/target/streams/$global/update/$global/streams/update_cache/output",
            json("d", false, false),
        ),
        // Ivy reports, crossPaths on and off, meta.
        (
            "a/target/scala-2.10/resolution-cache/reports/a-a_2.10-compile.xml",
            xml("a", false),
        ),
        (
            "d/target/resolution-cache/reports/d-d-compile.xml",
            xml("d", false),
        ),
        (
            "project/target/scala-2.10/sbt-0.13/resolution-cache/reports/default-x-build-compile.xml",
            xml("project", true),
        ),
        // Not evidence.
        (
            "a/target/scala-2.12/update/update_cache_2.12/inputs",
            None,
        ),
        (
            "a/target/streams/_global/dependencyPositions/_global/streams/update_cache_2.12/output_dsp",
            None,
        ),
        ("a/target/scala-2.12/resolution-cache/reports/ivy-report.css", None),
        ("build.sbt", None),
        ("a/../target/update/update_cache/output", None),
        ("a//target/update/update_cache/output", None),
    ];
        for (rel, want) in cases {
            assert_eq!(&classify_path(rel, "x"), want, "{rel}");
        }
    }

    #[test]
    fn sbt_id_matches_sbts_normalisation() {
        // Probe: an implicit root in `My_Proj.1` is `my_proj-1`.
        assert_eq!(sbt_id("My_Proj.1"), "my_proj-1");
        assert_eq!(sbt_id("x"), "x");
        assert_eq!(sbt_id("a  b..c"), "a-b-c");
        // `java.util.regex`'s `\W` is ASCII-only.
        assert_eq!(sbt_id("Café_Ünï"), "caf-_-n-");
    }

    /// The L0a scoping fixtures: per-project, per-config scoping and the
    /// lang3 conflict (`c`'s direct 3.12.0 against `a`'s transitive 3.11).
    #[test]
    fn test_compile_fixtures_scope_every_project_and_config() {
        for ver in VERSIONS {
            let (res, _, dirs) = resolve(ver, "test-compile", "t");
            assert_eq!(dirs, set(&[".", "a", "b", "c"]), "{ver}");
            assert_eq!(res.projects_seen, dirs, "{ver}");
            assert_eq!(versions(&res, LANG3), ["3.11", "3.12.0"], "{ver}");
            assert!(res.in_scope.contains(&ga(GSON)), "{ver}");
            assert_eq!(versions(&res, GSON), ["2.8.9"], "{ver}");
            assert_eq!(versions(&res, TEXT), ["1.10.0", "1.9"], "{ver}");
            // junit only in a's test configuration: still a library scope.
            let junit = ga(("junit", "junit"));
            assert!(res.in_scope.contains(&junit), "{ver}");
            let ids = &res.modules[&junit]["4.13.2"];
            assert!(
                ids.iter()
                    .all(|id| id.starts_with("a/") || id.starts_with("target/out")),
                "{ver}: {ids:?}"
            );
            assert!(ids.iter().any(|id| id.contains(":test")), "{ver}: {ids:?}");
            assert!(
                !ids.iter().any(|id| id.ends_with(":compile")),
                "{ver}: {ids:?}"
            );
            // The pin gate on that evidence.
            assert_eq!(
                check_new(Some(&res), Some(&dirs), false, LANG3.0, LANG3.1, "3.11"),
                Err(GateRefusal::VersionConflict {
                    found: vec!["3.11".into(), "3.12.0".into()]
                }),
                "{ver}"
            );
            assert_eq!(
                check_new(Some(&res), Some(&dirs), false, GSON.0, GSON.1, "2.8.9"),
                Ok(vec![]),
                "{ver}"
            );
            // Artifact paths are the container's cache files.
            let jars = res
                .artifacts
                .get(&(LANG3.0.into(), LANG3.1.into(), "3.12.0".into()))
                .unwrap_or_else(|| panic!("{ver}: {:?}", res.artifacts.keys()));
            assert!(
                jars.iter()
                    .all(|p| p.to_str().unwrap().ends_with("commons-lang3-3.12.0.jar")),
                "{ver}: {jars:?}"
            );
        }
    }

    /// The L2 probe matrix: `d` has `crossPaths := false`, `e` is cross-built
    /// (`+e/update`) and also depends on lang3's `tests` classifier.
    #[test]
    fn matrix_fixtures_read_crosspaths_cross_builds_and_classifiers() {
        for ver in VERSIONS {
            let (res, _, dirs) = resolve(ver, "matrix", "x");
            assert_eq!(dirs, set(&[".", "a", "d", "e"]), "{ver}");
            assert_eq!(res.projects_seen, dirs, "{ver}: crossPaths := false read");
            assert_eq!(versions(&res, GSON), ["2.8.9"], "{ver}");
            assert!(res.in_scope.contains(&ga(GSON)), "{ver}");
            assert_eq!(versions(&res, LANG3), ["3.11"], "{ver}");
            assert_eq!(
                res.classifiers.get(&ga(LANG3)),
                Some(&set(&["tests"])),
                "{ver}"
            );
            assert_eq!(
                check_new(Some(&res), Some(&dirs), false, LANG3.0, LANG3.1, "3.11"),
                Err(GateRefusal::Classifier {
                    found: vec!["tests".into()]
                }),
                "{ver}"
            );
            assert_eq!(
                check_new(Some(&res), Some(&dirs), false, TEXT.0, TEXT.1, "1.9"),
                Ok(vec![]),
                "{ver}"
            );
            // The meta-build feeds only `meta_build` (on 1.x it resolves only
            // the Scala tooling every project's scala-tool resolves too).
            assert!(!res.meta_build.contains(&ga(LANG3)), "{ver}");
            for ga in &res.meta_build {
                assert!(!res.in_scope.contains(ga), "{ver}: {ga:?}");
            }
        }
        // The cross build is a union: both Scala binaries' records are read
        // (0.13's `+e/update` crosses with the root's versions only; its own
        // fixture is `0.13.18/cross`).
        for ver in ["1.2.8", "1.3.13", "1.9.9", "1.13.0"] {
            let (res, _, _) = resolve(ver, "matrix", "x");
            let lib = versions(&res, ("org.scala-lang", "scala-library"));
            assert!(
                lib.contains(&"2.12.18".to_string()) && lib.contains(&"2.13.12".to_string()),
                "{ver}: {lib:?}"
            );
        }
        let (res, _, _) = resolve("2.0.9", "matrix", "x");
        assert_eq!(
            versions(&res, ("org.scala-lang", "scala3-library_3")),
            ["3.3.4", "3.8.4"]
        );
        assert!(res
            .meta_build
            .contains(&ga(("com.fasterxml.jackson.core", "jackson-core"))));
        // (`project e` then `+update`: only `e` resolved.)
        let (res, _, _) = resolve("0.13.18", "cross", "x13");
        assert_eq!(res.projects_seen, set(&["e"]));
        assert_eq!(
            versions(&res, ("org.scala-lang", "scala-library")),
            ["2.10.7", "2.11.12"]
        );
    }

    #[test]
    fn ivy_era_reports_and_json_agree() {
        // 1.2.8 writes both formats; each alone gives the same scoping.
        let files = load(&fixture("1.2.8", "test-compile"));
        let declared = declared_projects(&sources(&files)).unwrap();
        let only = |xml: bool| -> JvmResolution {
            let subset: Vec<_> = files
                .iter()
                .filter(|(rel, _)| rel.ends_with(".xml") == xml)
                .cloned()
                .collect();
            resolution(&subset, Some(&declared), "t").unwrap()
        };
        let (xml, json) = (only(true), only(false));
        assert_eq!(xml.in_scope, json.in_scope);
        assert_eq!(xml.projects_seen, json.projects_seen);
        assert_eq!(versions(&xml, LANG3), versions(&json, LANG3));
        // Ivy's own eviction trail is not a resolution.
        assert_eq!(versions(&xml, LANG3), ["3.11", "3.12.0"]);
    }

    #[test]
    fn zero_thirteen_binary_cache_is_not_json_and_reports_are_read() {
        let files = load(&fixture("0.13.18", "test-compile"));
        let (rel, bytes) = files
            .iter()
            .find(|(rel, _)| rel.ends_with("/output"))
            .unwrap();
        let path = classify_path(rel, "t").unwrap();
        assert_eq!(
            parse_into(&path, rel, bytes, &mut JvmResolution::default()),
            Err(EvidenceError::NotJson)
        );
        // Binary caches alone are no evidence.
        let binary: Vec<_> = files
            .iter()
            .filter(|(rel, _)| rel.ends_with("/output"))
            .cloned()
            .collect();
        assert_eq!(resolution(&binary, None, "t"), None);
    }

    #[test]
    fn sbt2_ids_map_through_the_declared_projects() {
        // An implicit root is the sanitized directory name.
        let (res, declared, dirs) = resolve("2.0.9", "implicit-root", "My_Proj.1");
        assert_eq!(
            declared.get(IMPLICIT_ROOT_ID).map(String::as_str),
            Some(".")
        );
        assert_eq!(res.projects_seen, dirs);
        assert_eq!(versions(&res, GSON), ["2.8.9"]);
        assert!(
            !res.meta_build.is_empty(),
            "my_proj-1-build is the meta-build"
        );
        let (res, _, dirs) = resolve("1.9.9", "implicit-root", "My_Proj.1");
        assert_eq!(res.projects_seen, dirs);

        // The implicit root of a directory itself named `*-build` is no
        // renamed root's meta-build.
        let renamed: Vec<(String, Vec<u8>)> = load(&fixture("2.0.9", "implicit-root"))
            .into_iter()
            .map(|(rel, b)| (rel.replace("/my_proj-1", "/tools-build"), b))
            .collect();
        let declared = declared_projects(&sources(&renamed)).unwrap();
        let res = resolution(&renamed, Some(&declared), "Tools-Build").unwrap();
        assert_eq!(res.projects_seen, set(&["."]));
        assert_eq!(versions(&res, GSON), ["2.8.9"]);
        assert!(!res.meta_build.is_empty(), "tools-build-build");

        // Unknown ids never satisfy a declared directory.
        let files = load(&fixture("2.0.9", "matrix"));
        let partial = BTreeMap::from([("root".to_string(), ".".to_string())]);
        let res = resolution(&files, Some(&partial), "x").unwrap();
        assert_eq!(res.projects_seen, set(&[".", "id:a", "id:d", "id:e"]));
    }

    #[test]
    fn sbt2_user_project_named_like_the_meta_build_is_never_trusted() {
        // Probe: sbt 2 writes a project `x-build` (in `xb/`) and the meta-build
        // of root `x` to one directory; the last resolution wins. The record
        // counts as meta-build only, so `xb` has no evidence: incomplete.
        let (res, _, dirs) = resolve("2.0.9", "x-build", "x");
        assert_eq!(dirs, set(&[".", "xb"]));
        assert_eq!(res.projects_seen, set(&["."]));
        assert_eq!(
            check_new(Some(&res), Some(&dirs), false, GSON.0, GSON.1, "2.8.9"),
            Err(GateRefusal::Incomplete {
                missing: vec!["xb".into()]
            })
        );
    }

    #[test]
    fn use_coursier_false_reads_ivy_reports_and_json() {
        let (res, _, dirs) = resolve("1.9.9", "use-coursier-false", "n");
        assert_eq!(res.projects_seen, dirs);
        assert_eq!(versions(&res, LANG3), ["3.12.0"]);
        let jars = &res.artifacts[&(LANG3.0.into(), LANG3.1.into(), "3.12.0".into())];
        assert!(
            jars.iter().any(|p| p.starts_with("/root/.ivy2/cache")),
            "{jars:?}"
        );
    }

    #[test]
    fn malformed_evidence_is_fail_closed() {
        let good = load(&fixture("1.9.9", "matrix"));
        let mut files = good.clone();
        let at = files
            .iter()
            .position(|(rel, _)| rel == "a/target/scala-2.12/update/update_cache_2.12/output")
            .unwrap();
        files[at].1.truncate(100);
        assert_eq!(resolution(&files, None, "x"), None);
        for body in [
        &b"{}"[..],
        br#"{"configurations":[{"modules":[]}]}"#,
        br#"{"configurations":[{"configuration":{"name":"compile"},"modules":[{"module":{}}]}]}"#,
    ] {
        let path = classify_path("target/update/update_cache/output", "x").unwrap();
        assert!(matches!(
            parse_into(&path, "r", body, &mut JvmResolution::default()),
            Err(EvidenceError::Malformed(_))
        ));
    }
        let xml = classify_path("target/resolution-cache/reports/r.xml", "x").unwrap();
        assert!(matches!(
            parse_into(&xml, "r", b"<html/>", &mut JvmResolution::default()),
            Err(EvidenceError::Malformed(_))
        ));
    }

    #[test]
    fn json_evicted_modules_feed_nothing() {
        let body = br#"{"configurations":[{"configuration":{"name":"compile"},"modules":[
        {"module":{"organization":"g","name":"a","revision":"1"},"artifacts":[[{"name":"a","classifier":"x"},"file:///c/a-1-x.jar"]],"evicted":true},
        {"module":{"organization":"g","name":"a","revision":"2"},"artifacts":[[{"name":"a"},"file:///c/a%20b/a-2.jar"]],"evicted":false}
    ],"details":[]},{"configuration":{"name":"scala-tool"},"modules":[
        {"module":{"organization":"g","name":"t","revision":"9"},"artifacts":[[{"name":"t","classifier":"x"},"file:///c/t.jar"]]}
    ]}]}"#;
        let path = classify_path("target/update/update_cache/output", "x").unwrap();
        let mut res = JvmResolution::default();
        parse_into(&path, "target/update/update_cache/output", body, &mut res).unwrap();
        assert_eq!(versions(&res, ("g", "a")), ["2"]);
        assert_eq!(
            res.artifacts[&("g".into(), "a".into(), "2".into())],
            BTreeSet::from([PathBuf::from("/c/a b/a-2.jar")])
        );
        // scala-tool: a module (conflicts), not in scope, its classifier
        // ignored.
        assert_eq!(versions(&res, ("g", "t")), ["9"]);
        assert!(!res.in_scope.contains(&ga(("g", "t"))));
        assert!(res.classifiers.is_empty());
        assert_eq!(res.projects_seen, set(&["."]));
    }

    #[test]
    fn ivy_xml_entities_and_eviction() {
        let body = br#"<?xml version="1.0"?><ivy-report version="1.0">
<info organisation="p" module="p" revision="1" conf="runtime"/>
<dependencies>
<module organisation="g&amp;h" name="a">
<revision name="1" evicted="latest-revision"><evicted-by rev="2"/></revision>
<revision name="2">
<artifacts><artifact name="a" type="jar" ext="jar" extra-classifier="cl" location="/c/a&#32;2.jar"><origin-location location="https://x/a.jar"/></artifact></artifacts>
</revision>
</module>
</dependencies></ivy-report>"#;
        let path = classify_path("target/resolution-cache/reports/p-p-runtime.xml", "x").unwrap();
        let mut res = JvmResolution::default();
        parse_into(&path, "r", body, &mut res).unwrap();
        assert_eq!(versions(&res, ("g&h", "a")), ["2"]);
        assert!(res.in_scope.contains(&ga(("g&h", "a"))));
        assert_eq!(
            res.artifacts[&("g&h".into(), "a".into(), "2".into())],
            BTreeSet::from([PathBuf::from("/c/a 2.jar")])
        );
        assert_eq!(res.classifiers[&ga(("g&h", "a"))], set(&["cl"]));
    }

    #[test]
    fn location_paths() {
        let p = |s: &str| location_path(s).map(|p| p.to_str().unwrap().to_string());
        assert_eq!(p("file:///a/b.jar").as_deref(), Some("/a/b.jar"));
        assert_eq!(p("file:/a/b.jar").as_deref(), Some("/a/b.jar"));
        assert_eq!(p("file:///C:/u/b.jar").as_deref(), Some("C:/u/b.jar"));
        assert_eq!(p("file:///a/%E2%82%AC.jar").as_deref(), Some("/a/€.jar"));
        assert_eq!(p("/a/b.jar").as_deref(), Some("/a/b.jar"));
        assert_eq!(p("https://h/b.jar"), None);
        assert_eq!(p("rel/b.jar"), None);
        assert_eq!(p("file:///a/%zz"), None);
    }

    #[test]
    fn no_evidence_is_none() {
        assert_eq!(resolution(&[], None, "x"), None);
        let only_sources = vec![("build.sbt".to_string(), b"x".to_vec())];
        assert_eq!(resolution(&only_sources, None, "x"), None);
    }

    #[test]
    fn resolution_doc_round_trips() {
        let (res, _, dirs) = resolve("1.9.9", "matrix", "x");
        let doc = ResolutionDoc {
            root: PathBuf::from("/w/x"),
            resolution: Some(res),
            declared: Some(dirs),
            stale: true,
            wiring_newer: false,
            deps_digest: "0123abcd".into(),
            read_error: None,
            findings: BuildFindings {
                overrides_assignment: vec!["a/build.sbt:3".into()],
                ..Default::default()
            },
            artifact_sha256: BTreeMap::from([(PathBuf::from("/c/x.jar"), "ab".repeat(32))]),
            declared_deps: [crate::formats::sbt::build::DepLiteral {
                group: "g".into(),
                op: "%%".into(),
                artifact: "a".into(),
                version: "1.0".into(),
            }]
            .into(),
        };
        let json = doc.to_json();
        assert!(doc.holds_pinned_bytes(Path::new("/c/x.jar"), &"AB".repeat(32)));
        assert!(!doc.holds_pinned_bytes(Path::new("/c/y.jar"), &"ab".repeat(32)));
        assert_eq!(ResolutionDoc::from_json(&json), Some(doc));
        let empty = ResolutionDoc {
            read_error: Some("over the cap".into()),
            ..Default::default()
        };
        assert_eq!(ResolutionDoc::from_json(&empty.to_json()), Some(empty));
        assert_eq!(ResolutionDoc::from_json("{}"), None);
        assert_eq!(
            ResolutionDoc::from_json(&json.replacen("\"v\":1", "\"v\":2", 1)),
            None
        );
    }
}
