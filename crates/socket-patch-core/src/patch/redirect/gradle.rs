//! Hosted Gradle: the owned settings script, its index and the lockfile
//! surgery that pin a patched Maven GAV to its Socket-suffixed version.
//!
//! A Gradle build gets three owned files under `.socket/gradle/`:
//!
//! - [`HOSTED_SCRIPT`] (`socket-patch.hosted.settings.gradle`), static
//!   bytes that change only with a CLI release;
//! - [`HOSTED_INDEX_REL`], one row per pinned GA:
//!   `g:a:base<TAB>suffixed<TAB>index_url<TAB>jar_sha256<TAB>pom_sha256<TAB>uuid`;
//! - `.gitattributes` (`* -text`, shared with the vendored script), so a
//!   `core.autocrlf` checkout keeps both byte-exact.
//!
//! Every settings file of the checkout's builds (the root, `buildSrc`, each
//! literal `includeBuild`) gets one apply line carrying the index digest,
//! `apply from: '.socket/gradle/socket-patch.hosted.settings.gradle' //
//! socket-patch-hosted <sha256[..16] of the index>`: the settings script is
//! a configuration-cache input on every Gradle major, so a changed index
//! invalidates cached configurations. A settings file the planner created
//! carries ` created` after the digest, so the restore deletes only those
//! (an existing empty `settings.gradle` marks a build root and stays). The script routes each suffixed
//! version to its Socket repository with `exclusiveContent`, rewrites every
//! request whose selector admits the base to the suffixed version
//! (dependency substitution plus `eachDependency`), rejects every other
//! candidate at or below the base, and trips on anything that still
//! resolves there. A request that admits the base is pinned like a lock:
//! a dynamic or range selector resolves the patched version even after a
//! newer upstream release appears (the Socket repository lists no
//! versions, so leaving the selector dynamic could find no acceptable
//! candidate at all), and the planner says so
//! (`redirect_gradle_dynamic_selector_pinned`). A `latest.*` request is
//! refused (`redirect_gradle_latest_selector`): whether it admits the base
//! depends on what the repositories list, so the script cannot rewrite it,
//! and with every upstream candidate at or below the base rejected it
//! would fail to resolve. A request whose selector
//! does not admit the base (an explicit newer version, a lock or
//! `strictly` above the base, a transitive bump) is left alone and
//! resolves above the base; discovery then withholds the attestation
//! where a lock records it.
//!
//! Every lock file of every build (`ScriptGraph::lockfile_paths`) has the
//! base entry rewritten to the suffixed one, and an existing
//! `gradle/verification-metadata.xml` gets the suffixed component. A dep
//! the planner refuses writes nothing and gets a per-DSL fallback snippet
//! (`redirect_gradle_manual_snippet`).
//!
//! The planner is pure over the candidate files: the hosted engine reads
//! every script, catalog and lock file the script graph reaches
//! ([`GradleFiles`]) before it runs. Discovery
//! (`vex::discover::gradle`) and the upstream restore
//! (`upstream::gradle`) share the index grammar, the targets and the
//! apply-line helpers below.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use super::{
    bare_sha256_hex, registry_override_of_kind, DepOverride, FileEdit, RewriteResult,
    RewriteWarning,
};
use crate::gradle::dsl::{self, is_ident, is_punct, Dsl, Tok, Token};
use crate::gradle::eol::{eol_eq, newline_of, to_lf};
use crate::gradle::graph::{
    filter_claims_group, wrapper_version, BuildKind, DeclKind, ScriptGraph, Site,
};
use crate::gradle::locks;
use crate::gradle::selector::{admits, gradle_version_cmp, parse_selector, Selector};
use crate::patch::path_safety::is_canonical_uuid;
use crate::vendor::jvm::gradle as vendored;
use crate::vendor::jvm::layout::GRADLE_ROOT_FILES;

/// The owned hosted settings script. Its bytes change only with a CLI
/// release.
pub const HOSTED_SCRIPT: &str = include_str!("socket-patch.hosted.settings.gradle");
/// Where [`HOSTED_SCRIPT`] lives, project-relative.
pub const HOSTED_SCRIPT_REL: &str = ".socket/gradle/socket-patch.hosted.settings.gradle";
/// The index the script reads.
pub const HOSTED_INDEX_REL: &str = ".socket/gradle/hosted-index.tsv";
pub const HOSTED_INDEX_HEADER: &str = "#socket-patch-gradle-hosted-index 1";
/// `.socket/gradle/.gitattributes`, shared with the vendored script.
pub const GITATTRIBUTES_REL: &str = vendored::SCRIPT_GITATTRIBUTES_REL;
/// What a created [`GITATTRIBUTES_REL`] holds.
pub const GITATTRIBUTES: &str = "* -text\n";
/// The comment after the apply line's path, followed by the index digest.
pub const DIGEST_TAG: &str = "// socket-patch-hosted";
/// The word after the digest on the apply line of a settings file the
/// planner created.
pub const CREATED_TAG: &str = "created";
/// The script's repository names (`<prefix>_<n>`).
const REPO_NAME_PREFIX: &str = "socketPatchHosted";
/// The vendored backend's index (a GA it serves cannot also be hosted).
const VENDORED_INDEX_REL: &str = vendored::INDEX_REL;
const VERIFICATION_REL: &str = vendored::VERIFICATION_REL;
const WRAPPER_PROPERTIES_REL: &str = "gradle/wrapper/gradle-wrapper.properties";

/// Whether `rel` is a settings-classpath lock (`settings-gradle.lockfile`
/// of any build). Gradle resolves that classpath before any settings
/// script runs, so the hosted script can never pin what it locks.
pub fn is_settings_lock(rel: &str) -> bool {
    rel.rsplit('/').next() == Some("settings-gradle.lockfile")
}

/// Whether `files` (root-relative) hold a root Gradle settings or build
/// script.
pub fn gradle_build_present(files: &BTreeMap<String, String>) -> bool {
    GRADLE_ROOT_FILES.iter().any(|f| files.contains_key(*f))
}

// ── the index ────────────────────────────────────────────────────────────

/// One index row: a GA pinned to its suffixed version on a Socket
/// repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedRow {
    pub group: String,
    pub artifact: String,
    pub base: String,
    pub suffixed: String,
    pub url: String,
    pub jar_sha256: String,
    pub pom_sha256: String,
    pub uuid: String,
}

impl HostedRow {
    pub fn ga(&self) -> String {
        format!("{}:{}", self.group, self.artifact)
    }

    /// The canonical base purl the row patches.
    pub fn purl(&self) -> String {
        format!("pkg:maven/{}/{}@{}", self.group, self.artifact, self.base)
    }

    fn line(&self) -> String {
        format!(
            "{}:{}:{}\t{}\t{}\t{}\t{}\t{}",
            self.group,
            self.artifact,
            self.base,
            self.suffixed,
            self.url,
            self.jar_sha256,
            self.pom_sha256,
            self.uuid
        )
    }

    /// One row, validated exactly as the script validates it.
    pub fn parse(line: &str) -> Option<Self> {
        let c: Vec<&str> = line.split('\t').collect();
        if c.len() != 6 {
            return None;
        }
        let gav: Vec<&str> = c[0].split(':').collect();
        let [g, a, base] = gav[..] else {
            return None;
        };
        let row = HostedRow {
            group: g.to_string(),
            artifact: a.to_string(),
            base: base.to_string(),
            suffixed: c[1].to_string(),
            url: c[2].to_string(),
            jar_sha256: c[3].to_string(),
            pom_sha256: c[4].to_string(),
            uuid: c[5].to_string(),
        };
        row.valid().then_some(row)
    }

    /// The script's row grammar: safe coordinates, a canonical lowercase
    /// uuid, `suffixed == base-socket.<uuid[..8]>`, an https url without
    /// whitespace and two lowercase sha256s.
    pub fn valid(&self) -> bool {
        let hex64 = |s: &str| crate::utils::digest::is_hex64_lower(s);
        crate::vendor::jvm::layout::safe_coordinates(&self.group, &self.artifact, &self.base)
            && self.base.chars().any(|c| c != '.')
            && is_canonical_uuid(&self.uuid)
            && self.uuid == self.uuid.to_ascii_lowercase()
            && self.suffixed == suffixed_version(&self.base, &self.uuid)
            && self.url.strip_prefix("https://").is_some_and(|rest| {
                !rest.is_empty() && !rest.chars().any(|c| c.is_whitespace() || c.is_control())
            })
            && hex64(&self.jar_sha256)
            && hex64(&self.pom_sha256)
    }
}

/// `<base>-socket.<first 8 hex of the uuid>`.
pub fn suffixed_version(base: &str, uuid: &str) -> String {
    format!("{base}-socket.{}", uuid.get(..8).unwrap_or(uuid))
}

/// The rows of an index text (LF or CRLF). `Err` names the first line the
/// script would refuse (an unknown header, a malformed or duplicate row).
pub fn parse_index(text: &str) -> Result<Vec<HostedRow>, String> {
    let lf = String::from_utf8_lossy(&to_lf(text.as_bytes())).into_owned();
    let mut lines = lf.split('\n');
    if lines.next() != Some(HOSTED_INDEX_HEADER) {
        return Err(format!("{HOSTED_INDEX_REL} has an unknown header"));
    }
    let mut rows: Vec<HostedRow> = Vec::new();
    for line in lines.filter(|l| !l.is_empty()) {
        let Some(row) = HostedRow::parse(line) else {
            return Err(format!("{HOSTED_INDEX_REL} has a malformed row: {line}"));
        };
        if rows.iter().any(|r| r.ga() == row.ga()) {
            return Err(format!("{HOSTED_INDEX_REL} pins {} twice", row.ga()));
        }
        rows.push(row);
    }
    Ok(rows)
}

/// The index text of `rows` (sorted by GA, LF, trailing newline).
pub fn render_index(rows: &[HostedRow]) -> String {
    let mut sorted: Vec<&HostedRow> = rows.iter().collect();
    sorted.sort_by_key(|r| (r.group.clone(), r.artifact.clone()));
    let mut out = format!("{HOSTED_INDEX_HEADER}\n");
    for r in sorted {
        out.push_str(&r.line());
        out.push('\n');
    }
    out
}

/// The apply line's digest of an index text: the first 16 hex of the
/// sha256 of its LF form.
pub fn index_digest(text: &str) -> String {
    let digest = Sha256::digest(to_lf(text.as_bytes()));
    hex::encode(digest)[..16].to_string()
}

// ── the settings files ───────────────────────────────────────────────────

/// One settings file to wire: the root build, `buildSrc` or an included
/// build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsTarget {
    /// The build directory (`""` = the root).
    pub dir: String,
    pub rel: String,
    pub dsl: Dsl,
    /// Whether the settings file exists (else the planner creates it).
    pub exists: bool,
}

impl SettingsTarget {
    /// `../` once per segment of the build directory.
    pub fn prefix(&self) -> String {
        "../".repeat(if self.dir.is_empty() {
            0
        } else {
            self.dir.split('/').count()
        })
    }
}

/// The settings files of every build `graph` found: the root's (created
/// when missing), and `buildSrc`'s and each included build's when the
/// build holds a settings or build script. A created file takes its DSL
/// from the build's own build script.
pub fn settings_targets(graph: &ScriptGraph) -> Vec<SettingsTarget> {
    let mut out = Vec::new();
    for b in &graph.builds {
        if let Some(rel) = &b.settings {
            out.push(SettingsTarget {
                dir: b.dir.clone(),
                rel: rel.clone(),
                dsl: dsl::dsl_of(rel).unwrap_or(Dsl::Groovy),
                exists: true,
            });
            continue;
        }
        let script = b
            .projects
            .iter()
            .find(|p| p.path == ":")
            .and_then(|p| p.build_script.clone());
        if script.is_none() && b.kind != BuildKind::Root {
            continue;
        }
        let dsl = script
            .as_deref()
            .and_then(dsl::dsl_of)
            .unwrap_or(Dsl::Groovy);
        let name = match dsl {
            Dsl::Kotlin => "settings.gradle.kts",
            Dsl::Groovy => "settings.gradle",
        };
        out.push(SettingsTarget {
            dir: b.dir.clone(),
            rel: crate::gradle::join_rel(&b.dir, name),
            dsl,
            exists: false,
        });
    }
    out
}

/// The apply line for a build `prefix` below the root (`created` when the
/// planner creates the settings file).
pub fn apply_line(dsl: Dsl, prefix: &str, digest: &str, created: bool) -> String {
    let path = format!("{prefix}{HOSTED_SCRIPT_REL}");
    let tag = if created {
        format!("{DIGEST_TAG} {digest} {CREATED_TAG}")
    } else {
        format!("{DIGEST_TAG} {digest}")
    };
    match dsl {
        Dsl::Kotlin => format!("apply(from = \"{path}\") {tag}"),
        Dsl::Groovy => format!("apply from: '{path}' {tag}"),
    }
}

/// The first live `apply from` of the hosted script at `prefix` (either
/// DSL's spelling; one inside a comment does not count): the byte range
/// from its `apply` token to the end of its line (no line break).
pub fn apply_line_span(text: &str, dsl: Dsl, prefix: &str) -> Option<(usize, usize)> {
    let path = format!("{prefix}{HOSTED_SCRIPT_REL}");
    let toks = dsl::tokens(text, dsl);
    let at = (0..toks.len()).find(|&i| {
        if !is_ident(toks.get(i), "apply") {
            return false;
        }
        let mut j = i + 1;
        if is_punct(toks.get(j), b'(') {
            j += 1;
        }
        is_ident(toks.get(j), "from")
            && (is_punct(toks.get(j + 1), b':') || is_punct(toks.get(j + 1), b'='))
            && matches!(toks.get(j + 2), Some(Token { tok: Tok::Str { value, .. }, .. }) if *value == path)
    })?;
    let start = toks[at].start;
    let end = text[start..].find('\n').map_or(text.len(), |i| start + i);
    let end = if text[..end].ends_with('\r') {
        end - 1
    } else {
        end
    };
    Some((start, end))
}

/// The words after [`DIGEST_TAG`] on the live apply line, if any.
fn apply_line_tail(text: &str, dsl: Dsl, prefix: &str) -> Option<Vec<String>> {
    let (start, end) = apply_line_span(text, dsl, prefix)?;
    let tail = text[start..end].split_once(DIGEST_TAG)?.1;
    Some(tail.split_whitespace().map(str::to_string).collect())
}

/// The digest the live apply line carries, if any.
pub fn apply_line_digest(text: &str, dsl: Dsl, prefix: &str) -> Option<String> {
    apply_line_tail(text, dsl, prefix)?.into_iter().next()
}

/// Whether the live apply line marks a settings file the planner created.
pub fn apply_line_created(text: &str, dsl: Dsl, prefix: &str) -> bool {
    apply_line_tail(text, dsl, prefix)
        .is_some_and(|t| t.get(1).map(String::as_str) == Some(CREATED_TAG))
}

/// `text` with its apply line set to the one for `digest`: replaced in
/// place (keeping its `created` mark), or appended in the file's
/// line-ending style, marked `created` when the planner is creating the
/// file. `None` when it already reads so.
pub fn with_apply_line(
    text: &str,
    dsl: Dsl,
    prefix: &str,
    digest: &str,
    created: bool,
) -> Option<String> {
    if let Some((start, end)) = apply_line_span(text, dsl, prefix) {
        let line = apply_line(dsl, prefix, digest, apply_line_created(text, dsl, prefix));
        if text[start..end] == line {
            return None;
        }
        return Some(format!("{}{line}{}", &text[..start], &text[end..]));
    }
    let line = apply_line(dsl, prefix, digest, created);
    let nl = newline_of(text);
    let mut out = text.to_string();
    if !out.is_empty() && !out.ends_with('\n') && out != "\u{feff}" {
        out.push_str(nl);
    }
    out.push_str(&line);
    out.push_str(nl);
    Some(out)
}

/// `text` without the whole line holding the live apply line (its line
/// break included). `None` when there is none, or when other code shares
/// its line.
pub fn without_apply_line(text: &str, dsl: Dsl, prefix: &str) -> Option<String> {
    let (start, end) = apply_line_span(text, dsl, prefix)?;
    let line_start = text[..start].rfind('\n').map_or(0, |i| i + 1);
    let lead = &text[line_start..start];
    if !lead.trim_start_matches('\u{feff}').trim().is_empty() {
        return None;
    }
    let keep_bom = if lead.starts_with('\u{feff}') {
        "\u{feff}"
    } else {
        ""
    };
    let mut cut_end = end;
    if text[cut_end..].starts_with("\r\n") {
        cut_end += 2;
    } else if text[cut_end..].starts_with('\n') {
        cut_end += 1;
    }
    Some(format!(
        "{}{keep_bom}{}",
        &text[..line_start],
        &text[cut_end..]
    ))
}

// ── reading the build ────────────────────────────────────────────────────

/// The fixed files besides the script graph the planner reads.
pub const FIXED_READS: &[&str] = &[
    HOSTED_INDEX_REL,
    HOSTED_SCRIPT_REL,
    GITATTRIBUTES_REL,
    VENDORED_INDEX_REL,
    VERIFICATION_REL,
    WRAPPER_PROPERTIES_REL,
];

/// The Gradle files a host must read before the planner (or discovery, or
/// the restore) can run: the script graph's scripts and catalogs, every
/// lock file of every build, and [`FIXED_READS`]. The host drives it to a
/// fixed point: [`GradleFiles::misses`] says what to read or list next,
/// [`GradleFiles::found`] / [`GradleFiles::absent`] /
/// [`GradleFiles::listed`] record the answers.
#[derive(Debug, Clone, Default)]
pub struct GradleFiles {
    pub files: BTreeMap<String, String>,
    absent: BTreeSet<String>,
    dirs: BTreeMap<String, Vec<String>>,
}

/// The rounds [`GradleFiles`] is driven for at most (each `apply from` or
/// included-build level costs one).
pub const MAX_ROUNDS: usize = 32;

impl GradleFiles {
    pub fn found(&mut self, rel: &str, text: String) {
        self.files.insert(rel.to_string(), text);
    }

    pub fn absent(&mut self, rel: &str) {
        self.absent.insert(rel.to_string());
    }

    /// A directory's children: names, directories ending in `/`.
    pub fn listed(&mut self, dir: &str, children: Vec<String>) {
        self.dirs.insert(dir.to_string(), children);
    }

    fn read(&self, rel: &str, misses: &std::cell::RefCell<BTreeSet<String>>) -> Option<String> {
        if let Some(t) = self.files.get(rel) {
            return Some(dsl::strip_bom(t).to_string());
        }
        if !self.absent.contains(rel) {
            misses.borrow_mut().insert(rel.to_string());
        }
        None
    }

    fn list(&self, dir: &str, misses: &std::cell::RefCell<BTreeSet<String>>) -> Vec<String> {
        match self.dirs.get(dir) {
            Some(children) => children.clone(),
            None => {
                misses.borrow_mut().insert(dir.to_string());
                Vec::new()
            }
        }
    }

    /// `(files to read, directories to list)` the graph still needs.
    /// Empty when the fixed point is reached.
    pub fn misses(&self) -> (Vec<String>, Vec<String>) {
        let reads = std::cell::RefCell::new(BTreeSet::new());
        let lists = std::cell::RefCell::new(BTreeSet::new());
        let read = |rel: &str| self.read(rel, &reads);
        let list = |dir: &str| self.list(dir, &lists);
        for rel in FIXED_READS.iter().chain(GRADLE_ROOT_FILES) {
            read(rel);
        }
        if GRADLE_ROOT_FILES
            .iter()
            .any(|f| self.files.contains_key(*f))
        {
            let graph = ScriptGraph::collect(&read, &list, "", &[]);
            for rel in graph.lockfile_paths(&list) {
                read(&rel);
            }
        }
        (
            reads.into_inner().into_iter().collect(),
            lists.into_inner().into_iter().collect(),
        )
    }
}

/// Whether a read error means the file is not there (absent to the script
/// graph), as opposed to a file that exists but cannot be read as text
/// (permissions, non-UTF-8 bytes, not a regular file), which
/// [`unreadable_refusal`] refuses.
pub fn is_absent_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    )
}

/// Refusal code for a build whose script graph reaches a file that exists
/// but cannot be read as text: the planner would take it for absent and,
/// for a settings file, write a new one over it.
pub const UNREADABLE_REFUSAL_CODE: &str = "redirect_gradle_build_file_unreadable";

/// The build-level refusal for the files the script graph reached that
/// exist but could not be read (see [`is_absent_error`]).
fn unreadable_refusal(unreadable: &BTreeSet<String>) -> Option<Refusal> {
    let rel = unreadable.iter().next()?;
    Some(refusal(
        UNREADABLE_REFUSAL_CODE,
        format!(
            "{rel} exists but cannot be read as UTF-8 text (permissions, encoding, or not a \
             regular file), so the hosted wiring cannot edit the build safely; make it a \
             readable UTF-8 file and re-run"
        ),
    ))
}

/// A Gradle build read from disk ([`read_build_from_disk`]).
#[derive(Debug, Clone, Default)]
pub struct DiskBuild {
    /// The readable files the script graph reached.
    pub files: BTreeMap<String, String>,
    /// Files it reached that exist but could not be read as text.
    pub unreadable: BTreeSet<String>,
}

/// The Gradle build under `root`, read from disk to the fixed point of
/// [`GradleFiles`] (a missing file is absent; one that exists but cannot
/// be read is absent to the graph and listed in `unreadable`; a directory
/// that cannot be listed lists as empty).
pub async fn read_build_from_disk(root: &std::path::Path) -> DiskBuild {
    let mut gradle = GradleFiles::default();
    let mut unreadable = BTreeSet::new();
    for _ in 0..MAX_ROUNDS {
        let (reads, lists) = gradle.misses();
        if reads.is_empty() && lists.is_empty() {
            break;
        }
        for rel in reads {
            match crate::utils::fs::read_regular_to_string(&root.join(&rel)).await {
                Ok(text) => gradle.found(&rel, text),
                Err(e) => {
                    if !is_absent_error(&e) {
                        unreadable.insert(rel.clone());
                    }
                    gradle.absent(&rel);
                }
            }
        }
        for dir in lists {
            let mut children = Vec::new();
            if let Ok(mut entries) = tokio::fs::read_dir(root.join(&dir)).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                        continue;
                    };
                    let is_dir = entry.file_type().await.is_ok_and(|t| t.is_dir());
                    children.push(if is_dir { format!("{name}/") } else { name });
                }
            }
            children.sort();
            gradle.listed(&dir, children);
        }
    }
    DiskBuild {
        files: gradle.files,
        unreadable,
    }
}

/// Every project file the hosted Gradle wiring of the build `files` holds
/// can live in: every build's settings file (created ones included), every
/// lock file of every build, and the owned and fixed files. The upstream
/// restore writes or deletes only these, so a snapshot of them undoes it.
pub fn wiring_files(files: &BTreeMap<String, String>) -> Vec<String> {
    let graph = graph_of(files);
    let mut out: BTreeSet<String> = settings_targets(&graph)
        .into_iter()
        .map(|t| t.rel)
        .collect();
    out.extend(lockfile_paths(&graph, files));
    out.extend(FIXED_READS.iter().map(|s| s.to_string()));
    out.into_iter().collect()
}

/// A [`crate::gradle::ListFn`] over the keys of `files`.
fn key_list(files: &BTreeMap<String, String>, dir: &str) -> Vec<String> {
    let prefix = if dir.is_empty() {
        String::new()
    } else {
        format!("{}/", dir.trim_end_matches('/'))
    };
    let mut out: Vec<String> = Vec::new();
    for key in files.keys() {
        let Some(rest) = key.strip_prefix(&prefix) else {
            continue;
        };
        let child = match rest.find('/') {
            Some(i) => format!("{}/", &rest[..i]),
            None => rest.to_string(),
        };
        if !out.contains(&child) {
            out.push(child);
        }
    }
    out
}

/// The script graph of the build `files` holds (BOMs stripped for the
/// tokenizer).
pub fn graph_of(files: &BTreeMap<String, String>) -> ScriptGraph {
    let read = |rel: &str| files.get(rel).map(|t| dsl::strip_bom(t).to_string());
    let list = |dir: &str| key_list(files, dir);
    ScriptGraph::collect(&read, &list, "", &[])
}

/// Every lock file of every build of `graph` that `files` holds.
pub fn lockfile_paths(graph: &ScriptGraph, files: &BTreeMap<String, String>) -> Vec<String> {
    let list = |dir: &str| key_list(files, dir);
    graph.lockfile_paths(&list)
}

// ── the planner ──────────────────────────────────────────────────────────

/// A refusal: nothing is written for the dep.
struct Refusal {
    code: &'static str,
    detail: String,
}

fn refusal(code: &'static str, detail: impl Into<String>) -> Refusal {
    Refusal {
        code,
        detail: detail.into(),
    }
}

/// One accepted dep.
struct Accepted {
    row: HostedRow,
    /// The suffixed version of an earlier patch of the same GAV this row
    /// replaces (its lock entries move to the new suffix).
    replaces: Option<String>,
    module_sha256: Option<String>,
}

/// The DSLs the build's scripts use.
fn build_dsls(files: &BTreeMap<String, String>) -> Vec<Dsl> {
    let mut out = Vec::new();
    let any = |pred: fn(&str) -> bool| files.keys().any(|k| pred(k));
    if any(|k| k.ends_with(".gradle") && !k.starts_with(".socket/")) {
        out.push(Dsl::Groovy);
    }
    if any(|k| k.ends_with(".gradle.kts")) {
        out.push(Dsl::Kotlin);
    }
    if out.is_empty() {
        out.push(Dsl::Groovy);
    }
    out
}

/// Refusals that hold for every dep of this build.
fn project_refusal(
    files: &BTreeMap<String, String>,
    graph: &ScriptGraph,
    index: &Result<Vec<HostedRow>, String>,
) -> Option<Refusal> {
    let read = |rel: &str| files.get(rel).map(|t| dsl::strip_bom(t).to_string());
    if let Some((maj, min, patch)) = wrapper_version(&read, "") {
        if (maj, min) < (6, 8) {
            return Some(refusal(
                "redirect_gradle_version_unsupported",
                format!(
                    "the Gradle wrapper pins {maj}.{min}.{patch}; hosted patches need Gradle \
                     6.8 or newer"
                ),
            ));
        }
    }
    if let Some((rel, id)) = graph.android_or_kmp() {
        return Some(refusal(
            "redirect_gradle_android_or_kmp",
            format!(
                "{rel} uses {id}; Android and Kotlin Multiplatform builds resolve variants the \
                 hosted wiring does not cover"
            ),
        ));
    }
    if let Some(u) = graph
        .unresolved
        .iter()
        .find(|u| u.site == Site::IncludeBuild)
    {
        return Some(refusal(
            "redirect_gradle_include_build_unresolved",
            format!(
                "{}:{}: includeBuild {} cannot be followed ({:?}); that build would stay \
                 unpinned",
                u.rel,
                u.line,
                if u.snippet.is_empty() {
                    "target"
                } else {
                    u.snippet.as_str()
                },
                u.reason
            ),
        ));
    }
    if let Some(rel) = graph.custom_lock_file() {
        return Some(refusal(
            "redirect_gradle_lock_location_unknown",
            format!(
                "{rel} sets a custom dependency-lock file (`lockFile`), which socket-patch \
                 cannot find to pin"
            ),
        ));
    }
    if let Err(why) = index {
        return Some(refusal(
            "redirect_gradle_index_malformed",
            format!("{why}; restore it from version control or delete it and re-run"),
        ));
    }
    None
}

/// The GAs the vendored Gradle backend serves (`.socket/vendor/gradle-index.tsv`).
fn vendored_gas(files: &BTreeMap<String, String>) -> BTreeSet<String> {
    let Some(text) = files.get(VENDORED_INDEX_REL) else {
        return BTreeSet::new();
    };
    text.lines()
        .skip(1)
        .filter_map(|l| l.split('\t').next())
        .filter_map(|gav| {
            let mut it = gav.trim().split(':');
            Some(format!("{}:{}", it.next()?, it.next()?))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn plan_dep(
    dep: &DepOverride,
    files: &BTreeMap<String, String>,
    graph: &ScriptGraph,
    lock_paths: &[String],
    rows: &[HostedRow],
    vendored_gas: &BTreeSet<String>,
    project: Option<&Refusal>,
) -> Result<Accepted, Refusal> {
    let ov = registry_override_of_kind(dep, "maven2").expect("filtered by the caller");
    let (group, artifact) = coords_of(dep);
    let base = dep.version.clone();
    let ga = format!("{group}:{artifact}");
    let (Some(suffixed), Some(pom)) = (
        ov.identifiers.maven_suffixed_version.clone(),
        ov.identifiers
            .maven_pom_sha256
            .as_deref()
            .map(bare_sha256_hex),
    ) else {
        return Err(refusal(
            "redirect_gradle_same_gav_unsupported",
            format!(
                "{ga}:{base} is served at its original GAV, which a Gradle build cannot pin \
                 fail-closed (a Socket-repository failure would resolve the unpatched upstream)"
            ),
        ));
    };
    if let Some(r) = project {
        return Err(refusal(r.code, r.detail.clone()));
    }
    let row = HostedRow {
        group: group.clone(),
        artifact: artifact.clone(),
        base: base.clone(),
        suffixed: suffixed.clone(),
        url: ov.index_url.clone(),
        jar_sha256: dep
            .integrity
            .sha256
            .as_deref()
            .map(bare_sha256_hex)
            .unwrap_or_default(),
        pom_sha256: pom,
        uuid: dep.patch_uuid.clone(),
    };
    if !row.valid() {
        return Err(refusal(
            "redirect_gradle_override_invalid",
            format!(
                "the hosted grant for {ga}:{base} is not usable in a Gradle build (it needs \
                 safe coordinates, a canonical uuid, the suffix {} on an https repository and \
                 the jar and pom sha256)",
                suffixed_version(&base, &dep.patch_uuid)
            ),
        ));
    }
    if vendored_gas.contains(&ga) {
        return Err(refusal(
            "redirect_gradle_vendored_conflict",
            format!(
                "{ga} is vendored ({VENDORED_INDEX_REL}); run `socket-patch vendor --revert` \
                 first"
            ),
        ));
    }
    if let Some(r) = ga_refusal(files, graph, lock_paths, &group, &artifact, &base) {
        return Err(r);
    }
    let replaces = match rows.iter().find(|r| r.ga() == ga) {
        Some(r) if r.base != base => {
            return Err(refusal(
                "redirect_gradle_version_conflict",
                format!(
                    "{HOSTED_INDEX_REL} already pins {ga} at {} (base {}); one GA takes one \
                     hosted patch",
                    r.suffixed, r.base
                ),
            ))
        }
        Some(r) if r.suffixed != suffixed => Some(r.suffixed.clone()),
        _ => None,
    };
    for rel in lock_paths {
        let Some(text) = files.get(rel) else { continue };
        let state = locks::parse(text);
        let conflict = state
            .entries_of(&group, &artifact)
            .find(|e| {
                e.version != base
                    && e.version != suffixed
                    && Some(&e.version) != replaces.as_ref()
                    && !above_base(&e.version, &base)
            })
            .cloned();
        if let Some(e) = conflict {
            return Err(refusal(
                "redirect_gradle_lock_conflict",
                format!(
                    "{rel}:{} locks {ga} at {}, below the patched {base} (and not {suffixed}), \
                     which the pin would reject; re-lock (`--write-locks`) first",
                    e.line, e.version
                ),
            ));
        }
    }
    Ok(Accepted {
        row,
        replaces,
        module_sha256: ov
            .identifiers
            .maven_module_sha256
            .as_deref()
            .map(bare_sha256_hex)
            .filter(|s| crate::utils::digest::is_hex64_lower(s)),
    })
}

/// The planner's refusals that depend only on the build and the GA (not
/// on the grant or the index): a settings-classpath declaration or lock,
/// a classifier request, a `strictly` that admits nothing the pin lets
/// resolve, a user `exclusiveContent` claiming the group. Discovery re-runs
/// them, so a build changed after the scan stops attesting.
fn ga_refusal(
    files: &BTreeMap<String, String>,
    graph: &ScriptGraph,
    lock_paths: &[String],
    group: &str,
    artifact: &str,
    base: &str,
) -> Option<Refusal> {
    let ga = format!("{group}:{artifact}");
    if graph.settings_classpath_has(group, artifact) {
        return Some(refusal(
            "redirect_gradle_settings_classpath",
            format!(
                "{ga} is on a settings-script classpath, which Gradle resolves before the hosted \
                 settings script runs"
            ),
        ));
    }
    // A settings plugin can pull the GA in transitively, which no literal
    // declaration shows; its settings-classpath lock does.
    if let Some(rel) = lock_paths.iter().find(|rel| {
        is_settings_lock(rel)
            && files
                .get(*rel)
                .is_some_and(|t| locks::parse(t).entries_of(group, artifact).next().is_some())
    }) {
        return Some(refusal(
            "redirect_gradle_settings_classpath",
            format!(
                "{rel} locks {ga} on a settings-script classpath, which Gradle resolves before \
                 the hosted settings script runs"
            ),
        ));
    }
    let decls = graph.declarations_of(group, artifact);
    if let Some(d) = decls.iter().find(|d| d.kind == DeclKind::Classifier) {
        return Some(refusal(
            "redirect_gradle_classifier_declared",
            format!(
                "{}:{} requests {ga} with classifier `{}`, which the Socket repository does not \
                 serve",
                d.rel,
                d.line,
                d.classifier.as_deref().unwrap_or_default()
            ),
        ));
    }
    // `latest.release` / `latest.integration` picks from the versions the
    // repositories list. The pin cannot rewrite it (whether it admits the
    // base depends on that listing), rejects every upstream candidate at or
    // below the base, and the Socket repository lists none: while upstream
    // has no release above the base, which is the usual case while the
    // vulnerability is unfixed, every resolution fails.
    if let Some((d, sel)) = decls.iter().find_map(|d| {
        let rich = d.rich.as_ref();
        [
            d.version.as_deref(),
            rich.and_then(|v| v.strictly.as_deref()),
            rich.and_then(|v| v.require.as_deref()),
            rich.and_then(|v| v.prefer.as_deref()),
        ]
        .into_iter()
        .flatten()
        .find(|sel| matches!(parse_selector(sel), Selector::Latest(_)))
        .map(|sel| (d, sel))
    }) {
        return Some(refusal(
            "redirect_gradle_latest_selector",
            format!(
                "{}:{} requests {ga} as `{sel}`, which the pin cannot rewrite: with every \
                 upstream release at or below {base} rejected and none listed by the Socket \
                 repository, the build would fail until upstream ships a newer release. Declare \
                 {ga}:{base} explicitly and scan again",
                d.rel, d.line
            ),
        ));
    }
    // A `strictly` above the base (a newer upstream fix) is left to
    // resolve, as the script lets it; one that only admits versions at or
    // below the base would fail every resolution under the pin.
    if let Some((d, strict)) = decls.iter().find_map(|d| {
        let strict = d.rich.as_ref()?.strictly.as_deref()?;
        let sel = parse_selector(strict);
        (admits(&sel, base) == Some(false) && !may_admit_above(&sel, base)).then_some((d, strict))
    }) {
        return Some(refusal(
            "redirect_gradle_range_declared",
            format!(
                "{}:{} declares {ga} `strictly {strict}`, which excludes the patched {base}; \
                 the pin would fail every resolution",
                d.rel, d.line
            ),
        ));
    }
    if let Some(f) = graph.exclusive_content_filters().into_iter().find(|f| {
        !f.rel.starts_with(".socket/")
            && !f
                .repo_strings
                .iter()
                .any(|s| s == REPO_NAME_PREFIX || s.starts_with(&format!("{REPO_NAME_PREFIX}_")))
            && filter_claims_group(f, group, artifact)
    }) {
        return Some(refusal(
            "redirect_gradle_exclusive_content_conflict",
            format!(
                "{}:{} routes {group} to another repository with exclusiveContent; drop {ga} \
                 from it",
                f.rel, f.line
            ),
        ));
    }
    None
}

/// Why the hosted wiring of `row` no longer holds in the build `files`
/// holds, by the planner's own build- and GA-level refusals (see
/// [`ga_refusal`]): `(code, detail)`. Discovery's re-check of a pin made
/// before the build changed.
pub(crate) fn pinned_row_refusal(
    files: &BTreeMap<String, String>,
    graph: &ScriptGraph,
    row: &HostedRow,
) -> Option<(&'static str, String)> {
    let lock_paths = lockfile_paths(graph, files);
    project_refusal(files, graph, &Ok(Vec::new()))
        .or_else(|| {
            ga_refusal(
                files,
                graph,
                &lock_paths,
                &row.group,
                &row.artifact,
                &row.base,
            )
        })
        .map(|r| (r.code, r.detail))
}

/// Whether `version` orders above `base` (Gradle's ordering): a newer
/// upstream release the hosted script lets resolve.
fn above_base(version: &str, base: &str) -> bool {
    gradle_version_cmp(version, base) == std::cmp::Ordering::Greater
}

/// Whether selector `sel` may admit some version above `base` (unknown
/// selectors may).
fn may_admit_above(sel: &Selector, base: &str) -> bool {
    match sel {
        Selector::Exact(v) => above_base(v, base),
        Selector::Range { upper, .. } => {
            upper.as_ref().is_none_or(|b| above_base(&b.version, base))
        }
        Selector::Prefix(p) => {
            let p = p.trim_end_matches(['.', '-', '_']);
            p.is_empty() || above_base(p, base)
        }
        Selector::Latest(_) | Selector::Unknown => true,
    }
}

/// Whether the hosted planner would refuse `dep` in the build `files`
/// holds once its vendored Gradle wiring is reverted: every refusal of
/// [`rewrite_gradle_hosted`] except the vendored-index conflict, which the
/// takeover's revert clears. The vendored backend serves the original GAV
/// and leaves lock files alone, so the lock checks hold before the revert
/// too. A takeover runs this before reverting anything, so a refused purl
/// keeps its working vendored patch. `None` when there is no Gradle build.
pub fn takeover_refusal(
    files: &BTreeMap<String, String>,
    unreadable: &BTreeSet<String>,
    dep: &DepOverride,
) -> Option<RewriteWarning> {
    if !gradle_build_present(files) {
        return None;
    }
    let (group, artifact) = coords_of(dep);
    let warning = |r: Refusal| RewriteWarning {
        code: r.code.into(),
        detail: format!(
            "{}; the vendored patch of {group}:{artifact}:{} stays in place (NOT switched to \
             hosted)",
            r.detail, dep.version
        ),
    };
    if registry_override_of_kind(dep, "maven2").is_none() {
        return Some(warning(refusal(
            "redirect_gradle_override_invalid",
            "the hosted grant carries no maven2 repository",
        )));
    }
    let graph = graph_of(files);
    let lock_paths = lockfile_paths(&graph, files);
    let index = files
        .get(HOSTED_INDEX_REL)
        .map_or(Ok(Vec::new()), |t| parse_index(t));
    let project = unreadable_refusal(unreadable).or_else(|| project_refusal(files, &graph, &index));
    let rows = index.unwrap_or_default();
    plan_dep(
        dep,
        files,
        &graph,
        &lock_paths,
        &rows,
        &BTreeSet::new(),
        project.as_ref(),
    )
    .err()
    .map(warning)
}

/// `(groupId, artifactId)` of a maven dep.
fn coords_of(dep: &DepOverride) -> (String, String) {
    let ids = dep.registry_override.as_ref().map(|o| &o.identifiers);
    let group = ids
        .and_then(|i| i.maven_group_id.clone())
        .or_else(|| dep.namespace.clone())
        .unwrap_or_default();
    let artifact = ids
        .and_then(|i| i.maven_artifact_id.clone())
        .unwrap_or_else(|| dep.name.clone());
    (group, artifact)
}

/// The start tag the planner writes for a row's component.
pub(crate) fn component_tag(row: &HostedRow) -> String {
    format!(
        "<component group=\"{}\" name=\"{}\" version=\"{}\">",
        row.group, row.artifact, row.suffixed
    )
}

pub(crate) fn has_component(text: &str, row: &HostedRow) -> bool {
    text.contains(&component_tag(row))
}

/// `text` without the row's component, when it is still exactly what the
/// planner wrote: its artifacts are the suffixed jar, pom and (optionally)
/// module, each holding one socket-patch sha256 (the jar's and pom's the
/// row's own). The component's lines go with it.
pub(crate) fn without_component(text: &str, row: &HostedRow) -> Option<String> {
    let tag = component_tag(row);
    let start = text.find(&tag)?;
    let close = "</component>";
    let end = start + text[start..].find(close)? + close.len();
    let block = &text[start + tag.len()..end - close.len()];
    let (a, v) = (&row.artifact, &row.suffixed);
    let artifact_re = regex::Regex::new(
        r#"^\s*<artifact name="([^"]+)">\s*<sha256 value="([0-9a-f]{64})" origin="socket-patch"/>\s*</artifact>"#,
    )
    .expect("static artifact regex is valid");
    let mut rest = block;
    let mut names = Vec::new();
    while let Some(c) = artifact_re.captures(rest) {
        let (name, sha) = (c[1].to_string(), c[2].to_string());
        let want = if name == format!("{a}-{v}.jar") {
            Some(&row.jar_sha256)
        } else if name == format!("{a}-{v}.pom") {
            Some(&row.pom_sha256)
        } else if name == format!("{a}-{v}.module") {
            None
        } else {
            return None;
        };
        if want.is_some_and(|w| *w != sha) {
            return None;
        }
        names.push(name);
        rest = &rest[c.get(0).expect("whole match").end()..];
    }
    if !rest.trim().is_empty() || !names.iter().any(|n| n.ends_with(".jar")) {
        return None;
    }
    let line_start = text[..start].rfind('\n').map_or(0, |i| i + 1);
    let lead_blank = text[line_start..start].trim().is_empty();
    let after = &text[end..];
    let line_end = if after.starts_with("\r\n") {
        end + 2
    } else if after.starts_with('\n') {
        end + 1
    } else {
        end
    };
    let cut_start = if lead_blank { line_start } else { start };
    let cut_end = if lead_blank { line_end } else { end };
    Some(format!("{}{}", &text[..cut_start], &text[cut_end..]))
}

/// The verification component for an accepted row.
fn verification_edit(text: &str, a: &Accepted) -> Result<String, String> {
    let patch = crate::vendor::jvm::JvmPatch {
        group_id: &a.row.group,
        artifact_id: &a.row.artifact,
        version: &a.row.suffixed,
        uuid: &a.row.uuid,
        jar: &[],
        upstream_pom: &[],
        upstream_module: None,
        extra_artifacts: &[],
        patched_members: &[],
    };
    let hashes = vendored::ArtifactHashes {
        jar: a.row.jar_sha256.clone(),
        pom: a.row.pom_sha256.clone(),
        module: a.module_sha256.clone(),
    };
    let (start, end, to) = vendored::update_verification_component(text, &patch, &hashes, None)
        .map_err(|r| r.detail)?;
    let mut text = format!("{}{to}{}", &text[..start], &text[end..]);
    // The component may predate this run (a re-scan): its pom and module
    // entries are socket-patch's too, so each is set, not only the jar's.
    // A component first written while the service served no `.module`
    // gains the module entry once a grant carries its digest; without it
    // Gradle fails verification of the `.module` it then downloads.
    let extra = [
        ("pom", Some(&a.row.pom_sha256)),
        ("module", a.module_sha256.as_ref()),
    ];
    for (extension, sha) in extra {
        let Some(sha) = sha else { continue };
        let (start, end, to) = vendored::set_verification_artifact(&text, &patch, extension, sha)
            .map_err(|r| r.detail)?;
        text = format!("{}{to}{}", &text[..start], &text[end..]);
    }
    Ok(text)
}

/// Plan the hosted Gradle wiring for every maven dep (see the module docs).
/// Records every maven uuid in `gradle_uuids`, then in exactly one of
/// `confirmed_gradle_uuids` and `refused_gradle_uuids`.
pub(crate) fn rewrite_gradle_hosted(
    files: &BTreeMap<String, String>,
    unreadable: &BTreeSet<String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    if !gradle_build_present(files) {
        return;
    }
    let maven: Vec<&DepOverride> = overrides
        .iter()
        .filter(|o| o.ecosystem == "maven")
        .collect();
    if maven.is_empty() {
        return;
    }
    let graph = graph_of(files);
    let lock_paths = lockfile_paths(&graph, files);
    let index = files
        .get(HOSTED_INDEX_REL)
        .map_or(Ok(Vec::new()), |t| parse_index(t));
    // A file the graph reached that exists but could not be read is not
    // absent: a settings target "created" over it would replace the
    // user's settings file.
    let project = unreadable_refusal(unreadable).or_else(|| project_refusal(files, &graph, &index));
    let rows = index.unwrap_or_default();
    let vendored_gas = vendored_gas(files);
    let dsls = build_dsls(files);
    let any_lock = !lock_paths.is_empty();

    let mut verification = files.get(VERIFICATION_REL).cloned();
    let mut left_components: Vec<RewriteWarning> = Vec::new();
    let mut accepted: Vec<Accepted> = Vec::new();
    for dep in maven {
        result.gradle_uuids.insert(dep.patch_uuid.clone());
        if registry_override_of_kind(dep, "maven2").is_none() {
            // The pom planner warns `redirect_maven_missing_override`.
            result.refused_gradle_uuids.insert(dep.patch_uuid.clone());
            continue;
        }
        if accepted.iter().any(|a| a.row.uuid == dep.patch_uuid) {
            continue;
        }
        let planned = plan_dep(
            dep,
            files,
            &graph,
            &lock_paths,
            &rows,
            &vendored_gas,
            project.as_ref(),
        )
        .and_then(|a| {
            if accepted.iter().any(|b| b.row.ga() == a.row.ga()) {
                return Err(refusal(
                    "redirect_gradle_version_conflict",
                    format!("two hosted patches pin {} in one run", a.row.ga()),
                ));
            }
            if let Some(text) = &verification {
                match verification_edit(text, &a) {
                    Ok(next) => verification = Some(next),
                    Err(why) => {
                        return Err(refusal(
                            "redirect_gradle_verification_unparseable",
                            format!("{VERIFICATION_REL}: {why}"),
                        ))
                    }
                }
            }
            // A replaced patch's component goes with its row, when it is
            // still exactly what the planner wrote (the restore only ever
            // removes the current row's).
            if let (Some(text), Some(old)) = (
                &verification,
                a.replaces
                    .as_ref()
                    .and_then(|_| rows.iter().find(|r| r.ga() == a.row.ga())),
            ) {
                match without_component(text, old) {
                    Some(next) => verification = Some(next),
                    None if has_component(text, old) => left_components.push(RewriteWarning {
                        code: "redirect_gradle_verification_component_left".into(),
                        detail: format!(
                            "{VERIFICATION_REL} keeps the {}:{} component of the replaced \
                             patch, which was changed after socket-patch added it; remove it \
                             if nothing else needs it",
                            old.ga(),
                            old.suffixed
                        ),
                    }),
                    None => {}
                }
            }
            Ok(a)
        });
        match planned {
            Ok(a) => accepted.push(a),
            Err(r) => refuse(result, dep, &r, &dsls, any_lock),
        }
    }
    if accepted.is_empty() {
        return;
    }
    result.warnings.extend(left_components);

    // The index: earlier rows (other GAs) plus this run's.
    let mut new_rows: Vec<HostedRow> = rows
        .iter()
        .filter(|r| !accepted.iter().any(|a| a.row.ga() == r.ga()))
        .cloned()
        .collect();
    new_rows.extend(accepted.iter().map(|a| a.row.clone()));
    let index_text = render_index(&new_rows);
    let digest = index_digest(&index_text);
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let edit = |out: &mut BTreeMap<String, String>,
                result: &mut RewriteResult,
                rel: &str,
                kind: &str,
                key: Option<String>,
                text: String| {
        let action = if files.contains_key(rel) || out.contains_key(rel) {
            "rewritten"
        } else {
            "added"
        };
        out.insert(rel.to_string(), text);
        result.edits.push(FileEdit {
            path: rel.to_string(),
            kind: kind.to_string(),
            action: action.to_string(),
            key,
            original: None,
            new: None,
        });
    };
    if !files
        .get(HOSTED_INDEX_REL)
        .is_some_and(|t| eol_eq(t.as_bytes(), index_text.as_bytes()))
    {
        edit(
            &mut out,
            result,
            HOSTED_INDEX_REL,
            "redirect_gradle_hosted_index",
            None,
            index_text.clone(),
        );
    }
    if !files
        .get(HOSTED_SCRIPT_REL)
        .is_some_and(|t| eol_eq(t.as_bytes(), HOSTED_SCRIPT.as_bytes()))
    {
        edit(
            &mut out,
            result,
            HOSTED_SCRIPT_REL,
            "redirect_gradle_hosted_script",
            None,
            HOSTED_SCRIPT.to_string(),
        );
    }
    if !files.contains_key(GITATTRIBUTES_REL) {
        edit(
            &mut out,
            result,
            GITATTRIBUTES_REL,
            "redirect_gradle_gitattributes",
            None,
            GITATTRIBUTES.to_string(),
        );
    }
    let targets = settings_targets(&graph);
    for t in &targets {
        let text = files.get(&t.rel).cloned().unwrap_or_default();
        if let Some(next) = with_apply_line(&text, t.dsl, &t.prefix(), &digest, !t.exists) {
            edit(
                &mut out,
                result,
                &t.rel,
                "redirect_gradle_settings_apply",
                Some(digest.clone()),
                next,
            );
        }
    }
    for rel in &lock_paths {
        let Some(text) = files.get(rel) else { continue };
        let mut next = text.clone();
        for a in &accepted {
            let r = &a.row;
            let froms = std::iter::once(&r.base).chain(a.replaces.as_ref());
            for from in froms {
                if let Some(t) =
                    locks::rewrite_entry(&next, &r.group, &r.artifact, from, &r.suffixed)
                {
                    next = t;
                }
            }
        }
        if &next != text {
            edit(
                &mut out,
                result,
                rel,
                "redirect_gradle_lock_entry",
                None,
                next,
            );
        }
    }
    if let Some(next) = verification.filter(|v| Some(v) != files.get(VERIFICATION_REL)) {
        edit(
            &mut out,
            result,
            VERIFICATION_REL,
            "redirect_gradle_verification_component",
            None,
            next,
        );
    }

    // Confirm what the final files pin.
    let final_text = |rel: &str| out.get(rel).or_else(|| files.get(rel));
    let script_ok = final_text(HOSTED_SCRIPT_REL)
        .is_some_and(|t| eol_eq(t.as_bytes(), HOSTED_SCRIPT.as_bytes()));
    let final_rows = final_text(HOSTED_INDEX_REL)
        .and_then(|t| parse_index(t).ok())
        .unwrap_or_default();
    let applied = targets.iter().all(|t| {
        final_text(&t.rel).is_some_and(|text| {
            let created = apply_line_created(text, t.dsl, &t.prefix());
            apply_line_span(text, t.dsl, &t.prefix()).is_some_and(|(s, e)| {
                text[s..e] == apply_line(t.dsl, &t.prefix(), &digest, created)
            })
        })
    });
    for a in &accepted {
        let r = &a.row;
        // Every lock entry pins the suffixed version, or a release above
        // the base the script lets resolve (VEX withholds while one does).
        let locked = lock_paths.iter().all(|rel| {
            final_text(rel).is_none_or(|t| {
                locks::parse(t)
                    .entries_of(&r.group, &r.artifact)
                    .all(|e| e.version == r.suffixed || above_base(&e.version, &r.base))
            })
        });
        if script_ok && applied && locked && final_rows.contains(r) {
            result.confirmed_gradle_uuids.insert(r.uuid.clone());
        } else {
            result.refused_gradle_uuids.insert(r.uuid.clone());
        }
        let dynamic: Vec<String> = graph
            .declarations_of(&r.group, &r.artifact)
            .iter()
            .flat_map(|d| {
                let rich = d.rich.as_ref();
                [
                    d.version.as_deref(),
                    rich.and_then(|v| v.strictly.as_deref()),
                    rich.and_then(|v| v.require.as_deref()),
                    rich.and_then(|v| v.prefer.as_deref()),
                ]
                .into_iter()
                .flatten()
                .filter(|sel| {
                    let parsed = parse_selector(sel);
                    // `latest.*` is refused (`redirect_gradle_latest_selector`):
                    // the pin never rewrites it.
                    matches!(parsed, Selector::Range { .. } | Selector::Prefix(_))
                        && admits(&parsed, &r.base) == Some(true)
                })
                .map(|sel| format!("{}:{} `{sel}`", d.rel, d.line))
                .collect::<Vec<_>>()
            })
            .collect();
        if let Some(first) = dynamic.first() {
            result.warnings.push(RewriteWarning {
                code: "redirect_gradle_dynamic_selector_pinned".into(),
                detail: format!(
                    "{first}{} requests {} with a dynamic version; the hosted pin resolves the \
                     patched {} for every selector that admits {}, so a newer upstream release \
                     the selector also admits is not picked up while the patch is in place. \
                     Declare the newer version explicitly (it resolves above the patch) or roll \
                     the patch back once upstream fixes it",
                    match dynamic.len() {
                        1 => String::new(),
                        n => format!(" (and {} more)", n - 1),
                    },
                    r.ga(),
                    r.suffixed,
                    r.base
                ),
            });
        }
        if a.module_sha256.is_none() {
            result.warnings.push(RewriteWarning {
                code: "redirect_gradle_module_metadata_unavailable".into(),
                detail: format!(
                    "the Socket repository serves no Gradle module metadata (`.module`) for \
                     {}:{}; if the upstream release publishes one, Gradle resolves the pom \
                     instead, so variants and capabilities it declares are not applied",
                    r.ga(),
                    r.suffixed
                ),
            });
        }
    }
    result.warnings.push(RewriteWarning {
        code: "redirect_gradle_detached_configs_unguarded".into(),
        detail: "the hosted Gradle pin covers every project and buildscript configuration; \
                 detached configurations (created by plugins with \
                 `configurations.detachedConfiguration`) are not reached and may resolve the \
                 upstream version"
            .into(),
    });
    let unscanned: Vec<String> = graph
        .unresolved
        .iter()
        .filter(|u| u.site != Site::IncludeBuild && !u.rel.starts_with(".socket/"))
        .map(|u| {
            if u.snippet.is_empty() {
                format!("{}: {:?}", u.rel, u.reason)
            } else {
                format!("{}:{}: {}", u.rel, u.line, u.snippet)
            }
        })
        .collect();
    if let Some(first) = unscanned.first() {
        result.warnings.push(RewriteWarning {
            code: "redirect_gradle_unscanned_build_logic".into(),
            detail: format!(
                "{first}{} could not be followed; a declaration, lock or repository there is \
                 unchecked",
                match unscanned.len() {
                    1 => String::new(),
                    n => format!(" (and {} more)", n - 1),
                }
            ),
        });
    }
    result.files.extend(out);
}

/// Record a refusal: its code, then the fallback snippet.
fn refuse(
    result: &mut RewriteResult,
    dep: &DepOverride,
    r: &Refusal,
    dsls: &[Dsl],
    any_lock: bool,
) {
    result.refused_gradle_uuids.insert(dep.patch_uuid.clone());
    let (group, artifact) = coords_of(dep);
    result.warnings.push(RewriteWarning {
        code: r.code.into(),
        detail: format!(
            "{}; nothing was written for {group}:{artifact}:{} (see \
             redirect_gradle_manual_snippet)",
            r.detail, dep.version
        ),
    });
    let Some(ov) = registry_override_of_kind(dep, "maven2") else {
        return;
    };
    let suffixed = ov.identifiers.maven_suffixed_version.as_deref();
    result.warnings.push(RewriteWarning {
        code: "redirect_gradle_manual_snippet".into(),
        detail: fallback_snippet(
            dsls,
            &ov.index_url,
            &group,
            &artifact,
            &dep.version,
            suffixed,
            &dep.patch_uuid,
            any_lock,
        ),
    });
}

/// The paste-able fallback for a refused dep, in each DSL the build uses
/// (labelled when there are two). With a suffixed version it follows the
/// owned script's rules: it routes only that version to the Socket
/// repository, rewrites every request whose selector admits the base to
/// it (dependency substitution on the strictly / require / prefer
/// constraint, so a `prefer`-only rich version is covered, plus
/// `eachDependency`), and rejects every other candidate at or below the
/// base, so a
/// version above the base (a newer upstream fix) still resolves. It adds
/// no dependency of its own, so it pastes into any project. For a same-GAV
/// grant it can only route the base version (not fail-closed).
#[allow(clippy::too_many_arguments)]
pub fn fallback_snippet(
    dsls: &[Dsl],
    index_url: &str,
    group: &str,
    artifact: &str,
    base: &str,
    suffixed: Option<&str>,
    uuid: &str,
    locks: bool,
) -> String {
    let mut out = String::from(
        "Gradle build: socket-patch did not wire this patch; add the following to the build \
         script of every project that resolves it",
    );
    match suffixed {
        Some(_) => out.push_str(
            " (it moves every request of the patched version to the patched build and fails \
             the build on any other version at or below it)",
        ),
        None => out.push_str(
            " (served at the original version, so a Socket-repository failure falls back to \
             the unpatched artifact)",
        ),
    }
    out.push(':');
    for dsl in dsls {
        if dsls.len() > 1 {
            out.push_str(match dsl {
                Dsl::Groovy => "\n// build.gradle (Groovy DSL):",
                Dsl::Kotlin => "\n// build.gradle.kts (Kotlin DSL):",
            });
        }
        out.push('\n');
        out.push_str(&snippet(
            *dsl, index_url, group, artifact, base, suffixed, uuid,
        ));
    }
    if locks && suffixed.is_some() {
        out.push_str(
            "\nThen re-lock the build (`./gradlew dependencies --write-locks`) so the lock files \
             name the patched version.",
        );
    }
    out
}

/// The package of Gradle's own version parser, comparator and selector
/// scheme (internal, stable from 6.9 through 9.x: the hosted suite's golden
/// check runs them), which the fallback snippet orders and matches with so
/// it pins exactly what the owned script pins.
const STRATEGY: &str = "org.gradle.api.internal.artifacts.ivyservice.ivyresolve.strategy";

fn snippet(
    dsl: Dsl,
    url: &str,
    g: &str,
    a: &str,
    base: &str,
    suffixed: Option<&str>,
    uuid: &str,
) -> String {
    let routed = suffixed.unwrap_or(base);
    match (dsl, suffixed) {
        (Dsl::Groovy, None) => format!(
            "repositories {{\n    exclusiveContent {{\n        forRepository {{ maven {{ url '{url}' }} }}\n        filter {{ includeVersion('{g}', '{a}', '{routed}') }}\n    }}\n}}"
        ),
        (Dsl::Kotlin, None) => format!(
            "repositories {{\n    exclusiveContent {{\n        forRepository {{ maven {{ url = uri(\"{url}\") }} }}\n        filter {{ includeVersion(\"{g}\", \"{a}\", \"{routed}\") }}\n    }}\n}}"
        ),
        (Dsl::Groovy, Some(s)) => format!(
            "repositories {{\n    exclusiveContent {{\n        forRepository {{ maven {{ url '{url}' }} }}\n        filter {{ includeVersion('{g}', '{a}', '{s}') }}\n    }}\n}}\n\
             configurations.configureEach {{\n    resolutionStrategy.dependencySubstitution.all {{ DependencySubstitution ds ->\n        def r = ds.requested\n        if (r instanceof org.gradle.api.artifacts.component.ModuleComponentSelector && r.group == '{g}' && r.module == '{a}') {{\n            def vc = r.versionConstraint\n            def sel = [vc.strictVersion, vc.requiredVersion, vc.preferredVersion].find {{ it }}\n            if (sel && sel != '{s}') {{\n                def p = new {STRATEGY}.VersionParser()\n                def vs = new {STRATEGY}.DefaultVersionSelectorScheme(new {STRATEGY}.DefaultVersionComparator(), p).parseSelector(sel)\n                if (!vs.requiresMetadata() && vs.accept('{base}')) {{\n                    ds.useTarget('{g}:{a}:{s}', 'socket-patch hosted patch {uuid}')\n                }}\n            }}\n        }}\n    }}\n    resolutionStrategy.eachDependency {{ DependencyResolveDetails d ->\n        def sel = d.requested.version\n        if (d.requested.group == '{g}' && d.requested.name == '{a}' && sel && sel != '{s}') {{\n            def p = new {STRATEGY}.VersionParser()\n            def vs = new {STRATEGY}.DefaultVersionSelectorScheme(new {STRATEGY}.DefaultVersionComparator(), p).parseSelector(sel)\n            if (!vs.requiresMetadata() && vs.accept('{base}')) {{\n                d.useVersion('{s}')\n                d.because('socket-patch hosted patch {uuid}')\n            }}\n        }}\n    }}\n    resolutionStrategy.componentSelection.all {{ ComponentSelection selection ->\n        def c = selection.candidate\n        def p = new {STRATEGY}.VersionParser()\n        def order = new {STRATEGY}.DefaultVersionComparator().asVersionComparator()\n        if (c.group == '{g}' && c.module == '{a}' && c.version != '{s}' && order.compare(p.transform(c.version), p.transform('{base}')) <= 0) {{\n            selection.reject('socket-patch: only {s} (hosted patch {uuid}) may resolve at or below {base}')\n        }}\n    }}\n}}"
        ),
        (Dsl::Kotlin, Some(s)) => format!(
            "repositories {{\n    exclusiveContent {{\n        forRepository {{ maven {{ url = uri(\"{url}\") }} }}\n        filter {{ includeVersion(\"{g}\", \"{a}\", \"{s}\") }}\n    }}\n}}\n\
             configurations.configureEach {{\n    resolutionStrategy.dependencySubstitution.all {{\n        val r = requested\n        if (r is org.gradle.api.artifacts.component.ModuleComponentSelector && r.group == \"{g}\" && r.module == \"{a}\") {{\n            val vc = r.versionConstraint\n            val sel = listOf(vc.strictVersion, vc.requiredVersion, vc.preferredVersion).firstOrNull {{ !it.isNullOrEmpty() }}\n            if (sel != null && sel != \"{s}\") {{\n                val vs = {STRATEGY}.DefaultVersionSelectorScheme({STRATEGY}.DefaultVersionComparator(), {STRATEGY}.VersionParser()).parseSelector(sel)\n                if (!vs.requiresMetadata() && vs.accept(\"{base}\")) {{\n                    useTarget(\"{g}:{a}:{s}\", \"socket-patch hosted patch {uuid}\")\n                }}\n            }}\n        }}\n    }}\n    resolutionStrategy.eachDependency {{\n        val sel = requested.version\n        if (requested.group == \"{g}\" && requested.name == \"{a}\" && !sel.isNullOrEmpty() && sel != \"{s}\") {{\n            val p = {STRATEGY}.VersionParser()\n            val vs = {STRATEGY}.DefaultVersionSelectorScheme({STRATEGY}.DefaultVersionComparator(), p).parseSelector(sel)\n            if (!vs.requiresMetadata() && vs.accept(\"{base}\")) {{\n                useVersion(\"{s}\")\n                because(\"socket-patch hosted patch {uuid}\")\n            }}\n        }}\n    }}\n    resolutionStrategy.componentSelection.all {{\n        val p = {STRATEGY}.VersionParser()\n        val order = {STRATEGY}.DefaultVersionComparator().asVersionComparator()\n        if (candidate.group == \"{g}\" && candidate.module == \"{a}\" && candidate.version != \"{s}\" && order.compare(p.transform(candidate.version), p.transform(\"{base}\")) <= 0) {{\n            reject(\"socket-patch: only {s} (hosted patch {uuid}) may resolve at or below {base}\")\n        }}\n    }}\n}}"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        rewrite_registry_redirect, Integrity, RegistryOverride, RegistryOverrideIdentifiers,
    };
    use super::*;

    const UUID: &str = "4d5e6f70-8192-4a3b-9c4d-5e6f708192a3";
    const UUID2: &str = "0abcdef1-2345-4678-9abc-def012345678";
    const TOKEN: &str = "22222222-3333-4444-8555-666666666666";
    const G: &str = "com.socketfixture";
    const A: &str = "victim";
    const BASE: &str = "1.10.0";
    const SFX: &str = "1.10.0-socket.4d5e6f70";

    fn url(uuid: &str) -> String {
        format!("https://patch.socket.dev/patch-registry/maven/{TOKEN}/{uuid}/maven2")
    }

    fn dep_for(uuid: &str, artifact: &str, base: &str) -> DepOverride {
        DepOverride {
            ecosystem: "maven".into(),
            name: artifact.into(),
            namespace: Some(G.into()),
            version: base.into(),
            token: TOKEN.into(),
            patch_uuid: uuid.into(),
            artifact_url: format!("https://patch.socket.dev/patch/maven/{G}/{artifact}/{base}/{TOKEN}/{uuid}/{artifact}.jar"),
            registry_override: Some(RegistryOverride {
                kind: "maven2".into(),
                index_url: url(uuid),
                identifiers: RegistryOverrideIdentifiers {
                    name: format!("{G}/{artifact}"),
                    version: base.into(),
                    maven_group_id: Some(G.into()),
                    maven_artifact_id: Some(artifact.into()),
                    maven_suffixed_version: Some(suffixed_version(base, uuid)),
                    maven_pom_sha256: Some("b".repeat(64)),
                    maven_module_sha256: Some("d".repeat(64)),
                    ..Default::default()
                },
            }),
            integrity: Integrity {
                sha256: Some("a".repeat(64)),
                ..Default::default()
            },
        }
    }

    fn dep() -> DepOverride {
        dep_for(UUID, A, BASE)
    }

    fn files(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn codes(r: &RewriteResult) -> Vec<&str> {
        r.warnings.iter().map(|w| w.code.as_str()).collect()
    }

    /// `files` with the rewrite's output written over it.
    fn applied(mut f: BTreeMap<String, String>, r: &RewriteResult) -> BTreeMap<String, String> {
        f.extend(r.files.clone());
        f
    }

    fn row_line(uuid: &str, artifact: &str, base: &str) -> String {
        format!(
            "{G}:{artifact}:{base}\t{}\t{}\t{}\t{}\t{uuid}",
            suffixed_version(base, uuid),
            url(uuid),
            "a".repeat(64),
            "b".repeat(64)
        )
    }

    fn index_with(rows: &[String]) -> String {
        let mut out = format!("{HOSTED_INDEX_HEADER}\n");
        for r in rows {
            out.push_str(r);
            out.push('\n');
        }
        out
    }

    /// The golden edit set of a plain Groovy build: the index row, the
    /// owned script and `.gitattributes`, the apply line with the index
    /// digest, and the lock entry moved to the suffixed version.
    #[test]
    fn groovy_build_golden_edit_set_and_idempotent_rerun() {
        let input = files(&[
            ("settings.gradle", "rootProject.name = 'app'\n"),
            ("build.gradle", "dependencies { implementation 'com.socketfixture:victim:1.10.0' }\n"),
            (
                "gradle.lockfile",
                "# lock\ncom.socketfixture:victim:1.10.0=compileClasspath,runtimeClasspath\nempty=\n",
            ),
        ]);
        let r = rewrite_registry_redirect(&input, &[dep()]);
        let index = index_with(&[row_line(UUID, A, BASE)]);
        let digest = index_digest(&index);
        assert_eq!(r.files.get(HOSTED_INDEX_REL), Some(&index));
        assert_eq!(
            r.files.get(HOSTED_SCRIPT_REL).map(String::as_str),
            Some(HOSTED_SCRIPT)
        );
        assert_eq!(
            r.files.get(GITATTRIBUTES_REL).map(String::as_str),
            Some("* -text\n")
        );
        assert_eq!(
            r.files["settings.gradle"],
            format!(
                "rootProject.name = 'app'\napply from: '.socket/gradle/socket-patch.hosted.settings.gradle' // socket-patch-hosted {digest}\n"
            )
        );
        assert_eq!(
            r.files["gradle.lockfile"],
            format!("# lock\ncom.socketfixture:victim:{SFX}=compileClasspath,runtimeClasspath\nempty=\n")
        );
        assert!(r.confirmed_gradle_uuids.contains(UUID));
        assert!(r.refused_gradle_uuids.is_empty());
        assert_eq!(
            codes(&r),
            vec!["redirect_gradle_detached_configs_unguarded"],
            "{:?}",
            r.warnings
        );
        // The build script is never edited.
        assert!(!r.files.contains_key("build.gradle"));

        let again = rewrite_registry_redirect(&applied(input, &r), &[dep()]);
        assert!(again.files.is_empty(), "{:?}", again.files.keys());
        assert!(again.edits.is_empty());
        assert!(again.confirmed_gradle_uuids.contains(UUID));
    }

    #[test]
    fn kotlin_apply_line_and_digest_follows_the_index() {
        let input = files(&[
            ("settings.gradle.kts", "rootProject.name = \"app\"\n"),
            (
                "build.gradle.kts",
                "dependencies { implementation(\"com.socketfixture:victim:1.10.0\") }\n",
            ),
        ]);
        let one = rewrite_registry_redirect(&input, &[dep()]);
        let d1 = index_digest(&one.files[HOSTED_INDEX_REL]);
        assert_eq!(
            one.files["settings.gradle.kts"],
            format!(
                "rootProject.name = \"app\"\napply(from = \".socket/gradle/socket-patch.hosted.settings.gradle\") // socket-patch-hosted {d1}\n"
            )
        );
        // A second row changes the digest, which is rewritten in place.
        let after = applied(input, &one);
        let two = rewrite_registry_redirect(&after, &[dep_for(UUID2, "other", "2.0")]);
        let d2 = index_digest(&two.files[HOSTED_INDEX_REL]);
        assert_ne!(d1, d2);
        assert_eq!(
            two.files["settings.gradle.kts"],
            format!(
                "rootProject.name = \"app\"\napply(from = \".socket/gradle/socket-patch.hosted.settings.gradle\") // socket-patch-hosted {d2}\n"
            )
        );
        let rows = parse_index(&two.files[HOSTED_INDEX_REL]).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].artifact, "other", "sorted by GA");
        assert!(two.confirmed_gradle_uuids.contains(UUID2));
        assert!(
            !two.files.contains_key(HOSTED_SCRIPT_REL),
            "script already final"
        );
    }

    /// CRLF settings and lock files keep their line endings; the apply
    /// line is removed again byte-exactly.
    #[test]
    fn crlf_files_keep_their_line_endings() {
        let settings = "\u{feff}rootProject.name = 'app'\r\ninclude 'lib'\r\n";
        let lock = "com.socketfixture:victim:1.10.0=runtimeClasspath\r\nempty=\r\n";
        let input = files(&[
            ("settings.gradle", settings),
            ("build.gradle", ""),
            (
                "lib/build.gradle",
                "dependencies { implementation 'com.socketfixture:victim:1.10.0' }\r\n",
            ),
            ("lib/gradle.lockfile", lock),
        ]);
        let r = rewrite_registry_redirect(&input, &[dep()]);
        let digest = index_digest(&r.files[HOSTED_INDEX_REL]);
        let wired = &r.files["settings.gradle"];
        assert_eq!(
            *wired,
            format!("{settings}apply from: '.socket/gradle/socket-patch.hosted.settings.gradle' // socket-patch-hosted {digest}\r\n")
        );
        assert_eq!(
            r.files["lib/gradle.lockfile"],
            format!("com.socketfixture:victim:{SFX}=runtimeClasspath\r\nempty=\r\n")
        );
        assert_eq!(
            apply_line_digest(wired, Dsl::Groovy, "").as_deref(),
            Some(digest.as_str())
        );
        assert_eq!(
            without_apply_line(wired, Dsl::Groovy, "").as_deref(),
            Some(settings)
        );
        // Kotlin, with the apply line first after a BOM.
        let kts = "\u{feff}apply(from = \".socket/gradle/socket-patch.hosted.settings.gradle\") // socket-patch-hosted 0123\r\nrootProject.name = \"x\"\r\n";
        assert_eq!(
            without_apply_line(kts, Dsl::Kotlin, "").as_deref(),
            Some("\u{feff}rootProject.name = \"x\"\r\n")
        );
        assert_eq!(
            with_apply_line(kts, Dsl::Kotlin, "", "4567", true).as_deref(),
            Some("\u{feff}apply(from = \".socket/gradle/socket-patch.hosted.settings.gradle\") // socket-patch-hosted 4567\r\nrootProject.name = \"x\"\r\n")
        );
    }

    /// buildSrc and a literal included build get their own apply line (one
    /// level up), and every build's locks move — legacy and buildscript
    /// locks included.
    #[test]
    fn build_src_included_builds_and_every_lock() {
        let input = files(&[
            (
                "settings.gradle",
                "includeBuild 'build-logic'\ninclude 'app'\n",
            ),
            ("build.gradle", ""),
            (
                "app/build.gradle",
                "dependencies { implementation 'com.socketfixture:victim:1.10.0' }\n",
            ),
            (
                "app/gradle.lockfile",
                "com.socketfixture:victim:1.10.0=runtimeClasspath\nempty=\n",
            ),
            (
                "buildscript-gradle.lockfile",
                "com.socketfixture:victim:1.10.0=classpath\nempty=\n",
            ),
            (
                "app/gradle/dependency-locks/compileClasspath.lockfile",
                "com.socketfixture:victim:1.10.0\n",
            ),
            ("buildSrc/build.gradle.kts", "plugins { `kotlin-dsl` }\n"),
            (
                "buildSrc/gradle.lockfile",
                "com.socketfixture:victim:1.10.0=runtimeClasspath\nempty=\n",
            ),
            (
                "build-logic/settings.gradle.kts",
                "rootProject.name = \"build-logic\"\n",
            ),
            ("build-logic/build.gradle.kts", ""),
            (
                "build-logic/gradle.lockfile",
                "com.socketfixture:victim:1.10.0=runtimeClasspath\nempty=\n",
            ),
        ]);
        let r = rewrite_registry_redirect(&input, &[dep()]);
        let digest = index_digest(&r.files[HOSTED_INDEX_REL]);
        assert!(r.files["settings.gradle"].ends_with(&format!(
            "apply from: '.socket/gradle/socket-patch.hosted.settings.gradle' // socket-patch-hosted {digest}\n"
        )));
        assert_eq!(
            r.files["buildSrc/settings.gradle.kts"],
            format!("apply(from = \"../.socket/gradle/socket-patch.hosted.settings.gradle\") // socket-patch-hosted {digest} created\n"),
            "created in the build script's DSL, and marked so"
        );
        assert!(
            !r.files["build-logic/settings.gradle.kts"].contains(" created"),
            "an existing file is not marked"
        );
        // A second row rewrites the digest and keeps the mark.
        let two = rewrite_registry_redirect(
            &applied(input, &r),
            &[dep(), dep_for(UUID2, "other", "2.0")],
        );
        let d2 = index_digest(&two.files[HOSTED_INDEX_REL]);
        assert_eq!(
            two.files["buildSrc/settings.gradle.kts"],
            format!("apply(from = \"../.socket/gradle/socket-patch.hosted.settings.gradle\") // socket-patch-hosted {d2} created\n"),
        );
        assert!(two.confirmed_gradle_uuids.contains(UUID2));
        assert!(r.files["build-logic/settings.gradle.kts"].contains(&format!(
            "apply(from = \"../.socket/gradle/socket-patch.hosted.settings.gradle\") // socket-patch-hosted {digest}"
        )));
        for lock in [
            "app/gradle.lockfile",
            "buildscript-gradle.lockfile",
            "app/gradle/dependency-locks/compileClasspath.lockfile",
            "buildSrc/gradle.lockfile",
            "build-logic/gradle.lockfile",
        ] {
            assert!(r.files[lock].contains(SFX), "{lock}: {}", r.files[lock]);
            assert!(
                !r.files[lock].contains(&format!("victim:{BASE}=")),
                "{lock}"
            );
        }
        assert!(r.confirmed_gradle_uuids.contains(UUID));
    }

    /// An existing verification file gets the suffixed component (with the
    /// module hash); none is ever created.
    #[test]
    fn verification_component_is_added_never_created() {
        let vm = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<verification-metadata>\n   <configuration>\n      <verify-metadata>true</verify-metadata>\n   </configuration>\n   <components/>\n</verification-metadata>\n";
        let input = files(&[
            ("settings.gradle", ""),
            ("gradle/verification-metadata.xml", vm),
        ]);
        let r = rewrite_registry_redirect(&input, &[dep()]);
        let out = &r.files["gradle/verification-metadata.xml"];
        assert!(out.contains(&format!(
            "<component group=\"{G}\" name=\"{A}\" version=\"{SFX}\">"
        )));
        assert!(out.contains(&format!("<artifact name=\"{A}-{SFX}.jar\">")));
        assert!(out.contains(&format!(
            "<sha256 value=\"{}\" origin=\"socket-patch\"/>",
            "a".repeat(64)
        )));
        assert!(out.contains(&format!("<artifact name=\"{A}-{SFX}.module\">")));
        assert!(out.contains(&format!("<artifact name=\"{A}-{SFX}.pom\">")));
        let r = rewrite_registry_redirect(&files(&[("settings.gradle", "")]), &[dep()]);
        assert!(!r.files.contains_key("gradle/verification-metadata.xml"));
    }

    /// #646 review: a component written while the service served no
    /// `.module` (jar and pom only) gains the module entry on the rescan
    /// whose grant carries `mavenModuleSha256`; the rerun after that is a
    /// no-op.
    #[test]
    fn a_rescan_adds_the_module_entry_to_an_existing_component() {
        let vm = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<verification-metadata>\n   <components/>\n</verification-metadata>\n";
        let input = files(&[
            ("settings.gradle", ""),
            ("gradle/verification-metadata.xml", vm),
        ]);
        let mut no_module = dep();
        no_module
            .registry_override
            .as_mut()
            .unwrap()
            .identifiers
            .maven_module_sha256 = None;
        let first = rewrite_registry_redirect(&input, &[no_module]);
        let first_vm = &first.files["gradle/verification-metadata.xml"];
        assert!(!first_vm.contains(".module"), "{first_vm}");
        let after = applied(input, &first);
        let second = rewrite_registry_redirect(&after, &[dep()]);
        let out = &second.files["gradle/verification-metadata.xml"];
        let module = format!(
            "<artifact name=\"{A}-{SFX}.module\">\n            <sha256 value=\"{}\" origin=\"socket-patch\"/>",
            "d".repeat(64)
        );
        assert!(out.contains(&module), "{out}");
        assert_eq!(out.matches("<component ").count(), 1, "{out}");
        // Name order, as Gradle writes them: jar, module, pom.
        let (jar, module, pom) = (
            out.find(&format!("{A}-{SFX}.jar")).unwrap(),
            out.find(&format!("{A}-{SFX}.module")).unwrap(),
            out.find(&format!("{A}-{SFX}.pom")).unwrap(),
        );
        assert!(jar < module && module < pom, "{out}");
        let again = rewrite_registry_redirect(&applied(after, &second), &[dep()]);
        assert!(
            !again.files.contains_key("gradle/verification-metadata.xml"),
            "idempotent"
        );
    }

    /// #646 review: a new patch of the same GAV drops the replaced
    /// patch's component (still as the planner wrote it), so a later
    /// restore leaves nothing of either behind.
    #[test]
    fn a_replaced_patch_drops_its_verification_component() {
        let vm = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<verification-metadata>\n   <components/>\n</verification-metadata>\n";
        let input = files(&[
            ("settings.gradle", ""),
            ("gradle/verification-metadata.xml", vm),
        ]);
        let first = rewrite_registry_redirect(&input, &[dep_for(UUID2, A, BASE)]);
        let old_sfx = suffixed_version(BASE, UUID2);
        assert!(first.files["gradle/verification-metadata.xml"].contains(&old_sfx));
        let after = applied(input, &first);
        let second = rewrite_registry_redirect(&after, &[dep()]);
        assert!(second.confirmed_gradle_uuids.contains(UUID));
        let out = &second.files["gradle/verification-metadata.xml"];
        assert!(!out.contains(&old_sfx), "{out}");
        assert!(out.contains(&format!("version=\"{SFX}\"")), "{out}");
        // Edited by hand: kept, and reported.
        let edited = files(&[
            ("settings.gradle", ""),
            (
                "gradle/verification-metadata.xml",
                &first.files["gradle/verification-metadata.xml"]
                    .replace("</component>", "   <!-- mine -->\n      </component>"),
            ),
            (HOSTED_INDEX_REL, &first.files[HOSTED_INDEX_REL]),
        ]);
        let r = rewrite_registry_redirect(&edited, &[dep()]);
        assert!(r.files["gradle/verification-metadata.xml"].contains(&old_sfx));
        assert!(codes(&r).contains(&"redirect_gradle_verification_component_left"));
    }

    /// #646 review (decision 3): a lock or `strictly` ABOVE the base is a
    /// newer upstream fix the script lets resolve, not a conflict: the GA
    /// is still pinned where the base resolves.
    #[test]
    fn locks_and_strict_versions_above_the_base_are_not_conflicts() {
        let input = files(&[
            ("settings.gradle", "include 'a', 'b'\n"),
            (
                "a/build.gradle",
                "dependencies { implementation 'com.socketfixture:victim:1.10.0' }\n",
            ),
            (
                "b/build.gradle",
                "dependencies { implementation('com.socketfixture:victim') { version { strictly '1.11.0' } } }\n",
            ),
            (
                "a/gradle.lockfile",
                "com.socketfixture:victim:1.10.0=runtimeClasspath\nempty=\n",
            ),
            (
                "b/gradle.lockfile",
                "com.socketfixture:victim:1.11.0=runtimeClasspath\nempty=\n",
            ),
        ]);
        let r = rewrite_registry_redirect(&input, &[dep()]);
        assert!(r.confirmed_gradle_uuids.contains(UUID), "{:?}", r.warnings);
        assert_eq!(
            r.files["a/gradle.lockfile"],
            format!("com.socketfixture:victim:{SFX}=runtimeClasspath\nempty=\n")
        );
        assert!(!r.files.contains_key("b/gradle.lockfile"));
        // A strictly that admits only versions below the base still refuses.
        assert_refused(
            &[
                ("settings.gradle", ""),
                (
                    "build.gradle",
                    "dependencies { implementation('com.socketfixture:victim') { version { strictly '1.9.0' } } }\n",
                ),
            ],
            dep(),
            "redirect_gradle_range_declared",
        );
    }

    /// A dynamic selector admitting the base is pinned like a lock; the
    /// planner says so.
    #[test]
    fn a_dynamic_selector_is_reported_pinned() {
        let input = files(&[
            ("settings.gradle", ""),
            (
                "build.gradle",
                "dependencies { implementation 'com.socketfixture:victim:[1.9,)' }\n",
            ),
        ]);
        let r = rewrite_registry_redirect(&input, &[dep()]);
        assert!(r.confirmed_gradle_uuids.contains(UUID));
        let w = r
            .warnings
            .iter()
            .find(|w| w.code == "redirect_gradle_dynamic_selector_pinned")
            .unwrap_or_else(|| panic!("{:?}", r.warnings));
        assert!(w.detail.contains("build.gradle:1 `[1.9,)`"), "{}", w.detail);
        let exact = files(&[
            ("settings.gradle", ""),
            (
                "build.gradle",
                "dependencies { implementation 'com.socketfixture:victim:1.10.0' }\n",
            ),
        ]);
        let r = rewrite_registry_redirect(&exact, &[dep()]);
        assert!(!codes(&r).contains(&"redirect_gradle_dynamic_selector_pinned"));
    }

    /// #646 review: `latest.release` / `latest.integration` is refused, not
    /// reported pinned: the script cannot rewrite it, and with every
    /// upstream candidate at or below the base rejected the build fails
    /// until upstream ships a newer release (verified on real Gradle).
    #[test]
    fn a_latest_selector_is_refused_not_reported_pinned() {
        for decl in [
            "implementation 'com.socketfixture:victim:latest.release'",
            "implementation 'com.socketfixture:victim:latest.integration'",
            "implementation('com.socketfixture:victim') { version { prefer 'latest.release' } }",
        ] {
            let r = assert_refused(
                &[
                    ("settings.gradle", ""),
                    ("build.gradle", &format!("dependencies {{ {decl} }}\n")),
                ],
                dep(),
                "redirect_gradle_latest_selector",
            );
            assert!(
                !codes(&r).contains(&"redirect_gradle_dynamic_selector_pinned"),
                "{decl}: {:?}",
                r.warnings
            );
        }
    }

    /// #646 review: the fallback snippet substitutes on the version
    /// constraint (strictly, then require, then prefer) like the owned
    /// script, so a `prefer`-only rich version, whose requested.version is
    /// empty, is rewritten too. Real Gradle runs it in
    /// `gradle_hosted_fallback_snippet_compiles_*`.
    #[test]
    fn the_fallback_snippet_substitutes_on_the_version_constraint() {
        for dsl in [Dsl::Groovy, Dsl::Kotlin] {
            let text = snippet(dsl, "https://x", G, A, "1.10.0", Some(SFX), UUID);
            assert!(
                text.contains("dependencySubstitution.all")
                    && text.contains("vc.strictVersion, vc.requiredVersion, vc.preferredVersion")
                    && text.contains("useTarget(")
                    && text.contains("eachDependency"),
                "{dsl:?}: {text}"
            );
        }
    }

    fn assert_refused(input: &[(&str, &str)], dep: DepOverride, code: &str) -> RewriteResult {
        let r = rewrite_registry_redirect(&files(input), std::slice::from_ref(&dep));
        assert!(
            r.files.is_empty() && r.edits.is_empty(),
            "{code}: nothing written: {:?}",
            r.files.keys()
        );
        assert!(r.refused_gradle_uuids.contains(&dep.patch_uuid), "{code}");
        assert!(
            !r.confirmed_gradle_uuids.contains(&dep.patch_uuid),
            "{code}"
        );
        assert_eq!(
            codes(&r),
            vec![code, "redirect_gradle_manual_snippet"],
            "{:?}",
            r.warnings
        );
        r
    }

    #[test]
    fn every_refusal_writes_nothing_and_prints_the_fallback() {
        let s = ("settings.gradle", "rootProject.name = 'app'\n");
        assert_refused(
            &[
                s,
                ("build.gradle", "plugins { id 'com.android.application' }\n"),
            ],
            dep(),
            "redirect_gradle_android_or_kmp",
        );
        assert_refused(
            &[
                s,
                (
                    "gradle/wrapper/gradle-wrapper.properties",
                    "distributionUrl=https\\://services.gradle.org/distributions/gradle-6.7.1-bin.zip\n",
                ),
            ],
            dep(),
            "redirect_gradle_version_unsupported",
        );
        assert_refused(
            &[("settings.gradle", "includeBuild(\"$rootDir/../logic\")\n")],
            dep(),
            "redirect_gradle_include_build_unresolved",
        );
        assert_refused(
            &[
                s,
                (
                    "build.gradle",
                    "dependencies { testImplementation 'com.socketfixture:victim:1.10.0:tests' }\n",
                ),
            ],
            dep(),
            "redirect_gradle_classifier_declared",
        );
        assert_refused(
            &[s, ("build.gradle", "dependencies { implementation('com.socketfixture:victim') { version { strictly '[1.0,1.10.0)' } } }\n")],
            dep(),
            "redirect_gradle_range_declared",
        );
        assert_refused(
            &[
                s,
                (
                    ".socket/vendor/gradle-index.tsv",
                    "#socket-patch-gradle-index 1\ncom.socketfixture:victim:1.10.0\tx\ty\tz\n",
                ),
            ],
            dep(),
            "redirect_gradle_vendored_conflict",
        );
        assert_refused(
            &[(
                "settings.gradle",
                "buildscript {\n  dependencies { classpath 'com.socketfixture:victim:1.10.0' }\n}\n",
            )],
            dep(),
            "redirect_gradle_settings_classpath",
        );
        // A settings plugin pulling the GA in transitively shows only in
        // the settings-classpath lock.
        assert_refused(
            &[
                (
                    "settings.gradle",
                    "plugins { id 'org.example.settings' version '1.0' }\n",
                ),
                (
                    "settings-gradle.lockfile",
                    "com.socketfixture:victim:1.10.0=classpath\nempty=\n",
                ),
            ],
            dep(),
            "redirect_gradle_settings_classpath",
        );
        assert_refused(
            &[
                s,
                (
                    "gradle.lockfile",
                    "com.socketfixture:victim:1.9=runtimeClasspath\n",
                ),
            ],
            dep(),
            "redirect_gradle_lock_conflict",
        );
        assert_refused(
            &[
                s,
                (
                    "build.gradle",
                    "dependencyLocking { lockFile = file('x.lockfile') }\n",
                ),
            ],
            dep(),
            "redirect_gradle_lock_location_unknown",
        );
        assert_refused(
            &[
                s,
                (
                    "build.gradle",
                    "repositories { exclusiveContent { forRepository { maven { url 'https://x' } }\n filter { includeGroup 'com.socketfixture' } } }\n",
                ),
            ],
            dep(),
            "redirect_gradle_exclusive_content_conflict",
        );
        assert_refused(
            &[s, (HOSTED_INDEX_REL, "garbage\n")],
            dep(),
            "redirect_gradle_index_malformed",
        );
        let mut legacy = dep();
        let ids = &mut legacy.registry_override.as_mut().unwrap().identifiers;
        ids.maven_suffixed_version = None;
        ids.maven_pom_sha256 = None;
        let r = assert_refused(&[s], legacy, "redirect_gradle_same_gav_unsupported");
        assert!(r.warnings[1]
            .detail
            .contains("includeVersion('com.socketfixture', 'victim', '1.10.0')"));
        assert!(
            !r.warnings[1].detail.contains("strictly"),
            "no pin to bump to"
        );
        let mut bad = dep();
        bad.patch_uuid = "uuid".into();
        assert_refused(&[s], bad, "redirect_gradle_override_invalid");
        // A second base for a pinned GA.
        let pinned = index_with(&[row_line(UUID2, A, "1.9")]);
        assert_refused(
            &[s, (HOSTED_INDEX_REL, pinned.as_str())],
            dep(),
            "redirect_gradle_version_conflict",
        );
    }

    /// The takeover preflight refuses what the planner would refuse once
    /// the vendored wiring is gone, and ignores the vendored index itself.
    #[test]
    fn takeover_refusal_mirrors_the_planner_except_the_vendored_index() {
        let vendored = (
            ".socket/vendor/gradle-index.tsv",
            "#socket-patch-gradle-index 1\ncom.socketfixture:victim:1.10.0\tx\ty\tz\n",
        );
        let s = ("settings.gradle", "rootProject.name = 'app'\n");
        let none = BTreeSet::new();
        assert!(takeover_refusal(&files(&[s, vendored]), &none, &dep()).is_none());
        assert!(takeover_refusal(&files(&[("pom.xml", "<project/>")]), &none, &dep()).is_none());
        // A build file that exists but cannot be read refuses the takeover.
        let unreadable: BTreeSet<String> = ["settings.gradle".to_string()].into();
        assert_eq!(
            takeover_refusal(
                &files(&[("build.gradle", ""), vendored]),
                &unreadable,
                &dep()
            )
            .map(|w| w.code)
            .as_deref(),
            Some(UNREADABLE_REFUSAL_CODE)
        );
        let code = |input: &[(&str, &str)], d: DepOverride| {
            takeover_refusal(&files(input), &none, &d).map(|w| w.code)
        };
        assert_eq!(
            code(
                &[
                    s,
                    vendored,
                    (
                        "build.gradle",
                        "dependencyLocking { lockFile = file('x.lockfile') }\n"
                    )
                ],
                dep()
            )
            .as_deref(),
            Some("redirect_gradle_lock_location_unknown")
        );
        let mut legacy = dep();
        legacy
            .registry_override
            .as_mut()
            .unwrap()
            .identifiers
            .maven_suffixed_version = None;
        assert_eq!(
            code(&[s, vendored], legacy).as_deref(),
            Some("redirect_gradle_same_gav_unsupported")
        );
        let mut no_sha = dep();
        no_sha.integrity.sha256 = None;
        assert_eq!(
            code(&[s, vendored], no_sha).as_deref(),
            Some("redirect_gradle_override_invalid")
        );
        let mut no_override = dep();
        no_override.registry_override = None;
        assert_eq!(
            code(&[s, vendored], no_override).as_deref(),
            Some("redirect_gradle_override_invalid")
        );
        assert_eq!(
            code(
                &[
                    s,
                    vendored,
                    (
                        "settings-gradle.lockfile",
                        "com.socketfixture:victim:1.10.0=classpath\n"
                    ),
                ],
                dep()
            )
            .as_deref(),
            Some("redirect_gradle_settings_classpath")
        );
        let w = takeover_refusal(
            &files(&[
                s,
                vendored,
                (
                    "gradle.lockfile",
                    "com.socketfixture:victim:1.9=runtimeClasspath\n",
                ),
            ]),
            &none,
            &dep(),
        )
        .unwrap();
        assert_eq!(w.code, "redirect_gradle_lock_conflict");
        assert!(w.detail.contains("stays in place"), "{}", w.detail);
    }

    /// The files a restore can touch: every build's settings (a missing
    /// one included), every lock and the owned files.
    #[test]
    fn wiring_files_cover_every_build() {
        let got = wiring_files(&files(&[
            ("settings.gradle", "includeBuild 'tools'\n"),
            ("buildSrc/build.gradle", ""),
            ("tools/settings.gradle", ""),
            ("tools/gradle.lockfile", ""),
            ("gradle/dependency-locks/compileClasspath.lockfile", ""),
        ]));
        for want in [
            "settings.gradle",
            "buildSrc/settings.gradle",
            "tools/settings.gradle",
            "tools/gradle.lockfile",
            "gradle/dependency-locks/compileClasspath.lockfile",
            HOSTED_INDEX_REL,
            HOSTED_SCRIPT_REL,
            VERIFICATION_REL,
        ] {
            assert!(got.iter().any(|g| g == want), "{want}: {got:?}");
        }
    }

    /// A newer patch of the same GAV replaces the row and moves the old
    /// suffixed lock entries.
    #[test]
    fn a_new_patch_of_the_same_gav_replaces_the_row() {
        let old = index_with(&[row_line(UUID2, A, BASE)]);
        let old_sfx = suffixed_version(BASE, UUID2);
        let lock = format!("com.socketfixture:victim:{old_sfx}=runtimeClasspath\n");
        let input = files(&[
            ("settings.gradle", ""),
            (HOSTED_INDEX_REL, old.as_str()),
            ("gradle.lockfile", lock.as_str()),
        ]);
        let r = rewrite_registry_redirect(&input, &[dep()]);
        assert_eq!(
            r.files[HOSTED_INDEX_REL],
            index_with(&[row_line(UUID, A, BASE)])
        );
        assert_eq!(
            r.files["gradle.lockfile"],
            format!("com.socketfixture:victim:{SFX}=runtimeClasspath\n")
        );
        assert!(r.confirmed_gradle_uuids.contains(UUID));
    }

    #[test]
    fn fallback_goldens_carry_the_pin_and_the_reject_block() {
        let groovy = fallback_snippet(
            &[Dsl::Groovy],
            &url(UUID),
            G,
            A,
            BASE,
            Some(SFX),
            UUID,
            true,
        );
        let want_groovy = format!(
            "repositories {{\n    exclusiveContent {{\n        forRepository {{ maven {{ url '{u}' }} }}\n        filter {{ includeVersion('{G}', '{A}', '{SFX}') }}\n    }}\n}}\n",
            u = url(UUID)
        );
        assert!(groovy.contains(&want_groovy), "{groovy}");
        // #646 review: the owned script's rules, not a blanket pin. Only
        // a selector admitting the base is rewritten, only candidates at
        // or below the base are rejected (Gradle's own ordering), and no
        // dependency is declared (a project without the java plugin has
        // no `implementation`).
        for want in [
            format!("vs.accept('{BASE}')"),
            format!("d.useVersion('{SFX}')"),
            format!("order.compare(p.transform(c.version), p.transform('{BASE}')) <= 0"),
            format!("{STRATEGY}.DefaultVersionSelectorScheme"),
        ] {
            assert!(groovy.contains(&want), "{want}: {groovy}");
        }
        for unwanted in ["strictly", "implementation(", "substitute module"] {
            assert!(!groovy.contains(unwanted), "{unwanted}: {groovy}");
        }
        assert!(groovy.contains("--write-locks"));
        // #348: the Kotlin DSL assigns the url with `uri(…)`.
        let kotlin = fallback_snippet(
            &[Dsl::Kotlin],
            &url(UUID),
            G,
            A,
            BASE,
            Some(SFX),
            UUID,
            false,
        );
        let want_kotlin = format!(
            "repositories {{\n    exclusiveContent {{\n        forRepository {{ maven {{ url = uri(\"{u}\") }} }}\n        filter {{ includeVersion(\"{G}\", \"{A}\", \"{SFX}\") }}\n    }}\n}}\n",
            u = url(UUID)
        );
        for want in [
            format!("vs.accept(\"{BASE}\")"),
            format!("useVersion(\"{SFX}\")"),
            format!("p.transform(\"{BASE}\")) <= 0"),
        ] {
            assert!(kotlin.contains(&want), "{want}: {kotlin}");
        }
        for unwanted in ["strictly", "implementation(", "substitute("] {
            assert!(!kotlin.contains(unwanted), "{unwanted}: {kotlin}");
        }
        assert!(kotlin.contains(&want_kotlin), "{kotlin}");
        assert!(
            !kotlin.contains("url '"),
            "no Groovy spelling in the Kotlin snippet"
        );
        assert!(!kotlin.contains("--write-locks"));
        let both = fallback_snippet(
            &[Dsl::Groovy, Dsl::Kotlin],
            &url(UUID),
            G,
            A,
            BASE,
            Some(SFX),
            UUID,
            false,
        );
        assert!(
            both.contains("// build.gradle (Groovy DSL):")
                && both.contains("// build.gradle.kts (Kotlin DSL):")
        );
    }

    #[test]
    fn index_grammar_matches_the_script() {
        let line = row_line(UUID, A, BASE);
        let row = HostedRow::parse(&line).unwrap();
        assert_eq!(row.line(), line);
        assert_eq!(row.purl(), "pkg:maven/com.socketfixture/victim@1.10.0");
        for bad in [
            line.replace(SFX, "1.10.0-socket.00000000"),
            line.replace("https://", "http://"),
            line.replace(UUID, &UUID.to_uppercase()),
            line.replace(&"a".repeat(64), "a"),
            line.replace("com.socketfixture:victim:1.10.0", "com..x:victim:1.10.0"),
            format!("{line}\textra"),
        ] {
            assert!(HostedRow::parse(&bad).is_none(), "{bad}");
        }
        let text = format!("{HOSTED_INDEX_HEADER}\r\n{line}\r\n");
        assert_eq!(parse_index(&text).unwrap(), vec![row.clone()]);
        assert_eq!(
            index_digest(&text),
            index_digest(&text.replace("\r\n", "\n"))
        );
        assert!(parse_index(&format!("{HOSTED_INDEX_HEADER}\n{line}\n{line}\n")).is_err());
        assert!(parse_index("#socket-patch-gradle-hosted-index 2\n").is_err());
    }

    /// The hosted script's bytes are pinned: a change is a CLI-release
    /// event (every hosted checkout rewrites it on its next scan).
    #[test]
    fn hosted_script_snapshot() {
        let digest = hex::encode(Sha256::digest(HOSTED_SCRIPT.as_bytes()));
        assert_eq!(
            digest, "98ac3cb22b45d2445215b1afb6492669be1638f849fbf3328c4f5cec7c77353e",
            "update the snapshot after reviewing the script change"
        );
        assert!(!HOSTED_SCRIPT.contains('\r'));
        assert!(HOSTED_SCRIPT.contains(HOSTED_INDEX_HEADER));
        assert!(HOSTED_SCRIPT.contains(&format!("'{REPO_NAME_PREFIX}'")));
    }

    /// The fixed point reads the graph's scripts and every lock file.
    #[test]
    fn gradle_files_reach_a_fixed_point() {
        let disk = files(&[
            (
                "settings.gradle",
                "include 'a'\napply from: 'gradle/extra.gradle'\n",
            ),
            ("gradle/extra.gradle", "include 'b'\n"),
            ("a/build.gradle", ""),
            ("b/build.gradle", ""),
            ("b/gradle.lockfile", "x:y:1=c\n"),
            ("unrelated/gradle.lockfile", "x:y:1=c\n"),
        ]);
        let mut g = GradleFiles::default();
        g.found("settings.gradle", disk["settings.gradle"].clone());
        for _ in 0..MAX_ROUNDS {
            let (reads, lists) = g.misses();
            if reads.is_empty() && lists.is_empty() {
                break;
            }
            for r in reads {
                match disk.get(&r) {
                    Some(t) => g.found(&r, t.clone()),
                    None => g.absent(&r),
                }
            }
            for d in lists {
                g.listed(&d, key_list(&disk, &d));
            }
        }
        assert!(g.misses().0.is_empty());
        assert!(g.files.contains_key("gradle/extra.gradle"));
        assert!(g.files.contains_key("b/gradle.lockfile"));
        assert!(
            !g.files.contains_key("unrelated/gradle.lockfile"),
            "not a project of the build"
        );
    }
}
