//! The script graph of a Gradle checkout: every settings and build script
//! Gradle would evaluate that can be found statically, and the queries
//! the modes need over it.
//!
//! [`ScriptGraph::collect`] starts from the root settings and follows:
//!
//! - literal `include` forms (with their implied parents), literal
//!   `projectDir` / `buildFileName` overrides, and each project's build
//!   script;
//! - `buildSrc/` and literal `includeBuild` roots (recursively, with their
//!   own subprojects), plus the precompiled convention plugins under
//!   `src/main/{groovy,kotlin}` of those builds;
//! - literal `apply from` targets, recursively with a visited set;
//! - each build's `gradle/libs.versions.toml` and literal
//!   `versionCatalogs { from(files(…)) }` catalogs;
//! - the init scripts the caller supplies (scanned only for `mavenLocal`
//!   and unresolved targets).
//!
//! Anything that cannot be followed statically (an interpolated or
//! computed path, a URL, a path escaping the root, a missing or oversized
//! file, a script that does not tokenize cleanly, a cap) is recorded in
//! [`ScriptGraph::unresolved`]; callers that must fail safe treat a
//! non-empty list as "could be anything". Caps: `apply from` and
//! included-build nesting ≤ 8 deep, ≤ 512 files, ≤ 1 MiB per file.
//!
//! All paths are forward-slash and in the caller's [`TextReadFn`] space
//! (so they already include `root_rel`); init scripts keep the caller's
//! tag as their `rel`.

use std::collections::BTreeSet;

use super::dsl::{
    self, all_blocks, call_at, call_sites, command_end, is_ident, is_punct, literal_of,
    matching_close, Dsl, Tok, Token,
};
use super::locks;
use super::selector::{parse_selector, Selector};
use super::{join_rel, line_of, parent_rel, resolve_rel, ListFn, TextReadFn};

/// `apply from` and included-build nesting depth.
pub const MAX_DEPTH: usize = 8;
/// Script, catalog and init-script files collected.
pub const MAX_FILES: usize = 512;
/// Bytes per file.
pub const MAX_FILE_BYTES: usize = 1 << 20;

/// Build-script text marking a project that builds Gradle plugins.
const PLUGIN_PROJECT_MARKERS: &[&str] = &[
    "java-gradle-plugin",
    "groovy-gradle-plugin",
    "kotlin-dsl",
    "gradlePlugin",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptKind {
    Settings,
    Build,
    /// A precompiled script plugin of `buildSrc` or an included build.
    ConventionPlugin,
    /// A binary plugin's source (`.kt`, `.java`, `.groovy`) in `buildSrc`
    /// or a plugin project of an included build. Lexed with the Kotlin
    /// (`.kt`) or Groovy (`.java`, `.groovy`) tokenizer, which is enough to
    /// find `mavenLocal()`, plugin ids and coordinates in it.
    PluginSource,
    /// The target of an `apply from`.
    Applied,
    Init,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    pub rel: String,
    pub kind: ScriptKind,
    pub dsl: Dsl,
    /// The root directory of the build the script belongs to (`""` for
    /// init scripts).
    pub build: String,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BuildKind {
    Root,
    BuildSrc,
    Included,
}

/// One Gradle build of the checkout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Build {
    pub dir: String,
    pub kind: BuildKind,
    /// The settings script, when there is one.
    pub settings: Option<String>,
    pub projects: Vec<Project>,
}

/// One project of a build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    /// The Gradle path (`:` for the root project, `:a:b`).
    pub path: String,
    pub dir: String,
    /// The build script, when there is one.
    pub build_script: Option<String>,
}

/// The kind of reference that could not be followed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Site {
    ApplyFrom,
    Include,
    ProjectDir,
    BuildFileName,
    IncludeBuild,
    Catalog,
    /// The script itself (oversized, unreadable or malformed).
    Script,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// Interpolated or computed.
    NonLiteral,
    Url,
    /// Absolute, or climbs above the root.
    Escapes,
    /// Names a file that cannot be read.
    Missing,
    TooLarge,
    /// Does not tokenize cleanly.
    Unparseable,
    /// Relative to a context only known when the plugin is applied (an
    /// `apply from` inside a convention plugin or init script).
    Contextual,
    DepthCap,
    FileCap,
}

/// A reference the graph could not follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unresolved {
    /// The script holding the reference.
    pub rel: String,
    /// 1-based line (0 for [`Site::Script`]).
    pub line: usize,
    pub site: Site,
    pub reason: Reason,
    /// The source text of the reference, trimmed to one line.
    pub snippet: String,
}

/// A version catalog file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalog {
    pub rel: String,
    pub text: String,
}

/// Whether the build (or a Gradle init script) adds `mavenLocal()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MavenLocal {
    /// Declared in this script (`rel`).
    Declared(String),
    NotDeclared,
    /// Something could not be read, so it cannot be ruled out.
    Undetermined(String),
}

/// A rich version constraint (`version { strictly … }`, or `…!!`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RichVersion {
    pub strictly: Option<String>,
    pub require: Option<String>,
    pub prefer: Option<String>,
    pub reject: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclKind {
    /// An exact version, or none / a non-literal one.
    Plain,
    /// A range, prefix (`1.+`) or `latest.*` selector.
    Range,
    Rich(RichVersion),
    /// Requests a classifier artifact.
    Classifier,
    /// A `[libraries]` entry of a version catalog.
    Catalog,
}

/// One declaration of a module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decl {
    pub rel: String,
    pub line: usize,
    pub kind: DeclKind,
    /// The version (selector) text; `None` when absent or not literal.
    pub version: Option<String>,
    pub rich: Option<RichVersion>,
    pub classifier: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FilterKind {
    Group,
    GroupAndSubgroups,
    GroupByRegex,
    Module,
    ModuleByRegex,
    Version,
    VersionByRegex,
}

/// One `include*` rule of an `exclusiveContent { filter { … } }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterRule {
    pub kind: FilterKind,
    /// The arguments; `None` for a non-literal one.
    pub args: Vec<Option<String>>,
}

/// One `exclusiveContent` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExclusiveFilter {
    pub rel: String,
    pub line: usize,
    /// Every string in its `forRepository` part (names, URLs).
    pub repo_strings: Vec<String>,
    pub rules: Vec<FilterRule>,
}

/// Whether `filter` could route `group:artifact` to its repository. A
/// non-literal argument, a regex that does not compile or a malformed rule
/// counts as a claim.
pub fn filter_claims_group(filter: &ExclusiveFilter, group: &str, artifact: &str) -> bool {
    filter.rules.iter().any(|r| rule_claims(r, group, artifact))
}

fn rule_claims(rule: &FilterRule, g: &str, a: &str) -> bool {
    let eq = |i: usize, want: &str| {
        rule.args
            .get(i)
            .cloned()
            .flatten()
            .is_none_or(|v| v == want)
    };
    let re = |i: usize, want: &str| match rule.args.get(i).cloned().flatten() {
        None => true,
        Some(pat) => regex::Regex::new(&format!("^(?:{pat})$")).map_or(true, |r| r.is_match(want)),
    };
    let arity = |n: usize| rule.args.len() < n;
    match rule.kind {
        FilterKind::Group => arity(1) || eq(0, g),
        FilterKind::GroupAndSubgroups => {
            arity(1)
                || rule.args[0]
                    .as_deref()
                    .is_none_or(|p| g == p || g.starts_with(&format!("{p}.")))
        }
        FilterKind::GroupByRegex => arity(1) || re(0, g),
        FilterKind::Module | FilterKind::Version => arity(2) || (eq(0, g) && eq(1, a)),
        FilterKind::ModuleByRegex | FilterKind::VersionByRegex => {
            arity(2) || (re(0, g) && re(1, a))
        }
    }
}

/// The statically known script graph of a checkout.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScriptGraph {
    pub root: String,
    pub builds: Vec<Build>,
    pub scripts: Vec<Script>,
    pub catalogs: Vec<Catalog>,
    pub unresolved: Vec<Unresolved>,
    /// Init scripts that exist but could not be read or tokenized.
    pub init_unparseable: Vec<String>,
}

/// What a build's settings (with the scripts it applies) says about it.
#[derive(Debug, Default)]
struct SettingsInfo {
    /// `(gradle path, dir)` of every included project, parents included.
    projects: Vec<(String, String)>,
    /// `(gradle path, build file name)` overrides.
    build_files: Vec<(String, String)>,
    /// Literal included-build directories.
    included_builds: Vec<String>,
    /// Literal catalog files.
    catalogs: Vec<String>,
    unresolved: Vec<Unresolved>,
}

/// A project statement of a settings script. Gradle applies them in
/// order: an included child's default directory is its parent's directory
/// at the time of the `include`.
#[derive(Debug)]
enum SettingsEvent {
    /// The path segments of an `include`.
    Include(Vec<String>),
    /// `(gradle path, dir)`.
    ProjectDir(String, String),
    /// `(gradle path, build file name)`.
    BuildFile(String, String),
}

fn snippet(text: &str, toks: &[Token], first: usize, last: usize) -> String {
    let start = toks.get(first).map_or(0, |t| t.start);
    let end = toks
        .get(last.saturating_sub(1).max(first))
        .map_or(start, |t| t.end)
        .max(start);
    let s = &text[start..end.min(text.len())];
    s.lines().next().unwrap_or("").trim().to_string()
}

/// Which directory a path expression is relative to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Base {
    /// The build root (`rootDir`, `settingsDir`, `rootProject`).
    Root,
    /// The project (or settings) directory of the script.
    Here,
}

const TEMPLATES: &[(&str, Base)] = &[
    ("${rootDir}", Base::Root),
    ("$rootDir", Base::Root),
    ("${project.rootDir}", Base::Root),
    ("$project.rootDir", Base::Root),
    ("${rootProject.projectDir}", Base::Root),
    ("$rootProject.projectDir", Base::Root),
    ("${rootProject.rootDir}", Base::Root),
    ("$rootProject.rootDir", Base::Root),
    ("${settingsDir}", Base::Root),
    ("$settingsDir", Base::Root),
    ("${projectDir}", Base::Here),
    ("$projectDir", Base::Here),
    ("${project.projectDir}", Base::Here),
    ("$project.projectDir", Base::Here),
];

/// A string value as `(base, relative path)`.
fn string_path(value: &str, literal: bool) -> Result<(Base, String), Reason> {
    if value.contains("://") {
        return Err(Reason::Url);
    }
    if literal {
        return Ok((Base::Here, value.to_string()));
    }
    for (prefix, base) in TEMPLATES {
        if let Some(rest) = value.strip_prefix(prefix) {
            if let Some(rest) = rest.strip_prefix('/') {
                if !rest.contains('$') {
                    return Ok((*base, rest.to_string()));
                }
            }
        }
    }
    Err(Reason::NonLiteral)
}

/// The base a receiver chain / directory expression names.
fn dir_base(toks: &[Token]) -> Option<Base> {
    let names: Vec<&str> = toks
        .iter()
        .filter_map(|t| match &t.tok {
            Tok::Ident(n) => Some(n.as_str()),
            Tok::Punct(b'.' | b'?' | b'!') => None,
            _ => Some("\u{0}"),
        })
        .collect();
    if names.contains(&"\u{0}") || names.is_empty() {
        return None;
    }
    let root = ["rootDir", "settingsDir", "rootProject", "settingsDirectory"];
    if names.iter().any(|n| root.contains(n)) {
        Some(Base::Root)
    } else if names
        .iter()
        .all(|n| matches!(*n, "projectDir" | "project" | "layout" | "projectDirectory"))
    {
        Some(Base::Here)
    } else {
        None
    }
}

/// A path expression (`'p'`, `"$rootDir/p"`, `file('p')`,
/// `rootProject.file('p')`, `new File(rootDir, 'p')`, `uri('p')`).
fn path_expr(toks: &[Token]) -> Result<(Base, String), Reason> {
    match toks {
        [Token {
            tok: Tok::Str { value, literal },
            ..
        }] => return string_path(value, *literal),
        [] => return Err(Reason::NonLiteral),
        _ => {}
    }
    // `… file(X)` / `… uri(X)` / `[new] File(D, X)` as the whole expression.
    let n = toks.len();
    if !is_punct(toks.last(), b')') {
        return Err(Reason::NonLiteral);
    }
    let open = (0..n)
        .find(|&i| is_punct(toks.get(i), b'(') && matching_close(toks, i) == Some(n - 1))
        .ok_or(Reason::NonLiteral)?;
    if open == 0 {
        return Err(Reason::NonLiteral);
    }
    let callee = match &toks[open - 1].tok {
        Tok::Ident(c) => c.as_str(),
        _ => return Err(Reason::NonLiteral),
    };
    let receiver = &toks[..open - 1];
    let inner = &toks[open + 1..n - 1];
    match callee {
        "file" | "uri" => {
            let base = if receiver.is_empty() {
                Base::Here
            } else {
                // `rootProject.file(`, `project.file(`, `layout.projectDirectory.file(`.
                if !is_punct(receiver.last(), b'.') {
                    return Err(Reason::NonLiteral);
                }
                dir_base(&receiver[..receiver.len() - 1]).ok_or(Reason::NonLiteral)?
            };
            let (inner_base, p) = path_expr(inner)?;
            Ok((
                if inner_base == Base::Root {
                    Base::Root
                } else {
                    base
                },
                p,
            ))
        }
        "File" => {
            let ok_receiver =
                receiver.is_empty() || (receiver.len() == 1 && is_ident(receiver.first(), "new"));
            if !ok_receiver {
                return Err(Reason::NonLiteral);
            }
            let comma = (0..inner.len())
                .find(|&i| is_punct(inner.get(i), b','))
                .ok_or(Reason::NonLiteral)?;
            let base = dir_base(&inner[..comma]).ok_or(Reason::NonLiteral)?;
            let (_, p) = match &inner[comma + 1..] {
                [Token {
                    tok:
                        Tok::Str {
                            value,
                            literal: true,
                        },
                    ..
                }] => string_path(value, true)?,
                _ => return Err(Reason::NonLiteral),
            };
            Ok((base, p))
        }
        _ => Err(Reason::NonLiteral),
    }
}

/// Resolve a path expression against `here` / `build_root`.
fn resolve_path(
    floor: &str,
    build_root: &str,
    here: &str,
    toks: &[Token],
) -> Result<String, Reason> {
    let (base, p) = path_expr(toks)?;
    let dir = match base {
        Base::Root => build_root,
        Base::Here => here,
    };
    resolve_rel(floor, dir, &p).ok_or(Reason::Escapes)
}

/// The `include` / `projectDir` / `buildFileName` / `includeBuild` /
/// catalog content of one settings script (or a script it applies) of
/// the build at `dir`. `here` is the directory the script's own relative
/// paths resolve against: the settings directory for the settings script,
/// the script's directory for an applied one. The project statements come
/// back as byte-offset-ordered events for [`fold_settings`]; `info` holds
/// the rest.
fn parse_settings(
    rel: &str,
    text: &str,
    dsl: Dsl,
    dir: &str,
    here: &str,
    floor: &str,
) -> (SettingsInfo, Vec<(usize, SettingsEvent)>) {
    let toks = dsl::tokens(text, dsl);
    let mut info = SettingsInfo::default();
    let mut events = Vec::new();
    let unresolved = |info: &mut SettingsInfo, line, site, reason, snip: String| {
        info.unresolved.push(Unresolved {
            rel: rel.to_string(),
            line,
            site,
            reason,
            snippet: snip,
        })
    };
    let settings_receiver = |r: &Option<String>| r.as_deref().is_none_or(|r| r == "settings");

    for callee in ["include", "includeFlat"] {
        for call in call_sites(text, &toks, callee) {
            if !settings_receiver(&call.receiver) {
                continue;
            }
            let snip = snippet(text, &toks, call.callee, call.end);
            if callee == "includeFlat" {
                unresolved(&mut info, call.line, Site::Include, Reason::Escapes, snip);
                continue;
            }
            let Some(paths) = call.literals() else {
                unresolved(
                    &mut info,
                    call.line,
                    Site::Include,
                    Reason::NonLiteral,
                    snip,
                );
                continue;
            };
            for p in paths {
                let segs: Vec<String> = p
                    .split(':')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
                if segs.iter().any(|s| s == ".." || s.contains(['/', '\\'])) {
                    unresolved(
                        &mut info,
                        call.line,
                        Site::Include,
                        Reason::Escapes,
                        snip.clone(),
                    );
                    continue;
                }
                if !segs.is_empty() {
                    events.push((toks[call.callee].start, SettingsEvent::Include(segs)));
                }
            }
        }
    }

    // `project(':a').projectDir = …` / `.buildFileName = …` (also
    // `findProject(":a")?.…` / `!!.`, and `rootProject.…`).
    for (i, t) in toks.iter().enumerate() {
        let site = match &t.tok {
            Tok::Ident(n) if n == "projectDir" => Site::ProjectDir,
            Tok::Ident(n) if n == "buildFileName" => Site::BuildFileName,
            _ => continue,
        };
        let assign = is_punct(toks.get(i + 1), b'=') && !is_punct(toks.get(i + 2), b'=');
        let set_call = is_punct(toks.get(i + 1), b'.') && is_ident(toks.get(i + 2), "set");
        if !assign && !set_call {
            continue;
        }
        let value_from = if assign { i + 2 } else { i + 3 };
        let value_to = command_end(text, &toks, value_from);
        let value = if set_call {
            // `.set(X)`: the parenthesised argument.
            match matching_close(&toks, value_from) {
                Some(close) if is_punct(toks.get(value_from), b'(') => &toks[value_from + 1..close],
                _ => &toks[value_from..value_to],
            }
        } else {
            &toks[value_from..value_to]
        };
        let line = line_of(text, t.start);
        let snip = snippet(text, &toks, i.saturating_sub(5), value_to);
        let target = project_receiver(&toks, i);
        let Some(path) = target else {
            unresolved(&mut info, line, site, Reason::NonLiteral, snip);
            continue;
        };
        match site {
            Site::ProjectDir if path == ":" => {
                unresolved(&mut info, line, site, Reason::NonLiteral, snip)
            }
            Site::ProjectDir => match resolve_path(floor, dir, here, value) {
                Ok(new_dir) => events.push((t.start, SettingsEvent::ProjectDir(path, new_dir))),
                Err(reason) => unresolved(&mut info, line, site, reason, snip),
            },
            _ => match value {
                [single] if literal_of(Some(single)).is_some() => {
                    let name = literal_of(Some(single)).unwrap_or_default().to_string();
                    if name.contains(['/', '\\']) {
                        unresolved(&mut info, line, site, Reason::Escapes, snip);
                    } else {
                        events.push((t.start, SettingsEvent::BuildFile(path, name)));
                    }
                }
                _ => unresolved(&mut info, line, site, Reason::NonLiteral, snip),
            },
        }
    }
    events.sort_by_key(|(at, _)| *at);

    for call in call_sites(text, &toks, "includeBuild") {
        if !settings_receiver(&call.receiver) {
            continue;
        }
        let snip = snippet(text, &toks, call.callee, call.end);
        let Some(arg) = call.args.first().filter(|a| a.name.is_none()) else {
            unresolved(
                &mut info,
                call.line,
                Site::IncludeBuild,
                Reason::NonLiteral,
                snip,
            );
            continue;
        };
        // A bare string is a settings path (relative to the settings
        // directory); `file(…)` is the script's own.
        let arg_toks = &toks[arg.first..arg.last];
        let base = match arg_toks {
            [Token {
                tok: Tok::Str { .. },
                ..
            }] => dir,
            _ => here,
        };
        match resolve_path(floor, dir, base, arg_toks) {
            Ok(d) if d != dir => info.included_builds.push(d),
            Ok(_) => {}
            Err(reason) => unresolved(&mut info, call.line, Site::IncludeBuild, reason, snip),
        }
    }

    for (open, close) in all_blocks(&toks, "versionCatalogs") {
        let body = &toks[open..close];
        for call in call_sites(text, body, "files") {
            let snip = snippet(text, body, call.callee, call.end);
            match call.literals().as_deref() {
                Some([p]) => match resolve_rel(floor, here, p) {
                    Some(r) => info.catalogs.push(r),
                    None => unresolved(&mut info, call.line, Site::Catalog, Reason::Escapes, snip),
                },
                _ => unresolved(
                    &mut info,
                    call.line,
                    Site::Catalog,
                    Reason::NonLiteral,
                    snip,
                ),
            }
        }
    }
    (info, events)
}

/// `(gradle path, value)` pairs.
type PathPairs = Vec<(String, String)>;

/// Apply project statements in order: `(projects, build files)`.
fn fold_settings(dir: &str, events: &[SettingsEvent]) -> (PathPairs, PathPairs) {
    let mut projects: Vec<(String, String)> = Vec::new();
    let mut build_files = Vec::new();
    for ev in events {
        match ev {
            SettingsEvent::Include(segs) => {
                // Gradle creates each missing ancestor under its parent's
                // directory as it stands now.
                let mut parent_dir = dir.to_string();
                for k in 1..=segs.len() {
                    let path = format!(":{}", segs[..k].join(":"));
                    if let Some((_, d)) = projects.iter().find(|(q, _)| *q == path) {
                        parent_dir = d.clone();
                        continue;
                    }
                    let d = join_rel(&parent_dir, &segs[k - 1]);
                    projects.push((path, d.clone()));
                    parent_dir = d;
                }
            }
            SettingsEvent::ProjectDir(path, d) => {
                if let Some(p) = projects.iter_mut().find(|(q, _)| q == path) {
                    p.1 = d.clone();
                }
            }
            SettingsEvent::BuildFile(path, name) => build_files.push((path.clone(), name.clone())),
        }
    }
    (projects, build_files)
}

/// A settings-side script as [`settings_info`] reads it: its text, DSL and
/// the `(byte offset, target)` of each `apply from` that was followed.
type SettingsSource = (String, Dsl, Vec<(usize, String)>);

/// Everything the settings script `root` of the build at `dir` says,
/// including the scripts it applies (spliced in at the `apply from`, as
/// Gradle runs them). `source` yields each script; a target it cannot
/// yield is recorded as a missing `apply from`.
fn settings_info(
    root: &str,
    dir: &str,
    floor: &str,
    source: &mut dyn FnMut(&str) -> Option<SettingsSource>,
) -> SettingsInfo {
    #[allow(clippy::too_many_arguments)]
    fn walk(
        rel: &str,
        dir: &str,
        floor: &str,
        source: &mut dyn FnMut(&str) -> Option<SettingsSource>,
        visited: &mut BTreeSet<String>,
        info: &mut SettingsInfo,
        events: &mut Vec<SettingsEvent>,
        depth: usize,
    ) -> bool {
        if !visited.insert(rel.to_string()) {
            return true;
        }
        let Some((text, dsl, applies)) = source(rel) else {
            return false;
        };
        let (mut own, own_events) = parse_settings(rel, &text, dsl, dir, parent_rel(rel), floor);
        info.included_builds.append(&mut own.included_builds);
        info.catalogs.append(&mut own.catalogs);
        info.unresolved.append(&mut own.unresolved);
        let mut own_events = own_events.into_iter().peekable();
        for (at, target) in applies {
            while let Some((_, ev)) = own_events.next_if(|(e, _)| *e < at) {
                events.push(ev);
            }
            let line = line_of(&text, at);
            if depth >= MAX_DEPTH {
                info.unresolved.push(Unresolved {
                    rel: rel.to_string(),
                    line,
                    site: Site::ApplyFrom,
                    reason: Reason::DepthCap,
                    snippet: target,
                });
                continue;
            }
            if !walk(
                &target,
                dir,
                floor,
                source,
                visited,
                info,
                events,
                depth + 1,
            ) {
                info.unresolved.push(Unresolved {
                    rel: rel.to_string(),
                    line,
                    site: Site::ApplyFrom,
                    reason: Reason::Missing,
                    snippet: target,
                });
            }
        }
        events.extend(own_events.map(|(_, ev)| ev));
        true
    }
    let mut info = SettingsInfo::default();
    let mut events = Vec::new();
    walk(
        root,
        dir,
        floor,
        source,
        &mut BTreeSet::new(),
        &mut info,
        &mut events,
        0,
    );
    (info.projects, info.build_files) = fold_settings(dir, &events);
    info
}

/// The Gradle path whose property is assigned at token `i`
/// (`project(':a').projectDir`, `findProject(":a")?.projectDir`,
/// `rootProject.projectDir`); `None` when it is not literal.
fn project_receiver(toks: &[Token], i: usize) -> Option<String> {
    let mut j = i.checked_sub(1)?;
    if !is_punct(toks.get(j), b'.') {
        return None;
    }
    j = j.checked_sub(1)?;
    // `?.` and `!!.`
    while is_punct(toks.get(j), b'?') || is_punct(toks.get(j), b'!') {
        j = j.checked_sub(1)?;
    }
    if is_ident(toks.get(j), "rootProject") {
        return Some(":".into());
    }
    if !is_punct(toks.get(j), b')') {
        return None;
    }
    let path = literal_of(toks.get(j.checked_sub(1)?))?;
    if !is_punct(toks.get(j.checked_sub(2)?), b'(') {
        return None;
    }
    let callee = toks.get(j.checked_sub(3)?)?;
    if !(is_ident(Some(callee), "project") || is_ident(Some(callee), "findProject")) {
        return None;
    }
    let segs: Vec<&str> = path.split(':').filter(|s| !s.is_empty()).collect();
    Some(format!(":{}", segs.join(":")))
}

struct Collector<'a> {
    read: TextReadFn<'a>,
    list: ListFn<'a>,
    floor: String,
    graph: ScriptGraph,
    seen: BTreeSet<String>,
    /// `(script, byte offset of the apply, target)` of every followed
    /// `apply from`.
    applied: Vec<(String, usize, String)>,
    files: usize,
    capped: bool,
}

impl Collector<'_> {
    fn unresolved(&mut self, rel: &str, line: usize, site: Site, reason: Reason, snip: String) {
        self.graph.unresolved.push(Unresolved {
            rel: rel.to_string(),
            line,
            site,
            reason,
            snippet: snip,
        });
    }

    /// Read a file under the caps; `None` when absent or refused (a
    /// refusal is recorded against the file itself).
    fn read_capped(&mut self, rel: &str) -> Option<String> {
        let text = (self.read)(rel)?;
        if self.files >= MAX_FILES {
            if !self.capped {
                self.capped = true;
                self.unresolved(rel, 0, Site::Script, Reason::FileCap, String::new());
            }
            return None;
        }
        self.files += 1;
        if text.len() > MAX_FILE_BYTES {
            self.unresolved(rel, 0, Site::Script, Reason::TooLarge, String::new());
            return None;
        }
        Some(crate::formats::text::strip_bom(&text).to_string())
    }

    /// The Groovy (preferred, as Gradle does) or Kotlin `<stem>` script of
    /// `dir`.
    fn find_script(&mut self, dir: &str, stem: &str) -> Option<(String, String)> {
        for ext in [".gradle", ".gradle.kts"] {
            let rel = join_rel(dir, &format!("{stem}{ext}"));
            if self.seen.contains(&rel) {
                return None;
            }
            if let Some(text) = self.read_capped(&rel) {
                return Some((rel, text));
            }
        }
        None
    }

    /// Record a script and follow its `apply from` targets. `here` is the
    /// directory relative targets resolve against (`None` when that is
    /// only known at the point of use). Under a settings script
    /// (`script_relative`) each applied script resolves against its own
    /// directory, as Gradle does for a non-project target; under a project
    /// they all resolve against the project directory.
    #[allow(clippy::too_many_arguments)]
    fn add_script(
        &mut self,
        rel: String,
        text: String,
        kind: ScriptKind,
        build: &str,
        here: Option<&str>,
        depth: usize,
        script_relative: bool,
    ) {
        if !self.seen.insert(rel.clone()) {
            return;
        }
        let dsl = if rel.ends_with(".kt") {
            Dsl::Kotlin
        } else {
            dsl::dsl_of(&rel).unwrap_or(Dsl::Groovy)
        };
        if !dsl::well_formed(&text, dsl) {
            self.unresolved(&rel, 0, Site::Script, Reason::Unparseable, String::new());
        }
        let toks = dsl::tokens(&text, dsl);
        let targets: Vec<(usize, usize, String, Result<String, Reason>)> =
            apply_from_targets(&text, &toks)
                .into_iter()
                .map(|(line, first, last)| {
                    let resolved = match here {
                        None => Err(Reason::Contextual),
                        Some(here) => resolve_path(&self.floor, build, here, &toks[first..last]),
                    };
                    let at = toks[first].start;
                    (line, at, snippet(&text, &toks, first, last), resolved)
                })
                .collect();
        self.graph.scripts.push(Script {
            rel: rel.clone(),
            kind,
            dsl,
            build: build.to_string(),
            text,
        });
        for (line, at, snip, resolved) in targets {
            let target = match resolved {
                Ok(t) => t,
                Err(reason) => {
                    self.unresolved(&rel, line, Site::ApplyFrom, reason, snip);
                    continue;
                }
            };
            if self.seen.contains(&target) {
                continue;
            }
            if depth >= MAX_DEPTH {
                self.unresolved(&rel, line, Site::ApplyFrom, Reason::DepthCap, snip);
                continue;
            }
            match self.read_capped(&target) {
                Some(t) => {
                    self.applied.push((rel.clone(), at, target.clone()));
                    let child_here = if script_relative {
                        Some(parent_rel(&target).to_string())
                    } else {
                        here.map(str::to_string)
                    };
                    self.add_script(
                        target,
                        t,
                        ScriptKind::Applied,
                        build,
                        child_here.as_deref(),
                        depth + 1,
                        script_relative,
                    )
                }
                None => {
                    if !self.capped {
                        self.unresolved(&rel, line, Site::ApplyFrom, Reason::Missing, snip)
                    }
                }
            }
        }
    }

    fn add_catalog(&mut self, rel: &str) -> bool {
        if self.graph.catalogs.iter().any(|c| c.rel == rel) {
            return true;
        }
        match self.read_capped(rel) {
            Some(text) => {
                self.graph.catalogs.push(Catalog {
                    rel: rel.to_string(),
                    text,
                });
                true
            }
            None => false,
        }
    }

    fn has_dir(&self, parent: &str, name: &str) -> bool {
        (self.list)(parent).iter().any(|c| c == &format!("{name}/"))
    }

    /// Precompiled script plugins under `<dir>/src/main/{groovy,kotlin}`
    /// and, with `sources`, binary plugin sources under
    /// `<dir>/src/main/{groovy,kotlin,java}`.
    fn convention_plugins(&mut self, build: &str, dir: &str, sources: bool) {
        for lang in ["groovy", "kotlin", "java"] {
            let mut stack = vec![(join_rel(dir, &format!("src/main/{lang}")), 0usize)];
            while let Some((d, depth)) = stack.pop() {
                for child in (self.list)(&d) {
                    if let Some(name) = child.strip_suffix('/') {
                        if depth < MAX_DEPTH {
                            stack.push((join_rel(&d, name), depth + 1));
                        }
                    } else {
                        let kind = if child.ends_with(".gradle") || child.ends_with(".gradle.kts") {
                            ScriptKind::ConventionPlugin
                        } else if sources
                            && [".kt", ".java", ".groovy"]
                                .iter()
                                .any(|e| child.ends_with(e))
                        {
                            ScriptKind::PluginSource
                        } else {
                            continue;
                        };
                        let rel = join_rel(&d, &child);
                        if self.seen.contains(&rel) {
                            continue;
                        }
                        if let Some(text) = self.read_capped(&rel) {
                            self.add_script(rel, text, kind, build, None, 0, false);
                        }
                    }
                }
            }
        }
    }

    fn collect_build(&mut self, dir: &str, kind: BuildKind, depth: usize) {
        if self.graph.builds.iter().any(|b| b.dir == dir) {
            return;
        }
        let settings = self.find_script(dir, "settings");
        let mut info = SettingsInfo::default();
        let settings_rel = settings.as_ref().map(|(rel, _)| rel.clone());
        if let Some((rel, text)) = settings {
            self.add_script(
                rel.clone(),
                text,
                ScriptKind::Settings,
                dir,
                Some(dir),
                0,
                true,
            );
            let (scripts, applied) = (&self.graph.scripts, &self.applied);
            info = settings_info(&rel, dir, &self.floor, &mut |r: &str| {
                let s = scripts.iter().find(|s| s.rel == r)?;
                let applies = applied
                    .iter()
                    .filter(|(from, _, _)| from == r)
                    .map(|(_, at, to)| (*at, to.clone()))
                    .collect();
                Some((s.text.clone(), s.dsl, applies))
            });
        }
        self.graph.unresolved.append(&mut info.unresolved);

        let mut projects = vec![Project {
            path: ":".into(),
            dir: dir.to_string(),
            build_script: None,
        }];
        projects.extend(info.projects.iter().map(|(path, d)| Project {
            path: path.clone(),
            dir: d.clone(),
            build_script: None,
        }));
        for p in &mut projects {
            let custom = info
                .build_files
                .iter()
                .rev()
                .find(|(path, _)| *path == p.path)
                .map(|(_, name)| name.clone());
            let found = match custom {
                Some(name) => {
                    let rel = join_rel(&p.dir, &name);
                    self.read_capped(&rel).map(|t| (rel, t))
                }
                None => self.find_script(&p.dir, "build"),
            };
            if let Some((rel, text)) = found {
                p.build_script = Some(rel.clone());
                let here = p.dir.clone();
                self.add_script(rel, text, ScriptKind::Build, dir, Some(&here), 0, false);
            }
        }
        if kind != BuildKind::Root {
            for p in &projects {
                // Binary plugins live in buildSrc and in the plugin
                // projects of included builds; other included builds are
                // product code.
                let sources = kind == BuildKind::BuildSrc
                    || p.build_script.as_ref().is_some_and(|b| {
                        self.graph.scripts.iter().any(|s| {
                            s.rel == *b && PLUGIN_PROJECT_MARKERS.iter().any(|m| s.text.contains(m))
                        })
                    });
                self.convention_plugins(dir, &p.dir, sources);
            }
        }
        let default_catalog = join_rel(dir, "gradle/libs.versions.toml");
        self.add_catalog(&default_catalog);
        for c in &info.catalogs {
            if !self.add_catalog(c) {
                let rel = settings_rel.clone().unwrap_or_default();
                self.unresolved(&rel, 0, Site::Catalog, Reason::Missing, c.clone());
            }
        }
        let included = info.included_builds.clone();
        self.graph.builds.push(Build {
            dir: dir.to_string(),
            kind,
            settings: settings_rel.clone(),
            projects,
        });

        if kind != BuildKind::BuildSrc && self.has_dir(dir, "buildSrc") {
            let bsrc = join_rel(dir, "buildSrc");
            if depth < MAX_DEPTH {
                self.collect_build(&bsrc, BuildKind::BuildSrc, depth + 1);
            }
        }
        for target in included {
            if depth >= MAX_DEPTH {
                let rel = settings_rel.clone().unwrap_or_default();
                self.unresolved(&rel, 0, Site::IncludeBuild, Reason::DepthCap, target);
                continue;
            }
            if (self.list)(&target).is_empty() {
                let rel = settings_rel.clone().unwrap_or_default();
                self.unresolved(&rel, 0, Site::IncludeBuild, Reason::Missing, target);
                continue;
            }
            self.collect_build(&target, BuildKind::Included, depth + 1);
        }
    }
}

/// `(line, first, last)` token ranges of every `apply from` target.
fn apply_from_targets(text: &str, toks: &[Token]) -> Vec<(usize, usize, usize)> {
    let mut out = Vec::new();
    for call in call_sites(text, toks, "apply") {
        if let Some(arg) = call.args.iter().find(|a| a.name.as_deref() == Some("from")) {
            out.push((call.line, arg.first, arg.last));
        }
        // `apply { from 'x' }` / `apply { from("x") }`.
        if let Some((open, close)) = call.closure.filter(|_| call.args.is_empty()) {
            for i in open + 1..close {
                if !is_ident(toks.get(i), "from") {
                    continue;
                }
                if let Some(inner) = call_at(text, toks, i) {
                    if let Some(arg) = inner.args.first() {
                        out.push((inner.line, arg.first, arg.last));
                    }
                }
            }
        }
    }
    out
}

impl ScriptGraph {
    /// Collect the graph of the checkout at `root_rel`. `init_scripts` are
    /// `(path or tag, text)` of the Gradle init scripts that apply (the
    /// caller reads them, see `home::GradleHome::init_scripts_with`).
    pub fn collect(
        read: TextReadFn<'_>,
        list: ListFn<'_>,
        root_rel: &str,
        init_scripts: &[(String, String)],
    ) -> Self {
        let mut c = Collector {
            read,
            list,
            floor: root_rel.to_string(),
            graph: ScriptGraph {
                root: root_rel.to_string(),
                ..Self::default()
            },
            seen: BTreeSet::new(),
            applied: Vec::new(),
            files: 0,
            capped: false,
        };
        c.collect_build(root_rel, BuildKind::Root, 0);
        for (tag, text) in init_scripts {
            if c.files >= MAX_FILES || text.len() > MAX_FILE_BYTES {
                c.graph.init_unparseable.push(tag.clone());
                continue;
            }
            c.files += 1;
            let text = crate::formats::text::strip_bom(text).to_string();
            let dsl = dsl::dsl_of(tag).unwrap_or(Dsl::Groovy);
            if !dsl::well_formed(&text, dsl) {
                c.graph.init_unparseable.push(tag.clone());
            }
            // Relative `apply from` in an init script is relative to the
            // init script, which is outside the checkout.
            c.add_script(tag.clone(), text, ScriptKind::Init, "", None, 0, false);
        }
        c.graph
    }

    /// Record an init script that exists but could not be read (not UTF-8,
    /// permission denied): `maven_local` is then undetermined.
    pub fn note_unreadable_init_script(&mut self, tag: &str) {
        self.init_unparseable.push(tag.to_string());
    }

    /// Every script of the checkout (no init scripts).
    pub fn checkout_scripts(&self) -> impl Iterator<Item = &Script> {
        self.scripts.iter().filter(|s| s.kind != ScriptKind::Init)
    }

    /// The scripts that configure projects: build scripts, convention
    /// plugins (and binary plugin sources) and `apply from` targets.
    pub fn build_scripts(&self) -> impl Iterator<Item = &Script> {
        self.scripts.iter().filter(|s| {
            matches!(
                s.kind,
                ScriptKind::Build
                    | ScriptKind::ConventionPlugin
                    | ScriptKind::PluginSource
                    | ScriptKind::Applied
            )
        })
    }

    /// The included projects of every build (root projects excluded).
    pub fn settings_includes(&self) -> Vec<&Project> {
        self.builds
            .iter()
            .flat_map(|b| b.projects.iter().filter(|p| p.path != ":"))
            .collect()
    }

    /// Every project directory of every build.
    pub fn project_dirs(&self) -> Vec<&str> {
        self.builds
            .iter()
            .flat_map(|b| b.projects.iter().map(|p| p.dir.as_str()))
            .collect()
    }

    /// The lock files of every project of every build (root, subprojects,
    /// `buildSrc`, included builds and theirs), legacy layout included;
    /// nested builds the checkout does not include are left out. See
    /// [`locks::lockfile_paths_in`].
    pub fn lockfile_paths(&self, list: ListFn<'_>) -> Vec<String> {
        locks::lockfile_paths_in(list, &self.project_dirs())
    }

    /// Every declaration of `group:artifact` in the checkout's scripts and
    /// version catalogs.
    pub fn declarations_of(&self, group: &str, artifact: &str) -> Vec<Decl> {
        let mut out: Vec<Decl> = self
            .checkout_scripts()
            .flat_map(|s| script_decls(s, group, artifact).into_iter().map(|(d, _)| d))
            .collect();
        for c in &self.catalogs {
            out.extend(catalog_decls(c, group, artifact));
        }
        out
    }

    /// Every `exclusiveContent` block (init scripts included).
    pub fn exclusive_content_filters(&self) -> Vec<ExclusiveFilter> {
        self.scripts.iter().flat_map(exclusive_filters).collect()
    }

    /// The first Android or Kotlin Multiplatform plugin reference:
    /// `(script or catalog, plugin id)`. A version catalog's `[plugins]`
    /// entry counts, since `alias(libs.plugins.…)` names the plugin only
    /// there.
    pub fn android_or_kmp(&self) -> Option<(String, String)> {
        let in_scripts = self.checkout_scripts().find_map(|s| {
            let toks = dsl::tokens(&s.text, s.dsl);
            let by_id = dsl::strings(&toks)
                .find(|v| is_android_or_kmp_id(v))
                .map(str::to_string);
            let by_kotlin = || {
                toks.windows(4).find_map(|w| {
                    let kmp = is_ident(Some(&w[0]), "kotlin")
                        && is_punct(Some(&w[1]), b'(')
                        && literal_of(Some(&w[2])) == Some("multiplatform")
                        && is_punct(Some(&w[3]), b')');
                    kmp.then(|| "kotlin(\"multiplatform\")".to_string())
                })
            };
            by_id.or_else(by_kotlin).map(|id| (s.rel.clone(), id))
        });
        in_scripts.or_else(|| {
            self.catalogs.iter().find_map(|c| {
                catalog_plugin_ids(c)
                    .into_iter()
                    .find(|id| is_android_or_kmp_id(id))
                    .map(|id| (c.rel.clone(), id))
            })
        })
    }

    /// Whether `group:artifact` is on a settings-script classpath: a
    /// declaration inside a settings `buildscript {}` block, or a
    /// `useModule(…)` plugin resolution rule.
    pub fn settings_classpath_has(&self, group: &str, artifact: &str) -> bool {
        self.scripts
            .iter()
            .filter(|s| s.kind == ScriptKind::Settings)
            .any(|s| {
                let toks = dsl::tokens(&s.text, s.dsl);
                let mut ranges = all_blocks(&toks, "buildscript");
                ranges.extend(
                    call_sites(&s.text, &toks, "useModule")
                        .into_iter()
                        .map(|c| (c.callee, c.end)),
                );
                script_decls(s, group, artifact)
                    .iter()
                    .any(|(_, at)| ranges.iter().any(|(o, c)| at > o && at < c))
            })
    }

    /// Whether `mavenLocal()` / `mavenLocal { … }` (or a repository URL
    /// into `.m2/repository`) is declared anywhere, init scripts included.
    pub fn maven_local(&self) -> MavenLocal {
        for s in &self.scripts {
            let toks = dsl::tokens(&s.text, s.dsl);
            let call = (0..toks.len()).any(|i| {
                is_ident(toks.get(i), "mavenLocal")
                    && (is_punct(toks.get(i + 1), b'(') || is_punct(toks.get(i + 1), b'{'))
            });
            let url = dsl::strings(&toks).any(|v| {
                v.contains(".m2/repository")
                    || v.contains(".m2\\\\repository")
                    || v.contains(".m2\\repository")
            });
            if call || url {
                return MavenLocal::Declared(s.rel.clone());
            }
        }
        if let Some(tag) = self.init_unparseable.first() {
            return MavenLocal::Undetermined(format!("init script {tag} could not be parsed"));
        }
        if let Some(u) = self.unresolved.first() {
            let what = if u.snippet.is_empty() {
                format!("{:?}", u.reason)
            } else {
                u.snippet.clone()
            };
            return MavenLocal::Undetermined(format!(
                "{}:{}: {what} could not be followed",
                u.rel, u.line
            ));
        }
        MavenLocal::NotDeclared
    }

    /// The first script setting a custom dependency-lock file location
    /// (`lockFile = …` / `lockFile.set(…)`).
    pub fn custom_lock_file(&self) -> Option<String> {
        self.scripts.iter().find_map(|s| {
            let toks = dsl::tokens(&s.text, s.dsl);
            (0..toks.len())
                .any(|i| {
                    is_ident(toks.get(i), "lockFile")
                        && ((is_punct(toks.get(i + 1), b'=') && !is_punct(toks.get(i + 2), b'='))
                            || (is_punct(toks.get(i + 1), b'.')
                                && is_ident(toks.get(i + 2), "set")
                                && is_punct(toks.get(i + 3), b'(')))
                })
                .then(|| s.rel.clone())
        })
    }
}

/// The subproject relation of a directory to an ancestor build: whether
/// the settings script at `ancestor_settings` makes `rel_dir` (relative to
/// that script's directory) one of its projects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owner {
    /// It does; the build root is this directory.
    Owned(String),
    /// Its includes cannot be read literally, so it might.
    Unparseable(String),
}

/// See [`Owner`]. `None` when the ancestor's settings is missing, or names
/// every project literally (in itself and the scripts it applies) and none
/// of them lives at `rel_dir`.
pub fn subproject_owner(
    read: TextReadFn<'_>,
    ancestor_settings: &str,
    rel_dir: &str,
) -> Option<Owner> {
    read(ancestor_settings)?;
    let dir = parent_rel(ancestor_settings);
    let want = resolve_rel(dir, dir, rel_dir)?;
    if want == dir {
        return None;
    }
    let mut problems: Vec<Unresolved> = Vec::new();
    let mut files = 0usize;
    let info = settings_info(ancestor_settings, dir, "", &mut |r: &str| {
        let issue = |reason| Unresolved {
            rel: r.to_string(),
            line: 0,
            site: Site::Script,
            reason,
            snippet: String::new(),
        };
        let text = read(r)?;
        files += 1;
        if files > MAX_FILES {
            problems.push(issue(Reason::FileCap));
            return None;
        }
        if text.len() > MAX_FILE_BYTES {
            problems.push(issue(Reason::TooLarge));
            return None;
        }
        let text = crate::formats::text::strip_bom(&text).to_string();
        let dsl = dsl::dsl_of(r).unwrap_or(Dsl::Groovy);
        if !dsl::well_formed(&text, dsl) {
            problems.push(issue(Reason::Unparseable));
        }
        let toks = dsl::tokens(&text, dsl);
        let mut applies = Vec::new();
        for (line, first, last) in apply_from_targets(&text, &toks) {
            match resolve_path("", dir, parent_rel(r), &toks[first..last]) {
                Ok(target) => applies.push((toks[first].start, target)),
                Err(reason) => problems.push(Unresolved {
                    rel: r.to_string(),
                    line,
                    site: Site::ApplyFrom,
                    reason,
                    snippet: snippet(&text, &toks, first, last),
                }),
            }
        }
        Some((text, dsl, applies))
    });
    if info.projects.iter().any(|(_, d)| *d == want) {
        return Some(Owner::Owned(dir.to_string()));
    }
    let unparseable = problems.iter().chain(&info.unresolved).any(|u| {
        matches!(
            u.site,
            Site::Include | Site::ProjectDir | Site::ApplyFrom | Site::Script
        )
    });
    unparseable.then(|| Owner::Unparseable(dir.to_string()))
}

/// The Gradle version of the wrapper under `root`, from
/// `gradle/wrapper/gradle-wrapper.properties`.
pub fn wrapper_version(read: TextReadFn<'_>, root: &str) -> Option<(u32, u32, u32)> {
    let text = read(&join_rel(root, "gradle/wrapper/gradle-wrapper.properties"))?;
    let url = crate::formats::text::strip_bom(&text)
        .lines()
        .find_map(|line| {
            let line = line.trim_start();
            let rest = line.strip_prefix("distributionUrl")?;
            let rest = rest.trim_start();
            let rest = rest
                .strip_prefix('=')
                .or_else(|| rest.strip_prefix(':'))
                .unwrap_or(rest);
            Some(rest.trim().replace('\\', ""))
        })?;
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"gradle-(\d+)\.(\d+)(?:\.(\d+))?").expect("valid wrapper regex")
    });
    let caps = re.captures(&url)?;
    Some((
        caps[1].parse().ok()?,
        caps[2].parse().ok()?,
        caps.get(3).map_or(Some(0), |m| m.as_str().parse().ok())?,
    ))
}

// ── declarations ────────────────────────────────────────────────────────────────

fn kind_of(
    version: Option<&str>,
    rich: &Option<RichVersion>,
    classifier: &Option<String>,
) -> DeclKind {
    if classifier.is_some() {
        DeclKind::Classifier
    } else if let Some(r) = rich {
        DeclKind::Rich(r.clone())
    } else if matches!(
        version.map(parse_selector),
        Some(Selector::Range { .. } | Selector::Prefix(_) | Selector::Latest(_))
    ) {
        DeclKind::Range
    } else {
        DeclKind::Plain
    }
}

/// Split a `…!!…` strict shorthand: `1.0!!` → strictly 1.0;
/// `[1,2)!!1.5` → strictly `[1,2)`, prefer 1.5.
fn bang_bang(version: &str) -> Option<RichVersion> {
    let (strict, prefer) = version.split_once("!!")?;
    Some(RichVersion {
        strictly: Some(strict.to_string()),
        prefer: (!prefer.is_empty()).then(|| prefer.to_string()),
        ..RichVersion::default()
    })
}

/// The rich version and classifier set in a dependency's configuration
/// closure `toks[open..=close]`.
fn closure_details(
    text: &str,
    toks: &[Token],
    open: usize,
    close: usize,
) -> (Option<RichVersion>, Option<String>) {
    let body = &toks[open..=close];
    let mut rich: Option<RichVersion> = None;
    for (o, c) in all_blocks(body, "version") {
        let r = rich.get_or_insert_with(RichVersion::default);
        let inner = &body[o..=c];
        for name in ["strictly", "require", "prefer", "reject"] {
            for call in call_sites(text, inner, name) {
                let vals: Vec<String> =
                    call.args.iter().filter_map(|a| a.literal.clone()).collect();
                match name {
                    "strictly" => r.strictly = vals.into_iter().next().or(r.strictly.take()),
                    "require" => r.require = vals.into_iter().next().or(r.require.take()),
                    "prefer" => r.prefer = vals.into_iter().next().or(r.prefer.take()),
                    _ => r.reject.extend(vals),
                }
            }
        }
    }
    let mut classifier = None;
    for (o, c) in all_blocks(body, "artifact") {
        let inner = &body[o..=c];
        for (i, t) in inner.iter().enumerate() {
            if !matches!(&t.tok, Tok::Ident(n) if n == "classifier") {
                continue;
            }
            // `classifier = 'c'`, `classifier("c")` or `classifier 'c'`.
            let v = if is_punct(inner.get(i + 1), b'=') || is_punct(inner.get(i + 1), b'(') {
                literal_of(inner.get(i + 2))
            } else {
                literal_of(inner.get(i + 1))
            };
            if let Some(v) = v {
                classifier = Some(v.to_string());
            }
        }
    }
    (rich, classifier)
}

/// Every declaration of `g:a` in one script, with the token index it sits
/// at.
fn script_decls(s: &Script, g: &str, a: &str) -> Vec<(Decl, usize)> {
    let text = &s.text;
    let toks = dsl::tokens(text, s.dsl);
    let mut out = Vec::new();
    let mut push = |at: usize,
                    version: Option<String>,
                    mut rich: Option<RichVersion>,
                    classifier: Option<String>,
                    closure: Option<(usize, usize)>| {
        let mut classifier = classifier;
        if let Some((o, c)) = closure {
            let (r, cl) = closure_details(text, &toks, o, c);
            if let Some(r) = r {
                let base = rich.take().unwrap_or_default();
                rich = Some(RichVersion {
                    strictly: r.strictly.or(base.strictly),
                    require: r.require.or(base.require),
                    prefer: r.prefer.or(base.prefer),
                    reject: [base.reject, r.reject].concat(),
                });
            }
            classifier = classifier.or(cl);
        }
        let kind = kind_of(version.as_deref(), &rich, &classifier);
        out.push((
            Decl {
                rel: s.rel.clone(),
                line: line_of(text, toks[at].start),
                kind,
                version,
                rich,
                classifier,
            },
            at,
        ));
    };

    for (i, t) in toks.iter().enumerate() {
        let Tok::Str { value, literal } = &t.tok else {
            continue;
        };
        // String notation `g:a[:v[:classifier]][@ext]`.
        let parts: Vec<&str> = value.split(':').collect();
        if parts.len() >= 2
            && parts.len() <= 4
            && parts[0] == g
            && parts[1].split('@').next() == Some(a)
        {
            let strip_ext = |p: &str| p.split('@').next().unwrap_or("").to_string();
            let mut version = parts.get(2).map(|v| strip_ext(v)).filter(|v| !v.is_empty());
            if !literal && version.as_deref().is_some_and(|v| v.contains('$')) {
                version = None;
            }
            let classifier = parts
                .get(3)
                .map(|c| strip_ext(c))
                .filter(|c| !c.is_empty() && !c.contains('$'));
            let rich = version.as_deref().and_then(bang_bang);
            let closure = (is_punct(toks.get(i.wrapping_sub(1)), b'(')
                && is_punct(toks.get(i + 1), b')')
                && is_punct(toks.get(i + 2), b'{'))
            .then(|| matching_close(&toks, i + 2).map(|c| (i + 2, c)))
            .flatten();
            push(i, version, rich, classifier, closure);
            continue;
        }
        // Kotlin positional `f("g", "a", "v", conf, "classifier")`.
        if *literal
            && value == g
            && i >= 2
            && is_punct(toks.get(i - 1), b'(')
            && is_punct(toks.get(i + 1), b',')
            && literal_of(toks.get(i + 2)) == Some(a)
        {
            if let Some(call) = call_at(text, &toks, i - 2) {
                let pos: Vec<&dsl::CallArg> =
                    call.args.iter().filter(|x| x.name.is_none()).collect();
                if pos.len() >= 2 && pos[0].first == i {
                    let version = pos.get(2).and_then(|x| x.literal.clone());
                    let classifier = pos.get(4).and_then(|x| x.literal.clone());
                    let rich = version.as_deref().and_then(bang_bang);
                    push(i, version, rich, classifier, call.closure);
                }
            }
        }
    }

    // Map notation: `group: 'g', name: 'a', …` / `group = "g", name = "a"`.
    for i in 0..toks.len() {
        let key = match &toks[i].tok {
            Tok::Ident(n) => n.as_str(),
            Tok::Str {
                value,
                literal: true,
            } => value.as_str(),
            _ => continue,
        };
        if key != "group"
            || !(is_punct(toks.get(i + 1), b':')
                || (is_punct(toks.get(i + 1), b'=') && !is_punct(toks.get(i + 2), b'=')))
            || literal_of(toks.get(i + 2)) != Some(g)
        {
            continue;
        }
        let Some(call) = enclosing_call(text, &toks, i) else {
            continue;
        };
        if call.named("name") != Some(Some(a)) {
            continue;
        }
        let version = call.named("version").flatten().map(str::to_string);
        let classifier = call.named("classifier").flatten().map(str::to_string);
        let rich = version.as_deref().and_then(bang_bang);
        push(i, version, rich, classifier, call.closure);
    }
    out
}

/// The call whose argument list holds token `i`.
fn enclosing_call(text: &str, toks: &[Token], i: usize) -> Option<dsl::CallSite> {
    // Inside parentheses: the nearest unmatched `(`.
    let mut depth = 0isize;
    let mut j = i;
    while j > 0 {
        j -= 1;
        match toks[j].tok {
            Tok::Punct(b')' | b']') => depth += 1,
            Tok::Punct(b'(' | b'[') if depth > 0 => depth -= 1,
            Tok::Punct(b'(') => {
                let call = call_at(text, toks, j.checked_sub(1)?)?;
                return (call.args.iter().any(|a| a.first <= i + 2 && i < a.last)).then_some(call);
            }
            Tok::Punct(b'[') => return None,
            Tok::Punct(b'{' | b'}' | b';') if depth == 0 => break,
            _ => {}
        }
        if depth == 0 && dsl::newline_between(text, toks, j, j + 1) && !is_punct(toks.get(j), b',')
        {
            j += 1;
            break;
        }
    }
    // A Groovy command expression starting the statement.
    let start = if matches!(
        toks.get(j).map(|t| &t.tok),
        Some(Tok::Punct(b'{' | b'}' | b';'))
    ) {
        j + 1
    } else {
        j
    };
    let call = call_at(text, toks, start)?;
    (call.args.iter().any(|a| a.first <= i + 2 && i < a.last)).then_some(call)
}

fn is_android_or_kmp_id(id: &str) -> bool {
    id.starts_with("com.android.") || id.starts_with("org.jetbrains.kotlin.multiplatform")
}

/// The plugin ids of a catalog's `[plugins]` (`{ id = "…" }` or `"id:version"`).
fn catalog_plugin_ids(c: &Catalog) -> Vec<String> {
    use toml_edit::{Document, Item};
    let Ok(doc) = Document::parse(c.text.as_str()) else {
        return Vec::new();
    };
    let Some(plugins) = doc.get("plugins").and_then(Item::as_table_like) else {
        return Vec::new();
    };
    plugins
        .iter()
        .filter_map(|(_, item)| match item.as_str() {
            Some(s) => Some(s.split(':').next().unwrap_or(s).to_string()),
            None => item
                .as_table_like()
                .and_then(|t| t.get("id"))
                .and_then(Item::as_str)
                .map(str::to_string),
        })
        .collect()
}

fn catalog_decls(c: &Catalog, g: &str, a: &str) -> Vec<Decl> {
    use toml_edit::{Document, Item, Value};
    let Ok(doc) = Document::parse(c.text.as_str()) else {
        return Vec::new();
    };
    let versions = doc.get("versions").and_then(Item::as_table_like);
    let rich_of = |item: Option<&Item>| -> (Option<String>, Option<RichVersion>) {
        let Some(item) = item else {
            return (None, None);
        };
        if let Some(s) = item.as_str() {
            return (Some(s.to_string()), None);
        }
        let Some(t) = item.as_table_like() else {
            return (None, None);
        };
        if let Some(r) = t.get("ref").and_then(Item::as_str) {
            let target = versions.and_then(|v| v.get(r));
            if let Some(s) = target.and_then(Item::as_str) {
                return (Some(s.to_string()), None);
            }
            return match target.and_then(Item::as_table_like) {
                Some(rt) => rich_table(rt),
                None => (None, None),
            };
        }
        rich_table(t)
    };
    fn rich_table(t: &dyn toml_edit::TableLike) -> (Option<String>, Option<RichVersion>) {
        let s = |k: &str| t.get(k).and_then(Item::as_str).map(str::to_string);
        let reject = t
            .get("reject")
            .and_then(Item::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let rich = RichVersion {
            strictly: s("strictly"),
            require: s("require"),
            prefer: s("prefer"),
            reject,
        };
        let version = rich.require.clone().or_else(|| rich.strictly.clone());
        let is_rich = rich.strictly.is_some() || rich.prefer.is_some() || !rich.reject.is_empty();
        (version, is_rich.then_some(rich))
    }
    let Some(libs) = doc.get("libraries").and_then(Item::as_table_like) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (key, item) in libs.iter() {
        let line = libs
            .get_key_value(key)
            .and_then(|(k, _)| k.span())
            .map_or(0, |sp| line_of(&c.text, sp.start));
        let (module, version, rich) = if let Some(s) = item.as_str() {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() < 2 {
                continue;
            }
            (
                (parts[0].to_string(), parts[1].to_string()),
                parts.get(2).map(|v| v.to_string()),
                None,
            )
        } else if let Some(t) = item.as_table_like() {
            let module = match t.get("module").and_then(Item::as_str) {
                Some(m) => match m.split_once(':') {
                    Some((mg, ma)) => (mg.to_string(), ma.to_string()),
                    None => continue,
                },
                None => match (
                    t.get("group").and_then(Item::as_str),
                    t.get("name").and_then(Item::as_str),
                ) {
                    (Some(mg), Some(ma)) => (mg.to_string(), ma.to_string()),
                    _ => continue,
                },
            };
            let (version, rich) = rich_of(t.get("version"));
            (module, version, rich)
        } else {
            continue;
        };
        if module.0 != g || module.1 != a {
            continue;
        }
        out.push(Decl {
            rel: c.rel.clone(),
            line,
            kind: DeclKind::Catalog,
            version,
            rich,
            classifier: None,
        });
    }
    out
}

fn exclusive_filters(s: &Script) -> Vec<ExclusiveFilter> {
    let toks = dsl::tokens(&s.text, s.dsl);
    let mut out = Vec::new();
    for (open, close) in all_blocks(&toks, "exclusiveContent") {
        let body = &toks[open..=close];
        let mut repo_strings = Vec::new();
        for (o, c) in all_blocks(body, "forRepository") {
            repo_strings.extend(dsl::strings(&body[o..=c]).map(str::to_string));
        }
        // `forRepository(…)` (Kotlin `forRepository { … }` is above).
        for call in call_sites(&s.text, body, "forRepository") {
            for arg in &call.args {
                repo_strings.extend(dsl::strings(&body[arg.first..arg.last]).map(str::to_string));
            }
        }
        let mut rules = Vec::new();
        for (o, c) in all_blocks(body, "filter") {
            let inner = &body[o..=c];
            for (name, kind) in [
                ("includeGroup", FilterKind::Group),
                ("includeGroupAndSubgroups", FilterKind::GroupAndSubgroups),
                ("includeGroupByRegex", FilterKind::GroupByRegex),
                ("includeModule", FilterKind::Module),
                ("includeModuleByRegex", FilterKind::ModuleByRegex),
                ("includeVersion", FilterKind::Version),
                ("includeVersionByRegex", FilterKind::VersionByRegex),
            ] {
                for call in call_sites(&s.text, inner, name) {
                    rules.push(FilterRule {
                        kind,
                        args: call.args.iter().map(|a| a.literal.clone()).collect(),
                    });
                }
            }
        }
        out.push(ExclusiveFilter {
            rel: s.rel.clone(),
            line: line_of(&s.text, toks[open].start),
            repo_strings,
            rules,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::test_fs::MemFs;
    use super::*;

    const G: &str = "com.socketfixture";
    const A: &str = "victim";

    fn graph(files: &[(&str, &str)]) -> ScriptGraph {
        graph_with_init(files, &[])
    }

    fn graph_with_init(files: &[(&str, &str)], init: &[(&str, &str)]) -> ScriptGraph {
        let fs = MemFs::new(files);
        let init: Vec<(String, String)> = init
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        ScriptGraph::collect(&|r: &str| fs.read(r), &|d: &str| fs.list(d), "", &init)
    }

    fn rels(g: &ScriptGraph, kind: ScriptKind) -> Vec<&str> {
        g.scripts
            .iter()
            .filter(|s| s.kind == kind)
            .map(|s| s.rel.as_str())
            .collect()
    }

    fn projects(g: &ScriptGraph) -> Vec<(String, String)> {
        g.settings_includes()
            .iter()
            .map(|p| (p.path.clone(), p.dir.clone()))
            .collect()
    }

    fn pair(a: &str, b: &str) -> (String, String) {
        (a.to_string(), b.to_string())
    }

    // ── #428: include forms, projectDir overrides ───────────────────────────────

    #[test]
    fn groovy_include_forms_and_project_dir_override() {
        let g = graph(&[
            (
                "settings.gradle",
                "rootProject.name = 'x'\ninclude ':app', 'lib'\ninclude 'libs:core'\nsettings.include(\":tools\")\nproject(':lib').projectDir = file('modules/lib')\nproject(':tools').projectDir = new File(settingsDir, 'dev/tools')\n",
            ),
            ("build.gradle", ""),
            ("app/build.gradle", ""),
            ("modules/lib/build.gradle.kts", ""),
            ("libs/core/build.gradle", ""),
        ]);
        assert_eq!(
            projects(&g),
            [
                pair(":app", "app"),
                pair(":lib", "modules/lib"),
                pair(":libs", "libs"),
                pair(":libs:core", "libs/core"),
                pair(":tools", "dev/tools"),
            ]
        );
        assert_eq!(
            rels(&g, ScriptKind::Build),
            [
                "build.gradle",
                "app/build.gradle",
                "modules/lib/build.gradle.kts",
                "libs/core/build.gradle"
            ]
        );
        assert!(g.unresolved.is_empty(), "{:?}", g.unresolved);
    }

    #[test]
    fn kotlin_include_forms_and_unparseable_list() {
        let g = graph(&[
            (
                "settings.gradle.kts",
                "include(\":app\", \"lib\")\nproject(\":app\").projectDir = File(settingsDir, \"apps/app\")\nfindProject(\":lib\")?.projectDir = file(\"modules/lib\")\ninclude(listOf(\"x\"))\n",
            ),
            ("apps/app/build.gradle.kts", ""),
        ]);
        assert_eq!(
            projects(&g),
            [pair(":app", "apps/app"), pair(":lib", "modules/lib")]
        );
        assert_eq!(g.unresolved.len(), 1, "{:?}", g.unresolved);
        let u = &g.unresolved[0];
        assert_eq!(
            (u.site, u.reason, u.line),
            (Site::Include, Reason::NonLiteral, 4)
        );
        assert_eq!(u.snippet, "include(listOf(\"x\"))");
    }

    #[test]
    fn settings_applied_scripts_include_projects() {
        let files: &[(&str, &str)] = &[
            (
                "settings.gradle",
                "apply from: 'gradle/modules.gradle'\nproject(':lib').projectDir = file('libs/lib')\n",
            ),
            // Relative paths in a script applied to settings resolve
            // against that script's directory.
            (
                "gradle/modules.gradle",
                "include ':app', ':lib'\nproject(':app').projectDir = file('../apps/app')\napply from: 'more.gradle'\nincludeBuild 'tools'\n",
            ),
            ("gradle/more.gradle", "include ':extra'\n"),
            (
                "apps/app/build.gradle",
                "dependencies { implementation 'com.socketfixture:victim:1.10.0' }\n",
            ),
            ("tools/settings.gradle", ""),
        ];
        let g = graph(files);
        assert!(g.unresolved.is_empty(), "{:?}", g.unresolved);
        assert_eq!(
            projects(&g),
            [
                pair(":app", "apps/app"),
                pair(":lib", "libs/lib"),
                pair(":extra", "extra"),
            ]
        );
        assert_eq!(g.declarations_of(G, A).len(), 1);
        assert_eq!(
            g.builds.iter().map(|b| b.dir.as_str()).collect::<Vec<_>>(),
            ["", "tools"]
        );
        let fs = MemFs::new(files);
        let read = |r: &str| fs.read(r);
        assert_eq!(
            subproject_owner(&read, "settings.gradle", "apps/app"),
            Some(Owner::Owned(String::new()))
        );
        assert_eq!(
            subproject_owner(&read, "settings.gradle", "extra"),
            Some(Owner::Owned(String::new()))
        );
        assert_eq!(subproject_owner(&read, "settings.gradle", "app"), None);

        // A settings-level `apply from` that cannot be followed hides
        // projects: the graph is undetermined and ownership unknown.
        let files: &[(&str, &str)] = &[
            (
                "settings.gradle",
                "apply from: \"$gradleDir/modules.gradle\"\n",
            ),
            ("nested/settings.gradle", "apply from: 'missing.gradle'\n"),
        ];
        let g = graph(files);
        assert!(matches!(g.maven_local(), MavenLocal::Undetermined(_)));
        let fs = MemFs::new(files);
        let read = |r: &str| fs.read(r);
        assert_eq!(
            subproject_owner(&read, "settings.gradle", "app"),
            Some(Owner::Unparseable(String::new()))
        );
        assert_eq!(
            subproject_owner(&read, "nested/settings.gradle", "app"),
            Some(Owner::Unparseable("nested".into()))
        );
    }

    #[test]
    fn includes_follow_the_parent_directory_in_order() {
        // Measured on Gradle 6.9.4 and 8.14.3: a child included after its
        // parent moved lives under the parent's new directory; one
        // included before stays where it was created.
        let g = graph(&[(
            "settings.gradle",
            "include ':a'\nproject(':a').projectDir = file('modules/a')\ninclude ':a:b'\ninclude ':x:y'\nproject(':x').projectDir = file('xx')\n",
        )]);
        assert_eq!(
            projects(&g),
            [
                pair(":a", "modules/a"),
                pair(":a:b", "modules/a/b"),
                pair(":x", "xx"),
                pair(":x:y", "x/y"),
            ]
        );
    }

    #[test]
    fn subproject_owner_cases() {
        let fs = MemFs::new(&[
            (
                "settings.gradle",
                "include ':app', 'lib'\nproject(':lib').projectDir = file('modules/lib')\nincludeBuild 'tools'\n",
            ),
            ("k/settings.gradle.kts", "include(listOf(\"x\"))\ninclude(\":a\")\n"),
            ("d/settings.gradle", "include ':a'\nrootProject.children.each { it.projectDir = file(\"m/${it.name}\") }\n"),
        ]);
        let read = |r: &str| fs.read(r);
        assert_eq!(
            subproject_owner(&read, "settings.gradle", "modules/lib"),
            Some(Owner::Owned(String::new()))
        );
        assert_eq!(
            subproject_owner(&read, "settings.gradle", "app/"),
            Some(Owner::Owned(String::new()))
        );
        assert_eq!(subproject_owner(&read, "settings.gradle", "lib"), None);
        assert_eq!(subproject_owner(&read, "settings.gradle", "tools"), None);
        assert_eq!(subproject_owner(&read, "settings.gradle", ""), None);
        assert_eq!(
            subproject_owner(&read, "k/settings.gradle.kts", "a"),
            Some(Owner::Owned("k".into()))
        );
        assert_eq!(
            subproject_owner(&read, "k/settings.gradle.kts", "zzz"),
            Some(Owner::Unparseable("k".into()))
        );
        assert_eq!(
            subproject_owner(&read, "d/settings.gradle", "m/a"),
            Some(Owner::Unparseable("d".into()))
        );
        assert_eq!(
            subproject_owner(&read, "missing/settings.gradle", "a"),
            None
        );
    }

    // ── #461: the whole script graph ────────────────────────────────────────────

    #[test]
    fn follows_subprojects_build_src_included_builds_and_apply_from() {
        let g = graph(&[
            (
                "settings.gradle.kts",
                "pluginManagement { includeBuild(\"build-logic\") }\ninclude(\"sub\")\n",
            ),
            (
                "build.gradle",
                "apply from: \"$rootDir/gradle/a.gradle\"\nallprojects { apply plugin: 'java' }\n",
            ),
            (
                "gradle/a.gradle",
                "apply from: rootProject.file('gradle/b.gradle')\n",
            ),
            // A cycle back to a.gradle is followed once.
            ("gradle/b.gradle", "apply from: file('gradle/a.gradle')\n"),
            (
                "sub/build.gradle.kts",
                "apply(from = \"deps.gradle.kts\")\napply { from(\"$rootDir/gradle/c.gradle\") }\n",
            ),
            ("sub/deps.gradle.kts", ""),
            ("gradle/c.gradle", ""),
            ("buildSrc/build.gradle.kts", "plugins { `kotlin-dsl` }\n"),
            (
                "buildSrc/src/main/kotlin/my.conventions.gradle.kts",
                "plugins { java }\n",
            ),
            ("buildSrc/src/main/groovy/deep/x/old.conventions.gradle", ""),
            (
                "build-logic/settings.gradle.kts",
                "include(\"convention\")\n",
            ),
            ("build-logic/convention/build.gradle.kts", ""),
            (
                "build-logic/convention/src/main/kotlin/socket.java.gradle.kts",
                "repositories { mavenCentral() }\n",
            ),
            ("build-logic/convention/src/main/kotlin/Helper.kt", ""),
        ]);
        assert!(g.unresolved.is_empty(), "{:?}", g.unresolved);
        assert_eq!(
            rels(&g, ScriptKind::Settings),
            ["settings.gradle.kts", "build-logic/settings.gradle.kts"]
        );
        assert_eq!(
            rels(&g, ScriptKind::Applied),
            [
                "gradle/a.gradle",
                "gradle/b.gradle",
                "sub/deps.gradle.kts",
                "gradle/c.gradle"
            ]
        );
        let mut conv = rels(&g, ScriptKind::ConventionPlugin);
        conv.sort();
        assert_eq!(
            conv,
            [
                "build-logic/convention/src/main/kotlin/socket.java.gradle.kts",
                "buildSrc/src/main/groovy/deep/x/old.conventions.gradle",
                "buildSrc/src/main/kotlin/my.conventions.gradle.kts",
            ]
        );
        let builds: Vec<(&str, BuildKind)> =
            g.builds.iter().map(|b| (b.dir.as_str(), b.kind)).collect();
        assert_eq!(
            builds,
            [
                ("", BuildKind::Root),
                ("buildSrc", BuildKind::BuildSrc),
                ("build-logic", BuildKind::Included)
            ]
        );
        assert_eq!(
            g.project_dirs(),
            [
                "",
                "sub",
                "buildSrc",
                "build-logic",
                "build-logic/convention"
            ]
        );
        assert!(g.build_scripts().all(|s| s.kind != ScriptKind::Settings));
    }

    #[test]
    fn rejects_escapes_urls_and_non_literals() {
        let g = graph(&[
            (
                "build.gradle",
                "apply from: '../outside.gradle'\napply from: '/etc/x.gradle'\napply from: 'https://example.com/x.gradle'\napply from: \"$someDir/x.gradle\"\napply from: 'missing.gradle'\n",
            ),
            ("settings.gradle", "includeBuild('../sibling')\nincludeFlat 'flat'\n"),
        ]);
        let got: Vec<(Site, Reason, usize)> = g
            .unresolved
            .iter()
            .map(|u| (u.site, u.reason, u.line))
            .collect();
        assert_eq!(
            got,
            [
                (Site::Include, Reason::Escapes, 2),
                (Site::IncludeBuild, Reason::Escapes, 1),
                (Site::ApplyFrom, Reason::Escapes, 1),
                (Site::ApplyFrom, Reason::Escapes, 2),
                (Site::ApplyFrom, Reason::Url, 3),
                (Site::ApplyFrom, Reason::NonLiteral, 4),
                (Site::ApplyFrom, Reason::Missing, 5),
            ]
        );
        assert!(matches!(g.maven_local(), MavenLocal::Undetermined(_)));
    }

    #[test]
    fn apply_from_depth_and_file_caps() {
        let mut files: Vec<(String, String)> =
            vec![("build.gradle".into(), "apply from: 'c/0.gradle'\n".into())];
        for i in 0..12 {
            files.push((
                format!("c/{i}.gradle"),
                format!("apply from: 'c/{}.gradle'\n", i + 1),
            ));
        }
        let refs: Vec<(&str, &str)> = files
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        let g = graph(&refs);
        assert_eq!(rels(&g, ScriptKind::Applied).len(), MAX_DEPTH);
        assert_eq!(g.unresolved.len(), 1);
        assert_eq!(g.unresolved[0].reason, Reason::DepthCap);
        assert_eq!(g.unresolved[0].rel, format!("c/{}.gradle", MAX_DEPTH - 1));

        let mut text = String::new();
        let mut files: Vec<(String, String)> = Vec::new();
        for i in 0..MAX_FILES + 10 {
            text.push_str(&format!("apply from: 'f/{i}.gradle'\n"));
            files.push((format!("f/{i}.gradle"), String::new()));
        }
        files.push(("build.gradle".into(), text));
        let refs: Vec<(&str, &str)> = files
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        let g = graph(&refs);
        assert_eq!(g.scripts.len(), MAX_FILES);
        let caps: Vec<_> = g
            .unresolved
            .iter()
            .filter(|u| u.reason == Reason::FileCap)
            .collect();
        assert_eq!(caps.len(), 1, "{:?}", g.unresolved.len());
        assert!(g.unresolved.iter().all(|u| u.reason == Reason::FileCap));

        let big = "x".repeat(MAX_FILE_BYTES + 1);
        let g = graph(&[
            ("build.gradle", "apply from: 'big.gradle'\n"),
            ("big.gradle", &big),
        ]);
        let reasons: Vec<Reason> = g.unresolved.iter().map(|u| u.reason).collect();
        assert_eq!(reasons, [Reason::TooLarge, Reason::Missing]);
    }

    #[test]
    fn settings_with_a_bom_parses() {
        let g = graph(&[
            ("settings.gradle", "\u{feff}include ':a'\n"),
            (
                "a/build.gradle",
                "\u{feff}dependencies { implementation 'com.socketfixture:victim:1.10.0' }\n",
            ),
        ]);
        assert_eq!(projects(&g), [pair(":a", "a")]);
        assert_eq!(g.declarations_of(G, A).len(), 1);
        assert!(!g.scripts[0].text.starts_with('\u{feff}'));
    }

    // ── #511: ranges, rich versions and catalogs ────────────────────────────────

    #[test]
    fn range_rich_and_catalog_declarations() {
        let g = graph(&[
            (
                "build.gradle",
                "dependencies {
  implementation 'com.socketfixture:victim:[1.9,1.11)'
  implementation('com.socketfixture:victim') { version { strictly '[1.9, 1.11)'; prefer '1.10.0' } }
  implementation libs.victim
  constraints { implementation('com.socketfixture:victim:1.10.0!!') }
  runtimeOnly 'com.socketfixture:victim:1.+'
  implementation 'com.socketfixture:victim:1.10.0'
  implementation \"com.socketfixture:victim:$victimVersion\"
  implementation 'com.socketfixture:victimx:1.0'
  // implementation 'com.socketfixture:victim:9'
}
",
            ),
            ("build.gradle.kts", "never read: Groovy wins"),
            (
                "gradle/libs.versions.toml",
                "[versions]
victim = { strictly = \"1.10.0\", reject = [\"1.9\"] }
plain = \"1.10.0\"

[libraries]
victim = { module = \"com.socketfixture:victim\", version.ref = \"victim\" }
victim2 = \"com.socketfixture:victim:1.10.0\"
victim3 = { group = \"com.socketfixture\", name = \"victim\", version.ref = \"plain\" }
other = { group = \"x\", name = \"y\", version = \"1\" }
",
            ),
        ]);
        let d = g.declarations_of(G, A);
        let summary: Vec<(String, usize, Option<&str>)> = d
            .iter()
            .map(|d| {
                let k = match &d.kind {
                    DeclKind::Plain => "plain",
                    DeclKind::Range => "range",
                    DeclKind::Rich(_) => "rich",
                    DeclKind::Classifier => "classifier",
                    DeclKind::Catalog => "catalog",
                };
                (format!("{}:{k}", d.rel), d.line, d.version.as_deref())
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("build.gradle:range".to_string(), 2, Some("[1.9,1.11)")),
                ("build.gradle:rich".to_string(), 3, None),
                ("build.gradle:rich".to_string(), 5, Some("1.10.0!!")),
                ("build.gradle:range".to_string(), 6, Some("1.+")),
                ("build.gradle:plain".to_string(), 7, Some("1.10.0")),
                ("build.gradle:plain".to_string(), 8, None),
                (
                    "gradle/libs.versions.toml:catalog".to_string(),
                    6,
                    Some("1.10.0")
                ),
                (
                    "gradle/libs.versions.toml:catalog".to_string(),
                    7,
                    Some("1.10.0")
                ),
                (
                    "gradle/libs.versions.toml:catalog".to_string(),
                    8,
                    Some("1.10.0")
                ),
            ]
        );
        assert_eq!(
            d[1].rich,
            Some(RichVersion {
                strictly: Some("[1.9, 1.11)".into()),
                prefer: Some("1.10.0".into()),
                ..RichVersion::default()
            })
        );
        assert_eq!(
            d[2].rich.as_ref().and_then(|r| r.strictly.as_deref()),
            Some("1.10.0")
        );
        assert_eq!(
            d[6].rich,
            Some(RichVersion {
                strictly: Some("1.10.0".into()),
                reject: vec!["1.9".into()],
                ..RichVersion::default()
            })
        );
        assert_eq!(d[8].rich, None);
    }

    #[test]
    fn kotlin_rich_and_positional_declarations() {
        let g = graph(&[(
            "build.gradle.kts",
            "dependencies {
    implementation(\"com.socketfixture:victim\") {
        version {
            strictly(\"[1.9, 1.11)\")
            require(\"1.10.0\")
            reject(\"1.9\", \"1.9.1\")
        }
    }
    implementation(\"com.socketfixture\", \"victim\", \"1.10.0\")
    implementation(group = \"com.socketfixture\", name = \"victim\", version = \"[1.9,)\")
}
",
        )]);
        let d = g.declarations_of(G, A);
        assert_eq!(d.len(), 3, "{d:?}");
        assert_eq!(
            d[0].kind,
            DeclKind::Rich(RichVersion {
                strictly: Some("[1.9, 1.11)".into()),
                require: Some("1.10.0".into()),
                prefer: None,
                reject: vec!["1.9".into(), "1.9.1".into()],
            })
        );
        assert_eq!((d[1].kind.clone(), d[1].line), (DeclKind::Plain, 9));
        assert_eq!(
            (d[2].kind.clone(), d[2].version.as_deref()),
            (DeclKind::Range, Some("[1.9,)"))
        );
    }

    // ── #533: classifiers ──────────────────────────────────────────────────────────

    #[test]
    fn classifier_in_all_four_forms() {
        let g = graph(&[
            ("settings.gradle", "include 'k'\n"),
            (
                "build.gradle",
                "dependencies {
  testImplementation 'com.socketfixture:victim:1.10.0:tests'
  testImplementation group: 'com.socketfixture', name: 'victim', version: '1.10.0', classifier: 'tests'
  testImplementation('com.socketfixture:victim:1.10.0') { artifact { classifier = 'tests' } }
  testImplementation 'com.socketfixture:victim:1.10.0:sources@jar'
}
",
            ),
            (
                "k/build.gradle.kts",
                "dependencies {
    testImplementation(group = \"com.socketfixture\", name = \"victim\", version = \"1.10.0\", classifier = \"tests\")
    testImplementation(\"com.socketfixture:victim:1.10.0\") {
        artifact {
            classifier = \"tests\"
        }
    }
}
",
            ),
        ]);
        let d = g.declarations_of(G, A);
        let got: Vec<(&str, usize, Option<&str>)> = d
            .iter()
            .map(|d| (d.rel.as_str(), d.line, d.classifier.as_deref()))
            .collect();
        assert_eq!(
            got,
            [
                ("build.gradle", 2, Some("tests")),
                ("build.gradle", 4, Some("tests")),
                ("build.gradle", 5, Some("sources")),
                ("build.gradle", 3, Some("tests")),
                ("k/build.gradle.kts", 3, Some("tests")),
                ("k/build.gradle.kts", 2, Some("tests")),
            ]
        );
        assert!(d.iter().all(|d| d.kind == DeclKind::Classifier));
        assert!(d.iter().all(|d| d.version.as_deref() == Some("1.10.0")));
    }

    // ── mavenLocal ───────────────────────────────────────────────────────────────

    #[test]
    fn maven_local_declared_from_every_kind_of_script() {
        // (checkout files, init scripts, declaring script)
        type Case<'a> = (&'a [(&'a str, &'a str)], &'a [(&'a str, &'a str)], &'a str);
        let cases: &[Case<'_>] = &[
            (
                &[(
                    "settings.gradle.kts",
                    "dependencyResolutionManagement { repositories { mavenLocal() } }\n",
                )],
                &[],
                "settings.gradle.kts",
            ),
            (&[("build.gradle", "repositories {\n  mavenLocal()\n}\n")], &[], "build.gradle"),
            (
                &[
                    ("buildSrc/build.gradle.kts", ""),
                    (
                        "buildSrc/src/main/kotlin/conv.gradle.kts",
                        "repositories { mavenLocal() }\n",
                    ),
                ],
                &[],
                "buildSrc/src/main/kotlin/conv.gradle.kts",
            ),
            (
                &[("build.gradle", "")],
                &[(
                    "/home/u/.gradle/init.d/local.gradle",
                    "allprojects { repositories { mavenLocal() } }\n",
                )],
                "/home/u/.gradle/init.d/local.gradle",
            ),
            (
                &[(
                    "build.gradle",
                    "repositories { maven { url \"${System.getProperty('user.home')}/.m2/repository\" } }\n",
                )],
                &[],
                "build.gradle",
            ),
            // The closure (trailing-lambda) form, used to scope it.
            (
                &[(
                    "build.gradle.kts",
                    "repositories {\n    mavenLocal {\n        content { includeGroup(\"com.socketfixture\") }\n    }\n    mavenCentral()\n}\n",
                )],
                &[],
                "build.gradle.kts",
            ),
            (
                &[("build.gradle", "repositories {\n  mavenLocal {\n  }\n}\n")],
                &[],
                "build.gradle",
            ),
            // A binary convention plugin in buildSrc.
            (
                &[
                    ("buildSrc/build.gradle.kts", "plugins { `kotlin-dsl` }\n"),
                    (
                        "buildSrc/src/main/kotlin/Conv.kt",
                        "class Conv : Plugin<Project> {\n    override fun apply(p: Project) { p.repositories.mavenLocal() }\n}\n",
                    ),
                    ("a/build.gradle", "plugins { id 'conv' }\n"),
                    ("settings.gradle", "include 'a'\n"),
                ],
                &[],
                "buildSrc/src/main/kotlin/Conv.kt",
            ),
            // A Java plugin in a plugin project of an included build.
            (
                &[
                    ("settings.gradle", "pluginManagement { includeBuild 'logic' }\n"),
                    ("logic/settings.gradle", "include 'plugins'\n"),
                    (
                        "logic/plugins/build.gradle",
                        "plugins { id 'java-gradle-plugin' }\n",
                    ),
                    (
                        "logic/plugins/src/main/java/x/RepoPlugin.java",
                        "public class RepoPlugin implements Plugin<Project> {\n  public void apply(Project p) { char q = '\\''; p.getRepositories().mavenLocal(); }\n}\n",
                    ),
                ],
                &[],
                "logic/plugins/src/main/java/x/RepoPlugin.java",
            ),
            // A settings script that includes its projects from an applied
            // script.
            (
                &[
                    ("settings.gradle", "apply from: 'gradle/modules.gradle'\n"),
                    ("gradle/modules.gradle", "include ':app'\n"),
                    ("app/build.gradle", "repositories { mavenLocal() }\n"),
                ],
                &[],
                "app/build.gradle",
            ),
        ];
        for (files, init, want) in cases {
            let g = graph_with_init(files, init);
            assert!(g.unresolved.is_empty(), "{files:?}: {:?}", g.unresolved);
            assert_eq!(
                g.maven_local(),
                MavenLocal::Declared(want.to_string()),
                "{files:?}"
            );
        }
        // A comment or a string that merely names it is not a declaration.
        let g = graph(&[(
            "build.gradle",
            "// mavenLocal()\nrepositories { mavenCentral() }\ndef s = 'mavenLocal'\n",
        )]);
        assert_eq!(g.maven_local(), MavenLocal::NotDeclared);
    }

    #[test]
    fn product_sources_of_included_builds_are_not_build_logic() {
        // An included library build is product code: its sources are not
        // read (only plugin projects' and buildSrc's are).
        let g = graph(&[
            ("settings.gradle", "includeBuild 'lib'\n"),
            ("lib/build.gradle", "plugins { id 'java-library' }\n"),
            (
                "lib/src/main/java/Lib.java",
                "class Lib { String s = \"com.android.application\"; }\n",
            ),
        ]);
        assert!(rels(&g, ScriptKind::PluginSource).is_empty());
        assert_eq!(g.android_or_kmp(), None);
        assert_eq!(g.maven_local(), MavenLocal::NotDeclared);
    }

    #[test]
    fn maven_local_undetermined() {
        let g = graph(&[("build.gradle", "apply from: \"$buildDir/x.gradle\"\n")]);
        assert!(
            matches!(g.maven_local(), MavenLocal::Undetermined(r) if r.contains("build.gradle:1"))
        );
        let g = graph_with_init(
            &[("build.gradle", "")],
            &[("/h/init.d/broken.gradle", "allprojects { repositories {\n")],
        );
        assert!(
            matches!(g.maven_local(), MavenLocal::Undetermined(r) if r.contains("broken.gradle"))
        );
        // An init script's own `apply from` is outside the checkout.
        let g = graph_with_init(
            &[("build.gradle", "")],
            &[("/h/init.gradle", "apply from: 'other.gradle'\n")],
        );
        assert!(matches!(g.maven_local(), MavenLocal::Undetermined(_)));
        let mut g = graph(&[("build.gradle", "")]);
        assert_eq!(g.maven_local(), MavenLocal::NotDeclared);
        g.note_unreadable_init_script("/h/init.gradle");
        assert!(matches!(g.maven_local(), MavenLocal::Undetermined(_)));
    }

    // ── other queries ────────────────────────────────────────────────────────────

    #[test]
    fn custom_lock_file_and_settings_classpath() {
        let g = graph(&[(
            "build.gradle",
            "dependencyLocking {\n  lockAllConfigurations()\n  lockFile = file(\"$projectDir/locks/x.lockfile\")\n}\n",
        )]);
        assert_eq!(g.custom_lock_file().as_deref(), Some("build.gradle"));
        let g = graph(&[(
            "build.gradle.kts",
            "dependencyLocking { lockFile.set(file(\"x.lockfile\")) }\n",
        )]);
        assert_eq!(g.custom_lock_file().as_deref(), Some("build.gradle.kts"));
        let g = graph(&[(
            "build.gradle",
            "dependencyLocking { lockAllConfigurations() }\nif (lockFile == null) {}\n",
        )]);
        assert_eq!(g.custom_lock_file(), None);

        let g = graph(&[
            (
                "settings.gradle",
                "buildscript {\n  dependencies { classpath 'com.socketfixture:victim:1.10.0' }\n}\n",
            ),
            ("build.gradle", "dependencies { implementation 'com.socketfixture:buildlogic-plugin:1.0' }\n"),
        ]);
        assert!(g.settings_classpath_has(G, A));
        assert!(!g.settings_classpath_has(G, "buildlogic-plugin"));
        let g = graph(&[
            (
                "settings.gradle.kts",
                "pluginManagement { resolutionStrategy { eachPlugin { if (requested.id.id == \"x\") useModule(\"com.socketfixture:victim:1.10.0\") } } }\n",
            ),
            ("build.gradle", "buildscript { dependencies { classpath 'com.socketfixture:other:1' } }\n"),
        ]);
        assert!(g.settings_classpath_has(G, A));
        assert!(!g.settings_classpath_has(G, "other"));
    }

    #[test]
    fn exclusive_content_filters_and_claims() {
        let g = graph(&[
            (
                "settings.gradle.kts",
                "dependencyResolutionManagement { repositories {
    exclusiveContent {
        forRepository { maven(\"https://corp.example/m2\") { name = \"corp\" } }
        filter { includeGroup(\"com.socketfixture\") }
    }
} }
",
            ),
            (
                "build.gradle",
                "repositories {
  exclusiveContent { forRepository { maven { url 'https://a' } }; filter { includeModule 'com.socketfixture', 'other' } }
  exclusiveContent { forRepository { maven { url 'https://b' } }; filter { includeGroupByRegex 'com\\\\.socket.*' } }
  exclusiveContent { forRepository { mavenCentral() }; filter { includeGroupByRegex '(' } }
  exclusiveContent { forRepository { mavenCentral() }; filter { includeGroupAndSubgroups 'com' } }
  exclusiveContent { forRepository { mavenCentral() }; filter { includeVersion 'com.socketfixture', 'victim', '1.10.0' } }
  exclusiveContent { forRepository { mavenCentral() }; filter { includeGroup \"$g\" } }
  exclusiveContent { forRepository { mavenCentral() }; filter { includeGroupAndSubgroups 'com.socketfixtures' } }
}
",
            ),
        ]);
        let f = g.exclusive_content_filters();
        assert_eq!(f.len(), 8);
        assert_eq!(f[0].rel, "settings.gradle.kts");
        assert_eq!(f[0].line, 2);
        assert!(f[0].repo_strings.contains(&"corp".to_string()));
        assert!(f[0]
            .repo_strings
            .contains(&"https://corp.example/m2".to_string()));
        let claims: Vec<bool> = f.iter().map(|x| filter_claims_group(x, G, A)).collect();
        assert_eq!(claims, [true, false, true, true, true, true, true, false]);
        assert!(filter_claims_group(&f[1], G, "other"));
    }

    #[test]
    fn android_kmp_and_wrapper_version() {
        let g = graph(&[
            ("settings.gradle", "include 'app'\n"),
            (
                "app/build.gradle.kts",
                "plugins { id(\"com.android.application\") }\n",
            ),
        ]);
        assert_eq!(
            g.android_or_kmp(),
            Some((
                "app/build.gradle.kts".to_string(),
                "com.android.application".to_string()
            ))
        );
        let g = graph(&[(
            "build.gradle.kts",
            "plugins { kotlin(\"multiplatform\") version \"2.0.0\" }\n",
        )]);
        assert_eq!(
            g.android_or_kmp().map(|x| x.1).as_deref(),
            Some("kotlin(\"multiplatform\")")
        );
        let g = graph(&[(
            "build.gradle.kts",
            "plugins { kotlin(\"jvm\") }\n// com.android.application\n",
        )]);
        assert_eq!(g.android_or_kmp(), None);
        // Applied by catalog alias: the id is only in the catalog.
        for (catalog, id) in [
            (
                "[plugins]\nandroid-application = { id = \"com.android.application\", version = \"8.5.0\" }\n",
                "com.android.application",
            ),
            (
                "[plugins]\nkotlinMultiplatform = \"org.jetbrains.kotlin.multiplatform:2.0.0\"\n",
                "org.jetbrains.kotlin.multiplatform",
            ),
        ] {
            let g = graph(&[
                ("settings.gradle.kts", "include(\"app\")\n"),
                (
                    "app/build.gradle.kts",
                    "plugins { alias(libs.plugins.android.application) }\n",
                ),
                ("gradle/libs.versions.toml", catalog),
            ]);
            assert_eq!(
                g.android_or_kmp(),
                Some(("gradle/libs.versions.toml".to_string(), id.to_string()))
            );
        }
        let g = graph(&[(
            "gradle/libs.versions.toml",
            "[plugins]\njvm = { id = \"org.jetbrains.kotlin.jvm\", version = \"2.0.0\" }\n",
        )]);
        assert_eq!(g.android_or_kmp(), None);

        let fs = MemFs::new(&[
            (
                "gradle/wrapper/gradle-wrapper.properties",
                "distributionBase=GRADLE_USER_HOME\r\ndistributionUrl=https\\://services.gradle.org/distributions/gradle-8.14.3-bin.zip\r\n",
            ),
            ("w/gradle/wrapper/gradle-wrapper.properties", "distributionUrl = https://x/gradle-9.0-all.zip\n"),
        ]);
        let read = |r: &str| fs.read(r);
        assert_eq!(wrapper_version(&read, ""), Some((8, 14, 3)));
        assert_eq!(wrapper_version(&read, "w"), Some((9, 0, 0)));
        assert_eq!(wrapper_version(&read, "none"), None);
    }

    #[test]
    fn lockfile_paths_keep_to_the_builds_projects() {
        let g = {
            let fs = MemFs::new(&[
                (
                    "settings.gradle",
                    "include 'app'\nincludeBuild 'build-logic'\n",
                ),
                ("gradle.lockfile", ""),
                ("settings-gradle.lockfile", ""),
                ("app/gradle.lockfile", ""),
                ("app/gradle/dependency-locks/compileClasspath.lockfile", ""),
                ("buildSrc/build.gradle", ""),
                ("buildSrc/buildscript-gradle.lockfile", ""),
                ("build-logic/settings.gradle", "include 'convention'\n"),
                ("build-logic/convention/gradle.lockfile", ""),
                // Not part of the build: a standalone sample and a test
                // fixture build.
                ("samples/demo/settings.gradle", ""),
                ("samples/demo/gradle.lockfile", ""),
                ("src/test/resources/projects/x/gradle.lockfile", ""),
            ]);
            let g = ScriptGraph::collect(&|r: &str| fs.read(r), &|d: &str| fs.list(d), "", &[]);
            (g.lockfile_paths(&|d: &str| fs.list(d)), fs)
        };
        assert_eq!(
            g.0,
            [
                "app/gradle.lockfile",
                "app/gradle/dependency-locks/compileClasspath.lockfile",
                "build-logic/convention/gradle.lockfile",
                "buildSrc/buildscript-gradle.lockfile",
                "gradle.lockfile",
                "settings-gradle.lockfile",
            ]
        );
        // The inventory walk still sees every one.
        assert_eq!(locks::lockfile_paths(&|d: &str| g.1.list(d), "").len(), 8);
    }

    #[test]
    fn rels_carry_the_root_prefix() {
        let g = {
            let fs = MemFs::new(&[
                ("proj/settings.gradle", "include 'a'\n"),
                ("proj/a/build.gradle", "apply from: '../gradle/x.gradle'\n"),
                ("proj/gradle/x.gradle", ""),
                ("proj/b/build.gradle", "apply from: '../../escape.gradle'\n"),
            ]);
            ScriptGraph::collect(&|r: &str| fs.read(r), &|d: &str| fs.list(d), "proj", &[])
        };
        assert_eq!(
            g.scripts.iter().map(|s| s.rel.as_str()).collect::<Vec<_>>(),
            [
                "proj/settings.gradle",
                "proj/a/build.gradle",
                "proj/gradle/x.gradle"
            ]
        );
        assert_eq!(projects(&g), [pair(":a", "proj/a")]);
    }
}
