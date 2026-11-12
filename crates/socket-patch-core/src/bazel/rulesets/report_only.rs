//! Recognizer: shapes that are reported and never patched (design 2.7,
//! 4.2 rows 24 and 31, HZ-23), with the out-of-scope counts of owner
//! decision D13.
//!
//! - rules_req_compile: its own lock dialect (`requirements.parse` tags
//!   and `py_requirements_repository`).
//! - rules_poetry: unmaintained; it skips every package whose source is
//!   not `legacy`.
//! - bazel-deps: a generated `.bzl` of Maven pins, loaded by `WORKSPACE`.
//! - hand-written JVM pins: `jvm_maven_import_external`,
//!   `jvm_import_external` and `http_jar`.
//! - cargo-raze: unmaintained; Bazel builds the generated `crates.bzl`
//!   or vendored tree, never `Cargo.lock`.
//! - hubs of a module that is not the root: their locks are files of
//!   that module's repository.
//!
//! Each is a hub of shape [`HubShape::ReportOnly`] over the files it
//! names, so that a lock one of them reads is refused with the token of
//! [`ReportOnlyKind::token`], not rewritten by a native writer that
//! does not know the dialect. The counts are for one info line: Bazel
//! modules and source archives have no Socket patches (F93).

use super::rules_rust::{
    loaded_calls, new_hub, not_literal, proxy_gaps, unread_uses, usages_of, Args, Home, LabelAttr,
    LoadedCall,
};
use super::{RecognizeInput, Recognized};
use crate::bazel::label::{Label, Repo};
use crate::bazel::model::{
    DeclSystem, Declaration, FileView, Hub, HubShape, LockRef, LockRole, RulesetDetail, Site,
};
use crate::bazel::module_file::ModuleModel;
use crate::bazel::starlark::{Value, ValueKind};
use crate::bazel::workspace_file::WorkspaceModel;
use crate::crawlers::types::Ecosystem;
use crate::formats::text::strip_bom_bytes;

/// Every `details.token` this file names.
pub const TOKENS: &[&str] = &["report_only", "cargo_raze", "hub_not_root_module"];

/// A shape that is recognized only to be reported.
pub const REPORT_ONLY: &str = TOKENS[0];
/// cargo-raze.
pub const CARGO_RAZE: &str = TOKENS[1];
/// The hub belongs to a module that is not the root module.
pub const HUB_NOT_ROOT_MODULE: &str = TOKENS[2];

/// Which report-only shape a hub is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportOnlyKind {
    RulesReqCompile,
    RulesPoetry,
    BazelDeps,
    /// `jvm_maven_import_external` / `jvm_import_external`.
    JvmImportExternal,
    HttpJar,
    CargoRaze,
    /// A repository the root imports from an extension it gives no tag:
    /// another module's tags declare it.
    NonRootModuleHub,
}

impl ReportOnlyKind {
    /// The `details.token` of a refusal over this shape.
    pub const fn token(self) -> &'static str {
        match self {
            Self::CargoRaze => CARGO_RAZE,
            Self::NonRootModuleHub => HUB_NOT_ROOT_MODULE,
            _ => REPORT_ONLY,
        }
    }
}

/// What this recognizer records about one hub.
#[derive(Debug, Clone, PartialEq)]
pub struct ReportOnlyDetail {
    pub kind: ReportOnlyKind,
    /// The packages the declaration pins that were counted: the calls of
    /// a hand-written rule in one file, the artifacts of a bazel-deps
    /// file. 0 where the pins are in a lock this reader does not parse.
    pub pins: usize,
}

/// The first line of a file bazel-deps generates (read at `4b583c6`
/// `3rdparty/workspace.bzl`).
const BAZEL_DEPS_HEADER: &[u8] = b"# Do not edit. bazel-deps autogenerates this file from";

/// The module extensions of design 2.7 whose repositories are hubs:
/// label package, file, extension name, ecosystem.
const HUB_EXTENSIONS: [(&str, &str, &str, Ecosystem); 12] = [
    ("npm", "extensions.bzl", "npm", Ecosystem::Npm),
    ("python/extensions", "pip.bzl", "pip", Ecosystem::Pypi),
    ("uv/unstable", "extension.bzl", "uv", Ecosystem::Pypi),
    ("uv", "extensions.bzl", "uv", Ecosystem::Pypi),
    ("extensions", "python.bzl", "requirements", Ecosystem::Pypi),
    ("", "extensions.bzl", "maven", Ecosystem::Maven),
    ("", "extensions.bzl", "go_deps", Ecosystem::Golang),
    ("crate_universe", "extension.bzl", "crate", Ecosystem::Cargo),
    (
        "crate_universe",
        "extensions.bzl",
        "crate",
        Ecosystem::Cargo,
    ),
    ("rs", "extensions.bzl", "crate", Ecosystem::Cargo),
    ("ruby", "extensions.bzl", "ruby", Ecosystem::Gem),
    ("csharp", "extensions.bzl", "nuget", Ecosystem::Nuget),
];

/// What a rule of `@bazel_tools//tools/build_defs/repo` fetches.
enum ToolsRule {
    /// A source tree or file: out of scope, counted.
    Archive,
    Pin(ReportOnlyKind),
}

fn tools_rule(label: &Label, symbol: &str) -> Option<ToolsRule> {
    let tools = matches!(&label.repo, Repo::Apparent(r) | Repo::Canonical(r) if r == "bazel_tools");
    if !tools || label.package != "tools/build_defs/repo" {
        return None;
    }
    match (label.name.as_str(), symbol) {
        ("http.bzl", "http_archive" | "http_file")
        | ("git.bzl", "git_repository" | "new_git_repository") => Some(ToolsRule::Archive),
        ("http.bzl", "http_jar") => Some(ToolsRule::Pin(ReportOnlyKind::HttpJar)),
        ("jvm.bzl", "jvm_maven_import_external" | "jvm_import_external") => {
            Some(ToolsRule::Pin(ReportOnlyKind::JvmImportExternal))
        }
        _ => None,
    }
}

fn hub(
    kind: ReportOnlyKind,
    ecosystem: Ecosystem,
    (site, name, literal): (Site, &str, bool),
    locks: Vec<LockRef>,
    pins: usize,
) -> Hub {
    let detail = RulesetDetail::ReportOnly(ReportOnlyDetail { kind, pins });
    let decl = Declaration {
        site,
        apparent_name: name.to_string(),
        literal,
    };
    new_hub(HubShape::ReportOnly, ecosystem, detail, decl, locks)
}

/// Counts a source archive, or a hand-written pin: the pins of one kind
/// in one file are one hub, declared where the first one is.
fn count(out: &mut Recognized, rule: ToolsRule, site: Site, name: &str) {
    let kind = match rule {
        ToolsRule::Archive => return out.out_of_scope.source_archives += 1,
        ToolsRule::Pin(kind) => kind,
    };
    let same = |hub: &&mut Hub| {
        let pin = matches!(&hub.detail, RulesetDetail::ReportOnly(d) if d.kind == kind);
        pin && hub.decl.site.file == site.file
    };
    match out.hubs.iter_mut().find(same).map(|hub| &mut hub.detail) {
        Some(RulesetDetail::ReportOnly(detail)) => detail.pins += 1,
        _ => out.hubs.push(hub(
            kind,
            Ecosystem::Maven,
            (site, name, true),
            Vec::new(),
            1,
        )),
    }
}

/// Where a declaration is, for a hub and for the gap that names it: its
/// site, its 1-based line and the statement as a user writes it.
type At<'a> = (Site, usize, &'a str);

/// Adds a hub over lock files: `labels` are its single-label attributes
/// by name, and `listed` its list of locks, `None` where that was not
/// read. A name or a label that cannot be followed is a gap as well: the
/// hub may then read any lock of its ecosystem.
fn lock_hub(
    out: &mut Recognized,
    (kind, ecosystem): (ReportOnlyKind, Ecosystem),
    (site, line, what): At<'_>,
    name: Result<Option<&str>, ()>,
    labels: &[(&'static str, LabelAttr)],
    (list, listed): (&'static str, Option<Vec<LockRef>>),
) {
    let followed = |locks: &Vec<LockRef>| locks.iter().all(|lock| lock.path.is_some());
    let unresolved = labels.iter().filter(|(_, label)| label.unresolved());
    let mut unread: Vec<&str> = unresolved.map(|(attr, _)| *attr).collect();
    unread.extend((!listed.as_ref().is_some_and(followed)).then_some(list));
    unread.extend(name.is_err().then_some("name"));
    if !unread.is_empty() {
        out.gaps.push(not_literal(&site, line, what, &unread));
    }
    let locks = labels.iter().filter_map(|(_, label)| label.lock());
    let locks = locks.chain(listed.into_iter().flatten()).collect();
    let decl = (
        site,
        name.ok().flatten().unwrap_or_default(),
        unread.is_empty(),
    );
    out.hubs.push(hub(kind, ecosystem, decl, locks, 0));
}

/// rules_req_compile: `requirements_lock`, and the keys of the
/// `requirements_locks` dict (a lock per platform). A `resolve` tag
/// names no file.
fn req_compile(out: &mut Recognized, args: &Args<'_>, at: At<'_>) {
    let keys = |value: &Value| match &value.kind {
        ValueKind::Dict(entries) => {
            let lock = |key| args.lock(key, LockRole::PackageLock);
            let keys = entries.iter().map(|(key, _)| key.as_str().map(lock));
            keys.collect()
        }
        _ => None,
    };
    let listed = match args.value("requirements_locks") {
        Ok(Some(value)) => keys(value),
        Ok(None) => Some(Vec::new()),
        Err(()) => None,
    };
    let single = args.label("requirements_lock", LockRole::PackageLock);
    let kind = (ReportOnlyKind::RulesReqCompile, Ecosystem::Pypi);
    let (labels, listed) = (
        [("requirements_lock", single)],
        ("requirements_locks", listed),
    );
    lock_hub(out, kind, at, args.text("name"), &labels, listed);
}

/// The byte span of the table header that makes the `Cargo.toml` at
/// `manifest` a cargo-raze input: `[package.metadata.raze]`,
/// `[workspace.metadata.raze]` or a table below one.
fn raze_table(view: &dyn FileView, manifest: &str) -> Option<(usize, usize)> {
    let read = view.read(manifest);
    let bytes = read.as_bytes()?;
    let text = strip_bom_bytes(bytes);
    let mut at = bytes.len() - text.len();
    for line in text.split_inclusive(|b| *b == b'\n') {
        let header = line.trim_ascii_start();
        let raze = |table: &[u8]| header.starts_with(table);
        if raze(b"[package.metadata.raze") || raze(b"[workspace.metadata.raze") {
            return Some((at, at + line.trim_ascii_end().len()));
        }
        at += line.len();
    }
    None
}

/// The cargo-raze hub declared at `site`, over the manifest with the
/// raze table and the lock beside it in each of `dirs` that has one. With
/// no table in any of them the settings are somewhere this reader does
/// not look, and the hub names the files of the first directory, where
/// the generated `crates.bzl` is.
fn cargo_raze(view: &dyn FileView, site: Site, dirs: &[&str]) -> Hub {
    let files = |dir: &str| {
        let file = |name: &str, role| LockRef {
            label: format!("//{dir}:{name}"),
            path: Some(format!("{dir}/{name}").trim_start_matches('/').to_string()),
            role,
        };
        let manifest = file("Cargo.toml", LockRole::Config);
        [manifest, file("Cargo.lock", LockRole::PackageLock)]
    };
    let mut locks: Vec<LockRef> = Vec::new();
    for [manifest, lock] in dirs.iter().map(|dir| files(dir)) {
        let path = manifest.path.as_deref();
        let raze = path.and_then(|path| raze_table(view, path));
        if raze.is_some() && !locks.contains(&manifest) {
            locks.extend([manifest, lock]);
        }
    }
    if locks.is_empty() {
        locks.extend(dirs.first().map(|dir| files(dir)).into_iter().flatten());
    }
    let (kind, decl) = (ReportOnlyKind::CargoRaze, (site, "", true));
    hub(kind, Ecosystem::Cargo, decl, locks, 0)
}

fn bzlmod(input: &RecognizeInput<'_>, module: &ModuleModel, out: &mut Recognized) {
    out.out_of_scope.bazel_modules = module.deps.len();
    for call in &module.repo_rule_calls {
        let rule = &module.repo_rules[call.rule];
        let known = rule.label.as_ref().and_then(|l| tools_rule(l, &rule.rule));
        if let Some(known) = known {
            let name = call.name.as_deref().unwrap_or_default();
            count(out, known, module.site(call.at), name);
        }
    }
    for usage in usages_of(module, "extensions", &["python.bzl"], "requirements") {
        // This recognizer is the ruleset's own: a tag of the usage that
        // was not read is a hub nobody else reports.
        out.gaps.extend(proxy_gaps(module, &usage));
        let hub_tag = |callee: &str| matches!(callee, "parse" | "resolve");
        let tags = module.tags.iter().filter(|tag| usage.contains(&tag.proxy));
        for tag in tags.filter(|tag| hub_tag(&tag.call.callee)) {
            let resolve = |value| module.resolve(tag.at, value);
            let args = Args {
                input,
                call: &tag.call,
                resolve: &resolve,
                package: Some(""),
                home: Home::Module,
            };
            let what = format!("requirements.{}", tag.call.callee);
            req_compile(out, &args, (module.site(tag.at), tag.at.line, &what));
        }
    }
    // An extension the root gives no tag generates only what other
    // modules' tags declare, and those name locks of their own
    // repositories. Where the root has tags of its own, telling its hubs
    // from another module's takes the ruleset's naming, which is not
    // known here: such an import is not reported. Nor is one of a usage
    // behind a gap: "no tag was recorded" is then not "the root gives no
    // tag" (`[pip.parse(hub_name = n) for n in HUBS]` records none), and
    // the gap is the ruleset's own recognizer's to report.
    for usage in module.usages() {
        let proxy = &module.proxies[usage[0]];
        let known = |l: &Label| {
            let is = |(package, file, name, _): &&(&str, &str, &str, Ecosystem)| {
                l.package == *package && l.name == *file && proxy.extension == *name
            };
            HUB_EXTENSIONS.iter().find(is).map(|row| row.3)
        };
        let Some(ecosystem) = proxy.label.as_ref().and_then(known) else {
            continue;
        };
        let gapped = usage.iter().any(|p| module.gaps_for(*p).next().is_some());
        if gapped || module.tags.iter().any(|tag| usage.contains(&tag.proxy)) {
            continue;
        }
        for import in module.imports.iter().filter(|i| usage.contains(&i.proxy)) {
            let decl = (module.site(import.at), import.local.as_str(), true);
            let kind = ReportOnlyKind::NonRootModuleHub;
            out.hubs.push(hub(kind, ecosystem, decl, Vec::new(), 0));
        }
    }
}

/// Whether a `load` binds the rule of rules_poetry
/// (`@com_sonia_rules_poetry//rules_poetry:poetry.bzl`, README), under
/// whatever name the `WORKSPACE` gives the repository. A function of the
/// same name in the main repository is the user's own code.
fn is_poetry(label: Option<&Label>, symbol: &str) -> bool {
    let file = |l: &Label| l.package == "rules_poetry" && l.name == "poetry.bzl";
    symbol == "poetry" && label.is_some_and(|l| l.repo != Repo::Main && file(l))
}

/// The same for the `WORKSPACE` rule of rules_req_compile.
fn is_req_compile(label: Option<&Label>, symbol: &str) -> bool {
    let file = |l: &Label| l.package.is_empty() && l.name == "defs.bzl";
    let rule = symbol == "py_requirements_repository";
    rule && label.is_some_and(|l| l.repo != Repo::Main && file(l))
}

fn workspace(input: &RecognizeInput<'_>, ws: &WorkspaceModel, out: &mut Recognized) {
    let calls = loaded_calls(ws);
    // A rule over a lock declares a hub wherever it runs: a use that is
    // no call the reader follows is a hub that was not read.
    out.gaps
        .extend(unread_uses(input, ws, &calls, &is_poetry, "poetry"));
    let rule = "py_requirements_repository";
    out.gaps
        .extend(unread_uses(input, ws, &calls, &is_req_compile, rule));
    for found in calls {
        let LoadedCall { load, symbol, .. } = found;
        let Some(label) = load.label.as_ref() else {
            continue;
        };
        let resolve = |value| found.file.resolve(value);
        let args = Args {
            input,
            call: found.call,
            resolve: &resolve,
            package: None,
            home: Home::Workspace(ws),
        };
        let name = args.text("name");
        if let Some(rule) = tools_rule(label, symbol) {
            count(
                out,
                rule,
                found.site(),
                name.ok().flatten().unwrap_or_default(),
            );
            continue;
        }
        let main = label.repo == Repo::Main;
        let at = (found.site(), found.stmt.line, symbol);
        let found = match (label.package.as_str(), label.name.as_str(), symbol) {
            _ if is_poetry(Some(label), symbol) => {
                let lock = args.label("lockfile", LockRole::PackageLock);
                let manifest = args.label("pyproject", LockRole::Config);
                let kind = (ReportOnlyKind::RulesPoetry, Ecosystem::Pypi);
                let labels = [("lockfile", lock), ("pyproject", manifest)];
                lock_hub(out, kind, at, name, &labels, ("", Some(Vec::new())));
                continue;
            }
            _ if is_req_compile(Some(label), symbol) => {
                req_compile(out, &args, at);
                continue;
            }
            (_, _, "maven_dependencies") if main => {
                let path = label.file();
                let read = input.files.read(&path);
                let text = strip_bom_bytes(read.as_bytes().unwrap_or_default());
                if !text.starts_with(BAZEL_DEPS_HEADER) {
                    continue;
                }
                // One dict per pinned artifact, which the generator writes
                // on a line of its own. The bare key also names an
                // attribute of the `jar_artifact` rule the file defines.
                let artifact = b"{\"artifact\":";
                let pins = text.windows(artifact.len()).filter(|w| w == artifact);
                let lock = LockRef {
                    label: load.load.module.clone(),
                    path: Some(path),
                    role: LockRole::PackageLock,
                };
                let decl = (found.site(), symbol, true);
                let kind = ReportOnlyKind::BazelDeps;
                hub(kind, Ecosystem::Maven, decl, vec![lock], pins.count())
            }
            // `raze_fetch_remote_crates`, or the same under the project's
            // `gen_workspace_prefix` (cargo-raze README).
            (dir, "crates.bzl", fetch) if main && fetch.ends_with("_fetch_remote_crates") => {
                cargo_raze(input.files, found.site(), &[dir, ""])
            }
            _ => continue,
        };
        out.hubs.push(found);
    }
}

/// The hubs of the report-only shapes in `input`, and the counts of what
/// is out of scope.
pub fn recognize(input: &RecognizeInput<'_>) -> Recognized {
    let mut out = Recognized::default();
    if let Some(module) = input.module {
        bzlmod(input, module, &mut out);
    }
    for ws in input.workspace_files {
        workspace(input, ws, &mut out);
    }
    let kind = |hub: &Hub| match &hub.detail {
        RulesetDetail::ReportOnly(detail) => Some((detail.kind, detail.pins)),
        _ => None,
    };
    // Vendored cargo-raze has no `WORKSPACE` call: the raze table of the
    // root manifest is then the declaration.
    let raze = |hub: &Hub| kind(hub).is_some_and(|(kind, _)| kind == ReportOnlyKind::CargoRaze);
    let in_bazel_root = input.module.is_some() || !input.workspace_files.is_empty();
    if in_bazel_root && !out.hubs.iter().any(raze) {
        if let Some(span) = raze_table(input.files, "Cargo.toml") {
            let site = Site {
                file: "Cargo.toml".to_string(),
                span,
                system: DeclSystem::Workspace,
            };
            out.hubs.push(cargo_raze(input.files, site, &[""]));
        }
    }
    let pins = out.hubs.iter().filter_map(kind).map(|(_, pins)| pins);
    out.out_of_scope.report_only_pins = pins.sum();
    out
}

#[cfg(test)]
mod tests {
    use super::super::rules_rust::testing::run;
    use super::*;
    use crate::bazel::model::{OutOfScope, Ruleset};

    const HTTP: &str = "@bazel_tools//tools/build_defs/repo:http.bzl";
    const JVM: &str = "@bazel_tools//tools/build_defs/repo:jvm.bzl";

    fn detail(hub: &Hub) -> &ReportOnlyDetail {
        assert_eq!(
            (hub.ruleset, hub.shape),
            (Ruleset::ReportOnly, HubShape::ReportOnly)
        );
        match &hub.detail {
            RulesetDetail::ReportOnly(detail) => detail,
            other => panic!("not a report-only hub: {other:?}"),
        }
    }

    fn paths(hub: &Hub) -> Vec<(&str, LockRole)> {
        let locks = hub.locks.iter();
        locks
            .map(|lock| (lock.path.as_deref().unwrap_or("?"), lock.role))
            .collect()
    }

    fn workspace(text: &str) -> Recognized {
        run(recognize, &[("WORKSPACE", text)])
    }

    /// D13: Bazel modules and source archives are counted and not
    /// examined, and so are hand-written JVM pins, in both systems.
    #[test]
    fn modules_archives_and_hand_written_pins_are_counted() {
        let module = format!(
            "module(name = \"app\")\nbazel_dep(name = \"rules_cc\", version = \"0.2.9\")\n\
             bazel_dep(name = \"platforms\", version = \"1.0.0\", dev_dependency = True)\n\
             http_archive = use_repo_rule(\"{HTTP}\", \"http_archive\")\n\
             http_jar = use_repo_rule(\"{HTTP}\", \"http_jar\")\n\
             http_archive(name = \"zlib\", urls = [\"https://example.com/zlib.tar.gz\"])\n\
             http_jar(name = \"guava\", url = \"https://repo1.maven.org/guava-33.0.jar\")\n\
             http_jar(name = \"asm\", url = \"https://repo1.maven.org/asm-9.7.jar\")\n"
        );
        let workspace = format!(
            "load(\"{HTTP}\", \"http_archive\", \"http_file\", \"http_jar\")\n\
             load(\"@bazel_tools//tools/build_defs/repo:git.bzl\", \"git_repository\")\n\
             load(\"@bazel_tools//tools/build_defs/repo:utils.bzl\", \"maybe\")\n\
             load(\"{JVM}\", \"jvm_maven_import_external\")\nload(\"//:deps.bzl\", \"deps\")\n\
             http_archive(name = \"a\")\nmaybe(git_repository, name = \"b\")\nhttp_file(name = \"c\")\n\
             deps()\ndeps()\nhttp_jar(name = \"junit\")\n\
             jvm_maven_import_external(name = \"x\", artifact = \"g:a:1\")\n\
             jvm_maven_import_external(name = \"y\", artifact = \"g:b:2\")\n"
        );
        let macros = format!(
            "load(\"{HTTP}\", \"http_archive\")\ndef deps():\n    http_archive(name = \"d\")\n    \
             http_archive(name = \"e\")\n"
        );
        let found = run(
            recognize,
            &[
                ("MODULE.bazel", &module),
                ("WORKSPACE", &workspace),
                ("deps.bzl", &macros),
            ],
        );
        // A macro body is counted once, however often it is called.
        let expected = OutOfScope {
            bazel_modules: 2,
            source_archives: 6,
            report_only_pins: 5,
        };
        assert_eq!(found.out_of_scope, expected);
        let seen: Vec<_> = found
            .hubs
            .iter()
            .map(|hub| {
                let (read, decl) = (detail(hub), &hub.decl);
                assert!(hub.locks.is_empty() && hub.ecosystem == Ecosystem::Maven);
                (
                    read.kind,
                    read.pins,
                    decl.site.file.as_str(),
                    decl.site.system,
                    decl.apparent_name.as_str(),
                )
            })
            .collect();
        let (jar, jvm) = (ReportOnlyKind::HttpJar, ReportOnlyKind::JvmImportExternal);
        assert_eq!(
            seen,
            [
                (jar, 2, "MODULE.bazel", DeclSystem::Bzlmod, "guava"),
                (jar, 1, "WORKSPACE", DeclSystem::Workspace, "junit"),
                (jvm, 2, "WORKSPACE", DeclSystem::Workspace, "x"),
            ]
        );
        assert!(found.gaps.is_empty() && found.signals.is_empty());
        assert_eq!((jar.token(), jvm.token()), ("report_only", "report_only"));
    }

    /// The `parse` tag of rules_req_compile's own `MODULE.bazel` (BCR
    /// 1.7.1), a `resolve` tag, and the WORKSPACE rule.
    #[test]
    fn rules_req_compile_hubs_name_their_locks() {
        let module = "module(name = \"app\")\nbazel_dep(name = \"rules_req_compile\", version = \"1.7.1\")\n\
             requirements = use_extension(\"@rules_req_compile//extensions:python.bzl\", \"requirements\")\n\
             requirements.parse(\n    name = \"req_compile_deps\",\n    requirements_locks = {\n        \
             \"//3rdparty:requirements.linux_x86_64.txt\": \"linux_x86_64\",\n        \
             \"//3rdparty:requirements.macos_aarch64.txt\": \"macos_aarch64\",\n    },\n)\n\
             requirements.resolve(name = \"solved\")\nrequirements.parse(name = \"dyn\", requirements_locks = LOCKS)\n\
             requirements.package_annotation(package = \"numpy\")\nuse_repo(requirements, \"req_compile_deps\")\n";
        let found = run(recognize, &[("MODULE.bazel", module)]);
        let [parse, resolve, dynamic] = &found.hubs[..] else {
            panic!("three hubs: {:?}", found.hubs)
        };
        let kind = ReportOnlyKind::RulesReqCompile;
        assert_eq!(
            (detail(parse).kind, detail(parse).pins, parse.ecosystem),
            (kind, 0, Ecosystem::Pypi)
        );
        assert_eq!(
            paths(parse),
            [
                (
                    "3rdparty/requirements.linux_x86_64.txt",
                    LockRole::PackageLock
                ),
                (
                    "3rdparty/requirements.macos_aarch64.txt",
                    LockRole::PackageLock
                ),
            ]
        );
        assert_eq!(
            (parse.decl.apparent_name.as_str(), parse.decl.literal),
            ("req_compile_deps", true)
        );
        assert!(resolve.locks.is_empty() && resolve.decl.literal);
        // A hub whose locks are not read may read any: a gap, by name.
        assert!(dynamic.locks.is_empty() && !dynamic.decl.literal);
        let [gap] = &found.gaps[..] else {
            panic!("one gap: {:?}", found.gaps)
        };
        assert_eq!(gap.token, "label_not_literal");
        let unread = "MODULE.bazel:12: `requirements.parse`: requirements_locks cannot be followed";
        assert!(gap.detail.starts_with(unread), "{}", gap.detail);
        assert_eq!(found.out_of_scope.report_only_pins, 0);

        let found = workspace(
            "load(\"@rules_req_compile//:defs.bzl\", \"py_requirements_repository\")\n\
             py_requirements_repository(name = \"deps\", requirements_lock = \"//:requirements.txt\")\n",
        );
        assert_eq!(detail(&found.hubs[0]).kind, kind);
        assert_eq!(
            paths(&found.hubs[0]),
            [("requirements.txt", LockRole::PackageLock)]
        );
        assert_eq!(found.hubs[0].decl.site.system, DeclSystem::Workspace);
    }

    /// The WORKSPACE stanza of the rules_poetry README.
    #[test]
    fn a_rules_poetry_hub_names_its_lock_and_manifest() {
        let found = workspace(
            "load(\"@com_sonia_rules_poetry//rules_poetry:poetry.bzl\", \"poetry\")\n\
             poetry(\n    name = \"poetry\",\n    lockfile = \"//:poetry.lock\",\n    \
             pyproject = \"//:pyproject.toml\",\n)\n",
        );
        let [hub] = &found.hubs[..] else {
            panic!("one hub: {:?}", found.hubs)
        };
        assert_eq!(
            (detail(hub).kind, hub.ecosystem),
            (ReportOnlyKind::RulesPoetry, Ecosystem::Pypi)
        );
        assert_eq!(
            paths(hub),
            [
                ("poetry.lock", LockRole::PackageLock),
                ("pyproject.toml", LockRole::Config)
            ]
        );
        assert_eq!(hub.decl.apparent_name, "poetry");
        assert!(hub.decl.literal && found.gaps.is_empty());
        // A lock of another repository is named and cannot be followed.
        let found = workspace(
            "load(\"@com_sonia_rules_poetry//rules_poetry:poetry.bzl\", \"poetry\")\n\
             poetry(name = \"p\", lockfile = \"@locks//:poetry.lock\", pyproject = PROJECT)\n",
        );
        assert!(!found.hubs[0].decl.literal);
        let unread = "WORKSPACE:2: `poetry`: lockfile, pyproject cannot be followed";
        assert!(found.gaps[0].detail.starts_with(unread), "{:?}", found.gaps);
        // A function of the same name in the main repository is not it.
        let own =
            workspace("load(\"//rules_poetry:poetry.bzl\", \"poetry\")\npoetry(name = \"p\")\n");
        assert!(own.hubs.is_empty());

        // A use of the rule that is no call the reader follows is a hub
        // that was not read: a gap, never silence.
        let found = workspace(
            "load(\"@com_sonia_rules_poetry//rules_poetry:poetry.bzl\", \"poetry\")\n\
             poetry(name = \"poetry\", lockfile = \"//:poetry.lock\", pyproject = \"//:pyproject.toml\")\n\
             [poetry(name = n, lockfile = \"//tools:poetry.lock\") for n in [\"tools\"]]\n",
        );
        assert_eq!(found.hubs.len(), 1);
        let [gap] = &found.gaps[..] else {
            panic!("one gap: {:?}", found.gaps)
        };
        assert_eq!(gap.token, "label_not_literal");
        assert!(
            gap.detail
                .starts_with("WORKSPACE:3: a use of `poetry` is not read: "),
            "{}",
            gap.detail
        );
    }

    #[test]
    fn a_bazel_deps_file_is_told_by_its_header() {
        let load =
            "load(\"//3rdparty:workspace.bzl\", \"maven_dependencies\")\nmaven_dependencies()\n";
        // The parts of bazel-deps@4b583c6 `3rdparty/workspace.bzl` that
        // name an artifact: the rule the file defines for the pins, its
        // callback, and the pins themselves, one dict on a line each.
        let generated = "# Do not edit. bazel-deps autogenerates this file from dependencies.yaml.\n\
             def _jar_artifact_impl(ctx):\n    return None\n\n\
             jar_artifact = repository_rule(\n    attrs = {\n        \
             \"artifact\": attr.string(mandatory = True),\n        \
             \"sha256\": attr.string(mandatory = True),\n        \
             \"urls\": attr.string_list(mandatory = True),\n    },\n    \
             implementation = _jar_artifact_impl\n)\n\n\
             def jar_artifact_callback(hash):\n    jar_artifact(\n        artifact = hash[\"artifact\"],\n        \
             name = hash[\"name\"],\n        urls = [hash[\"url\"]],\n        sha256 = hash[\"sha256\"],\n    )\n\n\
             def list_dependencies():\n    return [\n    \
             {\"artifact\": \"com.google.guava:guava:33.0\", \"lang\": \"java\", \"sha256\": \"aa\"},\n    \
             {\"artifact\": \"junit:junit:4.13\", \"lang\": \"java\", \"sha256\": \"bb\"},\n    ]\n\n\
             def maven_dependencies(callback = jar_artifact_callback):\n    for hash in list_dependencies():\n        callback(hash)\n";
        let found = run(
            recognize,
            &[("WORKSPACE", load), ("3rdparty/workspace.bzl", generated)],
        );
        let [hub] = &found.hubs[..] else {
            panic!("one hub: {:?}", found.hubs)
        };
        assert_eq!(
            (detail(hub).kind, detail(hub).pins),
            (ReportOnlyKind::BazelDeps, 2)
        );
        assert_eq!(hub.ecosystem, Ecosystem::Maven);
        assert_eq!(
            paths(hub),
            [("3rdparty/workspace.bzl", LockRole::PackageLock)]
        );
        assert_eq!(found.out_of_scope.report_only_pins, 2);

        // A hand-written macro of the same name is the user's own code.
        let own = "def maven_dependencies():\n    pass\n";
        let found = run(
            recognize,
            &[("WORKSPACE", load), ("3rdparty/workspace.bzl", own)],
        );
        assert!(found.hubs.is_empty());
    }

    #[test]
    fn cargo_raze_is_told_by_its_fetch_macro_or_by_the_raze_table() {
        let fetch = "load(\"//cargo:crates.bzl\", \"raze_fetch_remote_crates\")\nraze_fetch_remote_crates()\n";
        let manifest =
            "[package]\nname = \"deps\"\n\n[package.metadata.raze]\nworkspace_path = \"//cargo\"\n";
        let found = run(
            recognize,
            &[
                ("WORKSPACE", fetch),
                ("cargo/Cargo.toml", manifest),
                (
                    "cargo/crates.bzl",
                    "def raze_fetch_remote_crates():\n    pass\n",
                ),
                ("Cargo.toml", "[workspace]\nmembers = [\"cargo\"]\n"),
            ],
        );
        let [hub] = &found.hubs[..] else {
            panic!("one hub: {:?}", found.hubs)
        };
        assert_eq!(
            (detail(hub).kind, hub.ecosystem),
            (ReportOnlyKind::CargoRaze, Ecosystem::Cargo)
        );
        assert_eq!(detail(hub).kind.token(), "cargo_raze");
        assert_eq!(hub.decl.site.file, "WORKSPACE");
        assert_eq!(
            paths(hub),
            [
                ("cargo/Cargo.toml", LockRole::Config),
                ("cargo/Cargo.lock", LockRole::PackageLock)
            ]
        );

        // With the settings somewhere else, the files beside the generated
        // `crates.bzl` are still named.
        let found = run(recognize, &[("WORKSPACE", fetch)]);
        assert_eq!(paths(&found.hubs[0]), paths(hub));

        // Vendored mode has no fetch macro: the table of the root
        // manifest declares it, behind a BOM and under a sub-table too.
        let vendored = "\u{feff}[workspace]\nmembers = [\"a\"]\n\n  [workspace.metadata.raze.crates.ring.'*']\n";
        let files = [
            ("MODULE.bazel", "module(name = \"app\")\n"),
            ("Cargo.toml", vendored),
        ];
        let found = run(recognize, &files);
        let [hub] = &found.hubs[..] else {
            panic!("one hub: {:?}", found.hubs)
        };
        assert_eq!(
            paths(hub),
            [
                ("Cargo.toml", LockRole::Config),
                ("Cargo.lock", LockRole::PackageLock)
            ]
        );
        let (start, end) = hub.decl.site.span;
        assert_eq!(
            &vendored[start..end],
            "  [workspace.metadata.raze.crates.ring.'*']"
        );

        // A manifest without the table declares nothing, and outside a
        // Bazel root nothing is read at all.
        let plain = [
            ("MODULE.bazel", "module(name = \"app\")\n"),
            ("Cargo.toml", "[package]\nname = \"raze\"\n"),
        ];
        assert!(run(recognize, &plain).hubs.is_empty());
        assert_eq!(
            run(recognize, &[("Cargo.toml", vendored)]),
            Recognized::default()
        );
    }

    /// A repository the root imports from an extension it gives no tag
    /// comes from another module's tags, over that module's own locks.
    #[test]
    fn a_hub_of_another_module_is_reported() {
        let module =
            "module(name = \"app\")\nbazel_dep(name = \"rules_python\", version = \"1.4.1\")\n\
             bazel_dep(name = \"rules_rust\", version = \"0.75.0\")\n\
             pip = use_extension(\"@rules_python//python/extensions:pip.bzl\", \"pip\")\n\
             use_repo(pip, \"their_pip\", mine = \"other_pip\")\n\
             crate = use_extension(\"@rules_rust//crate_universe:extensions.bzl\", \"crate\")\n\
             crate.from_cargo(name = \"crates\", cargo_lockfile = \"//:Cargo.lock\")\n\
             use_repo(crate, \"crates\", \"foreign\")\n\
             tools = use_extension(\"@rules_python//python/extensions:python.bzl\", \"python\")\n\
             use_repo(tools, \"python_3_12\")\n";
        let found = run(recognize, &[("MODULE.bazel", module)]);
        let seen: Vec<_> = found
            .hubs
            .iter()
            .map(|hub| {
                (
                    detail(hub).kind,
                    hub.ecosystem,
                    hub.decl.apparent_name.as_str(),
                )
            })
            .collect();
        let kind = ReportOnlyKind::NonRootModuleHub;
        // The usage with a tag of the root's own is its recognizer's, and
        // an extension that makes no hub is nobody's.
        assert_eq!(
            seen,
            [
                (kind, Ecosystem::Pypi, "their_pip"),
                (kind, Ecosystem::Pypi, "mine")
            ]
        );
        assert_eq!(kind.token(), "hub_not_root_module");
        assert_eq!(found.out_of_scope.bazel_modules, 2);
        assert_eq!(found.out_of_scope.report_only_pins, 0);
    }

    /// "No tag was recorded" is not "the root gives no tag": tags behind a
    /// statement that is not read are the root's own (the idiom of
    /// protobuf@29.0 `MODULE.bazel`), and their hub is no other module's.
    #[test]
    fn a_usage_whose_tags_were_not_read_is_not_another_modules() {
        let pip = "module(name = \"app\")\nbazel_dep(name = \"rules_python\", version = \"1.4.1\")\n\
             pip = use_extension(\"@rules_python//python/extensions:pip.bzl\", \"pip\")\n\
             [pip.parse(hub_name = n, python_version = \"3.12\", requirements_lock = \"//:requirements.txt\") \
             for n in [\"pypi\"]]\nuse_repo(pip, \"pypi\")\n";
        let found = run(recognize, &[("MODULE.bazel", pip)]);
        // The gap is rules_python's to report, which reads the usage.
        assert!(found.hubs.is_empty() && found.gaps.is_empty(), "{found:?}");
        let cargo = "module(name = \"app\")\nbazel_dep(name = \"rules_rust\", version = \"0.75.0\")\n\
             crate = use_extension(\"@rules_rust//crate_universe:extensions.bzl\", \"crate\")\n\
             [crate.from_cargo(name = n, cargo_lockfile = \"//:Cargo.lock\") for n in [\"crates\"]]\n\
             use_repo(crate, \"crates\")\n";
        let found = run(recognize, &[("MODULE.bazel", cargo)]);
        assert!(found.hubs.is_empty() && found.gaps.is_empty(), "{found:?}");

        // rules_req_compile has no other recognizer: here the tags that
        // were not read are a gap, with or without an import.
        let head = "module(name = \"app\")\nbazel_dep(name = \"rules_req_compile\", version = \"1.7.1\")\n\
             requirements = use_extension(\"@rules_req_compile//extensions:python.bzl\", \"requirements\")\n\
             [requirements.parse(name = n, requirements_lock = \"//:requirements.txt\") for n in [\"a\"]]\n";
        for imports in ["", "use_repo(requirements, \"a\")\n"] {
            let found = run(recognize, &[("MODULE.bazel", &format!("{head}{imports}"))]);
            assert!(found.hubs.is_empty(), "{imports}: {:?}", found.hubs);
            let [gap] = &found.gaps[..] else {
                panic!("{imports}: one gap: {:?}", found.gaps)
            };
            assert_eq!(gap.token, "label_not_literal");
            assert!(
                gap.detail.starts_with("MODULE.bazel:4: `requirements`: "),
                "{}",
                gap.detail
            );
        }
    }

    /// A hub whose name is computed may be any hub: a gap, by name.
    #[test]
    fn a_computed_name_of_a_lock_hub_is_a_gap() {
        let module = "module(name = \"app\")\nbazel_dep(name = \"rules_req_compile\", version = \"1.7.1\")\n\
             requirements = use_extension(\"@rules_req_compile//extensions:python.bzl\", \"requirements\")\n\
             requirements.parse(name = NAME, requirements_lock = \"//:requirements.txt\")\n";
        let found = run(recognize, &[("MODULE.bazel", module)]);
        let [hub] = &found.hubs[..] else {
            panic!("one hub: {:?}", found.hubs)
        };
        assert!(!hub.decl.literal && hub.decl.apparent_name.is_empty());
        assert_eq!(paths(hub), [("requirements.txt", LockRole::PackageLock)]);
        let [gap] = &found.gaps[..] else {
            panic!("one gap: {:?}", found.gaps)
        };
        assert_eq!(gap.token, "label_not_literal");
        let unread = "MODULE.bazel:4: `requirements.parse`: name cannot be followed";
        assert!(gap.detail.starts_with(unread), "{}", gap.detail);
    }

    /// A function of the same name in the main repository is the user's
    /// own code, as for rules_poetry.
    #[test]
    fn a_requirements_rule_of_the_main_repository_is_no_hub() {
        let own = workspace(
            "load(\"//:defs.bzl\", \"py_requirements_repository\")\n\
             py_requirements_repository(name = \"deps\", requirements_lock = \"//:requirements.txt\")\n",
        );
        assert!(own.hubs.is_empty() && own.gaps.is_empty());

        // The ruleset's own rule in a statement that is not read.
        let looped = workspace(
            "load(\"@rules_req_compile//:defs.bzl\", \"py_requirements_repository\")\n\
             [py_requirements_repository(name = n, requirements_lock = \"//:requirements.txt\") \
             for n in [\"deps\"]]\n",
        );
        assert!(looped.hubs.is_empty());
        let [gap] = &looped.gaps[..] else {
            panic!("one gap: {:?}", looped.gaps)
        };
        let unread = "WORKSPACE:2: a use of `py_requirements_repository` is not read: ";
        assert!(gap.detail.starts_with(unread), "{}", gap.detail);
    }
}
