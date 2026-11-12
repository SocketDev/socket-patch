//! Recognizer: rules_pycross hubs (design 2.7; probe Y4).
//!
//! rules_pycross has two tag APIs, and which one a root uses is also the
//! proof of its version line:
//!
//! - 0.x: `lock_import.import_{uv,poetry,pdm}(lock_file, project_file,
//!   repo, local_wheels)`, with the hub repository made by the separate
//!   `lock_repos` extension (`use_repo(lock_repos, "<repo>")`);
//! - 2.0: one extension per lock format, `{uv,poetry,pdm,pylock}.workspace(
//!   name, lock_file, local_wheels, extra_project_files)` with
//!   `.repo(workspace, name)` (read at
//!   `v2.0.1:pycross/private/format_extension.bzl:26-45`; the tags first
//!   exist at `v2.0.0-alpha.1`, and `v2.0.0-alpha.0` still has the 0.x
//!   extensions). A `poetry.workspace` tag exists on 2.0 only.
//!
//! The 2.0 tags name no manifest. The paired one is the `pyproject.toml`
//! in the lock's package: the extension reads the manifest of each
//! project the lock lists, relative to the lock, and that file when it
//! lists none (`v2.0.1:pycross/private/lock_common.bzl:136-164, 380-397`),
//! and Bazel records it as an input although no tag names it (probe Y4
//! 2.5.4). So it is listed among the files the hub reads, and each
//! `extra_project_files` label is a further one. The manifests of other
//! workspace members are found from the lock itself, which this reader
//! does not open. On 0.x the pair is the tag's `project_file`, and it
//! must be the file beside the lock.
//!
//! uv and poetry locks are the shapes a lane can take. pdm and pylock
//! locks, `lock_file.instantiate` and the `WORKSPACE` rules are recognized
//! so that they are refused: no rewrite of theirs is one the ruleset
//! consumes, or a generated `.bzl` stands between the lock and the build.

use super::pip_compile::PipCompileDetail;
use super::rules_python::{
    called_rule, lock_checks, module_version, ruleset_load, unread_module, wheel_package,
    ExtensionUse, HubImport, PairedManifest, Pick, Ran, Reading, Usage, USER_OVERRIDE,
};
use super::{RecognizeInput, Recognized};
use crate::bazel::model::{
    Bypass, HubShape, LockRef, LockRole, Ruleset, RulesetDetail, Site, UserDecl,
};
use crate::bazel::module_file::ModuleModel;
use crate::bazel::ruleset_version::{Unproven, VersionVerdict};
use crate::bazel::version::Tri;
use crate::bazel::workspace_file::WorkspaceModel;
use crate::crawlers::python_crawler::canonicalize_pypi_name;

const MODULES: [&str; 1] = ["rules_pycross"];

/// The package of every extension file.
const EXTENSIONS: &str = "pycross/extensions";

/// The first release that has the 2.0 extensions
/// (`v2.0.0-alpha.1:pycross/extensions/uv.bzl`).
const WORKSPACE_TAGS_FROM: &str = "2.0.0-alpha.1";

/// Which declaration makes the hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PycrossApi {
    /// 0.x `lock_import.import_<format>` with `lock_repos`.
    LockImport,
    /// 2.0 `<format>.workspace` with `<format>.repo`.
    Workspace,
    /// `lock_file.instantiate` over a generated `.bzl` lock.
    Instantiate,
    /// `pycross_lock_repo` or `pycross_lock_file_repo` in a `WORKSPACE`.
    WorkspaceRule,
}

/// The format of the lock a hub reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PycrossLock {
    Uv,
    Poetry,
    Pdm,
    Pylock,
    /// A `.bzl` file that `pycross_lock_file` generated from a lock.
    GeneratedBzl,
    /// A `WORKSPACE` `pycross_lock_repo`, whose lock model is a call this
    /// reader does not follow.
    Unread,
}

/// A `package` tag: the user's build settings for one package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageOverride {
    /// PEP 503-normalized, without the `@version` of a package key; `*`
    /// for the wildcard of 2.0.
    pub package: String,
    /// `build_target`: the package can be built by the user's own target
    /// instead of from the pinned files.
    pub replacement: bool,
    pub site: Site,
}

/// What this recognizer records about one hub.
#[derive(Debug, Clone, PartialEq)]
pub struct RulesPycrossDetail {
    pub api: PycrossApi,
    pub lock: PycrossLock,
    /// The extension that reads the lock, as `MODULE.bazel.lock` keys its
    /// entry: `lock_import` on 0.x, where `lock_repos` makes the
    /// repositories. `None` for a `WORKSPACE` hub.
    pub extension: Option<ExtensionUse>,
    /// The tag is a dev dependency (its proxy is one, or its file is in
    /// a dev include): the hub is gone under `--ignore_dev_dependency`.
    pub dev: bool,
    /// The repositories the hub generates: `repo` on 0.x; on 2.0 the
    /// name of each `.repo` tag of the workspace, which defaults to the
    /// workspace's, and with no `.repo` tag the one repository the
    /// extension then makes under the workspace's name.
    pub repos: Vec<String>,
    /// 0.x: the tag's `project_file` against the `pyproject.toml` beside
    /// the lock. 2.0: that file, which no tag names.
    pub manifest: PairedManifest,
    /// The `use_repo` names that make the hub visible to the root module.
    pub imports: Vec<HubImport>,
    /// `local_wheels`: a file here replaces the same-named file of the
    /// lock with no digest check.
    pub local_wheels: Vec<String>,
    pub packages: Vec<PackageOverride>,
    /// The scan of the lock for lock checks.
    pub lock_checks: Vec<PipCompileDetail>,
}

/// The formats, by the name of their 0.x tag suffix and 2.0 extension.
const FORMATS: [(&str, PycrossLock); 4] = [
    ("uv", PycrossLock::Uv),
    ("poetry", PycrossLock::Poetry),
    ("pdm", PycrossLock::Pdm),
    ("pylock", PycrossLock::Pylock),
];

/// The row of design 4.2: uv and poetry locks through a tag API are the
/// lock-import shape, everything else is recognized to be refused.
fn shape(api: PycrossApi, lock: PycrossLock) -> HubShape {
    let tags = matches!(api, PycrossApi::LockImport | PycrossApi::Workspace);
    match lock {
        PycrossLock::Uv | PycrossLock::Poetry if tags => HubShape::PycrossLockImport,
        _ => HubShape::PycrossUnsupported,
    }
}

/// The `package` tags of one usage, each with the hub it belongs to
/// (`repo` on 0.x, `workspace` on 2.0; `None` when the tag names none).
fn packages<'a>(
    usage: &Usage<'a>,
    hub: &str,
    out: &mut Recognized,
) -> Vec<(Option<&'a str>, PackageOverride)> {
    let mut found = Vec::new();
    for tag in usage.tagged("package") {
        let mut reading = Reading::tag(usage.model, tag);
        if let Some(key) = reading.text("name") {
            // A package key is `name` or `name@version`.
            let name = key.split('@').next().unwrap_or(key);
            let package = match name {
                "*" => name.to_string(),
                name => canonicalize_pypi_name(name),
            };
            let over = PackageOverride {
                package,
                replacement: reading.has("build_target"),
                site: reading.site.clone(),
            };
            found.push((reading.plain(hub), over));
        }
        out.gaps.append(&mut reading.gaps);
    }
    found
}

/// What one lock tag gives a hub.
struct Declared<'a> {
    reading: Reading<'a>,
    api: PycrossApi,
    lock: PycrossLock,
    dev: bool,
    repos: Vec<String>,
    manifest: PairedManifest,
    imports: Vec<HubImport>,
    packages: Vec<PackageOverride>,
}

/// Completes one hub: its local wheels, lock checks, bypasses and consent
/// evidence.
fn push(
    input: &RecognizeInput<'_>,
    declared: Declared<'_>,
    version: &VersionVerdict,
    usage: Option<&Usage<'_>>,
    out: &mut Recognized,
) {
    let Declared {
        mut reading,
        api,
        lock,
        dev,
        repos,
        manifest,
        imports,
        packages,
    } = declared;
    let local_wheels = match reading.texts("local_wheels", Pick::Items) {
        Some(wheels) => wheels.into_iter().map(str::to_string).collect(),
        None => {
            reading.computed("local_wheels");
            Vec::new()
        }
    };
    let (scans, rows) = lock_checks(input.files, &reading.locks, Tri::Maybe, &mut reading.gaps);
    let first = imports.first().map(|import| import.local.clone());
    let apparent = first.or_else(|| repos.first().cloned()).unwrap_or_default();
    let site = reading.site.clone();
    let detail = RulesPycrossDetail {
        api,
        lock,
        extension: usage.and_then(Usage::extension),
        dev,
        repos,
        manifest,
        imports,
        local_wheels: local_wheels.clone(),
        packages: packages.clone(),
        lock_checks: scans,
    };
    let detail = RulesetDetail::RulesPycross(detail);
    let mut hub = reading.hub(shape(api, lock), detail, &apparent, version.clone());
    hub.derived = rows;
    hub.bypasses = usage.map(Usage::repo_overrides).unwrap_or_default();
    let replaced = |package: String, site: Site| {
        let what = package.clone();
        let bypass = Bypass {
            token: USER_OVERRIDE,
            what,
            site: Some(site.clone()),
        };
        let decl = UserDecl {
            package,
            replacement: true,
            site,
        };
        (bypass, decl)
    };
    // A local wheel stands in for the lock's file of its name. One whose
    // name is not a wheel's is kept under its label: which file it
    // replaces is not known.
    for wheel in &local_wheels {
        let package = wheel_package(wheel).unwrap_or_else(|| wheel.clone());
        let (bypass, decl) = replaced(package, site.clone());
        hub.bypasses.push(bypass);
        hub.user_decls.push(decl);
    }
    for over in packages {
        if over.replacement {
            let (bypass, decl) = replaced(over.package, over.site);
            hub.bypasses.push(bypass);
            hub.user_decls.push(decl);
        } else {
            hub.user_decls.push(UserDecl {
                package: over.package,
                replacement: false,
                site: over.site,
            });
        }
    }
    out.gaps.append(&mut reading.gaps);
    out.hubs.push(hub);
}

/// The 0.x API: `lock_import.import_<format>` tags, whose repositories
/// the `lock_repos` extension makes.
fn lock_import(input: &RecognizeInput<'_>, model: &ModuleModel, out: &mut Recognized) {
    let repos_usages = Usage::find(
        model,
        &MODULES,
        &[(EXTENSIONS, "lock_repos.bzl")],
        "lock_repos",
    );
    for usage in Usage::find(
        model,
        &MODULES,
        &[(EXTENSIONS, "lock_import.bzl")],
        "lock_import",
    ) {
        let gaps = usage.gaps();
        let before = out.hubs.len();
        let version = module_version(input, usage.module, None);
        let overrides = packages(&usage, "repo", out);
        for tag in usage.tags() {
            let format = tag.call.callee.strip_prefix("import_");
            let Some((_, lock)) = FORMATS.iter().find(|(name, _)| format == Some(*name)) else {
                continue;
            };
            let mut reading = Reading::tag(model, tag);
            let repo = reading.text("repo").unwrap_or_default();
            if repo.is_empty() && reading.literal {
                reading.computed("repo");
            }
            let path = reading.labels("lock_file", Pick::Items, LockRole::PackageLock);
            reading.labels("project_file", Pick::Items, LockRole::Config);
            let named = reading
                .locks
                .iter()
                .find(|file| file.role == LockRole::Config);
            let manifest = PairedManifest::of(path.first().map(String::as_str), named);
            let wanted = |name: &str| name == repo;
            let imports = repos_usages.iter().flat_map(|made| made.imports(wanted));
            let own = overrides
                .iter()
                .filter(|(of, _)| of.is_none_or(|of| of == repo));
            let declared = Declared {
                api: PycrossApi::LockImport,
                dev: tag.dev,
                lock: *lock,
                repos: vec![repo.to_string()],
                manifest,
                imports: imports.collect(),
                packages: own.map(|(_, over)| over.clone()).collect(),
                reading,
            };
            push(input, declared, &version, Some(&usage), out);
        }
        if out.hubs.len() == before && !gaps.is_empty() {
            out.signals.extend(usage.signal(Ruleset::RulesPycross));
        }
        out.gaps.extend(gaps);
    }
}

/// The 2.0 API: one extension per lock format.
fn workspaces(input: &RecognizeInput<'_>, model: &ModuleModel, out: &mut Recognized) {
    for (format, lock) in FORMATS {
        let file = format!("{format}.bzl");
        for usage in Usage::find(model, &MODULES, &[(EXTENSIONS, file.as_str())], format) {
            let gaps = usage.gaps();
            let before = out.hubs.len();
            let version = module_version(input, usage.module, Some(WORKSPACE_TAGS_FROM));
            let overrides = packages(&usage, "workspace", out);
            // `.repo(workspace = ..., name = ...)`: the repository of a
            // workspace, named after it unless `name` says otherwise.
            let mut repos: Vec<(Option<&str>, Option<&str>)> = Vec::new();
            for tag in usage.tagged("repo") {
                let mut reading = Reading::tag(model, tag);
                let of = reading.text("workspace");
                let name = reading.text("name");
                repos.push((of, name.or(of).filter(|_| reading.literal)));
                out.gaps.append(&mut reading.gaps);
            }
            for tag in usage.tagged("workspace") {
                let mut reading = Reading::tag(model, tag);
                let name = reading.text("name").unwrap_or_default();
                if name.is_empty() && reading.literal {
                    reading.computed("name");
                }
                let path = reading.labels("lock_file", Pick::Items, LockRole::PackageLock);
                // The extension reads the `pyproject.toml` of the lock's
                // package, and Bazel records it, though no tag names it.
                let manifest = PairedManifest::of(path.first().map(String::as_str), None);
                if let PairedManifest::Beside { path, .. } = &manifest {
                    let (dir, file) = path.rsplit_once('/').unwrap_or(("", path));
                    reading.locks.push(LockRef {
                        label: format!("//{dir}:{file}"),
                        path: Some(path.clone()),
                        role: LockRole::Config,
                    });
                }
                reading.labels("extra_project_files", Pick::Items, LockRole::Config);
                // With no `.repo` tag the extension makes one repository
                // for the workspace's only project, under its name
                // (`v2.0.1:pycross/private/lock_common.bzl:413-433`).
                let tagged: Vec<_> = repos.iter().filter(|(of, _)| *of == Some(name)).collect();
                let made: Vec<String> = match tagged.is_empty() {
                    true => vec![name.to_string()],
                    false => tagged
                        .iter()
                        .filter_map(|(_, repo)| Some(repo.as_ref()?.to_string()))
                        .collect(),
                };
                // The one workspace of the module needs no `workspace`.
                let own = overrides
                    .iter()
                    .filter(|(of, _)| of.is_none_or(|of| of == name));
                let declared = Declared {
                    api: PycrossApi::Workspace,
                    dev: tag.dev,
                    lock,
                    imports: usage.imports(|repo| made.iter().any(|made| made == repo)),
                    repos: made,
                    manifest,
                    packages: own.map(|(_, over)| over.clone()).collect(),
                    reading,
                };
                push(input, declared, &version, Some(&usage), out);
            }
            if out.hubs.len() == before && !gaps.is_empty() {
                out.signals.extend(usage.signal(Ruleset::RulesPycross));
            }
            out.gaps.extend(gaps);
        }
    }
}

/// `lock_file.instantiate(name, lock_file)`: a hub over a generated
/// `.bzl` lock, which an edit of the native lock never reaches.
fn instantiate(input: &RecognizeInput<'_>, model: &ModuleModel, out: &mut Recognized) {
    for usage in Usage::find(
        model,
        &MODULES,
        &[(EXTENSIONS, "lock_file.bzl")],
        "lock_file",
    ) {
        let gaps = usage.gaps();
        let before = out.hubs.len();
        let version = module_version(input, usage.module, None);
        for tag in usage.tagged("instantiate") {
            let mut reading = Reading::tag(model, tag);
            let name = reading.text("name").unwrap_or_default();
            if name.is_empty() && reading.literal {
                reading.computed("name");
            }
            reading.labels("lock_file", Pick::Items, LockRole::DerivedValue);
            let declared = Declared {
                api: PycrossApi::Instantiate,
                dev: tag.dev,
                lock: PycrossLock::GeneratedBzl,
                repos: vec![name.to_string()],
                manifest: PairedManifest::None,
                imports: usage.imports(|repo| repo == name),
                packages: Vec::new(),
                reading,
            };
            push(input, declared, &version, Some(&usage), out);
        }
        if out.hubs.len() == before && !gaps.is_empty() {
            out.signals.extend(usage.signal(Ruleset::RulesPycross));
        }
        out.gaps.extend(gaps);
    }
}

/// The 0.x `WORKSPACE` rules (`@rules_pycross//pycross:workspace.bzl`):
/// `pycross_lock_repo(name, lock_model = lock_repo_model_<format>(...))`
/// and `pycross_lock_file_repo(name, lock_file)`.
fn workspace(input: &RecognizeInput<'_>, ws: &WorkspaceModel, out: &mut Recognized) {
    for (file, stmt, call) in Ran::of(ws).calls {
        let Some((load, rule, maybe)) = called_rule(file, call) else {
            continue;
        };
        if ruleset_load(load, "pycross", "workspace.bzl").is_none() {
            continue;
        }
        let lock = match rule {
            "pycross_lock_repo" => PycrossLock::Unread,
            "pycross_lock_file_repo" => PycrossLock::GeneratedBzl,
            _ => continue,
        };
        let mut reading = Reading::rule(ws, file, stmt, call, (rule, maybe));
        let name = reading.text("name").unwrap_or_default();
        if name.is_empty() && reading.literal {
            reading.computed("name");
        }
        match lock {
            PycrossLock::GeneratedBzl => {
                reading.labels("lock_file", Pick::Items, LockRole::DerivedValue);
            }
            // The lock and its manifest are arguments of the nested
            // `lock_repo_model_<format>(...)` call.
            _ => reading
                .unnamed_lock("names its lock inside the `lock_model` call, which is not read"),
        }
        let declared = Declared {
            api: PycrossApi::WorkspaceRule,
            dev: false,
            lock,
            repos: vec![name.to_string()],
            manifest: PairedManifest::Unresolved,
            imports: Vec::new(),
            packages: Vec::new(),
            reading,
        };
        let version = VersionVerdict::unknown(Unproven::WorkspaceDefinition);
        push(input, declared, &version, None, out);
    }
}

/// The hubs, signals and gaps of this ruleset in `input`.
pub fn recognize(input: &RecognizeInput<'_>) -> Recognized {
    let mut out = Recognized::default();
    if let Some(model) = input.module {
        lock_import(input, model, &mut out);
        workspaces(input, model, &mut out);
        instantiate(input, model, &mut out);
        unread_module(model, &MODULES, Ruleset::RulesPycross, &mut out);
    }
    for ws in input.workspace_files {
        workspace(input, ws, &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::rules_python::tests::{gap_files, locals, locks, sides, Root};
    use super::*;
    use crate::bazel::model::{DeclSystem, Hub, Liveness};
    use crate::bazel::module_file::tests::fixtures;
    use crate::bazel::ruleset_version::Source;
    use crate::crawlers::types::Ecosystem;

    fn detail(hub: &Hub) -> &RulesPycrossDetail {
        match &hub.detail {
            RulesetDetail::RulesPycross(detail) => detail,
            other => panic!("not a rules_pycross hub: {other:?}"),
        }
    }

    fn recognized(files: &[(&str, &str)]) -> Recognized {
        Root::of(files).recognize(recognize)
    }

    /// The one hub of a root, which must be read in full.
    fn one(text: &str) -> Hub {
        let found = recognized(&[("MODULE.bazel", text)]);
        assert_eq!((&found.gaps, &found.signals), (&vec![], &vec![]), "{text}");
        assert_eq!(found.hubs.len(), 1, "{text}");
        found.hubs.into_iter().next().unwrap()
    }

    /// `heavy/rules_pycross/bzlmod/e9-0.8.3/MODULE.bazel`: the 0.x API
    /// (probe Y4, workspace `px0-uv-b8`).
    const LOCK_IMPORT: &str = "module(name = \"socket_fixture\", version = \"0.0.0\")\n\
        \n\
        bazel_dep(name = \"rules_pycross\", version = \"0.8.3\")\n\
        single_version_override(module_name = \"rules_pycross\", version = \"0.8.3\")\n\
        bazel_dep(name = \"rules_python\", version = \"2.0.0\")\n\
        single_version_override(module_name = \"rules_python\", version = \"2.0.0\")\n\
        \n\
        pycross = use_extension(\"@rules_pycross//pycross/extensions:pycross.bzl\", \"pycross\")\n\
        pycross.configure_environments(\n    platforms = [\n        \"aarch64-apple-darwin\",\n        \
        \"x86_64-unknown-linux-gnu\",\n    ],\n    python_versions = [\"3.12\"],\n)\n\
        \n\
        environments = use_extension(\"@rules_pycross//pycross/extensions:environments.bzl\", \"environments\")\n\
        use_repo(environments, \"pycross_environments\")\n\
        \n\
        lock_import = use_extension(\"@rules_pycross//pycross/extensions:lock_import.bzl\", \"lock_import\")\n\
        lock_import.import_uv(\n    lock_file = \"//:uv.lock\",\n    project_file = \"//:pyproject.toml\",\n    \
        repo = \"pypi\",\n)\n\
        \n\
        lock_repos = use_extension(\"@rules_pycross//pycross/extensions:lock_repos.bzl\", \"lock_repos\")\n\
        use_repo(lock_repos, \"pypi\")\n";

    /// `heavy/rules_pycross/bzlmod/e9/MODULE.bazel`: the 2.0 API (probe
    /// Y4, workspace `px2-uv-b8`). `FORMAT` and `LOCK` stand for the
    /// extension and its lock.
    const WORKSPACE_TAGS: &str = "module(name = \"socket_fixture\", version = \"0.0.0\")\n\
        \n\
        bazel_dep(name = \"rules_pycross\", version = \"2.0.1\")\n\
        single_version_override(module_name = \"rules_pycross\", version = \"2.0.1\")\n\
        bazel_dep(name = \"rules_python\", version = \"2.0.0\")\n\
        single_version_override(module_name = \"rules_python\", version = \"2.0.0\")\n\
        \n\
        pycross = use_extension(\"@rules_pycross//pycross/extensions:pycross.bzl\", \"pycross\")\n\
        pycross.configure_toolchains(\n    platforms = [\n        \"aarch64-apple-darwin\",\n        \
        \"x86_64-unknown-linux-gnu\",\n    ],\n    python_versions = [\"3.12\"],\n)\n\
        \n\
        FORMAT = use_extension(\"@rules_pycross//pycross/extensions:FORMAT.bzl\", \"FORMAT\")\n\
        FORMAT.workspace(\n    name = \"pypi\",\n    lock_file = \"//:LOCK\",\n)\n\
        FORMAT.repo(\n    dependency_groups = [\"default\"],\n    workspace = \"pypi\",\n)\n\
        use_repo(FORMAT, \"pypi\")\n";

    fn workspace_tags(format: &str, lock: &str) -> String {
        WORKSPACE_TAGS
            .replace("FORMAT", format)
            .replace("LOCK", lock)
    }

    #[test]
    fn the_0_8_3_golden_import_uv_with_lock_repos() {
        let hub = one(LOCK_IMPORT);
        assert_eq!(
            (hub.ruleset, hub.shape, hub.ecosystem),
            (
                Ruleset::RulesPycross,
                HubShape::PycrossLockImport,
                Ecosystem::Pypi
            )
        );
        assert_eq!(
            locks(&hub),
            [
                ("//:uv.lock", Some("uv.lock"), LockRole::PackageLock),
                (
                    "//:pyproject.toml",
                    Some("pyproject.toml"),
                    LockRole::Config
                ),
            ]
        );
        assert_eq!(
            (
                hub.decl.site.file.as_str(),
                hub.decl.site.system,
                hub.decl.literal
            ),
            ("MODULE.bazel", DeclSystem::Bzlmod, true)
        );
        assert!(matches!(hub.liveness, Liveness::Dead { .. }));
        let detail = detail(&hub);
        assert_eq!(
            (detail.api, detail.lock),
            (PycrossApi::LockImport, PycrossLock::Uv)
        );
        let extension = detail.extension.as_ref().expect("an extension");
        assert_eq!(
            (
                extension.bzl_file.as_str(),
                extension.name.as_str(),
                detail.dev
            ),
            (
                "@rules_pycross//pycross/extensions:lock_import.bzl",
                "lock_import",
                false
            )
        );
        assert_eq!(detail.repos, ["pypi"]);
        // The tag's `project_file` is the manifest beside the lock.
        let beside = PairedManifest::Beside {
            path: "pyproject.toml".to_string(),
            named: true,
        };
        assert_eq!(detail.manifest, beside);
        // The repository is made by `lock_repos`, and imported from it.
        assert_eq!(
            (locals(&detail.imports), hub.decl.apparent_name.as_str()),
            (vec!["pypi"], "pypi")
        );
        assert!(
            detail.local_wheels.is_empty() && hub.bypasses.is_empty() && hub.user_decls.is_empty()
        );
        let pinned = Some(("0.8.3", Source::SingleVersionOverride));
        assert_eq!(sides(&hub.ruleset_version), (pinned, pinned));
        // The 0.x API is no proof of 2.0.
        assert!(!hub.ruleset_version.at_least("2.0.0"));
    }

    #[test]
    fn the_2_0_1_golden_uv_workspace_with_uv_repo_has_the_manifest_of_the_locks_package() {
        let hub = one(&workspace_tags("uv", "uv.lock"));
        assert_eq!(hub.shape, HubShape::PycrossLockImport);
        // No tag names a manifest. The extension reads the
        // `pyproject.toml` of the lock's package and Bazel records it, so
        // it is a file of the hub, and the pair of the lock.
        assert_eq!(
            locks(&hub),
            [
                ("//:uv.lock", Some("uv.lock"), LockRole::PackageLock),
                (
                    "//:pyproject.toml",
                    Some("pyproject.toml"),
                    LockRole::Config
                ),
            ]
        );
        let detail = detail(&hub);
        assert_eq!(
            (detail.api, detail.lock),
            (PycrossApi::Workspace, PycrossLock::Uv)
        );
        let beside = PairedManifest::Beside {
            path: "pyproject.toml".to_string(),
            named: false,
        };
        assert_eq!(detail.manifest, beside);
        // No `paired_manifest_mismatch`: no label can disagree.
        assert_eq!(detail.manifest.refusal(), None);
        assert_eq!(detail.repos, ["pypi"]);
        assert_eq!(
            (locals(&detail.imports), hub.decl.apparent_name.as_str()),
            (vec!["pypi"], "pypi")
        );
        let pinned = Some(("2.0.1", Source::SingleVersionOverride));
        assert_eq!(sides(&hub.ruleset_version), (pinned, pinned));
        assert!(hub.ruleset_version.at_least("2.0.0"));
    }

    #[test]
    fn the_2_0_1_goldens_poetry_is_a_lock_import_and_pylock_and_pdm_are_refused_shapes() {
        let poetry = one(&workspace_tags("poetry", "poetry.lock"));
        assert_eq!(poetry.shape, HubShape::PycrossLockImport);
        assert_eq!(
            (detail(&poetry).api, detail(&poetry).lock),
            (PycrossApi::Workspace, PycrossLock::Poetry)
        );
        assert_eq!(poetry.locks[0].path.as_deref(), Some("poetry.lock"));
        assert_eq!(detail(&poetry).manifest.refusal(), None);

        // Probe Y4 2.4 (`px2-pylock-b8`): today's hosted pylock output
        // fails the 2.0.1 build, so the shape is recognized to be refused.
        let pylock = one(&workspace_tags("pylock", "pylock.toml"));
        assert_eq!(pylock.shape, HubShape::PycrossUnsupported);
        assert_eq!(detail(&pylock).lock, PycrossLock::Pylock);
        assert_eq!(pylock.locks[0].path.as_deref(), Some("pylock.toml"));
        let pdm = one(&workspace_tags("pdm", "pdm.lock"));
        assert_eq!(
            (pdm.shape, detail(&pdm).lock),
            (HubShape::PycrossUnsupported, PycrossLock::Pdm)
        );

        // The 0.x tags: poetry is a lock import there too (the lane asks
        // for 2.0 before it takes one), pdm is not.
        let old = |format: &str, lock: &str| {
            LOCK_IMPORT
                .replace("import_uv", &format!("import_{format}"))
                .replace("uv.lock", lock)
        };
        let poetry = one(&old("poetry", "poetry.lock"));
        assert_eq!(
            (poetry.shape, detail(&poetry).lock),
            (HubShape::PycrossLockImport, PycrossLock::Poetry)
        );
        assert_eq!(detail(&poetry).api, PycrossApi::LockImport);
        let pdm = one(&old("pdm", "pdm.lock"));
        assert_eq!(
            (pdm.shape, detail(&pdm).lock),
            (HubShape::PycrossUnsupported, PycrossLock::Pdm)
        );
    }

    #[test]
    fn the_workspace_tags_are_the_version_proof_from_their_first_release() {
        // A root that declares a 0.x release and uses `uv.workspace` was
        // lifted by another module: the tags exist from 2.0.0-alpha.1,
        // which is below 2.0.0.
        let text = workspace_tags("poetry", "poetry.lock");
        let text = text.replace(
            "single_version_override(module_name = \"rules_pycross\", version = \"2.0.1\")\n",
            "",
        );
        let lifted = one(&text.replace("version = \"2.0.1\"", "version = \"0.8.3\""));
        assert_eq!(
            sides(&lifted.ruleset_version),
            (Some(("2.0.0-alpha.1", Source::ApiShape)), None)
        );
        assert!(!lifted.ruleset_version.at_least("2.0.0"));
        assert_eq!(detail(&lifted).api, PycrossApi::Workspace);
        let declared = one(&text);
        assert_eq!(
            sides(&declared.ruleset_version).0,
            Some(("2.0.1", Source::Declared))
        );
    }

    #[test]
    fn a_lock_in_a_sub_package_pairs_with_the_manifest_of_that_package() {
        let text =
            workspace_tags("uv", "uv.lock").replace("\"//:uv.lock\"", "\"//services/api:uv.lock\"");
        let text = text.replace(
            "    lock_file",
            "    extra_project_files = [\"//libs/core:pyproject.toml\"],\n    lock_file",
        );
        let hub = one(&text);
        // Each `extra_project_files` label is a further recorded input.
        assert_eq!(
            locks(&hub),
            [
                (
                    "//services/api:uv.lock",
                    Some("services/api/uv.lock"),
                    LockRole::PackageLock
                ),
                (
                    "//services/api:pyproject.toml",
                    Some("services/api/pyproject.toml"),
                    LockRole::Config
                ),
                (
                    "//libs/core:pyproject.toml",
                    Some("libs/core/pyproject.toml"),
                    LockRole::Config
                ),
            ]
        );
        let beside = PairedManifest::Beside {
            path: "services/api/pyproject.toml".to_string(),
            named: false,
        };
        assert_eq!(detail(&hub).manifest, beside);

        // 0.x names its manifest, and one of another package is not the
        // file the native rewriter edits with the lock.
        let text = LOCK_IMPORT.replace("\"//:uv.lock\"", "\"//services/api:uv.lock\"");
        let mismatch = &detail(&one(&text)).manifest.clone();
        assert_eq!(
            *mismatch,
            PairedManifest::Mismatch {
                label: "//:pyproject.toml".to_string(),
                expected: "services/api/pyproject.toml".to_string(),
            }
        );
        assert_eq!(
            mismatch.refusal(),
            Some(super::super::rules_python::PAIRED_MANIFEST_MISMATCH)
        );
    }

    #[test]
    fn repositories_take_the_workspace_name_unless_a_repo_tag_names_them() {
        let text = workspace_tags("uv", "uv.lock").replace(
            "use_repo(uv, \"pypi\")\n",
            "uv.repo(name = \"pypi_dev\", dependency_groups = [\"*\"], workspace = \"pypi\")\n\
             uv.workspace(name = \"tools\", lock_file = \"//tools:uv.lock\")\n\
             use_repo(uv, \"pypi\", dev = \"pypi_dev\")\n",
        );
        let found = recognized(&[("MODULE.bazel", &text)]);
        assert_eq!((&found.gaps, &found.signals), (&vec![], &vec![]));
        let [pypi, tools] = &found.hubs[..] else {
            panic!("two hubs, found {:?}", found.hubs);
        };
        assert_eq!(detail(pypi).repos, ["pypi", "pypi_dev"]);
        assert_eq!(locals(&detail(pypi).imports), ["pypi", "dev"]);
        // A workspace with no `.repo` tag has one repository, under its
        // own name; here nothing imports it.
        assert_eq!(detail(tools).repos, ["tools"]);
        assert!(detail(tools).imports.is_empty());
        assert_eq!(tools.decl.apparent_name, "tools");
        assert_eq!(tools.locks[0].path.as_deref(), Some("tools/uv.lock"));
    }

    #[test]
    fn local_wheels_and_build_targets_replace_packages_and_patches_do_not() {
        // Probe Y4.e: a local wheel stands in for the lock's file of its
        // name with no digest check, on both API lines.
        let wheel = "//.socket/vendor/pypi/0b5e1c1e:six-1.16.0-py2.py3-none-any.whl";
        let text = workspace_tags("uv", "uv.lock").replace(
            "    lock_file = \"//:uv.lock\",\n",
            &format!("    local_wheels = [\"{wheel}\"],\n    lock_file = \"//:uv.lock\",\n"),
        );
        let text = format!(
            "{text}uv.package(name = \"psycopg2\", build_target = \"@//deps/psycopg2:wheel\", workspace = \"pypi\")\n\
             uv.package(name = \"PyYAML@6.0.2\", post_install_patches = [\"//:yaml.patch\"])\n\
             uv.package(name = \"other\", build_target = \"//:other\", workspace = \"elsewhere\")\n"
        );
        let hub = one(&text);
        assert_eq!(detail(&hub).local_wheels, [wheel]);
        let bypassed: Vec<_> = hub
            .bypasses
            .iter()
            .map(|bypass| (bypass.token, bypass.what.as_str()))
            .collect();
        assert_eq!(
            bypassed,
            [(USER_OVERRIDE, "six"), (USER_OVERRIDE, "psycopg2")]
        );
        let decls: Vec<_> = hub
            .user_decls
            .iter()
            .map(|decl| (decl.package.as_str(), decl.replacement))
            .collect();
        // A tag with no `workspace` belongs to the module's one workspace;
        // one of another workspace is not this hub's.
        assert_eq!(
            decls,
            [("six", true), ("psycopg2", true), ("pyyaml", false)]
        );

        let text = LOCK_IMPORT.replace(
            "    repo = \"pypi\",\n",
            &format!("    local_wheels = [\"{wheel}\"],\n    repo = \"pypi\",\n"),
        );
        let hub = one(&text);
        assert_eq!(hub.bypasses[0].what, "six");
        // A computed list could name any wheel.
        let text = LOCK_IMPORT.replace(
            "    repo = \"pypi\",\n",
            "    local_wheels = WHEELS,\n    repo = \"pypi\",\n",
        );
        let found = recognized(&[("MODULE.bazel", &text)]);
        assert_eq!(gap_files(&found), ["MODULE.bazel"]);
        assert!(!found.hubs[0].decl.literal);
    }

    /// The root module of the rules_pycross 2.0.1 `e2e/build_setuptools`
    /// workspace (the Starlark corpus). Its segments are not in the view,
    /// so the module was not read in full; the hub it shows still is.
    #[test]
    fn the_rules_pycross_e2e_module_has_a_uv_hub_and_a_build_target_override() {
        let name = "rules_pycross-2.0.1-build_setuptools.MODULE.bazel";
        let text = std::fs::read_to_string(fixtures().join("starlark/corpus").join(name));
        let found = recognized(&[("MODULE.bazel", &text.expect("the corpus file"))]);
        let [hub] = &found.hubs[..] else {
            panic!("one hub, found {:?}", found.hubs);
        };
        let detail = detail(hub);
        assert_eq!(
            (hub.shape, detail.api, detail.lock),
            (
                HubShape::PycrossLockImport,
                PycrossApi::Workspace,
                PycrossLock::Uv
            )
        );
        assert_eq!(
            (detail.repos.clone(), locals(&detail.imports)),
            (vec!["uv".to_string()], vec!["uv"])
        );
        let packages: Vec<_> = detail
            .packages
            .iter()
            .map(|over| (over.package.as_str(), over.replacement))
            .collect();
        assert_eq!(
            packages,
            [
                ("psycopg2", true),
                ("setproctitle", false),
                ("pyyaml", false)
            ]
        );
        // `local_path_override`, and segments that were not read: no
        // version is proven.
        assert!(hub.ruleset_version.lo.is_none() && hub.ruleset_version.hi.is_none());
        // The gaps of the whole model are the workspace reader's to
        // report; the usage itself was read.
        assert!(found.gaps.is_empty() && found.signals.is_empty());
    }

    #[test]
    fn generated_locks_and_workspace_rules_are_recognized_to_be_refused() {
        let text = "bazel_dep(name = \"rules_pycross\", version = \"0.8.3\")\n\
                    lock_file = use_extension(\"@rules_pycross//pycross/extensions:lock_file.bzl\", \"lock_file\")\n\
                    lock_file.instantiate(name = \"pypi\", lock_file = \"//third_party:lock.bzl\")\n\
                    use_repo(lock_file, \"pypi\")\n";
        let hub = one(text);
        assert_eq!(hub.shape, HubShape::PycrossUnsupported);
        assert_eq!(
            (detail(&hub).api, detail(&hub).lock),
            (PycrossApi::Instantiate, PycrossLock::GeneratedBzl)
        );
        // The `.bzl` is derived from a lock; no package lock is named.
        assert_eq!(
            locks(&hub),
            [(
                "//third_party:lock.bzl",
                Some("third_party/lock.bzl"),
                LockRole::DerivedValue
            )]
        );
        assert_eq!(locals(&detail(&hub).imports), ["pypi"]);

        let workspace = "load(\"@rules_pycross//pycross:workspace.bzl\", \"lock_repo_model_uv\", \"pycross_lock_file_repo\", \"pycross_lock_repo\")\n\
                         pycross_lock_file_repo(name = \"generated\", lock_file = \"//:lock.bzl\")\n\
                         pycross_lock_repo(\n    name = \"pypi\",\n    \
                         lock_model = lock_repo_model_uv(lock_file = \"//:uv.lock\", project_file = \"//:pyproject.toml\"),\n)\n";
        let found = recognized(&[("WORKSPACE", workspace)]);
        let [generated, pypi] = &found.hubs[..] else {
            panic!("two hubs, found {:?}", found.hubs);
        };
        for hub in [generated, pypi] {
            assert_eq!(
                (hub.shape, hub.decl.site.system),
                (HubShape::PycrossUnsupported, DeclSystem::Workspace)
            );
            assert_eq!(detail(hub).api, PycrossApi::WorkspaceRule);
            assert!(hub.ruleset_version.lo.is_none());
        }
        assert_eq!(
            locks(generated),
            [("//:lock.bzl", Some("lock.bzl"), LockRole::DerivedValue)]
        );
        // The lock of `pycross_lock_repo` is an argument of a nested call:
        // the hub reads a lock this reader cannot name, and says so.
        assert_eq!(
            (detail(pypi).lock, pypi.decl.literal),
            (PycrossLock::Unread, false)
        );
        assert_eq!(locks(pypi), [("", None, LockRole::PackageLock)]);
        assert_eq!(gap_files(&found), ["WORKSPACE"]);
    }

    #[test]
    fn what_is_not_rules_pycross_or_was_not_read_is_no_hub() {
        // The ruleset with no lock tag, and another module's file of the
        // same path.
        let bare = "bazel_dep(name = \"rules_pycross\", version = \"2.0.1\")\n\
                    pycross = use_extension(\"@rules_pycross//pycross/extensions:pycross.bzl\", \"pycross\")\n\
                    pycross.configure_toolchains(python_versions = [\"3.12\"])\n";
        assert_eq!(recognized(&[("MODULE.bazel", bare)]), Recognized::default());
        let foreign = workspace_tags("uv", "uv.lock").replace("rules_pycross", "my_pycross");
        assert_eq!(
            recognized(&[("MODULE.bazel", &foreign)]),
            Recognized::default()
        );
        assert_eq!(recognized(&[]), Recognized::default());

        // A workspace tag under an `if`: the usage was not all read.
        let hidden = "bazel_dep(name = \"rules_pycross\", version = \"2.0.1\")\n\
                      uv = use_extension(\"@rules_pycross//pycross/extensions:uv.bzl\", \"uv\")\n\
                      if True:\n    uv.workspace(name = \"pypi\", lock_file = \"//:uv.lock\")\n";
        let found = recognized(&[("MODULE.bazel", hidden)]);
        assert!(found.hubs.is_empty() && !found.gaps.is_empty());
        assert_eq!(found.signals.len(), 1);
        assert_eq!(found.signals[0].ruleset, Ruleset::RulesPycross);

        // A computed lock label and a computed workspace name.
        let computed = "bazel_dep(name = \"rules_pycross\", version = \"2.0.1\")\n\
                        uv = use_extension(\"@rules_pycross//pycross/extensions:uv.bzl\", \"uv\")\n\
                        uv.workspace(name = NAME, lock_file = lock())\n";
        let found = recognized(&[("MODULE.bazel", computed)]);
        assert_eq!(gap_files(&found), ["MODULE.bazel"; 2]);
        let hub = &found.hubs[0];
        assert!(!hub.decl.literal);
        assert_eq!(locks(hub), [("", None, LockRole::PackageLock)]);
        assert_eq!(detail(hub).manifest, PairedManifest::Unresolved);
    }
}
