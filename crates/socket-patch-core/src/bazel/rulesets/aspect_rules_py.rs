//! Recognizer: aspect_rules_py `uv` hubs (design 2.7; probe Y4).
//!
//! The `uv` extension has two tag APIs, and which one a root uses decides
//! whether a lock edit reaches the build at all:
//!
//! - `uv.project(hub_name, lock, pyproject)` from 1.8.5, with
//!   `uv.override_package`;
//! - `uv.lockfile(hub_name, venv_name, src)` on 1.7.0 to 1.8.4, with
//!   `uv.override_requirement`. Those releases never watch the lock, so
//!   on an existing output base a rewrite is a silent no-op (probe Y4
//!   2.5.4): the shape is recognized so that it can be refused.
//!
//! The tag API proves less than it seems to. `uv.project` exists from
//! 1.8.5, and cells ran only on 1.13.0 and the 2.0 alphas, so admission
//! needs a version of its own: the verdict is kept in
//! `Hub::ruleset_version` beside [`AspectRulesPyDetail::api`], and the tag
//! only lends it a floor.
//!
//! The extension is `//uv/unstable:extension.bzl` on 1.x and
//! `//uv:extensions.bzl` on 2.0, and the module is `rules_py` from
//! 2.0.0-alpha.11 (read at `v1.7.0`, `v1.8.4`, `v1.8.5`, `v1.13.0`,
//! `v2.0.0-alpha.10` and `v2.0.0-alpha.11`). It is Bzlmod only.

use super::pip_compile::PipCompileDetail;
use super::rules_python::{
    lock_checks, module_version, unread_module, ExtensionUse, HubImport, PairedManifest, Pick,
    Reading, Usage, USER_OVERRIDE,
};
use super::{RecognizeInput, Recognized};
use crate::bazel::model::{Bypass, HubShape, LockRole, Ruleset, RulesetDetail, Site, UserDecl};
use crate::bazel::module_file::Tag;
use crate::bazel::version::Tri;
use crate::crawlers::python_crawler::canonicalize_pypi_name;

const MODULES: [&str; 2] = ["aspect_rules_py", "rules_py"];

const UV_EXTENSION: [(&str, &str); 2] =
    [("uv/unstable", "extension.bzl"), ("uv", "extensions.bzl")];

/// The first release whose extension has `uv.project`
/// (`v1.8.5:uv/private/extension/defs.bzl`; `v1.8.4` has `uv.lockfile`).
/// 1.8.5 has no release candidate.
const PROJECT_FROM: &str = "1.8.5";

/// Which tag declares the hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UvApi {
    /// `uv.project(lock, pyproject)`: the lock is a watched input.
    Project,
    /// `uv.lockfile(src)`: the lock is read once per output base.
    Lockfile,
}

/// `uv.override_package` or `uv.override_requirement` on one package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UvOverride {
    /// PEP 503-normalized.
    pub package: String,
    /// The version the override is limited to, when it names one.
    pub version: Option<String>,
    /// The package is built from the user's own `target`, so no pin in
    /// the lock reaches the build (probe Y4.g: no warning, exit 0). An
    /// override without a target patches the pinned wheel instead.
    pub replacement: bool,
    pub site: Site,
}

/// What this recognizer records about one hub.
#[derive(Debug, Clone, PartialEq)]
pub struct AspectRulesPyDetail {
    pub api: UvApi,
    /// The hub's name inside the extension. Empty when it is computed.
    pub hub_name: String,
    /// The `uv` extension, as `MODULE.bazel.lock` keys its entry.
    pub extension: Option<ExtensionUse>,
    /// The tag is a dev dependency (its proxy is one, or its file is in
    /// a dev include): the hub is gone under `--ignore_dev_dependency`.
    pub dev: bool,
    /// The tag's `pyproject` against the `pyproject.toml` beside its
    /// lock. A `uv.lockfile` tag names none.
    pub manifest: PairedManifest,
    /// The `use_repo` names that make the hub visible to the root module.
    pub imports: Vec<HubImport>,
    /// The overrides that apply to this hub's lock.
    pub overrides: Vec<UvOverride>,
    /// The scan of the lock for lock checks (a `gazelle_python_manifest`
    /// can hash a `uv.lock`).
    pub lock_checks: Vec<PipCompileDetail>,
}

/// Where an override applies.
enum Applies {
    /// No `lock`: every project of the usage (2.0.0-alpha.11).
    Everywhere,
    /// The project whose lock is this path.
    Lock(String),
    /// The `uv.lockfile` hub of this name.
    Hub(String),
}

/// The package a requirement string names: `six` for `six==1.16.0`.
fn requirement_package(requirement: &str) -> String {
    let name = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');
    let end = requirement.find(|c| !name(c)).unwrap_or(requirement.len());
    canonicalize_pypi_name(&requirement[..end])
}

/// The overrides of one usage, each with where it applies. An override
/// whose package or place cannot be read applies everywhere it could and
/// leaves a gap.
fn overrides<'a>(usage: &Usage<'a>, out: &mut Recognized) -> Vec<(Applies, UvOverride)> {
    let mut found = Vec::new();
    let tags = usage
        .tags()
        .filter(|tag| tag.call.callee.starts_with("override_"));
    for tag in tags {
        let mut reading = Reading::tag(usage.model, tag);
        let (name, replacement, applies) = match tag.call.callee.as_str() {
            "override_package" => {
                let lock = reading.has("lock");
                let paths = reading.labels("lock", Pick::Items, LockRole::PackageLock);
                let applies = match (lock, paths.into_iter().next()) {
                    (true, Some(path)) => Applies::Lock(path),
                    _ => Applies::Everywhere,
                };
                // `post_install_patches` and `pre_build_patches` alone
                // patch the wheel the lock pins.
                (reading.text("name"), reading.has("target"), applies)
            }
            "override_requirement" => {
                let applies = match reading.text("hub_name") {
                    Some(hub) => Applies::Hub(hub.to_string()),
                    None => Applies::Everywhere,
                };
                let package = reading.text("requirement");
                (package, true, applies)
            }
            _ => continue,
        };
        if let Some(name) = name {
            let over = UvOverride {
                package: requirement_package(name),
                version: reading.plain("version").map(str::to_string),
                replacement,
                site: reading.site.clone(),
            };
            found.push((applies, over));
        }
        out.gaps.append(&mut reading.gaps);
    }
    found
}

/// The hubs, signals and gaps of this ruleset in `input`.
pub fn recognize(input: &RecognizeInput<'_>) -> Recognized {
    let mut out = Recognized::default();
    let Some(model) = input.module else {
        return out;
    };
    for usage in Usage::find(model, &MODULES, &UV_EXTENSION, "uv") {
        let gaps = usage.gaps();
        let before = out.hubs.len();
        let overrides = overrides(&usage, &mut out);
        let declares = |tag: &&Tag| matches!(tag.call.callee.as_str(), "project" | "lockfile");
        let hubs: Vec<&Tag> = usage.tags().filter(declares).collect();
        // The floor is the module's own: `rules_py` starts at an alpha of
        // 2.0, which its `bazel_dep` already says.
        let project = hubs.iter().any(|tag| tag.call.callee == "project");
        let floor = (project && usage.module == Some(MODULES[0])).then_some(PROJECT_FROM);
        let version = module_version(input, usage.module, floor);

        for tag in hubs {
            let mut reading = Reading::tag(model, tag);
            let name = reading.text("hub_name").unwrap_or_default();
            if name.is_empty() && reading.literal {
                reading.computed("hub_name");
            }
            let (api, shape, lock, manifest) = match tag.call.callee.as_str() {
                "project" => {
                    let lock = reading.labels("lock", Pick::Items, LockRole::PackageLock);
                    let lock = lock.into_iter().next();
                    reading.labels("pyproject", Pick::Items, LockRole::Config);
                    let named = reading
                        .locks
                        .iter()
                        .find(|file| file.role == LockRole::Config);
                    let manifest = PairedManifest::of(lock.as_deref(), named);
                    (UvApi::Project, HubShape::UvProject, lock, manifest)
                }
                _ => {
                    let lock = reading.labels("src", Pick::Items, LockRole::PackageLock);
                    let lock = lock.into_iter().next();
                    let manifest = PairedManifest::of(lock.as_deref(), None);
                    (UvApi::Lockfile, HubShape::UvLockfile, lock, manifest)
                }
            };
            let applies = |applies: &Applies| match applies {
                Applies::Everywhere => true,
                Applies::Lock(path) => lock.as_deref() == Some(path.as_str()),
                Applies::Hub(hub) => api == UvApi::Lockfile && hub == name,
            };
            let own = overrides.iter().filter(|(place, _)| applies(place));
            let own: Vec<UvOverride> = own.map(|(_, over)| over.clone()).collect();
            // No pip-compile check reads a `uv.lock`; the manifest check
            // has no version-dependent name.
            let (scans, rows) =
                lock_checks(input.files, &reading.locks, Tri::Maybe, &mut reading.gaps);
            let detail = AspectRulesPyDetail {
                api,
                hub_name: name.to_string(),
                extension: usage.extension(),
                dev: tag.dev,
                manifest,
                imports: usage.imports(|repo| repo == name),
                overrides: own.clone(),
                lock_checks: scans,
            };
            let apparent = detail.imports.first().map_or(name, |import| &import.local);
            let apparent = apparent.to_string();
            let detail = RulesetDetail::AspectRulesPy(detail);
            let mut hub = reading.hub(shape, detail, &apparent, version.clone());
            hub.derived = rows;
            hub.bypasses = usage.repo_overrides();
            for over in own {
                if over.replacement {
                    hub.bypasses.push(Bypass {
                        token: USER_OVERRIDE,
                        what: over.package.clone(),
                        site: Some(over.site.clone()),
                    });
                }
                hub.user_decls.push(UserDecl {
                    package: over.package,
                    replacement: over.replacement,
                    site: over.site,
                });
            }
            out.gaps.append(&mut reading.gaps);
            out.hubs.push(hub);
        }
        // The extension is used and what it declares was not all read:
        // with no hub to show for it, the ecosystem is undetermined.
        if out.hubs.len() == before && !gaps.is_empty() {
            out.signals.extend(usage.signal(Ruleset::AspectRulesPy));
        }
        out.gaps.extend(gaps);
    }
    unread_module(model, &MODULES, Ruleset::AspectRulesPy, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::super::rules_python::tests::{gap_files, locals, locks, sides, Root};
    use super::*;
    use crate::bazel::model::{DeclSystem, DerivedState, Hub, Liveness};
    use crate::bazel::module_file::tests::fixtures;
    use crate::bazel::ruleset_version::{Source, Unproven, VersionVerdict};
    use crate::crawlers::types::Ecosystem;

    fn detail(hub: &Hub) -> &AspectRulesPyDetail {
        match &hub.detail {
            RulesetDetail::AspectRulesPy(detail) => detail,
            other => panic!("not an aspect_rules_py hub: {other:?}"),
        }
    }

    fn recognized(files: &[(&str, &str)]) -> Recognized {
        Root::of(files).recognize(recognize)
    }

    /// A root module on aspect_rules_py `version` that uses the 1.x `uv`
    /// extension as `rest` says.
    fn module(version: &str, rest: &str) -> String {
        format!(
            "module(name = \"root\")\n\
             bazel_dep(name = \"aspect_rules_py\", version = \"{version}\")\n\
             uv = use_extension(\"@aspect_rules_py//uv/unstable:extension.bzl\", \"uv\")\n\
             uv.declare_hub(hub_name = \"pypi\")\n{rest}"
        )
    }

    /// `heavy/aspect_rules_py/bzlmod/e9/MODULE.bazel`: the fixture of the
    /// 1.13.0 baseline canary.
    const PROJECT: &str = "module(name = \"socket_fixture\", version = \"0.0.0\")\n\
        \n\
        bazel_dep(name = \"aspect_rules_py\", version = \"1.13.0\")\n\
        single_version_override(module_name = \"aspect_rules_py\", version = \"1.13.0\")\n\
        bazel_dep(name = \"rules_python\", version = \"1.7.0\")\n\
        single_version_override(module_name = \"rules_python\", version = \"1.7.0\")\n\
        \n\
        python = use_extension(\"@rules_python//python/extensions:python.bzl\", \"python\")\n\
        python.toolchain(\n    is_default = True,\n    python_version = \"3.12\",\n)\n\
        \n\
        uv = use_extension(\"@aspect_rules_py//uv/unstable:extension.bzl\", \"uv\")\n\
        uv.declare_hub(hub_name = \"pypi\")\n\
        uv.project(\n    hub_name = \"pypi\",\n    lock = \"//:uv.lock\",\n    pyproject = \"//:pyproject.toml\",\n)\n\
        use_repo(uv, \"pypi\")\n";

    /// `heavy/aspect_rules_py/bzlmod/e8-canary/MODULE.bazel`: 1.8.4, whose
    /// lock is not a watched input.
    const LOCKFILE: &str = "module(name = \"socket_fixture\", version = \"0.0.0\")\n\
        \n\
        bazel_dep(name = \"aspect_rules_py\", version = \"1.8.4\")\n\
        single_version_override(module_name = \"aspect_rules_py\", version = \"1.8.4\")\n\
        \n\
        uv = use_extension(\"@aspect_rules_py//uv/unstable:extension.bzl\", \"uv\")\n\
        uv.declare_hub(hub_name = \"pypi\")\n\
        uv.declare_venv(\n    hub_name = \"pypi\",\n    venv_name = \"default\",\n)\n\
        uv.lockfile(\n    hub_name = \"pypi\",\n    src = \"//:uv.lock\",\n    venv_name = \"default\",\n)\n\
        use_repo(uv, \"pypi\")\n";

    #[test]
    fn uv_project_is_a_hub_over_its_lock_and_the_manifest_beside_it() {
        let found = recognized(&[("MODULE.bazel", PROJECT)]);
        assert_eq!((&found.gaps, &found.signals), (&vec![], &vec![]));
        let [hub] = &found.hubs[..] else {
            panic!("one hub, found {:?}", found.hubs);
        };
        assert_eq!(
            (hub.ruleset, hub.shape, hub.ecosystem),
            (Ruleset::AspectRulesPy, HubShape::UvProject, Ecosystem::Pypi)
        );
        assert_eq!(
            locks(hub),
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
        assert_eq!(hub.decl.apparent_name, "pypi");
        assert!(matches!(hub.liveness, Liveness::Dead { .. }));
        let detail = detail(hub);
        assert_eq!(
            (detail.api, detail.hub_name.as_str()),
            (UvApi::Project, "pypi")
        );
        let extension = detail.extension.as_ref().expect("an extension");
        assert_eq!(
            (
                extension.bzl_file.as_str(),
                extension.name.as_str(),
                detail.dev
            ),
            ("@aspect_rules_py//uv/unstable:extension.bzl", "uv", false)
        );
        // The tag's `pyproject` is the file beside the lock.
        let beside = PairedManifest::Beside {
            path: "pyproject.toml".to_string(),
            named: true,
        };
        assert_eq!(detail.manifest, beside);
        assert_eq!(locals(&detail.imports), ["pypi"]);
        assert!(
            detail.overrides.is_empty() && hub.bypasses.is_empty() && hub.user_decls.is_empty()
        );
        // The verdict stands beside the tag API: admission asks for
        // 1.13.0, which the tag does not prove.
        let pinned = Some(("1.13.0", Source::SingleVersionOverride));
        assert_eq!(sides(&hub.ruleset_version), (pinned, pinned));
        assert!(hub.ruleset_version.at_least("1.13.0"));
    }

    #[test]
    fn uv_lockfile_is_recognized_as_the_shape_whose_lock_is_not_watched() {
        let found = recognized(&[("MODULE.bazel", LOCKFILE)]);
        assert_eq!((&found.gaps, &found.signals), (&vec![], &vec![]));
        let [hub] = &found.hubs[..] else {
            panic!("one hub, found {:?}", found.hubs);
        };
        assert_eq!(hub.shape, HubShape::UvLockfile);
        assert_eq!(
            locks(hub),
            [("//:uv.lock", Some("uv.lock"), LockRole::PackageLock)]
        );
        let detail = detail(hub);
        assert_eq!(
            (detail.api, detail.hub_name.as_str()),
            (UvApi::Lockfile, "pypi")
        );
        // The tag names no manifest; the rewriter's pair is beside the lock.
        let beside = PairedManifest::Beside {
            path: "pyproject.toml".to_string(),
            named: false,
        };
        assert_eq!(detail.manifest, beside);
        // The release is proven below the first one that watches the lock.
        assert!(hub.ruleset_version.below("1.8.5"));
    }

    #[test]
    fn the_tag_api_lends_the_version_a_floor_and_no_more() {
        let project = "uv.project(hub_name = \"pypi\", lock = \"//:uv.lock\", pyproject = \"//:pyproject.toml\")\n";
        let version = |declared: &str, rest: &str| {
            let found = recognized(&[("MODULE.bazel", &module(declared, rest))]);
            found.hubs[0].ruleset_version.clone()
        };
        // `uv.project` exists from 1.8.5: a lower declaration is lifted to
        // it, since another module must have raised the version.
        let lifted = version("1.7.0", project);
        assert_eq!(sides(&lifted), (Some(("1.8.5", Source::ApiShape)), None));
        // 1.8.5 to 1.12 is not admitted: the gate is `lo >= 1.13.0`.
        assert!(!lifted.at_least("1.13.0") && !version("1.12.1", project).at_least("1.13.0"));
        assert!(version("1.13.0", project).at_least("1.13.0"));
        // An alpha of 2.0 is above every 1.x release.
        assert!(version("2.0.0-alpha.10", project).at_least("1.13.0"));
        // `uv.lockfile` lends none: a declared 1.7.0 is a lower bound that
        // does not prove the release is one of the unwatched ones.
        let lockfile =
            "uv.lockfile(hub_name = \"pypi\", src = \"//:uv.lock\", venv_name = \"default\")\n";
        let declared = version("1.7.0", lockfile);
        assert_eq!(sides(&declared), (Some(("1.7.0", Source::Declared)), None));
        assert!(!declared.below("1.8.5"));
    }

    /// The `rules_py` 2.0.0-alpha.11 e2e module of the Starlark corpus:
    /// the module is renamed, the extension is `//uv:extensions.bzl`, four
    /// projects share one hub, and one override has no `lock`.
    #[test]
    fn rules_py_projects_share_a_hub_and_an_override_without_a_lock_reaches_all() {
        let name = "aspect_rules_py-2.0.0-alpha.11-uv-overrides-setup.MODULE.bazel";
        let segment = std::fs::read_to_string(fixtures().join("starlark/corpus").join(name));
        let text = format!(
            "bazel_dep(name = \"rules_py\", version = \"2.0.0-alpha.11\")\n{}",
            segment.expect("the corpus file")
        );
        let found = recognized(&[("MODULE.bazel", &text)]);
        assert_eq!((&found.gaps, &found.signals), (&vec![], &vec![]));
        let dirs = ["alpha", "beta", "gamma", "delta"];
        assert_eq!(found.hubs.len(), dirs.len());
        for (hub, dir) in found.hubs.iter().zip(dirs) {
            let package = format!("uv-all-lock-overrides/{dir}");
            let detail = detail(hub);
            assert_eq!(
                (hub.shape, detail.hub_name.as_str()),
                (HubShape::UvProject, "pypi_all_lock_overrides")
            );
            assert_eq!(hub.locks[0].path, Some(format!("{package}/uv.lock")));
            let beside = PairedManifest::Beside {
                path: format!("{package}/pyproject.toml"),
                named: true,
            };
            assert_eq!(detail.manifest, beside);
            assert_eq!(locals(&detail.imports), ["pypi_all_lock_overrides"]);
            // Patches over the pinned wheel: consent evidence, no bypass.
            let [over] = &detail.overrides[..] else {
                panic!("one override, found {:?}", detail.overrides);
            };
            assert_eq!(
                (
                    over.package.as_str(),
                    over.version.as_deref(),
                    over.replacement
                ),
                ("boltons", Some("25.0.0"), false)
            );
            assert!(hub.bypasses.is_empty());
            assert_eq!(hub.user_decls.len(), 1);
            assert!(!hub.user_decls[0].replacement && hub.user_decls[0].package == "boltons");
            assert_eq!(
                sides(&hub.ruleset_version).0,
                Some(("2.0.0-alpha.11", Source::Declared))
            );
        }
    }

    #[test]
    fn an_override_with_a_target_replaces_the_package_of_its_lock() {
        // Probe Y4.g (`as113-b8`): with this tag the hosted pin is never
        // fetched, exit 0 and no warning.
        let found = recognized(&[(
            "MODULE.bazel",
            &module(
                "1.13.0",
                "uv.project(hub_name = \"pypi\", lock = \"//:uv.lock\", pyproject = \"//:pyproject.toml\")\n\
                 uv.project(hub_name = \"pypi\", lock = \"//tools:uv.lock\", pyproject = \"//tools:pyproject.toml\")\n\
                 uv.override_package(\n    name = \"Six\",\n    lock = \"//:uv.lock\",\n    \
                 target = \"//third_party/six\",\n    version = \"1.16.0\",\n)\n\
                 use_repo(uv, pip = \"pypi\")\n",
            ),
        )]);
        assert_eq!((&found.gaps, &found.signals), (&vec![], &vec![]));
        let [root, tools] = &found.hubs[..] else {
            panic!("two hubs, found {:?}", found.hubs);
        };
        // The import renames the hub for the build.
        assert_eq!(
            (
                root.decl.apparent_name.as_str(),
                detail(root).hub_name.as_str()
            ),
            ("pip", "pypi")
        );
        let [bypass] = &root.bypasses[..] else {
            panic!("one bypass, found {:?}", root.bypasses);
        };
        assert_eq!((bypass.token, bypass.what.as_str()), (USER_OVERRIDE, "six"));
        let [decl] = &root.user_decls[..] else {
            panic!("one declaration, found {:?}", root.user_decls);
        };
        assert!(decl.replacement && decl.package == "six");
        // The override names the root lock: the other project keeps its pin.
        assert!(tools.bypasses.is_empty() && tools.user_decls.is_empty());
        assert!(detail(tools).overrides.is_empty());

        // 1.8.4: `override_requirement` on the hub of a `uv.lockfile`.
        let old = module(
            "1.8.4",
            "uv.lockfile(hub_name = \"pypi\", src = \"//:uv.lock\", venv_name = \"default\")\n\
             uv.override_requirement(hub_name = \"pypi\", requirement = \"six==1.16.0\", target = \"//third_party/six\", venv_name = \"default\")\n\
             uv.override_requirement(hub_name = \"other\", requirement = \"idna\", target = \"//third_party/idna\", venv_name = \"default\")\n",
        );
        let found = recognized(&[("MODULE.bazel", &old)]);
        let packages: Vec<_> = found.hubs[0]
            .user_decls
            .iter()
            .map(|decl| decl.package.as_str())
            .collect();
        assert_eq!(packages, ["six"]);
        assert_eq!(found.hubs[0].bypasses[0].token, USER_OVERRIDE);
    }

    #[test]
    fn a_manifest_elsewhere_a_computed_label_and_an_unread_tag_are_reported() {
        let hubs = |rest: &str| recognized(&[("MODULE.bazel", &module("1.13.0", rest))]);
        // The tag's manifest is not the one beside the lock, which is the
        // one the native rewriter edits.
        let found = hubs("uv.project(hub_name = \"pypi\", lock = \"//py:uv.lock\", pyproject = \"//:pyproject.toml\")\n");
        let mismatch = &detail(&found.hubs[0]).manifest;
        assert_eq!(
            *mismatch,
            PairedManifest::Mismatch {
                label: "//:pyproject.toml".to_string(),
                expected: "py/pyproject.toml".to_string(),
            }
        );
        assert!(mismatch.refusal().is_some() && found.gaps.is_empty());

        // A computed lock: the hub reads a file this reader cannot name.
        let found = hubs(
            "uv.project(hub_name = \"pypi\", lock = LOCKS[0], pyproject = \"//:pyproject.toml\")\n",
        );
        assert_eq!(gap_files(&found), ["MODULE.bazel"]);
        let hub = &found.hubs[0];
        assert!(!hub.decl.literal);
        assert_eq!(hub.locks[0].path, None);
        assert_eq!(detail(hub).manifest, PairedManifest::Unresolved);

        // An override whose lock is computed applies wherever it could.
        let found = hubs(
            "uv.project(hub_name = \"pypi\", lock = \"//:uv.lock\", pyproject = \"//:pyproject.toml\")\n\
             uv.override_package(name = \"six\", lock = lock_of(\"six\"), target = \"//third_party/six\")\n",
        );
        assert_eq!(gap_files(&found), ["MODULE.bazel"]);
        assert_eq!(found.hubs[0].bypasses.len(), 1);

        // A tag under an `if`: the usage was not all read, and with no
        // hub to show for it the ruleset is a signal.
        let found = hubs("if True:\n    uv.project(hub_name = \"pypi\", lock = \"//:uv.lock\", pyproject = \"//:pyproject.toml\")\n");
        assert!(found.hubs.is_empty() && !found.gaps.is_empty());
        assert_eq!(found.signals.len(), 1);
        assert_eq!(found.signals[0].ruleset, Ruleset::AspectRulesPy);

        // A hub that is declared and reads no lock governs nothing; the
        // ruleset alone is no hub; a `uv` extension of another module is
        // another ruleset.
        assert_eq!(hubs(""), Recognized::default());
        let other = "bazel_dep(name = \"rules_python\", version = \"1.7.0\")\n\
                     uv = use_extension(\"@rules_python//python/uv:uv.bzl\", \"uv\")\n\
                     uv.configure(version = \"0.6.2\")\n";
        assert_eq!(
            recognized(&[("MODULE.bazel", other)]),
            Recognized::default()
        );
        let foreign = "bazel_dep(name = \"my_rules\", version = \"1.0.0\")\n\
                       uv = use_extension(\"@my_rules//uv:extensions.bzl\", \"uv\")\n\
                       uv.project(hub_name = \"pypi\", lock = \"//:uv.lock\", pyproject = \"//:pyproject.toml\")\n";
        assert_eq!(
            recognized(&[("MODULE.bazel", foreign)]),
            Recognized::default()
        );
    }

    #[test]
    fn a_manifest_check_over_the_uv_lock_is_a_declared_row() {
        let build = "load(\"@rules_python_gazelle_plugin//manifest:defs.bzl\", \"gazelle_python_manifest\")\n\
                     gazelle_python_manifest(\n    name = \"gazelle_python_manifest\",\n    \
                     lockfiles = [\"uv.lock\"],\n    modules_mapping = \":modules_map\",\n    \
                     pip_repository_name = \"pypi\",\n)\n";
        let found = recognized(&[("MODULE.bazel", PROJECT), ("BUILD.bazel", build)]);
        assert_eq!(
            found.hubs[0].derived,
            [DerivedState::LockCheck {
                target: "//:gazelle_python_manifest".to_string(),
                input: "uv.lock".to_string(),
                kind: crate::bazel::derived::LockCheckKind::GazelleManifest,
            }]
        );
        // The manifest is not scanned: lanes ask the lock-refresh table
        // about it, not a lock check.
        assert_eq!(detail(&found.hubs[0]).lock_checks.len(), 1);
        // No module, no hub; the version of a module the root does not
        // declare is not known.
        assert_eq!(
            recognized(&[("WORKSPACE", "workspace(name = \"w\")\n")]),
            Recognized::default()
        );
        let canonical = "uv = use_extension(\"@@aspect_rules_py+//uv/unstable:extension.bzl\", \"uv\")\n\
                         uv.project(hub_name = \"pypi\", lock = \"//:uv.lock\", pyproject = \"//:pyproject.toml\")\n";
        let found = recognized(&[("MODULE.bazel", canonical)]);
        assert_eq!(
            found.hubs[0].ruleset_version,
            VersionVerdict::unknown(Unproven::NotDeclared)
        );
    }
}
