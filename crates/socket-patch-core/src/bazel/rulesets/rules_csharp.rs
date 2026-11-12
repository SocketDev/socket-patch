//! Recognizer: rules_csharp (design 2.7). `nuget.from_lock` reads the files
//! NuGet itself writes: a `packages.lock.json`, and the package sources of
//! a `NuGet.Config`. It is the one .NET ruleset whose hub reads the files
//! the native NuGet rewriter edits. Bzlmod only: the ruleset has no
//! `WORKSPACE` rule.
//!
//! What a pin has to know about the tag (read at `v0.5.0`,
//! `csharp/extensions.bzl` and `csharp/private/nuget_repo.bzl`):
//!
//! - **`nuget_config` is where the feeds come from.** The sources of the
//!   file replace the tag's `feeds`, and a `<clear />` in it turns
//!   nuget.org off. A tag without the attribute never reads the
//!   `NuGet.Config` the rewriter edits, so the label is a lock reference
//!   of its own, with the role `Config`.
//! - **The first source that answers is the one that is checked.** The
//!   extension downloads a package with no checksum, from
//!   `local_package_dirs` first, then the feeds in order, then nuget.org,
//!   and fails unless the bytes match `contentHash` (probe U3: the Socket
//!   source after the upstream one fails the build). So a tag that lists
//!   a local directory can put other bytes in front of a pin.
//! - **Through 0.5.0 every `from_lock` tag feeds one hub.** Its name and
//!   its feeds are the last tag's, and a package is pinned by the first
//!   lock that lists it. The count of the root's tags is recorded with
//!   each hub; the tags of other modules are not in this tree.
//!
//! The extension is not reproducible: `MODULE.bazel.lock` records both
//! files, and `derived` finds that from the lock, not from here.

use super::rules_dotnet::{hosted_by, repo_bypasses, usage_is_exact, UNDECIDED};
use super::{RecognizeInput, Recognized};
use crate::bazel::label::Label;
use crate::bazel::model::{
    Declaration, Gap, Hub, HubShape, Liveness, LockRef, LockRole, Ruleset, RulesetDetail,
    RulesetSignal,
};
use crate::bazel::module_file::{ExtensionProxy, Host, ModuleModel, Tag};
use crate::bazel::ruleset_version::{Unproven, VersionVerdict};
use crate::bazel::starlark::{Lookup, Value, ValueKind};
use crate::crawlers::types::Ecosystem;

/// Every `details.token` this file emits.
pub const TOKENS: &[&str] = &["label_not_literal", "lock_path", "repo_override"];

/// A hub name or a label is computed, or the tags of the extension are
/// not all known: the hub is never edited.
pub const LABEL_NOT_LITERAL: &str = TOKENS[0];
/// A label that is a plain string and names no file of the main
/// repository.
pub const LOCK_PATH: &str = TOKENS[1];
/// `override_repo` or `inject_repo` on the extension that makes the hub.
pub const REPO_OVERRIDE: &str = TOKENS[2];

/// The module name of the ruleset.
pub const MODULE: &str = "rules_csharp";

/// The hub a tag without `name` declares.
const DEFAULT_HUB: &str = "nuget";

/// A string-list attribute as it is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listed {
    Absent,
    /// A literal list of plain strings.
    Literal(Vec<String>),
    /// Anything else: what the build passes is not known.
    Computed,
}

/// What this recognizer records about one `from_lock` tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesCsharpDetail {
    /// `name` of the tag, `nuget` without one.
    pub hub: String,
    /// Every name a `use_repo` gives the hub; empty when nothing imports
    /// it.
    pub imported_as: Vec<String>,
    /// The extension or an import of the hub is a dev dependency.
    pub dev: bool,
    /// How many `from_lock` tags the root gives the extension. With more
    /// than one, through 0.5.0, they are one hub: see the module docs.
    pub root_tags: usize,
    /// Used only when `nuget_config` is absent or lists no source.
    pub feeds: Listed,
    /// Directories that are tried before every feed.
    pub local_package_dirs: Listed,
    /// `Some(false)` keeps nuget.org out; `None` when computed.
    pub use_public_sources: Option<bool>,
}

/// Whether the tag of `hub` names a `NuGet.Config`: its locks then hold a
/// reference with the role `Config`. A tag without one never reads the
/// file the native rewriter puts the patch host's source in.
pub fn names_nuget_config(hub: &Hub) -> bool {
    hub.locks.iter().any(|lock| lock.role == LockRole::Config)
}

fn is_nuget_extension(module: &ModuleModel, proxy: &ExtensionProxy) -> bool {
    let named = |label: &Label| label.package == "csharp" && label.name == "extensions.bzl";
    let label = proxy.label.as_ref().filter(|label| named(label));
    proxy.extension == "nuget" && label.is_some_and(|label| hosted_by(module, label, MODULE))
}

/// The hubs, signals and gaps of this ruleset in `input`.
pub fn recognize(input: &RecognizeInput<'_>) -> Recognized {
    let mut out = Recognized::default();
    let Some(module) = input.module else {
        return out;
    };
    let dep = module.deps.iter().find(|dep| dep.name == MODULE);
    let mut used = None;
    for usage in module.usages() {
        let first = &module.proxies[usage[0]];
        if is_nuget_extension(module, first) {
            used.get_or_insert(module.site(first.at));
            usage_hubs(module, &usage, &mut out);
        }
    }
    // The ruleset is there and no `from_lock` tag of the root was read:
    // Bazel may build NuGet packages from a lock this reader cannot see.
    let present = used.or(dep.map(|dep| module.site(dep.at)));
    if let Some(site) = present.filter(|_| out.hubs.is_empty() && out.signals.is_empty()) {
        let ruleset = Ruleset::RulesCsharp;
        out.signals.push(RulesetSignal { ruleset, site });
    }
    out
}

/// An attribute of a tag, after one level of constants.
fn attr<'a>(module: &'a ModuleModel, tag: &'a Tag, name: &str) -> Lookup<'a> {
    match tag.call.arg(name) {
        Lookup::Found(value) => Lookup::Found(module.resolve(tag.at, value)),
        other => other,
    }
}

/// A string or label attribute: `Ok(None)` when it is absent or `None`,
/// `Err` when it is not a plain string.
fn text<'a>(module: &'a ModuleModel, tag: &'a Tag, name: &str) -> Result<Option<&'a str>, ()> {
    match attr(module, tag, name) {
        Lookup::Absent => Ok(None),
        Lookup::Found(value) if value.kind == ValueKind::None => Ok(None),
        Lookup::Found(value) => value.as_str().map(Some).ok_or(()),
        Lookup::Unknown => Err(()),
    }
}

fn listed(module: &ModuleModel, tag: &Tag, name: &str) -> Listed {
    let items = match attr(module, tag, name) {
        Lookup::Absent => return Listed::Absent,
        Lookup::Found(Value {
            kind: ValueKind::List(items),
            ..
        }) => items,
        _ => return Listed::Computed,
    };
    let strings = items.iter().map(|item| item.as_str().map(str::to_string));
    strings
        .collect::<Option<_>>()
        .map_or(Listed::Computed, Listed::Literal)
}

/// The hubs of one usage of the extension: one per `from_lock` tag.
fn usage_hubs(module: &ModuleModel, usage: &[usize], out: &mut Recognized) {
    let mut exact = usage_is_exact(module, usage, LABEL_NOT_LITERAL, &mut out.gaps);
    let tags = module.tags.iter().filter(|tag| usage.contains(&tag.proxy));
    let tags: Vec<&Tag> = tags.collect();
    // A tag class this reader does not know may declare a hub.
    for tag in tags.iter().filter(|tag| tag.call.callee != "from_lock") {
        exact = false;
        let (ruleset, site) = (Ruleset::RulesCsharp, module.site(tag.at));
        out.signals.push(RulesetSignal { ruleset, site });
    }
    let tags: Vec<&Tag> = tags
        .into_iter()
        .filter(|tag| tag.call.callee == "from_lock")
        .collect();
    let first = out.hubs.len();
    for tag in &tags {
        let site = module.site(tag.at);
        let at = format!("{}:{}", site.file, tag.at.line);
        let mut gap = |token: &'static str, detail: String| {
            out.gaps.push(Gap {
                token,
                file: site.file.clone(),
                detail: format!("{at}: {detail}"),
            });
        };
        let Ok(name) = text(module, tag, "name") else {
            gap(
                LABEL_NOT_LITERAL,
                "the hub name of `nuget.from_lock` is computed; write it as a literal".to_string(),
            );
            exact = false;
            continue;
        };
        let name = name.unwrap_or(DEFAULT_HUB);
        let mut literal = true;
        let mut locks = Vec::new();
        let files = [
            ("packages_lock_json", LockRole::PackageLock, true),
            ("nuget_config", LockRole::Config, false),
        ];
        for (attribute, role, mandatory) in files {
            let label = match text(module, tag, attribute) {
                Ok(None) if !mandatory => continue,
                Ok(Some(label)) => label,
                // Computed, or the mandatory lock is missing: Bazel
                // rejects the latter, and no file is named either way.
                Ok(None) | Err(()) => {
                    literal = false;
                    let what = format!("`{attribute}` of hub `{name}` is not a plain label");
                    gap(LABEL_NOT_LITERAL, format!("{what}; write it as a literal"));
                    let (label, path) = (String::new(), None);
                    locks.push(LockRef { label, path, role });
                    continue;
                }
            };
            let parsed = Label::parse(label, Some("")).ok();
            // `@<root module>//` is the main repository too.
            let main = |l: &Label| l.path().is_some() || module.host(l) == Host::Root;
            let path = parsed.filter(main).map(|label| label.file());
            if path.is_none() {
                gap(
                    LOCK_PATH,
                    format!(
                        "`{attribute}` of hub `{name}` is `{label}`, which names no file of the \
                         main repository; name it as `//<package>:<file>`"
                    ),
                );
            }
            let label = label.to_string();
            locks.push(LockRef { label, path, role });
        }
        let imports = module
            .imports
            .iter()
            .filter(|import| usage.contains(&import.proxy));
        let imports = imports.filter(|import| import.exported.as_deref() == Some(name));
        let imported_as: Vec<String> = imports.map(|import| import.local.clone()).collect();
        let public = match attr(module, tag, "use_public_sources") {
            Lookup::Absent => Some(true),
            Lookup::Found(Value {
                kind: ValueKind::Bool(public),
                ..
            }) => Some(*public),
            _ => None,
        };
        let detail = RulesCsharpDetail {
            hub: name.to_string(),
            imported_as,
            dev: tag.dev,
            root_tags: tags.len(),
            feeds: listed(module, tag, "feeds"),
            local_package_dirs: listed(module, tag, "local_package_dirs"),
            use_public_sources: public,
        };
        out.hubs.push(Hub {
            ruleset: Ruleset::RulesCsharp,
            shape: HubShape::NugetFromLock,
            ecosystem: Ecosystem::Nuget,
            decl: Declaration {
                site,
                apparent_name: detail
                    .imported_as
                    .first()
                    .map_or(name, String::as_str)
                    .to_string(),
                literal,
            },
            detail: RulesetDetail::RulesCsharp(detail),
            locks,
            ruleset_version: VersionVerdict::unknown(Unproven::NotDeclared),
            liveness: Liveness::Dead {
                why: UNDECIDED.to_string(),
            },
            bypasses: repo_bypasses(module, usage, REPO_OVERRIDE),
            user_decls: Vec::new(),
            derived: Vec::new(),
        });
    }
    // A tag that was not read can rename the hub or replace its feeds.
    for hub in &mut out.hubs[first..] {
        hub.decl.literal &= exact;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bazel::model::{DeclSystem, RulesetSignal};
    use crate::bazel::module_file::tests::view;

    /// What the recognizer finds in a root whose `MODULE.bazel` is `text`.
    fn recognized(text: &str) -> Recognized {
        let view = view(&[("MODULE.bazel", text)]);
        let module = ModuleModel::read(&view);
        recognize(&RecognizeInput {
            module: module.as_ref(),
            workspace_files: &[],
            module_lock: None,
            flags: None,
            line: None,
            files: &view,
        })
    }

    fn detail(hub: &Hub) -> &RulesCsharpDetail {
        match &hub.detail {
            RulesetDetail::RulesCsharp(detail) => detail,
            other => panic!("{other:?} is not a rules_csharp detail"),
        }
    }

    fn one_hub(found: &Recognized) -> &Hub {
        match &found.hubs[..] {
            [hub] => hub,
            hubs => panic!("one hub, not {hubs:?}"),
        }
    }

    fn tokens(found: &Recognized) -> Vec<&'static str> {
        found.gaps.iter().map(|gap| gap.token).collect()
    }

    fn lock(label: &str, path: Option<&str>, role: LockRole) -> LockRef {
        LockRef {
            label: label.to_string(),
            path: path.map(str::to_string),
            role,
        }
    }

    /// The head of every fixture below.
    const HEAD: &str = r#"
module(name = "app")

bazel_dep(name = "rules_csharp", version = "0.5.0")

nuget = use_extension("@rules_csharp//csharp:extensions.bzl", "nuget")
"#;

    fn module(body: &str) -> Recognized {
        recognized(&format!("{HEAD}{body}"))
    }

    /// The `light/rules_csharp/bzlmod/e9` fixture: the tag names the two
    /// files the native NuGet rewriter edits.
    #[test]
    fn from_lock_names_the_lock_and_the_config() {
        let found = module(
            r#"
nuget.from_lock(
    nuget_config = "//:nuget.config",
    packages_lock_json = "//:packages.lock.json",
)
use_repo(nuget, "nuget", "nuget_sp_other", "nuget_sp_victim")
"#,
        );
        assert_eq!((found.gaps.len(), found.signals.len()), (0, 0), "{found:?}");
        let hub = one_hub(&found);
        assert_eq!(
            (hub.ruleset, hub.shape, hub.ecosystem),
            (
                Ruleset::RulesCsharp,
                HubShape::NugetFromLock,
                Ecosystem::Nuget
            )
        );
        assert_eq!(hub.shape.ruleset(), hub.ruleset);
        assert_eq!(
            hub.locks,
            [
                lock(
                    "//:packages.lock.json",
                    Some("packages.lock.json"),
                    LockRole::PackageLock
                ),
                lock("//:nuget.config", Some("nuget.config"), LockRole::Config),
            ]
        );
        assert!(names_nuget_config(hub));
        assert_eq!(
            (hub.decl.apparent_name.as_str(), hub.decl.literal),
            ("nuget", true)
        );
        assert_eq!(hub.decl.site.system, DeclSystem::Bzlmod);
        assert!(matches!(hub.liveness, Liveness::Dead { .. }));
        assert!(hub.derived.is_empty() && hub.user_decls.is_empty() && hub.bypasses.is_empty());
        let expected = RulesCsharpDetail {
            hub: "nuget".to_string(),
            imported_as: vec!["nuget".to_string()],
            dev: false,
            root_tags: 1,
            feeds: Listed::Absent,
            local_package_dirs: Listed::Absent,
            use_public_sources: Some(true),
        };
        assert_eq!(detail(hub), &expected);
    }

    /// A tag without `nuget_config` never reads the `NuGet.Config` the
    /// rewriter edits. What it does read is recorded as written.
    #[test]
    fn a_tag_without_a_config_names_only_the_lock() {
        let found = module(
            r#"
FEEDS = ["https://feed.example.invalid/v3/index.json"]
nuget.from_lock(
    name = "deps",
    feeds = FEEDS,
    local_package_dirs = ["third_party/nupkgs"],
    packages_lock_json = "//src/app:packages.lock.json",
    use_public_sources = False,
)
use_repo(nuget, packages = "deps")
"#,
        );
        assert!(
            found.gaps.is_empty() && found.signals.is_empty(),
            "{found:?}"
        );
        let hub = one_hub(&found);
        let path = Some("src/app/packages.lock.json");
        assert_eq!(
            hub.locks,
            [lock(
                "//src/app:packages.lock.json",
                path,
                LockRole::PackageLock
            )]
        );
        assert!(!names_nuget_config(hub));
        // The build refers to the hub by the name `use_repo` gives it.
        assert_eq!(hub.decl.apparent_name, "packages");
        let detail = detail(hub);
        assert_eq!(
            (detail.hub.as_str(), &detail.imported_as[..]),
            ("deps", &["packages".to_string()][..])
        );
        let feeds = vec!["https://feed.example.invalid/v3/index.json".to_string()];
        assert_eq!(detail.feeds, Listed::Literal(feeds));
        assert_eq!(
            detail.local_package_dirs,
            Listed::Literal(vec!["third_party/nupkgs".to_string()])
        );
        assert_eq!(detail.use_public_sources, Some(false));

        let computed = module(
            r#"
nuget.from_lock(
    feeds = [FEED],
    local_package_dirs = glob(["n/*"]),
    packages_lock_json = "//:packages.lock.json",
    use_public_sources = PUBLIC,
)
"#,
        );
        let detail = self::detail(one_hub(&computed));
        assert_eq!(
            (&detail.feeds, &detail.local_package_dirs),
            (&Listed::Computed, &Listed::Computed)
        );
        assert_eq!(detail.use_public_sources, None);
        assert!(detail.imported_as.is_empty());
    }

    /// A label must be one plain string that names a file of the main
    /// repository.
    #[test]
    fn a_label_that_cannot_be_followed_leaves_a_gap() {
        let tag = |lock: &str, config: &str| {
            module(&format!(
                "nuget.from_lock(packages_lock_json = {lock}, nuget_config = {config})\n"
            ))
        };
        let computed = tag("LOCK", "\"//:nuget.config\"");
        assert_eq!(tokens(&computed), [LABEL_NOT_LITERAL]);
        assert!(computed.gaps[0]
            .detail
            .starts_with("MODULE.bazel:7: `packages_lock_json`"));
        let hub = one_hub(&computed);
        assert!(!hub.decl.literal);
        assert_eq!(
            hub.locks,
            [
                lock("", None, LockRole::PackageLock),
                lock("//:nuget.config", Some("nuget.config"), LockRole::Config),
            ]
        );

        // A file of another repository is read by Bazel and not by us.
        let foreign = tag(
            "\"@app//:packages.lock.json\"",
            "\"@shared//:nuget.config\"",
        );
        assert_eq!(tokens(&foreign), [LOCK_PATH]);
        let hub = one_hub(&foreign);
        assert_eq!(hub.locks[0].path.as_deref(), Some("packages.lock.json"));
        assert_eq!(
            hub.locks[1],
            lock("@shared//:nuget.config", None, LockRole::Config)
        );
        assert!(names_nuget_config(hub));

        // The lock is mandatory: a tag without it names no file.
        let missing = module("nuget.from_lock(nuget_config = \"//:nuget.config\")\n");
        assert_eq!(tokens(&missing), [LABEL_NOT_LITERAL]);
        assert!(!one_hub(&missing).decl.literal);

        let unnamed = module("nuget.from_lock(name = NAME, packages_lock_json = \"//:p.json\")\n");
        assert_eq!(tokens(&unnamed), [LABEL_NOT_LITERAL]);
        assert!(unnamed.hubs.is_empty());
        assert_eq!(unnamed.signals.len(), 1);
    }

    /// Through 0.5.0 every tag feeds one hub, so each hub says how many
    /// tags the root has. A tag that was not read may be one more.
    #[test]
    fn every_tag_is_a_hub_that_knows_how_many_the_root_has() {
        let found = module(
            "nuget.from_lock(packages_lock_json = \"//a:packages.lock.json\")\n\
             nuget.from_lock(name = \"tools\", packages_lock_json = \"//b:packages.lock.json\")\n\
             use_repo(nuget, \"nuget\", \"tools\")\n",
        );
        let hubs: Vec<_> = found
            .hubs
            .iter()
            .map(|hub| {
                (
                    detail(hub).hub.as_str(),
                    detail(hub).root_tags,
                    hub.decl.literal,
                )
            })
            .collect();
        assert_eq!(hubs, [("nuget", 2, true), ("tools", 2, true)]);

        let hidden = module(
            "nuget.from_lock(packages_lock_json = \"//a:packages.lock.json\")\n\
             [nuget.from_lock(packages_lock_json = l) for l in LOCKS]\n",
        );
        assert_eq!(tokens(&hidden), [LABEL_NOT_LITERAL]);
        assert!(!one_hub(&hidden).decl.literal);

        // A tag class no release has defined may declare a hub.
        let unknown = module(
            "nuget.from_lock(packages_lock_json = \"//a:packages.lock.json\")\n\
             nuget.from_props(file = \"//:Directory.Packages.props\")\n",
        );
        assert_eq!(unknown.signals.len(), 1);
        assert!(!one_hub(&unknown).decl.literal);
    }

    /// The ruleset is found by the module that hosts the extension file.
    /// Present with no `from_lock` tag, it makes NuGet undetermined.
    #[test]
    fn the_ruleset_is_found_by_its_module_and_signals_without_a_hub() {
        let renamed = recognized(
            "bazel_dep(name = \"rules_csharp\", version = \"0.5.0\", repo_name = \"cs\")\n\
             n = use_extension(\"@cs//csharp:extensions.bzl\", \"nuget\", dev_dependency = True)\n\
             n.from_lock(packages_lock_json = \"//:packages.lock.json\")\n\
             override_repo(n, nuget_sp_victim = \"my_victim\")\n",
        );
        let hub = one_hub(&renamed);
        assert!(detail(hub).dev);
        let [bypass] = &hub.bypasses[..] else {
            panic!("{:?}", hub.bypasses)
        };
        assert_eq!(
            (bypass.token, bypass.what.as_str()),
            (REPO_OVERRIDE, "nuget_sp_victim")
        );

        let signal = |found: &Recognized| match &found.signals[..] {
            [RulesetSignal { ruleset, site }] => (*ruleset, site.span.0),
            signals => panic!("one signal, not {signals:?}"),
        };
        // The toolchain extension of the ruleset declares no hub.
        let toolchain = module(
            "csharp = use_extension(\"@rules_csharp//csharp:extensions.bzl\", \"csharp\")\n\
             csharp.toolchain(dotnet_version = \"10.0.100\")\n",
        );
        assert!(toolchain.hubs.is_empty());
        let at = HEAD.find("nuget = use_extension").unwrap();
        assert_eq!(signal(&toolchain), (Ruleset::RulesCsharp, at));

        let bare = recognized("bazel_dep(name = \"rules_csharp\", version = \"0.5.0\")\n");
        assert_eq!(signal(&bare), (Ruleset::RulesCsharp, 0));

        // Another module's `nuget` extension is not this ruleset.
        let other = recognized(
            "bazel_dep(name = \"acme\", version = \"1.0\")\n\
             n = use_extension(\"@acme//csharp:extensions.bzl\", \"nuget\")\n\
             n.from_lock(packages_lock_json = \"//:packages.lock.json\")\n",
        );
        assert_eq!(other, Recognized::default());
    }
}
