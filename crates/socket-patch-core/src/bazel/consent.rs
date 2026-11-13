//! Starlark patch and replacement declarations as evidence for the
//! user-patch consent gate, which today reads no Bazel file (design HZ-17;
//! the declarations are those of `research/gap-ruleset-patch-hooks.md`
//! 2.1).
//!
//! A user who patches or replaces a package through a ruleset's own hook
//! (`patches` of `npm_translate_lock`, pnpm `patchedDependencies`,
//! `pip.override`, `crate.annotation`, `go_deps.module_override`,
//! `maven.override`, ...) owns that package: a Socket pin under it would
//! be patched a second time, or never used. [`evidence`] turns what the
//! recognizers read into one list, in the terms `UserPatchIndex` matches
//! by (ecosystem, name as the purl spells it, version selector), so the
//! consent gate, the lane gate and `vex` see the same declarations.
//!
//! Three rules decide what is in the list:
//!
//! - **Only hubs Bazel may build from** ([`may_build`]): a declaration on
//!   a hub that is proven dead, shadowed or not imported patches nothing.
//! - **Own wiring is subtracted first** (revision 4, 2.2 row 6). Every
//!   exported function takes the filter as a parameter, and the gate and
//!   `attest` pass the same one (`exec::own_site` over the index they
//!   hold), so a `patches` item or a tag that socket-patch wrote itself
//!   is no user patch hook and no bypass in either.
//! - **Unread is not absent.** A declaration that names no single
//!   package, a hook attribute nobody read and a use of the ruleset that
//!   was not followed to a hub each protect every package of the
//!   ecosystem ([`Subject::Every`]). A recognizer gap is counted wherever
//!   it lies: a gap names a file and not the statement, so whether Bazel
//!   evaluates it is not asked, which only protects more.
//!
//! A replacement defeats a pin outright, so it is also a bypass that
//! `--allow-patch-conflicts` does not lift ([`bypasses`]). A patch on a
//! hub whose hook runs the host `patch` tool is a **user patch hook**
//! ([`user_patch_hooks`], token [`USER_PATCH_HOOK`]): probe P4 saw such a
//! hook stack silently, fail the fetch, or reverse the same fix over the
//! patched tarball with exit 0, so a pin written beside one is never
//! attested.

use super::govern::{self, WORKSPACE_UNREADABLE};
use super::inventory::may_build;
use super::model::{BazelWorkspace, Bypass, DeclSystem, Hub, HubId, Ruleset, RulesetDetail, Site};
use super::rulesets::rules_python::USER_OVERRIDE;
use super::starlark::Lookup;
use super::workspace_file::WsStmtKind;
use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::crawlers::types::Ecosystem;
use crate::utils::npm_range::npm_range_admits;

/// Every `details.token` this file names.
pub const TOKENS: &[&str] = &["user_patch_hook"];

/// The user's own patch for the package exists on a hub whose patch hook
/// runs the host `patch` tool. `attest` withholds with it.
pub const USER_PATCH_HOOK: &str = TOKENS[0];

/// Whether a statement is socket-patch's own wiring. The gate and `attest`
/// pass `exec::own_site` over the same index.
pub type OwnSite<'a> = &'a dyn Fn(&Site) -> bool;

/// What a declaration is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    /// One package: `name` as its purl spells it (`@scope/name`,
    /// `group/artifact`, a Go module path), and the versions the
    /// declaration is for. `None` is every version; for npm a selector may
    /// be a range.
    Package {
        name: String,
        version: Option<String>,
    },
    /// Every package of the ecosystem: the declaration names no single
    /// package, or what could hold one was not read. `unreadable` when a
    /// file could not be read or parsed, where the remedy is to fix the
    /// file.
    Every { why: String, unreadable: bool },
}

/// One declaration of the user's, or one place where one may stand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// `None` when no hub was resolved for the declaration.
    pub hub: Option<HubId>,
    pub ecosystem: Ecosystem,
    pub subject: Subject,
    /// Something else is built in the package's place, so a pin is never
    /// used: consent does not lift it.
    pub replacement: bool,
    /// The hub applies the user's patches with the host `patch` tool.
    pub host_patch: bool,
    /// Root-relative file the declaration stands in.
    pub file: String,
    pub site: Option<Site>,
}

impl Evidence {
    /// Whether the declaration covers `name`@`version` of `ecosystem`.
    /// Names are compared as the registry compares them, and a version
    /// selector that cannot be decided covers the version.
    pub fn covers(&self, ecosystem: Ecosystem, name: &str, version: &str) -> bool {
        let (wanted, selector) = match &self.subject {
            Subject::Every { .. } => return self.ecosystem == ecosystem,
            Subject::Package { name, version } => (name, version),
        };
        let fold = |name: &str| match ecosystem {
            Ecosystem::Pypi => canonicalize_pypi_name(name),
            // crates.io names are unique ignoring case and `-` / `_`.
            Ecosystem::Cargo => name.to_ascii_lowercase().replace('_', "-"),
            _ => name.to_string(),
        };
        let admits = |selector: &String| {
            selector == version
                || selector.trim() == "*"
                || npm_range_admits(selector, version).unwrap_or(true)
        };
        self.ecosystem == ecosystem
            && fold(wanted) == fold(name)
            && selector.as_ref().is_none_or(admits)
    }
}

/// Whether the hub applies a user's patches with the host `patch` tool:
/// rules_js and rules_nodejs on every release (bazel-lib's `patch` with a
/// `patch_directory`, and the install rules' own shell-out), and gazelle
/// until it is proven 0.29.0 or later, where `go_repository` moved to
/// Bazel's patcher. An unproven gazelle counts: the answer only withholds
/// an attestation.
pub fn host_patch(hub: &Hub) -> bool {
    match hub.ruleset {
        Ruleset::RulesJs | Ruleset::RulesNodejs => true,
        Ruleset::Gazelle => !hub.ruleset_version.at_least("0.29.0"),
        _ => false,
    }
}

/// The ecosystem of a ruleset that has a patch or replacement hook.
/// rules_ruby, rules_dotnet and rules_csharp have none, so nothing unread
/// in them can hide one.
fn hooked(ruleset: Ruleset) -> Option<Ecosystem> {
    let none = [
        Ruleset::RulesRuby,
        Ruleset::RulesDotnet,
        Ruleset::RulesCsharp,
    ];
    ruleset.ecosystem().filter(|_| !none.contains(&ruleset))
}

/// A recognizer's package key in the terms a purl is matched by.
fn subject(hub: &Hub, package: &str) -> Subject {
    let named = |name: &str, version: Option<&str>| Subject::Package {
        name: name.to_string(),
        version: version.map(str::to_string),
    };
    let every = |why: String| Subject::Every {
        why,
        unreadable: false,
    };
    match hub.ruleset {
        _ if package.is_empty() || package == "*" => {
            every("a declaration here names no single package".to_string())
        }
        // `name` or `name@version`; a scope starts with `@`.
        Ruleset::RulesJs => match package.rsplit_once('@') {
            Some((name, version)) if !name.is_empty() => named(name, Some(version)),
            _ => named(package, None),
        },
        Ruleset::RulesJvmExternal => match package.split(':').collect::<Vec<_>>()[..] {
            [group, artifact] if !group.is_empty() && !artifact.is_empty() => {
                named(&format!("{group}/{artifact}"), None)
            }
            _ => every(format!("`{package}` is not a `group:artifact` coordinate")),
        },
        _ => named(package, None),
    }
}

/// Whether the hub is a `crates_repository` or `crates_vendor` call whose
/// `annotations` may hold a patch: the recognizer reads `crate.annotation`
/// tags only. `false` for a hub a tag declares, and for a call that is
/// proven to pass no `annotations`; a call that is not found again (a
/// BUILD rule) is not known to pass none.
fn annotations_unread(ws: &BazelWorkspace, hub: &Hub) -> bool {
    let site = &hub.decl.site;
    let given = |call: &super::starlark::Call| call.arg("annotations") != Lookup::Absent;
    match site.system {
        DeclSystem::Bzlmod => ws.module.as_ref().is_none_or(|module| {
            let here = |at| module.site(at) == *site;
            let call = module.repo_rule_calls.iter().find(|call| here(call.at));
            let tag = module.tags.iter().any(|tag| here(tag.at));
            !tag && call.is_none_or(|call| given(&call.call))
        }),
        DeclSystem::Workspace => {
            let mut calls = ws.workspace_files.iter().filter_map(|model| {
                let index = model.files.iter().position(|f| f.path == site.file)?;
                let top = model.stmts.iter().filter(move |_| index == 0);
                let bodies = model.macros.iter().filter(move |made| made.file == index);
                let mut stmts = top.chain(bodies.flat_map(|made| &made.body));
                match &stmts.find(|stmt| stmt.span == site.span)?.kind {
                    WsStmtKind::Call(call) => Some(&call.call),
                    _ => None,
                }
            });
            calls.next().is_none_or(given)
        }
    }
}

/// Every declaration of the user's on a hub Bazel may build from, and
/// every place one may stand unread, after the own-wiring subtraction.
pub fn evidence(ws: &BazelWorkspace, own: OwnSite<'_>) -> Vec<Evidence> {
    let mut out = Vec::new();
    for (id, hub) in ws.hubs.iter().enumerate().filter(|(_, hub)| may_build(hub)) {
        let mut push = |subject: Subject, replacement: bool, site: &Site| {
            if !own(site) {
                out.push(Evidence {
                    hub: Some(HubId(id)),
                    ecosystem: hub.ecosystem,
                    subject,
                    replacement,
                    host_patch: host_patch(hub),
                    file: site.file.clone(),
                    site: Some(site.clone()),
                });
            }
        };
        let every = |why: String| Subject::Every {
            why,
            unreadable: false,
        };
        for decl in &hub.user_decls {
            push(subject(hub, &decl.package), decl.replacement, &decl.site);
        }
        // What a recognizer keeps in its detail and not in `user_decls`.
        match &hub.detail {
            RulesetDetail::RulesNodejs(detail) if !detail.install_patches.is_empty() => {
                let labels = detail.install_patches.join("`, `");
                let why = format!("the install patches `{labels}` name no package");
                push(every(why), false, &hub.decl.site);
            }
            RulesetDetail::RulesPython(detail) => {
                for over in detail.overrides.iter().filter(|o| o.package.is_none()) {
                    let why = format!(
                        "`pip.override` of `{}`, which is no wheel's name",
                        over.file
                    );
                    push(every(why), false, &over.site);
                }
            }
            RulesetDetail::RulesRust(_) if annotations_unread(ws, hub) => {
                let why = "the `annotations` of this crate_universe rule are not read";
                push(every(why.to_string()), false, &hub.decl.site);
            }
            _ => {}
        }
        // Which attribute was computed is not recorded, so a hook
        // attribute may be among them.
        if !hub.decl.literal && hooked(hub.ruleset).is_some() {
            let why = "the declaration is not literal, so its patches are not known";
            push(every(why.to_string()), false, &hub.decl.site);
        }
    }
    let unread =
        |ruleset: Ruleset, why: &str, unreadable: bool, site: Option<&Site>, file: &str| {
            hooked(ruleset).map(|ecosystem| Evidence {
                hub: None,
                ecosystem,
                subject: Subject::Every {
                    why: why.to_string(),
                    unreadable,
                },
                replacement: false,
                host_patch: matches!(
                    ruleset,
                    Ruleset::RulesJs | Ruleset::RulesNodejs | Ruleset::Gazelle
                ),
                file: file.to_string(),
                site: site.cloned(),
            })
        };
    for (ruleset, gap) in &ws.ruleset_gaps {
        let unreadable = gap.token == WORKSPACE_UNREADABLE;
        out.extend(unread(*ruleset, &gap.detail, unreadable, None, &gap.file));
    }
    let followed = |site: &Site| !own(site) && govern::may_evaluate(ws, site);
    for signal in ws.signals.iter().filter(|signal| followed(&signal.site)) {
        let why = format!("{} is used here and no hub was read", signal.ruleset.name());
        let (site, file) = (Some(&signal.site), &signal.site.file);
        out.extend(unread(signal.ruleset, &why, false, site, file));
    }
    out
}

/// The user's patch hooks for `name`@`version`: the patches of
/// [`evidence`] that cover it on a hub whose hook runs the host `patch`
/// tool (a `patches` key, a pnpm `patchedDependencies` entry, an install
/// patch, a `go_repository` patch). Empty when there is none. With one,
/// the gate allows a write only under `--allow-patch-conflicts`, and
/// `attest` withholds the pin ([`USER_PATCH_HOOK`]) while the entry exists.
pub fn user_patch_hooks(
    ws: &BazelWorkspace,
    own: OwnSite<'_>,
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
) -> Vec<Evidence> {
    let hook = |e: &Evidence| e.host_patch && !e.replacement && e.covers(ecosystem, name, version);
    evidence(ws, own).into_iter().filter(hook).collect()
}

/// The replacements of `name`@`version` on `hub` as bypasses of a pin
/// there: Bazel builds what the user put in the package's place, whatever
/// the lock says. Consent does not lift these.
pub fn bypasses(
    ws: &BazelWorkspace,
    own: OwnSite<'_>,
    hub: HubId,
    name: &str,
    version: &str,
) -> Vec<Bypass> {
    let Some(ecosystem) = ws.hubs.get(hub.0).map(|hub| hub.ecosystem) else {
        return Vec::new();
    };
    let replaced = evidence(ws, own)
        .into_iter()
        .filter(|e| e.hub == Some(hub) && e.replacement && e.covers(ecosystem, name, version));
    replaced
        .map(|e| Bypass {
            token: USER_OVERRIDE,
            what: format!("{}: a declaration of the user's replaces `{name}`", e.file),
            site: e.site,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bazel::exec;
    use crate::bazel::govern::tests::read;
    use crate::bazel::model::Index;

    const NPM: Ecosystem = Ecosystem::Npm;
    const JS: &str = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
        npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n";
    const LOCK: &str = "lockfileVersion: '9.0'\n\npatchedDependencies:\n  is-odd@3.0.1:\n    \
        hash: abc\n    path: patches/is-odd@3.0.1.patch\n";

    fn none(_: &Site) -> bool {
        false
    }

    fn js(tags: &str) -> BazelWorkspace {
        let module = format!("{JS}{tags}use_repo(npm, \"npm\")\n");
        read(&[("MODULE.bazel", &module), ("pnpm-lock.yaml", LOCK)])
    }

    /// The acceptance line: a `patches` key and a `patchedDependencies`
    /// entry each yield a user patch hook for the package, and for no
    /// other release.
    #[test]
    fn a_patches_key_and_a_patched_dependency_are_each_a_user_patch_hook() {
        let ws = js("npm.npm_translate_lock(\n    name = \"npm\",\n    pnpm_lock = \"//:pnpm-lock.yaml\",\n    \
                     patches = {\"left-pad@1.3.0\": [\"//:left-pad.patch\"], \"@scope/pkg\": [\"//:p.patch\"]},\n)\n");
        // The filter the gate and `attest` pass: an index with no
        // revision-4 row owns no site.
        let index = Index::default();
        let own = |site: &Site| exec::own_site(&index, site);
        let hooks = |name: &str, version: &str| user_patch_hooks(&ws, &own, NPM, name, version);

        let found = hooks("left-pad", "1.3.0");
        let [key] = &found[..] else {
            panic!("{found:?}");
        };
        assert_eq!(
            (key.hub, key.file.as_str()),
            (Some(HubId(0)), "MODULE.bazel")
        );
        assert!(key.host_patch && !key.replacement);
        assert!(hooks("left-pad", "1.2.0").is_empty(), "another version");
        // A key without a version is every version; a scope keeps its `@`.
        assert_eq!(hooks("@scope/pkg", "2.0.0").len(), 1);
        assert!(hooks("pkg", "2.0.0").is_empty());

        let found = hooks("is-odd", "3.0.1");
        let [entry] = &found[..] else {
            panic!("{found:?}");
        };
        assert_eq!(entry.file, "pnpm-lock.yaml");
        assert!(hooks("is-odd", "3.0.2").is_empty());
        assert!(!entry.covers(Ecosystem::Pypi, "is-odd", "3.0.1"));
        // A patch is no replacement, so it is no bypass.
        assert!(bypasses(&ws, &own, HubId(0), "left-pad", "1.3.0").is_empty());
        assert_eq!(USER_PATCH_HOOK, "user_patch_hook");
    }

    /// Own wiring is subtracted before anything is exported: a statement
    /// the filter claims is no hook and no bypass, and the user's own
    /// entry beside it stays.
    #[test]
    fn own_wiring_is_neither_a_hook_nor_a_bypass() {
        let ws = js("npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\", \
                     patches = {\"left-pad\": [\"//:p.patch\"]})\n\
                     npm.npm_replace_package(package = \"chalk@5.3.0\", replacement = \"//:chalk\")\n");
        let replaced = bypasses(&ws, &none, HubId(0), "chalk", "5.3.0");
        let [bypass] = &replaced[..] else {
            panic!("{replaced:?}");
        };
        assert_eq!(bypass.token, "user_override");
        assert_eq!(
            bypass.site.as_ref().map(|s| s.file.as_str()),
            Some("MODULE.bazel")
        );
        assert!(bypasses(&ws, &none, HubId(0), "chalk", "5.2.0").is_empty());
        // A replacement is no patch hook: consent does not lift it.
        assert!(user_patch_hooks(&ws, &none, NPM, "chalk", "5.3.0").is_empty());
        assert_eq!(
            user_patch_hooks(&ws, &none, NPM, "left-pad", "1.0.0").len(),
            1
        );

        let module = |site: &Site| site.file == "MODULE.bazel";
        assert!(bypasses(&ws, &module, HubId(0), "chalk", "5.3.0").is_empty());
        assert!(user_patch_hooks(&ws, &module, NPM, "left-pad", "1.0.0").is_empty());
        let left: Vec<String> = evidence(&ws, &module).into_iter().map(|e| e.file).collect();
        assert_eq!(left, ["pnpm-lock.yaml"]);
    }

    fn every(found: &[Evidence], ecosystem: Ecosystem) -> Vec<&str> {
        let whys = found.iter().filter(|e| e.ecosystem == ecosystem);
        let whys = whys.filter_map(|e| match &e.subject {
            Subject::Every { why, .. } => Some(why.as_str()),
            Subject::Package { .. } => None,
        });
        whys.collect()
    }

    const NODEJS: &str = "load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n\
        http_archive(name = \"build_bazel_rules_nodejs\", urls = [\"https://example.com/rules_nodejs-5.8.5.tar.gz\"])\n\
        load(\"@build_bazel_rules_nodejs//:index.bzl\", \"yarn_install\")\n\
        yarn_install(\n    name = \"npm\",\n    package_json = \"//:package.json\",\n    \
        yarn_lock = \"//:yarn.lock\",\n    post_install_patches = [\"//:fix.patch\"],\n)\n";

    /// ROUTED R-088: an install patch names no package, so it is a patch
    /// hook for every package of its hub. A hub Bazel never evaluates
    /// declares nothing.
    #[test]
    fn an_install_patch_of_rules_nodejs_covers_every_package_of_a_live_hub() {
        let files = [("WORKSPACE", NODEJS), ("yarn.lock", "# yarn lockfile v1\n")];
        let ws = read(&[(".bazelversion", "6.6.0\n"), files[0], files[1]]);
        let found = evidence(&ws, &none);
        assert_eq!(
            every(&found, NPM),
            ["the install patches `//:fix.patch` name no package"]
        );
        let hooks = user_patch_hooks(&ws, &none, NPM, "anything", "1.0.0");
        assert!(!hooks.is_empty() && hooks.iter().all(|e| e.host_patch));
        assert!(user_patch_hooks(&ws, &none, Ecosystem::Cargo, "anything", "1.0.0").is_empty());

        // Bazel 9 never opens the `WORKSPACE` file.
        let dead = read(&[
            (".bazelversion", "9.3.2\n"),
            ("MODULE.bazel", ""),
            files[0],
            files[1],
        ]);
        assert!(evidence(&dead, &none).is_empty());
    }

    /// ROUTED R-088: the `annotations` dict of a `WORKSPACE`
    /// `crates_repository` is not read, so it is "unknown", never "none";
    /// a call that passes no `annotations` hides nothing.
    #[test]
    fn the_annotations_of_a_workspace_crates_repository_are_unknown() {
        let rule = |attrs: &str| {
            let text = format!(
                "load(\"@rules_rust//crate_universe:defs.bzl\", \"crate\", \"crates_repository\")\n\
                 crates_repository(\n    name = \"crates\",\n    cargo_lockfile = \"//:Cargo.lock\",\n    \
                 lockfile = \"//:cargo-bazel-lock.json\",\n{attrs})\n"
            );
            read(&[
                (".bazelversion", "6.6.0\n"),
                ("WORKSPACE", &text),
                ("Cargo.lock", "version = 3\n"),
            ])
        };
        let annotated = rule("    annotations = {\"openssl-sys\": [crate.annotation(patches = [\"//:o.patch\"])]},\n");
        let found = evidence(&annotated, &none);
        assert_eq!(
            every(&found, Ecosystem::Cargo),
            ["the `annotations` of this crate_universe rule are not read"]
        );
        assert!(found
            .iter()
            .any(|e| e.covers(Ecosystem::Cargo, "openssl-sys", "0.9.0")));
        assert!(found
            .iter()
            .all(|e| !e.host_patch && !e.covers(NPM, "openssl-sys", "0.9.0")));
        assert_eq!(
            every(&evidence(&rule(""), &none), Ecosystem::Cargo),
            [""; 0]
        );
        assert!(!every(&evidence(&rule("    **EXTRA\n"), &none), Ecosystem::Cargo).is_empty());
    }

    /// A Maven override is keyed `group:artifact` and replaces the jar in
    /// every version; a `pip.override` patch covers its distribution in
    /// any PEP 503 spelling and runs through Bazel's own patcher.
    #[test]
    fn overrides_of_other_rulesets_are_matched_as_their_purls_spell_them() {
        let maven = read(&[(
            "MODULE.bazel",
            "bazel_dep(name = \"rules_jvm_external\", version = \"6.5\")\n\
             maven = use_extension(\"@rules_jvm_external//:extensions.bzl\", \"maven\")\n\
             maven.install(artifacts = [\"com.google.guava:guava:33.0.0-jre\"], lock_file = \"//:maven_install.json\")\n\
             maven.override(coordinates = \"com.google.guava:guava\", target = \"//third_party:guava\")\n\
             use_repo(maven, \"maven\")\n",
        )]);
        let found = bypasses(
            &maven,
            &none,
            HubId(0),
            "com.google.guava/guava",
            "33.0.0-jre",
        );
        assert_eq!(found.len(), 1, "{:?}", evidence(&maven, &none));
        assert!(bypasses(
            &maven,
            &none,
            HubId(0),
            "com.google.guava/failureaccess",
            "1.0"
        )
        .is_empty());
        assert!(bypasses(&maven, &none, HubId(7), "com.google.guava/guava", "1.0").is_empty());

        let pip = read(&[
            (
                "MODULE.bazel",
                "bazel_dep(name = \"rules_python\", version = \"1.5.0\")\n\
                 pip = use_extension(\"@rules_python//python/extensions:pip.bzl\", \"pip\")\n\
                 pip.parse(hub_name = \"pypi\", python_version = \"3.11\", requirements_lock = \"//:requirements.txt\")\n\
                 pip.override(file = \"Typing_Extensions-4.9.0-py3-none-any.whl\", patches = [\"//:t.patch\"])\n\
                 use_repo(pip, \"pypi\")\n",
            ),
            ("requirements.txt", "typing-extensions==4.9.0\n"),
        ]);
        let found = evidence(&pip, &none);
        let covers = |name: &str| {
            found
                .iter()
                .filter(|e| e.covers(Ecosystem::Pypi, name, "4.9.0"))
                .count()
        };
        assert_eq!(
            (covers("typing_extensions"), covers("requests")),
            (1, 0),
            "{found:?}"
        );
        assert!(
            user_patch_hooks(&pip, &none, Ecosystem::Pypi, "typing-extensions", "4.9.0").is_empty()
        );
    }

    /// A hook attribute that is computed, and a use of the ruleset that
    /// was not followed to a hub, protect the whole ecosystem.
    #[test]
    fn what_was_not_read_protects_the_ecosystem() {
        let computed = js("npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\", patches = PATCHES)\n");
        let found = evidence(&computed, &none);
        assert!(!every(&found, NPM).is_empty(), "{found:?}");
        assert!(!user_patch_hooks(&computed, &none, NPM, "left-pad", "1.3.0").is_empty());
        assert!(every(&found, Ecosystem::Pypi).is_empty());

        // The ruleset with no hub that was read.
        let signal = read(&[(
            "MODULE.bazel",
            "bazel_dep(name = \"rules_jvm_external\", version = \"6.5\")\n",
        )]);
        let found = evidence(&signal, &none);
        assert_eq!(
            every(&found, Ecosystem::Maven),
            ["rules_jvm_external is used here and no hub was read"]
        );
        assert!(found.iter().all(|e| e.hub.is_none() && !e.replacement));
    }
}
