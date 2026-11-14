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
//!   a hub that is proven dead or shadowed patches nothing. One on a hub
//!   that is a dev dependency, another module's or imported by a spoke
//!   alone still does: Bazel builds from those.
//! - **Own wiring is subtracted first** (revision 4, 2.2 row 6). Every
//!   exported function takes the filter as a parameter ([`OwnSite`]), and
//!   the gate and `attest` pass the same one (over the index they hold),
//!   so a `patches` item or a tag that socket-patch wrote itself is no
//!   user patch hook and no bypass in either. The filter is asked per
//!   item: the user's other key of a dict socket-patch added one to stays
//!   the user's.
//! - **Unread is not absent.** A declaration that names no single
//!   package, a hook attribute nobody read and a use of the ruleset that
//!   was not followed to a hub each protect every package of the
//!   ecosystem ([`Subject::Every`]). A recognizer gap and a signal count
//!   where Bazel may evaluate the statement, by the test
//!   `govern::governance` applies to the same gap: one in a file Bazel
//!   never opens declares nothing, and a refusal over it would name a
//!   file nobody has to fix.
//! - **Unread is not everywhere either.** A hook is an argument of a tag
//!   or of a repository rule call, so it needs a statement that can hold
//!   one. A ruleset's `bazel_dep` in a module file that was read whole and
//!   uses no extension and no repository rule of that module holds none
//!   ([`declares_no_hook`]), and is no evidence: every npm package of a
//!   workspace that only depends on `aspect_rules_js` would be held back
//!   over a hook that cannot exist, with nothing in the file to fix.
//!
//! A replacement defeats a pin outright, so it is also a bypass that
//! `--allow-patch-conflicts` does not lift ([`bypasses`]). A patch on a
//! hub whose hook runs, or is not known not to run, the host `patch` tool
//! is a **user patch hook** ([`user_patch_hooks`], token
//! [`USER_PATCH_HOOK`]): probe P4 saw such a hook stack silently, fail
//! the fetch, or reverse the same fix over the patched tarball with exit
//! 0, so a pin written beside one is never attested.

use super::govern::{self, WORKSPACE_UNREADABLE};
use super::inventory::may_build;
use super::label::{Label, Repo};
use super::model::{
    BazelWorkspace, Bypass, DeclSystem, Hub, HubId, Ruleset, RulesetDetail, RulesetSignal, Site,
};
use super::module_file::{
    ExtensionProxy, GapScope, GapWhy, Host, ModuleGap, ModuleModel, RepoRule,
};
use super::rulesets::gazelle::GazelleDetail;
use super::rulesets::rules_python::USER_OVERRIDE;
use super::starlark::Lookup;
use super::workspace_file::WsStmtKind;
use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::crawlers::types::Ecosystem;
use crate::utils::npm_range::npm_range_admits;
use crate::vendor::bun_lock_text::split_name_spec;

/// Every `details.token` this file names.
pub const TOKENS: &[&str] = &["user_patch_hook"];

/// The user's own patch for the package exists on a hub whose patch hook
/// runs the host `patch` tool. `attest` withholds with it.
pub const USER_PATCH_HOOK: &str = TOKENS[0];

/// Whether a statement, or one item of it, is socket-patch's own wiring.
///
/// The second argument is the recognizer's key of one item of the
/// statement at the site (`UserDecl.package`: a key of a `patches` or
/// `replace_packages` dict, the package of a tag, a local wheel). Every
/// key of one call carries the site of the whole call, so the site alone
/// cannot tell an item socket-patch added (a `tagEdits` row) from the
/// user's own item beside it. `None` asks about the statement as a whole:
/// a hub whose declaration is not literal, install patches, annotations
/// nobody read, a use of the ruleset that led to no hub.
///
/// A filter answers `true` for `None` only where the whole statement is
/// socket-patch's (it stands in an owned file). A statement of the user's
/// that is only the target of a tag edit is never subtracted whole: the
/// filter claims the edited item by its key and nothing else of the call.
///
/// The gate and `attest` pass the same filter. Until the `TagEdit`
/// handler lands an item matcher over the `tagEdits` rows, that is
/// `|site, _| exec::own_site(&index, site)`.
pub type OwnSite<'a> = &'a dyn Fn(&Site, Option<&str>) -> bool;

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

/// Whether the hub applies a user's patches with the host `patch` tool,
/// or is not known not to. "Not known" counts: the answer only withholds
/// an attestation for a pin beside the user's own patch of the package.
///
/// - rules_js and rules_nodejs on every release (bazel-lib's `patch` with
///   a `patch_directory`, and the install rules' own shell-out).
/// - A `WORKSPACE` `go_repository` on every release. Until gazelle 0.29.0
///   the rule shells out itself. From 0.29.0 it calls Bazel's `patch()`,
///   which is native only when `patch_tool` is empty and every
///   `patch_args` entry is `-p<n>` (bazel@7.7.2
///   tools/build_defs/repo/utils.bzl:162-195), and the rule still takes
///   both attributes (bazel-gazelle@v0.29.0 internal/go_repository.bzl).
///   The recognizer records one bit per hook and not those attributes.
/// - A `go_deps` hub only while gazelle is not proven 0.29.0 or later:
///   its override tags take `patches`, `patch_strip` and `patch_cmds`
///   only (bazel-gazelle@v0.54.0 internal/bzlmod/go_deps.bzl:1008-1057).
///   A tag proves the release it arrived in (`module_override`: 0.31.0),
///   so a hub with such a patch is proven as a rule.
/// - rules_rust: `crate.annotation` passes `patch_tool` and `patch_args`
///   through (rules_rust@0.57.1 crate_universe/private/crate.bzl:111-113),
///   and they are not recorded either. rules_rs has the same reader of
///   annotations; its patch path was not read, so it counts as well.
///
/// rules_python, rules_pycross, aspect_rules_py and rules_jvm_external
/// patch through Bazel's own patcher or have no patch hook.
pub fn host_patch(hub: &Hub) -> bool {
    match (hub.ruleset, &hub.detail) {
        (Ruleset::Gazelle, RulesetDetail::Gazelle(GazelleDetail::GoDeps(_))) => {
            !hub.ruleset_version.at_least("0.29.0")
        }
        (ruleset, _) => may_host_patch(ruleset),
    }
}

/// [`host_patch`] where no hub was read: whether any hub of the ruleset
/// may run the host `patch` tool.
fn may_host_patch(ruleset: Ruleset) -> bool {
    use Ruleset::{Gazelle, RulesJs, RulesNodejs, RulesRs, RulesRust};
    [RulesJs, RulesNodejs, Gazelle, RulesRust, RulesRs].contains(&ruleset)
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

/// Every ecosystem [`evidence`] can name: the ones a ruleset with a patch
/// or replacement hook builds. A package of any other ecosystem is
/// protected by no declaration of a Bazel workspace, so a caller that has
/// only such packages need not read one.
pub fn ecosystems() -> Vec<Ecosystem> {
    let mut found = Vec::new();
    for ecosystem in Ruleset::ALL.iter().filter_map(|ruleset| hooked(*ruleset)) {
        if !found.contains(&ecosystem) {
            found.push(ecosystem);
        }
    }
    found
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
        // `name`, `name@version` or `name@version` with the peer suffix
        // of one snapshot (`1.2.3(peer@2.0.0)`, pnpm 5 `1.2.3_peer@2.0.0`):
        // rules_js matches a key against all three spellings
        // (rules_js@v3.6.0 npm/private/npm_translate_lock_helpers.bzl:526-536).
        // A scope starts with `@` and a peer suffix holds one, so the
        // version starts at the first `@` past the scope's. A version
        // holds neither `(` nor `_`: what follows one is the peer set,
        // and the key covers the release whatever its peers.
        Ruleset::RulesJs => match split_name_spec(package) {
            Some((name, selector)) => {
                let version = selector.split(['(', '_']).next().unwrap_or(selector);
                named(name, Some(version).filter(|version| !version.is_empty()))
            }
            None => named(package, None),
        },
        Ruleset::RulesJvmExternal => match package.split(':').collect::<Vec<_>>()[..] {
            [group, artifact] if !group.is_empty() && !artifact.is_empty() => {
                named(&format!("{group}/{artifact}"), None)
            }
            _ => every(format!("`{package}` is not a `group:artifact` coordinate")),
        },
        // A key that cannot be a distribution name is a label (a local
        // wheel whose file name is not a wheel's): which package it
        // stands in for is not known.
        Ruleset::RulesPython | Ruleset::RulesPycross | Ruleset::AspectRulesPy
            if !package.chars().all(distribution_char) =>
        {
            every(format!(
                "`{package}` is no distribution name, so the package it is for is not known"
            ))
        }
        _ => named(package, None),
    }
}

/// A character of a Python distribution name (PEP 508).
fn distribution_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')
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
        // `key`: the recognizer's key of one item, `None` for evidence
        // that is of the statement as a whole.
        let mut push = |subject: Subject, replacement: bool, site: &Site, key: Option<&str>| {
            if !own(site, key) {
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
            let key = Some(decl.package.as_str());
            push(
                subject(hub, &decl.package),
                decl.replacement,
                &decl.site,
                key,
            );
        }
        // What a recognizer keeps in its detail and not in `user_decls`.
        match &hub.detail {
            RulesetDetail::RulesNodejs(detail) if !detail.install_patches.is_empty() => {
                let labels = detail.install_patches.join("`, `");
                let why = format!("the install patches `{labels}` name no package");
                push(every(why), false, &hub.decl.site, None);
            }
            RulesetDetail::RulesPython(detail) => {
                for over in detail.overrides.iter().filter(|o| o.package.is_none()) {
                    let why = format!(
                        "`pip.override` of `{}`, which is no wheel's name",
                        over.file
                    );
                    push(every(why), false, &over.site, None);
                }
            }
            RulesetDetail::RulesRust(_) if annotations_unread(ws, hub) => {
                let why = "the `annotations` of this crate_universe rule are not read";
                push(every(why.to_string()), false, &hub.decl.site, None);
            }
            _ => {}
        }
        // Which attribute was computed is not recorded, so a hook
        // attribute may be among them.
        if !hub.decl.literal && hooked(hub.ruleset).is_some() {
            let why = "the declaration is not literal, so its patches are not known";
            push(every(why.to_string()), false, &hub.decl.site, None);
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
                host_patch: may_host_patch(ruleset),
                file: file.to_string(),
                site: site.cloned(),
            })
        };
    // What a recognizer could not read, where Bazel may evaluate it.
    let gaps = ws.ruleset_gaps.iter();
    for (ruleset, gap) in gaps.filter(|(_, gap)| govern::may_evaluate_gap(ws, gap)) {
        let unreadable = gap.token == WORKSPACE_UNREADABLE;
        out.extend(unread(*ruleset, &gap.detail, unreadable, None, &gap.file));
    }
    let followed = |site: &Site| !own(site, None) && govern::may_evaluate(ws, site);
    let may_hold_one = |signal: &&RulesetSignal| !declares_no_hook(ws, signal);
    let signals = ws.signals.iter().filter(may_hold_one);
    for signal in signals.filter(|signal| followed(&signal.site)) {
        let why = format!("{} is used here and no hub was read", signal.ruleset.name());
        let (site, file) = (Some(&signal.site), &signal.site.file);
        out.extend(unread(signal.ruleset, &why, false, site, file));
    }
    out
}

/// Whether a gap of the module file leaves room for a declaration that
/// can hold a hook: a tag, a repository rule call, the extension proxy or
/// the rule either hangs on, a file that may hold any of them, or the
/// `bazel_dep` that says whose file a label names.
///
/// Every [`GapScope::Everything`] gap does but one. `use_repo` gives the
/// root module repository names and nothing else, so a use of it that was
/// not read (a comprehension over the names, an argument that is no
/// proxy) hides imports and no tag. A use of the proxy inside such a
/// statement is a gap of that proxy, which its ruleset's recognizer
/// reports.
fn may_hide_a_hook(gap: &ModuleGap) -> bool {
    let imports = |name: &str| name == "use_repo";
    let harmless = match &gap.why {
        GapWhy::Unmodelled { name, .. } => imports(name),
        GapWhy::Argument { directive, .. } => imports(directive),
        _ => false,
    };
    gap.scope == GapScope::Everything && !harmless
}

/// Whether `label` may name a file of the module the `bazel_dep` at
/// `dep` brings in. One Bazel rejects and a canonical name are not known
/// not to. An apparent name no `bazel_dep` gives is another repository:
/// a module is visible to the root under the name its `bazel_dep` gives
/// it and under no other.
fn may_be_of(module: &ModuleModel, label: Option<&Label>, dep: &str) -> bool {
    let Some(label) = label else {
        return true;
    };
    match module.host(label) {
        Host::Dep(host) => host.name == dep,
        Host::Root => false,
        Host::Unknown => matches!(label.repo, Repo::Canonical(_)),
    }
}

/// Whether `signal` is a ruleset's `bazel_dep` in a module file that
/// proves no hook of the ruleset stands in it.
///
/// A hook is an argument of a tag (`patches` of `npm.npm_translate_lock`,
/// `maven.override`) or of a repository rule call, and each needs a
/// `use_extension` or a `use_repo_rule` over a file of the ruleset's
/// module. Where every statement that could hold one was read
/// ([`may_hide_a_hook`]) and none names such a file, no tag exists, so no
/// hook does: the root only depends on the ruleset (for its build rules,
/// or to pin its version), and holding the ecosystem back would name a
/// declaration nobody can edit.
///
/// `false` for every other signal: one of a `WORKSPACE` file (the call
/// may be in a macro nobody read), one at an extension proxy, and a
/// `bazel_dep` beside a statement that was not read or beside a use of
/// the module. An extension of another module that wraps the ruleset is
/// outside what the model shows here as it is beside a hub that was read.
fn declares_no_hook(ws: &BazelWorkspace, signal: &RulesetSignal) -> bool {
    let bzlmod = signal.site.system == DeclSystem::Bzlmod;
    let Some(module) = ws.module.as_ref().filter(|_| bzlmod) else {
        return false;
    };
    let mut deps = module.deps.iter();
    let Some(dep) = deps.find(|dep| module.site(dep.at) == signal.site) else {
        return false;
    };
    let of_the_ruleset = |label: Option<&Label>| may_be_of(module, label, &dep.name);
    let extension = |proxy: &ExtensionProxy| of_the_ruleset(proxy.label.as_ref());
    let rule = |rule: &RepoRule| of_the_ruleset(rule.label.as_ref());
    !module.gaps.iter().any(may_hide_a_hook)
        && !module.proxies.iter().any(extension)
        && !module.repo_rules.iter().any(rule)
}

/// Where a hook may stand in a statement of the module file that was read
/// as text and not as what it declares: a `use_extension` whose label is
/// computed or that is used inside an expression, an `include` that is no
/// plain statement, a repository rule called in a comprehension. Such a
/// gap belongs to no ruleset, so no recognizer reports it, and beside a
/// hub it may be a second use of the same extension with tags nobody read
/// (`exts = [use_extension(...)]`, then `exts[0].npm_replace_package(...)`).
///
/// It counts for each ecosystem the workspace has a hub of that Bazel may
/// build from: there the ruleset's hooks are in use and one more may be
/// in what was not read. A ruleset with no hub is answered by its signal
/// in [`evidence`], which stands beside such a gap; an ecosystem the
/// workspace shows no use of is not held back by a statement that may be
/// anyone's. A gap counts where Bazel reads the module file, and one that
/// can hide no hook does not ([`may_hide_a_hook`]).
///
/// These are not part of [`evidence`]: the lane gate and `attest` hold
/// every ecosystem up for the same gaps through `govern::governance`,
/// with the refusal that names them, and a "patch of your own" there
/// would say more than is known. A gap that is an unreadable or missing
/// file is governance's too, for every ecosystem
/// ([`WORKSPACE_UNREADABLE`]).
pub fn unread_statements(ws: &BazelWorkspace) -> Vec<Evidence> {
    let Some(module) = ws.module.as_ref() else {
        return Vec::new();
    };
    let built = |ecosystem: &Ecosystem| {
        let of = |hub: &Hub| may_build(hub) && hooked(hub.ruleset) == Some(*ecosystem);
        ws.hubs.iter().any(of)
    };
    let used: Vec<Ecosystem> = ecosystems().into_iter().filter(built).collect();
    let computed = |gap: &&ModuleGap| {
        let text = matches!(
            gap.why,
            GapWhy::Unmodelled { .. } | GapWhy::Argument { .. } | GapWhy::IncludeShape
        );
        text && may_hide_a_hook(gap)
    };
    let mut out = Vec::new();
    for gap in module.gaps.iter().filter(computed) {
        let site = module.site(gap.at);
        if !govern::may_evaluate(ws, &site) {
            continue;
        }
        let why = module.describe(gap);
        out.extend(used.iter().map(|ecosystem| Evidence {
            hub: None,
            ecosystem: *ecosystem,
            subject: Subject::Every {
                why: why.clone(),
                unreadable: false,
            },
            replacement: false,
            // What stands there is not known, so neither is its patcher.
            host_patch: true,
            file: site.file.clone(),
            site: None,
        }));
    }
    out
}

/// The user's patch hooks for `name`@`version`: the patches of
/// [`evidence`] that cover it on a hub whose hook runs the host `patch`
/// tool or is not known not to ([`host_patch`]: a `patches` key, a pnpm
/// `patchedDependencies` entry, an install patch, a `go_repository`
/// patch, a `crate.annotation` patch). Empty when there is none. With one,
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
            what: match &e.subject {
                // Which package it replaces is not known: say what is.
                Subject::Every { why, .. } => format!("{}: {why}", e.file),
                Subject::Package { .. } => {
                    format!("{}: a declaration of the user's replaces `{name}`", e.file)
                }
            },
            site: e.site,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bazel::exec;
    use crate::bazel::govern::tests::{read, JS_WORKSPACE};
    use crate::bazel::model::Index;
    use crate::bazel::model::Liveness;
    use crate::bazel::owned_index::tests::revision_4;
    use crate::bazel::owned_index::OWNED_SEGMENT_PATH;
    use crate::bazel::ruleset_version::{Unproven, VersionVerdict};

    const NPM: Ecosystem = Ecosystem::Npm;
    const JS: &str = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
        npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n";
    const LOCK: &str = "lockfileVersion: '9.0'\n\npatchedDependencies:\n  is-odd@3.0.1:\n    \
        hash: abc\n    path: patches/is-odd@3.0.1.patch\n";

    fn none(_: &Site, _: Option<&str>) -> bool {
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
        let own = |site: &Site, _: Option<&str>| exec::own_site(&index, site);
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

        let module = |site: &Site, _: Option<&str>| site.file == "MODULE.bazel";
        assert!(bypasses(&ws, &module, HubId(0), "chalk", "5.3.0").is_empty());
        assert!(user_patch_hooks(&ws, &module, NPM, "left-pad", "1.0.0").is_empty());
        let left: Vec<String> = evidence(&ws, &module).into_iter().map(|e| e.file).collect();
        assert_eq!(left, ["pnpm-lock.yaml"]);
    }

    /// Every key of one `patches` dict carries the site of the whole
    /// call, so the filter is asked per key: the item it claims is
    /// subtracted, and the user's other item of the same call is still a
    /// hook. Evidence of the statement as a whole is asked with no key,
    /// and a filter that claims one item does not subtract it.
    #[test]
    fn the_filter_claims_one_item_of_a_call_and_not_the_users_other_item() {
        let ws = js("npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\", \
                     patches = {\"left-pad@1.3.0\": [\"//:user.patch\"], \
                     \"is-even@1.0.0\": [\"//.socket/bazel/patches/u/own.patch\"]}, \
                     replace_packages = {\"chalk@5.3.0\": \"//:chalk\", \"debug@4.3.4\": \"//:own\"})\n");
        let sites: Vec<Site> = (evidence(&ws, &none).into_iter())
            .filter(|e| e.file == "MODULE.bazel")
            .filter_map(|e| e.site)
            .collect();
        assert_eq!(sites.len(), 4);
        assert!(sites.iter().all(|site| *site == sites[0]), "{sites:?}");

        let call = sites[0].clone();
        let asked = std::cell::RefCell::new(Vec::new());
        let item = |site: &Site, key: Option<&str>| {
            asked.borrow_mut().push(key.map(str::to_string));
            *site == call && matches!(key, Some("is-even@1.0.0" | "debug@4.3.4"))
        };
        let hooks = |name: &str, version: &str| user_patch_hooks(&ws, &item, NPM, name, version);
        assert!(hooks("is-even", "1.0.0").is_empty(), "socket-patch's own");
        assert_eq!(hooks("left-pad", "1.3.0").len(), 1, "the user's own");
        assert!(bypasses(&ws, &item, HubId(0), "debug", "4.3.4").is_empty());
        assert_eq!(bypasses(&ws, &item, HubId(0), "chalk", "5.3.0").len(), 1);
        // The lock's `patchedDependencies` entry is asked by its key too.
        let asked = asked.into_inner();
        for key in ["left-pad@1.3.0", "is-even@1.0.0", "is-odd@3.0.1"] {
            assert!(asked.contains(&Some(key.to_string())), "{key}: {asked:?}");
        }

        // A computed `patches` is evidence of the whole statement: no key.
        let computed = js("npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\", patches = PATCHES)\n");
        let site = computed.hubs[0].decl.site.clone();
        let at_call = |own: OwnSite<'_>| {
            let found = evidence(&computed, own);
            let here = found.iter().filter(|e| e.site.as_ref() == Some(&site));
            here.map(|e| e.subject.clone()).collect::<Vec<_>>()
        };
        let keyed = |at: &Site, key: Option<&str>| *at == site && key.is_some();
        let [Subject::Every { why, .. }] = &at_call(&keyed)[..] else {
            panic!("{:?}", at_call(&keyed));
        };
        assert!(why.contains("not literal"), "{why}");
        let whole = |at: &Site, key: Option<&str>| *at == site && key.is_none();
        assert_eq!(at_call(&whole), []);
    }

    /// A replacement tag in the owned segment is subtracted once the
    /// filter claims it, and the user's tag of the same extension in
    /// `MODULE.bazel` is still a bypass.
    ///
    /// The filter the gate and `attest` pass today (`exec::own_site`)
    /// claims no site, with or without a segment row: a statement is own
    /// only where its file is proven to be what its rows render, and the
    /// segment's handler brings that check. Until it lands both tags are
    /// the user's, which refuses where it should subtract and never the
    /// reverse.
    #[test]
    fn a_tag_in_the_owned_segment_is_subtracted_only_by_a_filter_that_claims_it() {
        let module = format!(
            "{JS}npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n\
             npm.npm_replace_package(package = \"chalk@5.3.0\", replacement = \"//:chalk\")\n\
             use_repo(npm, \"npm\")\n\
             include(\"//.socket/bazel:socket-patch.MODULE.bazel\")\n"
        );
        let segment = "npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
             npm.npm_replace_package(package = \"left-pad@1.3.0\", replacement = \"@socket_patch_left_pad//:pkg\")\n";
        let ws = read(&[
            (".bazelversion", "8.8.2\n"),
            ("MODULE.bazel", &module),
            (OWNED_SEGMENT_PATH, segment),
            ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
        ]);
        let replaced = |own: OwnSite<'_>, name: &str, version: &str| {
            let found = bypasses(&ws, own, HubId(0), name, version);
            let files = found.iter().filter_map(|b| b.site.as_ref());
            files.map(|site| site.file.clone()).collect::<Vec<_>>()
        };
        // The real filter: with no row the segment is not rendered, and
        // with rows it cannot yet be checked against them.
        let rows = Index {
            segment: revision_4().segment,
            ..Index::default()
        };
        assert!(!rows.segment.is_empty());
        for index in [Index::default(), rows] {
            let real = |site: &Site, _: Option<&str>| exec::own_site(&index, site);
            assert_eq!(replaced(&real, "left-pad", "1.3.0"), [OWNED_SEGMENT_PATH]);
            assert_eq!(replaced(&real, "chalk", "5.3.0"), ["MODULE.bazel"]);
        }

        // A filter that claims the statements of the owned segment.
        let own = |site: &Site, _: Option<&str>| site.file == OWNED_SEGMENT_PATH;
        assert_eq!(replaced(&own, "left-pad", "1.3.0"), [""; 0]);
        assert_eq!(replaced(&own, "chalk", "5.3.0"), ["MODULE.bazel"]);
    }

    /// A hub that is a dev dependency under a flag that is only possible,
    /// and one the root imports by a spoke alone, are hubs Bazel builds
    /// from: the user's `patches` key on either is still a patch hook.
    /// The proven cases stay out: see the Bazel 9 `WORKSPACE` below.
    #[test]
    fn a_patches_key_on_a_dev_or_spoke_only_hub_is_still_a_hook() {
        let hub = |proxy: &str, import: &str| {
            format!(
                "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
                 npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\"{proxy})\n\
                 npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\", \
                 patches = {{\"left-pad@1.3.0\": [\"//:left-pad.patch\"]}})\n\
                 use_repo(npm, \"{import}\")\n"
            )
        };
        let lock = ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
        let hooks =
            |ws: &BazelWorkspace| user_patch_hooks(ws, &none, NPM, "left-pad", "1.3.0").len();
        let dev = hub(", dev_dependency = True", "npm");
        let ws = read(&[
            (".bazelversion", "9.3.2\n"),
            (".bazelrc", "common:ci --ignore_dev_dependency\n"),
            ("MODULE.bazel", &dev),
            lock,
        ]);
        assert_eq!(ws.hubs[0].liveness, Liveness::DevDependencyDropped);
        assert_eq!(hooks(&ws), 1);

        let spoke = hub("", "npm__left-pad__1.3.0");
        let ws = read(&[(".bazelversion", "9.3.2\n"), ("MODULE.bazel", &spoke), lock]);
        assert_eq!(ws.hubs[0].liveness, Liveness::NotImported);
        assert_eq!(hooks(&ws), 1);
    }

    /// rules_js matches a key against the name, the name with its
    /// version, and the name with the version and peer suffix of one
    /// snapshot. Each is a declaration for the plain name and version.
    #[test]
    fn a_peer_suffixed_key_is_for_the_plain_name_and_version() {
        let ws = js("npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\", \
                     patches = {\"@rollup/plugin-commonjs@21.1.0(rollup@2.70.2)\": [\"//:a.patch\"], \
                     \"foo@1.2.3_bar@2.0.0\": [\"//:b.patch\"], \
                     \"@s/foo@1.2.3(bar@2.0.0)\": [\"//:c.patch\"], \
                     \"styled-components@5.3.6_react@18.2.0\": [\"//:d.patch\"]}, \
                     replace_packages = {\"chalk@5.3.0(debug@4.3.4)\": \"//:chalk\"})\n");
        let hooks = |name: &str, version: &str| user_patch_hooks(&ws, &none, NPM, name, version);
        for (name, version) in [
            ("@rollup/plugin-commonjs", "21.1.0"),
            ("foo", "1.2.3"),
            ("@s/foo", "1.2.3"),
            ("styled-components", "5.3.6"),
        ] {
            let found = hooks(name, version);
            let [hook] = &found[..] else {
                panic!("{name}@{version}: {found:?}");
            };
            let subject = Subject::Package {
                name: name.to_string(),
                version: Some(version.to_string()),
            };
            assert_eq!(hook.subject, subject);
            // The key is for one release, whatever its peers.
            assert!(hooks(name, "9.9.9").is_empty(), "{name}");
        }
        // No package is named by a peer of another.
        assert!(hooks("rollup", "2.70.2").is_empty());
        assert!(hooks("bar", "2.0.0").is_empty());
        assert_eq!(bypasses(&ws, &none, HubId(0), "chalk", "5.3.0").len(), 1);
        assert!(bypasses(&ws, &none, HubId(0), "chalk", "5.2.0").is_empty());
        assert!(bypasses(&ws, &none, HubId(0), "debug", "4.3.4").is_empty());
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
        // `crate.annotation` passes `patch_tool` through, and it is not
        // read: the host tool is not ruled out.
        assert!(found
            .iter()
            .all(|e| e.host_patch && !e.covers(NPM, "openssl-sys", "0.9.0")));
        assert_eq!(
            every(&evidence(&rule(""), &none), Ecosystem::Cargo),
            [""; 0]
        );
        // `**EXTRA` may hold `annotations`, and the call is not literal.
        // Beside those two is what the recognizer could not read, in its
        // own words, and nothing else.
        let spread = rule("    **EXTRA\n");
        let found = evidence(&spread, &none);
        let (of_hub, unread): (Vec<Evidence>, Vec<Evidence>) =
            found.into_iter().partition(|e| e.hub == Some(HubId(0)));
        assert_eq!(
            every(&of_hub, Ecosystem::Cargo),
            [
                "the `annotations` of this crate_universe rule are not read",
                "the declaration is not literal, so its patches are not known",
            ]
        );
        assert_eq!(of_hub.len(), 2);
        let gaps = spread.ruleset_gaps.iter();
        let gaps: Vec<&str> = gaps.map(|(_, gap)| gap.detail.as_str()).collect();
        assert_eq!(every(&unread, Ecosystem::Cargo), gaps);
        assert!(unread.len() == gaps.len() && unread.iter().all(|e| e.hub.is_none()));
    }

    const CARGO: &str = "bazel_dep(name = \"rules_rust\", version = \"0.57.0\")\n\
        crate = use_extension(\"@rules_rust//crate_universe:extensions.bzl\", \"crate\")\n\
        crate.from_cargo(name = \"crates\", cargo_lockfile = \"//:Cargo.lock\", manifests = [\"//:Cargo.toml\"])\n";

    /// The Bzlmod half of the same rule. A hub a `crate.from_cargo` tag
    /// declares has its annotations in `crate.annotation` tags, which are
    /// read: without one nothing is protected, and with one only its
    /// crate is. A `crates_repository` called through `use_repo_rule`
    /// takes an `annotations` dict like the `WORKSPACE` rule.
    #[test]
    fn the_annotations_of_a_bzlmod_hub_are_read_from_its_tags() {
        let module = |tags: &str| {
            let text = format!("{CARGO}{tags}use_repo(crate, \"crates\")\n");
            read(&[
                (".bazelversion", "9.3.2\n"),
                ("MODULE.bazel", &text),
                ("Cargo.lock", "version = 3\n"),
            ])
        };
        let plain = module("");
        assert_eq!(plain.hubs.len(), 1);
        assert_eq!(evidence(&plain, &none), []);

        let annotated =
            module("crate.annotation(crate = \"openssl-sys\", patches = [\"//:o.patch\"])\n");
        let found = evidence(&annotated, &none);
        let [patch] = &found[..] else {
            panic!("{found:?}");
        };
        let subject = Subject::Package {
            name: "openssl-sys".to_string(),
            version: None,
        };
        assert_eq!((&patch.subject, patch.replacement), (&subject, false));
        // crates.io folds case and `-` / `_`.
        assert!(patch.covers(Ecosystem::Cargo, "openssl_sys", "0.9.0"));
        assert!(!patch.covers(Ecosystem::Cargo, "openssl", "0.10.0"));
        let hooks =
            |name: &str| user_patch_hooks(&annotated, &none, Ecosystem::Cargo, name, "1.0.0");
        assert_eq!((hooks("openssl-sys").len(), hooks("serde").len()), (1, 0));

        let rule = read(&[
            (".bazelversion", "9.3.2\n"),
            (
                "MODULE.bazel",
                "bazel_dep(name = \"rules_rust\", version = \"0.57.0\")\n\
                 crates_repository = use_repo_rule(\"@rules_rust//crate_universe:defs.bzl\", \"crates_repository\")\n\
                 crates_repository(name = \"crates\", cargo_lockfile = \"//:Cargo.lock\", \
                 lockfile = \"//:cargo-bazel-lock.json\", manifests = [\"//:Cargo.toml\"], annotations = ANNOTATIONS)\n",
            ),
            ("Cargo.lock", "version = 3\n"),
        ]);
        let found = evidence(&rule, &none);
        let whys = every(&found, Ecosystem::Cargo);
        assert!(
            whys.contains(&"the `annotations` of this crate_universe rule are not read"),
            "{found:?}"
        );
        assert!(!user_patch_hooks(&rule, &none, Ecosystem::Cargo, "serde", "1.0.0").is_empty());

        // A `crates_vendor` BUILD target takes the dict as well, and its
        // call is not found again: unknown, beside a tag hub that hides
        // nothing.
        let module = format!("{CARGO}use_repo(crate, \"crates\")\n");
        let build = "load(\"@rules_rust//crate_universe:defs.bzl\", \"crates_vendor\")\n\
             crates_vendor(\n    name = \"crates_vendor\",\n    cargo_lockfile = \"//:Cargo.lock\",\n    \
             manifests = [\"//:Cargo.toml\"],\n    mode = \"local\",\n    vendor_path = \"crates\",\n)\n";
        let vendored = read(&[
            (".bazelversion", "9.3.2\n"),
            ("MODULE.bazel", &module),
            ("Cargo.lock", "version = 3\n"),
            ("third_party/BUILD.bazel", build),
        ]);
        assert_eq!(vendored.hubs.len(), 2, "{:?}", vendored.hubs);
        let found = evidence(&vendored, &none);
        let unread: Vec<(&str, &Subject)> = (found.iter())
            .map(|e| (e.file.as_str(), &e.subject))
            .collect();
        let every = Subject::Every {
            why: "the `annotations` of this crate_universe rule are not read".to_string(),
            unreadable: false,
        };
        assert_eq!(unread, [("third_party/BUILD.bazel", &every)]);
    }

    const GO_RULES: &str = "workspace(name = \"sp\")\n\n\
        load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n\n\
        http_archive(\n    name = \"io_bazel_rules_go\",\n    \
        urls = [\"https://github.com/bazelbuild/rules_go/releases/download/v0.44.0/rules_go-v0.44.0.zip\"],\n)\n\n";

    /// A `WORKSPACE` hub of `go_repository` rules, gazelle fetched as
    /// release `version` (`None`: from a URL that proves no version).
    fn go_repositories(version: Option<&str>, attrs: &str) -> BazelWorkspace {
        let url = match version {
            Some(v) => format!(
                "https://github.com/bazelbuild/bazel-gazelle/releases/download/v{v}/bazel-gazelle-v{v}.tar.gz"
            ),
            None => "https://mirror.example.com/gazelle.tar.gz".to_string(),
        };
        let text = format!(
            "{GO_RULES}http_archive(\n    name = \"bazel_gazelle\",\n    urls = [\"{url}\"],\n)\n\n\
             load(\"@bazel_gazelle//:deps.bzl\", \"gazelle_dependencies\", \"go_repository\")\n\n\
             go_repository(\n    name = \"org_golang_x_crypto\",\n    importpath = \"golang.org/x/crypto\",\n    \
             sum = \"h1:SLqDtcPyVkkOYblt1rSVexJHaLWU/teyZ8o5mHyiUbA=\",\n    version = \"v0.17.0\",\n    \
             patches = [\"//:crypto.patch\"],\n{attrs})\n\ngazelle_dependencies()\n"
        );
        read(&[(".bazelversion", "6.6.0\n"), ("WORKSPACE", &text)])
    }

    /// The golang evidence. A `go_repository` patch is a user patch hook
    /// on every gazelle release: until 0.29.0 the rule shells out, and
    /// from 0.29.0 `patch_tool` or an argument that is not `-p<n>` still
    /// does, and neither attribute is recorded. A `go_deps` override tag
    /// has no such attribute: with gazelle proven 0.29.0 or later its
    /// patch is consent evidence and no hook, and an `archive_override`
    /// is a bypass.
    #[test]
    fn a_go_repository_patch_is_a_hook_and_a_go_deps_patch_is_not() {
        const GOLANG: Ecosystem = Ecosystem::Golang;
        let crypto = "golang.org/x/crypto";
        let tool = "    patch_tool = \"patch\",\n    patch_args = [\"-p1\", \"--binary\"],\n";
        for (version, attrs) in [
            (Some("0.28.0"), ""),
            (Some("0.35.0"), ""),
            (Some("0.35.0"), tool),
            (None, ""),
        ] {
            let ws = go_repositories(version, attrs);
            let label = format!("{version:?} {attrs:?}");
            let [hub] = &ws.hubs[..] else {
                panic!("{label}: {:?}", ws.hubs);
            };
            assert_eq!(hub.ruleset, Ruleset::Gazelle, "{label}");
            let proven = hub.ruleset_version.at_least("0.29.0");
            assert_eq!(proven, version == Some("0.35.0"), "{label}");
            assert!(host_patch(hub), "{label}");
            let found = user_patch_hooks(&ws, &none, GOLANG, crypto, "v0.17.0");
            let [hook] = &found[..] else {
                panic!("{label}: {found:?}");
            };
            let subject = Subject::Package {
                name: crypto.to_string(),
                version: None,
            };
            assert_eq!(
                (&hook.subject, hook.replacement),
                (&subject, false),
                "{label}"
            );
            // Another module path, and another ecosystem, are not covered.
            assert!(user_patch_hooks(&ws, &none, GOLANG, "golang.org/x/net", "v0.17.0").is_empty());
            assert!(user_patch_hooks(&ws, &none, NPM, crypto, "v0.17.0").is_empty());
            assert!(bypasses(&ws, &none, HubId(0), crypto, "v0.17.0").is_empty());
        }

        let go_deps = |gazelle: &str| {
            let module = format!(
                "bazel_dep(name = \"gazelle\", version = \"{gazelle}\")\n\
                 go_deps = use_extension(\"@gazelle//:extensions.bzl\", \"go_deps\")\n\
                 go_deps.from_file(go_mod = \"//:go.mod\")\n\
                 go_deps.module_override(path = \"example.com/a\", patches = [\"//:a.patch\"])\n\
                 go_deps.archive_override(path = \"example.com/b\", urls = [\"https://example.com/b.zip\"])\n\
                 use_repo(go_deps, \"com_example_a\", \"com_example_b\")\n"
            );
            let go_mod = "module example.com/app\n\ngo 1.21\n";
            read(&[
                (".bazelversion", "8.8.2\n"),
                ("MODULE.bazel", &module),
                ("go.mod", go_mod),
            ])
        };
        let ws = go_deps("0.35.0");
        let [hub] = &ws.hubs[..] else {
            panic!("{:?}", ws.hubs);
        };
        assert!(hub.ruleset_version.at_least("0.29.0") && !host_patch(hub));
        let found = evidence(&ws, &none);
        let patched: Vec<&Evidence> = found
            .iter()
            .filter(|e| e.covers(GOLANG, "example.com/a", "v1.0.0"))
            .collect();
        let [patch] = &patched[..] else {
            panic!("{found:?}");
        };
        assert!(!patch.host_patch && !patch.replacement);
        assert!(user_patch_hooks(&ws, &none, GOLANG, "example.com/a", "v1.0.0").is_empty());
        assert!(bypasses(&ws, &none, HubId(0), "example.com/a", "v1.0.0").is_empty());
        let replaced = bypasses(&ws, &none, HubId(0), "example.com/b", "v1.0.0");
        let [bypass] = &replaced[..] else {
            panic!("{replaced:?}");
        };
        assert_eq!(bypass.token, "user_override");
        // A replacement is no patch hook, whatever the hub's patcher.
        assert!(user_patch_hooks(&ws, &none, GOLANG, "example.com/b", "v1.0.0").is_empty());

        // The override tags prove the release themselves
        // (`module_override` is of 0.31.0), whatever the `bazel_dep` says:
        // a `go_deps` hub with a patch is past 0.29.0.
        let old = go_deps("0.28.0");
        assert!(old.hubs[0].ruleset_version.at_least("0.29.0") && !host_patch(&old.hubs[0]));
        // Should a `go_deps` hub ever stand with no proven release, its
        // patch counts as a hook: unknown is not "native".
        let mut unproven = ws.hubs[0].clone();
        unproven.ruleset_version = VersionVerdict::unknown(Unproven::NotDeclared);
        assert!(host_patch(&unproven));
    }

    /// A pycross local wheel whose label is no wheel file name stands in
    /// for a package nobody can name: it is a replacement of every
    /// package of its hub. One named like a wheel covers its distribution.
    #[test]
    fn a_local_wheel_that_names_no_distribution_replaces_any_package() {
        const PYPI: Ecosystem = Ecosystem::Pypi;
        let pycross = |wheel: &str| {
            let module = format!(
                "module(name = \"socket_fixture\", version = \"0.0.0\")\n\n\
                 bazel_dep(name = \"rules_pycross\", version = \"2.0.1\")\n\
                 bazel_dep(name = \"rules_python\", version = \"2.0.0\")\n\n\
                 uv = use_extension(\"@rules_pycross//pycross/extensions:uv.bzl\", \"uv\")\n\
                 uv.workspace(\n    name = \"pypi\",\n    local_wheels = [\"{wheel}\"],\n    lock_file = \"//:uv.lock\",\n)\n\
                 uv.repo(\n    dependency_groups = [\"default\"],\n    workspace = \"pypi\",\n)\n\
                 use_repo(uv, \"pypi\")\n"
            );
            read(&[
                (".bazelversion", "9.3.2\n"),
                ("MODULE.bazel", &module),
                ("uv.lock", "version = 1\n"),
            ])
        };
        let replaced =
            |ws: &BazelWorkspace, name: &str| bypasses(ws, &none, HubId(0), name, "1.16.0").len();
        let label = pycross("@my_wheel//file");
        assert_eq!(label.hubs[0].ruleset, Ruleset::RulesPycross);
        assert_eq!(
            (replaced(&label, "six"), replaced(&label, "requests")),
            (1, 1)
        );
        // The bypass names the label, not a package it cannot know.
        let bypass = &bypasses(&label, &none, HubId(0), "six", "1.16.0")[0];
        assert_eq!(
            (bypass.token, bypass.what.as_str()),
            (
                "user_override",
                "MODULE.bazel: `@my_wheel//file` is no distribution name, so the package it is \
                 for is not known"
            )
        );
        let found = evidence(&label, &none);
        assert_eq!(
            every(&found, PYPI),
            ["`@my_wheel//file` is no distribution name, so the package it is for is not known"]
        );
        // A replacement is no patch hook, and it is of its own ecosystem.
        assert!(user_patch_hooks(&label, &none, PYPI, "six", "1.16.0").is_empty());
        assert!(found.iter().all(|e| !e.covers(NPM, "six", "1.16.0")));

        let wheel = pycross("//third_party:six-1.16.0-py2.py3-none-any.whl");
        assert_eq!(
            (replaced(&wheel, "six"), replaced(&wheel, "requests")),
            (1, 0)
        );
        assert_eq!(every(&evidence(&wheel, &none), PYPI), [""; 0]);
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

        // The ruleset used and no hub of the root read: its extension is
        // there, and all it imports is a hub of another module.
        let signal = read(&[(
            "MODULE.bazel",
            "bazel_dep(name = \"rules_jvm_external\", version = \"6.5\")\n\
             maven = use_extension(\"@rules_jvm_external//:extensions.bzl\", \"maven\")\n\
             use_repo(maven, \"kotlin_rules_maven\")\n",
        )]);
        let found = evidence(&signal, &none);
        assert_eq!(
            every(&found, Ecosystem::Maven),
            ["rules_jvm_external is used here and no hub was read"]
        );
        assert!(found.iter().all(|e| e.hub.is_none() && !e.replacement));
    }

    /// The whys of [`evidence`] for npm over a root module that depends
    /// on rules_js and declares `rest`.
    fn npm_whys(rest: &str) -> Vec<String> {
        let module = format!(
            "module(name = \"app\")\n\
             bazel_dep(name = \"aspect_rules_js\", version = \"2.8.3\", repo_name = \"js\")\n\
             bazel_dep(name = \"gazelle\", version = \"0.47.0\")\n{rest}"
        );
        let ws = read(&[(".bazelversion", "8.4.2\n"), ("MODULE.bazel", &module)]);
        assert!(ws.hubs.iter().all(|hub| hub.ecosystem != NPM), "{rest}");
        let found = evidence(&ws, &none);
        every(&found, NPM).into_iter().map(str::to_string).collect()
    }

    /// A `bazel_dep` on a ruleset is no hook. A hook is an argument of a
    /// tag or of a repository rule call, and in a module file that was
    /// read whole and uses no extension and no rule of the ruleset's
    /// module there is none: the root depends on the ruleset for its
    /// build rules (the `MODULE.bazel` of bazelisk and of buildtools do,
    /// on `aspect_rules_js`). Holding every npm package back there would
    /// name a declaration nobody can edit.
    #[test]
    fn a_bazel_dep_alone_in_a_module_file_read_whole_is_no_evidence() {
        let used = ["rules_js is used here and no hub was read"];
        assert_eq!(npm_whys(""), [""; 0]);
        // Extensions and rules of other modules, of the root and of
        // Bazel's own repositories are no use of rules_js.
        let others = "go_deps = use_extension(\"@gazelle//:extensions.bzl\", \"go_deps\")\n\
             go_deps.from_file(go_mod = \"//:go.mod\")\n\
             use_repo(go_deps, \"org_golang_x_term\")\n\
             own = use_extension(\"//:extensions.bzl\", \"own\")\n\
             use_repo(own, \"tools\")\n\
             http_archive = use_repo_rule(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n\
             http_archive(name = \"x\", urls = [\"https://example.com/x.zip\"])\n";
        assert_eq!(npm_whys(others), [""; 0]);
        // What was not read can hold no hook: imports, in a comprehension.
        let imports = format!("{others}[use_repo(own, name) for name in [\"a\", \"b\"]]\n");
        assert_eq!(npm_whys(&imports), [""; 0]);

        // A use of the ruleset's module, under the name the root gives it:
        // an extension that led to no hub, and a repository rule.
        let extension = "pnpm = use_extension(\"@js//npm:extensions.bzl\", \"pnpm\")\n\
             use_repo(pnpm, \"pnpm\")\n";
        assert_eq!(npm_whys(extension), used);
        let rule = "npm_import = use_repo_rule(\"@js//npm:repositories.bzl\", \"npm_import\")\n";
        assert_eq!(npm_whys(rule), used);
        // A canonical name, and a label Bazel rejects: whose file it is
        // is not known.
        for label in ["@@aspect_rules_js+//npm:extensions.bzl", "@js//npm::x"] {
            let unknown = format!("other = use_extension(\"{label}\", \"npm\")\n");
            assert_eq!(npm_whys(&unknown), used, "{label}");
        }
        // A statement that was not read may be the use: a label that is
        // computed, an extension bound inside an expression, a file that
        // is not there.
        for unread in [
            "other = use_extension(\"@{}//npm:extensions.bzl\".format(\"js\"), \"npm\")\n",
            "exts = [use_extension(\"@js//npm:extensions.bzl\", \"npm\")]\n",
            "include(\"//third_party:deps.MODULE.bazel\")\n",
        ] {
            assert_eq!(npm_whys(unread), used, "{unread}");
        }
    }

    /// A signal of a `WORKSPACE` file stays evidence whatever the file
    /// shows: the hub call may be in a macro nobody read.
    #[test]
    fn a_ruleset_a_workspace_file_fetches_with_no_hub_read_is_still_evidence() {
        let workspace = JS_WORKSPACE
            .strip_suffix("npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n")
            .expect("the hub call ends the fixture");
        let ws = read(&[(".bazelversion", "6.6.0\n"), ("WORKSPACE", workspace)]);
        assert!(ws.hubs.is_empty(), "{:?}", ws.hubs);
        let found = evidence(&ws, &none);
        assert_eq!(
            every(&found, NPM),
            ["rules_js is used here and no hub was read"]
        );
    }

    /// The whys and ecosystems of [`unread_statements`] over a module
    /// that declares the `npm` hub and `rest`.
    fn unread(bazel: &str, rest: &str) -> Vec<(Ecosystem, String)> {
        let module = format!(
            "module(name = \"app\")\n{JS}\
             npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n\
             use_repo(npm, \"npm\")\n{rest}"
        );
        let ws = read(&[
            (".bazelversion", bazel),
            ("MODULE.bazel", &module),
            ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
            ("requirements.txt", "requests==2.31.0 --hash=sha256:aaaa\n"),
        ]);
        let found = unread_statements(&ws);
        for e in &found {
            assert!(e.hub.is_none() && e.site.is_none() && !e.replacement && e.host_patch);
            assert_eq!(e.file, "MODULE.bazel");
            assert!(e.covers(e.ecosystem, "anything", "1.0.0"));
        }
        let why = |e: &Evidence| match &e.subject {
            Subject::Every {
                why,
                unreadable: false,
            } => why.clone(),
            other => panic!("{other:?}"),
        };
        found.iter().map(|e| (e.ecosystem, why(e))).collect()
    }

    /// A statement of the module file that was not read as what it
    /// declares belongs to no ruleset, so no recognizer reports it.
    /// Beside a hub it may be a second use of the same extension, with a
    /// tag nobody read: each of these shapes carried an
    /// `npm_replace_package` of `left-pad` past the consent gate. It
    /// protects the ecosystems the workspace has a hub of, as a
    /// declaration that is not literal (not as a broken file), and no
    /// ecosystem the workspace shows no use of.
    #[test]
    fn an_unread_statement_beside_a_hub_protects_the_ecosystem_of_the_hub() {
        let replace =
            ".npm_replace_package(package = \"left-pad@1.3.0\", replacement = \"//:left_pad\")\n";
        let extension = "use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")";
        let computed = "the label and name of `use_extension` is computed; write it as a literal";
        let inside =
            "`use_extension`: the name is used in a statement or expression that is not read";
        for (statement, why) in [
            (format!("exts = [{extension}]\nexts[0]{replace}"), inside),
            (format!("other = {extension} if True else None\nother{replace}"), inside),
            (
                format!("other = use_extension(\"@{{}}//npm:extensions.bzl\".format(\"aspect_rules_js\"), \"npm\")\nother{replace}"),
                computed,
            ),
            (
                format!("other = use_extension(\"@%s//npm:extensions.bzl\" % \"aspect_rules_js\", \"npm\")\nother{replace}"),
                computed,
            ),
            (
                "other = use_extension(\"@{}//npm:extensions.bzl\".format(\"aspect_rules_js\"), \"npm\")\n\
                 other.npm_translate_lock(name = \"npm2\", pnpm_lock = \"//:pnpm-lock.yaml\", \
                 patches = {\"left-pad@1.3.0\": [\"//:left-pad.patch\"]})\n\
                 use_repo(other, \"npm2\")\n"
                    .to_string(),
                computed,
            ),
        ] {
            let found = unread("8.4.2\n", &statement);
            let [(ecosystem, said)] = &found[..] else {
                panic!("{statement}: {found:?}");
            };
            assert_eq!(*ecosystem, NPM, "{statement}");
            assert_eq!(said, &format!("MODULE.bazel:6: {why}"), "{statement}");
        }

        // What was read adds nothing here: a literal tag is evidence of
        // its package, and a use of the proxy that was not read is the
        // recognizer's gap. Both are in `evidence`.
        assert_eq!(unread("8.4.2\n", &format!("npm{replace}")), []);
        assert_eq!(unread("8.4.2\n", &format!("n = npm\nn{replace}")), []);
        // Imports hide no tag, whatever was not read of them.
        let imports = "[use_repo(npm, name) for name in [\"a\", \"b\"]]\n";
        assert_eq!(unread("8.4.2\n", imports), []);

        // Each ecosystem with a hub, and no other.
        let pip = format!(
            "bazel_dep(name = \"rules_python\", version = \"1.4.1\")\n\
             bazel_dep(name = \"rules_jvm_external\", version = \"6.5\")\n\
             pip = use_extension(\"@rules_python//python/extensions:pip.bzl\", \"pip\")\n\
             pip.parse(hub_name = \"pypi\", python_version = \"3.11\", requirements_lock = \"//:requirements.txt\")\n\
             use_repo(pip, \"pypi\")\n\
             exts = [{extension}]\n"
        );
        let held: Vec<Ecosystem> = (unread("8.4.2\n", &pip).into_iter())
            .map(|(ecosystem, _)| ecosystem)
            .collect();
        assert_eq!(held, [NPM, Ecosystem::Pypi]);

        // Bazel 6 with a `WORKSPACE` file never reads the module file.
        let module = format!("{JS}exts = [{extension}]\n");
        let off = read(&[
            (".bazelversion", "6.6.0\n"),
            ("WORKSPACE", JS_WORKSPACE),
            ("MODULE.bazel", &module),
            ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
        ]);
        assert!(off.hubs.iter().any(|hub| hub.ecosystem == NPM));
        assert_eq!(unread_statements(&off), []);
    }

    /// A recognizer gap counts where Bazel may evaluate its statement,
    /// as `govern::governance` counts it: one in a `WORKSPACE` that Bazel
    /// 9 never opens declares nothing, and the same file on Bazel 6
    /// protects the ecosystem.
    #[test]
    fn a_gap_in_a_file_bazel_never_evaluates_is_no_evidence() {
        let workspace = format!(
            "{}npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\", patches = PATCHES)\n",
            JS_WORKSPACE
                .strip_suffix("npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n")
                .expect("the hub call ends the fixture")
        );
        let lock = ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
        let nine = read(&[
            (".bazelversion", "9.3.2\n"),
            ("MODULE.bazel", ""),
            ("WORKSPACE", &workspace),
            lock,
        ]);
        let gaps: Vec<(Ruleset, &str)> = (nine.ruleset_gaps.iter())
            .map(|(ruleset, gap)| (*ruleset, gap.file.as_str()))
            .collect();
        assert_eq!(gaps, [(Ruleset::RulesJs, "WORKSPACE")]);
        assert!(matches!(nine.hubs[0].liveness, Liveness::Dead { .. }));
        assert_eq!(evidence(&nine, &none), []);
        assert!(user_patch_hooks(&nine, &none, NPM, "anything", "1.0.0").is_empty());

        let six = read(&[
            (".bazelversion", "6.6.0\n"),
            ("WORKSPACE", &workspace),
            lock,
        ]);
        assert_eq!(six.ruleset_gaps.len(), 1);
        let found = evidence(&six, &none);
        let unread: Vec<&Evidence> = found.iter().filter(|e| e.hub.is_none()).collect();
        let [gap] = &unread[..] else {
            panic!("{found:?}");
        };
        assert_eq!((gap.ecosystem, gap.file.as_str()), (NPM, "WORKSPACE"));
        assert!(gap.host_patch && matches!(gap.subject, Subject::Every { .. }));
        assert!(!user_patch_hooks(&six, &none, NPM, "anything", "1.0.0").is_empty());
        assert!(user_patch_hooks(&six, &none, Ecosystem::Cargo, "anything", "1.0.0").is_empty());
    }

    /// The consent gate skips its walk for a run whose packages no
    /// declaration can protect, so the list has to hold every ecosystem
    /// evidence can come with: each one a ruleset with a hook builds, and
    /// neither of the two whose rulesets have none.
    #[test]
    fn the_ecosystems_are_the_ones_a_ruleset_with_a_hook_builds() {
        use Ecosystem::{Cargo, Gem, Golang, Maven, Npm, Nuget, Pypi};
        let found = ecosystems();
        for ecosystem in [Npm, Pypi, Cargo, Golang, Maven] {
            let count = found.iter().filter(|e| **e == ecosystem).count();
            assert_eq!(count, 1, "{ecosystem:?}: {found:?}");
        }
        assert_eq!(found.len(), 5, "{found:?}");
        assert!(!found.contains(&Gem) && !found.contains(&Nuget));
        // Evidence that names no hub comes from a signal of the ruleset:
        // its ecosystem is in the list, and one without a hook gives none.
        // (The ruleset beside a statement that was not read: a
        // `bazel_dep` alone is no evidence.)
        let signal = |dep: &str| {
            let module = format!(
                "bazel_dep(name = \"{dep}\", version = \"1.0.0\")\n\
                 include(\"//third_party:deps.MODULE.bazel\")\n"
            );
            let ws = read(&[("MODULE.bazel", &module)]);
            let found = evidence(&ws, &none);
            found.iter().map(|e| e.ecosystem).collect::<Vec<_>>()
        };
        assert_eq!(signal("rules_jvm_external"), [Maven]);
        assert_eq!(signal("rules_ruby"), []);
    }
}
