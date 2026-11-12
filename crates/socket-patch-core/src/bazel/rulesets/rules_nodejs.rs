//! Recognizer: legacy `npm_install` and `yarn_install` of
//! `build_bazel_rules_nodejs` (design 2.7; row 5 of 4.2).
//!
//! These rules exist up to rules_nodejs 5.8.5 and only in a `WORKSPACE`.
//! They run the real npm or yarn inside an external repository on the
//! lock the rule names, so the lock is what Bazel builds from. No lane
//! serves them in the default set: the hub is recorded so that the lock
//! is never taken for one Bazel does not read, and so that the refusal
//! can name the rule.
//!
//! The `rules_nodejs` Bazel module of today is the Node.js toolchain and
//! declares no hub; it is not a signal of this ruleset.

use super::rules_js::{hub, signals, Decl, Lit, WsRuleset};
use super::{RecognizeInput, Recognized};
use crate::bazel::model::{Hub, HubShape, LockRole, Ruleset, RulesetDetail};

/// The repository name the ruleset is declared under.
const REPOS: [&str; 1] = ["build_bazel_rules_nodejs"];

/// The rules and the setup functions of a `WORKSPACE`, read at 5.8.5
/// (`index.bzl`, `repositories.bzl`): the dependencies are `rules_nodejs`
/// and `bazel_skylib`, the toolchains `nodejs*`, and `yarn_install`
/// declares `yarn` when no repository of that name exists.
const WORKSPACE: WsRuleset = WsRuleset {
    rules: &[("index.bzl", "npm_install"), ("index.bzl", "yarn_install")],
    hubs: &["npm_install", "yarn_install"],
    setup: &[
        ("repositories.bzl", "build_bazel_rules_nodejs_dependencies"),
        ("index.bzl", "node_repositories"),
        ("index.bzl", "yarn_repositories"),
        ("nodejs/repositories.bzl", "nodejs_register_toolchains"),
    ],
    stems: &["rules", "bazel", "nodejs", "yarn"],
};

/// Which package manager the rule runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallRule {
    /// `npm ci` over `package_lock_json`.
    NpmInstall,
    /// `yarn install --frozen-lockfile` over `yarn_lock`.
    YarnInstall,
}

/// What this recognizer records about one hub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesNodejsDetail {
    pub rule: InstallRule,
    /// The repository name of the hub; `None` when it is computed.
    pub repo: Option<String>,
    /// The repository name the rule's `load` uses.
    pub load_repo: Option<String>,
    /// `symlink_node_modules = True` runs the package manager in the
    /// source tree instead of an external repository.
    pub symlink_node_modules: Lit<bool>,
    /// The labels of `pre_install_patches` and `post_install_patches`:
    /// the user's own patches, which the rule applies with the host
    /// `patch` tool to whatever package they touch.
    pub install_patches: Vec<String>,
}

fn install(decl: &Decl<'_>, symbol: &str, load_repo: Option<String>) -> Hub {
    let (rule, lock) = match symbol {
        "yarn_install" => (InstallRule::YarnInstall, "yarn_lock"),
        _ => (InstallRule::NpmInstall, "package_lock_json"),
    };
    // Both rules require `name`, their lock and `package_json`: one that
    // is not passed is not read, and leaves the hub incomplete.
    let repo = match decl.string("name") {
        Lit::Is(name) => Some(name),
        Lit::Absent => {
            decl.note("name");
            None
        }
        Lit::Dynamic => None,
    };
    let mut locks = Vec::new();
    for (attr, role) in [
        (lock, LockRole::PackageLock),
        ("package_json", LockRole::Config),
    ] {
        match decl.label(attr, role) {
            Some(named) => locks.push(named),
            None => decl.note(attr),
        }
    }
    locks.extend(decl.labels("data", LockRole::Config));
    let patches = ["pre_install_patches", "post_install_patches"];
    let patches = patches.map(|attr| match decl.strings(attr) {
        Lit::Is(labels) => labels,
        Lit::Absent | Lit::Dynamic => Vec::new(),
    });
    let detail = RulesNodejsDetail {
        rule,
        repo: repo.clone(),
        load_repo,
        symlink_node_modules: decl.boolean("symlink_node_modules"),
        install_patches: patches.concat(),
    };
    let detail = RulesetDetail::RulesNodejs(detail);
    let name = repo.unwrap_or_default();
    hub(HubShape::NodeInstall, decl, name, detail, locks)
}

/// The hubs, signals and gaps of this ruleset in `input`.
pub fn recognize(input: &RecognizeInput<'_>) -> Recognized {
    let mut out = Recognized::default();
    for model in input.workspace_files {
        for site in WORKSPACE.hub_sites(model, &mut out.gaps) {
            let hub = install(&site.decl, site.symbol, site.load_repo.clone());
            out.gaps.extend(site.decl.gap(site.symbol));
            out.hubs.push(hub);
        }
    }
    out.signals = signals(Ruleset::RulesNodejs, input, &REPOS, &WORKSPACE, &out.hubs);
    out
}

#[cfg(test)]
mod tests {
    use super::super::rules_js::tests::{root, run};
    use super::*;
    use crate::bazel::model::{DeclSystem, LockRef};
    use crate::crawlers::types::Ecosystem;

    /// The `WORKSPACE` of probe J4's legacy cell (rules_nodejs 5.8.5 on
    /// Bazel 6.6.0), up to the rule.
    const SETUP: &str = "workspace(name = \"legacy\")\n\
        load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n\
        http_archive(name = \"build_bazel_rules_nodejs\", urls = [\"https://example.com/rules_nodejs-5.8.5.tar.gz\"])\n\
        load(\"@build_bazel_rules_nodejs//:repositories.bzl\", \"build_bazel_rules_nodejs_dependencies\")\n\
        build_bazel_rules_nodejs_dependencies()\n\
        load(\"@build_bazel_rules_nodejs//:index.bzl\", \"node_repositories\", \"npm_install\", \"yarn_install\")\n\
        node_repositories()\n";

    fn detail(hub: &Hub) -> &RulesNodejsDetail {
        match &hub.detail {
            RulesetDetail::RulesNodejs(detail) => detail,
            other => panic!("not a rules_nodejs hub: {other:?}"),
        }
    }

    fn lock_ref(label: &str, path: &str, role: LockRole) -> LockRef {
        LockRef {
            label: label.to_string(),
            path: Some(path.to_string()),
            role,
        }
    }

    #[test]
    fn npm_install_and_yarn_install_name_the_lock_bazel_installs_from() {
        let text = format!(
            "{SETUP}npm_install(\n    name = \"npm\",\n    package_json = \"//:package.json\",\n    \
             package_lock_json = \"//:package-lock.json\",\n)\n\
             yarn_install(\n    name = \"web_deps\",\n    package_json = \"//web:package.json\",\n    \
             yarn_lock = \"//web:yarn.lock\",\n    data = [\"//web:.yarnrc\"],\n    \
             symlink_node_modules = True,\n    post_install_patches = [\"//web:fix.patch\"],\n)\n"
        );
        let found = run(&root(&[("WORKSPACE", &text)]), recognize);
        assert_eq!((found.gaps.as_slice(), found.signals.len()), (&[][..], 0));
        let [npm, yarn] = found.hubs.as_slice() else {
            panic!("{} hubs", found.hubs.len());
        };
        for hub in [npm, yarn] {
            assert_eq!(
                (hub.ruleset, hub.shape, hub.ecosystem),
                (Ruleset::RulesNodejs, HubShape::NodeInstall, Ecosystem::Npm)
            );
            assert!(hub.decl.literal);
            assert_eq!(hub.decl.site.system, DeclSystem::Workspace);
            assert_eq!(
                detail(hub).load_repo.as_deref(),
                Some("build_bazel_rules_nodejs")
            );
        }
        assert_eq!(npm.decl.apparent_name, "npm");
        assert_eq!(
            npm.locks,
            [
                lock_ref(
                    "//:package-lock.json",
                    "package-lock.json",
                    LockRole::PackageLock
                ),
                lock_ref("//:package.json", "package.json", LockRole::Config),
            ]
        );
        let want = RulesNodejsDetail {
            rule: InstallRule::NpmInstall,
            repo: Some("npm".to_string()),
            load_repo: Some("build_bazel_rules_nodejs".to_string()),
            symlink_node_modules: Lit::Absent,
            install_patches: Vec::new(),
        };
        assert_eq!(detail(npm), &want);
        assert_eq!(
            yarn.locks,
            [
                lock_ref("//web:yarn.lock", "web/yarn.lock", LockRole::PackageLock),
                lock_ref("//web:package.json", "web/package.json", LockRole::Config),
                lock_ref("//web:.yarnrc", "web/.yarnrc", LockRole::Config),
            ]
        );
        let found = detail(yarn);
        assert_eq!(
            (found.rule, found.symlink_node_modules.clone()),
            (InstallRule::YarnInstall, Lit::Is(true))
        );
        assert_eq!(found.install_patches, ["//web:fix.patch"]);
    }

    /// Both rules require their lock. One that is missing, computed, or
    /// relative (a `WORKSPACE` rule lives in `//external`) names no file.
    #[test]
    fn a_lock_that_is_not_read_leaves_the_hub_incomplete() {
        for (attrs, unread) in [
            ("name = \"npm\", package_json = \"//:package.json\"", "`package_lock_json`"),
            ("name = \"npm\", package_json = \"//:package.json\", package_lock_json = LOCK", "`package_lock_json`"),
            ("name = \"npm\", package_json = \"//:package.json\", package_lock_json = \":package-lock.json\"", "`package_lock_json`"),
            ("name = \"npm\", package_lock_json = \"//:package-lock.json\"", "`package_json`"),
            ("package_json = \"//:package.json\", package_lock_json = \"//:package-lock.json\"", "`name`"),
            ("name = \"npm\", **ARGS", "`data`"),
        ] {
            let text = format!("{SETUP}npm_install({attrs})\n");
            let found = run(&root(&[("WORKSPACE", &text)]), recognize);
            let [hub] = found.hubs.as_slice() else {
                panic!("{attrs}: {} hubs", found.hubs.len());
            };
            assert!(!hub.decl.literal, "{attrs}");
            let [gap] = found.gaps.as_slice() else {
                panic!("{attrs}: {:?}", found.gaps);
            };
            assert_eq!(gap.token, "label_not_literal", "{attrs}");
            assert!(gap.detail.contains(unread), "{attrs}: {}", gap.detail);
            assert!(gap.detail.contains("of `npm_install`"), "{}", gap.detail);
        }
    }

    /// The rule is loaded and no call of it was resolved: a signal. The
    /// `rules_nodejs` module of today is only the Node.js toolchain.
    #[test]
    fn the_legacy_ruleset_with_no_hub_is_a_signal_and_the_toolchain_module_is_none() {
        let found = run(&root(&[("WORKSPACE", SETUP)]), recognize);
        assert!(found.hubs.is_empty() && found.gaps.is_empty());
        assert_eq!(found.signals.len(), 1);
        assert_eq!(found.signals[0].ruleset, Ruleset::RulesNodejs);

        let toolchain =
            "load(\"@rules_nodejs//nodejs:repositories.bzl\", \"nodejs_register_toolchains\")\n\
                         nodejs_register_toolchains(name = \"nodejs\")\n";
        let module = "bazel_dep(name = \"rules_nodejs\", version = \"6.3.0\")\n";
        let found = run(
            &root(&[("WORKSPACE", toolchain), ("MODULE.bazel", module)]),
            recognize,
        );
        assert_eq!(found, Recognized::default());
    }
}
