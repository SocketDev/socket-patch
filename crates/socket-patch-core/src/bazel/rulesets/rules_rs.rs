//! Recognizer: rules_rs hubs (design 2.7) and the versioned hub labels
//! the main repository uses.
//!
//! rules_rs is Bzlmod only. `crate.from_cargo(name, cargo_lock,
//! cargo_toml, cargo_config)`, a tag of the `crate` extension in
//! `//rs:extensions.bzl`, reads the `Cargo.lock` directly: there is no
//! splicing and no Bazel-specific lock (read at v0.0.26, v0.0.27 and
//! v0.2.2 `rs/extensions.bzl`).
//!
//! The hub aliases each crate twice, as `@<hub>//:<name>` and as
//! `@<hub>//:<name>-<version>`. A vendored pin retags the version, so the
//! second label stops existing and a BUILD file that names it fails with
//! `no such target` (probe R6 V5). A bounded scan of the main repository
//! therefore lists every versioned label of each hub. The gate that
//! refuses on one (`versioned_label_used`) is the lane's, as is the
//! answer to a scan that could not finish.

use super::rules_rust::{
    declare, hidden_hub, new_hub, not_literal, proxy_gaps, repo_bypasses, repo_of, scan_starlark,
    usages_of, user_decls, Args, LabelAttr,
};
use super::{RecognizeInput, Recognized};
use crate::bazel::model::{HubShape, LockRole, Ruleset, RulesetDetail, RulesetSignal};
use crate::bazel::module_file::ModuleModel;
use crate::crawlers::types::Ecosystem;

/// One `@<hub>//:<name>-<version>` in a BUILD or `.bzl` file. The scan is
/// over the bytes, comments included, and errs towards a hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedLabel {
    /// Root-relative.
    pub file: String,
    /// 1-based.
    pub line: usize,
    pub name: String,
    pub version: String,
}

/// What this recognizer records about one hub.
#[derive(Debug, Clone, PartialEq)]
pub struct RulesRsDetail {
    /// The name the tag gives the hub.
    pub hub_name: String,
    /// The names `use_repo` gives the hub in the root module: what a
    /// BUILD file writes after the `@`. Empty for a tag nothing imports.
    pub imported_as: Vec<String>,
    pub cargo_lock: LabelAttr,
    /// The manifest `cargo metadata` runs on. Cargo finds
    /// `.cargo/config.toml` by walking up from its directory, and a hosted
    /// pin fails the next evaluation without one there (probe R6 H4).
    pub cargo_toml: LabelAttr,
    /// The tag's `cargo_config`, else the `cargo_config_toml` of the
    /// root's `crate.config` tag, which applies to every hub without one.
    pub cargo_config: LabelAttr,
    /// Every versioned alias of this hub the main repository names.
    pub versioned_labels: Vec<VersionedLabel>,
    /// Where the label scan stopped short and why. `versioned_labels` is
    /// then a lower bound, and no label is ruled out.
    pub unscanned: Option<String>,
    /// The repository the root loads the ruleset by, as written.
    pub ruleset_repo: Option<String>,
}

const RULES_RS: &str = "rules_rs";

/// `<name>-<version>` split at the first `-` that a `major.minor.patch`
/// follows: a crate name has no `.`, so no name ends where a version
/// could start.
fn versioned(target: &str) -> Option<(&str, &str)> {
    let digits = |part: Option<&str>| {
        part.is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    };
    target.match_indices('-').find_map(|(at, _)| {
        let version = &target[at + 1..];
        let mut parts = version.splitn(3, '.');
        let release = digits(parts.next()) && digits(parts.next());
        let patch = parts
            .next()
            .is_some_and(|p| p.starts_with(|c: char| c.is_ascii_digit()));
        (at > 0 && release && patch).then(|| (&target[..at], version))
    })
}

/// The versioned aliases of `@<repo>//` that `text` names.
fn versioned_labels(file: &str, text: &[u8], repo: &str) -> Vec<VersionedLabel> {
    let needle = format!("@{repo}//:").into_bytes();
    let target = |b: &u8| b.is_ascii_alphanumeric() || b"-_.+".contains(b);
    let (mut found, mut at) = (Vec::new(), 0);
    while let Some(hit) = text[at..].windows(needle.len()).position(|w| w == needle) {
        let start = at + hit + needle.len();
        let len = text[start..].iter().take_while(|b| target(b)).count();
        let name = std::str::from_utf8(&text[start..start + len]).unwrap_or_default();
        if let Some((name, version)) = versioned(name) {
            found.push(VersionedLabel {
                file: file.to_string(),
                line: 1 + text[..start].iter().filter(|b| **b == b'\n').count(),
                name: name.to_string(),
                version: version.to_string(),
            });
        }
        at = start;
    }
    found
}

fn hubs(input: &RecognizeInput<'_>, module: &ModuleModel, usage: &[usize], out: &mut Recognized) {
    out.gaps.extend(proxy_gaps(module, usage));
    let tags = || module.tags.iter().filter(|tag| usage.contains(&tag.proxy));
    for tag in tags().filter(|tag| tag.call.callee == "from_cargo") {
        let resolve = |value| module.resolve(tag.at, value);
        let args = |call| Args {
            input,
            call,
            resolve: &resolve,
            package: Some(""),
        };
        let (mut decl, name, imported_as) = declare(module, usage, tag, &args(&tag.call));
        let own = args(&tag.call).label("cargo_config", LockRole::Config);
        // `crate.config` is the root's one global tag; a second one is
        // an error in Bazel, and here it leaves the config unknown.
        let mut global = tags().filter(|tag| tag.call.callee == "config");
        let cargo_config = match (own, global.next(), global.next()) {
            (LabelAttr::Absent, Some(config), None) => {
                args(&config.call).label("cargo_config_toml", LockRole::Config)
            }
            (LabelAttr::Absent, Some(_), Some(_)) => LabelAttr::Computed,
            (own, _, _) => own,
        };
        let label = module.proxies[tag.proxy].label.as_ref();
        let detail = RulesRsDetail {
            hub_name: name.clone(),
            imported_as,
            cargo_lock: args(&tag.call).label("cargo_lock", LockRole::PackageLock),
            cargo_toml: args(&tag.call).label("cargo_toml", LockRole::Config),
            cargo_config,
            versioned_labels: Vec::new(),
            unscanned: None,
            ruleset_repo: label.and_then(repo_of),
        };
        let attrs = [
            ("cargo_lock", &detail.cargo_lock),
            ("cargo_toml", &detail.cargo_toml),
            ("cargo_config", &detail.cargo_config),
        ];
        let unread = attrs.iter().filter(|(_, attr)| attr.unresolved());
        let mut unread: Vec<&str> = unread.map(|(name, _)| *name).collect();
        if !decl.literal {
            unread.insert(0, "name");
        }
        decl.literal = unread.is_empty();
        if !decl.literal {
            let gap = not_literal(&decl.site, tag.at.line, "crate.from_cargo", &unread);
            out.gaps.push(gap);
        }
        let locks = attrs.iter().filter_map(|(_, attr)| attr.lock()).collect();
        let detail = RulesetDetail::RulesRs(detail);
        let mut hub = new_hub(HubShape::RulesRsHub, Ecosystem::Cargo, detail, decl, locks);
        hub.user_decls = user_decls(module, usage, &name);
        hub.bypasses = repo_bypasses(module, usage, &name);
        out.hubs.push(hub);
    }
}

/// The hubs, signals and gaps of this ruleset in `input`.
pub fn recognize(input: &RecognizeInput<'_>) -> Recognized {
    let mut out = Recognized::default();
    let Some(module) = input.module else {
        return out;
    };
    let usages = usages_of(module, "rs", &["extensions.bzl"], "crate");
    for usage in &usages {
        hubs(input, module, usage, &mut out);
    }
    let mut details: Vec<&mut RulesRsDetail> = Vec::new();
    for hub in &mut out.hubs {
        if let RulesetDetail::RulesRs(detail) = &mut hub.detail {
            details.push(detail);
        }
    }
    // A hub nothing imports has no label a BUILD file could write, so a
    // root without an imported hub is not walked.
    if details.iter().any(|detail| !detail.imported_as.is_empty()) {
        let stopped = scan_starlark(input.files, &mut |path, bytes| {
            for detail in details.iter_mut() {
                for repo in &detail.imported_as {
                    let labels = versioned_labels(path, bytes, repo);
                    detail.versioned_labels.extend(labels);
                }
            }
        });
        let stopped = stopped.map(|stop| format!("{}: {}", stop.file, stop.why));
        for detail in details {
            detail.unscanned.clone_from(&stopped);
        }
    }
    if out.hubs.is_empty() {
        let site = hidden_hub(module, &usages, RULES_RS);
        out.signals.extend(site.map(|site| RulesetSignal {
            ruleset: Ruleset::RulesRs,
            site,
        }));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::rules_rust::testing::run;
    use super::super::rules_rust::LABEL_NOT_LITERAL;
    use super::*;
    use crate::bazel::model::{DeclSystem, Hub, LockRef};

    /// `heavy/rules_rs/bzlmod/e9/MODULE.bazel` without its toolchains.
    const HEAD: &str = "module(name = \"socket_fixture\", version = \"0.0.0\")\n\
        bazel_dep(name = \"rules_rs\", version = \"0.2.2\")\n\
        crate = use_extension(\"@rules_rs//rs:extensions.bzl\", \"crate\")\n";
    const HUB: &str =
        "crate.from_cargo(\n    name = \"crates\",\n    cargo_lock = \"//:Cargo.lock\",\n    \
        cargo_toml = \"//:Cargo.toml\",\n    platform_triples = [\"aarch64-apple-darwin\"],\n)\n";

    fn detail(hub: &Hub) -> &RulesRsDetail {
        match &hub.detail {
            RulesetDetail::RulesRs(detail) => detail,
            other => panic!("not a rules_rs hub: {other:?}"),
        }
    }

    fn lock(label: &str, path: &str, role: LockRole) -> LockRef {
        LockRef {
            label: label.to_string(),
            path: Some(path.to_string()),
            role,
        }
    }

    #[test]
    fn a_hub_is_read_with_its_lock_its_manifest_and_the_versioned_labels_that_name_it() {
        let module = format!("{HEAD}{HUB}use_repo(crate, \"crates\", vendored = \"crates\")\n");
        let build = "rust_binary(\n    name = \"app\",\n    deps = [\n        \"@crates//:cfg-if\",\n        \
                     \"@crates//:itoa-0.4.8\",\n        \"@vendored//:cfg-if-1.0.4+socket.6b7c8d9e\",\n    ],\n)\n";
        let found = run(
            recognize,
            &[
                ("MODULE.bazel", &module),
                ("BUILD.bazel", build),
                // Another hub's label, a prerelease, and a name with digits.
                (
                    "tools/defs.bzl",
                    "DEPS = [\"@other//:itoa-1.0.0\", \"@crates//:rand_core-0.9.0-rc.1\", \"@crates//:sha2\", \
                     \"@crates//:base64-url\"]\n",
                ),
            ],
        );
        assert!(found.gaps.is_empty() && found.signals.is_empty());
        let [hub] = &found.hubs[..] else {
            panic!("one hub: {:?}", found.hubs)
        };
        assert_eq!(
            (hub.ruleset, hub.shape, hub.ecosystem),
            (Ruleset::RulesRs, HubShape::RulesRsHub, Ecosystem::Cargo)
        );
        assert_eq!(
            (
                hub.decl.apparent_name.as_str(),
                hub.decl.literal,
                hub.decl.site.system
            ),
            ("crates", true, DeclSystem::Bzlmod)
        );
        let cargo_lock = lock("//:Cargo.lock", "Cargo.lock", LockRole::PackageLock);
        let cargo_toml = lock("//:Cargo.toml", "Cargo.toml", LockRole::Config);
        assert_eq!(hub.locks, [cargo_lock.clone(), cargo_toml.clone()]);
        let label = |file: &str, line, name: &str, version: &str| VersionedLabel {
            file: file.to_string(),
            line,
            name: name.to_string(),
            version: version.to_string(),
        };
        let expected = RulesRsDetail {
            hub_name: "crates".to_string(),
            imported_as: vec!["crates".to_string(), "vendored".to_string()],
            cargo_lock: LabelAttr::Label(cargo_lock),
            cargo_toml: LabelAttr::Label(cargo_toml),
            cargo_config: LabelAttr::Absent,
            versioned_labels: vec![
                label("BUILD.bazel", 5, "itoa", "0.4.8"),
                label("BUILD.bazel", 6, "cfg-if", "1.0.4+socket.6b7c8d9e"),
                label("tools/defs.bzl", 1, "rand_core", "0.9.0-rc.1"),
            ],
            unscanned: None,
            ruleset_repo: Some("rules_rs".to_string()),
        };
        assert_eq!(detail(hub), &expected);
    }

    #[test]
    fn a_versioned_alias_is_a_name_and_a_full_version() {
        for (target, expected) in [
            ("itoa-0.4.8", Some(("itoa", "0.4.8"))),
            ("cfg-if-1.0.4", Some(("cfg-if", "1.0.4"))),
            ("x86_64-0.15.2", Some(("x86_64", "0.15.2"))),
            ("foo-2-1.0.0-beta.1", Some(("foo-2", "1.0.0-beta.1"))),
            ("cfg-if", None),
            ("sha2", None),
            ("foo-2", None),
            ("foo-1.2", None),
            ("-1.0.0", None),
        ] {
            assert_eq!(versioned(target), expected, "{target}");
        }
    }

    #[test]
    fn the_cargo_config_is_the_tags_own_or_the_roots_global_one() {
        let global = "crate.config(cargo_config_toml = \"//:.cargo/config.toml\")\n";
        let own = HUB.replace(
            "name = \"crates\"",
            "name = \"own\", cargo_config = \"//:own.toml\"",
        );
        let found = run(
            recognize,
            &[("MODULE.bazel", &format!("{HEAD}{HUB}{own}{global}"))],
        );
        let [inherits, own] = &found.hubs[..] else {
            panic!("two hubs: {:?}", found.hubs)
        };
        assert_eq!(
            detail(inherits).cargo_config.path(),
            Some(".cargo/config.toml")
        );
        assert_eq!(detail(own).cargo_config.path(), Some("own.toml"));
        assert_eq!(inherits.locks.len(), 3);
        // Nothing imports either hub: no label to look for, so no walk.
        assert!(detail(own).imported_as.is_empty() && detail(own).unscanned.is_none());
        assert_eq!(inherits.decl.apparent_name, "crates");

        let twice = format!("{HEAD}{HUB}{global}{global}");
        let found = run(recognize, &[("MODULE.bazel", &twice)]);
        assert_eq!(detail(&found.hubs[0]).cargo_config, LabelAttr::Computed);
        assert!(!found.hubs[0].decl.literal);
    }

    #[test]
    fn a_computed_label_and_an_unfinished_scan_are_reported() {
        let module = format!(
            "{HEAD}crate.from_cargo(name = NAME, cargo_lock = LOCK, cargo_toml = \"//:Cargo.toml\")\n\
             {HUB}use_repo(crate, \"crates\")\n"
        );
        let found = run(
            recognize,
            &[
                ("MODULE.bazel", &module),
                ("BUILD", "x = \"@crates//:a-1.0.0\"\n"),
                ("locked/", ""),
            ],
        );
        let [computed, read] = &found.hubs[..] else {
            panic!("two hubs: {:?}", found.hubs)
        };
        assert!(!computed.decl.literal && read.decl.literal);
        assert_eq!(found.gaps.len(), 1);
        assert_eq!(found.gaps[0].token, LABEL_NOT_LITERAL);
        assert!(found.gaps[0].detail.starts_with(
            "MODULE.bazel:4: `crate.from_cargo`: name, cargo_lock cannot be followed;"
        ));
        // What was seen stays, and the scan says it is not everything.
        assert_eq!(detail(read).versioned_labels.len(), 1);
        let stopped = Some("locked: the directory cannot be listed".to_string());
        assert_eq!(detail(read).unscanned, stopped);
    }

    /// As for rules_rust: a signal only where a hub could hide. rules_rs
    /// is also a toolchain, so its `bazel_dep` alone declares no crates.
    #[test]
    fn a_signal_is_raised_only_where_a_hub_could_hide() {
        assert_eq!(
            run(recognize, &[("MODULE.bazel", HEAD)]),
            Recognized::default()
        );
        // rules_rust's `crate` extension is not this ruleset's.
        let other = "module(name = \"app\")\nbazel_dep(name = \"rules_rust\", version = \"0.75.0\")\n\
                     crate = use_extension(\"@rules_rust//crate_universe:extensions.bzl\", \"crate\")\n\
                     crate.from_cargo(name = \"crates\", cargo_lockfile = \"//:Cargo.lock\")\n";
        assert_eq!(
            run(recognize, &[("MODULE.bazel", other)]),
            Recognized::default()
        );
        assert_eq!(
            run(recognize, &[("WORKSPACE", "workspace(name = \"app\")\n")]),
            Recognized::default()
        );

        let hidden = format!("{HEAD}[crate.from_cargo(name = n) for n in [\"a\"]]\n");
        let found = run(recognize, &[("MODULE.bazel", &hidden)]);
        assert!(found.hubs.is_empty());
        assert_eq!(found.gaps[0].token, LABEL_NOT_LITERAL);
        let [signal] = &found.signals[..] else {
            panic!("one signal: {found:?}")
        };
        assert_eq!(
            (signal.ruleset, signal.site.file.as_str()),
            (Ruleset::RulesRs, "MODULE.bazel")
        );
    }
}
