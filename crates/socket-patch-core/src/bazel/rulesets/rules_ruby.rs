//! Recognizer: rules_ruby `bundle_fetch` hubs and the legacy bundle rules
//! (design 2.7, HZ-14).
//!
//! `ruby.bundle_fetch` (Bzlmod) and `rb_bundle_fetch` (`WORKSPACE`, up to
//! 0.29.0) copy the `gemfile` and `gemfile_lock` they name and download
//! every gem of the lock from its section's `remote`. A gem is checked
//! against a digest only when the `gem_checksums` dict of the declaration
//! has its `<name>-<version>` key. So the dict decides two things a lane
//! needs: a key that is there must change with the pin, or a cold build
//! fails and a warm one serves the upstream gem (probe U1); and only a
//! gem with a key is fetched fail-closed, which is the one case a tamper
//! test can be claimed for. Each value is recorded with the span a lane
//! would replace.
//!
//! The legacy `rb_bundle` and the bazelruby `ruby_bundle` run Bundler
//! itself and have no lane in the default set; they are recorded so that
//! their lock is not taken for one Bazel does not read.

use super::rules_js::{hub, signals, usages, Decl, Lit, WsRuleset};
use super::{RecognizeInput, Recognized};
use crate::bazel::derived::DerivedState;
use crate::bazel::model::{Hub, HubShape, LockRef, LockRole, Ruleset, RulesetDetail};
use crate::bazel::starlark::{Value, ValueKind};

/// The module name of the ruleset. bazelruby has no Bazel module.
const MODULES: [&str; 1] = ["rules_ruby"];

/// The repository names the two rulesets are declared under in a
/// `WORKSPACE`.
const REPOS: [&str; 2] = ["rules_ruby", "bazelruby_rules_ruby"];

/// The file of the `ruby` extension, inside the ruleset.
const EXTENSIONS_BZL: &str = "ruby/extensions.bzl";

/// The `ruby` extension as `MODULE.bazel.lock` names it: the label of its
/// file without a repository, and its name. Where the lock records the
/// extension (rules_ruby 0.16.0 on Bazel 6.6.0 and 7.0.2), its entry
/// holds the `gemfile` and `gemfile_lock` labels and the `gem_checksums`
/// dict of each tag, so an edit of the dict stales it (probe B2).
pub const EXTENSION: (&str, &str) = ("//ruby:extensions.bzl", "ruby");

/// The rules and setup functions of a `WORKSPACE`. rules_ruby, read at
/// v0.21.1 and v0.29.0 `ruby/deps.bzl`: `rb_register_toolchains` declares
/// `<name>` and `<name>_toolchains`, `ruby` unless it is told otherwise.
/// bazelruby, read at v0.6.0 `ruby/private`: `rules_ruby_dependencies`
/// declares `bazel_skylib` and `rules_pkg`, `rules_ruby_select_sdk`
/// declares `org_ruby_lang_ruby_toolchain`; its README has every
/// `WORKSPACE` call `bazel_skylib_workspace`, which registers a toolchain
/// and declares nothing.
const WORKSPACE: WsRuleset = WsRuleset {
    rules: &[
        ("ruby/deps.bzl", "rb_bundle_fetch"),
        ("ruby/deps.bzl", "rb_bundle"),
        ("ruby/deps.bzl", "rb_bundle_rule"),
        ("ruby/defs.bzl", "ruby_bundle"),
    ],
    hubs: &[
        "rb_bundle_fetch",
        "rb_bundle",
        "rb_bundle_rule",
        "ruby_bundle",
    ],
    setup: &[
        ("ruby/deps.bzl", "rb_register_toolchains"),
        ("ruby/deps.bzl", "rules_ruby_dependencies"),
        ("ruby/deps.bzl", "rules_ruby_select_sdk"),
        ("workspace.bzl", "bazel_skylib_workspace"),
    ],
    stems: &["ruby", "rules", "bazel", "org_ruby_lang_ruby_toolchain"],
};

/// The rule that declares a hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleRule {
    /// The `ruby.bundle_fetch` tag.
    BundleFetch,
    /// `rb_bundle_fetch` in a `WORKSPACE`.
    RbBundleFetch,
    /// rules_ruby `rb_bundle`, and the `ruby.bundle` tag that declares
    /// one (deprecated since 0.5.0, removed in 1.0): `bundle install` in
    /// the directory of the `Gemfile`.
    RbBundle,
    /// bazelruby `ruby_bundle`.
    RubyBundle,
}

/// One entry of a literal `gem_checksums` dict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GemChecksum {
    /// `<name>-<version>`, with the platform suffix of a platform gem.
    /// `None` when the key is computed: the dict may then hold any gem.
    pub key: Option<String>,
    /// The SHA-256 as written; `None` when the value is no string.
    pub value: Option<String>,
    /// The bytes between the quotes of the value: what a lane replaces.
    /// `None` when the value is not one plain string literal.
    pub inner: Option<(usize, usize)>,
    /// The whole value expression.
    pub span: (usize, usize),
}

/// The `gem_checksums` of a hub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GemChecksums {
    /// Not passed: every gem is downloaded with no digest of the rule's
    /// own, and only a `CHECKSUMS` section in the lock anchors a pin.
    Absent,
    /// Passed and not a dict literal: whether it holds a gem cannot be
    /// read, and no value can be replaced.
    Dynamic,
    /// A dict literal in `file` (relative to the Bazel root): the
    /// declaration's own file, also when the dict is a constant of it.
    Literal {
        file: String,
        entries: Vec<GemChecksum>,
    },
}

/// What a `gem_checksums` dict says about one gem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GemEntry<'a> {
    /// The dict has no key of the gem: it is not passed, or it is a
    /// literal whose keys were all read. rules_ruby then checks the gem
    /// against no digest of its own, and a lane leaves the dict as it is.
    Absent,
    /// Whether the dict holds the gem cannot be read: it is not a dict
    /// literal, or one of its keys is computed and may be the gem's. It is
    /// not absent: a value that is there and is left as it was fails a
    /// cold build and serves the upstream gem from a warm one (HZ-14).
    Unknown,
    Found(&'a GemChecksum),
}

impl GemChecksums {
    /// What the dict says about the gem `key` (`<name>-<version>`).
    pub fn entry(&self, key: &str) -> GemEntry<'_> {
        let entries = match self {
            Self::Absent => return GemEntry::Absent,
            Self::Dynamic => return GemEntry::Unknown,
            Self::Literal { entries, .. } => entries,
        };
        let named = |entry: &&GemChecksum| entry.key.as_deref() == Some(key);
        match entries.iter().find(named) {
            Some(entry) => GemEntry::Found(entry),
            None if entries.iter().any(|entry| entry.key.is_none()) => GemEntry::Unknown,
            None => GemEntry::Absent,
        }
    }
}

/// What this recognizer records about one hub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesRubyDetail {
    pub rule: BundleRule,
    /// The repository name of the hub: inside the extension, or in the
    /// `WORKSPACE`. `None` when it is computed.
    pub repo: Option<String>,
    /// Bzlmod: the module that hosts the extension (`rules_ruby`); `None`
    /// when nothing says which ruleset version runs.
    pub module: Option<String>,
    /// `WORKSPACE`: the repository name the rule's `load` uses.
    pub load_repo: Option<String>,
    /// Bzlmod: the `use_repo` names of the hub; empty when no `use_repo`
    /// imports it.
    pub imports: Vec<String>,
    /// `--ignore_dev_dependency` drops the hub.
    pub dev: bool,
    pub gem_checksums: GemChecksums,
}

fn checksums(decl: &Decl<'_>) -> GemChecksums {
    let dict = decl.peek("gem_checksums", |value| match &value.kind {
        ValueKind::Dict(entries) => Some(entries.as_slice()),
        _ => None,
    });
    let entries = match dict {
        Lit::Absent => return GemChecksums::Absent,
        Lit::Dynamic => return GemChecksums::Dynamic,
        Lit::Is(entries) => entries,
    };
    let entry = |(key, value): &(Value, Value)| GemChecksum {
        key: key.as_str().map(String::from),
        value: value.as_str().map(String::from),
        inner: match &value.kind {
            ValueKind::Str { inner, .. } => *inner,
            _ => None,
        },
        span: value.span,
    };
    GemChecksums::Literal {
        file: decl.site.file.clone(),
        entries: entries.iter().map(entry).collect(),
    }
}

/// The hub of one bundle declaration. `detail` arrives with what only its
/// dependency system knows.
fn bundle(decl: &Decl<'_>, mut detail: RulesRubyDetail) -> Hub {
    detail.repo = match decl.string("name") {
        Lit::Is(name) => Some(name),
        Lit::Absent => {
            decl.note("name");
            None
        }
        Lit::Dynamic => None,
    };
    let gemfile = decl.label("gemfile", LockRole::Config);
    let mut lock = decl.label("gemfile_lock", LockRole::PackageLock);
    let legacy = matches!(detail.rule, BundleRule::RbBundle | BundleRule::RubyBundle);
    if gemfile.is_none() {
        decl.note("gemfile");
    }
    match (&lock, &gemfile) {
        // The legacy rules run Bundler beside the `Gemfile`, which reads
        // and writes the lock next to it.
        (None, Some(gemfile)) if legacy => {
            lock = Some(LockRef {
                label: format!("{}.lock", gemfile.label),
                path: gemfile.path.as_ref().map(|path| format!("{path}.lock")),
                role: LockRole::PackageLock,
            });
        }
        (None, _) if !legacy => decl.note("gemfile_lock"),
        _ => {}
    }
    detail.gem_checksums = checksums(decl);

    let lock_path = lock.as_ref().and_then(|lock| lock.path.clone());
    let mut locks: Vec<LockRef> = lock.into_iter().chain(gemfile).collect();
    locks.extend(decl.labels("srcs", LockRole::Config));
    let mut derived = Vec::new();
    if let GemChecksums::Literal { file, entries } = &detail.gem_checksums {
        locks.push(LockRef {
            label: format!("//:{file}"),
            path: Some(file.clone()),
            role: LockRole::ChecksumAttr,
        });
        if let Some(input) = lock_path {
            let keys = entries.iter().filter_map(|entry| entry.key.clone());
            derived.extend(keys.map(|key| DerivedState::ChecksumValue {
                file: file.clone(),
                key,
                input: input.clone(),
            }));
        }
    }
    let shape = match legacy {
        true => HubShape::LegacyBundle,
        false => HubShape::BundleFetch,
    };
    let name = detail.imports.first().or(detail.repo.as_ref()).cloned();
    let detail = RulesetDetail::RulesRuby(detail);
    let mut hub = hub(shape, decl, name.unwrap_or_default(), detail, locks);
    hub.derived = derived;
    hub
}

/// The hubs, signals and gaps of this ruleset in `input`.
pub fn recognize(input: &RecognizeInput<'_>) -> Recognized {
    let mut out = Recognized::default();
    let detail = |rule| RulesRubyDetail {
        rule,
        repo: None,
        module: None,
        load_repo: None,
        imports: Vec::new(),
        dev: false,
        gem_checksums: GemChecksums::Absent,
    };
    if let Some(module) = input.module {
        // `rb_bundle_fetch` is a repository rule `use_repo_rule` can bind
        // (`rules_ruby@v0.29.0:ruby/deps.bzl`): a hub no tag declares.
        WORKSPACE.module_rule_gaps(module, &mut out.gaps);
        for usage in usages(module, EXTENSIONS_BZL, EXTENSION.1, &MODULES) {
            usage.gaps(&mut out.gaps);
            let tags = [
                ("bundle_fetch", BundleRule::BundleFetch),
                ("bundle", BundleRule::RbBundle),
            ];
            for (name, rule) in tags {
                for tag in usage.tags(name) {
                    let repo = tag.peek("name", |name| name.as_str());
                    let repo = match repo {
                        Lit::Is(repo) => repo,
                        Lit::Absent | Lit::Dynamic => "",
                    };
                    let (imports, dev) = usage.imported(repo, tag.dev);
                    let detail = RulesRubyDetail {
                        module: usage.host.map(String::from),
                        imports,
                        dev,
                        ..detail(rule)
                    };
                    let mut hub = bundle(&tag, detail);
                    hub.bypasses = usage.bypasses(|name| !repo.is_empty() && name == repo);
                    out.gaps.extend(tag.gap(&format!("ruby.{name}")));
                    out.hubs.push(hub);
                }
            }
        }
    }
    for model in input.workspace_files {
        for site in WORKSPACE.hub_sites(model, input.files, &mut out.gaps) {
            let rule = match site.symbol {
                "rb_bundle_fetch" => BundleRule::RbBundleFetch,
                "ruby_bundle" => BundleRule::RubyBundle,
                _ => BundleRule::RbBundle,
            };
            let detail = RulesRubyDetail {
                load_repo: site.load_repo.clone(),
                ..detail(rule)
            };
            out.hubs.push(bundle(&site.decl, detail));
            out.gaps.extend(site.decl.gap(site.symbol));
        }
    }
    out.signals = signals(Ruleset::RulesRuby, input, &REPOS, &WORKSPACE, &out.hubs);
    out
}

#[cfg(test)]
mod tests {
    use super::super::rules_js::tests::{fixtures, root, run};
    use super::*;
    use crate::bazel::model::{DeclSystem, Liveness};
    use crate::crawlers::types::Ecosystem;

    const VICTIM: &str = "8d0b87effed74620f9b1b7a9dff03f2fb376f74d9fbc9540a7d7ced335052c70";

    /// A root module with one `bundle_fetch` hub; `attrs` go into the tag
    /// and `before` precedes it.
    fn module(before: &str, attrs: &str) -> String {
        format!(
            "bazel_dep(name = \"rules_ruby\", version = \"1.0.0-rc2\")\n{before}\
             ruby = use_extension(\"@rules_ruby//ruby:extensions.bzl\", \"ruby\")\n\
             ruby.toolchain(name = \"ruby\", version = \"3.4.10\")\n\
             ruby.bundle_fetch(\n    name = \"bundle\",\n    gemfile = \"//:Gemfile\",\n    \
             gemfile_lock = \"//:Gemfile.lock\",{attrs}\n)\n\
             use_repo(ruby, \"bundle\", \"ruby\", \"ruby_toolchains\")\n"
        )
    }

    fn detail(hub: &Hub) -> &RulesRubyDetail {
        match &hub.detail {
            RulesetDetail::RulesRuby(detail) => detail,
            other => panic!("not a rules_ruby hub: {other:?}"),
        }
    }

    /// The one hub of a root that declares exactly one and is read in
    /// full.
    fn hub_of(files: &[(&str, &str)]) -> Hub {
        let found = run(&root(files), recognize);
        assert_eq!((found.gaps.as_slice(), found.signals.len()), (&[][..], 0));
        let [hub] = found.hubs.as_slice() else {
            panic!("{} hubs", found.hubs.len());
        };
        assert!(hub.decl.literal);
        hub.clone()
    }

    fn lock_ref(label: &str, path: &str, role: LockRole) -> LockRef {
        LockRef {
            label: label.to_string(),
            path: Some(path.to_string()),
            role,
        }
    }

    /// The entry of the gem `key` in a dict that holds it.
    fn entry_of<'a>(sums: &'a GemChecksums, key: &str) -> &'a GemChecksum {
        match sums.entry(key) {
            GemEntry::Found(entry) => entry,
            other => panic!("no entry of {key}: {other:?}"),
        }
    }

    /// The dict decides what a lane must edit with the pin: each key is a
    /// derived value of the lock, and each value is found where a lane
    /// would replace it.
    #[test]
    fn a_literal_gem_checksums_dict_is_recorded_value_by_value() {
        let attrs = format!(
            "\n    gem_checksums = {{\n        \"sp-other-1.0.0\": \"{}\",\n        \
             \"sp-victim-1.0.0\": \"{VICTIM}\",\n    }},",
            "2a".repeat(32)
        );
        let text = module("", &attrs);
        let hub = hub_of(&[("MODULE.bazel", &text)]);
        assert_eq!(
            (hub.ruleset, hub.shape, hub.ecosystem),
            (Ruleset::RulesRuby, HubShape::BundleFetch, Ecosystem::Gem)
        );
        assert_eq!(
            hub.locks,
            [
                lock_ref("//:Gemfile.lock", "Gemfile.lock", LockRole::PackageLock),
                lock_ref("//:Gemfile", "Gemfile", LockRole::Config),
                lock_ref("//:MODULE.bazel", "MODULE.bazel", LockRole::ChecksumAttr),
            ]
        );
        let found = detail(&hub);
        assert_eq!(
            (found.rule, found.repo.as_deref()),
            (BundleRule::BundleFetch, Some("bundle"))
        );
        assert_eq!(
            (found.module.as_deref(), found.load_repo.as_deref()),
            (Some("rules_ruby"), None)
        );
        assert_eq!(
            (found.imports.as_slice(), found.dev),
            (&["bundle".to_string()][..], false)
        );
        let GemChecksums::Literal { file, entries } = &found.gem_checksums else {
            panic!("{:?}", found.gem_checksums);
        };
        assert_eq!((file.as_str(), entries.len()), ("MODULE.bazel", 2));
        let victim = entry_of(&found.gem_checksums, "sp-victim-1.0.0");
        assert_eq!(victim.value.as_deref(), Some(VICTIM));
        let (start, end) = victim.inner.expect("a plain string literal");
        assert_eq!(&text[start..end], VICTIM);
        assert_eq!(&text[victim.span.0..victim.span.1], format!("\"{VICTIM}\""));
        // Every key was read and none is this gem's: it has no entry.
        assert_eq!(
            found.gem_checksums.entry("sp-victim-1.0.1"),
            GemEntry::Absent
        );

        let stale = |key: &str| DerivedState::ChecksumValue {
            file: "MODULE.bazel".to_string(),
            key: key.to_string(),
            input: "Gemfile.lock".to_string(),
        };
        assert_eq!(
            hub.derived,
            [stale("sp-other-1.0.0"), stale("sp-victim-1.0.0")]
        );
        assert!(matches!(hub.liveness, Liveness::Dead { .. }));
        assert!(!hub.ruleset_version.at_least("0.0.1"));
    }

    /// Without the dict rules_ruby checks no gem against a digest of its
    /// own (probe U1): nothing is derived, and no tamper test can be
    /// claimed.
    #[test]
    fn a_hub_without_gem_checksums_has_no_derived_value() {
        let hub = hub_of(&[("MODULE.bazel", &module("", ""))]);
        assert_eq!(detail(&hub).gem_checksums, GemChecksums::Absent);
        assert!(hub.derived.is_empty());
        assert_eq!(hub.locks.len(), 2);
        assert_eq!(
            detail(&hub).gem_checksums.entry("sp-victim-1.0.0"),
            GemEntry::Absent
        );
        // An empty dict is the rule's default.
        let hub = hub_of(&[("MODULE.bazel", &module("", "\n    gem_checksums = {},"))]);
        assert_eq!(
            detail(&hub).gem_checksums.entry("sp-victim-1.0.0"),
            GemEntry::Absent
        );
        assert!(
            matches!(&detail(&hub).gem_checksums, GemChecksums::Literal { entries, .. } if entries.is_empty())
        );
        assert!(hub.derived.is_empty());
    }

    /// A dict that is a constant of the file is a literal there. One that
    /// is computed is not: it is neither absent nor a gap of the hub, and
    /// the lane that needs a value refuses.
    #[test]
    fn a_dict_that_is_not_a_plain_literal_says_what_cannot_be_addressed() {
        let constant = format!("SUMS = {{\"sp-victim-1.0.0\": \"{VICTIM}\"}}\n");
        let text = module(&constant, "\n    gem_checksums = SUMS,");
        let hub = hub_of(&[("MODULE.bazel", &text)]);
        let victim = entry_of(&detail(&hub).gem_checksums, "sp-victim-1.0.0");
        let (start, end) = victim.inner.expect("addressable");
        assert_eq!(&text[start..end], VICTIM);

        for attrs in [
            "\n    gem_checksums = sums(),",
            "\n    gem_checksums = SUMS | MORE,",
        ] {
            let hub = hub_of(&[("MODULE.bazel", &module("", attrs))]);
            assert_eq!(detail(&hub).gem_checksums, GemChecksums::Dynamic, "{attrs}");
            assert!(hub.derived.is_empty());
            // Whether it holds the gem is not known, which is not "it has
            // no entry": a lane that leaves an entry that is there breaks
            // the cold build (HZ-14).
            assert_eq!(
                detail(&hub).gem_checksums.entry("sp-victim-1.0.0"),
                GemEntry::Unknown,
                "{attrs}"
            );
        }

        // A computed key may be any gem; a value built from pieces has no
        // one literal to replace.
        let (half, rest) = VICTIM.split_at(32);
        let attrs = format!(
            "\n    gem_checksums = {{\n        NAME + \"-1.0.0\": \"{VICTIM}\",\n        \
             \"sp-victim-1.0.0\": \"{half}\" + \"{rest}\",\n        \"sp-other-1.0.0\": SUM,\n    }},"
        );
        let hub = hub_of(&[("MODULE.bazel", &module("", &attrs))]);
        let GemChecksums::Literal { entries, .. } = &detail(&hub).gem_checksums else {
            panic!("not a literal dict");
        };
        let read: Vec<(Option<&str>, Option<&str>, bool)> = entries
            .iter()
            .map(|entry| {
                (
                    entry.key.as_deref(),
                    entry.value.as_deref(),
                    entry.inner.is_some(),
                )
            })
            .collect();
        assert_eq!(
            read,
            [
                (None, Some(VICTIM), true),
                (Some("sp-victim-1.0.0"), Some(VICTIM), false),
                (Some("sp-other-1.0.0"), None, false),
            ]
        );
        assert_eq!(hub.derived.len(), 2);
        // A key that was read is found; any other gem may be behind the
        // computed key, so its entry is unknown and never absent.
        let sums = &detail(&hub).gem_checksums;
        assert_eq!(entry_of(sums, "sp-victim-1.0.0").inner, None);
        assert_eq!(entry_of(sums, "sp-other-1.0.0").value, None);
        for key in ["sp-third-1.0.0", "sp-victim-1.0.1"] {
            assert_eq!(sums.entry(key), GemEntry::Unknown, "{key}");
        }
        // The hub itself stays exact: the lane refuses the one gem, and a
        // gap would make the whole ecosystem undetermined.
        assert!(hub.decl.literal);
        let computed =
            format!("\n    gem_checksums = {{\n        NAME + \"-1.0.0\": \"{VICTIM}\",\n    }},");
        let hub = hub_of(&[("MODULE.bazel", &module("", &computed))]);
        assert_eq!(
            detail(&hub).gem_checksums.entry("sp-victim-1.0.0"),
            GemEntry::Unknown
        );
        assert!(hub.derived.is_empty());
    }

    /// The dict lives in the file of its tag: an included segment, and
    /// then that file is what a lane edits.
    #[test]
    fn the_dict_of_a_tag_in_an_included_segment_is_in_that_segment() {
        let attrs = format!("\n    gem_checksums = {{\"sp-victim-1.0.0\": \"{VICTIM}\"}},");
        let segment = module("", &attrs);
        let (dep, tags) = segment.split_once('\n').expect("two lines");
        let root_file = format!("{dep}\ninclude(\"//deps:ruby.MODULE.bazel\")\n");
        let hub = hub_of(&[
            ("MODULE.bazel", &root_file),
            ("deps/ruby.MODULE.bazel", tags),
        ]);
        assert_eq!(hub.decl.site.file, "deps/ruby.MODULE.bazel");
        let GemChecksums::Literal { file, entries } = &detail(&hub).gem_checksums else {
            panic!("not a literal dict");
        };
        assert_eq!(file, "deps/ruby.MODULE.bazel");
        let (start, end) = entries[0].inner.expect("addressable");
        assert_eq!(&tags[start..end], VICTIM);
        let attr = lock_ref(
            "//:deps/ruby.MODULE.bazel",
            "deps/ruby.MODULE.bazel",
            LockRole::ChecksumAttr,
        );
        assert_eq!(hub.locks.last(), Some(&attr));
    }

    /// `bundle_fetch` requires both labels, and each must name a file of
    /// this repository.
    #[test]
    fn a_label_that_is_missing_or_computed_leaves_the_hub_incomplete() {
        for (from, to, unread) in [
            (
                "    gemfile_lock = \"//:Gemfile.lock\",",
                "",
                "`gemfile_lock`",
            ),
            ("\"//:Gemfile.lock\"", "LOCK", "`gemfile_lock`"),
            ("\"//:Gemfile\"", "\"@gems//:Gemfile\"", "`gemfile`"),
            ("    gemfile = \"//:Gemfile\",\n", "", "`gemfile`"),
            ("name = \"bundle\"", "name = NAME", "`name`"),
            ("name = \"bundle\",", "", "`name`"),
            (
                "gemfile = \"//:Gemfile\",",
                "srcs = glob([\"*.gemspec\"]), gemfile = \"//:Gemfile\",",
                "`srcs`",
            ),
        ] {
            let text = module("", "").replace(from, to);
            let found = run(&root(&[("MODULE.bazel", &text)]), recognize);
            let [hub] = found.hubs.as_slice() else {
                panic!("{to}: {} hubs", found.hubs.len());
            };
            assert!(!hub.decl.literal, "{from} -> {to}");
            let [gap] = found.gaps.as_slice() else {
                panic!("{to}: {:?}", found.gaps);
            };
            assert_eq!(gap.token, "label_not_literal");
            assert!(gap.detail.contains(unread), "{}", gap.detail);
            assert!(gap.detail.contains("`ruby.bundle_fetch`"), "{}", gap.detail);
        }
        // `srcs` are files the hub copies: part of what it reads.
        let hub = hub_of(&[(
            "MODULE.bazel",
            &module("", "\n    srcs = [\"//:gem.gemspec\"],"),
        )]);
        assert_eq!(
            hub.locks[2],
            lock_ref("//:gem.gemspec", "gem.gemspec", LockRole::Config)
        );
    }

    #[test]
    fn imports_overrides_and_dev_dependencies_are_recorded() {
        let text = module("", "").replace(
            "use_repo(ruby, \"bundle\", ",
            "override_repo(ruby, bundle = \"my_bundle\")\nuse_repo(ruby, gems = \"bundle\", ",
        );
        let hub = hub_of(&[("MODULE.bazel", &text)]);
        assert_eq!(
            (
                detail(&hub).imports.as_slice(),
                hub.decl.apparent_name.as_str()
            ),
            (&["gems".to_string()][..], "gems")
        );
        assert_eq!(hub.bypasses.len(), 1);
        assert_eq!(hub.bypasses[0].token, "repo_override");

        let unimported = module("", "").replace("use_repo(ruby, \"bundle\", ", "use_repo(ruby, ");
        let hub = hub_of(&[("MODULE.bazel", &unimported)]);
        assert!(detail(&hub).imports.is_empty() && !detail(&hub).dev);

        let dev = module("", "").replace("\"ruby\")\n", "\"ruby\", dev_dependency = True)\n");
        assert!(detail(&hub_of(&[("MODULE.bazel", &dev)])).dev);
    }

    const HTTP: &str = "load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n\
                        http_archive(name = \"rules_ruby\", strip_prefix = \"rules_ruby-0.21.1\", \
                        url = \"https://example.com/rules_ruby.tar.gz\")\n";

    /// `rb_bundle_fetch` in a `WORKSPACE` (up to 0.29.0) is the same rule;
    /// its dict is then in the `WORKSPACE` file.
    #[test]
    fn a_workspace_bundle_fetch_is_the_same_shape() {
        let text = format!(
            "{HTTP}load(\"@rules_ruby//ruby:deps.bzl\", \"rb_bundle_fetch\", \"rb_register_toolchains\")\n\
             rb_register_toolchains(version = \"system\")\n\
             rb_bundle_fetch(\n    name = \"bundle\",\n    gemfile = \"//app:Gemfile\",\n    \
             gemfile_lock = \"//app:Gemfile.lock\",\n    \
             gem_checksums = {{\"sp-victim-1.0.0\": \"{VICTIM}\"}},\n)\n"
        );
        let hub = hub_of(&[("WORKSPACE", &text)]);
        assert_eq!(
            (hub.shape, hub.decl.site.system),
            (HubShape::BundleFetch, DeclSystem::Workspace)
        );
        let found = detail(&hub);
        assert_eq!(
            (found.rule, found.load_repo.as_deref()),
            (BundleRule::RbBundleFetch, Some("rules_ruby"))
        );
        assert_eq!((found.module.as_deref(), found.imports.len()), (None, 0));
        let stale = DerivedState::ChecksumValue {
            file: "WORKSPACE".to_string(),
            key: "sp-victim-1.0.0".to_string(),
            input: "app/Gemfile.lock".to_string(),
        };
        assert_eq!(hub.derived, [stale]);
        let entry = entry_of(&found.gem_checksums, "sp-victim-1.0.0");
        let (start, end) = entry.inner.expect("addressable");
        assert_eq!(&text[start..end], VICTIM);

        // A toolchain registered under the hub's own name may be the
        // repository Bazel builds: the order rule cannot prove the hub.
        let text = text.replace(
            "version = \"system\"",
            "name = \"bundle\", version = \"system\"",
        );
        let found = run(&root(&[("WORKSPACE", &text)]), recognize);
        assert_eq!(found.hubs.len(), 1);
        assert_eq!(found.gaps[0].token, "workspace_definition_order");
    }

    /// The legacy rules run Bundler itself, beside the `Gemfile`: the
    /// lock is the one next to it, named or not.
    #[test]
    fn the_legacy_bundle_rules_are_their_own_shape() {
        let rb_bundle = format!(
            "{HTTP}load(\"@rules_ruby//ruby:deps.bzl\", \"rb_bundle\", \"rb_register_toolchains\")\n\
             rb_register_toolchains(version = \"system\")\n\
             rb_bundle(name = \"bundle\", gemfile = \"//app:Gemfile\")\n"
        );
        let hub = hub_of(&[("WORKSPACE", &rb_bundle)]);
        assert_eq!(hub.shape, HubShape::LegacyBundle);
        assert_eq!(detail(&hub).rule, BundleRule::RbBundle);
        assert_eq!(
            hub.locks,
            [
                lock_ref(
                    "//app:Gemfile.lock",
                    "app/Gemfile.lock",
                    LockRole::PackageLock
                ),
                lock_ref("//app:Gemfile", "app/Gemfile", LockRole::Config),
            ]
        );
        assert!(hub.derived.is_empty());

        // The bazelruby README, with a lock of another name.
        let ruby_bundle =
            "load(\"@bazelruby_rules_ruby//ruby:deps.bzl\", \"rules_ruby_dependencies\", \
                           \"rules_ruby_select_sdk\")\nrules_ruby_dependencies()\n\
                           load(\"@bazel_skylib//:workspace.bzl\", \"bazel_skylib_workspace\")\n\
                           bazel_skylib_workspace()\nrules_ruby_select_sdk(version = \"3.0.2\")\n\
                           load(\"@bazelruby_rules_ruby//ruby:defs.bzl\", \"ruby_bundle\")\n\
                           ruby_bundle(name = \"bundle\", gemfile = \"//:Gemfile\", \
                           gemfile_lock = \"//:Gemfile.release.lock\")\n";
        let hub = hub_of(&[("WORKSPACE", ruby_bundle)]);
        assert_eq!(
            (hub.shape, detail(&hub).rule),
            (HubShape::LegacyBundle, BundleRule::RubyBundle)
        );
        assert_eq!(
            detail(&hub).load_repo.as_deref(),
            Some("bazelruby_rules_ruby")
        );
        assert_eq!(hub.locks[0].path.as_deref(), Some("Gemfile.release.lock"));
    }

    /// Up to 0.29.0 the legacy rule is also a tag.
    #[test]
    fn the_legacy_bundle_tag_is_a_legacy_hub() {
        let text = module("", "").replace("ruby.bundle_fetch(", "ruby.bundle(");
        let text = text.replace("    gemfile_lock = \"//:Gemfile.lock\",", "");
        let hub = hub_of(&[("MODULE.bazel", &text)]);
        assert_eq!(
            (hub.shape, detail(&hub).rule),
            (HubShape::LegacyBundle, BundleRule::RbBundle)
        );
        assert_eq!(hub.locks[0].path.as_deref(), Some("Gemfile.lock"));
        assert_eq!(detail(&hub).imports, ["bundle"]);
    }

    /// The lock is searched by the extension's label without a
    /// repository, which must be the file the usages are found by.
    #[test]
    fn the_extension_is_named_the_way_the_lock_names_it() {
        let (label, name) = EXTENSION;
        let named = crate::bazel::derived::ExtRef::new(label, name).expect("a lock spelling");
        assert_eq!(
            (named.label(), named.name()),
            ("//ruby:extensions.bzl", "ruby")
        );
        let file = crate::bazel::label::Label::parse(label, None).expect("a label");
        assert_eq!(file.file(), EXTENSIONS_BZL);
    }

    /// A hub rule used where no declaration is read may declare a bundle
    /// nobody saw. Beside a hub that was resolved there is no signal, so
    /// the use is a gap: the gem ecosystem is then undetermined, and never
    /// "not governed" for the lock of the bundle that was not read.
    #[test]
    fn a_hub_rule_used_where_no_declaration_is_read_is_a_gap() {
        let hub = "rb_bundle_fetch(name = \"bundle\", gemfile = \"//:Gemfile\", \
                   gemfile_lock = \"//:Gemfile.lock\")\n";
        let workspace = |rest: &str| {
            format!(
                "{HTTP}load(\"@rules_ruby//ruby:deps.bzl\", \"rb_bundle_fetch\", \
                 \"rb_register_toolchains\")\nrb_register_toolchains(version = \"system\")\n\
                 {hub}{rest}"
            )
        };
        let exact = run(&root(&[("WORKSPACE", &workspace(""))]), recognize);
        assert_eq!((exact.hubs.len(), exact.gaps.as_slice()), (1, &[][..]));
        // A `load` starts a chunk, where nothing can replace the hub.
        let later = "load(\"@bazel_tools//tools/build_defs/repo:utils.bzl\", \"maybe\")\n";
        for (rest, line) in [
            (
                "[rb_bundle_fetch(name = n, gemfile = \"//\" + n + \":Gemfile\", gemfile_lock = \
                 \"//\" + n + \":Gemfile.lock\") for n in [\"a\", \"b\"]]\n",
                7,
            ),
            ("maybe(repo_rule = rb_bundle_fetch, name = \"more\")\n", 7),
            ("fetch = rb_bundle_fetch\nfetch(name = \"more\")\n", 7),
        ] {
            let text = workspace(&format!("{later}{rest}"));
            let found = run(&root(&[("WORKSPACE", &text)]), recognize);
            assert_eq!((found.hubs.len(), found.signals.len()), (1, 0), "{rest}");
            let [gap] = found.gaps.as_slice() else {
                panic!("{rest}: {:?}", found.gaps);
            };
            assert_eq!(
                (gap.token, gap.file.as_str()),
                ("label_not_literal", "WORKSPACE"),
                "{rest}"
            );
            let at = format!("WORKSPACE:{line}: `rb_bundle_fetch` is used where");
            assert!(gap.detail.starts_with(&at), "{rest}: {}", gap.detail);
        }

        // In a `MODULE.bazel` the rule is one `use_repo_rule` can bind
        // (`rules_ruby@v0.29.0:ruby/deps.bzl`): the bundle it declares is
        // no tag of the extension.
        let rule = "rb_bundle_fetch = use_repo_rule(\"@rules_ruby//ruby:deps.bzl\", \
                    \"rb_bundle_fetch\")\nrb_bundle_fetch(name = \"more\", gemfile = \
                    \"//more:Gemfile\", gemfile_lock = \"//more:Gemfile.lock\")\n";
        let text = format!("{}{rule}", module("", ""));
        let found = run(&root(&[("MODULE.bazel", &text)]), recognize);
        assert_eq!((found.hubs.len(), found.signals.len()), (1, 0));
        let [gap] = found.gaps.as_slice() else {
            panic!("{:?}", found.gaps);
        };
        assert_eq!(
            (gap.token, gap.file.as_str()),
            ("label_not_literal", "MODULE.bazel")
        );
        let line = text.lines().count();
        let at =
            format!("MODULE.bazel:{line}: `rb_bundle_fetch` is called through `use_repo_rule`");
        assert!(gap.detail.starts_with(&at), "{}", gap.detail);
        // Bound and never called, it declares nothing.
        let (bound, _) = rule.split_once('\n').expect("two statements");
        let text = format!("{}{bound}\n", module("", ""));
        let found = run(&root(&[("MODULE.bazel", &text)]), recognize);
        assert_eq!((found.hubs.len(), found.gaps.as_slice()), (1, &[][..]));
    }

    /// A ruleset that is there with no bundle declares no hub this reader
    /// resolved: the ecosystem is undetermined, never "not governed".
    #[test]
    fn a_ruleset_with_no_hub_is_a_signal() {
        let (toolchain_only, _) = module("", "")
            .split_once("ruby.bundle_fetch")
            .map(|(head, _)| (head.to_string(), ()))
            .expect("the tag");
        let found = run(&root(&[("MODULE.bazel", &toolchain_only)]), recognize);
        assert!(found.hubs.is_empty() && found.gaps.is_empty());
        assert_eq!(found.signals.len(), 1);
        assert_eq!(
            (found.signals[0].ruleset, found.signals[0].site.system),
            (Ruleset::RulesRuby, DeclSystem::Bzlmod)
        );

        let workspace = format!("{HTTP}load(\"@rules_ruby//ruby:deps.bzl\", \"rb_register_toolchains\")\nrb_register_toolchains()\n");
        let found = run(&root(&[("WORKSPACE", &workspace)]), recognize);
        assert_eq!((found.hubs.len(), found.signals.len()), (0, 1));
        assert_eq!(found.signals[0].site.system, DeclSystem::Workspace);

        let other = "bazel_dep(name = \"rules_python\", version = \"1.4.1\")\n";
        assert_eq!(
            run(&root(&[("MODULE.bazel", other)]), recognize),
            Recognized::default()
        );
    }

    /// The light fixture workspaces the real-Bazel cells build are each
    /// one exact hub over the root `Gemfile` pair, and only those with a
    /// dict have a derived value. A fixture added later is not this
    /// test's to judge.
    #[test]
    fn the_light_fixtures_are_each_one_exact_hub() {
        let roots = fixtures("rules_ruby");
        let known = [
            ("bzlmod/e9", "MODULE.bazel", true),
            ("bzlmod/e9-nosums", "MODULE.bazel", false),
            ("bzlmod/e9-transitive", "MODULE.bazel", true),
            ("workspace/e7", "WORKSPACE", false),
        ];
        for (name, declared_in, sums) in known {
            let files = roots
                .get(name)
                .unwrap_or_else(|| panic!("no fixture {name}"));
            let found = run(files, recognize);
            assert_eq!(
                (found.gaps.as_slice(), found.signals.len()),
                (&[][..], 0),
                "{name}"
            );
            let [hub] = found.hubs.as_slice() else {
                panic!("{name}: {} hubs", found.hubs.len());
            };
            assert!(hub.decl.literal, "{name}");
            assert_eq!(
                (hub.shape, hub.decl.site.file.as_str()),
                (HubShape::BundleFetch, declared_in)
            );
            let paths: Vec<Option<&str>> = hub.locks.iter().map(|l| l.path.as_deref()).collect();
            assert_eq!(
                paths[..2],
                [Some("Gemfile.lock"), Some("Gemfile")],
                "{name}"
            );
            let entry = detail(hub).gem_checksums.entry("sp-victim-1.0.0");
            let entry = match entry {
                GemEntry::Found(entry) => Some(entry),
                GemEntry::Absent => None,
                GemEntry::Unknown => panic!("{name}: the dict is not read"),
            };
            assert_eq!(
                (entry.is_some(), !hub.derived.is_empty()),
                (sums, sums),
                "{name}"
            );
            if let Some(entry) = entry {
                let (start, end) = entry.inner.expect("addressable");
                let text = files.0[declared_in].as_str().expect("text");
                assert_eq!(Some(&text[start..end]), entry.value.as_deref(), "{name}");
            }
        }
    }
}
