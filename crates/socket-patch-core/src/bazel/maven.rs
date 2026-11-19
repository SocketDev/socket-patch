//! What a rules_jvm_external hub of a Bazel workspace builds.
//!
//! Under Bzlmod a hub is the `install` tags of the ruleset's `maven`
//! extension that share a `name` (`maven` when none is given). A hub with a
//! `lock_file` is pinned: Bazel fetches each jar the lock names, at the
//! sha256 the lock holds, and reads no `pom.xml`, no Gradle file and no
//! Maven local repository. So a patch that socket-patch puts in one of
//! those does not reach what Bazel builds, and [`notices`] says so for
//! each artifact a hub builds.
//!
//! Everything is read from the checkout through [`super::workspace`]: the
//! root `MODULE.bazel` with the files it includes, the locks its hubs
//! name, the `WORKSPACE` file and what names the Bazel release. Nothing is
//! evaluated, no Bazel is run and nothing is written. What cannot be read
//! with certainty is said as such ([`UNREADABLE`]) and never guessed.
//!
//! Not seen: a hub or an override that another Bazel module declares, a
//! `maven_install` inside a function of a `.bzl` file, a jar that reaches
//! Bazel without a hub, and what a flag or an rc file tells Bazel.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use super::rc::declared_release;
use super::starlark::{Call, How, Value};
use super::workspace::{disk_up_to, Doubt, Entry, Extension, Repo, Tag, Workspace};
use crate::formats::maven::is_variant;
use crate::utils::fs::run_blocking;
use crate::utils::purl::{parse_maven_purl, purl_qualifier};

/// The extension whose `install` tags make a hub.
pub const EXTENSION: Extension<'static> = Extension {
    module: "rules_jvm_external",
    file: "//:extensions.bzl",
    name: "maven",
};

/// The warning for an artifact that a pinned hub builds: no patch of a
/// socket-patch command reaches that build.
pub const HUB_UNPATCHED: &str = "maven_bazel_hub_unpatched";
/// The warning for an artifact when the hubs of the workspace cannot be
/// read: a hub may build it.
pub const UNREADABLE: &str = "maven_bazel_unreadable";

/// The largest lock that is read.
const MAX_LOCK: usize = 16 << 20;

/// A hub of the root module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hub {
    pub name: String,
    /// Where its first `maven.install` is: the file, from the Bazel root,
    /// and the line.
    pub file: String,
    pub line: usize,
    /// The lock its tags name, from the Bazel root. `None`: the hub is not
    /// pinned, and Bazel resolves what it builds when it builds.
    pub lock: Option<String>,
}

const NOT_A_FILE: &str = "the `lock_file` of this hub is not a file of this repository";

/// The name and the lock of the hub that the `install` tag `call` adds to,
/// or why they cannot be read.
fn install(ws: &Workspace, call: &Call) -> Result<(String, Option<String>), &'static str> {
    if !call.whole || call.unpacks() {
        return Err("this `maven.install` is not a plain call of its own");
    }
    // What a repository name is made of: Bazel takes no other name, and
    // a warning prints this one.
    let named = |b: u8| b.is_ascii_alphanumeric() || b"_.-+".contains(&b);
    let name = match call.arg("name") {
        None => "maven",
        Some(Value::Str(name)) if name.bytes().all(named) => name,
        Some(_) => return Err("the `name` of this hub is not a repository name in a string"),
    };
    let lock = match call.arg("lock_file") {
        None => None,
        Some(Value::Str(label)) => match ws.label(label) {
            Some(file) if file.repo == Repo::Main => Some(file.path()),
            _ => return Err(NOT_A_FILE),
        },
        Some(_) => return Err(NOT_A_FILE),
    };
    Ok((name.to_string(), lock))
}

/// The hubs of the workspace, and what makes the list uncertain: the
/// doubts of the reader, a tag that cannot be read, and tags of one hub
/// that name different locks. The ruleset takes the lock of the last root
/// tag (`private/extensions/maven.bzl` at 6.5 and 7.2), so such a hub is
/// left out instead of given one of them. And no hub at all is given when
/// a tag cannot be read or the reader may have missed one: that tag may be
/// the last one of any hub.
pub fn hubs(ws: &Workspace) -> (Vec<Hub>, Vec<Doubt>) {
    let tags = ws.tags(&EXTENSION, "install");
    let mut doubts: Vec<Doubt> = ws.doubts.iter().chain(&tags.doubts).cloned().collect();
    let mut every_tag_read = doubts.is_empty();
    let (mut hubs, mut split): (Vec<Hub>, Vec<String>) = Default::default();
    for tag in &tags.calls {
        let (file, line) = (tag.file.to_string(), tag.call.line);
        let (name, lock) = match install(ws, tag.call) {
            Ok(read) => read,
            Err(why) => {
                every_tag_read = false;
                let why = why.to_string();
                doubts.push(Doubt { file, line, why });
                continue;
            }
        };
        let Some(hub) = hubs.iter().find(|hub| hub.name == name) else {
            hubs.push(Hub {
                name,
                file,
                line,
                lock,
            });
            continue;
        };
        if hub.lock != lock {
            let (first, at) = (&hub.file, hub.line);
            let why = format!("this tag and the one at {first}:{at} name different locks");
            doubts.push(Doubt { file, line, why });
            split.push(name);
        }
    }
    hubs.retain(|hub| every_tag_read && !split.contains(&hub.name));
    (hubs, doubts)
}

/// The jar of an artifact in a lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pinned {
    pub version: String,
    /// The sha256 the lock holds for it. `None`: the lock has none.
    pub jar_sha256: Option<String>,
    /// The hub fetches it: the lock has its sha256, a repository of the
    /// lock lists it and the lock does not skip it.
    pub fetched: bool,
}

/// A hub's lock, `maven_install.json`, in format 2 (rules_jvm_external 6.5
/// and 6.9 write it) or 3 (7.2 does).
#[derive(Debug)]
pub struct Lock {
    pub format: u8,
    /// The jar without a classifier of each `group:artifact`.
    jars: HashMap<String, Pinned>,
}

impl Lock {
    /// Reads a lock. An empty file (the hub is not pinned yet), text that
    /// is no JSON of this shape (a merge conflict), and any other format
    /// are an error: the reason.
    pub fn parse(text: &str) -> Result<Lock, String> {
        #[derive(serde::Deserialize)]
        struct Artifact {
            version: String,
            #[serde(default)]
            shasums: HashMap<String, Option<String>>,
        }
        #[derive(serde::Deserialize)]
        struct Raw {
            version: Option<String>,
            #[serde(default)]
            artifacts: HashMap<String, Artifact>,
            #[serde(default)]
            repositories: HashMap<String, HashSet<String>>,
            #[serde(default)]
            skipped: HashSet<String>,
        }
        if text.trim().is_empty() {
            return Err("it is empty: the hub is not pinned yet".to_string());
        }
        let raw: Raw = serde_json::from_str(text).map_err(|e| format!("it is no lock ({e})"))?;
        let format = match raw.version.as_deref() {
            Some("2") => 2,
            Some("3") => 3,
            _ => return Err("it is not a lock of format 2 or 3".to_string()),
        };
        let jar = |(key, mut artifact): (String, Artifact)| {
            // A third part of the key is a packaging other than `jar`, and
            // every other name among the sums is a classifier.
            let sum = artifact.shasums.remove("jar")?;
            let listed = raw.repositories.values().any(|keys| keys.contains(&key));
            let pinned = Pinned {
                version: artifact.version,
                fetched: sum.is_some() && listed && !raw.skipped.contains(&key),
                jar_sha256: sum,
            };
            (key.matches(':').count() == 1).then_some((key, pinned))
        };
        let jars = raw.artifacts.into_iter().filter_map(jar).collect();
        Ok(Lock { format, jars })
    }

    /// The jar of `group:artifact` without a classifier, when the lock
    /// holds one.
    pub fn plain_jar(&self, group: &str, artifact: &str) -> Option<&Pinned> {
        self.jars.get(&format!("{group}:{artifact}"))
    }
}

/// The name a hub gives the target of an artifact: `escape` in the
/// ruleset's `private/coursier_utilities.bzl` at 6.5, 6.9 and 7.2. An
/// override replaces the artifact whose target has the name of its
/// `coordinates`.
fn target(coordinates: &str) -> String {
    let first = coordinates.split(',').next().unwrap_or_default();
    let named = first.replace(['.', '-', ':', '/', '+', '$'], "_");
    named.replace(['[', ']'], "")
}

/// Why a hub that fetches a jar may not build it.
const OVERRIDDEN: &str = "a `maven.override` gives this artifact another target";

/// Whether Bazel builds an artifact through a hub of the workspace.
#[derive(Debug, PartialEq, Eq)]
pub enum Built<'a> {
    /// No hub does, and every hub was read.
    No,
    /// These pinned hubs fetch its jar at that version.
    Yes(Vec<(&'a Hub, &'a Pinned)>),
    /// It is not known. No hub that was read fetches its jar and this
    /// could not be read, or one does and this `maven.override` may put
    /// another target in the jar's place.
    Unknown(&'a Doubt),
}

/// What the hubs of a workspace build: read once, asked per artifact.
#[derive(Debug)]
pub struct Hubs {
    pinned: Vec<(Hub, Lock)>,
    /// The `override` tags of the root module: the [`target`] each
    /// replaces (`None`: its `coordinates` are no string, so any), and
    /// where it is. The tag's `name` is not asked for: the ruleset at 6.5
    /// takes an override for every hub.
    overrides: Vec<(Option<String>, Doubt)>,
    /// The first thing that could not be read.
    doubt: Option<Doubt>,
}

impl Hubs {
    /// Reads the hubs of the workspace behind `view`, their locks and the
    /// overrides. A hub without a lock, a lock that cannot be read, and a
    /// `WORKSPACE` file that calls `maven_install` or cannot be read while
    /// Bazel may read it (the workspace names no release, or one before 9)
    /// are doubts.
    pub fn read(view: &dyn Fn(&str) -> Entry) -> Hubs {
        let ws = Workspace::read(view);
        let (hubs, mut doubts) = hubs(&ws);
        let overrides = ws.tags(&EXTENSION, "override").calls.into_iter();
        let overrides = overrides.map(|Tag { file, call, .. }| {
            let (replaced, why) = match call.arg("coordinates") {
                Some(Value::Str(artifact)) => (Some(target(artifact)), OVERRIDDEN),
                _ => (None, "this `maven.override` cannot be read"),
            };
            let (file, line, why) = (file.to_string(), call.line, why.to_string());
            (replaced, Doubt { file, line, why })
        });
        let overrides = overrides.collect();
        let mut pinned = Vec::new();
        for hub in hubs {
            // Where a doubt about its lock is: the lock, or the tag.
            let (file, line) = match &hub.lock {
                Some(lock) => (lock.clone(), 0),
                None => (hub.file.clone(), hub.line),
            };
            let lock = match hub.lock.as_deref().map(view) {
                None => Err(format!("hub \"{}\" has no `lock_file`", hub.name)),
                Some(Entry::Text(text)) => Lock::parse(&text),
                Some(Entry::Absent) => Err("it does not exist".to_string()),
                Some(Entry::Unreadable(why)) => Err(format!("it cannot be read: {why}")),
            };
            match lock {
                Ok(lock) => pinned.push((hub, lock)),
                Err(why) => doubts.push(Doubt { file, line, why }),
            }
        }
        let before_9 = || declared_release(view).is_none_or(|release| release < (9, 0, 0));
        doubts.extend(match ws.legacy.filter(|_| before_9()) {
            Some(Ok((file, read))) => {
                // By its own name, or by one that a `load` gives it.
                let symbol = Value::Str("maven_install".to_string());
                let loads = read.calls.iter().filter(|call| call.callee == "load");
                let args = loads.flat_map(|load| &load.args);
                let aliases = args.filter_map(|arg| match &arg.how {
                    How::Keyword(alias) if arg.value == symbol => Some(alias.as_str()),
                    _ => None,
                });
                let names: Vec<_> = aliases.chain(["maven_install"]).collect();
                let installs = |call: &&Call| names.contains(&call.callee.as_str());
                read.calls.iter().find(installs).map(|call| Doubt {
                    file,
                    line: call.line,
                    why: "a `maven_install` of a WORKSPACE file is not read".to_string(),
                })
            }
            unread => unread.and_then(Result::err),
        });
        Hubs {
            pinned,
            overrides,
            doubt: doubts.into_iter().next(),
        }
    }

    /// Whether Bazel builds the jar of `group:artifact` at `version`.
    pub fn built(&self, group: &str, artifact: &str, version: &str) -> Built<'_> {
        let mut by = Vec::new();
        for (hub, lock) in &self.pinned {
            let jar = lock.plain_jar(group, artifact);
            let fetched = jar.filter(|jar| jar.fetched && jar.version == version);
            by.extend(fetched.map(|jar| (hub, jar)));
        }
        // In the place of a jar that a hub fetches, an override puts the
        // target it names: what that one builds is not read.
        let named = Some(target(&format!("{group}:{artifact}")));
        let over = |(of, _): &&(Option<String>, Doubt)| of.is_none() || *of == named;
        match self.overrides.iter().find(over) {
            _ if by.is_empty() => self.doubt.as_ref().map_or(Built::No, Built::Unknown),
            Some((_, tag)) => Built::Unknown(tag),
            None => Built::Yes(by),
        }
    }
}

/// The warnings for the patches `purls` of a command that ran in
/// `project`: a code and a detail for each Maven jar that a hub of the
/// project's Bazel workspace builds ([`HUB_UNPATCHED`]) or may build
/// ([`UNREADABLE`]). Nothing for a project in no Bazel workspace, and
/// nothing is looked for without a Maven purl among them.
pub async fn notices(project: &Path, purls: Vec<String>) -> Vec<(&'static str, String)> {
    let project = project.to_path_buf();
    run_blocking(move || notices_blocking(&project, purls)).await
}

fn notices_blocking(project: &Path, mut purls: Vec<String>) -> Vec<(&'static str, String)> {
    purls.sort();
    purls.dedup();
    // A classifier or another packaging is not the jar that a lock names
    // by group and artifact alone.
    let jar = |purl| {
        let variant = is_variant(
            purl_qualifier(purl, "type"),
            purl_qualifier(purl, "classifier"),
        );
        Some((purl, parse_maven_purl(purl).filter(|_| !variant)?))
    };
    let jars: Vec<_> = purls.iter().map(String::as_str).filter_map(jar).collect();
    let root = (!jars.is_empty()).then(|| super::bazel_root(project));
    let Some(root) = root.flatten() else {
        return Vec::new();
    };
    let hubs = Hubs::read(&disk_up_to(&root.dir, MAX_LOCK));
    let mut said = Vec::new();
    for (purl, (group, artifact, version)) in jars {
        let (code, detail) = match hubs.built(&group, &artifact, &version) {
            Built::No => continue,
            Built::Yes(by) => {
                let from = |(hub, _): &(&Hub, &Pinned)| {
                    let (lock, name) = (hub.lock.as_deref().unwrap_or_default(), &hub.name);
                    let (file, line) = (&hub.file, hub.line);
                    format!("{lock} (hub \"{name}\", `maven.install` at {file}:{line})")
                };
                let from = by.iter().map(from).collect::<Vec<_>>().join(" and ");
                let detail = format!(
                    "Bazel takes this artifact from {from}, which pins the upstream jar. \
                     socket-patch does not patch a rules_jvm_external hub yet, so the Bazel \
                     build stays unpatched whatever this command did for another build of the \
                     checkout"
                );
                (HUB_UNPATCHED, detail)
            }
            Built::Unknown(Doubt { file, line, why }) => {
                let at = match line {
                    0 => file.clone(),
                    line => format!("{file}:{line}"),
                };
                let detail = format!(
                    "socket-patch could not tell whether Bazel takes this artifact from \
                     a rules_jvm_external hub: {at}: {why}"
                );
                (UNREADABLE, detail)
            }
        };
        said.push((code, format!("{purl}: {detail}")));
    }
    said
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pinned hub, as teams write one.
    const PINNED: &str = r#"bazel_dep(name = "rules_jvm_external", version = "7.2")

maven = use_extension("@rules_jvm_external//:extensions.bzl", "maven")
maven.install(
    artifacts = ["io.netty:netty-tcnative-boringssl-static:2.0.61.Final"],
    lock_file = "//:maven_install.json",
)
use_repo(maven, "maven")
"#;

    // The ruleset's own `maven_install.json` at its tags 6.9 and 7.2, cut
    // down to two artifacts: format 2 as 6.9 wrote it, format 3 as 7.2
    // did.
    const NETTY: &str = r#"
  "artifacts": {
    "io.netty:netty-tcnative-boringssl-static": {
      "shasums": {
        "jar": "b6f974972c44cd6f9cecabc255290286faac40b6393c66c3c3c0db7f421cc28e",
        "linux-x86_64": "4ff9d14f1ec6ccee35b78f53a6f3d9c7c54535aa2a76138311c2f619c5e150e1",
        "osx-aarch_64": "58e0302c9fde3db984c3ff7ee7ec7159dc0320bdb91533cc290e12e40911cd1a"
      },
      "version": "2.0.61.Final"
    },
    "io.netty:netty-tcnative-classes": {
      "shasums": {"jar": "9b970eccd844bfae175a5cbbf7bf94891894add06d6ccbe1abf2250cd64080f6"},
      "version": "2.0.61.Final"
    }
  },
  "dependencies": {
    "io.netty:netty-tcnative-boringssl-static": [
      "io.netty:netty-tcnative-boringssl-static:jar:linux-x86_64",
      "io.netty:netty-tcnative-boringssl-static:jar:osx-aarch_64",
      "io.netty:netty-tcnative-classes"
    ]
  },
  "repositories": {
    "https://repo1.maven.org/maven2/": [
      "io.netty:netty-tcnative-boringssl-static",
      "io.netty:netty-tcnative-boringssl-static:jar:linux-x86_64",
      "io.netty:netty-tcnative-boringssl-static:jar:osx-aarch_64",
      "io.netty:netty-tcnative-classes"
    ]
  },
"#;
    const NETTY_JAR: &str = "b6f974972c44cd6f9cecabc255290286faac40b6393c66c3c3c0db7f421cc28e";

    fn lock_69() -> String {
        let signed =
            r#""__INPUT_ARTIFACTS_HASH": 1448912684, "__RESOLVED_ARTIFACTS_HASH": 771049556,"#;
        format!("{{{signed}{NETTY}\"version\": \"2\"}}\n")
    }

    fn lock_72() -> String {
        let signed = r#""__INPUT_ARTIFACTS_HASH": {"repositories": -1949687017},
  "__RESOLVED_ARTIFACTS_HASH": {"io.netty:netty-tcnative-classes": 1239547355},"#;
        format!("{{{signed}{NETTY}\"version\": \"3\"}}\n")
    }

    /// From `regression_testing_maven_install.json` of the ruleset's tests
    /// at 7.2: an artifact the lock skips, and a packaging other than jar.
    const LOCK_SKIPS: &str = r#"{
  "artifacts": {
    "org.codehaus.plexus:plexus": {"shasums": {"jar": null}, "version": "1.0.4"},
    "com.almworks.sqlite4java:libsqlite4java-osx:dylib": {
      "shasums": {"jar": "b84122142173f33137c76d05dd6c80cc96f619ead3dc476c12d6ea46ef12dd05"},
      "version": "1.0.392"
    },
    "com.almworks.sqlite4java:sqlite4java": {
      "shasums": {"jar": "243a64470fda0e86a6fddeb0af4c7aa9426ce84e68cbfe18d75ee5da4b7e0b92"},
      "version": "1.0.392"
    },
    "org.example:only-sources": {"shasums": {"sources": "00"}, "version": "1.0"},
    "org.example:unlisted": {"shasums": {"jar": "11"}, "version": "1.0"}
  },
  "dependencies": {},
  "repositories": {
    "https://repo1.maven.org/maven2/": [
      "com.almworks.sqlite4java:libsqlite4java-osx:dylib",
      "com.almworks.sqlite4java:sqlite4java",
      "org.codehaus.plexus:plexus",
      "org.example:only-sources:jar:sources"
    ],
    "https://maven.google.com/": []
  },
  "skipped": ["org.codehaus.plexus:plexus"],
  "version": "3"
}
"#;

    /// The view of the files `files`, held in memory.
    fn view<'a>(files: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Entry + 'a {
        move |path| match files.iter().find(|(name, _)| *name == path) {
            Some((_, text)) => Entry::Text(text.to_string()),
            None => Entry::Absent,
        }
    }

    /// Each hub as `name file:line lock`, and each doubt as
    /// `file:line: why`.
    fn listed(files: &[(&str, &str)]) -> (Vec<String>, Vec<String>) {
        let (hubs, doubts) = hubs(&Workspace::read(&view(files)));
        let hub = |hub: Hub| {
            let lock = hub.lock.unwrap_or_else(|| "-".to_string());
            format!("{} {}:{} {lock}", hub.name, hub.file, hub.line)
        };
        let doubt = |doubt: Doubt| format!("{}:{}: {}", doubt.file, doubt.line, doubt.why);
        (
            hubs.into_iter().map(hub).collect(),
            doubts.into_iter().map(doubt).collect(),
        )
    }

    /// The hubs and the doubts of one `MODULE.bazel`.
    fn module(text: &str) -> (Vec<String>, Vec<String>) {
        listed(&[("MODULE.bazel", text)])
    }

    /// What [`Hubs::built`] says of netty's jar at the version the locks
    /// above hold, in a word, with the doubt of an `Unknown`.
    fn built(files: &[(&str, &str)]) -> String {
        let hubs = Hubs::read(&view(files));
        let said = match hubs.built("io.netty", "netty-tcnative-classes", "2.0.61.Final") {
            Built::No => "no".to_string(),
            Built::Yes(by) => format!("yes, {}", by.len()),
            Built::Unknown(doubt) => format!("{}:{}: {}", doubt.file, doubt.line, doubt.why),
        };
        said
    }

    #[test]
    fn a_hub_is_an_install_tag_of_the_rulesets_maven_extension() {
        assert_eq!(
            module(PINNED),
            (
                vec!["maven MODULE.bazel:4 maven_install.json".to_string()],
                vec![]
            )
        );
        // Under another name for the proxy and for the ruleset, in a file
        // the root includes, and beside an extension called `maven` that
        // another module defines.
        let root = r#"bazel_dep(name = "rules_jvm_external", version = "6.9", repo_name = "rje")
bazel_dep(name = "rules_other", version = "1.0")
include("//third_party:jvm.MODULE.bazel")
other = use_extension("@rules_other//:extensions.bzl", "maven")
other.install(name = "not_a_hub", lock_file = "//:other.json")
"#;
        let included = r#"jvm = use_extension("@rje//:extensions.bzl", "maven", dev_dependency = True)
jvm.install(name = "deps", lock_file = "@//third_party:deps_install.json")
jvm.artifact(group = "com.example", artifact = "a", version = "1")
"#;
        let files = [
            ("MODULE.bazel", root),
            ("third_party/jvm.MODULE.bazel", included),
        ];
        let hubs = ["deps third_party/jvm.MODULE.bazel:2 third_party/deps_install.json"];
        assert_eq!(listed(&files), (hubs.map(String::from).to_vec(), vec![]));
        assert_eq!(module("module(name = 'no_java')\n"), (vec![], vec![]));
    }

    #[test]
    fn the_lock_of_a_hub_is_the_plain_label_its_tags_agree_on() {
        let hub = |tags: &str| {
            let proxy = "maven = use_extension('@rules_jvm_external//:extensions.bzl', 'maven')";
            module(&format!("{proxy}\n{tags}\n"))
        };
        // The default name, with and without a lock; two tags of one hub
        // that agree; two hubs.
        for (tags, hubs) in [
            ("maven.install()", vec!["maven MODULE.bazel:2 -"]),
            (
                "maven.install(lock_file = '//:a.json')\nmaven.install(lock_file = ':a.json')",
                vec!["maven MODULE.bazel:2 a.json"],
            ),
            (
                "maven.install(lock_file = '//:a.json')\nmaven.install(name = 'b')",
                vec!["maven MODULE.bazel:2 a.json", "b MODULE.bazel:3 -"],
            ),
        ] {
            assert_eq!(
                hub(tags),
                (hubs.iter().map(|h| h.to_string()).collect(), vec![]),
                "{tags}"
            );
        }
        // What cannot be read is a doubt, and gives no hub.
        let plain = "MODULE.bazel:2: this `maven.install` is not a plain call of its own";
        let label = "MODULE.bazel:2: the `lock_file` of this hub is not a file of this repository";
        let name = "MODULE.bazel:2: the `name` of this hub is not a repository name in a string";
        for (tags, doubt) in [
            ("maven.install(lock_file = LOCK)", label),
            ("maven.install(lock_file = '@other//:a.json')", label),
            ("maven.install(lock_file = '//:a' + '.json')", label),
            ("maven.install(name = NAME)", name),
            // Nothing Bazel takes for a name, and a line of its own in a
            // warning.
            ("maven.install(name = 'a\\nb')", name),
            ("maven.install(**ARGS)", plain),
            ("PINNED and maven.install(lock_file = '//:a.json')", plain),
            // A tag that cannot be read may be the last one of a hub that
            // another tag made: its lock is not known either.
            (
                "maven.install(name = NAME)\nmaven.install(lock_file = '//:a.json')",
                name,
            ),
        ] {
            assert_eq!(hub(tags), (vec![], vec![doubt.to_string()]), "{tags}");
        }
        // Two tags of one hub with different locks: the ruleset takes the
        // last one's, so neither is taken here.
        let split =
            "maven.install(lock_file = '//:a.json')\nmaven.install()\nmaven.install(name = 'b')";
        let doubt = "MODULE.bazel:3: this tag and the one at MODULE.bazel:2 name different locks";
        assert_eq!(
            hub(split),
            (
                vec!["b MODULE.bazel:4 -".to_string()],
                vec![doubt.to_string()]
            )
        );
    }

    #[test]
    fn a_v2_and_a_v3_lock_give_the_version_and_the_jar_sum() {
        for (lock, format) in [(lock_69(), 2), (lock_72(), 3)] {
            let lock = Lock::parse(&lock).unwrap();
            // The jar without a classifier, beside two with one.
            let jar = lock
                .plain_jar("io.netty", "netty-tcnative-boringssl-static")
                .unwrap();
            let pinned = Pinned {
                version: "2.0.61.Final".to_string(),
                jar_sha256: Some(NETTY_JAR.to_string()),
                fetched: true,
            };
            assert_eq!((lock.format, jar), (format, &pinned));
            assert_eq!(lock.plain_jar("io.netty", "netty"), None);
        }
    }

    #[test]
    fn a_classifier_or_a_packaging_key_is_not_the_plain_jar() {
        let lock = Lock::parse(LOCK_SKIPS).unwrap();
        assert!(
            lock.plain_jar("com.almworks.sqlite4java", "sqlite4java")
                .unwrap()
                .fetched
        );
        for (group, artifact) in [
            ("com.almworks.sqlite4java", "libsqlite4java-osx"),
            ("com.almworks.sqlite4java", "libsqlite4java-osx:dylib"),
            ("org.example", "only-sources"),
        ] {
            assert_eq!(lock.plain_jar(group, artifact), None, "{artifact}");
        }
    }

    #[test]
    fn a_skipped_or_unlisted_artifact_is_not_fetched() {
        let lock = Lock::parse(LOCK_SKIPS).unwrap();
        let plexus = lock.plain_jar("org.codehaus.plexus", "plexus").unwrap();
        assert_eq!(
            (plexus.version.as_str(), &plexus.jar_sha256, plexus.fetched),
            ("1.0.4", &None, false)
        );
        let unlisted = lock.plain_jar("org.example", "unlisted").unwrap();
        assert_eq!(
            (unlisted.jar_sha256.as_deref(), unlisted.fetched),
            (Some("11"), false)
        );
        // Listed with a sum, and skipped all the same.
        let skipped = LOCK_SKIPS.replace(
            r#"["org.codehaus.plexus:plexus"]"#,
            r#"["org.example:unlisted", "com.almworks.sqlite4java:sqlite4java"]"#,
        );
        let lock = Lock::parse(&skipped).unwrap();
        assert!(
            !lock
                .plain_jar("com.almworks.sqlite4java", "sqlite4java")
                .unwrap()
                .fetched
        );
    }

    #[test]
    fn an_empty_v1_conflicted_or_broken_lock_is_not_read() {
        let conflicted = lock_72().replace("\"artifacts\"", "<<<<<<< HEAD\n\"artifacts\"");
        let other = "it is not a lock of format 2 or 3";
        for (text, why) in [
            ("", "it is empty: the hub is not pinned yet"),
            (" \n", "it is empty: the hub is not pinned yet"),
            (r#"{"dependency_tree": {"dependencies": []}}"#, other),
            (r#"{"artifacts": {}, "version": "4"}"#, other),
            (r#"{"artifacts": {}, "version": 3}"#, "it is no lock ("),
            (
                r#"{"artifacts": {"a:b": {"shasums": {}}}, "version": "3"}"#,
                "it is no lock (",
            ),
            (r#"{"artifacts": [], "version": "3"}"#, "it is no lock ("),
            (&conflicted, "it is no lock ("),
            ("[]", "it is no lock ("),
        ] {
            let said = Lock::parse(text).unwrap_err();
            assert!(said.starts_with(why), "{text:?}: {said}");
        }
    }

    #[test]
    fn built_is_yes_only_at_the_locked_version() {
        let lock = lock_72();
        let hubs = Hubs::read(&view(&[
            ("MODULE.bazel", PINNED),
            ("maven_install.json", &lock),
        ]));
        let built = |artifact, version| hubs.built("io.netty", artifact, version);
        let Built::Yes(by) = built("netty-tcnative-classes", "2.0.61.Final") else {
            panic!("not built");
        };
        let [(hub, jar)] = by[..] else {
            panic!("{by:?}");
        };
        assert_eq!(
            (hub.name.as_str(), hub.line, jar.version.as_str()),
            ("maven", 4, "2.0.61.Final")
        );
        for (artifact, version) in [
            ("netty-tcnative-classes", "2.0.62.Final"),
            ("netty-tcnative-classes", "2.0.61.Final-socket.0a1b2c3d"),
            ("netty-tcnative-classes", ""),
            ("netty-tcnative", "2.0.61.Final"),
        ] {
            assert_eq!(built(artifact, version), Built::No, "{artifact} {version}");
        }
        // Not what the lock holds without a jar to fetch.
        let hubs = Hubs::read(&view(&[
            ("MODULE.bazel", PINNED),
            ("maven_install.json", LOCK_SKIPS),
        ]));
        assert_eq!(
            hubs.built("org.codehaus.plexus", "plexus", "1.0.4"),
            Built::No
        );
        assert_eq!(hubs.built("org.example", "unlisted", "1.0"), Built::No);
    }

    #[test]
    fn built_is_no_when_every_hub_is_pinned_and_none_holds_it() {
        let second =
            format!("{PINNED}maven.install(name = \"tools\", lock_file = \"//:tools.json\")\n");
        let (netty, other) = (lock_69(), LOCK_SKIPS);
        for (files, said) in [
            (vec![], "no"),
            (vec![("MODULE.bazel", "module(name = 'no_java')\n")], "no"),
            (
                vec![("MODULE.bazel", PINNED), ("maven_install.json", other)],
                "no",
            ),
            (
                vec![
                    ("MODULE.bazel", &second),
                    ("maven_install.json", other),
                    ("tools.json", other),
                ],
                "no",
            ),
            (
                vec![
                    ("MODULE.bazel", &second),
                    ("maven_install.json", other),
                    ("tools.json", &netty),
                ],
                "yes, 1",
            ),
            (
                vec![
                    ("MODULE.bazel", &second),
                    ("maven_install.json", &netty),
                    ("tools.json", &netty),
                ],
                "yes, 2",
            ),
        ] {
            assert_eq!(
                built(&files),
                said,
                "{:?}",
                files.iter().map(|f| f.0).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn a_lockless_hub_or_a_doubt_is_unknown() {
        let lockless = PINNED.replace("    lock_file = \"//:maven_install.json\",\n", "");
        let computed = PINNED.replace("\"//:maven_install.json\"", "LOCK");
        let beside = format!("{PINNED}maven.install(name = \"tools\")\n");
        let odd = format!("{PINNED}print(use_repo)\n");
        // A second tag of the hub that the ruleset takes the lock from,
        // and one that may be of any hub.
        let later = format!("{PINNED}LOCK = \"//:b.json\"\nmaven.install(lock_file = LOCK)\n");
        let unnamed = format!("{PINNED}maven.install(name = NAME, lock_file = \"//:b.json\")\n");
        let over = |tag: &str| format!("{PINNED}maven.override({tag}, target = \"//lib:netty\")\n");
        let overridden = over("coordinates = \"io.netty:netty-tcnative-classes\"");
        // As the ruleset matches it: by the name of the artifact's target,
        // for every hub at 6.5.
        let by_target = over("name = \"tools\", coordinates = \"io_netty_netty-tcnative.classes\"");
        let another = over("coordinates = \"io.netty:netty-tcnative-boringssl-static\"");
        let unread = over("coordinates = NETTY");
        let (netty, other) = (lock_72(), LOCK_SKIPS);
        let gives = "MODULE.bazel:9: a `maven.override` gives this artifact another target";
        for (module, lock, said) in [
            (
                lockless.as_str(),
                None,
                "MODULE.bazel:4: hub \"maven\" has no `lock_file`",
            ),
            (
                &computed,
                None,
                "MODULE.bazel:4: the `lock_file` of this hub is not a file of this repository",
            ),
            (PINNED, None, "maven_install.json:0: it does not exist"),
            (
                PINNED,
                Some(""),
                "maven_install.json:0: it is empty: the hub is not pinned yet",
            ),
            (
                PINNED,
                Some("{}"),
                "maven_install.json:0: it is not a lock of format 2 or 3",
            ),
            (
                &beside,
                Some(other),
                "MODULE.bazel:9: hub \"tools\" has no `lock_file`",
            ),
            // A hub that holds the jar is an answer, whatever another hub
            // leaves unread.
            (&beside, Some(&netty), "yes, 1"),
            // Not when the tags of the hub itself may be others than the
            // ones read: the ruleset takes the lock of the last.
            (
                &odd,
                Some(&netty),
                "MODULE.bazel:9: `use_repo` is used other than to call it",
            ),
            (
                &later,
                Some(&netty),
                "MODULE.bazel:10: the `lock_file` of this hub is not a file of this repository",
            ),
            (
                &unnamed,
                Some(&netty),
                "MODULE.bazel:9: the `name` of this hub is not a repository name in a string",
            ),
            // And not when an override puts another target in its place,
            // which matters only for a jar that a hub fetches.
            (&overridden, Some(&netty), gives),
            (&by_target, Some(&netty), gives),
            (
                &unread,
                Some(&netty),
                "MODULE.bazel:9: this `maven.override` cannot be read",
            ),
            (&another, Some(&netty), "yes, 1"),
            (&overridden, Some(other), "no"),
            (&unread, Some(other), "no"),
        ] {
            let mut files = vec![("MODULE.bazel", module)];
            files.extend(lock.map(|lock| ("maven_install.json", lock)));
            assert_eq!(built(&files), said, "{module}");
        }
        // The view's own reason for a lock it does not hand out.
        let files = [("MODULE.bazel", PINNED)];
        let unreadable = |path: &str| match path {
            "maven_install.json" => Entry::Unreadable("it is larger than 16 MiB".to_string()),
            path => view(&files)(path),
        };
        let hubs = Hubs::read(&unreadable);
        let Built::Unknown(doubt) =
            hubs.built("io.netty", "netty-tcnative-classes", "2.0.61.Final")
        else {
            panic!("read");
        };
        assert_eq!(doubt.why, "it cannot be read: it is larger than 16 MiB");
    }

    #[test]
    fn a_workspace_file_that_calls_maven_install_is_unknown_below_bazel_9() {
        let direct = "load('@rules_jvm_external//:defs.bzl', 'maven_install')\n\nmaven_install(\n    artifacts = [],\n)\n";
        let renamed =
            "load('@rules_jvm_external//:defs.bzl', pin = 'maven_install')\npin(artifacts = [])\n";
        let none =
            "workspace(name = 'w')\nmaven_install = 1\nhttp_archive(name = 'maven_install')\n";
        let why = "a `maven_install` of a WORKSPACE file is not read";
        for (name, text, line) in [
            ("WORKSPACE", direct, 3),
            ("WORKSPACE.bazel", direct, 3),
            ("WORKSPACE.bzlmod", renamed, 2),
        ] {
            let said = format!("{name}:{line}: {why}");
            for (release, expected) in [
                (None, said.as_str()),
                (Some("7.7.2\n"), &said),
                (Some("8.8.2\n"), &said),
                (Some("latest\n"), &said),
                (Some("9.0.0\n"), "no"),
                (Some("9.3.2\n"), "no"),
            ] {
                let mut files = vec![(name, text)];
                files.extend(release.map(|release| (".bazelversion", release)));
                assert_eq!(built(&files), expected, "{name} {release:?}");
                // Beside a hub that holds the jar, the hub answers.
                let lock = lock_72();
                files.extend([
                    ("MODULE.bazel", PINNED),
                    ("maven_install.json", lock.as_str()),
                ]);
                assert_eq!(built(&files), "yes, 1", "{name} {release:?}");
            }
        }
        // A file without the call says nothing, and of the three Bazel
        // reads the first that is there, alone.
        let shadowed = [
            ("WORKSPACE.bzlmod", none),
            ("WORKSPACE.bazel", direct),
            ("WORKSPACE", direct),
        ];
        assert_eq!(built(&shadowed[..1]), "no");
        assert_eq!(built(&shadowed), "no");
        assert_eq!(built(&shadowed[1..]), format!("WORKSPACE.bazel:3: {why}"));
        // One that cannot be read may call it, unless Bazel 9 leaves it.
        let open = [
            ("WORKSPACE", "maven_install(\n"),
            (".bazelversion", "9.0.0\n"),
        ];
        assert_eq!(built(&open[..1]), "WORKSPACE:1: a bracket is never closed");
        assert_eq!(built(&open), "no");
    }

    /// A project directory with the files `files`, in a checkout of its
    /// own.
    fn project(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        for (path, text) in files {
            std::fs::write(dir.path().join(path), text).unwrap();
        }
        dir
    }

    const NETTY_PURL: &str = "pkg:maven/io.netty/netty-tcnative-classes@2.0.61.Final";

    #[test]
    fn a_notice_names_the_lock_and_the_hub_or_what_was_not_read() {
        // A lock larger than the 1 MiB of a Starlark file.
        let lock = lock_72() + &" ".repeat(1 << 20);
        let dir = project(&[("MODULE.bazel", PINNED), ("maven_install.json", &lock)]);
        let purls = |purls: &[&str]| purls.iter().map(|purl| purl.to_string()).collect();
        // Once per jar, whatever else the command patched, and not for a
        // version, a classifier or a packaging the lock does not hold.
        let asked = purls(&[
            NETTY_PURL,
            "pkg:npm/left-pad@1.3.0",
            "pkg:maven/io.netty/netty-tcnative-classes@2.0.62.Final",
            "pkg:maven/io.netty/netty-tcnative-classes@2.0.61.Final?classifier=sources",
            "pkg:maven/io.netty/netty-tcnative-classes@2.0.61.Final?type=aar",
            NETTY_PURL,
        ]);
        let said = notices_blocking(dir.path(), asked);
        let detail = format!(
            "{NETTY_PURL}: Bazel takes this artifact from maven_install.json (hub \"maven\", \
             `maven.install` at MODULE.bazel:4), which pins the upstream jar. socket-patch does \
             not patch a rules_jvm_external hub yet, so the Bazel build stays unpatched whatever \
             this command did for another build of the checkout"
        );
        assert_eq!(said, [(HUB_UNPATCHED, detail.clone())]);
        // The same for a project below the Bazel root of its checkout.
        let below = dir.path().join("services/billing");
        std::fs::create_dir_all(&below).unwrap();
        let said = notices_blocking(&below, purls(&[NETTY_PURL]));
        assert_eq!(said, [(HUB_UNPATCHED, detail)]);
        // What cannot be read is said for every Maven jar of the run.
        std::fs::write(dir.path().join("maven_install.json"), "").unwrap();
        let said = notices_blocking(dir.path(), purls(&[NETTY_PURL, "pkg:maven/a.b/c@1"]));
        let why = "could not tell whether Bazel takes this artifact from a \
                   rules_jvm_external hub: maven_install.json: it is empty: the hub is not \
                   pinned yet";
        let expected = ["pkg:maven/a.b/c@1", NETTY_PURL]
            .map(|purl| (UNREADABLE, format!("{purl}: socket-patch {why}")));
        assert_eq!(said, expected);
        // And a lock over the bound is not read.
        let large = lock + &" ".repeat(MAX_LOCK);
        std::fs::write(dir.path().join("maven_install.json"), large).unwrap();
        let said = notices_blocking(dir.path(), purls(&[NETTY_PURL]));
        let why = "hub: maven_install.json: it cannot be read: it is larger than 16 MiB";
        assert!(said[0].1.ends_with(why), "{said:?}");
        std::fs::remove_file(dir.path().join("maven_install.json")).unwrap();
        let lockless = PINNED.replace("    lock_file = \"//:maven_install.json\",\n", "");
        std::fs::write(dir.path().join("MODULE.bazel"), lockless).unwrap();
        let said = notices_blocking(dir.path(), purls(&[NETTY_PURL]));
        assert!(
            said[0]
                .1
                .ends_with("hub: MODULE.bazel:4: hub \"maven\" has no `lock_file`"),
            "{said:?}"
        );
        // A directory that has the name of a `WORKSPACE` file is none, as
        // for Bazel, and a file that cannot be read is said with its reason.
        let odd = project(&[("MODULE.bazel", "module(name = 'no_java')\n")]);
        std::fs::create_dir(odd.path().join("WORKSPACE")).unwrap();
        assert_eq!(notices_blocking(odd.path(), purls(&[NETTY_PURL])), []);
        std::fs::write(odd.path().join("WORKSPACE.bazel"), "maven_install(\n").unwrap();
        let said = notices_blocking(odd.path(), purls(&[NETTY_PURL]));
        assert!(
            said[0]
                .1
                .ends_with("hub: WORKSPACE.bazel:1: a bracket is never closed"),
            "{said:?}"
        );
    }

    #[test]
    fn outside_a_bazel_workspace_or_without_a_maven_patch_nothing_is_said() {
        let lock = lock_72();
        let maven = vec![NETTY_PURL.to_string()];
        // A Maven project with a lock of that name and no workspace file,
        // and one below a workspace that its checkout does not reach.
        let plain = project(&[("pom.xml", "<project/>"), ("maven_install.json", &lock)]);
        assert_eq!(notices_blocking(plain.path(), maven.clone()), []);
        let outer = project(&[("MODULE.bazel", PINNED), ("maven_install.json", &lock)]);
        let inner = outer.path().join("inner");
        std::fs::create_dir_all(inner.join(".git")).unwrap();
        assert_eq!(notices_blocking(&inner, maven.clone()), []);
        // In the workspace: a hub that cannot be read says nothing for a
        // run without a Maven jar.
        let broken = project(&[("MODULE.bazel", PINNED)]);
        assert_eq!(notices_blocking(broken.path(), maven).len(), 1);
        let others = [
            "pkg:npm/a@1",
            "pkg:maven/a/b@1?classifier=tests",
            "pkg:maven/broken",
        ];
        let others = others.map(String::from).to_vec();
        assert_eq!(notices_blocking(broken.path(), others), []);
        assert_eq!(notices_blocking(broken.path(), Vec::new()), []);
    }
}
