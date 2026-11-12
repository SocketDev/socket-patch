//! Remedy text (design 2.10 and 4.3): the command a works-after advisory
//! or a refusal names, and the two manual procedures that follow a refusal.
//!
//! The reader pastes this text into a shell, so it follows the six rules of
//! the remedy matrix and what the probes that ran these commands found (L2,
//! L3.c, R5, Y6):
//!
//! - `MODULE.bazel.lock` is refreshed by [`LOCK_REFRESH`] and by nothing
//!   else as a first step. The flag is spelled out, because `mod` inherits
//!   nothing from a `build` rc line and a plain `bazel mod deps` does
//!   nothing on Bazel 6. It is the last argument, because a `--config`
//!   after it can set the mode back. No `--config` is printed at all: one
//!   that is defined only for `build` is an error for `mod`.
//! - The same command in `error` mode is never printed as a check: it
//!   exits 2 on a healthy lock that builds wrote.
//! - `bazel clean --expunge` is only ever a second step, for the Bazel
//!   releases that hide stale facts behind a warm output base.
//! - A repin names the ruleset's own variable. Bare `REPIN` would repin
//!   rules_jvm_external too. `bazel sync` is printed for a WORKSPACE hub
//!   only: it never evaluates a module extension, and Bazel 9 has no such
//!   command.
//! - A repository name or a label is the project's own, and it is printed
//!   only when it is a plain name. Grant tokens live in URLs, and no URL is
//!   ever copied into a remedy.
//! - A procedure that would erase the pin is not offered as a fix.
//!
//! socket-patch runs none of these commands, and it never snapshots or
//! restores `MODULE.bazel.lock`: a restored lock is exactly what creates
//! the hidden stale-facts state on Bazel 8.6 to 9.2.

use super::model::{DeclSystem, RunKind, RunRequired};
use super::module_lock::GENERAL;
use super::rc::{Chain, EffectiveFlags, Flag};
use super::version::{BazelLine, BazelVersion, Tri};

/// The one command that refreshes `MODULE.bazel.lock`, alone and with the
/// flag last.
pub const LOCK_REFRESH: &str = "bazel mod deps --lockfile_mode=update";

/// `mod deps` evaluates every extension of every module, so the first run
/// on a lock that only builds wrote grew it from 115 to 1,635 lines on
/// 7.7.2 and from 167 to 2,711 on 8.8.2 (probe L2.b).
const FIRST_RUN: &str = "The first run records every module extension, also the ones no build \
    evaluated, so the lock diff can be much larger than the patch, and it needs the network.";

/// Probe L3.c: on 8.6.0 to 9.2.0 a lock with old facts, put back after an
/// `update`-mode run, passes locally and survives the refresh.
const EXPUNGE: &str = "On Bazel 8.5 to 9.2: if MODULE.bazel.lock is unchanged afterwards and CI \
    still reports changed facts, run `bazel clean --expunge` and repeat the command. Those \
    releases keep stale facts behind a warm output base once a lock with old facts was put \
    back after an update-mode run.";

/// What a remedy tells the user to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remedy {
    /// What the command refreshes. `None` for a procedure that refreshes
    /// no state socket-patch tracks, and where no command exists.
    pub kind: Option<RunKind>,
    /// The one command; empty where none exists.
    pub command: String,
    /// The platform keys of the lock entries the command refreshes, each
    /// only on its own platform. Empty: one run anywhere.
    pub platforms: Vec<String>,
    /// The ordered manual procedure, when the remedy is more than its
    /// command. Each step is a sentence.
    pub steps: Vec<String>,
    /// What else the user has to know, in order.
    pub notes: Vec<String>,
}

impl Remedy {
    fn run(kind: RunKind, command: String) -> Self {
        Self {
            kind: Some(kind),
            command,
            platforms: Vec::new(),
            steps: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// No command helps: `why` says what to do instead.
    pub fn unavailable(why: &str) -> Self {
        Self {
            kind: None,
            command: String::new(),
            platforms: Vec::new(),
            steps: Vec::new(),
            notes: vec![why.to_string()],
        }
    }

    /// The remedy as the end of an advisory or refusal detail: the steps
    /// or the command, then the notes.
    pub fn text(&self) -> String {
        let mut parts = self.steps.clone();
        if parts.is_empty() && !self.command.is_empty() {
            parts.push(run_sentence(&self.command, &self.platforms));
        }
        parts.extend(self.notes.iter().cloned());
        parts.join(" ")
    }

    /// The manual procedure as numbered lines, for a refusal's snippet.
    pub fn snippet(&self) -> Option<String> {
        let numbered = self.steps.iter().enumerate();
        let lines: Vec<String> = numbered.map(|(i, s)| format!("{}. {s}", i + 1)).collect();
        (!lines.is_empty()).then(|| lines.join("\n"))
    }

    /// The advisory this remedy rides on. `None` where it names no command
    /// that refreshes tracked state.
    pub fn run_required(&self, gates_vex: bool) -> Option<RunRequired> {
        Some(RunRequired {
            kind: self.kind.filter(|_| !self.command.is_empty())?,
            command: self.command.clone(),
            platforms: self.platforms.clone(),
            gates_vex,
        })
    }
}

/// What remedy text may say about the workspace. Every field is something
/// a static read proved.
#[derive(Debug, Clone, Copy)]
pub struct Cx<'a> {
    pub line: &'a BazelLine,
    /// A tracked rc file sets or may set `--experimental_strict_repo_env`
    /// ([`strict_repo_env`]): a variable in front of the command is then
    /// not seen by a repository rule.
    pub strict_repo_env: bool,
    /// The lock holds facts or can come to hold them:
    /// `derived::facts_in_lock`, which `derived::decide` and
    /// `Evidence::withhold` apply themselves.
    pub facts_in_lock: bool,
    /// The hub's apparent name (`use_repo`, or the WORKSPACE `name`), for
    /// a ruleset whose real-Bazel cell ran the targeted query refresh
    /// (probe L2.f ran it on the toy, rules_python and gazelle).
    pub query_hub: Option<&'a str>,
}

/// Whether a tracked rc file sets or may set
/// `--experimental_strict_repo_env` for a command a repin runs through.
pub fn strict_repo_env(flags: &EffectiveFlags) -> bool {
    [Chain::Build, Chain::Mod, Chain::Sync].iter().any(|chain| {
        let state = flags.state(Flag::StrictRepoEnv, *chain);
        state.values().iter().any(|value| value.as_str() == "true")
    })
}

/// `text` as remedy text may print it, or `fallback`. A name, a label, an
/// extension id or a platform key from a workspace file is short and made
/// of the characters below. Anything else is not printed: a URL (which is
/// where a grant token lives), whitespace, or a character a shell acts on.
fn plain<'a>(text: &'a str, fallback: &'a str) -> &'a str {
    let allowed = |b: u8| b.is_ascii_alphanumeric() || b"_.-+~/:@%,".contains(&b);
    let ok = !text.is_empty() && text.len() <= 160 && !text.contains("://");
    if ok && text.bytes().all(allowed) {
        text
    } else {
        fallback
    }
}

fn run_sentence(command: &str, platforms: &[String]) -> String {
    if platforms.is_empty() {
        return format!("Run `{command}` and commit the result.");
    }
    format!(
        "Run `{command}` on each platform the lock records an entry for ({}) and commit the \
         result: an entry keyed by OS and architecture is refreshed only on its own platform.",
        platforms.join("; ")
    )
}

fn platform_keys(platforms: &[String]) -> Vec<String> {
    let keys = platforms.iter().map(|key| plain(key, "<platform>"));
    keys.map(str::to_string).collect()
}

/// Whether the line may run a release that hides stale facts (8.5 to 9.2;
/// 9.3.2 and 10.0.0rc3 report and repair them warm).
fn hides_stale_facts(line: &BazelLine) -> bool {
    let (first, fixed) = (BazelVersion::new(8, 5, 0), BazelVersion::new(9, 3, 0));
    line.at_least(first) != Tri::No && line.at_least(fixed) != Tri::Yes
}

/// The refresh of `MODULE.bazel.lock` (design 2.10): [`LOCK_REFRESH`], to
/// be run on each of `platforms`, and the three sentences of the advisory.
pub fn lock_refresh(cx: &Cx<'_>, platforms: &[String]) -> Remedy {
    let fallback = match cx.query_hub.map(|hub| plain(hub, "")) {
        Some(hub) if !hub.is_empty() => format!(
            "If it fails on an extension the build does not use, `bazel query @{hub}//:all \
             --lockfile_mode=update` refreshes only the stale entry, and so does `bazel build \
             //... --lockfile_mode=update`."
        ),
        _ => "If it fails on an extension the build does not use, `bazel build //... \
              --lockfile_mode=update` refreshes only the entries the build evaluates."
            .to_string(),
    };
    let mut notes = vec![FIRST_RUN.to_string(), fallback];
    if cx.facts_in_lock && hides_stale_facts(cx.line) {
        notes.push(EXPUNGE.to_string());
    }
    Remedy {
        platforms: platform_keys(platforms),
        notes,
        ..Remedy::run(RunKind::Lockfile, LOCK_REFRESH.to_string())
    }
}

/// The repair of a lock entry whose recorded digest is current while its
/// repositories are not, which is what a hand-resolved merge of the lock
/// leaves (probe L1.d). Bazel trusts such an entry in every mode and the
/// refresh alone does not heal it; a deleted entry fails closed and the
/// refresh writes it again in full (probe L1.e).
///
/// `platforms` are the keys of the forged members of an entry keyed by OS
/// and architecture; empty (or `general`) for an entry with one member.
/// Only those members are deleted, and the command is named for the same
/// keys: an `error`-mode build fails on a platform whose member is gone,
/// and the refresh writes back only the member of the platform it runs on
/// (probe L4), so a member deleted without need would stay missing.
pub fn delete_entry(extension: &str, platforms: &[String]) -> Remedy {
    let keyed: Vec<String> = platforms
        .iter()
        .filter(|k| *k != GENERAL)
        .cloned()
        .collect();
    let platforms = platform_keys(&keyed);
    let extension = plain(extension, "<extension>");
    let steps = if platforms.is_empty() {
        vec![
            format!(
                "Delete the `{extension}` entry under `moduleExtensions` in MODULE.bazel.lock."
            ),
            run_sentence(LOCK_REFRESH, &platforms),
        ]
    } else {
        let quoted: Vec<String> = platforms.iter().map(|key| format!("`{key}`")).collect();
        let (members, each) = match quoted.as_slice() {
            [one] => (format!("{one} member"), "that platform"),
            many => (
                format!("{} members", many.join(", ")),
                "each of those platforms",
            ),
        };
        vec![
            format!(
                "Delete the {members} of the `{extension}` entry under `moduleExtensions` in \
                 MODULE.bazel.lock, and leave its other members."
            ),
            format!(
                "Run `{LOCK_REFRESH}` on {each} and commit the result: an entry keyed by OS \
                 and architecture is written only on its own platform."
            ),
        ]
    };
    let why = "The entry records the current digest of its input beside repositories from before \
               the pin, so Bazel reuses it and builds the unpatched package, and the refresh alone \
               leaves it as it is.";
    Remedy {
        platforms,
        steps,
        notes: vec![why.to_string()],
        ..Remedy::run(RunKind::Lockfile, LOCK_REFRESH.to_string())
    }
}

/// The repin of a crate_universe hub with a `lockfile` (`kind: repin`):
/// until it has run the build fails with `Digests do not match`, under
/// every lockfile mode. `None` where no command exists: `bazel sync`,
/// which a WORKSPACE hub needs, is gone in Bazel 9.
///
/// No `bazel mod deps --lockfile_mode=update` follows: nothing about the
/// repin reaches `MODULE.bazel.lock` for such a hub, and that command
/// added 2,607 unrelated lines in probe R5.
pub fn repin(cx: &Cx<'_>, hub: &str, system: DeclSystem) -> Option<Remedy> {
    let mut notes = vec!["Until it has run, the build fails with `Digests do not match`.".into()];
    let command = match system {
        DeclSystem::Bzlmod => "bazel mod deps".to_string(),
        DeclSystem::Workspace => {
            // A candidate orders below its release, and `sync` changed with
            // the first candidate of each major: 9.0.0rc1 has no such
            // command, and on 8.0.0rc1 it already fails without the flag.
            // So each bound counts as the release it is a candidate of.
            let line = BazelLine {
                lo: cx.line.lo.map(BazelVersion::release),
                hi: cx.line.hi.map(BazelVersion::release),
                evidence: Vec::new(),
            };
            if line.at_least(BazelVersion::new(9, 0, 0)) == Tri::Yes {
                return None;
            }
            let flag = match line.at_least(BazelVersion::new(8, 0, 0)) {
                Tri::Yes => " --enable_workspace",
                Tri::Maybe => {
                    notes.push(
                        "On Bazel 8 add `--enable_workspace` to it: `sync` does not inherit the \
                         flag from a `build` rc line."
                            .to_string(),
                    );
                    ""
                }
                Tri::No => "",
            };
            format!("bazel sync --only={}{flag}", plain(hub, "<hub>"))
        }
    };
    // Under strict mode only `--repo_env` values reach a repository rule.
    let command = if cx.strict_repo_env {
        format!("{command} --repo_env=CARGO_BAZEL_REPIN=1")
    } else {
        format!("CARGO_BAZEL_REPIN=1 {command}")
    };
    Some(Remedy {
        notes,
        ..Remedy::run(RunKind::Repin, command)
    })
}

/// The manual procedure for a crate_universe hub with a `lockfile`, which
/// every mode refuses (design 4.3; probes R2 and R5). It starts with the
/// `cargo_config` edit: the splicer installs only the file that attribute
/// names, and without the registry table in it the repin exits 2 with
/// `registry index was not found in any configuration`. `cargo_config` is
/// the label the tag already has, if any. `None` as for [`repin`].
pub fn crate_universe_snippet(
    cx: &Cx<'_>,
    hub: &str,
    system: DeclSystem,
    cargo_config: Option<&str>,
) -> Option<Remedy> {
    let repin = repin(cx, hub, system)?;
    let table = "[registries.socket-patch-<uuid>]";
    let config = match cargo_config.map(|label| plain(label, "")) {
        Some(label) if !label.is_empty() => format!(
            "Put the `{table}` table into the file `cargo_config` names (`{label}`): the \
             splicer installs only that file."
        ),
        _ => format!(
            "Set `cargo_config` on the `{}` hub to the file that holds the `{table}` table: \
             the splicer installs only the file that attribute names.",
            plain(hub, "<hub>")
        ),
    };
    let edits = format!(
        "Make the three edits of the hosted redirect: `registry = \"socket-patch-<uuid>\"` on \
         the dependency in `Cargo.toml`, the `{table}` table in that config file, and the \
         crate's `source` and `checksum` in `Cargo.lock`."
    );
    let run = format!("Repin: `{}`.", repin.command);
    Some(Remedy {
        steps: vec![config, edits, run],
        ..repin
    })
}

/// The check target of a `compile_pip_requirements(name = ...)` macro:
/// `<name>.test` from rules_python 1.5.0, `<name>_test` below.
/// `dot_test` says whether the ruleset is proven at or above 1.5.0.
pub fn pip_compile_check(target: &str, dot_test: Tri) -> String {
    let target = plain(target, "<target>");
    match dot_test {
        Tri::Yes => format!("`{target}.test`"),
        Tri::No => format!("`{target}_test`"),
        Tri::Maybe => {
            format!("`{target}.test` (`{target}_test` on rules_python below 1.5.0)")
        }
    }
}

/// The manual procedure for a requirements lock that only a
/// `gazelle_python_manifest` checks (design 6): the pin goes into the lock
/// by hand, then the manifest's own update runs. That update regenerates
/// the manifest, whose `integrity` covers the bytes of the lock, and
/// never writes the lock, so the pin stays (remedy matrix 1.2, row 8).
pub fn gazelle_manifest(target: &str) -> Remedy {
    let update = format!("bazel run {}.update", plain(target, "<target>"));
    let steps = vec![
        "Write the pin into the lock by hand: replace the package's entry with its direct \
         reference (its name, ` @ ` and the patch URL)."
            .to_string(),
        format!(
            "Run `{update}`: it rewrites only the manifest, whose `integrity` covers the bytes \
             of the lock, and leaves the pin in place."
        ),
    ];
    Remedy {
        kind: None,
        command: update,
        platforms: Vec::new(),
        steps,
        notes: Vec::new(),
    }
}

/// What to do about a diff test over a checked-in `requirements.bzl`
/// (remedy matrix 1.2, row 14). The file is generated from the lock by a
/// target the project defines, so no command can be named; unlike the
/// update of a pip-compile check, that regeneration reads the lock and
/// keeps the pin.
pub fn requirements_bzl() -> Remedy {
    Remedy::unavailable(
        "A diff test compares the checked-in `requirements.bzl` with this lock. The target that \
         regenerates the file is the project's own (the rules_python example names it \
         `//:vendor_requirements`); it reads the lock and does not drop the pin, so write the \
         pin by hand and then run that target.",
    )
}

/// The manual procedure for a requirements file that a
/// `compile_pip_requirements` target checks (design 4.3): the sequence
/// probe Y6 ran. pip-compile keeps only what its `.in` source names, so a
/// reference written to the lock alone fails the check, and the update
/// that fixes the check drops the reference.
pub fn pip_compile_snippet(target: &str, dot_test: Tri) -> Remedy {
    let update = format!("bazel run {}.update", plain(target, "<target>"));
    let steps = vec![
        "Add the package's direct reference (its name, ` @ ` and the patch URL) to the `.in` \
         source of the lock: pip-compile keeps only what that file names."
            .to_string(),
        format!(
            "Run `{update}` twice: over a lock that still holds the `==` entry the first run \
             copies the upstream hash onto the patch URL, and the second writes the patch's \
             own hash."
        ),
        "Run `socket-patch scan` again: it compares the pinned digest with the patch and \
         reports a hash that was carried over."
            .to_string(),
    ];
    let check = format!(
        "The check target is {}.",
        pip_compile_check(target, dot_test)
    );
    Remedy {
        kind: None,
        command: update,
        platforms: Vec::new(),
        steps,
        notes: vec![check],
    }
}

#[cfg(test)]
mod tests {
    use super::super::rc::testing::Files;
    use super::*;

    const EXPUNGE_COMMAND: &str = "clean --expunge";

    /// The line of one release; no line for `""`.
    fn line(version: &str) -> BazelLine {
        if version.is_empty() {
            return BazelLine::unknown();
        }
        BazelLine::of(BazelVersion::parse(version).expect("a release"))
    }

    /// Every line the tests print remedies for: the pinned releases, the
    /// first candidates of 8 and 9, the two ends of the hidden-facts
    /// range, a floating major and no line.
    fn lines() -> Vec<BazelLine> {
        let exact = [
            "5.4.1",
            "6.6.0",
            "7.0.2",
            "7.7.2",
            "8.0.0rc1",
            "8.4.2",
            "8.5.0",
            "8.8.2",
            "9.0.0rc1",
            "9.2.0",
            "9.3.0",
            "9.3.2",
            "10.0.0rc3",
        ];
        let mut lines: Vec<BazelLine> = exact.iter().map(|version| line(version)).collect();
        for major in [8, 9] {
            lines.push(BazelLine {
                lo: Some(BazelVersion::new(major, 0, 0)),
                hi: Some(BazelVersion::ceiling(major)),
                evidence: Vec::new(),
            });
        }
        lines.push(BazelLine::unknown());
        lines
    }

    /// Every remedy this module can produce over [`lines`], with and
    /// without facts, strict mode, a hub for the query, platform keys, a
    /// declared `cargo_config`, and each naming of the check target.
    fn every_remedy() -> Vec<(String, Remedy)> {
        let platforms = [
            "os:linux,arch:amd64".to_string(),
            "os:osx,arch:aarch64".to_string(),
        ];
        let mut out = Vec::new();
        for line in &lines() {
            for bits in 0..8u8 {
                let cx = Cx {
                    line,
                    strict_repo_env: bits & 1 != 0,
                    facts_in_lock: bits & 2 != 0,
                    query_hub: (bits & 4 != 0).then_some("pypi"),
                };
                let keys = &platforms[..usize::from(bits & 1) * 2];
                let config = (bits & 2 != 0).then_some("//:.cargo/config.toml");
                let what = format!("{line} {bits:03b}");
                out.push((what.clone(), lock_refresh(&cx, keys)));
                out.push((what.clone(), delete_entry("//:ext.bzl%toy", keys)));
                out.push((
                    what.clone(),
                    delete_entry("//:ext.bzl%toy", &keys[..keys.len() / 2]),
                ));
                for system in [DeclSystem::Bzlmod, DeclSystem::Workspace] {
                    let what = format!("{what} {system:?}");
                    out.extend(repin(&cx, "crates", system).map(|r| (what.clone(), r)));
                    let snippet = crate_universe_snippet(&cx, "crates", system, config);
                    out.extend(snippet.map(|r| (what, r)));
                }
            }
        }
        for dot_test in [Tri::Yes, Tri::No, Tri::Maybe] {
            let remedy = pip_compile_snippet("//third_party/py:requirements", dot_test);
            out.push((format!("pip-compile {dot_test:?}"), remedy));
        }
        let manifest = gazelle_manifest("//:gazelle_python_manifest");
        out.push(("gazelle manifest".to_string(), manifest));
        out.push(("requirements.bzl".to_string(), requirements_bzl()));
        out.push((
            "none".to_string(),
            Remedy::unavailable("Regenerate the file."),
        ));
        out
    }

    /// The text a user can see of one remedy: detail, snippet and command.
    fn shown(remedy: &Remedy) -> String {
        let snippet = remedy.snippet().unwrap_or_default();
        format!("{}\n{snippet}\n`{}`", remedy.text(), remedy.command)
    }

    /// The commands of a text: what stands between backticks and starts
    /// with a program this module prints.
    fn commands(text: &str) -> Vec<&str> {
        let quoted = text.split('`').skip(1).step_by(2);
        let command = |q: &&str| {
            ["bazel ", "CARGO_", "socket-patch "]
                .iter()
                .any(|p| q.starts_with(p))
        };
        quoted.filter(command).collect()
    }

    /// The acceptance rules that hold for every text at once.
    #[test]
    fn no_text_breaks_a_rule_of_the_remedy_matrix() {
        let all = every_remedy();
        assert!(all.len() > 400, "{}", all.len());
        let mut expunge = 0;
        for (what, remedy) in &all {
            let text = shown(remedy);
            // Never the check that fails on a healthy lock, never a
            // config, never a URL (a grant token lives in one).
            for banned in ["--lockfile_mode=error", "--config", "://"] {
                assert!(!text.contains(banned), "{what}: {banned} in\n{text}");
            }
            // `clean --expunge` is never first: the plain command comes
            // before it, in the detail and in every other rendering.
            for rendering in [remedy.text(), remedy.snippet().unwrap_or_default()] {
                if let Some(at) = rendering.find(EXPUNGE_COMMAND) {
                    expunge += 1;
                    let plain_command = rendering.find(LOCK_REFRESH);
                    assert!(
                        plain_command.is_some_and(|first| first < at),
                        "{what}: {rendering}"
                    );
                }
            }
            assert!(!remedy.command.contains(EXPUNGE_COMMAND), "{what}");
            // The namespaced variable only: bare `REPIN` repins rje too.
            for (at, _) in text.match_indices("REPIN") {
                assert!(text[..at].ends_with("CARGO_BAZEL_"), "{what}: {text}");
            }
            for command in commands(&text) {
                // The lockfile flag is spelled out and is the last
                // argument, so nothing after it can set the mode back.
                if command.contains("--lockfile_mode") {
                    assert!(
                        command.ends_with("--lockfile_mode=update"),
                        "{what}: {command}"
                    );
                }
                // A refresh of the lock never carries a repin variable:
                // a lock written with one records it.
                let refresh = command.contains("--lockfile_mode=update");
                assert!(!(refresh && command.contains("REPIN")), "{what}: {command}");
            }
        }
        assert!(expunge > 0, "no text names the second step");
    }

    #[test]
    fn the_lock_refresh_is_the_plain_command_with_three_sentences() {
        let line = line("7.7.2");
        let cx = Cx {
            line: &line,
            strict_repo_env: false,
            facts_in_lock: false,
            query_hub: Some("pypi"),
        };
        let remedy = lock_refresh(&cx, &[]);
        assert_eq!(remedy.command, "bazel mod deps --lockfile_mode=update");
        assert_eq!(remedy.kind, Some(RunKind::Lockfile));
        assert!(remedy.steps.is_empty() && remedy.snippet().is_none());
        assert_eq!(
            remedy.text(),
            "Run `bazel mod deps --lockfile_mode=update` and commit the result. The first run \
             records every module extension, also the ones no build evaluated, so the lock diff \
             can be much larger than the patch, and it needs the network. If it fails on an \
             extension the build does not use, `bazel query @pypi//:all --lockfile_mode=update` \
             refreshes only the stale entry, and so does `bazel build //... \
             --lockfile_mode=update`."
        );
        // The targeted query is claimed per ruleset: without a hub only
        // the build is named.
        let unclaimed = lock_refresh(
            &Cx {
                query_hub: None,
                ..cx
            },
            &[],
        );
        assert!(!unclaimed.text().contains("bazel query"));
        assert!(unclaimed
            .text()
            .contains("`bazel build //... --lockfile_mode=update`"));

        // Entries keyed by OS and architecture: one run per platform.
        let keys = [
            "os:linux,arch:amd64".to_string(),
            "os:osx,arch:aarch64".to_string(),
        ];
        let per_platform = lock_refresh(&cx, &keys);
        assert_eq!(per_platform.platforms, keys);
        assert!(per_platform.text().starts_with(
            "Run `bazel mod deps --lockfile_mode=update` on each platform the lock records an \
             entry for (os:linux,arch:amd64; os:osx,arch:aarch64) and commit the result"
        ));
        let advisory = per_platform.run_required(true).unwrap();
        assert_eq!(advisory.kind.as_str(), "lockfile");
        assert_eq!(
            (advisory.command.as_str(), advisory.gates_vex),
            (LOCK_REFRESH, true)
        );
        assert_eq!(advisory.platforms, keys);
        assert!(!per_platform.run_required(false).unwrap().gates_vex);
    }

    /// Probe L3.c: only 8.6.0 to 9.2.0 hide stale facts, and only a lock
    /// with facts can be in that state. The sentence is conditional and
    /// comes last.
    #[test]
    fn the_expunge_sentence_is_for_a_line_that_includes_8_5_to_9_2_with_facts() {
        for candidate in lines() {
            let cx = |facts_in_lock| Cx {
                line: &candidate,
                strict_repo_env: false,
                facts_in_lock,
                query_hub: None,
            };
            let with_facts = lock_refresh(&cx(true), &[]);
            let named = with_facts.text().contains(EXPUNGE_COMMAND);
            let expected = !matches!(
                candidate.to_string().as_str(),
                "5.4.1"
                    | "6.6.0"
                    | "7.0.2"
                    | "7.7.2"
                    | "8.0.0rc1"
                    | "8.4.2"
                    | "9.3.0"
                    | "9.3.2"
                    | "10.0.0rc3"
            );
            assert_eq!(named, expected, "{candidate}");
            if named {
                assert_eq!(with_facts.notes.len(), 3);
                assert!(with_facts.notes[2].starts_with("On Bazel 8.5 to 9.2: if "));
            }
            assert!(!lock_refresh(&cx(false), &[])
                .text()
                .contains(EXPUNGE_COMMAND));
        }
    }

    #[test]
    fn a_forged_entry_is_deleted_before_the_refresh() {
        let remedy = delete_entry("@@rules_python+//python/extensions:pip.bzl%pip", &[]);
        assert_eq!(
            remedy.snippet().unwrap(),
            "1. Delete the `@@rules_python+//python/extensions:pip.bzl%pip` entry under \
             `moduleExtensions` in MODULE.bazel.lock.\n\
             2. Run `bazel mod deps --lockfile_mode=update` and commit the result."
        );
        assert_eq!(remedy.command, LOCK_REFRESH);
        assert!(remedy.text().contains("builds the unpatched package"));
        // `general` is the key of an entry with one member: the same text.
        let general = delete_entry("//:ext.bzl%toy", &[GENERAL.to_string()]);
        assert_eq!(general, delete_entry("//:ext.bzl%toy", &[]));
        assert!(general.snippet().unwrap().starts_with(
            "1. Delete the `//:ext.bzl%toy` entry under `moduleExtensions` in MODULE.bazel.lock.\n"
        ));
    }

    /// Probe L4: with a platform's member gone the `error`-mode build of
    /// that platform fails, and the refresh writes back only the member of
    /// the platform it runs on. So only the forged members are deleted,
    /// and the command is named for exactly those platforms.
    #[test]
    fn only_the_forged_platform_members_are_deleted_and_refreshed() {
        let keys = [
            "os:linux,arch:amd64".to_string(),
            "os:osx,arch:aarch64".to_string(),
        ];
        let one = delete_entry("//:ext.bzl%toy", &keys[..1]);
        assert_eq!(
            one.snippet().unwrap(),
            "1. Delete the `os:linux,arch:amd64` member of the `//:ext.bzl%toy` entry under \
             `moduleExtensions` in MODULE.bazel.lock, and leave its other members.\n\
             2. Run `bazel mod deps --lockfile_mode=update` on that platform and commit the \
             result: an entry keyed by OS and architecture is written only on its own platform."
        );
        assert_eq!(one.platforms, keys[..1]);
        assert!(!one.text().contains("os:osx"), "{}", one.text());
        let both = delete_entry("//:ext.bzl%toy", &keys);
        assert!(both.steps[0].starts_with(
            "Delete the `os:linux,arch:amd64`, `os:osx,arch:aarch64` members of the \
             `//:ext.bzl%toy` entry"
        ));
        assert!(both.steps[1].contains("on each of those platforms"));
        assert_eq!(both.platforms, keys);
        assert_eq!(both.run_required(true).unwrap().platforms, keys);
        assert!(!both.text().contains("Delete the `//:ext.bzl%toy` entry"));
    }

    /// Probe R5: the variable in front of the command repins on 7.7.2,
    /// 8.8.2 and 9.3.2; under strict mode only `--repo_env` is seen;
    /// `bazel sync` repins a WORKSPACE hub and nothing else.
    #[test]
    fn a_repin_names_the_cargo_variable_in_the_form_the_workspace_needs() {
        let remedy = |version: &str, strict_repo_env, system| {
            let line = line(version);
            let cx = Cx {
                line: &line,
                strict_repo_env,
                facts_in_lock: true,
                query_hub: Some("crates"),
            };
            let snippet = crate_universe_snippet(&cx, "crates", system, None);
            let repin = repin(&cx, "crates", system);
            // The snippet exists exactly where the command does, and ends
            // with it.
            assert_eq!(
                snippet.map(|s| s.command),
                repin.as_ref().map(|r| r.command.clone())
            );
            repin
        };
        let command =
            |version: &str, strict, system| remedy(version, strict, system).map(|r| r.command);
        let (bzlmod, workspace) = (DeclSystem::Bzlmod, DeclSystem::Workspace);
        for version in ["7.7.2", "8.8.2", "9.3.2", ""] {
            assert_eq!(
                command(version, false, bzlmod).as_deref(),
                Some("CARGO_BAZEL_REPIN=1 bazel mod deps"),
                "{version}"
            );
            assert_eq!(
                command(version, true, bzlmod).as_deref(),
                Some("bazel mod deps --repo_env=CARGO_BAZEL_REPIN=1"),
                "{version}"
            );
        }
        assert_eq!(
            command("7.7.2", false, workspace).as_deref(),
            Some("CARGO_BAZEL_REPIN=1 bazel sync --only=crates")
        );
        // On 8.x `sync` needs the flag itself.
        assert_eq!(
            command("8.8.2", false, workspace).as_deref(),
            Some("CARGO_BAZEL_REPIN=1 bazel sync --only=crates --enable_workspace")
        );
        assert_eq!(
            command("8.8.2", true, workspace).as_deref(),
            Some("bazel sync --only=crates --enable_workspace --repo_env=CARGO_BAZEL_REPIN=1")
        );
        let unknown = remedy("", false, workspace).unwrap();
        assert_eq!(
            unknown.command,
            "CARGO_BAZEL_REPIN=1 bazel sync --only=crates"
        );
        assert!(unknown
            .text()
            .contains("On Bazel 8 add `--enable_workspace`"));
        // Bazel 9 has no `sync`: no command is printed for a hub that
        // cannot be live there. A candidate of 9.0.0 has none either
        // (`SyncCommand.java` is gone at the tag 9.0.0rc1), although it
        // orders below the release.
        for version in [
            "9.0.0rc1",
            "9.0.0rc3",
            "9.0.0",
            "9.0.2",
            "9.3.2",
            "10.0.0rc3",
        ] {
            assert_eq!(command(version, false, workspace), None, "{version}");
        }
        // On a candidate of 8.0.0 `sync` already fails without the flag.
        for version in ["8.0.0rc1", "8.0.0rc2", "8.0.0"] {
            let remedy = remedy(version, false, workspace).unwrap();
            assert_eq!(
                remedy.command, "CARGO_BAZEL_REPIN=1 bazel sync --only=crates --enable_workspace",
                "{version}"
            );
            assert!(!remedy.text().contains("On Bazel 8 add"), "{version}");
        }
        // A floating major whose bottom is a candidate is that major.
        let candidates_of = |major: u32| BazelLine {
            lo: BazelVersion::parse(&format!("{major}.0.0rc1")),
            hi: Some(BazelVersion::ceiling(major)),
            evidence: Vec::new(),
        };
        let on = |line: &BazelLine| {
            let cx = Cx {
                line,
                strict_repo_env: false,
                facts_in_lock: false,
                query_hub: None,
            };
            repin(&cx, "crates", workspace).map(|r| r.command)
        };
        assert_eq!(on(&candidates_of(9)), None);
        assert_eq!(
            on(&candidates_of(8)).as_deref(),
            Some("CARGO_BAZEL_REPIN=1 bazel sync --only=crates --enable_workspace")
        );
        for (what, remedy) in every_remedy() {
            let bzlmod_or_nine = what.ends_with("Bzlmod")
                || ["9.", "10."].iter().any(|major| what.starts_with(major));
            assert!(
                !(bzlmod_or_nine && shown(&remedy).contains("bazel sync")),
                "{what}"
            );
        }
        let remedy = remedy("7.7.2", false, bzlmod).unwrap();
        let advisory = remedy.run_required(true).unwrap();
        assert_eq!(advisory.kind.as_str(), "repin");
        assert!(remedy.text().contains("`Digests do not match`"));
    }

    #[test]
    fn the_crate_universe_snippet_starts_with_the_cargo_config_edit() {
        let line = line("8.8.2");
        let cx = Cx {
            line: &line,
            strict_repo_env: false,
            facts_in_lock: true,
            query_hub: None,
        };
        let undeclared = crate_universe_snippet(&cx, "crates", DeclSystem::Bzlmod, None).unwrap();
        let [config, edits, run] = undeclared.steps.as_slice() else {
            panic!("{:?}", undeclared.steps);
        };
        assert!(
            config.starts_with("Set `cargo_config` on the `crates` hub"),
            "{config}"
        );
        assert!(config.contains("[registries.socket-patch-<uuid>]"));
        assert!(edits.starts_with("Make the three edits of the hosted redirect"));
        for file in ["`Cargo.toml`", "that config file", "`Cargo.lock`"] {
            assert!(edits.contains(file), "{file}");
        }
        assert_eq!(run, "Repin: `CARGO_BAZEL_REPIN=1 bazel mod deps`.");
        assert_eq!(undeclared.kind, Some(RunKind::Repin));
        assert!(undeclared
            .snippet()
            .unwrap()
            .starts_with("1. Set `cargo_config`"));

        // A tag that names a config already: the table goes into that file.
        let label = Some("//third_party:cargo-config.toml");
        let declared = crate_universe_snippet(&cx, "crates", DeclSystem::Bzlmod, label).unwrap();
        assert!(declared.steps[0].starts_with(
            "Put the `[registries.socket-patch-<uuid>]` table into the file `cargo_config` names \
             (`//third_party:cargo-config.toml`)"
        ));
        let strict = Cx {
            strict_repo_env: true,
            ..cx
        };
        let snippet = crate_universe_snippet(&strict, "crates", DeclSystem::Workspace, None);
        assert_eq!(
            snippet.unwrap().steps[2],
            "Repin: `bazel sync --only=crates --enable_workspace \
             --repo_env=CARGO_BAZEL_REPIN=1`."
        );
        // No refresh of MODULE.bazel.lock follows a repin, in any form.
        for (what, remedy) in every_remedy() {
            if remedy.kind == Some(RunKind::Repin) {
                assert!(!shown(&remedy).contains("--lockfile_mode"), "{what}");
                assert!(remedy.steps.is_empty() || remedy.steps[0].contains("`cargo_config`"));
            }
        }
    }

    /// Probe Y6: the direct reference goes into the `.in` source, the
    /// update runs twice and `scan` confirms the digest, in that order.
    #[test]
    fn the_pip_compile_snippet_is_the_sequence_a_probe_ran() {
        let target = "//third_party/py:requirements";
        let remedy = pip_compile_snippet(target, Tri::Yes);
        let [reference, update, scan] = remedy.steps.as_slice() else {
            panic!("{:?}", remedy.steps);
        };
        assert!(reference.starts_with("Add the package's direct reference"));
        assert!(reference.contains("`.in` source"));
        assert!(update.starts_with("Run `bazel run //third_party/py:requirements.update` twice"));
        assert!(scan.starts_with("Run `socket-patch scan` again"));
        assert_eq!(
            remedy.command,
            "bazel run //third_party/py:requirements.update"
        );
        // It refreshes no state socket-patch tracks: no advisory rides on it.
        assert_eq!((remedy.kind, remedy.run_required(true)), (None, None));

        let check = |dot_test| pip_compile_snippet(target, dot_test).notes[0].clone();
        assert_eq!(
            check(Tri::Yes),
            "The check target is `//third_party/py:requirements.test`."
        );
        assert_eq!(
            check(Tri::No),
            "The check target is `//third_party/py:requirements_test`."
        );
        assert_eq!(
            check(Tri::Maybe),
            "The check target is `//third_party/py:requirements.test` \
             (`//third_party/py:requirements_test` on rules_python below 1.5.0)."
        );
    }

    /// Remedy matrix 1.2, rows 8 and 14: the update of a gazelle manifest
    /// and the regeneration of a checked-in `requirements.bzl` read the
    /// lock and leave it alone, so neither text says the pin is dropped.
    #[test]
    fn a_manifest_and_a_requirements_bzl_check_keep_the_pin() {
        let manifest = gazelle_manifest("//:gazelle_python_manifest");
        let [pin, update] = manifest.steps.as_slice() else {
            panic!("{:?}", manifest.steps);
        };
        assert!(pin.starts_with("Write the pin into the lock by hand"));
        assert_eq!(
            update,
            "Run `bazel run //:gazelle_python_manifest.update`: it rewrites only the manifest, \
             whose `integrity` covers the bytes of the lock, and leaves the pin in place."
        );
        assert_eq!(
            manifest.command,
            "bazel run //:gazelle_python_manifest.update"
        );
        // It refreshes no state socket-patch tracks: no advisory rides on it.
        assert_eq!((manifest.kind, manifest.run_required(true)), (None, None));

        let generated = requirements_bzl();
        assert!(generated.command.is_empty() && generated.snippet().is_none());
        assert!(generated.text().contains("does not drop the pin"));
        assert!(generated.text().contains("the project's own"));
        for remedy in [manifest, generated] {
            assert!(
                !remedy.text().contains("drops the pin"),
                "{}",
                remedy.text()
            );
        }
    }

    /// A grant token is a path segment of a hosted URL. Whatever a caller
    /// hands over, no URL and nothing a shell would act on is printed.
    #[test]
    fn no_text_carries_a_url_or_a_token() {
        const TOKEN: &str = "9f3c2a1b-token-5d6e";
        let url = format!("https://patch.socket.dev/patch/npm/left-pad/1.3.0/{TOKEN}/uuid/x.tgz");
        let long = "x".repeat(161);
        let hostile = [&url, "crates; rm -rf ~", "two words", "$(id)", "", &long];
        let line = line("8.8.2");
        for text in hostile {
            let cx = Cx {
                line: &line,
                strict_repo_env: false,
                facts_in_lock: true,
                query_hub: Some(text),
            };
            let keys = [text.to_string()];
            let mut remedies = vec![
                lock_refresh(&cx, &keys),
                delete_entry(text, &keys),
                pip_compile_snippet(text, Tri::Maybe),
                gazelle_manifest(text),
            ];
            for system in [DeclSystem::Bzlmod, DeclSystem::Workspace] {
                remedies.extend(repin(&cx, text, system));
                remedies.extend(crate_universe_snippet(&cx, text, system, Some(text)));
            }
            for remedy in remedies {
                let shown = shown(&remedy);
                assert!(
                    text.is_empty() || !shown.contains(text),
                    "{text:?} in\n{shown}"
                );
                assert!(!shown.contains(TOKEN) && !shown.contains("://"), "{shown}");
                assert!(!remedy.platforms.iter().any(|key| key == text), "{text:?}");
            }
        }
        // What a workspace file can name is printed as it is.
        for name in [
            "pypi",
            "maven_2",
            "@@rules_python+//python/extensions:pip.bzl%pip",
            "os:linux,arch:amd64",
            "//a-b/c.d:e+f~g",
        ] {
            assert_eq!(plain(name, "<x>"), name);
        }
    }

    #[test]
    fn strict_mode_is_read_from_the_tracked_rc_files() {
        let strict = |rc: &str| {
            let files = Files::of(&[(".bazelrc", rc)]);
            strict_repo_env(&super::super::rc::read(&files).effective(&line("9.3.2")))
        };
        assert!(!strict(""));
        assert!(!strict("common --noexperimental_strict_repo_env\n"));
        assert!(strict("common --experimental_strict_repo_env\n"));
        // `mod` and `sync` inherit nothing from `build`, and the build
        // that follows the repin runs under the flag all the same.
        assert!(strict("build --experimental_strict_repo_env\n"));
        assert!(strict("mod --experimental_strict_repo_env\n"));
        // Set only under a config: it may be in effect.
        assert!(strict("common:ci --experimental_strict_repo_env\n"));
        assert!(!strict("query --experimental_strict_repo_env\n"));
    }
}
