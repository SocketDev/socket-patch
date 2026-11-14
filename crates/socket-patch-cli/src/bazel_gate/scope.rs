//! A command's scope root and the trees Bazel owns (design 3, HZ-02; owner
//! decision O16 of design 11.3).
//!
//! An output base, an entry of either cache and a vendor directory belong
//! to Bazel: it creates and replaces what is in them, and other workspaces
//! share a cache. A command that worked there would report a rollback, a
//! removal, a repair or an attestation of a tree the next build replaces,
//! so a command whose scope root (`--global-prefix`, else `--cwd`) is in
//! one, or links into one, is refused before it reads, fetches or writes
//! anything: the coded error `bazel_agent_output_tree`, exit 1. The
//! project a `--manifest-path` names is a scope root too: these commands
//! read and write the state of the manifest's project, and attest it,
//! wherever `--cwd` points.
//!
//! This is the one check for the commands of O16: `rollback`, `remove`,
//! `repair`, `get`, `vex` and `vendor` (`vendor --revert` with it). Each
//! calls [`refuse_in_bazel_tree`] as the first line of its `run`. It
//! refuses in both forms, a scope a flag or a variable named and the
//! working directory nobody named: a person runs these commands and no
//! lifecycle hook does, and a silent no-op would say that a rollback or a
//! removal happened. Which commands it applies to is [`scope_rule`] and
//! nothing else, so the decision is flipped in one place.
//!
//! `apply` and `scan` are older than this file and keep their own
//! preflights (`apply`'s lets a working directory nobody named through
//! with a warning and exit 0, for the legacy `npm_install` hooks that run
//! it inside an output base; owner decision O11). `list` only reads and is
//! never refused.
//!
//! The file is under `bazel_gate/`, not `commands/`, so that every command
//! module can call it with no new edge in `command_module_layering`.

use std::borrow::Cow;
use std::path::Path;

use socket_patch_core::bazel::codes::Code;
use socket_patch_core::patch::shared_store::{bazel_tree_of, SharedStore};

use crate::args::GlobalArgs;
use crate::json_envelope::{Command, Envelope, EnvelopeError};

/// What owner decision O16 has a command do when its scope root is in a
/// tree Bazel owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeRule {
    /// Refused, whether the scope was named or is the working directory:
    /// `bazel_agent_output_tree`, exit 1, nothing read or written.
    Refuse,
    /// Not this file's to judge: the command only reads (`list`), has a
    /// preflight of its own with another rule for the working directory
    /// (`apply`, `scan`), or has no project scope (`update`).
    NotJudgedHere,
}

/// Owner decision O16, defaulted (the owner may overrule): the commands a
/// person runs to change or attest a project are refused in a Bazel tree.
/// The alternative the decision names narrows the refusal to `scan` and
/// `apply`; taking it is this function answering `NotJudgedHere` for
/// every command.
pub const fn scope_rule(command: Command) -> ScopeRule {
    match command {
        Command::Rollback
        | Command::Remove
        | Command::Repair
        | Command::Get
        | Command::Vex
        | Command::Vendor => ScopeRule::Refuse,
        Command::List | Command::Apply | Command::Scan | Command::Update => {
            ScopeRule::NotJudgedHere
        }
    }
}

/// How a refusal names what chose the working directory: the flag, or
/// nothing when no flag and no variable moved the run. `--cwd .` reads as
/// the second, because it names the directory the process is already in.
fn cwd_named_by(common: &GlobalArgs) -> &'static str {
    match common.cwd == Path::new(".") {
        true => "the working directory",
        false => "--cwd",
    }
}

/// The scope roots of a run, in the order they are judged, each with the
/// name a refusal gives it. `--global-prefix` comes first: where it is
/// given it is the tree the run works in, and `--cwd` only locates the
/// manifest.
///
/// The last is the project of the manifest, where `--manifest-path` (or
/// its variable) names one that is not the working directory: every
/// command of the rule moves its run there (`GlobalArgs::project_root`,
/// `at_project_root`), reads that project's manifest, ledgers and
/// lockfiles and attests or changes it. The two are compared as paths, as
/// `at_project_root` compares them.
fn scope_roots(common: &GlobalArgs) -> Vec<(Cow<'_, Path>, &'static str)> {
    let prefix = common.global_prefix.as_deref();
    let prefix = prefix.map(|prefix| (Cow::Borrowed(prefix), "--global-prefix"));
    let cwd = (Cow::Borrowed(common.cwd.as_path()), cwd_named_by(common));
    let project = Some(common.project_root()).filter(|project| *project != common.cwd);
    let project = project.map(|project| (Cow::Owned(project), "--manifest-path"));
    prefix.into_iter().chain([cwd]).chain(project).collect()
}

/// A scope root in a Bazel tree, and the refusal it earns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InBazelTree {
    /// The sentence for a human and for `error.message`.
    pub detail: String,
}

impl InBazelTree {
    fn of(tree: &SharedStore, action: &str, named_by: &str) -> Self {
        Self {
            detail: tree.scope_refusal(action, named_by),
        }
    }

    /// The `--json` document: the command's envelope with the coded error
    /// and no event, as for every failure before the first event.
    pub fn envelope(&self, command: Command, dry_run: bool) -> Envelope {
        let mut env = Envelope::new(command);
        env.dry_run = dry_run;
        let code = Code::AgentOutputTree.as_str();
        env.mark_error(EnvelopeError::new(code, self.detail.clone()));
        env
    }
}

/// The first scope root of the run that is in a tree Bazel owns or links
/// into one, as a refusal of `action` ("roll back", "remove", ...).
/// `None` outside every such tree, which is every directory of a project
/// that does not build with Bazel.
pub async fn in_bazel_tree(common: &GlobalArgs, action: &str) -> Option<InBazelTree> {
    for (root, named_by) in scope_roots(common) {
        if let Some(tree) = bazel_tree_of(&root).await {
            return Some(InBazelTree::of(&tree, action, named_by));
        }
    }
    None
}

/// Refuses `command` when its scope root is in a tree Bazel owns: prints
/// the coded error (the envelope under `--json`; `Error:` on stderr
/// otherwise, under `--silent` too, as every error is) and returns the
/// exit code 1. `None` when the scope is outside every tree, or the
/// command is not one this rule applies to ([`scope_rule`]).
///
/// `action` is the verb of the sentence: "roll back", "remove", "repair",
/// "get", "attest", "vendor". Call it before the command reads a manifest
/// or makes a request.
pub async fn refuse_in_bazel_tree(
    common: &GlobalArgs,
    command: Command,
    action: &str,
) -> Option<i32> {
    if scope_rule(command) != ScopeRule::Refuse {
        return None;
    }
    let refused = in_bazel_tree(common, action).await?;
    if common.json {
        let env = refused.envelope(command, common.dry_run);
        println!("{}", env.to_pretty_json());
    } else {
        // Errors print even under --silent.
        eprintln!("Error: {}", refused.detail);
    }
    Some(1)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use socket_patch_core::patch::shared_store::BAZEL_TREE_REFUSAL_MARKER;

    use super::*;

    fn put(root: &Path, rel: &str, text: &str) {
        let file = rel
            .split('/')
            .fold(root.to_path_buf(), |at, part| at.join(part));
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, text).unwrap();
    }

    fn at(root: &Path, rel: &str) -> PathBuf {
        rel.split('/')
            .fold(root.to_path_buf(), |at, part| at.join(part))
    }

    /// One tree of each class Bazel owns, as Bazel marks them, beside a
    /// workspace: `(scratch, [(directory inside a tree, the place a
    /// refusal names)])`.
    fn trees() -> (tempfile::TempDir, PathBuf, Vec<(PathBuf, &'static str)>) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        put(&root, "ws/MODULE.bazel", "");
        put(&root, "ws/app/package.json", "{}");
        // An output base: the marker and one of its directories.
        put(&root, "base/DO_NOT_BUILD_HERE", "");
        put(&root, "base/external/npm/node_modules/x/package.json", "{}");
        // A vendor directory.
        put(&root, "ws/third_party/VENDOR.bazel", "");
        put(&root, "ws/third_party/+npm+x/package.json", "{}");
        // An entry of the repository cache.
        let cas = format!("cache/repo/content_addressable/sha256/{:064x}", 7);
        put(&root, &format!("{cas}/file"), "");
        // An entry of the repo contents cache: the marker lies beside it.
        put(&root, "cache/contents/ab/1.recorded_inputs", "");
        put(&root, "cache/contents/ab/1/package.json", "{}");
        let inside = vec![
            (at(&root, "base/external/npm"), "in a Bazel output base"),
            (
                at(&root, "ws/third_party/+npm+x"),
                "in a Bazel vendor directory",
            ),
            (at(&root, &cas), "in Bazel's repository cache"),
            (
                at(&root, "cache/contents/ab/1"),
                "in Bazel's repository contents cache",
            ),
        ];
        (tmp, root, inside)
    }

    fn run_at(cwd: &Path) -> GlobalArgs {
        GlobalArgs {
            cwd: cwd.to_path_buf(),
            ..GlobalArgs::default()
        }
    }

    /// Owner decision O16, as written: six commands are refused, `list`
    /// is the named exception, `apply` and `scan` keep their own rules.
    #[test]
    fn the_rule_names_the_commands_of_o16() {
        use Command::*;
        for command in [Rollback, Remove, Repair, Get, Vex, Vendor] {
            assert_eq!(scope_rule(command), ScopeRule::Refuse, "{command:?}");
        }
        for command in [List, Apply, Scan, Update] {
            assert_eq!(scope_rule(command), ScopeRule::NotJudgedHere, "{command:?}");
        }
    }

    #[tokio::test]
    async fn a_scope_in_each_kind_of_tree_is_refused_and_named() {
        let (_tmp, root, inside) = trees();
        for (dir, place) in &inside {
            let found = in_bazel_tree(&run_at(dir), "roll back").await;
            let detail = found.unwrap_or_else(|| panic!("{}", dir.display())).detail;
            assert!(detail.starts_with("Refusing to roll back in "), "{detail}");
            assert!(detail.contains(place), "{detail}");
            assert!(detail.contains("(--cwd)"), "{detail}");
            assert!(detail.contains(BAZEL_TREE_REFUSAL_MARKER), "{detail}");
            assert!(detail.ends_with("nothing was written"), "{detail}");
            // Every command of the rule exits 1 there, and no other does.
            let common = run_at(dir);
            for command in [Command::Remove, Command::Vex, Command::Vendor] {
                let code = refuse_in_bazel_tree(&common, command, "remove").await;
                assert_eq!(code, Some(1), "{command:?} in {}", dir.display());
            }
            for command in [Command::List, Command::Apply, Command::Scan] {
                let code = refuse_in_bazel_tree(&common, command, "list").await;
                assert_eq!(code, None, "{command:?} in {}", dir.display());
            }
        }
        // Outside every tree: the workspace, a project in it, a directory
        // that does not exist, and the directory that holds the caches.
        for plain in ["ws", "ws/app", "ws/not-there", "cache", ""] {
            let common = run_at(&at(&root, plain));
            assert_eq!(in_bazel_tree(&common, "roll back").await, None, "{plain}");
            let code = refuse_in_bazel_tree(&common, Command::Rollback, "roll back").await;
            assert_eq!(code, None, "{plain}");
        }
    }

    /// A convenience link, and any link that leads into a tree, is the
    /// tree: the scope is judged as found and as resolved.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_link_into_a_tree_is_refused() {
        let (_tmp, root, _) = trees();
        let link = at(&root, "ws/bazel-out");
        std::os::unix::fs::symlink(at(&root, "base/external"), &link).unwrap();
        for scope in [link.clone(), link.join("npm")] {
            let found = in_bazel_tree(&run_at(&scope), "repair").await;
            let detail = found.expect("a link into the output base").detail;
            assert!(detail.starts_with("Refusing to repair in "), "{detail}");
            assert!(detail.contains("Bazel output"), "{detail}");
        }
    }

    /// Both forms are refused, and the sentence says which it was. The
    /// prefix is judged first: where it is given it is where the run
    /// works.
    #[tokio::test]
    async fn the_refusal_says_what_named_the_scope() {
        let (_tmp, root, inside) = trees();
        let (tree, _) = &inside[0];
        // The working directory nobody named is spelled `.`.
        let implicit = GlobalArgs::default();
        assert_eq!(cwd_named_by(&implicit), "the working directory");
        assert_eq!(
            scope_roots(&implicit),
            [(Cow::Borrowed(Path::new(".")), "the working directory")]
        );
        assert_eq!(cwd_named_by(&run_at(tree)), "--cwd");
        let store = bazel_tree_of(tree).await.expect("a tree");
        let said = InBazelTree::of(&store, "remove", cwd_named_by(&implicit)).detail;
        assert!(said.contains("(the working directory)"), "{said}");

        // A prefix in a tree, from a working directory outside one.
        let mut prefixed = run_at(&at(&root, "ws"));
        prefixed.global_prefix = Some(tree.clone());
        let named: Vec<&str> = scope_roots(&prefixed).iter().map(|(_, by)| *by).collect();
        assert_eq!(named, ["--global-prefix", "--cwd"]);
        let detail = in_bazel_tree(&prefixed, "get")
            .await
            .expect("refused")
            .detail;
        assert!(detail.contains("(--global-prefix)"), "{detail}");
        // A prefix outside, a working directory inside: still refused.
        let mut inside_cwd = run_at(tree);
        inside_cwd.global_prefix = Some(at(&root, "ws"));
        let detail = in_bazel_tree(&inside_cwd, "get")
            .await
            .expect("refused")
            .detail;
        assert!(detail.contains("(--cwd)"), "{detail}");
    }

    /// A manifest in another project's `.socket` moves the run there:
    /// that project is judged too, and named by the flag that chose it.
    /// The default manifest, a manifest path that stays in the working
    /// directory's project, and a bare manifest file (whose project is
    /// the working directory) add no root.
    #[tokio::test]
    async fn the_project_a_manifest_path_names_is_a_scope_root() {
        let (_tmp, root, inside) = trees();
        let (tree, _) = &inside[0];
        let ws = at(&root, "ws");
        let named = |common: &GlobalArgs| -> Vec<&'static str> {
            scope_roots(common).iter().map(|(_, by)| *by).collect()
        };
        let with_manifest = |manifest: &Path| GlobalArgs {
            manifest_path: manifest.to_string_lossy().into_owned(),
            ..run_at(&ws)
        };

        // From the workspace, a manifest in the tree's `.socket`.
        let foreign = with_manifest(&tree.join(".socket").join("manifest.json"));
        assert_eq!(named(&foreign), ["--cwd", "--manifest-path"]);
        let roots = scope_roots(&foreign);
        assert_eq!(roots[1].0.as_ref(), tree.as_path());
        for (command, action) in [
            (Command::Vex, "attest"),
            (Command::Get, "get"),
            (Command::Vendor, "vendor"),
        ] {
            let refused = in_bazel_tree(&foreign, action).await;
            let detail = refused.unwrap_or_else(|| panic!("{command:?}")).detail;
            assert!(detail.contains("(--manifest-path)"), "{detail}");
            assert!(detail.contains("in a Bazel output base"), "{detail}");
            let code = refuse_in_bazel_tree(&foreign, command, action).await;
            assert_eq!(code, Some(1), "{command:?}");
        }
        // The prefix and the working directory are still judged first.
        let mut all = with_manifest(&tree.join(".socket").join("manifest.json"));
        all.global_prefix = Some(ws.clone());
        assert_eq!(named(&all), ["--global-prefix", "--cwd", "--manifest-path"]);

        // A manifest that leaves the run where it is adds nothing.
        assert_eq!(named(&run_at(&ws)), ["--cwd"]);
        let own = with_manifest(&ws.join(".socket").join("manifest.json"));
        assert_eq!(named(&own), ["--cwd"]);
        let bare = with_manifest(&tree.join("manifest.json"));
        assert_eq!(named(&bare), ["--cwd"]);
        assert_eq!(in_bazel_tree(&bare, "attest").await, None);
        // And a manifest in a project outside every tree is not refused.
        let plain = with_manifest(&at(&root, "ws/app/.socket/manifest.json"));
        assert_eq!(named(&plain), ["--cwd", "--manifest-path"]);
        assert_eq!(in_bazel_tree(&plain, "attest").await, None);
    }

    #[tokio::test]
    async fn the_json_form_is_the_commands_envelope_with_the_coded_error() {
        let (_tmp, _, inside) = trees();
        let (tree, _) = &inside[1];
        let refused = in_bazel_tree(&run_at(tree), "vendor")
            .await
            .expect("refused");
        let value = refused.envelope(Command::Vendor, true).to_value();
        assert_eq!(value["command"], "vendor");
        assert_eq!(value["status"], "error");
        assert_eq!(value["dryRun"], true);
        assert_eq!(value["error"]["code"], Code::AgentOutputTree.as_str());
        assert_eq!(value["error"]["message"], refused.detail.as_str());
        assert_eq!(value["events"].as_array().map(Vec::len), Some(0));
        let value = refused.envelope(Command::Rollback, false).to_value();
        assert_eq!(value["command"], "rollback");
        assert_eq!(value["dryRun"], false);
    }
}
