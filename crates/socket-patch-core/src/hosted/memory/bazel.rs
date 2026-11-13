//! Bazel in the in-memory engine (design 3, HZ-20; owner decisions D7 and
//! O2): the engine patches nothing Bazel builds.
//!
//! A Bazel ruleset fetches packages from the lock file its declaration
//! names, and what a pin in that lock does to the build (a stale derived
//! value, a frozen `MODULE.bazel.lock`, a lock check that goes red) is the
//! gate's to decide, over files this engine is never handed. So wherever
//! Bazel builds, or may build, an ecosystem's packages in a project, the
//! engine leaves that ecosystem alone and says so
//! (`bazel_workspace_unsupported_in_memory`): no patch is looked up for
//! it and no file of it is rewritten. A checkout and the CLI are the
//! remedy.
//!
//! What it reads to tell. Path selection streams, for every Bazel root at
//! or above a project root, the root's boundary files, its `.bazelrc` and
//! the socket-owned `.socket/bazel/` directory ([`selected`]): the files
//! that say which rulesets a workspace declares. The session reads them
//! into the same model the CLI reads from disk, through a view that knows
//! how little it was given ([`RootView`]), and asks the same question
//! (`govern::governance_over`). Whatever is not `NotGoverned` is left
//! alone: governed, declared and inactive, ambiguous, and every case the
//! streamed files cannot decide. That last one is the common one. An
//! `include()`, a `.bzl` macro of a `WORKSPACE`, a BUILD file with a
//! `crates_vendor` target are not streamed, and what was not read may
//! declare a hub, so the answer is `Undetermined` and the ecosystem is
//! skipped: unreadable is never absent. A `MODULE.bazel` that declares no
//! ruleset of an ecosystem and includes nothing leaves that ecosystem to
//! the engine, as before.
//!
//! The trust is the engine's usual one: a file selection asks for and the
//! host does not send is a file the repository does not have.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::path::PathBuf;

use crate::bazel::codes::Code;
use crate::bazel::model::{
    BazelLine, BazelWorkspace, FileText, FileView, Gap, Governance, Probe, RootRef, Ruleset,
};
use crate::bazel::owned_index::OWNED_DIR;
use crate::bazel::{detect, govern, rc};
use crate::crawlers::bazel_root::BOUNDARY_FILES;
use crate::crawlers::Ecosystem;
use crate::vendor::lock_inventory::MemoryEntry;

use super::roots::{at_or_above, join_root, split_path};
use super::types::EngineWarning;
use super::SharedFile;

/// The files directly in a Bazel root that selection streams whenever the
/// listing holds them: the four boundary files, the `WORKSPACE.bzlmod`
/// that replaces `WORKSPACE` under Bzlmod, and the workspace rc file.
/// [`RootView`] takes one of these that the session does not hold for
/// absent, and every other file for one nobody read.
pub(super) const ROOT_FILES: [&str; 6] = [
    "MODULE.bazel",
    "REPO.bazel",
    "WORKSPACE.bazel",
    "WORKSPACE",
    "WORKSPACE.bzlmod",
    ".bazelrc",
];

/// Whether `dir` holds a Bazel boundary file among `listed` paths.
fn is_root(dir: &str, listed: impl Fn(&str) -> bool) -> bool {
    BOUNDARY_FILES
        .iter()
        .any(|name| listed(&join_root(dir, name)))
}

/// The paths selection streams for Bazel: for each Bazel root at or above
/// one of `roots`, its [`ROOT_FILES`] and everything under its
/// `.socket/bazel/`, as far as `blobs` lists them. The owned directory is
/// what a later in-memory gate reads its index and wiring from (revision
/// 4, seam contract item 8); streaming it now means that change edits no
/// selection.
///
/// A Bazel root with no project root below it is not looked for: nothing
/// there is scanned, so there is nothing to leave alone.
pub(super) fn selected<'a>(roots: &[String], blobs: &'a BTreeMap<String, bool>) -> Vec<&'a str> {
    let dirs: BTreeSet<&str> = roots.iter().flat_map(|root| at_or_above(root)).collect();
    let mut out: Vec<&'a str> = Vec::new();
    for dir in dirs {
        if !is_root(dir, |path| blobs.contains_key(path)) {
            continue;
        }
        for name in ROOT_FILES {
            let listed = blobs.get_key_value(join_root(dir, name).as_str());
            out.extend(listed.map(|(path, _)| path.as_str()));
        }
        let owned = format!("{}/", join_root(dir, OWNED_DIR));
        let from = (Bound::Included(owned.as_str()), Bound::Unbounded);
        let below = blobs.range::<str, _>(from);
        let below = below.take_while(|(path, _)| path.starts_with(owned.as_str()));
        out.extend(below.map(|(path, _)| path.as_str()));
    }
    out
}

/// One Bazel root of the session as the pure layer reads files: the
/// streamed files below `base` (a repository-relative directory, `""` for
/// the repository root), and above it up to the repository root, which is
/// the read boundary.
///
/// The session holds what selection asked for, so the view answers by
/// what selection does: a file it streams whenever listed
/// ([`ROOT_FILES`] in `base`, anything under `base`'s owned directory) and
/// that is not here is `Absent`; any other path is `Unreadable`, because
/// it was never asked for and may well exist. A file the host marked
/// present without content (a symbolic link, an oversize file) is
/// `Unreadable` too. No directory can be listed: the session knows the
/// streamed files of one, not its entries, and "not listed" must not read
/// as "holds nothing" (`FileView::list`).
struct RootView<'a> {
    files: &'a BTreeMap<String, SharedFile>,
    base: &'a str,
}

impl RootView<'_> {
    /// The repository path a view path names; `None` past the repository
    /// root or for a path that is not normalised.
    fn locate(&self, rel: &str) -> Option<String> {
        let mut path: Vec<&str> = self.base.split('/').filter(|s| !s.is_empty()).collect();
        let mut below = false;
        for segment in rel.split('/').filter(|_| !rel.is_empty()) {
            match segment {
                ".." if !below => drop(path.pop()?),
                "" | "." | ".." => return None,
                name => {
                    below = true;
                    path.push(name);
                }
            }
        }
        Some(path.join("/"))
    }

    /// Whether selection streams `path` whenever the listing holds it.
    fn streamed_when_listed(&self, path: &str) -> bool {
        let (dir, name) = split_path(path);
        let owned = format!("{}/", join_root(self.base, OWNED_DIR));
        (dir == self.base && ROOT_FILES.contains(&name)) || path.starts_with(&owned)
    }
}

impl FileView for RootView<'_> {
    fn read(&self, rel: &str) -> FileText {
        let Some(path) = self.locate(rel) else {
            return FileText::Unreadable;
        };
        match self.files.get(&path).map(|file| &file.entry) {
            Some(MemoryEntry::Text(text)) => FileText::Bytes(text.as_bytes().to_vec()),
            Some(MemoryEntry::Binary(bytes)) => FileText::Bytes(bytes.to_vec()),
            Some(MemoryEntry::Present | MemoryEntry::Symlink) => FileText::Unreadable,
            None if self.streamed_when_listed(&path) => FileText::Absent,
            None => FileText::Unreadable,
        }
    }

    fn list(&self, _dir: &str) -> Option<Vec<String>> {
        None
    }
}

/// The Bazel roots of a session, found among its files.
pub(super) struct Workspaces<'a> {
    files: &'a BTreeMap<String, SharedFile>,
    /// Every directory that holds a boundary file.
    roots: BTreeSet<&'a str>,
}

impl<'a> Workspaces<'a> {
    /// One pass over the session's paths: a name comparison per file, and
    /// nothing more in a repository with no Bazel boundary file.
    pub(super) fn of(files: &'a BTreeMap<String, SharedFile>) -> Self {
        let boundary = |path: &&'a str| BOUNDARY_FILES.contains(&split_path(path).1);
        let paths = files.keys().map(String::as_str).filter(boundary);
        Self {
            files,
            roots: paths.map(|path| split_path(path).0).collect(),
        }
    }

    fn view(&self, base: &'a str) -> RootView<'a> {
        RootView {
            files: self.files,
            base,
        }
    }

    /// The directories that the streamed rc files of the roots name with
    /// `--vendor_dir`, repository-relative: nothing in one is a project
    /// (design 3, HZ-03), marker or no marker. Selection cannot know them,
    /// because it reads names and not content, so the session prunes by
    /// them.
    pub(super) fn vendor_dirs(&self) -> Vec<String> {
        let mut dirs: BTreeSet<String> = BTreeSet::new();
        for base in &self.roots {
            let flags = rc::read(&self.view(base)).effective(&BazelLine::unknown());
            let values = govern::tracked_vendor_dirs(&flags);
            let below = values.iter().filter_map(|v| govern::vendor_dir_below(v));
            dirs.extend(below.map(|dir| join_root(base, &dir)));
        }
        dirs.into_iter().collect()
    }

    /// What Bazel claims of the project at `root`: `None` under no Bazel
    /// root, which is every project of a repository that does not build
    /// with Bazel.
    pub(super) fn claims(&self, root: &str) -> Option<Claims> {
        // Nearest the project first, as the root probe reports them.
        let above: Vec<&str> = at_or_above(root)
            .filter(|dir| self.roots.contains(dir))
            .collect();
        let nearest = *above.first()?;
        let root_ref = |base: &&str| RootRef {
            root: PathBuf::from(if base.is_empty() { "." } else { base }),
            project_rel: match base.is_empty() {
                true => root.to_string(),
                false => root[base.len()..].trim_start_matches('/').to_string(),
            },
            boundary_levels: base.split('/').filter(|s| !s.is_empty()).count(),
        };
        let refs: Vec<RootRef> = above.iter().map(root_ref).collect();
        let read = above.iter().zip(&refs);
        let models: Vec<Result<BazelWorkspace, Gap>> = read
            .map(|(base, root)| detect(root, &self.view(base)))
            .collect();
        let probe = match refs.as_slice() {
            [only] => Probe::Workspace(only.clone()),
            _ => Probe::Nested(refs),
        };
        let mut ecosystems: Vec<Ecosystem> = Vec::new();
        for ecosystem in Ruleset::ALL.iter().filter_map(|r| r.ecosystem()) {
            let claimed =
                govern::governance_over(&probe, &models, ecosystem) != Governance::NotGoverned;
            if claimed && !ecosystems.contains(&ecosystem) {
                ecosystems.push(ecosystem);
            }
        }
        let name = BOUNDARY_FILES
            .iter()
            .find(|name| self.files.contains_key(&join_root(nearest, name)))?;
        Some(Claims {
            marker: join_root(nearest, name),
            ecosystems,
        })
    }
}

/// The ecosystems of one project that Bazel builds or may build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Claims {
    /// The boundary file of the nearest Bazel root, repository-relative.
    marker: String,
    ecosystems: Vec<Ecosystem>,
}

impl Claims {
    /// `purls` less the packages of the claimed ecosystems, which the
    /// engine then never asks the API about and never pins. When that
    /// left any out, one warning for the project says which ecosystems
    /// and how many packages.
    pub(super) fn withhold(
        &self,
        purls: BTreeSet<String>,
        root: &str,
        warnings: &mut Vec<EngineWarning>,
    ) -> BTreeSet<String> {
        let claimed = |purl: &String| {
            Ecosystem::from_purl(purl).is_some_and(|eco| self.ecosystems.contains(&eco))
        };
        let (left, kept): (BTreeSet<String>, BTreeSet<String>) =
            purls.into_iter().partition(claimed);
        if left.is_empty() {
            return kept;
        }
        let mut names: Vec<&str> = left
            .iter()
            .filter_map(|purl| Some(Ecosystem::from_purl(purl)?.cli_name()))
            .collect();
        names.sort_unstable();
        names.dedup();
        let names = names.join(", ");
        let (count, were) = match left.len() {
            1 => ("1 package".to_string(), "was"),
            n => (format!("{n} packages"), "were"),
        };
        let detail = format!(
            "{} makes this project part of a Bazel workspace whose rulesets build, or may \
             build, its {names} packages from lock files Bazel reads. The in-memory hosted scan \
             patches nothing Bazel builds, so {count} ({names}) {were} not scanned; run \
             `socket-patch scan --mode hosted` from a checkout",
            self.marker
        );
        let code = Code::WorkspaceUnsupportedInMemory.as_str();
        warnings.push(EngineWarning::new(code, detail, Some(root)));
        kept
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosted::memory::{share, InputFile, PresentKind};

    fn session(files: &[(&str, &str)]) -> BTreeMap<String, SharedFile> {
        let text = |(path, text): &(&str, &str)| {
            (path.to_string(), share(InputFile::Text(text.to_string())))
        };
        files.iter().map(text).collect()
    }

    const JS: &str = "bazel_dep(name = \"aspect_rules_js\", version = \"2.9.3\")\n\
        npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
        npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n\
        use_repo(npm, \"npm\")\n";
    const CC: &str =
        "module(name = \"app\")\nbazel_dep(name = \"rules_cc\", version = \"0.1.1\")\n";

    fn claimed(files: &[(&str, &str)], root: &str) -> Option<Vec<&'static str>> {
        let files = session(files);
        let claims = Workspaces::of(&files).claims(root)?;
        Some(claims.ecosystems.iter().map(|e| e.cli_name()).collect())
    }

    /// The whole point of reading the model: a workspace that declares no
    /// ruleset of an ecosystem, in files that were all read, leaves that
    /// ecosystem to the engine, and one that declares rules_js takes npm
    /// and nothing else.
    #[test]
    fn only_what_a_ruleset_may_build_is_claimed() {
        assert_eq!(claimed(&[("package-lock.json", "{}")], ""), None);
        assert_eq!(claimed(&[("MODULE.bazel", CC)], ""), Some(vec![]));
        assert_eq!(claimed(&[("MODULE.bazel", JS)], ""), Some(vec!["npm"]));
        // A project below the root is claimed by the root's hub only where
        // the hub's lock is its own; a hub that names the root's lock
        // leaves a sibling project alone.
        let nested = [("MODULE.bazel", JS), ("web/package-lock.json", "{}")];
        assert_eq!(claimed(&nested, "web"), Some(vec![]));
    }

    /// Unreadable is not absent: every way the streamed files can fail to
    /// say what the workspace declares claims what they may hide.
    #[test]
    fn what_the_streamed_files_cannot_decide_is_claimed() {
        let every = |found: Option<Vec<&'static str>>| {
            let found = found.expect("a Bazel root");
            let all = ["npm", "pypi", "maven", "golang", "cargo", "gem", "nuget"];
            all.iter().all(|eco| found.contains(eco))
        };
        // An include is a file selection does not stream.
        let include = "include(\"//third_party:deps.MODULE.bazel\")\n";
        assert!(every(claimed(&[("MODULE.bazel", include)], "")));
        // So is the `.bzl` file of a WORKSPACE macro.
        let workspace = "load(\"//:deps.bzl\", \"deps\")\ndeps()\n";
        assert!(every(claimed(&[("WORKSPACE", workspace)], "")));
        // A boundary file the host could not hand over.
        let mut files = session(&[("pnpm-lock.yaml", "")]);
        let present = InputFile::Present(PresentKind::Oversize);
        files.insert("MODULE.bazel".to_string(), share(present));
        let found = Workspaces::of(&files).claims("").expect("a Bazel root");
        assert!(every(Some(
            found.ecosystems.iter().map(|e| e.cli_name()).collect()
        )));
        files.insert("MODULE.bazel".to_string(), share(InputFile::Symlink));
        let found = Workspaces::of(&files).claims("").expect("a Bazel root");
        assert!(!found.ecosystems.is_empty());
    }

    /// A ruleset that is declared with no hub the streamed files show
    /// (the hub is in a BUILD file, behind a label, or not written yet)
    /// claims its ecosystem in every project of the workspace, and a hub
    /// claims the project of its lock. Which it is, the recognizers
    /// decide; this pins what the engine then skips.
    #[test]
    fn a_declared_ruleset_claims_its_ecosystem() {
        let dep = |name: &str| format!("bazel_dep(name = \"{name}\", version = \"1.0.0\")\n");
        let mut wrong = Vec::new();
        for (ruleset, ecosystem) in [
            ("rules_rust", "cargo"),
            ("rules_jvm_external", "maven"),
            ("rules_ruby", "gem"),
            ("rules_dotnet", "nuget"),
            ("aspect_rules_js", "npm"),
        ] {
            let module = dep(ruleset);
            for project in ["", "svc/api"] {
                let found = claimed(&[("MODULE.bazel", &module)], project);
                if found != Some(vec![ecosystem]) {
                    wrong.push(format!("{ruleset} at {project:?}: {found:?}"));
                }
            }
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
        // Two rulesets are declared for more than packages, and the
        // recognizers know it: rules_python for its toolchain, gazelle to
        // generate BUILD files. Each fetches packages only through its
        // extension (`pip`, `go_deps`), whose lock then claims its project.
        for toolchain in ["rules_python", "gazelle"] {
            let found = claimed(&[("MODULE.bazel", &dep(toolchain))], "");
            assert_eq!(found, Some(vec![]), "{toolchain}");
        }
        let go = "bazel_dep(name = \"gazelle\", version = \"0.45.0\")\n\
            go_deps = use_extension(\"@gazelle//:extensions.bzl\", \"go_deps\")\n\
            go_deps.from_file(go_mod = \"//svc:go.mod\")\n\
            use_repo(go_deps, \"com_github_pkg_errors\")\n";
        assert_eq!(
            claimed(&[("MODULE.bazel", go)], "svc"),
            Some(vec!["golang"])
        );
        let pip = "bazel_dep(name = \"rules_python\", version = \"1.4.1\")\n\
            pip = use_extension(\"@rules_python//python/extensions:pip.bzl\", \"pip\")\n\
            pip.parse(hub_name = \"pypi\", python_version = \"3.12\", \
            requirements_lock = \"//tools:requirements_lock.txt\")\n\
            use_repo(pip, \"pypi\")\n";
        // The recognizer opens a requirements lock to read its header,
        // and this one is a file selection does not stream: what it is
        // was not read, so the ecosystem is open in every project.
        for project in ["tools", "web"] {
            let found = claimed(&[("MODULE.bazel", pip)], project);
            assert_eq!(found, Some(vec!["pypi"]), "{project}");
        }
    }

    /// A nested boundary file does not cut its directory out of the outer
    /// workspace (design 2.2): every root above the project is asked.
    #[test]
    fn every_root_above_the_project_is_asked() {
        let lock = ("svc/web/pnpm-lock.yaml", "");
        let inner_js = [("MODULE.bazel", CC), ("svc/MODULE.bazel", JS), lock];
        // The inner root's hub names `svc/pnpm-lock.yaml`, not this one.
        assert_eq!(claimed(&inner_js, "svc/web"), Some(vec![]));
        assert_eq!(claimed(&inner_js, "svc"), Some(vec!["npm"]));
        let outer_js = [("MODULE.bazel", JS), ("svc/MODULE.bazel", CC), lock];
        assert_eq!(claimed(&outer_js, ""), Some(vec!["npm"]));
        assert_eq!(claimed(&outer_js, "svc"), Some(vec![]));
        assert_eq!(claimed(&outer_js, "other"), Some(vec![]));
    }

    #[test]
    fn the_view_tells_absent_from_unread_by_what_selection_streams() {
        let files = session(&[
            ("ws/MODULE.bazel", CC),
            ("ws/.socket/bazel/index.json", "{}"),
            (".bazelversion", "9.3.2\n"),
        ]);
        let view = RootView {
            files: &files,
            base: "ws",
        };
        assert_eq!(view.read("MODULE.bazel"), FileText::Bytes(CC.into()));
        // Streamed whenever listed, and not here: the repository has none.
        for absent in ["WORKSPACE", ".bazelrc", ".socket/bazel/socket.bazelrc"] {
            assert_eq!(view.read(absent), FileText::Absent, "{absent}");
        }
        // Never asked for, so nobody knows.
        for unread in [
            ".bazelversion",
            "MODULE.bazel.lock",
            "deps.bzl",
            "pkg/MODULE.bazel",
            "pkg/.bazelrc",
            "../.bazelrc",
            "../MODULE.bazel",
        ] {
            assert_eq!(view.read(unread), FileText::Unreadable, "{unread}");
        }
        // Streamed for another reason, above the root and inside the
        // repository: readable. Past the repository root nothing is.
        assert_eq!(
            view.read("../.bazelversion"),
            FileText::Bytes(b"9.3.2\n".to_vec())
        );
        assert_eq!(view.read("../../.bazelversion"), FileText::Unreadable);
        assert_eq!(view.read("a/../MODULE.bazel"), FileText::Unreadable);
        assert_eq!(view.list(""), None);
        assert_eq!(view.list("pkg"), None);
    }

    #[test]
    fn selection_streams_the_root_files_of_every_root_above_a_project() {
        let listed: BTreeMap<String, bool> = [
            "MODULE.bazel",
            ".bazelrc",
            ".bazelversion",
            ".socket/bazel/index.json",
            ".socket/bazel/patches/u/x.patch",
            ".socket/bazelish/x",
            ".socket/manifest.json",
            "svc/WORKSPACE",
            "svc/WORKSPACE.bzlmod",
            "svc/BUILD.bazel",
            "svc/api/go.sum",
            // No project root at or below it: not looked for.
            "tools/MODULE.bazel",
            "tools/.bazelrc",
            // No boundary file beside it: not a workspace rc file.
            "web/.bazelrc",
            "web/yarn.lock",
        ]
        .into_iter()
        .map(|path| (path.to_string(), false))
        .collect();
        let roots = ["svc/api".to_string(), "web".to_string()];
        assert_eq!(
            selected(&roots, &listed),
            [
                "MODULE.bazel",
                ".bazelrc",
                ".socket/bazel/index.json",
                ".socket/bazel/patches/u/x.patch",
                "svc/WORKSPACE",
                "svc/WORKSPACE.bzlmod",
            ]
        );
        let plain: BTreeMap<String, bool> = [("web/yarn.lock".to_string(), false)].into();
        assert!(selected(&["web".to_string()], &plain).is_empty());
    }

    #[test]
    fn tracked_vendor_dirs_are_read_from_the_streamed_rc_files() {
        let files = session(&[
            ("MODULE.bazel", CC),
            (
                ".bazelrc",
                "common --vendor_dir=third_party/bazel\nbuild:ci --vendor_dir=\n",
            ),
            ("svc/WORKSPACE", ""),
            (
                "svc/.bazelrc",
                "vendor --vendor_dir=deps\ncommon:x --vendor_dir=../up\n",
            ),
            // An rc file beside no boundary file is nobody's.
            ("web/.bazelrc", "common --vendor_dir=nope\n"),
        ]);
        assert_eq!(
            Workspaces::of(&files).vendor_dirs(),
            ["svc/deps", "third_party/bazel"]
        );
        assert!(Workspaces::of(&session(&[("yarn.lock", "")]))
            .vendor_dirs()
            .is_empty());
    }

    #[test]
    fn withholding_reports_once_and_only_what_it_left_out() {
        let claims = Claims {
            marker: "MODULE.bazel".to_string(),
            ecosystems: vec![Ecosystem::Npm, Ecosystem::Maven],
        };
        let purls = |list: &[&str]| -> BTreeSet<String> {
            list.iter().map(|purl| purl.to_string()).collect()
        };
        let mut warnings = Vec::new();
        let kept = claims.withhold(
            purls(&["pkg:npm/a@1.0.0", "pkg:npm/b@2.0.0", "pkg:pypi/c@3.0.0"]),
            "web",
            &mut warnings,
        );
        assert_eq!(kept, purls(&["pkg:pypi/c@3.0.0"]));
        let [warning] = warnings.as_slice() else {
            panic!("one warning: {warnings:?}");
        };
        assert_eq!(warning.code, Code::WorkspaceUnsupportedInMemory.as_str());
        assert_eq!(warning.project_root.as_deref(), Some("web"));
        assert!(warning.detail.contains("2 packages (npm) were not scanned"));
        assert!(warning.detail.starts_with("MODULE.bazel makes"));

        // Nothing of a claimed ecosystem: nothing was left alone.
        let mut warnings = Vec::new();
        let kept = claims.withhold(purls(&["pkg:pypi/c@3.0.0"]), "", &mut warnings);
        assert_eq!(kept.len(), 1);
        assert!(warnings.is_empty());
    }
}
