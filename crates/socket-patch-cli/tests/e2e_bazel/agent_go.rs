//! Hermetic CLI tests: the agent Go writer under the Bazel gate (design
//! 3, hazards HZ-05, HZ-06 and HZ-27).
//!
//! An agent Go patch is a copy of the module under `.socket/go-patches`
//! and a directory `replace` in `go.mod`. In a gazelle workspace `go.mod`
//! is a build input: `go_deps` fails on the `replace`, ignores it or
//! applies it to another version, depending on the gazelle release, and
//! under `go_repository` it has no effect at all. So `apply` writes
//! neither where a ruleset builds the project's Go modules, unless a lane
//! admits the write, and the refusal carries its code, token and lift as
//! fields of the event.
//!
//! The Bazel side of each governed case is a fixture the real-Bazel suite
//! builds (`fixtures/bazel/heavy/gazelle*`); the module cache is
//! fabricated, so there is no Go and no Bazel here. Whether a case is
//! refused is computed from the lane table (`lanes::admits`), so the
//! change that enables a lane does not turn this file red.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use socket_patch_core::bazel::codes::Code;
use socket_patch_core::bazel::lanes::{self, Cell};
use socket_patch_core::bazel::model::{HubId, Mode, RootRef, Ruleset};
use socket_patch_core::crawlers::bazel_workspace::{read_workspace, DiskView};

use crate::bazel_common::{assert_same_tree, assert_write_policy, snapshot, Snapshot};
use crate::common::envelope::{event_for, events, parse_json_envelope, warning_codes};
use crate::common::{git_sha256, run_with_env, write_blob, write_minimal_manifest, PatchEntry};

const MODULE: &str = "example.com/upstream";
const VERSION: &str = "v1.0.0";
const PURL: &str = "pkg:golang/example.com/upstream@v1.0.0";
const UUID: &str = "3d2f6a51-8c0e-4b7d-9a64-1f5e2c7b9d30";
const COPY: &str = ".socket/go-patches/example.com/upstream@v1.0.0";
/// The patch's two files, each as (name, upstream bytes, patched bytes).
/// Two, so that a run interrupted after its first rename leaves a stage
/// behind as well as the set-aside originals.
const FILES: [(&str, &[u8], &[u8]); 2] = [
    (
        "a.go",
        b"package upstream\n\nfunc A() string { return \"upstream\" }\n",
        b"package upstream\n\nfunc A() string { return \"patched\" }\n",
    ),
    (
        "b.go",
        b"package upstream\n\nfunc B() string { return \"upstream\" }\n",
        b"package upstream\n\nfunc B() string { return \"patched\" }\n",
    ),
];
/// A workspace that builds no Go: the writer goes through.
const NO_HUB: &str = "module(name = \"ws\")\n";
const GO_MOD: &str =
    "module example.com/consumer\n\ngo 1.21\n\nrequire example.com/upstream v1.0.0\n";
/// The two workspaces of the real-Bazel suite that build the module.
const GO_DEPS: &str = "heavy/gazelle/bzlmod/e9";
const GO_REPOSITORY: &str = "heavy/gazelle_workspace/workspace/e7";

fn fixture_dir(fixture: &str) -> PathBuf {
    let levels = fixture.split('/');
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bazel");
    levels.fold(base, |dir, level| dir.join(level))
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        match entry.file_type().unwrap().is_dir() {
            true => copy_tree(&entry.path(), &target),
            false => drop(std::fs::copy(entry.path(), &target).unwrap()),
        }
    }
}

/// A checkout that is one Bazel workspace and a Go project, with the
/// patch in its manifest, and a module cache beside it.
struct Workspace {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    cache: PathBuf,
}

impl Workspace {
    /// A copy of `fixture` pinned to the Bazel release its cell runs on,
    /// or, with none, a workspace that builds no Go.
    fn new(fixture: Option<(&str, &str)>) -> Self {
        let tmp = tempfile::tempdir().expect("a temporary directory");
        let top = std::fs::canonicalize(tmp.path()).expect("its real path");
        let (root, cache) = (top.join("ws"), top.join("modcache"));
        // `.git` makes `ws` the repository: nothing above it is read.
        std::fs::create_dir_all(root.join(".git")).unwrap();
        let ws = Self {
            _tmp: tmp,
            root,
            cache,
        };
        match fixture {
            Some((fixture, bazel)) => {
                copy_tree(&fixture_dir(fixture), &ws.root);
                ws.put(".bazelversion", format!("{bazel}\n"));
            }
            None => {
                ws.put("MODULE.bazel", NO_HUB);
                ws.put("go.mod", GO_MOD);
            }
        }
        // The module as upstream ships it, BUILD file included.
        let module = ws
            .cache
            .join("example.com")
            .join(format!("upstream@{VERSION}"));
        std::fs::create_dir_all(&module).unwrap();
        for (name, pristine, _) in FILES {
            std::fs::write(module.join(name), pristine).unwrap();
        }
        std::fs::write(
            module.join("go.mod"),
            format!("module {MODULE}\n\ngo 1.21\n"),
        )
        .unwrap();
        std::fs::write(module.join("BUILD.bazel"), "# upstream\n").unwrap();
        let hashes =
            FILES.map(|(_, pristine, patched)| (git_sha256(pristine), git_sha256(patched)));
        let entry = |at: usize| PatchEntry {
            file_name: FILES[at].0,
            before_hash: &hashes[at].0,
            after_hash: &hashes[at].1,
        };
        let socket = ws.root.join(".socket");
        write_minimal_manifest(&socket, PURL, UUID, &[entry(0), entry(1)]);
        for (_, _, patched) in FILES {
            write_blob(&socket, &git_sha256(patched), patched);
        }
        ws
    }

    fn put(&self, rel: &str, bytes: impl AsRef<[u8]>) {
        let levels = rel.split('/');
        let path = levels.fold(self.root.clone(), |dir, level| dir.join(level));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    /// The directory of the copy.
    fn copy_dir(&self) -> PathBuf {
        let levels = COPY.split('/');
        levels.fold(self.root.clone(), |dir, level| dir.join(level))
    }

    /// The copy's file `name`.
    fn copied(&self, name: &str) -> PathBuf {
        self.copy_dir().join(name)
    }

    fn run(&self, args: &[&str], more: &[(&str, &str)]) -> (i32, String, String) {
        let cache = self.cache.to_str().unwrap();
        let mut env = vec![("GOMODCACHE", cache), ("GOFLAGS", ""), ("GOWORK", "off")];
        env.extend_from_slice(more);
        run_with_env(&self.root, args, &env)
    }

    /// `apply --json` for the Go patch, dry or wet: the exit code and
    /// the envelope.
    fn apply(&self, dry_run: bool) -> (i32, Value) {
        let mut args = vec!["apply", "--offline", "--json", "--ecosystems", "golang"];
        args.extend(dry_run.then_some("--dry-run"));
        let (code, stdout, stderr) = self.run(&args, &[]);
        assert!(!stdout.is_empty(), "no envelope (exit {code}):\n{stderr}");
        (code, parse_json_envelope(&stdout))
    }

    /// [`Workspace::apply`], wet, with a module cache that holds nothing:
    /// the upstream module is not installed, so `apply` can only reuse the
    /// copy that is there.
    fn apply_without_upstream(&self) -> (i32, Value) {
        let empty = self.cache.with_file_name("empty-modcache");
        std::fs::create_dir_all(&empty).unwrap();
        let args = ["apply", "--offline", "--json", "--ecosystems", "golang"];
        let (code, stdout, stderr) = self.run(&args, &[("GOMODCACHE", empty.to_str().unwrap())]);
        assert!(!stdout.is_empty(), "no envelope (exit {code}):\n{stderr}");
        (code, parse_json_envelope(&stdout))
    }

    /// A set-aside original of the copy's `a.go`, as an interrupted run
    /// names one.
    fn leftover(&self) -> PathBuf {
        self.copied(&format!(".socket-orig-a.go-{UUID}"))
    }

    /// Whether an enabled lane serves the workspace's Go hub in agent
    /// mode, on the Bazel release the checkout pins.
    fn admitted(&self) -> bool {
        let root = RootRef {
            root: self.root.clone(),
            project_rel: String::new(),
            boundary_levels: 0,
        };
        let view = DiskView::new(&root);
        let model = read_workspace(&root, &view).expect("a workspace that can be read");
        let gazelle = |hub: &socket_patch_core::bazel::model::Hub| hub.ruleset == Ruleset::Gazelle;
        let hub = model.hubs.iter().position(gazelle).expect("a gazelle hub");
        let cell = Cell::of(&model, HubId(hub), Mode::Agent).expect("the hub's cell");
        lanes::admits(&lanes::PRODUCTION, &cell)
    }

    /// The copy as a wet run leaves it once it went through.
    fn assert_patched(&self) {
        for (name, _, patched) in FILES {
            assert_eq!(std::fs::read(self.copied(name)).unwrap(), patched, "{name}");
        }
    }
}

/// Every stage and set-aside original in the tree, by path.
fn leftovers(tree: &Snapshot) -> Vec<&String> {
    let transient =
        |name: &str| name.starts_with(".socket-stage-") || name.starts_with(".socket-orig-");
    let left = |path: &&String| path.rsplit('/').next().is_some_and(transient);
    tree.keys().filter(left).collect()
}

/// The details of the run-level entries of `code` in the envelope. A run
/// with nothing to say has no `warnings` member at all.
fn warnings_of(envelope: &Value, code: Code) -> Vec<&str> {
    let entries = envelope["warnings"].as_array();
    let entries = entries.map(Vec::as_slice).unwrap_or_default();
    let of_code = entries
        .iter()
        .filter(|entry| entry["code"] == code.as_str());
    of_code
        .map(|entry| entry["detail"].as_str().expect("a detail"))
        .collect()
}

/// The failed event of a refused Go write: the agent Go code as its
/// `errorCode`, and a sentence that leads with the code and ends with
/// "nothing was written". Returns its `details`.
fn refused(envelope: &Value) -> &Value {
    let event = event_for(envelope, PURL);
    assert_eq!(event["action"], "failed", "{envelope:#}");
    let code = Code::AgentGoUnsupported.as_str();
    assert_eq!(event["errorCode"], code, "{envelope:#}");
    let error = event["error"].as_str().expect("the refusal's sentence");
    assert!(error.starts_with(&format!("{code}: ")), "{error}");
    assert!(error.ends_with("nothing was written"), "{error}");
    &event["details"]
}

#[test]
fn a_go_deps_hub_refuses_the_write_with_its_code_token_and_lift() {
    let ws = Workspace::new(Some((GO_DEPS, "9.3.2")));
    let before = snapshot(&ws.root);
    for dry_run in [true, false] {
        let (code, envelope) = ws.apply(dry_run);
        if ws.admitted() {
            // A lane serves the cell: what it writes is its own suite's.
            assert_write_policy(&before, &snapshot(&ws.root));
            return;
        }
        // A dry run is refused where the real run is, in the same words.
        assert_eq!(code, 1, "{envelope:#}");
        let details = refused(&envelope);
        assert_eq!(details["token"], "lane_not_enabled", "{envelope:#}");
        let lift = json!({ "kind": "enable_lane", "lane": "A-GO1" });
        assert_eq!(details["lift"], lift, "{envelope:#}");
        assert_eq!(events(&envelope).len(), 1, "{envelope:#}");
        // The refusal is the package's event. The advisory says that the
        // installed copy is patched all the same and the exit code
        // unchanged, which is false of a package nothing was written for:
        // it does not name this one. What the run says about the
        // workspace is said all the same.
        let advised = warnings_of(&envelope, Code::AgentNotConsumed);
        let names = |detail: &&str| detail.contains(PURL);
        assert!(!advised.iter().any(names), "{envelope:#}");
        let detected = warnings_of(&envelope, Code::WorkspaceDetected);
        assert_eq!(detected.len(), 1, "{envelope:#}");
        assert_same_tree(&before, &snapshot(&ws.root));
    }
    // A person reads the code and the remedy on stderr, also when silent.
    let args = ["apply", "--offline", "--silent", "--ecosystems", "golang"];
    let (code, _, stderr) = ws.run(&args, &[]);
    assert_eq!(code, 1, "{stderr}");
    assert!(
        stderr.contains(Code::AgentGoUnsupported.as_str()),
        "{stderr}"
    );
    assert!(stderr.contains("lane A-GO1 is not enabled"), "{stderr}");
    assert_same_tree(&before, &snapshot(&ws.root));
}

#[test]
fn a_live_go_repository_consumer_refuses_under_its_own_token() {
    let ws = Workspace::new(Some((GO_REPOSITORY, "7.7.2")));
    let before = snapshot(&ws.root);
    // No lane is designed for this shape in agent mode at all.
    assert!(!ws.admitted());
    for dry_run in [true, false] {
        let (code, envelope) = ws.apply(dry_run);
        assert_eq!(code, 1, "{envelope:#}");
        let details = refused(&envelope);
        assert_eq!(details["token"], "workspace_go_repository", "{envelope:#}");
        // No lane to name, so the lift names none.
        assert_eq!(
            details["lift"],
            json!({ "kind": "enable_lane" }),
            "{envelope:#}"
        );
        assert_same_tree(&before, &snapshot(&ws.root));
    }
}

/// A redirect that an earlier release wrote, or that was written before
/// the workspace built its Go modules with gazelle, is left as it is: a
/// run that has nothing to write asks nothing and fails nothing. Once it
/// would write (the copy drifted), it is refused and writes nothing.
#[test]
fn a_redirect_in_sync_is_left_alone_and_a_drifted_one_is_not_rebuilt() {
    let ws = Workspace::new(None);
    let (code, envelope) = ws.apply(false);
    assert_eq!(code, 0, "{envelope:#}");
    ws.assert_patched();

    // The workspace starts building the module with gazelle.
    let module = std::fs::read(fixture_dir(GO_DEPS).join("MODULE.bazel")).unwrap();
    ws.put("MODULE.bazel", module);
    ws.put(".bazelversion", "9.3.2\n");
    let governed = snapshot(&ws.root);
    for dry_run in [true, false] {
        let (code, envelope) = ws.apply(dry_run);
        assert_eq!(code, 0, "{envelope:#}");
        assert_ne!(
            event_for(&envelope, PURL)["action"],
            "failed",
            "{envelope:#}"
        );
        assert_same_tree(&governed, &snapshot(&ws.root));
    }

    std::fs::write(ws.copied("a.go"), FILES[0].1).unwrap();
    let drifted = snapshot(&ws.root);
    let (code, envelope) = ws.apply(false);
    if ws.admitted() {
        assert_write_policy(&drifted, &snapshot(&ws.root));
        return;
    }
    assert_eq!(code, 1, "{envelope:#}");
    refused(&envelope);
    assert_same_tree(&drifted, &snapshot(&ws.root));
}

/// Where Bazel builds no Go for the project the gate changes nothing:
/// the run under a workspace is the run without one, but for the
/// `.bazelignore` line that hides the copy and the warning that says so.
#[test]
fn a_workspace_that_builds_no_go_is_patched_as_a_checkout_without_one() {
    let (plain, bazel) = (Workspace::new(None), Workspace::new(None));
    std::fs::remove_file(plain.root.join("MODULE.bazel")).unwrap();
    let neutral = |ws: &Workspace, envelope: &Value| {
        let text = serde_json::to_string(&envelope["events"]).unwrap();
        // The paths differ by the temporary directory alone.
        let root = serde_json::to_string(&ws.root).unwrap();
        text.replace(root.trim_matches('"'), "<root>")
    };
    let line = Code::WorkspaceIgnoreLineAdded.as_str().to_string();
    for dry_run in [true, false] {
        let (plain_code, plain_run) = plain.apply(dry_run);
        let (bazel_code, bazel_run) = bazel.apply(dry_run);
        assert_eq!(
            (plain_code, bazel_code),
            (0, 0),
            "{plain_run:#}\n{bazel_run:#}"
        );
        assert_eq!(neutral(&plain, &plain_run), neutral(&bazel, &bazel_run));
        assert_eq!(plain_run["summary"], bazel_run["summary"]);
        assert!(warning_codes(&plain_run).is_empty(), "{plain_run:#}");
        assert_eq!(warning_codes(&bazel_run), [line.clone()], "{bazel_run:#}");
    }
    plain.assert_patched();
    bazel.assert_patched();
    // The trees differ by the Bazel files alone.
    let mut under_bazel = snapshot(&bazel.root);
    for path in [
        "MODULE.bazel",
        ".bazelignore",
        ".socket/bazel",
        ".socket/bazel/index.json",
    ] {
        assert!(under_bazel.remove(path).is_some(), "{path}");
    }
    assert_same_tree(&snapshot(&plain.root), &under_bazel);
}

/// Hazard HZ-27. A leftover stage or set-aside original in the copy is an
/// action input wherever Bazel globs the directory, so none outlives the
/// writer: not after a run, and not after the run that follows one that
/// was cut short, whatever that run decides and however young the file.
#[test]
fn no_stage_or_original_is_left_after_a_run_or_an_interrupted_one() {
    let ws = Workspace::new(None);
    let before = snapshot(&ws.root);
    // A crash after the first of the two renames (exit 86, no cleanup).
    let args = ["apply", "--offline", "--json", "--ecosystems", "golang"];
    let crash = [("SOCKET_PATCH_FAILPOINT", "patch_file_committed")];
    let (code, _, stderr) = ws.run(&args, &crash);
    assert_eq!(code, 86, "{stderr}");
    let crashed = snapshot(&ws.root);
    let left = leftovers(&crashed);
    let named = |prefix: &str| left.iter().any(|path| path.contains(prefix));
    assert!(
        named(".socket-stage-b.go-") && named(".socket-orig-a.go-"),
        "{left:?}"
    );

    // The next run is refused (the workspace now builds the module with
    // gazelle), so nothing rebuilds the copy: the leftovers still go.
    let module = std::fs::read(fixture_dir(GO_DEPS).join("MODULE.bazel")).unwrap();
    ws.put("MODULE.bazel", module);
    ws.put(".bazelversion", "9.3.2\n");
    let (code, envelope) = ws.apply(true);
    if !ws.admitted() {
        assert_eq!(code, 1, "{envelope:#}");
        assert_eq!(
            leftovers(&snapshot(&ws.root)).len(),
            left.len(),
            "a dry run writes nothing"
        );
        let (code, envelope) = ws.apply(false);
        assert_eq!(code, 1, "{envelope:#}");
        refused(&envelope);
        assert_eq!(leftovers(&snapshot(&ws.root)), Vec::<&String>::new());
    }

    // And after a run that goes through there is none either: the policy
    // check fails on a stage or an original anywhere in the tree.
    ws.put("MODULE.bazel", NO_HUB);
    std::fs::remove_file(ws.root.join(".bazelversion")).unwrap();
    let (code, envelope) = ws.apply(false);
    assert_eq!(code, 0, "{envelope:#}");
    ws.assert_patched();
    let after = snapshot(&ws.root);
    assert_write_policy(&before, &after);
    assert_eq!(leftovers(&after), Vec::<&String>::new());
}

/// Hazard HZ-27, second half (probe C4): a file with a second link is
/// never written through. With repository-cache hard links a fetched file
/// shares its inode with the cache entry, and a truncating write would
/// rewrite the cache with no error. The writer replaces directory entries
/// only, so the other name keeps its bytes.
#[test]
fn a_file_with_a_second_link_is_never_written_through() {
    let ws = Workspace::new(None);
    // An earlier copy whose file is also an entry of a cache elsewhere.
    let cache_entry = ws.cache.with_file_name("cache-entry");
    std::fs::write(&cache_entry, b"what the cache holds\n").unwrap();
    let copied = ws.copied("a.go");
    std::fs::create_dir_all(copied.parent().unwrap()).unwrap();
    std::fs::hard_link(&cache_entry, &copied).unwrap();
    std::fs::write(ws.copied("go.mod"), format!("module {MODULE}\n")).unwrap();

    let (code, envelope) = ws.apply(false);
    assert_eq!(code, 0, "{envelope:#}");
    ws.assert_patched();
    assert_eq!(
        std::fs::read(&cache_entry).unwrap(),
        b"what the cache holds\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(std::fs::metadata(&cache_entry).unwrap().nlink(), 1);
        assert_eq!(std::fs::metadata(&copied).unwrap().nlink(), 1);
    }
}

/// A Bazel workspace somebody builds above the repository is one nobody
/// can read: whether it builds the project's Go modules is not known, and
/// not known is not "no". The write is refused, with the decision that
/// would lift it (design 11.3, O15). A stray workspace file up there
/// governs nothing, and the run is what it is without one.
#[test]
fn a_bazel_root_above_the_repository_refuses_until_it_can_be_read() {
    let ws = Workspace::new(None);
    std::fs::remove_file(ws.root.join("MODULE.bazel")).unwrap();
    let above = ws.root.parent().unwrap().to_path_buf();
    std::fs::write(above.join("WORKSPACE"), "").unwrap();
    std::fs::write(above.join(".bazelversion"), "7.7.2\n").unwrap();
    let before = snapshot(&ws.root);
    for dry_run in [true, false] {
        let (code, envelope) = ws.apply(dry_run);
        assert_eq!(code, 1, "{envelope:#}");
        let details = refused(&envelope);
        assert_eq!(
            details["token"], "bazel_root_outside_repository",
            "{envelope:#}"
        );
        let lift = json!({ "kind": "owner", "decision": "O15" });
        assert_eq!(details["lift"], lift, "{envelope:#}");
        assert_same_tree(&before, &snapshot(&ws.root));
    }

    // Nothing beside the file says anybody builds there.
    std::fs::remove_file(above.join(".bazelversion")).unwrap();
    let (code, envelope) = ws.apply(false);
    assert_eq!(code, 0, "{envelope:#}");
    ws.assert_patched();
    assert!(!ws.root.join(".bazelignore").exists());
}

/// A `WORKSPACE` file left beside a `MODULE.bazel` that builds no Go is
/// one Bazel 8 does not evaluate and Bazel 9 cannot. Its `go_repository`
/// builds nothing, so the patch is applied as it is without the file:
/// the same exit code and the same tree, and no agent Go refusal.
#[test]
fn a_dead_workspace_file_changes_nothing_for_a_module_file_with_no_go() {
    for bazel in ["8.4.2", "9.3.2"] {
        let fixture = Some((GO_REPOSITORY, bazel));
        let (dead, clean) = (Workspace::new(fixture), Workspace::new(fixture));
        dead.put("MODULE.bazel", NO_HUB);
        clean.put("MODULE.bazel", NO_HUB);
        std::fs::remove_file(clean.root.join("WORKSPACE")).unwrap();
        for dry_run in [true, false] {
            let (dead_code, dead_run) = dead.apply(dry_run);
            let (clean_code, clean_run) = clean.apply(dry_run);
            let said = format!("Bazel {bazel}\n{dead_run:#}\n{clean_run:#}");
            assert_eq!((dead_code, clean_code), (0, 0), "{said}");
            assert_eq!(
                event_for(&dead_run, PURL)["action"],
                event_for(&clean_run, PURL)["action"],
                "{said}"
            );
            assert_eq!(dead_run["summary"], clean_run["summary"], "{said}");
            let unsupported = Code::AgentGoUnsupported.as_str();
            assert!(!dead_run.to_string().contains(unsupported), "{said}");
            // Bazel builds the module from no lock here, so nothing says
            // that its build does not get the patch.
            assert!(
                warnings_of(&dead_run, Code::AgentNotConsumed).is_empty(),
                "{said}"
            );
        }
        dead.assert_patched();
        clean.assert_patched();
        let mut with_the_file = snapshot(&dead.root);
        assert!(with_the_file.remove("WORKSPACE").is_some());
        assert_same_tree(&snapshot(&clean.root), &with_the_file);
    }
}

/// A copy that is already there under a Bazel root above the repository
/// is not refused (design 3, HZ-04; 11.3, O15). Its rebuild leaves
/// `go.mod` as it is, so the workspace nobody can read is handed nothing
/// it does not have already: the copy is patched again and the run says
/// that the tree needs a line it cannot write. A copy that is not there
/// is a new tree, and creating one stays refused.
#[test]
fn a_stale_copy_under_a_bazel_root_above_the_repository_is_rebuilt() {
    let ws = Workspace::new(None);
    std::fs::remove_file(ws.root.join("MODULE.bazel")).unwrap();
    let (code, envelope) = ws.apply(false);
    assert_eq!(code, 0, "{envelope:#}");
    ws.assert_patched();

    // Somebody builds the directory above the repository with Bazel.
    let above = ws.root.parent().unwrap().to_path_buf();
    std::fs::write(above.join("WORKSPACE"), "").unwrap();
    std::fs::write(above.join(".bazelversion"), "7.7.2\n").unwrap();
    let in_sync = snapshot(&ws.root);
    let (code, envelope) = ws.apply(false);
    assert_eq!(code, 0, "{envelope:#}");
    assert_same_tree(&in_sync, &snapshot(&ws.root));

    // One file of the copy is the upstream one again.
    std::fs::write(ws.copied("a.go"), FILES[0].1).unwrap();
    let stale = snapshot(&ws.root);
    let (code, envelope) = ws.apply(true);
    assert_eq!(code, 0, "{envelope:#}");
    assert_ne!(event_for(&envelope, PURL)["action"], "failed");
    assert_same_tree(&stale, &snapshot(&ws.root));
    let (code, envelope) = ws.apply(false);
    assert_eq!(code, 0, "{envelope:#}");
    assert_eq!(
        event_for(&envelope, PURL)["action"],
        "applied",
        "{envelope:#}"
    );
    ws.assert_patched();
    // `go.mod` and everything else is what it was while in sync.
    assert_same_tree(&in_sync, &snapshot(&ws.root));
    let needed = Code::WorkspaceIgnoreLineNeeded;
    assert!(
        !warnings_of(&envelope, needed).is_empty(),
        "the tree is reported: {envelope:#}"
    );

    // The copy is gone and `go.mod` still points at it: the rebuild would
    // create a tree under a root whose `.bazelignore` nobody can write.
    std::fs::remove_dir_all(ws.copy_dir()).unwrap();
    let gone = snapshot(&ws.root);
    for dry_run in [true, false] {
        let (code, envelope) = ws.apply(dry_run);
        assert_eq!(code, 1, "{envelope:#}");
        let details = refused(&envelope);
        assert_eq!(
            details["token"], "bazel_root_outside_repository",
            "{envelope:#}"
        );
        assert_same_tree(&gone, &snapshot(&ws.root));
    }
}

/// Hazard HZ-27 on the runs that rebuild nothing. After a run that was
/// cut short, the next run finds no upstream module to rebuild from and
/// fails: the stage and the set-aside originals go all the same. And a
/// copy that is in sync is swept by the run that leaves it alone,
/// whichever way `apply` reaches it. No lane is asked in either case.
#[test]
fn a_run_that_rebuilds_nothing_leaves_no_stage_or_original_either() {
    let ws = Workspace::new(None);
    let args = ["apply", "--offline", "--json", "--ecosystems", "golang"];
    let crash = [("SOCKET_PATCH_FAILPOINT", "patch_file_committed")];
    let (code, _, stderr) = ws.run(&args, &crash);
    assert_eq!(code, 86, "{stderr}");
    assert!(!leftovers(&snapshot(&ws.root)).is_empty());
    let (code, envelope) = ws.apply_without_upstream();
    assert_eq!(code, 1, "{envelope:#}");
    let event = event_for(&envelope, PURL);
    assert_eq!(event["action"], "failed", "{envelope:#}");
    assert_eq!(event["errorCode"], "apply_failed", "{envelope:#}");
    assert_eq!(leftovers(&snapshot(&ws.root)), Vec::<&String>::new());

    // In sync: the run with the upstream module, then the one without.
    let (code, envelope) = ws.apply(false);
    assert_eq!(code, 0, "{envelope:#}");
    ws.assert_patched();
    let in_sync = snapshot(&ws.root);
    for reuse in [false, true] {
        std::fs::write(ws.leftover(), b"old").unwrap();
        let (code, envelope) = match reuse {
            true => ws.apply_without_upstream(),
            false => ws.apply(false),
        };
        assert_eq!(code, 0, "reuse={reuse}: {envelope:#}");
        assert_ne!(event_for(&envelope, PURL)["action"], "failed");
        assert!(!ws.leftover().exists(), "reuse={reuse}: left behind");
    }
    // The sweep removed the leftover and nothing else. Only the empty
    // module cache of the second run is new, and it lies beside the
    // checkout.
    assert_same_tree(&in_sync, &snapshot(&ws.root));
}
