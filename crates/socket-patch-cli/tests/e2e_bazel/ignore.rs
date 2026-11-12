//! Hermetic CLI tests: `.bazelignore` lines through the root channel
//! (hazard HZ-04, design 5.3 and 5.4).
//!
//! An agent Go patch is a copy of the module under `.socket/go-patches`,
//! upstream BUILD file included. Under a Bazel root that file joins
//! `//...`, so the copy is created only behind a line in the root's
//! `.bazelignore`, and `rollback` takes the line out with the last copy.
//! The same channel serves the dir-shaped `.socket/vendor` trees.
//!
//! No Go and no Bazel: a fabricated module cache holds the module, and
//! the real-Bazel twin (`e2e_bazel_build::ignore`) shows that `//...`
//! builds behind the line.

use std::path::{Path, PathBuf};

use serde_json::Value;
use socket_patch_core::bazel::codes::Code;

use crate::bazel_common::{
    assert_restore_policy_with, assert_same_tree, assert_write_policy_with, snapshot, Layout,
    WriteClass,
};
use crate::common::envelope::{has_event, parse_json_envelope, warning_codes};
use crate::common::{git_sha256, run_with_env, write_blob, write_minimal_manifest, PatchEntry};

#[allow(clippy::duplicate_mod)]
#[path = "../prebuilt_common/mod.rs"]
mod prebuilt_common;

const MODULE: &str = "example.com/m";
const VERSION: &str = "v1.0.0";
const PURL: &str = "pkg:golang/example.com/m@v1.0.0";
const UUID: &str = "0b5e1c1e-5f0a-4c8e-9a51-6d1f3c2b7a90";
const PRISTINE: &[u8] = b"package m\n\nfunc V() string { return \"upstream\" }\n";
const PATCHED: &[u8] = b"package m\n\nfunc V() string { return \"patched\" }\n";
/// What an upstream module ships and no other workspace can load.
const UPSTREAM_BUILD: &str = "load(\"@io_bazel_rules_go//go:def.bzl\", \"go_library\")\n";
const COPY: &str = ".socket/go-patches/example.com/m@v1.0.0";

/// A checkout that is one Bazel workspace, and a module cache beside it.
struct Workspace {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    cache: PathBuf,
}

impl Workspace {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("a temporary directory");
        let top = std::fs::canonicalize(tmp.path()).expect("its real path");
        let (root, cache) = (top.join("ws"), top.join("modcache"));
        let module = cache.join(format!("{MODULE}@{VERSION}"));
        std::fs::create_dir_all(&module).unwrap();
        std::fs::write(module.join("m.go"), PRISTINE).unwrap();
        std::fs::write(
            module.join("go.mod"),
            format!("module {MODULE}\n\ngo 1.21\n"),
        )
        .unwrap();
        std::fs::write(module.join("BUILD.bazel"), UPSTREAM_BUILD).unwrap();
        // `.git` makes `ws` the repository: nothing above it is read.
        std::fs::create_dir_all(root.join(".git")).unwrap();
        let ws = Self {
            _tmp: tmp,
            root,
            cache,
        };
        ws.put("MODULE.bazel", "module(name = \"ws\")\n");
        ws
    }

    fn put(&self, rel: &str, text: impl AsRef<[u8]>) {
        let path = self.root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn bytes(&self, rel: &str) -> Vec<u8> {
        let path = self.root.join(rel);
        std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    /// A Go project at `rel` (`""` = the Bazel root) that requires the
    /// module, with the patch in its manifest and blob store.
    fn project(&self, rel: &str) -> PathBuf {
        let dir = self.root.join(rel);
        let go_mod = format!("module example.com/app\n\ngo 1.21\n\nrequire {MODULE} {VERSION}\n");
        self.put(&join(rel, "go.mod"), go_mod);
        let files = [PatchEntry {
            file_name: "m.go",
            before_hash: &git_sha256(PRISTINE),
            after_hash: &git_sha256(PATCHED),
        }];
        write_minimal_manifest(&dir.join(".socket"), PURL, UUID, &files);
        write_blob(&dir.join(".socket"), &git_sha256(PATCHED), PATCHED);
        dir
    }

    fn run(&self, cwd: &Path, args: &[&str]) -> (i32, String, String) {
        let cache = self.cache.to_str().unwrap();
        let env = [("GOMODCACHE", cache), ("GOFLAGS", ""), ("GOWORK", "off")];
        run_with_env(cwd, args, &env)
    }

    /// A `vendor` run in `project`. Vendoring downloads the artifact, so
    /// a loopback patch service serves the one the manifest describes.
    fn vendor(&self, project: &Path, args: &[&str]) -> (i32, String, String) {
        let cache = self.cache.to_str().unwrap();
        let mut command = crate::common::hermetic_command(&crate::common::binary());
        command.current_dir(project).env("GOMODCACHE", cache);
        let env = [("GOMODCACHE", cache)];
        let _service = prebuilt_common::prepare_command(&mut command, project, args, &env);
        let out = command.output().expect("run socket-patch");
        let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
        let code = out.status.code().unwrap_or(-1);
        (code, text(&out.stdout), text(&out.stderr))
    }

    /// `apply --json` in `project`: the exit code and the envelope.
    fn apply(&self, project: &Path) -> (i32, Value) {
        let args = ["apply", "--offline", "--json", "--ecosystems", "golang"];
        let (code, stdout, stderr) = self.run(project, &args);
        assert!(!stdout.is_empty(), "no envelope (exit {code}):\n{stderr}");
        (code, parse_json_envelope(&stdout))
    }

    /// `apply` that must patch the module: the envelope.
    fn applied(&self, project: &Path) -> Value {
        let (code, envelope) = self.apply(project);
        assert_eq!(code, 0, "{envelope:#}");
        assert_eq!(
            std::fs::read(project.join(COPY).join("m.go")).unwrap(),
            PATCHED
        );
        let upstream = std::fs::read_to_string(project.join(COPY).join("BUILD.bazel"));
        assert_eq!(
            upstream.unwrap(),
            UPSTREAM_BUILD,
            "the copy keeps the upstream BUILD file"
        );
        envelope
    }

    /// `rollback` in `project` that keeps the manifest and the blobs, so
    /// the tree can be compared with the one before `apply`.
    fn roll_back(&self, project: &Path) {
        let args = [
            "rollback",
            "--yes",
            "--offline",
            "--json",
            "--preserve-state",
        ];
        let (code, stdout, stderr) = self.run(project, &args);
        assert_eq!(code, 0, "rollback failed:\n{stdout}\n{stderr}");
    }
}

fn join(dir: &str, name: &str) -> String {
    match dir {
        "" => name.to_string(),
        dir => format!("{dir}/{name}"),
    }
}

/// The detail of the one warning of `code`; panics when there is not one.
fn warning(envelope: &Value, code: Code) -> &str {
    let warnings = envelope["warnings"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    let of_code: Vec<&Value> = warnings
        .iter()
        .filter(|w| w["code"] == code.as_str())
        .collect();
    let [warning] = of_code.as_slice() else {
        panic!("one `{code}` warning expected in:\n{envelope:#}");
    };
    warning["detail"].as_str().expect("a detail")
}

/// The error of the one failed event; panics when the run did not fail so.
fn refusal(envelope: &Value) -> &str {
    let events = envelope["events"].as_array().expect("events");
    let [event] = events.as_slice() else {
        panic!("one event expected in:\n{envelope:#}");
    };
    assert_eq!(event["action"], "failed", "{envelope:#}");
    event["error"].as_str().expect("the refusal text")
}

const ROOT_ONLY: Layout<'static> = Layout {
    hub_locks: &[],
    bazel_roots: &[""],
};

#[test]
fn a_project_at_the_root_and_one_below_it_each_get_their_line() {
    for rel in ["", "svc/api"] {
        let ws = Workspace::new();
        let project = ws.project(rel);
        let before = snapshot(&ws.root);
        let line = join(rel, ".socket/go-patches");

        let envelope = ws.applied(&project);
        let detail = warning(&envelope, Code::WorkspaceIgnoreLineAdded);
        let file = ws.root.join(".bazelignore");
        let added = format!("added the line `{line}` to {}", file.display());
        assert!(detail.contains(&added), "{detail}");
        assert_eq!(ws.bytes(".bazelignore"), format!("{line}\n").as_bytes());
        let index: Value = serde_json::from_slice(&ws.bytes(".socket/bazel/index.json")).unwrap();
        let rows = serde_json::json!([{
            "addedFinalNewline": false, "createdFile": true, "file": ".bazelignore",
            "line": line, "project": rel,
        }]);
        assert_eq!(index["ignoreLines"], rows, "{index:#}");

        // Every changed path is one socket-patch may write under Bazel:
        // the ignore line, the owned index, `.socket` state and `go.mod`.
        let after = snapshot(&ws.root);
        let writes = assert_write_policy_with(&before, &after, &ROOT_ONLY);
        let class = |path: &str| {
            writes
                .iter()
                .find(|(p, _)| p == path)
                .map(|(_, class)| *class)
        };
        assert_eq!(class(".bazelignore"), Some(WriteClass::IgnoreLine));
        assert_eq!(
            class(".socket/bazel/index.json"),
            Some(WriteClass::OwnedFile)
        );
        assert_eq!(class(&join(rel, "go.mod")), Some(WriteClass::NativeLock));
        let outside = writes.iter().filter(|(path, class)| {
            *class == WriteClass::NativeLock && *path != join(rel, "go.mod")
        });
        assert_eq!(outside.count(), 0, "{writes:?}");

        // A second run finds the line and the copy and writes nothing.
        let (code, again) = ws.apply(&project);
        assert_eq!(code, 0, "{again:#}");
        assert!(warning_codes(&again).is_empty(), "{again:#}");
        assert_same_tree(&after, &snapshot(&ws.root));
    }
}

#[test]
fn two_sub_projects_share_the_file_and_one_rollback_run_restores_it() {
    let ws = Workspace::new();
    ws.put(".bazelignore", "node_modules");
    let (a, b) = (ws.project("a"), ws.project("b/c"));
    let before = snapshot(&ws.root);
    let envelope = ws.applied(&a);
    warning(&envelope, Code::WorkspaceIgnoreLineAdded);
    // A person reads the same on stderr.
    let (code, _, stderr) = ws.run(&b, &["apply", "--offline", "--ecosystems", "golang"]);
    assert_eq!(code, 0, "{stderr}");
    let file = ws.root.join(".bazelignore");
    let told = format!(
        "added the line `b/c/.socket/go-patches` to {}",
        file.display()
    );
    assert!(stderr.contains(&told), "{stderr}");
    let both = "node_modules\na/.socket/go-patches\nb/c/.socket/go-patches\n";
    assert_eq!(ws.bytes(".bazelignore"), both.as_bytes());
    let wired = snapshot(&ws.root);
    assert_write_policy_with(&before, &wired, &ROOT_ONLY);

    // One bare `rollback` from the root reaches both projects. Each line
    // goes with its project, and the newline the first insert put behind
    // the user's last line goes with the last of them.
    let args = ["rollback", "--yes", "--offline", "--preserve-state"];
    let (code, stdout, stderr) = ws.run(&ws.root, &args);
    assert_eq!(code, 0, "rollback failed:\n{stdout}\n{stderr}");
    for project in [&a, &b] {
        assert!(!project.join(".socket/go-patches").exists(), "{stdout}");
    }
    let after = snapshot(&ws.root);
    assert_restore_policy_with(&wired, &after, &ROOT_ONLY);
    assert_same_tree(&before, &after);
}

#[test]
fn a_build_file_gazelle_rewired_keeps_the_line_out_and_the_run_going() {
    let ws = Workspace::new();
    let project = ws.project("");
    // An earlier release left the copy with no line, and gazelle found it:
    // the user's own target now depends on a package inside the tree.
    ws.put(&format!("{COPY}/m.go"), PRISTINE);
    let rewired = "go_library(\n    name = \"app\",\n    deps = \
                   [\"//.socket/go-patches/example.com/m@v1.0.0:m\"],\n)\n";
    ws.put("BUILD.bazel", rewired);
    let before = snapshot(&ws.root);

    let envelope = ws.applied(&project);
    let detail = warning(&envelope, Code::WorkspaceIgnoreLineNeeded);
    let hit = format!("{}:3 names a label", ws.root.join("BUILD.bazel").display());
    for part in [
        hit.as_str(),
        "Add the line `.socket/go-patches`",
        "gazelle target",
    ] {
        assert!(detail.contains(part), "{part}: {detail}");
    }
    assert!(!warning_codes(&envelope).contains(&Code::WorkspaceIgnoreLineAdded.to_string()));
    // The label still resolves: no line was written, and nothing recorded.
    assert!(!ws.root.join(".bazelignore").exists());
    assert!(!ws.root.join(".socket/bazel").exists());
    assert_eq!(ws.bytes("BUILD.bazel"), rewired.as_bytes());
    assert_write_policy_with(&before, &snapshot(&ws.root), &ROOT_ONLY);
}

#[test]
fn nested_roots_refuse_the_tree_and_print_each_line_and_file() {
    let ws = Workspace::new();
    ws.put("svc/WORKSPACE", "");
    let project = ws.project("svc/api");
    let before = snapshot(&ws.root);

    let (code, envelope) = ws.apply(&project);
    assert_eq!(code, 1, "{envelope:#}");
    let text = refusal(&envelope);
    assert!(
        text.starts_with(Code::AgentGoUnsupported.as_str()),
        "{text}"
    );
    let outer = ws.root.join(".bazelignore");
    let inner = ws.root.join("svc/.bazelignore");
    for part in [
        "`nested_bazel_roots`".to_string(),
        format!(
            "the line `svc/api/.socket/go-patches` to {}",
            outer.display()
        ),
        format!("the line `api/.socket/go-patches` to {}", inner.display()),
        "nothing was written".to_string(),
    ] {
        assert!(text.contains(&part), "{part}: {text}");
    }
    assert_same_tree(&before, &snapshot(&ws.root));

    // The user adds both lines, as the refusal says: the run goes through
    // and writes neither file.
    ws.put(".bazelignore", "svc/api/.socket/go-patches\n");
    ws.put("svc/.bazelignore", "api/.socket/go-patches\n");
    let ignored = snapshot(&ws.root);
    let envelope = ws.applied(&project);
    assert!(warning_codes(&envelope).is_empty(), "{envelope:#}");
    let layout = Layout {
        hub_locks: &[],
        bazel_roots: &["", "svc"],
    };
    let writes = assert_write_policy_with(&ignored, &snapshot(&ws.root), &layout);
    assert!(
        writes.iter().all(|(path, _)| path.starts_with("svc/api/")),
        "{writes:?}"
    );
}

#[test]
fn rollback_is_byte_identical_for_lf_crlf_and_a_missing_final_newline() {
    let cases: [(&str, Option<&str>, &str); 5] = [
        ("created", None, "{line}\n"),
        ("LF", Some("node_modules\n"), "node_modules\n{line}\n"),
        (
            "CRLF",
            Some("node_modules\r\ndist\r\n"),
            "node_modules\r\ndist\r\n{line}\r\n",
        ),
        (
            "LF, unterminated",
            Some("# mine\ndist"),
            "# mine\ndist\n{line}\n",
        ),
        ("CRLF, unterminated", Some("a\r\nb"), "a\r\nb\r\n{line}\r\n"),
    ];
    for (name, original, wired) in cases {
        let ws = Workspace::new();
        if let Some(text) = original {
            ws.put(".bazelignore", text);
        }
        let project = ws.project("svc");
        let before = snapshot(&ws.root);

        ws.applied(&project);
        let wired = wired.replace("{line}", "svc/.socket/go-patches");
        assert_eq!(ws.bytes(".bazelignore"), wired.as_bytes(), "{name}");
        let applied = snapshot(&ws.root);
        assert_write_policy_with(&before, &applied, &ROOT_ONLY);

        ws.roll_back(&project);
        let after = snapshot(&ws.root);
        assert_restore_policy_with(&applied, &after, &ROOT_ONLY);
        assert_same_tree(&before, &after);
    }
}

/// `remove` rolls back through the same seam as `rollback`.
#[test]
fn remove_takes_the_line_out_with_the_last_copy() {
    let ws = Workspace::new();
    ws.put(".bazelignore", "node_modules\r\n");
    let project = ws.project("svc");
    let before = snapshot(&ws.root);
    ws.applied(&project);
    let applied = snapshot(&ws.root);

    let args = [
        "remove",
        PURL,
        "--yes",
        "--offline",
        "--json",
        "--preserve-state",
    ];
    let (code, stdout, stderr) = ws.run(&project, &args);
    assert_eq!(code, 0, "remove failed:\n{stdout}\n{stderr}");
    let after = snapshot(&ws.root);
    assert_restore_policy_with(&applied, &after, &ROOT_ONLY);
    assert_same_tree(&before, &after);
}

#[test]
fn a_cr_only_bazelignore_is_refused_with_the_advisory_and_left_byte_for_byte() {
    let ws = Workspace::new();
    let cr_only = "node_modules\rdist\r";
    ws.put(".bazelignore", cr_only);
    let project = ws.project("svc");
    let before = snapshot(&ws.root);

    let (code, envelope) = ws.apply(&project);
    assert_eq!(code, 1, "{envelope:#}");
    let text = refusal(&envelope);
    assert!(
        text.starts_with(Code::WorkspaceIgnoreLineNeeded.as_str()),
        "{text}"
    );
    let file = ws.root.join(".bazelignore");
    let remedy = format!(
        "Add the line `svc/.socket/go-patches` to {}",
        file.display()
    );
    for part in [
        "lone carriage return",
        remedy.as_str(),
        "nothing was written",
    ] {
        assert!(text.contains(part), "{part}: {text}");
    }
    assert_eq!(ws.bytes(".bazelignore"), cr_only.as_bytes());
    assert_same_tree(&before, &snapshot(&ws.root));

    // In human mode the refusal is the package's error line.
    let (code, _, stderr) = ws.run(&project, &["apply", "--offline", "--ecosystems", "golang"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains(&remedy), "{stderr}");
    assert_same_tree(&before, &snapshot(&ws.root));
}

#[test]
fn a_vendored_go_tree_gets_its_line_and_the_revert_takes_it_back() {
    let ws = Workspace::new();
    ws.put(".bazelignore", "node_modules\r\n");
    let project = ws.project("svc");
    let before = snapshot(&ws.root);

    let (code, stdout, stderr) = ws.vendor(&project, &["vendor", "--json"]);
    assert_eq!(code, 0, "vendor failed:\n{stdout}\n{stderr}");
    let envelope = parse_json_envelope(&stdout);
    // `vendor` reports a package's advisories as events of that package.
    let added = Code::WorkspaceIgnoreLineAdded.as_str();
    assert!(has_event(&envelope, "skipped", added, PURL), "{envelope:#}");
    let unpacked = format!(".socket/vendor/golang/{UUID}/{MODULE}@{VERSION}/BUILD.bazel");
    assert_eq!(
        std::fs::read_to_string(project.join(unpacked)).unwrap(),
        UPSTREAM_BUILD
    );
    assert_eq!(
        ws.bytes(".bazelignore"),
        b"node_modules\r\nsvc/.socket/vendor\r\n"
    );
    let vendored = snapshot(&ws.root);
    assert_write_policy_with(&before, &vendored, &ROOT_ONLY);

    let (code, stdout, stderr) = ws.vendor(&project, &["vendor", "--revert", "--json"]);
    assert_eq!(code, 0, "revert failed:\n{stdout}\n{stderr}");
    let after = snapshot(&ws.root);
    assert_restore_policy_with(&vendored, &after, &ROOT_ONLY);
    assert_same_tree(&before, &after);
}

#[test]
fn a_project_outside_any_bazel_workspace_is_patched_as_before() {
    let ws = Workspace::new();
    std::fs::remove_file(ws.root.join("MODULE.bazel")).unwrap();
    let project = ws.project("svc");
    let envelope = ws.applied(&project);
    assert!(warning_codes(&envelope).is_empty(), "{envelope:#}");
    assert!(!ws.root.join(".bazelignore").exists());
    assert!(!ws.root.join(".socket").exists());
}
