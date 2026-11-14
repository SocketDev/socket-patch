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
use crate::common::envelope::{event_for, has_event, parse_json_envelope, warning_codes};
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
/// A second module, for a project that is patched in two steps.
const OTHER_PURL: &str = "pkg:golang/example.com/n@v1.0.0";
const OTHER_UUID: &str = "7c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f";
const OTHER_PRISTINE: &[u8] = b"package n\n\nfunc V() string { return \"upstream\" }\n";
const OTHER_PATCHED: &[u8] = b"package n\n\nfunc V() string { return \"patched\" }\n";
const OTHER_COPY: &str = ".socket/go-patches/example.com/n@v1.0.0";

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

    /// A second module for the Go project `project`, added after the
    /// first was patched: in the module cache with its upstream BUILD
    /// file, required by `go.mod`, and with its patch in the manifest.
    fn second_module(&self, project: &Path) {
        let module = self.cache.join("example.com/n@v1.0.0");
        std::fs::create_dir_all(&module).unwrap();
        std::fs::write(module.join("n.go"), OTHER_PRISTINE).unwrap();
        std::fs::write(module.join("go.mod"), "module example.com/n\n\ngo 1.21\n").unwrap();
        std::fs::write(module.join("BUILD.bazel"), UPSTREAM_BUILD).unwrap();
        let go_mod = project.join("go.mod");
        let mut text = std::fs::read_to_string(&go_mod).unwrap();
        text.push_str("\nrequire example.com/n v1.0.0\n");
        std::fs::write(&go_mod, text).unwrap();
        let path = project.join(".socket/manifest.json");
        let mut manifest: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        manifest["patches"][OTHER_PURL] = serde_json::json!({
            "uuid": OTHER_UUID,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": {"n.go": {
                "beforeHash": git_sha256(OTHER_PRISTINE),
                "afterHash": git_sha256(OTHER_PATCHED),
            }},
            "vulnerabilities": {},
            "description": "synthetic test patch",
            "license": "MIT",
            "tier": "free",
        });
        std::fs::write(&path, serde_json::to_string_pretty(&manifest).unwrap()).unwrap();
        write_blob(
            &project.join(".socket"),
            &git_sha256(OTHER_PATCHED),
            OTHER_PATCHED,
        );
    }

    fn run(&self, cwd: &Path, args: &[&str]) -> (i32, String, String) {
        let cache = self.cache.to_str().unwrap();
        let env = [("GOMODCACHE", cache), ("GOFLAGS", ""), ("GOWORK", "off")];
        run_with_env(cwd, args, &env)
    }

    /// A command that prints an envelope: the exit code and the envelope.
    fn json(&self, cwd: &Path, args: &[&str]) -> (i32, Value) {
        let (code, stdout, stderr) = self.run(cwd, args);
        assert!(!stdout.is_empty(), "no envelope (exit {code}):\n{stderr}");
        (code, parse_json_envelope(&stdout))
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
        self.json(project, &args)
    }

    /// `apply --dry-run --json` in `project`.
    fn dry_apply(&self, project: &Path) -> (i32, Value) {
        let args = [
            "apply",
            "--dry-run",
            "--offline",
            "--json",
            "--ecosystems",
            "golang",
        ];
        self.json(project, &args)
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

/// What a `vendor` run in `project` printed and every path it left under
/// the project's `.socket/vendor`: the message of an assertion on the
/// vendored tree, so that a failure on a platform nobody can rerun the
/// test on says what the run did.
fn vendor_report(project: &Path, stdout: &str, stderr: &str) -> String {
    let dir = project.join(".socket").join("vendor");
    let left: Vec<String> = match dir.is_dir() {
        true => snapshot(&dir).into_keys().collect(),
        false => Vec::new(),
    };
    format!(
        "{} holds {left:#?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        dir.display()
    )
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

        // A dry run says which line the run would add, and writes nothing.
        let (code, dry) = ws.dry_apply(&project);
        assert_eq!(code, 0, "{dry:#}");
        let would = warning(&dry, Code::WorkspaceIgnoreLineAdded);
        let told = format!("would add the line `{line}`");
        assert!(would.contains(&told), "{would}");
        assert_same_tree(&before, &snapshot(&ws.root));

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

        // A second run finds the line and the copy and writes nothing,
        // and a dry run of it has nothing to say either.
        for (code, again) in [ws.apply(&project), ws.dry_apply(&project)] {
            assert_eq!(code, 0, "{again:#}");
            assert!(warning_codes(&again).is_empty(), "{again:#}");
            assert_same_tree(&after, &snapshot(&ws.root));
        }
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

    // A dry run is refused where the real run is, in the same words.
    for (code, envelope) in [ws.dry_apply(&project), ws.apply(&project)] {
        assert_eq!(code, 1, "{envelope:#}");
        let text = refusal(&envelope);
        assert!(
            text.starts_with(Code::AgentGoUnsupported.as_str()),
            "{text}"
        );
        // The code and the token are fields of the event, not only words
        // of its text, and the lift says that the user's edit lifts it.
        let event = event_for(&envelope, PURL);
        assert_eq!(event["errorCode"], Code::AgentGoUnsupported.as_str());
        assert_eq!(event["details"]["token"], "nested_bazel_roots");
        assert_eq!(event["details"]["lift"]["kind"], "user_edit");
        let outer = ws.root.join(".bazelignore");
        let inner = ws.root.join("svc").join(".bazelignore");
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
    }

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
    // A refusal that no token names is the event's code all the same
    // (never `apply_failed`), it has no `details.token`, and its lift
    // says that the user's edit of the file lifts it (ROUTED R-024).
    let event = event_for(&envelope, PURL);
    let needed = Code::WorkspaceIgnoreLineNeeded.as_str();
    assert_eq!(event["errorCode"], needed, "{envelope:#}");
    assert!(event["details"].get("token").is_none(), "{envelope:#}");
    assert_eq!(event["details"]["lift"]["kind"], "user_edit");
    assert_eq!(event["details"]["lift"]["file"], ".bazelignore");
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

    // A copy base with nothing in it is no tree: the copy is as new as
    // before, and as refused.
    std::fs::create_dir_all(project.join(".socket/go-patches")).unwrap();
    let emptied = snapshot(&ws.root);
    let (code, envelope) = ws.apply(&project);
    assert_eq!(code, 1, "{envelope:#}");
    assert!(refusal(&envelope).contains("lone carriage return"));
    assert_same_tree(&emptied, &snapshot(&ws.root));
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
    // The unit is the module as its upstream ships it: the fixture service
    // packs the module cache's directory, BUILD file included.
    let ran = vendor_report(&project, &stdout, &stderr);
    let unpacked = format!(".socket/vendor/golang/{UUID}/{MODULE}@{VERSION}/BUILD.bazel");
    let upstream = std::fs::read_to_string(project.join(&unpacked));
    assert_eq!(
        upstream.unwrap_or_else(|e| panic!("read {unpacked}: {e}\n{ran}")),
        UPSTREAM_BUILD,
        "{ran}"
    );
    let ignore = String::from_utf8_lossy(&ws.bytes(".bazelignore")).into_owned();
    assert_eq!(ignore, "node_modules\r\nsvc/.socket/vendor\r\n", "{ran}");
    let vendored = snapshot(&ws.root);
    assert_write_policy_with(&before, &vendored, &ROOT_ONLY);

    let (code, stdout, stderr) = ws.vendor(&project, &["vendor", "--revert", "--json"]);
    assert_eq!(code, 0, "revert failed:\n{stdout}\n{stderr}");
    // Shown with a failure of the two checks below, which name paths only.
    println!("revert stdout:\n{stdout}\nrevert stderr:\n{stderr}");
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

/// The first copy was made before the workspace was a Bazel one, so it has
/// no line. It lets no second copy through: each copy is decided by
/// itself, and one that is in sync is not asked about at all.
#[test]
fn a_new_copy_beside_an_older_one_is_refused_where_its_line_cannot_be_written() {
    for case in ["nested roots", "a CR-only file"] {
        let ws = Workspace::new();
        std::fs::remove_file(ws.root.join("MODULE.bazel")).unwrap();
        let project = ws.project("svc/api");
        let envelope = ws.applied(&project);
        assert!(warning_codes(&envelope).is_empty(), "{envelope:#}");

        ws.put("MODULE.bazel", "module(name = \"ws\")\n");
        let code = match case {
            "nested roots" => {
                ws.put("svc/WORKSPACE", "");
                Code::AgentGoUnsupported
            }
            _ => {
                ws.put(".bazelignore", "node_modules\rdist\r");
                Code::WorkspaceIgnoreLineNeeded
            }
        };
        ws.second_module(&project);
        let before = snapshot(&ws.root);

        for (exit, envelope) in [ws.dry_apply(&project), ws.apply(&project)] {
            assert_eq!(exit, 1, "{case}: {envelope:#}");
            let failed = event_for(&envelope, OTHER_PURL);
            assert_eq!(failed["action"], "failed", "{case}: {envelope:#}");
            let text = failed["error"].as_str().expect("the refusal text");
            assert!(text.starts_with(code.as_str()), "{case}: {text}");
            // The copy that was not made is the one named.
            for part in ["n@v1.0.0 was not created", "nothing was written"] {
                assert!(text.contains(part), "{case}: {part}: {text}");
            }
            // The copy that is there is neither refused nor touched.
            let kept = event_for(&envelope, PURL);
            assert_ne!(kept["action"], "failed", "{case}: {envelope:#}");
            assert!(!project.join(OTHER_COPY).exists(), "{case}");
            assert_same_tree(&before, &snapshot(&ws.root));
        }
    }
}

/// The line is written before the backend decides anything. A run that
/// is refused or fails after that takes it back out: the root's files
/// are the user's, and nothing told them to commit an edit.
#[test]
fn a_run_that_fails_after_the_line_leaves_the_root_byte_identical() {
    let ws = Workspace::new();
    ws.put(".bazelignore", "node_modules");
    let project = ws.project("svc/api");
    let before = snapshot(&ws.root);

    // `vendor --offline` is refused by its backend, after the guard.
    let args = ["vendor", "--offline", "--json", "--ecosystems", "golang"];
    let (code, envelope) = ws.json(&project, &args);
    assert_eq!(code, 1, "{envelope:#}");
    let offline = "vendor_service_offline_conflict";
    assert!(
        has_event(&envelope, "failed", offline, PURL),
        "{envelope:#}"
    );
    assert!(warning_codes(&envelope).is_empty(), "{envelope:#}");
    assert_same_tree(&before, &snapshot(&ws.root));

    // `apply` copies the module and then finds that its file is not the
    // one the patch was made for: the copy goes, and the line with it.
    let cached = ws.cache.join(format!("{MODULE}@{VERSION}")).join("m.go");
    std::fs::write(
        cached,
        b"package m\n\nfunc V() string { return \"drifted\" }\n",
    )
    .unwrap();
    let (code, envelope) = ws.apply(&project);
    assert_eq!(code, 1, "{envelope:#}");
    let text = refusal(&envelope);
    assert!(
        !text.contains(Code::WorkspaceIgnoreLineAdded.as_str()),
        "{text}"
    );
    assert!(warning_codes(&envelope).is_empty(), "{envelope:#}");
    assert_same_tree(&before, &snapshot(&ws.root));
}

/// The vendored seam refuses like the agent one, with its own code where
/// a token names the case.
#[test]
fn a_vendored_tree_is_refused_where_its_line_cannot_be_written() {
    for case in ["nested roots", "a CR-only file", "a label under the tree"] {
        let ws = Workspace::new();
        let rel = if case == "a label under the tree" {
            ""
        } else {
            "svc/api"
        };
        let project = ws.project(rel);
        let line = format!("the line `{}`", join(rel, ".socket/vendor"));
        let outer = ws.root.join(".bazelignore").display().to_string();
        let (code, parts) = match case {
            "nested roots" => {
                ws.put("svc/WORKSPACE", "");
                let inner = ws.root.join("svc").join(".bazelignore");
                let parts = vec![
                    "`nested_bazel_roots`".to_string(),
                    format!("{line} to {outer}"),
                    format!("the line `api/.socket/vendor` to {}", inner.display()),
                ];
                (Code::VendorRulesetUnsupported, parts)
            }
            "a CR-only file" => {
                ws.put(".bazelignore", "node_modules\rdist\r");
                let parts = vec![
                    "lone carriage return".to_string(),
                    format!("Add {line} to {outer}"),
                ];
                (Code::WorkspaceIgnoreLineNeeded, parts)
            }
            _ => {
                // A wheel vendored earlier, which the user made a package
                // of and named in a target: the line would delete it.
                let unit = format!(".socket/vendor/pypi/{OTHER_UUID}");
                ws.put(&format!("{unit}/x-1.0-py3-none-any.whl"), "");
                ws.put(
                    &format!("{unit}/BUILD.bazel"),
                    "exports_files(glob([\"*.whl\"]))\n",
                );
                let label = format!("//{unit}:x-1.0-py3-none-any.whl");
                ws.put(
                    "BUILD.bazel",
                    format!("filegroup(name = \"w\", srcs = [\"{label}\"])\n"),
                );
                let hit = ws.root.join("BUILD.bazel").display().to_string();
                let parts = vec![
                    format!("{hit}:1 names a label under `//.socket/vendor`"),
                    format!("Add {line} to {outer}, then rewrite each label under it"),
                ];
                (Code::WorkspaceIgnoreLineNeeded, parts)
            }
        };
        let before = snapshot(&ws.root);

        for args in [
            &["vendor", "--dry-run", "--json"][..],
            &["vendor", "--json"],
        ] {
            let (exit, stdout, stderr) = ws.vendor(&project, args);
            assert_eq!(exit, 1, "{case}:\n{stdout}\n{stderr}");
            let envelope = parse_json_envelope(&stdout);
            assert!(
                has_event(&envelope, "failed", code.as_str(), PURL),
                "{case}: {envelope:#}"
            );
            let text = event_for(&envelope, PURL)["error"]
                .as_str()
                .expect("the refusal");
            let named = format!("{UUID} was not created");
            for part in parts.iter().map(String::as_str).chain([named.as_str()]) {
                assert!(text.contains(part), "{case}: {part}: {text}");
            }
            assert!(text.ends_with("nothing was written"), "{case}: {text}");
            assert_same_tree(&before, &snapshot(&ws.root));
        }
    }
}

/// A recorded line that a rollback cannot take out is a warning of that
/// rollback: the user's file keeps an edit the run reports as undone.
#[test]
fn a_rollback_over_a_modified_index_says_that_the_line_stays() {
    let ws = Workspace::new();
    let project = ws.project("svc/api");
    ws.applied(&project);
    // The index as another tool re-serialised it: the same rows, and not
    // the bytes socket-patch writes.
    let index = String::from_utf8(ws.bytes(".socket/bazel/index.json")).unwrap();
    ws.put(".socket/bazel/index.json", index.replace("\n  ", "\n    "));
    let wired = snapshot(&ws.root);

    let args = [
        "rollback",
        "--yes",
        "--offline",
        "--json",
        "--preserve-state",
    ];
    let (code, envelope) = ws.json(&project, &args);
    assert_eq!(code, 0, "{envelope:#}");
    let detail = warning(&envelope, Code::WorkspaceIgnoreLineNeeded);
    let file = ws.root.join(".bazelignore");
    for part in [
        format!(
            "added the line `svc/api/.socket/go-patches` to {}",
            file.display()
        ),
        "could not take all of it back".to_string(),
        "is not the index socket-patch wrote".to_string(),
        "restore the index from version control and remove the line by hand".to_string(),
    ] {
        assert!(detail.contains(&part), "{part}: {detail}");
    }
    assert!(!project.join(".socket/go-patches").exists());
    let after = snapshot(&ws.root);
    for kept in [".bazelignore", ".socket/bazel/index.json"] {
        assert_eq!(after.get(kept), wired.get(kept), "{kept}");
    }
}

/// A line with a leading `/` is the user's: reported, never edited.
#[test]
fn a_line_with_a_leading_slash_is_reported_with_the_line_that_was_added() {
    let ws = Workspace::new();
    ws.put(".bazelignore", "/svc/api/.socket\n");
    let project = ws.project("svc/api");
    let envelope = ws.applied(&project);
    assert_eq!(
        ws.bytes(".bazelignore"),
        b"/svc/api/.socket\nsvc/api/.socket/go-patches\n"
    );
    warning(&envelope, Code::WorkspaceIgnoreLineAdded);
    let detail = warning(&envelope, Code::WorkspaceIgnoreLineNeeded);
    for part in [
        "line 1 (`/svc/api/.socket`)",
        "Bazel 8.8.2 and later reject the whole file",
        "left it as found",
    ] {
        assert!(detail.contains(part), "{part}: {detail}");
    }
}

/// The vendored revert reports the same, under the vendored code for an
/// index that is not the one socket-patch wrote.
#[test]
fn a_revert_over_a_modified_index_says_that_the_line_stays() {
    let ws = Workspace::new();
    let project = ws.project("svc");
    let (code, stdout, stderr) = ws.vendor(&project, &["vendor", "--json"]);
    assert_eq!(code, 0, "vendor failed:\n{stdout}\n{stderr}");
    let index = String::from_utf8(ws.bytes(".socket/bazel/index.json")).unwrap();
    ws.put(".socket/bazel/index.json", index.replace("\n  ", "\n    "));
    let wired = snapshot(&ws.root);

    let (code, stdout, stderr) = ws.vendor(&project, &["vendor", "--revert", "--json"]);
    assert_eq!(code, 0, "revert failed:\n{stdout}\n{stderr}");
    let envelope = parse_json_envelope(&stdout);
    // `vendor` reports a package's advisories as events of that package.
    let modified = Code::VendorOwnedFileModified.as_str();
    assert!(
        has_event(&envelope, "skipped", modified, PURL),
        "{envelope:#}"
    );
    assert!(!project.join(".socket/vendor").exists(), "{envelope:#}");
    let after = snapshot(&ws.root);
    for kept in [".bazelignore", ".socket/bazel/index.json"] {
        assert_eq!(after.get(kept), wired.get(kept), "{kept}");
    }
}

/// A run that is interrupted while it holds the lock of the Bazel root
/// takes that lock file out as it dies, as it does the project's: the
/// root's lock is the bare one of `patch::apply_lock`, which is in the
/// interrupt table. The binary is parked by a debug-only failpoint with
/// the root's lock held, then signalled.
#[cfg(unix)]
mod interrupted_under_the_root_lock {
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Child, Stdio};
    use std::time::{Duration, Instant};

    use super::*;

    /// A parked `apply`. It sleeps for good, so a test that fails before
    /// it signals the run must not leave it behind.
    struct Parked(Option<Child>);

    impl Drop for Parked {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    impl Parked {
        /// `apply` in `project`, parked at `failpoint`.
        fn at(ws: &Workspace, project: &Path, failpoint: &str) -> Self {
            // Beside the workspace: the marker is in no snapshot of it.
            let ready = ws.cache.with_file_name("failpoint-ready");
            let mut command = crate::common::hermetic_command(&crate::common::binary());
            crate::common::jvm_env::isolate_cli(&mut command);
            command
                .args(["apply", "--offline", "--json", "--ecosystems", "golang"])
                .current_dir(project)
                .env("GOMODCACHE", &ws.cache)
                .env("GOFLAGS", "")
                .env("GOWORK", "off")
                .env("SOCKET_PATCH_FAILPOINT", format!("{failpoint}~pause"))
                .env("SOCKET_PATCH_FAILPOINT_READY", &ready)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let mut parked = Self(Some(command.spawn().expect("spawn socket-patch apply")));
            let deadline = Instant::now() + Duration::from_secs(60);
            while !ready.exists() {
                let child = parked.0.as_mut().expect("the child");
                if let Some(status) = child.try_wait().unwrap() {
                    parked.0 = None;
                    panic!("apply exited ({status}) before it reached `{failpoint}`");
                }
                assert!(
                    Instant::now() < deadline,
                    "apply never reached `{failpoint}`"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            parked
        }

        /// Sends `signal`. The run must still die by it: the handler
        /// cleans up and hands the signal back to its default.
        fn interrupt(mut self, signal: libc::c_int) {
            let mut child = self.0.take().expect("the child");
            // SAFETY: plain kill(2) on the pid of a child nobody waited for.
            let rc = unsafe { libc::kill(child.id() as libc::pid_t, signal) };
            assert_eq!(rc, 0, "kill({signal}) failed");
            let status = child.wait().unwrap();
            assert_eq!(status.signal(), Some(signal), "got {status}");
        }
    }

    /// Every `apply.lock` under the workspace.
    fn lock_files(ws: &Workspace) -> Vec<String> {
        let is_lock = |path: &String| path.rsplit('/').next() == Some("apply.lock");
        snapshot(&ws.root).into_keys().filter(is_lock).collect()
    }

    /// Interrupted before the edit: nothing of the run is left, the
    /// directories the root's lock made included, and the next run and
    /// its rollback behave as if the first had never started.
    #[test]
    fn an_interrupt_before_the_edit_leaves_the_tree_as_it_was() {
        for (rel, signal) in [("", libc::SIGINT), ("svc/api", libc::SIGTERM)] {
            let ws = Workspace::new();
            let project = ws.project(rel);
            let before = snapshot(&ws.root);

            let parked = Parked::at(&ws, &project, "apply_lock.acquired_bare");
            let mut held = vec![
                ".socket/bazel/apply.lock".to_string(),
                join(rel, ".socket/apply.lock"),
            ];
            held.sort();
            assert_eq!(lock_files(&ws), held, "the root's lock and the project's");
            parked.interrupt(signal);

            assert_eq!(lock_files(&ws), Vec::<String>::new(), "{rel:?}");
            assert_same_tree(&before, &snapshot(&ws.root));

            let envelope = ws.applied(&project);
            warning(&envelope, Code::WorkspaceIgnoreLineAdded);
            ws.roll_back(&project);
            assert_same_tree(&before, &snapshot(&ws.root));
        }
    }

    /// Interrupted after the edit, while the lock is being let go: the
    /// lock file goes, and what stays is the line for a copy that was not
    /// made, which hides nothing, with its row. The next run finds the
    /// line and makes the copy, and its rollback takes the line out by
    /// that row.
    #[test]
    fn an_interrupt_after_the_edit_leaves_the_line_and_its_row_and_no_lock() {
        let ws = Workspace::new();
        ws.put(".bazelignore", "node_modules\r\n");
        let project = ws.project("svc/api");
        let before = snapshot(&ws.root);
        let wired = "node_modules\r\nsvc/api/.socket/go-patches\r\n";

        let parked = Parked::at(&ws, &project, "apply_lock.releasing_bare");
        assert_eq!(ws.bytes(".bazelignore"), wired.as_bytes());
        assert!(lock_files(&ws).contains(&".socket/bazel/apply.lock".to_string()));
        parked.interrupt(libc::SIGHUP);

        assert_eq!(lock_files(&ws), Vec::<String>::new());
        assert_eq!(ws.bytes(".bazelignore"), wired.as_bytes());
        let index: Value = serde_json::from_slice(&ws.bytes(".socket/bazel/index.json")).unwrap();
        assert_eq!(
            index["ignoreLines"][0]["line"], "svc/api/.socket/go-patches",
            "{index:#}"
        );
        assert!(!project.join(".socket/go-patches").exists());

        let envelope = ws.applied(&project);
        assert!(warning_codes(&envelope).is_empty(), "{envelope:#}");
        ws.roll_back(&project);
        assert_same_tree(&before, &snapshot(&ws.root));
    }
}
