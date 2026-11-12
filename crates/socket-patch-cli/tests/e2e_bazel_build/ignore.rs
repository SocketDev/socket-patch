//! Real-Bazel tests: `.bazelignore` lines hide a `.socket` tree from `//...`
//! (hazard HZ-04).
//!
//! `apply` in agent mode copies a Go module, upstream BUILD file included,
//! under `.socket/go-patches`. These tests take Bazel's own verdict: `build
//! //...` passes after the run, on a warm and on a restarted server, and
//! after the rollback; and it is the line that does it, because the same
//! tree without the line fails. The hermetic twin is `e2e_bazel::ignore`.

use crate::bazel_build_common::env::System;
use crate::bazel_build_common::toy;
use crate::bazel_common::{
    assert_same_tree_but_bazel_owned, assert_write_policy, snapshot, WriteClass,
};
use crate::common::{git_sha256, run_with_env, write_blob, write_minimal_manifest, PatchEntry};

const MODULE: &str = "example.com/m";
const VERSION: &str = "v1.0.0";
const PURL: &str = "pkg:golang/example.com/m@v1.0.0";
const UUID: &str = "0b5e1c1e-5f0a-4c8e-9a51-6d1f3c2b7a90";
const PRISTINE: &[u8] = b"package m\n\nfunc V() string { return \"upstream\" }\n";
const PATCHED: &[u8] = b"package m\n\nfunc V() string { return \"patched\" }\n";
/// What an upstream module ships: a BUILD file for a ruleset the user's
/// workspace does not have.
const UPSTREAM_BUILD: &str = "load(\"@io_bazel_rules_go//go:def.bzl\", \"go_library\")\n";
const COPY: &str = ".socket/go-patches/example.com/m@v1.0.0";

/// The scenario for a Go project at `rel` of the toy workspace (`""` = its
/// root): baseline, `apply`, do no harm, the control, `rollback`.
fn agent_go_tree_stays_out_of_the_build(test: &str, rel: &str) {
    let Some(toy) = toy::open(test, System::Bzlmod, false) else {
        return;
    };
    let cell = &toy.cell;
    let workspace = &cell.scratch.workspace;
    let below = |name: &str| match rel {
        "" => name.to_string(),
        rel => format!("{rel}/{name}"),
    };

    // The module in a cache outside the workspace, and a Go project that
    // requires it, with the patch in its manifest. `.git` makes the
    // workspace the repository, as it is in a checkout.
    let cache = cell.scratch.root.join("modcache");
    let module = cache.join(format!("{MODULE}@{VERSION}"));
    std::fs::create_dir_all(&module).unwrap();
    std::fs::write(module.join("m.go"), PRISTINE).unwrap();
    std::fs::write(module.join("go.mod"), format!("module {MODULE}\n")).unwrap();
    std::fs::write(module.join("BUILD.bazel"), UPSTREAM_BUILD).unwrap();
    cell.write(".git/HEAD", "ref: refs/heads/main\n");
    let go_mod = format!("module example.com/app\n\ngo 1.21\n\nrequire {MODULE} {VERSION}\n");
    cell.write(&below("go.mod"), go_mod);
    let project = workspace.join(rel);
    let files = [PatchEntry {
        file_name: "m.go",
        before_hash: &git_sha256(PRISTINE),
        after_hash: &git_sha256(PATCHED),
    }];
    write_minimal_manifest(&project.join(".socket"), PURL, UUID, &files);
    write_blob(&project.join(".socket"), &git_sha256(PATCHED), PATCHED);
    let socket_patch = |args: &[&str]| {
        let env = [
            ("GOMODCACHE", cache.to_str().unwrap()),
            ("GOFLAGS", ""),
            ("GOWORK", "off"),
        ];
        let (code, stdout, stderr) = run_with_env(&project, args, &env);
        assert_eq!(code, 0, "{test}: {args:?} failed:\n{stdout}\n{stderr}");
    };

    // 1. Baseline.
    cell.baseline(&["//..."], false);
    let before = snapshot(workspace);

    // 2. The run. Its writes are judged before any Bazel command: the
    //    line, the index, `.socket` state and `go.mod`, and no stage file.
    socket_patch(&["apply", "--offline", "--json", "--ecosystems", "golang"]);
    let applied = snapshot(workspace);
    let writes = assert_write_policy(&before, &applied);
    let ignore_line = (".bazelignore".to_string(), WriteClass::IgnoreLine);
    assert!(writes.contains(&ignore_line), "{writes:?}");
    let line = below(".socket/go-patches");
    let ignore_file = std::fs::read(workspace.join(".bazelignore")).unwrap();
    assert_eq!(ignore_file, format!("{line}\n").as_bytes());
    let copied = std::fs::read_to_string(project.join(COPY).join("BUILD.bazel"));
    assert_eq!(
        copied.unwrap(),
        UPSTREAM_BUILD,
        "the copy has the upstream BUILD file"
    );

    // 3. Do no harm: `//...` builds on the warm server and on a restarted
    //    one, the tree is no package, and Bazel wrote only its own files.
    cell.bazel_ok("build", &["//..."]);
    let packages = cell.bazel_ok("query", &["//..."]).stdout();
    assert!(!packages.contains(".socket"), "{packages}");
    cell.shutdown();
    cell.bazel_ok("build", &["//..."]);
    assert_same_tree_but_bazel_owned(&applied, &snapshot(workspace));

    // 4. The control: the line is what keeps the build green. Without it
    //    the same tree fails `//...`, as it does for today's releases.
    std::fs::remove_file(workspace.join(".bazelignore")).unwrap();
    let broken = cell.bazel("build", &["//..."]);
    assert!(
        !broken.ok(),
        "{test}: //... built over the tree:\n{}",
        broken.dump()
    );
    assert!(broken.stderr().contains(&line), "{}", broken.dump());
    cell.write(".bazelignore", &ignore_file);
    cell.bazel_ok("build", &["//..."]);

    // 5. Rollback: the tree, the line and the index are gone, and the
    //    workspace is what it was, byte for byte, but for Bazel's own files.
    socket_patch(&[
        "rollback",
        "--yes",
        "--offline",
        "--json",
        "--preserve-state",
    ]);
    assert!(!project.join(".socket/go-patches").exists());
    assert!(!workspace.join(".bazelignore").exists());
    assert_same_tree_but_bazel_owned(&before, &snapshot(workspace));
    cell.bazel_ok("build", &["//..."]);
    cell.shutdown();
    cell.bazel_ok("build", &["//..."]);
    toy.finish();
}

#[test]
#[ignore = "real Bazel; run with --ignored"]
fn bazel_guard_ignore_agent_go_tree_at_the_root() {
    agent_go_tree_stays_out_of_the_build("bazel_guard_ignore_agent_go_tree_at_the_root", "");
}

/// The project sits below the Bazel root, so the line is written through
/// the root channel into a `.bazelignore` outside the project (probe B5:
/// only a line in the outer root's file fixes the outer `build //...`).
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn bazel_guard_ignore_agent_go_tree_below_the_root() {
    agent_go_tree_stays_out_of_the_build(
        "bazel_guard_ignore_agent_go_tree_below_the_root",
        "services/api",
    );
}
