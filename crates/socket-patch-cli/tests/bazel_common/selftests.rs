//! Self-tests of the snapshot and write-policy helpers. The oracle guards
//! every Bazel test, so a hole in it would hide a harmful write in all of
//! them at once.

use std::path::Path;

use super::snapshot::{
    assert_same_tree, assert_same_tree_but_bazel_owned, changes, snapshot, without_bazel_owned,
    Change, Entry, Snapshot, PLACEHOLDER_MODULE_BAZEL,
};
use super::write_policy::{
    assert_restore_policy, assert_restore_policy_with, assert_write_policy,
    assert_write_policy_with, classify, classify_restore, Layout, WriteClass,
};

const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

fn file(text: &str) -> Entry {
    Entry::file(text)
}

fn link(target: &str) -> Entry {
    Entry::Link(target.to_string())
}

fn tree(files: &[(&str, &str)]) -> Snapshot {
    files
        .iter()
        .map(|(path, text)| (path.to_string(), file(text)))
        .collect()
}

/// The verdict on `path` going from `old` to `new` (`None` = absent), in a
/// tree whose root is the Bazel root.
fn verdict(path: &str, old: Option<&str>, new: Option<&str>) -> Result<WriteClass, String> {
    let (old, new) = (old.map(file), new.map(file));
    classify(path, old.as_ref(), new.as_ref(), &Layout::default())
}

/// [`verdict`] for a run that restores.
fn restored(path: &str, old: Option<&str>, new: Option<&str>) -> Result<WriteClass, String> {
    let (old, new) = (old.map(file), new.map(file));
    classify_restore(path, old.as_ref(), new.as_ref(), &Layout::default())
}

/// The verdict on a change between entries of any kind.
fn kinds(path: &str, old: Option<&Entry>, new: Option<&Entry>) -> Result<WriteClass, String> {
    classify(path, old, new, &Layout::default())
}

/// A tag with one `gem_checksums` entry, as rules_ruby reads it.
fn bundle_fetch(key: &str, digest: &str) -> String {
    format!("ruby.bundle_fetch(\n    gem_checksums = {{\"{key}\": \"{digest}\"}},\n)\n")
}

/// Writes a file with the mode `Entry::file` records, whatever the umask.
fn write_plain(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(Entry::PLAIN)).unwrap();
    }
}

#[test]
fn snapshot_records_files_and_directories_and_skips_git() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("svc/empty")).unwrap();
    std::fs::create_dir_all(tmp.path().join(".git/objects")).unwrap();
    write_plain(&tmp.path().join("svc/go.mod"), b"module m\r\n");
    std::fs::write(tmp.path().join(".git/index"), b"x").unwrap();
    let expected: Snapshot = [
        ("svc".to_string(), Entry::Dir),
        ("svc/empty".to_string(), Entry::Dir),
        ("svc/go.mod".to_string(), file("module m\r\n")),
    ]
    .into();
    assert_eq!(snapshot(tmp.path()), expected);
}

/// A convenience link points into the output base. Following it would
/// walk gigabytes that are not the workspace, and a dangling one (after
/// `bazel clean --expunge`) must not fail the walk.
#[cfg(unix)]
#[test]
fn snapshot_records_a_link_by_target_and_never_follows_it() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("big"), b"not the workspace").unwrap();
    std::os::unix::fs::symlink(outside.path(), tmp.path().join("bazel-bin")).unwrap();
    std::os::unix::fs::symlink("/nonexistent/execroot", tmp.path().join("bazel-out")).unwrap();
    let target = outside.path().to_string_lossy().into_owned();
    let expected: Snapshot = [
        ("bazel-bin".to_string(), Entry::Link(target)),
        ("bazel-out".to_string(), link("/nonexistent/execroot")),
    ]
    .into();
    assert_eq!(snapshot(tmp.path()), expected);
}

/// A write by stage and rename can reset a file's mode and leave its
/// bytes alone. The snapshot has to see that, or neither a rollback check
/// nor the oracle would.
#[test]
fn snapshot_records_the_mode_so_a_chmod_alone_is_a_modification() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("pnpm-lock.yaml");
    std::fs::write(&path, b"lockfileVersion: '9.0'\n").unwrap();
    // 0755 and then 0600 on Unix; writable and then read-only elsewhere.
    let chmod = |tight: bool| {
        #[cfg(unix)]
        let perms = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::Permissions::from_mode(if tight { 0o600 } else { 0o755 })
        };
        #[cfg(not(unix))]
        let perms = {
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_readonly(tight);
            perms
        };
        std::fs::set_permissions(&path, perms).unwrap();
    };
    chmod(false);
    let before = snapshot(tmp.path());
    chmod(true);
    let after = snapshot(tmp.path());
    // Windows cannot delete a read-only file when the directory is dropped.
    chmod(false);

    #[cfg(unix)]
    {
        let bytes = b"lockfileVersion: '9.0'\n".to_vec();
        let expected = Entry::File { bytes, mode: 0o755 };
        assert_eq!(before.get("pnpm-lock.yaml"), Some(&expected));
    }
    let modified = [("pnpm-lock.yaml".to_string(), Change::Modified)];
    assert_eq!(changes(&before, &after), modified);
    let path = "pnpm-lock.yaml";
    let why = kinds(path, before.get(path), after.get(path)).unwrap_err();
    assert!(why.contains("mode changed"), "{why}");
}

#[test]
#[should_panic(expected = "not byte-identical")]
fn a_mode_change_alone_is_not_the_same_tree() {
    let before = tree(&[("tools/run.sh", "#!/bin/sh\n")]);
    let (bytes, mode) = (b"#!/bin/sh\n".to_vec(), Entry::PLAIN ^ 1);
    let after: Snapshot = [("tools/run.sh".to_string(), Entry::File { bytes, mode })].into();
    assert_same_tree(&before, &after);
}

#[test]
fn outside_dot_socket_a_file_keeps_its_mode() {
    let moded = |text: &str| Entry::File {
        bytes: text.as_bytes().to_vec(),
        mode: Entry::PLAIN ^ 1,
    };
    for (path, old, new) in [
        ("go.mod", "old", "old"),
        ("go.mod", "old", "new"),
        (".bazelignore", "a\n", "a\nsvc/.socket/vendor\n"),
    ] {
        let why = kinds(path, Some(&file(old)), Some(&moded(new))).unwrap_err();
        assert!(why.contains("mode changed"), "{path}: {why}");
    }
    // Inside `.socket` socket-patch sets the modes: a patch can add or
    // drop an executable bit.
    let path = ".socket/vendor/npm/u/pkg/bin/tool.js";
    let class = kinds(path, Some(&file("old")), Some(&moded("old")));
    assert_eq!(class, Ok(WriteClass::SocketState));
}

#[test]
fn changes_lists_created_removed_and_modified_paths_in_path_order() {
    let before = tree(&[("a", "1"), ("b", "2"), ("d", "4")]);
    let after = tree(&[("a", "1"), ("b", "two"), ("c", "3")]);
    assert_eq!(
        changes(&before, &after),
        [
            ("b".to_string(), Change::Modified),
            ("c".to_string(), Change::Created),
            ("d".to_string(), Change::Removed),
        ]
    );
    assert_same_tree(&before, &before.clone());
}

#[test]
#[should_panic(expected = "not byte-identical")]
fn a_leftover_empty_directory_is_not_the_same_tree() {
    let before = tree(&[("go.mod", "m")]);
    let mut after = before.clone();
    after.insert(".socket".to_string(), Entry::Dir);
    assert_same_tree(&before, &after);
}

/// What Bazel writes into a workspace it builds, under the default link
/// names and under `--symlink_prefix=dist/`.
fn bazel_owned() -> Snapshot {
    let base = "/private/var/tmp/_bazel_u/0123abcd/execroot/_main";
    [
        ("MODULE.bazel.lock".to_string(), file("{}\n")),
        (
            "legacy/MODULE.bazel".to_string(),
            file(PLACEHOLDER_MODULE_BAZEL),
        ),
        ("legacy/MODULE.bazel.lock".to_string(), file("{}\n")),
        (
            "bazel-bin".to_string(),
            link(&format!("{base}/bazel-out/k8-fastbuild/bin")),
        ),
        ("bazel-ws".to_string(), link(base)),
        ("dist".to_string(), Entry::Dir),
        ("dist/out".to_string(), link(&format!("{base}/bazel-out"))),
        (
            "win-testlogs".to_string(),
            link(r"C:\b\x\execroot\_main\bazel-out\testlogs"),
        ),
    ]
    .into()
}

#[test]
fn the_bazel_owned_set_is_left_out_of_a_later_comparison() {
    let user: Snapshot = [
        ("MODULE.bazel".to_string(), file("module(name = \"m\")\n")),
        ("legacy".to_string(), Entry::Dir),
        ("legacy/WORKSPACE".to_string(), file("")),
        ("tools".to_string(), Entry::Dir),
        ("tools/current".to_string(), link("../third_party/v2")),
    ]
    .into();
    let mut built = user.clone();
    built.extend(bazel_owned());
    assert_eq!(without_bazel_owned(&built), user);
    assert_same_tree_but_bazel_owned(&user, &built);
    // A directory that holds a convenience link and a file of the user's
    // stays, with that file.
    built.insert("dist/notes.txt".to_string(), file("mine"));
    let kept = without_bazel_owned(&built);
    assert!(kept.contains_key("dist") && kept.contains_key("dist/notes.txt"));
    assert!(!kept.contains_key("dist/out"));
}

#[test]
#[should_panic(expected = "not byte-identical: [(\"MODULE.bazel\", Modified)]")]
fn a_module_file_the_user_wrote_is_not_bazel_owned() {
    let before = tree(&[("MODULE.bazel", "module(name = \"m\")\n")]);
    let mut after = tree(&[("MODULE.bazel", "module(name = \"n\")\n")]);
    after.extend(bazel_owned());
    assert_same_tree_but_bazel_owned(&before, &after);
}

/// The placeholder is matched by its bytes, so the constant must be the
/// file Bazel writes: 399 bytes with the digest the probes recorded.
#[test]
fn the_placeholder_module_file_is_the_one_bazel_writes() {
    use sha2::{Digest, Sha256};
    assert_eq!(PLACEHOLDER_MODULE_BAZEL.len(), 399);
    assert_eq!(
        hex::encode(Sha256::digest(PLACEHOLDER_MODULE_BAZEL)),
        "0e3e315145ac7ee7a4e0ac825e1c5e03c068ec1254dd42c3caaecb27e921dc4d"
    );
}

/// One run that makes a write of every class, the hash file, a created
/// `pnpm-workspace.yaml` and a label-addressed requirements file included.
#[test]
fn the_writes_of_the_design_are_each_in_their_class() {
    let hash_file = ".aspect/rules/external_repository_action_cache/npm_translate_lock_LTE4Nzc=";
    let (a, b) = ("0".repeat(64), "f".repeat(64));
    let paths = [
        "pnpm-lock.yaml",
        "svc/go.mod",
        "rust/.cargo/config.toml",
        "NuGet.Config",
        "third_party/reqs/lock_linux.txt",
        "maven_install.json",
        "deps/paket.main.bzl",
        hash_file,
    ];
    let mut before: Snapshot = paths.iter().map(|p| (p.to_string(), file("old"))).collect();
    let mut after: Snapshot = paths.iter().map(|p| (p.to_string(), file("new"))).collect();
    before.insert(
        "MODULE.bazel".to_string(),
        file(&bundle_fetch("rack-3.0.0", &a)),
    );
    after.insert(
        "MODULE.bazel".to_string(),
        file(&bundle_fetch("rack-3.0.0", &b)),
    );
    after.insert(".bazelignore".to_string(), file("svc/.socket/go-patches\n"));
    after.insert(
        "pnpm-workspace.yaml".to_string(),
        file("packages:\n  - '.'\ntrustLockfile: true\n"),
    );
    let upstream_build = format!("svc/.socket/vendor/golang/{UUID}/m@v1.0.0/BUILD.bazel");
    after.insert(upstream_build.clone(), file("go_library()"));
    after.insert(".socket/bazel".to_string(), Entry::Dir);
    after.insert(".socket/bazel/index.json".to_string(), file("{}\n"));

    let layout = Layout {
        hub_locks: &["third_party/reqs/lock_linux.txt"],
        ..Layout::default()
    };
    let writes = assert_write_policy_with(&before, &after, &layout);
    let class = |path: &str| {
        writes
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, class)| *class)
    };
    assert_eq!(writes.len(), 14);
    for path in paths[..5].iter().chain(&["pnpm-workspace.yaml"]) {
        assert_eq!(class(path), Some(WriteClass::NativeLock), "{path}");
    }
    for path in [
        "maven_install.json",
        "deps/paket.main.bzl",
        hash_file,
        "MODULE.bazel",
    ] {
        assert_eq!(class(path), Some(WriteClass::GeneratedValue), "{path}");
    }
    assert_eq!(class(".bazelignore"), Some(WriteClass::IgnoreLine));
    assert_eq!(class(".socket/bazel"), Some(WriteClass::OwnedFile));
    assert_eq!(
        class(".socket/bazel/index.json"),
        Some(WriteClass::OwnedFile)
    );
    assert_eq!(class(&upstream_build), Some(WriteClass::SocketState));

    // The rollback of that run is the inverse of each write. The forward
    // rules refuse it: they do not delete `pnpm-workspace.yaml`.
    let undone = assert_restore_policy_with(&after, &before, &layout);
    assert_eq!(undone.len(), 14);
    let forward = std::panic::catch_unwind(|| assert_write_policy_with(&after, &before, &layout));
    let refused = *forward.unwrap_err().downcast::<String>().unwrap();
    assert_eq!(
        refused,
        "socket-patch wrote outside the allowed classes:\n  \
         pnpm-workspace.yaml: outside `.socket` only an existing file may change"
    );
}

#[test]
fn files_bazel_or_the_user_own_are_never_written() {
    for path in [
        "MODULE.bazel.lock",
        "rust/cargo-bazel-lock.json",
        ".bazelrc",
        "tools/ci.bazelrc",
        ".bazelversion",
        "BUILD.bazel",
        "pkg/BUILD",
        "REPO.bazel",
        "defs.bzl",
        "deps/paket.bzl",
        "deps/paket.main_extension.bzl",
        "requirements.in",
        "third_party/reqs/lock_linux.txt",
        ".npmrc",
        "package-lock.json",
        "web/yarn.lock",
        "src/main.rs",
    ] {
        assert!(
            verdict(path, Some("old"), Some("new")).is_err(),
            "{path} was allowed"
        );
    }
}

#[test]
fn outside_dot_socket_only_the_two_side_files_are_created_and_nothing_else_goes() {
    for path in [".npmrc", "go.sum", "maven_install.json", "MODULE.bazel"] {
        assert!(
            verdict(path, None, Some("new")).is_err(),
            "{path} was created"
        );
        assert!(
            verdict(path, Some("old"), None).is_err(),
            "{path} was removed"
        );
    }
    // Native hosted mode creates the pnpm side file beside the lock, and
    // so does a rules_js lane (owner decision O14). A forward run never
    // deletes it.
    for path in ["pnpm-workspace.yaml", "web/pnpm-workspace.yaml"] {
        let created = verdict(path, None, Some("packages:\n  - '.'\n"));
        assert_eq!(created, Ok(WriteClass::NativeLock), "{path}");
        assert!(verdict(path, Some("old"), None).is_err(), "{path}");
    }
    assert!(kinds("bazel-bin", Some(&link("a")), Some(&link("b"))).is_err());
    assert!(kinds("go.mod", Some(&file("m")), Some(&link("x"))).is_err());
    assert!(kinds("third_party", None, Some(&Entry::Dir)).is_err());
    assert!(kinds(".bazelignore", None, Some(&link("x"))).is_err());
    assert!(kinds("pnpm-workspace.yaml", None, Some(&Entry::Dir)).is_err());
}

#[test]
fn dot_socket_admits_todays_state_and_only_the_index_under_bazel() {
    let ok = |path: &str| verdict(path, None, Some("new"));
    assert_eq!(ok(".socket/manifest.json"), Ok(WriteClass::SocketState));
    assert_eq!(
        ok("svc/.socket/go-patches/m@v1.0.0/WORKSPACE"),
        Ok(WriteClass::SocketState)
    );
    assert_eq!(
        ok("svc/.socket/bazel/index.json"),
        Ok(WriteClass::OwnedFile)
    );
    for path in [
        ".socket/bazel/BUILD.bazel",
        ".socket/bazel/index.json.bak",
        ".socket/bazel-manifests/maven.json",
        "svc/.socket-auto-manifest/pom.xml",
        ".socket/vendor/.socket-auto-manifest/pom.xml",
    ] {
        assert!(ok(path).is_err(), "{path} was allowed");
    }
}

/// `.socket`, `.socket/bazel` and the index keep their kind: a link in
/// place of one would move the owned index out of the tree, and the
/// snapshot does not look below a link.
#[test]
fn dot_socket_and_the_owned_index_keep_their_kind() {
    let (dir, a_file, a_link) = (Entry::Dir, file("{}\n"), link("/elsewhere"));
    assert_eq!(
        kinds("svc/.socket", None, Some(&dir)),
        Ok(WriteClass::SocketState)
    );
    assert_eq!(
        kinds(".socket/bazel", Some(&dir), None),
        Ok(WriteClass::OwnedFile)
    );
    for (path, old, new) in [
        (".socket", Some(&dir), Some(&a_link)),
        (".socket", Some(&a_link), Some(&dir)),
        ("svc/.socket", None, Some(&a_link)),
        (".socket", None, Some(&a_file)),
        (".socket/bazel", None, Some(&a_file)),
        (".socket/bazel", None, Some(&a_link)),
        (".socket/bazel/index.json", None, Some(&a_link)),
        (".socket/bazel/index.json", None, Some(&dir)),
        (".socket/bazel/index.json", Some(&a_file), Some(&a_link)),
    ] {
        assert!(kinds(path, old, new).is_err(), "{path}: {old:?} -> {new:?}");
    }
    // A vendored package may hold links of its own.
    let bin = ".socket/vendor/npm/u/pkg/node_modules/.bin/tool";
    assert_eq!(kinds(bin, None, Some(&a_link)), Ok(WriteClass::SocketState));
}

/// Hazard HZ-27: Bazel globs a leftover stage file into its actions.
#[test]
fn no_stage_or_saved_original_file_is_left_anywhere() {
    let stage = "svc/.socket/go-patches/m@v1.0.0/.socket-stage-go.mod-9f6b2c4e";
    for path in [
        stage,
        ".socket/vendor/golang/u/m@v1/.socket-orig-a.go",
        ".socket/.socket-stage-blobs-1",
        ".socket/.socket-stage-blobs-1/ab/cdef",
        "svc/.socket-stage-go.mod-9f6b2c4e",
    ] {
        assert!(
            verdict(path, None, Some("x")).is_err(),
            "{path} was created"
        );
        assert!(
            verdict(path, Some("x"), Some("y")).is_err(),
            "{path} was kept"
        );
        assert!(
            restored(path, None, Some("x")).is_err(),
            "{path} after a restore"
        );
    }
    assert!(kinds(".socket/.socket-stage-blobs-1", None, Some(&Entry::Dir)).is_err());
    // Sweeping one away is the fix, in either kind of run.
    assert_eq!(verdict(stage, Some("x"), None), Ok(WriteClass::SocketState));
    assert_eq!(
        restored(stage, Some("x"), None),
        Ok(WriteClass::SocketState)
    );
}

#[test]
fn bazelignore_only_grows_by_lines_that_hide_a_socket_tree() {
    let grow = |old: Option<&str>, new: &str| verdict(".bazelignore", old, Some(new));
    for (old, new) in [
        (None, "svc/.socket/go-patches\n"),
        (Some(""), ".socket/vendor\n"),
        (
            Some("third_party\n"),
            "third_party\n.socket/vendor\nsvc/.socket/vendor\n",
        ),
        (Some("a\r\n"), "a\r\nsvc/.socket/vendor\r\n"),
        // A missing final newline is added first, in the file's own form.
        (Some("a"), "a\nsvc/.socket/vendor\n"),
        (Some("a\r\nb"), "a\r\nb\r\nsvc/.socket/vendor\r\n"),
        // A file that mixes line endings takes either.
        (Some("a\r\nb\n"), "a\r\nb\nsvc/.socket/vendor\n"),
        (Some("a\r\nb\n"), "a\r\nb\nsvc/.socket/vendor\r\n"),
        // A BOM hides the first line only, and that line is not touched.
        (
            Some("\u{feff}third_party\n"),
            "\u{feff}third_party\nsvc/.socket/vendor\n",
        ),
        (Some("a\n"), "a\nmy services/api/.socket/vendor\n"),
    ] {
        assert_eq!(
            grow(old, new),
            Ok(WriteClass::IgnoreLine),
            "{old:?} -> {new:?}"
        );
    }
    for (old, new) in [
        (Some("a\nb\n"), "a\n"),
        (Some("a\n"), "b\nsvc/.socket/vendor\n"),
        (Some("a"), "asvc/.socket/vendor\n"),
        (Some("a"), "a\n"),
        (None, ""),
        // A bare `.socket` would also hide the index and the manifest.
        (None, ".socket\n"),
        (None, "/svc/.socket/vendor\n"),
        (None, "./svc/.socket/vendor\n"),
        (None, "../x/.socket/vendor\n"),
        (None, "svc//.socket/vendor\n"),
        (None, "svc/../.socket/vendor\n"),
        (None, "svc/.socket/vendor/\n"),
        (None, "*/.socket/vendor\n"),
        (None, "svc/.socket/vendor \n"),
        (None, " svc/.socket/vendor\n"),
        (None, "svc\t/.socket/vendor\n"),
        (None, "svc\\.socket\\vendor\n"),
        (None, "node_modules\n"),
        (None, "svc/.socket/vendor-old\n"),
        // A comment hides nothing, and neither does the first line of a
        // file that starts with a BOM.
        (None, "#x/.socket/vendor\n"),
        (None, "\u{feff}svc/.socket/vendor\n"),
        (Some("a\n"), "a\n\nsvc/.socket/vendor\n"),
        // Bazel splits on a lone CR: this would hide `src`.
        (Some("a\n"), "a\nsrc\rsvc/.socket/vendor\n"),
        // The file's own line ending, on every added line.
        (Some("a\r\n"), "a\r\nsvc/.socket/vendor\n"),
        (Some("a\n"), "a\nsvc/.socket/vendor\r\n"),
        (Some("a"), "a\r\nsvc/.socket/vendor\r\n"),
        (None, "svc/.socket/vendor\r\n"),
        (Some("a\n"), "a\nsvc/.socket/vendor"),
        (Some("a\n"), "a\nsvc/.socket/vendor\nx/.socket/vendor"),
        // A CR-only file has no line ending the writer could keep.
        (Some("a\rb"), "a\rb\nsvc/.socket/vendor\n"),
        (Some("a\rb\r"), "a\rb\rsvc/.socket/vendor\r"),
        (Some("a\rb\n"), "a\rb\nsvc/.socket/vendor\n"),
    ] {
        assert!(grow(old, new).is_err(), "{old:?} -> {new:?} was allowed");
    }
}

/// Design 7: a takeover moves the line, a line goes when the last tree it
/// covered is gone, and a file socket-patch created and emptied is
/// deleted. No line of the user's is touched on the way.
#[test]
fn a_socket_tree_line_may_move_or_go_and_no_other_line_may() {
    let change = |old: &str, new: Option<&str>| verdict(".bazelignore", Some(old), new);
    for (old, new) in [
        ("svc/.socket/go-patches\n", Some("svc/.socket/vendor\n")),
        (
            "a\nsvc/.socket/go-patches\nb\r\n",
            Some("a\nb\r\nsvc/.socket/vendor\n"),
        ),
        ("a\nsvc/.socket/vendor\n", Some("a\n")),
        (
            "x/.socket/go-patches\nsvc/.socket/vendor",
            Some("svc/.socket/vendor"),
        ),
        // The user's file stays, even empty; one that held nothing but
        // socket-tree lines may go.
        ("svc/.socket/vendor\n", Some("")),
        ("svc/.socket/vendor\n", None),
        ("svc/.socket/vendor\r\n.socket/go-patches\r\n", None),
    ] {
        assert_eq!(
            change(old, new),
            Ok(WriteClass::IgnoreLine),
            "{old:?} -> {new:?}"
        );
    }
    for (old, new) in [
        // A line of the user's removed, re-ended, reordered or rewritten.
        ("a\nsvc/.socket/go-patches\n", Some("svc/.socket/vendor\n")),
        ("a\nb\nsvc/.socket/vendor\n", Some("a\n")),
        (
            "a\r\nsvc/.socket/go-patches\n",
            Some("a\nsvc/.socket/vendor\n"),
        ),
        ("a\nb\nsvc/.socket/vendor\n", Some("b\na\n")),
        ("# keep\nsvc/.socket/vendor\n", Some("# kept\n")),
        // The final newline goes only in a restore.
        ("a\nsvc/.socket/vendor\n", Some("a")),
        // Socket-tree lines reordered: nothing was added or removed.
        (
            "a/.socket/vendor\nb/.socket/vendor\n",
            Some("b/.socket/vendor\na/.socket/vendor\n"),
        ),
        // Deleted with a line of the user's in it, or with no line at all.
        ("a\nsvc/.socket/vendor\n", None),
        ("# ours\nsvc/.socket/vendor\n", None),
        ("./svc/.socket/vendor\n", None),
        ("", None),
    ] {
        assert!(change(old, new).is_err(), "{old:?} -> {new:?} was allowed");
    }
}

/// Bazel reads `.bazelignore` at its root and nowhere else. Every other
/// write seam is relative to the project, so a line written beside the
/// project is the bug to expect, and it would hide nothing.
#[test]
fn bazelignore_is_written_at_a_bazel_root_only() {
    let line = file("svc/.socket/go-patches\n");
    let grown = file("a\n.socket/vendor\n");
    let at = |roots: &'static [&'static str], path: &str, old: Option<&Entry>, new: &Entry| {
        let layout = Layout {
            bazel_roots: roots,
            ..Layout::default()
        };
        classify(path, old, Some(new), &layout)
    };
    for path in ["svc/.bazelignore", "svc/deep/pkg/.bazelignore"] {
        assert!(at(&[""], path, None, &line).is_err(), "{path} was created");
        let old = file("a\n");
        assert!(
            at(&[""], path, Some(&old), &grown).is_err(),
            "{path} was appended to"
        );
    }
    let old = file("a\n");
    for (roots, path) in [
        (&["svc"][..], "svc/.bazelignore"),
        (&["", "svc/deep/pkg"][..], "svc/deep/pkg/.bazelignore"),
        (&["", "svc/deep/pkg"][..], ".bazelignore"),
    ] {
        assert_eq!(
            at(roots, path, None, &line),
            Ok(WriteClass::IgnoreLine),
            "{path}"
        );
        assert_eq!(
            at(roots, path, Some(&old), &grown),
            Ok(WriteClass::IgnoreLine),
            "{path}"
        );
    }
    // Declaring `svc` the root makes the snapshot root an ordinary
    // directory above it.
    assert!(at(&["svc"], ".bazelignore", None, &line).is_err());
    assert!(at(&["svc"], "svc/api/.bazelignore", None, &line).is_err());
}

#[test]
fn a_module_or_workspace_file_admits_one_gem_checksum_replacement_only() {
    let (a, b) = ("0".repeat(64), "f".repeat(64));
    let old = bundle_fetch("rack-3.0.0", &a);
    for path in [
        "MODULE.bazel",
        "deps/ruby.MODULE.bazel",
        "WORKSPACE",
        "WORKSPACE.bzlmod",
    ] {
        let new = bundle_fetch("rack-3.0.0", &b);
        assert_eq!(
            verdict(path, Some(&old), Some(&new)),
            Ok(WriteClass::GeneratedValue)
        );
    }
    // Other entries before and after the value, a comment line between
    // them and a WORKSPACE rule do not confuse the scan.
    let two = |x: &str, y: &str| {
        format!(
            "rb_bundle_fetch(\n    name = \"bundle\",\n    gem_checksums = {{\n        \
             \"a-1\": \"{x}\",\n        # pinned by hand\n        \"b-2\" : \"{y}\",\n    }},\n)\n"
        )
    };
    for new in [two(&b, &a), two(&a, &b)] {
        let class = verdict("WORKSPACE", Some(&two(&a, &a)), Some(&new));
        assert_eq!(class, Ok(WriteClass::GeneratedValue));
    }
    for (old, new) in [
        // A statement, a key, an identifier or a second digest: all are
        // edits to what the user wrote.
        (
            old.clone(),
            format!(
                "{}bazel_dep(name = \"x\")\n",
                bundle_fetch("rack-3.0.0", &b)
            ),
        ),
        (old.clone(), bundle_fetch("rack-3.0.1", &a)),
        (old.clone(), old.replace("gem_checksums", "gem_checksumz")),
        (two(&a, &a), two(&b, &b)),
        // Not a digest before, or not one after.
        (
            bundle_fetch("rack-3.0.0", &"z".repeat(64)),
            bundle_fetch("rack-3.0.0", &b),
        ),
        (old.clone(), bundle_fetch("rack-3.0.0", &"F".repeat(64))),
        (old.clone(), bundle_fetch("rack-3.0.0", &"f".repeat(63))),
    ] {
        assert!(
            verdict("MODULE.bazel", Some(&old), Some(&new)).is_err(),
            "{old:?} -> {new:?} was allowed"
        );
    }
}

/// A digest is replaced only as a `gem_checksums` value. Any other
/// 64-hex string in these files pins something the user declared.
#[test]
fn a_digest_outside_gem_checksums_is_never_replaced() {
    let (a, b) = ("0".repeat(64), "f".repeat(64));
    for shape in [
        "http_archive(name = \"x\", sha256 = \"<d>\")\n",
        "archive_override(\n    module_name = \"x\",\n    sha256 = \"<d>\",\n)\n",
        // A commented-out entry, and a comment after a live one.
        "ruby.bundle_fetch(\n    gem_checksums = {\n        # \"rack-3.0.0\": \"<d>\",\n    },\n)\n",
        "ruby.bundle_fetch(gem_checksums = {\"a-1\": \"x\"})  # \"a-1\": \"<d>\"\n",
        // A dict of another attribute, in the same call.
        "ruby.bundle_fetch(\n    gem_checksums = {},\n    env = {\"KEY\": \"<d>\"},\n)\n",
        "ruby.bundle_fetch(my_gem_checksums = {\"rack-3.0.0\": \"<d>\"})\n",
        // A dict nested in the value, a key, the value of a computed key,
        // a list item, and a variable the tag only refers to.
        "ruby.bundle_fetch(gem_checksums = {\"a-1\": {\"sha\": \"<d>\"}})\n",
        "ruby.bundle_fetch(gem_checksums = {\"<d>\": \"rack\"})\n",
        "ruby.bundle_fetch(gem_checksums = {RACK: \"<d>\"})\n",
        "ruby.bundle_fetch(gem_checksums = [\"<d>\"])\n",
        "gem_checksums = {\"rack-3.0.0\": \"<d>\"}\n",
    ] {
        let (old, new) = (shape.replace("<d>", &a), shape.replace("<d>", &b));
        for path in ["MODULE.bazel", "WORKSPACE"] {
            assert!(
                verdict(path, Some(&old), Some(&new)).is_err(),
                "{path}: {old:?} was allowed"
            );
        }
    }
}

#[test]
fn a_declared_hub_lock_cannot_unlock_a_never_written_file() {
    let (old, new) = (file("old"), file("new"));
    let with = |path: &str, old: Option<&Entry>| {
        let hub_locks = [path];
        let layout = Layout {
            hub_locks: &hub_locks,
            ..Layout::default()
        };
        classify(path, old, Some(&new), &layout)
    };
    assert_eq!(
        with("third_party/reqs/lock_linux.txt", Some(&old)),
        Ok(WriteClass::NativeLock)
    );
    for path in [
        "requirements.in",
        "BUILD.bazel",
        "MODULE.bazel.lock",
        ".bazelrc",
        "defs.bzl",
        // A created `.npmrc` fails rules_js 3.x, and no hub of the default
        // set reads an npm or yarn lock.
        ".npmrc",
        "package-lock.json",
        "yarn.lock",
    ] {
        assert!(with(path, Some(&old)).is_err(), "{path} was unlocked");
    }
    // Declaring it does not let it be created either.
    assert!(with("reqs/lock.txt", None).is_err());
}

/// A restore is judged as the inverse of a write: it may delete what a
/// write may create, and it may not create anything outside `.socket`.
#[test]
fn a_restore_is_the_inverse_of_an_allowed_write() {
    let scaffold = "packages:\n  - '.'\ntrustLockfile: true\n";
    for (path, old, new) in [
        ("pnpm-workspace.yaml", Some(scaffold), None),
        ("pnpm-lock.yaml", Some("pinned"), Some("upstream")),
        (".bazelignore", Some("svc/.socket/vendor\n"), None),
        (".bazelignore", Some("a\nsvc/.socket/vendor\n"), Some("a\n")),
        // The final newline the write added goes with the line.
        (".bazelignore", Some("a\nsvc/.socket/vendor\n"), Some("a")),
        (".socket/bazel/index.json", Some("{}\n"), None),
        ("svc/.socket/vendor/golang/u/m@v1/go.mod", Some("m"), None),
    ] {
        assert!(
            restored(path, old, new).is_ok(),
            "{path}: {old:?} -> {new:?}"
        );
    }
    for (path, old, new) in [
        ("pnpm-workspace.yaml", None, Some(scaffold)),
        (".bazelignore", Some("a\nb\n"), Some("a\n")),
        (".bazelignore", Some("a\n"), None),
        ("go.sum", Some("h1:x"), None),
        ("MODULE.bazel.lock", Some("{}"), Some("{ }")),
        (".npmrc", Some("x"), None),
    ] {
        assert!(
            restored(path, old, new).is_err(),
            "{path}: {old:?} -> {new:?}"
        );
    }
    let (before, after) = (
        tree(&[("go.mod", "pinned")]),
        tree(&[("go.mod", "upstream")]),
    );
    let writes = assert_restore_policy(&before, &after);
    assert_eq!(writes, [("go.mod".to_string(), WriteClass::NativeLock)]);
}

#[test]
#[should_panic(expected = "MODULE.bazel.lock: `MODULE.bazel.lock` is never written")]
fn assert_write_policy_names_the_offending_path() {
    let before = tree(&[("MODULE.bazel.lock", "{}"), ("go.mod", "a")]);
    let after = tree(&[("MODULE.bazel.lock", "{ }"), ("go.mod", "b")]);
    assert_write_policy(&before, &after);
}
