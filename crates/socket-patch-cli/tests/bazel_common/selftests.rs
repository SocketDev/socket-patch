//! Self-tests of the snapshot and write-policy helpers. The oracle guards
//! every Bazel test, so a hole in it would hide a harmful write in all of
//! them at once.

use super::snapshot::{assert_same_tree, changes, snapshot, Change, Entry, Snapshot};
use super::write_policy::{assert_write_policy, assert_write_policy_with, classify, WriteClass};

const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

fn file(text: &str) -> Entry {
    Entry::File(text.as_bytes().to_vec())
}

fn tree(files: &[(&str, &str)]) -> Snapshot {
    files
        .iter()
        .map(|(path, text)| (path.to_string(), file(text)))
        .collect()
}

/// The verdict on `path` going from `old` to `new` (`None` = absent).
fn verdict(path: &str, old: Option<&str>, new: Option<&str>) -> Result<WriteClass, String> {
    classify(path, old.map(file).as_ref(), new.map(file).as_ref(), &[])
}

/// A tag with one `gem_checksums` entry, as rules_ruby reads it.
fn bundle_fetch(key: &str, digest: &str) -> String {
    format!("ruby.bundle_fetch(\n    gem_checksums = {{\"{key}\": \"{digest}\"}},\n)\n")
}

#[test]
fn snapshot_records_files_and_directories_and_skips_git() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("svc/empty")).unwrap();
    std::fs::create_dir_all(tmp.path().join(".git/objects")).unwrap();
    std::fs::write(tmp.path().join("svc/go.mod"), b"module m\r\n").unwrap();
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
        (
            "bazel-out".to_string(),
            Entry::Link("/nonexistent/execroot".to_string()),
        ),
    ]
    .into();
    assert_eq!(snapshot(tmp.path()), expected);
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

/// One run that makes a write of every class, the hash file and a
/// label-addressed requirements file included.
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
    let upstream_build = format!("svc/.socket/vendor/golang/{UUID}/m@v1.0.0/BUILD.bazel");
    after.insert(upstream_build.clone(), file("go_library()"));
    after.insert(".socket/bazel".to_string(), Entry::Dir);
    after.insert(".socket/bazel/index.json".to_string(), file("{}\n"));

    let mut writes =
        assert_write_policy_with(&before, &after, &["third_party/reqs/lock_linux.txt"]);
    writes.sort_by(|x, y| x.0.cmp(&y.0));
    let class = |path: &str| {
        writes
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, class)| *class)
    };
    assert_eq!(writes.len(), 13);
    for path in &paths[..5] {
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
        "src/main.rs",
    ] {
        assert!(
            verdict(path, Some("old"), Some("new")).is_err(),
            "{path} was allowed"
        );
    }
}

#[test]
fn outside_dot_socket_nothing_is_created_or_removed_except_bazelignore() {
    for path in [
        "pnpm-workspace.yaml",
        ".npmrc",
        "go.sum",
        "maven_install.json",
        "MODULE.bazel",
    ] {
        assert!(
            verdict(path, None, Some("new")).is_err(),
            "{path} was created"
        );
        assert!(
            verdict(path, Some("old"), None).is_err(),
            "{path} was removed"
        );
    }
    assert!(verdict(".bazelignore", Some("svc/.socket/vendor\n"), None).is_err());
    let link = |target: &str| Entry::Link(target.to_string());
    assert!(classify("bazel-bin", Some(&link("a")), Some(&link("b")), &[]).is_err());
    assert!(classify("go.mod", Some(&file("m")), Some(&link("x")), &[]).is_err());
    assert!(classify("third_party", None, Some(&Entry::Dir), &[]).is_err());
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

#[test]
fn bazelignore_only_grows_by_lines_that_hide_a_socket_tree() {
    let grow = |old: Option<&str>, new: &str| verdict(".bazelignore", old, Some(new));
    for (old, new) in [
        (None, "svc/.socket/go-patches\n"),
        (
            Some("third_party\n"),
            "third_party\n.socket/vendor\nsvc/.socket/vendor\n",
        ),
        (Some("a\r\n"), "a\r\nsvc/.socket/vendor\r\n"),
        // A missing final newline is added first.
        (Some("a"), "a\nsvc/.socket/vendor\n"),
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
        // A bare `.socket` would also hide the index and the manifest.
        (None, ".socket\n"),
        (None, "/svc/.socket/vendor\n"),
        (None, "./svc/.socket/vendor\n"),
        (None, "*/.socket/vendor\n"),
        (None, "svc/.socket/vendor \n"),
        (None, "svc\\.socket\\vendor\n"),
        (None, "node_modules\n"),
        (None, "svc/.socket/vendor-old\n"),
    ] {
        assert!(grow(old, new).is_err(), "{old:?} -> {new:?} was allowed");
    }
}

#[test]
fn a_module_or_workspace_file_admits_one_digest_replacement_only() {
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
    // Other literals before and after the value do not confuse the scan.
    let two = |x: &str, y: &str| format!("d = {{\"a-1\": \"{x}\", \"b-2\": \"{y}\"}}\n");
    for new in [two(&b, &a), two(&a, &b)] {
        let class = verdict("MODULE.bazel", Some(&two(&a, &a)), Some(&new));
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

#[test]
fn a_declared_hub_lock_cannot_unlock_a_never_written_file() {
    let (old, new) = (file("old"), file("new"));
    let with = |path: &str| classify(path, Some(&old), Some(&new), &[path]);
    assert_eq!(
        with("third_party/reqs/lock_linux.txt"),
        Ok(WriteClass::NativeLock)
    );
    for path in [
        "requirements.in",
        "BUILD.bazel",
        "MODULE.bazel.lock",
        ".bazelrc",
        "defs.bzl",
    ] {
        assert!(with(path).is_err(), "{path} was unlocked");
    }
    // Declaring it does not let it be created either.
    assert!(classify("reqs/lock.txt", None, Some(&new), &["reqs/lock.txt"]).is_err());
}

#[test]
#[should_panic(expected = "MODULE.bazel.lock: `MODULE.bazel.lock` is never written")]
fn assert_write_policy_names_the_offending_path() {
    let before = tree(&[("MODULE.bazel.lock", "{}"), ("go.mod", "a")]);
    let after = tree(&[("MODULE.bazel.lock", "{ }"), ("go.mod", "b")]);
    assert_write_policy(&before, &after);
}
