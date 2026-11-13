//! Real-Bazel tests: the output-tree classifier (design 2.11) and the
//! guards that stand on it (design 3, HZ-02 and HZ-03) against trees a
//! real Bazel wrote, on the toy core fixture.
//!
//! The hermetic twin (`e2e_bazel::guard_tree`) fabricates these trees
//! from what the probes recorded. Here Bazel makes them: an output base
//! after a build and after `clean` and a build, the convenience links
//! under `--symlink_prefix=dist/`, the repository cache and the repo
//! contents cache, and a vendor directory. Each test then asks the
//! classifier and the binary about paths in them, and the binary must
//! leave every tree as it found it.

use std::path::{Path, PathBuf};

use socket_patch_core::bazel::codes::Code;
use socket_patch_core::bazel::output_tree::{Located, PathClass, Route, Tree, Verdict};
use socket_patch_core::crawlers::bazel_output::{
    classify, locate_output_base, vendor_dirs_at, Candidates,
};

use crate::bazel_build_common::env::System;
use crate::bazel_build_common::probe_report;
use crate::bazel_build_common::server::Cell;
use crate::bazel_build_common::toy::{self, DEP};
use crate::bazel_common::{assert_same_tree, snapshot};
use crate::common::{
    envelope_error_code, envelope_error_message, git_sha256, parse_json_envelope, run_with_env,
    write_blob, write_minimal_manifest, PatchEntry,
};

const UPSTREAM: &[u8] = b"module.exports = 'upstream';\n";

/// The output base of the cell's server, as Bazel names it.
fn output_base(cell: &Cell) -> PathBuf {
    PathBuf::from(cell.info("output_base"))
}

/// The spoke repository of the toy package under `<base>/external`, by
/// the end of its name (`_main~toy~toy_dep`, `+toy+toy_dep`).
fn spoke(base: &Path) -> PathBuf {
    let external = base.join("external");
    let entries = std::fs::read_dir(&external).expect("read external/");
    let mut spokes: Vec<PathBuf> = entries
        .map(|entry| entry.expect("an entry").path())
        .filter(|path| path.to_string_lossy().ends_with("toy_dep"))
        .collect();
    assert_eq!(
        spokes.len(),
        1,
        "one spoke of @toy in {external:?}: {spokes:?}"
    );
    spokes.remove(0)
}

fn is_link(path: &Path) -> bool {
    let meta = std::fs::symlink_metadata(path);
    meta.is_ok_and(|meta| meta.file_type().is_symlink())
}

/// The class of `path` and of the tree that decided it.
fn judged(path: &Path) -> (PathClass, Option<PathClass>) {
    let verdict = classify(path);
    assert!(!verdict.cannot_tell, "{}: {verdict:?}", path.display());
    (verdict.class, verdict.tree.map(|tree| tree.class))
}

/// `path` is in the output base rooted at `base`, however it is spelled.
fn assert_in_base(path: &Path, base: &Path) -> Verdict {
    let verdict = classify(path);
    let root = verdict.tree.as_ref().map(|tree| tree.root.canonicalize());
    let class = verdict.tree.as_ref().map(|tree| tree.class);
    assert_eq!(class, Some(PathClass::OutputBase), "{}", path.display());
    let canonical = base.canonicalize().expect("the base exists");
    assert_eq!(
        root.and_then(Result::ok),
        Some(canonical),
        "{}",
        path.display()
    );
    verdict
}

/// `socket-patch scan --json` aimed at `scope` is refused with the code
/// of HZ-02, naming `place`, before it asks anything of the API (which
/// is a closed port here).
fn assert_scan_refused(cwd: &Path, scope: &Path, place: &str) {
    let scope_arg = scope.to_string_lossy();
    let api = [
        "--api-url",
        "http://127.0.0.1:9",
        "--api-token",
        "fake",
        "--org",
        "o",
    ];
    for mode in ["agent", "hosted"] {
        let scan = ["scan", "--json", "--mode", mode, "--cwd", &*scope_arg];
        let (code, stdout, stderr) = run_with_env(cwd, &[&scan[..], &api[..]].concat(), &[]);
        assert_eq!(code, 1, "{scope_arg}\nstdout:\n{stdout}\nstderr:\n{stderr}");
        let envelope = parse_json_envelope(&stdout);
        let refusal = Code::AgentOutputTree.as_str();
        assert_eq!(envelope_error_code(&envelope), Some(refusal), "{stdout}");
        let message = envelope_error_message(&envelope).expect("a message");
        assert!(message.contains(place), "{scope_arg}: {message}");
        assert!(message.ends_with("nothing was written"), "{message}");
    }
}

/// What a legacy `npm_install` hook meets: a repository under the real
/// base's `external/` with an installed package, where `apply` exits 0
/// with and without a manifest and patches nothing.
fn assert_apply_in_external_is_a_no_op(base: &Path) {
    let repo = base.join("external/socket_guard_npm");
    let installed = repo.join("node_modules/left-pad/index.js");
    std::fs::create_dir_all(installed.parent().unwrap()).unwrap();
    let pkg = r#"{ "name": "left-pad", "version": "1.3.0" }"#;
    std::fs::write(installed.with_file_name("package.json"), pkg).unwrap();
    std::fs::write(&installed, UPSTREAM).unwrap();

    let (code, stdout, stderr) = run_with_env(&repo, &["apply"], &[]);
    assert_eq!(code, 0, "no manifest\nstdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("No patch manifest found"), "{stdout}");

    let patched = b"module.exports = 'patched';\n";
    let after = git_sha256(patched);
    let entry = PatchEntry {
        file_name: "package/index.js",
        before_hash: &git_sha256(UPSTREAM),
        after_hash: &after,
    };
    let socket = repo.join(".socket");
    let uuid = "9c1f4a52-7d3e-4b8a-a6f0-2e5d8c7b1a90";
    write_minimal_manifest(&socket, "pkg:npm/left-pad@1.3.0", uuid, &[entry]);
    write_blob(&socket, &after, patched);
    let before = snapshot(&repo);
    let (code, stdout, stderr) = run_with_env(&repo, &["apply", "--offline", "--json"], &[]);
    assert_eq!(code, 0, "a manifest\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let envelope = parse_json_envelope(&stdout);
    let warning = Code::WorkspaceInsideOutputTree.as_str();
    assert_eq!(envelope["warnings"][0]["code"], warning, "{stdout}");
    assert_eq!(std::fs::read(&installed).unwrap(), UPSTREAM);
    assert_same_tree(&before, &snapshot(&repo));
    std::fs::remove_dir_all(&repo).unwrap();
}

/// An output base is known by the one marker that outlives `bazel clean`:
/// after a build both markers are there, and after `clean` and a build on
/// the same server the one in `execroot` is gone for as long as the
/// server lives (probe C7), while the convenience links are live. The
/// links name the workspace's own base, whose marker holds the canonical
/// workspace path byte for byte.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn bazel_core_classifier_output_base_after_build_and_clean() {
    const TEST: &str = "bazel_core_classifier_output_base_after_build_and_clean";
    let Some(mut toy) = toy::open(TEST, System::Bzlmod, false) else {
        return;
    };
    let cell = &toy.cell;
    let ws = cell.scratch.workspace.clone();
    cell.baseline(&["//..."], false);
    let base = output_base(cell);
    let ws_link = format!("bazel-{}", ws.file_name().unwrap().to_string_lossy());
    let mut second_marker = Vec::new();
    for after_clean in [false, true] {
        if after_clean {
            // Only a server that lived through both commands shows the
            // state. One that idled out between them (15 s; a launcher
            // that queues each command can take longer) is replaced by a
            // server that writes the marker again, so the pair is run
            // again on that one.
            let mut lived = false;
            for _ in 0..3 {
                // Asked first, so that an idle server which went away is
                // replaced before the two commands, not between them.
                assert_eq!(output_base(cell), base);
                let server = cell.server_pid();
                cell.bazel_ok("clean", &[]);
                cell.bazel_ok("build", &["//..."]);
                if cell.server_pid() == server {
                    lived = true;
                    break;
                }
            }
            assert!(lived, "the server restarted between clean and build");
        }
        assert!(base.join("DO_NOT_BUILD_HERE").is_file(), "{after_clean}");
        second_marker.push(base.join("execroot/DO_NOT_BUILD_HERE").is_file());

        for link in ["bazel-bin", "bazel-out", "bazel-testlogs", &ws_link] {
            let link = ws.join(link);
            assert!(is_link(&link), "{}", link.display());
            let class = (PathClass::Link, Some(PathClass::OutputBase));
            assert_eq!(judged(&link), class, "{}", link.display());
        }
        assert_in_base(&ws.join("bazel-bin/not/yet/there.js"), &base);
        assert_in_base(&ws.join(&ws_link).join("external"), &base);
        let repo = spoke(&base);
        assert!(
            !is_link(&repo),
            "{}: the contents cache is off",
            repo.display()
        );
        assert_eq!(assert_in_base(&repo, &base).resolves_into, None);
        assert_in_base(&base, &base);
        for plain in [ws.clone(), ws.join("toy.lock.json"), ws.join("new/file")] {
            assert_eq!(
                judged(&plain),
                (PathClass::Plain, None),
                "{}",
                plain.display()
            );
        }
        let located = locate_output_base(&ws, &Candidates::default());
        let own = Located::Base {
            base: base.canonicalize().unwrap(),
            route: Route::Link,
        };
        assert_eq!(located, own, "after clean: {after_clean}");
        assert_eq!(vendor_dirs_at(&ws).dirs, Vec::<PathBuf>::new());

        // The binary, through the link and at the real path.
        let before = snapshot(&ws);
        assert_scan_refused(
            &ws,
            Path::new("bazel-bin"),
            "a link into a Bazel output tree",
        );
        assert_scan_refused(&ws, &repo, "in a Bazel output base");
        assert_apply_in_external_is_a_no_op(&base);
        assert_same_tree(&before, &snapshot(&ws));
    }
    // A new server writes both markers; `clean` deletes the second and no
    // build on that server writes it again.
    assert_eq!(second_marker, [true, false], "execroot/DO_NOT_BUILD_HERE");
    toy.cell
        .report
        .detail("execroot_marker_after_clean_and_build", false);
    toy.finish();
}

/// `--symlink_prefix=dist/` moves the links to `dist/bin`, `dist/out`
/// and their two siblings, so no name tells them from the user's
/// directories: the classifier knows them by where they lead, and the
/// base is located from them once the directory is named.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn bazel_core_classifier_symlink_prefix() {
    const TEST: &str = "bazel_core_classifier_symlink_prefix";
    let Some(toy) = toy::open(TEST, System::Bzlmod, false) else {
        return;
    };
    let cell = &toy.cell;
    let ws = cell.scratch.workspace.clone();
    cell.bazel_ok("build", &["--symlink_prefix=dist/", "//:socket_probe"]);
    let base = output_base(cell);
    let ws_name = ws.file_name().unwrap().to_string_lossy().into_owned();
    for link in ["bin", "out", "testlogs", &ws_name] {
        let link = ws.join("dist").join(link);
        assert!(is_link(&link), "{}", link.display());
        let class = (PathClass::Link, Some(PathClass::OutputBase));
        assert_eq!(judged(&link), class, "{}", link.display());
    }
    assert!(
        !ws.join("bazel-bin").exists(),
        "a link under the default prefix"
    );
    assert_in_base(&ws.join("dist/bin/any/output.js"), &base);
    assert_eq!(judged(&ws.join("dist")), (PathClass::Plain, None));

    // The links are looked for in the workspace root unless the caller
    // names the directory the prefix put them in.
    assert_eq!(
        locate_output_base(&ws, &Candidates::default()),
        Located::NotFound
    );
    let candidates = Candidates {
        link_dirs: vec![ws.join("dist")],
        ..Candidates::default()
    };
    let own = Located::Base {
        base: base.canonicalize().unwrap(),
        route: Route::Link,
    };
    assert_eq!(locate_output_base(&ws, &candidates), own);

    let before = snapshot(&ws);
    assert_scan_refused(
        &ws,
        Path::new("dist/bin"),
        "a link into a Bazel output tree",
    );
    assert_scan_refused(
        &ws.join("dist/bin"),
        Path::new("."),
        "in a Bazel output base",
    );
    assert_same_tree(&before, &snapshot(&ws));
    toy.finish();
}

/// Where the fetched repository of a package is stored. From Bazel 9 by
/// default, and from 8.3 with `--repo_contents_cache=<dir>`, a
/// reproducible repository is an entry of the repo contents cache that
/// `external/<repo>` links to and every workspace on the machine shares;
/// before that it is a directory of the output base. Either way the
/// download itself is an entry of the repository cache.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn bazel_core_classifier_contents_cache() {
    const TEST: &str = "bazel_core_classifier_contents_cache";
    // A cold cell: the caches are this test's own.
    let Some(mut toy) = toy::open(TEST, System::Bzlmod, true) else {
        return;
    };
    let version = toy.cell.bazel.version.clone();
    // 9.x: the line's default. 8.3 and later: a private directory outside
    // the workspace copy. Earlier lines have no such cache.
    let private = toy.cell.scratch.root.join("contents");
    let flag = format!("--repo_contents_cache={}", private.display());
    let mut build = vec!["//..."];
    if version.at_least(9, 0, 0) {
        toy.cell.options.contents_cache = true;
    } else if version.at_least(8, 3, 0) {
        toy.cell.options.contents_cache = true;
        build.insert(0, flag.as_str());
    }
    let cached = toy.cell.options.contents_cache;
    let cell = &toy.cell;
    let ws = cell.scratch.workspace.clone();
    cell.bazel_ok("build", &build);
    let base = output_base(cell);
    let repo = spoke(&base);
    let verdict = assert_in_base(&repo, &base);
    assert_eq!(is_link(&repo), cached, "{}", repo.display());

    let before = snapshot(&ws);
    if cached {
        // `external/<repo>` is spelled in the base and stored in the cache.
        let entry = repo.canonicalize().expect("the link resolves");
        let stored = Some(PathClass::RepoContentsCache);
        assert_eq!(verdict.resolves_into.map(|tree| tree.class), stored);
        let own = Tree {
            class: PathClass::RepoContentsCache,
            root: entry.clone(),
        };
        assert_eq!(classify(&entry.join("file/dep.sh")).tree, Some(own));
        assert!(!entry.starts_with(&base) && !entry.starts_with(&ws));
        if !version.at_least(9, 0, 0) {
            let private = private.canonicalize().expect("the private cache");
            assert!(entry.starts_with(&private), "{}", entry.display());
        }
        assert_scan_refused(&ws, &entry, "in Bazel's repository contents cache");
    } else {
        // A real directory, and nothing beside the base stores it.
        assert_eq!(verdict.resolves_into, None, "{}", repo.display());
        assert!(!private.exists(), "{}", private.display());
    }
    assert_scan_refused(&ws, &repo, "in a Bazel output base");

    // The download, in the repository cache every cell passes.
    let sha256 = toy::sha256_hex(&DEP.upstream());
    let cas = cell
        .scratch
        .repository_cache
        .join("content_addressable/sha256");
    let download = cas.join(sha256);
    assert!(download.join("file").is_file(), "{}", download.display());
    let class = (PathClass::RepositoryCache, Some(PathClass::RepositoryCache));
    assert_eq!(judged(&download.join("file")), class);
    assert_scan_refused(&ws, &download, "in Bazel's repository cache");
    assert_same_tree(&before, &snapshot(&ws));

    toy.cell.report.detail("external_repo_is_a_link", cached);
    toy.finish();
}

/// `bazel vendor` writes fetched repositories into a directory of the
/// workspace that is meant to be committed. It is known by the marker
/// Bazel puts there, nothing in it is a project, and `external/<repo>`
/// then leads out of the output base into it.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn bazel_core_classifier_vendor_dir() {
    const TEST: &str = "bazel_core_classifier_vendor_dir";
    let Some(toy) = toy::open(TEST, System::Bzlmod, false) else {
        return;
    };
    let cell = &toy.cell;
    if !cell.bazel.version.at_least(9, 0, 0) {
        // `bazel vendor` exists from 7.1, writes only `.vendorignore`
        // until 7.3 and is clean from 7.4.1 (probe C11). The claim is the
        // line where the directory is committed alongside a contents cache.
        probe_report::skip_na(&cell.report, "the vendor-directory cell runs on Bazel 9");
        return;
    }
    let ws = cell.scratch.workspace.clone();
    cell.baseline(&["//..."], false);
    let base = output_base(cell);
    let name = spoke(&base)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let spoke_arg = format!("--repo=@@{name}");
    let repos = ["--vendor_dir=vendor_src", "--repo=@toy", spoke_arg.as_str()];
    cell.bazel_ok("vendor", &repos);
    cell.bazel_ok("build", &["--vendor_dir=vendor_src", "//..."]);

    let vendored = ws.join("vendor_src");
    assert!(vendored.join("VENDOR.bazel").is_file(), "no marker");
    let found = vendor_dirs_at(&ws);
    assert_eq!(
        (found.dirs, found.cannot_tell),
        (vec![vendored.clone()], false)
    );
    let class = (PathClass::VendorDir, Some(PathClass::VendorDir));
    for path in [vendored.clone(), vendored.join(&name).join("file/dep.sh")] {
        assert_eq!(judged(&path), class, "{}", path.display());
    }
    // The build reads the vendored copy through the output base.
    let repo = spoke(&base);
    assert!(is_link(&repo), "{}", repo.display());
    let stored = assert_in_base(&repo, &base).resolves_into;
    assert_eq!(stored.map(|tree| tree.class), Some(PathClass::VendorDir));

    let before = snapshot(&ws);
    let scope = Path::new("vendor_src").join(&name);
    assert_scan_refused(&ws, &scope, "in a Bazel vendor directory");
    assert_same_tree(&before, &snapshot(&ws));
    toy.finish();
}
