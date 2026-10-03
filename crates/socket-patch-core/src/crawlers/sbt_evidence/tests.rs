//! Walk tests: the committed probe fixtures copied into a temp root, and
//! synthetic trees for depth, caps, staleness, FIFOs and symlinks.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use super::*;

const VERSIONS: &[&str] = &["0.13.18", "1.2.8", "1.3.13", "1.9.9", "1.13.0", "2.0.9"];

fn fixture(ver: &str, scenario: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sbt/evidence")
        .join(ver)
        .join(scenario)
}

/// A fixture copied to `<tmp>/<root_name>` (sbt 2's meta-build id is the
/// probe root's name).
fn staged(ver: &str, scenario: &str, root_name: &str) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join(root_name);
    stage_fixture(&fixture(ver, scenario), &root);
    (tmp, root)
}

fn write(root: &Path, rel: &str, body: &[u8]) -> PathBuf {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, body).unwrap();
    path
}

fn set_mtime(path: &Path, t: SystemTime) {
    fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(t)
        .unwrap();
}

const JSON: &str = r#"{"configurations":[{"configuration":{"name":"compile"},"modules":[{"module":{"organization":"g","name":"a","revision":"1"},"artifacts":[],"evicted":false}],"details":[]}]}"#;

fn rels(e: &SbtEvidence) -> Vec<&str> {
    e.files.iter().map(|(r, _)| r.as_str()).collect()
}

#[test]
fn every_fixture_version_is_discovered_and_resolved() {
    for ver in VERSIONS {
        let (_tmp, root) = staged(ver, "matrix", "x");
        let e = discover(&root).unwrap_or_else(|| panic!("{ver}"));
        assert!(!e.stale, "{ver}");
        assert_eq!(e.root_name, "x");
        assert!(
            e.build_sources.iter().any(|(r, _)| r == "build.sbt"),
            "{ver}"
        );
        let res = resolution(&e).unwrap_or_else(|| panic!("{ver}"));
        assert_eq!(
            res.projects_seen,
            [".", "a", "d", "e"].map(String::from).into(),
            "{ver}: {:?}",
            rels(&e)
        );
        assert!(res
            .in_scope
            .contains(&("com.google.code.gson".to_string(), "gson".to_string())));
        // Editing the build after the probe's `update` stales it.
        set_mtime(&root.join("build.sbt"), SystemTime::now());
        assert!(scan(&root).unwrap().stale, "{ver}");
    }
}

#[test]
fn sbt2_meta_build_follows_the_root_directory_name() {
    // Staged under the probe's root name, x-build is the meta-build...
    let (_tmp, root) = staged("2.0.9", "matrix", "x");
    let meta = resolution(&discover(&root).unwrap()).unwrap().meta_build;
    // ...and under another name the `-build` suffix still marks it.
    let (_tmp2, other) = staged("2.0.9", "matrix", "renamed");
    let res = resolution(&discover(&other).unwrap()).unwrap();
    assert_eq!(res.meta_build, meta);
    assert!(!meta.is_empty());
}

#[test]
fn depth_bounds_only_the_target_search() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(root, "project/build.properties", b"sbt.version=1.9.9\n");
    // sbt 2 at depth 8, 0.13-style streams at depth 9 in a nested module,
    // and a target at depth 6.
    let deep = [
        "target/out/jvm/scala-3.8.4/root/update/update_cache_3/output",
        "mods/a/target/streams/$global/update/$global/streams/update_cache_2.12/output",
        "a/b/c/d/e/target/update/update_cache/output",
    ];
    for rel in deep {
        write(root, rel, JSON.as_bytes());
    }
    // A target at depth 7, and evidence-shaped files off the patterns.
    write(
        root,
        "a/b/c/d/e/f/target/update/update_cache/output",
        JSON.as_bytes(),
    );
    write(
        root,
        "a/target/classes/update/update_cache/output",
        JSON.as_bytes(),
    );
    write(
        root,
        "a/target/scala-2.12/update/update_cache_2.12/output.bak",
        b"x",
    );
    let e = scan(root).unwrap();
    let mut want = deep.to_vec();
    want.sort();
    assert_eq!(rels(&e), want);
}

#[test]
fn skipped_directories_and_mill_out() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(root, "build.sbt", b"");
    for dir in SKIP_DIRS {
        write(
            root,
            &format!("{dir}/target/update/update_cache/output"),
            JSON.as_bytes(),
        );
        write(root, &format!("{dir}/build.sbt"), b"");
    }
    write(
        root,
        "out/target/update/update_cache/output",
        JSON.as_bytes(),
    );
    // `out/` is skipped only at the top level.
    write(
        root,
        "m/out/target/update/update_cache/output",
        JSON.as_bytes(),
    );
    let e = scan(root).unwrap();
    assert_eq!(rels(&e), ["m/out/target/update/update_cache/output"]);
    assert_eq!(
        e.build_sources
            .iter()
            .map(|(r, _)| r.as_str())
            .collect::<Vec<_>>(),
        ["build.sbt"]
    );
}

#[test]
fn caps_drop_all_evidence() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(root, "target/update/update_cache/output", JSON.as_bytes());
    assert!(discover(root).is_some());
    // One file over the per-file cap (sparse).
    let big = write(root, "a/target/update/update_cache/output", b"");
    fs::OpenOptions::new()
        .write(true)
        .open(&big)
        .unwrap()
        .set_len(MAX_FILE_BYTES + 1)
        .unwrap();
    let err = scan(root).unwrap_err();
    assert!(err.contains("cap"), "{err}");
    assert_eq!(discover(root), None);
    fs::remove_file(&big).unwrap();
    // Too many files.
    for i in 0..MAX_FILES {
        write(
            root,
            &format!("target/resolution-cache/reports/r{i}.xml"),
            b"<ivy-report/>",
        );
    }
    assert!(scan(root).unwrap_err().contains("cap"));
    assert_eq!(discover(root), None);
}

#[test]
fn staleness_compares_sources_with_the_newest_output_or_inputs() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let t0 = SystemTime::now() - Duration::from_secs(3600);
    let at = |s: u64| t0 + Duration::from_secs(s);
    let build = write(root, "build.sbt", b"lazy val a = project\n");
    let props = write(root, "project/build.properties", b"sbt.version=1.9.9\n");
    let sub = write(root, "a/build.sbt", b"");
    let opts = write(root, ".sbtopts", b"");
    let out = write(
        root,
        "a/target/scala-2.12/update/update_cache_2.12/output",
        JSON.as_bytes(),
    );
    let inputs = write(
        root,
        "a/target/scala-2.12/update/update_cache_2.12/inputs",
        b"1",
    );
    for p in [&build, &props, &sub, &opts] {
        set_mtime(p, at(10));
    }
    set_mtime(&out, at(20));
    set_mtime(&inputs, at(5));
    assert!(!scan(root).unwrap().stale);
    // A subproject source edited after the last update.
    set_mtime(&sub, at(30));
    assert!(scan(root).unwrap().stale);
    // `inputs` newer than every source also dates the evidence.
    set_mtime(&inputs, at(40));
    assert!(!scan(root).unwrap().stale);
    // `.sbtopts` is not a build source for staleness.
    set_mtime(&opts, at(50));
    assert!(!scan(root).unwrap().stale);
    set_mtime(&props, at(50));
    assert!(scan(root).unwrap().stale);
    // The generated files date the wiring, never the build.
    set_mtime(&props, at(10));
    let hosted = write(root, HOSTED_FILE, b"");
    set_mtime(&hosted, at(60));
    let e = scan(root).unwrap();
    assert!(!e.stale && e.wiring_newer);
    assert!(!e.build_sources.iter().any(|(r, _)| r == HOSTED_FILE));
    set_mtime(&hosted, at(1));
    assert!(!scan(root).unwrap().wiring_newer);
}

#[test]
fn one_projects_fresh_record_never_vouches_for_another() {
    // `core` and `api` both resolved; build.sbt bumped `api`'s dependency,
    // then only `sbt core/test` ran: core's record is newer than the edit,
    // api's predates it.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let t0 = SystemTime::now() - Duration::from_secs(3600);
    let at = |s: u64| t0 + Duration::from_secs(s);
    let build = write(
        root,
        "build.sbt",
        b"lazy val core = project\nlazy val api = project\n",
    );
    let props = write(root, "project/build.properties", b"sbt.version=1.9.9\n");
    let record = |p: &str| {
        write(
            root,
            &format!("{p}/target/scala-2.13/update/update_cache_2.13/output"),
            JSON.as_bytes(),
        )
    };
    let (core, api) = (record("core"), record("api"));
    set_mtime(&props, at(0));
    set_mtime(&build, at(10));
    set_mtime(&core, at(20));
    set_mtime(&api, at(20));
    assert!(!scan(root).unwrap().stale);
    set_mtime(&build, at(30));
    set_mtime(&core, at(40));
    let e = scan(root).unwrap();
    assert!(e.stale, "api's evidence predates the edit");
    assert_eq!(
        e.newest_evidence,
        Some(at(40)),
        "the newest still dates the wiring"
    );
    // A full `sbt update` refreshes both.
    set_mtime(&api, at(40));
    assert!(!scan(root).unwrap().stale);
    // api's `inputs` sibling dates api too.
    set_mtime(&api, at(20));
    let inputs = write(
        root,
        "api/target/scala-2.13/update/update_cache_2.13/inputs",
        b"1",
    );
    set_mtime(&inputs, at(45));
    assert!(!scan(root).unwrap().stale);
}

#[cfg(unix)]
#[test]
fn fifos_never_wedge_and_fail_closed() {
    fn mkfifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt as _;
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(root, "target/update/update_cache/output", JSON.as_bytes());
    mkfifo(&root.join("a/target/update/update_cache/output"));
    assert!(scan(root).is_err());
    assert_eq!(discover(root), None);

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(root, "target/update/update_cache/output", JSON.as_bytes());
    mkfifo(&root.join("build.sbt"));
    assert!(scan(root).is_err());
}

#[cfg(unix)]
#[test]
fn symlinks_are_never_followed() {
    use std::os::unix::fs::symlink;
    let outside = tempfile::tempdir().unwrap();
    write(
        outside.path(),
        "update/update_cache/output",
        JSON.as_bytes(),
    );
    write(
        outside.path(),
        "x/target/update/update_cache/output",
        JSON.as_bytes(),
    );
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(root, "build.sbt", b"");
    // A target symlinked outside, a module symlinked outside, a symlinked
    // evidence file.
    fs::create_dir_all(root.join("a")).unwrap();
    symlink(outside.path(), root.join("a/target")).unwrap();
    symlink(outside.path(), root.join("b")).unwrap();
    write(root, "c/target/update/update_cache/real", JSON.as_bytes());
    symlink(
        root.join("c/target/update/update_cache/real"),
        root.join("c/target/update/update_cache/output"),
    )
    .unwrap();
    symlink(root.join("build.sbt"), root.join("d.sbt")).unwrap();
    let e = scan(root).unwrap();
    assert!(e.files.is_empty(), "{:?}", rels(&e));
    assert_eq!(e.build_sources.len(), 1);
}

/// The `file:` URI sbt writes for `path`: `file:///C:/x` on Windows (a
/// backslash is no URI separator, and an invalid JSON escape).
fn file_uri(path: &Path) -> String {
    let text = path
        .to_string_lossy()
        .replace('\\', "/")
        .replace(' ', "%20");
    if text.starts_with('/') {
        format!("file://{text}")
    } else {
        format!("file:///{text}")
    }
}

#[test]
fn cache_roots_from_artifact_paths() {
    let caches = tempfile::tempdir().unwrap();
    let c = caches.path();
    let coursier = c.join("coursier/v1/https/repo1.maven.org/maven2");
    let ivy = c.join(".ivy2/cache");
    let m2 = c.join("m2/repository");
    let own = c.join("other/.socket/sbt-hosted/maven2");
    let jar = |base: &Path, maven: bool| {
        let p = if maven {
            base.join("org/apache/commons/commons-lang3/3.11/commons-lang3-3.11.jar")
        } else {
            base.join("org.apache.commons/commons-lang3/jars/commons-lang3-3.11.jar")
        };
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, b"jar").unwrap();
        file_uri(&p)
    };
    let uris = [
        jar(&coursier, true),
        jar(&ivy, false),
        jar(&m2, true),
        jar(&own, true),
        // Gone, mismatched coordinates, the sbt boot directory.
        file_uri(&c.join("gone/org/apache/commons/commons-lang3/3.11/x.jar")),
        file_uri(&c.join("m2/repository/org/other/commons-lang3/3.11/x.jar")),
        file_uri(&c.join(".sbt/boot/scala-2.12.18/lib/scala-library.jar")),
    ];
    let artifacts: Vec<String> = uris
        .iter()
        .map(|u| format!(r#"[{{"name":"commons-lang3"}},"{u}"]"#))
        .collect();
    let json = format!(
        r#"{{"configurations":[{{"configuration":{{"name":"compile"}},"modules":[{{"module":{{"organization":"org.apache.commons","name":"commons-lang3","revision":"3.11"}},"artifacts":[{}],"evicted":false}}],"details":[]}}]}}"#,
        artifacts.join(",")
    );
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write(root, "target/update/update_cache/output", json.as_bytes());
    // Not an sbt build: nothing.
    assert!(cache_roots(root).is_empty());
    write(root, "build.sbt", b"");
    let roots = cache_roots(root);
    let mut want = vec![
        JvmCacheRoot::new(coursier, JvmCacheLayout::Coursier),
        JvmCacheRoot::new(ivy, JvmCacheLayout::Ivy),
        JvmCacheRoot::new(m2, JvmCacheLayout::Maven2),
    ];
    want.sort();
    assert_eq!(roots, want);
}

#[test]
fn meta_build_records_never_date_the_evidence() {
    // Probe (1.9.9, 2.0.9): a plain sbt load after editing build.sbt
    // rewrites only the meta-build's `output`; the libraries' records still
    // predate the edit, so the evidence is stale.
    let t0 = SystemTime::now() - Duration::from_secs(3600);
    let at = |s: u64| t0 + Duration::from_secs(s);
    let cases = [
        (
            "x",
            "target/scala-2.12/update/update_cache_2.12",
            "project/target/scala-2.12/sbt-1.0/update/update_cache_2.12",
        ),
        (
            "x",
            "target/out/jvm/scala-3.8.4/x/update/update_cache_3",
            "target/out/jvm/scala-3.8.4/x-build/update/update_cache_3",
        ),
        // A root renamed since sbt wrote the meta-build's `-build` id.
        (
            "renamed",
            "target/out/jvm/scala-3.8.4/x/update/update_cache_3",
            "target/out/jvm/scala-3.8.4/x-build/update/update_cache_3",
        ),
    ];
    for (root_name, lib, meta) in cases {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join(root_name);
        let build = write(
            &root,
            "build.sbt",
            b"lazy val x = project.in(file(\".\"))\n",
        );
        let props = write(&root, "project/build.properties", b"sbt.version=1.9.9\n");
        let lib_out = write(&root, &format!("{lib}/output"), JSON.as_bytes());
        let lib_in = write(&root, &format!("{lib}/inputs"), b"1");
        let meta_out = write(&root, &format!("{meta}/output"), JSON.as_bytes());
        let meta_in = write(&root, &format!("{meta}/inputs"), b"1");
        for p in [&props, &lib_out, &lib_in, &meta_in] {
            set_mtime(p, at(10));
        }
        set_mtime(&build, at(20));
        set_mtime(&meta_out, at(30));
        let e = scan(&root).unwrap();
        assert!(e.stale, "{root_name}: {meta}");
        assert_eq!(e.newest_evidence, Some(at(10)), "{root_name}: {meta}");
        // `sbt update` rewrites the libraries' records: fresh again.
        set_mtime(&lib_out, at(40));
        assert!(!scan(&root).unwrap().stale, "{root_name}: {meta}");
        // The wiring is dated against the library records too.
        let hosted = write(&root, HOSTED_FILE, b"");
        set_mtime(&hosted, at(45));
        set_mtime(&meta_out, at(50));
        assert!(scan(&root).unwrap().wiring_newer, "{root_name}: {meta}");
    }
}

#[test]
fn distilled_root_has_no_verbatim_prefix() {
    assert_eq!(
        strip_verbatim(Path::new(r"\\?\C:\w\x")),
        PathBuf::from(r"C:\w\x")
    );
    assert_eq!(
        strip_verbatim(Path::new(r"\\?\UNC\srv\share\x")),
        PathBuf::from(r"\\srv\share\x")
    );
    assert_eq!(strip_verbatim(Path::new("/w/x")), PathBuf::from("/w/x"));
    let tmp = tempfile::tempdir().unwrap();
    let doc = distill(tmp.path());
    assert!(
        !doc.root.to_string_lossy().starts_with(r"\\?\"),
        "{}",
        doc.root.display()
    );
}

#[test]
fn pinned_artifacts_are_hashed_and_nothing_else() {
    use sha2::{Digest, Sha256};
    let tmp = tempfile::tempdir().unwrap();
    let pinned = tmp.path().join("ivy/jars/gson-2.8.9-socket.1d3c1fd2.jar");
    let plain = tmp.path().join("ivy/jars/gson-2.8.9.jar");
    std::fs::create_dir_all(pinned.parent().unwrap()).unwrap();
    std::fs::write(&pinned, b"PINNED").unwrap();
    std::fs::write(&plain, b"PLAIN").unwrap();
    let missing = tmp.path().join("gone.jar");
    let mut res = JvmResolution::default();
    let g = "com.google.code.gson".to_string();
    let a = "gson".to_string();
    res.artifacts
        .entry((g.clone(), a.clone(), "2.8.9-socket.1d3c1fd2".into()))
        .or_default()
        .extend([pinned.clone(), missing.clone()]);
    res.artifacts
        .entry((g, a, "2.8.9".into()))
        .or_default()
        .insert(plain.clone());
    #[cfg(unix)]
    {
        let link = tmp.path().join("link.jar");
        std::os::unix::fs::symlink(&pinned, &link).unwrap();
        res.artifacts
            .entry(("x".into(), "y".into(), "1-socket.abcdef12".into()))
            .or_default()
            .insert(link);
    }
    let hashes = pinned_artifact_hashes(&res);
    assert_eq!(
        hashes,
        [(pinned, hex::encode(Sha256::digest(b"PINNED")))].into()
    );
}
