//! Tests of the harness that need no Bazel. They run on every `cargo test`
//! of the suite, so a broken flag table or isolation check is caught on a
//! pull request and not first in a nightly cell.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256, Sha512};

use super::env::{System, Version};
use super::fixture_server::FixtureServer;
use super::invoke::{Bazel, Options};
use super::isolation::{self, OutsideState, Scratch};
use super::probe_report::{Report, Status};
use super::proof::{parse_locations, Anchor, SourceFile};
use super::server::Limiter;
use super::workspace;

fn version(text: &str) -> Version {
    Version::parse(text).unwrap_or_else(|| panic!("{text} parses"))
}

fn bazel(text: &str, bazelisk: bool) -> Bazel {
    Bazel {
        program: "bazel".into(),
        version: version(text),
        bazelisk,
        use_version: Some(text.into()),
    }
}

fn strings(args: &[OsString]) -> Vec<String> {
    args.iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

#[test]
fn version_parses_releases_and_prereleases_and_nothing_else() {
    let v = version("9.3.2");
    assert_eq!((v.major, v.minor, v.patch, v.prerelease), (9, 3, 2, false));
    let rc = version("10.0.0rc3");
    assert_eq!(
        (rc.major, rc.minor, rc.patch, rc.prerelease),
        (10, 0, 0, true)
    );
    assert!(version("9.0.0-pre.20250101.1").prerelease);
    for bad in [
        "", "9", "9.3", "9.3.2.1", "9..2", "9.3.2.", "v9.3.2", "latest",
    ] {
        assert_eq!(Version::parse(bad), None, "{bad:?}");
    }
}

#[test]
fn a_prerelease_is_below_its_release() {
    assert!(version("8.3.0").at_least(8, 3, 0));
    assert!(version("9.3.2").at_least(8, 3, 0));
    assert!(!version("8.2.9").at_least(8, 3, 0));
    assert!(!version("10.0.0rc3").at_least(10, 0, 0));
    assert!(version("10.0.0rc3").at_least(9, 3, 2));
    assert!(version("6.6.0").has_lockfile_mode() && !version("5.4.1").has_lockfile_mode());
    assert!(version("8.8.2").has_contents_cache() && !version("7.7.2").has_contents_cache());
    assert!(!version("8.3.0rc1").has_contents_cache());
}

#[test]
fn dependency_system_flags_per_line() {
    let flags = |v: &str, system| version(v).system_flags(system).map(<[_]>::to_vec);
    let none: Option<Vec<&str>> = None;
    assert_eq!(flags("5.4.1", System::Workspace), Some(vec![]));
    assert_eq!(flags("5.4.1", System::Bzlmod), none);
    assert_eq!(flags("6.6.0", System::Workspace), Some(vec![]));
    assert_eq!(
        flags("6.6.0", System::Bzlmod),
        Some(vec!["--enable_bzlmod"])
    );
    assert_eq!(flags("7.0.2", System::Bzlmod), Some(vec![]));
    // 7.0 has no --enable_workspace flag at all.
    assert_eq!(
        flags("7.0.2", System::Workspace),
        Some(vec!["--noenable_bzlmod"])
    );
    assert_eq!(flags("7.7.2", System::Hybrid), Some(vec![]));
    assert_eq!(
        flags("8.8.2", System::Workspace),
        Some(vec!["--enable_workspace", "--noenable_bzlmod"])
    );
    assert_eq!(
        flags("8.8.2", System::Hybrid),
        Some(vec!["--enable_workspace"])
    );
    assert_eq!(flags("9.3.2", System::Bzlmod), Some(vec![]));
    assert_eq!(flags("9.3.2", System::Workspace), none);
    assert_eq!(flags("10.0.0rc3", System::Hybrid), none);
}

#[test]
fn unsupported_workspace_paths_are_named() {
    let spaced = Path::new("/tmp/has space/ws");
    assert!(isolation::check_path(&version("7.2.0"), spaced).is_err());
    assert!(isolation::check_path(&version("7.0.2"), spaced).is_err());
    assert!(isolation::check_path(&version("7.7.2"), spaced).is_ok());
    let unicode = Path::new("/tmp/caf\u{e9}/ws");
    assert!(isolation::check_path(&version("7.7.2"), unicode).is_err());
    assert!(isolation::check_path(&version("5.4.1"), unicode).is_err());
    assert!(isolation::check_path(&version("8.8.2"), unicode).is_ok());
    assert!(isolation::check_path(&version("5.4.1"), Path::new("/tmp/plain/ws")).is_ok());
}

#[test]
fn scratch_keeps_every_directory_inside_one_root_and_removes_it() {
    let scratch = Scratch::cold();
    let root = scratch.root.clone();
    for dir in [
        &scratch.workspace,
        &scratch.tmp,
        &scratch.home,
        &scratch.repository_cache,
    ] {
        assert!(dir.is_dir() && dir.starts_with(&root), "{}", dir.display());
    }
    assert!(scratch.bazelisk_home.starts_with(&root));
    assert!(!scratch.repository_cache.starts_with(&scratch.workspace));
    // Bazel leaves read-only directories behind (the install base).
    let locked = scratch.output_user_root.join("install");
    std::fs::create_dir_all(&locked).unwrap();
    std::fs::write(locked.join("file"), "x").unwrap();
    for path in [locked.join("file"), locked.clone()] {
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&path, perms).unwrap();
    }
    let outside_root = scratch.output_user_root.clone();
    drop(scratch);
    assert!(
        !root.exists() && !outside_root.exists(),
        "scratch not removed"
    );
}

#[test]
fn startup_options_keep_the_server_inside_the_scratch_root() {
    let scratch = Scratch::cold();
    let args = strings(&bazel("9.3.2", false).startup_args(&scratch));
    let tmp = scratch.tmp.display();
    assert_eq!(
        args,
        [
            "--nohome_rc".to_string(),
            "--nosystem_rc".to_string(),
            format!("--output_user_root={}", scratch.output_user_root.display()),
            "--max_idle_secs=15".to_string(),
            format!("--host_jvm_args=-Djava.io.tmpdir={tmp}"),
            "--host_jvm_args=-XX:-UsePerfData".to_string(),
        ]
    );
    // The startup set is the same for every command: a different
    // --host_jvm_args would restart the server mid-test.
    let cmd = bazel("9.3.2", false).command(&scratch, "info");
    let argv: Vec<OsString> = cmd.get_args().map(OsString::from).collect();
    assert_eq!(strings(&argv[..args.len()]), args);
    assert_eq!(argv[args.len()], "info");
    assert_eq!(cmd.get_current_dir(), Some(scratch.workspace.as_path()));
}

#[test]
fn the_child_environment_is_scrubbed_and_points_into_the_scratch_root() {
    let scratch = Scratch::cold();
    let env_of = |bazel: &Bazel| -> BTreeMap<String, Option<PathBuf>> {
        bazel
            .command(&scratch, "info")
            .get_envs()
            .map(|(k, v)| (k.to_string_lossy().into_owned(), v.map(PathBuf::from)))
            .collect()
    };
    let direct = env_of(&bazel("7.7.2", false));
    for removed in super::env::REMOVED.iter().chain(super::env::PROXY) {
        if *removed != "USE_BAZEL_VERSION" {
            assert_eq!(
                direct.get(*removed),
                Some(&None),
                "{removed} must be removed"
            );
        }
    }
    // Windows environment names are case-insensitive: one entry covers both.
    if !cfg!(windows) {
        assert_eq!(direct.get("https_proxy"), Some(&None));
    }
    // Not known to be bazelisk: no home is forced on a wrapper launcher.
    assert_eq!(direct.get("BAZELISK_HOME"), Some(&None));
    let set =
        |env: &BTreeMap<String, Option<PathBuf>>, name: &str| env.get(name).cloned().flatten();
    assert_eq!(set(&direct, "USE_BAZEL_VERSION"), Some("7.7.2".into()));
    assert_eq!(set(&direct, "HOME"), Some(scratch.home.clone()));
    assert_eq!(set(&direct, "USERPROFILE"), Some(scratch.home.clone()));
    assert_eq!(set(&direct, "TMPDIR"), Some(scratch.tmp.clone()));
    assert_eq!(
        set(&direct, "COURSIER_CACHE"),
        Some(scratch.home.join("coursier"))
    );
    // hermetic::command removes DO_NOT_TRACK; the harness sets it again.
    assert_eq!(set(&direct, "DO_NOT_TRACK"), Some("1".into()));
    assert_eq!(
        set(&direct, "NO_CRASH_ON_LOGGING_IN_TEST"),
        Some("1".into())
    );
    assert_eq!(set(&direct, "SOCKET_TELEMETRY_DISABLED"), Some("1".into()));

    let launcher = env_of(&bazel("7.7.2", true));
    assert_eq!(
        set(&launcher, "BAZELISK_HOME"),
        Some(scratch.bazelisk_home.clone())
    );

    let mut unpinned = bazel("7.7.2", false);
    unpinned.use_version = None;
    assert_eq!(env_of(&unpinned).get("USE_BAZEL_VERSION"), Some(&None));
}

#[test]
fn command_options_follow_the_bazel_line() {
    let scratch = Scratch::cold();
    let args = |v: &str, options: &Options| {
        options
            .args(&bazel(v, false), &scratch)
            .map(|a| strings(&a))
    };
    let cache = format!("--repository_cache={}", scratch.repository_cache.display());
    let home = format!("--repo_env=HOME={}", scratch.home.display());

    let plain = args("5.4.1", &Options::default()).unwrap();
    assert_eq!(
        plain,
        ["--color=no", "--curses=no", cache.as_str(), home.as_str()]
    );

    let server_config = scratch.root.join("downloader.cfg");
    let cell = Options {
        system: Some(System::Workspace),
        downloader_config: Some(server_config.clone()),
        repo_env: vec![(
            "GOPROXY".into(),
            "http://127.0.0.1:1/proxy.golang.org".into(),
        )],
        no_retries: true,
        ..Options::default()
    };
    let seven = args("7.7.2", &cell).unwrap();
    assert!(seven.contains(&format!(
        "--experimental_downloader_config={}",
        server_config.display()
    )));
    assert!(seven.contains(&"--repo_env=GOPROXY=http://127.0.0.1:1/proxy.golang.org".to_string()));
    assert!(seven.contains(&"--noenable_bzlmod".to_string()));
    assert!(seven.contains(&"--lockfile_mode=update".to_string()));
    assert!(seven.contains(&"--experimental_repository_downloader_retries=0".to_string()));
    assert!(!seven.iter().any(|a| a.starts_with("--repo_contents_cache")));

    let eight = args("8.8.2", &cell).unwrap();
    assert!(eight.contains(&format!("--downloader_config={}", server_config.display())));
    assert!(eight.contains(&"--enable_workspace".to_string()));
    assert!(eight.contains(&"--repo_contents_cache=".to_string()));
    // Only the canary that tests the contents cache leaves it on.
    let canary = Options {
        contents_cache: true,
        ..Options::default()
    };
    assert!(!args("9.3.2", &canary)
        .unwrap()
        .iter()
        .any(|a| a.starts_with("--repo_contents_cache")));

    let refused = args("9.3.2", &cell).unwrap_err();
    assert!(
        refused.contains("9.3.2 has no workspace dependency system"),
        "{refused}"
    );
    assert!(
        !plain.iter().any(|a| a.starts_with("--lockfile_mode")),
        "5.x has no lockfile"
    );
}

#[test]
fn the_offline_phase_points_every_proxy_at_a_closed_port() {
    let mut cmd = std::process::Command::new("tool");
    Options::default().apply_env(&mut cmd);
    assert_eq!(cmd.get_envs().count(), 0);
    let offline = Options {
        closed_proxies: true,
        ..Options::default()
    };
    offline.apply_env(&mut cmd);
    let env: BTreeMap<_, _> = cmd.get_envs().collect();
    let lower: &[&str] = if cfg!(windows) { &[] } else { &["https_proxy"] };
    for name in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]
        .iter()
        .chain(lower)
    {
        assert_eq!(
            env[std::ffi::OsStr::new(name)],
            Some("http://127.0.0.1:9".as_ref()),
            "{name}"
        );
    }
    assert_eq!(
        env[std::ffi::OsStr::new("NO_PROXY")],
        Some("127.0.0.1,localhost".as_ref())
    );
}

#[test]
fn outside_state_reports_created_changed_and_removed_entries() {
    let tmp = tempfile::tempdir().unwrap();
    let present = tmp.path().join("present");
    let absent = tmp.path().join("absent");
    std::fs::create_dir_all(present.join("_bazel_user/old")).unwrap();
    let state = OutsideState::capture_of(&[present.clone(), absent.clone()]);
    assert_eq!(state.changes(), Vec::<String>::new());
    state.assert_untouched("nothing happened");

    // A stray run creates `<root>/_bazel_<user>/<md5>`, two levels down.
    std::fs::create_dir_all(present.join("_bazel_user/0123abcd")).unwrap();
    std::fs::create_dir_all(absent.join("downloads")).unwrap();
    std::fs::remove_dir(present.join("_bazel_user/old")).unwrap();
    let changes = state.changes().join("\n");
    assert!(
        changes.contains(&format!(
            "created: {}",
            present.join("_bazel_user/0123abcd").display()
        )),
        "{changes}"
    );
    assert!(
        changes.contains(&format!("created: {}", absent.display())),
        "{changes}"
    );
    assert!(
        changes.contains(&format!(
            "removed: {}",
            present.join("_bazel_user/old").display()
        )),
        "{changes}"
    );
    let failed = std::panic::catch_unwind(|| state.assert_untouched("after a stray run"));
    assert!(
        failed.is_err(),
        "a written default location must fail the check"
    );
}

#[test]
fn server_cmdline_is_read_from_the_output_base() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(isolation::server_cmdline(tmp.path()), Vec::<String>::new());
    std::fs::create_dir_all(tmp.path().join("server")).unwrap();
    let raw = b"bazel(ws)\0-Djava.io.tmpdir=/t/tmp\0-XX:-UsePerfData\0-jar\0";
    std::fs::write(tmp.path().join("server/cmdline"), raw).unwrap();
    assert_eq!(
        isolation::server_cmdline(tmp.path()),
        [
            "bazel(ws)",
            "-Djava.io.tmpdir=/t/tmp",
            "-XX:-UsePerfData",
            "-jar"
        ]
    );
    assert_eq!(isolation::stray_perf_data(u32::MAX), Vec::<PathBuf>::new());
}

#[test]
fn the_limiter_admits_two_and_blocks_the_third() {
    static LIMITER: Limiter = Limiter::new(2);
    let (taken, first_holds) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let first = std::thread::spawn(move || {
        let _slot = LIMITER.take();
        taken.send(()).unwrap();
        released.recv().unwrap();
    });
    first_holds.recv().unwrap();
    let _second = LIMITER.take();
    let (sent, received) = std::sync::mpsc::channel();
    let third = std::thread::spawn(move || {
        let _slot = LIMITER.take();
        sent.send(()).unwrap();
    });
    assert!(
        received.recv_timeout(Duration::from_millis(200)).is_err(),
        "a third server started while two were running"
    );
    release.send(()).unwrap();
    received
        .recv_timeout(Duration::from_secs(10))
        .expect("the freed slot is taken");
    first.join().unwrap();
    third.join().unwrap();
}

#[test]
fn a_test_holds_one_cell_at_a_time() {
    // A twin opened while the first cell is held would work alone and hang
    // the suite when two tests do it at once; it is refused every time,
    // also with a slot free.
    static LIMITER: Limiter = Limiter::new(2);
    let held = LIMITER.take();
    assert!(std::panic::catch_unwind(|| LIMITER.take()).is_err());
    drop(held);
    drop(LIMITER.take());
}

/// One request to the fixture server, as (status line, body).
fn http(server: &FixtureServer, method: &str, target: &str, headers: &str) -> (String, Vec<u8>) {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", server.port())).unwrap();
    write!(
        stream,
        "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n{headers}\r\n"
    )
    .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a header block");
    let head = String::from_utf8_lossy(&response[..split]).into_owned();
    (
        head.lines().next().unwrap().to_string(),
        response[split + 4..].to_vec(),
    )
}

#[test]
fn fixture_server_serves_by_original_url_and_answers_a_miss_with_404() {
    let server = FixtureServer::start();
    let url = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
    server.serve(url, b"tarball".to_vec());
    server.serve_status("https://repo1.maven.org/maven2/withdrawn.jar", 410);

    let target = "/registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
    assert_eq!(
        http(&server, "GET", target, ""),
        ("HTTP/1.1 200 OK".to_string(), b"tarball".to_vec())
    );
    assert_eq!(http(&server, "HEAD", target, "").1, b"");
    assert_eq!(
        http(&server, "GET", "/repo1.maven.org/maven2/withdrawn.jar", "").0,
        "HTTP/1.1 410 Gone"
    );
    assert_eq!(
        http(
            &server,
            "GET",
            "/bcr.bazel.build/modules/x/1.0/MODULE.bazel",
            ""
        )
        .0,
        "HTTP/1.1 404 Not Found"
    );
    assert_eq!(
        http(&server, "POST", target, "").0,
        "HTTP/1.1 405 Method Not Allowed"
    );

    assert_eq!(
        server.hosts(),
        ["bcr.bazel.build", "registry.npmjs.org", "repo1.maven.org"]
    );
    let hits = server.requests_for(url);
    assert_eq!(
        hits.iter()
            .map(|r| (r.method.as_str(), r.status))
            .collect::<Vec<_>>(),
        [("GET", 200), ("HEAD", 200), ("POST", 405)]
    );
    server.assert_not_requested(
        "https://registry.npmjs.org/other/-/other-1.0.0.tgz",
        "offline",
    );
    server.assert_no_header("Authorization", "no credential");
    let asked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        server.assert_not_requested(url, "offline")
    }));
    assert!(
        asked.is_err(),
        "a requested URL must fail the offline assertion"
    );

    http(&server, "GET", target, "Authorization: Bearer secret\r\n");
    let leaked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        server.assert_no_header("authorization", "no credential")
    }));
    assert!(leaked.is_err(), "a credential header must be seen");
}

#[test]
fn an_assertion_about_an_unreached_server_fails() {
    // A warm repository cache sends nothing: "no request for X" would pass
    // without having tested anything.
    let server = FixtureServer::start();
    for check in [
        Box::new(|| server.assert_not_requested("https://example.invalid/x", "twin"))
            as Box<dyn Fn()>,
        Box::new(|| server.assert_no_header("Authorization", "twin")),
    ] {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(check));
        assert!(result.is_err(), "an unreached server proves nothing");
    }
}

#[test]
fn downloader_config_rewrites_everything_but_loopback_to_the_server() {
    let config = workspace::render_downloader_config(4321);
    let directives: Vec<&str> = config
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .collect();
    assert_eq!(
        directives,
        [
            r"rewrite ((?!127\.0\.0\.1[:/]).*) http://127.0.0.1:4321/$1",
            "block *",
            "allow 127.0.0.1",
        ]
    );
    assert!(!config.contains("<port>") && !config.contains('\r'));
}

#[test]
fn the_probe_rule_needs_no_shell() {
    let rule = workspace::fixtures_root()
        .join("common")
        .join(workspace::PROBE_BZL);
    let text = std::fs::read_to_string(rule).unwrap();
    for banned in ["run_shell", "genrule", "ctx.actions.run("] {
        assert!(
            !text.contains(banned),
            "probe.bzl uses {banned}: it must build on Windows without Bash"
        );
    }
    assert!(text.contains("declare_directory") && text.contains("is_directory"));
}

#[test]
fn query_locations_are_read_from_the_right() {
    let stdout = "Loading: 0 packages loaded\n\
        /ob/external/+dep_ext+dep/pkg/index.js:1:1: source file @dep//:pkg/index.js\n\
        C:/b/x/external/npm__left-pad__1.3.0/package.tgz:1:1: source file @@npm__left-pad__1.3.0//:package.tgz\n\
        /ws/BUILD.bazel:3:13: socket_probe rule //:socket_probe\n";
    assert_eq!(
        parse_locations(stdout),
        [
            SourceFile {
                path: "/ob/external/+dep_ext+dep/pkg/index.js".into(),
                label: "@dep//:pkg/index.js".into()
            },
            SourceFile {
                path: "C:/b/x/external/npm__left-pad__1.3.0/package.tgz".into(),
                label: "@@npm__left-pad__1.3.0//:package.tgz".into(),
            },
        ]
    );
    let none = parse_locations("x: source file //:a\n:1:1: source file //:b\n");
    assert_eq!(none, Vec::<SourceFile>::new());
}

#[test]
fn anchors_name_exactly_one_file_and_compare_its_digest() {
    let tmp = tempfile::tempdir().unwrap();
    let file = |rel: &str, bytes: &[u8]| {
        let path = tmp.path().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        path
    };
    let source = |path: &Path, label: &str| SourceFile {
        path: path.to_path_buf(),
        label: label.into(),
    };
    let tgz = file("npm__left-pad__1.3.0/package.tgz", b"patched tarball");
    let other = file("npm__once__1.4.0/package.tgz", b"other tarball");
    let jar = file("gson/file/v1/com/google/gson-2.10.1.jar", b"registry jar");
    let processed = file("maven/processed_gson-2.10.1.jar", b"stamped jar");
    let sources = [
        source(&tgz, "@@npm__left-pad__1.3.0//:package.tgz"),
        source(&other, "@@npm__once__1.4.0//:package.tgz"),
        source(&jar, "@@gson//file:v1/com/google/gson-2.10.1.jar"),
        source(&processed, "@@maven//:processed_gson-2.10.1.jar"),
    ];
    let sha256 = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
    let integrity = |bytes: &[u8]| {
        use base64::Engine as _;
        format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
        )
    };

    let good = Anchor::Integrity {
        label: "npm__left-pad__1.3.0",
        integrity: &integrity(b"patched tarball"),
    };
    assert_eq!(good.check(&sources), Ok(tgz.clone()));
    let unpatched = Anchor::Integrity {
        label: "npm__left-pad__1.3.0",
        integrity: &integrity(b"upstream tarball"),
    };
    assert!(unpatched
        .check(&sources)
        .unwrap_err()
        .contains("has digest sha512-"));
    // Two tarballs match a loose label: refused, not "the first one".
    let loose = Anchor::Integrity {
        label: "npm__",
        integrity: &integrity(b"patched tarball"),
    };
    assert!(loose.check(&sources).unwrap_err().contains("found 2"));

    let by_hash = Anchor::Sha256 {
        label: "npm__once",
        sha256: &sha256(b"other tarball"),
    };
    assert_eq!(by_hash.check(&sources), Ok(other));
    let missing = Anchor::Sha256 {
        label: "npm__absent",
        sha256: &sha256(b"x"),
    };
    assert!(missing.check(&sources).unwrap_err().contains("found 0"));

    // The registry jar under `file/`, never the stamped `processed_` jar.
    let registry = Anchor::FileJar {
        jar: "gson-2.10.1.jar",
        sha256: &sha256(b"registry jar"),
    };
    assert_eq!(registry.check(&sources), Ok(jar));
    let stamped = Anchor::FileJar {
        jar: "processed_gson-2.10.1.jar",
        sha256: &sha256(b"stamped jar"),
    };
    assert!(stamped.check(&sources).unwrap_err().contains("found 0"));
}

#[test]
fn a_report_carries_the_fields_a_claim_is_audited_on() {
    let mut report = Report::new("bazel_core_launch_isolated");
    report.bazel = Some("9.3.2".into());
    report.system = Some(System::Bzlmod);
    report.hosts = vec!["bcr.bazel.build".into()];
    report
        .resolved
        .insert("aspect_rules_js".into(), "3.6.0".into());
    report.detail("tier", 1);
    let ran = report.to_json(Status::Ran, None);
    assert_eq!(ran["status"], "ran");
    assert_eq!(ran["bazel"], "9.3.2");
    assert_eq!(ran["system"], "bzlmod");
    assert_eq!(ran["hosts"], serde_json::json!(["bcr.bazel.build"]));
    assert_eq!(ran["resolved"]["aspect_rules_js"], "3.6.0");
    assert_eq!(ran["details"]["tier"], 1);
    assert_eq!(ran["direct_network"], false);
    assert!(ran["wall_ms"].is_u64() && ran["os"].is_string() && ran["reason"].is_null());

    let skipped = Report::new("bazel_core_x").to_json(Status::Skipped, Some("no Bazel"));
    assert_eq!(skipped["status"], "skipped");
    assert_eq!(skipped["reason"], "no Bazel");
    assert!(skipped["bazel"].is_null() && skipped["hosts"].as_array().unwrap().is_empty());

    // One file per (test, version, system, OS): matrix cells never collide.
    let name = report
        .path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(
        name.starts_with("bazel_core_launch_isolated.9.3.2.bzlmod."),
        "{name}"
    );
    let mut odd = Report::new("a/b c");
    odd.bazel = Some("10.0.0rc3".into());
    let odd = odd
        .path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(odd.starts_with("a_b_c.10.0.0rc3.any."), "{odd}");
}
