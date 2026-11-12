//! Tests of the harness that need no Bazel. They run on every `cargo test`
//! of the suite, so a broken flag table or isolation check is caught on a
//! pull request and not first in a nightly cell.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256, Sha512};

use super::env::{self, Group, System, Version};
use super::fixture_server::FixtureServer;
use super::invoke::{absolute_program, named_bazelisk, Bazel, Options};
use super::isolation::{self, OutsideState, Scratch};
use super::probe_report::{self, Report, Status};
use super::proof::{parse_locations, Anchor, SourceFile};
use super::server::{self, Cell, Limiter};
use super::toy;
use super::workspace;
use crate::common::hermetic;

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

/// Whether `check` panics.
fn panics(check: &dyn Fn()) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(check)).is_err()
}

/// The version of the cells the selftests open: no release has it, so
/// their report names cannot collide with a real cell's.
const NO_RELEASE: &str = "0.0.0";

/// A [`Cell`] that needs no Bazel: `detect` names a program and probes
/// nothing. With [`no_bazel`] any command the cell tried to run would fail
/// to spawn, so a selftest reaches only what works without a server. The
/// group is the one the environment selects, so the cell is never skipped.
fn selftest_cell(test: &str, detect: fn(&Scratch) -> Result<Bazel, String>) -> Cell {
    let group = env::selected_group().unwrap_or(Group::Core);
    Cell::open_in(test, group, None, Scratch::cold, detect).expect("a cell that needs no Bazel")
}

fn stand_in(program: &str) -> Result<Bazel, String> {
    Ok(Bazel {
        program: program.into(),
        version: version(NO_RELEASE),
        bazelisk: false,
        use_version: None,
    })
}

fn no_bazel(_: &Scratch) -> Result<Bazel, String> {
    stand_in("socket-patch-selftest-no-such-bazel")
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
    // A launcher may export TEST_TMPDIR itself: both variables, or a
    // failing extension on 7.x is a crash (exit 37) in that server.
    for test_mode in [
        "ENABLE_BUG_REPORT_LOGGING_IN_TEST",
        "NO_CRASH_ON_LOGGING_IN_TEST",
    ] {
        assert_eq!(set(&direct, test_mode), Some("1".into()), "{test_mode}");
    }
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
    // 8.2.0 renamed the downloader flag: 8.0.x and 8.1.x refuse the new
    // spelling (`Unrecognized option`), every earlier line too.
    let rewrite = Options {
        downloader_config: Some(server_config.clone()),
        ..Options::default()
    };
    let experimental = format!(
        "--experimental_downloader_config={}",
        server_config.display()
    );
    let renamed = format!("--downloader_config={}", server_config.display());
    for (line, want) in [
        ("5.4.1", &experimental),
        ("7.7.2", &experimental),
        ("8.0.0", &experimental),
        ("8.1.1", &experimental),
        ("8.2.0", &renamed),
        ("8.4.2", &renamed),
        ("8.8.2", &renamed),
        ("9.3.2", &renamed),
        ("10.0.0rc3", &renamed),
    ] {
        let all = args(line, &rewrite).unwrap();
        let flags: Vec<&String> = all
            .iter()
            .filter(|a| a.contains("downloader_config="))
            .collect();
        assert_eq!(flags, [want], "Bazel {line}");
    }
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

/// What makes a toy cell need no network: the committed registry as a
/// `file://` URL where that form is known to work, the committed archives
/// as a distdir, and a hand pin that only an upstream lock takes.
#[test]
fn a_toy_cell_reads_the_committed_registry_and_archives() {
    let scratch = Scratch::cold();
    let distdir = workspace::fixtures_root().join("registry/distdir/9.3.2");
    assert!(distdir.is_dir(), "{}", distdir.display());
    let options = Options {
        registry: Some("file:///srv/registry".into()),
        distdir: Some(distdir.clone()),
        ..Options::default()
    };
    let args = strings(&options.args(&bazel("9.3.2", false), &scratch).unwrap());
    assert!(args.contains(&"--registry=file:///srv/registry".to_string()));
    assert!(args.contains(&format!("--distdir={}", distdir.display())));

    // Off Unix, for a path a URL would have to escape, and for a relative
    // one, there is no URL: the fixture server plays the registry instead.
    let url = cfg!(unix).then(|| "file:///srv/registry".to_string());
    assert_eq!(toy::file_url(Path::new("/srv/registry")), url);
    assert_eq!(toy::file_url(Path::new("/srv/my registry")), None);
    assert_eq!(toy::file_url(Path::new("registry")), None);

    let lock = workspace::fixtures_root().join("core/bzlmod/e9/toy.lock.json");
    let lock = std::fs::read_to_string(lock).expect("read the toy lock");
    let pinned = toy::pin(&lock, toy::DEP);
    assert!(pinned.contains(&toy::DEP.hosted_url()) && !pinned.contains(toy::REGISTRY));
    assert!(
        panics(&|| drop(toy::pin(&pinned, toy::DEP))),
        "a lock already pinned takes no second pin"
    );
}

/// Whether a toy test runs in a cell is decided from committed files, and
/// a cell that is missing something never passes as "not applicable": a
/// required cell on a Bazel version with no fixture or no registry mirror
/// fails instead of reporting `skipped` for every test. The manifest here
/// has the shape of `registry/MANIFEST.json` and its three kinds of line.
#[test]
fn a_toy_cell_runs_or_is_not_applicable_or_cannot_run() {
    use toy::{Gate, Mirror};
    let manifest = serde_json::json!({ "versions": {
        "7.7.2": { "distdir": true, "archives": [{ "sha256": "p7" }] },
        "8.8.2": {
            "distdir": false,
            "archives": [{ "sha256": "both" }, { "sha256": "module" }],
            "workspace_archives": [{ "sha256": "suffix" }, { "sha256": "both" }],
        },
        "9.3.2": { "distdir": true, "archives": [{ "sha256": "p9" }] },
    }});
    let gate = |v: &str, system, fixture_present, zero_network| {
        toy::gate(
            &version(v),
            system,
            &manifest,
            fixture_present,
            zero_network,
        )
    };
    let digests = |list: &[&str]| -> Vec<String> { list.iter().map(|d| d.to_string()).collect() };

    // A line that commits its archives runs, zero network included.
    for (v, system) in [
        ("9.3.2", System::Bzlmod),
        ("7.7.2", System::Bzlmod),
        ("7.7.2", System::Workspace),
        ("7.7.2", System::Hybrid),
    ] {
        for zero_network in [false, true] {
            let run = Gate::Run(Mirror::Committed);
            assert_eq!(gate(v, system, true, zero_network), run, "{v} {system:?}");
        }
    }
    // A line that does not runs on the archives of its dependency system,
    // from a repository cache. A hybrid cell reads both files: both lists.
    for (system, list) in [
        (System::Bzlmod, &["both", "module"][..]),
        (System::Workspace, &["both", "suffix"][..]),
        (System::Hybrid, &["both", "module", "suffix"][..]),
    ] {
        let run = Gate::Run(Mirror::Cached(digests(list)));
        assert_eq!(gate("8.8.2", system, true, false), run, "{system:?}");
    }

    // Not applicable, also where the cell is required: the line lacks the
    // dependency system (whatever else is missing), or the test claims
    // zero network where the archives are not committed.
    let not_applicable = [
        gate("9.3.2", System::Workspace, false, false),
        gate("9.3.2", System::Hybrid, true, false),
        gate("5.4.1", System::Bzlmod, false, false),
        gate("8.8.2", System::Bzlmod, true, true),
    ];
    for gate in not_applicable {
        assert!(matches!(gate, Gate::NotApplicable(_)), "{gate:?}");
        assert_eq!(gate.declined("bazel_core_x", true), Some(Ok(())));
    }

    // Cannot run: no fixture for the line's major, or no registry mirror
    // for the version. That fails a required cell.
    let unmirrored = |v: &str| format!("Bazel {v} is not in fixtures/bazel/registry");
    let no_fixture = |fixture: &str| format!("there is no fixture {fixture}");
    let cannot_run = [
        (
            gate("7.1.2", System::Bzlmod, true, false),
            unmirrored("7.1.2"),
        ),
        (
            gate("7.0.2", System::Hybrid, true, false),
            unmirrored("7.0.2"),
        ),
        (
            gate("7.1.2", System::Bzlmod, true, true),
            unmirrored("7.1.2"),
        ),
        // From Bazel 8 the WORKSPACE suffix fetches archives of its own.
        (
            gate("8.4.2", System::Workspace, true, false),
            unmirrored("8.4.2"),
        ),
        (
            gate("10.0.0rc3", System::Bzlmod, false, false),
            no_fixture("core/bzlmod/e10"),
        ),
        (
            gate("6.6.0", System::Bzlmod, false, false),
            no_fixture("core/bzlmod/e6"),
        ),
        (
            gate("6.6.0", System::Workspace, false, false),
            no_fixture("core/workspace/e6"),
        ),
        // A mirror does not make up for a missing fixture.
        (
            gate("8.8.2", System::Bzlmod, false, false),
            no_fixture("core/bzlmod/e8"),
        ),
    ];
    for (gate, why) in cannot_run {
        assert!(
            matches!(&gate, Gate::CannotRun(text) if text.contains(&why)),
            "{gate:?}"
        );
        assert_eq!(gate.declined("bazel_core_x", false), Some(Ok(())));
        let failure = gate.declined("bazel_core_x", true).unwrap().unwrap_err();
        assert!(
            failure.contains(env::REQUIRED) && failure.contains(&why),
            "{failure}"
        );
    }

    // By need: with Bzlmod off below Bazel 8 a WORKSPACE cell resolves no
    // module and fetches no archive, so it runs on a version without a mirror.
    for v in ["7.0.2", "7.1.2"] {
        let run = gate(v, System::Workspace, true, false);
        assert_eq!(run, Gate::Run(Mirror::NotNeeded), "{v}");
        assert_eq!(run.declined("bazel_core_x", true), None);
    }
}

/// A line that does not commit its module archives takes them from a
/// repository cache: a cell is given the listed entries, whole, and
/// nothing else the shared cache holds.
#[test]
fn a_cell_is_seeded_with_the_listed_cache_entries_and_no_other() {
    let tmp = tempfile::tempdir().unwrap();
    let (shared, own) = (tmp.path().join("shared"), tmp.path().join("own"));
    let entry = |cache: &Path, digest: &str| cache.join("content_addressable/sha256").join(digest);
    let put = |cache: &Path, digest: &str, bytes: &[u8]| {
        std::fs::create_dir_all(entry(cache, digest)).unwrap();
        std::fs::write(entry(cache, digest).join("file"), bytes).unwrap();
        // Bazel takes a hit only with the marker of the asking repository.
        std::fs::write(entry(cache, digest).join("id-0123abcd"), b"").unwrap();
    };
    let (first, second) = (
        toy::sha256_hex(b"first archive"),
        toy::sha256_hex(b"second archive"),
    );
    let package = toy::sha256_hex(b"a toy package an earlier test fetched");
    put(&shared, &first, b"first archive");
    put(&shared, &second, b"second archive");
    put(&shared, &package, b"a toy package an earlier test fetched");
    let listed = vec![first.clone(), second.clone()];

    assert_eq!(toy::cache_lacks(&own, &listed), listed, "an empty cache");
    assert_eq!(toy::cache_lacks(&shared, &listed), Vec::<String>::new());
    toy::seed_cache(&shared, &own, &listed);
    assert_eq!(toy::cache_lacks(&own, &listed), Vec::<String>::new());
    for digest in &listed {
        let mut names: Vec<String> = std::fs::read_dir(entry(&own, digest))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            ["file", "id-0123abcd"],
            "the whole entry, no staging file"
        );
    }
    assert_eq!(
        std::fs::read(entry(&own, &first).join("file")).unwrap(),
        b"first archive"
    );
    assert!(!entry(&own, &package).exists(), "a package was copied");

    // A marker without its file is no entry; seeding again restores it and
    // leaves the entry that is there alone, but for a marker it lacks (the
    // same archive, fetched before under other URLs).
    std::fs::remove_file(entry(&own, &first).join("file")).unwrap();
    std::fs::remove_file(entry(&own, &second).join("id-0123abcd")).unwrap();
    std::fs::write(entry(&own, &second).join("id-other-urls"), b"").unwrap();
    assert_eq!(
        toy::cache_lacks(&own, &listed),
        std::slice::from_ref(&first)
    );
    std::fs::write(entry(&own, &second).join("file"), b"kept").unwrap();
    toy::seed_cache(&shared, &own, &listed);
    assert_eq!(toy::cache_lacks(&own, &listed), Vec::<String>::new());
    assert_eq!(
        std::fs::read(entry(&own, &second).join("file")).unwrap(),
        b"kept"
    );
    for marker in ["id-0123abcd", "id-other-urls"] {
        assert!(entry(&own, &second).join(marker).is_file(), "{marker}");
    }
    // The shared cache is only read.
    assert_eq!(
        std::fs::read(entry(&shared, &second).join("file")).unwrap(),
        b"second archive"
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
    let keep = present.join("_bazel_user/keep");
    std::fs::create_dir_all(&keep).unwrap();
    let state = OutsideState::capture_of(&[present.clone(), absent.clone()]);
    assert_eq!(state.changes(), Vec::<String>::new());
    state.assert_untouched("nothing happened");

    // A write three levels down (a new install base under an existing
    // `_bazel_<user>/install`, a bazelisk download under
    // `downloads/sha256`) is below what the fingerprint lists. Only the
    // modification time of the recorded directory above it tells. A
    // directory's time may not advance within one timestamp tick of its
    // creation, so entries are added until it does.
    let changed = format!("changed: {}", keep.display());
    let deadline = Instant::now() + Duration::from_secs(10);
    for n in 0.. {
        std::fs::write(keep.join(format!("x{n}")), "").unwrap();
        if state.changes().contains(&changed) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "an entry added to a recorded directory was never reported as {changed}: {:?}",
            state.changes()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let third_level = keep.join("x0").display().to_string();
    assert!(
        !state
            .changes()
            .iter()
            .any(|line| line.ends_with(&third_level)),
        "the third level is not listed: {:?}",
        state.changes()
    );

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
fn stray_perf_data_is_found_under_any_user_name() {
    // HotSpot names the directory from the passwd entry; the test process
    // may have no USER at all (a container that sets HOME only).
    let tmp = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let file = |rel: &str| {
        let path = tmp.path().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "").unwrap();
        path
    };
    let server = file("hsperfdata_alice/4242");
    file("hsperfdata_alice/7");
    let root_server = file("hsperfdata_root/1");
    // Not a perf-data directory, whatever it holds.
    file("bazel-jni.4242/4242");
    let dirs = [
        tmp.path().to_path_buf(),
        other.path().to_path_buf(),
        tmp.path().join("absent"),
    ];
    assert_eq!(isolation::stray_perf_data_in(&dirs, 4242), [server]);
    assert_eq!(isolation::stray_perf_data_in(&dirs, 1), [root_server]);
    assert_eq!(
        isolation::stray_perf_data_in(&dirs, 99),
        Vec::<PathBuf>::new()
    );
}

/// An environment that holds exactly `pairs`.
fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<OsString> {
    move |name| {
        let hit = pairs.iter().find(|(known, _)| *known == name);
        hit.map(|(_, value)| OsString::from(value))
    }
}

#[test]
fn the_default_output_roots_are_watched_without_a_user_variable() {
    let user_root = |home: &str, user: &str| {
        let name = format!("_bazel_{user}");
        [
            Path::new(home).join(&name),
            Path::new("/private/var/tmp").join(&name),
            Path::new("/var/tmp").join(&name),
        ]
    };
    let unasked = || -> Option<String> { panic!("USER is set: the passwd entry is not read") };

    let named =
        isolation::locations(&env_of(&[("HOME", "/h"), ("USER", "alice")]), unasked, true).unwrap();
    for path in user_root("/h", "alice") {
        assert!(named.contains(&path), "{}: {named:?}", path.display());
    }
    assert!(named.contains(&Path::new("/h").join(".cache").join("bazel")));

    // A container sets HOME alone: Bazel then names its root from the
    // passwd entry, and so must the watch.
    let container = env_of(&[("HOME", "/root")]);
    let watched = isolation::locations(&container, || Some("root".into()), true).unwrap();
    for path in user_root("/root", "root") {
        assert!(watched.contains(&path), "{}: {watched:?}", path.display());
    }

    // LOGNAME can differ from the passwd name: both roots are watched.
    let login = env_of(&[("HOME", "/h"), ("LOGNAME", "bob")]);
    let both = isolation::locations(&login, || Some("builder".into()), true).unwrap();
    for path in user_root("/h", "bob")
        .iter()
        .chain(&user_root("/h", "builder"))
    {
        assert!(both.contains(path), "{}: {both:?}", path.display());
    }

    // No name at all. Where the default root carries the name (macOS,
    // Windows) the check would watch nothing: refused. On Linux the root
    // is under ~/.cache/bazel, which HOME already covers.
    let nameless = env_of(&[("HOME", "/h")]);
    let refused = isolation::locations(&nameless, || None, true).unwrap_err();
    assert!(refused.contains("USER"), "{refused}");
    let empty_name = isolation::locations(&nameless, || Some(String::new()), true);
    assert!(empty_name.is_err(), "an empty name is no name");
    let linux = isolation::locations(&nameless, || None, false).unwrap();
    assert!(linux.contains(&Path::new("/h").join(".cache").join("bazel")));
    let named_roots = |paths: &[PathBuf]| {
        let has = |p: &&PathBuf| p.to_string_lossy().contains("_bazel_");
        paths.iter().filter(has).count()
    };
    assert_eq!(named_roots(&linux), 0);
    assert_eq!(named_roots(&named), 3);

    // No home directory: nothing but the macOS root could be watched.
    let homeless = env_of(&[("USER", "alice"), ("XDG_CACHE_HOME", "/x")]);
    let refused = isolation::locations(&homeless, || None, false).unwrap_err();
    assert!(refused.contains("HOME"), "{refused}");
    let windows = env_of(&[("USERPROFILE", "/u"), ("USERNAME", "alice")]);
    let watched = isolation::locations(&windows, || None, true).unwrap();
    assert!(watched.contains(&Path::new("/u").join("_bazel_alice")));
}

#[cfg(unix)]
#[test]
fn the_passwd_entry_names_the_current_user() {
    let name = isolation::passwd_user_name().expect("`id -un` prints a name");
    assert!(
        !name.is_empty() && !name.contains(char::is_whitespace),
        "{name:?}"
    );
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
    let (head, body) = http_response(server, method, target, headers);
    (head.lines().next().unwrap().to_string(), body)
}

/// One request to the fixture server, as (response head, body).
fn http_response(
    server: &FixtureServer,
    method: &str,
    target: &str,
    headers: &str,
) -> (String, Vec<u8>) {
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
    (head, response[split + 4..].to_vec())
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
    assert_eq!(server.assert_requested(url, "twin").len(), 3);
    server.assert_no_header("Authorization", url, "no credential");
    assert!(
        panics(&|| server.assert_not_requested(url, "offline")),
        "a requested URL must fail the offline assertion"
    );

    http(&server, "GET", target, "Authorization: Bearer secret\r\n");
    assert!(
        panics(&|| server.assert_no_header("authorization", url, "no credential")),
        "a credential header must be seen"
    );
}

#[test]
fn the_offline_assertion_has_no_minimum_and_a_cold_one_needs_the_artifact() {
    let server = FixtureServer::start();
    let artifact = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
    let requested = || drop(server.assert_requested(artifact, "twin"));
    let no_credential = || server.assert_no_header("Authorization", artifact, "twin");

    // The offline phase runs on a warm cache, where a fully checksummed
    // fixture sends nothing: zero requests is its expected result.
    server.assert_not_requested(artifact, "offline");
    // The same silence proves nothing about what a fetch would send.
    assert!(panics(&requested), "nothing was requested");
    assert!(panics(&no_credential), "nothing was requested");

    // A cold cell always asks the server for registry files, also when the
    // artifact itself was never fetched. "Some request arrived" is not
    // "the artifact was requested".
    http(
        &server,
        "GET",
        "/bcr.bazel.build/modules/x/1.0/MODULE.bazel",
        "",
    );
    assert_eq!(server.hosts(), ["bcr.bazel.build"]);
    server.assert_not_requested(artifact, "offline");
    assert!(panics(&requested), "only the registry was asked");
    assert!(
        panics(&no_credential),
        "no Authorization on a registry read says nothing about the artifact fetch"
    );

    server.serve(artifact, b"tarball".to_vec());
    let target = "/registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
    http(&server, "GET", target, "");
    let hits = server.assert_requested(artifact, "twin");
    assert_eq!(
        hits.iter().map(|r| r.status).collect::<Vec<_>>(),
        [200],
        "the twin reads the status from what is returned"
    );
    no_credential();
    assert!(panics(&|| server.assert_not_requested(artifact, "offline")));

    // A credential on any request is a leak, not only on the artifact's.
    http(
        &server,
        "GET",
        "/bcr.bazel.build/modules/x/1.0/source.json",
        "Authorization: Basic eDp5\r\n",
    );
    assert!(panics(&no_credential), "a credential went to the registry");
}

#[test]
fn fixture_server_states_the_content_type_a_route_was_given() {
    let server = FixtureServer::start();
    // pip skips an index page that is not text/html or a PyPI simple type.
    let index = "https://pypi.org/simple/six/";
    server.serve_as(index, "text/html", "<a href=\"six.whl\">six.whl</a>");
    server.serve("https://files.pythonhosted.org/six.whl", b"wheel".to_vec());
    let content_type = |method: &str, target: &str| {
        let (head, body) = http_response(&server, method, target, "");
        let value = head
            .lines()
            .find_map(|line| line.strip_prefix("Content-Type: "));
        (value.map(str::to_string), body)
    };
    let page = b"<a href=\"six.whl\">six.whl</a>".to_vec();
    assert_eq!(
        content_type("GET", "/pypi.org/simple/six/"),
        (Some("text/html".into()), page)
    );
    assert_eq!(
        content_type("HEAD", "/pypi.org/simple/six/"),
        (Some("text/html".into()), Vec::new())
    );
    let octets = Some("application/octet-stream".to_string());
    assert_eq!(
        content_type("GET", "/files.pythonhosted.org/six.whl"),
        (octets.clone(), b"wheel".to_vec())
    );
    assert_eq!(
        content_type("GET", "/pypi.org/simple/absent/"),
        (octets, Vec::new())
    );
    // A later registration replaces the route, type included.
    server.serve_as(index, "application/vnd.pypi.simple.v1+json", "{}");
    assert_eq!(
        content_type("GET", "/pypi.org/simple/six/"),
        (
            Some("application/vnd.pypi.simple.v1+json".into()),
            b"{}".to_vec()
        )
    );
    // A value that would end the header block is refused.
    assert!(panics(&|| server.serve_as(
        index,
        "text/html\r\nX-Injected: 1",
        ""
    )));
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

#[test]
fn a_report_an_earlier_run_left_is_discarded() {
    let dir = tempfile::tempdir().unwrap();
    let mut report = Report::new("bazel_core_launch_isolated");
    report.bazel = Some("9.3.2".into());
    // Nothing there yet: not an error.
    report.discard_in(dir.path());

    // An earlier run of this cell passed...
    let earlier = report.write_in(dir.path(), Status::Ran, None);
    assert_eq!(earlier, report.path_in(dir.path()));
    let text = std::fs::read_to_string(&earlier).unwrap();
    assert!(text.contains(r#""status": "ran""#), "{text}");
    // ...and so did another cell of the same test, on another Bazel.
    let mut other_cell = report.clone();
    other_cell.bazel = Some("7.7.2".into());
    let other = other_cell.write_in(dir.path(), Status::Ran, None);

    // This run of the cell has not finished: if it now fails, nothing on
    // disk may still say `ran` for it.
    report.discard_in(dir.path());
    assert!(!earlier.exists(), "the earlier `ran` report survived");
    assert!(other.exists(), "another cell's report is not this run's");
}

#[test]
fn opening_a_cell_discards_the_report_an_earlier_run_of_it_left() {
    const TEST: &str = "harness_selftest_stale_report";
    // What an earlier run of the cell left in the probe directory. Status
    // `skipped`, so the selftest itself never puts a `ran` report there.
    let mut earlier = Report::new(TEST);
    earlier.bazel = Some(NO_RELEASE.into());
    let why = Some("selftest: stands in for an earlier run");
    let stale = earlier.write_in(&probe_report::probe_dir(), Status::Skipped, why);

    let cell = selftest_cell(TEST, no_bazel);
    assert_eq!(cell.report.path(), stale, "the cell reports to that file");
    assert!(
        !stale.exists(),
        "an earlier report of the cell survived Cell::open: a failing run would keep it"
    );
    cell.close();
}

#[test]
fn a_required_cell_never_skips() {
    assert_eq!(
        probe_report::may_skip("bazel_core_x", "no Bazel", false),
        Ok(())
    );
    let failure = probe_report::may_skip("bazel_core_x", "no Bazel", true).unwrap_err();
    assert!(
        failure.contains("bazel_core_x")
            && failure.contains(env::REQUIRED)
            && failure.contains("no Bazel"),
        "{failure}"
    );
}

#[test]
fn an_unknown_group_or_system_is_an_error_not_every_cell() {
    assert_eq!(env::parse_group(None), Ok(None));
    assert_eq!(env::parse_system(None), Ok(None));
    for group in [Group::Core, Group::Light, Group::Heavy] {
        assert_eq!(env::parse_group(Some(group.name())), Ok(Some(group)));
    }
    for system in [System::Bzlmod, System::Workspace, System::Hybrid] {
        assert_eq!(env::parse_system(Some(system.name())), Ok(Some(system)));
    }
    // A typo in a CI cell must not select "everything" (or nothing).
    for typo in ["Core", "cores", "light ", "all", "bzlmod"] {
        let refused = env::parse_group(Some(typo)).unwrap_err();
        assert!(
            refused.contains(env::GROUP) && refused.contains(typo),
            "{refused}"
        );
    }
    for typo in ["Bzlmod", "bazelmod", "WORKSPACE", "both", "core"] {
        let refused = env::parse_system(Some(typo)).unwrap_err();
        assert!(
            refused.contains(env::SYSTEM) && refused.contains(typo),
            "{refused}"
        );
    }
}

#[test]
fn a_plain_write_never_reaches_the_module_lock_or_leaves_the_workspace() {
    for rel in [
        "MODULE.bazel",
        "BUILD.bazel",
        "pkg/BUILD.bazel",
        "./WORKSPACE",
        "MODULE.bazel.lock.bak",
        "locks/maven_install.json",
    ] {
        assert_eq!(workspace::check_plain_write(rel), Ok(()), "{rel}");
    }
    // Bazel owns the lock: only write_module_lock, which stops the server
    // first, may write it. macOS and Windows fold the case.
    for rel in [
        "MODULE.bazel.lock",
        "./MODULE.bazel.lock",
        "sub/MODULE.bazel.lock",
        "module.bazel.LOCK",
    ] {
        let refused = workspace::check_plain_write(rel).unwrap_err();
        assert!(refused.contains("write_module_lock"), "{rel}: {refused}");
    }
    for rel in [
        "",
        ".",
        "..",
        "../outside",
        "pkg/../../outside",
        "/etc/passwd",
    ] {
        let refused = workspace::check_plain_write(rel).unwrap_err();
        assert!(
            refused.contains("inside the workspace copy"),
            "{rel}: {refused}"
        );
    }
}

#[test]
fn a_mod_command_keeps_lock_rule_three() {
    let check = workspace::check_mod_command;
    // The two subcommands that write choose their mode, but for the one
    // mode that is no oracle.
    assert_eq!(check(&["deps"], "update"), Ok(()));
    assert_eq!(check(&["deps"], "refresh"), Ok(()));
    assert_eq!(check(&["tidy"], "update"), Ok(()));
    for args in [&["deps"][..], &["--enable_bzlmod", "deps"]] {
        let refused = check(args, "error").unwrap_err();
        assert!(refused.contains("error_mode_build"), "{refused}");
    }
    // An explicit mode among the arguments follows the cell's own on the
    // command line and wins there: it decides here too.
    let stated = check(&["deps", "--lockfile_mode=error"], "update").unwrap_err();
    assert!(stated.contains("error_mode_build"), "{stated}");
    assert_eq!(check(&["deps", "--lockfile_mode=update"], "error"), Ok(()));

    // Every subcommand that only asks runs with the lock off.
    for oracle in [
        "graph",
        "show_repo",
        "show_extension",
        "all_paths",
        "path",
        "explain",
        "dump_repo_mapping",
    ] {
        assert_eq!(check(&[oracle, "--output=json"], "off"), Ok(()), "{oracle}");
        for mode in ["update", "refresh", "error"] {
            let refused = check(&[oracle], mode).unwrap_err();
            assert!(
                refused.contains("mod_oracle") && refused.contains(oracle),
                "{oracle} {mode}: {refused}"
            );
        }
        assert_eq!(check(&["--lockfile_mode=off", oracle], "update"), Ok(()));
        assert!(check(&[oracle, "--lockfile_mode=update"], "off").is_err());
    }
    // No subcommand at all is Bazel's error to report, with the lock off.
    assert_eq!(check(&[], "off"), Ok(()));
    assert!(check(&[], "update").is_err());
}

/// A stand-in Bazel of a version no release has, on a line that knows
/// `--lockfile_mode`: for what a cell does per line without a server.
fn lockfile_line(_: &Scratch) -> Result<Bazel, String> {
    Ok(Bazel {
        version: version("99.0.0"),
        ..stand_in("socket-patch-selftest-no-such-bazel")?
    })
}

#[test]
fn a_cell_refuses_a_mod_command_that_breaks_lock_rule_three() {
    let cell = selftest_cell("harness_selftest_mod_commands", lockfile_line);
    let with = |mode: &'static str| Options {
        lockfile_mode: mode,
        ..cell.options.clone()
    };
    let argv = |options: &Options, args: &[&str]| -> Vec<String> {
        let cmd = cell.command_with(options, "mod", args);
        cmd.get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    };
    // What mod_oracle and baseline build.
    let oracle = argv(&with("off"), &["graph", "--output=json"]);
    assert!(
        oracle.contains(&"--lockfile_mode=off".to_string()),
        "{oracle:?}"
    );
    let deps = argv(&with("update"), &["deps"]);
    assert!(
        deps.contains(&"--lockfile_mode=update".to_string()),
        "{deps:?}"
    );

    // The cell's default mode is `update`: an oracle asked through the
    // plain helpers would rewrite the lock under test.
    assert!(panics(&|| drop(argv(&cell.options, &["graph"]))));
    assert!(panics(&|| drop(argv(
        &with("update"),
        &["show_repo", "@toy"]
    ))));
    assert!(panics(&|| drop(argv(&with("error"), &["deps"]))));
    assert!(panics(&|| drop(argv(
        &with("update"),
        &["deps", "--lockfile_mode=error"]
    ))));
    // Only `mod` is looked at: an `error`-mode build is the oracle itself.
    let build = cell.command_with(&with("error"), "build", &["//:socket_probe"]);
    assert!(build.get_args().any(|arg| arg == "--lockfile_mode=error"));
    cell.close();

    // A line without `--lockfile_mode` has no rule to keep (and no `mod`).
    let old = selftest_cell("harness_selftest_mod_commands_old_line", no_bazel);
    assert!(!old.bazel.version.has_lockfile_mode());
    drop(old.command_with(&old.options, "mod", &["graph"]));
    old.close();
}

#[test]
fn the_probe_rule_is_installed_once_and_never_over_a_fixtures_own() {
    let ws = tempfile::tempdir().unwrap();
    assert_eq!(workspace::install_probe_rule(ws.path()), Ok(()));
    let shared = workspace::fixtures_root()
        .join("common")
        .join(workspace::PROBE_BZL);
    let installed = ws.path().join(workspace::PROBE_BZL);
    assert_eq!(
        std::fs::read(&installed).unwrap(),
        std::fs::read(shared).unwrap()
    );
    let again = workspace::install_probe_rule(ws.path()).unwrap_err();
    assert!(again.contains("already has a probe.bzl"), "{again}");

    // A fixture that ships its own rule keeps its bytes and is refused.
    let fixture = tempfile::tempdir().unwrap();
    std::fs::write(fixture.path().join(workspace::PROBE_BZL), "# unreviewed\n").unwrap();
    assert!(workspace::install_probe_rule(fixture.path()).is_err());
    assert_eq!(
        std::fs::read(fixture.path().join(workspace::PROBE_BZL)).unwrap(),
        b"# unreviewed\n"
    );
}

#[test]
fn a_cell_keeps_the_lock_rules_without_a_server() {
    let cell = selftest_cell("harness_selftest_lock_rules", no_bazel);
    cell.write("MODULE.bazel", "module(name = \"selftest\")\n");
    cell.write("pkg/BUILD.bazel", "");
    assert!(cell.scratch.workspace.join("pkg/BUILD.bazel").is_file());
    assert_eq!(cell.module_lock(), None);
    assert!(
        panics(&|| cell.write(workspace::MODULE_LOCK, "{}")),
        "Cell::write must refuse MODULE.bazel.lock"
    );
    assert!(panics(&|| cell.write("../escaped", "")));
    assert_eq!(cell.module_lock(), None, "the refused write wrote nothing");
    assert!(!cell.scratch.root.join("escaped").exists());

    // No server runs, so the lock write needs no shutdown (the stand-in
    // program does not exist: a spawn would panic here).
    assert_eq!(cell.server_pid(), None);
    cell.write_module_lock(b"{\"lockFileVersion\": 0}\n");
    assert_eq!(
        cell.module_lock().as_deref(),
        Some(&b"{\"lockFileVersion\": 0}\n"[..])
    );

    cell.install_probe_rule();
    assert!(
        panics(&|| cell.install_probe_rule()),
        "a second probe.bzl must be refused"
    );
    cell.close();
}

#[test]
fn a_program_named_by_a_relative_path_is_made_absolute() {
    // A bare name is resolved on PATH by the spawn itself.
    assert_eq!(absolute_program("bazel".into()), OsString::from("bazel"));
    assert_eq!(
        absolute_program("bazel.exe".into()),
        OsString::from("bazel.exe")
    );
    // A relative path answers `--version` from the test's directory and
    // then fails to spawn from the workspace copy.
    let cwd = std::env::current_dir().unwrap();
    let nested = PathBuf::from(absolute_program("tools/bazel".into()));
    assert_eq!(nested, cwd.join("tools").join("bazel"));
    for relative in ["./bazel", "../../../../.bazel/tools/bazel"] {
        let made = PathBuf::from(absolute_program(relative.into()));
        assert!(made.is_absolute(), "{relative} became {}", made.display());
        assert_eq!(made.file_name(), Some("bazel".as_ref()), "{relative}");
    }
    let absolute = cwd.join("bazel").into_os_string();
    assert_eq!(absolute_program(absolute.clone()), absolute);
}

#[test]
fn a_program_is_bazelisk_by_its_file_name_links_followed() {
    let dir = tempfile::tempdir().unwrap();
    let file = |name: &str| {
        let path = dir.path().join(name);
        std::fs::write(&path, "").unwrap();
        path
    };
    // What the installer writes, and what a release is called.
    let pinned = file("bazelisk-v1.30.0-darwin-arm64");
    assert!(named_bazelisk(&pinned));
    assert!(named_bazelisk(&file("Bazelisk.exe")));
    // A Bazel release binary, and a wrapper script that contains its own
    // bazelisk home: neither gets a scratch BAZELISK_HOME forced on it.
    assert!(!named_bazelisk(&file("bazel-9.3.2-darwin-arm64")));
    let wrapper = dir.path().join("tools");
    std::fs::create_dir(&wrapper).unwrap();
    std::fs::write(wrapper.join("bazel"), "#!/bin/sh\n").unwrap();
    assert!(!named_bazelisk(&wrapper.join("bazel")));
    // A name that is not on disk is judged as written.
    assert!(named_bazelisk(Path::new("bazelisk")));
    assert!(!named_bazelisk(Path::new("bazel")));
    // Homebrew installs `bazel` as a link to bazelisk.
    #[cfg(unix)]
    {
        let link = dir.path().join("bazel");
        std::os::unix::fs::symlink(&pinned, &link).unwrap();
        assert!(named_bazelisk(&link));
    }
}

#[test]
fn a_dead_servers_pid_file_is_stale_and_a_live_servers_is_an_error() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("0123abcd/server/server.pid.txt");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, "4242\n").unwrap();
    // The install base and an output base that never had a server.
    std::fs::create_dir_all(root.path().join("install")).unwrap();
    std::fs::create_dir_all(root.path().join("89abcdef/server")).unwrap();
    assert_eq!(server::pid_files(root.path()), [(file.clone(), 4242)]);

    // The server still runs: `bazel shutdown` did not do its work.
    let running = server::settle_pid_files(root.path(), |pid| pid == 4242).unwrap_err();
    assert!(
        running.contains("server 4242 is still running"),
        "{running}"
    );
    assert!(file.exists(), "a live server's pid file is left alone");

    // The server was killed or crashed: nothing removed its file, and the
    // client's `shutdown` returned at once. Not a leak, and not an error.
    assert_eq!(server::settle_pid_files(root.path(), |_| false), Ok(()));
    assert!(!file.exists(), "the stale pid file was not removed");
    assert_eq!(server::pid_files(root.path()), []);
    let unasked = |_: u32| -> bool { panic!("no pid file is left to ask about") };
    assert_eq!(server::settle_pid_files(root.path(), unasked), Ok(()));
}

/// The pid of a process that has exited and been reaped.
fn exited_pid() -> u32 {
    let (program, args): (&str, &[&str]) = if cfg!(windows) {
        ("cmd", &["/C", "exit 0"])
    } else {
        ("sh", &["-c", "exit 0"])
    };
    let mut child = hermetic::command(Path::new(program))
        .args(args)
        .spawn()
        .expect("spawn a short-lived child");
    let pid = child.id();
    child.wait().expect("wait for the child");
    pid
}

#[test]
fn process_liveness_tells_this_process_from_one_that_exited() {
    assert!(server::process_alive(std::process::id()));
    assert!(!server::process_alive(exited_pid()));
}

#[cfg(unix)]
fn true_for_bazel(_: &Scratch) -> Result<Bazel, String> {
    // `true` exits 0 whatever its arguments: what `bazel shutdown` does
    // when no server answers.
    stand_in("true")
}

#[cfg(unix)]
#[test]
fn shutdown_clears_the_pid_file_of_a_server_that_died() {
    let cell = selftest_cell("harness_selftest_dead_server", true_for_bazel);
    // A server that was killed: its pid file is there, its process is not.
    let pid = exited_pid();
    let file = cell
        .scratch
        .output_user_root
        .join("0123abcd/server/server.pid.txt");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, pid.to_string()).unwrap();
    assert_eq!(cell.server_pid(), Some(pid));

    cell.shutdown();
    assert_eq!(cell.server_pid(), None);
    assert!(!file.exists(), "the stale pid file was not removed");
    // `close` shuts down again and asserts the scratch root is removed.
    cell.close();
}
