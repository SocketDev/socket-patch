//! `--patch-mirror-url`: the parts of hosted mode through a patch-server
//! mirror that a live mirror cannot show.
//!
//! The proof that a mirrored project installs is
//! `e2e_artifactory_mirror.rs`, which drives a real Artifactory, the
//! production patch API and the real package managers. This file holds
//! only what needs both ends of a conversation observed, or an answer a
//! healthy mirror never gives:
//!
//! * the run's own downloads go to the patch server, never to the mirror;
//! * the operator's mirror credential reaches the mirror and nothing else;
//! * what the run does with each answer to its check of the mirror (a
//!   redirect, a miss for one patch, a miss for every patch, no answer);
//! * a base that cannot prefix a committed URL is refused before the
//!   project is read;
//! * the everyday shape (pin the mirror, re-run, a run without the mirror
//!   leaves the pin alone), so the merge queue sees a regression without
//!   an Artifactory.
//!
//! Two wiremock servers stand in: one is the Socket API and the patch
//! server (the grants name its own origin), the other the mirror.

#[path = "common/envelope.rs"]
mod envelope;
#[path = "common/hermetic.rs"]
mod hermetic;

use std::path::Path;

use envelope::warning_codes;

use serial_test::serial;
use wiremock::matchers::{header, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const VERSION: &str = "1.0.0";
const TOKEN: &str = "22222222-2222-4222-8222-222222222222";
/// Where the mock mirror sits on its server: an Artifactory repository path.
const MIRROR_PREFIX: &str = "/artifactory/socket-patch";

/// One patched package of a fixture project.
#[derive(Clone, Copy)]
struct Pkg {
    name: &'static str,
    uuid: &'static str,
    version: &'static str,
}

const FIRST: Pkg = Pkg {
    name: "mirror-fixture",
    uuid: "11111111-1111-4111-8111-111111111111",
    version: VERSION,
};
const SECOND: Pkg = Pkg {
    name: "other-fixture",
    uuid: "33333333-3333-4333-8333-333333333333",
    version: VERSION,
};
/// The registry package the Bun fixture locks
/// (`socket-patch-core/tests/fixtures/bun-lockb/1.4.2`).
const BUN: Pkg = Pkg {
    name: "is-number",
    uuid: "44444444-4444-4444-8444-444444444444",
    version: "7.0.0",
};

impl Pkg {
    fn purl(&self) -> String {
        format!("pkg:npm/{}@{}", self.name, self.version)
    }

    /// The path the patch server serves the patched tarball at, and so the
    /// path under the mirror's base.
    fn served_path(&self) -> String {
        format!(
            "/patch/npm/{0}/{2}/{TOKEN}/{1}/{0}-{2}.tgz",
            self.name, self.uuid, self.version
        )
    }

    /// The patched tarball: a `package.json` and a marked `index.js`.
    fn tarball(&self) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (name, body) in [
            (
                "package/package.json",
                format!(r#"{{"name":"{}","version":"{}"}}"#, self.name, self.version),
            ),
            (
                "package/index.js",
                "/* patched */\nmodule.exports = 1;\n".to_string(),
            ),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, name, body.as_bytes())
                .unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn sha512(&self) -> String {
        use base64::Engine as _;
        use sha2::Digest as _;
        format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(self.tarball()))
        )
    }
}

fn mirror_base(mirror: &MockServer) -> String {
    format!("{}{MIRROR_PREFIX}", mirror.uri())
}

fn mirrored_url(mirror: &MockServer, pkg: Pkg) -> String {
    format!("{}{}", mirror_base(mirror), pkg.served_path())
}

/// The Socket API and the patch server on one origin: discovery, the
/// reference grants (which name this server), and each patched tarball at
/// its served path.
async fn mock_socket(server: &MockServer, pkgs: &[Pkg]) {
    let packages: Vec<serde_json::Value> = pkgs
        .iter()
        .map(|pkg| {
            serde_json::json!({
                "purl": pkg.purl(),
                "patches": [{
                    "uuid": pkg.uuid, "purl": pkg.purl(), "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "mirror fixture"
                }]
            })
        })
        .collect();
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": packages,
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    let mut results = serde_json::Map::new();
    for pkg in pkgs {
        let served = format!("{}{}", server.uri(), pkg.served_path());
        Mock::given(method("GET"))
            .and(path_regex(format!(
                "^/v0/orgs/{ORG}/patches/by-package/.*{}.*$",
                pkg.name
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "patches": [{
                    "uuid": pkg.uuid, "purl": pkg.purl(),
                    "publishedAt": "2024-01-01T00:00:00Z",
                    "description": "x", "license": "MIT", "tier": "free",
                    "vulnerabilities": {}
                }],
                "canAccessPaidPatches": false,
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(pkg.served_path()))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(pkg.tarball(), "application/octet-stream"),
            )
            .mount(server)
            .await;
        results.insert(
            pkg.uuid.to_string(),
            serde_json::json!({
                "status": "granted",
                "url": served,
                "purl": pkg.purl(),
                "artifacts": [{
                    "kind": "tarball",
                    "url": served,
                    "integrity": { "sha512": pkg.sha512() }
                }],
                "registryOverride": null
            }),
        );
    }
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "results": results })),
        )
        .mount(server)
        .await;
}

/// The mirror answering the run's check of `pkg` with `status`.
async fn mirror_answers(mirror: &MockServer, pkg: Pkg, status: u16) {
    Mock::given(method("HEAD"))
        .and(path(format!("{MIRROR_PREFIX}{}", pkg.served_path())))
        .respond_with(ResponseTemplate::new(status))
        .mount(mirror)
        .await;
}

/// An npm project that locks `pkgs` from the registry.
fn write_npm_project(root: &Path, pkgs: &[Pkg]) {
    let deps: Vec<String> = pkgs
        .iter()
        .map(|pkg| format!(r#""{}": "{VERSION}""#, pkg.name))
        .collect();
    let deps = deps.join(", ");
    std::fs::write(
        root.join("package.json"),
        format!(r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ {deps} }} }}"#),
    )
    .unwrap();
    let entries: Vec<String> = pkgs
        .iter()
        .map(|pkg| {
            format!(
                r#"    "node_modules/{0}": {{
      "version": "{VERSION}",
      "resolved": "https://registry.npmjs.org/{0}/-/{0}-{VERSION}.tgz",
      "integrity": "sha512-UPSTREAM{0}=="
    }}"#,
                pkg.name
            )
        })
        .collect();
    std::fs::write(
        root.join("package-lock.json"),
        format!(
            r#"{{
  "name": "consumer",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {{
    "": {{ "name": "consumer", "version": "0.0.0", "dependencies": {{ {deps} }} }},
{}
  }}
}}
"#,
            entries.join(",\n")
        ),
    )
    .unwrap();
}

fn lock(root: &Path) -> String {
    std::fs::read_to_string(root.join("package-lock.json")).unwrap()
}

/// The binary, hermetic, with no ambient mirror settings.
fn cli() -> std::process::Command {
    let mut cmd = hermetic::binary_command();
    cmd.env_remove("SOCKET_PATCH_MIRROR_URL")
        .env_remove("SOCKET_PATCH_MIRROR_AUTHORIZATION");
    cmd
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Run {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "stdout is not JSON: {e}\nstdout:\n{}\nstderr:\n{}",
                self.stdout, self.stderr
            )
        })
    }
}

fn run(mut cmd: std::process::Command) -> Run {
    let out = cmd.output().expect("run socket-patch");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// `scan --mode hosted --json` against `api`, with `extra` flags; the run
/// must exit 0.
fn hosted_scan(cwd: &Path, api: &MockServer, extra: &[&str], env: &[(&str, &str)]) -> Run {
    let mut cmd = cli();
    cmd.args([
        "scan",
        "--mode=hosted",
        "--json",
        "--yes",
        "--cwd",
        cwd.to_str().unwrap(),
        "--api-url",
        &api.uri(),
        "--org",
        ORG,
        "--api-token",
        "fake",
    ])
    .args(extra);
    for (key, value) in env {
        cmd.env(key, value);
    }
    let out = run(cmd);
    assert_eq!(out.code, Some(0), "{}\n{}", out.stdout, out.stderr);
    out
}

/// `(action, errorCode)` of the run's event for `pkg`.
fn event(env: &serde_json::Value, pkg: Pkg) -> (String, Option<String>) {
    let events = env["events"]
        .as_array()
        .unwrap_or_else(|| panic!("{env:#}"));
    let event = events
        .iter()
        .find(|e| e["uuid"] == pkg.uuid)
        .unwrap_or_else(|| panic!("no event for {}: {env:#}", pkg.name));
    (
        event["action"].as_str().unwrap_or_default().to_string(),
        event["errorCode"].as_str().map(str::to_string),
    )
}

fn applied() -> (String, Option<String>) {
    ("applied".to_string(), None)
}

fn skipped(code: &str) -> (String, Option<String>) {
    ("skipped".to_string(), Some(code.to_string()))
}

/// The requests `server` received, as `METHOD path`.
async fn requests(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .map(|r| format!("{} {}", r.method, r.url.path()))
        .collect()
}

/// The everyday shape: a run given a mirror pins the mirror's URL with the
/// patched integrity after asking the mirror once, a re-run asks nothing
/// and changes nothing, the environment variable is the flag, `list` reads
/// the pin only when given the mirror, and a run that was not given the
/// mirror leaves the pin alone and names the host to configure.
#[tokio::test]
#[serial]
async fn a_run_pins_the_mirror_and_a_run_without_it_leaves_the_pin_alone() {
    let api = MockServer::start().await;
    mock_socket(&api, &[FIRST]).await;
    let mirror = MockServer::start().await;
    mirror_answers(&mirror, FIRST, 200).await;
    let base = mirror_base(&mirror);
    let check = format!("HEAD {MIRROR_PREFIX}{}", FIRST.served_path());

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), &[FIRST]);

    let first = hosted_scan(tmp.path(), &api, &["--patch-mirror-url", &base], &[]);
    let env = first.json();
    assert_eq!(event(&env, FIRST), applied(), "{env:#}");
    assert!(
        !warning_codes(&env).iter().any(|c| c.contains("mirror")),
        "a mirror that serves the patch raises no mirror warning: {env:#}"
    );
    let pinned = lock(tmp.path());
    assert!(pinned.contains(&mirrored_url(&mirror, FIRST)), "{pinned}");
    assert!(pinned.contains(&FIRST.sha512()), "{pinned}");
    assert!(
        !pinned.contains(&api.uri()) && !pinned.contains("UPSTREAM"),
        "neither the patch server's origin nor the upstream entry is left: {pinned}"
    );
    assert_eq!(
        requests(&mirror).await,
        vec![check.clone()],
        "the run asks the mirror once, before writing, and downloads nothing from it"
    );

    // A re-run finds its own pin: same lock, and nothing more to ask.
    let again = hosted_scan(tmp.path(), &api, &["--patch-mirror-url", &base], &[]);
    assert_eq!(event(&again.json(), FIRST), applied(), "{}", again.stdout);
    assert_eq!(
        lock(tmp.path()),
        pinned,
        "a re-run leaves the lock as it is"
    );
    assert_eq!(
        requests(&mirror).await,
        vec![check.clone()],
        "a pin the project already holds is not asked about again"
    );

    // The environment variable is the flag, on a project of its own.
    let fresh = tempfile::tempdir().unwrap();
    write_npm_project(fresh.path(), &[FIRST]);
    let by_env = hosted_scan(
        fresh.path(),
        &api,
        &[],
        &[("SOCKET_PATCH_MIRROR_URL", &format!("{base}/"))],
    );
    assert_eq!(event(&by_env.json(), FIRST), applied(), "{}", by_env.stdout);
    assert_eq!(lock(fresh.path()), pinned, "the same pin as the flag wrote");

    // `list` reads the pin with the mirror, and nothing without it.
    let list = |extra: &[&str]| {
        let mut cmd = cli();
        cmd.args(["list", "--json", "--cwd", tmp.path().to_str().unwrap()])
            .args(extra);
        let out = run(cmd);
        assert_eq!(out.code, Some(0), "{}\n{}", out.stdout, out.stderr);
        out.stdout
    };
    assert!(list(&["--patch-mirror-url", &base]).contains(FIRST.uuid));
    assert!(
        !list(&[]).contains(FIRST.uuid),
        "a host the run was not given is no patch host"
    );
    // The mirror is its base, not its host: another repository of the same
    // host is not where the patch server is mirrored.
    let sibling = format!("{}/artifactory/team-local", mirror.uri());
    assert_ne!(sibling, base);
    assert!(
        !list(&["--patch-mirror-url", &sibling]).contains(FIRST.uuid),
        "a pin under another base of the mirror's host is no hosted pin"
    );

    // A run without the mirror: nothing moves onto the patch server.
    let bare = hosted_scan(tmp.path(), &api, &[], &[]);
    let env = bare.json();
    assert_eq!(
        event(&env, FIRST),
        skipped("redirect_pin_on_unconfigured_host"),
        "{env:#}"
    );
    let host = mirror.uri().trim_start_matches("http://").to_string();
    assert!(
        bare.stdout.contains(&host) && bare.stdout.contains("--patch-mirror-url"),
        "the warning names the host and the setting: {}",
        bare.stdout
    );
    assert_eq!(lock(tmp.path()), pinned, "the mirrored pin is untouched");
}

/// A Bun project that locks [`BUN`] from the registry, in a text `bun.lock`
/// or a binary `bun.lockb`.
fn write_bun_project(root: &Path, lock: &str) {
    std::fs::write(
        root.join("package.json"),
        include_bytes!("../../socket-patch-core/tests/fixtures/bun-lockb/1.4.2/package.json"),
    )
    .unwrap();
    if lock == "bun.lockb" {
        std::fs::write(
            root.join(lock),
            include_bytes!("../../socket-patch-core/tests/fixtures/bun-lockb/1.4.2/bun.lockb"),
        )
        .unwrap();
        return;
    }
    std::fs::write(
        root.join(lock),
        format!(
            "{{\n  \"lockfileVersion\": 1,\n  \"packages\": {{\n    \
             \"{0}\": [\"{0}@{1}\", \"\", {{}}, \"sha512-UPSTREAMupstream==\"],\n  \
             }}\n}}\n",
            BUN.name, BUN.version
        ),
    )
    .unwrap();
}

/// #2279: a Bun project an earlier run pinned directly on the patch server,
/// in a run given a mirror. Neither Bun rewriter moves that pin in place,
/// so it is left as it is and the run says which file holds it, on which
/// host, and how to get it onto the mirror; for `bun.lockb`, whose pin
/// `rollback` refuses, not by way of `rollback`. The pinned copy is the
/// patched one: nothing calls it a user's tarball or unpatched.
#[tokio::test]
#[serial]
async fn a_bun_pin_on_the_patch_server_is_named_and_not_called_unpatched() {
    for lock in ["bun.lock", "bun.lockb"] {
        let api = MockServer::start().await;
        mock_socket(&api, &[BUN]).await;
        let mirror = MockServer::start().await;
        mirror_answers(&mirror, BUN, 200).await;
        let base = mirror_base(&mirror);
        let tmp = tempfile::tempdir().unwrap();
        write_bun_project(tmp.path(), lock);
        let holds = |needle: &str| {
            let bytes = std::fs::read(tmp.path().join(lock)).unwrap();
            bytes.windows(needle.len()).any(|w| w == needle.as_bytes())
        };

        let direct = hosted_scan(tmp.path(), &api, &[], &[]);
        assert_eq!(
            event(&direct.json(), BUN),
            applied(),
            "{lock}: {}",
            direct.stdout
        );
        let served = format!("{}{}", api.uri(), BUN.served_path());
        assert!(
            holds(&served),
            "{lock}: the first run pins the patch server"
        );
        let pinned = std::fs::read(tmp.path().join(lock)).unwrap();

        let moved = hosted_scan(tmp.path(), &api, &["--patch-mirror-url", &base], &[]);
        let env = moved.json();
        assert_eq!(
            event(&env, BUN),
            skipped("redirect_unconfirmed"),
            "{lock}: {env:#}"
        );
        let codes = warning_codes(&env);
        assert!(
            codes.contains(&"redirect_mirror_pin_not_moved".to_string()),
            "{lock}: {env:#}"
        );
        assert!(
            !codes.contains(&"redirect_bun_non_registry_entry_skipped".to_string())
                && !moved.stdout.contains("UNPATCHED"),
            "{lock}: the earlier pin is the patched copy, not a user's tarball: {env:#}"
        );
        let host = api.uri().trim_start_matches("http://").to_string();
        let not_moved = env["warnings"]
            .as_array()
            .and_then(|warnings| {
                warnings
                    .iter()
                    .find(|w| w["code"] == "redirect_mirror_pin_not_moved")
            })
            .map(|w| w.to_string())
            .unwrap_or_default();
        assert!(
            not_moved.contains(lock) && not_moved.contains(&host) && not_moved.contains(&base),
            "{lock}: the warning names the file, the host and the mirror: {not_moved}"
        );
        // `rollback` restores a bun.lock pin and refuses a bun.lockb one.
        assert_eq!(
            not_moved.contains(&format!("run `socket-patch rollback {}`", BUN.purl())),
            lock == "bun.lock",
            "{lock}: {not_moved}"
        );
        if lock == "bun.lockb" {
            assert!(not_moved.contains("version control"), "{not_moved}");
        }
        assert_eq!(
            std::fs::read(tmp.path().join(lock)).unwrap(),
            pinned,
            "{lock}: the pin is left as it is"
        );
    }
}

/// #2279: the earlier pin is named even when the run pins another copy of
/// the package on the mirror: the lock still fetches the first copy from
/// the patch server, which a build that reaches only the mirror cannot.
#[tokio::test]
#[serial]
async fn a_bun_pin_left_beside_a_copy_moved_to_the_mirror_is_named() {
    let api = MockServer::start().await;
    mock_socket(&api, &[BUN]).await;
    let mirror = MockServer::start().await;
    mirror_answers(&mirror, BUN, 200).await;
    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path(), "bun.lock");
    hosted_scan(tmp.path(), &api, &[], &[]);
    // A later install adds a nested copy from the registry.
    let lock = tmp.path().join("bun.lock");
    let pinned = std::fs::read_to_string(&lock).unwrap();
    let nested = format!(
        "    \"is-odd/{0}\": [\"{0}@{1}\", \"\", {{}}, \"sha512-UPSTREAMupstream==\"],\n  }}\n}}\n",
        BUN.name, BUN.version
    );
    let grown = pinned.replacen("  }\n}\n", &nested, 1);
    assert_ne!(grown, pinned, "{pinned}");
    std::fs::write(&lock, &grown).unwrap();

    let moved = hosted_scan(
        tmp.path(),
        &api,
        &["--patch-mirror-url", &mirror_base(&mirror)],
        &[],
    );
    let env = moved.json();
    let after = std::fs::read_to_string(&lock).unwrap();
    assert!(
        after.contains(&mirrored_url(&mirror, BUN)),
        "the registry copy is pinned on the mirror: {after}"
    );
    assert!(
        after.contains(&format!("{}{}", api.uri(), BUN.served_path())),
        "the earlier pin is left as it is: {after}"
    );
    let codes = warning_codes(&env);
    assert!(
        codes.contains(&"redirect_mirror_pin_not_moved".to_string())
            && !codes.contains(&"redirect_bun_non_registry_entry_skipped".to_string()),
        "{env:#}"
    );
}

/// The earlier pin is taken for the patched copy only on a patch server of
/// this run. The same `bun.lockb` in a run whose patch server is another
/// host holds a URL nobody vouches for: it stays a user's tarball, reported
/// unpatched, and no mirror warning speaks of it.
#[tokio::test]
#[serial]
async fn a_bun_pin_on_a_host_the_run_does_not_know_stays_a_user_tarball() {
    let earlier = MockServer::start().await;
    mock_socket(&earlier, &[BUN]).await;
    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path(), "bun.lockb");
    hosted_scan(tmp.path(), &earlier, &[], &[]);
    let pinned = std::fs::read(tmp.path().join("bun.lockb")).unwrap();

    let api = MockServer::start().await;
    mock_socket(&api, &[BUN]).await;
    let mirror = MockServer::start().await;
    mirror_answers(&mirror, BUN, 200).await;
    let moved = hosted_scan(
        tmp.path(),
        &api,
        &["--patch-mirror-url", &mirror_base(&mirror)],
        &[],
    );
    let env = moved.json();
    let codes = warning_codes(&env);
    assert!(
        codes.contains(&"redirect_bun_non_registry_entry_skipped".to_string())
            && !codes.contains(&"redirect_mirror_pin_not_moved".to_string()),
        "{env:#}"
    );
    assert_ne!(event(&env, BUN), applied(), "{env:#}");
    assert_eq!(
        std::fs::read(tmp.path().join("bun.lockb")).unwrap(),
        pinned,
        "nothing is written"
    );
}

/// What the run needs for itself it downloads from the patch server, not
/// from the mirror, which may want credentials the run does not have. A
/// yarn classic pin reads the served tarball (its sha1 goes into the
/// lock); here the mirror answers the check and nothing else, so a
/// download sent its way would fail the pin.
#[tokio::test]
#[serial]
async fn the_runs_own_downloads_read_the_patch_server_not_the_mirror() {
    let api = MockServer::start().await;
    mock_socket(&api, &[FIRST]).await;
    let mirror = MockServer::start().await;
    mirror_answers(&mirror, FIRST, 200).await;

    let tmp = tempfile::tempdir().unwrap();
    let name = FIRST.name;
    std::fs::write(
        tmp.path().join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{name}": "{VERSION}" }} }}"#
        ),
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("yarn.lock"),
        format!(
            "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
             # yarn lockfile v1\n\n\n\
             {name}@{VERSION}:\n  version \"{VERSION}\"\n  \
             resolved \"https://registry.yarnpkg.com/{name}/-/{name}-{VERSION}.tgz#bbbb\"\n  \
             integrity sha512-UPSTREAMupstream==\n"
        ),
    )
    .unwrap();

    let out = hosted_scan(
        tmp.path(),
        &api,
        &["--patch-mirror-url", &mirror_base(&mirror)],
        &[],
    );
    let env = out.json();
    assert_eq!(event(&env, FIRST), applied(), "{env:#}");

    use sha1::Digest as _;
    let sha1 = hex::encode(sha1::Sha1::digest(FIRST.tarball()));
    let pinned = std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap();
    assert!(
        pinned.contains(&format!(
            "resolved \"{}#{sha1}\"",
            mirrored_url(&mirror, FIRST)
        )),
        "the lock pins the mirror, with the sha1 of the tarball the run read: {pinned}"
    );
    assert!(
        requests(&api)
            .await
            .contains(&format!("GET {}", FIRST.served_path())),
        "the tarball was read from the patch server"
    );
    assert_eq!(
        requests(&mirror).await,
        vec![format!("HEAD {MIRROR_PREFIX}{}", FIRST.served_path())],
        "the mirror was asked the one check and sent no download"
    );
}

/// The run's check, answer by answer. A redirect is not followed: the pin
/// is written with the "not checked" warning, and the redirect's target
/// never hears from the run. A miss for one patch withholds that patch
/// alone. A miss for every patch, or no answer at all, is said of the
/// mirror, and nothing is pinned.
#[tokio::test]
#[serial]
async fn each_answer_to_the_mirror_check_is_acted_on() {
    let api = MockServer::start().await;
    mock_socket(&api, &[FIRST, SECOND]).await;
    let project = || {
        let tmp = tempfile::tempdir().unwrap();
        write_npm_project(tmp.path(), &[FIRST, SECOND]);
        tmp
    };

    // A redirect, to a server that would say yes.
    let elsewhere = MockServer::start().await;
    Mock::given(method("HEAD"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&elsewhere)
        .await;
    let redirecting = MockServer::start().await;
    Mock::given(method("HEAD"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", format!("{}/login", elsewhere.uri()).as_str()),
        )
        .mount(&redirecting)
        .await;
    let tmp = project();
    let out = hosted_scan(
        tmp.path(),
        &api,
        &["--patch-mirror-url", &mirror_base(&redirecting)],
        &[],
    );
    let env = out.json();
    assert_eq!(event(&env, FIRST), applied(), "{env:#}");
    assert_eq!(event(&env, SECOND), applied(), "{env:#}");
    assert_eq!(
        warning_codes(&env)
            .iter()
            .filter(|c| c.as_str() == "redirect_mirror_unverified")
            .count(),
        1,
        "{env:#}"
    );
    assert!(
        requests(&elsewhere).await.is_empty(),
        "the redirect is not followed"
    );
    assert_eq!(
        requests(&redirecting).await.len(),
        1,
        "one answer that says nothing about the patch ends the check"
    );

    // One patch the mirror serves, one it does not.
    let partial = MockServer::start().await;
    mirror_answers(&partial, FIRST, 200).await;
    mirror_answers(&partial, SECOND, 404).await;
    let tmp = project();
    let out = hosted_scan(
        tmp.path(),
        &api,
        &["--patch-mirror-url", &mirror_base(&partial)],
        &[],
    );
    let env = out.json();
    assert_eq!(event(&env, FIRST), applied(), "{env:#}");
    assert_eq!(
        event(&env, SECOND),
        skipped("redirect_mirror_unavailable"),
        "{env:#}"
    );
    let pinned = lock(tmp.path());
    assert!(pinned.contains(&mirrored_url(&partial, FIRST)), "{pinned}");
    assert!(
        pinned.contains(&format!("sha512-UPSTREAM{}==", SECOND.name))
            && !pinned.contains(SECOND.uuid),
        "the patch the mirror does not serve keeps its registry entry: {pinned}"
    );
    assert!(
        out.stdout
            .contains(&format!("{}: the patch mirror", SECOND.purl())),
        "the warning is about that package, not the mirror: {}",
        out.stdout
    );

    // Nothing served (HTTP 404 and 500), and nothing listening.
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!(
            "http://{}/artifactory/socket-patch",
            listener.local_addr().unwrap()
        )
    };
    let missing = MockServer::start().await;
    let failing = MockServer::start().await;
    for pkg in [FIRST, SECOND] {
        mirror_answers(&failing, pkg, 500).await;
    }
    for base in [mirror_base(&missing), mirror_base(&failing), closed] {
        let tmp = project();
        let pristine = lock(tmp.path());
        let out = hosted_scan(tmp.path(), &api, &["--patch-mirror-url", &base], &[]);
        let env = out.json();
        for pkg in [FIRST, SECOND] {
            assert_eq!(
                event(&env, pkg),
                skipped("redirect_mirror_unavailable"),
                "{base}: {env:#}"
            );
        }
        assert_eq!(
            warning_codes(&env)
                .iter()
                .filter(|c| c.as_str() == "redirect_mirror_unavailable")
                .count(),
            1,
            "{base}: one warning, about the mirror: {env:#}"
        );
        assert_eq!(lock(tmp.path()), pristine, "{base}: nothing is written");
        assert!(
            !tmp.path().join(".npmrc").exists(),
            "{base}: no install setting is written for a pin that was not"
        );
        assert!(
            !out.stdout.contains(TOKEN) && !out.stderr.contains(TOKEN),
            "the grant token is not printed: {}\n{}",
            out.stdout,
            out.stderr
        );
    }
}

/// A mirror that wants credentials cannot be checked by a run that has
/// none: the pin is written, with a warning. Given the operator's header
/// value, the run checks the mirror with it, and sends it nowhere else:
/// not to the Socket API, not into a file, not into its own output.
#[tokio::test]
#[serial]
async fn the_mirror_credential_reaches_the_mirror_and_nothing_else() {
    const SECRET: &str = "Bearer mirror-s3cret";
    let api = MockServer::start().await;
    mock_socket(&api, &[FIRST]).await;
    let mirror = MockServer::start().await;
    let at = format!("{MIRROR_PREFIX}{}", FIRST.served_path());
    Mock::given(method("HEAD"))
        .and(path(at.clone()))
        .and(header("authorization", SECRET))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mirror)
        .await;
    Mock::given(method("HEAD"))
        .and(path(at))
        .respond_with(
            ResponseTemplate::new(401)
                .insert_header("WWW-Authenticate", "Basic realm=\"Artifactory Realm\""),
        )
        .mount(&mirror)
        .await;
    let base = mirror_base(&mirror);

    // No credential: pinned, with the warning.
    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), &[FIRST]);
    let out = hosted_scan(tmp.path(), &api, &["--patch-mirror-url", &base], &[]);
    let env = out.json();
    assert_eq!(event(&env, FIRST), applied(), "{env:#}");
    assert!(
        warning_codes(&env).contains(&"redirect_mirror_unverified".to_string()),
        "{env:#}"
    );
    assert!(lock(tmp.path()).contains(&mirrored_url(&mirror, FIRST)));

    // With the operator's credential: checked, no warning.
    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), &[FIRST]);
    let out = hosted_scan(
        tmp.path(),
        &api,
        &["--patch-mirror-url", &base],
        &[("SOCKET_PATCH_MIRROR_AUTHORIZATION", SECRET)],
    );
    let env = out.json();
    assert_eq!(event(&env, FIRST), applied(), "{env:#}");
    assert!(
        !warning_codes(&env).iter().any(|c| c.contains("mirror")),
        "{env:#}"
    );
    assert!(lock(tmp.path()).contains(&mirrored_url(&mirror, FIRST)));

    let api_requests = api.received_requests().await.unwrap_or_default();
    assert!(!api_requests.is_empty());
    for request in &api_requests {
        for (name, value) in request.headers.iter() {
            assert!(
                !value.to_str().unwrap_or_default().contains("mirror-s3cret"),
                "the Socket API received the mirror credential in `{name}`"
            );
        }
    }
    assert!(!out.stdout.contains("mirror-s3cret") && !out.stderr.contains("mirror-s3cret"));
    for file in ["package-lock.json", ".npmrc"] {
        let text = std::fs::read_to_string(tmp.path().join(file)).unwrap_or_default();
        assert!(!text.contains("mirror-s3cret"), "{file}: {text}");
    }
}

/// A base that cannot prefix a committed URL is refused before the project
/// is read, and the refusal never repeats the value: a base given with
/// credentials in it must not be echoed into a terminal or a CI log.
#[test]
fn a_base_that_cannot_be_committed_is_refused_without_echoing_it() {
    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), &[FIRST]);
    let pristine = lock(tmp.path());
    for (base, why) in [
        ("https://user:secret@repo.example/x", "credentials"),
        ("repo.example/artifactory/socket-patch", "http(s)"),
        ("https://repo.example/x?repo=y", "query"),
    ] {
        for command in ["scan", "list"] {
            let mut cmd = cli();
            cmd.args([
                command,
                "--cwd",
                tmp.path().to_str().unwrap(),
                "--patch-mirror-url",
                base,
            ]);
            let out = run(cmd);
            assert_eq!(
                out.code,
                Some(2),
                "{command} {base}: {}\n{}",
                out.stdout,
                out.stderr
            );
            assert!(out.stderr.contains(why), "{base}: {}", out.stderr);
            assert!(!out.stderr.contains("secret"), "{}", out.stderr);
        }
        // `apply` does not use the mirror and runs unattended from install
        // hooks: a base it cannot use must not fail the install.
        let mut cmd = cli();
        cmd.args(["apply", "--cwd", tmp.path().to_str().unwrap()])
            .env("SOCKET_PATCH_MIRROR_URL", base);
        let out = run(cmd);
        assert_eq!(
            out.code,
            Some(0),
            "apply {base}: {}\n{}",
            out.stdout,
            out.stderr
        );
        assert!(!out.stderr.contains("secret"), "{}", out.stderr);
    }
    assert_eq!(lock(tmp.path()), pristine);
}
