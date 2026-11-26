//! The closing lines of a hosted `scan` over gems the Bundler lock names
//! as precompiled platform builds, against a wiremock patch API (the real
//! binary; nothing is installed here).
//!
//! Such a gem moves to its patch registry once one locked build is
//! patched, and the registry serves upstream's own gem for a platform with
//! no patched build yet. The run's package is patched, so by the count of
//! advisories nothing is left, while that platform still installs what it
//! installed before. The closing lines name it where they would say that
//! nothing is left to patch: one plain line, no warning, exit 0.

use std::path::Path;

use serde_json::{json, Value};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common;

const ORG: &str = "test-org";
const VERSION: &str = "1.19.3";
const TOKEN: &str = "66666666-6666-4666-8666-666666666666";
/// Shaped like a Socket API token, so no run warns about the token itself.
const API_TOKEN: &str = "sktsec_00000000000000000000000000000000000000000000_api";

const ARM: &str = "arm64-darwin";
const LINUX: &str = "x86_64-linux-gnu";
const MUSL: &str = "x86_64-linux-musl";
/// The patches of the patched platform builds.
const ARM_UUID: &str = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
const LINUX_UUID: &str = "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e";

/// The sha256 a lock pins before any run: upstream's own platform gems.
const ARM_UPSTREAM: &str = "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
const LINUX_UPSTREAM: &str = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0";
const MUSL_UPSTREAM: &str = "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0";
/// The sha256 of the patched gems.
const RUBY_PATCHED: &str = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";
const ARM_PATCHED: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const LINUX_PATCHED: &str = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";

/// One platform gem as a reference lists it (`gemBuilds`): its platform,
/// the sha256 the registry serves, and the patch of its patched build
/// (`None`: the registry serves upstream's own gem).
type Listed = (&'static str, &'static str, Option<&'static str>);

const ARM_ON_UPSTREAM: Listed = (ARM, ARM_UPSTREAM, None);
const ARM_IS_PATCHED: Listed = (ARM, ARM_PATCHED, Some(ARM_UUID));
const LINUX_IS_PATCHED: Listed = (LINUX, LINUX_PATCHED, Some(LINUX_UUID));
const MUSL_ON_UPSTREAM: Listed = (MUSL, MUSL_UPSTREAM, None);

/// One gem the project locks as platform builds: its name (one nothing on
/// the developer's machine can have installed), the uuid of its patch,
/// and the platform gems that patch's reference lists.
struct Gem {
    name: &'static str,
    uuid: &'static str,
    builds: &'static [Listed],
}

impl Gem {
    fn purl(&self) -> String {
        format!("pkg:gem/{}@{VERSION}", self.name)
    }

    fn cve(&self) -> String {
        format!("CVE-2026-{}", &self.uuid[..4])
    }
}

/// `arm64-darwin` on upstream's gem, `x86_64-linux-gnu` patched.
const PROBE: Gem = Gem {
    name: "platform-probe",
    uuid: "7001e4f3-2c5d-4e6f-8a9b-0c1d2e3f4a5b",
    builds: &[ARM_ON_UPSTREAM, LINUX_IS_PATCHED],
};
/// The same gem with both locked builds patched.
const PROBE_PATCHED: Gem = Gem {
    builds: &[ARM_IS_PATCHED, LINUX_IS_PATCHED],
    ..PROBE
};
/// Two of its three locked builds on upstream's gem.
const PROBE_WIDE: Gem = Gem {
    builds: &[ARM_ON_UPSTREAM, LINUX_IS_PATCHED, MUSL_ON_UPSTREAM],
    ..PROBE
};
const FFI: Gem = Gem {
    name: "probe-ffi",
    uuid: "7002e4f3-2c5d-4e6f-8a9b-0c1d2e3f4a5b",
    builds: &[ARM_ON_UPSTREAM, LINUX_IS_PATCHED],
};
const GRPC: Gem = Gem {
    name: "probe-grpc",
    uuid: "7003e4f3-2c5d-4e6f-8a9b-0c1d2e3f4a5b",
    builds: &[ARM_IS_PATCHED, LINUX_IS_PATCHED],
};

/// Mount the patch API of `gems`: one patch each, whose reference lists
/// the gem's builds under a registry snapshot.
async fn mount_api(server: &MockServer, gems: &[Gem]) {
    let api = server.uri();
    let mut offers = Vec::new();
    let mut searches = serde_json::Map::new();
    let mut references = serde_json::Map::new();
    for gem in gems {
        let (name, uuid, purl) = (gem.name, gem.uuid, gem.purl());
        let vulnerabilities = json!({ format!("GHSA-{name}"): {
            "cves": [gem.cve()], "summary": "s", "severity": "high", "description": "d",
        }});
        offers.push(json!({ "purl": purl, "patches": [{
            "uuid": uuid, "purl": purl, "tier": "free", "cveIds": [gem.cve()],
            "ghsaIds": [format!("GHSA-{name}")], "severity": "high",
            "title": "platform gem fixture",
        }]}));
        searches.insert(
            purl.clone(),
            json!({
                "patches": [{
                    "uuid": uuid, "purl": purl, "publishedAt": "2026-01-01T00:00:00Z",
                    "description": "x", "license": "MIT", "tier": "free",
                    "vulnerabilities": vulnerabilities,
                }],
                "canAccessPaidPatches": false,
            }),
        );
        let artifact =
            format!("{api}/patch/gem/{name}/{VERSION}/{TOKEN}/{uuid}/{name}-{VERSION}.gem");
        let listed: Vec<Value> = gem
            .builds
            .iter()
            .map(|(platform, sha, patch)| {
                json!({ "platform": platform, "gemChecksumSha256": sha, "patchUuid": patch })
            })
            .collect();
        references.insert(
            uuid.to_string(),
            json!({
                "status": "granted",
                "url": artifact,
                "purl": purl,
                "artifacts": [{
                    "kind": "tarball", "url": artifact,
                    "integrity": { "sha256": RUBY_PATCHED },
                }],
                "registryOverride": {
                    "kind": "rubygems-compact-index",
                    "indexUrl": format!("{api}/patch-registry/gem/{TOKEN}/{uuid}/s/4f0a/"),
                    "identifiers": {
                        "name": name, "version": VERSION,
                        "gemChecksumSha256": RUBY_PATCHED, "gemBuilds": listed,
                    },
                },
            }),
        );
        Mock::given(method("GET"))
            .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "uuid": uuid, "purl": purl, "publishedAt": "2026-01-01T00:00:00Z",
                "files": { format!("lib/{name}.rb"): {
                    "beforeHash": "a".repeat(64), "afterHash": "b".repeat(64),
                }},
                "vulnerabilities": vulnerabilities,
                "description": "x", "license": "MIT", "tier": "free",
            })))
            .mount(server)
            .await;
    }
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": offers,
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(move |request: &wiremock::Request| {
            let asked = request.url.path().rsplit('/').next().unwrap_or_default();
            let purl = asked
                .replace("%3A", ":")
                .replace("%2F", "/")
                .replace("%40", "@");
            let none = json!({ "patches": [], "canAccessPaidPatches": false });
            ResponseTemplate::new(200).set_body_json(searches.get(&purl).unwrap_or(&none))
        })
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(move |request: &wiremock::Request| {
            let asked: Value = serde_json::from_slice(&request.body).unwrap_or_default();
            let answered: serde_json::Map<String, Value> = asked["uuids"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|uuid| {
                    let uuid = uuid.as_str()?;
                    Some((uuid.to_string(), references.get(uuid)?.clone()))
                })
                .collect();
            ResponseTemplate::new(200).set_body_json(json!({ "results": answered }))
        })
        .mount(server)
        .await;
}

/// The sha256 of upstream's gem for `platform`, as a lock pins it before
/// any run.
fn upstream(platform: &str) -> &'static str {
    match platform {
        ARM => ARM_UPSTREAM,
        LINUX => LINUX_UPSTREAM,
        _ => MUSL_UPSTREAM,
    }
}

/// A project whose lock names each of `gems` as its platform builds, each
/// pinned to upstream's archive.
fn project(gems: &[Gem]) -> tempfile::TempDir {
    let mut gemfile = "source \"https://rubygems.org\"\n\n".to_string();
    let (mut specs, mut dependencies, mut checksums) =
        (String::new(), String::new(), String::new());
    let mut platforms: Vec<&str> = Vec::new();
    for gem in gems {
        let name = gem.name;
        gemfile.push_str(&format!("gem \"{name}\", \"{VERSION}\"\n"));
        dependencies.push_str(&format!("  {name} (= {VERSION})\n"));
        for (platform, _, _) in gem.builds {
            specs.push_str(&format!("    {name} ({VERSION}-{platform})\n"));
            checksums.push_str(&format!(
                "  {name} ({VERSION}-{platform}) sha256={}\n",
                upstream(platform)
            ));
            if !platforms.contains(platform) {
                platforms.push(platform);
            }
        }
    }
    platforms.sort_unstable();
    let platforms: String = platforms.iter().map(|p| format!("  {p}\n")).collect();
    let lock = format!(
        "GEM\n  remote: https://rubygems.org/\n  specs:\n{specs}\nPLATFORMS\n{platforms}\n\
         DEPENDENCIES\n{dependencies}\nCHECKSUMS\n{checksums}\nBUNDLED WITH\n  4.0.15\n"
    );
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("Gemfile"), gemfile).unwrap();
    std::fs::write(dir.path().join("Gemfile.lock"), lock).unwrap();
    dir
}

/// The arguments of `socket-patch scan --mode hosted` over `proj` against
/// `api`, with `extra` ones.
fn scan_args<'a>(proj: &'a Path, api: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec![
        "scan",
        "--mode",
        "hosted",
        "--yes",
        "--cwd",
        proj.to_str().expect("utf8 temp path"),
        "--api-url",
        api,
        "--org",
        ORG,
        "--api-token",
        API_TOKEN,
    ];
    args.extend_from_slice(extra);
    args
}

/// The closing lines of a run's stdout: what follows its last blank line.
fn closing_lines(stdout: &str) -> Vec<&str> {
    let lines: Vec<&str> = stdout.lines().collect();
    let start = lines
        .iter()
        .rposition(|line| line.is_empty())
        .map_or(0, |at| at + 1);
    lines[start..].to_vec()
}

/// What the closing lines say of [`PROBE`]'s build on upstream's gem.
const BUILD_LINE: &str = "Not patched yet: platform-probe 1.19.3 for arm64-darwin.";
/// And of the three such builds of [`PROBE_WIDE`] and [`FFI`], whose
/// platforms do not fit the row.
const BUILDS_LINE: &str = "Not patched yet: 3 builds of platform-probe 1.19.3, probe-ffi 1.19.3.";

/// One locked build patched, one on upstream's gem: the closing lines name
/// the build that is not patched where they would say that nothing is
/// left, on a dry run too. Nothing warns, and the run exits 0.
#[tokio::test(flavor = "multi_thread")]
async fn the_closing_lines_name_a_build_left_on_upstreams_gem() {
    let server = MockServer::start().await;
    mount_api(&server, &[PROBE]).await;
    let api = server.uri();

    let proj = project(&[PROBE]);
    let (code, stdout, stderr) =
        common::run_with_env(proj.path(), &scan_args(proj.path(), &api, &[]), &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains(&format!(
            "\nplatform-probe {VERSION}: patched for {LINUX}; upstream gem kept for {ARM} (no \
             patched build yet)\n"
        )),
        "{stdout}"
    );
    assert_eq!(
        closing_lines(&stdout),
        [
            "Patched 1 package, fixing 1 vulnerability (1 high).",
            "Saved about 2 hours of engineering time (1 package upgrade at ~2 hours).",
            BUILD_LINE,
        ],
        "{stdout}"
    );
    assert!(!stdout.contains("Nothing left to patch"), "{stdout}");
    assert!(
        !stderr.contains("Warning") && !stderr.contains(BUILD_LINE),
        "{stderr}"
    );

    let proj = project(&[PROBE]);
    let (code, stdout, stderr) = common::run_with_env(
        proj.path(),
        &scan_args(proj.path(), &api, &["--dry-run"]),
        &[],
    );
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(
        closing_lines(&stdout),
        [
            "Would patch 1 package, fixing 1 vulnerability (1 high).",
            "Would save about 2 hours of engineering time (1 package upgrade at ~2 hours).",
            BUILD_LINE,
        ],
        "{stdout}"
    );

    // `--silent` prints none of it.
    let proj = project(&[PROBE]);
    let (code, stdout, stderr) = common::run_with_env(
        proj.path(),
        &scan_args(proj.path(), &api, &["--silent"]),
        &[],
    );
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        !stdout.contains("Not patched") && !stderr.contains("Not patched"),
        "{stdout}\n{stderr}"
    );
}

/// Every locked build patched: nothing is left, and the lines say so.
#[tokio::test(flavor = "multi_thread")]
async fn the_closing_lines_say_nothing_is_left_once_every_locked_build_is_patched() {
    let server = MockServer::start().await;
    mount_api(&server, &[PROBE_PATCHED]).await;
    let api = server.uri();

    let proj = project(&[PROBE_PATCHED]);
    let (code, stdout, stderr) =
        common::run_with_env(proj.path(), &scan_args(proj.path(), &api, &[]), &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(
        closing_lines(&stdout),
        [
            "Patched 1 package, fixing 1 vulnerability (1 high).",
            "Saved about 2 hours of engineering time (1 package upgrade at ~2 hours).",
            "Nothing left to patch.",
        ],
        "{stdout}"
    );
    assert!(!stdout.contains("Not patched yet"), "{stdout}");
}

/// Three gems, two of them with builds on upstream's gem on more
/// platforms than one row names: the line counts the builds of the gems
/// it names, and the gem whose builds are all patched is not among them.
#[tokio::test(flavor = "multi_thread")]
async fn the_closing_lines_count_the_builds_of_several_gems() {
    let server = MockServer::start().await;
    mount_api(&server, &[PROBE_WIDE, FFI, GRPC]).await;
    let api = server.uri();

    let proj = project(&[PROBE_WIDE, FFI, GRPC]);
    let (code, stdout, stderr) =
        common::run_with_env(proj.path(), &scan_args(proj.path(), &api, &[]), &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    // The run's own line about each gem names every platform.
    for line in [
        format!(
            "platform-probe {VERSION}: patched for {LINUX}; upstream gem kept for {ARM}, {MUSL} \
             (no patched build yet)"
        ),
        format!(
            "probe-ffi {VERSION}: patched for {LINUX}; upstream gem kept for {ARM} (no patched \
             build yet)"
        ),
        format!("probe-grpc {VERSION}: patched for {ARM}, {LINUX}"),
    ] {
        assert!(stdout.contains(&format!("\n{line}\n")), "{line}\n{stdout}");
    }
    assert_eq!(
        closing_lines(&stdout),
        [
            "Patched 3 packages, fixing 3 vulnerabilities (3 high).",
            "Saved about 6 hours of engineering time (3 package upgrades at ~2 hours each).",
            BUILDS_LINE,
        ],
        "{stdout}"
    );
    assert!(!stderr.contains("Warning"), "{stderr}");
}

/// `get --mode hosted` has no closing lines of its own: with one locked
/// build on upstream's gem it says which builds are patched, and nothing
/// that claims the gem is patched everywhere.
#[tokio::test(flavor = "multi_thread")]
async fn a_hosted_get_names_the_build_and_has_no_closing_lines() {
    let server = MockServer::start().await;
    mount_api(&server, &[PROBE]).await;
    let api = server.uri();

    let proj = project(&[PROBE]);
    let mut args = scan_args(proj.path(), &api, &[]);
    args.splice(0..1, ["get", PROBE.uuid]);
    let (code, stdout, stderr) = common::run_with_env(proj.path(), &args, &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains(&format!(
            "\nplatform-probe {VERSION}: patched for {LINUX}; upstream gem kept for {ARM} (no \
             patched build yet)\n"
        )),
        "{stdout}"
    );
    assert!(
        !stdout.contains("Nothing left to patch") && !stdout.contains("Patched 1 package"),
        "{stdout}"
    );
}

/// `socket-patch <args>` on a terminal `cols` wide, in a UTF-8 locale
/// (where the lines of what was done open with a check mark): its exit
/// code and the screen it leaves, row by row.
#[cfg(unix)]
fn on_a_terminal(cols: u16, args: &[&str], cwd: &Path) -> (i32, Vec<String>) {
    // `LANG` is the last of the three variables a locale is read from,
    // and the child inherits the other two.
    let mut binary = common::hermetic::pty_binary_command();
    binary.env_remove("LC_ALL");
    binary.env_remove("LC_CTYPE");
    let run = crate::pty_io::run_command_at(
        cols,
        binary,
        args,
        cwd,
        &[("LANG", "en_US.UTF-8")],
        &[],
        std::time::Duration::from_secs(60),
    );
    (run.code, crate::pty_io::render(run.output.as_bytes()))
}

/// On a terminal 80, 100 and 120 columns wide the closing lines stand in
/// their gutter under a check mark and say which builds are not patched,
/// for one gem and for several, on one row of the terminal.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn the_closing_lines_fit_a_terminal_of_80_100_and_120_columns() {
    for (gems, patched, saved, builds) in [
        (
            &[PROBE][..],
            "Patched 1 package, fixing 1 vulnerability (1 high) in ",
            "  Saved about 2 hours of engineering time (1 package upgrade at ~2 hours).",
            BUILD_LINE,
        ),
        (
            &[PROBE_WIDE, FFI, GRPC][..],
            "Patched 3 packages, fixing 3 vulnerabilities (3 high) in ",
            "  Saved about 6 hours of engineering time (3 package upgrades at ~2 hours each).",
            BUILDS_LINE,
        ),
    ] {
        let server = MockServer::start().await;
        mount_api(&server, gems).await;
        for cols in [80u16, 100, 120] {
            let proj = project(gems);
            let cwd = proj.path().to_path_buf();
            let api = server.uri();
            let (code, screen) = tokio::task::spawn_blocking(move || {
                on_a_terminal(cols, &scan_args(&cwd, &api, &[]), &cwd)
            })
            .await
            .expect("spawn_blocking join");
            let shown = screen.join("\n");
            println!("--- {cols} columns\n{shown}");
            assert_eq!(code, 0, "{shown}");
            let last_blank = screen.iter().rposition(String::is_empty);
            let closing = &screen[last_blank.map_or(0, |at| at + 1)..];
            assert_eq!(closing.len(), 3, "{shown}");
            // The time the run took follows, on a terminal only.
            assert!(
                closing[0].starts_with(&format!("✔ {patched}")) && closing[0].ends_with("s."),
                "{shown}"
            );
            assert_eq!(closing[1..], [saved.to_string(), format!("  {builds}")]);
            assert!(!shown.contains("Nothing left to patch"), "{shown}");
            assert!(
                closing[2].chars().count() < usize::from(cols),
                "wider than {cols} columns: {:?}\n{shown}",
                closing[2]
            );
        }
    }
}
