//! Docker-driven real-tool chains for sbt, Mill and scala-cli
//! (`docs/design/sbt-support.md` §8.5; image `tests/docker/Dockerfile.sbt`).
//!
//! `agent_*`: the real tool resolves `commons-text 1.9` into its cache
//! (Coursier for sbt 1.3+ / 2, Mill and scala-cli; Ivy for sbt <= 1.2 and
//! `useCoursier := false`), then `socket-patch scan --sync` (agent mode,
//! against a wiremock patch API) patches that cache copy in place, as a
//! whole-file `commons-text-1.9.jar` key. Each cell prints a marker per leg
//! and the host asserts them:
//!
//! - `===PATCH OK===`: the jar the tool's classpath names is byte-identical
//!   to the patched jar, after a `clean update` too;
//! - `===SIDECAR OK===` (Coursier only): `.<jar>__sha1` holds the patched
//!   jar's sha1, md5 is gone, and with the cached `.computed` digests
//!   deleted a `clean update` still keeps the patched bytes (a stale
//!   `__sha1` would make Coursier silently re-download the pristine jar);
//! - `===ROLLBACK OK===`: `rollback` (fetching the before blob from the
//!   mock) restores the pristine bytes
//!   and the tool keeps them;
//! - `===E2E PASS===`.
//!
//! sbt versions come from `SOCKET_PATCH_SBT_DOCKER_VERSIONS` (default
//! `1.13.0`), Mill versions from `SOCKET_PATCH_MILL_DOCKER_VERSIONS`
//! (default `1.1.10`; the image installs 0.11.13, 0.12.17 and 1.1.10:
//! `build.mill` + `mvnDeps` on 1.x, `build.sc` + `ivyDeps` on 0.11 /
//! 0.12); JDK 8 for sbt <= 1.3.13, else 17, unless
//! `SOCKET_PATCH_SBT_DOCKER_JDK` (`8` / `17` / `21`) picks one for every
//! cell (`scripts/sbt-compat-matrix.sh --jdk`). A missing image or docker
//! skips unless `SOCKET_PATCH_DOCKER_E2E_REQUIRED=1`. Every container runs
//! `--rm -m 2g`; run the suite with `--test-threads=1`.
//!
//! The socket-patch inside the image is the base image's; to test a local
//! build, point `SOCKET_PATCH_DOCKER_BIN` at a Linux binary (mounted over
//! it), or use the coverage hook (`SOCKET_PATCH_COV_BIN`).
//!
//! ```sh
//! docker build -t socket-patch-test-sbt:latest -f tests/docker/Dockerfile.sbt tests/docker
//! SOCKET_PATCH_DOCKER_E2E_REQUIRED=1 SOCKET_PATCH_SBT_DOCKER_VERSIONS="1.2.8 1.13.0 2.0.9" \
//!   cargo test -p socket-patch-cli --features docker-e2e --test docker_e2e_sbt -- --test-threads=1
//! ```

#![cfg(feature = "docker-e2e")]

#[path = "common/mod.rs"]
mod common;
use common::git_sha256;

use std::io::{Read as _, Write as _};
use std::process::Command;

use base64::Engine as _;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The image (`SOCKET_PATCH_SBT_DOCKER_IMAGE` overrides the tag).
fn image() -> String {
    std::env::var("SOCKET_PATCH_SBT_DOCKER_IMAGE")
        .unwrap_or_else(|_| "socket-patch-test-sbt:latest".to_string())
}
const ORG: &str = "test-org";
const PURL: &str = "pkg:maven/org.apache.commons/commons-text@1.9";
const UUID: &str = "5b7a0000-0000-4000-8000-0000000000a1";
const JAR: &str = "commons-text-1.9.jar";
const CENTRAL_JAR: &str =
    "https://repo1.maven.org/maven2/org/apache/commons/commons-text/1.9/commons-text-1.9.jar";
/// The marker member the patched jar adds.
const MARKER: &str = "SOCKET_PATCHED.txt";

fn hex_of<D: Digest>(bytes: &[u8]) -> String {
    hex::encode(D::digest(bytes))
}

/// The pristine jar from Maven Central (checked against Central's `.sha1`)
/// and the patched one: every member copied raw, plus [`MARKER`].
async fn jars() -> (Vec<u8>, Vec<u8>) {
    let client = reqwest::Client::new();
    let get = |url: String| {
        let client = client.clone();
        async move {
            let resp = client.get(&url).send().await.expect("fetch from Central");
            assert!(resp.status().is_success(), "{url}: {}", resp.status());
            resp.bytes().await.expect("body").to_vec()
        }
    };
    let pristine = get(CENTRAL_JAR.to_string()).await;
    let sha1 = String::from_utf8(get(format!("{CENTRAL_JAR}.sha1")).await).unwrap();
    assert_eq!(hex_of::<Sha1>(&pristine), sha1.trim(), "Central sha1");

    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(pristine.clone())).unwrap();
    let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for i in 0..archive.len() {
        let file = archive.by_index_raw(i).unwrap();
        out.raw_copy_file(file).unwrap();
    }
    out.start_file(MARKER, zip::write::SimpleFileOptions::default())
        .unwrap();
    out.write_all(b"socket-patch docker e2e\n").unwrap();
    let patched = out.finish().unwrap().into_inner();
    // Sanity: the marker is readable back.
    let mut check = zip::ZipArchive::new(std::io::Cursor::new(patched.clone())).unwrap();
    let mut text = String::new();
    check
        .by_name(MARKER)
        .unwrap()
        .read_to_string(&mut text)
        .unwrap();
    assert!(text.contains("socket-patch"));
    (pristine, patched)
}

/// The authenticated patch API serving one whole-jar patch for
/// commons-text 1.9 (the patched blob inline, the pristine one by hash).
async fn mock_api(pristine: &[u8], patched: &[u8]) -> MockServer {
    let listener = std::net::TcpListener::bind("0.0.0.0:0").expect("bind wiremock");
    let server = MockServer::builder().listener(listener).start().await;
    let summary = serde_json::json!({
        "uuid": UUID, "purl": PURL, "tier": "free", "cveIds": [], "ghsaIds": [],
        "severity": "medium", "title": "sbt agent e2e fixture"
    });
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{ "purl": PURL, "patches": [summary] }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID, "purl": PURL, "publishedAt": "2024-01-01T00:00:00Z",
                "description": "sbt agent e2e fixture", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    // Rollback fetches the before blob (scan stores only the after blob).
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG}/patches/blob/{}",
            git_sha256(pristine)
        )))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(pristine.to_vec()))
        .mount(&server)
        .await;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID, "purl": PURL, "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                JAR: {
                    "beforeHash": git_sha256(pristine),
                    "afterHash": git_sha256(patched),
                    "blobContent": b64(patched),
                }
            },
            "vulnerabilities": {},
            "description": "sbt agent e2e fixture", "license": "MIT", "tier": "free",
        })))
        .mount(&server)
        .await;
    server
}

/// Which tool a cell drives.
#[derive(Clone, Copy, Debug)]
enum Tool {
    /// sbt at this version; `ivy` forces `useCoursier := false`.
    Sbt {
        version: &'static str,
        ivy: bool,
    },
    /// Mill at this version (`mill-<version>` in the image).
    Mill {
        version: &'static str,
    },
    ScalaCli,
}

impl Tool {
    fn coursier(self) -> bool {
        match self {
            Tool::Sbt { version, ivy } => !ivy && !sbt_uses_ivy(version),
            Tool::Mill { .. } | Tool::ScalaCli => true,
        }
    }
}

/// sbt 0.13 and 1.0-1.2 resolve with Ivy.
fn sbt_uses_ivy(version: &str) -> bool {
    version.starts_with("0.")
        || ["1.0.", "1.1.", "1.2."]
            .iter()
            .any(|p| version.starts_with(p))
}

/// The JDK of an sbt cell: `SOCKET_PATCH_SBT_DOCKER_JDK` (`8` / `17` /
/// `21`) when set, else 8 for sbt <= 1.3.x and 17 after.
fn sbt_jdk(version: &str) -> &'static str {
    match std::env::var("SOCKET_PATCH_SBT_DOCKER_JDK").as_deref() {
        Ok("8") => return "/opt/jdk8",
        Ok("17") => return "/opt/jdk17",
        Ok("21") => return "/opt/jdk21",
        Ok(other) if !other.is_empty() => {
            panic!("SOCKET_PATCH_SBT_DOCKER_JDK={other}: expected 8, 17 or 21")
        }
        _ => {}
    }
    let old = version.starts_with("0.")
        || ["1.0.", "1.1.", "1.2.", "1.3."]
            .iter()
            .any(|p| version.starts_with(p));
    if old {
        "/opt/jdk8"
    } else {
        "/opt/jdk17"
    }
}

/// The in-container script for one cell.
fn script(tool: Tool, api_url: &str, pristine: &[u8], patched: &[u8]) -> String {
    let setup = match tool {
        Tool::Sbt { version, ivy } => {
            let jdk = sbt_jdk(version);
            let server = if version.starts_with("2.") {
                " --server"
            } else {
                ""
            };
            let cp = if version.starts_with("0.") {
                "compile:dependencyClasspath"
            } else {
                "Compile/dependencyClasspath"
            };
            let ivy_line = if ivy {
                "ThisBuild / useCoursier := false"
            } else {
                ""
            };
            format!(
                r#"export JAVA_HOME={jdk} PATH={jdk}/bin:$PATH
echo "sbt.version={version}" > project/build.properties
cat > build.sbt <<'EOF'
autoScalaLibrary := false
crossPaths := false
libraryDependencies += "org.apache.commons" % "commons-text" % "1.9"
{ivy_line}
EOF
TOOL() {{ timeout 300 sbt -batch -no-colors -Dsbt.server.autostart=false{server} "$@"; }}
RESOLVE() {{ TOOL clean update "export {cp}"; }}"#
            )
        }
        Tool::Mill { version } if version.starts_with("0.") => {
            // Mill 0.11 / 0.12: `build.sc`, `ivyDeps`, `.mill-version`;
            // 0.11 spells the ticker flag `--disable-ticker`.
            let ticker = if version.starts_with("0.11.") {
                "--disable-ticker"
            } else {
                "--ticker false"
            };
            format!(
                r#"export JAVA_HOME=${{SOCKET_PATCH_JDK:-/opt/jdk17}} PATH=${{SOCKET_PATCH_JDK:-/opt/jdk17}}/bin:$PATH
echo "{version}" > .mill-version
cat > build.sc <<'EOF'
import mill._, scalalib._
object foo extends ScalaModule {{
  def scalaVersion = "2.13.16"
  def ivyDeps = Agg(ivy"org.apache.commons:commons-text:1.9")
}}
EOF
TOOL() {{ timeout 300 mill-{version} --no-server {ticker} "$@"; }}
RESOLVE() {{ rm -rf out; TOOL show foo.compileClasspath; }}"#
            )
        }
        Tool::Mill { version } => format!(
            r#"export JAVA_HOME=${{SOCKET_PATCH_JDK:-/opt/jdk17}} PATH=${{SOCKET_PATCH_JDK:-/opt/jdk17}}/bin:$PATH
cat > build.mill <<'EOF'
//| mill-version: {version}
package build
import mill.*, scalalib.*
object foo extends ScalaModule {{
  def scalaVersion = "2.13.16"
  def mvnDeps = Seq(mvn"org.apache.commons:commons-text:1.9")
}}
EOF
TOOL() {{ timeout 300 mill-{version} --no-daemon --ticker false "$@"; }}
RESOLVE() {{ rm -rf out; TOOL show foo.compileClasspath; }}"#
        ),
        Tool::ScalaCli => r#"export JAVA_HOME=${SOCKET_PATCH_JDK:-/opt/jdk17} PATH=${SOCKET_PATCH_JDK:-/opt/jdk17}/bin:$PATH
cat > project.scala <<'EOF'
//> using scala 3.3.6
//> using dep org.apache.commons:commons-text:1.9
EOF
echo '@main def m() = println("ok")' > Main.scala
TOOL() { timeout 300 scala-cli "$@"; }
RESOLVE() { rm -rf .scala-build; TOOL compile . --server=false --print-class-path; }"#
            .to_string(),
    };
    let cache_jar = if tool.coursier() {
        format!("/root/.cache/coursier/v1/https/repo1.maven.org/maven2/org/apache/commons/commons-text/1.9/{JAR}")
    } else {
        format!("/root/.ivy2/cache/org.apache.commons/commons-text/jars/{JAR}")
    };
    let coursier = if tool.coursier() { "1" } else { "" };
    format!(
        r#"#!/usr/bin/env bash
set -uo pipefail
PRISTINE='{pristine_sha}'
PATCHED='{patched_sha}'
PATCHED_SHA1='{patched_sha1}'
PRISTINE_SHA1='{pristine_sha1}'
CACHE_JAR='{cache_jar}'
COURSIER='{coursier}'
fail() {{ echo "FAIL: $*" >&2; exit 1; }}
s256() {{ sha256sum "$1" | cut -d' ' -f1; }}
mkdir -p /w/p/project && cd /w/p
{setup}
# The jar the tool's resolved classpath names (it must be the cache copy).
cp_jar() {{
  RESOLVE > /tmp/resolve.log 2>&1 || {{ tail -40 /tmp/resolve.log >&2; fail "resolve"; }}
  local j
  # sbt 2 prints Coursier paths as `${{CSR_CACHE}}/…`.
  j=$(sed -e 's#[$]{{CSR_CACHE}}#/root/.cache/coursier/v1#g' /tmp/resolve.log \
    | grep -oE "/[^\":,\[( ]*/{jar}" | tail -1)
  [ "$j" = "$CACHE_JAR" ] || {{ tail -20 /tmp/resolve.log >&2; fail "classpath names '$j', not $CACHE_JAR"; }}
  echo "$j"
}}
J=$(cp_jar) || exit 1
[ "$(s256 "$J")" = "$PRISTINE" ] || fail "cache jar is not the pristine Central jar"
echo "resolved $J" >&2

# Agent scan: crawls the tool's cache from the project's build files.
socket-patch scan --json --sync --yes --api-url '{api_url}' --api-token fake --org {org} \
  > /tmp/scan.out 2>/tmp/scan.err
rc=$?
cat /tmp/scan.err >&2
[ $rc -eq 0 ] || {{ cat /tmp/scan.out >&2; fail "scan exit $rc"; }}
[ "$(s256 "$CACHE_JAR")" = "$PATCHED" ] || {{ cat /tmp/scan.out >&2; fail "scan did not patch the cache jar"; }}
J=$(cp_jar) || exit 1
[ "$(s256 "$J")" = "$PATCHED" ] || fail "the tool re-fetched the pristine jar after a clean resolve"
jar tf "$J" | grep -qx '{marker}' || fail "marker member missing"
echo "===PATCH OK==="

if [ -n "$COURSIER" ]; then
  D=$(dirname "$CACHE_JAR")
  [ "$(cat "$D/.{jar}__sha1")" = "$PATCHED_SHA1" ] || fail "__sha1 not resynced: $(cat "$D/.{jar}__sha1")"
  [ ! -e "$D/.{jar}__md5" ] || fail "__md5 left behind"
  rm -f "$D"/.*.computed
  J=$(cp_jar) || exit 1
  [ "$(s256 "$J")" = "$PATCHED" ] || fail "Coursier reverted the patch once the cached digests were gone"
  ls -a "$D" >&2
  echo "===SIDECAR OK==="
fi

socket-patch rollback --json --api-url '{api_url}' --api-token fake --org {org} > /tmp/rb.out 2>/tmp/rb.err
rc=$?
cat /tmp/rb.err >&2
[ $rc -eq 0 ] || {{ cat /tmp/rb.out >&2; fail "rollback exit $rc"; }}
[ "$(s256 "$CACHE_JAR")" = "$PRISTINE" ] || {{ cat /tmp/rb.out >&2; fail "rollback did not restore the jar"; }}
if [ -n "$COURSIER" ]; then
  [ "$(cat "$(dirname "$CACHE_JAR")/.{jar}__sha1")" = "$PRISTINE_SHA1" ] || fail "__sha1 not resynced on rollback"
fi
J=$(cp_jar) || exit 1
[ "$(s256 "$J")" = "$PRISTINE" ] || fail "the tool does not see the restored jar"
echo "===ROLLBACK OK==="
echo "===E2E PASS==="
"#,
        pristine_sha = hex_of::<Sha256>(pristine),
        patched_sha = hex_of::<Sha256>(patched),
        patched_sha1 = hex_of::<Sha1>(patched),
        pristine_sha1 = hex_of::<Sha1>(pristine),
        org = ORG,
        jar = JAR,
        marker = MARKER,
    )
}

fn required() -> bool {
    std::env::var("SOCKET_PATCH_DOCKER_E2E_REQUIRED").is_ok_and(|v| v == "1")
}

/// `true` when the cell should be skipped (no docker / no image).
#[must_use]
fn skip_if_no_image() -> bool {
    let reason = match Command::new("docker")
        .args(["image", "inspect", &image()])
        .output()
    {
        Err(_) => "`docker` not on PATH",
        Ok(out) if !out.status.success() => "the sbt docker image is not present",
        Ok(_) => return false,
    };
    assert!(
        !required(),
        "SOCKET_PATCH_DOCKER_E2E_REQUIRED=1 but {reason}"
    );
    eprintln!("skipping: {reason}");
    true
}

/// The binary mounts: a local Linux build, or the coverage hook.
fn binary_mounts() -> Vec<String> {
    if let Ok(bin) = std::env::var("SOCKET_PATCH_DOCKER_BIN") {
        return vec!["-v".into(), format!("{bin}:/usr/local/bin/socket-patch:ro")];
    }
    let (Ok(bin), Ok(dir)) = (
        std::env::var("SOCKET_PATCH_COV_BIN"),
        std::env::var("SOCKET_PATCH_COV_PROFRAW_DIR"),
    ) else {
        return Vec::new();
    };
    vec![
        "-v".into(),
        format!("{bin}:/usr/local/bin/socket-patch:ro"),
        "-v".into(),
        format!("{dir}:/coverage"),
        "-e".into(),
        "LLVM_PROFILE_FILE=/coverage/docker-e2e-%p-%14m.profraw".into(),
    ]
}

/// Run one cell in a fresh container and assert its markers.
async fn run_cell(tool: Tool) {
    if skip_if_no_image() {
        return;
    }
    let (pristine, patched) = jars().await;
    let server = mock_api(&pristine, &patched).await;
    let api_url = format!("http://host.docker.internal:{}", server.address().port());
    let script = script(tool, &api_url, &pristine, &patched);
    let out = tokio::task::spawn_blocking(move || {
        Command::new("docker")
            .args([
                "run",
                "--rm",
                "-m",
                "2g",
                "--add-host=host.docker.internal:host-gateway",
            ])
            .args(binary_mounts())
            .args(["-e", &format!("SOCKET_PATCH_JDK={}", sbt_jdk("1.13.0"))])
            .args([image().as_str(), "bash", "-c", &script])
            .output()
            .expect("docker run")
    })
    .await
    .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let mut want = vec!["===PATCH OK==="];
    if tool.coursier() {
        want.push("===SIDECAR OK===");
    }
    want.extend(["===ROLLBACK OK===", "===E2E PASS==="]);
    for marker in want {
        assert!(
            stdout.contains(marker),
            "{tool:?}: {marker} missing (exit {:?})\nstdout:\n{stdout}\nstderr:\n{stderr}",
            out.status.code()
        );
    }
    assert!(out.status.success(), "{tool:?}\nstderr:\n{stderr}");
    eprintln!("{tool:?}: {}", stdout.trim().replace('\n', " "));
    // The scan reached the mock with the crawled purl.
    let bodies: Vec<String> = server
        .received_requests()
        .await
        .expect("wiremock records requests")
        .iter()
        .filter(|r| r.url.path().ends_with("/patches/batch"))
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect();
    assert!(
        bodies.iter().any(|b| b.contains(PURL)),
        "{tool:?}: the batch query never carried {PURL}"
    );
}

/// The whitespace-separated versions `var` names, else `default`.
fn versions(var: &str, default: &str) -> Vec<&'static str> {
    std::env::var(var)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
        .split_whitespace()
        .map(|v| &*Box::leak(v.to_string().into_boxed_str()))
        .collect()
}

fn sbt_versions() -> Vec<&'static str> {
    versions("SOCKET_PATCH_SBT_DOCKER_VERSIONS", "1.13.0")
}

/// The versions the image installs a `mill-<version>` launcher for.
const MILL_VERSIONS: &[&str] = &["0.11.13", "0.12.17", "1.1.10"];

fn mill_versions() -> Vec<&'static str> {
    let picked = versions("SOCKET_PATCH_MILL_DOCKER_VERSIONS", "1.1.10");
    for v in &picked {
        assert!(
            MILL_VERSIONS.contains(v),
            "SOCKET_PATCH_MILL_DOCKER_VERSIONS: the image has no mill-{v} ({MILL_VERSIONS:?})"
        );
    }
    picked
}

/// `all` split into the sbt versions `useCoursier := false` applies to
/// (1.3 – 1.x) and the rest: sbt <= 1.2 has no `useCoursier` (it resolves
/// through Ivy already), and sbt 2 dropped the setting with Ivy.
fn coursier_sbt_versions(all: &[&'static str]) -> (Vec<&'static str>, Vec<&'static str>) {
    all.iter()
        .partition(|v| !sbt_uses_ivy(v) && v.starts_with("1."))
}

#[tokio::test]
async fn agent_sbt_versions_patch_in_place() {
    for version in sbt_versions() {
        run_cell(Tool::Sbt {
            version,
            ivy: false,
        })
        .await;
    }
}

/// `useCoursier := false` on each requested sbt 1.3 – 1.x version (the
/// setting arrived with Coursier in 1.3; older lines are Ivy already and
/// covered by `agent_sbt_versions_patch_in_place`; sbt 2 has no Ivy).
#[tokio::test]
async fn agent_sbt_use_coursier_false_patches_the_ivy_cache() {
    let (coursier, ivy) = coursier_sbt_versions(&sbt_versions());
    for version in ivy {
        eprintln!(
            "SKIP useCoursier := false on sbt {version}: the setting exists on sbt 1.3 – 1.x \
             only (older lines resolve through Ivy already; sbt 2 has no Ivy)"
        );
    }
    for version in coursier {
        run_cell(Tool::Sbt { version, ivy: true }).await;
    }
}

#[tokio::test]
async fn scala_tools_agent_mill_patches_in_place() {
    for version in mill_versions() {
        run_cell(Tool::Mill { version }).await;
    }
}

#[test]
fn version_selection() {
    assert_eq!(
        coursier_sbt_versions(&["0.13.18", "1.2.8", "1.3.13", "1.13.0", "2.0.9"]),
        (vec!["1.3.13", "1.13.0"], vec!["0.13.18", "1.2.8", "2.0.9"])
    );
    let legacy = script(Tool::Mill { version: "0.11.13" }, "http://api", b"p", b"q");
    assert!(legacy.contains("build.sc") && legacy.contains("--disable-ticker"));
    assert!(legacy.contains("mill-0.11.13 --no-server"));
    let twelve = script(Tool::Mill { version: "0.12.17" }, "http://api", b"p", b"q");
    assert!(twelve.contains("--ticker false") && twelve.contains("ivyDeps"));
    let one = script(Tool::Mill { version: "1.1.10" }, "http://api", b"p", b"q");
    assert!(one.contains("build.mill") && one.contains("//| mill-version: 1.1.10"));
}

#[tokio::test]
async fn scala_tools_agent_scala_cli_patches_in_place() {
    run_cell(Tool::ScalaCli).await;
}
