//! A reference grant is checked once, before it becomes a rewrite candidate
//! (core `hosted::engine::build_candidates`): a field that is not in the
//! shape the project's files need refuses that package with
//! `redirect_grant_malformed`, and an artifact or index URL over plain
//! `http` on an origin that is neither loopback nor the configured
//! `--patch-server-url` refuses it with `redirect_grant_insecure_url`. Each
//! is a hosted `skipped` event and a `warnings[]` entry, exit 0, and every
//! project file is left byte-identical.
//!
//! One test per sink a malformed grant used to reach: `package-lock.json`,
//! `yarn.lock`, `Gemfile.lock`, `pom.xml`, `composer.lock` and
//! `requirements.txt`. `scan` drives the npm-family locks (their fixtures
//! have an installed copy to crawl); `get <uuid>` drives the others, since
//! the uuid path needs no installed package.

use std::path::Path;

use wiremock::MockServer;

use crate::common;
use crate::hosted_fixture::*;

const MALFORMED: &str = "redirect_grant_malformed";
const INSECURE_URL: &str = "redirect_grant_insecure_url";
/// The grant-token path level before the patch uuid in a hosted URL.
const TOKEN: &str = "22222222-2222-4222-8222-222222222222";

/// `get <uuid> --mode hosted --json` → `(exit code, stdout, stderr)`.
fn get_hosted(cwd: &Path, api_url: &str, uuid: &str) -> (i32, String, String) {
    let cwd_s = cwd.to_str().unwrap();
    common::run_with_env(
        cwd,
        &[
            "get",
            uuid,
            "--mode",
            "hosted",
            "--yes",
            "--json",
            "--cwd",
            cwd_s,
            "--api-url",
            api_url,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
        &[],
    )
}

/// The envelope of a `get` run that must exit 0 (a panic exits 101 with no
/// envelope at all).
fn get_hosted_json(cwd: &Path, api_url: &str, uuid: &str) -> Value {
    let (code, stdout, stderr) = get_hosted(cwd, api_url, uuid);
    assert_eq!(
        code, 0,
        "a refused grant still exits 0;\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("stdout must be the JSON envelope ({e});\nstdout=\n{stdout}\nstderr=\n{stderr}")
    })
}

/// `doc` reports exactly one refusal, `code` for `purl`, as a hosted
/// `skipped` event and as a warning, both naming `field`; nothing is
/// pinned.
#[track_caller]
fn assert_refused(doc: &Value, purl: &str, uuid: &str, code: &str, field: &str) {
    let skipped = hosted_skipped(doc);
    assert_eq!(skipped.len(), 1, "one skip row: {doc:#}");
    assert_eq!(skipped[0]["purl"], purl, "{doc:#}");
    assert_eq!(skipped[0]["uuid"], uuid, "{doc:#}");
    assert_eq!(skipped[0]["reason"], code, "{doc:#}");
    let detail = skipped[0]["detail"].as_str().unwrap_or_default();
    assert!(detail.contains(field), "the skip names `{field}`: {detail}");
    assert_eq!(
        warning_detail(doc, code),
        detail,
        "the warning carries the skip's detail: {doc:#}"
    );
    assert!(
        !detail.chars().any(char::is_control),
        "the detail never echoes the grant's raw bytes: {detail:?}"
    );
    assert_eq!(hosted_pins(doc).len(), 0, "nothing pinned: {doc:#}");
}

/// `(relative path, bytes)` of every file under `root`, sorted: what a
/// refused run must leave exactly as it found it.
fn tree(root: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let rel = path.strip_prefix(root).unwrap().to_string_lossy();
                out.push((rel.replace('\\', "/"), std::fs::read(&path).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

/// A granted reference for `(uuid, purl)` with the given tarball
/// `integrity` and `registryOverride`.
fn granted(uuid: &str, purl: &str, url: &str, integrity: Value, registry_override: Value) -> Value {
    json!({
        uuid: {
            "status": "granted",
            "url": url,
            "purl": purl,
            "artifacts": [{ "kind": "tarball", "url": url, "integrity": integrity }],
            "registryOverride": registry_override
        }
    })
}

// ───────────────────────── plain-http artifact URL ─────────────────────────

/// A grant naming a plain-`http` artifact URL on some other host is never
/// written into `package-lock.json`: every later install would send the
/// grant token in that URL in clear text. The operator's own
/// `--patch-server-url` origin is the explicit override, plain `http`
/// included.
#[tokio::test]
async fn plain_http_artifact_url_is_refused_unless_its_origin_is_configured() {
    let url =
        format!("http://patch.test/patch/npm/{NAME}/{VERSION}/{TOKEN}/{UUID}/{NAME}-{VERSION}.tgz");
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, &url).await;

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), NAME);
    let before = tree(tmp.path());

    let (code, doc) = scan_hosted_json(tmp.path(), &server.uri(), &[], &[]);
    assert_eq!(code, 0, "a refused grant still exits 0: {doc:#}");
    assert_refused(&doc, PURL, UUID, INSECURE_URL, "artifact URL");
    let detail = warning_detail(&doc, INSECURE_URL);
    assert!(
        detail.contains("patch.test") && detail.contains("--patch-server-url"),
        "names the host and the override: {detail}"
    );
    assert!(
        !detail.contains(TOKEN),
        "never prints the grant token: {detail}"
    );
    assert_eq!(tree(tmp.path()), before, "nothing was written");

    // Human mode says which package, and why, on stderr.
    let (code, _stdout, stderr) = scan_hosted(tmp.path(), &server.uri(), &[], &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stderr.contains(&format!(
            "{PURL}: the patch server's reference for it names a plain-http URL"
        )) && stderr.contains("Warning: ")
            && stderr.contains("its artifact URL is plain http on patch.test"),
        "{stderr}"
    );
    assert_eq!(tree(tmp.path()), before, "nothing was written");

    let (code, doc) = scan_hosted_json(
        tmp.path(),
        &server.uri(),
        &["--patch-server-url", "http://patch.test"],
        &[],
    );
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(
        hosted_pins(&doc),
        vec![(PURL.to_string(), UUID.to_string())],
        "the configured origin is accepted: {doc:#}"
    );
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(lock.contains(&url), "{lock}");
}

// ─────────────────────────────── yarn classic ───────────────────────────────

/// `yarn.lock` (v1) takes the grant's sha1 as the `resolved` fragment and its
/// sha512 as the `integrity` line, both unquoted line grammar: a digest
/// holding a quote and a newline used to add a field to the block (and the
/// tarball check passed, since an SRI string is read up to its first
/// whitespace).
#[tokio::test]
async fn yarn_classic_grant_with_an_injected_digest_is_refused() {
    type Edit = fn(&mut Value);
    let cases: [(&str, Edit); 2] = [
        ("sha1", |integrity| {
            let sha1 = integrity["sha1"].as_str().unwrap().to_string();
            integrity["sha1"] = json!(format!("{sha1}\"\n  evil-injected-field \"pwned"));
        }),
        ("sha512", |integrity| {
            let sri = integrity["sha512"].as_str().unwrap().to_string();
            integrity["sha512"] = json!(format!("{sri}\n  injected-by-integrity \"x\""));
        }),
    ];
    for (field, edit) in cases {
        let server = MockServer::start().await;
        mock_discovery(&server, PURL, UUID).await;
        mock_served_classic_reference_with(&server, edit).await;

        let tmp = tempfile::tempdir().unwrap();
        write_yarn_classic_project(tmp.path(), Some("yarn@1.22.22"));
        let before = tree(tmp.path());

        let (code, doc) = scan_hosted_json(tmp.path(), &server.uri(), &[], &[]);
        assert_eq!(code, 0, "{field}: {doc:#}");
        assert_refused(&doc, PURL, UUID, MALFORMED, field);
        assert_eq!(tree(tmp.path()), before, "{field}: nothing was written");
    }
}

// ─────────────────────────────────── gem ───────────────────────────────────

/// `Gemfile.lock`'s CHECKSUMS entry is added through a regex replacement:
/// `${1}` in the grant's checksum used to be read as a capture reference,
/// and a newline added a second entry for a gem the project never locked.
#[tokio::test]
async fn gem_grant_with_an_injected_checksum_is_refused() {
    const GEM_UUID: &str = "e5e5e5e5-e5e5-4e5e-8e5e-e5e5e5e5e5e5";
    const GEM_PURL: &str = "pkg:gem/rails@7.0.0";
    let index_url = format!("https://patch.test/patch-registry/gem/{TOKEN}/{GEM_UUID}/");
    let url =
        format!("https://patch.test/patch/gem/rails/7.0.0/{TOKEN}/{GEM_UUID}/rails-7.0.0.gem");
    let checksum = format!(
        "dead${{1}}beef\n  evilgem (6.6.6) sha256={}",
        "f".repeat(64)
    );

    let server = MockServer::start().await;
    mock_view(&server, GEM_UUID, GEM_PURL).await;
    mock_reference_results(
        &server,
        granted(
            GEM_UUID,
            GEM_PURL,
            &url,
            json!({ "sha256": "a".repeat(64) }),
            json!({
                "kind": "rubygems-compact-index",
                "indexUrl": index_url,
                "identifiers": {
                    "name": "rails",
                    "version": "7.0.0",
                    "gemChecksumSha256": checksum,
                }
            }),
        ),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("Gemfile"),
        "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n",
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("Gemfile.lock"),
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n\n\
         PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (= 7.0.0)\n\n\
         CHECKSUMS\n\nBUNDLED WITH\n   2.6.2\n",
    )
    .unwrap();
    let before = tree(tmp.path());

    let doc = get_hosted_json(tmp.path(), &server.uri(), GEM_UUID);
    assert_refused(&doc, GEM_PURL, GEM_UUID, MALFORMED, "gem checksum");
    assert_eq!(tree(tmp.path()), before, "nothing was written");
}

// ────────────────────────────────── maven ──────────────────────────────────

const MAVEN_UUID: &str = "b2b2b2b2-b2b2-4b2b-8b2b-b2b2b2b2b2b2";
const MAVEN_PURL: &str = "pkg:maven/org.apache.commons/commons-lang3@3.12.0";
const MAVEN_SUFFIXED: &str = "3.12.0-socket.b2b2b2b2";

/// The maven2 override of a well-formed grant for [`MAVEN_PURL`].
fn maven_override() -> Value {
    json!({
        "kind": "maven2",
        "indexUrl": format!(
            "https://patch.test/patch-registry/maven/{TOKEN}/{MAVEN_UUID}/maven2"
        ),
        "identifiers": {
            "name": "org.apache.commons/commons-lang3",
            "version": "3.12.0",
            "mavenGroupId": "org.apache.commons",
            "mavenArtifactId": "commons-lang3",
            "mavenSuffixedVersion": MAVEN_SUFFIXED,
            "mavenPomSha256": "d".repeat(64),
        }
    })
}

/// `pom.xml` takes the grant's coordinates, suffixed version and repository
/// URL as element text. Markup in any of them used to land verbatim (a
/// `system`-scoped path, a pom that is no longer well formed), and a group
/// id holding `</dependency>` panicked the run.
#[tokio::test]
async fn maven_grant_with_markup_is_refused() {
    type Edit = fn(&mut Value);
    let cases: [(&str, Edit); 4] = [
        ("suffixed version", |ov| {
            ov["identifiers"]["mavenSuffixedVersion"] = json!(format!(
                "{MAVEN_SUFFIXED}</version><scope>system</scope>\
                 <systemPath>/tmp/evil.jar</systemPath><version>x"
            ));
        }),
        ("index URL", |ov| {
            let index = ov["indexUrl"].as_str().unwrap().to_string();
            ov["indexUrl"] = json!(format!("{index}?a=1&b=2</url><!-- injected -->"));
        }),
        ("group id", |ov| {
            ov["identifiers"]["mavenGroupId"] = json!("org.other</dependency>");
        }),
        ("artifact id", |ov| {
            ov["identifiers"]["mavenArtifactId"] = json!("commons-lang3\n<!--");
        }),
    ];
    for (field, edit) in cases {
        let url = format!(
            "https://patch.test/patch/maven/org.apache.commons/commons-lang3/3.12.0/{TOKEN}/{MAVEN_UUID}/commons-lang3-{MAVEN_SUFFIXED}.jar"
        );
        let mut ov = maven_override();
        edit(&mut ov);
        let server = MockServer::start().await;
        mock_view(&server, MAVEN_UUID, MAVEN_PURL).await;
        mock_reference_results(
            &server,
            granted(
                MAVEN_UUID,
                MAVEN_PURL,
                &url,
                json!({ "sha256": "c".repeat(64) }),
                ov,
            ),
        )
        .await;

        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("pom.xml"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>dev.socket.test</groupId>
  <artifactId>consumer</artifactId>
  <version>1.0.0</version>
  <packaging>jar</packaging>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.12.0</version>
    </dependency>
  </dependencies>
</project>
"#,
        )
        .unwrap();
        let before = tree(tmp.path());

        let doc = get_hosted_json(tmp.path(), &server.uri(), MAVEN_UUID);
        assert_refused(&doc, MAVEN_PURL, MAVEN_UUID, MALFORMED, field);
        assert_eq!(tree(tmp.path()), before, "{field}: nothing was written");
    }
}

// ───────────────────────────────── composer ─────────────────────────────────

/// `composer.lock`'s dist `url` and `shasum` are replaced through a regex:
/// `${1}` in the grant's URL used to expand to the matched `"url": "`
/// prefix, and a quote in either value ended the JSON string early.
#[tokio::test]
async fn composer_grant_with_a_capture_reference_or_quote_is_refused() {
    const COMPOSER_UUID: &str = "d4d4d4d4-d4d4-4d4d-8d4d-d4d4d4d4d4d4";
    const COMPOSER_PURL: &str = "pkg:composer/monolog/monolog@3.5.0";
    const SHA1: &str = "abcdef0123456789abcdef0123456789abcdef01";
    let url = format!(
        "https://patch.test/patch/composer/monolog/monolog/3.5.0/{TOKEN}/{COMPOSER_UUID}/monolog-3.5.0.zip"
    );
    let cases = [
        ("artifact URL", format!("{url}?x=${{1}}y"), SHA1.to_string()),
        (
            "sha1",
            url.clone(),
            format!("{SHA1}\", \"reference\": \"evil"),
        ),
    ];
    for (field, url, sha1) in cases {
        let server = MockServer::start().await;
        mock_view(&server, COMPOSER_UUID, COMPOSER_PURL).await;
        mock_reference_results(
            &server,
            granted(
                COMPOSER_UUID,
                COMPOSER_PURL,
                &url,
                json!({ "sha1": sha1 }),
                Value::Null,
            ),
        )
        .await;

        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("composer.lock"),
            r#"{
    "content-hash": "abc123def456abc123def456abc1",
    "packages": [
        {
            "name": "monolog/monolog",
            "version": "3.5.0",
            "dist": {
                "type": "zip",
                "url": "https:\/\/api.github.com\/repos\/Seldaek\/monolog\/zipball\/abc123",
                "reference": "abc123def456",
                "shasum": ""
            }
        }
    ],
    "packages-dev": []
}
"#,
        )
        .unwrap();
        let before = tree(tmp.path());

        let doc = get_hosted_json(tmp.path(), &server.uri(), COMPOSER_UUID);
        assert_refused(&doc, COMPOSER_PURL, COMPOSER_UUID, MALFORMED, field);
        assert_eq!(tree(tmp.path()), before, "{field}: nothing was written");
    }
}

// ───────────────────────────── requirements.txt ─────────────────────────────

/// `requirements.txt` takes the grant's URL and sha256 as one
/// whitespace-delimited line: a digest holding a space used to add a pip
/// option, and a newline a second requirement.
#[tokio::test]
async fn requirements_grant_with_whitespace_in_its_digest_is_refused() {
    const PYPI_UUID: &str = "a1a1a1a1-a1a1-4a1a-8a1a-a1a1a1a1a1a1";
    const PYPI_PURL: &str = "pkg:pypi/requests@2.31.0";
    let url = format!(
        "https://patch.test/patch/pypi/requests/2.31.0/{TOKEN}/{PYPI_UUID}/requests-2.31.0-py3-none-any.whl"
    );
    let sha256 = format!(
        "{} --index-url=http://evil.test/simple\nevilpkg==6.6.6",
        "0".repeat(64)
    );

    let server = MockServer::start().await;
    mock_view(&server, PYPI_UUID, PYPI_PURL).await;
    mock_reference_results(
        &server,
        granted(
            PYPI_UUID,
            PYPI_PURL,
            &url,
            json!({ "sha256": sha256 }),
            Value::Null,
        ),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("requirements.txt"),
        "flask==2.0.1\nrequests==2.31.0\n",
    )
    .unwrap();
    let before = tree(tmp.path());

    let doc = get_hosted_json(tmp.path(), &server.uri(), PYPI_UUID);
    assert_refused(&doc, PYPI_PURL, PYPI_UUID, MALFORMED, "sha256");
    assert_eq!(tree(tmp.path()), before, "nothing was written");
}
